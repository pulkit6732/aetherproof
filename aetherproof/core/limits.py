"""Aggregate limits and revocation for the payment gate.

A signed instruction proves one payout was approved. It does not stop many approved-looking
payouts from draining an account (a stolen signing key, a runaway agent, structuring into
small amounts), and it cannot be withdrawn once issued. This module adds both:

* per payout, per day, per destination per day, and count per day caps, per source account;
* revocation of an instruction id before it is used.

Every check-and-spend runs in one SQLite IMMEDIATE transaction, so concurrent executors in
different processes cannot together exceed a cap. A reservation made for a payout that is
then refused elsewhere (for example a replay) is released; a crash between reserve and
release leaves the cap over-counted, which errs on the safe side.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from .dbutil import open_db  # noqa: F401 - re-exported for older imports
from .instruction import REJECT, Decision, money, PaymentInstruction, PayoutRequest, ReplayStore, verify_instruction, REVIEW


@dataclass(frozen=True)
class LimitPolicy:
    per_payout_max_minor: int
    daily_max_minor: int
    daily_count_max: int
    per_destination_daily_max_minor: int
    utc_offset_minutes: int = 330  # days roll over at local midnight; 330 = India


class LimitStore:
    def __init__(self, path: str):
        self.path = path
        self._db = open_db(path, [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=FULL",
            "CREATE TABLE IF NOT EXISTS spend (account TEXT, day TEXT, total INTEGER, n INTEGER, PRIMARY KEY(account, day))",
            "CREATE TABLE IF NOT EXISTS dest_spend (account TEXT, dest TEXT, day TEXT, total INTEGER, PRIMARY KEY(account, dest, day))",
            "CREATE TABLE IF NOT EXISTS revoked (instruction_id TEXT PRIMARY KEY, at_ms INTEGER)",
            "CREATE TABLE IF NOT EXISTS held (instruction_id TEXT PRIMARY KEY, account TEXT, dest TEXT, day TEXT, amount INTEGER)"])

    @staticmethod
    def day_of(now_ms: int, policy: LimitPolicy) -> str:
        t = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc) + timedelta(minutes=policy.utc_offset_minutes)
        return t.strftime("%Y-%m-%d")

    def revoke(self, instruction_id: str, now_ms: Optional[int] = None) -> None:
        self._db.execute("INSERT OR IGNORE INTO revoked VALUES (?, ?)", (instruction_id, now_ms or int(time.time() * 1000)))

    def is_revoked(self, instruction_id: str) -> bool:
        return self._db.execute("SELECT 1 FROM revoked WHERE instruction_id=?", (instruction_id,)).fetchone() is not None

    def reserve(self, instruction_id: str, account: str, dest: str, amount_minor: int,
                policy: LimitPolicy, now_ms: int) -> Tuple[bool, str]:
        if amount_minor > policy.per_payout_max_minor:
            return False, f"amount above the per payout cap {money(policy.per_payout_max_minor)}"
        day = self.day_of(now_ms, policy)
        cur = self._db.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            if cur.execute("SELECT 1 FROM revoked WHERE instruction_id=?", (instruction_id,)).fetchone():
                cur.execute("ROLLBACK")
                return False, "instruction revoked"
            total, n = cur.execute("SELECT total, n FROM spend WHERE account=? AND day=?", (account, day)).fetchone() or (0, 0)
            dtotal = (cur.execute("SELECT total FROM dest_spend WHERE account=? AND dest=? AND day=?",
                                  (account, dest, day)).fetchone() or (0,))[0]
            why = ""
            if total + amount_minor > policy.daily_max_minor:
                why = "daily cap for the account would be exceeded"
            elif n + 1 > policy.daily_count_max:
                why = "daily payout count cap reached"
            elif dtotal + amount_minor > policy.per_destination_daily_max_minor:
                why = "daily cap for this destination would be exceeded"
            if why:
                cur.execute("ROLLBACK")
                return False, why
            cur.execute("INSERT INTO spend VALUES (?, ?, ?, 1) ON CONFLICT(account, day) DO UPDATE SET total=total+?, n=n+1",
                        (account, day, amount_minor, amount_minor))
            cur.execute("INSERT INTO dest_spend VALUES (?, ?, ?, ?) ON CONFLICT(account, dest, day) DO UPDATE SET total=total+?",
                        (account, dest, day, amount_minor, amount_minor))
            cur.execute("INSERT OR REPLACE INTO held VALUES (?, ?, ?, ?, ?)", (instruction_id, account, dest, day, amount_minor))
            cur.execute("COMMIT")
            return True, ""
        except BaseException:
            cur.execute("ROLLBACK")
            raise

    def release(self, instruction_id: str) -> None:
        cur = self._db.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            row = cur.execute("SELECT account, dest, day, amount FROM held WHERE instruction_id=?", (instruction_id,)).fetchone()
            if row:
                account, dest, day, amount = row
                cur.execute("UPDATE spend SET total=total-?, n=n-1 WHERE account=? AND day=?", (amount, account, day))
                cur.execute("UPDATE dest_spend SET total=total-? WHERE account=? AND dest=? AND day=?", (amount, account, dest, day))
                cur.execute("DELETE FROM held WHERE instruction_id=?", (instruction_id,))
            cur.execute("COMMIT")
        except BaseException:
            cur.execute("ROLLBACK")
            raise

    def spent(self, account: str, now_ms: int, policy: LimitPolicy) -> Tuple[int, int]:
        row = self._db.execute("SELECT total, n FROM spend WHERE account=? AND day=?",
                               (account, self.day_of(now_ms, policy))).fetchone()
        return row or (0, 0)

    def close(self) -> None:
        self._db.close()


def verify_with_limits(ins: PaymentInstruction, request: PayoutRequest, public_keys, replay: ReplayStore,
                       limits: LimitStore, policy: LimitPolicy, *, account: str, destination: str,
                       now_ms: Optional[int] = None) -> Decision:
    """The full gate: every check of verify_instruction, then revocation and aggregate caps,
    then single use. Fails closed: a store error is a reject, never an allow."""
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    if not account or not destination or request.amount_minor <= 0:
        # caps are keyed by account and destination: an empty key would share one bucket for all
        return Decision(REJECT, ins.instruction_id, ["account, destination and a positive amount are required"])
    # Hard checks first, consuming nothing (no replay store: a clean request comes back REVIEW).
    first = verify_instruction(ins, request, public_keys, None, now_ms=now)
    if first.verdict == REJECT:
        return first
    if first.verdict == REVIEW and not request.reference:
        return first
    try:
        ok, why = limits.reserve(ins.instruction_id, account, destination, request.amount_minor, policy, now)
    except (OSError, sqlite3.Error) as e:
        return Decision(REJECT, ins.instruction_id, [f"limit store unavailable ({type(e).__name__}): not paid"])
    if not ok:
        return Decision(REJECT, ins.instruction_id, [why])
    try:
        final = verify_instruction(ins, request, public_keys, replay, now_ms=now)
    except (OSError, sqlite3.Error) as e:
        final = Decision(REJECT, ins.instruction_id, [f"replay store unavailable ({type(e).__name__}): not paid"])
    if not final.allowed:
        try:
            limits.release(ins.instruction_id)
        except (OSError, sqlite3.Error):
            pass  # over-counted cap: safe side
    return final
