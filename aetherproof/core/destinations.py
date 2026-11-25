"""Destination authorization, independent of the payout approver.

A valid payout signature proves the approver's key signed. It does not prove the key was not
stolen or the approver not deceived. This registry adds a second, separate question: is this
destination approved for this account by the *policy authority* (k of n policy keys that are
not the approver's key)?

* Lending: the destination is the borrower's mandate account; adding or changing it needs the
  policy keys (for example the mandate system and a second officer), not the loan approver.
* Crypto and treasury: the destination is network + asset + address, so the same address on
  another network or token is a different, unapproved destination.
* Stock orders: the destination is account + instrument; the entry lists the allowed sides.

Every add or revoke is a signed record with a version that must be exactly one above the
current one, so an old record cannot be replayed to undo a revoke. Stored signatures are
checked again on every lookup, so rows written straight into the database are refused, and
every change is appended to a hash chain (`verify_history`).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Dict, Iterable, List, Optional, Tuple

from .log import _as_keyring

DOMAINS = ("bank", "crypto", "stock")


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bank_destination(ifsc: str, account_number: str) -> str:
    """Bank destinations are stored as a hash of IFSC and account, never the raw number."""
    norm = f"{ifsc.strip().upper()}|{''.join(account_number.split())}"
    return "bank:" + hashlib.sha256(norm.encode()).hexdigest()


def lookup_key(destination: str) -> Tuple[str, str]:
    """(registry key, side) for a destination. Stock orders carry the side last; the entry is
    per instrument and lists the allowed sides."""
    if destination.startswith("stock:"):
        parts = destination.split(":")
        if len(parts) == 4:
            return ":".join(parts[:3]), parts[3].upper()
    return destination, ""


def make_record(*, account: str, destination: str, domain: str, action: str, version: int,
                attrs: Optional[Dict] = None, evidence: str = "", created_ms: Optional[int] = None) -> Dict:
    if domain not in DOMAINS:
        raise ValueError(f"domain must be one of {DOMAINS}")
    if action not in ("add", "revoke"):
        raise ValueError("action must be add or revoke")
    if not account or not destination or version < 1:
        raise ValueError("account, destination and a version of at least 1 are required")
    return {"account": account, "destination": destination, "domain": domain, "action": action,
            "version": int(version), "attrs": dict(attrs or {}), "evidence": evidence,
            "created_ms": int(created_ms if created_ms is not None else time.time() * 1000)}


def sign_record(record: Dict, signer) -> Dict[str, str]:
    from .receipt import Receipt
    return {"key_id": Receipt.key_id(signer.get_public_key()), "sig": signer.sign(_canonical(record))}


class DestinationRegistry:
    def __init__(self, path: str, policy_keys: Iterable, required_signers: int = 2):
        self.keys = _as_keyring(list(policy_keys))
        if required_signers < 1 or required_signers > len(self.keys):
            raise ValueError("required_signers must be between 1 and the number of policy keys")
        self.k = required_signers
        from .dbutil import open_db
        self._db = open_db(path, [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=FULL",
            "CREATE TABLE IF NOT EXISTS entries (account TEXT, key TEXT, version INTEGER, active INTEGER, "
            "record TEXT, sigs TEXT, PRIMARY KEY(account, key))",
            "CREATE TABLE IF NOT EXISTS history (seq INTEGER PRIMARY KEY AUTOINCREMENT, prev TEXT, hash TEXT, body TEXT)"])

    def _signed_by_enough(self, record: Dict, sigs: List[Dict]) -> bool:
        msg, good = _canonical(record), set()
        for s in sigs or []:
            v = self.keys.get(s.get("key_id", ""))
            if v is not None and s["key_id"] not in good and v.verify(msg, s.get("sig", "")):
                good.add(s["key_id"])
        return len(good) >= self.k

    def apply(self, record: Dict, sigs: List[Dict]) -> Tuple[bool, str]:
        if not self._signed_by_enough(record, sigs):
            return False, f"needs {self.k} distinct policy key signatures"
        key, _ = lookup_key(record["destination"])
        cur = self._db.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            row = cur.execute("SELECT version FROM entries WHERE account=? AND key=?", (record["account"], key)).fetchone()
            current = row[0] if row else 0
            if record["version"] != current + 1:
                cur.execute("ROLLBACK")
                return False, f"version {record['version']} is not the next version ({current + 1})"
            cur.execute("INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?, ?)",
                        (record["account"], key, record["version"], 1 if record["action"] == "add" else 0,
                         json.dumps(record, sort_keys=True), json.dumps(sigs, sort_keys=True)))
            prev = (cur.execute("SELECT hash FROM history ORDER BY seq DESC LIMIT 1").fetchone() or ("0" * 64,))[0]
            body = json.dumps({"record": record, "sigs": sigs}, sort_keys=True)
            cur.execute("INSERT INTO history (prev, hash, body) VALUES (?, ?, ?)",
                        (prev, hashlib.sha256((prev + body).encode()).hexdigest(), body))
            cur.execute("COMMIT")
            return True, ""
        except BaseException:
            cur.execute("ROLLBACK")
            raise

    def check(self, account: str, destination: str) -> Tuple[bool, str]:
        key, side = lookup_key(destination)
        row = self._db.execute("SELECT active, record, sigs FROM entries WHERE account=? AND key=?", (account, key)).fetchone()
        if row is None:
            return False, "destination not approved by the policy authority"
        active, record, sigs = row[0], json.loads(row[1]), json.loads(row[2])
        # A row written straight into the database, without the policy keys, does not count.
        if not self._signed_by_enough(record, sigs) or record["account"] != account or lookup_key(record["destination"])[0] != key:
            return False, "destination entry fails its policy signatures"
        if not active or record["action"] != "add":
            return False, "destination revoked"
        sides = record["attrs"].get("sides")
        if side and sides is not None and side not in [s.upper() for s in sides]:
            return False, f"side {side} not approved for this instrument"
        return True, ""

    def verify_history(self) -> Tuple[bool, str]:
        prev = "0" * 64
        for seq, p, h, body in self._db.execute("SELECT seq, prev, hash, body FROM history ORDER BY seq"):
            if p != prev or hashlib.sha256((p + body).encode()).hexdigest() != h:
                return False, f"history broken at entry {seq}"
            prev = h
        return True, ""

    def close(self) -> None:
        self._db.close()
