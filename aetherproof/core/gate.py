"""One payment gate for the library, the CLI and the local API.

Without a gate policy file the decision is exactly `verify_instruction` with the replay store
(0.5.x behaviour). With `gate_policy.json` in the AetherProof home (or a path given), the
same decision also requires:

* destinations: the destination is approved for the account by k of n policy keys
  (core/destinations.py), checked after the hard checks and before anything is spent;
* limits: per payout, daily, per destination and count caps, plus revocation
  (core/limits.py), reserved atomically before single use is consumed.

gate_policy.json:
{
  "account": "nbfc-main",
  "limits": {"per_payout_max": "200000.00", "daily_max": "8000000.00", "daily_count_max": 500,
             "per_destination_daily_max": "200000.00", "utc_offset_minutes": 330},
  "destinations": {"policy_pubkeys": ["policy_a.pub", "policy_b.pub"], "required_signers": 2}
}
Amounts are in major units. Relative paths are relative to the policy file. Any error reading
the policy is a refusal to decide, never a silent fall back to fewer checks.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import List, Optional

from .destinations import DestinationRegistry, bank_destination
from .instruction import REJECT, Decision, PaymentInstruction, PayoutRequest, ReplayStore, verify_instruction
from .limits import LimitPolicy, LimitStore, verify_with_limits

POLICY_FILE = "gate_policy.json"


class GatePolicyError(ValueError):
    """The gate policy exists but cannot be used. The caller must not pay."""


@dataclass
class GatePolicy:
    account: str
    limits: Optional[LimitPolicy]
    limits_db: str
    policy_keys: List
    required_signers: int
    destinations_db: str


def _minor(value) -> int:
    try:
        d = Decimal(str(value))
    except InvalidOperation as e:
        raise GatePolicyError(f"not an amount: {value!r}") from e
    if d <= 0 or d != d.quantize(Decimal("0.01")):
        raise GatePolicyError(f"amount must be positive with at most 2 decimals: {value!r}")
    return int(d * 100)


def load_policy(home_dir: Path, path: Optional[str] = None) -> Optional[GatePolicy]:
    p = Path(path) if path else Path(home_dir) / POLICY_FILE
    if not p.exists():
        if path:
            raise GatePolicyError(f"gate policy not found: {p}")
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        account = str(raw["account"]).strip()
        if not account:
            raise GatePolicyError("account is empty")
        lim = raw.get("limits")
        limits = None
        if lim is not None:
            limits = LimitPolicy(_minor(lim["per_payout_max"]), _minor(lim["daily_max"]), int(lim["daily_count_max"]),
                                 _minor(lim["per_destination_daily_max"]), int(lim.get("utc_offset_minutes", 330)))
        keys, k = [], 0
        dst = raw.get("destinations")
        if dst is not None:
            from .signer import Verifier
            keys = [Verifier.from_public_file(str(kp if Path(kp).is_absolute() else p.parent / kp))
                    for kp in dst["policy_pubkeys"]]
            k = int(dst.get("required_signers", 2))
            if not keys or k < 1 or k > len(keys):
                raise GatePolicyError("destinations needs policy keys and 1 <= required_signers <= number of keys")
    except GatePolicyError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise GatePolicyError(f"gate policy unusable ({type(e).__name__}: {e})") from e
    base = Path(home_dir)
    return GatePolicy(account, limits, str(base / "limits.db"), keys, k, str(base / "destinations.db"))


_local = threading.local()   # one connection per thread and file: SQLite connections are not shared across threads


def _cached(kind, path, factory):
    cache = getattr(_local, "stores", None)
    if cache is None:
        cache = _local.stores = {}
    key = (kind, path)
    if key not in cache:
        cache[key] = factory()
    return cache[key]


def _drop(kind, path):
    st = getattr(_local, "stores", {}).pop((kind, path), None)
    if st is not None:
        try:
            st.close()
        except Exception:  # noqa: BLE001 - the store already failed; closing is best effort
            pass


def destination_of(req: PayoutRequest) -> str:
    if req.beneficiary_token:
        return req.beneficiary_token
    if req.ifsc and req.account_number:
        return bank_destination(req.ifsc, req.account_number)
    return ""


def decide(ins: PaymentInstruction, req: PayoutRequest, public_keys, replay: ReplayStore,
           policy: Optional[GatePolicy] = None, *, now_ms: Optional[int] = None) -> Decision:
    if policy is None:
        return verify_instruction(ins, req, public_keys, replay, now_ms=now_ms)
    first = verify_instruction(ins, req, public_keys, None, now_ms=now_ms)
    if first.verdict == REJECT:
        return first
    dest = destination_of(req)
    if policy.policy_keys:
        try:
            reg = _cached("dest", policy.destinations_db,
                          lambda: DestinationRegistry(policy.destinations_db, policy.policy_keys, policy.required_signers))
            ok, why = reg.check(policy.account, dest)
        except (OSError, sqlite3.Error, ValueError) as e:
            _drop("dest", policy.destinations_db)
            return Decision(REJECT, ins.instruction_id, [f"destination registry unavailable ({type(e).__name__}): not paid"])
        if not ok:
            return Decision(REJECT, ins.instruction_id, [why])
    if policy.limits is None:
        return verify_instruction(ins, req, public_keys, replay, now_ms=now_ms)
    try:
        store = _cached("limits", policy.limits_db, lambda: LimitStore(policy.limits_db))
    except (OSError, sqlite3.Error) as e:
        return Decision(REJECT, ins.instruction_id, [f"limit store unavailable ({type(e).__name__}): not paid"])
    d = verify_with_limits(ins, req, public_keys, replay, store, policy.limits,
                           account=policy.account, destination=dest, now_ms=now_ms)
    if any("store unavailable" in r for r in d.reasons):
        _drop("limits", policy.limits_db)   # reopen next time instead of reusing a broken connection
    return d
