"""Signed payment instructions: proof of authority that travels with the money.

A payout API trusts whoever holds a valid credential. CERT-In CIAD-2026-0046 and
-0058 describe exactly how that fails: stolen gateway credentials call disbursal
APIs directly and skip sanction, beneficiary and limit checks. A credential says
who is calling, not that this payment was approved.

Here the system that approves money movement (a loan system, an AP workflow, an
AI agent's policy service) signs the exact instruction it authorised. The system
that executes it checks the signature, the amount, the currency, the beneficiary,
the validity window and single use before any money moves:

    originator:  sign_instruction(...)            -> PaymentInstruction (signed)
    executor:    verify_instruction(ins, request) -> allow | reject

A stolen credential can still call the payout API, but it cannot mint a valid
instruction without the originator's signing key - which lives somewhere else.
See docs/SIGNED-INSTRUCTION-SPEC.md for the wire format.
"""

import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .receipt import Receipt

from ..contract import ALLOW, MAX_AMOUNT_MINOR, REJECT, REVIEW  # noqa: F401  (re-exported for callers)

INSTRUCTION_TYPE = "aetherproof.instruction/v0"
# instruction_id travels as the payout provider's reference (RazorpayX reference_id
# is at most 40 characters), so the outcome can be tied back to its instruction
MAX_ID_LEN = 40
DEFAULT_VALIDITY_MS = 15 * 60 * 1000


def money(minor: int, currency: str = "") -> str:
    """Human amount for messages: 4850000 -> '48,500.00 INR' (2-decimal currencies)."""
    return f"{minor / 100:,.2f}{' ' + currency if currency else ''}"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _canonical(obj: Any) -> bytes:
    # integers and strings only in this format, so sorted-key JSON is canonical
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ beneficiary

def _normalise_bank(ifsc: str, account_number: str) -> str:
    # digits kept exactly: stripping leading zeros could merge two distinct accounts
    return f"{ifsc.strip().upper()}|{account_number.strip()}"


def bank_beneficiary(ifsc: str, account_number: str, salt: str = "") -> Dict[str, str]:
    """Bind to a bank account without putting the account number in the instruction.
    The random salt stops a precomputed table from reversing the digest; an attacker
    targeting one instruction can still brute-force a short account space."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}|{_normalise_bank(ifsc, account_number)}".encode()).hexdigest()
    return {"kind": "bank", "salt": salt, "digest": digest}


def token_beneficiary(token: str) -> Dict[str, str]:
    """Bind to a provider's beneficiary token, e.g. a RazorpayX fund_account_id."""
    if not token:
        raise ValueError("beneficiary token is empty")
    return {"kind": "token", "value": token}


def beneficiary_matches(ben: Dict[str, str], *, token: str = "", ifsc: str = "", account_number: str = "") -> bool:
    if ben.get("kind") == "token":
        return bool(token) and secrets.compare_digest(ben["value"], token)
    if ben.get("kind") == "bank":
        if not (ifsc and account_number):
            return False
        got = hashlib.sha256(f"{ben['salt']}|{_normalise_bank(ifsc, account_number)}".encode()).hexdigest()
        return secrets.compare_digest(ben["digest"], got)
    return False


# ------------------------------------------------------------------ instruction

@dataclass
class PaymentInstruction:
    instruction_id: str
    originator: str
    amount_minor: int          # paise / cents: never floats for money
    currency: str
    beneficiary: Dict[str, str]
    purpose: str
    reference: str             # business reference, e.g. loan account number
    approval_ref: str          # where the approval lives (sanction id, ticket)
    approved_by: str
    policy: str                # policy version the approval was made under
    not_before_ms: int
    not_after_ms: int
    signing_key_id: str = ""
    signature: str = ""
    type: str = INSTRUCTION_TYPE

    def signing_bytes(self) -> bytes:
        body = asdict(self)
        body.pop("signature")
        return _canonical(body)

    def digest(self) -> str:
        return hashlib.sha256(self.signing_bytes()).hexdigest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "PaymentInstruction":
        data = json.loads(text)
        if data.get("type") != INSTRUCTION_TYPE:
            raise ValueError(f"not an AetherProof instruction: type={data.get('type')!r}")
        known = set(cls.__dataclass_fields__)
        ins = cls(**{k: v for k, v in data.items() if k in known})
        for name in ("amount_minor", "not_before_ms", "not_after_ms"):
            if not isinstance(getattr(ins, name), int) or isinstance(getattr(ins, name), bool):
                raise ValueError(f"{name} must be an integer")
        return ins


def sign_instruction(signer, *, originator: str, amount_minor: int, currency: str,
                     beneficiary: Dict[str, str], purpose: str, reference: str,
                     approval_ref: str, approved_by: str, policy: str,
                     validity_ms: int = DEFAULT_VALIDITY_MS, not_before_ms: int = 0,
                     instruction_id: str = "") -> PaymentInstruction:
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
        raise ValueError("amount_minor must be a positive integer (minor units)")
    if amount_minor > MAX_AMOUNT_MINOR:
        raise ValueError(f"amount_minor above the maximum {MAX_AMOUNT_MINOR}")
    if len(currency) != 3 or not currency.isalpha():
        raise ValueError("currency must be a 3-letter ISO 4217 code")
    if beneficiary.get("kind") not in ("bank", "token"):
        raise ValueError("beneficiary must come from bank_beneficiary() or token_beneficiary()")
    if validity_ms <= 0:
        raise ValueError("validity must be positive")
    instruction_id = instruction_id or f"ins_{secrets.token_hex(12)}"
    if len(instruction_id) > MAX_ID_LEN:
        raise ValueError(f"instruction_id longer than {MAX_ID_LEN} characters will not fit a provider reference")
    start = not_before_ms or _now_ms()
    ins = PaymentInstruction(
        instruction_id=instruction_id, originator=originator, amount_minor=amount_minor,
        currency=currency.upper(), beneficiary=dict(beneficiary), purpose=purpose, reference=reference,
        approval_ref=approval_ref, approved_by=approved_by, policy=policy,
        not_before_ms=start, not_after_ms=start + validity_ms,
        signing_key_id=Receipt.key_id(signer.get_public_key()),
    )
    ins.signature = signer.sign(ins.signing_bytes())
    return ins


# ------------------------------------------------------------------ executor side

class ReplayStore:
    """Remembers consumed instruction ids so one approval moves money once.

    The INSERT is the claim: a PRIMARY KEY makes two concurrent executors racing
    on the same instruction resolve to exactly one winner, across threads and
    processes. synchronous=FULL by default - forgetting a consumed id after a
    power cut would re-open it for replay.
    """

    def __init__(self, path: str, synchronous: str = "FULL"):
        if synchronous.upper() not in ("FULL", "NORMAL", "EXTRA"):
            raise ValueError(f"invalid synchronous mode: {synchronous}")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sync = synchronous.upper()
        self._local = threading.local()
        conn = self._conn()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS consumed (instruction_id TEXT PRIMARY KEY, "
                     "consumed_at_ms INTEGER NOT NULL, request_digest TEXT NOT NULL)")

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute(f"PRAGMA synchronous={self._sync}")
            self._local.conn = conn
        return conn

    def consume(self, instruction_id: str, request_digest: str) -> bool:
        """True if this call claimed the id; False if it was already consumed."""
        cur = self._conn().execute(
            "INSERT OR IGNORE INTO consumed VALUES (?, ?, ?)", (instruction_id, _now_ms(), request_digest))
        return cur.rowcount == 1

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


@dataclass
class PayoutRequest:
    """What the executor is about to send to the payment rail."""

    amount_minor: int
    currency: str
    reference: str = ""            # provider reference the payout will carry
    beneficiary_token: str = ""
    ifsc: str = ""
    account_number: str = ""

    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass
class Decision:
    verdict: str
    instruction_id: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def verify_instruction(ins: PaymentInstruction, request: PayoutRequest, public_keys,
                       replay: Optional[ReplayStore] = None, *, now_ms: Optional[int] = None) -> Decision:
    """Decide whether `request` may be executed under `ins`. Fails closed: any
    doubt is a reject, and the instruction is consumed only when everything else
    passed, so a rejected attempt cannot burn a legitimate instruction."""
    from .log import _as_keyring

    reasons = []
    if ins.type != INSTRUCTION_TYPE:
        reasons.append(f"unsupported instruction type {ins.type!r}")
    key = _as_keyring(public_keys).get(ins.signing_key_id)
    if key is None:
        reasons.append(f"no trusted originator key for signing_key_id={ins.signing_key_id}")
    elif not key.verify(ins.signing_bytes(), ins.signature):
        reasons.append("instruction signature invalid (altered or forged)")

    now = now_ms if now_ms is not None else _now_ms()
    if now < ins.not_before_ms:
        reasons.append("instruction not yet valid")
    elif now > ins.not_after_ms:
        reasons.append("instruction expired")

    if request.amount_minor != ins.amount_minor:
        reasons.append(f"amount {money(request.amount_minor, ins.currency)} differs from authorised {money(ins.amount_minor, ins.currency)}")
    if request.currency.upper() != ins.currency:
        reasons.append(f"currency {request.currency} differs from authorised {ins.currency}")
    if not beneficiary_matches(ins.beneficiary, token=request.beneficiary_token,
                               ifsc=request.ifsc, account_number=request.account_number):
        reasons.append("beneficiary differs from the authorised one")
    if request.reference and request.reference != ins.instruction_id:
        reasons.append("payout reference does not carry this instruction id")

    if reasons:
        return Decision(REJECT, ins.instruction_id, reasons)
    if not request.reference:
        # Valid in every hard check, but the payout would not carry the instruction id, so
        # the outcome could never be tied back. A person decides; nothing is consumed.
        return Decision(REVIEW, ins.instruction_id,
                        ["payout reference not set: outcome cannot be matched to this instruction"])
    if replay is None:
        # Fail closed: without a store, single use cannot be enforced, and an ALLOW here could
        # be repeated for ever. A person decides; nothing is consumed.
        return Decision(REVIEW, ins.instruction_id,
                        ["no replay store: single use cannot be enforced, so this payout is not allowed automatically"])
    if not replay.consume(ins.instruction_id, request.digest()):
        return Decision(REJECT, ins.instruction_id, ["instruction already used (replay)"])
    return Decision(ALLOW, ins.instruction_id, [])
