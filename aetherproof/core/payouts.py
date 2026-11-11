"""Outcome verification for payouts: did the rail execute what was authorised?

verify_instruction() guards the moment before money moves. This module checks
afterwards, from the payout provider's own records, and also catches what the
gate never saw: payouts sent around it with a stolen credential, which carry no
signed instruction at all.

Each instruction gets one verdict (matched / conflict / missing / ambiguous), and
every executed payout with no valid instruction is reported as a conflict.
Payouts are tied to instructions through the provider reference, which the
executor sets to the instruction id (RazorpayX: reference_id).
"""

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .hash import sha256
from .instruction import PaymentInstruction, beneficiary_matches, money
from .log import _as_keyring
from .reconcile import (AMBIGUOUS, CONFLICT, MATCHED, MISSING, ActionResult,
                        ReconciliationReport, canonical_json)

# The provider's clock is not the originator's, and providers stamp whole seconds
# (RazorpayX created_at), so a payout in the same second as its instruction can read
# as earlier than it. Window checks allow this much either side.
CLOCK_TOLERANCE_MS = 60_000

SUCCESS = {"processed", "success", "completed", "settled"}
FAILED = {"failed", "rejected", "cancelled", "reversed"}
PENDING = {"queued", "pending", "processing", "scheduled", "initiated"}

# column / key names per source. RazorpayX names follow its payout entity
# (amount in paise, created_at in unix seconds, reference_id up to 40 chars).
MAPPINGS = {
    "razorpayx": {"payout_id": "id", "reference": "reference_id", "amount_minor": "amount",
                  "currency": "currency", "status": "status", "time": "created_at",
                  "beneficiary_token": "fund_account_id", "utr": "utr"},
    "generic": {"payout_id": "payout_id", "reference": "reference", "amount_minor": "amount_minor",
                "currency": "currency", "status": "status", "time": "time",
                "beneficiary_token": "beneficiary_token", "ifsc": "ifsc",
                "account_number": "account_number", "utr": "utr"},
}


@dataclass
class PayoutRecord:
    payout_id: str
    reference: str
    amount_minor: int
    currency: str
    status: str
    time_ms: int
    beneficiary_token: str = ""
    ifsc: str = ""
    account_number: str = ""
    utr: str = ""
    record_hash: str = ""


def _time_ms(value) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)) or str(value).strip().isdigit():
        n = int(float(value))
        return n * 1000 if n < 10**12 else n          # unix seconds or milliseconds
    return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)


def payout_from_row(row: Dict, mapping: Dict[str, str]) -> PayoutRecord:
    def get(name):
        col = mapping.get(name)
        v = row.get(col) if col else None
        return "" if v is None else v

    amount = get("amount_minor")
    if isinstance(amount, float) or (isinstance(amount, str) and not amount.strip().lstrip("-").isdigit()):
        raise ValueError(f"payout {get('payout_id')}: amount must be an integer in minor units, got {amount!r}")
    return PayoutRecord(
        payout_id=str(get("payout_id")), reference=str(get("reference")), amount_minor=int(amount),
        currency=str(get("currency")).upper(), status=str(get("status")).lower(), time_ms=_time_ms(get("time")),
        beneficiary_token=str(get("beneficiary_token")), ifsc=str(get("ifsc")),
        account_number=str(get("account_number")), utr=str(get("utr")),
        record_hash=sha256(canonical_json(row)),
    )


def load_payouts(path, source: str = "generic") -> List[PayoutRecord]:
    """CSV with a header row, a JSON list, a provider collection ({"items": [...]}),
    or JSON lines."""
    if source not in MAPPINGS:
        raise ValueError(f"unknown payout source {source!r}; known: {', '.join(MAPPINGS)}")
    mapping = MAPPINGS[source]
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if p.suffix.lower() == ".csv":
        rows = list(csv.DictReader(text.splitlines()))
    elif text[0] == "{" and "\n{" in text:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        data = json.loads(text)
        rows = data.get("items", [data]) if isinstance(data, dict) else data
    return [payout_from_row(r, mapping) for r in rows]


def _compare(ins: PaymentInstruction, p: PayoutRecord) -> List[str]:
    diffs = []
    if p.amount_minor != ins.amount_minor:
        diffs.append(f"paid {money(p.amount_minor, ins.currency)}, authorised {money(ins.amount_minor, ins.currency)}")
    if p.currency and p.currency != ins.currency:
        diffs.append(f"currency {p.currency}, authorised {ins.currency}")
    if p.beneficiary_token or (p.ifsc and p.account_number):
        if not beneficiary_matches(ins.beneficiary, token=p.beneficiary_token, ifsc=p.ifsc,
                                   account_number=p.account_number):
            diffs.append("paid to a different beneficiary")
    else:
        diffs.append("payout record carries no beneficiary to check")
    if p.time_ms and not (ins.not_before_ms - CLOCK_TOLERANCE_MS <= p.time_ms <= ins.not_after_ms + CLOCK_TOLERANCE_MS):
        diffs.append("payout created outside the instruction's validity window")
    return diffs


def _check_signatures(instructions: List[PaymentInstruction], keys) -> List[bool]:
    """Ed25519 checks are ~70% of reconcile time; the library releases the GIL, so a
    thread pool gives ~3x on large batches (measured 20k verifies: 1.54 s -> 0.47 s)."""
    def ok(ins: PaymentInstruction) -> bool:
        key = keys.get(ins.signing_key_id)
        return key is not None and key.verify(ins.signing_bytes(), ins.signature)

    if len(instructions) < 2_000:
        return [ok(i) for i in instructions]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(ok, instructions, chunksize=500))


def reconcile_payouts(instructions: Iterable[PaymentInstruction], payouts: Iterable[PayoutRecord],
                      public_keys, *, as_of_ms: Optional[int] = None) -> ReconciliationReport:
    keys = _as_keyring(public_keys)
    as_of = as_of_ms if as_of_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    report = ReconciliationReport(as_of_ms=as_of)

    # One payout, many records: providers resend webhooks and exports repeat rows, and a
    # payout moves processing -> processed -> reversed. Keep each payout's latest state;
    # counting every row made one payout read as "paid twice".
    latest: Dict[str, PayoutRecord] = {}
    for p in payouts:
        prev = latest.get(p.payout_id)
        if prev is None or p.time_ms >= prev.time_ms:
            latest[p.payout_id] = p
    by_ref: Dict[str, List[PayoutRecord]] = {}
    for p in latest.values():
        by_ref.setdefault(p.reference, []).append(p)

    instructions = list(instructions)
    signed_ok = _check_signatures(instructions, keys)
    trusted = set()
    for ins, sig_ok in zip(instructions, signed_ok):
        res = ActionResult(MATCHED, action_id=ins.instruction_id, basis="reference")
        if not sig_ok:
            res.verdict = CONFLICT
            res.reasons = ["instruction not signed by a trusted originator key"]
            report.results.append(res)
            continue
        trusted.add(ins.instruction_id)
        records = by_ref.get(ins.instruction_id, [])
        res.event_ids = [p.payout_id for p in records]
        done = [p for p in records if p.status in SUCCESS]
        failed = [p for p in records if p.status in FAILED]
        pending = [p for p in records if p.status in PENDING]
        unknown = [p for p in records if p.status not in SUCCESS | FAILED | PENDING]

        if len(done) > 1:
            res.verdict = CONFLICT
            res.reasons = [f"authorised once, paid {len(done)} times"]
        elif done:
            res.reasons = _compare(ins, done[0])
            res.verdict = CONFLICT if res.reasons else MATCHED
        elif pending or unknown:
            res.verdict = AMBIGUOUS
            res.reasons = [f"payout status {', '.join(sorted({p.status for p in pending + unknown}))}"]
        elif failed:
            res.verdict = MISSING
            res.reasons = [f"payout {', '.join(sorted({p.status for p in failed}))}"]
        elif as_of <= ins.not_after_ms:
            res.verdict = AMBIGUOUS
            res.reasons = ["no payout yet; instruction still valid"]
        else:
            res.verdict = MISSING
            res.reasons = ["no payout for this instruction"]
            res.basis = ""
        report.results.append(res)

    for ref, records in by_ref.items():
        if ref in trusted:
            continue
        for p in records:
            if p.status in FAILED:
                continue
            report.results.append(ActionResult(
                CONFLICT, action_id=ref, event_ids=[p.payout_id], basis="reference", kind="unapproved_event",
                reasons=[f"{money(p.amount_minor, p.currency)} paid out ({p.payout_id}, {p.status}) with no valid signed instruction"]))
    return report
