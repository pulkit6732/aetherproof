"""Independent settlement evidence: does the bank statement show the money the provider says moved?

A payout provider's own record can be wrong or manipulated. In 2022 forged authorisation
responses made Razorpay record 831 failed payments as approved (Rs 7.38 crore). A provider
"processed" status is therefore a claim, and the bank statement is the independent check:

    confirmed  a debit on the statement matches the payout (UTR, or payout id in the narration)
    mismatch   the matching debit is for a different amount
    absent     provider says processed, the grace period has passed, no debit exists
    pending    no debit yet, still inside the grace period (never treated as fraud)

Debits that no payout explains are reported separately (unexplained_debit).
"""

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .hash import sha256

# Banks post debits after the provider reports success; IMPS/UPI are near-instant, NEFT and
# batch files can take a working day. A missing debit is only "absent" after this long.
DEFAULT_SETTLEMENT_GRACE_MS = 2 * 24 * 3600 * 1000

COLUMNS = ("entry_id", "utr", "amount_minor", "currency", "direction", "time", "narration")


@dataclass
class BankEntry:
    entry_id: str
    utr: str
    amount_minor: int
    currency: str
    direction: str      # "debit" or "credit"; only debits settle payouts
    time_ms: int
    narration: str = ""
    record_hash: str = ""


def _canonical(row: Dict) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_from_row(row: Dict) -> BankEntry:
    from .payouts import _time_ms
    amount = row.get("amount_minor")
    if isinstance(amount, bool) or not (isinstance(amount, int) or (isinstance(amount, str) and amount.strip().lstrip("-").isdigit())):
        raise ValueError(f"bank entry {row.get('entry_id')}: amount_minor must be an integer, got {amount!r}")
    direction = str(row.get("direction", "")).strip().lower()
    if direction not in ("debit", "credit"):
        raise ValueError(f"bank entry {row.get('entry_id')}: direction must be debit or credit")
    return BankEntry(entry_id=str(row.get("entry_id", "")), utr=str(row.get("utr") or "").strip(),
                     amount_minor=abs(int(amount)), currency=str(row.get("currency", "")).upper(),
                     direction=direction, time_ms=_time_ms(row.get("time")), narration=str(row.get("narration") or ""),
                     record_hash=sha256(_canonical(row)))


def load_statement(path) -> List[BankEntry]:
    """CSV with a header (columns: entry_id, utr, amount_minor, currency, direction, time,
    narration) or a JSON list of the same objects."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    rows = list(csv.DictReader(text.splitlines())) if p.suffix.lower() == ".csv" else json.loads(text)
    if isinstance(rows, dict):
        rows = rows.get("entries", [])
    return [entry_from_row(r) for r in rows]


class SettlementBook:
    """Matches successful payouts to statement debits, each debit used once."""

    def __init__(self, entries: List[BankEntry], as_of_ms: int, grace_ms: int = DEFAULT_SETTLEMENT_GRACE_MS):
        self.debits = [e for e in entries if e.direction == "debit"]
        self.used: set = set()
        self.as_of, self.grace = as_of_ms, grace_ms
        self.by_utr: Dict[str, BankEntry] = {e.utr: e for e in self.debits if e.utr}

    def _find(self, payout_id: str, utr: str) -> Optional[BankEntry]:
        e = self.by_utr.get(utr) if utr else None
        if e is None:  # fall back to the payout id quoted in the narration
            e = next((d for d in self.debits if payout_id and payout_id in d.narration and d.entry_id not in self.used), None)
        return e if e is not None and e.entry_id not in self.used else None

    def check(self, payout_id: str, utr: str, amount_minor: int, payout_time_ms: int) -> Tuple[str, str, Optional[BankEntry]]:
        """(state, reason, entry) for one successful payout."""
        from .instruction import money
        e = self._find(payout_id, utr)
        if e is not None:
            self.used.add(e.entry_id)
            if e.amount_minor != amount_minor:
                return "mismatch", f"bank debited {money(e.amount_minor, e.currency)}, provider reported {money(amount_minor, e.currency)}", e
            return "confirmed", "", e
        if self.as_of >= payout_time_ms + self.grace:
            return "absent", "provider reports the payout processed, but the bank statement shows no matching debit", None
        return "pending", "settlement not yet visible in the bank statement", None

    def unexplained(self) -> List[BankEntry]:
        return [d for d in self.debits if d.entry_id not in self.used]
