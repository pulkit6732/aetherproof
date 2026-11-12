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
import re
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
        self.credits = [e for e in entries if e.direction == "credit"]
        self.credit_keys: Dict[str, List[BankEntry]] = {}
        for c in self.credits:
            for k in {c.utr, *re.split(r"[^A-Za-z0-9_\-]+", c.narration)} - {""}:
                self.credit_keys.setdefault(k, []).append(c)
        self.used: set = set()
        self.as_of, self.grace = as_of_ms, grace_ms
        self.by_utr: Dict[str, BankEntry] = {e.utr: e for e in self.debits if e.utr}
        # Narration fallback matches whole tokens only: a substring test let "pout_n12" claim the
        # debit for "pout_n123" (measured: 1,005 false alarms in 16,400 clean payouts).
        self.by_token: Dict[str, List[BankEntry]] = {}
        for d in self.debits:
            for tok in set(re.split(r"[^A-Za-z0-9_\-]+", d.narration)):
                if tok:
                    self.by_token.setdefault(tok, []).append(d)

    def _find(self, payout_id: str, utr: str) -> Optional[BankEntry]:
        e = self.by_utr.get(utr) if utr else None
        if e is None and payout_id:  # fall back to the payout id quoted in the narration
            e = next((d for d in self.by_token.get(payout_id, []) if d.entry_id not in self.used), None)
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

    def reversal(self, payout_id: str, utr: str, amount_minor: int) -> Tuple[str, str]:
        """For a payout the provider reports reversed: if its debit is on the statement, the
        money must also have come back as a credit of the same amount (by UTR or payout id)."""
        e = self._find(payout_id, utr)
        if e is None:
            return "", ""                       # money never left: consistent with the reversal
        self.used.add(e.entry_id)
        keys = {utr, e.utr, payout_id} - {""}
        back = next((c for k in keys for c in self.credit_keys.get(k, [])
                     if c.amount_minor == amount_minor and c.entry_id not in self.used), None)
        if back is not None:
            self.used.add(back.entry_id)
            return "returned", ""
        if self.as_of >= e.time_ms + self.grace:
            return "absent", "provider reports the payout reversed, but the bank shows the debit and no return credit"
        return "pending", "reversal credit not yet visible in the bank statement"

    def unexplained(self) -> List[BankEntry]:
        """Debits no successful payout used. A debit returned by a credit with the same UTR and
        amount (a reversal: money left, then came back) is explained and not reported."""
        returned = {(c.utr, c.amount_minor) for c in self.credits if c.utr}
        return [d for d in self.debits if d.entry_id not in self.used and (d.utr, d.amount_minor) not in returned]
