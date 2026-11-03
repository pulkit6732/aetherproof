"""Signed log checkpoints, optionally time stamped by an independent TSA.

The hash chain catches edits, reordering and deletions in the middle of the log,
but not deleting the newest entries: a truncated chain is still a valid chain.
A checkpoint records (log_size, head_entry_hash) under the log key. Kept
somewhere the log's operator does not control - sent to the customer, an
auditor, a witness - it makes truncation and rewriting detectable:

    log shorter than the checkpoint             -> truncated
    entry at log_size has a different hash      -> rewritten

With a TSA token, the checkpoint also proves every covered receipt existed no
later than the TSA's genTime, which no longer depends on the signer's clock.
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from .log import ReceiptLog, _as_keyring
from .receipt import Receipt

CHECKPOINT_TYPE = "aetherproof.checkpoint/v1"
# A signer clock further than this from the TSA's genTime is reported - it is
# exactly the backdating an independent time source exists to expose.
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000


@dataclass
class Checkpoint:
    log_size: int
    head_entry_hash: str
    created_at_ms: int
    signing_key_id: str
    signature: str = ""
    timestamp_token: str = ""   # base64 DER RFC 3161 token over digest()
    type: str = CHECKPOINT_TYPE

    def signing_bytes(self) -> bytes:
        # length-prefixed like Receipt.canonical_message, so fields cannot bleed together
        fields = [self.type, str(self.log_size), self.head_entry_hash,
                  str(self.created_at_ms), self.signing_key_id]
        return "".join(f"{len(f)}:{f}" for f in fields).encode("utf-8")

    def digest(self) -> bytes:
        """What the TSA time stamps: the signed statement plus its signature."""
        return hashlib.sha256(self.signing_bytes() + bytes.fromhex(self.signature)).digest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Checkpoint":
        data = json.loads(text)
        if data.get("type") != CHECKPOINT_TYPE:
            raise ValueError(f"not an AetherProof checkpoint: type={data.get('type')!r}")
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


def create_checkpoint(log: ReceiptLog, signer, *, tsa_url: str = "") -> Checkpoint:
    """Sign the log's current head. With `tsa_url`, also fetch an RFC 3161 token."""
    size = log.max_sequence()
    if size == 0:
        raise ValueError("log is empty; nothing to checkpoint")
    row = log.get_by_sequence(size)
    cp = Checkpoint(
        log_size=size,
        head_entry_hash=row["entry_hash"],
        created_at_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        signing_key_id=Receipt.key_id(signer.get_public_key()),
    )
    cp.signature = signer.sign(cp.signing_bytes())
    if tsa_url:
        from .timestamp import request_timestamp
        token, _nonce = request_timestamp(tsa_url, cp.digest())
        cp.timestamp_token = base64.b64encode(token).decode("ascii")
    return cp


@dataclass
class CheckpointReport:
    ok: bool = False
    problems: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tsa_time: Optional[str] = None      # ISO 8601, only when the token verified
    tsa_subject: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def verify_checkpoint(cp: Checkpoint, log: ReceiptLog, public_keys, *,
                      tsa_roots: Iterable = ()) -> CheckpointReport:
    """Check a checkpoint against the current log.

    `tsa_roots`: CA certificates trusted for time stamping. If the checkpoint has
    a token and no roots are given, the time is reported as unchecked rather than
    accepted.
    """
    rep = CheckpointReport()
    key = _as_keyring(public_keys).get(cp.signing_key_id)
    if key is None:
        rep.problems.append(f"no trusted key for signing_key_id={cp.signing_key_id}")
    elif not key.verify(cp.signing_bytes(), cp.signature):
        rep.problems.append("checkpoint signature invalid")

    have = log.max_sequence()
    if have < cp.log_size:
        rep.problems.append(f"truncated: log has {have} entries, checkpoint recorded {cp.log_size}")
    else:
        row = log.get_by_sequence(cp.log_size)
        if row is None or row["entry_hash"] != cp.head_entry_hash:
            rep.problems.append(f"rewritten: entry {cp.log_size} no longer matches the checkpoint")
    integrity = log.verify_integrity_report()
    if not integrity.ok:
        rep.problems.append(f"log chain broken at {integrity.broken_at}: {integrity.reason}")
    if have > cp.log_size:
        rep.notes.append(f"{have - cp.log_size} entries added after this checkpoint (not covered by it)")

    if cp.timestamp_token:
        roots = list(tsa_roots)
        if not roots:
            rep.notes.append("time stamp present but not checked: no trusted TSA root given")
        else:
            from .timestamp import TimestampError, verify_token
            try:
                ts = verify_token(base64.b64decode(cp.timestamp_token), cp.digest(), roots)
                rep.tsa_time = ts.gen_time.isoformat()
                rep.tsa_subject = ts.tsa_subject
                skew = abs(ts.gen_time.timestamp() * 1000 - cp.created_at_ms)
                if skew > MAX_CLOCK_SKEW_MS:
                    rep.problems.append(f"signer clock differs from TSA time by {skew / 1000:.0f} s")
            except TimestampError as e:
                rep.problems.append(f"time stamp invalid: {e}")
    else:
        rep.notes.append("no independent time stamp; created_at is the signer's own clock")

    rep.ok = not rep.problems
    return rep
