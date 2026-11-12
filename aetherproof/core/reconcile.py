"""Action reconciliation: approved intent vs. what the destination system recorded.

A receipt proves a record was not edited. It cannot say whether the change that
happened in the destination system is the change that was approved - the agent
writes its own log, so a manipulated agent's log agrees with itself. This module
joins three records the agent does not control together:

    approval receipt (signed)  ->  destination event (e.g. AWS CloudTrail)  ->  verdict

and returns one verdict per approved action:

    matched    exactly one successful event, same operation, resource and params,
               inside the approved window
    conflict   an event happened but differs from the approval (or happened more
               than once, or the approval receipt itself fails verification);
               also used for state-changing events no approval covers
    missing    the window closed and no successful event exists
    ambiguous  the evidence cannot decide: several uncorrelated candidates, or the
               window is still open

Correlation is by `action_id`. On AWS the agent assumes its role with
`SourceIdentity=<action_id>`, which CloudTrail records as
`userIdentity.sessionContext.sourceIdentity` on every call made in that session.
Without it, matching falls back to operation + resource + time and the result
says so (basis="operation+resource+time").
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .hash import sha256
from .receipt import Receipt

ACTION_NS = "org.aetherproof.action/v1"

from ..contract import AMBIGUOUS, CONFLICT, MATCHED, MISSING  # noqa: E402  single definition

DEFAULT_WINDOW_MS = 15 * 60 * 1000


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class ApprovedAction:
    """What a person or policy approved. Stored as a signed receipt extension.

    Every value is a string because the extension commitment canonicalises
    strings only (see Receipt._canonicalize); params travel as canonical JSON.
    """

    action_id: str
    actor: str          # identity expected to perform it (e.g. an IAM role ARN)
    operation: str      # "<service>:<Action>", the IAM action name, e.g. "s3:DeleteObject"
    resource: str       # e.g. "arn:aws:s3:::invoices/2026/1042.pdf"
    params: Dict[str, Any] = field(default_factory=dict)  # must all appear in the event
    approved_by: str = ""
    approval_ref: str = ""   # ticket / change request id
    not_before_ms: int = 0
    not_after_ms: int = 0

    def to_extension(self) -> Dict[str, str]:
        return {
            "action_id": self.action_id,
            "actor": self.actor,
            "operation": self.operation,
            "resource": self.resource,
            "params_json": canonical_json(self.params),
            "approved_by": self.approved_by,
            "approval_ref": self.approval_ref,
            "not_before_ms": str(self.not_before_ms),
            "not_after_ms": str(self.not_after_ms),
        }

    @classmethod
    def from_extension(cls, ext: Dict[str, str]) -> "ApprovedAction":
        return cls(
            action_id=ext["action_id"],
            actor=ext.get("actor", ""),
            operation=ext["operation"],
            resource=ext["resource"],
            params=json.loads(ext.get("params_json") or "{}"),
            approved_by=ext.get("approved_by", ""),
            approval_ref=ext.get("approval_ref", ""),
            not_before_ms=int(ext.get("not_before_ms") or 0),
            not_after_ms=int(ext.get("not_after_ms") or 0),
        )

    def digest(self) -> str:
        """Bound into the receipt as output_hash, so the receipt names this intent."""
        return sha256(canonical_json(self.to_extension()))


def issue_action_receipt(signer, log, action: ApprovedAction, *,
                         window_ms: int = DEFAULT_WINDOW_MS, receipts_dir: Path = None):
    """Sign and log an approval. Defaults the window to [now, now + window_ms]."""
    from .keystore import issue_receipt

    now = int(datetime.now(timezone.utc).timestamp() * 1000)
    if not action.not_before_ms:
        action.not_before_ms = now
    if not action.not_after_ms:
        action.not_after_ms = action.not_before_ms + window_ms
    if action.not_after_ms <= action.not_before_ms:
        raise ValueError("approval window must end after it starts")
    return issue_receipt(
        signer, log,
        model_weight_root=sha256(f"actor:{action.actor}"),
        model_root_type="name_only",
        output_hash=action.digest(),
        receipts_dir=receipts_dir,
        extensions={ACTION_NS: action.to_extension()},
    )


@dataclass
class DestinationEvent:
    """One record from the system that was changed, normalised."""

    event_id: str
    operation: str
    resources: List[str]
    params: Dict[str, Any]
    time_ms: int
    actor: str = ""
    correlation_id: str = ""
    error: str = ""          # non-empty when the call failed, so nothing changed
    read_only: bool = False
    source: str = ""
    record_hash: str = ""    # sha256 of the raw record, for the evidence trail


def _parse_time_ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def from_cloudtrail(record: Dict[str, Any]) -> DestinationEvent:
    """Normalise one CloudTrail record (management or data event)."""
    service = record.get("eventSource", "").split(".")[0]
    identity = record.get("userIdentity") or {}
    session = identity.get("sessionContext") or {}
    resources = [r["ARN"] for r in record.get("resources") or [] if r.get("ARN")]
    read_only = record.get("readOnly")
    if isinstance(read_only, str):
        read_only = read_only.lower() == "true"
    return DestinationEvent(
        event_id=record.get("eventID", ""),
        operation=f"{service}:{record.get('eventName', '')}",
        resources=resources,
        params=record.get("requestParameters") or {},
        time_ms=_parse_time_ms(record["eventTime"]),
        actor=identity.get("arn", ""),
        correlation_id=session.get("sourceIdentity", ""),
        error=record.get("errorCode", "") or "",
        read_only=bool(read_only),
        source="aws.cloudtrail",
        record_hash=sha256(canonical_json(record)),
    )


def load_cloudtrail(path) -> List[DestinationEvent]:
    """Read a CloudTrail file: {"Records": [...]} as delivered to S3, a JSON list,
    or JSON lines (one record per line, as exported by CloudTrail Lake queries)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "{" and "\n{" in text:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        data = json.loads(text)
        records = data.get("Records", [data]) if isinstance(data, dict) else data
    return [from_cloudtrail(r) for r in records]


@dataclass
class ActionResult:
    verdict: str
    action_id: str = ""
    receipt_id: str = ""
    event_ids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    basis: str = ""          # "correlation_id" | "operation+resource+time" | "" (no event)
    kind: str = "approval"   # "approval" | "unapproved_event" | "unexplained_debit"
    settlement: str = ""     # payouts only: confirmed | mismatch | absent | pending | returned | not_checked


@dataclass
class ReconciliationReport:
    results: List[ActionResult] = field(default_factory=list)
    as_of_ms: int = 0

    def counts(self) -> Dict[str, int]:
        out = {MATCHED: 0, CONFLICT: 0, MISSING: 0, AMBIGUOUS: 0}
        for r in self.results:
            out[r.verdict] += 1
        return out

    @property
    def ok(self) -> bool:
        return all(r.verdict == MATCHED for r in self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "as_of_ms": self.as_of_ms, "counts": self.counts(),
                "results": [asdict(r) for r in self.results]}


def _subset_mismatches(approved: Any, actual: Any, path: str = "") -> List[str]:
    """Every approved key must be present in the event with an equal value.
    Extra keys in the event are allowed: services add their own parameters."""
    if isinstance(approved, dict) and isinstance(actual, dict):
        out = []
        for k, v in approved.items():
            if k not in actual:
                out.append(f"param {path + k} missing from event")
            else:
                out.extend(_subset_mismatches(v, actual[k], f"{path}{k}."))
        return out
    if approved != actual:
        return [f"param {path.rstrip('.')} approved {approved!r}, event has {actual!r}"]
    return []


def _compare(action: ApprovedAction, event: DestinationEvent) -> List[str]:
    diffs = []
    if event.operation != action.operation:
        diffs.append(f"operation approved {action.operation}, event did {event.operation}")
    if event.resources and action.resource not in event.resources:
        diffs.append(f"resource approved {action.resource}, event touched {', '.join(event.resources)}")
    if action.actor and event.actor and event.actor != action.actor:
        diffs.append(f"actor approved {action.actor}, event by {event.actor}")
    if not (action.not_before_ms <= event.time_ms <= action.not_after_ms):
        diffs.append("event time outside the approved window")
    diffs.extend(_subset_mismatches(action.params, event.params))
    return diffs


def _keyring(public_keys) -> Dict[str, Any]:
    from .log import _as_keyring
    return _as_keyring(public_keys)


def _approval_from(receipt: Receipt, keys: Dict[str, Any]):
    """Return (action, problem). problem is set when the approval cannot be trusted."""
    ext = receipt.signed_extensions.get(ACTION_NS)
    if not ext:
        return None, "receipt carries no approved action"
    key = keys.get(receipt.signing_key_id) if receipt.signing_key_id else None
    candidates = [key] if key else ([] if receipt.signing_key_id else list(keys.values()))
    if not candidates:
        return None, f"no trusted key for signing_key_id={receipt.signing_key_id}"
    if not any(k.verify(receipt.signing_bytes(), receipt.signature) for k in candidates):
        return None, "approval receipt fails signature check"
    try:
        action = ApprovedAction.from_extension(ext)
    except (KeyError, ValueError) as e:
        return None, f"approved action is malformed: {e}"
    if receipt.output_hash != action.digest():
        return None, "receipt output_hash does not commit to the approved action"
    return action, ""


def reconcile(receipts: Iterable[Receipt], events: Iterable[DestinationEvent], public_keys, *,
              agent_actors: Iterable[str] = (), as_of_ms: Optional[int] = None) -> ReconciliationReport:
    """Reconcile approval receipts against destination events.

    `public_keys`: the approvers' keys you trust (a Verifier, list, or {key_id: Verifier}).
    Receipts are never trusted on their own say-so: a receipt signed by a key not
    in this set is reported, not matched.
    `agent_actors`: identities (exact ARN or ARN prefix) whose state-changing
    events must each be covered by an approval; uncovered ones are conflicts.
    `as_of_ms`: "now" for deciding whether a window has closed (default: wall clock).
    """
    keys = _keyring(public_keys)
    events = list(events)
    as_of = as_of_ms if as_of_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    report = ReconciliationReport(as_of_ms=as_of)

    approvals = []
    for rcpt in receipts:
        action, problem = _approval_from(rcpt, keys)
        if problem:
            report.results.append(ActionResult(CONFLICT, receipt_id=rcpt.receipt_id, reasons=[problem]))
        else:
            approvals.append((rcpt, action))

    known_ids = {a.action_id for _, a in approvals}
    used = set()
    # index once: scanning every event per approval was O(approvals x events)
    by_correlation: Dict[str, List[DestinationEvent]] = {}
    untagged_by_op: Dict[str, List[DestinationEvent]] = {}
    for e in events:
        if e.read_only:
            continue
        if e.correlation_id:
            by_correlation.setdefault(e.correlation_id, []).append(e)
        else:
            untagged_by_op.setdefault(e.operation, []).append(e)

    for rcpt, action in approvals:
        res = ActionResult(MATCHED, action_id=action.action_id, receipt_id=rcpt.receipt_id)
        correlated = by_correlation.get(action.action_id, [])
        if correlated:
            res.basis = "correlation_id"
            candidates = correlated
        else:
            # fallback: same operation on the same resource inside the window. Only
            # untagged events qualify - one tagged with a different action id
            # belongs to that action, and claiming it here let a mis-tagged
            # (unapproved) change pass as this approval's evidence.
            res.basis = "operation+resource+time"
            candidates = [e for e in untagged_by_op.get(action.operation, [])
                          if (not e.resources or action.resource in e.resources)
                          and action.not_before_ms <= e.time_ms <= action.not_after_ms
                          and e.event_id not in used]

        succeeded = [e for e in candidates if not e.error]
        failed = [e for e in candidates if e.error]
        res.event_ids = [e.event_id for e in candidates]
        used.update(res.event_ids)

        if not succeeded:
            res.basis = res.basis if candidates else ""
            if failed:
                res.verdict = MISSING
                res.reasons = [f"attempted but failed: {', '.join(sorted({e.error for e in failed}))}"]
            elif as_of <= action.not_after_ms:
                res.verdict = AMBIGUOUS
                res.reasons = ["no event yet; approval window still open"]
            else:
                res.verdict = MISSING
                res.reasons = ["no destination event inside the approved window"]
        elif len(succeeded) > 1 and res.basis == "correlation_id":
            res.verdict = CONFLICT
            res.reasons = [f"approved once, executed {len(succeeded)} times"]
            for e in succeeded:
                res.reasons.extend(_compare(action, e))
        elif len(succeeded) > 1:
            res.verdict = AMBIGUOUS
            res.reasons = [f"{len(succeeded)} events match on operation, resource and time, none carries the action id"]
        else:
            diffs = _compare(action, succeeded[0])
            if diffs:
                res.verdict = CONFLICT
                res.reasons = diffs
        report.results.append(res)

    prefixes = tuple(agent_actors)
    for e in events:
        if e.event_id in used or e.read_only or e.error:
            continue
        unknown_correlation = e.correlation_id and e.correlation_id not in known_ids
        if unknown_correlation or (prefixes and e.actor.startswith(prefixes)):
            report.results.append(ActionResult(
                CONFLICT, action_id=e.correlation_id, event_ids=[e.event_id],
                reasons=[f"{e.operation} on {', '.join(e.resources) or 'unknown resource'} by {e.actor or 'unknown actor'} has no approval"],
                basis="correlation_id" if e.correlation_id else "actor",
                kind="unapproved_event",
            ))
    return report
