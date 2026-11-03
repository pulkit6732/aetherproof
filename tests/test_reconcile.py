"""Action reconciliation: approval receipts vs. CloudTrail records.

The CloudTrail records follow the documented record format (eventSource,
eventName, eventTime, userIdentity.sessionContext.sourceIdentity, resources,
requestParameters, errorCode, readOnly) - the fields the reconciler reads.
"""

import json
from datetime import datetime, timezone

import pytest

from aetherproof.core.log import ReceiptLog
from aetherproof.core.receipt import Receipt
from aetherproof.core.reconcile import (ACTION_NS, AMBIGUOUS, CONFLICT, MATCHED, MISSING,
                                        ApprovedAction, from_cloudtrail, issue_action_receipt,
                                        load_cloudtrail, reconcile)
from aetherproof.core.signer import Signer

ROLE = "arn:aws:sts::111122223333:assumed-role/viewer-7/session"
BUCKET_OBJ = "arn:aws:s3:::invoices/2026/1042.pdf"
T0 = 1_793_000_000_000            # fixed approval start (Nov 2026), so tests do not depend on the clock
WINDOW = 15 * 60 * 1000


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ct(event_id, *, name="DeleteObject", source="s3.amazonaws.com", at=T0 + 60_000, arn=BUCKET_OBJ,
       params=None, sid="act-1", actor=ROLE, error=None, read_only=False):
    rec = {
        "eventVersion": "1.09", "eventID": event_id, "eventTime": _iso(at),
        "eventSource": source, "eventName": name, "awsRegion": "ap-south-1",
        "userIdentity": {"type": "AssumedRole", "arn": actor,
                         "sessionContext": {"sourceIdentity": sid} if sid else {}},
        "requestParameters": params if params is not None else {"bucketName": "invoices", "key": "2026/1042.pdf"},
        "resources": [{"type": "AWS::S3::Object", "ARN": arn}] if arn else [],
        "readOnly": read_only,
    }
    if error:
        rec["errorCode"] = error
    return rec


@pytest.fixture
def env(tmp_path):
    signer = Signer.generate()
    log = ReceiptLog(str(tmp_path / "log.db"))
    yield signer, log, tmp_path
    log.close()


def approve(env, action_id="act-1", *, operation="s3:DeleteObject", resource=BUCKET_OBJ, params=None):
    signer, log, tmp = env
    action = ApprovedAction(action_id=action_id, actor=ROLE, operation=operation, resource=resource,
                            params=params if params is not None else {"bucketName": "invoices", "key": "2026/1042.pdf"},
                            approved_by="finance-lead@example.com", approval_ref="CHG-2041",
                            not_before_ms=T0, not_after_ms=T0 + WINDOW)
    receipt, _ = issue_action_receipt(signer, log, action, receipts_dir=tmp / "r")
    return receipt


def run(env, receipts, records, **kw):
    kw.setdefault("as_of_ms", T0 + 2 * WINDOW)
    return reconcile(receipts, [from_cloudtrail(r) for r in records], env[0].get_public_key(), **kw)


def only(report):
    assert len(report.results) == 1, report.to_dict()
    return report.results[0]


def test_matching_event_is_matched_by_source_identity(env):
    rep = run(env, [approve(env)], [ct("e1")])
    res = only(rep)
    assert res.verdict == MATCHED and res.basis == "correlation_id" and res.event_ids == ["e1"]
    assert rep.ok


def test_extra_service_parameters_do_not_cause_a_conflict(env):
    params = {"bucketName": "invoices", "key": "2026/1042.pdf", "Host": "invoices.s3.ap-south-1.amazonaws.com"}
    assert only(run(env, [approve(env)], [ct("e1", params=params)])).verdict == MATCHED


def test_different_parameter_is_a_conflict(env):
    res = only(run(env, [approve(env)], [ct("e1", params={"bucketName": "invoices", "key": "2026/9999.pdf"})]))
    assert res.verdict == CONFLICT and any("key" in r for r in res.reasons)


def test_different_resource_is_a_conflict(env):
    res = only(run(env, [approve(env)], [ct("e1", arn="arn:aws:s3:::payroll/2026/all.csv")]))
    assert res.verdict == CONFLICT and any("resource" in r for r in res.reasons)


def test_different_operation_is_a_conflict(env):
    res = only(run(env, [approve(env)], [ct("e1", name="DeleteBucket", arn="arn:aws:s3:::invoices")]))
    assert res.verdict == CONFLICT and any("operation" in r for r in res.reasons)


def test_event_outside_window_is_a_conflict(env):
    # CloudTrail eventTime has 1 s resolution, so "just after" means one second after
    res = only(run(env, [approve(env)], [ct("e1", at=T0 + WINDOW + 1000)]))
    assert res.verdict == CONFLICT and any("window" in r for r in res.reasons)


def test_window_boundaries_are_inclusive(env):
    rcpts = [approve(env, "a"), approve(env, "b")]
    rep = run(env, rcpts, [ct("e1", sid="a", at=T0), ct("e2", sid="b", at=T0 + WINDOW)])
    assert [r.verdict for r in rep.results] == [MATCHED, MATCHED]


def test_no_event_after_window_is_missing(env):
    res = only(run(env, [approve(env)], []))
    assert res.verdict == MISSING and res.basis == ""


def test_no_event_while_window_open_is_ambiguous_not_missing(env):
    res = only(run(env, [approve(env)], [], as_of_ms=T0 + 1000))
    assert res.verdict == AMBIGUOUS and "still open" in res.reasons[0]


def test_failed_attempt_is_missing_with_the_error(env):
    res = only(run(env, [approve(env)], [ct("e1", error="AccessDenied")]))
    assert res.verdict == MISSING and "AccessDenied" in res.reasons[0]


def test_retry_after_failure_still_matches(env):
    res = only(run(env, [approve(env)], [ct("e1", error="SlowDown"), ct("e2", at=T0 + 90_000)]))
    assert res.verdict == MATCHED and res.event_ids == ["e1", "e2"]


def test_executed_twice_is_a_conflict(env):
    res = only(run(env, [approve(env)], [ct("e1"), ct("e2", at=T0 + 120_000)]))
    assert res.verdict == CONFLICT and "executed 2 times" in res.reasons[0]


def test_single_uncorrelated_event_matches_on_the_weaker_basis(env):
    res = only(run(env, [approve(env)], [ct("e1", sid="")]))
    assert res.verdict == MATCHED and res.basis == "operation+resource+time"


def test_two_uncorrelated_candidates_are_ambiguous(env):
    res = only(run(env, [approve(env)], [ct("e1", sid=""), ct("e2", sid="", at=T0 + 70_000)]))
    assert res.verdict == AMBIGUOUS


def test_unapproved_state_change_by_the_agent_is_flagged(env):
    rep = run(env, [approve(env)], [
        ct("e1"),
        ct("e2", name="PutBucketPolicy", arn="arn:aws:s3:::invoices", sid="", params={"bucketName": "invoices"}),
        ct("e3", name="GetObject", read_only=True, sid=""),            # reads need no approval
    ], agent_actors=["arn:aws:sts::111122223333:assumed-role/viewer-7/"])
    verdicts = {r.kind: r.verdict for r in rep.results}
    assert verdicts == {"approval": MATCHED, "unapproved_event": CONFLICT}
    assert not rep.ok and rep.counts()[CONFLICT] == 1


def test_event_with_unknown_action_id_is_flagged_even_without_actor_list(env):
    rep = run(env, [approve(env)], [ct("e1"), ct("e9", sid="act-never-approved", at=T0 + 100_000)])
    assert [r.kind for r in rep.results if r.verdict == CONFLICT] == ["unapproved_event"]


def test_event_tagged_for_another_action_is_never_fallback_evidence(env):
    # same operation, resource and time as the approval, but tagged with an id nobody approved
    rep = run(env, [approve(env)], [ct("e1", sid="act-other")])
    by_kind = {r.kind: r for r in rep.results}
    assert by_kind["approval"].verdict == MISSING
    assert by_kind["unapproved_event"].verdict == CONFLICT and by_kind["unapproved_event"].event_ids == ["e1"]


def test_receipt_from_untrusted_key_is_not_matched(env):
    rcpt = approve(env)
    rep = reconcile([rcpt], [from_cloudtrail(ct("e1"))], Signer.generate().get_public_key(), as_of_ms=T0 + 2 * WINDOW)
    assert rep.results[0].verdict == CONFLICT and "no trusted key" in rep.results[0].reasons[0]


def test_edited_approval_fails_the_signature(env):
    rcpt = approve(env)
    data = rcpt.to_dict()
    data["signed_extensions"][ACTION_NS]["resource"] = "arn:aws:s3:::payroll/2026/all.csv"
    res = run(env, [Receipt.from_dict(data)], [ct("e1", arn="arn:aws:s3:::payroll/2026/all.csv")]).results[0]
    assert res.verdict == CONFLICT and "signature" in res.reasons[0]


def test_receipt_without_an_action_is_reported(env):
    signer, log, tmp = env
    from aetherproof.core.keystore import issue_receipt
    plain, _ = issue_receipt(signer, log, model_weight_root="m" * 64, output_hash="1" * 64, receipts_dir=tmp / "r")
    assert "no approved action" in only(run(env, [plain], [])).reasons[0]


def test_two_approvals_each_claim_their_own_event(env):
    rep = run(env, [approve(env, "a"), approve(env, "b", resource="arn:aws:s3:::invoices/2026/1043.pdf",
                                                 params={"key": "2026/1043.pdf"})],
              [ct("e1", sid="a"), ct("e2", sid="b", arn="arn:aws:s3:::invoices/2026/1043.pdf",
                                     params={"bucketName": "invoices", "key": "2026/1043.pdf"})])
    assert [(r.action_id, r.verdict, r.event_ids) for r in rep.results] == [("a", MATCHED, ["e1"]), ("b", MATCHED, ["e2"])]


def test_bad_window_is_refused(env):
    signer, log, tmp = env
    action = ApprovedAction("x", ROLE, "s3:DeleteObject", BUCKET_OBJ, not_before_ms=T0, not_after_ms=T0)
    with pytest.raises(ValueError, match="window"):
        issue_action_receipt(signer, log, action, receipts_dir=tmp / "r")


@pytest.mark.parametrize("layout", ["records", "list", "jsonl"])
def test_cloudtrail_file_layouts(tmp_path, layout):
    recs = [ct("e1"), ct("e2", name="GetObject", read_only=True)]
    text = {"records": json.dumps({"Records": recs}), "list": json.dumps(recs),
            "jsonl": "\n".join(json.dumps(r) for r in recs)}[layout]
    p = tmp_path / "trail.json"
    p.write_text(text, encoding="utf-8")
    events = load_cloudtrail(p)
    assert [e.event_id for e in events] == ["e1", "e2"] and events[1].read_only
    assert events[0].operation == "s3:DeleteObject" and events[0].correlation_id == "act-1"


def test_empty_cloudtrail_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    assert load_cloudtrail(p) == []


def test_report_serialises(env):
    data = run(env, [approve(env)], [ct("e1")]).to_dict()
    assert json.loads(json.dumps(data))["counts"] == {"matched": 1, "conflict": 0, "missing": 0, "ambiguous": 0}
