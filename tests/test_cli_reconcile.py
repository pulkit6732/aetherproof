"""CLI: approve -> reconcile against a CloudTrail file, and checkpoint create/verify."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from aetherproof.core.keystore import log_path
from aetherproof.core.signer import Signer
from aetherproof.ui import expert_mode as em

ROLE = "arn:aws:sts::111122223333:assumed-role/viewer-7/s"
OBJ = "arn:aws:s3:::invoices/2026/1042.pdf"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)


def out(capsys):
    return capsys.readouterr().out


def approve(capsys, action_id="chg-2041", *extra):
    assert em.run_expert_mode(["approve", "--action-id", action_id, "--actor", ROLE,
                               "--operation", "s3:DeleteObject", "--resource", OBJ, *extra, "--quiet"]) is True
    return json.loads(out(capsys))


def trail(tmp_path, receipt, *, key="2026/1042.pdf", sid=None, name="DeleteObject"):
    ext = receipt["signed_extensions"]["org.aetherproof.action/v1"]
    at = datetime.fromtimestamp((int(ext["not_before_ms"]) + 60_000) / 1000, timezone.utc)
    rec = {"eventID": "e1", "eventTime": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "eventSource": "s3.amazonaws.com", "eventName": name,
           "userIdentity": {"arn": ROLE, "sessionContext": {"sourceIdentity": sid or ext["action_id"]}},
           "requestParameters": {"bucketName": "invoices", "key": key},
           "resources": [{"ARN": OBJ}], "readOnly": False}
    p = tmp_path / "trail.json"
    p.write_text(json.dumps({"Records": [rec]}), encoding="utf-8")
    return p


def reconcile(capsys, tmp_path, trail_path, *extra):
    ok = em.run_expert_mode(["reconcile", str(trail_path), "--receipts", str(tmp_path / "home" / "receipts"),
                             *extra, "--quiet"])
    return ok, json.loads(out(capsys))


def test_approve_then_matching_cloudtrail_reconciles(capsys, tmp_path):
    r = approve(capsys, "chg-2041", "--approved-by", "finance-lead", "--ref", "CHG-2041")
    ok, rep = reconcile(capsys, tmp_path, trail(tmp_path, r))
    assert ok is True and rep["counts"]["matched"] == 1


def test_params_file_is_bound_and_a_different_key_conflicts(capsys, tmp_path):
    params = tmp_path / "params.json"
    params.write_text(json.dumps({"key": "2026/1042.pdf"}), encoding="utf-8")
    r = approve(capsys, "chg-1", "--params", str(params))
    ok, rep = reconcile(capsys, tmp_path, trail(tmp_path, r, key="2026/9999.pdf"))
    assert ok is False and rep["results"][0]["verdict"] == "conflict"


def test_unapproved_action_id_in_cloudtrail_fails(capsys, tmp_path):
    r = approve(capsys)
    ok, rep = reconcile(capsys, tmp_path, trail(tmp_path, r, sid="chg-unknown"))
    kinds = sorted((x["kind"], x["verdict"]) for x in rep["results"])
    assert ok is False and ("unapproved_event", "conflict") in kinds


def test_untrusted_pubkey_matches_nothing(capsys, tmp_path):
    r = approve(capsys)
    stranger = tmp_path / "stranger.pub"
    Signer.generate().export_public_file(str(stranger))
    ok, rep = reconcile(capsys, tmp_path, trail(tmp_path, r), "--pubkey", str(stranger))
    assert ok is False and "no trusted key" in rep["results"][0]["reasons"][0]


@pytest.mark.parametrize("argv,needle", [
    (["approve", "--action-id", "x"], "approve needs"),
    (["approve", "--action-id", "x", "--actor", "a", "--operation", "o", "--resource", "r", "--window", "soon"], "minutes"),
    (["reconcile"], "usage"),
    (["reconcile", "trail.json", "--receipts", "nowhere"], "not found"),
    (["checkpoint"], "usage"),
    (["checkpoint", "create"], "empty"),
])
def test_bad_input_fails_cleanly(capsys, argv, needle):
    assert em.run_expert_mode([*argv, "--quiet"]) is False
    assert needle in out(capsys)


def test_params_must_be_an_object(capsys, tmp_path):
    bad = tmp_path / "p.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert em.run_expert_mode(["approve", "--action-id", "x", "--actor", "a", "--operation", "o",
                               "--resource", "r", "--params", str(bad), "--quiet"]) is False
    assert "JSON object" in out(capsys)


def test_checkpoint_catches_deleted_receipts(capsys, tmp_path):
    for i in range(3):
        approve(capsys, f"chg-{i}")
    cp = tmp_path / "cp.json"
    assert em.run_expert_mode(["checkpoint", "create", "--out", str(cp), "--quiet"]) is True
    out(capsys)
    assert em.run_expert_mode(["checkpoint", "verify", str(cp), "--quiet"]) is True
    assert json.loads(out(capsys))["ok"] is True

    with sqlite3.connect(log_path()) as c:
        c.execute("DELETE FROM receipts WHERE sequence = 3")
    assert em.run_expert_mode(["log", "verify"]) is True, "the chain alone still looks fine"
    out(capsys)
    assert em.run_expert_mode(["checkpoint", "verify", str(cp), "--quiet"]) is False
    assert any("truncated" in p for p in json.loads(out(capsys))["problems"])


def test_help_lists_the_new_commands(capsys):
    em.run_expert_mode(["--help"])
    text = out(capsys)
    for cmd in ("approve", "reconcile", "checkpoint"):
        assert cmd in text
