"""CLI: instruction sign -> instruction verify (executor gate) -> payouts reconcile."""

import json
from datetime import datetime, timezone

import pytest

from aetherproof.core.keystore import home
from aetherproof.ui import expert_mode as em


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)


def out(capsys):
    return capsys.readouterr().out


def sign(capsys, *extra):
    assert em.run_expert_mode(["instruction", "sign", "--amount", "48500.00", "--currency", "INR",
                               "--beneficiary-token", "fa_1", "--reference", "LN-1", "--approval-ref", "SAN-1",
                               "--approved-by", "credit-ops", *extra, "--quiet"]) is True
    return json.loads(out(capsys))


def verify(capsys, ins_id, *extra):
    path = home() / "instructions" / f"{ins_id}.json"
    ok = em.run_expert_mode(["instruction", "verify", str(path), "--quiet", *extra])
    return ok, json.loads(out(capsys))


def test_sign_then_executor_allows_once(capsys):
    ins = sign(capsys)
    assert ins["amount_minor"] == 4_850_000 and len(ins["instruction_id"]) <= 40
    args = ["--amount", "48500", "--currency", "INR", "--beneficiary-token", "fa_1", "--reference", ins["instruction_id"]]
    ok, d = verify(capsys, ins["instruction_id"], *args)
    assert ok is True and d["verdict"] == "allow"
    ok, d = verify(capsys, ins["instruction_id"], *args)
    assert ok is False and "replay" in d["reasons"][0]


def test_executor_rejects_changed_amount(capsys):
    ins = sign(capsys)
    ok, d = verify(capsys, ins["instruction_id"], "--amount", "48500.01", "--currency", "INR", "--beneficiary-token", "fa_1")
    assert ok is False and "amount" in d["reasons"][0]


def test_signing_is_logged_for_checkpoints(capsys):
    sign(capsys)
    assert em.run_expert_mode(["log", "count"]) is True
    assert "1 receipts" in capsys.readouterr().out


def test_payouts_reconcile_end_to_end(capsys, tmp_path):
    ins = sign(capsys)
    created = (ins["not_before_ms"] + 60_000) // 1000
    rows = [{"id": "pout_1", "fund_account_id": "fa_1", "amount": 4_850_000, "currency": "INR",
             "status": "processed", "reference_id": ins["instruction_id"], "created_at": created},
            {"id": "pout_9", "fund_account_id": "fa_mule", "amount": 9_900_000, "currency": "INR",
             "status": "processed", "reference_id": "", "created_at": created}]
    f = tmp_path / "payouts.json"
    f.write_text(json.dumps({"entity": "collection", "items": rows}), encoding="utf-8")
    ok = em.run_expert_mode(["payouts", "reconcile", str(f), "--instructions", str(home() / "instructions"),
                             "--source", "razorpayx", "--quiet"])
    rep = json.loads(out(capsys))
    assert ok is False and rep["counts"] == {"matched": 1, "conflict": 1, "missing": 0, "ambiguous": 0}


@pytest.mark.parametrize("argv,needle", [
    (["instruction"], "usage"),
    (["instruction", "sign", "--amount", "1", "--currency", "INR"], "either --beneficiary-token"),
    (["instruction", "sign", "--amount", "1.001", "--currency", "INR", "--beneficiary-token", "f"], "2 decimals"),
    (["instruction", "sign", "--amount", "abc", "--currency", "INR", "--beneficiary-token", "f"], "not a number"),
    (["instruction", "sign", "--amount", "1", "--currency", "INR", "--beneficiary-token", "f"], "needs --reference"),
    (["instruction", "verify", "--amount", "1", "--currency", "INR", "--beneficiary-token", "f"], "usage"),
    (["payouts", "reconcile", "x.json"], "--instructions"),
    (["payouts", "reconcile", "x.json", "--instructions", "nowhere"], "not found"),
])
def test_bad_input_fails_cleanly(capsys, argv, needle):
    assert em.run_expert_mode([*argv, "--quiet"]) is False
    assert needle in out(capsys)
