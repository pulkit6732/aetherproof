"""Evidence package: export a run, verify it offline, catch tampering."""

import copy
import json

from aetherproof.core.evidence import FORMAT, export_package, verify_package
from aetherproof.core.signer import Signer
from aetherproof.ui.expert_mode import cmd_evidence

KEY = Signer.generate()
RUN = {"run_id": "run_abc", "report": {"counts": {"matched": 1, "conflict": 1}, "at_risk_minor": 6_000_000,
                                       "results": [{"verdict": "conflict", "settlement": "absent", "amount_minor": 6_000_000}]}}


def test_untouched_package_verifies():
    pkg = export_package(RUN, KEY)
    assert pkg["format"] == FORMAT and verify_package(pkg, KEY.get_public_key()) == (True, [])


def test_changed_verdict_is_detected():
    pkg = export_package(RUN, KEY)
    bad = copy.deepcopy(pkg)
    bad["run"]["report"]["results"][0]["verdict"] = "matched"   # an insider hides the forged payout
    ok, problems = verify_package(bad, KEY.get_public_key())
    assert not ok and "modified after export" in problems[0]


def test_resealed_digest_still_fails_the_signature():
    from aetherproof.core.evidence import _digest
    bad = export_package(RUN, KEY)
    bad["run"]["report"]["at_risk_minor"] = 0
    bad["digest"] = _digest(bad["run"])                          # attacker recomputes the hash too
    ok, problems = verify_package(bad, KEY.get_public_key())
    assert not ok and problems == ["signature does not verify under the trusted key"]


def test_package_signed_by_another_key_is_untrusted():
    ok, problems = verify_package(export_package(RUN, Signer.generate()), KEY.get_public_key())
    assert not ok and "no trusted key" in problems[0]


def test_not_a_package_and_missing_fields_fail_closed():
    assert verify_package({}, KEY.get_public_key())[0] is False
    assert verify_package({"format": FORMAT}, KEY.get_public_key())[0] is False
    assert verify_package([], KEY.get_public_key())[0] is False
    assert verify_package(None, KEY.get_public_key())[0] is False
    pkg = export_package(RUN, KEY)
    for field in ("digest", "signature", "signing_key_id", "run"):
        assert verify_package({**pkg, field: None}, KEY.get_public_key())[0] is False, field


def test_empty_run_and_zero_amounts_seal_and_verify():
    for run in ({}, {"report": {"results": [], "at_risk_minor": 0}}):
        assert verify_package(export_package(run, KEY), KEY.get_public_key()) == (True, [])


def test_cli_verify_exit_status(tmp_path, capsys):
    pub = tmp_path / "k.pub.pem"
    pub.write_bytes(KEY.export_public_pem())
    good = tmp_path / "good.json"
    good.write_text(json.dumps(export_package(RUN, KEY)), encoding="utf-8")
    assert cmd_evidence(["verify", str(good), "--pubkey", str(pub), "--quiet"]) is True
    pkg = json.loads(good.read_text(encoding="utf-8"))
    pkg["run"]["report"]["counts"]["conflict"] = 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(pkg), encoding="utf-8")
    assert cmd_evidence(["verify", str(bad), "--pubkey", str(pub), "--quiet"]) is False
    torn = tmp_path / "torn.json"
    torn.write_text("{", encoding="utf-8")
    assert cmd_evidence(["verify", str(torn), "--pubkey", str(pub), "--quiet"]) is False
