"""The CLI and the local API enforce the same gate policy (core/gate.py): destination approval
and aggregate caps. Without a policy file both keep the 0.5.x behaviour."""
import http.client
import json
import threading

import pytest

from aetherproof.core.destinations import DestinationRegistry, make_record, sign_record
from aetherproof.core.gate import load_policy
from aetherproof.core.keystore import home
from aetherproof.core.signer import Signer
from aetherproof.ui import expert_mode as em

LOAN = "48500.00"
CAP_BELOW_LOAN = "40000.00"
CAP_ABOVE_LOAN = "100000.00"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    (tmp_path / "home").mkdir()


def write_policy(per_payout_max, with_destinations):
    a, b = Signer.generate(), Signer.generate()
    pol = {"account": "nbfc", "limits": {"per_payout_max": per_payout_max, "daily_max": "1000000.00",
                                         "daily_count_max": 100, "per_destination_daily_max": "1000000.00"}}
    if with_destinations:
        a.export_public_file(str(home() / "pa.pub"))
        b.export_public_file(str(home() / "pb.pub"))
        pol["destinations"] = {"policy_pubkeys": ["pa.pub", "pb.pub"], "required_signers": 2}
    (home() / "gate_policy.json").write_text(json.dumps(pol), encoding="utf-8")
    return a, b


def approve(a, b, dest):
    pol = load_policy(home())
    reg = DestinationRegistry(pol.destinations_db, pol.policy_keys, pol.required_signers)
    rec = make_record(account="nbfc", destination=dest, domain="bank", action="add", version=1)
    assert reg.apply(rec, [sign_record(rec, a), sign_record(rec, b)])[0]
    reg.close()


def cli_sign(capsys):
    assert em.run_expert_mode(["instruction", "sign", "--amount", LOAN, "--currency", "INR", "--beneficiary-token", "fa_1",
                               "--reference", "LN-1", "--approval-ref", "SAN-1", "--approved-by", "ops", "--quiet"]) is True
    return json.loads(capsys.readouterr().out)["instruction_id"]


def cli_verify(capsys, ins_id):
    ok = em.run_expert_mode(["instruction", "verify", str(home() / "instructions" / f"{ins_id}.json"), "--amount", LOAN,
                             "--currency", "INR", "--beneficiary-token", "fa_1", "--reference", ins_id, "--quiet"])
    return ok, capsys.readouterr()


def test_cli_enforces_the_per_payout_cap(capsys):
    write_policy(CAP_BELOW_LOAN, with_destinations=False)
    ok, cap = cli_verify(capsys, cli_sign(capsys))
    assert ok is False and "per payout cap" in cap.out


def test_cli_enforces_destination_approval(capsys):
    a, b = write_policy(CAP_ABOVE_LOAN, with_destinations=True)
    ins_id = cli_sign(capsys)
    ok, cap = cli_verify(capsys, ins_id)
    assert ok is False and "not approved by the policy authority" in cap.out
    approve(a, b, "fa_1")
    ok, cap = cli_verify(capsys, ins_id)
    assert ok is True and json.loads(cap.out)["verdict"] == "allow"


def test_cli_with_broken_policy_refuses(capsys):
    (home() / "gate_policy.json").write_text("{broken", encoding="utf-8")
    ok, cap = cli_verify(capsys, cli_sign(capsys))
    assert ok is False and "gate policy unusable" in (cap.out + cap.err)


@pytest.fixture
def api():
    from aetherproof.server import build_server
    servers = []

    def start():
        srv, tokens = build_server(port=0, token="t" * 43)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        port = srv.server_address[1]

        def call(method, path, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                      headers={"Host": f"127.0.0.1:{port}", "Authorization": f"Bearer {tokens['admin']}",
                               "Content-Type": "application/json"})
            r = c.getresponse()
            out = (r.status, json.loads(r.read() or b"{}"))
            c.close()
            return out
        return call
    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def api_sign_and_verify(call):
    st, body = call("POST", "/api/v1/instructions", {"amount": LOAN, "currency": "INR", "beneficiary_token": "fa_1",
                                                     "reference": "LN-1", "approval_ref": "SAN-1", "approved_by": "ops"})
    assert st == 200, body
    iid = body["instruction"]["instruction_id"]
    return lambda: call("POST", "/api/v1/verify", {"instruction_id": iid, "amount": LOAN, "currency": "INR",
                                                   "beneficiary_token": "fa_1", "reference": iid})


def test_api_enforces_the_same_policy(api):
    a, b = write_policy(CAP_ABOVE_LOAN, with_destinations=True)
    verify = api_sign_and_verify(api())
    st, body = verify()
    assert st == 200 and body["decision"]["verdict"] == "reject"
    assert "not approved by the policy authority" in body["decision"]["reasons"][0]
    approve(a, b, "fa_1")
    st, body = verify()
    assert body["decision"]["verdict"] == "allow"
    st, body = verify()
    assert body["decision"]["verdict"] == "reject"        # single use still holds


def test_api_without_policy_keeps_the_05_behaviour(api):
    st, body = api_sign_and_verify(api())()
    assert st == 200 and body["decision"]["verdict"] == "allow"


def test_api_with_broken_policy_refuses_to_decide(api):
    (home() / "gate_policy.json").write_text("{broken", encoding="utf-8")
    st, body = api_sign_and_verify(api())()
    assert st == 503 and body["error"]["code"] == "gate_policy"


def test_cli_allows_an_amount_exactly_at_the_cap(capsys):
    write_policy(LOAN, with_destinations=False)          # per payout cap equal to the loan
    ok, cap = cli_verify(capsys, cli_sign(capsys))
    assert ok is True and json.loads(cap.out)["verdict"] == "allow"


@pytest.mark.parametrize("field", ["account", "limits"])
def test_policy_missing_a_required_field_refuses(capsys, field):
    pol = {"account": "nbfc", "limits": {"per_payout_max": LOAN, "daily_max": "1000000.00", "daily_count_max": 100,
                                         "per_destination_daily_max": "1000000.00"}}
    if field == "limits":
        del pol["limits"]["daily_max"]
    else:
        del pol["account"]
    (home() / "gate_policy.json").write_text(json.dumps(pol), encoding="utf-8")
    ok, cap = cli_verify(capsys, cli_sign(capsys))
    assert ok is False and "gate policy unusable" in (cap.out + cap.err)


def test_api_refuses_an_empty_destination(api):
    write_policy(CAP_ABOVE_LOAN, with_destinations=False)
    call = api()
    st, body = call("POST", "/api/v1/instructions", {"amount": LOAN, "currency": "INR", "beneficiary_token": "fa_1",
                                                     "reference": "LN-1", "approval_ref": "SAN-1", "approved_by": "ops"})
    iid = body["instruction"]["instruction_id"]
    st, body = call("POST", "/api/v1/verify", {"instruction_id": iid, "amount": LOAN, "currency": "INR",
                                               "beneficiary_token": "", "reference": iid})
    assert st == 400 or body["decision"]["verdict"] == "reject"
