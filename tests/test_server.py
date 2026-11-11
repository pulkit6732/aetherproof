"""Local API: auth, host check, limits, and the full sign -> gate -> reconcile -> checkpoint flow over HTTP."""

import http.client
import json
import threading

import pytest

from aetherproof.core.keystore import home


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    from aetherproof.server import build_server
    srv, token = build_server(port=0, token="t" * 43)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None, *, auth=True, host=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{port}", "Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {token}"
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"), dict(r.getheaders()))
        c.close()
        return out

    yield call
    srv.shutdown()
    srv.server_close()


def test_token_required(api):
    assert api("GET", "/api/status", auth=False)[0] == 401


def test_foreign_host_rejected(api):
    status, body, _ = api("GET", "/api/status", host="evil.example:80")
    assert status == 403 and body["error"] == "bad host"


def test_no_cors_and_no_cache(api):
    _, _, headers = api("GET", "/api/status")
    assert "Access-Control-Allow-Origin" not in headers and headers["Cache-Control"] == "no-store"


def test_body_limits(api):
    assert api("POST", "/api/instructions", raw=b"[1,2]")[0] == 400
    assert api("POST", "/api/instructions", raw=b"{not json")[0] == 400
    assert api("GET", "/api/nothing")[0] == 404


def test_token_file_written(api):
    assert (home() / "api_token").read_text() == "t" * 43


def test_full_flow_over_http(api):
    status, body, _ = api("POST", "/api/instructions", {
        "amount": "48500.00", "currency": "INR", "beneficiary_token": "fa_1", "reference": "LN-1",
        "approval_ref": "SAN-1", "approved_by": "credit-ops"})
    assert status == 200
    ins = body["instruction"]

    gate = {"instruction_id": ins["instruction_id"], "amount": "48500", "currency": "INR",
            "beneficiary_token": "fa_1", "reference": ins["instruction_id"]}
    assert api("POST", "/api/verify", gate)[1]["decision"]["verdict"] == "allow"
    again = api("POST", "/api/verify", gate)[1]["decision"]
    assert again["verdict"] == "reject" and "replay" in again["reasons"][0]
    assert api("POST", "/api/verify", {**gate, "instruction_id": "../../etc/passwd"})[0] == 404

    rows = [{"id": "pout_1", "reference_id": ins["instruction_id"], "amount": 4_850_000, "currency": "INR",
             "fund_account_id": "fa_1", "status": "processed", "created_at": ins["not_before_ms"] // 1000 + 60}]
    rep = api("POST", "/api/payouts/reconcile", {"payouts": rows, "source": "razorpayx"})[1]["report"]
    assert rep["counts"]["matched"] == 1 and rep["ok"]

    assert api("POST", "/api/checkpoints", {})[0] == 200
    cps = api("GET", "/api/checkpoints/verify")[1]["checkpoints"]
    assert len(cps) == 1 and cps[0]["ok"]

    st = api("GET", "/api/status")[1]
    assert st["instructions"] == 1 and st["log_entries"] == 1 and st["log_intact"]


def test_demo_seed_finds_the_planted_attacks(api):
    seeded = api("POST", "/api/demo", {})[1]
    rep = api("POST", "/api/payouts/reconcile", {"path": seeded["payouts_path"], "source": "razorpayx"})[1]["report"]
    assert rep["counts"] == {"matched": 1, "conflict": 4, "missing": 0, "ambiguous": 0}


@pytest.mark.parametrize("body,needle", [
    ({}, "missing"),
    ({"amount": "1", "currency": "INR", "reference": "r", "approval_ref": "a", "approved_by": "b"}, "either"),
    ({"amount": "1.234", "currency": "INR", "reference": "r", "approval_ref": "a", "approved_by": "b",
      "beneficiary_token": "f"}, "2 decimals"),
    ({"amount": "1", "currency": "RUPEES", "reference": "r", "approval_ref": "a", "approved_by": "b",
      "beneficiary_token": "f"}, "currency"),
])
def test_bad_sign_requests(api, body, needle):
    status, out, _ = api("POST", "/api/instructions", body)
    assert status == 400 and needle in out["error"]


def test_reconcile_input_errors(api):
    assert api("POST", "/api/payouts/reconcile", {"source": "stripe", "payouts": []})[0] == 400
    assert api("POST", "/api/payouts/reconcile", {})[0] == 400
    assert api("POST", "/api/payouts/reconcile", {"path": "Z:/nope.json"})[0] == 400
