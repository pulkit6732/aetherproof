"""Contract v1: one definition of verdicts and decisions, versioned API, typed errors, saved runs, REVIEW."""

import json
import threading
import http.client

import pytest

from aetherproof import contract
from aetherproof.core import instruction, payouts, reconcile
from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary, verify_instruction
from aetherproof.core.signer import Signer


def test_every_layer_uses_the_contract_constants():
    assert (reconcile.MATCHED, reconcile.CONFLICT, reconcile.MISSING, reconcile.AMBIGUOUS) == contract.VERDICTS
    assert (instruction.ALLOW, instruction.REJECT, instruction.REVIEW) == contract.DECISIONS
    assert payouts.MATCHED is contract.MATCHED


def test_gate_review_when_payout_cannot_be_tied_back(tmp_path):
    s = Signer.generate()
    ins = sign_instruction(s, originator="o", amount_minor=100, currency="INR", beneficiary=token_beneficiary("fa_1"),
                           purpose="p", reference="r", approval_ref="a", approved_by="b", policy="c", not_before_ms=1000)
    store = ReplayStore(str(tmp_path / "r.db"))
    d = verify_instruction(ins, PayoutRequest(100, "INR", "", "fa_1"), s.get_public_key(), store, now_ms=2000)
    assert d.verdict == contract.REVIEW and "reference not set" in d.reasons[0]
    # REVIEW consumed nothing: the properly referenced payout still goes through once
    ok = verify_instruction(ins, PayoutRequest(100, "INR", ins.instruction_id, "fa_1"), s.get_public_key(), store, now_ms=2000)
    assert ok.verdict == contract.ALLOW
    # a hard failure wins over REVIEW
    bad = verify_instruction(ins, PayoutRequest(999, "INR", "", "fa_1"), s.get_public_key(), store, now_ms=2000)
    assert bad.verdict == contract.REJECT
    store.close()


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    from aetherproof.server import build_server
    srv, tokens = build_server(port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None, role="admin"):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                  headers={"Host": f"127.0.0.1:{port}", "Authorization": f"Bearer {tokens[role]}"})
        r = c.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        c.close()
        return out

    call.port, call.tokens = port, tokens
    yield call
    srv.shutdown()
    srv.server_close()


def test_v1_errors_are_typed_and_legacy_keeps_its_shape(api):
    status, body = api("POST", "/api/v1/instructions", {"amount": "1.234"})
    assert status == 400 and body["error"]["code"] == "missing_field" and body["contract_version"] == "1"
    status, body = api("POST", "/api/v1/instructions", {"amount": "x", "currency": "INR", "reference": "r",
                                                         "approval_ref": "a", "approved_by": "b", "beneficiary_token": "f"})
    assert body["error"]["code"] == "invalid_amount"
    status, body = api("POST", "/api/instructions", {})
    assert status == 400 and isinstance(body["error"], str)
    assert api("GET", "/api/v1/nothing")[1]["error"]["code"] == "not_found"
    assert api("POST", "/api/v1/verify", {}, role="auditor")[1]["error"]["code"] == "forbidden"


@pytest.mark.parametrize("size", [8, 1 << 20])  # small, and exactly the largest body accepted
@pytest.mark.parametrize("path,role,status", [("/api/v1/verify", "auditor", 403), ("/api/v1/nothing", "admin", 404)])
def test_rejected_post_reads_its_body_before_replying(api, path, role, status, size):
    # A reply sent while the body is still unread, then a close, makes Windows reset the socket:
    # the client sees ConnectionAbortedError instead of the error (seen on CI, Windows, 3.11).
    # Deterministic check: send only the headers. The server must wait for the body, not reply.
    import select
    import socket
    body = b"x" * size
    s = socket.create_connection(("127.0.0.1", api.port), timeout=10)
    try:
        s.sendall((f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{api.port}\r\n"
                   f"Authorization: Bearer {api.tokens[role]}\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n").encode())
        early, _, _ = select.select([s], [], [], 0.5)
        assert not early, "server replied before reading the request body"
        s.sendall(body)
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
    except OSError as e:  # the bug this test guards against shows up as a reset or abort
        pytest.fail(f"connection broke instead of getting the {status} reply: {type(e).__name__}: {e}")
    finally:
        s.close()
    assert reply.startswith(b"HTTP/"), f"no HTTP reply received: {reply[:80]!r}"
    assert reply.split(b" ", 2)[1] == str(status).encode()


def test_runs_are_saved_idempotent_and_readable(api):
    seed = api("POST", "/api/v1/demo", {})[1]
    first = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
    again = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
    assert first["run_id"] == again["run_id"] and first["replayed"] is False and again["replayed"] is True
    runs = api("GET", "/api/v1/runs")[1]["runs"]
    assert [r["run_id"] for r in runs] == [first["run_id"]] and runs[0]["counts"]["conflict"] == 4
    run = api("GET", f"/api/v1/runs/{first['run_id']}")[1]
    assert run["report"]["counts"] == first["report"]["counts"] and run["contract_version"] == "1"
    assert api("GET", "/api/v1/runs/run_nope")[1]["error"]["code"] == "unknown_run"
    assert api("GET", "/api/v1/runs/..%2f..%2fapi_tokens")[1]["error"]["code"] == "unknown_run"
    assert api("GET", "/api/v1/runs", role="executor")[0] == 403


def test_evidence_export_verifies_and_catches_tampering(api, tmp_path):
    seed = api("POST", "/api/v1/demo", {})[1]
    run = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
    out = api("POST", f"/api/v1/runs/{run['run_id']}/evidence", {})[1]
    assert api("POST", "/api/v1/evidence/verify", {"path": out["path"]}, role="auditor")[1] == {"ok": True, "problems": []}
    pkg = json.loads(open(out["path"], encoding="utf-8").read())
    pkg["run"]["report"]["counts"]["conflict"] = 0
    verdict = api("POST", "/api/v1/evidence/verify", {"package": pkg})[1]
    assert verdict["ok"] is False and "modified after export" in verdict["problems"][0]
    assert api("POST", "/api/v1/runs/run_nope/evidence", {})[1]["error"]["code"] == "unknown_run"
    assert api("POST", "/api/v1/evidence/verify", {"path": out["path"]}, role="executor")[0] == 403


def test_a_damaged_run_file_is_reported_not_fatal(api, tmp_path):
    seed = api("POST", "/api/v1/demo", {})[1]
    run = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
    (tmp_path / "home" / "runs" / f"{run['run_id']}.json").write_text("{torn", encoding="utf-8")
    listing = api("GET", "/api/v1/runs")[1]
    assert listing["runs"] == [] and listing["unreadable"] == 1
    assert api("GET", f"/api/v1/runs/{run['run_id']}")[1]["error"]["code"] == "unreadable_input"
    again = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
    assert again["run_id"] == run["run_id"] and again["replayed"] is False      # rewritten from the inputs
    assert api("GET", f"/api/v1/runs/{run['run_id']}")[0] == 200
