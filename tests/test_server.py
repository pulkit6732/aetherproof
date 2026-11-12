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
    srv, tokens = build_server(port=0, token="t" * 43)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None, *, auth=True, host=None, raw=None, role="admin", token=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{port}", "Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {token or tokens[role]}"
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


def test_token_files_written(api):
    assert (home() / "api_token").read_text() == "t" * 43
    roles = json.loads((home() / "api_tokens.json").read_text())
    assert set(roles) == {"admin", "signer", "executor", "auditor"} and len(set(roles.values())) == 4


SIGN = {"amount": "100", "currency": "INR", "beneficiary_token": "fa_1", "reference": "r",
        "approval_ref": "a", "approved_by": "b"}


@pytest.mark.parametrize("role,method,path,body,allowed", [
    ("executor", "POST", "/api/instructions", SIGN, False),      # a payer cannot mint approvals
    ("executor", "POST", "/api/payouts/reconcile", {"payouts": []}, False),
    ("auditor", "POST", "/api/instructions", SIGN, False),
    ("auditor", "POST", "/api/verify", {}, False),               # an auditor cannot consume instructions
    ("signer", "POST", "/api/verify", {}, False),                # the signer cannot pay its own instructions
    ("signer", "POST", "/api/demo", {}, False),
    ("signer", "POST", "/api/instructions", SIGN, True),
    ("auditor", "POST", "/api/payouts/reconcile", {"payouts": []}, True),
    ("executor", "GET", "/api/status", None, True),
])
def test_least_privilege_roles(api, role, method, path, body, allowed):
    status, out, _ = api(method, path, body, role=role)
    assert (status != 403) == allowed, out


def test_bad_tokens_lock_the_client_out(api):
    for _ in range(10):
        assert api("GET", "/api/status", token="wrong")[0] == 401
    status, body, _ = api("GET", "/api/status", token="wrong")   # wrong tokens are refused outright now
    assert status == 429 and "locked out" in body["error"]


# Regression: CSO-1 — every local client is 127.0.0.1, so 10 wrong tokens from any local process
# (another Windows user included) locked the real executor out of the payment gate. Valid tokens
# (256-bit random) are now always served; only wrong ones are locked out.
def test_a_lockout_cannot_deny_the_executor_its_gate(api):
    for _ in range(12):
        api("GET", "/api/v1/status", token="attacker-guess")
    assert api("GET", "/api/v1/status", role="executor")[0] == 200
    assert api("GET", "/api/v1/status", token="attacker-guess")[0] == 429


def test_every_call_is_audited_and_the_chain_detects_edits(api):
    from aetherproof.server import verify_audit
    api("GET", "/api/status")
    api("POST", "/api/instructions", SIGN, role="signer")
    api("POST", "/api/verify", {}, role="auditor")
    path = home() / "audit.jsonl"
    ok, n, _ = verify_audit(path)
    assert ok and n == 3
    lines = path.read_text().splitlines()
    assert json.loads(lines[1])["ref"].startswith("ins_") and json.loads(lines[2])["status"] == 403
    lines[1] = lines[1].replace('"status": 200', '"status": 500')
    path.write_text("\n".join(lines) + "\n")
    assert verify_audit(path) == (False, 3, 2)


def test_torn_audit_line_is_reported_not_fatal(tmp_path):
    from aetherproof.server import AuditLog, verify_audit
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.write(status=200)
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"t": "2026-11-11T10:0')            # crash mid-write
    again = AuditLog(path)                            # reopening must not raise
    again.write(status=200)
    assert verify_audit(path) == (False, 3, 2)


def test_status_reports_protections(api):
    st = api("GET", "/api/status")[1]
    assert st["key_protection"] in ("dpapi", "file-permissions-only", "passphrase") and st["audit_intact"]


def test_key_on_disk_is_encrypted_on_windows(api):
    import sys
    pem = (home() / "signing_key.pem").read_text()
    if sys.platform == "win32":
        assert "ENCRYPTED" in pem and (home() / "key_passphrase.dpapi").exists()


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
    # provider records alone: the forged "processed" payout looks clean
    assert rep["counts"] == {"matched": 2, "conflict": 4, "missing": 0, "ambiguous": 0}
    assert rep["settlement_source"] == "none"
    body = {"path": seeded["payouts_path"], "source": "razorpayx", "statement_path": seeded["statement_path"],
            "settlement_grace_minutes": seeded["settlement_grace_minutes"]}
    rep = api("POST", "/api/payouts/reconcile", body)[1]["report"]
    assert rep["counts"] == {"matched": 1, "conflict": 5, "missing": 0, "ambiguous": 0}
    forged = [r for r in rep["results"] if r["settlement"] == "absent"]
    assert len(forged) == 1 and forged[0]["amount_minor"] == 6_000_000 and rep["at_risk_minor"] > 6_000_000


@pytest.mark.parametrize("extra,needle", [({"settlement_grace_minutes": -1}, "non-negative"),
                                          ({"settlement_grace_minutes": "30"}, "non-negative"),
                                          ({"statement_path": "Z:/no/such/statement.json"}, "bank statement"),
                                          ({"statement": [{"entry_id": "e", "amount_minor": 1.5, "direction": "debit"}]}, "integer"),
                                          ({"path": None, "payouts": [{"id": "p", "amount": 1.5}]}, "integer"),
                                          ({"statement": ["not an object"]}, "invalid input")])
def test_bad_settlement_inputs_are_refused(api, extra, needle):
    seeded = api("POST", "/api/demo", {})[1]
    status, out = api("POST", "/api/payouts/reconcile", {"path": seeded["payouts_path"], "source": "razorpayx", **extra})[:2]
    assert status == 400 and needle in json.dumps(out)


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


# Regression: QA I6 I7 I9 I10 I11 I23 — non-finite or out-of-range amounts crashed (500) or were signed
# Found by bench/qa_contracts.py on 2026-11-12
@pytest.mark.parametrize("field,value", [("amount", "NaN"), ("amount", "sNaN"), ("amount", "Infinity"),
                                         ("amount", "1e400"), ("amount", "99999999999999999999999"),
                                         ("amount", "10000000000000.01"), ("valid_minutes", "inf")])
def test_non_finite_or_out_of_range_sign_inputs_are_400(api, field, value):
    status, out, _ = api("POST", "/api/v1/instructions", {**SIGN, field: value})
    assert status == 400, out


def test_largest_allowed_amount_still_signs(api):
    assert api("POST", "/api/v1/instructions", {**SIGN, "amount": "10000000000000.00"})[0] == 200   # 10^15 paise


# Regression: QA I35 I36 — payout amounts beyond the app's int64 range, or negative, were accepted
@pytest.mark.parametrize("amount", [10**20, 10**15 + 1, -500, "-500"])
def test_out_of_range_payout_amounts_are_400(api, amount):
    row = {"payout_id": "p1", "reference": "x", "amount_minor": amount, "currency": "INR", "status": "processed",
           "time": 0, "beneficiary_token": "fa"}
    status, out, _ = api("POST", "/api/v1/payouts/reconcile", {"source": "generic", "payouts": [row]})
    assert status == 400 and out["error"]["code"] == "invalid_request"


# Regression: CSO-2 — an import path was read whole with no size limit (memory exhaustion)
@pytest.mark.parametrize("field", ["path", "statement_path"])
def test_import_size_limit_boundary(api, tmp_path, monkeypatch, field):
    import aetherproof.server as server
    limit = 64                                   # small limit so the test needs no large file
    monkeypatch.setattr(server, "MAX_IMPORT_BYTES", limit)
    ok = tmp_path / "ok.json"
    ok.write_text("[]", encoding="utf-8")
    at_limit = tmp_path / "at.json"
    at_limit.write_text("[" + " " * (limit - 2) + "]", encoding="utf-8")       # exactly the limit: accepted
    over = tmp_path / "over.json"
    over.write_text("[" + " " * (limit - 1) + "]", encoding="utf-8")           # one byte over: refused
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")                                     # empty: accepted, no rows
    call = lambda p: api("POST", "/api/v1/payouts/reconcile", {"source": "generic", "path": str(ok), field: str(p)})
    assert call(at_limit)[0] == 200 and call(empty)[0] == 200
    status, out, _ = call(over)
    assert status == 413 and out["error"]["code"] == "too_large"


def test_a_failed_disk_write_is_a_clear_500_not_a_crash(api, monkeypatch):
    import aetherproof.server as server

    def disk_full(_path, _data):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(server, "_atomic_write", disk_full)
    status, out, _ = api("POST", "/api/v1/instructions", SIGN)
    assert status == 500 and out["error"]["code"] == "internal" and "No space left" in out["error"]["message"]
    assert api("GET", "/api/v1/status")[0] == 200            # the server keeps serving


@pytest.mark.parametrize("what", ["receipt", "evidence"])
def test_other_write_failures_are_clear_500s(api, monkeypatch, what):
    import aetherproof.server as server

    def disk_full(*_a, **_k):
        raise OSError(28, "No space left on device")
    if what == "receipt":
        monkeypatch.setattr(server, "issue_receipt", disk_full)
        status, out, _ = api("POST", "/api/v1/instructions", SIGN)
    else:
        seed = api("POST", "/api/v1/demo", {})[1]
        run = api("POST", "/api/v1/payouts/reconcile", {"path": seed["payouts_path"], "source": "razorpayx"})[1]
        monkeypatch.setattr(server, "_atomic_write", disk_full)
        status, out, _ = api("POST", f"/api/v1/runs/{run['run_id']}/evidence", {})
    assert status == 500 and "No space left" in out["error"]["message"]


# Regression: I/O review — a damaged stored instruction at the gate, a damaged checkpoint file,
# and a failed checkpoint write fell to the generic catch-all
def test_gate_on_a_damaged_stored_instruction_fails_closed_with_a_clear_error(api):
    (home() / "instructions").mkdir(parents=True, exist_ok=True)
    (home() / "instructions" / "ins_bad.json").write_text("{torn", encoding="utf-8")
    body = {"instruction_id": "ins_bad", "amount": "1", "currency": "INR", "beneficiary_token": "f"}
    status, out, _ = api("POST", "/api/v1/verify", body, role="executor")
    assert status == 500 and out["error"]["code"] == "internal" and "unreadable" in out["error"]["message"]


def test_one_damaged_checkpoint_file_does_not_hide_the_others(api):
    api("POST", "/api/v1/instructions", SIGN, role="signer")
    assert api("POST", "/api/v1/checkpoints", {}, role="signer")[0] == 200
    (home() / "checkpoints" / "checkpoint_zz_torn.json").write_text("{torn", encoding="utf-8")
    status, out, _ = api("GET", "/api/v1/checkpoints/verify", role="auditor")
    assert status == 200 and len(out["checkpoints"]) == 2
    bad = [c for c in out["checkpoints"] if c["file"] == "checkpoint_zz_torn.json"][0]
    assert bad["ok"] is False and "unreadable" in bad["problems"][0]


def test_a_failed_checkpoint_write_is_a_clear_500(api, monkeypatch):
    import aetherproof.server as server
    api("POST", "/api/v1/instructions", SIGN, role="signer")

    def disk_full(*_a, **_k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(server, "_atomic_write", disk_full)
    status, out, _ = api("POST", "/api/v1/checkpoints", {}, role="signer")
    assert status == 500 and "No space left" in out["error"]["message"]


def test_an_unreadable_audit_log_reads_as_not_intact_not_a_crash(tmp_path):
    from aetherproof.server import verify_audit
    unreadable = tmp_path / "audit.jsonl"
    unreadable.mkdir()                       # a directory where the file should be: reading it raises OSError
    assert verify_audit(unreadable) == (False, 0, 0)
    assert verify_audit(tmp_path / "absent.jsonl") == (True, 0, 0)


# Regression: QA R1 R2 — one torn instruction file (crash mid-write) broke every list and reconcile
def test_a_torn_instruction_file_is_counted_not_fatal(api):
    api("POST", "/api/v1/instructions", SIGN)
    (home() / "instructions" / "ins_torn.json").write_text('{"type": "aetherproof.instruction/v0", "amou', encoding="utf-8")
    status, out, _ = api("GET", "/api/v1/instructions")
    assert status == 200 and len(out["instructions"]) == 1 and out["unreadable"] == 1
    assert api("POST", "/api/v1/payouts/reconcile", {"source": "generic", "payouts": []})[0] == 200


# Regression: QA C3 — parallel identical reconciles collided on one temp file and one failed
def test_parallel_identical_reconciles_all_succeed_with_one_run(api):
    from concurrent.futures import ThreadPoolExecutor
    seed = api("POST", "/api/v1/demo", {})[1]
    body = {"path": seed["payouts_path"], "source": "razorpayx"}
    with ThreadPoolExecutor(8) as pool:
        outs = list(pool.map(lambda _: api("POST", "/api/v1/payouts/reconcile", body), range(16)))
    assert [o[0] for o in outs] == [200] * 16 and len({o[1]["run_id"] for o in outs}) == 1


def test_reconcile_input_errors(api):
    assert api("POST", "/api/payouts/reconcile", {"source": "stripe", "payouts": []})[0] == 400
    assert api("POST", "/api/payouts/reconcile", {})[0] == 400
    assert api("POST", "/api/payouts/reconcile", {"path": "Z:/nope.json"})[0] == 400
