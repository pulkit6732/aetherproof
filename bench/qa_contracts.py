"""Functional QA of the local API and CLI against their documented contracts (gstack /qa
contract map, applied by hand): success, invalid input per field, auth, CLI exit codes,
state transitions, idempotency, concurrency, timeouts and partial-failure recovery.

Runs a real server on an ephemeral port in an isolated AETHERPROOF_HOME with synthetic
data; touches nothing else. Prints one line per probe and a JSON summary.
usage: python bench/qa_contracts.py
"""

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="ap_qa_"))
os.environ["AETHERPROOF_HOME"] = str(HOME)
from aetherproof.server import build_server  # noqa: E402

results = []


def start():
    srv, tokens = build_server(0, None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, tokens, srv.server_address[1]


srv, TOK, PORT = start()


def call(method, path, body=None, role="admin", token=None, host=None, raw=None, timeout=30):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    data = raw if raw is not None else (json.dumps(body) if body is not None else None)
    hdr = {"Host": host or f"127.0.0.1:{PORT}", "Content-Type": "application/json"}
    if token is not False:
        hdr["Authorization"] = f"Bearer {token or TOK[role]}"
    c.request(method, path, data, hdr)
    r = c.getresponse()
    txt = r.read()
    try:
        return r.status, json.loads(txt or b"{}")
    except ValueError:
        return r.status, {"_raw": txt[:200].decode("utf-8", "replace")}


def probe(pid, contract, expected, ok, observed):
    results.append({"id": pid, "contract": contract, "expected": expected, "observed": observed, "pass": bool(ok)})
    print(f"{'PASS' if ok else 'FAIL'}  {pid:<5} {contract:<38} {observed}")


def code(out):
    return (out.get("error") or {}).get("code") if isinstance(out.get("error"), dict) else out.get("error")


SIGN = {"amount": "48500.00", "currency": "INR", "beneficiary_token": "fa_1", "reference": "LN-1",
        "approval_ref": "SAN-1", "approved_by": "ops"}

# ---------------------------------------------------------------- success
st, out = call("POST", "/api/v1/instructions", SIGN, role="signer")
ins = out.get("instruction", {})
probe("S1", "sign returns a stored instruction", "200 + id", st == 200 and (HOME / "instructions" / f"{ins.get('instruction_id')}.json").exists(), f"{st} {ins.get('instruction_id')}")
VER = {"instruction_id": ins.get("instruction_id"), "amount": "48500.00", "currency": "INR", "beneficiary_token": "fa_1", "reference": ins.get("instruction_id")}

# ---------------------------------------------------------------- invalid input, one rule per probe
bad_amounts = ["", "abc", "-1", "0", "1.234", "NaN", "Infinity", "-Infinity", "sNaN", "1e400", "99999999999999999999999"]
for i, a in enumerate(bad_amounts):
    st, out = call("POST", "/api/v1/instructions", {**SIGN, "amount": a}, role="signer")
    probe(f"I{i + 1}", f"sign amount={a!r}", "400", st == 400, f"{st} {code(out)}")
for i, (k, v) in enumerate([("currency", "RUPEES"), ("currency", ""), ("valid_minutes", "-5"), ("valid_minutes", "inf"),
                            ("valid_minutes", "nan"), ("beneficiary_token", "")]):
    st, out = call("POST", "/api/v1/instructions", {**SIGN, k: v}, role="signer")
    probe(f"I{20 + i}", f"sign {k}={v!r}", "400", st == 400, f"{st} {code(out)}")
st, out = call("POST", "/api/v1/instructions", raw="{not json", role="signer")
probe("I30", "malformed JSON body", "400", st == 400, f"{st} {code(out)}")
st, out = call("POST", "/api/v1/instructions", raw=json.dumps([1, 2]), role="signer")
probe("I31", "JSON array body", "400", st == 400, f"{st} {code(out)}")
st, out = call("POST", "/api/v1/instructions", raw="x" * (1024 * 1024 + 10), role="signer")
probe("I32", "body over 1 MiB", "413", st == 413, f"{st} {code(out)}")
st, out = call("POST", "/api/v1/verify", {**VER, "instruction_id": "..\\..\\api_tokens"}, role="executor")
probe("I33", "verify id with path traversal", "404, no file read", st == 404, f"{st} {code(out)}")
st, out = call("POST", "/api/v1/payouts/reconcile", {"source": "generic", "path": str(HOME / "api_tokens.json")}, role="auditor")
leak = any(t in json.dumps(out) for t in TOK.values())
probe("I34", "reconcile pointed at the token file", "400, no secret in reply", st == 400 and not leak, f"{st} {code(out)} leak={leak}")
big = [{"payout_id": "p1", "reference": "x", "amount_minor": 10**20, "currency": "INR", "status": "processed", "time": 0, "beneficiary_token": "fa"}]
st, out = call("POST", "/api/v1/payouts/reconcile", {"source": "generic", "payouts": big}, role="auditor")
probe("I35", "payout amount beyond int64 (app range)", "400", st == 400, f"{st} {code(out)}")
neg = [{**big[0], "amount_minor": -500}]
st, out = call("POST", "/api/v1/payouts/reconcile", {"source": "generic", "payouts": neg}, role="auditor")
probe("I36", "negative payout amount", "400", st == 400, f"{st} {code(out)}")

# ---------------------------------------------------------------- auth
st, out = call("GET", "/api/v1/status", token=False)
probe("A1", "no token", "401", st == 401, f"{st} {code(out)}")
for i, (role, m, p, b) in enumerate([("executor", "POST", "/api/v1/instructions", SIGN), ("signer", "POST", "/api/v1/verify", VER),
                                     ("auditor", "POST", "/api/v1/instructions", SIGN), ("executor", "GET", "/api/v1/runs", None),
                                     ("signer", "POST", "/api/v1/evidence/verify", {"path": "x"})]):
    st, out = call(m, p, b, role=role)
    probe(f"A{2 + i}", f"{role} {m} {p}", "403", st == 403, f"{st} {code(out)}")
for i, h in enumerate(["evil.example:80", f"127.0.0.1:{PORT}.evil.example", "localhost"]):
    st, out = call("GET", "/api/v1/status", host=h)
    probe(f"A{10 + i}", f"Host header {h!r}", "403 bad_host", st == 403, f"{st} {code(out)}")

# ---------------------------------------------------------------- state transitions and idempotency
st, out = call("POST", "/api/v1/verify", {**VER, "amount": "98500.00"}, role="executor")
probe("T1", "REJECT does not consume", "reject", out.get("decision", {}).get("verdict") == "reject", out.get("decision", {}).get("verdict"))
st, out = call("POST", "/api/v1/verify", {**VER, "reference": ""}, role="executor")
probe("T2", "REVIEW does not consume", "review", out.get("decision", {}).get("verdict") == "review", out.get("decision", {}).get("verdict"))
st, out = call("POST", "/api/v1/verify", VER, role="executor")
probe("T3", "ALLOW after reject/review", "allow", out.get("decision", {}).get("verdict") == "allow", out.get("decision", {}).get("verdict"))
st, out = call("POST", "/api/v1/verify", VER, role="executor")
probe("T4", "second ALLOW impossible", "reject (replay)", out.get("decision", {}).get("verdict") == "reject", out.get("decision", {}).get("reasons"))

# ---------------------------------------------------------------- concurrency
st, out = call("POST", "/api/v1/instructions", {**SIGN, "reference": "LN-race"}, role="signer")
race = out["instruction"]["instruction_id"]
with ThreadPoolExecutor(32) as pool:
    verdicts = list(pool.map(lambda _: call("POST", "/api/v1/verify", {**VER, "instruction_id": race, "reference": race}, role="executor")[1]
                             .get("decision", {}).get("verdict"), range(64)))
probe("C1", "64 parallel gate calls, one instruction", "exactly 1 allow", verdicts.count("allow") == 1, f"allow={verdicts.count('allow')} reject={verdicts.count('reject')}")
with ThreadPoolExecutor(16) as pool:
    ids = list(pool.map(lambda i: call("POST", "/api/v1/instructions", {**SIGN, "reference": f"LN-p{i}"}, role="signer")[1]["instruction"]["instruction_id"], range(32)))
probe("C2", "32 parallel signs", "32 unique ids", len(set(ids)) == 32, f"unique={len(set(ids))}")
seed = call("POST", "/api/v1/demo", {})[1]
body = {"path": seed["payouts_path"], "source": "razorpayx", "statement_path": seed["statement_path"], "settlement_grace_minutes": 0}
with ThreadPoolExecutor(8) as pool:
    runs = list(pool.map(lambda _: call("POST", "/api/v1/payouts/reconcile", body, role="auditor")[1], range(8)))
run_ids = {r.get("run_id") for r in runs}
probe("C3", "8 parallel identical reconciles", "1 run id, readable", len(run_ids) == 1 and call("GET", f"/api/v1/runs/{run_ids.pop()}", role="auditor")[0] == 200, f"run_ids={len({r.get('run_id') for r in runs})}")

# ---------------------------------------------------------------- timeouts: a stalled client must not block others
s = socket.create_connection(("127.0.0.1", PORT))
s.sendall(f"POST /api/v1/verify HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Bearer {TOK['executor']}\r\n"
          f"Content-Length: 100\r\n\r\n{{".encode())
t0 = time.perf_counter()
st, _ = call("GET", "/api/v1/status", role="auditor", timeout=5)
probe("O1", "stalled client, others still served", "200 < 1 s", st == 200 and time.perf_counter() - t0 < 1, f"{st} in {time.perf_counter() - t0:.3f}s")
s.settimeout(15)
t0 = time.perf_counter()
try:
    s.recv(4096)            # server gives up on the half-sent body: a response or a close
    closed = True
except ConnectionError:
    closed = True
except socket.timeout:
    closed = False
waited = time.perf_counter() - t0
probe("O2", "stalled client dropped by socket timeout", "dropped after ~10 s", closed and 8 < waited < 14, f"closed={closed} after {waited:.1f}s")
s.close()

# ---------------------------------------------------------------- partial failure and recovery
torn = HOME / "instructions" / "ins_torn000000000000000.json"
torn.write_text('{"type": "aetherproof.instruction/v0", "amount_mi', encoding="utf-8")
st, out = call("GET", "/api/v1/instructions", role="auditor")
probe("R1", "torn instruction file: list still works", "200 + unreadable count", st == 200, f"{st} {code(out)} unreadable={out.get('unreadable')}")
st, out = call("POST", "/api/v1/payouts/reconcile", body, role="auditor")
probe("R2", "torn instruction file: reconcile still works", "200", st == 200, f"{st} {code(out)}")
torn.unlink()
srv.shutdown()
srv.server_close()
srv, TOK, PORT = start()      # restart on the same home: replay store must survive
st, out = call("POST", "/api/v1/verify", VER, role="executor")
probe("R3", "after restart, consumed instruction stays consumed", "reject (replay)", out.get("decision", {}).get("verdict") == "reject", out.get("decision", {}).get("verdict"))

# ---------------------------------------------------------------- CLI process contract
cli = [sys.executable, "-m", "aetherproof"]
env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
ins_file = HOME / "instructions" / f"{ids[0]}.json"
r = subprocess.run(cli + ["instruction", "verify", str(ins_file), "--amount", "48500.00", "--currency", "INR",
                          "--beneficiary-token", "fa_1", "--reference", ids[0], "--quiet"], capture_output=True, text=True, env=env)
probe("L1", "CLI gate, matching request", "exit 0", r.returncode == 0, f"exit {r.returncode}")
r = subprocess.run(cli + ["instruction", "verify", str(ins_file), "--amount", "1.00", "--currency", "INR",
                          "--beneficiary-token", "fa_1", "--reference", ids[0], "--quiet"], capture_output=True, text=True, env=env)
probe("L2", "CLI gate, changed amount", "exit 1", r.returncode == 1, f"exit {r.returncode}")
r = subprocess.run(cli + ["payouts", "reconcile", str(HOME / "nope.json"), "--instructions", str(HOME / "instructions"), "--quiet"],
                   capture_output=True, text=True, env=env)
probe("L3", "CLI reconcile, missing file", "non-zero, message, no traceback", r.returncode != 0 and "Traceback" not in r.stderr + r.stdout, f"exit {r.returncode}")
r = subprocess.run(cli + ["payouts", "reconcile", seed["payouts_path"], "--instructions", str(HOME / "instructions"), "--source", "razorpayx",
                          "--statement", seed["statement_path"], "--settlement-grace-minutes", "0", "--quiet"], capture_output=True, text=True, env=env)
try:
    rep = json.loads(r.stdout.strip().splitlines()[-1])
    ok = r.returncode == 1 and any(x.get("settlement") == "absent" for x in rep["results"])
except (ValueError, IndexError, KeyError):
    ok = False
probe("L4", "CLI reconcile with statement finds forged", "exit 1 + absent", ok, f"exit {r.returncode}")
r = subprocess.run(cli + ["evidence", "verify", str(HOME / "nope.json"), "--quiet"], capture_output=True, text=True, env=env)
probe("L5", "CLI evidence verify, missing file", "exit 1, no traceback", r.returncode == 1 and "Traceback" not in r.stderr + r.stdout, f"exit {r.returncode}")

srv.shutdown()
failed = [x for x in results if not x["pass"]]
print(json.dumps({"probes": len(results), "passed": len(results) - len(failed), "failed": [x["id"] for x in failed]}, indent=1))
sys.exit(1 if failed else 0)
