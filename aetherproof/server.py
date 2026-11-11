"""Local AetherProof API for the desktop app (and scripts): `aetherproof serve`.

It signs payment instructions, so it is locked to this machine:
- binds 127.0.0.1 only;
- every request needs `Authorization: Bearer <token>`; the token is random, written
  0600 to <home>/api_token, and rotated each start unless one is supplied;
- the Host header must be localhost/127.0.0.1 (stops DNS-rebinding pages);
- no CORS headers, so a web page cannot read responses;
- request bodies are capped at 1 MiB and must be JSON objects.
"""

import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

from . import __version__
from .core.anchor import Checkpoint, create_checkpoint, verify_checkpoint
from .core.instruction import (PaymentInstruction, PayoutRequest, ReplayStore, bank_beneficiary,
                               sign_instruction, token_beneficiary, verify_instruction)
from .core.keystore import default_log, home, issue_receipt, load_or_create_signer
from .core.payouts import MAPPINGS, payout_from_row, reconcile_payouts
from .core.receipt import Receipt

MAX_BODY = 1 << 20
INSTRUCTION_NS = "org.aetherproof.instruction/v0"


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


# Least privilege: an executor's token can only check payments, an auditor's can only
# read and reconcile, a signer's can only sign. "admin" is the desktop app.
ROLES = ("admin", "signer", "executor", "auditor")
PERMS = {
    ("GET", "/api/status"): {"admin", "signer", "executor", "auditor"},
    ("GET", "/api/instructions"): {"admin", "signer", "auditor"},
    ("POST", "/api/instructions"): {"admin", "signer"},
    ("POST", "/api/verify"): {"admin", "executor"},
    ("POST", "/api/payouts/reconcile"): {"admin", "auditor"},
    ("POST", "/api/checkpoints"): {"admin", "signer"},
    ("GET", "/api/checkpoints/verify"): {"admin", "auditor"},
    ("POST", "/api/demo"): {"admin"},
}
AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_S, LOCKOUT_S = 10, 60.0, 60.0
RATE_LIMIT, RATE_WINDOW_S = 600, 60.0          # requests per role per window


class Limiter:
    """Bad-token lockout per client and a sliding request window per role."""

    def __init__(self):
        self._lock = threading.Lock()
        self._fails: Dict[str, deque] = {}
        self._blocked: Dict[str, float] = {}
        self._calls: Dict[str, deque] = {}

    def blocked(self, client: str, now: float) -> bool:
        with self._lock:
            return self._blocked.get(client, 0.0) > now

    def fail(self, client: str, now: float) -> None:
        with self._lock:
            q = self._fails.setdefault(client, deque())
            q.append(now)
            while q and q[0] < now - AUTH_FAIL_WINDOW_S:
                q.popleft()
            if len(q) >= AUTH_FAIL_LIMIT:
                self._blocked[client] = now + LOCKOUT_S
                q.clear()

    def allow(self, role: str, now: float) -> bool:
        with self._lock:
            q = self._calls.setdefault(role, deque())
            while q and q[0] < now - RATE_WINDOW_S:
                q.popleft()
            if len(q) >= RATE_LIMIT:
                return False
            q.append(now)
            return True


class AuditLog:
    """Append-only JSON lines, each carrying the hash of the line before it, so an
    edited, reordered or deleted call record breaks the chain (verify_audit)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._prev = "0" * 64
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines:
                try:
                    self._prev = json.loads(lines[-1])["hash"]
                except (ValueError, KeyError):
                    # a torn last line (crash mid-write) must not stop the API; the chain
                    # break it leaves stays visible to verify_audit
                    self._prev = "torn-line"

    def write(self, **fields) -> None:
        with self._lock:
            entry = {"t": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **fields, "prev": self._prev}
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._prev = entry["hash"]


def verify_audit(path: Path) -> Tuple[bool, int, int]:
    """(intact, entries, first broken line number or 0)."""
    prev = "0" * 64
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    for n, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except ValueError:
            return False, len(lines), n
        claimed = entry.pop("hash", "")
        if entry.get("prev") != prev or hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest() != claimed:
            return False, len(lines), n
        prev = claimed
    return True, len(lines), 0


def _instructions_dir() -> Path:
    return home() / "instructions"


def _load_instructions():
    d = _instructions_dir()
    return [PaymentInstruction.from_json(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] if d.exists() else []


def _minor(amount: Any) -> int:
    from decimal import Decimal, InvalidOperation
    try:
        d = Decimal(str(amount))
    except InvalidOperation:
        raise ApiError(400, "amount is not a number")
    if d <= 0 or d.as_tuple().exponent < -2:
        raise ApiError(400, "amount must be positive with at most 2 decimals")
    return int(d * 100)


def _need(body: Dict, *names: str):
    missing = [n for n in names if not str(body.get(n, "")).strip()]
    if missing:
        raise ApiError(400, f"missing: {', '.join(missing)}")


def _beneficiary(body: Dict):
    token, ifsc, account = body.get("beneficiary_token", ""), body.get("ifsc", ""), body.get("account_number", "")
    if bool(token) == bool(ifsc and account):
        raise ApiError(400, "give either beneficiary_token, or both ifsc and account_number")
    return token, ifsc, account


class Api:
    """Route handlers. Plain methods over the core, so tests call them without HTTP."""

    def __init__(self):
        self.signer = load_or_create_signer()
        self.key = self.signer.get_public_key()
        self.replay = ReplayStore(str(home() / "replay.db"))

    def status(self, _body):
        log = default_log()
        cps = sorted((home() / "checkpoints").glob("*.json")) if (home() / "checkpoints").exists() else []
        from .core.keyprotect import SEALED_NAME
        audit_ok, audit_n, _ = verify_audit(home() / "audit.jsonl")
        protection = ("passphrase" if os.environ.get("AETHERPROOF_KEY_PASSPHRASE")
                      else "dpapi" if (home() / SEALED_NAME).exists() else "file-permissions-only")
        return {"version": __version__, "key_id": Receipt.key_id(self.key), "key_protection": protection,
                "audit_entries": audit_n, "audit_intact": audit_ok, "log_entries": log.count(),
                "log_intact": log.verify_integrity(), "instructions": len(_load_instructions()),
                "checkpoints": len(cps), "home": str(home())}

    def list_instructions(self, _body):
        rows = []
        for ins in sorted(_load_instructions(), key=lambda i: i.not_before_ms, reverse=True)[:200]:
            d = json.loads(ins.to_json())
            d["amount"] = f"{ins.amount_minor / 100:.2f}"
            rows.append(d)
        return {"instructions": rows}

    def sign(self, body):
        _need(body, "amount", "currency", "reference", "approval_ref", "approved_by")
        token, ifsc, account = _beneficiary(body)
        try:
            ins = sign_instruction(
                self.signer, originator=body.get("originator") or "local", amount_minor=_minor(body["amount"]),
                currency=body["currency"], beneficiary=token_beneficiary(token) if token else bank_beneficiary(ifsc, account),
                purpose=body.get("purpose") or "payout", reference=body["reference"], approval_ref=body["approval_ref"],
                approved_by=body["approved_by"], policy=body.get("policy") or "default",
                validity_ms=int(float(body.get("valid_minutes") or 15) * 60_000))
        except ValueError as e:
            raise ApiError(400, str(e))
        _instructions_dir().mkdir(parents=True, exist_ok=True)
        (_instructions_dir() / f"{ins.instruction_id}.json").write_text(ins.to_json(), encoding="utf-8")
        issue_receipt(self.signer, default_log(), model_weight_root=ins.digest(), model_root_type="name_only",
                      output_hash=ins.digest(), extensions={INSTRUCTION_NS: {"instruction_id": ins.instruction_id,
                                                                            "digest": ins.digest()}})
        return {"instruction": json.loads(ins.to_json())}

    def verify(self, body):
        _need(body, "instruction_id", "amount", "currency")
        token, ifsc, account = _beneficiary(body)
        path = _instructions_dir() / f"{Path(body['instruction_id']).name}.json"
        if not path.exists():
            raise ApiError(404, "unknown instruction_id")
        ins = PaymentInstruction.from_json(path.read_text(encoding="utf-8"))
        req = PayoutRequest(amount_minor=_minor(body["amount"]), currency=body["currency"],
                            reference=body.get("reference", ""), beneficiary_token=token, ifsc=ifsc, account_number=account)
        return {"decision": verify_instruction(ins, req, self.key, self.replay).to_dict()}

    def reconcile(self, body):
        source = body.get("source") or "generic"
        if source not in MAPPINGS:
            raise ApiError(400, f"unknown source {source!r}")
        rows = body.get("payouts")
        if rows is None and body.get("path"):
            from .core.payouts import load_payouts
            try:
                records = load_payouts(body["path"], source)
            except OSError as e:
                raise ApiError(400, f"cannot read payouts file: {e}")
        elif isinstance(rows, list):
            records = [payout_from_row(r, MAPPINGS[source]) for r in rows]
        else:
            raise ApiError(400, "give payouts (a list) or path")
        instructions = _load_instructions()
        report = reconcile_payouts(instructions, records, self.key).to_dict()
        # money each verdict concerns: the authorised amount, or what an unapproved payout moved
        authorised = {i.instruction_id: i.amount_minor for i in instructions}
        paid = {r.payout_id: r.amount_minor for r in records}
        for r in report["results"]:
            r["amount_minor"] = (sum(paid.get(p, 0) for p in r["event_ids"]) if r["kind"] == "unapproved_event"
                                 else authorised.get(r["action_id"], 0))
        report["at_risk_minor"] = sum(r["amount_minor"] for r in report["results"] if r["verdict"] == "conflict")
        report["verified_minor"] = sum(r["amount_minor"] for r in report["results"] if r["verdict"] == "matched")
        return {"report": report, "payouts": len(records)}

    def checkpoint(self, body):
        try:
            cp = create_checkpoint(default_log(), self.signer, tsa_url=body.get("tsa_url", ""))
        except ValueError as e:
            raise ApiError(400, str(e))
        d = home() / "checkpoints"
        d.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = d / f"checkpoint_{cp.log_size:06d}_{stamp}.json"
        path.write_text(cp.to_json(), encoding="utf-8")
        return {"checkpoint": json.loads(cp.to_json()), "path": str(path)}

    def verify_checkpoints(self, _body):
        d = home() / "checkpoints"
        out = []
        for p in sorted(d.glob("*.json")) if d.exists() else []:
            rep = verify_checkpoint(Checkpoint.from_json(p.read_text(encoding="utf-8")), default_log(), self.key)
            out.append({"file": p.name, **rep.to_dict()})
        return {"checkpoints": out}

    def demo(self, _body):
        """Seed a realistic run: four approved disbursals and a payout file that contains
        the attacks CERT-In describes (no instruction, changed amount, changed beneficiary, paid twice)."""
        made = []
        for i, (amt, fa) in enumerate([("48500.00", "fa_borrower_01"), ("125000.00", "fa_borrower_02"),
                                       ("30000.00", "fa_borrower_03"), ("75000.00", "fa_borrower_04")], 1):
            made.append(self.sign({"amount": amt, "currency": "INR", "beneficiary_token": fa,
                                   "reference": f"LN-2026-{1040 + i}", "approval_ref": f"SAN-{7700 + i}",
                                   "approved_by": "credit-ops", "purpose": "loan_disbursal",
                                   "policy": "disbursal-v3", "originator": "demo-lender"})["instruction"])
        now = int(datetime.now(timezone.utc).timestamp())
        row = lambda pid, ref, amt, fa, st="processed": {"id": pid, "reference_id": ref, "amount": amt,
                                                          "currency": "INR", "fund_account_id": fa, "status": st,
                                                          "created_at": now, "utr": f"UTR{pid[-4:]}"}
        payouts = [row("pout_0001", made[0]["instruction_id"], 4_850_000, "fa_borrower_01"),
                   row("pout_0002", made[1]["instruction_id"], 12_500_000, "fa_mule_77"),
                   row("pout_0003", made[2]["instruction_id"], 3_500_000, "fa_borrower_03"),
                   row("pout_0004", made[3]["instruction_id"], 7_500_000, "fa_borrower_04"),
                   row("pout_0005", made[3]["instruction_id"], 7_500_000, "fa_borrower_04"),
                   row("pout_0006", "", 9_900_000, "fa_mule_77")]
        path = home() / "demo_payouts.json"
        path.write_text(json.dumps({"entity": "collection", "items": payouts}, indent=2), encoding="utf-8")
        return {"instructions": len(made), "payouts_path": str(path), "source": "razorpayx"}

    def routes(self) -> Dict[Tuple[str, str], Callable[[Dict], Dict]]:
        return {("GET", "/api/status"): self.status, ("GET", "/api/instructions"): self.list_instructions,
                ("POST", "/api/instructions"): self.sign, ("POST", "/api/verify"): self.verify,
                ("POST", "/api/payouts/reconcile"): self.reconcile, ("POST", "/api/checkpoints"): self.checkpoint,
                ("GET", "/api/checkpoints/verify"): self.verify_checkpoints, ("POST", "/api/demo"): self.demo}


def _role_for(auth: str, tokens: Dict[str, str]) -> str:
    """Constant-time match against every role's token; '' when none matches."""
    found = ""
    for role, tok in tokens.items():
        if hmac.compare_digest(auth.encode(), f"Bearer {tok}".encode()):
            found = role
    return found


def make_handler(api: Api, tokens: Dict[str, str], port_hosts: Tuple[str, ...]):
    routes = api.routes()
    limiter = Limiter()
    audit = AuditLog(home() / "audit.jsonl")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AetherProof"
        sys_version = ""
        timeout = 10  # seconds per socket read: a stalled client cannot hold a worker

        def _send(self, status: int, payload: Dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            path, role, status, ref = self.path.split("?")[0], "", 500, ""
            client = self.client_address[0]
            now = time.monotonic()
            try:
                if self.headers.get("Host", "").lower() not in port_hosts:
                    raise ApiError(403, "bad host")
                if limiter.blocked(client, now):
                    raise ApiError(429, "too many bad tokens; locked out for a minute")
                role = _role_for(self.headers.get("Authorization", ""), tokens)
                if not role:
                    limiter.fail(client, now)
                    raise ApiError(401, "missing or wrong token")
                if not limiter.allow(role, now):
                    raise ApiError(429, "rate limit")
                fn = routes.get((method, path))
                if fn is None:
                    raise ApiError(404, "no such endpoint")
                if role not in PERMS[(method, path)]:
                    raise ApiError(403, f"role {role} may not call {method} {path}")
                body: Dict = {}
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > MAX_BODY:
                        raise ApiError(413, "body too large")
                    try:
                        body = json.loads(self.rfile.read(n) or b"{}")
                    except ValueError:
                        raise ApiError(400, "body is not JSON")
                    if not isinstance(body, dict):
                        raise ApiError(400, "body must be a JSON object")
                    ref = str(body.get("instruction_id", ""))[:64]
                out = fn(body)
                ref = ref or str((out.get("instruction") or {}).get("instruction_id", ""))
                status = 200
                self._send(200, out)
            except ApiError as e:
                status = e.status
                self._send(e.status, {"error": str(e)})
            except Exception as e:  # never leak a traceback to the client; report the type only
                self._send(500, {"error": f"internal error ({type(e).__name__})"})
            finally:
                try:
                    audit.write(client=client, role=role or "-", method=method, path=path[:100], status=status, ref=ref)
                except OSError:
                    pass  # a full disk must not take the API down; the gap shows in verify_audit

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def log_message(self, fmt, *args):  # quiet: no request lines with tokens in the console
            pass

    return Handler


def _write_private(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def write_tokens(tokens: Dict[str, str]) -> None:
    """api_token keeps the admin token (the desktop app reads it); api_tokens.json holds
    every role's token, to hand the executor or auditor only what they need."""
    _write_private(home() / "api_token", tokens["admin"])
    _write_private(home() / "api_tokens.json", json.dumps(tokens, indent=2))


def build_server(port: int = 8787, token: str = "") -> Tuple[ThreadingHTTPServer, Dict[str, str]]:
    tokens = {role: secrets.token_urlsafe(32) for role in ROLES}
    if token:
        tokens["admin"] = token
    write_tokens(tokens)
    srv = ThreadingHTTPServer(("127.0.0.1", port), None)
    actual = srv.server_address[1]
    hosts = (f"127.0.0.1:{actual}", f"localhost:{actual}")
    srv.RequestHandlerClass = make_handler(Api(), tokens, hosts)
    return srv, tokens


def serve(port: int = 8787) -> None:
    srv, _ = build_server(port)
    print(f"AetherProof API on http://127.0.0.1:{srv.server_address[1]}  (token in {home() / 'api_token'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
