"""Local AetherProof API for the desktop app (and scripts): `aetherproof serve`.

It signs payment instructions, so it is locked to this machine:
- binds 127.0.0.1 only;
- every request needs `Authorization: Bearer <token>`; the token is random, written
  0600 to <home>/api_token, and rotated each start unless one is supplied;
- the Host header must be localhost/127.0.0.1 (stops DNS-rebinding pages);
- no CORS headers, so a web page cannot read responses;
- request bodies are capped at 1 MiB and must be JSON objects.
"""

import hmac
import json
import os
import secrets
import stat
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
        return {"version": __version__, "key_id": Receipt.key_id(self.key), "log_entries": log.count(),
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
        report = reconcile_payouts(_load_instructions(), records, self.key)
        return {"report": report.to_dict(), "payouts": len(records)}

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


def make_handler(api: Api, token: str, port_hosts: Tuple[str, ...]):
    routes = api.routes()

    class Handler(BaseHTTPRequestHandler):
        server_version = "AetherProof"
        sys_version = ""

        def _send(self, status: int, payload: Dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            try:
                if self.headers.get("Host", "").lower() not in port_hosts:
                    raise ApiError(403, "bad host")
                auth = self.headers.get("Authorization", "")
                if not hmac.compare_digest(auth.encode(), f"Bearer {token}".encode()):
                    raise ApiError(401, "missing or wrong token")
                fn = routes.get((method, self.path.split("?")[0]))
                if fn is None:
                    raise ApiError(404, "no such endpoint")
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
                self._send(200, fn(body))
            except ApiError as e:
                self._send(e.status, {"error": str(e)})
            except Exception as e:  # never leak a traceback to the client; report the type only
                self._send(500, {"error": f"internal error ({type(e).__name__})"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def log_message(self, fmt, *args):  # quiet: no request lines with tokens in the console
            pass

    return Handler


def write_token(token: str) -> Path:
    path = home() / "api_token"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def build_server(port: int = 8787, token: str = "") -> Tuple[ThreadingHTTPServer, str]:
    token = token or secrets.token_urlsafe(32)
    write_token(token)
    srv = ThreadingHTTPServer(("127.0.0.1", port), None)
    actual = srv.server_address[1]
    hosts = (f"127.0.0.1:{actual}", f"localhost:{actual}")
    srv.RequestHandlerClass = make_handler(Api(), token, hosts)
    return srv, token


def serve(port: int = 8787) -> None:
    srv, _ = build_server(port)
    print(f"AetherProof API on http://127.0.0.1:{srv.server_address[1]}  (token in {home() / 'api_token'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
