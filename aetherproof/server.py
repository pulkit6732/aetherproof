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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

from . import __version__
from .contract import CONTRACT_VERSION, ERRORS, MAX_AMOUNT_MINOR
from .core.anchor import Checkpoint, create_checkpoint, verify_checkpoint
from .core.instruction import (PaymentInstruction, PayoutRequest, ReplayStore, bank_beneficiary,
                               sign_instruction, token_beneficiary, verify_instruction)
from .core.keystore import _atomic_write, default_log, home, issue_receipt, load_or_create_signer
from .core.payouts import MAPPINGS, payout_from_row, reconcile_payouts
from .core.receipt import Receipt

MAX_BODY = 1 << 20
INSTRUCTION_NS = "org.aetherproof.instruction/v0"


_DEFAULT_CODE = {400: "invalid_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found",
                 413: "too_large", 429: "rate_limited", 500: "internal"}


class ApiError(Exception):
    def __init__(self, status: int, message: str, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code or _DEFAULT_CODE[status]
        assert self.code in ERRORS, self.code


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
    ("GET", "/api/runs"): {"admin", "auditor"},
    ("POST", "/api/evidence/verify"): {"admin", "auditor"},
}
AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_S, LOCKOUT_S = 10, 60.0, 60.0
MAX_IMPORT_BYTES = 256 * 1024 * 1024           # one payout export or statement file (~2M rows)
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
            if path.read_bytes()[-1:] not in (b"", b"\n"):
                with open(path, "a", encoding="utf-8") as f:
                    f.write("\n")  # never glue the next entry onto a torn line

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


def _runs_dir() -> Path:
    return home() / "runs"


def _read_instructions() -> Tuple[list, int]:
    """(instructions, unreadable). A torn or foreign file is counted, never fatal: one bad
    file used to break every list and reconcile (QA R1/R2). Its payouts then show as
    having no valid instruction, which fails toward flagging, not toward approving."""
    d, out, bad = _instructions_dir(), [], 0
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            out.append(PaymentInstruction.from_json(p.read_text(encoding="utf-8")))
        except (OSError, ValueError, KeyError, TypeError):
            bad += 1
    return out, bad


def _load_instructions():
    return _read_instructions()[0]


def _save(path: Path, data: bytes) -> None:
    """Atomic write; a disk failure (full, locked after retries) is a clear 500, never a traceback."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(path, data)
    except OSError as e:
        raise ApiError(500, f"cannot write {path.name}: {e.strerror or type(e).__name__}", "internal") from e


def _minor(amount: Any) -> int:
    from decimal import Decimal, InvalidOperation
    try:
        d = Decimal(str(amount))
    except InvalidOperation:
        raise ApiError(400, "amount is not a number", "invalid_amount") from None
    if not d.is_finite() or d <= 0 or d.as_tuple().exponent < -2:   # NaN/Infinity crashed the compare (QA I6/I7/I9)
        raise ApiError(400, "amount must be positive with at most 2 decimals", "invalid_amount")
    if d * 100 > MAX_AMOUNT_MINOR:
        raise ApiError(400, f"amount above the maximum {MAX_AMOUNT_MINOR // 100}", "invalid_amount")
    return int(d * 100)


def _need(body: Dict, *names: str):
    missing = [n for n in names if not str(body.get(n, "")).strip()]
    if missing:
        raise ApiError(400, f"missing: {', '.join(missing)}", "missing_field")


def _beneficiary(body: Dict):
    token, ifsc, account = body.get("beneficiary_token", ""), body.get("ifsc", ""), body.get("account_number", "")
    if bool(token) == bool(ifsc and account):
        raise ApiError(400, "give either beneficiary_token, or both ifsc and account_number", "invalid_beneficiary")
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
        instructions, unreadable = _read_instructions()
        for ins in sorted(instructions, key=lambda i: i.not_before_ms, reverse=True)[:200]:
            d = json.loads(ins.to_json())
            d["amount"] = f"{ins.amount_minor // 100}.{ins.amount_minor % 100:02d}"   # integer paise, never a float
            rows.append(d)
        return {"instructions": rows, "unreadable": unreadable}

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
        except (ValueError, OverflowError) as e:   # valid_minutes "inf" overflowed int() (QA I23)
            raise ApiError(400, str(e)) from e
        _save(_instructions_dir() / f"{ins.instruction_id}.json", ins.to_json().encode("utf-8"))
        try:
            issue_receipt(self.signer, default_log(), model_weight_root=ins.digest(), model_root_type="name_only",
                          output_hash=ins.digest(), extensions={INSTRUCTION_NS: {"instruction_id": ins.instruction_id,
                                                                                "digest": ins.digest()}})
        except OSError as e:   # the instruction is saved; only its log receipt failed (issue_receipt rolls its files back)
            raise ApiError(500, f"instruction saved, but its log receipt could not be written: {e.strerror or type(e).__name__}", "internal") from e
        return {"instruction": json.loads(ins.to_json())}

    def verify(self, body):
        _need(body, "instruction_id", "amount", "currency")
        token, ifsc, account = _beneficiary(body)
        path = _instructions_dir() / f"{Path(body['instruction_id']).name}.json"
        if not path.exists():
            raise ApiError(404, "unknown instruction_id", "unknown_instruction")
        ins = PaymentInstruction.from_json(path.read_text(encoding="utf-8"))
        req = PayoutRequest(amount_minor=_minor(body["amount"]), currency=body["currency"],
                            reference=body.get("reference", ""), beneficiary_token=token, ifsc=ifsc, account_number=account)
        return {"decision": verify_instruction(ins, req, self.key, self.replay).to_dict()}

    def reconcile(self, body):
        source = body.get("source") or "generic"
        if source not in MAPPINGS:
            raise ApiError(400, f"unknown source {source!r}", "unknown_source")
        rows = body.get("payouts")
        for key in ("path", "statement_path"):   # stat before reading: no unbounded file read (CSO-2)
            p = body.get(key)
            try:
                too_big = isinstance(p, str) and bool(p) and os.path.isfile(p) and os.path.getsize(p) > MAX_IMPORT_BYTES
            except OSError:
                too_big = False   # vanished or unreadable: the read below reports unreadable_input
            if too_big:
                raise ApiError(413, f"{key} file larger than {MAX_IMPORT_BYTES} bytes", "too_large")
        from .core.payouts import load_payouts
        from .core.settlement import entry_from_row, load_statement
        try:
            if rows is None and body.get("path"):
                try:
                    records = load_payouts(body["path"], source)
                except OSError as e:
                    raise ApiError(400, f"cannot read payouts file: {e}", "unreadable_input") from e
            elif isinstance(rows, list):
                records = [payout_from_row(r, MAPPINGS[source]) for r in rows]
            else:
                raise ApiError(400, "give payouts (a list) or path")
            # optional independent settlement source: the bank statement (list or file path)
            statement = None
            if isinstance(body.get("statement"), list):
                statement = [entry_from_row(r) for r in body["statement"]]
            elif body.get("statement_path"):
                try:
                    statement = load_statement(body["statement_path"])
                except OSError as e:
                    raise ApiError(400, f"cannot read bank statement: {e}", "unreadable_input") from e
        except (ValueError, TypeError, AttributeError) as e:  # malformed customer rows are a 400, not a crash
            raise ApiError(400, f"invalid input: {e}", "invalid_request") from e
        grace = body.get("settlement_grace_minutes")
        if grace is not None and (isinstance(grace, bool) or not isinstance(grace, int) or grace < 0):
            raise ApiError(400, "settlement_grace_minutes must be a non-negative integer")
        instructions = _load_instructions()
        report = reconcile_payouts(instructions, records, self.key, statement=statement,
                                   settlement_grace_ms=None if grace is None else grace * 60_000).to_dict()
        report["settlement_source"] = "bank_statement" if statement is not None else "none"
        # money each verdict concerns: the authorised amount, or what an unapproved payout moved
        authorised = {i.instruction_id: i.amount_minor for i in instructions}
        paid = {r.payout_id: r.amount_minor for r in records}
        bank = {e.entry_id: e.amount_minor for e in statement or []}
        for r in report["results"]:
            r["amount_minor"] = (sum(paid.get(p, 0) for p in r["event_ids"]) if r["kind"] == "unapproved_event"
                                 else bank.get(r["event_ids"][0], 0) if r["kind"] == "unexplained_debit"
                                 else authorised.get(r["action_id"], 0))
        report["at_risk_minor"] = sum(r["amount_minor"] for r in report["results"] if r["verdict"] == "conflict")
        report["verified_minor"] = sum(r["amount_minor"] for r in report["results"] if r["verdict"] == "matched")
        # Investigation detail: the signed instruction and every raw provider row behind each
        # verdict (duplicates and status changes included, in time order), with their hashes.
        by_id = {i.instruction_id: i for i in instructions}
        rows_by_ref: Dict[str, list] = {}
        for rec in records:
            rows_by_ref.setdefault(rec.reference, []).append(rec)
        for r in report["results"]:
            ins = by_id.get(r["action_id"]) if r["kind"] == "approval" else None
            rows = rows_by_ref.get(r["action_id"], []) if ins else [x for x in records if x.payout_id in r["event_ids"]]
            r["events"] = [{"payout_id": x.payout_id, "status": x.status, "amount_minor": x.amount_minor,
                            "currency": x.currency, "beneficiary": x.beneficiary_token or (x.ifsc and "bank account"),
                            "time_ms": x.time_ms, "utr": x.utr, "record_hash": x.record_hash}
                           for x in sorted(rows, key=lambda x: x.time_ms)]
            if ins:
                ben = ins.beneficiary
                r["instruction"] = {
                    "instruction_id": ins.instruction_id, "amount_minor": ins.amount_minor, "currency": ins.currency,
                    "beneficiary": ben.get("value") if ben.get("kind") == "token" else f"bank account (salted digest {ben['digest'][:12]}…)",
                    "purpose": ins.purpose, "reference": ins.reference, "approval_ref": ins.approval_ref,
                    "approved_by": ins.approved_by, "policy": ins.policy, "originator": ins.originator,
                    "not_before_ms": ins.not_before_ms, "not_after_ms": ins.not_after_ms,
                    "signing_key_id": ins.signing_key_id, "digest": ins.digest(),
                    "signature_valid": not any("not signed by a trusted" in x for x in r["reasons"]),
                }
        report["demo"] = bool(instructions) and all(i.originator == "demo-lender" for i in instructions)
        # Persist the run. The id is a digest of exactly what was compared, so re-running the
        # same inputs returns the same stored run instead of a second, divergent one.
        fingerprint = hashlib.sha256(json.dumps(
            [sorted(i.digest() for i in instructions), sorted(r.record_hash for r in records), source,
             None if statement is None else sorted(e.record_hash for e in statement), grace]).encode()).hexdigest()
        run_id = f"run_{fingerprint[:20]}"
        path = _runs_dir() / f"{run_id}.json"
        if path.exists():
            try:
                run = json.loads(path.read_text(encoding="utf-8"))
                return {"run_id": run_id, "report": run["report"], "payouts": run["payouts"], "replayed": True}
            except (OSError, ValueError, KeyError):
                pass  # an unreadable stored run is rewritten below from the same inputs
        run = {"run_id": run_id, "contract_version": CONTRACT_VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
               "source": source, "instructions": len(instructions), "payouts": len(records), "input_digest": fingerprint,
               "report": report}
        _save(path, json.dumps(run).encode("utf-8"))  # a reader never sees half a run
        return {"run_id": run_id, "report": report, "payouts": len(records), "replayed": False}

    def list_runs(self, _body):
        runs = []
        unreadable = 0
        for p in sorted(_runs_dir().glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:100] if _runs_dir().exists() else []:
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
                runs.append({k: r[k] for k in ("run_id", "created_at", "source", "instructions", "payouts")} | {"counts": r["report"]["counts"]})
            except (OSError, ValueError, KeyError):
                unreadable += 1  # one damaged file must not hide every other run
        return {"runs": runs, "unreadable": unreadable}

    def get_run(self, run_id: str):
        if not run_id.startswith("run_") or not run_id[4:].isalnum():
            raise ApiError(404, "unknown run", "unknown_run")
        path = _runs_dir() / f"{run_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ApiError(404, "unknown run", "unknown_run") from None
        except (OSError, ValueError):
            raise ApiError(400, "stored run is unreadable; re-run the reconciliation", "unreadable_input") from None

    def export_evidence(self, run_id: str):
        """Seal a stored run into a signed evidence package a third party can verify offline."""
        from .core.evidence import export_package
        pkg = export_package(self.get_run(run_id), self.signer)
        d = home() / "evidence"
        path = d / f"{run_id}.evidence.json"   # _save creates the folder and reports a failed write
        _save(path, json.dumps(pkg, indent=1).encode("utf-8"))
        return {"path": str(path), "digest": pkg["digest"], "signing_key_id": pkg["signing_key_id"]}

    def verify_evidence(self, body):
        from .core.evidence import load_package, verify_package
        pkg = body.get("package")
        if pkg is None and body.get("path"):
            try:
                pkg = load_package(body["path"])
            except OSError as e:
                raise ApiError(400, f"cannot read evidence package: {e}", "unreadable_input") from e
            except ValueError:
                return {"ok": False, "problems": ["evidence package is not valid JSON"]}
        if pkg is None:
            raise ApiError(400, "give package or path")
        ok, problems = verify_package(pkg, self.key)
        return {"ok": ok, "problems": problems}

    def checkpoint(self, body):
        try:
            cp = create_checkpoint(default_log(), self.signer, tsa_url=body.get("tsa_url", ""))
        except ValueError as e:
            raise ApiError(400, str(e)) from e
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
        """Seed a realistic run: five approved disbursals, a payout file with the attacks CERT-In
        describes (no instruction, changed amount, changed beneficiary, paid twice) and a bank
        statement that shows one "processed" payout never left the bank (forged provider status)."""
        made = []
        for i, (amt, fa) in enumerate([("48500.00", "fa_borrower_01"), ("125000.00", "fa_borrower_02"),
                                       ("30000.00", "fa_borrower_03"), ("75000.00", "fa_borrower_04"),
                                       ("60000.00", "fa_borrower_05")], 1):
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
                   row("pout_0006", "", 9_900_000, "fa_mule_77"),
                   row("pout_0007", made[4]["instruction_id"], 6_000_000, "fa_borrower_05")]
        path = home() / "demo_payouts.json"
        path.write_text(json.dumps({"entity": "collection", "items": payouts}, indent=2), encoding="utf-8")
        # the bank moved every payout except pout_0007, whose "processed" status is forged
        debits = [{"entry_id": f"stmt_{p['id'][-4:]}", "utr": p["utr"], "amount_minor": p["amount"], "currency": "INR",
                   "direction": "debit", "time": (now + 30) * 1000, "narration": f"IMPS/{p['id']}"}
                  for p in payouts if p["id"] != "pout_0007"]
        stmt = home() / "demo_statement.json"
        stmt.write_text(json.dumps({"entries": debits}, indent=2), encoding="utf-8")
        # DEMO: grace 0 so the missing debit shows at once; real runs keep the 2-day default
        return {"instructions": len(made), "payouts_path": str(path), "source": "razorpayx",
                "statement_path": str(stmt), "settlement_grace_minutes": 0}

    def routes(self) -> Dict[Tuple[str, str], Callable[[Dict], Dict]]:
        """Canonical routes live under /api/v1. The unversioned /api paths are the same
        handlers kept for the 0.5.x app and scripts; they return the legacy error shape."""
        base = {("GET", "/status"): self.status, ("GET", "/instructions"): self.list_instructions,
                ("POST", "/instructions"): self.sign, ("POST", "/verify"): self.verify,
                ("POST", "/payouts/reconcile"): self.reconcile, ("POST", "/checkpoints"): self.checkpoint,
                ("GET", "/checkpoints/verify"): self.verify_checkpoints, ("POST", "/demo"): self.demo,
                ("GET", "/runs"): self.list_runs, ("POST", "/evidence/verify"): self.verify_evidence}
        out = {}
        for (m, p), fn in base.items():
            out[(m, f"/api/v1{p}")] = fn
            if p not in ("/runs", "/evidence/verify"):
                out[(m, f"/api{p}")] = fn
        return out


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

        @staticmethod
        def _error(code: str, message: str, path: str) -> Dict:
            if path.startswith("/api/v1/"):
                return {"error": {"code": code, "message": message}, "contract_version": CONTRACT_VERSION}
            return {"error": message}  # legacy shape for the unversioned routes

        def _handle(self, method: str) -> None:
            path, role, status, ref = self.path.split("?")[0], "", 500, ""
            client = self.client_address[0]
            now = time.monotonic()
            try:
                if self.headers.get("Host", "").lower() not in port_hosts:
                    raise ApiError(403, "bad host", "bad_host")
                # A valid token is always served: every local client shares 127.0.0.1, so a lockout
                # applied to valid tokens let any local process deny the executor its gate (CSO-1).
                role = _role_for(self.headers.get("Authorization", ""), tokens)
                if not role:
                    if limiter.blocked(client, now):
                        raise ApiError(429, "too many bad tokens; locked out for a minute", "locked_out")
                    limiter.fail(client, now)
                    raise ApiError(401, "missing or wrong token")
                if not limiter.allow(role, now):
                    raise ApiError(429, "rate limit")
                fn = routes.get((method, path))
                perm_key = (method, path.replace("/api/v1/", "/api/", 1))
                if fn is None and method == "GET" and path.startswith("/api/v1/runs/"):
                    run_id = path[len("/api/v1/runs/"):]
                    fn, perm_key = (lambda _b, rid=run_id: api.get_run(rid)), ("GET", "/api/runs")
                if fn is None and method == "POST" and path.startswith("/api/v1/runs/") and path.endswith("/evidence"):
                    run_id = path[len("/api/v1/runs/"):-len("/evidence")]
                    fn, perm_key = (lambda _b, rid=run_id: api.export_evidence(rid)), ("GET", "/api/runs")
                if fn is None:
                    raise ApiError(404, "no such endpoint")
                if role not in PERMS[perm_key]:
                    raise ApiError(403, f"role {role} may not call {method} {path}")
                body: Dict = {}
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > MAX_BODY:
                        raise ApiError(413, "body too large")
                    try:
                        body = json.loads(self.rfile.read(n) or b"{}")
                    except ValueError:
                        raise ApiError(400, "body is not JSON") from None
                    if not isinstance(body, dict):
                        raise ApiError(400, "body must be a JSON object")
                    ref = str(body.get("instruction_id", ""))[:64]
                out = fn(body)
                ref = ref or str((out.get("instruction") or {}).get("instruction_id", ""))
                status = 200
                self._send(200, out)
            except ApiError as e:
                status = e.status
                self._send(e.status, self._error(e.code, str(e), path))
            except Exception as e:  # never leak a traceback to the client; report the type only
                self._send(500, self._error("internal", f"internal error ({type(e).__name__})", path))
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
