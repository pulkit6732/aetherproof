"""Headless AetherProof - zero interaction, for automation.

The wizard and the CLI both assume a human at a terminal. That is the wrong
shape for where receipts actually need to be generated: a cloud coding model, a
CI job, an agent loop, a cron task. Those callers cannot answer a prompt, cannot
read a passphrase from a TTY, and must never block.

Everything here is configured by environment or by argument, never by prompt.
Nothing in this module reads stdin or writes to stdout.

    # one-liner, works with no setup at all
    from aetherproof.auto import sign
    receipt = sign(prompt="what is 2+2?", output="4", model_id="gpt-4o")

    # a whole conversation, sealed once at the end
    from aetherproof.auto import AutoSession
    with AutoSession(model_id="claude-opus-5") as s:
        s.turn(prompt=..., output=...)
        s.turn(prompt=..., output=...)
    # seals on exit; s.seal_path holds the signed root

    # wrap any client call - the lazy path
    from aetherproof.auto import receipted
    @receipted(model_id="gpt-4o")
    def ask(prompt): return client.responses(prompt)

Configuration (all optional):
    AETHERPROOF_HOME             where keys/log/receipts live (default ~/.aetherproof)
    AETHERPROOF_KEY_PASSPHRASE   encrypts the key at rest; unset = unprotected
    AETHERPROOF_DISABLE=1        turn every call in this module into a no-op
    AETHERPROOF_STRICT=1         raise on failure instead of degrading quietly

Failure policy, and it is deliberate: receipt generation must never take down
the caller's actual work. By default any failure here is swallowed and the
function returns None. An automated pipeline losing a receipt is bad; an
automated pipeline crashing because a receipt could not be written is worse.
Set AETHERPROOF_STRICT=1 in environments where a missing receipt IS the failure.
"""

from __future__ import annotations

import functools
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .core.hash import sha256
from .core.keystore import load_or_create_signer, issue_receipt
from .core.log import ReceiptLog
from .core.receipt import Receipt
from .core.session import Session, SessionSeal
from .core.signer import Signer

HOME_ENV = "AETHERPROOF_HOME"
DISABLE_ENV = "AETHERPROOF_DISABLE"
STRICT_ENV = "AETHERPROOF_STRICT"

_lock = threading.Lock()
_signer: Optional[Signer] = None
_log: Optional[ReceiptLog] = None
_home: Optional[Path] = None


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def is_disabled() -> bool:
    return _truthy(DISABLE_ENV)


def is_strict() -> bool:
    return _truthy(STRICT_ENV)


def home() -> Path:
    d = os.environ.get(HOME_ENV)
    return Path(d) if d else Path.home() / ".aetherproof"


def _swallow(exc: BaseException):
    """Re-raise in strict mode, otherwise degrade to None."""
    if is_strict():
        raise exc
    return None


def reset() -> None:
    """Drop cached handles. Needed when AETHERPROOF_HOME changes mid-process."""
    global _signer, _log, _home
    with _lock:
        _signer = None
        _log = None
        _home = None


def _ensure():
    """Lazily build the signer and log, once per process, thread-safely.

    load_or_create_signer is already race-safe across processes (atomic O_EXCL);
    this lock just avoids doing the work N times in one process.
    """
    global _signer, _log, _home
    current = home()
    if _signer is not None and _log is not None and _home == current:
        return _signer, _log
    with _lock:
        if _signer is None or _log is None or _home != current:
            current.mkdir(parents=True, exist_ok=True)
            _signer = load_or_create_signer(key_dir=current)
            _log = ReceiptLog(db_path=str(current / "log.db"))
            _home = current
    return _signer, _log


def signer() -> Optional[Signer]:
    """The process signing key, created on first use."""
    if is_disabled():
        return None
    try:
        return _ensure()[0]
    except Exception as e:
        return _swallow(e)


def public_key_pem() -> Optional[bytes]:
    """The public key to hand a verifier. Safe to publish."""
    s = signer()
    return s.get_public_key().export_public_pem() if s else None


# ── single receipt ───────────────────────────────────────────────────────────

def sign(
    *,
    output: str = "",
    prompt: str = "",
    model_id: str = "",
    output_hash: str = "",
    input_commitment: str = "",
    model_root_type: str = "",
    session_id: str = "",
    turn_index: int = None,
    **metadata: Any,
) -> Optional[Receipt]:
    """Sign one output. Returns the Receipt, or None if disabled/failed.

    Pass text and it is hashed here; pass `output_hash` directly when the caller
    streamed the output or must not retain plaintext.

    `model_id` sets the honest tier automatically: given one, the root is
    `api_attested` built from the id the provider returned; without one it is
    `name_only`. Neither claims to bind the weights - that needs a local file.
    """
    if is_disabled():
        return None
    try:
        sgn, log = _ensure()
        oh = output_hash or sha256(output)
        ic = input_commitment or (sha256(prompt) if prompt else "")

        if model_id:
            root = Receipt.api_attested_root(model_id, metadata.pop("provider", ""),
                                             **metadata)
            tier = model_root_type or "api_attested"
        else:
            root = sha256(model_id or "unspecified")
            tier = model_root_type or "name_only"

        receipt, _ = issue_receipt(
            sgn, log,
            model_weight_root=root,
            model_root_type=tier,
            input_commitment=ic,
            output_hash=oh,
            receipts_dir=home() / "receipts",
            session_id=session_id,
            turn_index=turn_index,
        )
        return receipt
    except Exception as e:
        return _swallow(e)


# ── whole conversations ──────────────────────────────────────────────────────

class AutoSession:
    """Record turns, seal once. Safe to use as a context manager.

    Sealing once at the end is the point: one signature covers the whole
    conversation, and any single turn can later be proved with ~log2(N) hashes
    without disclosing the rest.

    Per-turn receipts are OFF by default. A thousand-turn agent loop does not
    want a thousand files; it wants one seal. Set per_turn_receipts=True when
    each turn must be independently anchored in the log.
    """

    def __init__(self, model_id: str = "", session_id: str = "",
                 per_turn_receipts: bool = False, model_root_type: str = ""):
        self.model_id = model_id
        self.per_turn_receipts = per_turn_receipts
        self.model_root_type = model_root_type or ("api_attested" if model_id else "name_only")
        self.disabled = is_disabled()
        self.seal: Optional[SessionSeal] = None
        self.seal_path: Optional[Path] = None
        self.error: Optional[BaseException] = None

        self._session: Optional[Session] = None
        if not self.disabled:
            try:
                sgn, _ = _ensure()
                self._session = Session(sgn, session_id=session_id,
                                        model_id=model_id,
                                        model_root_type=self.model_root_type)
            except Exception as e:
                self.error = e
                _swallow(e)

    @property
    def session_id(self) -> str:
        # `is not None`, never truthiness: Session defines __len__, so a valid
        # but empty session is falsy and would read as "no session at all".
        return self._session.session_id if self._session is not None else ""

    def __len__(self) -> int:
        return len(self._session) if self._session is not None else 0

    def turn(self, prompt: str = "", output: str = "", *,
             prompt_hash: str = "", output_hash: str = "", **meta: Any):
        """Record one exchange. Never raises unless strict."""
        if self._session is None:
            return None
        try:
            t = self._session.record(prompt=prompt, output=output,
                                     prompt_hash=prompt_hash,
                                     output_hash=output_hash, **meta)
            if self.per_turn_receipts:
                sign(output_hash=t.output_hash, input_commitment=t.prompt_hash,
                     model_id=self.model_id, session_id=self._session.session_id,
                     turn_index=t.index)
            return t
        except Exception as e:
            self.error = e
            return _swallow(e)

    def close(self, start: int = None, end: int = None) -> Optional[SessionSeal]:
        """Seal the session (or a range of it) and write the seal to disk."""
        if self._session is None or len(self._session) == 0:
            return None
        try:
            self.seal = self._session.seal(start=start, end=end)
            out = home() / "sessions"
            out.mkdir(parents=True, exist_ok=True)
            self.seal_path = out / f"{self._session.session_id}.seal.json"
            self.seal_path.write_text(self.seal.to_json(pretty=True), encoding="utf-8")
            return self.seal
        except Exception as e:
            self.error = e
            return _swallow(e)

    def prove(self, index: int):
        """Compact proof for one turn. Write it next to the seal if you like."""
        if self._session is None:
            return None
        try:
            return self._session.prove(index)
        except Exception as e:
            return _swallow(e)

    def __enter__(self) -> "AutoSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # seal even when the caller's block raised - a crashed run still wants
        # a record of what it produced up to that point
        self.close()
        return False


@contextmanager
def session(model_id: str = "", **kw):
    """Functional form of AutoSession."""
    s = AutoSession(model_id=model_id, **kw)
    try:
        yield s
    finally:
        s.close()


# ── decorator ────────────────────────────────────────────────────────────────

def receipted(model_id: str = "", extract: Callable[[Any], str] = None,
              prompt_arg: str = "prompt"):
    """Wrap a function so every call is receipted.

    `extract` turns the return value into the text to hash; the default is str().
    The wrapped function's return value is passed through untouched, and a
    receipt failure never changes what the caller sees (unless strict).
    """
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            try:
                text = extract(result) if extract else str(result)
                prompt = kwargs.get(prompt_arg, "")
                if not prompt and args:
                    prompt = str(args[0])
                sign(prompt=prompt, output=text, model_id=model_id)
            except Exception as e:
                _swallow(e)
            return result
        return wrapper
    return decorate


# ── verification helpers ─────────────────────────────────────────────────────

def verify(receipt: Receipt, public_key=None) -> bool:
    """Verify a receipt against a public key (default: this process's key)."""
    from .core.verifier import verify_receipt
    if public_key is None:
        s = signer()
        if s is None:
            return False
        public_key = s.get_public_key()
    return verify_receipt(receipt, public_key)


def verify_turn(turn_proof, seal, public_key=None) -> bool:
    """Verify one turn against a session seal."""
    if public_key is None:
        s = signer()
        if s is None:
            return False
        public_key = s.get_public_key()
    return Session.verify_turn(turn_proof, seal, public_key)


def status() -> dict:
    """Machine-readable state. For a health check in a pipeline."""
    st = {
        "disabled": is_disabled(),
        "strict": is_strict(),
        "home": str(home()),
        "key_present": (home() / "signing_key.pem").exists(),
        "key_encrypted": False,
        "receipts": 0,
        "log_intact": None,
    }
    try:
        priv = home() / "signing_key.pem"
        if priv.exists():
            st["key_encrypted"] = b"ENCRYPTED" in priv.read_bytes()
        if not is_disabled():
            _, log = _ensure()
            st["receipts"] = log.count()
            st["log_intact"] = log.verify_integrity()
    except Exception as e:
        st["error"] = f"{type(e).__name__}: {e}"
    return st
