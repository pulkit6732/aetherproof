"""Persistent app signing key + receipt issuance (sign, persist, log)."""

import os
import secrets
import stat
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple

from .signer import Signer
from .receipt import Receipt
from .log import ReceiptLog

HOME_ENV = "AETHERPROOF_HOME"


def home() -> Path:
    """Where keys, the log, and receipts live.

    Read from the environment on every call, not captured at import: a constant
    frozen at import time silently ignored AETHERPROOF_HOME for the CLI while
    aetherproof.auto honoured it, so the two halves of the same tool disagreed
    about where a user's receipts were.
    """
    d = os.environ.get(HOME_ENV)
    return Path(d) if d else Path.home() / ".aetherproof"


def log_path() -> Path:
    """The transparency log.

    MUST be absolute. ReceiptLog's own default is "./receipts/log.db", which is
    CWD-relative — signing from two different directories produced two separate
    logs, so the append-only chain silently forked per working directory and
    neither log was complete.
    """
    return home() / "log.db"


def default_log() -> ReceiptLog:
    return ReceiptLog(db_path=str(log_path()))


def receipts_path() -> Path:
    return home() / "receipts"


def __getattr__(name):
    # KEY_DIR stays importable for existing callers but now tracks the env var
    # instead of being frozen at import time.
    if name == "KEY_DIR":
        return home()
    raise AttributeError(name)

# Optional passphrase for the private key at rest. When set, the PEM is written
# with BestAvailableEncryption instead of NoEncryption. Left unset the key is
# still written 0600, but an attacker who can read the file can forge receipts —
# so the env var is the difference between "protected by file permissions" and
# "protected by a secret".
PASSPHRASE_ENV = "AETHERPROOF_KEY_PASSPHRASE"

_MAX_SEQUENCE_ATTEMPTS = 16

# Namespace for conversation binding. Follows the v1.2 signed-extensions
# convention from issue #1 (safal207's causal-context proposal), so the
# commitment lands inside the signature rather than beside it.
SESSION_NS = "org.aetherproof.session/v0.1"


def _passphrase() -> Optional[bytes]:
    p = os.environ.get(PASSPHRASE_ENV)
    return p.encode("utf-8") if p else None


def _chmod_600(path: Path) -> None:
    """Owner-read/write only. Best effort — POSIX bits are advisory on Windows."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def load_or_create_signer(key_dir: Path = None) -> Signer:
    """Load the persistent signing key, creating it exactly once.

    Creation is an atomic O_EXCL claim rather than exists()-then-write. The old
    check-then-create was a race: measured over 8 trials x 16 threads it handed
    out 2-4 DISTINCT keys every single time, and the losing threads' public keys
    were overwritten and never persisted — making their receipts permanently
    unverifiable. Now exactly one caller wins the create; everyone else falls
    through and reads the winner's key.
    """
    key_dir = key_dir or home()
    key_dir.mkdir(parents=True, exist_ok=True)
    priv = key_dir / "signing_key.pem"
    pub = key_dir / "signing_key.pub"
    pw = _passphrase()

    if priv.exists():
        return Signer.from_private_file(str(priv), password=pw)

    candidate = Signer.generate()
    pem = candidate.export_private_pem(password=pw)
    try:
        # O_EXCL is the atomic claim — it fails if anyone else got here first.
        fd = os.open(priv, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # Lost the race: the winner's key is authoritative. Discard ours rather
        # than overwriting, which is what produced orphaned signers before.
        return Signer.from_private_file(str(priv), password=pw)

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    except BaseException:
        try:
            priv.unlink()
        except OSError:
            pass
        raise

    _chmod_600(priv)
    candidate.export_public_file(str(pub))
    return candidate


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _cleanup(paths) -> None:
    for p in paths:
        try:
            p.unlink()
        except OSError:
            pass


def issue_receipt(
    signer: Signer,
    log: ReceiptLog,
    *,
    model_weight_root: str,
    output_hash: str,
    model_root_type: str = "artifact_hash",
    input_commitment: str = "",
    receipts_dir: Path = None,
    session_id: str = "",
    turn_index: int = None,
    session_root: str = "",
    extensions: dict = None,
) -> Tuple[Receipt, Path]:
    """Build, sign, persist, and log a receipt.

    The log_sequence is reserved (max+1) and the log_anchor set BEFORE signing,
    so both are covered by the signature. Files are written first; log.append is
    the commit point — on any failure the files are rolled back so nothing is
    left orphaned. Raises ValueError on a concurrent sequence collision.

    Passing `session_id` / `turn_index` / `session_root` binds this receipt to a
    conversation via the v1.2 signed-extensions namespace, so a standalone
    receipt file says which session and turn it came from. Without it a receipt
    is an orphan: nothing connects turn N to turn N-1, which was the gap the
    agent-chain extension (issue #1) was proposed to close and which
    issue_receipt never populated.
    """
    receipts_dir = Path(receipts_dir) if receipts_dir else receipts_path()
    receipts_dir.mkdir(parents=True, exist_ok=True)

    # Assemble the signed extensions once — every retry must sign the same
    # context, or the receipt's identity would shift between attempts.
    signed_ext = dict(extensions or {})
    ctx = {}
    if session_id:
        ctx["session_id"] = session_id
    if turn_index is not None:
        ctx["turn_index"] = str(turn_index)
    if session_root:
        ctx["session_root"] = session_root
    if ctx:
        signed_ext.setdefault(SESSION_NS, {}).update(ctx)

    # The sequence is inside the signing preimage, so it cannot be assigned
    # after signing — it has to be chosen, signed, and committed, and if another
    # writer took that slot first the whole build must be redone. v0.2.2 tried
    # once and gave up: 29 of 32 concurrent calls failed. Signing is ~45 us, so
    # retrying is far cheaper than the lock it would otherwise need.
    last_error = None
    for _attempt in range(_MAX_SEQUENCE_ATTEMPTS):
        seq = log.max_sequence() + 1
        receipt = Receipt(
            model_weight_root=model_weight_root,
            model_root_type=model_root_type,
            input_commitment=input_commitment,
            output_hash=output_hash,
            timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
            log_sequence=seq,
            hw_evidence=[],
            signature="",
            log_anchor=f"local://log/{seq}",
            receipt_id=f"ap_{secrets.token_hex(8)}",
            # names the key, so a verifier holding many keys picks the right one
            # in a single lookup instead of trying each in turn
            signing_key_id=Receipt.key_id(signer.get_public_key()),
            signed_extensions=signed_ext,
        )
        receipt.signature = signer.sign(receipt.signing_bytes())

        path = receipts_dir / f"{receipt.receipt_id}.json"
        pub = path.with_suffix(".pub")
        written = []
        committed = False
        try:
            _atomic_write(path, receipt.to_json(pretty=True).encode("utf-8"))
            written.append(path)
            _atomic_write(pub, signer.get_public_key().export_public_pem())
            written.append(pub)
            assigned = log.append(receipt)
            if assigned != seq:
                raise RuntimeError(f"log sequence drift ({assigned} != {seq}); concurrent write")
            committed = True
        except (ValueError, RuntimeError) as e:
            # Slot taken by a concurrent writer. Files are rolled back in the
            # finally block; loop and re-sign against the new head.
            last_error = e
        finally:
            if not committed:
                _cleanup(written)

        if committed:
            return receipt, path

    raise RuntimeError(
        f"could not reserve a log sequence after {_MAX_SEQUENCE_ATTEMPTS} attempts: {last_error}"
    )
