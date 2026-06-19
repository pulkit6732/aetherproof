"""Persistent app signing key + receipt issuance (sign, persist, log)."""

import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Tuple

from .signer import Signer
from .receipt import Receipt
from .log import ReceiptLog

KEY_DIR = Path.home() / ".aetherproof"


def load_or_create_signer(key_dir: Path = None) -> Signer:
    key_dir = key_dir or KEY_DIR
    key_dir.mkdir(parents=True, exist_ok=True)
    priv = key_dir / "signing_key.pem"
    pub = key_dir / "signing_key.pub"
    if priv.exists():
        return Signer.from_private_file(str(priv))
    signer = Signer.generate()
    signer.export_private_file(str(priv))
    signer.export_public_file(str(pub))
    return signer


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
    receipts_dir: Path = KEY_DIR / "receipts",
) -> Tuple[Receipt, Path]:
    """Build, sign, persist, and log a receipt.

    The log_sequence is reserved (max+1) and the log_anchor set BEFORE signing,
    so both are covered by the signature. Files are written first; log.append is
    the commit point — on any failure the files are rolled back so nothing is
    left orphaned. Raises ValueError on a concurrent sequence collision.
    """
    receipts_dir.mkdir(parents=True, exist_ok=True)
    seq = log.max_sequence() + 1
    receipt = Receipt(
        receipt_version="1.1",
        model_weight_root=model_weight_root,
        model_root_type=model_root_type,
        input_commitment=input_commitment,
        output_hash=output_hash,
        timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
        log_sequence=seq,
        hw_evidence=[],
        signature="",
        log_anchor=f"local://log/{seq}",
        receipt_id=f"ap_{secrets.token_hex(4)}",
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
    finally:
        if not committed:
            _cleanup(written)

    return receipt, path
