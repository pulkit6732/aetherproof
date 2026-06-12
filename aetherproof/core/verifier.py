"""Offline receipt verification — the core invariant."""

from typing import Optional, Dict, Any
from pathlib import Path
from .receipt import Receipt
from .signer import Verifier
from .hash import sha256


def verify_receipt(
    receipt: Receipt, public_key: Verifier, log_entry: Optional[Dict[str, Any]] = None
) -> bool:
    """Verify a receipt with only the three required inputs.

    THE INVARIANT:
    Verify(receipt, public_key, log) = TRUE
    using ONLY those three inputs, forever, with zero dependency on
    AetherProof/Signet servers, any vendor SDK, or any hardware driver.

    Args:
        receipt: Receipt object to verify
        public_key: Verifier (public key) from the signer
        log_entry: Optional log entry dict for transparency log anchor validation

    Returns:
        True if receipt is valid and unmodified, False otherwise
    """
    # 1. Check receipt fields are non-empty
    if not receipt.receipt_id:
        return False
    if not receipt.model_weight_root:
        return False
    if not receipt.output_hash:
        return False
    if not receipt.signature:
        return False

    # 2. Reconstruct the message that was signed
    # Message format: receipt fields in canonical order, as strings
    message = _canonical_message(receipt)

    # 3. Verify the Ed25519 signature
    if not public_key.verify(message.encode("utf-8"), receipt.signature):
        return False

    # 4. Verify log anchor if log_entry is provided
    if log_entry:
        if not _verify_log_anchor(receipt, log_entry):
            return False

    return True


def verify_receipt_file(
    receipt_path: str, pubkey_path: str, log_path: Optional[str] = None
) -> bool:
    """Verify a receipt file with a public key file (offline, no network).

    Args:
        receipt_path: path to saved receipt JSON
        pubkey_path: path to public key PEM file
        log_path: optional path to transparency log

    Returns:
        True if receipt is valid
    """
    # Load receipt from file
    with open(receipt_path, "r") as f:
        receipt = Receipt.from_json(f.read())

    # Load public key
    public_key = Verifier.from_public_file(pubkey_path)

    # Load log entry if log_path provided (not required for core verification)
    log_entry = None
    if log_path:
        import json

        with open(log_path, "r") as f:
            log_data = json.load(f)
            # Look for receipt in log by sequence number
            if receipt.log_sequence > 0:
                for entry in log_data:
                    if entry.get("sequence") == receipt.log_sequence:
                        log_entry = entry
                        break

    return verify_receipt(receipt, public_key, log_entry)


def verify_output_unmodified(receipt: Receipt, current_output_hash: str) -> bool:
    """Verify that model output has NOT been modified since receipt generation.

    Args:
        receipt: the original receipt
        current_output_hash: SHA-256 of current output

    Returns:
        True if output matches (unmodified), False otherwise
    """
    return receipt.output_hash == current_output_hash


def verify_model_identity(receipt: Receipt, current_model_weight_root: str) -> bool:
    """Verify that model has NOT been swapped (FDA PCCP use case).

    Args:
        receipt: the original receipt
        current_model_weight_root: SHA-256 Merkle root of current weights

    Returns:
        True if model matches (not swapped), False otherwise
    """
    return receipt.model_weight_root == current_model_weight_root


def tamper_detect(receipt: Receipt, public_key: Verifier) -> bool:
    """Tamper detection test: flip a bit in the receipt, should FAIL.

    This is a one-bit probe. If the signature verifies after a single bit flip,
    something is wrong with the cryptography.

    Args:
        receipt: Receipt to test
        public_key: Verifier (public key)

    Returns:
        False if tamper detection fails (bad), True if works (good)
    """
    # Flip one bit in the model_weight_root
    tampered_root = list(receipt.model_weight_root)
    if tampered_root:
        # Flip first hex digit
        original_char = tampered_root[0]
        tampered_root[0] = "F" if original_char != "F" else "0"
        tampered = Receipt(
            receipt_version=receipt.receipt_version,
            model_weight_root="".join(tampered_root),
            input_commitment=receipt.input_commitment,
            output_hash=receipt.output_hash,
            timestamp_ms=receipt.timestamp_ms,
            log_sequence=receipt.log_sequence,
            hw_evidence=receipt.hw_evidence,
            signature=receipt.signature,
            log_anchor=receipt.log_anchor,
            receipt_id=receipt.receipt_id,
        )

        # Original should verify, tampered should NOT
        original_valid = verify_receipt(receipt, public_key)
        tampered_valid = verify_receipt(tampered, public_key)

        return original_valid and not tampered_valid

    return False


def _canonical_message(receipt: Receipt) -> str:
    # delegate to the single source of truth on Receipt
    return receipt.canonical_message()


def _verify_log_anchor(receipt: Receipt, log_entry: Dict[str, Any]) -> bool:
    """Verify that the receipt's log anchor matches the log entry.

    Args:
        receipt: Receipt with log anchor
        log_entry: Entry from transparency log

    Returns:
        True if anchor is valid
    """
    if not receipt.log_anchor or not log_entry:
        return True  # Not validating if anchor/entry missing

    # Log anchor format: "local://log/<sequence>"
    # Check that the receipt's sequence matches the log entry's sequence
    expected_sequence = receipt.log_sequence
    log_sequence = log_entry.get("sequence")

    return expected_sequence == log_sequence and expected_sequence > 0
