"""Tests for the verification invariant: Verify(receipt, pk, log) = TRUE forever."""

import pytest
from datetime import datetime
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer, Verifier
from aetherproof.core.verifier import (
    verify_receipt,
    verify_output_unmodified,
    verify_model_identity,
    tamper_detect,
)


def test_basic_receipt_signing_and_verification():
    """Test that we can sign a receipt and verify it."""
    # Create receipt
    receipt = Receipt(
        model_weight_root="model_hash_abc123",
        output_hash="output_hash_def456",
        timestamp_ms=1700000000000,
    )

    # Sign it
    signer = Signer.generate()
    message = f"{receipt.receipt_version}|{receipt.model_weight_root}|{receipt.input_commitment}|{receipt.output_hash}|{receipt.timestamp_ms}|{receipt.log_sequence}|{receipt.hw_evidence}|{receipt.log_anchor}"
    receipt.signature = signer.sign(message.encode("utf-8"))

    # Verify with public key
    verifier = signer.get_public_key()
    assert verify_receipt(receipt, verifier) is True


def test_tampered_receipt_fails_verification():
    """Test that tampering with a receipt breaks verification."""
    # Create and sign receipt
    receipt = Receipt(
        model_weight_root="model_hash_abc123",
        output_hash="output_hash_def456",
    )

    signer = Signer.generate()
    message = f"{receipt.receipt_version}|{receipt.model_weight_root}|{receipt.input_commitment}|{receipt.output_hash}|{receipt.timestamp_ms}|{receipt.log_sequence}|{receipt.hw_evidence}|{receipt.log_anchor}"
    receipt.signature = signer.sign(message.encode("utf-8"))
    verifier = signer.get_public_key()

    # Verify it's valid
    assert verify_receipt(receipt, verifier) is True

    # Tamper with output hash
    tampered = Receipt(
        receipt_version=receipt.receipt_version,
        model_weight_root=receipt.model_weight_root,
        input_commitment=receipt.input_commitment,
        output_hash="TAMPERED_HASH",  # Changed
        timestamp_ms=receipt.timestamp_ms,
        log_sequence=receipt.log_sequence,
        hw_evidence=receipt.hw_evidence,
        signature=receipt.signature,  # Keep same sig (invalid now)
        log_anchor=receipt.log_anchor,
        receipt_id=receipt.receipt_id,
    )

    # Should fail verification
    assert verify_receipt(tampered, verifier) is False


def test_wrong_public_key_fails_verification():
    """Test that verification fails with wrong public key."""
    receipt = Receipt(model_weight_root="abc", output_hash="def")

    # Sign with key 1
    signer1 = Signer.generate()
    message = f"{receipt.receipt_version}|{receipt.model_weight_root}|{receipt.input_commitment}|{receipt.output_hash}|{receipt.timestamp_ms}|{receipt.log_sequence}|{receipt.hw_evidence}|{receipt.log_anchor}"
    receipt.signature = signer1.sign(message.encode("utf-8"))

    # Try to verify with key 2
    signer2 = Signer.generate()
    verifier2 = signer2.get_public_key()

    assert verify_receipt(receipt, verifier2) is False


def test_verify_output_unmodified():
    """Test output modification detection."""
    receipt = Receipt(output_hash="original_output_hash")

    assert verify_output_unmodified(receipt, "original_output_hash") is True
    assert verify_output_unmodified(receipt, "different_hash") is False


def test_verify_model_identity():
    """Test model swap detection."""
    receipt = Receipt(model_weight_root="original_model_hash")

    assert verify_model_identity(receipt, "original_model_hash") is True
    assert verify_model_identity(receipt, "different_model") is False


def test_tamper_detection_probe():
    """Test the one-bit tamper detection probe."""
    receipt = Receipt(
        model_weight_root="abcdef0123456789abcdef0123456789",
        output_hash="fedcba9876543210fedcba9876543210",
    )

    signer = Signer.generate()
    message = f"{receipt.receipt_version}|{receipt.model_weight_root}|{receipt.input_commitment}|{receipt.output_hash}|{receipt.timestamp_ms}|{receipt.log_sequence}|{receipt.hw_evidence}|{receipt.log_anchor}"
    receipt.signature = signer.sign(message.encode("utf-8"))
    verifier = signer.get_public_key()

    # Tamper probe should pass (original valid, tampered invalid)
    assert tamper_detect(receipt, verifier) is True


def test_empty_receipt_fails_verification():
    """Test that a receipt with missing fields fails."""
    receipt = Receipt()  # All empty/default

    signer = Signer.generate()
    verifier = signer.get_public_key()

    # Empty receipt with no signature should fail
    assert verify_receipt(receipt, verifier) is False
