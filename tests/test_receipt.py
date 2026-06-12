"""Tests for Receipt dataclass."""

import pytest
from datetime import datetime
from aetherproof.core.receipt import Receipt


def test_receipt_creation():
    """Test creating a Receipt."""
    receipt = Receipt(
        receipt_version="1.0",
        model_weight_root="abc123",
        output_hash="def456",
        timestamp_ms=1700000000000,
    )
    assert receipt.receipt_version == "1.0"
    assert receipt.model_weight_root == "abc123"
    assert receipt.output_hash == "def456"


def test_receipt_auto_timestamp():
    """Test that Receipt auto-generates timestamp if not provided."""
    receipt = Receipt()
    assert receipt.timestamp_ms > 0


def test_receipt_auto_receipt_id():
    """Test that Receipt auto-generates receipt_id."""
    receipt = Receipt(timestamp_ms=1700000000000)
    assert receipt.receipt_id.startswith("receipt_")


def test_receipt_to_json():
    """Test JSON serialization."""
    receipt = Receipt(
        model_weight_root="abc123",
        output_hash="def456",
    )
    json_str = receipt.to_json()
    assert "abc123" in json_str
    assert "def456" in json_str


def test_receipt_from_json():
    """Test JSON deserialization."""
    original = Receipt(
        model_weight_root="abc123",
        output_hash="def456",
    )
    json_str = original.to_json()
    reconstructed = Receipt.from_json(json_str)
    assert reconstructed.model_weight_root == original.model_weight_root
    assert reconstructed.output_hash == original.output_hash


def test_receipt_round_trip():
    """Test to_dict -> from_dict round trip."""
    original = Receipt(
        model_weight_root="hash1",
        input_commitment="hash2",
        output_hash="hash3",
        timestamp_ms=1700000000000,
    )
    data = original.to_dict()
    reconstructed = Receipt.from_dict(data)
    assert reconstructed.model_weight_root == original.model_weight_root
    assert reconstructed.input_commitment == original.input_commitment
