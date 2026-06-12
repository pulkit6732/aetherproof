"""Pytest configuration."""

import pytest


@pytest.fixture
def sample_output():
    """Sample AI model output for testing."""
    return "This is a sample AI output that demonstrates the receipt system."


@pytest.fixture
def sample_model_path(tmp_path):
    """Create a sample model file for testing."""
    model_file = tmp_path / "model.onnx"
    model_file.write_bytes(b"SAMPLE_ONNX_DATA" * 100)
    return model_file
