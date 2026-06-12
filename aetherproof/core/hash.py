"""Hashing utilities: SHA-256 for inputs, outputs, and Merkle trees for model weights."""

import hashlib
import os
from pathlib import Path
from typing import Union, List, Tuple


def sha256(data: Union[str, bytes]) -> str:
    """Compute SHA-256 hash of data.

    Args:
        data: string or bytes to hash

    Returns:
        Hex-encoded SHA-256 hash
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file (streaming for large files).

    Args:
        file_path: path to file

    Returns:
        Hex-encoded SHA-256 hash
    """
    hasher = hashlib.sha256()
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)

    return hasher.hexdigest()


def merkle_hash(left: str, right: str) -> str:
    """Compute Merkle parent hash from two children."""
    combined = (left + right).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def compute_merkle_root(hashes: List[str]) -> str:
    """Compute Merkle root from a list of leaf hashes.

    Args:
        hashes: list of hex-encoded hashes

    Returns:
        Hex-encoded Merkle root

    If list is empty, return empty string. If list has one item, return it.
    """
    if not hashes:
        return ""
    if len(hashes) == 1:
        return hashes[0]

    # Build tree bottom-up, padding with last hash if odd count
    current_level = hashes.copy()

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
            parent = merkle_hash(left, right)
            next_level.append(parent)
        current_level = next_level

    return current_level[0]


def compute_model_weight_root(model_path: Union[str, Path], chunk_size: int = 4096) -> str:
    """Compute SHA-256 Merkle root over model weights.

    For a single file, this is just the file's SHA-256.
    For a directory, hash each file and compute Merkle root of hashes.

    Args:
        model_path: path to model file or directory
        chunk_size: size of chunks when splitting large files (not used for single files)

    Returns:
        Hex-encoded Merkle root
    """
    model_path = Path(model_path)

    if model_path.is_file():
        # Single file: return its SHA-256
        return sha256_file(model_path)

    elif model_path.is_dir():
        # Directory: hash each file, compute Merkle root
        file_hashes = []
        for file_path in sorted(model_path.rglob("*")):
            if file_path.is_file():
                file_hashes.append(sha256_file(file_path))

        if not file_hashes:
            return ""

        return compute_merkle_root(file_hashes)

    else:
        raise FileNotFoundError(f"Model path not found: {model_path}")


def hash_input(input_text: str) -> str:
    """Compute SHA-256 hash of input prompt.

    Args:
        input_text: raw input text (may include data to be hidden by later privacy layer)

    Returns:
        Hex-encoded SHA-256 hash
    """
    return sha256(input_text)


def hash_output(output_text: str) -> str:
    """Compute SHA-256 hash of model output.

    Args:
        output_text: raw output text from the model

    Returns:
        Hex-encoded SHA-256 hash
    """
    return sha256(output_text)
