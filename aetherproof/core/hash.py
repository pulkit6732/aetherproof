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


# RFC 6962 §2.1 domain-separation tags. Leaves and internal nodes MUST hash
# under different prefixes: without them every node is a bare 64-hex string, so
# an internal node can be replayed as a leaf and the root no longer identifies
# one unique tree (second-preimage).
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def merkle_leaf(leaf_hash: str) -> str:
    """Hash a leaf under the leaf domain tag (RFC 6962 MTH of a 1-element list)."""
    return hashlib.sha256(LEAF_PREFIX + leaf_hash.encode("utf-8")).hexdigest()


def merkle_node(left: str, right: str) -> str:
    """Hash an internal node under the node domain tag."""
    return hashlib.sha256(NODE_PREFIX + (left + right).encode("utf-8")).hexdigest()


def merkle_hash(left: str, right: str) -> str:
    """Compute Merkle parent hash from two children.

    Deprecated alias for merkle_node, kept so external callers of the v0.2.x
    helper keep working. New code should use merkle_node/merkle_leaf.
    """
    return merkle_node(left, right)


def compute_merkle_root(hashes: List[str]) -> str:
    """Compute a Merkle root over leaf hashes, RFC 6962 style.

    Two properties the v0.2.x construction did not have:

    1. **No odd-leaf duplication.**The old code padded an odd level by hashing
       the last node against itself, which is the Bitcoin CVE-2012-2459 pattern:
       [A,B,C] and [A,B,C,C] produced an identical root, so a model directory's
       root did not identify a unique file set. An unpaired node is now promoted
       to the next level unchanged.
    2. **Leaf/internal domain separation.**Leaves hash under LEAF_PREFIX and
       internal nodes under NODE_PREFIX, so an internal node cannot be presented
       as a leaf.

    Empty list returns "". A single leaf returns its *tagged* hash, not the raw
    input - returning the leaf unchanged would break property 2 for 1-file trees.

    Args:
        hashes: list of hex-encoded leaf hashes

    Returns:
        Hex-encoded Merkle root
    """
    if not hashes:
        return ""

    current_level = [merkle_leaf(h) for h in hashes]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(merkle_node(current_level[i], current_level[i + 1]))
            else:
                # odd node out: promote unchanged, never duplicate
                next_level.append(current_level[i])
        current_level = next_level

    return current_level[0]


def compute_model_weight_root(model_path: Union[str, Path], chunk_size: int = 4096) -> str:
    """Compute SHA-256 Merkle root over model weights.

    For a single file, this is the file's SHA-256 (unchanged contract).

    For a directory, each leaf commits to the file's **path as well as its
    bytes**- `sha256("<relative/path>\\x00<digest>")`. v0.2.x hashed contents
    only, so two directories holding the same bytes under different filenames
    produced an identical root; renaming `weights.bin` to `config.json` was
    invisible to the model-identity check. Paths are POSIX-normalised so a root
    computed on Windows matches one computed on Linux.

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
        # Directory: commit to (relative path, content digest) per file, in a
        # deterministic path order, then Merkle over those leaves.
        entries = []
        for file_path in model_path.rglob("*"):
            if file_path.is_file():
                rel = file_path.relative_to(model_path).as_posix()
                entries.append((rel, sha256_file(file_path)))

        if not entries:
            return ""

        entries.sort(key=lambda e: e[0])
        leaves = [sha256(f"{rel}\x00{digest}") for rel, digest in entries]
        return compute_merkle_root(leaves)

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
