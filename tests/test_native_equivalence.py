"""The native Rust core must agree with the pure-Python implementation exactly.

The extension is optional. `aetherproof` never imports it, so its absence changes
nothing and these tests skip. When it *is* installed, every function it exposes
must produce byte-identical output to the Python it mirrors - otherwise a caller
who opts into the faster path gets different receipts, which is worse than having
no faster path at all.

Build it with:

    cd rust/py && python -m maturin build --release
    pip install ../target/wheels/aetherproof_native-*.whl
"""

import hashlib
import random

import pytest

from aetherproof.core.hash import merkle_leaf, merkle_node
from aetherproof.core.session import inclusion_proof, merkle_root, verify_inclusion

native = pytest.importorskip("_native", reason="native extension not built")


def leaves(n, tag="t"):
    return [hashlib.sha256(f"{tag}-{i}".encode()).hexdigest() for i in range(n)]


# ── Constants ────────────────────────────────────────────────────────────────


def test_domain_prefixes_match():
    from aetherproof.core.hash import LEAF_PREFIX, NODE_PREFIX

    assert native.LEAF_PREFIX == LEAF_PREFIX[0]
    assert native.NODE_PREFIX == NODE_PREFIX[0]


def test_receipt_size_is_the_frozen_wire_size():
    assert native.RECEIPT_SIZE == 128
    assert native.receipt_size() == 128
    assert native.SIGNED_PREFIX == 64


# ── Primitives ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("h", ["00" * 32, "ff" * 32, "de" * 32, hashlib.sha256(b"x").hexdigest()])
def test_merkle_leaf_matches(h):
    assert native.merkle_leaf(h) == merkle_leaf(h)


def test_merkle_node_matches():
    a, b = "aa" * 32, "bb" * 32
    assert native.merkle_node(a, b) == merkle_node(a, b)
    # Order matters, and must matter identically in both.
    assert native.merkle_node(b, a) == merkle_node(b, a)
    assert native.merkle_node(a, b) != native.merkle_node(b, a)


# ── Roots ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 64, 100, 257])
def test_merkle_root_matches(n):
    """Sizes chosen to cover powers of two and the odd-promotion cases around them."""
    assert native.merkle_root(leaves(n)) == merkle_root(leaves(n))


def test_odd_leaf_promotion_agrees():
    """CVE-2012-2459: [A,B,C] and [A,B,C,C] must differ, in both implementations."""
    three = leaves(3)
    four = three + [three[2]]
    assert merkle_root(three) != merkle_root(four)
    assert native.merkle_root(three) != native.merkle_root(four)
    assert native.merkle_root(three) == merkle_root(three)
    assert native.merkle_root(four) == merkle_root(four)


# ── Proofs ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 17, 32, 33, 64])
def test_inclusion_proof_matches_for_every_index(n):
    src = leaves(n)
    for i in range(n):
        py = [list(step) for step in inclusion_proof(src, i)]
        rs = [list(step) for step in native.inclusion_proof(src, i)]
        assert py == rs, f"proof for leaf {i} of {n} differs"


@pytest.mark.parametrize("n", [1, 3, 8, 17, 33])
def test_proofs_cross_verify_in_both_directions(n):
    """A proof from either implementation must satisfy the other's verifier."""
    src = leaves(n)
    root = merkle_root(src)
    assert native.merkle_root(src) == root
    for i in range(n):
        py_proof = inclusion_proof(src, i)
        rs_proof = native.inclusion_proof(src, i)
        assert verify_inclusion(src[i], py_proof, root)
        assert native.verify_inclusion(src[i], rs_proof, root)
        # The real check: each verifier accepts the other's proof.
        assert native.verify_inclusion(src[i], py_proof, root)
        assert verify_inclusion(src[i], [tuple(s) for s in rs_proof], root)


def test_out_of_range_index_raises_in_both():
    src = leaves(5)
    with pytest.raises(IndexError):
        inclusion_proof(src, 5)
    with pytest.raises(IndexError):
        native.inclusion_proof(src, 5)


def test_native_rejects_a_proof_for_the_wrong_leaf():
    src = leaves(8)
    root = merkle_root(src)
    proof = inclusion_proof(src, 3)
    assert native.verify_inclusion(src[3], proof, root)
    assert not native.verify_inclusion(src[4], proof, root)


def test_native_rejects_an_unknown_side_marker():
    src = leaves(8)
    root = merkle_root(src)
    bad = [("X", h) for _, h in inclusion_proof(src, 3)]
    assert not native.verify_inclusion(src[3], bad, root)
    assert not verify_inclusion(src[3], bad, root)


def test_randomised_agreement():
    random.seed(20260816)
    for _ in range(150):
        n = random.randint(1, 60)
        src = [hashlib.sha256(random.randbytes(16)).hexdigest() for _ in range(n)]
        assert native.merkle_root(src) == merkle_root(src)
        i = random.randrange(n)
        assert [list(s) for s in native.inclusion_proof(src, i)] == [
            list(s) for s in inclusion_proof(src, i)
        ]


# ── Receipts ─────────────────────────────────────────────────────────────────


def test_native_receipt_roundtrip():
    seed = bytes(range(32))
    data = native.generate_receipt(1, b"model-bytes", 0, 1, seed)
    assert len(data) == 128
    assert data[:8] == b"AETHPRF1"

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    from cryptography.hazmat.primitives import serialization

    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    assert native.verify_receipt(data, raw) is True

    tampered = bytearray(data)
    tampered[16] ^= 0xFF
    assert native.verify_receipt(bytes(tampered), raw) is False


def test_native_receipt_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        native.generate_receipt(1, b"x", 0, 1, b"too-short")


def test_fnv1a_is_deterministic_and_distinguishing():
    assert native.fnv1a(b"") == native.fnv1a(b"")
    assert native.fnv1a(b"a") != native.fnv1a(b"b")


# ── Post-quantum ─────────────────────────────────────────────────────────────


def test_pq_hybrid_roundtrip_and_backward_compatibility():
    pk, sk = native.pq_keygen()
    assert len(pk) == 1952, "ML-DSA-65 public key is 1952 bytes"

    seed = bytes(range(32))
    core = native.generate_receipt(9, b"weights", 0, 1, seed)
    hybrid = native.pq_attach(core, sk)

    # The core must be untouched, so a pre-trailer verifier still works.
    assert hybrid[:128] == core
    assert len(hybrid) == 3453, "128 core + 16 header + 3309 ML-DSA signature"
    assert native.pq_has_trailer(hybrid)
    assert not native.pq_has_trailer(core)
    assert native.pq_verify(hybrid, pk) is True


def test_pq_rejects_wrong_key_and_tampering():
    pk, sk = native.pq_keygen()
    other_pk, _ = native.pq_keygen()
    core = native.generate_receipt(9, b"weights", 0, 1, bytes(range(32)))
    hybrid = native.pq_attach(core, sk)

    assert native.pq_verify(hybrid, other_pk) is False

    tampered = bytearray(hybrid)
    tampered[16] ^= 0xFF  # inside the signed prefix
    assert native.pq_verify(bytes(tampered), pk) is False

    truncated = hybrid[:-1]
    assert native.pq_verify(truncated, pk) is False
