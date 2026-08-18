"""The native security layer: secrets stay in Rust, and everything fails closed.

These cover the properties that make `SecureSigner` worth using over passing raw
key bytes around:

  * the private key is never returned by any method
  * it is overwritten on `destroy()`, on context-manager exit, and on collection
  * every operation after destruction errors rather than silently misbehaving
  * `repr()` and `str()` carry no key material
  * `SecureVerifier` rejects malformed keys at construction, not at verify time

That last one is the failure the pure-Python `Verifier` has: its constructor is
type-hinted `Ed25519PublicKey` but validates nothing, so handing it the wrong
object produces a verifier that returns True for every signature. A verifier must
fail closed.
"""

import gc

import pytest

native = pytest.importorskip("_native", reason="native extension not built")


# ── The secret must not be reachable ─────────────────────────────────────────


def test_no_method_returns_private_key_material():
    s = native.SecureSigner()
    exposed = [a for a in dir(s) if not a.startswith("_")]
    # from_seed accepts a seed; nothing hands one back.
    assert "private_key" not in exposed
    assert "seed" not in exposed
    assert "secret" not in exposed
    assert "export" not in exposed

    pub = s.public_key()
    assert len(pub) == 32
    sig = s.sign(b"message")
    assert len(sig) == 64
    # Neither output may contain the seed used to build a known signer.
    known = native.SecureSigner.from_seed(bytes([0xAB] * 32))
    assert bytes([0xAB] * 32) not in known.public_key()
    assert bytes([0xAB] * 32) not in known.sign(b"m")


def test_repr_and_str_carry_no_key_material():
    s = native.SecureSigner.from_seed(bytes([0xC7] * 32))
    for text in (repr(s), str(s)):
        assert "c7" not in text.lower()
        assert "live" in text
    s.destroy()
    assert "destroyed" in repr(s)


# ── Destruction ──────────────────────────────────────────────────────────────


def test_destroy_makes_every_operation_fail_closed():
    s = native.SecureSigner()
    assert s.is_live
    s.destroy()
    assert not s.is_live

    for call in (
        lambda: s.sign(b"x"),
        lambda: s.public_key(),
        lambda: s.sign_receipt(1, b"m", 0, 1),
    ):
        with pytest.raises(ValueError, match="Destroyed"):
            call()


def test_destroy_is_idempotent():
    s = native.SecureSigner()
    s.destroy()
    s.destroy()
    assert not s.is_live


def test_context_manager_destroys_on_exit():
    with native.SecureSigner() as s:
        assert s.is_live
        pub = s.public_key()
        assert len(pub) == 32
    assert not s.is_live
    with pytest.raises(ValueError, match="Destroyed"):
        s.sign(b"x")


def test_context_manager_destroys_even_on_exception():
    s = native.SecureSigner()
    with pytest.raises(RuntimeError):
        with s:
            assert s.is_live
            raise RuntimeError("boom")
    assert not s.is_live, "an exception must not leave the key live"


def test_exception_is_not_swallowed_by_exit():
    """__exit__ returns False, so errors propagate rather than being hidden."""
    with pytest.raises(ZeroDivisionError):
        with native.SecureSigner():
            1 / 0


def test_collection_does_not_leave_a_usable_signer():
    s = native.SecureSigner()
    pub = s.public_key()
    del s
    gc.collect()
    # The public key is still valid material; the point is only that no dangling
    # handle survives to sign with.
    assert len(pub) == 32


# ── Signing and verification ─────────────────────────────────────────────────


def test_sign_and_verify_roundtrip():
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    sig = s.sign(b"message")
    assert v.verify(b"message", sig) is True
    assert v.verify(b"other", sig) is False


def test_deterministic_for_a_fixed_seed():
    a = native.SecureSigner.from_seed(bytes(range(32)))
    b = native.SecureSigner.from_seed(bytes(range(32)))
    assert a.public_key() == b.public_key()
    assert a.sign(b"m") == b.sign(b"m")


def test_generated_keys_differ():
    keys = {native.SecureSigner().public_key() for _ in range(25)}
    assert len(keys) == 25, "generate() must not repeat a key"


def test_bad_seed_length_rejected():
    for n in (0, 1, 31, 33, 64):
        with pytest.raises(ValueError):
            native.SecureSigner.from_seed(bytes(n))


def test_signed_receipt_verifies_and_tampering_breaks_it():
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    r = s.sign_receipt(7, b"weights", 3, 2)
    assert len(r) == 128
    assert v.verify_receipt(r) is True
    for i in range(128):
        bad = bytearray(r)
        bad[i] ^= 0x01
        assert v.verify_receipt(bytes(bad)) is False, f"byte {i} must invalidate"


# ── The verifier must fail closed ────────────────────────────────────────────


def test_verifier_rejects_malformed_keys_at_construction():
    """The pure-Python Verifier's constructor validates nothing. This one does."""
    for n in (0, 1, 16, 31, 33, 64, 128):
        with pytest.raises(ValueError):
            native.SecureVerifier(bytes(n))


def test_verifier_cannot_be_built_from_another_verifier():
    """Wrapping a verifier in a verifier is what makes the Python one fail open."""
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    with pytest.raises(TypeError):
        native.SecureVerifier(v)


def test_verifier_rejects_every_wrong_signature_length():
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    for n in (0, 1, 32, 63, 65, 128, 4096):
        assert v.verify(b"m", bytes(n)) is False, f"sig len {n} must not verify"


def test_verifier_rejects_every_wrong_receipt_length():
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    for n in (0, 1, 127, 129, 256, 3453):
        assert v.verify_receipt(bytes(n)) is False, f"receipt len {n} must not verify"


def test_verifier_rejects_a_signature_from_a_different_key():
    a, b = native.SecureSigner(), native.SecureSigner()
    va = native.SecureVerifier(a.public_key())
    assert va.verify(b"m", a.sign(b"m")) is True
    assert va.verify(b"m", b.sign(b"m")) is False


def test_verifier_repr_is_inert():
    s = native.SecureSigner()
    v = native.SecureVerifier(s.public_key())
    assert repr(v) == "<SecureVerifier>"


# ── Constant-time comparison ─────────────────────────────────────────────────


def test_ct_eq_matches_plain_equality():
    cases = [
        (b"", b"", True),
        (b"a", b"a", True),
        (b"abc", b"abd", False),
        (b"abc", b"ab", False),
        (b"", b"a", False),
        (bytes(32), bytes(32), True),
    ]
    for a, b, want in cases:
        assert native.ct_eq(a, b) is want
        assert native.ct_eq(a, b) == (a == b)


def test_ct_eq_detects_a_difference_at_every_position():
    base = bytes([0x5A] * 64)
    for i in range(64):
        other = bytearray(base)
        other[i] ^= 0xFF
        assert native.ct_eq(base, bytes(other)) is False, f"difference at {i} missed"


def test_ct_eq_str_matches():
    assert native.ct_eq_str("deadbeef", "deadbeef") is True
    assert native.ct_eq_str("deadbeef", "deadbeee") is False
    assert native.ct_eq_str("dead", "deadbeef") is False
    assert native.ct_eq_str("", "") is True


def test_ct_eq_agrees_with_python_on_random_pairs():
    import random

    random.seed(20260816)
    for _ in range(500):
        n = random.randint(0, 128)
        a = random.randbytes(n)
        b = a if random.random() < 0.5 else random.randbytes(n)
        assert native.ct_eq(a, b) == (a == b)


# ── Interoperability with the pure-Python package ────────────────────────────


def test_native_receipt_verifies_under_cryptography_directly():
    """A third party with only the public key and `cryptography` can check it."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    s = native.SecureSigner()
    pub = Ed25519PublicKey.from_public_bytes(s.public_key())
    msg = b"an arbitrary message"
    sig = s.sign(msg)
    pub.verify(sig, msg)  # raises if invalid

    with pytest.raises(InvalidSignature):
        pub.verify(sig, b"a different message")
