"""The headless automation surface (aetherproof.auto).

This module exists because the wizard and CLI assume a human at a terminal, and
the places receipts actually need generating — a cloud coding model, a CI job, an
agent loop, a cron task — have no human to prompt. Nothing here may read stdin,
block, or take down the caller's real work.

The failure policy is the load-bearing property: by default a receipt failure is
swallowed and the call returns None, because an automated pipeline losing a
receipt is bad but crashing over one is worse. AETHERPROOF_STRICT=1 inverts that
for environments where a missing receipt IS the failure.
"""

import os

import pytest

from aetherproof import auto
from aetherproof.core.receipt import Receipt


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own AETHERPROOF_HOME and a clean module cache."""
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_DISABLE", raising=False)
    monkeypatch.delenv("AETHERPROOF_STRICT", raising=False)
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    auto.reset()
    yield
    auto.reset()


# ── zero-setup signing ───────────────────────────────────────────────────────

def test_sign_works_with_no_configuration():
    r = auto.sign(prompt="what is 2+2?", output="4")
    assert r is not None
    assert auto.verify(r) is True


def test_key_is_created_on_first_use():
    assert auto.status()["key_present"] is False
    auto.sign(output="hello")
    assert auto.status()["key_present"] is True


def test_model_id_selects_the_api_attested_tier():
    r = auto.sign(output="4", model_id="gpt-4o-2024-08-06", provider="openai",
                  system_fingerprint="fp_abc")
    assert r.model_root_type == "api_attested"


def test_no_model_id_falls_back_to_name_only():
    """No id means no provider attestation — the tier must say so."""
    r = auto.sign(output="4")
    assert r.model_root_type == "name_only"


def test_precomputed_hashes_avoid_retaining_plaintext():
    from aetherproof.core.hash import sha256
    r = auto.sign(output_hash=sha256("secret"), input_commitment=sha256("prompt"))
    assert r.output_hash == sha256("secret")
    assert auto.verify(r) is True


def test_receipts_are_unique_and_logged():
    ids = {auto.sign(output=f"o{i}").receipt_id for i in range(20)}
    assert len(ids) == 20
    st = auto.status()
    assert st["receipts"] == 20
    assert st["log_intact"] is True


def test_signed_receipts_name_their_key():
    r = auto.sign(output="x")
    assert r.signing_key_id == Receipt.key_id(auto.signer().get_public_key())


# ── disable / strict ─────────────────────────────────────────────────────────

def test_disable_makes_everything_a_noop(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_DISABLE", "1")
    auto.reset()
    assert auto.sign(output="x") is None
    assert auto.signer() is None
    assert auto.public_key_pem() is None
    assert auto.status()["disabled"] is True


def test_disabled_session_records_nothing(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_DISABLE", "1")
    auto.reset()
    with auto.AutoSession() as s:
        assert s.turn(prompt="p", output="o") is None
    assert len(s) == 0
    assert s.seal is None


def test_failure_is_swallowed_by_default(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", "Z:/definitely/not/a/real/path")
    auto.reset()
    assert auto.sign(output="x") is None       # must not raise


def test_strict_mode_raises_instead(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", "Z:/definitely/not/a/real/path")
    monkeypatch.setenv("AETHERPROOF_STRICT", "1")
    auto.reset()
    with pytest.raises(Exception):
        auto.sign(output="x")


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("maybe", False),
])
def test_env_flag_parsing(monkeypatch, value, expected):
    monkeypatch.setenv("AETHERPROOF_DISABLE", value)
    assert auto.is_disabled() is expected


# ── sessions ─────────────────────────────────────────────────────────────────

def test_session_seals_on_exit_and_writes_the_seal():
    with auto.AutoSession(model_id="claude-opus-5") as s:
        for i in range(32):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    assert len(s) == 32
    assert s.seal is not None
    assert s.seal_path.exists()
    assert auto.verify_turn(s.prove(7), s.seal) is True


def test_session_seals_even_when_the_block_raises():
    """A crashed run still wants a record of what it produced."""
    s = auto.AutoSession()
    try:
        with s:
            s.turn(prompt="q", output="a")
            raise RuntimeError("agent blew up")
    except RuntimeError:
        pass
    assert s.seal is not None
    assert len(s) == 1


def test_one_signature_covers_the_whole_session():
    with auto.AutoSession() as s:
        for i in range(500):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    # 500 turns, one seal, and it stays small
    assert len(s.seal.to_json()) < 600
    assert s.seal.turn_count == 500


def test_every_turn_of_a_session_is_provable():
    with auto.AutoSession() as s:
        for i in range(64):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    for i in (0, 1, 31, 63):
        assert auto.verify_turn(s.prove(i), s.seal) is True


def test_per_turn_receipts_are_off_by_default():
    """A 1000-turn agent loop wants one seal, not 1000 files."""
    with auto.AutoSession() as s:
        for i in range(10):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    assert auto.status()["receipts"] == 0


def test_per_turn_receipts_can_be_enabled():
    with auto.AutoSession(per_turn_receipts=True) as s:
        for i in range(5):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    st = auto.status()
    assert st["receipts"] == 5
    assert st["log_intact"] is True


def test_per_turn_receipts_are_bound_to_the_session():
    from aetherproof.core.keystore import SESSION_NS
    from aetherproof.core.log import ReceiptLog
    with auto.AutoSession(per_turn_receipts=True) as s:
        for i in range(3):
            s.turn(prompt=f"q{i}", output=f"a{i}")
    log = ReceiptLog(db_path=str(auto.home() / "log.db"))
    try:
        stored = Receipt.from_json(log.get_by_sequence(2)["receipt_json"])
    finally:
        log.close()
    assert stored.signed_extensions[SESSION_NS]["session_id"] == s.session_id
    assert stored.signed_extensions[SESSION_NS]["turn_index"] == "1"


def test_empty_session_seals_to_nothing():
    with auto.AutoSession() as s:
        pass
    assert s.seal is None


def test_functional_session_helper():
    with auto.session(model_id="gpt-4o") as s:
        s.turn(prompt="q", output="a")
    assert s.seal is not None


def test_sessions_have_distinct_ids():
    a, b = auto.AutoSession(), auto.AutoSession()
    assert a.session_id != b.session_id


# ── decorator ────────────────────────────────────────────────────────────────

def test_decorator_receipts_the_return_value():
    @auto.receipted(model_id="gpt-4o")
    def ask(prompt):
        return "the answer is 42"

    assert ask("meaning of life?") == "the answer is 42"
    assert auto.status()["receipts"] == 1


def test_decorator_passes_the_return_value_through_untouched():
    sentinel = {"complex": ["object"]}

    @auto.receipted(extract=lambda r: r["complex"][0])
    def f():
        return sentinel

    assert f() is sentinel


def test_decorator_failure_never_changes_the_caller_result(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", "Z:/nope")
    auto.reset()

    @auto.receipted()
    def f():
        return "result"

    assert f() == "result"


def test_decorator_preserves_metadata():
    @auto.receipted()
    def documented(x):
        """docstring survives"""
        return x

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "docstring survives"


# ── status ───────────────────────────────────────────────────────────────────

def test_status_is_machine_readable_before_any_use():
    st = auto.status()
    assert st["key_present"] is False
    assert st["receipts"] == 0
    assert isinstance(st["home"], str)


def test_status_reports_encryption_when_a_passphrase_is_set(monkeypatch):
    monkeypatch.setenv("AETHERPROOF_KEY_PASSPHRASE", "correct horse battery staple")
    auto.reset()
    auto.sign(output="x")
    assert auto.status()["key_encrypted"] is True


def test_key_is_unencrypted_without_a_passphrase():
    auto.sign(output="x")
    assert auto.status()["key_encrypted"] is False


def test_home_follows_the_env_var(monkeypatch, tmp_path):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("AETHERPROOF_HOME", str(other))
    auto.reset()
    auto.sign(output="x")
    assert (other / "signing_key.pem").exists()


def test_public_key_is_exportable_for_verifiers():
    auto.sign(output="x")
    pem = auto.public_key_pem()
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
