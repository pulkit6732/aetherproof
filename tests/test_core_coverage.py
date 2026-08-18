"""Coverage for the core paths the existing suite never exercised.

Coverage analysis put verifier.py - the module that implements the project's
one stated invariant - at 57%, the lowest of any core module. The file-based
verification path (`verify_receipt_file`), the log-anchor check, the empty-field
guards, and `tamper_detect` had no tests at all. signer.py (74%), keystore.py
(73%) and hash.py (93%) had similar holes around PEM loading, password handling,
and path resolution.

These are not exotic paths. `verify_receipt_file` is what the CLI's `verify`
command calls, and it is the exact function an external auditor would use.
"""

import json
import os
import stat
import sqlite3
from pathlib import Path

import pytest

from aetherproof.core import hash as h
from aetherproof.core.hash import (
    sha256, sha256_file, hash_input, hash_output, merkle_hash, merkle_leaf,
    merkle_node, compute_merkle_root, compute_model_weight_root,
)
from aetherproof.core.keystore import (
    home, log_path, receipts_path, default_log, load_or_create_signer,
    issue_receipt, PASSPHRASE_ENV, HOME_ENV,
)
from aetherproof.core.log import ReceiptLog
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer, Verifier
from aetherproof.core.verifier import (
    verify_receipt, verify_receipt_file, verify_output_unmodified,
    verify_model_identity, tamper_detect,
)


@pytest.fixture
def signer():
    return Signer.generate()


@pytest.fixture
def pub(signer):
    return signer.get_public_key()


def make(signer, **kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="c" * 64,
                log_sequence=1, log_anchor="local://log/1")
    base.update(kw)
    r = Receipt(**base)
    r.signature = signer.sign(r.signing_bytes())
    return r


# ══ verifier.py - the invariant ═════════════════════════════════════════════

@pytest.mark.parametrize("field", ["receipt_id", "model_weight_root",
                                   "output_hash", "signature"])
def test_a_receipt_missing_a_required_field_is_rejected(signer, pub, field):
    """Fail closed on an incomplete receipt rather than reaching the crypto."""
    r = make(signer)
    setattr(r, field, "")
    assert verify_receipt(r, pub) is False


def test_a_complete_receipt_verifies(signer, pub):
    assert verify_receipt(make(signer), pub) is True


# ── verify_receipt_file: what the CLI and an external auditor actually call ──

def test_verify_receipt_file_round_trip(tmp_path, signer, pub):
    r = make(signer)
    rp = tmp_path / "r.json"
    kp = tmp_path / "r.pub"
    rp.write_text(r.to_json(), encoding="utf-8")
    kp.write_bytes(pub.export_public_pem())
    assert verify_receipt_file(str(rp), str(kp)) is True


def test_verify_receipt_file_detects_an_edited_file(tmp_path, signer, pub):
    r = make(signer)
    rp = tmp_path / "r.json"
    kp = tmp_path / "r.pub"
    d = json.loads(r.to_json())
    d["output_hash"] = "f" * 64
    rp.write_text(json.dumps(d), encoding="utf-8")
    kp.write_bytes(pub.export_public_pem())
    assert verify_receipt_file(str(rp), str(kp)) is False


def test_verify_receipt_file_rejects_the_wrong_key(tmp_path, signer):
    r = make(signer)
    rp = tmp_path / "r.json"
    kp = tmp_path / "other.pub"
    rp.write_text(r.to_json(), encoding="utf-8")
    kp.write_bytes(Signer.generate().get_public_key().export_public_pem())
    assert verify_receipt_file(str(rp), str(kp)) is False


def test_verify_receipt_file_with_a_matching_log_entry(tmp_path, signer, pub):
    r = make(signer, log_sequence=7, log_anchor="local://log/7")
    rp = tmp_path / "r.json"
    kp = tmp_path / "r.pub"
    lp = tmp_path / "log.json"
    rp.write_text(r.to_json(), encoding="utf-8")
    kp.write_bytes(pub.export_public_pem())
    lp.write_text(json.dumps([{"sequence": 7, "receipt_id": r.receipt_id}]),
                  encoding="utf-8")
    assert verify_receipt_file(str(rp), str(kp), str(lp)) is True


def test_verify_receipt_file_rejects_a_mismatched_log_position(tmp_path, signer, pub):
    """The receipt claims slot 7; the log puts that sequence elsewhere."""
    r = make(signer, log_sequence=7, log_anchor="local://log/7")
    rp = tmp_path / "r.json"
    kp = tmp_path / "r.pub"
    lp = tmp_path / "log.json"
    rp.write_text(r.to_json(), encoding="utf-8")
    kp.write_bytes(pub.export_public_pem())
    # a log whose entry 7 exists but the receipt was signed for a different slot
    tampered = make(signer, log_sequence=7, log_anchor="local://log/7")
    tampered.log_sequence = 9          # rewritten after signing
    rp.write_text(tampered.to_json(), encoding="utf-8")
    lp.write_text(json.dumps([{"sequence": 9}]), encoding="utf-8")
    assert verify_receipt_file(str(rp), str(kp), str(lp)) is False


def test_verify_receipt_file_when_the_log_has_no_such_sequence(tmp_path, signer, pub):
    """No matching entry means no anchor check - signature alone still decides."""
    r = make(signer, log_sequence=7, log_anchor="local://log/7")
    rp = tmp_path / "r.json"
    kp = tmp_path / "r.pub"
    lp = tmp_path / "log.json"
    rp.write_text(r.to_json(), encoding="utf-8")
    kp.write_bytes(pub.export_public_pem())
    lp.write_text(json.dumps([{"sequence": 999}]), encoding="utf-8")
    assert verify_receipt_file(str(rp), str(kp), str(lp)) is True


def test_verify_receipt_file_missing_receipt_raises(tmp_path, signer, pub):
    kp = tmp_path / "r.pub"
    kp.write_bytes(pub.export_public_pem())
    with pytest.raises(FileNotFoundError):
        verify_receipt_file(str(tmp_path / "nope.json"), str(kp))


# ── the log-anchor check ─────────────────────────────────────────────────────

def test_log_anchor_matching_sequence_passes(signer, pub):
    r = make(signer, log_sequence=3, log_anchor="local://log/3")
    assert verify_receipt(r, pub, {"sequence": 3}) is True


def test_log_anchor_mismatched_sequence_fails(signer, pub):
    r = make(signer, log_sequence=3, log_anchor="local://log/3")
    assert verify_receipt(r, pub, {"sequence": 4}) is False


def test_log_anchor_zero_sequence_fails(signer, pub):
    """Sequence 0 is not a real slot - it must not satisfy the anchor."""
    r = make(signer, log_sequence=0, log_anchor="local://log/0")
    assert verify_receipt(r, pub, {"sequence": 0}) is False


def test_no_anchor_string_skips_the_check(signer, pub):
    r = make(signer, log_sequence=3, log_anchor="")
    assert verify_receipt(r, pub, {"sequence": 999}) is True


# ── the helper comparisons ───────────────────────────────────────────────────

def test_verify_output_unmodified(signer):
    r = make(signer, output_hash=sha256("hello"))
    assert verify_output_unmodified(r, sha256("hello")) is True
    assert verify_output_unmodified(r, sha256("hello!")) is False


def test_verify_model_identity(signer):
    r = make(signer, model_weight_root="d" * 64)
    assert verify_model_identity(r, "d" * 64) is True
    assert verify_model_identity(r, "e" * 64) is False


# ── tamper_detect ────────────────────────────────────────────────────────────

def test_tamper_detect_reports_working_crypto(signer, pub):
    assert tamper_detect(make(signer), pub) is True


def test_tamper_detect_on_an_empty_root_returns_false(signer, pub):
    """Nothing to flip - the probe cannot make a claim."""
    r = make(signer)
    r.model_weight_root = ""
    assert tamper_detect(r, pub) is False


def test_tamper_detect_flips_an_f_root_the_other_way(signer, pub):
    """The probe flips to 'F' unless the digit already is - cover that branch."""
    r = make(signer, model_weight_root="F" * 64)
    assert tamper_detect(r, pub) is True


def test_tamper_detect_fails_with_the_wrong_key(signer):
    """The original must verify for the probe to mean anything."""
    assert tamper_detect(make(signer), Signer.generate().get_public_key()) is False


# ══ signer.py ═══════════════════════════════════════════════════════════════

def test_private_pem_round_trip(signer):
    reloaded = Signer.from_private_pem(signer.export_private_pem())
    assert (reloaded.get_public_key().export_public_pem()
            == signer.get_public_key().export_public_pem())


def test_private_pem_round_trip_with_a_password(signer):
    pw = b"correct horse battery staple"
    pem = signer.export_private_pem(password=pw)
    assert b"ENCRYPTED" in pem
    reloaded = Signer.from_private_pem(pem, password=pw)
    assert (reloaded.get_public_key().export_public_pem()
            == signer.get_public_key().export_public_pem())


def test_encrypted_key_needs_the_right_password(signer):
    pem = signer.export_private_pem(password=b"right")
    with pytest.raises(Exception):
        Signer.from_private_pem(pem, password=b"wrong")


def test_private_file_round_trip(tmp_path, signer):
    p = tmp_path / "k.pem"
    signer.export_private_file(str(p))
    reloaded = Signer.from_private_file(str(p))
    assert reloaded.sign(b"x") == signer.sign(b"x")   # Ed25519 is deterministic


def test_private_file_round_trip_with_a_password(tmp_path, signer):
    p = tmp_path / "k.pem"
    signer.export_private_file(str(p), password=b"pw")
    assert b"ENCRYPTED" in p.read_bytes()
    assert Signer.from_private_file(str(p), password=b"pw") is not None


def test_public_file_round_trip(tmp_path, signer, pub):
    p = tmp_path / "k.pub"
    signer.export_public_file(str(p))
    loaded = Verifier.from_public_file(str(p))
    msg = b"message"
    assert loaded.verify(msg, signer.sign(msg)) is True


def test_verifier_export_public_file(tmp_path, pub):
    p = tmp_path / "v.pub"
    pub.export_public_file(str(p))
    assert p.read_bytes() == pub.export_public_pem()


def test_sign_message_and_verify_message(signer, pub):
    sig = signer.sign_message("héllo wörld")
    assert pub.verify_message("héllo wörld", sig) is True
    assert pub.verify_message("héllo world", sig) is False


def test_verify_rejects_malformed_signature_hex(signer, pub):
    assert pub.verify(b"x", "not-hex") is False
    assert pub.verify(b"x", "") is False
    assert pub.verify(b"x", "ab") is False        # right charset, wrong length


def test_reprs_do_not_leak_the_private_key(signer, pub):
    s = repr(signer)
    assert s.startswith("Signer(public_key=")
    assert "PRIVATE" not in s
    assert repr(pub).startswith("Verifier(public_key=")


def test_ed25519_signing_is_deterministic(signer):
    assert signer.sign(b"same") == signer.sign(b"same")


def test_two_generated_signers_differ():
    a, b = Signer.generate(), Signer.generate()
    assert a.export_private_pem() != b.export_private_pem()


# ══ keystore.py - path resolution ═══════════════════════════════════════════

def test_home_defaults_under_the_user_home(monkeypatch):
    monkeypatch.delenv(HOME_ENV, raising=False)
    assert home() == Path.home() / ".aetherproof"


def test_home_follows_the_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    assert home() == tmp_path


def test_home_is_read_at_call_time_not_import_time(monkeypatch, tmp_path):
    """The bug: a constant frozen at import ignored later env changes."""
    monkeypatch.setenv(HOME_ENV, str(tmp_path / "one"))
    first = home()
    monkeypatch.setenv(HOME_ENV, str(tmp_path / "two"))
    assert home() != first


def test_log_and_receipt_paths_are_absolute_and_under_home(monkeypatch, tmp_path):
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    assert log_path().is_absolute()
    assert log_path() == tmp_path / "log.db"
    assert receipts_path() == tmp_path / "receipts"


def test_default_log_opens_under_home(monkeypatch, tmp_path):
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    log = default_log()
    try:
        assert Path(log.db_path) == tmp_path / "log.db"
    finally:
        log.close()


def test_key_dir_alias_still_works(monkeypatch, tmp_path):
    """KEY_DIR stayed importable for existing callers but now tracks the env."""
    import aetherproof.core.keystore as ks
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    assert ks.KEY_DIR == tmp_path


def test_unknown_keystore_attribute_still_raises():
    import aetherproof.core.keystore as ks
    with pytest.raises(AttributeError):
        ks.NoSuchThing


# ── keystore.py - key creation ───────────────────────────────────────────────

def test_second_call_reuses_the_same_key(tmp_path):
    a = load_or_create_signer(key_dir=tmp_path)
    b = load_or_create_signer(key_dir=tmp_path)
    assert (a.get_public_key().export_public_pem()
            == b.get_public_key().export_public_pem())


def test_passphrase_encrypts_the_key_at_rest(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a long passphrase")
    load_or_create_signer(key_dir=tmp_path)
    assert b"ENCRYPTED" in (tmp_path / "signing_key.pem").read_bytes()


def test_an_encrypted_key_reloads_with_the_same_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a long passphrase")
    a = load_or_create_signer(key_dir=tmp_path)
    b = load_or_create_signer(key_dir=tmp_path)
    assert (a.get_public_key().export_public_pem()
            == b.get_public_key().export_public_pem())


def test_an_encrypted_key_will_not_load_without_the_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSPHRASE_ENV, "a long passphrase")
    load_or_create_signer(key_dir=tmp_path)
    monkeypatch.delenv(PASSPHRASE_ENV)
    with pytest.raises(Exception):
        load_or_create_signer(key_dir=tmp_path)


def test_public_key_is_written_beside_the_private_one(tmp_path):
    load_or_create_signer(key_dir=tmp_path)
    assert (tmp_path / "signing_key.pub").exists()
    assert (tmp_path / "signing_key.pem").exists()


# ── keystore.py - issue_receipt failure handling ─────────────────────────────

def test_issue_receipt_writes_both_receipt_and_pubkey(tmp_path):
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    try:
        s = Signer.generate()
        r, path = issue_receipt(s, log, model_weight_root="a" * 64,
                                output_hash="c" * 64,
                                receipts_dir=tmp_path / "r")
        assert path.exists()
        assert path.with_suffix(".pub").exists()
        assert verify_receipt(r, s.get_public_key()) is True
    finally:
        log.close()


def test_issue_receipt_leaves_no_orphan_files_when_the_log_rejects(tmp_path):
    """The commit point is log.append; a failure there must roll the files back."""
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    rdir = tmp_path / "r"
    try:
        s = Signer.generate()

        calls = {"n": 0}
        real_append = log.append

        def always_reject(receipt):
            calls["n"] += 1
            raise ValueError("sequence taken")

        log.append = always_reject
        with pytest.raises(RuntimeError, match="could not reserve"):
            issue_receipt(s, log, model_weight_root="a" * 64,
                          output_hash="c" * 64, receipts_dir=rdir)
        assert calls["n"] == 16                      # bounded retry
        assert list(rdir.glob("*.json")) == []       # nothing left behind
        assert list(rdir.glob("*.pub")) == []
        log.append = real_append
    finally:
        log.close()


def test_issue_receipt_defaults_receipts_dir_to_home(tmp_path, monkeypatch):
    monkeypatch.setenv(HOME_ENV, str(tmp_path))
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    try:
        _, path = issue_receipt(Signer.generate(), log,
                                model_weight_root="a" * 64, output_hash="c" * 64)
        assert path.parent == tmp_path / "receipts"
    finally:
        log.close()


# ══ hash.py ═════════════════════════════════════════════════════════════════

def test_hash_input_and_hash_output_are_sha256(tmp_path):
    assert hash_input("abc") == sha256("abc")
    assert hash_output("abc") == sha256("abc")


def test_merkle_hash_is_an_alias_for_merkle_node():
    a, b = sha256("a"), sha256("b")
    assert merkle_hash(a, b) == merkle_node(a, b)


def test_sha256_file_matches_sha256_of_the_bytes(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"some bytes")
    assert sha256_file(p) == sha256("some bytes")


def test_sha256_file_streams_a_large_file(tmp_path):
    p = tmp_path / "big.bin"
    blob = os.urandom(3 * 1024 * 1024)
    p.write_bytes(blob)
    import hashlib
    assert sha256_file(p) == hashlib.sha256(blob).hexdigest()


def test_model_root_on_a_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        compute_model_weight_root(tmp_path / "nothing-here")


def test_model_root_of_an_empty_directory_is_empty(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    assert compute_model_weight_root(d) == ""


def test_model_root_recurses_into_subdirectories(tmp_path):
    d = tmp_path / "m"
    (d / "nested").mkdir(parents=True)
    (d / "a.bin").write_bytes(b"A")
    (d / "nested" / "b.bin").write_bytes(b"B")
    root = compute_model_weight_root(d)
    assert len(root) == 64

    # moving a file between directories must change the root
    (d / "nested" / "b.bin").rename(d / "b.bin")
    assert compute_model_weight_root(d) != root


def test_model_root_is_path_separator_independent(tmp_path):
    """Roots computed on Windows and POSIX must agree (as_posix normalisation)."""
    d = tmp_path / "m"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "w.bin").write_bytes(b"W")
    root = compute_model_weight_root(d)
    expected_leaf = sha256("sub/w.bin\x00" + sha256("W"))
    assert root == compute_merkle_root([expected_leaf])


def test_merkle_leaf_and_node_are_distinct_domains():
    a = sha256("a")
    assert merkle_leaf(a) != a
    assert merkle_leaf(a) != merkle_node(a, a)
