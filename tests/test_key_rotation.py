"""Key rotation and multi-signer log verification (D13).

Before the fix, verify_integrity(new_key) returned False on an authentic log the
moment the signing key had been rotated: rows signed by the retired key could
not be checked with the current one, and "cannot check" was reported as
"tampered". That is a false accusation of forgery for a routine operation.

The fix separates the two outcomes. Receipts carry signing_key_id (v1.3), so the
verifier selects the key each row names; a row naming a key we were not given is
UNVERIFIABLE, not broken. Pass strict_keys=True when every row must be checkable.
"""

import json
import sqlite3

import pytest

from aetherproof.core.keystore import issue_receipt
from aetherproof.core.log import ReceiptLog, IntegrityReport
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer


@pytest.fixture
def rotated(tmp_path):
    """3 receipts under an old key, then 3 under a new one."""
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    old, new = Signer.generate(), Signer.generate()
    for i in range(3):
        issue_receipt(old, log, model_weight_root="a" * 64,
                      output_hash="%064x" % i, receipts_dir=tmp_path / "r")
    for i in range(3, 6):
        issue_receipt(new, log, model_weight_root="a" * 64,
                      output_hash="%064x" % i, receipts_dir=tmp_path / "r")
    return log, old, new, tmp_path


def test_key_free_verification_survives_rotation(rotated):
    log, _, _, _ = rotated
    assert log.verify_integrity() is True


def test_current_key_alone_does_not_false_flag(rotated):
    """The regression: this returned False before the fix."""
    log, _, new, _ = rotated
    assert log.verify_integrity(new.get_public_key()) is True


def test_retired_key_alone_does_not_false_flag(rotated):
    log, old, _, _ = rotated
    assert log.verify_integrity(old.get_public_key()) is True


def test_full_keyring_verifies_every_row(rotated):
    log, old, new, _ = rotated
    report = log.verify_integrity_report([old.get_public_key(), new.get_public_key()])
    assert report.ok is True
    assert report.verified == 6
    assert report.unverifiable == []


def test_partial_keyring_reports_which_rows_it_could_not_check(rotated):
    log, _, new, _ = rotated
    report = log.verify_integrity_report(new.get_public_key())
    assert report.ok is True
    assert report.verified == 3
    assert [seq for seq, _ in report.unverifiable] == [1, 2, 3]


def test_strict_keys_requires_every_row_be_checkable(rotated):
    log, old, new, _ = rotated
    assert log.verify_integrity(new.get_public_key(), strict_keys=True) is False
    assert log.verify_integrity([old.get_public_key(), new.get_public_key()],
                                strict_keys=True) is True


def test_keyring_accepts_mapping_form(rotated):
    log, old, new, _ = rotated
    ring = {Receipt.key_id(k.get_public_key()): k.get_public_key() for k in (old, new)}
    assert log.verify_integrity_report(ring).verified == 6


def test_tampering_is_still_caught_with_a_full_keyring(rotated):
    """Rotation tolerance must not weaken tamper detection."""
    log, old, new, tmp = rotated
    conn = sqlite3.connect(tmp / "log.db")
    body = conn.execute(
        "SELECT receipt_json FROM receipts WHERE sequence=5").fetchone()[0]
    j = json.loads(body)
    j["output_hash"] = "f" * 64
    conn.execute("UPDATE receipts SET receipt_json=?, output_hash=? WHERE sequence=5",
                 (json.dumps(j), "f" * 64))
    conn.commit()
    conn.close()

    report = log.verify_integrity_report([old.get_public_key(), new.get_public_key()])
    assert report.ok is False
    assert report.broken_at == 5


def test_a_row_naming_a_held_key_that_rejects_is_forgery(tmp_path):
    """Named a key we hold, and that key says no -> broken, not unverifiable."""
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    signer = Signer.generate()
    issue_receipt(signer, log, model_weight_root="a" * 64,
                  output_hash="c" * 64, receipts_dir=tmp_path / "r")

    # forge the signature while keeping the chain and columns self-consistent
    conn = sqlite3.connect(tmp_path / "log.db")
    body = conn.execute(
        "SELECT receipt_json FROM receipts WHERE sequence=1").fetchone()[0]
    j = json.loads(body)
    j["signature"] = "00" * 64
    new_body = json.dumps(j)
    from aetherproof.core.log import _body_hash, _chain_entry_hash, GENESIS
    eh = _chain_entry_hash(1, j["receipt_id"], _body_hash(new_body), GENESIS)
    conn.execute(
        "UPDATE receipts SET receipt_json=?, signature=?, entry_hash=? WHERE sequence=1",
        (new_body, "00" * 64, eh))
    conn.commit()
    conn.close()

    report = log.verify_integrity_report(signer.get_public_key())
    assert report.ok is False
    assert "signature" in report.reason


def test_report_is_truthy_and_readable(rotated):
    log, old, new, _ = rotated
    report = log.verify_integrity_report([old.get_public_key(), new.get_public_key()])
    assert bool(report) is True
    assert isinstance(report, IntegrityReport)
    assert "6 rows" in repr(report)


def test_legacy_rows_without_key_id_are_tried_against_all_keys(tmp_path):
    """<=v1.2 receipts name no key; they must still verify against a keyring."""
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    a, b = Signer.generate(), Signer.generate()
    r = Receipt(receipt_version="1.1", model_weight_root="a" * 64,
                model_root_type="artifact_hash", input_commitment="b" * 64,
                output_hash="c" * 64, log_sequence=1, log_anchor="local://log/1")
    r.signature = b.sign(r.signing_bytes())
    log.append(r)

    assert r.signing_key_id == ""
    report = log.verify_integrity_report([a.get_public_key(), b.get_public_key()])
    assert report.ok is True
    assert report.verified == 1
