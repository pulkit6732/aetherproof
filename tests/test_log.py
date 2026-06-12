"""Tests for the append-only transparency log."""

import pytest
import tempfile
from pathlib import Path
from aetherproof.core.receipt import Receipt
from aetherproof.core.log import ReceiptLog


@pytest.fixture
def temp_log():
    """Create a temporary log for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        log = ReceiptLog(str(db_path))
        yield log


def test_log_creation(temp_log):
    """Test that log is created."""
    assert temp_log.db_path.exists()


def test_append_receipt(temp_log):
    """Test appending a receipt to the log."""
    receipt = Receipt(
        model_weight_root="abc123",
        output_hash="def456",
    )

    sequence = temp_log.append(receipt)
    assert sequence == 1
    assert temp_log.count() == 1


def test_append_multiple_receipts(temp_log):
    """Test appending multiple receipts."""
    for i in range(5):
        receipt = Receipt(
            receipt_id=f"receipt_{i}",
            model_weight_root=f"model_{i}",
            output_hash=f"output_{i}",
        )
        sequence = temp_log.append(receipt)
        assert sequence == i + 1

    assert temp_log.count() == 5


def test_duplicate_receipt_rejected(temp_log):
    """Test that duplicate receipt_id is rejected (append-only)."""
    receipt = Receipt(receipt_id="unique_id_123")
    temp_log.append(receipt)

    # Try to append again
    with pytest.raises(ValueError, match="already in log"):
        temp_log.append(receipt)


def test_get_receipt(temp_log):
    """Test retrieving a receipt by ID."""
    receipt = Receipt(
        receipt_id="test_receipt_1",
        model_weight_root="abc",
        output_hash="def",
    )
    temp_log.append(receipt)

    retrieved = temp_log.get("test_receipt_1")
    assert retrieved is not None
    assert retrieved["model_weight_root"] == "abc"


def test_get_by_sequence(temp_log):
    """Test retrieving a receipt by sequence number."""
    receipt = Receipt(
        receipt_id="get_by_seq",
        model_weight_root="abc",
        output_hash="def"
    )
    sequence = temp_log.append(receipt)

    retrieved = temp_log.get_by_sequence(sequence)
    assert retrieved is not None
    assert retrieved["model_weight_root"] == "abc"


def test_max_sequence(temp_log):
    """Test getting the maximum sequence number."""
    assert temp_log.max_sequence() == 0

    for i in range(3):
        receipt = Receipt(
            receipt_id=f"max_seq_{i}",
            model_weight_root=f"model_{i}"
        )
        temp_log.append(receipt)

    assert temp_log.max_sequence() == 3


def test_log_integrity_check(temp_log):
    """Test that log integrity verification works."""
    # Empty log should be valid
    assert temp_log.verify_integrity() is True

    # Add receipts in order
    for i in range(5):
        receipt = Receipt(
            receipt_id=f"integrity_{i}",
            model_weight_root=f"model_{i}"
        )
        temp_log.append(receipt)

    # Should still be valid (no gaps)
    assert temp_log.verify_integrity() is True


def test_list_all_receipts(temp_log):
    """Test listing all receipts."""
    for i in range(3):
        receipt = Receipt(
            receipt_id=f"list_{i}",
            model_weight_root=f"model_{i}"
        )
        temp_log.append(receipt)

    receipts = temp_log.list_all()
    assert len(receipts) == 3
    # Most recent first
    assert receipts[0]["model_weight_root"] == "model_2"


def test_log_repr(temp_log):
    """Test log string representation."""
    receipt = Receipt(
        receipt_id="repr_test",
        model_weight_root="abc"
    )
    temp_log.append(receipt)

    repr_str = str(temp_log)
    assert "ReceiptLog" in repr_str
    assert "count=1" in repr_str


def test_chain_detects_content_edit(temp_log):
    """Editing any field of a logged receipt breaks the body hash chain (key-free)."""
    import sqlite3, json
    for i in range(3):
        temp_log.append(Receipt(receipt_id=f"edit_{i}", model_weight_root="m", output_hash=str(i)))
    assert temp_log.verify_integrity() is True
    # edit the authoritative receipt_json of row 1
    con = sqlite3.connect(temp_log.db_path)
    rj = con.execute("SELECT receipt_json FROM receipts WHERE sequence = 1").fetchone()[0]
    d = json.loads(rj); d["output_hash"] = "tampered"
    con.execute("UPDATE receipts SET receipt_json = ? WHERE sequence = 1", (json.dumps(d),))
    con.commit(); con.close()
    assert temp_log.verify_integrity() is False


def test_chain_detects_naive_delete_then_renumber(temp_log):
    """Delete a middle row and renumber survivors: caught key-free by the chain."""
    import sqlite3
    for i in range(3):
        temp_log.append(Receipt(receipt_id=f"ren_{i}", model_weight_root="m", output_hash=str(i)))
    con = sqlite3.connect(temp_log.db_path)
    con.execute("DELETE FROM receipts WHERE sequence = 2")
    con.execute("UPDATE receipts SET sequence = 2 WHERE sequence = 3")
    con.commit(); con.close()
    assert temp_log.verify_integrity() is False


def _sophisticated_renumber(db_path):
    """Delete seq 2, move seq 3 -> 2, and recompute a self-consistent chain.

    The receipts' embedded log_sequence is left untouched, so the chain is
    internally consistent but each receipt's signed slot no longer matches.
    """
    import sqlite3
    from aetherproof.core.log import GENESIS, _chain_entry_hash, _body_hash
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("DELETE FROM receipts WHERE sequence = 2")
    con.execute("UPDATE receipts SET sequence = 2 WHERE sequence = 3")
    con.commit()
    prev = GENESIS
    for r in con.execute("SELECT * FROM receipts ORDER BY sequence ASC").fetchall():
        eh = _chain_entry_hash(r["sequence"], r["receipt_id"], _body_hash(r["receipt_json"]), prev)
        con.execute("UPDATE receipts SET prev_hash = ?, entry_hash = ? WHERE sequence = ?",
                    (prev, eh, r["sequence"]))
        prev = eh
    con.commit(); con.close()


def test_sophisticated_renumber_caught_key_free(temp_log):
    """A recomputed-chain renumber is caught KEY-FREE via the sequence binding.

    The attacker did not rewrite each receipt's embedded log_sequence, so a row's
    signed log_sequence no longer equals its slot — detected without any key, and
    therefore robust to key rotation.
    """
    import tempfile
    from pathlib import Path
    from aetherproof.core.signer import Signer
    from aetherproof.core.keystore import issue_receipt

    signer = Signer.generate()
    rdir = Path(tempfile.mkdtemp())
    for i in range(3):
        issue_receipt(signer, temp_log, model_weight_root="m" * 64,
                      output_hash=str(i) * 64, receipts_dir=rdir)
    assert temp_log.verify_integrity() is True
    _sophisticated_renumber(temp_log.db_path)
    assert temp_log.verify_integrity() is False  # caught with NO key


def test_most_thorough_forgery_needs_signature(temp_log):
    """If the attacker also rewrites each receipt's embedded log_sequence, only the
    key-bound signature check catches it — the chain and sequence binding pass."""
    import tempfile, sqlite3, json
    from pathlib import Path
    from aetherproof.core.signer import Signer
    from aetherproof.core.keystore import issue_receipt
    from aetherproof.core.log import GENESIS, _chain_entry_hash, _body_hash

    signer = Signer.generate()
    pub = signer.get_public_key()
    rdir = Path(tempfile.mkdtemp())
    for i in range(3):
        issue_receipt(signer, temp_log, model_weight_root="m" * 64,
                      output_hash=str(i) * 64, receipts_dir=rdir)

    con = sqlite3.connect(temp_log.db_path)
    con.row_factory = sqlite3.Row
    con.execute("DELETE FROM receipts WHERE sequence = 2")
    con.execute("UPDATE receipts SET sequence = 2 WHERE sequence = 3")
    con.commit()
    prev = GENESIS
    for r in con.execute("SELECT * FROM receipts ORDER BY sequence ASC").fetchall():
        d = json.loads(r["receipt_json"]); d["log_sequence"] = r["sequence"]  # rewrite embedded slot
        rj = json.dumps(d)
        eh = _chain_entry_hash(r["sequence"], r["receipt_id"], _body_hash(rj), prev)
        con.execute("UPDATE receipts SET receipt_json = ?, prev_hash = ?, entry_hash = ? WHERE sequence = ?",
                    (rj, prev, eh, r["sequence"]))
        prev = eh
    con.commit(); con.close()

    assert temp_log.verify_integrity() is True       # chain + sequence binding both pass
    assert temp_log.verify_integrity(pub) is False    # signature re-verification catches it


def test_chain_detects_denormalized_column_edit(temp_log):
    """Editing a denormalized query column (not receipt_json) is caught: the
    column must stay consistent with the authoritative receipt body."""
    import sqlite3
    from aetherproof.core.signer import Signer
    from aetherproof.core.keystore import issue_receipt
    import tempfile
    from pathlib import Path

    signer = Signer.generate()
    rdir = Path(tempfile.mkdtemp())
    for i in range(3):
        issue_receipt(signer, temp_log, model_weight_root="m" * 64,
                      output_hash=str(i) * 64, receipts_dir=rdir)
    assert temp_log.verify_integrity() is True
    con = sqlite3.connect(temp_log.db_path)
    con.execute("UPDATE receipts SET output_hash = 'x' WHERE sequence = 2")  # column only
    con.commit(); con.close()
    assert temp_log.verify_integrity() is False


def test_migration_idempotent_runs_once(temp_log):
    """verify_integrity holds after re-opening; user_version gates the migration."""
    import sqlite3
    for i in range(3):
        temp_log.append(Receipt(receipt_id=f"mig_{i}", model_weight_root="m", output_hash=str(i)))
    # user_version stamped to current schema
    con = sqlite3.connect(temp_log.db_path)
    assert con.execute("PRAGMA user_version").fetchone()[0] == 2
    con.close()
    # re-open: must not corrupt the chain (idempotent)
    reopened = ReceiptLog(str(temp_log.db_path))
    assert reopened.verify_integrity() is True
    assert reopened.count() == 3
