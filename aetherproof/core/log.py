"""Append-only SQLite transparency log for receipts."""

import sqlite3
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Any

GENESIS = "0" * 64  # prev_hash of the first entry
SCHEMA_VERSION = 2  # 1 = pre-chain, 2 = hash-chained over the full receipt body


def _body_hash(receipt_json: str) -> str:
    # hash of the entire stored receipt — chains the whole record, not a subset
    return hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()


def _chain_entry_hash(sequence, receipt_id, body_hash, prev_hash):
    # links each row to the one before it; any edit/reorder/delete breaks the chain
    preimage = f"{sequence}|{receipt_id}|{body_hash}|{prev_hash}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


class ReceiptLog:
    """Local append-only transparency log using SQLite.

    Single-writer (R0): one process appends at a time. The hash chain over the
    full receipt body makes deletion, reordering, and content edits tamper-evident
    without any key; verify_integrity(public_key) adds signature re-verification
    as a deeper, key-bound layer.
    """

    def __init__(self, db_path: str = "./receipts/log.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                model_weight_root TEXT NOT NULL,
                input_commitment TEXT NOT NULL,
                output_hash TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                signature TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL DEFAULT '',
                entry_hash TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CHECK (sequence > 0)
            )
        """)
        conn.commit()

        # one-time migration, guarded by user_version (no per-open full-table scan)
        version = cursor.execute("PRAGMA user_version").fetchone()[0]
        if version < SCHEMA_VERSION:
            self._migrate(conn)
            cursor.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            conn.commit()
        conn.close()

    def _migrate(self, conn) -> None:
        # add chain columns if missing, then (re)compute the chain over all rows.
        # NOTE: recomputing means the chain attests integrity FROM MIGRATION FORWARD;
        # it cannot retroactively prove pre-migration rows were untouched.
        cur = conn.cursor()
        existing = {r[1] for r in cur.execute("PRAGMA table_info(receipts)").fetchall()}
        if "prev_hash" not in existing:
            cur.execute("ALTER TABLE receipts ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
        if "entry_hash" not in existing:
            cur.execute("ALTER TABLE receipts ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")
        conn.commit()

        rows = cur.execute(
            "SELECT sequence, receipt_id, receipt_json FROM receipts ORDER BY sequence ASC"
        ).fetchall()
        prev = GENESIS
        for seq, rid, rj in rows:
            eh = _chain_entry_hash(seq, rid, _body_hash(rj), prev)
            cur.execute(
                "UPDATE receipts SET prev_hash = ?, entry_hash = ? WHERE sequence = ?",
                (prev, eh, seq),
            )
            prev = eh
        conn.commit()

    def append(self, receipt: "Receipt") -> int:
        """Append a receipt to the log.

        When receipt.log_sequence > 0 the sequence is inserted explicitly; the
        PRIMARY KEY makes a concurrent duplicate sequence raise IntegrityError
        (nothing is inserted), closing the read-then-write race. log_sequence == 0
        falls back to AUTOINCREMENT.

        Raises ValueError if the receipt_id or sequence is already taken.
        """
        receipt_json = receipt.to_json()
        body = _body_hash(receipt_json)
        explicit = receipt.log_sequence and receipt.log_sequence > 0

        cols = ["receipt_id", "model_weight_root", "input_commitment", "output_hash",
                "timestamp_ms", "signature", "receipt_json", "prev_hash", "entry_hash"]

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            head = cursor.execute(
                "SELECT entry_hash FROM receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            prev_hash = head[0] if head and head[0] else GENESIS

            vals = [receipt.receipt_id, receipt.model_weight_root, receipt.input_commitment,
                    receipt.output_hash, receipt.timestamp_ms, receipt.signature,
                    receipt_json, prev_hash, ""]  # entry_hash filled once seq is known
            insert_cols = list(cols)
            if explicit:
                insert_cols.insert(0, "sequence")
                vals.insert(0, receipt.log_sequence)

            placeholders = ", ".join("?" * len(vals))
            cursor.execute(
                f"INSERT INTO receipts ({', '.join(insert_cols)}) VALUES ({placeholders})", vals
            )

            if explicit:
                sequence = receipt.log_sequence
            else:
                sequence = cursor.execute(
                    "SELECT sequence FROM receipts WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0]

            entry_hash = _chain_entry_hash(sequence, receipt.receipt_id, body, prev_hash)
            cursor.execute(
                "UPDATE receipts SET entry_hash = ? WHERE sequence = ?", (entry_hash, sequence)
            )
            conn.commit()
            return sequence
        except sqlite3.IntegrityError as e:
            raise ValueError(
                f"Receipt already in log or sequence taken: {receipt.receipt_id}"
            ) from e
        finally:
            conn.close()

    def get(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_by_sequence(self, sequence: int) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM receipts WHERE sequence = ?", (sequence,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def list_all(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM receipts ORDER BY sequence DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def verify_integrity(self, public_key=None) -> bool:
        """Verify the log is intact.

        Key-free (always): sequences are contiguous 1..N; the hash chain over each
        receipt body is consistent; and each receipt's own signed log_sequence
        equals its slot. Together these make deletion, reordering, content edits,
        and delete-then-renumber tamper-evident WITHOUT any key — so key rotation
        never false-flags an authentic log.

        With public_key (deeper, key-bound): additionally re-verifies each receipt's
        Ed25519 signature. This catches a maximally thorough forger who rewrites a
        receipt's embedded log_sequence and recomputes the whole chain — they still
        cannot reproduce the signature. Note: this layer assumes the signing key has
        not rotated; on rotation, re-anchor rather than verifying old rows with a new
        key. The single-machine trust assumption itself is removed only by an
        independent witness log (Signet).
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM receipts ORDER BY sequence ASC").fetchall()
        conn.close()

        if not rows:
            return True

        from .receipt import Receipt
        prev = GENESIS
        for i, row in enumerate(rows, start=1):
            if row["sequence"] != i:
                return False  # gap / non-contiguous

            expected = _chain_entry_hash(
                row["sequence"], row["receipt_id"], _body_hash(row["receipt_json"]), prev
            )
            if row["entry_hash"] != expected or row["prev_hash"] != prev:
                return False  # chain broken (edit / reorder / delete)
            prev = row["entry_hash"]

            rcpt = Receipt.from_json(row["receipt_json"])

            # the denormalized query columns must match the authoritative body,
            # so a column edit cannot silently desync from receipt_json
            if (row["receipt_id"] != rcpt.receipt_id
                    or row["output_hash"] != rcpt.output_hash
                    or row["model_weight_root"] != rcpt.model_weight_root
                    or row["input_commitment"] != rcpt.input_commitment
                    or row["timestamp_ms"] != rcpt.timestamp_ms
                    or row["signature"] != rcpt.signature):
                return False  # column desynced from receipt_json

            # a receipt that committed to a sequence (>0) must sit in that slot;
            # unsequenced legacy rows (log_sequence == 0) fall back to chain-only
            if rcpt.log_sequence and rcpt.log_sequence != row["sequence"]:
                return False  # renumbered: signed slot != position

            if public_key is not None:
                if not public_key.verify(rcpt.signing_bytes(), rcpt.signature):
                    return False  # body does not match its signature

        return True

    def max_sequence(self) -> int:
        conn = sqlite3.connect(self.db_path)
        result = conn.execute("SELECT MAX(sequence) FROM receipts").fetchone()
        conn.close()
        return result[0] if result[0] else 0

    def count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        result = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        conn.close()
        return result[0] if result else 0

    def __repr__(self) -> str:
        return f"ReceiptLog(path={self.db_path}, count={self.count()}, max_sequence={self.max_sequence()})"
