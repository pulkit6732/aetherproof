"""Append-only SQLite transparency log for receipts."""

import sqlite3
import hashlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

GENESIS = "0" * 64  # prev_hash of the first entry
SCHEMA_VERSION = 2  # 1 = pre-chain, 2 = hash-chained over the full receipt body


def _body_hash(receipt_json: str) -> str:
    # hash of the entire stored receipt - chains the whole record, not a subset
    return hashlib.sha256(receipt_json.encode("utf-8")).hexdigest()


def _chain_entry_hash(sequence, receipt_id, body_hash, prev_hash):
    # links each row to the one before it; any edit/reorder/delete breaks the chain
    preimage = f"{sequence}|{receipt_id}|{body_hash}|{prev_hash}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


@dataclass
class IntegrityReport:
    """Outcome of a log verification.

    Separates "this row is forged" from "I cannot check this row", which the
    single bool could not express. Conflating them made an authentic log look
    tampered after a routine key rotation.
    """

    total: int = 0
    verified: int = 0                                   # signature re-checked OK
    unverifiable: List[tuple] = field(default_factory=list)  # [(sequence, key_id)]
    broken_at: Optional[int] = None                     # sequence that failed
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.broken_at is None

    def fail(self, sequence: int, reason: str) -> "IntegrityReport":
        self.broken_at = sequence
        self.reason = reason
        return self

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        if not self.ok:
            return f"IntegrityReport(BROKEN at {self.broken_at}: {self.reason})"
        tail = f", {len(self.unverifiable)} unverifiable" if self.unverifiable else ""
        return f"IntegrityReport(ok, {self.total} rows, {self.verified} verified{tail})"


def _as_keyring(public_key) -> Dict[str, Any]:
    """Normalise a single Verifier / iterable / mapping into {key_id: Verifier}."""
    if public_key is None:
        return {}
    from .receipt import Receipt

    if isinstance(public_key, dict):
        return dict(public_key)
    if hasattr(public_key, "verify"):
        return {Receipt.key_id(public_key): public_key}
    return {Receipt.key_id(k): k for k in public_key}


class ReceiptLog:
    """Local append-only transparency log using SQLite.

    Single-writer (R0): one process appends at a time. The hash chain over the
    full receipt body makes deletion, reordering, and content edits tamper-evident
    without any key; verify_integrity(public_key) adds signature re-verification
    as a deeper, key-bound layer.
    """

    def __init__(self, db_path: str = "./receipts/log.db", synchronous: str = "FULL"):
        """`synchronous` trades durability for throughput.

        FULL (default) survives OS crash and power loss. NORMAL is still
        corruption-safe under WAL - the only exposure is losing the most recent
        commits on a power cut - and is the usual recommendation for WAL. A
        receipt log defaults to the durable end because a receipt that was
        acknowledged and then vanished is worse than a slow one.
        """
        if synchronous.upper() not in ("FULL", "NORMAL", "OFF", "EXTRA"):
            raise ValueError(f"invalid synchronous mode: {synchronous}")
        self.synchronous = synchronous.upper()
        # One cached connection PER THREAD. sqlite3 connections are not safe to
        # share across threads, but reopening one for every call was costing
        # ~2/3 of each append: profiling 800 appends showed connect+close at 48%
        # of total time and the per-connection PRAGMAs another 19%.
        self._local = threading.local()
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self, timeout: float = 30.0) -> sqlite3.Connection:
        """Open a connection configured for safe multi-writer use.

        `isolation_level=None` turns OFF the sqlite3 module's implicit
        transaction management so we can issue BEGIN IMMEDIATE ourselves -
        without this, python starts a deferred transaction and the write lock is
        not taken until the first INSERT, which is exactly the window that let
        two writers read the same chain head.

        `journal_mode` is deliberately NOT set here. WAL is a persistent property
        of the database file, so setting it per-connection is pure overhead -
        measured at 2.4 ms of the 7.9 ms each append was costing, because it
        takes a lock to switch mode even when the mode is already WAL. It is set
        once in _init_db instead. busy_timeout and synchronous are per-connection
        and cheap (~0.3 ms total).
        """
        cached = getattr(self._local, "conn", None)
        if cached is not None:
            try:
                cached.execute("SELECT 1").fetchone()
                return cached
            except sqlite3.Error:
                # stale (db replaced, handle closed) - drop and reopen
                try:
                    cached.close()
                except sqlite3.Error:
                    pass
                self._local.conn = None

        conn = sqlite3.connect(self.db_path, timeout=timeout, isolation_level=None)
        conn.row_factory = sqlite3.Row
        # busy_timeout makes contending writers wait for the lock rather than
        # failing immediately; synchronous=FULL survives OS crash / power loss.
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute(f"PRAGMA synchronous={self.synchronous}")
        self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close this thread's cached connection. Safe to call repeatedly."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    def __enter__(self) -> "ReceiptLog":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def __del__(self):
        # A cached handle keeps the .db file open, which on Windows blocks the
        # directory from being deleted. Release it when the log goes out of
        # scope so callers are not forced to remember close().
        try:
            self.close()
        except Exception:
            pass

    def _init_db(self) -> None:
        conn = self._connect()
        # WAL persists in the file header, so this is a one-time cost at open
        # rather than a per-connection one. It lets readers proceed during a
        # write and makes cross-process locking reliable.
        conn.execute("PRAGMA journal_mode=WAL")
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

        conn = self._connect()
        try:
            cursor = conn.cursor()
            # BEGIN IMMEDIATE takes the RESERVED write lock up front, so the
            # read of the chain head and the write that extends it are one
            # atomic step. Without it (v0.2.2) two writers both read the same
            # head and the chain forked - measured to break at 2 concurrent
            # writers, silently, with every row still written and no exception
            # raised. This holds across processes as well as threads.
            cursor.execute("BEGIN IMMEDIATE")
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
            cursor.execute("COMMIT")
            return sequence
        except sqlite3.IntegrityError as e:
            conn.execute("ROLLBACK")
            raise ValueError(
                f"Receipt already in log or sequence taken: {receipt.receipt_id}"
            ) from e
        except BaseException:
            # any other failure must not leave the write transaction open on a
            # connection we are about to hand back to the next caller
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def get(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_by_sequence(self, sequence: int) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM receipts WHERE sequence = ?", (sequence,)
        ).fetchone()
        return dict(row) if row else None

    def list_all(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM receipts ORDER BY sequence DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def verify_integrity(self, public_key=None, *, strict_keys: bool = False) -> bool:
        """Verify the log is intact. See verify_integrity_report for detail.

        Key-free (always): sequences are contiguous 1..N; the hash chain over each
        receipt body is consistent; and each receipt's own signed log_sequence
        equals its slot. Together these make deletion, reordering, content edits,
        and delete-then-renumber tamper-evident WITHOUT any key - so key rotation
        never false-flags an authentic log.

        With public_key (deeper, key-bound): additionally re-verifies each receipt's
        Ed25519 signature, catching a forger who rewrites an embedded log_sequence
        and recomputes the whole chain - they still cannot reproduce the signature.

        `public_key` may be a single Verifier or a mapping/iterable of them. Rows
        naming a `signing_key_id` we were not given are reported UNVERIFIABLE, not
        forged: after a key rotation you legitimately no longer hold the old key,
        and treating that as tampering was a false positive (D13). Pass
        `strict_keys=True` to require that every row be checkable.

        The single-machine trust assumption itself is removed only by an
        independent witness log (Signet).
        """
        return self.verify_integrity_report(
            public_key, strict_keys=strict_keys
        ).ok

    def verify_integrity_report(self, public_key=None, *,
                                strict_keys: bool = False) -> "IntegrityReport":
        """Full result: what verified, what could not, and why."""
        conn = self._connect()
        rows = conn.execute("SELECT * FROM receipts ORDER BY sequence ASC").fetchall()

        report = IntegrityReport(total=len(rows))
        if not rows:
            return report

        from .receipt import Receipt
        keys = _as_keyring(public_key)

        prev = GENESIS
        for i, row in enumerate(rows, start=1):
            if row["sequence"] != i:
                return report.fail(i, "gap / non-contiguous sequence")

            expected = _chain_entry_hash(
                row["sequence"], row["receipt_id"], _body_hash(row["receipt_json"]), prev
            )
            if row["entry_hash"] != expected or row["prev_hash"] != prev:
                return report.fail(i, "chain broken (edit / reorder / delete)")
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
                return report.fail(i, "column desynced from receipt_json")

            # a receipt that committed to a sequence (>0) must sit in that slot;
            # unsequenced legacy rows (log_sequence == 0) fall back to chain-only
            if rcpt.log_sequence and rcpt.log_sequence != row["sequence"]:
                return report.fail(i, "renumbered: signed slot != position")

            if not keys:
                continue

            # Pick the key this receipt names. v1.3+ carries signing_key_id, so
            # this is one lookup; <=v1.2 rows name nothing and must be tried
            # against every key we hold.
            if rcpt.signing_key_id:
                key = keys.get(rcpt.signing_key_id)
                if key is None:
                    # Not forgery - we simply were not given this key (rotation).
                    report.unverifiable.append((i, rcpt.signing_key_id))
                    continue
                candidates = [key]
            else:
                candidates = list(keys.values())

            if any(k.verify(rcpt.signing_bytes(), rcpt.signature) for k in candidates):
                report.verified += 1
            elif rcpt.signing_key_id:
                # It named a key we hold, and that key rejects it.
                return report.fail(i, "body does not match its signature")
            else:
                # Legacy row, none of our keys match. Ambiguous: could be a
                # rotated-away key or could be forged. Reported, not asserted.
                report.unverifiable.append((i, ""))

        if strict_keys and report.unverifiable:
            seq, kid = report.unverifiable[0]
            return report.fail(seq, f"no key held for signing_key_id={kid or '<none>'}")
        return report

    def max_sequence(self) -> int:
        conn = self._connect()
        result = conn.execute("SELECT MAX(sequence) FROM receipts").fetchone()
        return result[0] if result[0] else 0

    def count(self) -> int:
        conn = self._connect()
        result = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        return result[0] if result else 0

    def __repr__(self) -> str:
        return f"ReceiptLog(path={self.db_path}, count={self.count()}, max_sequence={self.max_sequence()})"
