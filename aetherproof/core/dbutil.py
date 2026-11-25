"""SQLite setup that survives several processes starting at once.

Switching a new database file to WAL needs an exclusive lock, and SQLite can report
"database is locked" at once, without waiting for its busy timeout, when several processes
open the same new file together (seen on Windows CI and in tests/test_limits.py). Setup is
retried with a short random back-off for up to timeout_s, then the error is raised.
"""
from __future__ import annotations

import random
import sqlite3
import time


def run_setup(conn: sqlite3.Connection, statements, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            for stmt in statements:
                conn.execute(stmt)
            return
        except sqlite3.OperationalError as e:
            if ("locked" not in str(e) and "busy" not in str(e)) or time.monotonic() > deadline:
                raise
            time.sleep(0.01 + random.random() * 0.04)


def open_db(path: str, statements, timeout_s: float = 30.0) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=timeout_s, isolation_level=None, check_same_thread=False)
    try:
        run_setup(db, statements, timeout_s)
    except BaseException:
        db.close()
        raise
    return db
