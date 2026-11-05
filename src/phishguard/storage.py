"""SQLite keeps the application's jobs, provider IDs, approvals, and activity log."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATABASE = ROOT / ".local" / "signal.db"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@contextmanager
def connection():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE, timeout=15)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        with db:
            yield db
    finally:
        db.close()


def acquire_worker_lock():
    """The OS releases this lock if the server exits or crashes."""
    handle = DATABASE.with_suffix(".lock").open("a+b")
    handle.seek(0)
    if not handle.read(1):
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise RuntimeError(
            "Another Signal worker is already using this database"
        ) from None
    return handle


def initialize() -> None:
    with connection() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
                status TEXT NOT NULL, error TEXT, created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, time TEXT NOT NULL, case_id TEXT, message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS commitments (
                id TEXT PRIMARY KEY, service TEXT NOT NULL, cents INTEGER NOT NULL
            );
        """)


def get(key: str, default=None):
    with connection() as db:
        row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def put(key: str, value) -> None:
    with connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO state VALUES (?, ?)", (key, json.dumps(value))
        )


def event(message: str, case_id: str | None = None) -> None:
    with connection() as db:
        db.execute(
            "INSERT INTO events(time,case_id,message) VALUES(?,?,?)",
            (now(), case_id, message),
        )


def events() -> list[dict]:
    with connection() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT time,case_id,message FROM events ORDER BY id DESC LIMIT 100"
            )
        ]


def enqueue(identifier: str, kind: str, payload: dict | None = None) -> None:
    # A stable ID makes repeated clicks harmless.
    with connection() as db:
        db.execute(
            "INSERT OR IGNORE INTO commands VALUES(?,?,?,?,?,?)",
            (identifier, kind, json.dumps(payload or {}), "pending", None, now()),
        )


def claim() -> dict | None:
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM commands WHERE status='pending' ORDER BY created LIMIT 1"
        ).fetchone()
        if not row:
            return None
        db.execute("UPDATE commands SET status='running' WHERE id=?", (row["id"],))
    return dict(row) | {"payload": json.loads(row["payload"])}


def finish(identifier: str, error: str | None = None) -> None:
    with connection() as db:
        db.execute(
            "UPDATE commands SET status=?,error=? WHERE id=?",
            ("error" if error else "done", error, identifier),
        )


def recover() -> None:
    # Never replay an interrupted external mutation: its remote outcome may be unknown.
    with connection() as db:
        db.execute(
            "UPDATE commands SET status='error', error=? WHERE status='running'",
            (
                "Interrupted. Inspect the provider before retrying; automatic replay is disabled.",
            ),
        )


def commands() -> list[dict]:
    with connection() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT id,kind,status,error FROM commands ORDER BY created"
            )
        ]


def committed(service: str) -> int:
    with connection() as db:
        return db.execute(
            "SELECT COALESCE(SUM(cents),0) FROM commitments WHERE service=?", (service,)
        ).fetchone()[0]


def reserve(identifier: str, service: str, cents: int) -> None:
    # $50 available, $5 held back. Keep reservations after ambiguous outcomes.
    if isinstance(cents, bool) or not isinstance(cents, int) or cents <= 0:
        raise ValueError("A positive, verified USD quote is required")
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM commitments WHERE id=?", (identifier,)).fetchone():
            raise ValueError(
                "This operation already has a reservation; inspect its status"
            )
        total = db.execute(
            "SELECT COALESCE(SUM(cents),0) FROM commitments WHERE service=?", (service,)
        ).fetchone()[0]
        if total + cents > 4500:
            raise ValueError(
                "Quote exceeds the $45 operating limit ($5 reserve from your $50 budget)"
            )
        db.execute(
            "INSERT INTO commitments VALUES(?,?,?)", (identifier, service, cents)
        )
