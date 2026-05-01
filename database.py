"""database.py - SQLite connection + schema helpers."""
import sqlite3

from flask import g, current_app


def get_db() -> sqlite3.Connection:
    """Return the request-scoped SQLite connection (lazy-init)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


def close_db(_error=None) -> None:
    """Tear down the request-scoped connection at the end of each request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path: str) -> None:
    """Create the users table if it doesn't yet exist. Idempotent."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL CHECK(role IN ('user', 'admin')),
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()
