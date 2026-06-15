"""SQLite connection and schema initialization.

This lab uses a single SQLite file (`vulnerable_app.db` at the repo root) as
its only datastore. The file is auto-created on first launch by init_db(),
which runs once from main.py at startup.

Why SQLite and not Postgres/MySQL? The app is an educational lab meant to be
clonable and runnable with zero infrastructure. SQLite ships with Python,
needs no server, and lets students reset the data layer with a single `rm`.
"""

import sqlite3
import os

# Absolute path to the database file: <repo>/vulnerable_app.db.
# The four `..` segments climb from this file (backend/app/db/session.py)
# back up to the project root. We resolve this at import time so the path
# is stable regardless of which directory uvicorn was launched from.
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vulnerable_app.db")


def get_db():
    """Open a fresh SQLite connection.

    Callers are responsible for closing the returned connection (use
    try/finally or `with`). Each handler opens its own connection so we
    do not need a connection pool -- SQLite's file-level locking is
    sufficient for a single-process educational lab.

    - check_same_thread=False: required because FastAPI runs handlers on
      an asyncio event loop that may dispatch them across threads. SQLite
      objects are not normally thread-safe; this flag tells sqlite3 to
      trust us to serialize access ourselves (we do, by opening one
      connection per request and never sharing it).
    - row_factory = sqlite3.Row: makes cursor.fetchone() return a Row
      object that supports both `row[0]` and `row["username"]` access,
      so auth_service.login() can read `user["password"]` by column name.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table if it does not already exist.

    Called once from main.py at app startup. Idempotent thanks to
    `IF NOT EXISTS`, so re-running the app against an existing DB is
    safe and preserves user rows.

    Schema notes:
    - `username TEXT UNIQUE`: signup relies on this to surface
      "Username already exists" via sqlite3.IntegrityError.
    - `password TEXT`: stores the bcrypt hash string (not the plaintext
      password and not a binary blob -- bcrypt.hashpw() returns bytes
      that we decode to UTF-8 in core/security.py).
    """
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email    TEXT,
            password TEXT
        )"""
    )
    conn.commit()
    conn.close()
