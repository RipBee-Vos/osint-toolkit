from __future__ import annotations
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "osint_cases.db"


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              engagement_id TEXT NOT NULL,
              purpose TEXT NOT NULL,
              target TEXT NOT NULL,
              scope_file TEXT NOT NULL,
              outdir TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'created',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              error_message TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id INTEGER NOT NULL,
              finding_id TEXT NOT NULL,
              severity TEXT NOT NULL,
              confidence TEXT,
              evidence TEXT,
              recommendation TEXT,
              FOREIGN KEY(case_id) REFERENCES cases(id)
            )
            """
        )
