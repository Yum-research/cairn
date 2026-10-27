"""Prepare a read-only screenshot database from the demo database.

This never touches .cairn/gui-demo.db; it copies it and pins the demo
engagement to the top of the engagement list so the dashboard selects it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".cairn" / "gui-demo.db"
TARGET = ROOT / ".cairn" / "gui-screenshot.db"


def main() -> None:
    source = sqlite3.connect(SOURCE)
    target = sqlite3.connect(TARGET)
    source.backup(target)
    target.execute(
        "UPDATE engagements SET created_at='2099-01-01T00:00:00+00:00' WHERE name LIKE 'Cairn local demo%'"
    )
    target.commit()
    target.close()
    source.close()
    print(f"wrote {TARGET}")


if __name__ == "__main__":
    main()
