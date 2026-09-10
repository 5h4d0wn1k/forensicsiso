"""Build browser artifact fixtures (Chrome SQLite history, Firefox places)."""
from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timezone

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _webkit_ts(dt: datetime) -> int:
    """Convert datetime to Chrome WebKit timestamp (microseconds since 1601-01-01)."""
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int(delta.total_seconds() * 1_000_000)


def _unix_ts(dt: datetime) -> int:
    return int(dt.timestamp())


def build_chrome_history_fixture(dest: str) -> str:
    """Build a real SQLite Chrome History fixture."""
    if os.path.exists(dest):
        os.unlink(dest)
    db = sqlite3.connect(dest)
    db.execute("""CREATE TABLE urls (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT,
        visit_count INTEGER DEFAULT 0,
        last_visit_time INTEGER NOT NULL,
        hidden INTEGER DEFAULT 0
    )""")
    db.execute("""CREATE TABLE visits (
        id INTEGER PRIMARY KEY,
        url INTEGER NOT NULL,
        visit_time INTEGER NOT NULL,
        from_visit INTEGER DEFAULT 0,
        transition INTEGER DEFAULT 0
    )""")

    base = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    urls = [
        ("https://example.com/", "Example", 3, 0),
        ("https://alice@example.com/mail/", "Alice Mail", 2, 1),
        ("https://evil.example.com/phish/", "Phish Site", 1, 0),
        ("https://github.com/forensicsiso", "GitHub Repo", 1, 0),
        ("http://10.0.0.1/admin", "Admin Panel", 1, 0),
    ]
    visit_id = 0
    for i, (url, title, count, hidden) in enumerate(urls, 1):
        ts = _webkit_ts(base)
        db.execute("INSERT INTO urls VALUES (?,?,?,?,?,?)", (i, url, title, count, ts, hidden))
        for _ in range(count):
            visit_id += 1
            visit_ts = _webkit_ts(base)
            db.execute("INSERT INTO visits VALUES (?,?,?,?,?)", (visit_id, i, visit_ts, 0, 0))
        base = datetime(base.year, base.month, base.day, base.hour + 1, 0, 0, tzinfo=timezone.utc)

    # Download record
    db.execute("""CREATE TABLE downloads (
        id INTEGER PRIMARY KEY,
        guid TEXT,
        current_path TEXT,
        target_path TEXT,
        start_time INTEGER,
        received_bytes INTEGER,
        total_bytes INTEGER,
        state INTEGER,
        danger_type INTEGER,
        interrupt_reason INTEGER,
        url TEXT,
        last_download_time INTEGER
    )""")
    dl_time = _webkit_ts(datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc))
    db.execute("INSERT INTO downloads VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (1, "guid-001", "/home/alice/Downloads/tool.exe", "/home/alice/Downloads/tool.exe",
                dl_time, 1048576, 1048576, 1, 0, 0, "https://evil.example.com/tool.exe", dl_time))

    db.commit()
    db.close()
    return dest


def build_firefox_places_fixture(dest: str) -> str:
    """Build a Firefox places.sqlite fixture."""
    if os.path.exists(dest):
        os.unlink(dest)
    db = sqlite3.connect(dest)
    db.execute("""CREATE TABLE moz_places (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT,
        visit_count INTEGER DEFAULT 0,
        last_visit_date INTEGER
    )""")
    db.execute("""CREATE TABLE moz_historyvisits (
        id INTEGER PRIMARY KEY,
        place_id INTEGER NOT NULL,
        visit_date INTEGER,
        visit_type INTEGER DEFAULT 1
    )""")

    base = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    places = [
        ("https://example.com/docs/", "Docs", 2),
        ("https://alice@example.com/mail/", "Alice Mail", 1),
        ("https://example.com/login.php?user=alice@example.com", "Login", 1),
    ]
    visit_id = 0
    for i, (url, title, count) in enumerate(places, 1):
        ts = _unix_ts(base)
        db.execute("INSERT INTO moz_places VALUES (?,?,?,?,?)", (i, url, title, count, ts))
        for _ in range(count):
            visit_id += 1
            db.execute("INSERT INTO moz_historyvisits VALUES (?,?,?,?)", (visit_id, i, ts, 1))
        base = datetime(base.year, base.month, base.day, base.hour + 1, 0, 0, tzinfo=timezone.utc)

    db.commit()
    db.close()
    return dest
