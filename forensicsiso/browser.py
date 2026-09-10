"""Browser artifact parser — Chrome/Firefox history SQLite, cookies, downloads, timeline."""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file
from forensicsiso.custody import CustodyManifest

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
EMAIL_RE_PLACEHOLDER = "alice@example.com"


def _webkit_to_dt(ts: int) -> str:
    """Convert Chrome WebKit timestamp to ISO 8601."""
    try:
        dt = WEBKIT_EPOCH + timedelta(microseconds=ts)
        return dt.isoformat()
    except Exception:
        return str(ts)


def _unix_to_dt(ts: int) -> str:
    try:
        dt = UNIX_EPOCH + timedelta(seconds=ts)
        return dt.isoformat()
    except Exception:
        return str(ts)


def parse_chrome_history(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse Chrome History SQLite database."""
    if not os.path.exists(path):
        return {"error": f"file not found: {path}"}
    if custody:
        custody.add_file(path, "chrome_history")

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row

    urls = []
    try:
        for row in db.execute("SELECT * FROM urls ORDER BY last_visit_time DESC"):
            urls.append({
                "id": row["id"],
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "last_visit": _webkit_to_dt(row["last_visit_time"]),
            })
    except sqlite3.OperationalError:
        pass

    visits = []
    try:
        for row in db.execute("SELECT * FROM visits ORDER BY visit_time DESC LIMIT 50"):
            visits.append({
                "id": row["id"],
                "url_id": row["url"],
                "visit_time": _webkit_to_dt(row["visit_time"]),
                "transition": row["transition"],
            })
    except sqlite3.OperationalError:
        pass

    downloads = []
    try:
        for row in db.execute("SELECT * FROM downloads"):
            downloads.append({
                "id": row["id"],
                "url": row["url"],
                "path": row["current_path"],
                "start_time": _webkit_to_dt(row["start_time"]),
                "received_bytes": row["received_bytes"],
                "state": row["state"],
            })
    except sqlite3.OperationalError:
        pass

    db.close()

    emails_found = []
    for u in urls:
        if "@" in u.get("url", "") or "@" in u.get("title", ""):
            # extract from URL
            import re
            for m in re.finditer(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', u["url"]):
                emails_found.append(m.group())

    result = {
        "type": "chrome_history",
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "urls": urls,
        "visits": visits,
        "downloads": downloads,
        "emails_found": sorted(set(emails_found)),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("chrome_history", result)
    return result


def parse_firefox_places(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse Firefox places.sqlite."""
    if not os.path.exists(path):
        return {"error": f"file not found: {path}"}
    if custody:
        custody.add_file(path, "firefox_places")

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row

    places = []
    try:
        for row in db.execute("SELECT * FROM moz_places ORDER BY last_visit_date DESC"):
            places.append({
                "id": row["id"],
                "url": row["url"],
                "title": row["title"],
                "visit_count": row["visit_count"],
                "last_visit": _unix_to_dt(row["last_visit_date"]) if row["last_visit_date"] else None,
            })
    except sqlite3.OperationalError:
        pass

    db.close()

    emails_found = []
    import re
    for p in places:
        for m in re.finditer(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', p.get("url", "")):
            emails_found.append(m.group())

    result = {
        "type": "firefox_places",
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "places": places,
        "emails_found": sorted(set(emails_found)),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("firefox_places", result)
    return result


def build_browser_timeline(chrome: Dict[str, Any], firefox: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Merge browser history into a sorted timeline."""
    timeline = []
    for url in chrome.get("urls", []):
        timeline.append({
            "source": "chrome",
            "timestamp": url.get("last_visit", ""),
            "url": url.get("url", ""),
            "title": url.get("title", ""),
            "visit_count": url.get("visit_count", 0),
        })
    for visit in chrome.get("visits", []):
        timeline.append({
            "source": "chrome_visit",
            "timestamp": visit.get("visit_time", ""),
            "url_id": visit.get("url_id"),
            "transition": visit.get("transition"),
        })
    for dl in chrome.get("downloads", []):
        timeline.append({
            "source": "chrome_download",
            "timestamp": dl.get("start_time", ""),
            "url": dl.get("url", ""),
            "path": dl.get("path", ""),
            "bytes": dl.get("received_bytes", 0),
        })
    for place in firefox.get("places", []):
        timeline.append({
            "source": "firefox",
            "timestamp": place.get("last_visit") or "",
            "url": place.get("url", ""),
            "title": place.get("title", ""),
            "visit_count": place.get("visit_count", 0),
        })
    timeline.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return timeline
