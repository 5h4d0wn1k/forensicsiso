"""Super-timeline: merge all artifact events into one UTC timeline."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file, sha256_str
from forensicsiso.custody import CustodyManifest


def build_timeline(*analyses: Dict[str, Any],
                   custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Merge events from multiple analysis results into a single sorted timeline."""
    events = []

    for analysis in analyses:
        src_type = analysis.get("type", "unknown")

        # Syslog / Apache / SSH
        for ev in analysis.get("events", []):
            ts = ev.get("timestamp") or _build_timestamp(ev)
            events.append({
                "source": ev.get("source", src_type),
                "timestamp": ts,
                "detail": ev.get("message") or ev.get("request") or str(ev),
                "line": ev.get("line"),
            })

        # Windows events
        for ev in analysis.get("events", []):
            if "TimeCreated" in ev:
                events.append({
                    "source": "windows_event",
                    "timestamp": ev.get("TimeCreated", ""),
                    "detail": ev.get("Message", ""),
                    "event_id": ev.get("EventID"),
                })

        # USN journal
        for ev in analysis.get("entries", []):
            events.append({
                "source": "usn_journal",
                "timestamp": ev.get("timestamp", ""),
                "detail": f"{ev.get('operation', '')} {ev.get('filename', '')}",
            })

        # Disk
        if "superblock" in analysis:
            events.append({
                "source": "disk",
                "timestamp": analysis["superblock"].get("mtime", ""),
                "detail": f"disk image superblock mtime",
            })

        # Registry
        for vk in analysis.get("persistence", []):
            events.append({
                "source": "registry",
                "timestamp": "",
                "detail": f"persistence: {vk.get('name', '')} = {vk.get('decoded', '')}",
            })

        # Browser
        for url in analysis.get("urls", []):
            events.append({
                "source": "browser_chrome",
                "timestamp": url.get("last_visit", ""),
                "detail": url.get("url", ""),
            })
        for place in analysis.get("places", []):
            events.append({
                "source": "browser_firefox",
                "timestamp": place.get("last_visit", ""),
                "detail": place.get("url", ""),
            })
        for dl in analysis.get("downloads", []):
            events.append({
                "source": "browser_download",
                "timestamp": dl.get("start_time", ""),
                "detail": f"downloaded {dl.get('url', '')} → {dl.get('path', '')}",
            })

        # PCAP flows
        for flow in analysis.get("flows", []):
            events.append({
                "source": "pcap",
                "timestamp": flow.get("timestamp", ""),
                "detail": f"{flow.get('type', '').upper()} {flow.get('src', '')} → {flow.get('dst', '')}",
            })
        for dns in analysis.get("dns_queries", []):
            events.append({
                "source": "pcap_dns",
                "timestamp": dns.get("timestamp", ""),
                "detail": f"DNS {dns.get('type', '')} {dns.get('name', '')}",
            })

        # Memory
        for proc in analysis.get("processes", []):
            events.append({
                "source": "memory",
                "timestamp": proc.get("create_time", ""),
                "detail": f"process {proc.get('name', '')} (PID {proc.get('pid', '')})",
            })

    events.sort(key=lambda x: x.get("timestamp", "") or "0000")
    timeline_hash = sha256_str(json.dumps(events, sort_keys=True))

    result = {
        "event_count": len(events),
        "timeline_hash": timeline_hash,
        "events": events,
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("timeline", result)
    return result


def generate_html_timeline(timeline: Dict[str, Any], output_path: str) -> str:
    """Generate an HTML timeline view."""
    events = timeline.get("events", [])
    html = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>forensicsiso Timeline</title>",
        "<style>",
        "body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:20px;}",
        "h1{color:#0f3460;}",
        "table{border-collapse:collapse;width:100%;}",
        "th{background:#16213e;color:#e94560;padding:8px;text-align:left;border-bottom:2px solid #e94560;}",
        "td{padding:6px 8px;border-bottom:1px solid #333;}",
        "tr:hover{background:#16213e;}",
        ".source{color:#0f3460;font-weight:bold;}",
        ".timestamp{color:#e94560;}",
        "</style></head><body>",
        "<h1>forensicsiso — Evidence Timeline</h1>",
        f"<p>{len(events)} events</p>",
        "<table><tr><th>Source</th><th>Timestamp</th><th>Detail</th></tr>",
    ]
    for ev in events:
        html.append(
            f"<tr><td class='source'>{ev.get('source', '')}</td>"
            f"<td class='timestamp'>{ev.get('timestamp', '')}</td>"
            f"<td>{ev.get('detail', '')}</td></tr>"
        )
    html.append("</table></body></html>")
    with open(output_path, "w") as f:
        f.write("\n".join(html))
    return output_path


def _build_timestamp(ev: Dict[str, Any]) -> str:
    """Best-effort timestamp from syslog-style fields."""
    month = ev.get("month", "")
    day = ev.get("day", "")
    time_str = ev.get("time", "")
    if month and day and time_str:
        try:
            from datetime import datetime
            dt = datetime.strptime(f"2026 {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return ""
