"""Log parser — syslog, Apache access, SSH auth, Windows Event, USN journal."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file
from forensicsiso.custody import CustodyManifest

SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$'
)
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)'
)
SSH_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$'
)
SSH_ACCEPT_RE = re.compile(r'Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)')
SSH_FAIL_RE = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)')
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}')


def parse_syslog(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse syslog fixture, extract events, logons, anomalies."""
    if custody:
        custody.add_file(path, "syslog")
    events = []
    anomalies = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            m = SYSLOG_RE.match(line)
            if m:
                ev = {
                    "source": "syslog",
                    "line": line_no,
                    "month": m.group("month"),
                    "day": m.group("day"),
                    "time": m.group("time"),
                    "host": m.group("host"),
                    "service": m.group("service"),
                    "pid": m.group("pid"),
                    "message": m.group("message"),
                }
                events.append(ev)
                msg = m.group("message")
                if "Failed password" in msg:
                    anomalies.append({"type": "failed_login", "line": line_no, "detail": msg})
                if "UFW BLOCK" in msg:
                    anomalies.append({"type": "firewall_block", "line": line_no, "detail": msg})
                if "sudo:" in m.group("service") and "COMMAND=" in msg:
                    anomalies.append({"type": "sudo_command", "line": line_no, "detail": msg})
    result = {"type": "syslog", "path": os.path.abspath(path), "events": events, "anomalies": anomalies}
    if custody:
        result["custody_hash"] = custody.add_json_output("syslog_analysis", result)
    return result


def parse_apache_access(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse Apache access log (common/combined format)."""
    if custody:
        custody.add_file(path, "apache_access")
    entries = []
    anomalies = []
    status_counts: Dict[str, int] = {}
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            m = APACHE_RE.match(line)
            if m:
                status = m.group("status")
                status_counts[status] = status_counts.get(status, 0) + 1
                entry = {
                    "source": "apache_access",
                    "line": line_no,
                    "ip": m.group("ip"),
                    "user": m.group("user"),
                    "timestamp": m.group("timestamp"),
                    "request": m.group("request"),
                    "status": int(status),
                    "size": int(m.group("size")),
                }
                entries.append(entry)
                if status in ("401", "403", "404", "500"):
                    anomalies.append({"type": f"http_{status}", "line": line_no, "ip": m.group("ip"),
                                      "request": m.group("request")})
                if "DELETE" in m.group("request"):
                    anomalies.append({"type": "delete_operation", "line": line_no,
                                      "request": m.group("request")})
    emails = set()
    for e in entries:
        emails.update(EMAIL_RE.findall(e.get("user", "")))
    result = {
        "type": "apache_access",
        "path": os.path.abspath(path),
        "entries": entries,
        "anomalies": anomalies,
        "status_summary": status_counts,
        "emails_found": sorted(emails),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("apache_analysis", result)
    return result


def parse_ssh_auth(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse SSH authentication log."""
    if custody:
        custody.add_file(path, "ssh_auth")
    events = []
    anomalies = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            m = SSH_RE.match(line)
            if m:
                msg = m.group("message")
                ev = {
                    "source": "ssh_auth",
                    "line": line_no,
                    "timestamp": m.group("timestamp"),
                    "host": m.group("host"),
                    "pid": m.group("pid"),
                    "message": msg,
                }
                am = SSH_ACCEPT_RE.search(msg)
                if am:
                    ev["action"] = "accepted"
                    ev["user"] = am.group(1)
                    ev["from_ip"] = am.group(2)
                    ev["port"] = am.group(3)
                fm = SSH_FAIL_RE.search(msg)
                if fm:
                    ev["action"] = "failed"
                    ev["user"] = fm.group(1)
                    ev["from_ip"] = fm.group(2)
                    anomalies.append({"type": "ssh_failed", "user": fm.group(1),
                                      "from_ip": fm.group(2), "timestamp": m.group("timestamp")})
                events.append(ev)
    emails = set()
    for e in events:
        if "user" in e and "@" in e["user"]:
            emails.add(e["user"])
    result = {
        "type": "ssh_auth",
        "path": os.path.abspath(path),
        "events": events,
        "anomalies": anomalies,
        "emails_found": sorted(emails),
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("ssh_auth_analysis", result)
    return result


def parse_windows_events(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse Windows Event-like JSON log."""
    if custody:
        custody.add_file(path, "windows_events")
    events = []
    anomalies = []
    with open(path) as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev["source"] = "windows_event"
                ev["line"] = line_no
                events.append(ev)
                eid = ev.get("EventID")
                if eid in (4625,):
                    anomalies.append({"type": "failed_logon", "line": line_no,
                                      "message": ev.get("Message", "")})
                if eid == 4720:
                    anomalies.append({"type": "account_created", "line": line_no,
                                      "message": ev.get("Message", "")})
                if eid == 4732:
                    anomalies.append({"type": "group_member_added", "line": line_no,
                                      "message": ev.get("Message", "")})
                if eid == 1102:
                    anomalies.append({"type": "audit_log_cleared", "line": line_no,
                                      "message": ev.get("Message", "")})
            except json.JSONDecodeError:
                pass
    result = {
        "type": "windows_events",
        "path": os.path.abspath(path),
        "events": events,
        "anomalies": anomalies,
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("windows_events_analysis", result)
    return result


def parse_usn_journal(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse USN journal CSV fixture."""
    if custody:
        custody.add_file(path, "usn_journal")
    entries = []
    anomalies = []
    with open(path) as f:
        header = f.readline()  # skip CSV header
        for line_no, line in enumerate(f, 2):
            parts = line.strip().split(",")
            if len(parts) < 4:
                continue
            ts, op, filename, inode = parts[0], parts[1], parts[2], parts[3]
            entry = {"timestamp": ts, "operation": op, "filename": filename, "inode": inode}
            entries.append(entry)
            if op == "FILE_DELETE":
                anomalies.append({"type": "file_deleted", "filename": filename, "timestamp": ts})
            if "tool.exe" in filename.lower():
                anomalies.append({"type": "suspicious_executable", "filename": filename, "timestamp": ts})
    result = {
        "type": "usn_journal",
        "path": os.path.abspath(path),
        "entries": entries,
        "anomalies": anomalies,
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("usn_journal_analysis", result)
    return result


def parse_all_logs(syslog_path: str, apache_path: str, ssh_path: str,
                   windows_path: str, usn_path: str,
                   custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse all log fixtures in one call."""
    results = {}
    results["syslog"] = parse_syslog(syslog_path, custody)
    results["apache"] = parse_apache_access(apache_path, custody)
    results["ssh"] = parse_ssh_auth(ssh_path, custody)
    results["windows"] = parse_windows_events(windows_path, custody)
    results["usn"] = parse_usn_journal(usn_path, custody)
    total_events = sum(len(r.get("events", r.get("entries", []))) for r in results.values())
    total_anomalies = sum(len(r.get("anomalies", [])) for r in results.values())
    results["summary"] = {
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "sources": list(results.keys()),
    }
    return results
