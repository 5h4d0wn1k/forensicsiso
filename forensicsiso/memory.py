"""Memory/crash snapshot parser — Volatility-style PSSCAN format, /proc-derived process dumps, string scanning."""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file
from forensicsiso.custody import CustodyManifest

MAGIC = b"PSSCAN\x01\x02"
PID_TABLE_OFFSET = 64
PROC_REC_SIZE = 160

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')


def parse_psscan_header(data: bytes) -> Dict[str, Any]:
    """Parse the Volatility-style PSSCAN header."""
    if data[:8] != MAGIC:
        return {"error": f"bad magic: expected {MAGIC!r}, got {data[:8]!r}"}
    proc_count = struct.unpack_from("<I", data, 8)[0]
    timestamp = struct.unpack_from("<Q", data, 16)[0]
    source_id = data[24:32].rstrip(b"\x00").decode(errors="replace")
    return {
        "magic": MAGIC.hex(),
        "process_count": proc_count,
        "capture_time": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        "source": source_id,
    }


def parse_process_table(data: bytes) -> List[Dict[str, Any]]:
    """Parse process records from the PSSCAN table."""
    count = struct.unpack_from("<I", data, 8)[0]
    processes = []
    for i in range(count):
        off = PID_TABLE_OFFSET + i * PROC_REC_SIZE
        if off + PROC_REC_SIZE > len(data):
            break
        pid = struct.unpack_from("<I", data, off)[0]
        ppid = struct.unpack_from("<I", data, off + 4)[0]
        uid = struct.unpack_from("<I", data, off + 8)[0]
        create_time = struct.unpack_from("<Q", data, off + 12)[0]
        state = struct.unpack_from("<I", data, off + 20)[0]
        name = data[off + 24: off + 56].split(b"\x00")[0].decode(errors="replace")
        cmdline = data[off + 56: off + 136].split(b"\x00")[0].decode(errors="replace")
        processes.append({
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "name": name,
            "cmdline": cmdline,
            "state": "sleeping" if state == 0x800 else f"0x{state:X}",
            "create_time": datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat(),
        })
    return processes


def parse_proc_dump(dump_path: str) -> Dict[str, Any]:
    """Parse a /proc-derived JSON process dump."""
    with open(dump_path) as f:
        data = json.load(f)
    result = {
        "pid": data.get("pid"),
        "ppid": data.get("ppid"),
        "cmdline": data.get("cmdline"),
        "exe": data.get("exe"),
        "cwd": data.get("cwd"),
    }
    # Parse status for VmRSS
    status = data.get("status", "")
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            result["vm_rss"] = line.split(":")[1].strip()
    return result


def string_scan(data: bytes, patterns: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Scan binary data for interesting strings — IPs, emails, paths, keywords."""
    if patterns is None:
        patterns = [r"C:\\", r"/etc/", r"password", r"secret", r"key", r"token"]
    results = []
    text = data.decode(errors="replace")
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            ctx_start = max(0, m.start() - 20)
            ctx_end = min(len(text), m.end() + 40)
            results.append({
                "pattern": pat,
                "match": m.group(),
                "context": text[ctx_start:ctx_end].replace("\x00", ""),
                "offset": m.start(),
            })
    for m in IP_PATTERN.finditer(text):
        ip = m.group()
        if not ip.startswith("0.") and not ip.startswith("127."):
            results.append({
                "pattern": "IP_ADDRESS",
                "match": ip,
                "context": text[max(0, m.start() - 20): min(len(text), m.end() + 20)].replace("\x00", ""),
                "offset": m.start(),
            })
    for m in EMAIL_PATTERN.finditer(text):
        results.append({
            "pattern": "EMAIL",
            "match": m.group(),
            "context": text[max(0, m.start() - 20): min(len(text), m.end() + 20)].replace("\x00", ""),
            "offset": m.start(),
        })
    return results


def parse_memory(fixture_path: str, proc_dump_path: Optional[str] = None,
                 custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Full memory analysis pipeline."""
    if custody:
        custody.add_file(fixture_path, "memory_fixture")

    with open(fixture_path, "rb") as f:
        data = f.read()

    result: Dict[str, Any] = {
        "type": "memory",
        "image": os.path.abspath(fixture_path),
        "size": len(data),
        "sha256": sha256_file(fixture_path),
    }

    # PSSCAN header + process table
    result["header"] = parse_psscan_header(data)
    result["processes"] = parse_process_table(data)

    # /proc-derived dump
    if proc_dump_path and os.path.exists(proc_dump_path):
        if custody:
            custody.add_file(proc_dump_path, "proc_dump")
        result["proc_dump"] = parse_proc_dump(proc_dump_path)

    # String scan
    result["string_hits"] = string_scan(data)

    if custody:
        result["custody_hash"] = custody.add_json_output("memory_analysis", result)

    return result
