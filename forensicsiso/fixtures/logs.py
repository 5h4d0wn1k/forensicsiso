"""Build log fixtures: syslog, apache access, SSH auth, Windows Event, USN journal."""
from __future__ import annotations

import json
import os
import struct
import time
from datetime import datetime, timezone, timedelta


def build_syslog_fixture(dest: str) -> str:
    lines = [
        "Sep  9 10:00:01 host1 CRON[1234]: (root) CMD (test -x /usr/sbin/run-crons)",
        "Sep  9 10:05:12 host1 sshd[5678]: Accepted publickey for alice@example.com from 192.168.1.10 port 44832 ssh2",
        "Sep  9 10:06:01 host1 sshd[5679]: pam_unix(sshd:session): session opened for user alice by (uid=0)",
        "Sep  9 10:10:33 host1 kernel: [UFW BLOCK] IN=eth0 SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP DPT=22",
        "Sep  9 10:15:44 host1 sudo: alice@example.com : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Sep  9 11:00:00 host1 systemd[1]: Starting Daily apt activities...",
        "Sep  9 11:30:00 host1 CRON[1235]: (root) CMD (/usr/local/bin/backup.sh)",
        "Sep  9 12:00:01 host1 sshd[5680]: Failed password for bob from 192.168.1.50 port 44900 ssh2",
        "Sep  9 12:00:05 host1 sshd[5680]: Failed password for bob from 192.168.1.50 port 44900 ssh2",
        "Sep  9 12:00:08 host1 sshd[5680]: Failed password for bob from 192.168.1.50 port 44900 ssh2",
        "Sep  9 12:01:00 host1 sshd[5680]: Disconnected from 192.168.1.50 port 44900 [preauth]",
        "Sep  9 13:00:00 host1 CRON[1236]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
        "Sep  9 14:22:10 host1 sudo: alice@example.com : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/rm -rf /tmp/junk",
        "Sep  9 15:00:01 host1 CRON[1237]: (alice) CMD (cd /home/alice && python3 cleanup.py)",
    ]
    with open(dest, "w") as f:
        f.write("\n".join(lines) + "\n")
    return dest


def build_apache_access_fixture(dest: str) -> str:
    entries = [
        ('192.168.1.10', '-', 'alice', '09/Sep/2026:10:05:12 +0000', 'GET /index.html HTTP/1.1', 200, 3421),
        ('192.168.1.10', '-', 'alice', '09/Sep/2026:10:05:13 +0000', 'GET /style.css HTTP/1.1', 200, 1204),
        ('192.168.1.50', '-', '-', '09/Sep/2026:10:10:00 +0000', 'GET /admin HTTP/1.1', 403, 274),
        ('10.0.0.5', '-', '-', '09/Sep/2026:10:10:33 +0000', 'POST /login HTTP/1.1', 401, 0),
        ('10.0.0.5', '-', '-', '09/Sep/2026:10:10:34 +0000', 'POST /login HTTP/1.1', 401, 0),
        ('10.0.0.5', '-', '-', '09/Sep/2026:10:10:35 +0000', 'POST /login HTTP/1.1', 401, 0),
        ('192.168.1.10', '-', 'alice', '09/Sep/2026:11:00:00 +0000', 'GET /dashboard HTTP/1.1', 200, 8912),
        ('192.168.1.10', '-', 'alice', '09/Sep/2026:12:00:00 +0000', 'POST /upload HTTP/1.1', 200, 54321),
        ('192.168.1.20', '-', 'bob', '09/Sep/2026:13:00:00 +0000', 'GET /index.html HTTP/1.1', 200, 3421),
        ('192.168.1.10', '-', 'alice', '09/Sep/2026:14:00:00 +0000', 'DELETE /uploads/secret.txt HTTP/1.1', 200, 0),
    ]
    with open(dest, "w") as f:
        for ip, ident, user, ts, req, status, size in entries:
            f.write(f'{ip} {ident} {user} [{ts}] "{req}" {status} {size}\n')
    return dest


def build_ssh_auth_fixture(dest: str) -> str:
    lines = [
        "2026-09-09T10:05:12.000000+00:00 host1 sshd[5678]: Accepted publickey for alice@example.com from 192.168.1.10 port 44832 ssh2: RSA SHA256:abc123",
        "2026-09-09T10:06:01.000000+00:00 host1 sshd[5679]: pam_unix(sshd:session): session opened for user alice@example.com by (uid=0)",
        "2026-09-09T12:00:01.000000+00:00 host1 sshd[5680]: Failed password for invalid user bob from 192.168.1.50 port 44900 ssh2",
        "2026-09-09T12:00:05.000000+00:00 host1 sshd[5680]: Failed password for invalid user bob from 192.168.1.50 port 44900 ssh2",
        "2026-09-09T12:00:08.000000+00:00 host1 sshd[5680]: Failed password for invalid user bob from 192.168.1.50 port 44900 ssh2",
        "2026-09-09T12:01:00.000000+00:00 host1 sshd[5680]: Disconnected from 192.168.1.50 port 44900 [preauth]",
        "2026-09-09T15:30:00.000000+00:00 host1 sshd[5681]: Accepted publickey for alice@example.com from 192.168.1.10 port 45000 ssh2: RSA SHA256:abc123",
        "2026-09-09T15:31:00.000000+00:00 host1 sshd[5682]: pam_unix(sshd:session): session opened for user alice@example.com by (uid=0)",
        "2026-09-09T16:00:00.000000+00:00 host1 sshd[5683]: Received disconnect from 192.168.1.10 port 45000:11: disconnected by user",
    ]
    with open(dest, "w") as f:
        f.write("\n".join(lines) + "\n")
    return dest


def build_windows_event_fixture(dest: str) -> str:
    events = [
        {"EventID": 4624, "TimeCreated": "2026-09-09T10:00:00Z", "Level": 0, "Computer": "WIN-DESK",
         "Message": "An account was successfully logged on. Account: alice; Logon Type: 10",
         "Channel": "Security", "ProcessID": 600, "ThreadID": 1200},
        {"EventID": 4625, "TimeCreated": "2026-09-09T12:00:00Z", "Level": 2, "Computer": "WIN-DESK",
         "Message": "An account failed to log on. Account: bob; Failure Reason: Unknown user or bad password",
         "Channel": "Security", "ProcessID": 600, "ThreadID": 1300},
        {"EventID": 4720, "TimeCreated": "2026-09-09T13:00:00Z", "Level": 0, "Computer": "WIN-DESK",
         "Message": "A user account was created. New Account: eve",
         "Channel": "Security", "ProcessID": 600, "ThreadID": 1400},
        {"EventID": 4732, "TimeCreated": "2026-09-09T13:05:00Z", "Level": 0, "Computer": "WIN-DESK",
         "Message": "A member was added to a security-enabled local group. Group: Administrators; Account: eve",
         "Channel": "Security", "ProcessID": 600, "ThreadID": 1500},
        {"EventID": 1102, "TimeCreated": "2026-09-09T14:00:00Z", "Level": 0, "Computer": "WIN-DESK",
         "Message": "The audit log was cleared. Subject: alice",
         "Channel": "Security", "ProcessID": 600, "ThreadID": 1600},
    ]
    with open(dest, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    return dest


def build_usn_journal_fixture(dest: str) -> str:
    """Build a USN-journal-like CSV fixture."""
    entries = [
        ("2026-09-09T10:00:00Z", "FILE_CREATE", r"C:\Users\alice\Documents\report.docx", 12345),
        ("2026-09-09T10:05:00Z", "FILE_MODIFY", r"C:\Users\alice\Documents\report.docx", 12345),
        ("2026-09-09T11:00:00Z", "FILE_CREATE", r"C:\Users\alice\Downloads\tool.exe", 67890),
        ("2026-09-09T12:00:00Z", "FILE_DELETE", r"C:\Users\alice\Documents\report.docx", 12345),
        ("2026-09-09T13:00:00Z", "FILE_RENAME", r"C:\Users\alice\Downloads\tool.exe", 67890),
        ("2026-09-09T14:00:00Z", "FILE_DELETE", r"C:\Users\alice\Downloads\tool.exe", 67890),
    ]
    with open(dest, "w") as f:
        f.write("timestamp,operation,filename,inode\n")
        for ts, op, fn, ino in entries:
            f.write(f"{ts},{op},{fn},{ino}\n")
    return dest
