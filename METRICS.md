# Metrics

Measured on clean build (Python 3.13.5, Linux). Updated after each feature.

## Test suite

- **Total tests:** 51 (`python3 -m unittest discover -s tests` → `OK`)
- **Module pass rate:** 51/51 (100%)
- **Runtime (parsers only):** 5.69 s

## Demo pipeline (`forensicsiso --demo`, offline fixtures)

- **Exit code:** 0 — "DEMO COMPLETE — ALL MODULES OK"
- **Wall time (full 10-module pipeline + fixture builds + custody):** 14.3 s

Per-module proof (parsers run over regenerable fixtures, hashed + custody-tracked):

| Module | Artifacts parsed | Key output | Status |
|---|---|---|---|
| disk    | 1 MiB ext2 image | 4 root dir entries (`hello.txt`, `deleted.txt`…), MBR Linux partition, GPT header, superblock magic 0xEF53, **deleted file recovered (hash ca0884f9…)** | PASS |
| memory  | PSSCAN fixture + /proc dump | **8 processes** (systemd/bas/bash/sshd/python3/nginx/httpd/netcat/cron), 4 string hits, marker exe path present | PASS |
| logs    | 5 log families | **44 events, 21 anomalies** (logons, brute-force cluster, audit clear, file deletions) | PASS |
| pcap    | 3-packet pcap | **3 flows**, 1 DNS query (`evil.example.com`), 2 TCP sessions, 1 HTTP `GET /secret` | PASS |
| registry| regf hive replica | 15 keys, 3 values, **2 Run keys, 3 persistence** (`malware.exe`, `payload.bat`, `init.dll`), 2 services, **2 SAM users** (`alice`,`bob`) | PASS |
| browser | SQLite Chrome + Firefox | 5 Chrome URLs, 3 Firefox places, 1 download, planted `alice@example.com` URL timestamps | PASS |
| email   | .eml + mbox | 1 MIME attachment (SHA-256 hashed), envelope headers, 3 mbox messages | PASS |
| timeline| merged events | **25 events**, event-level hash + HTML view | PASS |
| correlate | cross-artifact | **alice@example.com cross-correlated across 6 sources** (syslog, ssh_auth, chrome, firefox, eml, mbox), 12 suspicious-behavior signatures | PASS |
| hashes  | SHA-256 chain | every fixture + output in custody manifest; `--verify` confirms chain | PASS |

## Integration

- **Deleted file recovered with matching hash:** yes (inode 3 → `ca0884f907e2001b…`)
- **Memory parser yields planted marker process / bin path:** yes (PID + `/usr/bin/python3.13`)
- **Logon timestamps correct:** SSH accepted logon `2026-09-09T10:05:12+00:00` parsed exactly
- **Registry Run key + SAM-like Users:** Run/Updater + Run/Launcher + (Default); Users: alice, bob
- **Browser planted URL + timestamp:** `https://alice@example.com/mail/` @ 2026-09-09T11:00:00+00:00
- **alice@example.com across 3+ sources:** yes — 6 sources
- **Hash chain verification:** passes (`forensicsiso hashes --verify` → 9/9 custody manifests valid, chain_valid True)