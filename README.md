# forensicsiso

Full DFIR workstation - disk/memory/log/pcap/registry/browser/email parsing, timeline, cross-artifact correlation.

Parsers operate **read-only** over evidence fixtures, every artifact and output is **SHA-256 hashed**, and results carry **chain-of-custody** metadata (who / when / what). Default is dry-run (~simulation) mode; live-lab actions stay offline.

## Quickstart

```bash
python3 -m pip install -e .
python3 -m forensicsiso --help
python3 -m forensicsiso --demo    # offline, exit 0
python3 -m forensicsiso disk --json
python3 -m unittest discover -s tests
```

## Command structure

```
forensicsiso disk      # ext-style image: superblock, inodes, dir entries, deleted-file recovery, MBR/GPT, carving
forensicsiso memory    # Volatility-style PSSCAN + /proc dump, processes, open files, string scan
forensicsiso logs      # syslog, Apache access, SSH auth, Windows Events, USN-journal
forensicsiso pcap      # flows, host pairs, protocols, DNS, TCP sessions, HTTP payloads
forensicsiso registry  # regf hive replica: header, root keys, values, Run keys, SAM, services
forensicsiso browser   # Chrome history/cookies/downloads SQLite + Firefox places
forensicsiso email     # .eml (MIME) + mbox
forensicsiso timeline  # merged UTC super-timeline (JSON + HTML)
forensicsiso correlate # cross-artifact correlation (person-hash) + suspicious-behavior signatures
forensicsiso hashes    # SHA-256 chain, custody manifest, --verify
```

Add `--json` for machine output. `--force` rebuilds fixtures. Evidence fixtures are regenerated
deterministically under `forensicsiso/_fixtures/` and never modified by parsers.

## Architecture

`forensicsiso/fixtures/` builds binary / SQLite / log fixtures that parse like their real-world
counterparts (ext2 superblock+inodes+dir entries, regf hive, PSSCAN memory, valid pcap, real SQLite
Chrome/Firefox history, MIME .eml, mbox). Each parser module (`disk.py`, `memory.py`, `logs.py`,
`pcap.py`, `registry.py`, `browser.py`, `email.py`, `timeline.py`, `correlate.py`, `hashes.py`)
is a pure-stdlib reader that records a custody entry per artifact.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

## Live Lab Test Plan

All steps below run **on your own lab VM / loopback only**. Never run against hosts you
do not own or lack written authorization for.

1. **disk** — capture a small real device (`dd if=/dev/sdX of=case.img bs=4M count=8
   conv=noerror,sync` on YOUR lab disk or a temp loop file), then
   `forensicsiso disk --json`; expect: superblock parsed, MBR/GPT partitions listed,
   directory entries enumerated, deleted-file recovery attempt hashed and verified.
2. **memory** — `forensicsiso memory` against the PSSCAN fixture; on a lab host also run
   `utils/proc_dump` (see `fixtures/memory.py`) to snapshot a process you spawned, then
   verify its exe path appears in `processes[].cmdline`.
3. **logs** — feed the tool real Apache/SSH/syslog captures from your own server;
   compare parsed logon timestamps against `journalctl`/`auth.log` ground truth.
4. **pcap** — `tcpdump -i lo port 53 or port 80 -w lab.pcap` on your lab box while
   resolving a name and fetching a page; run `forensicsiso pcap` and confirm the DNS
   name + HTTP host pair appear in the flow table.
5. **registry** — copy a hive replica fixture into an empty hive container (lab only)
   and confirm Run-key values + SAM user list match what you injected.
6. **browser** — open a URL in your own browser profile, copy the History/places db,
   and confirm the URL+timestamp round-trips.
7. **email** — import lab-generated .eml and mbox, confirm envelope + attachment hashes.
8. **timeline** — merge artifact sets; every event is UTC-sorted and the HTML view renders.
9. **correlate** — plant `alice@example.com` in browser history, an SSH log, and an email;
   expect the person-hash to flag `cross_correlated: true` across ≥3 sources.
10. **hashes** — run `forensicsiso hashes` so every artifact + report is recorded in the
    custody manifest; re-run `--verify` to confirm the chain is untouched.

Expected proof: command + exit code + the JSON report it produced, archived under `_output/`.

## Metrics

Real measurements recorded in `METRICS.md` after each feature lands (tests, demo
timings, parser pass/fail counts, coverage of the hash chain). Tracked: total tests,
module pass rate, demo exit status, fixture hashes, custody manifest validity.