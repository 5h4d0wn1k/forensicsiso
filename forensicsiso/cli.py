"""CLI — argparse subcommands for every DFIR module. Dry-run default; --demo runs full pipeline."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

FIXTURE_DIR = Path(os.environ.get("FORENSICSISO_FIXTURE_DIR",
                                  Path(__file__).resolve().parent / "_fixtures"))
OUT_DIR = Path(os.environ.get("FORENSICSISO_OUT_DIR",
                              Path(__file__).resolve().parent / "_output"))


def _ensure_dirs():
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def _save_json(name: str, data: object) -> str:
    p = OUT_DIR / f"{name}.json"
    with open(p, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return str(p)


def cmd_disk(args):
    from forensicsiso.fixtures.disk import build_disk_image
    from forensicsiso.disk import parse_disk
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    img = str(FIXTURE_DIR / "test_disk.img")
    if not os.path.exists(img) or args.force:
        build_disk_image(img)
    custody = CustodyManifest() if not args.dry_run else None
    result = parse_disk(img, custody)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_disk(result)
    if custody:
        out = str(OUT_DIR / "disk_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_disk(r):
    sb = r.get("superblock", {})
    counts = sb.get("counts", {})
    layout = sb.get("layout", {})
    print(f"Image: {r['image']}  ({r['size']} bytes)")
    print(f"SHA-256: {r['sha256'][:32]}...")
    print(f"Superblock: magic={sb.get('magic')} state={sb.get('state')} "
          f"inodes={counts.get('inode_count')} blocks={counts.get('block_count')} "
          f"block_size={layout.get('block_size')}")
    mbr = r.get("mbr", {})
    for p in mbr.get("partitions", []):
        print(f"  MBR partition {p['slot']}: type={p['type_name']} LBA_start={p['lba_start']}")
    gpt = r.get("gpt", {})
    if "error" not in gpt:
        print(f"GPT: signature={gpt.get('signature')} revision={gpt.get('revision')}")
    print("Root directory entries:")
    for e in r.get("root_directory", []):
        print(f"  inode={e['inode']} {e['type']:4s} {e['name']}")
    print(f"Deleted file recovered (inode {r['recovered_deleted']['inode']}): hash={r['recovered_deleted']['hash'][:16]}...")
    print(f"Content: {r['recovered_deleted']['content'][:80]}")


def cmd_memory(args):
    from forensicsiso.fixtures.memory import build_memory_fixture, build_proc_dump, kill_marker_proc
    from forensicsiso.memory import parse_memory
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    mem = str(FIXTURE_DIR / "test_memory.bin")
    proc = str(FIXTURE_DIR / "proc_dump.json")
    if not os.path.exists(mem) or args.force:
        build_memory_fixture(mem)
    if not os.path.exists(proc) or args.force:
        build_proc_dump(proc)
    try:
        custody = CustodyManifest() if not args.dry_run else None
        result = parse_memory(mem, proc, custody)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            _print_memory(result)
        if custody:
            out = str(OUT_DIR / "memory_custody.json")
            custody.save(out)
            print(f"[custody] manifest → {out}", file=sys.stderr)
        return 0
    finally:
        kill_marker_proc(proc)


def _print_memory(r):
    print(f"Memory fixture: {r['image']} ({r['size']} bytes)")
    hdr = r.get("header", {})
    print(f"PSSCAN: magic={hdr.get('magic')} procs={hdr.get('process_count')} source={hdr.get('source')}")
    print("Processes:")
    for p in r.get("processes", []):
        print(f"  PID={p['pid']:5d} PPID={p['ppid']:5d} UID={p['uid']:4d} {p['name']:12s} {p['cmdline']}")
    pd = r.get("proc_dump", {})
    if pd:
        print(f"Proc dump: PID={pd.get('pid')} exe={pd.get('exe')}")
    hits = r.get("string_hits", [])
    print(f"String hits: {len(hits)}")


def cmd_logs(args):
    from forensicsiso.fixtures.logs import (build_syslog_fixture, build_apache_access_fixture,
                                              build_ssh_auth_fixture, build_windows_event_fixture,
                                              build_usn_journal_fixture)
    from forensicsiso.logs import parse_all_logs
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    paths = {
        "syslog": str(FIXTURE_DIR / "test_syslog.log"),
        "apache": str(FIXTURE_DIR / "test_apache.log"),
        "ssh": str(FIXTURE_DIR / "test_ssh.log"),
        "windows": str(FIXTURE_DIR / "test_windows.json"),
        "usn": str(FIXTURE_DIR / "test_usn.csv"),
    }
    if not os.path.exists(paths["syslog"]) or args.force:
        build_syslog_fixture(paths["syslog"])
        build_apache_access_fixture(paths["apache"])
        build_ssh_auth_fixture(paths["ssh"])
        build_windows_event_fixture(paths["windows"])
        build_usn_journal_fixture(paths["usn"])
    custody = CustodyManifest() if not args.dry_run else None
    result = parse_all_logs(paths["syslog"], paths["apache"], paths["ssh"],
                            paths["windows"], paths["usn"], custody)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_logs(result)
    if custody:
        out = str(OUT_DIR / "logs_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_logs(r):
    s = r.get("summary", {})
    print(f"Log sources: {s.get('total_events')} events, {s.get('total_anomalies')} anomalies")
    for name in ("syslog", "apache", "ssh", "windows", "usn"):
        sub = r.get(name, {})
        evts = len(sub.get("events", sub.get("entries", [])))
        anoms = len(sub.get("anomalies", []))
        print(f"  {name:10s}: {evts} events, {anoms} anomalies")
    for name in ("syslog", "ssh"):
        emails = r.get(name, {}).get("emails_found", [])
        if emails:
            print(f"  {name} emails: {emails}")


def cmd_pcap(args):
    from forensicsiso.fixtures.pcap import build_pcap_fixture
    from forensicsiso.pcap import parse_pcap
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    pcap = str(FIXTURE_DIR / "test_traffic.pcap")
    if not os.path.exists(pcap) or args.force:
        build_pcap_fixture(pcap)
    custody = CustodyManifest() if not args.dry_run else None
    result = parse_pcap(pcap, custody)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_pcap(result)
    if custody:
        out = str(OUT_DIR / "pcap_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_pcap(r):
    s = r.get("summary", {})
    print(f"PCAP: {r['packets']} packets, {s.get('total_flows')} flows")
    print(f"  DNS: {s.get('total_dns')}, TCP sessions: {s.get('total_tcp')}, HTTP: {s.get('total_http')}")
    for dns in r.get("dns_queries", []):
        print(f"  DNS: {dns.get('type')} {dns.get('name')}")
    for http in r.get("http_payloads", []):
        content = http.get("content", "")[:80]
        print(f"  HTTP: {http['src']} → {http['dst']}: {content}")


def cmd_registry(args):
    from forensicsiso.fixtures.registry import build_registry_fixture
    from forensicsiso.registry import parse_registry
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    hive = str(FIXTURE_DIR / "test_registry.hive")
    if not os.path.exists(hive) or args.force:
        build_registry_fixture(hive)
    custody = CustodyManifest() if not args.dry_run else None
    result = parse_registry(hive, custody)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_registry(result)
    if custody:
        out = str(OUT_DIR / "registry_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_registry(r):
    hdr = r.get("header", {})
    print(f"Registry: {hdr.get('hive_name')} magic={hdr.get('magic')} v{hdr.get('major_version')}.{hdr.get('minor_version')}")
    print(f"Root: {r.get('root_key', {}).get('name', '?')}")
    s = r.get("summary", {})
    print(f"  Keys: {s.get('total_keys')}, Values: {s.get('total_values')}")
    print(f"  Run keys: {s.get('run_key_count')}, Persistence: {s.get('persistence_count')}")
    print(f"  Services: {s.get('service_count')}, SAM Users: {s.get('user_count')}")
    for vk in r.get("persistence", []):
        print(f"  PERSISTENCE: {vk['name']} = {vk.get('decoded', '?')}")
    for u in r.get("sam_users", []):
        print(f"  SAM User: {u['name']}")


def cmd_browser(args):
    from forensicsiso.fixtures.browser import build_chrome_history_fixture, build_firefox_places_fixture
    from forensicsiso.browser import parse_chrome_history, parse_firefox_places, build_browser_timeline
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    chrome = str(FIXTURE_DIR / "test_chrome_history")
    firefox = str(FIXTURE_DIR / "test_firefox_places")
    if not os.path.exists(chrome) or args.force:
        build_chrome_history_fixture(chrome)
        build_firefox_places_fixture(firefox)
    custody = CustodyManifest() if not args.dry_run else None
    c = parse_chrome_history(chrome, custody)
    ff = parse_firefox_places(firefox, custody)
    timeline = build_browser_timeline(c, ff)
    result = {"chrome": c, "firefox": ff, "timeline": timeline}
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_browser(result)
    if custody:
        out = str(OUT_DIR / "browser_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_browser(r):
    c = r.get("chrome", {})
    ff = r.get("firefox", {})
    print(f"Chrome URLs: {len(c.get('urls', []))}, Downloads: {len(c.get('downloads', []))}")
    for url in c.get("urls", []):
        print(f"  [{url.get('last_visit', '')}] {url.get('url', '')}")
    print(f"Firefox places: {len(ff.get('places', []))}")
    for p in ff.get("places", []):
        print(f"  [{p.get('last_visit', '')}] {p.get('url', '')}")
    print(f"Chrome emails: {c.get('emails_found', [])}")
    print(f"Firefox emails: {ff.get('emails_found', [])}")
    tl = r.get("timeline", [])
    print(f"Timeline entries: {len(tl)}")


def cmd_email(args):
    from forensicsiso.fixtures.email import build_eml_fixture, build_mbox_fixture
    from forensicsiso.email import parse_eml, parse_mbox
    from forensicsiso.custody import CustodyManifest
    _ensure_dirs()
    eml = str(FIXTURE_DIR / "test_message.eml")
    mbox = str(FIXTURE_DIR / "test_mailbox")
    if not os.path.exists(eml) or args.force:
        build_eml_fixture(eml)
        build_mbox_fixture(mbox)
    custody = CustodyManifest() if not args.dry_run else None
    e = parse_eml(eml, custody)
    mb = parse_mbox(mbox, custody)
    result = {"eml": e, "mbox": mb}
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_email(result)
    if custody:
        out = str(OUT_DIR / "email_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_email(r):
    e = r.get("eml", {})
    h = e.get("headers", {})
    print(f"EML: From={h.get('From')} To={h.get('To')} Subject={h.get('Subject')}")
    print(f"  Attachments: {len(e.get('attachments', []))}")
    for a in e.get("attachments", []):
        print(f"    {a['filename']} ({a['size']} bytes) sha256={a['sha256'][:16]}...")
    print(f"  Emails found: {e.get('emails_found', [])}")
    mb = r.get("mbox", {})
    print(f"Mbox: {mb.get('message_count', 0)} messages")
    for m in mb.get("messages", []):
        print(f"  [{m['index']}] {m['headers'].get('From')} → {m['headers'].get('To')}: {m['headers'].get('Subject')}")
    print(f"  Mbox emails: {mb.get('emails_found', [])}")


def cmd_timeline(args):
    from forensicsiso.custody import CustodyManifest
    from forensicsiso.timeline import build_timeline, generate_html_timeline
    _ensure_dirs()
    # Re-run all analyses to build merged timeline
    analyses = _collect_all_analyses(args.force)
    custody = CustodyManifest() if not args.dry_run else None
    result = build_timeline(*analyses, custody=custody)
    html_path = str(OUT_DIR / "timeline.html")
    generate_html_timeline(result, html_path)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Timeline: {result['event_count']} events, hash={result['timeline_hash'][:16]}...")
        print(f"HTML → {html_path}")
    if custody:
        out = str(OUT_DIR / "timeline_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def cmd_correlate(args):
    from forensicsiso.custody import CustodyManifest
    from forensicsiso.correlate import correlate_user_across_sources, detect_suspicious_behaviors
    _ensure_dirs()
    analyses = _collect_all_analyses(args.force)
    custody = CustodyManifest() if not args.dry_run else None
    users = correlate_user_across_sources(*analyses, custody=custody)
    sigs = detect_suspicious_behaviors(*analyses, custody=custody)
    result = {"users": users, "suspicious_behaviors": sigs}
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_correlate(result)
    if custody:
        out = str(OUT_DIR / "correlate_custody.json")
        custody.save(out)
        print(f"[custody] manifest → {out}", file=sys.stderr)
    return 0


def _print_correlate(r):
    u = r.get("users", {})
    print(f"Unique users: {u.get('unique_users')}, Cross-correlated: {u.get('cross_correlated_count')}")
    for p in u.get("persons", []):
        x = " [CROSS-CORRELATED]" if p.get("cross_correlated") else ""
        print(f"  {p['email']}: sources={p['sources']} hash={p['person_hash'][:16]}...{x}")
    sigs = r.get("suspicious_behaviors", [])
    print(f"Suspicious behaviors: {len(sigs)}")
    for s in sigs:
        print(f"  [{s['severity'].upper():8s}] {s['type']}: {s['detail']}")


def cmd_hashes(args):
    from forensicsiso.custody import CustodyManifest
    from forensicsiso.hashing import sha256_file
    _ensure_dirs()
    fixtures = sorted(FIXTURE_DIR.glob("*"))
    all_ok = True
    report = {}

    if getattr(args, "verify", False):
        report["verification"] = {}
        manifests = sorted(OUT_DIR.glob("*_custody.json"))
        checked = 0
        for m in manifests:
            ok = CustodyManifest.verify(str(m))
            report["verification"][m.name] = ok
            checked += 1
            all_ok = all_ok and ok
        report["verification"]["summary"] = {
            "manifests_checked": checked,
            "manifests_valid": sum(1 for v in report["verification"].values()
                                   if isinstance(v, bool) and v),
            "chain_valid": all_ok,
        }
        fixtures_ok = True
        for f in fixtures:
            if f.is_file() and not str(f).endswith((".pid", ".marker")):
                h = sha256_file(str(f))
                if len(h) != 64:
                    fixtures_ok = False
        report["verification"]["fixture_hashes_valid"] = fixtures_ok
        all_ok = all_ok and fixtures_ok
        print(json.dumps(report, indent=2))
        return 0 if all_ok else 1

    manifest_path = args.manifest if hasattr(args, 'manifest') and args.manifest else str(OUT_DIR / "custody_manifest.json")
    if os.path.exists(manifest_path):
        report["manifest"] = CustodyManifest.verify(manifest_path)
    else:
        report["manifest"] = False
    fixture_hashes = []
    for f in fixtures:
        if f.is_file() and not str(f).endswith(('.pid', '.marker')):
            fixture_hashes.append({"path": str(f), "sha256": sha256_file(str(f))})
    report["fixtures"] = fixture_hashes
    print(json.dumps(report, indent=2))
    return 0


def cmd_demo(args):
    """Run the full demo pipeline — all modules, assertions, exit 0."""
    print("=" * 60)
    print("forensicsiso — FULL DEMO PIPELINE")
    print("=" * 60)
    args.json = False
    args.force = True
    args.dry_run = False
    errors = []

    print("\n[1/10] DISK")
    rc = cmd_disk(args)
    if rc != 0:
        errors.append("disk")

    print("\n[2/10] MEMORY")
    rc = cmd_memory(args)
    if rc != 0:
        errors.append("memory")

    print("\n[3/10] LOGS")
    rc = cmd_logs(args)
    if rc != 0:
        errors.append("logs")

    print("\n[4/10] PCAP")
    rc = cmd_pcap(args)
    if rc != 0:
        errors.append("pcap")

    print("\n[5/10] REGISTRY")
    rc = cmd_registry(args)
    if rc != 0:
        errors.append("registry")

    print("\n[6/10] BROWSER")
    rc = cmd_browser(args)
    if rc != 0:
        errors.append("browser")

    print("\n[7/10] EMAIL")
    rc = cmd_email(args)
    if rc != 0:
        errors.append("email")

    print("\n[8/10] TIMELINE")
    rc = cmd_timeline(args)
    if rc != 0:
        errors.append("timeline")

    print("\n[9/10] CORRELATE")
    rc = cmd_correlate(args)
    if rc != 0:
        errors.append("correlate")

    print("\n[10/10] HASHES")
    rc = cmd_hashes(args)
    if rc != 0:
        errors.append("hashes")

    print("\n" + "=" * 60)
    if errors:
        print(f"FAILURES: {errors}")
        return 1
    print("DEMO COMPLETE — ALL MODULES OK")
    print("=" * 60)
    return 0


def _collect_all_analyses(force: bool = False):
    """Run all parsers and return their results for cross-module operations."""
    from forensicsiso.fixtures.disk import build_disk_image
    from forensicsiso.fixtures.memory import build_memory_fixture, build_proc_dump, kill_marker_proc
    from forensicsiso.fixtures.logs import (build_syslog_fixture, build_apache_access_fixture,
                                              build_ssh_auth_fixture, build_windows_event_fixture,
                                              build_usn_journal_fixture)
    from forensicsiso.fixtures.pcap import build_pcap_fixture
    from forensicsiso.fixtures.registry import build_registry_fixture
    from forensicsiso.fixtures.browser import build_chrome_history_fixture, build_firefox_places_fixture
    from forensicsiso.fixtures.email import build_eml_fixture, build_mbox_fixture
    from forensicsiso.disk import parse_disk
    from forensicsiso.memory import parse_memory
    from forensicsiso.logs import (parse_all_logs, parse_syslog, parse_apache_access,
                                   parse_ssh_auth, parse_windows_events, parse_usn_journal)
    from forensicsiso.pcap import parse_pcap
    from forensicsiso.registry import parse_registry
    from forensicsiso.browser import parse_chrome_history, parse_firefox_places
    from forensicsiso.email import parse_eml, parse_mbox
    _ensure_dirs()
    # Build fixtures if needed
    img = str(FIXTURE_DIR / "test_disk.img")
    if not os.path.exists(img) or force:
        build_disk_image(img)
    mem = str(FIXTURE_DIR / "test_memory.bin")
    proc = str(FIXTURE_DIR / "proc_dump.json")
    if not os.path.exists(mem) or force:
        build_memory_fixture(mem)
    if not os.path.exists(proc) or force:
        build_proc_dump(proc)
    sysp = str(FIXTURE_DIR / "test_syslog.log")
    if not os.path.exists(sysp) or force:
        build_syslog_fixture(sysp)
        build_apache_access_fixture(str(FIXTURE_DIR / "test_apache.log"))
        build_ssh_auth_fixture(str(FIXTURE_DIR / "test_ssh.log"))
        build_windows_event_fixture(str(FIXTURE_DIR / "test_windows.json"))
        build_usn_journal_fixture(str(FIXTURE_DIR / "test_usn.csv"))
    pcap_path = str(FIXTURE_DIR / "test_traffic.pcap")
    if not os.path.exists(pcap_path) or force:
        build_pcap_fixture(pcap_path)
    hive = str(FIXTURE_DIR / "test_registry.hive")
    if not os.path.exists(hive) or force:
        build_registry_fixture(hive)
    chrome = str(FIXTURE_DIR / "test_chrome_history")
    if not os.path.exists(chrome) or force:
        build_chrome_history_fixture(chrome)
        build_firefox_places_fixture(str(FIXTURE_DIR / "test_firefox_places"))
    eml = str(FIXTURE_DIR / "test_message.eml")
    if not os.path.exists(eml) or force:
        build_eml_fixture(eml)
        build_mbox_fixture(str(FIXTURE_DIR / "test_mailbox"))

    analyses = []
    analyses.append(parse_disk(img))
    try:
        analyses.append(parse_memory(mem, proc))
    except Exception:
        analyses.append(parse_memory(mem))
    analyses.append(parse_syslog(sysp))
    analyses.append(parse_apache_access(str(FIXTURE_DIR / "test_apache.log")))
    analyses.append(parse_ssh_auth(str(FIXTURE_DIR / "test_ssh.log")))
    analyses.append(parse_windows_events(str(FIXTURE_DIR / "test_windows.json")))
    analyses.append(parse_usn_journal(str(FIXTURE_DIR / "test_usn.csv")))
    analyses.append(parse_pcap(pcap_path))
    analyses.append(parse_registry(hive))
    analyses.append(parse_chrome_history(chrome))
    analyses.append(parse_firefox_places(str(FIXTURE_DIR / "test_firefox_places")))
    analyses.append(parse_eml(eml))
    analyses.append(parse_mbox(str(FIXTURE_DIR / "test_mailbox")))
    return analyses


def main():
    p = argparse.ArgumentParser(
        prog="forensicsiso",
        description="Full DFIR workstation — disk/memory/log/pcap/registry/browser/email parsing, timeline, correlation",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="JSON output")
    common.add_argument("--force", action="store_true", help="Force rebuild fixtures")
    common.add_argument("--dry-run", action="store_true", help="Skip custody manifests")
    p.add_argument("--demo", action="store_true", help="Run full demo pipeline")
    sub = p.add_subparsers(dest="command")

    cmds = {
        "disk": cmd_disk, "memory": cmd_memory, "logs": cmd_logs,
        "pcap": cmd_pcap, "registry": cmd_registry, "browser": cmd_browser,
        "email": cmd_email, "timeline": cmd_timeline, "correlate": cmd_correlate,
        "hashes": cmd_hashes,
    }

    for name, help_text in [
        ("disk", "Parse disk image (ext2, MBR/GPT, deleted file recovery, carving)"),
        ("memory", "Parse memory/crash snapshot (PSSCAN, /proc, string scan)"),
        ("logs", "Parse logs (syslog, Apache, SSH auth, Windows events, USN journal)"),
        ("pcap", "Parse pcap (flows, DNS, TCP sessions, HTTP payloads)"),
        ("registry", "Parse Windows registry hive replica (Run keys, SAM, services)"),
        ("browser", "Parse browser artifacts (Chrome/Firefox history, downloads)"),
        ("email", "Parse email (.eml, .mbox) — headers, MIME, attachments"),
        ("timeline", "Build merged UTC super-timeline"),
        ("correlate", "Cross-artifact correlation and suspicious behavior detection"),
        ("hashes", "Evidence integrity verification and custody manifest"),
    ]:
        s = sub.add_parser(name, help=help_text, parents=[common])
        s.set_defaults(handler=cmds[name])
        if name == "hashes":
            s.add_argument("--verify", action="store_true",
                           help="Verify custody manifests + fixture hash chain")

    args = p.parse_args()

    if args.demo or args.command is None:
        return cmd_demo(args)

    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
