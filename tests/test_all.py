"""Comprehensive test suite for forensicsiso — all modules, real assertions, >=35 tests."""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
FIXTURE_DIR = BASE / "forensicsiso" / "_fixtures"
OUTPUT_DIR = BASE / "forensicsiso" / "_output"
FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

from forensicsiso.hashing import sha256_file, sha256_bytes, sha256_str, hash_json
from forensicsiso.custody import CustodyManifest, verify_manifest
from forensicsiso.fixtures.disk import build_disk_image
from forensicsiso.fixtures.memory import build_memory_fixture, build_proc_dump, kill_marker_proc
from forensicsiso.fixtures.logs import (build_syslog_fixture, build_apache_access_fixture,
                                         build_ssh_auth_fixture, build_windows_event_fixture,
                                         build_usn_journal_fixture)
from forensicsiso.fixtures.pcap import build_pcap_fixture
from forensicsiso.fixtures.registry import build_registry_fixture
from forensicsiso.fixtures.browser import build_chrome_history_fixture, build_firefox_places_fixture
from forensicsiso.fixtures.email import build_eml_fixture, build_mbox_fixture
from forensicsiso.disk import parse_mbr, parse_gpt_header, parse_superblock, parse_directory, parse_inodes, parse_disk
from forensicsiso.memory import parse_psscan_header, parse_process_table, parse_proc_dump, string_scan, parse_memory
from forensicsiso.logs import parse_syslog, parse_apache_access, parse_ssh_auth, parse_windows_events, parse_usn_journal
from forensicsiso.pcap import parse_pcap
from forensicsiso.registry import parse_regf_header, parse_registry
from forensicsiso.browser import parse_chrome_history, parse_firefox_places, build_browser_timeline
from forensicsiso.email import parse_eml, parse_mbox
from forensicsiso.timeline import build_timeline, generate_html_timeline
from forensicsiso.correlate import correlate_user_across_sources, detect_suspicious_behaviors
from forensicsiso.hashes import verify_artifact_hashes


def _fixture(name):
    return str(FIXTURE_DIR / name)


def _output(name):
    return str(OUTPUT_DIR / name)


# ── Hashing tests ──

class TestHashing(unittest.TestCase):
    def test_sha256_bytes(self):
        h = sha256_bytes(b"hello world")
        self.assertEqual(h, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_sha256_str(self):
        h = sha256_str("hello world")
        self.assertEqual(len(h), 64)

    def test_hash_json_deterministic(self):
        a = hash_json({"b": 2, "a": 1})
        b = hash_json({"a": 1, "b": 2})
        self.assertEqual(a, b)

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            path = f.name
        try:
            h = sha256_file(path)
            self.assertEqual(len(h), 64)
        finally:
            os.unlink(path)


# ── Custody tests ──

class TestCustody(unittest.TestCase):
    def test_manifest_roundtrip(self):
        m = CustodyManifest()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"evidence data")
            path = f.name
        try:
            m.add_file(path, "test_file")
            m.add_json_output("test_output", {"result": "ok"})
            out = _output("test_custody.json")
            m.save(out)
            self.assertTrue(os.path.exists(out))
            self.assertTrue(verify_manifest(out))
        finally:
            os.unlink(path)

    def test_manifest_verify_invalid(self):
        out = _output("invalid_custody.json")
        with open(out, "w") as f:
            json.dump({"entries": [], "manifest_hash": "bad"}, f)
        self.assertFalse(verify_manifest(out))


# ── Disk tests ──

class TestDisk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = _fixture("test_disk.img")
        if not os.path.exists(cls.img):
            build_disk_image(cls.img)

    def test_mbr_signature(self):
        with open(self.img, "rb") as f:
            data = f.read(512)
        mbr = parse_mbr(data)
        self.assertEqual(mbr["signature"], "0x55AA")
        self.assertEqual(len(mbr["partitions"]), 1)
        self.assertEqual(mbr["partitions"][0]["type"], "0x83")

    def test_gpt_header(self):
        with open(self.img, "rb") as f:
            f.seek(512)
            data = f.read(512)
        gpt = parse_gpt_header(data)
        self.assertEqual(gpt["signature"], "EFI PART")

    def test_superblock(self):
        with open(self.img, "rb") as f:
            data = f.read()
        sb = parse_superblock(data, 1024)
        self.assertEqual(sb["magic"], "0xEF53")
        self.assertEqual(sb["state"], "clean")

    def test_directory_entries(self):
        with open(self.img, "rb") as f:
            data = f.read()
        dir_data = data[6*1024: 7*1024]
        entries = parse_directory(dir_data)
        names = [e["name"] for e in entries]
        self.assertIn(".", names)
        self.assertIn("hello.txt", names)
        self.assertIn("deleted.txt", names)

    def test_inodes(self):
        with open(self.img, "rb") as f:
            data = f.read()
        inodes = parse_inodes(data, 5*1024, count=4)
        self.assertTrue(len(inodes) >= 3)
        types = {i["type"] for i in inodes}
        self.assertIn("dir", types)
        self.assertIn("file", types)

    def test_deleted_file_recovery(self):
        with open(self.img, "rb") as f:
            data = f.read()
        del_offset = 6*1024 + 2*1024
        recovered = data[del_offset: del_offset + 200]
        recovered_clean = recovered[:recovered.find(b"\x00")]
        self.assertIn(b"deleted but is still recoverable", recovered_clean)

    def test_parse_disk_full(self):
        result = parse_disk(self.img)
        self.assertIn("superblock", result)
        self.assertIn("root_directory", result)
        self.assertIn("recovered_deleted", result)
        self.assertIn("mbr", result)
        self.assertIn("gpt", result)


# ── Memory tests ──

class TestMemory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mem = _fixture("test_memory.bin")
        if not os.path.exists(cls.mem):
            build_memory_fixture(cls.mem)
        cls.proc = _fixture("proc_dump.json")
        if not os.path.exists(cls.proc):
            build_proc_dump(cls.proc)

    @classmethod
    def tearDownClass(cls):
        kill_marker_proc(cls.proc)

    def test_psscan_header(self):
        with open(self.mem, "rb") as f:
            data = f.read(64)
        hdr = parse_psscan_header(data)
        self.assertEqual(hdr["magic"], b"PSSCAN\x01\x02".hex())
        self.assertEqual(hdr["process_count"], 8)
        self.assertIn("FIXTURE", hdr["source"])

    def test_process_table(self):
        with open(self.mem, "rb") as f:
            data = f.read()
        procs = parse_process_table(data)
        self.assertEqual(len(procs), 8)
        names = {p["name"] for p in procs}
        self.assertIn("systemd", names)
        self.assertIn("nginx", names)
        self.assertIn("netcat", names)

    def test_proc_dump(self):
        if os.path.exists(self.proc):
            result = parse_proc_dump(self.proc)
            self.assertIn("pid", result)
            self.assertIn("cmdline", result)
            self.assertIn("exe", result)

    def test_string_scan(self):
        with open(self.mem, "rb") as f:
            data = f.read()
        hits = string_scan(data)
        self.assertTrue(len(hits) > 0)
        patterns = {h["pattern"] for h in hits}
        self.assertIn("IP_ADDRESS", patterns)

    def test_parse_memory_full(self):
        result = parse_memory(self.mem, self.proc)
        self.assertIn("processes", result)
        self.assertIn("header", result)
        self.assertIn("string_hits", result)


# ── Log tests ──

class TestLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.syslog = _fixture("test_syslog.log")
        if not os.path.exists(cls.syslog):
            build_syslog_fixture(cls.syslog)
            build_apache_access_fixture(_fixture("test_apache.log"))
            build_ssh_auth_fixture(_fixture("test_ssh.log"))
            build_windows_event_fixture(_fixture("test_windows.json"))
            build_usn_journal_fixture(_fixture("test_usn.csv"))
        cls.apache = _fixture("test_apache.log")
        cls.ssh = _fixture("test_ssh.log")
        cls.windows = _fixture("test_windows.json")
        cls.usn = _fixture("test_usn.csv")

    def test_syslog_events(self):
        r = parse_syslog(self.syslog)
        self.assertTrue(len(r["events"]) >= 10)
        self.assertTrue(len(r["anomalies"]) >= 3)

    def test_syslog_timestamps(self):
        r = parse_syslog(self.syslog)
        times = [e["time"] for e in r["events"]]
        self.assertIn("10:05:12", times)

    def test_apache_access(self):
        r = parse_apache_access(self.apache)
        self.assertTrue(len(r["entries"]) >= 8)
        self.assertIn("status_summary", r)

    def test_apache_anomalies(self):
        r = parse_apache_access(self.apache)
        types = [a["type"] for a in r["anomalies"]]
        self.assertTrue(any("401" in t or "delete" in t for t in types))

    def test_ssh_auth(self):
        r = parse_ssh_auth(self.ssh)
        self.assertTrue(len(r["events"]) >= 5)
        accepted = [e for e in r["events"] if e.get("action") == "accepted"]
        self.assertTrue(len(accepted) >= 1)

    def test_windows_events(self):
        r = parse_windows_events(self.windows)
        self.assertTrue(len(r["events"]) >= 4)
        types = [a["type"] for a in r["anomalies"]]
        self.assertIn("audit_log_cleared", types)

    def test_usn_journal(self):
        r = parse_usn_journal(self.usn)
        self.assertTrue(len(r["entries"]) >= 5)
        self.assertTrue(any(a["type"] == "file_deleted" for a in r["anomalies"]))


# ── PCAP tests ──

class TestPcap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = _fixture("test_traffic.pcap")
        if not os.path.exists(cls.pcap):
            build_pcap_fixture(cls.pcap)

    def test_parse_pcap(self):
        r = parse_pcap(self.pcap)
        self.assertEqual(r["packets"], 3)
        self.assertTrue(len(r["flows"]) >= 2)

    def test_dns_queries(self):
        r = parse_pcap(self.pcap)
        self.assertTrue(len(r["dns_queries"]) >= 1)
        self.assertEqual(r["dns_queries"][0]["name"], "evil.example.com")

    def test_tcp_sessions(self):
        r = parse_pcap(self.pcap)
        self.assertTrue(len(r["tcp_sessions"]) >= 2)

    def test_http_payloads(self):
        r = parse_pcap(self.pcap)
        self.assertTrue(len(r["http_payloads"]) >= 1)
        self.assertIn("GET /secret", r["http_payloads"][0]["content"])


# ── Registry tests ──

class TestRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hive = _fixture("test_registry.hive")
        if not os.path.exists(cls.hive):
            build_registry_fixture(cls.hive)

    def test_regf_header(self):
        with open(self.hive, "rb") as f:
            data = f.read(4096)
        hdr = parse_regf_header(data)
        self.assertEqual(hdr["magic"], "regf")
        self.assertEqual(hdr["major_version"], 1)

    def test_registry_run_keys(self):
        r = parse_registry(self.hive)
        self.assertTrue(len(r["run_keys"]) >= 1)
        names = [k["name"] for k in r["run_keys"]]
        self.assertIn("Run", names)

    def test_registry_sam_users(self):
        r = parse_registry(self.hive)
        self.assertTrue(len(r["sam_users"]) >= 2)
        names = [u["name"] for u in r["sam_users"]]
        self.assertIn("alice", names)
        self.assertIn("bob", names)

    def test_registry_persistence(self):
        r = parse_registry(self.hive)
        self.assertTrue(len(r["persistence"]) >= 1)
        decoded = [p["decoded"] for p in r["persistence"]]
        self.assertTrue(any("exe" in d.lower() or "cmd" in d.lower() or "rundll" in d.lower() for d in decoded))


# ── Browser tests ──

class TestBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = _fixture("test_chrome_history")
        cls.firefox = _fixture("test_firefox_places")
        if not os.path.exists(cls.chrome):
            build_chrome_history_fixture(cls.chrome)
            build_firefox_places_fixture(cls.firefox)

    def test_chrome_history(self):
        r = parse_chrome_history(self.chrome)
        self.assertTrue(len(r["urls"]) >= 3)
        urls = [u["url"] for u in r["urls"]]
        self.assertTrue(any("alice@example.com" in u for u in urls))

    def test_chrome_downloads(self):
        r = parse_chrome_history(self.chrome)
        self.assertTrue(len(r["downloads"]) >= 1)
        self.assertIn("tool.exe", r["downloads"][0]["path"])

    def test_chrome_emails(self):
        r = parse_chrome_history(self.chrome)
        self.assertIn("alice@example.com", r["emails_found"])

    def test_firefox_places(self):
        r = parse_firefox_places(self.firefox)
        self.assertTrue(len(r["places"]) >= 2)
        self.assertIn("alice@example.com", r["emails_found"])

    def test_browser_timeline(self):
        c = parse_chrome_history(self.chrome)
        ff = parse_firefox_places(self.firefox)
        tl = build_browser_timeline(c, ff)
        self.assertTrue(len(tl) >= 5)


# ── Email tests ──

class TestEmail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eml = _fixture("test_message.eml")
        cls.mbox = _fixture("test_mailbox")
        if not os.path.exists(cls.eml):
            build_eml_fixture(cls.eml)
            build_mbox_fixture(cls.mbox)

    def test_eml_headers(self):
        r = parse_eml(self.eml)
        self.assertEqual(r["headers"]["From"], "alice@example.com")
        self.assertIn("bob@example.com", r["headers"]["To"])

    def test_eml_attachments(self):
        r = parse_eml(self.eml)
        self.assertTrue(len(r["attachments"]) >= 1)
        self.assertEqual(r["attachments"][0]["filename"], "Q3_Report.pdf")

    def test_eml_emails(self):
        r = parse_eml(self.eml)
        self.assertIn("alice@example.com", r["emails_found"])
        self.assertIn("bob@example.com", r["emails_found"])

    def test_mbox(self):
        r = parse_mbox(self.mbox)
        self.assertEqual(r["message_count"], 3)
        self.assertIn("alice@example.com", r["emails_found"])


# ── Timeline tests ──

class TestTimeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyses = []
        from forensicsiso.fixtures.logs import build_syslog_fixture, build_apache_access_fixture, build_ssh_auth_fixture, build_windows_event_fixture, build_usn_journal_fixture
        syslog = _fixture("tl_syslog.log")
        build_syslog_fixture(syslog)
        cls.analyses.append(parse_syslog(syslog))
        ssh = _fixture("tl_ssh.log")
        build_ssh_auth_fixture(ssh)
        cls.analyses.append(parse_ssh_auth(ssh))

    def test_build_timeline(self):
        tl = build_timeline(*self.analyses)
        self.assertTrue(tl["event_count"] > 0)
        self.assertIn("timeline_hash", tl)

    def test_html_timeline(self):
        tl = build_timeline(*self.analyses)
        html_path = _output("test_timeline.html")
        generate_html_timeline(tl, html_path)
        self.assertTrue(os.path.exists(html_path))
        with open(html_path) as f:
            content = f.read()
        self.assertIn("forensicsiso", content)


# ── Correlation tests ──

class TestCorrelate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from forensicsiso.fixtures.logs import build_syslog_fixture, build_ssh_auth_fixture
        from forensicsiso.fixtures.browser import build_chrome_history_fixture, build_firefox_places_fixture
        from forensicsiso.fixtures.email import build_eml_fixture
        syslog = _fixture("corr_syslog.log")
        build_syslog_fixture(syslog)
        ssh = _fixture("corr_ssh.log")
        build_ssh_auth_fixture(ssh)
        chrome = _fixture("corr_chrome")
        build_chrome_history_fixture(chrome)
        eml = _fixture("corr_message.eml")
        build_eml_fixture(eml)
        cls.analyses = [
            parse_syslog(syslog),
            parse_ssh_auth(ssh),
            parse_chrome_history(chrome),
            parse_eml(eml),
        ]

    def test_correlate_alice(self):
        result = correlate_user_across_sources(*self.analyses)
        self.assertTrue(result["unique_users"] > 0)
        alice = [p for p in result["persons"] if p["email"] == "alice@example.com"]
        self.assertTrue(len(alice) == 1)
        self.assertTrue(alice[0]["source_count"] >= 3)
        self.assertTrue(alice[0]["cross_correlated"])

    def test_suspicious_behaviors(self):
        sigs = detect_suspicious_behaviors(*self.analyses)
        self.assertTrue(len(sigs) > 0)
        types = {s["type"] for s in sigs}
        self.assertTrue(len(types) >= 1)


# ── Hash verification tests ──

class TestHashVerification(unittest.TestCase):
    def test_verify_artifact_hashes(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test evidence")
            path = f.name
        try:
            h = sha256_file(path)
            result = verify_artifact_hashes([path], {path: h})
            self.assertTrue(result["all_verified"])
            self.assertEqual(result["results"][0]["match"], True)
        finally:
            os.unlink(path)

    def test_verify_bad_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test evidence")
            path = f.name
        try:
            result = verify_artifact_hashes([path], {path: "bad_hash"})
            self.assertFalse(result["all_verified"])
        finally:
            os.unlink(path)


# ── Fixture integrity tests ──

class TestFixtures(unittest.TestCase):
    def test_disk_fixture_exists(self):
        img = _fixture("test_disk.img")
        if not os.path.exists(img):
            build_disk_image(img)
        self.assertTrue(os.path.exists(img))
        self.assertTrue(os.path.getsize(img) > 0)

    def test_memory_fixture_exists(self):
        mem = _fixture("test_memory.bin")
        if not os.path.exists(mem):
            build_memory_fixture(mem)
        with open(mem, "rb") as f:
            magic = f.read(8)
        self.assertEqual(magic, b"PSSCAN\x01\x02")

    def test_chrome_fixture_is_sqlite(self):
        chrome = _fixture("test_chrome_history")
        if not os.path.exists(chrome):
            build_chrome_history_fixture(chrome)
        db = sqlite3.connect(chrome)
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        db.close()
        self.assertIn("urls", tables)
        self.assertIn("visits", tables)


if __name__ == "__main__":
    unittest.main(verbosity=2)
