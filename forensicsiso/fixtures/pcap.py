"""Build a minimal pcap fixture (pure Python, no scapy dependency).

Creates a valid pcap file with:
  - TCP SYN/FIN handshake between two hosts
  - DNS query/response
  - HTTP GET with payload
"""
from __future__ import annotations

import os
import struct
import time
from datetime import datetime, timezone

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VER_MAJ = 2
PCAP_VER_MIN = 4
LINK_ETHERNET = 1


def _eth(dst: bytes, src: bytes, etype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", etype) + payload


def _ip(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    hdr = bytearray(20)
    hdr[0] = 0x45  # ver + ihl
    total = 20 + len(payload)
    struct.pack_into("!H", hdr, 2, total)
    hdr[6] = 0x40  # flags: don't fragment
    struct.pack_into("!H", hdr, 8, 64)
    hdr[9] = proto
    hdr[12:16] = src
    hdr[16:20] = dst
    return bytes(hdr) + payload


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    hdr = bytearray(20)
    struct.pack_into("!H", hdr, 0, sport)
    struct.pack_into("!H", hdr, 2, dport)
    struct.pack_into("!I", hdr, 4, seq)
    struct.pack_into("!I", hdr, 8, ack)
    hdr[12] = 0x50  # data offset
    hdr[13] = flags
    struct.pack_into("!H", hdr, 14, 65535)  # window
    hdr[16:18] = b"\x00\x00"  # checksum placeholder
    hdr[18:20] = b"\x00\x00"  # urgent
    return bytes(hdr) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    hdr = bytearray(8)
    struct.pack_into("!H", hdr, 0, sport)
    struct.pack_into("!H", hdr, 2, dport)
    length = 8 + len(payload)
    struct.pack_into("!H", hdr, 4, length)
    return bytes(hdr) + payload


def _dns_query(name: str, qtype: int = 1) -> bytes:
    qid = struct.pack("!H", 0x1234)
    flags = struct.pack("!H", 0x0100)  # standard query
    counts = struct.pack("!HHHH", 0, 1, 0, 0)  # qd=1, an=0, ns=0, ar=0
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    q = struct.pack("!HH", qtype, 1)  # type A, class IN
    return qid + flags + counts + qname + q


def _dns_response(name: str, ip: bytes) -> bytes:
    qid = struct.pack("!H", 0x1234)
    flags = struct.pack("!H", 0x8180)  # response, no error
    counts = struct.pack("!HHHH", 0, 1, 1, 0)  # qd=1, an=1, ns=0, ar=0
    qname = b""
    for label in name.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    q = struct.pack("!HH", 1, 1)  # type A, class IN
    # Answer: pointer to offset 12, type A, class IN, TTL 300, len 4
    a = struct.pack("!HHIH", 0xC00C, 1, 1, 300) + struct.pack("!H", 4) + ip
    return qid + flags + counts + qname + q + a


def build_pcap_fixture(dest: str) -> str:
    """
    Build a 3-packet pcap:
      1. TCP SYN from 192.168.1.10:44832 → 10.0.0.1:80
      2. DNS query for evil.example.com from 192.168.1.10
      3. HTTP GET from 192.168.1.10:44832 → 10.0.0.1:80
    """
    src_ip = bytes([192, 168, 1, 10])
    dst_ip = bytes([10, 0, 0, 1])
    dns_ip = bytes([10, 0, 0, 53])
    eth_dst = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    eth_src = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])

    ts_base = int(time.time())

    # Packet 1: TCP SYN
    tcp_syn = _tcp(44832, 80, 1000, 0, 0x02)  # SYN
    ip1 = _ip(src_ip, dst_ip, 6, tcp_syn)
    eth1 = _eth(eth_dst, eth_src, 0x0800, ip1)

    # Packet 2: DNS query for evil.example.com
    dns_q = _dns_query("evil.example.com")
    udp2 = _udp(44832, 53, dns_q)
    ip2 = _ip(src_ip, dns_ip, 17, udp2)
    eth2 = _eth(eth_dst, eth_src, 0x0800, ip2)

    # Packet 3: HTTP GET with payload
    http_payload = b"GET /secret HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: forensiso/1.0\r\n\r\n"
    tcp3 = _tcp(44832, 80, 1000, 1, 0x18, http_payload)  # PSH+ACK
    ip3 = _ip(src_ip, dst_ip, 6, tcp3)
    eth3 = _eth(eth_dst, eth_src, 0x0800, ip3)

    packets = [
        (ts_base, eth1),
        (ts_base + 1, eth2),
        (ts_base + 2, eth3),
    ]

    with open(dest, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, PCAP_VER_MAJ, PCAP_VER_MIN, 0, 0, 65535, LINK_ETHERNET))
        for ts, pkt in packets:
            f.write(struct.pack("<IIII", ts, 0, len(pkt), len(pkt)))
            f.write(pkt)

    return dest
