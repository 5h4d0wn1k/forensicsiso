"""PCAP parser — flow extraction, host pairs, protocols, DNS, TCP sessions, payload strings."""
from __future__ import annotations

import os
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file
from forensicsiso.custody import CustodyManifest

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


def parse_pcap(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Parse a pcap file and extract flows, DNS, TCP sessions."""
    if custody:
        custody.add_file(path, "pcap")

    with open(path, "rb") as f:
        global_hdr = f.read(24)
    magic = struct.unpack_from("<I", global_hdr, 0)[0]
    big_endian = False
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
        big_endian = True
    else:
        return {"error": f"unknown pcap magic: 0x{magic:08X}"}

    with open(path, "rb") as f:
        global_hdr = f.read(24)
        link_type = struct.unpack_from(f"{endian}I", global_hdr, 20)[0]

        flows = []
        dns_queries = []
        tcp_sessions = []
        payload_strings = []
        packet_count = 0

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            packet_count += 1
            timestamp = datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()

            if link_type != 1 or len(pkt_data) < 14:
                continue

            # Ethernet
            eth_type = struct.unpack_from("!H", pkt_data, 12)[0]
            if eth_type == 0x0800:  # IPv4
                ip_data = pkt_data[14:]
                if len(ip_data) < 20:
                    continue
                ip_hdr_len = (ip_data[0] & 0x0F) * 4
                protocol = ip_data[9]
                src_ip = ".".join(str(b) for b in ip_data[12:16])
                dst_ip = ".".join(str(b) for b in ip_data[16:20])
                total_len = struct.unpack_from("!H", ip_data, 2)[0]
                transport = ip_data[ip_hdr_len:] if ip_hdr_len < len(ip_data) else b""

                if protocol == 6 and len(transport) >= 20:  # TCP
                    sport = struct.unpack_from("!H", transport, 0)[0]
                    dport = struct.unpack_from("!H", transport, 2)[0]
                    tcp_hdr_len = ((transport[12] >> 4) & 0x0F) * 4
                    payload = transport[tcp_hdr_len:] if tcp_hdr_len < len(transport) else b""

                    flows.append({
                        "type": "tcp",
                        "src": f"{src_ip}:{sport}",
                        "dst": f"{dst_ip}:{dport}",
                        "timestamp": timestamp,
                        "payload_len": len(payload),
                    })

                    if dport == 80 or sport == 80:
                        if payload[:3] == b"GET" or payload[:4] == b"POST":
                            try:
                                payload_strings.append({
                                    "type": "http",
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "content": payload[:512].decode(errors="replace"),
                                    "timestamp": timestamp,
                                })
                            except Exception:
                                pass

                    tcp_sessions.append({
                        "src": f"{src_ip}:{sport}",
                        "dst": f"{dst_ip}:{dport}",
                        "timestamp": timestamp,
                        "payload_len": len(payload),
                        "flags": f"0x{transport[13]:02X}" if len(transport) > 13 else "unknown",
                    })

                elif protocol == 17 and len(transport) >= 8:  # UDP
                    sport = struct.unpack_from("!H", transport, 0)[0]
                    dport = struct.unpack_from("!H", transport, 2)[0]
                    udp_payload = transport[8:]

                    flows.append({
                        "type": "udp",
                        "src": f"{src_ip}:{sport}",
                        "dst": f"{dst_ip}:{dport}",
                        "timestamp": timestamp,
                        "payload_len": len(udp_payload),
                    })

                    if dport == 53 or sport == 53:  # DNS
                        dns = _parse_dns(udp_payload)
                        if dns:
                            dns["timestamp"] = timestamp
                            dns_queries.append(dns)

    result = {
        "file": os.path.abspath(path),
        "sha256": sha256_file(path),
        "packets": packet_count,
        "flows": flows,
        "dns_queries": dns_queries,
        "tcp_sessions": tcp_sessions,
        "http_payloads": payload_strings,
        "summary": {
            "total_flows": len(flows),
            "total_dns": len(dns_queries),
            "total_tcp": len(tcp_sessions),
            "total_http": len(payload_strings),
        },
    }
    if custody:
        result["custody_hash"] = custody.add_json_output("pcap_analysis", result)
    return result


def _parse_dns(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a DNS packet payload."""
    if len(data) < 12:
        return None
    qid, flags, qdcount, ancount = struct.unpack_from("!HHHH", data, 0)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    qname, offset = _dns_name(data, 12)
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    result: Dict[str, Any] = {
        "type": "response" if qr else "query",
        "name": qname,
        "qtype": {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}.get(qtype, str(qtype)),
    }
    if qr and ancount > 0:
        answers = []
        off = offset + 4
        for _ in range(ancount):
            if off + 12 > len(data):
                break
            rtype = struct.unpack_from("!H", data, off + 2)[0]
            rdlen = struct.unpack_from("!H", data, off + 10)[0]
            rdata = data[off + 12: off + 12 + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append({"type": "A", "ip": ".".join(str(b) for b in rdata)})
            off += 12 + rdlen
        result["answers"] = answers
    return result


def _dns_name(data: bytes, offset: int):
    """Parse a DNS name, returning (name_str, new_offset)."""
    parts = []
    jumped = False
    start = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                start = offset + 2
            offset = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            break
        parts.append(data[offset: offset + length].decode(errors="replace"))
        offset += length
    return ".".join(parts), start if jumped else offset
