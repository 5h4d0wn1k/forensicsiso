"""Windows Registry hive replica parser — header, root keys, key/value extraction, persistence artifacts."""
from __future__ import annotations

import os
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from forensicsiso.hashing import sha256_file
from forensicsiso.custody import CustodyManifest


def parse_regf_header(data: bytes) -> Dict[str, Any]:
    """Parse the regf header of a registry hive."""
    if len(data) < 4096:
        return {"error": "insufficient data"}
    magic = data[0:4]
    if magic != b"regf":
        return {"error": f"bad magic: {magic!r}"}
    major = struct.unpack_from("<I", data, 4)[0]
    minor = struct.unpack_from("<I", data, 8)[0]
    mtime = struct.unpack_from("<Q", data, 16)[0]
    data_size = struct.unpack_from("<I", data, 24)[0]
    root_offset = struct.unpack_from("<I", data, 28)[0]
    return {
        "magic": "regf",
        "major_version": major,
        "minor_version": minor,
        "data_size": data_size,
        "root_offset": root_offset,
        "hive_name": data[40:48].rstrip(b"\x00").decode(errors="replace"),
    }


def _parse_nk(data: bytes, offset: int) -> Optional[Dict[str, Any]]:
    """Parse an nk (named key) cell."""
    if offset + 76 > len(data):
        return None
    sig = data[offset: offset + 2]
    if sig != b"nk":
        return None
    flags = struct.unpack_from("<H", data, offset + 2)[0]
    parent_offset = struct.unpack_from("<I", data, offset + 16)[0]
    subkey_count = struct.unpack_from("<i", data, offset + 20)[0]
    name_len = struct.unpack_from("<H", data, offset + 60)[0]
    name = data[offset + 68: offset + 68 + name_len].decode(errors="replace")
    return {
        "signature": "nk",
        "name": name,
        "name_len": name_len,
        "flags": f"0x{flags:04X}",
        "is_volatile": bool(flags & 0x0001),
        "is_link": bool(flags & 0x0010),
        "subkey_count": subkey_count,
        "parent_offset": parent_offset,
        "offset": offset,
    }


def _parse_vk(data: bytes, offset: int) -> Optional[Dict[str, Any]]:
    """Parse a vk (value key) cell."""
    if offset + 20 > len(data):
        return None
    sig = data[offset: offset + 2]
    if sig != b"vk":
        return None
    name_len = struct.unpack_from("<H", data, offset + 2)[0]
    data_len = struct.unpack_from("<I", data, offset + 4)[0]
    data_offset = struct.unpack_from("<I", data, offset + 8)[0]
    data_type = struct.unpack_from("<I", data, offset + 12)[0]
    inline = bool(data_offset & 0x80000000)
    actual_data_len = data_offset & 0x7FFFFFFF if inline else data_len

    name = data[offset + 20: offset + 20 + name_len].decode(errors="replace") if name_len > 0 else "(Default)"
    type_names = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
                  4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ"}

    value_data = b""
    # Inline data follows the name in the cell
    if inline:
        start = offset + 20 + name_len
        value_data = data[start: start + actual_data_len]
    elif 0 < data_len <= 65536 and data_offset < len(data):
        value_data = data[data_offset: data_offset + data_len]

    decoded = ""
    if data_type in (1, 2) and value_data:
        decoded = value_data.rstrip(b"\x00").decode(errors="replace")
    elif data_type == 4 and len(value_data) == 4:
        decoded = str(struct.unpack("<I", value_data)[0])
    elif data_type == 3:
        decoded = value_data.hex()

    return {
        "name": name,
        "type": type_names.get(data_type, f"unknown({data_type})"),
        "data_length": data_len,
        "decoded": decoded,
        "offset": offset,
    }


def parse_registry(path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Full registry hive analysis."""
    if custody:
        custody.add_file(path, "registry_hive")

    with open(path, "rb") as f:
        data = f.read()

    result: Dict[str, Any] = {
        "file": os.path.abspath(path),
        "size": len(data),
        "sha256": sha256_file(path),
    }

    # regf header
    result["header"] = parse_regf_header(data)

    # Parse all nk and vk cells
    root_offset = result["header"].get("root_offset", 0x1000)
    root = _parse_nk(data, root_offset)
    result["root_key"] = root

    # Walk cells from the root offset using the cell layout
    keys = []
    values = []
    services = []
    users = []
    run_keys = []
    persistence = []

    pos = root_offset
    guard = 0
    while pos < len(data) - 2 and guard < 2000:
        guard += 1
        sig = data[pos: pos + 2]
        if sig == b"nk":
            nk = _parse_nk(data, pos)
            if not nk:
                break
            keys.append(nk)
            name_lower = nk["name"].lower()
            if name_lower in ("run", "runonce"):
                run_keys.append(nk)
            if nk["name"] in ("alice", "bob"):
                users.append(nk)
            if "svc" in name_lower or "service" in name_lower:
                services.append(nk)
            cell_size = 76 + nk["name_len"] if "name_len" in nk else 128
            step = max((cell_size + 7) // 8 * 8, 8)
            pos += step
        elif sig == b"vk":
            vk = _parse_vk(data, pos)
            if not vk:
                break
            values.append(vk)
            if vk.get("decoded") and ("exe" in vk["decoded"].lower() or "cmd" in vk["decoded"].lower()
                                       or "rundll" in vk["decoded"].lower()):
                persistence.append(vk)
            name_len = struct.unpack_from("<H", data, pos + 2)[0]
            data_len = struct.unpack_from("<I", data, pos + 4)[0]
            cell_size = 20 + name_len + data_len
            pos += max((cell_size + 7) // 8 * 8, 8)
        else:
            pos += 1

    result["keys"] = keys
    result["values"] = values
    result["run_keys"] = run_keys
    result["persistence"] = persistence
    result["services"] = services
    result["sam_users"] = users
    result["summary"] = {
        "total_keys": len(keys),
        "total_values": len(values),
        "run_key_count": len(run_keys),
        "persistence_count": len(persistence),
        "service_count": len(services),
        "user_count": len(users),
    }

    if custody:
        result["custody_hash"] = custody.add_json_output("registry_analysis", result)
    return result
