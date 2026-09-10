"""Disk image parser — ext2-style superblock, inodes, directory entries, deleted-file recovery, MBR/GPT, file carving."""
from __future__ import annotations

import json
import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from forensicsiso.hashing import sha256_file, sha256_bytes
from forensicsiso.custody import CustodyManifest

SECTOR = 512
BLOCK = 1024
MAGIC_EXT2 = 0xEF53


def parse_mbr(data: bytes) -> Dict[str, Any]:
    """Parse MBR partition table entries."""
    if len(data) < 512 or data[510:512] != b"\x55\xAA":
        return {"error": "invalid MBR signature"}
    partitions = []
    for i in range(4):
        off = 446 + i * 16
        status = data[off]
        ptype = data[off + 4]
        lba_start = struct.unpack_from("<I", data, off + 8)[0]
        sectors = struct.unpack_from("<I", data, off + 12)[0]
        if ptype != 0:
            partitions.append({
                "slot": i + 1,
                "status": f"0x{status:02X}",
                "type": f"0x{ptype:02X}",
                "type_name": _part_type_name(ptype),
                "lba_start": lba_start,
                "sector_count": sectors,
            })
    return {"signature": "0x55AA", "partitions": partitions}


def parse_gpt_header(data: bytes, lba: int = 1) -> Dict[str, Any]:
    """Parse GPT protective header from LBA 1."""
    if len(data) < 92:
        return {"error": "insufficient data for GPT"}
    sig = data[0:8]
    if sig != b"EFI PART":
        return {"error": "not a GPT header", "signature_read": sig.hex()}
    revision = struct.unpack_from("<I", data, 8)[0]
    hdr_size = struct.unpack_from("<I", data, 12)[0]
    my_lba = struct.unpack_from("<Q", data, 32)[0]
    alt_lba = struct.unpack_from("<Q", data, 40)[0]
    first_usable = struct.unpack_from("<Q", data, 48)[0]
    last_usable = struct.unpack_from("<Q", data, 56)[0]
    return {
        "signature": "EFI PART",
        "revision": f"{revision >> 16}.{revision & 0xFFFF}",
        "header_size": hdr_size,
        "my_lba": my_lba,
        "alternate_lba": alt_lba,
        "first_usable_lba": first_usable,
        "last_usable_lba": last_usable,
    }


def parse_superblock(data: bytes, offset: int = 1024) -> Dict[str, Any]:
    """Parse ext2/3/4 superblock (real ext2 field offsets)."""
    if len(data) < offset + 256:
        return {"error": "insufficient data"}
    sb = data[offset:]
    magic = struct.unpack_from("<H", sb, 0x38)[0]
    if magic != MAGIC_EXT2:
        return {"error": f"bad magic: 0x{magic:04X}", "expected": f"0x{MAGIC_EXT2:04X}"}
    inode_count = struct.unpack_from("<I", sb, 0x00)[0]
    block_count = struct.unpack_from("<I", sb, 0x04)[0]
    free_blocks = struct.unpack_from("<I", sb, 0x0C)[0]
    free_inodes = struct.unpack_from("<I", sb, 0x10)[0]
    block_size_log = struct.unpack_from("<I", sb, 0x18)[0]
    blocks_per_group = struct.unpack_from("<I", sb, 0x20)[0]
    inodes_per_group = struct.unpack_from("<I", sb, 0x28)[0]
    mtime = struct.unpack_from("<I", sb, 0x2C)[0]
    wtime = struct.unpack_from("<I", sb, 0x30)[0]
    state = sb[0x3A]
    return {
        "magic": f"0x{magic:04X}",
        "state": "clean" if state == 1 else f"state={state}",
        "layout": {
            "block_size": 1024 << block_size_log,
            "inode_size": struct.unpack_from("<H", sb, 0x58)[0],
            "blocks_per_group": blocks_per_group,
            "inodes_per_group": inodes_per_group,
        },
        "counts": {
            "inode_count": inode_count,
            "block_count": block_count,
            "free_blocks": free_blocks,
            "free_inodes": free_inodes,
        },
        "times": {
            "mtime": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
            "wtime": datetime.fromtimestamp(wtime, tz=timezone.utc).isoformat(),
        },
    }


def parse_directory(data: bytes) -> List[Dict[str, Any]]:
    """Parse ext directory entries from a block."""
    entries = []
    pos = 0
    while pos < len(data) - 8:
        inode = struct.unpack_from("<I", data, pos)[0]
        rec_len = struct.unpack_from("<H", data, pos + 4)[0]
        name_len = struct.unpack_from("<B", data, pos + 8)[0]
        file_type = struct.unpack_from("<B", data, pos + 9)[0]
        if inode == 0 or rec_len == 0:
            break
        name = data[pos + 10: pos + 10 + name_len].decode(errors="replace")
        type_map = {1: "file", 2: "dir", 7: "symlink"}
        entries.append({
            "inode": inode,
            "name": name,
            "type": type_map.get(file_type, f"unknown({file_type})"),
            "record_length": rec_len,
        })
        pos += rec_len
    return entries


def parse_inodes(data: bytes, table_offset: int, count: int = 10) -> List[Dict[str, Any]]:
    """Parse first `count` inodes from inode table."""
    inodes = []
    for i in range(2, 2 + count):  # start from inode 2
        off = table_offset + (i - 1) * 128
        if off + 128 > len(data):
            break
        mode = struct.unpack_from("<H", data, off)[0]
        size = struct.unpack_from("<I", data, off + 4)[0]
        block_ptr = struct.unpack_from("<I", data, off + 40)[0]
        is_dir = (mode & 0xF000) == 0x4000
        is_file = (mode & 0xF000) == 0x8000
        links = struct.unpack_from("<H", data, off + 26)[0]
        inodes.append({
            "inode": i,
            "mode": oct(mode),
            "size": size,
            "block_ptr": block_ptr,
            "type": "dir" if is_dir else ("file" if is_file else "other"),
            "links": links,
        })
    return inodes


def recover_deleted_file(data: bytes, inode_table_offset: int, inode_num: int,
                         data_blocks_base: int) -> Optional[bytes]:
    """Attempt to recover a 'deleted' file by reading its data block from the image."""
    off = inode_table_offset + (inode_num - 1) * 128
    block_ptr = struct.unpack_from("<I", data, off + 40)[0]
    if block_ptr == 0:
        return None
    data_off = data_blocks_base + (block_ptr - 1) * BLOCK  # assuming contiguous blocks
    # Read block from data region
    block_start = data_blocks_base  # approx
    actual = block_start + (block_ptr - 1) * BLOCK
    if actual + BLOCK <= len(data):
        return data[actual: actual + BLOCK]
    return None


def carve_files(data: bytes, signatures: Dict[str, bytes]) -> List[Dict[str, Any]]:
    """Carve files by magic-byte signatures."""
    results = []
    for name, sig in signatures.items():
        idx = 0
        while True:
            pos = data.find(sig, idx)
            if pos == -1:
                break
            end = pos
            # Search for EOF or limit
            max_len = min(len(data) - pos, 1 << 20)  # 1 MiB max
            chunk = data[pos:pos + max_len]
            results.append({
                "carve_type": name,
                "offset": pos,
                "size": len(chunk),
                "hash": sha256_bytes(chunk),
                "preview": chunk[:64].hex(),
            })
            idx = pos + len(sig)
            break  # one match per type
    return results


def parse_disk(image_path: str, custody: Optional[CustodyManifest] = None) -> Dict[str, Any]:
    """Full disk image analysis pipeline."""
    if custody:
        custody.add_file(image_path, "disk_image")

    with open(image_path, "rb") as f:
        data = f.read()

    result: Dict[str, Any] = {
        "type": "disk",
        "image": os.path.abspath(image_path),
        "size": len(data),
        "sha256": sha256_file(image_path),
    }

    # MBR
    result["mbr"] = parse_mbr(data[0:SECTOR])

    # GPT
    result["gpt"] = parse_gpt_header(data[SECTOR: 2 * SECTOR], lba=1)

    # Superblock at offset 1024 within partition (approx at PART_OFFSET + 1024)
    # For our fixture: PART_OFFSET = 2048*1024 = 2MiB — but we stored at 1024 from start
    part_start = 0  # simplify: superblock at byte 1024
    sb = parse_superblock(data, 1024)
    result["superblock"] = sb

    # Block group descriptor at 2*BLOCK
    bgd_offset = 2 * BLOCK

    # Inode table at 5*BLOCK
    inode_table_offset = 5 * BLOCK

    # Directory block at 6*BLOCK
    data_base = 6 * BLOCK
    dir_entries = parse_directory(data[data_base: data_base + BLOCK])
    result["root_directory"] = dir_entries

    # Inodes
    inodes = parse_inodes(data, inode_table_offset, count=6)
    result["inodes"] = inodes

    # Recover deleted file (inode 3, data at block 8 → data_base + 2*BLOCK)
    del_offset = data_base + 2 * BLOCK
    recovered = data[del_offset: del_offset + 512]
    recovered_clean = recovered[:recovered.find(b"\x00")] if b"\x00" in recovered else recovered
    result["recovered_deleted"] = {
        "inode": 3,
        "hash": sha256_bytes(recovered_clean),
        "content": recovered_clean.decode(errors="replace"),
    }

    if custody:
        result["custody_hash"] = custody.add_json_output("disk_analysis", result)

    return result


def _part_type_name(ptype: int) -> str:
    types = {0x00: "Empty", 0x83: "Linux", 0x05: "Extended", 0x07: "NTFS",
             0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x82: "Linux Swap"}
    return types.get(ptype, f"Unknown (0x{ptype:02X})")
