"""Build a Windows registry hive replica fixture (binary)."""
from __future__ import annotations

import os
import struct
import time
from datetime import datetime, timezone

# Registry regf header format (simplified but parseable)
REGF_MAGIC = b"regf"
REGF_VERSION = 1
REGF_ROOT_OFFSET = 0x1000

# Cell types
CELL_KEY = 1
CELL_VALUE = 2
CELL_DATA = 3


def _regf_header(root_offset: int, size: int) -> bytes:
    hdr = bytearray(4096)
    hdr[0:4] = REGF_MAGIC
    struct.pack_into("<I", hdr, 4, REGF_VERSION)  # major version
    struct.pack_into("<I", hdr, 8, REGF_VERSION)  # minor version
    struct.pack_into("<Q", hdr, 16, int(time.time()))  # mtime
    struct.pack_into("<I", hdr, 24, size)  # hive bins data size
    struct.pack_into("<I", hdr, 28, root_offset)  # root cell offset
    struct.pack_into("<I", hdr, 32, 0x50)  # hive bins data start
    hdr[40:44] = b"Test"
    return bytes(hdr)


def _nk_cell(name: str, subkey_count: int, parent_offset: int, flags: int = 0) -> bytes:
    """Build an nk (named key) cell."""
    name_enc = name.encode("ascii")
    cell_size = 76 + len(name_enc)
    # Round to 8-byte boundary
    if cell_size % 8:
        cell_size += 8 - (cell_size % 8)
    cell = bytearray(cell_size)
    cell[0:2] = b"nk"  # signature
    struct.pack_into("<H", cell, 2, flags)  # flags
    struct.pack_into("<Q", cell, 4, int(time.time())  // 10000000 + 11644473600)  # mtime
    struct.pack_into("<I", cell, 16, parent_offset)
    struct.pack_into("<i", cell, 20, subkey_count)  # subkey count (signed)
    struct.pack_into("<I", cell, 24, 0)  # subkeys offset
    struct.pack_into("<I", cell, 28, 0)  # volatile subkey count
    struct.pack_into("<I", cell, 32, 0)  # volatile subkey offset
    struct.pack_into("<I", cell, 36, 0)  # class name offset
    struct.pack_into("<I", cell, 40, 0)  # max subkey name len
    struct.pack_into("<I", cell, 44, 0)  # max class name len
    struct.pack_into("<I", cell, 48, 0)  # max value name len
    struct.pack_into("<I", cell, 52, 0)  # max value data len
    struct.pack_into("<I", cell, 56, 0)  # workvar
    struct.pack_into("<H", cell, 60, len(name_enc))  # name length
    struct.pack_into("<I", cell, 64, 0)  # class name length (unused)
    cell[68:68 + len(name_enc)] = name_enc
    return bytes(cell)


def _vk_cell(name: str, data_type: int, data: bytes) -> bytes:
    """Build a vk (value key) cell. Data is stored inline in the cell."""
    name_enc = name.encode("ascii") if name else b""
    cell_size = 20 + len(name_enc) + len(data)
    if cell_size % 8:
        cell_size += 8 - (cell_size % 8)
    cell = bytearray(cell_size)
    cell[0:2] = b"vk"
    struct.pack_into("<H", cell, 2, len(name_enc))  # name length
    struct.pack_into("<I", cell, 4, len(data))  # data length
    struct.pack_into("<I", cell, 8, 0x80000000 | len(data))  # inline data flag + len
    struct.pack_into("<I", cell, 12, data_type)  # data type
    cell[20:20 + len(name_enc)] = name_enc
    cell[20 + len(name_enc): 20 + len(name_enc) + len(data)] = data
    return bytes(cell)


def build_registry_fixture(dest: str) -> str:
    """
    Build a registry hive with:
      - root Run/RunOnce keys with persistence values
      - SAM users (alice, bob)
      - Services (SuspiciousSvc, LegitDriver)
    """
    hive = bytearray(256 * 4096)  # 1 MiB hive

    # regf header
    hive[0:4096] = _regf_header(REGF_ROOT_OFFSET, 256 * 4096)

    # Build cells from REGF_ROOT_OFFSET
    off = REGF_ROOT_OFFSET

    # Root key cell
    root_cell = _nk_cell("CMI-CreateHive{...}", subkey_count=3, parent_offset=0, flags=0x20)
    hive[off:off + len(root_cell)] = root_cell
    root_off = off
    off += len(root_cell)

    # SOFTWARE key
    sw_cell = _nk_cell("SOFTWARE", subkey_count=2, parent_offset=root_off, flags=0x20)
    hive[off:off + len(sw_cell)] = sw_cell
    sw_off = off
    off += len(sw_cell)

    # Run key
    run_cell = _nk_cell("Run", subkey_count=2, parent_offset=sw_off, flags=0x20)
    hive[off:off + len(run_cell)] = run_cell
    run_off = off
    off += len(run_cell)

    # Run key values: two persistence entries
    run_data1 = b"C:\\Windows\\System32\\malware.exe\x00"
    vk1 = _vk_cell("Updater", 1, run_data1)  # REG_SZ = 1
    hive[off:off + len(vk1)] = vk1
    off += len(vk1)

    run_data2 = b"cmd.exe /c C:\\temp\\payload.bat\x00"
    vk2 = _vk_cell("Launcher", 1, run_data2)
    hive[off:off + len(vk2)] = vk2
    off += len(vk2)

    # RunOnce key
    ro_cell = _nk_cell("RunOnce", subkey_count=1, parent_offset=sw_off, flags=0x20)
    hive[off:off + len(ro_cell)] = ro_cell
    ro_off = off
    off += len(ro_cell)

    ro_data = b"rundll32.exe C:\\temp\\init.dll,EntryPoint\x00"
    vk_ro = _vk_cell("", 1, ro_data)
    hive[off:off + len(vk_ro)] = vk_ro
    off += len(vk_ro)

    # SAM key
    sam_cell = _nk_cell("SAM", subkey_count=1, parent_offset=root_off, flags=0x20)
    hive[off:off + len(sam_cell)] = sam_cell
    sam_off = off
    off += len(sam_cell)

    dom_cell = _nk_cell("Domains", subkey_count=1, parent_offset=sam_off, flags=0x20)
    hive[off:off + len(dom_cell)] = dom_cell
    dom_off = off
    off += len(dom_cell)

    acct_cell = _nk_cell("Account", subkey_count=1, parent_offset=dom_off, flags=0x20)
    hive[off:off + len(acct_cell)] = acct_cell
    acct_off = off
    off += len(acct_cell)

    users_cell = _nk_cell("Users", subkey_count=2, parent_offset=acct_off, flags=0x20)
    hive[off:off + len(users_cell)] = users_cell
    users_off = off
    off += len(users_cell)

    # User entries
    for uname in ["alice", "bob"]:
        u_cell = _nk_cell(uname, subkey_count=0, parent_offset=users_off, flags=0x20)
        hive[off:off + len(u_cell)] = u_cell
        off += len(u_cell)

    # SYSTEM key
    sys_cell = _nk_cell("SYSTEM", subkey_count=1, parent_offset=root_off, flags=0x20)
    hive[off:off + len(sys_cell)] = sys_cell
    sys_off = off
    off += len(sys_cell)

    ccs_cell = _nk_cell("CurrentControlSet", subkey_count=1, parent_offset=sys_off, flags=0x20)
    hive[off:off + len(ccs_cell)] = ccs_cell
    ccs_off = off
    off += len(ccs_cell)

    svc_cell = _nk_cell("Services", subkey_count=2, parent_offset=ccs_off, flags=0x20)
    hive[off:off + len(svc_cell)] = svc_cell
    svc_off = off
    off += len(svc_cell)

    for svc_name in ["SuspiciousSvc", "LegitDriver"]:
        svc = _nk_cell(svc_name, subkey_count=0, parent_offset=svc_off, flags=0x20)
        hive[off:off + len(svc)] = svc
        off += len(svc)

    with open(dest, "wb") as f:
        f.write(hive)
    return dest