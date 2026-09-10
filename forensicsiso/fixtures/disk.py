"""Build a small ext2-style raw disk image fixture for the disk parser.

Creates a 1 MiB image with:
  - MBR partition table (one Linux partition covering LBA 1..2047)
  - Ext2 filesystem at image-absolute offsets (superblock at byte 1024,
    block group descriptor at 2048, inode table at 5120, data blocks from 6144)
  - Root inode with directory entries: "hello.txt" and "deleted.txt"
  - "deleted.txt" content recoverable (inode marked deleted only)
  - GPT protective header at LBA 1
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path

# Constants
SECTOR = 512
BLOCK = 1024
IMG_SIZE = 1 << 20  # 1 MiB
PART_START_BLK = 1
PART_OFFSET = 0  # ext2 layout is image-absolute (whole image ≈ one partition)
INODE_SIZE = 128
INODES_PER_GRP = 8192
BLOCKS_PER_GRP = 8192
NUM_GROUPS = 1

ROOT_INO = 2
DELETED_INO = 3
FILE_INO = 4

MAGIC = 0xEF53
MINOR_VER = 1
MAJOR_VER = 2

DELETED_CONTENT = b"This file was deleted but is still recoverable from the raw image.\n"
HELLO_CONTENT = b"Hello from forensicsiso test fixture!\n"
FILE2_NAME = b"secret.dat"
FILE2_CONTENT = b"Hidden in plain sight - forensic test file.\n"
BOOT_SIG = b"\x55\xAA"


def _little32(val: int) -> bytes:
    return struct.pack("<I", val)


def _little16(val: int) -> bytes:
    return struct.pack("<H", val)


def build_disk_image(dest: str) -> str:
    if os.path.exists(dest):
        os.unlink(dest)
    img = bytearray(IMG_SIZE)

    # ── MBR (sector 0) ──
    # Partition 1: type 0x83 (Linux), LBA start = PART_START_BLK, sectors = IMG_SIZE//SECTOR - PART_START_BLK
    part_start_sector = PART_START_BLK
    part_sectors = (IMG_SIZE // SECTOR) - part_start_sector
    mbr = bytearray(SECTOR)
    # Partition table at offset 446
    off = 446
    mbr[off] = 0x00  # status
    mbr[off + 1] = 0x00  # CHS start (unused)
    mbr[off + 2] = 0x00
    mbr[off + 3] = 0x00
    mbr[off + 4] = 0x83  # type: Linux
    mbr[off + 5] = 0x00  # CHS end
    mbr[off + 6] = 0x00
    mbr[off + 7] = 0x00
    struct.pack_into("<I", mbr, off + 8, part_start_sector)
    struct.pack_into("<I", mbr, off + 12, part_sectors)
    mbr[510] = 0x55
    mbr[511] = 0xAA
    img[0:SECTOR] = mbr

    # ── GPT header at LBA 1 (protective) ──
    gpt = bytearray(SECTOR)
    gpt[0:8] = b"EFI PART"
    struct.pack_into("<I", gpt, 8, 0x00010000)  # revision 1.0
    struct.pack_into("<I", gpt, 12, 92)  # header size
    struct.pack_into("<I", gpt, 16, 0)  # checksum placeholder
    gpt[24:28] = b"\x00\x00\x00\x00"  # reserved
    struct.pack_into("<Q", gpt, 32, 1)  # my LBA
    struct.pack_into("<Q", gpt, 40, IMG_SIZE // SECTOR - 1)  # alt LBA
    struct.pack_into("<Q", gpt, 48, 34)  # first usable LBA
    struct.pack_into("<Q", gpt, 56, IMG_SIZE // SECTOR - 33)  # last usable LBA
    # disk GUID
    struct.pack_into("<Q", gpt, 56, 0)
    img[SECTOR: 2 * SECTOR] = gpt

    # ── Ext2 superblock at PART_OFFSET + 1024 ──
    sb_off = PART_OFFSET + BLOCK
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x00, 256)  # inode count
    struct.pack_into("<I", sb, 0x04, 1024)  # blocks count (low)
    struct.pack_into("<I", sb, 0x08, 0)  # reserved blocks
    struct.pack_into("<I", sb, 0x0C, 1018)  # free blocks
    struct.pack_into("<I", sb, 0x10, 251)  # free inodes
    struct.pack_into("<I", sb, 0x14, 1)  # first data block
    struct.pack_into("<I", sb, 0x18, 0)  # log block size (1024)
    struct.pack_into("<I", sb, 0x1C, 0)  # log cluster size
    struct.pack_into("<I", sb, 0x20, BLOCKS_PER_GRP)  # blocks per group
    struct.pack_into("<I", sb, 0x24, BLOCKS_PER_GRP)  # clusters per group
    struct.pack_into("<I", sb, 0x28, INODES_PER_GRP)  # inodes per group
    struct.pack_into("<I", sb, 0x2C, int(time.time()))  # mtime
    struct.pack_into("<I", sb, 0x30, int(time.time()))  # wtime
    struct.pack_into("<H", sb, 0x34, 0)  # mount count
    struct.pack_into("<H", sb, 0x36, 0xFFFF)  # max mount count
    struct.pack_into("<H", sb, 0x38, 0xEF53)  # magic
    sb[0x3A] = 1  # state: clean
    sb[0x3B] = 0  # errors: continue
    struct.pack_into("<H", sb, 0x3E, 0)  # minor rev level
    struct.pack_into("<I", sb, 0x40, int(time.time()))  # last check time
    struct.pack_into("<I", sb, 0x44, 600)  # check interval
    struct.pack_into("<I", sb, 0x48, 0)  # creator OS (linux)
    struct.pack_into("<I", sb, 0x4C, 1)  # rev level (dynamic)
    struct.pack_into("<H", sb, 0x50, 1000)  # default resuid
    struct.pack_into("<H", sb, 0x52, 1000)  # default resgid
    struct.pack_into("<H", sb, 0x58, INODE_SIZE)  # inode size
    img[sb_off: sb_off + 1024] = sb

    # ── Block Group Descriptor at PART_OFFSET + 2*BLOCK ──
    bgd_off = PART_OFFSET + 2 * BLOCK
    bgd = bytearray(32)
    struct.pack_into("<I", bgd, 0, PART_OFFSET + 3 * BLOCK)  # block bitmap
    struct.pack_into("<I", bgd, 4, PART_OFFSET + 4 * BLOCK)  # inode bitmap
    struct.pack_into("<I", bgd, 8, PART_OFFSET + 5 * BLOCK)  # inode table
    struct.pack_into("<H", bgd, 16, BLOCKS_PER_GRP - 10)  # free blocks
    struct.pack_into("<H", bgd, 18, INODES_PER_GRP - 6)  # free inodes
    img[bgd_off: bgd_off + 32] = bgd

    # ── Block bitmap at PART_OFFSET + 3*BLOCK ──
    bb_off = PART_OFFSET + 3 * BLOCK
    bb = bytearray(BLOCK)
    # Mark blocks 0-5 as used
    for i in range(6):
        bb[i // 8] |= 1 << (i % 8)
    img[bb_off: bb_off + BLOCK] = bb

    # ── Inode bitmap at PART_OFFSET + 4*BLOCK ──
    ib_off = PART_OFFSET + 4 * BLOCK
    ib = bytearray(BLOCK)
    # Inodes 1..4 used (0 unused, 1 bad, 2 root, 3 deleted, 4 file)
    for i in range(1, 5):
        ib[i // 8] |= 1 << (i % 8)
    img[ib_off: ib_off + BLOCK] = ib

    # ── Inode table at PART_OFFSET + 5*BLOCK ──
    it_off = PART_OFFSET + 5 * BLOCK

    S_IFREG = 0x8000
    S_IFDIR = 0x4000
    PERM_0644 = 0o644
    PERM_0755 = 0o755

    def write_inode(idx: int, size: int, block_ptr: int, mode: int, flags: int = 0) -> None:
        off = it_off + (idx - 1) * INODE_SIZE
        struct.pack_into("<H", img, off + 0, mode)  # mode
        struct.pack_into("<H", img, off + 2, 0)  # uid
        struct.pack_into("<I", img, off + 4, size)  # size
        struct.pack_into("<I", img, off + 8, int(time.time()))  # atime
        struct.pack_into("<I", img, off + 12, int(time.time()))  # ctime
        struct.pack_into("<I", img, off + 16, int(time.time()))  # mtime
        struct.pack_into("<H", img, off + 26, 1)  # links
        img[off + 28] = flags  # l_i_flags_high or OS-specific2
        # block pointers 40..100
        struct.pack_into("<I", img, off + 40, block_ptr)

    # ── Data blocks ──
    data_base = PART_OFFSET + 6 * BLOCK

    # Block 6: directory entries for root (inode 2)
    dir_off = data_base
    dir_data = bytearray(BLOCK)
    d = 0
    # inode 2 (self)
    struct.pack_into("<I", dir_data, d, 2)
    struct.pack_into("<H", dir_data, d + 4, 12)  # rec_len
    struct.pack_into("<B", dir_data, d + 8, 1)  # name_len
    struct.pack_into("<B", dir_data, d + 9, 2)  # file_type (dir)
    dir_data[d + 10:d + 10 + 1] = b"."
    d += 12
    # inode 2 parent
    struct.pack_into("<I", dir_data, d, 2)
    struct.pack_into("<H", dir_data, d + 4, 12)
    struct.pack_into("<B", dir_data, d + 8, 2)
    struct.pack_into("<B", dir_data, d + 9, 2)
    dir_data[d + 10:d + 10 + 2] = b".."
    d += 12
    # hello.txt → inode 4
    name = b"hello.txt"
    rec = 10 + len(name)
    if rec % 4:
        rec += 4 - (rec % 4)
    struct.pack_into("<I", dir_data, d, 4)
    struct.pack_into("<H", dir_data, d + 4, rec)
    struct.pack_into("<B", dir_data, d + 8, len(name))
    struct.pack_into("<B", dir_data, d + 9, 1)  # file
    dir_data[d + 10:d + 10 + len(name)] = name
    d += rec
    # deleted.txt → inode 3 (still referenced here but inode is "deleted")
    name2 = b"deleted.txt"
    rec2 = 10 + len(name2)
    if rec2 % 4:
        rec2 += 4 - (rec2 % 4)
    struct.pack_into("<I", dir_data, d, 3)
    struct.pack_into("<H", dir_data, d + 4, rec2)
    struct.pack_into("<B", dir_data, d + 8, len(name2))
    struct.pack_into("<B", dir_data, d + 9, 1)
    dir_data[d + 10:d + 10 + len(name2)] = name2
    d += rec2

    img[dir_off: dir_off + BLOCK] = dir_data

    # Block 7: data for hello.txt
    file_off = data_base + BLOCK
    img[file_off: file_off + len(HELLO_CONTENT)] = HELLO_CONTENT

    # Block 8: data for deleted.txt (recoverable!)
    del_off = data_base + 2 * BLOCK
    img[del_off: del_off + len(DELETED_CONTENT)] = DELETED_CONTENT

    # Block 9: data for secret.dat
    secret_off = data_base + 3 * BLOCK
    img[secret_off: secret_off + len(FILE2_CONTENT)] = FILE2_CONTENT

    # Write inodes
    # root dir inode
    write_inode(ROOT_INO, size=4096, block_ptr=data_base // BLOCK, mode=S_IFDIR | PERM_0755, flags=0)
    # deleted file inode (marked deleted — size=0, no blocks)
    write_inode(DELETED_INO, size=0, block_ptr=0, mode=S_IFREG | PERM_0644, flags=2)  # flag bit 1 = deleted marker
    # hello.txt
    write_inode(FILE_INO, size=len(HELLO_CONTENT), block_ptr=7, mode=S_IFREG | PERM_0644, flags=0)
    # secret.dat
    write_inode(5, size=len(FILE2_CONTENT), block_ptr=9, mode=S_IFREG | PERM_0644, flags=0)
    # Update inode bitmap to include inode 5
    ib[5 // 8] |= 1 << (5 % 8)
    img[ib_off: ib_off + BLOCK] = ib

    with open(dest, "wb") as f:
        f.write(img)
    return dest
