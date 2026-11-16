"""
Synthetic MSF/PDB fixture builders for the PDB test-suite.

These helpers assemble minimal but spec-valid MSF 7.0 containers from raw streams, so tests can exercise corruption,
cyclic records, duplicate types and oversize records without depending on a particular real PDB. The builder mirrors
the on-disk layout that :mod:`angr.analyses.pdb.msf` reads, including the two-level directory page table.
"""

from __future__ import annotations

import math
import struct

MSF7_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


def build_msf7(streams: list[bytes], page_size: int = 512) -> bytes:
    """
    Assemble a valid MSF 7.0 image containing ``streams``.

    Page 0 holds the superblock and the (single-level here) directory-page-table pointer. Stream pages are allocated
    sequentially after the superblock, followed by the directory pages and finally the directory page table.
    """
    # Assign data pages to each stream.
    stream_pages: list[list[int]] = []
    allocated: list[int] = [0]  # page 0 is the superblock
    for content in streams:
        if not content:
            stream_pages.append([])
            continue
        count = math.ceil(len(content) / page_size)
        pages = []
        for _ in range(count):
            allocated.append(len(allocated))
            pages.append(len(allocated) - 1)
        stream_pages.append(pages)

    # Build the logical stream directory.
    directory = struct.pack("<I", len(streams))
    for content in streams:
        directory += struct.pack("<I", len(content) if content else 0)
    for content, pages in zip(streams, stream_pages):
        if not content:
            continue
        for page in pages:
            directory += struct.pack("<I", page)
    dir_page_count = math.ceil(len(directory) / page_size)
    while len(directory) < dir_page_count * page_size:
        directory += b"\x00"

    # Allocate directory pages and the page table page that points at them.
    dir_pages = []
    for _ in range(dir_page_count):
        allocated.append(len(allocated))
        dir_pages.append(len(allocated) - 1)
    allocated.append(len(allocated))
    page_table_page = len(allocated) - 1
    total_pages = len(allocated)

    out = bytearray(total_pages * page_size)

    # Superblock (32-byte signature + 5 dwords + root page table).
    struct.pack_into("<32s", out, 0, MSF7_SIGNATURE)
    struct.pack_into("<IIIII", out, 32, page_size, 1, total_pages, len(directory), 0)
    struct.pack_into("<I", out, 52, page_table_page)

    # Stream data pages.
    for content, pages in zip(streams, stream_pages):
        for i, page in enumerate(pages):
            chunk = content[i * page_size : (i + 1) * page_size]
            out[page * page_size : page * page_size + len(chunk)] = chunk

    # Directory pages and their page table.
    for i, page in enumerate(dir_pages):
        out[page * page_size : (page + 1) * page_size] = directory[i * page_size : (i + 1) * page_size]
    for i, page in enumerate(dir_pages):
        struct.pack_into("<I", out, page_table_page * page_size + i * 4, page)

    return bytes(out)


def tpi_stream(records: list[tuple[int, bytes]], ti_min: int = 0x1000, header_size: int = 56) -> bytes:
    """
    Build a TPI stream from a list of ``(leaf, body)`` records. Each record is framed as u16 length + u16 leaf +
    body, with parity (2-byte) padding, and prefixed with a 56-byte TPI header.
    """
    body = b""
    count = 0
    for leaf, payload in records:
        record = struct.pack("<H", 2 + len(payload)) + struct.pack("<H", leaf) + payload
        if len(record) & 1:
            record += b"\x00"
        body += record
        count += 1
    header = struct.pack("<IIIII", 0x0131CA0B, header_size, ti_min, ti_min + count, len(body))
    header += b"\x00" * (header_size - 20)
    return header + body


def dbi_stream(
    machine: int = 0x8664,
    symbol_stream: int = -1,
    module_size: int = 0,
    substream_sizes: tuple[int, ...] = (0, 0, 0, 0),
    optional_debug: bytes = b"",
) -> bytes:
    """Build a 64-byte DBI header (plus optional substreams) with the supplied machine and symbol stream index."""
    sec_contrib, sec_map, src_info, type_server = substream_sizes
    flags = 0
    header = struct.pack(
        "<iiiHHHHHHiiiiiiiiHHI",
        -1,                       # signature (int32)
        0x01310977,               # version (uint32)
        1,                        # age (uint32)
        (-1) & 0xFFFF,            # global stream (int16, stored as uint16)
        0,                        # build number
        (-1) & 0xFFFF,            # public stream (int16)
        0,                        # pdb dll version
        symbol_stream & 0xFFFF,   # symbol record stream (uint16)
        0,                        # pdb dll rbld
        module_size,
        sec_contrib,
        sec_map,
        src_info,
        type_server,
        0,                        # MFC index
        len(optional_debug),
        0,                        # EC substream size
        flags,
        machine,
        0,                        # padding
    )
    return header + optional_debug


def symbol_record(kind: int, payload: bytes) -> bytes:
    """Frame one CodeView symbol record (u16 length + u16 kind + payload), 4-byte aligned."""
    record = struct.pack("<H", 2 + len(payload)) + struct.pack("<H", kind) + payload
    while len(record) % 4:
        record += b"\x00"
    return record


def type_record(leaf: int, payload: bytes) -> bytes:
    """Frame one CodeView type record (u16 length + u16 leaf + payload) with parity padding."""
    record = struct.pack("<H", 2 + len(payload)) + struct.pack("<H", leaf) + payload
    if len(record) & 1:
        record += b"\x00"
    return record
