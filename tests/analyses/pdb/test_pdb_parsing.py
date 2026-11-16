"""
Unit tests for the low-level PDB/MSF/CodeView parsers.

These tests use the synthetic fixture builder in :mod:`fixtures` so that corruption and edge cases can be exercised
deterministically without a real compiler or PDB. End-to-end tests against a real MSVC PDB live in
``test_pdb_integration.py``.
"""

from __future__ import annotations

import os
import struct

import pytest

from angr.analyses.pdb.constants import (
    LF_ARGLIST,
    LF_FIELDLIST,
    LF_POINTER,
    LF_PROCEDURE,
    LF_STRUCTURE,
    T_VOID,
)
from angr.analyses.pdb.dbi import parse_dbi
from angr.analyses.pdb.msf import MSFFile, PDBFormatError
from angr.analyses.pdb.peinfo import read_codeview_info
from angr.analyses.pdb.tpi import (
    AggregateRecord,
    FieldListRecord,
    PointerRecord,
    ProcedureRecord,
    TPIStream,
)

from .fixtures import build_msf7, dbi_stream, symbol_record, tpi_stream


# ---------------------------------------------------------------------------
# MSF container
# ---------------------------------------------------------------------------


def test_msf7_roundtrip_basic():
    s0 = b"stream-zero!"
    s1 = os.urandom(1500)  # spans multiple 512-byte pages
    s2 = b""
    image = build_msf7([s0, s1, s2], page_size=512)
    msf = MSFFile(image)
    assert msf.version == 7
    assert msf.num_streams == 3
    assert msf.get_stream(0) == s0
    assert msf.get_stream(1) == s1
    assert msf.get_stream(2) == b""
    # Caching: repeated reads return the same object without re-parsing.
    assert msf.get_stream(1) is msf.get_stream(1)


def test_msf7_single_page_small_page_size():
    payload = b"A" * 40
    image = build_msf7([payload], page_size=128)
    assert MSFFile(image).get_stream(0) == payload


def test_msf_rejects_bad_signature():
    with pytest.raises(PDBFormatError):
        MSFFile(b"definitely not an MSF file" + b"\x00" * 100)
    with pytest.raises(PDBFormatError):
        MSFFile(b"")


def test_msf_rejects_truncated_superblock():
    image = build_msf7([b"hello"])
    with pytest.raises(PDBFormatError):
        MSFFile(image[:20])


def test_msf_rejects_out_of_range_stream_page():
    image = bytearray(build_msf7([b"x" * 64]))
    # Corrupt the directory's stream page pointer to an impossible page number.
    # Locate directory page table pointer at superblock offset 52, then the directory page, then a page entry.
    page_size = struct.unpack_from("<I", image, 32)[0]
    table_page = struct.unpack_from("<I", image, 52)[0]
    dir_page = struct.unpack_from("<I", image, table_page * page_size)[0]
    # Directory layout: u32 stream count, u32 size(64), then the page list.
    struct.pack_into("<I", image, dir_page * page_size + 8, 0x7FFFFFFF)
    with pytest.raises(PDBFormatError):
        MSFFile(bytes(image))


def test_msf_stream_index_out_of_range():
    msf = MSFFile(build_msf7([b"a"]))
    with pytest.raises(PDBFormatError):
        msf.get_stream(99)


# ---------------------------------------------------------------------------
# TPI type records
# ---------------------------------------------------------------------------


def _lf_pointer(utype: int, attributes: int = 0) -> bytes:
    return struct.pack("<II", utype, attributes)


def _lf_procedure(ret: int, call: int, count: int, arglist: int) -> bytes:
    return struct.pack("<IBBHI", ret, call, 0, count, arglist)


def _lf_arglist(types: list[int]) -> bytes:
    return struct.pack("<I", len(types)) + b"".join(struct.pack("<I", t) for t in types)


def _lf_structure(field_list: int, size: int, name: str, properties: int = 0) -> bytes:
    # count(u16) property(u16) fieldlist(u32) derived(u32) vshape(u32) numeric-size(u16, direct) name cstr
    return (
        struct.pack("<HHIIIH", 0, properties, field_list, 0, 0, size)
        + name.encode()
        + b"\x00"
    )


def _lf_fieldlist(member_type: int, offset: int, name: str) -> bytes:
    # LF_MEMBER: fldattr(u16) type(u32) numeric offset(u16 direct) name
    return (
        struct.pack("<H", 0x150D)
        + struct.pack("<H", 3)  # public access
        + struct.pack("<I", member_type)
        + struct.pack("<H", offset)
        + name.encode()
        + b"\x00"
    )


def test_tpi_parses_pointer_and_procedure():
    records = [
        (LF_POINTER, _lf_pointer(T_VOID)),                              # 0x1000 void*
        (LF_ARGLIST, _lf_arglist([T_VOID])),                            # 0x1001
        (LF_PROCEDURE, _lf_procedure(T_VOID, 0, 1, 0x1001)),            # 0x1002 void(void*)
    ]
    tpi = TPIStream(tpi_stream(records))
    assert tpi.ti_min == 0x1000 and tpi.ti_max == 0x1003
    ptr = tpi.records[0x1000]
    assert isinstance(ptr, PointerRecord) and ptr.utype == T_VOID
    proc = tpi.records[0x1002]
    assert isinstance(proc, ProcedureRecord)
    assert proc.return_type == T_VOID and proc.arglist == 0x1001 and proc.param_count == 1


def test_tpi_parses_structure_with_fieldlist():
    # 0x1000 field list, 0x1001 struct referencing it.
    records = [
        (LF_FIELDLIST, _lf_fieldlist(T_VOID, 0, "member_a")),
        (LF_STRUCTURE, _lf_structure(0x1000, 16, "my_struct")),
    ]
    tpi = TPIStream(tpi_stream(records))
    field_list = tpi.records[0x1000]
    struct_rec = tpi.records[0x1001]
    assert isinstance(field_list, FieldListRecord)
    assert field_list.members[0].name == "member_a"
    assert field_list.members[0].offset == 0
    assert isinstance(struct_rec, AggregateRecord)
    assert struct_rec.name == "my_struct" and struct_rec.size_bytes == 16
    assert struct_rec.field_list == 0x1000


def test_tpi_forward_ref_flag():
    records = [
        (LF_STRUCTURE, _lf_structure(0, 0, "fwd", properties=0x1)),   # forward reference
        (LF_STRUCTURE, _lf_structure(0, 8, "fwd", properties=0x0)),   # real definition
    ]
    tpi = TPIStream(tpi_stream(records))
    assert tpi.records[0x1000].is_forward_ref is True
    assert tpi.records[0x1001].is_forward_ref is False


def test_tpi_rejects_truncated_header():
    with pytest.raises(PDBFormatError):
        TPIStream(b"\x00" * 10)


def test_tpi_rejects_record_exceeding_stream():
    # Header claims a large record region but provides too few bytes.
    header = struct.pack("<IIIII", 0x0131CA0B, 56, 0x1000, 0x1001, 4096)
    header += b"\x00" * 36
    with pytest.raises(PDBFormatError):
        TPIStream(header + b"\x02\x00\x02\x10")


def test_tpi_oversized_record_does_not_crash():
    # A record whose declared length runs past the stream must raise a bounded error rather than run away.
    bad = struct.pack("<HH", 0xFFFF, LF_STRUCTURE) + b"\x00" * 8
    header = struct.pack("<IIIII", 0x0131CA0B, 56, 0x1000, 0x1001, len(bad))
    header += b"\x00" * 36
    with pytest.raises(PDBFormatError):
        TPIStream(header + bad)


# ---------------------------------------------------------------------------
# DBI / symbols
# ---------------------------------------------------------------------------


def test_dbi_header_basic():
    # Symbol record stream index 5 with one S_PUB32 record; no modules.
    pub_payload = struct.pack("<IIH", 0, 0x10, 1) + b"public_name\x00"
    symbols = symbol_record(0x110D, pub_payload)
    # Stream layout: 0..3 standard (DBI at index 3), index 4 unused, symbol stream at index 5.
    streams = [b"", b"", b"", dbi_stream(symbol_stream=5), b"", symbols]
    info = parse_dbi(streams[3], streams)
    assert info.machine == 0x8664
    names = [s.name for s in info.symbols if s.is_public]
    assert "public_name" in names


def test_dbi_rejects_bad_version():
    bad_header = bytearray(dbi_stream())
    struct.pack_into("<I", bad_header, 0, 0x12345678)  # corrupt signature
    with pytest.raises(PDBFormatError):
        parse_dbi(bytes(bad_header), [])


def test_dbi_malformed_symbol_record_is_skipped():
    # A valid PUB32 followed by a truncated frame; the valid one must still be returned.
    good = symbol_record(0x110D, struct.pack("<IIH", 0, 4, 1) + b"good_sym\x00")
    truncated = struct.pack("<HH", 4, 0x110D)  # claims 4 bytes but no payload follows
    # Symbol stream at index 4.
    streams = [b"", b"", b"", dbi_stream(symbol_stream=4), good + truncated]
    info = parse_dbi(streams[3], streams)
    assert any(s.name == "good_sym" for s in info.symbols)


# ---------------------------------------------------------------------------
# PE CodeView directory
# ---------------------------------------------------------------------------


def test_peinfo_returns_none_for_non_pe():
    # Not structurally a PE; should raise PEFormatError (a ValueError subclass path used by callers).
    from angr.analyses.pdb.peinfo import PEFormatError

    with pytest.raises(PEFormatError):
        read_codeview_info(b"MZ" + b"\x00" * 64)


def test_peinfo_missing_debug_directory():
    # Build a tiny PE with a data-directory debug entry of size zero.
    pe = _build_minimal_pe(debug_rva=0, debug_size=0)
    assert read_codeview_info(pe) is None


def test_peinfo_rsds_entry():
    cv = b"RSDS" + b"\x11" * 16 + struct.pack("<I", 7) + b"test.pdb\x00"
    pe = _build_minimal_pe(debug_rva=0x200, debug_size=28, cv_data=cv)
    info = read_codeview_info(pe)
    assert info is not None and info.signature == "RSDS"
    assert info.age == 7 and info.pdb_path == "test.pdb"
    assert info.is_pdb7


def _build_minimal_pe(debug_rva: int, debug_size: int, cv_data: bytes | None = None) -> bytes:
    """Construct a just-barely-valid PE with one .rdata section holding the debug directory and optional CV data."""
    # Layout: headers in first 0x200 file bytes, section raw data at 0x200 (RVA 0x200, identity-mapped).
    file_align = 0x200
    debug_entry = b""
    if debug_size:
        cv_rva = 0x200 + 28
        debug_entry = struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(cv_data), cv_rva, 0x200 + 28)
    section_data = debug_entry + (cv_data or b"")
    while len(section_data) % file_align:
        section_data += b"\x00"

    e_lfanew = 0x40
    coff = e_lfanew + 4
    opt = coff + 20
    data_dir_off = opt + 112  # PE32+
    num_sections = 1
    opt_size = 112 + 16 * 8
    section_table_off = opt + opt_size

    buf = bytearray(b"\x00" * (file_align + len(section_data)))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, coff, 0x8664, num_sections, 0, 0, 0, opt_size, 0)
    struct.pack_into("<H", buf, opt, 0x20B)  # PE32+
    struct.pack_into("<II", buf, data_dir_off + 6 * 8, debug_rva, debug_size)
    # One section, RVA == raw offset 0x200 for simplicity.
    name = b".rdata\x00\x00"
    struct.pack_into("<8sIIII", buf, section_table_off, name, len(section_data), 0x200, len(section_data), 0x200)
    buf[file_align : file_align + len(section_data)] = section_data
    return bytes(buf)
