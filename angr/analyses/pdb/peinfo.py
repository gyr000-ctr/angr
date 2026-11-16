"""
Minimal, dependency-free extraction of the CodeView debug entry from a PE image's debug directory.

Only the structures needed to locate an associated PDB (the ``RSDS`` CodeView record carrying GUID, age and PDB file
name) are parsed. Everything is read from raw file bytes via :mod:`struct`, so no ``pefile`` dependency is required
and the same logic works for PE objects cle loaded from a stream.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IMAGE_DEBUG_TYPE_CODEVIEW = 2
CV_SIGNATURE_RSDS = b"RSDS"
CV_SIGNATURE_NB10 = b"NB10"


class PEFormatError(Exception):
    """Raised when PE bytes cannot be navigated to the debug directory."""


@dataclass
class CodeViewInfo:
    """Information from an IMAGE_DEBUG_TYPE_CODEVIEW debug entry."""

    signature: str  # "RSDS" or "NB10"
    guid: str | None
    age: int
    pdb_path: str
    raw_data: bytes

    @property
    def is_pdb7(self) -> bool:
        return self.signature == "RSDS"


def _rva_to_file_offset(sections, rva):
    for name, vaddr, virtual_size, raw_addr, raw_size in sections:
        span = max(virtual_size, raw_size)
        if vaddr <= rva < vaddr + span:
            return raw_addr + (rva - vaddr)
    raise PEFormatError(f"RVA {rva:#x} does not fall within any section")


def _parse_sections(data, coff_off, num_sections, opt_header_size):
    section_table_off = coff_off + 20 + opt_header_size
    sections = []
    for i in range(num_sections):
        base = section_table_off + i * 40
        if base + 40 > len(data):
            raise PEFormatError("Section table exceeds file bounds")
        name = data[base : base + 8].rstrip(b"\x00").decode("latin1")
        virtual_size, vaddr, raw_size, raw_addr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((name, vaddr, virtual_size, raw_addr, raw_size))
    return sections


def read_codeview_info(data: bytes) -> CodeViewInfo | None:
    """
    Return the first CodeView (type 2) debug entry, or ``None`` if the image has none.

    Raises :class:`PEFormatError` only for structurally invalid PE bytes; a missing/empty debug directory yields
    ``None``.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("Not an MZ/PE image")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEFormatError("Missing or invalid PE signature")
    coff = e_lfanew + 4
    _machine, num_sections, _timestamp, _ptr_symtab, _num_syms, opt_size, _chars = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt = coff + 20
    if opt + opt_size > len(data) or opt_size < 2:
        raise PEFormatError("Optional header exceeds file bounds")
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32_plus = magic == 0x20B
    # Data directory starts after the standard+Windows-specific optional header fields.
    data_dir_off = opt + (112 if is_pe32_plus else 96)
    # Debug directory is data directory index 6.
    if data_dir_off + 8 * 7 > len(data):
        return None
    debug_rva, debug_size = struct.unpack_from("<II", data, data_dir_off + 6 * 8)
    if debug_rva == 0 or debug_size == 0:
        return None
    sections = _parse_sections(data, coff, num_sections, opt_size)
    debug_file_off = _rva_to_file_offset(sections, debug_rva)
    num_entries = debug_size // 28
    for i in range(num_entries):
        entry = debug_file_off + i * 28
        if entry + 28 > len(data):
            raise PEFormatError("Debug directory entry exceeds file bounds")
        (
            _characteristics,
            _timestamp,
            _major,
            _minor,
            entry_type,
            data_size,
            _rva,
            raw_ptr,
        ) = struct.unpack_from("<IIHHIIII", data, entry)
        if entry_type != IMAGE_DEBUG_TYPE_CODEVIEW or raw_ptr == 0 or data_size == 0:
            continue
        if raw_ptr + data_size > len(data):
            raise PEFormatError("CodeView debug data exceeds file bounds")
        raw = data[raw_ptr : raw_ptr + data_size]
        return _decode_codeview(raw)
    return None


def _decode_codeview(raw: bytes) -> CodeViewInfo | None:
    if raw[:4] == CV_SIGNATURE_RSDS and len(raw) >= 24:
        import uuid

        guid = str(uuid.UUID(bytes_le=raw[4:20]))
        (age,) = struct.unpack_from("<I", raw, 20)
        path = raw[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return CodeViewInfo("RSDS", guid, age, path, raw)
    if raw[:4] == CV_SIGNATURE_NB10 and len(raw) >= 16:
        _offset, _timestamp, age = struct.unpack_from("<III", raw, 4)
        path = raw[16:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return CodeViewInfo("NB10", None, age, path, raw)
    return None
