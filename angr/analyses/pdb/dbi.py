"""
Parsing of the DBI (debug information) stream and its module/global symbol streams.

The DBI stream describes the object modules that make up the image, each with its own symbol stream, plus stream
indices for the global-symbol record stream and the public/global GSI hash streams. Symbol records name functions and
data by (section, offset) and carry a CodeView type index, which is everything the importer needs to bind types.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    DBI_VERSION_V70,
    PROC_SYMBOLS,
    S_GDATA32,
    S_LDATA32,
    S_PUB32,
    S_UDT,
)
from .msf import PDBFormatError
from .records import Cursor, iter_symbol_records

# Standard MSF stream indices.
STREAM_PDB = 1
STREAM_TPI = 2
STREAM_DBI = 3
STREAM_IPI = 4


@dataclass
class ModuleInfo:
    stream_index: int
    symbol_bytes: int
    c13_bytes: int
    name: str
    object_name: str
    section: int
    section_offset: int
    section_size: int


@dataclass
class SymbolEntry:
    name: str
    section: int
    offset: int
    type_index: int
    kind: int
    is_function: bool
    is_public: bool


@dataclass
class UDTEntry:
    name: str
    type_index: int


@dataclass
class DBIStreamInfo:
    machine: int
    flags: int
    age: int
    modules: list[ModuleInfo] = field(default_factory=list)
    global_symbol_stream: int = -1
    public_stream: int = -1
    # Stream indices from the optional debug header.
    section_header_stream: int = -1
    section_header_orig_stream: int = -1
    symbols: list[SymbolEntry] = field(default_factory=list)
    udts: list[UDTEntry] = field(default_factory=list)


def _parse_module_list(dbi: bytes, module_size: int) -> list[ModuleInfo]:
    modules: list[ModuleInfo] = []
    cur = Cursor(dbi, 64, 64 + module_size)
    while cur.remaining() > 0:
        # Fixed 64-byte ModuleInfo prefix (see LLVM ModuleInfo):
        #   SectionContribEntry (32 bytes), flags(u16), module sym stream(u16), sym bytes(u32),
        #   c11 bytes(u32), c13 bytes(u32), source file count(u16), pad(u16), unused(u32),
        #   source file name index(u32), pdb file path name index(u32)
        section = cur.u16()
        cur.u16()  # padding
        section_offset = cur.i32()
        section_size = cur.i32()
        cur.u32()  # characteristics
        cur.u16()  # module index
        cur.u16()  # padding
        cur.u32()  # data CRC
        cur.u32()  # reloc CRC
        cur.u16()  # flags
        stream_index = cur.u16()
        symbol_bytes = cur.u32()
        cur.u32()  # c11 line bytes
        c13_bytes = cur.u32()
        cur.u16()  # source file count
        cur.u16()  # padding
        cur.u32()  # unused
        cur.u32()  # source file name index
        cur.u32()  # pdb file path name index
        name = cur.cstring()
        object_name = cur.cstring()
        cur.align4()
        modules.append(
            ModuleInfo(
                stream_index=stream_index,
                symbol_bytes=symbol_bytes,
                c13_bytes=c13_bytes,
                name=name,
                object_name=object_name,
                section=section,
                section_offset=section_offset,
                section_size=section_size,
            )
        )
    return modules


def _parse_symbol_records(buf: bytes, size: int, skip_signature: bool):
    """Yield :class:`SymbolEntry` / :class:`UDTEntry` objects from a symbol stream.

    A single record that cannot be decoded (truncated name, unexpected layout), or a broken record frame, is handled
    gracefully: the records decoded before the failure are still produced rather than aborting the whole stream.
    """
    try:
        record_iter = iter_symbol_records(buf, 0, size, skip_signature)
        while True:
            try:
                kind, cur = next(record_iter)
            except StopIteration:
                break
            except PDBFormatError:
                # Framing is no longer trustworthy after a corrupt length; keep the records decoded so far.
                break
            try:
                if kind in PROC_SYMBOLS:
                    # S_LPROC32 / S_GPROC32 (and _ID variants):
                    #   type(u32), offset(u32), segment(u16), NUL name
                    type_index = cur.u32()
                    offset = cur.u32()
                    section = cur.u16()
                    name = cur.cstring()
                    yield SymbolEntry(name, section, offset, type_index, kind, True, False)
                elif kind in (S_GDATA32, S_LDATA32):
                    # S_GDATA32 / S_LDATA32: type(u32), offset(u32), segment(u16), NUL name
                    type_index = cur.u32()
                    offset = cur.u32()
                    section = cur.u16()
                    name = cur.cstring()
                    yield SymbolEntry(name, section, offset, type_index, kind, False, False)
                elif kind == S_PUB32:
                    # S_PUB32 has no type index: flags(u32), offset(u32), segment(u16), name
                    cur.u32()  # flags
                    offset = cur.u32()
                    section = cur.u16()
                    name = cur.cstring()
                    yield SymbolEntry(name, section, offset, 0, kind, False, True)
                elif kind == S_UDT:
                    # S_UDT: type(u32), NUL name.
                    type_index = cur.u32()
                    name = cur.cstring()
                    yield UDTEntry(name, type_index)
                # Thread-local (S_*THREAD32), thunks, constants and other record kinds have distinct layouts and are
                # not needed for function/global type binding, so they are intentionally ignored.
            except PDBFormatError:
                continue
    except PDBFormatError:
        # Even the initial region bounds were invalid; emit nothing.
        return


def parse_dbi(dbi: bytes, streams: list[bytes]) -> DBIStreamInfo:
    """
    Parse the DBI stream and walk the global and per-module symbol streams.

    :param dbi:      The DBI stream bytes.
    :param streams:  All MSF streams (indexed by stream number) so module/global streams can be read.
    """
    if len(dbi) < 64:
        raise PDBFormatError("DBI stream shorter than its 64-byte header")
    signature, version, age = struct.unpack_from("<III", dbi, 0)
    if signature != 0xFFFFFFFF or version != DBI_VERSION_V70:
        # Older/other versions are not supported; report rather than misparse.
        raise PDBFormatError(f"Unsupported DBI version {version:#x} (signature {signature:#x})")
    global_stream = struct.unpack_from("<h", dbi, 12)[0]
    public_stream = struct.unpack_from("<h", dbi, 16)[0]
    symbol_record_stream = struct.unpack_from("<H", dbi, 20)[0]
    module_size = struct.unpack_from("<i", dbi, 24)[0]
    section_contrib_size = struct.unpack_from("<i", dbi, 28)[0]
    section_map_size = struct.unpack_from("<i", dbi, 32)[0]
    source_info_size = struct.unpack_from("<i", dbi, 36)[0]
    type_server_size = struct.unpack_from("<i", dbi, 40)[0]
    optional_debug_size = struct.unpack_from("<i", dbi, 48)[0]
    flags, machine = struct.unpack_from("<HH", dbi, 56)

    if module_size < 0 or 64 + module_size > len(dbi):
        raise PDBFormatError("DBI module info substream exceeds stream bounds")
    modules = _parse_module_list(dbi, module_size)

    info = DBIStreamInfo(
        machine=machine,
        flags=flags,
        age=age,
        modules=modules,
        global_symbol_stream=global_stream,
        public_stream=public_stream,
    )

    # Locate the optional debug header (11 int16 stream indices) after the fixed-size substreams.
    optional_off = (
        64
        + module_size
        + max(section_contrib_size, 0)
        + max(section_map_size, 0)
        + max(source_info_size, 0)
        + max(type_server_size, 0)
    )
    if optional_debug_size >= 22 and optional_off + 22 <= len(dbi):
        debug_streams = struct.unpack_from("<11h", dbi, optional_off)
        info.section_header_stream = debug_streams[5]
        info.section_header_orig_stream = debug_streams[10]

    def get_stream(idx: int) -> bytes | None:
        if idx < 0 or idx >= len(streams):
            return None
        return streams[idx]

    # Global symbol record stream: holds the canonical S_*PROC32 / S_*DATA32 definitions and S_UDT names.
    gsym = get_stream(symbol_record_stream)
    if gsym is not None:
        for entry in _parse_symbol_records(gsym, len(gsym), skip_signature=False):
            if isinstance(entry, UDTEntry):
                info.udts.append(entry)
            else:
                info.symbols.append(entry)

    # Per-module symbol streams: pick up any definitions not present in the global stream and additional UDT names.
    seen_locations = {(s.section, s.offset, s.name) for s in info.symbols}
    for module in modules:
        if module.stream_index <= 0 or module.symbol_bytes <= 0:
            continue
        mstream = get_stream(module.stream_index)
        if mstream is None or module.symbol_bytes > len(mstream):
            continue
        for entry in _parse_symbol_records(mstream, module.symbol_bytes, skip_signature=True):
            if isinstance(entry, UDTEntry):
                info.udts.append(entry)
                continue
            key = (entry.section, entry.offset, entry.name)
            if key not in seen_locations:
                seen_locations.add(key)
                info.symbols.append(entry)

    return info
