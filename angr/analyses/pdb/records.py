"""
Bounded binary readers and CodeView record framing.

Everything that walks untrusted PDB bytes goes through :class:`Cursor`, which raises :class:`PDBFormatError` on any
out-of-bounds read or malformed encoding. This keeps malformed/truncated streams from ever producing ``struct.error``
or running off the end of a buffer.
"""

from __future__ import annotations

import struct

from .constants import (
    LF_CHAR,
    LF_LONG,
    LF_OCTWORD,
    LF_QUADWORD,
    LF_REAL128,
    LF_REAL32,
    LF_REAL48,
    LF_REAL64,
    LF_REAL80,
    LF_SHORT,
    LF_UOCTWORD,
    LF_UQUADWORD,
    LF_ULONG,
    LF_USHORT,
)
from .msf import PDBFormatError


class Cursor:
    """A little-endian, bounds-checked cursor over an immutable bytes buffer."""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf: bytes, start: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end
        if self.end > len(buf) or self.pos < 0 or self.pos > self.end:
            raise PDBFormatError("Cursor initialized outside buffer bounds")

    def remaining(self) -> int:
        return self.end - self.pos

    def align4(self) -> None:
        self.pos = (self.pos + 3) & ~3

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise PDBFormatError("Read exceeds buffer bounds")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        if self.pos + 1 > self.end:
            raise PDBFormatError("u8 read exceeds buffer bounds")
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def i8(self) -> int:
        return struct.unpack("<b", self.take(1))[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def i16(self) -> int:
        return struct.unpack("<h", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def cstring(self) -> str:
        """Read a NUL-terminated byte string (CodeView names are UTF-8/latin-1)."""
        end = self.buf.find(b"\x00", self.pos, self.end)
        if end < 0:
            raise PDBFormatError("Unterminated string in record")
        raw = self.buf[self.pos : end]
        self.pos = end + 1
        return raw.decode("utf-8", errors="replace")

    def numeric(self) -> int:
        """
        Read a CodeView "numeric" value. Values below ``LF_CHAR`` (0x8000) are a bare u16; larger values are a leaf
        tag followed by the appropriately sized integer.
        """
        tag = self.u16()
        if tag < LF_CHAR:
            return tag
        if tag == LF_CHAR:
            return self.i8()
        if tag == LF_SHORT:
            return self.i16()
        if tag == LF_USHORT:
            return self.u16()
        if tag in (LF_LONG,):
            return self.i32()
        if tag in (LF_ULONG, LF_REAL32):
            return self.u32()
        if tag in (LF_QUADWORD, LF_REAL64):
            return self.i64()
        if tag in (LF_UQUADWORD, LF_REAL80, LF_REAL128):
            # REAL80 is 10 bytes and REAL128 16, but they only ever describe floating aggregate sizes; consume the
            # integer width we need for layout bookkeeping.
            return self.u64()
        if tag in (LF_OCTWORD, LF_UOCTWORD):
            return self.u64()
        if tag == LF_REAL48:
            self.take(6)
            return 48 // 8
        raise PDBFormatError(f"Unsupported numeric leaf {tag:#x}")


def iter_type_records(buf: bytes, header_size: int, record_bytes: int):
    """
    Yield ``(record_offset, leaf, body_cursor)`` for each record in a TPI/IPI stream.

    Type records are framed as ``u16 length`` (covering leaf + body, excluding the length itself) then ``u16 leaf``.
    The length prefix counts the 2-byte leaf, so when it is odd the whole record is padded by one byte to keep the
    next record on a 2-byte boundary (verified against both TPI and IPI streams of real MSVC PDBs).
    """
    end = header_size + record_bytes
    if end > len(buf) or header_size < 0 or record_bytes < 0:
        raise PDBFormatError("TPI record region exceeds stream bounds")
    pos = header_size
    while pos < end:
        if pos + 4 > end:
            raise PDBFormatError("Truncated type record header")
        length, leaf = struct.unpack_from("<HH", buf, pos)
        record_end = pos + 2 + length
        if length < 2 or record_end > end:
            raise PDBFormatError("Type record length exceeds stream bounds")
        yield pos, leaf, Cursor(buf, pos + 4, record_end)
        # An odd record length (leaf + body) means one padding byte follows.
        pos = record_end + (length & 1)


def iter_symbol_records(buf: bytes, start: int, size: int, skip_signature: bool):
    """
    Yield ``(kind, body_cursor)`` for CodeView symbol records in a module or global symbol stream.

    Module symbol streams begin with a 4-byte signature that must be skipped; the global symbol record stream does
    not. Each record is ``u16 length`` (leaf kind + body, excluding the length) + ``u16 kind``, 4-byte aligned.
    """
    region_end = start + size
    if region_end > len(buf) or start < 0 or size < 0:
        raise PDBFormatError("Symbol region exceeds stream bounds")
    pos = start + (4 if skip_signature else 0)
    while pos + 4 <= region_end:
        length, kind = struct.unpack_from("<HH", buf, pos)
        record_end = pos + 2 + length
        if length < 2 or record_end > region_end:
            raise PDBFormatError("Symbol record length exceeds stream bounds")
        yield kind, Cursor(buf, pos + 4, record_end)
        pos = (record_end + 3) & ~3
