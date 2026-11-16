"""
MSF (Multi-Stream File) container parsing for Microsoft PDB files.

A PDB file is an MSF container: a fixed-size header (the "superblock"), a stream directory describing every stream
(size + page list), and the streams themselves stored as sequences of fixed-size pages. Both the historical
"PDB 2.0" (``Microsoft C/C++ program database 2.00``) and the modern "MSF 7.0" layouts are supported.

The parser deliberately keeps the whole file in a single ``bytes`` object and materializes each stream lazily as a
``bytes`` slice. Memory use is therefore linear in the file size plus the sum of the streams that are actually read,
and no stream is ever re-read from disk after construction.

Every structural inconsistency raises :class:`PDBFormatError`; callers treat that as "no debug info available" rather
than letting it escape.
"""

from __future__ import annotations

import struct

MSF7_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
MSF7_SIGNATURE_LEN = len(MSF7_SIGNATURE)
MSF2_SIGNATURE = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00"
MSF2_SIGNATURE_LEN = len(MSF2_SIGNATURE)

# A stream whose stored size is this sentinel is reserved/unused.
INVALID_STREAM_SIZE = 0xFFFFFFFF


class PDBFormatError(Exception):
    """Raised when PDB/MSF bytes are structurally invalid and cannot be parsed."""


def _ceil_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise PDBFormatError("Non-positive page size")
    return (numerator + denominator - 1) // denominator


class MSFFile:
    """
    A parsed MSF container.

    :ivar page_size:      Page size in bytes (always a power of two in practice).
    :ivar num_pages:      Number of pages in the file.
    :ivar version:        Either ``7`` or ``2``.
    :ivar stream_sizes:   Tuple of stream sizes in bytes.
    :ivar stream_pages:   Tuple of tuples of page numbers, one entry per stream (``()`` for empty streams).
    """

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise PDBFormatError("PDB data must be a bytes-like object")
        self._data = bytes(data)
        self.page_size = 0
        self.num_pages = 0
        self.version = 0
        self.stream_sizes: tuple[int, ...] = ()
        self.stream_pages: tuple[tuple[int, ...], ...] = ()
        self._stream_cache: dict[int, bytes] = {}
        self._parse()

    #
    # Container parsing
    #

    def _parse(self) -> None:
        data = self._data
        if len(data) >= MSF7_SIGNATURE_LEN and data[:MSF7_SIGNATURE_LEN] == MSF7_SIGNATURE:
            self.version = 7
            self._parse_msf7(data)
        elif len(data) >= MSF2_SIGNATURE_LEN and data[:MSF2_SIGNATURE_LEN] == MSF2_SIGNATURE:
            self.version = 2
            self._parse_msf2(data)
        else:
            raise PDBFormatError("Unrecognized MSF/PDB signature")

    def _parse_msf7(self, data: bytes) -> None:
        # Superblock layout immediately after the 32-byte signature:
        #   u32 page_size, u32 free_page_map, u32 num_pages, u32 directory_size, u32 reserved
        off = MSF7_SIGNATURE_LEN
        if len(data) < off + 20:
            raise PDBFormatError("Truncated MSF 7.0 superblock")
        page_size, _free_map, num_pages, directory_size, _reserved = struct.unpack_from("<IIIII", data, off)
        if page_size == 0 or page_size & (page_size - 1) != 0:
            raise PDBFormatError(f"Invalid MSF page size {page_size}")
        if num_pages == 0 or num_pages * page_size > len(data):
            raise PDBFormatError("MSF page count exceeds file size")
        self.page_size = page_size
        self.num_pages = num_pages

        # The superblock holds the list of "directory page table" pages. Each table page contains page numbers of the
        # pages that make up the actual stream directory (one level of indirection).
        num_root_pages = _ceil_div(directory_size, page_size)
        num_table_pages = _ceil_div(num_root_pages * 4, page_size)
        table_off = off + 20
        table_end = table_off + num_table_pages * 4
        if table_end > len(data):
            raise PDBFormatError("MSF directory page table exceeds file bounds")
        table_pages = struct.unpack_from(f"<{num_table_pages}I", data, table_off)

        directory_pages: list[int] = []
        for table_page in table_pages:
            if table_page >= num_pages:
                raise PDBFormatError("MSF directory page table references an out-of-range page")
            directory_pages.extend(
                struct.unpack_from(f"<{page_size // 4}I", data, table_page * page_size)
            )
        directory_pages = directory_pages[:num_root_pages]
        directory = self._read_pages(directory_pages, directory_size)
        self._parse_directory(directory, page_pointer_width=4)

    def _parse_msf2(self, data: bytes) -> None:
        # PDB 2.0 superblock: signature, u32 page_size, u16 start_page, u16 num_pages, u32 directory_size, u32 reserved
        off = MSF2_SIGNATURE_LEN
        if len(data) < off + 16:
            raise PDBFormatError("Truncated MSF 2.0 superblock")
        page_size, _start_page, num_pages, directory_size, _reserved = struct.unpack_from("<IHHII", data, off)
        if page_size == 0 or page_size & (page_size - 1) != 0:
            raise PDBFormatError(f"Invalid MSF page size {page_size}")
        self.page_size = page_size
        self.num_pages = num_pages
        num_root_pages = _ceil_div(directory_size, page_size)
        root_off = off + 16
        if root_off + num_root_pages * 2 > len(data):
            raise PDBFormatError("MSF 2.0 root page list exceeds file bounds")
        root_pages = struct.unpack_from(f"<{num_root_pages}H", data, root_off)
        directory = self._read_pages(root_pages, directory_size)
        self._parse_directory(directory, page_pointer_width=2)

    def _parse_directory(self, directory: bytes, page_pointer_width: int) -> None:
        if len(directory) < 4:
            raise PDBFormatError("Empty MSF stream directory")
        (num_streams,) = struct.unpack_from("<I", directory, 0)
        # A reasonable upper bound: the directory cannot hold more (size, page-list) entries than its own bytes.
        if num_streams > len(directory) // 4:
            raise PDBFormatError("Implausible stream count in MSF directory")

        cursor = 4
        sizes: list[int] = []
        for _ in range(num_streams):
            (raw_size,) = struct.unpack_from("<I", directory, cursor)
            cursor += 4
            sizes.append(0 if raw_size == INVALID_STREAM_SIZE else raw_size)

        stream_pages: list[tuple[int, ...]] = []
        for size in sizes:
            count = _ceil_div(size, self.page_size) if size else 0
            if page_pointer_width == 4:
                needed = count * 4
                if cursor + needed > len(directory):
                    raise PDBFormatError("Truncated MSF stream page list")
                pages = struct.unpack_from(f"<{count}I", directory, cursor) if count else ()
            else:
                needed = count * 2
                if cursor + needed > len(directory):
                    raise PDBFormatError("Truncated MSF stream page list")
                pages = struct.unpack_from(f"<{count}H", directory, cursor) if count else ()
            cursor += needed
            for page in pages:
                if page >= self.num_pages:
                    raise PDBFormatError("Stream page references an out-of-range MSF page")
            stream_pages.append(tuple(pages))

        self.stream_sizes = tuple(sizes)
        self.stream_pages = tuple(stream_pages)

    def _read_pages(self, pages, size: int) -> bytes:
        page_size = self.page_size
        chunks = []
        for page in pages:
            start = page * page_size
            if start >= len(self._data):
                raise PDBFormatError("Page read beyond end of PDB file")
            chunks.append(self._data[start : start + page_size])
        joined = b"".join(chunks)
        if size > len(joined):
            raise PDBFormatError("Stream shorter than its declared size")
        return joined[:size]

    #
    # Public API
    #

    @property
    def num_streams(self) -> int:
        return len(self.stream_sizes)

    def has_stream(self, index: int) -> bool:
        return 0 <= index < self.num_streams and self.stream_sizes[index] > 0

    def get_stream(self, index: int) -> bytes:
        """Return the (cached) bytes of stream ``index``; empty bytes for unused streams."""
        if index < 0 or index >= self.num_streams:
            raise PDBFormatError(f"Stream index {index} out of range")
        cached = self._stream_cache.get(index)
        if cached is not None:
            return cached
        size = self.stream_sizes[index]
        if size == 0:
            self._stream_cache[index] = b""
            return b""
        raw = self._read_pages(self.stream_pages[index], size)
        self._stream_cache[index] = raw
        return raw


def parse_msf(data: bytes) -> MSFFile:
    """Convenience wrapper around :class:`MSFFile`."""
    return MSFFile(data)
