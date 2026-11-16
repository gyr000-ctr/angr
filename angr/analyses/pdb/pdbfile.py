"""
High-level, fault-tolerant PDB reader.

:class:`PDBFile` assembles the MSF container, TPI/IPI type streams and DBI debug stream into one object, and
:func:`load_pdb` adds a process-wide, path-keyed cache so repeated queries never re-read or re-parse a file.

Any structural failure raises :class:`PDBLoadError`; the analysis layer treats that as "no type information" and
leaves the project unchanged.
"""

from __future__ import annotations

import logging
import os
import struct
import threading

from .dbi import STREAM_DBI, STREAM_IPI, STREAM_TPI, DBIStreamInfo, parse_dbi
from .msf import MSFFile, PDBFormatError
from .tpi import TPIStream

_l = logging.getLogger(__name__)


class PDBLoadError(Exception):
    """Raised when a PDB cannot be loaded or is missing required streams."""


class PDBFile:
    """
    A parsed PDB: container, type information and debug/symbol information.

    :ivar msf:        The :class:`MSFFile` container.
    :ivar tpi:        The :class:`TPIStream` type stream.
    :ivar ipi:        The IPI stream, or ``None``.
    :ivar dbi:        The parsed :class:`DBIStreamInfo`.
    :ivar guid/age:   Identity fields from the PDB info stream (best-effort; may be ``None`` on malformed input).
    """

    def __init__(self, data: bytes):
        try:
            self.msf = MSFFile(data)
            self.tpi = self._load_tpi()
            self.ipi = self._load_ipi()
            self.dbi = self._load_dbi()
            self.guid, self.age = self._read_identity()
        except PDBFormatError as ex:
            raise PDBLoadError(str(ex)) from ex

    def _stream(self, index: int) -> bytes:
        if not self.msf.has_stream(index):
            raise PDBLoadError(f"Required PDB stream {index} is missing")
        return self.msf.get_stream(index)

    def _load_tpi(self) -> TPIStream:
        return TPIStream(self._stream(STREAM_TPI), is_ipi=False)

    def _load_ipi(self) -> TPIStream | None:
        if not self.msf.has_stream(STREAM_IPI):
            return None
        try:
            return TPIStream(self.msf.get_stream(STREAM_IPI), is_ipi=True)
        except PDBFormatError as ex:
            # The string table is optional for type binding; degrade gracefully.
            _l.debug("IPI stream unusable, continuing without string table: %s", ex)
            return None

    def _load_dbi(self) -> DBIStreamInfo:
        dbi_bytes = self._stream(STREAM_DBI)
        all_streams = [self.msf.get_stream(i) for i in range(self.msf.num_streams)]
        return parse_dbi(dbi_bytes, all_streams)

    def _read_identity(self) -> tuple[str | None, int | None]:
        try:
            import uuid

            info = self.msf.get_stream(1)
            if len(info) < 28:
                return None, None
            _version, _timestamp, age = struct.unpack_from("<III", info, 0)
            guid = str(uuid.UUID(bytes_le=info[12:28]))
            return guid, age
        except Exception:  # pragma: no cover - identity is best-effort
            return None, None

    # Convenience accessors -------------------------------------------------

    @property
    def machine(self) -> int:
        return self.dbi.machine

    @property
    def symbols(self):
        return self.dbi.symbols

    @property
    def udts(self):
        return self.dbi.udts


# Process-wide cache: absolute path / mtime / size -> parsed PDBFile. The value also stores the identity so a
# changed file is re-parsed rather than returning stale data.
_CACHE_LOCK = threading.Lock()
_PDB_CACHE: dict[str, tuple[tuple[int, int, int], PDBFile]] = {}


def load_pdb(path: str) -> PDBFile:
    """
    Load (and cache) a PDB from disk.

    The cache key is the absolute path plus ``(mtime, size)``; queries after the first never re-read the file, and an
    edited/replaced PDB is detected and re-parsed.
    """
    abs_path = os.path.abspath(path)
    try:
        stat = os.stat(abs_path)
    except OSError as ex:
        raise PDBLoadError(f"PDB not found: {abs_path}") from ex
    key_token = (int(stat.st_mtime), stat.st_size, stat.st_ino)

    with _CACHE_LOCK:
        cached = _PDB_CACHE.get(abs_path)
        if cached is not None and cached[0] == key_token:
            return cached[1]

    with open(abs_path, "rb") as fp:
        data = fp.read()
    pdb = PDBFile(data)

    with _CACHE_LOCK:
        _PDB_CACHE[abs_path] = (key_token, pdb)
    return pdb


def clear_pdb_cache() -> None:
    """Drop all cached PDBs (used by tests and when files are replaced on disk)."""
    with _CACHE_LOCK:
        _PDB_CACHE.clear()
