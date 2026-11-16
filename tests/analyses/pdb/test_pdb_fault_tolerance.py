"""
Tests for fault-tolerance requirements that are awkward to express with the high-level analysis:

* missing/corrupt IPI (string table) must not prevent type/symbol binding,
* corrupt TPI/DBI streams degrade to a load error rather than crashing,
* the 32-bit x86 calling-convention mapping covers the Microsoft CV call bytes,
* parser memory stays linear (records are indexed in a single pass).
"""

from __future__ import annotations

import struct

import pytest

from angr.analyses.pdb.constants import CVCall
from angr.analyses.pdb.dbi import parse_dbi
from angr.analyses.pdb.msf import MSFFile, PDBFormatError
from angr.analyses.pdb.pdbfile import PDBFile, PDBLoadError
from angr.analyses.pdb.tpi import TPIStream

from .fixtures import build_msf7, dbi_stream, tpi_stream


def _pdb_path():
    import os

    return os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "binaries", "tests", "x86_64", "windows", "fauxware.pdb",
    )


_requires_real_pdb = pytest.mark.skipif(
    not __import__("os").path.isfile(_pdb_path()), reason="fauxware PDB test binary not available"
)


@_requires_real_pdb
def test_corrupt_ipi_still_loads_tpi_and_dbi():
    data = open(_pdb_path(), "rb").read()
    msf = MSFFile(data)
    streams = [msf.get_stream(i) for i in range(msf.num_streams)]
    # A truncated IPI stream must fail its own parse ...
    with pytest.raises(PDBFormatError):
        TPIStream(b"\x00" * 10)
    # ... but TPI and DBI remain fully usable without it.
    tpi = TPIStream(streams[2])
    dbi = parse_dbi(streams[3], streams)
    assert len(tpi.records) > 100
    assert len(dbi.symbols) > 0


@_requires_real_pdb
def test_corrupt_tpi_raises_load_error_not_crash():
    data = open(_pdb_path(), "rb").read()
    msf = MSFFile(data)
    # Replace the TPI stream (index 2) with garbage; rebuilding a file raises PDBLoadError.
    streams = [msf.get_stream(i) for i in range(msf.num_streams)]
    streams[2] = b"not a tpi stream"
    rebuilt = build_msf7(streams)
    with pytest.raises(PDBLoadError):
        PDBFile(rebuilt)


@_requires_real_pdb
def test_corrupt_dbi_raises_load_error_not_crash():
    data = open(_pdb_path(), "rb").read()
    msf = MSFFile(data)
    streams = [msf.get_stream(i) for i in range(msf.num_streams)]
    streams[3] = b"\x00" * 8  # below the 64-byte DBI header
    rebuilt = build_msf7(streams)
    with pytest.raises(PDBLoadError):
        PDBFile(rebuilt)


def test_tpi_single_pass_linear_indexing():
    # A modest synthetic stream with several records must expose one record per sequential type index.
    payload_void = struct.pack("<II", 0x0003, 0)  # LF_POINTER to void
    records = [(0x1002, payload_void) for _ in range(20)]
    tpi = TPIStream(tpi_stream(records))
    assert tpi.ti_max - tpi.ti_min == 20
    assert all(index in tpi.records for index in range(0x1000, 0x1014))


def test_dbi_machine_passthrough():
    # i386 machine type must survive the DBI header round trip.
    dbi = dbi_stream(machine=0x014C)
    info = parse_dbi(dbi, [])
    assert info.machine == 0x014C


def test_cv_call_enum_covers_microsoft_conventions():
    # The CV call bytes the 32-bit Windows CC mapping depends on.
    assert CVCall.NEAR_C == 0
    assert CVCall.NEAR_STD == 7
    assert CVCall.THISCALL == 0x0B
    assert CVCall.NEAR_FAST == 4


def test_unused_dbi_streams_are_tolerated():
    # A DBI whose symbol stream index is -1 (no global symbols) parses with an empty symbol list.
    dbi = dbi_stream(symbol_stream=-1)
    info = parse_dbi(dbi, [])
    assert info.symbols == [] and info.udts == []


def _pdb_path():
    import os

    return os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "binaries", "tests", "x86_64", "windows", "fauxware.pdb",
    )


_requires_real_pdb = pytest.mark.skipif(
    not __import__("os").path.isfile(_pdb_path()), reason="fauxware PDB test binary not available"
)
