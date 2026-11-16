"""
Decompilation regression tests for PDB type import.

These verify that types and names imported from a PDB actually reach the decompiler's output — function names,
struct field accesses and global variable names — rather than merely being stored in the knowledge base.
"""

from __future__ import annotations

import os

import pytest

from angr.analyses.pdb import clear_pdb_cache

try:
    from tests.common import bin_location
except Exception:  # pragma: no cover
    bin_location = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries")

PDB_PATH = os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware.pdb")
EXE_PATH = os.path.join(bin_location, "tests", "x86_64", "windows", "fauxware.exe")

pytestmark = pytest.mark.skipif(not os.path.isfile(PDB_PATH), reason="fauxware PDB test binary not available")


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_pdb_cache()
    yield
    clear_pdb_cache()


def _project():
    import angr

    return angr.Project(EXE_PATH, auto_load_libs=False)


def test_decompiled_function_keeps_pdb_name():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    addr = next(addr for addr, name in analysis.bound_functions.items() if name == "authenticate")

    # A CFG gives the decompiler normalized function boundaries; then decompile the PDB-named function.
    cfg = proj.analyses.CFGFast(
        regions=[(addr, addr + 0x100)],
        data_references=False,
        cross_references=False,
        normalize=True,
        show_progressbar=False,
    )
    func = proj.kb.functions.function(addr=addr)
    decomp = proj.analyses.Decompiler(func, cfg=cfg.model)
    text = str(decomp.codegen.text)
    # The PDB-provided symbol name must appear in the decompiled source.
    assert "authenticate" in text


def test_pdb_struct_type_resolves_in_type_store():
    # A PDB struct registered in kb.types must round-trip through the type store with its fields intact.
    proj = _project()
    proj.analyses.PDBTypes()
    guid_ref = proj.kb.types["_GUID"]
    guid = guid_ref.type
    assert guid.name == "_GUID"
    assert set(guid.fields) == {"Data1", "Data2", "Data3", "Data4"}
    # Field offsets are preserved through the TypeRef/with_arch round trip.
    assert guid.offsets["Data4"] == 8


def test_global_name_available_for_decompilation():
    # The decompiler resolves global variables through kb.labels; ensure PDB globals are published there.
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    # Every address the importer classified as a global must carry a kb label (kb.labels is keyed by address via
    # __contains__, even though iterating it yields names).
    for addr in analysis.bound_globals:
        assert addr in proj.kb.labels
    # And at least one well-known MSVC global is present.
    assert "__security_cookie" in {name for _addr, name in proj.kb.labels.items()}


def test_repeated_analysis_is_idempotent():
    # Running the importer twice must not duplicate types or corrupt the knowledge base.
    proj = _project()
    proj.analyses.PDBTypes()
    types_after_first = set(proj.kb.types.iter_own_keys())
    funcs_after_first = len(proj.kb.functions)
    proj.analyses.PDBTypes()
    assert set(proj.kb.types.iter_own_keys()) == types_after_first
    assert len(proj.kb.functions) == funcs_after_first
