"""
End-to-end tests for PDB type/symbol import against a real MSVC PDB.

These use the matched ``fauxware.exe`` / ``fauxware.pdb`` pair from the angr binaries repository. If the binaries are
not checked out (the normal case in minimal environments), the whole module is skipped so the unit tests still run.
"""

from __future__ import annotations

import os

import pytest

from angr.analyses.pdb import clear_pdb_cache, load_pdb
from angr.analyses.pdb.peinfo import read_codeview_info
from angr.sim_type import SimTypeEnum, SimTypeFunction, SimStruct, SimUnion

try:
    from tests.common import bin_location
except Exception:  # pragma: no cover
    bin_location = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries")

WINDOWS_DIR = os.path.join(bin_location, "tests", "x86_64", "windows")
EXE_PATH = os.path.join(WINDOWS_DIR, "fauxware.exe")
PDB_PATH = os.path.join(WINDOWS_DIR, "fauxware.pdb")

pytestmark = pytest.mark.skipif(not os.path.isfile(PDB_PATH), reason="fauxware PDB test binary not available")


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_pdb_cache()
    yield
    clear_pdb_cache()


def _project():
    import angr

    return angr.Project(EXE_PATH, auto_load_libs=False)


# ---------------------------------------------------------------------------
# Container / stream parsing
# ---------------------------------------------------------------------------


def test_real_msf_and_streams():
    pdb = load_pdb(PDB_PATH)
    assert pdb.msf.version == 7
    assert pdb.msf.num_streams > 10
    # Standard streams 1..4 must all be present and non-empty.
    for stream_index in (1, 2, 3, 4):
        assert pdb.msf.has_stream(stream_index)
    assert len(pdb.tpi.records) > 100
    assert pdb.ipi is not None and len(pdb.ipi.records) > 0
    assert pdb.dbi.machine == 0x8664


def test_pe_codeview_reference_matches_pdb():
    with open(EXE_PATH, "rb") as fp:
        cv = read_codeview_info(fp.read())
    assert cv is not None and cv.signature == "RSDS"
    pdb = load_pdb(PDB_PATH)
    # The GUID/age embedded in the PE must match the identity in the PDB.
    assert cv.guid == pdb.guid
    assert cv.age == pdb.age


def test_pdb_cache_returns_same_object():
    first = load_pdb(PDB_PATH)
    second = load_pdb(PDB_PATH)
    assert first is second


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------


def test_struct_field_offsets_match_pdb():
    proj = _project()
    proj.analyses.PDBTypes()
    guid = proj.kb.types["_GUID"].type
    assert isinstance(guid, SimStruct)
    assert guid.size == 128  # 16 bytes
    assert guid.offsets["Data1"] == 0
    assert guid.offsets["Data2"] == 4
    assert guid.offsets["Data3"] == 6
    assert guid.offsets["Data4"] == 8


def test_named_aggregate_and_enum_registered():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    # A representative struct, union and enum exist among the bound types.
    assert any(kind == "struct" for kind in analysis.bound_types.values())
    assert any(kind == "union" for kind in analysis.bound_types.values())
    assert any(kind == "enum" for kind in analysis.bound_types.values())

    enum_names = [n for n, k in analysis.bound_types.items() if k == "enum"]
    sample = proj.kb.types[enum_names[0]].type
    assert isinstance(sample, SimTypeEnum) and len(sample.members) > 0


def test_struct_and_union_namespaced_aliases():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    struct_name = next(n for n, k in analysis.bound_types.items() if k == "struct")
    union_name = next(n for n, k in analysis.bound_types.items() if k == "union")
    assert f"struct {struct_name}" in proj.kb.types
    assert f"union {union_name}" in proj.kb.types
    assert isinstance(proj.kb.types[f"union {union_name}"].type, SimUnion)


def test_tpi_procedure_converts_to_function_type():
    pdb = load_pdb(PDB_PATH)
    proj = _project()
    from angr.analyses.pdb.tpi import ProcedureRecord
    from angr.analyses.pdb.type_translator import PDBTypeTranslator

    translator = PDBTypeTranslator(pdb.tpi, pdb.ipi, proj.arch)
    proc_index = next(i for i, r in pdb.tpi.records.items() if isinstance(r, ProcedureRecord))
    func = translator.convert(proc_index)
    assert isinstance(func, SimTypeFunction)


# ---------------------------------------------------------------------------
# Symbol binding
# ---------------------------------------------------------------------------


def test_function_names_and_addresses_bound():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    # authenticate/accepted/rejected are the named fauxware functions.
    by_name = {name: addr for addr, name in analysis.bound_functions.items()}
    for expected in ("authenticate", "accepted", "rejected"):
        assert expected in by_name
        addr = by_name[expected]
        func = proj.kb.functions.function(addr=addr)
        assert func is not None and func.name == expected
        assert func.is_default_name is False
        assert func.from_signature == "pdb"


def test_global_variables_bound_within_image():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    main_object = proj.loader.main_object
    assert "sneaky" in {name for name in analysis.bound_globals.values()}
    for addr in analysis.bound_globals:
        assert main_object.contains_addr(addr)


def test_public_symbol_names_published_as_labels():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    # __security_cookie is a public symbol in the MSVC runtime.
    labels = {proj.kb.labels.get(addr): addr for addr in analysis.bound_globals}
    assert "__security_cookie" in labels


def test_no_pdb_leaves_project_unchanged(tmp_path):
    import shutil

    shutil.copy(EXE_PATH, tmp_path / "standalone.exe")
    proj = _project_with(tmp_path / "standalone.exe")
    before = set(proj.kb.types.iter_own_keys())
    analysis = proj.analyses.PDBTypes()
    assert analysis.loaded is False
    assert set(proj.kb.types.iter_own_keys()) == before


def _project_with(path):
    import angr

    return angr.Project(str(path), auto_load_libs=False)


# ---------------------------------------------------------------------------
# Calling convention
# ---------------------------------------------------------------------------


def test_amd64_windows_cc_selected():
    proj = _project()
    analysis = proj.analyses.PDBTypes()
    # Every bound function on Win64 should resolve to the Microsoft AMD64 CC when a prototype is attached.
    from angr.calling_conventions import SimCCMicrosoftAMD64

    cc_classes = set()
    for addr in analysis.bound_functions:
        func = proj.kb.functions.function(addr=addr)
        if func is not None and func.calling_convention is not None:
            cc_classes.add(type(func.calling_convention))
    # Functions without a TPI prototype simply have no CC assigned; any assigned CC must be the Win64 one.
    assert cc_classes.issubset({SimCCMicrosoftAMD64})
