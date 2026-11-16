"""
Unit tests for the CodeView -> SimType translator.

Cycle handling, forward references, duplicate names, nested aggregates and graceful degradation on missing or
corrupt type indices are exercised with in-memory :mod:`tpi` records, avoiding any binary dependency.
"""

from __future__ import annotations

import pytest

from angr.sim_type import (
    SimTypeEnum,
    SimTypeFunction,
    SimTypeNum,
    SimTypeNumOffset,
    SimTypePointer,
    SimTypeReference,
    SimStruct,
    SimUnion,
    TypeRef,
)
from angr.analyses.pdb.tpi import (
    AggregateRecord,
    AliasRecord,
    ArgListRecord,
    ArrayRecord,
    BitfieldRecord,
    EnumRecord,
    FieldListRecord,
    FieldMember,
    ModifierRecord,
    PointerRecord,
    ProcedureRecord,
)
from angr.analyses.pdb.type_translator import PDBTypeTranslator


class _FakeTPI:
    """Minimal stand-in for :class:`TPIStream` exposing only what the translator reads."""

    def __init__(self, records):
        self.records = records
        self.string_ids = {}


@pytest.fixture(scope="module")
def arch():
    import angr

    return archinfo_arch(angr)


def archinfo_arch(angr):
    # A minimal shellcode project gives us an AMD64 arch without requiring any binary.
    return angr.load_shellcode(b"\x90", "AMD64").arch


def _translator(records, arch):
    return PDBTypeTranslator(_FakeTPI(records), None, arch)


# ---------------------------------------------------------------------------
# Built-in / simple types
# ---------------------------------------------------------------------------


def test_builtin_primitives(arch):
    tr = _translator({}, arch)
    assert tr.convert(0x0003).__class__.__name__ == "SimTypeBottom"  # T_VOID
    int32 = tr.convert(0x0074)  # T_INT4
    assert isinstance(int32, SimTypeNum) and int32.size == 32 and int32.signed is True
    uint8 = tr.convert(0x0069)  # T_UINT1
    assert uint8.size == 8 and uint8.signed is False
    pvoid = tr.convert(0x0603)  # T_64PVOID
    assert isinstance(pvoid, SimTypePointer) and pvoid.size == 64


# ---------------------------------------------------------------------------
# Pointers, modifiers, references, arrays
# ---------------------------------------------------------------------------


def test_pointer_and_reference(arch):
    records = {
        0x1000: PointerRecord(0x1000, 0x1002, utype=0x0074, attributes=0x0000),          # int*
        0x1001: PointerRecord(0x1001, 0x1002, utype=0x0074, attributes=0x0001),          # int& (mode=1)
        0x1002: ModifierRecord(0x1002, 0x1001, modified_type=0x0074, is_const=True),
    }
    tr = _translator(records, arch)
    ptr = tr.convert(0x1000)
    ref = tr.convert(0x1001)
    const_int = tr.convert(0x1002)
    assert isinstance(ptr, SimTypePointer) and isinstance(ptr.pts_to, SimTypeNum)
    assert isinstance(ref, SimTypeReference)
    assert "const" in (const_int.qualifier or ())


def test_array_length_from_size(arch):
    # 4-element int32 array = 16 bytes.
    records = {0x1000: ArrayRecord(0x1000, 0x1503, element_type=0x0074, index_type=0x0011, size_bytes=16)}
    tr = _translator(records, arch)
    arr = tr.convert(0x1000)
    assert arr.length == 4 and isinstance(arr.elem_type, SimTypeNum)


def test_bitfield(arch):
    records = {
        0x1000: BitfieldRecord(0x1000, 0x1205, base_type=0x0075, bit_length=5, bit_position=3),
    }
    tr = _translator(records, arch)
    bf = tr.convert(0x1000)
    assert isinstance(bf, SimTypeNumOffset) and bf.size == 5 and bf.offset == 3


# ---------------------------------------------------------------------------
# Procedures
# ---------------------------------------------------------------------------


def test_procedure_signature(arch):
    records = {
        0x1000: ArgListRecord(0x1000, 0x1201, arg_types=(0x0074, 0x0069)),
        0x1001: ProcedureRecord(
            0x1001, 0x1008, return_type=0x0074, call_conv=0, param_count=2, arglist=0x1000
        ),
    }
    tr = _translator(records, arch)
    func = tr.convert(0x1001)
    assert isinstance(func, SimTypeFunction)
    assert len(func.args) == 2 and func.returnty.size == 32


def test_void_return_becomes_none(arch):
    records = {
        0x1000: ArgListRecord(0x1000, 0x1201, arg_types=()),
        0x1001: ProcedureRecord(0x1001, 0x1008, return_type=0x0003, call_conv=0, param_count=0, arglist=0x1000),
    }
    tr = _translator(records, arch)
    assert tr.convert(0x1001).returnty is None


# ---------------------------------------------------------------------------
# Structs, unions, enums, nesting
# ---------------------------------------------------------------------------


def test_struct_fields_and_offsets(arch):
    records = {
        0x1000: FieldListRecord(
            0x1000,
            0x1203,
            members=[
                FieldMember("member", type_index=0x0074, name="a", offset=0),
                FieldMember("member", type_index=0x0074, name="b", offset=4),
            ],
        ),
        0x1001: AggregateRecord(
            0x1001, 0x1505, kind="struct", field_list=0x1000, size_bytes=8, name="pair"
        ),
    }
    tr = _translator(records, arch)
    struct = tr.convert(0x1001)
    assert isinstance(struct, SimStruct)
    assert list(struct.fields.keys()) == ["a", "b"]
    assert struct.offsets["a"] == 0 and struct.offsets["b"] == 4


def test_nested_struct(arch):
    records = {
        0x1000: FieldListRecord(0x1000, 0x1203, members=[
            FieldMember("member", type_index=0x0074, name="x", offset=0),
        ]),
        0x1001: AggregateRecord(0x1001, 0x1505, kind="struct", field_list=0x1000, size_bytes=4, name="inner"),
        0x1002: FieldListRecord(0x1002, 0x1203, members=[
            FieldMember("nested", type_index=0x1001, name="child", offset=0),
        ]),
        0x1003: AggregateRecord(0x1003, 0x1505, kind="struct", field_list=0x1002, size_bytes=4, name="outer"),
    }
    tr = _translator(records, arch)
    outer = tr.convert(0x1003)
    assert isinstance(outer.fields["child"], SimStruct)
    assert outer.fields["child"].name == "inner"


def test_union_members(arch):
    records = {
        0x1000: FieldListRecord(0x1000, 0x1203, members=[
            FieldMember("member", type_index=0x0074, name="i", offset=0),
            FieldMember("member", type_index=0x0075, name="u", offset=0),
        ]),
        0x1001: AggregateRecord(0x1001, 0x1506, kind="union", field_list=0x1000, size_bytes=4, name="number"),
    }
    tr = _translator(records, arch)
    union = tr.convert(0x1001)
    assert isinstance(union, SimUnion) and set(union.members) == {"i", "u"}


def test_enum_members(arch):
    records = {
        0x1000: FieldListRecord(0x1000, 0x1203, members=[
            FieldMember("enumerate", name="A", offset=0),
            FieldMember("enumerate", name="B", offset=1),
            FieldMember("enumerate", name="C", offset=2),
        ]),
        0x1001: EnumRecord(
            0x1001, 0x1507, field_list=0x1000, underlying_type=0x0075, size_bytes=4, name="mode"
        ),
    }
    tr = _translator(records, arch)
    enum = tr.convert(0x1001)
    assert isinstance(enum, SimTypeEnum)
    assert enum.members == {"A": 0, "B": 1, "C": 2}


# ---------------------------------------------------------------------------
# Cycles, forward refs, duplicates, missing/corrupt indices
# ---------------------------------------------------------------------------


def test_cyclic_typedef_terminates(arch):
    # alias 0x1000 -> pointer 0x1001 -> alias 0x1000 (self-referential typedef).
    records = {
        0x1000: AliasRecord(0x1000, 0x150A, aliased_type=0x1001, name="node_t"),
        0x1001: PointerRecord(0x1001, 0x1002, utype=0x1000, attributes=0),
    }
    tr = _translator(records, arch)
    ty = tr.convert(0x1000)  # must terminate
    assert isinstance(ty, SimTypePointer)


def test_self_referential_struct_via_pointer(arch):
    # struct node { struct node* next; } — the pointer breaks the structural cycle.
    records = {
        0x1000: PointerRecord(0x1000, 0x1002, utype=0x1002, attributes=0),
        0x1001: FieldListRecord(0x1001, 0x1203, members=[
            FieldMember("member", type_index=0x1000, name="next", offset=0),
        ]),
        0x1002: AggregateRecord(0x1002, 0x1505, kind="struct", field_list=0x1001, size_bytes=8, name="node"),
    }
    tr = _translator(records, arch)
    node = tr.convert(0x1002)
    assert isinstance(node, SimStruct)
    assert isinstance(node.fields["next"], SimTypePointer)


def test_forward_ref_resolves_to_real_definition(arch):
    records = {
        0x1000: AggregateRecord(0x1000, 0x1505, kind="struct", field_list=0, size_bytes=0,
                                name="S", properties=0x1),
        0x1001: FieldListRecord(0x1001, 0x1203, members=[
            FieldMember("member", type_index=0x0074, name="v", offset=0),
        ]),
        0x1002: AggregateRecord(0x1002, 0x1505, kind="struct", field_list=0x1001, size_bytes=4,
                                name="S", properties=0x0),
    }
    tr = _translator(records, arch)
    assert tr._name_to_index["S"] == 0x1002  # real definition preferred over forward ref
    resolved = tr.named_type("S")
    assert isinstance(resolved, SimStruct) and "v" in resolved.fields


def test_duplicate_names_collapse(arch):
    records = {
        0x1000: AggregateRecord(0x1000, 0x1505, kind="struct", field_list=0, size_bytes=4, name="dup"),
        0x1001: AggregateRecord(0x1001, 0x1505, kind="struct", field_list=0, size_bytes=8, name="dup"),
    }
    tr = _translator(records, arch)
    # First real definition wins; the name maps to exactly one index.
    assert tr._name_to_index["dup"] == 0x1000


def test_missing_index_degrades_to_opaque(arch):
    tr = _translator({}, arch)
    ty = tr.convert(0x7777)  # referenced but absent (cross-module gap)
    # Must not raise; yields an opaque top type.
    assert ty.__class__.__name__ == "SimTypeTop"


def test_typedef_label_applied(arch):
    records = {
        0x1000: AliasRecord(0x1000, 0x150A, aliased_type=0x0074, name="my_int"),
    }
    tr = _translator(records, arch)
    ty = tr.convert(0x1000)
    assert ty.label == "my_int"


def test_make_type_ref(arch):
    records = {
        0x1000: AggregateRecord(0x1000, 0x1505, kind="struct", field_list=0, size_bytes=4, name="S"),
    }
    tr = _translator(records, arch)
    ref = tr.make_type_ref("S", tr.convert(0x1000))
    assert isinstance(ref, TypeRef) and ref.name == "S"
    assert isinstance(ref.type, SimStruct)
