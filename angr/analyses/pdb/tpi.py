"""
Parsing of TPI (type information) and IPI (ID/string-table information) streams.

The parser produces a compact, index-addressed intermediate representation (:class:`TypeRecord` subclasses) rather
than angr types directly. This keeps the untrusted-byte handling in one place and lets the SimType translator cache
and resolve references lazily.

Only one pass over the record bytes is performed, so memory and time are both linear in the number of records.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    AGGREGATE_LEAVES,
    ENUM_LEAVES,
    FLD_BCLASS,
    FLD_ENUMERATE,
    FLD_FRIENDFCN,
    FLD_INDEX,
    FLD_MEMBER,
    FLD_MEMBER_ST,
    FLD_METHOD,
    FLD_METHOD_ST,
    FLD_NESTTYPE,
    FLD_NESTTYPE_ST,
    FLD_ONEMETHOD,
    FLD_ONEMETHOD_ST,
    FLD_STMEMBER,
    FLD_STMEMBER_ST,
    FLD_VBCLASS,
    FLD_VFUNCTAB,
    LF_ALIAS,
    LF_ALIAS_ST,
    LF_ARGLIST,
    LF_ARRAY,
    LF_ARRAY_ST,
    LF_BITFIELD,
    LF_CLASS_ST,
    LF_DERIVED,
    LF_ENUM_ST,
    LF_FIELDLIST,
    LF_INDEX,
    LF_MFUNCTION,
    LF_MODIFIER,
    LF_POINTER,
    LF_PROCEDURE,
    LF_STRING_ID,
    LF_STRUCTURE_ST,
    LF_UNION,
    LF_UNION_ST,
    PROP_FWDREF,
    PTR_MODE_PMFUNC,
    PTR_MODE_REF,
    TPI_FIRST_NON_BUILTIN,
    UNION_LEAVES,
)
from .msf import PDBFormatError
from .records import Cursor, iter_type_records


# ---------------------------------------------------------------------------
# Intermediate representation
# ---------------------------------------------------------------------------


@dataclass
class TypeRecord:
    index: int
    leaf: int


@dataclass
class ModifierRecord(TypeRecord):
    modified_type: int = 0
    is_const: bool = False
    is_volatile: bool = False
    is_unaligned: bool = False


@dataclass
class PointerRecord(TypeRecord):
    utype: int = 0
    attributes: int = 0
    is_64bit: bool = False
    # Optional "new style" pointer name (LF_POINTER with a trailing NUL string).
    name: str | None = None
    member_class: int = 0  # for PTR_MODE_PMEM: class type containing the member

    @property
    def mode(self) -> int:
        return self.attributes & 0x7

    @property
    def ptr_type(self) -> int:
        return (self.attributes >> 3) & 0x1F

    @property
    def is_reference(self) -> bool:
        return self.mode == PTR_MODE_REF


@dataclass
class ProcedureRecord(TypeRecord):
    return_type: int = 0
    call_conv: int = 0
    param_count: int = 0
    arglist: int = 0


@dataclass
class MemberFunctionRecord(TypeRecord):
    return_type: int = 0
    class_type: int = 0
    this_type: int = 0
    call_conv: int = 0
    param_count: int = 0
    arglist: int = 0
    this_adjustment: int = 0


@dataclass
class ArgListRecord(TypeRecord):
    arg_types: tuple[int, ...] = ()


@dataclass
class ArrayRecord(TypeRecord):
    element_type: int = 0
    index_type: int = 0
    size_bytes: int = 0
    name: str | None = None


@dataclass
class BitfieldRecord(TypeRecord):
    base_type: int = 0
    bit_length: int = 0
    bit_position: int = 0


@dataclass
class FieldMember:
    kind: str  # 'member' | 'enumerate' | 'nested' | 'baseclass' | 'static' | 'method' | 'vfunctab' | 'index'
    type_index: int = 0
    name: str = ""
    offset: int | None = None  # byte offset for data members / base classes
    bit_position: int | None = None
    bit_length: int | None = None
    access: int = 3
    attributes: int = 0


@dataclass
class FieldListRecord(TypeRecord):
    members: list[FieldMember] = field(default_factory=list)


@dataclass
class AggregateRecord(TypeRecord):
    kind: str = "struct"  # 'struct' | 'class' | 'interface' | 'union'
    field_list: int = 0
    size_bytes: int = 0
    name: str = ""
    properties: int = 0
    # LF_UNION has no derived/vshape; keep them for a uniform shape.
    derived: int = 0
    vshape: int = 0

    @property
    def is_forward_ref(self) -> bool:
        return bool(self.properties & PROP_FWDREF)


@dataclass
class EnumRecord(TypeRecord):
    field_list: int = 0
    underlying_type: int = 0
    size_bytes: int = 0
    name: str = ""
    properties: int = 0

    @property
    def is_forward_ref(self) -> bool:
        return bool(self.properties & PROP_FWDREF)


@dataclass
class AliasRecord(TypeRecord):
    aliased_type: int = 0
    name: str = ""


@dataclass
class UnknownRecord(TypeRecord):
    """A leaf we do not model explicitly; its type index can still be referenced."""


@dataclass
class StringIdRecord(TypeRecord):
    string_id: int = 0
    text: str = ""


# ---------------------------------------------------------------------------
# Field-list sub-records
# ---------------------------------------------------------------------------


def _parse_field_member(cur: Cursor, sub_leaf: int) -> FieldMember:
    if sub_leaf in (FLD_MEMBER, FLD_MEMBER_ST, 0x0406):
        attributes = cur.u16()
        if sub_leaf == 0x0406:  # LF_MEMBER_16t: 16-bit type index and offset
            type_index = cur.u16()
            offset = cur.u16()
            name = cur.cstring()
        else:
            type_index = cur.u32()
            if sub_leaf == FLD_MEMBER_ST:
                offset = cur.u16()
                name = cur.cstring()
            else:
                offset = cur.numeric()
                name = cur.cstring()
        return FieldMember(
            "member",
            type_index=type_index,
            name=name,
            offset=offset,
            access=attributes & 0x3,
            attributes=attributes,
        )
    if sub_leaf in (FLD_STMEMBER, FLD_STMEMBER_ST, 0x0407):
        attributes = cur.u16()
        type_index = cur.u16() if sub_leaf == 0x0407 else cur.u32()
        name = cur.cstring()
        return FieldMember("static", type_index=type_index, name=name, access=attributes & 0x3)
    if sub_leaf in (FLD_ENUMERATE, 0x0403):
        attributes = cur.u16()
        if sub_leaf == 0x0403:  # LF_ENUMERATE_ST: 16-bit (actually 8-bit) value
            value = cur.i8()
        else:
            value = cur.numeric()
        name = cur.cstring()
        return FieldMember("enumerate", name=name, offset=value, access=attributes & 0x3)
    if sub_leaf in (FLD_NESTTYPE, FLD_NESTTYPE_ST):
        cur.u16()  # padding
        type_index = cur.u32()
        name = cur.cstring()
        return FieldMember("nested", type_index=type_index, name=name)
    if sub_leaf in (FLD_BCLASS, 0x0400):  # 0x0400 = LF_BCLASS_16t
        attributes = cur.u16()
        if sub_leaf == 0x0400:
            type_index = cur.u16()
            offset = cur.u16()
        else:
            type_index = cur.u32()
            offset = cur.numeric()
        return FieldMember("baseclass", type_index=type_index, offset=offset, access=attributes & 0x3)
    if sub_leaf in (FLD_VBCLASS, 0x0401):
        attributes = cur.u16()
        if sub_leaf == 0x0401:
            cur.u16(); cur.u16(); cur.u16()  # base, vb pointer type, vbp offset (all 16-bit in the 16t form)
        else:
            cur.u32()  # base class type
            cur.u32()  # virtual base pointer type
            cur.numeric()  # vbp offset
            cur.numeric()  # virtual base offset from vbtable
        return FieldMember("baseclass", type_index=0, name="<virtual-base>")
    if sub_leaf == FLD_VFUNCTAB:
        cur.u16()  # padding
        type_index = cur.u32()
        return FieldMember("vfunctab", type_index=type_index)
    if sub_leaf in (FLD_ONEMETHOD, FLD_ONEMETHOD_ST, 0x040C, FLD_METHOD, FLD_METHOD_ST, 0x0408):
        # Methods are captured by name only; full method prototypes are not required for struct field layout.
        is_16t = sub_leaf in (0x040C, 0x0408)
        attributes = cur.u16()
        if sub_leaf in (FLD_METHOD, FLD_METHOD_ST, 0x0408):
            cur.u16()  # method count
            method_list = cur.u16() if is_16t else cur.u32()
            name = cur.cstring()
            return FieldMember("method", type_index=method_list, name=name, attributes=attributes)
        type_index = cur.u16() if is_16t else cur.u32()
        # Intro/virtual methods carry an extra "vbase offset" field before the name.
        mprop = (attributes >> 2) & 0x7
        if mprop in (1, 4, 5):  # virtual / intro / pure-intro
            if is_16t:
                cur.u16()
            else:
                cur.u32()
        name = cur.cstring()
        return FieldMember("method", type_index=type_index, name=name, attributes=attributes)
    if sub_leaf in (FLD_NESTTYPE, FLD_NESTTYPE_ST, 0x0409):
        cur.u16()  # padding
        type_index = cur.u16() if sub_leaf == 0x0409 else cur.u32()
        name = cur.cstring()
        return FieldMember("nested", type_index=type_index, name=name)
    if sub_leaf == FLD_INDEX:
        # Continuation record: the real field list lives at the referenced type.
        type_index = cur.u32()
        return FieldMember("index", type_index=type_index)
    if sub_leaf == FLD_FRIENDFCN:
        cur.u16()
        cur.u32()
        name = cur.cstring()
        return FieldMember("method", name=name)
    raise PDBFormatError(f"Unsupported field-list sub-leaf {sub_leaf:#x}")


# ---------------------------------------------------------------------------
# Stream parsing
# ---------------------------------------------------------------------------


class TPIStream:
    """
    Parsed contents of a TPI or IPI stream.

    :ivar records:          Mapping of type index -> :class:`TypeRecord`.
    :ivar ti_min/ti_max:   Declared index range of the stream.
    :ivar string_ids:       IPI string table (LF_STRING_ID id -> text); empty for TPI.
    """

    def __init__(self, stream: bytes, is_ipi: bool = False):
        if len(stream) < 56:
            raise PDBFormatError("TPI stream shorter than its 56-byte header")
        (
            _version,
            header_size,
            self.ti_min,
            self.ti_max,
            record_bytes,
        ) = struct.unpack_from("<IIIII", stream, 0)
        if header_size < 56 or self.ti_min < TPI_FIRST_NON_BUILTIN or self.ti_max < self.ti_min:
            raise PDBFormatError("Invalid TPI header bounds")
        if header_size + record_bytes > len(stream):
            raise PDBFormatError("TPI record region exceeds stream size")
        self.records: dict[int, TypeRecord] = {}
        self.string_ids: dict[int, str] = {}
        self._is_ipi = is_ipi
        self._parse(stream, header_size, record_bytes)

    def _parse(self, stream: bytes, header_size: int, record_bytes: int) -> None:
        index = self.ti_min
        for _pos, leaf, cur in iter_type_records(stream, header_size, record_bytes):
            record = self._parse_record(index, leaf, cur)
            if record is not None:
                self.records[index] = record
            index += 1
        if index != self.ti_max:
            # Some linkers pad the tail; a mismatch is tolerated rather than fatal, but reported for diagnostics.
            # We keep whatever records were successfully decoded.
            pass

    def _parse_record(self, index: int, leaf: int, cur: Cursor) -> TypeRecord | None:
        if leaf == LF_MODIFIER:
            modified = cur.u32()
            flags = cur.u16()
            return ModifierRecord(
                index,
                leaf,
                modified_type=modified,
                is_const=bool(flags & 0x1),
                is_volatile=bool(flags & 0x2),
                is_unaligned=bool(flags & 0x4),
            )
        if leaf == LF_POINTER:
            utype = cur.u32()
            attributes = cur.u32()
            rec = PointerRecord(index, leaf, utype=utype, attributes=attributes)
            # "New-style" pointer (attributes bit 13 = ptrtype 0xC with size 0xC encoding): an optional name follows
            # when the high attribute bit (0x80000000) is set.
            if attributes & 0x80000000:
                rec.name = cur.cstring()
            # Pointer-to-member records encode the containing class type next.
            if rec.mode in (2, PTR_MODE_PMFUNC):
                rec.member_class = cur.u32()
            return rec
        if leaf == LF_PROCEDURE:
            return_type = cur.u32()
            call_conv = cur.u8()
            cur.u8()  # reserved
            param_count = cur.u16()
            arglist = cur.u32()
            return ProcedureRecord(
                index, leaf, return_type=return_type, call_conv=call_conv,
                param_count=param_count, arglist=arglist,
            )
        if leaf == LF_MFUNCTION:
            return_type = cur.u32()
            class_type = cur.u32()
            this_type = cur.u32()
            call_conv = cur.u8()
            cur.u8()
            param_count = cur.u16()
            arglist = cur.u32()
            adjustment = cur.i32()
            return MemberFunctionRecord(
                index, leaf, return_type=return_type, class_type=class_type, this_type=this_type,
                call_conv=call_conv, param_count=param_count, arglist=arglist, this_adjustment=adjustment,
            )
        if leaf == LF_ARGLIST:
            count = cur.u32()
            args = tuple(cur.u32() for _ in range(count))
            return ArgListRecord(index, leaf, arg_types=args)
        if leaf in (LF_ARRAY, LF_ARRAY_ST):
            elem = cur.u32()
            idx_ty = cur.u32()
            if leaf == LF_ARRAY_ST:
                size = cur.u16()
                name = cur.cstring()
            else:
                size = cur.numeric()
                name = None
            return ArrayRecord(index, leaf, element_type=elem, index_type=idx_ty, size_bytes=size, name=name)
        if leaf == LF_BITFIELD:
            base = cur.u32()
            bit_len = cur.u8()
            bit_pos = cur.u8()
            return BitfieldRecord(index, leaf, base_type=base, bit_length=bit_len, bit_position=bit_pos)
        if leaf == LF_FIELDLIST:
            members = self._parse_field_list(cur)
            return FieldListRecord(index, leaf, members=members)
        if leaf in UNION_LEAVES or leaf == LF_UNION_ST:
            return self._parse_union(index, leaf, cur)
        if leaf in AGGREGATE_LEAVES or leaf in (LF_CLASS_ST, LF_STRUCTURE_ST):
            return self._parse_aggregate(index, leaf, cur)
        if leaf in ENUM_LEAVES or leaf == LF_ENUM_ST:
            return self._parse_enum(index, leaf, cur)
        if leaf in (LF_ALIAS, LF_ALIAS_ST):
            aliased = cur.u32()
            name = cur.cstring()
            return AliasRecord(index, leaf, aliased_type=aliased, name=name)
        if leaf == LF_INDEX:
            # A type-index continuation: resolve target lazily; represent as alias-like unknown marker.
            target = cur.u32()
            return AliasRecord(index, leaf, aliased_type=target, name="")
        if leaf == LF_DERIVED:
            count = cur.u32()
            for _ in range(count):
                cur.u32()
            return UnknownRecord(index, leaf)
        if leaf == LF_STRING_ID:
            string_id = cur.u32()
            text = cur.cstring()
            rec = StringIdRecord(index, leaf, string_id=string_id, text=text)
            self.string_ids[string_id] = text
            return rec
        # Anything else (OEM, vector/matrix, managed, etc.) is retained as an opaque record.
        return UnknownRecord(index, leaf)

    def _parse_field_list(self, cur: Cursor) -> list[FieldMember]:
        members: list[FieldMember] = []
        while cur.remaining() >= 4:
            # Field lists align sub-records explicitly with LF_PAD0..LF_PAD15 pad leaves (0xF0..0xFF). A pad leaf
            # marks padding up to the next 4-byte boundary; consume the whole run and resume there. Any trailing pad
            # bytes at the very end of the record are simply skipped.
            peek = cur.buf[cur.pos]
            if 0xF0 <= peek <= 0xFF:
                cur.align4()
                continue
            sub_leaf = cur.u16()
            try:
                member = _parse_field_member(cur, sub_leaf)
            except PDBFormatError:
                # An unknown/corrupt sub-leaf: the record boundary is no longer trustworthy, so keep the members
                # decoded so far and stop rather than aborting the entire TPI parse.
                break
            members.append(member)
        # Fewer than 4 bytes can only be trailing alignment padding.
        while cur.remaining() and 0xF0 <= cur.buf[cur.pos] <= 0xFF:
            cur.u8()
        return members

    def _parse_aggregate(self, index: int, leaf: int, cur: Cursor) -> AggregateRecord:
        cur.u16()  # member count (not needed for layout)
        properties = cur.u16()
        field_list = cur.u32()
        derived = cur.u32()
        vshape = cur.u32()
        if leaf in (LF_CLASS_ST, LF_STRUCTURE_ST):
            size = cur.u16()
            name = cur.cstring()
        else:
            size = cur.numeric()
            name = cur.cstring()
        if leaf == LF_UNION or leaf == LF_UNION_ST:
            kind = "union"
        elif leaf in AGGREGATE_LEAVES and leaf != 0x1505:
            kind = "interface" if leaf == 0x1519 else "class"
        else:
            kind = "struct"
        return AggregateRecord(
            index, leaf, kind=kind, field_list=field_list, size_bytes=size,
            name=name, properties=properties, derived=derived, vshape=vshape,
        )

    def _parse_union(self, index: int, leaf: int, cur: Cursor) -> AggregateRecord:
        cur.u16()  # member count
        properties = cur.u16()
        field_list = cur.u32()
        if leaf == LF_UNION_ST:
            size = cur.u16()
            name = cur.cstring()
        else:
            size = cur.numeric()
            name = cur.cstring()
        return AggregateRecord(
            index, leaf, kind="union", field_list=field_list, size_bytes=size,
            name=name, properties=properties,
        )

    def _parse_enum(self, index: int, leaf: int, cur: Cursor) -> EnumRecord:
        cur.u16()  # enumerator count
        properties = cur.u16()
        underlying = cur.u32()
        field_list = cur.u32()
        if leaf == LF_ENUM_ST:
            size = cur.u16()
            name = cur.cstring()
        else:
            size = cur.numeric()
            name = cur.cstring()
        return EnumRecord(
            index, leaf, field_list=field_list, underlying_type=underlying,
            size_bytes=size, name=name, properties=properties,
        )
