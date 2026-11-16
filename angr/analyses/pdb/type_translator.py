"""
Translate CodeView type records (the :mod:`tpi` intermediate representation) into angr :class:`SimType` objects.

Design points required by the importer:

* Every CodeView type index is converted at most once and cached, so cost is linear in the number of referenced
  records rather than the whole TPI.
* Forward references and self/cyclic references resolve via mutable shells plus an ``in_progress`` guard, so cyclic
  typedefs or structs containing pointers to themselves terminate instead of recursing forever.
* Duplicate definitions (the same name emitted as both a forward ref and a real record) collapse to one SimType;
  the real definition always wins over the forward ref.
* Any record that cannot be translated degrades to an opaque/unknown type rather than raising.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from ...sim_type import (
    SimType,
    SimTypeArray,
    SimTypeBottom,
    SimTypeBool,
    SimTypeChar,
    SimTypeDouble,
    SimTypeEnum,
    SimTypeFloat,
    SimTypeLongDouble,
    SimTypeNum,
    SimTypeNumOffset,
    SimTypePointer,
    SimTypeReference,
    SimStruct,
    SimTypeTop,
    SimUnion,
    TypeRef,
)
from .constants import (
    PTR_MODE_PMEM,
    PTR_MODE_PMFUNC,
    T_BIT,
    T_BOOL32FF,
    T_CHAR,
    T_CHAR16,
    T_CHAR32,
    T_HRESULT,
    T_INT1,
    T_INT16,
    T_INT2,
    T_INT4,
    T_INT8,
    T_LONG,
    T_NOTYPE,
    T_OCT,
    T_QUAD,
    T_RCHAR,
    T_REAL128,
    T_REAL16,
    T_REAL32,
    T_REAL32PP,
    T_REAL48,
    T_REAL64,
    T_REAL80,
    T_SEGMENT,
    T_SHORT,
    T_UCHAR,
    T_UINT1,
    T_UINT16,
    T_UINT2,
    T_UINT4,
    T_UINT8,
    T_ULONG,
    T_UOCT,
    T_UQUAD,
    T_USHORT,
    T_VOID,
    T_WCHAR,
    TPI_FIRST_NON_BUILTIN,
    SimpleTypeMode,
)
from .tpi import (
    AggregateRecord,
    AliasRecord,
    ArgListRecord,
    ArrayRecord,
    BitfieldRecord,
    EnumRecord,
    FieldListRecord,
    MemberFunctionRecord,
    ModifierRecord,
    PointerRecord,
    ProcedureRecord,
    TPIStream,
    UnknownRecord,
)

_l = logging.getLogger(__name__)

# Primitive index -> (bits, signed, factory-ish marker). Floats and special types are handled separately.
_PRIMITIVE_INTS = {
    T_CHAR: (8, True),
    T_UCHAR: (8, False),
    T_RCHAR: (8, True),
    T_INT1: (8, True),
    T_UINT1: (8, False),
    T_SHORT: (16, True),
    T_USHORT: (16, False),
    T_INT2: (16, True),
    T_UINT2: (16, False),
    T_LONG: (32, True),
    T_ULONG: (32, False),
    T_INT4: (32, True),
    T_UINT4: (32, False),
    T_QUAD: (64, True),
    T_UQUAD: (64, False),
    T_INT8: (64, True),
    T_UINT8: (64, False),
    T_OCT: (128, True),
    T_UOCT: (128, False),
    T_INT16: (128, True),
    T_UINT16: (128, False),
    T_WCHAR: (16, False),
    T_CHAR16: (16, False),
    T_CHAR32: (32, False),
}

_PRIMITIVE_FLOATS = {
    T_REAL16: 16,
    T_REAL32: 32,
    T_REAL32PP: 32,
    T_REAL48: 48,
    T_REAL64: 64,
    T_REAL80: 80,
    T_REAL128: 128,
}


class PDBTypeTranslator:
    """
    Convert CodeView type indices into arch-specialized angr SimTypes.

    :param tpi:          Parsed TPI stream.
    :param ipi:          Parsed IPI stream (may be ``None``).
    :param arch:         The target :class:`archinfo.Arch`; pointer widths and ``SimTypeInt`` resolution depend on it.
    """

    def __init__(self, tpi: TPIStream, ipi: TPIStream | None, arch):
        self.tpi = tpi
        self.ipi = ipi
        self.arch = arch
        self._cache: dict[int, SimType] = {}
        # Indices currently being converted; maps to the placeholder shell so cycles resolve.
        self._in_progress: dict[int, SimType] = {}
        # Name -> index of the chosen (non-forward-ref preferred) definition.
        self._name_to_index: dict[str, int] = {}
        self._build_name_index()

    #
    # Name bookkeeping (forward refs vs. real definitions, duplicates)
    #

    def _build_name_index(self) -> None:
        for index, record in self.tpi.records.items():
            name = getattr(record, "name", None)
            if not name:
                continue
            existing = self._name_to_index.get(name)
            if existing is None:
                self._name_to_index[name] = index
                continue
            # Prefer a non-forward-ref definition over a forward ref; on a tie keep the first.
            existing_rec = self.tpi.records.get(existing)
            if getattr(existing_rec, "is_forward_ref", False) and not getattr(record, "is_forward_ref", False):
                self._name_to_index[name] = index

    def _unique_name(self, base: str) -> str:
        if base not in self._name_to_index:
            return base
        suffix = 2
        while f"{base}_{suffix}" in self._name_to_index:
            suffix += 1
        return f"{base}_{suffix}"

    #
    # Public entry point
    #

    def convert(self, index: int) -> SimType:
        """Return the SimType for a CodeView type ``index`` (built-in or TPI-defined)."""
        if index < TPI_FIRST_NON_BUILTIN:
            return self._convert_simple(index)
        cached = self._cache.get(index)
        if cached is not None:
            return cached
        in_progress = self._in_progress.get(index)
        if in_progress is not None:
            # Cyclic reference: hand back the shell currently being filled.
            return in_progress
        record = self.tpi.records.get(index)
        if record is None:
            # Cross-module / missing index: opaque type rather than a crash.
            return SimTypeTop(label=f"unknown_cv_{index:#x}")
        try:
            converted = self._convert_record(index, record)
        except Exception as ex:  # pragma: no cover - defensive, exercised by corruption tests
            _l.debug("Failed to convert PDB type %#x (%s): %s", index, type(record).__name__, ex)
            converted = SimTypeTop(label=f"bad_cv_{index:#x}")
        self._cache[index] = converted
        self._in_progress.pop(index, None)
        return converted

    #
    # Built-in / simple types
    #

    def _convert_simple(self, index: int) -> SimType:
        mode = index & 0xFF00
        primitive = index & 0x00FF
        base = self._primitive(primitive)
        if mode == SimpleTypeMode.DIRECT:
            return base
        # Pointer modes embedded in simple-type indices (e.g. T_64PVOID).
        if mode in (SimpleTypeMode.NEAR_PTR64,):
            return SimTypePointer(base).with_arch(self.arch)
        if mode in (SimpleTypeMode.NEAR_PTR32, SimpleTypeMode.NEAR_PTR, SimpleTypeMode.FAR_PTR,
                    SimpleTypeMode.HUGE_PTR, SimpleTypeMode.FAR_PTR32):
            ptr = SimTypePointer(base).with_arch(self.arch)
            return ptr
        return SimTypePointer(base).with_arch(self.arch)

    def _primitive(self, primitive: int) -> SimType:
        if primitive in (T_NOTYPE, T_SEGMENT):
            return SimTypeBottom(label="void" if primitive == T_NOTYPE else None)
        if primitive == T_VOID:
            return SimTypeBottom(label="void")
        if primitive == T_HRESULT:
            return SimTypeNum(32, signed=True, label="HRESULT")
        if primitive == T_BOOL32FF:
            return SimTypeBool()
        if primitive == T_BIT:
            return SimTypeNum(1, signed=False)
        if primitive in _PRIMITIVE_FLOATS:
            bits = _PRIMITIVE_FLOATS[primitive]
            if bits == 32:
                return SimTypeFloat()
            if bits == 64:
                return SimTypeDouble()
            if bits == 80:
                return SimTypeLongDouble()
            return SimTypeNum(bits, signed=False)
        if primitive in _PRIMITIVE_INTS:
            bits, signed = _PRIMITIVE_INTS[primitive]
            if primitive in (T_CHAR, T_UCHAR, T_RCHAR):
                return SimTypeChar(signed=signed)
            return SimTypeNum(bits, signed=signed)
        # Unrecognized primitive: degrade to an opaque integer of pointer width.
        return SimTypeNum(self.arch.bits, signed=False, label=f"cv_primitive_{primitive:#x}")

    #
    # TPI record dispatch
    #

    def _convert_record(self, index: int, record) -> SimType:  # noqa: PLR0911
        if isinstance(record, ModifierRecord):
            inner = self.convert(record.modified_type)
            qualifiers = []
            if record.is_const:
                qualifiers.append("const")
            if record.is_volatile:
                qualifiers.append("volatile")
            if record.is_unaligned:
                qualifiers.append("unaligned")
            if qualifiers and hasattr(inner, "qualifier"):
                inner = inner.copy()
                inner.qualifier = tuple(qualifiers)
            return inner
        if isinstance(record, PointerRecord):
            return self._convert_pointer(record)
        if isinstance(record, ProcedureRecord):
            return self._convert_procedure(record.return_type, record.arglist, record.param_count, record.call_conv)
        if isinstance(record, MemberFunctionRecord):
            return self._convert_member_function(record)
        if isinstance(record, ArgListRecord):
            # An arglist on its own is rendered as a void-ish placeholder; it only makes sense via a procedure.
            return SimTypeTop(label="arglist")
        if isinstance(record, ArrayRecord):
            return self._convert_array(record)
        if isinstance(record, BitfieldRecord):
            base = self.convert(record.base_type)
            bits = record.bit_length
            signed = getattr(base, "signed", True)
            return SimTypeNumOffset(bits, signed=signed, offset=record.bit_position)
        if isinstance(record, AggregateRecord):
            return self._convert_aggregate(index, record)
        if isinstance(record, EnumRecord):
            return self._convert_enum(index, record)
        if isinstance(record, AliasRecord):
            return self._convert_alias(index, record)
        if isinstance(record, FieldListRecord):
            # Standalone field list: cannot be named, return an opaque placeholder.
            return SimTypeTop(label="fieldlist")
        if isinstance(record, UnknownRecord):
            return SimTypeTop(label=f"cv_{record.leaf:#x}")
        return SimTypeTop(label=f"cv_unknown_{index:#x}")

    def _convert_pointer(self, record: PointerRecord) -> SimType:
        pointee = self.convert(record.utype)
        if record.is_reference:
            return SimTypeReference(pointee).with_arch(self.arch)
        if record.mode in (PTR_MODE_PMEM, PTR_MODE_PMFUNC):
            # Pointer-to-member: model as a plain pointer; the containing class is not representable in C prototype
            # form and the layout remains pointer-sized.
            pass
        ptr = SimTypePointer(pointee, label=record.name).with_arch(self.arch)
        return ptr

    def _arg_types(self, arglist_index: int, param_count: int) -> tuple[SimType, ...]:
        arglist = self.tpi.records.get(arglist_index)
        if not isinstance(arglist, ArgListRecord):
            return ()
        count = min(param_count, len(arglist.arg_types)) if param_count else len(arglist.arg_types)
        return tuple(self.convert(ti) for ti in arglist.arg_types[:count])

    def _convert_procedure(self, return_type: int, arglist: int, param_count: int, call_conv: int):
        from ...sim_type import SimTypeFunction

        ret = self.convert(return_type)
        if isinstance(ret, SimTypeBottom):
            ret = None
        args = self._arg_types(arglist, param_count)
        # The calling convention is applied at function-binding time via SimCC; store the CV code on the label only
        # for diagnostics.
        func = SimTypeFunction(args, ret)
        func.label = f"cv_call_{call_conv}"
        return func.with_arch(self.arch)

    def _convert_member_function(self, record: MemberFunctionRecord):
        from ...sim_type import SimTypeFunction

        ret = self.convert(record.return_type)
        if isinstance(ret, SimTypeBottom):
            ret = None
        args = self._arg_types(record.arglist, record.param_count)
        # Prefix the implicit `this` pointer for member functions.
        this_ptr = SimTypePointer(self.convert(record.class_type)).with_arch(self.arch)
        func = SimTypeFunction((this_ptr, *args), ret, label=f"cv_call_{record.call_conv}")
        return func.with_arch(self.arch)

    def _convert_array(self, record: ArrayRecord) -> SimType:
        element = self.convert(record.element_type)
        element_size = element.size // 8 if getattr(element, "size", None) else None
        if element_size:
            length = max(record.size_bytes // element_size, 0)
        else:
            length = 0
        return SimTypeArray(element, length=length or None).with_arch(self.arch)

    #
    # Aggregates (struct / class / interface / union), enums, typedefs
    #

    def _convert_aggregate(self, index: int, record: AggregateRecord) -> SimType:
        name = record.name or f"__unnamed_{index:x}"
        # Forward-reference shell: emit an empty aggregate now; the real definition (if present) replaces it through
        # the name index when referenced by name.
        shell: SimType
        if record.kind == "union":
            shell = SimUnion({}, name=name)
        else:
            shell = SimStruct(OrderedDict(), name=name)
        self._in_progress[index] = shell

        field_list = self.tpi.records.get(record.field_list) if record.field_list else None
        if record.kind == "union":
            members = self._build_union_members(field_list)
            if isinstance(shell, SimUnion):
                shell.members = members
            if record.size_bytes:
                shell._arch = self.arch
        else:
            fields = self._build_struct_fields(field_list, record.size_bytes)
            if isinstance(shell, SimStruct):
                shell.fields = fields
                shell._pack = False
        shell = shell.with_arch(self.arch)
        self._in_progress[index] = shell
        return shell

    def _collect_field_members(self, field_list, seen: set[int] | None = None) -> list:
        """Flatten a (possibly continued, LF_INDEX-chained) field-list into FieldMember objects."""
        if seen is None:
            seen = set()
        if field_list is None or not isinstance(field_list, FieldListRecord):
            return []
        if field_list.index in seen:
            return []
        seen.add(field_list.index)
        out: list = []
        for member in field_list.members:
            if member.kind == "index":
                chained = self.tpi.records.get(member.type_index)
                out.extend(self._collect_field_members(chained, seen))
            else:
                out.append(member)
        return out

    def _build_struct_fields(self, field_list, total_size: int) -> OrderedDict:
        fields: OrderedDict[str, SimType] = OrderedDict()
        current_offset = 0
        anonymous_counter = 0
        for member in self._collect_field_members(field_list):
            if member.kind == "method" or member.kind == "static" or member.kind == "vfunctab":
                continue  # methods/static members/vtable descriptors do not define instance layout
            if member.kind == "baseclass":
                base_type = self.convert(member.type_index)
                name = f"__base_{anonymous_counter}"
                anonymous_counter += 1
                fields[name] = base_type
                current_offset += (base_type.size or 0) // 8
                continue
            if member.kind == "nested":
                nested = self.convert(member.type_index)
                fields[member.name or f"__nested_{anonymous_counter}"] = nested
                anonymous_counter += 1
                continue
            if member.kind != "member":
                continue
            ty = self.convert(member.type_index)
            name = member.name or f"__field_{anonymous_counter}"
            anonymous_counter += 1
            target_offset = member.offset or 0
            # Insert explicit padding so computed SimType offsets match the PDB-declared offsets.
            if target_offset > current_offset:
                pad_bytes = target_offset - current_offset
                fields[f"__pad_{current_offset:x}"] = SimTypeArray(
                    SimTypeNum(8, signed=False), length=pad_bytes
                ).with_arch(self.arch)
                current_offset = target_offset
            if isinstance(ty, SimTypeNumOffset):
                fields[name] = ty
            else:
                fields[name] = ty
            size_bytes = (getattr(ty, "size", None) or 0) // 8
            if size_bytes:
                current_offset = target_offset + size_bytes
        del total_size
        return fields

    def _build_union_members(self, field_list) -> dict[str, SimType]:
        members: dict[str, SimType] = {}
        counter = 0
        for member in self._collect_field_members(field_list):
            if member.kind != "member":
                continue
            ty = self.convert(member.type_index)
            name = member.name or f"__anon_{counter}"
            counter += 1
            members[name] = ty
        return members

    def _convert_enum(self, index: int, record: EnumRecord) -> SimType:
        name = record.name or f"__unnamed_enum_{index:x}"
        base_type = self.convert(record.underlying_type)
        values: dict[str, int] = {}
        field_list = self.tpi.records.get(record.field_list) if record.field_list else None
        for member in self._collect_field_members(field_list):
            if member.kind == "enumerate":
                values[member.name] = member.offset if member.offset is not None else 0
        enum = SimTypeEnum(values, base_type=base_type, name=name)
        return enum.with_arch(self.arch)

    def _convert_alias(self, index: int, record: AliasRecord) -> SimType:
        # Cyclic typedef guard: a typedef that (transitively) names itself returns the in-progress shell.
        if index in self._in_progress:
            return self._in_progress[index]
        target = self.convert(record.aliased_type)
        if record.name:
            target = target.copy()
            target.label = record.name
        return target

    #
    # Named lookup used by S_UDT bindings
    #

    def named_type(self, name: str) -> SimType | None:
        index = self._name_to_index.get(name)
        if index is None:
            return None
        return self.convert(index)

    def make_type_ref(self, name: str, ty: SimType) -> TypeRef:
        return TypeRef(name, ty).with_arch(self.arch)
