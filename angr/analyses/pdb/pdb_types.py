"""
The ``PDBTypes`` analysis: bind PDB/CodeView debug information onto an angr project.

Given a PE project and a PDB file (located automatically next to the binary or supplied explicitly), the analysis

* parses the TPI/IPI type streams and registers structs/unions/enums/typedefs into ``kb.types``,
* attaches :class:`SimTypeFunction` prototypes and Windows calling conventions to functions,
* publishes function and global-variable names (and global variable types) into the knowledge base.

When no PDB is available, or the PDB is malformed, the analysis logs and returns without modifying the project, so
behavior is unchanged for binaries without debug info. Results are cached per PDB path by :mod:`pdbfile`, and the
analysis itself is cheap to re-run.
"""

from __future__ import annotations

import logging
import os

from ...calling_conventions import (
    SimCCMicrosoftAMD64,
    SimCCMicrosoftCdecl,
    SimCCMicrosoftFastcall,
    SimCCMicrosoftThiscall,
    SimCCStdcall,
    default_cc_for_project,
)
from ...knowledge_plugins.functions.function import PrototypeSource
from ...sim_type import (
    SimTypeBottom,
    SimTypeFunction,
    TypeRef,
)
from ..analysis import Analysis, register_analysis
from .constants import CVCall
from .dbi import SymbolEntry
from .pdbfile import PDBFile, PDBLoadError, clear_pdb_cache, load_pdb
from .peinfo import PEFormatError, read_codeview_info
from .tpi import AggregateRecord, AliasRecord, EnumRecord
from .type_translator import PDBTypeTranslator

_l = logging.getLogger(__name__)

# CodeView calling-convention byte -> SimCC class. The x86-64 convention ignores the byte entirely (there is only one
# Win64 ABI); these classes are used for 32-bit x86.
_CV_CALL_TO_CC = {
    CVCall.NEAR_C: SimCCMicrosoftCdecl,
    CVCall.FAR_C: SimCCMicrosoftCdecl,
    CVCall.NEAR_STD: SimCCStdcall,
    CVCall.FAR_STD: SimCCStdcall,
    CVCall.THISCALL: SimCCMicrosoftThiscall,
    CVCall.NEAR_FAST: SimCCMicrosoftFastcall,
    CVCall.FAR_FAST: SimCCMicrosoftFastcall,
}


class PDBTypesAnalysis(Analysis):
    """
    Import types and symbols from a PDB into the project's knowledge base.
    """

    def __init__(
        self,
        pdb_path: str | None = None,
        *,
        bind_types: bool = True,
        bind_functions: bool = True,
        bind_globals: bool = True,
        search_adjacent: bool = True,
    ):
        self.pdb: PDBFile | None = None
        self.translator: PDBTypeTranslator | None = None
        self.loaded = False
        self.error: str | None = None
        # Outputs (also useful for tests/assertions).
        self.bound_functions: dict[int, str] = {}
        self.bound_globals: dict[int, str] = {}
        self.bound_types: dict[str, str] = {}
        self._type_name_collisions: set[str] = set()

        try:
            self._run(pdb_path, bind_types, bind_functions, bind_globals, search_adjacent)
        except (PDBLoadError, PEFormatError, OSError) as ex:
            # Guaranteed fallback: never crash the host analysis pipeline.
            self.error = str(ex)
            _l.info("PDB type import skipped: %s", ex)

    # ------------------------------------------------------------------ run

    def _run(self, pdb_path, bind_types, bind_functions, bind_globals, search_adjacent) -> None:
        resolved = self._resolve_pdb_path(pdb_path, search_adjacent)
        if resolved is None:
            self.error = "No PDB file available for this binary"
            return

        self.pdb = load_pdb(resolved)
        self.translator = PDBTypeTranslator(self.pdb.tpi, self.pdb.ipi, self.project.arch)

        if bind_types:
            self._bind_named_types()
        if bind_functions:
            self._bind_symbols(functions=True, globals_=False)
        if bind_globals:
            self._bind_symbols(functions=False, globals_=True)
        self.loaded = True

    def _resolve_pdb_path(self, explicit: str | None, search_adjacent: bool) -> str | None:
        if explicit:
            return explicit if os.path.isfile(explicit) else None

        main_object = self.project.loader.main_object
        binary_path = getattr(main_object, "binary", None)
        if binary_path is None or not os.path.isfile(binary_path):
            return None
        try:
            with open(binary_path, "rb") as fp:
                pe_bytes = fp.read()
            cv = read_codeview_info(pe_bytes)
        except (PEFormatError, OSError):
            return None
        if cv is None or not cv.pdb_path:
            return None

        # 1. Exact path embedded in the PE (usually a build-machine absolute path) — accept if it exists locally.
        if os.path.isfile(cv.pdb_path):
            return cv.pdb_path
        # 2. PDB sitting next to the binary, matching either the embedded basename or the binary's own basename.
        if search_adjacent:
            directory = os.path.dirname(binary_path)
            candidates = [os.path.join(directory, os.path.basename(cv.pdb_path))]
            stem = os.path.splitext(os.path.basename(binary_path))[0]
            candidates.append(os.path.join(directory, stem + ".pdb"))
            for candidate in candidates:
                if os.path.isfile(candidate):
                    return candidate
        return None

    # ------------------------------------------------------------- types

    def _bind_named_types(self) -> None:
        assert self.pdb is not None and self.translator is not None
        # S_UDT symbols are the authoritative user-facing names (including typedef'd names) for type indices.
        udt_names: dict[int, list[str]] = {}
        for udt in self.pdb.udts:
            udt_names.setdefault(udt.type_index, []).append(udt.name)

        registered: set[str] = set()
        # First register every named aggregate/enum/alias directly from TPI records.
        for index, record in self.pdb.tpi.records.items():
            if getattr(record, "is_forward_ref", False):
                continue  # real definition wins; forward refs are skipped here
            name = getattr(record, "name", None)
            if not name:
                continue
            if isinstance(record, AggregateRecord):
                self._register_named_type(name, index, registered, kind=record.kind)
            elif isinstance(record, EnumRecord):
                self._register_named_type(name, index, registered, kind="enum")
            elif isinstance(record, AliasRecord) and record.name:
                self._register_named_type(name, index, registered, kind="typedef")

        # Then apply S_UDT names (typedef-style aliases pointing at a type index).
        for type_index, names in udt_names.items():
            if type_index < 0x1000 or type_index not in self.pdb.tpi.records:
                continue
            for name in names:
                if name in registered:
                    continue
                self._register_named_type(name, type_index, registered, kind="udt")

    def _register_named_type(self, name: str, index: int, registered: set[str], *, kind: str) -> None:
        assert self.translator is not None
        if name in registered:
            # Duplicate named type: keep the first registration but record the collision.
            self._type_name_collisions.add(name)
            return
        try:
            ty = self.translator.convert(index)
        except Exception as ex:  # pragma: no cover - defensive
            _l.debug("Skipping PDB type %s (%#x): %s", name, index, ex)
            return
        # Store under the bare name; the C "struct "/"union " convention is added as an alias for aggregates.
        self.kb.types[name] = TypeRef(name, ty).with_arch(self.project.arch)
        registered.add(name)
        self.bound_types[name] = kind
        if kind in ("struct", "class", "interface"):
            struct_name = f"struct {name}"
            if struct_name not in self.kb.types:
                self.kb.types[struct_name] = TypeRef(struct_name, ty).with_arch(self.project.arch)
        elif kind == "union":
            union_name = f"union {name}"
            if union_name not in self.kb.types:
                self.kb.types[union_name] = TypeRef(union_name, ty).with_arch(self.project.arch)
        elif kind == "enum":
            enum_name = f"enum {name}"
            if enum_name not in self.kb.types:
                self.kb.types[enum_name] = TypeRef(enum_name, ty).with_arch(self.project.arch)

    # ----------------------------------------------------------- symbols

    def _section_to_base(self) -> dict[int, int]:
        """Map PDB 1-based section numbers to their rebased load addresses."""
        result = {0: self.project.loader.main_object.linked_base}
        for i, section in enumerate(self.project.loader.main_object.sections, start=1):
            result[i] = section.min_addr
        return result

    def _bind_symbols(self, *, functions: bool, globals_: bool) -> None:
        assert self.pdb is not None and self.translator is not None
        section_bases = self._section_to_base()
        num_sections = len(self.project.loader.main_object.sections)

        for symbol in self.pdb.symbols:
            base = section_bases.get(symbol.section)
            # Reject data records whose section number is not a real image section. Some compiler-emitted records
            # (e.g. SDK enumerator constants carried as pseudo-data) lack a valid (section, offset) location and must
            # not be bound as globals at garbage addresses.
            if symbol.section < 1 or symbol.section > num_sections or base is None:
                continue
            addr = base + symbol.offset
            if symbol.is_function and functions:
                self._bind_function(symbol, addr)
            elif not symbol.is_function and globals_:
                self._bind_global(symbol, addr)

        # Public symbols (S_PUB32) carry no type but provide names for functions/globals not otherwise named.
        for symbol in self.pdb.symbols:
            if not symbol.is_public:
                continue
            if symbol.section < 1 or symbol.section > num_sections:
                continue
            base = section_bases.get(symbol.section)
            if base is None:
                continue
            addr = base + symbol.offset
            if addr in self.kb.labels:
                continue
            self.kb.labels[addr] = symbol.name
            if functions:
                self.bound_functions.setdefault(addr, symbol.name)
            elif globals_:
                self.bound_globals.setdefault(addr, symbol.name)

    def _bind_function(self, symbol: SymbolEntry, addr: int) -> None:
        assert self.translator is not None
        func = self.kb.functions.function(addr=addr, create=True)
        if func is None:
            return
        func.name = symbol.name
        func.is_default_name = False
        func.from_signature = "pdb"

        if symbol.type_index and symbol.type_index >= 0x1000:
            try:
                proto = self.translator.convert(symbol.type_index)
            except Exception as ex:  # pragma: no cover - defensive
                _l.debug("Prototype conversion failed for %s: %s", symbol.name, ex)
                proto = None
            if isinstance(proto, SimTypeFunction):
                func.set_prototype(None, proto, source=PrototypeSource.SIGNATURES)
                cc = self._cc_for_prototype(proto)
                if cc is not None:
                    func.calling_convention = cc
        self.bound_functions[addr] = symbol.name

    def _cc_for_prototype(self, proto: SimTypeFunction):
        # Win64 always uses the single Microsoft AMD64 ABI regardless of the CV call byte.
        default = default_cc_for_project(self.project)
        if self.project.arch.name == "AMD64":
            return SimCCMicrosoftAMD64(self.project.arch)
        # 32-bit x86: decode the CV call convention stashed on the prototype label.
        cv_byte = None
        if proto.label and proto.label.startswith("cv_call_"):
            try:
                cv_byte = int(proto.label.split("_")[-1])
            except ValueError:
                cv_byte = None
        cc_cls = _CV_CALL_TO_CC.get(cv_byte) if cv_byte is not None else None
        if cc_cls is None:
            return default(self.project.arch) if default is not None else None
        return cc_cls(self.project.arch)

    def _bind_global(self, symbol: SymbolEntry, addr: int) -> None:
        assert self.translator is not None
        # Do not clobber a label already established for this address (e.g. a loader symbol or an earlier PDB entry).
        if addr not in self.kb.labels:
            self.kb.labels[addr] = symbol.name
        self.bound_globals[addr] = self.kb.labels[addr]
        if symbol.type_index and symbol.type_index >= 0x1000:
            try:
                ty = self.translator.convert(symbol.type_index)
            except Exception as ex:  # pragma: no cover - defensive
                _l.debug("Global type conversion failed for %s: %s", symbol.name, ex)
                return
            if isinstance(ty, SimTypeBottom):
                return
            # Record the global's type in kb.types keyed by its name; variables consumers can resolve by label.
            if symbol.name not in self.kb.types:
                self.kb.types[symbol.name] = TypeRef(symbol.name, ty).with_arch(self.project.arch)


# Re-exported for callers that want to invalidate the on-disk PDB cache.
__all__ = ("PDBTypesAnalysis", "clear_pdb_cache")

register_analysis(PDBTypesAnalysis, "PDBTypes")
