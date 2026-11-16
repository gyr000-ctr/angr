"""
PDB (Microsoft Program Database / CodeView) debug-info support for angr.

This package parses PDB type (TPI/IPI), debug (DBI) and symbol (GSI/module) streams, maps CodeView type records onto
angr :class:`~angr.sim_type.SimType` objects, and binds function prototypes, calling conventions, struct/enum/typedef
names and global variables onto a project's knowledge base through the :class:`PDBTypesAnalysis`.
"""

from __future__ import annotations

from .msf import MSFFile, PDBFormatError
from .pdb_types import PDBTypesAnalysis
from .pdbfile import PDBFile, PDBLoadError, clear_pdb_cache, load_pdb
from .peinfo import CodeViewInfo, read_codeview_info

__all__ = (
    "CodeViewInfo",
    "MSFFile",
    "PDBFile",
    "PDBFormatError",
    "PDBLoadError",
    "PDBTypesAnalysis",
    "clear_pdb_cache",
    "load_pdb",
    "read_codeview_info",
)
