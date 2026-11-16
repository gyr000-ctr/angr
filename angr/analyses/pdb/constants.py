"""
CodeView (CV) constants used by PDB type and symbol records.

Values follow the public Microsoft ``cvinfo.h`` definitions (and the LLVM ``CodeView`` headers). Only the subset
needed by the type/symbol importer is enumerated; unknown leaves are handled generically by the parser rather than
raising.
"""

from __future__ import annotations

import enum

# ---------------------------------------------------------------------------
# Type record leaves (TPI / IPI streams)
# ---------------------------------------------------------------------------

LF_MODIFIER = 0x1001
LF_POINTER = 0x1002
LF_ARRAY_ST = 0x1003
LF_CLASS_ST = 0x1004
LF_STRUCTURE_ST = 0x1005
LF_UNION_ST = 0x1006
LF_ENUM_ST = 0x1007
LF_PROCEDURE = 0x1008
LF_MFUNCTION = 0x1009
LF_COBOL0 = 0x100A
LF_BARRAY = 0x100B
LF_DIMARRAY_ST = 0x100C
LF_VFTPATH = 0x100D
LF_PRECOMP_ST = 0x100E
LF_OEM = 0x100F
LF_ALIAS_ST = 0x1010
LF_OEM2 = 0x1011

LF_SKIP = 0x1200
LF_ARGLIST = 0x1201
LF_DEFARG_ST = 0x1202
LF_FIELDLIST = 0x1203
LF_DERIVED = 0x1204
LF_BITFIELD = 0x1205
LF_METHODLIST = 0x1206
LF_DIMCONU = 0x1207
LF_DIMCONLU = 0x1208
LF_DIMVARU = 0x1209
LF_DIMVARLU = 0x120A
LF_BCLASS = 0x1400
LF_VBCLASS = 0x1401
LF_IVBCLASS = 0x1402
LF_INDEX = 0x1404
LF_MEMBER_ST = 0x1405
LF_STMEMBER_ST = 0x1406
LF_METHOD_ST = 0x1407
LF_NESTTYPE_ST = 0x1408
LF_VFUNCTAB = 0x1409
LF_FRIENDCLS = 0x140A
LF_ONEMETHOD_ST = 0x140B
LF_VFUNCOFF = 0x140C
LF_NESTTYPEEX_ST = 0x140D
LF_MEMBERMODIFY_ST = 0x140E
LF_MANAGED_ST = 0x140F

LF_TYPESERVER = 0x1501
LF_ENUMERATE = 0x1502
LF_ARRAY = 0x1503
LF_CLASS = 0x1504
LF_STRUCTURE = 0x1505
LF_UNION = 0x1506
LF_ENUM = 0x1507
LF_DIMARRAY = 0x1508
LF_PRECOMP = 0x1509
LF_ALIAS = 0x150A
LF_DEFARG = 0x150B
LF_FRIENDFCN = 0x150C
LF_MEMBER = 0x150D
LF_STMEMBER = 0x150E
LF_METHOD = 0x150F
LF_NESTTYPE = 0x1510
LF_ONEMETHOD = 0x1511
LF_NESTTYPEEX = 0x1512
LF_MEMBERMODIFY = 0x1513
LF_MANAGED = 0x1514
LF_TYPESERVER2 = 0x1515
LF_STRIDED_ARRAY = 0x1516
LF_HLSL = 0x1517
LF_MODIFIER_EX = 0x1518
LF_INTERFACE = 0x1519
LF_BINTERFACE = 0x151A
LF_VECTOR = 0x151B
LF_MATRIX = 0x151C
LF_VFTABLE = 0x151D

LF_FUNC_ID = 0x1601
LF_MFUNC_ID = 0x1602
LF_BUILDINFO = 0x1603
LF_SUBSTR_LIST = 0x1604
LF_STRING_ID = 0x1605
LF_UDT_SRC_LINE = 0x1606
LF_UDT_MOD_SRC_LINE = 0x1607

# Numeric leaf prefixes (values below LF_CHAR are encoded directly as a u16).
LF_CHAR = 0x8000
LF_SHORT = 0x8001
LF_USHORT = 0x8002
LF_LONG = 0x8003
LF_ULONG = 0x8004
LF_REAL32 = 0x8005
LF_REAL64 = 0x8006
LF_REAL80 = 0x8007
LF_REAL128 = 0x8008
LF_QUADWORD = 0x8009
LF_UQUADWORD = 0x800A
LF_REAL48 = 0x800B
LF_OCTWORD = 0x8017
LF_UOCTWORD = 0x8018

# Field-list sub-record leaves.
FLD_BCLASS = 0x1400
FLD_VBCLASS = 0x1401
FLD_IVBCLASS = 0x1402
FLD_INDEX = 0x1404
FLD_MEMBER_ST = 0x1405
FLD_STMEMBER_ST = 0x1406
FLD_METHOD_ST = 0x1407
FLD_NESTTYPE_ST = 0x1408
FLD_VFUNCTAB = 0x1409
FLD_ONEMETHOD_ST = 0x140B
FLD_VFUNCOFF = 0x140C
FLD_NESTTYPEEX_ST = 0x140D
FLD_MEMBER = 0x150D
FLD_STMEMBER = 0x150E
FLD_METHOD = 0x150F
FLD_NESTTYPE = 0x1510
FLD_ONEMETHOD = 0x1511
FLD_ENUMERATE = 0x1502
FLD_FRIENDFCN = 0x150C
FLD_NESTTYPEEX = 0x1512

AGGREGATE_LEAVES = {
    LF_CLASS,
    LF_CLASS_ST,
    LF_STRUCTURE,
    LF_STRUCTURE_ST,
    LF_INTERFACE,
}
UNION_LEAVES = {LF_UNION, LF_UNION_ST}
ENUM_LEAVES = {LF_ENUM, LF_ENUM_ST}

# ---------------------------------------------------------------------------
# Symbol record kinds (DBI / GSI / module streams)
# ---------------------------------------------------------------------------

S_COMPILE = 0x1001
S_OBJNAME = 0x1102
S_GDATA32 = 0x1105
S_LDATA32 = 0x1107
S_GTHREAD32 = 0x1106
S_LTHREAD32 = 0x1108
S_UDT = 0x110C
S_PUB32 = 0x110D
S_LPROC32 = 0x110E
S_GPROC32 = 0x110F
S_GPROCREF = 0x1110
S_LPROCREF = 0x1111
S_THUNK32 = 0x1120
S_LPROC32_ID = 0x1127
S_GPROC32_ID = 0x1128
S_BUILDINFO = 0x1139
S_CONSTANT = 0x1125
S_MANCONSTANT = 0x1126

PROC_SYMBOLS = {S_LPROC32, S_GPROC32, S_LPROC32_ID, S_GPROC32_ID}
DATA_SYMBOLS = {S_GDATA32, S_LDATA32, S_GTHREAD32, S_LTHREAD32}

# ---------------------------------------------------------------------------
# Built-in (simple) type encoding
# ---------------------------------------------------------------------------
# A simple type index is mode (high byte) | primitive (low byte). Primitives below 0x1000 are built in and never
# appear in the TPI stream.


class SimpleTypeMode(enum.IntEnum):
    DIRECT = 0x0000
    NEAR_PTR = 0x0100
    FAR_PTR = 0x0200
    HUGE_PTR = 0x0300
    NEAR_PTR32 = 0x0400
    FAR_PTR32 = 0x0500
    NEAR_PTR64 = 0x0600


# Primitive base type indices (low byte values).
T_NOTYPE = 0x0000
T_ABS = 0x0001
T_SEGMENT = 0x0002
T_VOID = 0x0003
T_HRESULT = 0x0008
T_CHAR = 0x0010
T_UCHAR = 0x0020
T_RCHAR = 0x0070
T_WCHAR = 0x0071
T_CHAR16 = 0x007A
T_CHAR32 = 0x007B
T_INT1 = 0x0068
T_UINT1 = 0x0069
T_SHORT = 0x0011
T_USHORT = 0x0021
T_INT2 = 0x0072
T_UINT2 = 0x0073
T_LONG = 0x0012
T_ULONG = 0x0022
T_INT4 = 0x0074
T_UINT4 = 0x0075
T_QUAD = 0x0013
T_UQUAD = 0x0023
T_INT8 = 0x0076
T_UINT8 = 0x0077
T_OCT = 0x0014
T_UOCT = 0x0024
T_INT16 = 0x0078
T_UINT16 = 0x0079
T_REAL16 = 0x0046
T_REAL32 = 0x0040
T_REAL32PP = 0x0045
T_REAL48 = 0x0044
T_REAL64 = 0x0041
T_REAL80 = 0x0042
T_REAL128 = 0x0043
T_BOOL32FF = 0x0062
T_BOOL32 = T_BOOL32FF  # alias used by modern MSVC for plain _Bool32
T_BIT = 0x0060

# The first type index actually stored in the TPI stream; everything below is a built-in/simple type.
TPI_FIRST_NON_BUILTIN = 0x1000

# ---------------------------------------------------------------------------
# Calling convention (CV_call_e, the byte embedded in LF_PROCEDURE/LF_MFUNCTION)
# ---------------------------------------------------------------------------


class CVCall(enum.IntEnum):
    NEAR_C = 0x00
    FAR_C = 0x01
    NEAR_PASCAL = 0x02
    FAR_PASCAL = 0x03
    NEAR_FAST = 0x04
    FAR_FAST = 0x05
    SKIPPED = 0x06
    NEAR_STD = 0x07
    FAR_STD = 0x08
    NEAR_SYS = 0x09
    FAR_SYS = 0x0A
    THISCALL = 0x0B
    MIPSCALL = 0x0C
    GENERIC = 0x0D
    ALPHACALL = 0x0E
    PPCCALL = 0x0F
    SHCALL = 0x10
    ARMCALL = 0x11
    SH5CALL = 0x12
    TRICALL = 0x13
    M32RCALL = 0x14
    RESERVED = 0x15
    EBCCALL = 0x16
    X86_INLINETYPE = 0x17
    NEAR_VECTOR = 0x18
    RESERVED19 = 0x19


# Pointer mode (low 3 bits of LF_POINTER attributes).
PTR_MODE_PTR = 0
PTR_MODE_REF = 1
PTR_MODE_PMEM = 2
PTR_MODE_PMFUNC = 3

# Property (CV_prop_t) bit 0 marks a forward-reference record.
PROP_FWDREF = 0x01
PROP_PACKED = 0x80
PROP_CNESTED = 0x08
PROP_SCALED = 0x04  # "scoped" enum flag sits at bit 2 of the high byte in practice

# ---------------------------------------------------------------------------
# TPI / DBI stream header versions
# ---------------------------------------------------------------------------

TPI_IMPLEMENTATION_V70 = 0x0131CA0B
DBI_VERSION_V70 = 0x01310977
GSI_HASH_VERSION = 0xF12F091A
GSI_HASH_SIGNATURE = 0xFFFFFFFF
