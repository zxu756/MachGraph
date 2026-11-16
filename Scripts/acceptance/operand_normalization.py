#!/usr/bin/env python3
"""Single source of truth for ARM64 operand normalization in differential checks.

Policy (fixed by `02-machgraph.md`, M2 item 2 and pre-work verification):
  - Exactly four reference-side operand comparison rules (O1-O4) are permitted.
  - Every difference outside O1-O4 is classified as an operand mismatch; this
    table may only shrink, never grow.
"""

from fractions import Fraction
import functools
import re
from typing import Any, Optional, Tuple, Union

OPERAND_NORMALIZATION_RULES = (
    {
        "id": "O1",
        "name": "whitespace_and_case",
        "reason": (
            "llvm-objdump inserts spaces inside Neon register lists (e.g. '{ v0.h }[1]') "
            "and differs in letter casing for hex digits or system operand identifiers; "
            "whitespace between tokens and ASCII letter case do not change operand meaning."
        ),
    },
    {
        "id": "O2",
        "name": "numeric_value",
        "reason": (
            "llvm-objdump mixes hexadecimal and decimal immediates (hex for general/address "
            "immediates, decimal for shifts/bitfields, both in hints, 16-zero '#0000000000000000' "
            "for movi.2d #0, 8-decimal-place floats like '#1.00000000'), whereas MachGraph uses "
            "decimal below 16, hex at 16+, and '%.6g' for floats. Signed integers (hex or decimal) "
            "and floating-point literals are compared by exact mathematical value."
        ),
    },
    {
        "id": "O3",
        "name": "adrp_comment_address",
        "reason": (
            "Under --macho, llvm-objdump prints a signed page count as adrp's immediate operand "
            "and places the resolved target page address in the trailing '; 0x...' comment, "
            "whereas MachGraph prints the resolved page address directly."
        ),
    },
    {
        "id": "O4",
        "name": "pc_relative_offset",
        "reason": (
            "llvm-objdump prints PC-relative '#offset' for adr and unbracketed literal loads "
            "(ldr, ldrsw, prfm), whereas MachGraph prints the resolved target address "
            "(instruction PC + offset)."
        ),
    },
)

OPERAND_NORMALIZATION_SUMMARY = (
    "O1 whitespace/case, O2 numeric value, O3 adrp comment addr, O4 pc-relative offset"
)

_LITERAL_LOAD_MNEMONICS = frozenset(("ldr", "ldrsw", "prfm"))
_SIGNED_INT_RE = re.compile(r"^([-+]?)(?:0[xX]([0-9a-fA-F]+)|(\d+))$")
_COMMENT_HEX_ADDR_RE = re.compile(r"^\s*(0[xX][0-9a-fA-F]+)\b")

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
    | (?P<ident>[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*)
    | (?P<num>\#?[-+]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)(?![a-zA-Z0-9_.]))
    | (?P<alnum>[a-zA-Z0-9_]+)
    | (?P<punct>.)
    """,
    re.VERBOSE,
)

_REG_SHAPE_RE = re.compile(
    r"^(?:(?P<cls>[xwbhsdq])(?:30|[12]?[0-9]|31)|(?P<vec>v)(?:3[01]|[12]?[0-9])(?P<arr>\.[a-z0-9]+)?|(?P<creg>c)(?:1[0-5]|[0-9]))$"
)

NumericValue = Union[int, Fraction]


def _parse_signed_int(text: str) -> Optional[int]:
    m = _SIGNED_INT_RE.match(text.strip())
    if not m:
        return None
    sign = -1 if m.group(1) == "-" else 1
    if m.group(2) is not None:
        return sign * int(m.group(2), 16)
    return sign * int(m.group(3), 10)


def _parse_numeric_token(raw_token: str) -> NumericValue:
    num_str = raw_token[1:] if raw_token.startswith("#") else raw_token
    sign = -1 if num_str.startswith("-") else 1
    mag_str = num_str[1:] if num_str.startswith(("+", "-")) else num_str
    if mag_str.startswith(("0x", "0X")):
        return sign * int(mag_str[2:], 16)
    if "." in mag_str or "e" in mag_str or "E" in mag_str:
        frac = Fraction(num_str)
        return int(frac.numerator) if frac.denominator == 1 else frac
    return sign * int(mag_str, 10)


def normalize_reference_operands(
    address: int,
    reference_mnemonic: str,
    raw_reference_operands: str,
) -> str:
    """Apply reference-side PC-relative rules O3 (`adrp`) and O4 (`adr` / literal loads)."""
    if ";" in raw_reference_operands:
        core_raw, comment_raw = raw_reference_operands.split(";", 1)
        core = core_raw.strip()
    else:
        core = raw_reference_operands.strip()
        comment_raw = ""

    mnem = reference_mnemonic.strip().lower()

    # O3: adrp takes target address from trailing '; 0x...' comment when operand is a page count
    if mnem == "adrp" and comment_raw:
        addr_match = _COMMENT_HEX_ADDR_RE.match(comment_raw)
        if addr_match is not None:
            parts = core.split(",")
            if len(parts) == 2 and _parse_signed_int(parts[1]) is not None:
                return f"{parts[0].strip()}, {addr_match.group(1)}"

    # O4: adr and unbracketed literal loads (ldr, ldrsw, prfm) replace '#offset' with PC + offset
    if mnem == "adr" or (mnem in _LITERAL_LOAD_MNEMONICS and "[" not in core and "]" not in core):
        parts = core.split(",")
        if len(parts) == 2:
            rhs = parts[1].strip()
            if rhs.startswith("#"):
                offset = _parse_signed_int(rhs[1:])
                if offset is not None:
                    target = (address + offset) & 0xFFFFFFFFFFFFFFFF
                    return f"{parts[0].strip()}, {hex(target)}"

    return core


@functools.lru_cache(maxsize=65536)
def canonicalize_operands(operands: str) -> Tuple[Tuple[str, Any], ...]:
    """Canonicalize an operand string under O1 (whitespace/case) and O2 (exact numeric value)."""
    tokens = []
    for m in _TOKEN_RE.finditer(operands):
        kind = m.lastgroup
        val = m.group()
        if kind == "ws":
            continue
        if kind == "num":
            tokens.append(("NUM", _parse_numeric_token(val)))
        elif kind in ("ident", "alnum"):
            tokens.append(("ID", val.lower()))
        else:
            tokens.append(("P", val.lower()))
    return tuple(tokens)


def operands_equal(
    reference_mnemonic: str,
    raw_reference_operands: str,
    machgraph_operands: str,
    address: int = 0,
) -> bool:
    """Return True iff `raw_reference_operands` and `machgraph_operands` agree under O1-O4."""
    ref_adjusted = normalize_reference_operands(address, reference_mnemonic, raw_reference_operands)
    mg_clean = (
        machgraph_operands.split(";", 1)[0].strip()
        if ";" in machgraph_operands
        else machgraph_operands.strip()
    )
    if ref_adjusted == mg_clean:
        return True
    return canonicalize_operands(ref_adjusted) == canonicalize_operands(mg_clean)


def _format_ident_shape(ident_lower: str) -> str:
    m = _REG_SHAPE_RE.match(ident_lower)
    if not m:
        return ident_lower
    if m.group("cls") is not None:
        cls = m.group("cls")
        # x31 / w31 do not appear as canonical names, but gp0..gp30 map to X / W
        if cls in ("x", "w") and ident_lower in ("x31", "w31"):
            return ident_lower
        return cls.upper()
    if m.group("vec") is not None:
        arr = m.group("arr") or ""
        return f"V{arr}"
    return "C"


def _format_num_shape(num_tok: str) -> str:
    prefix = "#" if num_tok.startswith("#") else ""
    rest = num_tok[1:] if prefix else num_tok
    sign = "-" if rest.startswith("-") else ""
    mag = rest[1:] if rest.startswith(("+", "-")) else rest
    if not mag.startswith(("0x", "0X")) and "." in mag:
        return f"{prefix}{sign}N.N"
    return f"{prefix}{sign}N"


@functools.lru_cache(maxsize=16384)
def operand_shape_for_category(operands: str) -> str:
    """Return structural shape with register numbers replaced by class letters and numbers by N."""
    core = operands.split(";", 1)[0].strip()
    if not core:
        return ""
    pieces = []
    prev_kind = None
    prev_text = ""
    for m in _TOKEN_RE.finditer(core):
        kind = m.lastgroup
        val = m.group()
        if kind == "ws":
            continue
        if kind == "ident":
            piece = _format_ident_shape(val.lower())
        elif kind == "alnum":
            piece = val.lower()
        elif kind == "num":
            piece = _format_num_shape(val)
        else:
            piece = val.lower()

        if pieces:
            if prev_text == ",":
                pieces.append(" ")
            elif prev_kind in ("ident", "alnum") and kind in ("ident", "alnum", "num"):
                pieces.append(" ")
        pieces.append(piece)
        prev_kind = kind
        prev_text = piece
    return "".join(pieces)
