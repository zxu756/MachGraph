#!/usr/bin/env python3
"""Single source of truth for ARM64 mnemonic normalization in differential checks.

Both `mnemonic-agreement.py` and `differential.py` import this module so the
allowed normalization table exists in exactly one place.

Policy (fixed by `02-machgraph.md`, M1 item 3):
  - Exactly three rules are permitted.
  - This table may only shrink in future milestones (M2 removes rules as
    MachGraph aligns wide-immediate `mov` and `udf`), never grow.
"""

import re
from typing import List, Tuple

REFERENCE_COMMAND_TEMPLATE = (
    "xcrun llvm-objdump --macho -d --no-show-raw-insn --arch=<slice> "
    "--mattr=+bti --section=__TEXT,__text <file>"
)


def build_reference_command(binary: str, arch: str) -> List[str]:
    """Return the fixed reference `llvm-objdump` argv for `<binary>` and `<arch>`."""
    return [
        "xcrun",
        "llvm-objdump",
        "--macho",
        "-d",
        "--no-show-raw-insn",
        f"--arch={arch}",
        "--mattr=+bti",
        "--section=__TEXT,__text",
        binary,
    ]

# Declarative table of the ONLY three permitted normalization rules, each with
# its architectural rationale.
NORMALIZATION_RULES = (
    {
        "id": "wide_immediate_mov",
        "reference": "mov",
        "machgraph": ("movz", "movn"),
        "reason": (
            "llvm-objdump prints the preferred alias 'mov' for MOVZ/MOVN "
            "wide-immediate moves when representable as a synthesized immediate, "
            "whereas MachGraph prints the underlying 'movz'/'movn' mnemonic "
            "(scheduled for M2)."
        ),
    },
    {
        "id": "permanently_undefined_udf",
        "reference": "udf",
        "machgraph": (".inst",),
        "reason": (
            "llvm-objdump prints 'udf' for permanently-undefined A64 words "
            "(0x0000_0000..0x0000_ffff), whereas MachGraph emits raw '.inst' "
            "directives for undefined encodings (scheduled for M2)."
        ),
    },
    {
        "id": "darwin_vector_arrangement_suffix",
        "reference": "<mnemonic>.<arrangement> (excluding b.<cond>)",
        "machgraph": "<mnemonic> (arrangement attached to vector register operands)",
        "reason": (
            "Apple's llvm-objdump Mach-O printer appends Neon arrangement "
            "specifiers to the mnemonic (e.g. 'fmov.2d', 'cmeq.16b'), whereas "
            "MachGraph places arrangement suffixes on the vector register "
            "operands ('fmov v0.2d, ...'). Conditional branches ('b.eq', "
            "'b.ne', ...) are kept intact because the condition is part of the "
            "branch mnemonic."
        ),
    },
)

NORMALIZATION_SUMMARY = "movz/movn->mov, udf->.inst, vector suffix dropped"

_DARWIN_ARRANGEMENT_SUFFIX_RE = re.compile(r"\.(?:16b|8b|8h|4h|4s|2s|2d|1d|1q|b|h|s|d|q)$")


def normalize_reference_mnemonic(mnemonic: str) -> str:
    """Apply Rule 3: strip a Neon arrangement suffix on the reference mnemonic, keeping `b.<cond>`."""
    lowered = mnemonic.strip().lower()
    if lowered.startswith("b."):
        return lowered
    return _DARWIN_ARRANGEMENT_SUFFIX_RE.sub("", lowered)


def mnemonics_agree(normalized_reference: str, machgraph_mnemonic: str) -> bool:
    """Compare a Rule-3-normalized reference mnemonic against a MachGraph mnemonic under Rules 1 and 2."""
    mg = machgraph_mnemonic.strip().lower()
    if mg == normalized_reference:
        return True
    if normalized_reference == "mov" and mg in ("movz", "movn"):  # Rule 1
        return True
    if normalized_reference == "udf" and mg == ".inst":  # Rule 2
        return True
    return False


def classify_mnemonic_pair(raw_reference: str, raw_machgraph: str) -> Tuple[str, str, str]:
    """Classify one instruction's mnemonics as ('agree' | 'unknown' | 'wrong', norm_ref, norm_mg)."""
    norm_ref = normalize_reference_mnemonic(raw_reference)
    norm_mg = raw_machgraph.strip().lower()
    if mnemonics_agree(norm_ref, norm_mg):
        return ("agree", norm_ref, norm_mg)
    if norm_mg == ".inst":
        return ("unknown", norm_ref, norm_mg)
    return ("wrong", norm_ref, norm_mg)
