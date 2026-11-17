#!/usr/bin/env python3
"""Generate and check per-group ARM64 encoding reference tables (`Fixtures/a64/<group>.tsv`).

Usage:
  Scripts/acceptance/encoding-table.py generate <group...> [--out-dir <dir>]
  Scripts/acceptance/encoding-table.py generate --all [--out-dir <dir>]
  Scripts/acceptance/encoding-table.py check <group...> [--machgraph <path>] [--table-dir <dir>]
  Scripts/acceptance/encoding-table.py check --all [--machgraph <path>] [--table-dir <dir>]
  Scripts/acceptance/encoding-table.py check --table <path.tsv> [--machgraph <path>]

Design (`02-machgraph.md`, M2 item 3):
  - Each encoding group produces one TSV table (`<= 4,096` data rows) under `Fixtures/a64/<group>.tsv`.
  - Non-register fields in the group are enumerated exhaustively; register fields are fixed to
    distinct register numbers so swapped operands are caught; large immediate fields sample
    `0`, `1`, a midpoint value, and maximum value.
  - `generate` compiles the `.inst` words into an `arm64e` Mach-O with `xcrun clang` and runs the
    shared reference command (`mnemonic_normalization.build_reference_command`). Every row comes
    verbatim from real `llvm-objdump` output; no rows are handwritten.
  - `check` compiles the table's machine words into a temporary Mach-O, runs `machgraph disasm`,
    and compares mnemonics (`mnemonic_normalization`) and operands (`operand_normalization`).
    Rows where the reference prints `.long` require MachGraph to print `.inst`.

Exit status:
  0 when all checked rows match;
  1 when any row mismatches or a runtime/table validation error occurs;
  2 on command-line usage errors.
"""

import argparse
import collections
from dataclasses import dataclass
import functools
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from mnemonic_normalization import (  # noqa: E402
    NORMALIZATION_RULES,
    NORMALIZATION_SUMMARY,
    REFERENCE_COMMAND_TEMPLATE,
    build_reference_command,
    classify_mnemonic_pair,
    find_non_generic_neon_mnemonic,
    has_neon_arrangement_suffix,
)
from operand_normalization import (  # noqa: E402
    OPERAND_NORMALIZATION_RULES,
    OPERAND_NORMALIZATION_SUMMARY,
    operand_shape_for_category,
    operands_equal,
)

DEFAULT_TABLE_DIR = os.path.join(REPO_ROOT, "Fixtures", "a64")
MAX_TABLE_ROWS = 4096
TARGET_ARCH = "arm64e"

_REF_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")
_WORD_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{8}$")
_GENERIC_NEON_OPERAND_RE = re.compile(
    r"\bv(?:3[01]|[12]?[0-9])\.(?:16b|8b|8h|4h|2h|4s|2s|2d|1d|1q|b|h|s|d|q)\b"
)


class _UsageError(Exception):
    """Raised on CLI usage errors (exit code 2)."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(f"{self.prog}: error: {message}")


@dataclass(frozen=True)
class EncodingGroupSpec:
    name: str
    title: str
    header_notes: Tuple[str, ...]
    generate_words: Callable[[], List[int]]


def _generate_move_wide_imm_words() -> List[int]:
    """ARM DDI 0487 C4.1.92.5 Move wide (immediate): bits[28:23] == 0b100101."""
    words: List[int] = []
    for sf in (0, 1):
        for opc in (0, 1, 2, 3):
            for hw in (0, 1, 2, 3):
                for imm16 in (0x0000, 0x0001, 0x8000, 0xFFFF):
                    rd = 1
                    word = (
                        (sf << 31)
                        | (opc << 29)
                        | (0b100101 << 23)
                        | (hw << 21)
                        | (imm16 << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_logical_imm_words() -> List[int]:
    """ARM DDI 0487 C4.1.92.4 Logical (immediate): bits[28:23] == 0b100100."""
    words: List[int] = []
    # Distinct (Rd, Rn) pairs covering general registers (1, 2), ORR's mov alias Rn=ZR (1, 31),
    # and ANDS's tst alias / SP destination Rd=31 (31, 2).
    reg_pairs = ((1, 2), (1, 31), (31, 2))
    immr_samples = (0, 1, 16, 63)
    imms_samples = (0, 1, 24, 63)
    for sf in (0, 1):
        for opc in (0, 1, 2, 3):
            for n_bit in (0, 1):
                for immr in immr_samples:
                    for imms in imms_samples:
                        for rd, rn in reg_pairs:
                            word = (
                                (sf << 31)
                                | (opc << 29)
                                | (0b100100 << 23)
                                | (n_bit << 22)
                                | (immr << 16)
                                | (imms << 10)
                                | (rn << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_load_store_reg_offset_words() -> List[int]:
    """ARM DDI 0487 C4.1.94.10 Load/store register (register offset): (word & 0x3b200c00) == 0x38200800."""
    words: List[int] = []
    rn = 2
    rm = 3
    for size in (0, 1, 2, 3):
        for v_bit in (0, 1):
            for opc in (0, 1, 2, 3):
                # When (size, V, opc) == (3, 0, 2), bits[4:0] is the non-register 5-bit `prfop` field
                # (covering PRFM 0..23 and FEAT_RPRFM 24..31), not a general/SIMD target register.
                is_prfm_space = size == 3 and v_bit == 0 and opc == 2
                low5_values: Sequence[int] = range(32) if is_prfm_space else (1,)
                for option in range(8):
                    for s_bit in (0, 1):
                        for low5 in low5_values:
                            word = (
                                (size << 30)
                                | (0b111 << 27)
                                | (v_bit << 26)
                                | (opc << 22)
                                | (1 << 21)
                                | (rm << 16)
                                | (option << 13)
                                | (s_bit << 12)
                                | (0b10 << 10)
                                | (rn << 5)
                                | low5
                            )
                            words.append(word)
    return words


def _generate_cond_branch_imm_words() -> List[int]:
    """ARM DDI 0487 C4.1.93.1 Conditional branch (immediate): (word & 0xfe000000) == 0x54000000."""
    words: List[int] = []
    imm19_samples = (0x00000, 0x00001, 0x40000, 0x7FFFF)
    for o1 in (0, 1):
        for imm19 in imm19_samples:
            for o0 in (0, 1):
                for cond in range(16):
                    word = (
                        0x54000000
                        | (o1 << 24)
                        | (imm19 << 5)
                        | (o0 << 4)
                        | cond
                    )
                    words.append(word)
    return words


def _generate_advsimd_copy_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.8 Advanced SIMD copy (and bit[15]=1 sibling space): (word & 0x9fe00400) == 0x0e000400."""
    words: List[int] = []
    rn = 2
    rd = 1
    for q_bit in (0, 1):
        for op_bit in (0, 1):
            for imm5 in range(32):
                for bit15 in (0, 1):
                    for imm4 in range(16):
                        word = (
                            (q_bit << 30)
                            | (op_bit << 29)
                            | (0b01110000 << 21)
                            | (imm5 << 16)
                            | (bit15 << 15)
                            | (imm4 << 11)
                            | (1 << 10)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)
    return words


def _generate_bitfield_words() -> List[int]:
    """ARM DDI 0487 C4.1.92.6 Bitfield (SBFM / BFM / UBFM): fixed bits[28:23] = 0b100110."""
    words: List[int] = []
    imm_samples = (0, 1, 7, 15, 16, 31, 32, 63)
    reg_pairs = ((1, 2), (1, 31), (31, 2))
    for sf in (0, 1):
        for opc in (0, 1, 2, 3):
            for n_bit in (0, 1):
                for immr in imm_samples:
                    for imms in imm_samples:
                        for rd, rn in reg_pairs:
                            word = (
                                (sf << 31)
                                | (opc << 29)
                                | (0b100110 << 23)
                                | (n_bit << 22)
                                | (immr << 16)
                                | (imms << 10)
                                | (rn << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_lse_atomic_words() -> List[int]:
    """ARM DDI 0487 C4.1.94.8 Atomic memory operations: (word & 0x3f200c00) == 0x38200000."""
    words: List[int] = []
    # Distinct (Rs, Rn, Rt) tuples covering general registers (3, 2, 1), Rt=ZR for A=1 acquire
    # retention + A=0 ST* preferred aliases (3, 2, 31), Rs=ZR / Rs=11111 LDAPR discriminator (31, 2, 1),
    # and Rn=SP with Rt=ZR (3, 31, 31).
    reg_tuples = ((3, 2, 1), (3, 2, 31), (31, 2, 1), (3, 31, 31))
    for size in (0, 1, 2, 3):
        for a_bit in (0, 1):
            for r_bit in (0, 1):
                for o3 in (0, 1):
                    for opc in range(8):
                        for rs, rn, rt in reg_tuples:
                            word = (
                                (size << 30)
                                | (0b111000 << 24)
                                | (a_bit << 23)
                                | (r_bit << 22)
                                | (1 << 21)
                                | (rs << 16)
                                | (o3 << 15)
                                | (opc << 12)
                                | (0b00 << 10)
                                | (rn << 5)
                                | rt
                            )
                            words.append(word)
    return words


def _generate_fp_imm_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.24 Floating-point immediate & C4.1.95.22 Floating-point compare."""
    words: List[int] = []
    # 1. All 4 x 256 = 1,024 combinations of ftype=0..3 (S, D, unallocated 10, H) and imm8=0..255
    #    with sf=0, S=0, Rn=0, Rd=1.
    for ftype in range(4):
        for imm8 in range(256):
            word = 0x1E201000 | (ftype << 22) | (imm8 << 13) | 1
            words.append(word)

    # 2. All 2 x 2 x 4 x 4 x 2 = 128 combinations of FCMP / FCMPE across sf=0..1, S=0..1,
    #    ftype=0..3, opc=0..3 (register vs #0.0, quiet vs signaling), and Rm in {0, 3} with Rn=2.
    for sf in (0, 1):
        for s_bit in (0, 1):
            for ftype in range(4):
                for opc in range(4):
                    for rm in (0, 3):
                        word = (
                            (sf << 31)
                            | (s_bit << 29)
                            | 0x1E202000
                            | (ftype << 22)
                            | (rm << 16)
                            | (2 << 5)
                            | (opc << 3)
                        )
                        words.append(word)
    return words


def _generate_add_sub_ext_reg_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.2 Add/subtract (extended register): (word & 0x1f200000) == 0x0b200000."""
    words: List[int] = []
    reg_pairs = ((1, 2), (31, 2), (1, 31), (31, 31))
    imm3_samples = (0, 1, 4, 7)
    rm = 3
    for sf in (0, 1):
        for op in (0, 1):
            for s_bit in (0, 1):
                for opt in range(4):
                    for option in range(8):
                        for imm3 in imm3_samples:
                            for rd, rn in reg_pairs:
                                word = (
                                    (sf << 31)
                                    | (op << 30)
                                    | (s_bit << 29)
                                    | (0b01011 << 24)
                                    | (opt << 22)
                                    | (1 << 21)
                                    | (rm << 16)
                                    | (option << 13)
                                    | (imm3 << 10)
                                    | (rn << 5)
                                    | rd
                                )
                                words.append(word)
    return words


def _generate_system_instr_words() -> List[int]:
    """ARM DDI 0487 C4.1.93.6 System instructions (SYS / SYSL): (word & 0xffd80000) == 0xd5080000."""
    words: List[int] = []
    crm_samples = (1, 8)
    op2_samples = (0, 1, 4, 7)
    rt_samples = (1, 31)
    for l_bit in (0, 1):
        for op1 in range(8):
            for crn in range(16):
                for crm in crm_samples:
                    for op2 in op2_samples:
                        for rt in rt_samples:
                            word = (
                                0xD5080000
                                | (l_bit << 21)
                                | (op1 << 16)
                                | (crn << 12)
                                | (crm << 8)
                                | (op2 << 5)
                                | rt
                            )
                            words.append(word)
    return words


def _make_sysreg_words_generator(is_read: bool, op1_val: int) -> Callable[[], List[int]]:
    """ARM DDI 0487 C4.1.93.7 System register move (MRS L=1 / MSR L=0) slice for fixed op1."""

    def _gen() -> List[int]:
        words: List[int] = []
        base = 0xD5200000 if is_read else 0xD5000000
        rt = 1
        for op0 in (2, 3):
            for crn in range(16):
                for crm in range(16):
                    for op2 in range(8):
                        sys_enc = (
                            ((op0 & 0x3) << 14)
                            | ((op1_val & 0x7) << 11)
                            | (crn << 7)
                            | (crm << 3)
                            | op2
                        )
                        words.append(base | (sys_enc << 5) | rt)
        return words

    return _gen


def _generate_udf_words() -> List[int]:
    """ARM DDI 0487 C4.1.91 Reserved — UDF #imm16 ((word & 0xffff0000) == 0) plus high-16-bit != 0 counterexamples."""
    udf_imms = set(range(0x0000, 0x0100))
    udf_imms.update(range(0xFF00, 0x10000))
    for hi in range(1, 255):
        udf_imms.add(hi << 8)
        udf_imms.add((hi << 8) | hi)
    for bit in range(16):
        udf_imms.add(1 << bit)
        udf_imms.add(0xFFFF ^ (1 << bit))
    udf_imms.update((0x0FFF, 0x1000, 0x1234, 0x5555, 0x7FFF, 0x8001, 0xAAAA, 0xABCD, 0xBEEF, 0xBFFB, 0xDEAD))
    words: List[int] = sorted(udf_imms)

    reserved_hi16_samples = (
        0x0001,
        0x0002,
        0x0004,
        0x0008,
        0x0010,
        0x0020,
        0x0040,
        0x0080,
        0x0100,
        0x0200,
        0x03FF,
        0x8000,
        0x8001,
        0x81FF,
    )
    for hi16 in reserved_hi16_samples:
        for lo16 in (0x0000, 0x0001, 0xFFFF):
            words.append((hi16 << 16) | lo16)
    words.extend((0x32800000, 0x32800001, 0x3280FFFF, 0x54000010, 0x54000050, 0xFFFFFFFF))
    return words


def _generate_advsimd_vec_three_same_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.15/16/17 Advanced SIMD vector three-register same (+ FP16, FHM, RDMA, FCMA)."""
    words: List[int] = []
    rd = 1
    rn = 2
    rm = 3
    for q_bit in (0, 1):
        for u_bit in (0, 1):
            for size in range(4):
                for bit21 in (0, 1):
                    for opcode in range(32):
                        # Exclude AdvSIMD Copy (size=0, bit21=0, bit[15]=0 -> covered by advsimd_copy.tsv)
                        if size == 0 and bit21 == 0 and (opcode & 0b10000) == 0:
                            continue
                        # Exclude C4.1.95.17 dot-product / matrix slice (bit21=0, opcode in 18..23 -> advsimd_dot_product.tsv)
                        if bit21 == 0 and 18 <= opcode <= 23:
                            continue
                        word = (
                            (q_bit << 30)
                            | (u_bit << 29)
                            | (0b01110 << 24)
                            | (size << 22)
                            | (bit21 << 21)
                            | (rm << 16)
                            | (opcode << 11)
                            | (1 << 10)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)

    # Also enumerate Rm == Rn (Rd=1, Rn=2, Rm=2) across all 16 (Q, U, size) bitwise forms
    # (bit21=1, opcode=0b00011) to verify ORR -> MOV preferred alias and non-aliasing AND/BIC/ORN/EOR/BSL/BIT/BIF.
    for q_bit in (0, 1):
        for u_bit in (0, 1):
            for size in range(4):
                word = (
                    (q_bit << 30)
                    | (u_bit << 29)
                    | (0b01110 << 24)
                    | (size << 22)
                    | (1 << 21)
                    | (rn << 16)
                    | (0b00011 << 11)
                    | (1 << 10)
                    | (rn << 5)
                    | rd
                )
                words.append(word)
    return words


def _generate_advsimd_scalar_three_same_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.5/6/7 Advanced SIMD scalar three-register same (+ FP16 & RDMA)."""
    words: List[int] = []
    rd = 1
    rn = 2
    rm = 3
    for u_bit in (0, 1):
        for size in range(4):
            for bit21 in (0, 1):
                for opcode in range(32):
                    # Exclude AdvSIMD Scalar Copy (size=0, bit21=0, bit[15]=0 -> Group 15, Stage 11)
                    if size == 0 and bit21 == 0 and (opcode & 0b10000) == 0:
                        continue
                    word = (
                        (1 << 30)
                        | (u_bit << 29)
                        | (0b11110 << 24)
                        | (size << 22)
                        | (bit21 << 21)
                        | (rm << 16)
                        | (opcode << 11)
                        | (1 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_advsimd_dot_product_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.17 Advanced SIMD three-register extension (dot-product / matrix slice):
    0|Q|U|01110|size(2)|0|Rm(5)|opcode(5)|1|Rn(5)|Rd(5), with opcode in 18..23 (0b10010..0b10111).
    Enumerates all 2 x 2 x 4 x 6 = 96 combinations of Q=0..1, U=0..1, size=0..3, opcode=18..23
    with distinct vector registers Rd=1, Rn=2, Rm=3.
    On apple-m1, opcode=18 (0b10010) with size=0b10 decodes to SDOT (U=0) and UDOT (U=1);
    other sizes and opcode=19..23 (USDOT / BFDOT / SMMLA / UMMLA / USMMLA) are unallocated (.long).
    """
    words: List[int] = []
    rd = 1
    rn = 2
    rm = 3
    for q_bit in (0, 1):
        for u_bit in (0, 1):
            for size in range(4):
                for opcode in range(18, 24):
                    word = (
                        (q_bit << 30)
                        | (u_bit << 29)
                        | (0b01110 << 24)
                        | (size << 22)
                        | (rm << 16)
                        | (opcode << 11)
                        | (1 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


ENCODING_GROUPS: Dict[str, EncodingGroupSpec] = {
    "move_wide_imm": EncodingGroupSpec(
        name="move_wide_imm",
        title="Move wide (immediate) — MOVN / MOVZ / MOVK and MOV preferred aliases",
        header_notes=(
            "ARM DDI 0487 C4.1.92.5 Move wide (immediate): fixed bits[28:23] = 0b100101.",
            "Enumerates all 2 x 4 x 4 x 4 = 128 combinations of sf=0..1, opc=0..3 (MOVN/unallocated/MOVZ/MOVK),",
            "hw=0..3, and imm16 in {0x0000, 0x0001, 0x8000, 0xffff} with fixed register Rd=1.",
        ),
        generate_words=_generate_move_wide_imm_words,
    ),
    "logical_imm": EncodingGroupSpec(
        name="logical_imm",
        title="Logical (immediate) — AND / ORR / EOR / ANDS and MOV / TST preferred aliases",
        header_notes=(
            "ARM DDI 0487 C4.1.92.4 Logical (immediate): fixed bits[28:23] = 0b100100.",
            "Enumerates all 2 x 4 x 2 x 4 x 4 x 3 = 768 combinations of sf=0..1, opc=0..3, N=0..1,",
            "immr in {0, 1, 16, 63}, imms in {0, 1, 24, 63}, and distinct (Rd, Rn) in {(1,2), (1,31), (31,2)}",
            "(covering ORR Rn=ZR -> MOV alias + MoveWidePreferred counterexamples, ANDS Rd=ZR -> TST, and Rd=SP).",
        ),
        generate_words=_generate_logical_imm_words,
    ),
    "load_store_reg_offset": EncodingGroupSpec(
        name="load_store_reg_offset",
        title="Load/store register (register offset) — scalar/SIMD LDR/STR, PRFM, and RPRFM",
        header_notes=(
            "ARM DDI 0487 C4.1.94.10 Load/store register (register offset): (word & 0x3b200c00) == 0x38200800.",
            "Enumerates size=0..3, V=0..1, opc=0..3, option=0..7 (all 8 values), S=0..1 with fixed Rn=2, Rm=3:",
            "Rt=1 for load/store forms (31 x 8 x 2 = 496 rows), plus all prfop=0..31 for (size=3, V=0, opc=2)",
            "PRFM/RPRFM space (1 x 8 x 2 x 32 = 512 rows), totaling 1,008 rows.",
        ),
        generate_words=_generate_load_store_reg_offset_words,
    ),
    "cond_branch_imm": EncodingGroupSpec(
        name="cond_branch_imm",
        title="Conditional branch (immediate) — B.<cond> and unallocated o1/o0 (BC.<cond>) space",
        header_notes=(
            "ARM DDI 0487 C4.1.93.1 Conditional branch (immediate): (word & 0xfe000000) == 0x54000000.",
            "Enumerates all 2 x 4 x 2 x 16 = 256 combinations of o1=0..1, imm19 in {0x00000, 0x00001, 0x40000, 0x7ffff},",
            "o0=0..1 (B.<cond> vs FEAT_HBC BC.<cond>, unallocated on apple-m1), and cond=0..15.",
        ),
        generate_words=_generate_cond_branch_imm_words,
    ),
    "advsimd_copy": EncodingGroupSpec(
        name="advsimd_copy",
        title="Advanced SIMD copy — DUP, INS/MOV, UMOV/MOV, SMOV, and bit[15]=1 unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.8 Advanced SIMD copy: (word & 0x9fe00400) == 0x0e000400.",
            "Enumerates all 2 x 2 x 32 x 2 x 16 = 4,096 combinations of Q=0..1, op=0..1, imm5=0..31,",
            "bit[15]=0..1, and imm4=0..15 with fixed distinct registers Rn=2, Rd=1.",
        ),
        generate_words=_generate_advsimd_copy_words,
    ),
    "bitfield": EncodingGroupSpec(
        name="bitfield",
        title="Bitfield — SBFM / BFM / UBFM and ASR, LSL, LSR, SXT*, UXT*, SBFIZ, SBFX, BFI, BFC, BFXIL, UBFIZ, UBFX aliases",
        header_notes=(
            "ARM DDI 0487 C4.1.92.6 Bitfield: fixed bits[28:23] = 0b100110.",
            "Enumerates all 2 x 4 x 2 x 8 x 8 x 3 = 3,072 combinations of sf=0..1, opc=0..3, N=0..1,",
            "immr in {0, 1, 7, 15, 16, 31, 32, 63}, imms in {0, 1, 7, 15, 16, 31, 32, 63},",
            "and distinct (Rd, Rn) in {(1,2), (1,31), (31,2)} (covering BFM Rn=ZR -> BFC and BFXIL counterexamples).",
        ),
        generate_words=_generate_bitfield_words,
    ),
    "lse_atomic": EncodingGroupSpec(
        name="lse_atomic",
        title="LSE atomic memory operations — LD* / ST* preferred aliases, SWP*, and RCpc LDAPR* space",
        header_notes=(
            "ARM DDI 0487 C4.1.94.8 Atomic memory operations: (word & 0x3f200c00) == 0x38200000.",
            "Enumerates all 4 x 2 x 2 x 2 x 8 x 4 = 1,024 combinations of size=0..3, A=0..1, R=0..1,",
            "o3=0..1, opc=0..7, and (Rs, Rn, Rt) in {(3,2,1), (3,2,31), (31,2,1), (3,31,31)}",
            "(covering Rt=ZR acquire retention, A=0 ST* two-operand aliases, Rs=11111 LDAPR*, and Rn=SP).",
        ),
        generate_words=_generate_lse_atomic_words,
    ),
    "fp_imm": EncodingGroupSpec(
        name="fp_imm",
        title="Scalar floating-point immediate and zero compare — FMOV #imm8 and FCMP / FCMPE #0.0",
        header_notes=(
            "ARM DDI 0487 C4.1.95.24 Floating-point immediate & C4.1.95.22 Floating-point compare.",
            "Enumerates all 4 x 256 = 1,024 FMOV #imm8 combinations (ftype=0..3 covering S/D/unallocated/H x imm8=0..255, Rd=1)",
            "plus 2 x 2 x 4 x 4 x 2 = 128 FCMP/FCMPE combinations (sf=0..1, S=0..1, ftype=0..3, opc=0..3, Rm in {0,3}, Rn=2).",
        ),
        generate_words=_generate_fp_imm_words,
    ),
    "add_sub_ext_reg": EncodingGroupSpec(
        name="add_sub_ext_reg",
        title="Add/subtract (extended register) — ADD / ADDS / SUB / SUBS, CMN / CMP, and SP LSL preferred aliases",
        header_notes=(
            "ARM DDI 0487 C4.1.95.2 Add/subtract (extended register): (word & 0x1f200000) == 0x0b200000.",
            "Enumerates all 2 x 2 x 2 x 4 x 8 x 4 x 4 = 4,096 combinations of sf=0..1, op=0..1, S=0..1, opt=0..3,",
            "option=0..7, imm3 in {0, 1, 4, 7}, and (Rd, Rn) in {(1,2), (31,2), (1,31), (31,31)} with Rm=3.",
        ),
        generate_words=_generate_add_sub_ext_reg_words,
    ),
    "system_instr": EncodingGroupSpec(
        name="system_instr",
        title="System instructions — SYS (IC / DC / AT / TLBI / CFP / DVP / CPP / APAS aliases) and SYSL",
        header_notes=(
            "ARM DDI 0487 C4.1.93.6 System instructions (op0=01): (word & 0xffd80000) == 0xd5080000.",
            "Enumerates all 2 x 8 x 16 x 2 x 4 x 2 = 4,096 combinations of L=0..1 (SYS vs SYSL), op1=0..7,",
            "CRn=0..15, CRm in {1, 8}, op2 in {0, 1, 4, 7}, and Rt in {1, 31} (x1 vs xzr).",
        ),
        generate_words=_generate_system_instr_words,
    ),
    **{
        f"sysreg_mrs_op1_{op1}": EncodingGroupSpec(
            name=f"sysreg_mrs_op1_{op1}",
            title=f"System register move MRS (L=1) — slice op1={op1} (op0 in {{2,3}}, CRn=0..15, CRm=0..15, op2=0..7)",
            header_notes=(
                f"ARM DDI 0487 C4.1.93.7 MRS <Xt>, <systemreg>: slice {op1 + 1}/8 of all 32,768 MRS system-register encodings.",
                f"Range: L=1, op0 in {{2, 3}} (2), op1={op1} (1), CRn=0..15 (16), CRm=0..15 (16), op2=0..7 (8) with fixed Rt=1 (4,096 rows).",
                "Across sysreg_mrs_op1_0..sysreg_mrs_op1_7 (8 x 4,096 = 32,768 rows), every MRS encoding is covered.",
            ),
            generate_words=_make_sysreg_words_generator(is_read=True, op1_val=op1),
        )
        for op1 in range(8)
    },
    **{
        f"sysreg_msr_op1_{op1}": EncodingGroupSpec(
            name=f"sysreg_msr_op1_{op1}",
            title=f"System register move MSR (L=0) — slice op1={op1} (op0 in {{2,3}}, CRn=0..15, CRm=0..15, op2=0..7)",
            header_notes=(
                f"ARM DDI 0487 C4.1.93.7 MSR <systemreg>, <Xt>: MSR verification slice for op1={op1}.",
                f"Range: L=0, op0 in {{2, 3}} (2), op1={op1} (1), CRn=0..15 (16), CRm=0..15 (16), op2=0..7 (8) with fixed Rt=1 (4,096 rows).",
                "Verifies shared RW names, write-only names (e.g. OSLAR_EL1/TRCOSLAR/PMSWINC_EL0), RO generic fallbacks, and DBGDTRTX_EL0.",
            ),
            generate_words=_make_sysreg_words_generator(is_read=False, op1_val=op1),
        )
        for op1 in (0, 1, 3)
    },
    "udf": EncodingGroupSpec(
        name="udf",
        title="Reserved / permanently undefined — UDF #imm16 (0x0000xxxx) and non-zero high-16-bit counterexamples",
        header_notes=(
            "ARM DDI 0487 C4.1.91 Reserved & C6.2.439 UDF: (word & 0xffff0000) == 0x00000000.",
            "Enumerates 1,035 unique 0x0000xxxx encodings (all 0x0000..0x00ff, all 0xff00..0xffff, page bases/diagonals,",
            "single-bit set/clear, and signed/hex boundaries) plus 48 high-16-bit != 0 counterexamples (.long), totaling 1,083 rows.",
        ),
        generate_words=_generate_udf_words,
    ),
    "advsimd_vec_three_same": EncodingGroupSpec(
        name="advsimd_vec_three_same",
        title="Advanced SIMD vector three-register same — integer, bitwise (ORR/MOV), FP32/FP64, FP16, FHM, RDMA, and FCMA",
        header_notes=(
            "ARM DDI 0487 C4.1.95.15/16/17: (word & 0x9f000400) == 0x0e000400 excluding AdvSIMD Copy (advsimd_copy.tsv)",
            "and the C4.1.95.17 dot-product/matrix slice bit[21]=0, opcode=18..23 (advsimd_dot_product.tsv).",
            "Enumerates all 864 non-register combinations of Q=0..1, U=0..1, size=0..3, bit[21]=0..1, opcode=0..31",
            "with distinct Rd=1, Rn=2, Rm=3, plus 16 Rm==Rn (Rd=1, Rn=2, Rm=2) bitwise rows (bit[21]=1, opcode=0b00011),",
            "totaling 880 rows.",
        ),
        generate_words=_generate_advsimd_vec_three_same_words,
    ),
    "advsimd_scalar_three_same": EncodingGroupSpec(
        name="advsimd_scalar_three_same",
        title="Advanced SIMD scalar three-register same — integer, saturating/shift, FP32/FP64, FP16, and RDMA",
        header_notes=(
            "ARM DDI 0487 C4.1.95.5/6/7: (word & 0xdf000400) == 0x5e000400 excluding AdvSIMD Scalar Copy",
            "(size=0, bit[21]=0, bit[15]=0; Group 15).",
            "Enumerates all 480 non-register combinations of U=0..1, size=0..3, bit[21]=0..1, opcode=0..31",
            "with distinct scalar registers Rd=1, Rn=2, Rm=3.",
        ),
        generate_words=_generate_advsimd_scalar_three_same_words,
    ),
    "advsimd_dot_product": EncodingGroupSpec(
        name="advsimd_dot_product",
        title="Advanced SIMD dot product — SDOT / UDOT and unallocated USDOT / BFDOT / Int8-matrix sibling opcodes",
        header_notes=(
            "ARM DDI 0487 C4.1.95.17 Advanced SIMD three-register extension (dot-product / matrix slice):",
            "(word & 0x9f200400) == 0x0e000400 with opcode in 18..23 (0b10010..0b10111).",
            "Enumerates all 2 x 2 x 4 x 6 = 96 non-register combinations of Q=0..1, U=0..1, size=0..3,",
            "opcode=18..23 with distinct vector registers Rd=1, Rn=2, Rm=3.",
        ),
        generate_words=_generate_advsimd_dot_product_words,
    ),
}


def default_machgraph_bin() -> str:
    env_bin = os.environ.get("MACHGRAPH_BIN")
    if env_bin:
        return env_bin
    candidates = [
        os.path.join(REPO_ROOT, ".build", "release", "MachGraph"),
        os.path.join(REPO_ROOT, ".build", "debug", "MachGraph"),
    ]
    existing = [p for p in candidates if os.path.isfile(p) and os.access(p, os.X_OK)]
    if existing:
        existing.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return existing[0]
    return candidates[0]


def query_llvm_version() -> str:
    proc = subprocess.run(
        ["xcrun", "llvm-objdump", "--version"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=30.0,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"llvm-objdump --version exited {proc.returncode}")
    raw = proc.stdout.decode("utf-8", errors="replace")
    for line in raw.splitlines():
        stripped = line.strip()
        if "LLVM version" in stripped or "Apple LLVM" in stripped:
            return stripped
    first = raw.strip().splitlines()
    return first[0].strip() if first else "unknown"


def compile_inst_words_macho(words: Sequence[int], bin_path: str, arch: str = TARGET_ARCH) -> None:
    asm_path = bin_path + ".s"
    lines = [
        ".section __TEXT,__text,regular,pure_instructions\n",
        ".globl _main\n",
        ".p2align 2\n",
        "_main:\n",
    ]
    for w in words:
        if not (0 <= w <= 0xFFFFFFFF):
            raise ValueError(f"32-bit word out of range: {w:#x}")
        lines.append(f"\t.inst 0x{w:08x}\n")
    with open(asm_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    proc = subprocess.run(
        ["xcrun", "clang", "-arch", arch, asm_path, "-o", bin_path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120.0,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise RuntimeError(f"xcrun clang failed (exit {proc.returncode}): {err}")


@functools.lru_cache(maxsize=1)
def verify_clang_generic_neon_syntax() -> Optional[str]:
    """Self-contained check (without reading any system binary) that `-mllvm=-aarch64-neon-syntax=generic` works."""
    with tempfile.TemporaryDirectory(prefix="machgraph-neon-check-") as tmp:
        bin_path = os.path.join(tmp, "neon_probe.macho")
        try:
            # 0x6f00e400 = movi v0.2d, #0
            compile_inst_words_macho([0x6F00E400], bin_path, arch=TARGET_ARCH)
            proc = subprocess.run(
                build_reference_command(bin_path, TARGET_ARCH),
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30.0,
            )
        except Exception as exc:  # pragma: no cover - defensive
            return f"generic Neon syntax self-check failed: {exc}"

        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()[:240]
            return f"generic Neon syntax self-check failed: llvm-objdump exited {proc.returncode}: {err}"

        text = proc.stdout.decode("utf-8", errors="replace")
        saw_generic = False
        for line in text.splitlines():
            if line.strip() == "Contents of (__TEXT,__text) section":
                break
            m = _REF_INSN_RE.match(line)
            if not m:
                continue
            mnem = m.group(2).strip().lower()
            ops = (m.group(3) or "").split(";", 1)[0].strip().lower()
            if has_neon_arrangement_suffix(mnem):
                return f"generic Neon syntax self-check failed: reference printed Darwin suffix '{mnem}'"
            if _GENERIC_NEON_OPERAND_RE.search(ops):
                saw_generic = True
        if not saw_generic:
            return "generic Neon syntax self-check failed: expected generic operand 'v0.2d' on movi probe"
    return None


def disassemble_reference_macho(bin_path: str, expected_count: int, arch: str = TARGET_ARCH) -> List[Tuple[int, str, str]]:
    """Run `build_reference_command` on `bin_path` and return `[(addr, mnem, full_ops), ...]`."""
    proc = subprocess.run(
        build_reference_command(bin_path, arch),
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120.0,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:300]
        raise RuntimeError(f"llvm-objdump exited {proc.returncode}: {err}")

    text = proc.stdout.decode("utf-8", errors="replace")
    rows: List[Tuple[int, str, str]] = []
    for line in text.splitlines():
        if line.strip() == "Contents of (__TEXT,__text) section":
            break
        m = _REF_INSN_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw_mnem = m.group(2).strip().lower()
        raw_full_ops = (m.group(3) or "").strip()
        rows.append((addr, raw_mnem, raw_full_ops))

    bad_neon = find_non_generic_neon_mnemonic((addr, mnem) for addr, mnem, _ in rows)
    if bad_neon is not None:
        bad_addr, bad_mnem = bad_neon
        raise RuntimeError(
            f"non-generic Neon syntax in reference output: saw arrangement-suffixed mnemonic '{bad_mnem}' at 0x{bad_addr:x}"
        )

    if len(rows) != expected_count:
        raise RuntimeError(
            f"reference instruction count mismatch: expected {expected_count} rows, got {len(rows)}"
        )
    if rows:
        base = rows[0][0]
        for idx, (addr, _, _) in enumerate(rows):
            expected_addr = base + 4 * idx
            if addr != expected_addr:
                raise RuntimeError(
                    f"non-contiguous reference address at row {idx}: expected 0x{expected_addr:x}, got 0x{addr:x}"
                )
    return rows


def disassemble_machgraph_macho(
    bin_path: str,
    machgraph_bin: str,
    expected_words: Sequence[int],
    isolated_home: str,
) -> List[Tuple[int, int, str, str]]:
    """Run `machgraph disasm` on `bin_path` and return `[(addr, word, mnem, ops), ...]`."""
    env = dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )
    proc = subprocess.run(
        [machgraph_bin, "disasm", bin_path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120.0,
        env=env,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        first_err = err.splitlines()[0] if err else ""
        raise RuntimeError(f"machgraph disasm exited {proc.returncode}: {first_err[:240]}")

    stdout_txt = proc.stdout.decode("utf-8", errors="replace")
    rows: List[Tuple[int, int, str, str]] = []
    in_text_section = True
    saw_section_header = False
    for line in stdout_txt.splitlines():
        if not line:
            continue
        if line.startswith("; Section "):
            saw_section_header = True
            in_text_section = line.startswith("; Section __TEXT,__text ")
            continue
        if line.startswith(";"):
            continue
        if saw_section_header and not in_text_section:
            continue
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].startswith("0x"):
            addr = int(parts[0], 16)
            word_val = int(parts[1].strip(), 16)
            mnem = parts[2].strip().lower()
            ops = parts[3].strip() if len(parts) > 3 else ""
            rows.append((addr, word_val, mnem, ops))

    if len(rows) != len(expected_words):
        raise RuntimeError(
            f"machgraph instruction count mismatch: expected {len(expected_words)} rows, got {len(rows)}"
        )
    if rows:
        base = rows[0][0]
        for idx, ((addr, got_word, _, _), exp_word) in enumerate(zip(rows, expected_words)):
            expected_addr = base + 4 * idx
            if addr != expected_addr:
                raise RuntimeError(
                    f"non-contiguous machgraph address at row {idx}: expected 0x{expected_addr:x}, got 0x{addr:x}"
                )
            if got_word != exp_word:
                raise RuntimeError(
                    f"machine word mismatch at row {idx} (0x{addr:x}): expected 0x{exp_word:08x}, got 0x{got_word:08x}"
                )
    return rows


def write_reference_table(
    words: Sequence[int],
    output_path: str,
    group_name: str,
    header_notes: Sequence[str] = (),
) -> int:
    if len(words) == 0:
        raise ValueError(f"group '{group_name}' produced 0 words")
    if len(words) > MAX_TABLE_ROWS:
        raise ValueError(
            f"group '{group_name}' produced {len(words)} rows, exceeding MAX_TABLE_ROWS={MAX_TABLE_ROWS}"
        )

    neon_err = verify_clang_generic_neon_syntax()
    if neon_err is not None:
        raise RuntimeError(neon_err)

    llvm_ver = query_llvm_version()
    with tempfile.TemporaryDirectory(prefix=f"machgraph-table-{group_name}-") as tmp:
        bin_path = os.path.join(tmp, f"{group_name}.macho")
        compile_inst_words_macho(words, bin_path, arch=TARGET_ARCH)
        ref_rows = disassemble_reference_macho(bin_path, expected_count=len(words), arch=TARGET_ARCH)

    ref_cmd_display = " ".join(build_reference_command(f"{group_name}.macho", TARGET_ARCH))
    out_lines: List[str] = [
        f"# A64 encoding reference table: {group_name}\n",
    ]
    for note in header_notes:
        out_lines.append(f"# {note}\n")
    out_lines.extend(
        [
            f"# Rows: {len(words)} (max allowed: {MAX_TABLE_ROWS})\n",
            f"# Reference tool version: {llvm_ver}\n",
            f"# Assembly command: xcrun clang -arch {TARGET_ARCH} {group_name}.s -o {group_name}.macho\n",
            f"# Reference command: {ref_cmd_display}\n",
            f"# Generation command: python3 -I Scripts/acceptance/encoding-table.py generate {group_name}\n",
            "# Format: <machine_word_hex>\\t<llvm_objdump_mnemonic>[\\t<llvm_objdump_operands>]\n",
        ]
    )
    for w, (_, mnem, full_ops) in zip(words, ref_rows):
        if full_ops:
            out_lines.append(f"0x{w:08x}\t{mnem}\t{full_ops}\n")
        else:
            out_lines.append(f"0x{w:08x}\t{mnem}\n")

    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.writelines(out_lines)
    return len(words)


def load_reference_table(tsv_path: str) -> Tuple[List[str], List[Tuple[int, str, str]]]:
    if not os.path.isfile(tsv_path):
        raise FileNotFoundError(f"table file not found: {tsv_path}")

    with open(tsv_path, "r", encoding="utf-8") as fh:
        raw_lines = fh.read().splitlines()

    comments: List[str] = []
    rows: List[Tuple[int, str, str]] = []
    for line_no, raw in enumerate(raw_lines, start=1):
        if not raw.strip():
            continue
        if raw.startswith("#"):
            comments.append(raw)
            continue
        parts = raw.split("\t", 2)
        if len(parts) < 2:
            raise ValueError(f"{tsv_path}:{line_no}: expected at least 2 tab-separated fields, got {raw!r}")
        word_str = parts[0].strip()
        if not _WORD_HEX_RE.match(word_str):
            raise ValueError(f"{tsv_path}:{line_no}: invalid 32-bit hex word {word_str!r}")
        mnem = parts[1].strip().lower()
        if not mnem:
            raise ValueError(f"{tsv_path}:{line_no}: empty reference mnemonic")
        if has_neon_arrangement_suffix(mnem):
            raise ValueError(
                f"{tsv_path}:{line_no}: non-generic Darwin Neon arrangement suffix in reference mnemonic {mnem!r}"
            )
        full_ops = parts[2].strip() if len(parts) == 3 else ""
        rows.append((int(word_str, 16), mnem, full_ops))

    joined_comments = "\n".join(comments)
    if "LLVM version" not in joined_comments and "Apple LLVM" not in joined_comments:
        raise ValueError(f"{tsv_path}: header comments must record LLVM version")
    if "xcrun clang" not in joined_comments or "llvm-objdump" not in joined_comments:
        raise ValueError(f"{tsv_path}: header comments must record clang and llvm-objdump generation commands")
    if len(rows) == 0:
        raise ValueError(f"{tsv_path}: table contains 0 data rows")
    if len(rows) > MAX_TABLE_ROWS:
        raise ValueError(f"{tsv_path}: table has {len(rows)} rows, exceeding MAX_TABLE_ROWS={MAX_TABLE_ROWS}")
    return comments, rows


def sanitize_label(path: str) -> str:
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, REPO_ROOT)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return os.path.basename(abs_path)


def check_one_table(tsv_path: str, machgraph_bin: str) -> Dict[str, Any]:
    _, table_rows = load_reference_table(tsv_path)
    words = [w for w, _, _ in table_rows]

    with tempfile.TemporaryDirectory(prefix="machgraph-table-check-") as tmp:
        bin_path = os.path.join(tmp, "table_check.macho")
        home_dir = os.path.join(tmp, "home")
        os.makedirs(home_dir, exist_ok=True)
        compile_inst_words_macho(words, bin_path, arch=TARGET_ARCH)
        mg_rows = disassemble_machgraph_macho(bin_path, machgraph_bin, words, home_dir)

    matched = 0
    ref_long_matched = 0
    mismatches: List[Dict[str, str]] = []
    category_counts: collections.Counter = collections.Counter()

    for (word, ref_mnem, ref_full_ops), (addr, _, mg_mnem, mg_ops) in zip(table_rows, mg_rows):
        ref_disp_ops = (
            ref_full_ops
            if (ref_mnem == "adrp" and ";" in ref_full_ops)
            else ref_full_ops.split(";", 1)[0].strip()
        )
        ref_core_ops = ref_full_ops.split(";", 1)[0].strip()
        ref_text = f"{ref_mnem} {ref_disp_ops}".strip()
        mg_text = f"{mg_mnem} {mg_ops}".strip()

        kind, norm_ref, norm_mg = classify_mnemonic_pair(ref_mnem, mg_mnem)
        if kind == "reference_long_machgraph_inst":
            matched += 1
            ref_long_matched += 1
            continue
        if kind == "agree":
            if operands_equal(norm_ref, ref_full_ops, mg_ops, address=addr):
                matched += 1
                continue
            ref_sh = operand_shape_for_category(ref_core_ops)
            mg_sh = operand_shape_for_category(mg_ops)
            cat = f"operand_mismatch: {norm_ref}|{norm_mg}: {ref_sh} != {mg_sh}"
        elif kind == "unknown":
            cat = f"unknown: {norm_ref}|.inst"
        else:
            cat = f"wrong_mnemonic: {norm_ref}|{norm_mg}"

        category_counts[cat] += 1
        mismatches.append(
            {
                "word": f"0x{word:08x}",
                "address": f"0x{addr:x}",
                "llvm": ref_text,
                "machgraph": mg_text,
                "category": cat,
            }
        )

    return {
        "label": sanitize_label(tsv_path),
        "total": len(table_rows),
        "matched": matched,
        "ref_long_matched": ref_long_matched,
        "mismatch_count": len(mismatches),
        "categories": dict(category_counts),
        "mismatches": mismatches,
    }


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="encoding-table.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand")

    gen = sub.add_parser("generate", help="generate reference TSV table(s) using clang and llvm-objdump")
    gen.add_argument("groups", nargs="*", help="encoding group name(s)")
    gen.add_argument("--all", action="store_true", dest="all_groups", help="generate all registered groups")
    gen.add_argument("--out-dir", default=DEFAULT_TABLE_DIR, help="output directory (default: Fixtures/a64)")

    chk = sub.add_parser("check", help="check MachGraph disassembly against reference TSV table(s)")
    chk.add_argument("groups", nargs="*", help="encoding group name(s)")
    chk.add_argument("--all", action="store_true", dest="all_groups", help="check all registered groups")
    chk.add_argument("--table-dir", default=DEFAULT_TABLE_DIR, help="table directory (default: Fixtures/a64)")
    chk.add_argument("--table", default=None, help="explicit path to a single TSV table file")
    chk.add_argument("--machgraph", default=default_machgraph_bin(), help="path to MachGraph CLI executable")

    return parser


def _validate_group_names(names: Sequence[str]) -> List[str]:
    unknown = [g for g in names if g not in ENCODING_GROUPS]
    if unknown:
        known_str = ", ".join(sorted(ENCODING_GROUPS.keys()))
        raise _UsageError(
            f"unknown encoding group(s): {', '.join(unknown)} (known groups: {known_str})"
        )
    return list(names)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.subcommand not in ("generate", "check"):
            raise _UsageError("must specify subcommand 'generate' or 'check'")

        if args.subcommand == "generate":
            if args.all_groups and args.groups:
                raise _UsageError("cannot combine --all with explicit <group> arguments")
            if not args.all_groups and not args.groups:
                raise _UsageError("generate requires <group...> or --all")
            target_groups = list(ENCODING_GROUPS.keys()) if args.all_groups else _validate_group_names(args.groups)

            for grp_name in target_groups:
                spec = ENCODING_GROUPS[grp_name]
                words = spec.generate_words()
                out_path = os.path.join(args.out_dir, f"{grp_name}.tsv")
                try:
                    row_count = write_reference_table(
                        words=words,
                        output_path=out_path,
                        group_name=grp_name,
                        header_notes=spec.header_notes,
                    )
                except Exception as exc:
                    print(f"[FAIL] generate {grp_name}: {exc}", file=sys.stderr)
                    return 1
                print(f"[GENERATED] {sanitize_label(out_path)}: {row_count} rows ({spec.title})")
            return 0

        # subcommand == "check"
        mode_count = int(bool(args.all_groups)) + int(bool(args.groups)) + int(args.table is not None)
        if mode_count != 1:
            raise _UsageError("check requires exactly one of <group...>, --all, or --table <path>")

        if args.table is not None:
            tsv_paths = [args.table]
        elif args.all_groups:
            seen_paths = []
            for grp_name in ENCODING_GROUPS:
                seen_paths.append(os.path.join(args.table_dir, f"{grp_name}.tsv"))
            if os.path.isdir(args.table_dir):
                for fname in sorted(os.listdir(args.table_dir)):
                    if fname.endswith(".tsv"):
                        full = os.path.join(args.table_dir, fname)
                        if full not in seen_paths:
                            seen_paths.append(full)
            tsv_paths = seen_paths
        else:
            valid_groups = _validate_group_names(args.groups)
            tsv_paths = [os.path.join(args.table_dir, f"{g}.tsv") for g in valid_groups]

    except _UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(f"[FAIL] MachGraph executable not found or not executable: {args.machgraph}", file=sys.stderr)
        return 1

    print(f"=== MachGraph Encoding Table Check (tables={len(tsv_paths)}) ===")
    print(f"Mnemonic rules ({len(NORMALIZATION_RULES)}): {NORMALIZATION_SUMMARY}")
    print(f"Operand rules ({len(OPERAND_NORMALIZATION_RULES)}):  {OPERAND_NORMALIZATION_SUMMARY}")

    overall_ok = True
    for tsv_path in tsv_paths:
        try:
            res = check_one_table(tsv_path, args.machgraph)
        except Exception as exc:
            print(f"[FAIL] {sanitize_label(tsv_path)}: {exc}", file=sys.stderr)
            overall_ok = False
            continue

        tag = "PASS" if res["mismatch_count"] == 0 else "FAIL"
        print(
            f"[{tag}] {res['label']}: total={res['total']} matched={res['matched']} "
            f"(ref_long_mg_inst={res['ref_long_matched']}) mismatch={res['mismatch_count']}"
        )
        if res["mismatch_count"] > 0:
            overall_ok = False
            cat_items = sorted(res["categories"].items(), key=lambda kv: (-kv[1], kv[0]))
            print(f"  mismatch categories ({len(cat_items)}):")
            for cat, cnt in cat_items:
                print(f"    - {cat}: count={cnt}")
            print(f"  mismatched rows ({res['mismatch_count']}):")
            for item in res["mismatches"]:
                print(
                    f"    {item['word']}\tllvm='{item['llvm']}'\tmachgraph='{item['machgraph']}'\t[{item['category']}]"
                )

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
