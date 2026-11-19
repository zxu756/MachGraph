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


def _generate_advsimd_scalar_two_reg_misc_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.10 Advanced SIMD scalar two-register miscellaneous &
    C4.1.95.11 Advanced SIMD scalar two-register miscellaneous FP16:
    0|1|U|11110|size(2)|b21_17(5)|opcode(5)|10|Rn(5)|Rd(5), with b21_17 in {0b10000, 0b11100}.
    Enumerates all 2 x 2 x 4 x 32 = 512 non-register combinations of subtable (0b10000 vs 0b11100),
    U=0..1, size=0..3 (including bit[22]=0 unallocated counterexamples in the FP16 subtable),
    and opcode=0..31 with distinct scalar registers Rd=1, Rn=2.
    """
    words: List[int] = []
    rd = 1
    rn = 2
    for b21_17 in (0b10000, 0b11100):
        for u_bit in (0, 1):
            for size in range(4):
                for opcode in range(32):
                    word = (
                        (1 << 30)
                        | (u_bit << 29)
                        | (0b11110 << 24)
                        | (size << 22)
                        | (b21_17 << 17)
                        | (opcode << 12)
                        | (0b10 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_advsimd_vec_two_reg_misc_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.20 Advanced SIMD two-register miscellaneous &
    C4.1.95.21 Advanced SIMD two-register miscellaneous FP16:
    0|Q|U|01110|size(2)|b21_17(5)|opcode(5)|10|Rn(5)|Rd(5), with b21_17 in {0b10000, 0b11100}.
    Enumerates all 2 x 2 x 2 x 4 x 32 = 1,024 non-register combinations of subtable (0b10000 vs 0b11100),
    Q=0..1, U=0..1, size=0..3 (including bit[22]=0 unallocated counterexamples in the FP16 subtable),
    and opcode=0..31 with distinct vector registers Rd=1, Rn=2.
    """
    words: List[int] = []
    rd = 1
    rn = 2
    for b21_17 in (0b10000, 0b11100):
        for q_bit in (0, 1):
            for u_bit in (0, 1):
                for size in range(4):
                    for opcode in range(32):
                        word = (
                            (q_bit << 30)
                            | (u_bit << 29)
                            | (0b01110 << 24)
                            | (size << 22)
                            | (b21_17 << 17)
                            | (opcode << 12)
                            | (0b10 << 10)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)
    return words


def _make_advsimd_vec_shift_imm_words_generator(q_bit: int, u_bit: int) -> Callable[[], List[int]]:
    """ARM DDI 0487 C4.1.95.19 Advanced SIMD vector shift by immediate slice for fixed (Q, U):
    0|Q|U|01111|0|immh(4)|immb(3)|opcode(5)|1|Rn(5)|Rd(5), with immh in 1..15.
    (immh == 0 is Group 11 AdvSIMD modified immediate; bit[10] == 0 is Group 13 AdvSIMD vector indexed element.)
    Enumerates all 15 x 8 x 32 = 3,840 non-register combinations of immh=1..15, immb=0..7, opcode=0..31
    with distinct vector registers Rd=1, Rn=2.
    """

    def _gen() -> List[int]:
        words: List[int] = []
        rd = 1
        rn = 2
        for immh in range(1, 16):
            for immb in range(8):
                for opcode in range(32):
                    word = (
                        (q_bit << 30)
                        | (u_bit << 29)
                        | (0b011110 << 23)
                        | (immh << 19)
                        | (immb << 16)
                        | (opcode << 11)
                        | (1 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
        return words

    return _gen


def _make_advsimd_scalar_shift_imm_words_generator(u_bit: int) -> Callable[[], List[int]]:
    """ARM DDI 0487 C4.1.95.8 / C4.1.95.9 Advanced SIMD scalar shift by immediate slice for fixed U:
    0|1|U|11111|0|immh(4)|immb(3)|opcode(5)|1|Rn(5)|Rd(5), with immh in 0..15.
    (Includes immh == 0 unallocated counterexamples; bit[10] == 0 is Group 26 AdvSIMD scalar indexed element.)
    Enumerates all 16 x 8 x 32 = 4,096 non-register combinations of immh=0..15, immb=0..7, opcode=0..31
    with distinct scalar registers Rd=1, Rn=2.
    """

    def _gen() -> List[int]:
        words: List[int] = []
        rd = 1
        rn = 2
        for immh in range(16):
            for immb in range(8):
                for opcode in range(32):
                    word = (
                        (1 << 30)
                        | (u_bit << 29)
                        | (0b111110 << 23)
                        | (immh << 19)
                        | (immb << 16)
                        | (opcode << 11)
                        | (1 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
        return words

    return _gen


def _generate_scalar_fp_fixed_point_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.25 Floating-point<->fixed-point conversions: (word & 0x5f200000) == 0x1e000000.
    1) Enumerates all 2 x 2 x 4 x 4 x 8 = 512 combinations of sf=0..1, S=0..1 (including S=1 unallocated),
       ftype=0..3 (S, D, unallocated 10, H), rmode=0..3, opcode=0..7 across 7 scale samples
       {0, 1, 16, 31, 32, 48, 63} (covering 0, 1, midpoints 16 & 48, exact sf=0 boundary 31 vs 32, and max 63)
       with distinct (Rd, Rn) = (1, 2): 512 x 7 = 3,584 rows.
    2) Plus zero-register boundary rows (Rd, Rn) in {(1, 31), (31, 2)} across sf=0..1, S=0,
       ftype in {0, 1, 3}, rmode in {0, 3}, opcode in {0, 1, 2, 3}, scale in {32, 63}: 192 rows.
    Total = 3,776 rows (<= 4,096).
    """
    words: List[int] = []
    scale_samples = (0, 1, 16, 31, 32, 48, 63)
    for sf in (0, 1):
        for s_bit in (0, 1):
            for ftype in range(4):
                for rmode in range(4):
                    for opcode in range(8):
                        for scale in scale_samples:
                            word = (
                                (sf << 31)
                                | (s_bit << 29)
                                | (0b11110 << 24)
                                | (ftype << 22)
                                | (rmode << 19)
                                | (opcode << 16)
                                | (scale << 10)
                                | (2 << 5)
                                | 1
                            )
                            words.append(word)

    for sf in (0, 1):
        for ftype in (0, 1, 3):
            for rmode in (0, 3):
                for opcode in (0, 1, 2, 3):
                    for scale in (32, 63):
                        for rd, rn in ((1, 31), (31, 2)):
                            word = (
                                (sf << 31)
                                | (0b11110 << 24)
                                | (ftype << 22)
                                | (rmode << 19)
                                | (opcode << 16)
                                | (scale << 10)
                                | (rn << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_pac_data_ptr_words() -> List[int]:
    """ARM DDI 0487 C4.1.94.2 Data-processing (1 source) & Pointer Authentication 1-source:
    sf(1)|1|S(1)|11010110|opcode2(5)|opcode(6)|Rn(5)|Rd(5), i.e. (word & 0x5fe00000) == 0x5ac00000.
    1) Enumerates all sf=0..1, S=0..1, opcode2 in {0b00000, 0b00001, 0b00010, 0b11111}, opcode=0..63
       across (Rd, Rn) in {(1, 2), (1, 31), (31, 31)} (covering standard 1-source RBIT/REV/CLZ/CLS,
       all 8 two-operand PAC/AUT <Xd>, <Xn|SP>, all 10 one-operand PACI*/PACD*/AUTI*/AUTD*/XPAC* <Xd>
       requiring Rn==31 + Rn!=31 unallocated counterexamples, and Rd=xzr): 2 x 2 x 4 x 64 x 3 = 3,072 rows.
    2) Plus (Rd, Rn) = (31, 2) across sf=1, S=0, opcode2 in {0b00000, 0b00001}, opcode=0..63: 128 rows.
    Total = 3,200 rows (<= 4,096).
    """
    words: List[int] = []
    for sf in (0, 1):
        for s_bit in (0, 1):
            for opcode2 in (0b00000, 0b00001, 0b00010, 0b11111):
                for opcode in range(64):
                    for rd, rn in ((1, 2), (1, 31), (31, 31)):
                        word = (
                            (sf << 31)
                            | (s_bit << 29)
                            | 0x5AC00000
                            | (opcode2 << 16)
                            | (opcode << 10)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)

    for opcode2 in (0b00000, 0b00001):
        for opcode in range(64):
            word = (
                (1 << 31)
                | 0x5AC00000
                | (opcode2 << 16)
                | (opcode << 10)
                | (2 << 5)
                | 31
            )
            words.append(word)
    return words


def _generate_rcpc_ldapr_words() -> List[int]:
    """ARM DDI 0487 C4.1.94.8 Atomic memory operations o3=1 subtable (SWP* & FEAT_LRCPC LDAPR*):
    size(2)|111000|A(1)|R(1)|1|Rs(5)|1|opc(3)|00|Rn(5)|Rt(5), i.e. (word & 0x3f208c00) == 0x38208000.
    Enumerates all 4 x 2 x 2 x 8 x 4 = 512 combinations of size=0..3, A=0..1, R=0..1, opc=0..7,
    and (Rs, Rn, Rt) in {(31,2,1), (31,31,1), (31,2,31), (30,2,1)} (covering LDAPRB/LDAPRH/LDAPR W/X,
    Rn=SP, Rt=WZR/XZR, and Rs=30 != 31 unallocated counterexamples alongside lse_atomic.tsv).
    """
    words: List[int] = []
    reg_tuples = ((31, 2, 1), (31, 31, 1), (31, 2, 31), (30, 2, 1))
    for size in range(4):
        for a_bit in (0, 1):
            for r_bit in (0, 1):
                for opc in range(8):
                    for rs, rn, rt in reg_tuples:
                        word = (
                            (size << 30)
                            | (0b111000 << 24)
                            | (a_bit << 23)
                            | (r_bit << 22)
                            | (1 << 21)
                            | (rs << 16)
                            | (1 << 15)
                            | (opc << 12)
                            | (rn << 5)
                            | rt
                        )
                        words.append(word)
    return words


def _generate_scalar_fp_int_conv_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.26 Floating-point<->integer conversions:
    sf(1)|0|S(1)|11110|ftype(2)|1|rmode(2)|opcode(3)|000000|Rn(5)|Rd(5), i.e. (word & 0x5f20fc00) == 0x1e200000.
    Enumerates all 2 x 2 x 4 x 4 x 8 x 3 = 1,536 combinations of sf=0..1, S=0..1 (including S=1 unallocated),
    ftype=0..3 (S, D, Q/lane-1, H), rmode=0..3, opcode=0..7 across (Rd, Rn) in {(1, 2), (1, 31), (31, 2)}
    (covering FCVTNS/U, SCVTF/UCVTF, FCVTAS/U, FCVTPS/U, FCVTMS/U, FCVTZS/U, FJCVTZS, FMOV GP<->FP,
    FMOV X<->V.D[1], wzr/xzr vs s31/d31/h31/v31, and mismatched-width FMOV unallocated counterexamples).
    """
    words: List[int] = []
    for sf in (0, 1):
        for s_bit in (0, 1):
            for ftype in range(4):
                for rmode in range(4):
                    for opcode in range(8):
                        for rd, rn in ((1, 2), (1, 31), (31, 2)):
                            word = (
                                (sf << 31)
                                | (s_bit << 29)
                                | (0b11110 << 24)
                                | (ftype << 22)
                                | (1 << 21)
                                | (rmode << 19)
                                | (opcode << 16)
                                | (rn << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_scalar_fp_one_source_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.21 Floating-point data-processing (1 source):
    M(1)|0|S(1)|11110|ftype(2)|1|opcode(6)|10000|Rn(5)|Rd(5), i.e. (word & 0x5f207c00) == 0x1e204000.
    1) Enumerates all 2 x 2 x 4 x 64 = 1,024 non-register combinations of M=0..1, S=0..1,
       ftype=0..3 (S, D, unallocated 10, H), opcode=0..63 with distinct (Rd, Rn) = (1, 2)
       (covering FMOV, FABS, FNEG, FSQRT, cross-width FCVT + same-width unallocated FCVT counterexamples,
       FRINTN/P/M/Z/A/X/I, and FRINT32Z/X / FRINT64Z/X on S/D + H unallocated counterexamples).
    2) Plus 3 x 32 = 96 high-register rows M=0, S=0, ftype in {0, 1, 3}, opcode=0..31 with (Rd, Rn) = (31, 31).
    Total = 1,120 rows (<= 4,096).
    """
    words: List[int] = []
    for m_bit in (0, 1):
        for s_bit in (0, 1):
            for ftype in range(4):
                for opcode in range(64):
                    word = (
                        (m_bit << 31)
                        | (s_bit << 29)
                        | (0b11110 << 24)
                        | (ftype << 22)
                        | (1 << 21)
                        | (opcode << 15)
                        | (0b10000 << 10)
                        | (2 << 5)
                        | 1
                    )
                    words.append(word)

    for ftype in (0, 1, 3):
        for opcode in range(32):
            word = (
                (0b11110 << 24)
                | (ftype << 22)
                | (1 << 21)
                | (opcode << 15)
                | (0b10000 << 10)
                | (31 << 5)
                | 31
            )
            words.append(word)
    return words


def _generate_scalar_fp_three_source_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.20 Floating-point data-processing (3 source):
    M(1)|0|S(1)|11111|ftype(2)|o1(1)|Rm(5)|o0(1)|Ra(5)|Rn(5)|Rd(5), i.e. (word & 0x5f000000) == 0x1f000000.
    Enumerates all 2 x 2 x 4 x 2 x 2 x 2 = 128 combinations of M=0..1, S=0..1, ftype=0..3 (S/D/unallocated/H),
    o1=0..1, o0=0..1 across (Rd, Rn, Rm, Ra) in {(1, 2, 3, 4), (31, 31, 31, 31)}
    (verifying Rd, Rn, Rm, Ra operand order and M/S/ftype=10 unallocated counterexamples).
    """
    words: List[int] = []
    for m_bit in (0, 1):
        for s_bit in (0, 1):
            for ftype in range(4):
                for o1 in (0, 1):
                    for o0 in (0, 1):
                        for rd, rn, rm, ra in ((1, 2, 3, 4), (31, 31, 31, 31)):
                            word = (
                                (m_bit << 31)
                                | (s_bit << 29)
                                | (0b11111 << 24)
                                | (ftype << 22)
                                | (o1 << 21)
                                | (rm << 16)
                                | (o0 << 15)
                                | (ra << 10)
                                | (rn << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_load_store_exclusive_casp_words() -> List[int]:
    """ARM DDI 0487 C4.1.94.1..4 Load/store exclusive, Load-acquire/store-release, LORegion, CAS, and CASP:
    size(2)|001000|o2(1)|L(1)|o1(1)|Rs(5)|o0(1)|Rt2(5)|Rn(5)|Rt(5), i.e. (word & 0x3f000000) == 0x08000000.
    Enumerates all 4 x 2 x 2 x 2 x 2 = 64 combinations of size=0..3, o2=0..1, L=0..1, o1=0..1, o0=0..1 across
    8 register tuples (Rs, Rt2, Rn, Rt) = 512 unique words:
      - (4, 31, 6, 2): canonical Rt2=31 with distinct even Rs=4, Rn=6, Rt=2 (CASP, CAS, STXR/STXP, G62 Rs!=31);
      - (31, 31, 6, 2): canonical Rs=31, Rt2=31 (LDXR/LDAR/LDLAR, CAS wzr, CASP odd-Rs counterexample);
      - (4, 8, 6, 2): four distinct non-31 registers (STXP/LDXP operand order, G62 Rt2!=31, CAS/CASP .long);
      - (5, 31, 6, 2): odd Rs=5 with even Rt=2, Rt2=31 (CASP odd-Rs .long vs valid CAS/STXR);
      - (4, 31, 6, 3): even Rs=4 with odd Rt=3, Rt2=31 (CASP odd-Rt .long vs valid CAS/STXR);
      - (30, 31, 31, 30): Rs=30, Rt2=31, Rn=SP, Rt=30 (CASP w30, wzr / x30, xzr and [sp] base);
      - (31, 31, 31, 31): all 31 (ZR operands with [sp]);
      - (31, 8, 6, 2): Rs=31, Rt2=8 != 31 (G62 Rt2!=31 with Rs=31 vs CAS .long).
    """
    reg_tuples = (
        (4, 31, 6, 2),
        (31, 31, 6, 2),
        (4, 8, 6, 2),
        (5, 31, 6, 2),
        (4, 31, 6, 3),
        (30, 31, 31, 30),
        (31, 31, 31, 31),
        (31, 8, 6, 2),
    )
    words: List[int] = []
    for size in range(4):
        for o2 in (0, 1):
            for l_bit in (0, 1):
                for o1 in (0, 1):
                    for o0 in (0, 1):
                        for rs, rt2, rn, rt in reg_tuples:
                            word = (
                                (size << 30)
                                | (0b001000 << 24)
                                | (o2 << 23)
                                | (l_bit << 22)
                                | (o1 << 21)
                                | (rs << 16)
                                | (o0 << 15)
                                | (rt2 << 10)
                                | (rn << 5)
                                | rt
                            )
                            words.append(word)
    return words


def _generate_barriers_words() -> List[int]:
    """ARM DDI 0487 C4.1.93.5 Barriers:
    11010101000|0|00|011|0011|CRm(4)|op2(3)|Rt(5), i.e. (word & 0xfffff000) == 0xd5033000.
    Enumerates all 16 x 8 x 2 = 256 combinations of CRm=0..15, op2=0..7 across Rt in {31, 1}
    (covering Rt=31 CLREX, DSB, SSBB/PSSBB, DMB, ISB, SB, and op2 in {0,1,3} / Rt!=31 MSR S0_3_C3_* fallbacks).
    """
    words: List[int] = []
    for crm in range(16):
        for op2 in range(8):
            for rt in (31, 1):
                word = 0xD5033000 | (crm << 8) | (op2 << 5) | rt
                words.append(word)
    return words


def _generate_advsimd_scalar_copy_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.4 Advanced SIMD scalar copy:
    0|1|op(1)|11110000|imm5(5)|0|imm4(4)|1|Rn(5)|Rd(5), i.e. (word & 0xdfe08400) == 0x5e000400.
    Enumerates all 2 x 32 x 16 x 2 = 2,048 combinations of op=0..1, imm5=0..31, imm4=0..15
    across (Rd, Rn) in {(1, 2), (31, 31)} (covering DUP <V><d>, <Vn>.<Ts>[index] preferred alias
    MOV across B/H/S/D, b31/h31/s31/d31/v31 registers, and op=1 / imm4!=0 / imm5 in {0,16} unallocated .long).
    """
    words: List[int] = []
    for op_bit in (0, 1):
        for imm5 in range(32):
            for imm4 in range(16):
                for rd, rn in ((1, 2), (31, 31)):
                    word = (
                        (1 << 30)
                        | (op_bit << 29)
                        | (0b11110000 << 21)
                        | (imm5 << 16)
                        | (imm4 << 11)
                        | (1 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_advsimd_modified_imm_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.14 Advanced SIMD modified immediate:
    0|Q(1)|op(1)|0111100000|a|b|c|cmode(4)|o2(1)|1|d|e|f|g|h|Rd(5), i.e. (word & 0x9ff80400) == 0x0f000400.
    Enumerates all 2 x 2 x 16 x 2 = 128 combinations of Q=0..1, op=0..1, cmode=0..15, o2=0..1:
      - With Rd=1: imm8 in {0x00, 0x01, 0x80, 0xff} for cmode=0..14 (480 rows), and all 256 values
        imm8=0..255 for cmode=0b1111 (FMOV vector forms 2s/4s/2d/4h/8h plus unallocated Q=0,op=1,o2=0
        and op=1,o2=1 counterexamples; 2,048 rows);
      - With Rd=31: imm8 in {0x00, 0x01, 0x80, 0xff} across all cmode=0..15 (512 rows, covering d31/v31),
    totaling 3,040 unique rows (<= 4,096).
    """
    sampled_imm8 = (0x00, 0x01, 0x80, 0xFF)
    words: List[int] = []
    for rd in (1, 31):
        for q_bit in (0, 1):
            for op_bit in (0, 1):
                for cmode in range(16):
                    for o2 in (0, 1):
                        imm8_values = range(256) if (rd == 1 and cmode == 0b1111) else sampled_imm8
                        for imm8 in imm8_values:
                            abc = (imm8 >> 5) & 0x7
                            defgh = imm8 & 0x1F
                            word = (
                                (q_bit << 30)
                                | (op_bit << 29)
                                | (0b0111100000 << 19)
                                | (abc << 16)
                                | (cmode << 12)
                                | (o2 << 11)
                                | (1 << 10)
                                | (defgh << 5)
                                | rd
                            )
                            words.append(word)
    return words


def _generate_advsimd_ext_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.12 Advanced SIMD extract (EXT):
    0|Q(1)|101110|op2(2)|0|Rm(5)|0|imm4(4)|0|Rn(5)|Rd(5), i.e. (word & 0xbf208400) == 0x2e000000.
    Enumerates all 2 x 4 x 16 x 2 = 256 combinations of Q=0..1, op2=0..3, imm4=0..15
    across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering EXT v<d>.<8b|16b>, v<n>.<8b|16b>,
    v<m>.<8b|16b>, #<imm4>, v31 registers, op2!=0 unallocated space, and Q=0 with imm4<3>==1 .long).
    """
    words: List[int] = []
    for rd, rn, rm in ((1, 2, 3), (31, 31, 31)):
        for q_bit in (0, 1):
            for op2 in range(4):
                for imm4 in range(16):
                    word = (
                        (q_bit << 30)
                        | (0b101110 << 24)
                        | (op2 << 22)
                        | (rm << 16)
                        | (imm4 << 11)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_advsimd_permute_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.11 Advanced SIMD permute (UZP1 / TRN1 / ZIP1 / UZP2 / TRN2 / ZIP2):
    0|Q(1)|001110|size(2)|0|Rm(5)|0|opcode(3)|10|Rn(5)|Rd(5), i.e. (word & 0xbf208c00) == 0x0e000800.
    Enumerates all 2 x 4 x 8 x 2 = 128 combinations of Q=0..1, size=0..3, opcode=0..7
    across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering UZP1/TRN1/ZIP1/UZP2/TRN2/ZIP2
    across 8b/16b/4h/8h/2s/4s/2d, v31 registers, and size=11,Q=0 / opcode in {0,4} unallocated .long).
    """
    words: List[int] = []
    for rd, rn, rm in ((1, 2, 3), (31, 31, 31)):
        for q_bit in (0, 1):
            for size in range(4):
                for opcode in range(8):
                    word = (
                        (q_bit << 30)
                        | (0b001110 << 24)
                        | (size << 22)
                        | (rm << 16)
                        | (opcode << 12)
                        | (0b10 << 10)
                        | (rn << 5)
                        | rd
                    )
                    words.append(word)
    return words


def _generate_advsimd_table_lookup_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.10 Advanced SIMD table lookup (TBL / TBX):
    0|Q(1)|001110|op2(2)|0|Rm(5)|0|len(2)|op(1)|00|Rn(5)|Rd(5), i.e. (word & 0xbf208c00) == 0x0e000000.
    Enumerates all 2 x 4 x 4 x 2 x 2 = 128 combinations of Q=0..1, op2=0..3, len=0..3 (1..4 table registers),
    and op=0..1 (TBL vs TBX) across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)}
    (covering .8b/.16b, 1..4 table registers { v2.16b .. v5.16b }, v31->v0..v2 wrap-around
    { v31.16b, v0.16b, ... }, and op2!=0 unallocated .long space).
    """
    words: List[int] = []
    for rd, rn, rm in ((1, 2, 3), (31, 31, 31)):
        for q_bit in (0, 1):
            for op2 in range(4):
                for length in range(4):
                    for op_bit in (0, 1):
                        word = (
                            (q_bit << 30)
                            | (0b001110 << 24)
                            | (op2 << 22)
                            | (rm << 16)
                            | (length << 13)
                            | (op_bit << 12)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)
    return words


def _generate_advsimd_three_different_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.18 Advanced SIMD three different:
    0|Q(1)|U(1)|01110|size(2)|1|Rm(5)|opcode(4)|00|Rn(5)|Rd(5), i.e. (word & 0x9f200c00) == 0x0e200000.
    Enumerates all 2 x 2 x 4 x 16 x 2 = 512 combinations of Q=0..1, U=0..1, size=0..3, opcode=0..15
    across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering SADDL/UADDL, SADDW/UADDW, SSUBL/USUBL,
    SSUBW/USUBW, ADDHN/RADDHN, SABAL/UABAL, SUBHN/RSUBHN, SABDL/UABDL, SMLAL/UMLAL, SQDMLAL, SMLSL/UMLSL,
    SQDMLSL, SMULL/UMULL, SQDMULL, PMULL incl. size=11 .1q, *2 upper-half forms, and .long space).
    """
    words: List[int] = []
    for rd, rn, rm in ((1, 2, 3), (31, 31, 31)):
        for q_bit in (0, 1):
            for u_bit in (0, 1):
                for size in range(4):
                    for opcode in range(16):
                        word = (
                            (q_bit << 30)
                            | (u_bit << 29)
                            | (0b01110 << 24)
                            | (size << 22)
                            | (1 << 21)
                            | (rm << 16)
                            | (opcode << 12)
                            | (rn << 5)
                            | rd
                        )
                        words.append(word)
    return words


def _generate_advsimd_vector_by_element_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.13 Advanced SIMD vector x indexed element:
    0|Q(1)|U(1)|01111|size(2)|L(1)|M(1)|Rm4(4)|opcode(4)|H(1)|0|Rn(5)|Rd(5), i.e. (word & 0x9f000400) == 0x0f000000.
    Enumerates all 2 x 2 x 4 x 16 x 2 x 2 x 2 x 2 = 4,096 combinations of Q=0..1, U=0..1, size=0..3,
    opcode=0..15, L=0..1, M=0..1, H=0..1 across (Rd, Rn, Rm4) in {(1, 2, 3), (31, 31, 15)}
    (covering FP16/FP32/FP64 FMLA/FMLS/FMUL/FMULX, FHM FMLAL/FMLSL/FMLAL2/FMLSL2, FCMLA #0/#90/#180/#270,
    integer MLA/MLS/MUL/SQDMULH/SQRDMULH/SQRDMLAH/SQRDMLSH, widening SMLAL/UMLAL/SQDMLAL/SMLSL/UMLSL/SQDMLSL/
    SMULL/UMULL/SQDMULL/*2, SDOT/UDOT .4b[idx], 4-bit v0..v15 vs 5-bit v0..v31 Rm, and .long space).
    """
    words: List[int] = []
    for rd, rn, rm4 in ((1, 2, 3), (31, 31, 15)):
        for q_bit in (0, 1):
            for u_bit in (0, 1):
                for size in range(4):
                    for opcode in range(16):
                        for l_bit in (0, 1):
                            for m_bit in (0, 1):
                                for h_bit in (0, 1):
                                    word = (
                                        (q_bit << 30)
                                        | (u_bit << 29)
                                        | (0b01111 << 24)
                                        | (size << 22)
                                        | (l_bit << 21)
                                        | (m_bit << 20)
                                        | (rm4 << 16)
                                        | (opcode << 12)
                                        | (h_bit << 11)
                                        | (rn << 5)
                                        | rd
                                    )
                                    words.append(word)
    return words


def _generate_advsimd_scalar_by_element_words() -> List[int]:
    """ARM DDI 0487 C4.1.95.9 Advanced SIMD scalar x indexed element:
    0|1|U(1)|11111|size(2)|L(1)|M(1)|Rm4(4)|opcode(4)|H(1)|0|Rn(5)|Rd(5), i.e. (word & 0xdf000400) == 0x5f000000.
    Enumerates all 2 x 4 x 16 x 2 x 2 x 2 x 2 = 2,048 combinations of U=0..1, size=0..3, opcode=0..15,
    L=0..1, M=0..1, H=0..1 across (Rd, Rn, Rm4) in {(1, 2, 3), (31, 31, 15)}
    (covering scalar FP16/FP32/FP64 FMLA/FMLS/FMUL/FMULX, saturating widening SQDMLAL/SQDMLSL/SQDMULL,
    saturating doubling/RDMA SQDMULH/SQRDMULH/SQRDMLAH/SQRDMLSH, 4-bit v0..v15 vs 5-bit v0..v31 Rm, and .long space).
    """
    words: List[int] = []
    for rd, rn, rm4 in ((1, 2, 3), (31, 31, 15)):
        for u_bit in (0, 1):
            for size in range(4):
                for opcode in range(16):
                    for l_bit in (0, 1):
                        for m_bit in (0, 1):
                            for h_bit in (0, 1):
                                word = (
                                    (0b01 << 30)
                                    | (u_bit << 29)
                                    | (0b11111 << 24)
                                    | (size << 22)
                                    | (l_bit << 21)
                                    | (m_bit << 20)
                                    | (rm4 << 16)
                                    | (opcode << 12)
                                    | (h_bit << 11)
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
    "advsimd_scalar_two_reg_misc": EncodingGroupSpec(
        name="advsimd_scalar_two_reg_misc",
        title="Advanced SIMD scalar two-register miscellaneous — integer, zero-compare, narrowing, and FP32/FP64/FP16 conversions/estimates",
        header_notes=(
            "ARM DDI 0487 C4.1.95.10 ((word & 0xdf3e0c00) == 0x5e200800) & C4.1.95.11 FP16 ((word & 0xdf3e0c00) == 0x5e380800).",
            "Enumerates all 2 x 2 x 4 x 32 = 512 non-register combinations of b21_17 in {0b10000, 0b11100},",
            "U=0..1, size=0..3 (including bit[22]=0 unallocated counterexamples in the FP16 subtable),",
            "and opcode=0..31 with fixed distinct scalar registers Rd=1, Rn=2.",
        ),
        generate_words=_generate_advsimd_scalar_two_reg_misc_words,
    ),
    "advsimd_vec_two_reg_misc": EncodingGroupSpec(
        name="advsimd_vec_two_reg_misc",
        title="Advanced SIMD vector two-register miscellaneous — rev/cnt/mvn/rbit, pairwise-long, zero-compare, narrowing/widening, and FP32/FP64/FP16/FRINTTS",
        header_notes=(
            "ARM DDI 0487 C4.1.95.20 ((word & 0x9f3e0c00) == 0x0e200800) & C4.1.95.21 FP16 ((word & 0x9f3e0c00) == 0x0e380800).",
            "Enumerates all 2 x 2 x 2 x 4 x 32 = 1,024 non-register combinations of b21_17 in {0b10000, 0b11100},",
            "Q=0..1, U=0..1, size=0..3 (including bit[22]=0 unallocated counterexamples in the FP16 subtable),",
            "and opcode=0..31 with fixed distinct vector registers Rd=1, Rn=2.",
        ),
        generate_words=_generate_advsimd_vec_two_reg_misc_words,
    ),
    **{
        f"advsimd_vec_shift_imm_q{q_bit}_u{u_bit}": EncodingGroupSpec(
            name=f"advsimd_vec_shift_imm_q{q_bit}_u{u_bit}",
            title=(
                f"Advanced SIMD vector shift by immediate — slice Q={q_bit}, U={u_bit} "
                "(immh=1..15, immb=0..7, opcode=0..31)"
            ),
            header_notes=(
                "ARM DDI 0487 C4.1.95.19 Advanced SIMD shift by immediate: (word & 0x9f800400) == 0x0f000400 with immh != 0.",
                f"Slice Q={q_bit}, U={u_bit} ({2 * q_bit + u_bit + 1}/4): enumerates all 15 x 8 x 32 = 3,840 non-register combinations",
                "of immh=1..15, immb=0..7, opcode=0..31 (bit[23]=0, bit[10]=1) with fixed distinct vector registers Rd=1, Rn=2.",
                "Excludes immh=0 (Group 11 AdvSIMD modified immediate) and bit[10]=0 (Group 13 AdvSIMD vector indexed element).",
                "Across advsimd_vec_shift_imm_q0_u0..q1_u1 (4 x 3,840 = 15,360 rows), every Group 3 non-register encoding is covered.",
            ),
            generate_words=_make_advsimd_vec_shift_imm_words_generator(q_bit=q_bit, u_bit=u_bit),
        )
        for q_bit in (0, 1)
        for u_bit in (0, 1)
    },
    **{
        f"advsimd_scalar_shift_imm_u{u_bit}": EncodingGroupSpec(
            name=f"advsimd_scalar_shift_imm_u{u_bit}",
            title=(
                f"Advanced SIMD scalar shift by immediate — slice U={u_bit} "
                "(immh=0..15, immb=0..7, opcode=0..31)"
            ),
            header_notes=(
                "ARM DDI 0487 C4.1.95.8 / C4.1.95.9 Advanced SIMD scalar shift by immediate: (word & 0xdf800400) == 0x5f000400.",
                f"Slice U={u_bit} ({u_bit + 1}/2): enumerates all 16 x 8 x 32 = 4,096 non-register combinations",
                "of immh=0..15 (including immh=0 unallocated counterexamples), immb=0..7, opcode=0..31 (bit[23]=0, bit[10]=1)",
                "with fixed distinct scalar registers Rd=1, Rn=2 (excludes bit[10]=0 Group 26 AdvSIMD scalar indexed element).",
                "Across advsimd_scalar_shift_imm_u0 and u1 (2 x 4,096 = 8,192 rows), every Group 30 non-register encoding is covered.",
            ),
            generate_words=_make_advsimd_scalar_shift_imm_words_generator(u_bit=u_bit),
        )
        for u_bit in (0, 1)
    },
    "scalar_fp_fixed_point": EncodingGroupSpec(
        name="scalar_fp_fixed_point",
        title="Scalar floating-point <-> fixed-point conversions — SCVTF, UCVTF, FCVTZS, FCVTZU with #fbits",
        header_notes=(
            "ARM DDI 0487 C4.1.95.25 Floating-point<->fixed-point conversions: (word & 0x5f200000) == 0x1e000000.",
            "Enumerates all 2 x 2 x 4 x 4 x 8 = 512 combinations of sf=0..1, S=0..1, ftype=0..3 (S/D/unallocated/H),",
            "rmode=0..3, opcode=0..7 across scale in {0, 1, 16, 31, 32, 48, 63} (covering #fbits=64, 63, 48, sf=0 boundary 33/32, 16, 1)",
            "with distinct (Rd, Rn) = (1, 2) (3,584 rows), plus 192 zero-register rows (Rd, Rn) in {(1,31), (31,2)} (wzr/xzr vs s31/d31/h31),",
            "totaling 3,776 rows.",
        ),
        generate_words=_generate_scalar_fp_fixed_point_words,
    ),
    "pac_data_ptr": EncodingGroupSpec(
        name="pac_data_ptr",
        title="Pointer Authentication 1-source & Data-processing (1 source) — PACIA/B, PACDA/B, AUTIA/B, AUTDA/B, PACI*Z*, PACD*Z*, AUTI*Z*, AUTD*Z*, XPACI/D, and RBIT/REV/CLZ/CLS",
        header_notes=(
            "ARM DDI 0487 C4.1.94.2 Data-processing (1 source) & Pointer Authentication: (word & 0x5fe00000) == 0x5ac00000.",
            "Enumerates sf=0..1, S=0..1, opcode2 in {0b00000, 0b00001, 0b00010, 0b11111}, opcode=0..63 across",
            "(Rd, Rn) in {(1,2), (1,31), (31,31)} (3,072 rows), plus (Rd, Rn) = (31,2) across sf=1, S=0, opcode2 in {0,1},",
            "opcode=0..63 (128 rows), totaling 3,200 rows.",
        ),
        generate_words=_generate_pac_data_ptr_words,
    ),
    "rcpc_ldapr": EncodingGroupSpec(
        name="rcpc_ldapr",
        title="RCpc register-base load-acquire (FEAT_LRCPC) & o3=1 atomic subtable — LDAPRB, LDAPRH, LDAPR (W/X), and SWP*",
        header_notes=(
            "ARM DDI 0487 C4.1.94.8 Atomic memory operations o3=1 subtable: (word & 0x3f208c00) == 0x38208000.",
            "Enumerates all 4 x 2 x 2 x 8 x 4 = 512 combinations of size=0..3, A=0..1, R=0..1, opc=0..7,",
            "and (Rs, Rn, Rt) in {(31,2,1), (31,31,1), (31,2,31), (30,2,1)} (complementing lse_atomic.tsv).",
        ),
        generate_words=_generate_rcpc_ldapr_words,
    ),
    "scalar_fp_int_conv": EncodingGroupSpec(
        name="scalar_fp_int_conv",
        title="Scalar floating-point <-> integer conversions & GP<->FP moves — FCVTN/P/M/Z/A*, SCVTF, UCVTF, FJCVTZS, and FMOV",
        header_notes=(
            "ARM DDI 0487 C4.1.95.26 Floating-point<->integer conversions: (word & 0x5f20fc00) == 0x1e200000.",
            "Enumerates all 2 x 2 x 4 x 4 x 8 x 3 = 1,536 combinations of sf=0..1, S=0..1, ftype=0..3 (S/D/lane-1/H),",
            "rmode=0..3, opcode=0..7 across (Rd, Rn) in {(1,2), (1,31), (31,2)}.",
        ),
        generate_words=_generate_scalar_fp_int_conv_words,
    ),
    "scalar_fp_one_source": EncodingGroupSpec(
        name="scalar_fp_one_source",
        title="Scalar floating-point data-processing (1 source) — FMOV, FABS, FNEG, FSQRT, FCVT, FRINTN/P/M/Z/A/X/I, and FRINT32/64*",
        header_notes=(
            "ARM DDI 0487 C4.1.95.21 Floating-point data-processing (1 source): (word & 0x5f207c00) == 0x1e204000.",
            "Enumerates all 2 x 2 x 4 x 64 = 1,024 combinations of M=0..1, S=0..1, ftype=0..3 (S/D/unallocated/H),",
            "opcode=0..63 with (Rd, Rn) = (1, 2), plus 96 high-register rows (Rd, Rn) = (31, 31), totaling 1,120 rows.",
        ),
        generate_words=_generate_scalar_fp_one_source_words,
    ),
    "scalar_fp_three_source": EncodingGroupSpec(
        name="scalar_fp_three_source",
        title="Scalar floating-point data-processing (3 source) — FMADD, FMSUB, FNMADD, and FNMSUB",
        header_notes=(
            "ARM DDI 0487 C4.1.95.20 Floating-point data-processing (3 source): (word & 0x5f000000) == 0x1f000000.",
            "Enumerates all 2 x 2 x 4 x 2 x 2 x 2 = 128 combinations of M=0..1, S=0..1, ftype=0..3 (S/D/unallocated/H),",
            "o1=0..1, o0=0..1 across (Rd, Rn, Rm, Ra) in {(1,2,3,4), (31,31,31,31)}.",
        ),
        generate_words=_generate_scalar_fp_three_source_words,
    ),
    "load_store_exclusive_casp": EncodingGroupSpec(
        name="load_store_exclusive_casp",
        title="Load/store exclusive, Load-acquire/store-release (incl. LORegion), CAS, and CASP",
        header_notes=(
            "ARM DDI 0487 C4.1.94.1..4 Load/store exclusive & atomic CAS/CASP: (word & 0x3f000000) == 0x08000000.",
            "Enumerates all 4 x 2 x 2 x 2 x 2 = 64 combinations of size=0..3, o2=0..1, L=0..1, o1=0..1, o0=0..1",
            "across 8 register tuples (Rs, Rt2, Rn, Rt) covering STXR/LDXR, STXP/LDXP, LDAR/STLR, LDLAR/STLLR,",
            "CAS/CASA/CASL/CASAL (Rt2=31), CASP/CASPA/CASPL/CASPAL (Rt2=31, even Rs/Rt incl. 30->ZR), and G62 non-31 Rs/Rt2 (512 rows).",
        ),
        generate_words=_generate_load_store_exclusive_casp_words,
    ),
    "barriers": EncodingGroupSpec(
        name="barriers",
        title="Barriers — CLREX, DSB, SSBB, PSSBB, DMB, ISB, SB, and S0_3_C3_* MSR fallbacks",
        header_notes=(
            "ARM DDI 0487 C4.1.93.5 Barriers: (word & 0xfffff000) == 0xd5033000.",
            "Enumerates all 16 x 8 x 2 = 256 combinations of CRm=0..15, op2=0..7 across Rt in {31, 1}",
            "(covering Rt=31 CLREX, DSB, SSBB, PSSBB, DMB, ISB, SB, and op2 in {0,1,3} / Rt!=31 MSR S0_3_C3_* fallbacks).",
        ),
        generate_words=_generate_barriers_words,
    ),
    "advsimd_scalar_copy": EncodingGroupSpec(
        name="advsimd_scalar_copy",
        title="Advanced SIMD scalar copy — scalar DUP element (preferred alias MOV) and unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.4 Advanced SIMD scalar copy: (word & 0xdfe08400) == 0x5e000400.",
            "Enumerates all 2 x 32 x 16 x 2 = 2,048 combinations of op=0..1, imm5=0..31, imm4=0..15",
            "across (Rd, Rn) in {(1, 2), (31, 31)} (covering MOV <B|H|S|D><d>, v<n>.<b|h|s|d>[index] and .long space).",
        ),
        generate_words=_generate_advsimd_scalar_copy_words,
    ),
    "advsimd_modified_imm": EncodingGroupSpec(
        name="advsimd_modified_imm",
        title="Advanced SIMD modified immediate — MOVI, MVNI, ORR, BIC, FMOV vector forms, and o2/cmode unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.14 Advanced SIMD modified immediate: (word & 0x9ff80400) == 0x0f000400.",
            "Enumerates all 2 x 2 x 16 x 2 = 128 combinations of Q=0..1, op=0..1, cmode=0..15, o2=0..1:",
            "imm8 in {0x00, 0x01, 0x80, 0xff} for cmode=0..14 with Rd=1 (480 rows), all 256 imm8=0..255 values",
            "for cmode=0b1111 FMOV/unallocated space with Rd=1 (2,048 rows), plus Rd=31 across cmode=0..15",
            "with imm8 in {0x00, 0x01, 0x80, 0xff} (512 rows), totaling 3,040 rows.",
        ),
        generate_words=_generate_advsimd_modified_imm_words,
    ),
    "advsimd_ext": EncodingGroupSpec(
        name="advsimd_ext",
        title="Advanced SIMD extract — EXT (.8b / .16b) and op2!=0 / Q=0,imm4>=8 unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.12 Advanced SIMD extract: (word & 0xbf208400) == 0x2e000000.",
            "Enumerates all 2 x 4 x 16 x 2 = 256 combinations of Q=0..1, op2=0..3, imm4=0..15",
            "across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering EXT .8b/.16b and .long space).",
        ),
        generate_words=_generate_advsimd_ext_words,
    ),
    "advsimd_permute": EncodingGroupSpec(
        name="advsimd_permute",
        title="Advanced SIMD permute — UZP1, TRN1, ZIP1, UZP2, TRN2, ZIP2 and size=11,Q=0 / opcode in {0,4} unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.11 Advanced SIMD permute: (word & 0xbf208c00) == 0x0e000800.",
            "Enumerates all 2 x 4 x 8 x 2 = 128 combinations of Q=0..1, size=0..3, opcode=0..7",
            "across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering 8b/16b/4h/8h/2s/4s/2d and .long space).",
        ),
        generate_words=_generate_advsimd_permute_words,
    ),
    "advsimd_table_lookup": EncodingGroupSpec(
        name="advsimd_table_lookup",
        title="Advanced SIMD table lookup — TBL / TBX (1..4 table registers incl. v31->v0 wrap-around) and op2!=0 unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.10 Advanced SIMD table lookup: (word & 0xbf208c00) == 0x0e000000.",
            "Enumerates all 2 x 4 x 4 x 2 x 2 = 128 combinations of Q=0..1, op2=0..3, len=0..3, op=0..1",
            "across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering 1..4 table regs, v31->v0 wrap, and .long space).",
        ),
        generate_words=_generate_advsimd_table_lookup_words,
    ),
    "advsimd_three_different": EncodingGroupSpec(
        name="advsimd_three_different",
        title="Advanced SIMD three different — widening/narrowing integer & PMULL (incl. .1q and *2 upper-half forms) and unallocated space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.18 Advanced SIMD three different: (word & 0x9f200c00) == 0x0e200000.",
            "Enumerates all 2 x 2 x 4 x 16 x 2 = 512 combinations of Q=0..1, U=0..1, size=0..3, opcode=0..15",
            "across (Rd, Rn, Rm) in {(1, 2, 3), (31, 31, 31)} (covering SADDL/UADDL, SADDW/UADDW, SSUBL/USUBL,",
            "SSUBW/USUBW, ADDHN/RADDHN, SABAL/UABAL, SUBHN/RSUBHN, SABDL/UABDL, SMLAL/UMLAL, SQDMLAL, SMLSL/UMLSL,",
            "SQDMLSL, SMULL/UMULL, SQDMULL, PMULL .8h/.1q, *2 upper-half forms, and .long space).",
        ),
        generate_words=_generate_advsimd_three_different_words,
    ),
    "advsimd_vector_by_element": EncodingGroupSpec(
        name="advsimd_vector_by_element",
        title="Advanced SIMD vector x indexed element — FP16/32/64, FHM, FCMA, DotProd, integer/widening/RDMA by element, and .long space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.13 Advanced SIMD vector x indexed element: (word & 0x9f000400) == 0x0f000000.",
            "Enumerates all 2 x 2 x 4 x 16 x 2 x 2 x 2 x 2 = 4,096 combinations of Q=0..1, U=0..1, size=0..3,",
            "opcode=0..15, L=0..1, M=0..1, H=0..1 across (Rd, Rn, Rm4) in {(1, 2, 3), (31, 31, 15)}",
            "(covering 4-bit Rm v0..v15 for .h vs 5-bit Rm v0..v31 via M=Rm<4> for .s/.d/.4b/FCMLA, and .long space).",
        ),
        generate_words=_generate_advsimd_vector_by_element_words,
    ),
    "advsimd_scalar_by_element": EncodingGroupSpec(
        name="advsimd_scalar_by_element",
        title="Advanced SIMD scalar x indexed element — scalar FP16/32/64, saturating widening & RDMA by element, and .long space",
        header_notes=(
            "ARM DDI 0487 C4.1.95.9 Advanced SIMD scalar x indexed element: (word & 0xdf000400) == 0x5f000000.",
            "Enumerates all 2 x 4 x 16 x 2 x 2 x 2 x 2 = 2,048 combinations of U=0..1, size=0..3, opcode=0..15,",
            "L=0..1, M=0..1, H=0..1 across (Rd, Rn, Rm4) in {(1, 2, 3), (31, 31, 15)}",
            "(covering 4-bit Rm v0..v15 for .h vs 5-bit Rm v0..v31 via M=Rm<4> for .s/.d, and .long space).",
        ),
        generate_words=_generate_advsimd_scalar_by_element_words,
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
