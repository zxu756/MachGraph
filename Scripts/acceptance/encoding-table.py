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
