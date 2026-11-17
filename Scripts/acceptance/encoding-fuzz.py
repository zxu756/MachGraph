#!/usr/bin/env python3
"""Random 32-bit A64 machine-word differential fuzz check (`machgraph disasm` vs `llvm-objdump`).

Usage:
  Scripts/acceptance/encoding-fuzz.py --seed <N> --count <M>
      [--machgraph <path>] [--json-out <path>]

Design (`02-machgraph.md`, M2 item 3):
  - Generates `M` 32-bit words via `random.seed(N)` followed by `getrandbits(32)`.
  - Assembles all words as `.inst` directives into an `arm64e` Mach-O with `xcrun clang`.
  - Runs the shared reference command (`mnemonic_normalization.build_reference_command`) and
    `machgraph disasm`, aligns every word by address, and reports:
      1. Both decoded and mnemonics agree (`agreed_instructions`);
      2. Both unrecognized: reference `.long` and MachGraph `.inst` (`both_unrecognized`);
      3. Reference decodes while MachGraph prints `.inst` (`unknown_instructions`, grouped by A64 encoding group);
      4. Wrong mnemonic (`wrong_instructions`, grouped by mnemonic pair and encoding group);
      5. Operand differences among mnemonic-agreed instructions (`operand_differences`, grouped by category with examples).

Exit status:
  0 when `wrong_instructions == 0` and `operand_mismatch == 0`;
  1 when `wrong_instructions > 0` or `operand_mismatch > 0` (or tool/runtime error);
  2 on command-line usage errors.
"""

import argparse
import collections
import datetime
import functools
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

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

TARGET_ARCH = "arm64e"
MAX_EXAMPLES_PER_BUCKET = 5
_REF_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")
_GENERIC_NEON_OPERAND_RE = re.compile(
    r"\bv(?:3[01]|[12]?[0-9])\.(?:16b|8b|8h|4h|2h|4s|2s|2d|1d|1q|b|h|s|d|q)\b"
)


class _UsageError(Exception):
    """Raised on CLI usage errors (exit code 2)."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(f"{self.prog}: error: {message}")


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


def sanitize_repo_label(path: str) -> str:
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, REPO_ROOT)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return os.path.basename(abs_path)


def generate_random_words(seed: int, count: int) -> List[int]:
    """Generate `count` 32-bit words identically to `random.seed(seed)` + `random.getrandbits(32)`."""
    rng = random.Random()
    rng.seed(seed)
    return [rng.getrandbits(32) for _ in range(count)]


def classify_a64_encoding_group(word: int) -> str:
    """Classify a 32-bit A64 word into its ARM DDI 0487 C4.1 encoding group."""
    op0 = (word >> 25) & 0xF

    # 1. Reserved (op0 = 000x)
    if (op0 & 0b1110) == 0b0000:
        return "Reserved / UDF"

    # 2. Data Processing -- Immediate (op0 = 100x)
    if (op0 & 0b1110) == 0b1000:
        op1 = (word >> 23) & 0x7
        if op1 in (0b000, 0b001):
            return "PC-rel. addressing"
        if op1 == 0b010:
            return "Add/subtract (immediate)"
        if op1 == 0b011:
            return "Add/subtract (immediate, with tags)"
        if op1 == 0b100:
            return "Logical (immediate)"
        if op1 == 0b101:
            return "Move wide (immediate)"
        if op1 == 0b110:
            return "Bitfield"
        return "Extract"

    # 3. Branches, Exception Generating and System (op0 = 101x)
    if (op0 & 0b1110) == 0b1010:
        if (word & 0x7C000000) == 0x14000000:
            return "Unconditional branch (immediate)"
        if (word & 0x7E000000) == 0x34000000:
            return "Compare and branch (immediate)"
        if (word & 0x7E000000) == 0x36000000:
            return "Test and branch (immediate)"
        if (word & 0xFE000000) == 0x54000000:
            return "Conditional branch (immediate)"
        if (word & 0xFF000000) == 0xD4000000:
            return "Exception generation"
        if (word & 0xFFFFF000) == 0xD5031000:
            return "System instructions with register argument"
        if (word & 0xFFFFF01F) == 0xD503201F:
            return "Hints"
        if (word & 0xFFFFF000) == 0xD5033000:
            return "Barriers"
        if (word & 0xFFF8F01F) == 0xD500401F:
            return "PSTATE"
        if (word & 0xFFD80000) == 0xD5080000:
            return "System instruction (SYS/SYSL)"
        if (word & 0xFFC00000) == 0xD5000000:
            return "System register move (MRS/MSR)"
        if (word & 0xFE000000) == 0xD6000000:
            return "Unconditional branch (register)"
        return "Branches/System (unclassified)"

    # 4. Loads and Stores (op0 = x1x0)
    if (op0 & 0b0101) == 0b0100:
        if (word & 0xBF000000) == 0x0C000000:
            return "AdvSIMD load/store multiple structures"
        if (word & 0xBF000000) == 0x0D000000:
            return "AdvSIMD load/store single structure"
        if (word & 0x3F000000) == 0x08000000:
            return "Load/store exclusive and CASP"
        if (word & 0x3F000000) == 0x19000000:
            return "LDAPR/STLR (unscaled immediate)"
        if (word & 0x3B000000) == 0x18000000:
            return "Load register (literal)"
        if (word & 0x3A000000) == 0x28000000:
            return "Load/store pair"
        if (word & 0x3B000000) == 0x39000000:
            return "Load/store register (unsigned immediate)"
        if (word & 0x3B000000) == 0x38000000:
            bit21 = (word >> 21) & 1
            op4 = (word >> 10) & 0x3
            is_simd = (word >> 26) & 1
            if bit21 == 0:
                if op4 == 0b00:
                    return "Load/store register (unscaled immediate)"
                if op4 == 0b01:
                    return "Load/store register (immediate post-indexed)"
                if op4 == 0b10:
                    return "Load/store register (unprivileged)"
                return "Load/store register (immediate pre-indexed)"
            else:
                if op4 == 0b00 and not is_simd:
                    return "LDAPR (RCpc) and LSE atomic"
                if op4 == 0b10:
                    return "Load/store register (register offset)"
                if op4 in (0b01, 0b11) and not is_simd:
                    return "Load/store register PAC"
        return "Loads and stores (unclassified)"

    # 5. Data Processing -- Register (op0 = x101)
    if (op0 & 0b0111) == 0b0101:
        if (word & 0x1F000000) == 0x0A000000:
            return "Logical (shifted register)"
        if (word & 0x1F000000) == 0x0B000000:
            if ((word >> 21) & 1) == 0:
                return "Add/subtract (shifted register)"
            return "Add/subtract (extended register)"
        if (word & 0x1F000000) == 0x1B000000:
            return "Data-processing (3 source)"
        if (word & 0x5FE00000) == 0x5AC00000:
            if (word & 0xFFFF8000) == 0xDAC10000:
                return "PAC data/instruction pointer"
            return "Data-processing (1 source)"
        if (word & 0x5FE00000) == 0x1AC00000:
            return "Data-processing (2 source)"
        if (word & 0x1FE00000) == 0x1A000000:
            op2 = (word >> 10) & 0x3F
            if op2 == 0:
                return "Add/subtract (with carry)"
            return "Rotate right / Evaluate into flags"
        if (word & 0x1FE00800) == 0x1A400000:
            return "Conditional compare (register)"
        if (word & 0x1FE00800) == 0x1A400800:
            return "Conditional compare (immediate)"
        if (word & 0x1FE00000) == 0x1A800000:
            return "Conditional select"
        return "Data-processing register (unclassified)"

    # 6. Data Processing -- Scalar FP and AdvSIMD (op0 = x111)
    if (word & 0xFF3E0C00) == 0x4E280800:
        opcode = (word >> 12) & 0x1F
        if opcode in (0b00100, 0b00101, 0b00110, 0b00111):
            return "Crypto AES"
    if (word & 0xFF3E0C00) == 0x5E280800 or (word & 0xFFE08C00) == 0x5E000000:
        return "Crypto SHA (SHA1/SHA256)"
    if (word & 0xFF000000) == 0xCE000000:
        op_hi = (word >> 21) & 0x7
        if op_hi in (0b000, 0b001, 0b010, 0b100):
            return "Crypto four-register / SHA3 (EOR3/BCAX/SM3/XAR)"
        return "Crypto SHA512/SM3/SM4"

    # Scalar Floating-Point: bit[30]==0, bit[28]==1
    if (word & 0x5E000000) == 0x1E000000:
        if (word & 0x5F000000) == 0x1F000000:
            return "Scalar FP data-processing (3 source)"
        if ((word >> 21) & 1) == 0:
            return "Scalar FP <-> fixed-point conversions"
        if (word & 0x5F207C00) == 0x1E204000:
            return "Scalar FP data-processing (1 source)"
        if (word & 0x5F203C00) == 0x1E200800:
            return "Scalar FP data-processing (2 source)"
        if (word & 0x5F203C00) == 0x1E202000:
            return "Scalar FP compare"
        if (word & 0x5F201C00) == 0x1E201000:
            return "Scalar FP immediate"
        if (word & 0x5F200C00) == 0x1E200400:
            return "Scalar FP conditional compare"
        if (word & 0x5F200C00) == 0x1E200C00:
            return "Scalar FP conditional select"
        if ((word >> 10) & 0x3F) == 0:
            return "Scalar FP <-> integer conversions"
        return "Scalar FP (unclassified)"

    # AdvSIMD (vector when bit[28]==0; scalar when bit[30]==1 and bit[28]==1)
    is_advsimd_scalar = ((word >> 28) & 1) == 1 and ((word >> 30) & 1) == 1
    w_vec = word & ~(1 << 28) if is_advsimd_scalar else word

    # In 0x0f00_0000..0x0f7f_ffff: bit[10]==1 is Shift by immediate / Modified immediate;
    # bit[10]==0 is FP16 / RDMA Indexed element.
    if (w_vec & 0x9F800400) == 0x0F000400:
        immh = (w_vec >> 19) & 0xF
        if immh == 0 and not is_advsimd_scalar:
            return "AdvSIMD vector modified immediate"
        return "AdvSIMD scalar shift by immediate" if is_advsimd_scalar else "AdvSIMD vector shift by immediate"

    if (w_vec & 0x9F800400) == 0x0F000000 or (w_vec & 0x9F800000) == 0x0F800000:
        return "AdvSIMD scalar indexed element" if is_advsimd_scalar else "AdvSIMD vector indexed element"

    if not is_advsimd_scalar:
        if (word & 0xBF208400) == 0x2E000000:
            return "AdvSIMD vector EXT"
        if (word & 0xBF208C00) == 0x0E000000:
            return "AdvSIMD vector table lookup (TBL/TBX)"
        if (word & 0xBF208C00) == 0x0E000800:
            return "AdvSIMD vector permute (ZIP/UZP/TRN)"

    if (w_vec & 0x9FE08400) == 0x0E000400:
        return "AdvSIMD scalar copy" if is_advsimd_scalar else "AdvSIMD vector copy"

    if (w_vec & 0x9F3E0C00) == 0x0E200800 or (w_vec & 0x9F7E0C00) == 0x0E780800:
        return "AdvSIMD scalar two-register misc" if is_advsimd_scalar else "AdvSIMD vector two-register misc"

    if (w_vec & 0x9F3E0C00) == 0x0E300800:
        return "AdvSIMD scalar pairwise" if is_advsimd_scalar else "AdvSIMD vector across lanes"

    if (w_vec & 0x9F200C00) == 0x0E200000:
        return "AdvSIMD scalar three-register different" if is_advsimd_scalar else "AdvSIMD vector three-register different"

    if not is_advsimd_scalar and (word & 0x9FA0FC00) == 0x0E809400:
        return "AdvSIMD dot product (SDOT/UDOT)"

    if (w_vec & 0x9F000400) == 0x0E000400:
        return "AdvSIMD scalar three-register same" if is_advsimd_scalar else "AdvSIMD vector three-register same"

    if (w_vec & 0x9F000000) == 0x0E000000:
        return "AdvSIMD scalar three-register extension" if is_advsimd_scalar else "AdvSIMD vector three-register extension"

    return "AdvSIMD/FP (unclassified)"


def compile_inst_words_macho(words: Sequence[int], bin_path: str, arch: str = TARGET_ARCH) -> None:
    asm_path = bin_path + ".s"
    lines = [
        ".section __TEXT,__text,regular,pure_instructions\n",
        ".globl _main\n",
        ".p2align 2\n",
        "_main:\n",
    ]
    lines.extend(f"\t.inst 0x{w:08x}\n" for w in words)
    with open(asm_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    proc = subprocess.run(
        ["xcrun", "clang", "-arch", arch, asm_path, "-o", bin_path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=180.0,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:400]
        raise RuntimeError(f"xcrun clang failed (exit {proc.returncode}): {err}")


@functools.lru_cache(maxsize=1)
def verify_clang_generic_neon_syntax() -> Optional[str]:
    """Self-contained check (without reading any system binary) that `-mllvm=-aarch64-neon-syntax=generic` works."""
    with tempfile.TemporaryDirectory(prefix="machgraph-fuzz-neon-") as tmp:
        bin_path = os.path.join(tmp, "neon_probe.macho")
        try:
            compile_inst_words_macho([0x6F00E400], bin_path, arch=TARGET_ARCH)
            proc = subprocess.run(
                build_reference_command(bin_path, TARGET_ARCH),
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=30.0,
            )
        except Exception as exc:  # pragma: no cover
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


def is_worktree_clean() -> bool:
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=REPO_ROOT,
    )
    if res.returncode != 0:
        return False
    return res.stdout.decode("utf-8", errors="replace").strip() == ""


def collect_environment_metadata(machgraph_bin: str) -> Dict[str, Any]:
    def run_text(cmd: List[str], cwd: Optional[str] = None) -> str:
        r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, cwd=cwd)
        return r.stdout.decode("utf-8", errors="replace").strip()

    llvm_ver_raw = run_text(["xcrun", "llvm-objdump", "--version"])
    llvm_ver_line = next(
        (ln.strip() for ln in llvm_ver_raw.splitlines() if "LLVM version" in ln or "Apple LLVM" in ln),
        llvm_ver_raw.splitlines()[0].strip() if llvm_ver_raw else "unknown",
    )
    commit_sha = run_text(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT) or "unknown"
    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
        "llvm_objdump_version": llvm_ver_line,
        "machgraph_commit": commit_sha,
        "worktree_clean": is_worktree_clean(),
        "machgraph_binary": sanitize_repo_label(machgraph_bin),
    }


def run_fuzz(seed: int, count: int, machgraph_bin: str) -> Dict[str, Any]:
    neon_err = verify_clang_generic_neon_syntax()
    if neon_err is not None:
        raise RuntimeError(neon_err)

    t0 = time.monotonic()
    words = generate_random_words(seed, count)

    with tempfile.TemporaryDirectory(prefix="machgraph-encoding-fuzz-") as tmp:
        bin_path = os.path.join(tmp, "fuzz.macho")
        home_dir = os.path.join(tmp, "home")
        os.makedirs(home_dir, exist_ok=True)

        compile_inst_words_macho(words, bin_path, arch=TARGET_ARCH)

        ref_proc = subprocess.run(
            build_reference_command(bin_path, TARGET_ARCH),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=180.0,
        )
        if ref_proc.returncode != 0:
            err = ref_proc.stderr.decode("utf-8", errors="replace").strip()[:300]
            raise RuntimeError(f"llvm-objdump exited {ref_proc.returncode}: {err}")

        ref_rows: List[Tuple[int, str, str, str]] = []
        for line in ref_proc.stdout.decode("utf-8", errors="replace").splitlines():
            if line.strip() == "Contents of (__TEXT,__text) section":
                break
            m = _REF_INSN_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw_mnem = m.group(2).strip().lower()
            raw_full_ops = (m.group(3) or "").strip()
            raw_ops = raw_full_ops.split(";", 1)[0].strip()
            ref_rows.append((addr, raw_mnem, raw_ops, raw_full_ops))

        bad_neon = find_non_generic_neon_mnemonic((addr, mnem) for addr, mnem, _, _ in ref_rows)
        if bad_neon is not None:
            bad_addr, bad_mnem = bad_neon
            raise RuntimeError(
                f"non-generic Neon syntax in reference output: saw arrangement-suffixed mnemonic '{bad_mnem}' at 0x{bad_addr:x}"
            )
        if len(ref_rows) != len(words):
            raise RuntimeError(f"reference row count mismatch: expected {len(words)}, got {len(ref_rows)}")

        env = dict(
            os.environ,
            HOME=home_dir,
            CFFIXED_USER_HOME=home_dir,
            SWIFT_BACKTRACE="enable=no",
        )
        mg_proc = subprocess.run(
            [machgraph_bin, "disasm", bin_path],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=180.0,
            env=env,
        )
        if mg_proc.returncode != 0:
            err = mg_proc.stderr.decode("utf-8", errors="replace").strip()
            first_err = err.splitlines()[0] if err else ""
            raise RuntimeError(f"machgraph disasm exited {mg_proc.returncode}: {first_err[:240]}")

        mg_map: Dict[int, Tuple[int, str, str]] = {}
        in_text_section = True
        saw_section_header = False
        for line in mg_proc.stdout.decode("utf-8", errors="replace").splitlines():
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
                w_val = int(parts[1].strip(), 16)
                mnem = parts[2].strip().lower()
                ops = parts[3].strip() if len(parts) > 3 else ""
                mg_map[addr] = (w_val, mnem, ops)

        if len(mg_map) != len(words):
            raise RuntimeError(f"machgraph row count mismatch: expected {len(words)}, got {len(mg_map)}")

    elapsed = round(time.monotonic() - t0, 3)

    agreed = 0
    both_unrecognized = 0
    unknown_total = 0
    wrong_total = 0
    operand_compared = 0
    operand_equal = 0

    unknown_group_counts: collections.Counter = collections.Counter()
    unknown_group_examples: Dict[str, List[Dict[str, str]]] = {}

    wrong_pair_counts: collections.Counter = collections.Counter()
    wrong_pair_groups: Dict[Tuple[str, str], str] = {}
    wrong_pair_examples: Dict[Tuple[str, str], List[Dict[str, str]]] = {}

    wrong_group_counts: collections.Counter = collections.Counter()
    wrong_group_examples: Dict[str, List[Dict[str, str]]] = {}

    operand_diff_counts: collections.Counter = collections.Counter()
    operand_diff_examples: Dict[str, List[Dict[str, str]]] = {}

    base_addr = ref_rows[0][0] if ref_rows else 0
    for idx, (word, (addr, raw_ref_mnem, raw_ref_ops, raw_ref_full_ops)) in enumerate(zip(words, ref_rows)):
        expected_addr = base_addr + 4 * idx
        if addr != expected_addr:
            raise RuntimeError(f"address alignment error at index {idx}: expected 0x{expected_addr:x}, got 0x{addr:x}")
        got = mg_map.get(addr)
        if got is None:
            raise RuntimeError(f"missing machgraph address 0x{addr:x} at index {idx}")
        mg_word, mg_mnem, mg_ops = got
        if mg_word != word:
            raise RuntimeError(f"word mismatch at 0x{addr:x}: expected 0x{word:08x}, got 0x{mg_word:08x}")

        kind, norm_ref, norm_mg = classify_mnemonic_pair(raw_ref_mnem, mg_mnem)
        ref_disp_ops = (
            raw_ref_full_ops
            if (norm_ref == "adrp" and ";" in raw_ref_full_ops)
            else raw_ref_ops
        )
        sample_rec = {
            "address": f"0x{addr:x}",
            "word": f"0x{word:08x}",
            "llvm": f"{raw_ref_mnem} {ref_disp_ops}".strip(),
            "machgraph": f"{mg_mnem} {mg_ops}".strip(),
        }

        if kind == "agree":
            agreed += 1
            operand_compared += 1
            if operands_equal(norm_ref, raw_ref_full_ops, mg_ops, address=addr):
                operand_equal += 1
            else:
                ref_sh = operand_shape_for_category(raw_ref_ops)
                mg_sh = operand_shape_for_category(mg_ops)
                cat_key = f"{norm_ref}|{norm_mg}|{ref_sh}|{mg_sh}"
                operand_diff_counts[cat_key] += 1
                ex_list = operand_diff_examples.setdefault(cat_key, [])
                if len(ex_list) < MAX_EXAMPLES_PER_BUCKET:
                    ex_list.append(sample_rec)
        elif kind == "reference_long_machgraph_inst":
            both_unrecognized += 1
        elif kind == "unknown":
            unknown_total += 1
            grp = classify_a64_encoding_group(word)
            unknown_group_counts[grp] += 1
            ex_list = unknown_group_examples.setdefault(grp, [])
            if len(ex_list) < MAX_EXAMPLES_PER_BUCKET:
                ex_list.append(sample_rec)
        else:
            wrong_total += 1
            grp = classify_a64_encoding_group(word)
            pair_key = (norm_ref, norm_mg)
            wrong_pair_counts[pair_key] += 1
            wrong_pair_groups.setdefault(pair_key, grp)
            p_ex = wrong_pair_examples.setdefault(pair_key, [])
            if len(p_ex) < MAX_EXAMPLES_PER_BUCKET:
                p_ex.append(sample_rec)

            grp_key = f"{grp}: {norm_ref} != {norm_mg}"
            wrong_group_counts[grp_key] += 1
            g_ex = wrong_group_examples.setdefault(grp_key, [])
            if len(g_ex) < MAX_EXAMPLES_PER_BUCKET:
                g_ex.append(sample_rec)

    operand_mismatch = operand_compared - operand_equal
    operand_pct = (100.0 * operand_equal / operand_compared) if operand_compared else 100.0

    unknown_group_list = [
        {
            "encoding_group": grp,
            "count": cnt,
            "examples": unknown_group_examples[grp],
        }
        for grp, cnt in sorted(unknown_group_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    wrong_pair_list = [
        {
            "llvm_mnemonic": llvm_m,
            "machgraph_mnemonic": mg_m,
            "encoding_group": wrong_pair_groups[(llvm_m, mg_m)],
            "count": cnt,
            "examples": wrong_pair_examples[(llvm_m, mg_m)],
        }
        for (llvm_m, mg_m), cnt in sorted(wrong_pair_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    wrong_group_list = [
        {
            "category": grp_key,
            "count": cnt,
            "examples": wrong_group_examples[grp_key],
        }
        for grp_key, cnt in sorted(wrong_group_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    operand_diff_list = []
    for cat_key, cnt in sorted(operand_diff_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        llvm_m, mg_m, llvm_sh, mg_sh = cat_key.split("|", 3)
        operand_diff_list.append(
            {
                "category": f"{llvm_m}|{mg_m}: {llvm_sh} != {mg_sh}",
                "llvm_mnemonic": llvm_m,
                "machgraph_mnemonic": mg_m,
                "llvm_shape": llvm_sh,
                "machgraph_shape": mg_sh,
                "count": cnt,
                "examples": operand_diff_examples[cat_key],
            }
        )

    passed = wrong_total == 0 and operand_mismatch == 0
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    env_meta = collect_environment_metadata(machgraph_bin)

    return {
        "schema_version": 1,
        "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": "PASS" if passed else "FAIL",
        "environment": env_meta,
        "reference_command": REFERENCE_COMMAND_TEMPLATE,
        "normalization_rules": list(NORMALIZATION_RULES),
        "operand_normalization_rules": list(OPERAND_NORMALIZATION_RULES),
        "summary": {
            "seed": seed,
            "count": count,
            "agreed_instructions": agreed,
            "both_unrecognized": both_unrecognized,
            "reference_long_machgraph_inst": both_unrecognized,
            "unknown_instructions": unknown_total,
            "wrong_instructions": wrong_total,
            "operand_compared": operand_compared,
            "operand_equal": operand_equal,
            "operand_mismatch": operand_mismatch,
            "operand_agreement_pct": round(operand_pct, 6),
            "elapsed_seconds": elapsed,
        },
        "unknown_by_encoding_group": unknown_group_list,
        "wrong_by_mnemonic_pair": wrong_pair_list,
        "wrong_by_encoding_group": wrong_group_list,
        "operand_differences": operand_diff_list,
    }


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="encoding-fuzz.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--seed", required=True, type=int, help="integer seed passed to random.seed(N)")
    parser.add_argument("--count", required=True, type=int, help="number of random 32-bit words (M >= 1)")
    parser.add_argument("--machgraph", default=default_machgraph_bin(), help="path to MachGraph CLI executable")
    parser.add_argument("--json-out", default=None, help="write structured JSON report to this path")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.count < 1:
            raise _UsageError("--count must be >= 1")
    except _UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(f"[FAIL] MachGraph executable not found or not executable: {args.machgraph}", file=sys.stderr)
        return 1

    try:
        payload = run_fuzz(args.seed, args.count, args.machgraph)
    except Exception as exc:
        print(f"[FAIL] encoding-fuzz failed: {exc}", file=sys.stderr)
        return 1

    s = payload["summary"]
    env_meta = payload["environment"]
    verdict = payload["verdict"]

    print(f"=== MachGraph Random Word Differential Fuzz (seed={s['seed']}, count={s['count']}) ===")
    print(f"Date (UTC):   {payload['generated_at_utc']}")
    print(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    print(f"Reference:    {env_meta['llvm_objdump_version']}")
    print(f"Ref command:  {REFERENCE_COMMAND_TEMPLATE}")
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print(f"Mnemonic rules ({len(NORMALIZATION_RULES)}): {NORMALIZATION_SUMMARY}")
    print(f"Operand rules ({len(OPERAND_NORMALIZATION_RULES)}):  {OPERAND_NORMALIZATION_SUMMARY}")
    print("")
    print(
        f"[{verdict}] Summary: count={s['count']} agree={s['agreed_instructions']} "
        f"both_unrecognized={s['both_unrecognized']} unknown={s['unknown_instructions']} "
        f"wrong={s['wrong_instructions']} "
        f"operands={s['operand_equal']}/{s['operand_compared']} ({s['operand_agreement_pct']:.4f}%, "
        f"mismatch={s['operand_mismatch']}) elapsed={s['elapsed_seconds']:.2f}s"
    )

    if payload["unknown_by_encoding_group"]:
        print(
            f"  unknown (reference decoded, MachGraph .inst) by encoding group "
            f"({len(payload['unknown_by_encoding_group'])} groups, total={s['unknown_instructions']}):"
        )
        for item in payload["unknown_by_encoding_group"]:
            ex = item["examples"][0]
            print(
                f"    - {item['encoding_group']}: count={item['count']} "
                f"e.g. [{ex['word']}] llvm='{ex['llvm']}' vs machgraph='{ex['machgraph']}'"
            )

    if payload["wrong_by_mnemonic_pair"]:
        print(
            f"  wrong mnemonics ({len(payload['wrong_by_mnemonic_pair'])} pairs, total={s['wrong_instructions']}):"
        )
        for item in payload["wrong_by_mnemonic_pair"]:
            ex = item["examples"][0]
            print(
                f"    - {item['llvm_mnemonic']} != {item['machgraph_mnemonic']} "
                f"({item['encoding_group']}): count={item['count']} "
                f"e.g. [{ex['word']}] llvm='{ex['llvm']}' vs machgraph='{ex['machgraph']}'"
            )

    if payload["operand_differences"]:
        print(
            f"  operand difference categories ({len(payload['operand_differences'])}, "
            f"total={s['operand_mismatch']}):"
        )
        for item in payload["operand_differences"]:
            print(f"    - {item['category']}: count={item['count']}")
            for ex in item["examples"][:3]:
                print(
                    f"        [{ex['word']}] machgraph='{ex['machgraph']}' vs llvm='{ex['llvm']}'"
                )

    if args.json_out is not None:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2) + "\n")
        print(f"  JSON report written to {sanitize_repo_label(args.json_out)}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
