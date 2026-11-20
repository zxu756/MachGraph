#!/usr/bin/env python3
"""Shared helpers for MachGraph M2 assembler acceptance scripts (`asm-roundtrip.py`, `asm-clang.py`).

Provides:
  - Stage 15b/15d canonical instruction form normalizer (`split_mnemonic_and_operands`,
    `format_instruction_form`) — single source of truth across Python harnesses.
  - `machgraph disasm` `__TEXT,__text` section parser (`DisasmRow`, `parse_disasm_text_section`,
    `run_machgraph_disasm`) matching `differential.compare_one_binary`.
  - Isolated `HOME` environment construction and path label scrubbing.
"""

from dataclasses import dataclass
import functools
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import differential  # noqa: E402


@dataclass(frozen=True)
class DisasmRow:
    addr: int
    word_hex: str
    mnem: str
    ops: str

    @property
    def statement(self) -> str:
        return f"{self.mnem} {self.ops}" if self.ops else self.mnem


# MARK: - Canonical Form Normalizer (Matches Stage 15b `A64AssemblerOperandClassifier.formatInstructionForm`)


def split_mnemonic_and_operands(statement: str) -> Tuple[str, List[str]]:
    trimmed = statement.strip()
    if not trimmed:
        return ("", [])
    split_idx: Optional[int] = None
    for i, ch in enumerate(trimmed):
        if ch in (" ", "\t"):
            split_idx = i
            break
    if split_idx is None:
        return (trimmed.lower(), [])
    mnem = trimmed[:split_idx].lower()
    rest = trimmed[split_idx:].strip(" \t")
    if not rest:
        return (mnem, [])

    operands: List[str] = []
    current: List[str] = []
    bracket_depth = 0
    brace_depth = 0
    for ch in rest:
        if ch == "[":
            bracket_depth += 1
            current.append(ch)
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            current.append(ch)
        elif ch == "{":
            brace_depth += 1
            current.append(ch)
        elif ch == "}":
            brace_depth = max(0, brace_depth - 1)
            current.append(ch)
        elif ch == "," and bracket_depth == 0 and brace_depth == 0:
            operands.append("".join(current).strip(" \t"))
            current = []
        else:
            current.append(ch)
    operands.append("".join(current).strip(" \t"))
    return (mnem, operands)


def _is_word_char(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c == "_"


def _is_hex_digit(c: str) -> bool:
    return ("0" <= c <= "9") or ("a" <= c <= "f") or ("A" <= c <= "F")


def _register_class_letter(lower_word: str) -> Optional[str]:
    if len(lower_word) < 2:
        return None
    first = lower_word[0]
    digits = lower_word[1:]
    if not all("0" <= ch <= "9" for ch in digits):
        return None
    idx = int(digits, 10)
    if first == "x":
        return "X" if idx <= 30 else None
    if first == "w":
        return "W" if idx <= 30 else None
    if first == "v":
        return "V" if idx <= 31 else None
    if first == "q":
        return "Q" if idx <= 31 else None
    if first == "d":
        return "D" if idx <= 31 else None
    if first == "s":
        return "S" if idx <= 31 else None
    if first == "h":
        return "H" if idx <= 31 else None
    if first == "b":
        return "B" if idx <= 31 else None
    return None


def _scan_unsigned_hex_or_dec(chars: str, start: int) -> Optional[int]:
    n = len(chars)
    if start >= n:
        return None
    if (
        chars[start] == "0"
        and start + 2 < n
        and chars[start + 1] == "x"
        and _is_hex_digit(chars[start + 2])
    ):
        p = start + 3
        while p < n and _is_hex_digit(chars[p]):
            p += 1
        return p
    if "0" <= chars[start] <= "9":
        p = start + 1
        while p < n and "0" <= chars[p] <= "9":
            p += 1
        return p
    return None


def _format_single_operand_shape(raw_operand: str) -> str:
    lower = raw_operand.lower()
    normalized = ", ".join(" ".join(seg.split()) for seg in lower.split(","))

    # Pass 1: Replace word-bounded register tokens (x0..x30, w0..w30, v0..v31, q/d/s/h/b0..31).
    pass1_parts: List[str] = []
    i = 0
    n = len(normalized)
    while i < n:
        ch = normalized[i]
        prev_is_word = (i > 0) and _is_word_char(normalized[i - 1])
        if not prev_is_word and (("a" <= ch <= "z") or ch == "_"):
            j = i + 1
            while j < n and _is_word_char(normalized[j]):
                j += 1
            word = normalized[i:j]
            repl = _register_class_letter(word)
            pass1_parts.append(repl if repl is not None else word)
            i = j
        else:
            pass1_parts.append(ch)
            i += 1
    pass1 = "".join(pass1_parts)

    # Pass 2: Replace every number (optional '-', hex 0x[0-9a-f]+ or decimal [0-9]+) with 'N'.
    out_parts: List[str] = []
    k = 0
    m = len(pass1)
    while k < m:
        if pass1[k] == "-":
            end_neg = _scan_unsigned_hex_or_dec(pass1, k + 1)
            if end_neg is not None:
                out_parts.append("N")
                k = end_neg
                continue
        end_pos = _scan_unsigned_hex_or_dec(pass1, k)
        if end_pos is not None:
            out_parts.append("N")
            k = end_pos
        else:
            out_parts.append(pass1[k])
            k += 1
    return "".join(out_parts)


def format_instruction_form(statement: str) -> str:
    """Format an instruction statement into its Stage 15b canonical shape (`form`)."""
    mnem, operands = split_mnemonic_and_operands(statement)
    if not operands:
        return mnem
    return f"{mnem} {', '.join(_format_single_operand_shape(op) for op in operands)}"


# MARK: - Shared Disasm Runner & Environment Helpers


def isolated_env(isolated_home: str) -> Dict[str, str]:
    return dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )


def display_file_label(path: str) -> str:
    """Display system/repo-relative paths while scrubbing user home directory prefixes."""
    abs_p = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_p, REPO_ROOT)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    real_home = os.path.expanduser("~")
    if real_home and real_home != "/" and (abs_p == real_home or abs_p.startswith(real_home + os.sep)):
        return os.path.basename(abs_p)
    return path


def parse_disasm_text_section(mg_stdout: str) -> List[DisasmRow]:
    """Extract `__TEXT,__text` rows from `machgraph disasm <file>` output (mirrors `differential.compare_one_binary`)."""
    rows: List[DisasmRow] = []
    in_text_section = True
    saw_section_header = False
    for line in mg_stdout.splitlines():
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
            raw_hex = f"{int(parts[1].strip(), 16):08x}"
            mnem = parts[2].strip().lower()
            ops = parts[3].strip() if len(parts) > 3 else ""
            rows.append(DisasmRow(addr=addr, word_hex=raw_hex, mnem=mnem, ops=ops))
    return rows


def run_machgraph_disasm(
    machgraph_bin: str,
    target_path: str,
    isolated_home: str,
) -> Tuple[Optional[List[DisasmRow]], Optional[str], float]:
    timeout_sec = max(120.0, differential.per_file_timeout_seconds(target_path))
    env = isolated_env(isolated_home)
    t0 = time.monotonic()
    proc: Optional[subprocess.CompletedProcess] = None
    for attempt in range(2):
        try:
            proc = subprocess.run(
                [machgraph_bin, "disasm", target_path],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout_sec,
                env=env,
            )
            break
        except subprocess.TimeoutExpired:
            if attempt == 0:
                print(f"[RETRY] machgraph disasm timed out on {target_path}; retrying once...", file=sys.stderr)
                continue
            elapsed = round(time.monotonic() - t0, 3)
            return (None, f"machgraph disasm timed out after {timeout_sec:.0f}s", elapsed)

    elapsed = round(time.monotonic() - t0, 3)
    assert proc is not None
    stdout_txt = proc.stdout.decode("utf-8", errors="replace")
    stderr_txt = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err_line = stderr_txt.strip().splitlines()[0] if stderr_txt.strip() else ""
        return (None, f"machgraph disasm exit {proc.returncode}: {err_line[:240]}", elapsed)

    try:
        rows = parse_disasm_text_section(stdout_txt)
    except ValueError as exc:
        return (None, f"malformed machgraph disasm output: {exc}", elapsed)

    if not rows:
        return (None, "machgraph disasm produced 0 instructions in __TEXT,__text", elapsed)

    seen_addrs = set()
    for r in rows:
        if r.addr in seen_addrs:
            return (None, f"duplicate instruction address {hex(r.addr)} in __TEXT,__text", elapsed)
        seen_addrs.add(r.addr)

    return (rows, None, elapsed)


@functools.lru_cache(maxsize=1)
def static_host_os_info() -> Dict[str, str]:
    def run_text(cmd: List[str]) -> str:
        r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL)
        return r.stdout.decode("utf-8", errors="replace").strip()

    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
    }
