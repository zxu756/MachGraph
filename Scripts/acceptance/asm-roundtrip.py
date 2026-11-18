#!/usr/bin/env python3
"""Roundtrip ARM64 disassembly through `machgraph asm` and classify pre-M2 vs newly-decoded forms.

Usage:
  Scripts/acceptance/asm-roundtrip.py <quick|standard|file...>
      [--machgraph <path>] [--baseline <path>] [--json-out <path>] [--verbose]

  Scripts/acceptance/asm-roundtrip.py --write-baseline
      --baseline-machgraph <v1.3.0 binary> --baseline-commit 2ee33ed
      [--baseline <path>] <quick|standard|file...>

Exit codes:
  0: All target files compared cleanly, mismatch == 0, error == 0,
     all pre-M2 instructions are ok, and all `.inst` placeholders are ok
     (or `--write-baseline` succeeded).
  1: Verification/comparison failure, SHA-256/baseline mismatch, or roundtrip failure.
  2: CLI usage error.
"""

import argparse
from dataclasses import dataclass, field
import datetime
import functools
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import differential  # noqa: E402

DEFAULT_BASELINE_PATH = os.path.join(REPO_ROOT, "Fixtures", "asm", "v1.3.0-inst-words.tsv")
V130_PROBE_BINARY = "/bin/ls"


class _UsageError(Exception):
    """Raised on CLI usage errors (exit code 2)."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(f"{self.prog}: error: {message}")


@dataclass(frozen=True)
class DisasmRow:
    addr: int
    word_hex: str
    mnem: str
    ops: str


@dataclass
class BaselineFileMeta:
    path: str
    arch: str
    sha256: str
    text_lines: int
    inst_lines: int
    unique_inst_words: int


@dataclass
class BaselineData:
    path: str
    sha256: str
    baseline_commit: str
    files: Dict[str, BaselineFileMeta] = field(default_factory=dict)
    words_by_file: Dict[str, Set[str]] = field(default_factory=dict)
    total_data_rows: int = 0


@dataclass
class FormBucket:
    category: str  # "pre_m2" or "newly_decoded"
    form: str
    ok: int = 0
    mismatch: int = 0
    unsupported: int = 0
    error: int = 0
    examples: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return self.ok + self.mismatch + self.unsupported + self.error

    @property
    def non_ok(self) -> int:
        return self.mismatch + self.unsupported + self.error

    def primary_example(self) -> Optional[Dict[str, Any]]:
        for key in ("mismatch", "error", "unsupported"):
            if key in self.examples:
                return self.examples[key]
        return None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "category": self.category,
            "form": self.form,
            "total": self.total,
            "ok": self.ok,
            "mismatch": self.mismatch,
            "unsupported": self.unsupported,
            "error": self.error,
        }
        prim = self.primary_example()
        if prim is not None:
            out["example"] = prim
            out["examples"] = dict(self.examples)
        return out


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


# MARK: - Disasm Parsing, Contiguous Splitting & Helpers


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _isolated_env(isolated_home: str) -> Dict[str, str]:
    return dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )


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


def split_contiguous_runs(rows: Sequence[DisasmRow]) -> List[List[DisasmRow]]:
    """Split `__TEXT,__text` rows into contiguous 4-byte-stepped runs."""
    runs: List[List[DisasmRow]] = []
    for row in rows:
        if not runs or row.addr != runs[-1][-1].addr + 4:
            runs.append([row])
        else:
            runs[-1].append(row)
    return runs


def _run_machgraph_disasm(
    machgraph_bin: str,
    target_path: str,
    isolated_home: str,
) -> Tuple[Optional[List[DisasmRow]], Optional[str], float]:
    timeout_sec = max(120.0, differential.per_file_timeout_seconds(target_path))
    env = _isolated_env(isolated_home)
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

    seen_addrs: Set[int] = set()
    for r in rows:
        if r.addr in seen_addrs:
            return (None, f"duplicate instruction address {hex(r.addr)} in __TEXT,__text", elapsed)
        seen_addrs.add(r.addr)

    return (rows, None, elapsed)


@functools.lru_cache(maxsize=1)
def _static_host_os_info() -> Dict[str, str]:
    def run_text(cmd: List[str]) -> str:
        r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL)
        return r.stdout.decode("utf-8", errors="replace").strip()

    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
    }


def collect_environment_metadata(machgraph_bin: str) -> Dict[str, Any]:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=REPO_ROOT,
    )
    commit_sha = r.stdout.decode("utf-8", errors="replace").strip() or "unknown"
    os_info = _static_host_os_info()
    return {
        "macos_product_name": os_info["macos_product_name"],
        "macos_version": os_info["macos_version"],
        "macos_build": os_info["macos_build"],
        "machine": os_info["machine"],
        "machgraph_commit": commit_sha,
        "worktree_clean": differential.is_worktree_clean(),
        "machgraph_binary": differential.sanitize_repo_label(machgraph_bin),
    }


def _display_file_label(path: str) -> str:
    """Display system paths as-is while scrubbing user home directory paths if custom paths are passed."""
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


# MARK: - Baseline Generation & Loading


def verify_v130_baseline_binary(
    baseline_machgraph: str,
    isolated_home: str,
    probe_binary: str = V130_PROBE_BINARY,
) -> Tuple[Optional[List[DisasmRow]], Optional[str]]:
    """Verify `baseline_machgraph` exhibits v1.3.0 (`2ee33ed`) pre-Stage-6 decoder behavior on `/bin/ls`:
    1) High-16-bit-zero words (`0x0000xxxx`) in `/bin/ls` are printed as `.inst` (post-Stage-6 prints `udf`);
    2) `movz` or `movn` mnemonic appears in `/bin/ls` (post-Stage-6 prints `mov`).
    """
    rows, err, _ = _run_machgraph_disasm(baseline_machgraph, probe_binary, isolated_home)
    if err is not None or rows is None:
        return (None, f"pre-generation probe on {probe_binary} failed: {err}")

    high16_zero_rows = [r for r in rows if (int(r.word_hex, 16) & 0xFFFF0000) == 0]
    if not high16_zero_rows:
        return (
            None,
            f"pre-generation check failed on {probe_binary}: found 0 words with upper 16 bits == 0 in __TEXT,__text",
        )
    non_inst_high16 = [r for r in high16_zero_rows if r.mnem != ".inst"]
    if non_inst_high16:
        sample = non_inst_high16[0]
        return (
            None,
            f"pre-generation check failed on {probe_binary}: word 0x{sample.word_hex} at {hex(sample.addr)} "
            f"printed as '{sample.mnem}' instead of '.inst' (post-Stage-6 binary prints 'udf'; need v1.3.0 / 2ee33ed)",
        )

    has_movz_or_movn = any(r.mnem in ("movz", "movn") for r in rows)
    if not has_movz_or_movn:
        return (
            None,
            f"pre-generation check failed on {probe_binary}: neither 'movz' nor 'movn' appeared in __TEXT,__text "
            f"(post-Stage-6 binary prints 'mov'; need v1.3.0 / 2ee33ed)",
        )

    return (rows, None)


def write_baseline_file(
    corpus_name: str,
    candidates: Sequence[str],
    baseline_path: str,
    baseline_machgraph: str,
    baseline_commit: str,
) -> int:
    if not os.path.isfile(baseline_machgraph) or not os.access(baseline_machgraph, os.X_OK):
        print(
            f"[FAIL] Baseline MachGraph executable not found or not executable: "
            f"{differential.sanitize_repo_label(baseline_machgraph)}",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory(prefix="machgraph-asm-baseline-home-") as isolated_home:
        probe_rows, probe_err = verify_v130_baseline_binary(baseline_machgraph, isolated_home)
        if probe_err is not None or probe_rows is None:
            print(f"[FAIL] Refusing to generate baseline: {probe_err}", file=sys.stderr)
            return 1

        file_metas: List[BaselineFileMeta] = []
        data_pairs: List[Tuple[str, str]] = []

        for path in candidates:
            if not os.path.isfile(path):
                print(f"[FAIL] Target binary not found: {_display_file_label(path)}", file=sys.stderr)
                return 1
            arch = differential.select_arm64_slice(path)
            if arch is None:
                print(f"[FAIL] No arm64/arm64e slice in {_display_file_label(path)}", file=sys.stderr)
                return 1
            file_sha = sha256_file(path)

            if path == V130_PROBE_BINARY:
                rows = probe_rows
            else:
                rows, err, _ = _run_machgraph_disasm(baseline_machgraph, path, isolated_home)
                if err is not None or rows is None:
                    print(f"[FAIL] {_display_file_label(path)}: {err}", file=sys.stderr)
                    return 1

            inst_rows = [r for r in rows if r.mnem == ".inst"]
            uniq_words = sorted({r.word_hex for r in inst_rows})
            file_metas.append(
                BaselineFileMeta(
                    path=path,
                    arch=arch,
                    sha256=file_sha,
                    text_lines=len(rows),
                    inst_lines=len(inst_rows),
                    unique_inst_words=len(uniq_words),
                )
            )
            for w in uniq_words:
                data_pairs.append((path, w))

    data_pairs.sort()
    env_meta = collect_environment_metadata(baseline_machgraph)
    if corpus_name in ("quick", "standard", "full"):
        target_arg_desc = corpus_name
    else:
        target_arg_desc = " ".join(differential.sanitize_repo_label(p) for p in candidates)

    gen_cmd = (
        f"python3 -I Scripts/acceptance/asm-roundtrip.py --write-baseline "
        f'--baseline-machgraph "<v1.3.0（{baseline_commit}）的 release 构建>" '
        f"--baseline-commit {baseline_commit} {target_arg_desc}"
    )

    lines: List[str] = [
        f"# MachGraph v1.3.0 ({baseline_commit}) __TEXT,__text .inst baseline words\n",
        f"# Generation command: {gen_cmd}\n",
        f"# Baseline commit: {baseline_commit}\n",
        f"# System: {env_meta['macos_product_name']} {env_meta['macos_version']} ({env_meta['macos_build']}) {env_meta['machine']}\n",
        "# File metadata columns: # file\t<path>\tslice=<arch>\tsha256=<sha256>\ttext_lines=<n>\tinst_lines=<n>\tunique_inst_words=<n>\n",
    ]
    for meta in file_metas:
        lines.append(
            f"# file\t{meta.path}\tslice={meta.arch}\tsha256={meta.sha256}\t"
            f"text_lines={meta.text_lines}\tinst_lines={meta.inst_lines}\tunique_inst_words={meta.unique_inst_words}\n"
        )
    lines.append("# Data columns: <path>\t<word_hex>\n")
    for file_path, word_hex in data_pairs:
        lines.append(f"{file_path}\t{word_hex}\n")

    out_dir = os.path.dirname(os.path.abspath(baseline_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    rendered_bytes = "".join(lines).encode("utf-8")
    with open(baseline_path, "wb") as fh:
        fh.write(rendered_bytes)

    out_sha = hashlib.sha256(rendered_bytes).hexdigest()
    label = differential.sanitize_repo_label(baseline_path)
    print(f"[GENERATED] {label} (sha256={out_sha}): files={len(file_metas)} unique_inst_rows={len(data_pairs)}")
    for meta in file_metas:
        print(
            f"  {_display_file_label(meta.path)} ({meta.arch}): sha256={meta.sha256} "
            f"text_lines={meta.text_lines} inst_lines={meta.inst_lines} unique_inst_words={meta.unique_inst_words}"
        )
    return 0


def load_baseline(baseline_path: str) -> BaselineData:
    with open(baseline_path, "rb") as fh:
        raw_bytes = fh.read()
    file_sha = hashlib.sha256(raw_bytes).hexdigest()
    text = raw_bytes.decode("utf-8")

    baseline_commit = "unknown"
    files: Dict[str, BaselineFileMeta] = {}
    words_by_file: Dict[str, Set[str]] = {}
    data_rows = 0

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("# Baseline commit:"):
                baseline_commit = stripped.split(":", 1)[1].strip() or "unknown"
            elif raw_line.startswith("# file\t"):
                parts = raw_line.split("\t")
                if len(parts) < 6:
                    raise ValueError(f"line {line_no}: malformed '# file' metadata row")
                f_path = parts[1]
                kv: Dict[str, str] = {}
                for field_tok in parts[2:]:
                    if "=" in field_tok:
                        k, v = field_tok.split("=", 1)
                        kv[k.strip()] = v.strip()
                sha_val = kv.get("sha256", "").lower()
                if len(sha_val) != 64 or not all(_is_hex_digit(c) for c in sha_val):
                    raise ValueError(f"line {line_no}: invalid sha256 in '# file' row for {f_path}")
                files[f_path] = BaselineFileMeta(
                    path=f_path,
                    arch=kv.get("slice", "unknown"),
                    sha256=sha_val,
                    text_lines=int(kv.get("text_lines", "0")),
                    inst_lines=int(kv.get("inst_lines", "0")),
                    unique_inst_words=int(kv.get("unique_inst_words", "0")),
                )
                words_by_file.setdefault(f_path, set())
            continue

        cols = raw_line.split("\t")
        if len(cols) != 2:
            raise ValueError(f"line {line_no}: expected 2 tab-separated columns (<file>\\t<word_hex>)")
        f_path = cols[0]
        w_raw = cols[1].strip().lower()
        if w_raw.startswith("0x"):
            w_raw = w_raw[2:]
        if not w_raw or len(w_raw) > 8 or not all(_is_hex_digit(c) for c in w_raw):
            raise ValueError(f"line {line_no}: invalid machine word {cols[1]!r}")
        w_norm = f"{int(w_raw, 16):08x}"
        words_by_file.setdefault(f_path, set()).add(w_norm)
        data_rows += 1

    return BaselineData(
        path=baseline_path,
        sha256=file_sha,
        baseline_commit=baseline_commit,
        files=files,
        words_by_file=words_by_file,
        total_data_rows=data_rows,
    )


# MARK: - Roundtrip Comparison


def _empty_cat_counts() -> Dict[str, int]:
    return {"total": 0, "ok": 0, "mismatch": 0, "unsupported": 0, "error": 0}


def roundtrip_one_binary(
    path: str,
    machgraph_bin: str,
    baseline_words: Set[str],
    expected_sha256: str,
    isolated_home: str,
) -> Dict[str, Any]:
    arch = differential.select_arm64_slice(path)
    if arch is None:
        return {"path": path, "failure": "no arm64/arm64e slice found"}

    t0 = time.monotonic()
    rows, dis_err, _ = _run_machgraph_disasm(machgraph_bin, path, isolated_home)
    if dis_err is not None or rows is None:
        return {
            "path": path,
            "arch": arch,
            "failure": dis_err or "disasm failed",
            "seconds": round(time.monotonic() - t0, 3),
        }

    runs = split_contiguous_runs(rows)
    env = _isolated_env(isolated_home)
    asm_timeout = max(120.0, differential.per_file_timeout_seconds(path))

    inst_placeholders = 0
    inst_placeholders_ok = 0
    inst_placeholders_not_ok = 0
    inst_failure_examples: List[Dict[str, Any]] = []

    cat_counts: Dict[str, Dict[str, int]] = {
        "pre_m2": _empty_cat_counts(),
        "newly_decoded": _empty_cat_counts(),
    }
    form_buckets: Dict[Tuple[str, str], FormBucket] = {}

    disp_file = _display_file_label(path)

    for seg in runs:
        seg_start = seg[0].addr
        stmts: List[str] = []
        for r in seg:
            if r.mnem == ".inst":
                stmts.append(f".inst 0x{r.word_hex}")
            else:
                stmts.append(f"{r.mnem} {r.ops}" if r.ops else r.mnem)

        stdin_bytes = ("\n".join(stmts) + "\n").encode("utf-8")
        asm_proc: Optional[subprocess.CompletedProcess] = None
        for attempt in range(2):
            try:
                asm_proc = subprocess.run(
                    [machgraph_bin, "asm", "--at", f"0x{seg_start:x}", "--json"],
                    input=stdin_bytes,
                    capture_output=True,
                    timeout=asm_timeout,
                    env=env,
                )
                break
            except subprocess.TimeoutExpired:
                if attempt == 0:
                    print(
                        f"[RETRY] machgraph asm timed out on {disp_file} @ {hex(seg_start)}; retrying once...",
                        file=sys.stderr,
                    )
                    continue
                return {
                    "path": path,
                    "arch": arch,
                    "failure": f"machgraph asm timed out after {asm_timeout:.0f}s at {hex(seg_start)}",
                    "seconds": round(time.monotonic() - t0, 3),
                }

        assert asm_proc is not None
        if asm_proc.returncode not in (0, 1, 3):
            err_snip = asm_proc.stderr.decode("utf-8", errors="replace").strip()[:240]
            return {
                "path": path,
                "arch": arch,
                "failure": f"machgraph asm exited {asm_proc.returncode} at {hex(seg_start)}: {err_snip}",
                "seconds": round(time.monotonic() - t0, 3),
            }

        try:
            doc = json.loads(asm_proc.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            return {
                "path": path,
                "arch": arch,
                "failure": f"machgraph asm produced invalid JSON at {hex(seg_start)}: {exc}",
                "seconds": round(time.monotonic() - t0, 3),
            }

        results = doc.get("results") if isinstance(doc, dict) else None
        if not isinstance(results, list):
            return {
                "path": path,
                "arch": arch,
                "failure": f"machgraph asm JSON missing 'results' array at {hex(seg_start)}",
                "seconds": round(time.monotonic() - t0, 3),
            }

        if len(results) != len(seg):
            return {
                "path": path,
                "arch": arch,
                "failure": (
                    f"machgraph asm result count mismatch at {hex(seg_start)}: "
                    f"sent {len(seg)} statements, got {len(results)} results"
                ),
                "seconds": round(time.monotonic() - t0, 3),
            }

        for idx, (orig, stmt, item) in enumerate(zip(seg, stmts, results)):
            if not isinstance(item, dict) or "address" not in item or "status" not in item:
                return {
                    "path": path,
                    "arch": arch,
                    "failure": f"malformed result entry at index {idx} ({hex(orig.addr)})",
                    "seconds": round(time.monotonic() - t0, 3),
                }
            if "index" in item and item["index"] != idx:
                return {
                    "path": path,
                    "arch": arch,
                    "failure": f"result index mismatch at {hex(orig.addr)}: expected {idx}, got {item['index']}",
                    "seconds": round(time.monotonic() - t0, 3),
                }
            try:
                got_addr = int(str(item["address"]), 16)
            except ValueError:
                return {
                    "path": path,
                    "arch": arch,
                    "failure": f"invalid result address {item['address']!r} at index {idx}",
                    "seconds": round(time.monotonic() - t0, 3),
                }
            if got_addr != orig.addr:
                return {
                    "path": path,
                    "arch": arch,
                    "failure": (
                        f"result address mismatch at index {idx}: "
                        f"expected {hex(orig.addr)}, got {hex(got_addr)}"
                    ),
                    "seconds": round(time.monotonic() - t0, 3),
                }

            raw_status = item["status"]
            if orig.mnem == ".inst":
                inst_placeholders += 1
                got_w_raw = item.get("word")
                got_w = f"{int(got_w_raw, 16):08x}" if isinstance(got_w_raw, str) and got_w_raw else ""
                if raw_status == "ok" and got_w == orig.word_hex:
                    inst_placeholders_ok += 1
                else:
                    inst_placeholders_not_ok += 1
                    if len(inst_failure_examples) < 5:
                        inst_failure_examples.append(
                            {
                                "file": disp_file,
                                "address": hex(orig.addr),
                                "word": orig.word_hex,
                                "text": stmt,
                                "status": raw_status,
                                "assembled_word": got_w or None,
                                "reason": item.get("reason"),
                            }
                        )
                continue

            category = "newly_decoded" if (orig.word_hex in baseline_words) else "pre_m2"
            computed_form = format_instruction_form(stmt)

            if raw_status == "ok":
                word_field = item.get("word")
                if not isinstance(word_field, str) or not word_field:
                    return {
                        "path": path,
                        "arch": arch,
                        "failure": f"missing 'word' on ok result at {hex(orig.addr)}",
                        "seconds": round(time.monotonic() - t0, 3),
                    }
                got_word = f"{int(word_field, 16):08x}"
                outcome = "ok" if got_word == orig.word_hex else "mismatch"
            elif raw_status == "unsupported":
                got_word = ""
                outcome = "unsupported"
            elif raw_status == "error":
                got_word = ""
                outcome = "error"
            else:
                return {
                    "path": path,
                    "arch": arch,
                    "failure": f"unknown status {raw_status!r} at {hex(orig.addr)}",
                    "seconds": round(time.monotonic() - t0, 3),
                }

            form_key = item.get("form") if (outcome == "unsupported" and isinstance(item.get("form"), str)) else computed_form

            cat_counts[category]["total"] += 1
            cat_counts[category][outcome] += 1

            bucket = form_buckets.get((category, form_key))
            if bucket is None:
                bucket = FormBucket(category=category, form=form_key)
                form_buckets[(category, form_key)] = bucket

            if outcome == "ok":
                bucket.ok += 1
            elif outcome == "mismatch":
                bucket.mismatch += 1
                bucket.examples.setdefault(
                    "mismatch",
                    {
                        "status": "mismatch",
                        "file": disp_file,
                        "address": hex(orig.addr),
                        "word": orig.word_hex,
                        "assembled_word": got_word,
                        "text": stmt,
                        "form": form_key,
                        "reason": f"assembled {got_word} != original {orig.word_hex}",
                    },
                )
            elif outcome == "unsupported":
                bucket.unsupported += 1
                bucket.examples.setdefault(
                    "unsupported",
                    {
                        "status": "unsupported",
                        "file": disp_file,
                        "address": hex(orig.addr),
                        "word": orig.word_hex,
                        "text": stmt,
                        "mnemonic": item.get("mnemonic") or orig.mnem,
                        "form": form_key,
                    },
                )
            elif outcome == "error":
                bucket.error += 1
                bucket.examples.setdefault(
                    "error",
                    {
                        "status": "error",
                        "file": disp_file,
                        "address": hex(orig.addr),
                        "word": orig.word_hex,
                        "text": stmt,
                        "form": form_key,
                        "reason": item.get("reason") or "assembler error",
                    },
                )

    elapsed = round(time.monotonic() - t0, 3)
    file_passed = (
        inst_placeholders_not_ok == 0
        and cat_counts["pre_m2"]["mismatch"] == 0
        and cat_counts["pre_m2"]["unsupported"] == 0
        and cat_counts["pre_m2"]["error"] == 0
        and cat_counts["newly_decoded"]["mismatch"] == 0
        and cat_counts["newly_decoded"]["error"] == 0
    )
    return {
        "path": path,
        "display_path": disp_file,
        "arch": arch,
        "sha256": expected_sha256,
        "contiguous_segments": len(runs),
        "text_instructions": len(rows),
        "inst_placeholders": inst_placeholders,
        "inst_placeholders_ok": inst_placeholders_ok,
        "inst_placeholders_not_ok": inst_placeholders_not_ok,
        "inst_failure_examples": inst_failure_examples,
        "pre_m2": cat_counts["pre_m2"],
        "newly_decoded": cat_counts["newly_decoded"],
        "form_buckets": form_buckets,
        "passed": file_passed,
        "seconds": elapsed,
    }


def _summarize_category_forms(
    buckets: Sequence[FormBucket],
    totals: Dict[str, int],
) -> Dict[str, int]:
    total_forms = len(buckets)
    all_ok_forms = sum(1 for b in buckets if b.non_ok == 0 and b.total > 0)
    non_ok_forms = sum(1 for b in buckets if b.non_ok > 0)
    mismatch_forms = sum(1 for b in buckets if b.mismatch > 0)
    unsupported_forms = sum(1 for b in buckets if b.unsupported > 0)
    error_forms = sum(1 for b in buckets if b.error > 0)
    return {
        "total": totals["total"],
        "ok": totals["ok"],
        "mismatch": totals["mismatch"],
        "unsupported": totals["unsupported"],
        "error": totals["error"],
        "total_forms": total_forms,
        "all_ok_forms": all_ok_forms,
        "non_ok_forms": non_ok_forms,
        "mismatch_forms": mismatch_forms,
        "unsupported_forms": unsupported_forms,
        "error_forms": error_forms,
    }


def _format_example_inline(ex: Optional[Dict[str, Any]]) -> str:
    if ex is None:
        return ""
    loc = f"{ex['file']} @ {ex['address']} [{ex['word']}] '{ex['text']}'"
    st = ex.get("status")
    if st == "mismatch":
        return f"{loc} -> got [{ex.get('assembled_word')}]"
    if st == "error":
        return f"{loc} -> error: {ex.get('reason')}"
    if st == "unsupported":
        return f"{loc} (form='{ex.get('form')}')"
    return loc


# MARK: - CLI Entrypoint


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="asm-roundtrip.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", help="'quick', 'standard', or one or more binary paths")
    parser.add_argument(
        "--machgraph",
        default=differential.default_machgraph_bin(),
        help="path to MachGraph CLI executable",
    )
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE_PATH,
        help="path to v1.3.0 .inst baseline TSV (default: Fixtures/asm/v1.3.0-inst-words.tsv)",
    )
    parser.add_argument("--json-out", default=None, help="write structured JSON report to this path")
    parser.add_argument("--verbose", action="store_true", help="print additional per-form details")
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="generate the v1.3.0 .inst baseline TSV instead of running roundtrip",
    )
    parser.add_argument(
        "--baseline-machgraph",
        default=None,
        help="path to v1.3.0 MachGraph binary (required with --write-baseline)",
    )
    parser.add_argument(
        "--baseline-commit",
        default=None,
        help="commit hash of the baseline MachGraph build, e.g. 2ee33ed (required with --write-baseline)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.write_baseline:
            if not args.baseline_machgraph or not args.baseline_commit:
                raise _UsageError("--write-baseline requires both --baseline-machgraph and --baseline-commit")
            if args.json_out is not None:
                raise _UsageError("--json-out cannot be combined with --write-baseline")
        else:
            if args.baseline_machgraph is not None or args.baseline_commit is not None:
                raise _UsageError("--baseline-machgraph / --baseline-commit require --write-baseline")
    except _UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    corpus_name, candidates = differential.resolve_targets(args.targets)
    if not candidates:
        print(f"[FAIL] No candidate binaries found for '{corpus_name}'", file=sys.stderr)
        return 1

    if args.write_baseline:
        return write_baseline_file(
            corpus_name=corpus_name,
            candidates=candidates,
            baseline_path=args.baseline,
            baseline_machgraph=args.baseline_machgraph,
            baseline_commit=args.baseline_commit,
        )

    # Normal roundtrip mode: verify baseline & every target SHA-256 BEFORE running MachGraph.
    baseline_label = differential.sanitize_repo_label(args.baseline)
    if not os.path.isfile(args.baseline):
        print(
            f"[FAIL] Baseline file not found: {baseline_label} "
            f"(generate with --write-baseline --baseline-machgraph <v1.3.0 binary> --baseline-commit 2ee33ed)",
            file=sys.stderr,
        )
        return 1

    try:
        baseline = load_baseline(args.baseline)
    except Exception as exc:
        print(f"[FAIL] Invalid baseline file {baseline_label}: {exc}", file=sys.stderr)
        return 1

    verified_shas: Dict[str, str] = {}
    for path in candidates:
        disp = _display_file_label(path)
        if not os.path.isfile(path):
            print(f"[FAIL] Target binary not found: {disp}", file=sys.stderr)
            return 1
        meta = baseline.files.get(path)
        if meta is None:
            print(
                f"[FAIL] Target binary '{disp}' is missing from baseline {baseline_label}. "
                f"Regenerate baseline using v1.3.0 (--write-baseline --baseline-machgraph <v1.3.0 binary> --baseline-commit 2ee33ed).",
                file=sys.stderr,
            )
            return 1
        actual_sha = sha256_file(path)
        if actual_sha != meta.sha256:
            print(
                f"[FAIL] SHA-256 mismatch for '{disp}': baseline has {meta.sha256}, actual file is {actual_sha}. "
                f"System file changed; regenerate baseline using v1.3.0 "
                f"(--write-baseline --baseline-machgraph <v1.3.0 binary> --baseline-commit 2ee33ed).",
                file=sys.stderr,
            )
            return 1
        verified_shas[path] = actual_sha

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(
            f"[FAIL] MachGraph executable not found or not executable: {differential.sanitize_repo_label(args.machgraph)}",
            file=sys.stderr,
        )
        return 1

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    date_str = utc_now.strftime("%Y-%m-%d")
    env_meta = collect_environment_metadata(args.machgraph)

    env_isolated = os.environ.get("MACHGRAPH_ISOLATED_HOME")
    temp_home_ctx = None
    if not env_isolated:
        temp_home_ctx = tempfile.TemporaryDirectory(prefix="machgraph-asm-rt-home-")
        isolated_home = temp_home_ctx.name
    else:
        isolated_home = env_isolated

    t_start = time.monotonic()
    try:
        file_rows = [
            roundtrip_one_binary(
                path=p,
                machgraph_bin=args.machgraph,
                baseline_words=baseline.words_by_file.get(p, set()),
                expected_sha256=verified_shas[p],
                isolated_home=isolated_home,
            )
            for p in candidates
        ]
    finally:
        if temp_home_ctx is not None:
            temp_home_ctx.cleanup()
    wall_seconds = round(time.monotonic() - t_start, 2)

    print(f"=== MachGraph Assembler Roundtrip ({corpus_name}) ===")
    print(f"Date (UTC):   {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print(f"Baseline:     {baseline_label} (commit={baseline.baseline_commit}, sha256={baseline.sha256})")
    print("")

    compared_files = 0
    failures: List[Dict[str, Any]] = []
    compact_files: List[Dict[str, Any]] = []
    inst_failure_examples: List[Dict[str, Any]] = []

    total_text = 0
    total_inst = 0
    total_inst_ok = 0
    total_inst_not_ok = 0
    pre_m2_totals = _empty_cat_counts()
    new_totals = _empty_cat_counts()
    merged_buckets: Dict[Tuple[str, str], FormBucket] = {}

    print_each_file = args.verbose or corpus_name != "full"

    for r in file_rows:
        disp = _display_file_label(r["path"])
        if "failure" in r:
            failures.append(
                {
                    "file": disp,
                    "arch": r.get("arch", "unknown"),
                    "error": r["failure"],
                }
            )
            print(f"[FAIL] {disp}: {r['failure']}")
            continue

        compared_files += 1
        total_text += r["text_instructions"]
        total_inst += r["inst_placeholders"]
        total_inst_ok += r["inst_placeholders_ok"]
        total_inst_not_ok += r["inst_placeholders_not_ok"]
        for ex in r["inst_failure_examples"]:
            if len(inst_failure_examples) < 10:
                inst_failure_examples.append(ex)

        for k in ("total", "ok", "mismatch", "unsupported", "error"):
            pre_m2_totals[k] += r["pre_m2"][k]
            new_totals[k] += r["newly_decoded"][k]

        for key, fb in r["form_buckets"].items():
            dst = merged_buckets.get(key)
            if dst is None:
                dst = FormBucket(category=fb.category, form=fb.form)
                merged_buckets[key] = dst
            dst.ok += fb.ok
            dst.mismatch += fb.mismatch
            dst.unsupported += fb.unsupported
            dst.error += fb.error
            for st_key, ex_val in fb.examples.items():
                dst.examples.setdefault(st_key, ex_val)

        if print_each_file or not r["passed"]:
            tag = "PASS" if r["passed"] else "FAIL"
            pm = r["pre_m2"]
            nw = r["newly_decoded"]
            inst_note = (
                f"inst={r['inst_placeholders']} (not_ok={r['inst_placeholders_not_ok']})"
                if r["inst_placeholders_not_ok"] > 0
                else f"inst_skip={r['inst_placeholders']}"
            )
            print(
                f"[{tag}] {disp} ({r['arch']}): text={r['text_instructions']} {inst_note} "
                f"pre_m2={pm['total']} (ok={pm['ok']} mismatch={pm['mismatch']} unsup={pm['unsupported']} err={pm['error']}) "
                f"new={nw['total']} (ok={nw['ok']} mismatch={nw['mismatch']} unsup={nw['unsupported']} err={nw['error']}) "
                f"({r['seconds']:.2f}s)"
            )

        compact_files.append(
            {
                "path": disp,
                "arch": r["arch"],
                "sha256": r["sha256"],
                "contiguous_segments": r["contiguous_segments"],
                "text_instructions": r["text_instructions"],
                "inst_placeholders": r["inst_placeholders"],
                "inst_placeholders_ok": r["inst_placeholders_ok"],
                "inst_placeholders_not_ok": r["inst_placeholders_not_ok"],
                "pre_m2": dict(r["pre_m2"]),
                "newly_decoded": dict(r["newly_decoded"]),
                "passed": r["passed"],
                "seconds": r["seconds"],
            }
        )

    pre_m2_buckets = [b for b in merged_buckets.values() if b.category == "pre_m2"]
    new_buckets = [b for b in merged_buckets.values() if b.category == "newly_decoded"]

    pre_m2_summary = _summarize_category_forms(pre_m2_buckets, pre_m2_totals)
    new_summary = _summarize_category_forms(new_buckets, new_totals)

    total_ok = pre_m2_totals["ok"] + new_totals["ok"]
    total_mismatch = pre_m2_totals["mismatch"] + new_totals["mismatch"]
    total_unsupported = pre_m2_totals["unsupported"] + new_totals["unsupported"]
    total_error = pre_m2_totals["error"] + new_totals["error"]
    total_decoded = pre_m2_totals["total"] + new_totals["total"]

    forms_mismatch_or_error = sorted(
        [b for b in merged_buckets.values() if (b.mismatch + b.error) > 0],
        key=lambda b: (-(b.mismatch + b.error), b.category, b.form),
    )
    pre_m2_non_ok_forms = sorted(
        [b for b in pre_m2_buckets if b.non_ok > 0],
        key=lambda b: (-b.non_ok, b.form),
    )
    newly_decoded_unsupported_forms = sorted(
        [b for b in new_buckets if b.unsupported > 0],
        key=lambda b: (-b.unsupported, b.form),
    )

    passed = (
        compared_files == len(candidates)
        and compared_files > 0
        and len(failures) == 0
        and total_inst_not_ok == 0
        and total_mismatch == 0
        and total_error == 0
        and pre_m2_totals["mismatch"] == 0
        and pre_m2_totals["unsupported"] == 0
        and pre_m2_totals["error"] == 0
        and pre_m2_totals["ok"] == pre_m2_totals["total"]
    )
    verdict = "PASS" if passed else "FAIL"

    print("")
    print(
        f"[{verdict}] Summary ({corpus_name}): candidates={len(candidates)} compared={compared_files} "
        f"failures={len(failures)} text={total_text} decoded={total_decoded} "
        f"inst_placeholders={total_inst} (ok={total_inst_ok} not_ok={total_inst_not_ok}) elapsed={wall_seconds:.2f}s"
    )
    print(
        f"       pre-M2:        total={pre_m2_summary['total']} ok={pre_m2_summary['ok']} "
        f"mismatch={pre_m2_summary['mismatch']} unsupported={pre_m2_summary['unsupported']} error={pre_m2_summary['error']} | "
        f"forms={pre_m2_summary['total_forms']} (all_ok={pre_m2_summary['all_ok_forms']} non_ok={pre_m2_summary['non_ok_forms']})"
    )
    print(
        f"       newly-decoded: total={new_summary['total']} ok={new_summary['ok']} "
        f"mismatch={new_summary['mismatch']} unsupported={new_summary['unsupported']} error={new_summary['error']} | "
        f"forms={new_summary['total_forms']} (all_ok={new_summary['all_ok_forms']} non_ok={new_summary['non_ok_forms']})"
    )
    print(
        f"       combined:      total={total_decoded} ok={total_ok} "
        f"mismatch={total_mismatch} unsupported={total_unsupported} error={total_error}"
    )

    if inst_failure_examples:
        print(f"\n.inst placeholder failures ({total_inst_not_ok}):")
        for ex in inst_failure_examples:
            print(
                f"  - {ex['file']} @ {ex['address']} [{ex['word']}] '{ex['text']}' -> "
                f"status={ex['status']} word={ex.get('assembled_word')} reason={ex.get('reason')}"
            )

    print(f"\nForms with mismatch or error ({len(forms_mismatch_or_error)}):")
    if forms_mismatch_or_error:
        for b in forms_mismatch_or_error:
            cat_label = "pre-M2" if b.category == "pre_m2" else "newly-decoded"
            print(
                f"  - [{cat_label}] {b.form}: mismatch={b.mismatch} error={b.error} "
                f"(ok={b.ok} unsup={b.unsupported} total={b.total}) | e.g. {_format_example_inline(b.primary_example())}"
            )
    else:
        print("  (none)")

    print(f"\npre-M2 forms not 100% ok ({len(pre_m2_non_ok_forms)}):")
    if pre_m2_non_ok_forms:
        for b in pre_m2_non_ok_forms:
            print(
                f"  - {b.form}: non_ok={b.non_ok} (unsup={b.unsupported} mismatch={b.mismatch} err={b.error} ok={b.ok} total={b.total}) "
                f"| e.g. {_format_example_inline(b.primary_example())}"
            )
    else:
        print("  (none)")

    print(f"\nNewly-decoded unsupported forms ({len(newly_decoded_unsupported_forms)}):")
    if newly_decoded_unsupported_forms:
        for b in newly_decoded_unsupported_forms:
            ex = b.examples.get("unsupported") or b.primary_example()
            print(
                f"  - {b.form}: unsupported={b.unsupported} (ok={b.ok} total={b.total}) "
                f"| e.g. {_format_example_inline(ex)}"
            )
    else:
        print("  (none)")

    if args.verbose:
        all_ok_list = sorted(
            [b for b in merged_buckets.values() if b.non_ok == 0],
            key=lambda b: (b.category, -b.ok, b.form),
        )
        print(f"\nAll-ok forms ({len(all_ok_list)}):")
        for b in all_ok_list:
            cat_label = "pre-M2" if b.category == "pre_m2" else "newly-decoded"
            print(f"  - [{cat_label}] {b.form}: ok={b.ok}")

    report_payload: Dict[str, Any] = {
        "schema_version": 1,
        "date": date_str,
        "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus": corpus_name,
        "verdict": verdict,
        "passed": passed,
        "environment": env_meta,
        "baseline": {
            "path": baseline_label,
            "sha256": baseline.sha256,
            "baseline_commit": baseline.baseline_commit,
            "file_count": len(baseline.files),
            "total_unique_inst_words": baseline.total_data_rows,
        },
        "summary": {
            "candidate_files": len(candidates),
            "compared_files": compared_files,
            "failures": len(failures),
            "text_instructions": total_text,
            "decoded_instructions": total_decoded,
            "inst_placeholders": total_inst,
            "inst_placeholders_ok": total_inst_ok,
            "inst_placeholders_not_ok": total_inst_not_ok,
            "pre_m2": pre_m2_summary,
            "newly_decoded": new_summary,
            "totals": {
                "total": total_decoded,
                "ok": total_ok,
                "mismatch": total_mismatch,
                "unsupported": total_unsupported,
                "error": total_error,
            },
            "elapsed_seconds": wall_seconds,
        },
        "forms_with_mismatch_or_error": [b.to_dict() for b in forms_mismatch_or_error],
        "pre_m2_non_ok_forms": [b.to_dict() for b in pre_m2_non_ok_forms],
        "newly_decoded_unsupported_forms": [b.to_dict() for b in newly_decoded_unsupported_forms],
        "inst_placeholder_failures": inst_failure_examples,
        "failures": failures,
        "files": compact_files,
    }

    if args.json_out is not None:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(report_payload, indent=2) + "\n")
        print(f"\nJSON report written to {differential.sanitize_repo_label(args.json_out)}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
