#!/usr/bin/env python3
"""Independent clang verification of MachGraph A64 disassembly and assembly (`asm-clang.py`).

Modes & Usage:
  1. Corpus mode (Acceptance Table Row 12 — independent check of decoded text without MachGraph's assembler):
       Scripts/acceptance/asm-clang.py <quick|standard|file...>
           [--machgraph <path>] [--json-out <path>]

  2. Test-case mode (Acceptance Table Row 13 — line-by-line `machgraph asm` vs `clang` on a `.s` file):
       Scripts/acceptance/asm-clang.py <cases.s>
           [--machgraph <path>] [--json-out <path>]

Exit codes:
  0: Passed (corpus mode: every non-`adrp` form accepted by clang with identical machine word;
             case mode: 0 failing lines).
  1: Verification failure or runtime/process error.
  2: CLI usage error (including `;` in `.s` input or empty `.s` file).
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import datetime
import functools
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import differential  # noqa: E402
from asm_common import (  # noqa: E402
    DisasmRow,
    display_file_label,
    format_instruction_form,
    isolated_env,
    parse_disasm_text_section,
    run_machgraph_disasm,
    split_mnemonic_and_operands,
    static_host_os_info,
)

CLANG_COMPILE_BASE_CMD = [
    "xcrun",
    "clang",
    "-c",
    "-arch",
    "arm64e",
    "-mcpu=apple-m1",
]
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


class _UsageError(Exception):
    """Raised on CLI or `.s` format usage errors (exit code 2)."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(f"{self.prog}: error: {message}")


@dataclass(frozen=True)
class ClangCompileResult:
    ok: bool
    words: List[str]
    error: str = ""


ClangRunner = Callable[[Sequence[str]], ClangCompileResult]


@dataclass(frozen=True)
class CorpusFormSample:
    form: str
    file: str
    addr: int
    word_hex: str
    mnem: str
    original_text: str
    clang_text: Optional[str]


@dataclass(frozen=True)
class CaseStatement:
    line_no: int
    text: str
    form: str


# MARK: - PC-Relative Rewriting & Corpus Form Selection


def rewrite_pc_relative_for_clang(statement: str, addr: int) -> Optional[str]:
    """Rewrite absolute PC-relative targets to `.+<delta>` or `.-<abs_delta>` for `clang -c`.

    Returns `None` when `mnemonic == 'adrp'` (skipped in corpus mode because Mach-O object
    files reject non-GOT `adrp` relocations).
    """
    mnem, operands = split_mnemonic_and_operands(statement)
    if not mnem:
        return statement.strip()
    if mnem == "adrp":
        return None

    target_idx: Optional[int] = None
    if mnem in ("b", "bl") or mnem.startswith("b."):
        if len(operands) == 1:
            target_idx = 0
    elif mnem in ("cbz", "cbnz", "adr"):
        if len(operands) == 2:
            target_idx = 1
    elif mnem in ("tbz", "tbnz"):
        if len(operands) == 3:
            target_idx = 2
    elif mnem in ("ldr", "ldrsw", "prfm"):
        if len(operands) == 2 and not operands[1].lstrip().startswith("["):
            target_idx = 1

    if target_idx is None:
        return statement.strip()

    raw_tok = operands[target_idx].strip()
    if not raw_tok or raw_tok.startswith(".") or raw_tok.startswith("["):
        return statement.strip()

    num_str = raw_tok[1:].strip() if raw_tok.startswith("#") else raw_tok
    try:
        target_addr = int(num_str, 0)
    except ValueError:
        return statement.strip()

    delta = target_addr - addr
    rel_tok = f".+{delta}" if delta >= 0 else f".-{-delta}"
    rewritten_ops = list(operands)
    rewritten_ops[target_idx] = rel_tok
    return f"{mnem} {', '.join(rewritten_ops)}"


def select_first_by_form(
    file_rows: Sequence[Tuple[str, Sequence[DisasmRow]]],
) -> Tuple[List[CorpusFormSample], List[CorpusFormSample]]:
    """Select the first corpus occurrence of every decoded instruction form (skipping `.inst`).

    Returns `(active_samples, adrp_skipped_samples)`.
    """
    seen_forms: Set[str] = set()
    active: List[CorpusFormSample] = []
    adrp_skipped: List[CorpusFormSample] = []

    for file_label, rows in file_rows:
        for row in rows:
            if row.mnem == ".inst":
                continue
            stmt = row.statement
            form = format_instruction_form(stmt)
            if form in seen_forms:
                continue
            seen_forms.add(form)
            clang_text = rewrite_pc_relative_for_clang(stmt, row.addr)
            sample = CorpusFormSample(
                form=form,
                file=file_label,
                addr=row.addr,
                word_hex=row.word_hex,
                mnem=row.mnem,
                original_text=stmt,
                clang_text=clang_text,
            )
            if clang_text is None:
                adrp_skipped.append(sample)
            else:
                active.append(sample)

    return (active, adrp_skipped)


# MARK: - Mach-O Object Reader & Clang Invocation


def read_macho_text_words(obj_path: str) -> List[str]:
    """Read 32-bit little-endian instruction words from `__TEXT,__text` of a 64-bit Mach-O `.o`."""
    with open(obj_path, "rb") as fh:
        data = fh.read()
    if len(data) < 32:
        raise ValueError(f"object file too small ({len(data)} bytes)")

    magic, _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags, _reserved = struct.unpack_from(
        "<IIIIIIII", data, 0
    )
    if magic != MH_MAGIC_64:
        raise ValueError(f"unexpected Mach-O magic 0x{magic:08x} (expected 0x{MH_MAGIC_64:08x})")

    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise ValueError("truncated Mach-O load command header")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            raise ValueError("invalid Mach-O load command size")
        if cmd == LC_SEGMENT_64:
            if off + 72 > len(data):
                raise ValueError("truncated LC_SEGMENT_64 command")
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            sect_off = off + 72
            for _ in range(nsects):
                if sect_off + 80 > off + cmdsize:
                    raise ValueError("truncated section_64 header")
                sectname = data[sect_off : sect_off + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
                segname = data[sect_off + 16 : sect_off + 32].split(b"\x00", 1)[0].decode("ascii", "replace")
                _addr, size, fileoff = struct.unpack_from("<QQI", data, sect_off + 32)
                if (segname, sectname) == ("__TEXT", "__text"):
                    if size % 4 != 0:
                        raise ValueError(f"__TEXT,__text size {size} is not a multiple of 4")
                    if fileoff + size > len(data):
                        raise ValueError("__TEXT,__text extends past end of object file")
                    raw = data[fileoff : fileoff + size]
                    return [f"{w:08x}" for (w,) in struct.iter_unpack("<I", raw)]
                sect_off += 80
        off += cmdsize

    return []


def clean_clang_stderr(stderr_text: str, temp_paths: Sequence[str] = ()) -> str:
    """Extract clang's primary error diagnostic while scrubbing local filesystem paths."""
    for raw_line in stderr_text.splitlines():
        if ": error: " in raw_line:
            msg = raw_line.split(": error: ", 1)[1].strip()
            if msg:
                return msg

    real_home = os.path.expanduser("~")
    for raw_line in stderr_text.splitlines():
        s = raw_line.strip()
        if not s:
            continue
        for tp in temp_paths:
            if tp:
                s = s.replace(tp, "<tmp>")
        if real_home and real_home != "/":
            s = s.replace(real_home, "~")
        return s[:240]
    return "clang exited with non-zero status"


def compile_lines_with_clang(lines: Sequence[str], isolated_home: str) -> ClangCompileResult:
    """Assemble `lines` into a temporary arm64e `.o` via `xcrun clang` and read `__TEXT,__text`."""
    if not lines:
        return ClangCompileResult(ok=True, words=[], error="")

    env = isolated_env(isolated_home)
    with tempfile.TemporaryDirectory(prefix="mg-clang-") as tmpdir:
        s_path = os.path.join(tmpdir, "snippet.s")
        o_path = os.path.join(tmpdir, "snippet.o")
        asm_src = ".text\n.globl _main\n_main:\n" + "".join(f"  {ln}\n" for ln in lines)
        with open(s_path, "w", encoding="utf-8") as fh:
            fh.write(asm_src)

        cmd = list(CLANG_COMPILE_BASE_CMD) + [s_path, "-o", o_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=180.0,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return ClangCompileResult(ok=False, words=[], error="xcrun clang timed out after 180s")

        if proc.returncode != 0:
            stderr_txt = proc.stderr.decode("utf-8", errors="replace")
            return ClangCompileResult(
                ok=False,
                words=[],
                error=clean_clang_stderr(stderr_txt, [tmpdir, os.path.realpath(tmpdir)]),
            )

        try:
            words = read_macho_text_words(o_path)
        except Exception as exc:
            return ClangCompileResult(ok=False, words=[], error=f"failed to read Mach-O __TEXT,__text: {exc}")

        if len(words) != len(lines):
            return ClangCompileResult(
                ok=False,
                words=words,
                error=f"expected {len(lines)} words in __TEXT,__text, got {len(words)}",
            )
        return ClangCompileResult(ok=True, words=words, error="")


@functools.lru_cache(maxsize=1)
def _query_llvm_version() -> str:
    r = subprocess.run(
        ["xcrun", "clang", "--version"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    txt = r.stdout.decode("utf-8", errors="replace").strip()
    if not txt:
        return "unknown"
    return txt.splitlines()[0].strip()


def collect_environment_metadata(machgraph_bin: str, llvm_version: Optional[str] = None) -> Dict[str, Any]:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=REPO_ROOT,
    )
    commit_sha = r.stdout.decode("utf-8", errors="replace").strip() or "unknown"
    os_info = static_host_os_info()
    return {
        "macos_product_name": os_info["macos_product_name"],
        "macos_version": os_info["macos_version"],
        "macos_build": os_info["macos_build"],
        "machine": os_info["machine"],
        "llvm_version": llvm_version if llvm_version is not None else _query_llvm_version(),
        "machgraph_commit": commit_sha,
        "worktree_clean": differential.is_worktree_clean(),
        "machgraph_binary": differential.sanitize_repo_label(machgraph_bin),
    }


def _write_json_report(json_out: str, payload: Dict[str, Any]) -> None:
    out_dir = os.path.dirname(os.path.abspath(json_out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(json_out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")


# MARK: - Corpus Mode (Acceptance Row 12)


def evaluate_corpus_samples_with_clang(
    active_samples: Sequence[CorpusFormSample],
    clang_runner: ClangRunner,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    """Compile all non-`adrp` form representatives with clang; isolate rejected lines if batch fails."""
    matched: List[Dict[str, Any]] = []
    mismatched: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    if not active_samples:
        return (matched, mismatched, rejected, None)

    batch_lines = [s.clang_text or s.original_text for s in active_samples]
    batch_res = clang_runner(batch_lines)

    survivors: List[CorpusFormSample]
    survivor_words: List[str]

    if batch_res.ok and len(batch_res.words) == len(active_samples):
        survivors = list(active_samples)
        survivor_words = batch_res.words
    else:
        # Isolate rejected lines one by one, remove them, and re-compile surviving lines as a batch.
        survivors = []
        for s in active_samples:
            line_txt = s.clang_text or s.original_text
            single_res = clang_runner([line_txt])
            if not single_res.ok or len(single_res.words) != 1:
                rejected.append(
                    {
                        "form": s.form,
                        "file": s.file,
                        "address": hex(s.addr),
                        "word": s.word_hex,
                        "text": s.original_text,
                        "clang_text": line_txt,
                        "clang_error": single_res.error or "failed to assemble single line",
                    }
                )
            else:
                survivors.append(s)

        if survivors:
            rebatch_lines = [s.clang_text or s.original_text for s in survivors]
            rebatch_res = clang_runner(rebatch_lines)
            if not rebatch_res.ok or len(rebatch_res.words) != len(survivors):
                return (
                    matched,
                    mismatched,
                    rejected,
                    f"clang batch compilation failed even after removing {len(rejected)} rejected line(s): "
                    f"{rebatch_res.error}",
                )
            survivor_words = rebatch_res.words
        else:
            survivor_words = []

    for s, clang_word in zip(survivors, survivor_words):
        rec = {
            "form": s.form,
            "file": s.file,
            "address": hex(s.addr),
            "word": s.word_hex,
            "text": s.original_text,
            "clang_text": s.clang_text or s.original_text,
            "clang_word": clang_word.lower(),
        }
        if clang_word.lower() == s.word_hex.lower():
            matched.append(rec)
        else:
            mismatched.append(rec)

    return (matched, mismatched, rejected, None)


def run_corpus_mode(
    raw_targets: List[str],
    machgraph_bin: str,
    json_out: Optional[str],
    clang_runner: Optional[ClangRunner],
    llvm_version: Optional[str],
) -> int:
    corpus_name, candidates = differential.resolve_targets(raw_targets)
    if not candidates:
        print(f"[FAIL] No candidate binaries found for '{corpus_name}'", file=sys.stderr)
        return 1

    t_start = time.monotonic()
    env_meta = collect_environment_metadata(machgraph_bin, llvm_version=llvm_version)

    print(f"=== MachGraph Disassembly vs Clang Verification ({corpus_name}) ===")
    print(f"Date (UTC):   {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    print(f"LLVM/Clang:   {env_meta['llvm_version']}")
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print()

    file_summaries: List[Dict[str, Any]] = []
    collected_file_rows: List[Tuple[str, List[DisasmRow]]] = []
    file_failures = 0

    with tempfile.TemporaryDirectory(prefix="machgraph-asm-clang-home-") as isolated_home:
        effective_clang: ClangRunner = (
            clang_runner
            if clang_runner is not None
            else (lambda lines: compile_lines_with_clang(lines, isolated_home))
        )

        for path in candidates:
            disp = display_file_label(path)
            if not os.path.isfile(path):
                file_failures += 1
                msg = "target binary not found"
                print(f"[FAIL] {disp}: {msg}")
                file_summaries.append({"path": disp, "failure": msg})
                continue

            arch = differential.select_arm64_slice(path)
            if arch is None:
                if corpus_name == "full":
                    file_summaries.append({"path": disp, "skipped": "no arm64 slice"})
                    continue
                file_failures += 1
                msg = "no arm64/arm64e slice found"
                print(f"[FAIL] {disp}: {msg}")
                file_summaries.append({"path": disp, "failure": msg})
                continue

            rows, dis_err, dis_sec = run_machgraph_disasm(machgraph_bin, path, isolated_home)
            if dis_err is not None or rows is None:
                file_failures += 1
                msg = dis_err or "machgraph disasm failed"
                print(f"[FAIL] {disp} ({arch}): {msg} ({dis_sec:.2f}s)")
                file_summaries.append({"path": disp, "arch": arch, "failure": msg, "seconds": dis_sec})
                continue

            decoded_count = sum(1 for r in rows if r.mnem != ".inst")
            inst_count = len(rows) - decoded_count
            collected_file_rows.append((disp, rows))
            file_summaries.append(
                {
                    "path": disp,
                    "arch": arch,
                    "text_rows": len(rows),
                    "decoded_rows": decoded_count,
                    "inst_rows": inst_count,
                    "seconds": dis_sec,
                }
            )
            print(
                f"[DISASM] {disp} ({arch}): text={len(rows)} decoded={decoded_count} "
                f"inst_skip={inst_count} ({dis_sec:.2f}s)"
            )

        active_samples, adrp_skipped_samples = select_first_by_form(collected_file_rows)
        t_clang0 = time.monotonic()
        matched, mismatched, clang_rejected, batch_error = evaluate_corpus_samples_with_clang(
            active_samples, effective_clang
        )
        clang_sec = round(time.monotonic() - t_clang0, 3)

    total_forms = len(active_samples) + len(adrp_skipped_samples)
    adrp_skipped_count = len(adrp_skipped_samples)
    compared_forms = len(active_samples)
    matched_count = len(matched)
    mismatched_count = len(mismatched)
    rejected_count = len(clang_rejected)
    elapsed_total = round(time.monotonic() - t_start, 3)

    passed = (
        file_failures == 0
        and batch_error is None
        and total_forms > 0
        and matched_count == compared_forms
        and mismatched_count == 0
        and rejected_count == 0
    )
    verdict = "PASS" if passed else "FAIL"

    print()
    print(
        f"[{verdict}] Summary ({corpus_name}): files_compared={len(collected_file_rows)} "
        f"file_failures={file_failures} total_forms={total_forms} adrp_skipped={adrp_skipped_count} "
        f"compared={compared_forms} matched={matched_count} mismatched={mismatched_count} "
        f"clang_rejected={rejected_count} clang_elapsed={clang_sec:.2f}s total_elapsed={elapsed_total:.2f}s"
    )
    if batch_error is not None:
        print(f"       batch_error: {batch_error}")

    print()
    print(f"Mismatched forms ({mismatched_count}):")
    if mismatched:
        for item in mismatched:
            print(
                f"  - {item['form']}: machgraph_word={item['word']} clang_word={item['clang_word']} "
                f"| text='{item['text']}' (clang='{item['clang_text']}') @ {item['file']} {item['address']}"
            )
    else:
        print("  (none)")

    print()
    print(f"Clang-rejected forms ({rejected_count}):")
    if clang_rejected:
        for item in clang_rejected:
            print(
                f"  - {item['form']}: text='{item['text']}' (clang='{item['clang_text']}') "
                f"| clang_error='{item['clang_error']}' @ {item['file']} {item['address']}"
            )
    else:
        print("  (none)")

    if json_out is not None:
        report: Dict[str, Any] = {
            "mode": "corpus",
            "corpus": corpus_name,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verdict": verdict,
            "passed": passed,
            "clang_command": " ".join(CLANG_COMPILE_BASE_CMD),
            "environment": env_meta,
            "summary": {
                "files_compared": len(collected_file_rows),
                "file_failures": file_failures,
                "total_forms": total_forms,
                "adrp_skipped": adrp_skipped_count,
                "compared_forms": compared_forms,
                "matched": matched_count,
                "mismatched": mismatched_count,
                "clang_rejected": rejected_count,
                "clang_seconds": clang_sec,
                "elapsed_seconds": elapsed_total,
            },
            "batch_error": batch_error,
            "adrp_skipped_forms": [
                {
                    "form": s.form,
                    "file": s.file,
                    "address": hex(s.addr),
                    "word": s.word_hex,
                    "text": s.original_text,
                }
                for s in adrp_skipped_samples
            ],
            "mismatched": mismatched,
            "clang_rejected": clang_rejected,
            "matched": matched,
            "files": file_summaries,
        }
        _write_json_report(json_out, report)
        print()
        print(f"JSON report written to {display_file_label(json_out)}")

    return 0 if passed else 1


# MARK: - Test-Case `.s` Mode (Acceptance Row 13)


def parse_cases_file(s_path: str) -> List[CaseStatement]:
    """Parse a `.s` cases file (skipping blank and `//` comment lines; forbidding `;`)."""
    with open(s_path, "r", encoding="utf-8") as fh:
        raw_text = fh.read()

    if ";" in raw_text:
        for idx, raw_ln in enumerate(raw_text.splitlines(), start=1):
            if ";" in raw_ln:
                raise _UsageError(
                    f"asm-clang.py: error: ';' found at {display_file_label(s_path)}:{idx} "
                    f"(';' is a comment in Darwin clang but a statement separator in MachGraph)"
                )

    cases: List[CaseStatement] = []
    for idx, raw_ln in enumerate(raw_text.splitlines(), start=1):
        stripped = raw_ln.strip()
        if not stripped or stripped.startswith("//"):
            continue
        cases.append(CaseStatement(line_no=idx, text=stripped, form=format_instruction_form(stripped)))

    if not cases:
        raise _UsageError(f"asm-clang.py: error: no assembly statements found in {display_file_label(s_path)}")

    return cases


def run_cases_mode(
    cases_path: str,
    machgraph_bin: str,
    json_out: Optional[str],
    clang_runner: Optional[ClangRunner],
    llvm_version: Optional[str],
) -> int:
    disp_cases = display_file_label(cases_path)
    if not os.path.isfile(cases_path):
        print(f"[FAIL] Cases file not found: {disp_cases}", file=sys.stderr)
        return 1

    cases = parse_cases_file(cases_path)
    t_start = time.monotonic()
    env_meta = collect_environment_metadata(machgraph_bin, llvm_version=llvm_version)

    print(f"=== MachGraph vs Clang Case-by-Case Verification ({disp_cases}) ===")
    print(f"Date (UTC):   {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    print(f"LLVM/Clang:   {env_meta['llvm_version']}")
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print()

    with tempfile.TemporaryDirectory(prefix="machgraph-asm-cases-home-") as isolated_home:
        env = isolated_env(isolated_home)
        stdin_bytes = ("\n".join(c.text for c in cases) + "\n").encode("utf-8")
        try:
            mg_proc = subprocess.run(
                [machgraph_bin, "asm", "--at", "0", "--json"],
                input=stdin_bytes,
                capture_output=True,
                timeout=120.0,
                env=env,
            )
        except OSError as exc:
            print(f"[FAIL] Failed to execute machgraph binary '{env_meta['machgraph_binary']}': {exc}", file=sys.stderr)
            return 1
        except subprocess.TimeoutExpired:
            print("[FAIL] machgraph asm timed out after 120s", file=sys.stderr)
            return 1

        if mg_proc.returncode not in (0, 1, 3):
            err_snip = mg_proc.stderr.decode("utf-8", errors="replace").strip()[:240]
            print(f"[FAIL] machgraph asm exited {mg_proc.returncode}: {err_snip}", file=sys.stderr)
            return 1

        try:
            mg_doc = json.loads(mg_proc.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            print(f"[FAIL] machgraph asm produced invalid JSON: {exc}", file=sys.stderr)
            return 1

        mg_results = mg_doc.get("results") if isinstance(mg_doc, dict) else None
        if not isinstance(mg_results, list) or len(mg_results) != len(cases):
            got_len = len(mg_results) if isinstance(mg_results, list) else "non-list"
            print(
                f"[FAIL] machgraph asm result count mismatch: expected {len(cases)}, got {got_len}",
                file=sys.stderr,
            )
            return 1

        for idx, r in enumerate(mg_results):
            try:
                got_addr = int(str(r.get("address", "")), 16)
            except ValueError:
                got_addr = -1
            if got_addr != 4 * idx:
                print(
                    f"[FAIL] machgraph asm address mismatch at index {idx}: "
                    f"expected {hex(4 * idx)}, got {r.get('address')!r}",
                    file=sys.stderr,
                )
                return 1

        if clang_runner is not None:
            clang_results = [clang_runner([c.text]) for c in cases]
        else:
            with ThreadPoolExecutor(max_workers=4) as pool:
                clang_results = list(
                    pool.map(lambda c: compile_lines_with_clang([c.text], isolated_home), cases)
                )

    rows_out: List[Dict[str, Any]] = []
    counts = {
        "total": len(cases),
        "match": 0,
        "unsupported": 0,
        "clang_unverifiable": 0,
        "both_rejected": 0,
        "mismatch": 0,
        "mg_error_clang_ok": 0,
        "failures": 0,
    }

    for idx, (case, mg_r, cl_r) in enumerate(zip(cases, mg_results, clang_results)):
        mg_status = str(mg_r.get("status", ""))
        mg_word = str(mg_r["word"]).lower() if mg_r.get("word") is not None else None
        mg_form = mg_r.get("form")
        mg_reason = mg_r.get("reason")
        cl_ok = cl_r.ok and len(cl_r.words) == 1
        cl_word = cl_r.words[0].lower() if cl_ok else None
        cl_err = None if cl_ok else (cl_r.error or "clang rejected statement")

        if mg_status == "ok":
            if cl_ok:
                if mg_word == cl_word:
                    verdict_row = "match"
                    counts["match"] += 1
                else:
                    verdict_row = "mismatch"
                    counts["mismatch"] += 1
                    counts["failures"] += 1
            else:
                verdict_row = "clang_unverifiable"
                counts["clang_unverifiable"] += 1
        elif mg_status == "unsupported":
            verdict_row = "unsupported"
            counts["unsupported"] += 1
        elif mg_status == "error":
            if cl_ok:
                verdict_row = "mg_error_clang_ok"
                counts["mg_error_clang_ok"] += 1
                counts["failures"] += 1
            else:
                verdict_row = "both_rejected"
                counts["both_rejected"] += 1
        else:
            verdict_row = "mg_error_clang_ok"
            counts["mg_error_clang_ok"] += 1
            counts["failures"] += 1

        rows_out.append(
            {
                "index": idx,
                "line": case.line_no,
                "address": hex(4 * idx),
                "text": case.text,
                "form": mg_form or case.form,
                "machgraph_status": mg_status,
                "machgraph_word": mg_word,
                "machgraph_reason": mg_reason,
                "clang_ok": cl_ok,
                "clang_word": cl_word,
                "clang_error": cl_err,
                "verdict": verdict_row,
            }
        )

    elapsed_total = round(time.monotonic() - t_start, 3)
    passed = counts["failures"] == 0
    overall_verdict = "PASS" if passed else "FAIL"

    print(
        f"[{overall_verdict}] Summary ({disp_cases}): total={counts['total']} "
        f"match={counts['match']} unsupported={counts['unsupported']} "
        f"clang_unverifiable={counts['clang_unverifiable']} both_rejected={counts['both_rejected']} "
        f"failures={counts['failures']} (mismatch={counts['mismatch']} "
        f"mg_error_clang_ok={counts['mg_error_clang_ok']}) elapsed={elapsed_total:.2f}s"
    )

    failing_rows = [r for r in rows_out if r["verdict"] in ("mismatch", "mg_error_clang_ok")]
    print()
    print(f"Failing lines ({len(failing_rows)}):")
    if failing_rows:
        for r in failing_rows:
            if r["verdict"] == "mismatch":
                print(
                    f"  - line {r['line']} ({r['address']}): '{r['text']}' -> "
                    f"machgraph={r['machgraph_word']} != clang={r['clang_word']}"
                )
            else:
                print(
                    f"  - line {r['line']} ({r['address']}): '{r['text']}' -> "
                    f"machgraph=error ({r['machgraph_reason']}) while clang={r['clang_word']}"
                )
    else:
        print("  (none)")

    unverifiable_rows = [r for r in rows_out if r["verdict"] == "clang_unverifiable"]
    print()
    print(f"Clang unverifiable lines (clang 无法对照) ({len(unverifiable_rows)}):")
    if unverifiable_rows:
        for r in unverifiable_rows:
            print(
                f"  - line {r['line']} ({r['address']}): '{r['text']}' -> "
                f"machgraph=ok ({r['machgraph_word']}) | clang rejected: \"{r['clang_error']}\""
            )
    else:
        print("  (none)")

    unsupported_rows = [r for r in rows_out if r["verdict"] == "unsupported"]
    print()
    print(f"MachGraph unsupported lines ({len(unsupported_rows)}):")
    if unsupported_rows:
        for r in unsupported_rows:
            cl_desc = f"clang={r['clang_word']}" if r["clang_ok"] else f"clang_rejected=\"{r['clang_error']}\""
            print(
                f"  - line {r['line']} ({r['address']}): '{r['text']}' "
                f"(form='{r['form']}') | {cl_desc}"
            )
    else:
        print("  (none)")

    both_rejected_rows = [r for r in rows_out if r["verdict"] == "both_rejected"]
    if both_rejected_rows:
        print()
        print(f"Both rejected lines (两边都拒收) ({len(both_rejected_rows)}):")
        for r in both_rejected_rows:
            print(
                f"  - line {r['line']} ({r['address']}): '{r['text']}' -> "
                f"machgraph='{r['machgraph_reason']}' | clang=\"{r['clang_error']}\""
            )

    if json_out is not None:
        report = {
            "mode": "cases",
            "cases_file": disp_cases,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verdict": overall_verdict,
            "passed": passed,
            "clang_command": " ".join(CLANG_COMPILE_BASE_CMD),
            "environment": env_meta,
            "summary": dict(counts, elapsed_seconds=elapsed_total),
            "results": rows_out,
        }
        _write_json_report(json_out, report)
        print()
        print(f"JSON report written to {display_file_label(json_out)}")

    return 0 if passed else 1


# MARK: - CLI Entrypoint


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="asm-clang.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="'quick', 'standard', binary path(s), or a single '<cases.s>' file",
    )
    parser.add_argument(
        "--machgraph",
        default=differential.default_machgraph_bin(),
        help="path to MachGraph CLI executable",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="write structured JSON report to this path",
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    clang_runner: Optional[ClangRunner] = None,
    llvm_version: Optional[str] = None,
) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        s_targets = [t for t in args.targets if t.lower().endswith(".s")]
        if s_targets:
            if len(args.targets) != 1:
                raise _UsageError(
                    "asm-clang.py: error: '.s' case mode accepts exactly one '.s' file and cannot be mixed with other targets"
                )
            return run_cases_mode(
                cases_path=args.targets[0],
                machgraph_bin=args.machgraph,
                json_out=args.json_out,
                clang_runner=clang_runner,
                llvm_version=llvm_version,
            )
    except _UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return run_corpus_mode(
        raw_targets=args.targets,
        machgraph_bin=args.machgraph,
        json_out=args.json_out,
        clang_runner=clang_runner,
        llvm_version=llvm_version,
    )


if __name__ == "__main__":
    raise SystemExit(main())
