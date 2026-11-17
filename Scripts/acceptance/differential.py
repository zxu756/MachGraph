#!/usr/bin/env python3
"""Differential ARM64 disassembly check (`machgraph disasm` vs `llvm-objdump`).

Usage:
  Scripts/acceptance/differential.py <quick|standard|full|file...>
      [--machgraph <path>] [--json-out <path>] [--record] [--workers <n>] [--verbose]

Reference command (fixed by `02-machgraph.md`, M1 item 1 / G32 / G42 / D-M2-1):
  xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>

Normalization rules:
  - Mnemonics: imported from `mnemonic_normalization.py` (0 normalization rules
    as of M2 Stage 6; generic Neon syntax is enforced on reference output).
  - Operands: imported from `operand_normalization.py` (rules O1-O4 only,
    evaluated on every mnemonic-agreed instruction without affecting mnemonic
    counts or pass/fail exit status).

Exit status:
  0 when crashes/failures == 0, missing_addresses == 0, and wrong_instructions == 0
    (and `standard` unknown counts do not exceed the M1 baseline ceilings);
  1 otherwise.
"""

import argparse
import collections
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    verify_reference_generic_neon_syntax,
)
from operand_normalization import (  # noqa: E402
    OPERAND_NORMALIZATION_RULES,
    OPERAND_NORMALIZATION_SUMMARY,
    operand_shape_for_category,
    operands_equal,
)

QUICK_FILES = ["/bin/ls"]
STANDARD_FILES = ["/bin/ls", "/usr/bin/ssh", "/usr/bin/vim"]
STANDARD_UNKNOWN_CEILINGS = {
    "/bin/ls": 1,
    "/usr/bin/ssh": 1596,
    "/usr/bin/vim": 142,
}
FULL_SCAN_ROOTS = ["/bin", "/usr/bin", "/usr/sbin", "/usr/libexec"]
MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"\xbe\xba\xfe\xca",
    b"\xbf\xba\xfe\xca",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
}

PER_FILE_TIMEOUT_SECONDS = 60
PER_MIB_TIMEOUT_SECONDS = 5.0
MAX_PER_FILE_TIMEOUT_SECONDS = 900.0
MAX_OPERAND_EXAMPLES_PER_CATEGORY = 5
MAX_PRINTED_OPERAND_CATEGORIES = 10
_REF_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")
_NUMBER_SHAPE_RE = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)")


def per_file_timeout_seconds(path: str) -> float:
    """Hang-detection timeout scaled by file size (G39; not a performance gate)."""
    try:
        size_bytes = os.stat(path).st_size
    except OSError:
        return float(PER_FILE_TIMEOUT_SECONDS)
    size_mib = max(0.0, size_bytes / (1024.0 * 1024.0))
    scaled = float(PER_FILE_TIMEOUT_SECONDS) + size_mib * PER_MIB_TIMEOUT_SECONDS
    return min(MAX_PER_FILE_TIMEOUT_SECONDS, max(float(PER_FILE_TIMEOUT_SECONDS), round(scaled, 1)))


def run_with_solo_retry(
    candidates: List[str],
    worker_count: int,
    fn: Callable[[str], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Run `fn` across `candidates`; if any file times out in parallel mode, retry it solo once (G39)."""
    if worker_count <= 1:
        return [fn(p) for p in candidates]
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        rows = list(pool.map(fn, candidates))
    for idx, row in enumerate(rows):
        if row.get("timed_out"):
            path = candidates[idx]
            print(f"[RETRY] {path} timed out during parallel run; retrying solo...", file=sys.stderr)
            retry_row = dict(fn(path))
            retry_row["retried_after_timeout"] = True
            rows[idx] = retry_row
    return rows


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


def discover_full_candidates() -> List[str]:
    seen_inodes = set()
    found: List[str] = []
    for root in FULL_SCAN_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                try:
                    st = os.stat(path)
                    inode_key = (st.st_dev, st.st_ino)
                    if inode_key in seen_inodes:
                        continue
                    seen_inodes.add(inode_key)
                    with open(path, "rb") as fh:
                        magic = fh.read(4)
                except OSError:
                    continue
                if magic in MACHO_MAGICS:
                    found.append(path)
    found.sort()
    return found


def select_arm64_slice(path: str) -> Optional[str]:
    res = subprocess.run(
        ["lipo", "-archs", path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
    )
    if res.returncode != 0:
        return None
    archs = res.stdout.decode("utf-8", errors="replace").split()
    if "arm64e" in archs:
        return "arm64e"
    if "arm64" in archs:
        return "arm64"
    return None


def operand_shape(operands: str) -> str:
    core = operands.split(";")[0].strip()
    return _NUMBER_SHAPE_RE.sub("N", core)


def compare_one_binary(path: str, machgraph_bin: str, isolated_home: str) -> Dict[str, Any]:
    arch = select_arm64_slice(path)
    if arch is None:
        return {"path": path, "skipped": "no arm64 slice"}

    mg_timeout = per_file_timeout_seconds(path)
    ref_timeout = max(300.0, mg_timeout)
    ref_cmd = build_reference_command(path, arch)
    try:
        ref_proc = subprocess.run(
            ref_cmd,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=ref_timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "path": path,
            "arch": arch,
            "failure": f"llvm-objdump timed out after {ref_timeout:.0f}s",
            "exit_code": -1,
            "timed_out": True,
        }

    ref_text = ref_proc.stdout.decode("utf-8", errors="replace")
    non_utf8_ref = "\ufffd" in ref_text
    if ref_proc.returncode != 0:
        err_snip = ref_proc.stderr.decode("utf-8", errors="replace").strip()[:240]
        return {
            "path": path,
            "arch": arch,
            "failure": f"llvm-objdump exited {ref_proc.returncode}: {err_snip}",
            "exit_code": ref_proc.returncode,
            "timed_out": False,
        }

    ref_map: Dict[int, Tuple[str, str, str]] = {}
    for line in ref_text.splitlines():
        if line.strip() == "Contents of (__TEXT,__text) section":
            break
        m = _REF_INSN_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            raw_mnem = m.group(2).lower()
            raw_full_ops = (m.group(3) or "").strip()
            raw_ops = raw_full_ops.split(";", 1)[0].strip()
            ref_map[addr] = (raw_mnem, raw_ops, raw_full_ops)

    bad_neon = find_non_generic_neon_mnemonic((addr, mnem) for addr, (mnem, _ops, _full_ops) in ref_map.items())
    if bad_neon is not None:
        bad_addr, bad_mnem = bad_neon
        return {
            "path": path,
            "arch": arch,
            "total": len(ref_map),
            "seconds": 0.0,
            "failure": (
                f"non-generic Neon syntax in reference output: saw arrangement-suffixed mnemonic "
                f"'{bad_mnem}' at {hex(bad_addr)}"
            ),
            "exit_code": 1,
            "timed_out": False,
        }

    env = dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )
    t0 = time.monotonic()
    try:
        mg_proc = subprocess.run(
            [machgraph_bin, "disasm", path],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=mg_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - t0, 3)
        return {
            "path": path,
            "arch": arch,
            "total": len(ref_map),
            "seconds": elapsed,
            "failure": f"machgraph timed out after {mg_timeout:.0f}s",
            "exit_code": 124,
            "timed_out": True,
        }
    elapsed = round(time.monotonic() - t0, 3)

    mg_stdout = mg_proc.stdout.decode("utf-8", errors="replace")
    mg_stderr = mg_proc.stderr.decode("utf-8", errors="replace")
    non_utf8_mg = "\ufffd" in mg_stdout

    if mg_proc.returncode != 0:
        # Convert negative Python signal codes (-N) to shell convention (128 + N) for clarity alongside raw code
        rc = mg_proc.returncode
        err_line = mg_stderr.strip().splitlines()[0] if mg_stderr.strip() else ""
        return {
            "path": path,
            "arch": arch,
            "total": len(ref_map),
            "seconds": elapsed,
            "failure": f"machgraph exit {rc}: {err_line[:240]}",
            "exit_code": rc,
            "timed_out": False,
        }

    mine_text: Dict[int, Tuple[str, str, str]] = {}
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
            raw_hex = parts[1].strip().lower()
            mnem = parts[2].strip().lower()
            ops = parts[3].strip() if len(parts) > 3 else ""
            mine_text[addr] = (raw_hex, mnem, ops)

    if len(ref_map) == 0 and len(mine_text) > 0:
        return {
            "path": path,
            "arch": arch,
            "total": 0,
            "machgraph_total": len(mine_text),
            "seconds": elapsed,
            "failure": (
                f"empty reference listing: llvm-objdump decoded 0 instructions in __TEXT,__text "
                f"while machgraph decoded {len(mine_text)}"
            ),
            "exit_code": 1,
            "timed_out": False,
            "empty_reference": True,
        }

    agree = 0
    operand_compared = 0
    operand_equal = 0
    ref_long_mg_inst = 0
    missing = 0
    missing_examples: List[Dict[str, str]] = []
    unknown_counter: collections.Counter = collections.Counter()
    wrong_pair_counter: collections.Counter = collections.Counter()
    wrong_pair_examples: Dict[Tuple[str, str], Dict[str, str]] = {}
    wrong_shape_counter: collections.Counter = collections.Counter()
    wrong_shape_examples: Dict[str, Dict[str, str]] = {}
    operand_diff_counter: collections.Counter = collections.Counter()
    operand_diff_examples: Dict[str, List[Dict[str, str]]] = {}

    for addr, (raw_ref_mnem, raw_ref_ops, raw_ref_full_ops) in ref_map.items():
        got = mine_text.get(addr)
        if got is None:
            missing += 1
            if len(missing_examples) < 5:
                missing_examples.append(
                    {
                        "file": path,
                        "address": hex(addr),
                        "llvm": f"{raw_ref_mnem} {raw_ref_ops}".strip(),
                    }
                )
            continue
        raw_word_hex, mg_mnem, mg_ops = got
        kind, norm_ref, norm_mg = classify_mnemonic_pair(raw_ref_mnem, mg_mnem)
        if kind == "agree":
            agree += 1
            operand_compared += 1
            if operands_equal(norm_ref, raw_ref_full_ops, mg_ops, address=addr):
                operand_equal += 1
            else:
                ref_sh = operand_shape_for_category(raw_ref_ops)
                mg_sh = operand_shape_for_category(mg_ops)
                cat_key = f"{norm_ref}|{norm_mg}|{ref_sh}|{mg_sh}"
                operand_diff_counter[cat_key] += 1
                ex_list = operand_diff_examples.setdefault(cat_key, [])
                if len(ex_list) < MAX_OPERAND_EXAMPLES_PER_CATEGORY:
                    ref_disp_ops = (
                        raw_ref_full_ops
                        if (norm_ref == "adrp" and ";" in raw_ref_full_ops)
                        else raw_ref_ops
                    )
                    ex_list.append(
                        {
                            "file": path,
                            "address": hex(addr),
                            "word": raw_word_hex,
                            "llvm": f"{raw_ref_mnem} {ref_disp_ops}".strip(),
                            "machgraph": f"{mg_mnem} {mg_ops}".strip(),
                        }
                    )
        elif kind == "reference_long_machgraph_inst":
            ref_long_mg_inst += 1
        elif kind == "unknown":
            unknown_counter[norm_ref] += 1
        else:
            pair_key = (norm_ref, norm_mg)
            wrong_pair_counter[pair_key] += 1
            sample = {
                "file": path,
                "address": hex(addr),
                "word": raw_word_hex,
                "llvm": f"{raw_ref_mnem} {raw_ref_ops}".strip(),
                "machgraph": f"{mg_mnem} {mg_ops}".strip(),
            }
            wrong_pair_examples.setdefault(pair_key, sample)
            s_key = f"{raw_ref_mnem}|{norm_mg}|{operand_shape(raw_ref_ops)}"
            wrong_shape_counter[s_key] += 1
            wrong_shape_examples.setdefault(s_key, sample)

    # Reverse direction (G33): addresses present in MachGraph __TEXT,__text but omitted by llvm-objdump
    machgraph_only_inst = 0
    machgraph_only_wrong = 0
    for addr in sorted(mine_text.keys()):
        if addr in ref_map:
            continue
        raw_word_hex, mg_mnem, mg_ops = mine_text[addr]
        if mg_mnem == ".inst":
            machgraph_only_inst += 1
        else:
            machgraph_only_wrong += 1
            pair_key = ("<omitted>", mg_mnem)
            wrong_pair_counter[pair_key] += 1
            sample = {
                "file": path,
                "address": hex(addr),
                "word": raw_word_hex,
                "llvm": "<omitted>",
                "machgraph": f"{mg_mnem} {mg_ops}".strip(),
            }
            wrong_pair_examples.setdefault(pair_key, sample)
            s_key = f"<omitted>|{mg_mnem}|"
            wrong_shape_counter[s_key] += 1
            wrong_shape_examples.setdefault(s_key, sample)

    return {
        "path": path,
        "arch": arch,
        "total": len(ref_map),
        "agree": agree,
        "operand_compared": operand_compared,
        "operand_equal": operand_equal,
        "operand_mismatch": operand_compared - operand_equal,
        "unknown_total": sum(unknown_counter.values()),
        "reference_long_machgraph_inst": ref_long_mg_inst,
        "wrong_total": sum(wrong_pair_counter.values()),
        "missing": missing,
        "machgraph_only_inst": machgraph_only_inst,
        "machgraph_only_wrong": machgraph_only_wrong,
        "missing_examples": missing_examples,
        "unknown": dict(unknown_counter),
        "wrong_pairs": {f"{k[0]}|{k[1]}": v for k, v in wrong_pair_counter.items()},
        "wrong_pair_examples": {f"{k[0]}|{k[1]}": v for k, v in wrong_pair_examples.items()},
        "wrong_shapes": dict(wrong_shape_counter),
        "wrong_shape_examples": wrong_shape_examples,
        "operand_diffs": dict(operand_diff_counter),
        "operand_diff_examples": operand_diff_examples,
        "non_utf8_reference": non_utf8_ref,
        "non_utf8_machgraph": non_utf8_mg,
        "exit_code": 0,
        "seconds": elapsed,
    }


def is_worktree_clean(repo_root: Optional[str] = None) -> bool:
    root = repo_root if repo_root is not None else REPO_ROOT
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=root,
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


def resolve_targets(raw_targets: List[str]) -> Tuple[str, List[str]]:
    if len(raw_targets) == 1:
        tier = raw_targets[0]
        if tier == "quick":
            return ("quick", list(QUICK_FILES))
        if tier == "standard":
            return ("standard", list(STANDARD_FILES))
        if tier == "full":
            return ("full", discover_full_candidates())
    return ("custom", [os.path.abspath(p) if not os.path.isabs(p) else p for p in raw_targets])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("targets", nargs="+", help="'quick', 'standard', 'full', or one or more binary paths")
    parser.add_argument("--machgraph", default=default_machgraph_bin(), help="path to MachGraph CLI executable")
    parser.add_argument("--json-out", default=None, help="write structured JSON report to this path")
    parser.add_argument(
        "--record",
        action="store_true",
        help="write JSON report to reports/differential-<corpus>-<YYYY-MM-DD>.json under repo root",
    )
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 4), help="parallel worker count")
    parser.add_argument("--verbose", action="store_true", help="print every file row even on full corpus")
    args = parser.parse_args()

    if args.record and not is_worktree_clean():
        print(
            "[FAIL] --record refused: git worktree has uncommitted changes "
            "(commit all changes before recording a report into reports/).",
            file=sys.stderr,
        )
        return 1

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(f"[FAIL] MachGraph executable not found or not executable: {args.machgraph}", file=sys.stderr)
        return 1

    corpus_name, candidates = resolve_targets(args.targets)
    if not candidates:
        print(f"[FAIL] No candidate binaries found for '{corpus_name}'", file=sys.stderr)
        return 1

    syntax_err = verify_reference_generic_neon_syntax()
    if syntax_err is not None:
        print(f"[FAIL] {syntax_err}", file=sys.stderr)
        return 1

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    date_str = utc_now.strftime("%Y-%m-%d")
    json_out_path = args.json_out
    if args.record and json_out_path is None:
        json_out_path = os.path.join(REPO_ROOT, "reports", f"differential-{corpus_name}-{date_str}.json")

    env_isolated = os.environ.get("MACHGRAPH_ISOLATED_HOME")
    temp_home_ctx = None
    if not env_isolated:
        temp_home_ctx = tempfile.TemporaryDirectory(prefix="machgraph-diff-home-")
        isolated_home = temp_home_ctx.name
    else:
        isolated_home = env_isolated

    t_start = time.monotonic()
    try:
        worker_count = 1 if len(candidates) <= 1 else max(1, args.workers)
        rows = run_with_solo_retry(
            candidates,
            worker_count,
            lambda p: compare_one_binary(p, args.machgraph, isolated_home),
        )
    finally:
        if temp_home_ctx is not None:
            temp_home_ctx.cleanup()
    wall_seconds = round(time.monotonic() - t_start, 2)

    env_meta = collect_environment_metadata(args.machgraph)

    skipped_no_arm64 = 0
    compared_files = 0
    compared_by_arch: collections.Counter = collections.Counter()
    zero_ref_files = 0
    non_utf8_ref_files = 0
    non_utf8_mg_files = 0

    total_insns = 0
    total_agree = 0
    total_operand_compared = 0
    total_operand_equal = 0
    total_operand_mismatch = 0
    operand_mismatch_files = 0
    total_unknown = 0
    total_ref_long_mg_inst = 0
    ref_long_mg_inst_files = 0
    total_wrong = 0
    total_missing = 0
    total_mg_only_inst = 0
    mg_only_inst_files = 0
    total_mg_only_wrong = 0
    mg_only_wrong_files = 0

    failures: List[Dict[str, Any]] = []
    missing_examples: List[Dict[str, str]] = []

    wrong_pair_counts: collections.Counter = collections.Counter()
    wrong_pair_files: Dict[str, int] = collections.defaultdict(int)
    wrong_pair_example: Dict[str, Dict[str, str]] = {}

    wrong_shape_counts: collections.Counter = collections.Counter()
    wrong_shape_files: Dict[str, int] = collections.defaultdict(int)
    wrong_shape_example: Dict[str, Dict[str, str]] = {}

    operand_diff_counts: collections.Counter = collections.Counter()
    operand_diff_files: Dict[str, int] = collections.defaultdict(int)
    operand_diff_examples: Dict[str, List[Dict[str, str]]] = {}

    unknown_counts: collections.Counter = collections.Counter()
    unknown_files: Dict[str, int] = collections.defaultdict(int)

    compact_files: List[Dict[str, Any]] = []
    ceiling_violations: List[str] = []

    print_each_file = args.verbose or corpus_name != "full"

    print(f"=== MachGraph Differential Disassembly ({corpus_name}) ===")
    print(f"Date (UTC):   {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} ({env_meta['macos_build']}) {env_meta['machine']}")
    print(f"Reference:    {env_meta['llvm_objdump_version']}")
    print(f"Ref command:  {REFERENCE_COMMAND_TEMPLATE}")
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print(f"Rules ({len(NORMALIZATION_RULES)}):    {NORMALIZATION_SUMMARY}")
    print(f"Operand rules ({len(OPERAND_NORMALIZATION_RULES)}): {OPERAND_NORMALIZATION_SUMMARY}")
    print("")

    for r in rows:
        path = r["path"]
        if "skipped" in r:
            skipped_no_arm64 += 1
            continue
        if "failure" in r:
            if r.get("empty_reference"):
                zero_ref_files += 1
            failures.append(
                {
                    "file": path,
                    "arch": r.get("arch", "unknown"),
                    "exit_code": r.get("exit_code", 1),
                    "timed_out": r.get("timed_out", False),
                    "error": r["failure"],
                }
            )
            print(f"[CRASH/FAIL] {path}: {r['failure']}")
            continue

        compared_files += 1
        compared_by_arch[r["arch"]] += 1
        if r["total"] == 0:
            zero_ref_files += 1
        if r["non_utf8_reference"]:
            non_utf8_ref_files += 1
        if r["non_utf8_machgraph"]:
            non_utf8_mg_files += 1

        total_insns += r["total"]
        total_agree += r["agree"]
        row_op_compared = r.get("operand_compared", r["agree"])
        row_op_equal = r.get("operand_equal", row_op_compared)
        row_op_mismatch = r.get("operand_mismatch", row_op_compared - row_op_equal)
        total_operand_compared += row_op_compared
        total_operand_equal += row_op_equal
        total_operand_mismatch += row_op_mismatch
        if row_op_mismatch > 0:
            operand_mismatch_files += 1
        total_unknown += r["unknown_total"]
        row_ref_long_mg_inst = r.get("reference_long_machgraph_inst", 0)
        total_ref_long_mg_inst += row_ref_long_mg_inst
        if row_ref_long_mg_inst > 0:
            ref_long_mg_inst_files += 1
        total_wrong += r["wrong_total"]
        total_missing += r["missing"]
        total_mg_only_inst += r["machgraph_only_inst"]
        if r["machgraph_only_inst"] > 0:
            mg_only_inst_files += 1
        total_mg_only_wrong += r["machgraph_only_wrong"]
        if r["machgraph_only_wrong"] > 0:
            mg_only_wrong_files += 1

        for m_ex in r["missing_examples"]:
            if len(missing_examples) < 20:
                missing_examples.append(m_ex)

        for k, cnt in r["wrong_pairs"].items():
            wrong_pair_counts[k] += cnt
            wrong_pair_files[k] += 1
            wrong_pair_example.setdefault(k, r["wrong_pair_examples"][k])

        for k, cnt in r["wrong_shapes"].items():
            wrong_shape_counts[k] += cnt
            wrong_shape_files[k] += 1
            wrong_shape_example.setdefault(k, r["wrong_shape_examples"][k])

        for cat_key, cnt in r.get("operand_diffs", {}).items():
            operand_diff_counts[cat_key] += cnt
            operand_diff_files[cat_key] += 1
            ex_dst = operand_diff_examples.setdefault(cat_key, [])
            for ex_item in r.get("operand_diff_examples", {}).get(cat_key, ()):
                if len(ex_dst) >= MAX_OPERAND_EXAMPLES_PER_CATEGORY:
                    break
                ex_dst.append(ex_item)

        for k, cnt in r["unknown"].items():
            unknown_counts[k] += cnt
            unknown_files[k] += 1

        if corpus_name == "standard" and path in STANDARD_UNKNOWN_CEILINGS:
            ceil_val = STANDARD_UNKNOWN_CEILINGS[path]
            if r["unknown_total"] > ceil_val:
                ceiling_violations.append(
                    f"{path}: unknown={r['unknown_total']} exceeds baseline ceiling {ceil_val}"
                )

        file_pct = (100.0 * r["agree"] / r["total"]) if r["total"] else 100.0
        op_file_pct = (100.0 * row_op_equal / row_op_compared) if row_op_compared else 100.0
        if print_each_file or r["wrong_total"] > 0 or r["missing"] > 0:
            tag = "PASS" if (r["wrong_total"] == 0 and r["missing"] == 0) else "FAIL"
            print(
                f"[{tag}] {path} ({r['arch']}): total={r['total']} agree={r['agree']} "
                f"({file_pct:.2f}%) operand_equal={row_op_equal}/{row_op_compared} ({op_file_pct:.2f}%) "
                f"unknown={r['unknown_total']} "
                f"ref_long_mg_inst={row_ref_long_mg_inst} wrong={r['wrong_total']} "
                f"missing={r['missing']} mg_only_inst={r['machgraph_only_inst']} ({r['seconds']:.2f}s)"
            )

        compact_files.append(
            {
                "path": path,
                "arch": r["arch"],
                "instructions": r["total"],
                "agree": r["agree"],
                "operand_compared": row_op_compared,
                "operand_equal": row_op_equal,
                "operand_mismatch": row_op_mismatch,
                "unknown": r["unknown_total"],
                "reference_long_machgraph_inst": row_ref_long_mg_inst,
                "wrong": r["wrong_total"],
                "missing": r["missing"],
                "machgraph_only_inst": r["machgraph_only_inst"],
                "machgraph_only_wrong": r["machgraph_only_wrong"],
                "exit_code": r["exit_code"],
                "seconds": r["seconds"],
            }
        )

    recognized_insns = total_agree + total_wrong
    overall_pct = (100.0 * total_agree / total_insns) if total_insns else 0.0
    recognized_pct = (100.0 * total_agree / recognized_insns) if recognized_insns else 0.0
    unknown_pct = (100.0 * total_unknown / total_insns) if total_insns else 0.0
    operand_pct = (100.0 * total_operand_equal / total_operand_compared) if total_operand_compared else 0.0

    wrong_pair_list = []
    for k, cnt in wrong_pair_counts.most_common():
        llvm_m, mg_m = k.split("|", 1)
        wrong_pair_list.append(
            {
                "llvm_mnemonic": llvm_m,
                "machgraph_mnemonic": mg_m,
                "count": cnt,
                "file_count": wrong_pair_files[k],
                "example": wrong_pair_example[k],
            }
        )

    wrong_shape_list = []
    for s_key, cnt in wrong_shape_counts.most_common():
        wrong_shape_list.append(
            {
                "shape": s_key,
                "count": cnt,
                "file_count": wrong_shape_files[s_key],
                "example": wrong_shape_example[s_key],
            }
        )

    operand_diff_list = []
    for cat_key, cnt in sorted(operand_diff_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        llvm_m, mg_m, llvm_sh, mg_sh = cat_key.split("|", 3)
        examples = operand_diff_examples[cat_key]
        operand_diff_list.append(
            {
                "category": f"{llvm_m}|{mg_m}: {llvm_sh} != {mg_sh}",
                "llvm_mnemonic": llvm_m,
                "machgraph_mnemonic": mg_m,
                "llvm_shape": llvm_sh,
                "machgraph_shape": mg_sh,
                "count": cnt,
                "file_count": operand_diff_files[cat_key],
                "example": examples[0],
                "examples": examples,
            }
        )

    unknown_list = [
        {
            "llvm_mnemonic": k,
            "count": cnt,
            "file_count": unknown_files[k],
        }
        for k, cnt in unknown_counts.most_common()
    ]

    passed = (
        len(failures) == 0
        and total_missing == 0
        and total_wrong == 0
        and len(ceiling_violations) == 0
        and compared_files > 0
    )

    print("")
    verdict = "PASS" if passed else "FAIL"
    print(
        f"[{verdict}] Summary ({corpus_name}): candidates={len(candidates)} compared={compared_files} "
        f"skipped_no_arm64={skipped_no_arm64} crashes_or_failures={len(failures)} "
        f"missing={total_missing} elapsed={wall_seconds:.2f}s"
    )
    print(
        f"       instructions={total_insns} agree={total_agree} ({overall_pct:.4f}% overall | "
        f"{recognized_pct:.4f}% of {recognized_insns} recognized) "
        f"unknown={total_unknown} ({unknown_pct:.4f}%) "
        f"reference_long_machgraph_inst={total_ref_long_mg_inst} (files={ref_long_mg_inst_files}) "
        f"wrong={total_wrong} "
        f"machgraph_only_inst={total_mg_only_inst} (files={mg_only_inst_files})"
    )
    print(
        f"       operands={total_operand_equal}/{total_operand_compared} "
        f"({operand_pct:.4f}%) mismatch={total_operand_mismatch} (files={operand_mismatch_files})"
    )
    if operand_diff_list:
        shown = operand_diff_list[:MAX_PRINTED_OPERAND_CATEGORIES]
        hdr_suffix = (
            f" (top {len(shown)} of {len(operand_diff_list)})"
            if len(operand_diff_list) > len(shown)
            else f" ({len(operand_diff_list)})"
        )
        print(f"       operand difference categories{hdr_suffix}:")
        for item in shown:
            print(
                f"         - {item['category']}: count={item['count']} files={item['file_count']}"
            )
            for ex in item["examples"][:3]:
                print(
                    f"             {ex['file']} @ {ex['address']} [{ex['word']}] "
                    f"machgraph='{ex['machgraph']}' vs llvm='{ex['llvm']}'"
                )

    if wrong_pair_list:
        print("       wrong mnemonic categories (llvm != machgraph):", file=sys.stderr)
        for item in wrong_pair_list:
            ex = item["example"]
            print(
                f"         - {item['llvm_mnemonic']} != {item['machgraph_mnemonic']}: "
                f"count={item['count']} files={item['file_count']} "
                f"e.g. {ex['file']} @ {ex['address']} [{ex['word']}] "
                f"llvm='{ex['llvm']}' vs machgraph='{ex['machgraph']}'",
                file=sys.stderr,
            )
    if missing_examples:
        print("       missing reference addresses:", file=sys.stderr)
        for ex in missing_examples[:10]:
            print(f"         - {ex['file']} @ {ex['address']} llvm='{ex['llvm']}'", file=sys.stderr)
    for cv in ceiling_violations:
        print(f"       [CEILING] {cv}", file=sys.stderr)

    report_payload: Dict[str, Any] = {
        "schema_version": 1,
        "date": date_str,
        "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus": corpus_name,
        "verdict": verdict,
        "environment": env_meta,
        "reference_command": REFERENCE_COMMAND_TEMPLATE,
        "normalization_rules": list(NORMALIZATION_RULES),
        "operand_normalization_rules": list(OPERAND_NORMALIZATION_RULES),
        "summary": {
            "candidate_macho_files": len(candidates),
            "compared_files": compared_files,
            "compared_by_arch": dict(compared_by_arch),
            "skipped_no_arm64_slice": skipped_no_arm64,
            "zero_instruction_reference_files": zero_ref_files,
            "non_utf8_reference_files": non_utf8_ref_files,
            "non_utf8_machgraph_files": non_utf8_mg_files,
            "crashes_or_failures": len(failures),
            "missing_addresses": total_missing,
            "total_instructions": total_insns,
            "recognized_instructions": recognized_insns,
            "agreed_instructions": total_agree,
            "operand_compared": total_operand_compared,
            "operand_equal": total_operand_equal,
            "operand_mismatch": total_operand_mismatch,
            "operand_mismatch_files": operand_mismatch_files,
            "operand_agreement_pct": round(operand_pct, 6),
            "unknown_instructions": total_unknown,
            "reference_long_machgraph_inst": total_ref_long_mg_inst,
            "reference_long_machgraph_inst_files": ref_long_mg_inst_files,
            "wrong_instructions": total_wrong,
            "machgraph_only_inst_instructions": total_mg_only_inst,
            "machgraph_only_inst_files": mg_only_inst_files,
            "machgraph_only_wrong_instructions": total_mg_only_wrong,
            "machgraph_only_wrong_files": mg_only_wrong_files,
            "overall_agreement_pct": round(overall_pct, 6),
            "recognized_agreement_pct": round(recognized_pct, 6),
            "unknown_pct": round(unknown_pct, 6),
            "elapsed_seconds": wall_seconds,
        },
        "failures": failures,
        "missing_examples": missing_examples,
        "ceiling_violations": ceiling_violations,
        "wrong_by_mnemonic_pair": wrong_pair_list,
        "wrong_by_shape": wrong_shape_list,
        "operand_differences": operand_diff_list,
        "unknown_by_reference_mnemonic": unknown_list,
        "files": compact_files,
    }

    if json_out_path is not None:
        out_dir = os.path.dirname(os.path.abspath(json_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        serialized = json.dumps(report_payload, indent=2) + "\n"
        with open(json_out_path, "w", encoding="utf-8") as fh:
            fh.write(serialized)
        print(f"       JSON report written to {sanitize_repo_label(json_out_path)}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
