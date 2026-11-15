#!/usr/bin/env python3
"""Differential ARM64 disassembly check (`machgraph disasm` vs `llvm-objdump`).

Usage:
  Scripts/acceptance/differential.py <quick|standard|full|file...>
      [--machgraph <path>] [--json-out <path>] [--record] [--workers <n>] [--verbose]

Reference command (fixed by `02-machgraph.md`, M1 item 1):
  xcrun llvm-objdump -d --no-show-raw-insn --arch=<slice> --mattr=+bti --section=__TEXT,__text <file>

Normalization rules: imported from `mnemonic_normalization.py` (only the three
narrow rules: `movz`/`movn` == `mov`, `udf` == `.inst`, drop reference vector
arrangement suffix while keeping `b.<cond>`).

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
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from mnemonic_normalization import (  # noqa: E402
    NORMALIZATION_RULES,
    NORMALIZATION_SUMMARY,
    classify_mnemonic_pair,
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
REFERENCE_COMMAND_TEMPLATE = (
    "xcrun llvm-objdump -d --no-show-raw-insn --arch=<slice> "
    "--mattr=+bti --section=__TEXT,__text <file>"
)
_REF_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")
_NUMBER_SHAPE_RE = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)")


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

    ref_cmd = [
        "xcrun",
        "llvm-objdump",
        "-d",
        "--no-show-raw-insn",
        f"--arch={arch}",
        "--mattr=+bti",
        "--section=__TEXT,__text",
        path,
    ]
    try:
        ref_proc = subprocess.run(
            ref_cmd,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {
            "path": path,
            "arch": arch,
            "failure": "llvm-objdump timed out after 300s",
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

    ref_map: Dict[int, Tuple[str, str]] = {}
    for line in ref_text.splitlines():
        if line.strip() == "Contents of (__TEXT,__text) section":
            break
        m = _REF_INSN_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            raw_mnem = m.group(2).lower()
            raw_ops = (m.group(3) or "").split(";")[0].strip()
            ref_map[addr] = (raw_mnem, raw_ops)

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
            timeout=PER_FILE_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - t0, 3)
        return {
            "path": path,
            "arch": arch,
            "total": len(ref_map),
            "seconds": elapsed,
            "failure": f"machgraph timed out after {PER_FILE_TIMEOUT_SECONDS}s",
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

    agree = 0
    missing = 0
    missing_examples: List[Dict[str, str]] = []
    unknown_counter: collections.Counter = collections.Counter()
    wrong_pair_counter: collections.Counter = collections.Counter()
    wrong_pair_examples: Dict[Tuple[str, str], Dict[str, str]] = {}
    wrong_shape_counter: collections.Counter = collections.Counter()
    wrong_shape_examples: Dict[str, Dict[str, str]] = {}

    for addr, (raw_ref_mnem, raw_ref_ops) in ref_map.items():
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

    return {
        "path": path,
        "arch": arch,
        "total": len(ref_map),
        "agree": agree,
        "unknown_total": sum(unknown_counter.values()),
        "wrong_total": sum(wrong_pair_counter.values()),
        "missing": missing,
        "missing_examples": missing_examples,
        "unknown": dict(unknown_counter),
        "wrong_pairs": {f"{k[0]}|{k[1]}": v for k, v in wrong_pair_counter.items()},
        "wrong_pair_examples": {f"{k[0]}|{k[1]}": v for k, v in wrong_pair_examples.items()},
        "wrong_shapes": dict(wrong_shape_counter),
        "wrong_shape_examples": wrong_shape_examples,
        "non_utf8_reference": non_utf8_ref,
        "non_utf8_machgraph": non_utf8_mg,
        "exit_code": 0,
        "seconds": elapsed,
    }


def collect_environment_metadata(machgraph_bin: str) -> Dict[str, str]:
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
        help="write JSON report to reports/differential-<YYYY-MM-DD>.json under repo root",
    )
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 4), help="parallel worker count")
    parser.add_argument("--verbose", action="store_true", help="print every file row even on full corpus")
    args = parser.parse_args()

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(f"[FAIL] MachGraph executable not found or not executable: {args.machgraph}", file=sys.stderr)
        return 1

    corpus_name, candidates = resolve_targets(args.targets)
    if not candidates:
        print(f"[FAIL] No candidate binaries found for '{corpus_name}'", file=sys.stderr)
        return 1

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    date_str = utc_now.strftime("%Y-%m-%d")
    json_out_path = args.json_out
    if args.record and json_out_path is None:
        json_out_path = os.path.join(REPO_ROOT, "reports", f"differential-{date_str}.json")

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
        if worker_count == 1:
            rows = [compare_one_binary(p, args.machgraph, isolated_home) for p in candidates]
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                rows = list(pool.map(lambda p: compare_one_binary(p, args.machgraph, isolated_home), candidates))
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
    total_unknown = 0
    total_wrong = 0
    total_missing = 0

    failures: List[Dict[str, Any]] = []
    missing_examples: List[Dict[str, str]] = []

    wrong_pair_counts: collections.Counter = collections.Counter()
    wrong_pair_files: Dict[str, int] = collections.defaultdict(int)
    wrong_pair_example: Dict[str, Dict[str, str]] = {}

    wrong_shape_counts: collections.Counter = collections.Counter()
    wrong_shape_files: Dict[str, int] = collections.defaultdict(int)
    wrong_shape_example: Dict[str, Dict[str, str]] = {}

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
    print(f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]}")
    print(f"Rules (3):    {NORMALIZATION_SUMMARY}")
    print("")

    for r in rows:
        path = r["path"]
        if "skipped" in r:
            skipped_no_arm64 += 1
            continue
        if "failure" in r:
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
        total_unknown += r["unknown_total"]
        total_wrong += r["wrong_total"]
        total_missing += r["missing"]

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
        if print_each_file or r["wrong_total"] > 0 or r["missing"] > 0:
            tag = "PASS" if (r["wrong_total"] == 0 and r["missing"] == 0) else "FAIL"
            print(
                f"[{tag}] {path} ({r['arch']}): total={r['total']} agree={r['agree']} "
                f"({file_pct:.2f}%) unknown={r['unknown_total']} wrong={r['wrong_total']} "
                f"missing={r['missing']} ({r['seconds']:.2f}s)"
            )

        compact_files.append(
            {
                "path": path,
                "arch": r["arch"],
                "instructions": r["total"],
                "agree": r["agree"],
                "unknown": r["unknown_total"],
                "wrong": r["wrong_total"],
                "missing": r["missing"],
                "exit_code": r["exit_code"],
                "seconds": r["seconds"],
            }
        )

    recognized_insns = total_agree + total_wrong
    overall_pct = (100.0 * total_agree / total_insns) if total_insns else 0.0
    recognized_pct = (100.0 * total_agree / recognized_insns) if recognized_insns else 0.0
    unknown_pct = (100.0 * total_unknown / total_insns) if total_insns else 0.0

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
        f"unknown={total_unknown} ({unknown_pct:.4f}%) wrong={total_wrong}"
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
            "unknown_instructions": total_unknown,
            "wrong_instructions": total_wrong,
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
