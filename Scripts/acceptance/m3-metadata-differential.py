#!/usr/bin/env python3
"""Differential Mach-O metadata & demangling check for MachGraph M3.

Usage:
  Scripts/acceptance/m3-metadata-differential.py [<quick|standard|objc|full|file...>]
      [--only <subcheck,...>] [--machgraph <path>] [--json-out <path>]
      [--record] [--workers <n>] [--verbose]

Implemented subchecks:
  - symbols : `machgraph symbols <file> --json` (`realSymbols` multiset of `(address, name)`)
              vs `xcrun nm --no-dyldinfo -arch <slice> <file>` (all defined symbols with an address,
              excluding `U`/`u` undefined imports and `<redacted function N>` placeholders).
  - dylibs  : `machgraph info <file> --json` (`installID` + ordered `libraries` tuples of
              `(installName, compatibilityVersion, currentVersion, isWeak, isReexport)`) and
              `machgraph info <file>` text output vs `xcrun otool -arch <slice> -L <file>`
              (for `MH_DYLIB`, line 1 `LC_ID_DYLIB` is compared against `installID`).
  - objc    : `machgraph objc <file> --json` (`classes`, `±[Class sel]`, `±[Class(Cat) sel]`,
              `protocols` sets) vs `xcrun otool -arch <slice> -ov <file>` (+ `otool -l`
              `__objc_selrefs` base VA for relative selector resolution). Defaults to
              `Calculator`, `assetutil`, `screencapture`, and `log` when `--only objc` omits targets.

Slice selection follows `arm64e` -> `arm64` via `lipo -archs <file>`, matching MachGraph's preferred slice.
At most 6 child processes are spawned concurrently (`MAX_CONCURRENT_SUBPROCESSES = 6`).
All subprocess streams are read as raw bytes and decoded with `errors="replace"` so non-UTF-8 output never aborts.

Exit status:
  0 when all compared files and selected subchecks pass with 0 crashes, 0 timeouts, and 0 mismatches;
  1 on any crash, timeout, non-zero exit, empty corpus, dirty `--record` worktree, or data mismatch;
  2 on invalid CLI arguments (e.g., unknown `--only` check name).
"""

import argparse
import collections
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Counter as CounterType, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

QUICK_FILES: Tuple[str, ...] = ("/bin/ls",)
STANDARD_FILES: Tuple[str, ...] = ("/bin/ls", "/usr/bin/ssh", "/usr/bin/vim")
OBJC_DEFAULT_FILES: Tuple[str, ...] = (
    "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
    "/usr/bin/assetutil",
    "/usr/sbin/screencapture",
    "/usr/bin/log",
)
FULL_SCAN_ROOTS: Tuple[str, ...] = ("/bin", "/usr/bin", "/usr/sbin", "/usr/libexec")

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

CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0x00FFFFFF
MH_MAGIC_64 = 0xFEEDFACF
MH_DYLIB = 0x6
MH_DYLIB_STUB = 0x9
LC_ID_DYLIB = 0xD

MAX_CONCURRENT_SUBPROCESSES = 6
MAX_EXAMPLES_PER_CHECK = 5
PER_FILE_TIMEOUT_SECONDS = 60.0
PER_MIB_TIMEOUT_SECONDS = 5.0
MAX_PER_FILE_TIMEOUT_SECONDS = 900.0

AVAILABLE_CHECKS: Tuple[str, ...] = ("symbols", "dylibs", "objc")

NM_REFERENCE_TEMPLATE = "xcrun nm --no-dyldinfo -arch <slice> <file>"
OTOOL_L_REFERENCE_TEMPLATE = "xcrun otool -arch <slice> -L <file>"
OTOOL_OV_REFERENCE_TEMPLATE = (
    "xcrun otool -arch <slice> -ov <file> (+ xcrun otool -arch <slice> -l <file> for __objc_selrefs base)"
)

_NM_LINE_RE = re.compile(r"^([0-9a-fA-F]{8,16}|\s{8,16}) ([A-Za-z?-]) (.*)$")
_REDACTED_FN_RE = re.compile(r"^<redacted function \d+>$")
_OTOOL_LIB_RE = re.compile(
    r"^\t(.+?) \(compatibility version ([0-9.]+), current version ([0-9.]+)(?:, ([^)]+))?\)$"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+\x40[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_USERS_PREFIX = os.sep + "Users" + os.sep
_USERS_PATH_RE = re.compile(re.escape(_USERS_PREFIX) + r"[^/\s\"']+")

_SUBPROCESS_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_SUBPROCESSES)


def decode_utf8_safe(raw: Optional[bytes]) -> Tuple[str, bool]:
    """Decode raw subprocess bytes without failing on invalid UTF-8 sequences."""
    if not raw:
        return ("", False)
    try:
        return (raw.decode("utf-8"), False)
    except UnicodeDecodeError:
        return (raw.decode("utf-8", errors="replace"), True)


def sanitize_display_path(path: str, repo_root: Optional[str] = None) -> str:
    """Format a path relative to repo root or system root without exposing local home paths."""
    root = os.path.abspath(repo_root if repo_root is not None else REPO_ROOT)
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, root)
        if rel == "." or (not rel.startswith("..") and not os.path.isabs(rel)):
            return rel
    except ValueError:
        pass
    home_dir = os.path.expanduser("~")
    if (home_dir and home_dir != "/" and abs_path.startswith(home_dir)) or abs_path.startswith(_USERS_PREFIX):
        return os.path.basename(abs_path) or "binary"
    return abs_path


def sanitize_text(text: str) -> str:
    """Scrub local home directories and email addresses from diagnostic/version strings."""
    out = text
    home_dir = os.path.expanduser("~")
    if home_dir and home_dir != "/":
        out = out.replace(home_dir, "<home>")
    out = _USERS_PATH_RE.sub("<home>", out)
    out = _EMAIL_RE.sub("<redacted-email>", out)
    return out


def run_subprocess_bytes(
    cmd: Sequence[str],
    *,
    timeout: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Execute a subprocess while strictly enforcing `MAX_CONCURRENT_SUBPROCESSES`."""
    with _SUBPROCESS_SEMAPHORE:
        return subprocess.run(
            list(cmd),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )


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
    """Run `fn` across `candidates` with bounded worker threads; retry any timeout solo once (G39)."""
    capped_workers = min(MAX_CONCURRENT_SUBPROCESSES, max(1, worker_count))
    if capped_workers <= 1 or len(candidates) <= 1:
        return [fn(p) for p in candidates]
    with ThreadPoolExecutor(max_workers=capped_workers) as pool:
        rows = list(pool.map(fn, candidates))
    for idx, row in enumerate(rows):
        if row.get("timed_out"):
            path = candidates[idx]
            print(
                f"[RETRY] {sanitize_display_path(path)} timed out during parallel run; retrying solo...",
                file=sys.stderr,
            )
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


def is_worktree_clean(repo_root: Optional[str] = None) -> bool:
    root = repo_root if repo_root is not None else REPO_ROOT
    res = run_subprocess_bytes(["git", "status", "--porcelain"], timeout=30.0, cwd=root)
    if res.returncode != 0:
        return False
    txt, _ = decode_utf8_safe(res.stdout)
    return txt.strip() == ""


def collect_environment_metadata(machgraph_bin: str, repo_root: Optional[str] = None) -> Dict[str, Any]:
    root = repo_root if repo_root is not None else REPO_ROOT

    def run_text(cmd: Sequence[str], cwd: Optional[str] = None) -> str:
        try:
            proc = run_subprocess_bytes(cmd, timeout=30.0, cwd=cwd)
        except Exception:
            return "unknown"
        out, _ = decode_utf8_safe(proc.stdout)
        err, _ = decode_utf8_safe(proc.stderr)
        combined = out.strip() or err.strip()
        return sanitize_text(combined)

    def pick_version_line(raw: str) -> str:
        if not raw:
            return "unknown"
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if not lines:
            return "unknown"
        for ln in lines:
            if "LLVM version" in ln or "Apple LLVM" in ln or "cctools" in ln:
                return ln
        return lines[0]

    nm_ver = pick_version_line(run_text(["xcrun", "nm", "--version"]))
    otool_ver = pick_version_line(run_text(["xcrun", "otool", "--version"]))
    commit_sha = run_text(["git", "rev-parse", "HEAD"], cwd=root) or "unknown"

    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
        "reference_tools": {
            "nm_version": nm_ver,
            "otool_version": otool_ver,
        },
        "machgraph_commit": commit_sha,
        "worktree_clean": is_worktree_clean(repo_root=root),
        "machgraph_binary": sanitize_display_path(machgraph_bin, repo_root=root),
    }


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


def resolve_targets(raw_targets: Sequence[str]) -> Tuple[str, List[str]]:
    if len(raw_targets) == 1:
        tier = raw_targets[0]
        if tier == "quick":
            return ("quick", list(QUICK_FILES))
        if tier == "standard":
            return ("standard", list(STANDARD_FILES))
        if tier == "objc":
            return ("objc", list(OBJC_DEFAULT_FILES))
        if tier == "full":
            return ("full", discover_full_candidates())
    return ("custom", [os.path.abspath(p) if not os.path.isabs(p) else p for p in raw_targets])


def parse_only_checks(raw_only: Optional[str]) -> List[str]:
    if raw_only is None:
        return list(AVAILABLE_CHECKS)
    requested: List[str] = []
    for tok in raw_only.split(","):
        item = tok.strip()
        if not item:
            continue
        if item not in AVAILABLE_CHECKS:
            raise ValueError(
                f"Unknown or unimplemented check '{item}' in --only "
                f"(available: {', '.join(AVAILABLE_CHECKS)})"
            )
        if item not in requested:
            requested.append(item)
    if not requested:
        raise ValueError(f"--only must name at least one check (available: {', '.join(AVAILABLE_CHECKS)})")
    return requested


def default_record_path(date_str: str, repo_root: Optional[str] = None) -> str:
    root = repo_root if repo_root is not None else REPO_ROOT
    return os.path.join(root, "reports", f"m3-metadata-{date_str}.json")


def select_arm64_slice(path: str, timeout_sec: float = 30.0) -> Optional[str]:
    res = run_subprocess_bytes(["lipo", "-archs", path], timeout=timeout_sec)
    if res.returncode != 0:
        return None
    txt, _ = decode_utf8_safe(res.stdout)
    archs = txt.split()
    if "arm64e" in archs:
        return "arm64e"
    if "arm64" in archs:
        return "arm64"
    return None


def inspect_macho_slice_dylib_kind(path: str, arch: str) -> Tuple[bool, bool]:
    """Inspect the selected Mach-O 64 slice header to detect `MH_DYLIB` and `LC_ID_DYLIB`."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if len(head) < 32:
            return (False, False)
        magic_be = struct.unpack(">I", head[:4])[0]
        magic_le = struct.unpack("<I", head[:4])[0]
        slice_off = 0
        if magic_be in (0xCAFEBABE, 0xCAFEBABF):
            is_fat64 = magic_be == 0xCAFEBABF
            narch = struct.unpack(">I", head[4:8])[0]
            pos = 8
            slices: List[Tuple[int, int, int]] = []
            for _ in range(narch):
                if is_fat64:
                    if pos + 32 > len(head):
                        break
                    cputype, cpusubtype, offset, _, _, _ = struct.unpack(">iiQQII", head[pos : pos + 32])
                    pos += 32
                else:
                    if pos + 20 > len(head):
                        break
                    cputype, cpusubtype, offset, _, _ = struct.unpack(">iiIII", head[pos : pos + 20])
                    pos += 20
                slices.append((cputype, cpusubtype & CPU_SUBTYPE_MASK, offset))
            chosen_off: Optional[int] = None
            if arch == "arm64e":
                for cputype, sub, off in slices:
                    if cputype == CPU_TYPE_ARM64 and sub == CPU_SUBTYPE_ARM64E:
                        chosen_off = off
                        break
            if chosen_off is None:
                for cputype, _, off in slices:
                    if cputype == CPU_TYPE_ARM64:
                        chosen_off = off
                        break
            if chosen_off is None:
                return (False, False)
            slice_off = chosen_off
        elif magic_le != MH_MAGIC_64:
            return (False, False)

        with open(path, "rb") as fh:
            fh.seek(slice_off)
            mh = fh.read(32)
            if len(mh) < 32:
                return (False, False)
            magic, _, _, filetype, ncmds, sizeofcmds, _, _ = struct.unpack("<IiiIIIII", mh)
            if magic != MH_MAGIC_64:
                return (False, False)
            is_dylib = filetype in (MH_DYLIB, MH_DYLIB_STUB)
            if ncmds == 0 or sizeofcmds == 0:
                return (is_dylib, is_dylib)
            lc_buf = fh.read(min(sizeofcmds, 512 * 1024))

        has_id_dylib = False
        pos = 0
        for _ in range(ncmds):
            if pos + 8 > len(lc_buf):
                break
            cmd, cmdsize = struct.unpack("<II", lc_buf[pos : pos + 8])
            if cmd == LC_ID_DYLIB:
                has_id_dylib = True
                break
            if cmdsize < 8:
                break
            pos += cmdsize
        return (is_dylib, has_id_dylib)
    except OSError:
        return (False, False)


def format_exit_reason(tool_label: str, rc: int, stderr_txt: str) -> str:
    first_line = sanitize_text(stderr_txt.strip().splitlines()[0]) if stderr_txt.strip() else ""
    if rc < 0:
        sig = -rc
        detail = f": {first_line[:200]}" if first_line else ""
        return f"{tool_label} crashed with signal {sig} (exit {rc}){detail}"
    if rc >= 128:
        detail = f": {first_line[:200]}" if first_line else ""
        return f"{tool_label} terminated with code {rc} (signal {rc - 128}){detail}"
    detail = f": {first_line[:200]}" if first_line else ""
    return f"{tool_label} exited {rc}{detail}"


def run_machgraph_command(
    machgraph_bin: str,
    args: Sequence[str],
    env: Dict[str, str],
    timeout_sec: float,
) -> Tuple[Optional[str], Optional[str], bool, bool]:
    """Run MachGraph CLI returning `(stdout_txt, error_msg, timed_out, had_non_utf8)`."""
    cmd = [machgraph_bin, *args]
    label = f"machgraph {args[0]}" if args else "machgraph"
    try:
        proc = run_subprocess_bytes(cmd, timeout=timeout_sec, env=env)
    except subprocess.TimeoutExpired:
        return (None, f"{label} timed out after {timeout_sec:.0f}s", True, False)

    out_txt, non_utf8_out = decode_utf8_safe(proc.stdout)
    err_txt, non_utf8_err = decode_utf8_safe(proc.stderr)
    had_non_utf8 = non_utf8_out or non_utf8_err
    if proc.returncode != 0:
        return (None, format_exit_reason(label, proc.returncode, err_txt), False, had_non_utf8)
    return (out_txt, None, False, had_non_utf8)


def parse_nm_defined_symbols(
    path: str, arch: str, timeout_sec: float
) -> Tuple[Optional[CounterType[Tuple[int, str]]], Optional[str], bool, bool]:
    """Run `xcrun nm --no-dyldinfo -arch <arch> <path>` and return defined `(address, name)` multiset."""
    cmd = ["xcrun", "nm", "--no-dyldinfo", "-arch", arch, path]
    try:
        proc = run_subprocess_bytes(cmd, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return (None, f"nm --no-dyldinfo timed out after {timeout_sec:.0f}s", True, False)

    out_txt, non_utf8_out = decode_utf8_safe(proc.stdout)
    err_txt, non_utf8_err = decode_utf8_safe(proc.stderr)
    had_non_utf8 = non_utf8_out or non_utf8_err
    if proc.returncode != 0:
        return (None, format_exit_reason("nm --no-dyldinfo", proc.returncode, err_txt), False, had_non_utf8)

    counts: CounterType[Tuple[int, str]] = collections.Counter()
    for line in out_txt.splitlines():
        m = _NM_LINE_RE.match(line)
        if not m:
            continue
        addr_s, sym_type, name = m.group(1), m.group(2), m.group(3)
        if sym_type in ("U", "u", "I", "i"):
            continue
        addr_stripped = addr_s.strip()
        if not addr_stripped:
            continue
        if _REDACTED_FN_RE.match(name):
            continue
        counts[(int(addr_stripped, 16), name)] += 1
    return (counts, None, False, had_non_utf8)


def check_symbols_for_binary(
    path: str,
    arch: str,
    machgraph_bin: str,
    env: Dict[str, str],
    timeout_sec: float,
) -> Dict[str, Any]:
    ref_counts, ref_err, ref_to, ref_non_utf8 = parse_nm_defined_symbols(path, arch, max(120.0, timeout_sec))
    if ref_err is not None or ref_counts is None:
        return {
            "status": "failure",
            "error": ref_err or "nm failed",
            "timed_out": ref_to,
            "non_utf8": ref_non_utf8,
        }

    mg_out, mg_err, mg_to, mg_non_utf8 = run_machgraph_command(
        machgraph_bin, ["symbols", path, "--json"], env, timeout_sec
    )
    if mg_err is not None or mg_out is None:
        return {
            "status": "failure",
            "error": mg_err or "machgraph symbols failed",
            "timed_out": mg_to,
            "non_utf8": ref_non_utf8 or mg_non_utf8,
        }

    try:
        mg_json = json.loads(mg_out)
    except json.JSONDecodeError as exc:
        return {
            "status": "failure",
            "error": f"machgraph symbols invalid JSON: {exc}",
            "timed_out": False,
            "non_utf8": ref_non_utf8 or mg_non_utf8,
        }

    real_syms = mg_json.get("realSymbols")
    if not isinstance(real_syms, list):
        return {
            "status": "failure",
            "error": "machgraph symbols --json missing 'realSymbols' list",
            "timed_out": False,
            "non_utf8": ref_non_utf8 or mg_non_utf8,
        }

    mg_counts: CounterType[Tuple[int, str]] = collections.Counter()
    structural_diffs: List[Dict[str, Any]] = []
    if mg_json.get("realCount") != len(real_syms):
        structural_diffs.append(
            {
                "kind": "realCount_mismatch",
                "realCount": mg_json.get("realCount"),
                "len_realSymbols": len(real_syms),
            }
        )

    for sym in real_syms:
        if not isinstance(sym, dict) or "address" not in sym or "name" not in sym:
            structural_diffs.append({"kind": "malformed_symbol_entry", "entry": str(sym)[:120]})
            continue
        addr = int(sym["address"])
        name = str(sym["name"])
        mg_counts[(addr, name)] += 1
        if sym.get("inferred") is not False or sym.get("source") != "lc_symtab":
            if len(structural_diffs) < MAX_EXAMPLES_PER_CHECK:
                structural_diffs.append(
                    {
                        "kind": "non_symtab_in_realSymbols",
                        "address": hex(addr),
                        "name": name,
                        "inferred": sym.get("inferred"),
                        "source": sym.get("source"),
                    }
                )

    missing = ref_counts - mg_counts
    extra = mg_counts - ref_counts
    missing_total = sum(missing.values())
    extra_total = sum(extra.values())
    diff_total = missing_total + extra_total + len(structural_diffs)

    examples: List[Dict[str, Any]] = list(structural_diffs[:MAX_EXAMPLES_PER_CHECK])
    for (addr, name), _ in sorted(missing.items()):
        if len(examples) >= MAX_EXAMPLES_PER_CHECK:
            break
        examples.append(
            {
                "kind": "missing_in_machgraph",
                "address": hex(addr),
                "name": name,
                "nm_count": ref_counts[(addr, name)],
                "mg_count": mg_counts[(addr, name)],
            }
        )
    for (addr, name), _ in sorted(extra.items()):
        if len(examples) >= MAX_EXAMPLES_PER_CHECK:
            break
        examples.append(
            {
                "kind": "extra_in_machgraph",
                "address": hex(addr),
                "name": name,
                "nm_count": ref_counts[(addr, name)],
                "mg_count": mg_counts[(addr, name)],
            }
        )

    return {
        "status": "pass" if diff_total == 0 else "mismatch",
        "ref_count": sum(ref_counts.values()),
        "mg_count": sum(mg_counts.values()),
        "missing_count": missing_total,
        "extra_count": extra_total,
        "diff_count": diff_total,
        "examples": examples,
        "non_utf8": ref_non_utf8 or mg_non_utf8,
    }


def parse_otool_dylibs(
    path: str, arch: str, timeout_sec: float
) -> Tuple[Optional[List[Tuple[str, str, str, bool, bool]]], Optional[str], bool, bool]:
    """Run `xcrun otool -arch <arch> -L <path>` and parse ordered dylib entries."""
    cmd = ["xcrun", "otool", "-arch", arch, "-L", path]
    try:
        proc = run_subprocess_bytes(cmd, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return (None, f"otool -L timed out after {timeout_sec:.0f}s", True, False)

    out_txt, non_utf8_out = decode_utf8_safe(proc.stdout)
    err_txt, non_utf8_err = decode_utf8_safe(proc.stderr)
    had_non_utf8 = non_utf8_out or non_utf8_err
    if proc.returncode != 0:
        return (None, format_exit_reason("otool -L", proc.returncode, err_txt), False, had_non_utf8)

    entries: List[Tuple[str, str, str, bool, bool]] = []
    for line in out_txt.splitlines():
        if not line.startswith("\t"):
            continue
        m = _OTOOL_LIB_RE.match(line)
        if not m:
            return (
                None,
                f"otool -L unparseable library line: {sanitize_text(line.strip())[:160]}",
                False,
                had_non_utf8,
            )
        install_name = m.group(1)
        compat_ver = m.group(2)
        current_ver = m.group(3)
        tag = (m.group(4) or "").strip()
        is_weak = tag == "weak"
        is_reexport = tag == "reexport"
        entries.append((install_name, compat_ver, current_ver, is_weak, is_reexport))
    return (entries, None, False, had_non_utf8)


def check_dylibs_for_binary(
    path: str,
    arch: str,
    machgraph_bin: str,
    env: Dict[str, str],
    timeout_sec: float,
) -> Dict[str, Any]:
    otool_entries, ref_err, ref_to, ref_non_utf8 = parse_otool_dylibs(path, arch, max(120.0, timeout_sec))
    if ref_err is not None or otool_entries is None:
        return {
            "status": "failure",
            "error": ref_err or "otool -L failed",
            "timed_out": ref_to,
            "non_utf8": ref_non_utf8,
        }

    mg_json_txt, mg_err, mg_to, mg_non_utf8 = run_machgraph_command(
        machgraph_bin, ["info", path, "--json"], env, timeout_sec
    )
    if mg_err is not None or mg_json_txt is None:
        return {
            "status": "failure",
            "error": mg_err or "machgraph info --json failed",
            "timed_out": mg_to,
            "non_utf8": ref_non_utf8 or mg_non_utf8,
        }

    try:
        mg_info = json.loads(mg_json_txt)
    except json.JSONDecodeError as exc:
        return {
            "status": "failure",
            "error": f"machgraph info invalid JSON: {exc}",
            "timed_out": False,
            "non_utf8": ref_non_utf8 or mg_non_utf8,
        }

    mg_text_out, txt_err, txt_to, txt_non_utf8 = run_machgraph_command(
        machgraph_bin, ["info", path], env, timeout_sec
    )
    if txt_err is not None or mg_text_out is None:
        return {
            "status": "failure",
            "error": txt_err or "machgraph info text failed",
            "timed_out": txt_to,
            "non_utf8": ref_non_utf8 or mg_non_utf8 or txt_non_utf8,
        }

    had_non_utf8 = ref_non_utf8 or mg_non_utf8 or txt_non_utf8
    examples: List[Dict[str, Any]] = []
    diff_count = 0

    expected_arch_label = "arm64e (PAC)" if arch == "arm64e" else "arm64"
    if mg_info.get("architecture") != expected_arch_label:
        diff_count += 1
        examples.append(
            {
                "kind": "slice_architecture_mismatch",
                "expected": expected_arch_label,
                "mg": mg_info.get("architecture"),
            }
        )

    is_mh_dylib, has_lc_id_dylib = inspect_macho_slice_dylib_kind(path, arch)
    expect_install_id = is_mh_dylib and has_lc_id_dylib

    if expect_install_id:
        if not otool_entries:
            diff_count += 1
            if len(examples) < MAX_EXAMPLES_PER_CHECK:
                examples.append({"kind": "missing_otool_id_dylib", "mg_installID": mg_info.get("installID")})
            ref_id: Optional[Tuple[str, str, str]] = None
            ref_libs: List[Tuple[str, str, str, bool, bool]] = []
        else:
            first = otool_entries[0]
            ref_id = (first[0], first[1], first[2])
            ref_libs = otool_entries[1:]
        mg_id_raw = mg_info.get("installID")
        if not isinstance(mg_id_raw, dict):
            diff_count += 1
            if len(examples) < MAX_EXAMPLES_PER_CHECK:
                examples.append({"kind": "installID_missing_or_null", "otool_id": ref_id, "mg_installID": mg_id_raw})
        elif ref_id is not None:
            mg_id_tuple = (
                mg_id_raw.get("installName"),
                mg_id_raw.get("compatibilityVersion"),
                mg_id_raw.get("currentVersion"),
            )
            if mg_id_tuple != ref_id:
                diff_count += 1
                if len(examples) < MAX_EXAMPLES_PER_CHECK:
                    examples.append(
                        {
                            "kind": "installID_mismatch",
                            "otool": {
                                "installName": ref_id[0],
                                "compatibilityVersion": ref_id[1],
                                "currentVersion": ref_id[2],
                            },
                            "mg": mg_id_raw,
                        }
                    )
            if ref_id[0] not in mg_text_out:
                diff_count += 1
                if len(examples) < MAX_EXAMPLES_PER_CHECK:
                    examples.append({"kind": "info_text_missing_installID", "installName": ref_id[0]})
    else:
        ref_libs = otool_entries
        if not has_lc_id_dylib:
            if "installID" not in mg_info or mg_info.get("installID") is not None:
                diff_count += 1
                if len(examples) < MAX_EXAMPLES_PER_CHECK:
                    examples.append(
                        {
                            "kind": "unexpected_or_missing_installID_key",
                            "has_key": "installID" in mg_info,
                            "mg_installID": mg_info.get("installID"),
                        }
                    )

    raw_mg_libs = mg_info.get("libraries")
    if not isinstance(raw_mg_libs, list):
        return {
            "status": "failure",
            "error": "machgraph info --json missing 'libraries' list",
            "timed_out": False,
            "non_utf8": had_non_utf8,
        }

    mg_libs: List[Tuple[Any, Any, Any, bool, bool]] = []
    for lib in raw_mg_libs:
        if not isinstance(lib, dict):
            mg_libs.append((None, None, None, False, False))
            continue
        mg_libs.append(
            (
                lib.get("installName"),
                lib.get("compatibilityVersion"),
                lib.get("currentVersion"),
                bool(lib.get("isWeak")),
                bool(lib.get("isReexport")),
            )
        )

    max_len = max(len(ref_libs), len(mg_libs))
    for idx in range(max_len):
        ref_item = ref_libs[idx] if idx < len(ref_libs) else None
        mg_item = mg_libs[idx] if idx < len(mg_libs) else None
        if ref_item != mg_item:
            diff_count += 1
            if len(examples) < MAX_EXAMPLES_PER_CHECK:
                examples.append(
                    {
                        "kind": "library_entry_mismatch",
                        "index": idx,
                        "otool": (
                            {
                                "installName": ref_item[0],
                                "compatibilityVersion": ref_item[1],
                                "currentVersion": ref_item[2],
                                "isWeak": ref_item[3],
                                "isReexport": ref_item[4],
                            }
                            if ref_item is not None
                            else None
                        ),
                        "mg": (
                            {
                                "installName": mg_item[0],
                                "compatibilityVersion": mg_item[1],
                                "currentVersion": mg_item[2],
                                "isWeak": mg_item[3],
                                "isReexport": mg_item[4],
                            }
                            if mg_item is not None
                            else None
                        ),
                    }
                )

    for ref_item in ref_libs:
        if ref_item[0] not in mg_text_out:
            diff_count += 1
            if len(examples) < MAX_EXAMPLES_PER_CHECK:
                examples.append(
                    {
                        "kind": "info_text_missing_library",
                        "installName": ref_item[0],
                    }
                )

    return {
        "status": "pass" if diff_count == 0 else "mismatch",
        "is_mh_dylib": is_mh_dylib,
        "ref_count": len(ref_libs),
        "mg_count": len(mg_libs),
        "diff_count": diff_count,
        "examples": examples,
        "non_utf8": had_non_utf8,
    }


def parse_otool_objc(
    path: str, arch: str, timeout_sec: float
) -> Tuple[Optional[Dict[str, Set[str]]], Optional[str], bool, bool]:
    """Extract ObjC classes, ±[Class sel], ±[Class(Cat) sel], and protocols via `otool -l` + `otool -ov`."""
    cmd_l = ["xcrun", "otool", "-arch", arch, "-l", path]
    try:
        proc_l = run_subprocess_bytes(cmd_l, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return (None, f"otool -l timed out after {timeout_sec:.0f}s", True, False)

    out_l, non_utf8_l_out = decode_utf8_safe(proc_l.stdout)
    err_l, non_utf8_l_err = decode_utf8_safe(proc_l.stderr)
    had_non_utf8 = non_utf8_l_out or non_utf8_l_err
    if proc_l.returncode != 0:
        return (None, format_exit_reason("otool -l", proc_l.returncode, err_l), False, had_non_utf8)

    sec_addrs: Dict[str, int] = {}
    for blk in out_l.split("Section\n")[1:]:
        sn = re.search(r"\bsectname\s+(\S+)", blk)
        gn = re.search(r"\bsegname\s+(\S+)", blk)
        ad = re.search(r"\baddr\s+(0x[0-9a-fA-F]+|\d+)", blk)
        if sn and gn and ad:
            sec_addrs[f"{gn.group(1)[:16]},{sn.group(1)[:16]}"] = int(ad.group(1), 0)

    cmd_ov = ["xcrun", "otool", "-arch", arch, "-ov", path]
    try:
        proc_ov = run_subprocess_bytes(cmd_ov, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return (None, f"otool -ov timed out after {timeout_sec:.0f}s", True, had_non_utf8)

    out_ov, non_utf8_ov_out = decode_utf8_safe(proc_ov.stdout)
    err_ov, non_utf8_ov_err = decode_utf8_safe(proc_ov.stderr)
    had_non_utf8 = had_non_utf8 or non_utf8_ov_out or non_utf8_ov_err
    if proc_ov.returncode != 0:
        return (None, format_exit_reason("otool -ov", proc_ov.returncode, err_ov), False, had_non_utf8)

    blocks = re.split(r"^Contents of \(([^)]+)\) section\s*$", out_ov, flags=re.MULTILINE)

    # Pass 1: build slot_va -> selector_name from `(__DATA*,__objc_selrefs)`
    slot_to_sel: Dict[int, str] = {}
    for i in range(1, len(blocks), 2):
        sname, body = blocks[i], blocks[i + 1]
        if sname.endswith("__objc_selrefs"):
            base_va = sec_addrs.get(sname)
            idx = 0
            for ln in body.splitlines():
                m = re.match(r"^\s*(?:([0-9a-fA-F]{8,16})\s+)?0x[0-9a-fA-F]+(?:\s+(.*))?$", ln)
                if not m:
                    continue
                sel_txt = (m.group(2) or "").strip()
                if sel_txt:
                    if base_va is not None:
                        slot_to_sel[base_va + idx * 8] = sel_txt
                    if m.group(1):
                        slot_to_sel[int(m.group(1), 16)] = sel_txt
                idx += 1

    def resolve_sel(raw_rhs: str) -> str:
        raw_rhs = raw_rhs.strip()
        m_ptr = re.match(r"^\(0x([0-9a-fA-F]+)\)(?:\s+(.*))?$", raw_rhs)
        if m_ptr:
            va = int(m_ptr.group(1), 16)
            rest = (m_ptr.group(2) or "").strip()
            return rest if rest else slot_to_sel.get(va, raw_rhs)
        return raw_rhs

    def extract_selectors_from_block(text_part: str, header_kw: str, indent_spaces: int) -> List[str]:
        pat = rf"^ {{{indent_spaces}}}{header_kw}\s+0x[0-9a-fA-F]+(.*)$"
        m_hdr = re.search(pat, text_part, flags=re.MULTILINE)
        if not m_hdr or "__mh_execute_header" in m_hdr.group(1):
            return []
        after = text_part[m_hdr.end() :]
        stop_m = re.search(rf"^ {{0,{indent_spaces}}}\S", after, flags=re.MULTILINE)
        chunk = after[: stop_m.start()] if stop_m else after
        selectors: List[str] = []
        cur_sel: Optional[str] = None
        for ln in chunk.splitlines():
            ms = re.match(rf"^ {{{indent_spaces + 4}}}name\s+0x[0-9a-fA-F]+\s+(.+)$", ln)
            if ms:
                cur_sel = resolve_sel(ms.group(1))
                continue
            mi = re.match(rf"^ {{{indent_spaces + 4}}}imp\s+0x[0-9a-fA-F]+", ln)
            if mi and cur_sel is not None:
                selectors.append(cur_sel)
                cur_sel = None
        return selectors

    classes: Set[str] = set()
    methods: Set[str] = set()
    category_methods: Set[str] = set()
    protocols: Set[str] = set()
    class_va_to_name: Dict[int, str] = {}

    # Pass 2: classes and ±[Class sel] methods
    for i in range(1, len(blocks), 2):
        sname, body = blocks[i], blocks[i + 1]
        if sname.endswith("__objc_classlist") or sname.endswith("__objc_nlclslist"):
            entries = re.split(r"^(?=[0-9a-fA-F]{8,16}\s+0x[0-9a-fA-F]+)", body, flags=re.MULTILINE)
            for ent in entries:
                if not ent.strip():
                    continue
                m_cva = re.match(r"^[0-9a-fA-F]{8,16}\s+(0x[0-9a-fA-F]+)", ent)
                parts = ent.split("Meta Class\n", 1)
                cls_part = parts[0]
                meta_part = parts[1] if len(parts) > 1 else ""
                mn = re.search(r"^ {8}name\s+0x[0-9a-fA-F]+\s+(\S+)", cls_part, flags=re.MULTILINE)
                if not mn:
                    continue
                cname = mn.group(1)
                classes.add(cname)
                if m_cva:
                    class_va_to_name[int(m_cva.group(1), 16)] = cname
                for sel in extract_selectors_from_block(cls_part, "baseMethods", 8):
                    methods.add(f"-[{cname} {sel}]")
                for sel in extract_selectors_from_block(meta_part, "baseMethods", 8):
                    methods.add(f"+[{cname} {sel}]")

    # Pass 3: categories (±[Host(Cat) sel]) and protocols
    for i in range(1, len(blocks), 2):
        sname, body = blocks[i], blocks[i + 1]
        if sname.endswith("__objc_catlist") or sname.endswith("__objc_nlcatlist"):
            entries = re.split(r"^(?=[0-9a-fA-F]{8,16}\s+0x[0-9a-fA-F]+)", body, flags=re.MULTILINE)
            for ent in entries:
                if not ent.strip():
                    continue
                mc = re.search(r"^ {4}name\s+0x[0-9a-fA-F]+\s+(\S+)", ent, flags=re.MULTILINE)
                mhost = re.search(r"^ {4}cls\s+(0x[0-9a-fA-F]+)(?:[ \t]+(\S+))?", ent, flags=re.MULTILINE)
                if not mc:
                    continue
                cat_name = mc.group(1)
                raw_host = (mhost.group(2) if mhost and mhost.group(2) else "").strip()
                for pfx in ("_OBJC_CLASS_$_", "OBJC_CLASS_$_"):
                    if raw_host.startswith(pfx):
                        raw_host = raw_host[len(pfx) :]
                        break
                if not raw_host and mhost:
                    raw_host = class_va_to_name.get(int(mhost.group(1), 16), "")
                host_cls = raw_host or "UnknownClass"
                for sel in extract_selectors_from_block(ent, "instanceMethods", 4):
                    category_methods.add(f"-[{host_cls}({cat_name}) {sel}]")
                for sel in extract_selectors_from_block(ent, "classMethods", 4):
                    category_methods.add(f"+[{host_cls}({cat_name}) {sel}]")

        elif sname.endswith("__objc_protolist"):
            entries = re.split(r"^(?=[0-9a-fA-F]{8,16}\s+0x[0-9a-fA-F]+)", body, flags=re.MULTILINE)
            for ent in entries:
                if not ent.strip():
                    continue
                mp = re.search(r"^ {4}name\s+0x[0-9a-fA-F]+\s+(\S+)", ent, flags=re.MULTILINE)
                if mp:
                    protocols.add(mp.group(1))

    return (
        {
            "classes": classes,
            "methods": methods,
            "category_methods": category_methods,
            "protocols": protocols,
        },
        None,
        False,
        had_non_utf8,
    )


def check_objc_for_binary(
    path: str,
    arch: str,
    machgraph_bin: str,
    env: Dict[str, str],
    timeout_sec: float,
) -> Dict[str, Any]:
    ref_sets, ref_err, ref_to, ref_non_utf8 = parse_otool_objc(path, arch, max(120.0, timeout_sec))
    if ref_err is not None or ref_sets is None:
        return {
            "status": "failure",
            "error": ref_err or "otool -ov failed",
            "timed_out": ref_to,
            "non_utf8": ref_non_utf8,
        }

    mg_out, mg_err, mg_to, mg_non_utf8 = run_machgraph_command(
        machgraph_bin, ["objc", path, "--json"], env, timeout_sec
    )
    had_non_utf8 = ref_non_utf8 or mg_non_utf8
    if mg_err is not None or mg_out is None:
        return {
            "status": "failure",
            "error": mg_err or "machgraph objc failed",
            "timed_out": mg_to,
            "non_utf8": had_non_utf8,
        }

    try:
        mg_json = json.loads(mg_out)
    except json.JSONDecodeError as exc:
        return {
            "status": "failure",
            "error": f"machgraph objc invalid JSON: {exc}",
            "timed_out": False,
            "non_utf8": had_non_utf8,
        }

    raw_classes = mg_json.get("classes")
    raw_categories = mg_json.get("categories")
    raw_protocols = mg_json.get("protocols")
    if not isinstance(raw_classes, list) or not isinstance(raw_categories, list) or not isinstance(raw_protocols, list):
        return {
            "status": "failure",
            "error": "machgraph objc --json missing 'classes', 'categories', or 'protocols' list",
            "timed_out": False,
            "non_utf8": had_non_utf8,
        }

    mg_classes: Set[str] = set()
    mg_methods: Set[str] = set()
    mg_cat_methods: Set[str] = set()
    mg_protocols: Set[str] = set()
    structural_diffs: List[Dict[str, Any]] = []

    if mg_json.get("classCount") != len(raw_classes):
        structural_diffs.append(
            {"kind": "classCount_mismatch", "classCount": mg_json.get("classCount"), "len_classes": len(raw_classes)}
        )
    if mg_json.get("categoryCount") != len(raw_categories):
        structural_diffs.append(
            {
                "kind": "categoryCount_mismatch",
                "categoryCount": mg_json.get("categoryCount"),
                "len_categories": len(raw_categories),
            }
        )
    if mg_json.get("protocolCount") != len(raw_protocols):
        structural_diffs.append(
            {
                "kind": "protocolCount_mismatch",
                "protocolCount": mg_json.get("protocolCount"),
                "len_protocols": len(raw_protocols),
            }
        )

    for cls_entry in raw_classes:
        if not isinstance(cls_entry, dict) or "name" not in cls_entry:
            structural_diffs.append({"kind": "malformed_class_entry", "entry": sanitize_text(str(cls_entry))[:120]})
            continue
        cname = str(cls_entry["name"])
        mg_classes.add(cname)
        for m in cls_entry.get("instanceMethods") or []:
            if isinstance(m, dict) and "selector" in m:
                mg_methods.add(f"-[{cname} {m['selector']}]")
                if m.get("isClassMethod") is not False:
                    structural_diffs.append({"kind": "class_method_in_instanceMethods", "class": cname, "method": m.get("selector")})
        for m in cls_entry.get("classMethods") or []:
            if isinstance(m, dict) and "selector" in m:
                mg_methods.add(f"+[{cname} {m['selector']}]")
                if m.get("isClassMethod") is not True:
                    structural_diffs.append({"kind": "instance_method_in_classMethods", "class": cname, "method": m.get("selector")})

    for cat_entry in raw_categories:
        if not isinstance(cat_entry, dict) or "name" not in cat_entry or "className" not in cat_entry:
            structural_diffs.append({"kind": "malformed_category_entry", "entry": sanitize_text(str(cat_entry))[:120]})
            continue
        cat_name = str(cat_entry["name"])
        host_cls = str(cat_entry["className"])
        for m in cat_entry.get("instanceMethods") or []:
            if isinstance(m, dict) and "selector" in m:
                mg_cat_methods.add(f"-[{host_cls}({cat_name}) {m['selector']}]")
                if m.get("isClassMethod") is not False:
                    structural_diffs.append({"kind": "class_method_in_category_instanceMethods", "category": f"{host_cls}({cat_name})", "method": m.get("selector")})
        for m in cat_entry.get("classMethods") or []:
            if isinstance(m, dict) and "selector" in m:
                mg_cat_methods.add(f"+[{host_cls}({cat_name}) {m['selector']}]")
                if m.get("isClassMethod") is not True:
                    structural_diffs.append({"kind": "instance_method_in_category_classMethods", "category": f"{host_cls}({cat_name})", "method": m.get("selector")})

    for proto_entry in raw_protocols:
        if not isinstance(proto_entry, dict) or "name" not in proto_entry:
            structural_diffs.append({"kind": "malformed_protocol_entry", "entry": sanitize_text(str(proto_entry))[:120]})
            continue
        mg_protocols.add(str(proto_entry["name"]))

    comparisons = [
        ("class", ref_sets["classes"], mg_classes),
        ("method", ref_sets["methods"], mg_methods),
        ("category_method", ref_sets["category_methods"], mg_cat_methods),
        ("protocol", ref_sets["protocols"], mg_protocols),
    ]

    diff_total = len(structural_diffs)
    examples: List[Dict[str, Any]] = list(structural_diffs[:MAX_EXAMPLES_PER_CHECK])

    for kind_label, ref_s, mg_s in comparisons:
        missing = sorted(ref_s - mg_s)
        extra = sorted(mg_s - ref_s)
        diff_total += len(missing) + len(extra)
        for item in missing:
            if len(examples) >= MAX_EXAMPLES_PER_CHECK:
                break
            examples.append(
                {
                    "kind": f"missing_{kind_label}_in_machgraph",
                    "item": sanitize_text(item),
                }
            )
        for item in extra:
            if len(examples) >= MAX_EXAMPLES_PER_CHECK:
                break
            examples.append(
                {
                    "kind": f"extra_{kind_label}_in_machgraph",
                    "item": sanitize_text(item),
                }
            )

    ref_total = sum(len(ref_s) for _, ref_s, _ in comparisons)
    mg_total = sum(len(mg_s) for _, _, mg_s in comparisons)

    return {
        "status": "pass" if diff_total == 0 else "mismatch",
        "ref_count": ref_total,
        "mg_count": mg_total,
        "diff_count": diff_total,
        "examples": examples,
        "non_utf8": had_non_utf8,
    }


CHECK_HANDLERS: Dict[str, Callable[[str, str, str, Dict[str, str], float], Dict[str, Any]]] = {
    "symbols": check_symbols_for_binary,
    "dylibs": check_dylibs_for_binary,
    "objc": check_objc_for_binary,
}


def evaluate_one_binary(
    path: str,
    selected_checks: Sequence[str],
    machgraph_bin: str,
    isolated_home: str,
) -> Dict[str, Any]:
    t0 = time.monotonic()
    if not os.path.isfile(path):
        return {
            "path": path,
            "failure": f"target binary does not exist: {sanitize_display_path(path)}",
            "timed_out": False,
            "seconds": round(time.monotonic() - t0, 3),
        }

    try:
        arch = select_arm64_slice(path)
    except subprocess.TimeoutExpired:
        return {
            "path": path,
            "failure": "lipo -archs timed out after 30s",
            "timed_out": True,
            "seconds": round(time.monotonic() - t0, 3),
        }

    if arch is None:
        return {"path": path, "skipped": "no arm64 slice"}

    timeout_sec = per_file_timeout_seconds(path)
    env = dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )

    per_check: Dict[str, Dict[str, Any]] = {}
    any_non_utf8 = False
    for chk in selected_checks:
        res = CHECK_HANDLERS[chk](path, arch, machgraph_bin, env, timeout_sec)
        any_non_utf8 = any_non_utf8 or bool(res.get("non_utf8"))
        if res.get("status") == "failure":
            return {
                "path": path,
                "arch": arch,
                "failed_check": chk,
                "failure": res.get("error", f"{chk} failed"),
                "timed_out": bool(res.get("timed_out")),
                "non_utf8": any_non_utf8,
                "seconds": round(time.monotonic() - t0, 3),
            }
        per_check[chk] = res

    return {
        "path": path,
        "arch": arch,
        "checks": per_check,
        "non_utf8": any_non_utf8,
        "seconds": round(time.monotonic() - t0, 3),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "targets",
        nargs="*",
        help="'quick', 'standard', 'objc', 'full', or one or more binary paths (optional when --only objc)",
    )
    parser.add_argument(
        "--only",
        default=None,
        help=f"comma-separated subset of checks to run (default: all implemented: {','.join(AVAILABLE_CHECKS)})",
    )
    parser.add_argument("--machgraph", default=default_machgraph_bin(), help="path to MachGraph CLI executable")
    parser.add_argument("--json-out", default=None, help="optional path to write JSON report")
    parser.add_argument(
        "--record",
        action="store_true",
        help="write JSON report to reports/m3-metadata-<YYYY-MM-DD>.json (requires clean git worktree)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(MAX_CONCURRENT_SUBPROCESSES, os.cpu_count() or 4),
        help=f"parallel worker count (capped at {MAX_CONCURRENT_SUBPROCESSES})",
    )
    parser.add_argument("--verbose", action="store_true", help="include verbose per-example detail on stdout")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        selected_checks = parse_only_checks(args.only)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2

    if not args.targets:
        if selected_checks == ["objc"]:
            raw_targets: Sequence[str] = ["objc"]
        else:
            print(
                "[FAIL] positional 'targets' required unless '--only objc' is specified",
                file=sys.stderr,
            )
            return 2
    else:
        raw_targets = args.targets

    if args.record and not is_worktree_clean():
        print(
            "[FAIL] --record refused: git worktree has uncommitted changes "
            "(commit all changes before recording a report into reports/).",
            file=sys.stderr,
        )
        return 1

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(
            f"[FAIL] MachGraph executable not found or not executable: {sanitize_display_path(args.machgraph)}",
            file=sys.stderr,
        )
        return 1

    corpus_name, candidates = resolve_targets(raw_targets)
    if not candidates:
        print(f"[FAIL] No candidate binaries found for '{corpus_name}'", file=sys.stderr)
        return 1

    env_isolated = os.environ.get("MACHGRAPH_ISOLATED_HOME")
    temp_home_ctx = None
    if not env_isolated:
        temp_home_ctx = tempfile.TemporaryDirectory(prefix="machgraph-m3-home-")
        isolated_home = temp_home_ctx.name
    else:
        isolated_home = env_isolated

    worker_count = min(MAX_CONCURRENT_SUBPROCESSES, max(1, args.workers))
    t_start = time.monotonic()
    try:
        rows = run_with_solo_retry(
            candidates,
            worker_count,
            lambda p: evaluate_one_binary(p, selected_checks, args.machgraph, isolated_home),
        )
    finally:
        if temp_home_ctx is not None:
            temp_home_ctx.cleanup()
    wall_seconds = round(time.monotonic() - t_start, 2)

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    date_str = utc_now.strftime("%Y-%m-%d")
    json_out_path = args.json_out
    if args.record and json_out_path is None:
        json_out_path = default_record_path(date_str)

    env_meta = collect_environment_metadata(args.machgraph)

    print(f"=== MachGraph M3 Metadata Differential ({corpus_name}) ===")
    print(f"Date (UTC):   {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    print(f"Ref nm:       {env_meta['reference_tools']['nm_version']}")
    print(f"Ref otool:    {env_meta['reference_tools']['otool_version']}")
    print(f"Checks:       {', '.join(selected_checks)} (max_concurrent_subprocesses={MAX_CONCURRENT_SUBPROCESSES})")
    print(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    print("")

    skipped_no_arm64 = 0
    compared_files = 0
    non_utf8_files = 0
    failures: List[Dict[str, Any]] = []
    file_records: List[Dict[str, Any]] = []

    check_summaries: Dict[str, Dict[str, Any]] = {
        chk: {
            "compared_files": 0,
            "matched_files": 0,
            "mismatched_files": 0,
            "total_ref_items": 0,
            "total_mg_items": 0,
            "total_diffs": 0,
            "examples": [],
        }
        for chk in selected_checks
    }

    for r in rows:
        disp_path = sanitize_display_path(r["path"])
        if "skipped" in r:
            skipped_no_arm64 += 1
            continue
        if "failure" in r:
            if r.get("non_utf8"):
                non_utf8_files += 1
            fail_entry = {
                "file": disp_path,
                "check": r.get("failed_check"),
                "error": sanitize_text(str(r["failure"])),
                "timed_out": bool(r.get("timed_out")),
            }
            failures.append(fail_entry)
            print(f"[CRASH/FAIL] {disp_path}: {fail_entry['error']}")
            continue

        compared_files += 1
        if r.get("non_utf8"):
            non_utf8_files += 1

        arch = r["arch"]
        per_check = r["checks"]
        file_passed = True
        part_Tokens: List[str] = []
        compact_checks: Dict[str, Any] = {}

        for chk in selected_checks:
            cres = per_check[chk]
            csum = check_summaries[chk]
            csum["compared_files"] += 1
            csum["total_ref_items"] += int(cres.get("ref_count", 0))
            csum["total_mg_items"] += int(cres.get("mg_count", 0))
            csum["total_diffs"] += int(cres.get("diff_count", 0))

            if cres["status"] == "pass":
                csum["matched_files"] += 1
                part_Tokens.append(f"{chk}=OK({cres['mg_count']})")
            else:
                file_passed = False
                csum["mismatched_files"] += 1
                part_Tokens.append(f"{chk}=DIFF({cres['diff_count']})")
                for ex in cres.get("examples", []):
                    if len(csum["examples"]) < MAX_EXAMPLES_PER_CHECK:
                        csum["examples"].append({"file": disp_path, "arch": arch, **ex})

            compact_checks[chk] = {
                "status": cres["status"],
                "ref_count": cres["ref_count"],
                "mg_count": cres["mg_count"],
                "diff_count": cres["diff_count"],
                **(
                    {"examples": cres["examples"][:MAX_EXAMPLES_PER_CHECK]}
                    if cres["diff_count"] > 0
                    else {}
                ),
            }

        file_records.append(
            {
                "file": disp_path,
                "arch": arch,
                "status": "PASS" if file_passed else "FAIL",
                "seconds": r["seconds"],
                "checks": compact_checks,
            }
        )

        tag = "PASS" if file_passed else "FAIL"
        print(f"[{tag}] {disp_path} ({arch}): {' '.join(part_Tokens)} ({r['seconds']:.2f}s)")
        if not file_passed:
            for chk in selected_checks:
                cres = per_check[chk]
                for ex in cres.get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                    print(f"    [{chk} example] {json.dumps(ex, ensure_ascii=False)}")

    total_mismatched_files = sum(
        1 for rec in file_records if rec["status"] != "PASS"
    )
    passed = len(failures) == 0 and total_mismatched_files == 0 and compared_files > 0
    verdict = "PASS" if passed else "FAIL"

    print("")
    for chk in selected_checks:
        csum = check_summaries[chk]
        chk_verdict = "PASS" if (csum["mismatched_files"] == 0 and len(failures) == 0 and compared_files > 0) else "FAIL"
        print(
            f"[{chk_verdict}] Check '{chk}': matched={csum['matched_files']}/{csum['compared_files']} "
            f"mismatched_files={csum['mismatched_files']} total_diffs={csum['total_diffs']} "
            f"ref_items={csum['total_ref_items']} mg_items={csum['total_mg_items']}"
        )
        for ex in csum["examples"][:MAX_EXAMPLES_PER_CHECK]:
            print(f"  example: {json.dumps(ex, ensure_ascii=False)}")

    print(
        f"[{verdict}] Summary ({corpus_name}): candidates={len(candidates)} compared={compared_files} "
        f"skipped_no_arm64={skipped_no_arm64} crashes_or_failures={len(failures)} "
        f"mismatched_files={total_mismatched_files} non_utf8_files={non_utf8_files} "
        f"elapsed={wall_seconds:.2f}s"
    )

    if json_out_path:
        out_dir = os.path.dirname(os.path.abspath(json_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        payload = {
            "date": date_str,
            "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "corpus": corpus_name,
            "selected_checks": selected_checks,
            "verdict": verdict,
            "environment": env_meta,
            "reference_commands": {
                "symbols": NM_REFERENCE_TEMPLATE,
                "dylibs": OTOOL_L_REFERENCE_TEMPLATE,
                "objc": OTOOL_OV_REFERENCE_TEMPLATE,
            },
            "summary": {
                "candidate_macho_files": len(candidates),
                "compared_files": compared_files,
                "skipped_no_arm64_slice": skipped_no_arm64,
                "crashes_or_failures": len(failures),
                "mismatched_files": total_mismatched_files,
                "non_utf8_output_files": non_utf8_files,
                "max_concurrent_subprocesses": MAX_CONCURRENT_SUBPROCESSES,
                "elapsed_seconds": wall_seconds,
            },
            "checks": check_summaries,
            "failures": failures,
            "files": file_records,
        }
        with open(json_out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
