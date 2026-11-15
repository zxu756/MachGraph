#!/usr/bin/env python3
"""Differential Mach-O container check (`info`, `fixups`, `codesign` vs Apple tools).

Usage:
  Scripts/acceptance/macho-differential.py <quick|standard|full|file...>
      [--machgraph <path>] [--json-out <path>] [--workers <n>] [--verbose]

Reference tools per binary (matched on the same slice selected by MachGraph):
  1. `lipo -archs <file>` + `xcrun otool -arch <slice> -l <file>`
     -> architecture, fileName, segments (name, vmaddr, vmsize, fileoff, filesize),
        sections (segment, section, addr, size, offset), UUID, entryPoint
  2. `xcrun dyld_info -arch <slice> -fixups <file>`
     -> chained fixups count, rebase/bind counts, locations, rebase target addresses,
        and bound symbol names (when `LC_DYLD_CHAINED_FIXUPS` is present; verifies
        `count == 0` when `LC_DYLD_CHAINED_FIXUPS` is absent)
  3. `/usr/bin/codesign -a <slice> -dvvv <file>`
     -> signature presence, ad-hoc flag, identifier, teamIdentifier, CDHash

Exit status:
  0 when all files exit cleanly within 60s and all compared fields match;
  1 on any crash, timeout, non-zero exit, or field mismatch.
"""

import argparse
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

QUICK_FILES = ["/bin/ls"]
STANDARD_FILES = ["/bin/ls", "/usr/bin/ssh", "/usr/bin/vim"]
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

_DYLD_FIXUP_RE = re.compile(
    r"^\s*\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(rebase|auth-rebase|bind|auth-bind)\s+(.+)$"
)
_KIND_MAP = {
    "rebase": "DYLD_REBASE",
    "auth-rebase": "DYLD_AUTH_REBASE",
    "bind": "DYLD_BIND",
    "auth-bind": "DYLD_AUTH_BIND",
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
                    key = (st.st_dev, st.st_ino)
                    if key in seen_inodes:
                        continue
                    seen_inodes.add(key)
                    with open(path, "rb") as fh:
                        magic = fh.read(4)
                except OSError:
                    continue
                if magic in MACHO_MAGICS:
                    found.append(path)
    found.sort()
    return found


def select_slice(path: str) -> Optional[str]:
    res = subprocess.run(["lipo", "-archs", path], capture_output=True, stdin=subprocess.DEVNULL)
    if res.returncode != 0:
        return None
    archs = res.stdout.decode("utf-8", errors="replace").split()
    if "arm64e" in archs:
        return "arm64e"
    if "arm64" in archs:
        return "arm64"
    return None


def parse_otool_load_commands(path: str, arch: str) -> Dict[str, Any]:
    proc = subprocess.run(
        ["xcrun", "otool", "-arch", arch, "-l", path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
    )
    txt = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:200]
        raise RuntimeError(f"otool -l exited {proc.returncode}: {err}")

    segments: List[Tuple[str, int, int, int, int]] = []
    sections: List[Tuple[str, str, int, int, int]] = []
    uuid_val: Optional[str] = None
    entry_off: Optional[int] = None
    unixthread_pc: Optional[int] = None
    has_chained_fixups = False
    text_vmaddr: Optional[int] = None

    for blk in txt.split("Load command ")[1:]:
        cmd_m = re.search(r"^\s*\d+\s*\n\s*cmd\s+(\S+)", blk)
        cmd_name = cmd_m.group(1) if cmd_m else ""
        if cmd_name == "LC_SEGMENT_64":
            header_part = re.split(r"\bSection\n", blk, maxsplit=1)[0]
            seg_m = re.search(r"\bsegname\s+(\S+)", header_part)
            vm_m = re.search(r"\bvmaddr\s+(0x[0-9a-fA-F]+|\d+)", header_part)
            vmsz_m = re.search(r"\bvmsize\s+(0x[0-9a-fA-F]+|\d+)", header_part)
            foff_m = re.search(r"\bfileoff\s+(\d+)", header_part)
            fsz_m = re.search(r"\bfilesize\s+(\d+)", header_part)
            if seg_m and vm_m and vmsz_m and foff_m and fsz_m:
                segname = seg_m.group(1)
                vmaddr = int(vm_m.group(1), 0)
                vmsize = int(vmsz_m.group(1), 0)
                fileoff = int(foff_m.group(1), 10)
                filesize = int(fsz_m.group(1), 10)
                segments.append((segname, vmaddr, vmsize, fileoff, filesize))
                if segname == "__TEXT" and text_vmaddr is None:
                    text_vmaddr = vmaddr
            for sec_blk in re.split(r"\bSection\n", blk)[1:]:
                sn_m = re.search(r"\bsectname\s+(\S+)", sec_blk)
                gn_m = re.search(r"\bsegname\s+(\S+)", sec_blk)
                ad_m = re.search(r"\baddr\s+(0x[0-9a-fA-F]+|\d+)", sec_blk)
                sz_m = re.search(r"\bsize\s+(0x[0-9a-fA-F]+|\d+)", sec_blk)
                of_m = re.search(r"\boffset\s+(\d+)", sec_blk)
                if sn_m and gn_m and ad_m and sz_m and of_m:
                    sections.append(
                        (
                            gn_m.group(1),
                            sn_m.group(1),
                            int(ad_m.group(1), 0),
                            int(sz_m.group(1), 0),
                            int(of_m.group(1), 10),
                        )
                    )
        elif cmd_name == "LC_UUID":
            u_m = re.search(r"\buuid\s+([0-9A-Fa-f-]+)", blk)
            if u_m:
                uuid_val = u_m.group(1).upper()
        elif cmd_name == "LC_MAIN":
            eo_m = re.search(r"\bentryoff\s+(\d+)", blk)
            if eo_m:
                entry_off = int(eo_m.group(1), 10)
        elif cmd_name == "LC_UNIXTHREAD":
            pc_m = re.search(r"\bpc\s+(0x[0-9a-fA-F]+)", blk)
            if pc_m:
                unixthread_pc = int(pc_m.group(1), 16)
        elif cmd_name == "LC_DYLD_CHAINED_FIXUPS":
            has_chained_fixups = True

    expected_entry: Optional[int] = None
    if entry_off is not None and text_vmaddr is not None:
        expected_entry = text_vmaddr + entry_off
    elif unixthread_pc is not None:
        expected_entry = unixthread_pc

    return {
        "segments": segments,
        "sections": sections,
        "uuid": uuid_val,
        "entry_point": expected_entry,
        "has_chained_fixups": has_chained_fixups,
    }


def parse_dyld_info_fixups(path: str, arch: str) -> Dict[int, Tuple[str, Optional[int], Optional[str]]]:
    proc = subprocess.run(
        ["xcrun", "dyld_info", "-arch", arch, "-fixups", path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
    )
    txt = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[:200]
        raise RuntimeError(f"dyld_info -fixups exited {proc.returncode}: {err}")

    parsed: Dict[int, Tuple[str, Optional[int], Optional[str]]] = {}
    for line in txt.splitlines():
        m = _DYLD_FIXUP_RE.match(line)
        if not m:
            continue
        loc = int(m.group(1), 16)
        raw_kind = m.group(2)
        rest = m.group(3).strip()
        mg_kind = _KIND_MAP[raw_kind]
        if "rebase" in raw_kind:
            tm = re.match(r"^(0x[0-9a-fA-F]+)", rest)
            tgt = int(tm.group(1), 16) if tm else None
            parsed[loc] = (mg_kind, tgt, None)
        else:
            # Strip trailing annotations like `[weak-import]` and `(div=0x... ad=... key=...)`, plus `+ 0x...` addends
            cleaned = re.sub(r"\s*\(div=[^)]*\)\s*$", "", rest)
            cleaned = re.sub(r"\s*\[weak-import\]\s*", " ", cleaned).strip()
            cleaned = re.split(r"\s+[+-]\s+(?:0x[0-9a-fA-F]+|\d+)", cleaned)[0].strip()
            sym = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
            parsed[loc] = (mg_kind, None, sym)
    return parsed


def parse_codesign_ref(path: str, arch: str) -> Dict[str, Any]:
    proc = subprocess.run(
        ["/usr/bin/codesign", "-a", arch, "-dvvv", path],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    combined = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
    if "code object is not signed at all" in combined.lower():
        return {
            "is_signed": False,
            "is_adhoc": False,
            "identifier": "",
            "team_identifier": None,
            "cdhash_full": None,
            "cdhash_short": None,
        }
    if proc.returncode != 0:
        raise RuntimeError(f"codesign -dvvv exited {proc.returncode}: {combined.strip()[:200]}")

    ident = ""
    team_id: Optional[str] = None
    is_adhoc = False
    cdhash_full: Optional[str] = None
    cdhash_short: Optional[str] = None

    for line in combined.splitlines():
        if line.startswith("Identifier="):
            ident = line.split("=", 1)[1].strip()
        elif line.startswith("TeamIdentifier="):
            val = line.split("=", 1)[1].strip()
            team_id = None if val == "not set" else val
        elif line.startswith("Signature="):
            if line.split("=", 1)[1].strip() == "adhoc":
                is_adhoc = True
        elif line.startswith("CodeDirectory "):
            if "adhoc" in line:
                is_adhoc = True
        elif line.startswith("CandidateCDHashFull "):
            # e.g. CandidateCDHashFull sha256=54097a16...
            if "=" in line:
                cdhash_full = line.split("=", 1)[1].strip().lower()
        elif line.startswith("CDHash="):
            cdhash_short = line.split("=", 1)[1].strip().lower()

    return {
        "is_signed": True,
        "is_adhoc": is_adhoc,
        "identifier": ident,
        "team_identifier": team_id,
        "cdhash_full": cdhash_full,
        "cdhash_short": cdhash_short,
    }


def run_mg_json(machgraph_bin: str, subcmd: str, path: str, env: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        proc = subprocess.run(
            [machgraph_bin, subcmd, path, "--json"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=PER_FILE_TIMEOUT_SECONDS,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return (None, f"machgraph {subcmd} timed out after {PER_FILE_TIMEOUT_SECONDS}s")

    stdout_txt = proc.stdout.decode("utf-8", errors="replace")
    stderr_txt = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        first_err = stderr_txt.strip().splitlines()[0] if stderr_txt.strip() else ""
        return (None, f"machgraph {subcmd} exited {proc.returncode}: {first_err[:200]}")

    try:
        return (json.loads(stdout_txt), None)
    except json.JSONDecodeError as exc:
        return (None, f"machgraph {subcmd} invalid JSON: {exc}")


def check_one_binary(path: str, machgraph_bin: str, isolated_home: str) -> Dict[str, Any]:
    arch = select_slice(path)
    if arch is None:
        return {"path": path, "skipped": "no arm64 slice"}

    t0 = time.monotonic()
    env = dict(
        os.environ,
        HOME=isolated_home,
        CFFIXED_USER_HOME=isolated_home,
        SWIFT_BACKTRACE="enable=no",
    )

    mismatches: List[str] = []

    try:
        ref_otool = parse_otool_load_commands(path, arch)
        ref_cs = parse_codesign_ref(path, arch)
        ref_fixups = (
            parse_dyld_info_fixups(path, arch) if ref_otool["has_chained_fixups"] else {}
        )
    except Exception as exc:
        return {
            "path": path,
            "arch": arch,
            "seconds": round(time.monotonic() - t0, 3),
            "failure": f"reference tool error: {exc}",
        }

    mg_info, err_info = run_mg_json(machgraph_bin, "info", path, env)
    if err_info:
        return {"path": path, "arch": arch, "seconds": round(time.monotonic() - t0, 3), "failure": err_info}

    mg_fx, err_fx = run_mg_json(machgraph_bin, "fixups", path, env)
    if err_fx:
        return {"path": path, "arch": arch, "seconds": round(time.monotonic() - t0, 3), "failure": err_fx}

    mg_cs, err_cs = run_mg_json(machgraph_bin, "codesign", path, env)
    if err_cs:
        return {"path": path, "arch": arch, "seconds": round(time.monotonic() - t0, 3), "failure": err_cs}

    assert mg_info is not None and mg_fx is not None and mg_cs is not None

    # 1. Compare `info` vs `otool -l`
    if mg_info.get("fileName") != os.path.basename(path):
        mismatches.append(f"info.fileName: mg={mg_info.get('fileName')!r} != {os.path.basename(path)!r}")

    expected_arch_label = "arm64e (PAC)" if arch == "arm64e" else "arm64"
    if mg_info.get("architecture") != expected_arch_label:
        mismatches.append(f"info.architecture: mg={mg_info.get('architecture')!r} != {expected_arch_label!r}")

    mg_segs = [
        (s["name"], s["vmaddr"], s["vmsize"], s["fileoff"], s["filesize"])
        for s in mg_info.get("segments", [])
    ]
    if mg_segs != ref_otool["segments"]:
        mismatches.append(
            f"info.segments mismatch (mg={len(mg_segs)} vs otool={len(ref_otool['segments'])})"
        )

    mg_secs = [
        (s["segment"], s["section"], s["addr"], s["size"], s["offset"])
        for s in mg_info.get("sections", [])
    ]
    if mg_secs != ref_otool["sections"]:
        mismatches.append(
            f"info.sections mismatch (mg={len(mg_secs)} vs otool={len(ref_otool['sections'])})"
        )

    mg_uuid = (mg_info.get("uuid") or None)
    if isinstance(mg_uuid, str):
        mg_uuid = mg_uuid.upper()
    if mg_uuid != ref_otool["uuid"]:
        mismatches.append(f"info.uuid: mg={mg_uuid!r} != otool={ref_otool['uuid']!r}")

    if mg_info.get("entryPoint") != ref_otool["entry_point"]:
        mismatches.append(
            f"info.entryPoint: mg={mg_info.get('entryPoint')!r} != otool={ref_otool['entry_point']!r}"
        )

    # 2. Compare `fixups` vs `dyld_info -fixups`
    mg_fixup_rows = mg_fx.get("fixups", [])
    if not ref_otool["has_chained_fixups"]:
        if mg_fx.get("count", 0) != 0 or len(mg_fixup_rows) != 0:
            mismatches.append(
                f"fixups: binary has no LC_DYLD_CHAINED_FIXUPS, expected 0 chained fixups, got {mg_fx.get('count')}"
            )
    else:
        if mg_fx.get("count") != len(ref_fixups):
            mismatches.append(
                f"fixups.count: mg={mg_fx.get('count')} != dyld_info={len(ref_fixups)}"
            )
        mg_by_loc = {row["location"]: row for row in mg_fixup_rows}
        if set(mg_by_loc.keys()) != set(ref_fixups.keys()):
            diff_n = len(set(mg_by_loc.keys()) ^ set(ref_fixups.keys()))
            mismatches.append(f"fixups.locations: {diff_n} location(s) differ from dyld_info")
        else:
            for loc, (exp_kind, exp_tgt, exp_sym) in ref_fixups.items():
                got_row = mg_by_loc[loc]
                if got_row.get("kind") != exp_kind:
                    mismatches.append(
                        f"fixups[{hex(loc)}].kind: mg={got_row.get('kind')!r} != {exp_kind!r}"
                    )
                    break
                if exp_tgt is not None and got_row.get("targetAddress") != exp_tgt:
                    mismatches.append(
                        f"fixups[{hex(loc)}].targetAddress: mg={got_row.get('targetAddressHex')} != {hex(exp_tgt)}"
                    )
                    break
                if exp_sym is not None and got_row.get("symbolName") != exp_sym:
                    mismatches.append(
                        f"fixups[{hex(loc)}].symbolName: mg={got_row.get('symbolName')!r} != {exp_sym!r}"
                    )
                    break

    # 3. Compare `codesign` vs `/usr/bin/codesign -a <slice> -dvvv`
    if bool(mg_cs.get("isSigned")) != ref_cs["is_signed"]:
        mismatches.append(
            f"codesign.isSigned: mg={mg_cs.get('isSigned')} != codesign={ref_cs['is_signed']}"
        )
    elif ref_cs["is_signed"]:
        if bool(mg_cs.get("isAdHoc")) != ref_cs["is_adhoc"]:
            mismatches.append(
                f"codesign.isAdHoc: mg={mg_cs.get('isAdHoc')} != codesign={ref_cs['is_adhoc']}"
            )
        if (mg_cs.get("identifier") or "") != ref_cs["identifier"]:
            mismatches.append(
                f"codesign.identifier: mg={mg_cs.get('identifier')!r} != codesign={ref_cs['identifier']!r}"
            )
        if mg_cs.get("teamIdentifier") != ref_cs["team_identifier"]:
            mismatches.append(
                f"codesign.teamIdentifier: mg={mg_cs.get('teamIdentifier')!r} != codesign={ref_cs['team_identifier']!r}"
            )
        mg_cdhash = (mg_cs.get("cdHash") or "").lower()
        if ref_cs["cdhash_full"]:
            if mg_cdhash != ref_cs["cdhash_full"]:
                mismatches.append(
                    f"codesign.cdHash: mg={mg_cdhash!r} != codesign={ref_cs['cdhash_full']!r}"
                )
        elif ref_cs["cdhash_short"]:
            if not mg_cdhash.startswith(ref_cs["cdhash_short"]):
                mismatches.append(
                    f"codesign.cdHash: mg={mg_cdhash!r} does not match prefix {ref_cs['cdhash_short']!r}"
                )

    return {
        "path": path,
        "arch": arch,
        "segments": len(mg_segs),
        "sections": len(mg_secs),
        "fixups": mg_fx.get("count", 0),
        "has_chained_fixups": ref_otool["has_chained_fixups"],
        "is_signed": bool(mg_cs.get("isSigned")),
        "mismatches": mismatches,
        "seconds": round(time.monotonic() - t0, 3),
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
    parser.add_argument("--json-out", default=None, help="optional path to write JSON summary")
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

    env_isolated = os.environ.get("MACHGRAPH_ISOLATED_HOME")
    temp_home_ctx = None
    if not env_isolated:
        temp_home_ctx = tempfile.TemporaryDirectory(prefix="machgraph-macho-home-")
        isolated_home = temp_home_ctx.name
    else:
        isolated_home = env_isolated

    t0 = time.monotonic()
    try:
        worker_count = 1 if len(candidates) <= 1 else max(1, args.workers)
        if worker_count == 1:
            rows = [check_one_binary(p, args.machgraph, isolated_home) for p in candidates]
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                rows = list(pool.map(lambda p: check_one_binary(p, args.machgraph, isolated_home), candidates))
    finally:
        if temp_home_ctx is not None:
            temp_home_ctx.cleanup()
    wall_seconds = round(time.monotonic() - t0, 2)

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    print(f"=== MachGraph Mach-O Differential Check ({corpus_name}) ===")
    print(f"Date (UTC):  {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"MachGraph:   {sanitize_repo_label(args.machgraph)}")
    print("")

    skipped = 0
    compared = 0
    failures: List[Dict[str, Any]] = []
    mismatch_files: List[Dict[str, Any]] = []
    total_segments = 0
    total_sections = 0
    total_fixups = 0
    signed_count = 0

    print_each = args.verbose or corpus_name != "full"

    for r in rows:
        if "skipped" in r:
            skipped += 1
            continue
        if "failure" in r:
            failures.append({"file": r["path"], "error": r["failure"]})
            print(f"[CRASH/FAIL] {r['path']}: {r['failure']}")
            continue

        compared += 1
        total_segments += r["segments"]
        total_sections += r["sections"]
        total_fixups += r["fixups"]
        if r["is_signed"]:
            signed_count += 1

        if r["mismatches"]:
            mismatch_files.append({"file": r["path"], "arch": r["arch"], "mismatches": r["mismatches"]})
            print(f"[FAIL] {r['path']} ({r['arch']}): " + "; ".join(r["mismatches"]))
        elif print_each:
            print(
                f"[PASS] {r['path']} ({r['arch']}): segments={r['segments']} "
                f"sections={r['sections']} fixups={r['fixups']} signed={r['is_signed']} ({r['seconds']:.2f}s)"
            )

    passed = len(failures) == 0 and len(mismatch_files) == 0 and compared > 0
    verdict = "PASS" if passed else "FAIL"
    print("")
    print(
        f"[{verdict}] Summary ({corpus_name}): candidates={len(candidates)} compared={compared} "
        f"skipped_no_arm64={skipped} failures={len(failures)} mismatched_files={len(mismatch_files)} "
        f"segments={total_segments} sections={total_sections} fixups={total_fixups} "
        f"signed={signed_count} elapsed={wall_seconds:.2f}s"
    )

    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        payload = {
            "date": utc_now.strftime("%Y-%m-%d"),
            "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "corpus": corpus_name,
            "verdict": verdict,
            "machgraph_binary": sanitize_repo_label(args.machgraph),
            "summary": {
                "candidate_macho_files": len(candidates),
                "compared_files": compared,
                "skipped_no_arm64_slice": skipped,
                "failures": len(failures),
                "mismatched_files": len(mismatch_files),
                "total_segments": total_segments,
                "total_sections": total_sections,
                "total_chained_fixups": total_fixups,
                "signed_files": signed_count,
                "elapsed_seconds": wall_seconds,
            },
            "failures": failures,
            "mismatches": mismatch_files,
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
