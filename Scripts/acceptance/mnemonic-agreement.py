#!/usr/bin/env python3
"""Mnemonic agreement between `machgraph disasm` and `xcrun llvm-objdump --macho -d` for one binary.

Usage:
  mnemonic-agreement.py <binary> [--arch arm64e] [--machgraph <path>]
                        [--min-agreement <percent>] [--max-wrong <n>]

Both tools disassemble `__TEXT,__text` of the chosen slice using the fixed
reference command and single shared 3-rule normalization table in
`mnemonic_normalization.py`.

The result line starts with [PASS]/[FAIL] when a threshold was given and with [INFO] when the run only
measures. Exit status: 0 on success, 1 if a threshold is missed or the two listings do not line up.
"""

import argparse
import collections
import os
import re
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from mnemonic_normalization import (  # noqa: E402
    NORMALIZATION_SUMMARY,
    REFERENCE_COMMAND_TEMPLATE,
    build_reference_command,
    classify_mnemonic_pair,
)

_INSN_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")
MIN_REFERENCE_INSTRUCTIONS = 100


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
    return candidates[1]


def reference_listing(binary: str, arch: str) -> dict:
    raw = subprocess.run(
        build_reference_command(binary, arch),
        capture_output=True,
        check=True,
    ).stdout
    out = raw.decode("utf-8", errors="replace")
    ref = {}
    for line in out.splitlines():
        if line.strip() == "Contents of (__TEXT,__text) section":
            break
        m = _INSN_LINE_RE.match(line)
        if m:
            ref[int(m.group(1), 16)] = m.group(2).lower()
    return ref


def machgraph_listing(machgraph_bin: str, binary: str) -> dict:
    env = dict(os.environ)
    env["SWIFT_BACKTRACE"] = "enable=no"
    isolated_home = env.get("MACHGRAPH_ISOLATED_HOME")
    temp_ctx = None
    if not isolated_home:
        temp_ctx = tempfile.TemporaryDirectory(prefix="machgraph-home-")
        isolated_home = temp_ctx.name
    try:
        size_mib = os.stat(binary).st_size / (1024.0 * 1024.0)
    except OSError:
        size_mib = 0.0
    timeout_sec = min(900.0, max(60.0, 60.0 + size_mib * 5.0))
    try:
        env.update(HOME=isolated_home, CFFIXED_USER_HOME=isolated_home)
        raw = subprocess.run(
            [machgraph_bin, "disasm", binary],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout_sec,
            check=True,
            env=env,
        ).stdout
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()

    out = raw.decode("utf-8", errors="replace")
    insns = {}
    in_text_section = True
    saw_section_header = False
    for line in out.splitlines():
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
            insns[int(parts[0], 16)] = parts[2].strip().lower()
    return insns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary")
    parser.add_argument("--arch", default="arm64e")
    parser.add_argument("--machgraph", default=default_machgraph_bin())
    parser.add_argument("--min-agreement", type=float, default=None, help="fail below this agreement percentage")
    parser.add_argument("--max-wrong", type=int, default=None, help="fail above this many wrong mnemonics")
    parser.add_argument("--label", default=None, help="prefix for the result line")
    args = parser.parse_args()

    ref = reference_listing(args.binary, args.arch)
    mine = machgraph_listing(args.machgraph, args.binary)
    if len(ref) == 0 and len(mine) > 0:
        print(
            f"[FAIL] empty reference listing for {args.binary}: llvm-objdump decoded 0 instructions "
            f"in __TEXT,__text while machgraph decoded {len(mine)}",
            file=sys.stderr,
        )
        return 1
    if len(ref) < MIN_REFERENCE_INSTRUCTIONS:
        print(
            f"[FAIL] llvm-objdump reference for {args.binary} has only {len(ref)} instructions "
            f"(< {MIN_REFERENCE_INSTRUCTIONS} minimum)",
            file=sys.stderr,
        )
        return 1

    total = agree = 0
    unknown = collections.Counter()
    wrong = collections.Counter()
    missing = 0
    for addr, raw_ref in ref.items():
        total += 1
        got = mine.get(addr)
        if got is None:
            missing += 1
            continue
        kind, norm_ref, norm_mg = classify_mnemonic_pair(raw_ref, got)
        if kind == "agree":
            agree += 1
        elif kind == "unknown":
            unknown[norm_ref] += 1
        else:
            wrong[(norm_ref, norm_mg)] += 1

    mg_only_inst = 0
    for addr in sorted(mine.keys()):
        if addr in ref:
            continue
        if mine[addr] == ".inst":
            mg_only_inst += 1
        else:
            wrong[("<omitted>", mine[addr])] += 1

    pct = 100.0 * agree / total
    n_unknown = sum(unknown.values())
    n_wrong = sum(wrong.values())
    failures = []
    if missing:
        failures.append(f"{missing} reference addresses missing from machgraph disasm")
    if args.min_agreement is not None and pct < args.min_agreement:
        failures.append(f"agreement {pct:.4f}% < {args.min_agreement}%")
    if args.max_wrong is not None and n_wrong > args.max_wrong:
        failures.append(f"wrong mnemonics {n_wrong} > {args.max_wrong}")

    label = args.label or f"disasm {args.binary} vs llvm-objdump"
    has_threshold = args.min_agreement is not None or args.max_wrong is not None
    # Without thresholds this is a measurement, not a verdict: print INFO so "wrong > 0" is never shown as a pass.
    status = "FAIL" if failures else ("PASS" if has_threshold else "INFO")
    print(
        f"[{status}] {label} (after mnemonic normalization: {NORMALIZATION_SUMMARY}): "
        f"total={total} agree={agree} ({pct:.2f}%) unknown={n_unknown} wrong={n_wrong} "
        f"mg_only_inst={mg_only_inst}"
    )
    if unknown:
        print("        unknown (.inst) by reference mnemonic: " + ", ".join(f"{k}={v}" for k, v in unknown.most_common(12)))
    if wrong:
        print("        wrong (reference, machgraph): " + ", ".join(f"{k[0]}!={k[1]} x{v}" for k, v in wrong.most_common(12)))
    for failure in failures:
        print(f"        {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
