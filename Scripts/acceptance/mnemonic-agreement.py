#!/usr/bin/env python3
"""Mnemonic agreement between `machgraph disasm` and `xcrun llvm-objdump -d` for one binary.

Usage:
  mnemonic-agreement.py <binary> [--arch arm64e] [--machgraph <path>]
                        [--min-agreement <percent>] [--max-wrong <n>]

Both tools disassemble `__TEXT,__text` of the chosen slice. Instructions are matched by address and only
the mnemonic is compared, after the normalization below. Every README agreement figure is produced by
this script, so the README always says "after mnemonic normalization".

Normalization rules (the only ones allowed; the acceptance document fixes this set):

  1. Reference `mov`  == MachGraph `movz` or `movn`.
     LLVM prints the preferred alias `mov` for MOVZ/MOVN wide-immediate moves; MachGraph still prints
     the underlying instruction name.
  2. Reference `udf`  == MachGraph `.inst`.
     MachGraph prints permanently-undefined words as raw `.inst` data.
  3. A vector arrangement suffix on the reference mnemonic is dropped before comparing
     (`fmov.2d` -> `fmov`). Condition codes (`b.eq`, `b.ne`, ...) are part of the mnemonic and are kept.

Classification of each instruction after normalization:
  agree    mnemonics are equal
  unknown  MachGraph printed `.inst` for a word LLVM decodes (not recognized; not counted as wrong)
  wrong    MachGraph printed a different mnemonic

Exit status: 0 on success, 1 if a threshold is missed or the two listings do not line up.
"""

import argparse
import collections
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def normalize_reference(mnemonic: str) -> str:
    """Rule 3: drop a vector arrangement suffix, keep `b.<cond>`."""
    if mnemonic.startswith("b."):
        return mnemonic
    return re.sub(r"\.\w+$", "", mnemonic)


def mnemonics_agree(reference: str, machgraph: str) -> bool:
    if machgraph == reference:
        return True
    if reference == "mov" and machgraph in ("movz", "movn"):  # rule 1
        return True
    if reference == "udf" and machgraph == ".inst":  # rule 2
        return True
    return False


def reference_listing(binary: str, arch: str) -> dict:
    out = subprocess.run(
        ["xcrun", "llvm-objdump", "-d", "--no-show-raw-insn", f"--arch={arch}", "--section=__TEXT,__text", binary],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    ref = {}
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$", line)
        if m:
            ref[int(m.group(1), 16)] = m.group(2).lower()
    return ref


def machgraph_listing(machgraph_bin: str, binary: str) -> dict:
    env = dict(os.environ)
    isolated_home = env.get("MACHGRAPH_ISOLATED_HOME")
    if isolated_home:  # set by m0-quick.sh so the product never touches the real preferences
        env.update(HOME=isolated_home, CFFIXED_USER_HOME=isolated_home)
    out = subprocess.run([machgraph_bin, "disasm", binary], capture_output=True, text=True, check=True, env=env).stdout
    insns = {}
    for line in out.splitlines():
        if not line or line.startswith(";"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].startswith("0x"):
            insns[int(parts[0], 16)] = parts[2].strip().lower()
    return insns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary")
    parser.add_argument("--arch", default="arm64e")
    parser.add_argument("--machgraph", default=os.environ.get("MACHGRAPH_BIN", os.path.join(REPO_ROOT, ".build/debug/MachGraph")))
    parser.add_argument("--min-agreement", type=float, default=None, help="fail below this agreement percentage")
    parser.add_argument("--max-wrong", type=int, default=None, help="fail above this many wrong mnemonics")
    parser.add_argument("--label", default=None, help="prefix for the result line")
    args = parser.parse_args()

    ref = reference_listing(args.binary, args.arch)
    if len(ref) < 100:
        print(f"[FAIL] llvm-objdump reference for {args.binary} has only {len(ref)} instructions", file=sys.stderr)
        return 1
    mine = machgraph_listing(args.machgraph, args.binary)

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
        base = normalize_reference(raw_ref)
        if mnemonics_agree(base, got):
            agree += 1
        elif got == ".inst":
            unknown[base] += 1
        else:
            wrong[(base, got)] += 1

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
    status = "FAIL" if failures else "PASS"
    print(
        f"[{status}] {label} (after mnemonic normalization: movz/movn->mov, udf->.inst, vector suffix dropped): "
        f"total={total} agree={agree} ({pct:.2f}%) unknown={n_unknown} wrong={n_wrong}"
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
