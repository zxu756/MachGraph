#!/usr/bin/env python3
"""Single source of truth for ARM64 mnemonic normalization in differential checks.

Both `mnemonic-agreement.py` and `differential.py` import this module so the
allowed normalization table and fixed reference command exist in one place.

Policy (fixed by `02-machgraph.md`, M1 item 3 and M2 item 1 / D-M2-1):
  - Rule 3 (Darwin vector arrangement suffix) has been removed now that the
    reference command enables `-mllvm=-aarch64-neon-syntax=generic`.
  - Only two rules remain (`wide_immediate_mov` and `permanently_undefined_udf`),
    and this table may only shrink (to zero in M2), never grow.
"""

import os
import re
import subprocess
from typing import Iterable, List, Optional, Tuple

REFERENCE_COMMAND_TEMPLATE = (
    "xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands "
    "--arch=<slice> --mcpu=apple-m1 --mattr=+bti "
    "-mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>"
)


def build_reference_command(binary: str, arch: str) -> List[str]:
    """Return the fixed reference `llvm-objdump` argv for `<binary>` and `<arch>`."""
    return [
        "xcrun",
        "llvm-objdump",
        "--macho",
        "-d",
        "--no-show-raw-insn",
        "--no-symbolic-operands",
        f"--arch={arch}",
        "--mcpu=apple-m1",
        "--mattr=+bti",
        "-mllvm=-aarch64-neon-syntax=generic",
        "--section=__TEXT,__text",
        binary,
    ]


# Declarative table of the ONLY permitted normalization rules, each with its
# architectural rationale. Rule 3 (Darwin vector arrangement suffix) was removed
# in M2 Stage 1 under D-M2-1.
NORMALIZATION_RULES = (
    {
        "id": "wide_immediate_mov",
        "reference": "mov",
        "machgraph": ("movz", "movn"),
        "reason": (
            "llvm-objdump prints the preferred alias 'mov' for MOVZ/MOVN "
            "wide-immediate moves when representable as a synthesized immediate, "
            "whereas MachGraph prints the underlying 'movz'/'movn' mnemonic "
            "(scheduled for M2)."
        ),
    },
    {
        "id": "permanently_undefined_udf",
        "reference": "udf",
        "machgraph": (".inst",),
        "reason": (
            "llvm-objdump prints 'udf' for permanently-undefined A64 words "
            "(0x0000_0000..0x0000_ffff), whereas MachGraph emits raw '.inst' "
            "directives for undefined encodings (scheduled for M2)."
        ),
    },
)

NORMALIZATION_SUMMARY = "movz/movn->mov, udf->.inst"

_NEON_ARRANGEMENT_SUFFIX_RE = re.compile(
    r"^[a-z0-9_]+\.(?:16b|8b|8h|4h|2h|4s|2s|2d|1d|1q|b|h|s|d|q)$"
)
_GENERIC_NEON_OPERAND_RE = re.compile(
    r"\bv(?:3[01]|[12]?[0-9])\.(?:16b|8b|8h|4h|2h|4s|2s|2d|1d|1q|b|h|s|d|q)\b"
)
_SAMPLE_INSN_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\t(\S+)(?:\t(.*))?$")


def has_neon_arrangement_suffix(mnemonic: str) -> bool:
    """Return True if `mnemonic` carries an Apple/Darwin Neon arrangement suffix (excluding `b.<cond>`)."""
    lowered = mnemonic.strip().lower()
    if lowered.startswith(("b.", "bc.")):
        return False
    return bool(_NEON_ARRANGEMENT_SUFFIX_RE.match(lowered))


def find_non_generic_neon_mnemonic(
    entries: Iterable[Tuple[int, str]],
) -> Optional[Tuple[int, str]]:
    """Return `(address, mnemonic)` for the first Darwin-suffixed Neon mnemonic, or `None`."""
    for addr, raw_mnem in entries:
        if has_neon_arrangement_suffix(raw_mnem):
            return (addr, raw_mnem.strip().lower())
    return None


def verify_reference_generic_neon_syntax(
    sample_binary: str = "/bin/ls",
    arch: str = "arm64e",
) -> Optional[str]:
    """Sample-check `llvm-objdump` output to confirm `-mllvm=-aarch64-neon-syntax=generic` is honored.

    Returns `None` when generic Neon syntax is confirmed, or an error string on failure.
    """
    if not os.path.isfile(sample_binary):
        return f"generic Neon syntax self-check failed: sample binary not found: {sample_binary}"
    try:
        proc = subprocess.run(
            build_reference_command(sample_binary, arch),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=60.0,
        )
    except subprocess.TimeoutExpired:
        return f"generic Neon syntax self-check timed out on {sample_binary}"
    except OSError as exc:
        return f"generic Neon syntax self-check failed to launch llvm-objdump: {exc}"

    if proc.returncode != 0:
        err_snip = proc.stderr.decode("utf-8", errors="replace").strip()[:240]
        return (
            f"generic Neon syntax self-check failed: llvm-objdump exited {proc.returncode} "
            f"on {sample_binary}: {err_snip}"
        )

    text = proc.stdout.decode("utf-8", errors="replace")
    insn_count = 0
    generic_neon_operands = 0
    for line in text.splitlines():
        if line.strip() == "Contents of (__TEXT,__text) section":
            break
        m = _SAMPLE_INSN_LINE_RE.match(line)
        if not m:
            continue
        insn_count += 1
        addr = int(m.group(1), 16)
        raw_mnem = m.group(2).lower()
        raw_ops = (m.group(3) or "").split(";")[0].strip().lower()
        if has_neon_arrangement_suffix(raw_mnem):
            return (
                f"generic Neon syntax self-check failed on {sample_binary}: "
                f"reference output contains arrangement-suffixed mnemonic '{raw_mnem}' at 0x{addr:x}"
            )
        if _GENERIC_NEON_OPERAND_RE.search(raw_ops):
            generic_neon_operands += 1

    if insn_count >= 100 and generic_neon_operands == 0:
        return (
            f"generic Neon syntax self-check failed on {sample_binary}: "
            f"sampled {insn_count} instructions without observing any generic Neon operand (vN.<arrangement>)"
        )
    return None


def normalize_reference_mnemonic(mnemonic: str) -> str:
    """Lowercase and trim a reference mnemonic without stripping any arrangement suffix."""
    return mnemonic.strip().lower()


def mnemonics_agree(normalized_reference: str, machgraph_mnemonic: str) -> bool:
    """Compare a reference mnemonic against a MachGraph mnemonic under Rules 1 and 2."""
    if normalized_reference == ".long":
        return False
    mg = machgraph_mnemonic.strip().lower()
    if mg == normalized_reference:
        return True
    if normalized_reference == "mov" and mg in ("movz", "movn"):  # Rule 1
        return True
    if normalized_reference == "udf" and mg == ".inst":  # Rule 2
        return True
    return False


def classify_mnemonic_pair(raw_reference: str, raw_machgraph: str) -> Tuple[str, str, str]:
    """Classify one instruction's mnemonics as
    ('agree' | 'reference_long_machgraph_inst' | 'unknown' | 'wrong', norm_ref, norm_mg).
    """
    norm_ref = normalize_reference_mnemonic(raw_reference)
    norm_mg = raw_machgraph.strip().lower()
    if mnemonics_agree(norm_ref, norm_mg):
        return ("agree", norm_ref, norm_mg)
    if norm_ref == ".long" and norm_mg == ".inst":
        return ("reference_long_machgraph_inst", norm_ref, norm_mg)
    if norm_mg == ".inst":
        return ("unknown", norm_ref, norm_mg)
    return ("wrong", norm_ref, norm_mg)
