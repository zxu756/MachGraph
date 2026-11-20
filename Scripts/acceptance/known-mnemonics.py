#!/usr/bin/env python3
"""Generate and verify `Sources/MachA64Decoder/A64KnownMnemonics.swift` from LLVM reference outputs.

Usage:
  python3 -I Scripts/acceptance/known-mnemonics.py generate [--output <path>]
  python3 -I Scripts/acceptance/known-mnemonics.py check [--output <path>]

Sources (union, lowercase, `.long` excluded):
  1. All repository reference tables: `Fixtures/a64/*.tsv` (globbed dynamically),
     `Fixtures/hint_llvm_table.tsv`, and `Fixtures/sys_crn7_8_llvm_table.tsv`.
  2. Reference `llvm-objdump` output on `differential.STANDARD_FILES` (`/bin/ls`, `/usr/bin/ssh`, `/usr/bin/vim`).
  3. Reference `llvm-objdump` output on random words: seeds `17` and `20261117`, `100,000` words each.
"""

import argparse
from dataclasses import dataclass
import difflib
import glob
import importlib.util
import os
import subprocess
import sys
import tempfile
from typing import Iterable, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import differential  # noqa: E402
import mnemonic_normalization  # noqa: E402


def _load_sibling_module(module_name: str, filename: str):
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {filename!r} from {path!r}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


encoding_table = _load_sibling_module("_known_mnem_encoding_table", "encoding-table.py")
encoding_fuzz = _load_sibling_module("_known_mnem_encoding_fuzz", "encoding-fuzz.py")

GENERATION_COMMAND = "python3 -I Scripts/acceptance/known-mnemonics.py generate"
DEFAULT_OUTPUT_PATH = os.path.join(REPO_ROOT, "Sources", "MachA64Decoder", "A64KnownMnemonics.swift")
M1_TABLE_FILENAMES: Tuple[str, ...] = ("hint_llvm_table.tsv", "sys_crn7_8_llvm_table.tsv")
FUZZ_SEEDS: Tuple[int, ...] = (17, 20261117)
FUZZ_WORDS_PER_SEED = 100_000


class _UsageError(Exception):
    """Raised on CLI usage errors (exit code 2)."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(f"{self.prog}: error: {message}")


@dataclass(frozen=True)
class CollectedMnemonicSources:
    llvm_version: str
    tables: Set[str]
    standard: Set[str]
    random_words: Set[str]
    a64_tables: Optional[Set[str]] = None
    m1_tables: Optional[Set[str]] = None


def _clean_mnemonic_set(items: Iterable[str]) -> Set[str]:
    cleaned: Set[str] = set()
    for raw in items:
        tok = raw.strip().lower()
        if tok and tok != ".long":
            cleaned.add(tok)
    return cleaned


def extract_mnemonics_from_table_text(text: str) -> Set[str]:
    """Extract reference mnemonics from TSV content (skip `#` and blanks, column 2 word 1, lowercased, no `.long`)."""
    found: Set[str] = set()
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = raw_line.split("\t")
        if len(parts) < 2:
            raise ValueError(f"line {line_no}: expected at least 2 tab-separated columns, got {raw_line!r}")
        col2 = parts[1].strip()
        if not col2:
            raise ValueError(f"line {line_no}: empty reference mnemonic column")
        mnem = col2.split()[0].lower()
        if mnem != ".long":
            found.add(mnem)
    return found


def collect_table_mnemonics_breakdown(repo_root: str = REPO_ROOT) -> Tuple[Set[str], Set[str], Set[str]]:
    """Return `(all_tables, a64_group_tables, m1_tables)` from `<repo_root>/Fixtures`."""
    fixtures_dir = os.path.join(repo_root, "Fixtures")
    a64_paths = sorted(glob.glob(os.path.join(fixtures_dir, "a64", "*.tsv")))
    if not a64_paths:
        raise FileNotFoundError(f"no TSV tables found under {os.path.join(fixtures_dir, 'a64')}")

    a64_mnemonics: Set[str] = set()
    for path in a64_paths:
        with open(path, "r", encoding="utf-8") as fh:
            a64_mnemonics |= extract_mnemonics_from_table_text(fh.read())

    m1_mnemonics: Set[str] = set()
    for fname in M1_TABLE_FILENAMES:
        m1_path = os.path.join(fixtures_dir, fname)
        if not os.path.isfile(m1_path):
            raise FileNotFoundError(f"missing M1 reference table: {m1_path}")
        with open(m1_path, "r", encoding="utf-8") as fh:
            m1_mnemonics |= extract_mnemonics_from_table_text(fh.read())

    return (a64_mnemonics | m1_mnemonics, a64_mnemonics, m1_mnemonics)


def collect_table_mnemonics(repo_root: str = REPO_ROOT) -> Set[str]:
    """Collect reference mnemonics across `Fixtures/a64/*.tsv` and the two M1 reference tables."""
    all_tables, _, _ = collect_table_mnemonics_breakdown(repo_root=repo_root)
    return all_tables


def collect_standard_mnemonics(files: Sequence[str] = tuple(differential.STANDARD_FILES)) -> Set[str]:
    """Collect reference mnemonics from `differential.STANDARD_FILES` via `build_reference_command`."""
    found: Set[str] = set()
    for path in files:
        arch = differential.select_arm64_slice(path)
        if arch is None:
            raise RuntimeError(f"no arm64/arm64e slice found in standard binary: {path}")
        ref_timeout = max(300.0, differential.per_file_timeout_seconds(path))
        ref_cmd = mnemonic_normalization.build_reference_command(path, arch)
        proc = subprocess.run(
            ref_cmd,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=ref_timeout,
        )
        if proc.returncode != 0:
            err_snip = proc.stderr.decode("utf-8", errors="replace").strip()[:240]
            raise RuntimeError(f"llvm-objdump exited {proc.returncode} on {path}: {err_snip}")

        ref_text = proc.stdout.decode("utf-8", errors="replace")
        entries: List[Tuple[int, str]] = []
        for line in ref_text.splitlines():
            if line.strip() == "Contents of (__TEXT,__text) section":
                break
            m = differential._REF_INSN_RE.match(line)
            if m:
                addr = int(m.group(1), 16)
                raw_mnem = m.group(2).strip().lower()
                entries.append((addr, raw_mnem))

        if not entries:
            raise RuntimeError(f"llvm-objdump decoded 0 instructions on standard binary: {path}")

        bad_neon = mnemonic_normalization.find_non_generic_neon_mnemonic(entries)
        if bad_neon is not None:
            bad_addr, bad_mnem = bad_neon
            raise RuntimeError(
                f"non-generic Neon syntax in reference output for {path}: '{bad_mnem}' at 0x{bad_addr:x}"
            )

        for _, mnem in entries:
            if mnem and mnem != ".long":
                found.add(mnem)
    return found


def collect_random_word_mnemonics(
    seeds: Sequence[int] = FUZZ_SEEDS,
    count_per_seed: int = FUZZ_WORDS_PER_SEED,
) -> Set[str]:
    """Collect reference mnemonics from random 32-bit words compiled and disassembled in a temp dir."""
    found: Set[str] = set()
    with tempfile.TemporaryDirectory(prefix="machgraph-known-mnemonics-") as tmp:
        for seed in seeds:
            words = encoding_fuzz.generate_random_words(seed, count_per_seed)
            bin_path = os.path.join(tmp, f"random_seed_{seed}.macho")
            encoding_table.compile_inst_words_macho(words, bin_path)
            rows = encoding_table.disassemble_reference_macho(bin_path, expected_count=len(words))
            for _, mnem, _ in rows:
                cleaned = mnem.strip().lower()
                if cleaned and cleaned != ".long":
                    found.add(cleaned)
    return found


def collect_all_sources(repo_root: str = REPO_ROOT) -> CollectedMnemonicSources:
    llvm_ver = encoding_table.query_llvm_version()
    tables_all, tables_a64, tables_m1 = collect_table_mnemonics_breakdown(repo_root=repo_root)
    standard_set = collect_standard_mnemonics()
    random_set = collect_random_word_mnemonics()
    return CollectedMnemonicSources(
        llvm_version=llvm_ver,
        tables=tables_all,
        standard=standard_set,
        random_words=random_set,
        a64_tables=tables_a64,
        m1_tables=tables_m1,
    )


def render_swift_source(
    sources: CollectedMnemonicSources,
    generation_command: str = GENERATION_COMMAND,
) -> str:
    tables_clean = _clean_mnemonic_set(sources.tables)
    standard_clean = _clean_mnemonic_set(sources.standard)
    random_clean = _clean_mnemonic_set(sources.random_words)
    union_sorted = sorted(tables_clean | standard_clean | random_clean)

    if sources.a64_tables is not None and sources.m1_tables is not None:
        a64_cnt = len(_clean_mnemonic_set(sources.a64_tables))
        m1_cnt = len(_clean_mnemonic_set(sources.m1_tables))
        tables_detail = (
            f"{len(tables_clean)} "
            f"(Fixtures/a64/*.tsv: {a64_cnt}, Fixtures/hint_llvm_table.tsv + sys_crn7_8_llvm_table.tsv: {m1_cnt})"
        )
    else:
        tables_detail = f"{len(tables_clean)}"

    seeds_str = ", ".join(str(s) for s in FUZZ_SEEDS)
    std_str = ", ".join(differential.STANDARD_FILES)

    lines: List[str] = [
        "// Auto-generated by MachGraph known-mnemonics harness — DO NOT EDIT MANUALLY.\n",
        f"// Generation command: {generation_command}\n",
        f"// LLVM version: {sources.llvm_version}\n",
        "// Source mnemonic counts (excluding .long):\n",
        f"//   - Reference tables: {tables_detail}\n",
        f"//   - Standard corpus ({std_str}): {len(standard_clean)}\n",
        f"//   - Random words (seeds {seeds_str} x {FUZZ_WORDS_PER_SEED:,}): {len(random_clean)}\n",
        f"// Total unique mnemonics: {len(union_sorted)}\n",
        "\n",
        "public enum A64KnownMnemonics {\n",
        "    public static let all: Set<String> = [\n",
    ]
    for mnem in union_sorted:
        lines.append(f'        "{mnem}",\n')
    lines.extend(
        [
            "    ]\n",
            "}\n",
        ]
    )
    return "".join(lines)


def _sanitize_label(path: str) -> str:
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, REPO_ROOT)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return os.path.basename(abs_path)


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="known-mnemonics.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand")

    gen = sub.add_parser("generate", help="generate Sources/MachA64Decoder/A64KnownMnemonics.swift")
    gen.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="output Swift file path")

    chk = sub.add_parser("check", help="regenerate in memory and compare byte-for-byte with committed file")
    chk.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="committed Swift file path to verify")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.subcommand not in ("generate", "check"):
            raise _UsageError("must specify subcommand 'generate' or 'check'")
    except _UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    output_path = args.output
    label = _sanitize_label(output_path)

    if args.subcommand == "check" and not os.path.isfile(output_path):
        print(f"[FAIL] {label}: committed file does not exist", file=sys.stderr)
        return 1

    try:
        sources = collect_all_sources(repo_root=REPO_ROOT)
        rendered = render_swift_source(sources)
    except Exception as exc:
        print(f"[FAIL] {args.subcommand}: {exc}", file=sys.stderr)
        return 1

    expected_bytes = rendered.encode("utf-8")
    total_cnt = len(_clean_mnemonic_set(sources.tables) | _clean_mnemonic_set(sources.standard) | _clean_mnemonic_set(sources.random_words))

    if args.subcommand == "generate":
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "wb") as fh:
            fh.write(expected_bytes)
        print(
            f"[GENERATED] {label}: total={total_cnt} "
            f"(tables={len(_clean_mnemonic_set(sources.tables))}, "
            f"standard={len(_clean_mnemonic_set(sources.standard))}, "
            f"random={len(_clean_mnemonic_set(sources.random_words))})"
        )
        return 0

    with open(output_path, "rb") as fh:
        actual_bytes = fh.read()

    if actual_bytes == expected_bytes:
        print(
            f"[PASS] {label}: byte-identical ({len(expected_bytes)} bytes, {total_cnt} mnemonics)"
        )
        return 0

    actual_text = actual_bytes.decode("utf-8", errors="replace")
    diff_lines = list(
        difflib.unified_diff(
            actual_text.splitlines(keepends=True),
            rendered.splitlines(keepends=True),
            fromfile=f"committed/{label}",
            tofile=f"regenerated/{label}",
        )
    )
    print(
        f"[FAIL] {label}: differs from regenerated output "
        f"(committed={len(actual_bytes)} bytes, regenerated={len(expected_bytes)} bytes)",
        file=sys.stderr,
    )
    if diff_lines:
        sys.stderr.writelines(diff_lines[:200])
        if len(diff_lines) > 200:
            print(f"... ({len(diff_lines) - 200} more diff lines truncated)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
