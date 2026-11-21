#!/usr/bin/env python3
"""Control-Flow Graph (CFG) acceptance suite for MachGraph M4 (rows 1-3 and 5).

Usage:
  Scripts/acceptance/m4-cfg-acceptance.py [<standard|quick|full|known-c|perf|file...>]
      [--only <check,...>] [--machgraph <path>] [--json-out <path>] [--txt-out <path>]
      [--record] [--seed <int>] [--sample-size <int>] [--full-all]
      [--workers <n>] [--verbose]

Implemented checks:
  - function-starts (Row 1):
      Independently parses Mach-O / Universal Fat headers and decodes the raw
      `LC_FUNCTION_STARTS` ULEB128 delta table in pure Python, cross-checks 100%
      equality against `xcrun dyld_info -arch <slice> -function_starts <file>`,
      verifies `machgraph info <file> --json` (`functionStarts` and `lcFunctionStarts`,
      with no `0x100000000` header leakage), verifies `machgraph cfg <file> --json`
      satisfies `recovered_text_starts ∪ inlineJumpTableStarts == LC_FUNCTION_STARTS`
      (0 missing, 0 extra, strictly disjoint), and verifies `__TEXT,__objc_stubs`
      contains no fake functions split at `brk`/`hlt`/`udf`/`nop` padding.

  - invariants (Row 2):
      Independently decodes 32-bit ARM64 / ARM64e instructions from raw Mach-O slice
      bytes (without calling MachGraph's decoder or CFG code), resolves imported stub
      symbols via `xcrun otool -arch <slice> -Iv <file>`, solves internal `noreturn`
      wrapper reachability to fixed point, solves dominator sets via iterative RPO
      bitset intersection, and recovers natural loops from independent dominators:
        * I1: Every block ends with a terminator or falls through contiguously into
              the adjacent block (`next.startAddress == block.endAddress`), with zero
              interior terminators; every non-fallthrough `bl` exit block targets a
              verified imported `noreturn` symbol (from `otool -Iv` against the explicit
              `KNOWN_NORETURN_IMPORT_NAMES` table) or an internal function whose every
              reachable path is independently proven non-returning.
        * I2: Intra-function branch and jump-table targets land on a block `startAddress`
              in the same function (with corresponding CFG edge); cross-function tail
              branches land on the `address` of another recovered function; every inline
              jump table is referenced by `adr`, `adrp + add`, or page-aligned `adrp` in
              its owning function, has zero overlap with instruction addresses, and is
              not immediately followed by a `udf` word (guarding against table truncation).
        * I3: Functions and basic blocks are non-overlapping and 4-byte aligned;
              instructions inside each block are strictly contiguous by 4 bytes.
        * I4: All block IDs in `edges`, `predecessorIDs`, `successorIDs`, `dominatorTree`,
              and `naturalLoops` exist and agree; `immediateDominatorID`, `dominatedChildrenIDs`,
              `depth`, `dominanceFrontierIDs`, and `naturalLoops` (`headerBlockID`,
              `latchBlockIDs`, `bodyBlockIDs`, `exitBlockIDs`, `nestingDepth`) match
              independent computation 100%.

  - known-c (Row 3):
      Compiles 8 small C functions (`fn_seq`, `fn_if_else`, `fn_while`, `fn_for`,
      `fn_nested_loop`, `fn_switch5_dense`, `fn_switch10_jumptable`,
      `fn_loop_break_continue`) on the fly in an ephemeral temporary directory with
      `xcrun clang -O0 -arch arm64`, verifies both single-function (`--symbol`) and
      full-file `machgraph cfg --json` outputs against the hand-audited ground-truth
      answer table (audited line-by-line with `xcrun llvm-objdump --macho -d`), and
      additionally runs `function-starts` and `invariants` on the compiled binary.

  - perf (Row 5):
      Measures wall-clock latency (`time.perf_counter()`, median of 3 runs, isolated
      `HOME`) for full-file `machgraph cfg /usr/bin/ssh --json`, full-file
      `machgraph cfg /usr/bin/vim --json`, and single-function
      `machgraph cfg /usr/bin/ssh --symbol _entry --json`, validating output JSON on
      every run and recording `/usr/bin/uptime` before and after. Emits `[WARN]` if
      `ssh` full-file median exceeds `5.0s`; fails if `ssh` exceeds `30.0s` (hang guard).

Corpus tiers:
  - `quick`    : `/bin/ls` (`function-starts` + `invariants` by default)
  - `standard` : `/bin/ls`, `/usr/bin/ssh`, `/usr/bin/vim` (defaults to all 4 checks:
                 `function-starts`, `invariants`, `known-c`, `perf` when `--only` is omitted)
  - `full`     : Discovers all unique Mach-O files under `/bin`, `/usr/bin`, `/usr/sbin`,
                 `/usr/libexec` (same walk + inode dedup as `differential.py`), filters to
                 executable ARM64/ARM64e images, and selects a deterministic fixed-seed
                 sample (`--seed 20261121 --sample-size 40`, always retaining `standard`
                 files; pass `--full-all` or `--sample-size 0` to run every candidate).

Exit status:
  0 when all selected checks pass;
  1 on any mismatch, violation, subprocess crash/timeout, or dirty `--record` worktree;
  2 on invalid CLI arguments.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
import random
import re
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

QUICK_FILES: Tuple[str, ...] = ("/bin/ls",)
STANDARD_FILES: Tuple[str, ...] = ("/bin/ls", "/usr/bin/ssh", "/usr/bin/vim")
FULL_SCAN_ROOTS: Tuple[str, ...] = ("/bin", "/usr/bin", "/usr/sbin", "/usr/libexec")

DEFAULT_FULL_SEED = 20261121
DEFAULT_FULL_SAMPLE_SIZE = 40

AVAILABLE_CHECKS: Tuple[str, ...] = ("function-starts", "invariants", "known-c", "perf")
CORPUS_CHECKS: Tuple[str, ...] = ("function-starts", "invariants")

MAX_CONCURRENT_SUBPROCESSES = 6
MAX_EXAMPLES_PER_CHECK = 8
PER_FILE_TIMEOUT_SECONDS = 90.0
PER_MIB_TIMEOUT_SECONDS = 8.0
MAX_PER_FILE_TIMEOUT_SECONDS = 600.0

SSH_BUDGET_WARN_SECONDS = 5.0
SSH_HANG_FAIL_SECONDS = 30.0
VIM_HANG_FAIL_SECONDS = 90.0
PERF_RUN_COUNT = 3

# Mach-O / Universal binary constants
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE

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
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0x00FFFFFF

MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_DYLINKER = 0x7
MH_BUNDLE = 0x8
SUPPORTED_FILETYPES = frozenset({MH_EXECUTE, MH_DYLIB, MH_DYLINKER, MH_BUNDLE})

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
SECTION_TYPE_MASK = 0x000000FF
S_SYMBOL_STUBS = 0x08

# Explicit allowlist of standard imported `noreturn` functions (unprefixed canonical C/ABI names).
# Verified against ISO C11, POSIX.1-2017, BSD/Darwin Libsystem, compiler-rt, Itanium C++ ABI,
# libunwind, Objective-C runtime, Swift runtime, and system language runtimes (e.g. libperl).
KNOWN_NORETURN_IMPORT_NAMES: frozenset[str] = frozenset(
    {
        # ISO C11 & POSIX process/thread termination & non-local jumps
        "abort",
        "exit",
        "_exit",
        "_Exit",
        "quick_exit",
        "thrd_exit",
        "pthread_exit",
        "longjmp",
        "_longjmp",
        "siglongjmp",
        # BSD / Darwin <err.h>, assertions, compiler-rt SSP, OS crash & Libsystem fatal APIs
        "err",
        "errx",
        "errc",
        "verr",
        "verrx",
        "verrc",
        "__stack_chk_fail",
        "__assert_rtn",
        "__assert_fail",
        "abort_report_np",
        "abort_with_reason",
        "abort_with_payload",
        "exit_with_payload",
        "terminate_with_reason",
        "terminate_with_payload",
        "_os_crash",
        "_os_crash_fmt",
        "_os_crash_msg",
        "_os_assumes_log_crash",
        "os_fault_with_payload",
        # Event-loop / server never-returning entry points
        "dispatch_main",
        "xpc_main",
        "xpc_transaction_exit_clean",
        "NSApplicationMain",
        "UIApplicationMain",
        # Unwinder & Itanium C++ ABI exception / termination intrinsics
        "_Unwind_Resume",
        "_Unwind_RaiseException",
        "_Unwind_ForcedUnwind",
        "_Unwind_Resume_or_Rethrow",
        "__cxa_throw",
        "__cxa_rethrow",
        "__cxa_bad_cast",
        "__cxa_bad_typeid",
        "__cxa_throw_bad_array_new_length",
        "__cxa_pure_virtual",
        "__cxa_deleted_virtual",
        "__cxa_call_unexpected",
        "__cxa_call_terminate",
        "__clang_call_terminate",
        "_ZSt9terminatev",
        "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE",
        "_ZSt19__throw_logic_errorPKc",
        "_ZSt20__throw_length_errorPKc",
        "_ZSt20__throw_out_of_rangePKc",
        "_ZSt24__throw_out_of_range_fmtPKcz",
        "_ZSt17__throw_bad_allocv",
        "_ZSt28__throw_bad_array_new_lengthv",
        "_ZSt20__throw_system_errori",
        "_ZSt21__throw_runtime_errorPKc",
        "_ZSt25__throw_bad_function_callv",
        "_ZSt16__throw_bad_castv",
        "_ZSt18__throw_bad_typeidv",
        "__libcpp_verbose_abort",
        "_ZNSt3__122__libcpp_verbose_abortEPKcz",
        # Objective-C & Swift runtime fatal / exception entry points
        "objc_exception_throw",
        "objc_exception_rethrow",
        "objc_terminate",
        "swift_unexpectedError",
        "swift_errorInMain",
        "swift_fatalError",
        "swift_deletedMethodError",
        "swift_deletedAsyncMethodError",
        "_swift_stdlib_reportFatalError",
        "_swift_stdlib_reportFatalErrorInFile",
        "_swift_stdlib_reportUnimplementedInitializer",
        "_swift_stdlib_reportUnimplementedInitializerInFile",
        # System embedded language & RPC runtimes (e.g. libperl, DCERPC <dce/dcethread.h>)
        "dcethread_exc_raise",
        "Perl_croak",
        "Perl_croak_nocontext",
        "Perl_croak_no_modify",
        "Perl_croak_xs_usage",
        "Perl_croak_memory_wrap",
        "Perl_die",
        "Perl_die_nocontext",
        "Perl_my_exit",
        "Perl_my_failure_exit",
    }
)

# Prefix patterns for C++/Swift compiler-emitted noreturn throw helpers in system dylibs.
_NORETURN_PREFIX_PATTERNS: Tuple[str, ...] = (
    "_ZSt7__throw",
    "_ZSt8__throw_",
    "_ZSt9__throw_",
    "_ZSt16__throw_",
    "_ZSt17__throw_",
    "_ZSt18__throw_",
    "_ZSt19__throw_",
    "_ZSt20__throw_",
    "_ZSt21__throw_",
    "_ZSt24__throw_",
    "_ZSt25__throw_",
    "_ZSt28__throw_",
    "_ZNSt3__118__throw_",
    "_ZNSt3__119__throw_",
    "_ZNSt3__120__throw_",
    "_ZNSt3__121__throw_",
    "_ZNSt3__122__libcpp_verbose_abort",
    "$ss17_assertionFailure",
    "$ss11_fatalError",
    "$ss18_preconditionFailure",
)

# Known-answer C source for Row 3 (`xcrun clang -O0 -arch arm64`).
KNOWN_C_SOURCE = r"""
#include <stdint.h>

__attribute__((noinline))
int fn_seq(int a, int b) {
    int c = a + b;
    int d = c * 3;
    return d - 1;
}

__attribute__((noinline))
int fn_if_else(int a, int b) {
    int r;
    if (a > b) {
        r = a - b;
    } else {
        r = b - a;
    }
    return r + 1;
}

__attribute__((noinline))
int fn_while(int n) {
    int s = 0;
    int i = 0;
    while (i < n) {
        s += i;
        i++;
    }
    return s;
}

__attribute__((noinline))
int fn_for(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i * 2;
    }
    return s;
}

__attribute__((noinline))
int fn_nested_loop(int m, int n) {
    int s = 0;
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            s += i + j;
        }
    }
    return s;
}

__attribute__((noinline))
int fn_switch5_dense(int x) {
    int r = 0;
    switch (x) {
        case 0: r = 10; break;
        case 1: r = 20; break;
        case 2: r = 30; break;
        case 3: r = 40; break;
        case 4: r = 50; break;
        default: r = -1; break;
    }
    return r;
}

__attribute__((noinline))
int fn_switch10_jumptable(int x) {
    int r = 0;
    switch (x) {
        case 0: r = 10; break;
        case 1: r = 20; break;
        case 2: r = 30; break;
        case 3: r = 40; break;
        case 4: r = 50; break;
        case 5: r = 60; break;
        case 6: r = 70; break;
        case 7: r = 80; break;
        case 8: r = 90; break;
        case 9: r = 100; break;
        default: r = -1; break;
    }
    return r;
}

__attribute__((noinline))
int fn_loop_break_continue(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if ((i & 1) == 0) {
            continue;
        }
        if (i > 15) {
            break;
        }
        s += i;
    }
    return s;
}

int main(int argc, char **argv) {
    return fn_seq(argc, 2)
         + fn_if_else(argc, 3)
         + fn_while(argc)
         + fn_for(argc)
         + fn_nested_loop(argc, 2)
         + fn_switch5_dense(argc)
         + fn_switch10_jumptable(argc)
         + fn_loop_break_continue(argc);
}
"""

# Hand-audited ground-truth table for `xcrun clang -O0 -arch arm64` (Apple Clang 17 / LLVM 21).
# Each entry was audited instruction-by-instruction against
# `xcrun llvm-objdump --macho -d --no-show-raw-insn --arch=arm64`:
#
# 1. `_fn_seq` (15 insns):
#      Straight-line stack prologue (`sub sp`), `add`/`mul`/`subs`, `add sp`, `ret`.
#      Zero branches -> 1 block (B0), 0 edges, 0 loops, 0 jump tables.
# 2. `_fn_if_else` (22 insns):
#      Apple `clang -O0` emits an unconditional fallthrough trampoline block after `b.le`:
#      B0 (`subs; b.le L_else`), B1 (`b L_then`), B2 (`then` body + `b L_merge`),
#      B3 (`else` body + `b L_merge`), B4 (`L_merge`: `ldr; add; add sp; ret`).
#      5 blocks, 5 edges (`B0->B3`, `B0->B1`, `B1->B2`, `B2->B4`, `B3->B4`), 0 loops, 0 jump tables.
# 3. `_fn_while` (21 insns):
#      B0 (init + `b L_hdr`), B1 (`L_hdr`: `subs; b.ge L_exit`), B2 (`b L_body`),
#      B3 (`L_body`: `s += i; i++; b L_hdr` back-edge `B3->B1`), B4 (`L_exit`: `ret`).
#      5 blocks, 5 edges, 1 natural loop (`header=B1`, `latch=[B3]`, `nestingDepth=1`), 0 jump tables.
# 4. `_fn_for` (22 insns):
#      B0 (init + `b L_hdr`), B1 (`L_hdr`: `subs; b.ge L_exit`), B2 (`b L_body`),
#      B3 (`L_body` + `b L_inc`), B4 (`L_inc`: `i++; b L_hdr` back-edge `B4->B1`), B5 (`L_exit`: `ret`).
#      6 blocks, 6 edges, 1 natural loop (`header=B1`, `latch=[B4]`, `nestingDepth=1`), 0 jump tables.
# 5. `_fn_nested_loop` (37 insns):
#      B0 (init + `b B1`), B1 (outer header `b.ge B10`), B2 (`b B3`), B3 (inner init `j=0; b B4`),
#      B4 (inner header `b.ge B8`), B5 (`b B6`), B6 (inner body `b B7`),
#      B7 (inner latch `j++; b B4` back-edge `B7->B4`), B8 (inner exit `b B9`),
#      B9 (outer latch `i++; b B1` back-edge `B9->B1`), B10 (`ret`).
#      11 blocks, 12 edges, 2 natural loops with nesting depths `[1, 2]`, 0 jump tables.
# 6. `_fn_switch5_dense` (44 insns):
#      Under `-O0`, 5 dense cases (`0..4`) lower to a comparison chain with ZERO jump tables:
#      B0 (`cbz w8, L_c0`), 4 pairs `(b L_cmpK, subs #K + b.eq L_cK)` plus `b L_def` trampoline
#      (10 dispatch/trampoline blocks), 5 case blocks (`mov; str; b L_ret`), 1 default block
#      (`mov #-1; str; b L_ret`), 1 return block (`L_ret: ret`).
#      17 blocks, 21 edges, 0 loops, 0 jump tables (`jump_table_targets=0`).
# 7. `_fn_switch10_jumptable` (52 code insns + 10-entry 32-bit inline offset table):
#      Under `-O0`, 10 dense cases (`0..9`) lower to an inline jump table:
#      B0 (`subs x8, x8, #0x9; b.hi L_def`), B1 (`adrp+add` table base + `adr` anchor + `ldrsw`
#      + `add` + `br x8`), 10 case blocks B2..B11 (`b L_ret`), 1 default block B12 (`b L_ret`),
#      1 return block B13 (`ret`); the trailing 10 signed 32-bit offsets (`udf #0x10..#0x7c` in
#      raw objdump) are stripped as an inline jump table (`inlineJumpTableStarts`).
#      14 blocks, 23 edges (`2 + 10 + 10 + 1`), 0 loops, 1 jump table with 10 targets.
# 8. `_fn_loop_break_continue` (31 insns):
#      B0 (entry `b B1`), B1 (header `b.ge B11`), B2 (`b B3`), B3 (`tbnz w8, #0, B6`),
#      B4 (`b B5`), B5 (`continue`: `b B10`), B6 (`subs #0xf; b.le B9`), B7 (`b B8`),
#      B8 (`break`: `b B11`), B9 (`s += i; b B10`), B10 (latch `i++; b B1` back-edge `B10->B1`),
#      B11 (`ret`).
#      12 blocks, 14 edges, 1 natural loop (`nestingDepth=1`), 0 jump tables.
KNOWN_C_EXPECTED: Tuple[Dict[str, Any], ...] = (
    {
        "symbol": "_fn_seq",
        "description": "sequential arithmetic (15 insns, single block)",
        "blocks": 1,
        "edges": 0,
        "loops": 0,
        "loop_nesting_depths": [],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_if_else",
        "description": "if/else diamond with -O0 fallthrough trampoline",
        "blocks": 5,
        "edges": 5,
        "loops": 0,
        "loop_nesting_depths": [],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_while",
        "description": "single while (i < n) loop",
        "blocks": 5,
        "edges": 5,
        "loops": 1,
        "loop_nesting_depths": [1],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_for",
        "description": "single for (i = 0; i < n; i++) loop with separate latch",
        "blocks": 6,
        "edges": 6,
        "loops": 1,
        "loop_nesting_depths": [1],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_nested_loop",
        "description": "nested 2-level for loops (depths 1 and 2)",
        "blocks": 11,
        "edges": 12,
        "loops": 2,
        "loop_nesting_depths": [1, 2],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_switch5_dense",
        "description": "5-case dense switch (-O0 lowers to comparison chain, 0 jump tables)",
        "blocks": 17,
        "edges": 21,
        "loops": 0,
        "loop_nesting_depths": [],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
    {
        "symbol": "_fn_switch10_jumptable",
        "description": "10-case dense switch (-O0 emits 10-entry 32-bit inline jump table)",
        "blocks": 14,
        "edges": 23,
        "loops": 0,
        "loop_nesting_depths": [],
        "jump_table_count": 1,
        "jump_table_targets": 10,
    },
    {
        "symbol": "_fn_loop_break_continue",
        "description": "for loop with both continue (to latch) and break (to exit)",
        "blocks": 12,
        "edges": 14,
        "loops": 1,
        "loop_nesting_depths": [1],
        "jump_table_count": 0,
        "jump_table_targets": 0,
    },
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+\x40[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_USERS_PREFIX = os.sep + "Users" + os.sep
_USERS_PATH_RE = re.compile(re.escape(_USERS_PREFIX) + r"[^/\s\"']+")
_DYLD_FN_START_RE = re.compile(r"^\s*0x([0-9a-fA-F]+)\b")
_OTOOL_IV_SECTION_RE = re.compile(r"^Indirect symbols for \(([^,]+),([^)]+)\)")
_OTOOL_IV_ENTRY_RE = re.compile(r"^\s*0x([0-9a-fA-F]+)\s+(?:\d+\s+)?(\S+)\s*$")

_SUBPROCESS_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_SUBPROCESSES)


# ---------------------------------------------------------------------------
# Path / text sanitization & subprocess helpers
# ---------------------------------------------------------------------------


def decode_utf8_safe(raw: Optional[bytes]) -> Tuple[str, bool]:
    if not raw:
        return ("", False)
    try:
        return (raw.decode("utf-8"), False)
    except UnicodeDecodeError:
        return (raw.decode("utf-8", errors="replace"), True)


def sanitize_display_path(path: str, repo_root: Optional[str] = None) -> str:
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
    out = text
    home_dir = os.path.expanduser("~")
    if home_dir and home_dir != "/":
        out = out.replace(home_dir, "<home>")
    out = _USERS_PATH_RE.sub("<home>", out)
    out = _EMAIL_RE.sub("<redacted-email>", out)
    return out


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
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=root,
    )
    if res.returncode != 0:
        return False
    return res.stdout.decode("utf-8", errors="replace").strip() == ""


def run_subprocess_bytes(
    cmd: Sequence[str],
    *,
    timeout: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
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
    capped = min(MAX_CONCURRENT_SUBPROCESSES, max(1, worker_count))
    if capped <= 1 or len(candidates) <= 1:
        return [fn(p) for p in candidates]
    with ThreadPoolExecutor(max_workers=capped) as pool:
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


# ---------------------------------------------------------------------------
# Independent Mach-O / Universal Fat + ULEB128 `LC_FUNCTION_STARTS` parser
# ---------------------------------------------------------------------------


def decode_uleb128_stream(blob: bytes) -> List[int]:
    """Decode a sequence of unsigned ULEB128 integers, stopping at trailing 0x00 padding."""
    deltas: List[int] = []
    idx = 0
    n = len(blob)
    while idx < n:
        value = 0
        shift = 0
        while True:
            if idx >= n:
                raise ValueError("truncated ULEB128 sequence at end of LC_FUNCTION_STARTS blob")
            byte = blob[idx]
            idx += 1
            if shift >= 64 or (shift == 63 and (byte & 0x7F) > 1):
                raise ValueError("ULEB128 integer overflow (> 64 bits)")
            value |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        if value == 0:
            # In Mach-O LC_FUNCTION_STARTS, a zero delta marks trailing alignment padding;
            # verify any remaining non-zero deltas if present? Apple's ld64/dyld stops at 0.
            break
        deltas.append(value)
    return deltas


def decode_lc_function_starts_blob(blob: bytes, base_vmaddr: int) -> List[int]:
    """Accumulate `LC_FUNCTION_STARTS` ULEB128 deltas starting from `base_vmaddr`."""
    addr = base_vmaddr
    starts: List[int] = []
    for delta in decode_uleb128_stream(blob):
        addr = (addr + delta) & 0xFFFFFFFFFFFFFFFF
        starts.append(addr)
    return starts


def _clean_c_name(raw: bytes) -> str:
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    return raw.decode("utf-8", errors="replace")


def locate_arm64_slice_in_bytes(data: bytes, preferred_arch: Optional[str] = None) -> Optional[Tuple[str, int, int]]:
    """Return `(arch_name, slice_offset, slice_size)` for the preferred ARM64 slice (`arm64e` -> `arm64`)."""
    if len(data) < 32:
        return None
    magic_be = struct.unpack(">I", data[:4])[0]
    magic_le = struct.unpack("<I", data[:4])[0]

    if magic_le == MH_MAGIC_64:
        cputype, cpusubtype = struct.unpack("<ii", data[4:12])
        if cputype != CPU_TYPE_ARM64:
            return None
        sub = cpusubtype & CPU_SUBTYPE_MASK
        arch = "arm64e" if sub == CPU_SUBTYPE_ARM64E else "arm64"
        if preferred_arch is not None and arch != preferred_arch:
            return None
        return (arch, 0, len(data))

    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack(">I", data[4:8])[0]
        is_fat64 = magic_be == FAT_MAGIC_64
        entry_size = 32 if is_fat64 else 20
        if 8 + nfat * entry_size > len(data):
            return None
        slices: List[Tuple[str, int, int, int]] = []
        for i in range(nfat):
            off_e = 8 + i * entry_size
            if is_fat64:
                cputype, cpusubtype, s_off, s_size, _align, _res = struct.unpack(">iiQQII", data[off_e : off_e + 32])
            else:
                cputype, cpusubtype, s_off, s_size, _align = struct.unpack(">iiIII", data[off_e : off_e + 20])
            if cputype != CPU_TYPE_ARM64:
                continue
            if s_off + s_size > len(data) or s_size < 32:
                continue
            sub = cpusubtype & CPU_SUBTYPE_MASK
            if sub == CPU_SUBTYPE_ARM64E and (cpusubtype & 0xFF000000) == 0x80000000:
                arch_label = "arm64e"
                prio = 0
            elif sub == CPU_SUBTYPE_ARM64E:
                arch_label = "arm64e.other"
                prio = 2
            elif sub == CPU_SUBTYPE_ARM64_ALL:
                arch_label = "arm64"
                prio = 1
            else:
                arch_label = "arm64"
                prio = 3
            slices.append((arch_label, s_off, s_size, prio))

        if not slices:
            return None
        if preferred_arch == "arm64e":
            cand = [s for s in slices if s[0].startswith("arm64e")]
            if cand:
                cand.sort(key=lambda x: x[3])
                return ("arm64e", cand[0][1], cand[0][2])
            return None
        if preferred_arch == "arm64":
            cand = [s for s in slices if s[0] == "arm64"]
            if cand:
                cand.sort(key=lambda x: x[3])
                return ("arm64", cand[0][1], cand[0][2])
            return None
        slices.sort(key=lambda x: x[3])
        chosen_label = "arm64e" if slices[0][0].startswith("arm64e") else "arm64"
        return (chosen_label, slices[0][1], slices[0][2])

    return None


class MachOSliceView:
    """Lightweight read-only view of a single 64-bit ARM64 Mach-O slice."""

    def __init__(
        self,
        arch: str,
        slice_bytes: bytes,
        filetype: int,
        base_vmaddr: int,
        segments: List[Dict[str, Any]],
        sections: List[Dict[str, Any]],
        lc_function_starts: List[int],
    ) -> None:
        self.arch = arch
        self.slice_bytes = slice_bytes
        self.filetype = filetype
        self.base_vmaddr = base_vmaddr
        self.segments = segments
        self.sections = sections
        self.lc_function_starts = lc_function_starts
        self._exec_sections = [
            s
            for s in sections
            if (s["flags"] & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0 and s["size"] > 0
        ]

    @property
    def executable_sections(self) -> List[Dict[str, Any]]:
        return self._exec_sections

    def find_section(self, segname: str, sectname: str) -> Optional[Dict[str, Any]]:
        for s in self.sections:
            if s["segname"] == segname and s["sectname"] == sectname:
                return s
        return None

    def section_containing(self, va: int) -> Optional[Dict[str, Any]]:
        for s in self.sections:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def va_to_slice_offset(self, va: int) -> Optional[int]:
        for s in self.sections:
            if s["addr"] <= va < s["addr"] + s["size"] and s["offset"] > 0:
                off = s["offset"] + (va - s["addr"])
                if 0 <= off < len(self.slice_bytes):
                    return off
        for seg in self.segments:
            if seg["vmaddr"] <= va < seg["vmaddr"] + seg["filesize"]:
                off = seg["fileoff"] + (va - seg["vmaddr"])
                if 0 <= off < len(self.slice_bytes):
                    return off
        return None

    def read_u32(self, va: int) -> Optional[int]:
        off = self.va_to_slice_offset(va)
        if off is None or off + 4 > len(self.slice_bytes):
            return None
        return struct.unpack_from("<I", self.slice_bytes, off)[0]

    def read_u64(self, va: int) -> Optional[int]:
        off = self.va_to_slice_offset(va)
        if off is None or off + 8 > len(self.slice_bytes):
            return None
        return struct.unpack_from("<Q", self.slice_bytes, off)[0]


def parse_macho_arm64_slice(data: bytes, preferred_arch: Optional[str] = None) -> Optional[MachOSliceView]:
    loc = locate_arm64_slice_in_bytes(data, preferred_arch=preferred_arch)
    if loc is None:
        return None
    arch, s_off, s_size = loc
    sb = data[s_off : s_off + s_size]
    if len(sb) < 32:
        return None
    magic, cputype, _cpusubtype, filetype, ncmds, sizeofcmds, _flags, _res = struct.unpack_from("<IiiIIIII", sb, 0)
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
        return None
    if 32 + sizeofcmds > len(sb):
        raise ValueError("Mach-O sizeofcmds exceeds slice bounds")

    segments: List[Dict[str, Any]] = []
    sections: List[Dict[str, Any]] = []
    fn_starts_range: Optional[Tuple[int, int]] = None

    off = 32
    end_cmds = 32 + sizeofcmds
    for _ in range(ncmds):
        if off + 8 > end_cmds:
            raise ValueError("truncated Mach-O load command header")
        cmd, cmdsize = struct.unpack_from("<II", sb, off)
        if cmdsize < 8 or off + cmdsize > end_cmds:
            raise ValueError(f"invalid Mach-O load command size {cmdsize}")
        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            segname = _clean_c_name(sb[off + 8 : off + 24])
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = struct.unpack_from(
                "<QQQQiiII", sb, off + 24
            )
            segments.append(
                {
                    "segname": segname,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "maxprot": maxprot,
                    "initprot": initprot,
                    "flags": segflags,
                }
            )
            sect_off = off + 72
            for _s in range(nsects):
                if sect_off + 80 > off + cmdsize:
                    break
                sectname = _clean_c_name(sb[sect_off : sect_off + 16])
                s_segname = _clean_c_name(sb[sect_off + 16 : sect_off + 32])
                s_addr, s_sz, s_foff, s_align, s_reloff, s_nreloc, s_flags = struct.unpack_from(
                    "<QQIIIII", sb, sect_off + 32
                )
                sections.append(
                    {
                        "segname": s_segname,
                        "sectname": sectname,
                        "fullname": f"{s_segname},{sectname}",
                        "addr": s_addr,
                        "size": s_sz,
                        "offset": s_foff,
                        "align": s_align,
                        "flags": s_flags,
                    }
                )
                sect_off += 80
        elif cmd == LC_FUNCTION_STARTS and cmdsize >= 16:
            dataoff, datasize = struct.unpack_from("<II", sb, off + 8)
            fn_starts_range = (dataoff, datasize)
        off += cmdsize

    base_vmaddr = 0
    zero_fileoff_segs = [seg for seg in segments if seg["fileoff"] == 0 and seg["filesize"] > 0]
    if zero_fileoff_segs:
        base_vmaddr = zero_fileoff_segs[0]["vmaddr"]
    else:
        text_segs = [seg for seg in segments if seg["segname"] == "__TEXT"]
        if text_segs:
            base_vmaddr = text_segs[0]["vmaddr"]

    lc_starts: List[int] = []
    if fn_starts_range is not None:
        d_off, d_size = fn_starts_range
        if d_size > 0:
            if d_off + d_size > len(sb):
                raise ValueError("LC_FUNCTION_STARTS range exceeds slice bounds")
            lc_starts = decode_lc_function_starts_blob(sb[d_off : d_off + d_size], base_vmaddr)

    return MachOSliceView(
        arch=arch,
        slice_bytes=sb,
        filetype=filetype,
        base_vmaddr=base_vmaddr,
        segments=segments,
        sections=sections,
        lc_function_starts=lc_starts,
    )


def select_arm64_slice(path: str) -> Optional[str]:
    res = run_subprocess_bytes(["lipo", "-archs", path], timeout=30.0)
    if res.returncode != 0:
        return None
    archs = res.stdout.decode("utf-8", errors="replace").split()
    if "arm64e" in archs:
        return "arm64e"
    if "arm64" in archs:
        return "arm64"
    return None


def parse_dyld_info_function_starts_text(text: str) -> List[int]:
    """Parse `xcrun dyld_info -arch <arch> -function_starts <file>` stdout."""
    starts: List[int] = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("-function_starts:"):
            in_section = True
            continue
        if in_section:
            if stripped.endswith(":") and not stripped.startswith("0x"):
                break
            m = _DYLD_FN_START_RE.match(line)
            if m:
                starts.append(int(m.group(1), 16))
    return starts


def run_dyld_info_function_starts(path: str, arch: str, timeout: float = 60.0) -> Tuple[List[int], Optional[str], bool]:
    try:
        proc = run_subprocess_bytes(["xcrun", "dyld_info", "-arch", arch, "-function_starts", path], timeout=timeout)
    except subprocess.TimeoutExpired:
        return ([], f"dyld_info timed out after {timeout:.0f}s", True)
    text, _ = decode_utf8_safe(proc.stdout)
    if proc.returncode != 0:
        err_text, _ = decode_utf8_safe(proc.stderr)
        return ([], f"dyld_info exited {proc.returncode}: {err_text.strip()[:200]}", False)
    return (parse_dyld_info_function_starts_text(text), None, False)


# ---------------------------------------------------------------------------
# Independent ARM64 / ARM64e 32-bit instruction decoder & address-idiom solver
# ---------------------------------------------------------------------------


def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def decode_arm64_insn(word: int, pc: int) -> Dict[str, Any]:
    """Independently decode an ARM64 32-bit instruction word for CFG & address verification.

    Returns a dict with:
      - `kind`: one of
          `'udf'`, `'brk'`, `'hlt'`, `'svc'`, `'hvc_smc'`,
          `'b'`, `'bl'`, `'cond_branch'`,
          `'ret'`, `'indirect_jump'`, `'indirect_call'`,
          `'adr'`, `'adrp'`, `'add_imm64'`, `'sub_imm64'`, `'ldr_uimm64'`,
          `'movz_x16'`, `'nop'`, `'sequential'`
      - `is_terminator`: bool (True if instruction ends a basic block unconditionally or conditionally;
        note `bl` is False unless its target is noreturn)
      - `target`: Optional[int] (for `b`, `bl`, `cond_branch`, `adr`, `adrp`)
      - `rd`, `rn`, `imm`: register indices / immediate where applicable
    """
    w = word & 0xFFFFFFFF

    # 1. Permanently undefined `udf #imm16`: 0000 0000 0000 0000 imm16
    if (w & 0xFFFF0000) == 0x00000000:
        return {"kind": "udf", "is_terminator": True, "can_fallthrough": False, "imm": w & 0xFFFF}

    # 2. NOP: 0xD503201F
    if w == 0xD503201F:
        return {"kind": "nop", "is_terminator": False, "can_fallthrough": True}

    # 3. Unconditional branch immediate `b` / `bl`
    op6 = w & 0xFC000000
    if op6 == 0x14000000:
        off = _sign_extend(w & 0x03FFFFFF, 26) * 4
        return {
            "kind": "b",
            "is_terminator": True,
            "can_fallthrough": False,
            "target": (pc + off) & 0xFFFFFFFFFFFFFFFF,
        }
    if op6 == 0x94000000:
        off = _sign_extend(w & 0x03FFFFFF, 26) * 4
        return {
            "kind": "bl",
            "is_terminator": False,
            "can_fallthrough": True,
            "target": (pc + off) & 0xFFFFFFFFFFFFFFFF,
        }

    # 4. Compare and branch (`cbz` / `cbnz`)
    if (w & 0x7E000000) == 0x34000000:
        off = _sign_extend((w >> 5) & 0x7FFFF, 19) * 4
        return {
            "kind": "cond_branch",
            "is_terminator": True,
            "can_fallthrough": True,
            "target": (pc + off) & 0xFFFFFFFFFFFFFFFF,
        }

    # 5. Test bit and branch (`tbz` / `tbnz`)
    if (w & 0x7E000000) == 0x36000000:
        off = _sign_extend((w >> 5) & 0x3FFF, 14) * 4
        return {
            "kind": "cond_branch",
            "is_terminator": True,
            "can_fallthrough": True,
            "target": (pc + off) & 0xFFFFFFFFFFFFFFFF,
        }

    # 6. Conditional branch immediate (`b.cond` / `bc.cond`): 0101 0100 imm19 o0 cond
    if (w & 0xFF000000) == 0x54000000:
        off = _sign_extend((w >> 5) & 0x7FFFF, 19) * 4
        return {
            "kind": "cond_branch",
            "is_terminator": True,
            "can_fallthrough": True,
            "target": (pc + off) & 0xFFFFFFFFFFFFFFFF,
        }

    # 7. Unconditional branch (register) including ARMv8.3-A PAC (`br*`, `blr*`, `ret*`, `eret*`, `drps`)
    if (w & 0xFE000000) == 0xD6000000:
        opc = (w >> 21) & 0xF
        op2 = (w >> 16) & 0x1F
        op3 = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F
        op4 = w & 0x1F
        if op2 == 0x1F:
            if opc == 0x0 and ((op3 == 0 and op4 == 0) or (op3 in (2, 3) and op4 == 0x1F)):
                return {"kind": "indirect_jump", "is_terminator": True, "can_fallthrough": False, "rn": rn}
            if opc == 0x8 and op3 in (2, 3):
                return {"kind": "indirect_jump", "is_terminator": True, "can_fallthrough": False, "rn": rn}
            if opc == 0x1 and ((op3 == 0 and op4 == 0) or (op3 in (2, 3) and op4 == 0x1F)):
                return {"kind": "indirect_call", "is_terminator": False, "can_fallthrough": True, "rn": rn}
            if opc == 0x9 and op3 in (2, 3):
                return {"kind": "indirect_call", "is_terminator": False, "can_fallthrough": True, "rn": rn}
            if opc == 0x2 and ((op3 == 0 and op4 == 0) or (op3 in (2, 3) and rn == 0x1F and op4 == 0x1F)):
                return {"kind": "ret", "is_terminator": True, "can_fallthrough": False}
            if opc in (0x4, 0x5):
                return {"kind": "ret", "is_terminator": True, "can_fallthrough": False}

    # 8. Exception generation (`svc`, `hvc`, `smc`, `brk`, `hlt`)
    if (w & 0xFF000000) == 0xD4000000:
        opc = (w >> 21) & 0x7
        op2 = (w >> 2) & 0x7
        ll = w & 0x3
        imm16 = (w >> 5) & 0xFFFF
        if op2 == 0:
            if opc == 0 and ll == 1:
                return {"kind": "svc", "is_terminator": True, "can_fallthrough": True, "imm": imm16}
            if opc == 0 and ll in (2, 3):
                return {"kind": "hvc_smc", "is_terminator": True, "can_fallthrough": True, "imm": imm16}
            if opc == 1 and ll == 0:
                return {"kind": "brk", "is_terminator": True, "can_fallthrough": False, "imm": imm16}
            if opc == 2 and ll == 0:
                return {"kind": "hlt", "is_terminator": True, "can_fallthrough": False, "imm": imm16}

    # 9. PC-relative addressing (`adr` / `adrp`)
    if (w & 0x9F000000) == 0x10000000:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = _sign_extend((immhi << 2) | immlo, 21)
        rd = w & 0x1F
        return {
            "kind": "adr",
            "is_terminator": False,
            "can_fallthrough": True,
            "rd": rd,
            "target": (pc + imm21) & 0xFFFFFFFFFFFFFFFF,
        }
    if (w & 0x9F000000) == 0x90000000:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm21 = _sign_extend((immhi << 2) | immlo, 21)
        rd = w & 0x1F
        page = ((pc & ~0xFFF) + (imm21 << 12)) & 0xFFFFFFFFFFFFFFFF
        return {
            "kind": "adrp",
            "is_terminator": False,
            "can_fallthrough": True,
            "rd": rd,
            "target": page,
        }

    # 10. 64-bit `add Xd, Xn, #imm12{, lsl #12}` / `sub Xd, Xn, #imm12{, lsl #12}`
    if (w & 0xFF800000) == 0x91000000:
        sh = (w >> 22) & 0x1
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return {
            "kind": "add_imm64",
            "is_terminator": False,
            "can_fallthrough": True,
            "rd": rd,
            "rn": rn,
            "imm": imm12 << (12 if sh else 0),
        }
    if (w & 0xFF800000) == 0xD1000000:
        sh = (w >> 22) & 0x1
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        return {
            "kind": "sub_imm64",
            "is_terminator": False,
            "can_fallthrough": True,
            "rd": rd,
            "rn": rn,
            "imm": imm12 << (12 if sh else 0),
        }

    # 11. 64-bit unsigned-offset `ldr Xt, [Xn, #pimm]` (for GOT stub target resolution)
    if (w & 0xFFC00000) == 0xF9400000:
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        return {
            "kind": "ldr_uimm64",
            "is_terminator": False,
            "can_fallthrough": True,
            "rd": rt,
            "rn": rn,
            "imm": imm12 * 8,
        }

    # 12. `movz w16/x16, #imm16` (for Darwin `svc #0x80` exit syscall setup `x16 == 1` or `431`)
    if (w & 0x7F800000) == 0x52800000 and ((w >> 21) & 0x3) == 0 and (w & 0x1F) == 16:
        imm16 = (w >> 5) & 0xFFFF
        return {
            "kind": "movz_x16",
            "is_terminator": False,
            "can_fallthrough": True,
            "imm": imm16,
        }

    return {"kind": "sequential", "is_terminator": False, "can_fallthrough": True}


def compute_referenced_code_addresses(insn_words: Sequence[Tuple[int, int]]) -> Set[int]:
    """Compute all addresses formed via `adr`, `adrp + add` (or `sub`), and page-aligned `adrp`
    across `(pc, word)` pairs of a function."""
    referenced: Set[int] = set()
    pages_by_reg: Dict[int, Set[int]] = {}
    adds_by_rn: Dict[int, List[Tuple[int, int]]] = {}

    for pc, word in insn_words:
        dec = decode_arm64_insn(word, pc)
        kind = dec["kind"]
        if kind == "adr":
            referenced.add(dec["target"])
        elif kind == "adrp":
            rd = dec["rd"]
            page = dec["target"]
            pages_by_reg.setdefault(rd, set()).add(page)
            # When tableBaseAddress is 4KB page-aligned (pageoff == 0), compilers omit `add x, x, #0`.
            referenced.add(page)
        elif kind == "add_imm64":
            rn = dec["rn"]
            rd = dec["rd"]
            imm = dec["imm"]
            adds_by_rn.setdefault(rn, []).append((rd, imm))
            for page in pages_by_reg.get(rn, ()):
                val = (page + imm) & 0xFFFFFFFFFFFFFFFF
                referenced.add(val)
                if imm == 0 and rd != 31:
                    pages_by_reg.setdefault(rd, set()).add(page)
        elif kind == "sub_imm64":
            rn = dec["rn"]
            imm = dec["imm"]
            for page in pages_by_reg.get(rn, ()):
                referenced.add((page - imm) & 0xFFFFFFFFFFFFFFFF)
        # Also propagate `mov xD, xN` (`orr xD, xzr, xN`: 0xAA0003E0 | (rm << 16) | rd)
        elif (word & 0xFFE0FFE0) == 0xAA0003E0:
            rm = (word >> 16) & 0x1F
            rd = word & 0x1F
            if rm in pages_by_reg and rd != 31:
                pages_by_reg.setdefault(rd, set()).update(pages_by_reg[rm])

    # Second pass in case `adrp` lives in a higher-address block than a loop/branch `add` block.
    for rn, add_list in adds_by_rn.items():
        for page in pages_by_reg.get(rn, ()):
            for _rd, imm in add_list:
                referenced.add((page + imm) & 0xFFFFFFFFFFFFFFFF)

    return referenced


# ---------------------------------------------------------------------------
# Independent `otool -Iv` import symbol resolution & internal `noreturn` solver
# ---------------------------------------------------------------------------


def canonical_symbol_matches_noreturn(raw_name: str) -> bool:
    cleaned = raw_name.strip()
    if not cleaned or cleaned in ("LOCAL", "ABSOLUTE"):
        return False
    if cleaned.endswith("$stub"):
        cleaned = cleaned[:-5]
    if "@" in cleaned:
        cleaned = cleaned.split("@", 1)[0]
    if "$" in cleaned:
        base, suffix = cleaned.split("$", 1)
        if suffix.startswith(("UNIX", "DARWIN", "INODE", "NOCANCEL", "NEW")):
            cleaned = base
    if not cleaned:
        return False

    candidates = [cleaned]
    if cleaned.startswith("_"):
        candidates.append(cleaned[1:])
    for cand in candidates:
        if cand in KNOWN_NORETURN_IMPORT_NAMES:
            return True
        for prefix in _NORETURN_PREFIX_PATTERNS:
            if cand.startswith(prefix):
                return True
    return False


def parse_otool_indirect_symbols(text: str) -> Dict[int, str]:
    """Parse `xcrun otool -arch <arch> -Iv <file>` into `{address: symbol_name}`."""
    mapping: Dict[int, str] = {}
    for line in text.splitlines():
        if _OTOOL_IV_SECTION_RE.match(line):
            continue
        m = _OTOOL_IV_ENTRY_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        sym = m.group(2)
        if sym in ("LOCAL", "ABSOLUTE", "name"):
            continue
        mapping[addr] = sym
    return mapping


def resolve_import_symbols_for_binary(
    path: str, arch: str, slice_view: MachOSliceView, cfg_functions: Sequence[Dict[str, Any]], timeout: float = 60.0
) -> Tuple[Dict[int, str], Optional[str], bool]:
    """Build `{function_or_stub_address: imported_symbol_name}` from `otool -Iv` + stub GOT targets."""
    try:
        proc = run_subprocess_bytes(["xcrun", "otool", "-arch", arch, "-Iv", path], timeout=timeout)
    except subprocess.TimeoutExpired:
        return ({}, f"otool -Iv timed out after {timeout:.0f}s", True)
    text, _ = decode_utf8_safe(proc.stdout)
    if proc.returncode != 0:
        err_text, _ = decode_utf8_safe(proc.stderr)
        return ({}, f"otool -Iv exited {proc.returncode}: {err_text.strip()[:200]}", False)

    indirect_map = parse_otool_indirect_symbols(text)
    resolved: Dict[int, str] = dict(indirect_map)

    # Also map stub functions that load from a GOT slot (`adrp x16/x17, page; ldr/add ...`) to the GOT entry's symbol.
    for fn in cfg_functions:
        f_addr = int(fn["address"])
        if f_addr in resolved:
            continue
        if not fn.get("isStub"):
            continue
        f_end = int(fn["endAddress"])
        pages: Dict[int, int] = {}
        for pc in range(f_addr, min(f_end, f_addr + 32), 4):
            w = slice_view.read_u32(pc)
            if w is None:
                break
            dec = decode_arm64_insn(w, pc)
            if dec["kind"] == "adrp":
                pages[dec["rd"]] = dec["target"]
            elif dec["kind"] in ("ldr_uimm64", "add_imm64") and dec["rn"] in pages:
                slot = (pages[dec["rn"]] + dec["imm"]) & 0xFFFFFFFFFFFFFFFF
                if slot in indirect_map:
                    resolved[f_addr] = indirect_map[slot]
                    break
    return (resolved, None, False)


def solve_independent_noreturn_functions(
    slice_view: MachOSliceView,
    cfg_functions: Sequence[Dict[str, Any]],
    imported_symbols_by_addr: Dict[int, str],
    max_iterations: int = 24,
) -> Set[int]:
    """Independently compute the set of `noreturn` function start addresses.

    Seeds with imported symbols matching `KNOWN_NORETURN_IMPORT_NAMES`, then runs
    fixed-point forward reachability over raw ARM64 machine instructions of internal
    functions: an internal function is proven `noreturn` iff EVERY path reachable from
    its entry address terminates in a `noreturn` direct call (`bl`), a `noreturn`
    cross-function tail jump (`b`), or a non-returning trap (`udf`/`brk`/`hlt`/Darwin exit `svc`),
    with zero reachable `ret`, zero reachable fall-offs, and zero unresolved indirect jumps.
    """
    noreturn_addrs: Set[int] = {
        addr for addr, sym in imported_symbols_by_addr.items() if canonical_symbol_matches_noreturn(sym)
    }

    # Pre-decode raw instructions for each non-stub function
    fn_insns: Dict[int, List[Tuple[int, Dict[str, Any]]]] = {}
    fn_jt_by_dispatch: Dict[int, Dict[int, List[int]]] = {}
    internal_starts: List[int] = []

    for fn in cfg_functions:
        f_start = int(fn["address"])
        if f_start in noreturn_addrs or fn.get("isStub"):
            continue
        # Collect sorted instruction addresses from blocks (already verified by I3 to be disjoint 4B code)
        addrs = sorted({int(a) for blk in fn.get("blocks", []) for a in blk.get("instructionAddresses", [])})
        if not addrs:
            continue
        decoded_list: List[Tuple[int, Dict[str, Any]]] = []
        valid = True
        for pc in addrs:
            w = slice_view.read_u32(pc)
            if w is None:
                valid = False
                break
            decoded_list.append((pc, decode_arm64_insn(w, pc)))
        if not valid:
            continue
        fn_insns[f_start] = decoded_list
        jt_map: Dict[int, List[int]] = {}
        for jt in fn.get("jumpTables", []):
            jt_map[int(jt["dispatchInstructionAddress"])] = [int(t) for t in jt.get("targetAddresses", [])]
        fn_jt_by_dispatch[f_start] = jt_map
        internal_starts.append(f_start)

    def is_fn_all_paths_noreturn(f_start: int) -> bool:
        insns = fn_insns[f_start]
        addr_to_idx = {pc: idx for idx, (pc, _d) in enumerate(insns)}
        if f_start not in addr_to_idx:
            return False
        jt_map = fn_jt_by_dispatch[f_start]
        visited = [False] * len(insns)
        stack = [addr_to_idx[f_start]]
        visited[stack[0]] = True

        while stack:
            idx = stack.pop()
            pc, dec = insns[idx]
            kind = dec["kind"]

            if kind == "ret":
                return False
            if kind in ("udf", "brk", "hlt"):
                continue
            if kind == "svc":
                is_exit_svc = (
                    dec.get("imm") == 0x80
                    and idx > 0
                    and insns[idx - 1][1]["kind"] == "movz_x16"
                    and insns[idx - 1][1].get("imm") in (1, 431)
                )
                if is_exit_svc:
                    continue
                nxt = addr_to_idx.get(pc + 4)
                if nxt is None:
                    return False
                if not visited[nxt]:
                    visited[nxt] = True
                    stack.append(nxt)
                continue
            if kind == "bl":
                tgt = dec["target"]
                if tgt in noreturn_addrs:
                    continue
                nxt = addr_to_idx.get(pc + 4)
                if nxt is None:
                    # A `bl` at the very end of the function to an unverified target cannot prove noreturn!
                    return False
                if not visited[nxt]:
                    visited[nxt] = True
                    stack.append(nxt)
                continue
            if kind == "b":
                tgt = dec["target"]
                tgt_idx = addr_to_idx.get(tgt)
                if tgt_idx is not None:
                    if not visited[tgt_idx]:
                        visited[tgt_idx] = True
                        stack.append(tgt_idx)
                elif tgt in noreturn_addrs:
                    continue
                else:
                    return False
                continue
            if kind == "cond_branch":
                tgt = dec["target"]
                tgt_idx = addr_to_idx.get(tgt)
                if tgt_idx is not None:
                    if not visited[tgt_idx]:
                        visited[tgt_idx] = True
                        stack.append(tgt_idx)
                elif tgt not in noreturn_addrs:
                    return False
                nxt = addr_to_idx.get(pc + 4)
                if nxt is None:
                    return False
                if not visited[nxt]:
                    visited[nxt] = True
                    stack.append(nxt)
                continue
            if kind == "indirect_jump":
                targets = jt_map.get(pc)
                if not targets:
                    return False
                for t in targets:
                    t_idx = addr_to_idx.get(t)
                    if t_idx is not None:
                        if not visited[t_idx]:
                            visited[t_idx] = True
                            stack.append(t_idx)
                    elif t not in noreturn_addrs:
                        return False
                continue

            # All sequential / indirect_call / arithmetic / load / store instructions fall through to pc + 4
            nxt = addr_to_idx.get(pc + 4)
            if nxt is None:
                return False
            if not visited[nxt]:
                visited[nxt] = True
                stack.append(nxt)

        return True

    for _ in range(max_iterations):
        added = False
        for f_start in internal_starts:
            if f_start in noreturn_addrs:
                continue
            if is_fn_all_paths_noreturn(f_start):
                noreturn_addrs.add(f_start)
                added = True
        if not added:
            break

    return noreturn_addrs


# ---------------------------------------------------------------------------
# Independent iterative dominator-set & natural-loop solver
# ---------------------------------------------------------------------------


def solve_dominators_and_loops_independent(
    block_ids: Sequence[int],
    entry_id: int,
    edges: Sequence[Tuple[int, int]],
) -> Dict[str, Any]:
    """Compute exact dominator sets, `idom`, tree children, depth, dominance frontiers,
    natural back-edges, and natural loops via iterative dataflow bitset intersection."""
    id_set = set(block_ids)
    succs: Dict[int, List[int]] = {bid: [] for bid in block_ids}
    preds: Dict[int, List[int]] = {bid: [] for bid in block_ids}
    seen_edges: Set[Tuple[int, int]] = set()
    for u, v in edges:
        if u in id_set and v in id_set and (u, v) not in seen_edges:
            seen_edges.add((u, v))
            succs[u].append(v)
            preds[v].append(u)

    # Iterative DFS postorder from `entry_id` to build Reverse Post-Order (RPO)
    visited: Set[int] = set()
    postorder: List[int] = []
    if entry_id in id_set:
        visited.add(entry_id)
        dfs_stack: List[Tuple[int, int]] = [(entry_id, 0)]
        while dfs_stack:
            node, idx = dfs_stack[-1]
            node_succs = succs[node]
            if idx < len(node_succs):
                dfs_stack[-1] = (node, idx + 1)
                nxt = node_succs[idx]
                if nxt not in visited:
                    visited.add(nxt)
                    dfs_stack.append((nxt, 0))
            else:
                dfs_stack.pop()
                postorder.append(node)

    rpo = list(reversed(postorder))
    rpo_index: Dict[int, int] = {bid: i for i, bid in enumerate(rpo)}
    reachable_set = set(rpo)
    rcount = len(rpo)

    # Iterative dataflow equation: Dom(entry) = {entry}; Dom(n) = {n} U (/\_{p in pred(n)} Dom(p))
    all_mask = (1 << rcount) - 1
    dom_masks = [all_mask] * rcount
    if rcount > 0:
        dom_masks[0] = 1
        rpo_preds: List[List[int]] = [[] for _ in range(rcount)]
        for i in range(1, rcount):
            bid = rpo[i]
            rpo_preds[i] = [rpo_index[p] for p in preds[bid] if p in rpo_index]

        changed = True
        while changed:
            changed = False
            for i in range(1, rcount):
                inter = all_mask
                for p_idx in rpo_preds[i]:
                    inter &= dom_masks[p_idx]
                new_mask = inter | (1 << i)
                if new_mask != dom_masks[i]:
                    dom_masks[i] = new_mask
                    changed = True

    idom: Dict[int, Optional[int]] = {bid: None for bid in block_ids}
    depth: Dict[int, int] = {bid: 0 for bid in block_ids}
    children: Dict[int, List[int]] = {bid: [] for bid in block_ids}

    for i in range(1, rcount):
        bid = rpo[i]
        sdom_mask = dom_masks[i] ^ (1 << i)
        # Strict dominators form a chain ordered strictly by RPO index; the immediate dominator
        # has the highest RPO index among strict dominators (`bit_length() - 1`).
        parent_rpo = sdom_mask.bit_length() - 1
        assert parent_rpo >= 0 and (dom_masks[parent_rpo] | (1 << i)) == dom_masks[i]
        parent_id = rpo[parent_rpo]
        idom[bid] = parent_id
        depth[bid] = depth[parent_id] + 1
        assert bin(dom_masks[i]).count("1") - 1 == depth[bid]
        children[parent_id].append(bid)

    for bid in block_ids:
        children[bid].sort()

    # Join-point Dominance Frontiers (Cooper-Harvey-Kennedy 2001): `y in DF(x)` iff `y` is a
    # reachable CFG join node (`len(reach_preds) >= 2`), `x` dominates some reachable predecessor
    # `p` of `y`, and `x` does NOT strictly dominate `y`.
    df_sets: Dict[int, Set[int]] = {bid: set() for bid in block_ids}
    for y_i in range(rcount):
        y_id = rpo[y_i]
        reach_preds = [p for p in preds[y_id] if p in rpo_index]
        if len(reach_preds) < 2:
            continue
        pred_dom_union = 0
        for p in reach_preds:
            pred_dom_union |= dom_masks[rpo_index[p]]
        strict_dom_y = dom_masks[y_i] ^ (1 << y_i)
        df_contributors = pred_dom_union & ~strict_dom_y
        m = df_contributors
        while m:
            lsb = m & -m
            x_i = lsb.bit_length() - 1
            df_sets[rpo[x_i]].add(y_id)
            m ^= lsb

    df_sorted: Dict[int, List[int]] = {bid: sorted(df_sets[bid]) for bid in block_ids}

    # Natural back-edges `(u -> h)` where `u` is reachable and `h` dominates `u`
    latches_by_header: Dict[int, Set[int]] = {}
    natural_back_edges: Set[Tuple[int, int]] = set()
    for u, h in seen_edges:
        if u in rpo_index and h in rpo_index:
            u_i = rpo_index[u]
            h_i = rpo_index[h]
            if (dom_masks[u_i] >> h_i) & 1:
                natural_back_edges.add((u, h))
                latches_by_header.setdefault(h, set()).add(u)

    prelim_loops: List[Dict[str, Any]] = []
    for h in sorted(latches_by_header.keys()):
        latches = sorted(latches_by_header[h])
        body: Set[int] = {h}
        work: List[int] = []
        for l_id in latches:
            if l_id not in body:
                body.add(l_id)
                work.append(l_id)
        while work:
            curr = work.pop()
            for p in preds[curr]:
                if p in reachable_set and p not in body:
                    body.add(p)
                    work.append(p)
        exits = sorted({s for b in body for s in succs[b] if s not in body})
        prelim_loops.append(
            {
                "headerBlockID": h,
                "latchBlockIDs": latches,
                "bodySet": body,
                "bodyBlockIDs": sorted(body),
                "exitBlockIDs": exits,
            }
        )

    natural_loops: List[Dict[str, Any]] = []
    for cand in prelim_loops:
        enclosing = sum(
            1
            for other in prelim_loops
            if other["headerBlockID"] != cand["headerBlockID"]
            and cand["headerBlockID"] in other["bodySet"]
            and len(other["bodySet"]) >= len(cand["bodySet"])
        )
        natural_loops.append(
            {
                "headerBlockID": cand["headerBlockID"],
                "latchBlockIDs": cand["latchBlockIDs"],
                "bodyBlockIDs": cand["bodyBlockIDs"],
                "exitBlockIDs": cand["exitBlockIDs"],
                "nestingDepth": enclosing + 1,
            }
        )

    return {
        "reachable": reachable_set,
        "idom": idom,
        "depth": depth,
        "children": children,
        "dominance_frontiers": df_sorted,
        "natural_back_edges": natural_back_edges,
        "natural_loops": natural_loops,
    }


# ---------------------------------------------------------------------------
# Row 1 (`function-starts`) & Row 2 (`invariants`) evaluation per binary
# ---------------------------------------------------------------------------


def verify_objc_stubs_no_brk_fakes(
    slice_view: MachOSliceView, cfg_functions: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Verify `__TEXT,__objc_stubs` has zero fake functions split at `brk`/`hlt`/`udf`/`nop` padding,
    and matches independent slot count on raw section bytes."""
    issues: List[Dict[str, Any]] = []
    objc_sec = slice_view.find_section("__TEXT", "__objc_stubs")
    mg_objc_fns = [fn for fn in cfg_functions if fn.get("section") == "__TEXT,__objc_stubs"]

    for fn in mg_objc_fns:
        f_addr = int(fn["address"])
        w = slice_view.read_u32(f_addr)
        if w is None:
            issues.append({"kind": "OBJC_STUB_UNREADABLE_START", "address": hex(f_addr), "name": fn.get("name")})
            continue
        dec = decode_arm64_insn(w, f_addr)
        if dec["kind"] in ("brk", "hlt", "udf", "nop"):
            issues.append(
                {
                    "kind": "OBJC_STUB_FAKE_PADDING_FUNCTION",
                    "address": hex(f_addr),
                    "name": fn.get("name"),
                    "first_insn_kind": dec["kind"],
                    "word": f"0x{w:08x}",
                }
            )

    if objc_sec is not None and objc_sec["size"] >= 4:
        # Independently segment `__TEXT,__objc_stubs` by advancing through each stub to its
        # `indirect_jump`/`b`/`ret` terminator and skipping trailing `nop`/`brk`/`hlt`/`udf` words.
        expected_starts: List[int] = []
        sec_start = objc_sec["addr"]
        sec_end = sec_start + objc_sec["size"]
        pc = sec_start
        while pc + 4 <= sec_end:
            w = slice_view.read_u32(pc)
            if w is None:
                break
            dec = decode_arm64_insn(w, pc)
            if dec["kind"] in ("nop", "brk", "hlt", "udf"):
                pc += 4
                continue
            expected_starts.append(pc)
            pc += 4
            while pc + 4 <= sec_end:
                w2 = slice_view.read_u32(pc)
                if w2 is None:
                    break
                dec2 = decode_arm64_insn(w2, pc)
                pc += 4
                if dec2["kind"] in ("indirect_jump", "b", "ret"):
                    while pc + 4 <= sec_end:
                        w_pad = slice_view.read_u32(pc)
                        if w_pad is None:
                            break
                        dec_pad = decode_arm64_insn(w_pad, pc)
                        if dec_pad["kind"] in ("nop", "brk", "hlt", "udf"):
                            pc += 4
                        else:
                            break
                    break
        mg_starts = sorted(int(fn["address"]) for fn in mg_objc_fns)
        if mg_starts != expected_starts:
            issues.append(
                {
                    "kind": "OBJC_STUBS_START_SET_MISMATCH",
                    "expected_count": len(expected_starts),
                    "mg_count": len(mg_starts),
                    "missing": [hex(a) for a in sorted(set(expected_starts) - set(mg_starts))[:5]],
                    "extra": [hex(a) for a in sorted(set(mg_starts) - set(expected_starts))[:5]],
                }
            )

    return issues


def check_function_starts_on_loaded(
    slice_view: MachOSliceView,
    dyld_starts: Sequence[int],
    info_json: Dict[str, Any],
    cfg_json: Dict[str, Any],
) -> Dict[str, Any]:
    """Pure verification logic for Row 1 (`function-starts`) given parsed inputs."""
    examples: List[Dict[str, Any]] = []
    py_starts = list(slice_view.lc_function_starts)
    dyld_list = list(dyld_starts)

    # 1. Cross-check Python ULEB128 parser vs `xcrun dyld_info -function_starts`
    if py_starts != dyld_list:
        py_set, dy_set = set(py_starts), set(dyld_list)
        examples.append(
            {
                "kind": "REF_PY_VS_DYLD_INFO_MISMATCH",
                "py_count": len(py_starts),
                "dyld_info_count": len(dyld_list),
                "only_py": [hex(a) for a in sorted(py_set - dy_set)[:5]],
                "only_dyld_info": [hex(a) for a in sorted(dy_set - py_set)[:5]],
            }
        )

    ref_set = set(py_starts)

    # 2. Check `machgraph info --json` functionStarts & lcFunctionStarts
    info_starts = [int(x) for x in info_json.get("functionStarts", [])]
    info_lc_starts = [int(x) for x in info_json.get("lcFunctionStarts", [])]
    info_count = int(info_json.get("functionStartsCount", -1))

    if slice_view.base_vmaddr in set(info_starts) and slice_view.base_vmaddr not in ref_set:
        examples.append(
            {
                "kind": "INFO_CONTAINS_IMAGE_BASE_HEADER",
                "imageBase": hex(slice_view.base_vmaddr),
            }
        )

    if info_count != len(py_starts) or info_starts != py_starts or info_lc_starts != py_starts:
        info_set = set(info_starts)
        examples.append(
            {
                "kind": "INFO_FUNCTION_STARTS_MISMATCH",
                "ref_count": len(py_starts),
                "info_count": info_count,
                "missing_in_info": [hex(a) for a in sorted(ref_set - info_set)[:5]],
                "extra_in_info": [hex(a) for a in sorted(info_set - ref_set)[:5]],
            }
        )

    # 3. Check `machgraph cfg --json`: (__TEXT,__text starts) U inlineJumpTableStarts == LC_FUNCTION_STARTS
    cfg_fns = cfg_json.get("functions", [])
    cfg_lc_starts = [int(x) for x in cfg_json.get("lcFunctionStarts", [])]
    if cfg_lc_starts != py_starts:
        examples.append(
            {
                "kind": "CFG_LC_FUNCTION_STARTS_FIELD_MISMATCH",
                "ref_count": len(py_starts),
                "cfg_lc_count": len(cfg_lc_starts),
            }
        )

    text_sec = slice_view.find_section("__TEXT", "__text")
    text_fn_starts = {int(fn["address"]) for fn in cfg_fns if fn.get("section") == "__TEXT,__text"}
    inline_jt_starts = {int(x) for x in cfg_json.get("inlineJumpTableStarts", [])}

    if text_sec is not None:
        t_lo, t_hi = text_sec["addr"], text_sec["addr"] + text_sec["size"]
        inline_jt_in_text = {a for a in inline_jt_starts if t_lo <= a < t_hi}
        ref_in_text = {a for a in ref_set if t_lo <= a < t_hi}
    else:
        inline_jt_in_text = set(inline_jt_starts)
        ref_in_text = set(ref_set)

    overlap = text_fn_starts & inline_jt_in_text
    if overlap:
        examples.append(
            {
                "kind": "TEXT_FN_AND_INLINE_JT_NOT_DISJOINT",
                "overlap": [hex(a) for a in sorted(overlap)[:5]],
            }
        )

    if ref_set:
        # Check `__TEXT,__text` union equality and full `LC_FUNCTION_STARTS` coverage
        union_text = text_fn_starts | inline_jt_in_text
        missing_text = sorted(ref_in_text - union_text)
        extra_text = sorted(union_text - ref_in_text)
        if missing_text or extra_text:
            examples.append(
                {
                    "kind": "CFG_TEXT_UNION_INLINE_JT_MISMATCH",
                    "ref_in_text_count": len(ref_in_text),
                    "text_fn_count": len(text_fn_starts),
                    "inline_jt_in_text_count": len(inline_jt_in_text),
                    "missing": [hex(a) for a in missing_text[:5]],
                    "extra": [hex(a) for a in extra_text[:5]],
                }
            )
        all_non_stub_starts = {int(fn["address"]) for fn in cfg_fns if not fn.get("isStub")}
        missing_any = sorted(ref_set - (all_non_stub_starts | inline_jt_starts))
        if missing_any:
            examples.append(
                {
                    "kind": "CFG_MISSING_NON_TEXT_LC_FUNCTION_START",
                    "missing": [hex(a) for a in missing_any[:5]],
                }
            )

    # 4. Check `__TEXT,__objc_stubs` has zero fake `brk`-split functions
    objc_issues = verify_objc_stubs_no_brk_fakes(slice_view, cfg_fns)
    examples.extend(objc_issues)

    objc_count = sum(1 for fn in cfg_fns if fn.get("section") == "__TEXT,__objc_stubs")
    diff_count = len(examples)
    return {
        "status": "pass" if diff_count == 0 else "fail",
        "ref_count": len(py_starts),
        "mg_count": len(text_fn_starts) + len(inline_jt_in_text),
        "text_fn_count": len(text_fn_starts),
        "inline_jt_count": len(inline_jt_in_text),
        "objc_stub_count": objc_count,
        "diff_count": diff_count,
        "examples": examples[:MAX_EXAMPLES_PER_CHECK],
    }


def check_invariants_on_loaded(
    slice_view: MachOSliceView,
    cfg_json: Dict[str, Any],
    imported_symbols_by_addr: Dict[int, str],
) -> Dict[str, Any]:
    """Pure verification logic for Row 2 (`invariants`: I1, I2, I3, I4 + noreturn + inline JT + idom/loops)."""
    cfg_fns = cfg_json.get("functions", [])
    inline_ranges_raw = cfg_json.get("inlineJumpTableRanges", [])

    violations_by_inv: Dict[str, int] = {"I1": 0, "I2": 0, "I3": 0, "I4": 0}
    examples: List[Dict[str, Any]] = []

    def record_violation(inv: str, kind: str, detail: Dict[str, Any]) -> None:
        violations_by_inv[inv] += 1
        if len(examples) < MAX_EXAMPLES_PER_CHECK:
            examples.append({"invariant": inv, "kind": kind, **detail})

    all_fn_starts: Set[int] = {int(fn["address"]) for fn in cfg_fns}

    # Global inline jump table exclusion intervals (4-byte aligned)
    global_jt_intervals: List[Tuple[int, int]] = []
    for r in inline_ranges_raw:
        r_lo = int(r["start"]) & ~0x3
        r_hi = (int(r["end"]) + 3) & ~0x3
        if r_lo < r_hi:
            global_jt_intervals.append((r_lo, r_hi))
    global_jt_intervals.sort()
    global_jt_starts = {lo for lo, _hi in global_jt_intervals}

    def overlaps_inline_jt(addr: int) -> bool:
        # Binary search over sorted global_jt_intervals
        lo_i, hi_i = 0, len(global_jt_intervals)
        while lo_i < hi_i:
            mid = (lo_i + hi_i) // 2
            if global_jt_intervals[mid][0] <= addr:
                lo_i = mid + 1
            else:
                hi_i = mid
        return lo_i > 0 and addr < global_jt_intervals[lo_i - 1][1]

    # Function-level non-overlap check (I3)
    sorted_fns = sorted(cfg_fns, key=lambda f: int(f["address"]))
    for idx, fn in enumerate(sorted_fns):
        f_start = int(fn["address"])
        f_end = int(fn["endAddress"])
        if f_start >= f_end or (f_start & 3) != 0 or (f_end & 3) != 0:
            record_violation(
                "I3",
                "INVALID_FUNCTION_BOUNDS",
                {"function": fn.get("name"), "start": hex(f_start), "end": hex(f_end)},
            )
        if idx > 0:
            prev_end = int(sorted_fns[idx - 1]["endAddress"])
            if prev_end > f_start:
                record_violation(
                    "I3",
                    "OVERLAPPING_FUNCTIONS",
                    {
                        "prev": sorted_fns[idx - 1].get("name"),
                        "prev_end": hex(prev_end),
                        "curr": fn.get("name"),
                        "curr_start": hex(f_start),
                    },
                )
        first_w = slice_view.read_u32(f_start)
        if first_w is None or (first_w & 0xFFFF0000) == 0:
            record_violation(
                "I3",
                "FUNCTION_ENTRY_NOT_CODE",
                {"function": fn.get("name"), "start": hex(f_start), "word": None if first_w is None else hex(first_w)},
            )

    # Independently solve internal noreturn functions using raw slice instructions + otool -Iv imports
    verified_noreturn_addrs = solve_independent_noreturn_functions(
        slice_view, cfg_fns, imported_symbols_by_addr
    )

    total_blocks = 0
    total_edges = 0
    total_loops = 0
    total_inline_jts = 0
    noreturn_exit_calls_checked = 0

    for fn in sorted_fns:
        f_start = int(fn["address"])
        f_end = int(fn["endAddress"])
        f_name = str(fn.get("name", hex(f_start)))
        blocks = fn.get("blocks", [])
        edges = fn.get("edges", [])
        dom_tree = fn.get("dominatorTree", [])
        nat_loops = fn.get("naturalLoops", [])
        jump_tables = fn.get("jumpTables", [])

        total_blocks += len(blocks)
        total_edges += len(edges)
        total_loops += len(nat_loops)

        if not blocks:
            record_violation("I3", "EMPTY_FUNCTION_BLOCKS", {"function": f_name, "address": hex(f_start)})
            continue

        # --- I3 & I4: Block uniqueness, bounds, 4-byte instruction contiguity, non-overlap ---
        block_by_id: Dict[int, Dict[str, Any]] = {}
        block_by_start: Dict[int, int] = {}
        entry_blocks: List[int] = []
        fn_insn_words: List[Tuple[int, int]] = []

        blocks_by_addr = sorted(blocks, key=lambda b: int(b["startAddress"]))
        for b_pos, blk in enumerate(blocks_by_addr):
            bid = int(blk["id"])
            b_start = int(blk["startAddress"])
            b_end = int(blk["endAddress"])
            insn_addrs = [int(a) for a in blk.get("instructionAddresses", [])]
            insn_cnt = int(blk.get("instructionCount", -1))

            if bid in block_by_id:
                record_violation("I4", "DUPLICATE_BLOCK_ID", {"function": f_name, "blockID": bid})
            block_by_id[bid] = blk

            if b_start in block_by_start:
                record_violation("I3", "DUPLICATE_BLOCK_START", {"function": f_name, "start": hex(b_start)})
            block_by_start[b_start] = bid

            if blk.get("isEntry"):
                entry_blocks.append(bid)

            if b_start < f_start or b_end > f_end or b_start >= b_end:
                record_violation(
                    "I3",
                    "BLOCK_OUT_OF_FUNCTION_RANGE",
                    {"function": f_name, "blockID": bid, "start": hex(b_start), "end": hex(b_end)},
                )

            if b_pos > 0:
                prev_b_end = int(blocks_by_addr[b_pos - 1]["endAddress"])
                if prev_b_end > b_start:
                    record_violation(
                        "I3",
                        "OVERLAPPING_BLOCKS",
                        {"function": f_name, "prevEnd": hex(prev_b_end), "currStart": hex(b_start)},
                    )

            if not insn_addrs or len(insn_addrs) != insn_cnt:
                record_violation(
                    "I3",
                    "EMPTY_OR_COUNT_MISMATCH_BLOCK",
                    {"function": f_name, "blockID": bid, "count": insn_cnt, "len": len(insn_addrs)},
                )
                continue

            if insn_addrs[0] != b_start or insn_addrs[-1] + 4 != b_end:
                record_violation(
                    "I3",
                    "BLOCK_SPAN_MISMATCH_INSNS",
                    {
                        "function": f_name,
                        "blockID": bid,
                        "start": hex(b_start),
                        "end": hex(b_end),
                        "firstInsn": hex(insn_addrs[0]),
                        "lastInsn": hex(insn_addrs[-1]),
                    },
                )

            for k, pc in enumerate(insn_addrs):
                if (pc & 3) != 0 or (k > 0 and pc != insn_addrs[k - 1] + 4):
                    record_violation(
                        "I3",
                        "NON_CONTIGUOUS_4B_INSN",
                        {"function": f_name, "blockID": bid, "pc": hex(pc)},
                    )
                if overlaps_inline_jt(pc):
                    record_violation(
                        "I2",
                        "INLINE_JT_BYTES_DECODED_AS_INSN",
                        {"function": f_name, "blockID": bid, "pc": hex(pc)},
                    )
                w = slice_view.read_u32(pc)
                if w is not None:
                    fn_insn_words.append((pc, w))

        if len(entry_blocks) != 1 or int(block_by_id[entry_blocks[0]]["startAddress"]) != f_start:
            record_violation(
                "I3",
                "INVALID_ENTRY_BLOCK",
                {"function": f_name, "entryBlocks": entry_blocks, "fnStart": hex(f_start)},
            )
            continue
        entry_id = entry_blocks[0]

        # --- I4: Edges, predecessorIDs, successorIDs ---
        edge_pairs: List[Tuple[int, int]] = []
        edge_pair_set: Set[Tuple[int, int]] = set()
        out_edges_by_blk: Dict[int, List[Dict[str, Any]]] = {bid: [] for bid in block_by_id}
        in_sources_by_blk: Dict[int, Set[int]] = {bid: set() for bid in block_by_id}
        out_targets_by_blk: Dict[int, Set[int]] = {bid: set() for bid in block_by_id}

        for e in edges:
            src = int(e["sourceBlockID"])
            dst = int(e["targetBlockID"])
            if src not in block_by_id or dst not in block_by_id:
                record_violation(
                    "I4",
                    "DANGLING_EDGE_ENDPOINT",
                    {"function": f_name, "src": src, "dst": dst},
                )
                continue
            if (src, dst) in edge_pair_set:
                record_violation(
                    "I4",
                    "DUPLICATE_DIRECTED_EDGE",
                    {"function": f_name, "src": src, "dst": dst},
                )
                continue
            edge_pair_set.add((src, dst))
            edge_pairs.append((src, dst))
            out_edges_by_blk[src].append(e)
            out_targets_by_blk[src].add(dst)
            in_sources_by_blk[dst].add(src)

        for bid, blk in block_by_id.items():
            preds_field = [int(x) for x in blk.get("predecessorIDs", [])]
            succs_field = [int(x) for x in blk.get("successorIDs", [])]
            if len(preds_field) != len(set(preds_field)) or set(preds_field) != in_sources_by_blk[bid]:
                record_violation(
                    "I4",
                    "PREDECESSOR_IDS_MISMATCH",
                    {"function": f_name, "blockID": bid, "reported": preds_field, "expected": sorted(in_sources_by_blk[bid])},
                )
            if len(succs_field) != len(set(succs_field)) or set(succs_field) != out_targets_by_blk[bid]:
                record_violation(
                    "I4",
                    "SUCCESSOR_IDS_MISMATCH",
                    {"function": f_name, "blockID": bid, "reported": succs_field, "expected": sorted(out_targets_by_blk[bid])},
                )

        # --- Jump table index & inline jump table checks (I2) ---
        jt_by_dispatch: Dict[int, Dict[str, Any]] = {}
        referenced_addrs = compute_referenced_code_addresses(fn_insn_words) if jump_tables else set()

        for jt in jump_tables:
            disp_pc = int(jt["dispatchInstructionAddress"])
            tbl_base = int(jt["tableBaseAddress"])
            entry_sz = int(jt["entryByteSize"])
            targets = [int(t) for t in jt.get("targetAddresses", [])]
            jt_by_dispatch[disp_pc] = jt

            if jt.get("isInlineInCode"):
                total_inline_jts += 1
                if tbl_base not in referenced_addrs:
                    record_violation(
                        "I2",
                        "INLINE_JT_NOT_REFERENCED_BY_ADR_OR_ADRP_ADD",
                        {"function": f_name, "dispatch": hex(disp_pc), "tableBase": hex(tbl_base)},
                    )
                tbl_end = tbl_base + len(targets) * max(1, entry_sz)
                aligned_end = (tbl_end + 3) & ~0x3
                sec = slice_view.section_containing(tbl_base)
                if sec is not None and aligned_end + 4 <= sec["addr"] + sec["size"]:
                    if aligned_end not in global_jt_starts and not overlaps_inline_jt(aligned_end):
                        post_word = slice_view.read_u32(aligned_end)
                        if post_word is not None and (post_word & 0xFFFF0000) == 0:
                            record_violation(
                                "I2",
                                "INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION",
                                {
                                    "function": f_name,
                                    "tableBase": hex(tbl_base),
                                    "alignedEnd": hex(aligned_end),
                                    "postWord": f"0x{post_word:08x}",
                                },
                            )

        # --- I1 & I2: Instruction-level block interior, terminator/fallthrough, branch targets, noreturn calls ---
        for blk in blocks_by_addr:
            bid = int(blk["id"])
            insn_addrs = [int(a) for a in blk.get("instructionAddresses", [])]
            if not insn_addrs:
                continue

            # 1) Interior instructions must NOT be architectural basic-block terminators
            for pc in insn_addrs[:-1]:
                w = slice_view.read_u32(pc)
                if w is None:
                    record_violation("I1", "UNREADABLE_INSN_BYTES", {"function": f_name, "pc": hex(pc)})
                    continue
                dec = decode_arm64_insn(w, pc)
                if dec["is_terminator"]:
                    record_violation(
                        "I1",
                        "INTERIOR_TERMINATOR",
                        {"function": f_name, "blockID": bid, "pc": hex(pc), "insnKind": dec["kind"]},
                    )

            # 2) Last instruction of block
            last_pc = insn_addrs[-1]
            last_w = slice_view.read_u32(last_pc)
            if last_w is None:
                record_violation("I1", "UNREADABLE_LAST_INSN", {"function": f_name, "pc": hex(last_pc)})
                continue
            dec = decode_arm64_insn(last_w, last_pc)
            kind = dec["kind"]
            out_targets = out_targets_by_blk[bid]
            is_exit = bool(blk.get("isExit"))
            adj_next_id = block_by_start.get(last_pc + 4)

            if kind in ("ret", "udf", "brk", "hlt"):
                if out_targets or not is_exit:
                    record_violation(
                        "I1",
                        "NON_FALLTHROUGH_TERMINATOR_HAS_OUT_EDGE_OR_NOT_EXIT",
                        {"function": f_name, "blockID": bid, "pc": hex(last_pc), "kind": kind, "out": sorted(out_targets)},
                    )

            elif kind == "b":
                tgt = dec["target"]
                if f_start <= tgt < f_end:
                    tgt_bid = block_by_start.get(tgt)
                    if tgt_bid is None:
                        record_violation(
                            "I2",
                            "INTRA_FN_BRANCH_TARGET_NOT_BLOCK_START",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc), "target": hex(tgt)},
                        )
                    elif out_targets != {tgt_bid}:
                        record_violation(
                            "I4",
                            "UNCOND_BRANCH_EDGE_MISMATCH",
                            {"function": f_name, "blockID": bid, "expected": [tgt_bid], "actual": sorted(out_targets)},
                        )
                else:
                    if tgt not in all_fn_starts:
                        record_violation(
                            "I2",
                            "CROSS_FN_TAIL_JUMP_NOT_FUNCTION_START",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc), "target": hex(tgt)},
                        )
                    if out_targets or not is_exit:
                        record_violation(
                            "I1",
                            "TAIL_JUMP_BLOCK_MUST_BE_EXIT_WITHOUT_INTRA_EDGES",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc)},
                        )

            elif kind == "cond_branch":
                tgt = dec["target"]
                expected_succs: Set[int] = set()
                if f_start <= tgt < f_end:
                    tgt_bid = block_by_start.get(tgt)
                    if tgt_bid is None:
                        record_violation(
                            "I2",
                            "INTRA_FN_COND_BRANCH_TARGET_NOT_BLOCK_START",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc), "target": hex(tgt)},
                        )
                    else:
                        expected_succs.add(tgt_bid)
                else:
                    if tgt not in all_fn_starts:
                        record_violation(
                            "I2",
                            "CROSS_FN_COND_TAIL_BRANCH_NOT_FUNCTION_START",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc), "target": hex(tgt)},
                        )
                if adj_next_id is None:
                    record_violation(
                        "I1",
                        "COND_BRANCH_MISSING_ADJACENT_FALLTHROUGH_BLOCK",
                        {"function": f_name, "blockID": bid, "pc": hex(last_pc)},
                    )
                else:
                    expected_succs.add(adj_next_id)
                if expected_succs and out_targets != expected_succs:
                    record_violation(
                        "I4",
                        "COND_BRANCH_OUT_EDGES_MISMATCH",
                        {"function": f_name, "blockID": bid, "expected": sorted(expected_succs), "actual": sorted(out_targets)},
                    )

            elif kind == "indirect_jump":
                jt = jt_by_dispatch.get(last_pc)
                if jt is not None and jt.get("targetAddresses"):
                    expected_jt_succs: Set[int] = set()
                    for t_raw in jt["targetAddresses"]:
                        t = int(t_raw)
                        if f_start <= t < f_end:
                            t_bid = block_by_start.get(t)
                            if t_bid is None:
                                record_violation(
                                    "I2",
                                    "JUMP_TABLE_TARGET_NOT_BLOCK_START",
                                    {"function": f_name, "blockID": bid, "dispatch": hex(last_pc), "target": hex(t)},
                                )
                            else:
                                expected_jt_succs.add(t_bid)
                        elif t not in all_fn_starts:
                            record_violation(
                                "I2",
                                "JUMP_TABLE_EXTERNAL_TARGET_NOT_FN_START",
                                {"function": f_name, "blockID": bid, "dispatch": hex(last_pc), "target": hex(t)},
                            )
                    if expected_jt_succs and out_targets != expected_jt_succs:
                        record_violation(
                            "I4",
                            "JUMP_TABLE_OUT_EDGES_MISMATCH",
                            {
                                "function": f_name,
                                "blockID": bid,
                                "expected": sorted(expected_jt_succs),
                                "actual": sorted(out_targets),
                            },
                        )
                else:
                    if out_targets or not is_exit:
                        record_violation(
                            "I1",
                            "UNRESOLVED_INDIRECT_JUMP_MUST_BE_EXIT",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc)},
                        )

            elif kind in ("svc", "hvc_smc"):
                if out_targets:
                    if adj_next_id is None or out_targets != {adj_next_id}:
                        record_violation(
                            "I1",
                            "SVC_FALLTHROUGH_NOT_ADJACENT",
                            {"function": f_name, "blockID": bid, "pc": hex(last_pc)},
                        )
                elif not is_exit:
                    record_violation(
                        "I1",
                        "SVC_WITHOUT_FALLTHROUGH_NOT_MARKED_EXIT",
                        {"function": f_name, "blockID": bid, "pc": hex(last_pc)},
                    )

            elif kind == "bl":
                tgt = dec["target"]
                if not out_targets and is_exit:
                    # Noreturn call at end of block: verify target is an approved imported noreturn
                    # symbol (from otool -Iv) OR an internal function whose all reachable paths never return!
                    noreturn_exit_calls_checked += 1
                    if tgt not in verified_noreturn_addrs:
                        imp_sym = imported_symbols_by_addr.get(tgt)
                        record_violation(
                            "I1",
                            "UNVERIFIED_NORETURN_BL_EXIT",
                            {
                                "function": f_name,
                                "blockID": bid,
                                "pc": hex(last_pc),
                                "callee": hex(tgt),
                                "importedSymbol": imp_sym,
                            },
                        )
                else:
                    # Returning direct call: must fall through contiguously to `last_pc + 4`
                    if adj_next_id is None or out_targets != {adj_next_id} or is_exit:
                        record_violation(
                            "I1",
                            "RETURNING_BL_MISSING_CONTIGUOUS_FALLTHROUGH",
                            {
                                "function": f_name,
                                "blockID": bid,
                                "pc": hex(last_pc),
                                "callee": hex(tgt),
                                "out": sorted(out_targets),
                            },
                        )

            else:
                # Sequential / indirect_call instruction at end of block MUST fall through contiguously
                if adj_next_id is None or out_targets != {adj_next_id} or is_exit:
                    record_violation(
                        "I1",
                        "SEQUENTIAL_BLOCK_END_NOT_CONTIGUOUS_FALLTHROUGH",
                        {
                            "function": f_name,
                            "blockID": bid,
                            "pc": hex(last_pc),
                            "kind": kind,
                            "out": sorted(out_targets),
                        },
                    )

        # Verify every jumpTable in `fn["jumpTables"]` actually points to an indirect_jump instruction in `fn`
        for jt in jump_tables:
            disp_pc = int(jt["dispatchInstructionAddress"])
            w_disp = slice_view.read_u32(disp_pc)
            if w_disp is None or decode_arm64_insn(w_disp, disp_pc)["kind"] != "indirect_jump":
                record_violation(
                    "I2",
                    "JUMP_TABLE_DISPATCH_NOT_INDIRECT_JUMP",
                    {"function": f_name, "dispatch": hex(disp_pc)},
                )

        # --- I4: Independent Iterative Dominator Tree & Natural Loops cross-check ---
        ordered_ids = [int(b["id"]) for b in blocks]
        indep = solve_dominators_and_loops_independent(ordered_ids, entry_id, edge_pairs)

        dom_by_id: Dict[int, Dict[str, Any]] = {}
        for dnode in dom_tree:
            dbid = int(dnode["blockID"])
            if dbid not in block_by_id or dbid in dom_by_id:
                record_violation("I4", "INVALID_OR_DUP_DOM_NODE", {"function": f_name, "blockID": dbid})
                continue
            dom_by_id[dbid] = dnode

        if set(dom_by_id.keys()) != set(block_by_id.keys()):
            record_violation(
                "I4",
                "DOM_TREE_BLOCK_SET_MISMATCH",
                {"function": f_name, "domCount": len(dom_by_id), "blockCount": len(block_by_id)},
            )
        else:
            for bid, dnode in dom_by_id.items():
                raw_idom = dnode.get("immediateDominatorID")
                rep_idom = None if raw_idom is None else int(raw_idom)
                exp_idom = indep["idom"][bid]
                if rep_idom != exp_idom:
                    record_violation(
                        "I4",
                        "IDOM_MISMATCH",
                        {"function": f_name, "blockID": bid, "reported": rep_idom, "expected": exp_idom},
                    )
                rep_children = sorted(int(c) for c in dnode.get("dominatedChildrenIDs", []))
                if rep_children != indep["children"][bid]:
                    record_violation(
                        "I4",
                        "DOM_CHILDREN_MISMATCH",
                        {"function": f_name, "blockID": bid, "reported": rep_children, "expected": indep["children"][bid]},
                    )
                rep_depth = int(dnode.get("depth", -1))
                if rep_depth != indep["depth"][bid]:
                    record_violation(
                        "I4",
                        "DOM_DEPTH_MISMATCH",
                        {"function": f_name, "blockID": bid, "reported": rep_depth, "expected": indep["depth"][bid]},
                    )
                rep_df = sorted(int(x) for x in dnode.get("dominanceFrontierIDs", []))
                if any(x not in block_by_id for x in rep_df) or rep_df != indep["dominance_frontiers"][bid]:
                    record_violation(
                        "I4",
                        "DOM_FRONTIER_MISMATCH",
                        {"function": f_name, "blockID": bid, "reported": rep_df, "expected": indep["dominance_frontiers"][bid]},
                    )

        # Natural back-edges & natural loops check
        for e in edges:
            pair = (int(e["sourceBlockID"]), int(e["targetBlockID"]))
            if pair in indep["natural_back_edges"] and not e.get("isBackEdge"):
                record_violation(
                    "I4",
                    "NATURAL_BACK_EDGE_NOT_MARKED",
                    {"function": f_name, "edge": list(pair)},
                )

        rep_loops_norm = sorted(
            [
                {
                    "headerBlockID": int(lp["headerBlockID"]),
                    "latchBlockIDs": sorted(int(x) for x in lp.get("latchBlockIDs", [])),
                    "bodyBlockIDs": sorted(int(x) for x in lp.get("bodyBlockIDs", [])),
                    "exitBlockIDs": sorted(int(x) for x in lp.get("exitBlockIDs", [])),
                    "nestingDepth": int(lp.get("nestingDepth", -1)),
                }
                for lp in nat_loops
            ],
            key=lambda x: x["headerBlockID"],
        )
        for lp in rep_loops_norm:
            referenced_loop_ids = (
                [lp["headerBlockID"]] + lp["latchBlockIDs"] + lp["bodyBlockIDs"] + lp["exitBlockIDs"]
            )
            if any(x not in block_by_id for x in referenced_loop_ids):
                record_violation("I4", "LOOP_REFERENCES_MISSING_BLOCK", {"function": f_name, "loop": lp})

        if rep_loops_norm != indep["natural_loops"]:
            record_violation(
                "I4",
                "NATURAL_LOOPS_MISMATCH",
                {
                    "function": f_name,
                    "reportedCount": len(rep_loops_norm),
                    "expectedCount": len(indep["natural_loops"]),
                    "reportedSample": rep_loops_norm[:2],
                    "expectedSample": indep["natural_loops"][:2],
                },
            )

    total_violations = sum(violations_by_inv.values())
    return {
        "status": "pass" if total_violations == 0 else "fail",
        "ref_count": len(sorted_fns),
        "mg_count": len(sorted_fns),
        "function_count": len(sorted_fns),
        "block_count": total_blocks,
        "edge_count": total_edges,
        "loop_count": total_loops,
        "inline_jt_count": total_inline_jts,
        "noreturn_exit_calls_verified": noreturn_exit_calls_checked,
        "violations_by_invariant": violations_by_inv,
        "diff_count": total_violations,
        "examples": examples[:MAX_EXAMPLES_PER_CHECK],
    }


def evaluate_one_binary(
    path: str,
    selected_corpus_checks: Sequence[str],
    machgraph_bin: str,
    isolated_home: str,
) -> Dict[str, Any]:
    """Run selected corpus checks (`function-starts` and/or `invariants`) on a single binary."""
    t0 = time.perf_counter()
    try:
        with open(path, "rb") as fh:
            file_bytes = fh.read()
    except OSError as exc:
        return {"path": path, "skipped": f"unreadable: {exc}"}

    arch = select_arm64_slice(path)
    if arch is None:
        return {"path": path, "skipped": "no arm64 slice"}

    try:
        slice_view = parse_macho_arm64_slice(file_bytes, preferred_arch=arch)
    except ValueError as exc:
        return {"path": path, "arch": arch, "failure": f"Mach-O parse error: {exc}", "timed_out": False}

    if slice_view is None:
        return {"path": path, "skipped": "no 64-bit arm64 slice"}
    if slice_view.filetype not in SUPPORTED_FILETYPES or not slice_view.executable_sections:
        return {"path": path, "skipped": f"unsupported filetype={slice_view.filetype} or no code sections"}

    timeout_sec = per_file_timeout_seconds(path)
    env = dict(os.environ, HOME=isolated_home)

    # Always run `machgraph cfg <path> --json` once since both `function-starts` and `invariants` inspect it.
    try:
        cfg_proc = run_subprocess_bytes([machgraph_bin, "cfg", path, "--json"], timeout=timeout_sec, env=env)
    except subprocess.TimeoutExpired:
        return {
            "path": path,
            "arch": arch,
            "failed_check": selected_corpus_checks[0],
            "failure": f"machgraph cfg timed out after {timeout_sec:.0f}s",
            "timed_out": True,
        }
    cfg_out, non_utf8_cfg = decode_utf8_safe(cfg_proc.stdout)
    if cfg_proc.returncode != 0:
        err_out, _ = decode_utf8_safe(cfg_proc.stderr)
        return {
            "path": path,
            "arch": arch,
            "failed_check": selected_corpus_checks[0],
            "failure": f"machgraph cfg exited {cfg_proc.returncode}: {err_out.strip()[:240]}",
            "timed_out": False,
            "non_utf8": non_utf8_cfg,
        }
    try:
        cfg_json = json.loads(cfg_out)
    except json.JSONDecodeError as exc:
        return {
            "path": path,
            "arch": arch,
            "failed_check": selected_corpus_checks[0],
            "failure": f"invalid JSON from machgraph cfg: {exc}",
            "timed_out": False,
        }

    checks_out: Dict[str, Any] = {}
    non_utf8 = non_utf8_cfg

    if "function-starts" in selected_corpus_checks:
        dyld_starts, dyld_err, dyld_to = run_dyld_info_function_starts(path, arch, timeout=max(60.0, timeout_sec))
        if dyld_err is not None:
            return {
                "path": path,
                "arch": arch,
                "failed_check": "function-starts",
                "failure": dyld_err,
                "timed_out": dyld_to,
            }
        try:
            info_proc = run_subprocess_bytes([machgraph_bin, "info", path, "--json"], timeout=timeout_sec, env=env)
        except subprocess.TimeoutExpired:
            return {
                "path": path,
                "arch": arch,
                "failed_check": "function-starts",
                "failure": f"machgraph info timed out after {timeout_sec:.0f}s",
                "timed_out": True,
            }
        info_out, non_utf8_info = decode_utf8_safe(info_proc.stdout)
        non_utf8 = non_utf8 or non_utf8_info
        if info_proc.returncode != 0:
            err_out, _ = decode_utf8_safe(info_proc.stderr)
            return {
                "path": path,
                "arch": arch,
                "failed_check": "function-starts",
                "failure": f"machgraph info exited {info_proc.returncode}: {err_out.strip()[:240]}",
                "timed_out": False,
            }
        try:
            info_json = json.loads(info_out)
        except json.JSONDecodeError as exc:
            return {
                "path": path,
                "arch": arch,
                "failed_check": "function-starts",
                "failure": f"invalid JSON from machgraph info: {exc}",
                "timed_out": False,
            }
        checks_out["function-starts"] = check_function_starts_on_loaded(slice_view, dyld_starts, info_json, cfg_json)

    if "invariants" in selected_corpus_checks:
        imp_map, imp_err, imp_to = resolve_import_symbols_for_binary(
            path, arch, slice_view, cfg_json.get("functions", []), timeout=max(60.0, timeout_sec)
        )
        if imp_err is not None:
            return {
                "path": path,
                "arch": arch,
                "failed_check": "invariants",
                "failure": imp_err,
                "timed_out": imp_to,
            }
        checks_out["invariants"] = check_invariants_on_loaded(slice_view, cfg_json, imp_map)

    elapsed = round(time.perf_counter() - t0, 3)
    return {
        "path": path,
        "arch": arch,
        "seconds": elapsed,
        "non_utf8": non_utf8,
        "checks": checks_out,
    }


# ---------------------------------------------------------------------------
# Row 3 (`known-c`): live `xcrun clang -O0` compilation & ground-truth check
# ---------------------------------------------------------------------------


def evaluate_known_c_suite(machgraph_bin: str, isolated_home: str) -> Dict[str, Any]:
    """Compile the 8 known-answer C functions with `xcrun clang -O0 -arch arm64` in a temp dir
    and verify both `--symbol` single-function and full-file `cfg --json` outputs."""
    t0 = time.perf_counter()
    env = dict(os.environ, HOME=isolated_home)
    examples: List[Dict[str, Any]] = []
    case_rows: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="machgraph-m4-known-c-") as tmp_dir:
        c_path = os.path.join(tmp_dir, "known_cfg.c")
        bin_path = os.path.join(tmp_dir, "known_cfg")
        with open(c_path, "w", encoding="utf-8") as fh:
            fh.write(KNOWN_C_SOURCE)

        comp = run_subprocess_bytes(
            ["xcrun", "clang", "-O0", "-arch", "arm64", c_path, "-o", bin_path],
            timeout=60.0,
            env=env,
        )
        if comp.returncode != 0:
            err_txt, _ = decode_utf8_safe(comp.stderr)
            return {
                "status": "fail",
                "error": f"xcrun clang -O0 failed (exit {comp.returncode}): {sanitize_text(err_txt.strip()[:300])}",
                "diff_count": 1,
                "ref_count": len(KNOWN_C_EXPECTED),
                "mg_count": 0,
                "cases": [],
                "examples": [],
                "seconds": round(time.perf_counter() - t0, 3),
            }

        # Run full-file `function-starts` + `invariants` on the compiled binary as well
        full_eval = evaluate_one_binary(bin_path, ("function-starts", "invariants"), machgraph_bin, isolated_home)
        if "failure" in full_eval:
            return {
                "status": "fail",
                "error": sanitize_text(str(full_eval["failure"])),
                "diff_count": 1,
                "ref_count": len(KNOWN_C_EXPECTED),
                "mg_count": 0,
                "cases": [],
                "examples": [],
                "seconds": round(time.perf_counter() - t0, 3),
            }

        for sub_chk in ("function-starts", "invariants"):
            sub_res = full_eval["checks"][sub_chk]
            if sub_res["status"] != "pass":
                for ex in sub_res.get("examples", []):
                    examples.append({"subcheck": sub_chk, **ex})

        # Full-file CFG lookup map
        full_proc = run_subprocess_bytes([machgraph_bin, "cfg", bin_path, "--json"], timeout=60.0, env=env)
        full_json = json.loads(full_proc.stdout.decode("utf-8", errors="replace"))
        full_by_name = {fn["name"]: fn for fn in full_json.get("functions", [])}

        # Check each of the 8 known-answer functions via `--symbol` AND full-file consistency
        for spec in KNOWN_C_EXPECTED:
            sym = spec["symbol"]
            single_proc = run_subprocess_bytes(
                [machgraph_bin, "cfg", bin_path, "--symbol", sym, "--json"],
                timeout=30.0,
                env=env,
            )
            if single_proc.returncode != 0:
                err_txt, _ = decode_utf8_safe(single_proc.stderr)
                examples.append({"symbol": sym, "error": f"cfg --symbol exited {single_proc.returncode}: {err_txt.strip()[:160]}"})
                case_rows.append({"symbol": sym, "status": "FAIL"})
                continue

            single_json = json.loads(single_proc.stdout.decode("utf-8", errors="replace"))
            fns = single_json.get("functions", [])
            if len(fns) != 1:
                examples.append({"symbol": sym, "error": f"expected 1 function, got {len(fns)}"})
                case_rows.append({"symbol": sym, "status": "FAIL"})
                continue

            fn_obj = fns[0]
            actual_blocks = len(fn_obj.get("blocks", []))
            actual_edges = len(fn_obj.get("edges", []))
            actual_loops = len(fn_obj.get("naturalLoops", []))
            actual_depths = sorted(int(lp["nestingDepth"]) for lp in fn_obj.get("naturalLoops", []))
            jts = fn_obj.get("jumpTables", [])
            actual_jt_count = len(jts)
            actual_jt_targets = sum(len(jt.get("targetAddresses", [])) for jt in jts)

            full_fn = full_by_name.get(sym)
            full_consistent = (
                full_fn is not None
                and len(full_fn.get("blocks", [])) == actual_blocks
                and len(full_fn.get("edges", [])) == actual_edges
                and len(full_fn.get("naturalLoops", [])) == actual_loops
            )

            mismatches: Dict[str, Any] = {}
            if actual_blocks != spec["blocks"]:
                mismatches["blocks"] = {"expected": spec["blocks"], "actual": actual_blocks}
            if actual_edges != spec["edges"]:
                mismatches["edges"] = {"expected": spec["edges"], "actual": actual_edges}
            if actual_loops != spec["loops"]:
                mismatches["loops"] = {"expected": spec["loops"], "actual": actual_loops}
            if actual_depths != spec["loop_nesting_depths"]:
                mismatches["loop_nesting_depths"] = {
                    "expected": spec["loop_nesting_depths"],
                    "actual": actual_depths,
                }
            if actual_jt_count != spec["jump_table_count"]:
                mismatches["jump_table_count"] = {
                    "expected": spec["jump_table_count"],
                    "actual": actual_jt_count,
                }
            if actual_jt_targets != spec["jump_table_targets"]:
                mismatches["jump_table_targets"] = {
                    "expected": spec["jump_table_targets"],
                    "actual": actual_jt_targets,
                }
            if not full_consistent:
                mismatches["single_vs_full_file_cfg"] = "mismatch"

            passed_case = len(mismatches) == 0
            if not passed_case:
                examples.append({"symbol": sym, "mismatches": mismatches})

            case_rows.append(
                {
                    "symbol": sym,
                    "description": spec["description"],
                    "status": "PASS" if passed_case else "FAIL",
                    "expected": {
                        "blocks": spec["blocks"],
                        "edges": spec["edges"],
                        "loops": spec["loops"],
                        "loop_nesting_depths": spec["loop_nesting_depths"],
                        "jump_table_count": spec["jump_table_count"],
                        "jump_table_targets": spec["jump_table_targets"],
                    },
                    "actual": {
                        "blocks": actual_blocks,
                        "edges": actual_edges,
                        "loops": actual_loops,
                        "loop_nesting_depths": actual_depths,
                        "jump_table_count": actual_jt_count,
                        "jump_table_targets": actual_jt_targets,
                    },
                }
            )

    matched_cases = sum(1 for c in case_rows if c.get("status") == "PASS")
    diff_count = len(examples)
    return {
        "status": "pass" if (diff_count == 0 and matched_cases == len(KNOWN_C_EXPECTED)) else "fail",
        "ref_count": len(KNOWN_C_EXPECTED),
        "mg_count": matched_cases,
        "matched_cases": matched_cases,
        "total_cases": len(KNOWN_C_EXPECTED),
        "diff_count": diff_count,
        "cases": case_rows,
        "examples": examples[:MAX_EXAMPLES_PER_CHECK],
        "seconds": round(time.perf_counter() - t0, 3),
    }


# ---------------------------------------------------------------------------
# Row 5 (`perf`): monotonic wall-clock latency & functional check on ssh / vim
# ---------------------------------------------------------------------------


def _read_uptime() -> str:
    res = subprocess.run(["/usr/bin/uptime"], capture_output=True, stdin=subprocess.DEVNULL)
    txt, _ = decode_utf8_safe(res.stdout)
    return sanitize_text(txt.strip())


def evaluate_perf_suite(machgraph_bin: str, isolated_home: str) -> Dict[str, Any]:
    """Measure 3-run median monotonic wall-clock time for `ssh` full-file, `vim` full-file,
    and `ssh --symbol _entry` single-function `cfg --json`."""
    t_suite = time.perf_counter()
    env = dict(os.environ, HOME=isolated_home)
    uptime_before = _read_uptime()

    specs = [
        {
            "id": "ssh_full",
            "label": "cfg /usr/bin/ssh --json (full-file)",
            "args": [machgraph_bin, "cfg", "/usr/bin/ssh", "--json"],
            "hang_timeout": SSH_HANG_FAIL_SECONDS,
            "warn_budget": SSH_BUDGET_WARN_SECONDS,
            "min_functions": 1000,
        },
        {
            "id": "vim_full",
            "label": "cfg /usr/bin/vim --json (full-file)",
            "args": [machgraph_bin, "cfg", "/usr/bin/vim", "--json"],
            "hang_timeout": VIM_HANG_FAIL_SECONDS,
            "warn_budget": None,
            "min_functions": 5000,
        },
        {
            "id": "ssh_single_symbol",
            "label": "cfg /usr/bin/ssh --symbol _entry --json (single-function)",
            "args": [machgraph_bin, "cfg", "/usr/bin/ssh", "--symbol", "_entry", "--json"],
            "hang_timeout": SSH_HANG_FAIL_SECONDS,
            "warn_budget": None,
            "expected_functions": 1,
        },
    ]

    benchmarks: Dict[str, Any] = {}
    warnings: List[str] = []
    failures: List[Dict[str, Any]] = []

    for sp in specs:
        runs: List[float] = []
        fn_count = 0
        block_total = 0
        out_bytes = 0
        bench_failed = False

        for run_idx in range(PERF_RUN_COUNT):
            t0 = time.perf_counter()
            try:
                proc = subprocess.run(
                    sp["args"],
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    timeout=sp["hang_timeout"],
                    env=env,
                )
            except subprocess.TimeoutExpired:
                failures.append(
                    {
                        "benchmark": sp["id"],
                        "run": run_idx + 1,
                        "error": f"timed out exceeding {sp['hang_timeout']:.1f}s hang guard",
                    }
                )
                bench_failed = True
                break
            elapsed = time.perf_counter() - t0

            if proc.returncode != 0:
                err_txt, _ = decode_utf8_safe(proc.stderr)
                failures.append(
                    {
                        "benchmark": sp["id"],
                        "run": run_idx + 1,
                        "error": f"exited {proc.returncode}: {sanitize_text(err_txt.strip()[:200])}",
                    }
                )
                bench_failed = True
                break

            try:
                payload = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                failures.append({"benchmark": sp["id"], "run": run_idx + 1, "error": f"invalid JSON: {exc}"})
                bench_failed = True
                break

            fns = payload.get("functions", [])
            if payload.get("schema") != "machgraph.cfg/1" or int(payload.get("functionCount", -1)) != len(fns):
                failures.append({"benchmark": sp["id"], "run": run_idx + 1, "error": "schema or functionCount mismatch"})
                bench_failed = True
                break
            if "min_functions" in sp and len(fns) < sp["min_functions"]:
                failures.append(
                    {
                        "benchmark": sp["id"],
                        "run": run_idx + 1,
                        "error": f"expected >= {sp['min_functions']} functions, got {len(fns)}",
                    }
                )
                bench_failed = True
                break
            if "expected_functions" in sp and len(fns) != sp["expected_functions"]:
                failures.append(
                    {
                        "benchmark": sp["id"],
                        "run": run_idx + 1,
                        "error": f"expected {sp['expected_functions']} function, got {len(fns)}",
                    }
                )
                bench_failed = True
                break

            runs.append(round(elapsed, 4))
            fn_count = len(fns)
            block_total = sum(len(f.get("blocks", [])) for f in fns)
            out_bytes = len(proc.stdout)

        median_sec = round(statistics.median(runs), 4) if runs else None
        warn_msg: Optional[str] = None
        if not bench_failed and median_sec is not None:
            if sp["id"] == "ssh_full" and median_sec > SSH_HANG_FAIL_SECONDS:
                failures.append(
                    {
                        "benchmark": sp["id"],
                        "error": f"median {median_sec:.4f}s exceeded {SSH_HANG_FAIL_SECONDS:.1f}s hang limit",
                    }
                )
                bench_failed = True
            elif sp.get("warn_budget") is not None and median_sec > sp["warn_budget"]:
                warn_msg = (
                    f"{sp['label']} median {median_sec:.4f}s > {sp['warn_budget']:.1f}s reference line "
                    f"(non-fatal under host load)"
                )
                warnings.append(warn_msg)

        benchmarks[sp["id"]] = {
            "label": sp["label"],
            "status": "FAIL" if bench_failed else ("WARN" if warn_msg else "PASS"),
            "runs_seconds": runs,
            "median_seconds": median_sec,
            "function_count": fn_count,
            "block_count": block_total,
            "json_bytes": out_bytes,
            "warn_budget_seconds": sp.get("warn_budget"),
            "hang_timeout_seconds": sp["hang_timeout"],
            **({"warning": warn_msg} if warn_msg else {}),
        }

    uptime_after = _read_uptime()
    return {
        "status": "pass" if len(failures) == 0 else "fail",
        "ref_count": len(specs),
        "mg_count": sum(1 for b in benchmarks.values() if b["status"] in ("PASS", "WARN")),
        "diff_count": len(failures),
        "uptime_before": uptime_before,
        "uptime_after": uptime_after,
        "benchmarks": benchmarks,
        "warnings": warnings,
        "examples": failures[:MAX_EXAMPLES_PER_CHECK],
        "seconds": round(time.perf_counter() - t_suite, 3),
    }


# ---------------------------------------------------------------------------
# Corpus discovery, fixed-seed `full` sampling, metadata & CLI reporting
# ---------------------------------------------------------------------------


def discover_full_candidates(roots: Sequence[str] = FULL_SCAN_ROOTS) -> List[str]:
    """Same Mach-O candidate discovery as `differential.py`: walk `/bin`, `/usr/bin`,
    `/usr/sbin`, `/usr/libexec`, skip symlinks, deduplicate by `(st_dev, st_ino)`, sort."""
    seen_inodes: Set[Tuple[int, int]] = set()
    found: List[str] = []
    for root in roots:
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


def _has_arm64_executable_slice_fast(path: str) -> bool:
    """Fast header-only filter (no subprocesses) checking for a 64-bit ARM64/ARM64e executable image."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if len(head) < 32:
                return False
            magic_be = struct.unpack(">I", head[:4])[0]
            magic_le = struct.unpack("<I", head[:4])[0]
            if magic_le == MH_MAGIC_64:
                cputype, _sub, filetype = struct.unpack("<iiI", head[4:16])
                return cputype == CPU_TYPE_ARM64 and filetype in SUPPORTED_FILETYPES
            if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
                nfat = struct.unpack(">I", head[4:8])[0]
                is_fat64 = magic_be == FAT_MAGIC_64
                esize = 32 if is_fat64 else 20
                for i in range(nfat):
                    off = 8 + i * esize
                    if off + esize > len(head):
                        break
                    if is_fat64:
                        cputype, _sub, s_off, _s_sz, _a, _r = struct.unpack(">iiQQII", head[off : off + 32])
                    else:
                        cputype, _sub, s_off, _s_sz, _a = struct.unpack(">iiIII", head[off : off + 20])
                    if cputype == CPU_TYPE_ARM64:
                        fh.seek(s_off)
                        shdr = fh.read(16)
                        if len(shdr) == 16:
                            smagic, scpu, _ssub, sft = struct.unpack("<IiiI", shdr)
                            if smagic == MH_MAGIC_64 and scpu == CPU_TYPE_ARM64 and sft in SUPPORTED_FILETYPES:
                                return True
    except OSError:
        return False
    return False


def select_full_corpus_targets(
    seed: int = DEFAULT_FULL_SEED,
    sample_size: int = DEFAULT_FULL_SAMPLE_SIZE,
    full_all: bool = False,
    roots: Sequence[str] = FULL_SCAN_ROOTS,
) -> Tuple[List[str], Dict[str, Any]]:
    """Discover all Mach-O files under `roots` and deterministically sample with fixed `seed`."""
    all_macho = discover_full_candidates(roots=roots)
    arm64_pool = [p for p in all_macho if _has_arm64_executable_slice_fast(p)]
    skipped_pre = len(all_macho) - len(arm64_pool)

    if full_all or sample_size <= 0 or sample_size >= len(arm64_pool):
        selected = list(arm64_pool)
        method = "exhaustive_all_discovered_arm64_macho"
    else:
        pinned = [p for p in STANDARD_FILES if p in arm64_pool]
        pinned_set = set(pinned)
        remaining = [p for p in arm64_pool if p not in pinned_set]
        rng = random.Random(seed)
        extra_needed = max(0, sample_size - len(pinned))
        sampled_extra = rng.sample(remaining, min(extra_needed, len(remaining)))
        selected = sorted(pinned + sampled_extra)
        method = (
            f"fixed_seed_uniform_without_replacement(seed={seed}, sample_size={len(selected)}, "
            f"pinned_standard={len(pinned)},roots={list(roots)})"
        )

    meta = {
        "method": method,
        "scan_roots": list(roots),
        "total_discovered_macho_files": len(all_macho),
        "arm64_executable_pool_count": len(arm64_pool),
        "pre_filtered_non_arm64_count": skipped_pre,
        "seed": seed,
        "requested_sample_size": 0 if full_all else sample_size,
        "selected_count": len(selected),
        "selected_files": [sanitize_display_path(p) for p in selected],
    }
    return (selected, meta)


def parse_only_checks(only_arg: Optional[str]) -> Optional[List[str]]:
    if only_arg is None:
        return None
    parts = [p.strip() for p in only_arg.split(",") if p.strip()]
    if not parts:
        raise ValueError("--only must name at least one check")
    unknown = [p for p in parts if p not in AVAILABLE_CHECKS]
    if unknown:
        raise ValueError(f"unknown check(s) in --only: {', '.join(unknown)} (available: {', '.join(AVAILABLE_CHECKS)})")
    dedup: List[str] = []
    for p in parts:
        if p not in dedup:
            dedup.append(p)
    return dedup


def collect_environment_metadata(machgraph_bin: str) -> Dict[str, Any]:
    def run_text(cmd: Sequence[str], cwd: Optional[str] = None) -> str:
        r = subprocess.run(list(cmd), capture_output=True, stdin=subprocess.DEVNULL, cwd=cwd)
        txt, _ = decode_utf8_safe(r.stdout)
        return sanitize_text(txt.strip())

    objdump_raw = run_text(["xcrun", "llvm-objdump", "--version"])
    objdump_ver = next(
        (ln.strip() for ln in objdump_raw.splitlines() if "LLVM version" in ln or "Apple LLVM" in ln),
        objdump_raw.splitlines()[0].strip() if objdump_raw else "unknown",
    )
    clang_raw = run_text(["xcrun", "clang", "--version"])
    clang_ver = clang_raw.splitlines()[0].strip() if clang_raw else "unknown"
    commit_sha = run_text(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT) or "unknown"

    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
        "clang_version": clang_ver,
        "llvm_objdump_version": objdump_ver,
        "machgraph_commit": commit_sha,
        "worktree_clean": is_worktree_clean(),
        "machgraph_binary": sanitize_display_path(machgraph_bin),
    }


def default_record_paths(mode_label: str, date_str: str) -> Tuple[str, str]:
    reports_dir = os.path.join(REPO_ROOT, "reports")
    if mode_label == "standard":
        base = os.path.join(reports_dir, "m4-cfg-acceptance")
    elif mode_label == "full":
        base = os.path.join(reports_dir, f"m4-cfg-acceptance-full-{date_str}")
    else:
        base = os.path.join(reports_dir, f"m4-cfg-acceptance-{mode_label}")
    return (base + ".json", base + ".txt")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "targets",
        nargs="*",
        help="'standard' (default), 'quick', 'full', 'known-c', 'perf', 'all', or binary paths",
    )
    parser.add_argument(
        "--only",
        default=None,
        help=f"comma-separated subset of checks ({','.join(AVAILABLE_CHECKS)})",
    )
    parser.add_argument("--machgraph", default=default_machgraph_bin(), help="path to MachGraph CLI executable")
    parser.add_argument("--json-out", default=None, help="optional path to write structured JSON report")
    parser.add_argument("--txt-out", default=None, help="optional path to write plain-text report")
    parser.add_argument(
        "--record",
        action="store_true",
        help="write report to reports/m4-cfg-acceptance.json and .txt (requires clean git worktree)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_FULL_SEED,
        help=f"fixed RNG seed for 'full' corpus sampling (default: {DEFAULT_FULL_SEED})",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_FULL_SAMPLE_SIZE,
        help=f"sample size for 'full' corpus (default: {DEFAULT_FULL_SAMPLE_SIZE}; 0 = all)",
    )
    parser.add_argument("--full-all", action="store_true", help="run all discovered ARM64 Mach-O files in 'full' mode")
    parser.add_argument(
        "--workers",
        type=int,
        default=min(MAX_CONCURRENT_SUBPROCESSES, os.cpu_count() or 4),
        help=f"parallel worker count (capped at {MAX_CONCURRENT_SUBPROCESSES})",
    )
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        explicit_only = parse_only_checks(args.only)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2

    raw_targets = list(args.targets) if args.targets else ["standard"]

    # Determine mode, selected checks, and candidate files
    sampling_meta: Optional[Dict[str, Any]] = None
    candidates: List[str] = []

    if len(raw_targets) == 1 and raw_targets[0] == "known-c":
        mode_label = "known-c"
        selected_checks = explicit_only if explicit_only is not None else ["known-c"]
    elif len(raw_targets) == 1 and raw_targets[0] == "perf":
        mode_label = "perf"
        selected_checks = explicit_only if explicit_only is not None else ["perf"]
    elif len(raw_targets) == 1 and raw_targets[0] in ("standard", "all"):
        mode_label = "standard"
        selected_checks = explicit_only if explicit_only is not None else list(AVAILABLE_CHECKS)
        if any(c in selected_checks for c in CORPUS_CHECKS):
            candidates = list(STANDARD_FILES)
    elif len(raw_targets) == 1 and raw_targets[0] == "quick":
        mode_label = "quick"
        selected_checks = explicit_only if explicit_only is not None else list(CORPUS_CHECKS)
        if any(c in selected_checks for c in CORPUS_CHECKS):
            candidates = list(QUICK_FILES)
    elif len(raw_targets) == 1 and raw_targets[0] == "full":
        mode_label = "full"
        selected_checks = explicit_only if explicit_only is not None else list(CORPUS_CHECKS)
        if any(c in selected_checks for c in CORPUS_CHECKS):
            candidates, sampling_meta = select_full_corpus_targets(
                seed=args.seed, sample_size=args.sample_size, full_all=args.full_all
            )
    else:
        mode_label = "custom"
        selected_checks = explicit_only if explicit_only is not None else list(CORPUS_CHECKS)
        if any(c in selected_checks for c in CORPUS_CHECKS):
            candidates = [os.path.abspath(p) if not os.path.isabs(p) else p for p in raw_targets]

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

    selected_corpus_checks = [c for c in selected_checks if c in CORPUS_CHECKS]
    if selected_corpus_checks and not candidates:
        print(f"[FAIL] No candidate binaries found for '{mode_label}'", file=sys.stderr)
        return 1

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    date_str = utc_now.strftime("%Y-%m-%d")
    json_out_path = args.json_out
    txt_out_path = args.txt_out
    if args.record:
        def_json, def_txt = default_record_paths(mode_label, date_str)
        if json_out_path is None:
            json_out_path = def_json
        if txt_out_path is None:
            txt_out_path = def_txt

    env_meta = collect_environment_metadata(args.machgraph)
    lines_out: List[str] = []

    def emit(line: str = "") -> None:
        clean = sanitize_text(line)
        print(clean)
        lines_out.append(clean)

    emit(f"=== MachGraph M4 CFG Acceptance ({mode_label}) ===")
    emit(f"Date (UTC):   {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    emit(
        f"System:       {env_meta['macos_product_name']} {env_meta['macos_version']} "
        f"({env_meta['macos_build']}) {env_meta['machine']}"
    )
    emit(f"Ref clang:    {env_meta['clang_version']}")
    emit(f"Ref objdump:  {env_meta['llvm_objdump_version']}")
    emit(f"Checks:       {', '.join(selected_checks)} (max_concurrent_subprocesses={MAX_CONCURRENT_SUBPROCESSES})")
    emit(
        f"MachGraph:    {env_meta['machgraph_binary']} @ {env_meta['machgraph_commit'][:12]} "
        f"(worktree_clean={env_meta['worktree_clean']})"
    )
    if sampling_meta is not None:
        emit(
            f"Full sample:  {sampling_meta['method']} -> selected={sampling_meta['selected_count']} / "
            f"arm64_pool={sampling_meta['arm64_executable_pool_count']} "
            f"(discovered_macho={sampling_meta['total_discovered_macho_files']})"
        )
    emit("")

    temp_home_ctx = tempfile.TemporaryDirectory(prefix="machgraph-m4-home-")
    isolated_home = temp_home_ctx.name
    t_start = time.perf_counter()

    skipped_no_arm64 = sampling_meta["pre_filtered_non_arm64_count"] if sampling_meta else 0
    compared_files = 0
    non_utf8_files = 0
    failures: List[Dict[str, Any]] = []
    file_records: List[Dict[str, Any]] = []
    check_summaries: Dict[str, Any] = {}

    try:
        # 1. Run corpus checks (`function-starts` and/or `invariants`)
        if selected_corpus_checks:
            for chk in selected_corpus_checks:
                check_summaries[chk] = {
                    "compared_files": 0,
                    "matched_files": 0,
                    "mismatched_files": 0,
                    "total_ref_items": 0,
                    "total_mg_items": 0,
                    "total_diffs": 0,
                    **(
                        {
                            "total_functions": 0,
                            "total_blocks": 0,
                            "total_edges": 0,
                            "total_loops": 0,
                            "total_inline_jts": 0,
                            "noreturn_exit_calls_verified": 0,
                            "violations_by_invariant": {"I1": 0, "I2": 0, "I3": 0, "I4": 0},
                        }
                        if chk == "invariants"
                        else {
                            "total_text_functions": 0,
                            "total_inline_jts": 0,
                            "total_objc_stubs": 0,
                        }
                    ),
                    "examples": [],
                }

            rows = run_with_solo_retry(
                candidates,
                args.workers,
                lambda p: evaluate_one_binary(p, selected_corpus_checks, args.machgraph, isolated_home),
            )

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
                    emit(f"[CRASH/FAIL] {disp_path}: {fail_entry['error']}")
                    continue

                compared_files += 1
                if r.get("non_utf8"):
                    non_utf8_files += 1
                arch = r["arch"]
                per_check = r["checks"]
                file_passed = True
                tokens: List[str] = []
                compact_checks: Dict[str, Any] = {}

                for chk in selected_corpus_checks:
                    cres = per_check[chk]
                    csum = check_summaries[chk]
                    csum["compared_files"] += 1
                    csum["total_ref_items"] += int(cres.get("ref_count", 0))
                    csum["total_mg_items"] += int(cres.get("mg_count", 0))
                    csum["total_diffs"] += int(cres.get("diff_count", 0))

                    if chk == "function-starts":
                        csum["total_text_functions"] += int(cres.get("text_fn_count", 0))
                        csum["total_inline_jts"] += int(cres.get("inline_jt_count", 0))
                        csum["total_objc_stubs"] += int(cres.get("objc_stub_count", 0))
                        if cres["status"] == "pass":
                            csum["matched_files"] += 1
                            tokens.append(
                                f"function-starts=OK({cres['text_fn_count']}+{cres['inline_jt_count']}={cres['ref_count']})"
                            )
                        else:
                            file_passed = False
                            csum["mismatched_files"] += 1
                            tokens.append(f"function-starts=DIFF({cres['diff_count']})")
                    elif chk == "invariants":
                        csum["total_functions"] += int(cres.get("function_count", 0))
                        csum["total_blocks"] += int(cres.get("block_count", 0))
                        csum["total_edges"] += int(cres.get("edge_count", 0))
                        csum["total_loops"] += int(cres.get("loop_count", 0))
                        csum["total_inline_jts"] += int(cres.get("inline_jt_count", 0))
                        csum["noreturn_exit_calls_verified"] += int(cres.get("noreturn_exit_calls_verified", 0))
                        for inv_k, inv_v in cres.get("violations_by_invariant", {}).items():
                            csum["violations_by_invariant"][inv_k] += int(inv_v)
                        if cres["status"] == "pass":
                            csum["matched_files"] += 1
                            tokens.append(
                                f"invariants=OK(fns={cres['function_count']},blks={cres['block_count']},edges={cres['edge_count']})"
                            )
                        else:
                            file_passed = False
                            csum["mismatched_files"] += 1
                            tokens.append(f"invariants=DIFF({cres['diff_count']})")

                    for ex in cres.get("examples", []):
                        if len(csum["examples"]) < MAX_EXAMPLES_PER_CHECK:
                            csum["examples"].append({"file": disp_path, "arch": arch, **ex})

                    compact_checks[chk] = dict(cres)

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
                emit(f"[{tag}] {disp_path} ({arch}): {' '.join(tokens)} ({r['seconds']:.2f}s)")
                if not file_passed:
                    for chk in selected_corpus_checks:
                        for ex in per_check[chk].get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                            emit(f"    [{chk} example] {json.dumps(ex, ensure_ascii=False)}")

        # 2. Run `known-c` check (Row 3)
        if "known-c" in selected_checks:
            kc_res = evaluate_known_c_suite(args.machgraph, isolated_home)
            check_summaries["known-c"] = kc_res
            if selected_corpus_checks:
                emit("")
            for c_row in kc_res.get("cases", []):
                act = c_row.get("actual", {})
                emit(
                    f"[{c_row['status']}] known-c {c_row['symbol']}: "
                    f"blocks={act.get('blocks')} edges={act.get('edges')} "
                    f"loops={act.get('loops')}(depths={act.get('loop_nesting_depths')}) "
                    f"jumpTables={act.get('jump_table_count')}(targets={act.get('jump_table_targets')})"
                )
            if kc_res.get("error"):
                emit(f"[FAIL] known-c error: {kc_res['error']}")

        # 3. Run `perf` check (Row 5)
        if "perf" in selected_checks:
            pf_res = evaluate_perf_suite(args.machgraph, isolated_home)
            check_summaries["perf"] = pf_res
            emit("")
            emit(f"Perf uptime (before): {pf_res['uptime_before']}")
            for _bid, binfo in pf_res["benchmarks"].items():
                emit(
                    f"[{binfo['status']}] perf {binfo['label']}: "
                    f"median={binfo['median_seconds']}s runs={binfo['runs_seconds']} "
                    f"(functions={binfo['function_count']}, blocks={binfo['block_count']})"
                )
            for w_msg in pf_res.get("warnings", []):
                emit(f"[WARN] {w_msg}")
            emit(f"Perf uptime (after):  {pf_res['uptime_after']}")
    finally:
        temp_home_ctx.cleanup()

    wall_seconds = round(time.perf_counter() - t_start, 2)

    # Compute overall pass/fail verdict
    all_checks_ok = True
    emit("")
    for chk in selected_checks:
        csum = check_summaries[chk]
        if chk in CORPUS_CHECKS:
            chk_ok = csum["mismatched_files"] == 0 and len(failures) == 0 and compared_files > 0
            tag = "PASS" if chk_ok else "FAIL"
            emit(
                f"[{tag}] Check '{chk}': matched={csum['matched_files']}/{csum['compared_files']} "
                f"mismatched_files={csum['mismatched_files']} total_diffs={csum['total_diffs']} "
                f"ref_items={csum['total_ref_items']} mg_items={csum['total_mg_items']}"
            )
            if chk == "function-starts":
                emit(
                    f"  totals: text_functions={csum['total_text_functions']} "
                    f"inline_jump_tables={csum['total_inline_jts']} objc_stubs={csum['total_objc_stubs']}"
                )
            elif chk == "invariants":
                emit(
                    f"  totals: functions={csum['total_functions']} blocks={csum['total_blocks']} "
                    f"edges={csum['total_edges']} loops={csum['total_loops']} "
                    f"inline_jts={csum['total_inline_jts']} noreturn_exits={csum['noreturn_exit_calls_verified']} "
                    f"violations={json.dumps(csum['violations_by_invariant'])}"
                )
            for ex in csum.get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                emit(f"  example: {json.dumps(ex, ensure_ascii=False)}")
        elif chk == "known-c":
            chk_ok = csum["status"] == "pass"
            tag = "PASS" if chk_ok else "FAIL"
            emit(
                f"[{tag}] Check 'known-c': matched={csum['matched_cases']}/{csum['total_cases']} "
                f"total_diffs={csum['diff_count']} elapsed={csum['seconds']:.2f}s"
            )
            for ex in csum.get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                emit(f"  example: {json.dumps(ex, ensure_ascii=False)}")
        elif chk == "perf":
            chk_ok = csum["status"] == "pass"
            tag = "PASS" if chk_ok else "FAIL"
            ssh_med = csum["benchmarks"].get("ssh_full", {}).get("median_seconds")
            vim_med = csum["benchmarks"].get("vim_full", {}).get("median_seconds")
            sym_med = csum["benchmarks"].get("ssh_single_symbol", {}).get("median_seconds")
            emit(
                f"[{tag}] Check 'perf': ssh_full_median={ssh_med}s vim_full_median={vim_med}s "
                f"ssh_symbol_median={sym_med}s warnings={len(csum.get('warnings', []))} "
                f"failures={csum['diff_count']} elapsed={csum['seconds']:.2f}s"
            )
            for ex in csum.get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                emit(f"  example: {json.dumps(ex, ensure_ascii=False)}")
        else:
            chk_ok = False
        if not chk_ok:
            all_checks_ok = False

    if failures:
        all_checks_ok = False

    verdict = "PASS" if all_checks_ok else "FAIL"
    mismatched_files = sum(1 for rec in file_records if rec["status"] != "PASS")
    emit(
        f"[{verdict}] Summary ({mode_label}): candidates={len(candidates)} compared={compared_files} "
        f"skipped_no_arm64={skipped_no_arm64} crashes_or_failures={len(failures)} "
        f"mismatched_files={mismatched_files} non_utf8_files={non_utf8_files} "
        f"elapsed={wall_seconds:.2f}s"
    )

    if json_out_path:
        out_dir = os.path.dirname(os.path.abspath(json_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        payload = {
            "schema": "machgraph.m4.acceptance/1",
            "date": date_str,
            "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": mode_label,
            "selected_checks": selected_checks,
            "verdict": verdict,
            "environment": env_meta,
            **({"sampling": sampling_meta} if sampling_meta is not None else {}),
            "summary": {
                "candidate_macho_files": len(candidates),
                "compared_files": compared_files,
                "skipped_no_arm64_slice": skipped_no_arm64,
                "crashes_or_failures": len(failures),
                "mismatched_files": mismatched_files,
                "non_utf8_output_files": non_utf8_files,
                "max_concurrent_subprocesses": MAX_CONCURRENT_SUBPROCESSES,
                "elapsed_seconds": wall_seconds,
            },
            "checks": check_summaries,
            "failures": failures,
            "files": file_records,
        }
        serialized = sanitize_text(json.dumps(payload, indent=2, ensure_ascii=False)) + "\n"
        with open(json_out_path, "w", encoding="utf-8") as fh:
            fh.write(serialized)

    if txt_out_path:
        out_dir = os.path.dirname(os.path.abspath(txt_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(txt_out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines_out) + "\n")

    return 0 if all_checks_ok else 1


if __name__ == "__main__":
    sys.exit(main())
