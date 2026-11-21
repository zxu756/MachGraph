#!/usr/bin/env python3
"""Differential function-boundary & BasicBlockModel check against Ghidra 12.1.4 (M4 Row 4).

Usage:
  Scripts/acceptance/m4-ghidra-differential.py [<binary_path>]
      [--machgraph <path>] [--json-out <path>] [--timeout <seconds>]

Environment variables (read dynamically, never hardcoded):
  - `GHIDRA_INSTALL_DIR` : Path to Ghidra 12.x installation containing `support/analyzeHeadless`
                           (e.g. `export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC`).
  - `JAVA_HOME`          : Path to JDK 21+ home containing `bin/java`
                           (e.g. `export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`).

When either `GHIDRA_INSTALL_DIR` or `JAVA_HOME` is unset or missing on disk, prints
`[SKIPPED] 已跳过、不算通过 ...` and exits with code `77` (`EXIT_SKIPPED`, non-zero so a
skipped run is never mistaken for a passing verification).

Runs `support/analyzeHeadless` inside an ephemeral `mktemp -d` project directory with an
isolated `HOME` inside the same temporary directory (never touching `~`, `~/Library`, or
`~/.ghidra`), exports every real function's start/end addresses and `BasicBlockModel`
blocks for the `arm64e`/`arm64` slice, deletes the temporary project on exit, and
compares against `machgraph cfg <binary> --json`.

Every difference is structurally classified from raw ARM64 machine words and
`LC_FUNCTION_STARTS`:
  1. `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT` (+ paired `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION`):
     Ghidra's prologue pattern analyzer falsely splits a single PAC function right after
     `pacibsp`/`paciasp`/`bti` (`addr - 4` is in `LC_FUNCTION_STARTS`, `addr` is NOT in
     `LC_FUNCTION_STARTS`, and MachGraph keeps `[addr - 4, end)` intact).
  2. `TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION`:
     Ghidra's switch analyzer splits a recovered switch `br xN` instruction into a
     1-instruction trailing `CodeBlock` `[s, s + 4)` even though zero direct branches or
     jump-table entries target `s` and `s - 4` is sequential (MachGraph keeps the block
     unsplit per the standard textbook basic-block leader definition).
  3. Any other start-address, end-address, or basic-block discrepancy is classified as a
     `MACHGRAPH_ERROR_*` and fails the check (`machgraph_error_count == 0` required).

Exit status:
  0  when `machgraph_error_count == 0` and comparison completes cleanly;
  1  when `machgraph_error_count > 0` or a tool crashes / times out;
  2  on invalid CLI arguments;
  77 when `GHIDRA_INSTALL_DIR` or `JAVA_HOME` is unavailable (`已跳过、不算通过`).
"""

import argparse
from collections import Counter
import datetime
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_SKIPPED = 77

DEFAULT_TARGET = "/bin/ls"
DEFAULT_GHIDRA_TIMEOUT_SECONDS = 300.0

PAC_OR_BTI_PROLOGUE_WORDS = frozenset(
    {
        0xD503233F,  # paciasp
        0xD503237F,  # pacibsp
        0xD503245F,  # bti c
        0xD503249F,  # bti j
        0xD50324DF,  # bti jc
    }
)

GHIDRA_EXPORT_JAVA_NAME = "ExportArm64CFGInventory.java"
GHIDRA_EXPORT_JAVA_SOURCE = r"""import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportArm64CFGInventory extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            return;
        }
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Missing output directory argument");
        }
        String outDir = args[0];
        String lang = currentProgram.getLanguageID().getIdAsString();
        String comp = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        String domPath = (currentProgram.getDomainFile() != null)
            ? currentProgram.getDomainFile().getPathname()
            : currentProgram.getName();
        String safeLang = lang.replaceAll("[^A-Za-z0-9_.-]", "_");
        String safeDom = domPath.replaceAll("[^A-Za-z0-9_.-]", "_");
        File outFile = new File(outDir, "ghidra-cfg-" + safeLang + "-" + safeDom + ".json");

        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
            out.println("{");
            out.println("  \"programName\": \"" + esc(currentProgram.getName()) + "\",");
            out.println("  \"domainPath\": \"" + esc(domPath) + "\",");
            out.println("  \"languageID\": \"" + esc(lang) + "\",");
            out.println("  \"compilerSpecID\": \"" + esc(comp) + "\",");
            out.println("  \"imageBase\": \"0x" + currentProgram.getImageBase().toString() + "\",");
            out.println("  \"functions\": [");

            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            boolean firstFn = true;
            while (fit.hasNext() && !monitor.isCancelled()) {
                Function fn = fit.next();
                Address entry = fn.getEntryPoint();
                AddressSetView body = fn.getBody();
                Address minAddr = body.getMinAddress();
                Address maxAddr = body.getMaxAddress();
                MemoryBlock mb = currentProgram.getMemory().getBlock(entry);
                String mbName = (mb != null) ? mb.getName() : "";

                if (!firstFn) out.println(",");
                firstFn = false;

                out.println("    {");
                out.println("      \"name\": \"" + esc(fn.getName()) + "\",");
                out.println("      \"entry\": \"0x" + entry.toString() + "\",");
                out.println("      \"minAddr\": \"0x" + (minAddr != null ? minAddr.toString() : entry.toString()) + "\",");
                out.println("      \"maxAddr\": \"0x" + (maxAddr != null ? maxAddr.toString() : entry.toString()) + "\",");
                out.println("      \"numRanges\": " + body.getNumAddressRanges() + ",");
                out.println("      \"byteCount\": " + body.getNumAddresses() + ",");
                out.println("      \"isThunk\": " + fn.isThunk() + ",");
                out.println("      \"isExternal\": " + fn.isExternal() + ",");
                out.println("      \"hasNoReturn\": " + fn.hasNoReturn() + ",");
                out.println("      \"memoryBlock\": \"" + esc(mbName) + "\",");

                out.print("      \"ranges\": [");
                boolean firstR = true;
                for (AddressRange r : body) {
                    if (!firstR) out.print(", ");
                    firstR = false;
                    out.print("[\"0x" + r.getMinAddress().toString() + "\", \"0x" + r.getMaxAddress().toString() + "\"]");
                }
                out.println("],");

                CodeBlockIterator cbit = bbm.getCodeBlocksContaining(body, monitor);
                StringBuilder bb = new StringBuilder();
                int bbCount = 0;
                while (cbit.hasNext() && !monitor.isCancelled()) {
                    CodeBlock cb = cbit.next();
                    if (bbCount > 0) bb.append(", ");
                    bb.append("{\"start\": \"0x").append(cb.getMinAddress().toString())
                      .append("\", \"endMax\": \"0x").append(cb.getMaxAddress().toString()).append("\"}");
                    bbCount++;
                }
                out.println("      \"blockCount\": " + bbCount + ",");
                out.println("      \"blocks\": [" + bb.toString() + "]");
                out.print("    }");
            }
            out.println();
            out.println("  ]");
            out.println("}");
        }
    }
}
"""


def _load_m4_core():
    path = os.path.join(SCRIPT_DIR, "m4-cfg-acceptance.py")
    spec = importlib.util.spec_from_file_location("_m4_cfg_acceptance_core", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_core = _load_m4_core()


def _parse_hex(val: Any) -> int:
    if isinstance(val, int):
        return val
    s = str(val).strip()
    return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 16)


def resolve_ghidra_environment(environ: Optional[Dict[str, str]] = None) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
    """Read `GHIDRA_INSTALL_DIR` and `JAVA_HOME` from environment; return `((headless_bin, java_home), None)`
    or `(None, skip_reason)`."""
    env = environ if environ is not None else os.environ
    ghidra_dir = env.get("GHIDRA_INSTALL_DIR", "").strip()
    java_home = env.get("JAVA_HOME", "").strip()

    if not ghidra_dir or not java_home:
        missing = []
        if not ghidra_dir:
            missing.append("GHIDRA_INSTALL_DIR")
        if not java_home:
            missing.append("JAVA_HOME")
        return (
            None,
            f"已跳过、不算通过 (SKIPPED — does not count as PASS): 环境变量 {', '.join(missing)} 未设置 "
            f"(hint: export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC "
            f"JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home)",
        )

    headless_path = os.path.join(ghidra_dir, "support", "analyzeHeadless")
    java_bin = os.path.join(java_home, "bin", "java")
    if not (os.path.isfile(headless_path) and os.access(headless_path, os.X_OK)):
        return (
            None,
            "已跳过、不算通过 (SKIPPED — does not count as PASS): "
            "GHIDRA_INSTALL_DIR/support/analyzeHeadless 不存在或不可执行",
        )
    if not (os.path.isfile(java_bin) and os.access(java_bin, os.X_OK)):
        return (
            None,
            "已跳过、不算通过 (SKIPPED — does not count as PASS): JAVA_HOME/bin/java 不存在或不可执行",
        )
    return ((headless_path, java_home), None)


def _is_frame_prologue_word(word: int) -> bool:
    # `stp xN, xM, [sp, #...]` (`0xA9000000`..`0xA9FFFFFF`) or `sub sp, sp, #imm` (`(w & 0xFF8003FF) == 0xD10003FF`)
    if (word & 0xFE000000) == 0xA8000000 and ((word >> 5) & 0x1F) == 31:
        return True
    if (word & 0xFF8003FF) == 0xD10003FF:
        return True
    return False


def compare_and_classify_ghidra_vs_machgraph(
    slice_view: Any,
    mg_cfg_json: Dict[str, Any],
    gh_export_json: Dict[str, Any],
    imported_symbols_by_addr: Optional[Dict[int, str]] = None,
) -> Dict[str, Any]:
    """Compare Ghidra's exported function starts/ends/`BasicBlockModel` blocks against
    `machgraph cfg --json` and structurally classify every difference."""
    lc_starts_set: Set[int] = set(slice_view.lc_function_starts)
    inline_jt_starts: Set[int] = {int(x) for x in mg_cfg_json.get("inlineJumpTableStarts", [])}
    verified_noreturn = _core.solve_independent_noreturn_functions(
        slice_view,
        mg_cfg_json.get("functions", []),
        imported_symbols_by_addr or {},
    )

    mg_all: Dict[int, Dict[str, Any]] = {int(fn["address"]): fn for fn in mg_cfg_json.get("functions", [])}
    gh_real: Dict[int, Dict[str, Any]] = {}
    gh_external_count = 0

    for gfn in gh_export_json.get("functions", []):
        if gfn.get("isExternal") or gfn.get("memoryBlock") == "EXTERNAL":
            gh_external_count += 1
            continue
        gh_real[_parse_hex(gfn["entry"])] = gfn

    common_addrs = sorted(set(mg_all.keys()) & set(gh_real.keys()))
    only_mg_addrs = sorted(set(mg_all.keys()) - set(gh_real.keys()))
    only_gh_addrs = sorted(set(gh_real.keys()) - set(mg_all.keys()))

    differences: List[Dict[str, Any]] = []
    pac_split_extra_addrs: Set[int] = set()

    # 1. Start-address differences: only in MachGraph
    for addr in only_mg_addrs:
        mfn = mg_all[addr]
        w0 = slice_view.read_u32(addr)
        if addr in inline_jt_starts or (w0 is not None and (w0 & 0xFFFF0000) == 0):
            differences.append(
                {
                    "dimension": "function_start",
                    "address": hex(addr),
                    "category": "MACHGRAPH_ERROR_INLINE_JUMP_TABLE_AS_FUNCTION",
                    "attribution": "machgraph_error",
                    "reason": (
                        f"MachGraph reported {hex(addr)} ({mfn.get('name')}) as a code function, "
                        f"but it is inline jump-table / non-code data."
                    ),
                }
            )
        else:
            differences.append(
                {
                    "dimension": "function_start",
                    "address": hex(addr),
                    "category": "MACHGRAPH_ERROR_UNEXPLAINED_EXTRA_FUNCTION_START",
                    "attribution": "machgraph_error",
                    "reason": (
                        f"MachGraph reported function {mfn.get('name')} at {hex(addr)} not present in Ghidra "
                        f"(in_lc_function_starts={addr in lc_starts_set})."
                    ),
                }
            )

    # 2. Start-address differences: only in Ghidra
    for addr in only_gh_addrs:
        gfn = gh_real[addr]
        gh_end_excl = _parse_hex(gfn["maxAddr"]) + 1
        prev_addr = addr - 4
        prev_word = slice_view.read_u32(prev_addr)
        curr_word = slice_view.read_u32(addr)
        prev_mg = mg_all.get(prev_addr)

        if (
            addr not in lc_starts_set
            and prev_addr in lc_starts_set
            and prev_mg is not None
            and int(prev_mg["endAddress"]) == gh_end_excl
            and prev_word in PAC_OR_BTI_PROLOGUE_WORDS
            and curr_word is not None
            and _is_frame_prologue_word(curr_word)
        ):
            pac_split_extra_addrs.add(addr)
            differences.append(
                {
                    "dimension": "function_start",
                    "address": hex(addr),
                    "category": "TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT",
                    "attribution": "ghidra_heuristic_quirk",
                    "reason": (
                        f"LC_FUNCTION_STARTS contains {hex(prev_addr)} (word 0x{prev_word:08x} PAC/BTI prologue) "
                        f"and NOT {hex(addr)} (word 0x{curr_word:08x} frame setup); Ghidra's prologue analyzer "
                        f"falsely split after PAC into a second function {gfn.get('name')} at {hex(addr)}..{hex(gh_end_excl)}, "
                        f"whereas MachGraph accurately kept {prev_mg.get('name')} as {hex(prev_addr)}..{hex(gh_end_excl)}."
                    ),
                }
            )
        else:
            differences.append(
                {
                    "dimension": "function_start",
                    "address": hex(addr),
                    "category": "MACHGRAPH_ERROR_MISSING_FUNCTION_START",
                    "attribution": "machgraph_error",
                    "reason": (
                        f"Ghidra recovered function {gfn.get('name')} at {hex(addr)}..{hex(gh_end_excl)} "
                        f"(in_lc_function_starts={addr in lc_starts_set}) missing from MachGraph."
                    ),
                }
            )

    # 3. End-address & BasicBlockModel count + block-leader set comparison across common function starts
    end_equal_count = 0
    bb_equal_count = 0
    bb_starts_equal_count = 0
    exact_all_three_equal = 0

    for addr in common_addrs:
        mfn = mg_all[addr]
        gfn = gh_real[addr]
        mg_end = int(mfn["endAddress"])
        gh_end_excl = _parse_hex(gfn["maxAddr"]) + 1
        gh_num_ranges = int(gfn.get("numRanges", 1))

        end_same = mg_end == gh_end_excl and gh_num_ranges == 1
        if end_same:
            end_equal_count += 1
        else:
            if gh_end_excl == addr + 4 and (addr + 4) in pac_split_extra_addrs:
                split_end = _parse_hex(gh_real[addr + 4]["maxAddr"]) + 1
                if mg_end == split_end:
                    differences.append(
                        {
                            "dimension": "function_end",
                            "address": hex(addr),
                            "category": "TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION",
                            "attribution": "ghidra_heuristic_quirk",
                            "reason": (
                                f"Paired consequence of Ghidra's false PAC split at {hex(addr + 4)}: "
                                f"Ghidra truncated {gfn.get('name')} to 4 bytes ({hex(addr)}..{hex(gh_end_excl)}), "
                                f"whereas MachGraph preserved the full function {hex(addr)}..{hex(mg_end)}."
                            ),
                        }
                    )
                else:
                    differences.append(
                        {
                            "dimension": "function_end",
                            "address": hex(addr),
                            "category": "MACHGRAPH_ERROR_END_ADDRESS_MISMATCH",
                            "attribution": "machgraph_error",
                            "reason": f"End address mismatch at {hex(addr)}: MachGraph={hex(mg_end)} vs Ghidra={hex(gh_end_excl)}.",
                        }
                    )
            else:
                differences.append(
                    {
                        "dimension": "function_end",
                        "address": hex(addr),
                        "category": "MACHGRAPH_ERROR_END_ADDRESS_MISMATCH",
                        "attribution": "machgraph_error",
                        "reason": (
                            f"End address / range mismatch on {mfn.get('name')} ({hex(addr)}): "
                            f"MachGraph={hex(mg_end)} vs Ghidra={hex(gh_end_excl)} (numRanges={gh_num_ranges})."
                        ),
                    }
                )

        mg_blocks = mfn.get("blocks", [])
        mg_bb_count = len(mg_blocks)
        gh_bb_count = int(gfn.get("blockCount", 0))
        if mg_bb_count == gh_bb_count:
            bb_equal_count += 1

        mg_starts = {int(b["startAddress"]) for b in mg_blocks}
        gh_blocks_by_start = {_parse_hex(b["start"]): _parse_hex(b["endMax"]) + 1 for b in gfn.get("blocks", [])}
        gh_starts = set(gh_blocks_by_start.keys())
        if mg_bb_count == gh_bb_count and mg_starts == gh_starts:
            bb_starts_equal_count += 1
            if end_same:
                exact_all_three_equal += 1
            continue

        mg_only_starts = sorted(mg_starts - gh_starts)
        gh_only_starts = sorted(gh_starts - mg_starts)

        # Collect all genuine intra-function branch targets and switch-table targets from raw slice bytes
        all_branch_targets: Set[int] = set()
        jt_dispatch_addrs: Set[int] = set()
        for jt in mfn.get("jumpTables", []):
            jt_dispatch_addrs.add(int(jt["dispatchInstructionAddress"]))
            for t in jt.get("targetAddresses", []):
                all_branch_targets.add(int(t))
        for pc in range(addr, mg_end, 4):
            w = slice_view.read_u32(pc)
            if w is None:
                continue
            dec = _core.decode_arm64_insn(w, pc)
            if dec["kind"] in ("b", "cond_branch"):
                all_branch_targets.add(dec["target"])

        # Verify whether every `gh_only` start is Ghidra's 1-insn switch `br xN` isolation
        unexplained_gh_only: List[int] = []
        explained_gh_switch: List[int] = []
        for s in gh_only_starts:
            w_s = slice_view.read_u32(s)
            w_prev = slice_view.read_u32(s - 4)
            if (
                end_same
                and s in jt_dispatch_addrs
                and gh_blocks_by_start.get(s) == s + 4
                and s not in all_branch_targets
                and w_s is not None
                and _core.decode_arm64_insn(w_s, s)["kind"] == "indirect_jump"
                and w_prev is not None
                and not _core.decode_arm64_insn(w_prev, s - 4)["is_terminator"]
                and _core.decode_arm64_insn(w_prev, s - 4)["kind"] != "bl"
            ):
                explained_gh_switch.append(s)
            else:
                unexplained_gh_only.append(s)

        # Verify whether every `mg_only` start immediately follows a `bl <callee>` proven `noreturn`
        # where Ghidra did not mark `<callee>` as `hasNoReturn`
        unexplained_mg_only: List[int] = []
        explained_mg_noreturn: List[Tuple[int, int]] = []
        for s in mg_only_starts:
            w_prev = slice_view.read_u32(s - 4)
            dec_prev = _core.decode_arm64_insn(w_prev, s - 4) if w_prev is not None else None
            callee = dec_prev["target"] if (dec_prev and dec_prev["kind"] == "bl") else None
            gh_callee = gh_real.get(callee) if callee is not None else None
            if (
                end_same
                and callee is not None
                and callee in verified_noreturn
                and (gh_callee is None or not gh_callee.get("hasNoReturn", False))
            ):
                explained_mg_noreturn.append((s, callee))
            else:
                unexplained_mg_only.append(s)

        if not unexplained_gh_only and not unexplained_mg_only and (explained_gh_switch or explained_mg_noreturn):
            if explained_gh_switch:
                differences.append(
                    {
                        "dimension": "basic_blocks",
                        "address": hex(addr),
                        "function": mfn.get("name"),
                        "machgraph_blocks": mg_bb_count,
                        "ghidra_blocks": gh_bb_count,
                        "ghidra_extra_starts": [hex(s) for s in explained_gh_switch],
                        "category": "TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION",
                        "attribution": "ghidra_switch_block_attachment",
                        "reason": (
                            f"On {mfn.get('name')} ({hex(addr)}), Ghidra isolated switch dispatch "
                            f"`br xN` at {[hex(s) for s in explained_gh_switch]} into a 1-instruction CodeBlock "
                            f"with zero incoming branch/jump-table edges; MachGraph keeps the block unsplit per "
                            f"the standard basic-block leader definition."
                        ),
                    }
                )
            if explained_mg_noreturn:
                differences.append(
                    {
                        "dimension": "basic_blocks",
                        "address": hex(addr),
                        "function": mfn.get("name"),
                        "machgraph_blocks": mg_bb_count,
                        "ghidra_blocks": gh_bb_count,
                        "machgraph_noreturn_splits": [
                            {"blockStart": hex(s), "noreturnCallee": hex(c)} for s, c in explained_mg_noreturn
                        ],
                        "category": "TOOL_DIFF_MACHGRAPH_NORETURN_WRAPPER_SPLIT",
                        "attribution": "ghidra_missing_internal_noreturn",
                        "reason": (
                            f"On {mfn.get('name')} ({hex(addr)}), MachGraph split after proven non-returning "
                            f"call(s) {[f'{hex(s - 4)}->callee {hex(c)}' for s, c in explained_mg_noreturn]}, "
                            f"whereas Ghidra did not propagate `noreturn` to that internal wrapper."
                        ),
                    }
                )
        else:
            differences.append(
                {
                    "dimension": "basic_blocks",
                    "address": hex(addr),
                    "function": mfn.get("name"),
                    "machgraph_blocks": mg_bb_count,
                    "ghidra_blocks": gh_bb_count,
                    "machgraph_only_starts": [hex(s) for s in unexplained_mg_only[:8]],
                    "ghidra_only_starts": [hex(s) for s in unexplained_gh_only[:8]],
                    "category": "MACHGRAPH_ERROR_BLOCK_PARTITION_MISMATCH",
                    "attribution": "machgraph_error",
                    "reason": (
                        f"Unexplained basic-block count/leader mismatch on {mfn.get('name')} ({hex(addr)}): "
                        f"MachGraph={mg_bb_count} vs Ghidra={gh_bb_count} "
                        f"(mg_only={[hex(s) for s in unexplained_mg_only[:5]]}, "
                        f"gh_only={[hex(s) for s in unexplained_gh_only[:5]]})."
                    ),
                }
            )

    cat_counts = Counter(d["category"] for d in differences)
    mg_errors = [d for d in differences if d["attribution"] == "machgraph_error"]

    return {
        "verdict": "PASS" if len(mg_errors) == 0 else "FAIL",
        "machgraph_error_count": len(mg_errors),
        "explained_tool_diff_count": len(differences) - len(mg_errors),
        "total_difference_records": len(differences),
        "counts": {
            "machgraph_functions": len(mg_all),
            "ghidra_real_functions": len(gh_real),
            "ghidra_external_pseudo_functions": gh_external_count,
            "common_function_starts": len(common_addrs),
            "only_machgraph_starts": len(only_mg_addrs),
            "only_ghidra_starts": len(only_gh_addrs),
            "common_end_address_equal": end_equal_count,
            "common_block_count_equal": bb_equal_count,
            "common_block_starts_equal": bb_starts_equal_count,
            "common_exact_start_end_and_blocks_equal": exact_all_three_equal,
        },
        "differences_by_category": dict(sorted(cat_counts.items())),
        "differences": differences,
    }


def export_ghidra_arm64_inventory(
    target_path: str,
    headless_bin: str,
    java_home: str,
    timeout_sec: float = DEFAULT_GHIDRA_TIMEOUT_SECONDS,
) -> Tuple[Optional[Dict[str, Any]], Optional[str], float]:
    """Run Ghidra `support/analyzeHeadless` inside an ephemeral `mktemp -d` project + isolated `HOME`
    and return `(parsed_export_json, error_message, elapsed_seconds)`."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="machgraph-m4-ghidra-") as tmp_root:
        iso_home = os.path.join(tmp_root, "home")
        proj_dir = os.path.join(tmp_root, "proj")
        script_dir = os.path.join(tmp_root, "scripts")
        out_dir = os.path.join(tmp_root, "out")
        for d in (iso_home, proj_dir, script_dir, out_dir):
            os.makedirs(d, exist_ok=True)

        java_script_path = os.path.join(script_dir, GHIDRA_EXPORT_JAVA_NAME)
        with open(java_script_path, "w", encoding="utf-8") as fh:
            fh.write(GHIDRA_EXPORT_JAVA_SOURCE)

        env = dict(os.environ)
        env["HOME"] = iso_home
        env["JAVA_HOME"] = java_home
        env["PATH"] = os.path.join(java_home, "bin") + os.pathsep + env.get("PATH", "")
        env["JAVA_TOOL_OPTIONS"] = f"-Duser.home={iso_home}"

        cmd = [
            headless_bin,
            proj_dir,
            "MachGraphM4Diff",
            "-import",
            target_path,
            "-recursive",
            "-scriptPath",
            script_dir,
            "-postScript",
            GHIDRA_EXPORT_JAVA_NAME,
            out_dir,
            "-deleteProject",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                timeout=timeout_sec,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return (None, f"Ghidra analyzeHeadless timed out after {timeout_sec:.0f}s", round(time.perf_counter() - t0, 2))

        elapsed = round(time.perf_counter() - t0, 2)
        if proc.returncode != 0:
            stderr_txt, _ = _core.decode_utf8_safe(proc.stderr)
            return (
                None,
                f"Ghidra analyzeHeadless exited {proc.returncode}: {_core.sanitize_text(stderr_txt.strip()[:280])}",
                elapsed,
            )

        exported = sorted(
            f for f in os.listdir(out_dir) if f.startswith("ghidra-cfg-AARCH64") and f.endswith(".json")
        )
        if not exported:
            return (None, "Ghidra analyzeHeadless did not produce an AARCH64 export JSON", elapsed)

        # Prefer standard AppleSilicon arm64e slice (`cpu0x80000002`) over secondary `arm64e.x1` if present
        chosen_file = exported[0]
        for cand in exported:
            if "cpu0x80000002" in cand:
                chosen_file = cand
                break
        else:
            for cand in exported:
                if "AppleSilicon" in cand:
                    chosen_file = cand
                    break
        with open(os.path.join(out_dir, chosen_file), "r", encoding="utf-8") as fh:
            gh_json = json.load(fh)
        return (gh_json, None, elapsed)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET, help="target Mach-O binary (default: /bin/ls)")
    parser.add_argument("--machgraph", default=_core.default_machgraph_bin(), help="path to MachGraph CLI executable")
    parser.add_argument("--json-out", default=None, help="optional path to write structured JSON report")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_GHIDRA_TIMEOUT_SECONDS,
        help=f"timeout in seconds for Ghidra analyzeHeadless (default: {DEFAULT_GHIDRA_TIMEOUT_SECONDS:.0f})",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    resolved_env, skip_reason = resolve_ghidra_environment()
    if resolved_env is None:
        print(f"[SKIPPED] {skip_reason}")
        return EXIT_SKIPPED

    headless_bin, java_home = resolved_env
    target_path = os.path.abspath(args.target) if not os.path.isabs(args.target) else args.target
    if not os.path.isfile(target_path):
        print(f"[FAIL] Target binary not found: {_core.sanitize_display_path(target_path)}", file=sys.stderr)
        return EXIT_FAIL

    if not os.path.isfile(args.machgraph) or not os.access(args.machgraph, os.X_OK):
        print(
            f"[FAIL] MachGraph executable not found or not executable: {_core.sanitize_display_path(args.machgraph)}",
            file=sys.stderr,
        )
        return EXIT_FAIL

    with open(target_path, "rb") as fh:
        raw_bytes = fh.read()
    arch = _core.select_arm64_slice(target_path)
    if arch is None:
        print(f"[FAIL] No arm64/arm64e slice in {_core.sanitize_display_path(target_path)}", file=sys.stderr)
        return EXIT_FAIL
    slice_view = _core.parse_macho_arm64_slice(raw_bytes, preferred_arch=arch)
    if slice_view is None:
        print(f"[FAIL] Failed to parse 64-bit ARM64 slice in {_core.sanitize_display_path(target_path)}", file=sys.stderr)
        return EXIT_FAIL

    with tempfile.TemporaryDirectory(prefix="machgraph-m4-gh-mg-home-") as mg_home:
        mg_proc = subprocess.run(
            [args.machgraph, "cfg", target_path, "--json"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=90.0,
            env=dict(os.environ, HOME=mg_home),
        )
    if mg_proc.returncode != 0:
        err_txt, _ = _core.decode_utf8_safe(mg_proc.stderr)
        print(f"[FAIL] machgraph cfg exited {mg_proc.returncode}: {_core.sanitize_text(err_txt.strip()[:240])}", file=sys.stderr)
        return EXIT_FAIL
    mg_cfg_json = json.loads(mg_proc.stdout.decode("utf-8", errors="replace"))

    imp_map, imp_err, _ = _core.resolve_import_symbols_for_binary(
        target_path, arch, slice_view, mg_cfg_json.get("functions", [])
    )
    if imp_err is not None:
        print(f"[FAIL] {imp_err}", file=sys.stderr)
        return EXIT_FAIL

    gh_json, gh_err, gh_elapsed = export_ghidra_arm64_inventory(
        target_path, headless_bin=headless_bin, java_home=java_home, timeout_sec=args.timeout
    )
    if gh_err is not None or gh_json is None:
        print(f"[FAIL] {gh_err}", file=sys.stderr)
        return EXIT_FAIL

    report = compare_and_classify_ghidra_vs_machgraph(slice_view, mg_cfg_json, gh_json, imp_map)
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    disp_target = _core.sanitize_display_path(target_path)
    counts = report["counts"]

    print(f"=== MachGraph M4 Ghidra Differential ({disp_target}, {arch}) ===")
    print(f"Date (UTC):       {utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"Ghidra language:  {gh_json.get('languageID')} ({gh_json.get('compilerSpecID')}) elapsed={gh_elapsed:.2f}s")
    print(f"MachGraph binary: {_core.sanitize_display_path(args.machgraph)}")
    print(
        f"Function starts:  MachGraph={counts['machgraph_functions']} Ghidra={counts['ghidra_real_functions']} "
        f"common={counts['common_function_starts']} only_mg={counts['only_machgraph_starts']} "
        f"only_gh={counts['only_ghidra_starts']}"
    )
    print(
        f"Common functions: end_equal={counts['common_end_address_equal']}/{counts['common_function_starts']} "
        f"block_count_equal={counts['common_block_count_equal']}/{counts['common_function_starts']} "
        f"block_starts_equal={counts['common_block_starts_equal']}/{counts['common_function_starts']} "
        f"exact_match={counts['common_exact_start_end_and_blocks_equal']}/{counts['common_function_starts']}"
    )
    print(
        f"Differences:      total={report['total_difference_records']} "
        f"explained_ghidra_diffs={report['explained_tool_diff_count']} "
        f"machgraph_errors={report['machgraph_error_count']} "
        f"categories={json.dumps(report['differences_by_category'])}"
    )
    for d in report["differences"]:
        print(f"  [{d['category']}] {d['dimension']} @ {d['address']}: {d['reason']}")
    print(
        f"[{report['verdict']}] Summary ({disp_target}): "
        f"machgraph_errors={report['machgraph_error_count']} "
        f"explained_tool_diffs={report['explained_tool_diff_count']} "
        f"ghidra_elapsed={gh_elapsed:.2f}s"
    )

    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        full_payload = {
            "schema": "machgraph.m4.ghidra_differential/1",
            "date": utc_now.strftime("%Y-%m-%d"),
            "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": disp_target,
            "arch": arch,
            "ghidra_language": gh_json.get("languageID"),
            "ghidra_compiler_spec": gh_json.get("compilerSpecID"),
            "ghidra_elapsed_seconds": gh_elapsed,
            **report,
        }
        clean_json = _core.sanitize_text(json.dumps(full_payload, indent=2, ensure_ascii=False)) + "\n"
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(clean_json)

    return EXIT_PASS if report["machgraph_error_count"] == 0 else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
