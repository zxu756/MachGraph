# MachGraph

**English** | **[简体中文](README.zh-CN.md)**

ARM64/ARM64e disassembler, control-flow graph (CFG) analyzer, inline mini-assembler, symbol demangler, and Universal/Mach-O 64 binary & metadata parser for macOS (`arm64`), written in Swift with a headless bilingual CLI (`--lang en|zh`) and a stdio JSON-RPC 2.0 MCP server.

> **Reproducible Baselines (`macOS 27.0.1 (26A434) arm64`):**
> Mach-O container parsing, dyld chained fixups, Objective-C metadata, embedded code-signature hashing & entitlements parsing, ARM64 instruction decoding, control-flow graph & dominator/loop recovery, and cross-reference recovery run directly in Swift without invoking `otool`, `llvm-objdump`, `nm`, or `codesign`. Symbol demangling (`demangle` and symbol-table loading) calls `libswiftCore`'s `swift_demangle` and `libc++abi`'s `__cxa_demangle` in-process (spawning `0` child processes, keeping the handwritten Swift/Itanium C++ parsers as a fallback).
> - **`/bin/ls` (`arm64e` slice, `M0`–`M2`, logged in [`reports/m0-quick.txt`](reports/m0-quick.txt)):** `5` segments and `11` sections match `otool -arch arm64e -l /bin/ls` item-for-item (`vmaddr`, `vmsize`, `fileoff`, `filesize`, `addr`, `size`, `offset`); across all `3,846` instructions in `__TEXT,__text` (`2026-11-20`, `Apple LLVM 21.0.0`), comparison against `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=arm64e --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text /bin/ls` with **`0` mnemonic normalization rules** ([`Scripts/acceptance/mnemonic_normalization.py`](Scripts/acceptance/mnemonic_normalization.py)) achieves **`3,846 / 3,846` (`100.00%`) mnemonic agreement**, **`0` wrong mnemonics**, **`0` unrecognized words (`.inst`)**, and **`3,846 / 3,846` (`100.00%`) operand agreement** under the `4` reference-side rules `O1`–`O4` in [`Scripts/acceptance/operand_normalization.py`](Scripts/acceptance/operand_normalization.py).
> - **`/usr/bin/ssh` (`arm64e` slice):** **`115,546` instructions** decoded strictly from instruction-attributed sections (`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`), with **`0` lines** decoded from non-instruction data sections such as `__TEXT,__info_plist`.
> - **Full-Corpus Disassembly (`M2`, `2026-11-20`, `Apple LLVM 21.0.0`, [`reports/differential-full-2026-11-20.json`](reports/differential-full-2026-11-20.json)):** Across `1,278` system Mach-O binaries (`/bin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `65,969,684` instructions, `0` mnemonic normalization rules, `4` operand rules `O1`–`O4`), records **`65,969,542 / 65,969,684` (`99.9998%` overall; `100.0000%` of `65,969,542` recognized) mnemonic agreement**, **`0` wrong mnemonics**, **`0` unrecognized words** (`142` words across `8` files where `llvm-objdump` also emits `.long`), and **`65,969,542 / 65,969,542` (`100.0000%`) operand agreement** (`0` mismatches).
> - **Full-Corpus Metadata & Demangling (`M3`, `2026-11-21`, `Apple LLVM 21.0.0` & `cctools-1040`, [`reports/m3-metadata-full-2026-11-21.json`](reports/m3-metadata-full-2026-11-21.json), [`reports/m3-metadata-full-2026-11-21.txt`](reports/m3-metadata-full-2026-11-21.txt)):** Running `python3 -I Scripts/acceptance/m3-metadata-differential.py full --machgraph .build/release/MachGraph` across the same **`1,278` files** (`1,281` candidates, `3` without `arm64`/`arm64e` skipped, `0` crashes) records **`0` differences across all six checks**: **`114,513 / 114,513` defined symbols** (`nm --no-dyldinfo`), **`11,516 / 11,516` imported dylibs & install IDs** (`otool -L`), **`8,152 / 8,152` top-level entitlement keys across `513` entitled files + `765` empty `{}`** (`codesign -a <slice> -d --entitlements :-`), **`117,076 / 117,076` unique symbols across four demangle buckets** (`28,982` Swift vs `swift-demangle -compact`, `12,611` C++ `__Z`/`___Z`/`____Z` vs `c++filt` per-argument, `105` plain-C `_Z` verbatim, `75,378` other symbols verbatim; `0` wrong/partial outputs), **`7,498,057 / 7,498,057` `CALL` (`bl`) xrefs** (`llvm-objdump` across all `S_ATTR_PURE_INSTRUCTIONS` sections, with `0` non-string-section `STRING_REF` across `18,497,352` xrefs), and **`155,495 / 155,495` Objective-C metadata items** (`otool -ov` + `otool -l`).
> - **Control-Flow Graph Verification (`M4`, `2026-11-21`, commit `50f1fcf`, `Apple clang 21.0.0` & `Apple LLVM 21.0.0`, [`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt), [`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt), [`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt), [`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)):** **`0` violations** of invariants `I1`–`I4`, dominator trees, natural loops, and `LC_FUNCTION_STARTS` accounting across `standard` (`ls` `50`, `ssh` `1,097`, `vim` `6,623` `LC_FUNCTION_STARTS`; `8,408` functions, `150,147` blocks, `220,315` edges) and the fixed-seed `full` sample (`40` files selected from `1,278` `arm64`/`arm64e` binaries, `3` non-ARM64 skipped; `31,981` functions, `258,906` blocks, `339,379` edges); **`8 / 8`** `clang -O0` known-answer C functions matched; **`0` MachGraph errors** (`4` classified tool differences) against Ghidra `12.1.4` on `/bin/ls`; whole-file `cfg --json` median **`0.3411s`** on `ssh` (`0.91s` before Stage 2), **`1.9243s`** on `vim` (`6.63s` before Stage 2), and **`0.2108s`** on single-function `ssh --symbol _entry` (measured under concurrent build load on the coordinator's machine).
> - **Reproduce on any Apple Silicon Mac:** `./Scripts/test.sh milestone 0` (or `./Scripts/acceptance/m0-quick.sh`), `./Scripts/test.sh milestone 1`, `./Scripts/test.sh milestone 2`, `./Scripts/test.sh milestone 3`, and `./Scripts/test.sh milestone 4`.

---

## Verified Capabilities (`M0`–`M4`)

| Area | Subcommands | What Is Verified in `M0`–`M4` |
|---|---|---|
| **Universal & Mach-O 64 Container Parsing & Dylibs** | `info`, `segments` | Parses Fat/Fat64 slices, `mach_header_64`, `LC_SEGMENT_64` segments/sections, `LC_UUID`, `LC_BUILD_VERSION`, `LC_MAIN`, `LC_ID_DYLIB` (`installID`), `LC_FUNCTION_STARTS`, and ordered imported dylibs with three-part `X.Y.Z` `currentVersion` & `compatibilityVersion` (`--json` & text). Rejects empty files, plain text, truncated Mach-O slices, and unsupported ELF `ET_REL` relocatable object files with non-zero exit codes. |
| **Chained Fixups, Symbols, Demangling, ObjC, Strings & CodeSign** | `fixups`, `symbols`, `demangle`, `objc`, `strings`, `codesign`, `entropy` | Parses `LC_DYLD_CHAINED_FIXUPS` binds/rebases (`fixups`); preserves every defined `LC_SYMTAB` `(address, name)` entry without deduplicating aliases or letting inferred `[inferred:...]` entries overwrite real names (`symbols`); demangles Swift and Itanium C++ names in-process via `swift_demangle` and `__cxa_demangle` from positional args or line-by-line `stdin`, returning unrecognized or plain-C symbols verbatim (`demangle`); extracts Objective-C classes, `±[Class sel]` methods, ivars, categories, and protocols (`objc`, supports `--slice`); scans printable strings (`strings`); prints whole-file Shannon entropy, byte chi-square, zero-byte ratio, and 1024-byte sliding-window anomaly counts (`entropy`); and verifies `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory` / CDHash while decoding XML (`0xFADE7171`) and CoreEntitlements DER (`0xFADE7172`) entitlements into native JSON booleans, integers, strings, arrays, and nested dictionaries (`codesign`). |
| **ARM64 / ARM64e Disassembly, CFG & Xrefs** | `disasm`, `cfg`, `cfg-dot`, `xrefs` | Disassembles only sections carrying `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS` (`disasm`, supports `--symbol` / `--function`, `--address`, and `--count`); recovers whole-binary or single-function structured control-flow graphs, Lengauer–Tarjan dominator trees, natural loops, and switch jump tables in `machgraph.cfg/1` JSON or localized text (`cfg`, supports `--symbol` / `--function`, `--address`, `--slice`, `--json`) while preserving Graphviz DOT export (`cfg-dot`); and queries incoming/outgoing cross-references or dumps the full-binary xref table (`xrefs`, classifying `ADRP+ADD` / `ADR` targets into `STRING_REF` strictly inside string sections, `CODE_REF` for executable code sections, and `DATA_READ` for other data sections). Missing targets fail with exit code `1` and empty `stdout`. |
| **Inline ARM64 Mini-Assembler & Ad-Hoc Re-Signing** | `asm`, `patch-asm`, `resign` | `asm` assembles ARM64 statements from `--asm` or `stdin` starting at `--at` into machine words without reading or writing files (exit `0` when all succeed, `3` when a valid A64 form is not yet supported, `1` on invalid statement). `patch-asm` writes assembled statements onto a Mach-O copy and refreshes the ad-hoc `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory`. `;` only separates statements (`//` and `/* */` are comments): if any statement cannot be assembled, `patch-asm` exits non-zero and writes no output file. `--force` overrides the safety check that otherwise refuses a patch whose interior covers a branch target, function start, symbol, or PAC/BTI landing pad. |
| **Decoder & Assembler Differential Verification (`M2`)** | `disasm`, `asm` | Verified on `2026-11-21` ([`reports/MachGraph-M2.md`](reports/MachGraph-M2.md), [`reports/differential-full-2026-11-20.json`](reports/differential-full-2026-11-20.json); reproduce with `./Scripts/test.sh milestone 2`) against `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>` (`0` mnemonic normalization rules, `4` operand rules `O1`–`O4`): `full` (`1,278` files) records `0` crashes, `0` wrong mnemonics, `0` unrecognized words, `65,969,542 / 65,969,684` (`99.9998%`) mnemonic agreement, and `100%` (`65,969,542 / 65,969,542`) operand agreement; `standard` (`ls`, `ssh`, `vim`) records `0` wrong mnemonics, `0` unrecognized words, and `707,444 / 707,444` operand agreement; `Scripts/acceptance/asm-clang.py standard` verifies `911` of `912` instruction forms produce the original machine word via `clang` (`1` `adrp` form skipped), and `Scripts/acceptance/asm-roundtrip.py standard` records `ok` on `699,038` pre-`M2` instructions (`814` forms) and `6,667` `ok` / `1,739` `unsupported` on `8,406` newly decoded instructions (`0` mismatches, `0` errors). |
| **Metadata & Demangler Differential Verification (`M3`)** | `symbols`, `info`, `codesign`, `demangle`, `xrefs`, `objc` | Verified on `2026-11-21` (`macOS 27.0.1 (26A434) arm64`, `Apple LLVM version 21.0.0`, `cctools-1040`; [`reports/MachGraph-M3.md`](reports/MachGraph-M3.md), [`reports/m3-metadata-full-2026-11-21.json`](reports/m3-metadata-full-2026-11-21.json), [`reports/m3-metadata-objc.txt`](reports/m3-metadata-objc.txt); reproduce with `./Scripts/test.sh milestone 3`): on `full` (`1,278` files), `0` differences across all `6` checks — `symbols` `114,513 / 114,513` vs `xcrun nm --no-dyldinfo -arch <slice> <file>`; `dylibs` `11,516 / 11,516` vs `xcrun otool -arch <slice> -L <file>`; `entitlements` `8,152 / 8,152` top-level keys (`513` files with entitlements, `765` empty) vs `/usr/bin/codesign -a <slice> -d --entitlements :- <file>`; `demangle` `117,076 / 117,076` unique symbols (`28,982` Swift `100.00%` vs `xcrun swift-demangle -compact`, `12,611` C++ `100.00%` vs `/usr/bin/c++filt` per-symbol `argv`, `105` plain-C `_Z` `100.00%` verbatim, `75,378` other symbols `100.00%` verbatim; `0` wrong outputs); `xrefs` `7,498,057 / 7,498,057` `CALL` (`bl`) edges vs `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti` (plus `llvm-objdump --section=<seg>,<sect>` on all non-`__TEXT,__text` `S_ATTR_PURE_INSTRUCTIONS` sections) and `0` non-string-section `STRING_REF` (`1,752,712` `STRING_REF`, `308,955` `CODE_REF` among `18,497,352` xrefs); `objc` `155,495 / 155,495` on `full` and `2,773 / 2,773` on the 4-binary `objc` corpus (`Calculator.app` `62`, `assetutil` `2,378`, `screencapture` `42`, `log` `291`) vs `xcrun otool -arch <slice> -ov <file>` + `otool -arch <slice> -l <file>`. |
| **Control-Flow Graph Verification (`M4`)** | `cfg`, `cfg-dot`, `info` | Verified on `2026-11-21` at commit `50f1fcf` ([`reports/MachGraph-M4.md`](reports/MachGraph-M4.md), [`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt), [`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt), [`reports/m4-cfg-acceptance-known-c.txt`](reports/m4-cfg-acceptance-known-c.txt), [`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt), [`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json); reproduce with `./Scripts/test.sh milestone 4`): `0` violations on `standard` (`8,408` functions, `150,147` blocks, `220,315` edges) and `full` (`40` sampled files, `31,981` functions, `258,906` blocks, `339,379` edges), `8 / 8` `known-c` functions matched, `0` MachGraph errors vs Ghidra `12.1.4` on `/bin/ls` (`4` classified tool differences), and `9 / 9` destructive CFG mutations caught by `Scripts/acceptance/m4-mutations.sh`. Details in *Control-Flow Graph (M4)* below. |
| **Bilingual CLI, HTML Dossier & MCP Server** | `export-html`, `mcp` | Supports `--lang en|zh` and `MACHGRAPH_LANG=en|zh`, exports standalone bilingual (`中文 \| EN`) HTML binary triage reports (`export-html`), and serves JSON-RPC 2.0 MCP requests over `stdio` (`mcp`), requiring an explicit `binaryPath` on every tool call. |

---

## Control-Flow Graph (`M4`)

### Subcommands & `machgraph.cfg/1` Output Schema
- **Whole-binary & single-function CFG (`cfg`):** `machgraph cfg <binary> --json` recovers and exports all functions across executable sections in ascending address order; `machgraph cfg <binary> --symbol <name> --json` (or `--function <name>`, `--address <0x...>`, `--slice <index>`) builds and exports only the matched function. Omitting `--json` prints a localized EN/ZH text summary. Missing symbols/addresses exit with code `1` and empty `stdout`; conflicting flags (`--symbol` with `--address`) exit with code `2` and empty `stdout`.
- **Graphviz DOT (`cfg-dot`):** `machgraph cfg-dot <binary> [--symbol <name> | --address <0x...>] [--json]` remains unchanged for Graphviz DOT export.
- **Schema (`"schema": "machgraph.cfg/1"`):**
  - **Container header:** `filePath`, `fileName`, `isDemo`, `architecture`, `selectedSliceIndex`, `sliceFileOffset`, `lcFunctionStarts` (`UInt64` virtual addresses from `LC_FUNCTION_STARTS`), `inlineJumpTableStarts`, `inlineJumpTableRanges` (`{start, end, size}` byte ranges of inline jump tables inside executable sections), `functionCount`, and `functions`.
  - **Functions (`functions[]`):** `address`, `endAddress`, `name`, `demangledName`, `section`, `isStub`, `isLeaf`, `isThunk`, `usesPAC`, `cyclomaticComplexity`, `instructionCount`, plus:
    - **Basic blocks (`blocks[]`):** `id`, `startAddress`, `endAddress`, `isEntry`, `isExit`, `loopDepth`, `predecessorIDs`, `successorIDs`, `instructionCount`, `instructionAddresses`.
    - **Edges (`edges[]`):** `sourceBlockID`, `targetBlockID`, `kind` (`unconditional`, `conditionalTrue`, `conditionalFalse`, `fallthroughEdge`, `switchCase`), `caseValue` (integer case index for `switchCase`, explicit `null` otherwise), `isBackEdge`.
    - **Dominator tree (`dominatorTree[]`):** `blockID`, `immediateDominatorID` (explicit `null` for the entry block), `dominatedChildrenIDs`, `dominanceFrontierIDs`, `depth`.
    - **Natural loops (`naturalLoops[]`):** `headerBlockID`, `latchBlockIDs`, `bodyBlockIDs`, `exitBlockIDs`, `nestingDepth`.
    - **Jump tables (`jumpTables[]`):** `dispatchInstructionAddress`, `tableBaseAddress`, `entryByteSize`, `isInlineInCode`, `targetAddresses`.
    - **Inline jump-table byte ranges (`inlineJumpTableRanges[]`):** `{start, end, size}` ranges stripped from the instruction stream and function seed list.

### Verification Oracles & Method
- **Function starts:** [`Scripts/acceptance/m4-cfg-acceptance.py`](Scripts/acceptance/m4-cfg-acceptance.py) independently parses `LC_FUNCTION_STARTS` from the Mach-O slice and cross-checks it against `xcrun dyld_info -arch <slice> -function_starts`. `info --json`'s `functionStarts` / `lcFunctionStarts` must match item-for-item (excluding `0x100000000` `__mh_execute_header`); in `__TEXT,__text`, `cfg --json`'s recovered function starts `∪` `inlineJumpTableStarts` must equal `LC_FUNCTION_STARTS` (`0` missing, `0` extra, disjoint); and `__TEXT,__objc_stubs` must have `0` false functions split at `brk` padding.
- **Four CFG invariants (`I1`–`I4`) & independent dominator/loop solver:** Without calling product code, the acceptance script decodes 32-bit ARM64 instructions directly from slice bytes, queries indirect symbols via `xcrun otool -arch <slice> -Iv`, and recomputes dominator sets and natural back-edges with an iterative dataflow solver to verify `I1` (no interior terminators; every block ends at a terminator or falls through `+4` to the next block start; every direct `bl` to a proven `noreturn` target ends its block with `isExit = true` and `0` outgoing edges), `I2` (intra-function branch/jump-table targets are block starts of the same function; cross-function tail jumps target function starts; inline jump tables do not overlap instructions and are not truncated before trailing `udf` words), `I3` (4-byte aligned, non-overlapping functions and blocks with contiguous instructions), and `I4` (consistent block IDs and exact equality of `immediateDominatorID`, dominance frontiers, and `naturalLoops` including `nestingDepth`).
- **Known-answer C functions (`known-c`):** Compiles `8` C functions on the fly with `xcrun clang -O0 -arch arm64` (`_fn_seq`, `_fn_if_else`, `_fn_while`, `_fn_for`, `_fn_nested_loop`, `_fn_switch5_dense` lowered to a comparison chain with `0` jump tables at `-O0`, `_fn_switch10_jumptable` with `1` 10-entry inline jump table, and `_fn_loop_break_continue`) and checks block counts, edge counts, loop counts & nesting depths, and jump-table target counts against `llvm-objdump`-audited ground truth.
- **Ghidra `12.1.4` differential (`/bin/ls`):** [`Scripts/acceptance/m4-ghidra-differential.py`](Scripts/acceptance/m4-ghidra-differential.py) runs Ghidra `12.1.4` `support/analyzeHeadless` (`AARCH64:LE:64:AppleSilicon`) in a temporary project and compares function starts, end addresses, `BasicBlockModel` block counts, and block-start sets, classifying every difference (`0` MachGraph errors).
- **Evidence-backed `noreturn` allowlist:** All `44` symbols kept in `KnownNoreturnSymbols` (`86` candidates audited, `44` kept, `42` removed) are backed by an explicit SDK header `noreturn` attribute (`39` entries, verified against installed SDK headers and line numbers by unit tests), ABI specification (`3` entries: `__stack_chk_fail`, `_Unwind_Resume`, `_ZSt9terminatev`), or call-site evidence (`2` entries: `_os_crash`, `abort_report_np`), recorded in [`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json).

### Recorded Metrics (`2026-11-21`, Commit `50f1fcf`)
All numbers below come from clean-worktree records at commit `50f1fcf` (`macOS 27.0.1 (26A434) arm64`, `Apple clang 21.0.0`, `Apple LLVM 21.0.0`):
- **`standard` corpus ([`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt), [`reports/m4-cfg-acceptance.json`](reports/m4-cfg-acceptance.json), `2026-11-21T15:14:23Z`):**
  - `/bin/ls` (`arm64e`): `50` `LC_FUNCTION_STARTS` (`49` `__TEXT,__text` functions + `1` inline jump table), `133` functions, `871` blocks, `1,110` edges (`38` loops, `32` noreturn exits).
  - `/usr/bin/ssh` (`arm64e`): `1,097` `LC_FUNCTION_STARTS` (`1,094` `__TEXT,__text` functions + `3` inline jump tables; `10` `__objc_stubs`), `1,494` functions, `18,941` blocks, `26,513` edges (`955` loops, `466` noreturn exits).
  - `/usr/bin/vim` (`arm64e`): `6,623` `LC_FUNCTION_STARTS` (`6,528` `__TEXT,__text` functions + `95` inline jump tables; `19` `__objc_stubs`), `6,781` functions, `130,335` blocks, `192,692` edges (`5,200` loops, `582` noreturn exits).
  - `standard` totals (`3 / 3` files): `7,770 / 7,770` `LC_FUNCTION_STARTS`, `8,408` functions, `150,147` blocks, `220,315` edges, `6,193` natural loops, `1,080 / 1,080` verified noreturn exits/direct calls, **`0` violations across `I1`–`I4`** and **`0` noreturn completeness violations**.
- **`known-c` ([`reports/m4-cfg-acceptance-known-c.txt`](reports/m4-cfg-acceptance-known-c.txt), [`reports/m4-cfg-acceptance-known-c.json`](reports/m4-cfg-acceptance-known-c.json), `2026-11-21T15:13:35Z`):** **`8 / 8` matched**, `0` diffs, `0` invariant violations.
- **`full` corpus sample ([`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt), [`reports/m4-cfg-acceptance-full-2026-11-21.json`](reports/m4-cfg-acceptance-full-2026-11-21.json), `2026-11-21T15:13:47Z`):** Fixed-seed uniform sample (`seed=20261121`) of **`40` files** from `1,278` `arm64`/`arm64e` executables (`1,281` discovered Mach-O files, **`3` skipped without an `arm64`/`arm64e` slice**): **`40 / 40` passed**, `0` crashes, `21,945 / 21,945` `LC_FUNCTION_STARTS` (`21,816` `__TEXT,__text` functions + `129` inline jump tables; `5,251` `__objc_stubs`), `31,981` functions, `258,906` blocks, `339,379` edges, `9,274` natural loops, `4,035 / 4,035` noreturn exits/direct calls, **`0` violations across `I1`–`I4`**.
- **Performance (`perf`, [`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt), [`reports/m4-cfg-acceptance-perf.json`](reports/m4-cfg-acceptance-perf.json), `2026-11-21T15:13:36Z`) & before/after comparison:**
  - Measured on the coordinator's machine while other builds were running concurrently (load averages in record: `5.13 5.17 4.58` before, `4.88 5.12 4.57` after; 3-run median):
    - `cfg /usr/bin/ssh --json` (full-file, `1,494` functions, `18,941` blocks): **`0.3411s`** (`[0.3383, 0.3411, 0.3417]s`)
    - `cfg /usr/bin/vim --json` (full-file, `6,781` functions, `130,335` blocks): **`1.9243s`** (`[1.9243, 1.932, 1.8299]s`)
    - `cfg /usr/bin/ssh --symbol _entry --json` (single-function, `1` function, `729` blocks): **`0.2108s`** (`[0.2111, 0.2093, 0.2108]s`)
  - **Before vs. after Stage 2 optimization:** Before Stage 2 (Stage 1 engine building CFGs and writing JSON via the export tool — measured by the coordinator during Stage 2 verification, not in the `reports/` files), whole-file CFG export took **`0.91s`** on `ssh` and **`6.63s`** on `vim`; in [`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt), `cfg --json` takes **`0.3411s`** on `ssh` and **`1.9243s`** on `vim`.
- **Ghidra `12.1.4` differential on `/bin/ls` ([`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json), `2026-11-21T15:14:09Z`):** `133` MachGraph functions vs `134` Ghidra real functions (`133` common starts, `132 / 133` end addresses equal, `133 / 133` block counts equal, `132 / 133` block-start sets equal, `131 / 133` exact on all three; `9.47s`), with **`4` difference records across `4` categories and `0` MachGraph errors (`machgraph_error_count = 0`)**: `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT` (`1`, `@ 0x1000038e8`), `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION` (`1`, `@ 0x1000038e4`), `TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION` (`1`, `_entry` `@ 0x100000b30`), and `TOOL_DIFF_MACHGRAPH_NORETURN_WRAPPER_SPLIT` (`1`, `_entry` `@ 0x100000fe4`).

### Boundaries & Known Limitations
- **Architecture & container:** Only `ARM64` / `ARM64e` Mach-O slices are supported (`x86_64` and non-Mach-O containers are not supported/verified for CFG recovery).
- **Indirect jumps:** Only PC-relative / inline switch jump tables are resolved into `switchCase` edges; other indirect branches (vtable dispatches, function-pointer tail jumps, computed `br` patterns) do not emit outgoing CFG edges.
- **Non-returning callees:** External `noreturn` functions are recognized strictly from the `44`-symbol allowlist ([`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json)). Calls to unlisted non-returning functions keep a fallthrough edge to the next instruction — for example, Swift runtime entry points such as `swift_unexpectedError` are excluded because public macOS SDK headers do not declare them `noreturn` and the tested corpora contain `0` direct call sites. Internal non-returning wrapper functions are inferred through call-graph reachability propagation from known `noreturn` targets and traps.

---

## System Libraries & External Tool Boundaries

- **Binary & Metadata Parsing, Disassembly, Inline Assembly, CFG/Xrefs & CodeSign (`M0`–`M4`):** Implemented directly in Swift on mapped binary bytes. No CLI subcommand or MCP tool spawns `otool`, `llvm-objdump`, `nm`, `codesign`, `dyld_info`, `swift-demangle`, or `c++filt`. (Reference tools and Ghidra `analyzeHeadless` are invoked only by external differential verification scripts under `Scripts/acceptance/`.)
- **Symbol Demangling (`demangle` & Symbol-Table Loading):** Calls `swift_demangle` (`libswiftCore.dylib`) and `__cxa_demangle` (`libc++abi.dylib`) **in-process** on macOS without spawning child processes; the pure-Swift `Swift5ABIDemangler` and `ItaniumCppDemangler` remain in-tree as the fallback when the Darwin runtime is disabled or unavailable.
- **Optional Ghidra Headless Bridge (`GhidraHeadlessSideBySideBridge` in `Sources/MachMicroDecompiler/StructuralRegionAndPseudoCEmitter.swift`):** Contains the repository's only `Foundation.Process()` call, executing `<ghidraInstallDir>/support/analyzeHeadless`. Neither the `decompile` CLI subcommand nor `mcp` ever invokes it; it runs **only** when a desktop GUI user clicks the `"Ghidra 12.1.4 Diff"` button (`MachStudioViewModel.toggleOrRunGhidraComparison`) or a library caller explicitly calls `GhidraHeadlessSideBySideBridge.decompileFunction` / `decompileSideBySide`, **and** `probeInstallation()` finds executable `support/analyzeHeadless`, OpenJDK 21 `bin/java`, and Ghidra's native `decompile` binary under the configured `GHIDRA_INSTALL_DIR` / `JAVA_HOME` (or Preferences / default paths `~/Applications/ghidra_12.1.4_PUBLIC` and `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`).

---

## Build & Run Verification

```bash
swift build --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

Unified test runner (`Scripts/test.sh`). `milestone 0`–`milestone 4` keep their logs in a temporary directory and leave the work tree untouched; `./Scripts/test.sh milestone 4 --record` (on a clean worktree) refreshes `reports/m4-cfg-acceptance.{json,txt}`, and `./Scripts/test.sh mutations` runs the isolated M3 and M4 mutation suites (`Scripts/acceptance/m3-mutations.sh` and `Scripts/acceptance/m4-mutations.sh`):

```bash
./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachCFGEngine MachHeadlessCLI
./Scripts/test.sh milestone 0
./Scripts/test.sh milestone 3
./Scripts/test.sh milestone 4
```

---

## CLI & MCP Usage Examples

Every command below runs against a real binary or explicit input (no hidden fallback data; omitting `<file>` without `--demo` exits with code `2`) and is replayed verbatim in [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh):

```bash
# Inspect Mach-O container metadata (including imported dylibs), segments, chained fixups, symbols, and native entitlements
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls
.build/debug/MachGraph codesign /usr/bin/ssh --json

# Demangle Swift and Itanium C++ symbols in-process (positional arguments or line-by-line stdin), inspect ObjC metadata, and dump full-binary xrefs
.build/debug/MachGraph demangle '_$sSiN' __Z3fooi _ZeroFilesTested --json
printf '_$sSiN\n__Z12set_darkbooti.cold.1\n_main\n' | .build/debug/MachGraph demangle
.build/debug/MachGraph objc /System/Applications/Calculator.app/Contents/MacOS/Calculator --json
.build/debug/MachGraph xrefs /bin/ls --json

# Disassemble /bin/ls from its LC_MAIN entry symbol or inspect the compiled ARM64 fixture by address
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10

# Export whole-binary and single-function structured CFGs (schema machgraph.cfg/1) and Graphviz DOT for /bin/ls
.build/debug/MachGraph cfg /bin/ls --json
.build/debug/MachGraph cfg /bin/ls --symbol _entry --json
.build/debug/MachGraph cfg-dot /bin/ls --symbol _entry

# Assemble a 4-instruction ARM64 sequence onto a temporary copy and ad-hoc re-sign
cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample
.build/debug/MachGraph patch-asm /tmp/machgraph_readme_sample \
  --address 0x100000460 \
  --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" \
  --force \
  --output /tmp/machgraph_readme_patched \
  --json
rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched

# Assemble ARM64 statements only (no files read or written; exit 0 all ok, 3 unsupported valid A64 form, 1 invalid statement)
.build/debug/MachGraph asm --at 0x100000460 --asm "stp x29, x30, [sp, #-16]!; mov x0, #42; b .+8" --json

# Export a standalone bilingual (中文 | EN) HTML binary triage report for /bin/ls
.build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html
rm -f /tmp/machgraph_ls_triage.html

# Bilingual CLI output (--lang zh|en) and explicit [DEMO] sample mode
.build/debug/MachGraph --help --lang zh
.build/debug/MachGraph info --demo --lang zh

# Query the stdio JSON-RPC 2.0 MCP server with an explicit binaryPath
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/bin/ls"}}}\n' \
  | .build/debug/MachGraph mcp
```

### Language Resolution Order
`MachGraph` resolves the output language in this fixed order:
1. Command-line option: `--lang zh` / `--lang en`
2. Environment variable: `MACHGRAPH_LANG=zh` / `MACHGRAPH_LANG=en`
3. User preference: `UserDefaults` (`io.github.zxu756.MachGraph.language`)
4. System preferred language: Simplified Chinese when `Locale.preferredLanguages.first` starts with `"zh"`, otherwise English

---

## Planned Milestones & Experimental / Frozen Modules

`M0`–`M4` are completed and verified above. The following roadmap items and in-tree modules have **not** yet completed differential acceptance and are excluded from the verified feature table:

- **M5 — Expanded MCP Tool Surface & SwiftPM Library API:** Adding `mach_disasm_function`, `mach_list_symbols`, `mach_cfg`, and `mach_find_strings` to `mcp`, plus standalone SwiftPM consumer examples.
- **Experimental / Frozen Until Post-M5:**
  - **Pseudo-C Decompiler (`decompile` / `MachMicroDecompiler`):** **Experimental** — condition expressions, loop bounds, and switch recovery are known to produce incorrect output on real binaries. `decompile` emits an explicit reliability warning on line 1 (`// EXPERIMENTAL: Decompiler output — condition expressions are known to be unreliable.`); rely on `disasm` for ground truth. (See *System Libraries & External Tool Boundaries* above for when `GhidraHeadlessSideBySideBridge` invokes local Ghidra `analyzeHeadless`.)
  - **Security Audit Plugins (`audit-plugins` / `MachPluginSDK`):** Heuristic `JavaScriptCore` rules have known false positives and false negatives and have not yet been calibrated against a ground-truth benchmark.
  - **Desktop App (`MachStudioViews` / `MachWorkbenchShell`), `.machproj` Store & Non-Mach-O Loaders (`ELF64` / `PE32+` / `WASM`):** Launching `MachGraph` without CLI arguments opens an empty workspace (`Open File...` or explicit `Load Demo (DEMO)`). Full GUI verification, `.machproj` persistence, and non-Mach-O reference differential tests are deferred until after `M5`.

---

## License

MIT License. Copyright (c) 2026 Xu (`zxu756`).
