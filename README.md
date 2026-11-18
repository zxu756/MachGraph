# MachGraph

**English** | **[简体中文](README.zh-CN.md)**

Pure-Swift ARM64/ARM64e disassembler, inline mini-assembler, and Universal/Mach-O 64 binary parser for macOS (`arm64`), with a headless bilingual CLI (`--lang en|zh`) and a stdio JSON-RPC 2.0 MCP server.

> **Reproducible Baseline (`2026-11-14`, `macOS 27.0.1 (26A434) arm64`, logged in [`reports/m0-quick.txt`](reports/m0-quick.txt)):**
> Mach-O container parsing, dyld chained fixups, embedded code-signature hashing, and ARM64 instruction decoding run natively in Swift without invoking `otool`, `llvm-objdump`, `nm`, or `codesign`.
> - **`/bin/ls` (`arm64e` slice):** `5` segments and `11` sections match `otool -arch arm64e -l /bin/ls` item-for-item (`vmaddr`, `vmsize`, `fileoff`, `filesize`, `addr`, `size`, `offset`); across all `3,846` instructions in `__TEXT,__text`, mnemonic agreement with `xcrun llvm-objdump -d --no-show-raw-insn --arch=arm64e` **after mnemonic normalization** is **`3,845 / 3,846` (`99.97%`)**, with **`0` wrong mnemonics** and `1` unrecognized word (`.inst`). The normalization is exactly three rules, applied by [`Scripts/acceptance/mnemonic-agreement.py`](Scripts/acceptance/mnemonic-agreement.py): `movz`/`movn` count as `mov`, `udf` counts as `.inst`, and a vector arrangement suffix on the reference mnemonic is dropped. Operands are not compared.
> - **`/usr/bin/ssh` (`arm64e` slice):** **`115,546` instructions** decoded strictly from instruction-attributed sections (`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`), with **`0` lines** decoded from non-instruction data sections such as `__TEXT,__info_plist`.
> - **Reproduce on any Apple Silicon Mac:** `./Scripts/test.sh milestone 0` (or `./Scripts/acceptance/m0-quick.sh`). The `M1` differential harness (`./Scripts/test.sh milestone 1`) runs the `quick` and `standard` corpora; the committed [`full` report](reports/differential-full-2026-11-15.json) (`/bin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `1,278` files, `65,969,684` instructions, same three normalization rules) records `0` wrong mnemonics, `38,063` unrecognized words (`.inst`), and `99.94%` overall agreement.

---

## Verified Capabilities (`M0` Baseline)

| Area | Subcommands | What Is Verified in `M0` |
|---|---|---|
| **Universal & Mach-O 64 Container Parsing** | `info`, `segments` | Parses Fat/Fat64 slices, `mach_header_64`, `LC_SEGMENT_64` segments/sections, `LC_UUID`, `LC_BUILD_VERSION`, `LC_MAIN`, and imported dylibs (`--json` & text). Rejects empty files, plain text, truncated Mach-O slices, and unsupported ELF `ET_REL` relocatable object files with non-zero exit codes. |
| **Chained Fixups, Symbols, Strings & CodeSign** | `fixups`, `symbols`, `strings`, `codesign`, `entropy` | Parses `LC_DYLD_CHAINED_FIXUPS` binds/rebases (`fixups`), separates `LC_SYMTAB` symbols from `[inferred:...]` `LC_FUNCTION_STARTS` / `LC_DYSYMTAB` stub entries (`symbols`), scans printable strings (`strings`), prints one Shannon entropy figure for the whole file together with its byte chi-square, zero-byte ratio, and the number of 1024-byte sliding windows and anomalies (`entropy`; per-section entropy is not printed), and verifies embedded `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory` & CDHash (`codesign`). |
| **ARM64 / ARM64e Disassembly & Xrefs** | `disasm`, `xrefs`, `cfg-dot` | Disassembles only sections carrying `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`, supports `--symbol` / `--function`, `--address`, and `--count`, queries resolved call/branch/data cross-references (`xrefs`), and exports Graphviz DOT control-flow graphs (`cfg-dot`). Missing targets fail with exit code `1` and empty `stdout`. |
| **Inline ARM64 Mini-Assembler & Ad-Hoc Re-Signing** | `asm`, `patch-asm`, `resign` | `asm` assembles ARM64 statements from `--asm` or `stdin` starting at `--at` into machine words without reading or writing files (exit `0` when all succeed, `3` when a valid A64 form is not yet supported, `1` on invalid statement). `patch-asm` writes assembled statements onto a Mach-O copy and refreshes the ad-hoc `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory`. `;` only separates statements (`//` and `/* */` are comments): if any statement cannot be assembled, `patch-asm` exits non-zero and writes no output file. `--force` overrides the safety check that otherwise refuses a patch whose interior covers a branch target, function start, symbol, or PAC/BTI landing pad. |
| **Bilingual CLI, HTML Dossier & MCP Server** | `export-html`, `mcp` | Supports `--lang en|zh` and `MACHGRAPH_LANG=en|zh`, exports standalone bilingual (`中文 \| EN`) HTML binary triage reports (`export-html`), and serves JSON-RPC 2.0 MCP requests over `stdio` (`mcp`), requiring an explicit `binaryPath` on every tool call. |

---

## Build & Run Verification

```bash
swift build --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

Unified test runner (`Scripts/test.sh`). `milestone 0` keeps its logs in a temporary directory and leaves the work tree untouched; `./Scripts/test.sh milestone 0 --record` refreshes the committed copies under `reports/`:

```bash
./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachHeadlessCLI
./Scripts/test.sh milestone 0
```

---

## CLI & MCP Usage Examples

Every command below runs against a real binary (no hidden fallback data; omitting `<file>` without `--demo` exits with code `2`) and is replayed verbatim in [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh):

```bash
# Inspect Mach-O container metadata, segments, dyld chained fixups, symbols, and code signature
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls

# Disassemble /bin/ls from its LC_MAIN entry symbol or inspect the compiled ARM64 fixture by address
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10

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

The following roadmap items and in-tree modules have **not** yet completed differential acceptance and are excluded from the verified feature table above:

- **M2 — SIMD Integer Vector Decoder & Operand Parity:** Complete coverage for unrecognized AdvSIMD integer mnemonics (currently emitted as `.inst`), remaining LLVM canonical alias emission (`movz`/`movn` as `mov`), and operand-level round-trip assembly checks.
- **M3 — Metadata & Demangler Differential Verification:** Full `LC_SYMTAB` parity with `nm -arch arm64e` (including undefined `U` import records), Swift `$s` (`swift-demangle`) and Itanium `_Z` (`c++filt`) demangling benchmarks, ObjC metadata (`otool -ov`), and entitlement plist parity.
- **M4 — Control-Flow Graph Invariants & Performance:** CFG basic-block invariants, Ghidra block-boundary comparison, and `ssh`/`vim` whole-binary CFG construction profiling.
- **M5 — Expanded MCP Tool Surface & SwiftPM Library API:** Adding `mach_disasm_function`, `mach_list_symbols`, `mach_cfg`, and `mach_find_strings` to `mcp`, plus standalone SwiftPM consumer examples.
- **Experimental / Frozen Until Post-M5:**
  - **Pseudo-C Decompiler (`decompile` / `MachMicroDecompiler`):** **Experimental** — condition expressions, loop bounds, and switch recovery are known to produce incorrect output on real binaries. `decompile` emits an explicit reliability warning on line 1 (`// EXPERIMENTAL: Decompiler output — condition expressions are known to be unreliable.`); rely on `disasm` for ground truth. (An optional local Ghidra `analyzeHeadless` comparison helper also lives in this module when explicitly configured.)
  - **Security Audit Plugins (`audit-plugins` / `MachPluginSDK`):** Heuristic `JavaScriptCore` rules have known false positives and false negatives and have not yet been calibrated against a ground-truth benchmark.
  - **Desktop App (`MachStudioViews` / `MachWorkbenchShell`), `.machproj` Store & Non-Mach-O Loaders (`ELF64` / `PE32+` / `WASM`):** Launching `MachGraph` without CLI arguments opens an empty workspace (`Open File...` or explicit `Load Demo (DEMO)`). Full GUI verification, `.machproj` persistence, and non-Mach-O reference differential tests are deferred until after `M5`.

---

## License

MIT License. Copyright (c) 2026 Xu (`zxu756`).
