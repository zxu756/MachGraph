# MachGraph

**English** | **[简体中文](README.zh-CN.md)**

> Pure-Swift ARM64/ARM64e disassembler and Mach-O 64 parser that spawns zero external commands. Across **`1,278`** system Mach-O binaries and **`65,969,684`** instructions on this Mac (`macOS 27.0.1 (26A434) arm64`, `Apple LLVM version 21.0.0`, recorded `2026-11-22` at clean commit `fadecfa`, [`reports/differential-full-2026-11-22.json`](reports/differential-full-2026-11-22.json)), mnemonic agreement with `xcrun llvm-objdump` is **`99.9998%`** (`65,969,542 / 65,969,684` overall; **`100.0000%`** across all `65,969,542` recognized instructions, plus `142` words in `8` files where `llvm-objdump` also emits `.long`), with **`0` wrong mnemonics** and **`100.0000%` (`65,969,542 / 65,969,542`) operand agreement**.
>
> **Reproduce in one command:** `swift build -c release --product MachGraph && python3 -I Scripts/acceptance/differential.py full --machgraph .build/release/MachGraph` (or run the full 35-step release gate: `GHIDRA_INSTALL_DIR=<path-to-ghidra> JAVA_HOME=<path-to-jdk21> ./Scripts/test.sh release`).

MachGraph provides three verified SwiftPM library products (`MachBinaryFormats`, `MachA64Decoder`, `MachCFGEngine`), a bilingual headless CLI (`--lang en|zh`), and a stdio JSON-RPC 2.0 MCP server (`machgraph mcp`).

### Reproducible Recorded Baselines (`2026-11-22`, Commit `fadecfa`, `macOS 27.0.1 (26A434) arm64`)

- **`/bin/ls` & `/usr/bin/ssh` (`M0`–`M2`, [`reports/m0-quick.txt`](reports/m0-quick.txt), [`reports/differential-standard.txt`](reports/differential-standard.txt), [`reports/macho-differential-standard.txt`](reports/macho-differential-standard.txt)):** `/bin/ls` (`arm64e`) matches `otool -arch arm64e -l` item-for-item (`5` segments, `11` sections, `3` imported libraries, `113` chained fixups) and records **`3,846 / 3,846` (`100.00%`)** mnemonic and operand agreement (`0` wrong, `0` `.inst`) with `0` mnemonic normalization rules ([`Scripts/acceptance/mnemonic_normalization.py`](Scripts/acceptance/mnemonic_normalization.py)) and `4` reference-side operand rules `O1`–`O4` ([`Scripts/acceptance/operand_normalization.py`](Scripts/acceptance/operand_normalization.py)). `/usr/bin/ssh` (`arm64e`) decodes **`115,546`** instructions strictly from instruction-attributed sections (`0` lines from `__TEXT,__info_plist`), and `standard` (`ls`, `ssh`, `vim`) achieves **`707,444 / 707,444` (`100.0000%`)** mnemonic and operand agreement (`0` wrong, `0` unrecognized; `1` `mg_only_inst` word in `ssh` and `102` in `vim`).
- **Full-Corpus Disassembly, Container & Inline Assembler (`M1`–`M2`, [`reports/differential-full-2026-11-22.json`](reports/differential-full-2026-11-22.json), [`reports/macho-differential-full-2026-11-22.json`](reports/macho-differential-full-2026-11-22.json), [`reports/encoding-table-check.txt`](reports/encoding-table-check.txt), [`reports/encoding-fuzz-20261117.txt`](reports/encoding-fuzz-20261117.txt), [`reports/encoding-fuzz-17.txt`](reports/encoding-fuzz-17.txt), [`reports/asm-clang-standard.txt`](reports/asm-clang-standard.txt), [`reports/asm-roundtrip-standard.txt`](reports/asm-roundtrip-standard.txt), [`reports/asm-clang-cases.txt`](reports/asm-clang-cases.txt), [`reports/known-mnemonics-check.txt`](reports/known-mnemonics-check.txt)):** Across `1,278` system Mach-O binaries (`1,281` discovered in `/bin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`; `3` without `arm64`/`arm64e` skipped; `1,275` `arm64e` + `3` `arm64`; `0` crashes): Mach-O container checks match `6,176` segments, `21,558` sections, `11,516` imported libraries, `1,903,277` chained fixups, and `1,278` signed binaries (`0` mismatches); disassembly matches `65,969,542 / 65,969,684` (`99.9998%`) mnemonics and `65,969,542 / 65,969,542` (`100.0000%`) operands (`0` wrong, `0` unrecognized); `56` encoding tables pass with `0` mismatches; two `100,000`-word random fuzz runs record `0` wrong mnemonics and `100.0000%` operand agreement (`seed=20261117`: `31,180` agreed, `68,456` both unrecognized, `364` unknown; `seed=17`: `31,086` agreed, `68,574` both unrecognized, `340` unknown); `asm-clang.py standard` matches **`911 / 912`** forms via `clang` (`1` `adrp` skipped); `asm-roundtrip.py standard` (`707,444` decoded) verifies `699,038 / 699,038` pre-`M2` instructions (`814` forms) and `6,667` newly decoded (`1,739` unsupported, `0` mismatches/errors); `asm-clang.py Fixtures/asm-cases.s` (`71` cases) records `35` matched, `35` unsupported, `1` `adrp` unverifiable (`0` failures); and `A64KnownMnemonics.swift` (`727` mnemonics, `13,184` bytes) matches byte-for-byte.
- **Full-Corpus Metadata & Symbol Demangling (`M3`, [`reports/m3-metadata-full-2026-11-22.json`](reports/m3-metadata-full-2026-11-22.json), [`reports/m3-metadata-full-2026-11-22.txt`](reports/m3-metadata-full-2026-11-22.txt), [`reports/m3-metadata-objc.txt`](reports/m3-metadata-objc.txt)):** Across the same **`1,278`** files (`0` crashes, **`0` diffs across all `6` checks**): **`114,513 / 114,513`** defined symbols (`nm --no-dyldinfo`), **`11,516 / 11,516`** imported dylibs & install IDs (`otool -L`), **`8,152 / 8,152`** top-level entitlement keys (`513` entitled files + `765` empty `{}`, vs `codesign -a <slice> -d --entitlements :-`), **`117,076 / 117,076`** unique symbols across `4` demangle buckets (`28,982` Swift vs `swift-demangle -compact`, `12,611` C++ vs `c++filt`, `105` plain-C `_Z` verbatim, `75,378` other verbatim; `0` wrong), **`7,498,057 / 7,498,057`** `CALL` (`bl`) xrefs (`0` non-string-section `STRING_REF` across `18,496,618` total xrefs, including `1,752,712` `STRING_REF` and `308,955` `CODE_REF`), and **`155,495 / 155,495`** Objective-C metadata items (`2,773 / 2,773` on the `4`-file `objc` corpus: `Calculator` `62`, `assetutil` `2,378`, `screencapture` `42`, `log` `291`).
- **Control-Flow Graph (`M4`, [`reports/m4-cfg-acceptance.json`](reports/m4-cfg-acceptance.json), [`reports/m4-cfg-acceptance-full-2026-11-22.json`](reports/m4-cfg-acceptance-full-2026-11-22.json), [`reports/m4-cfg-acceptance-known-c.json`](reports/m4-cfg-acceptance-known-c.json), [`reports/m4-cfg-acceptance-perf.json`](reports/m4-cfg-acceptance-perf.json), [`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)):** **`0` violations** across `I1`–`I4`, dominator trees, natural loops, and `LC_FUNCTION_STARTS` on `standard` (`3 / 3` files, `7,770` `LC_FUNCTION_STARTS`, `8,408` functions, `150,147` blocks, `220,315` edges, `6,193` loops, `1,080 / 1,080` noreturn calls) and the fixed-seed `full` sample (`40 / 40` files, `seed=20261121`, `21,945` `LC_FUNCTION_STARTS`, `31,981` functions, `258,906` blocks, `339,379` edges, `9,274` loops, `4,035 / 4,035` noreturn calls); **`8 / 8`** `clang -O0` known-answer C functions matched; **`0` MachGraph errors** (`4` classified tool differences, `8.89s`) vs Ghidra `12.1.4` on `/bin/ls`; and `perf` 3-run medians of **`0.3196s`** on whole-file `ssh`, **`1.711s`** on whole-file `vim`, and **`0.1962s`** on single-function `ssh --symbol _entry` (load averages `4.24 5.96 5.70` -> `3.82 5.81 5.65`).
- **MCP Server & SwiftPM Library Release (`M5`, [`reports/m5-mcp-protocol.json`](reports/m5-mcp-protocol.json), [`reports/m5-mcp-tools.json`](reports/m5-mcp-tools.json), [`reports/m5-mcp-legacy.json`](reports/m5-mcp-legacy.json), [`reports/m5-mcp-perf.json`](reports/m5-mcp-perf.json), [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json), [`reports/MachGraph-M5.md`](reports/MachGraph-M5.md)):** MCP `protocol` (`8` tools, `0` diffs), `tools` (**`14 / 14`** byte-identical cases vs CLI `--json`, including `/bin/ls` `LC_MAIN` entry `0x100000960` and `/usr/bin/ssh` entry `0x100017898`), `legacy` (`0` diffs, bidirectional xrefs at `0x10000073c` + bilingual `[EXPERIMENTAL / UNVERIFIED]` banners), `perf` 3-run medians (`ssh`: `mach_list_symbols` `0.0334s`, `mach_find_strings` `0.0225s`, `mach_cfg` `0.1947s`, `mach_disasm_function` `0.2369s`; `vim`: `mach_list_symbols` `0.0942s`, `mach_find_strings` `0.0513s`, `mach_cfg` `0.8729s`, `mach_disasm_function` `0.8736s`), **`3 / 3`** standalone external SwiftPM consumer packages (`14`, `16`, and `16` lines, `0` warnings) + **`14 / 14`** negative access-control/product probes rejected, **`8 / 8`** M5 mutations caught (`Scripts/acceptance/m5-mutations.sh`), and **`35 / 35`** steps passed in `Scripts/test.sh release`.

---

## Verified Capabilities (`M0`–`M5`)

Only capabilities that have passed independent differential acceptance are listed below. Unverified and roadmap items are documented in *Planned & Experimental / Unverified Items*.

| Area | Entry Points | Verified Scope & Oracles |
|---|---|---|
| **ARM64 / ARM64e Disassembler & Inline Assembler (`M1`, `M2`)** | CLI: `disasm`, `asm` | Decodes instruction-attributed Mach-O sections (`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`, supporting `--symbol` / `--function`, `--address`, `--count`, `--slice`, `--json`) and assembles ARM64 statements at `--at` without touching disk (`asm`, exit `0` ok, `3` unsupported valid A64 form, `1` invalid syntax). Verified against `xcrun llvm-objdump` (`1,278` binaries, `65,969,684` instructions, `0` wrong mnemonics, `100.0000%` operand agreement) and `xcrun clang` (`911 / 912` standard forms, `56` encoding tables, `2 x 100,000` random words). |
| **Mach-O 64 Metadata & Symbol Demangling (`M0`, `M1`, `M3`)** | CLI: `info`, `segments`, `fixups`, `symbols`, `demangle`, `objc`, `strings`, `codesign`, `xrefs` | Parses Fat/Fat64 slices, `mach_header_64`, segments/sections, `LC_UUID`, `LC_MAIN`, `LC_ID_DYLIB`, `LC_FUNCTION_STARTS`, ordered imported dylibs (`X.Y.Z` versions), `LC_DYLD_CHAINED_FIXUPS`, non-deduplicated `LC_SYMTAB` symbols (`symbols`), in-process `swift_demangle` & `__cxa_demangle` demangling (`demangle`), Objective-C classes/methods/ivars/categories/protocols (`objc`), UTF-8/UTF-16 strings (`strings`), SHA-256 `CodeDirectory` & native XML/DER entitlements (`codesign`), and typed cross-references (`xrefs`). Verified with `0` diffs across `1,278` binaries against `otool`, `nm`, `codesign`, `swift-demangle`, `c++filt`, and `llvm-objdump`. |
| **Control-Flow Graph, Dominators & Loops (`M4`)** | CLI: `cfg`, `cfg-dot` | Recovers whole-binary or single-function structured CFGs (`schema: "machgraph.cfg/1"`), inline switch jump tables (`cmp + b.hi` and branchless `cmp + csel`), Lengauer–Tarjan dominator trees & dominance frontiers, natural loops with nesting depths, and `44` evidence-backed `noreturn` callees ([`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json)), plus Graphviz DOT export (`cfg-dot`). Verified against independent Python ARM64/dataflow solvers (`standard` `8,408` functions & `full` `31,981` functions, `0` violations across `I1`–`I4`), `8 / 8` `clang -O0` C functions, and Ghidra `12.1.4` on `/bin/ls` (`0` MachGraph errors). |
| **MCP Server — 6 Verified Tools (`M5`)** | CLI: `mcp` (`stdio` JSON-RPC 2.0) | Verified tools: `mach_inspect_binary`, `mach_list_symbols`, `mach_find_strings`, `mach_disasm_function`, `mach_cfg`, and `mach_query_xrefs`. Every tool delegates directly to `MachCLIRunner`'s shared implementation (`mach_list_symbols`, `mach_find_strings`, `mach_disasm_function`, and `mach_cfg` are byte-for-byte identical to CLI `--json`; `mach_cfg` requires `symbol` or `address`; `mach_query_xrefs` emits both incoming `<-` and outgoing `->` xrefs). `mach_decompile_function` and `mach_audit_security` remain available solely as **experimental, unverified** tools with mandatory line-1 warnings. |
| **SwiftPM Library Products — 3 Verified Modules (`M5`)** | Library products: `MachBinaryFormats`, `MachA64Decoder`, `MachCFGEngine` | Public Swift 6 library products for Mach-O/Universal parsing & code-signing (`MachBinaryFormats`), ARM64 decoding, mini-assembly & demangling (`MachA64Decoder`), and CFG/dominator/loop/xref analysis (`MachCFGEngine`). Each re-exports `MachGraphModels` via `@_exported import MachGraphModels`. Verified in standalone external Swift packages (`3 / 3` examples build with `0` warnings and match system tools; `14 / 14` tightened `internal`/`package` symbols and unexported frozen products are rejected at compile time). |

---

## MCP Server (`M5`)

`machgraph mcp` serves JSON-RPC 2.0 (`protocolVersion: "2024-11-05"`) over `stdio`. Every tool call requires `binaryPath` (unless a default binary was passed on the command line) and shares the exact same internal functions as the headless CLI:

| Tool Name | Parameters (`required` in **bold**) | CLI Equivalent & Output Contract |
|---|---|---|
| `mach_inspect_binary` | **`binaryPath`**, `slice` | Calls the same `buildBinaryInfoSnapshot` + `formatBinaryInfo` pipeline as `machgraph info <file> [--slice <n>]` (compact container, segment, symbol, fixup, and `cdhash` summary). |
| `mach_list_symbols` | **`binaryPath`**, `filter`, `slice` | Byte-for-byte identical to `machgraph symbols <file> [--filter <q>] [--slice <n>] --json` (uses container-only fast path without building CFGs). |
| `mach_find_strings` | **`binaryPath`**, `filter`, `slice` | Byte-for-byte identical to `machgraph strings <file> [--filter <q>] [--slice <n>] --json` (uses container-only fast path). |
| `mach_disasm_function` | **`binaryPath`**, `symbol` (or `function`) \| `address` *(mutually exclusive)*, `count`, `slice` | Byte-for-byte identical to `machgraph disasm <file> [--symbol <name> \| --address <0x...>] [--count <n>] [--slice <n>] --json`. |
| `mach_cfg` | **`binaryPath`**, plus **one of `symbol` (or `function`) or `address`** *(required, mutually exclusive)*, `slice` | Byte-for-byte identical to single-function `machgraph cfg <file> (--symbol <name> \| --address <0x...>) [--slice <n>] --json`. **`mach_cfg` must pass `symbol` or `address`** (omitting both returns `isError: true`; whole-binary CFG export stays on the CLI). |
| `mach_query_xrefs` | **`binaryPath`**, **`address`**, `slice` | Calls the same `formatTargetXrefs` query as `machgraph xrefs <file> --address <0x...> [--slice <n>]`, returning both incoming (`<-`) and outgoing (`->`) cross-references. |
| `mach_decompile_function` | **`binaryPath`**, **`function`**, `slice` | **Experimental, unverified (has not passed acceptance):** identical to `machgraph decompile <file> (--symbol <name> \| --address <0x...>) [--slice <n>]`; line 1 always emits `// EXPERIMENTAL: [EXPERIMENTAL / UNVERIFIED] ...` (EN) or `// 【实验性】【未通过验收】...` (ZH). |
| `mach_audit_security` | **`binaryPath`**, `slice` | **Experimental, unverified (has not passed acceptance):** identical to `machgraph audit-plugins <file> [--slice <n>]`; line 1 always emits `# [EXPERIMENTAL / UNVERIFIED] ...` (EN) or `# 【实验性・未通过验收】...` (ZH). |

---

## SwiftPM Library Usage (`M5`)

### Package Dependency & Exported Products

Add `MachGraph` to your `Package.swift` via a local path (`.package(path:)`) or Git URL (`.package(url:from:)`), and depend on any of the three verified library products — **`MachBinaryFormats`**, **`MachA64Decoder`**, or **`MachCFGEngine`** (`MachGraphModels` is re-exported automatically via `@_exported import MachGraphModels`, so consumers do not need to import `MachGraphModels` separately):

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MyBinaryTool",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../MachGraph")
        // or: .package(url: "https://github.com/zxu756/MachGraph.git", from: "1.4.0")
    ],
    targets: [
        .executableTarget(
            name: "MyBinaryTool",
            dependencies: [
                .product(name: "MachBinaryFormats", package: "MachGraph"),
                .product(name: "MachA64Decoder", package: "MachGraph"),
                .product(name: "MachCFGEngine", package: "MachGraph")
            ]
        )
    ]
)
```

(`Package.swift` also exports `MachGraphModels`, `MachHeadlessCLI`, and the `MachGraph` executable; unverified internal targets are not exported as SwiftPM library products.)

The three `<= 20`-line examples below are extracted directly from `README.md` and `README.zh-CN.md`, compiled with `0` warnings in standalone temporary Swift packages, and verified against system reference tools by [`Scripts/acceptance/m5-lib-examples.py`](Scripts/acceptance/m5-lib-examples.py) (logged in [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)).

### 1. `MachBinaryFormats` — Read Mach-O Header, Segments, and Code Signature

Load `/bin/ls` (automatically selecting the preferred `arm64e` slice from the Universal Fat container) and inspect its Mach-O header, segments, `LC_FUNCTION_STARTS` count, and SHA-256 `CodeDirectory` hash:

```swift
import MachBinaryFormats

@main
struct BinaryFormatsDemo {
    static func main() throws {
        let image = try UniversalBinaryDispatcher.load(filePath: "/bin/ls")
        let segments: [BinarySegment] = image.segments
        let names = segments.map(\.name).joined(separator: ",")
        print("format=\(image.containerFormat.rawValue) arch=\(image.architecture.displayName)")
        print("entry=\(image.entryPoint?.hexString ?? "none") segments=\(segments.count) [\(names)]")
        print("lcFunctionStarts=\(image.lcFunctionStarts.count)")
        print("signed=\(image.codeSignature.isSigned) cdhash=\(image.codeSignature.cdHashHex)")
    }
}
```

Expected output (`macOS 27.0.1 (26A434) arm64` `/bin/ls`; verified independently against `xcrun otool -l`, `llvm-objdump --macho --function-starts`, and `codesign -dvvv` in [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)):

```text
format=Mach-O Universal Fat arch=arm64e (PAC)
entry=0x0000000100000960 segments=5 [__PAGEZERO,__TEXT,__DATA_CONST,__DATA,__LINKEDIT]
lcFunctionStarts=50
signed=true cdhash=54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce
```

### 2. `MachA64Decoder` — Assemble and Decode A64 Instructions

Assemble a four-instruction A64 prologue/epilogue sequence at `0x100000000` and decode the raw instruction buffer back into structured `A64DecodedInstruction` values:

```swift
import MachA64Decoder

@main
struct A64DecoderDemo {
    static func main() throws {
        let base = VirtualAddress(0x1_0000_0000)
        let src = "entry: sub sp, sp, #16; mov w0, #42; add sp, sp, #16; ret"
        let assembled = try A64MiniAssembler().assembleProgram(src, baseAddress: base)
        let decoded = A64InstructionDecoder().decodeBuffer(assembled.bytes, baseAddress: base)
        for insn in decoded {
            let hex = String(insn.rawWord, radix: 16)
            let wordHex = String(repeating: "0", count: max(0, 8 - hex.count)) + hex
            print("\(insn.address.hexString)  \(wordHex)  \(insn.formattedDisassembly)")
        }
    }
}
```

Expected output (verified independently against `xcrun clang -arch arm64` and `xcrun llvm-objdump -d` in [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)):

```text
0x0000000100000000  d10043ff  sub sp, sp, #0x10
0x0000000100000004  52800540  mov w0, #0x2a
0x0000000100000008  910043ff  add sp, sp, #0x10
0x000000010000000c  d65f03c0  ret
```

### 3. `MachCFGEngine` — Build the Control-Flow Graph for a Single Function

Recover basic blocks, control-flow edges, Lengauer–Tarjan dominators, and natural loops for `/bin/ls`'s `LC_MAIN` entry point (`0x100000960`) via the single-function fast path `analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`:

```swift
import Foundation
import MachCFGEngine

@main
struct CFGEngineDemo {
    static func main() throws {
        let entry = VirtualAddress(0x1_0000_0960)
        let snapshot = try BinaryAnalysisCoordinator().analyzeCFGOnly(
            fileURL: URL(fileURLWithPath: "/bin/ls"),
            selector: .address(entry)
        )
        guard let fn = snapshot.functions.first else { return }
        print("functions=\(snapshot.boundariesByAddress.count) entry=\(fn.name)@\(fn.address.hexString)")
        print("blocks=\(fn.blocks.count) edges=\(fn.edges.count) dom=\(fn.dominatorTree.count) loops=\(fn.naturalLoops.count)")
    }
}
```

Expected output (`macOS 27.0.1 (26A434) arm64` `/bin/ls`; verified independently from `LC_MAIN`, `LC_FUNCTION_STARTS`, `otool -Iv`, `llvm-objdump -d`, and independent dominator/loop analysis in [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)):

```text
functions=133 entry=_entry@0x0000000100000960
blocks=154 edges=259 dom=154 loops=1
```

---

## Control-Flow Graph (`M4`)

- **Schema (`"schema": "machgraph.cfg/1"`):** `machgraph cfg <binary> --json` exports all recovered functions in ascending address order; `machgraph cfg <binary> --symbol <name> --json` (or `--function <name>`, `--address <0x...>`, `--slice <index>`) builds only the matched function (`cfg-dot` exports Graphviz DOT). Top-level fields include `lcFunctionStarts`, `inlineJumpTableStarts`, `inlineJumpTableRanges`, `functionCount`, and `functions[]` (`blocks[]`, `edges[]`, `dominatorTree[]`, `naturalLoops[]`, `jumpTables[]`, `inlineJumpTableRanges[]`).
- **Boundaries & known limitations:** Only `ARM64` / `ARM64e` Mach-O slices are supported for CFG recovery; only PC-relative / inline switch jump tables emit `switchCase` edges (other indirect `br` forms do not emit outgoing edges); external `noreturn` callees are recognized strictly from the `44`-symbol evidence table in [`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json) (with internal wrapper propagation over the call graph).

---

## System Libraries & External Process Boundaries

- **Mach-O Parsing, Disassembly, Inline Assembly, CFG/Xrefs, CodeSign & MCP (`M0`–`M5`):** Executed directly in Swift on mapped binary bytes. No CLI subcommand or MCP tool spawns `otool`, `llvm-objdump`, `nm`, `codesign`, `dyld_info`, `swift-demangle`, or `c++filt` (system tools and Ghidra `analyzeHeadless` are invoked only by external acceptance scripts under `Scripts/acceptance/`).
- **In-Process Symbol Demangling (`demangle` & Symbol Loading):** Calls `swift_demangle` (`libswiftCore.dylib`) and `__cxa_demangle` (`libc++abi.dylib`) in-process on macOS (`0` child processes), keeping the pure-Swift `Swift5ABIDemangler` and `ItaniumCppDemangler` as a fallback.
- **Internal GUI Ghidra Diff Helper:** An internal (non-exported) desktop comparison helper contains the repository's only `Foundation.Process()` call (`support/analyzeHeadless`). Neither `decompile`, `mcp`, nor any exported SwiftPM library product ever invokes it.

---

## Build & Run Verification

```bash
swift build --product MachGraph
swift build -c release --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

Unified test runner (`Scripts/test.sh`). `milestone 0`–`milestone 5` keep temporary logs without dirtying the work tree (`./Scripts/test.sh milestone <N> --record` refreshes `reports/` on a clean worktree), `./Scripts/test.sh mutations` runs the isolated M3, M4, and M5 destructive mutation suites (`9` + `9` + `8` mutations), and `GHIDRA_INSTALL_DIR=<path-to-ghidra> JAVA_HOME=<path-to-jdk21> ./Scripts/test.sh release` runs all `35` release checks (`Scripts/test.sh release --only <step>` runs selected steps; skipped steps exit `77`):

```bash
./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachCFGEngine MachHeadlessCLI
./Scripts/test.sh milestone 0
./Scripts/test.sh milestone 1
./Scripts/test.sh milestone 2
./Scripts/test.sh milestone 3
./Scripts/test.sh milestone 4
./Scripts/test.sh milestone 5
./Scripts/test.sh mutations
```

---

## CLI & MCP Usage Examples

Every command below runs against a real binary or explicit input (omitting `<file>` without `--demo` exits `2`) and is replayed verbatim by [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh):

```bash
# Inspect Mach-O container metadata (including imported dylibs), segments, chained fixups, symbols, and native entitlements
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls
.build/debug/MachGraph codesign /usr/bin/ssh --json

# Demangle Swift and Itanium C++ symbols in-process, inspect ObjC metadata, and dump full-binary xrefs
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

# Query verified MCP tools over stdio JSON-RPC 2.0 (inspect, disasm at /bin/ls LC_MAIN 0x100000960, single-function CFG, symbols, strings)
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/bin/ls"}}}\n' \
  | .build/debug/MachGraph mcp
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_disasm_function","arguments":{"binaryPath":"/bin/ls","address":"0x100000960","count":12}}}\n' \
  | .build/debug/MachGraph mcp
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_cfg","arguments":{"binaryPath":"/bin/ls","address":"0x100000960"}}}\n' \
  | .build/debug/MachGraph mcp
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_list_symbols","arguments":{"binaryPath":"/bin/ls"}}}\n' \
  | .build/debug/MachGraph mcp
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_find_strings","arguments":{"binaryPath":"/bin/ls","filter":"usage"}}}\n' \
  | .build/debug/MachGraph mcp
```

### Language Resolution Order

1. Command-line option: `--lang zh` / `--lang en`
2. Environment variable: `MACHGRAPH_LANG=zh` / `MACHGRAPH_LANG=en`
3. User preference: `UserDefaults` (`io.github.zxu756.MachGraph.language`)
4. System preferred language: Simplified Chinese when `Locale.preferredLanguages.first` starts with `"zh"`, otherwise English

---

## Planned & Experimental / Unverified Items

`M0`–`M5` are verified above. The items below have **not** passed independent differential acceptance, are not exported as public SwiftPM library products, and are excluded from the verified capabilities table:

- **Pseudo-C Decompiler (`decompile` CLI / `mach_decompile_function` MCP — Experimental, Unverified):** Has **not** passed acceptance; condition expressions, loop bounds, and `switch` recovery have known inaccuracies on real binaries. Both entry points emit `[EXPERIMENTAL / UNVERIFIED]` on line 1; rely on `disasm` / `mach_disasm_function` for ground truth. Planned post-`M5`: benchmark against `clang -O0` ground-truth samples and Ghidra `12.1.4`.
- **Security Audit Plugins (`audit-plugins` CLI / `mach_audit_security` MCP — Experimental, Unverified):** Has **not** passed acceptance; heuristic `JavaScriptCore` rules have known false positives and false negatives and emit `# [EXPERIMENTAL / UNVERIFIED]` on line 1. Planned post-`M5`: ground-truth corpus with measured recall and false-positive rates.
- **Binary Patch Engine & Re-Signing (`patch-asm`, `resign` — Planned):** Inline assembly patching and ad-hoc SHA-256 `CodeDirectory` re-signing exist for basic CLI workflows, while end-to-end behavioral patch acceptance suites and broader relocation safety checks are planned post-`M5` (internal target only, not a public library product).
- **Desktop GUI & `.machproj` Project Store (Planned):** Launching `MachGraph` without CLI arguments opens an empty workspace (`Open File...` or explicit `Load Demo (DEMO)`). A verified read-only disassembly + CFG viewer backed by the CLI/library pipeline and `.machproj` persistence checks are planned post-`M5` (no GUI screenshots are included prior to GUI acceptance).
- **Non-Mach-O Containers (`ELF64`, `PE32+`, `WASM` — Planned):** Internal loaders remain `package`-scoped (inaccessible to external SwiftPM consumers, with `ELF` `ET_REL` object files explicitly rejected). Differential verification against `llvm-readelf` and `wasm-objdump` is planned post-`M5`.

---

## License

MIT License. Copyright (c) 2026 Xu (`zxu756`).
