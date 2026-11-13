# MachGraph

**English** | **[简体中文](README.zh-CN.md)**

**Zero-CLI-Wrapper Native Binary Reverse-Engineering IDE, ARM64 SSA Decompiler & Patch Workbench for macOS (Apple Silicon) · `v1.1.0` Bilingual (`中文 / EN`)**

![MachGraph Sugiyama CFG Canvas](docs/screenshot-cfg-canvas.png)

`MachGraph v1.1.0` (`74,303 LOC` of strict Swift 6 across 11 modular libraries + native desktop IDE + 145 automated Swift Testing checks) is a standalone Apple Silicon reverse-engineering workbench built from first principles **without shelling out to `otool`, `objdump`, `nm`, `llvm-mc`, or `c++filt`**. Every container loader, ARM64/ARM64e PAC instruction decoder, two-pass inline mini-assembler, Lengauer-Tarjan dominator & Sugiyama Control-Flow Graph layout solver, Cytron SSA Micro-IR -> structured zero-`goto` Pseudo-C decompiler, sparse Copy-on-Write hex patcher, Mach-O `LC_CODE_SIGNATURE` SHA-256 re-signer, `.machproj` SQLite WAL database, and `JavaScriptCore` security analyzer sandbox runs natively in-process.

### What's New in `v1.1.0`
- **Live In-App Bilingual (`中文 / EN`) Switching**: Instant zero-restart language switching via the Cold-Tungsten **`中文 | EN`** toolbar pill, **`⇧⌘L`** menu command (`Toggle Language / 切换语言`), `⌘,` Preferences language bar, CLI `--lang zh|en`, or `MACHGRAPH_LANG=zh|en` (auto-detecting Simplified Chinese on `zh*` macOS locales).
- **Bilingual Offline HTML Binary Triage Dossier**: Standalone Cold-Tungsten HTML reports (`docs/demo-mach-triage.html`) include an interactive top-right **`中文 | EN`** segmented switch backed by `localStorage` and `navigator.language` auto-detection.
- **2x Retina Bilingual Screenshots (`2720 × 1680`)**: Offscreen Retina export pipeline (`--export-screenshots <dir> --lang zh|en`) with CJK-tuned typography and zero ellipsis truncation across all 7 reverse-engineering studios.

---

## Architecture (`74,303 LOC` Across 11 SwiftPM Modules + Executable + Test Suite)

| Module | LOC | Responsibility |
|---|---:|---|
| `MachBinaryFormats` | `9,200` | Universal Fat/Fat64, Mach-O 64, Dyld Chained Fixups (`ARM64E` PAC + `PTR_64`), Export Trie, Embedded `LC_CODE_SIGNATURE` CMS/DER/CDHash, ObjC 2.0 Runtime & Swift 5 Type Descriptors, ELF64, PE32+, WebAssembly 1.0 |
| `MachMicroDecompiler` | `8,868` | ARM64 -> Micro-IR lifter, Cytron dominance-frontier SSA $\phi$-placement, dead-store & copy propagation, structured `if / else / while / do-while / switch` Pseudo-C emitter (`0` `goto`s) + optional Ghidra 12.1.4 side-by-side bridge |
| `MachA64Decoder` | `8,817` | Handwritten ARMv8-A / ARMv8.3-A (`arm64e` PAC + LSE Atomics + SIMD/FP) decoder, two-pass inline ARM64 mini-assembler, `ADRP+ADD`/`ADRP+LDR` idiom recognizer, and pure-Swift `$s` + Itanium `_Z` + ObjC symbol demangler |
| `MachCFGEngine` | `8,207` | Function boundary & switch jump-table recovery, Lengauer-Tarjan dominator tree & `IDF+` dominance frontiers, natural loop detector, bidirectional Xref & Call Graph SCC index, Brandes-Köpf Sugiyama zero-overlap CFG layout |
| `MachProjectStore` | `7,551` | `.machproj` SQLite3 WAL persistence (`v1..v4` checksummed migrations), dual-indexed Xref queries, persistent Undo/Redo journal across cold restarts, atomic checkpoints, JSON / Ghidra / IDA / C-header / Markdown dossier export |
| `MachStudioViews` | `7,382` | Infinite pan/zoom Sugiyama CFG canvas + minimap radar, synchronized ARM64 <-> Pseudo-C split studio, 16-byte Sparse CoW Hex & Inline ARM64 Patcher, Strings/ObjC/Swift runtime browser, Sliding-Window Entropy & CodeSign studio |
| `MachPatchAndHexEngine` | `6,393` | $O(\log P)$ Sparse Copy-on-Write byte overlay, Horspool masked wildcard search, safety-checked inline ARM64 patcher + veneer stubs, IPS/IPS32/BPS1 patch codecs, Mach-O `CodeDirectory` SHA-256 re-signer, Shannon & $\chi^2$ entropy profiler |
| `MachWorkbenchShell` | `5,592` | Cold Tungsten Steel (`#0F1216`) bilingual (`中文 / EN`) workbench shell, synchronized cross-pane `VirtualAddress` cursor bus, `⌘K` Command Palette, `G` Go-To-Address/Symbol expression parser, `X` Xref jump modal, `⌘,` multi-tab preferences |
| `MachGraphModels` | `3,638` | Zero-copy `BinarySliceReader`, `VirtualAddress`/`FileOffset` arithmetic, ARM64 AST, CFG/Dominator/Loop models, SSA Micro-IR, Pseudo-C AST, Patch & SQLite WAL domain types, `MachLanguage` & `MachLocalizer` |
| `MachPluginSDK` | `2,937` | Capability-gated `JavaScriptCore` reverse-engineering plugin host with 4 built-in security analyzers (Hardcoded Secret/Key Scanner, Dangerous C Sink Auditor, ARM64E PAC Gadget Inspector, Entitlement Privilege Escalation Analyzer) |
| `MachHeadlessCLI` | `1,194` | 15-subcommand headless CLI (`--lang zh|en`), JSON-RPC 2.0 MCP server (`stdio`) for AI coding agents, and Hallmark-clean standalone Cold-Tungsten bilingual HTML triage report exporter |
| `MachGraph` + `MachGraphTests` | `4,524` | Unified desktop/CLI/MCP entry point (`368` LOC) + **145 Swift Testing `@Test` checks across 7 suites** (`4,156` LOC, `~1.0s`, `0` failures) |

---

## 2x Retina Workbench Gallery (`2720 × 1680`)

| Sugiyama CFG, Lengauer-Tarjan Dominators & Minimap | Synchronized ARM64 Disassembly & SSA Pseudo-C Split |
|---|---|
| ![CFG Canvas](docs/screenshot-cfg-canvas.png) | ![Decompiler Split](docs/screenshot-decompiler-split.png) |

| Sparse CoW Hex, Inline ARM64 Assembler & SHA-256 Re-Signer | Sliding-Window Entropy Spectrum, CodeSign & JSC Security Audit |
|---|---|
| ![Hex Patcher](docs/screenshot-hex-patcher.png) | ![Entropy & Audit](docs/screenshot-entropy-audit.png) |

---

## Install & Build

### Homebrew Cask

```bash
brew tap zxu756/tap
brew install --cask zxu756/tap/machgraph
```

### Build From Source

```bash
git clone https://github.com/zxu756/MachGraph.git
cd MachGraph
swift test --no-parallel
./Scripts/build-app.sh
open build/MachGraph.app
```

---

## Headless CLI & MCP Server Usage

```bash
# Launch desktop IDE directly in Simplified Chinese or English (or press Shift+Cmd+L in-app)
MachGraph --lang zh
MACHGRAPH_LANG=en MachGraph

# Inspect Universal / Mach-O 64 / ELF64 / PE32+ / WASM container, segments, Xrefs, and CDHash
MachGraph info --binary /bin/ls

# Disassemble a function with inline ADRP+ADD / PAC / Xref annotations
MachGraph disasm --binary /bin/ls --function _main

# Lift ARM64 machine code into structured zero-goto SSA Pseudo-C
MachGraph decompile --binary /bin/ls --function _main

# Run all 4 built-in JavaScriptCore security audit plugins
MachGraph audit-plugins --binary /bin/ls

# Export a standalone Cold-Tungsten bilingual (中文 | EN) HTML binary triage dossier
MachGraph export-html triage-report.html --binary /bin/ls

# Start JSON-RPC 2.0 MCP Server over stdio for Claude Code / Codex / OpenCode / Antigravity
MachGraph mcp
```

---

## License

MIT License. Copyright (c) 2026 Xu (`zxu756`).
