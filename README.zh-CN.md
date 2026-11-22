# MachGraph

**[English](README.md)** | **简体中文**

> 纯 Swift、不调用任何外部命令的 ARM64/ARM64e 反汇编和 Mach-O 64 解析库。在本机 **`1,278`** 个系统二进制的 **`65,969,684`** 条指令上（`macOS 27.0.1 (26A434) arm64`，`Apple LLVM version 21.0.0`，`2026-11-22` 于干净工作树提交 `fadecfa` 录制，见 [`reports/differential-full-2026-11-22.json`](reports/differential-full-2026-11-22.json)），和 `xcrun llvm-objdump` 的助记符一致率是 **`99.9998%`**（`65,969,542 / 65,969,684`；全部 `65,969,542` 条已识别指令上为 **`100.0000%`**，另有 `8` 个文件共 `142` 个字 `llvm-objdump` 同样输出 `.long`），**没有一条判错（`0` 条）**，操作数一致率 **`100.0000%`**（`65,969,542 / 65,969,542`）。
>
> **一条命令复现全量反汇编对照：** `swift build -c release --product MachGraph && python3 -I Scripts/acceptance/differential.py full --machgraph .build/release/MachGraph`（完整 35 步发版门禁：`GHIDRA_INSTALL_DIR=<ghidra目录> JAVA_HOME=<jdk21目录> ./Scripts/test.sh release`）。

MachGraph 提供三个已通过验收的 SwiftPM 库产品（`MachBinaryFormats`、`MachA64Decoder`、`MachCFGEngine`）、中英双语无头命令行（`--lang zh|en`）以及基于 `stdio` 的 JSON-RPC 2.0 MCP 服务端（`machgraph mcp`）。

### 可复现实测基线（`2026-11-22`，提交 `fadecfa`，`macOS 27.0.1 (26A434) arm64`）

- **`/bin/ls` 与 `/usr/bin/ssh`（`M0`–`M2`，[`reports/m0-quick.txt`](reports/m0-quick.txt)、[`reports/differential-standard.txt`](reports/differential-standard.txt)、[`reports/macho-differential-standard.txt`](reports/macho-differential-standard.txt)）：** `/bin/ls`（`arm64e`）的 `5` 个段、`11` 个节、`3` 个依赖库与 `113` 条链式修正与 `otool -arch arm64e -l` 逐项一致；在助记符归一规则为 `0` 条（[`Scripts/acceptance/mnemonic_normalization.py`](Scripts/acceptance/mnemonic_normalization.py)）、参考侧操作数规则 `O1`–`O4` 共 `4` 条（[`Scripts/acceptance/operand_normalization.py`](Scripts/acceptance/operand_normalization.py)）下，全部 `3,846` 条指令助记符与操作数一致率均为 **`3,846 / 3,846`（`100.00%`）**（判错 `0` 条、`.inst` `0` 条）。`/usr/bin/ssh`（`arm64e`）仅对带指令属性的节解码出 **`115,546`** 条指令（`__TEXT,__info_plist` 等非指令节输出 `0` 行）；`standard` 三文件（`ls`、`ssh`、`vim`）共 **`707,444 / 707,444`（`100.0000%`）** 助记符与操作数一致（判错 `0`、未识别 `0`；`ssh` `1` 个字、`vim` `102` 个字为 `mg_only_inst`）。
- **全量反汇编、容器解析与内联汇编（`M1`–`M2`，[`reports/differential-full-2026-11-22.json`](reports/differential-full-2026-11-22.json)、[`reports/macho-differential-full-2026-11-22.json`](reports/macho-differential-full-2026-11-22.json)、[`reports/encoding-table-check.txt`](reports/encoding-table-check.txt)、[`reports/encoding-fuzz-20261117.txt`](reports/encoding-fuzz-20261117.txt)、[`reports/encoding-fuzz-17.txt`](reports/encoding-fuzz-17.txt)、[`reports/asm-clang-standard.txt`](reports/asm-clang-standard.txt)、[`reports/asm-roundtrip-standard.txt`](reports/asm-roundtrip-standard.txt)、[`reports/asm-clang-cases.txt`](reports/asm-clang-cases.txt)、[`reports/known-mnemonics-check.txt`](reports/known-mnemonics-check.txt)）：** 在 `/bin`、`/usr/bin`、`/usr/sbin`、`/usr/libexec` 发现的 `1,281` 个候选 Mach-O 中比较全部 **`1,278`** 个含 ARM64 切片的文件（跳过无 `arm64`/`arm64e` 切片 `3` 个；`arm64e` `1,275` 个、`arm64` `3` 个；崩溃 `0` 个）：Mach-O 容器对照核验 `6,176` 个段、`21,558` 个节、`11,516` 个依赖库、`1,903,277` 条链式修正与 `1,278` 个签名文件（差异 `0`）；反汇编助记符一致 `65,969,542 / 65,969,684`（`99.9998%`）、操作数一致 `65,969,542 / 65,969,542`（`100.0000%`，判错 `0`、未识别 `0`）；`56` 张编码表 `0` 不符；两组 `100,000` 随机字差分测试判错均为 `0`、操作数一致率 `100.0000%`（`seed=20261117`：一致 `31,180`、同未识别 `68,456`、未覆盖 `364`；`seed=17`：一致 `31,086`、同未识别 `68,574`、未覆盖 `340`）；`asm-clang.py standard` 共 `912` 种形态中 **`911`** 种经 `clang` 汇编还原原机器码（`adrp` 跳过 `1` 种）；`asm-roundtrip.py standard`（解码 `707,444` 条）在 `M2` 前 `699,038` 条（`814` 种形态）上全部 `ok`，新解码 `8,406` 条中 `ok` `6,667` 条、`unsupported` `1,739` 条（`mismatch` `0`、`error` `0`）；`Fixtures/asm-cases.s`（`71` 例）`35` 匹配、`35` 不支持、`1` 条 `adrp` 无法对照（失败 `0`）；`A64KnownMnemonics.swift`（`727` 个助记符、`13,184` 字节）逐字节一致。
- **全量元数据与符号解混淆（`M3`，[`reports/m3-metadata-full-2026-11-22.json`](reports/m3-metadata-full-2026-11-22.json)、[`reports/m3-metadata-full-2026-11-22.txt`](reports/m3-metadata-full-2026-11-22.txt)、[`reports/m3-metadata-objc.txt`](reports/m3-metadata-objc.txt)）：** 在同一批 **`1,278`** 个文件上（崩溃 `0` 个，**六项检查合计 `0` 差异**）：已定义符号 **`114,513 / 114,513`** 条（对照 `nm --no-dyldinfo`）、依赖库与安装 ID **`11,516 / 11,516`** 条（对照 `otool -L`）、entitlements 顶层键 **`8,152 / 8,152`** 个（`513` 个带权限文件 + `765` 个空 `{}`，对照 `codesign -a <slice> -d --entitlements :-`）、解混淆四桶唯一符号 **`117,076 / 117,076`** 个（Swift `28,982` 个对照 `swift-demangle -compact`、C++ `12,611` 个对照 `c++filt`、单 `_Z` 普通 C 符号 `105` 个原样保留、其余符号 `75,378` 个原样保留；错误 `0` 条）、`CALL`（`bl`）交叉引用边 **`7,498,057 / 7,498,057`** 条（全语料 `18,496,618` 条交叉引用中非字符串节 `STRING_REF` 为 `0` 条，含 `STRING_REF` `1,752,712` 条、`CODE_REF` `308,955` 条）、Objective-C 元数据项 **`155,495 / 155,495`** 条（`objc` 四文件语料 `2,773 / 2,773` 条：`Calculator` `62`、`assetutil` `2,378`、`screencapture` `42`、`log` `291`）。
- **控制流图验证（`M4`，[`reports/m4-cfg-acceptance.json`](reports/m4-cfg-acceptance.json)、[`reports/m4-cfg-acceptance-full-2026-11-22.json`](reports/m4-cfg-acceptance-full-2026-11-22.json)、[`reports/m4-cfg-acceptance-known-c.json`](reports/m4-cfg-acceptance-known-c.json)、[`reports/m4-cfg-acceptance-perf.json`](reports/m4-cfg-acceptance-perf.json)、[`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)）：** 在 `standard`（`3 / 3` 文件，`7,770` 个 `LC_FUNCTION_STARTS`、`8,408` 个函数、`150,147` 个块、`220,315` 条边、`6,193` 个自然循环、`1,080 / 1,080` 处不返回调用）与固定种子 `full` 抽样（`40 / 40` 文件，`seed=20261121`，`21,945` 个 `LC_FUNCTION_STARTS`、`31,981` 个函数、`258,906` 个块、`339,379` 条边、`9,274` 个自然循环、`4,035 / 4,035` 处不返回调用）上，函数起点对账与四条不变量 `I1`–`I4`、支配树、自然循环均为 **`0` 违反**；`clang -O0` 已知答案 C 函数 **`8 / 8`** 通过；`/bin/ls` 对照 Ghidra `12.1.4` **属于 MachGraph 的错误 `0` 条**（`4` 条工具差异已归类，耗时 `8.89` 秒）；`perf` 三次运行中位数为 `ssh` 全文件 **`0.3196` 秒**、`vim` 全文件 **`1.711` 秒**、`ssh --symbol _entry` 单函数 **`0.1962` 秒**（负载 `4.24 5.96 5.70` -> `3.82 5.81 5.65`）。
- **MCP 服务端与 SwiftPM 库发布（`M5`，[`reports/m5-mcp-protocol.json`](reports/m5-mcp-protocol.json)、[`reports/m5-mcp-tools.json`](reports/m5-mcp-tools.json)、[`reports/m5-mcp-legacy.json`](reports/m5-mcp-legacy.json)、[`reports/m5-mcp-perf.json`](reports/m5-mcp-perf.json)、[`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)、[`reports/MachGraph-M5.md`](reports/MachGraph-M5.md)）：** MCP `protocol`（`8` 个工具，`0` 差异）、`tools`（**`14 / 14`** 组用例与命令行 `--json` 逐字节相等，含 `/bin/ls` `LC_MAIN` 入口 `0x100000960` 与 `/usr/bin/ssh` 入口 `0x100017898`）、`legacy`（`0` 差异，含 `0x10000073c` 双向交叉引用与中英双语 `【实验性・未通过验收】` 首行标记）、`perf` 三次中位数（`ssh`：`mach_list_symbols` `0.0334` 秒、`mach_find_strings` `0.0225` 秒、`mach_cfg` `0.1947` 秒、`mach_disasm_function` `0.2369` 秒；`vim`：`mach_list_symbols` `0.0942` 秒、`mach_find_strings` `0.0513` 秒、`mach_cfg` `0.8729` 秒、`mach_disasm_function` `0.8736` 秒）、外部空包编译运行三段示例 **`3 / 3`**（各 `14`、`16`、`16` 行，`0` 警告）+ **`14 / 14`** 项负向访问级别/移除产品探针按预期拒绝编译、`Scripts/acceptance/m5-mutations.sh` **`8 / 8`** 条变异全部抓获、`Scripts/test.sh release` 全部 **`35 / 35`** 步通过。

---

## 已通过验收的能力（`M0`–`M5`）

下表只列已通过独立参考答案对照验收的能力；未通过验收和后续路线图事项见下方「计划中与实验性/未通过验收项」。

| 领域 | 入口 | 已验证范围与独立对照物 |
|---|---|---|
| **ARM64 / ARM64e 反汇编与内联汇编（`M1`、`M2`）** | 命令行：`disasm`、`asm` | 仅反汇编带 `S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS` 指令属性的节（支持 `--symbol` / `--function`、`--address`、`--count`、`--slice`、`--json`），并在 `--at` 起将 ARM64 语句汇编为机器字而不读写磁盘文件（`asm`，退出码 `0` 全部成功、`3` 存在合法但暂不支持写法、`1` 语句错误）。已对照 `xcrun llvm-objdump`（`1,278` 个文件、`65,969,684` 条指令，`0` 判错、`100.0000%` 操作数一致）与 `xcrun clang`（`standard` `911 / 912` 种形态、`56` 张编码表、`2 x 100,000` 随机字）。 |
| **Mach-O 64 元数据与符号解混淆（`M0`、`M1`、`M3`）** | 命令行：`info`、`segments`、`fixups`、`symbols`、`demangle`、`objc`、`strings`、`codesign`、`xrefs` | 解析 Fat/Fat64 切片、`mach_header_64`、段节、`LC_UUID`、`LC_MAIN`、`LC_ID_DYLIB`、`LC_FUNCTION_STARTS`、带 `X.Y.Z` 版本号的有序动态库依赖、`LC_DYLD_CHAINED_FIXUPS`、不去重同地址别名的 `LC_SYMTAB` 符号表（`symbols`）、进程内 `swift_demangle` 与 `__cxa_demangle` 解混淆（`demangle`）、Objective-C 类/方法/成员变量/分类/协议（`objc`）、UTF-8/UTF-16 字符串（`strings`）、SHA-256 `CodeDirectory` 与原生类型 XML/DER entitlements（`codesign`）以及分类型交叉引用（`xrefs`）。已在 `1,278` 个文件上对照 `otool`、`nm`、`codesign`、`swift-demangle`、`c++filt` 与 `llvm-objdump` 取得 `0` 差异。 |
| **控制流图、支配树与自然循环（`M4`）** | 命令行：`cfg`、`cfg-dot` | 恢复全文件或单函数结构化控制流图（`schema: "machgraph.cfg/1"`）、可执行节内联跳转表（`cmp + b.hi` 与无分支 `cmp + csel`）、Lengauer–Tarjan 支配树与支配边界、带嵌套深度的自然循环及 `44` 个有依据的不返回符号（[`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json)），并支持 Graphviz DOT 导出（`cfg-dot`）。已对照独立 Python ARM64/数据流求解器（`standard` `8,408` 函数与 `full` `31,981` 函数，`I1`–`I4` `0` 违反）、`8 / 8` 个 `clang -O0` C 函数及 `/bin/ls` 上的 Ghidra `12.1.4`（MachGraph 错误 `0` 条）。 |
| **MCP 服务端 —— 6 个已验收工具（`M5`）** | 命令行：`mcp`（`stdio` JSON-RPC 2.0） | 已验收工具：`mach_inspect_binary`、`mach_list_symbols`、`mach_find_strings`、`mach_disasm_function`、`mach_cfg`、`mach_query_xrefs`。全部直接调用 `MachCLIRunner` 的同一套实现（`mach_list_symbols`、`mach_find_strings`、`mach_disasm_function`、`mach_cfg` 与命令行 `--json` 逐字节相等；`mach_cfg` 必传 `symbol` 或 `address`；`mach_query_xrefs` 同时返回传入 `<-` 与传出 `->` 引用）。`mach_decompile_function` 与 `mach_audit_security` 仅作为**实验性、未通过验收**工具保留，第 1 行固定输出未验收警告。 |
| **SwiftPM 库产品 —— 3 个已验收模块（`M5`）** | 库产品：`MachBinaryFormats`、`MachA64Decoder`、`MachCFGEngine` | 面向外部 Swift 6 项目的 Mach-O/Universal 解析与签名库（`MachBinaryFormats`）、ARM64 解码/微型汇编与解混淆库（`MachA64Decoder`）及控制流图/支配树/循环/交叉引用库（`MachCFGEngine`），均通过 `@_exported import MachGraphModels` 自动重导出基础模型。已在独立外部空包中编译运行验证（`3 / 3` 段示例 `0` 警告通过并与系统工具一致；`14 / 14` 项已收紧为 `internal`/`package` 的符号及移除的未验收产品均在编译期被拒绝）。 |

---

## MCP 服务端（`M5`）

`machgraph mcp` 在标准输入输出上提供 JSON-RPC 2.0 服务（`protocolVersion: "2024-11-05"`）。除命令行已预设默认二进制外，每次调用均须显式传入 `binaryPath`，并与命令行子命令共用同一内部实现：

| 工具名 | 参数（**粗体**为必填） | 对应命令行子命令与输出契约 |
|---|---|---|
| `mach_inspect_binary` | **`binaryPath`**、`slice` | 与 `machgraph info <file> [--slice <n>]` 共用 `buildBinaryInfoSnapshot` + `formatBinaryInfo`（返回容器格式、段、符号、修正链与 `cdhash` 紧凑摘要）。 |
| `mach_list_symbols` | **`binaryPath`**、`filter`、`slice` | 与 `machgraph symbols <file> [--filter <q>] [--slice <n>] --json` 逐字节相同（走仅加载容器快路径，不建全表 CFG）。 |
| `mach_find_strings` | **`binaryPath`**、`filter`、`slice` | 与 `machgraph strings <file> [--filter <q>] [--slice <n>] --json` 逐字节相同（走仅加载容器快路径）。 |
| `mach_disasm_function` | **`binaryPath`**、`symbol`（或 `function`）\| `address` *（互斥）*、`count`、`slice` | 与 `machgraph disasm <file> [--symbol <名称> \| --address <0x...>] [--count <n>] [--slice <n>] --json` 逐字节相同。 |
| `mach_cfg` | **`binaryPath`**，以及 **`symbol`（或 `function`）或 `address` 二选一必传** *（互斥）*、`slice` | 与单函数 `machgraph cfg <file> (--symbol <名称> \| --address <0x...>) [--slice <n>] --json` 逐字节相同。**`mach_cfg` 必须传 `symbol` 或 `address`**（省略目标返回 `isError: true`；全文件 CFG 导出只留在命令行）。 |
| `mach_query_xrefs` | **`binaryPath`**、**`address`**、`slice` | 与 `machgraph xrefs <file> --address <0x...> [--slice <n>]` 共用 `formatTargetXrefs`，同时返回传入（`<-`）与传出（`->`）交叉引用。 |
| `mach_decompile_function` | **`binaryPath`**、**`function`**、`slice` | **实验性、未通过验收：** 与 `machgraph decompile <file> (--symbol <名称> \| --address <0x...>) [--slice <n>]` 输出一致，第 1 行固定标明 `// 【实验性】【未通过验收】...`（中文）或 `// EXPERIMENTAL: [EXPERIMENTAL / UNVERIFIED] ...`（英文）。 |
| `mach_audit_security` | **`binaryPath`**、`slice` | **实验性、未通过验收：** 与 `machgraph audit-plugins <file> [--slice <n>]` 输出一致，第 1 行固定标明 `# 【实验性・未通过验收】...`（中文）或 `# [EXPERIMENTAL / UNVERIFIED] ...`（英文）。 |

---

## SwiftPM 库接口与示例（`M5`）

### 依赖配置与三个库产品

在外部项目的 `Package.swift` 中通过本地路径（`.package(path:)`）或仓库地址（`.package(url:from:)`）引入 `MachGraph`，按需依赖三个已验收产品 —— **`MachBinaryFormats`**、**`MachA64Decoder`**、**`MachCFGEngine`**（三者均已通过 `@_exported import MachGraphModels` 重导出模型类型，调用方无需再单独导入 `MachGraphModels`）：

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MyBinaryTool",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../MachGraph")
        // 或: .package(url: "https://github.com/zxu756/MachGraph.git", from: "1.4.0")
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

（`Package.swift` 同时保留底层 `MachGraphModels`、`MachHeadlessCLI` 与可执行目标 `MachGraph`；其余尚未通过验收的内部模块均不作为对外 SwiftPM 库产品导出。）

下方三段 `20` 行以内的 Swift 示例由 [`Scripts/acceptance/m5-lib-examples.py`](Scripts/acceptance/m5-lib-examples.py) 直接从 `README.md` 与 `README.zh-CN.md` 实时提取，在新建临时空包中以 `0` 警告编译运行，并与系统参考工具逐项核对（记录于 [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)）。

### 1. `MachBinaryFormats` —— 读取 Mach-O 头、段表与代码签名

加载 `/bin/ls`（自动从 Universal Fat 胖二进制中选择首选 `arm64e` 切片），读取其 Mach-O 容器头、段列表、`LC_FUNCTION_STARTS` 数量及 SHA-256 `CodeDirectory` 哈希：

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

期望输出（`macOS 27.0.1 (26A434) arm64` `/bin/ls`；对照 `xcrun otool -l`、`llvm-objdump --macho --function-starts` 与 `codesign -dvvv` 独立核验，见 [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)）：

```text
format=Mach-O Universal Fat arch=arm64e (PAC)
entry=0x0000000100000960 segments=5 [__PAGEZERO,__TEXT,__DATA_CONST,__DATA,__LINKEDIT]
lcFunctionStarts=50
signed=true cdhash=54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce
```

### 2. `MachA64Decoder` —— 汇编与解码 A64 指令

在基址 `0x100000000` 处汇编四条 A64 栈帧开场/尾声指令，再将原始指令字节流解码为结构化 `A64DecodedInstruction` 序列：

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

期望输出（对照 `xcrun clang -arch arm64` 与 `xcrun llvm-objdump -d` 独立核验，见 [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)）：

```text
0x0000000100000000  d10043ff  sub sp, sp, #0x10
0x0000000100000004  52800540  mov w0, #0x2a
0x0000000100000008  910043ff  add sp, sp, #0x10
0x000000010000000c  d65f03c0  ret
```

### 3. `MachCFGEngine` —— 为单个函数构建控制流图（CFG）

调用单函数快路径 `analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`，为 `/bin/ls` 的 `LC_MAIN` 入口函数（`0x100000960`）恢复基本块、控制流边、Lengauer–Tarjan 支配树与自然循环：

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

期望输出（`macOS 27.0.1 (26A434) arm64` `/bin/ls`；根据 `LC_MAIN`、`LC_FUNCTION_STARTS`、`otool -Iv`、`llvm-objdump -d` 及独立支配树/循环求解器核验，见 [`reports/m5-lib-examples.json`](reports/m5-lib-examples.json)）：

```text
functions=133 entry=_entry@0x0000000100000960
blocks=154 edges=259 dom=154 loops=1
```

---

## 控制流图（`M4`）

- **结构（`"schema": "machgraph.cfg/1"`）：** `machgraph cfg <binary> --json` 按起始地址升序输出全文件所有恢复函数；`machgraph cfg <binary> --symbol <名字> --json`（或 `--function <名字>`、`--address <0x...>`、`--slice <序号>`）仅构建匹配的单函数（`cfg-dot` 导出 Graphviz DOT）。顶层包含 `lcFunctionStarts`、`inlineJumpTableStarts`、`inlineJumpTableRanges`、`functionCount` 与 `functions[]`（含 `blocks[]`、`edges[]`、`dominatorTree[]`、`naturalLoops[]`、`jumpTables[]`、`inlineJumpTableRanges[]`）。
- **边界与已知限制：** 仅支持 `ARM64` / `ARM64e` Mach-O 切片；间接跳转仅解析内联/PC 相对 switch 跳转表并生成 `switchCase` 边（其余间接 `br` 形式不连后继边）；外部不返回函数只认 [`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json) 中的 `44` 个名字（内部包装函数沿调用图可达性传播）。

---

## 系统库与外部进程边界说明

- **Mach-O 解析、反汇编、内联汇编、CFG/交叉引用、代码签名与 MCP（`M0`–`M5`）：** 全部由 Swift 直接读取二进制字节在进程内完成；所有命令行子命令与 `mcp` 工具均**不启动** `otool`、`llvm-objdump`、`nm`、`codesign`、`dyld_info`、`swift-demangle` 或 `c++filt` 等外部子进程（上述工具与 Ghidra `analyzeHeadless` 仅在 `Scripts/acceptance/` 验收脚本中作为独立对照物调用）。
- **进程内符号解混淆（`demangle` 与符号表加载）：** 在 macOS 本进程内直接链接调用系统 `libswiftCore.dylib` 的 `swift_demangle` 与 `libc++abi.dylib` 的 `__cxa_demangle`（`0` 个外部子进程），仓库内的纯 Swift `Swift5ABIDemangler` 与 `ItaniumCppDemangler` 保留作回退。
- **内部桌面端 Ghidra 对照辅助逻辑：** 未对外导出的内部模块中含有全仓唯一一处 `Foundation.Process()`（调用 `support/analyzeHeadless`），命令行 `decompile`、`mcp` 以及全部对外导出的 SwiftPM 库产品均**从不调用**它。

---

## 编译与运行验收脚本

```bash
swift build --product MachGraph
swift build -c release --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

统一测试入口（`Scripts/test.sh`）。`milestone 0`–`milestone 5` 将日志写入临时目录而不改动工作树（在干净工作树上传 `./Scripts/test.sh milestone <N> --record` 可刷新 `reports/`），`./Scripts/test.sh mutations` 在隔离临时副本中依次执行 M3、M4、M5 破坏性变异套件（`9` + `9` + `8` 条变异），`GHIDRA_INSTALL_DIR=<ghidra目录> JAVA_HOME=<jdk21目录> ./Scripts/test.sh release` 运行全部 `35` 步发版门禁（可用 `Scripts/test.sh release --only <step>` 选择步骤；任一步跳过时以 `77` 非零退出）：

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

## 命令行与 MCP 示例

以下每条命令均直接作用于真实二进制文件或显式输入（未传 `<文件>` 且未指定 `--demo` 时退出码为 `2`），并在 [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh) 中逐条原样回放验证：

```bash
# 查看容器摘要（含动态库依赖）、段节映射、dyld 链式修正、符号表与原生类型 entitlements
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls
.build/debug/MachGraph codesign /usr/bin/ssh --json

# 在进程内解混淆 Swift 与 Itanium C++ 符号、查看 ObjC 元数据并导出全表交叉引用
.build/debug/MachGraph demangle '_$sSiN' __Z3fooi _ZeroFilesTested --json
printf '_$sSiN\n__Z12set_darkbooti.cold.1\n_main\n' | .build/debug/MachGraph demangle
.build/debug/MachGraph objc /System/Applications/Calculator.app/Contents/MacOS/Calculator --json
.build/debug/MachGraph xrefs /bin/ls --json

# 从 LC_MAIN 入口符号反汇编 /bin/ls，或按地址反汇编仓库内的真实编译样本
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10

# 为 /bin/ls 导出全文件与单函数结构化控制流图（schema machgraph.cfg/1）及 Graphviz DOT
.build/debug/MachGraph cfg /bin/ls --json
.build/debug/MachGraph cfg /bin/ls --symbol _entry --json
.build/debug/MachGraph cfg-dot /bin/ls --symbol _entry

# 将分号分隔的 4 条 ARM64 指令汇编写入样本副本并执行 SHA-256 临时重签名
cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample
.build/debug/MachGraph patch-asm /tmp/machgraph_readme_sample \
  --address 0x100000460 \
  --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" \
  --force \
  --output /tmp/machgraph_readme_patched \
  --json
rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched

# 只汇编、不写文件；退出码 0 全部成功，3 表示有合法 A64 写法汇编器还不支持，1 表示有写错的语句
.build/debug/MachGraph asm --at 0x100000460 --asm "stp x29, x30, [sp, #-16]!; mov x0, #42; b .+8" --json

# 为 /bin/ls 导出单文件离线中英双语（中文 | EN）HTML 二进制分诊报告
.build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html
rm -f /tmp/machgraph_ls_triage.html

# 简体中文命令行输出（--lang zh|en）与显式 [演示数据] 样本模式（--demo）
.build/debug/MachGraph --help --lang zh
.build/debug/MachGraph info --demo --lang zh

# 通过 stdio JSON-RPC 2.0 调用已验收的 MCP 工具（容器检视、/bin/ls 入口 0x100000960 反汇编、单函数 CFG、符号与字符串）
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

### 语言解析优先级

1. 命令行选项：`--lang zh` / `--lang en`
2. 环境变量：`MACHGRAPH_LANG=zh` / `MACHGRAPH_LANG=en`
3. 用户偏好：`UserDefaults`（`io.github.zxu756.MachGraph.language`）
4. 系统首选语言：`Locale.preferredLanguages.first` 以 `"zh"` 开头时用简体中文，否则用英文

---

## 计划中与实验性/未通过验收项

`M0`–`M5` 已在上方完成验收。以下事项**尚未**完成独立参考工具对照验收，不作为对外 SwiftPM 库产品导出，也不列入上方已验证能力表：

- **伪 C 反编译器（`decompile` 命令行 / `mach_decompile_function` MCP —— 实验性、未通过验收）：** 尚未通过验收，条件表达式、循环上下界与 `switch` 多路分支在真实二进制上已知存在还原错误；两个入口第 1 行均显式输出 `【实验性】【未通过验收】` 警告，分析请以 `disasm` / `mach_disasm_function` 为准。计划在 `M5` 之后对照 `clang -O0` 标准样本与 Ghidra `12.1.4` 验收。
- **安全审计插件（`audit-plugins` 命令行 / `mach_audit_security` MCP —— 实验性、未通过验收）：** 尚未通过验收，基于启发式规则的 `JavaScriptCore` 插件已知存在误报与漏报，第 1 行固定输出 `# 【实验性・未通过验收】` 警告。计划在 `M5` 之后建立带标准答案的样本集并标定检出率与误报率。
- **补丁引擎与重签名（`patch-asm`、`resign` —— 计划中）：** 仓库内具备基础内联汇编写入与 SHA-256 `CodeDirectory` 临时重签名功能，完整端到端行为改动验收脚本与重定位安全覆盖计划排在 `M5` 之后（内部模块不作为对外库产品暴露）。
- **桌面图形界面与 `.machproj` 工程存储（计划中）：** 无参启动默认打开空工作台（仅提供「打开文件...」与带 `演示数据` 标记的显式演示加载）。只读反汇编 + 控制流图查看器（复用命令行同一套接口）与 `.machproj` 工程库验收排在 `M5` 之后；界面通过验收前不放截图。
- **非 Mach-O 容器格式（`ELF64`、`PE32+`、`WASM` —— 计划中）：** 内部加载器已收紧为 `package` 作用域（外部 SwiftPM 包不可访问，且 `ELF` `ET_REL` 可重定位目标文件显式报错拒绝）。计划在 `M5` 之后逐格式对照 `llvm-readelf`、`wasm-objdump` 验收后再开放。

---

## 开源许可

MIT License. Copyright (c) 2026 Xu (`zxu756`).
