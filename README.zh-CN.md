# MachGraph

**[English](README.md)** | **简体中文**

纯 Swift 实现的 macOS (`arm64`) ARM64/ARM64e 反汇编器、内联微型汇编器与 Universal/Mach-O 64 二进制解析工具，内置中英双语命令行（`--lang zh|en`）与 stdio JSON-RPC 2.0 MCP 服务端。

> **可复现基线（`2026-11-14`，`macOS 27.0.1 (26A434) arm64`，原始记录见 [`reports/m0-quick.txt`](reports/m0-quick.txt)）：**
> Mach-O 容器解析、dyld 链式修正、内嵌代码签名哈希计算与 ARM64 指令解码均由纯 Swift 在进程内完成，默认分析路径不调用 `otool`、`llvm-objdump`、`nm` 或 `codesign` 等外部命令。
> - **`/bin/ls`（`arm64e` 切片）：** `5` 个段（segment）与 `11` 个节（section）的名称、虚拟地址、大小与文件偏移与 `otool -arch arm64e -l /bin/ls` 逐项完全一致；`__TEXT,__text` 全部 `3,846` 条指令与 `xcrun llvm-objdump -d --no-show-raw-insn --arch=arm64e` 对照，**助记符归一之后**的一致数为 **`3,845 / 3,846`（`99.97%`）**，**判错 `0` 条**，未识别指令 `1` 条（输出 `.inst`）。归一只有三条规则，由 [`Scripts/acceptance/mnemonic-agreement.py`](Scripts/acceptance/mnemonic-agreement.py) 执行：`movz`/`movn` 算作 `mov`，`udf` 算作 `.inst`，参考助记符上的向量排列后缀去掉。不比较操作数。
> - **`/usr/bin/ssh`（`arm64e` 切片）：** 仅对带指令属性的节（`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`）解码出 **`115,546` 条指令**，非指令数据节（如 `__TEXT,__info_plist`）输出为 **`0` 行**。
> - **在本机复现：** 运行 `./Scripts/test.sh milestone 0`（或 `./Scripts/acceptance/m0-quick.sh`）。跨系统二进制大语料（`standard` / `full`）的自动化对照脚本排在里程碑 `M1`。

---

## 已通过 `M0` 验收的能力

| 领域 | 子命令 | `M0` 已验证范围 |
|---|---|---|
| **Universal 与 Mach-O 64 容器解析** | `info`、`segments` | 解析 Fat/Fat64 多架构切片、`mach_header_64`、`LC_SEGMENT_64` 段与节、`LC_UUID`、`LC_BUILD_VERSION`、`LC_MAIN` 与动态库依赖（支持文本与 `--json`）；对空文件、纯文本、截断的 Mach-O 文件以及暂不支持的 ELF `ET_REL` 可重定位目标文件均以非零退出码报错退出。 |
| **链式修正、符号、字符串与代码签名** | `fixups`、`symbols`、`strings`、`codesign`、`entropy` | 解析 `LC_DYLD_CHAINED_FIXUPS` 绑定与重定位记录（`fixups`），将 `LC_SYMTAB` 符号与 `[inferred:...]` 推导入口/桩符号显式区分并标注来源（`symbols`），扫描可打印字符串（`strings`），输出整个文件的一个香农熵数值，以及字节卡方值、零字节占比、1024 字节滑动窗口的个数与异常数（`entropy`；不输出各节的熵），并校验内嵌 `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory` 与 CDHash（`codesign`）。 |
| **ARM64 / ARM64e 反汇编与交叉引用** | `disasm`、`xrefs`、`cfg-dot` | 仅反汇编带 `S_ATTR_PURE_INSTRUCTIONS` 或 `S_ATTR_SOME_INSTRUCTIONS` 属性的节；支持 `--symbol` / `--function`、`--address` 与 `--count` 过滤，查询调用/跳转/数据交叉引用（`xrefs`），导出 Graphviz DOT 控制流图（`cfg-dot`）。目标函数或地址不存在时以退出码 `1` 报错且 `stdout` 不输出任何指令。 |
| **内联 ARM64 微型汇编与临时重签名** | `patch-asm`、`resign` | 支持分号分隔的多条 ARM64 汇编语句（如 `pacibsp; stp ...; mov ...; retab`）逐条编码写入副本，并重算 Mach-O `LC_CODE_SIGNATURE` SHA-256 页哈希完成临时重签名。`;` 只是语句分隔符（注释用 `//`）：只要有一条语句汇编不了，`patch-asm` 就以非零退出码报错，不写出文件。补丁内部盖住跳转目标、函数起点、符号或 PAC/BTI 落点时默认拒绝写入，加 `--force` 可跳过这项安全检查。 |
| **中英双语命令行、HTML 报告与 MCP 服务端** | `export-html`、`mcp` | 支持 `--lang zh|en` 与 `MACHGRAPH_LANG=zh|en`（简体中文环境自动默认中文），导出单文件离线双语（`中文 \| EN`）HTML 分诊报告（`export-html`），并提供基于 `stdio` 的 JSON-RPC 2.0 MCP 服务端（`mcp`，所有工具调用均要求显式传入 `binaryPath`）。 |

---

## 编译与运行验收脚本

```bash
swift build --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

统一测试入口（`Scripts/test.sh`）。`milestone 0` 把日志写到临时目录，不改动工作区；要更新仓库里 `reports/` 下的记录，用 `./Scripts/test.sh milestone 0 --record`：

```bash
./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachHeadlessCLI
./Scripts/test.sh milestone 0
```

---

## 命令行与 MCP 示例

以下每条命令均直接作用于真实二进制文件（无隐藏演示回退；未传 `<文件>` 且未显式指定 `--demo` 时退出码为 `2`），并在 [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh) 中逐条原样回放验证：

```bash
# 查看 /bin/ls 的容器摘要、段节映射、dyld 链式修正、符号表与代码签名（文本与 JSON）
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls

# 从 LC_MAIN 入口符号反汇编 /bin/ls，或按地址反汇编仓库内的真实编译样本
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10

# 将分号分隔的 4 条 ARM64 指令汇编写入样本副本并执行 SHA-256 临时重签名
cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample
.build/debug/MachGraph patch-asm /tmp/machgraph_readme_sample \
  --address 0x100000460 \
  --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" \
  --force \
  --output /tmp/machgraph_readme_patched \
  --json
rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched

# 为 /bin/ls 导出单文件离线中英双语（中文 | EN）HTML 二进制分诊报告
.build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html
rm -f /tmp/machgraph_ls_triage.html

# 简体中文命令行输出（--lang zh|en）与显式 [演示数据] 样本模式（--demo）
.build/debug/MachGraph --help --lang zh
.build/debug/MachGraph info --demo --lang zh

# 通过 stdio JSON-RPC 2.0 调用 MCP 服务端（必须显式提供 binaryPath）
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/bin/ls"}}}\n' \
  | .build/debug/MachGraph mcp
```

### 语言解析优先级
`MachGraph` 按以下固定顺序确定输出语言：
1. 命令行选项：`--lang zh` / `--lang en`
2. 环境变量：`MACHGRAPH_LANG=zh` / `MACHGRAPH_LANG=en`
3. 用户偏好：`UserDefaults`（`io.github.zxu756.MachGraph.language`）
4. 系统首选语言：`Locale.preferredLanguages.first` 以 `"zh"` 开头时用简体中文，否则用英文

---

## 后续里程碑计划与实验性/冻结模块说明

以下路线图事项及仓库内既有模块**尚未**完成独立参考工具对照验收，不计入上方已验证能力表：

- **M1 — 语料对照测试进仓库：** 新增 `Scripts/acceptance/differential.py` 与 `macho-differential.py`，覆盖 `quick`（`/bin/ls`）、`standard`（`ls`、`ssh`、`vim`）与 `full`（`/bin`、`/usr/bin`、`/usr/sbin`、`/usr/libexec`）三档系统二进制语料。
- **M2 — SIMD 整数向量指令补齐与操作数对照：** 补齐当前输出为 `.inst` 的 AdvSIMD 整数向量指令族，统一 `mov` 系列首选别名，并加入操作数级对照与解码->汇编回环验证。
- **M3 — 元数据与符号解混淆对照：** `symbols --json` 与 `nm -arch arm64e` 完整集合对齐（含未定义外部导入符号 `U`）、Swift `$s`（对照 `swift-demangle`）与 C++ `_Z`（对照 `c++filt`）解混淆基准、ObjC 元数据（对照 `otool -ov`）及 entitlements 键值对照。
- **M4 — 控制流图不变量与性能：** 基本块划分不变量校验、与 Ghidra 基本块边界对比，以及 `ssh` / `vim` 全量建图性能剖析与优化。
- **M5 — MCP 工具补齐与 SwiftPM 库接口：** 为 `mcp` 增补 `mach_disasm_function`、`mach_list_symbols`、`mach_cfg`、`mach_find_strings`，并提供可独立编译运行的 SwiftPM 库调用示例。
- **实验性及 M5 前冻结模块：**
  - **伪 C 反编译器（`decompile` / `MachMicroDecompiler`）：** **实验性功能**——条件表达式、循环上下界与 `switch` 多路分支还原在真实二进制上已知不可靠。`decompile` 输出第 1 行固定打印警告（`// 【实验性】反编译输出：已知条件表达式还原不可靠，请以反汇编为准。`），分析请以 `disasm` 反汇编结果为准。（该模块内另含可选的本地 Ghidra `analyzeHeadless` 对照桥接，仅在用户显式配置本地 Ghidra 路径时调用外部进程。）
  - **安全审计插件（`audit-plugins` / `MachPluginSDK`）：** 基于启发式规则的 `JavaScriptCore` 插件已知存在误报与漏报，尚未完成带标准答案样本集的检出率/误报率标定。
  - **桌面图形界面（`MachStudioViews` / `MachWorkbenchShell`）、`.machproj` 工程库与非 Mach-O 加载器（`ELF64` / `PE32+` / `WASM`）：** 无参启动桌面端默认进入空状态工作台（仅提供“打开文件...”与带 `演示数据` 标记的显式演示加载），完整界面改造、持久化工程库与非 Mach-O 格式对照验收排在 `M5` 之后。

---

## 开源许可

MIT License. Copyright (c) 2026 Xu (`zxu756`).
