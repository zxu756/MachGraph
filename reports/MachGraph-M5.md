## MachGraph M5 报告

### 运行环境、工具版本、提交号与实测耗时

| 项目 | 实测值 |
|---|---|
| 操作系统与工具链 | `macOS 27.0.1 (26A434) arm64`；`Xcode 27.2 (Build version 27B52)`（`/Applications/Xcode.app/Contents/Developer`） |
| 参考编译器与系统对照工具 | `Apple clang version 21.0.0 (clang-2100.4.1.1)`（`xcrun clang`）、`Apple LLVM version 21.0.0`（`xcrun llvm-objdump`、`xcrun nm`、`c++filt`）、`llvm-otool(1): Apple Inc. version cctools-1040`（`xcrun otool`）、`/usr/bin/codesign`、`xcrun dyld_info`、`xcrun swift-demangle -compact` |
| 参考控制流图外部工具 | Ghidra `12.1.4`（`support/analyzeHeadless`，`AARCH64:LE:64:AppleSilicon`，`compiler_spec = default`） |
| 分支与各段提交号 | 分支 `m5/mcp-lib`；M4 收尾起点 `1c4e596`；第 1 段（MCP 与 CLI 共用函数、新增 4 工具、修 `mach_query_xrefs`、未验收标记与 `m5-mcp-acceptance.py`）`3454c8b`、`b8381e7`、`1dfc4dd`；第 2 段（`@_exported import MachGraphModels`、`analyzeCFGOnly(fileURL:)`、公开接口分层收紧、库产品收敛与 `m5-lib-examples.py`）`ac36d7a`、`96e757c`、`6385b0c`；第 3a 段（`m5-mutations.sh` 8 条变异规格与 `Scripts/test.sh release` 35 步门禁、`77` 跳过退出、`--only` 调度）`d8b92c7`、`fadecfa`；本段（第 3b 段）在干净工作树 `fadecfae6cd5f98b28d8802bface294d67cb5cc5` 上全量录制刷新 `reports/`、改写双语 `README`、切换 `m5-lib-examples.py` 默认读双语 `README`、补 `release` 替身模式警告并撰写本报告 |
| 记录文件与生成时间 | 全部录制于干净工作树 `fadecfae6cd5f98b28d8802bface294d67cb5cc5`（UTC 日期 `2026-11-22`）：<br>• `M0`：`reports/m0-quick.txt`（`2026-11-22T11:48:47Z`）、`reports/readme-commands.txt`<br>• `M1`–`M2`：`reports/differential-{quick,standard}.txt`、`reports/differential-full-2026-11-22.json`（`2026-11-22T11:59:00Z`）、`reports/macho-differential-{quick,standard}.txt`、`reports/macho-differential-full-2026-11-22.json`（`2026-11-22T12:03:47Z`）、`reports/encoding-table-check.txt`、`reports/encoding-fuzz-{20261117,17}.txt`、`reports/asm-roundtrip-standard.txt`、`reports/asm-clang-{standard,cases}.txt`、`reports/known-mnemonics-check.txt`<br>• `M3`：`reports/m3-metadata-standard.txt`、`reports/m3-metadata-objc.txt`、`reports/m3-metadata-full-2026-11-22.{json,txt}`（`2026-11-22T11:57:06Z`）<br>• `M4`：`reports/m4-cfg-acceptance.{json,txt}`（`2026-11-22T11:58:13Z`）、`reports/m4-cfg-acceptance-known-c.{json,txt}`（`2026-11-22T11:58:29Z`）、`reports/m4-cfg-acceptance-perf.{json,txt}`（`2026-11-22T11:58:30Z`）、`reports/m4-cfg-acceptance-full-2026-11-22.{json,txt}`（`2026-11-22T11:58:40Z`）、`reports/m4-ghidra-differential-ls.json`（`2026-11-22T11:59:00Z`）<br>• `M5`：`reports/m5-mcp-protocol.{json,txt}`（`2026-11-22T12:04:59Z`）、`reports/m5-mcp-tools.{json,txt}`（`2026-11-22T12:05:00Z`）、`reports/m5-mcp-legacy.{json,txt}`（`2026-11-22T12:05:02Z`）、`reports/m5-mcp-perf.{json,txt}`（`2026-11-22T12:05:03Z`）、`reports/m5-lib-examples.{json,txt}`（`2026-11-22T12:06:03Z`） |
| 主要实测耗时 | • **全量 `release`（总调度于 `2026-11-22` / 本地 `2026-11-23` 在干净克隆提交 `fadecfa`、隔离 `HOME`、`MACHGRAPH_CORPUS=full` + Ghidra 环境下实测）：** 全部 `35 / 35` 步通过，耗时 **`2,054.905s`（约 `2,055s`）**（含 `m3-mutations` `260.806s`、`m4-mutations` `283.455s`、`m5-mutations` `701.708s`、`differential-full` `251.342s`、`macho-differential-full` `52.815s`、`m3-metadata-full` `219.106s`、`m4-cfg-full` `12.948s`、`m4-ghidra` `8.942s`、`m5-lib-examples` `53.695s`）。<br>• **本段干净工作树录制总耗时：** `release` 构建 `60.47s` + 12 步录制合计 `1,051.93s`。<br>• **本段收尾 7 项检查实测耗时：** `readme-commands.sh`（`29` 条回放命令）`2.41s`、`m5-lib-examples.py`（默认读双语 `README`）`51.92s`、`test_m5_harnesses.py -v`（`25` 项）`6.98s`、`Scripts/test.sh milestone 5` `149.03s`、`Scripts/test.sh release --only readme-commands,m5-lib-examples,test-m5-harnesses` `78.32s`、替身模式警告检查 `0.41s`、`swift test --no-parallel`（`310` 项 / `21` 套件）测试执行 `10.486s`（总耗时 `14.65s`） |
| 隐私与路径核查 | `git grep --untracked -n` 扫描本机家目录绝对路径、个人邮箱及本机外部工具安装路径均为 `0` 处命中 |

---

- **做了什么：**
  1. **MCP 工具补齐、CLI 共用函数与未验收工具标记（第 1 段，`3454c8b`、`b8381e7`、`1dfc4dd`）：** 在 `MachCLIRunner` 中抽离容器加载、分析加载与结构化格式化函数，使 `MachMCPServer` 与 CLI 完全共用同一实现并按工具走最小必要快路径（`symbols`、`strings`、`info` 仅加载容器；`cfg`、`disasm --json` 走 `analyzeCFGOnly`）；新增 `mach_disasm_function`、`mach_list_symbols`、`mach_cfg`、`mach_find_strings` 四个工具；修复 `mach_query_xrefs` 漏掉传出（`->`）交叉引用的缺陷；为 `mach_decompile_function` 与 `mach_audit_security` 补齐中英双语“实验性、未通过验收”首行警告并统一 `mach_audit_security` 与 CLI `audit-plugins` 的输出格式；新建 `Scripts/acceptance/m5-mcp-acceptance.py` 与 `Scripts/acceptance/test_m5_harnesses.py`。
  2. **库公开接口整理、`@_exported` 与外部空包示例验收（第 2 段，`ac36d7a`、`96e757c`、`6385b0c`）：** 在 `MachBinaryFormats`、`MachA64Decoder`、`MachCFGEngine` 中加入 `@_exported import MachGraphModels`，补充 `BinaryAnalysisCoordinator.analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`；将模块外零调用的辅助符号收为 `internal`、仅供仓内调用的冻结/支撑符号收为 Swift 6 `package`，并将 `Package.swift` 中 6 个未通过验收的模块从对外 `products:` 移除；新增三段 `<= 20` 行双语库示例与 `Scripts/acceptance/m5-lib-examples.py`（含 3 个独立外部 Swift 空包构建运行及 14 个负向访问控制/移除产品编译探针），接入 `Scripts/test.sh milestone 5`。
  3. **M5 变异套件、发版门禁补齐与干净工作树全量录制/README 改写（第 3a 段 `d8b92c7`、`fadecfa` + 本段 3b）：** 新建 `Scripts/acceptance/m5-mutations.sh` 与 8 条严格单次匹配（`count == 1`）变异规格；在 `Scripts/test.sh release` 中补齐遗漏的 M2 七项（双随机种子共 8 步）、M5 六项与 `m5-mutations.sh`（共 `35` 步），默认 `MACHGRAPH_CORPUS=full`，任何步骤返回 `77` 时汇总后以 `77` 非零退出，支持 `--only` / `--list-steps`，并为 `MACHGRAPH_RELEASE_STUB_SCRIPT` 自测替身模式补上开头与汇总双重醒目警告且最后一行不宣称发版通过；在干净工作树 `fadecfa` 上全量录制刷新 `reports/`，将三段库示例搬入中英双语 `README` 并将 `m5-lib-examples.py` 默认输入切换为 `README.md` 与 `README.zh-CN.md`。

---

### 1. M5 规格验收表三行实测结果（`02-machgraph.md`）

| # | 检查项 | 命令 | 期望 | 实测结果与出处 | 通过与否 |
|---:|---|---|---|---|---|
| 1 | 用脚本发 JSON-RPC 调 `mach_disasm_function`，目标是 `/bin/ls` 的入口地址（`/bin/ls` 去掉了符号，没有 `_main`） | `python3 -I Scripts/acceptance/m5-mcp-acceptance.py tools --machgraph .build/release/MachGraph`（以及 `readme-commands.sh` 中的 `printf ... \| .build/debug/MachGraph mcp`） | 结果和 `machgraph disasm /bin/ls --address <入口> --json` 相同 | 取自 `reports/m5-mcp-tools.{json,txt}`（干净工作树 `fadecfa`，`2026-11-22T12:05:00Z`）：脚本用 `xcrun otool -arch arm64e -l /bin/ls` 独立算出 `LC_MAIN` 入口 `0x100000960`（并用 `xcrun nm` 核验 `/bin/ls` 无 `_main`），在 `/bin/ls` 入口全函数、`count=12`、`/usr/bin/ssh` 入口 `0x100017898` 等 **`14 / 14` 组用例**上，`mach_disasm_function`、`mach_list_symbols`、`mach_cfg`、`mach_find_strings` 全部 `isError: false`，且 `result.content[0].text` 与同参数 CLI `--json` **逐字节完全相等**（`diff_count = 0`，耗时 `1.89s`） | **通过** |
| 2 | 新建一个空的 Swift 包，依赖本仓库，编译 `README` 里的三段示例 | `python3 -I Scripts/acceptance/m5-lib-examples.py`（默认读取 `README.md` 与 `README.zh-CN.md`） | 编译通过，输出符合示例里写的结果 | 取自本段收尾实测（及干净工作树记录 `reports/m5-lib-examples.{json,txt}`）：实时从 `README.md` 与 `README.zh-CN.md` 提取三段 Swift 示例（`MachBinaryFormats` `14` 行、`MachA64Decoder` `16` 行、`MachCFGEngine` `16` 行，中英逐字一致且均不显式 `import MachGraphModels`），在 `mktemp -d` 隔离目录下分别新建三个独立空 Swift 包通过 `.package(path:)` 依赖并编译运行：**`3 / 3` 段示例均 `0` 警告编译通过**，运行输出与示例期望输出及 `otool -l`、`codesign -dvvv`、`clang`、`llvm-objdump` 独立计算的参考答案完全一致（`diffs = 0`）；另有 **`14 / 14` 项负向编译探针**全部按预期因访问级别或产品未导出被拒（收尾实测耗时 `51.92s`） | **通过** |
| 3 | `Scripts/test.sh release` | 全量：`GHIDRA_INSTALL_DIR=<ghidra_dir> JAVA_HOME=<jdk21_home> ./Scripts/test.sh release`（默认 `MACHGRAPH_CORPUS=full`）；本段增量核对：`./Scripts/test.sh release --only readme-commands,m5-lib-examples,test-m5-harnesses` | 通过（退出码 `0`，无跳过混充通过） | 1) **总调度全量实测**（`2026-11-22` UTC / 本地 `2026-11-23`，在干净新克隆提交 `fadecfa`、隔离 `HOME`、`MACHGRAPH_CORPUS=full` + Ghidra 环境下运行）：**全部 `35 / 35` 个步骤 `PASS`，`skipped = 0`，`failed = 0`，退出码 `0`，总耗时 `2,054.905s`（约 `2,055s`）**。<br>2) **本段第 6 步实测：** `./Scripts/test.sh release --only readme-commands,m5-lib-examples,test-m5-harnesses` **`3 / 3` 步 `PASS`（退出码 `0`，耗时 `78.32s`）**；设 `MACHGRAPH_RELEASE_STUB_SCRIPT` 替身跑 `release` 时开头与汇总均打印醒目警告且最后一行不宣称发版通过（退出码 `0`，耗时 `0.41s`） | **通过** |

---

### 2. 开工前核对报告（`SURVEY.md` 第 6.1 节）7 行细化验收表逐行结果

| # | 检查项 | 命令 | 对照物 | 实测结果与出处 | 门禁性质 / 结论 |
|---:|---|---|---|---|---|
| 1 | MCP 协议握手、`tools/list` 八工具 Schema 与错误路径 | `python3 -I Scripts/acceptance/m5-mcp-acceptance.py protocol --machgraph .build/release/MachGraph` | MCP `2024-11-05` 规范与预期工具表 | 取自 `reports/m5-mcp-protocol.{json,txt}`（`2026-11-22T12:04:59Z`）：EN/ZH 双语 `initialize`、`notifications/initialized`（无回包）、`tools/list` 精确包含 8 个工具且 `inputSchema` 属性完整；非法 JSON 返 `-32700`、未知方法返 `-32601`；缺 `binaryPath`、不存在路径、`/dev/null`、未知工具、`/bin/ls` 查 `_main`、`mach_cfg` 缺目标或冲突参数、非法地址与错误参数类型全部返回 `isError: true` 且消息非空（`diff_count = 0`，耗时 `0.46s`） | 硬性 / **通过** |
| 2 | 新增 4 个工具与 CLI `--json` 及系统工具对照 | `python3 -I Scripts/acceptance/m5-mcp-acceptance.py tools --machgraph .build/release/MachGraph` | `xcrun otool -arch <slice> -l` 独立算出的 `LC_MAIN` 入口地址 + 同参数 `machgraph <disasm\|symbols\|cfg\|strings> ... --json` | 取自 `reports/m5-mcp-tools.{json,txt}`（`2026-11-22T12:05:00Z`）：`/bin/ls`（`0x100000960`）、`/usr/bin/ssh`（`0x100017898`）及 `filter`/`count` 组合共 **`14 / 14` 组用例逐字节相等**（`diff_count = 0`，耗时 `1.89s`） | 硬性 / **通过** |
| 3 | 原有 4 个工具行为与未通过验收标记检查 | `python3 -I Scripts/acceptance/m5-mcp-acceptance.py legacy --machgraph .build/release/MachGraph` | `codesign -a <slice> -dvvv`、`machgraph xrefs --json`、`machgraph audit-plugins` 及双语未验收文案 | 取自 `reports/m5-mcp-legacy.{json,txt}`（`2026-11-22T12:05:02Z`）：`mach_inspect_binary` 在 `/bin/ls` 与 `/usr/bin/ssh` 上的 `cdhash` 精确匹配 `codesign`；`mach_query_xrefs` 在 `/bin/ls` `0x10000073c` 上同时返回传入（`<-`）与传出（`->`）交叉引用；`mach_decompile_function` 与 `mach_audit_security` 在 EN/ZH 下第 1 行严格包含 `[EXPERIMENTAL / UNVERIFIED]` / `【实验性】【未通过验收】` / `【实验性・未通过验收】`，且 `mach_audit_security` 与 CLI `audit-plugins` 输出一致（`diff_count = 0`，耗时 `0.95s`） | 硬性 / **通过** |
| 4 | 外部 Swift 包编译运行 `README` 三段库示例与公开接口边界 | `python3 -I Scripts/acceptance/m5-lib-examples.py` | 实时从 `README.md` 与 `README.zh-CN.md` 提取的三段 `<= 20` 行示例 + 系统工具独立计算值 + 14 项负向编译探针 | 取自本段收尾实测（及 `reports/m5-lib-examples.{json,txt}`）：`Docs: README.md \| README.zh-CN.md`，三段示例（`14`、`16`、`16` 行）中英逐字一致、外部空包 `0` 警告编过且输出一致；`13` 个已收紧为 `internal`/`package` 的符号探针 + `1` 个已移除库产品探针（`MachMicroDecompiler`）共 **`14 / 14` 全部按预期编译失败**（`diffs = 0`，耗时 `51.92s`） | 硬性 / **通过** |
| 5 | MCP 调用耗时基线（快路径核验） | `python3 -I Scripts/acceptance/m5-mcp-acceptance.py perf --machgraph .build/release/MachGraph` | 单调时钟，三次取中位数（记录前后 `uptime`，`30s` 卡死超时） | 取自 `reports/m5-mcp-perf.{json,txt}`（`2026-11-22T12:05:03Z`，测前 `load averages: 3.56 4.66 5.12`、测后 `3.44 4.62 5.10`，总耗时 `7.32s`，`failures = 0`）：<br>• `/usr/bin/ssh`：`mach_list_symbols` **`0.0334s`**（`595,853` B）、`mach_find_strings` **`0.0225s`**（`35,691` B）、`mach_cfg`（`_entry`）**`0.1947s`**（`475,758` B）、`mach_disasm_function`（`_entry`）**`0.2369s`**（`1,189,447` B）<br>• `/usr/bin/vim`：`mach_list_symbols` **`0.0942s`**（`2,184,629` B）、`mach_find_strings` **`0.0513s`**（`46,839` B）、`mach_cfg`（`_entry`）**`0.8729s`**（`283,910` B）、`mach_disasm_function`（`_entry`）**`0.8736s`**（`392,351` B） | 只记录 / **已记录（通过）** |
| 6 | M5 破坏性变异套件 | `./Scripts/acceptance/m5-mutations.sh` | 临时仓库拷贝中的 8 条严格单次替换变异规格（`Scripts/acceptance/mutations/m5-*.json`） | 第 3a 段实测耗时 `744.714s`、总调度在 `fadecfa` 新克隆 `release` 中实测耗时 `701.708s`：**`8 / 8` 条变异全部使对应验收脚本以退出码 `1` 失败并报出预期差异**，每条还原后临时副本与主仓库 `Sources/`、`Package.swift` 零差异（明细见第 3 节） | 硬性 / **通过** |
| 7 | 发版前全量门禁、全量报告录制与双语 `README` 核对 | `GHIDRA_INSTALL_DIR=<ghidra_dir> JAVA_HOME=<jdk21_home> ./Scripts/test.sh release`；`./Scripts/acceptance/readme-commands.sh` | M0–M5 全套单测、对照脚本（含补齐的 M2 与 Ghidra）、M3/M4/M5 变异套件与本次 `reports/` 记录文件 | 总调度在 `fadecfa` 干净克隆跑通完整 `35 / 35` 步 `release`（`2,054.905s`，退出码 `0`）；本段在干净工作树 `fadecfa` 上完成全部 12 步 `--record` 录制，双语 `README` 所有数字均取自本次 `reports/` 且功能表不含未验收模块；`readme-commands.sh` **`29 / 29` 条示例命令回放通过**（含 5 条 MCP JSON-RPC 调用），家目录路径与邮箱扫描 `0` 命中 | 硬性 / **通过** |

---

### 3. 三段破坏性变异检查汇总（第 1 段、第 2 段与第 3a 段 8 条固化套件）

- **第 1 段手工变异验证（M5-01）：**
  - **变异 1a（`mach_disasm_function` 忽略 `count` 并丢弃最后 1 条指令）：** `m5-mcp-acceptance.py tools` 以退出码 `1` 失败，检出 4 处 `BYTE_MISMATCH`（如 `ls_disasm_entry_count12`: `mcp_bytes=195084 != cli_bytes=3289`）。
  - **变异 1b（删掉 `mach_decompile_function` 与 `mach_audit_security` 首行未验收标记）：** `m5-mcp-acceptance.py legacy` 以退出码 `1` 失败，检出 4 处 `MISSING_UNVERIFIED_MARKER`（双工具 EN/ZH 全抓获）。
  - *总调度复核第 1 段时另自做 3 条变异*（MCP 忽略 `count`、去掉审计标记、去掉传出引用），分别被 `tools`、`legacy`、`legacy` 抓获。
- **第 2 段手工变异验证（M5-02）：**
  - **变异 2a（去掉 `MachA64Decoder` 的 `@_exported import MachGraphModels`）：** `m5-lib-examples.py` 以退出码 `1` 失败，检出 `BUILD_FAILED`（外部空包找不到 `VirtualAddress`）。
  - **变异 2b（将 `ELF64Loader` 与 `signExtend` 改回 `public`）：** `m5-lib-examples.py` 以退出码 `1` 失败，检出 2 条 `NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED`。
  - *总调度复核第 2 段时另自做 4 条变异*（`analyzeCFGOnly(fileURL:)` 忽略 `selector`、`ASN1DERWalker` 改回 `public`、将 `MachMicroDecompiler` 加回对外 `products:`、去掉 `MachCFGEngine` 的 `@_exported`），全部使 `m5-lib-examples.py` 变红。
- **第 3a 段固化变异套件（`Scripts/acceptance/m5-mutations.sh`，合并第 1、2 段与总调度复核共 8 条单缺陷规格，`8 / 8` 抓获）：**

| 变异 | 规格文件（`Scripts/acceptance/mutations/`） | 修改位置与缺陷内容 | 验收脚本 | 退出码与捕获差异摘要 |
|---|---|---|---|---|
| **1a** | `m5-01a-mcp-disasm-ignore-count.json` | `MachCLIRunnerAndMCPServer.swift`（`mach_disasm_function` 忽略 `count` 参数） | `m5-mcp-acceptance.py tools` | 退出码 `1`：`BYTE_MISMATCH case=ls_disasm_entry_count12 mcp_bytes=195331 != cli_bytes=3289` |
| **1b** | `m5-01b-mcp-audit-drop-unverified-marker.json` | `MachCLIRunnerAndMCPServer.swift`（去掉 `mach_audit_security` 首行未通过验收标记） | `m5-mcp-acceptance.py legacy` | 退出码 `1`：`MISSING_UNVERIFIED_MARKER tool=mach_audit_security lang=en` |
| **2a** | `m5-02a-a64-drop-exported-models.json` | `SymbolDemangler.swift`（去掉 `MachA64Decoder` 的 `@_exported import MachGraphModels`） | `m5-lib-examples.py` | 退出码 `1`：`BUILD_FAILED target=MachA64Decoder returncode=1` |
| **2b** | `m5-02b-elf64loader-leak-public.json` | `MultiFormatCrossLoader.swift`（将 `package` 的 `ELF64Loader` 改回 `public`） | `m5-lib-examples.py` | 退出码 `1`：`NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe=ELF64Loader_package` |
| **2c** | `m5-02c-cfg-fileurl-ignore-selector.json` | `CrossReferenceAndCallGraphDatabase.swift`（`analyzeCFGOnly(fileURL:)` 忽略 `selector`） | `m5-lib-examples.py` | 退出码 `1`：`RUNTIME_OUTPUT_MISMATCH module=MachCFGEngine actual='...sub_100000700...' != reference='..._entry@0x0000000100000960...'` |
| **2d** | `m5-02d-asn1derwalker-leak-public.json` | `CodeSignatureAndCMSParser.swift`（将 `internal` 的 `ASN1DERWalker` 改回 `public`） | `m5-lib-examples.py` | 退出码 `1`：`NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe=ASN1DERWalker_internal` |
| **2e** | `m5-02e-package-readd-decompiler-product.json` | `Package.swift`（把已移除的冻结模块 `MachMicroDecompiler` 加回对外 `products:`） | `m5-lib-examples.py` | 退出码 `1`：`NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe=removed_product_MachMicroDecompiler` |
| **2f** | `m5-02f-cfg-drop-exported-models.json` | `CrossReferenceAndCallGraphDatabase.swift`（去掉 `MachCFGEngine` 的 `@_exported import MachGraphModels`） | `m5-lib-examples.py` | 退出码 `1`：`BUILD_FAILED target=MachCFGEngine returncode=1` |

（此外，总调度在复核 3a 时对 `Scripts/test.sh` 做了 3 条门禁变异：跳过改退出 `0`、删掉 M2 的 `known-mnemonics` 步骤、默认语料改为 `standard`，`test_m5_harnesses.py` 全部变红；本段 3b 又补充了 `README` 默认路径、中英期望输出逐字一致与替身模式警告的先红后绿单测。）

---

### 4. 用户拍板的四件事（`2026-11-22`“都按建议办”）落实情况

1. **D-M5-1（四个新 MCP 工具逐字节对齐 CLI `--json`、`mach_cfg` 必传目标函数、修 `mach_query_xrefs`）：**
   - `mach_list_symbols`、`mach_find_strings`、`mach_disasm_function`、`mach_cfg` 内部直接调用 `MachCLIRunner` 的同一格式化函数，`result.content[0].text`（含末尾换行）与同参数命令行 `--json` 逐字节完全一致。
   - `mach_cfg` 强制必传 `symbol`（或别名 `function`）与 `address` 之一（互斥），缺省或同时传入均返回 `isError: true`，全文件 CFG 导出仅保留在命令行 `machgraph cfg <file> --json`。
   - `mach_query_xrefs` 改为调用 `MachCLIRunner.formatTargetXrefs`，同时返回传入（`<-`）与传出（`->`）交叉引用。
2. **D-M5-2（两个未通过验收工具保留并标明“实验性、未通过验收”，统一审计输出格式）：**
   - `mach_decompile_function` 与 `mach_audit_security` 保留在 `tools/list` 中，其 EN/ZH `description` 与调用返回文本第 1 行均显式包含 `[EXPERIMENTAL / UNVERIFIED]` 与中文 `【实验性】【未通过验收】` / `【实验性・未通过验收】`。
   - `mach_audit_security` 改为调用与命令行 `audit-plugins` 相同的文本格式化函数，不再拼接半截 `//` 注释与裸 JSON。
3. **D-M5-3（三库模块 `@_exported`、快路径重载、`internal` / `package` 分层收紧与对外产品收敛）：**
   - `MachBinaryFormats`、`MachA64Decoder`、`MachCFGEngine` 统一声明 `@_exported import MachGraphModels`；`BinaryAnalysisCoordinator` 新增 `analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`。
   - 模块外零调用的辅助类型与位运算函数降为 `internal`（如 `ASN1DERWalker`、`MachO64Loader`、`signExtend`、`DecodeBitMasks`、`A64BitUtils`）；仅供仓内模块使用的未验收或内部支撑类型降为 `package`（如 `ELF64Loader`、`PE32PlusLoader`、`WasmModuleLoader`、`A64SystemRegisterTable`、`PostDominatorTreeNode`、`SugiyamaCFGLayoutSolver`、`KnownNoreturnSymbols`）。
   - `Package.swift` 的对外 `products:` 收敛为 `MachGraphModels`、`MachBinaryFormats`、`MachA64Decoder`、`MachCFGEngine`、`MachHeadlessCLI` 与可执行目标 `MachGraph`（6 个未验收模块从对外库产品移除）。
4. **D-M5-4（`Scripts/test.sh release` 补齐 M2 七项与 M5、默认 `full` 语料、跳过退出 `77` 及替身警告）：**
   - `release` 串入全部 `35` 个步骤（含补齐的 M2 七项共 8 步、M5 六项及 M3/M4/M5 三套变异检查），默认 `MACHGRAPH_CORPUS=full`；缺 Ghidra 环境变量或 `MACHGRAPH_CORPUS != full` 时跑完其余步骤并以 `77` 非零退出（失败步骤优先于 `77` 返回失败码）。
   - 设置自测用的 `MACHGRAPH_RELEASE_STUB_SCRIPT` 时，在开头与汇总表均打印醒目警告（写明这是自测用的替身、不是真的发版检查），且最后一行不宣称 `release` 通过。

---

### 5. 没做或没验证的项

- **伪 C 反编译器（`decompile` / `mach_decompile_function`，G18）：** 尚未通过验收（条件表达式、循环上下界与 `switch` 还原在真实二进制上不可靠），已在 CLI 与 MCP 第 1 行标明“实验性、未通过验收”，并从对外库产品和已验证功能表中移出。
- **静态安全审计插件（`audit-plugins` / `mach_audit_security`，G21）：** 尚未通过带标准答案样本集的检出率与误报率标定，已在第 1 行标明“实验性、未通过验收”，不列入已验证功能表。
- **补丁引擎端到端行为验收（`patch-asm` / `resign`，G17）：** 基础指令汇编与临时重签名可用，但基于 `t1.c` / `t3.c` 的端到端行为改动验收套件排在 M5 之后，放入 `README`「计划中」。
- **桌面图形界面与 `.machproj` 工程存储：** 尚未做界面验收（无参启动为空工作台，未放任何界面截图），排在 M5 之后。
- **非 Mach-O 容器格式（`ELF64`、`PE32+`、`WASM`，G22）：** 尚未与 `llvm-readelf`、`wasm-objdump` 等参考工具完成差分对照验收，内部加载器已收为 `package` 作用域，放入 `README`「计划中」。
- **M4 控制流图的既有边界保持不变：** 仅支持 `ARM64` / `ARM64e` Mach-O 切片；间接跳转仅解析内联/PC 相对 switch 跳转表；外部不返回函数只认 `Scripts/acceptance/noreturn-evidence.json` 中的 `44` 个名字；Ghidra `12.1.4` 对照仅跑了 `/bin/ls`。
- **提交后重录 `reports/readme-commands.txt`（及可选重录 `reports/m5-lib-examples.{json,txt}`）：** 因 `--record` 要求干净工作树而本段不执行 `git commit`，新双语 `README` 的 `29` 条示例命令已在收尾跑通 `Scripts/acceptance/readme-commands.sh`，留待总调度按分块提交后在干净工作树上运行 `./Scripts/test.sh milestone 0 --record`（及可选 `./Scripts/test.sh milestone 5 --record`）刷新。
