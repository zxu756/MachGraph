## MachGraph M4 报告

### 运行环境、工具版本、提交号与实测耗时

| 项目 | 实测值 |
|---|---|
| 操作系统 | `macOS 27.0.1 (26A434) arm64` |
| 参考编译器与反汇编工具 | `Apple clang version 21.0.0 (clang-2100.4.1.1)`（`xcrun clang`）、`Apple LLVM version 21.0.0`（`xcrun llvm-objdump`） |
| 参考函数起点与间接符号工具 | `xcrun dyld_info -arch <slice> -function_starts`、`xcrun otool -arch <slice> -Iv` |
| 参考控制流图外部工具 | Ghidra `12.1.4`（`support/analyzeHeadless`，`AARCH64:LE:64:AppleSilicon`，`compiler_spec = default`） |
| 分支与各段提交号 | 分支 `m4/cfg`；M3 收尾起点 `8ef0fd4`；第 1 段（引擎修复）`dd09373`、`3bbaac1`、`ff16d6b`；第 2 段（三处无用功消除与独立 `cfg` 命令）`9b27810`、`cec3bd1`；第 3 段（验收脚本、Ghidra 对照与 `milestone 4`）`02c315d`、`555e2ed`、`b2234aa`；第 4a 段（`m4-mutations.sh` 与 9 条变异补丁）`23009b3`、`24825e3`、`c05369f`；第 4a2 段（不返回调用完备性断言与变异脚本工作树快照比对）`5e7d6b6`、`ec5d0f2`；第 4a3 段（不返回名单依据表与三方核对）`b50f9f7`、`329b433`、`50f1fcf`；总调度在干净工作树 `50f1fcf` 上用 `--record` 录制验收与 Ghidra 对照提交 `8ed0258`（其上叠加第 4b 段中英文 `README`、`Scripts/acceptance/readme_commands.py` 与本报告） |
| 记录文件与生成时间 | 全部录制于干净工作树 `50f1fcfc91c56fd5bcef93db40bdc051763986b2`（日期 `2026-11-21`，`worktree_clean = true`）：<br>• `reports/m4-cfg-acceptance.{txt,json}`（`standard`，UTC `2026-11-21T15:14:23Z`）<br>• `reports/m4-cfg-acceptance-known-c.{txt,json}`（`known-c`，UTC `2026-11-21T15:13:35Z`）<br>• `reports/m4-cfg-acceptance-perf.{txt,json}`（`perf`，UTC `2026-11-21T15:13:36Z`）<br>• `reports/m4-cfg-acceptance-full-2026-11-21.{txt,json}`（`full` 固定种子抽样 40 个文件，UTC `2026-11-21T15:13:47Z`）<br>• `reports/m4-ghidra-differential-ls.json`（`/bin/ls` Ghidra 12.1.4 对照，UTC `2026-11-21T15:14:09Z`） |
| 主要实测耗时 | 记录文件耗时：`m4-cfg-acceptance.py standard` `17.41s`、`known-c` `0.30s`、`perf` `9.93s`（`ssh` 全文件中位数 `0.3411s`、`vim` 全文件中位数 `1.9243s`、`ssh --symbol _entry` 单函数中位数 `0.2108s`）、`full`（40 个文件）`12.24s`、`m4-ghidra-differential.py /bin/ls` `9.47s`；本段回归实测耗时：`Scripts/acceptance/m4-mutations.sh`（9 条变异）`309.16s`、`swift test --no-parallel`（`304` 项 / `20` 套件）测试执行 `7.137s`（总计 `12.84s`）、`test_m4_harnesses.py`（`18` 项）`0.027s`、`Scripts/test.sh milestone 0` `17.48s`、`milestone 1` `85.86s`、`milestone 2` `118.34s`、`milestone 3` `78.30s`、`milestone 4` `91.98s`、`Scripts/acceptance/readme-commands.sh`（`25` 条命令）通过 |
| 隐私与路径核查 | `git grep --untracked -n` 扫描本机家目录绝对路径与个人邮箱均为 `0` 处命中 |

---

- **做了什么：**
  1. **引擎修复（第 1 段，`dd09373`、`3bbaac1`、`ff16d6b`）：** 保存原始 `LC_FUNCTION_STARTS` 并从 `info --json` 函数起点表剔除 `0x100000000`（`__mh_execute_header`）及非可执行节地址；重写 `findSwitchBoundsGuard`，在寄存器与栈槽同源追踪下同时识别条件分支上界与 `cmp + csel` 无分支钳位上界（以及页首 `adrp` 直传 `ldrsw`），并将可执行节内联跳转表字节区间从函数起点种子与指令流中剥离；将 `udf` 标为基本块终结指令；支持已知不返回函数及内部包装函数有界不动点传播，`bl` 不连落入边并标 `isExit = true`；修复 `__TEXT,__objc_stubs` 被 `brk` 填充切成假函数。
  2. **三处无用功消除与独立 `cfg` 子命令（第 2 段，`9b27810`、`cec3bd1`）：** 后支配树与结构化区域改为反编译器与界面按需计算，`cfg` 新增不构建全表交叉引用与调用图的 `analyzeCFGOnly` 快路径，函数边界启发式中的保护跨度扫描改为二分查找；新增独立 `machgraph cfg <file> [--symbol <name> | --address <0x...>] [--slice <index>] [--json]` 子命令（`schema: "machgraph.cfg/1"`，支持全文件与单函数输出），原样保留 `cfg-dot`。
  3. **验收脚本、Ghidra 对照与 `milestone 4`（第 3 段，`02c315d`、`555e2ed`、`b2234aa`）：** 修复 `trimARM64FunctionEnd` 对条件分支后及跳转表指向的函数末尾 `brk #0x1` 误裁；新建 `Scripts/acceptance/m4-cfg-acceptance.py`（独立解析 `LC_FUNCTION_STARTS`、独立解码 ARM64 控制流、独立迭代求支配集与自然循环、现场编译 8 个 `clang -O0` 已知答案 C 函数、单调时钟测耗时）、`Scripts/acceptance/m4-ghidra-differential.py`（调用 Ghidra `12.1.4` `analyzeHeadless` 对照 `/bin/ls`）与 `Scripts/acceptance/test_m4_harnesses.py`，接入 `Scripts/test.sh milestone 4` 与 `release`。
  4. **破坏性变异套件、不返回调用完备性与依据表（第 4a–4a3 段，`23009b3`–`50f1fcf`，记录提交 `8ed0258`）：** 新建 `Scripts/acceptance/m4-mutations.sh` 与 9 条单点变异补丁；在 `m4-cfg-acceptance.py --only invariants` 中补齐“直接调用确定不返回的目标后块必须结束且无后继边”完备性断言（`NORETURN_CALL_NOT_BLOCK_END`、`NORETURN_CALL_HAS_SUCCESSOR`）；新建 `Scripts/acceptance/noreturn-evidence.json` 对 86 个候选符号逐条核定依据（保留 44 个、删除 42 个），由单测强约束产品、验收脚本与依据表三方一致及本机 SDK 头文件行号核对；总调度在干净工作树 `50f1fcf` 上用 `--record` 录制全部 M4 报告文件，并在本段（第 4b 段）更新双语 `README`、`readme_commands.py` 与本报告。

---

### 1. M4 新验收表逐行实测结果（第 1–6 行）

| # | 检查项 | 命令 | 对照物 | 期望 | 实测（含记录文件出处） | 通过与否 |
|---:|---|---|---|---|---|---|
| 1 | 函数起点（`function-starts`） | `python3 -I Scripts/acceptance/m4-cfg-acceptance.py standard --only function-starts --machgraph .build/release/MachGraph`（另跑 `full` 抽样 40 个文件） | 脚本自己解析的 `LC_FUNCTION_STARTS` ULEB128 表，和 `xcrun dyld_info -arch <slice> -function_starts` | `info --json` 的函数起点表和参考完全相等（`ls` `50`、`ssh` `1,097`、`vim` `6,623`，没有 `0x100000000`）；`cfg --json` 在 `__TEXT,__text` 里恢复出的函数起点 `∪` 识别出的内联跳转表起点 `== LC_FUNCTION_STARTS`（`0` 缺、`0` 多）；`__objc_stubs` 里没有被 `brk` 切出来的假函数 | 取自 `reports/m4-cfg-acceptance.{txt,json}`：`standard` **`matched = 3/3`**，`total_diffs = 0`，`ref_items = mg_items = 7,770`（`ls` `49+1=50`，`ssh` `1,094+3=1,097` 且 `__objc_stubs` `10` 个，`vim` `6,528+95=6,623` 且 `__objc_stubs` `19` 个；无 `0x100000000`，假函数 `0` 个）。<br>取自 `reports/m4-cfg-acceptance-full-2026-11-21.{txt,json}`：`full` **`matched = 40/40`**（跳过无 `arm64`/`arm64e` 切片 `3` 个），`total_diffs = 0`，`ref_items = mg_items = 21,945`（`__TEXT,__text` 函数 `21,816` + 内联跳转表 `129`；`__objc_stubs` `5,251` 个，假函数 `0` 个） | **通过** |
| 2 | 四条不变量和支配树、循环（`standard` 全部函数及 `full` 抽样） | `python3 -I Scripts/acceptance/m4-cfg-acceptance.py standard --only invariants --machgraph .build/release/MachGraph`（另跑 `full` 抽样 40 个文件） | 脚本自己写的 ARM64 控制流解码、`xcrun otool -arch <slice> -Iv` 间接符号表、迭代求支配集和自然回边（不用产品代码），以及 `Scripts/acceptance/noreturn-evidence.json`（44 个有依据不返回符号） | `I1` 块尾是终结指令或紧邻落入下一块开头、块内没有终结指令（直接调用确定不返回的目标后块必须结束且无后继边）；`I2` 函数内分支和跳转表目标是本函数的块开头，跨函数尾跳目标是另一函数的起点，内联表不与指令重叠且末尾不跟截短 `udf`；`I3` 函数和块都不重叠、块内指令按 4 字节连续；`I4` 边两端、前驱后继、支配树、循环里的块都存在且一致，`idom` 和脚本独立求的完全相等：四条都 `0` 违反 | 取自 `reports/m4-cfg-acceptance.{txt,json}`：`standard` **`matched = 3/3`**，`8,408` 个函数、`150,147` 个块、`220,315` 条边、`6,193` 个自然循环、`99` 张内联跳转表、核验不返回出口与直接调用 `1,080 / 1,080` 处，**`violations = {"I1": 0, "I2": 0, "I3": 0, "I4": 0}`**，完备性违反 `{"NORETURN_CALL_NOT_BLOCK_END": 0, "NORETURN_CALL_HAS_SUCCESSOR": 0}`。<br>取自 `reports/m4-cfg-acceptance-full-2026-11-21.{txt,json}`：`full` **`matched = 40/40`**（崩溃 `0` 个），`31,981` 个函数、`258,906` 个块、`339,379` 条边、`9,274` 个自然循环、`129` 张内联跳转表、核验不返回出口与直接调用 `4,035 / 4,035` 处，**`violations = {"I1": 0, "I2": 0, "I3": 0, "I4": 0}`**，完备性违反 `0` 处 | **通过** |
| 3 | 已知答案（clang `-O0` 现场编译 8 个小函数） | `python3 -I Scripts/acceptance/m4-cfg-acceptance.py known-c --machgraph .build/release/MachGraph` | `xcrun clang -O0 -arch arm64` 编到临时目录，答案表手工核定（`xcrun llvm-objdump` 对过） | 顺序、if/else、while、for、嵌套循环、5 分支 switch（`-O0` 下是比较链、`0` 个表）、10 分支 switch（跳转表 `10` 项）、带 break 和 continue 的循环：块数、边数、循环数和嵌套深度、跳转表项数全部相等 | 取自 `reports/m4-cfg-acceptance-known-c.{txt,json}`（及 `reports/m4-cfg-acceptance.txt` 第 13–20、32 行）：**`matched = 8/8`**，`total_diffs = 0`（耗时 `0.30s`），8 个函数块数、边数、循环数与嵌套深度、跳转表数与表项数全部相等，同步 `invariants` `I1`–`I4` 均 `0` 违反（逐函数明细见第 3.1 节） | **通过** |
| 4 | `/bin/ls` 和 Ghidra `12.1.4` 对照 | `GHIDRA_INSTALL_DIR=... JAVA_HOME=... python3 -I Scripts/acceptance/m4-ghidra-differential.py /bin/ls --machgraph .build/release/MachGraph`（临时工程直接调 `analyzeHeadless`，跑完即删；不进每次 `milestone 4`，本机和发版时跑） | Ghidra `12.1.4` 的函数起止和 `BasicBlockModel` 块数与块起点集合 | 每条差异都归类并写明原因；属于 MachGraph 的错误 `0` 条；没有 Ghidra 的机器打印“已跳过、不算通过”（退出码 `77`） | 取自 `reports/m4-ghidra-differential-ls.json`：`verdict = "PASS"`（耗时 `9.47s`），MachGraph `133` 个函数 vs Ghidra `134` 个实函数（共同起点 `133` 个；共同函数中结束地址相等 `132/133`、块数相等 **`133/133`**、块起点相等 `132/133`、三项全等 `131/133`）；**`machgraph_error_count = 0`**，共 **`4` 条差异记录全部归类解释**（明细见第 3.2 节）；无 `GHIDRA_INSTALL_DIR` 时输出“已跳过、不算通过”并退出 `77` | **通过** |
| 5 | `ssh`、`vim` 全函数建图耗时（`perf`） | `python3 -I Scripts/acceptance/m4-cfg-acceptance.py perf --machgraph .build/release/MachGraph` | 单调时钟，三次取中位数（每次校验完整 JSON，前后记录 `uptime`） | `ssh` 全函数 `cfg --json` 功能校验通过，`<= 5` 秒（超线告警，`30` 秒算卡死、失败）；报告写 `ssh`、`vim` 的实测秒数、单函数 `--symbol` 延迟和优化前后对比 | 取自 `reports/m4-cfg-acceptance-perf.{txt,json}`（在总调度的机器上、同时有别的构建在跑，测前 `load averages: 5.13 5.17 4.58`、测后 `4.88 5.12 4.57`）：`warnings = 0`，`failures = 0`；**`ssh` 全文件中位数 `0.3411s`**（`[0.3383, 0.3411, 0.3417]s`），**`vim` 全文件中位数 `1.9243s`**（`[1.9243, 1.932, 1.8299]s`），**`ssh --symbol _entry` 单函数中位数 `0.2108s`**（`[0.2111, 0.2093, 0.2108]s`）。优化前（第 2 段之前第 1 段引擎经导出工具建图并写 JSON，总调度在第 2 段核对时实测、不在记录文件里）`ssh` **`0.91s`**、`vim` **`6.63s`** -> 优化后 `ssh` **`0.3411s`**、`vim` **`1.9243s`** | **已记录（通过）** |
| 6 | 变异和回归 | `./Scripts/acceptance/m4-mutations.sh`；`swift test --no-parallel`；`./Scripts/test.sh milestone 0`–`4`；`./Scripts/acceptance/readme-commands.sh` | 7 类能力共 `9` 条单点破坏性变异补丁（覆盖函数起点、`I1`、`I2`/`I4`、支配树、自然循环、`cmp + csel` 与 `b.hi` 上界、不返回调用完备性）及全套单测与 M0–M4 门禁 | 每个变异让对应检查以非零退出码失败并指出差异；改回后 `Sources/` 不变，全部测试和 M0–M4 退出码 `0` | 本段实测全部退出码 **`0`**：`m4-mutations.sh` **`9 / 9` 条变异全部抓获**（耗时 `309.16s`，逐条失败项见第 4 节表），还原后 `Sources/` 零改动；`swift test --no-parallel` **`304 / 304`**（`20` 个套件，`7.137s`）全过；`milestone 0`（`17.48s`）、`1`（`85.86s`）、`2`（`118.34s`）、`3`（`78.30s`）、`4`（`91.98s`）全部通过；`readme-commands.sh` **`25 / 25`** 条示例命令通过（含将 `/bin/ls` 函数数期望改坏变红、还原后重新变绿校验） | **通过** |

---

### 2. 第 1–2 行与第 5 行明细：语料对账、性能前后对比与不返回名单依据

#### 2.1 `standard` 与 `full` 抽样语料对账明细（取自 `reports/m4-cfg-acceptance.{txt,json}` 与 `reports/m4-cfg-acceptance-full-2026-11-21.{txt,json}`）

| 目标 / 语料 | `LC_FUNCTION_STARTS`（`__text` 函数 + 内联跳转表） | `__objc_stubs` 桩数（假函数数） | 全可执行节恢复函数数 | 基本块数 | 有向边数 | 自然循环数 | 核验不返回出口 / 直接调用 | `I1`–`I4` 违反数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `/bin/ls` (`arm64e`) | `50` (`49 + 1`) | `0` (`0`) | `133` | `871` | `1,110` | `38` | `32 / 32` | `0` |
| `/usr/bin/ssh` (`arm64e`) | `1,097` (`1,094 + 3`) | `10` (`0`) | `1,494` | `18,941` | `26,513` | `955` | `466 / 466` | `0` |
| `/usr/bin/vim` (`arm64e`) | `6,623` (`6,528 + 95`) | `19` (`0`) | `6,781` | `130,335` | `192,692` | `5,200` | `582 / 582` | `0` |
| **`standard` 合计（`3 / 3`）** | **`7,770` (`7,671 + 99`)** | **`29` (`0`)** | **`8,408`** | **`150,147`** | **`220,315`** | **`6,193`** | **`1,080 / 1,080`** | **`0`** |
| **`full` 抽样合计（`40 / 40`，发现 `1,281`、跳过无 ARM64 `3`、池 `1,278`、`seed=20261121`）** | **`21,945` (`21,816 + 129`)** | **`5,251` (`0`)** | **`31,981`** | **`258,906`** | **`339,379`** | **`9,274`** | **`4,035 / 4,035`** | **`0`** |

#### 2.2 性能实测与第 2 段前后对比

- **当前记录值（取自 `reports/m4-cfg-acceptance-perf.{txt,json}`，在总调度的机器上、同时有别的构建在跑，测前 `load averages: 5.13 5.17 4.58`、测后 `4.88 5.12 4.57`）：**
  - `cfg /usr/bin/ssh --json`（全文件 `1,494` 函数、`18,941` 块、`12,042,121` 字节 JSON）：三次 `[0.3383, 0.3411, 0.3417]s`，中位数 **`0.3411s`**（门禁告警线 `<= 5.0s`，卡死超时 `30.0s`）。
  - `cfg /usr/bin/vim --json`（全文件 `6,781` 函数、`130,335` 块、`80,234,750` 字节 JSON）：三次 `[1.9243, 1.932, 1.8299]s`，中位数 **`1.9243s`**（卡死超时 `90.0s`）。
  - `cfg /usr/bin/ssh --symbol _entry --json`（单函数 `1` 函数、`729` 块、`475,758` 字节 JSON）：三次 `[0.2111, 0.2093, 0.2108]s`，中位数 **`0.2108s`**（卡死超时 `30.0s`）。
  - 另附 `reports/m4-cfg-acceptance.{txt,json}` 中 `standard` 联跑轮次的 `perf` 记录（测前 `load averages: 5.56 5.25 4.65`、测后 `5.65 5.28 4.66`）：`ssh` 全文件中位数 `0.3372s`（`[0.3434, 0.3372, 0.335]s`）、`vim` 全文件中位数 `1.9073s`（`[1.9153, 1.7909, 1.9073]s`）、`ssh --symbol _entry` 单函数中位数 `0.2066s`（`[0.2079, 0.2066, 0.2063]s`）。
- **第 2 段优化前后对比：**
  - **第 2 段之前**（第 1 段的引擎经导出工具建图并写 JSON——来源是总调度在第 2 段核对时测的、不在记录文件里）：`ssh` **`0.91` 秒**、`vim` **`6.63` 秒**。
  - **现在**（`reports/m4-cfg-acceptance-perf.txt`）：`ssh` **`0.3411` 秒**、`vim` **`1.9243` 秒**。

#### 2.3 不返回函数名单依据表（`Scripts/acceptance/noreturn-evidence.json`）

共对 `86` 个候选符号逐条核查 SDK 头文件、ABI 规则与语料调用点证据：
- **保留（`decision: "keep"`，共 `44` 个）：**
  - `sdk_attribute`（**`39` 个**）：SDK 头文件中显式带有 `__dead2`、`DISPATCH_NORETURN`、`XPC_NORETURN`、`OBJC_NORETURN`、`_LIBCXXABI_NORETURN`、`[[__noreturn__]]` 或 `__attribute__noreturn__` 声明（`test_m4_harnesses.py` 在本机有 SDK 时逐条核对头文件路径与行号）。
  - `abi_rule`（**`3` 个**）：`__stack_chk_fail`（Clang SSP ABI）、`_Unwind_Resume`（Itanium C++ EH ABI 清理着陆垫末尾恢复入口）、`_ZSt9terminatev`（Itanium C++ ABI `std::terminate()`）。
  - 调用点证据（**`2` 个**）：`_os_crash`、`abort_report_np`（公开 SDK 无头文件声明，语料调用点后接 `brk #0x1` 或独立跳转目标块、无顺序落入代码）。
- **删除（`decision: "remove"`，共 `42` 个）：** 包含头文件声明返回 `int` 或 `_Unwind_Reason_Code` 的 `NSApplicationMain`、`UIApplicationMain`、`_Unwind_RaiseException`、`_Unwind_ForcedUnwind`、`_Unwind_Resume_or_Rethrow`、`terminate_with_reason`、`terminate_with_payload`、`os_fault_with_payload`，总调度实测在有未结束事务时会返回的 `xpc_transaction_exit_clean`，以及公开 SDK 无不返回声明且测过语料中无直接调用点的 `33` 个 Linux / GNU `libstdc++` / Swift 运行时符号。

---

### 3. 第 3–4 行明细：`known-c` 八函数答案表与 `/bin/ls` Ghidra 12.1.4 对照差异归类

#### 3.1 `known-c` 八函数实测结果（取自 `reports/m4-cfg-acceptance-known-c.{txt,json}`）

| 符号 | 说明 | 期望块数 / 实测块数 | 期望边数 / 实测边数 | 期望循环数（嵌套深度） / 实测 | 期望跳转表数（表项数） / 实测 | 状态 |
|---|---|---:|---:|---|---|---|
| `_fn_seq` | 顺序算术（15 条指令，单块） | `1 / 1` | `0 / 0` | `0 ([]) / 0 ([])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_if_else` | `if/else` 菱形分支（含 `-O0` 落入过渡块） | `5 / 5` | `5 / 5` | `0 ([]) / 0 ([])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_while` | 单层 `while (i < n)` 循环 | `5 / 5` | `5 / 5` | `1 ([1]) / 1 ([1])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_for` | 单层 `for (i = 0; i < n; i++)` 循环（独立步进回边块） | `6 / 6` | `6 / 6` | `1 ([1]) / 1 ([1])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_nested_loop` | 双层嵌套 `for` 循环（深度 1 与 2） | `11 / 11` | `12 / 12` | `2 ([1, 2]) / 2 ([1, 2])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_switch5_dense` | 5 分支密集 `switch`（`-O0` 编成比较链，无跳转表） | `17 / 17` | `21 / 21` | `0 ([]) / 0 ([])` | `0 (0) / 0 (0)` | `PASS` |
| `_fn_switch10_jumptable` | 10 分支密集 `switch`（`-O0` 生成 10 项 32 位内联跳转表） | `14 / 14` | `23 / 23` | `0 ([]) / 0 ([])` | `1 (10) / 1 (10)` | `PASS` |
| `_fn_loop_break_continue` | 含 `continue`（跳步进块）与 `break`（跳出口块）的 `for` 循环 | `12 / 12` | `14 / 14` | `1 ([1]) / 1 ([1])` | `0 (0) / 0 (0)` | `PASS` |

#### 3.2 `/bin/ls` 与 Ghidra `12.1.4` 对照逐条差异归类（取自 `reports/m4-ghidra-differential-ls.json`）

对账汇总：`machgraph_functions = 133`，`ghidra_real_functions = 134`，`common_function_starts = 133`（`only_machgraph_starts = 0`、`only_ghidra_starts = 1`），`common_end_address_equal = 132 / 133`，`common_block_count_equal = 133 / 133`，`common_block_starts_equal = 132 / 133`，`common_exact_start_end_and_blocks_equal = 131 / 133`，`machgraph_error_count = 0`，`explained_tool_diff_count = 4`：

| # | 维度（`dimension`） | 地址 / 函数 | 分类（`category`） | 归因与原因（取自 `reports/m4-ghidra-differential-ls.json`） |
|---:|---|---|---|---|
| 1 | `function_start` | `0x1000038e8` | `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT` | `LC_FUNCTION_STARTS` 含 `0x1000038e4`（`0xd503237f` PAC/BTI 开场）而不含 `0x1000038e8`（`0xa9bf7bfd` 栈帧建立）；Ghidra 开场启发式在 PAC 指令后误切出第二个函数 `FUN_1000038e8`（`0x1000038e8..0x100003900`），MachGraph 保持完整函数 `sub_1000038e4`（`0x1000038e4..0x100003900`）。 |
| 2 | `basic_blocks` | `0x100000960`（`_entry`） | `TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION` | 在 `_entry`（两工具均为 `154` 块）中，Ghidra 将无任何分支或跳转表跳入的 switch 派发指令 `0x100000b30`（`br xN`）单独拆成 1 条指令的 `CodeBlock`；MachGraph 按标准基本块 leader 定义保持不切分。 |
| 3 | `basic_blocks` | `0x100000960`（`_entry`） | `TOOL_DIFF_MACHGRAPH_NORETURN_WRAPPER_SPLIT` | 在 `_entry` 中，`0x100000fe0` 调用已证明不返回的内部包装函数 `0x1000042ec`，MachGraph 按设计在 `0x100000fe4` 切块，而 Ghidra 未将 `noreturn` 传播给该内部包装函数。 |
| 4 | `function_end` | `0x1000038e4` | `TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION` | 与第 1 条成对出现：因 Ghidra 在 `0x1000038e8` 误切，其 `FUN_1000038e4` 被截短为 4 字节（`0x1000038e4..0x1000038e8`），MachGraph 保留完整范围 `0x1000038e4..0x100003900`。 |

---

### 4. 第 6 行明细：`m4-mutations.sh` 九条破坏性变异实测记录

`Scripts/acceptance/m4-mutations.sh` 在 `mktemp -d` 临时目录中拷贝源码（不改动工作树与 `.git`），先编译未变异 release 二进制并通过基线自检，随后逐一打入 `Scripts/acceptance/mutations/m4-*.patch`、增量编译 release、运行最小档位的 `m4-cfg-acceptance.py --machgraph <tmp>/.build/release/MachGraph` 子检查并校验非零退出码与预期差异类型，每次反向还原后用 `diff -qr` 校验 `Sources/` 与工作树逐字节一致。本段实测 **`9 / 9` 全部抓获**：

| 变异 | 补丁文件（`Scripts/acceptance/mutations/`） | 修改位置 | 执行命令（均传 `--machgraph <tmp>/.build/release/MachGraph`） | 失败项与退出码 | 本段实测捕获差异摘要 |
|---|---|---|---|---|---|
| **1** | `m4-01-function-starts-drop-last.patch` | `FunctionBoundaryAndJumpTableAnalyzer.swift:556`（丢弃最后一个 `LC_FUNCTION_STARTS` 起点） | `m4-cfg-acceptance.py quick --only function-starts` | `function-starts`（退出码 `1`） | `/bin/ls ref_in_text=50 vs mg=(48 text + 1 inline_jt); missing=['0x1000042ec']` |
| **2a** | `m4-02a-i1-no-split-after-b.patch` | `BasicBlockAndCFGBuilder.swift:679`（无条件 `b` 后不插入 `idx + 1` leader） | `m4-cfg-acceptance.py <tmp>/untargeted_after_b_fixture /bin/ls --only invariants` | `invariants`（退出码 `1`） | `I1 violations=1: INTERIOR_TERMINATOR in _unreach_after_b blockID=0 pc=0x100000330 insnKind=b` |
| **2b** | `m4-02b-i1-no-split-after-bcond.patch` | `BasicBlockAndCFGBuilder.swift:687`（条件分支后不插入 `idx + 1` leader） | `m4-cfg-acceptance.py quick --only invariants` | `invariants`（退出码 `1`） | `/bin/ls I1 violations=338 (total_diffs=338): INTERIOR_TERMINATOR in sub_10000071c blockID=4 pc=0x100000754 insnKind=cond_branch` |
| **3** | `m4-03-i2-cond-branch-no-leader.patch` | `BasicBlockAndCFGBuilder.swift:684`（条件分支目标不加入 `leaderIndices`） | `m4-cfg-acceptance.py quick --only invariants` | `invariants`（退出码 `1`） | `/bin/ls I2 violations=116 (total_diffs=116): INTRA_FN_COND_BRANCH_TARGET_NOT_BLOCK_START in _entry pc=0x100000a6c -> target=0x100000a84` |
| **4** | `m4-04-domtree-skip-lt-step4.patch` | `LengauerTarjanDominatorAndLoopAnalyzer.swift:1109`（注释掉 Lengauer–Tarjan 第 4 步显式修正 `idom`） | `m4-cfg-acceptance.py quick --only invariants` | `invariants`（退出码 `1`） | `/bin/ls I4 dominator violations=49: DOM_FRONTIER_MISMATCH in _entry blockID=0 reported=[118] vs expected=[]` |
| **5** | `m4-05-loops-fixed-depth-one.patch` | `LengauerTarjanDominatorAndLoopAnalyzer.swift:593`（自然循环 `nestingDepth` 固定写死为 `1`） | `m4-cfg-acceptance.py known-c` | `known-c`（退出码 `1`） | `known-c matched=7/8 (diffs=2): _fn_nested_loop loop_nesting_depths actual=[1, 1] != expected=[1, 2]` |
| **6a** | `m4-06a-switch-csel-bound-minus-one.patch` | `FunctionBoundaryAndJumpTableAnalyzer.swift:1386`（`cmp + csel` 跳转表上界减 `1`） | `m4-cfg-acceptance.py /usr/bin/ssh --only invariants` | `invariants`（退出码 `1`） | `/usr/bin/ssh I2 violations=3: INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION in sub_10000f000 tableBase=0x100012838 alignedEnd=0x1000129f4 postWord=0x00001658` |
| **6b** | `m4-06b-switch-bhi-bound-minus-one.patch` | `FunctionBoundaryAndJumpTableAnalyzer.swift:1278`（`b.hi`/`b.gt` 跳转表上界减 `1`） | `m4-cfg-acceptance.py known-c` | `known-c`（退出码 `1`） | `known-c matched=7/8: _fn_switch10_jumptable jump_table_targets actual=9 != expected=10 + INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION` |
| **7** | `m4-07-noreturn-drop-stack-chk-fail.patch` | `BasicBlockAndCFGBuilder.swift:42`（从 `KnownNoreturnSymbols` 删去 `__stack_chk_fail`） | `m4-cfg-acceptance.py /usr/bin/ssh --only invariants` | `invariants`（退出码 `1`） | `/usr/bin/ssh invariants total_diffs=29 (violations={'I1': 29, 'I2': 0, 'I3': 0, 'I4': 0}); e.g. NORETURN_CALL_HAS_SUCCESSOR in sub_100001438 pc=0x1000016bc` |

---

### 5. 总调度另测的

- 总调度自己写的检查（不在仓库里）：用 `xcrun dyld_info`、`lipo` 切片后的 `llvm-objdump` 和 `otool -Iv` 独立核对 13 个二进制的函数起点、四条不变量、支配树和不返回调用的完备性，0 违反；用一个篡改 MachGraph 输出的包装程序做了 5 条变异（`info` 少报一个起点、`cfg` 删一个函数、改错一个 `idom`、删一条落入边、清空循环），验收脚本全部抓到。
- 第 4a 段时第 7 条变异（从不返回名单里去掉 `__stack_chk_fail`）没被抓到，原因是当时的检查只验了可靠性没验完备性；第 4a2 段补上后 9/9。第 4a2 段曾把 `xpc_transaction_exit_clean` 加进名单，总调度实测它在有未结束的事务时会返回，第 4a3 段按依据表删掉，并删掉了声明会返回的 `NSApplicationMain`、`_Unwind_RaiseException` 等。

---

### 6. 没做或没验证的

- `x86_64`（只支持并验证了 `ARM64` / `ARM64e` 的 Mach-O 切片）。
- 间接跳转除内联跳转表以外的形式（如虚表派发、函数指针尾跳及其他计算跳转）。
- 名单以外的不返回函数（只认 `Scripts/acceptance/noreturn-evidence.json` 依据表中保留的 `44` 个名字；如 Swift 运行时的 `swift_unexpectedError` 因 SDK 无声明且测过语料无直接调用点未收进名单，调用后会多一条落入边）。
- Ghidra 只对照了 `/bin/ls`。
