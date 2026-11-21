# MachGraph

**[English](README.md)** | **简体中文**

面向 macOS (`arm64`) 的 Swift ARM64/ARM64e 反汇编器、控制流图（CFG）分析器、内联微型汇编器、符号解混淆器与 Universal/Mach-O 64 二进制及元数据解析工具，内置中英双语命令行（`--lang zh|en`）与 stdio JSON-RPC 2.0 MCP 服务端。

> **可复现基线（`macOS 27.0.1 (26A434) arm64`）：**
> Mach-O 容器解析、dyld 链式修正、Objective-C 元数据、内嵌代码签名哈希与 entitlements 解析、ARM64 指令解码、控制流图与支配树/自然循环恢复及交叉引用分析均由 Swift 在进程内直接读取二进制完成，不调用 `otool`、`llvm-objdump`、`nm` 或 `codesign` 等外部命令。符号解混淆（`demangle` 及符号表加载）在 macOS 本进程内直接链接调用系统 `libswiftCore` 的 `swift_demangle` 与 `libc++abi` 的 `__cxa_demangle`（不起任何子进程；仓库内的手写 Swift/Itanium C++ 解混淆器保留作回退）。
> - **`/bin/ls`（`arm64e` 切片，`M0`–`M2`，原始记录见 [`reports/m0-quick.txt`](reports/m0-quick.txt)）：** `5` 个段（segment）与 `11` 个节（section）的名称、虚拟地址、大小与文件偏移与 `otool -arch arm64e -l /bin/ls` 逐项完全一致；`__TEXT,__text` 全部 `3,846` 条指令（`2026-11-20`，`Apple LLVM 21.0.0`）与 `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=arm64e --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text /bin/ls` 对照，在**助记符归一规则为 `0` 条**（[`Scripts/acceptance/mnemonic_normalization.py`](Scripts/acceptance/mnemonic_normalization.py)）下，助记符一致数为 **`3,846 / 3,846`（`100.00%`）**，**判错 `0` 条**，**未识别指令（`.inst`）`0` 条**，按 [`Scripts/acceptance/operand_normalization.py`](Scripts/acceptance/operand_normalization.py) 的 `4` 条参考侧规则 `O1`–`O4` 比较的操作数一致数为 **`3,846 / 3,846`（`100.00%`）**。
> - **`/usr/bin/ssh`（`arm64e` 切片）：** 仅对带指令属性的节（`S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS`）解码出 **`115,546` 条指令**，非指令数据节（如 `__TEXT,__info_plist`）输出为 **`0` 行**。
> - **全量指令与操作数对照（`M2`，`2026-11-20`，`Apple LLVM 21.0.0`，[`reports/differential-full-2026-11-20.json`](reports/differential-full-2026-11-20.json)）：** 在 `/bin`、`/usr/bin`、`/usr/sbin`、`/usr/libexec` 共 `1,278` 个系统二进制（`65,969,684` 条指令，助记符归一规则 `0` 条，操作数规则 `O1`–`O4` 共 `4` 条）上，**助记符一致 `65,969,542 / 65,969,684`（总体 `99.9998%`；已识别 `65,969,542` 条中 `100.0000%`）**，**判错 `0` 条**，**未识别 `0` 条**（另有 `8` 个文件共 `142` 个字 `llvm-objdump` 同样输出 `.long`），**操作数一致 `65,969,542 / 65,969,542`（`100.0000%`，差异 `0` 条）**。
> - **全量元数据与符号解混淆对照（`M3`，`2026-11-21`，`Apple LLVM 21.0.0` 与 `cctools-1040`，[`reports/m3-metadata-full-2026-11-21.json`](reports/m3-metadata-full-2026-11-21.json)、[`reports/m3-metadata-full-2026-11-21.txt`](reports/m3-metadata-full-2026-11-21.txt)）：** 运行 `python3 -I Scripts/acceptance/m3-metadata-differential.py full --machgraph .build/release/MachGraph`，在同一批 **`1,278` 个文件**（候选 `1,281` 个，跳过无 `arm64`/`arm64e` 切片 `3` 个，崩溃 `0` 个）上**六项检查合计 `0` 处差异**：**已定义符号 `114,513 / 114,513` 条**（对照 `nm --no-dyldinfo`）、**依赖库与安装 ID `11,516 / 11,516` 条**（对照 `otool -L`）、**entitlements 顶层键 `8,152 / 8,152` 个**（`513` 个带 entitlements 文件 + `765` 个空 `{}`，对照 `codesign -a <slice> -d --entitlements :-`）、**解混淆四桶唯一符号 `117,076 / 117,076` 个**（Swift `28,982` 个对照 `swift-demangle -compact`、C++ `__Z`/`___Z`/`____Z` `12,611` 个对照 `c++filt` 逐个传参、单 `_Z` 普通 C 符号 `105` 个原样保留、其余符号 `75,378` 个原样保留；错误或半截输出 `0` 条）、**`CALL`（`bl`）交叉引用边 `7,498,057 / 7,498,057` 条**（对照覆盖全部 `S_ATTR_PURE_INSTRUCTIONS` 纯指令节的 `llvm-objdump`，全语料 `18,497,352` 条交叉引用中非字符串节 `STRING_REF` 为 `0` 条）、**Objective-C 元数据项 `155,495 / 155,495` 条**（对照 `otool -ov` 与 `otool -l`）。
> - **控制流图对照与不变量验收（`M4`，`2026-11-21`，提交 `50f1fcf`，`Apple clang 21.0.0` 与 `Apple LLVM 21.0.0`，[`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt)、[`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt)、[`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt)、[`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)）：** 在 `standard`（`ls` `50`、`ssh` `1,097`、`vim` `6,623` 个 `LC_FUNCTION_STARTS`；共 `8,408` 个函数、`150,147` 个块、`220,315` 条边）及固定种子抽样的 `full` 语料（从 `1,278` 个 `arm64`/`arm64e` 二进制抽取 `40` 个文件，跳过无 ARM64 切片 `3` 个；共 `31,981` 个函数、`258,906` 个块、`339,379` 条边）上，函数起点对账、四条不变量 `I1`–`I4`、支配树与自然循环复算均为 **`0` 违反**；`clang -O0` 现场编译的已知答案 C 函数 **`8 / 8`** 通过；`/bin/ls` 与 Ghidra `12.1.4` 对照**属于 MachGraph 的错误 `0` 条**（工具差异 `4` 条已归类）；全文件 `cfg --json` 中位数耗时 `ssh` **`0.3411` 秒**（第 2 段之前为 `0.91` 秒）、`vim` **`1.9243` 秒**（第 2 段之前为 `6.63` 秒）、`ssh --symbol _entry` 单函数 **`0.2108` 秒**（在总调度的机器上、同时有别的构建在跑时测得）。
> - **在本机复现：** 运行 `./Scripts/test.sh milestone 0`（或 `./Scripts/acceptance/m0-quick.sh`）、`./Scripts/test.sh milestone 1`、`./Scripts/test.sh milestone 2`、`./Scripts/test.sh milestone 3` 与 `./Scripts/test.sh milestone 4`。

---

## 已通过 `M0`–`M4` 验收的能力

| 领域 | 子命令 | `M0`–`M4` 已验证范围 |
|---|---|---|
| **Universal 与 Mach-O 64 容器解析及依赖库** | `info`、`segments` | 解析 Fat/Fat64 多架构切片、`mach_header_64`、`LC_SEGMENT_64` 段与节、`LC_UUID`、`LC_BUILD_VERSION`、`LC_MAIN`、`LC_ID_DYLIB`（`installID`）、`LC_FUNCTION_STARTS` 以及带三段式 `X.Y.Z` `currentVersion` 与 `compatibilityVersion` 的有序动态库依赖（文本模式与 `--json` 均完整输出）；对空文件、纯文本、截断的 Mach-O 文件以及暂不支持的 ELF `ET_REL` 可重定位目标文件均以非零退出码报错退出。 |
| **链式修正、符号、解混淆、ObjC、字符串与代码签名** | `fixups`、`symbols`、`demangle`、`objc`、`strings`、`codesign`、`entropy` | 解析 `LC_DYLD_CHAINED_FIXUPS` 绑定与重定位记录（`fixups`）；完整保留 `LC_SYMTAB` 全部有地址已定义符号（不去重同地址别名或多重集项，且不被 `[inferred:...]` 推导项覆盖，`symbols`）；在进程内通过 `swift_demangle` 与 `__cxa_demangle` 解混淆位置参数或标准输入逐行传入的 Swift 与 Itanium C++ 符号，无法解混淆或普通 C 符号原样返回（`demangle`）；解析 Objective-C 类、`±[Class sel]` 实例与类方法、成员变量、分类与协议（`objc`，支持 `--slice`）；扫描可打印字符串（`strings`）；输出整个文件的香农熵、字节卡方值、零字节占比及 1024 字节滑动窗口异常计数（`entropy`）；校验内嵌 `LC_CODE_SIGNATURE` SHA-256 `CodeDirectory` 与 CDHash，并将 XML（`0xFADE7171`）及 CoreEntitlements DER（`0xFADE7172`）槽位中的 entitlements 无损解析为原生布尔、整数、字符串、数组与嵌套字典 JSON 结构（`codesign`）。 |
| **ARM64 / ARM64e 反汇编、控制流图与交叉引用** | `disasm`、`cfg`、`cfg-dot`、`xrefs` | 仅反汇编带 `S_ATTR_PURE_INSTRUCTIONS` 或 `S_ATTR_SOME_INSTRUCTIONS` 属性的节（`disasm`，支持 `--symbol` / `--function`、`--address` 与 `--count`）；按全文件或单函数输出包含基本块、有向边、Lengauer–Tarjan 支配树、自然循环、跳转表与内联跳转表区间的结构化 `machgraph.cfg/1` JSON 或双语摘要（`cfg`，支持 `--symbol` / `--function`、`--address`、`--slice`、`--json`），并原样保留 Graphviz DOT 导出（`cfg-dot`）；查询目标传入/传出交叉引用或在省略 `--address` 与 `--symbol` 时输出全文件交叉引用整表（`xrefs`；`ADRP+ADD` / `ADR` 仅在目标位于字符串节时标 `STRING_REF`，指向可执行代码节时标 `CODE_REF`，其余数据节标 `DATA_READ`）。目标函数或地址不存在时以退出码 `1` 报错且 `stdout` 为空。 |
| **内联 ARM64 微型汇编与临时重签名** | `asm`、`patch-asm`、`resign` | `asm` 从 `--asm` 或标准输入读取 ARM64 语句并在 `--at` 起逐条汇编成机器码，不读写任何文件（退出码 `0` 全部成功，`3` 表示有合法 A64 写法汇编器还不支持，`1` 表示有写错的语句）。`patch-asm` 将汇编结果写入副本并重算 Mach-O `LC_CODE_SIGNATURE` SHA-256 页哈希完成临时重签名。`;` 只是语句分隔符（注释用 `//` 或 `/* */`）：只要有一条语句汇编不了，`patch-asm` 就以非零退出码报错，不写出文件。补丁内部盖住跳转目标、函数起点、符号或 PAC/BTI 落点时默认拒绝写入，加 `--force` 可跳过这项安全检查。 |
| **解码器与汇编器差分对照验收（`M2`）** | `disasm`、`asm` | `2026-11-21` 验收通过（见 [`reports/MachGraph-M2.md`](reports/MachGraph-M2.md) 与 [`reports/differential-full-2026-11-20.json`](reports/differential-full-2026-11-20.json)，复现命令 `./Scripts/test.sh milestone 2`），对照 `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>`（助记符归一规则 `0` 条，操作数规则 `O1`–`O4` 共 `4` 条）：`full` `1,278` 个文件实测崩溃 `0`、判错 `0`、不认识 `0`、助记符一致 `65,969,542 / 65,969,684`（`99.9998%`）、操作数一致 `100%`（`65,969,542 / 65,969,542`）；`standard`（`ls`、`ssh`、`vim`）判错 `0`、不认识 `0`、操作数一致 `707,444 / 707,444`；汇编对照 `Scripts/acceptance/asm-clang.py standard` 共 `912` 种形态中 `911` 种经 `clang` 汇编得到原机器码（`adrp` 跳过 `1` 种），`Scripts/acceptance/asm-roundtrip.py standard` 中 `M2` 之前的 `699,038` 条指令（`814` 种形态）返回 `ok`、新解码 `8,406` 条中 `ok` `6,667` 条、`unsupported` `1,739` 条（`mismatch` `0`、`error` `0`）。 |
| **元数据与符号解混淆差分对照验收（`M3`）** | `symbols`、`info`、`codesign`、`demangle`、`xrefs`、`objc` | `2026-11-21` 验收通过（`macOS 27.0.1 (26A434) arm64`，`Apple LLVM version 21.0.0`，`cctools-1040`；见 [`reports/MachGraph-M3.md`](reports/MachGraph-M3.md)、[`reports/m3-metadata-full-2026-11-21.json`](reports/m3-metadata-full-2026-11-21.json)、[`reports/m3-metadata-objc.txt`](reports/m3-metadata-objc.txt)，复现命令 `./Scripts/test.sh milestone 3`）：在 `full` `1,278` 个文件上六项检查全部 `0` 差异——`symbols` `114,513 / 114,513` 条对照 `xcrun nm --no-dyldinfo -arch <slice> <file>`；`dylibs` `11,516 / 11,516` 条对照 `xcrun otool -arch <slice> -L <file>`；`entitlements` `8,152 / 8,152` 个顶层键（`513` 个文件带 entitlements、`765` 个为空 `{}`）对照 `/usr/bin/codesign -a <slice> -d --entitlements :- <file>` 原生类型深度比较；`demangle` `117,076 / 117,076` 个唯一符号（Swift `28,982` 个 `100.00%` 对照 `xcrun swift-demangle -compact`，C++ `12,611` 个 `100.00%` 对照 `/usr/bin/c++filt` 逐个以命令行参数传入，单 `_Z` 普通 C 符号 `105` 个 `100.00%` 原样保留，其余符号 `75,378` 个 `100.00%` 原样保留；错误输出 `0` 条）；`xrefs` `7,498,057 / 7,498,057` 条 `CALL`（`bl`）边对照 `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti`（并以 `llvm-objdump --section=<seg>,<sect>` 覆盖全部非 `__TEXT,__text` 的 `S_ATTR_PURE_INSTRUCTIONS` 纯指令节），全语料 `18,497,352` 条交叉引用中非字符串节 `STRING_REF` 为 `0` 条（字符串节 `STRING_REF` `1,752,712` 条、`CODE_REF` `308,955` 条）；`objc` 在 `full` 上 `155,495 / 155,495` 条及在 `objc` 四文件语料（`Calculator.app` `62`、`assetutil` `2,378`、`screencapture` `42`、`log` `291`）上 `2,773 / 2,773` 条对照 `xcrun otool -arch <slice> -ov <file>` + `otool -arch <slice> -l <file>`。 |
| **控制流图不变量与差分对照验收（`M4`）** | `cfg`、`cfg-dot`、`info` | `2026-11-21` 于提交 `50f1fcf` 验收通过（见 [`reports/MachGraph-M4.md`](reports/MachGraph-M4.md)、[`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt)、[`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt)、[`reports/m4-cfg-acceptance-known-c.txt`](reports/m4-cfg-acceptance-known-c.txt)、[`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt)、[`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)，复现命令 `./Scripts/test.sh milestone 4`）：`standard`（`8,408` 个函数、`150,147` 个块、`220,315` 条边）与 `full`（`40` 个抽样文件、`31,981` 个函数、`258,906` 个块、`339,379` 条边）上全部 **`0` 违反**，`known-c` **`8 / 8`** 通过，`/bin/ls` 与 Ghidra `12.1.4` 对照属于 MachGraph 的错误 **`0` 条**（`4` 条工具差异已归类），`Scripts/acceptance/m4-mutations.sh` 的 **`9 / 9`** 条 CFG 变异全部抓获。详见下方「控制流图（M4）」一节。 |
| **中英双语命令行、HTML 报告与 MCP 服务端** | `export-html`、`mcp` | 支持 `--lang zh|en` 与 `MACHGRAPH_LANG=zh|en`（简体中文环境自动默认中文），导出单文件离线双语（`中文 \| EN`）HTML 分诊报告（`export-html`），并提供基于 `stdio` 的 JSON-RPC 2.0 MCP 服务端（`mcp`，所有工具调用均要求显式传入 `binaryPath`）。 |

---

## 控制流图（`M4`）

### 命令与 `machgraph.cfg/1` 输出结构
- **全文件与单函数控制流图（`cfg`）：** `machgraph cfg <binary> --json` 按起始地址升序输出全文件所有可执行节中恢复出的函数；`machgraph cfg <binary> --symbol <名字> --json`（或 `--function <名字>`、`--address <0x...>`、`--slice <序号>`）仅对匹配的那 `1` 个函数建图并输出。省略 `--json` 时输出中/英文可读摘要。目标符号或地址不存在时退出码为 `1`、`stdout` 为空；`--symbol` 与 `--address` 同时传入等参数冲突时退出码为 `2`、`stdout` 为空。
- **Graphviz DOT 导出（`cfg-dot`）：** `machgraph cfg-dot <binary> [--symbol <名字> | --address <0x...>] [--json]` 原样保留，用于导出单函数 Graphviz DOT。
- **JSON Schema（`"schema": "machgraph.cfg/1"`）：**
  - **顶层容器字段：** `filePath`、`fileName`、`isDemo`、`architecture`、`selectedSliceIndex`、`sliceFileOffset`、`lcFunctionStarts`（来自 `LC_FUNCTION_STARTS` 的 `UInt64` 虚拟地址数组）、`inlineJumpTableStarts`、`inlineJumpTableRanges`（可执行节内联跳转表的 `{start, end, size}` 字节区间）、`functionCount` 与 `functions`。
  - **函数（`functions[]`）：** `address`、`endAddress`、`name`、`demangledName`、`section`、`isStub`、`isLeaf`、`isThunk`、`usesPAC`、`cyclomaticComplexity`、`instructionCount`，以及：
    - **基本块（`blocks[]`）：** `id`、`startAddress`、`endAddress`、`isEntry`、`isExit`、`loopDepth`、`predecessorIDs`、`successorIDs`、`instructionCount`、`instructionAddresses`。
    - **有向边（`edges[]`）：** `sourceBlockID`、`targetBlockID`、`kind`（共 5 种：`unconditional`、`conditionalTrue`、`conditionalFalse`、`fallthroughEdge`、`switchCase`）、`caseValue`（`switchCase` 时为分支索引整数，其余边显式输出 `null`）、`isBackEdge`。
    - **支配树（`dominatorTree[]`）：** `blockID`、`immediateDominatorID`（入口块显式输出 `null`）、`dominatedChildrenIDs`、`dominanceFrontierIDs`、`depth`。
    - **自然循环（`naturalLoops[]`）：** `headerBlockID`、`latchBlockIDs`、`bodyBlockIDs`、`exitBlockIDs`、`nestingDepth`。
    - **跳转表（`jumpTables[]`）：** `dispatchInstructionAddress`、`tableBaseAddress`、`entryByteSize`、`isInlineInCode`、`targetAddresses`。
    - **函数内联跳转表区间（`inlineJumpTableRanges[]`）：** 从指令流和函数起点种子中剔除的 `{start, end, size}` 字节区间。

### 验证方法与独立对照物
- **函数起点对账：** [`Scripts/acceptance/m4-cfg-acceptance.py`](Scripts/acceptance/m4-cfg-acceptance.py) 自己从 Mach-O 切片解析 `LC_FUNCTION_STARTS` 并与 `xcrun dyld_info -arch <slice> -function_starts` 交叉核对：要求 `info --json` 的函数起点表与之完全相等（不含 `0x100000000` `__mh_execute_header`）；`cfg --json` 在 `__TEXT,__text` 里恢复出的函数起点 `∪` `inlineJumpTableStarts` 等于 `LC_FUNCTION_STARTS`（`0` 缺、`0` 多、互不相交）；`__TEXT,__objc_stubs` 里没有被 `brk` 填充切出来的假函数。
- **四条不变量（`I1`–`I4`）与支配树、自然循环独立复算：** 验收脚本不调用产品代码，自己直接从切片字节解码 32 位 ARM64 控制流与寻址指令、用 `xcrun otool -arch <slice> -Iv` 读取间接符号表，并用独立的数据流迭代算法求支配集与自然回边，逐函数核对 `I1`（块内无终结指令；块尾是终结指令或按 `+4` 紧邻落入下一块开头；直接 `bl` 调用确定不返回的目标后块必须结束、标 `isExit = true` 且无后继边）、`I2`（函数内分支与跳转表目标为本函数块起点，跨函数尾跳目标为函数起点；内联跳转表与指令字节不重叠且对齐末尾后紧跟的不是截短遗留的 `udf`）、`I3`（函数与块均按 4 字节对齐且不重叠，块内指令连续）、`I4`（边、前驱后继、支配树、自然循环中的块 ID 均存在且一致，`immediateDominatorID`、支配边界及含 `nestingDepth` 的 `naturalLoops` 与独立迭代求解完全相等）。
- **已知答案用例（`known-c`）：** 用 `xcrun clang -O0 -arch arm64` 现场编译 `8` 个小 C 函数（`_fn_seq`、`_fn_if_else`、`_fn_while`、`_fn_for`、`_fn_nested_loop`、`-O0` 下编成比较链且 `0` 张跳转表的 `_fn_switch5_dense`、生成 `1` 张 10 项内联跳转表的 `_fn_switch10_jumptable`、含 `break` 与 `continue` 的 `_fn_loop_break_continue`），逐项比对经 `llvm-objdump` 手工核定的块数、边数、循环数与嵌套深度、跳转表项数。
- **`/bin/ls` 与 Ghidra `12.1.4` 对照：** [`Scripts/acceptance/m4-ghidra-differential.py`](Scripts/acceptance/m4-ghidra-differential.py) 在临时工程中调用 Ghidra `12.1.4` `support/analyzeHeadless`（`AARCH64:LE:64:AppleSilicon`），对比函数起点、结束地址、`BasicBlockModel` 块数与块起点集合，差异逐条归类解释，要求属于 MachGraph 的错误为 `0` 条。
- **不返回函数名单依据：** 保留在 `KnownNoreturnSymbols` 中的全部 `44` 个名字（共核查 `86` 个候选，保留 `44` 个、删除 `42` 个）每一条都有明确依据——SDK 头文件中的不返回标记（`39` 个，单测在本机有 SDK 时逐条核对头文件与行号）、语言/编译器 ABI 规则（`3` 个：`__stack_chk_fail`、`_Unwind_Resume`、`_ZSt9terminatev`）或调用点证据（`2` 个：`_os_crash`、`abort_report_np`），见 [`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json)。

### 实测指标（`2026-11-21`，提交 `50f1fcf`）
以下数字均取自干净工作树在提交 `50f1fcf` 上录制的记录文件（`macOS 27.0.1 (26A434) arm64`，`Apple clang 21.0.0`，`Apple LLVM 21.0.0`）：
- **`standard` 语料（[`reports/m4-cfg-acceptance.txt`](reports/m4-cfg-acceptance.txt)、[`reports/m4-cfg-acceptance.json`](reports/m4-cfg-acceptance.json)，`2026-11-21T15:14:23Z`）：**
  - `/bin/ls`（`arm64e`）：函数起点 `50` 个（`__TEXT,__text` 函数 `49` + 内联跳转表 `1`），恢复函数 `133` 个、基本块 `871` 个、边 `1,110` 条（自然循环 `38` 个，不返回出口 `32` 处）。
  - `/usr/bin/ssh`（`arm64e`）：函数起点 `1,097` 个（`__TEXT,__text` 函数 `1,094` + 内联跳转表 `3`；`__objc_stubs` `10` 个），恢复函数 `1,494` 个、基本块 `18,941` 个、边 `26,513` 条（自然循环 `955` 个，不返回出口 `466` 处）。
  - `/usr/bin/vim`（`arm64e`）：函数起点 `6,623` 个（`__TEXT,__text` 函数 `6,528` + 内联跳转表 `95`；`__objc_stubs` `19` 个），恢复函数 `6,781` 个、基本块 `130,335` 个、边 `192,692` 条（自然循环 `5,200` 个，不返回出口 `582` 处）。
  - `standard` 合计（`3 / 3` 文件）：`LC_FUNCTION_STARTS` `7,770 / 7,770`，函数 `8,408` 个、基本块 `150,147` 个、边 `220,315` 条、自然循环 `6,193` 个、核验不返回出口与直接调用 `1,080 / 1,080` 处，**四条不变量 `I1`–`I4` 违反 `0` 处**、不返回完备性违反 `0` 处。
- **`known-c`（[`reports/m4-cfg-acceptance-known-c.txt`](reports/m4-cfg-acceptance-known-c.txt)、[`reports/m4-cfg-acceptance-known-c.json`](reports/m4-cfg-acceptance-known-c.json)，`2026-11-21T15:13:35Z`）：** **`8 / 8` 全部符合**，差异 `0` 处，不变量 `0` 违反。
- **`full` 语料（[`reports/m4-cfg-acceptance-full-2026-11-21.txt`](reports/m4-cfg-acceptance-full-2026-11-21.txt)、[`reports/m4-cfg-acceptance-full-2026-11-21.json`](reports/m4-cfg-acceptance-full-2026-11-21.json)，`2026-11-21T15:13:47Z`）：** 固定种子（`seed=20261121`）从 `1,278` 个 `arm64`/`arm64e` 可执行文件抽取 **`40` 个文件**（共发现 `1,281` 个 Mach-O，**跳过无 `arm64`/`arm64e` 切片 `3` 个**）：**`40 / 40` 通过**，崩溃 `0` 个，`LC_FUNCTION_STARTS` `21,945 / 21,945`（`__TEXT,__text` 函数 `21,816` + 内联跳转表 `129`；`__objc_stubs` `5,251` 个），函数 `31,981` 个、基本块 `258,906` 个、边 `339,379` 条、自然循环 `9,274` 个、不返回出口与直接调用 `4,035 / 4,035` 处，**四条不变量 `I1`–`I4` 违反 `0` 处**。
- **性能（`perf`，[`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt)、[`reports/m4-cfg-acceptance-perf.json`](reports/m4-cfg-acceptance-perf.json)，`2026-11-21T15:13:36Z`）及优化前后对比：**
  - 在总调度的机器上、同时有别的构建在跑时测得（负载见记录：测前 `load averages: 5.13 5.17 4.58`，测后 `4.88 5.12 4.57`；三次运行取中位数）：
    - `cfg /usr/bin/ssh --json`（全文件 `1,494` 个函数、`18,941` 个块）：中位数 **`0.3411` 秒**（三次 `[0.3383, 0.3411, 0.3417]` 秒）
    - `cfg /usr/bin/vim --json`（全文件 `6,781` 个函数、`130,335` 个块）：中位数 **`1.9243` 秒**（三次 `[1.9243, 1.932, 1.8299]` 秒）
    - `cfg /usr/bin/ssh --symbol _entry --json`（单函数 `1` 个函数、`729` 个块）：中位数 **`0.2108` 秒**（三次 `[0.2111, 0.2093, 0.2108]` 秒）
  - **性能前后对比：** 第 2 段之前（第 1 段的引擎经导出工具建图并写 JSON——来源是总调度在第 2 段核对时实测的、不在记录文件里）`ssh` **`0.91` 秒**、`vim` **`6.63` 秒**；现在的数字（[`reports/m4-cfg-acceptance-perf.txt`](reports/m4-cfg-acceptance-perf.txt)）为 `ssh` **`0.3411` 秒**、`vim` **`1.9243` 秒**。
- **`/bin/ls` 与 Ghidra `12.1.4` 对照（[`reports/m4-ghidra-differential-ls.json`](reports/m4-ghidra-differential-ls.json)，`2026-11-21T15:14:09Z`）：** MachGraph 恢复 `133` 个函数、Ghidra 实函数 `134` 个（共同函数起点 `133` 个，共同函数中结束地址相等 `132 / 133`、基本块数相等 `133 / 133`、基本块起点集合相等 `132 / 133`、三项全等 `131 / 133`；耗时 `9.47` 秒），共 **`4` 条差异记录（分属 `4` 类），属于 MachGraph 的错误 `0` 条（`machgraph_error_count = 0`）**：`TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT`（`1` 条，`0x1000038e8`）、`TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION`（`1` 条，`0x1000038e4`）、`TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION`（`1` 条，`_entry` `0x100000b30`）、`TOOL_DIFF_MACHGRAPH_NORETURN_WRAPPER_SPLIT`（`1` 条，`_entry` `0x100000fe4`）。

### 边界与已知限制
- **架构与容器：** 只支持 `ARM64` / `ARM64e` 的 Mach-O 切片（不支持或未验证 `x86_64` 及非 Mach-O 格式的控制流图）。
- **间接跳转：** 只认识内联/PC 相对跳转表这一类并生成 `switchCase` 边；虚表调用、函数指针尾跳及其他间接 `br` 形式不生成后继控制流边。
- **不返回函数：** 外部不返回函数只认依据表里的 `44` 个名字（[`Scripts/acceptance/noreturn-evidence.json`](Scripts/acceptance/noreturn-evidence.json)），名单以外的不返回函数调用后会多一条落入边——例如 Swift 运行时的 `swift_unexpectedError` 一类因为公开 SDK 头文件里没有不返回声明、测过的语料里也没有直接调用点而没有收进名单；不返回的内部包装函数靠调用关系可达性推出来。

---

## 系统库与外部程序调用边界说明

- **二进制与元数据解析、反汇编、内联汇编、CFG/交叉引用与代码签名（`M0`–`M4`）：** 全部由 Swift 直接读取二进制字节在进程内完成；所有命令行子命令与 `mcp` 工具均**不启动** `otool`、`llvm-objdump`、`nm`、`codesign`、`dyld_info`、`swift-demangle` 或 `c++filt` 等外部子进程（上述系统工具及 Ghidra `analyzeHeadless` 仅在 `Scripts/acceptance/` 下的外部验收对照脚本中作为独立参考答案调用）。
- **符号解混淆（`demangle` 与符号表加载）：** 在 macOS 上于**本进程内**直接链接调用系统 `libswiftCore.dylib` 的 `swift_demangle` 与 `libc++abi.dylib` 的 `__cxa_demangle`（不起任何外部子进程）；纯 Swift 手写的 `Swift5ABIDemangler` 与 `ItaniumCppDemangler` 保留在仓库内作为非 Darwin 环境或显式关闭系统运行时时的回退。
- **可选 Ghidra 无头对照后端（`Sources/MachMicroDecompiler/StructuralRegionAndPseudoCEmitter.swift` 中的 `GhidraHeadlessSideBySideBridge`）：** 包含全仓库源码中唯一一处 `Foundation.Process()` 调用，用于执行 `<ghidraInstallDir>/support/analyzeHeadless`。命令行 `decompile` 子命令与 `mcp` **从不调用**该桥接；它**仅**在桌面图形界面用户点击「`Ghidra 12.1.4 对比`」（`"Ghidra 12.1.4 Diff"`，`MachStudioViewModel.toggleOrRunGhidraComparison`）或库调用方显式调用 `GhidraHeadlessSideBySideBridge.decompileFunction` / `decompileSideBySide`，**并且** `probeInstallation()` 检测到所配置的 `GHIDRA_INSTALL_DIR` / `JAVA_HOME`（或偏好设置 / 默认路径 `~/Applications/ghidra_12.1.4_PUBLIC` 与 `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`）下同时存在可执行的 `support/analyzeHeadless`、OpenJDK 21 `bin/java` 与 Ghidra 原生 `decompile` 程序时，才会在临时目录中启动 `analyzeHeadless`。

---

## 编译与运行验收脚本

```bash
swift build --product MachGraph
./Scripts/acceptance/m0-quick.sh
./Scripts/acceptance/readme-commands.sh
```

统一测试入口（`Scripts/test.sh`）。`milestone 0`–`milestone 4` 把日志写到临时目录，不改动工作区；在干净工作区上运行 `./Scripts/test.sh milestone 4 --record` 可刷新 `reports/m4-cfg-acceptance.{json,txt}`，运行 `./Scripts/test.sh mutations` 可在隔离临时拷贝中依次执行 M3 与 M4 变异检查（`Scripts/acceptance/m3-mutations.sh` 与 `Scripts/acceptance/m4-mutations.sh`）：

```bash
./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachCFGEngine MachHeadlessCLI
./Scripts/test.sh milestone 0
./Scripts/test.sh milestone 3
./Scripts/test.sh milestone 4
```

---

## 命令行与 MCP 示例

以下每条命令均直接作用于真实二进制文件或显式输入（无隐藏演示回退；未传 `<文件>` 且未显式指定 `--demo` 时退出码为 `2`），并在 [`Scripts/acceptance/readme-commands.sh`](Scripts/acceptance/readme-commands.sh) 中逐条原样回放验证：

```bash
# 查看容器摘要（含动态库依赖）、段节映射、dyld 链式修正、符号表与原生类型 entitlements
.build/debug/MachGraph info /bin/ls
.build/debug/MachGraph info /bin/ls --json
.build/debug/MachGraph segments /bin/ls
.build/debug/MachGraph fixups /bin/ls --json
.build/debug/MachGraph symbols /bin/ls
.build/debug/MachGraph codesign /bin/ls
.build/debug/MachGraph codesign /usr/bin/ssh --json

# 在进程内解混淆 Swift 与 Itanium C++ 符号（位置参数或标准输入逐行读取）、查看 ObjC 元数据并导出全表交叉引用
.build/debug/MachGraph demangle '_$sSiN' __Z3fooi _ZeroFilesTested --json
printf '_$sSiN\n__Z12set_darkbooti.cold.1\n_main\n' | .build/debug/MachGraph demangle
.build/debug/MachGraph objc /System/Applications/Calculator.app/Contents/MacOS/Calculator --json
.build/debug/MachGraph xrefs /bin/ls --json

# 从 LC_MAIN 入口符号反汇编 /bin/ls，或按地址反汇编仓库内的真实编译样本
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10

# 为 /bin/ls 导出全文件与单函数结构化控制流图（schema machgraph.cfg/1）及保留的 Graphviz DOT
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

`M0`–`M4` 已完成并在上方列出。以下路线图事项及仓库内既有模块**尚未**完成独立参考工具对照验收，不计入上方已验证能力表：

- **M5 — MCP 工具补齐与 SwiftPM 库接口：** 为 `mcp` 增补 `mach_disasm_function`、`mach_list_symbols`、`mach_cfg`、`mach_find_strings`，并提供可独立编译运行的 SwiftPM 库调用示例。
- **实验性及 M5 前冻结模块：**
  - **伪 C 反编译器（`decompile` / `MachMicroDecompiler`）：** **实验性功能**——条件表达式、循环上下界与 `switch` 多路分支还原在真实二进制上已知不可靠。`decompile` 输出第 1 行固定打印警告（`// 【实验性】反编译输出：已知条件表达式还原不可靠，请以反汇编为准。`），分析请以 `disasm` 反汇编结果为准。（`GhidraHeadlessSideBySideBridge` 启动本地 Ghidra `analyzeHeadless` 的具体触发条件见上方「系统库与外部程序调用边界说明」。）
  - **安全审计插件（`audit-plugins` / `MachPluginSDK`）：** 基于启发式规则的 `JavaScriptCore` 插件已知存在误报与漏报，尚未完成带标准答案样本集的检出率/误报率标定。
  - **桌面图形界面（`MachStudioViews` / `MachWorkbenchShell`）、`.machproj` 工程库与非 Mach-O 加载器（`ELF64` / `PE32+` / `WASM`）：** 无参启动桌面端默认进入空状态工作台（仅提供“打开文件...”与带 `演示数据` 标记的显式演示加载），完整界面改造、持久化工程库与非 Mach-O 格式对照验收排在 `M5` 之后。

---

## 开源许可

MIT License. Copyright (c) 2026 Xu (`zxu756`).
