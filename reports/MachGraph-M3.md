## MachGraph M3 报告

### 运行环境、工具版本、提交号与实测耗时

| 项目 | 实测值 |
|---|---|
| 操作系统 | `macOS 27.0.1 (26A434) arm64` |
| 参考符号与反汇编工具 | `Apple LLVM version 21.0.0`（`xcrun nm`、`xcrun llvm-objdump`、`/usr/bin/c++filt`） |
| 参考容器与 ObjC 工具 | `llvm-otool(1): Apple Inc. version cctools-1040`（`xcrun otool`） |
| 参考代码签名与 Swift 解混淆 | `/usr/bin/codesign`、`xcrun swift-demangle -compact` |
| 编译与变异夹具工具链 | `Apple Swift version 6.4.2 (swiftlang-6.4.2.1.9 clang-2100.4.1.1)`、`xcrun clang` |
| 六项参考命令模板 | `symbols`: `xcrun nm --no-dyldinfo -arch <slice> <file>`<br>`dylibs`: `xcrun otool -arch <slice> -L <file>`<br>`entitlements`: `/usr/bin/codesign -a <slice> -d --entitlements :- <file>`<br>`demangle` (Swift): `xcrun swift-demangle -compact`（按行 `stdin`）<br>`demangle` (C++ / `_Z`): `/usr/bin/c++filt <symbol...>`（逐个以位置参数传入）<br>`xrefs`: `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti [--section=<seg>,<sect> 覆盖全部非 __TEXT,__text 的 S_ATTR_PURE_INSTRUCTIONS 节] <file>`<br>`objc`: `xcrun otool -arch <slice> -ov <file>`（配合 `xcrun otool -arch <slice> -l <file>` 取 `__objc_selrefs` 基址） |
| 分支与各段提交号 | 分支 `m3/integrate`；M2 收尾起点 `28585fc`；第 1 段 `b0861de`、`21f96c7`；同步 `v1.4.0`（`97b415a`、`da19346`、合并 `223e2c9`）；第 2 段 `d492b88`、`041cfd2`；第 3 段（`m3/objc`）`b007f25`、`1c44b0b`、`c91ccc2`（合并 `f89fe07`）；第 4 段（`m3/symbols`）`b49dd77`、`213f189`、`5d5101b`；第 5 段（`m3/xrefs`）`a87b5fc`、`95e9bb7`、`06f48ed`（合并 `a2c854b`）；第 6a 段 `8bccec7`、`d67980d`；全量报告录制 `8d5ba25`（其上叠加第 6b 段变异脚本、双语 `README` 与本报告） |
| 全量报告文件与生成时间 | `reports/m3-metadata-full-2026-11-21.json`、`reports/m3-metadata-full-2026-11-21.txt`（UTC `2026-11-21T04:25:23Z`，`machgraph_commit = d67980d4d46d48c6cf745d08879ad5075440400a`，`worktree_clean = true`）；另附 `reports/m3-metadata-standard.txt`、`reports/m3-metadata-objc.txt`（UTC `2026-11-21T04:21:15Z`） |
| 主要实测耗时 | `m3-metadata-differential.py full --record`: `246.55s`（其中 `demangle` 四桶批处理与 `--json` 抽检 `1.47s`）；`m3-metadata-differential.py standard`: `6.49s`（录制版 `6.78s`）；`m3-metadata-differential.py objc --only objc`: `0.14s`；`Scripts/test.sh milestone 3`: `78.85s`；`Scripts/acceptance/m3-mutations.sh`（8 项共 10 个补丁）: `334.70s`；`swift test --no-parallel`（288 项）: 测试执行 `7.339s`（总计 `37.29s`）；`test_m3_harnesses.py`（19 项）: `0.333s`；`test_differential_harnesses.py`（55 项）: `11.321s`；`test_asm_harnesses.py`（18 项）: `4.936s`；`Scripts/test.sh milestone 0`: `16.35s`；`milestone 1`: `80.65s`；`milestone 2`: `119.10s` |
| 隐私与路径核查 | `reports/m3-metadata-full-2026-11-21.{json,txt}`、`reports/m3-metadata-{standard,objc}.txt`、`reports/MachGraph-M3.md`、双语 `README` 与 `Scripts/acceptance/m3-mutations.sh` 扫描本机家目录绝对路径与个人邮箱均为 `0` 处命中 |

---

- **做了什么：**
  1. **符号表保真与依赖库三段式版本导出（第 1 段，`b0861de`、`21f96c7`，D-M3-3 / D-M3-5）：** `MachO64Loader.consolidateAndSizeSymbols` 完整保留 `LC_SYMTAB` 全部有地址已定义符号（不去重同地址别名或多重集项，且禁止 `objc_metadata`/`functionStarts` 等推断符号覆盖真实符号名），字符串池读取上限放宽至切片剩余长度；新增 `MachOConstants.formatDylibVersion` 固定输出 `X.Y.Z` 三段式版本号，导出 `compatibilityVersion` 与 `LC_ID_DYLIB`（`installID`），并在 `machgraph info` 文本模式打印全部依赖库；新建 `Scripts/acceptance/m3-metadata-differential.py` 与 `Scripts/acceptance/test_m3_harnesses.py`。
  2. **Entitlements 原生类型化与 CoreEntitlements DER 回退（第 2 段，`d492b88`、`041cfd2`，D-M3-7）：** 引入 `EntitlementValue` 取代把键值压成字符串的 `entitlementsPairs`；存在 `0xFADE7171` XML 槽位时经 `PropertyListSerialization` 无损解析（保留布尔/整数/浮点/数组/嵌套字典类型与前导空格键名，不再混入 `0xFADE7172` DER 槽位），仅在缺失 XML 槽位时回退解析 DER 为同一套原生类型；`machgraph codesign --json` 输出原生 `entitlements` JSON 对象。
  3. **Objective-C 元数据修复与 `machgraph objc` 子命令（第 3 段，`b007f25`、`1c44b0b`、`c91ccc2`，合并 `f89fe07`，D-M3-4）：** 修复 `ObjCAndSwiftMetadataParser` 误调符号解混淆剥除类名前导 `_` 的缺陷，将 C 字符串读取上限提升至 `16 KiB` 并拦截指向 `imageBase` 的零重定位空指针；新增结构化分类（`__objc_catlist`）与协议（`__objc_protolist`）解析；新增 `machgraph objc <file> [--slice <index>] [--json]` 子命令与双语 `--help`。
  4. **进程内 `swift_demangle` / `__cxa_demangle` 统一解混淆与 `machgraph demangle`（第 4 段，`b49dd77`、`213f189`、`5d5101b`，D-M3-1 / D-M3-2）：** 在 `MachGraphModels/SymbolDemangler.swift` 统一全仓解混淆入口，在 macOS 进程内直接调用 `libswiftCore` 的 `swift_demangle`（配 `[T]`/`[K : V]`/`T?`/`T!` 语法糖合成以对齐 `swift-demangle -compact`）与 `libc++abi` 的 `__cxa_demangle`（不起任何外部子进程，手写解析器保留作回退），严格执行“无法完整解混淆一律原样返回、普通 C 符号保留前导 `_`”守卫；新增支持位置参数与按行 `stdin` 的 `machgraph demangle [<symbol...>] [--json]` 子命令。
  5. **交叉引用全表导出、`CODE_REF` 与 G25 修复（第 5 段，`a87b5fc`、`95e9bb7`、`06f48ed`，合并 `a2c854b`，D-M3-6）：** 新增 `XrefKind.codeReference`（`CODE_REF`），修正 `A64IdiomRecognizer` 与 `BinaryAnalysisCoordinator` 对 `ADRP+ADD` / `ADR` 目标地址的节分类（仅字符串节标 `STRING_REF`，可执行代码节标 `CODE_REF`，其余数据节标 `DATA_READ`）；`machgraph xrefs <file> [--json]` 在省略 `--address` 与 `--symbol` 时输出全文件交叉引用整表。
  6. **全量联跑修补、`milestone 3` 接入、破坏性变异脚本与双语文档（第 6a–6b 段，`8bccec7`、`d67980d`、`8d5ba25` 及第 6b 段工作树改动）：** 修补 `m3-metadata-differential.py` 使其 `xrefs` 参考覆盖全部 `S_ATTR_PURE_INSTRUCTIONS` 纯指令节、为 `demangle` 补齐 `___Z`/`____Z` block 符号与第四桶“其余符号原样返回”、修复联跑失败汇总 `KeyError`；接入 `Scripts/test.sh milestone 3` 与 `release` 并录制 `reports/m3-metadata-full-2026-11-21.{json,txt}`；新建 `Scripts/acceptance/m3-mutations.sh` 与 `Scripts/acceptance/mutations/*.patch`（覆盖全部 8 项共 10 个独立变异补丁，接入 `Scripts/test.sh mutations` 与 `release`）；同步更新中英文 `README.md` / `README.zh-CN.md` 并完成全套回归。
- **跑的命令和结果：**
  - 全量六项元数据与解混淆对照（总调度在干净工作树 `d67980d` 上由 `./Scripts/test.sh milestone 3 --record` 录制于 `8d5ba25`）：`python3 -I Scripts/acceptance/m3-metadata-differential.py full --record --json-out reports/m3-metadata-full-2026-11-21.json --machgraph .build/release/MachGraph` -> 退出码 `0`（`246.55s`），候选 `1,281` 个文件、实测比较 **`1,278`** 个（跳过无 `arm64`/`arm64e` 切片 `3` 个），崩溃/超时/非零退出 **`0`** 个，六项合计差异 **`0`** 处：`symbols` `114,513 / 114,513`、`dylibs` `11,516 / 11,516`、`entitlements` `8,152 / 8,152`（`513` 个带 entitlements 文件 + `765` 个空 `{}`）、`demangle` 四桶唯一符号 `117,076 / 117,076`（Swift `28,982`、C++ `12,611`、单 `_Z` `105`、其余符号 `75,378`，一致率均为 `100.00%`，错误输出 `0`）、`xrefs` `CALL` 边 `7,498,057 / 7,498,057` 且非字符串节 `STRING_REF` 为 `0`（总引用 `18,497,352`）、`objc` `155,495 / 155,495`。
  - 里程碑 3 验收门禁：`./Scripts/test.sh milestone 3` -> 退出码 `0`（`78.85s`：5 个模块共 `229` 条范围单测、`test_m3_harnesses.py` `19` 条单测、`release` 构建、`standard` 六项 `3/3` 通过、`objc` 四文件 `4/4` 共 `2,773 / 2,773` 条通过，工作树零改动）。
  - 八项破坏性变异反证：`./Scripts/test.sh mutations`（即 `./Scripts/acceptance/m3-mutations.sh`）-> 退出码 `0`（`334.70s`），在临时拷贝中逐一注入 `1`、`2a`、`2b`、`3`、`4`、`5`、`6a`、`6b`、`7`、`8` 共 `10` 个补丁，每次运行对应 `m3-metadata-differential.py` 子检查均以退出码 `1` 失败并精确报出目标差异，还原后仓库源码零改动。
  - 全仓单测与既有里程碑回归：`python3 -I Scripts/acceptance/test_m3_harnesses.py`（`19` 项，`0.333s`）、`test_differential_harnesses.py`（`55` 项，`11.321s`）、`test_asm_harnesses.py`（`18` 项，`4.936s`）、`swift test --no-parallel`（`288` 个测试 / `17` 个套件，`7.339s`）、`./Scripts/test.sh milestone 0`（`16.35s`，含 `22` 条双语 README 命令回放）、`milestone 1`（`80.65s`）、`milestone 2`（`119.10s`）、`./Scripts/acceptance/readme-commands.sh`（`22 / 22` 通过）全部退出码 `0`。
- **没验证的项和原因：**
  - **M3 验收表草案第 1–10 行已全部完成实测验证并通过，无未验证的 M3 验收行。**
  - **按范围留待后续里程碑或本段不重跑的项：**
    1. 在本段未提交的工作树上未重复执行耗时的 `m3-metadata-differential.py full --record`（总调度已在干净工作树 `d67980d` 上执行 `milestone 3 --record` 录制并提交为 `8d5ba25`，且 `--record` 按设计拒绝存在未提交改动的工作树；第 6b 段未修改任何 `Sources/` 或 `m3-metadata-differential.py` 代码）。
    2. `nm` 中的未定义外部导入符号（`U`）在 `demangle` 四桶中已覆盖全部名称原样/解混淆核验，但导入调用点地址绑定属于 `fixups`（已在 M1 验证）；`xrefs` 中除 `bl`（`CALL`）与 `STRING_REF` 节归属之外的间接调用（`ICALL`）、跨函数尾调用（`JMP`）及基本块边界与 Ghidra 对照排在 **M4**。
    3. MCP 扩展工具与 SwiftPM 库示例排在 **M5**；伪 C 反编译器（含 `GhidraHeadlessSideBySideBridge`）、安全审计插件、桌面图形界面（未跑 `Scripts/build-app.sh`）与 `ELF64`/`PE32+`/`WASM` 加载器排在 **M5 之后**；改版本号、打 tag、推送与发布按总则规则 9 不执行。
- **待验证的假设里，哪些已证实、哪些被推翻：**
  1. **D-M3-1 进程内系统运行时解混淆（已证实）：** 进程内调用 `libswiftCore` 的 `swift_demangle`（配类型语法糖还原）与 `libc++abi` 的 `__cxa_demangle`（配 `.cold`/`.llvm` 等后缀处理）无需启动任何子进程，在 `full` 全部 `28,982` 个唯一 Swift 符号与 `12,611` 个唯一 C++ 符号上均达到 **`100.00%` 完全相等、错误输出 `0` 条**（远高于 `99%` 门禁线）。
  2. **`nm --no-dyldinfo` 与不带该标志的 Swift 符号计数差异（已核实）：** 开工前核对初算 Swift 唯一符号为 `29,768` 个（使用了未加 `--no-dyldinfo` 的 `nm`，混入仅存于 dyld 导出树中的符号）；按 D-M3-3 统一采用 `nm --no-dyldinfo` 后，`full` 语料唯一 Swift 符号精确为 `28,982` 个，且全部四桶（`28,982 + 12,611 + 105 + 75,378 = 117,076`）互斥穷尽覆盖 `nm --no-dyldinfo` 的全部有效符号。
  3. **`c++filt` 输入方式陷阱（已证实并修正）：** `/usr/bin/c++filt` 从 `stdin` 读取时会按空白字符切分（导致 `/usr/libexec/aned` 中含 ObjC 方法空格的 `____ZZ31-[_ANEServer ...]..._block_invoke` 等 `30` 个符号被切碎原样吐回）；改为逐个通过命令行位置参数调用 `/usr/bin/c++filt <symbol...>` 后，含空格的 `____Z` block 符号亦 `100%` 准确对照。
  4. **`llvm-objdump --macho -d` 默认只反汇编 `__TEXT,__text` 的假设修正（已证实）：** 不加 `--section` 时 `llvm-objdump --macho -d` 会漏掉 `/usr/bin/auvaltool` 等 `8` 个系统二进制中的 `24` 个非 `__text` `S_ATTR_PURE_INSTRUCTIONS` 纯指令节（如 `__TEXT,__realtime`、`__TEXT,__delay_helper`、`__TEXT,__lazy_helpers`、`rosetta/runtime` 的 `runtime_*`）；由脚本纯 Python 读取节表追加非 `(__TEXT, __text)` 的 `S_ATTR_PURE_INSTRUCTIONS` `--section=<seg>,<sect>` 后，全量 `1,278` 个文件 `7,498,057` 条 `CALL` 边实现 `0` 差异。
  5. **ObjC 类名 `_` 缺陷与 G25 修复效果（已证实）：** 去除 ObjC 类名误调 `demangle` 并补齐分类/协议与 `16 KiB` 字符串上限后，`Calculator.app`、`assetutil` 及 `full` 全部 `1,278` 个文件（`155,495` 项）与 `otool -ov` `0` 差异；修复 G25 后，全量 `1,752,712` 条 `STRING_REF` 100% 落在真实字符串节，指向非字符串节的条数由上万条降为 `0` 条。
- **删掉或冻结的代码：**
  - **删除：** 删除 `Sources/MachA64Decoder/SymbolDemangler.swift` 中重复的 `1,830` 行解混淆实现（改为重导出 `MachGraphModels.SymbolDemangler`）；删除 `Sources/MachBinaryFormats/UniversalAndMachOLoader.swift` 中第 2 套 `426` 行 `MachOSymbolDemangler` 分裂实现；删除 `Sources/MachBinaryFormats/CodeSignatureAndCMSParser.swift` 中手写扁平化 XML/DER 字符串解析器及 `CodeSignatureSummary.entitlementsPairs: [String: String]`。
  - **保留回退 / 冻结：** 手写 `Swift5ABIDemangler` 与 `ItaniumCppDemangler` 合并保留在 `Sources/MachGraphModels/SymbolDemangler.swift` 中作为 `useSystemRuntime == false` 或非 Darwin 环境回退；`MachMicroDecompiler`（含 `GhidraHeadlessSideBySideBridge`）、`MachPluginSDK`、桌面端 `MachStudioViews` / `MachWorkbenchShell` 与 `ELF64` / `PE32+` / `WASM` 加载器在 M5 前继续冻结。

---

### 1. M3 验收表逐行实测结果（第 1–10 行）

| # | 检查项 | 实际执行命令 | 期望 | 实测结果 | 通过与否 |
|---:|---|---|---|---|---|
| 1 | 符号表（`standard` + `full`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py standard --machgraph .build/release/MachGraph`；全量见 `reports/m3-metadata-full-2026-11-21.json` | `full` 全部 `1,278` 个文件崩溃 `0` 个，每个文件的 `(address, name)` 已定义符号多重集与 `xcrun nm --no-dyldinfo -arch <slice>` **100% 相等** | 退出码 `0`：`standard` `3/3` 相等（`3 / 3` 条）；`full` **`1,278 / 1,278` 文件相等**，崩溃 `0`，参考与 MachGraph 均为 **`114,513 / 114,513` 条**，**`total_diffs = 0`** | **通过** |
| 2 | Swift 解混淆（`full`） | 读取 `reports/m3-metadata-full-2026-11-21.json`（`machgraph demangle` 批量 `stdin` 对照 `xcrun swift-demangle -compact`） | `full` 语料 `nm --no-dyldinfo` 全部 `_$s`/`$s`/`_$S`/`$S`/`_T0`/`__T0`/`_$e`/`$e` 唯一符号：错误/半截输出 **`0` 条**，完全相等比例 **`>= 99%`** | `full` 共 **`28,982`** 个唯一 Swift 符号：**相等 `28,982 / 28,982`（`100.00%`）**，`raw_passthrough = 0`，**`wrong = 0`**（注：草案初写 `29,768` 系未加 `--no-dyldinfo` 的计数，`nm --no-dyldinfo` 下精确为 `28,982` 个） | **通过** |
| 3 | C++ 解混淆与其余符号原样守卫（`full`） | 同第 2 行（对照 `/usr/bin/c++filt <symbol...>` 逐参数调用及原样守卫） | C++ `__Z`/`___Z`/`____Z` 错误输出 `0` 条且相等 **`>= 99%`**；单 `_Z` 普通 C 符号（`105` 个）`100%` 原样相等；第四桶其余符号 `100%` 原样返回 | C++ `__Z`/`___Z`/`____Z` 共 **`12,611`** 个唯一符号（`__Z` `12,520` + `____Z` block 符号 `91`）-> **相等 `12,611 / 12,611`（`100.00%`），`wrong = 0`**；单 `_Z` 普通 C 符号 **`105 / 105`（`100.00%`）** 原样相等，`wrong = 0`；第四桶其余符号 **`75,378 / 75,378`（`100.00%`）** 原样相等，`wrong = 0`；四桶合计 **`117,076 / 117,076`**，`--json` 抽检不一致 `0` | **通过** |
| 4 | ObjC 元数据（`objc` 四文件 + `full`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py objc --only objc --machgraph .build/release/MachGraph`；全量见 `reports/m3-metadata-full-2026-11-21.json` | `Calculator.app`（`33` 类 / `22` 方法 / `7` 协议）与 `/usr/bin/assetutil`（`118` 类 / `2,224` 方法 / `4` 分类 `26` 方法 / `10` 协议）等类名、`±[Class sel]` 方法、`±[Class(Cat) sel]` 分类方法、协议名集合与 `otool -ov` **100% 相等** | 退出码 `0`：`objc` 四文件 **`4 / 4` 相等**（`Calculator` `62/62`、`assetutil` `2,378/2,378`、`screencapture` `42/42`、`log` `291/291`，合计 **`2,773 / 2,773`**，`total_diffs = 0`）；`full` **`1,278 / 1,278` 文件相等**，合计 **`155,495 / 155,495` 项**，**`total_diffs = 0`** | **通过** |
| 5 | 依赖库（`standard` + `full`） | 同第 1 行（`machgraph info <file> --json` 与文本模式对照 `xcrun otool -arch <slice> -L`） | `full` 全部 `1,278` 个文件的有序导入库 `(installName, compatibilityVersion, currentVersion, isWeak, isReexport)` 与 `MH_DYLIB` 首行 `LC_ID_DYLIB`（`installID`）**100% 逐字相等**，且文本模式打印全部库路径 | 退出码 `0`：`standard` `3/3` 相等（`26 / 26` 条）；`full` **`1,278 / 1,278` 文件相等**，参考与 MachGraph 均为 **`11,516 / 11,516` 条**，**`total_diffs = 0`** | **通过** |
| 6 | 交叉引用与 G25（`standard` + `full`） | 同第 1 行（`machgraph xrefs <file> --json` 对照覆盖全部 `S_ATTR_PURE_INSTRUCTIONS` 节的 `llvm-objdump`） | `CALL` 的 `(fromAddress, toAddress)` 集合与参考全部 `bl` 边 **100% 相等**（`standard` `54,330 / 54,330`）；`STRING_REF` 必须落在字符串节（非字符串节条数 **`0`**），指向代码标 `CODE_REF` | 退出码 `0`：`standard` `CALL` 边 **`54,330 / 54,330`**，`non_string_section_string_refs = 0`（`CODE_REF = 675`）；`full` `1,278 / 1,278` 文件相等，`CALL` 边 **`7,498,057 / 7,498,057`**（`0` 缺失、`0` 多余、`0` 重复），全语料 `18,497,352` 条引用中 **`non_string_section_string_refs = 0`**（`CODE_REF = 308,955`） | **通过** |
| 7 | `xrefs` 非 `bl` 引用分布 | 读取 `reports/m3-metadata-standard.txt` 与 `reports/m3-metadata-full-2026-11-21.json` | 记录 `standard`（及 `full`）上各类 `XrefKind` 与字符串节引用计数（只记录） | `standard` 总计 **`219,330`** 条、`full` 总计 **`18,497,352`** 条，全部 10 类 `XrefKind` 与 6 类字符串节完整分布已记录于下文第 2 节 | **已记录** |
| 8 | Entitlements（`full` + DER 单测） | 读取 `reports/m3-metadata-full-2026-11-21.json`；运行 `BinaryFormatLoadersTests` / `PluginSDKCLIMCPAndWorkbenchTests` 中 DER-only 测试 | `full` `1,278` 个文件（`765` 个无 entitlements 为 `{}`，`513` 个带 entitlements 共 `8,152` 个顶层键）与 `/usr/bin/codesign -a <slice> -d --entitlements :-` 经 `plistlib.loads` **100% 原生类型深度相等**；DER-only（`0xFADE7172`）单测完全相等 | `full` **`1,278 / 1,278` 文件深度相等**（`513` 个非空共 **`8,152 / 8,152` 个顶层键**，`765` 个 `{}`，**`total_diffs = 0`**，含 `wifip2pd` / `wifivelocityd` 带前导空格键名）；`m3ParserDecodesDEROnlySlotIntoStructuredEntitlements` 与 `m3CLICodeSignJSONParsesDEROnlyEntitlementsSlotWithNativeTypes` 通过 | **通过** |
| 9 | 破坏性变异检查（覆盖全部 8 项共 10 个补丁） | `./Scripts/acceptance/m3-mutations.sh`（或 `./Scripts/test.sh mutations`） | 在临时拷贝逐一打入 `Scripts/acceptance/mutations/*.patch`（含 5.4 七项的 `1`、`2a`、`2b`、`3`、`4`、`5`、`6a`、`6b`、`7` 及第 `8` 项普通符号剥 `_`），每次对应验收子检查退出非 `0` 并报出预期差异；跑完工作树源码无改动 | 退出码 **`0`**：全部 **`10 / 10` 个变异补丁**各自触发对应 `m3-metadata-differential.py` 子检查以**退出码 `1`** 失败并报出目标差异，逐项还原校验通过，仓库 `Sources/` 零改动。明细见第 4 节 | **通过** |
| 10 | 回归与文档 | `python3 -I Scripts/acceptance/test_{m3,differential,asm}_harnesses.py`、`swift test --no-parallel`、`./Scripts/test.sh milestone 0`、`1`、`2`、`3`、`./Scripts/acceptance/readme-commands.sh` | 全部退出码 `0`；新增子命令 `demangle`、`objc` 及新行为写入中英文 `--help` 与 `README.md` / `README.zh-CN.md`，经 `readme-commands.sh` 回放通过 | 全部退出码 **`0`**：Python 单测 `19 + 55 + 18` 全过；`swift test --no-parallel` **`288 / 288`**（`17` 个套件）全过；`milestone 0`、`1`、`2`、`3` 全过；双语 `README` 共 **`22 / 22`** 条示例命令回放全过 | **通过** |

---

### 2. 第 7 行明细：`xrefs` 引用类型（`XrefKind`）与字符串节分布

#### 2.1 按 `XrefKind` 统计（`standard` 3 个文件 vs `full` 1,278 个文件）

| `XrefKind` | 含义 | `standard`（`ls`、`ssh`、`vim`）条数 | `full`（`1,278` 个文件）条数 |
|---|---|---:|---:|
| `CALL` | 直接函数调用（`bl`） | `54,330` | `7,498,057` |
| `BRANCH` | 条件跳转（`b.<cond>`、`cbz`/`cbnz`、`tbz`/`tbnz`） | `81,704` | `3,629,952` |
| `DATA_READ` | 非字符串数据节指针/字面量读取（含跳转表基址与全局数据 `ADRP+ADD`/`LDR`） | `26,149` | `2,679,442` |
| `JMP` | 无条件跳转（`b`，含函数内跳转、跳转表分支及跨函数尾调用） | `29,010` | `1,801,980` |
| `STRING_REF` | 字符串节引用（严格位于字符串节，`non_string_section_string_refs = 0`） | `20,230` | `1,752,712` |
| `FIXUP_PTR` | `LC_DYLD_CHAINED_FIXUPS` 重定位指针目标 | `4,028` | `734,717` |
| `CODE_REF` | 取可执行代码节地址（`ADRP+ADD` / `ADR` 指向 `__TEXT,__text` 等代码节，G25 新增） | `675` | `308,955` |
| `DATA_WRITE` | `ADRP+STR` 全局数据写入 | `2,100` | `38,890` |
| `ICALL` | 基本块内由 GOT 追踪解析出的寄存器间接调用/尾跳（`blr` / `br`） | `472` | `35,821` |
| `ADRP_PAGE` | 未配对的独立 `adrp` 页基址引用 | `632` | `16,826` |
| **合计** | `total_xrefs` | **`219,330`** | **`18,497,352`** |

#### 2.2 `STRING_REF` 落入的目标节分布（非字符串节条数均为 `0`）

| 目标节（`<segment>,<section>`） | `standard` 条数 | `full` 条数 |
|---|---:|---:|
| `__TEXT,__cstring` | `20,189` | `1,041,014` |
| `__TEXT,__objc_methname` | `29` | `323,824` |
| `__DATA_CONST,__cfstring` | `12` | `228,890` |
| `__TEXT,__oslogstring` | `0` | `158,589` |
| `__TEXT,__ustring` | `0` | `387` |
| `__AUTH_CONST,__cfstring` | `0` | `8` |
| 非字符串节（`non_string_section_string_refs`） | **`0`** | **`0`** |

---

### 3. 第 4 行明细：`objc` 专项语料与全量核对

`python3 -I Scripts/acceptance/m3-metadata-differential.py objc --only objc --machgraph .build/release/MachGraph`（记录见 `reports/m3-metadata-objc.txt`）逐文件对照 `xcrun otool -arch arm64e -ov` 与 `xcrun otool -arch arm64e -l`（取 `__objc_selrefs` 基址解析相对方法选择器）：

- `/System/Applications/Calculator.app/Contents/MacOS/Calculator`（`arm64e`）：**`62 / 62` 项完全相等**（`33` 个类、`22` 个类与实例方法、`0` 个分类、`7` 个协议，保留 `_TtC10Calculator...` 前导下划线，`0` 差异）。
- `/usr/bin/assetutil`（`arm64e`）：**`2,378 / 2,378` 项完全相等**（`118` 个类、`2,224` 个类与实例方法、`4` 个分类含 `26` 个分类方法、`10` 个协议，`0` 差异）。
- `/usr/sbin/screencapture`（`arm64e`）：**`42 / 42` 项完全相等**（`0` 差异）。
- `/usr/bin/log`（`arm64e`）：**`291 / 291` 项完全相等**（`0` 差异）。
- `full` 全量 `1,278` 个文件：**`155,495 / 155,495` 项完全相等**（`0` 差异）。

---

### 4. 第 9 行明细：八项能力（10 个补丁）破坏性变异验证记录

`Scripts/acceptance/m3-mutations.sh` 在 `mktemp -d` 临时目录中拷贝 `Package.swift`、`Sources/`、`Tests/`、`Fixtures/`（不触碰工作树源码与 `.git`），先编译未变异 release 二进制并通过基线自检（含用 `xcrun clang -arch arm64` 编出带畸形符号 `_$s9MachGraph99Truncated` 的真实 Mach-O 夹具与 `/usr/bin/archiveutil` 联跑 `demangle` 退出 `0`），再逐一应用 `Scripts/acceptance/mutations/` 下的 10 个补丁、增量重编 release、运行最小档位的 `m3-metadata-differential.py` 子检查并校验退出码非 `0` 与目标差异类型，每次完成后反向还原补丁并用 `diff -qr` 校验临时 `Sources/` 与工作树逐字节一致：

| 项 | 补丁文件（`Scripts/acceptance/mutations/`） | 修改文件与位置 | 执行命令（`--machgraph <tmp>/.build/release/MachGraph`） | 失败子检查与退出码 | 实测捕获差异摘要 |
|---|---|---|---|---|---|
| **1** | `01-symbols-skip-local.patch` | `Sources/MachBinaryFormats/UniversalAndMachOLoader.swift:1258`（`MachO64Loader.loadSlice` 加 `if binding == .local { continue }`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py /bin/csh --only symbols` | `symbols`（退出码 `1`） | `/bin/csh` `ref_items=1,550` vs `mg_items=1,107`，检出 **`443` 条缺失局部符号**（如 `0x10000285c _srcfile`、`_btell.cold.1`） |
| **2a** | `02a-swift-demangle-prefix.patch` | `Sources/MachGraphModels/SymbolDemangler.swift:170`（`demangleSwiftWithSystemRuntime` 将 `_$s` 输出的 `"Swift."` 改为 `"Swift_"`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py /usr/bin/archiveutil --only demangle` | `demangle`（退出码 `1`） | Swift 一致率跌至 **`43 / 138 = 31.1594%`（`< 99%`）** 且 **`wrong = 95`**（如 `_$s10Foundation17URLResourceValuesV13isRegularFileSbSgvg -> '... : Swift_Option...'`） |
| **2b** | `02b-swift-demangle-verbatim.patch` | `Sources/MachGraphModels/SymbolDemangler.swift:106,114`（`demangle` 对系统库拒绝的畸形 Swift 符号剥除前导 `_`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py <tmp>/truncated_swift_fixture /usr/bin/archiveutil --only demangle` | `demangle`（退出码 `1`） | Swift 一致率仍为 **`138 / 139 = 99.2806%`（`>= 99%`）**，但因 **`wrong = 1`**（`_$s9MachGraph99Truncated -> '$s9MachGraph99Truncated'`，违反“未解出必须原样返回”）独立报红拦截 |
| **3** | `03-cpp-demangle-plain-z.patch` | `Sources/MachGraphModels/SymbolDemangler.swift:131`（`demangle` 对单 `_Z` 普通 C 符号剥除前导 `_`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py /usr/bin/unzip --only demangle` | `demangle`（退出码 `1`） | `Plain C _Z` 桶 `equal = 0 / 23`、**`wrong = 23`**（首例 `_ZeroFilesTested -> 'ZeroFilesTested'`，期望原样 `'_ZeroFilesTested'`） |
| **4** | `04-objc-skip-metaclass.patch` | `Sources/MachBinaryFormats/ObjCAndSwiftMetadataParser.swift:362`（`parseObjCClass` 跳过 `metaClassVA` 类方法列表遍历） | `python3 -I Scripts/acceptance/m3-metadata-differential.py objc --only objc` | `objc`（退出码 `1`） | `matched = 3/4`，`/usr/bin/assetutil` 检出 **`total_diffs = 147`**（`ref=2,773` vs `mg=2,626`，缺失类方法如 `+[CUIEncapsulationShape defaultRoundedRectCornerRadius]`） |
| **5** | `05-dylibs-drop-zero-patch.patch` | `Sources/MachBinaryFormats/UniversalAndMachOLoader.swift:183`（`formatDylibVersion` 恢复 `if patch == 0 { return "\(major).\(minor)" }`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py standard --only dylibs` | `dylibs`（退出码 `1`） | `standard` 三个文件 **`matched = 0/3`**，**`total_diffs = 26`**（如 `/bin/ls` `/usr/lib/libutil.dylib` `mg='1.0'` vs `otool='1.0.0'` 及 `libSystem.B.dylib` 缺 `.0`） |
| **6a** | `06a-xrefs-skip-auth-stubs.patch` | `Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift:1444`（`buildCrossReferenceTable` 跳过目标在 `__auth_stubs` 的 `.directCall`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py quick --only xrefs` | `xrefs`（退出码 `1`） | `/bin/ls` `CALL` 边 `ref = 275` vs `mg = 41`，检出 **`234` 条缺失 `bl` 调用边**（如 `0x1000009bc -> 0x1000046b8`） |
| **6b** | `06b-xrefs-g25-string-ref.patch` | `Sources/MachA64Decoder/A64SequenceIdiomsRecognizer.swift:347` + `Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift:1426`（恢复 `ADRP+ADD` 无条件标 `.stringReference`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py quick --only xrefs` | `xrefs`（退出码 `1`） | `/bin/ls` 检出 **`non_string_section_string_refs = 179`** 条落在字符串节之外的非法 `STRING_REF`（含指向 `__TEXT,__text` 与 `__DATA,__common` 的条目，如 `0x100000760 -> 0x10000c02c`） |
| **7** | `07-entitlements-bool-as-string.patch` | `Sources/MachBinaryFormats/CodeSignatureAndCMSParser.swift:465`（`convertPropertyListValue` 将 `CFBoolean` 转为字符串 `"true"`/`"false"`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py /usr/libexec/wifip2pd /bin/ps --only entitlements` | `entitlements`（退出码 `1`） | 两个文件 **`matched = 0/2`**，**`total_diffs = 45`**（如 `/usr/libexec/wifip2pd` 键 `' com.apple.security.app-sandbox'`: `ref=True (bool) != mg='true' (str)`） |
| **8** | `08-demangle-strip-other-underscore.patch` | `Sources/MachGraphModels/SymbolDemangler.swift:143`（`demangle` 末尾普通符号分支剥除单前导 `_`，使 `_main -> main`） | `python3 -I Scripts/acceptance/m3-metadata-differential.py /bin/csh --only demangle` | `demangle`（退出码 `1`） | 前三桶（Swift、C++、单 `_Z`）保持 `100.00%`（`wrong=0`），**仅新增第四桶 `Other verbatim` 检出 `wrong = 1,687`**（`equal = 15 / 1,702`，如 `_ActionFlag -> 'ActionFlag'`、`_main -> 'main'`） |

---

### 5. 系统库与外部程序调用边界核查

1. **纯进程内二进制解析路径（`M0`–`M3`）：** 容器结构、段节映射、dyld 链式修正、内嵌代码签名页哈希与 XML/DER entitlements、ARM64 解码与内联汇编、CFG/交叉引用与 Objective-C 元数据全部在进程内由 Swift 直接解析二进制字节，不启动 `otool`、`llvm-objdump`、`nm`、`codesign`、`swift-demangle` 或 `c++filt` 子进程。
2. **进程内系统运行时解混淆（`Sources/MachGraphModels/SymbolDemangler.swift`）：** 在 macOS 上通过 `@_silgen_name("swift_demangle")` 与 `@_silgen_name("__cxa_demangle")` 直接调用本进程已链接的 `libswiftCore.dylib` 与 `libc++abi.dylib`（不起任何子进程），手写解析器保留作回退。
3. **可选 Ghidra 无头对照桥接（`Sources/MachMicroDecompiler/StructuralRegionAndPseudoCEmitter.swift:2515-2815`）：** `GhidraHeadlessSideBySideBridge.runHeadlessDecompile` 含仓库 `Sources/` 中唯一一处 `Foundation.Process()`（第 `2771` 行），调用 `<ghidraInstallDir>/support/analyzeHeadless`。命令行 `decompile` 及所有其他 CLI 子命令、`mcp` 均从不调用该桥接；它仅在桌面图形界面用户点击「`Ghidra 12.1.4 对比`」按钮（`MachStudioViewModel.toggleOrRunGhidraComparison`）或库调用方显式调用 `GhidraHeadlessSideBySideBridge.decompileFunction` / `decompileSideBySide`，且 `probeInstallation()` 确认本地同时存在可执行的 `support/analyzeHeadless`、OpenJDK 21 `bin/java` 与 Ghidra 原生 `decompile` 二进制时才会启动。
