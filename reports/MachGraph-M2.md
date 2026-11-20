## MachGraph M2 报告

### 运行环境、工具版本、提交号与实测耗时

| 项目 | 实测值 |
|---|---|
| 操作系统 | `macOS 27.0.1 (26A434) arm64` |
| 参考反汇编工具 | `Apple LLVM version 21.0.0 (Optimized build)`（`xcrun llvm-objdump`） |
| 独立对照汇编器 | `Apple clang version 21.0.0 (clang-2100.4.1.1)`（`xcrun clang`） |
| Swift 工具链 | `Apple Swift version 6.4.2 (swiftlang-6.4.2.1.9 clang-2100.4.1.1)` |
| 参考命令模板 | `xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands --arch=<slice> --mcpu=apple-m1 --mattr=+bti -mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>` |
| 分支与基准提交 | 分支 `m2/decoder`；`main` / `v1.3.0` 起点 `2ee33ed40320d7fd78cb2e761aecfecb1b466e8f`；三条开发线合并（`a9c7199`、`f8a0fe8`）与第 17a 段合并修整后提交 `0f35763480f3e8f12c97b8e4e3777ad3b53b418b`（其上叠加第 17b 段收尾改动） |
| 全量报告文件与生成时间 | `reports/differential-full-2026-11-20.json`（UTC `2026-11-20T20:13:41Z`，`machgraph_commit = 0f35763480f3e8f12c97b8e4e3777ad3b53b418b`，`worktree_clean = true`） |
| 主要实测耗时 | `differential.py full --record`: `387.36s`；`differential.py standard`: `3.72s`；`encoding-fuzz.py`（两颗种子各 `100,000` 字）: `0.647s` / `0.665s`；`asm-roundtrip.py standard`: `12.21s`；`asm-clang.py standard`: `7.841s`（其中 clang 汇编 `0.107s`）；`asm-clang.py Fixtures/asm-cases.s`: `0.579s`；`swift test --no-parallel`: `4.698s`；`test_differential_harnesses.py`（55 项）: `7.388s`；`test_asm_harnesses.py`（18 项）: `4.678s` |
| 隐私与路径核查 | `reports/differential-full-2026-11-20.json`、`reports/MachGraph-M2.md`、双语 `README` 及脚本测试扫描本机家目录路径与用户邮箱均为 `0` 处命中 |

---

- **做了什么：**
  1. **参考命令升级、分桶与零助记符归一（第 1–2、6 段，D-M2-1）：** 共用参考命令加入 `--no-symbolic-operands` 与 `-mllvm=-aarch64-neon-syntax=generic` 并上线启动抽样 + 逐文件通用语法后缀自检；将参考印 `.long` 且 MachGraph 印 `.inst` 的字单独分桶为 `reference_long_machgraph_inst`；在解码器直接输出 `movz`/`movn` 首选 `mov` 别名与 `udf #imm16` 后清空 `Scripts/acceptance/mnemonic_normalization.py`（`NORMALIZATION_RULES = ()`，`0` 条规则）；新建 `Scripts/acceptance/operand_normalization.py`（仅含参考侧规则 `O1`–`O4`）并在 `differential.py` 逐条比较助记符一致指令的操作数且纳入通过门禁（非 `full` 要求 `operand_mismatch == 0`，`full` 要求 `>= 99.99%`）。
  2. **逐编码表、随机字对照、解码器勘误与 31 组指令补齐（第 3–14 段，D-M2-2 / D-M2-4 / D-M2-5）：** 新建 `Scripts/acceptance/encoding-table.py`（生成并校验 `Fixtures/a64/*.tsv` 共 `56` 张逐编码参考表，每张 `<= 4,096` 行，连同 M1 两张表共 `58` 张）与 `Scripts/acceptance/encoding-fuzz.py`；修复 `G47`–`G52` 判错与操作数格式偏差（含 `bc.<cond>` 按 D-M2-4 印 `.inst`、`MRS`/`MSR` 系统寄存器全表核对）；按位域补齐开工前核对的全部 `31` 个指令组（AdvSIMD 三同宽/两杂项/移位/复制/修改立即数/`ext`/置换/查表/三异宽/按元素/跨通道/成对/单结构与多结构加载存储、标量浮点与定点/整数转换/单源/三源、PAC 数据、RCpc `ldapr*`、LSE 与排他/CASP、屏障 `sb`/`ssbb`/`pssbb`、AES/SHA1/SHA256/SHA3），全量 `1,278` 个系统二进制的未识别指令由 `38,063` 条降至 **`0` 条**，`STANDARD_UNKNOWN_CEILINGS` 全部置 `0`。 SHA512/SM3/SM4 按 D-M2-5 不做，保持 `.inst`。
  3. **结构化不支持、`machgraph asm` 与双路汇编对照（第 15–17a 段，D-M2-2 / D-M2-3）：** 新增 `MachGraphError.assemblerUnsupported(mnemonic:form:)`、自动生成的 `A64KnownMnemonics`（`727` 个助记符）及 `msr` 解码器已知屏障/PSTATE 名字闸门；新增 `machgraph asm` 命令行子命令（退出码 `0` / `3` / `1`）并接入双语 `README` 与 `readme-commands.sh`；补齐 M2 前已在 `standard` 语料中的全部 `14` 种遗漏形态（`pre-M2` `814 / 814` 种形态、`699,038 / 699,038` 条指令 `100%` 回环为原机器码）；新建 `asm-roundtrip.py`、`asm-clang.py` 与 `Fixtures/asm-cases.s`（`71` 条用例）。
  4. **里程碑收尾、全量录制、双语 README 更新与破坏性变异验证（第 17b 段）：** 补齐 `Scripts/test.sh milestone 2`；在干净工作树录制提交级全量报告 `reports/differential-full-2026-11-20.json`；将 `README.md` 与 `README.zh-CN.md` 差分对照段落同步更新为新参考命令、新全量数字与操作数一致率；逐条执行验收表第 15–17 行破坏性变异并验证全部按预期失败且还原干净。
- **跑的命令和结果：**
  - 全量指令与操作数对照：`python3 -I Scripts/acceptance/differential.py full --record --machgraph .build/release/MachGraph` -> 退出码 `0`，生成 `reports/differential-full-2026-11-20.json`（候选 `1,281`、比较 `1,278`、跳过纯 `x86_64` `3`，崩溃/失败 `0`，双向缺失或多余非 `.inst` 地址 `0`，总指令 `65,969,684`，助记符一致 `65,969,542` 即 `99.999785%`，未识别 `0`，`reference_long_machgraph_inst = 142`，`machgraph_only_inst = 2,335`，判错 `0`，操作数一致 `65,969,542 / 65,969,542` 即 `100.0000%`）。
  - 里程碑 2 验收门禁：`./Scripts/test.sh milestone 2` -> 退出码 `0`（`MachA64Decoder` + `MachHeadlessCLI` 范围单测、`55 + 18` 条 Python 脚本单测、`differential.py standard`、`encoding-table.py check --all` 56 张表、随机字两颗种子 `20261117` 与 `17`、`asm-roundtrip.py standard`、`asm-clang.py standard`、`asm-clang.py Fixtures/asm-cases.s`、`known-mnemonics.py check` 全部通过，工作树零改动）。
  - 全仓单元测试与既有里程碑回归：`swift test --no-parallel`（`261` 个测试 / `15` 个套件，退出码 `0`）、`./Scripts/test.sh milestone 0`（退出码 `0`）、`./Scripts/test.sh milestone 1`（退出码 `0`）、`python3 -I Scripts/acceptance/macho-differential.py standard --machgraph .build/release/MachGraph`（退出码 `0`）、`./Scripts/acceptance/readme-commands.sh`（`17` 条双语示例命令回放，退出码 `0`）。
  - 破坏性变异反证（验收表第 15–17 行）：向量 `add` 对调 `Vn`/`Vm`、参考命令去掉 `--no-symbolic-operands` 跑 `/bin/csh`、去掉 G52 寄存器偏移 `option` 守卫跑 `encoding-fuzz.py`、改坏 `ldp` 写回位跑 `asm-roundtrip.py quick`、向任一归一表加规则跑脚本单测——共 7 次运行全部以退出码 `1` 失败并精确报出目标指令/断言，还原后文件逐字节一致。逐行命令与输出见下文第 1–6 节。
- **没验证的项和原因：**
  - **无。** `02-machgraph.md` M2 验收表第 1–17 行（含第 18 行回归项）全部完成实测验证并通过。
  - 按路线图不在 M2 范围内的事项：操作数印符号名、完整 `LC_SYMTAB` / ObjC / 解混淆对照排在 **M3**；`udf` 控制流语义、CFG 基本块不变量、Ghidra 对照与性能剖析排在 **M4**；MCP 工具扩充、SwiftPM 库示例及新解码 AdvSIMD 形态的汇编实现排在 **M5 及之后**；打 tag、改版本号与发布动作按总则规则 9 留待用户决定。
- **待验证的假设里，哪些已证实、哪些被推翻：**
  1. **假设 1（已证实）：** 加 `--no-symbolic-operands` 与 `-mllvm=-aarch64-neon-syntax=generic` 后，第 1 段在全量 `1,278` 个文件上逐文件核对确认：除 `8` 个文件共 `142` 个 `.long` 字按设计从 `unknown` 移入 `reference_long_machgraph_inst` 外，全部 `1,278` 个文件的指令地址集合、`instructions`、`agree`、`wrong=0`、`missing=0`、`machgraph_only_inst=2,335` 逐项完全不变；`non_utf8_reference_files` 由 `4` 降为 `0`。
  2. **假设 2（已证实）：** 旧参考命令下的 `113,526` 条操作数长尾差异确系符号名，换参考命令后降为 `0` 条；第 2 段全量首测 `439,020` 条差异 100% 归属规则 1（`431,115`）、G48(a) ORR `mov`（`7,882`）与 G49（`23`）三类已知根因，修复后最终全量 `65,969,542 / 65,969,542` 操作数差异为 `0` 条（`100.0000%`）。
  3. **假设 3（已证实）：** 本机 `Apple LLVM version 21.0.0` 完整支持 `-mllvm=-aarch64-neon-syntax=generic`；`mnemonic_normalization.py` 已上线启动抽样自检与逐文件后缀检查，一旦未来工具链忽略该选项立即报错退出。
  4. **假设 4（已证实）：** 生成 `56` 张 `Fixtures/a64/*.tsv` 逐编码表时逐组核实了位域边界（如大空间移位按 `Q`/`U` 拆表、`MRS`/`MSR` 按 `op1` 拆表使每张表 `<= 4,096` 行），全部表与 `llvm-objdump` 100% 一致。
  5. **假设 5（已证实）：** 系统二进制语料中的编译器编码均为规范编码，`standard` 语料 `pre-M2` `699,038` 条指令回环 `100%` 得到原机器码（`mismatch = 0`）；而逐编码表确实存在硬件非规范编码（如 `load_store_exclusive_casp.tsv` 中 G62 `stxrb`/`stxrh` 的 `Rt2 != 31`），单测性质检查 `15b(1.a)` 按“重解码语义等价”共识别 `209` 行等价重编码。
  6. **假设 6（已证实）：** `0x0000xxxx` 改印 `udf #imm16` 且保持 `A64Mnemonic` 控制流语义不变后，`CFGDominatorsSugiyamaAndXrefsTests` 与全仓 `261` 个单元测试全部通过，未影响函数发现或跳转表识别。
  7. **假设 7（已证实）：** 全量中参考印 `.long` 的仍为那 `8` 个未去符号系统二进制共 `142` 个字（归入 `reference_long_machgraph_inst`），参考仅打警告跳过不印的仍为 `146` 个文件共 `2,335` 个字（归入 `machgraph_only_inst`），两桶内 MachGraph 均 100% 输出 `.inst`。
  8. **假设 8（已证实）：** 同一 `Apple LLVM version 21.0.0` 下 `encoding-table.py check --all` 对全部 `56` 张表复核 `mismatch = 0`，完全可重复。
- **删掉或冻结的代码：**
  - **删除：** 删除 `Scripts/acceptance/mnemonic_normalization.py` 中的全部 3 条助记符归一规则（规则 3 `darwin_vector_arrangement_suffix`、规则 1 `wide_immediate_mov`、规则 2 `permanently_undefined_udf`，现 `NORMALIZATION_RULES = ()`）；移除 `A64InstructionDecoder` 中对 Armv8.8 `bc.<cond>` 的解码分支（按 D-M2-4 照 `apple-m1` 参考输出 `.inst`）。
  - **冻结：** 第 6 条新解码出的 AdvSIMD 向量/标量指令、屏障指令、`CASP`、Crypto 与标量四源浮点在 `A64MiniAssembler` 中统一抛出结构化 `assemblerUnsupported`（按 D-M2-2 排在 M5 之后）；`SHA512`/`SM3`/`SM4`（按 D-M2-5）与 `SVE`/`SME` 保持输出 `.inst`；伪 C 反编译器（`MachMicroDecompiler`）、安全审计插件（`MachPluginSDK`）、桌面界面与 `ELF64`/`PE32+`/`WASM` 加载器在 M5 前继续冻结。

---

### 1. M2 验收表逐行实测结果（第 1–17 行，附第 18 行回归检查）

| # | 检查 | 实际执行命令 | 期望 | 实测结果 | 通过与否 |
|---:|---|---|---|---|---|
| 1 | `differential.py full --record`（新参考命令） | `python3 -I Scripts/acceptance/differential.py full --record --machgraph .build/release/MachGraph` | 崩溃 0，判错 0，两个方向都没有对不上的地址，MachGraph 多出且印非 `.inst` 的 0，每个文件参考指令数大于 0 | 退出码 `0`（写入 `reports/differential-full-2026-11-20.json`）：比较 `1,278` 个文件（候选 `1,281`，无 arm64 切片跳过 `3`），`crashes_or_failures=0`，`wrong_instructions=0`，`missing_addresses=0`，`machgraph_only_wrong_instructions=0`（`machgraph_only_inst=2,335` / `146` 个文件），`zero_instruction_reference_files=0` | **通过** |
| 2 | 同上，不认识的指令（不含参考也印 `.long` 的那一桶） | 同第 1 行（读取 `reports/differential-full-2026-11-20.json`） | 前 25 组每组 0；总数不超过 300（分母 65,969,684）；剩下的按组列出条数和例子 | 31 组全部实现，**`unknown_instructions = 0`**（前 25 组每组 `0`，剩余 6 组亦全部为 `0`；分母 `65,969,684`；`unknown_by_reference_mnemonic = []`；参考印 `.long` 且 MachGraph 印 `.inst` 单独计 `reference_long_machgraph_inst = 142`，涉 `8` 个文件） | **通过** |
| 3 | 同上，助记符一致率（一致数 / 总指令数） | 同第 1 行（读取 `reports/differential-full-2026-11-20.json`） | 不低于 99.999% | **`65,969,542 / 65,969,684 = 99.999785%`**（高于 `99.999%`；在参考识别为指令的 `65,969,542` 条上为 `100.000000%`，其余 `142` 条参考本身印 `.long`） | **通过** |
| 4 | `differential.py standard` | `python3 -I Scripts/acceptance/differential.py standard --machgraph .build/release/MachGraph` | 判错 0；ls、ssh、vim 不认识都是 0；`STANDARD_UNKNOWN_CEILINGS` 改成 0 | 退出码 `0`：`wrong=0`；`/bin/ls`（`3,846` 条）、`/usr/bin/ssh`（`113,905` 条）、`/usr/bin/vim`（`589,693` 条）的 `unknown` 均为 **`0`**（合计 `707,444 / 707,444` 一致）；`STANDARD_UNKNOWN_CEILINGS` 已改为 `{'/bin/ls': 0, '/usr/bin/ssh': 0, '/usr/bin/vim': 0}` | **通过** |
| 5 | 归一表 | `python3 -I Scripts/acceptance/test_differential_harnesses.py` | `mnemonic_normalization.py` 规则 0 条；`operand_normalization.py` 只有 O1–O4；脚本单元测试断言两张表的条数不超过这个数 | 退出码 `0`（`55 / 55` 通过）：`len(NORMALIZATION_RULES) == 0`（断言 `<= 0` 且 `== 0`）；`OPERAND_NORMALIZATION_RULES` 仅含 `['O1', 'O2', 'O3', 'O4']` 共 `4` 条（断言 `<= 4` 且 `== 4`） | **通过** |
| 6 | `standard` 操作数（助记符一致的指令里） | `python3 -I Scripts/acceptance/differential.py standard --machgraph .build/release/MachGraph` | 差异 0 条 | 退出码 `0`：`operands = 707,444 / 707,444`（`100.0000%`），**`operand_mismatch = 0`**（`ls` `3,846/3,846`、`ssh` `113,905/113,905`、`vim` `589,693/589,693`） | **通过** |
| 7 | `full` 操作数 | 同第 1 行（读取 `reports/differential-full-2026-11-20.json`） | 不低于 99.99%（分母是助记符一致的条数），剩下的每一类列出条数和例子 | **`65,969,542 / 65,969,542 = 100.000000%`**（高于 `99.99%`），**`operand_mismatch = 0`**，`operand_differences = []`（无剩余差异类） | **通过** |
| 8 | `encoding-table.py check --all` | `python3 -I Scripts/acceptance/encoding-table.py check --all --machgraph .build/release/MachGraph` | 每张表 100% 相符（助记符和操作数）；参考印 `.long` 的行 MachGraph 印 `.inst`；第 6 条实现的每一组都有表 | 退出码 `0`：全部 **`56 / 56`** 张 `Fixtures/a64/*.tsv` 表 `100%` 相符（总计 `123,699` 行，`mismatch = 0`，覆盖第 4–14 段全部修复组与 31 个指令组；参考印 `.long` 的行 MachGraph 全部印 `.inst`） | **通过** |
| 9 | `encoding-fuzz.py --seed 20261117 --count 100000` | `python3 -I Scripts/acceptance/encoding-fuzz.py --seed 20261117 --count 100000 --machgraph .build/release/MachGraph`（另加跑 `--seed 17`） | 判错 0；助记符一致的指令里操作数差异 0 | 退出码 `0`：种子 `20261117` `agree=31,180`、`both_unrecognized=68,456`、`unknown=364`、**`wrong=0`**、**`operands=31,180/31,180`（`mismatch=0`）**；种子 `17` `agree=31,086`、`both_unrecognized=68,574`、`unknown=340`、**`wrong=0`**、**`operands=31,086/31,086`（`mismatch=0`）** | **通过** |
| 10 | 同上，参考能解、MachGraph 印 `.inst` 的条数 | 同第 9 行 | 按编码组列出（只记录） | 种子 `20261117` 共 **`364` 条**（7 个编码组：`Load/store register (unprivileged)` `159`、`LDAPR/STLR (unscaled immediate)` `157`、`System register move (MRS/MSR)` `32`、`AdvSIMD scalar three-register different` `6`、`Exception generation` `6`、`Crypto SHA512/SM3/SM4` `3`、`Rotate right / Evaluate into flags` `1`）；种子 `17` 共 **`340` 条**（同 7 个组）。完整表与例子见第 2 节 | **已记录** |
| 11 | `asm-roundtrip.py standard` | `python3 -I Scripts/acceptance/asm-roundtrip.py standard --machgraph .build/release/MachGraph` | `mismatch 0`；`error 0`；M2 之前就在语料里的形态全部 `ok`；`unsupported` 只出现在第 6 条新解码的组里，按形态列出 | 退出码 `0`：总计 `707,444` 条已解码指令，**`mismatch=0`**、**`error=0`**（另 `103` 条 `.inst` 占位 `103/103 ok`）；`pre-M2` **`699,038 / 699,038` 条（规范形态 `814 / 814` 种）100% `ok`**（`unsupported=0`）；新解码 `8,406` 条（`98` 种形态）中 `udf #N` `6,667` 条 `ok`，其余 `97` 种新解码形态共 `1,739` 条报 `unsupported`（明细见第 3 节） | **通过** |
| 12 | `asm-clang.py standard` | `python3 -I Scripts/acceptance/asm-clang.py standard --machgraph .build/release/MachGraph` | 除 `adrp` 外每种形态 clang 都收，并得到原机器码（包括新解码的形态） | 退出码 `0`：共提取 `912` 种规范形态，跳过 `adrp` `1` 种，实际送交 `xcrun clang -c -arch arm64e -mcpu=apple-m1` 对照 **`911` 种形态，`matched = 911 / 911`（`100%`）**，`mismatched = 0`，`clang_rejected = 0` | **通过** |
| 13 | `asm-clang.py Fixtures/asm-cases.s` | `python3 -I Scripts/acceptance/asm-clang.py Fixtures/asm-cases.s --machgraph .build/release/MachGraph` | `machgraph asm` 报 `ok` 的每一行和 clang 逐字节相同；报 `unsupported` 的列出 | 退出码 `0`：共 `71` 条语句，`machgraph asm` 报 `ok` 且 clang 可汇编的 **`35 / 35` 行逐字节完全相同**（另 `1` 行 `adrp x8, .+4096` 因 clang 要求 GOT 重定位无法单编对照，`machgraph` 编出 `b0000008`）；报 `unsupported` 的 **`35` 行**全部为新解码组语句且 clang 接受，`failures = 0`（`mismatch = 0`，`mg_error_clang_ok = 0`）。明细见第 4 节 | **通过** |
| 14 | `differential.py full` 里每个文件的指令数、地址，和 M1 报告比 | 比对 `reports/differential-full-2026-11-20.json` 与 `reports/differential-full-2026-11-15.json` | 只因参考多解出指令而增加，有变的逐个列出（只记录） | 全部 `1,278` 个文件集合完全一致；参考指令数 `instructions` 变化的文件 **`0` 个**，双向地址差（`missing`、`machgraph_only_inst`、`machgraph_only_wrong`）变化的文件 **`0` 个**（因 M1 返工 R2/R3 已启用 `--macho --mcpu=apple-m1`，M2 新增参数不改变解码边界）；`8` 个文件共 `142` 条 `.long` 由 `unknown` 移入 `reference_long_machgraph_inst`，`480` 个文件的 `unknown`（合计 `38,063` 条）全部清零（`+37,921` 转入 `agree`）。明细见第 5 节 | **已记录** |
| 15 | 把向量 `add` 的 Vn、Vm 输出对调，跑 `differential.py standard` 和 `encoding-table.py check` | 单处修改 `Sources/MachA64Decoder/A64InstructionDecoder.swift` 第 `3858` 行后重编，分别运行两条检查，再还原 | 两个都失败，并报出 `add` 和例子；改回后 `git status` 干净 | 两条命令退出码均为 **`1`**：`differential.py standard` 报 `mismatch=128`（6 类 `add|add`，首例 `/usr/bin/ssh @ 0x10003bff4 [4e618441] machgraph='add v1.8h, v1.8h, v2.8h' vs llvm='add v1.8h, v2.8h, v1.8h'`）；`encoding-table.py check --all` 报 `Fixtures/a64/advsimd_vec_three_same.tsv mismatch=7`（全部 7 种向量宽度 `add|add`）；还原重编后受测文件 `git status` 为空。详见第 6.1 节 | **通过** |
| 16 | 去掉参考命令里的 `--no-symbolic-operands`，对 `/bin/csh` 跑 `differential.py` | 单处修改 `Scripts/acceptance/mnemonic_normalization.py` 第 `37` 行，运行 `python3 -I Scripts/acceptance/differential.py /bin/csh --machgraph .build/release/MachGraph`，再还原 | 操作数失败（符号名），不是通过 | 退出码 **`1`**（`[FAIL]`）：`/bin/csh` 检出 **`mismatch = 5,474`**（`679` 类符号名差异，首类 `bl|bl: _xcatgets != N` `458` 条，首例 `/bin/csh @ 0x100001754 [9400488f] machgraph='bl 0x100013990' vs llvm='bl _xcatgets'`）；还原后文件干净。详见第 6.2 节 | **通过** |
| 17 | 去掉 G52 寄存器偏移 `option` 检查跑 `encoding-fuzz.py`；把汇编器 `ldp` 写回位改坏跑 `asm-roundtrip.py quick`；往任一张归一表加一条跑脚本单元测试 | 分别单处修改 `A64InstructionDecoder.swift` 第 `1912` 行、`A64MiniAssembler.swift` 第 `2020` 行、`operand_normalization.py` 第 `52` 行（及 `mnemonic_normalization.py` 第 `49` 行），逐项运行并还原 | 三个都失败 | 全部以退出码 **`1`** 失败：① `encoding-fuzz.py --seed 20261117` 报 `wrong=169`（11 对 `.long != ldr/str/...`）；② `asm-roundtrip.py quick` 报 `ldp X, X, [sp], #N mismatch=10`（`[a8c66ffc] -> got [a9466ffc]`）；③ `test_differential_harnesses.py` 对操作数表 `+1` 报 `AssertionError: 5 not less than or equal to 4`，对助记符表 `+1` 报 `AssertionError: 1 not less than or equal to 0`；全部还原并重编干净。详见第 6.3 节 | **通过** |
| 18 | `swift test --no-parallel`、`Scripts/test.sh milestone 0`、`milestone 1`、`macho-differential.py standard` | 依次运行四条回归命令及 `Scripts/test.sh milestone 2`、`readme-commands.sh` | 全过 | 全部退出码 **`0`**：`swift test --no-parallel` `261 / 261` 测试通过；`milestone 0`（15 项检查 + 17 条双语 README 命令）、`milestone 1`（范围单测 + 55 条脚本单测 + `differential.py`/`macho-differential.py` 的 `quick`/`standard`）、`milestone 2`、`macho-differential.py standard`（`segments=15 sections=48 libraries=26 fixups=10,901 signed=3`）全部通过 | **通过** |

---

### 2. 第 10 行明细：随机字对照中参考能解、MachGraph 印 `.inst` 的编码组分布

这些字均属于 M2 范围之外的架构扩展或特权/非特权专有指令（非特权 `LDTR*`/`STTR*`、RCpc 非缩放立即数 `LDAPUR*`/`STLUR*`、内核实现自定义 `S0_*` 系统寄存器、标量加长饱和乘加 `SQDMLAL`/`SQDMLSL`/`SQDMULL` 补充子集、调试状态切换 `DCPS2`/`DCPS3`、D-M2-5 明确不做的 `SHA512`/`RAX1`、标志位旋转 `RMIF`），在全量 `1,278` 个系统二进制（`65,969,684` 条指令）中出现次数均为 `0`。

#### 2.1 种子 `20261117`（`count = 100,000`，`unknown = 364`）

| # | 编码组 (`encoding_group`) | 条数 | 代表例子（机器码 / `llvm-objdump` / `MachGraph`） |
|---:|---|---:|---|
| 1 | `Load/store register (unprivileged)` | `159` | `0x7890ea5d`：`ldtrsh x29, [x18, #-0xf2]` vs `.inst 0x7890ea5d` |
| 2 | `LDAPR/STLR (unscaled immediate)` | `157` | `0x19dde173`：`ldapursb w19, [x11, #-0x22]` vs `.inst 0x19dde173` |
| 3 | `System register move (MRS/MSR)` | `32` | `0xd505548f`：`msr S0_5_C5_C4_4, x15` vs `.inst 0xd505548f` |
| 4 | `AdvSIMD scalar three-register different` | `6` | `0x5e63d35c`：`sqdmull s28, h26, h3` vs `.inst 0x5e63d35c` |
| 5 | `Exception generation` | `6` | `0xd4a66983`：`dcps3 #0x334c` vs `.inst 0xd4a66983` |
| 6 | `Crypto SHA512/SM3/SM4` | `3` | `0xce788f84`：`rax1 v4.2d, v28.2d, v24.2d` vs `.inst 0xce788f84` |
| 7 | `Rotate right / Evaluate into flags` | `1` | `0xba0204a8`：`rmif x5, #0x4, #0x8` vs `.inst 0xba0204a8` |

#### 2.2 种子 `17`（`count = 100,000`，`unknown = 340`）

| # | 编码组 (`encoding_group`) | 条数 | 代表例子（机器码 / `llvm-objdump` / `MachGraph`） |
|---:|---|---:|---|
| 1 | `Load/store register (unprivileged)` | `154` | `0x38d37a5b`：`ldtrsb w27, [x18, #-0xc9]` vs `.inst 0x38d37a5b` |
| 2 | `LDAPR/STLR (unscaled immediate)` | `149` | `0x199b5175`：`ldapursb x21, [x11, #-0x4b]` vs `.inst 0x199b5175` |
| 3 | `System register move (MRS/MSR)` | `21` | `0xd507cfeb`：`msr S0_7_C12_C15_7, x11` vs `.inst 0xd507cfeb` |
| 4 | `Exception generation` | `8` | `0xd4a9e743`：`dcps3 #0x4f3a` vs `.inst 0xd4a9e743` |
| 5 | `AdvSIMD scalar three-register different` | `4` | `0x5eaf9071`：`sqdmlal d17, s3, s15` vs `.inst 0x5eaf9071` |
| 6 | `Crypto SHA512/SM3/SM4` | `3` | `0xce75869b`：`sha512h2 q27, q20, v21.2d` vs `.inst 0xce75869b` |
| 7 | `Rotate right / Evaluate into flags` | `1` | `0xba1805c2`：`rmif x14, #0x30, #0x2` vs `.inst 0xba1805c2` |

---

### 3. 第 11 行明细：`asm-roundtrip.py standard` 汇总与新解码 `unsupported` 形态清单

- **关于 `pre-M2` 规范形态数 `814` 与文档预估 `825` 的说明：** `02-machgraph.md` 开工前核对使用临时脚本并在移除规则 1（`movz`/`movn -> mov`）之前统计为 `825` 种；按 `asm-roundtrip.py`（`A64AssemblerOperandClassifier`）将立即数、向量通道数与元素下标统一归为 `N` 的规范形态定义，且第 6 段将绝大部分 `movz`/`movn` 合并输出为 `mov` 后，`Fixtures/asm/v1.3.0-inst-words.tsv`（`2ee33ed` 基线）对应的 `standard` 语料 `pre-M2` 实际共 **`814` 种规范形态（`699,038` 条指令），现 `814 / 814` 种形态、`699,038 / 699,038` 条指令全部 `ok`（`100%`）**。
- **新解码部分（`newly-decoded`）：** 共 `8,406` 条指令、`98` 种规范形态：其中第 6 段由 `.inst` 改印 `udf #imm16` 的 `udf #N` 形态共 `6,667` 条全部 `ok`；其余 **`97` 种形态（共 `1,739` 条指令）** 100% 来自第 7–13 段新解码的 AdvSIMD 向量/标量指令组，依 D-M2-2 全部返回结构化 `unsupported`（退出码 `3`），`mismatch = 0`、`error = 0`：

| # | 规范形态 (`form`) | 条数 | 首条实例（文件 @ 地址 `[机器码]` 反汇编文本） |
|---:|---|---:|---|
| 1 | `ld1 { V.h }[N], [X]` | `225` | `/usr/bin/ssh` @ `0x10003f1c8` `[0d404960]` `ld1 { v0.h }[1], [x11]` |
| 2 | `smull V.Ns, V.Nh, V.Nh` | `170` | `/usr/bin/ssh` @ `0x10003c070` `[0e68c042]` `smull v2.4s, v2.4h, v8.4h` |
| 3 | `shrn V.Nh, V.Ns, #N` | `166` | `/usr/bin/ssh` @ `0x10003c068` `[0f108421]` `shrn v1.4h, v1.4s, #0x10` |
| 4 | `mov V.h[N], V.h[N]` | `136` | `/usr/bin/ssh` @ `0x10003ef18` `[6e063465]` `mov v5.h[1], v3.h[3]` |
| 5 | `sub V.Nh, V.Nh, V.Nh` | `116` | `/usr/bin/ssh` @ `0x10003c088` `[6e618400]` `sub v0.8h, v0.8h, v1.8h` |
| 6 | `add V.Nh, V.Nh, V.Nh` | `85` | `/usr/bin/ssh` @ `0x10003bff4` `[4e618441]` `add v1.8h, v2.8h, v1.8h` |
| 7 | `mul V.Ns, V.Ns, V.Ns` | `68` | `/usr/bin/ssh` @ `0x10003c060` `[4ea49c42]` `mul v2.4s, v2.4s, v4.4s` |
| 8 | `uzp2 V.Nh, V.Nh, V.Nh` | `64` | `/usr/bin/ssh` @ `0x10003c078` `[4e425821]` `uzp2 v1.8h, v1.8h, v2.8h` |
| 9 | `smlal V.Ns, V.Nh, V.Nh` | `51` | `/usr/bin/ssh` @ `0x10003c0cc` `[0e668001]` `smlal v1.4s, v0.4h, v6.4h` |
| 10 | `sshr V.Ns, V.Ns, #N` | `46` | `/usr/bin/ssh` @ `0x10003c0d8` `[4f260442]` `sshr v2.4s, v2.4s, #0x1a` |
| 11 | `add V.Ns, V.Ns, V.Ns` | `35` | `/usr/bin/ssh` @ `0x1000441b4` `[4ea08420]` `add v0.4s, v1.4s, v0.4s` |
| 12 | `mla V.Nh, V.Nh, V.Nh` | `35` | `/usr/bin/ssh` @ `0x10003c0e4` `[4e679420]` `mla v0.8h, v1.8h, v7.8h` |
| 13 | `xtn V.Nh, V.Ns` | `33` | `/usr/bin/ssh` @ `0x10003eef0` `[0e612842]` `xtn v2.4h, v2.4s` |
| 14 | `scvtf D, D` | `31` | `/usr/bin/ssh` @ `0x100051d1c` `[5e61d800]` `scvtf d0, d0` |
| 15 | `ushll V.Ns, V.Nh, #N` | `27` | `/usr/bin/ssh` @ `0x10003c058` `[2f10a401]` `ushll v1.4s, v0.4h, #0x0` |
| 16 | `ushll2 V.Ns, V.Nh, #N` | `24` | `/usr/bin/ssh` @ `0x10003c05c` `[6f10a402]` `ushll2 v2.4s, v0.8h, #0x0` |
| 17 | `uzp1 V.Nh, V.Nh, V.Nh` | `23` | `/usr/bin/ssh` @ `0x10003c0e0` `[4e421821]` `uzp1 v1.8h, v1.8h, v2.8h` |
| 18 | `ushl V.Ns, V.Ns, V.Ns` | `20` | `/usr/bin/ssh` @ `0x10003e794` `[6ea144c7]` `ushl v7.4s, v6.4s, v1.4s` |
| 19 | `zip1 V.Nh, V.Nh, V.Nh` | `19` | `/usr/bin/ssh` @ `0x10003ef50` `[0e433884]` `zip1 v4.4h, v4.4h, v3.4h` |
| 20 | `mul V.Ns, V.Ns, V.s[N]` | `18` | `/usr/bin/ssh` @ `0x10003c980` `[4f808084]` `mul v4.4s, v4.4s, v0.s[0]` |
| 21 | `smull2 V.Ns, V.Nh, V.Nh` | `18` | `/usr/bin/ssh` @ `0x10003c07c` `[4e65c002]` `smull2 v2.4s, v0.8h, v5.8h` |
| 22 | `sub V.Ns, V.Ns, V.Ns` | `17` | `/usr/bin/ssh` @ `0x10003e7b4` `[6eb184e7]` `sub v7.4s, v7.4s, v17.4s` |
| 23 | `addhn V.Nh, V.Ns, V.Ns` | `16` | `/usr/bin/ssh` @ `0x10003f460` `[0e6c414c]` `addhn v12.4h, v10.4s, v12.4s` |
| 24 | `trn2 V.Nh, V.Nh, V.Nh` | `16` | `/usr/bin/ssh` @ `0x10003f8a0` `[0e536ab2]` `trn2 v18.4h, v21.4h, v19.4h` |
| 25 | `zip2 V.Nh, V.Nh, V.Nh` | `16` | `/usr/bin/ssh` @ `0x10003f8ac` `[0e537abb]` `zip2 v27.4h, v21.4h, v19.4h` |
| 26 | `ld1 { V.h }[N], [X], #N` | `15` | `/usr/bin/ssh` @ `0x10003f15c` `[0ddf4920]` `ld1 { v0.h }[1], [x9], #2` |
| 27 | `mvni V.Nh, #N, lsl #N` | `14` | `/usr/bin/ssh` @ `0x10003c030` `[6f00a5a7]` `mvni v7.8h, #0xd, lsl #8` |
| 28 | `ushll V.Nh, V.Nb, #N` | `12` | `/usr/bin/ssh` @ `0x100040fb8` `[2f08a4c5]` `ushll v5.8h, v6.8b, #0x0` |
| 29 | `smlal2 V.Ns, V.Nh, V.Nh` | `11` | `/usr/bin/ssh` @ `0x10003c0d4` `[4e668002]` `smlal2 v2.4s, v0.8h, v6.8h` |
| 30 | `add V.Nd, V.Nd, V.Nd` | `10` | `/usr/bin/ssh` @ `0x100040c98` `[4ee48421]` `add v1.2d, v1.2d, v4.2d` |
| 31 | `cmlt V.Nh, V.Nh, #N` | `9` | `/usr/bin/ssh` @ `0x10003d110` `[4e60a886]` `cmlt v6.8h, v4.8h, #0` |
| 32 | `sshll V.Ns, V.Nh, #N` | `9` | `/usr/bin/ssh` @ `0x10003c970` `[0f10a443]` `sshll v3.4s, v2.4h, #0x0` |
| 33 | `sshll2 V.Ns, V.Nh, #N` | `9` | `/usr/bin/ssh` @ `0x10003c974` `[4f10a444]` `sshll2 v4.4s, v2.8h, #0x0` |
| 34 | `ext V.Nb, V.Nb, V.Nb, #N` | `8` | `/usr/bin/ssh` @ `0x10003ee18` `[6e034042]` `ext v2.16b, v2.16b, v3.16b, #0x8` |
| 35 | `sshl V.Nd, V.Nd, V.Nd` | `8` | `/usr/bin/vim` @ `0x1001e2680` `[4ee14401]` `sshl v1.2d, v0.2d, v1.2d` |
| 36 | `ushll2 V.Nh, V.Nb, #N` | `8` | `/usr/bin/ssh` @ `0x100044ab8` `[6f08a400]` `ushll2 v0.8h, v0.16b, #0x0` |
| 37 | `uzp1 V.Nb, V.Nb, V.Nb` | `8` | `/usr/bin/ssh` @ `0x1000455ec` `[4e021800]` `uzp1 v0.16b, v0.16b, v2.16b` |
| 38 | `mov V.d[N], V.d[N]` | `7` | `/usr/bin/ssh` @ `0x10003ee08` `[6e180464]` `mov v4.d[1], v3.d[0]` |
| 39 | `rev64 V.Nh, V.Nh` | `7` | `/usr/bin/ssh` @ `0x100041554` `[0e600a24]` `rev64 v4.4h, v17.4h` |
| 40 | `bic V.Ns, #N` | `6` | `/usr/bin/ssh` @ `0x10002aeec` `[2f001420]` `bic v0.2s, #0x1` |
| 41 | `neg V.Nh, V.Nh` | `6` | `/usr/bin/ssh` @ `0x10003f44c` `[2e60baac]` `neg v12.4h, v21.4h` |
| 42 | `ushl V.Nh, V.Nh, V.Nh` | `6` | `/usr/bin/ssh` @ `0x10003d184` `[2e634484]` `ushl v4.4h, v4.4h, v3.4h` |
| 43 | `uzp1 V.Ns, V.Ns, V.Ns` | `6` | `/usr/bin/vim` @ `0x1000f3a08` `[4e831821]` `uzp1 v1.4s, v1.4s, v3.4s` |
| 44 | `zip1 V.Ns, V.Ns, V.Ns` | `6` | `/usr/bin/ssh` @ `0x10003eee8` `[4e843842]` `zip1 v2.4s, v2.4s, v4.4s` |
| 45 | `bit V.Nb, V.Nb, V.Nb` | `4` | `/usr/bin/ssh` @ `0x10004655c` `[6ea01c83]` `bit v3.16b, v4.16b, v0.16b` |
| 46 | `ld1 { V.s }[N], [X]` | `4` | `/usr/bin/vim` @ `0x1001e9178` `[0d409140]` `ld1 { v0.s }[1], [x10]` |
| 47 | `mov V.s[N], V.s[N]` | `4` | `/usr/bin/ssh` @ `0x1000460a8` `[6e0404a4]` `mov v4.s[0], v5.s[0]` |
| 48 | `umaxv S, V.Ns` | `4` | `/usr/bin/ssh` @ `0x10003b4e4` `[6eb0a800]` `umaxv s0, v0.4s` |
| 49 | `uzp2 V.Ns, V.Ns, V.Ns` | `4` | `/usr/bin/ssh` @ `0x100040ca8` `[4e805860]` `uzp2 v0.4s, v3.4s, v0.4s` |
| 50 | `bic V.Nb, V.Nb, V.Nb` | `3` | `/usr/bin/ssh` @ `0x1000449f4` `[4e611c00]` `bic v0.16b, v0.16b, v1.16b` |
| 51 | `bic V.Nh, #N` | `3` | `/usr/bin/ssh` @ `0x100040fa4` `[2f0797c5]` `bic v5.4h, #0xfe` |
| 52 | `movi V.Nh, #N` | `3` | `/usr/bin/ssh` @ `0x100041318` `[4f0085e2]` `movi v2.8h, #0xf` |
| 53 | `tbl V.Nb, { V.Nb }, V.Nb` | `3` | `/usr/bin/vim` @ `0x1001dbb5c` `[4e010000]` `tbl v0.16b, { v0.16b }, v1.16b` |
| 54 | `ushr V.Ns, V.Ns, #N` | `3` | `/usr/bin/vim` @ `0x1001e926c` `[6f300401]` `ushr v1.4s, v0.4s, #0x10` |
| 55 | `bic V.Nh, #N, lsl #N` | `2` | `/usr/bin/ssh` @ `0x10003ac38` `[2f07b7e0]` `bic v0.4h, #0xff, lsl #8` |
| 56 | `bif V.Nb, V.Nb, V.Nb` | `2` | `/usr/bin/vim` @ `0x10001de20` `[6ee21c20]` `bif v0.16b, v1.16b, v2.16b` |
| 57 | `ld1r { V.Nh }, [X]` | `2` | `/usr/bin/ssh` @ `0x10003ede4` `[0d40c5c4]` `ld1r { v4.4h }, [x14]` |
| 58 | `ld4 { V.Nh, V.Nh, V.Nh, V.Nh }, [X]` | `2` | `/usr/bin/ssh` @ `0x10003f13c` `[0c400535]` `ld4 { v21.4h, v22.4h, v23.4h, v24.4h }, [x9]` |
| 59 | `mla V.Ns, V.Ns, V.s[N]` | `2` | `/usr/bin/ssh` @ `0x1000447a8` `[6f800022]` `mla v2.4s, v1.4s, v0.s[0]` |
| 60 | `mul V.Nh, V.Nh, V.Nh` | `2` | `/usr/bin/ssh` @ `0x10003dd80` `[4e669c21]` `mul v1.8h, v1.8h, v6.8h` |
| 61 | `mvn V.Nb, V.Nb` | `2` | `/usr/bin/ssh` @ `0x10003b230` `[6e205800]` `mvn v0.16b, v0.16b` |
| 62 | `orr V.Nh, #N` | `2` | `/usr/bin/vim` @ `0x1000c2bf4` `[0f049400]` `orr v0.4h, #0x80` |
| 63 | `orr V.Ns, #N` | `2` | `/usr/bin/vim` @ `0x100107ec0` `[0f001440]` `orr v0.2s, #0x2` |
| 64 | `rev64 V.Ns, V.Ns` | `2` | `/usr/bin/ssh` @ `0x10004609c` `[4ea00887]` `rev64 v7.4s, v4.4s` |
| 65 | `rshrn V.Nh, V.Ns, #N` | `2` | `/usr/bin/ssh` @ `0x10003c810` `[0f158c00]` `rshrn v0.4h, v0.4s, #0xb` |
| 66 | `rshrn2 V.Nh, V.Ns, #N` | `2` | `/usr/bin/ssh` @ `0x10003c814` `[4f158c20]` `rshrn2 v0.8h, v1.4s, #0xb` |
| 67 | `shrn2 V.Nh, V.Ns, #N` | `2` | `/usr/bin/ssh` @ `0x100040cb4` `[4f1d8401]` `shrn2 v1.8h, v0.4s, #0x3` |
| 68 | `ucvtf D, D` | `2` | `/usr/bin/ssh` @ `0x100002d84` `[7e61d800]` `ucvtf d0, d0` |
| 69 | `umaxv H, V.Nh` | `2` | `/usr/bin/ssh` @ `0x1000449dc` `[2e70a842]` `umaxv h2, v2.4h` |
| 70 | `umlal V.Nd, V.Ns, V.Ns` | `2` | `/usr/bin/ssh` @ `0x10004136c` `[2ea18066]` `umlal v6.2d, v3.2s, v1.2s` |
| 71 | `umlal2 V.Nd, V.Ns, V.Ns` | `2` | `/usr/bin/ssh` @ `0x100041364` `[6ea18065]` `umlal2 v5.2d, v3.4s, v1.4s` |
| 72 | `ushl V.Nb, V.Nb, V.Nb` | `2` | `/usr/bin/ssh` @ `0x100040f6c` `[2e2044c6]` `ushl v6.8b, v6.8b, v0.8b` |
| 73 | `ushll V.Nd, V.Ns, #N` | `2` | `/usr/bin/ssh` @ `0x100040c24` `[2f20a422]` `ushll v2.2d, v1.2s, #0x0` |
| 74 | `ushll2 V.Nd, V.Ns, #N` | `2` | `/usr/bin/ssh` @ `0x100040c38` `[6f20a400]` `ushll2 v0.2d, v0.4s, #0x0` |
| 75 | `xtn V.Nb, V.Nh` | `2` | `/usr/bin/vim` @ `0x1001e26b4` `[0e212800]` `xtn v0.8b, v0.8h` |
| 76 | `add V.Nb, V.Nb, V.Nb` | `1` | `/usr/bin/vim` @ `0x1001abca8` `[4e218400]` `add v0.16b, v0.16b, v1.16b` |
| 77 | `addp D, V.Nd` | `1` | `/usr/bin/vim` @ `0x1000dbf24` `[5ef1b800]` `addp d0, v0.2d` |
| 78 | `bsl V.Nb, V.Nb, V.Nb` | `1` | `/usr/bin/vim` @ `0x1000dbf20` `[6e611c40]` `bsl v0.16b, v2.16b, v1.16b` |
| 79 | `cmgt D, D, D` | `1` | `/usr/bin/vim` @ `0x10001de30` `[5ee13402]` `cmgt d2, d0, d1` |
| 80 | `cmgt V.Nd, V.Nd, V.Nd` | `1` | `/usr/bin/vim` @ `0x10001de1c` `[4ee13402]` `cmgt v2.2d, v0.2d, v1.2d` |
| 81 | `cmgt V.Ns, V.Ns, V.Ns` | `1` | `/usr/bin/ssh` @ `0x10004653c` `[4ea13400]` `cmgt v0.4s, v0.4s, v1.4s` |
| 82 | `cmhi V.Nd, V.Nd, V.Nd` | `1` | `/usr/bin/vim` @ `0x1000dbf1c` `[6ee03460]` `cmhi v0.2d, v3.2d, v0.2d` |
| 83 | `cmhi V.Ns, V.Ns, V.Ns` | `1` | `/usr/bin/vim` @ `0x1000c4ba4` `[6ea03420]` `cmhi v0.4s, v1.4s, v0.4s` |
| 84 | `cmtst V.Ns, V.Ns, V.Ns` | `1` | `/usr/bin/ssh` @ `0x10003b4e0` `[4ea08c00]` `cmtst v0.4s, v0.4s, v0.4s` |
| 85 | `fcvtzs D, D` | `1` | `/usr/bin/vim` @ `0x1000a4fc8` `[5ee1b800]` `fcvtzs d0, d0` |
| 86 | `ld1r { V.Ns }, [X]` | `1` | `/usr/bin/vim` @ `0x1001e925c` `[4d40cac0]` `ld1r { v0.4s }, [x22]` |
| 87 | `ld2 { V.Nh, V.Nh }, [X]` | `1` | `/usr/bin/ssh` @ `0x100041a1c` `[0c408605]` `ld2 { v5.4h, v6.4h }, [x16]` |
| 88 | `mov V.b[N], V.b[N]` | `1` | `/usr/bin/ssh` @ `0x100040f88` `[6e0104a6]` `mov v6.b[0], v5.b[0]` |
| 89 | `mvni V.Ns, #N, lsl #N` | `1` | `/usr/bin/vim` @ `0x1000d2610` `[2f046408]` `mvni v8.2s, #0x80, lsl #24` |
| 90 | `smax V.Ns, V.Ns, V.Ns` | `1` | `/usr/bin/vim` @ `0x100213e84` `[0ea26421]` `smax v1.2s, v1.2s, v2.2s` |
| 91 | `smin V.Ns, V.Ns, V.Ns` | `1` | `/usr/bin/vim` @ `0x100213e90` `[0ea16c00]` `smin v0.2s, v0.2s, v1.2s` |
| 92 | `st2 { V.Ns, V.Ns }, [X]` | `1` | `/usr/bin/vim` @ `0x10011da60` `[0c008900]` `st2 { v0.2s, v1.2s }, [x8]` |
| 93 | `sub V.Nd, V.Nd, V.Nd` | `1` | `/bin/ls` @ `0x100002f94` `[6ee18401]` `sub v1.2d, v0.2d, v1.2d` |
| 94 | `ushr V.Nb, V.Nb, #N` | `1` | `/usr/bin/ssh` @ `0x100040f80` `[2f0904a5]` `ushr v5.8b, v5.8b, #0x7` |
| 95 | `ushr V.Nh, V.Nh, #N` | `1` | `/usr/bin/ssh` @ `0x10003d150` `[6f110484]` `ushr v4.8h, v4.8h, #0xf` |
| 96 | `zip1 V.Nd, V.Nd, V.Nd` | `1` | `/usr/bin/vim` @ `0x1001cd074` `[4ec53886]` `zip1 v6.2d, v4.2d, v5.2d` |
| 97 | `zip2 V.Nd, V.Nd, V.Nd` | `1` | `/usr/bin/vim` @ `0x1001cd07c` `[4ec57884]` `zip2 v4.2d, v4.2d, v5.2d` |

---

### 4. 第 13 行明细：`asm-clang.py Fixtures/asm-cases.s` 逐行分类明细

- 总语句数：`71` 条；`machgraph asm` 与 `xcrun clang -c -arch arm64e -mcpu=apple-m1` 均成功且机器码逐字节相等（`match`）：**`35` 条**；`failures`（`mismatch` 或 `mg_error_clang_ok`）：**`0` 条**。
- **`clang_unverifiable`（`1` 条）：** 第 `19` 行（`@ 0x14`）`adrp x8, .+4096`——`machgraph asm` 输出 `ok`（`b0000008`），`clang` 单文件汇编器因 Mach-O 重定位限制拒绝无 `@PAGE` 符号的相对页偏移（报 `ADR/ADRP relocations must be GOT relative`）。
- **`machgraph asm` 报 `unsupported` 且经 `clang` 独立汇编校验合法的 `35` 条新族代表语句：**

| # | 行号 | 地址 | 语句 | 规范形态 (`form`) | `clang` 机器码 |
|---:|---:|---|---|---|---|
| 1 | `44` | `0x78` | `ld1 {v0.4s}, [x0]` | `ld1 {V.Ns}, [X]` | `4c407800` |
| 2 | `45` | `0x7c` | `add v0.4s, v1.4s, v2.4s` | `add V.Ns, V.Ns, V.Ns` | `4ea28420` |
| 3 | `55` | `0x98` | `shadd v1.8b, v2.8b, v3.8b` | `shadd V.Nb, V.Nb, V.Nb` | `0e230441` |
| 4 | `57` | `0x9c` | `sqadd b1, b2, b3` | `sqadd B, B, B` | `5e230c41` |
| 5 | `59` | `0xa0` | `sdot v1.2s, v2.8b, v3.8b` | `sdot V.Ns, V.Nb, V.Nb` | `0e839441` |
| 6 | `61` | `0xa4` | `suqadd b1, b2` | `suqadd B, B` | `5e203841` |
| 7 | `63` | `0xa8` | `rev64 v1.8b, v2.8b` | `rev64 V.Nb, V.Nb` | `0e200841` |
| 8 | `65` | `0xac` | `sshr v1.8b, v2.8b, #0x8` | `sshr V.Nb, V.Nb, #N` | `0f080441` |
| 9 | `67` | `0xb0` | `ushr v1.8b, v2.8b, #0x8` | `ushr V.Nb, V.Nb, #N` | `2f080441` |
| 10 | `69` | `0xb4` | `sshr v1.16b, v2.16b, #0x8` | `sshr V.Nb, V.Nb, #N` | `4f080441` |
| 11 | `71` | `0xb8` | `ushr v1.16b, v2.16b, #0x8` | `ushr V.Nb, V.Nb, #N` | `6f080441` |
| 12 | `73` | `0xbc` | `sqshl b1, b2, #0x0` | `sqshl B, B, #N` | `5f087441` |
| 13 | `75` | `0xc0` | `sqshlu b1, b2, #0x0` | `sqshlu B, B, #N` | `7f086441` |
| 14 | `77` | `0xc4` | `scvtf s1, w2, #0x20` | `scvtf S, W, #N` | `1e028041` |
| 15 | `79` | `0xc8` | `pacdza x1` | `pacdza X` | `dac12be1` |
| 16 | `81` | `0xcc` | `ldaprb w1, [x2]` | `ldaprb W, [X]` | `38bfc041` |
| 17 | `83` | `0xd0` | `fcvtns w1, s2` | `fcvtns W, S` | `1e200041` |
| 18 | `85` | `0xd4` | `frinta s1, s2` | `frinta S, S` | `1e264041` |
| 19 | `89` | `0xd8` | `saddlv h1, v2.8b` | `saddlv H, V.Nb` | `0e303841` |
| 20 | `91` | `0xdc` | `ext v1.8b, v2.8b, v3.8b, #0x0` | `ext V.Nb, V.Nb, V.Nb, #N` | `2e030041` |
| 21 | `93` | `0xe0` | `st4 { v1.8b, v2.8b, v3.8b, v4.8b }, [x2]` | `st4 { V.Nb, V.Nb, V.Nb, V.Nb }, [X]` | `0c000041` |
| 22 | `95` | `0xe4` | `st1 { v1.b }[0], [x2]` | `st1 { V.b }[N], [X]` | `0d000041` |
| 23 | `97` | `0xe8` | `orr v1.2s, #0x0` | `orr V.Ns, #N` | `0f001401` |
| 24 | `99` | `0xec` | `uzp1 v1.8b, v2.8b, v3.8b` | `uzp1 V.Nb, V.Nb, V.Nb` | `0e031841` |
| 25 | `101` | `0xf0` | `fmla h1, h2, v3.h[0]` | `fmla H, H, V.h[N]` | `5f031041` |
| 26 | `103` | `0xf4` | `mov b1, v2.b[0]` | `mov B, V.b[N]` | `5e010441` |
| 27 | `105` | `0xf8` | `fmaxnmp h1, v2.2h` | `fmaxnmp H, V.Nh` | `5e30c841` |
| 28 | `107` | `0xfc` | `tbl v1.8b, { v2.16b }, v3.8b` | `tbl V.Nb, { V.Nb }, V.Nb` | `0e030041` |
| 29 | `109` | `0x100` | `saddl v1.8h, v2.8b, v3.8b` | `saddl V.Nh, V.Nb, V.Nb` | `0e230041` |
| 30 | `111` | `0x104` | `fmla v1.4h, v2.4h, v3.h[0]` | `fmla V.Nh, V.Nh, V.h[N]` | `0f031041` |
| 31 | `113` | `0x108` | `msr S0_3_C3_C0_0, xzr` | `msr sN_N_cN_cN_N, xzr` | `d503301f` |
| 32 | `115` | `0x10c` | `aese v1.16b, v2.16b` | `aese V.Nb, V.Nb` | `4e284841` |
| 33 | `117` | `0x110` | `sha1c q1, s2, v3.4s` | `sha1c Q, S, V.Ns` | `5e030041` |
| 34 | `119` | `0x114` | `eor3 v1.16b, v2.16b, v3.16b, v4.16b` | `eor3 V.Nb, V.Nb, V.Nb, V.Nb` | `ce031041` |
| 35 | `121` | `0x118` | `fnmadd s1, s2, s3, s4` | `fnmadd S, S, S, S` | `1f231041` |

---

### 5. 第 14 行明细：`differential.py full` 与 M1 报告逐文件对比

将本次录制的 `reports/differential-full-2026-11-20.json` 与仓库中 M1 最终提交的全量报告 `reports/differential-full-2026-11-15.json` 在全部 `1,278` 个可比 Mach-O 文件上逐项比对：

1. **文件集合与架构切片：** `1,278` 个文件路径与所选切片（`arm64e` `1,275` 个、`arm64` `3` 个）**100% 相同**。
2. **每个文件的参考指令数（`instructions`）与双向地址集合：**
   - **`instructions` 变化的文件：`0` 个**（全部 `1,278` 个文件逐文件相等，总计保持 `65,969,684` 条）；
   - **`missing`（参考有而 MachGraph 无）：** 全部文件均为 `0 -> 0`；
   - **`machgraph_only_inst`（MachGraph 有且印 `.inst`、参考跳过未印）：** **`0` 个文件变化**（保持相同的 `146` 个文件、共 `2,335` 条）；
   - **`machgraph_only_wrong`：** 全部文件均为 `0 -> 0`。
   - 说明：M1 返工 R2/R3 生成 `reports/differential-full-2026-11-15.json` 时已加入 `--macho` 与 `--mcpu=apple-m1`（当时相较未加 `--mcpu=apple-m1` 的 R1 有 `11` 个文件因参考多解出 LSE/CRC32/`eor3`/`udot` 而增加指令数，已记录于 M1 报告 R.4）；M2 在此基础上新增的 `--no-symbolic-operands` 与 `-mllvm=-aarch64-neon-syntax=generic` 仅改变操作数与通用向量打印语法，不改变任何文件的指令数或地址集合。
3. **参考印 `.long` 且 MachGraph 印 `.inst` 单独分桶的 `8` 个文件（共 `142` 条，M1 计入 `unknown`，M2 计入 `reference_long_machgraph_inst`）：**

| # | 文件路径 | 切片 | `instructions`（M1 -> M2） | `agree`（M1 -> M2） | `unknown`（M1 -> M2） | `reference_long_machgraph_inst`（M2） |
|---:|---|---|---|---|---|---:|
| 1 | `/bin/csh` | `arm64e` | `79,043 -> 79,043` | `78,946 -> 79,013` (`+67`) | `97 -> 0` | `30` |
| 2 | `/bin/zsh` | `arm64e` | `122,758 -> 122,758` | `122,704 -> 122,735` (`+31`) | `54 -> 0` | `23` |
| 3 | `/usr/bin/demandoc` | `arm64e` | `27,961 -> 27,961` | `27,959 -> 27,959` (`+0`) | `2 -> 0` | `2` |
| 4 | `/usr/bin/mandoc` | `arm64e` | `64,140 -> 64,140` | `64,117 -> 64,137` (`+20`) | `23 -> 0` | `3` |
| 5 | `/usr/bin/unzip` | `arm64e` | `23,697 -> 23,697` | `23,669 -> 23,695` (`+26`) | `28 -> 0` | `2` |
| 6 | `/usr/bin/unzipsfx` | `arm64e` | `12,090 -> 12,090` | `12,089 -> 12,089` (`+0`) | `1 -> 0` | `1` |
| 7 | `/usr/sbin/mDNSResponder` | `arm64e` | `269,593 -> 269,593` | `269,486 -> 269,566` (`+80`) | `107 -> 0` | `27` |
| 8 | `/usr/sbin/tcpdump` | `arm64e` | `155,152 -> 155,152` | `155,034 -> 155,098` (`+64`) | `118 -> 0` | `54` |

4. **解码覆盖率提升汇总：** 共 **`480` 个文件**的 `unknown` 计数由正数降为 **`0`**（其余 `798` 个文件在 M1 时已为 `unknown = 0`，全部计数保持不变）：其中 `142` 条 `.long` 归入 `reference_long_machgraph_inst`，其余全部 **`37,921` 条** M1 未识别指令现均被 MachGraph 正确解码并与 `llvm-objdump` 助记符及操作数 100% 一致（`agreed_instructions`: `65,931,621 -> 65,969,542`，`+37,921`）。

---

### 6. 第 15–17 行明细：三条破坏性变异验证记录

每次只修改单处源码，执行对应检查捕获非零退出码与错误输出后立即逐字节还原（含重编干净的 `.build/release/MachGraph`），最后校验 `git status` 无任何残留修改。

#### 6.1 第 15 行：对调向量 `add` 的 `Vn` 与 `Vm`
- **修改位置：** `Sources/MachA64Decoder/A64InstructionDecoder.swift` 第 `3858` 行（`decodeAdvSIMDVectorThreeSame` 中 `case 0b10000` 的 `!u` 即向量 `add` 分支，将操作数顺序 `[.register(vd), .register(vn), .register(vm)]` 改为 `[.register(vd), .register(vm), .register(vn)]`）。
- **运行 1：** `python3 -I Scripts/acceptance/differential.py standard --machgraph .build/release/MachGraph` -> **退出码 `1`**（失败）：
  ```text
  [FAIL] /usr/bin/ssh (arm64e): total=113905 agree=113905 (100.00%) operand_equal=113803/113905 (99.91%) unknown=0 ref_long_mg_inst=0 wrong=0 missing=0 mg_only_inst=1
  [FAIL] /usr/bin/vim (arm64e): total=589693 agree=589693 (100.00%) operand_equal=589667/589693 (100.00%) unknown=0 ref_long_mg_inst=0 wrong=0 missing=0 mg_only_inst=102
  [FAIL] Summary (standard): candidates=3 compared=3 ... operands=707316/707444 (99.9819%) mismatch=128 (files=2)
         operand difference categories (6):
           - add|add: V.8h, V.8h, V.8h != V.8h, V.8h, V.8h: count=54 files=1
               /usr/bin/ssh @ 0x10003bff4 [4e618441] machgraph='add v1.8h, v1.8h, v2.8h' vs llvm='add v1.8h, v2.8h, v1.8h'
           - add|add: V.4h, V.4h, V.4h != V.4h, V.4h, V.4h: count=31 files=1
               /usr/bin/ssh @ 0x10003ef58 [0e628462] machgraph='add v2.4h, v2.4h, v3.4h' vs llvm='add v2.4h, v3.4h, v2.4h'
  ```
- **运行 2：** `python3 -I Scripts/acceptance/encoding-table.py check --all --machgraph .build/release/MachGraph` -> **退出码 `1`**（失败）：
  ```text
  [FAIL] Fixtures/a64/advsimd_vec_three_same.tsv: total=880 matched=873 (ref_long_mg_inst=399) mismatch=7
    mismatched rows (7):
      0x0e238441  llvm='add v1.8b, v2.8b, v3.8b'   machgraph='add v1.8b, v3.8b, v2.8b'   [operand_mismatch: add|add: V.8b, V.8b, V.8b != V.8b, V.8b, V.8b]
      0x4ee38441  llvm='add v1.2d, v2.2d, v3.2d'   machgraph='add v1.2d, v3.2d, v2.2d'   [operand_mismatch: add|add: V.2d, V.2d, V.2d != V.2d, V.2d, V.2d]
  ```

#### 6.2 第 16 行：去掉参考命令里的 `--no-symbolic-operands` 对 `/bin/csh` 跑 `differential.py`
- **修改位置：** `Scripts/acceptance/mnemonic_normalization.py` 第 `37` 行（从 `build_reference_command` 返回参数列表中删除 `"--no-symbolic-operands",`）。
- **运行：** `python3 -I Scripts/acceptance/differential.py /bin/csh --machgraph .build/release/MachGraph` -> **退出码 `1`**（失败）：
  ```text
  [FAIL] /bin/csh (arm64e): total=79043 agree=79013 (99.96%) operand_equal=73539/79013 (93.07%) unknown=0 ref_long_mg_inst=30 wrong=0 missing=0 mg_only_inst=0
  [FAIL] Summary (custom): candidates=1 compared=1 ... operands=73539/79013 (93.0720%) mismatch=5474 (files=1)
         operand difference categories (top 10 of 679):
           - bl|bl: _xcatgets != N: count=458 files=1
               /bin/csh @ 0x100001754 [9400488f] machgraph='bl 0x100013990' vs llvm='bl _xcatgets'
  ```

#### 6.3 第 17 行：三项守卫与门禁变异
1. **去掉 G52 寄存器偏移 `option` 检查：** 删除 `Sources/MachA64Decoder/A64InstructionDecoder.swift` 第 `1912` 行 `guard (option & 0b010) != 0 else { return nil }`，重编后运行 `python3 -I Scripts/acceptance/encoding-fuzz.py --seed 20261117 --count 100000 --machgraph .build/release/MachGraph` -> **退出码 `1`**（失败）：
   ```text
   [FAIL] Summary: count=100000 agree=31180 both_unrecognized=68287 unknown=364 wrong=169 operands=31180/31180 (100.0000%, mismatch=0)
     wrong mnemonics (11 pairs, total=169):
       - .long != str (Load/store register (register offset)): count=47 e.g. [0x3c3488a2] llvm='.long 0x3c3488a2' vs machgraph='str b2, [x5, w20, sxtb]'
       - .long != ldr (Load/store register (register offset)): count=45 e.g. [0x3ce018b3] llvm='.long 0x3ce018b3' vs machgraph='ldr q19, [x5, w0, uxtb #4]'
   ```
2. **改坏汇编器 `ldp` 的写回位：** 修改 `Sources/MachA64Decoder/A64MiniAssembler.swift` 第 `2020` 行（将 `case .postIndex` 中的 `modeCode = 0b01` 改为对 `ldp` 错填无写回编码 `0b10`），重编后运行 `python3 -I Scripts/acceptance/asm-roundtrip.py quick --machgraph .build/release/MachGraph` -> **退出码 `1`**（失败）：
   ```text
   [FAIL] Summary (quick): candidates=1 compared=1 failures=0 text=3846 decoded=3846 inst_placeholders=0
          pre-M2:        total=3753 ok=3743 mismatch=10 unsupported=0 error=0 | forms=179 (all_ok=178 non_ok=1)
   Forms with mismatch or error (1):
     - [pre-M2] ldp X, X, [sp], #N: mismatch=10 error=0 (ok=0 unsup=0 total=10) | e.g. /bin/ls @ 0x100002310 [a8c66ffc] 'ldp x28, x27, [sp], #0x60' -> got [a9466ffc]
   ```
3. **往任一张归一表新增一条规则：**
   - 向 `Scripts/acceptance/operand_normalization.py` 第 `52` 行 `OPERAND_NORMALIZATION_RULES` 追加虚拟规则 `O5`，运行 `python3 -I Scripts/acceptance/test_differential_harnesses.py` -> **退出码 `1`**（失败，`TestItem12OperandNormalizationRules.test_rule_table_has_only_o1_through_o4_and_cannot_grow` 报 `AssertionError: 5 not less than or equal to 4`）；
   - 向 `Scripts/acceptance/mnemonic_normalization.py` 第 `49` 行 `NORMALIZATION_RULES` 追加虚拟规则 `M1`，运行 `python3 -I Scripts/acceptance/test_differential_harnesses.py` -> **退出码 `1`**（失败，`TestItem12OperandNormalizationRules`、`TestItem10DropRule3AndGenericNeonSelfCheck`、`TestItem1MachOReferenceCommand` 报 `AssertionError: 1 not less than or equal to 0` / `1 != 0`）。
