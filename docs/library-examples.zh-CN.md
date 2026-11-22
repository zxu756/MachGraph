# MachGraph Swift 库使用示例

`MachBinaryFormats`、`MachA64Decoder` 与 `MachCFGEngine` 均已通过 `@_exported import MachGraphModels` 重导出底层模型类型，外部 Swift 包只需依赖并 `import` 对应的目标模块即可直接使用。

## 1. `MachBinaryFormats` —— 读取 Mach-O 头、段表与代码签名

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

期望输出（macOS 26.5 `arm64e` `/bin/ls`；由 `Scripts/acceptance/m5-lib-examples.py` 独立对照 `xcrun otool -l`、`llvm-objdump --macho --function-starts` 与 `codesign -dvvv` 核验）：

```text
format=Mach-O Universal Fat arch=arm64e (PAC)
entry=0x0000000100000960 segments=5 [__PAGEZERO,__TEXT,__DATA_CONST,__DATA,__LINKEDIT]
lcFunctionStarts=50
signed=true cdhash=54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce
```

## 2. `MachA64Decoder` —— 汇编与解码 A64 指令

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

期望输出（独立对照 `xcrun clang -arch arm64` 与 `xcrun llvm-objdump -d` 核验）：

```text
0x0000000100000000  d10043ff  sub sp, sp, #0x10
0x0000000100000004  52800540  mov w0, #0x2a
0x0000000100000008  910043ff  add sp, sp, #0x10
0x000000010000000c  d65f03c0  ret
```

## 3. `MachCFGEngine` —— 为单个函数构建控制流图（CFG）

调用单函数快路径 `analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`，为 `/bin/ls` 的 `LC_MAIN` 入口函数（`0x100000960`）恢复基本块、控制流边、Lengauer-Tarjan 支配树与自然循环：

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

期望输出（macOS 26.5 `arm64e` `/bin/ls`；根据 `LC_MAIN`、`LC_FUNCTION_STARTS`、`otool -Iv`、`llvm-objdump -d` 及独立支配树/循环求解器核验）：

```text
functions=133 entry=_entry@0x0000000100000960
blocks=154 edges=259 dom=154 loops=1
```
