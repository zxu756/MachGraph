# MachGraph Swift Library Examples

`MachBinaryFormats`, `MachA64Decoder`, and `MachCFGEngine` re-export `MachGraphModels` via `@_exported import MachGraphModels`, so external Swift packages only need to depend on and `import` the target module they use.

## 1. `MachBinaryFormats` — Read Mach-O Header, Segments, and Code Signature

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

Expected output (macOS 26.5 `arm64e` `/bin/ls`; verified independently against `xcrun otool -l`, `llvm-objdump --macho --function-starts`, and `codesign -dvvv` by `Scripts/acceptance/m5-lib-examples.py`):

```text
format=Mach-O Universal Fat arch=arm64e (PAC)
entry=0x0000000100000960 segments=5 [__PAGEZERO,__TEXT,__DATA_CONST,__DATA,__LINKEDIT]
lcFunctionStarts=50
signed=true cdhash=54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce
```

## 2. `MachA64Decoder` — Assemble and Decode A64 Instructions

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

Expected output (verified independently against `xcrun clang -arch arm64` and `xcrun llvm-objdump -d`):

```text
0x0000000100000000  d10043ff  sub sp, sp, #0x10
0x0000000100000004  52800540  mov w0, #0x2a
0x0000000100000008  910043ff  add sp, sp, #0x10
0x000000010000000c  d65f03c0  ret
```

## 3. `MachCFGEngine` — Build the Control-Flow Graph for a Single Function

Recover basic blocks, control-flow edges, Lengauer-Tarjan dominators, and natural loops for `/bin/ls`'s `LC_MAIN` entry point (`0x100000960`) via the single-function fast path `analyzeCFGOnly(fileURL:preferredSliceIndex:selector:)`:

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

Expected output (macOS 26.5 `arm64e` `/bin/ls`; verified independently from `LC_MAIN`, `LC_FUNCTION_STARTS`, `otool -Iv`, `llvm-objdump -d`, and independent dominator/loop analysis):

```text
functions=133 entry=_entry@0x0000000100000960
blocks=154 edges=259 dom=154 loops=1
```
