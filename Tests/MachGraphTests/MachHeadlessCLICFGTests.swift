import Foundation
import Testing
import MachGraphModels
@testable import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine
import MachHeadlessCLI

@Suite("M4 Stage 2: Standalone Headless CLI cfg Subcommand, Schema machgraph.cfg/1, Error Exit Codes & cfg-dot Preservation")
struct MachHeadlessCLICFGTests {

    // MARK: - Synthetic ARM64 Mach-O Fixture Helpers (Zero Dependency on System Binary Addresses)

    private static let insnNOP: UInt32 = 0xD503_201F
    private static let insnRET: UInt32 = 0xD65F_03C0
    private static let insnBR_X16: UInt32 = 0xD61F_0200
    private static let insnLDRSW_X16_X17_X16_LSL2: UInt32 = 0xB8B0_7A30
    private static let insnADR_X17_SELF: UInt32 = 0x1000_0011
    private static let insnADD_X16_X17_X16: UInt32 = 0x8B10_0230
    private static let insnCSEL_X16_X16_XZR_LO: UInt32 = 0x9A9F_3210

    private static func encMOVZ_W(rd: UInt8, imm16: UInt16) -> UInt32 {
        0x5280_0000 | (UInt32(imm16) << 5) | UInt32(rd & 0x1F)
    }

    private static func encADD_WImm(rd: UInt8, rn: UInt8, imm12: UInt16) -> UInt32 {
        0x1100_0000 | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5) | UInt32(rd & 0x1F)
    }

    private static func encSUB_WImm(rd: UInt8, rn: UInt8, imm12: UInt16) -> UInt32 {
        0x5100_0000 | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5) | UInt32(rd & 0x1F)
    }

    private static func encCMP_XImm(rn: UInt8, imm12: UInt16) -> UInt32 {
        0xF100_001F | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5)
    }

    private static func encADRP(rd: UInt8, from pc: UInt64, targetPage: UInt64) -> UInt32 {
        let pageDelta = (Int64(bitPattern: targetPage & ~UInt64(0xFFF)) - Int64(bitPattern: pc & ~UInt64(0xFFF))) >> 12
        let bits = UInt32(bitPattern: Int32(truncatingIfNeeded: pageDelta))
        let immlo = bits & 0x3
        let immhi = (bits >> 2) & 0x7FFFF
        return 0x9000_0000 | (immlo << 29) | (immhi << 5) | UInt32(rd & 0x1F)
    }

    private static func encADD_XImm(rd: UInt8, rn: UInt8, imm12: UInt16) -> UInt32 {
        0x9100_0000 | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5) | UInt32(rd & 0x1F)
    }

    private static func encLDR_XImm(rt: UInt8, rn: UInt8, byteOffset: UInt16) -> UInt32 {
        let scaled = UInt32((byteOffset / 8) & 0xFFF)
        return 0xF940_0000 | (scaled << 10) | (UInt32(rn & 0x1F) << 5) | UInt32(rt & 0x1F)
    }

    private static func encB(from pc: UInt64, to target: UInt64) -> UInt32 {
        let wordOff = (Int64(bitPattern: target) - Int64(bitPattern: pc)) >> 2
        let imm26 = UInt32(bitPattern: Int32(truncatingIfNeeded: wordOff)) & 0x03FF_FFFF
        return 0x1400_0000 | imm26
    }

    private static func encCBZ_W(rt: UInt8, from pc: UInt64, to target: UInt64) -> UInt32 {
        let wordOff = (Int64(bitPattern: target) - Int64(bitPattern: pc)) >> 2
        let imm19 = UInt32(bitPattern: Int32(truncatingIfNeeded: wordOff)) & 0x7FFFF
        return 0x3400_0000 | (imm19 << 5) | UInt32(rt & 0x1F)
    }

    private static func encCBNZ_W(rt: UInt8, from pc: UInt64, to target: UInt64) -> UInt32 {
        let wordOff = (Int64(bitPattern: target) - Int64(bitPattern: pc)) >> 2
        let imm19 = UInt32(bitPattern: Int32(truncatingIfNeeded: wordOff)) & 0x7FFFF
        return 0x3500_0000 | (imm19 << 5) | UInt32(rt & 0x1F)
    }

    private struct SyntheticFixtureLayout {
        let data: Data
        let fn1VA: UInt64
        let inlineTableVA: UInt64
        let inlineTableBytes: UInt64
        let fn2VA: UInt64
        let stubVA: UInt64
        let lcStarts: [UInt64]
    }

    /// Builds a deterministic synthetic ARM64e Mach-O binary containing:
    /// 1. `_loop_and_switch` at `0x100001000` (`__TEXT,__text`):
    ///    - Entry block falls into a counted `do-while` loop (`sub w1, w1, #1; cbnz w1, L_loop`)
    ///    - Loop exits into a 5-case `cmp x16, #5; csel x16, x16, xzr, lo` jump table whose 4-byte
    ///      signed offset table is inlined right after `_loop_and_switch` in `__TEXT,__text` and
    ///      recorded in `LC_FUNCTION_STARTS` (mirroring `ld_prime`).
    /// 2. `__Z7computei` (`compute(int)`) right after the inline jump table (`__TEXT,__text`):
    ///    - Diamond `if/else` (`cbz w0, L_else; mov w0, #10; b L_join; L_else: mov w0, #20; L_join: ret`).
    /// 3. A symbol stub at `0x100002000` in `__TEXT,__stubs` (`isStub == true`).
    private static func makeSyntheticCFGFixture() -> SyntheticFixtureLayout {
        let imageBase: UInt64 = 0x1_0000_0000
        let fn1VA: UInt64 = 0x1_0000_1000
        let stubVA: UInt64 = 0x1_0000_2000
        let gotVA: UInt64 = 0x1_0000_8000
        let caseCount = 5

        // _loop_and_switch layout:
        // +0x00: mov w1, #3                  (B0 entry, idom = null)
        // +0x04: L_loop: sub w1, w1, #1      (B1 loop header + latch, loopDepth = 1)
        // +0x08: cbnz w1, L_loop (+0x04)
        // +0x0c: cmp x16, #5                 (B2 switch dispatch)
        // +0x10: csel x16, x16, xzr, lo
        // +0x14: adrp x17, inlineTablePage
        // +0x18: add x17, x17, inlineTablePageOff
        // +0x1c: ldrsw x16, [x17, x16, lsl #2]
        // +0x20: adr x17, .                  (anchorVA = fn1VA + 0x20)
        // +0x24: add x16, x17, x16
        // +0x28: br x16
        // +0x2c..+0x54: 5 cases, each 2 words (`mov w0, #(100+i); ret`) = 10 words = 0x28 bytes
        // +0x54..+0x68: inline jump table (5 * 4B = 0x14 bytes)
        let anchorVA = fn1VA + 0x20
        let firstCaseVA = fn1VA + 0x2C
        let inlineTableVA = firstCaseVA + UInt64(caseCount * 8) // 0x100001054
        let inlineTableBytes = UInt64(caseCount * 4)            // 20 bytes
        let fn2VA = inlineTableVA + inlineTableBytes            // 0x100001068

        var textWords: [UInt32] = [
            encMOVZ_W(rd: 1, imm16: 3),                                     // +0x00
            encSUB_WImm(rd: 1, rn: 1, imm12: 1),                            // +0x04: L_loop
            encCBNZ_W(rt: 1, from: fn1VA + 0x08, to: fn1VA + 0x04),         // +0x08: back-edge to +0x04
            encCMP_XImm(rn: 16, imm12: UInt16(caseCount)),                  // +0x0c
            insnCSEL_X16_X16_XZR_LO,                                        // +0x10
            encADRP(rd: 17, from: fn1VA + 0x14, targetPage: inlineTableVA), // +0x14
            encADD_XImm(rd: 17, rn: 17, imm12: UInt16(inlineTableVA & 0xFFF)), // +0x18
            insnLDRSW_X16_X17_X16_LSL2,                                     // +0x1c
            insnADR_X17_SELF,                                               // +0x20
            insnADD_X16_X17_X16,                                            // +0x24
            insnBR_X16                                                      // +0x28
        ]

        var tableWords: [UInt32] = []
        for idx in 0..<caseCount {
            let caseVA = firstCaseVA + UInt64(idx * 8)
            textWords.append(encMOVZ_W(rd: 0, imm16: UInt16(100 + idx)))
            textWords.append(insnRET)
            let rel = Int32(Int64(bitPattern: caseVA) - Int64(bitPattern: anchorVA))
            tableWords.append(UInt32(bitPattern: rel))
        }
        textWords.append(contentsOf: tableWords)

        // Function 2: `__Z7computei` at fn2VA (`0x100001068`):
        // +0x00: cbz w0, L_else (+0x0c)
        // +0x04: mov w0, #10
        // +0x08: b L_join (+0x10)
        // +0x0c: L_else: mov w0, #20
        // +0x10: L_join: add w0, w0, #1
        // +0x14: ret
        textWords.append(contentsOf: [
            encCBZ_W(rt: 0, from: fn2VA + 0x00, to: fn2VA + 0x0C),
            encMOVZ_W(rd: 0, imm16: 10),
            encB(from: fn2VA + 0x08, to: fn2VA + 0x10),
            encMOVZ_W(rd: 0, imm16: 20),
            encADD_WImm(rd: 0, rn: 0, imm12: 1),
            insnRET
        ])

        // Stub in __TEXT,__stubs at 0x100002000 (3 words = 12 bytes):
        let stubWords: [UInt32] = [
            encADRP(rd: 16, from: stubVA + 0x00, targetPage: gotVA),
            encLDR_XImm(rt: 16, rn: 16, byteOffset: 0),
            insnBR_X16
        ]

        let lcStarts: [UInt64] = [fn1VA, inlineTableVA, fn2VA]

        // Assemble minimal Mach-O 64 image
        let textSegSize = 0x8000
        let dataSegFileOff = 0x8000
        let dataSegSize = 0x4000
        let linkeditFileOff = 0xC000
        let linkeditVA = imageBase + UInt64(linkeditFileOff)
        var sliceBytes = [UInt8](repeating: 0, count: linkeditFileOff)

        func writeWords(_ words: [UInt32], at fileOff: Int) {
            for (i, w) in words.enumerated() {
                let off = fileOff + i * 4
                sliceBytes[off + 0] = UInt8(truncatingIfNeeded: w)
                sliceBytes[off + 1] = UInt8(truncatingIfNeeded: w >> 8)
                sliceBytes[off + 2] = UInt8(truncatingIfNeeded: w >> 16)
                sliceBytes[off + 3] = UInt8(truncatingIfNeeded: w >> 24)
            }
        }
        writeWords(textWords, at: 0x1000)
        writeWords(stubWords, at: 0x2000)
        writeWords([0, 0], at: 0x8000)

        var fsWriter = BinaryBufferWriter(capacity: 64, endianness: .little)
        var prevOff: UInt64 = 0
        for va in lcStarts.sorted() {
            let off = va - imageBase
            fsWriter.appendULEB128(off - prevOff)
            prevOff = off
        }
        fsWriter.padToAlignment(8)

        let symbols: [(name: String, nSect: UInt8, va: UInt64)] = [
            ("__mh_execute_header", 1, imageBase),
            ("_loop_and_switch", 1, fn1VA),
            ("__Z7computei", 1, fn2VA)
        ]
        var strPool = BinaryBufferWriter(capacity: 128, endianness: .little)
        strPool.appendUInt8(0)
        var nlistWriter = BinaryBufferWriter(capacity: symbols.count * 16, endianness: .little)
        for sym in symbols {
            let strIdx = UInt32(strPool.count)
            strPool.appendCString(sym.name)
            nlistWriter.appendUInt32(strIdx)
            nlistWriter.appendUInt8(MachOConstants.nSect | MachOConstants.nExt)
            nlistWriter.appendUInt8(sym.nSect)
            nlistWriter.appendUInt16(0)
            nlistWriter.appendUInt64(sym.va)
        }
        strPool.padToAlignment(8)

        var linkedit = BinaryBufferWriter(capacity: 512, endianness: .little)
        let fsOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(fsWriter.bytes)
        let symtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(nlistWriter.bytes)
        let strtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(strPool.bytes)
        linkedit.padToAlignment(16)

        var lc = BinaryBufferWriter(capacity: 1024, endianness: .little)
        var ncmds: UInt32 = 0

        // __PAGEZERO
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(72)
        lc.appendFixedASCII("__PAGEZERO", length: 16)
        lc.appendUInt64(0)
        lc.appendUInt64(imageBase)
        lc.appendUInt64(0)
        lc.appendUInt64(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        ncmds += 1

        // __TEXT with 2 sections: __text and __stubs
        let pureFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let stubFlags = MachOConstants.sSymbolStubs | pureFlags
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(UInt32(72 + 2 * 80))
        lc.appendFixedASCII("__TEXT", length: 16)
        lc.appendUInt64(imageBase)
        lc.appendUInt64(UInt64(textSegSize))
        lc.appendUInt64(0)
        lc.appendUInt64(UInt64(textSegSize))
        lc.appendUInt32(5)
        lc.appendUInt32(5)
        lc.appendUInt32(2)
        lc.appendUInt32(0)
        // Section 1: __TEXT,__text
        lc.appendFixedASCII("__text", length: 16)
        lc.appendFixedASCII("__TEXT", length: 16)
        lc.appendUInt64(fn1VA)
        lc.appendUInt64(UInt64(textWords.count * 4))
        lc.appendUInt32(0x1000)
        lc.appendUInt32(2)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(pureFlags)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        // Section 2: __TEXT,__stubs (reserved2 = 12 byte stub slot size)
        lc.appendFixedASCII("__stubs", length: 16)
        lc.appendFixedASCII("__TEXT", length: 16)
        lc.appendUInt64(stubVA)
        lc.appendUInt64(UInt64(stubWords.count * 4))
        lc.appendUInt32(0x2000)
        lc.appendUInt32(2)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(stubFlags)
        lc.appendUInt32(0)
        lc.appendUInt32(12)
        lc.appendUInt32(0)
        ncmds += 1

        // __DATA_CONST,__got
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(UInt32(72 + 80))
        lc.appendFixedASCII("__DATA_CONST", length: 16)
        lc.appendUInt64(gotVA)
        lc.appendUInt64(UInt64(dataSegSize))
        lc.appendUInt64(UInt64(dataSegFileOff))
        lc.appendUInt64(UInt64(dataSegSize))
        lc.appendUInt32(3)
        lc.appendUInt32(3)
        lc.appendUInt32(1)
        lc.appendUInt32(0)
        lc.appendFixedASCII("__got", length: 16)
        lc.appendFixedASCII("__DATA_CONST", length: 16)
        lc.appendUInt64(gotVA)
        lc.appendUInt64(8)
        lc.appendUInt32(UInt32(dataSegFileOff))
        lc.appendUInt32(3)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(MachOConstants.sNonLazySymbolPointers)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        ncmds += 1

        // __LINKEDIT
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(72)
        lc.appendFixedASCII("__LINKEDIT", length: 16)
        lc.appendUInt64(linkeditVA)
        lc.appendUInt64(0x4000)
        lc.appendUInt64(UInt64(linkeditFileOff))
        lc.appendUInt64(UInt64(linkedit.count))
        lc.appendUInt32(1)
        lc.appendUInt32(1)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        ncmds += 1

        // LC_MAIN -> fn1VA
        lc.appendUInt32(MachOConstants.lcMain)
        lc.appendUInt32(24)
        lc.appendUInt64(0x1000)
        lc.appendUInt64(0)
        ncmds += 1

        // LC_FUNCTION_STARTS
        lc.appendUInt32(MachOConstants.lcFunctionStarts)
        lc.appendUInt32(16)
        lc.appendUInt32(UInt32(fsOff))
        lc.appendUInt32(UInt32(fsWriter.count))
        ncmds += 1

        // LC_SYMTAB
        lc.appendUInt32(MachOConstants.lcSymtab)
        lc.appendUInt32(24)
        lc.appendUInt32(UInt32(symtabOff))
        lc.appendUInt32(UInt32(symbols.count))
        lc.appendUInt32(UInt32(strtabOff))
        lc.appendUInt32(UInt32(strPool.count))
        ncmds += 1

        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(2) // arm64e
        hdr.appendUInt32(MachOConstants.mhExecute)
        hdr.appendUInt32(ncmds)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(0x0020_0085)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for (i, b) in hdr.bytes.enumerated() {
            sliceBytes[i] = b
        }
        sliceBytes.append(contentsOf: linkedit.bytes)

        return SyntheticFixtureLayout(
            data: Data(sliceBytes),
            fn1VA: fn1VA,
            inlineTableVA: inlineTableVA,
            inlineTableBytes: inlineTableBytes,
            fn2VA: fn2VA,
            stubVA: stubVA,
            lcStarts: lcStarts
        )
    }

    private static func makeTempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("mg-cli-cfg-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private static func jsonUInt64(_ any: Any?) -> UInt64? {
        if let u = any as? UInt64 { return u }
        if let i = any as? Int, i >= 0 { return UInt64(i) }
        if let n = any as? NSNumber { return n.uint64Value }
        return nil
    }

    // MARK: - 1. Single-Function Mode (--symbol & --address) Schema, Null Entry idom, Loops & Jump Tables

    @Test("machgraph cfg --symbol / --address --json emits schema machgraph.cfg/1 with null entry idom, loops, jump tables & inline ranges")
    func singleFunctionCFGJSONAndBilingualSummary() async throws {
        let tempDir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fixture = Self.makeSyntheticCFGFixture()
        let binURL = tempDir.appendingPathComponent("synth_cfg.arm64e")
        try fixture.data.write(to: binURL)

        let cli = MachCLIRunner()
        let rawJSON = try await cli.execute(arguments: [
            "cfg", binURL.path, "--symbol", "_loop_and_switch", "--json"
        ])
        let doc = try #require(JSONSerialization.jsonObject(with: Data(rawJSON.utf8)) as? [String: Any])

        #expect(doc["schema"] as? String == "machgraph.cfg/1")
        #expect(doc["filePath"] as? String == binURL.path)
        #expect(doc["fileName"] as? String == "synth_cfg.arm64e")
        #expect(doc["architecture"] as? String == "arm64e (PAC)")
        #expect(doc["selectedSliceIndex"] as? Int == 0)
        #expect(doc["dot"] == nil)

        let lcStarts = try #require(doc["lcFunctionStarts"] as? [Any]).compactMap(Self.jsonUInt64)
        #expect(lcStarts == fixture.lcStarts)

        let inlineStarts = try #require(doc["inlineJumpTableStarts"] as? [Any]).compactMap(Self.jsonUInt64)
        #expect(inlineStarts == [fixture.inlineTableVA])

        let functions = try #require(doc["functions"] as? [[String: Any]])
        #expect(functions.count == 1)

        let fn = functions[0]
        #expect(Self.jsonUInt64(fn["address"]) == fixture.fn1VA)
        #expect(Self.jsonUInt64(fn["endAddress"]) == fixture.inlineTableVA)
        #expect(fn["name"] as? String == "_loop_and_switch")
        #expect(fn["demangledName"] as? String == "_loop_and_switch")
        #expect(fn["section"] as? String == "__TEXT,__text")
        #expect(fn["isStub"] as? Bool == false)

        // Blocks
        let blocks = try #require(fn["blocks"] as? [[String: Any]])
        #expect(blocks.count == 8) // entry + loop + switch dispatch + 5 switch cases
        let entryBlock = try #require(blocks.first { ($0["isEntry"] as? Bool) == true })
        let entryID = try #require(entryBlock["id"] as? Int)
        #expect(Self.jsonUInt64(entryBlock["startAddress"]) == fixture.fn1VA)
        #expect(entryBlock["isExit"] as? Bool == false)
        #expect(entryBlock["loopDepth"] as? Int == 0)
        #expect(entryBlock["predecessorIDs"] as? [Int] == [])
        #expect((entryBlock["successorIDs"] as? [Int])?.count == 1)
        let entryInsnAddrs = try #require(entryBlock["instructionAddresses"] as? [Any]).compactMap(Self.jsonUInt64)
        #expect(entryInsnAddrs == [fixture.fn1VA])
        #expect(entryBlock["instructionCount"] as? Int == 1)

        // Edges: back-edge on loop latch + 5 switchCase edges with caseValue 0..4 + non-switch caseValue == null
        let edges = try #require(fn["edges"] as? [[String: Any]])
        #expect(edges.contains { ($0["isBackEdge"] as? Bool) == true })
        let switchEdges = edges.filter { ($0["kind"] as? String) == "switchCase" }
        #expect(switchEdges.count == 5)
        let caseValues = switchEdges.compactMap { $0["caseValue"] as? Int }.sorted()
        #expect(caseValues == [0, 1, 2, 3, 4])
        let nonSwitchEdge = try #require(edges.first { ($0["kind"] as? String) != "switchCase" })
        #expect(nonSwitchEdge.keys.contains("caseValue"))
        #expect(nonSwitchEdge["caseValue"] is NSNull)

        // Dominator tree: entry block MUST explicitly carry `"immediateDominatorID": null`
        let domTree = try #require(fn["dominatorTree"] as? [[String: Any]])
        #expect(domTree.count == blocks.count)
        let entryDom = try #require(domTree.first { ($0["blockID"] as? Int) == entryID })
        #expect(entryDom.keys.contains("immediateDominatorID"))
        #expect(entryDom["immediateDominatorID"] is NSNull)
        for domNode in domTree where (domNode["blockID"] as? Int) != entryID {
            #expect(domNode["immediateDominatorID"] as? Int != nil)
        }

        // Natural loops
        let loops = try #require(fn["naturalLoops"] as? [[String: Any]])
        #expect(loops.count == 1)
        #expect(loops[0]["nestingDepth"] as? Int == 1)
        #expect((loops[0]["latchBlockIDs"] as? [Int])?.isEmpty == false)
        #expect((loops[0]["bodyBlockIDs"] as? [Int])?.isEmpty == false)
        #expect((loops[0]["exitBlockIDs"] as? [Int])?.isEmpty == false)
        #expect(loops[0]["headerBlockID"] as? Int != nil)

        // Jump tables & inlineJumpTableRanges
        let jumpTables = try #require(fn["jumpTables"] as? [[String: Any]])
        #expect(jumpTables.count == 1)
        #expect(Self.jsonUInt64(jumpTables[0]["dispatchInstructionAddress"]) == fixture.fn1VA + 0x28)
        #expect(Self.jsonUInt64(jumpTables[0]["tableBaseAddress"]) == fixture.inlineTableVA)
        #expect(jumpTables[0]["entryByteSize"] as? Int == 4)
        #expect(jumpTables[0]["isInlineInCode"] as? Bool == true)
        let jtTargets = try #require(jumpTables[0]["targetAddresses"] as? [Any]).compactMap(Self.jsonUInt64)
        #expect(jtTargets.count == 5)

        let fnInlineRanges = try #require(fn["inlineJumpTableRanges"] as? [[String: Any]])
        #expect(fnInlineRanges.count == 1)
        #expect(Self.jsonUInt64(fnInlineRanges[0]["start"]) == fixture.inlineTableVA)
        #expect(Self.jsonUInt64(fnInlineRanges[0]["end"]) == fixture.inlineTableVA + fixture.inlineTableBytes)

        // Single-function selection via --address (with C++ demangledName verification)
        let byAddrJSON = try await cli.execute(arguments: [
            "cfg", binURL.path, "--address", String(format: "0x%llx", fixture.fn2VA), "--slice", "0", "--json"
        ])
        let addrDoc = try #require(JSONSerialization.jsonObject(with: Data(byAddrJSON.utf8)) as? [String: Any])
        let addrFns = try #require(addrDoc["functions"] as? [[String: Any]])
        #expect(addrFns.count == 1)
        #expect(Self.jsonUInt64(addrFns[0]["address"]) == fixture.fn2VA)
        #expect(addrFns[0]["name"] as? String == "__Z7computei")
        #expect(addrFns[0]["demangledName"] as? String == "compute(int)")
        let fn2Blocks = try #require(addrFns[0]["blocks"] as? [[String: Any]])
        #expect(fn2Blocks.count == 4) // diamond if/else

        // Human-readable text mode (EN and ZH)
        let textEN = try await cli.execute(arguments: ["cfg", binURL.path, "--symbol", "_loop_and_switch", "--lang", "en"])
        let textZH = try await cli.execute(arguments: ["cfg", binURL.path, "--symbol", "_loop_and_switch", "--lang", "zh"])
        #expect(!textEN.contains("digraph "))
        #expect(textEN.contains("_loop_and_switch"))
        #expect(textZH.contains("_loop_and_switch"))
        #expect(textZH != textEN)
    }

    // MARK: - 2. Full-File Mode Function Count, Inline Jump Table Starts & Stub Classification

    @Test("machgraph cfg <file> without --symbol/--address outputs all recovered functions and inlineJumpTableStarts")
    func fullFileCFGOutputsAllFunctionsAndMatchesEngineCount() async throws {
        let tempDir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fixture = Self.makeSyntheticCFGFixture()
        let binURL = tempDir.appendingPathComponent("full_cfg.arm64e")
        try fixture.data.write(to: binURL)

        let expectedIndex = try BinaryAnalysisCoordinator(
            options: BinaryAnalysisOptions(computeSugiyamaLayouts: false, computePostDominatorTrees: false)
        ).analyzeBinary(data: fixture.data, filePath: binURL.path, fileName: binURL.lastPathComponent)

        let cli = MachCLIRunner()
        let fullJSON = try await cli.execute(arguments: ["cfg", binURL.path, "--json"])
        let doc = try #require(JSONSerialization.jsonObject(with: Data(fullJSON.utf8)) as? [String: Any])

        #expect(doc["schema"] as? String == "machgraph.cfg/1")
        let functions = try #require(doc["functions"] as? [[String: Any]])
        #expect(functions.count == expectedIndex.functions.count)
        #expect(functions.count == 3) // _loop_and_switch, __Z7computei, and __TEXT,__stubs entry

        let fnAddrs = functions.compactMap { Self.jsonUInt64($0["address"]) }
        #expect(fnAddrs == [fixture.fn1VA, fixture.fn2VA, fixture.stubVA])

        // Inline jump table start appears in inlineJumpTableStarts and NOT as a fake function
        let inlineStarts = Set(try #require(doc["inlineJumpTableStarts"] as? [Any]).compactMap(Self.jsonUInt64))
        let lcStarts = Set(try #require(doc["lcFunctionStarts"] as? [Any]).compactMap(Self.jsonUInt64))
        let textFnStarts = Set(
            functions
                .filter { ($0["section"] as? String) == "__TEXT,__text" }
                .compactMap { Self.jsonUInt64($0["address"]) }
        )
        #expect(inlineStarts == [fixture.inlineTableVA])
        #expect(textFnStarts.isDisjoint(with: inlineStarts))
        #expect(textFnStarts.union(inlineStarts) == lcStarts)

        // Stub section classification
        let stubFn = try #require(functions.first { Self.jsonUInt64($0["address"]) == fixture.stubVA })
        #expect(stubFn["section"] as? String == "__TEXT,__stubs")
        #expect(stubFn["isStub"] as? Bool == true)

        // Also cross-check on repo fixture `Fixtures/demo_arm64_sample`
        let demoSampleData = try RepoFixtures.thinARM64SampleData()
        let expectedSampleIndex = try BinaryAnalysisCoordinator(
            options: BinaryAnalysisOptions(computeSugiyamaLayouts: false, computePostDominatorTrees: false)
        ).analyzeBinary(
            data: demoSampleData,
            filePath: RepoFixtures.thinARM64SampleURL.path,
            fileName: RepoFixtures.thinARM64SampleURL.lastPathComponent
        )
        let sampleJSON = try await cli.execute(arguments: ["cfg", RepoFixtures.thinARM64SampleURL.path, "--json"])
        let sampleDoc = try #require(JSONSerialization.jsonObject(with: Data(sampleJSON.utf8)) as? [String: Any])
        let sampleFns = try #require(sampleDoc["functions"] as? [[String: Any]])
        #expect(sampleFns.count == expectedSampleIndex.functions.count)
        #expect(sampleFns.count > 1)

        // Full-file human-readable mode (EN & ZH)
        let fullTextEN = try await cli.execute(arguments: ["cfg", binURL.path, "--lang", "en"])
        let fullTextZH = try await cli.execute(arguments: ["cfg", binURL.path, "--lang", "zh"])
        #expect(fullTextEN.contains("_loop_and_switch"))
        #expect(fullTextEN.contains("compute(int)"))
        #expect(fullTextZH.contains("_loop_and_switch"))
        #expect(fullTextZH.contains("compute(int)"))
    }

    // MARK: - 3. Error Exit Codes, Parameter Conflict & Empty stdout on Failure

    @Test("machgraph cfg fails cleanly with expected exit codes and empty stdout on missing symbol, conflicting flags, missing file, or non-Mach-O")
    func errorExitCodesConflictAndEmptyStdout() async throws {
        let tempDir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fixture = Self.makeSyntheticCFGFixture()
        let binURL = tempDir.appendingPathComponent("err_cfg.arm64e")
        try fixture.data.write(to: binURL)

        let plainTextURL = tempDir.appendingPathComponent("not_a_macho.txt")
        try Data("plain text payload\n".utf8).write(to: plainTextURL)
        let missingURL = tempDir.appendingPathComponent("does_not_exist.macho")

        let cli = MachCLIRunner()

        // 1) --symbol not found -> exit code 1
        do {
            _ = try await cli.run(arguments: ["cfg", binURL.path, "--symbol", "_no_such_symbol_xyz", "--json"])
            Issue.record("Expected missing --symbol to throw")
        } catch {
            #expect(MachCLIRunner.exitCode(for: error) == 1)
        }

        // 2) --address not found -> exit code 1
        do {
            _ = try await cli.run(arguments: ["cfg", binURL.path, "--address", "0x100099000", "--json"])
            Issue.record("Expected missing --address to throw")
        } catch {
            #expect(MachCLIRunner.exitCode(for: error) == 1)
        }

        // 3) --symbol and --address passed simultaneously -> parameter conflict (exit code 2)
        for lang in ["en", "zh"] {
            do {
                _ = try await cli.run(arguments: [
                    "cfg", binURL.path,
                    "--symbol", "_loop_and_switch",
                    "--address", "0x100001000",
                    "--json",
                    "--lang", lang
                ])
                Issue.record("Expected --symbol + --address conflict to throw invalidCLIArguments (\(lang))")
            } catch let mgErr as MachGraphError {
                #expect(MachCLIRunner.exitCode(for: mgErr) == 2)
                let msg = mgErr.localizedMessage(in: lang == "zh" ? .zhHans : .en)
                #expect(!msg.isEmpty)
            }
        }

        // 4) Nonexistent file & non-Mach-O file -> exit code 1
        for badPath in [missingURL.path, plainTextURL.path] {
            do {
                _ = try await cli.run(arguments: ["cfg", badPath, "--json"])
                Issue.record("Expected invalid input '\(badPath)' to throw")
            } catch {
                #expect(MachCLIRunner.exitCode(for: error) == 1)
            }
        }

        // 5) Subprocess check when debug/release binary is built: stdout MUST be 0 bytes and stderr non-empty
        let debugBin = RepoFixtures.repositoryRoot.appendingPathComponent(".build/debug/MachGraph")
        let releaseBin = RepoFixtures.repositoryRoot.appendingPathComponent(".build/release/MachGraph")
        if let execURL = [debugBin, releaseBin].first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) {
            let isoHome = tempDir.appendingPathComponent("iso_home", isDirectory: true)
            try FileManager.default.createDirectory(at: isoHome, withIntermediateDirectories: true)

            func runProc(_ args: [String]) throws -> (rc: Int32, out: String, err: String) {
                let proc = Process()
                proc.executableURL = execURL
                proc.arguments = args
                var env = ProcessInfo.processInfo.environment
                env["HOME"] = isoHome.path
                env["CFFIXED_USER_HOME"] = isoHome.path
                proc.environment = env
                let outPipe = Pipe()
                let errPipe = Pipe()
                proc.standardOutput = outPipe
                proc.standardError = errPipe
                try proc.run()
                let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
                let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                proc.waitUntilExit()
                return (
                    proc.terminationStatus,
                    String(decoding: outData, as: UTF8.self),
                    String(decoding: errData, as: UTF8.self)
                )
            }

            let missingSymRes = try runProc(["cfg", binURL.path, "--symbol", "_missing_sym", "--json", "--lang", "en"])
            #expect(missingSymRes.rc == 1)
            #expect(missingSymRes.out.isEmpty)
            #expect(!missingSymRes.err.isEmpty)

            let conflictRes = try runProc([
                "cfg", binURL.path, "--symbol", "_loop_and_switch", "--address", "0x100001000", "--json", "--lang", "zh"
            ])
            #expect(conflictRes.rc == 2)
            #expect(conflictRes.out.isEmpty)
            #expect(!conflictRes.err.isEmpty)
        }
    }

    // MARK: - 4. cfg-dot Byte-for-Byte Preservation & Bilingual --help

    @Test("cfg-dot preserves byte-for-byte DOT and JSON output while --help lists both cfg and cfg-dot")
    func cfgDotPreservedByteForByteAndBilingualHelpUpdated() async throws {
        let tempDir = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fixture = Self.makeSyntheticCFGFixture()
        let binURL = tempDir.appendingPathComponent("dot_preserve.arm64e")
        try fixture.data.write(to: binURL)

        let expectedIndex = try BinaryAnalysisCoordinator(
            options: BinaryAnalysisOptions(computeSugiyamaLayouts: false, computePostDominatorTrees: false)
        ).analyzeBinary(data: fixture.data, filePath: binURL.path, fileName: binURL.lastPathComponent)
        let fn2 = try #require(expectedIndex.function(at: VirtualAddress(fixture.fn2VA)))

        // Reference byte-for-byte expected DOT for fn2 (`compute(int)`)
        var expectedLines: [String] = [
            "digraph \"\(fn2.demangledName)\" {",
            "  rankdir=TB;",
            "  node [shape=box, fontname=\"Menlo\", fontsize=10];"
        ]
        for block in fn2.blocks {
            let body = block.instructions.map { "\($0.address.hexString): \($0.formattedDisassembly)" }.joined(separator: "\\l") + "\\l"
            let escaped = body.replacingOccurrences(of: "\"", with: "\\\"")
            expectedLines.append("  b\(block.id) [label=\"\(block.label)\\l\(escaped)\"];")
        }
        for edge in fn2.edges {
            let color: String
            switch edge.kind {
            case .conditionalTrue: color = "#3FB950"
            case .conditionalFalse: color = "#F85149"
            case .switchCase: color = "#D29922"
            case .unconditional, .fallthroughEdge: color = edge.isBackEdge ? "#FFA657" : "#58A6FF"
            }
            let labelAttr = edge.kind.displayLabel.map { ", label=\"\($0)\"" } ?? ""
            expectedLines.append("  b\(edge.sourceBlockID) -> b\(edge.targetBlockID) [color=\"\(color)\"\(labelAttr)];")
        }
        expectedLines.append("}")
        let expectedDOT = expectedLines.joined(separator: "\n")

        let cli = MachCLIRunner()
        let actualDOT = try await cli.execute(arguments: ["cfg-dot", binURL.path, "--symbol", "__Z7computei"])
        #expect(actualDOT == expectedDOT)

        let expectedJSONObj: [String: Any] = [
            "fileName": binURL.lastPathComponent,
            "isDemo": false,
            "function": fn2.name,
            "demangledName": fn2.demangledName,
            "address": fn2.address.rawValue,
            "addressHex": fn2.address.hexString,
            "blockCount": fn2.blocks.count,
            "edgeCount": fn2.edges.count,
            "cyclomaticComplexity": fn2.cyclomaticComplexity,
            "loopCount": fn2.naturalLoops.count,
            "dot": expectedDOT
        ]
        let expectedJSONData = try JSONSerialization.data(withJSONObject: expectedJSONObj, options: [.prettyPrinted, .sortedKeys])
        let expectedJSONText = String(decoding: expectedJSONData, as: UTF8.self)
        let actualJSONText = try await cli.execute(arguments: ["cfg-dot", binURL.path, "--symbol", "__Z7computei", "--json"])
        #expect(actualJSONText == expectedJSONText)

        // Canonical subcommand resolution: `cfg` and `cfg-dot` are now distinct subcommands
        #expect(MachCLIRunner.resolveCanonicalSubcommand("cfg") == "cfg")
        #expect(MachCLIRunner.resolveCanonicalSubcommand("cfg-dot") == "cfg-dot")

        // Bilingual --help lists both `cfg` and `cfg-dot`
        let helpEN = try await cli.execute(arguments: ["--help", "--lang", "en"])
        let helpZH = try await cli.execute(arguments: ["--help", "--lang", "zh"])
        #expect(helpEN.contains("\n  cfg "))
        #expect(helpEN.contains("\n  cfg-dot "))
        #expect(helpZH.contains("\n  cfg "))
        #expect(helpZH.contains("\n  cfg-dot "))

        // M5 adds `mach_cfg` to the MCP tool registry
        let mcpToolNames = MachMCPServer.toolDefinitions.compactMap { $0["name"] as? String }
        #expect(mcpToolNames.contains("mach_cfg"))
    }
}
