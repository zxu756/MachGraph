import Foundation
import Testing
import MachGraphModels
@testable import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine
import MachHeadlessCLI

@Suite("M4 Stage 1: CFG Engine Fixes (Jump Tables, Inline Data, UDF, Noreturn, ObjC Stubs, Function Starts)")
struct MachCFGEngineM4Tests {

    // MARK: - Synthetic ARM64 Encoding & Mach-O Builder Helpers

    private static let insnNOP: UInt32 = 0xD503_201F
    private static let insnRET: UInt32 = 0xD65F_03C0
    private static let insnBRK1: UInt32 = 0xD420_0020
    private static let insnUDFDead: UInt32 = 0x0000_DEAD
    private static let insnBR_X16: UInt32 = 0xD61F_0200
    private static let insnBRAA_X16_X17: UInt32 = 0xD71F_0A11
    private static let insnLDRSW_X16_X17_X16_LSL2: UInt32 = 0xB8B0_7A30
    private static let insnADR_X17_SELF: UInt32 = 0x1000_0011
    private static let insnADD_X16_X17_X16: UInt32 = 0x8B10_0230
    private static let insnCSEL_X16_X16_XZR_LS: UInt32 = 0x9A9F_9210
    private static let insnCSEL_X16_X16_XZR_LO: UInt32 = 0x9A9F_3210

    private static func encMOVZ_W(rd: UInt8, imm16: UInt16) -> UInt32 {
        0x5280_0000 | (UInt32(imm16) << 5) | UInt32(rd & 0x1F)
    }

    private static func encMOV_X(rd: UInt8, rm: UInt8) -> UInt32 {
        0xAA00_03E0 | (UInt32(rm & 0x1F) << 16) | UInt32(rd & 0x1F)
    }

    private static func encMOV_W(rd: UInt8, rm: UInt8) -> UInt32 {
        0x2A00_03E0 | (UInt32(rm & 0x1F) << 16) | UInt32(rd & 0x1F)
    }

    private static func encCMP_XImm(rn: UInt8, imm12: UInt16) -> UInt32 {
        0xF100_001F | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5)
    }

    private static func encCMP_WImm(rn: UInt8, imm12: UInt16) -> UInt32 {
        0x7100_001F | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5)
    }

    private static func encSUB_WImm(rd: UInt8, rn: UInt8, imm12: UInt16) -> UInt32 {
        0x5100_0000 | (UInt32(imm12 & 0xFFF) << 10) | (UInt32(rn & 0x1F) << 5) | UInt32(rd & 0x1F)
    }

    private static func encSXTW_X(rd: UInt8, rn: UInt8) -> UInt32 {
        0x9340_7C00 | (UInt32(rn & 0x1F) << 5) | UInt32(rd & 0x1F)
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

    private static func encBL(from pc: UInt64, to target: UInt64) -> UInt32 {
        let wordOff = (Int64(bitPattern: target) - Int64(bitPattern: pc)) >> 2
        let imm26 = UInt32(bitPattern: Int32(truncatingIfNeeded: wordOff)) & 0x03FF_FFFF
        return 0x9400_0000 | imm26
    }

    private static func encBCond(cond: UInt8, from pc: UInt64, to target: UInt64) -> UInt32 {
        let wordOff = (Int64(bitPattern: target) - Int64(bitPattern: pc)) >> 2
        let imm19 = UInt32(bitPattern: Int32(truncatingIfNeeded: wordOff)) & 0x7FFFF
        return 0x5400_0000 | (imm19 << 5) | UInt32(cond & 0xF)
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

    private struct SyntheticSectionSpec {
        let segment: String
        let section: String
        let vmAddress: UInt64
        let fileOffset: Int
        let words: [UInt32]
        let flags: UInt32
    }

    private struct SyntheticSymbolSpec {
        let name: String
        let nSect: UInt8
        let vmAddress: UInt64
        let isExternal: Bool
    }

    /// Builds a minimal valid 64-bit ARM64/ARM64e Mach-O executable in memory from explicit sections,
    /// `LC_FUNCTION_STARTS` entries, and `LC_SYMTAB` symbols.
    private static func buildSyntheticMachO(
        useARM64E: Bool = true,
        textSections: [SyntheticSectionSpec],
        dataSections: [SyntheticSectionSpec] = [],
        lcFunctionStarts: [UInt64],
        symbols: [SyntheticSymbolSpec],
        entryOffset: UInt64 = 0x1000
    ) -> Data {
        let imageBase: UInt64 = 0x1_0000_0000
        let textSegSize = 0x8000
        let dataSegFileOff = 0x8000
        let dataSegSize = 0x4000
        let linkeditFileOff = 0xC000
        let linkeditVA = imageBase + UInt64(linkeditFileOff)

        var sliceBytes = [UInt8](repeating: 0, count: linkeditFileOff)
        func writeWords(_ words: [UInt32], at fileOffset: Int) {
            for (idx, w) in words.enumerated() {
                let off = fileOffset + idx * 4
                sliceBytes[off + 0] = UInt8(truncatingIfNeeded: w)
                sliceBytes[off + 1] = UInt8(truncatingIfNeeded: w >> 8)
                sliceBytes[off + 2] = UInt8(truncatingIfNeeded: w >> 16)
                sliceBytes[off + 3] = UInt8(truncatingIfNeeded: w >> 24)
            }
        }

        for sec in textSections + dataSections {
            writeWords(sec.words, at: sec.fileOffset)
        }

        // Encode LC_FUNCTION_STARTS ULEB128 delta blob
        var fsWriter = BinaryBufferWriter(capacity: 64, endianness: .little)
        var prevOff: UInt64 = 0
        for va in lcFunctionStarts.sorted() {
            let off = va - imageBase
            if off > prevOff {
                fsWriter.appendULEB128(off - prevOff)
                prevOff = off
            }
        }
        fsWriter.padToAlignment(8)

        // Encode LC_SYMTAB
        var strPool = BinaryBufferWriter(capacity: 256, endianness: .little)
        strPool.appendUInt8(0)
        var nlistWriter = BinaryBufferWriter(capacity: 64 * max(1, symbols.count), endianness: .little)
        for sym in symbols {
            let strOff = UInt32(strPool.count)
            strPool.appendCString(sym.name)
            nlistWriter.appendUInt32(strOff)
            let nType: UInt8 = MachOConstants.nSect | (sym.isExternal ? MachOConstants.nExt : 0)
            nlistWriter.appendUInt8(nType)
            nlistWriter.appendUInt8(sym.nSect)
            nlistWriter.appendUInt16(0)
            nlistWriter.appendUInt64(sym.vmAddress)
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

        var lc = BinaryBufferWriter(capacity: 2048, endianness: .little)
        var ncmds: UInt32 = 0

        func appendSegment(
            name: String,
            vmaddr: UInt64,
            vmsize: UInt64,
            fileoff: UInt64,
            filesize: UInt64,
            prot: Int32,
            secs: [SyntheticSectionSpec]
        ) {
            let cmdSize = UInt32(72 + secs.count * 80)
            lc.appendUInt32(MachOConstants.lcSegment64)
            lc.appendUInt32(cmdSize)
            lc.appendFixedASCII(name, length: 16)
            lc.appendUInt64(vmaddr)
            lc.appendUInt64(vmsize)
            lc.appendUInt64(fileoff)
            lc.appendUInt64(filesize)
            lc.appendUInt32(UInt32(bitPattern: prot))
            lc.appendUInt32(UInt32(bitPattern: prot))
            lc.appendUInt32(UInt32(secs.count))
            lc.appendUInt32(0)
            for s in secs {
                lc.appendFixedASCII(s.section, length: 16)
                lc.appendFixedASCII(s.segment, length: 16)
                lc.appendUInt64(s.vmAddress)
                lc.appendUInt64(UInt64(s.words.count * 4))
                lc.appendUInt32(UInt32(s.fileOffset))
                lc.appendUInt32(2)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(s.flags)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
            }
            ncmds += 1
        }

        appendSegment(name: "__PAGEZERO", vmaddr: 0, vmsize: imageBase, fileoff: 0, filesize: 0, prot: 0, secs: [])
        appendSegment(
            name: "__TEXT",
            vmaddr: imageBase,
            vmsize: UInt64(textSegSize),
            fileoff: 0,
            filesize: UInt64(textSegSize),
            prot: 5,
            secs: textSections
        )
        if !dataSections.isEmpty {
            appendSegment(
                name: "__DATA",
                vmaddr: imageBase + UInt64(dataSegFileOff),
                vmsize: UInt64(dataSegSize),
                fileoff: UInt64(dataSegFileOff),
                filesize: UInt64(dataSegSize),
                prot: 3,
                secs: dataSections
            )
        }
        appendSegment(
            name: "__LINKEDIT",
            vmaddr: linkeditVA,
            vmsize: 0x4000,
            fileoff: UInt64(linkeditFileOff),
            filesize: UInt64(linkedit.count),
            prot: 1,
            secs: []
        )

        // LC_MAIN
        lc.appendUInt32(MachOConstants.lcMain)
        lc.appendUInt32(24)
        lc.appendUInt64(entryOffset)
        lc.appendUInt64(0)
        ncmds += 1

        // LC_FUNCTION_STARTS
        if !lcFunctionStarts.isEmpty {
            lc.appendUInt32(MachOConstants.lcFunctionStarts)
            lc.appendUInt32(16)
            lc.appendUInt32(UInt32(fsOff))
            lc.appendUInt32(UInt32(fsWriter.count))
            ncmds += 1
        }

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
        hdr.appendUInt32(useARM64E ? 2 : 0)
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
        return Data(sliceBytes)
    }

    // MARK: - 1. cmp + csel Branchless Clamp Jump-Table Upper Bound (Full Table > 64 Entries)

    @Test("Jump-table bounds guard recognizes cmp + csel (ls/lo) clamp and recovers all 72 entries instead of truncating at 64")
    func cmpCselJumpTableRecoversFull72EntryTable() throws {
        let fnVA: UInt64 = 0x1_0000_1000
        let constTableVA: UInt64 = 0x1_0000_4000
        let caseCount = 72
        let anchorVA = fnVA + 24 // adr x17, . is at word index 6 (24 bytes)

        var textWords: [UInt32] = [
            Self.encMOV_W(rd: 16, rm: 0),                                   // +0x00: mov w16, w0
            Self.encCMP_XImm(rn: 16, imm12: UInt16(caseCount - 1)),         // +0x04: cmp x16, #71
            Self.insnCSEL_X16_X16_XZR_LS,                                   // +0x08: csel x16, x16, xzr, ls
            Self.encADRP(rd: 17, from: fnVA + 12, targetPage: constTableVA),// +0x0c: adrp x17, 0x100004000
            Self.encADD_XImm(rd: 17, rn: 17, imm12: 0),                     // +0x10: add x17, x17, #0
            Self.insnLDRSW_X16_X17_X16_LSL2,                                // +0x14: ldrsw x16, [x17, x16, lsl #2]
            Self.insnADR_X17_SELF,                                          // +0x18: adr x17, .
            Self.insnADD_X16_X17_X16,                                       // +0x1c: add x16, x17, x16
            Self.insnBR_X16                                                 // +0x20: br x16
        ]

        let firstCaseVA = fnVA + UInt64(textWords.count * 4)
        var tableWords: [UInt32] = []
        var expectedTargets: [VirtualAddress] = []
        for idx in 0..<caseCount {
            let caseVA = firstCaseVA + UInt64(idx * 8)
            expectedTargets.append(VirtualAddress(caseVA))
            textWords.append(Self.encMOVZ_W(rd: 0, imm16: UInt16(idx + 1)))
            textWords.append(Self.insnRET)
            let rel = Int32(Int64(bitPattern: caseVA) - Int64(bitPattern: anchorVA))
            tableWords.append(UInt32(bitPattern: rel))
        }

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: fnVA, fileOffset: 0x1000, words: textWords, flags: pureInsnFlags),
                .init(segment: "__TEXT", section: "__const", vmAddress: constTableVA, fileOffset: 0x4000, words: tableWords, flags: 0)
            ],
            lcFunctionStarts: [fnVA],
            symbols: [
                .init(name: "__mh_execute_header", nSect: 1, vmAddress: 0x1_0000_0000, isExternal: true),
                .init(name: "_big_switch", nSect: 1, vmAddress: fnVA, isExternal: true)
            ]
        )

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "CselSwitch72.arm64e")
        let fn = try #require(index.function(named: "_big_switch"))
        let jt = try #require(fn.jumpTables.first)
        #expect(jt.targetAddresses.count == caseCount)
        #expect(jt.targetAddresses == expectedTargets)
    }

    // MARK: - 2. Register Co-Sourcing Check Rejects Unrelated Earlier CMP

    @Test("Jump-table bounds guard requires cmp register to share provenance with table index register")
    func unrelatedRegisterCmpDoesNotTruncateOrMisguideJumpTable() throws {
        let fnVA: UInt64 = 0x1_0000_1000
        let fn2VA: UInt64 = 0x1_0000_1200
        let constTableVA: UInt64 = 0x1_0000_4000
        let constTable2VA: UInt64 = 0x1_0000_4100

        // Function 1: Unrelated `sub w9, w8, #48; cmp w9, #3; b.hi L_bail` followed by
        // `sxtw x16, w26; cmp x16, #11; csel x16, x16, xzr, ls` (12 entries).
        // Must recover 12 entries (from x16), NOT 4 entries (from w9).
        let caseCount1 = 12
        let bailTarget1 = fnVA + 0x28 + UInt64(caseCount1 * 8)
        let anchor1VA = fnVA + 0x20
        var fn1Words: [UInt32] = [
            Self.encSUB_WImm(rd: 9, rn: 8, imm12: 0x30),                    // +0x00: sub w9, w8, #0x30
            Self.encCMP_WImm(rn: 9, imm12: 3),                              // +0x04: cmp w9, #3
            Self.encBCond(cond: 0x8, from: fnVA + 0x08, to: bailTarget1),   // +0x08: b.hi L_bail (unrelated!)
            Self.encSXTW_X(rd: 16, rn: 26),                                 // +0x0c: sxtw x16, w26
            Self.encCMP_XImm(rn: 16, imm12: UInt16(caseCount1 - 1)),        // +0x10: cmp x16, #11
            Self.insnCSEL_X16_X16_XZR_LS,                                   // +0x14: csel x16, x16, xzr, ls
            Self.encADRP(rd: 17, from: fnVA + 0x18, targetPage: constTableVA),
            Self.insnLDRSW_X16_X17_X16_LSL2,                                // +0x1c: ldrsw x16, [x17, x16, lsl #2]
            Self.insnADR_X17_SELF,                                          // +0x20: adr x17, .
            Self.insnADD_X16_X17_X16,                                       // +0x24: add x16, x17, x16
            Self.insnBR_X16                                                 // +0x28: br x16
        ]
        // Wait: anchor1VA is at word index 8 (+0x20), firstCase1VA is at word index 11 (+0x2c)
        let firstCase1VA = fnVA + UInt64(fn1Words.count * 4)
        // Recompute b.hi target to exact bail block after the 12 cases
        let exactBail1VA = firstCase1VA + UInt64(caseCount1 * 8)
        fn1Words[2] = Self.encBCond(cond: 0x8, from: fnVA + 0x08, to: exactBail1VA)

        var tbl1Words: [UInt32] = []
        for idx in 0..<caseCount1 {
            let caseVA = firstCase1VA + UInt64(idx * 8)
            fn1Words.append(Self.encMOVZ_W(rd: 0, imm16: UInt16(100 + idx)))
            fn1Words.append(Self.insnRET)
            tbl1Words.append(UInt32(bitPattern: Int32(Int64(bitPattern: caseVA) - Int64(bitPattern: anchor1VA))))
        }
        // L_bail:
        fn1Words.append(Self.encMOVZ_W(rd: 0, imm16: 0))
        fn1Words.append(Self.insnRET)

        // Function 2: Has ONLY an unrelated `cmp w9, #1; b.hi L_bail2`, while `x16` comes from `x0`
        // with NO bounds check on x0/x16, and table2 has 6 valid entries followed by invalid 0x7fffffff.
        // Because w9 is unrelated to x16, bounds guard must return nil and fallback reader must read all 6 valid entries!
        let caseCount2 = 6
        let anchor2VA = fn2VA + 0x18
        var fn2Words: [UInt32] = [
            Self.encCMP_WImm(rn: 9, imm12: 1),                              // +0x00: cmp w9, #1 (unrelated!)
            Self.insnNOP,                                                   // +0x04: placeholder for b.hi L_bail2
            Self.encMOV_X(rd: 16, rm: 0),                                   // +0x08: mov x16, x0
            Self.encADRP(rd: 17, from: fn2VA + 0x0c, targetPage: constTable2VA),
            Self.encADD_XImm(rd: 17, rn: 17, imm12: 0x100),                 // +0x10: add x17, x17, #0x100
            Self.insnLDRSW_X16_X17_X16_LSL2,                                // +0x14: ldrsw x16, [x17, x16, lsl #2]
            Self.insnADR_X17_SELF,                                          // +0x18: adr x17, .
            Self.insnADD_X16_X17_X16,                                       // +0x1c: add x16, x17, x16
            Self.insnBR_X16                                                 // +0x20: br x16
        ]
        let firstCase2VA = fn2VA + UInt64(fn2Words.count * 4)
        let exactBail2VA = firstCase2VA + UInt64(caseCount2 * 8)
        fn2Words[1] = Self.encBCond(cond: 0x8, from: fn2VA + 0x04, to: exactBail2VA)

        var tbl2Words: [UInt32] = []
        for idx in 0..<caseCount2 {
            let caseVA = firstCase2VA + UInt64(idx * 8)
            fn2Words.append(Self.encMOVZ_W(rd: 0, imm16: UInt16(200 + idx)))
            fn2Words.append(Self.insnRET)
            tbl2Words.append(UInt32(bitPattern: Int32(Int64(bitPattern: caseVA) - Int64(bitPattern: anchor2VA))))
        }
        fn2Words.append(Self.encMOVZ_W(rd: 0, imm16: 999))
        fn2Words.append(Self.insnRET)
        tbl2Words.append(0x7FFF_FFFF) // sentinel outside executable sections

        // Combine fn1 + padding + fn2 in __text, and tbl1 + padding + tbl2 in __const
        var combinedText = fn1Words
        let padCount = Int((fn2VA - fnVA) / 4) - combinedText.count
        combinedText.append(contentsOf: repeatElement(Self.insnNOP, count: max(0, padCount)))
        combinedText.append(contentsOf: fn2Words)

        var combinedConst = tbl1Words
        let constPad = Int((constTable2VA - constTableVA) / 4) - combinedConst.count
        combinedConst.append(contentsOf: repeatElement(0, count: max(0, constPad)))
        combinedConst.append(contentsOf: tbl2Words)

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: fnVA, fileOffset: 0x1000, words: combinedText, flags: pureInsnFlags),
                .init(segment: "__TEXT", section: "__const", vmAddress: constTableVA, fileOffset: 0x4000, words: combinedConst, flags: 0)
            ],
            lcFunctionStarts: [fnVA, fn2VA],
            symbols: [
                .init(name: "_fn_with_earlier_cmp", nSect: 1, vmAddress: fnVA, isExternal: true),
                .init(name: "_fn_unrelated_cmp_only", nSect: 1, vmAddress: fn2VA, isExternal: true)
            ]
        )

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "RegProvenance.arm64e")
        let fn1 = try #require(index.function(named: "_fn_with_earlier_cmp"))
        let jt1 = try #require(fn1.jumpTables.first)
        #expect(jt1.targetAddresses.count == caseCount1)

        let fn2 = try #require(index.function(named: "_fn_unrelated_cmp_only"))
        let jt2 = try #require(fn2.jumpTables.first)
        #expect(jt2.targetAddresses.count == caseCount2)
    }

    // MARK: - 3. Inline Jump Table in __TEXT,__text Excluded from Function List and Instruction Stream

    @Test("Inline jump-table bytes in __TEXT,__text are stripped from function starts and function instruction slices")
    func inlineJumpTableInTextExcludedFromFunctionListAndInstructionStream() throws {
        let fnVA: UInt64 = 0x1_0000_1000
        let caseCount = 5
        // Layout inside __TEXT,__text:
        //   0x100001000: _inline_switch_fn (9 dispatch words + 5 * 2 case words = 19 words = 0x4c bytes)
        //   0x10000104c: inline jump table (5 * 4-byte signed offsets = 0x14 bytes, seeded in LC_FUNCTION_STARTS like ld_prime!)
        //   0x100001060: _following_fn (2 words: mov w0, #77; ret)
        let inlineTableVA = fnVA + 0x4C
        let followingFnVA = inlineTableVA + UInt64(caseCount * 4)
        let anchorVA = fnVA + 0x18

        var words: [UInt32] = [
            Self.encCMP_XImm(rn: 16, imm12: UInt16(caseCount)),             // +0x00: cmp x16, #5
            Self.insnCSEL_X16_X16_XZR_LO,                                   // +0x04: csel x16, x16, xzr, lo (0..<5 -> 5 entries)
            Self.encADRP(rd: 17, from: fnVA + 0x08, targetPage: inlineTableVA),
            Self.encADD_XImm(rd: 17, rn: 17, imm12: UInt16(inlineTableVA & 0xFFF)),
            Self.insnNOP,                                                   // +0x10
            Self.insnLDRSW_X16_X17_X16_LSL2,                                // +0x14: ldrsw x16, [x17, x16, lsl #2]
            Self.insnADR_X17_SELF,                                          // +0x18: adr x17, .
            Self.insnADD_X16_X17_X16,                                       // +0x1c: add x16, x17, x16
            Self.insnBR_X16                                                 // +0x20: br x16
        ]

        let firstCaseVA = fnVA + UInt64(words.count * 4) // +0x24
        var inlineTableWords: [UInt32] = []
        for idx in 0..<caseCount {
            let caseVA = firstCaseVA + UInt64(idx * 8)
            words.append(Self.encMOVZ_W(rd: 0, imm16: UInt16(10 + idx)))
            words.append(Self.insnRET)
            // Positive small delta (0x0000_000c etc. -> would decode as `udf #...` if treated as code!)
            let rel = Int32(Int64(bitPattern: caseVA) - Int64(bitPattern: anchorVA))
            inlineTableWords.append(UInt32(bitPattern: rel))
        }
        #expect(fnVA + UInt64(words.count * 4) == inlineTableVA)
        words.append(contentsOf: inlineTableWords)
        #expect(fnVA + UInt64(words.count * 4) == followingFnVA)

        // _following_fn at 0x100001060
        words.append(Self.encMOVZ_W(rd: 0, imm16: 77))
        words.append(Self.insnRET)

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: fnVA, fileOffset: 0x1000, words: words, flags: pureInsnFlags)
            ],
            // Include inlineTableVA in LC_FUNCTION_STARTS just like Apple ld_prime does
            lcFunctionStarts: [fnVA, inlineTableVA, followingFnVA],
            symbols: [
                .init(name: "_inline_switch_fn", nSect: 1, vmAddress: fnVA, isExternal: true),
                .init(name: "_following_fn", nSect: 1, vmAddress: followingFnVA, isExternal: true)
            ]
        )

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "InlineJT.arm64e")

        // Must recover only the 2 real code functions, NOT a fake function at inlineTableVA
        #expect(index.functions.map(\.address) == [VirtualAddress(fnVA), VirtualAddress(followingFnVA)])

        let switchFn = try #require(index.function(at: VirtualAddress(fnVA)))
        #expect(switchFn.endAddress == VirtualAddress(inlineTableVA))
        #expect(switchFn.jumpTables.first?.targetAddresses.count == caseCount)
        #expect(switchFn.jumpTables.first?.isInlineInCode == true)
        #expect(switchFn.inlineJumpTableRanges == [AddressRange(start: VirtualAddress(inlineTableVA), size: UInt64(caseCount * 4))])
        #expect(index.inlineJumpTableRanges == [AddressRange(start: VirtualAddress(inlineTableVA), size: UInt64(caseCount * 4))])
        #expect(index.inlineJumpTableStarts == [VirtualAddress(inlineTableVA)])

        // Neither block instructions nor index.decodedInstructions may contain table data bytes [inlineTableVA, followingFnVA)
        let allBlockInsnAddrs = index.functions.flatMap(\.blocks).flatMap(\.instructions).map(\.address.rawValue)
        #expect(!allBlockInsnAddrs.contains { $0 >= inlineTableVA && $0 < followingFnVA })
        #expect(!index.decodedInstructions.contains { $0.address.rawValue >= inlineTableVA && $0.address.rawValue < followingFnVA })
    }

    // MARK: - 4. UDF Terminates Basic Block Without Changing Disassembly Text

    @Test("UDF decodes as basic-block terminator with no fallthrough edge while preserving udf mnemonic and #0x... operand text")
    func udfTerminatesBasicBlockWithoutChangingDisassemblyText() throws {
        let baseVA: UInt64 = 0x1_0000_2000
        let words: [UInt32] = [
            Self.encCBZ_W(rt: 0, from: baseVA + 0x00, to: baseVA + 0x08), // +0x00: cbz w0, L_ok (+0x08)
            Self.insnUDFDead,                                              // +0x04: udf #0xdead
            Self.encMOVZ_W(rd: 0, imm16: 1),                               // +0x08: L_ok: mov w0, #1
            Self.insnRET                                                   // +0x0c: ret
        ]
        let decoded = A64InstructionDecoder().decodeWords(words, baseAddress: VirtualAddress(baseVA))
        #expect(decoded[1].mnemonicText == "udf")
        #expect(decoded[1].operandText == "#0xdead")
        #expect(decoded[1].formattedDisassembly == "udf #0xdead")
        #expect(decoded[1].flow.terminatesBasicBlock)

        let cfg = CFGBuilderEngine().buildCFG(
            functionAddress: VirtualAddress(baseVA),
            name: "_udf_trap_fn",
            instructions: decoded
        )

        #expect(cfg.blocks.count == 3)
        let udfBlock = try #require(cfg.blocks.first { $0.startAddress == VirtualAddress(baseVA + 0x04) })
        #expect(udfBlock.instructions.count == 1)
        #expect(udfBlock.successorIDs.isEmpty)
        #expect(udfBlock.isExit)

        let okBlock = try #require(cfg.blocks.first { $0.startAddress == VirtualAddress(baseVA + 0x08) })
        #expect(okBlock.predecessorIDs == [0])
    }

    // MARK: - 5. Noreturn Imported Calls & Trailing BL at Function End

    @Test("BL to known noreturn symbols omits fallthrough edge and marks block as exit, and trailing BL at fnEnd is marked exit")
    func noreturnDirectCallAndTrailingCallHaveNoFallthroughAndMarkExit() throws {
        let fnMidVA: UInt64 = 0x1_0000_1000
        let fnTailVA: UInt64 = 0x1_0000_1018
        let fnUnknownHelperVA: UInt64 = 0x1_0000_1020
        let stubsVA: UInt64 = 0x1_0000_2000

        // _mid_noreturn @ 0x100001000 (6 words = 0x18 bytes):
        //   +0x00: cbnz w0, L_safe (+0x10)
        //   +0x04: mov w0, #1
        //   +0x08: bl ___stack_chk_fail (0x100002000)  <-- noreturn! Must split here, no fallthrough to +0x0c or +0x10!
        //   +0x0c: nop
        //   +0x10: L_safe: mov w0, #42
        //   +0x14: ret
        // _tail_bl @ 0x100001018 (2 words = 0x08 bytes):
        //   +0x00: mov w0, #9
        //   +0x04: bl _unknown_helper (0x100001020)     <-- last insn of _tail_bl (next addr == fnEnd == 0x100001020)
        // _unknown_helper @ 0x100001020:
        //   +0x00: ret
        let textWords: [UInt32] = [
            Self.encCBNZ_W(rt: 0, from: fnMidVA + 0x00, to: fnMidVA + 0x10),
            Self.encMOVZ_W(rd: 0, imm16: 1),
            Self.encBL(from: fnMidVA + 0x08, to: stubsVA),
            Self.insnNOP,
            Self.encMOVZ_W(rd: 0, imm16: 42),
            Self.insnRET,
            // _tail_bl:
            Self.encMOVZ_W(rd: 0, imm16: 9),
            Self.encBL(from: fnTailVA + 0x04, to: fnUnknownHelperVA),
            // _unknown_helper:
            Self.insnRET
        ]

        let stubWords: [UInt32] = [
            Self.insnBR_X16
        ]

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let stubFlags = MachOConstants.sSymbolStubs | pureInsnFlags
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: fnMidVA, fileOffset: 0x1000, words: textWords, flags: pureInsnFlags),
                .init(segment: "__TEXT", section: "__stubs", vmAddress: stubsVA, fileOffset: 0x2000, words: stubWords, flags: stubFlags)
            ],
            lcFunctionStarts: [fnMidVA, fnTailVA, fnUnknownHelperVA],
            symbols: [
                .init(name: "_mid_noreturn", nSect: 1, vmAddress: fnMidVA, isExternal: true),
                .init(name: "_tail_bl", nSect: 1, vmAddress: fnTailVA, isExternal: true),
                .init(name: "_unknown_helper", nSect: 1, vmAddress: fnUnknownHelperVA, isExternal: true),
                .init(name: "___stack_chk_fail", nSect: 2, vmAddress: stubsVA, isExternal: true)
            ]
        )

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "NoreturnCall.arm64e")

        let midFn = try #require(index.function(named: "_mid_noreturn"))
        let failBlock = try #require(midFn.blocks.first { $0.startAddress == VirtualAddress(fnMidVA + 0x04) })
        #expect(failBlock.instructions.last?.address == VirtualAddress(fnMidVA + 0x08))
        #expect(failBlock.successorIDs.isEmpty)
        #expect(failBlock.isExit)
        #expect(!midFn.edges.contains { $0.sourceBlockID == failBlock.id })

        let safeBlock = try #require(midFn.blocks.first { $0.startAddress == VirtualAddress(fnMidVA + 0x10) })
        #expect(safeBlock.predecessorIDs.count == 1)

        let tailFn = try #require(index.function(named: "_tail_bl"))
        let tailBlock = try #require(tailFn.blocks.last)
        #expect(tailBlock.successorIDs.isEmpty)
        #expect(tailBlock.isExit)
    }

    // MARK: - 6. Fixed-Point Noreturn Propagation Across Internal Wrapper Functions

    @Test("Fixed-point noreturn analysis propagates from _abort/_exit through multi-hop internal fatal wrappers")
    func noreturnFixedPointPropagatesThroughInternalWrapperChain() throws {
        let callerVA: UInt64 = 0x1_0000_1000
        let fatalMidVA: UInt64 = 0x1_0000_1018
        let fatalLeafVA: UInt64 = 0x1_0000_1030
        let normalHelperVA: UInt64 = 0x1_0000_1038
        let abortStubVA: UInt64 = 0x1_0000_2000
        let exitStubVA: UInt64 = 0x1_0000_2004

        // _caller @ 0x100001000 (6 words = 0x18 bytes):
        //   +0x00: cbz w0, L_fatal (+0x0c)
        //   +0x04: bl _normal_helper      <-- returns! Must keep fallthrough to L_done (+0x10)!
        //   +0x08: b L_done (+0x10)
        //   +0x0c: L_fatal: bl _fatal_mid <-- 2-hop internal noreturn wrapper! Must NOT fall through to L_done (+0x10)!
        //   +0x10: L_done: mov w0, #0
        //   +0x14: ret
        //
        // _fatal_mid @ 0x100001018 (6 words = 0x18 bytes):
        //   +0x00: cbnz w0, L_use_exit (+0x0c)
        //   +0x04: bl _fatal_leaf
        //   +0x08: nop
        //   +0x0c: L_use_exit: mov w0, #1
        //   +0x10: bl _exit
        //   +0x14: nop
        //
        // _fatal_leaf @ 0x100001030 (2 words = 0x08 bytes):
        //   +0x00: mov w0, #2
        //   +0x04: bl _abort
        //
        // _normal_helper @ 0x100001038 (2 words = 0x08 bytes):
        //   +0x00: mov w0, #3
        //   +0x04: ret
        let textWords: [UInt32] = [
            // _caller:
            Self.encCBZ_W(rt: 0, from: callerVA + 0x00, to: callerVA + 0x0C),
            Self.encBL(from: callerVA + 0x04, to: normalHelperVA),
            Self.encB(from: callerVA + 0x08, to: callerVA + 0x10),
            Self.encBL(from: callerVA + 0x0C, to: fatalMidVA),
            Self.encMOVZ_W(rd: 0, imm16: 0),
            Self.insnRET,
            // _fatal_mid:
            Self.encCBNZ_W(rt: 0, from: fatalMidVA + 0x00, to: fatalMidVA + 0x0C),
            Self.encBL(from: fatalMidVA + 0x04, to: fatalLeafVA),
            Self.insnNOP,
            Self.encMOVZ_W(rd: 0, imm16: 1),
            Self.encBL(from: fatalMidVA + 0x10, to: exitStubVA),
            Self.insnNOP,
            // _fatal_leaf:
            Self.encMOVZ_W(rd: 0, imm16: 2),
            Self.encBL(from: fatalLeafVA + 0x04, to: abortStubVA),
            // _normal_helper:
            Self.encMOVZ_W(rd: 0, imm16: 3),
            Self.insnRET
        ]

        let stubWords: [UInt32] = [
            Self.insnBR_X16,
            Self.insnBR_X16
        ]

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let stubFlags = MachOConstants.sSymbolStubs | pureInsnFlags
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: callerVA, fileOffset: 0x1000, words: textWords, flags: pureInsnFlags),
                .init(segment: "__TEXT", section: "__stubs", vmAddress: abortStubVA, fileOffset: 0x2000, words: stubWords, flags: stubFlags)
            ],
            lcFunctionStarts: [callerVA, fatalMidVA, fatalLeafVA, normalHelperVA],
            symbols: [
                .init(name: "_caller", nSect: 1, vmAddress: callerVA, isExternal: true),
                .init(name: "_fatal_mid", nSect: 1, vmAddress: fatalMidVA, isExternal: false),
                .init(name: "_fatal_leaf", nSect: 1, vmAddress: fatalLeafVA, isExternal: false),
                .init(name: "_normal_helper", nSect: 1, vmAddress: normalHelperVA, isExternal: false),
                .init(name: "_abort", nSect: 2, vmAddress: abortStubVA, isExternal: true),
                .init(name: "_exit", nSect: 2, vmAddress: exitStubVA, isExternal: true)
            ]
        )

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "NoreturnWrapper.arm64e")
        let callerFn = try #require(index.function(named: "_caller"))

        let fatalCallBlock = try #require(callerFn.blocks.first { $0.startAddress == VirtualAddress(callerVA + 0x0C) })
        #expect(fatalCallBlock.successorIDs.isEmpty)
        #expect(fatalCallBlock.isExit)

        let doneBlock = try #require(callerFn.blocks.first { $0.startAddress == VirtualAddress(callerVA + 0x10) })
        #expect(!doneBlock.predecessorIDs.contains(fatalCallBlock.id))
        #expect(doneBlock.predecessorIDs.count == 1)
    }

    // MARK: - 7. __objc_stubs Skips NOP and BRK Padding Without Splitting Stubs

    @Test("__TEXT,__objc_stubs skips trailing nop and brk padding so each selector stub is recovered as one function")
    func objcStubsSectionSkipsNopAndBrkPaddingWithoutSplittingStubs() throws {
        let textVA: UInt64 = 0x1_0000_1000
        let objcStubsVA: UInt64 = 0x1_0000_2000
        let dataPtrVA: UInt64 = 0x1_0000_8000

        // Two 32-byte ARM64e ObjC selector stubs (each 6 code words + 2 `brk #0x1` trap padding words)
        func makeObjCStub(at stubVA: UInt64, selOff: UInt16) -> [UInt32] {
            [
                Self.encADRP(rd: 1, from: stubVA + 0x00, targetPage: dataPtrVA),
                Self.encLDR_XImm(rt: 1, rn: 1, byteOffset: selOff),
                Self.encADRP(rd: 17, from: stubVA + 0x08, targetPage: dataPtrVA),
                Self.encADD_XImm(rd: 17, rn: 17, imm12: 0x10),
                Self.encLDR_XImm(rt: 16, rn: 17, byteOffset: 0),
                Self.insnBRAA_X16_X17,
                Self.insnBRK1,
                Self.insnBRK1
            ]
        }

        let stub0VA = objcStubsVA
        let stub1VA = objcStubsVA + 0x20
        let objcStubWords = makeObjCStub(at: stub0VA, selOff: 0) + makeObjCStub(at: stub1VA, selOff: 8)

        let textWords: [UInt32] = [
            Self.encBL(from: textVA + 0x00, to: stub0VA),
            Self.encBL(from: textVA + 0x04, to: stub1VA),
            Self.insnRET
        ]

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: textVA, fileOffset: 0x1000, words: textWords, flags: pureInsnFlags),
                .init(segment: "__TEXT", section: "__objc_stubs", vmAddress: objcStubsVA, fileOffset: 0x2000, words: objcStubWords, flags: pureInsnFlags)
            ],
            dataSections: [
                .init(segment: "__DATA", section: "__data", vmAddress: dataPtrVA, fileOffset: 0x8000, words: [0, 0, 0, 0, 0, 0], flags: 0)
            ],
            lcFunctionStarts: [textVA],
            symbols: [
                .init(name: "_objc_caller", nSect: 1, vmAddress: textVA, isExternal: true)
            ]
        )

        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjCStubs.arm64e")
        let engine = FunctionDiscoveryEngine()
        let decoded = try engine.decodeExecutableSections(in: image, data: data)
        let boundaries = engine.discoverFunctions(in: image, decodedSections: decoded, data: data)

        let objcStubBoundaries = boundaries.filter { $0.sectionName == "__TEXT,__objc_stubs" }
        #expect(objcStubBoundaries.count == 2)
        #expect(objcStubBoundaries.map(\.startAddress) == [VirtualAddress(stub0VA), VirtualAddress(stub1VA)])
    }

    // MARK: - 8. info Function Starts Excludes Non-Executable __mh_execute_header (0x100000000)

    @Test("LoadedBinaryImage and info --json exclude non-executable __mh_execute_header and match raw LC_FUNCTION_STARTS")
    func infoFunctionStartsExcludesNonExecutableHeaderAndMatchesLCFunctionStarts() async throws {
        let fn1VA: UInt64 = 0x1_0000_1000
        let fn2VA: UInt64 = 0x1_0000_1008
        let dataVA: UInt64 = 0x1_0000_8000

        let textWords: [UInt32] = [
            Self.encMOVZ_W(rd: 0, imm16: 1),
            Self.insnRET,
            Self.encMOVZ_W(rd: 0, imm16: 2),
            Self.insnRET
        ]

        let pureInsnFlags = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        let data = Self.buildSyntheticMachO(
            textSections: [
                .init(segment: "__TEXT", section: "__text", vmAddress: fn1VA, fileOffset: 0x1000, words: textWords, flags: pureInsnFlags)
            ],
            dataSections: [
                .init(segment: "__DATA", section: "__data", vmAddress: dataVA, fileOffset: 0x8000, words: [0x1234_5678], flags: 0)
            ],
            lcFunctionStarts: [fn1VA, fn2VA],
            symbols: [
                .init(name: "__mh_execute_header", nSect: 1, vmAddress: 0x1_0000_0000, isExternal: true),
                .init(name: "_fn_one", nSect: 1, vmAddress: fn1VA, isExternal: true),
                .init(name: "_fn_two", nSect: 1, vmAddress: fn2VA, isExternal: true),
                .init(name: "_exported_global", nSect: 2, vmAddress: dataVA, isExternal: true)
            ]
        )

        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "FuncStartsCheck.arm64e")
        #expect(image.lcFunctionStarts == [VirtualAddress(fn1VA), VirtualAddress(fn2VA)])
        #expect(!image.functionStarts.contains(VirtualAddress(0x1_0000_0000)))
        #expect(!image.functionStarts.contains(VirtualAddress(dataVA)))
        #expect(image.functionStarts == [VirtualAddress(fn1VA), VirtualAddress(fn2VA)])

        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("mg-m4-info-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let binURL = tmpDir.appendingPathComponent("FuncStartsCheck.arm64e")
        try data.write(to: binURL)

        let jsonStr = try await MachCLIRunner().execute(arguments: ["info", binURL.path, "--json"])
        let jsonObj = try #require(try JSONSerialization.jsonObject(with: Data(jsonStr.utf8)) as? [String: Any])
        let fsCount = try #require(jsonObj["functionStartsCount"] as? Int)
        #expect(fsCount == 2)
        let lcStarts = try #require(jsonObj["lcFunctionStarts"] as? [UInt64])
        #expect(lcStarts == [fn1VA, fn2VA])
    }
}
