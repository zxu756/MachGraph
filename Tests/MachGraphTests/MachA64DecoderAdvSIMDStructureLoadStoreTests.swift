import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("MachA64Decoder AdvSIMD Structure Load/Store")
struct MachA64DecoderAdvSIMDStructureLoadStoreTests {

    private let decoder = A64InstructionDecoder()

    @Test("Stage 13 Group 9: AdvSIMD single-structure load/store samples, register tracking, and must-be-zero guards")
    func advsimdSingleStructureSamplesAndSemantics() {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x0D9F_8100, "st1 { v0.s }[0], [x8], #4"),
            (0x4D40_8500, "ld1 { v0.d }[1], [x8]"),
            (0x4D40_C841, "ld1r { v1.4s }, [x2]"),
            (0x0DDF_CC41, "ld1r { v1.1d }, [x2], #8"),
            (0x4DE3_A441, "ld4 { v1.d, v2.d, v3.d, v4.d }[1], [x2], x3"),
            (0x4DBF_A441, "st4 { v1.d, v2.d, v3.d, v4.d }[1], [x2], #32"),
            (0x4DFF_E7FF, "ld4r { v31.8h, v0.8h, v1.8h, v2.8h }, [sp], #8"),
            (0x0D00_23FF, "st3 { v31.b, v0.b, v1.b }[0], [sp]"),
        ]

        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.group == .simdAndFP, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Verify non-scalar mnemonic selection (.ins for loads, .umov for stores) and register tracking:
        let ld4Single = decoder.decode(word: 0x4DE3_A441, at: pc)
        #expect(ld4Single.mnemonic == .ins)
        #expect(ld4Single.mnemonicText == "ld4")
        #expect(
            ld4Single.readsRegisters == [
                .x(2), .x(3),
                .v(1, arrangement: "d"), .v(2, arrangement: "d"),
                .v(3, arrangement: "d"), .v(4, arrangement: "d"),
            ]
        )
        #expect(
            ld4Single.writesRegisters == [
                .v(1, arrangement: "d"), .v(2, arrangement: "d"),
                .v(3, arrangement: "d"), .v(4, arrangement: "d"),
                .x(2),
            ]
        )

        let ld1rNoOffset = decoder.decode(word: 0x4D40_C841, at: pc)
        #expect(ld1rNoOffset.mnemonic == .ins)
        #expect(ld1rNoOffset.mnemonicText == "ld1r")
        #expect(ld1rNoOffset.readsRegisters == [.x(2)])
        #expect(ld1rNoOffset.writesRegisters == [.v(1, arrangement: "4s")])

        let st1PostImm = decoder.decode(word: 0x0D9F_8100, at: pc)
        #expect(st1PostImm.mnemonic == .umov)
        #expect(st1PostImm.mnemonicText == "st1")
        #expect(st1PostImm.readsRegisters == [.x(8), .v(0, arrangement: "s")])
        #expect(st1PostImm.writesRegisters == [.x(8)])

        let st3SpNoOffset = decoder.decode(word: 0x0D00_23FF, at: pc)
        #expect(st3SpNoOffset.mnemonic == .umov)
        #expect(st3SpNoOffset.mnemonicText == "st3")
        #expect(
            st3SpNoOffset.readsRegisters == [
                .sp,
                .v(31, arrangement: "b"), .v(0, arrangement: "b"), .v(1, arrangement: "b"),
            ]
        )
        #expect(st3SpNoOffset.writesRegisters.isEmpty)

        // Corpus data words in single-structure space with non-zero bits[20:16] when bit[23]==0,
        // plus Group 21 multiple-structure encodings (Stage 13b), must remain .inst:
        let mustRemainInst: [UInt32] = [
            0x0D0C_0B0A,
            0x0D0E_0F10,
            0x4D2C_6DFC,
            0x4C00_8161,
        ]
        for badWord in mustRemainInst {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }
    }

    @Test("Stage 13 Group 9: Exhaustive field table advsimd_ldst_single.tsv matches reference disassembly")
    func advsimdSingleStructureTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_ldst_single"), encoding: .utf8)
        var rowCount = 0
        var mismatches: [String] = []

        for line in rawText.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("#") { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let parts = line.split(separator: "\t", maxSplits: 2)
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            let expectedMnem = String(parts[1])
            let expectedOps = parts.count > 2
                ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces)
                : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(
                            String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly)
                        )
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(
                            String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly)
                        )
                    }
                }
            }
        }

        #expect(rowCount == 3584)
        #expect(mismatches.isEmpty, "Group 9 advsimd_ldst_single mismatches: \(mismatches.joined(separator: "; "))")
    }
}
