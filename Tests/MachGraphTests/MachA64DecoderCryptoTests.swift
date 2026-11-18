import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("MachA64Decoder Cryptographic Extensions")
struct MachA64DecoderCryptoTests {

    private let decoder = A64InstructionDecoder()

    @Test("Stage 14 Group 17: Cryptographic AES samples, register tracking, and unallocated guards")
    func cryptoAESSamplesAndSemantics() {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x4E28_4840, "aese v0.16b, v2.16b"),     // /usr/libexec/DumpPanic
            (0x4E28_782C, "aesimc v12.16b, v1.16b"),  // seed 17 fuzz & /usr/libexec/DumpPanic
            (0x4E28_5841, "aesd v1.16b, v2.16b"),     // crypto_aes.tsv
            (0x4E28_6841, "aesmc v1.16b, v2.16b"),    // crypto_aes.tsv
            (0x4E28_4BFF, "aese v31.16b, v31.16b"),   // crypto_aes.tsv high-register dedup
            (0x4E28_6BFF, "aesmc v31.16b, v31.16b"),  // crypto_aes.tsv
        ]

        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .eorVec, "word=0x\(String(word, radix: 16))")
            #expect(decoded.group == .simdAndFP, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Destructive round operations (AESE, AESD) read both Vd and Vn; deduplicate when Vd == Vn:
        let aeseDistinct = decoder.decode(word: 0x4E28_4840, at: pc)
        #expect(aeseDistinct.readsRegisters == [.v(0, arrangement: "16b"), .v(2, arrangement: "16b")])
        #expect(aeseDistinct.writesRegisters == [.v(0, arrangement: "16b")])

        let aeseSame = decoder.decode(word: 0x4E28_4BFF, at: pc)
        #expect(aeseSame.readsRegisters == [.v(31, arrangement: "16b")])
        #expect(aeseSame.writesRegisters == [.v(31, arrangement: "16b")])

        let aesdDistinct = decoder.decode(word: 0x4E28_5841, at: pc)
        #expect(aesdDistinct.readsRegisters == [.v(1, arrangement: "16b"), .v(2, arrangement: "16b")])
        #expect(aesdDistinct.writesRegisters == [.v(1, arrangement: "16b")])

        // Non-destructive MixColumns operations (AESMC, AESIMC) read only Vn:
        let aesimc = decoder.decode(word: 0x4E28_782C, at: pc)
        #expect(aesimc.readsRegisters == [.v(1, arrangement: "16b")])
        #expect(aesimc.writesRegisters == [.v(12, arrangement: "16b")])

        // Unallocated encodings in AES space (non-zero size or unallocated opcode) must decode as .inst:
        let mustRemainInst: [UInt32] = [
            0x4E28_0841, // size=0, opcode=0b00000
            0x4E28_3841, // size=0, opcode=0b00011
            0x4E28_8841, // size=0, opcode=0b01000
            0x4E68_4841, // size=1, opcode=0b00100
            0x4EA8_5841, // size=2, opcode=0b00101
            0x4EE8_782C, // size=3, opcode=0b00111
        ]
        for badWord in mustRemainInst {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }
    }

    @Test("Stage 14 Group 17: Exhaustive field table crypto_aes.tsv matches reference disassembly")
    func cryptoAESTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("crypto_aes"), encoding: .utf8)
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

        #expect(rowCount == 256)
        #expect(mismatches.isEmpty, "Group 17 crypto_aes mismatches: \(mismatches.joined(separator: "; "))")
    }
}
