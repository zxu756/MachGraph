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

    @Test("Stage 14 Group 23: Cryptographic four-register & XAR samples, register tracking, and SHA512/SM3/unallocated guards")
    func cryptoSHA3SamplesAndSemantics() {
        let pc = VirtualAddress(0x1_0000_2000)

        let sampleCases: [(UInt32, String)] = [
            (0xCE10_4ABC, "eor3 v28.16b, v21.16b, v16.16b, v18.16b"), // /usr/libexec/AssetCache/AssetCache
            (0xCE32_06CF, "bcax v15.16b, v22.16b, v18.16b, v1.16b"),  // seed 20261117 fuzz
            (0xCE83_4960, "xar v0.2d, v11.2d, v3.2d, #0x12"),         // seed 17 fuzz
            (0xCE03_1041, "eor3 v1.16b, v2.16b, v3.16b, v4.16b"),     // crypto_sha3.tsv
            (0xCE23_1041, "bcax v1.16b, v2.16b, v3.16b, v4.16b"),     // crypto_sha3.tsv
            (0xCE83_0041, "xar v1.2d, v2.2d, v3.2d, #0x0"),           // crypto_sha3.tsv imm6=0
            (0xCE83_8041, "xar v1.2d, v2.2d, v3.2d, #0x20"),          // crypto_sha3.tsv imm6=32
            (0xCE9F_FFFF, "xar v31.2d, v31.2d, v31.2d, #0x3f"),       // crypto_sha3.tsv imm6=63 & dedup
        ]

        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .eorVec, "word=0x\(String(word, radix: 16))")
            #expect(decoded.group == .simdAndFP, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        let eor3 = decoder.decode(word: 0xCE10_4ABC, at: pc)
        #expect(
            eor3.readsRegisters == [
                .v(21, arrangement: "16b"),
                .v(16, arrangement: "16b"),
                .v(18, arrangement: "16b"),
            ]
        )
        #expect(eor3.writesRegisters == [.v(28, arrangement: "16b")])

        let bcax = decoder.decode(word: 0xCE32_06CF, at: pc)
        #expect(
            bcax.readsRegisters == [
                .v(22, arrangement: "16b"),
                .v(18, arrangement: "16b"),
                .v(1, arrangement: "16b"),
            ]
        )
        #expect(bcax.writesRegisters == [.v(15, arrangement: "16b")])

        let xar = decoder.decode(word: 0xCE83_4960, at: pc)
        #expect(xar.readsRegisters == [.v(11, arrangement: "2d"), .v(3, arrangement: "2d")])
        #expect(xar.writesRegisters == [.v(0, arrangement: "2d")])

        let xarDedup = decoder.decode(word: 0xCE9F_FFFF, at: pc)
        #expect(xarDedup.readsRegisters == [.v(31, arrangement: "2d")])
        #expect(xarDedup.writesRegisters == [.v(31, arrangement: "2d")])

        // Unallocated encodings in 0xCE00_0000..0xCEFF_FFFF, apple-m1 unsupported SM3/SM4,
        // and out-of-scope SHA512 / RAX1 must decode as .inst:
        let mustRemainInst: [UInt32] = [
            0xCE03_9041, // Op0=00, bit[15]=1 (.long)
            0xCE23_9041, // Op0=01, bit[15]=1 (.long)
            0xCE43_1041, // Op0=10, bit[15]=0 (sm3ss1 -> .long on apple-m1)
            0xCE63_1041, // Op0=11, bit[15]=0 (.long)
            0xCE63_9041, // Op0=11, bit[15]=1, Ra=4 (.long)
            0xCE75_869B, // sha512h2 (seed 17 fuzz, out of scope -> must remain .inst)
            0xCE78_8F84, // rax1 (seed 20261117 fuzz, out of scope -> must remain .inst)
            0xCEC0_8041, // sha512su0 in 0xCEC0_0000 (out of scope -> must remain .inst)
            0xCEA3_0041, // 0xCE80_0000 sibling bits[23:21]=0b101 (.long)
        ]
        for badWord in mustRemainInst {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }
    }

    @Test("Stage 14 Group 23: Exhaustive field table crypto_sha3.tsv matches reference disassembly")
    func cryptoSHA3TableParity() throws {
        let pc = VirtualAddress(0x1_0000_2000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("crypto_sha3"), encoding: .utf8)
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

        #expect(rowCount == 24)
        #expect(mismatches.isEmpty, "Group 23 crypto_sha3 mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 14 Group 25: Cryptographic SHA1 & SHA256 samples, register tracking, and unallocated guards")
    func cryptoSHASamplesAndSemantics() {
        let pc = VirtualAddress(0x1_0000_3000)

        let sampleCases: [(UInt32, String)] = [
            (0x5E04_4272, "sha256h q18, q19, v4.4s"),  // /usr/libexec/DumpPanic
            (0x5E28_2820, "sha256su0 v0.4s, v1.4s"),   // /usr/libexec/DumpPanic
            (0x5E1A_0052, "sha1c q18, s2, v26.4s"),    // seed 17 fuzz
            (0x5E01_207B, "sha1m q27, s3, v1.4s"),     // seed 20261117 fuzz
            (0x5E03_1041, "sha1p q1, s2, v3.4s"),      // crypto_sha.tsv
            (0x5E03_3041, "sha1su0 v1.4s, v2.4s, v3.4s"),
            (0x5E03_5041, "sha256h2 q1, q2, v3.4s"),
            (0x5E03_6041, "sha256su1 v1.4s, v2.4s, v3.4s"),
            (0x5E28_0841, "sha1h s1, s2"),
            (0x5E28_1841, "sha1su1 v1.4s, v2.4s"),
        ]

        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .eorVec, "word=0x\(String(word, radix: 16))")
            #expect(decoded.group == .simdAndFP, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        let sha256h = decoder.decode(word: 0x5E04_4272, at: pc)
        #expect(sha256h.readsRegisters == [.q(18), .q(19), .v(4, arrangement: "4s")])
        #expect(sha256h.writesRegisters == [.q(18)])

        let sha1c = decoder.decode(word: 0x5E1A_0052, at: pc)
        #expect(sha1c.readsRegisters == [.q(18), .s(2), .v(26, arrangement: "4s")])
        #expect(sha1c.writesRegisters == [.q(18)])

        let sha1h = decoder.decode(word: 0x5E28_0841, at: pc)
        #expect(sha1h.readsRegisters == [.s(2)])
        #expect(sha1h.writesRegisters == [.s(1)])

        let sha256su0 = decoder.decode(word: 0x5E28_2820, at: pc)
        #expect(sha256su0.readsRegisters == [.v(0, arrangement: "4s"), .v(1, arrangement: "4s")])
        #expect(sha256su0.writesRegisters == [.v(0, arrangement: "4s")])

        // Unallocated encodings in 3-reg (0x5E00_0000) and 2-reg (0x5E28_0800) SHA spaces must decode as .inst:
        let mustRemainInst: [UInt32] = [
            0x5E03_7041, // 3-reg size=0, opcode=7
            0x5E43_0041, // 3-reg size=1, opcode=0
            0x5E83_4041, // 3-reg size=2, opcode=4
            0x5EC3_6041, // 3-reg size=3, opcode=6
            0x5E28_3841, // 2-reg size=0, opcode=3
            0x5E68_0841, // 2-reg size=1, opcode=0
            0x5EA8_2841, // 2-reg size=2, opcode=2
        ]
        for badWord in mustRemainInst {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }
    }

    @Test("Stage 14 Group 25: Exhaustive field table crypto_sha.tsv matches reference disassembly")
    func cryptoSHATableParity() throws {
        let pc = VirtualAddress(0x1_0000_3000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("crypto_sha"), encoding: .utf8)
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

        #expect(rowCount == 320)
        #expect(mismatches.isEmpty, "Group 25 crypto_sha mismatches: \(mismatches.joined(separator: "; "))")
    }
}
