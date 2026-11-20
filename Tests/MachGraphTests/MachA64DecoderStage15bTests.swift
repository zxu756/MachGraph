import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine

@Suite("M2 Stage 15b: Operand Classes, Wrong-Word Gate, Self-Check, G50, PAC XZR & Reference Table Property Tests")
struct MachA64DecoderStage15bTests {

    private let decoder = A64InstructionDecoder()
    private let assembler = A64MiniAssembler()

    private struct TableStats {
        let name: String
        var totalRows: Int = 0
        var skippedInst: Int = 0
        var ok: Int = 0
        var equivalent: Int = 0
        var unsupported: Int = 0
        var errors: Int = 0
        var wrongWords: Int = 0
    }

    private static func discoverReferenceTables() throws -> [(name: String, url: URL)] {
        let fixturesDir = RepoFixtures.repositoryRoot.appendingPathComponent("Fixtures", isDirectory: true)
        let a64Dir = fixturesDir.appendingPathComponent("a64", isDirectory: true)
        let entries = try FileManager.default.contentsOfDirectory(
            at: a64Dir,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        let a64Tables = entries
            .filter { $0.pathExtension.lowercased() == "tsv" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { (name: "a64/\($0.lastPathComponent)", url: $0) }

        #expect(a64Tables.count >= 38, "Expected at least 38 Fixtures/a64/*.tsv tables, found \(a64Tables.count)")

        let m1Tables: [(name: String, url: URL)] = [
            ("hint_llvm_table.tsv", RepoFixtures.hintAliasTableURL),
            ("sys_crn7_8_llvm_table.tsv", RepoFixtures.sysAliasTableURL),
        ]
        return a64Tables + m1Tables
    }

    @Test("15b(1.a): Every non-.inst row across all Fixtures/a64/*.tsv and M1 TSV tables round-trips or throws assemblerUnsupported")
    func referenceTablesRoundTripOrThrowUnsupported() throws {
        let tables = try Self.discoverReferenceTables()
        var allStats: [TableStats] = []
        allStats.reserveCapacity(tables.count)

        for table in tables {
            let rawText = try String(contentsOf: table.url, encoding: .utf8)
            var stats = TableStats(name: table.name)
            var rowIndex: UInt64 = 0

            for rawLine in rawText.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
                let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty || trimmed.hasPrefix("#") {
                    continue
                }
                let cols = rawLine.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
                guard let firstCol = cols.first else { continue }
                let hexPart = firstCol.hasPrefix("0x") || firstCol.hasPrefix("0X")
                    ? firstCol.dropFirst(2)
                    : firstCol[...]
                let word = try #require(
                    UInt32(hexPart, radix: 16),
                    "Malformed hex word '\(firstCol)' in \(table.name)"
                )

                let addr = VirtualAddress(0x1_0000_0000 + rowIndex * 4)
                rowIndex += 1
                stats.totalRows += 1

                let decoded = decoder.decode(word: word, at: addr)
                if decoded.mnemonicText == ".inst" {
                    stats.skippedInst += 1
                    continue
                }

                let text = decoded.formattedDisassembly
                do {
                    let encoded = try assembler.assembleSingle(text, at: addr)
                    if encoded == word {
                        stats.ok += 1
                    } else {
                        let redecoded = decoder.decode(word: encoded, at: addr)
                        if redecoded.mnemonicText != ".inst" && redecoded.formattedDisassembly == text {
                            stats.equivalent += 1
                        } else {
                            stats.wrongWords += 1
                            Issue.record(
                                Comment(
                                    rawValue: String(
                                        format: "[%@] word=0x%08x text='%@' produced wrong word 0x%08x ('%@')",
                                        table.name,
                                        word,
                                        text,
                                        encoded,
                                        redecoded.formattedDisassembly
                                    )
                                )
                            )
                        }
                    }
                } catch let err as MachGraphError {
                    if case .assemblerUnsupported = err {
                        stats.unsupported += 1
                    } else {
                        stats.errors += 1
                        Issue.record(
                            Comment(
                                rawValue: String(
                                    format: "[%@] word=0x%08x text='%@' threw unexpected error: %@",
                                    table.name,
                                    word,
                                    text,
                                    String(describing: err)
                                )
                            )
                        )
                    }
                } catch {
                    stats.errors += 1
                    Issue.record(
                        Comment(
                            rawValue: String(
                                format: "[%@] word=0x%08x text='%@' threw non-MachGraphError: %@",
                                table.name,
                                word,
                                text,
                                String(describing: error)
                            )
                        )
                    )
                }
            }
            allStats.append(stats)
        }

        var sumRows = 0
        var sumSkipped = 0
        var sumOk = 0
        var sumEquiv = 0
        var sumUnsup = 0
        var sumErr = 0
        var sumWrong = 0
        for s in allStats {
            let decoded = s.totalRows - s.skippedInst
            print(
                "[15b-table] \(s.name)\trows=\(s.totalRows)\tdecoded=\(decoded)\tok=\(s.ok)\tequiv=\(s.equivalent)\tunsupported=\(s.unsupported)\terror=\(s.errors)\twrong=\(s.wrongWords)"
            )
            sumRows += s.totalRows
            sumSkipped += s.skippedInst
            sumOk += s.ok
            sumEquiv += s.equivalent
            sumUnsup += s.unsupported
            sumErr += s.errors
            sumWrong += s.wrongWords
        }
        print(
            "[15b-table-total] tables=\(allStats.count)\trows=\(sumRows)\tdecoded=\(sumRows - sumSkipped)\tok=\(sumOk)\tequiv=\(sumEquiv)\tunsupported=\(sumUnsup)\terror=\(sumErr)\twrong=\(sumWrong)"
        )
    }

    @Test("15b(1.b): /bin/ls (arm64e) __TEXT,__text instructions all round-trip or throw assemblerUnsupported, with ok >= 3845")
    func binLsTextInstructionsRoundTripOrThrowUnsupported() throws {
        let url = URL(fileURLWithPath: "/bin/ls")
        let data = try Data(contentsOf: url)
        let image = try UniversalBinaryDispatcher.load(
            data: data,
            filePath: url.path,
            fileName: url.lastPathComponent,
            preferredSliceIndex: nil
        )
        #expect(image.architecture == .arm64e)

        let decodedSections = try FunctionDiscoveryEngine().decodeExecutableSections(in: image, data: data)
        let textSection = try #require(
            decodedSections.first { $0.section.segmentName == "__TEXT" && $0.section.sectionName == "__text" }
        )

        var skippedInst = 0
        var ok = 0
        var equivalent = 0
        var unsupported = 0
        var errors = 0
        var wrongWords = 0

        for insn in textSection.instructions {
            if insn.mnemonicText == ".inst" {
                skippedInst += 1
                continue
            }
            let addr = insn.address
            let word = insn.rawWord
            let text = insn.formattedDisassembly

            do {
                let encoded = try assembler.assembleSingle(text, at: addr)
                if encoded == word {
                    ok += 1
                } else {
                    let redecoded = decoder.decode(word: encoded, at: addr)
                    if redecoded.mnemonicText != ".inst" && redecoded.formattedDisassembly == text {
                        equivalent += 1
                    } else {
                        wrongWords += 1
                        Issue.record(
                            Comment(
                                rawValue: String(
                                    format: "[/bin/ls] addr=0x%llx word=0x%08x text='%@' produced wrong word 0x%08x ('%@')",
                                    addr.rawValue,
                                    word,
                                    text,
                                    encoded,
                                    redecoded.formattedDisassembly
                                )
                            )
                        )
                    }
                }
            } catch let err as MachGraphError {
                if case .assemblerUnsupported = err {
                    unsupported += 1
                } else {
                    errors += 1
                    Issue.record(
                        Comment(
                            rawValue: String(
                                format: "[/bin/ls] addr=0x%llx word=0x%08x text='%@' threw unexpected error: %@",
                                addr.rawValue,
                                word,
                                text,
                                String(describing: err)
                            )
                        )
                    )
                }
            }
        }

        print(
            "[15b-bin-ls] total=\(textSection.instructions.count)\tskipped=\(skippedInst)\tok=\(ok)\tequiv=\(equivalent)\tunsupported=\(unsupported)\terror=\(errors)\twrong=\(wrongWords)"
        )
        #expect(ok >= 3845, "Expected at least 3,845 exact round-tripped instructions in /bin/ls, got \(ok)")
    }

    private func expectUnsupported(
        _ statement: String,
        mnemonic expectedMnemonic: String,
        form expectedForm: String,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_1000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        var singleCaught: MachGraphError?
        do {
            let word = try assembler.assembleSingle(statement, at: pc)
            Issue.record(
                Comment(rawValue: "assembleSingle('\(statement)') returned word \(String(format: "0x%08x", word)) instead of assemblerUnsupported"),
                sourceLocation: sourceLocation
            )
            return
        } catch let err as MachGraphError {
            singleCaught = err
        } catch {
            Issue.record("Unexpected error for '\(statement)': \(error)", sourceLocation: sourceLocation)
            return
        }

        if case .assemblerUnsupported(let mnem, let form) = singleCaught {
            #expect(mnem == expectedMnemonic, "For '\(statement)', expected mnemonic '\(expectedMnemonic)', got '\(mnem)'", sourceLocation: sourceLocation)
            #expect(form == expectedForm, "For '\(statement)', expected form '\(expectedForm)', got '\(form)'", sourceLocation: sourceLocation)
        } else {
            Issue.record("assembleSingle('\(statement)') expected assemblerUnsupported, got \(String(describing: singleCaught))", sourceLocation: sourceLocation)
        }

        var programCaught: MachGraphError?
        do {
            _ = try assembler.assembleProgram("nop; \(statement); ret", baseAddress: pc)
            Issue.record("assembleProgram('nop; \(statement); ret') succeeded instead of throwing assemblerUnsupported", sourceLocation: sourceLocation)
            return
        } catch let err as MachGraphError {
            programCaught = err
        } catch {
            Issue.record("Unexpected program error for '\(statement)': \(error)", sourceLocation: sourceLocation)
            return
        }

        if case .assemblerUnsupported(let mnem, let form) = programCaught {
            #expect(mnem == expectedMnemonic, sourceLocation: sourceLocation)
            #expect(form == expectedForm, sourceLocation: sourceLocation)
        } else {
            Issue.record("assembleProgram('nop; \(statement); ret') expected assemblerUnsupported, got \(String(describing: programCaught))", sourceLocation: sourceLocation)
        }
    }

    @Test("15b(1.c.1): Previously wrong-word SIMD/scalar-SIMD forms now throw assemblerUnsupported with normalized form")
    func previouslyWrongWordFormsThrowUnsupported() {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(word: UInt32, text: String, mnemonic: String, form: String)] = [
            (0x4EA4_9C42, "mul v2.4s, v2.4s, v4.4s", "mul", "mul V.Ns, V.Ns, V.Ns"),
            (0x4E66_9C21, "mul v1.8h, v1.8h, v6.8h", "mul", "mul V.Nh, V.Nh, V.Nh"),
            (0x5E61_D800, "scvtf d0, d0", "scvtf", "scvtf D, D"),
            (0x7E61_D800, "ucvtf d0, d0", "ucvtf", "ucvtf D, D"),
            (0x5EE1_B800, "fcvtzs d0, d0", "fcvtzs", "fcvtzs D, D"),
        ]

        for c in cases {
            let decoded = decoder.decode(word: c.word, at: pc)
            #expect(decoded.formattedDisassembly == c.text)
            expectUnsupported(c.text, mnemonic: c.mnemonic, form: c.form, at: pc)
        }
    }

    @Test("15b(1.c.2): Previously assemblerError decoded SIMD/fixed-point forms now throw assemblerUnsupported")
    func previouslyErrorDecodedFormsThrowUnsupported() {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(word: UInt32, text: String, mnemonic: String, form: String)] = [
            (0x4E61_8441, "add v1.8h, v2.8h, v1.8h", "add", "add V.Nh, V.Nh, V.Nh"),
            (0x6EE1_8401, "sub v1.2d, v0.2d, v1.2d", "sub", "sub V.Nd, V.Nd, V.Nd"),
            (0x5F40_E441, "scvtf d1, d2, #0x40", "scvtf", "scvtf D, D, #N"),
            (0x1E03_8041, "ucvtf s1, w2, #0x20", "ucvtf", "ucvtf S, W, #N"),
            (0x0E63_1C41, "bic v1.8b, v2.8b, v3.8b", "bic", "bic V.Nb, V.Nb, V.Nb"),
            (0x2E60_BAAC, "neg v12.4h, v21.4h", "neg", "neg V.Nh, V.Nh"),
        ]

        for c in cases {
            let decoded = decoder.decode(word: c.word, at: pc)
            expectUnsupported(c.text, mnemonic: c.mnemonic, form: c.form, at: pc)
            expectUnsupported(decoded.formattedDisassembly, mnemonic: c.mnemonic, form: c.form, at: pc)
        }
    }

    @Test("15b(1.c.3): Valid unimplemented AdvSIMD/element/modified-imm forms throw assemblerUnsupported instead of mis-encoding")
    func validUnimplementedSIMDFormsThrowUnsupported() {
        let cases: [(text: String, mnemonic: String, form: String)] = [
            ("movi v0.4h, #0x5", "movi", "movi V.Nh, #N"),
            ("movi v0.8h, #0x1, lsl #8", "movi", "movi V.Nh, #N, lsl #N"),
            ("movi v0.2s, #0x3f, msl #8", "movi", "movi V.Ns, #N, msl #N"),
            ("fmov v0.2d, #1.0", "fmov", "fmov V.Nd, #N.N"),
            ("fmov v0.d[1], x8", "fmov", "fmov V.d[N], X"),
            ("mov s10, v2.s[1]", "mov", "mov S, V.s[N]"),
            ("mov v1.s[3], v0.s[3]", "mov", "mov V.s[N], V.s[N]"),
            ("orr v0.4s, #0x1, lsl #8", "orr", "orr V.Ns, #N, lsl #N"),
        ]

        for c in cases {
            expectUnsupported(c.text, mnemonic: c.mnemonic, form: c.form)
        }
    }

    @Test("15b(1.c.4): G50 byte-width register-offset extend preserves S=1 when #0 is written and S=0 when omitted")
    func g50ByteRegisterOffsetExtendExplicitZeroShiftSetsSBit() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(text: String, expectedWord: UInt32)] = [
            ("strb w1, [x2, w3, uxtw #0]", 0x3823_5841),
            ("strb w1, [x2, w3, uxtw]",    0x3823_4841),
            ("strb w1, [x2, w3, sxtw #0]", 0x3823_D841),
            ("strb w1, [x2, w3, sxtw]",    0x3823_C841),
            ("strb w1, [x2, x3, sxtx #0]", 0x3823_F841),
            ("strb w1, [x2, x3, sxtx]",    0x3823_E841),
            ("ldr b1, [x2, w3, uxtw #0]",  0x3C63_5841),
            ("ldr b1, [x2, w3, uxtw]",     0x3C63_4841),
            ("ldrsb x1, [x2, w3, uxtw #0]", 0x38A3_5841),
            ("ldrsb x1, [x2, w3, uxtw]",    0x38A3_4841),
        ]

        for c in cases {
            let word = try assembler.assembleSingle(c.text, at: pc)
            #expect(word == c.expectedWord, "Expected \(String(format: "0x%08x", c.expectedWord)) for '\(c.text)', got \(String(format: "0x%08x", word))")
            #expect(decoder.decode(word: c.expectedWord, at: pc).formattedDisassembly == c.text)
        }
    }

    @Test("15b(1.c.5): Single-operand PAC instructions accept xzr")
    func singleOperandPACAcceptsXZR() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(text: String, expectedWord: UInt32)] = [
            ("paciza xzr", 0xDAC1_23FF),
            ("pacizb xzr", 0xDAC1_27FF),
            ("autiza xzr", 0xDAC1_33FF),
            ("autizb xzr", 0xDAC1_37FF),
            ("xpaci xzr",  0xDAC1_43FF),
            ("xpacd xzr",  0xDAC1_47FF),
        ]

        for c in cases {
            let word = try assembler.assembleSingle(c.text, at: pc)
            #expect(word == c.expectedWord, "Expected \(String(format: "0x%08x", c.expectedWord)) for '\(c.text)', got \(String(format: "0x%08x", word))")
            #expect(decoder.decode(word: c.expectedWord, at: pc).formattedDisassembly == c.text)
        }
    }

    @Test("15b(1.c.6): Post-encoding self-check rejects unallocated encodings as assemblerError while allowing aliases and .inst/.word")
    func postEncodingSelfCheckRejectsUnallocatedEncodings() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let unallocated = [
            "fmov w1, d2",
            "fcvt s1, s2",
        ]

        for text in unallocated {
            var singleCaught: MachGraphError?
            do {
                let w = try assembler.assembleSingle(text, at: pc)
                Issue.record("assembleSingle('\(text)') returned \(String(format: "0x%08x", w)) instead of assemblerError")
            } catch let err as MachGraphError {
                singleCaught = err
            }
            if case .assemblerError(_, _, let reason) = singleCaught {
                #expect(reason.contains("encodes an unallocated instruction"), "Unexpected reason for '\(text)': \(reason)")
            } else {
                Issue.record("Expected assemblerError for '\(text)', got \(String(describing: singleCaught))")
            }

            var progCaught: MachGraphError?
            do {
                _ = try assembler.assembleProgram("nop; \(text)", baseAddress: pc)
                Issue.record("assembleProgram('nop; \(text)') succeeded instead of throwing assemblerError")
            } catch let err as MachGraphError {
                progCaught = err
            }
            if case .assemblerError(_, _, let reason) = progCaught {
                #expect(reason.contains("encodes an unallocated instruction"))
            } else {
                Issue.record("Expected assemblerError from assembleProgram for '\(text)', got \(String(describing: progCaught))")
            }
        }

        // Directives .inst and .word bypass self-check even when the raw 32-bit value is unallocated.
        #expect(try assembler.assembleSingle(".inst 0x1e660041", at: pc) == 0x1E66_0041)
        #expect(try assembler.assembleSingle(".word 0x1e660041", at: pc) == 0x1E66_0041)
        let dirProg = try assembler.assembleProgram(".inst 0x1e660041; .word 0x1e224041", baseAddress: pc)
        #expect(dirProg.words == [0x1E66_0041, 0x1E22_4041])

        // Canonical aliases whose disassembly text differs from input still succeed.
        #expect(try assembler.assembleSingle("csinc w0, wzr, wzr, ne", at: pc) == 0x1A9F_17E0)
        #expect(try assembler.assembleSingle("orr x0, xzr, x1", at: pc) == 0xAA01_03E0)
    }

    @Test("15b(1.c.7): Invalid registers, malformed brackets/braces, non-numeric #, unknown mnemonics, and bad shifts remain assemblerError")
    func syntaxAndLexicalErrorsRemainAssemblerError() {
        let pc = VirtualAddress(0x1_0000_1000)
        let badInputs = [
            "add x99, x1, x2",
            "ldr x0, [x1",
            "mov x0, #zz",
            "foo x0",
            "ldr x0, [x1, x2, lsl #7]",
            "ldr d0, [x1",
            "ld1 { v0.16b, [x0]",
            "add v32.4s, v1.4s, v2.4s",
            "add v0.3s, v1.4s, v2.4s",
            "movi v0.4h, #zz",
        ]

        for text in badInputs {
            var singleCaught: MachGraphError?
            do {
                let w = try assembler.assembleSingle(text, at: pc)
                Issue.record("assembleSingle('\(text)') unexpectedly succeeded with \(String(format: "0x%08x", w))")
            } catch let err as MachGraphError {
                singleCaught = err
            } catch {
                Issue.record("Unexpected error type for '\(text)': \(error)")
            }
            if case .assemblerError = singleCaught {
                // Expected
            } else {
                Issue.record("Expected assemblerError for '\(text)', got \(String(describing: singleCaught))")
            }

            var progCaught: MachGraphError?
            do {
                _ = try assembler.assembleProgram("nop; \(text)", baseAddress: pc)
                Issue.record("assembleProgram('nop; \(text)') unexpectedly succeeded")
            } catch let err as MachGraphError {
                progCaught = err
            } catch {}
            if case .assemblerError = progCaught {
                // Expected
            } else {
                Issue.record("Expected assemblerError from assembleProgram for '\(text)', got \(String(describing: progCaught))")
            }
        }
    }

    @Test("15b(2 & 4): A64AssemblerOperandClassifier covers all operand classes, brace splitting, and canonical form edge cases")
    func operandClassifierAndCanonicalFormEdgeCases() throws {
        // Brace & bracket splitting
        let (m1, ops1) = A64AssemblerOperandClassifier.splitMnemonicAndOperands("ld2 { v0.16b, v1.16b }, [x0, #32]!")
        #expect(m1 == "ld2")
        #expect(ops1 == ["{ v0.16b, v1.16b }", "[x0, #32]!"])

        // Operand classes
        #expect(try A64AssemblerOperandClassifier.classifyOperand("x0") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("x30") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("xzr") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("sp") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("fp") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("lr") == .gpX)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("w0") == .gpW)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("w30") == .gpW)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("wzr") == .gpW)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("wsp") == .gpW)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("b31") == .scalarB)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("h0") == .scalarH)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("s15") == .scalarS)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("d7") == .scalarD)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("q31") == .scalarQ)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v0.1q") == .vector("1q"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v3.4b") == .vector("4b"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v5.2h") == .vector("2h"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v2.4b[1]") == .vectorElement("4b"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v7.2h[0]") == .vectorElement("2h"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("v1.q[0]") == .vectorElement("q"))
        #expect(try A64AssemblerOperandClassifier.classifyOperand("{ v0.16b - v3.16b }") == .registerList)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("{ v0.h, v1.h }[1]") == .registerList)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("#-0x3333333333333334") == .immediate)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("#-0.12500000") == .immediate)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("msl #8") == .shiftOrExtend)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("uxtw") == .shiftOrExtend)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("sxtx #3") == .shiftOrExtend)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("[sp, #-16]!") == .memory)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("vbar_el1") == .other)
        #expect(try A64AssemblerOperandClassifier.classifyOperand("vs") == .other)
        #expect(try A64AssemblerOperandClassifier.classifyOperand(".+12") == .other)

        // Form preserves sp/wsp/xzr/wzr and avoids false register matches inside hex literals
        #expect(
            A64AssemblerOperandClassifier.formatInstructionForm(
                mnemonic: "st1",
                operands: ["{ v0.16b - v3.16b }", "[sp]", "#-0xd0"]
            ) == "st1 { V.Nb - V.Nb }, [sp], #N"
        )
        #expect(
            A64AssemblerOperandClassifier.formatInstructionForm(
                mnemonic: "autdza",
                operands: ["xzr"]
            ) == "autdza xzr"
        )
        #expect(
            A64AssemblerOperandClassifier.formatInstructionForm(
                mnemonic: "add",
                operands: ["wsp", "wzr", "#0x1b0"]
            ) == "add wsp, wzr, #N"
        )
    }
}
