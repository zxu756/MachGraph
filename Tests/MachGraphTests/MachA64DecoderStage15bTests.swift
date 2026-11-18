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
}
