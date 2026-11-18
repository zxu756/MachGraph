import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("M2 Stage 15a: Structured Assembler Unsupported Mnemonics vs Syntax Errors")
struct MachA64DecoderAssemblerUnsupportedTests {

    private let assembler = A64MiniAssembler()

    @Test("15a(a): Known unimplemented A64 mnemonics throw assemblerUnsupported in assembleSingle and assembleProgram")
    func knownUnimplementedA64MnemonicsThrowAssemblerUnsupported() {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(statement: String, mnemonic: String)] = [
            ("shrn v1.4h, v1.4s, #0x10", "shrn"),
            ("xtn v2.4h, v2.4s", "xtn"),
            ("ushll v1.4s, v0.4h, #0x0", "ushll"),
            ("frinta d0, d0", "frinta"),
            ("autdza x16", "autdza"),
            ("ldaprb w8, [x8]", "ldaprb"),
            ("ld1 {v0.4s}, [x0]", "ld1"),
            ("ld1 { v0.16b, v1.16b }, [x0]", "ld1"),
            ("tbl v2.8b, { v27.16b }, v0.8b", "tbl"),
            ("sysl x1, #0, c1, c1, #1", "sysl"),
            ("hint #0x9", "hint"),
        ]

        for (statement, expectedMnemonic) in cases {
            var singleCaught: MachGraphError?
            do {
                _ = try assembler.assembleSingle(statement, at: pc)
            } catch let err as MachGraphError {
                singleCaught = err
            } catch {
                Issue.record("Unexpected non-MachGraphError for '\(statement)': \(error)")
            }

            if case .assemblerUnsupported(let mnem, let form) = singleCaught {
                #expect(mnem == expectedMnemonic, "Expected mnemonic '\(expectedMnemonic)' for '\(statement)', got '\(mnem)'")
                #expect(!form.isEmpty, "Expected non-empty form for '\(statement)'")
            } else {
                Issue.record("assembleSingle('\(statement)') must throw assemblerUnsupported, got \(String(describing: singleCaught))")
            }

            var programCaught: MachGraphError?
            let programSource = "nop; \(statement); ret"
            do {
                _ = try assembler.assembleProgram(programSource, baseAddress: pc)
            } catch let err as MachGraphError {
                programCaught = err
            } catch {
                Issue.record("Unexpected non-MachGraphError for program '\(programSource)': \(error)")
            }

            if case .assemblerUnsupported(let mnem, let form) = programCaught {
                #expect(mnem == expectedMnemonic, "assembleProgram('\(programSource)') expected mnemonic '\(expectedMnemonic)', got '\(mnem)'")
                #expect(!form.isEmpty)
            } else {
                Issue.record("assembleProgram('\(programSource)') must throw assemblerUnsupported, got \(String(describing: programCaught))")
            }
        }
    }

    @Test("15a(a): Stage 15a normalizes statement form to lowercase with single space after commas")
    func stage15aNormalizesStatementWhitespaceInForm() {
        var caught: MachGraphError?
        do {
            _ = try assembler.assembleSingle("  SHRN\tV1.4H ,  V1.4S,#0x10  ", at: .zero)
        } catch let err as MachGraphError {
            caught = err
        } catch {}

        if case .assemblerUnsupported(let mnem, let form) = caught {
            #expect(mnem == "shrn")
            #expect(form == "shrn V.Nh, V.Ns, #N")
        } else {
            Issue.record("Expected assemblerUnsupported, got \(String(describing: caught))")
        }

        var listCaught: MachGraphError?
        do {
            _ = try assembler.assembleSingle("ld1 { v0.16b, v1.16b }, [x0]", at: .zero)
        } catch let err as MachGraphError {
            listCaught = err
        } catch {}

        if case .assemblerUnsupported(let mnem, let form) = listCaught {
            #expect(mnem == "ld1")
            #expect(form == "ld1 { V.Nb, V.Nb }, [X]")
        } else {
            Issue.record("Expected assemblerUnsupported for ld1, got \(String(describing: listCaught))")
        }
    }

    @Test("15a(b): Non-A64 mnemonics still throw assemblerError with Unknown ARM64 mnemonic")
    func nonA64MnemonicsThrowAssemblerError() {
        let nonA64 = [
            "bogus x1",
            "garbage",
            "return to caller",
            "set return value to true",
            "foo x0, x1",
            "bogus_opcode x0, x1",
        ]

        for statement in nonA64 {
            var singleCaught: MachGraphError?
            do {
                _ = try assembler.assembleSingle(statement, at: .zero)
            } catch let err as MachGraphError {
                singleCaught = err
            } catch {
                Issue.record("Unexpected non-MachGraphError for '\(statement)': \(error)")
            }

            if case .assemblerError(_, _, let reason) = singleCaught {
                #expect(reason.contains("Unknown ARM64 mnemonic"), "Expected 'Unknown ARM64 mnemonic' reason for '\(statement)', got '\(reason)'")
            } else {
                Issue.record("assembleSingle('\(statement)') must throw assemblerError, got \(String(describing: singleCaught))")
            }

            var programCaught: MachGraphError?
            do {
                _ = try assembler.assembleProgram("nop; \(statement)")
            } catch let err as MachGraphError {
                programCaught = err
            } catch {
                Issue.record("Unexpected non-MachGraphError for program with '\(statement)': \(error)")
            }

            if case .assemblerError(_, _, let reason) = programCaught {
                #expect(reason.contains("Unknown ARM64 mnemonic"))
            } else {
                Issue.record("assembleProgram('nop; \(statement)') must throw assemblerError, got \(String(describing: programCaught))")
            }
        }
    }

    @Test("15a(c): Implemented mnemonics with invalid operands remain assemblerError and b.<cond> stays intact")
    func implementedMnemonicsWithBadOperandsRemainAssemblerError() throws {
        let badImplemented = [
            "add x0, x1",
            "udf #0x10000",
        ]

        for statement in badImplemented {
            var singleCaught: MachGraphError?
            do {
                _ = try assembler.assembleSingle(statement, at: .zero)
            } catch let err as MachGraphError {
                singleCaught = err
            } catch {
                Issue.record("Unexpected non-MachGraphError for '\(statement)': \(error)")
            }

            if case .assemblerError = singleCaught {
                // Expected in Stage 15a
            } else {
                Issue.record("assembleSingle('\(statement)') must remain assemblerError in 15a, got \(String(describing: singleCaught))")
            }

            var programCaught: MachGraphError?
            do {
                _ = try assembler.assembleProgram("nop\n\(statement)")
            } catch let err as MachGraphError {
                programCaught = err
            } catch {}

            if case .assemblerError = programCaught {
                // Expected in Stage 15a
            } else {
                Issue.record("assembleProgram with '\(statement)' must remain assemblerError in 15a, got \(String(describing: programCaught))")
            }
        }

        // Conditional branch b.<cond> remains working for valid conditions and throws assemblerError on unknown condition.
        let pc = VirtualAddress(0x1_0000_1000)
        let bEqWord = try assembler.assembleSingle("b.eq 0x100001040", at: pc)
        #expect(bEqWord == 0x5400_0200)

        var badCondCaught: MachGraphError?
        do {
            _ = try assembler.assembleSingle("b.zz 0x100001040", at: pc)
        } catch let err as MachGraphError {
            badCondCaught = err
        } catch {}
        if case .assemblerError = badCondCaught {
            // Expected
        } else {
            Issue.record("b.zz must throw assemblerError, got \(String(describing: badCondCaught))")
        }
    }

    @Test("15a(e): localizedMessage(in: .en) and localizedMessage(in: .zhHans) include both mnemonic and form")
    func localizedMessagesIncludeMnemonicAndForm() {
        let realistic = MachGraphError.assemblerUnsupported(
            mnemonic: "shrn",
            form: "shrn v1.4h, v1.4s, #0x10"
        )
        let enRealistic = realistic.localizedMessage(in: .en)
        let zhRealistic = realistic.localizedMessage(in: .zhHans)
        #expect(enRealistic.contains("shrn"))
        #expect(enRealistic.contains("shrn v1.4h, v1.4s, #0x10"))
        #expect(zhRealistic.contains("shrn"))
        #expect(zhRealistic.contains("shrn v1.4h, v1.4s, #0x10"))

        // Use non-overlapping mnemonic and form strings to prove both fields are interpolated independently.
        let distinct = MachGraphError.assemblerUnsupported(
            mnemonic: "autdza",
            form: "FORM_PLACEHOLDER_TOKEN"
        )
        let enDistinct = distinct.localizedMessage(in: .en)
        let zhDistinct = distinct.localizedMessage(in: .zhHans)
        #expect(enDistinct.contains("autdza"))
        #expect(enDistinct.contains("FORM_PLACEHOLDER_TOKEN"))
        #expect(zhDistinct.contains("autdza"))
        #expect(zhDistinct.contains("FORM_PLACEHOLDER_TOKEN"))
    }
}
