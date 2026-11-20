import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("M2 Stage 17a: Post-Merge MSR System Register Gate & Regenerated Known Mnemonics")
struct MachA64DecoderStage17aTests {

    private let decoder = A64InstructionDecoder()
    private let assembler = A64MiniAssembler()

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

    private func expectAssemblerError(
        _ statement: String,
        expectedReasonSubstring: String? = nil,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_1000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        var singleCaught: MachGraphError?
        do {
            let word = try assembler.assembleSingle(statement, at: pc)
            Issue.record(
                Comment(rawValue: "assembleSingle('\(statement)') unexpectedly succeeded with \(String(format: "0x%08x", word))"),
                sourceLocation: sourceLocation
            )
            return
        } catch let err as MachGraphError {
            singleCaught = err
        } catch {
            Issue.record("Unexpected error type for '\(statement)': \(error)", sourceLocation: sourceLocation)
            return
        }

        if case .assemblerError(_, _, let reason) = singleCaught {
            if let expectedReasonSubstring {
                #expect(
                    reason.contains(expectedReasonSubstring),
                    "Expected reason containing '\(expectedReasonSubstring)' for '\(statement)', got '\(reason)'",
                    sourceLocation: sourceLocation
                )
            }
        } else {
            Issue.record("assembleSingle('\(statement)') expected assemblerError, got \(String(describing: singleCaught))", sourceLocation: sourceLocation)
        }

        var programCaught: MachGraphError?
        do {
            _ = try assembler.assembleProgram("nop; \(statement)", baseAddress: pc)
            Issue.record("assembleProgram('nop; \(statement)') unexpectedly succeeded", sourceLocation: sourceLocation)
            return
        } catch let err as MachGraphError {
            programCaught = err
        } catch {
            Issue.record("Unexpected program error type for '\(statement)': \(error)", sourceLocation: sourceLocation)
            return
        }

        if case .assemblerError(_, _, let reason) = programCaught {
            if let expectedReasonSubstring {
                #expect(reason.contains(expectedReasonSubstring), sourceLocation: sourceLocation)
            }
        } else {
            Issue.record("assembleProgram('nop; \(statement)') expected assemblerError, got \(String(describing: programCaught))", sourceLocation: sourceLocation)
        }
    }

    @Test("17a(1): Decoder-recognized unimplemented MSR system registers throw assemblerUnsupported while supported MSR forms round-trip")
    func decoderRecognizedUnimplementedMSRSystemRegistersThrowUnsupported() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // Decoder prints S0_3_C3_C<crm>_<op2> for barrier-space MSR fallbacks (Fixtures/a64/barriers.tsv)
        #expect(decoder.decode(word: 0xD503_3001, at: pc).formattedDisassembly == "msr S0_3_C3_C0_0, x1")
        #expect(decoder.decode(word: 0xD503_301F, at: pc).formattedDisassembly == "msr S0_3_C3_C0_0, xzr")
        #expect(decoder.decode(word: 0xD503_3FE1, at: pc).formattedDisassembly == "msr S0_3_C3_C15_7, x1")

        expectUnsupported("msr S0_3_C3_C0_0, x1", mnemonic: "msr", form: "msr sN_N_cN_cN_N, X", at: pc)
        expectUnsupported("msr S0_3_C3_C0_0, xzr", mnemonic: "msr", form: "msr sN_N_cN_cN_N, xzr", at: pc)
        expectUnsupported("msr s0_3_c3_c15_7, x1", mnemonic: "msr", form: "msr sN_N_cN_cN_N, X", at: pc)

        // Decoder prints PSTATE immediate MSR forms (e.g. MSR SPSel, #1; MSR DAIFSet, #2)
        #expect(decoder.decode(word: 0xD500_41BF, at: pc).formattedDisassembly == "msr SPSel, #1")
        #expect(decoder.decode(word: 0xD503_42DF, at: pc).formattedDisassembly == "msr DAIFSet, #2")
        expectUnsupported("msr SPSel, #1", mnemonic: "msr", form: "msr spsel, #N", at: pc)
        expectUnsupported("msr DAIFSet, #2", mnemonic: "msr", form: "msr daifset, #N", at: pc)

        // Already-supported MSR forms (named op0>=2 and generic S2/S3) must continue to encode to exact words
        #expect(try assembler.assembleSingle("msr tpidr_el0, x0", at: pc) == 0xD51B_D040)
        #expect(try assembler.assembleSingle("msr S3_3_C13_C0_2, x0", at: pc) == 0xD51B_D040)
        #expect(try assembler.assembleSingle("msr nzcv, x1", at: pc) == 0xD51B_4201)
    }

    @Test("17a(2): Misspelled system register names and malformed MSR operands still throw assemblerError")
    func misspelledSystemRegistersAndBadOperandsThrowAssemblerError() {
        expectAssemblerError("msr bogus_reg, x0", expectedReasonSubstring: "Unknown system register")
        expectAssemblerError("msr S0_3_C4_C0_0, x0", expectedReasonSubstring: "Unknown system register")
        expectAssemblerError("msr S1_3_C3_C0_0, x0", expectedReasonSubstring: "Unknown system register")
        expectAssemblerError("msr S9_3_C3_C0_0, x0", expectedReasonSubstring: "Unknown system register")
        expectAssemblerError("msr bogus_reg, #1", expectedReasonSubstring: "Unknown system register")
        expectAssemblerError("msr S0_3_C3_C0_0, w1")
        expectAssemblerError("msr S0_3_C3_C0_0, sp")
        expectAssemblerError("msr SPSel, #99")
    }

    @Test("17a(3): Newly merged A64 mnemonics (saddlv, casp, aese, sb, etc.) throw assemblerUnsupported")
    func newlyMergedMnemonicsThrowAssemblerUnsupported() {
        let pc = VirtualAddress(0x1_0000_1000)
        let cases: [(statement: String, mnemonic: String, form: String)] = [
            ("saddlv h1, v2.8b", "saddlv", "saddlv H, V.Nb"),
            ("casp x0, x1, x2, x3, [x4]", "casp", "casp X, X, X, X, [X]"),
            ("aese v1.16b, v2.16b", "aese", "aese V.Nb, V.Nb"),
            ("sb", "sb", "sb"),
            ("ssbb", "ssbb", "ssbb"),
            ("pssbb", "pssbb", "pssbb"),
            ("sha1su0 v1.4s, v2.4s, v3.4s", "sha1su0", "sha1su0 V.Ns, V.Ns, V.Ns"),
        ]

        for c in cases {
            expectUnsupported(c.statement, mnemonic: c.mnemonic, form: c.form, at: pc)
        }
    }
}
