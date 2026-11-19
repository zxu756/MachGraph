import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("M2 Stage 16: Dot-Relative Offsets (.+-N, .-N, .+N) and ADRP .±N")
struct MachA64DecoderStage16Tests {

    private let decoder = A64InstructionDecoder()
    private let assembler = A64MiniAssembler()

    private func expectAssemblerError(
        _ statement: String,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_0000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            let word = try assembler.assembleSingle(statement, at: pc)
            Issue.record(
                "Expected assemblerError for '\(statement)', got \(String(format: "0x%08x", word))",
                sourceLocation: sourceLocation
            )
        } catch let error as MachGraphError {
            if case .assemblerError = error {
                return
            }
            Issue.record(
                "Expected assemblerError for '\(statement)', got \(error)",
                sourceLocation: sourceLocation
            )
        } catch {
            Issue.record(
                "Unexpected error type for '\(statement)': \(error)",
                sourceLocation: sourceLocation
            )
        }
    }

    @Test("Stage 16(1a): .+-N, .-N, and .+N across branches, adr, and literal ldr")
    func dotPlusMinusAndSignedRelativeBranchesAndLiterals() throws {
        let pcs: [VirtualAddress] = [
            .zero,
            VirtualAddress(0x14),
            VirtualAddress(0x1_0000_0000),
            VirtualAddress(0x1_0000_2348),
        ]

        // Clang-verified harness words (position-independent relative offsets)
        for pc in pcs {
            #expect(try assembler.assembleSingle("b.eq .+-12", at: pc) == 0x54ff_ffa0)
            #expect(try assembler.assembleSingle("b.eq .-12", at: pc) == 0x54ff_ffa0)
            #expect(try assembler.assembleSingle("b.eq .+12", at: pc) == 0x5400_0060)

            #expect(try assembler.assembleSingle("ldr x0, .+-24", at: pc) == 0x58ff_ff40)
            #expect(try assembler.assembleSingle("ldr x0, .-24", at: pc) == 0x58ff_ff40)
            #expect(try assembler.assembleSingle("ldr x0, .+24", at: pc) == 0x5800_00c0)

            #expect(try assembler.assembleSingle("tbz w1, #3, .+-64", at: pc) == 0x361f_fe01)
            #expect(try assembler.assembleSingle("tbz w1, #3, .-64", at: pc) == 0x361f_fe01)
            #expect(try assembler.assembleSingle("tbnz x2, #40, .+-16", at: pc) == 0xb747_ff82)
            #expect(try assembler.assembleSingle("tbnz x2, #40, .-16", at: pc) == 0xb747_ff82)

            #expect(try assembler.assembleSingle("b .+-16", at: pc) == 0x17ff_fffc)
            #expect(try assembler.assembleSingle("b .-16", at: pc) == 0x17ff_fffc)
            #expect(try assembler.assembleSingle("bl .+-16", at: pc) == 0x97ff_fffc)
            #expect(try assembler.assembleSingle("bl .+232", at: pc) == 0x9400_003a)

            #expect(try assembler.assembleSingle("cbz x0, .+0", at: pc) == 0xb400_0000)
            #expect(try assembler.assembleSingle("cbz x0, .+-0", at: pc) == 0xb400_0000)
            #expect(try assembler.assembleSingle("cbz x0, .+-8", at: pc) == 0xb4ff_ffc0)
            #expect(try assembler.assembleSingle("cbnz w3, .+-8", at: pc) == 0x35ff_ffc3)

            #expect(try assembler.assembleSingle("ldrsw x4, .+-8", at: pc) == 0x98ff_ffc4)
            #expect(try assembler.assembleSingle("ldr d5, .+-16", at: pc) == 0x5cff_ff85)
        }

        // Unaligned byte-granular offsets on `adr`
        let basePC = VirtualAddress(0x1_0000_1000)
        let adrNegWord = try assembler.assembleSingle("adr x5, .+-13", at: basePC)
        #expect(adrNegWord == (try assembler.assembleSingle("adr x5, .-13", at: basePC)))
        #expect(decoder.decode(word: adrNegWord, at: basePC).formattedDisassembly == "adr x5, 0x100000ff3")

        let adrPosWord = try assembler.assembleSingle("adr x5, .+13", at: basePC)
        #expect(decoder.decode(word: adrPosWord, at: basePC).formattedDisassembly == "adr x5, 0x10000100d")

        // Hex relative offsets
        #expect(try assembler.assembleSingle("b.ne .+-0x10", at: basePC) == (try assembler.assembleSingle("b.ne .-16", at: basePC)))

        // Alignment, range, and malformed syntax errors
        expectAssemblerError("b.eq .+-10")
        expectAssemblerError("ldr x0, .+-6")
        expectAssemblerError("tbz w1, #3, .+-65536")
        expectAssemblerError("b .+")
        expectAssemblerError("b .-")
        expectAssemblerError("b .+-")
        expectAssemblerError("b .++12")
        expectAssemblerError("b .+--12")
        expectAssemblerError("b .--12")
        expectAssemblerError("b .+#12")
    }

    @Test("Stage 16(1b): adrp Xd, .±N resolves to page containing (PC + N)")
    func adrpDotRelativeTargetsPageOfPCPlusDelta() throws {
        let pc = VirtualAddress(0x1_0000_0000)
        let word4096 = try assembler.assembleSingle("adrp x8, .+4096", at: pc)
        #expect(word4096 == 0xb000_0008)
        let decoded = decoder.decode(word: word4096, at: pc)
        #expect(decoded.formattedDisassembly == "adrp x8, 0x100001000")

        // Same +1 page difference at PC = 0x0 and PC = 0x14 (case-mode offset 4*5)
        #expect(try assembler.assembleSingle("adrp x8, .+4096", at: .zero) == 0xb000_0008)
        #expect(try assembler.assembleSingle("adrp x8, .+4096", at: VirtualAddress(0x14)) == 0xb000_0008)

        // Negative page offsets via .+-N and .-N
        let pc2 = VirtualAddress(0x1_0000_2340)
        let negWord1 = try assembler.assembleSingle("adrp x8, .+-4096", at: pc2)
        let negWord2 = try assembler.assembleSingle("adrp x8, .-4096", at: pc2)
        #expect(negWord1 == 0xf0ff_ffe8)
        #expect(negWord2 == 0xf0ff_ffe8)
        #expect(decoder.decode(word: negWord1, at: pc2).formattedDisassembly == "adrp x8, 0x100001000")

        // Page-boundary crossing: target is page of (PC + N), not (page(PC) + N)
        let nearEndOfPage = VirtualAddress(0x1_0000_0ff0)
        let crossUp = try assembler.assembleSingle("adrp x8, .+32", at: nearEndOfPage)
        #expect(crossUp == 0xb000_0008)
        #expect(decoder.decode(word: crossUp, at: nearEndOfPage).formattedDisassembly == "adrp x8, 0x100001000")

        let nearStartOfPage = VirtualAddress(0x1_0000_1008)
        let crossDown = try assembler.assembleSingle("adrp x8, .+-16", at: nearStartOfPage)
        #expect(crossDown == 0xf0ff_ffe8)
        #expect(decoder.decode(word: crossDown, at: nearStartOfPage).formattedDisassembly == "adrp x8, 0x100000000")

        // Same page (. and .+0)
        #expect(try assembler.assembleSingle("adrp x8, .", at: nearEndOfPage) == 0x9000_0008)
        #expect(try assembler.assembleSingle("adrp x8, .+0", at: nearEndOfPage) == 0x9000_0008)

        // Malformed & out-of-range ADRP dot offsets
        expectAssemblerError("adrp x8, .+-")
        expectAssemblerError("adrp x8, .+0x200000000")
        expectAssemblerError("adrp x8, .+-0x200000000")
    }
}
