import Foundation
import Testing
import MachGraphModels
import MachA64Decoder
import MachCFGEngine

@Suite("ARM64 Instruction Decoder, Two-Pass Mini-Assembler, Idioms & Demangler")
struct ARM64DecoderAssemblerAndDemanglerTests {

    private let decoder = A64InstructionDecoder()
    private let assembler = A64MiniAssembler()
    private let idiomRecognizer = A64IdiomRecognizer()
    private let demangler = SymbolDemangler()

    @Test("Decode A64 data-processing immediate arithmetic and wide move instructions")
    func decodeDataProcessingImmediateArithmeticAndWideMoves() throws {
        let base = VirtualAddress(0x1_0000_1000)

        let addWord = try assembler.assembleSingle("add x0, x1, #0x42", at: base)
        let addInsn = decoder.decode(word: addWord, at: base)
        #expect(addInsn.mnemonic == .add)
        #expect(addInsn.group == .dataProcessingImm)
        #expect(addInsn.writesRegisters.contains(.x(0)))
        #expect(addInsn.readsRegisters.contains(.x(1)))

        let subsWord = try assembler.assembleSingle("subs xzr, x2, #16", at: base)
        let subsInsn = decoder.decode(word: subsWord, at: base)
        #expect(subsInsn.mnemonic == .cmp || subsInsn.mnemonic == .subs)
        #expect(subsInsn.writesFlags)

        let movzWord = try assembler.assembleSingle("movz x8, #0x1234, lsl #16", at: base)
        let movzInsn = decoder.decode(word: movzWord, at: base)
        #expect(movzInsn.mnemonic == .movz || movzInsn.mnemonic == .mov)
        #expect(movzInsn.writesRegisters.contains(.x(8)))

        let movkWord = try assembler.assembleSingle("movk x8, #0x5678, lsl #32", at: base)
        let movkInsn = decoder.decode(word: movkWord, at: base)
        #expect(movkInsn.mnemonic == .movk)
    }

    @Test("Encode and decode ARMv8 logical bitmask immediates (N:immr:imms)")
    func decodeAndEncodeLogicalBitmaskImmediates() throws {
        let masks64: [UInt64] = [
            0x0000_0000_0000_FFFF,
            0xFFFF_0000_FFFF_0000,
            0x5555_5555_5555_5555,
            0x00FF_00FF_00FF_00FF,
            0xFFFF_FFFF_FFFF_FFF0
        ]
        for expected in masks64 {
            let encoded = try #require(encodeBitmaskImmediate(expected, regSize: 64))
            let decoded = try #require(
                DecodeBitMasks(
                    immN: encoded.n,
                    imms: encoded.imms,
                    immr: encoded.immr,
                    immediate: true,
                    regSize: 64
                )
            )
            #expect(decoded.wmask == expected)
        }

        let andWord = try assembler.assembleSingle("and x3, x4, #0xff", at: VirtualAddress(0x1_0000_1000))
        let andInsn = decoder.decode(word: andWord, at: VirtualAddress(0x1_0000_1000))
        #expect(andInsn.mnemonic == .and)
        #expect(andInsn.operandText.contains("0xff") || andInsn.operandText.contains("255"))
    }

    @Test("Decode data-processing register shifted, extended, multiply/divide, and conditional select instructions")
    func decodeDataProcessingRegisterShiftsExtendsMultiplyDivideAndCondSelect() throws {
        let addr = VirtualAddress(0x1_0000_2000)

        let cases: [(String, Set<A64Mnemonic>)] = [
            ("add x0, x1, x2, lsl #3", [.add]),
            ("sub x5, sp, w3, uxtw #2", [.sub]),
            ("madd x0, x1, x2, x3", [.madd]),
            ("mul w4, w5, w6", [.mul, .madd]),
            ("udiv x7, x8, x9", [.udiv]),
            ("sdiv w1, w2, w3", [.sdiv]),
            ("csel x0, x1, x2, eq", [.csel]),
            ("csinc w0, wzr, wzr, ne", [.csinc, .cset]),
            ("rbit x10, x11", [.rbit]),
            ("rev x12, x13", [.rev])
        ]

        for (asm, validMnemonics) in cases {
            let word = try assembler.assembleSingle(asm, at: addr)
            let decoded = decoder.decode(word: word, at: addr)
            #expect(validMnemonics.contains(decoded.mnemonic), "Expected \(validMnemonics) for '\(asm)', got \(decoded.mnemonic)")
            #expect(decoded.group == .dataProcessingReg)
        }
    }

    @Test("Decode unconditional b/bl and conditional b.cond with exact signed PC-relative target addresses")
    func decodeUnconditionalAndConditionalBranchesWithPCRelativeTargets() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let bFwdWord = try assembler.assembleSingle("b 0x100001080", at: pc)
        let bFwd = decoder.decode(word: bFwdWord, at: pc)
        #expect(bFwd.mnemonic == .b)
        #expect(bFwd.flow == .unconditionalJump(target: VirtualAddress(0x1_0000_1080)))

        let blBackWord = try assembler.assembleSingle("bl 0x100000fc0", at: pc)
        let blBack = decoder.decode(word: blBackWord, at: pc)
        #expect(blBack.mnemonic == .bl)
        #expect(blBack.flow == .directCall(target: VirtualAddress(0x1_0000_0FC0)))

        let bEqWord = try assembler.assembleSingle("b.eq 0x100001040", at: pc)
        let bEq = decoder.decode(word: bEqWord, at: pc)
        #expect(bEq.mnemonic == .bCond)
        #expect(bEq.flow == .conditionalBranch(target: VirtualAddress(0x1_0000_1040), condition: .eq))
        #expect(bEq.readsFlags)
    }

    @Test("Decode compare-and-branch (cbz/cbnz) and test-bit-and-branch (tbz/tbnz)")
    func decodeCompareAndTestBitBranches() throws {
        let pc = VirtualAddress(0x1_0000_1200)

        let cbzWord = try assembler.assembleSingle("cbz x0, 0x100001240", at: pc)
        let cbz = decoder.decode(word: cbzWord, at: pc)
        #expect(cbz.mnemonic == .cbz)
        if case .conditionalBranch(let target, _) = cbz.flow {
            #expect(target == VirtualAddress(0x1_0000_1240))
        } else {
            Issue.record("Expected conditionalBranch flow for cbz, got \(cbz.flow)")
        }

        let tbnzWord = try assembler.assembleSingle("tbnz x1, #63, 0x1000011e0", at: pc)
        let tbnz = decoder.decode(word: tbnzWord, at: pc)
        #expect(tbnz.mnemonic == .tbnz)
        if case .conditionalBranch(let target, _) = tbnz.flow {
            #expect(target == VirtualAddress(0x1_0000_11E0))
        } else {
            Issue.record("Expected conditionalBranch flow for tbnz, got \(tbnz.flow)")
        }
    }

    @Test("Decode indirect register branches (br, blr, ret) and ARM64E PAC branches (braa, blraa, retaa, retab)")
    func decodeIndirectRegisterBranchesReturnsAndARM64EPACBranches() throws {
        let pc = VirtualAddress(0x1_0000_1400)

        let br = decoder.decode(word: try assembler.assembleSingle("br x16", at: pc), at: pc)
        #expect(br.mnemonic == .br)
        #expect(br.flow == .indirectJump(register: .x(16)))

        let blr = decoder.decode(word: try assembler.assembleSingle("blr x8", at: pc), at: pc)
        #expect(blr.mnemonic == .blr)
        #expect(blr.flow == .indirectCall(register: .x(8)))

        let ret = decoder.decode(word: try assembler.assembleSingle("ret", at: pc), at: pc)
        #expect(ret.mnemonic == .ret)
        #expect(ret.flow == .returnControl)

        let retaa = decoder.decode(word: try assembler.assembleSingle("retaa", at: pc), at: pc)
        #expect(retaa.mnemonic == .retaa)
        #expect(retaa.group == .pacPointerAuth)
        #expect(retaa.flow == .returnControl)

        let retab = decoder.decode(word: try assembler.assembleSingle("retab", at: pc), at: pc)
        #expect(retab.mnemonic == .retab)
        #expect(retab.flow == .returnControl)

        // ARMv8.3-A `braa x16, x17` (0xD71F0A11) and `blraa x8, x9` (0xD73F0909)
        let braa = decoder.decode(word: 0xD71F_0A11, at: pc)
        #expect(braa.mnemonic == .braa)
        #expect(braa.group == .pacPointerAuth)

        let blraa = decoder.decode(word: 0xD73F_0909, at: pc)
        #expect(blraa.mnemonic == .blraa)
        #expect(blraa.group == .pacPointerAuth)
    }

    @Test("Decode loads and stores across unsigned scaled, unscaled, pre-index, post-index, and register-offset modes")
    func decodeLoadStoreUnsignedUnscaledPrePostIndexAndRegisterOffset() throws {
        let pc = VirtualAddress(0x1_0000_1800)

        let ldrScaled = decoder.decode(word: try assembler.assembleSingle("ldr x0, [x1, #24]", at: pc), at: pc)
        #expect(ldrScaled.mnemonic == .ldr)
        #expect(ldrScaled.operands.contains(.memory(.baseOffset(base: .x(1), offset: 24))))

        let ldurNeg = decoder.decode(word: try assembler.assembleSingle("ldur w2, [x29, #-8]", at: pc), at: pc)
        #expect(ldurNeg.mnemonic == .ldur)
        #expect(ldurNeg.operands.contains(.memory(.baseOffset(base: .x(29), offset: -8))))

        let strPre = decoder.decode(word: try assembler.assembleSingle("str x30, [sp, #-16]!", at: pc), at: pc)
        #expect(strPre.mnemonic == .str)
        #expect(strPre.operands.contains(.memory(.preIndex(base: .sp, offset: -16))))

        let ldrPost = decoder.decode(word: try assembler.assembleSingle("ldr x30, [sp], #16", at: pc), at: pc)
        #expect(ldrPost.mnemonic == .ldr)
        #expect(ldrPost.operands.contains(.memory(.postIndex(base: .sp, offset: 16))))

        let ldrReg = decoder.decode(word: try assembler.assembleSingle("ldrsw x9, [x10, x11, lsl #2]", at: pc), at: pc)
        #expect(ldrReg.mnemonic == .ldrsw)
        #expect(ldrReg.group == .loadStore)
    }

    @Test("Decode load/store pairs (stp/ldp) and PC-relative literal loads")
    func decodeLoadStorePairsAndPCRelativeLiteralLoads() throws {
        let pc = VirtualAddress(0x1_0000_2000)

        let stpPre = decoder.decode(word: try assembler.assembleSingle("stp x29, x30, [sp, #-32]!", at: pc), at: pc)
        #expect(stpPre.mnemonic == .stp)
        #expect(stpPre.operands.contains(.memory(.preIndex(base: .sp, offset: -32))))

        let ldpPost = decoder.decode(word: try assembler.assembleSingle("ldp x29, x30, [sp], #32", at: pc), at: pc)
        #expect(ldpPost.mnemonic == .ldp)
        #expect(ldpPost.operands.contains(.memory(.postIndex(base: .sp, offset: 32))))

        // LDR X0, label (+0x40 -> imm19 = 16 -> 0x58000200)
        let ldrLit = decoder.decode(word: 0x5800_0200, at: pc)
        #expect(ldrLit.mnemonic == .ldr)
        #expect(ldrLit.operands.contains(.memory(.pcRelativeLiteral(target: VirtualAddress(0x1_0000_2040)))))
    }

    @Test("Decode system, barrier, exception (svc, brk), MSR/MRS, and PAC instructions (paciasp, autiasp)")
    func decodeSystemBarriersExceptionsSysRegsAndPACInstructions() throws {
        let pc = VirtualAddress(0x1_0000_2400)

        let paciasp = decoder.decode(word: try assembler.assembleSingle("paciasp", at: pc), at: pc)
        #expect(paciasp.mnemonic == .paciasp)
        #expect(paciasp.group == .pacPointerAuth)

        let autiasp = decoder.decode(word: try assembler.assembleSingle("autiasp", at: pc), at: pc)
        #expect(autiasp.mnemonic == .autiasp)
        #expect(autiasp.group == .pacPointerAuth)

        let svc = decoder.decode(word: try assembler.assembleSingle("svc #0x80", at: pc), at: pc)
        #expect(svc.mnemonic == .svc)
        #expect(svc.flow == .trapOrSupervisor(immediate: 0x80))

        let brk = decoder.decode(word: try assembler.assembleSingle("brk #0x1", at: pc), at: pc)
        #expect(brk.mnemonic == .brk)
        #expect(brk.flow == .trapOrSupervisor(immediate: 0x1))

        let dmb = decoder.decode(word: try assembler.assembleSingle("dmb ish", at: pc), at: pc)
        #expect(dmb.mnemonic == .dmb)

        let mrs = decoder.decode(word: try assembler.assembleSingle("mrs x0, nzcv", at: pc), at: pc)
        #expect(mrs.mnemonic == .mrs)
        #expect(mrs.operandText.lowercased().contains("nzcv"))
    }

    @Test("Decode scalar floating-point and 128-bit SIMD/NEON instructions (fadd, fcmp, ldp q0, q1)")
    func decodeScalarFloatingPointAndNEONVectorInstructions() throws {
        let pc = VirtualAddress(0x1_0000_2800)

        let fadd = decoder.decode(word: try assembler.assembleSingle("fadd d0, d1, d2", at: pc), at: pc)
        #expect(fadd.mnemonic == .fadd)
        #expect(fadd.group == .simdAndFP)
        #expect(fadd.writesRegisters.contains(.d(0)))

        let fcmp = decoder.decode(word: try assembler.assembleSingle("fcmp d0, d1", at: pc), at: pc)
        #expect(fcmp.mnemonic == .fcmp)
        #expect(fcmp.writesFlags)

        let scvtf = decoder.decode(word: try assembler.assembleSingle("scvtf d3, x4", at: pc), at: pc)
        #expect(scvtf.mnemonic == .scvtf)

        let ldpQ = decoder.decode(word: try assembler.assembleSingle("ldp q0, q1, [sp, #32]", at: pc), at: pc)
        #expect(ldpQ.mnemonic == .ldp)
        #expect(ldpQ.operands.contains(.register(.q(0))))
        #expect(ldpQ.operands.contains(.register(.q(1))))
        #expect(ldpQ.operands.contains(.memory(.baseOffset(base: .sp, offset: 32))))
    }

    @Test("Decode PC-relative ADR and ADRP 4KiB page calculations with symbol lookup auto-comments")
    func decodePCRelativeADRAndADRPWithSymbolLookupComments() throws {
        let pc = VirtualAddress(0x1_0000_1024)
        let adrpWord = try assembler.assembleSingle("adrp x8, 0x100004000", at: pc)
        let adrp = decoder.decode(word: adrpWord, at: pc)
        #expect(adrp.mnemonic == .adrp)
        #expect(adrp.operands.contains(.branchTarget(VirtualAddress(0x1_0000_4000))))

        let blWord = try assembler.assembleSingle("bl 0x100001800", at: pc)
        let bl = decoder.decode(word: blWord, at: pc) { target in
            target == VirtualAddress(0x1_0000_1800) ? "_verify_license" : nil
        }
        #expect(bl.autoComment?.contains("_verify_license") == true)
    }

    @Test("Two-pass A64MiniAssembler resolves forward and backward labels across branch families")
    func miniAssemblerTwoPassForwardAndBackwardLabelResolution() throws {
        let source = """
        entry:
            paciasp
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            cbz x0, .L_zero
            mov w8, #0
        .L_loop:
            add w8, w8, #1
            subs x0, x0, #1
            b.ne .L_loop
            mov w0, w8
            b .L_exit
        .L_zero:
            mov w0, #0
        .L_exit:
            ldp x29, x30, [sp], #16
            retaa
        """
        let base = VirtualAddress(0x1_0000_1000)
        let program = try assembler.assembleProgram(source, baseAddress: base)

        #expect(program.words.count == 13)
        #expect(program.bytes.count == 52)
        #expect(program.labels["entry"] == base)
        #expect(program.labels[".L_loop"] == base.adding(UInt64(5 * 4)))
        #expect(program.labels[".L_zero"] == base.adding(UInt64(10 * 4)))
        #expect(program.labels[".L_exit"] == base.adding(UInt64(11 * 4)))

        // Forward branch `cbz x0, .L_zero` at index 3
        if case .conditionalBranch(let target, _) = program.instructions[3].flow {
            #expect(target == program.labels[".L_zero"])
        } else {
            Issue.record("Expected forward cbz target resolution")
        }

        // Backward branch `b.ne .L_loop` at index 7
        #expect(program.instructions[7].flow == .conditionalBranch(target: base.adding(UInt64(5 * 4)), condition: .ne))
    }

    @Test("Round-trip assemble -> decode -> re-assemble preserves exact 32-bit machine words")
    func miniAssemblerToDecoderRoundTripEquivalence() throws {
        let pc = VirtualAddress(0x1_0000_3000)
        let samples = [
            "paciasp",
            "stp x29, x30, [sp, #-32]!",
            "mov x29, sp",
            "add x0, x1, #0x120",
            "sub x2, x3, x4, lsl #2",
            "ldr x8, [x9, #16]",
            "str w10, [x11, #-4]!",
            "cbz x0, 0x100003040",
            "b.gt 0x100003080",
            "bl 0x100003200",
            "fadd d0, d1, d2",
            "fcmp d0, d1",
            "ldp q0, q1, [sp, #16]",
            "svc #0x80",
            "nop",
            "autiasp",
            "ret",
            "retaa"
        ]

        for line in samples {
            let word1 = try assembler.assembleSingle(line, at: pc)
            let decoded1 = decoder.decode(word: word1, at: pc)
            let reassembledText = "\(decoded1.mnemonicText) \(decoded1.operandText)".trimmingCharacters(in: .whitespaces)
            let word2 = try assembler.assembleSingle(reassembledText, at: pc)
            let decoded2 = decoder.decode(word: word2, at: pc)

            #expect(word2 == word1, "Word mismatch round-tripping '\(line)' -> '\(reassembledText)'")
            #expect(decoded2.mnemonic == decoded1.mnemonic)
            #expect(decoded2.flow == decoded1.flow)
        }
    }

    @Test("A64MiniAssembler throws structured assemblerError on unknown mnemonics and undefined labels")
    func miniAssemblerRejectsInvalidSyntaxAndUndefinedLabels() {
        #expect(throws: MachGraphError.self) {
            _ = try assembler.assembleSingle("bogus_opcode x0, x1", at: .zero)
        }
        #expect(throws: MachGraphError.self) {
            _ = try assembler.assembleProgram("b .L_missing_target", baseAddress: VirtualAddress(0x1_0000_0000))
        }
    }

    @Test("A64MiniAssembler.assembleProgram splits semicolon-separated statements into all 4 machine words and rejects invalid trailing statements")
    func miniAssemblerProgramSemicolonSeparatedStatementsAndInvalidClauseRejection() throws {
        let program = try assembler.assembleProgram(
            "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab // trailing comment",
            baseAddress: VirtualAddress(0x1_0000_0000)
        )
        #expect(program.words.count == 4)
        #expect(program.words == [0xD503_237F, 0xA9BF_7BFD, 0xD280_0540, 0xD65F_0FFF])

        #expect(throws: MachGraphError.self) {
            _ = try assembler.assembleProgram("nop; bogus_trailing_opcode x0, x1")
        }
    }

    @Test("G27: zero-operand instructions and single-option hints reject surplus operands instead of ignoring them")
    func miniAssemblerRejectsSurplusOperandsInsteadOfIgnoringThem() throws {
        // Operand-less forms keep assembling to the reference encodings (clang -arch arm64e).
        #expect(try assembler.assembleSingle("nop") == 0xD503_201F)
        #expect(try assembler.assembleSingle("retab") == 0xD65F_0FFF)
        #expect(try assembler.assembleSingle("bti c") == 0xD503_245F)
        #expect(try assembler.assembleSingle("isb") == 0xD503_3FDF)
        #expect(try assembler.assembleSingle("clrex") == 0xD503_3F5F)

        let surplus = [
            "nop extra words here", "nop x0", "yield now", "wfe x1", "wfi 1", "sev x0", "sevl x0",
            "xpaclri x30", "paciasp x0", "pacibsp sp", "autiasp x0", "autibsp x0", "retaa x30", "retab x30",
            "bti c, j", "clrex #1, #2", "isb sy, sy"
        ]
        for source in surplus {
            #expect(throws: MachGraphError.self, "assembleSingle must reject \(source.debugDescription)") {
                _ = try assembler.assembleSingle(source)
            }
            #expect(throws: MachGraphError.self, "assembleProgram must reject \(source.debugDescription)") {
                _ = try assembler.assembleProgram("nop; \(source)")
            }
        }
    }

    @Test("A64IdiomRecognizer resolves ADRP+ADD pointer materialization and ADRP+LDR GOT loads")
    func idiomRecognizerResolvesADRPAddAndADRPLoadPairs() throws {
        let base = VirtualAddress(0x1_0000_1018)
        let program = try assembler.assembleProgram("""
            adrp x8, 0x100004000
            add x8, x8, #0x138
            adrp x16, 0x100008000
            ldr x16, [x16, #0x28]
        """, baseAddress: base)

        let resolvedPtr = idiomRecognizer.resolveAdrpAdd(
            adrp: program.instructions[0],
            add: program.instructions[1]
        )
        #expect(resolvedPtr == VirtualAddress(0x1_0000_4138))

        let resolvedGOT = idiomRecognizer.resolveAdrpLoad(
            adrp: program.instructions[2],
            load: program.instructions[3]
        )
        #expect(resolvedGOT == VirtualAddress(0x1_0000_8028))
    }

    @Test("A64IdiomRecognizer folds 64-bit MOVZ + MOVK wide constant chains")
    func idiomRecognizerResolvesWideMOVZMOVKConstantChains() throws {
        let program = try assembler.assembleProgram("""
            movz x0, #0xef01
            movk x0, #0xabcd, lsl #16
            movk x0, #0x5678, lsl #32
            movk x0, #0x1234, lsl #48
        """, baseAddress: VirtualAddress(0x1_0000_1100))

        let folded = idiomRecognizer.resolveMovWideChain(program.instructions)
        #expect(folded == 0x1234_5678_ABCD_EF01)
    }

    @Test("A64IdiomRecognizer annotates multi-instruction idioms with resolved symbol names")
    func idiomRecognizerFullSequenceAnnotationAndXrefClassification() throws {
        let program = try assembler.assembleProgram("""
            adrp x0, 0x100003000
            add x0, x0, #0x40
            bl 0x100001900
        """, baseAddress: VirtualAddress(0x1_0000_1200))

        let lookup: @Sendable (VirtualAddress) -> String? = { addr in
            if addr == VirtualAddress(0x1_0000_3040) { return "\"MACHGRAPH-PRO-2026\"" }
            if addr == VirtualAddress(0x1_0000_1900) { return "_puts" }
            return nil
        }

        let idioms = idiomRecognizer.recognizeIdioms(in: program.instructions, symbolLookup: lookup)
        #expect(!idioms.isEmpty)
        let ptrIdiom = try #require(idioms.first { $0.targetAddress == VirtualAddress(0x1_0000_3040) })
        #expect(ptrIdiom.resolvedSymbol?.contains("MACHGRAPH-PRO-2026") == true)

        let annotated = idiomRecognizer.annotateInstructions(program.instructions, symbolLookup: lookup)
        #expect(annotated.contains { ($0.autoComment ?? "").contains("MACHGRAPH-PRO-2026") })
    }

    @Test("Prologue and epilogue analyzer recovers PAC usage, frame pointer setup, stack frame bytes, and saved registers")
    func prologueAndEpilogueAnalyzerStandardAndARM64EPACFrames() throws {
        let pacFunc = try assembler.assembleProgram("""
            paciasp
            sub sp, sp, #48
            stp x20, x19, [sp, #16]
            stp x29, x30, [sp, #32]
            add x29, sp, #32
            bl 0x100002000
            ldp x29, x30, [sp, #32]
            ldp x20, x19, [sp, #16]
            add sp, sp, #48
            retaa
        """, baseAddress: VirtualAddress(0x1_0000_1500))

        let analysis = idiomRecognizer.analyzePrologueAndEpilogue(in: pacFunc.instructions)
        #expect(analysis.hasPrologue)
        #expect(analysis.hasEpilogue)
        #expect(analysis.usesPAC)
        #expect(analysis.establishesFramePointer)
        #expect(analysis.stackFrameBytes == 48)
        #expect(!analysis.isLeaf)
        #expect(analysis.savedRegisters.contains { $0.register == .x(19) })
        #expect(analysis.savedRegisters.contains { $0.register == .x(29) })
    }

    @Test("SymbolDemangler classifies and demangles Swift 5 $s / _$s symbols")
    func symbolDemanglerSwift5FunctionsMethodsGenericsAndTypes() {
        let swiftFunc = "_$s9MachGraph13LicensePacketV8validate5tokenSbSS_tF"
        #expect(demangler.classify(swiftFunc) == .swift)
        let demangledFunc = demangler.demangle(swiftFunc)
        #expect(demangledFunc != swiftFunc)
        #expect(demangledFunc.contains("MachGraph"))
        #expect(demangledFunc.contains("LicensePacket"))
        #expect(demangledFunc.contains("validate"))

        let swiftNominal = "$s15MachGraphTarget13LicensePacketVMn"
        #expect(demangler.classify(swiftNominal) == .swift)
        let demangledNominal = demangler.demangle(swiftNominal)
        #expect(demangledNominal.contains("LicensePacket"))
    }

    @Test("SymbolDemangler classifies and demangles Itanium C++ _Z nested namespaces, templates, and qualifiers")
    func symbolDemanglerItaniumCPPNamespacesTemplatesAndQualifiers() {
        let cppMethod = "__ZN9machgraph6crypto12VerifyDigestEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE"
        #expect(demangler.classify(cppMethod) == .cpp)
        let demangled = demangler.demangle(cppMethod)
        #expect(demangled.contains("machgraph::crypto::VerifyDigest"))

        let cppSimple = "_ZN4core6Engine4stepEib"
        let demangledSimple = demangler.demangle(cppSimple)
        #expect(demangledSimple.contains("core::Engine::step"))
        #expect(demangledSimple.contains("int"))
        #expect(demangledSimple.contains("bool"))
    }

    @Test("SymbolDemangler classifies Objective-C methods and preserves plain C symbols cleanly")
    func symbolDemanglerObjectiveCMethodsAndPlainCSymbols() {
        let objcInst = "-[MGAuthController validateToken:error:]"
        let objcClass = "+[MGAuthController sharedController]"
        #expect(demangler.classify(objcInst) == .objc)
        #expect(demangler.classify(objcClass) == .objc)
        #expect(demangler.demangle(objcInst).contains("MGAuthController"))
        #expect(demangler.demangle(objcInst).contains("validateToken:error:"))

        #expect(demangler.classify("_verify_license") == .c)
        let cDemangled = demangler.demangle("_verify_license")
        #expect(cDemangled == "verify_license" || cDemangled == "_verify_license")
    }

    @Test("VFP 8-bit floating-point immediate and system register table encoding round-trips")
    func vfpFloatImmediateAndSystemRegisterTableRoundTrips() throws {
        for value in [1.0, 2.0, 0.5, -1.0, -4.5] {
            let imm8 = try #require(encodeVFPImm8(value))
            let decoded = decodeVFPExpandImm8(imm8)
            #expect(abs(decoded - value) < 1e-9)
        }

        let nzcvEnc = try #require(A64SystemRegisterTable.encoding(forName: "nzcv"))
        #expect(A64SystemRegisterTable.name(forEncoding: nzcvEnc).lowercased() == "nzcv")
        let unpacked = A64SystemRegisterTable.unpackEncoding(nzcvEnc)
        let repacked = A64SystemRegisterTable.packEncoding(
            op0: unpacked.op0,
            op1: unpacked.op1,
            crn: unpacked.crn,
            crm: unpacked.crm,
            op2: unpacked.op2
        )
        #expect(repacked == nzcvEnc)
    }

    @Test("M1: Decode LLVM preferred aliases (vector ORR mov, general INS mov, 32/64-bit UMOV mov, PAC/system HINTs) and preserve non-alias counterexamples")
    func decodeM1PreferredAliasesAndBoundaryCounterexamples() {
        let pc = VirtualAddress(0x1_0000_4000)

        // 1. Vector ORR -> MOV when Rm == Rn; stays ORR when Rm != Rn.
        // 0x4ea01c08 -> llvm-objdump: `mov.16b v8, v0`
        let orrSame16b = decoder.decode(word: 0x4EA0_1C08, at: pc)
        #expect(orrSame16b.mnemonic == .mov)
        #expect(orrSame16b.mnemonicText == "mov")
        #expect(orrSame16b.formattedDisassembly == "mov v8.16b, v0.16b")

        // 0x0ea41c82 -> llvm-objdump: `mov.8b v2, v4`
        let orrSame8b = decoder.decode(word: 0x0EA4_1C82, at: pc)
        #expect(orrSame8b.mnemonic == .mov)
        #expect(orrSame8b.mnemonicText == "mov")
        #expect(orrSame8b.formattedDisassembly == "mov v2.8b, v4.8b")

        // Counterexample (Rm != Rn): 0x4ea11c08 -> llvm-objdump: `orr.16b v8, v0, v1`
        let orrDiff16b = decoder.decode(word: 0x4EA1_1C08, at: pc)
        #expect(orrDiff16b.mnemonic == .orrVec)
        #expect(orrDiff16b.mnemonicText == "orr")
        #expect(orrDiff16b.formattedDisassembly == "orr v8.16b, v0.16b, v1.16b")

        // Counterexample (Rm != Rn): 0x0ea51c82 -> llvm-objdump: `orr.8b v2, v4, v5`
        let orrDiff8b = decoder.decode(word: 0x0EA5_1C82, at: pc)
        #expect(orrDiff8b.mnemonic == .orrVec)
        #expect(orrDiff8b.mnemonicText == "orr")
        #expect(orrDiff8b.formattedDisassembly == "orr v2.8b, v4.8b, v5.8b")

        // 2. INS (from general-purpose register, Q=1, !U, imm4=0b0011):
        // Apple llvm-objdump unconditionally emits `mov.<b|h|s|d>` for all valid encodings
        // (and `.long` when Q=0, which is unallocated in ARMv8-A).
        let insCases: [(UInt32, String)] = [
            (0x4E03_1D00, "mov v0.b[1], w8"),    // llvm-objdump: `mov.b v0[1], w8`
            (0x4E06_1D60, "mov v0.h[1], w11"),   // llvm-objdump: `mov.h v0[1], w11`
            (0x4E0C_1D21, "mov v1.s[1], w9"),    // llvm-objdump: `mov.s v1[1], w9`
            (0x4E18_1F21, "mov v1.d[1], x25"),   // llvm-objdump: `mov.d v1[1], x25`
            (0x4E01_1FE0, "mov v0.b[0], wzr"),   // llvm-objdump: `mov.b v0[0], wzr`
            (0x4E08_1FFD, "mov v29.d[0], xzr"),  // llvm-objdump: `mov.d v29[0], xzr`
        ]
        for (word, expected) in insCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .mov, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == "mov", "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }
        // Unallocated Q=0 boundary: 0x0e0c1d21 -> llvm-objdump: `.long 0x0e0c1d21`
        let insQ0Invalid = decoder.decode(word: 0x0E0C_1D21, at: pc)
        #expect(insQ0Invalid.mnemonic == .unknown)
        #expect(insQ0Invalid.mnemonicText == ".inst")

        // 3. UMOV -> MOV when copying 32-bit `.s` to Wd (Q=0, tz=2) or 64-bit `.d` to Xd (Q=1, tz=3);
        // stays UMOV for zero-extending 8-bit `.b` (Q=0, tz=0) and 16-bit `.h` (Q=0, tz=1).
        // 0x0e0c3cca -> llvm-objdump: `mov.s w10, v6[1]`
        let umovS = decoder.decode(word: 0x0E0C_3CCA, at: pc)
        #expect(umovS.mnemonic == .mov)
        #expect(umovS.mnemonicText == "mov")
        #expect(umovS.formattedDisassembly == "mov w10, v6.s[1]")

        // 0x4e183c43 -> llvm-objdump: `mov.d x3, v2[1]`
        let umovD = decoder.decode(word: 0x4E18_3C43, at: pc)
        #expect(umovD.mnemonic == .mov)
        #expect(umovD.mnemonicText == "mov")
        #expect(umovD.formattedDisassembly == "mov x3, v2.d[1]")

        // Counterexample (.b): 0x0e013c20 -> llvm-objdump: `umov.b w0, v1[0]`
        let umovB = decoder.decode(word: 0x0E01_3C20, at: pc)
        #expect(umovB.mnemonic == .umov)
        #expect(umovB.mnemonicText == "umov")
        #expect(umovB.formattedDisassembly == "umov w0, v1.b[0]")

        // Counterexample (.h): 0x0e023c20 -> llvm-objdump: `umov.h w0, v1[0]`
        let umovH = decoder.decode(word: 0x0E02_3C20, at: pc)
        #expect(umovH.mnemonic == .umov)
        #expect(umovH.mnemonicText == "umov")
        #expect(umovH.formattedDisassembly == "umov w0, v1.h[0]")

        // Unallocated Q/width mismatches: 0x0e083c20 (Q=0,.d) and 0x4e043c20 (Q=1,.s) -> `.long`
        #expect(decoder.decode(word: 0x0E08_3C20, at: pc).mnemonicText == ".inst")
        #expect(decoder.decode(word: 0x4E04_3C20, at: pc).mnemonicText == ".inst")

        // 4. Architectural & PAC HINT encodings matching `llvm-objdump --arch=arm64e --mattr=+bti`,
        // plus unallocated hint counterexamples that must remain `hint #imm`.
        let hintAliases: [(UInt32, String)] = [
            (0xD503_20DF, "dgh"),        // hint #6  -> llvm-objdump: `dgh`
            (0xD503_211F, "pacia1716"),  // hint #8  -> llvm-objdump: `pacia1716`
            (0xD503_215F, "pacib1716"),  // hint #10 -> llvm-objdump: `pacib1716`
            (0xD503_219F, "autia1716"),  // hint #12 -> llvm-objdump: `autia1716`
            (0xD503_21DF, "autib1716"),  // hint #14 -> llvm-objdump: `autib1716`
            (0xD503_221F, "esb"),        // hint #16 -> llvm-objdump: `esb`
            (0xD503_229F, "csdb"),       // hint #20 -> llvm-objdump: `csdb`
            (0xD503_231F, "paciaz"),     // hint #24 -> llvm-objdump: `paciaz`
            (0xD503_235F, "pacibz"),     // hint #26 -> llvm-objdump: `pacibz`
            (0xD503_239F, "autiaz"),     // hint #28 -> llvm-objdump: `autiaz`
            (0xD503_23DF, "autibz"),     // hint #30 -> llvm-objdump: `autibz`
        ]
        for (word, expected) in hintAliases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonicText == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples: unallocated hint codes remain `hint #<imm>` (llvm-objdump also emits `hint`,
        // formatting the immediate as `#0x9`, `#0x11`, and `#39` respectively).
        let hintCounterexamples: [(UInt32, String)] = [
            (0xD503_213F, "hint #9"),     // hint #9  -> llvm-objdump: `hint #0x9`
            (0xD503_223F, "hint #0x11"),  // hint #17 -> llvm-objdump: `hint #0x11`
            (0xD503_24FF, "hint #0x27"),  // hint #39 -> llvm-objdump: `hint #39`
        ]
        for (word, expected) in hintCounterexamples {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .hint)
            #expect(decoded.mnemonicText == "hint")
            #expect(decoded.formattedDisassembly == expected)
        }
    }

    @Test("SYS preferred aliases match Apple llvm-objdump across all 2,048 op1/CRn∈{7,8}/CRm/op2 encodings")
    func sysPreferredAliasesMatchLLVMReferenceTable() throws {
        let rawText = try String(contentsOf: RepoFixtures.sysAliasTableURL, encoding: .utf8)
        let lines = rawText.split(whereSeparator: \.isNewline).map(String.init)

        let comments = lines.filter { $0.hasPrefix("#") }.joined(separator: "\n")
        #expect(comments.contains("Apple LLVM version"))
        #expect(comments.contains("xcrun llvm-objdump --macho -d --no-show-raw-insn"))
        #expect(comments.contains("--mcpu=apple-m1"))

        var rows: [(word: UInt32, mnemonic: String)] = []
        rows.reserveCapacity(2048)
        for line in lines where !line.hasPrefix("#") && !line.trimmingCharacters(in: .whitespaces).isEmpty {
            let parts = line.split(separator: "\t")
            #expect(parts.count == 2, "Malformed table row: \(line)")
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            rows.append((word, String(parts[1])))
        }
        #expect(rows.count == 2048)

        let decoder = A64InstructionDecoder()
        let pc = VirtualAddress(0x1_0000_1000)
        var mismatchSamples: [String] = []

        for (wordRt0, expectedMnemonic) in rows {
            for rtVariant in [wordRt0, wordRt0 | 0x1F] {
                let decoded = decoder.decode(word: rtVariant, at: pc)
                if decoded.mnemonic != .sys || decoded.mnemonicText != expectedMnemonic {
                    if mismatchSamples.count < 10 {
                        mismatchSamples.append(
                            String(format: "0x%08x expected %@ got %@", rtVariant, expectedMnemonic, decoded.mnemonicText)
                        )
                    }
                }
            }
        }
        #expect(mismatchSamples.isEmpty, "SYS alias mismatches (sample): \(mismatchSamples.joined(separator: "; "))")

        // Concrete runtime words from /usr/libexec/rosetta/runtime plus registerless / SYSL / non-{7,8} CRn checks:
        #expect(decoder.decode(word: 0xD50B_7520, at: pc).formattedDisassembly == "ic ivau, x0")
        #expect(decoder.decode(word: 0xD50B_7423, at: pc).formattedDisassembly == "dc zva, x3")
        #expect(decoder.decode(word: 0xD508_751F, at: pc).formattedDisassembly == "ic iallu")
        #expect(decoder.decode(word: 0xD508_831F, at: pc).formattedDisassembly == "tlbi vmalle1is")
        #expect(decoder.decode(word: 0xD508_8325, at: pc).formattedDisassembly == "tlbi vae1is, x5")
        #expect(decoder.decode(word: 0xD508_7802, at: pc).formattedDisassembly == "at s1e1r, x2")
        #expect(decoder.decode(word: 0xD52B_7520, at: pc).mnemonicText == "sysl")
        #expect(decoder.decode(word: 0xD508_6000, at: pc).mnemonicText == "sys")
    }

    @Test("G34: Unallocated SMOV and DUP encodings in AdvSIMD Copy decode as .inst while valid forms still decode")
    func smovAndDupUnallocatedEncodingsDecodeAsInst() {
        let decoder = A64InstructionDecoder()
        let pc = VirtualAddress(0x1_0000_1000)

        // All 12 unallocated AdvSIMD Copy words (Rn=1, Rd=2) where llvm-objdump prints `.long`:
        let unallocatedWords: [UInt32] = [
            // DUP (element): Q=0, imm5 in {0b01000, 0b11000} (1d is unallocated)
            0x0E08_0422,
            0x0E18_0422,
            // DUP (general): Q=0, imm5 in {0b01000, 0b11000} (1d is unallocated)
            0x0E08_0C22,
            0x0E18_0C22,
            // SMOV: Q=0 with .s (imm5 in {0b00100, 0b01100, 0b10100, 0b11100})
            0x0E04_2C22,
            0x0E0C_2C22,
            0x0E14_2C22,
            0x0E1C_2C22,
            // SMOV: Q=0 with .d (imm5 in {0b01000, 0b11000})
            0x0E08_2C22,
            0x0E18_2C22,
            // SMOV: Q=1 with .d (imm5 in {0b01000, 0b11000})
            0x4E08_2C22,
            0x4E18_2C22,
        ]
        for word in unallocatedWords {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "Expected .unknown for 0x\(String(word, radix: 16)), got \(decoded.mnemonic)")
            #expect(decoded.mnemonicText == ".inst", "Expected .inst for 0x\(String(word, radix: 16)), got \(decoded.formattedDisassembly)")
        }

        // Allocated SMOV & DUP forms must continue decoding cleanly:
        #expect(decoder.decode(word: 0x0E01_2C22, at: pc).formattedDisassembly == "smov w2, v1.b[0]")
        #expect(decoder.decode(word: 0x0E02_2C22, at: pc).formattedDisassembly == "smov w2, v1.h[0]")
        #expect(decoder.decode(word: 0x4E01_2C22, at: pc).formattedDisassembly == "smov x2, v1.b[0]")
        #expect(decoder.decode(word: 0x4E02_2C22, at: pc).formattedDisassembly == "smov x2, v1.h[0]")
        #expect(decoder.decode(word: 0x4E04_2C22, at: pc).formattedDisassembly == "smov x2, v1.s[0]")
        #expect(decoder.decode(word: 0x0E04_0422, at: pc).formattedDisassembly == "dup v2.2s, v1.s[0]")
        #expect(decoder.decode(word: 0x4E08_0422, at: pc).formattedDisassembly == "dup v2.2d, v1.d[0]")
        #expect(decoder.decode(word: 0x0E04_0C22, at: pc).formattedDisassembly == "dup v2.2s, w1")
        #expect(decoder.decode(word: 0x4E08_0C22, at: pc).formattedDisassembly == "dup v2.2d, x1")
    }

    @Test("G43: HINT preferred aliases match Apple llvm-objdump across all 128 CRm/op2 encodings")
    func hintPreferredAliasesMatchLLVMReferenceTable() throws {
        let rawText = try String(contentsOf: RepoFixtures.hintAliasTableURL, encoding: .utf8)
        let lines = rawText.split(whereSeparator: \.isNewline).map(String.init)

        let comments = lines.filter { $0.hasPrefix("#") }.joined(separator: "\n")
        #expect(comments.contains("Apple LLVM version"))
        #expect(comments.contains("xcrun llvm-objdump --macho -d --no-show-raw-insn"))
        #expect(comments.contains("--mcpu=apple-m1"))
        #expect(comments.contains("--mattr=+bti"))

        var rows: [(word: UInt32, mnemonic: String)] = []
        rows.reserveCapacity(128)
        for line in lines where !line.hasPrefix("#") && !line.trimmingCharacters(in: .whitespaces).isEmpty {
            let parts = line.split(separator: "\t")
            #expect(parts.count == 2, "Malformed table row: \(line)")
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            rows.append((word, String(parts[1])))
        }
        #expect(rows.count == 128)

        let decoder = A64InstructionDecoder()
        let pc = VirtualAddress(0x1_0000_1000)
        var mismatches: [String] = []

        for (word, expectedMnemonic) in rows {
            let decoded = decoder.decode(word: word, at: pc)
            if decoded.mnemonicText != expectedMnemonic {
                mismatches.append(
                    String(format: "0x%08x expected %@ got %@", word, expectedMnemonic, decoded.mnemonicText)
                )
            }
        }
        #expect(mismatches.isEmpty, "HINT alias mismatches: \(mismatches.joined(separator: "; "))")

        // Concrete check for hint #18 (CRm=2, op2=2 -> 0xd503225f -> `tsb csync` under --mcpu=apple-m1):
        let tsb = decoder.decode(word: 0xD503_225F, at: pc)
        #expect(tsb.mnemonic == .hint)
        #expect(tsb.mnemonicText == "tsb")
        #expect(tsb.formattedDisassembly == "tsb csync")
    }

    @Test("G52a: Register-offset load/store and PRFM reject option<1>==0 unallocated encodings as .inst")
    func registerOffsetLoadStoreAndPrfmRejectUnallocatedOptionEncodings() {
        let pc = VirtualAddress(0x1_0000_1000)

        // Unallocated option in {0b000, 0b001, 0b100, 0b101} from Fixtures/a64/load_store_reg_offset.tsv:
        let unallocatedWords: [UInt32] = [
            0x3823_0841, // option=000 (strb space)
            0x3863_2841, // option=001 (ldrb space)
            0xFC63_9841, // option=100, S=1 (ldr d1 space)
            0xFC63_B841, // option=101, S=1 (ldr d1 space)
            0xF8A3_0840, // option=000 (prfm space)
            0xF8A3_B858, // option=101, S=1 (rprfm rt=24 space)
        ]
        for word in unallocatedWords {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "Expected .unknown for 0x\(String(word, radix: 16)), got \(decoded.mnemonic)")
            #expect(decoded.mnemonicText == ".inst", "Expected .inst for 0x\(String(word, radix: 16)), got \(decoded.formattedDisassembly)")
        }

        // Valid option<1>==1 encodings ({0b010, 0b011, 0b110, 0b111}) continue decoding:
        #expect(decoder.decode(word: 0xF863_4841, at: pc).formattedDisassembly == "ldr x1, [x2, w3, uxtw]")
        #expect(decoder.decode(word: 0xF863_7841, at: pc).formattedDisassembly == "ldr x1, [x2, x3, lsl #3]")
        #expect(decoder.decode(word: 0xFC63_C841, at: pc).formattedDisassembly == "ldr d1, [x2, w3, sxtw]")
        #expect(decoder.decode(word: 0xF8A3_E840, at: pc).formattedDisassembly == "prfm pldl1keep, [x2, x3, sxtx]")
    }

    @Test("G52b (D-M2-4): Conditional branch encodings with bit[4]==1 (bc.<cond>) decode as .inst under apple-m1")
    func conditionalBranchConsistentHintBit4DecodesAsInst() {
        let pc = VirtualAddress(0x1_0000_1000)

        // FEAT_HBC `bc.<cond>` words (bit[4]==1) from Fixtures/a64/cond_branch_imm.tsv:
        let bcWords: [UInt32] = [
            0x5400_0010, // bc.eq
            0x5400_0031, // bc.ne
            0x5480_001A, // bc.ge
            0x54FF_FFFE, // bc.al
            0x54FF_FFFF, // bc.nv
        ]
        for word in bcWords {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "Expected .unknown for 0x\(String(word, radix: 16)), got \(decoded.mnemonic)")
            #expect(decoded.mnemonicText == ".inst", "Expected .inst for 0x\(String(word, radix: 16)), got \(decoded.formattedDisassembly)")
        }

        // Standard `b.<cond>` words (bit[4]==0) continue decoding:
        #expect(decoder.decode(word: 0x5400_0000, at: pc).formattedDisassembly == "b.eq 0x100001000")
        #expect(decoder.decode(word: 0x5400_0021, at: pc).formattedDisassembly == "b.ne 0x100001004")
        #expect(decoder.decode(word: 0x54FF_FFEE, at: pc).formattedDisassembly == "b.al 0x100000ffc")
    }

    @Test("G52c: AdvSIMD Copy checks bit[15]==0 at group entry before DUP, UMOV, SMOV, and INS/MOV")
    func advsimdCopyChecksBit15AtGroupEntry() {
        let pc = VirtualAddress(0x1_0000_1000)

        // Unallocated bit[15]==1 words from random fuzz seeds (17, 20261117) and Fixtures/a64/advsimd_copy.tsv:
        let bit15SetWords: [UInt32] = [
            0x4E0E_87A9, // seed 17 (DUP element path)
            0x0E19_8F6F, // seed 20261117 (DUP general path)
            0x0E12_BE72, // seed 20261117 (UMOV path)
            0x4E19_9F3D, // seed 20261117 (INS/MOV path)
            0x0E01_AC41, // advsimd_copy.tsv (SMOV path)
            0x0E04_BC41, // advsimd_copy.tsv (UMOV->MOV path)
        ]
        for word in bit15SetWords {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "Expected .unknown for 0x\(String(word, radix: 16)), got \(decoded.mnemonic)")
            #expect(decoded.mnemonicText == ".inst", "Expected .inst for 0x\(String(word, radix: 16)), got \(decoded.formattedDisassembly)")
        }

        // Valid bit[15]==0 encodings across all four copy subforms continue decoding:
        #expect(decoder.decode(word: 0x0E01_0C41, at: pc).formattedDisassembly == "dup v1.8b, w2")
        #expect(decoder.decode(word: 0x0E01_2C41, at: pc).formattedDisassembly == "smov w1, v2.b[0]")
        #expect(decoder.decode(word: 0x0E01_3C41, at: pc).formattedDisassembly == "umov w1, v2.b[0]")
        #expect(decoder.decode(word: 0x4E01_1C41, at: pc).formattedDisassembly == "mov v1.b[0], w2")
    }

    @Test("G52d: RPRFM encodings in register-offset prefetch space format named and hex range-prefetch operands")
    func rprfmRegisterOffsetEncodingsMatchLLVMReference() {
        let pc = VirtualAddress(0x1_0000_1000)

        // Named and immediate RPRFM encodings from Fixtures/a64/load_store_reg_offset.tsv and fuzz seed 20261117:
        let rprfmCases: [(UInt32, String)] = [
            (0xF8A3_4858, "rprfm pldkeep, x3, [x2]"),
            (0xF8A3_4859, "rprfm pstkeep, x3, [x2]"),
            (0xF8A3_485A, "rprfm #0x2, x3, [x2]"),
            (0xF8A3_485B, "rprfm #0x3, x3, [x2]"),
            (0xF8A3_485C, "rprfm pldstrm, x3, [x2]"),
            (0xF8A3_485D, "rprfm pststrm, x3, [x2]"),
            (0xF8A3_485E, "rprfm #0x6, x3, [x2]"),
            (0xF8A3_5858, "rprfm #0x8, x3, [x2]"),
            (0xF8A3_6858, "rprfm #0x10, x3, [x2]"),
            (0xF8A3_C858, "rprfm #0x20, x3, [x2]"),
            (0xF8A3_F85F, "rprfm #0x3f, x3, [x2]"),
            (0xF8B3_F9FF, "rprfm #0x3f, x19, [x15]"), // seed 20261117
            (0xF8BF_4BF8, "rprfm pldkeep, xzr, [sp]"),
        ]
        for (word, expected) in rprfmCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonicText == "rprfm", "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Boundary prfop=23 (< 24) stays PRFM:
        #expect(decoder.decode(word: 0xF8A3_4857, at: pc).formattedDisassembly == "prfm #0x17, [x2, w3, uxtw]")
    }

    @Test("G48b: Logical-immediate ORR with Rn=ZR emits orr when MoveWidePreferred holds and mov otherwise")
    func logicalImmediateOrrMoveWidePreferredCondition() {
        let pc = VirtualAddress(0x1_0000_1000)

        // MoveWidePreferred == true counterexamples from Fixtures/a64/logical_imm.tsv and fuzz seeds (17, 20261117):
        let orrCounterexamples: [(UInt32, String)] = [
            (0x3200_03E1, "orr w1, wzr, #1"),
            (0x3210_07E1, "orr w1, wzr, #0x30000"),
            (0x3201_63E1, "orr w1, wzr, #0x80ffffff"),
            (0x3201_63E4, "orr w4, wzr, #0x80ffffff"), // seed 17
            (0x3210_63E1, "orr w1, wzr, #0xffff01ff"),
            (0xB240_03E1, "orr x1, xzr, #1"),
            (0xB250_07E1, "orr x1, xzr, #0x3000000000000"),
            (0xB27F_03E1, "orr x1, xzr, #2"),
            (0xB269_E7F4, "orr x20, xzr, #0xffffffffff81ffff"), // seed 20261117
        ]
        for (word, expected) in orrCounterexamples {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .orr, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == "orr", "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // MoveWidePreferred == false bitmasks from Fixtures/a64/logical_imm.tsv keep emitting `mov`:
        let movBitmaskCases: [UInt32] = [
            0x323F_63E1, // mov w1, #0x3fffffe
            0xB200_03E1, // mov x1, #0x100000001
            0xB240_63E1, // mov x1, #0x1ffffff
            0xB27F_63E1, // mov x1, #0x3fffffe
        ]
        for word in movBitmaskCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .mov, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == "mov", "word=0x\(String(word, radix: 16))")
        }
    }

    @Test("G52f: BFM with Rn=ZR emits bfc across lsb==0 and lsb>0 while preserving bfxil and non-ZR bfi")
    func bfmZeroSourceEmitsBfcPreferredAlias() {
        let pc = VirtualAddress(0x1_0000_1000)

        // BFC cases from Fixtures/a64/bitfield.tsv (both immr==0 and immr>imms) and fuzz seed 20261117:
        let bfcCases: [(UInt32, String)] = [
            (0x3300_03E1, "bfc w1, #0, #1"),
            (0x3300_1FE1, "bfc w1, #0, #8"),
            (0x331F_1FE1, "bfc w1, #1, #8"),
            (0xB340_1FE1, "bfc x1, #0, #8"),
            (0xB34F_13E9, "bfc x9, #0x31, #5"), // seed 20261117
        ]
        for (word, expected) in bfcCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonicText == "bfc", "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples: Rn=ZR with immr>0 && imms>=immr stays bfxil; Rn!=ZR with imms<immr stays bfi:
        #expect(decoder.decode(word: 0x3307_3FE1, at: pc).formattedDisassembly == "bfxil w1, wzr, #7, #9")
        #expect(decoder.decode(word: 0xB34F_7FE1, at: pc).formattedDisassembly == "bfxil x1, xzr, #15, #0x11")
        #expect(decoder.decode(word: 0x331F_1C41, at: pc).formattedDisassembly == "bfi w1, w2, #1, #8")
    }

    @Test("G52g: LSE atomic operations with Rt=ZR preserve acquire suffix when A=1 and emit two-operand st* aliases when A=0")
    func lseAtomicZeroDestinationAcquireAndStPreferredAliases() {
        let pc = VirtualAddress(0x1_0000_1000)

        // Rt=ZR with A=1 retains `a`/`al` and 3 operands (seeds 17, 20261117, and Fixtures/a64/lse_atomic.tsv):
        let acquireZeroRtCases: [(UInt32, String)] = [
            (0x38EE_33BF, "ldsetalb w14, wzr, [x29]"), // seed 17
            (0x78F5_20BF, "ldeoralh w21, wzr, [x5]"),  // seed 20261117
            (0xF8A3_005F, "ldadda x3, xzr, [x2]"),
            (0xF8E3_13FF, "ldclral x3, xzr, [sp]"),
            (0xB8A3_605F, "ldumaxa w3, wzr, [x2]"),
        ]
        for (word, expected) in acquireZeroRtCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Rt=ZR with A=0 emits two-operand st* aliases across all 8 stems and l/b/h suffixes:
        let stAliasCases: [(UInt32, String)] = [
            (0xF83A_025F, "stadd x26, [x18]"),   // seed 20261117
            (0xB875_119F, "stclrl w21, [x12]"),  // seed 20261117
            (0x3837_317F, "stsetb w23, [x11]"),  // seed 20261117
            (0x7863_205F, "steorlh w3, [x2]"),
            (0xF823_405F, "stsmax x3, [x2]"),
            (0x3863_505F, "stsminlb w3, [x2]"),
            (0x7823_605F, "stumaxh w3, [x2]"),
            (0xB863_73FF, "stuminl w3, [sp]"),
        ]
        for (word, expected) in stAliasCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.isEmpty, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples: Rt != ZR stays 3-operand ld*, and SWP with Rt=ZR, A=0 stays 3-operand swp:
        #expect(decoder.decode(word: 0xF823_0041, at: pc).formattedDisassembly == "ldadd x3, x1, [x2]")
        #expect(decoder.decode(word: 0xF823_4041, at: pc).formattedDisassembly == "ldsmax x3, x1, [x2]")
        #expect(decoder.decode(word: 0xF823_805F, at: pc).formattedDisassembly == "swp x3, xzr, [x2]")
    }

    @Test("G47: Scalar FMOV #imm8 and FCMP/FCMPE #0.0 match llvm-objdump verbatim across all 1,152 fp_imm.tsv rows and round-trip through A64MiniAssembler")
    func fpImmediateAndFcmpZeroVerbatimReferenceAndAssemblerRoundTrip() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // Concrete precision-loss and #0.0 examples from 02-machgraph.md (G47):
        #expect(decoder.decode(word: 0x1E68_3000, at: pc).formattedDisassembly == "fmov d0, #0.13281250")
        #expect(decoder.decode(word: 0x1E28_3000, at: pc).formattedDisassembly == "fmov s0, #0.13281250")
        #expect(decoder.decode(word: 0x1EE8_3000, at: pc).formattedDisassembly == "fmov h0, #0.13281250")
        #expect(decoder.decode(word: 0x1E60_1000, at: pc).formattedDisassembly == "fmov d0, #2.00000000")
        #expect(decoder.decode(word: 0x1E60_2108, at: pc).formattedDisassembly == "fcmp d8, #0.0")
        #expect(decoder.decode(word: 0x1E60_2118, at: pc).formattedDisassembly == "fcmpe d8, #0.0")
        #expect(decoder.decode(word: 0x1E20_2048, at: pc).formattedDisassembly == "fcmp s2, #0.0")
        #expect(decoder.decode(word: 0x1EE0_2058, at: pc).formattedDisassembly == "fcmpe h2, #0.0")

        // Verbatim text comparison (NOT numeric O2) against every row in Fixtures/a64/fp_imm.tsv:
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("fp_imm"), encoding: .utf8)
        let lines = rawText.split(whereSeparator: \.isNewline).map(String.init)
        var rowCount = 0
        var verbatimMismatches: [String] = []
        var roundTripMismatches: [String] = []
        var fcmpZeroRowCount = 0

        for line in lines where !line.hasPrefix("#") && !line.trimmingCharacters(in: .whitespaces).isEmpty {
            let parts = line.split(separator: "\t", maxSplits: 2).map(String.init)
            #expect(parts.count == 3, "Malformed fp_imm.tsv row: \(line)")
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            let refMnem = parts[1]
            let refOps = parts[2]
            rowCount += 1

            let decoded = decoder.decode(word: word, at: pc)
            if refMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    verbatimMismatches.append(String(format: "0x%08x expected .inst got %@", word, decoded.formattedDisassembly))
                }
                continue
            }

            let expectedText = "\(refMnem) \(refOps)"
            if decoded.formattedDisassembly != expectedText {
                if verbatimMismatches.count < 12 {
                    verbatimMismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                }
            }
            if (refMnem == "fcmp" || refMnem == "fcmpe") && refOps.hasSuffix("#0.0") {
                fcmpZeroRowCount += 1
            }

            // Canonical encodings (FMOV #imm8 and FCMP/FCMPE with Rm==0 for #0.0) must round-trip via A64MiniAssembler:
            let isNonCanonicalZeroCmp = (refMnem == "fcmp" || refMnem == "fcmpe") && refOps.hasSuffix("#0.0") && ((word >> 16) & 0x1F) != 0
            if !isNonCanonicalZeroCmp {
                if let reencoded = try? assembler.assembleSingle(decoded.formattedDisassembly, at: pc), reencoded == word {
                    // ok
                } else {
                    if roundTripMismatches.count < 10 {
                        roundTripMismatches.append(String(format: "0x%08x ('%@') failed round-trip", word, decoded.formattedDisassembly))
                    }
                }
            }
        }

        #expect(rowCount == 1152)
        #expect(fcmpZeroRowCount == 12)
        #expect(verbatimMismatches.isEmpty, "G47 verbatim mismatches (\(verbatimMismatches.count)): \(verbatimMismatches.joined(separator: "; "))")
        #expect(roundTripMismatches.isEmpty, "G47 assembler round-trip mismatches: \(roundTripMismatches.joined(separator: "; "))")
    }

    @Test("G48a: Logical-immediate ORR mov alias formats negative signed immediates in 32-bit and 64-bit while preserving unsigned logical immediates")
    func logicalImmediateOrrMovAliasFormatsSignedImmediates() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // Signed negative MOV bitmask immediates from standard/full corpus, logical_imm.tsv, and fuzz seeds:
        let negativeMovCases: [(UInt32, String)] = [
            (0x3201_07E1, "mov w1, #-0x7fffffff"),            // logical_imm.tsv (0x80000001)
            (0x3201_0BE1, "mov w1, #-0x7ffffffd"),            // /usr/bin/ssh (0x80000003)
            (0x320D_B7EA, "mov w10, #-0x60007"),              // /bin/unlink (0xfff9fff9)
            (0x3227_27F3, "mov w19, #-0x1fffff9"),            // seed 20261117
            (0x320A_AFE9, "mov w9, #-0x3c003d"),              // seed 17
            (0x3201_07FF, "mov wsp, #-0x7fffffff"),           // 32-bit WSP destination
            (0xB202_E7EA, "mov x10, #-0x3333333333333334"),   // /usr/bin/ssh (0xcccccccccccccccc)
            (0xB260_7FE8, "mov x8, #-0x100000000"),           // /bin/bash (0xffffffff00000000)
            (0xB250_63E1, "mov x1, #-0xfffffffffe01"),        // logical_imm.tsv
            (0xB21B_73E2, "mov x2, #-0x1c0000001d"),          // seed 20261117
            (0xB20B_6FEA, "mov x10, #-0x1e0000001e0001"),     // seed 17
            (0xB202_E7FF, "mov sp, #-0x3333333333333334"),    // 64-bit SP destination
        ]
        for (word, expected) in negativeMovCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .mov, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            let reencoded = try assembler.assembleSingle(decoded.formattedDisassembly, at: pc)
            if word == 0x3227_27F3 {
                // Non-canonical random fuzz word (32-bit immr=39 aliases canonical immr=7 -> 0x320727f3)
                #expect(reencoded == 0x3207_27F3)
                #expect(decoder.decode(word: reencoded, at: pc).formattedDisassembly == expected)
            } else {
                #expect(reencoded == word, "word=0x\(String(word, radix: 16))")
            }
        }

        // Int64.min boundary in A64Operand.immediate must not trap on negation:
        #expect(A64Operand.immediate(Int64.min).description == "#-0x8000000000000000")

        // Positive bitmask MOV and non-MOV logical immediates (ORR/AND/EOR/TST) remain unsigned:
        #expect(decoder.decode(word: 0xB200_03E1, at: pc).formattedDisassembly == "mov x1, #0x100000001")
        #expect(decoder.decode(word: 0x323F_63E1, at: pc).formattedDisassembly == "mov w1, #0x3fffffe")
        #expect(decoder.decode(word: 0xB269_E7F4, at: pc).formattedDisassembly == "orr x20, xzr, #0xffffffffff81ffff")
        #expect(decoder.decode(word: 0x9240_0041, at: pc).formattedDisassembly == "and x1, x2, #1")
        #expect(decoder.decode(word: 0xF202_E45F, at: pc).formattedDisassembly == "tst x2, #0xcccccccccccccccc")
    }

    @Test("G49: Extended-register ADD/SUB/ADDS/SUBS and CMN/CMP with SP/WSP emit lsl #n or omit #0 for matching width UXTW/UXTX")
    func extendedRegisterAddSubSpLslPreferredFormatting() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // Preferred LSL / omitted-#0 forms when Rd or Rn is SP/WSP and extend is UXTW (32-bit) or UXTX (64-bit):
        let lslPreferredCases: [(UInt32, String)] = [
            (0x0B23_405F, "add wsp, w2, w3"),               // 32-bit Rd=wsp, uxtw #0 -> omit
            (0x0B23_43E1, "add w1, wsp, w3"),               // 32-bit Rn=wsp, uxtw #0 -> omit
            (0x0B34_4F7F, "add wsp, w27, w20, lsl #3"),     // seed 20261117
            (0x2B27_47FA, "adds w26, wsp, w7, lsl #1"),     // seed 17
            (0x2B23_43FF, "cmn wsp, w3"),                   // S=1, Rd=wzr, Rn=wsp, uxtw #0 -> cmn omit
            (0x6B23_53FF, "cmp wsp, w3, lsl #4"),           // S=1, Rd=wzr, Rn=wsp, uxtw #4 -> cmp lsl #4
            (0x6B23_4FE1, "subs w1, wsp, w3, lsl #3"),      // 32-bit subs Rn=wsp
            (0xCB36_623F, "sub sp, x17, x22"),              // seed 17 (64-bit Rd=sp, uxtx #0 -> omit)
            (0xCB25_73F7, "sub x23, sp, x5, lsl #4"),       // /usr/bin/assetutil (64-bit Rn=sp, uxtx #4)
            (0x8B23_63FF, "add sp, sp, x3"),                // both Rd=sp and Rn=sp, uxtx #0
            (0xAB23_67E1, "adds x1, sp, x3, lsl #1"),       // 64-bit adds Rn=sp
            (0xAB23_73FF, "cmn sp, x3, lsl #4"),            // 64-bit cmn Rn=sp, uxtx #4
            (0xEB23_63FF, "cmp sp, x3"),                    // 64-bit cmp Rn=sp, uxtx #0
            (0xEB23_6FE1, "subs x1, sp, x3, lsl #3"),       // 64-bit subs Rn=sp
        ]
        for (word, expected) in lslPreferredCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            let reencoded = try assembler.assembleSingle(decoded.formattedDisassembly, at: pc)
            #expect(reencoded == word, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples where UXTW/UXTX/SXT* MUST be preserved:
        let nonLslCounterexamples: [(UInt32, String)] = [
            (0xCB23_4BE5, "sub x5, sp, w3, uxtw #2"),       // 64-bit SP with 32-bit UXTW (option=010) stays uxtw
            (0x0B23_645F, "add wsp, w2, w3, uxtx #1"),      // 32-bit WSP with option=011 UXTX stays uxtx
            (0xEB23_645F, "cmp x2, x3, uxtx #1"),           // S=1, Rd=31 is XZR (not SP), Rn=x2 -> stays uxtx
            (0x2B23_405F, "cmn w2, w3, uxtw"),              // S=1, Rd=31 is WZR (not WSP), Rn=w2 -> stays uxtw
            (0x8B23_6841, "add x1, x2, x3, uxtx #2"),       // Neither Rd nor Rn is SP -> stays uxtx
            (0xCB23_EBFF, "sub sp, sp, x3, sxtx #2"),       // Signed extend SXTX with SP -> stays sxtx
        ]
        for (word, expected) in nonLslCounterexamples {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }
    }

    @Test("G50: Register-offset byte loads and stores (including SIMD scalar B) print explicit #0 when S=1 across uxtw, sxtw, and sxtx")
    func registerOffsetByteLoadStoreExplicitZeroShiftWhenSSet() {
        let pc = VirtualAddress(0x1_0000_1000)

        // All 18 table forms (6 byte instructions x 3 extend options with S=1) plus fuzz examples:
        let s1ByteCases: [(UInt32, String)] = [
            (0x3823_5841, "strb w1, [x2, w3, uxtw #0]"),
            (0x3823_D841, "strb w1, [x2, w3, sxtw #0]"),
            (0x3823_F841, "strb w1, [x2, x3, sxtx #0]"),
            (0x3863_5841, "ldrb w1, [x2, w3, uxtw #0]"),
            (0x3863_D841, "ldrb w1, [x2, w3, sxtw #0]"),
            (0x3863_F841, "ldrb w1, [x2, x3, sxtx #0]"),
            (0x38A3_5841, "ldrsb x1, [x2, w3, uxtw #0]"),
            (0x38A3_D841, "ldrsb x1, [x2, w3, sxtw #0]"),
            (0x38A3_F841, "ldrsb x1, [x2, x3, sxtx #0]"),
            (0x38E3_5841, "ldrsb w1, [x2, w3, uxtw #0]"),
            (0x38E3_D841, "ldrsb w1, [x2, w3, sxtw #0]"),
            (0x38E3_F841, "ldrsb w1, [x2, x3, sxtx #0]"),
            (0x3C23_5841, "str b1, [x2, w3, uxtw #0]"),
            (0x3C23_D841, "str b1, [x2, w3, sxtw #0]"),
            (0x3C23_F841, "str b1, [x2, x3, sxtx #0]"),
            (0x3C63_5841, "ldr b1, [x2, w3, uxtw #0]"),
            (0x3C63_D841, "ldr b1, [x2, w3, sxtw #0]"),
            (0x3C63_F841, "ldr b1, [x2, x3, sxtx #0]"),
            (0x3833_FAFF, "strb wzr, [x23, x19, sxtx #0]"), // seed 20261117
            (0x3C2C_5BA3, "str b3, [x29, w12, uxtw #0]"),   // seed 17
        ]
        for (word, expected) in s1ByteCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples: S=0 omits #0; option=011 S=1 prints lsl #0; larger widths omit #0 when S=0:
        #expect(decoder.decode(word: 0x3823_4841, at: pc).formattedDisassembly == "strb w1, [x2, w3, uxtw]")
        #expect(decoder.decode(word: 0x3863_C841, at: pc).formattedDisassembly == "ldrb w1, [x2, w3, sxtw]")
        #expect(decoder.decode(word: 0x3C63_E841, at: pc).formattedDisassembly == "ldr b1, [x2, x3, sxtx]")
        #expect(decoder.decode(word: 0x3823_7841, at: pc).formattedDisassembly == "strb w1, [x2, x3, lsl #0]")
        #expect(decoder.decode(word: 0x3823_6841, at: pc).formattedDisassembly == "strb w1, [x2, x3]")
        #expect(decoder.decode(word: 0x7863_4841, at: pc).formattedDisassembly == "ldrh w1, [x2, w3, uxtw]")
        #expect(decoder.decode(word: 0x7863_5841, at: pc).formattedDisassembly == "ldrh w1, [x2, w3, uxtw #1]")
    }

    @Test("G51: SYSL prints destination Xt (including xzr) as first operand while SYS keeps trailing optional Xt")
    func syslOperandOrderAndXzrDestinationMatchLLVMReference() {
        let pc = VirtualAddress(0x1_0000_1000)

        let syslCases: [(UInt32, String, [A64Register])] = [
            (0xD529_F175, "sysl x21, #1, c15, c1, #3", [.x(21)]), // seed 17 / G51
            (0xD52D_322C, "sysl x12, #5, c3, c2, #1", [.x(12)]),  // seed 20261117
            (0xD528_0101, "sysl x1, #0, c0, c1, #0", [.x(1)]),    // system_instr.tsv Rt=1
            (0xD528_011F, "sysl xzr, #0, c0, c1, #0", []),        // system_instr.tsv Rt=31 (xzr retained!)
            (0xD52B_7520, "sysl x0, #3, c7, c5, #1", [.x(0)]),    // L=1 never uses IC/DC/AT/TLBI aliases
            (0xD52B_753F, "sysl xzr, #3, c7, c5, #1", []),
        ]
        for (word, expected, expectedWrites) in syslCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonicText == "sysl", "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters.isEmpty, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Counterexamples: L=0 SYS without preferred alias keeps Xt last and omits xzr when Rt==31:
        #expect(decoder.decode(word: 0xD508_0101, at: pc).formattedDisassembly == "sys #0, c0, c1, #0, x1")
        #expect(decoder.decode(word: 0xD508_011F, at: pc).formattedDisassembly == "sys #0, c0, c1, #0")
    }

    @Test("G61: A64SystemRegisterTable matches Apple llvm-objdump across all 32,768 MRS encodings and MSR verification slices (RW, RO, WO, and DBGDTRRX/TX)")
    func systemRegisterTableMatchesAll32768MrsAndMsrReferenceSlices() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // 1. Concrete G61 examples from random fuzz seeds 20261117 and 17:
        let fuzzExamples: [(UInt32, String)] = [
            (0xD530_EBC7, "mrs x7, PMEVCNTSVR30_EL1"), // seed 20261117 (RO register)
            (0xD538_373A, "mrs x26, AFGDTP9_EL1"),     // seed 17
            (0xD53C_CC53, "mrs x19, ICH_LR2_EL2"),     // seed 17
            (0xD518_CCB6, "msr ICC_SRE_EL1, x22"),     // seed 17
            (0xD511_04A0, "msr TRCCNTCTLR0, x0"),      // seed 17
            (0xD511_1850, "msr TRCSSCSR0, x16"),       // seed 17
        ]
        for (word, expected) in fuzzExamples {
            #expect(decoder.decode(word: word, at: pc).formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // 2. Read-only, write-only, shared read/write split (DBGDTRRX_EL0 vs DBGDTRTX_EL0), and apple-m1 unenabled MTE:
        #expect(decoder.decode(word: 0xD538_0001, at: pc).formattedDisassembly == "mrs x1, MIDR_EL1")
        #expect(decoder.decode(word: 0xD518_0001, at: pc).formattedDisassembly == "msr S3_0_C0_C0_0, x1")
        #expect(decoder.decode(word: 0xD530_1081, at: pc).formattedDisassembly == "mrs x1, S2_0_C1_C0_4")
        #expect(decoder.decode(word: 0xD510_1081, at: pc).formattedDisassembly == "msr OSLAR_EL1, x1")
        #expect(decoder.decode(word: 0xD531_1081, at: pc).formattedDisassembly == "mrs x1, S2_1_C1_C0_4")
        #expect(decoder.decode(word: 0xD511_1081, at: pc).formattedDisassembly == "msr TRCOSLAR, x1")
        #expect(decoder.decode(word: 0xD53B_9C81, at: pc).formattedDisassembly == "mrs x1, S3_3_C9_C12_4")
        #expect(decoder.decode(word: 0xD51B_9C81, at: pc).formattedDisassembly == "msr PMSWINC_EL0, x1")
        #expect(decoder.decode(word: 0xD533_0501, at: pc).formattedDisassembly == "mrs x1, DBGDTRRX_EL0")
        #expect(decoder.decode(word: 0xD513_0501, at: pc).formattedDisassembly == "msr DBGDTRTX_EL0, x1")
        #expect(decoder.decode(word: 0xD53B_42E1, at: pc).formattedDisassembly == "mrs x1, S3_3_C4_C2_7")

        // Name-to-encoding lookup supports RW, RO, WO, and split-direction names case-insensitively:
        #expect(A64SystemRegisterTable.encoding(forName: "dbgdtrrx_el0") == A64SystemRegisterTable.encoding(forName: "DBGDTRTX_EL0"))
        #expect(A64SystemRegisterTable.encoding(forName: "oslar_el1") == A64SystemRegisterTable.packEncoding(op0: 2, op1: 0, crn: 1, crm: 0, op2: 4))

        // 3. Exhaustive check against all 8 MRS reference tables (32,768 encodings) and 3 MSR verification slices (12,288 encodings):
        var tableGroups = (0..<8).map { "sysreg_mrs_op1_\($0)" }
        tableGroups.append(contentsOf: ["sysreg_msr_op1_0", "sysreg_msr_op1_1", "sysreg_msr_op1_3"])

        var totalChecked = 0
        var mismatchSamples: [String] = []
        var mismatchCount = 0

        for grp in tableGroups {
            let rawText = try String(contentsOf: RepoFixtures.a64TableURL(grp), encoding: .utf8)
            for line in rawText.split(whereSeparator: \.isNewline) {
                if line.hasPrefix("#") { continue }
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty { continue }
                let parts = line.split(separator: "\t", maxSplits: 2)
                guard parts.count == 3 else {
                    Issue.record("Malformed row in \(grp): \(line)")
                    continue
                }
                let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
                let word = try #require(UInt32(wordHex, radix: 16))
                let expectedText = "\(parts[1]) \(parts[2])"
                let decoded = decoder.decode(word: word, at: pc)
                totalChecked += 1
                if decoded.formattedDisassembly != expectedText {
                    mismatchCount += 1
                    if mismatchSamples.count < 12 {
                        mismatchSamples.append(String(format: "%@ 0x%08x expected '%@' got '%@'", grp, word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }

        #expect(totalChecked == 32768 + 12288)
        #expect(mismatchCount == 0, "G61 mismatches (\(mismatchCount)): \(mismatchSamples.joined(separator: "; "))")
    }

    @Test("Stage 6 Rule 1: MOVZ and MOVN emit preferred mov with signed immediate while preserving A64Mnemonic and caller idioms")
    func moveWideImmediateMovPreferredAliasAndCallerInvariants() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("move_wide_imm"), encoding: .utf8)

        var rowCount = 0
        var movAliasCount = 0
        var retainedWideCount = 0
        var movkCount = 0
        var unallocatedCount = 0

        for line in rawText.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("#") { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let parts = line.split(separator: "\t", maxSplits: 2)
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            let expectedMnem = String(parts[1])
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                unallocatedCount += 1
                #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
                #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
                continue
            }

            #expect(decoded.mnemonicText == expectedMnem, "word=0x\(String(word, radix: 16)) got \(decoded.formattedDisassembly)")

            switch expectedMnem {
            case "mov":
                movAliasCount += 1
                // Structured mnemonic MUST remain .movz or .movn for A64IdiomRecognizer / CFG / Lifter callers!
                #expect(decoded.mnemonic == .movz || decoded.mnemonic == .movn, "word=0x\(String(word, radix: 16))")
                #expect(decoded.formattedDisassembly == "mov \(expectedOps)", "word=0x\(String(word, radix: 16))")
            case "movz":
                retainedWideCount += 1
                #expect(decoded.mnemonic == .movz, "word=0x\(String(word, radix: 16))")
            case "movn":
                retainedWideCount += 1
                #expect(decoded.mnemonic == .movn, "word=0x\(String(word, radix: 16))")
            case "movk":
                movkCount += 1
                #expect(decoded.mnemonic == .movk, "word=0x\(String(word, radix: 16))")
            default:
                Issue.record("Unexpected mnemonic \(expectedMnem) in move_wide_imm.tsv")
            }

            // Every valid row in move_wide_imm.tsv must round-trip cleanly through A64MiniAssembler:
            let reencoded = try assembler.assembleSingle(decoded.formattedDisassembly, at: pc)
            #expect(reencoded == word, "Round-trip mismatch for '\(decoded.formattedDisassembly)'")
        }

        #expect(rowCount == 128)
        #expect(movAliasCount == 38)
        #expect(retainedWideCount == 10)
        #expect(movkCount == 24)
        #expect(unallocatedCount == 56)

        // Zero-register destination (wzr / xzr) boundary checks:
        #expect(decoder.decode(word: 0x5280_001F, at: pc).formattedDisassembly == "mov wzr, #0x0")
        #expect(decoder.decode(word: 0x1280_001F, at: pc).formattedDisassembly == "mov wzr, #-0x1")
        #expect(decoder.decode(word: 0x129F_FFFF, at: pc).formattedDisassembly == "movn wzr, #0xffff")
        #expect(decoder.decode(word: 0x929F_FFFF, at: pc).formattedDisassembly == "mov xzr, #-0x10000")

        // Verify caller invariant: A64IdiomRecognizer still resolves MOVZ/MOVN + MOVK 64-bit chains via structured .movz/.movn:
        let chainProg = try assembler.assembleProgram("""
            movz x0, #0xcdef
            movk x0, #0x89ab, lsl #16
            movk x0, #0x4567, lsl #32
            movk x0, #0x0123, lsl #48
        """, baseAddress: pc)
        #expect(chainProg.instructions[0].mnemonic == .movz)
        #expect(chainProg.instructions[0].mnemonicText == "mov")
        let resolvedChain = idiomRecognizer.resolveMovWideChain(chainProg.instructions)
        #expect(resolvedChain == 0x0123_4567_89AB_CDEF)
    }

    @Test("Stage 6 Rule 2: 0x0000xxxx decodes as udf #imm16 while keeping sequential flow, assembler round-trip, and CFG invariants")
    func udfImmediateDecodingAssemblerRoundTripAndHypothesis6() throws {
        let pc = VirtualAddress(0x1_0000_1000)
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("udf"), encoding: .utf8)

        var rowCount = 0
        var udfCount = 0
        var longCount = 0

        for line in rawText.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("#") { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let parts = line.split(separator: "\t", maxSplits: 2)
            let wordHex = parts[0].hasPrefix("0x") ? parts[0].dropFirst(2) : parts[0][...]
            let word = try #require(UInt32(wordHex, radix: 16))
            let expectedMnem = String(parts[1])
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == "udf" {
                udfCount += 1
                #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
                #expect(decoded.mnemonicText == "udf", "word=0x\(String(word, radix: 16))")
                #expect(decoded.flow == .sequential, "word=0x\(String(word, radix: 16))")
                #expect(decoded.readsRegisters.isEmpty, "word=0x\(String(word, radix: 16))")
                #expect(decoded.writesRegisters.isEmpty, "word=0x\(String(word, radix: 16))")
                #expect(decoded.formattedDisassembly == "udf \(expectedOps)", "word=0x\(String(word, radix: 16))")
                let reencoded = try assembler.assembleSingle(decoded.formattedDisassembly, at: pc)
                #expect(reencoded == word, "UDF round-trip mismatch for 0x\(String(word, radix: 16))")
            } else {
                longCount += 1
                #expect(expectedMnem == ".long")
                #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
                #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
                #expect(decoded.formattedDisassembly == String(format: ".inst 0x%08x", word))
            }
        }

        #expect(rowCount == 1083)
        #expect(udfCount == 1035)
        #expect(longCount == 48)

        // Decimal immediate convenience and strict 16-bit unsigned range enforcement in A64MiniAssembler:
        #expect(try assembler.assembleSingle("udf #0", at: pc) == 0x0000_0000)
        #expect(try assembler.assembleSingle("udf #12", at: pc) == 0x0000_000C)
        #expect(try assembler.assembleSingle("udf #65535", at: pc) == 0x0000_FFFF)
        #expect(throws: MachGraphError.self) { _ = try assembler.assembleSingle("udf", at: pc) }
        #expect(throws: MachGraphError.self) { _ = try assembler.assembleSingle("udf #-1", at: pc) }
        #expect(throws: MachGraphError.self) { _ = try assembler.assembleSingle("udf #0x10000", at: pc) }
        #expect(throws: MachGraphError.self) { _ = try assembler.assembleSingle("udf x0", at: pc) }

        // Hypothesis 6 check: 0x0000xxxx keeps sequential flow, pure 0x00000000 alignment padding is still pruned,
        // and jump-table recovery is completely unaffected.
        let insnsWithTrailingZeroPadding: [A64DecodedInstruction] = [
            decoder.decode(word: 0x5280_0540, at: pc),                  // mov w0, #0x2a
            decoder.decode(word: 0x0000_DEAD, at: pc.adding(UInt64(4))), // udf #0xdead (sequential inside block)
            decoder.decode(word: 0xD65F_03C0, at: pc.adding(UInt64(8))), // ret
            decoder.decode(word: 0x0000_0000, at: pc.adding(UInt64(12))), // udf #0x0 (trailing alignment padding)
            decoder.decode(word: 0x0000_0000, at: pc.adding(UInt64(16))), // udf #0x0 (trailing alignment padding)
        ]
        let cfg = CFGBuilderEngine().buildCFG(
            functionAddress: pc,
            name: "_udf_padding_probe",
            instructions: insnsWithTrailingZeroPadding
        )
        #expect(cfg.blocks.count == 1)
        #expect(cfg.blocks[0].instructions.count == 3)
        #expect(cfg.blocks[0].instructions[1].formattedDisassembly == "udf #0xdead")
    }
}
