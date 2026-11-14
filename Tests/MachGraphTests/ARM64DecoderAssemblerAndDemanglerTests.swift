import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

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
}
