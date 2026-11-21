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

    @Test("G25: A64IdiomRecognizer does not default adrp+add to STRING_REF and honors optional addressXrefClassifier")
    func idiomRecognizerAdrpAddG25Classification() throws {
        let program = try assembler.assembleProgram("""
            adrp x0, 0x100001000
            add x0, x0, #0x80
            adrp x1, 0x100008000
            add x1, x1, #0x10
            adrp x2, 0x100003000
            add x2, x2, #0x40
        """, baseAddress: VirtualAddress(0x1_0000_1200))

        let unclassified = idiomRecognizer.recognizeIdioms(in: program.instructions)
        #expect(unclassified.count == 3)
        for idiom in unclassified where idiom.kind == .adrpAddAddress {
            #expect(idiom.xrefKind != .stringReference)
            #expect(idiom.xrefKind == .dataPointerRead)
        }

        let classified = idiomRecognizer.recognizeIdioms(
            in: program.instructions,
            addressXrefClassifier: { addr in
                switch addr {
                case VirtualAddress(0x1_0000_1080): return .codeReference
                case VirtualAddress(0x1_0000_3040): return .stringReference
                default: return .dataPointerRead
                }
            }
        )
        #expect(classified.map(\.xrefKind) == [.codeReference, .dataPointerRead, .stringReference])
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

    @Test("Stage 7 Group 1: AdvSIMD vector three-register same (integer, bitwise, FP32/FP64, FP16, FHM, RDMA, FCMA) matches advsimd_vec_three_same.tsv")
    func advsimdVectorThreeSameDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        // Concrete table & corpus examples across sub-families:
        let sampleCases: [(UInt32, String)] = [
            (0x4EE0_8420, "add v0.2d, v1.2d, v0.2d"),          // /bin/csh baseline example
            (0x4EA3_8441, "add v1.4s, v2.4s, v3.4s"),          // advsimd_vec_three_same.tsv
            (0x6EE3_8441, "sub v1.2d, v2.2d, v3.2d"),          // advsimd_vec_three_same.tsv
            (0x4EA3_9C41, "mul v1.4s, v2.4s, v3.4s"),          // advsimd_vec_three_same.tsv
            (0x2E23_9C41, "pmul v1.8b, v2.8b, v3.8b"),         // 8b/16b-only PMUL
            (0x4E63_1C41, "bic v1.16b, v2.16b, v3.16b"),       // bitwise BIC
            (0x4EE2_1C41, "orn v1.16b, v2.16b, v2.16b"),       // Rm==Rn stays ORN (no MOV/MVN alias)
            (0x6E62_1C41, "bsl v1.16b, v2.16b, v2.16b"),       // Rm==Rn stays BSL
            (0x4EA2_1C41, "mov v1.16b, v2.16b"),               // ORR Rm==Rn -> MOV preferred alias
            (0x4EA3_1C41, "orr v1.16b, v2.16b, v3.16b"),       // ORR Rm!=Rn -> stays ORR
            (0x4E63_D441, "fadd v1.2d, v2.2d, v3.2d"),         // FP64 three-same
            (0x6E23_FC41, "fdiv v1.4s, v2.4s, v3.4s"),         // FP32 three-same
            (0x4E43_1441, "fadd v1.8h, v2.8h, v3.8h"),         // FP16 three-same
            (0x0E23_EC41, "fmlal v1.2s, v2.2h, v3.2h"),        // FEAT_FHM Q=0
            (0x6EA3_CC41, "fmlsl2 v1.4s, v2.4h, v3.4h"),       // FEAT_FHM Q=1
            (0x6E83_8441, "sqrdmlah v1.4s, v2.4s, v3.4s"),     // FEAT_RDM
            (0x6EC3_CC41, "fcmla v1.2d, v2.2d, v3.2d, #90"),   // FEAT_FCMA complex MLA
            (0x2E83_F441, "fcadd v1.2s, v2.2s, v3.2s, #270"),  // FEAT_FCMA complex ADD
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples from advsimd_vec_three_same.tsv must stay .inst:
        let unallocatedCases: [UInt32] = [
            0x0EE3_8441, // Q=0, size=11 integer ADD (no .1d vector ADD)
            0x2E63_9C41, // PMUL with size=01 (only size=00 allowed)
            0x2E23_BC41, // U=1 ADDP slot (unallocated)
            0x0E63_D441, // Q=0 FP64 FADD (no .1d vector FADD)
            0x2EC3_C441, // Q=0 size=11 FCMLA (no .1d complex pair)
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        // Exhaustive check against all 880 rows in Fixtures/a64/advsimd_vec_three_same.tsv:
        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_vec_three_same"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 880)
        #expect(mismatches.isEmpty, "Group 1 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 7 Group 14: AdvSIMD scalar three-register same (integer, saturating/shift, FP32/FP64, FP16, RDMA) matches advsimd_scalar_three_same.tsv")
    func advsimdScalarThreeSameDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x7EA1_D400, "fabd s0, s0, s1"),       // /usr/bin/afida baseline example
            (0x5EE3_8441, "add d1, d2, d3"),        // 64-bit scalar ADD
            (0x7EE3_8441, "sub d1, d2, d3"),        // 64-bit scalar SUB
            (0x5EE3_3441, "cmgt d1, d2, d3"),       // 64-bit scalar CMGT
            (0x7EE3_3441, "cmhi d1, d2, d3"),       // 64-bit scalar CMHI
            (0x5E23_0C41, "sqadd b1, b2, b3"),      // 8-bit saturating SQADD
            (0x7EE6_4E76, "uqshl d22, d19, d6"),    // seed 20261117 example
            (0x5E63_B441, "sqdmulh h1, h2, h3"),    // 16-bit SQDMULH
            (0x7EA3_B441, "sqrdmulh s1, s2, s3"),   // 32-bit SQRDMULH
            (0x5E63_DC41, "fmulx d1, d2, d3"),      // FP64 scalar FMULX
            (0x5ECC_3E6A, "frsqrts h10, h19, h12"), // seed 17 FP16 scalar FRSQRTS
            (0x7EC3_1441, "fabd h1, h2, h3"),       // FP16 scalar FABD
            (0x7E43_8441, "sqrdmlah h1, h2, h3"),   // FEAT_RDM 16-bit scalar SQRDMLAH
            (0x7E83_8C41, "sqrdmlsh s1, s2, s3"),   // FEAT_RDM 32-bit scalar SQRDMLSH
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples from advsimd_scalar_three_same.tsv must stay .inst:
        let unallocatedCases: [UInt32] = [
            0x5EA3_8441, // scalar ADD with size=10 (only size=11 D-reg allowed)
            0x5E23_B441, // scalar SQDMULH with size=00 (only size in {01, 10} allowed)
            0x5E23_D441, // scalar FADD in AdvSIMD scalar space (uses 0x1e202800 Scalar FP instead)
            0x7EE3_8441 ^ (1 << 30), // bit[30]==0 is Scalar FP space, not AdvSIMD scalar
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_scalar_three_same"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 480)
        #expect(mismatches.isEmpty, "Group 14 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 7 Group 29: AdvSIMD dot product (SDOT / UDOT) matches advsimd_dot_product.tsv")
    func advsimdDotProductDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x0E83_9441, "sdot v1.2s, v2.8b, v3.8b"),     // advsimd_dot_product.tsv Q=0 U=0
            (0x2E83_9441, "udot v1.2s, v2.8b, v3.8b"),     // advsimd_dot_product.tsv Q=0 U=1
            (0x4E83_9441, "sdot v1.4s, v2.16b, v3.16b"),   // advsimd_dot_product.tsv Q=1 U=0
            (0x6E83_9441, "udot v1.4s, v2.16b, v3.16b"),   // advsimd_dot_product.tsv Q=1 U=1
            (0x6E81_9440, "udot v0.4s, v2.16b, v1.16b"),   // /usr/bin/file baseline example
            (0x0E84_942C, "sdot v12.2s, v1.8b, v4.8b"),    // seed 17 example
            (0x6E94_978B, "udot v11.4s, v28.16b, v20.16b"), // seed 20261117 example
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters.count == 3, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated sibling sizes/opcodes (FEAT_I8MM / FEAT_BF16 on apple-m1) must remain .inst:
        let unallocatedCases: [UInt32] = [
            0x0E03_9441, // opcode=18 with size=00
            0x0E43_9441, // opcode=18 with size=01
            0x0EC3_9441, // opcode=18 with size=11
            0x4E83_9C41, // USDOT (FEAT_I8MM)
            0x6E43_9C41, // BFDOT (FEAT_BF16)
            0x4E83_A441, // SMMLA (FEAT_I8MM)
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_dot_product"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 96)
        #expect(mismatches.isEmpty, "Group 29 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 8 Group 2: AdvSIMD scalar two-register misc (integer, zero-compare, narrowing, FP32/FP64/FP16 conversions & estimates) matches advsimd_scalar_two_reg_misc.tsv")
    func advsimdScalarTwoRegMiscDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register])] = [
            (0x5E61_D800, "scvtf d0, d0", [.d(0)]),             // /bin/cp baseline example
            (0x7E21_D841, "ucvtf s1, s2", [.s(2)]),             // advsimd_scalar_two_reg_misc.tsv
            (0x5EA1_B841, "fcvtzs s1, s2", [.s(2)]),            // advsimd_scalar_two_reg_misc.tsv
            (0x7EE1_B841, "fcvtzu d1, d2", [.d(2)]),            // advsimd_scalar_two_reg_misc.tsv
            (0x7EA1_A9ED, "fcvtpu s13, s15", [.s(15)]),         // seed 20261117 example
            (0x5EF8_EAC7, "fcmlt h7, h22, #0.0", [.h(22)]),     // seed 17 FP16 zero-compare example
            (0x5E20_3841, "suqadd b1, b2", [.b(1), .b(2)]),     // saturating accumulate reads Rd + Rn
            (0x7EE0_3841, "usqadd d1, d2", [.d(1), .d(2)]),     // saturating accumulate reads Rd + Rn
            (0x5E60_7841, "sqabs h1, h2", [.h(2)]),             // 16-bit scalar SQABS
            (0x7EA0_7841, "sqneg s1, s2", [.s(2)]),             // 32-bit scalar SQNEG
            (0x5EE0_8841, "cmgt d1, d2, #0", [.d(2)]),          // 64-bit integer zero-compare
            (0x7EE0_9841, "cmle d1, d2, #0", [.d(2)]),          // 64-bit integer zero-compare
            (0x5EE0_B841, "abs d1, d2", [.d(2)]),               // 64-bit scalar ABS
            (0x7EE0_B841, "neg d1, d2", [.d(2)]),               // 64-bit scalar NEG
            (0x5EE0_D841, "fcmeq d1, d2, #0.0", [.d(2)]),       // FP64 scalar zero-compare
            (0x7E21_2841, "sqxtun b1, h2", [.h(2)]),            // narrowing H -> B
            (0x5EA1_4841, "sqxtn s1, d2", [.d(2)]),             // narrowing D -> S
            (0x7E61_4841, "uqxtn h1, s2", [.s(2)]),             // narrowing S -> H
            (0x7E61_6841, "fcvtxn s1, d2", [.d(2)]),            // round-to-odd FP64 -> FP32
            (0x5EA1_F841, "frecpx s1, s2", [.s(2)]),            // scalar-only FRECPX
            (0x7EF9_D841, "frsqrte h1, h2", [.h(2)]),           // FP16 scalar FRSQRTE
            (0x7E79_D841, "ucvtf h1, h2", [.h(2)]),             // FP16 scalar UCVTF
        ]
        for (word, expected, expectedReads) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples from advsimd_scalar_two_reg_misc.tsv must remain .inst:
        let unallocatedCases: [UInt32] = [
            0x5E20_0841, // no scalar REV64
            0x5EA0_8841, // scalar CMGT #0 only valid for size=11 (D)
            0x7EE0_A841, // U=1 slot of CMLT #0 is unallocated
            0x7EE0_E841, // U=1 slot of FCMLT #0.0 is unallocated
            0x5EE0_F841, // scalar FABS uses Scalar FP space (0x1e20c000), not AdvSIMD scalar
            0x5E21_2841, // no scalar XTN (U=0 opcode=10010)
            0x7E21_6841, // scalar FCVTXN only valid for size=01 (D -> S)
            0x5E39_D841, // FP16 subtable with bit[22]==0 (size=00) is unallocated
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_scalar_two_reg_misc"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 512)
        #expect(mismatches.isEmpty, "Group 2 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 8 Group 4: AdvSIMD vector two-register misc (rev/cnt/mvn/rbit, pairwise-long, zero-compare, narrowing/widening, FP32/FP64/FP16 & FRINTTS) matches advsimd_vec_two_reg_misc.tsv")
    func advsimdVectorTwoRegMiscDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x0EA0_0800, "rev64 v0.2s, v0.2s"),                // /bin/csh baseline example
            (0x6E20_0841, "rev32 v1.16b, v2.16b"),              // advsimd_vec_two_reg_misc.tsv
            (0x4E20_1841, "rev16 v1.16b, v2.16b"),              // advsimd_vec_two_reg_misc.tsv
            (0x4E20_5841, "cnt v1.16b, v2.16b"),                // CNT .16b
            (0x6E20_5841, "mvn v1.16b, v2.16b"),                // NOT preferred alias MVN
            (0x2E60_5841, "rbit v1.8b, v2.8b"),                 // RBIT (size=01 uses .8b/.16b!)
            (0x6E60_5841, "rbit v1.16b, v2.16b"),               // RBIT Q=1
            (0x0EA0_2841, "saddlp v1.1d, v2.2s"),               // SADDLP Q=0 size=10 -> .1d
            (0x0E20_6AB1, "sadalp v17.4h, v21.8b"),             // seed 20261117 example
            (0x4EE0_8841, "cmgt v1.2d, v2.2d, #0"),             // integer zero-compare .2d
            (0x4EE0_9841, "cmeq v1.2d, v2.2d, #0"),             // existing CMEQ #0 preserved
            (0x6EE0_B841, "neg v1.2d, v2.2d"),                  // 64-bit lane NEG
            (0x0E61_2841, "xtn v1.4h, v2.4s"),                  // XTN Q=0
            (0x4E61_2841, "xtn2 v1.8h, v2.4s"),                 // XTN2 Q=1
            (0x2E21_3841, "shll v1.8h, v2.8b, #8"),             // SHLL #8
            (0x6EA1_3841, "shll2 v1.2d, v2.4s, #32"),           // SHLL2 #32 (decimal shift)
            (0x0E21_7841, "fcvtl v1.4s, v2.4h"),                // FCVTL Q=0
            (0x4E61_7841, "fcvtl2 v1.2d, v2.4s"),               // FCVTL2 Q=1
            (0x2E61_6841, "fcvtxn v1.2s, v2.2d"),               // FCVTXN Q=0
            (0x6E61_6841, "fcvtxn2 v1.4s, v2.2d"),              // FCVTXN2 Q=1
            (0x6E21_9A6F, "frintx v15.4s, v19.4s"),             // seed 17 example
            (0x4E21_E841, "frint32z v1.4s, v2.4s"),             // FEAT_FRINTTS FRINT32Z
            (0x6E61_F841, "frint64x v1.2d, v2.2d"),             // FEAT_FRINTTS FRINT64X
            (0x4EA1_C841, "urecpe v1.4s, v2.4s"),               // URECPE (.2s/.4s only)
            (0x6EE1_F841, "fsqrt v1.2d, v2.2d"),                // FSQRT .2d
            (0x4EF8_C841, "fcmgt v1.8h, v2.8h, #0.0"),          // FP16 zero-compare
            (0x6EF9_F841, "fsqrt v1.8h, v2.8h"),                // FP16 FSQRT
            (0x6E79_D841, "ucvtf v1.8h, v2.8h"),                // FP16 UCVTF
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Accumulating & upper-half narrowing (*2) forms read destination Vd as well as source Vn:
        #expect(decoder.decode(word: 0x0E20_6841, at: pc).readsRegisters.count == 2) // sadalp v1.4h, v2.8b
        #expect(decoder.decode(word: 0x4E61_2841, at: pc).readsRegisters.count == 2) // xtn2 v1.8h, v2.4s
        #expect(decoder.decode(word: 0x0E61_2841, at: pc).readsRegisters.count == 1) // xtn v1.4h, v2.4s

        // Unallocated counterexamples from advsimd_vec_two_reg_misc.tsv must remain .inst:
        let unallocatedCases: [UInt32] = [
            0x0EE0_0841, // REV64 with size=11 is unallocated
            0x2EA0_0841, // REV32 with size=10 is unallocated
            0x0E60_1841, // REV16 with size=01 is unallocated
            0x4EE0_4841, // CLS with size=11 (.2d) is unallocated
            0x0EE0_9841, // CMEQ #0 with Q=0, size=11 (.1d) is unallocated
            0x2E21_6841, // FCVTXN with size=00 is unallocated (only size=01 D->S exists)
            0x4EE1_C841, // URECPE with size=11 (.2d) is unallocated
            0x4EE1_F841, // U=0, szHi=1 opcode=11111 has no vector FRECPX
            0x0E39_D841, // FP16 subtable with bit[22]==0 (size=00) is unallocated
            0x4E79_E841, // FP16 subtable has no FRINT32Z
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_vec_two_reg_misc"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 1024)
        #expect(mismatches.isEmpty, "Group 4 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 9 Group 3: AdvSIMD vector shift by immediate (same-width shifts/inserts, narrowing, widening sshll/ushll, and fixed-point FP32/FP64/FP16) matches all 4 advsimd_vec_shift_imm slices")
    func advsimdVectorShiftByImmediateDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, Int)] = [
            (0x2F20_A442, "ushll v2.2d, v2.2s, #0x0", 1),          // /bin/csh baseline example (kept as ushll #0x0, not uxtl)
            (0x0F08_A441, "sshll v1.8h, v2.8b, #0x0", 1),          // sshll #0x0 kept as sshll
            (0x6F3F_A441, "ushll2 v1.2d, v2.4s, #0x1f", 1),        // ushll2 Q=1
            (0x4F08_A441, "sshll2 v1.8h, v2.16b, #0x0", 1),        // sshll2 Q=1
            (0x0F08_0441, "sshr v1.8b, v2.8b, #0x8", 1),           // right shift max for 8-bit
            (0x6F7F_0441, "ushr v1.2d, v2.2d, #0x1", 1),           // right shift min for 64-bit
            (0x0F08_1441, "ssra v1.8b, v2.8b, #0x8", 2),           // accumulating right shift reads [vd, vn]
            (0x6F7F_3441, "ursra v1.2d, v2.2d, #0x1", 2),          // rounding accumulating right shift reads [vd, vn]
            (0x4F0B_25E6, "srshr v6.16b, v15.16b, #0x5", 1),       // seed 20261117 example
            (0x2F08_4441, "sri v1.8b, v2.8b, #0x8", 2),            // shift right and insert reads [vd, vn]
            (0x0F08_5441, "shl v1.8b, v2.8b, #0x0", 1),            // left shift #0x0
            (0x6F7F_5441, "sli v1.2d, v2.2d, #0x3f", 2),           // shift left and insert reads [vd, vn]
            (0x6F7F_6441, "sqshlu v1.2d, v2.2d, #0x3f", 1),        // saturating shift left unsigned
            (0x4F7F_7441, "sqshl v1.2d, v2.2d, #0x3f", 1),         // saturating shift left signed
            (0x0F08_8441, "shrn v1.8b, v2.8h, #0x8", 1),           // narrowing Q=0 reads [vn]
            (0x4F3F_8441, "shrn2 v1.4s, v2.2d, #0x1", 2),          // upper-half narrowing Q=1 reads [vd, vn]
            (0x6F0E_9E6A, "uqrshrn2 v10.16b, v19.8h, #0x2", 2),    // seed 17 example
            (0x2F08_8C41, "sqrshrun v1.8b, v2.8h, #0x8", 1),       // saturating rounding shift right unsigned narrow
            (0x0F10_E441, "scvtf v1.4h, v2.4h, #0x10", 1),         // FP16 vector fixed-point SCVTF
            (0x6F7F_E441, "ucvtf v1.2d, v2.2d, #0x1", 1),          // FP64 vector fixed-point UCVTF
            (0x0F20_FC41, "fcvtzs v1.2s, v2.2s, #0x20", 1),        // FP32 vector fixed-point FCVTZS
            (0x6F7F_FC41, "fcvtzu v1.2d, v2.2d, #0x1", 1),         // FP64 vector fixed-point FCVTZU
        ]
        for (word, expected, expectedReadCount) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters.count == expectedReadCount, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated & sibling-group boundary counterexamples must remain .inst:
        let unallocatedOrOtherGroupCases: [UInt32] = [
            0x0F40_0441, // Q=0 with immh>=8 (no .1d vector SSHR)
            0x4F40_8441, // SHRN2 with immh>=8 (no 128->64 narrowing)
            0x4F40_A441, // SSHLL2 with immh>=8 (no 64->128 widening)
            0x0F08_4441, // U=0 slot of SRI (opcode=01000) is unallocated
            0x0F08_6441, // U=0 slot of SQSHLU (opcode=01100) is unallocated
            0x0F08_E441, // vector fixed-point SCVTF with immh=1 (8-bit) is unallocated
            0x0F40_1041, // bit[23]==0, bit[10]==0 is Group 13 indexed element (not shift by immediate)
            0x0F01_CFE1, // immh==0, o2==1 is unallocated in Group 11 modified immediate (not Group 3)
        ]
        for word in unallocatedOrOtherGroupCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }
        // immh==0 allocated encoding routes to Group 11 modified immediate (MOVI msl #8), never Group 3:
        let group11Boundary = decoder.decode(word: 0x0F01_C7E1, at: pc)
        #expect(group11Boundary.mnemonic == .movi)
        #expect(group11Boundary.formattedDisassembly == "movi v1.2s, #0x3f, msl #8")

        let slices = [
            "advsimd_vec_shift_imm_q0_u0",
            "advsimd_vec_shift_imm_q0_u1",
            "advsimd_vec_shift_imm_q1_u0",
            "advsimd_vec_shift_imm_q1_u1",
        ]
        var totalRows = 0
        var mismatches: [String] = []
        for slice in slices {
            let rawText = try String(contentsOf: RepoFixtures.a64TableURL(slice), encoding: .utf8)
            var sliceRows = 0
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
                sliceRows += 1
                totalRows += 1

                if expectedMnem == ".long" {
                    if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected .inst got '%@'", slice, word, decoded.formattedDisassembly))
                        }
                    }
                } else {
                    let expectedText = "\(expectedMnem) \(expectedOps)"
                    if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected '%@' got '%@'", slice, word, expectedText, decoded.formattedDisassembly))
                        }
                    }
                }
            }
            #expect(sliceRows == 3840)
        }
        #expect(totalRows == 15360)
        #expect(mismatches.isEmpty, "Group 3 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 9 Group 30: AdvSIMD scalar shift by immediate (64-bit D shifts/inserts, B/H/S/D saturating shifts, narrowing, and fixed-point H/S/D) matches both advsimd_scalar_shift_imm slices")
    func advsimdScalarShiftByImmediateDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, Int)] = [
            (0x5F64_54A6, "shl d6, d5, #0x24", 1),          // /usr/bin/afscexpand baseline example
            (0x5F48_07BC, "sshr d28, d29, #0x38", 1),       // seed 17 example
            (0x7F7F_0441, "ushr d1, d2, #0x1", 1),          // 64-bit scalar USHR
            (0x5F7E_1438, "ssra d24, d1, #0x2", 2),         // seed 20261117 example (accumulating reads [sd, sn])
            (0x7F40_3441, "ursra d1, d2, #0x40", 2),        // 64-bit scalar URSRA reads [sd, sn]
            (0x7F40_4441, "sri d1, d2, #0x40", 2),          // 64-bit scalar SRI reads [sd, sn]
            (0x7F7F_5441, "sli d1, d2, #0x3f", 2),          // 64-bit scalar SLI reads [sd, sn]
            (0x7F08_6441, "sqshlu b1, b2, #0x0", 1),        // 8-bit scalar SQSHLU
            (0x5F11_7441, "sqshl h1, h2, #0x1", 1),         // 16-bit scalar SQSHL
            (0x7F3F_7441, "uqshl s1, s2, #0x1f", 1),        // 32-bit scalar UQSHL
            (0x7F08_8441, "sqshrun b1, h2, #0x8", 1),       // scalar narrowing H -> B
            (0x7F10_8C41, "sqrshrun h1, s2, #0x10", 1),     // scalar narrowing S -> H
            (0x5F3F_9441, "sqshrn s1, d2, #0x1", 1),        // scalar narrowing D -> S
            (0x7F3F_9C41, "uqrshrn s1, d2, #0x1", 1),       // scalar narrowing D -> S
            (0x5F10_E441, "scvtf h1, h2, #0x10", 1),        // FP16 scalar fixed-point SCVTF
            (0x7F20_E441, "ucvtf s1, s2, #0x20", 1),        // FP32 scalar fixed-point UCVTF
            (0x5F40_FC41, "fcvtzs d1, d2, #0x40", 1),       // FP64 scalar fixed-point FCVTZS
            (0x7F7F_FC41, "fcvtzu d1, d2, #0x1", 1),        // FP64 scalar fixed-point FCVTZU
        ]
        for (word, expected, expectedReadCount) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters.count == expectedReadCount, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated & sibling-group boundary counterexamples must remain .inst:
        let unallocatedOrOtherGroupCases: [UInt32] = [
            0x5F00_0441, // immh == 0 is unallocated in AdvSIMD scalar shift space
            0x5F20_5441, // scalar SHL only valid for 64-bit D (immh >= 8), not 32-bit S
            0x5F08_8441, // no non-saturating scalar SHRN (opcode=10000, U=0)
            0x5F08_8C41, // no non-saturating scalar RSHRN (opcode=10001, U=0)
            0x5F08_A441, // no scalar SSHLL / USHLL widening in Group 30
            0x5F08_E441, // scalar fixed-point SCVTF with immh=1 (8-bit) is unallocated
            0x5F43_1041, // bit[23]==0, bit[10]==0 unallocated slot in Group 26 scalar indexed element (not Group 30)
        ]
        for word in unallocatedOrOtherGroupCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }
        // bit[23]==0, bit[10]==0 allocated encoding routes to Group 26 scalar indexed element (SQRDMULH), never Group 30:
        let group26Boundary = decoder.decode(word: 0x5F49_D380, at: pc)
        #expect(group26Boundary.mnemonic != .unknown)
        #expect(group26Boundary.formattedDisassembly == "sqrdmulh h0, h28, v9.h[0]")

        let slices = ["advsimd_scalar_shift_imm_u0", "advsimd_scalar_shift_imm_u1"]
        var totalRows = 0
        var mismatches: [String] = []
        for slice in slices {
            let rawText = try String(contentsOf: RepoFixtures.a64TableURL(slice), encoding: .utf8)
            var sliceRows = 0
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
                sliceRows += 1
                totalRows += 1

                if expectedMnem == ".long" {
                    if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected .inst got '%@'", slice, word, decoded.formattedDisassembly))
                        }
                    }
                } else {
                    let expectedText = "\(expectedMnem) \(expectedOps)"
                    if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected '%@' got '%@'", slice, word, expectedText, decoded.formattedDisassembly))
                        }
                    }
                }
            }
            #expect(sliceRows == 4096)
        }
        #expect(totalRows == 8192)
        #expect(mismatches.isEmpty, "Group 30 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 9 Group 12: Scalar FP <-> fixed-point conversions (SCVTF, UCVTF, FCVTZS, FCVTZU with #fbits across S/D/H and W/X/ZR) match scalar_fp_fixed_point.tsv")
    func scalarFPFixedPointConversionsDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x1E02_C000, "scvtf s0, w0, #0x10", [.w(0)], [.s(0)]),     // /usr/bin/IOMFBDiagnose baseline example
            (0x1E18_82BA, "fcvtzs w26, s21, #0x20", [.s(21)], [.w(26)]), // seed 20261117 example
            (0x9E19_7DCA, "fcvtzu x10, s14, #0x21", [.s(14)], [.x(10)]), // seed 17 example (sf=1 scale=31 -> #0x21)
            (0x9E42_0041, "scvtf d1, x2, #0x40", [.x(2)], [.d(1)]),      // sf=1 scale=0 -> #0x40
            (0x9EC3_FC41, "ucvtf h1, x2, #0x1", [.x(2)], [.h(1)]),       // FP16 H target, scale=63 -> #0x1
            (0x1ED8_8041, "fcvtzs w1, h2, #0x20", [.h(2)], [.w(1)]),     // FP16 H source, sf=0 max #fbits=32
            (0x1E03_83E1, "ucvtf s1, wzr, #0x20", [], [.s(1)]),          // Rn=31 is wzr (readsRegisters omits ZR)
            (0x9E59_805F, "fcvtzu xzr, d2, #0x20", [.d(2)], []),         // Rd=31 is xzr (writesRegisters omits ZR)
            (0x9E18_83E1, "fcvtzs x1, s31, #0x20", [.s(31)], [.x(1)]),   // FP Rn=31 stays s31
            (0x9E42_805F, "scvtf d31, x2, #0x20", [.x(2)], [.d(31)]),    // FP Rd=31 stays d31
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples from scalar_fp_fixed_point.tsv must remain .inst:
        let unallocatedCases: [UInt32] = [
            0x1E02_7C41, // sf=0 with scale=31 (#fbits=33 > 32) is unallocated
            0x1E02_0041, // sf=0 with scale=0 (#fbits=64 > 32) is unallocated
            0x3E02_8041, // S=1 (bit[29]==1) is unallocated
            0x1E82_8041, // ftype=10 is unallocated
            0x1E04_8041, // rmode=00 opcode=100 (no fixed-point FCVTAS) is unallocated
            0x1E00_8041, // rmode=00 opcode=000 (no fixed-point FCVTNS) is unallocated
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("scalar_fp_fixed_point"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 3776)
        #expect(mismatches.isEmpty, "Group 12 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 5: PAC data/instruction pointer 1-source operations (PACDZA/PACDZB/AUTDZA/AUTDZB, PACI*/AUTI*/XPAC*, two-operand PAC/AUT, and 1-source GP) match pac_data_ptr.tsv")
    func pacDataPointer1SourceDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0xDAC1_3BF0, "autdza x16", [.x(16)], [.x(16)]),       // /usr/bin/IOAccelMemory baseline example
            (0xDAC1_2BE1, "pacdza x1", [.x(1)], [.x(1)]),          // pac_data_ptr.tsv Rd=1
            (0xDAC1_2FE1, "pacdzb x1", [.x(1)], [.x(1)]),          // pac_data_ptr.tsv Rd=1
            (0xDAC1_3BE1, "autdza x1", [.x(1)], [.x(1)]),          // pac_data_ptr.tsv Rd=1
            (0xDAC1_3FE1, "autdzb x1", [.x(1)], [.x(1)]),          // pac_data_ptr.tsv Rd=1
            (0xDAC1_2BFF, "pacdza xzr", [], []),                   // Rd=31 is xzr
            (0xDAC1_3BFF, "autdza xzr", [], []),                   // Rd=31 is xzr
            (0xDAC1_23E1, "paciza x1", [.x(1)], [.x(1)]),          // existing PACIZA preserved
            (0xDAC1_47E1, "xpacd x1", [.x(1)], [.x(1)]),           // existing XPACD preserved
            (0xDAC1_0BE1, "pacda x1, sp", [.x(1), .sp], [.x(1)]),  // two-operand PACDA with SP modifier
            (0xDAC1_1841, "autda x1, x2", [.x(1), .x(2)], [.x(1)]),// two-operand AUTDA with Xn modifier
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples from pac_data_ptr.tsv must remain .inst:
        let unallocatedCases: [UInt32] = [
            0xDAC1_2841, // PACDZA opcode with Rn=2 (!= 31) is unallocated
            0xDAC1_3841, // AUTDZA opcode with Rn=2 (!= 31) is unallocated
            0x5AC1_2BE1, // sf=0 (32-bit) PACDZA slot is unallocated
            0xFAC1_2BE1, // S=1 (bit[29]==1) is unallocated
            0xDAC1_4BE1, // opcode=010010 (>= 18) is unallocated on apple-m1
            0xDAC2_2BE1, // opcode2=00010 is unallocated
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("pac_data_ptr"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 3200)
        #expect(mismatches.isEmpty, "Group 5 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 16: RCpc load-acquire (LDAPRB, LDAPRH, LDAPR W/X) and LSE atomic operations match lse_atomic.tsv and rcpc_ldapr.tsv")
    func rcpcLdaprAndLseAtomicDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x38BF_C108, "ldaprb w8, [x8]", [.x(8)], [.w(8)]),     // /usr/bin/afinfo baseline example
            (0x38BF_C041, "ldaprb w1, [x2]", [.x(2)], [.w(1)]),     // lse_atomic.tsv / rcpc_ldapr.tsv
            (0x78BF_C041, "ldaprh w1, [x2]", [.x(2)], [.w(1)]),     // lse_atomic.tsv / rcpc_ldapr.tsv
            (0xB8BF_C041, "ldapr w1, [x2]", [.x(2)], [.w(1)]),      // lse_atomic.tsv / rcpc_ldapr.tsv
            (0xF8BF_C041, "ldapr x1, [x2]", [.x(2)], [.x(1)]),      // lse_atomic.tsv / rcpc_ldapr.tsv
            (0x38BF_C3E1, "ldaprb w1, [sp]", [.sp], [.w(1)]),       // Rn=31 is SP
            (0xF8BF_C3E1, "ldapr x1, [sp]", [.sp], [.x(1)]),        // Rn=31 is SP
            (0xB8BF_C05F, "ldapr wzr, [x2]", [.x(2)], []),          // Rt=31 is wzr
            (0xF8BF_C05F, "ldapr xzr, [x2]", [.x(2)], []),          // Rt=31 is xzr
            (0x78A3_6041, "ldumaxah w3, w1, [x2]", [.x(2), .w(3)], [.w(1)]), // Group 16 LSE atomic ldumaxah
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples must remain .inst:
        let unallocatedCases: [UInt32] = [
            0x38BE_C041, // Rs=30 (!= 31) in LDAPR slot is unallocated
            0x38A3_C041, // Rs=3  (!= 31) in LDAPR slot is unallocated
            0x38FF_C041, // A=1, R=1 (not R=0) with o3=1, opc=100, Rs=31 is unallocated
            0x383F_C041, // A=0, R=0 with o3=1, opc=100, Rs=31 is unallocated
            0x387F_C041, // A=0, R=1 with o3=1, opc=100, Rs=31 is unallocated
            0x38BF_D041, // opc=101 with o3=1, Rs=31 is unallocated
        ]
        for word in unallocatedCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(word, radix: 16))")
        }

        for (tableName, expectedRows) in [("lse_atomic", 1024), ("rcpc_ldapr", 512)] {
            let rawText = try String(contentsOf: RepoFixtures.a64TableURL(tableName), encoding: .utf8)
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
                let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
                let decoded = decoder.decode(word: word, at: pc)
                rowCount += 1

                if expectedMnem == ".long" {
                    if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected .inst got '%@'", tableName, word, decoded.formattedDisassembly))
                        }
                    }
                } else {
                    let expectedText = "\(expectedMnem) \(expectedOps)"
                    if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                        if mismatches.count < 12 {
                            mismatches.append(String(format: "%@ 0x%08x expected '%@' got '%@'", tableName, word, expectedText, decoded.formattedDisassembly))
                        }
                    }
                }
            }
            #expect(rowCount == expectedRows)
            #expect(mismatches.isEmpty, "Group 16 \(tableName) mismatches: \(mismatches.joined(separator: "; "))")
        }
    }

    @Test("Stage 10 Group 18: Scalar FP <-> integer conversions (FCVTN/P/M/Z/A*, SCVTF/UCVTF, FJCVTZS, FMOV GP<->FP and V.D[1]) match scalar_fp_int_conv.tsv")
    func scalarFPIntConversionsDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x9E69_0009, "fcvtpu x9, d0"),      // /usr/bin/afinfo baseline example
            (0x1EF1_035C, "fcvtmu w28, h26"),    // seed 17 fuzz example
            (0x1E20_0041, "fcvtns w1, s2"),
            (0x1E21_0041, "fcvtnu w1, s2"),
            (0x9E68_0041, "fcvtps x1, d2"),
            (0x9E70_0041, "fcvtms x1, d2"),
            (0x9EF1_0041, "fcvtmu x1, h2"),
            (0x1E7E_0041, "fjcvtzs w1, d2"),     // FEAT_JSCVT
            (0x9EAE_0041, "fmov x1, v2.d[1]"),   // high 64-bit lane to GP
            (0x9EAF_0041, "fmov v1.d[1], x2"),   // GP to high 64-bit lane
            (0x9EAF_03E1, "fmov v1.d[1], xzr"),  // XZR to high 64-bit lane
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // FJCVTZS updates NZCV flags
        let fjcvtzs = decoder.decode(word: 0x1E7E_0041, at: pc)
        #expect(fjcvtzs.writesFlags == true)

        // Mismatched-width FMOV (w <-> d, x <-> s) and sf=1 FJCVTZS must decode as .inst:
        for badWord: UInt32 in [0x1E66_0041, 0x1E67_0041, 0x9E26_0041, 0x9E27_0041, 0x9E7E_0041, 0x1EAE_0041] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("scalar_fp_int_conv"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 1536)
        #expect(mismatches.isEmpty, "Group 18 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 19: Scalar FP 1-source operations (FRINTA/X/I, FRINT32Z/X, FRINT64Z/X, and cross-width FCVT) match scalar_fp_one_source.tsv")
    func scalarFPOneSourceDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x1E66_4000, "frinta d0, d0"),      // /usr/bin/afinfo baseline example
            (0x1E27_C104, "frinti s4, s8"),      // seed 20261117 fuzz example
            (0x1E27_4041, "frintx s1, s2"),
            (0x1EE6_4041, "frinta h1, h2"),
            (0x1EE7_C041, "frinti h1, h2"),
            (0x1E28_4041, "frint32z s1, s2"),
            (0x1E28_C041, "frint32x s1, s2"),
            (0x1E69_4041, "frint64z d1, d2"),
            (0x1E69_C041, "frint64x d1, d2"),
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // Same-width FCVT (S->S, D->D, H->H) and FP16 FRINT32Z/64Z must decode as .inst:
        for badWord: UInt32 in [0x1E22_4041, 0x1E62_C041, 0x1EE3_C041, 0x1EE8_4041, 0x1EE9_4041] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("scalar_fp_one_source"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 1120)
        #expect(mismatches.isEmpty, "Group 19 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 27: Scalar FP 3-source operations (FMADD, FMSUB, FNMADD, FNMSUB across S/D/H) match scalar_fp_three_source.tsv")
    func scalarFPThreeSourceDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x1FFF_FFFF, "fnmsub h31, h31, h31, h31"), // /usr/bin/afscexpand baseline example
            (0x1F60_8020, "fnmsub d0, d1, d0, d0"),
            (0x1F6A_4DBF, "fnmadd d31, d13, d10, d19"), // seed 20261117 fuzz example
            (0x1F6B_D5A4, "fnmsub d4, d13, d11, d21"),  // seed 17 fuzz example
            (0x1F23_1041, "fnmadd s1, s2, s3, s4"),
            (0x1F23_9041, "fnmsub s1, s2, s3, s4"),
            (0x1FE3_1041, "fnmadd h1, h2, h3, h4"),
            (0x1FE3_9041, "fnmsub h1, h2, h3, h4"),
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("scalar_fp_three_source"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 128)
        #expect(mismatches.isEmpty, "Group 27 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 28: Load/store exclusive, ordered/LORegion, CAS, CASP, and G62 non-31 Rs/Rt2 match load_store_exclusive_casp.tsv")
    func loadStoreExclusiveOrderedAndCaspDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0x0807_0605, "stxrb w7, w5, [x16]"),            // /usr/bin/afscexpand G62 Rt2!=31 baseline example
            (0x4824_7D00, "casp x4, x5, x0, x1, [x8]"),      // /usr/bin/stz CASP X baseline example
            (0x4838_FD00, "caspl x24, x25, x0, x1, [x8]"),   // /usr/bin/stz CASPL X baseline example
            (0x0824_7CC2, "casp w4, w5, w2, w3, [x6]"),
            (0x0864_7CC2, "caspa w4, w5, w2, w3, [x6]"),
            (0x4864_FCC2, "caspal x4, x5, x2, x3, [x6]"),
            (0x483E_7FFE, "casp x30, xzr, x30, xzr, [sp]"),
            (0x8824_20C2, "stxp w4, w2, w8, [x6]"),
            (0xC824_A0C2, "stlxp w4, x2, x8, [x6]"),
            (0x8864_20C2, "ldxp w2, w8, [x6]"),              // G62 Rs=4 ignored
            (0xC864_A0C2, "ldaxp x2, x8, [x6]"),             // G62 Rs=4 ignored
            (0x48D2_E1DC, "ldarh w28, [x14]"),               // seed 20261117 fuzz G62 example
            (0x88D1_429E, "ldlar w30, [x20]"),               // seed 20261117 fuzz LORegion example
            (0xC884_20C2, "stllr x2, [x6]"),
            (0x08C4_20C2, "ldlarb w2, [x6]"),
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        // CASP odd Rs/Rt or Rt2!=31 and CAS Rt2!=31 must decode as .inst:
        for badWord: UInt32 in [0x0825_7CC2, 0x0824_7CC3, 0x0824_20C2, 0x88A4_20C2, 0xC8E4_A0C2] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("load_store_exclusive_casp"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 512)
        #expect(mismatches.isEmpty, "Group 28 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 10 Group 31: Barriers (SB, SSBB, PSSBB, CLREX, DSB, DMB, ISB, and S0_3_C3_* MSR fallbacks) match barriers.tsv")
    func barriersAndSbDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String)] = [
            (0xD503_30FF, "sb"),                     // /usr/libexec/DumpPanic baseline example (CRm=0)
            (0xD503_3FFF, "sb"),                     // CRm=15 SB
            (0xD503_309F, "ssbb"),                   // DSB CRm=0 alias
            (0xD503_349F, "pssbb"),                  // DSB CRm=4 alias
            (0xD503_3F9F, "dsb sy"),
            (0xD503_3BBF, "dmb ish"),
            (0xD503_3FDF, "isb"),
            (0xD503_3BDF, "isb #11"),                // ISB non-15 CRm prints #<imm>, not barrier domain
            (0xD503_3F5F, "clrex"),
            (0xD503_3A5F, "clrex #0xa"),
            (0xD503_301F, "msr S0_3_C3_C0_0, xzr"),  // op2=0 Rt=31 fallback
            (0xD503_30E1, "msr S0_3_C3_C0_7, x1"),   // op2=7 Rt=1 fallback
        ]
        for (word, expected) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("barriers"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 256)
        #expect(mismatches.isEmpty, "Group 31 table mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11a Group 6: AdvSIMD vector copy element-to-element INS (preferred alias MOV) and G52 bit[15]==0 guard match all 4,096 rows of advsimd_copy.tsv")
    func advsimdVectorCopyElementInsDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, Int)] = [
            (0x6E1C_6401, "mov v1.s[3], v0.s[3]", 2),   // /bin/ksh baseline example
            (0x6E01_0441, "mov v1.b[0], v2.b[0]", 2),   // advsimd_copy.tsv byte lane 0 <- 0
            (0x6E1F_7C41, "mov v1.b[15], v2.b[15]", 2), // advsimd_copy.tsv byte lane 15 <- 15
            (0x6E02_0C41, "mov v1.h[0], v2.h[0]", 2),   // advsimd_copy.tsv halfword ignored imm4<0>=1
            (0x6E1E_7C41, "mov v1.h[7], v2.h[7]", 2),   // advsimd_copy.tsv halfword lane 7 <- 7
            (0x6E1C_7C41, "mov v1.s[3], v2.s[3]", 2),   // advsimd_copy.tsv singleword ignored imm4<1:0>=11
            (0x6E08_4441, "mov v1.d[0], v2.d[1]", 2),   // advsimd_copy.tsv doubleword lane 0 <- 1
            (0x6E18_7C41, "mov v1.d[1], v2.d[1]", 2),   // advsimd_copy.tsv doubleword ignored imm4<2:0>=111
            (0x6E01_0C42, "mov v2.b[0], v2.b[1]", 1),   // Rd == Rn deduplicates readsRegisters to [v2]
            (0x6E18_47FF, "mov v31.d[1], v31.d[1]", 1), // high vector register v31
        ]
        for (word, expected, expectedReadCount) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters.count == expectedReadCount, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters.count == 1, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (G52 bit[15]==1, Q==0 with op==1, imm5 in {0, 16}) must remain .inst:
        for badWord: UInt32 in [0x6E01_8441, 0x6E1C_E401, 0x2E01_0441, 0x2E1C_6401, 0x6E00_0441, 0x6E10_0441] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_copy"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 4096)
        #expect(mismatches.isEmpty, "Group 6 advsimd_copy mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11a Group 15: AdvSIMD scalar copy (scalar DUP element -> MOV) matches all 2,048 rows of advsimd_scalar_copy.tsv")
    func advsimdScalarCopyDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x5E0C_044A, "mov s10, v2.s[1]", [.v(2, arrangement: "s")], [.s(10)]), // /usr/bin/IOMFBDiagnose baseline example (generic Neon syntax)
            (0x5E01_0441, "mov b1, v2.b[0]", [.v(2, arrangement: "b")], [.b(1)]),   // advsimd_scalar_copy.tsv byte lane 0
            (0x5E1F_0441, "mov b1, v2.b[15]", [.v(2, arrangement: "b")], [.b(1)]),  // advsimd_scalar_copy.tsv byte lane 15
            (0x5E02_0441, "mov h1, v2.h[0]", [.v(2, arrangement: "h")], [.h(1)]),   // advsimd_scalar_copy.tsv halfword lane 0
            (0x5E1E_0441, "mov h1, v2.h[7]", [.v(2, arrangement: "h")], [.h(1)]),   // advsimd_scalar_copy.tsv halfword lane 7
            (0x5E04_0441, "mov s1, v2.s[0]", [.v(2, arrangement: "s")], [.s(1)]),   // advsimd_scalar_copy.tsv singleword lane 0
            (0x5E1C_0441, "mov s1, v2.s[3]", [.v(2, arrangement: "s")], [.s(1)]),   // advsimd_scalar_copy.tsv singleword lane 3
            (0x5E08_0441, "mov d1, v2.d[0]", [.v(2, arrangement: "d")], [.d(1)]),   // advsimd_scalar_copy.tsv doubleword lane 0
            (0x5E18_0441, "mov d1, v2.d[1]", [.v(2, arrangement: "d")], [.d(1)]),   // advsimd_scalar_copy.tsv doubleword lane 1
            (0x5E1F_07FF, "mov b31, v31.b[15]", [.v(31, arrangement: "b")], [.b(31)]), // (Rd,Rn)=(31,31) stays b31/v31, never wzr/xzr
            (0x5E18_07FF, "mov d31, v31.d[1]", [.v(31, arrangement: "d")], [.d(31)]),  // (Rd,Rn)=(31,31) stays d31/v31
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (op==1, imm4!=0, imm5 in {0, 16}, bit[15]==1) must remain .inst:
        for badWord: UInt32 in [0x7E01_0441, 0x5E01_0C41, 0x5E00_0441, 0x5E10_0441, 0x5E01_8441, 0x5E0C_844A] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_scalar_copy"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 2048)
        #expect(mismatches.isEmpty, "Group 15 advsimd_scalar_copy mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11a Group 11: AdvSIMD modified immediate (MOVI, MVNI, ORR, BIC, FMOV vector) matches all 3,040 rows of advsimd_modified_imm.tsv")
    func advsimdModifiedImmediateDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x0F01_C7E1, "movi v1.2s, #0x3f, msl #8", [], [.v(1, arrangement: "2s")]),       // /bin/dd baseline example (msl #8)
            (0x4F07_D7E1, "movi v1.4s, #0xff, msl #16", [], [.v(1, arrangement: "4s")]),      // 32-bit MOVI msl #16
            (0x6F04_C401, "mvni v1.4s, #0x80, msl #8", [], [.v(1, arrangement: "4s")]),       // 32-bit MVNI msl #8
            (0x6F01_0634, "mvni v20.4s, #0x31", [], [.v(20, arrangement: "4s")]),             // seed 17 random fuzz example
            (0x0F00_8421, "movi v1.4h, #0x1", [], [.v(1, arrangement: "4h")]),                // 16-bit MOVI lsl #0 (#0x1 hex format)
            (0x4F07_A7E1, "movi v1.8h, #0xff, lsl #8", [], [.v(1, arrangement: "8h")]),       // 16-bit MOVI lsl #8
            (0x0F05_169B, "orr v27.2s, #0xb4", [.v(27, arrangement: "2s")], [.v(27, arrangement: "2s")]), // seed 20261117 ORR (read-modify-write)
            (0x4F00_3421, "orr v1.4s, #0x1, lsl #8", [.v(1, arrangement: "4s")], [.v(1, arrangement: "4s")]),
            (0x6F07_B7FF, "bic v31.8h, #0xff, lsl #8", [.v(31, arrangement: "8h")], [.v(31, arrangement: "8h")]),
            (0x2F00_E401, "movi d1, #0000000000000000", [], [.d(1)]),                         // 64-bit scalar D-reg zero mask
            (0x6F00_E401, "movi v1.2d, #0000000000000000", [], [.v(1, arrangement: "2d")]),   // 128-bit 2d zero mask
            (0x2F00_E421, "movi d1, #0x000000000000ff", [], [.d(1)]),                         // 64-bit mask < 2^56 (#0x + 14 hex digits)
            (0x6F04_E401, "movi v1.2d, #0xff00000000000000", [], [.v(1, arrangement: "2d")]), // 64-bit mask >= 2^56 (#0x + 16 hex digits)
            (0x2F00_E41F, "movi d31, #0000000000000000", [], [.d(31)]),                       // Rd=31 stays d31, never xzr
            (0x0F00_F401, "fmov v1.2s, #2.00000000", [], [.v(1, arrangement: "2s")]),         // FP32 2s FMOV
            (0x4F04_F401, "fmov v1.4s, #-2.00000000", [], [.v(1, arrangement: "4s")]),        // negative FP32 4s FMOV
            (0x6F02_F421, "fmov v1.2d, #0.13281250", [], [.v(1, arrangement: "2d")]),         // G47 full precision 17/128 FP64 2d FMOV
            (0x0F00_FC01, "fmov v1.4h, #2.00000000", [], [.v(1, arrangement: "4h")]),         // FP16 4h FMOV (o2=1)
            (0x4F02_FC21, "fmov v1.8h, #0.13281250", [], [.v(1, arrangement: "8h")]),         // FP16 8h FMOV (o2=1)
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (Q=0,op=1,cmode=1111,o2=0; op=1,cmode=1111,o2=1; o2=1 with cmode!=1111) must stay .inst:
        for badWord: UInt32 in [0x2F00_F401, 0x2F00_FC01, 0x6F00_FC01, 0x0F00_0C01, 0x4F00_EC01, 0x6F00_EC01] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_modified_imm"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 3040)
        #expect(mismatches.isEmpty, "Group 11 advsimd_modified_imm mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11b Group 10: AdvSIMD vector EXT (.8b / .16b) and Q=0,imm4>=8 / op2!=0 unallocated guards match all 256 rows of advsimd_ext.tsv")
    func advsimdVectorExtDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x6E02_4043, "ext v3.16b, v2.16b, v2.16b, #0x8", [.v(2, arrangement: "16b")], [.v(3, arrangement: "16b")]), // /bin/csh baseline example (Rn == Rm deduplicates readsRegisters)
            (0x2E1F_09C5, "ext v5.8b, v14.8b, v31.8b, #0x1", [.v(14, arrangement: "8b"), .v(31, arrangement: "8b")], [.v(5, arrangement: "8b")]), // seed 20261117 fuzz example
            (0x6E18_18C3, "ext v3.16b, v6.16b, v24.16b, #0x3", [.v(6, arrangement: "16b"), .v(24, arrangement: "16b")], [.v(3, arrangement: "16b")]), // seed 17 fuzz example
            (0x2E03_0041, "ext v1.8b, v2.8b, v3.8b, #0x0", [.v(2, arrangement: "8b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8b")]),     // advsimd_ext.tsv Q=0 imm4=0
            (0x2E03_3841, "ext v1.8b, v2.8b, v3.8b, #0x7", [.v(2, arrangement: "8b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8b")]),     // advsimd_ext.tsv Q=0 imm4=7 max
            (0x6E03_0041, "ext v1.16b, v2.16b, v3.16b, #0x0", [.v(2, arrangement: "16b"), .v(3, arrangement: "16b")], [.v(1, arrangement: "16b")]), // advsimd_ext.tsv Q=1 imm4=0
            (0x6E03_7841, "ext v1.16b, v2.16b, v3.16b, #0xf", [.v(2, arrangement: "16b"), .v(3, arrangement: "16b")], [.v(1, arrangement: "16b")]), // advsimd_ext.tsv Q=1 imm4=15 max
            (0x2E1F_3BFF, "ext v31.8b, v31.8b, v31.8b, #0x7", [.v(31, arrangement: "8b")], [.v(31, arrangement: "8b")]),   // (Rd,Rn,Rm)=(31,31,31) Q=0
            (0x6E1F_7BFF, "ext v31.16b, v31.16b, v31.16b, #0xf", [.v(31, arrangement: "16b")], [.v(31, arrangement: "16b")]), // (Rd,Rn,Rm)=(31,31,31) Q=1
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (Q=0 with imm4<3>==1, op2!=0, bit[15]==1) must remain .inst:
        for badWord: UInt32 in [0x2E03_4041, 0x2E03_7841, 0x2E1F_43FF, 0x2E43_0041, 0x6E43_0041, 0x6EC3_4041, 0x2E03_8041] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_ext"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 256)
        #expect(mismatches.isEmpty, "Group 10 advsimd_ext mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11b Group 8: AdvSIMD vector permute (UZP1, TRN1, ZIP1, UZP2, TRN2, ZIP2) and size=11,Q=0 / opcode in {0,4} guards match all 128 rows of advsimd_permute.tsv")
    func advsimdVectorPermuteDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x0E81_7802, "zip2 v2.2s, v0.2s, v1.2s", [.v(0, arrangement: "2s"), .v(1, arrangement: "2s")], [.v(2, arrangement: "2s")]),     // /bin/csh baseline example
            (0x0E40_5B64, "uzp2 v4.4h, v27.4h, v0.4h", [.v(27, arrangement: "4h"), .v(0, arrangement: "4h")], [.v(4, arrangement: "4h")]),   // seed 20261117 fuzz example
            (0x4E1C_7A41, "zip2 v1.16b, v18.16b, v28.16b", [.v(18, arrangement: "16b"), .v(28, arrangement: "16b")], [.v(1, arrangement: "16b")]), // seed 17 fuzz example
            (0x0E03_1841, "uzp1 v1.8b, v2.8b, v3.8b", [.v(2, arrangement: "8b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8b")]),     // advsimd_permute.tsv 8b UZP1
            (0x4E03_2841, "trn1 v1.16b, v2.16b, v3.16b", [.v(2, arrangement: "16b"), .v(3, arrangement: "16b")], [.v(1, arrangement: "16b")]), // advsimd_permute.tsv 16b TRN1
            (0x4E43_3841, "zip1 v1.8h, v2.8h, v3.8h", [.v(2, arrangement: "8h"), .v(3, arrangement: "8h")], [.v(1, arrangement: "8h")]),     // advsimd_permute.tsv 8h ZIP1
            (0x4E83_6841, "trn2 v1.4s, v2.4s, v3.4s", [.v(2, arrangement: "4s"), .v(3, arrangement: "4s")], [.v(1, arrangement: "4s")]),     // advsimd_permute.tsv 4s TRN2
            (0x4EC3_7841, "zip2 v1.2d, v2.2d, v3.2d", [.v(2, arrangement: "2d"), .v(3, arrangement: "2d")], [.v(1, arrangement: "2d")]),     // advsimd_permute.tsv 2d ZIP2 (size=11, Q=1)
            (0x0E02_3841, "zip1 v1.8b, v2.8b, v2.8b", [.v(2, arrangement: "8b")], [.v(1, arrangement: "8b")]),                               // Rn == Rm deduplicates readsRegisters
            (0x4EDF_6BFF, "trn2 v31.2d, v31.2d, v31.2d", [.v(31, arrangement: "2d")], [.v(31, arrangement: "2d")]),                          // (Rd,Rn,Rm)=(31,31,31) 2d
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (size=11 with Q=0, opcode in {0, 4}, bit[15]==1) must remain .inst:
        for badWord: UInt32 in [0x0EC3_1841, 0x0EC3_3841, 0x0EC3_7841, 0x0EDF_7BFF, 0x0E03_0841, 0x0E03_4841, 0x4EC3_0841, 0x4EC3_4841, 0x0E03_9841] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_permute"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 128)
        #expect(mismatches.isEmpty, "Group 8 advsimd_permute mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 11b Group 22: AdvSIMD vector table lookup (TBL, TBX across 1..4 table registers incl. v31->v0 wrap-around) matches all 128 rows of advsimd_table_lookup.tsv")
    func advsimdVectorTableLookupDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x0E00_0362, "tbl v2.8b, { v27.16b }, v0.8b", [.v(27, arrangement: "16b"), .v(0, arrangement: "8b")], [.v(2, arrangement: "8b")]), // /usr/bin/afscexpand baseline example (generic Neon syntax)
            (0x0E0D_41A5, "tbl v5.8b, { v13.16b, v14.16b, v15.16b }, v13.8b", [.v(13, arrangement: "16b"), .v(14, arrangement: "16b"), .v(15, arrangement: "16b"), .v(13, arrangement: "8b")], [.v(5, arrangement: "8b")]), // seed 20261117 fuzz example
            (0x4E01_4334, "tbl v20.16b, { v25.16b, v26.16b, v27.16b }, v1.16b", [.v(25, arrangement: "16b"), .v(26, arrangement: "16b"), .v(27, arrangement: "16b"), .v(1, arrangement: "16b")], [.v(20, arrangement: "16b")]), // seed 17 fuzz example
            (0x0E03_0041, "tbl v1.8b, { v2.16b }, v3.8b", [.v(2, arrangement: "16b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8b")]),   // 1-reg TBL .8b (does not read Vd)
            (0x0E03_1041, "tbx v1.8b, { v2.16b }, v3.8b", [.v(1, arrangement: "8b"), .v(2, arrangement: "16b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8b")]), // 1-reg TBX .8b (read-modify-write on Vd)
            (0x4E03_2041, "tbl v1.16b, { v2.16b, v3.16b }, v3.16b", [.v(2, arrangement: "16b"), .v(3, arrangement: "16b")], [.v(1, arrangement: "16b")]), // 2-reg TBL .16b (v3.16b deduplicated)
            (0x4E03_7041, "tbx v1.16b, { v2.16b, v3.16b, v4.16b, v5.16b }, v3.16b", [.v(1, arrangement: "16b"), .v(2, arrangement: "16b"), .v(3, arrangement: "16b"), .v(4, arrangement: "16b"), .v(5, arrangement: "16b")], [.v(1, arrangement: "16b")]), // 4-reg TBX .16b
            (0x0E1F_23FF, "tbl v31.8b, { v31.16b, v0.16b }, v31.8b", [.v(31, arrangement: "16b"), .v(0, arrangement: "16b"), .v(31, arrangement: "8b")], [.v(31, arrangement: "8b")]), // v31->v0 wrap-around
            (0x4E1F_73FF, "tbx v31.16b, { v31.16b, v0.16b, v1.16b, v2.16b }, v31.16b", [.v(31, arrangement: "16b"), .v(0, arrangement: "16b"), .v(1, arrangement: "16b"), .v(2, arrangement: "16b")], [.v(31, arrangement: "16b")]), // 4-reg v31->v2 wrap-around TBX .16b
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (op2 != 0, bit[15] == 1) must remain .inst:
        for badWord: UInt32 in [0x0E43_0041, 0x0E83_2041, 0x0EC3_7041, 0x4E43_0041, 0x4EDF_73FF, 0x0E03_8041] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_table_lookup"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 128)
        #expect(mismatches.isEmpty, "Group 22 advsimd_table_lookup mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 12a Group 7: AdvSIMD vector three-register different (widening/narrowing integer & PMULL .8h/.1q incl. *2 upper-half forms) matches all 512 rows of advsimd_three_different.tsv")
    func advsimdVectorThreeDifferentDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x4EA3_C044, "smull2 v4.2d, v2.4s, v3.4s", [.v(2, arrangement: "4s"), .v(3, arrangement: "4s")], [.v(4, arrangement: "2d")]), // /bin/df baseline example
            (0x0EB9_8049, "smlal v9.2d, v2.2s, v25.2s", [.v(9, arrangement: "2d"), .v(2, arrangement: "2s"), .v(25, arrangement: "2s")], [.v(9, arrangement: "2d")]), // seed 20261117 fuzz example
            (0x0E6E_617D, "subhn v29.4h, v11.4s, v14.4s", [.v(11, arrangement: "4s"), .v(14, arrangement: "4s")], [.v(29, arrangement: "4h")]), // seed 17 fuzz example
            (0x0E23_0041, "saddl v1.8h, v2.8b, v3.8b", [.v(2, arrangement: "8b"), .v(3, arrangement: "8b")], [.v(1, arrangement: "8h")]),
            (0x4E23_1041, "saddw2 v1.8h, v2.8h, v3.16b", [.v(2, arrangement: "8h"), .v(3, arrangement: "16b")], [.v(1, arrangement: "8h")]),
            (0x6E23_4041, "raddhn2 v1.16b, v2.8h, v3.8h", [.v(1, arrangement: "16b"), .v(2, arrangement: "8h"), .v(3, arrangement: "8h")], [.v(1, arrangement: "16b")]),
            (0x0E63_9041, "sqdmlal v1.4s, v2.4h, v3.4h", [.v(1, arrangement: "4s"), .v(2, arrangement: "4h"), .v(3, arrangement: "4h")], [.v(1, arrangement: "4s")]),
            (0x0EE3_E041, "pmull v1.1q, v2.1d, v3.1d", [.v(2, arrangement: "1d"), .v(3, arrangement: "1d")], [.v(1, arrangement: "1q")]),
            (0x4EFF_E3FF, "pmull2 v31.1q, v31.2d, v31.2d", [.v(31, arrangement: "2d")], [.v(31, arrangement: "1q")]),
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (size=11 for integer, U=1 or size=0 for sqd*, size in {1,2} or U=1 for pmull, opcode=15) must remain .inst:
        for badWord: UInt32 in [0x0EE3_0041, 0x2E63_9041, 0x0E23_9041, 0x0E63_E041, 0x2EE3_E041, 0x0E23_F041] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_three_different"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 512)
        #expect(mismatches.isEmpty, "Group 7 advsimd_three_different mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 12a Group 13: AdvSIMD vector by element (FP16/32/64, FHM, FCMA, DotProd, integer/widening/RDMA) matches all 4,096 rows of advsimd_vector_by_element.tsv")
    func advsimdVectorByElementDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x0F80_1023, "fmla v3.2s, v1.2s, v0.s[0]", [.v(3, arrangement: "2s"), .v(1, arrangement: "2s"), .v(0, arrangement: "s")], [.v(3, arrangement: "2s")]), // /usr/bin/IOMFBDiagnose baseline example
            (0x0F3D_90D4, "fmul v20.4h, v6.4h, v13.h[3]", [.v(6, arrangement: "4h"), .v(13, arrangement: "h")], [.v(20, arrangement: "4h")]), // seed 20261117 fuzz example
            (0x0F61_B095, "sqdmull v21.4s, v4.4h, v1.h[2]", [.v(4, arrangement: "4h"), .v(1, arrangement: "h")], [.v(21, arrangement: "4s")]), // seed 17 fuzz example
            (0x4F7F_8BFF, "mul v31.8h, v31.8h, v15.h[7]", [.v(31, arrangement: "8h"), .v(15, arrangement: "h")], [.v(31, arrangement: "8h")]), // 4-bit Rm v15.h[7]
            (0x4FBF_9BFF, "fmul v31.4s, v31.4s, v31.s[3]", [.v(31, arrangement: "4s"), .v(31, arrangement: "s")], [.v(31, arrangement: "4s")]), // 5-bit Rm v31.s[3]
            (0x6FDF_9BFF, "fmulx v31.2d, v31.2d, v31.d[1]", [.v(31, arrangement: "2d"), .v(31, arrangement: "d")], [.v(31, arrangement: "2d")]), // 5-bit Rm v31.d[1]
            (0x6FBF_EBFF, "udot v31.4s, v31.16b, v31.4b[3]", [.v(31, arrangement: "4s"), .v(31, arrangement: "16b"), .v(31, arrangement: "4b")], [.v(31, arrangement: "4s")]), // FEAT_DotProd .4b[3]
            (0x6FBF_CBFF, "fmlsl2 v31.4s, v31.4h, v15.h[7]", [.v(31, arrangement: "4s"), .v(31, arrangement: "4h"), .v(15, arrangement: "h")], [.v(31, arrangement: "4s")]), // FEAT_FHM 4-bit Rm .h[7]
            (0x6F7F_7BFF, "fcmla v31.8h, v31.8h, v31.h[3], #270", [.v(31, arrangement: "8h"), .v(31, arrangement: "h")], [.v(31, arrangement: "8h")]), // FEAT_FCMA 5-bit Rm .h[3]
            (0x6F9F_3BFF, "fcmla v31.4s, v31.4s, v31.s[1], #90", [.v(31, arrangement: "4s"), .v(31, arrangement: "s")], [.v(31, arrangement: "4s")]), // FEAT_FCMA 5-bit Rm .s[1]
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (size=3 with Q=0 or L=1, FCMLA invalid H/L/Q, bit[23]=1&bit[10]=1) must remain .inst:
        for badWord: UInt32 in [0x0FC3_9041, 0x4FE3_9041, 0x2F43_1841, 0x2F83_1041, 0x6FA3_1041, 0x0F83_1441] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_vector_by_element"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 4096)
        #expect(mismatches.isEmpty, "Group 13 advsimd_vector_by_element mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 12a Group 26: AdvSIMD scalar by element (FP16/32/64, saturating widening & RDMA) matches all 2,048 rows of advsimd_scalar_by_element.tsv")
    func advsimdScalarByElementDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x5FA7_9212, "fmul s18, s16, v7.s[1]", [.s(16), .v(7, arrangement: "s")], [.s(18)]), // /usr/libexec/locationd baseline example
            (0x5F49_D380, "sqrdmulh h0, h28, v9.h[0]", [.h(28), .v(9, arrangement: "h")], [.h(0)]), // seed 20261117 fuzz example
            (0x5FB3_727F, "sqdmlsl d31, s19, v19.s[1]", [.d(31), .s(19), .v(19, arrangement: "s")], [.d(31)]), // seed 17 fuzz example
            (0x5F3F_1BFF, "fmla h31, h31, v15.h[7]", [.h(31), .v(15, arrangement: "h")], [.h(31)]), // 4-bit Rm v15.h[7]
            (0x7FDF_9BFF, "fmulx d31, d31, v31.d[1]", [.d(31), .v(31, arrangement: "d")], [.d(31)]), // 5-bit Rm v31.d[1]
            (0x5F7F_BBFF, "sqdmull s31, h31, v15.h[7]", [.h(31), .v(15, arrangement: "h")], [.s(31)]), // 4-bit Rm widening
            (0x7FBF_FBFF, "sqrdmlsh s31, s31, v31.s[3]", [.s(31), .v(31, arrangement: "s")], [.s(31)]), // 5-bit Rm RDMA
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (size=1 FP, size=3 L=1 FP64, U=1 sqdmlal, size=0 sqdmulh, vector-only mul/sdot, bit[10]=1) must remain .inst:
        for badWord: UInt32 in [0x5F43_1041, 0x5FE3_9041, 0x7F43_3041, 0x5F03_C041, 0x5F43_8041, 0x5F83_E041, 0x5F83_1441] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_scalar_by_element"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 2048)
        #expect(mismatches.isEmpty, "Group 26 advsimd_scalar_by_element mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 12b Group 20: AdvSIMD vector across lanes (SADDLV/UADDLV, SMAXV/UMAXV, SMINV/UMINV, ADDV, FP16/FP32 FMAXNMV/FMAXV/FMINNMV/FMINV) matches all 1,024 rows of advsimd_across_lanes.tsv")
    func advsimdAcrossLanesDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x6E30_A864, "umaxv b4, v3.16b", [.v(3, arrangement: "16b")], [.b(4)]), // /bin/csh baseline example
            (0x2E30_3B65, "uaddlv h5, v27.8b", [.v(27, arrangement: "8b")], [.h(5)]), // seed 20261117 fuzz example
            (0x6E30_AA45, "umaxv b5, v18.16b", [.v(18, arrangement: "16b")], [.b(5)]), // seed 17 fuzz example
            (0x2E71_A842, "uminv h2, v2.4h", [.v(2, arrangement: "4h")], [.h(2)]), // /bin/zsh corpus example
            (0x4EB0_3841, "saddlv d1, v2.4s", [.v(2, arrangement: "4s")], [.d(1)]), // widening .4s -> d
            (0x0E30_C841, "fmaxnmv h1, v2.4h", [.v(2, arrangement: "4h")], [.h(1)]), // FP16 U=0, Q=0, size=00
            (0x4EB0_F841, "fminv h1, v2.8h", [.v(2, arrangement: "8h")], [.h(1)]), // FP16 U=0, Q=1, size=10
            (0x6E30_FBF1, "fmaxv s17, v31.4s", [.v(31, arrangement: "4s")], [.s(17)]), // FP32 U=1, Q=1, size=00
            (0x6EB0_CBFF, "fminnmv s31, v31.4s", [.v(31, arrangement: "4s")], [.s(31)]), // FP32 U=1, Q=1, size=10, (31,31)
            (0x4EB1_BBFF, "addv s31, v31.4s", [.v(31, arrangement: "4s")], [.s(31)]), // ADDV preserved
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }
        #expect(decoder.decode(word: 0x4EB1_BBFF, at: pc).mnemonic == .addv)

        // Unallocated counterexamples (Q=0 .2s integer, U=1 ADDV, U=1 Q=0 FP32, U=0 size=01 FP16, size=11 integer/FP) must remain .inst:
        for badWord: UInt32 in [0x0EB1_B841, 0x2E31_B841, 0x0EB0_A841, 0x2E30_F841, 0x4E70_C841, 0x6EF0_F841, 0x4EF0_3841] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_across_lanes"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 1024)
        #expect(mismatches.isEmpty, "Group 20 advsimd_across_lanes mismatches: \(mismatches.joined(separator: "; "))")
    }

    @Test("Stage 12b Group 24: AdvSIMD scalar pairwise (ADDP d, v.2d and FP16/FP32/FP64 FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP) matches all 512 rows of advsimd_scalar_pairwise.tsv")
    func advsimdScalarPairwiseDecodingAndTableParity() throws {
        let pc = VirtualAddress(0x1_0000_1000)

        let sampleCases: [(UInt32, String, [A64Register], [A64Register])] = [
            (0x5EF1_B800, "addp d0, v0.2d", [.v(0, arrangement: "2d")], [.d(0)]), // /usr/bin/afscexpand baseline example
            (0x7E70_D842, "faddp d2, v2.2d", [.v(2, arrangement: "2d")], [.d(2)]), // /usr/bin/assetutil corpus example
            (0x7E30_D820, "faddp s0, v1.2s", [.v(1, arrangement: "2s")], [.s(0)]), // FP32 FADDP example
            (0x5E30_D841, "faddp h1, v2.2h", [.v(2, arrangement: "2h")], [.h(1)]), // FP16 U=0, size=00 FADDP
            (0x5E30_C841, "fmaxnmp h1, v2.2h", [.v(2, arrangement: "2h")], [.h(1)]), // FP16 FMAXNMP
            (0x5EB0_F841, "fminp h1, v2.2h", [.v(2, arrangement: "2h")], [.h(1)]), // FP16 FMINP
            (0x7E30_FBFF, "fmaxp s31, v31.2s", [.v(31, arrangement: "2s")], [.s(31)]), // FP32 FMAXP (31,31)
            (0x7EB0_C841, "fminnmp s1, v2.2s", [.v(2, arrangement: "2s")], [.s(1)]), // FP32 FMINNMP
            (0x7E70_C841, "fmaxnmp d1, v2.2d", [.v(2, arrangement: "2d")], [.d(1)]), // FP64 FMAXNMP
            (0x7EF0_FBFF, "fminp d31, v31.2d", [.v(31, arrangement: "2d")], [.d(31)]), // FP64 FMINP (31,31)
        ]
        for (word, expected, expectedReads, expectedWrites) in sampleCases {
            let decoded = decoder.decode(word: word, at: pc)
            #expect(decoded.mnemonic != .unknown, "word=0x\(String(word, radix: 16))")
            #expect(decoded.formattedDisassembly == expected, "word=0x\(String(word, radix: 16))")
            #expect(decoded.readsRegisters == expectedReads, "word=0x\(String(word, radix: 16))")
            #expect(decoded.writesRegisters == expectedWrites, "word=0x\(String(word, radix: 16))")
        }

        // Unallocated counterexamples (size!=11 or U=1 ADDP, U=0 size=01 FP16, szHi=1 opcode=01101, integer across-lanes opcodes) must remain .inst:
        for badWord: UInt32 in [0x5EB1_B841, 0x7EF1_B841, 0x5E70_D841, 0x5EB0_D841, 0x7EB0_D841, 0x7EF0_D841, 0x5E30_A841] {
            let decoded = decoder.decode(word: badWord, at: pc)
            #expect(decoded.mnemonic == .unknown, "word=0x\(String(badWord, radix: 16))")
            #expect(decoded.mnemonicText == ".inst", "word=0x\(String(badWord, radix: 16))")
        }

        let rawText = try String(contentsOf: RepoFixtures.a64TableURL("advsimd_scalar_pairwise"), encoding: .utf8)
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
            let expectedOps = parts.count > 2 ? String(parts[2]).split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespaces) : ""
            let decoded = decoder.decode(word: word, at: pc)
            rowCount += 1

            if expectedMnem == ".long" {
                if decoded.mnemonic != .unknown || decoded.mnemonicText != ".inst" {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected .inst got '%@'", word, decoded.formattedDisassembly))
                    }
                }
            } else {
                let expectedText = expectedOps.isEmpty ? expectedMnem : "\(expectedMnem) \(expectedOps)"
                if decoded.formattedDisassembly != expectedText || decoded.mnemonic == .unknown {
                    if mismatches.count < 12 {
                        mismatches.append(String(format: "0x%08x expected '%@' got '%@'", word, expectedText, decoded.formattedDisassembly))
                    }
                }
            }
        }
        #expect(rowCount == 512)
        #expect(mismatches.isEmpty, "Group 24 advsimd_scalar_pairwise mismatches: \(mismatches.joined(separator: "; "))")
    }
}
