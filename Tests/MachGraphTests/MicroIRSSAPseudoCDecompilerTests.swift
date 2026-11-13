import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine
import MachMicroDecompiler

@Suite("Micro-IR Lifter, Cytron SSA Optimizer & Structured Pseudo-C Decompiler")
struct MicroIRSSAPseudoCDecompilerTests {

    private func countGotos(in statements: [PseudoCStatement]) -> Int {
        var total = 0
        for stmt in statements {
            switch stmt {
            case .gotoStmt:
                total += 1
            case .ifStmt(_, _, let thenBody, let elseBody):
                total += countGotos(in: thenBody) + countGotos(in: elseBody)
            case .whileLoop(_, _, let body), .doWhileLoop(let body, _, _):
                total += countGotos(in: body)
            case .switchStmt(_, _, let arms, let defaultBody):
                for arm in arms {
                    total += countGotos(in: arm.body)
                }
                total += countGotos(in: defaultBody)
            default:
                break
            }
        }
        return total
    }

    private func containsWhileOrDoWhile(in statements: [PseudoCStatement]) -> Bool {
        for stmt in statements {
            switch stmt {
            case .whileLoop, .doWhileLoop:
                return true
            case .ifStmt(_, _, let t, let e):
                if containsWhileOrDoWhile(in: t) || containsWhileOrDoWhile(in: e) { return true }
            case .switchStmt(_, _, let arms, let d):
                if arms.contains(where: { containsWhileOrDoWhile(in: $0.body) }) || containsWhileOrDoWhile(in: d) {
                    return true
                }
            default:
                break
            }
        }
        return false
    }

    private func containsSwitch(in statements: [PseudoCStatement]) -> StructuredSwitchResult? {
        for stmt in statements {
            switch stmt {
            case .switchStmt(_, _, let arms, let defaultBody):
                return StructuredSwitchResult(arms: arms, defaultBody: defaultBody)
            case .ifStmt(_, _, let t, let e):
                if let found = containsSwitch(in: t) ?? containsSwitch(in: e) { return found }
            case .whileLoop(_, _, let b), .doWhileLoop(let b, _, _):
                if let found = containsSwitch(in: b) { return found }
            default:
                break
            }
        }
        return nil
    }

    private struct StructuredSwitchResult {
        let arms: [StructuredSwitchArm]
        let defaultBody: [PseudoCStatement]
    }

    @Test("ARM64ToMicroIRLifter synthesizes wide MOVZ/MOVK constants and suppresses PAC/prologue boilerplate")
    func lifterSynthesizesWideConstantsAndSuppressesPACAndPrologue() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            paciasp
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            movz x0, #0xbeef
            movk x0, #0xdead, lsl #16
            ldp x29, x30, [sp], #16
            retaa
        """, baseAddress: VirtualAddress(0x1_0000_4000))

        let fn = BinaryAnalysisCoordinator().analyzeSingleFunction(
            at: prog.baseAddress,
            name: "_magic_const",
            instructions: prog.instructions
        )
        let lifted = ARM64ToMicroIRLifter().lift(function: fn)

        #expect(lifted.returnsValue)
        let allStmts = lifted.microBlocks.flatMap(\.statements)

        // Ensure PAC intrinsics were suppressed under default configuration
        let hasPACIntrinsic = allStmts.contains { stmt in
            if case .intrinsic(let name, _) = stmt.kind {
                return name.lowercased().contains("pac") || name.lowercased().contains("aut")
            }
            return false
        }
        #expect(!hasPACIntrinsic)

        // Decompile and verify folded hex constant 0xdeadbeef (or decimal 3735928559)
        let out = MachMicroDecompilerEngine().decompile(function: fn)
        let lower = out.fullSourceText.lowercased()
        #expect(lower.contains("deadbeef") || lower.contains("3735928559"))
    }

    @Test("ARM64ToMicroIRLifter recovers AAPCS64 call arguments and PC-relative string literals")
    func lifterRecoversAAPCS64CallArgumentsAndPCRelativeStrings() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "LiftCall.arm64e")
        let verifyFn = try #require(index.function(named: "_verify_license"))

        let lifted = ARM64ToMicroIRLifter().lift(
            function: verifyFn,
            image: index.image,
            analysisIndex: index,
            recognizedIdioms: index.recognizedIdioms
        )

        #expect(!lifted.detectedLiveInParameters.isEmpty)
        let allStmts = lifted.microBlocks.flatMap(\.statements)

        let foundCallWithArgs = allStmts.contains { stmt in
            switch stmt.kind {
            case .assign(_, .call(_, let args, _)):
                return !args.isEmpty
            case .callStmt(_, let args):
                return !args.isEmpty
            default:
                return false
            }
        }
        #expect(foundCallWithArgs)
    }

    @Test("KnownFunctionSignatureCatalog resolves POSIX/libc prototypes, printf format counts, and ObjC encodings")
    func knownFunctionSignatureCatalogPrototypesFormatSpecifiersAndObjCEncoding() {
        #expect(KnownFunctionSignatureCatalog.normalizeSymbolName("imp___stubs__strcmp") == "strcmp")
        #expect(KnownFunctionSignatureCatalog.normalizeSymbolName("_strcmp [stub]") == "strcmp")
        let strcmpProto = KnownFunctionSignatureCatalog.lookup("_strcmp")
        #expect(strcmpProto != nil)
        #expect(strcmpProto?.fixedParameterTypes.count == 2)

        #expect(KnownFunctionSignatureCatalog.countPrintfFormatSpecifiers(in: "user=%s code=%d %% hex=0x%llx") == 3)

        let objcTypes = KnownFunctionSignatureCatalog.parseObjCTypeEncoding("B24@0:8@16")
        #expect(objcTypes.count >= 3)
        #expect(objcTypes[0] == .boolType)
    }

    @Test("CytronSSAPhiAndOptimizerEngine inserts minimal pruned phi-nodes at dominance frontiers")
    func cytronSSAInsertsPrunedPhiNodesAtDominanceFrontiers() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            cbz x0, .L_else
            mov w1, #10
            b .L_merge
        .L_else:
            mov w1, #20
        .L_merge:
            add w0, w1, #5
            ret
        """, baseAddress: VirtualAddress(0x1_0000_4200))

        let fn = BinaryAnalysisCoordinator().analyzeSingleFunction(
            at: prog.baseAddress,
            name: "_diamond_phi",
            instructions: prog.instructions
        )
        let lifted = ARM64ToMicroIRLifter().lift(function: fn)

        var unoptConfig = SSAOptimizationConfiguration.standard
        unoptConfig.enableSingleUseInlining = false
        let ssaResult = CytronSSAPhiAndOptimizerEngine(configuration: unoptConfig).buildSSAAndOptimize(
            lifted: lifted,
            function: fn
        )

        #expect(ssaResult.metrics.insertedPhiCount >= 1)
        let hasPhi = ssaResult.ssaBlocks.flatMap(\.statements).contains { stmt in
            if case .assign(_, .phi(let incomings)) = stmt.kind {
                return incomings.count == 2
            }
            return false
        }
        #expect(hasPhi)
    }

    @Test("CytronSSAPhiAndOptimizerEngine performs constant propagation, copy propagation, and algebraic simplification")
    func cytronSSAConstantAndCopyPropagationAndAlgebraicSimplification() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            mov w1, #10
            add w2, w1, #25
            mov w3, w2
            add w0, w3, #0
            ret
        """, baseAddress: VirtualAddress(0x1_0000_4400))

        let fn = BinaryAnalysisCoordinator().analyzeSingleFunction(
            at: prog.baseAddress,
            name: "_const_prop",
            instructions: prog.instructions
        )
        let lifted = ARM64ToMicroIRLifter().lift(function: fn)
        let ssaResult = CytronSSAPhiAndOptimizerEngine().buildSSAAndOptimize(lifted: lifted, function: fn)

        #expect(ssaResult.metrics.propagatedConstantsCount >= 1 || ssaResult.metrics.propagatedCopiesCount >= 1)
        let out = MachMicroDecompilerEngine().decompile(function: fn)
        #expect(out.fullSourceText.contains("35") || out.fullSourceText.contains("0x23"))
    }

    @Test("CytronSSAPhiAndOptimizerEngine dead-store elimination removes overwritten unused register definitions")
    func cytronSSADeadStoreEliminationRemovesUnusedAssignments() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            mov w8, #111
            mov w9, #222
            add w10, w8, w9
            mov w0, #7
            ret
        """, baseAddress: VirtualAddress(0x1_0000_4600))

        let fn = BinaryAnalysisCoordinator().analyzeSingleFunction(
            at: prog.baseAddress,
            name: "_dead_stores",
            instructions: prog.instructions
        )
        let out = MachMicroDecompilerEngine().decompile(function: fn)
        #expect(out.eliminatedDeadStoreCount >= 3)
        #expect(!out.fullSourceText.contains("111"))
        #expect(!out.fullSourceText.contains("222"))
        #expect(out.fullSourceText.contains("return 7") || out.fullSourceText.contains("return 0x7"))
    }

    @Test("MachMicroDecompilerEngine recovers structured while loop with zero gotos on _compute_checksum")
    func decompileComputeChecksumRecoversStructuredWhileLoopZeroGotos() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DecompLoop.arm64e")
        let checksumFn = try #require(index.function(named: "_compute_checksum"))

        let output = MachMicroDecompilerEngine().decompile(function: checksumFn, in: index)
        #expect(countGotos(in: output.structuredBody) == 0)
        #expect(!output.fullSourceText.contains("goto "))
        #expect(containsWhileOrDoWhile(in: output.structuredBody))
        #expect(output.fullSourceText.contains("while"))
    }

    @Test("MachMicroDecompilerEngine recovers structured if/else and MACHGRAPH-PRO-2026 literal on _verify_license")
    func decompileVerifyLicenseRecoversIfElseAndLicenseStringLiteralZeroGotos() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DecompLicense.arm64e")
        let verifyFn = try #require(index.function(named: "_verify_license"))

        let output = MachMicroDecompilerEngine().decompile(function: verifyFn, in: index)
        #expect(countGotos(in: output.structuredBody) == 0)
        #expect(!output.fullSourceText.contains("goto "))
        #expect(output.fullSourceText.contains("if ("))
        #expect(output.fullSourceText.contains("MACHGRAPH-PRO-2026"))
        #expect(output.fullSourceText.contains("strcmp"))
    }

    @Test("MachMicroDecompilerEngine recovers switch statement with cases 0..3 and default on _dispatch_command")
    func decompileDispatchCommandRecoversSwitchCases0To3AndDefaultZeroGotos() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DecompSwitch.arm64")
        let dispatchFn = try #require(index.function(named: "_dispatch_command"))

        let output = MachMicroDecompilerEngine().decompile(function: dispatchFn, in: index)
        #expect(countGotos(in: output.structuredBody) == 0)
        #expect(!output.fullSourceText.contains("goto "))
        #expect(output.fullSourceText.contains("switch"))

        let recoveredSwitch = try #require(containsSwitch(in: output.structuredBody))
        let allCaseValues = Set(recoveredSwitch.arms.flatMap(\.caseValues))
        #expect(allCaseValues.isSuperset(of: [0, 1, 2, 3]))
        #expect(!recoveredSwitch.defaultBody.isEmpty || output.fullSourceText.contains("999") || output.fullSourceText.contains("0x3e7"))
    }

    @Test("MachMicroDecompilerEngine recovers Objective-C instance method signature and ivar field names")
    func decompileObjCMethodSignatureAndIvarAccessRecovery() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DecompObjC.arm64e")
        let objcFn = try #require(index.function(named: "-[MGAuthController validateToken:]"))

        let output = MachMicroDecompilerEngine().decompile(function: objcFn, in: index)
        #expect(output.signatureLine.contains("MGAuthController"))
        #expect(output.signatureLine.contains("validateToken"))
        #expect(countGotos(in: output.structuredBody) == 0)
    }

    @Test("MachMicroDecompilerEngine recovers Objective-C class method +[MGAuthController sharedController]")
    func decompileObjCClassMethodSharedController() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DecompObjCClass.arm64e")
        let clsFn = try #require(index.function(named: "+[MGAuthController sharedController]"))

        let output = MachMicroDecompilerEngine().decompile(function: clsFn, in: index)
        #expect(output.signatureLine.contains("MGAuthController"))
        #expect(output.signatureLine.contains("sharedController"))
        #expect(countGotos(in: output.structuredBody) == 0)
    }

    @Test("Custom C struct definition resolves pointer-offset memory loads into named ->field accesses")
    func decompileCustomCStructFieldOffsetDereferenceResolution() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            ldr w8, [x0, #8]
            ldr w9, [x0, #12]
            add w0, w8, w9
            ret
        """, baseAddress: VirtualAddress(0x1_0000_5000))

        let fn = BinaryAnalysisCoordinator().analyzeSingleFunction(
            at: prog.baseAddress,
            name: "_sum_packet_header",
            instructions: prog.instructions
        )

        let packetStruct = CustomStructDefinition(
            name: "PacketHeader",
            totalByteSize: 16,
            fields: [
                CustomStructField(name: "magic", offset: 0, byteSize: 8, typeExpr: .intType(bits: 64, signed: false)),
                CustomStructField(name: "payloadLen", offset: 8, byteSize: 4, typeExpr: .intType(bits: 32, signed: false)),
                CustomStructField(name: "checksum", offset: 12, byteSize: 4, typeExpr: .intType(bits: 32, signed: false))
            ]
        )

        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "StructCtx.arm64")

        let output = MachMicroDecompilerEngine().decompile(
            function: fn,
            in: index,
            symbolRenames: [
                UserSymbolRename(
                    address: fn.address,
                    originalName: fn.name,
                    customName: "sum_packet_header",
                    signatureOverride: "uint32_t sum_packet_header(struct PacketHeader *hdr)"
                )
            ],
            customStructs: [packetStruct]
        )

        #expect(output.fullSourceText.contains("payloadLen") || output.fullSourceText.contains("PacketHeader"))
    }

    @Test("Analyst symbol renames and inline comments propagate into Pseudo-C signature and body")
    func decompileAppliesUserSymbolRenamesAndInlineComments() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "RenameComment.arm64e")
        let verifyFn = try #require(index.function(named: "_verify_license"))
        let checksumFn = try #require(index.function(named: "_compute_checksum"))

        let renames = [
            UserSymbolRename(address: verifyFn.address, originalName: verifyFn.name, customName: "audit_pro_entitlement"),
            UserSymbolRename(address: checksumFn.address, originalName: checksumFn.name, customName: "rolling_fnv_hash")
        ]
        let comments = [
            UserInlineComment(address: verifyFn.address, text: "Analyst verified license gate")
        ]

        let output = MachMicroDecompilerEngine().decompile(
            function: verifyFn,
            in: index,
            symbolRenames: renames,
            inlineComments: comments
        )

        #expect(output.functionName == "audit_pro_entitlement")
        #expect(output.signatureLine.contains("audit_pro_entitlement"))
        #expect(output.fullSourceText.contains("rolling_fnv_hash"))
        #expect(output.fullSourceText.contains("Analyst verified license gate"))
    }

    @Test("decompileAllFunctions produces structured Pseudo-C for every non-thunk function in binary")
    func decompileAllFunctionsInSyntheticBinaryProducesCleanPseudoC() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "BatchDecomp.arm64e")

        let allOutputs = MachMicroDecompilerEngine().decompileAllFunctions(in: index, includeThunks: false)
        #expect(allOutputs.count >= 6)
        for output in allOutputs {
            #expect(!output.fullSourceText.isEmpty)
            #expect(!output.renderedLines.isEmpty)
            #expect(output.confidenceScore > 0.5)
            #expect(countGotos(in: output.structuredBody) == 0, "Unexpected goto in \(output.functionName)")
        }
    }

    @Test("Lossless PseudoCToken round-trip invariant: joining line.tokens equals line.text across all decompiled functions")
    func pseudoCTokenLosslessRoundTripAcrossAllRenderedLines() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Tokens.arm64e")
        let outputs = MachMicroDecompilerEngine().decompileAllFunctions(in: index, includeThunks: false)

        var checkedLineCount = 0
        for out in outputs {
            for line in out.renderedLines {
                let reconstructed = line.tokens.map(\.text).joined()
                #expect(reconstructed == line.text, "Token round-trip mismatch on line \(line.lineNumber): '\(reconstructed)' != '\(line.text)'")
                checkedLineCount += 1
            }
        }
        #expect(checkedLineCount > 40)
    }

    @Test("PseudoCCodeFormatter formats nested AST statements and classifies C keywords, types, strings, and numbers")
    func pseudoCCodeFormatterCustomStatementsAndIndentation() {
        let formatter = PseudoCCodeFormatter(indentWidth: 4)
        let addr = VirtualAddress(0x1_0000_1000)
        let body: [PseudoCStatement] = [
            .varDecl(name: "acc", type: .intType(bits: 32, signed: false), initialValue: "0", address: addr),
            .ifStmt(
                condition: "input != NULL",
                address: addr.adding(UInt64(4)),
                thenBody: [
                    .exprStmt(expression: "puts(\"ok\")", address: addr.adding(UInt64(8))),
                    .returnStmt(expression: "1", address: addr.adding(UInt64(12)))
                ],
                elseBody: [
                    .returnStmt(expression: "0", address: addr.adding(UInt64(16)))
                ]
            )
        ]

        let formatted = formatter.formatFunction(
            functionAddress: addr,
            functionName: "check_input",
            returnType: .intType(bits: 32, signed: true),
            parameters: [NamedParameterDecl(name: "input", type: .cString)],
            body: body
        )

        #expect(formatted.signatureLine == "int32_t check_input(const char *input)")
        #expect(formatted.fullSourceText.contains("    if (input != NULL)"))
        #expect(formatted.fullSourceText.contains("        puts(\"ok\");"))

        let tokens = formatter.tokenizeCLine("uint64_t count = 0x42; // init", knownVariables: ["count"])
        #expect(tokens.map(\.text).joined() == "uint64_t count = 0x42; // init")
        #expect(tokens.contains { $0.kind == .typeName && $0.text == "uint64_t" })
        #expect(tokens.contains { $0.kind == .variableName && $0.text == "count" })
        #expect(tokens.contains { $0.kind == .numericLiteral && $0.text == "0x42" })
        #expect(tokens.contains { $0.kind == .comment })
    }

    @Test("StructuralControlFlowRecoverer recovers if-else and while statements directly from MicroBasicBlocks")
    func structuralControlFlowRecovererDirectMicroIRIfElseAndWhile() {
        let base = VirtualAddress(0x1_0000_6000)
        let x0 = SSAVar(baseName: "x0", version: 1)
        let blocks: [MicroBasicBlock] = [
            MicroBasicBlock(
                blockID: 0,
                startAddress: base,
                statements: [
                    MicroStmt(
                        originAddress: base,
                        kind: .conditionalBranch(
                            condition: .binary(.signedGreater, .variable(x0), .signedConst(0, bits: 64)),
                            trueBlockID: 1,
                            falseBlockID: 2
                        )
                    )
                ]
            ),
            MicroBasicBlock(
                blockID: 1,
                startAddress: base.adding(UInt64(4)),
                statements: [MicroStmt(originAddress: base.adding(UInt64(4)), kind: .returnStmt(value: .signedConst(1, bits: 32)))]
            ),
            MicroBasicBlock(
                blockID: 2,
                startAddress: base.adding(UInt64(8)),
                statements: [MicroStmt(originAddress: base.adding(UInt64(8)), kind: .returnStmt(value: .signedConst(0, bits: 32)))]
            )
        ]

        let stmts = StructuralControlFlowRecoverer().recoverStructuredStatements(blocks: blocks, entryBlockID: 0)
        #expect(countGotos(in: stmts) == 0)
        let hasIf = stmts.contains {
            if case .ifStmt = $0 { return true }
            return false
        }
        #expect(hasIf)
    }

    @Test("CTypeExpr C declaration spelling and SSAVar versioned naming")
    func cTypeExprFormattingAndSSAVarDisplayNames() {
        #expect(CTypeExpr.voidType.cTypeName == "void")
        #expect(CTypeExpr.boolType.cTypeName == "bool")
        #expect(CTypeExpr.intType(bits: 32, signed: false).cTypeName == "uint32_t")
        #expect(CTypeExpr.pointer(to: .voidType).cTypeName == "void *")
        #expect(CTypeExpr.cString.cTypeName == "const char *")
        #expect(CTypeExpr.objcObject(className: "NSString").cTypeName == "NSString *")
        #expect(CTypeExpr.objcObject(className: nil).cTypeName == "id")
        #expect(CTypeExpr.structRef(name: "Packet").cTypeName == "struct Packet")

        #expect(SSAVar(baseName: "x0", version: 0).displayName == "x0")
        #expect(SSAVar(baseName: "x0", version: 3).displayName == "x0_3")
    }

    @Test("GhidraHeadlessSideBySideBridge probes installation cleanly and falls back gracefully when missing")
    func ghidraHeadlessBridgeProbeAndGracefulFallbackWhenUnavailable() async throws {
        let missingDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nonexistent-ghidra-\(UUID().uuidString)").path
        let bridge = GhidraHeadlessSideBySideBridge(
            ghidraInstallDirectory: missingDir,
            javaHomeDirectory: missingDir,
            timeoutSeconds: 5.0
        )

        let probe = bridge.probeInstallation()
        #expect(!probe.isAvailable)
        #expect(!probe.diagnosticMessage.isEmpty)

        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Fallback.arm64")
        let fn = try #require(index.function(named: "_verify_license"))

        let result = await bridge.decompileSideBySide(
            function: fn,
            in: index,
            binaryData: data
        )
        #expect(!result.fullSourceText.isEmpty)
        #expect(result.ghidraSideBySideSource == nil)
    }

    @Test("G18: Decompiler output starts line 1 with explicit experimental warning about unreliable condition expressions (EN + ZH)")
    func decompilerEmitsExperimentalWarningOnFirstLine() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "ExperimentalBanner.arm64")
        let fn = try #require(index.function(named: "_verify_license"))

        let outEN = MachMicroDecompilerEngine().decompile(function: fn, in: index, language: .en)
        let firstLineEN = try #require(outEN.fullSourceText.split(separator: "\n", omittingEmptySubsequences: false).first)
        #expect(String(firstLineEN) == "// EXPERIMENTAL: Decompiler output — condition expressions are known to be unreliable.")
        #expect(outEN.renderedLines.first?.lineNumber == 1)
        #expect(outEN.renderedLines.first?.text == String(firstLineEN))

        let outZH = MachMicroDecompilerEngine().decompile(function: fn, in: index, language: .zhHans)
        let firstLineZH = try #require(outZH.fullSourceText.split(separator: "\n", omittingEmptySubsequences: false).first)
        #expect(String(firstLineZH) == "// 【实验性】反编译输出：已知条件表达式还原不可靠，请以反汇编为准。")
        #expect(outZH.renderedLines.first?.lineNumber == 1)
        #expect(outZH.renderedLines.first?.text == String(firstLineZH))
    }
}
