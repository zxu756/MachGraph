import Foundation
import MachGraphModels
import MachA64Decoder
import MachCFGEngine

// MARK: - SSA Optimization Configuration & Result Models

public struct SSAOptimizationConfiguration: Sendable, Codable, Hashable {
    public var maxOptimizationIterations: Int
    public var enablePrunedPhiPlacement: Bool
    public var enableConstantPropagation: Bool
    public var enableAlgebraicSimplification: Bool
    public var enableCopyPropagation: Bool
    public var enableSingleUseInlining: Bool
    public var enableDeadStoreElimination: Bool
    public var enableTypeInference: Bool

    public init(
        maxOptimizationIterations: Int = 8,
        enablePrunedPhiPlacement: Bool = true,
        enableConstantPropagation: Bool = true,
        enableAlgebraicSimplification: Bool = true,
        enableCopyPropagation: Bool = true,
        enableSingleUseInlining: Bool = true,
        enableDeadStoreElimination: Bool = true,
        enableTypeInference: Bool = true
    ) {
        self.maxOptimizationIterations = max(1, maxOptimizationIterations)
        self.enablePrunedPhiPlacement = enablePrunedPhiPlacement
        self.enableConstantPropagation = enableConstantPropagation
        self.enableAlgebraicSimplification = enableAlgebraicSimplification
        self.enableCopyPropagation = enableCopyPropagation
        self.enableSingleUseInlining = enableSingleUseInlining
        self.enableDeadStoreElimination = enableDeadStoreElimination
        self.enableTypeInference = enableTypeInference
    }

    public static let standard = SSAOptimizationConfiguration()
}

public struct SSAOptimizationMetrics: Sendable, Codable, Hashable {
    public let insertedPhiCount: Int
    public let totalSSAVariableCount: Int
    public let propagatedConstantsCount: Int
    public let propagatedCopiesCount: Int
    public let inlinedSingleUseCount: Int
    public let algebraicSimplificationsCount: Int
    public let eliminatedDeadStoreCount: Int
    public let optimizationPassesRun: Int

    public init(
        insertedPhiCount: Int = 0,
        totalSSAVariableCount: Int = 0,
        propagatedConstantsCount: Int = 0,
        propagatedCopiesCount: Int = 0,
        inlinedSingleUseCount: Int = 0,
        algebraicSimplificationsCount: Int = 0,
        eliminatedDeadStoreCount: Int = 0,
        optimizationPassesRun: Int = 0
    ) {
        self.insertedPhiCount = insertedPhiCount
        self.totalSSAVariableCount = totalSSAVariableCount
        self.propagatedConstantsCount = propagatedConstantsCount
        self.propagatedCopiesCount = propagatedCopiesCount
        self.inlinedSingleUseCount = inlinedSingleUseCount
        self.algebraicSimplificationsCount = algebraicSimplificationsCount
        self.eliminatedDeadStoreCount = eliminatedDeadStoreCount
        self.optimizationPassesRun = optimizationPassesRun
    }
}

public struct SSAOptimizedFunctionIR: Sendable, Codable, Hashable {
    public let functionAddress: VirtualAddress
    public let functionName: String
    public let demangledName: String
    public let entryBlockID: Int
    public let ssaBlocks: [MicroBasicBlock]
    public let inferredReturnType: CTypeExpr
    public let inferredParameters: [NamedParameterDecl]
    public let parameterSSAVars: [SSAVar]
    public let variableTypes: [SSAVar: CTypeExpr]
    public let variableDisplayNames: [SSAVar: String]
    public let metrics: SSAOptimizationMetrics

    public init(
        functionAddress: VirtualAddress,
        functionName: String,
        demangledName: String,
        entryBlockID: Int,
        ssaBlocks: [MicroBasicBlock],
        inferredReturnType: CTypeExpr,
        inferredParameters: [NamedParameterDecl],
        parameterSSAVars: [SSAVar],
        variableTypes: [SSAVar: CTypeExpr],
        variableDisplayNames: [SSAVar: String],
        metrics: SSAOptimizationMetrics
    ) {
        self.functionAddress = functionAddress
        self.functionName = functionName
        self.demangledName = demangledName
        self.entryBlockID = entryBlockID
        self.ssaBlocks = ssaBlocks
        self.inferredReturnType = inferredReturnType
        self.inferredParameters = inferredParameters
        self.parameterSSAVars = parameterSSAVars
        self.variableTypes = variableTypes
        self.variableDisplayNames = variableDisplayNames
        self.metrics = metrics
    }
}

// MARK: - Canonical SSA Variable Key (Type/Width-Agnostic Identity)

internal struct SSAVarKey: Sendable, Hashable, Comparable, CustomStringConvertible {
    let baseName: String
    let version: Int

    init(_ variable: SSAVar) {
        self.baseName = variable.baseName
        self.version = variable.version
    }

    init(baseName: String, version: Int) {
        self.baseName = baseName
        self.version = version
    }

    var description: String {
        version == 0 ? baseName : "\(baseName)_\(version)"
    }

    static func < (lhs: SSAVarKey, rhs: SSAVarKey) -> Bool {
        if lhs.baseName != rhs.baseName {
            return lhs.baseName < rhs.baseName
        }
        return lhs.version < rhs.version
    }
}

// MARK: - Cytron-Ferrante-Rosen-Wegman-Zadeck SSA & Decompiler Optimizer Engine

public struct CytronSSAPhiAndOptimizerEngine: Sendable {
    public let configuration: SSAOptimizationConfiguration
    private let dominatorAnalyzer: DominatorAndLoopAnalyzer

    public init(configuration: SSAOptimizationConfiguration = .standard) {
        self.configuration = configuration
        self.dominatorAnalyzer = DominatorAndLoopAnalyzer()
    }

    // MARK: - Primary Entry Points

    /// Runs full Cytron SSA $\phi$-placement, dominator-tree variable renaming, iterative fixed-point algebraic/copy/inlining/DSE optimization, and forward/backward C type inference.
    public func buildSSAAndOptimize(
        lifted: LiftedFunctionIR,
        function: RecoveredFunction,
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> SSAOptimizedFunctionIR {
        guard !lifted.microBlocks.isEmpty else {
            let emptyRet = lifted.explicitReturnTypeHint ?? (lifted.returnsValue ? .intType(bits: lifted.returnBitWidth, signed: false) : .voidType)
            return SSAOptimizedFunctionIR(
                functionAddress: lifted.functionAddress,
                functionName: lifted.functionName,
                demangledName: lifted.demangledName,
                entryBlockID: 0,
                ssaBlocks: [],
                inferredReturnType: emptyRet,
                inferredParameters: [],
                parameterSSAVars: [],
                variableTypes: [:],
                variableDisplayNames: [:],
                metrics: SSAOptimizationMetrics()
            )
        }

        let entryID = function.blocks.first(where: \.isEntry)?.id ?? lifted.microBlocks[0].blockID

        // 1. Build Micro-IR CFG topology & Lengauer-Tarjan Dominator Tree
        let initialGraph = Self.deriveMicroCFG(from: lifted.microBlocks, fallbackEdges: function.edges, entryBlockID: entryID)
        let domTree = dominatorAnalyzer.computeDominatorTree(
            blocks: initialGraph.syntheticBasicBlocks,
            edges: initialGraph.edges,
            entryBlockID: entryID
        )

        // 2. Cytron Iterated Dominance Frontier Phi Placement + Dominator-Tree Variable Renaming
        let ssaConstructed = constructCytronSSA(
            blocks: lifted.microBlocks,
            entryBlockID: entryID,
            predecessorsByBlock: initialGraph.predecessors,
            successorsByBlock: initialGraph.successors,
            dominatorTree: domTree,
            liveInParameterRegs: lifted.detectedLiveInParameters,
            objcContext: lifted.objcContext
        )

        var workingBlocks = ssaConstructed.blocks
        var canonicalVarByKey = ssaConstructed.canonicalVarsByKey

        // 3. Iterative Decompiler Optimization Pipeline
        var totalConstProp = 0
        var totalCopyProp = 0
        var totalSingleUseInline = 0
        var totalAlgebraic = 0
        var totalDeadStoresEliminated = 0
        var passesExecuted = 0

        for _ in 0..<configuration.maxOptimizationIterations {
            passesExecuted += 1
            var roundChanged = false

            if configuration.enableConstantPropagation || configuration.enableAlgebraicSimplification {
                let constResult = runConstantAndAlgebraicPass(on: workingBlocks, entryBlockID: entryID)
                if constResult.changed {
                    workingBlocks = constResult.blocks
                    totalConstProp += constResult.propagatedConstants
                    totalAlgebraic += constResult.algebraicSimplifications
                    roundChanged = true
                }
            }

            if configuration.enableCopyPropagation {
                let copyResult = runCopyPropagationPass(on: workingBlocks)
                if copyResult.changed {
                    workingBlocks = copyResult.blocks
                    totalCopyProp += copyResult.propagatedCopies
                    roundChanged = true
                }
            }

            if configuration.enableSingleUseInlining {
                let inlineResult = runSingleUseForwardSubstitutionPass(on: workingBlocks)
                if inlineResult.changed {
                    workingBlocks = inlineResult.blocks
                    totalSingleUseInline += inlineResult.inlinedCount
                    roundChanged = true
                }
            }

            if configuration.enableDeadStoreElimination {
                let dseResult = runDeadAssignmentEliminationPass(on: workingBlocks, entryBlockID: entryID)
                if dseResult.changed {
                    workingBlocks = dseResult.blocks
                    totalDeadStoresEliminated += dseResult.eliminatedCount
                    roundChanged = true
                }
            }

            if !roundChanged {
                break
            }
        }

        // Refresh canonical variable inventory over surviving statements
        Self.collectVarsInBlocks(workingBlocks, into: &canonicalVarByKey)

        // 4. Forward & Backward C Type Inference + Parameter/Variable Naming
        let typeAndNameResult = inferTypesAndNames(
            blocks: workingBlocks,
            entryBlockID: entryID,
            lifted: lifted,
            canonicalVarsByKey: canonicalVarByKey,
            structDefinitions: structDefinitions
        )

        let rewrittenBlocks = Self.rewriteBlockVariableTypes(
            blocks: workingBlocks,
            resolvedVarsByKey: typeAndNameResult.resolvedVarsByKey
        )

        let metrics = SSAOptimizationMetrics(
            insertedPhiCount: ssaConstructed.insertedPhiCount,
            totalSSAVariableCount: typeAndNameResult.resolvedVarsByKey.count,
            propagatedConstantsCount: totalConstProp,
            propagatedCopiesCount: totalCopyProp,
            inlinedSingleUseCount: totalSingleUseInline,
            algebraicSimplificationsCount: totalAlgebraic,
            eliminatedDeadStoreCount: totalDeadStoresEliminated,
            optimizationPassesRun: passesExecuted
        )

        return SSAOptimizedFunctionIR(
            functionAddress: lifted.functionAddress,
            functionName: lifted.functionName,
            demangledName: lifted.demangledName,
            entryBlockID: entryID,
            ssaBlocks: rewrittenBlocks,
            inferredReturnType: typeAndNameResult.returnType,
            inferredParameters: typeAndNameResult.parameters,
            parameterSSAVars: typeAndNameResult.parameterSSAVars,
            variableTypes: typeAndNameResult.variableTypesByVar,
            variableDisplayNames: typeAndNameResult.displayNamesByVar,
            metrics: metrics
        )
    }

    /// Standalone entry point converting raw `[MicroBasicBlock]` directly into SSA-optimized `[MicroBasicBlock]`.
    public func constructAndOptimizeBlocks(
        _ microBlocks: [MicroBasicBlock],
        function: RecoveredFunction,
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> (blocks: [MicroBasicBlock], metrics: SSAOptimizationMetrics) {
        let syntheticLifted = LiftedFunctionIR(
            functionAddress: function.address,
            functionName: function.name,
            demangledName: function.demangledName,
            microBlocks: microBlocks,
            stackSlots: [],
            detectedLiveInParameters: [],
            returnsValue: true,
            returnBitWidth: 64,
            explicitReturnTypeHint: nil,
            objcContext: nil,
            prologueAnalysis: A64PrologueEpilogueAnalysis(
                hasPrologue: false,
                hasEpilogue: false,
                usesPAC: function.usesPAC,
                establishesFramePointer: false,
                stackFrameBytes: function.stackFrameBytes,
                savedRegisters: [],
                prologueAddresses: [],
                epilogueAddresses: [],
                isLeaf: function.isLeaf,
                isThunk: function.isThunk
            )
        )
        let res = buildSSAAndOptimize(lifted: syntheticLifted, function: function, structDefinitions: structDefinitions)
        return (res.ssaBlocks, res.metrics)
    }

    // MARK: - Phase 1: Cytron Iterated Dominance Frontier Phi Placement & Renaming

    private struct CytronConstructionResult {
        let blocks: [MicroBasicBlock]
        let insertedPhiCount: Int
        let canonicalVarsByKey: [SSAVarKey: SSAVar]
    }

    private func constructCytronSSA(
        blocks: [MicroBasicBlock],
        entryBlockID: Int,
        predecessorsByBlock: [Int: [Int]],
        successorsByBlock: [Int: [Int]],
        dominatorTree: [DominatorTreeNode],
        liveInParameterRegs: [A64Register],
        objcContext: ObjCMethodSignatureContext?
    ) -> CytronConstructionResult {
        var blockMap: [Int: MicroBasicBlock] = [:]
        for b in blocks {
            blockMap[b.blockID] = b
        }

        // 1. Compute variable liveness across Micro-IR blocks (for pruned SSA phi insertion)
        let liveInByBlock = Self.computeVariableLiveness(
            blocks: blocks,
            successorsByBlock: successorsByBlock
        )

        // 2. Collect def-sites and canonical template per base variable name
        var defBlocksByBase: [String: Set<Int>] = [:]
        var templateByBase: [String: SSAVar] = [:]

        // Seed entry parameter definitions on `entryBlockID`
        for (idx, reg) in liveInParameterRegs.enumerated() {
            let base = ARM64ToMicroIRLifter.canonicalBaseName(for: reg)
            let initType: CTypeExpr
            if let objc = objcContext, idx < objc.parameterTypes.count {
                initType = objc.parameterTypes[idx]
            } else {
                initType = reg.isSIMD
                    ? .floatType(bits: min(64, max(32, reg.bitWidth)))
                    : .intType(bits: reg.bitWidth, signed: false)
            }
            let paramVar = SSAVar(baseName: base, version: 0, bitWidth: reg.bitWidth, inferredType: initType)
            templateByBase[base] = paramVar
            defBlocksByBase[base, default: []].insert(entryBlockID)
        }

        for base in liveInByBlock[entryBlockID] ?? [] {
            defBlocksByBase[base, default: []].insert(entryBlockID)
        }

        for block in blocks {
            for stmt in block.statements {
                Self.harvestTemplateVars(in: stmt.kind, into: &templateByBase)
                if case .assign(let dest, _) = stmt.kind {
                    defBlocksByBase[dest.baseName, default: []].insert(block.blockID)
                }
            }
        }

        // 3. Place minimal Phi-nodes at Iterated Dominance Frontiers (`DF^+(DefSites)`)
        var phiBasesByBlock: [Int: [String]] = [:]
        var insertedPhiCount = 0

        for baseName in defBlocksByBase.keys.sorted() {
            guard let defBlocks = defBlocksByBase[baseName], !defBlocks.isEmpty else { continue }
            let idfBlocks = dominatorAnalyzer.iteratedDominanceFrontier(
                forDefinitionBlocks: defBlocks,
                dominatorTree: dominatorTree
            )
            for frontierID in idfBlocks {
                let preds = predecessorsByBlock[frontierID] ?? []
                guard preds.count >= 2 else { continue }
                if configuration.enablePrunedPhiPlacement {
                    guard (liveInByBlock[frontierID] ?? []).contains(baseName) else { continue }
                }
                phiBasesByBlock[frontierID, default: []].append(baseName)
                insertedPhiCount += 1
            }
        }

        for (bID, phiBases) in phiBasesByBlock {
            guard let origBlock = blockMap[bID] else { continue }
            var newStmts: [MicroStmt] = []
            newStmts.reserveCapacity(phiBases.count + origBlock.statements.count)
            for base in phiBases {
                let tmpl = templateByBase[base] ?? SSAVar(baseName: base, version: 0, bitWidth: 64)
                let placeholderDest = SSAVar(
                    baseName: base,
                    version: 0,
                    bitWidth: tmpl.bitWidth,
                    inferredType: tmpl.inferredType
                )
                newStmts.append(
                    MicroStmt(
                        originAddress: origBlock.startAddress,
                        kind: .assign(dest: placeholderDest, expr: .phi([]))
                    )
                )
            }
            newStmts.append(contentsOf: origBlock.statements)
            blockMap[bID] = MicroBasicBlock(
                blockID: origBlock.blockID,
                startAddress: origBlock.startAddress,
                statements: newStmts
            )
        }

        // 4. Dominator-Tree Recursive Variable Renaming & Phi Incoming Wiring
        var domChildrenByBlock: [Int: [Int]] = [:]
        for node in dominatorTree {
            domChildrenByBlock[node.blockID] = node.dominatedChildrenIDs
        }

        var nextVersionByBase: [String: Int] = [:]
        var stackByBase: [String: [SSAVar]] = [:]
        var canonicalVarsByKey: [SSAVarKey: SSAVar] = [:]

        // Initialize version 0 on every known variable stack so live-in parameters & uninitialized reads resolve to `v_0`
        for (base, tmpl) in templateByBase {
            let v0 = SSAVar(baseName: base, version: 0, bitWidth: tmpl.bitWidth, inferredType: tmpl.inferredType)
            stackByBase[base] = [v0]
            nextVersionByBase[base] = 1
            canonicalVarsByKey[SSAVarKey(v0)] = v0
        }

        // Track accumulated PhiIncoming operands keyed by `(targetBlockID, stmtIndex)`
        var phiIncomingsBySlot: [Int: [Int: [PhiIncoming]]] = [:]
        var visitedDomBlocks = Set<Int>()

        func allocateFreshVersion(for origDest: SSAVar) -> SSAVar {
            let base = origDest.baseName
            let ver = nextVersionByBase[base] ?? 1
            nextVersionByBase[base] = ver + 1
            let fresh = SSAVar(
                baseName: base,
                version: ver,
                bitWidth: origDest.bitWidth,
                inferredType: origDest.inferredType
            )
            stackByBase[base, default: []].append(fresh)
            canonicalVarsByKey[SSAVarKey(fresh)] = fresh
            return fresh
        }

        func currentReachingVar(for orig: SSAVar) -> SSAVar {
            if let top = stackByBase[orig.baseName]?.last {
                return top
            }
            let fallback = SSAVar(
                baseName: orig.baseName,
                version: 0,
                bitWidth: orig.bitWidth,
                inferredType: orig.inferredType
            )
            stackByBase[orig.baseName] = [fallback]
            nextVersionByBase[orig.baseName] = max(nextVersionByBase[orig.baseName] ?? 1, 1)
            canonicalVarsByKey[SSAVarKey(fallback)] = fallback
            return fallback
        }

        func renameExpr(_ expr: MicroExpr) -> MicroExpr {
            switch expr {
            case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
                return expr
            case .variable(let v):
                return .variable(currentReachingVar(for: v))
            case .unary(let op, let sub):
                return .unary(op, renameExpr(sub))
            case .binary(let op, let lhs, let rhs):
                return .binary(op, renameExpr(lhs), renameExpr(rhs))
            case .load(let addr, let bits, let ty):
                return .load(address: renameExpr(addr), bits: bits, type: ty)
            case .call(let target, let args, let retTy):
                return .call(target: renameExpr(target), arguments: args.map(renameExpr), returnType: retTy)
            case .phi:
                return expr
            case .cast(let sub, let ty):
                return .cast(renameExpr(sub), to: ty)
            case .ternary(let c, let t, let e):
                return .ternary(condition: renameExpr(c), thenExpr: renameExpr(t), elseExpr: renameExpr(e))
            }
        }

        func renameDFS(_ blockID: Int) {
            guard visitedDomBlocks.insert(blockID).inserted,
                  let block = blockMap[blockID] else { return }

            var pushedBases: [String] = []
            var renamedStmts = block.statements

            // Step A: Rename LHS destinations of all Phi statements at top of `block`
            for idx in renamedStmts.indices {
                if case .assign(let dest, .phi(let existing)) = renamedStmts[idx].kind {
                    let freshDest = allocateFreshVersion(for: dest)
                    pushedBases.append(dest.baseName)
                    renamedStmts[idx] = MicroStmt(
                        id: renamedStmts[idx].id,
                        originAddress: renamedStmts[idx].originAddress,
                        kind: .assign(dest: freshDest, expr: .phi(existing))
                    )
                } else {
                    break
                }
            }

            // Step B: Rename ordinary statements sequentially (RHS uses BEFORE LHS definition!)
            for idx in renamedStmts.indices {
                let stmt = renamedStmts[idx]
                switch stmt.kind {
                case .assign(_, .phi):
                    continue

                case .assign(let dest, let rhs):
                    let newRHS = renameExpr(rhs)
                    let freshDest = allocateFreshVersion(for: dest)
                    pushedBases.append(dest.baseName)
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .assign(dest: freshDest, expr: newRHS)
                    )

                case .store(let addr, let val, let bits):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .store(address: renameExpr(addr), value: renameExpr(val), bits: bits)
                    )

                case .callStmt(let target, let args):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .callStmt(target: renameExpr(target), arguments: args.map(renameExpr))
                    )

                case .conditionalBranch(let cond, let tID, let fID):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .conditionalBranch(condition: renameExpr(cond), trueBlockID: tID, falseBlockID: fID)
                    )

                case .switchJump(let sel, let cases, let defID):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .switchJump(selector: renameExpr(sel), cases: cases, defaultBlockID: defID)
                    )

                case .returnStmt(let val):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .returnStmt(value: val.map(renameExpr))
                    )

                case .intrinsic(let name, let args):
                    renamedStmts[idx] = MicroStmt(
                        id: stmt.id,
                        originAddress: stmt.originAddress,
                        kind: .intrinsic(name: name, arguments: args.map(renameExpr))
                    )

                case .jump, .nop:
                    break
                }
            }

            blockMap[blockID] = MicroBasicBlock(
                blockID: block.blockID,
                startAddress: block.startAddress,
                statements: renamedStmts
            )

            // Step C: Populate `PhiIncoming` operands in all immediate CFG successors of `blockID`
            for succID in successorsByBlock[blockID] ?? [] {
                guard let succBlock = blockMap[succID] else { continue }
                for (sIdx, succStmt) in succBlock.statements.enumerated() {
                    guard case .assign(let phiDest, .phi) = succStmt.kind else { break }
                    let reaching = currentReachingVar(for: phiDest)
                    var slotMap = phiIncomingsBySlot[succID] ?? [:]
                    var list = slotMap[sIdx] ?? []
                    if !list.contains(where: { $0.predecessorBlockID == blockID }) {
                        list.append(PhiIncoming(predecessorBlockID: blockID, variable: reaching))
                    }
                    slotMap[sIdx] = list
                    phiIncomingsBySlot[succID] = slotMap
                }
            }

            // Step D: Recurse into dominated children in deterministic block ID order
            for childID in domChildrenByBlock[blockID] ?? [] {
                renameDFS(childID)
            }

            // Step E: Pop versions pushed by `blockID`
            for base in pushedBases.reversed() {
                _ = stackByBase[base]?.popLast()
            }
        }

        renameDFS(entryBlockID)
        // Also rename any unreachable orphan blocks deterministically so every block has valid SSA variables
        for b in blocks where !visitedDomBlocks.contains(b.blockID) {
            renameDFS(b.blockID)
        }

        // Materialize accumulated `PhiIncoming` arrays into all `.phi` statements
        var finalBlocks: [MicroBasicBlock] = []
        finalBlocks.reserveCapacity(blocks.count)
        for orig in blocks {
            guard let b = blockMap[orig.blockID] else { continue }
            if let slotMap = phiIncomingsBySlot[b.blockID], !slotMap.isEmpty {
                var stmts = b.statements
                for (sIdx, incomings) in slotMap where sIdx < stmts.count {
                    if case .assign(let phiDest, .phi) = stmts[sIdx].kind {
                        let sortedInc = incomings.sorted { $0.predecessorBlockID < $1.predecessorBlockID }
                        stmts[sIdx] = MicroStmt(
                            id: stmts[sIdx].id,
                            originAddress: stmts[sIdx].originAddress,
                            kind: .assign(dest: phiDest, expr: .phi(sortedInc))
                        )
                    }
                }
                finalBlocks.append(MicroBasicBlock(blockID: b.blockID, startAddress: b.startAddress, statements: stmts))
            } else {
                finalBlocks.append(b)
            }
        }

        return CytronConstructionResult(
            blocks: finalBlocks,
            insertedPhiCount: insertedPhiCount,
            canonicalVarsByKey: canonicalVarsByKey
        )
    }

    // MARK: - Phase 2A: Constant Propagation & Algebraic Simplification

    private func runConstantAndAlgebraicPass(
        on blocks: [MicroBasicBlock],
        entryBlockID: Int
    ) -> (blocks: [MicroBasicBlock], changed: Bool, propagatedConstants: Int, algebraicSimplifications: Int) {
        // Harvest all SSA definitions that directly bind a compile-time constant / string / symbol
        var knownConstByVar: [SSAVarKey: MicroExpr] = [:]
        for block in blocks {
            for stmt in block.statements {
                if case .assign(let dest, let expr) = stmt.kind, Self.isPropagatableConstant(expr) {
                    knownConstByVar[SSAVarKey(dest)] = expr
                }
            }
        }

        // Note: Do NOT substitute constants directly into `PhiIncoming` (which holds `SSAVar`),
        // AND do NOT overwrite variables that participate as `PhiIncoming` operands if their constant differs across arms;
        // substituting constants at every `MicroExpr.variable(v)` read site is 100% SSA-safe!
        var constCount = 0
        var algCount = 0
        var anyChanged = false
        var prunedPredecessorEdges: [(from: Int, removedTarget: Int)] = []

        func rewrite(_ expr: MicroExpr) -> MicroExpr {
            let substituted: MicroExpr
            switch expr {
            case .variable(let v):
                if configuration.enableConstantPropagation, let c = knownConstByVar[SSAVarKey(v)] {
                    constCount += 1
                    anyChanged = true
                    return c
                }
                return expr

            case .unary(let op, let sub):
                substituted = .unary(op, rewrite(sub))

            case .binary(let op, let lhs, let rhs):
                substituted = .binary(op, rewrite(lhs), rewrite(rhs))

            case .load(let addr, let bits, let ty):
                substituted = .load(address: rewrite(addr), bits: bits, type: ty)

            case .call(let tgt, let args, let retTy):
                substituted = .call(target: rewrite(tgt), arguments: args.map(rewrite), returnType: retTy)

            case .cast(let sub, let ty):
                substituted = .cast(rewrite(sub), to: ty)

            case .ternary(let c, let t, let e):
                substituted = .ternary(condition: rewrite(c), thenExpr: rewrite(t), elseExpr: rewrite(e))

            case .phi(let incomings):
                // Fold trivial phi: `v = phi(u)` or `v = phi(v, u, u)` or all arms equal same constant
                let simplified = simplifyPhi(incomings, selfVar: nil, knownConstByVar: knownConstByVar)
                if let simplified {
                    algCount += 1
                    anyChanged = true
                    return simplified
                }
                return expr

            case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
                return expr
            }

            guard configuration.enableAlgebraicSimplification else {
                return substituted
            }
            let folded = Self.algebraicallySimplify(substituted)
            if folded != substituted {
                algCount += 1
                anyChanged = true
            }
            return folded
        }

        var updatedBlocks: [MicroBasicBlock] = []
        updatedBlocks.reserveCapacity(blocks.count)

        for block in blocks {
            var newStmts: [MicroStmt] = []
            newStmts.reserveCapacity(block.statements.count)

            for stmt in block.statements {
                switch stmt.kind {
                case .assign(let dest, .phi(let incomings)):
                    if let collapsed = simplifyPhi(incomings, selfVar: SSAVarKey(dest), knownConstByVar: knownConstByVar) {
                        algCount += 1
                        anyChanged = true
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: collapsed)))
                    } else {
                        newStmts.append(stmt)
                    }

                case .assign(let dest, let expr):
                    let nextExpr = rewrite(expr)
                    if configuration.enableConstantPropagation && Self.isPropagatableConstant(nextExpr) {
                        knownConstByVar[SSAVarKey(dest)] = nextExpr
                    }
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: nextExpr)))

                case .store(let addr, let val, let bits):
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .store(address: rewrite(addr), value: rewrite(val), bits: bits)))

                case .callStmt(let tgt, let args):
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .callStmt(target: rewrite(tgt), arguments: args.map(rewrite))))

                case .conditionalBranch(let cond, let tID, let fID):
                    let nextCond = rewrite(cond)
                    if tID == fID {
                        anyChanged = true
                        algCount += 1
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .jump(targetBlockID: tID)))
                    } else if let constBool = Self.evaluateConstantTruthiness(nextCond) {
                        anyChanged = true
                        algCount += 1
                        let winner = constBool ? tID : fID
                        let loser = constBool ? fID : tID
                        prunedPredecessorEdges.append((from: block.blockID, removedTarget: loser))
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .jump(targetBlockID: winner)))
                    } else {
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .conditionalBranch(condition: nextCond, trueBlockID: tID, falseBlockID: fID)))
                    }

                case .switchJump(let sel, let cases, let defID):
                    let nextSel = rewrite(sel)
                    if let constVal = Self.extractSignedInt64Constant(nextSel) {
                        let matchedTarget = cases.first(where: { $0.caseValue == constVal })?.targetBlockID ?? defID
                        for c in cases where c.targetBlockID != matchedTarget {
                            prunedPredecessorEdges.append((from: block.blockID, removedTarget: c.targetBlockID))
                        }
                        if defID != matchedTarget {
                            prunedPredecessorEdges.append((from: block.blockID, removedTarget: defID))
                        }
                        anyChanged = true
                        algCount += 1
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .jump(targetBlockID: matchedTarget)))
                    } else {
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .switchJump(selector: nextSel, cases: cases, defaultBlockID: defID)))
                    }

                case .returnStmt(let val):
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .returnStmt(value: val.map(rewrite))))

                case .intrinsic(let name, let args):
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .intrinsic(name: name, arguments: args.map(rewrite))))

                case .jump, .nop:
                    newStmts.append(stmt)
                }
            }

            updatedBlocks.append(MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: newStmts))
        }

        // If constant branch folding detached edges, prune unreachable blocks & stale `PhiIncoming` entries
        if !prunedPredecessorEdges.isEmpty {
            updatedBlocks = Self.pruneDeadCFGEdgesAndBlocks(updatedBlocks, entryBlockID: entryBlockID)
        }

        return (updatedBlocks, anyChanged, constCount, algCount)
    }

    private func simplifyPhi(
        _ incomings: [PhiIncoming],
        selfVar: SSAVarKey?,
        knownConstByVar: [SSAVarKey: MicroExpr]
    ) -> MicroExpr? {
        guard !incomings.isEmpty else { return nil }
        let nonSelf = incomings.filter { SSAVarKey($0.variable) != selfVar }
        guard let first = nonSelf.first else { return nil }

        // Check if every non-self incoming is the exact same SSA variable
        let firstKey = SSAVarKey(first.variable)
        if nonSelf.allSatisfy({ SSAVarKey($0.variable) == firstKey }) {
            return .variable(first.variable)
        }

        // Check if every non-self incoming resolves to the exact same constant expression
        if configuration.enableConstantPropagation, let firstConst = knownConstByVar[firstKey] {
            let allSameConst = nonSelf.allSatisfy { inc in
                knownConstByVar[SSAVarKey(inc.variable)] == firstConst
            }
            if allSameConst {
                return firstConst
            }
        }

        return nil
    }

    // MARK: - Phase 2B: Transitive Copy Propagation

    private func runCopyPropagationPass(
        on blocks: [MicroBasicBlock]
    ) -> (blocks: [MicroBasicBlock], changed: Bool, propagatedCopies: Int) {
        var directCopyMap: [SSAVarKey: SSAVar] = [:]
        for block in blocks {
            for stmt in block.statements {
                if case .assign(let dest, .variable(let src)) = stmt.kind {
                    let dstKey = SSAVarKey(dest)
                    let srcKey = SSAVarKey(src)
                    if dstKey != srcKey {
                        directCopyMap[dstKey] = src
                    }
                }
            }
        }

        guard !directCopyMap.isEmpty else {
            return (blocks, false, 0)
        }

        func resolveCopy(_ v: SSAVar) -> SSAVar {
            var current = v
            var visited = Set<SSAVarKey>([SSAVarKey(v)])
            while let next = directCopyMap[SSAVarKey(current)] {
                let nextKey = SSAVarKey(next)
                if !visited.insert(nextKey).inserted {
                    break
                }
                current = next
            }
            return current
        }

        var count = 0
        var changed = false

        func rewriteExpr(_ expr: MicroExpr) -> MicroExpr {
            switch expr {
            case .variable(let v):
                let resolved = resolveCopy(v)
                if SSAVarKey(resolved) != SSAVarKey(v) {
                    count += 1
                    changed = true
                    return .variable(resolved)
                }
                return expr
            case .unary(let op, let sub):
                return .unary(op, rewriteExpr(sub))
            case .binary(let op, let lhs, let rhs):
                return .binary(op, rewriteExpr(lhs), rewriteExpr(rhs))
            case .load(let addr, let bits, let ty):
                return .load(address: rewriteExpr(addr), bits: bits, type: ty)
            case .call(let tgt, let args, let retTy):
                return .call(target: rewriteExpr(tgt), arguments: args.map(rewriteExpr), returnType: retTy)
            case .phi(let incomings):
                var phiChanged = false
                let updated = incomings.map { inc -> PhiIncoming in
                    let resolved = resolveCopy(inc.variable)
                    if SSAVarKey(resolved) != SSAVarKey(inc.variable) {
                        phiChanged = true
                        count += 1
                        changed = true
                        return PhiIncoming(predecessorBlockID: inc.predecessorBlockID, variable: resolved)
                    }
                    return inc
                }
                return phiChanged ? .phi(updated) : expr
            case .cast(let sub, let ty):
                return .cast(rewriteExpr(sub), to: ty)
            case .ternary(let c, let t, let e):
                return .ternary(condition: rewriteExpr(c), thenExpr: rewriteExpr(t), elseExpr: rewriteExpr(e))
            case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
                return expr
            }
        }

        let newBlocks = blocks.map { block in
            let stmts = block.statements.map { stmt -> MicroStmt in
                switch stmt.kind {
                case .assign(let dest, let expr):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: rewriteExpr(expr)))
                case .store(let addr, let val, let bits):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .store(address: rewriteExpr(addr), value: rewriteExpr(val), bits: bits))
                case .callStmt(let tgt, let args):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .callStmt(target: rewriteExpr(tgt), arguments: args.map(rewriteExpr)))
                case .conditionalBranch(let cond, let tID, let fID):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .conditionalBranch(condition: rewriteExpr(cond), trueBlockID: tID, falseBlockID: fID))
                case .switchJump(let sel, let cases, let defID):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .switchJump(selector: rewriteExpr(sel), cases: cases, defaultBlockID: defID))
                case .returnStmt(let val):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .returnStmt(value: val.map(rewriteExpr)))
                case .intrinsic(let name, let args):
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .intrinsic(name: name, arguments: args.map(rewriteExpr)))
                case .jump, .nop:
                    return stmt
                }
            }
            return MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: stmts)
        }

        return (newBlocks, changed, count)
    }

    // MARK: - Phase 2C: Controlled Single-Use Expression Forward Substitution

    private struct UseLocation {
        let blockIndex: Int
        let stmtIndex: Int
        let inPhi: Bool
    }

    private func runSingleUseForwardSubstitutionPass(
        on blocks: [MicroBasicBlock]
    ) -> (blocks: [MicroBasicBlock], changed: Bool, inlinedCount: Int) {
        // Count every read occurrence of every SSAVarKey across all blocks
        var useCountByVar: [SSAVarKey: Int] = [:]
        var singleUseLocation: [SSAVarKey: UseLocation] = [:]

        for (bIdx, block) in blocks.enumerated() {
            for (sIdx, stmt) in block.statements.enumerated() {
                if case .assign(_, .phi(let incomings)) = stmt.kind {
                    for inc in incomings {
                        let k = SSAVarKey(inc.variable)
                        useCountByVar[k, default: 0] += 1
                        singleUseLocation[k] = UseLocation(blockIndex: bIdx, stmtIndex: sIdx, inPhi: true)
                    }
                } else {
                    Self.forEachReadVar(in: stmt.kind) { v in
                        let k = SSAVarKey(v)
                        useCountByVar[k, default: 0] += 1
                        singleUseLocation[k] = UseLocation(blockIndex: bIdx, stmtIndex: sIdx, inPhi: false)
                    }
                }
            }
        }

        // Collect candidate single-use definitions that are safe & readable to forward-substitute
        var inlineExprByVar: [SSAVarKey: MicroExpr] = [:]
        var consumedDefLocations = Set<String>()

        for (bIdx, block) in blocks.enumerated() {
            for (sIdx, stmt) in block.statements.enumerated() {
                guard case .assign(let dest, let rhs) = stmt.kind else { continue }
                // Keep explicit user-meaningful stack slots (`local_*`) as named local variables unless pure copy
                if dest.baseName.hasPrefix("local_") || dest.baseName.hasPrefix("self->") {
                    continue
                }
                if case .phi = rhs { continue }

                let key = SSAVarKey(dest)
                guard useCountByVar[key] == 1,
                      let useLoc = singleUseLocation[key],
                      !useLoc.inPhi else {
                    continue
                }

                // Prevent substituting into an expression if `rhs` itself depends on a variable already being consumed in this pass
                let rhsComplexity = Self.expressionNodeCount(rhs)
                guard rhsComplexity <= 18 else { continue }

                let hasCall = Self.containsCall(rhs)
                let hasLoad = Self.containsLoad(rhs)

                if !hasCall && !hasLoad {
                    // Pure arithmetic/relational/constant expression: safe to inline anywhere outside `.phi`
                    inlineExprByVar[key] = rhs
                    consumedDefLocations.insert("\(bIdx):\(sIdx)")
                } else if hasLoad && !hasCall {
                    // Memory load: safe to inline within the SAME basic block if no intervening memory write or call occurs
                    guard useLoc.blockIndex == bIdx && useLoc.stmtIndex > sIdx else { continue }
                    let interveningSafe = ((sIdx + 1)..<useLoc.stmtIndex).allSatisfy { midIdx in
                        !Self.statementHasMemoryOrCallSideEffect(block.statements[midIdx].kind)
                    }
                    if interveningSafe {
                        inlineExprByVar[key] = rhs
                        consumedDefLocations.insert("\(bIdx):\(sIdx)")
                    }
                } else if case .call = rhs {
                    // Direct call result: inline ONLY into `.conditionalBranch`, `.switchJump`, or `.returnStmt`
                    // in the SAME basic block when no intervening memory/call side effects exist!
                    guard useLoc.blockIndex == bIdx && useLoc.stmtIndex > sIdx else { continue }
                    let targetStmtKind = block.statements[useLoc.stmtIndex].kind
                    let isControlOrReturnConsumer: Bool
                    switch targetStmtKind {
                    case .conditionalBranch, .switchJump, .returnStmt:
                        isControlOrReturnConsumer = true
                    default:
                        isControlOrReturnConsumer = false
                    }
                    guard isControlOrReturnConsumer else { continue }
                    let interveningSafe = ((sIdx + 1)..<useLoc.stmtIndex).allSatisfy { midIdx in
                        !Self.statementHasMemoryOrCallSideEffect(block.statements[midIdx].kind)
                    }
                    if interveningSafe {
                        inlineExprByVar[key] = rhs
                        consumedDefLocations.insert("\(bIdx):\(sIdx)")
                    }
                }
            }
        }

        guard !inlineExprByVar.isEmpty else {
            return (blocks, false, 0)
        }

        var inlinedCount = 0

        func substituteExpr(_ expr: MicroExpr, depth: Int = 0) -> MicroExpr {
            guard depth < 12 else { return expr }
            switch expr {
            case .variable(let v):
                let k = SSAVarKey(v)
                if let replacement = inlineExprByVar[k] {
                    inlinedCount += 1
                    return Self.algebraicallySimplify(substituteExpr(replacement, depth: depth + 1))
                }
                return expr
            case .unary(let op, let sub):
                return Self.algebraicallySimplify(.unary(op, substituteExpr(sub, depth: depth + 1)))
            case .binary(let op, let lhs, let rhs):
                return Self.algebraicallySimplify(.binary(op, substituteExpr(lhs, depth: depth + 1), substituteExpr(rhs, depth: depth + 1)))
            case .load(let addr, let bits, let ty):
                return .load(address: substituteExpr(addr, depth: depth + 1), bits: bits, type: ty)
            case .call(let tgt, let args, let retTy):
                return .call(
                    target: substituteExpr(tgt, depth: depth + 1),
                    arguments: args.map { substituteExpr($0, depth: depth + 1) },
                    returnType: retTy
                )
            case .phi:
                return expr
            case .cast(let sub, let ty):
                return .cast(substituteExpr(sub, depth: depth + 1), to: ty)
            case .ternary(let c, let t, let e):
                return Self.algebraicallySimplify(
                    .ternary(
                        condition: substituteExpr(c, depth: depth + 1),
                        thenExpr: substituteExpr(t, depth: depth + 1),
                        elseExpr: substituteExpr(e, depth: depth + 1)
                    )
                )
            case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
                return expr
            }
        }

        // Only remove a consumed definition if its variable was actually substituted (guards chained single-use order)
        var substitutedKeys = Set<SSAVarKey>()
        func trackSubstituted(_ expr: MicroExpr) {
            switch expr {
            case .variable(let v):
                let k = SSAVarKey(v)
                if let rep = inlineExprByVar[k], substitutedKeys.insert(k).inserted {
                    trackSubstituted(rep)
                }
            case .unary(_, let s): trackSubstituted(s)
            case .binary(_, let l, let r): trackSubstituted(l); trackSubstituted(r)
            case .load(let a, _, _): trackSubstituted(a)
            case .call(let t, let args, _): trackSubstituted(t); args.forEach(trackSubstituted)
            case .cast(let s, _): trackSubstituted(s)
            case .ternary(let c, let t, let e): trackSubstituted(c); trackSubstituted(t); trackSubstituted(e)
            case .phi, .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef: break
            }
        }

        // Pre-pass: substitute across non-consumed statements first
        var newBlocks: [MicroBasicBlock] = []
        newBlocks.reserveCapacity(blocks.count)

        for (bIdx, block) in blocks.enumerated() {
            var newStmts: [MicroStmt] = []
            newStmts.reserveCapacity(block.statements.count)

            for (sIdx, stmt) in block.statements.enumerated() {
                if consumedDefLocations.contains("\(bIdx):\(sIdx)"),
                   case .assign(let dest, _) = stmt.kind {
                    // Defer removal to DSE or remove right after confirming substitution
                    let _ = dest
                }
                switch stmt.kind {
                case .assign(let dest, .phi):
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: {
                        if case .assign(_, let e) = stmt.kind { return e }
                        return .nopPlaceholder
                    }())))
                case .assign(let dest, let rhs):
                    if inlineExprByVar[SSAVarKey(dest)] != nil {
                        // Keep temporarily; if `dest` is substituted into its consumer below, DSE removes it cleanly without counting as dead store, OR we strip substituted ones right below!
                        newStmts.append(stmt)
                    } else {
                        trackSubstituted(rhs)
                        newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: substituteExpr(rhs))))
                    }
                case .store(let addr, let val, let bits):
                    trackSubstituted(addr); trackSubstituted(val)
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .store(address: substituteExpr(addr), value: substituteExpr(val), bits: bits)))
                case .callStmt(let tgt, let args):
                    trackSubstituted(tgt); args.forEach(trackSubstituted)
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .callStmt(target: substituteExpr(tgt), arguments: args.map { substituteExpr($0) })))
                case .conditionalBranch(let cond, let tID, let fID):
                    trackSubstituted(cond)
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .conditionalBranch(condition: substituteExpr(cond), trueBlockID: tID, falseBlockID: fID)))
                case .switchJump(let sel, let cases, let defID):
                    trackSubstituted(sel)
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .switchJump(selector: substituteExpr(sel), cases: cases, defaultBlockID: defID)))
                case .returnStmt(let val):
                    if let val { trackSubstituted(val) }
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .returnStmt(value: val.map { substituteExpr($0) })))
                case .intrinsic(let name, let args):
                    args.forEach(trackSubstituted)
                    newStmts.append(MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .intrinsic(name: name, arguments: args.map { substituteExpr($0) })))
                case .jump, .nop:
                    newStmts.append(stmt)
                }
            }

            // Strip definitions that were just inlined into their sole consumer
            if !substitutedKeys.isEmpty {
                newStmts.removeAll { s in
                    if case .assign(let dest, _) = s.kind {
                        return substitutedKeys.contains(SSAVarKey(dest))
                    }
                    return false
                }
            }

            newBlocks.append(MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: newStmts))
        }

        return (newBlocks, inlinedCount > 0, inlinedCount)
    }

    // MARK: - Phase 2D: Dead-Store & Unused SSA Assignment Elimination

    private func runDeadAssignmentEliminationPass(
        on blocks: [MicroBasicBlock],
        entryBlockID: Int
    ) -> (blocks: [MicroBasicBlock], changed: Bool, eliminatedCount: Int) {
        let prunedBlocks = Self.pruneDeadCFGEdgesAndBlocks(blocks, entryBlockID: entryBlockID)
        var eliminated = 0
        var changed = prunedBlocks.count != blocks.count

        // Count non-self uses of every variable across all surviving blocks
        var useCountByVar: [SSAVarKey: Int] = [:]
        for block in prunedBlocks {
            for stmt in block.statements {
                switch stmt.kind {
                case .assign(let dest, .phi(let incomings)):
                    let selfKey = SSAVarKey(dest)
                    for inc in incomings where SSAVarKey(inc.variable) != selfKey {
                        useCountByVar[SSAVarKey(inc.variable), default: 0] += 1
                    }
                default:
                    Self.forEachReadVar(in: stmt.kind) { v in
                        useCountByVar[SSAVarKey(v), default: 0] += 1
                    }
                }
            }
        }

        var nextBlocks: [MicroBasicBlock] = []
        nextBlocks.reserveCapacity(prunedBlocks.count)

        for block in prunedBlocks {
            var keptStmts: [MicroStmt] = []
            keptStmts.reserveCapacity(block.statements.count)

            for stmt in block.statements {
                switch stmt.kind {
                case .nop:
                    changed = true

                case .assign(let dest, let expr):
                    // Preserve ObjC ivar writes (`self->field = ...`) since they mutate heap object state!
                    if dest.baseName.hasPrefix("self->") {
                        keptStmts.append(stmt)
                        continue
                    }

                    let uses = useCountByVar[SSAVarKey(dest)] ?? 0
                    if uses == 0 {
                        if case .call(let target, let arguments, _) = expr {
                            // Convert dead return capture `x0_1 = puts(...)` into side-effect `.callStmt`
                            keptStmts.append(
                                MicroStmt(
                                    id: stmt.id,
                                    originAddress: stmt.originAddress,
                                    kind: .callStmt(target: target, arguments: arguments)
                                )
                            )
                            eliminated += 1
                            changed = true
                        } else if !Self.containsCall(expr) {
                            // Pure / load / phi dead assignment -> eliminate completely
                            eliminated += 1
                            changed = true
                        } else {
                            keptStmts.append(stmt)
                        }
                    } else {
                        keptStmts.append(stmt)
                    }

                default:
                    keptStmts.append(stmt)
                }
            }

            nextBlocks.append(MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: keptStmts))
        }

        return (nextBlocks, changed, eliminated)
    }

    // MARK: - Phase 3: Forward/Backward C Type Inference & Variable Naming

    private struct TypeAndNamingOutput {
        let returnType: CTypeExpr
        let parameters: [NamedParameterDecl]
        let parameterSSAVars: [SSAVar]
        let resolvedVarsByKey: [SSAVarKey: SSAVar]
        let variableTypesByVar: [SSAVar: CTypeExpr]
        let displayNamesByVar: [SSAVar: String]
    }

    private func inferTypesAndNames(
        blocks: [MicroBasicBlock],
        entryBlockID: Int,
        lifted: LiftedFunctionIR,
        canonicalVarsByKey: [SSAVarKey: SSAVar],
        structDefinitions: [String: CustomStructDefinition]
    ) -> TypeAndNamingOutput {
        let _ = entryBlockID
        var typeByKey: [SSAVarKey: CTypeExpr] = [:]
        var widthByKey: [SSAVarKey: Int] = [:]

        for (k, v) in canonicalVarsByKey {
            typeByKey[k] = v.inferredType
            widthByKey[k] = v.bitWidth
        }

        // Seed parameter types from ObjC method context or known C catalog (`main`, etc.)
        let cleanFnName = KnownFunctionSignatureCatalog.normalizeSymbolName(lifted.demangledName)
        let knownSelfProto = KnownFunctionSignatureCatalog.lookup(cleanFnName)

        var paramKeys: [SSAVarKey] = []
        for (idx, reg) in lifted.detectedLiveInParameters.enumerated() {
            let base = ARM64ToMicroIRLifter.canonicalBaseName(for: reg)
            let key = SSAVarKey(baseName: base, version: 0)
            paramKeys.append(key)
            widthByKey[key] = widthByKey[key] ?? reg.bitWidth

            if let objc = lifted.objcContext, idx < objc.parameterTypes.count {
                typeByKey[key] = objc.parameterTypes[idx]
            } else if let proto = knownSelfProto, idx < proto.fixedParameterTypes.count {
                typeByKey[key] = proto.fixedParameterTypes[idx]
            } else if typeByKey[key] == nil {
                typeByKey[key] = reg.isSIMD
                    ? .floatType(bits: min(64, max(32, reg.bitWidth)))
                    : .intType(bits: reg.bitWidth, signed: false)
            }
        }

        if configuration.enableTypeInference {
            // Fixed-point forward & backward constraint propagation (4 iterations suffices for deep chains)
            var observedOffsetsByBaseKey: [SSAVarKey: Set<Int>] = [:]

            for _ in 0..<4 {
                for block in blocks {
                    for stmt in block.statements {
                        propagateStatementTypes(
                            stmt.kind,
                            typeByKey: &typeByKey,
                            widthByKey: &widthByKey,
                            observedOffsetsByBaseKey: &observedOffsetsByBaseKey
                        )
                    }
                }

                // Match observed `[ptr + offset]` dereference clusters against analyst `CustomStructDefinition`s
                if !structDefinitions.isEmpty {
                    for (baseKey, offsets) in observedOffsetsByBaseKey where !offsets.isEmpty {
                        if let matchedStruct = Self.matchCustomStruct(offsets: offsets, in: structDefinitions) {
                            Self.refineType(&typeByKey, key: baseKey, candidate: .pointer(to: .structRef(name: matchedStruct.name)))
                        }
                    }
                }
            }
        }

        // Infer function return type from explicit hint, ObjC signature, or `returnStmt` expressions
        var returnType: CTypeExpr
        if let explicit = lifted.explicitReturnTypeHint {
            returnType = explicit
        } else if !lifted.returnsValue {
            returnType = .voidType
        } else {
            var joinedRet: CTypeExpr? = nil
            for block in blocks {
                for stmt in block.statements {
                    if case .returnStmt(let expr?) = stmt.kind {
                        let exprTy = inferExpressionType(expr, typeByKey: typeByKey)
                        joinedRet = joinedRet.map { Self.meetTypes($0, exprTy) } ?? exprTy
                    }
                }
            }
            returnType = joinedRet ?? .intType(bits: lifted.returnBitWidth, signed: false)
        }

        // Propagate `returnType` backward onto variables directly returned in `returnStmt`
        if returnType != .voidType && configuration.enableTypeInference {
            for block in blocks {
                for stmt in block.statements {
                    if case .returnStmt(.variable(let retVar)?) = stmt.kind {
                        Self.refineType(&typeByKey, key: SSAVarKey(retVar), candidate: returnType)
                    }
                }
            }
            // Re-propagate once through Phi webs feeding `returnStmt`
            for block in blocks {
                for stmt in block.statements {
                    if case .assign(let dest, .phi(let incomings)) = stmt.kind,
                       let destTy = typeByKey[SSAVarKey(dest)] {
                        for inc in incomings where inc.variable.version != 0 {
                            Self.refineType(&typeByKey, key: SSAVarKey(inc.variable), candidate: destTy)
                        }
                    }
                }
            }
        }

        // Rebuild canonical `SSAVar` dictionary with finalized `inferredType`
        var resolvedVarsByKey: [SSAVarKey: SSAVar] = [:]
        for (key, origVar) in canonicalVarsByKey {
            let finalType = typeByKey[key] ?? origVar.inferredType
            let finalBits = widthByKey[key] ?? origVar.bitWidth
            resolvedVarsByKey[key] = SSAVar(
                baseName: key.baseName,
                version: key.version,
                bitWidth: finalBits,
                inferredType: finalType
            )
        }
        for key in paramKeys where resolvedVarsByKey[key] == nil {
            let finalBits = widthByKey[key] ?? 64
            let finalType = typeByKey[key] ?? .intType(bits: finalBits, signed: false)
            resolvedVarsByKey[key] = SSAVar(
                baseName: key.baseName,
                version: 0,
                bitWidth: finalBits,
                inferredType: finalType
            )
        }

        // Assign clean, collision-free C parameter & variable names
        var displayNameByKey: [SSAVarKey: String] = [:]
        var usedNames = Set<String>()
        var namedParams: [NamedParameterDecl] = []
        var paramVars: [SSAVar] = []

        let selectorKeywords: [String] = {
            guard let objc = lifted.objcContext else { return [] }
            return objc.selector.split(separator: ":").map(String.init)
        }()

        for (idx, key) in paramKeys.enumerated() {
            let pVar = resolvedVarsByKey[key]!
            let pName: String
            if lifted.objcContext != nil {
                if idx == 0 {
                    pName = "self"
                } else if idx == 1 {
                    pName = "_cmd"
                } else {
                    let kwIdx = idx - 2
                    if kwIdx < selectorKeywords.count,
                       let derived = Self.deriveObjCParameterName(fromKeyword: selectorKeywords[kwIdx], fallbackIndex: idx),
                       !usedNames.contains(derived) {
                        pName = derived
                    } else {
                        pName = "arg\(idx)"
                    }
                }
            } else if cleanFnName == "main" && paramKeys.count == 2 {
                pName = (idx == 0) ? "argc" : "argv"
            } else {
                pName = "arg\(idx)"
            }

            usedNames.insert(pName)
            displayNameByKey[key] = pName
            namedParams.append(NamedParameterDecl(name: pName, type: pVar.inferredType))
            paramVars.append(pVar)
        }

        // Assign names for remaining SSA variables (deterministic order)
        var tempCounter = 1
        for key in resolvedVarsByKey.keys.sorted() where displayNameByKey[key] == nil {
            let candidate: String
            if key.baseName.hasPrefix("local_") || key.baseName.hasPrefix("arg_stack_") || key.baseName.hasPrefix("self->") {
                candidate = key.version <= 1 && !usedNames.contains(key.baseName)
                    ? key.baseName
                    : "\(key.baseName)_\(key.version)"
            } else if key.version == 0 {
                candidate = "in_\(key.baseName)"
            } else {
                var vName = "v\(tempCounter)"
                tempCounter += 1
                while usedNames.contains(vName) {
                    vName = "v\(tempCounter)"
                    tempCounter += 1
                }
                candidate = vName
            }
            usedNames.insert(candidate)
            displayNameByKey[key] = candidate
        }

        var variableTypesByVar: [SSAVar: CTypeExpr] = [:]
        var displayNamesByVar: [SSAVar: String] = [:]
        for (k, v) in resolvedVarsByKey {
            variableTypesByVar[v] = v.inferredType
            displayNamesByVar[v] = displayNameByKey[k] ?? v.displayName
        }

        return TypeAndNamingOutput(
            returnType: returnType,
            parameters: namedParams,
            parameterSSAVars: paramVars,
            resolvedVarsByKey: resolvedVarsByKey,
            variableTypesByVar: variableTypesByVar,
            displayNamesByVar: displayNamesByVar
        )
    }

    private func propagateStatementTypes(
        _ kind: MicroStmtKind,
        typeByKey: inout [SSAVarKey: CTypeExpr],
        widthByKey: inout [SSAVarKey: Int],
        observedOffsetsByBaseKey: inout [SSAVarKey: Set<Int>]
    ) {
        let _ = widthByKey
        switch kind {
        case .assign(let dest, let expr):
            let dstKey = SSAVarKey(dest)
            propagateExpressionBackwardConstraints(
                expr,
                expectedType: typeByKey[dstKey],
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )
            let rhsType = inferExpressionType(expr, typeByKey: typeByKey)
            Self.refineType(&typeByKey, key: dstKey, candidate: rhsType)

            if case .phi(let incomings) = expr, let merged = typeByKey[dstKey] {
                for inc in incomings where inc.variable.version != 0 {
                    Self.refineType(&typeByKey, key: SSAVarKey(inc.variable), candidate: merged)
                }
            }

        case .store(let addr, let val, let bits):
            let valType = inferExpressionType(val, typeByKey: typeByKey)
            let elemType = Self.isDefaultUntypedInt(valType) ? .intType(bits: bits, signed: false) : valType
            propagateAddressPointerConstraint(
                addr,
                elementType: elemType,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )
            propagateExpressionBackwardConstraints(
                val,
                expectedType: elemType,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .callStmt(let target, let args):
            propagateCallArgumentTypes(
                target: target,
                arguments: args,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .conditionalBranch(let cond, _, _):
            propagateExpressionBackwardConstraints(
                cond,
                expectedType: .boolType,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .switchJump(let sel, _, _):
            propagateExpressionBackwardConstraints(
                sel,
                expectedType: nil,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .returnStmt(let val?):
            propagateExpressionBackwardConstraints(
                val,
                expectedType: nil,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .returnStmt(nil), .intrinsic, .jump, .nop:
            break
        }
    }

    private func propagateExpressionBackwardConstraints(
        _ expr: MicroExpr,
        expectedType: CTypeExpr?,
        typeByKey: inout [SSAVarKey: CTypeExpr],
        observedOffsetsByBaseKey: inout [SSAVarKey: Set<Int>]
    ) {
        switch expr {
        case .variable(let v):
            if let expectedType {
                Self.refineType(&typeByKey, key: SSAVarKey(v), candidate: expectedType)
            }

        case .load(let addr, _, let loadType):
            propagateAddressPointerConstraint(
                addr,
                elementType: loadType,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .call(let target, let args, _):
            propagateCallArgumentTypes(
                target: target,
                arguments: args,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )

        case .binary(let op, let lhs, let rhs):
            switch op {
            case .signedLess, .signedLessEqual, .signedGreater, .signedGreaterEqual, .sdiv, .shiftRightArithmetic:
                if case .variable(let lv) = lhs {
                    let cur = typeByKey[SSAVarKey(lv)] ?? lv.inferredType
                    if case .intType(let b, false) = cur {
                        Self.refineType(&typeByKey, key: SSAVarKey(lv), candidate: .intType(bits: b, signed: true))
                    }
                }
                if case .variable(let rv) = rhs {
                    let cur = typeByKey[SSAVarKey(rv)] ?? rv.inferredType
                    if case .intType(let b, false) = cur {
                        Self.refineType(&typeByKey, key: SSAVarKey(rv), candidate: .intType(bits: b, signed: true))
                    }
                }
            default:
                break
            }
            propagateExpressionBackwardConstraints(lhs, expectedType: nil, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)
            propagateExpressionBackwardConstraints(rhs, expectedType: nil, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)

        case .unary(_, let sub):
            propagateExpressionBackwardConstraints(sub, expectedType: nil, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)

        case .cast(let sub, _):
            propagateExpressionBackwardConstraints(sub, expectedType: nil, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)

        case .ternary(let c, let t, let e):
            propagateExpressionBackwardConstraints(c, expectedType: .boolType, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)
            propagateExpressionBackwardConstraints(t, expectedType: expectedType, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)
            propagateExpressionBackwardConstraints(e, expectedType: expectedType, typeByKey: &typeByKey, observedOffsetsByBaseKey: &observedOffsetsByBaseKey)

        case .phi, .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
            break
        }
    }

    private func propagateAddressPointerConstraint(
        _ addrExpr: MicroExpr,
        elementType: CTypeExpr,
        typeByKey: inout [SSAVarKey: CTypeExpr],
        observedOffsetsByBaseKey: inout [SSAVarKey: Set<Int>]
    ) {
        switch addrExpr {
        case .variable(let baseVar):
            let key = SSAVarKey(baseVar)
            observedOffsetsByBaseKey[key, default: []].insert(0)
            Self.refineType(&typeByKey, key: key, candidate: .pointer(to: elementType))

        case .binary(.add, .variable(let lhsVar), let rhs):
            let lhsKey = SSAVarKey(lhsVar)
            if let constOff = Self.extractSignedInt64Constant(rhs), constOff >= 0 && constOff < 0x10000 {
                observedOffsetsByBaseKey[lhsKey, default: []].insert(Int(constOff))
                // Constant field offset: if offset == 0, refine element pointer; otherwise at least `void *` unless struct matches
                if constOff == 0 {
                    Self.refineType(&typeByKey, key: lhsKey, candidate: .pointer(to: elementType))
                } else {
                    Self.refineType(&typeByKey, key: lhsKey, candidate: .pointer(to: .voidType))
                }
            } else {
                // Array indexing `base + index`: `lhsVar` is pointer to `elementType`!
                Self.refineType(&typeByKey, key: lhsKey, candidate: .pointer(to: elementType))
            }

        default:
            break
        }
    }

    private func propagateCallArgumentTypes(
        target: MicroExpr,
        arguments: [MicroExpr],
        typeByKey: inout [SSAVarKey: CTypeExpr],
        observedOffsetsByBaseKey: inout [SSAVarKey: Set<Int>]
    ) {
        if case .symbolRef(let calleeName, _) = target {
            if calleeName == "objc_msgSend" {
                if let first = arguments.first, case .variable(let recvVar) = first {
                    Self.refineType(&typeByKey, key: SSAVarKey(recvVar), candidate: .objcObject(className: nil))
                }
                if arguments.count >= 2, case .variable(let selVar) = arguments[1] {
                    Self.refineType(&typeByKey, key: SSAVarKey(selVar), candidate: .cString)
                }
            } else if let proto = KnownFunctionSignatureCatalog.lookup(calleeName) {
                for (idx, paramType) in proto.fixedParameterTypes.enumerated() where idx < arguments.count {
                    if case .variable(let argVar) = arguments[idx] {
                        Self.refineType(&typeByKey, key: SSAVarKey(argVar), candidate: paramType)
                    }
                }
            }
        }

        for arg in arguments {
            propagateExpressionBackwardConstraints(
                arg,
                expectedType: nil,
                typeByKey: &typeByKey,
                observedOffsetsByBaseKey: &observedOffsetsByBaseKey
            )
        }
    }

    private func inferExpressionType(
        _ expr: MicroExpr,
        typeByKey: [SSAVarKey: CTypeExpr]
    ) -> CTypeExpr {
        switch expr {
        case .signedConst(_, let bits):
            return .intType(bits: bits, signed: true)
        case .unsignedConst(_, let bits):
            return bits == 1 ? .boolType : .intType(bits: bits, signed: false)
        case .floatConst:
            return .floatType(bits: 64)
        case .stringLiteral:
            return .cString
        case .symbolRef(let name, _):
            if name.hasPrefix("&") {
                return .pointer(to: .voidType)
            }
            return .intType(bits: 64, signed: false)
        case .variable(let v):
            return typeByKey[SSAVarKey(v)] ?? v.inferredType
        case .unary(let op, let sub):
            switch op {
            case .logicalNot:
                return .boolType
            case .negate, .signExtend:
                let subTy = inferExpressionType(sub, typeByKey: typeByKey)
                if case .intType(let b, _) = subTy {
                    return .intType(bits: op == .signExtend ? 64 : b, signed: true)
                }
                return .intType(bits: 64, signed: true)
            case .zeroExtend:
                return .intType(bits: 64, signed: false)
            case .bitwiseNot, .byteSwap:
                return inferExpressionType(sub, typeByKey: typeByKey)
            }
        case .binary(let op, let lhs, let rhs):
            switch op {
            case .equal, .notEqual,
                 .unsignedLess, .unsignedLessEqual, .unsignedGreater, .unsignedGreaterEqual,
                 .signedLess, .signedLessEqual, .signedGreater, .signedGreaterEqual,
                 .logicalAnd, .logicalOr:
                return .boolType
            case .add, .sub:
                let lTy = inferExpressionType(lhs, typeByKey: typeByKey)
                let rTy = inferExpressionType(rhs, typeByKey: typeByKey)
                if Self.isPointerLike(lTy) && !Self.isPointerLike(rTy) {
                    return lTy
                }
                if op == .add && Self.isPointerLike(rTy) && !Self.isPointerLike(lTy) {
                    return rTy
                }
                return Self.meetTypes(lTy, rTy)
            case .sdiv, .shiftRightArithmetic:
                let lTy = inferExpressionType(lhs, typeByKey: typeByKey)
                if case .intType(let b, _) = lTy {
                    return .intType(bits: b, signed: true)
                }
                return lTy
            default:
                return inferExpressionType(lhs, typeByKey: typeByKey)
            }
        case .load(_, _, let loadType):
            return loadType
        case .call(_, _, let retType):
            return retType
        case .phi(let incomings):
            guard let first = incomings.first else {
                return .intType(bits: 64, signed: false)
            }
            var acc = typeByKey[SSAVarKey(first.variable)] ?? first.variable.inferredType
            for inc in incomings.dropFirst() {
                let next = typeByKey[SSAVarKey(inc.variable)] ?? inc.variable.inferredType
                acc = Self.meetTypes(acc, next)
            }
            return acc
        case .cast(_, let targetType):
            return targetType
        case .ternary(_, let t, let e):
            return Self.meetTypes(inferExpressionType(t, typeByKey: typeByKey), inferExpressionType(e, typeByKey: typeByKey))
        }
    }

    // MARK: - Static Algebraic Simplifier & Constant Evaluator

    internal static func algebraicallySimplify(_ expr: MicroExpr) -> MicroExpr {
        switch expr {
        case .unary(let op, let sub):
            return simplifyUnary(op: op, sub: sub)
        case .binary(let op, let lhs, let rhs):
            return simplifyBinary(op: op, lhs: lhs, rhs: rhs)
        case .ternary(let cond, let thenExpr, let elseExpr):
            if let truth = evaluateConstantTruthiness(cond) {
                return truth ? thenExpr : elseExpr
            }
            if thenExpr == elseExpr && !containsCall(cond) && !containsLoad(cond) {
                return thenExpr
            }
            if isOneConstant(thenExpr) && isZeroConstant(elseExpr) && isRelationalOrBooleanExpr(cond) {
                return cond
            }
            if isZeroConstant(thenExpr) && isOneConstant(elseExpr) && isRelationalOrBooleanExpr(cond) {
                return ARM64ToMicroIRLifter.negateConditionExpr(cond)
            }
            return expr
        case .cast(let inner, let targetType):
            if case .cast(let subInner, let innerType) = inner, innerType == targetType {
                return .cast(subInner, to: targetType)
            }
            return expr
        default:
            return expr
        }
    }

    private static func simplifyUnary(op: MicroUnaryOp, sub: MicroExpr) -> MicroExpr {
        switch op {
        case .negate:
            if case .signedConst(let v, let b) = sub, v != Int64.min {
                return .signedConst(-v, bits: b)
            }
            if case .unsignedConst(let v, let b) = sub {
                if v == 0 { return .unsignedConst(0, bits: b) }
                let neg = Int64(bitPattern: 0 &- v)
                return .signedConst(b == 32 ? Int64(Int32(truncatingIfNeeded: neg)) : neg, bits: b)
            }
            if case .unary(.negate, let inner) = sub {
                return inner
            }

        case .bitwiseNot:
            if let (uVal, bits) = extractUnsignedBits(sub) {
                let mask: UInt64 = bits == 32 ? 0xFFFF_FFFF : UInt64.max
                return .unsignedConst((~uVal) & mask, bits: bits)
            }
            if case .unary(.bitwiseNot, let inner) = sub {
                return inner
            }

        case .logicalNot:
            if let truth = evaluateConstantTruthiness(sub) {
                return .unsignedConst(truth ? 0 : 1, bits: 1)
            }
            if isRelationalOrBooleanExpr(sub) {
                return ARM64ToMicroIRLifter.negateConditionExpr(sub)
            }

        case .zeroExtend:
            if let (uVal, _) = extractUnsignedBits(sub) {
                return .unsignedConst(uVal & 0xFFFF_FFFF, bits: 64)
            }
            if case .unary(.zeroExtend, _) = sub {
                return sub
            }

        case .signExtend:
            if case .signedConst(let v, _) = sub {
                return .signedConst(v, bits: 64)
            }
            if case .unsignedConst(let v, let b) = sub {
                let s: Int64
                switch b {
                case 8:  s = Int64(Int8(bitPattern: UInt8(truncatingIfNeeded: v)))
                case 16: s = Int64(Int16(bitPattern: UInt16(truncatingIfNeeded: v)))
                case 32: s = Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: v)))
                default: s = Int64(bitPattern: v)
                }
                return .signedConst(s, bits: 64)
            }

        case .byteSwap:
            if let (uVal, bits) = extractUnsignedBits(sub) {
                let swapped: UInt64
                switch bits {
                case 16: swapped = UInt64(UInt16(truncatingIfNeeded: uVal).byteSwapped)
                case 32: swapped = UInt64(UInt32(truncatingIfNeeded: uVal).byteSwapped)
                default: swapped = uVal.byteSwapped
                }
                return .unsignedConst(swapped, bits: bits)
            }
            if case .unary(.byteSwap, let inner) = sub {
                return inner
            }
        }
        return .unary(op, sub)
    }

    private static func simplifyBinary(op: MicroBinaryOp, lhs: MicroExpr, rhs: MicroExpr) -> MicroExpr {
        // 1. Exact constant folding when both operands are integer constants
        if let (lBitsVal, lWidth) = extractUnsignedBits(lhs),
           let (rBitsVal, rWidth) = extractUnsignedBits(rhs) {
            let width = max(lWidth, rWidth)
            if let folded = foldConstantBinary(op: op, lRaw: lBitsVal, rRaw: rBitsVal, bits: width) {
                return folded
            }
        }

        let lhsPure = !containsCall(lhs) && !containsLoad(lhs)
        let rhsPure = !containsCall(rhs) && !containsLoad(rhs)

        // 2. Algebraic identities & reassociations
        switch op {
        case .add:
            if isZeroConstant(rhs) { return lhs }
            if isZeroConstant(lhs) { return rhs }
            // `(a + c1) + c2 -> a + (c1 + c2)`
            if case .binary(.add, let base, let c1) = lhs,
               let v1 = extractSignedInt64Constant(c1),
               let v2 = extractSignedInt64Constant(rhs) {
                let sum = v1 &+ v2
                if sum == 0 { return base }
                return sum > 0
                    ? .binary(.add, base, .unsignedConst(UInt64(bitPattern: sum), bits: 64))
                    : .binary(.sub, base, .unsignedConst(UInt64(bitPattern: -sum), bits: 64))
            }
            // `(a - b) + b -> a`
            if case .binary(.sub, let a, let b) = lhs, b == rhs && rhsPure {
                return a
            }

        case .sub:
            if isZeroConstant(rhs) { return lhs }
            if isZeroConstant(lhs) { return simplifyUnary(op: .negate, sub: rhs) }
            if lhs == rhs && lhsPure {
                return .unsignedConst(0, bits: 64)
            }
            // `(a + b) - b -> a` and `(a + b) - a -> b`
            if case .binary(.add, let a, let b) = lhs {
                if b == rhs && rhsPure { return a }
                if a == rhs && rhsPure { return b }
                if let v1 = extractSignedInt64Constant(b), let v2 = extractSignedInt64Constant(rhs) {
                    let delta = v1 &- v2
                    if delta == 0 { return a }
                    return delta > 0
                        ? .binary(.add, a, .unsignedConst(UInt64(bitPattern: delta), bits: 64))
                        : .binary(.sub, a, .unsignedConst(UInt64(bitPattern: -delta), bits: 64))
                }
            }

        case .mul:
            if isOneConstant(rhs) { return lhs }
            if isOneConstant(lhs) { return rhs }
            if isZeroConstant(rhs) && lhsPure { return .unsignedConst(0, bits: 64) }
            if isZeroConstant(lhs) && rhsPure { return .unsignedConst(0, bits: 64) }

        case .udiv, .sdiv:
            if isOneConstant(rhs) { return lhs }

        case .shiftLeft, .shiftRightLogical, .shiftRightArithmetic:
            if isZeroConstant(rhs) { return lhs }
            if isZeroConstant(lhs) { return lhs }

        case .bitwiseOr:
            if isZeroConstant(rhs) { return lhs }
            if isZeroConstant(lhs) { return rhs }
            if lhs == rhs && lhsPure { return lhs }

        case .bitwiseXor:
            if isZeroConstant(rhs) { return lhs }
            if isZeroConstant(lhs) { return rhs }
            if lhs == rhs && lhsPure { return .unsignedConst(0, bits: 64) }

        case .bitwiseAnd:
            if isZeroConstant(rhs) && lhsPure { return .unsignedConst(0, bits: 64) }
            if isZeroConstant(lhs) && rhsPure { return .unsignedConst(0, bits: 64) }
            if lhs == rhs && lhsPure { return lhs }
            if let (mask, bits) = extractUnsignedBits(rhs) {
                let allOnes: UInt64 = bits == 32 ? 0xFFFF_FFFF : UInt64.max
                if mask == allOnes { return lhs }
            }

        case .equal:
            if lhs == rhs && lhsPure { return .unsignedConst(1, bits: 1) }
            if isZeroConstant(rhs) && isRelationalOrBooleanExpr(lhs) {
                return ARM64ToMicroIRLifter.negateConditionExpr(lhs)
            }
            if isOneConstant(rhs) && isRelationalOrBooleanExpr(lhs) {
                return lhs
            }

        case .notEqual:
            if lhs == rhs && lhsPure { return .unsignedConst(0, bits: 1) }
            if isZeroConstant(rhs) && isRelationalOrBooleanExpr(lhs) {
                return lhs
            }

        case .logicalAnd:
            if let lt = evaluateConstantTruthiness(lhs) {
                return lt ? rhs : .unsignedConst(0, bits: 1)
            }
            if let rt = evaluateConstantTruthiness(rhs) {
                return rt ? lhs : exprIfPureZero(lhs: lhs, pure: lhsPure)
            }

        case .logicalOr:
            if let lt = evaluateConstantTruthiness(lhs) {
                return lt ? .unsignedConst(1, bits: 1) : rhs
            }
            if let rt = evaluateConstantTruthiness(rhs) {
                return rt ? (lhsPure ? .unsignedConst(1, bits: 1) : .binary(op, lhs, rhs)) : lhs
            }

        default:
            break
        }

        return .binary(op, lhs, rhs)
    }

    private static func exprIfPureZero(lhs: MicroExpr, pure: Bool) -> MicroExpr {
        pure ? .unsignedConst(0, bits: 1) : .binary(.logicalAnd, lhs, .unsignedConst(0, bits: 1))
    }

    private static func foldConstantBinary(
        op: MicroBinaryOp,
        lRaw: UInt64,
        rRaw: UInt64,
        bits: Int
    ) -> MicroExpr? {
        let mask: UInt64 = bits <= 32 ? 0xFFFF_FFFF : UInt64.max
        let lU = lRaw & mask
        let rU = rRaw & mask
        let lS: Int64 = bits <= 32
            ? Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: lU)))
            : Int64(bitPattern: lU)
        let rS: Int64 = bits <= 32
            ? Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: rU)))
            : Int64(bitPattern: rU)

        switch op {
        case .add:
            return .unsignedConst((lU &+ rU) & mask, bits: bits)
        case .sub:
            return .unsignedConst((lU &- rU) & mask, bits: bits)
        case .mul:
            return .unsignedConst((lU &* rU) & mask, bits: bits)
        case .udiv:
            guard rU != 0 else { return nil }
            return .unsignedConst((lU / rU) & mask, bits: bits)
        case .sdiv:
            guard rS != 0 && !(lS == Int64.min && rS == -1) else { return nil }
            return .signedConst(lS / rS, bits: bits)
        case .umod:
            guard rU != 0 else { return nil }
            return .unsignedConst((lU % rU) & mask, bits: bits)
        case .bitwiseAnd:
            return .unsignedConst(lU & rU, bits: bits)
        case .bitwiseOr:
            return .unsignedConst(lU | rU, bits: bits)
        case .bitwiseXor:
            return .unsignedConst(lU ^ rU, bits: bits)
        case .shiftLeft:
            let sh = Int(rU & UInt64(bits - 1))
            return .unsignedConst((lU << sh) & mask, bits: bits)
        case .shiftRightLogical:
            let sh = Int(rU & UInt64(bits - 1))
            return .unsignedConst((lU >> sh) & mask, bits: bits)
        case .shiftRightArithmetic:
            let sh = Int(rU & UInt64(bits - 1))
            return .signedConst(lS >> sh, bits: bits)
        case .equal:
            return .unsignedConst(lU == rU ? 1 : 0, bits: 1)
        case .notEqual:
            return .unsignedConst(lU != rU ? 1 : 0, bits: 1)
        case .unsignedLess:
            return .unsignedConst(lU < rU ? 1 : 0, bits: 1)
        case .unsignedLessEqual:
            return .unsignedConst(lU <= rU ? 1 : 0, bits: 1)
        case .unsignedGreater:
            return .unsignedConst(lU > rU ? 1 : 0, bits: 1)
        case .unsignedGreaterEqual:
            return .unsignedConst(lU >= rU ? 1 : 0, bits: 1)
        case .signedLess:
            return .unsignedConst(lS < rS ? 1 : 0, bits: 1)
        case .signedLessEqual:
            return .unsignedConst(lS <= rS ? 1 : 0, bits: 1)
        case .signedGreater:
            return .unsignedConst(lS > rS ? 1 : 0, bits: 1)
        case .signedGreaterEqual:
            return .unsignedConst(lS >= rS ? 1 : 0, bits: 1)
        case .logicalAnd:
            return .unsignedConst((lU != 0 && rU != 0) ? 1 : 0, bits: 1)
        case .logicalOr:
            return .unsignedConst((lU != 0 || rU != 0) ? 1 : 0, bits: 1)
        }
    }

    // MARK: - CFG, Liveness, Type Lattice & AST Traversal Helpers

    internal struct DerivedMicroCFG {
        let predecessors: [Int: [Int]]
        let successors: [Int: [Int]]
        let edges: [CFGEdge]
        let syntheticBasicBlocks: [BasicBlock]
    }

    internal static func deriveMicroCFG(
        from microBlocks: [MicroBasicBlock],
        fallbackEdges: [CFGEdge] = [],
        entryBlockID: Int
    ) -> DerivedMicroCFG {
        let validIDs = Set(microBlocks.map(\.blockID))
        var succs: [Int: [Int]] = [:]
        var preds: [Int: [Int]] = [:]
        for b in microBlocks {
            succs[b.blockID] = []
            preds[b.blockID] = []
        }

        var edges: [CFGEdge] = []

        func addEdge(_ from: Int, _ to: Int, kind: CFGEdgeKind) {
            guard validIDs.contains(from) && validIDs.contains(to) else { return }
            if !(succs[from]?.contains(to) ?? false) {
                succs[from, default: []].append(to)
                preds[to, default: []].append(from)
                edges.append(CFGEdge(sourceBlockID: from, targetBlockID: to, kind: kind))
            }
        }

        for b in microBlocks {
            var foundTerm = false
            if let last = b.statements.last {
                switch last.kind {
                case .conditionalBranch(_, let tID, let fID):
                    addEdge(b.blockID, tID, kind: .conditionalTrue)
                    addEdge(b.blockID, fID, kind: .conditionalFalse)
                    foundTerm = true
                case .jump(let targetID):
                    addEdge(b.blockID, targetID, kind: .unconditional)
                    foundTerm = true
                case .switchJump(_, let cases, let defID):
                    for c in cases {
                        addEdge(b.blockID, c.targetBlockID, kind: .switchCase(value: c.caseValue))
                    }
                    addEdge(b.blockID, defID, kind: .unconditional)
                    foundTerm = true
                case .returnStmt:
                    foundTerm = true
                default:
                    break
                }
            }
            if !foundTerm {
                for fe in fallbackEdges where fe.sourceBlockID == b.blockID {
                    addEdge(fe.sourceBlockID, fe.targetBlockID, kind: fe.kind)
                }
            }
        }

        let fnStart = microBlocks.first(where: { $0.blockID == entryBlockID })?.startAddress
            ?? microBlocks.first?.startAddress
            ?? .zero
        let syntheticBlocks = microBlocks.map { mb in
            let sList = succs[mb.blockID] ?? []
            let pList = preds[mb.blockID] ?? []
            let endAddr = mb.statements.last?.originAddress.adding(UInt64(4)) ?? mb.startAddress.adding(UInt64(4))
            return BasicBlock(
                id: mb.blockID,
                functionAddress: fnStart,
                startAddress: mb.startAddress,
                endAddress: max(endAddr, mb.startAddress.adding(UInt64(4))),
                instructions: [],
                predecessorIDs: pList,
                successorIDs: sList,
                isEntry: mb.blockID == entryBlockID,
                isExit: sList.isEmpty
            )
        }

        return DerivedMicroCFG(
            predecessors: preds,
            successors: succs,
            edges: edges,
            syntheticBasicBlocks: syntheticBlocks
        )
    }

    private static func pruneDeadCFGEdgesAndBlocks(
        _ blocks: [MicroBasicBlock],
        entryBlockID: Int
    ) -> [MicroBasicBlock] {
        guard !blocks.isEmpty else { return [] }
        let graph = deriveMicroCFG(from: blocks, entryBlockID: entryBlockID)

        // Forward BFS from `entryBlockID`
        var reachable = Set<Int>()
        if graph.successors[entryBlockID] != nil {
            reachable.insert(entryBlockID)
            var queue = [entryBlockID]
            var head = 0
            while head < queue.count {
                let curr = queue[head]
                head += 1
                for succ in graph.successors[curr] ?? [] where reachable.insert(succ).inserted {
                    queue.append(succ)
                }
            }
        } else {
            for b in blocks { reachable.insert(b.blockID) }
        }

        return blocks.compactMap { block -> MicroBasicBlock? in
            guard reachable.contains(block.blockID) else { return nil }
            let validPreds = Set((graph.predecessors[block.blockID] ?? []).filter { reachable.contains($0) })
            let cleanedStmts = block.statements.map { stmt -> MicroStmt in
                guard case .assign(let dest, .phi(let incomings)) = stmt.kind else { return stmt }
                let filtered = incomings.filter { validPreds.contains($0.predecessorBlockID) }
                if filtered.count == 1 {
                    return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: .variable(filtered[0].variable)))
                }
                return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: .assign(dest: dest, expr: .phi(filtered)))
            }
            return MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: cleanedStmts)
        }
    }

    private static func computeVariableLiveness(
        blocks: [MicroBasicBlock],
        successorsByBlock: [Int: [Int]]
    ) -> [Int: Set<String>] {
        var genByBlock: [Int: Set<String>] = [:]
        var killByBlock: [Int: Set<String>] = [:]

        for block in blocks {
            var gen = Set<String>()
            var kill = Set<String>()
            for stmt in block.statements {
                forEachReadVar(in: stmt.kind) { v in
                    if !kill.contains(v.baseName) {
                        gen.insert(v.baseName)
                    }
                }
                if case .assign(let dest, _) = stmt.kind {
                    kill.insert(dest.baseName)
                }
            }
            genByBlock[block.blockID] = gen
            killByBlock[block.blockID] = kill
        }

        var liveIn: [Int: Set<String>] = [:]
        for b in blocks {
            liveIn[b.blockID] = genByBlock[b.blockID] ?? []
        }

        var changed = true
        var iter = 0
        while changed && iter < 64 {
            changed = false
            iter += 1
            for b in blocks.reversed() {
                var liveOut = Set<String>()
                for succ in successorsByBlock[b.blockID] ?? [] {
                    liveOut.formUnion(liveIn[succ] ?? [])
                }
                let updated = (genByBlock[b.blockID] ?? []).union(liveOut.subtracting(killByBlock[b.blockID] ?? []))
                if updated != liveIn[b.blockID] {
                    liveIn[b.blockID] = updated
                    changed = true
                }
            }
        }
        return liveIn
    }

    private static func harvestTemplateVars(in kind: MicroStmtKind, into map: inout [String: SSAVar]) {
        func record(_ v: SSAVar) {
            if let existing = map[v.baseName] {
                if typeSpecificityRank(v.inferredType) > typeSpecificityRank(existing.inferredType) {
                    map[v.baseName] = SSAVar(
                        baseName: v.baseName,
                        version: 0,
                        bitWidth: max(existing.bitWidth, v.bitWidth),
                        inferredType: v.inferredType
                    )
                }
            } else {
                map[v.baseName] = SSAVar(baseName: v.baseName, version: 0, bitWidth: v.bitWidth, inferredType: v.inferredType)
            }
        }

        if case .assign(let dest, _) = kind {
            record(dest)
        }
        forEachReadVar(in: kind, record)
    }

    private static func collectVarsInBlocks(_ blocks: [MicroBasicBlock], into map: inout [SSAVarKey: SSAVar]) {
        for block in blocks {
            for stmt in block.statements {
                if case .assign(let dest, _) = stmt.kind {
                    map[SSAVarKey(dest)] = dest
                }
                forEachReadVar(in: stmt.kind) { v in
                    if map[SSAVarKey(v)] == nil {
                        map[SSAVarKey(v)] = v
                    }
                }
            }
        }
    }

    private static func rewriteBlockVariableTypes(
        blocks: [MicroBasicBlock],
        resolvedVarsByKey: [SSAVarKey: SSAVar]
    ) -> [MicroBasicBlock] {
        func mapVar(_ v: SSAVar) -> SSAVar {
            resolvedVarsByKey[SSAVarKey(v)] ?? v
        }

        func mapExpr(_ expr: MicroExpr) -> MicroExpr {
            switch expr {
            case .variable(let v):
                return .variable(mapVar(v))
            case .unary(let op, let s):
                return .unary(op, mapExpr(s))
            case .binary(let op, let l, let r):
                return .binary(op, mapExpr(l), mapExpr(r))
            case .load(let a, let b, let t):
                return .load(address: mapExpr(a), bits: b, type: t)
            case .call(let tgt, let args, let rt):
                return .call(target: mapExpr(tgt), arguments: args.map(mapExpr), returnType: rt)
            case .phi(let inc):
                return .phi(inc.map { PhiIncoming(predecessorBlockID: $0.predecessorBlockID, variable: mapVar($0.variable)) })
            case .cast(let s, let t):
                return .cast(mapExpr(s), to: t)
            case .ternary(let c, let t, let e):
                return .ternary(condition: mapExpr(c), thenExpr: mapExpr(t), elseExpr: mapExpr(e))
            case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
                return expr
            }
        }

        return blocks.map { block in
            let stmts = block.statements.map { stmt -> MicroStmt in
                let nextKind: MicroStmtKind
                switch stmt.kind {
                case .assign(let dest, let expr):
                    nextKind = .assign(dest: mapVar(dest), expr: mapExpr(expr))
                case .store(let a, let v, let b):
                    nextKind = .store(address: mapExpr(a), value: mapExpr(v), bits: b)
                case .callStmt(let t, let args):
                    nextKind = .callStmt(target: mapExpr(t), arguments: args.map(mapExpr))
                case .conditionalBranch(let c, let tID, let fID):
                    nextKind = .conditionalBranch(condition: mapExpr(c), trueBlockID: tID, falseBlockID: fID)
                case .switchJump(let s, let cases, let dID):
                    nextKind = .switchJump(selector: mapExpr(s), cases: cases, defaultBlockID: dID)
                case .returnStmt(let v):
                    nextKind = .returnStmt(value: v.map(mapExpr))
                case .intrinsic(let n, let args):
                    nextKind = .intrinsic(name: n, arguments: args.map(mapExpr))
                case .jump, .nop:
                    nextKind = stmt.kind
                }
                return MicroStmt(id: stmt.id, originAddress: stmt.originAddress, kind: nextKind)
            }
            return MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: stmts)
        }
    }

    internal static func forEachReadVar(in kind: MicroStmtKind, _ body: (SSAVar) -> Void) {
        switch kind {
        case .assign(_, let expr):
            forEachReadVarInExpr(expr, body)
        case .store(let a, let v, _):
            forEachReadVarInExpr(a, body)
            forEachReadVarInExpr(v, body)
        case .callStmt(let t, let args):
            forEachReadVarInExpr(t, body)
            for a in args { forEachReadVarInExpr(a, body) }
        case .conditionalBranch(let c, _, _):
            forEachReadVarInExpr(c, body)
        case .switchJump(let s, _, _):
            forEachReadVarInExpr(s, body)
        case .returnStmt(let v?):
            forEachReadVarInExpr(v, body)
        case .intrinsic(_, let args):
            for a in args { forEachReadVarInExpr(a, body) }
        case .returnStmt(nil), .jump, .nop:
            break
        }
    }

    internal static func forEachReadVarInExpr(_ expr: MicroExpr, _ body: (SSAVar) -> Void) {
        switch expr {
        case .variable(let v):
            body(v)
        case .unary(_, let s):
            forEachReadVarInExpr(s, body)
        case .binary(_, let l, let r):
            forEachReadVarInExpr(l, body)
            forEachReadVarInExpr(r, body)
        case .load(let a, _, _):
            forEachReadVarInExpr(a, body)
        case .call(let t, let args, _):
            forEachReadVarInExpr(t, body)
            for a in args { forEachReadVarInExpr(a, body) }
        case .phi(let incomings):
            for inc in incomings { body(inc.variable) }
        case .cast(let s, _):
            forEachReadVarInExpr(s, body)
        case .ternary(let c, let t, let e):
            forEachReadVarInExpr(c, body)
            forEachReadVarInExpr(t, body)
            forEachReadVarInExpr(e, body)
        case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
            break
        }
    }

    internal static func containsCall(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .call: return true
        case .unary(_, let s), .cast(let s, _), .load(let s, _, _): return containsCall(s)
        case .binary(_, let l, let r): return containsCall(l) || containsCall(r)
        case .ternary(let c, let t, let e): return containsCall(c) || containsCall(t) || containsCall(e)
        default: return false
        }
    }

    internal static func containsLoad(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .load: return true
        case .unary(_, let s), .cast(let s, _): return containsLoad(s)
        case .binary(_, let l, let r): return containsLoad(l) || containsLoad(r)
        case .call(let t, let args, _): return containsLoad(t) || args.contains(where: containsLoad)
        case .ternary(let c, let t, let e): return containsLoad(c) || containsLoad(t) || containsLoad(e)
        default: return false
        }
    }

    internal static func statementHasMemoryOrCallSideEffect(_ kind: MicroStmtKind) -> Bool {
        switch kind {
        case .store, .callStmt, .intrinsic:
            return true
        case .assign(let dest, let expr):
            return dest.baseName.hasPrefix("self->") || containsCall(expr)
        default:
            return false
        }
    }

    private static func expressionNodeCount(_ expr: MicroExpr) -> Int {
        switch expr {
        case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef, .variable, .phi:
            return 1
        case .unary(_, let s), .cast(let s, _), .load(let s, _, _):
            return 1 + expressionNodeCount(s)
        case .binary(_, let l, let r):
            return 1 + expressionNodeCount(l) + expressionNodeCount(r)
        case .call(let t, let args, _):
            return 1 + expressionNodeCount(t) + args.reduce(0) { $0 + expressionNodeCount($1) }
        case .ternary(let c, let t, let e):
            return 1 + expressionNodeCount(c) + expressionNodeCount(t) + expressionNodeCount(e)
        }
    }

    private static func isPropagatableConstant(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .signedConst, .unsignedConst, .floatConst, .stringLiteral, .symbolRef:
            return true
        default:
            return false
        }
    }

    internal static func extractUnsignedBits(_ expr: MicroExpr) -> (UInt64, Int)? {
        switch expr {
        case .unsignedConst(let v, let b):
            return (v, b)
        case .signedConst(let v, let b):
            return (UInt64(bitPattern: v), b)
        default:
            return nil
        }
    }

    internal static func extractSignedInt64Constant(_ expr: MicroExpr) -> Int64? {
        switch expr {
        case .signedConst(let v, _):
            return v
        case .unsignedConst(let v, let b):
            if b <= 32 {
                return Int64(UInt32(truncatingIfNeeded: v))
            }
            return Int64(bitPattern: v)
        default:
            return nil
        }
    }

    private static func evaluateConstantTruthiness(_ expr: MicroExpr) -> Bool? {
        switch expr {
        case .unsignedConst(let v, _):
            return v != 0
        case .signedConst(let v, _):
            return v != 0
        case .stringLiteral:
            return true
        default:
            return nil
        }
    }

    internal static func isZeroConstant(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .unsignedConst(0, _), .signedConst(0, _): return true
        default: return false
        }
    }

    private static func isOneConstant(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .unsignedConst(1, _), .signedConst(1, _): return true
        default: return false
        }
    }

    internal static func isRelationalOrBooleanExpr(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .unary(.logicalNot, _):
            return true
        case .binary(let op, _, _):
            switch op {
            case .equal, .notEqual,
                 .unsignedLess, .unsignedLessEqual, .unsignedGreater, .unsignedGreaterEqual,
                 .signedLess, .signedLessEqual, .signedGreater, .signedGreaterEqual,
                 .logicalAnd, .logicalOr:
                return true
            default:
                return false
            }
        default:
            return false
        }
    }

    // MARK: - Type Lattice Helpers

    internal static func isPointerLike(_ type: CTypeExpr) -> Bool {
        switch type {
        case .pointer, .cString, .objcObject:
            return true
        default:
            return false
        }
    }

    private static func isDefaultUntypedInt(_ type: CTypeExpr) -> Bool {
        switch type {
        case .unknownBits, .intType(64, false), .intType(32, false):
            return true
        default:
            return false
        }
    }

    internal static func typeSpecificityRank(_ type: CTypeExpr) -> Int {
        switch type {
        case .unknownBits:
            return 0
        case .voidType:
            return 1
        case .intType(let bits, let signed):
            if bits == 64 && !signed { return 2 }
            if bits == 32 && !signed { return 3 }
            return signed ? 5 : 4
        case .boolType:
            return 6
        case .floatType:
            return 7
        case .pointer(let inner):
            if inner == .voidType { return 8 }
            if case .structRef = inner { return 13 }
            return 10
        case .objcObject(let cls):
            return cls == nil ? 9 : 12
        case .cString:
            return 11
        case .structRef:
            return 12
        }
    }

    private static func meetTypes(_ a: CTypeExpr, _ b: CTypeExpr) -> CTypeExpr {
        if a == b { return a }
        if typeSpecificityRank(b) > typeSpecificityRank(a) {
            return b
        }
        return a
    }

    private static func refineType(
        _ map: inout [SSAVarKey: CTypeExpr],
        key: SSAVarKey,
        candidate: CTypeExpr
    ) {
        guard candidate != .voidType else { return }
        if let current = map[key] {
            if typeSpecificityRank(candidate) > typeSpecificityRank(current) {
                map[key] = candidate
            }
        } else {
            map[key] = candidate
        }
    }

    private static func matchCustomStruct(
        offsets: Set<Int>,
        in structDefinitions: [String: CustomStructDefinition]
    ) -> CustomStructDefinition? {
        var best: CustomStructDefinition? = nil
        var bestMatchCount = 0

        for def in structDefinitions.values {
            let fieldOffsets = Set(def.fields.map(\.offset))
            let matched = offsets.intersection(fieldOffsets).count
            // Require at least one non-zero field offset match (or >= 2 field matches) so ordinary pointers aren't misclassified
            let hasNonZeroMatch = offsets.contains { $0 > 0 && fieldOffsets.contains($0) }
            if hasNonZeroMatch && matched > bestMatchCount {
                bestMatchCount = matched
                best = def
            }
        }
        return best
    }

    private static func deriveObjCParameterName(fromKeyword keyword: String, fallbackIndex: Int) -> String? {
        guard !keyword.isEmpty else { return nil }
        // Find last uppercase transition in camelCase selector piece (e.g. `validateToken` -> `token`, `initWithKey` -> `key`)
        let chars = Array(keyword)
        var splitPos: Int? = nil
        for i in stride(from: chars.count - 1, through: 1, by: -1) {
            if chars[i].isUppercase && chars[i - 1].isLowercase {
                splitPos = i
                break
            }
        }
        let rawTail: String
        if let pos = splitPos {
            rawTail = String(chars[pos...]).lowercased()
        } else {
            rawTail = keyword.lowercased()
        }
        let reserved: Set<String> = ["int", "char", "void", "if", "else", "while", "for", "switch", "case", "default", "return", "break", "continue", "goto", "struct", "const", "bool", "id", "self"]
        if rawTail.isEmpty || reserved.contains(rawTail) {
            return "arg\(fallbackIndex)"
        }
        return rawTail
    }
}

private extension MicroExpr {
    static var nopPlaceholder: MicroExpr {
        .unsignedConst(0, bits: 64)
    }
}
