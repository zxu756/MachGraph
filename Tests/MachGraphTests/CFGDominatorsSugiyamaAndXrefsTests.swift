import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine

@Suite("Control-Flow Graph, Dominators, Sugiyama Layout & Cross-References")
struct CFGDominatorsSugiyamaAndXrefsTests {

    private func rectsStrictlyIntersect(_ a: CGRectBridge, _ b: CGRectBridge) -> Bool {
        a.minX < b.maxX && a.maxX > b.minX && a.minY < b.maxY && a.maxY > b.minY
    }

    private func makeDummyBlock(id: Int, succs: [Int], preds: [Int] = [], isEntry: Bool = false, isExit: Bool = false) -> BasicBlock {
        let va = VirtualAddress(0x1_0000_1000 + UInt64(id * 16))
        let nop = A64InstructionDecoder().decode(word: 0xD503_201F, at: va)
        return BasicBlock(
            id: id,
            functionAddress: VirtualAddress(0x1_0000_1000),
            startAddress: va,
            endAddress: va.adding(UInt64(4)),
            instructions: [nop],
            predecessorIDs: preds,
            successorIDs: succs,
            isEntry: isEntry,
            isExit: isExit
        )
    }

    @Test("FunctionDiscoveryEngine recovers authoritative functions and import stubs in ARM64E Mach-O")
    func functionDiscoveryRecoversAuthoritativeAndStubFunctions() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "CFGTarget.arm64e")
        let engine = FunctionDiscoveryEngine()

        let decodedSections = try engine.decodeExecutableSections(in: image, data: data)
        #expect(!decodedSections.isEmpty)

        let boundaries = engine.discoverFunctions(in: image, decodedSections: decodedSections, data: data)
        let names = boundaries.map(\.name)
        #expect(names.contains("_compute_checksum"))
        #expect(names.contains("_verify_license"))
        #expect(names.contains("_dispatch_command"))
        #expect(names.contains("-[MGAuthController validateToken:]"))
        #expect(names.contains("+[MGAuthController sharedController]"))
        #expect(names.contains("_main"))
        #expect(boundaries.contains { $0.isStubSection })
    }

    @Test("Switch jump-table recovery extracts 4-way dispatch table on _dispatch_command")
    func switchJumpTableRecoveryOnDispatchCommand() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Switch.arm64")

        let dispatchFn = try #require(index.function(named: "_dispatch_command"))
        #expect(!dispatchFn.jumpTables.isEmpty)

        let jt = try #require(dispatchFn.jumpTables.first)
        #expect(jt.targetAddresses.count == 4)
        #expect(Set(jt.targetAddresses).count == 4)

        let switchEdges = dispatchFn.edges.filter {
            if case .switchCase = $0.kind { return true }
            return false
        }
        #expect(switchEdges.count >= 4)
    }

    @Test("CFGBuilderEngine splits basic blocks at branch targets and classifies true/false/fallthrough edges")
    func cfgBuilderSplitsBasicBlocksAndClassifiesEdges() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
        entry:
            cmp w0, #10
            b.lt .L_small
            mov w0, #100
            b .L_done
        .L_small:
            mov w0, #1
        .L_done:
            ret
        """, baseAddress: VirtualAddress(0x1_0000_2000))

        let cfg = CFGBuilderEngine().buildCFG(
            functionAddress: prog.baseAddress,
            name: "_clamp_value",
            instructions: prog.instructions
        )

        #expect(cfg.blocks.count == 4)
        #expect(cfg.edges.count == 4)
        #expect(cfg.cyclomaticComplexity == 2)
        #expect(cfg.edges.contains { $0.kind == .conditionalTrue })
        #expect(cfg.edges.contains { $0.kind == .conditionalFalse })
        #expect(cfg.blocks.filter(\.isEntry).count == 1)
        #expect(cfg.blocks.filter(\.isExit).count == 1)
    }

    @Test("CFGBuilderEngine detects unreachable dead blocks, prunes them, and computes Reverse Post-Order")
    func cfgBuilderUnreachableBlockPruningAndReversePostOrder() throws {
        let asm = A64MiniAssembler()
        let prog = try asm.assembleProgram("""
            mov w0, #42
            ret
            mov w0, #99
            ret
        """, baseAddress: VirtualAddress(0x1_0000_3000))

        let builder = CFGBuilderEngine()
        let rawCFG = builder.buildCFG(
            functionAddress: prog.baseAddress,
            name: "_with_dead_tail",
            instructions: prog.instructions
        )
        #expect(!rawCFG.unreachableBlockIDs.isEmpty)

        let rpo = builder.computeReversePostOrder(blocks: rawCFG.blocks, entryBlockID: 0)
        #expect(rpo.reachableBlockIDs == [0])

        let pruned = builder.pruneUnreachableBlocks(in: rawCFG)
        #expect(pruned.blocks.count == 1)
        #expect(pruned.unreachableBlockIDs.isEmpty)
    }

    @Test("Lengauer-Tarjan immediate dominators match Cooper-Harvey-Kennedy iterative solver on diamond and nested loops")
    func lengauerTarjanMatchesCooperHarveyKennedyOnDiamondAndLoops() {
        // 0 -> 1, 2; 1 -> 3; 2 -> 3; 3 -> 4, 6; 4 -> 5; 5 -> 4 (inner loop), 3 (outer loop); 6 (exit)
        let edges: [CFGEdge] = [
            .init(sourceBlockID: 0, targetBlockID: 1, kind: .conditionalTrue),
            .init(sourceBlockID: 0, targetBlockID: 2, kind: .conditionalFalse),
            .init(sourceBlockID: 1, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 2, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 3, targetBlockID: 4, kind: .conditionalTrue),
            .init(sourceBlockID: 3, targetBlockID: 6, kind: .conditionalFalse),
            .init(sourceBlockID: 4, targetBlockID: 5, kind: .unconditional),
            .init(sourceBlockID: 5, targetBlockID: 4, kind: .conditionalTrue),
            .init(sourceBlockID: 5, targetBlockID: 3, kind: .conditionalFalse)
        ]
        let blocks: [BasicBlock] = [
            makeDummyBlock(id: 0, succs: [1, 2], preds: [], isEntry: true),
            makeDummyBlock(id: 1, succs: [3], preds: [0]),
            makeDummyBlock(id: 2, succs: [3], preds: [0]),
            makeDummyBlock(id: 3, succs: [4, 6], preds: [1, 2, 5]),
            makeDummyBlock(id: 4, succs: [5], preds: [3, 5]),
            makeDummyBlock(id: 5, succs: [4, 3], preds: [4]),
            makeDummyBlock(id: 6, succs: [], preds: [3], isExit: true)
        ]

        let analyzer = DominatorAndLoopAnalyzer()
        let ltTree = analyzer.computeDominatorTree(blocks: blocks, edges: edges, entryBlockID: 0)
        let chkMap = analyzer.computeImmediateDominatorsCooperHarveyKennedy(
            blocks: blocks,
            edges: edges,
            entryBlockID: 0
        )

        #expect(ltTree.count == blocks.count)
        for node in ltTree {
            #expect(chkMap[node.blockID] == node.immediateDominatorID)
        }
        let byID = Dictionary(uniqueKeysWithValues: ltTree.map { ($0.blockID, $0) })
        #expect(byID[0]?.immediateDominatorID == nil)
        #expect(byID[3]?.immediateDominatorID == 0)
        #expect(byID[4]?.immediateDominatorID == 3)
        #expect(byID[5]?.immediateDominatorID == 4)
        #expect(byID[6]?.immediateDominatorID == 3)
    }

    @Test("Lengauer-Tarjan matches Cooper-Harvey-Kennedy across every recovered function in synthetic binary")
    func lengauerTarjanMatchesCooperHarveyKennedyAcrossEntireBinaryAndSwitch() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "DomVerify.arm64e")
        let analyzer = DominatorAndLoopAnalyzer()

        #expect(index.functions.count >= 6)
        for fn in index.functions where !fn.blocks.isEmpty {
            let entryID = fn.blocks.first(where: \.isEntry)?.id ?? fn.blocks[0].id
            let ltTree = analyzer.computeDominatorTree(blocks: fn.blocks, edges: fn.edges, entryBlockID: entryID)
            let chk = analyzer.computeImmediateDominatorsCooperHarveyKennedy(
                blocks: fn.blocks,
                edges: fn.edges,
                entryBlockID: entryID
            )
            for node in ltTree {
                #expect(chk[node.blockID] == node.immediateDominatorID, "Dominator mismatch in \(fn.name) block \(node.blockID)")
            }
        }
    }

    @Test("Dominator tree dominance, strict dominance, and lowest common dominator queries")
    func dominatorTreeDominanceQueriesAndLowestCommonDominator() {
        let edges: [CFGEdge] = [
            .init(sourceBlockID: 0, targetBlockID: 1, kind: .conditionalTrue),
            .init(sourceBlockID: 0, targetBlockID: 2, kind: .conditionalFalse),
            .init(sourceBlockID: 1, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 2, targetBlockID: 3, kind: .unconditional)
        ]
        let blocks: [BasicBlock] = [
            makeDummyBlock(id: 0, succs: [1, 2], preds: [], isEntry: true),
            makeDummyBlock(id: 1, succs: [3], preds: [0]),
            makeDummyBlock(id: 2, succs: [3], preds: [0]),
            makeDummyBlock(id: 3, succs: [], preds: [1, 2], isExit: true)
        ]
        let analyzer = DominatorAndLoopAnalyzer()
        let domTree = analyzer.computeDominatorTree(blocks: blocks, edges: edges, entryBlockID: 0)

        #expect(analyzer.dominates(0, 0, in: domTree))
        #expect(!analyzer.strictlyDominates(0, 0, in: domTree))
        #expect(analyzer.strictlyDominates(0, 3, in: domTree))
        #expect(!analyzer.dominates(1, 3, in: domTree))
        #expect(analyzer.lowestCommonDominator(1, 2, in: domTree) == 0)
    }

    @Test("Iterated Dominance Frontier (IDF+) computes exact SSA phi-node join blocks")
    func iteratedDominanceFrontierComputesExactPhiJoinNodes() {
        // Preheader 0 -> Loop header 1 -> Diamond (2, 3 -> 4) -> Latch 4 -> 1 (and Exit 4 -> 5)
        let edges: [CFGEdge] = [
            .init(sourceBlockID: 0, targetBlockID: 1, kind: .unconditional),
            .init(sourceBlockID: 1, targetBlockID: 2, kind: .conditionalTrue),
            .init(sourceBlockID: 1, targetBlockID: 3, kind: .conditionalFalse),
            .init(sourceBlockID: 2, targetBlockID: 4, kind: .unconditional),
            .init(sourceBlockID: 3, targetBlockID: 4, kind: .unconditional),
            .init(sourceBlockID: 4, targetBlockID: 1, kind: .conditionalTrue),
            .init(sourceBlockID: 4, targetBlockID: 5, kind: .conditionalFalse)
        ]
        let blocks: [BasicBlock] = [
            makeDummyBlock(id: 0, succs: [1], preds: [], isEntry: true),
            makeDummyBlock(id: 1, succs: [2, 3], preds: [0, 4]),
            makeDummyBlock(id: 2, succs: [4], preds: [1]),
            makeDummyBlock(id: 3, succs: [4], preds: [1]),
            makeDummyBlock(id: 4, succs: [1, 5], preds: [2, 3]),
            makeDummyBlock(id: 5, succs: [], preds: [4], isExit: true)
        ]
        let analyzer = DominatorAndLoopAnalyzer()
        let domTree = analyzer.computeDominatorTree(blocks: blocks, edges: edges, entryBlockID: 0)

        // Variable defined in block 2 reaches diamond merge 4, and via latch 4->1 also requires phi at loop header 1!
        let idf = Set(analyzer.iteratedDominanceFrontier(forDefinitionBlocks: [2], dominatorTree: domTree))
        #expect(idf == [1, 4])
    }

    @Test("Post-dominator tree and immediate structured merge block recovery on diamond CFG")
    func postDominatorTreeAndStructuredMergeBlockRecovery() {
        let edges: [CFGEdge] = [
            .init(sourceBlockID: 0, targetBlockID: 1, kind: .conditionalTrue),
            .init(sourceBlockID: 0, targetBlockID: 2, kind: .conditionalFalse),
            .init(sourceBlockID: 1, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 2, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 3, targetBlockID: 4, kind: .unconditional)
        ]
        let blocks: [BasicBlock] = [
            makeDummyBlock(id: 0, succs: [1, 2], preds: [], isEntry: true),
            makeDummyBlock(id: 1, succs: [3], preds: [0]),
            makeDummyBlock(id: 2, succs: [3], preds: [0]),
            makeDummyBlock(id: 3, succs: [4], preds: [1, 2]),
            makeDummyBlock(id: 4, succs: [], preds: [3], isExit: true)
        ]
        let analyzer = DominatorAndLoopAnalyzer()
        let pdom = analyzer.computePostDominatorTree(blocks: blocks, edges: edges)

        #expect(analyzer.postDominates(3, 0, in: pdom))
        #expect(analyzer.postDominates(4, 1, in: pdom))
        #expect(!analyzer.postDominates(1, 0, in: pdom))
        #expect(analyzer.structuredMergeBlockID(forBranchBlock: 0, postDominatorTree: pdom) == 3)
    }

    @Test("Natural loop recovery identifies loop headers, latches, body blocks, exits, and nested depth = 2")
    func naturalLoopDetectionSingleAndNestedLoopDepths() {
        // Outer loop header 1 (latch 4 -> 1), inner loop header 2 (latch 3 -> 2), exit 5
        let edges: [CFGEdge] = [
            .init(sourceBlockID: 0, targetBlockID: 1, kind: .unconditional),
            .init(sourceBlockID: 1, targetBlockID: 2, kind: .conditionalTrue),
            .init(sourceBlockID: 1, targetBlockID: 5, kind: .conditionalFalse),
            .init(sourceBlockID: 2, targetBlockID: 3, kind: .unconditional),
            .init(sourceBlockID: 3, targetBlockID: 2, kind: .conditionalTrue),
            .init(sourceBlockID: 3, targetBlockID: 4, kind: .conditionalFalse),
            .init(sourceBlockID: 4, targetBlockID: 1, kind: .unconditional)
        ]
        let blocks: [BasicBlock] = [
            makeDummyBlock(id: 0, succs: [1], preds: [], isEntry: true),
            makeDummyBlock(id: 1, succs: [2, 5], preds: [0, 4]),
            makeDummyBlock(id: 2, succs: [3], preds: [1, 3]),
            makeDummyBlock(id: 3, succs: [2, 4], preds: [2]),
            makeDummyBlock(id: 4, succs: [1], preds: [3]),
            makeDummyBlock(id: 5, succs: [], preds: [1], isExit: true)
        ]

        let result = DominatorAndLoopAnalyzer().analyze(blocks: blocks, edges: edges, entryBlockID: 0)
        #expect(result.isReducibleFlowGraph)
        #expect(result.naturalLoops.count == 2)
        #expect(result.backEdgePairs.count == 2)

        let outer = try! #require(result.naturalLoops.first { $0.headerBlockID == 1 })
        let inner = try! #require(result.naturalLoops.first { $0.headerBlockID == 2 })
        #expect(outer.nestingDepth == 1)
        #expect(inner.nestingDepth == 2)
        #expect(Set(outer.bodyBlockIDs) == [1, 2, 3, 4])
        #expect(Set(inner.bodyBlockIDs) == [2, 3])

        let annotatedByID = Dictionary(uniqueKeysWithValues: result.annotatedBlocks.map { ($0.id, $0) })
        #expect(annotatedByID[2]?.loopDepth == 2)
        #expect(annotatedByID[4]?.loopDepth == 1)
        #expect(annotatedByID[0]?.loopDepth == 0)
    }

    @Test("Structured control-flow region discovery detects loop, conditional, and switch regions")
    func structuredControlRegionDiscoveryOnDiamondLoopAndSwitch() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Regions.arm64e")

        let checksumFn = try #require(index.function(named: "_compute_checksum"))
        #expect(!checksumFn.naturalLoops.isEmpty)
        let checksumRegions = index.structuredRegionsByFunction[checksumFn.address] ?? []
        #expect(!checksumRegions.isEmpty)

        let verifyFn = try #require(index.function(named: "_verify_license"))
        let verifyRegions = index.structuredRegionsByFunction[verifyFn.address] ?? []
        #expect(!verifyRegions.isEmpty)
    }

    @Test("SugiyamaCFGLayoutSolver guarantees zero pairwise node bounding-box overlap across all binary functions")
    func sugiyamaLayoutZeroNodeOverlapAcrossAllBinaryFunctions() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Layout.arm64e")
        let solver = SugiyamaCFGLayoutSolver()

        for fn in index.functions where !fn.blocks.isEmpty {
            let layout = fn.layout ?? solver.solveLayout(for: fn)
            #expect(layout.nodes.count == fn.blocks.count)
            #expect(layout.canvasWidth > 0)
            #expect(layout.canvasHeight > 0)
            #expect(solver.verifyZeroNodeBoxOverlap(in: layout, insetEpsilon: 0.0))

            for i in 0..<layout.nodes.count {
                for j in (i + 1)..<layout.nodes.count {
                    let a = layout.nodes[i].frame
                    let b = layout.nodes[j].frame
                    #expect(!rectsStrictlyIntersect(a, b), "Node \(layout.nodes[i].blockID) intersects \(layout.nodes[j].blockID) in \(fn.name)")
                }
            }
        }
    }

    @Test("SugiyamaCFGLayoutSolver guarantees zero node overlap on dense 14-block multi-branch & back-edge stress CFG")
    func sugiyamaLayoutZeroNodeOverlapOnDenseMultiLayerStressCFG() {
        // 14-node graph with 5-way fan-out, cross-layer long edges, diamond merge, and 2 back-edges
        let succs: [Int: [Int]] = [
            0: [1, 2, 3, 4, 5],
            1: [6, 7],
            2: [7, 8],
            3: [8, 9],
            4: [9, 10],
            5: [10, 12],
            6: [11],
            7: [11],
            8: [11],
            9: [11],
            10: [11],
            11: [12, 1],
            12: [13, 0],
            13: []
        ]
        var preds: [Int: [Int]] = [:]
        var edges: [CFGEdge] = []
        for u in 0...13 {
            for (idx, v) in (succs[u] ?? []).enumerated() {
                preds[v, default: []].append(u)
                let isBack = v <= u
                let kind: CFGEdgeKind = (succs[u]?.count ?? 0) > 2 ? .switchCase(value: Int64(idx)) : .unconditional
                edges.append(CFGEdge(sourceBlockID: u, targetBlockID: v, kind: kind, isBackEdge: isBack))
            }
        }
        let blocks = (0...13).map { id in
            makeDummyBlock(
                id: id,
                succs: succs[id] ?? [],
                preds: preds[id] ?? [],
                isEntry: id == 0,
                isExit: id == 13
            )
        }

        let solver = SugiyamaCFGLayoutSolver()
        let layout = solver.solveLayout(
            functionAddress: VirtualAddress(0x1_0000_9000),
            blocks: blocks,
            edges: edges
        )

        #expect(layout.nodes.count == 14)
        #expect(layout.routes.count == edges.count)
        #expect(solver.verifyZeroNodeBoxOverlap(in: layout, insetEpsilon: 0.0))

        for i in 0..<layout.nodes.count {
            for j in (i + 1)..<layout.nodes.count {
                #expect(!rectsStrictlyIntersect(layout.nodes[i].frame, layout.nodes[j].frame))
            }
        }
    }

    @Test("SugiyamaCFGLayoutSolver produces valid finite orthogonal waypoints for forward and back edges")
    func sugiyamaLayoutOrthogonalWaypointsAndBackEdgeRouting() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Routes.arm64")

        let checksumFn = try #require(index.function(named: "_compute_checksum"))
        let layout = try #require(checksumFn.layout)
        #expect(layout.routes.count == checksumFn.edges.count)

        let backRoute = try #require(layout.routes.first { $0.edge.isBackEdge })
        #expect(backRoute.waypoints.count >= 4)

        for route in layout.routes {
            #expect(route.waypoints.count >= 2)
            for pt in route.waypoints {
                #expect(pt.x.isFinite && pt.y.isFinite)
            }
        }
    }

    @Test("CrossReferenceIndex resolves incoming/outgoing code Xrefs and STRING_REF to MACHGRAPH-PRO-2026")
    func crossReferenceIndexCodeAndStringXrefsInVerifyLicense() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Xrefs.arm64e")

        let verifyFn = try #require(index.function(named: "_verify_license"))
        let mainFn = try #require(index.function(named: "_main"))
        let checksumFn = try #require(index.function(named: "_compute_checksum"))

        let incomingVerify = index.xrefsTo(address: verifyFn.address)
        #expect(incomingVerify.contains { $0.fromFunction == mainFn.address && $0.kind == .directCall })

        let incomingChecksum = index.xrefsTo(address: checksumFn.address)
        #expect(incomingChecksum.contains { $0.fromFunction == verifyFn.address && $0.kind == .directCall })

        let licenseString = try #require(index.image.strings.first { $0.value == "MACHGRAPH-PRO-2026" })
        let strRefs = index.crossReferences.stringXrefs(to: licenseString.address)
        #expect(!strRefs.isEmpty)
        #expect(strRefs.contains { $0.fromFunction == verifyFn.address && $0.kind == .stringReference })
    }

    @Test("CrossReferenceIndex indexes imported stub call sites and chained fixup pointer xrefs")
    func crossReferenceIndexImportCallSitesAndChainedFixupXrefs() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Imports.arm64e")

        let strcmpCalls = index.crossReferences.importCallSites(matching: "strcmp")
        #expect(!strcmpCalls.isEmpty)
        #expect(strcmpCalls.contains { ($0.callerFunctionName ?? "").contains("verify_license") })

        let putsCalls = index.crossReferences.importCallSites(matching: "puts")
        #expect(!putsCalls.isEmpty)
    }

    @Test("ProgramCallGraph computes callers, callees, reachable functions, and shortest BFS call paths")
    func programCallGraphCallerCalleeAndShortestCallPath() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "CallGraph.arm64e")

        let mainFn = try #require(index.function(named: "_main"))
        let verifyFn = try #require(index.function(named: "_verify_license"))
        let checksumFn = try #require(index.function(named: "_compute_checksum"))

        #expect(index.callGraph.callees(of: mainFn.address).contains(verifyFn.address))
        #expect(index.callGraph.callers(of: verifyFn.address).contains(mainFn.address))

        let reachable = index.callGraph.reachableFunctions(from: mainFn.address)
        #expect(reachable.contains(verifyFn.address))
        #expect(reachable.contains(checksumFn.address))

        let path = try #require(index.shortestCallPath(from: mainFn.address, to: checksumFn.address))
        #expect(path.hopAddresses == [mainFn.address, verifyFn.address, checksumFn.address])
        #expect(path.hopCount == 2)
    }

    @Test("ProgramCallGraph classifies dangerous C sinks and finds mutual recursion strongly connected components")
    func programCallGraphDangerousSinkReachabilityAndRecursionSCCs() {
        #expect(BinaryAnalysisCoordinator.classifyDangerousSink(symbolName: "_strcpy") != nil)
        #expect(BinaryAnalysisCoordinator.classifyDangerousSink(symbolName: "_system") != nil)

        let fnA = VirtualAddress(0x1_0000_1000)
        let fnB = VirtualAddress(0x1_0000_2000)
        let sink = VirtualAddress(0x1_0000_3000)
        let sinkCat = BinaryAnalysisCoordinator.classifyDangerousSink(symbolName: "_system")

        let nodes = [
            CallGraphNode(address: fnA, name: "_main", demangledName: "_main", isEntryOrExported: true),
            CallGraphNode(address: fnB, name: "_helper", demangledName: "_helper"),
            CallGraphNode(address: sink, name: "_system", demangledName: "_system", isImportedThunk: true, sinkCategory: sinkCat)
        ]
        let edges = [
            CallGraphEdge(callerAddress: fnA, calleeAddress: fnB, callSiteAddresses: [fnA.adding(UInt64(8))]),
            CallGraphEdge(callerAddress: fnB, calleeAddress: fnA, callSiteAddresses: [fnB.adding(UInt64(12))]),
            CallGraphEdge(callerAddress: fnB, calleeAddress: sink, callSiteAddresses: [fnB.adding(UInt64(20))])
        ]
        let graph = ProgramCallGraph(nodes: nodes, edges: edges)

        let sccs = graph.stronglyConnectedRecursiveGroups()
        #expect(sccs.count == 1)
        #expect(Set(sccs[0]) == [fnA, fnB])

        let sinkPaths = graph.discoverDangerousSinkPaths(fromRoots: [fnA])
        #expect(!sinkPaths.isEmpty)
        #expect(sinkPaths[0].sinkAddress == sink)
    }

    @Test("BinaryAnalysisCoordinator end-to-end indexing and address/instruction lookup queries")
    func binaryAnalysisCoordinatorFullPipelineAndLookupQueries() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Coordinator.arm64e")

        let verifyFn = try #require(index.function(named: "verify_license"))
        let midAddress = verifyFn.address.adding(UInt64(8))
        #expect(index.function(containing: midAddress)?.address == verifyFn.address)
        #expect(index.instruction(at: verifyFn.address) != nil)
        #expect(!index.recognizedIdioms.isEmpty)
        #expect(index.postDominatorTrees[verifyFn.address] != nil)
    }

    @Test("GraphExportFormatter emits valid Graphviz DOT and Mermaid syntax for CFGs and call graphs")
    func graphExportFormatterDOTAndMermaidOutputs() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "ExportGraph.arm64")
        let verifyFn = try #require(index.function(named: "_verify_license"))

        let cfgDOT = index.exportCFGDOT(for: verifyFn)
        #expect(cfgDOT.contains("digraph"))
        #expect(cfgDOT.contains("->"))

        let cfgMermaid = index.exportCFGMermaid(for: verifyFn)
        #expect(cfgMermaid.contains("flowchart TD"))

        let cgDOT = index.exportCallGraphDOT()
        #expect(cgDOT.contains("digraph"))
        #expect(cgDOT.contains("_verify_license") || cgDOT.contains("verify_license"))
    }

    @Test("G2: decodeExecutableSections fails when section bytes are unavailable instead of fabricating ret instructions")
    func missingSectionBytesThrowsInsteadOfFabricatingRetStubs() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false, identifier: "com.test.g2.unique")
        let loaded = try UniversalBinaryDispatcher.load(data: data, filePath: "<in-memory-g2>", fileName: "G2.arm64")
        #expect(throws: MachGraphError.self) {
            _ = try FunctionDiscoveryEngine().decodeExecutableSections(in: loaded, data: nil)
        }
    }

    @Test("G3: analyzeBinary(image) without backing bytes fails instead of lazily generating built-in synthetic binaries")
    func analyzeBinaryWithoutBackingDataDoesNotMaterializeSyntheticFixtures() throws {
        let defaultBuiltIn = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false, includeCMSCertificates: true)
        let image = try UniversalBinaryDispatcher.load(
            data: defaultBuiltIn,
            filePath: "<in-memory-unregistered>",
            fileName: "Unregistered.arm64"
        )
        #expect(throws: MachGraphError.self) {
            _ = try BinaryAnalysisCoordinator().analyzeBinary(image)
        }
    }

    @Test("G9: Non-ARM64 x86_64 slice is rejected with unsupportedArchitecture rather than toy 5-byte recognizer")
    func nonARM64X86SliceThrowsUnsupportedArchitecture() throws {
        let fatData = SyntheticBinaryFixtureBuilder.buildUniversalFatBinary()
        #expect(throws: MachGraphError.self) {
            _ = try BinaryAnalysisCoordinator().analyzeBinary(
                data: fatData,
                fileName: "UniversalFat.x86_64",
                preferredSliceIndex: 0
            )
        }
    }
}
