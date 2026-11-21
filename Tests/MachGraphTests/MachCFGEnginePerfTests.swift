import Foundation
import Testing
import MachGraphModels
@testable import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine

@Suite("M4 Stage 2: CFG Engine Performance Fast Paths & Zero-Drift Equivalence")
struct MachCFGEnginePerfTests {

    @Test("DominatorAndLoopAnalyzer skips post-dominators and structured regions on demand while preserving full structured region recovery by default")
    func dominatorAnalyzerOnDemandPostDomAndPrebuiltRegionAdjacency() {
        let fnAddr = VirtualAddress(0x1_0000_1000)
        func makeBlock(_ id: Int, isEntry: Bool = false, isExit: Bool = false, preds: [Int], succs: [Int]) -> BasicBlock {
            let start = fnAddr.adding(UInt64(id * 8))
            return BasicBlock(
                id: id,
                functionAddress: fnAddr,
                startAddress: start,
                endAddress: start.adding(UInt64(8)),
                instructions: [],
                predecessorIDs: preds,
                successorIDs: succs,
                isEntry: isEntry,
                isExit: isExit
            )
        }

        // B0 (entry) -> loop B1 -> switch B2 -> (B3, B4, B5) -> merge B6 -> if/else (B7, B8) -> exit B9
        let blocks: [BasicBlock] = [
            makeBlock(0, isEntry: true, preds: [], succs: [1]),
            makeBlock(1, preds: [0, 1], succs: [1, 2]),
            makeBlock(2, preds: [1], succs: [3, 4, 5]),
            makeBlock(3, preds: [2], succs: [6]),
            makeBlock(4, preds: [2], succs: [6]),
            makeBlock(5, preds: [2], succs: [6]),
            makeBlock(6, preds: [3, 4, 5], succs: [7, 8]),
            makeBlock(7, preds: [6], succs: [9]),
            makeBlock(8, preds: [6], succs: [9]),
            makeBlock(9, isExit: true, preds: [7, 8], succs: [])
        ]
        let edges: [CFGEdge] = [
            CFGEdge(sourceBlockID: 0, targetBlockID: 1, kind: .fallthroughEdge),
            CFGEdge(sourceBlockID: 1, targetBlockID: 1, kind: .conditionalTrue),
            CFGEdge(sourceBlockID: 1, targetBlockID: 2, kind: .conditionalFalse),
            CFGEdge(sourceBlockID: 2, targetBlockID: 3, kind: .switchCase(value: 0)),
            CFGEdge(sourceBlockID: 2, targetBlockID: 4, kind: .switchCase(value: 1)),
            CFGEdge(sourceBlockID: 2, targetBlockID: 5, kind: .switchCase(value: 2)),
            CFGEdge(sourceBlockID: 3, targetBlockID: 6, kind: .unconditional),
            CFGEdge(sourceBlockID: 4, targetBlockID: 6, kind: .unconditional),
            CFGEdge(sourceBlockID: 5, targetBlockID: 6, kind: .unconditional),
            CFGEdge(sourceBlockID: 6, targetBlockID: 7, kind: .conditionalTrue),
            CFGEdge(sourceBlockID: 6, targetBlockID: 8, kind: .conditionalFalse),
            CFGEdge(sourceBlockID: 7, targetBlockID: 9, kind: .unconditional),
            CFGEdge(sourceBlockID: 8, targetBlockID: 9, kind: .unconditional)
        ]

        let analyzer = DominatorAndLoopAnalyzer()
        let full = analyzer.analyze(blocks: blocks, edges: edges, entryBlockID: 0)
        let cfgOnly = analyzer.analyze(blocks: blocks, edges: edges, entryBlockID: 0, includePostDominatorsAndRegions: false)

        // Forward dominator tree, natural loops, and block/edge loop annotations must be 100% identical
        #expect(cfgOnly.dominatorTree == full.dominatorTree)
        #expect(cfgOnly.naturalLoops == full.naturalLoops)
        #expect(cfgOnly.backEdgePairs == full.backEdgePairs)
        #expect(cfgOnly.irreducibleRetreatEdges == full.irreducibleRetreatEdges)
        #expect(cfgOnly.annotatedBlocks == full.annotatedBlocks)
        #expect(cfgOnly.annotatedEdges == full.annotatedEdges)

        // Fast path skips post-dominators and structured regions
        #expect(cfgOnly.postDominatorTree.isEmpty)
        #expect(cfgOnly.structuredRegions.isEmpty)

        // Default full path preserves post-dominator tree and structured regions (`selfLoop`, `switchDispatch`, `ifThenElse`)
        #expect(full.postDominatorTree.count == blocks.count)
        let switchRegion = full.structuredRegions.first { $0.kind == .switchDispatch && $0.headerBlockID == 2 }
        #expect(switchRegion?.followMergeBlockID == 6)
        #expect(switchRegion?.bodyBlockIDs == [2, 3, 4, 5])
        let ifElseRegion = full.structuredRegions.first { $0.kind == .ifThenElse && $0.headerBlockID == 6 }
        #expect(ifElseRegion?.followMergeBlockID == 9)
        #expect(ifElseRegion?.bodyBlockIDs == [6, 7, 8])
    }

    @Test("analyzeCFGOnly full-file and single-function modes match analyzeBinary byte-for-byte on repo sample fixture")
    func analyzeCFGOnlyMatchesAnalyzeBinaryOnSampleFixture() throws {
        let data = try RepoFixtures.thinARM64SampleData()
        let url = RepoFixtures.thinARM64SampleURL
        let image = try UniversalBinaryDispatcher.load(data: data, filePath: url.path, fileName: url.lastPathComponent)

        let cliOptions = BinaryAnalysisOptions(computeSugiyamaLayouts: false, computePostDominatorTrees: false)
        let coordinator = BinaryAnalysisCoordinator(options: cliOptions)

        let fullIndex = try coordinator.analyzeBinary(image, data: data)
        #expect(fullIndex.postDominatorTrees.isEmpty)
        #expect(fullIndex.structuredRegionsByFunction.isEmpty)

        let cfgSnapshot = try coordinator.analyzeCFGOnly(image, data: data, selector: nil)
        #expect(cfgSnapshot.functions == fullIndex.functions)
        #expect(cfgSnapshot.inlineJumpTableRanges == fullIndex.inlineJumpTableRanges)

        for expectedFn in fullIndex.functions {
            let byAddr = try coordinator.analyzeCFGOnly(image, data: data, selector: .address(expectedFn.address))
            #expect(byAddr.functions == [expectedFn])

            let bySym = try coordinator.analyzeCFGOnly(image, data: data, selector: .symbol(expectedFn.name))
            #expect(bySym.functions.count == 1)
        }

        let missing = try coordinator.analyzeCFGOnly(image, data: data, selector: .symbol("__nonexistent_symbol__"))
        #expect(missing.functions.isEmpty)
    }
}
