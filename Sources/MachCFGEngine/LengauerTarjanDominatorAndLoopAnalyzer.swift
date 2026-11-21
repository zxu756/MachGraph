import Foundation
import MachGraphModels

// MARK: - Post-Dominator & Structured Control-Flow Region Models

public struct PostDominatorTreeNode: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { blockID }
    public let blockID: Int
    /// Immediate post-dominator `blockID`, or `nil` when post-dominated directly by the procedure's virtual exit.
    public let immediatePostDominatorID: Int?
    public let postDominatedChildrenIDs: [Int]
    public let postDominanceFrontierIDs: [Int]
    public let depthFromExit: Int

    public init(
        blockID: Int,
        immediatePostDominatorID: Int?,
        postDominatedChildrenIDs: [Int] = [],
        postDominanceFrontierIDs: [Int] = [],
        depthFromExit: Int = 0
    ) {
        self.blockID = blockID
        self.immediatePostDominatorID = immediatePostDominatorID
        self.postDominatedChildrenIDs = postDominatedChildrenIDs
        self.postDominanceFrontierIDs = postDominanceFrontierIDs
        self.depthFromExit = depthFromExit
    }
}

public enum StructuredRegionKind: String, Sendable, Codable, Hashable, CaseIterable {
    case ifThen = "if-then"
    case ifThenElse = "if-then-else"
    case switchDispatch = "switch"
    case whileLoop = "while"
    case doWhileLoop = "do-while"
    case selfLoop = "self-loop"
}

public struct StructuredControlRegion: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue)@\(headerBlockID)" }
    public let kind: StructuredRegionKind
    public let headerBlockID: Int
    public let thenBlockID: Int?
    public let elseBlockID: Int?
    /// Exact merge (`follow`) block ID computed from the post-dominator tree (`ipdom`), if convergent.
    public let followMergeBlockID: Int?
    public let bodyBlockIDs: [Int]

    public init(
        kind: StructuredRegionKind,
        headerBlockID: Int,
        thenBlockID: Int? = nil,
        elseBlockID: Int? = nil,
        followMergeBlockID: Int? = nil,
        bodyBlockIDs: [Int] = []
    ) {
        self.kind = kind
        self.headerBlockID = headerBlockID
        self.thenBlockID = thenBlockID
        self.elseBlockID = elseBlockID
        self.followMergeBlockID = followMergeBlockID
        self.bodyBlockIDs = bodyBlockIDs
    }
}

public struct DominatorAndLoopAnalysisResult: Sendable, Codable, Hashable {
    public let dominatorTree: [DominatorTreeNode]
    public let postDominatorTree: [PostDominatorTreeNode]
    public let naturalLoops: [NaturalLoop]
    public let backEdgePairs: Set<CFGDirectedPair>
    public let irreducibleRetreatEdges: Set<CFGDirectedPair>
    public let structuredRegions: [StructuredControlRegion]
    public let annotatedBlocks: [BasicBlock]
    public let annotatedEdges: [CFGEdge]

    public init(
        dominatorTree: [DominatorTreeNode],
        postDominatorTree: [PostDominatorTreeNode],
        naturalLoops: [NaturalLoop],
        backEdgePairs: Set<CFGDirectedPair>,
        irreducibleRetreatEdges: Set<CFGDirectedPair> = [],
        structuredRegions: [StructuredControlRegion] = [],
        annotatedBlocks: [BasicBlock],
        annotatedEdges: [CFGEdge]
    ) {
        self.dominatorTree = dominatorTree
        self.postDominatorTree = postDominatorTree
        self.naturalLoops = naturalLoops
        self.backEdgePairs = backEdgePairs
        self.irreducibleRetreatEdges = irreducibleRetreatEdges
        self.structuredRegions = structuredRegions
        self.annotatedBlocks = annotatedBlocks
        self.annotatedEdges = annotatedEdges
    }

    public var isReducibleFlowGraph: Bool {
        irreducibleRetreatEdges.isEmpty
    }
}

// MARK: - Lengauer-Tarjan O(E alpha(V)) Dominator, Post-Dominator & Natural Loop Analyzer

public struct DominatorAndLoopAnalyzer: Sendable {
    public init() {}

    // MARK: - Unified Full Analysis Entry Point

    /// Runs the complete dominance, dominance-frontier, natural-loop, and (when `includePostDominatorsAndRegions`
    /// is `true`) post-dominance and structured-region analysis pass over `(blocks, edges)` and returns annotated
    /// blocks (`loopDepth`) and edges (`isBackEdge`).
    public func analyze(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        entryBlockID: Int? = nil,
        includePostDominatorsAndRegions: Bool = true
    ) -> DominatorAndLoopAnalysisResult {
        guard !blocks.isEmpty else {
            return DominatorAndLoopAnalysisResult(
                dominatorTree: [],
                postDominatorTree: [],
                naturalLoops: [],
                backEdgePairs: [],
                irreducibleRetreatEdges: [],
                structuredRegions: [],
                annotatedBlocks: [],
                annotatedEdges: []
            )
        }

        let resolvedEntry = entryBlockID
            ?? blocks.first(where: \.isEntry)?.id
            ?? blocks[0].id

        // 1. Forward Lengauer-Tarjan Dominator Tree + Cooper-Harvey-Kennedy Dominance Frontiers
        let domTree = computeDominatorTree(
            blocks: blocks,
            edges: edges,
            entryBlockID: resolvedEntry
        )

        // 2. Natural Loop Recovery (back-edges u -> h where h dom u, body worklist, nesting depth, exits)
        let loopRecovery = recoverNaturalLoops(
            blocks: blocks,
            edges: edges,
            dominatorTree: domTree,
            entryBlockID: resolvedEntry
        )

        // 3. Annotate `BasicBlock.loopDepth` and `CFGEdge.isBackEdge`
        let allBackEdges = loopRecovery.backEdges.union(loopRecovery.irreducibleRetreatEdges)
        let (annotatedBlocks, annotatedEdges) = annotateCFGWithLoops(
            blocks: blocks,
            edges: edges,
            naturalLoops: loopRecovery.loops,
            backEdgePairs: allBackEdges
        )

        // 4. Optional Post-Dominator Tree (`ipdom`) & Structured Control-Flow Regions (`if/else`, `switch`, loops)
        let postDomTree: [PostDominatorTreeNode]
        let structuredRegions: [StructuredControlRegion]
        if includePostDominatorsAndRegions {
            let computedPostDom = computePostDominatorTree(
                blocks: blocks,
                edges: edges
            )
            postDomTree = computedPostDom
            structuredRegions = discoverStructuredRegions(
                blocks: annotatedBlocks,
                edges: annotatedEdges,
                dominatorTree: domTree,
                postDominatorTree: computedPostDom,
                naturalLoops: loopRecovery.loops
            )
        } else {
            postDomTree = []
            structuredRegions = []
        }

        return DominatorAndLoopAnalysisResult(
            dominatorTree: domTree,
            postDominatorTree: postDomTree,
            naturalLoops: loopRecovery.loops,
            backEdgePairs: allBackEdges,
            irreducibleRetreatEdges: loopRecovery.irreducibleRetreatEdges,
            structuredRegions: structuredRegions,
            annotatedBlocks: annotatedBlocks,
            annotatedEdges: annotatedEdges
        )
    }

    // MARK: - 1. Handwritten Lengauer-Tarjan O(E alpha(V)) Immediate Dominator + DF Solver

    /// Computes `[DominatorTreeNode]` using Lengauer & Tarjan's (TOPLAS 1979) $O(E \alpha(V))$ balanced
    /// semidominator forest algorithm (`LINK`/`EVAL`/`COMPRESS`) paired with Cooper-Harvey-Kennedy
    /// Dominance Frontier (`DF`) construction for Cytron SSA $\phi$-node placement.
    public func computeDominatorTree(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        entryBlockID: Int? = nil
    ) -> [DominatorTreeNode] {
        guard !blocks.isEmpty else { return [] }

        let allBlockIDs = blocks.map(\.id)
        let resolvedEntry = entryBlockID
            ?? blocks.first(where: \.isEntry)?.id
            ?? blocks[0].id

        var succMap: [Int: [Int]] = [:]
        var predMap: [Int: [Int]] = [:]
        for id in allBlockIDs {
            succMap[id] = []
            predMap[id] = []
        }

        if !edges.isEmpty {
            for e in edges where succMap[e.sourceBlockID] != nil && succMap[e.targetBlockID] != nil {
                if !(succMap[e.sourceBlockID]?.contains(e.targetBlockID) ?? false) {
                    succMap[e.sourceBlockID, default: []].append(e.targetBlockID)
                }
                if !(predMap[e.targetBlockID]?.contains(e.sourceBlockID) ?? false) {
                    predMap[e.targetBlockID, default: []].append(e.sourceBlockID)
                }
            }
        } else {
            for b in blocks {
                succMap[b.id] = b.successorIDs
                predMap[b.id] = b.predecessorIDs
            }
        }

        let idomByBlock = runLengauerTarjanCore(
            vertexIDs: allBlockIDs,
            rootID: resolvedEntry,
            successors: succMap,
            predecessors: predMap
        )

        // Assemble children lists in deterministic ascending blockID order
        var childrenByBlock: [Int: [Int]] = [:]
        for id in allBlockIDs {
            childrenByBlock[id] = []
        }
        for (blockID, maybeIdom) in idomByBlock {
            if let idom = maybeIdom {
                childrenByBlock[idom, default: []].append(blockID)
            }
        }
        for id in allBlockIDs {
            childrenByBlock[id]?.sort()
        }

        // Compute tree depths via BFS from `resolvedEntry`
        // Note: `idomByBlock[resolvedEntry]` is `nil`, and assigning `nil` to a `[Int: Int?]` subscript removes
        // the key unless `updateValue(nil, forKey:)` is used; check `succMap[resolvedEntry] != nil` directly!
        var depthByBlock: [Int: Int] = [:]
        if succMap[resolvedEntry] != nil {
            depthByBlock[resolvedEntry] = 0
            var queue: [Int] = [resolvedEntry]
            var head = 0
            while head < queue.count {
                let curr = queue[head]
                head += 1
                let nextDepth = (depthByBlock[curr] ?? 0) + 1
                for child in childrenByBlock[curr] ?? [] {
                    depthByBlock[child] = nextDepth
                    queue.append(child)
                }
            }
        }

        // Compute Dominance Frontiers (`DF`) using Cooper-Harvey-Kennedy runner walk over reachable join nodes
        let reachableSet = Set(depthByBlock.keys)
        let dfByBlock = computeDominanceFrontiers(
            blockIDs: allBlockIDs,
            reachableSet: reachableSet,
            predecessors: predMap,
            idomByBlock: idomByBlock
        )

        return blocks.map { b in
            let idom = idomByBlock[b.id] ?? nil
            let children = childrenByBlock[b.id] ?? []
            let df = dfByBlock[b.id] ?? []
            let depth = depthByBlock[b.id] ?? 0
            return DominatorTreeNode(
                blockID: b.id,
                immediateDominatorID: idom,
                dominatedChildrenIDs: children,
                dominanceFrontierIDs: df,
                depth: depth
            )
        }
    }

    /// Computes the Iterated Dominance Frontier $DF^+(S)$ for a set of variable-defining `blockID`s —
    /// directly yielding the exact set of basic blocks requiring SSA $\phi$-functions in Cytron's algorithm.
    public func iteratedDominanceFrontier(
        forDefinitionBlocks definitionBlockIDs: Set<Int>,
        dominatorTree: [DominatorTreeNode]
    ) -> [Int] {
        guard !definitionBlockIDs.isEmpty && !dominatorTree.isEmpty else { return [] }

        var dfMap: [Int: [Int]] = [:]
        dfMap.reserveCapacity(dominatorTree.count)
        for node in dominatorTree {
            dfMap[node.blockID] = node.dominanceFrontierIDs
        }

        var idfResult = Set<Int>()
        var worklist = Array(definitionBlockIDs)
        var everQueued = definitionBlockIDs

        while let current = worklist.popLast() {
            for frontierBlock in dfMap[current] ?? [] {
                if idfResult.insert(frontierBlock).inserted {
                    if everQueued.insert(frontierBlock).inserted {
                        worklist.append(frontierBlock)
                    }
                }
            }
        }

        return idfResult.sorted()
    }

    // MARK: - 2. Post-Dominator Tree (`ipdom`) & Structured Merge-Point Solver

    /// Computes `[PostDominatorTreeNode]` on the reversed CFG augmented with a virtual super-exit sentinel,
    /// handling multiple `ret`/`brk`/tail-call exits as well as non-terminating infinite-loop components.
    public func computePostDominatorTree(
        blocks: [BasicBlock],
        edges: [CFGEdge]
    ) -> [PostDominatorTreeNode] {
        guard !blocks.isEmpty else { return [] }

        let virtualExitID = -1
        let allRealIDs = blocks.map(\.id)
        var forwardSuccs: [Int: [Int]] = [:]
        var forwardPreds: [Int: [Int]] = [:]
        for id in allRealIDs {
            forwardSuccs[id] = []
            forwardPreds[id] = []
        }

        if !edges.isEmpty {
            for e in edges where forwardSuccs[e.sourceBlockID] != nil && forwardSuccs[e.targetBlockID] != nil {
                if !(forwardSuccs[e.sourceBlockID]?.contains(e.targetBlockID) ?? false) {
                    forwardSuccs[e.sourceBlockID, default: []].append(e.targetBlockID)
                }
                if !(forwardPreds[e.targetBlockID]?.contains(e.sourceBlockID) ?? false) {
                    forwardPreds[e.targetBlockID, default: []].append(e.sourceBlockID)
                }
            }
        } else {
            for b in blocks {
                forwardSuccs[b.id] = b.successorIDs
                forwardPreds[b.id] = b.predecessorIDs
            }
        }

        // Identify exit blocks (explicit exits or zero outgoing edges)
        var exitBlockIDs: [Int] = []
        for b in blocks {
            if b.isExit || (forwardSuccs[b.id]?.isEmpty ?? true) {
                exitBlockIDs.append(b.id)
            }
        }

        // Build Reversed Graph rooted at `virtualExitID`:
        // Every real edge `u -> v` becomes reversed edge `v -> u`;
        // Every exit block `x` gets `virtualExitID -> x` in the reversed graph.
        var revSuccs: [Int: [Int]] = [virtualExitID: []]
        var revPreds: [Int: [Int]] = [virtualExitID: []]
        for id in allRealIDs {
            revSuccs[id] = forwardPreds[id] ?? []
            revPreds[id] = forwardSuccs[id] ?? []
        }

        for exitID in exitBlockIDs {
            revSuccs[virtualExitID, default: []].append(exitID)
            revPreds[exitID, default: []].append(virtualExitID)
        }

        // Handle non-terminating loops (blocks that cannot reach any exit block in forward CFG):
        // Connect the highest-ID block of each non-exiting sink component to `virtualExitID` so post-dominance covers 100% of blocks.
        let reverseReachable = collectReachable(from: virtualExitID, successors: revSuccs)
        let unreachedByExit = allRealIDs.filter { !reverseReachable.contains($0) }
        if !unreachedByExit.isEmpty {
            var covered = reverseReachable
            for candidate in unreachedByExit.reversed() where !covered.contains(candidate) {
                revSuccs[virtualExitID, default: []].append(candidate)
                revPreds[candidate, default: []].append(virtualExitID)
                let newlyCovered = collectReachable(from: candidate, successors: revSuccs)
                covered.formUnion(newlyCovered)
            }
        }

        let augmentedVertices = [virtualExitID] + allRealIDs
        let rawIpdom = runLengauerTarjanCore(
            vertexIDs: augmentedVertices,
            rootID: virtualExitID,
            successors: revSuccs,
            predecessors: revPreds
        )

        // Normalize `virtualExitID` parent to `nil` for real blocks
        var ipdomByRealBlock: [Int: Int?] = [:]
        var postChildrenByBlock: [Int: [Int]] = [:]
        for id in allRealIDs {
            postChildrenByBlock[id] = []
        }

        for id in allRealIDs {
            if let parent = rawIpdom[id] ?? nil, parent != virtualExitID {
                ipdomByRealBlock[id] = parent
                postChildrenByBlock[parent, default: []].append(id)
            } else {
                ipdomByRealBlock[id] = nil
            }
        }
        for id in allRealIDs {
            postChildrenByBlock[id]?.sort()
        }

        // Compute depth from virtual exit
        var depthFromExit: [Int: Int] = [:]
        var queue: [Int] = allRealIDs.filter { (ipdomByRealBlock[$0] ?? nil) == nil }
        for rootChild in queue {
            depthFromExit[rootChild] = 1
        }
        var head = 0
        while head < queue.count {
            let curr = queue[head]
            head += 1
            let nextDepth = (depthFromExit[curr] ?? 1) + 1
            for child in postChildrenByBlock[curr] ?? [] {
                depthFromExit[child] = nextDepth
                queue.append(child)
            }
        }

        // Compute Post-Dominance Frontiers (`PDF` — control dependence graph!) on reversed CFG
        let augmentedReachable = Set(augmentedVertices)
        let rawPDF = computeDominanceFrontiers(
            blockIDs: augmentedVertices,
            reachableSet: augmentedReachable,
            predecessors: revPreds,
            idomByBlock: rawIpdom
        )

        return blocks.map { b in
            let pdf = (rawPDF[b.id] ?? []).filter { $0 != virtualExitID }
            return PostDominatorTreeNode(
                blockID: b.id,
                immediatePostDominatorID: ipdomByRealBlock[b.id] ?? nil,
                postDominatedChildrenIDs: postChildrenByBlock[b.id] ?? [],
                postDominanceFrontierIDs: pdf,
                depthFromExit: depthFromExit[b.id] ?? 0
            )
        }
    }

    /// Returns the immediate structured merge (`follow`) block ID for a conditional/switch branch header `blockID`.
    public func structuredMergeBlockID(
        forBranchBlock blockID: Int,
        postDominatorTree: [PostDominatorTreeNode]
    ) -> Int? {
        postDominatorTree.first(where: { $0.blockID == blockID })?.immediatePostDominatorID
    }

    // MARK: - 3. Natural Loop Recovery & Loop Nesting Forest

    /// Identifies natural back-edges `(u -> h)` where `h` dominates `u`, collects loop bodies via reverse CFG
    /// reachability, computes exit targets & nesting depth, and detects any irreducible retreat edges.
    public func recoverNaturalLoops(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        dominatorTree: [DominatorTreeNode],
        entryBlockID: Int? = nil
    ) -> (
        loops: [NaturalLoop],
        backEdges: Set<CFGDirectedPair>,
        irreducibleRetreatEdges: Set<CFGDirectedPair>
    ) {
        guard !blocks.isEmpty && !edges.isEmpty else {
            return ([], [], [])
        }

        let dominanceAncestorSets = buildDominatorAncestorSets(dominatorTree: dominatorTree)
        let reachableBlockIDs = Set(dominanceAncestorSets.keys)

        var predMap: [Int: [Int]] = [:]
        var succMap: [Int: [Int]] = [:]
        for b in blocks {
            predMap[b.id] = []
            succMap[b.id] = []
        }
        for e in edges {
            succMap[e.sourceBlockID, default: []].append(e.targetBlockID)
            predMap[e.targetBlockID, default: []].append(e.sourceBlockID)
        }

        // Identify natural back-edges: (u -> h) where both u and h are reachable and h dominates u
        var latchesByHeader: [Int: Set<Int>] = [:]
        var naturalBackEdges = Set<CFGDirectedPair>()

        for edge in edges {
            let u = edge.sourceBlockID
            let h = edge.targetBlockID
            guard reachableBlockIDs.contains(u),
                  let domAncestorsOfU = dominanceAncestorSets[u] else {
                continue
            }
            if domAncestorsOfU.contains(h) {
                latchesByHeader[h, default: []].insert(u)
                naturalBackEdges.insert(CFGDirectedPair(sourceBlockID: u, targetBlockID: h))
            }
        }

        // Also detect DFS retreat edges not dominated by their target (irreducible multi-entry cycles)
        let resolvedEntry = entryBlockID
            ?? blocks.first(where: \.isEntry)?.id
            ?? blocks[0].id
        let dfsRetreatEdges = findDFSRetreatEdges(
            entryBlockID: resolvedEntry,
            successors: succMap
        )
        let irreducibleEdges = dfsRetreatEdges.subtracting(naturalBackEdges)

        guard !latchesByHeader.isEmpty else {
            return ([], naturalBackEdges, irreducibleEdges)
        }

        // Recover body & exit blocks for each natural loop header
        struct PreliminaryLoop {
            let headerID: Int
            let latchIDs: [Int]
            let bodySet: Set<Int>
            let bodyIDs: [Int]
            let exitIDs: [Int]
        }

        var prelimLoops: [PreliminaryLoop] = []
        for headerID in latchesByHeader.keys.sorted() {
            let latches = (latchesByHeader[headerID] ?? []).sorted()
            var bodySet: Set<Int> = [headerID]
            var stack: [Int] = []

            for latch in latches where bodySet.insert(latch).inserted {
                stack.append(latch)
            }

            while let curr = stack.popLast() {
                for pred in predMap[curr] ?? [] where reachableBlockIDs.contains(pred) {
                    if bodySet.insert(pred).inserted {
                        stack.append(pred)
                    }
                }
            }

            // Collect exit target blocks outside the loop body
            var exitSet = Set<Int>()
            for memberID in bodySet {
                for succID in succMap[memberID] ?? [] where !bodySet.contains(succID) {
                    exitSet.insert(succID)
                }
            }

            prelimLoops.append(
                PreliminaryLoop(
                    headerID: headerID,
                    latchIDs: latches,
                    bodySet: bodySet,
                    bodyIDs: bodySet.sorted(),
                    exitIDs: exitSet.sorted()
                )
            )
        }

        // Compute loop nesting depth: loop A is nested inside loop B iff A.header != B.header and B.bodySet.contains(A.header)
        let finalLoops: [NaturalLoop] = prelimLoops.map { candidate in
            var enclosingCount = 0
            for other in prelimLoops where other.headerID != candidate.headerID {
                if other.bodySet.contains(candidate.headerID) && other.bodySet.count >= candidate.bodySet.count {
                    enclosingCount += 1
                }
            }
            return NaturalLoop(
                headerBlockID: candidate.headerID,
                latchBlockIDs: candidate.latchIDs,
                bodyBlockIDs: candidate.bodyIDs,
                exitBlockIDs: candidate.exitIDs,
                nestingDepth: enclosingCount + 1
            )
        }

        return (finalLoops, naturalBackEdges, irreducibleEdges)
    }

    /// Returns the in-loop basic block IDs that carry outgoing edges exiting `loop` (`ExitingBlocks` in LLVM terminology).
    public func exitingBlockIDs(for loop: NaturalLoop, blocks: [BasicBlock]) -> [Int] {
        let bodySet = Set(loop.bodyBlockIDs)
        var blockMap: [Int: BasicBlock] = [:]
        for b in blocks { blockMap[b.id] = b }

        var exiting: [Int] = []
        for bID in loop.bodyBlockIDs {
            guard let block = blockMap[bID] else { continue }
            if block.successorIDs.contains(where: { !bodySet.contains($0) }) {
                exiting.append(bID)
            }
        }
        return exiting
    }

    // MARK: - 4. Dominance & Lowest-Common-Dominator Query API

    /// Returns `true` iff `dominatorID` dominates `targetID` (reflexive: `dominates(x, x) == true`).
    public func dominates(
        _ dominatorID: Int,
        _ targetID: Int,
        in dominatorTree: [DominatorTreeNode]
    ) -> Bool {
        if dominatorID == targetID { return true }
        return strictlyDominates(dominatorID, targetID, in: dominatorTree)
    }

    /// Returns `true` iff `dominatorID != targetID` and `dominatorID` is an ancestor of `targetID` in `dominatorTree`.
    public func strictlyDominates(
        _ dominatorID: Int,
        _ targetID: Int,
        in dominatorTree: [DominatorTreeNode]
    ) -> Bool {
        guard dominatorID != targetID else { return false }
        var idomMap: [Int: Int?] = [:]
        idomMap.reserveCapacity(dominatorTree.count)
        for n in dominatorTree {
            idomMap[n.blockID] = n.immediateDominatorID
        }

        var cursor = idomMap[targetID] ?? nil
        var guardSteps = 0
        while let current = cursor, guardSteps <= dominatorTree.count {
            if current == dominatorID {
                return true
            }
            cursor = idomMap[current] ?? nil
            guardSteps += 1
        }
        return false
    }

    /// Returns `true` iff `postDominatorID` post-dominates `targetID`.
    public func postDominates(
        _ postDominatorID: Int,
        _ targetID: Int,
        in postDominatorTree: [PostDominatorTreeNode]
    ) -> Bool {
        if postDominatorID == targetID { return true }
        var ipdomMap: [Int: Int?] = [:]
        ipdomMap.reserveCapacity(postDominatorTree.count)
        for n in postDominatorTree {
            ipdomMap[n.blockID] = n.immediatePostDominatorID
        }

        var cursor = ipdomMap[targetID] ?? nil
        var guardSteps = 0
        while let current = cursor, guardSteps <= postDominatorTree.count {
            if current == postDominatorID {
                return true
            }
            cursor = ipdomMap[current] ?? nil
            guardSteps += 1
        }
        return false
    }

    /// Computes the Lowest Common Dominator (LCA in the dominator tree) of `blockA` and `blockB`.
    public func lowestCommonDominator(
        _ blockA: Int,
        _ blockB: Int,
        in dominatorTree: [DominatorTreeNode]
    ) -> Int? {
        var nodeMap: [Int: DominatorTreeNode] = [:]
        for n in dominatorTree { nodeMap[n.blockID] = n }
        guard var nodeA = nodeMap[blockA], var nodeB = nodeMap[blockB] else { return nil }

        while nodeA.depth > nodeB.depth {
            guard let parentID = nodeA.immediateDominatorID, let parent = nodeMap[parentID] else { return nil }
            nodeA = parent
        }
        while nodeB.depth > nodeA.depth {
            guard let parentID = nodeB.immediateDominatorID, let parent = nodeMap[parentID] else { return nil }
            nodeB = parent
        }
        while nodeA.blockID != nodeB.blockID {
            guard let pA = nodeA.immediateDominatorID,
                  let pB = nodeB.immediateDominatorID,
                  let nextA = nodeMap[pA],
                  let nextB = nodeMap[pB] else {
                return nil
            }
            nodeA = nextA
            nodeB = nextB
        }
        return nodeA.blockID
    }

    // MARK: - 5. Structured Region Discovery (Consumed by MachMicroDecompiler)

    /// Identifies structured `if-then`, `if-then-else`, `switch`, `while`, `do-while`, and `self-loop` regions
    /// by combining natural loops with immediate post-dominator (`ipdom`) merge points.
    public func discoverStructuredRegions(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        dominatorTree: [DominatorTreeNode],
        postDominatorTree: [PostDominatorTreeNode],
        naturalLoops: [NaturalLoop]
    ) -> [StructuredControlRegion] {
        guard !blocks.isEmpty else { return [] }

        var ipdomMap: [Int: Int?] = [:]
        for n in postDominatorTree {
            ipdomMap[n.blockID] = n.immediatePostDominatorID
        }

        var outgoingEdgesByBlock: [Int: [CFGEdge]] = [:]
        for e in edges {
            outgoingEdgesByBlock[e.sourceBlockID, default: []].append(e)
        }

        var loopByHeader: [Int: NaturalLoop] = [:]
        for loop in naturalLoops {
            loopByHeader[loop.headerBlockID] = loop
        }

        var regions: [StructuredControlRegion] = []

        // A. Classify Natural Loops (`selfLoop`, `whileLoop`, `doWhileLoop`)
        for loop in naturalLoops {
            let headerID = loop.headerBlockID
            let bodySet = Set(loop.bodyBlockIDs)
            let followID = loop.exitBlockIDs.first ?? (ipdomMap[headerID] ?? nil)

            if loop.bodyBlockIDs.count == 1 && loop.latchBlockIDs == [headerID] {
                regions.append(
                    StructuredControlRegion(
                        kind: .selfLoop,
                        headerBlockID: headerID,
                        followMergeBlockID: followID,
                        bodyBlockIDs: loop.bodyBlockIDs
                    )
                )
                continue
            }

            let headerOut = outgoingEdgesByBlock[headerID] ?? []
            let headerExitsLoop = headerOut.contains { !bodySet.contains($0.targetBlockID) }
            let kind: StructuredRegionKind = headerExitsLoop ? .whileLoop : .doWhileLoop

            regions.append(
                StructuredControlRegion(
                    kind: kind,
                    headerBlockID: headerID,
                    followMergeBlockID: followID,
                    bodyBlockIDs: loop.bodyBlockIDs
                )
            )
        }

        // B. Classify Acyclic Conditional & Switch Regions (prebuild forward adjacency map once per function)
        var forwardSuccessorsByBlock: [Int: [Int]] = [:]
        forwardSuccessorsByBlock.reserveCapacity(blocks.count)
        for e in edges where !e.isBackEdge {
            forwardSuccessorsByBlock[e.sourceBlockID, default: []].append(e.targetBlockID)
        }

        for block in blocks where loopByHeader[block.id] == nil {
            let outEdges = (outgoingEdgesByBlock[block.id] ?? []).filter { !$0.isBackEdge }
            guard outEdges.count >= 2 else { continue }

            let mergeID = ipdomMap[block.id] ?? nil

            if outEdges.contains(where: {
                if case .switchCase = $0.kind { return true }
                return false
            }) {
                let regionBody = collectRegionBetween(
                    headerID: block.id,
                    stopAtMergeID: mergeID,
                    forwardSuccessors: forwardSuccessorsByBlock
                )
                regions.append(
                    StructuredControlRegion(
                        kind: .switchDispatch,
                        headerBlockID: block.id,
                        followMergeBlockID: mergeID,
                        bodyBlockIDs: regionBody
                    )
                )
                continue
            }

            if outEdges.count == 2 {
                let trueEdge = outEdges.first { $0.kind == .conditionalTrue } ?? outEdges[0]
                let falseEdge = outEdges.first { $0.kind == .conditionalFalse } ?? outEdges[1]
                let tTarget = trueEdge.targetBlockID
                let fTarget = falseEdge.targetBlockID

                let regionBody = collectRegionBetween(
                    headerID: block.id,
                    stopAtMergeID: mergeID,
                    forwardSuccessors: forwardSuccessorsByBlock
                )

                if let merge = mergeID {
                    if fTarget == merge && tTarget != merge {
                        regions.append(
                            StructuredControlRegion(
                                kind: .ifThen,
                                headerBlockID: block.id,
                                thenBlockID: tTarget,
                                elseBlockID: nil,
                                followMergeBlockID: merge,
                                bodyBlockIDs: regionBody
                            )
                        )
                        continue
                    } else if tTarget == merge && fTarget != merge {
                        regions.append(
                            StructuredControlRegion(
                                kind: .ifThen,
                                headerBlockID: block.id,
                                thenBlockID: fTarget,
                                elseBlockID: nil,
                                followMergeBlockID: merge,
                                bodyBlockIDs: regionBody
                            )
                        )
                        continue
                    }
                }

                regions.append(
                    StructuredControlRegion(
                        kind: .ifThenElse,
                        headerBlockID: block.id,
                        thenBlockID: tTarget,
                        elseBlockID: fTarget,
                        followMergeBlockID: mergeID,
                        bodyBlockIDs: regionBody
                    )
                )
            }
        }

        return regions
    }

    // MARK: - Companion Cooper-Harvey-Kennedy Iterative Solver (Cross-Check & Verification)

    /// Computes immediate dominators using Cooper, Harvey & Kennedy's (2001) RPO finger-intersect fixed-point
    /// algorithm. Provided for independent cross-verification against Lengauer-Tarjan.
    public func computeImmediateDominatorsCooperHarveyKennedy(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        entryBlockID: Int
    ) -> [Int: Int?] {
        var succMap: [Int: [Int]] = [:]
        var predMap: [Int: [Int]] = [:]
        for b in blocks {
            succMap[b.id] = []
            predMap[b.id] = []
        }
        for e in edges where succMap[e.sourceBlockID] != nil && succMap[e.targetBlockID] != nil {
            if !(succMap[e.sourceBlockID]?.contains(e.targetBlockID) ?? false) {
                succMap[e.sourceBlockID, default: []].append(e.targetBlockID)
            }
            if !(predMap[e.targetBlockID]?.contains(e.sourceBlockID) ?? false) {
                predMap[e.targetBlockID, default: []].append(e.sourceBlockID)
            }
        }

        // Iterative post-order from `entryBlockID`
        guard succMap[entryBlockID] != nil else { return [:] }
        var visited: Set<Int> = [entryBlockID]
        var postOrder: [Int] = []
        var stack: [(id: Int, idx: Int)] = [(entryBlockID, 0)]
        while let top = stack.last {
            let succs = succMap[top.id] ?? []
            if top.idx < succs.count {
                stack[stack.count - 1].idx += 1
                let next = succs[top.idx]
                if visited.insert(next).inserted {
                    stack.append((next, 0))
                }
            } else {
                _ = stack.popLast()
                postOrder.append(top.id)
            }
        }

        let rpo = Array(postOrder.reversed())
        let n = rpo.count
        var rpoIndexByBlock: [Int: Int] = [:]
        for (i, bID) in rpo.enumerated() {
            rpoIndexByBlock[bID] = i
        }

        var doms = [Int](repeating: -1, count: n)
        doms[0] = 0

        func intersect(_ b1: Int, _ b2: Int) -> Int {
            var finger1 = b1
            var finger2 = b2
            while finger1 != finger2 {
                while finger1 > finger2 {
                    finger1 = doms[finger1]
                }
                while finger2 > finger1 {
                    finger2 = doms[finger2]
                }
            }
            return finger1
        }

        var changed = true
        while changed {
            changed = false
            if n > 1 {
                for i in 1..<n {
                    let bID = rpo[i]
                    let preds = (predMap[bID] ?? []).compactMap { rpoIndexByBlock[$0] }
                    guard let firstProcessed = preds.first(where: { doms[$0] != -1 }) else {
                        continue
                    }
                    var newIdom = firstProcessed
                    for p in preds where p != firstProcessed && doms[p] != -1 {
                        newIdom = intersect(p, newIdom)
                    }
                    if doms[i] != newIdom {
                        doms[i] = newIdom
                        changed = true
                    }
                }
            }
        }

        var result: [Int: Int?] = [:]
        for b in blocks {
            if let idx = rpoIndexByBlock[b.id] {
                if idx == 0 {
                    result.updateValue(nil, forKey: b.id)
                } else {
                    let idomIdx = doms[idx]
                    result.updateValue(idomIdx >= 0 ? rpo[idomIdx] : nil, forKey: b.id)
                }
            } else {
                result.updateValue(nil, forKey: b.id)
            }
        }
        return result
    }

    // MARK: - Internal Lengauer-Tarjan O(E alpha(V)) Core Engine

    private func runLengauerTarjanCore(
        vertexIDs: [Int],
        rootID: Int,
        successors: [Int: [Int]],
        predecessors: [Int: [Int]]
    ) -> [Int: Int?] {
        var result: [Int: Int?] = [:]
        for v in vertexIDs {
            result.updateValue(nil, forKey: v)
        }
        guard successors[rootID] != nil else { return result }

        // Step 1: Iterative DFS numbering `1...N` from `rootID`
        var dfnByVertex: [Int: Int] = [:]
        var vertexAtDFN: [Int] = [0] // 1-indexed (`vertexAtDFN[0]` unused)
        var parentDFN: [Int] = [0]

        var dfsStack: [(vertex: Int, parentNum: Int, nextIdx: Int)] = []
        dfnByVertex[rootID] = 1
        vertexAtDFN.append(rootID)
        parentDFN.append(0)
        dfsStack.append((rootID, 0, 0))

        while let top = dfsStack.last {
            let curNum = dfnByVertex[top.vertex] ?? 1
            let succs = successors[top.vertex] ?? []
            if top.nextIdx < succs.count {
                dfsStack[dfsStack.count - 1].nextIdx += 1
                let wVertex = succs[top.nextIdx]
                if dfnByVertex[wVertex] == nil && successors[wVertex] != nil {
                    let nextNum = vertexAtDFN.count
                    dfnByVertex[wVertex] = nextNum
                    vertexAtDFN.append(wVertex)
                    parentDFN.append(curNum)
                    dfsStack.append((wVertex, curNum, 0))
                }
            } else {
                _ = dfsStack.popLast()
            }
        }

        let n = vertexAtDFN.count - 1
        guard n >= 2 else {
            return result
        }

        // Allocate 1-based Lengauer-Tarjan arrays (`0` = sentinel with `semi[0] = 0, label[0] = 0, size[0] = 0`)
        var semi = Array(0...n)
        var label = Array(0...n)
        var idom = [Int](repeating: 0, count: n + 1)
        var ancestor = [Int](repeating: 0, count: n + 1)
        var child = [Int](repeating: 0, count: n + 1)
        var size = [Int](repeating: 1, count: n + 1)
        size[0] = 0

        var bucket = Array(repeating: [Int](), count: n + 1)

        // Iterative path-compression helper for EVAL
        func compress(_ startNode: Int) {
            var spine: [Int] = []
            var cursor = startNode
            while ancestor[ancestor[cursor]] != 0 {
                spine.append(cursor)
                cursor = ancestor[cursor]
            }
            for v in spine.reversed() {
                let anc = ancestor[v]
                if semi[label[anc]] < semi[label[v]] {
                    label[v] = label[anc]
                }
                ancestor[v] = ancestor[anc]
            }
        }

        // Balanced O(alpha(V)) EVAL (Lengauer & Tarjan 1979, p. 130)
        func eval(_ v: Int) -> Int {
            if ancestor[v] == 0 {
                return label[v]
            }
            compress(v)
            let ancLabel = label[ancestor[v]]
            let selfLabel = label[v]
            return semi[ancLabel] >= semi[selfLabel] ? selfLabel : ancLabel
        }

        // Balanced O(alpha(V)) LINK by subtree size (Lengauer & Tarjan 1979, p. 130)
        func link(_ v: Int, _ w: Int) {
            var s = w
            while child[s] != 0 && semi[label[w]] < semi[label[child[s]]] {
                let cs = child[s]
                let ccs = child[cs]
                if size[s] + size[ccs] >= 2 * size[cs] {
                    ancestor[cs] = s
                    child[s] = ccs
                } else {
                    size[cs] = size[s]
                    ancestor[s] = cs
                    s = cs
                }
            }
            label[s] = label[w]
            size[v] += size[w]
            if size[v] < 2 * size[w] {
                let tmp = s
                s = child[v]
                child[v] = tmp
            }
            while s != 0 {
                ancestor[s] = v
                s = child[s]
            }
        }

        // Steps 2 & 3: Reverse DFS order pass `n` down to `2`
        for w in stride(from: n, through: 2, by: -1) {
            let wVertex = vertexAtDFN[w]

            // Step 2: Semidominator Theorem (`sdom(w)`)
            for vVertex in predecessors[wVertex] ?? [] {
                guard let v = dfnByVertex[vVertex], v > 0 else { continue }
                let u = eval(v)
                if semi[u] < semi[w] {
                    semi[w] = semi[u]
                }
            }

            bucket[semi[w]].append(w)
            let p = parentDFN[w]
            link(p, w)

            // Step 3: Implicit Immediate Dominator Corollary
            if !bucket[p].isEmpty {
                for v in bucket[p] {
                    let u = eval(v)
                    idom[v] = (semi[u] < semi[v]) ? u : p
                }
                bucket[p].removeAll(keepingCapacity: true)
            }
        }

        // Step 4: Explicit Immediate Dominator Resolution (`2...n`)
        for w in 2...n {
            if idom[w] != semi[w] {
                idom[w] = idom[idom[w]]
            }
            let wVertex = vertexAtDFN[w]
            let domDFN = idom[w]
            result.updateValue(domDFN > 0 ? vertexAtDFN[domDFN] : nil, forKey: wVertex)
        }

        result.updateValue(nil, forKey: rootID)
        return result
    }

    // MARK: - Internal Dominance Frontier & Graph Helpers

    private func computeDominanceFrontiers(
        blockIDs: [Int],
        reachableSet: Set<Int>,
        predecessors: [Int: [Int]],
        idomByBlock: [Int: Int?]
    ) -> [Int: [Int]] {
        var dfSets: [Int: Set<Int>] = [:]
        for id in blockIDs {
            dfSets[id] = []
        }

        for b in blockIDs where reachableSet.contains(b) {
            let reachablePreds = (predecessors[b] ?? []).filter { reachableSet.contains($0) }
            guard reachablePreds.count >= 2 else { continue }

            let idomOfB = idomByBlock[b] ?? nil
            for p in reachablePreds {
                var runner: Int? = p
                var guardCount = 0
                while let r = runner, r != idomOfB, guardCount <= blockIDs.count {
                    dfSets[r, default: []].insert(b)
                    runner = idomByBlock[r] ?? nil
                    guardCount += 1
                }
            }
        }

        var sortedDF: [Int: [Int]] = [:]
        sortedDF.reserveCapacity(blockIDs.count)
        for (id, set) in dfSets {
            sortedDF[id] = set.sorted()
        }
        return sortedDF
    }

    private func buildDominatorAncestorSets(
        dominatorTree: [DominatorTreeNode]
    ) -> [Int: Set<Int>] {
        var idomMap: [Int: Int?] = [:]
        var hasEntry = Set<Int>()
        for n in dominatorTree {
            idomMap[n.blockID] = n.immediateDominatorID
            if n.depth > 0 || n.immediateDominatorID != nil || !n.dominatedChildrenIDs.isEmpty {
                hasEntry.insert(n.blockID)
            }
        }
        if let firstRoot = dominatorTree.first(where: { $0.immediateDominatorID == nil }) {
            hasEntry.insert(firstRoot.blockID)
        }

        var result: [Int: Set<Int>] = [:]
        for n in dominatorTree {
            var ancestors = Set<Int>()
            var cur: Int? = n.blockID
            var reachedRoot = false
            var steps = 0
            while let c = cur, steps <= dominatorTree.count {
                ancestors.insert(c)
                let parent = idomMap[c] ?? nil
                if parent == nil {
                    if hasEntry.contains(c) {
                        reachedRoot = true
                    }
                    break
                }
                cur = parent
                steps += 1
            }
            if reachedRoot || dominatorTree.count == 1 {
                result[n.blockID] = ancestors
            }
        }
        return result
    }

    private func findDFSRetreatEdges(
        entryBlockID: Int,
        successors: [Int: [Int]]
    ) -> Set<CFGDirectedPair> {
        guard successors[entryBlockID] != nil else { return [] }
        enum Color { case white, gray, black }
        var color: [Int: Color] = [:]
        for k in successors.keys { color[k] = .white }

        var retreat = Set<CFGDirectedPair>()
        var stack: [(id: Int, idx: Int)] = [(entryBlockID, 0)]
        color[entryBlockID] = .gray

        while let top = stack.last {
            let succs = successors[top.id] ?? []
            if top.idx < succs.count {
                stack[stack.count - 1].idx += 1
                let v = succs[top.idx]
                switch color[v] ?? .black {
                case .white:
                    color[v] = .gray
                    stack.append((v, 0))
                case .gray:
                    retreat.insert(CFGDirectedPair(sourceBlockID: top.id, targetBlockID: v))
                case .black:
                    break
                }
            } else {
                color[top.id] = .black
                _ = stack.popLast()
            }
        }
        return retreat
    }

    private func collectReachable(from root: Int, successors: [Int: [Int]]) -> Set<Int> {
        var visited: Set<Int> = [root]
        var queue: [Int] = [root]
        var head = 0
        while head < queue.count {
            let cur = queue[head]
            head += 1
            for next in successors[cur] ?? [] where visited.insert(next).inserted {
                queue.append(next)
            }
        }
        return visited
    }

    private func collectRegionBetween(
        headerID: Int,
        stopAtMergeID: Int?,
        forwardSuccessors: [Int: [Int]]
    ) -> [Int] {
        var region: Set<Int> = [headerID]
        var queue: [Int] = [headerID]
        var head = 0
        while head < queue.count {
            let cur = queue[head]
            head += 1
            for s in forwardSuccessors[cur] ?? [] {
                if let merge = stopAtMergeID, s == merge {
                    continue
                }
                if region.insert(s).inserted {
                    queue.append(s)
                }
            }
        }
        return region.sorted()
    }

    private func annotateCFGWithLoops(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        naturalLoops: [NaturalLoop],
        backEdgePairs: Set<CFGDirectedPair>
    ) -> (blocks: [BasicBlock], edges: [CFGEdge]) {
        var loopDepthByBlock: [Int: Int] = [:]
        for loop in naturalLoops {
            for bID in loop.bodyBlockIDs {
                loopDepthByBlock[bID, default: 0] += 1
            }
        }

        let updatedBlocks = blocks.map { b in
            let depth = loopDepthByBlock[b.id] ?? 0
            guard depth != b.loopDepth else { return b }
            return BasicBlock(
                id: b.id,
                functionAddress: b.functionAddress,
                startAddress: b.startAddress,
                endAddress: b.endAddress,
                instructions: b.instructions,
                predecessorIDs: b.predecessorIDs,
                successorIDs: b.successorIDs,
                isEntry: b.isEntry,
                isExit: b.isExit,
                loopDepth: depth
            )
        }

        let updatedEdges = edges.map { e in
            let isBack = backEdgePairs.contains(CFGDirectedPair(sourceBlockID: e.sourceBlockID, targetBlockID: e.targetBlockID))
            guard isBack != e.isBackEdge else { return e }
            return CFGEdge(
                sourceBlockID: e.sourceBlockID,
                targetBlockID: e.targetBlockID,
                kind: e.kind,
                isBackEdge: isBack
            )
        }

        return (updatedBlocks, updatedEdges)
    }
}
