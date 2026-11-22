import Foundation
import MachGraphModels

// MARK: - Sugiyama Hierarchical Layout Configuration & Styling

package enum SugiyamaEdgeRoutingMode: String, Sendable, Codable, Hashable, CaseIterable {
    case orthogonalChannel = "Orthogonal Channel"
    case cubicBezierSpline = "Cubic Spline"
}

package struct SugiyamaLayoutConfiguration: Sendable, Codable, Hashable {
    package var minNodeWidth: Double
    package var maxNodeWidth: Double
    package var characterAdvanceWidth: Double
    package var nodeHorizontalPadding: Double
    package var headerBarHeight: Double
    package var instructionLineHeight: Double
    package var nodeVerticalPadding: Double
    package var minNodeHeight: Double
    package var horizontalNodeSpacing: Double
    package var dummyCorridorWidth: Double
    package var baseVerticalLayerSpacing: Double
    package var channelTrackSpacing: Double
    package var outerGutterLaneSpacing: Double
    package var canvasMargin: Double
    package var maxCrossingMinimizationSweeps: Int
    package var coffmanGrahamMaxLayerWidth: Int
    package var routingMode: SugiyamaEdgeRoutingMode

    package init(
        minNodeWidth: Double = 264.0,
        maxNodeWidth: Double = 540.0,
        characterAdvanceWidth: Double = 7.4,
        nodeHorizontalPadding: Double = 28.0,
        headerBarHeight: Double = 28.0,
        instructionLineHeight: Double = 18.0,
        nodeVerticalPadding: Double = 16.0,
        minNodeHeight: Double = 56.0,
        horizontalNodeSpacing: Double = 56.0,
        dummyCorridorWidth: Double = 24.0,
        baseVerticalLayerSpacing: Double = 72.0,
        channelTrackSpacing: Double = 12.0,
        outerGutterLaneSpacing: Double = 24.0,
        canvasMargin: Double = 64.0,
        maxCrossingMinimizationSweeps: Int = 24,
        coffmanGrahamMaxLayerWidth: Int = 18,
        routingMode: SugiyamaEdgeRoutingMode = .orthogonalChannel
    ) {
        self.minNodeWidth = minNodeWidth
        self.maxNodeWidth = maxNodeWidth
        self.characterAdvanceWidth = characterAdvanceWidth
        self.nodeHorizontalPadding = nodeHorizontalPadding
        self.headerBarHeight = headerBarHeight
        self.instructionLineHeight = instructionLineHeight
        self.nodeVerticalPadding = nodeVerticalPadding
        self.minNodeHeight = minNodeHeight
        self.horizontalNodeSpacing = horizontalNodeSpacing
        self.dummyCorridorWidth = dummyCorridorWidth
        self.baseVerticalLayerSpacing = baseVerticalLayerSpacing
        self.channelTrackSpacing = channelTrackSpacing
        self.outerGutterLaneSpacing = outerGutterLaneSpacing
        self.canvasMargin = canvasMargin
        self.maxCrossingMinimizationSweeps = max(2, maxCrossingMinimizationSweeps)
        self.coffmanGrahamMaxLayerWidth = max(2, coffmanGrahamMaxLayerWidth)
        self.routingMode = routingMode
    }

    package static let standard = SugiyamaLayoutConfiguration()
}

// MARK: - 5-Phase Sugiyama Hierarchical CFG Layout Solver

package struct SugiyamaCFGLayoutSolver: Sendable {
    package let configuration: SugiyamaLayoutConfiguration

    package init(configuration: SugiyamaLayoutConfiguration = .standard) {
        self.configuration = configuration
    }

    // MARK: - Public Layout Entry Points

    /// Computes a complete 5-phase `SugiyamaCFGLayout` for a `RecoveredFunction`.
    package func solveLayout(for function: RecoveredFunction) -> SugiyamaCFGLayout {
        solveLayout(
            functionAddress: function.address,
            blocks: function.blocks,
            edges: function.edges
        )
    }

    /// Executes the 5-phase Sugiyama layout pipeline:
    ///   1. Feedback-arc cycle reversal (DFS + Eades-Lin-Smyth greedy cycle breaker),
    ///   2. Longest-path + feasible-tree slack minimization + Coffman-Graham rank assignment & dummy vertices,
    ///   3. Two-sided iterative wmedian/barycentric crossing minimization + adjacent transpose + Fenwick counter,
    ///   4. Brandes-Kopf (2001) 4-directional block alignment + strict overlap-free horizontal compaction,
    ///   5. Interval-colored orthogonal channel & outer-gutter back-edge routing with zero node-box overlap.
    package func solveLayout(
        functionAddress: VirtualAddress,
        blocks: [BasicBlock],
        edges: [CFGEdge]
    ) -> SugiyamaCFGLayout {
        guard !blocks.isEmpty else {
            let emptySize = configuration.canvasMargin * 2.0
            return SugiyamaCFGLayout(
                functionAddress: functionAddress,
                canvasWidth: emptySize,
                canvasHeight: emptySize,
                layerCount: 0,
                nodes: [],
                routes: []
            )
        }

        let realCount = blocks.count
        var blockIdxByID: [Int: Int] = [:]
        blockIdxByID.reserveCapacity(realCount)
        for (idx, b) in blocks.enumerated() {
            blockIdxByID[b.id] = idx
        }

        // Measure intrinsic width & height of every real BasicBlock node
        var vertexWidths = [Double](repeating: 0.0, count: realCount)
        var vertexHeights = [Double](repeating: 0.0, count: realCount)
        for (idx, block) in blocks.enumerated() {
            let size = measureBasicBlockBox(block)
            vertexWidths[idx] = size.width
            vertexHeights[idx] = size.height
        }

        // Single-block fast path (with optional self-loop support)
        if realCount == 1 {
            return buildSingleNodeLayout(
                functionAddress: functionAddress,
                block: blocks[0],
                width: vertexWidths[0],
                height: vertexHeights[0],
                edges: edges
            )
        }

        // Map original CFGEdges to dense real vertex indices `0..<realCount`
        var indexedEdges: [IndexedCFGEdge] = []
        indexedEdges.reserveCapacity(edges.count)
        for (edgeIdx, edge) in edges.enumerated() {
            guard let u = blockIdxByID[edge.sourceBlockID],
                  let v = blockIdxByID[edge.targetBlockID] else {
                continue
            }
            indexedEdges.append(
                IndexedCFGEdge(
                    originalIndex: edgeIdx,
                    edge: edge,
                    srcReal: u,
                    dstReal: v,
                    isSelfLoop: u == v,
                    isReversedFeedbackArc: false
                )
            )
        }

        // -----------------------------------------------------------------
        // PHASE 1: Feedback-Arc Cycle Reversal (DFS + Greedy Cycle Removal)
        // -----------------------------------------------------------------
        let entryRealIdx = blocks.firstIndex(where: \.isEntry) ?? 0
        let acyclicEdges = breakCyclesIntoDAG(
            realCount: realCount,
            entryIdx: entryRealIdx,
            edges: indexedEdges
        )

        // -----------------------------------------------------------------
        // PHASE 2: Rank / Layer Assignment + Dummy Virtual Vertex Insertion
        // -----------------------------------------------------------------
        let realRanks = assignHierarchicalRanks(
            realCount: realCount,
            entryIdx: entryRealIdx,
            dagEdges: acyclicEdges,
            blocks: blocks
        )

        let layerCount = (realRanks.max() ?? 0) + 1
        var augmentedGraph = insertDummyVerticesForLongEdges(
            realCount: realCount,
            layerCount: layerCount,
            realRanks: realRanks,
            realWidths: vertexWidths,
            realHeights: vertexHeights,
            dagEdges: acyclicEdges
        )

        // -----------------------------------------------------------------
        // PHASE 3: Two-Sided Barycentric + Wmedian Crossing Minimization
        // -----------------------------------------------------------------
        let orderedLayers = minimizeEdgeCrossings(
            graph: &augmentedGraph,
            entryIdx: entryRealIdx
        )

        // -----------------------------------------------------------------
        // PHASE 4: Brandes-Kopf 4-Directional Horizontal Coordinate Solver
        // -----------------------------------------------------------------
        let centerXByVertex = assignHorizontalCoordinatesBrandesKopf(
            layers: orderedLayers,
            graph: augmentedGraph
        )

        // -----------------------------------------------------------------
        // PHASE 5: Orthogonal Channel & Outer-Gutter Back-Edge Router
        // -----------------------------------------------------------------
        return routeEdgesAndAssembleCanvas(
            functionAddress: functionAddress,
            blocks: blocks,
            layers: orderedLayers,
            graph: augmentedGraph,
            centerXByVertex: centerXByVertex,
            allEdges: acyclicEdges
        )
    }

    // MARK: - Geometric Overlap Audit Utility

    /// Verifies that no interior orthogonal segment of any `CFGEdgeRoute` pierces the interior bounding box
    /// of any non-endpoint `CFGNodeLayout`.
    package func verifyZeroNodeBoxOverlap(in layout: SugiyamaCFGLayout, insetEpsilon: Double = 1.5) -> Bool {
        guard layout.nodes.count > 1 && !layout.routes.isEmpty else { return true }

        for route in layout.routes {
            let pts = route.waypoints
            guard pts.count >= 2 else { continue }
            let srcID = route.edge.sourceBlockID
            let dstID = route.edge.targetBlockID

            for segIdx in 0..<(pts.count - 1) {
                let p0 = pts[segIdx]
                let p1 = pts[segIdx + 1]

                for node in layout.nodes where node.blockID != srcID && node.blockID != dstID {
                    let shrunk = CGRectBridge(
                        x: node.frame.minX + insetEpsilon,
                        y: node.frame.minY + insetEpsilon,
                        width: max(0.0, node.frame.width - 2.0 * insetEpsilon),
                        height: max(0.0, node.frame.height - 2.0 * insetEpsilon)
                    )
                    if segmentIntersectsRect(p0: p0, p1: p1, rect: shrunk) {
                        return false
                    }
                }
            }
        }
        return true
    }

    // MARK: - Internal Graph Representations

    private struct IndexedCFGEdge {
        let originalIndex: Int
        let edge: CFGEdge
        let srcReal: Int
        let dstReal: Int
        let isSelfLoop: Bool
        var isReversedFeedbackArc: Bool

        var dagSource: Int { isReversedFeedbackArc ? dstReal : srcReal }
        var dagTarget: Int { isReversedFeedbackArc ? srcReal : dstReal }
    }

    private struct UnitDAGEdge {
        let fromVertex: Int
        let toVertex: Int
        let originalEdgeIndex: Int
        let kind: CFGEdgeKind
        let isInnerDummySegment: Bool
    }

    private struct AugmentedLayeredGraph {
        let realCount: Int
        let layerCount: Int
        var totalVertexCount: Int
        var rankOfVertex: [Int]
        var widthOfVertex: [Double]
        var heightOfVertex: [Double]
        var isDummyVertex: [Bool]
        var unitEdges: [UnitDAGEdge]
        var upperNeighbors: [[Int]]
        var lowerNeighbors: [[Int]]
        /// Maps `originalEdgeIndex` -> `[dagSource, dummy_1, ..., dummy_k, dagTarget]`
        var chainByOriginalEdge: [Int: [Int]]
    }

    // MARK: - Phase 1: Feedback-Arc Cycle Reversal

    private func breakCyclesIntoDAG(
        realCount: Int,
        entryIdx: Int,
        edges: [IndexedCFGEdge]
    ) -> [IndexedCFGEdge] {
        var working = edges

        // 1a. Immediately reverse edges already proven to be natural loop back-edges by Lengauer-Tarjan
        for i in 0..<working.count where !working[i].isSelfLoop {
            if working[i].edge.isBackEdge {
                working[i].isReversedFeedbackArc = true
            }
        }

        // 1b. Run Eades-Lin-Smyth (1993) Greedy Cycle-Removal ordering seeded from `entryIdx`
        // to handle any remaining irreducible multi-entry cycles cleanly.
        let nonLoopIndices = working.indices.filter { !working[$0].isSelfLoop }
        if !nonLoopIndices.isEmpty {
            let linearOrder = computeEadesLinSmythLinearOrder(
                vertexCount: realCount,
                entryIdx: entryIdx,
                edges: working
            )
            var orderRank = [Int](repeating: 0, count: realCount)
            for (pos, v) in linearOrder.enumerated() {
                orderRank[v] = pos
            }

            // Verify acyclicity with iterative 3-color DFS; reverse any remaining cycle-closing arc
            var safetyPass = 0
            while safetyPass < realCount + 2 {
                let cycleEdgeIndices = detectRemainingCycleEdgesDFS(
                    vertexCount: realCount,
                    entryIdx: entryIdx,
                    edges: working,
                    tieBreakOrder: orderRank
                )
                if cycleEdgeIndices.isEmpty {
                    break
                }
                for idx in cycleEdgeIndices {
                    working[idx].isReversedFeedbackArc.toggle()
                }
                safetyPass += 1
            }
        }

        return working
    }

    private func computeEadesLinSmythLinearOrder(
        vertexCount: Int,
        entryIdx: Int,
        edges: [IndexedCFGEdge]
    ) -> [Int] {
        var active = [Bool](repeating: true, count: vertexCount)
        var outAdj = Array(repeating: [Int](), count: vertexCount)
        var inAdj = Array(repeating: [Int](), count: vertexCount)
        var inDeg = [Int](repeating: 0, count: vertexCount)
        var outDeg = [Int](repeating: 0, count: vertexCount)

        for e in edges where !e.isSelfLoop {
            let u = e.dagSource
            let v = e.dagTarget
            outAdj[u].append(v)
            inAdj[v].append(u)
            outDeg[u] += 1
            inDeg[v] += 1
        }

        var leftSeq: [Int] = []
        var rightSeq: [Int] = []
        leftSeq.reserveCapacity(vertexCount)
        rightSeq.reserveCapacity(vertexCount)

        var remaining = vertexCount
        func removeVertex(_ v: Int) {
            active[v] = false
            remaining -= 1
            for w in outAdj[v] where active[w] {
                inDeg[w] -= 1
            }
            for u in inAdj[v] where active[u] {
                outDeg[u] -= 1
            }
        }

        while remaining > 0 {
            // Strip sinks (`outDeg == 0`, preserving `entryIdx` on the left when possible)
            var strippedSink = true
            while strippedSink && remaining > 0 {
                strippedSink = false
                for v in stride(from: vertexCount - 1, through: 0, by: -1) {
                    if active[v] && outDeg[v] == 0 && (v != entryIdx || remaining == 1) {
                        rightSeq.append(v)
                        removeVertex(v)
                        strippedSink = true
                    }
                }
            }

            // Strip sources (`inDeg == 0`, preferring `entryIdx` first)
            var strippedSource = true
            while strippedSource && remaining > 0 {
                strippedSource = false
                if active[entryIdx] && inDeg[entryIdx] == 0 {
                    leftSeq.append(entryIdx)
                    removeVertex(entryIdx)
                    strippedSource = true
                    continue
                }
                for v in 0..<vertexCount where active[v] && inDeg[v] == 0 {
                    leftSeq.append(v)
                    removeVertex(v)
                    strippedSource = true
                }
            }

            // Choose active vertex maximizing `outDeg[v] - inDeg[v]`
            if remaining > 0 {
                var bestV = -1
                var bestScore = Int.min
                for v in 0..<vertexCount where active[v] {
                    let bonus = (v == entryIdx) ? 10_000 : 0
                    let score = (outDeg[v] - inDeg[v]) * 4 + bonus
                    if score > bestScore {
                        bestScore = score
                        bestV = v
                    }
                }
                if bestV >= 0 {
                    leftSeq.append(bestV)
                    removeVertex(bestV)
                }
            }
        }

        return leftSeq + rightSeq.reversed()
    }

    private func detectRemainingCycleEdgesDFS(
        vertexCount: Int,
        entryIdx: Int,
        edges: [IndexedCFGEdge],
        tieBreakOrder: [Int]
    ) -> [Int] {
        var adj = Array(repeating: [(to: Int, edgeIdx: Int)](), count: vertexCount)
        for (idx, e) in edges.enumerated() where !e.isSelfLoop {
            adj[e.dagSource].append((e.dagTarget, idx))
        }
        for u in 0..<vertexCount {
            adj[u].sort { tieBreakOrder[$0.to] < tieBreakOrder[$1.to] }
        }

        enum Color { case white, gray, black }
        var color = [Color](repeating: .white, count: vertexCount)
        var cycleEdges: [Int] = []

        let rootOrder = [entryIdx] + (0..<vertexCount).filter { $0 != entryIdx }

        for root in rootOrder where color[root] == .white {
            var stack: [(u: Int, nextIdx: Int)] = [(root, 0)]
            color[root] = .gray

            while let top = stack.last {
                let list = adj[top.u]
                if top.nextIdx < list.count {
                    stack[stack.count - 1].nextIdx += 1
                    let item = list[top.nextIdx]
                    switch color[item.to] {
                    case .white:
                        color[item.to] = .gray
                        stack.append((item.to, 0))
                    case .gray:
                        cycleEdges.append(item.edgeIdx)
                    case .black:
                        break
                    }
                } else {
                    color[top.u] = .black
                    _ = stack.popLast()
                }
            }
        }

        return cycleEdges
    }

    // MARK: - Phase 2: Longest-Path + Slack-Tightening + Coffman-Graham Rank Assignment & Dummy Insertion

    private func assignHierarchicalRanks(
        realCount: Int,
        entryIdx: Int,
        dagEdges: [IndexedCFGEdge],
        blocks: [BasicBlock]
    ) -> [Int] {
        var outAdj = Array(repeating: [Int](), count: realCount)
        var inAdj = Array(repeating: [Int](), count: realCount)
        var inDeg = [Int](repeating: 0, count: realCount)

        for e in dagEdges where !e.isSelfLoop {
            let u = e.dagSource
            let v = e.dagTarget
            if !outAdj[u].contains(v) {
                outAdj[u].append(v)
                inAdj[v].append(u)
                inDeg[v] += 1
            }
        }

        // 2a. Kahn topological sort + Longest-Path initial rank assignment
        var rank = [Int](repeating: 0, count: realCount)
        var topoOrder: [Int] = []
        topoOrder.reserveCapacity(realCount)

        var queue: [Int] = []
        if inDeg[entryIdx] == 0 {
            queue.append(entryIdx)
        }
        for v in 0..<realCount where v != entryIdx && inDeg[v] == 0 {
            queue.append(v)
        }

        var head = 0
        while head < queue.count {
            let u = queue[head]
            head += 1
            topoOrder.append(u)
            for v in outAdj[u] {
                if rank[u] + 1 > rank[v] {
                    rank[v] = rank[u] + 1
                }
                inDeg[v] -= 1
                if inDeg[v] == 0 {
                    queue.append(v)
                }
            }
        }

        // Safety fallback if any isolated vertex was missed
        if topoOrder.count < realCount {
            let seen = Set(topoOrder)
            for v in 0..<realCount where !seen.contains(v) {
                topoOrder.append(v)
            }
        }

        // 2b. Network-Simplex / Feasible-Tree Slack Minimization Tightening Sweeps:
        // Pull down floating headers / single-in multiple-out blocks close to their successors,
        // and pull up intermediate single-out blocks close to their predecessors to minimize total edge span!
        for _ in 0..<6 {
            // Reverse topological pull-down pass (never move `entryIdx` away from rank 0)
            for u in topoOrder.reversed() where u != entryIdx && !blocks[u].isEntry {
                guard !outAdj[u].isEmpty else { continue }
                let minSuccRank = outAdj[u].map { rank[$0] }.min() ?? (rank[u] + 1)
                let maxAllowedRank = minSuccRank - 1
                if maxAllowedRank > rank[u] {
                    if inAdj[u].isEmpty || outAdj[u].count > inAdj[u].count {
                        rank[u] = maxAllowedRank
                    }
                }
            }

            // Forward topological pull-up pass
            for u in topoOrder where u != entryIdx && !blocks[u].isEntry {
                guard !inAdj[u].isEmpty else { continue }
                let maxPredRank = inAdj[u].map { rank[$0] }.max() ?? 0
                let minAllowedRank = maxPredRank + 1
                if rank[u] < minAllowedRank {
                    rank[u] = minAllowedRank
                } else if inAdj[u].count > outAdj[u].count && rank[u] > minAllowedRank {
                    rank[u] = minAllowedRank
                }
            }
        }

        // 2c. Coffman-Graham Layer Width-Bound Refinement for Extra-Wide Unconstrained Layers
        var countByRank: [Int: [Int]] = [:]
        for v in 0..<realCount {
            countByRank[rank[v], default: []].append(v)
        }
        let maxW = configuration.coffmanGrahamMaxLayerWidth
        if countByRank.values.contains(where: { $0.count > maxW }) {
            rank = applyCoffmanGrahamWidthCap(
                realCount: realCount,
                entryIdx: entryIdx,
                topoOrder: topoOrder,
                initialRank: rank,
                inAdj: inAdj,
                outAdj: outAdj,
                maxWidth: maxW
            )
        }

        // 2d. Normalize ranks to contiguous `0..<L` with `entryIdx` at rank 0
        rank[entryIdx] = 0
        for u in topoOrder {
            for v in outAdj[u] where rank[v] <= rank[u] {
                rank[v] = rank[u] + 1
            }
        }

        let distinctSortedRanks = Array(Set(rank)).sorted()
        var rankRemap: [Int: Int] = [:]
        for (denseIdx, oldRank) in distinctSortedRanks.enumerated() {
            rankRemap[oldRank] = denseIdx
        }
        return rank.map { rankRemap[$0] ?? 0 }
    }

    private func applyCoffmanGrahamWidthCap(
        realCount: Int,
        entryIdx: Int,
        topoOrder: [Int],
        initialRank: [Int],
        inAdj: [[Int]],
        outAdj: [[Int]],
        maxWidth: Int
    ) -> [Int] {
        var newRank = [Int](repeating: 0, count: realCount)
        var layerFill: [Int: Int] = [:]

        for u in topoOrder {
            if u == entryIdx {
                newRank[u] = 0
                layerFill[0, default: 0] += 1
                continue
            }
            let minReq = inAdj[u].map { newRank[$0] + 1 }.max() ?? initialRank[u]
            var candidateRank = max(0, minReq)
            // Only spill into next rank if not a switch-case fanout that naturally belongs on one row
            let sharedParentSwitch = inAdj[u].count == 1 && outAdj[inAdj[u][0]].count > maxWidth
            if !sharedParentSwitch {
                while (layerFill[candidateRank] ?? 0) >= maxWidth {
                    candidateRank += 1
                }
            }
            newRank[u] = candidateRank
            layerFill[candidateRank, default: 0] += 1
        }
        return newRank
    }

    private func insertDummyVerticesForLongEdges(
        realCount: Int,
        layerCount: Int,
        realRanks: [Int],
        realWidths: [Double],
        realHeights: [Double],
        dagEdges: [IndexedCFGEdge]
    ) -> AugmentedLayeredGraph {
        var rankOfVertex = realRanks
        var widthOfVertex = realWidths
        var heightOfVertex = realHeights
        var isDummyVertex = [Bool](repeating: false, count: realCount)
        var unitEdges: [UnitDAGEdge] = []
        var chainByOriginalEdge: [Int: [Int]] = [:]

        // Sort DAG edges deterministically so True/False/SwitchCase ordering is preserved
        let sortedDAGEdges = dagEdges.filter { !$0.isSelfLoop }.sorted { a, b in
            if a.dagSource != b.dagSource { return a.dagSource < b.dagSource }
            let pA = edgeHorizontalSortPriority(a.edge.kind, isReversed: a.isReversedFeedbackArc)
            let pB = edgeHorizontalSortPriority(b.edge.kind, isReversed: b.isReversedFeedbackArc)
            if pA != pB { return pA < pB }
            return a.dagTarget < b.dagTarget
        }

        for item in sortedDAGEdges {
            let u = item.dagSource
            let v = item.dagTarget
            let rU = rankOfVertex[u]
            let rV = rankOfVertex[v]
            let span = rV - rU
            guard span >= 1 else { continue }

            if span == 1 {
                unitEdges.append(
                    UnitDAGEdge(
                        fromVertex: u,
                        toVertex: v,
                        originalEdgeIndex: item.originalIndex,
                        kind: item.edge.kind,
                        isInnerDummySegment: false
                    )
                )
                chainByOriginalEdge[item.originalIndex] = [u, v]
            } else {
                var chain: [Int] = [u]
                chain.reserveCapacity(span + 1)
                var prev = u
                for stepRank in (rU + 1)..<rV {
                    let dummyID = rankOfVertex.count
                    rankOfVertex.append(stepRank)
                    widthOfVertex.append(configuration.dummyCorridorWidth)
                    heightOfVertex.append(0.0)
                    isDummyVertex.append(true)
                    let isInner = isDummyVertex[prev] && true
                    unitEdges.append(
                        UnitDAGEdge(
                            fromVertex: prev,
                            toVertex: dummyID,
                            originalEdgeIndex: item.originalIndex,
                            kind: item.edge.kind,
                            isInnerDummySegment: isInner
                        )
                    )
                    chain.append(dummyID)
                    prev = dummyID
                }
                unitEdges.append(
                    UnitDAGEdge(
                        fromVertex: prev,
                        toVertex: v,
                        originalEdgeIndex: item.originalIndex,
                        kind: item.edge.kind,
                        isInnerDummySegment: false
                    )
                )
                chain.append(v)
                chainByOriginalEdge[item.originalIndex] = chain
            }
        }

        let totalCount = rankOfVertex.count
        var upperNeighbors = Array(repeating: [Int](), count: totalCount)
        var lowerNeighbors = Array(repeating: [Int](), count: totalCount)

        for ue in unitEdges {
            lowerNeighbors[ue.fromVertex].append(ue.toVertex)
            upperNeighbors[ue.toVertex].append(ue.fromVertex)
        }

        return AugmentedLayeredGraph(
            realCount: realCount,
            layerCount: layerCount,
            totalVertexCount: totalCount,
            rankOfVertex: rankOfVertex,
            widthOfVertex: widthOfVertex,
            heightOfVertex: heightOfVertex,
            isDummyVertex: isDummyVertex,
            unitEdges: unitEdges,
            upperNeighbors: upperNeighbors,
            lowerNeighbors: lowerNeighbors,
            chainByOriginalEdge: chainByOriginalEdge
        )
    }

    private func edgeHorizontalSortPriority(_ kind: CFGEdgeKind, isReversed: Bool) -> Int {
        if isReversed { return 900 }
        switch kind {
        case .conditionalTrue: return 10
        case .conditionalFalse: return 20
        case .fallthroughEdge: return 30
        case .unconditional: return 40
        case .switchCase(let v): return 100 + Int(clamping: v)
        }
    }

    // MARK: - Phase 3: Two-Sided Wmedian + Barycentric Crossing Minimization

    private func minimizeEdgeCrossings(
        graph: inout AugmentedLayeredGraph,
        entryIdx: Int
    ) -> [[Int]] {
        var layers = buildInitialDFSOrderedLayers(graph: graph, entryIdx: entryIdx)
        guard graph.layerCount >= 2 else { return layers }

        var bestLayers = layers
        var bestCrossings = countTotalGraphCrossings(layers: layers, lowerNeighbors: graph.lowerNeighbors)
        if bestCrossings == 0 {
            return bestLayers
        }

        let sweeps = configuration.maxCrossingMinimizationSweeps
        for iter in 0..<sweeps {
            if iter % 2 == 0 {
                // Top-down sweep (`layer = 1 ..< L`) referencing fixed upper layer `layer - 1`
                for r in 1..<graph.layerCount {
                    orderLayerByWmedianAndBarycenter(
                        layerIndex: r,
                        referenceLayer: layers[r - 1],
                        neighborsOfVertex: graph.upperNeighbors,
                        layers: &layers
                    )
                }
                transposeAdjacentSwaps(layers: &layers, graph: graph, topDown: true)
            } else {
                // Bottom-up sweep (`layer = L - 2 ... 0`) referencing fixed lower layer `layer + 1`
                for r in stride(from: graph.layerCount - 2, through: 0, by: -1) {
                    orderLayerByWmedianAndBarycenter(
                        layerIndex: r,
                        referenceLayer: layers[r + 1],
                        neighborsOfVertex: graph.lowerNeighbors,
                        layers: &layers
                    )
                }
                transposeAdjacentSwaps(layers: &layers, graph: graph, topDown: false)
            }

            let currentCrossings = countTotalGraphCrossings(layers: layers, lowerNeighbors: graph.lowerNeighbors)
            if currentCrossings < bestCrossings {
                bestCrossings = currentCrossings
                bestLayers = layers
                if bestCrossings == 0 {
                    break
                }
            }
        }

        return bestLayers
    }

    private func buildInitialDFSOrderedLayers(
        graph: AugmentedLayeredGraph,
        entryIdx: Int
    ) -> [[Int]] {
        var layers = Array(repeating: [Int](), count: graph.layerCount)
        var placed = [Bool](repeating: false, count: graph.totalVertexCount)

        var stack: [Int] = [entryIdx]
        while let u = stack.popLast() {
            guard !placed[u] else { continue }
            placed[u] = true
            layers[graph.rankOfVertex[u]].append(u)
            // Push reversed so first lowerNeighbor (`conditionalTrue` / `case 0`) visits first (leftmost)
            for child in graph.lowerNeighbors[u].reversed() where !placed[child] {
                stack.append(child)
            }
        }

        for v in 0..<graph.totalVertexCount where !placed[v] {
            placed[v] = true
            layers[graph.rankOfVertex[v]].append(v)
        }
        return layers
    }

    private func orderLayerByWmedianAndBarycenter(
        layerIndex: Int,
        referenceLayer: [Int],
        neighborsOfVertex: [[Int]],
        layers: inout [[Int]]
    ) {
        let current = layers[layerIndex]
        guard current.count >= 2 else { return }

        var refPos: [Int: Int] = [:]
        refPos.reserveCapacity(referenceLayer.count)
        for (idx, v) in referenceLayer.enumerated() {
            refPos[v] = idx
        }

        struct ScoredVertex {
            let vertex: Int
            let originalOrder: Int
            let score: Double
        }

        var scored: [ScoredVertex] = []
        scored.reserveCapacity(current.count)

        for (origPos, v) in current.enumerated() {
            let positions = neighborsOfVertex[v].compactMap { refPos[$0] }.sorted()
            if positions.isEmpty {
                scored.append(ScoredVertex(vertex: v, originalOrder: origPos, score: Double(origPos)))
                continue
            }

            // Gansner et al. Weighted Median (`wmedian`)
            let m = positions.count / 2
            let wmedian: Double
            if positions.count % 2 == 1 {
                wmedian = Double(positions[m])
            } else if positions.count == 2 {
                wmedian = 0.5 * Double(positions[0] + positions[1])
            } else {
                let leftSpan = Double(positions[m - 1] - positions[0])
                let rightSpan = Double(positions[positions.count - 1] - positions[m])
                let denom = leftSpan + rightSpan
                if denom > 0 {
                    wmedian = (Double(positions[m - 1]) * rightSpan + Double(positions[m]) * leftSpan) / denom
                } else {
                    wmedian = 0.5 * Double(positions[m - 1] + positions[m])
                }
            }

            // Sugiyama Barycenter
            let sum = positions.reduce(0, +)
            let barycenter = Double(sum) / Double(positions.count)

            let blended = 0.65 * wmedian + 0.35 * barycenter
            scored.append(ScoredVertex(vertex: v, originalOrder: origPos, score: blended))
        }

        scored.sort { a, b in
            if abs(a.score - b.score) > 1e-9 {
                return a.score < b.score
            }
            return a.originalOrder < b.originalOrder
        }

        layers[layerIndex] = scored.map(\.vertex)
    }

    private func transposeAdjacentSwaps(
        layers: inout [[Int]],
        graph: AugmentedLayeredGraph,
        topDown: Bool
    ) {
        var improved = true
        var passCount = 0
        while improved && passCount < 4 {
            improved = false
            passCount += 1

            let range: [Int] = topDown
                ? Array(0..<graph.layerCount)
                : Array((0..<graph.layerCount).reversed())

            for r in range {
                let count = layers[r].count
                guard count >= 2 else { continue }

                var upperPos: [Int: Int] = [:]
                if r > 0 {
                    for (idx, u) in layers[r - 1].enumerated() { upperPos[u] = idx }
                }
                var lowerPos: [Int: Int] = [:]
                if r + 1 < graph.layerCount {
                    for (idx, w) in layers[r + 1].enumerated() { lowerPos[w] = idx }
                }

                for i in 0..<(count - 1) {
                    let v = layers[r][i]
                    let w = layers[r][i + 1]

                    var uvCross = 0
                    var wuCross = 0

                    if r > 0 {
                        let (cVW, cWV) = pairCrossings(
                            uNeighbors: graph.upperNeighbors[v],
                            wNeighbors: graph.upperNeighbors[w],
                            posMap: upperPos
                        )
                        uvCross += cVW
                        wuCross += cWV
                    }
                    if r + 1 < graph.layerCount {
                        let (cVW, cWV) = pairCrossings(
                            uNeighbors: graph.lowerNeighbors[v],
                            wNeighbors: graph.lowerNeighbors[w],
                            posMap: lowerPos
                        )
                        uvCross += cVW
                        wuCross += cWV
                    }

                    if wuCross < uvCross {
                        layers[r].swapAt(i, i + 1)
                        improved = true
                    }
                }
            }
        }
    }

    private func pairCrossings(
        uNeighbors: [Int],
        wNeighbors: [Int],
        posMap: [Int: Int]
    ) -> (uwOrder: Int, wuOrder: Int) {
        guard !uNeighbors.isEmpty && !wNeighbors.isEmpty else { return (0, 0) }
        var uw = 0
        var wu = 0
        for a in uNeighbors {
            guard let pA = posMap[a] else { continue }
            for b in wNeighbors {
                guard let pB = posMap[b] else { continue }
                if pA > pB {
                    uw += 1
                } else if pB > pA {
                    wu += 1
                }
            }
        }
        return (uw, wu)
    }

    /// $O(E \log V)$ bipartite crossing counter across all adjacent layer pairs via Fenwick Binary Indexed Tree.
    private func countTotalGraphCrossings(
        layers: [[Int]],
        lowerNeighbors: [[Int]]
    ) -> Int {
        guard layers.count >= 2 else { return 0 }
        var total = 0
        for r in 0..<(layers.count - 1) {
            total += countBipartiteCrossings(
                northLayer: layers[r],
                southLayer: layers[r + 1],
                lowerNeighbors: lowerNeighbors
            )
        }
        return total
    }

    private func countBipartiteCrossings(
        northLayer: [Int],
        southLayer: [Int],
        lowerNeighbors: [[Int]]
    ) -> Int {
        guard northLayer.count >= 2 && southLayer.count >= 2 else { return 0 }
        var southPos: [Int: Int] = [:]
        southPos.reserveCapacity(southLayer.count)
        for (idx, v) in southLayer.enumerated() {
            southPos[v] = idx
        }

        // Collect south indices ordered by `(northIdx, southIdx)`
        var southSequence: [Int] = []
        for u in northLayer {
            let targets = lowerNeighbors[u].compactMap { southPos[$0] }.sorted()
            southSequence.append(contentsOf: targets)
        }
        guard southSequence.count >= 2 else { return 0 }

        // Count inversions in `southSequence` using a 1-indexed Fenwick tree
        let m = southLayer.count
        var bit = [Int](repeating: 0, count: m + 2)
        func add(_ idx0: Int) {
            var i = idx0 + 1
            while i <= m + 1 {
                bit[i] += 1
                i += i & (-i)
            }
        }
        func prefixSum(_ idx0: Int) -> Int {
            var i = idx0 + 1
            var sum = 0
            while i > 0 {
                sum += bit[i]
                i -= i & (-i)
            }
            return sum
        }

        var crossings = 0
        var inserted = 0
        for s in southSequence {
            let leq = prefixSum(s)
            crossings += (inserted - leq)
            add(s)
            inserted += 1
        }
        return crossings
    }

    // MARK: - Phase 4: Brandes-Kopf (2001) Horizontal Coordinate Assignment

    private func assignHorizontalCoordinatesBrandesKopf(
        layers: [[Int]],
        graph: AugmentedLayeredGraph
    ) -> [Double] {
        let totalN = graph.totalVertexCount
        var posInLayer = [Int](repeating: 0, count: totalN)
        for layer in layers {
            for (pos, v) in layer.enumerated() {
                posInLayer[v] = pos
            }
        }

        // 4a. Mark Type-1 conflicts (non-inner segment crossing an inner dummy-to-dummy segment)
        let type1Conflicts = markBrandesKopfType1Conflicts(
            layers: layers,
            posInLayer: posInLayer,
            graph: graph
        )

        // 4b. Compute 4 directional Brandes-Kopf coordinate candidates:
        //   0: Up-Left, 1: Up-Right, 2: Down-Left, 3: Down-Right
        let upLeft = solveSingleBrandesKopfDirection(
            layers: layers,
            posInLayer: posInLayer,
            graph: graph,
            conflicts: type1Conflicts,
            alignWithUpper: true,
            preferLeftToRight: true
        )
        let upRight = solveSingleBrandesKopfDirection(
            layers: layers,
            posInLayer: posInLayer,
            graph: graph,
            conflicts: type1Conflicts,
            alignWithUpper: true,
            preferLeftToRight: false
        )
        let downLeft = solveSingleBrandesKopfDirection(
            layers: layers,
            posInLayer: posInLayer,
            graph: graph,
            conflicts: type1Conflicts,
            alignWithUpper: false,
            preferLeftToRight: true
        )
        let downRight = solveSingleBrandesKopfDirection(
            layers: layers,
            posInLayer: posInLayer,
            graph: graph,
            conflicts: type1Conflicts,
            alignWithUpper: false,
            preferLeftToRight: false
        )

        var candidates = [upLeft, upRight, downLeft, downRight]

        // 4c. Align all 4 candidates to the minimum-width assignment's bounding span (Brandes & Kopf 2001 Sec. 5)
        var minBounds = [Double](repeating: 0.0, count: 4)
        var maxBounds = [Double](repeating: 0.0, count: 4)
        var bestDir = 0
        var smallestSpan = Double.greatestFiniteMagnitude

        for k in 0..<4 {
            let lo = candidates[k].min() ?? 0.0
            let hi = candidates[k].max() ?? 0.0
            minBounds[k] = lo
            maxBounds[k] = hi
            let span = hi - lo
            if span < smallestSpan {
                smallestSpan = span
                bestDir = k
            }
        }

        for k in 0..<4 where k != bestDir {
            // Left-biased runs (`k == 0 || k == 2`) align minBound; right-biased runs (`k == 1 || k == 3`) align maxBound
            let delta = (k % 2 == 0)
                ? (minBounds[bestDir] - minBounds[k])
                : (maxBounds[bestDir] - maxBounds[k])
            for v in 0..<totalN {
                candidates[k][v] += delta
            }
        }

        // Average median of the 4 candidate coordinates
        var mergedX = [Double](repeating: 0.0, count: totalN)
        for v in 0..<totalN {
            var four = [candidates[0][v], candidates[1][v], candidates[2][v], candidates[3][v]]
            four.sort()
            mergedX[v] = 0.5 * (four[1] + four[2])
        }

        // 4d. Symmetric diamond & child-centroid polish + Strict per-layer minimum-gap enforcement
        enforceStrictHorizontalSeparationAndBalance(
            layers: layers,
            graph: graph,
            centerX: &mergedX
        )

        return mergedX
    }

    private func markBrandesKopfType1Conflicts(
        layers: [[Int]],
        posInLayer: [Int],
        graph: AugmentedLayeredGraph
    ) -> Set<CFGDirectedPair> {
        var conflicts = Set<CFGDirectedPair>()
        guard layers.count >= 3 else { return conflicts }

        for r in 1..<(layers.count - 1) {
            let upper = layers[r]
            let lower = layers[r + 1]
            var k0 = 0
            var l = 0

            for (l1, v) in lower.enumerated() {
                let innerUpperPred: Int? = {
                    guard graph.isDummyVertex[v] else { return nil }
                    return graph.upperNeighbors[v].first { graph.isDummyVertex[$0] }
                }()

                if l1 == lower.count - 1 || innerUpperPred != nil {
                    let k1: Int
                    if let innerU = innerUpperPred {
                        k1 = posInLayer[innerU]
                    } else {
                        k1 = upper.count - 1
                    }

                    while l <= l1 {
                        let w = lower[l]
                        for u in graph.upperNeighbors[w] {
                            let k = posInLayer[u]
                            let isInner = graph.isDummyVertex[u] && graph.isDummyVertex[w]
                            if !isInner && (k < k0 || k > k1) {
                                conflicts.insert(CFGDirectedPair(sourceBlockID: u, targetBlockID: w))
                            }
                        }
                        l += 1
                    }
                    k0 = k1
                }
            }
        }

        return conflicts
    }

    private func solveSingleBrandesKopfDirection(
        layers: [[Int]],
        posInLayer: [Int],
        graph: AugmentedLayeredGraph,
        conflicts: Set<CFGDirectedPair>,
        alignWithUpper: Bool,
        preferLeftToRight: Bool
    ) -> [Double] {
        let n = graph.totalVertexCount
        var root = Array(0..<n)
        var align = Array(0..<n)

        // 1. Vertical Alignment into disjoint vertical blocks
        let layerIndices: [Int] = alignWithUpper
            ? Array(1..<layers.count)
            : Array((0..<(layers.count - 1)).reversed())

        for r in layerIndices {
            let currentLayer = preferLeftToRight ? layers[r] : Array(layers[r].reversed())
            var prevLim = preferLeftToRight ? -1 : Int.max

            for v in currentLayer {
                let rawNeighbors = alignWithUpper ? graph.upperNeighbors[v] : graph.lowerNeighbors[v]
                let sortedNeighbors = rawNeighbors.sorted { posInLayer[$0] < posInLayer[$1] }
                guard !sortedNeighbors.isEmpty else { continue }

                let d = sortedNeighbors.count
                let medianIndices: [Int] = (d % 2 == 1)
                    ? [d / 2]
                    : (preferLeftToRight ? [d / 2 - 1, d / 2] : [d / 2, d / 2 - 1])

                for mIdx in medianIndices {
                    guard align[v] == v else { break }
                    let u = sortedNeighbors[mIdx]
                    let pair = alignWithUpper
                        ? CFGDirectedPair(sourceBlockID: u, targetBlockID: v)
                        : CFGDirectedPair(sourceBlockID: v, targetBlockID: u)
                    guard !conflicts.contains(pair) else { continue }

                    let uPos = posInLayer[u]
                    let monotonicOK = preferLeftToRight ? (uPos > prevLim) : (uPos < prevLim)
                    if monotonicOK {
                        align[u] = v
                        root[v] = root[u]
                        align[v] = root[v]
                        prevLim = uPos
                    }
                }
            }
        }

        // 2. Horizontal Block Compaction
        var sink = Array(0..<n)
        var shift = [Double](repeating: Double.greatestFiniteMagnitude, count: n)
        var x = [Double](repeating: Double.nan, count: n)

        let gap = configuration.horizontalNodeSpacing

        func placeBlock(_ startV: Int) {
            guard x[startV].isNaN else { return }
            x[startV] = 0.0
            var w = startV
            repeat {
                let r = graph.rankOfVertex[w]
                let pos = posInLayer[w]
                let predInLayer: Int? = preferLeftToRight
                    ? (pos > 0 ? layers[r][pos - 1] : nil)
                    : (pos + 1 < layers[r].count ? layers[r][pos + 1] : nil)

                if let pred = predInLayer {
                    let uRoot = root[pred]
                    placeBlock(uRoot)
                    if sink[startV] == startV {
                        sink[startV] = sink[uRoot]
                    }
                    let minSep = 0.5 * (graph.widthOfVertex[pred] + graph.widthOfVertex[w]) + gap
                    if sink[startV] != sink[uRoot] {
                        let candidateShift = preferLeftToRight
                            ? (x[startV] - x[uRoot] - minSep)
                            : (x[uRoot] - x[startV] - minSep)
                        shift[sink[uRoot]] = min(shift[sink[uRoot]], candidateShift)
                    } else {
                        if preferLeftToRight {
                            x[startV] = max(x[startV], x[uRoot] + minSep)
                        } else {
                            x[startV] = min(x[startV], x[uRoot] - minSep)
                        }
                    }
                }
                w = align[w]
            } while w != startV
        }

        for v in 0..<n where root[v] == v {
            placeBlock(v)
        }

        for v in 0..<n {
            x[v] = x[root[v]]
            let s = shift[sink[root[v]]]
            if s < Double.greatestFiniteMagnitude * 0.5 {
                if preferLeftToRight {
                    x[v] += s
                } else {
                    x[v] -= s
                }
            }
        }

        return x
    }

    private func enforceStrictHorizontalSeparationAndBalance(
        layers: [[Int]],
        graph: AugmentedLayeredGraph,
        centerX: inout [Double]
    ) {
        let gap = configuration.horizontalNodeSpacing

        // Pass A: Enforce strict left-to-right non-overlap inside each layer while preserving layer centroid
        for layer in layers where layer.count >= 2 {
            let oldCentroid = layer.map { centerX[$0] }.reduce(0.0, +) / Double(layer.count)

            for i in 1..<layer.count {
                let leftV = layer[i - 1]
                let rightV = layer[i]
                let minRequired = centerX[leftV]
                    + 0.5 * (graph.widthOfVertex[leftV] + graph.widthOfVertex[rightV])
                    + gap
                if centerX[rightV] < minRequired {
                    centerX[rightV] = minRequired
                }
            }

            let newCentroid = layer.map { centerX[$0] }.reduce(0.0, +) / Double(layer.count)
            let recenterDelta = oldCentroid - newCentroid
            for v in layer {
                centerX[v] += recenterDelta
            }
        }

        // Pass B: Center single-node / diamond parent headers directly above their children's midpoint when slack permits
        for _ in 0..<2 {
            for r in stride(from: layers.count - 2, through: 0, by: -1) {
                let layer = layers[r]
                for (pos, v) in layer.enumerated() where !graph.isDummyVertex[v] {
                    let children = graph.lowerNeighbors[v]
                    guard !children.isEmpty else { continue }
                    let childAvg = children.map { centerX[$0] }.reduce(0.0, +) / Double(children.count)

                    var loBound = -Double.greatestFiniteMagnitude
                    var hiBound = Double.greatestFiniteMagnitude
                    if pos > 0 {
                        let leftV = layer[pos - 1]
                        loBound = centerX[leftV] + 0.5 * (graph.widthOfVertex[leftV] + graph.widthOfVertex[v]) + gap
                    }
                    if pos + 1 < layer.count {
                        let rightV = layer[pos + 1]
                        hiBound = centerX[rightV] - 0.5 * (graph.widthOfVertex[rightV] + graph.widthOfVertex[v]) - gap
                    }
                    if loBound <= hiBound {
                        centerX[v] = min(hiBound, max(loBound, childAvg))
                    }
                }
            }
        }
    }

    // MARK: - Phase 5: Orthogonal Channel & Outer-Gutter Back-Edge Router

    private struct HorizontalSegmentInterval {
        let edgeKey: String
        let minX: Double
        let maxX: Double
        let targetX: Double
    }

    private func routeEdgesAndAssembleCanvas(
        functionAddress: VirtualAddress,
        blocks: [BasicBlock],
        layers: [[Int]],
        graph: AugmentedLayeredGraph,
        centerXByVertex: [Double],
        allEdges: [IndexedCFGEdge]
    ) -> SugiyamaCFGLayout {
        let L = graph.layerCount

        // 5a. Compute per-layer real-node heights
        var layerMaxHeight = [Double](repeating: configuration.minNodeHeight, count: L)
        for r in 0..<L {
            var maxH = 24.0
            for v in layers[r] where !graph.isDummyVertex[v] {
                maxH = max(maxH, graph.heightOfVertex[v])
            }
            layerMaxHeight[r] = maxH
        }

        // 5b. Pre-allocate outgoing bottom ports & incoming top ports on every real node
        // sorted by destination/source X coordinate to prevent port-exit twists!
        var outgoingPortXByEdgeIdx: [Int: Double] = [:]
        var incomingPortXByEdgeIdx: [Int: Double] = [:]

        var outEdgesByReal = Array(repeating: [IndexedCFGEdge](), count: graph.realCount)
        var inEdgesByReal = Array(repeating: [IndexedCFGEdge](), count: graph.realCount)

        for e in allEdges {
            outEdgesByReal[e.srcReal].append(e)
            inEdgesByReal[e.dstReal].append(e)
        }

        for u in 0..<graph.realCount {
            let outs = outEdgesByReal[u].sorted { a, b in
                let xA = nextHopX(for: a, fromSource: true, graph: graph, centerX: centerXByVertex)
                let xB = nextHopX(for: b, fromSource: true, graph: graph, centerX: centerXByVertex)
                if abs(xA - xB) > 1.0 { return xA < xB }
                return a.originalIndex < b.originalIndex
            }
            let w = graph.widthOfVertex[u]
            let usableSpan = min(w * 0.68, max(0.0, w - 40.0))
            for (idx, item) in outs.enumerated() {
                let offset: Double
                if outs.count == 1 {
                    offset = 0.0
                } else {
                    let frac = (Double(idx) / Double(outs.count - 1)) - 0.5
                    offset = frac * usableSpan
                }
                outgoingPortXByEdgeIdx[item.originalIndex] = centerXByVertex[u] + offset
            }

            let ins = inEdgesByReal[u].sorted { a, b in
                let xA = nextHopX(for: a, fromSource: false, graph: graph, centerX: centerXByVertex)
                let xB = nextHopX(for: b, fromSource: false, graph: graph, centerX: centerXByVertex)
                if abs(xA - xB) > 1.0 { return xA < xB }
                return a.originalIndex < b.originalIndex
            }
            for (idx, item) in ins.enumerated() {
                let offset: Double
                if ins.count == 1 {
                    offset = 0.0
                } else {
                    let frac = (Double(idx) / Double(ins.count - 1)) - 0.5
                    offset = frac * usableSpan
                }
                incomingPortXByEdgeIdx[item.originalIndex] = centerXByVertex[u] + offset
            }
        }

        // 5c. Collect horizontal segments in each inter-layer channel `0..<L` (and top header channel `-1` for back-edges to layer 0)
        // Channel `c` (`0 <= c < L - 1`) sits strictly between `layerBottom[c]` and `layerTop[c + 1]`.
        var channelIntervals = Array(repeating: [HorizontalSegmentInterval](), count: max(1, L))
        var topAboveRootBackEdgeCount = 0

        for item in allEdges {
            if item.isSelfLoop { continue }
            let isBack = item.isReversedFeedbackArc || (graph.rankOfVertex[item.dstReal] <= graph.rankOfVertex[item.srcReal])
            if isBack {
                let srcRank = graph.rankOfVertex[item.srcReal]
                let dstRank = graph.rankOfVertex[item.dstReal]
                channelIntervals[min(srcRank, L - 1)].append(
                    HorizontalSegmentInterval(
                        edgeKey: "back_exit_\(item.originalIndex)",
                        minX: -1e6,
                        maxX: 1e6,
                        targetX: centerXByVertex[item.srcReal]
                    )
                )
                if dstRank == 0 {
                    topAboveRootBackEdgeCount += 1
                } else {
                    channelIntervals[dstRank - 1].append(
                        HorizontalSegmentInterval(
                            edgeKey: "back_enter_\(item.originalIndex)",
                            minX: -1e6,
                            maxX: 1e6,
                            targetX: centerXByVertex[item.dstReal]
                        )
                    )
                }
                continue
            }

            // Forward DAG edge (was NOT reversed)
            guard let chain = graph.chainByOriginalEdge[item.originalIndex], chain.count >= 2 else { continue }
            for hop in 0..<(chain.count - 1) {
                let a = chain[hop]
                let b = chain[hop + 1]
                let r = graph.rankOfVertex[a]
                let xA = (hop == 0) ? (outgoingPortXByEdgeIdx[item.originalIndex] ?? centerXByVertex[a]) : centerXByVertex[a]
                let xB = (hop == chain.count - 2) ? (incomingPortXByEdgeIdx[item.originalIndex] ?? centerXByVertex[b]) : centerXByVertex[b]
                if abs(xA - xB) >= 1.5 && r < channelIntervals.count {
                    channelIntervals[r].append(
                        HorizontalSegmentInterval(
                            edgeKey: "fwd_\(item.originalIndex)_\(hop)",
                            minX: min(xA, xB),
                            maxX: max(xA, xB),
                            targetX: xB
                        )
                    )
                }
            }
        }

        // Interval-color tracks per channel and size vertical gaps dynamically so tracks never crowd
        var trackAssignmentByKey: [String: (trackIndex: Int, totalTracks: Int)] = [:]
        var interLayerGapHeights = [Double](repeating: configuration.baseVerticalLayerSpacing, count: max(1, L))

        for c in 0..<channelIntervals.count {
            let colored = colorHorizontalTracks(channelIntervals[c])
            for (k, v) in colored.assignments {
                trackAssignmentByKey[k] = (v, colored.trackCount)
            }
            let neededHeight = Double(max(1, colored.trackCount) + 2) * configuration.channelTrackSpacing + 28.0
            interLayerGapHeights[c] = max(configuration.baseVerticalLayerSpacing, neededHeight)
        }

        // 5d. Assign absolute vertical `layerTopY[r]` and `layerBottomY[r]`
        let topHeaderReserve = Double(topAboveRootBackEdgeCount) * configuration.channelTrackSpacing + (topAboveRootBackEdgeCount > 0 ? 28.0 : 0.0)
        var layerTopY = [Double](repeating: 0.0, count: L)
        var layerBottomY = [Double](repeating: 0.0, count: L)
        var cursorY = configuration.canvasMargin + topHeaderReserve

        for r in 0..<L {
            layerTopY[r] = cursorY
            layerBottomY[r] = cursorY + layerMaxHeight[r]
            cursorY = layerBottomY[r] + interLayerGapHeights[r]
        }

        // Determine extreme left & right X across all real and dummy nodes for dedicated outer back-edge gutters
        var minNodeLeftX = Double.greatestFiniteMagnitude
        var maxNodeRightX = -Double.greatestFiniteMagnitude
        for v in 0..<graph.totalVertexCount {
            let half = 0.5 * graph.widthOfVertex[v]
            minNodeLeftX = min(minNodeLeftX, centerXByVertex[v] - half)
            maxNodeRightX = max(maxNodeRightX, centerXByVertex[v] + half)
        }
        let graphMidX = 0.5 * (minNodeLeftX + maxNodeRightX)

        // Helper computing Y for a track inside inter-layer channel `c`
        func channelTrackY(channel c: Int, key: String) -> Double {
            let top = layerBottomY[min(c, L - 1)]
            let gapH = interLayerGapHeights[min(c, interLayerGapHeights.count - 1)]
            if let info = trackAssignmentByKey[key], info.totalTracks > 0 {
                let frac = Double(info.trackIndex + 1) / Double(info.totalTracks + 1)
                return top + gapH * (0.18 + 0.64 * frac)
            }
            return top + gapH * 0.5
        }

        // 5e. Route every edge cleanly into `[CGPointBridge]` waypoints
        var rawRoutes: [(edge: CFGEdge, points: [CGPointBridge], label: String?)] = []
        rawRoutes.reserveCapacity(allEdges.count)

        var leftGutterLane = 0
        var rightGutterLane = 0
        var aboveRootLane = 0

        for item in allEdges {
            let u = item.srcReal
            let v = item.dstReal
            let uRank = graph.rankOfVertex[u]
            let vRank = graph.rankOfVertex[v]
            let uFrame = CGRectBridge(
                x: centerXByVertex[u] - 0.5 * graph.widthOfVertex[u],
                y: layerTopY[uRank],
                width: graph.widthOfVertex[u],
                height: graph.heightOfVertex[u]
            )
            let vFrame = CGRectBridge(
                x: centerXByVertex[v] - 0.5 * graph.widthOfVertex[v],
                y: layerTopY[vRank],
                width: graph.widthOfVertex[v],
                height: graph.heightOfVertex[v]
            )

            let startX = outgoingPortXByEdgeIdx[item.originalIndex] ?? uFrame.midX
            let endX = incomingPortXByEdgeIdx[item.originalIndex] ?? vFrame.midX
            let startPt = CGPointBridge(x: startX, y: uFrame.maxY)
            let endPt = CGPointBridge(x: endX, y: vFrame.minY)

            // Case 1: Self-loop (`u == v`)
            if item.isSelfLoop {
                let rightClearance = findRightClearanceX(
                    forRealVertex: u,
                    inLayer: layers[uRank],
                    graph: graph,
                    centerX: centerXByVertex,
                    fallbackOuterRightX: maxNodeRightX + Double(rightGutterLane + 1) * configuration.outerGutterLaneSpacing + 20.0
                )
                if rightClearance > maxNodeRightX {
                    rightGutterLane += 1
                }
                let belowY = uFrame.maxY + 18.0
                let aboveY = uFrame.minY - 18.0
                let loopPts = simplifyOrthogonalPolyline([
                    CGPointBridge(x: min(uFrame.maxX - 14.0, max(startX, uFrame.midX + 16.0)), y: uFrame.maxY),
                    CGPointBridge(x: min(uFrame.maxX - 14.0, max(startX, uFrame.midX + 16.0)), y: belowY),
                    CGPointBridge(x: rightClearance, y: belowY),
                    CGPointBridge(x: rightClearance, y: aboveY),
                    CGPointBridge(x: min(uFrame.maxX - 14.0, max(endX, uFrame.midX + 16.0)), y: aboveY),
                    CGPointBridge(x: min(uFrame.maxX - 14.0, max(endX, uFrame.midX + 16.0)), y: uFrame.minY)
                ])
                rawRoutes.append((item.edge, applyRoutingStyle(loopPts), item.edge.kind.displayLabel))
                continue
            }

            // Case 2: Back-edge (`vRank <= uRank` or reversed feedback arc)
            let isBackRoute = item.isReversedFeedbackArc || (vRank <= uRank)
            if isBackRoute {
                let avgX = 0.5 * (startX + endX)
                let useLeftGutter = avgX <= graphMidX
                let gutterX: Double
                if useLeftGutter {
                    leftGutterLane += 1
                    gutterX = minNodeLeftX - 32.0 - Double(leftGutterLane) * configuration.outerGutterLaneSpacing
                } else {
                    rightGutterLane += 1
                    gutterX = maxNodeRightX + 32.0 + Double(rightGutterLane) * configuration.outerGutterLaneSpacing
                }

                let exitY = channelTrackY(channel: uRank, key: "back_exit_\(item.originalIndex)")
                let enterY: Double
                if vRank == 0 {
                    aboveRootLane += 1
                    enterY = vFrame.minY - 18.0 - Double(aboveRootLane) * configuration.channelTrackSpacing
                } else {
                    enterY = channelTrackY(channel: vRank - 1, key: "back_enter_\(item.originalIndex)")
                }

                let backPts = simplifyOrthogonalPolyline([
                    startPt,
                    CGPointBridge(x: startPt.x, y: exitY),
                    CGPointBridge(x: gutterX, y: exitY),
                    CGPointBridge(x: gutterX, y: enterY),
                    CGPointBridge(x: endPt.x, y: enterY),
                    endPt
                ])
                rawRoutes.append((item.edge, applyRoutingStyle(backPts), item.edge.kind.displayLabel))
                continue
            }

            // Case 3: Forward DAG edge (`vRank > uRank`) along virtual dummy corridor chain
            let chain = graph.chainByOriginalEdge[item.originalIndex] ?? [u, v]
            var pts: [CGPointBridge] = [startPt]

            if chain.count == 2 {
                if abs(startPt.x - endPt.x) < 1.5 {
                    pts.append(endPt)
                } else {
                    let midY = channelTrackY(channel: uRank, key: "fwd_\(item.originalIndex)_0")
                    pts.append(CGPointBridge(x: startPt.x, y: midY))
                    pts.append(CGPointBridge(x: endPt.x, y: midY))
                    pts.append(endPt)
                }
            } else {
                var curX = startPt.x
                for hop in 0..<(chain.count - 1) {
                    let a = chain[hop]
                    let b = chain[hop + 1]
                    let r = graph.rankOfVertex[a]
                    let nextX = (hop == chain.count - 2) ? endPt.x : centerXByVertex[b]
                    let trackY = channelTrackY(channel: r, key: "fwd_\(item.originalIndex)_\(hop)")

                    if abs(curX - nextX) >= 1.5 {
                        pts.append(CGPointBridge(x: curX, y: trackY))
                        pts.append(CGPointBridge(x: nextX, y: trackY))
                    }
                    if hop < chain.count - 2 {
                        // Thread vertically down through the dummy vertex's clear corridor across layer `r + 1`
                        pts.append(CGPointBridge(x: nextX, y: layerTopY[r + 1]))
                        pts.append(CGPointBridge(x: nextX, y: layerBottomY[r + 1]))
                    }
                    curX = nextX
                }
                pts.append(endPt)
            }

            let cleaned = simplifyOrthogonalPolyline(pts)
            rawRoutes.append((item.edge, applyRoutingStyle(cleaned), item.edge.kind.displayLabel))
        }

        // 5f. Normalize global canvas coordinates so minimum X & Y equal `canvasMargin`
        var rawNodeLayouts: [(blockID: Int, layer: Int, orderInLayer: Int, frame: CGRectBridge)] = []
        rawNodeLayouts.reserveCapacity(graph.realCount)

        for r in 0..<L {
            var realOrder = 0
            for v in layers[r] where !graph.isDummyVertex[v] {
                let w = graph.widthOfVertex[v]
                let h = graph.heightOfVertex[v]
                let rect = CGRectBridge(
                    x: centerXByVertex[v] - 0.5 * w,
                    y: layerTopY[r],
                    width: w,
                    height: h
                )
                rawNodeLayouts.append((blocks[v].id, r, realOrder, rect))
                realOrder += 1
            }
        }

        var globalMinX = Double.greatestFiniteMagnitude
        var globalMinY = Double.greatestFiniteMagnitude
        for n in rawNodeLayouts {
            globalMinX = min(globalMinX, n.frame.minX)
            globalMinY = min(globalMinY, n.frame.minY)
        }
        for r in rawRoutes {
            for p in r.points {
                globalMinX = min(globalMinX, p.x)
                globalMinY = min(globalMinY, p.y)
            }
        }

        let shiftX = (globalMinX < Double.greatestFiniteMagnitude) ? (configuration.canvasMargin - globalMinX) : 0.0
        let shiftY = (globalMinY < Double.greatestFiniteMagnitude) ? (configuration.canvasMargin - globalMinY) : 0.0

        var globalMaxX = 0.0
        var globalMaxY = 0.0

        let finalNodes: [CFGNodeLayout] = rawNodeLayouts
            .map { item in
                let shifted = CGRectBridge(
                    x: (item.frame.x + shiftX).roundedToQuarterPixel(),
                    y: (item.frame.y + shiftY).roundedToQuarterPixel(),
                    width: item.frame.width.roundedToQuarterPixel(),
                    height: item.frame.height.roundedToQuarterPixel()
                )
                globalMaxX = max(globalMaxX, shifted.maxX)
                globalMaxY = max(globalMaxY, shifted.maxY)
                return CFGNodeLayout(
                    blockID: item.blockID,
                    layer: item.layer,
                    orderInLayer: item.orderInLayer,
                    frame: shifted
                )
            }
            .sorted { $0.blockID < $1.blockID }

        let finalRoutes: [CFGEdgeRoute] = rawRoutes.map { item in
            let shiftedPts = item.points.map { pt -> CGPointBridge in
                let sp = CGPointBridge(
                    x: (pt.x + shiftX).roundedToQuarterPixel(),
                    y: (pt.y + shiftY).roundedToQuarterPixel()
                )
                globalMaxX = max(globalMaxX, sp.x)
                globalMaxY = max(globalMaxY, sp.y)
                return sp
            }
            return CFGEdgeRoute(
                edge: item.edge,
                waypoints: shiftedPts,
                label: item.label
            )
        }

        let totalCanvasWidth = max(configuration.canvasMargin * 2.0, globalMaxX + configuration.canvasMargin)
        let totalCanvasHeight = max(configuration.canvasMargin * 2.0, globalMaxY + configuration.canvasMargin)

        return SugiyamaCFGLayout(
            functionAddress: functionAddress,
            canvasWidth: totalCanvasWidth.roundedToQuarterPixel(),
            canvasHeight: totalCanvasHeight.roundedToQuarterPixel(),
            layerCount: L,
            nodes: finalNodes,
            routes: finalRoutes
        )
    }

    // MARK: - Single-Node Fast Path & Node Box Sizing

    private func buildSingleNodeLayout(
        functionAddress: VirtualAddress,
        block: BasicBlock,
        width: Double,
        height: Double,
        edges: [CFGEdge]
    ) -> SugiyamaCFGLayout {
        let margin = configuration.canvasMargin
        let frame = CGRectBridge(x: margin, y: margin, width: width, height: height)
        let node = CFGNodeLayout(blockID: block.id, layer: 0, orderInLayer: 0, frame: frame)

        var routes: [CFGEdgeRoute] = []
        var maxX = frame.maxX
        var maxY = frame.maxY
        var minY = frame.minY

        for (idx, edge) in edges.enumerated() where edge.sourceBlockID == block.id && edge.targetBlockID == block.id {
            let gutterX = frame.maxX + 28.0 + Double(idx) * 20.0
            let belowY = frame.maxY + 20.0 + Double(idx) * 10.0
            let aboveY = frame.minY - 20.0 - Double(idx) * 10.0
            let rawPts = [
                CGPointBridge(x: frame.midX + 24.0, y: frame.maxY),
                CGPointBridge(x: frame.midX + 24.0, y: belowY),
                CGPointBridge(x: gutterX, y: belowY),
                CGPointBridge(x: gutterX, y: aboveY),
                CGPointBridge(x: frame.midX + 24.0, y: aboveY),
                CGPointBridge(x: frame.midX + 24.0, y: frame.minY)
            ]
            maxX = max(maxX, gutterX)
            maxY = max(maxY, belowY)
            minY = min(minY, aboveY)
            routes.append(CFGEdgeRoute(edge: edge, waypoints: applyRoutingStyle(rawPts), label: edge.kind.displayLabel))
        }

        let shiftY = minY < margin ? (margin - minY) : 0.0
        let adjustedNode: CFGNodeLayout
        let adjustedRoutes: [CFGEdgeRoute]
        if shiftY > 0 {
            adjustedNode = CFGNodeLayout(
                blockID: node.blockID,
                layer: 0,
                orderInLayer: 0,
                frame: CGRectBridge(x: frame.x, y: frame.y + shiftY, width: frame.width, height: frame.height)
            )
            adjustedRoutes = routes.map { r in
                CFGEdgeRoute(
                    edge: r.edge,
                    waypoints: r.waypoints.map { CGPointBridge(x: $0.x, y: $0.y + shiftY) },
                    label: r.label
                )
            }
            maxY += shiftY
        } else {
            adjustedNode = node
            adjustedRoutes = routes
        }

        return SugiyamaCFGLayout(
            functionAddress: functionAddress,
            canvasWidth: maxX + margin,
            canvasHeight: maxY + margin,
            layerCount: 1,
            nodes: [adjustedNode],
            routes: adjustedRoutes
        )
    }

    private func measureBasicBlockBox(_ block: BasicBlock) -> (width: Double, height: Double) {
        var maxChars = block.label.count + 6
        for insn in block.instructions {
            // Address column (`0x100001000: `) + disassembly text
            var lineChars = 13 + insn.formattedDisassembly.count
            if let comment = insn.autoComment, !comment.isEmpty {
                lineChars += min(28, comment.count + 4)
            }
            if lineChars > maxChars {
                maxChars = lineChars
            }
        }

        let estimatedWidth = Double(maxChars) * configuration.characterAdvanceWidth + configuration.nodeHorizontalPadding
        let clampedWidth = min(configuration.maxNodeWidth, max(configuration.minNodeWidth, estimatedWidth))

        let lineCount = max(1, block.instructions.count)
        let estimatedHeight = configuration.headerBarHeight
            + Double(lineCount) * configuration.instructionLineHeight
            + configuration.nodeVerticalPadding
        let clampedHeight = max(configuration.minNodeHeight, estimatedHeight)

        return (clampedWidth, clampedHeight)
    }

    // MARK: - Routing Geometry & Interval Track Coloring Helpers

    private func nextHopX(
        for edge: IndexedCFGEdge,
        fromSource: Bool,
        graph: AugmentedLayeredGraph,
        centerX: [Double]
    ) -> Double {
        if edge.isSelfLoop {
            return centerX[edge.srcReal] + 100.0
        }
        if !edge.isReversedFeedbackArc,
           let chain = graph.chainByOriginalEdge[edge.originalIndex],
           chain.count >= 2 {
            return fromSource ? centerX[chain[1]] : centerX[chain[chain.count - 2]]
        }
        return fromSource ? centerX[edge.dstReal] : centerX[edge.srcReal]
    }

    private func colorHorizontalTracks(
        _ intervals: [HorizontalSegmentInterval]
    ) -> (assignments: [String: Int], trackCount: Int) {
        guard !intervals.isEmpty else { return ([:], 0) }
        let sorted = intervals.sorted {
            if $0.minX != $1.minX { return $0.minX < $1.minX }
            return $0.maxX < $1.maxX
        }

        var trackRightEnd: [Double] = []
        var assignments: [String: Int] = [:]

        for interval in sorted {
            var chosenTrack: Int?
            for t in 0..<trackRightEnd.count {
                if interval.minX > trackRightEnd[t] + 6.0 {
                    chosenTrack = t
                    trackRightEnd[t] = interval.maxX
                    break
                }
            }
            if let existing = chosenTrack {
                assignments[interval.edgeKey] = existing
            } else {
                let newTrack = trackRightEnd.count
                trackRightEnd.append(interval.maxX)
                assignments[interval.edgeKey] = newTrack
            }
        }

        return (assignments, trackRightEnd.count)
    }

    private func findRightClearanceX(
        forRealVertex u: Int,
        inLayer layer: [Int],
        graph: AugmentedLayeredGraph,
        centerX: [Double],
        fallbackOuterRightX: Double
    ) -> Double {
        let uRight = centerX[u] + 0.5 * graph.widthOfVertex[u]
        guard let idx = layer.firstIndex(of: u) else {
            return fallbackOuterRightX
        }
        if idx == layer.count - 1 {
            return uRight + 26.0
        }
        let nextV = layer[idx + 1]
        let nextLeft = centerX[nextV] - 0.5 * graph.widthOfVertex[nextV]
        if nextLeft - uRight >= 36.0 {
            return uRight + 0.5 * (nextLeft - uRight)
        }
        return fallbackOuterRightX
    }

    private func simplifyOrthogonalPolyline(_ points: [CGPointBridge]) -> [CGPointBridge] {
        guard points.count >= 3 else { return points }
        var dedup: [CGPointBridge] = [points[0]]
        for p in points.dropFirst() {
            let prev = dedup[dedup.count - 1]
            if hypot(p.x - prev.x, p.y - prev.y) > 0.25 {
                dedup.append(p)
            }
        }
        guard dedup.count >= 3 else { return dedup }

        var simplified: [CGPointBridge] = [dedup[0]]
        for i in 1..<(dedup.count - 1) {
            let a = simplified[simplified.count - 1]
            let b = dedup[i]
            let c = dedup[i + 1]
            let sameVertical = abs(a.x - b.x) < 0.5 && abs(b.x - c.x) < 0.5 && ((b.y - a.y) * (c.y - b.y) >= 0)
            let sameHorizontal = abs(a.y - b.y) < 0.5 && abs(b.y - c.y) < 0.5 && ((b.x - a.x) * (c.x - b.x) >= 0)
            if !sameVertical && !sameHorizontal {
                simplified.append(b)
            }
        }
        simplified.append(dedup[dedup.count - 1])
        return simplified
    }

    private func applyRoutingStyle(_ orthogonalWaypoints: [CGPointBridge]) -> [CGPointBridge] {
        switch configuration.routingMode {
        case .orthogonalChannel:
            return orthogonalWaypoints
        case .cubicBezierSpline:
            return roundOrthogonalCornersWithSplineSamples(orthogonalWaypoints, cornerRadius: 14.0)
        }
    }

    private func roundOrthogonalCornersWithSplineSamples(
        _ pts: [CGPointBridge],
        cornerRadius: Double
    ) -> [CGPointBridge] {
        guard pts.count >= 3 else { return pts }
        var out: [CGPointBridge] = [pts[0]]
        for i in 1..<(pts.count - 1) {
            let prev = pts[i - 1]
            let curr = pts[i]
            let next = pts[i + 1]

            let dx1 = curr.x - prev.x
            let dy1 = curr.y - prev.y
            let len1 = hypot(dx1, dy1)

            let dx2 = next.x - curr.x
            let dy2 = next.y - curr.y
            let len2 = hypot(dx2, dy2)

            let r = min(cornerRadius, 0.4 * min(len1, len2))
            if r < 2.0 || len1 < 1e-3 || len2 < 1e-3 {
                out.append(curr)
                continue
            }

            let entry = CGPointBridge(x: curr.x - (dx1 / len1) * r, y: curr.y - (dy1 / len1) * r)
            let exit = CGPointBridge(x: curr.x + (dx2 / len2) * r, y: curr.y + (dy2 / len2) * r)
            out.append(entry)
            // Sample quadratic/cubic fillet arc inside the corner (guaranteed inside the clear channel!)
            for step in 1...3 {
                let t = Double(step) / 4.0
                let omt = 1.0 - t
                let sx = omt * omt * entry.x + 2.0 * omt * t * curr.x + t * t * exit.x
                let sy = omt * omt * entry.y + 2.0 * omt * t * curr.y + t * t * exit.y
                out.append(CGPointBridge(x: sx, y: sy))
            }
            out.append(exit)
        }
        out.append(pts[pts.count - 1])
        return out
    }

    private func segmentIntersectsRect(p0: CGPointBridge, p1: CGPointBridge, rect: CGRectBridge) -> Bool {
        guard rect.width > 0 && rect.height > 0 else { return false }
        let minX = min(p0.x, p1.x)
        let maxX = max(p0.x, p1.x)
        let minY = min(p0.y, p1.y)
        let maxY = max(p0.y, p1.y)

        if maxX <= rect.minX || minX >= rect.maxX || maxY <= rect.minY || minY >= rect.maxY {
            return false
        }

        //Liang-Barsky parametric segment-vs-AABB intersection test
        let dx = p1.x - p0.x
        let dy = p1.y - p0.y
        var t0 = 0.0
        var t1 = 1.0

        let checks: [(p: Double, q: Double)] = [
            (-dx, p0.x - rect.minX),
            (dx, rect.maxX - p0.x),
            (-dy, p0.y - rect.minY),
            (dy, rect.maxY - p0.y)
        ]

        for item in checks {
            if abs(item.p) < 1e-9 {
                if item.q <= 0 { return false }
            } else {
                let r = item.q / item.p
                if item.p < 0 {
                    if r > t1 { return false }
                    if r > t0 { t0 = r }
                } else {
                    if r < t0 { return false }
                    if r < t1 { t1 = r }
                }
            }
        }
        return t0 < t1
    }
}

private extension Double {
    func roundedToQuarterPixel() -> Double {
        (self * 4.0).rounded() * 0.25
    }
}
