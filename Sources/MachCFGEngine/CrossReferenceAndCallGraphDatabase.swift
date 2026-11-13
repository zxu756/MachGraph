import Foundation
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder

// MARK: - Import Call Site & Bidirectional Cross-Reference Database

public struct ImportCallSiteRecord: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(callInstructionAddress.hexString)->\(importedSymbolName)" }
    public let callInstructionAddress: VirtualAddress
    public let callerFunctionAddress: VirtualAddress?
    public let callerFunctionName: String?
    public let stubOrGOTAddress: VirtualAddress
    public let importedSymbolName: String
    public let demangledSymbolName: String
    public let libraryName: String?
    public let isTailCall: Bool

    public init(
        callInstructionAddress: VirtualAddress,
        callerFunctionAddress: VirtualAddress?,
        callerFunctionName: String?,
        stubOrGOTAddress: VirtualAddress,
        importedSymbolName: String,
        demangledSymbolName: String? = nil,
        libraryName: String? = nil,
        isTailCall: Bool = false
    ) {
        self.callInstructionAddress = callInstructionAddress
        self.callerFunctionAddress = callerFunctionAddress
        self.callerFunctionName = callerFunctionName
        self.stubOrGOTAddress = stubOrGOTAddress
        self.importedSymbolName = importedSymbolName
        self.demangledSymbolName = demangledSymbolName ?? importedSymbolName
        self.libraryName = libraryName
        self.isTailCall = isTailCall
    }
}

public struct CrossReferenceIndex: Sendable, Codable, Hashable {
    public let allRecords: [XrefRecord]
    public let stringXrefs: [XrefRecord]
    public let importCallSites: [ImportCallSiteRecord]

    private let incomingByTarget: [VirtualAddress: [XrefRecord]]
    private let outgoingBySource: [VirtualAddress: [XrefRecord]]
    private let outgoingByFunction: [VirtualAddress: [XrefRecord]]
    private let stringXrefsByTarget: [VirtualAddress: [XrefRecord]]

    public init(
        records: [XrefRecord],
        importCallSites: [ImportCallSiteRecord] = []
    ) {
        let sortedRecords = records.sorted {
            if $0.fromAddress != $1.fromAddress { return $0.fromAddress < $1.fromAddress }
            if $0.toAddress != $1.toAddress { return $0.toAddress < $1.toAddress }
            return $0.kind.rawValue < $1.kind.rawValue
        }
        self.allRecords = sortedRecords
        self.importCallSites = importCallSites.sorted { $0.callInstructionAddress < $1.callInstructionAddress }

        var inMap: [VirtualAddress: [XrefRecord]] = [:]
        var outMap: [VirtualAddress: [XrefRecord]] = [:]
        var fnOutMap: [VirtualAddress: [XrefRecord]] = [:]
        var strList: [XrefRecord] = []
        var strMap: [VirtualAddress: [XrefRecord]] = [:]

        for rec in sortedRecords {
            inMap[rec.toAddress, default: []].append(rec)
            outMap[rec.fromAddress, default: []].append(rec)
            if let fnAddr = rec.fromFunction {
                fnOutMap[fnAddr, default: []].append(rec)
            }
            if rec.kind == .stringReference {
                strList.append(rec)
                strMap[rec.toAddress, default: []].append(rec)
            }
        }

        self.stringXrefs = strList
        self.incomingByTarget = inMap
        self.outgoingBySource = outMap
        self.outgoingByFunction = fnOutMap
        self.stringXrefsByTarget = strMap
    }

    public var count: Int { allRecords.count }

    /// Returns all cross-references targeting `address` (`XREFS TO`).
    public func xrefsTo(address: VirtualAddress) -> [XrefRecord] {
        incomingByTarget[address] ?? []
    }

    /// Returns all cross-references originating at instruction/data `address` (`XREFS FROM`).
    public func xrefsFrom(address: VirtualAddress) -> [XrefRecord] {
        outgoingBySource[address] ?? []
    }

    /// Returns all outgoing cross-references emitted by instructions inside the function at `functionAddress`.
    public func xrefsFromFunction(at functionAddress: VirtualAddress) -> [XrefRecord] {
        outgoingByFunction[functionAddress] ?? []
    }

    /// Returns all string literal cross-references targeting `stringAddress`.
    public func stringXrefs(to stringAddress: VirtualAddress) -> [XrefRecord] {
        stringXrefsByTarget[stringAddress] ?? []
    }

    /// Filters `importCallSites` whose raw or demangled symbol name matches `symbolQuery` (case-insensitive substring or exact).
    public func importCallSites(matching symbolQuery: String) -> [ImportCallSiteRecord] {
        let q = symbolQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return importCallSites }
        return importCallSites.filter {
            $0.importedSymbolName.lowercased().contains(q) ||
            $0.demangledSymbolName.lowercased().contains(q)
        }
    }
}

// MARK: - Whole-Program Call Graph & Dangerous Sink Path Models

public enum DangerousSinkCategory: String, Sendable, Codable, Hashable, CaseIterable {
    case commandExecution = "Process / Command Execution"
    case unboundedMemoryOrString = "Memory Copy / Buffer Handling"
    case formatStringOutput = "Format String / Variadic Output"
    case dynamicLoaderOrJIT = "Dynamic Code Loading / RWX"
    case authenticationOrCrypto = "Authentication / Constant-Time Sensitive"
    case environmentOrNetwork = "Environment / External I/O"
}

public struct CallGraphNode: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let name: String
    public let demangledName: String
    public let isImportedThunk: Bool
    public let isExternalSymbol: Bool
    public let isEntryOrExported: Bool
    public let sinkCategory: DangerousSinkCategory?
    public let inDegree: Int
    public let outDegree: Int

    public init(
        address: VirtualAddress,
        name: String,
        demangledName: String,
        isImportedThunk: Bool = false,
        isExternalSymbol: Bool = false,
        isEntryOrExported: Bool = false,
        sinkCategory: DangerousSinkCategory? = nil,
        inDegree: Int = 0,
        outDegree: Int = 0
    ) {
        self.address = address
        self.name = name
        self.demangledName = demangledName
        self.isImportedThunk = isImportedThunk
        self.isExternalSymbol = isExternalSymbol
        self.isEntryOrExported = isEntryOrExported
        self.sinkCategory = sinkCategory
        self.inDegree = inDegree
        self.outDegree = outDegree
    }
}

public struct CallGraphEdge: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(callerAddress.hexString)->\(calleeAddress.hexString)" }
    public let callerAddress: VirtualAddress
    public let calleeAddress: VirtualAddress
    public let callSiteAddresses: [VirtualAddress]
    public let isTailCall: Bool
    public let isIndirectResolved: Bool

    public init(
        callerAddress: VirtualAddress,
        calleeAddress: VirtualAddress,
        callSiteAddresses: [VirtualAddress],
        isTailCall: Bool = false,
        isIndirectResolved: Bool = false
    ) {
        self.callerAddress = callerAddress
        self.calleeAddress = calleeAddress
        self.callSiteAddresses = callSiteAddresses
        self.isTailCall = isTailCall
        self.isIndirectResolved = isIndirectResolved
    }
}

public struct CallPathRoute: Sendable, Codable, Hashable, Identifiable {
    public var id: String {
        hopAddresses.map(\.compactHexString).joined(separator: "->")
    }
    public let sourceAddress: VirtualAddress
    public let sinkAddress: VirtualAddress
    public let sinkName: String
    public let sinkCategory: DangerousSinkCategory?
    public let hopAddresses: [VirtualAddress]
    public let hopNames: [String]
    public let callSiteChain: [VirtualAddress]

    public init(
        sourceAddress: VirtualAddress,
        sinkAddress: VirtualAddress,
        sinkName: String,
        sinkCategory: DangerousSinkCategory? = nil,
        hopAddresses: [VirtualAddress],
        hopNames: [String],
        callSiteChain: [VirtualAddress]
    ) {
        self.sourceAddress = sourceAddress
        self.sinkAddress = sinkAddress
        self.sinkName = sinkName
        self.sinkCategory = sinkCategory
        self.hopAddresses = hopAddresses
        self.hopNames = hopNames
        self.callSiteChain = callSiteChain
    }

    public var hopCount: Int {
        max(0, hopAddresses.count - 1)
    }

    public var formattedSummary: String {
        hopNames.joined(separator: " -> ")
    }
}

public struct ProgramCallGraph: Sendable, Codable, Hashable {
    public let nodes: [CallGraphNode]
    public let edges: [CallGraphEdge]

    private let nodeByAddress: [VirtualAddress: CallGraphNode]
    private let outgoingByCaller: [VirtualAddress: [CallGraphEdge]]
    private let incomingByCallee: [VirtualAddress: [CallGraphEdge]]

    public init(nodes: [CallGraphNode], edges: [CallGraphEdge]) {
        let sortedNodes = nodes.sorted { $0.address < $1.address }
        let sortedEdges = edges.sorted {
            if $0.callerAddress != $1.callerAddress { return $0.callerAddress < $1.callerAddress }
            return $0.calleeAddress < $1.calleeAddress
        }
        self.nodes = sortedNodes
        self.edges = sortedEdges

        var nMap: [VirtualAddress: CallGraphNode] = [:]
        for n in sortedNodes { nMap[n.address] = n }
        self.nodeByAddress = nMap

        var outMap: [VirtualAddress: [CallGraphEdge]] = [:]
        var inMap: [VirtualAddress: [CallGraphEdge]] = [:]
        for e in sortedEdges {
            outMap[e.callerAddress, default: []].append(e)
            inMap[e.calleeAddress, default: []].append(e)
        }
        self.outgoingByCaller = outMap
        self.incomingByCallee = inMap
    }

    public func node(at address: VirtualAddress) -> CallGraphNode? {
        nodeByAddress[address]
    }

    /// Returns sorted caller function addresses invoking `functionAddress`.
    public func callers(of functionAddress: VirtualAddress) -> [VirtualAddress] {
        (incomingByCallee[functionAddress] ?? []).map(\.callerAddress)
    }

    /// Returns sorted callee function addresses invoked by `functionAddress`.
    public func callees(of functionAddress: VirtualAddress) -> [VirtualAddress] {
        (outgoingByCaller[functionAddress] ?? []).map(\.calleeAddress)
    }

    public func incomingEdges(to functionAddress: VirtualAddress) -> [CallGraphEdge] {
        incomingByCallee[functionAddress] ?? []
    }

    public func outgoingEdges(from functionAddress: VirtualAddress) -> [CallGraphEdge] {
        outgoingByCaller[functionAddress] ?? []
    }

    /// Computes the shortest unweighted call-chain route from `source` to `target` using Breadth-First Search (BFS).
    public func shortestCallPath(
        from source: VirtualAddress,
        to target: VirtualAddress
    ) -> CallPathRoute? {
        guard nodeByAddress[source] != nil, nodeByAddress[target] != nil else { return nil }
        if source == target {
            let n = nodeByAddress[source]!
            return CallPathRoute(
                sourceAddress: source,
                sinkAddress: target,
                sinkName: n.demangledName,
                sinkCategory: n.sinkCategory,
                hopAddresses: [source],
                hopNames: [n.demangledName],
                callSiteChain: []
            )
        }

        var visited: Set<VirtualAddress> = [source]
        var parentInfo: [VirtualAddress: (caller: VirtualAddress, callSite: VirtualAddress)] = [:]
        var queue: [VirtualAddress] = [source]
        var head = 0

        var found = false
        while head < queue.count {
            let curr = queue[head]
            head += 1

            for edge in outgoingByCaller[curr] ?? [] {
                let next = edge.calleeAddress
                if visited.insert(next).inserted {
                    let firstCallSite = edge.callSiteAddresses.first ?? curr
                    parentInfo[next] = (curr, firstCallSite)
                    if next == target {
                        found = true
                        break
                    }
                    queue.append(next)
                }
            }
            if found { break }
        }

        guard found else { return nil }

        var hopAddrs: [VirtualAddress] = [target]
        var callSites: [VirtualAddress] = []
        var cursor = target
        while cursor != source, let step = parentInfo[cursor] {
            hopAddrs.append(step.caller)
            callSites.append(step.callSite)
            cursor = step.caller
        }
        hopAddrs.reverse()
        callSites.reverse()

        let hopNames = hopAddrs.map { nodeByAddress[$0]?.demangledName ?? $0.compactHexString }
        let sinkNode = nodeByAddress[target]

        return CallPathRoute(
            sourceAddress: source,
            sinkAddress: target,
            sinkName: sinkNode?.demangledName ?? target.compactHexString,
            sinkCategory: sinkNode?.sinkCategory,
            hopAddresses: hopAddrs,
            hopNames: hopNames,
            callSiteChain: callSites
        )
    }

    /// Multi-source BFS discovering shortest call paths from entry points / exported APIs to all reachable dangerous sinks.
    public func discoverDangerousSinkPaths(
        fromRoots explicitRoots: [VirtualAddress]? = nil
    ) -> [CallPathRoute] {
        let sinkNodes = nodes.filter { $0.sinkCategory != nil }
        guard !sinkNodes.isEmpty else { return [] }

        let roots: [VirtualAddress] = {
            if let explicit = explicitRoots, !explicit.isEmpty {
                return explicit.filter { nodeByAddress[$0] != nil }
            }
            let entryAndExported = nodes
                .filter { $0.isEntryOrExported && !$0.isImportedThunk && !$0.isExternalSymbol }
                .map(\.address)
            if !entryAndExported.isEmpty {
                return entryAndExported
            }
            return nodes
                .filter { !$0.isImportedThunk && !$0.isExternalSymbol }
                .map(\.address)
        }()
        guard !roots.isEmpty else { return [] }

        var bestRoutes: [CallPathRoute] = []
        for sink in sinkNodes {
            var bestForSink: CallPathRoute?
            for root in roots where root != sink.address {
                if let candidate = shortestCallPath(from: root, to: sink.address) {
                    if let currentBest = bestForSink {
                        if candidate.hopCount < currentBest.hopCount {
                            bestForSink = candidate
                        }
                    } else {
                        bestForSink = candidate
                    }
                }
            }
            // If no entry/export root reached this sink, check any direct caller as fallback
            if bestForSink == nil {
                for caller in callers(of: sink.address) {
                    if let direct = shortestCallPath(from: caller, to: sink.address) {
                        bestForSink = direct
                        break
                    }
                }
            }
            if let resolved = bestForSink {
                bestRoutes.append(resolved)
            }
        }

        return bestRoutes.sorted {
            if $0.hopCount != $1.hopCount { return $0.hopCount < $1.hopCount }
            return $0.sinkAddress < $1.sinkAddress
        }
    }

    /// Returns all functions reachable via direct or resolved calls starting from `rootAddress`.
    public func reachableFunctions(from rootAddress: VirtualAddress) -> Set<VirtualAddress> {
        guard nodeByAddress[rootAddress] != nil else { return [] }
        var visited: Set<VirtualAddress> = [rootAddress]
        var queue: [VirtualAddress] = [rootAddress]
        var head = 0
        while head < queue.count {
            let cur = queue[head]
            head += 1
            for callee in callees(of: cur) where visited.insert(callee).inserted {
                queue.append(callee)
            }
        }
        return visited
    }

    /// Runs Tarjan's Strongly Connected Components (SCC) algorithm to find recursive / mutually-recursive function groups.
    public func stronglyConnectedRecursiveGroups() -> [[VirtualAddress]] {
        var index = 0
        var indices: [VirtualAddress: Int] = [:]
        var lowlink: [VirtualAddress: Int] = [:]
        var onStack: Set<VirtualAddress> = []
        var stack: [VirtualAddress] = []
        var recursiveSCCs: [[VirtualAddress]] = []

        func strongConnect(_ v: VirtualAddress) {
            indices[v] = index
            lowlink[v] = index
            index += 1
            stack.append(v)
            onStack.insert(v)

            for w in callees(of: v) {
                if indices[w] == nil {
                    strongConnect(w)
                    lowlink[v] = min(lowlink[v]!, lowlink[w]!)
                } else if onStack.contains(w) {
                    lowlink[v] = min(lowlink[v]!, indices[w]!)
                }
            }

            if lowlink[v] == indices[v] {
                var component: [VirtualAddress] = []
                while let w = stack.popLast() {
                    onStack.remove(w)
                    component.append(w)
                    if w == v { break }
                }
                if component.count > 1 {
                    recursiveSCCs.append(component.sorted())
                } else if let sole = component.first, callees(of: sole).contains(sole) {
                    recursiveSCCs.append([sole])
                }
            }
        }

        for n in nodes where indices[n.address] == nil {
            strongConnect(n.address)
        }
        return recursiveSCCs
    }
}

// MARK: - Graphviz DOT & Mermaid CFG / Call-Graph Exporters

public enum GraphExportFormatter: Sendable {

    /// Formats a `RecoveredFunction`'s Control Flow Graph as a publication-grade Graphviz `DOT` digraph.
    public static func exportFunctionCFGDOT(
        _ function: RecoveredFunction,
        includeInstructions: Bool = true
    ) -> String {
        var lines: [String] = []
        let safeGraphID = sanitizeIdentifier(function.name)
        lines.append("digraph CFG_\(safeGraphID) {")
        lines.append("    rankdir=TB;")
        lines.append("    graph [fontname=\"Menlo\", fontsize=11, pad=\"0.4\", nodesep=\"0.55\", ranksep=\"0.75\", bgcolor=\"#0d1117\"];")
        lines.append("    node [shape=box, style=\"filled,rounded\", fontname=\"Menlo\", fontsize=10, color=\"#30363d\", fillcolor=\"#161b22\", fontcolor=\"#e6edf3\"];")
        lines.append("    edge [fontname=\"Menlo\", fontsize=9, penwidth=1.4];")
        lines.append("")

        for block in function.blocks {
            let borderColor: String
            if block.isEntry {
                borderColor = "#3fb950"
            } else if block.isExit {
                borderColor = "#f85149"
            } else if block.loopDepth > 0 {
                borderColor = "#d29922"
            } else {
                borderColor = "#30363d"
            }

            var bodyLines: [String] = []
            let loopBadge = block.loopDepth > 0 ? " [loop d=\(block.loopDepth)]" : ""
            bodyLines.append("\(escapeDOT(block.label))\(loopBadge)")

            if includeInstructions {
                for insn in block.instructions {
                    let text = "\(insn.address.compactHexString): \(insn.formattedDisassembly)"
                    bodyLines.append(escapeDOT(text))
                }
            } else {
                bodyLines.append("\(block.instructions.count) insns (\(block.startAddress.compactHexString)..\(block.endAddress.compactHexString))")
            }

            // Left-aligned `\l` newline separator in Graphviz
            let joinedLabel = bodyLines.joined(separator: "\\l") + "\\l"
            lines.append("    bb\(block.id) [label=\"\(joinedLabel)\", color=\"\(borderColor)\"];")
        }

        lines.append("")
        for edge in function.edges {
            let color: String
            switch edge.kind {
            case .conditionalTrue: color = "#3fb950"
            case .conditionalFalse: color = "#f85149"
            case .switchCase: color = "#58a6ff"
            case .unconditional, .fallthroughEdge:
                color = edge.isBackEdge ? "#d29922" : "#8b949e"
            }
            let styleAttr = edge.isBackEdge ? ", style=\"dashed\"" : ""
            if let lbl = edge.kind.displayLabel {
                lines.append("    bb\(edge.sourceBlockID) -> bb\(edge.targetBlockID) [label=\"\(escapeDOT(lbl))\", color=\"\(color)\", fontcolor=\"\(color)\"\(styleAttr)];")
            } else {
                lines.append("    bb\(edge.sourceBlockID) -> bb\(edge.targetBlockID) [color=\"\(color)\"\(styleAttr)];")
            }
        }

        lines.append("}")
        return lines.joined(separator: "\n")
    }

    /// Formats a `RecoveredFunction`'s Control Flow Graph as a GitHub-compatible Mermaid `flowchart TD` diagram.
    public static func exportFunctionCFGMermaid(
        _ function: RecoveredFunction,
        includeInstructions: Bool = true
    ) -> String {
        var lines: [String] = []
        lines.append("flowchart TD")

        for block in function.blocks {
            var rowTexts: [String] = []
            let loopBadge = block.loopDepth > 0 ? " (loop \(block.loopDepth))" : ""
            rowTexts.append("\(block.label)\(loopBadge)")

            if includeInstructions {
                for insn in block.instructions {
                    rowTexts.append("\(insn.address.compactHexString): \(insn.formattedDisassembly)")
                }
            } else {
                rowTexts.append("\(block.instructions.count) instructions")
            }

            let escapedBody = rowTexts.map(escapeMermaid).joined(separator: "\\n")
            lines.append("    BB\(block.id)[\"\(escapedBody)\"]")
        }

        for edge in function.edges {
            let arrow = edge.isBackEdge ? "-.->" : "-->"
            if let lbl = edge.kind.displayLabel {
                let arrowWithLabel = edge.isBackEdge
                    ? "-. \"\(escapeMermaid(lbl))\" .->"
                    : "-- \"\(escapeMermaid(lbl))\" -->"
                lines.append("    BB\(edge.sourceBlockID) \(arrowWithLabel) BB\(edge.targetBlockID)")
            } else {
                lines.append("    BB\(edge.sourceBlockID) \(arrow) BB\(edge.targetBlockID)")
            }
        }

        return lines.joined(separator: "\n")
    }

    /// Formats the whole-program `ProgramCallGraph` as a Graphviz `DOT` digraph.
    public static func exportCallGraphDOT(_ callGraph: ProgramCallGraph) -> String {
        var lines: [String] = []
        lines.append("digraph CallGraph {")
        lines.append("    rankdir=LR;")
        lines.append("    node [shape=box, style=\"filled,rounded\", fontname=\"Menlo\", fontsize=10, fillcolor=\"#161b22\", fontcolor=\"#e6edf3\", color=\"#30363d\"];")
        lines.append("    edge [fontname=\"Menlo\", fontsize=9, color=\"#8b949e\"];")

        for node in callGraph.nodes {
            let nodeID = "fn_\(String(node.address.rawValue, radix: 16))"
            let border: String
            if node.sinkCategory != nil {
                border = "#f85149"
            } else if node.isEntryOrExported {
                border = "#3fb950"
            } else if node.isImportedThunk || node.isExternalSymbol {
                border = "#58a6ff"
            } else {
                border = "#30363d"
            }
            let label = "\(escapeDOT(node.demangledName))\\n\(node.address.compactHexString)"
            lines.append("    \(nodeID) [label=\"\(label)\", color=\"\(border)\"];")
        }

        for edge in callGraph.edges {
            let u = "fn_\(String(edge.callerAddress.rawValue, radix: 16))"
            let v = "fn_\(String(edge.calleeAddress.rawValue, radix: 16))"
            let style = edge.isTailCall ? " [style=\"dashed\", label=\"tail\"]" : ""
            lines.append("    \(u) -> \(v)\(style);")
        }

        lines.append("}")
        return lines.joined(separator: "\n")
    }

    /// Formats the whole-program `ProgramCallGraph` as a Mermaid `flowchart LR` diagram.
    public static func exportCallGraphMermaid(_ callGraph: ProgramCallGraph) -> String {
        var lines: [String] = ["flowchart LR"]
        for node in callGraph.nodes {
            let nodeID = "FN_\(String(node.address.rawValue, radix: 16))"
            lines.append("    \(nodeID)[\"\(escapeMermaid(node.demangledName)) (\(node.address.compactHexString))\"]")
        }
        for edge in callGraph.edges {
            let u = "FN_\(String(edge.callerAddress.rawValue, radix: 16))"
            let v = "FN_\(String(edge.calleeAddress.rawValue, radix: 16))"
            let arrow = edge.isTailCall ? "-. tail .->" : "-->"
            lines.append("    \(u) \(arrow) \(v)")
        }
        return lines.joined(separator: "\n")
    }

    private static func sanitizeIdentifier(_ text: String) -> String {
        let mapped = text.unicodeScalars.map { s -> Character in
            if CharacterSet.alphanumerics.contains(s) || s == "_" {
                return Character(s)
            }
            return "_"
        }
        let s = String(mapped)
        return s.isEmpty ? "func" : s
    }

    private static func escapeDOT(_ text: String) -> String {
        text
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
    }

    private static func escapeMermaid(_ text: String) -> String {
        text
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "'")
            .replacingOccurrences(of: "\n", with: " ")
    }
}

// MARK: - Whole-Binary Analysis Options & Aggregate Index

public struct BinaryAnalysisOptions: Sendable, Codable, Hashable {
    public var discoveryConfiguration: FunctionDiscoveryConfiguration
    public var cfgConfiguration: CFGBuilderConfiguration
    public var layoutConfiguration: SugiyamaLayoutConfiguration
    public var computeSugiyamaLayouts: Bool
    public var computePostDominatorTrees: Bool

    public init(
        discoveryConfiguration: FunctionDiscoveryConfiguration = .standard,
        cfgConfiguration: CFGBuilderConfiguration = .standard,
        layoutConfiguration: SugiyamaLayoutConfiguration = .standard,
        computeSugiyamaLayouts: Bool = true,
        computePostDominatorTrees: Bool = true
    ) {
        self.discoveryConfiguration = discoveryConfiguration
        self.cfgConfiguration = cfgConfiguration
        self.layoutConfiguration = layoutConfiguration
        self.computeSugiyamaLayouts = computeSugiyamaLayouts
        self.computePostDominatorTrees = computePostDominatorTrees
    }

    public static let standard = BinaryAnalysisOptions()
}

public struct BinaryAnalysisIndex: Sendable, Codable, Hashable {
    public let image: LoadedBinaryImage
    public let functions: [RecoveredFunction]
    public let decodedInstructions: [A64DecodedInstruction]
    public let crossReferences: CrossReferenceIndex
    public let callGraph: ProgramCallGraph
    public let dangerousSinkPaths: [CallPathRoute]
    public let recognizedIdioms: [A64RecognizedIdiom]
    public let postDominatorTrees: [VirtualAddress: [PostDominatorTreeNode]]
    public let structuredRegionsByFunction: [VirtualAddress: [StructuredControlRegion]]
    public let analysisDurationMilliseconds: Double

    private let functionIndexByAddress: [VirtualAddress: Int]
    private let instructionIndexByAddress: [VirtualAddress: Int]

    public init(
        image: LoadedBinaryImage,
        functions: [RecoveredFunction],
        decodedInstructions: [A64DecodedInstruction],
        crossReferences: CrossReferenceIndex,
        callGraph: ProgramCallGraph,
        dangerousSinkPaths: [CallPathRoute],
        recognizedIdioms: [A64RecognizedIdiom] = [],
        postDominatorTrees: [VirtualAddress: [PostDominatorTreeNode]] = [:],
        structuredRegionsByFunction: [VirtualAddress: [StructuredControlRegion]] = [:],
        analysisDurationMilliseconds: Double = 0.0
    ) {
        let sortedFns = functions.sorted { $0.address < $1.address }
        let sortedInsns = decodedInstructions.sorted { $0.address < $1.address }

        self.image = image
        self.functions = sortedFns
        self.decodedInstructions = sortedInsns
        self.crossReferences = crossReferences
        self.callGraph = callGraph
        self.dangerousSinkPaths = dangerousSinkPaths
        self.recognizedIdioms = recognizedIdioms
        self.postDominatorTrees = postDominatorTrees
        self.structuredRegionsByFunction = structuredRegionsByFunction
        self.analysisDurationMilliseconds = analysisDurationMilliseconds

        var fMap: [VirtualAddress: Int] = [:]
        fMap.reserveCapacity(sortedFns.count)
        for (idx, fn) in sortedFns.enumerated() {
            fMap[fn.address] = idx
        }
        self.functionIndexByAddress = fMap

        var iMap: [VirtualAddress: Int] = [:]
        iMap.reserveCapacity(sortedInsns.count)
        for (idx, insn) in sortedInsns.enumerated() {
            if iMap[insn.address] == nil {
                iMap[insn.address] = idx
            }
        }
        self.instructionIndexByAddress = iMap
    }

    // MARK: - High-Speed Query Convenience Methods

    public var xrefs: [XrefRecord] { crossReferences.allRecords }
    public var stringXrefs: [XrefRecord] { crossReferences.stringXrefs }
    public var importCallSites: [ImportCallSiteRecord] { crossReferences.importCallSites }

    /// Exact O(1) lookup for a `RecoveredFunction` by its entry `VirtualAddress`.
    public func function(at entryAddress: VirtualAddress) -> RecoveredFunction? {
        guard let idx = functionIndexByAddress[entryAddress] else { return nil }
        return functions[idx]
    }

    /// Binary-search lookup returning the `RecoveredFunction` whose `[address, endAddress)` contains `vmAddress`.
    public func function(containing vmAddress: VirtualAddress) -> RecoveredFunction? {
        guard !functions.isEmpty else { return nil }
        var lo = 0
        var hi = functions.count - 1
        var candidateIdx: Int?
        while lo <= hi {
            let mid = (lo + hi) >> 1
            if functions[mid].address <= vmAddress {
                candidateIdx = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        guard let idx = candidateIdx else { return nil }
        let fn = functions[idx]
        return (vmAddress >= fn.address && vmAddress < fn.endAddress) ? fn : nil
    }

    /// Lookup by exact or substring raw/demangled function name.
    public func function(named query: String) -> RecoveredFunction? {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let exact = functions.first(where: { $0.name == trimmed || $0.demangledName == trimmed }) {
            return exact
        }
        let stripped = trimmed.hasPrefix("_") ? String(trimmed.dropFirst()) : "_\(trimmed)"
        if let match = functions.first(where: { $0.name == stripped || $0.demangledName == stripped }) {
            return match
        }
        return functions.first {
            $0.name.localizedCaseInsensitiveContains(trimmed) ||
            $0.demangledName.localizedCaseInsensitiveContains(trimmed)
        }
    }

    /// O(1) decoded instruction lookup at `address`.
    public func instruction(at address: VirtualAddress) -> A64DecodedInstruction? {
        guard let idx = instructionIndexByAddress[address] else { return nil }
        return decodedInstructions[idx]
    }

    public func xrefsTo(address: VirtualAddress) -> [XrefRecord] {
        crossReferences.xrefsTo(address: address)
    }

    public func xrefsFrom(address: VirtualAddress) -> [XrefRecord] {
        crossReferences.xrefsFrom(address: address)
    }

    public func callers(of functionAddress: VirtualAddress) -> [RecoveredFunction] {
        callGraph.callers(of: functionAddress).compactMap { function(at: $0) }
    }

    public func callees(of functionAddress: VirtualAddress) -> [RecoveredFunction] {
        callGraph.callees(of: functionAddress).compactMap { function(at: $0) }
    }

    public func shortestCallPath(from source: VirtualAddress, to target: VirtualAddress) -> CallPathRoute? {
        callGraph.shortestCallPath(from: source, to: target)
    }

    public func exportCFGDOT(for function: RecoveredFunction, includeInstructions: Bool = true) -> String {
        GraphExportFormatter.exportFunctionCFGDOT(function, includeInstructions: includeInstructions)
    }

    public func exportCFGMermaid(for function: RecoveredFunction, includeInstructions: Bool = true) -> String {
        GraphExportFormatter.exportFunctionCFGMermaid(function, includeInstructions: includeInstructions)
    }

    public func exportCallGraphDOT() -> String {
        GraphExportFormatter.exportCallGraphDOT(callGraph)
    }

    public func exportCallGraphMermaid() -> String {
        GraphExportFormatter.exportCallGraphMermaid(callGraph)
    }
}

// MARK: - Thread-Safe In-Memory Binary Byte Cache (Supports 1-Arg `analyzeBinary(image)`)

private final class LockedBinaryByteRegistry: @unchecked Sendable {
    static let shared = LockedBinaryByteRegistry()

    private let lock = NSLock()
    private var storageBySHA256: [String: Data] = [:]
    private var didPopulateBuiltInFixtures = false

    func register(data: Data, sha256Hex: String? = nil) {
        let digest = (sha256Hex ?? BinaryHashAndEntropy.sha256Hex(of: data)).lowercased()
        lock.lock()
        storageBySHA256[digest] = data
        lock.unlock()
    }

    func lookup(sha256Hex: String) -> Data? {
        let key = sha256Hex.lowercased()
        lock.lock()
        if let hit = storageBySHA256[key] {
            lock.unlock()
            return hit
        }
        let alreadyPopulated = didPopulateBuiltInFixtures
        lock.unlock()

        guard !alreadyPopulated else { return nil }

        // Lazily materialize built-in synthetic test/demo fixtures once if an in-memory `LoadedBinaryImage`
        // was passed to `analyzeBinary(_ image:)` without explicit `data` or disk backing!
        let builtIns: [Data] = [
            SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false, includeCMSCertificates: false),
            SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true, includeCMSCertificates: false),
            SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false, includeCMSCertificates: true),
            SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true, includeCMSCertificates: true),
            SyntheticBinaryFixtureBuilder.buildUniversalFatBinary(),
            SyntheticBinaryFixtureBuilder.buildUniversalFat64Binary(),
            SyntheticBinaryFixtureBuilder.buildLegacyDyldInfoMachOBinary(),
            SyntheticBinaryFixtureBuilder.buildELF64Binary(),
            SyntheticBinaryFixtureBuilder.buildPE32PlusARM64Binary(),
            SyntheticBinaryFixtureBuilder.buildWasmBinary()
        ]

        lock.lock()
        if !didPopulateBuiltInFixtures {
            for blob in builtIns {
                let h = BinaryHashAndEntropy.sha256Hex(of: blob).lowercased()
                if storageBySHA256[h] == nil {
                    storageBySHA256[h] = blob
                }
            }
            didPopulateBuiltInFixtures = true
        }
        let resolved = storageBySHA256[key]
        lock.unlock()
        return resolved
    }
}

// MARK: - Whole-Binary Analysis Coordinator

public struct BinaryAnalysisCoordinator: Sendable {
    public let options: BinaryAnalysisOptions
    private let demangler: SymbolDemangler

    public init(options: BinaryAnalysisOptions = .standard) {
        self.options = options
        self.demangler = SymbolDemangler()
    }

    /// Registers an in-memory binary buffer so subsequent single-argument `analyzeBinary(image)` calls
    /// can resolve raw section and jump-table bytes by SHA-256 without disk I/O.
    public static func registerInMemoryBinaryData(_ data: Data, sha256Hex: String? = nil) {
        LockedBinaryByteRegistry.shared.register(data: data, sha256Hex: sha256Hex)
    }

    // MARK: - Primary Whole-Binary Pipeline Entry Points

    /// Convenience loader + analyzer from raw `Data`.
    public func analyzeBinary(
        data: Data,
        filePath: String = "<in-memory>",
        fileName: String? = nil,
        preferredSliceIndex: Int? = nil,
        options explicitOptions: BinaryAnalysisOptions? = nil
    ) throws -> BinaryAnalysisIndex {
        let image = try UniversalBinaryDispatcher.load(
            data: data,
            filePath: filePath,
            fileName: fileName,
            preferredSliceIndex: preferredSliceIndex
        )
        Self.registerInMemoryBinaryData(data, sha256Hex: image.sha256Hex)
        return analyzeBinary(image, data: data, options: explicitOptions)
    }

    /// Convenience loader + analyzer from disk `URL`.
    public func analyzeBinary(
        fileURL: URL,
        preferredSliceIndex: Int? = nil,
        options explicitOptions: BinaryAnalysisOptions? = nil
    ) throws -> BinaryAnalysisIndex {
        let path = fileURL.path
        guard FileManager.default.fileExists(atPath: path) else {
            throw MachGraphError.fileNotFound(path)
        }
        let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        let image = try UniversalBinaryDispatcher.load(
            data: data,
            filePath: path,
            fileName: fileURL.lastPathComponent,
            preferredSliceIndex: preferredSliceIndex
        )
        return analyzeBinary(image, data: data, options: explicitOptions)
    }

    /// Explicit `rawData:` label alias for callers passing `(image, rawData: bytes)`.
    public func analyzeBinary(
        _ image: LoadedBinaryImage,
        rawData: Data,
        options explicitOptions: BinaryAnalysisOptions? = nil
    ) -> BinaryAnalysisIndex {
        analyzeBinary(image, data: rawData, options: explicitOptions)
    }

    /// Executes the end-to-end static binary analysis pipeline on `image`:
    ///   1. Executable section disassembly + multi-instruction idiom & constant propagation,
    ///   2. Multi-source function boundary & switch jump-table recovery,
    ///   3. Basic-block leader partitioning + CFG edge construction,
    ///   4. Lengauer-Tarjan $O(E \alpha(V))$ dominators + Cooper-Harvey-Kennedy DF + `ipdom` + natural loops,
    ///   5. 5-phase Sugiyama hierarchical CFG layout solving,
    ///   6. Bidirectional cross-reference (`XrefRecord`) indexing + whole-program Call Graph + dangerous sink BFS.
    public func analyzeBinary(
        _ image: LoadedBinaryImage,
        data: Data? = nil,
        options explicitOptions: BinaryAnalysisOptions? = nil
    ) -> BinaryAnalysisIndex {
        let startTime = CFAbsoluteTimeGetCurrent()
        let activeOptions = explicitOptions ?? self.options
        let binaryBytes = resolveBackingBytes(for: image, explicitData: data)

        let discoveryEngine = FunctionDiscoveryEngine(configuration: activeOptions.discoveryConfiguration)
        let cfgEngine = CFGBuilderEngine(configuration: activeOptions.cfgConfiguration)
        let domAnalyzer = DominatorAndLoopAnalyzer()
        let layoutSolver = SugiyamaCFGLayoutSolver(configuration: activeOptions.layoutConfiguration)

        // 1. Decode all executable sections
        let decodedSections = discoveryEngine.decodeExecutableSections(
            in: image,
            data: binaryBytes
        )

        var allInstructions: [A64DecodedInstruction] = []
        var allIdioms: [A64RecognizedIdiom] = []
        for ds in decodedSections {
            allInstructions.append(contentsOf: ds.instructions)
            allIdioms.append(contentsOf: ds.recognizedIdioms)
        }
        allInstructions.sort { $0.address < $1.address }

        // 2. Discover function boundaries across all executable sections
        let boundaries = discoveryEngine.discoverFunctions(
            in: image,
            decodedSections: decodedSections,
            data: binaryBytes
        )

        // 3. Per-function Jump Table Recovery -> Basic Block CFG -> Lengauer-Tarjan Dominators & Loops -> Sugiyama Layout
        let defaultStride: UInt64 = image.architecture.isARM64Family ? 4 : 1
        var recoveredFunctions: [RecoveredFunction] = []
        recoveredFunctions.reserveCapacity(boundaries.count)

        var postDomByFunction: [VirtualAddress: [PostDominatorTreeNode]] = [:]
        var structuredRegionsByFunction: [VirtualAddress: [StructuredControlRegion]] = [:]
        var jumpTableDescriptorsByFunction: [VirtualAddress: [SwitchJumpTableDescriptor]] = [:]
        var tailTargetsByFunction: [VirtualAddress: [VirtualAddress]] = [:]

        for boundary in boundaries {
            let fnInsns = discoveryEngine.sliceInstructions(
                in: allInstructions,
                from: boundary.startAddress,
                to: boundary.endAddress
            )

            let jtDescriptors = discoveryEngine.recoverJumpTableDescriptors(
                in: fnInsns,
                functionStart: boundary.startAddress,
                functionEnd: boundary.endAddress,
                image: image,
                data: binaryBytes
            )
            let jumpTables = jtDescriptors.map(\.jumpTable)
            if !jtDescriptors.isEmpty {
                jumpTableDescriptorsByFunction[boundary.startAddress] = jtDescriptors
            }

            let builtCFG = cfgEngine.buildCFG(
                boundary: boundary,
                instructions: fnInsns,
                jumpTables: jumpTables,
                jumpTableDescriptors: jtDescriptors,
                defaultInstructionByteStride: defaultStride
            )

            if !builtCFG.tailCallTargets.isEmpty {
                tailTargetsByFunction[boundary.startAddress] = builtCFG.tailCallTargets
            }

            let domResult = domAnalyzer.analyze(
                blocks: builtCFG.blocks,
                edges: builtCFG.edges,
                entryBlockID: builtCFG.blocks.first(where: \.isEntry)?.id
            )

            if activeOptions.computePostDominatorTrees {
                postDomByFunction[boundary.startAddress] = domResult.postDominatorTree
                structuredRegionsByFunction[boundary.startAddress] = domResult.structuredRegions
            }

            let cfgLayout: SugiyamaCFGLayout? = activeOptions.computeSugiyamaLayouts
                ? layoutSolver.solveLayout(
                    functionAddress: boundary.startAddress,
                    blocks: domResult.annotatedBlocks,
                    edges: domResult.annotatedEdges
                )
                : nil

            let recovered = RecoveredFunction(
                address: builtCFG.functionAddress,
                endAddress: builtCFG.endAddress,
                name: builtCFG.name,
                demangledName: builtCFG.demangledName,
                isLeaf: builtCFG.isLeaf,
                isThunk: builtCFG.isThunk,
                usesPAC: builtCFG.usesPAC,
                stackFrameBytes: builtCFG.stackFrameBytes,
                blocks: domResult.annotatedBlocks,
                edges: domResult.annotatedEdges,
                dominatorTree: domResult.dominatorTree,
                naturalLoops: domResult.naturalLoops,
                jumpTables: builtCFG.jumpTables,
                cyclomaticComplexity: builtCFG.cyclomaticComplexity,
                layout: cfgLayout
            )
            recoveredFunctions.append(recovered)
        }

        // 4. Build Bidirectional Cross-Reference Database (`CrossReferenceIndex`) + `ImportCallSiteRecord`s
        let (xrefIndex, resolvedIndirectTargetsByInsn) = buildCrossReferenceDatabase(
            image: image,
            boundaries: boundaries,
            functions: recoveredFunctions,
            allIdioms: allIdioms,
            jumpTableDescriptorsByFunction: jumpTableDescriptorsByFunction
        )

        // 5. Build Whole-Program Call Graph + Shortest Dangerous Sink Paths
        let callGraph = buildProgramCallGraph(
            image: image,
            boundaries: boundaries,
            functions: recoveredFunctions,
            tailTargetsByFunction: tailTargetsByFunction,
            resolvedIndirectTargetsByInsn: resolvedIndirectTargetsByInsn,
            importCallSites: xrefIndex.importCallSites
        )

        let dangerousPaths = callGraph.discoverDangerousSinkPaths()
        let elapsedMs = max(0.0, (CFAbsoluteTimeGetCurrent() - startTime) * 1000.0)

        return BinaryAnalysisIndex(
            image: image,
            functions: recoveredFunctions,
            decodedInstructions: allInstructions,
            crossReferences: xrefIndex,
            callGraph: callGraph,
            dangerousSinkPaths: dangerousPaths,
            recognizedIdioms: allIdioms,
            postDominatorTrees: postDomByFunction,
            structuredRegionsByFunction: structuredRegionsByFunction,
            analysisDurationMilliseconds: elapsedMs
        )
    }

    /// Standalone single-function CFG + Dominator + Loop + Sugiyama analyzer (useful after inline patching!).
    public func analyzeSingleFunction(
        at address: VirtualAddress,
        name: String,
        demangledName: String? = nil,
        instructions: [A64DecodedInstruction],
        image: LoadedBinaryImage? = nil,
        data: Data? = nil
    ) -> RecoveredFunction {
        let sorted = instructions.sorted { $0.address < $1.address }
        let endAddr = sorted.last.map { $0.address.adding(UInt64(4)) } ?? address.adding(UInt64(4))

        let discoveryEngine = FunctionDiscoveryEngine(configuration: options.discoveryConfiguration)
        let jtDescriptors: [SwitchJumpTableDescriptor]
        if let image {
            let resolvedBytes = resolveBackingBytes(for: image, explicitData: data)
            jtDescriptors = discoveryEngine.recoverJumpTableDescriptors(
                in: sorted,
                functionStart: address,
                functionEnd: endAddr,
                image: image,
                data: resolvedBytes
            )
        } else {
            jtDescriptors = []
        }

        let cfgEngine = CFGBuilderEngine(configuration: options.cfgConfiguration)
        let built = cfgEngine.buildCFG(
            functionAddress: address,
            endAddress: endAddr,
            name: name,
            demangledName: demangledName ?? demangler.demangle(name),
            instructions: sorted,
            jumpTables: jtDescriptors.map(\.jumpTable),
            jumpTableDescriptors: jtDescriptors
        )

        let domResult = DominatorAndLoopAnalyzer().analyze(
            blocks: built.blocks,
            edges: built.edges,
            entryBlockID: built.blocks.first(where: \.isEntry)?.id
        )

        let layout = options.computeSugiyamaLayouts
            ? SugiyamaCFGLayoutSolver(configuration: options.layoutConfiguration).solveLayout(
                functionAddress: address,
                blocks: domResult.annotatedBlocks,
                edges: domResult.annotatedEdges
            )
            : nil

        return RecoveredFunction(
            address: built.functionAddress,
            endAddress: built.endAddress,
            name: built.name,
            demangledName: built.demangledName,
            isLeaf: built.isLeaf,
            isThunk: built.isThunk,
            usesPAC: built.usesPAC,
            stackFrameBytes: built.stackFrameBytes,
            blocks: domResult.annotatedBlocks,
            edges: domResult.annotatedEdges,
            dominatorTree: domResult.dominatorTree,
            naturalLoops: domResult.naturalLoops,
            jumpTables: built.jumpTables,
            cyclomaticComplexity: built.cyclomaticComplexity,
            layout: layout
        )
    }

    // MARK: - Internal Cross-Reference Extraction Engine

    private struct ResolvedImportDescriptor {
        let symbolName: String
        let demangledName: String
        let libraryName: String?
        let targetAddress: VirtualAddress
    }

    private func buildCrossReferenceDatabase(
        image: LoadedBinaryImage,
        boundaries: [DiscoveredFunctionBoundary],
        functions: [RecoveredFunction],
        allIdioms: [A64RecognizedIdiom],
        jumpTableDescriptorsByFunction: [VirtualAddress: [SwitchJumpTableDescriptor]]
    ) -> (index: CrossReferenceIndex, resolvedIndirectCalls: [VirtualAddress: VirtualAddress]) {
        var libraryByOrdinal: [Int: String] = [:]
        for lib in image.importedLibraries {
            libraryByOrdinal[lib.ordinal] = lib.shortName
        }

        // Map GOT slots & import stubs -> `ResolvedImportDescriptor`
        var importByAddress: [VirtualAddress: ResolvedImportDescriptor] = [:]

        for fixup in image.chainedFixups {
            if let sym = fixup.symbolName, !sym.isEmpty {
                let libName = fixup.libraryOrdinal.flatMap { libraryByOrdinal[$0] }
                importByAddress[fixup.location] = ResolvedImportDescriptor(
                    symbolName: sym,
                    demangledName: demangler.demangle(sym),
                    libraryName: libName,
                    targetAddress: fixup.location
                )
            }
        }

        for sym in image.symbols where sym.kind == .importedStub {
            let libName = sym.libraryOrdinal.flatMap { libraryByOrdinal[$0] }
            importByAddress[sym.address] = ResolvedImportDescriptor(
                symbolName: sym.name,
                demangledName: sym.demangledName,
                libraryName: libName,
                targetAddress: sym.address
            )
        }

        // Propagate GOT bindings onto Mach-O `__stubs` / `.plt` functions
        var boundaryByStart: [VirtualAddress: DiscoveredFunctionBoundary] = [:]
        for b in boundaries {
            boundaryByStart[b.startAddress] = b
            if let gotSym = b.resolvedGOTTargetSymbol {
                // Find library from matching fixup if available
                let matchedFixup = image.chainedFixups.first { $0.symbolName == gotSym }
                let libName = matchedFixup?.libraryOrdinal.flatMap { libraryByOrdinal[$0] }
                importByAddress[b.startAddress] = ResolvedImportDescriptor(
                    symbolName: gotSym,
                    demangledName: demangler.demangle(gotSym),
                    libraryName: libName,
                    targetAddress: b.startAddress
                )
            }
        }

        // Prepare sorted string ranges & cstring section ranges for fast `.stringReference` matching
        let sortedStrings = image.strings.sorted { $0.address < $1.address }
        let cstringRanges = image.sections
            .filter { $0.kind == .cstring }
            .map(\.addressRange)

        func resolveCanonicalStringAddress(_ addr: VirtualAddress) -> VirtualAddress? {
            if !sortedStrings.isEmpty {
                var lo = 0
                var hi = sortedStrings.count - 1
                var bestIdx: Int?
                while lo <= hi {
                    let mid = (lo + hi) >> 1
                    if sortedStrings[mid].address <= addr {
                        bestIdx = mid
                        lo = mid + 1
                    } else {
                        hi = mid - 1
                    }
                }
                if let idx = bestIdx {
                    let s = sortedStrings[idx]
                    let span = UInt64(max(1, s.lengthBytes))
                    if addr >= s.address && addr < s.address.adding(span) {
                        return s.address
                    }
                }
            }
            if cstringRanges.contains(where: { $0.contains(addr) }) {
                return addr
            }
            return nil
        }

        // Index multi-instruction idioms by completing instruction address
        var idiomsByCompletingAddress: [VirtualAddress: [A64RecognizedIdiom]] = [:]
        var pairedADRPAddresses = Set<VirtualAddress>()
        for idiom in allIdioms {
            idiomsByCompletingAddress[idiom.completingAddress, default: []].append(idiom)
            if idiom.instructionAddresses.count >= 2 {
                pairedADRPAddresses.insert(idiom.instructionAddresses[0])
            }
        }

        // Dedup key so each `(fromAddress, toAddress, kind)` is emitted once
        struct XrefDedupKey: Hashable {
            let from: VirtualAddress
            let to: VirtualAddress
            let kind: XrefKind
        }
        var seenXrefKeys = Set<XrefDedupKey>()
        var records: [XrefRecord] = []
        var importCallSites: [ImportCallSiteRecord] = []
        var seenImportSiteAddrs = Set<VirtualAddress>()
        var resolvedIndirectCalls: [VirtualAddress: VirtualAddress] = [:]

        func emitXref(
            from: VirtualAddress,
            fromFn: VirtualAddress?,
            to: VirtualAddress,
            kind: XrefKind,
            preview: String
        ) {
            let key = XrefDedupKey(from: from, to: to, kind: kind)
            guard seenXrefKeys.insert(key).inserted else { return }
            records.append(
                XrefRecord(
                    fromAddress: from,
                    fromFunction: fromFn,
                    toAddress: to,
                    kind: kind,
                    instructionPreview: preview
                )
            )
        }

        for fn in functions {
            let fnAddr = fn.address
            let fnBoundary = boundaryByStart[fnAddr]
            let isStubFn = fnBoundary?.isStubSection ?? fn.isThunk

            // Track latest register loaded from GOT inside each basic block to resolve `blr x16`
            for block in fn.blocks {
                var recentLoadedAddressByReg: [UInt8: VirtualAddress] = [:]

                for insn in block.instructions {
                    let preview = insn.formattedDisassembly

                    // 1. Multi-instruction idioms completing at `insn.address`
                    if let completedIdioms = idiomsByCompletingAddress[insn.address] {
                        for idiom in completedIdioms {
                            if let dstReg = idiom.destinationRegister, let tgt = idiom.targetAddress {
                                recentLoadedAddressByReg[dstReg.index] = tgt
                            }
                            guard let tgt = idiom.targetAddress else { continue }

                            if let strAddr = resolveCanonicalStringAddress(tgt) {
                                emitXref(from: insn.address, fromFn: fnAddr, to: strAddr, kind: .stringReference, preview: preview)
                            } else if let xKind = idiom.xrefKind {
                                emitXref(from: insn.address, fromFn: fnAddr, to: tgt, kind: xKind, preview: preview)
                            }
                        }
                    }

                    // 2. Instruction-level control-flow & PC-relative operands
                    switch insn.flow {
                    case .directCall(let target):
                        emitXref(from: insn.address, fromFn: fnAddr, to: target, kind: .directCall, preview: preview)
                        if let imp = importByAddress[target], seenImportSiteAddrs.insert(insn.address).inserted {
                            importCallSites.append(
                                ImportCallSiteRecord(
                                    callInstructionAddress: insn.address,
                                    callerFunctionAddress: fnAddr,
                                    callerFunctionName: fn.demangledName,
                                    stubOrGOTAddress: target,
                                    importedSymbolName: imp.symbolName,
                                    demangledSymbolName: imp.demangledName,
                                    libraryName: imp.libraryName,
                                    isTailCall: false
                                )
                            )
                        }

                    case .unconditionalJump(let target):
                        emitXref(from: insn.address, fromFn: fnAddr, to: target, kind: .unconditionalJump, preview: preview)
                        let isExternalTail = (target < fn.address || target >= fn.endAddress)
                        if isExternalTail, let imp = importByAddress[target], !isStubFn,
                           seenImportSiteAddrs.insert(insn.address).inserted {
                            importCallSites.append(
                                ImportCallSiteRecord(
                                    callInstructionAddress: insn.address,
                                    callerFunctionAddress: fnAddr,
                                    callerFunctionName: fn.demangledName,
                                    stubOrGOTAddress: target,
                                    importedSymbolName: imp.symbolName,
                                    demangledSymbolName: imp.demangledName,
                                    libraryName: imp.libraryName,
                                    isTailCall: true
                                )
                            )
                        }

                    case .conditionalBranch(let target, _):
                        emitXref(from: insn.address, fromFn: fnAddr, to: target, kind: .conditionalBranch, preview: preview)

                    case .indirectCall(let reg):
                        if let resolvedGOT = recentLoadedAddressByReg[reg.index] {
                            emitXref(from: insn.address, fromFn: fnAddr, to: resolvedGOT, kind: .indirectCall, preview: preview)
                            resolvedIndirectCalls[insn.address] = resolvedGOT
                            if let imp = importByAddress[resolvedGOT], seenImportSiteAddrs.insert(insn.address).inserted {
                                importCallSites.append(
                                    ImportCallSiteRecord(
                                        callInstructionAddress: insn.address,
                                        callerFunctionAddress: fnAddr,
                                        callerFunctionName: fn.demangledName,
                                        stubOrGOTAddress: resolvedGOT,
                                        importedSymbolName: imp.symbolName,
                                        demangledSymbolName: imp.demangledName,
                                        libraryName: imp.libraryName,
                                        isTailCall: false
                                    )
                                )
                            }
                        }

                    case .indirectJump(let reg):
                        if let jt = fn.jumpTables.first(where: { $0.dispatchInstructionAddress == insn.address }) {
                            emitXref(from: insn.address, fromFn: fnAddr, to: jt.tableBaseAddress, kind: .dataPointerRead, preview: preview)
                            for caseTarget in jt.targetAddresses {
                                emitXref(from: insn.address, fromFn: fnAddr, to: caseTarget, kind: .unconditionalJump, preview: preview)
                            }
                        } else if let resolvedGOT = recentLoadedAddressByReg[reg.index] {
                            emitXref(from: insn.address, fromFn: fnAddr, to: resolvedGOT, kind: .indirectCall, preview: preview)
                            if !isStubFn, let imp = importByAddress[resolvedGOT], seenImportSiteAddrs.insert(insn.address).inserted {
                                importCallSites.append(
                                    ImportCallSiteRecord(
                                        callInstructionAddress: insn.address,
                                        callerFunctionAddress: fnAddr,
                                        callerFunctionName: fn.demangledName,
                                        stubOrGOTAddress: resolvedGOT,
                                        importedSymbolName: imp.symbolName,
                                        demangledSymbolName: imp.demangledName,
                                        libraryName: imp.libraryName,
                                        isTailCall: true
                                    )
                                )
                            }
                        }

                    case .sequential, .returnControl, .trapOrSupervisor:
                        break
                    }

                    // 3. Standalone `ADR`, `ADRP`, and PC-relative literal `LDR` references
                    if insn.mnemonic == .adr,
                       insn.operands.count == 2,
                       case .branchTarget(let target) = insn.operands[1] {
                        if let strAddr = resolveCanonicalStringAddress(target) {
                            emitXref(from: insn.address, fromFn: fnAddr, to: strAddr, kind: .stringReference, preview: preview)
                        } else {
                            emitXref(from: insn.address, fromFn: fnAddr, to: target, kind: .dataPointerRead, preview: preview)
                        }
                    } else if insn.mnemonic == .adrp,
                              !pairedADRPAddresses.contains(insn.address),
                              insn.operands.count == 2,
                              case .branchTarget(let pageTarget) = insn.operands[1] {
                        emitXref(from: insn.address, fromFn: fnAddr, to: pageTarget, kind: .pageBaseADRP, preview: preview)
                    } else if insn.group == .loadStore {
                        for op in insn.operands {
                            if case .memory(.pcRelativeLiteral(let litAddr)) = op {
                                if let strAddr = resolveCanonicalStringAddress(litAddr) {
                                    emitXref(from: insn.address, fromFn: fnAddr, to: strAddr, kind: .stringReference, preview: preview)
                                } else {
                                    emitXref(from: insn.address, fromFn: fnAddr, to: litAddr, kind: .dataPointerRead, preview: preview)
                                }
                            }
                        }
                    }
                }
            }

            _ = jumpTableDescriptorsByFunction[fnAddr]
        }

        // 4. Emit dyld Chained Fixup pointer references (`chainedFixupTarget`)
        for fixup in image.chainedFixups {
            if let target = fixup.targetAddress {
                let kindNote = "\(fixup.kind.rawValue) -> \(target.compactHexString)"
                let actualKind: XrefKind = resolveCanonicalStringAddress(target) != nil
                    ? .stringReference
                    : .chainedFixupTarget
                let finalTo = resolveCanonicalStringAddress(target) ?? target
                emitXref(
                    from: fixup.location,
                    fromFn: nil,
                    to: finalTo,
                    kind: actualKind,
                    preview: kindNote
                )
            }
        }

        let index = CrossReferenceIndex(records: records, importCallSites: importCallSites)
        return (index, resolvedIndirectCalls)
    }

    // MARK: - Internal Whole-Program Call Graph Builder & Dangerous Sink Classifier

    private func buildProgramCallGraph(
        image: LoadedBinaryImage,
        boundaries: [DiscoveredFunctionBoundary],
        functions: [RecoveredFunction],
        tailTargetsByFunction: [VirtualAddress: [VirtualAddress]],
        resolvedIndirectTargetsByInsn: [VirtualAddress: VirtualAddress],
        importCallSites: [ImportCallSiteRecord]
    ) -> ProgramCallGraph {
        var functionByEntry: [VirtualAddress: RecoveredFunction] = [:]
        for fn in functions {
            functionByEntry[fn.address] = fn
        }

        var boundaryByStart: [VirtualAddress: DiscoveredFunctionBoundary] = [:]
        for b in boundaries {
            boundaryByStart[b.startAddress] = b
        }

        // Identify entry & exported symbol addresses
        var entryOrExportedSet = Set<VirtualAddress>()
        if let ep = image.entryPoint {
            entryOrExportedSet.insert(ep)
        }
        for sym in image.symbols {
            if sym.kind == .exportedEntry || (sym.binding == .global && sym.kind != .importedStub) {
                entryOrExportedSet.insert(sym.address)
            }
        }
        for cls in image.objcClasses {
            for m in cls.methods {
                entryOrExportedSet.insert(m.implementationAddress)
            }
        }

        // Track external pseudo-nodes (e.g. WASM imported functions or direct GOT calls without a `__stubs` function)
        var externalNodesByAddress: [VirtualAddress: (name: String, demangled: String)] = [:]
        for sym in image.symbols where sym.kind == .importedStub && functionByEntry[sym.address] == nil {
            externalNodesByAddress[sym.address] = (sym.name, sym.demangledName)
        }
        for site in importCallSites where functionByEntry[site.stubOrGOTAddress] == nil {
            externalNodesByAddress[site.stubOrGOTAddress] = (site.importedSymbolName, site.demangledSymbolName)
        }

        // Accumulate call edges `(caller, callee)` -> `(callSites, isTail, isIndirect)`
        struct PendingCallEdge {
            var sites: [VirtualAddress] = []
            var isTailCall: Bool = false
            var isIndirect: Bool = false
        }
        var edgeTable: [VirtualAddress: [VirtualAddress: PendingCallEdge]] = [:]

        func recordCall(
            caller: VirtualAddress,
            callee: VirtualAddress,
            site: VirtualAddress,
            isTail: Bool,
            isIndirect: Bool
        ) {
            guard functionByEntry[callee] != nil || externalNodesByAddress[callee] != nil else {
                return
            }
            var entry = edgeTable[caller, default: [:]][callee] ?? PendingCallEdge()
            if !entry.sites.contains(site) {
                entry.sites.append(site)
            }
            if isTail { entry.isTailCall = true }
            if isIndirect { entry.isIndirect = true }
            edgeTable[caller, default: [:]][callee] = entry
        }

        for fn in functions {
            let callerAddr = fn.address
            let isStub = boundaryByStart[callerAddr]?.isStubSection ?? false
            if isStub { continue }

            for block in fn.blocks {
                for insn in block.instructions {
                    switch insn.flow {
                    case .directCall(let target):
                        recordCall(caller: callerAddr, callee: target, site: insn.address, isTail: false, isIndirect: false)
                    case .indirectCall:
                        if let resolved = resolvedIndirectTargetsByInsn[insn.address] {
                            recordCall(caller: callerAddr, callee: resolved, site: insn.address, isTail: false, isIndirect: true)
                        }
                    case .unconditionalJump(let target):
                        if target != callerAddr && (target < fn.address || target >= fn.endAddress) {
                            recordCall(caller: callerAddr, callee: target, site: insn.address, isTail: true, isIndirect: false)
                        }
                    default:
                        break
                    }
                }
            }

            for tailTarget in tailTargetsByFunction[callerAddr] ?? [] where tailTarget != callerAddr {
                let tailSite = fn.blocks.last?.instructions.last?.address ?? callerAddr
                recordCall(caller: callerAddr, callee: tailTarget, site: tailSite, isTail: true, isIndirect: false)
            }
        }

        var edges: [CallGraphEdge] = []
        var inDeg: [VirtualAddress: Int] = [:]
        var outDeg: [VirtualAddress: Int] = [:]

        for (caller, calleesMap) in edgeTable {
            for (callee, info) in calleesMap {
                edges.append(
                    CallGraphEdge(
                        callerAddress: caller,
                        calleeAddress: callee,
                        callSiteAddresses: info.sites.sorted(),
                        isTailCall: info.isTailCall,
                        isIndirectResolved: info.isIndirect
                    )
                )
                outDeg[caller, default: 0] += 1
                inDeg[callee, default: 0] += 1
            }
        }

        var nodes: [CallGraphNode] = []
        nodes.reserveCapacity(functions.count + externalNodesByAddress.count)

        for fn in functions {
            let b = boundaryByStart[fn.address]
            let isThunkOrStub = fn.isThunk || (b?.isStubSection ?? false)
            let symbolForSink = b?.resolvedGOTTargetSymbol ?? fn.name
            let sinkCat = Self.classifyDangerousSink(symbolName: symbolForSink)
                ?? Self.classifyDangerousSink(symbolName: fn.demangledName)

            let isRootOrExport = entryOrExportedSet.contains(fn.address)
                || fn.name == "_main" || fn.name == "main" || fn.name == "_start"

            nodes.append(
                CallGraphNode(
                    address: fn.address,
                    name: fn.name,
                    demangledName: fn.demangledName,
                    isImportedThunk: isThunkOrStub,
                    isExternalSymbol: false,
                    isEntryOrExported: isRootOrExport,
                    sinkCategory: sinkCat,
                    inDegree: inDeg[fn.address] ?? 0,
                    outDegree: outDeg[fn.address] ?? 0
                )
            )
        }

        for (extAddr, extNames) in externalNodesByAddress {
            let sinkCat = Self.classifyDangerousSink(symbolName: extNames.name)
                ?? Self.classifyDangerousSink(symbolName: extNames.demangled)
            nodes.append(
                CallGraphNode(
                    address: extAddr,
                    name: extNames.name,
                    demangledName: extNames.demangled,
                    isImportedThunk: true,
                    isExternalSymbol: true,
                    isEntryOrExported: false,
                    sinkCategory: sinkCat,
                    inDegree: inDeg[extAddr] ?? 0,
                    outDegree: outDeg[extAddr] ?? 0
                )
            )
        }

        return ProgramCallGraph(nodes: nodes, edges: edges)
    }

    /// Classifies C / POSIX / Darwin / Win32 / WebAssembly sink APIs into security-relevant sink categories.
    public static func classifyDangerousSink(symbolName: String) -> DangerousSinkCategory? {
        var clean = symbolName.trimmingCharacters(in: .whitespacesAndNewlines)
        for suffix in ["$stub", "@PLT", "$shim", " [stub]"] {
            if clean.hasSuffix(suffix) {
                clean = String(clean.dropLast(suffix.count))
            }
        }
        while clean.hasPrefix("_") {
            clean.removeFirst()
        }
        if let dotIdx = clean.lastIndex(of: ".") {
            clean = String(clean[clean.index(after: dotIdx)...])
        }
        if let parenIdx = clean.firstIndex(of: "(") {
            clean = String(clean[..<parenIdx])
        }
        let lower = clean.lowercased()
        guard !lower.isEmpty else { return nil }

        let commandSinks: Set<String> = [
            "system", "popen", "posix_spawn", "posix_spawnp",
            "execve", "execl", "execlp", "execle", "execv", "execvp", "execvpe",
            "fork", "vfork", "winexec", "createprocessa", "createprocessw", "shellexecutew"
        ]
        if commandSinks.contains(lower) || lower.contains("nstask") {
            return .commandExecution
        }

        let memorySinks: Set<String> = [
            "strcpy", "strncpy", "strcat", "strncat", "gets",
            "sprintf", "vsprintf", "scanf", "sscanf", "fscanf",
            "memcpy", "memmove", "bcopy", "alloca", "realloc"
        ]
        if memorySinks.contains(lower) {
            return .unboundedMemoryOrString
        }

        let formatSinks: Set<String> = [
            "printf", "fprintf", "dprintf", "vprintf", "vfprintf",
            "snprintf", "vsnprintf", "asprintf", "syslog", "nslog"
        ]
        if formatSinks.contains(lower) {
            return .formatStringOutput
        }

        let loaderSinks: Set<String> = [
            "dlopen", "dlsym", "NSCreateObjectFileImageFromMemory".lowercased(),
            "mmap", "mprotect", "pthread_jit_write_protect_np",
            "virtualalloc", "virtualprotect", "loadlibrarya", "loadlibraryw", "getprocaddress"
        ]
        if loaderSinks.contains(lower) {
            return .dynamicLoaderOrJIT
        }

        let authCryptoSinks: Set<String> = [
            "strcmp", "strncmp", "strcasecmp", "memcmp",
            "cccrypt", "ccdigest", "secitemcopymatching", "secitemadd", "seckeyrawverify"
        ]
        if authCryptoSinks.contains(lower) {
            return .authenticationOrCrypto
        }

        let envNetSinks: Set<String> = [
            "getenv", "setenv", "connect", "bind", "listen", "accept",
            "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
            "xpc_connection_create", "xpc_connection_create_mach_service", "host_trace"
        ]
        if envNetSinks.contains(lower) {
            return .environmentOrNetwork
        }

        return nil
    }

    private func resolveBackingBytes(for image: LoadedBinaryImage, explicitData: Data?) -> Data? {
        if let explicitData, !explicitData.isEmpty {
            LockedBinaryByteRegistry.shared.register(data: explicitData, sha256Hex: image.sha256Hex)
            return explicitData
        }
        if !image.filePath.isEmpty && !image.filePath.hasPrefix("<") && FileManager.default.fileExists(atPath: image.filePath) {
            if let diskData = try? Data(contentsOf: URL(fileURLWithPath: image.filePath), options: [.mappedIfSafe]),
               !diskData.isEmpty {
                return diskData
            }
        }
        if !image.sha256Hex.isEmpty,
           let cached = LockedBinaryByteRegistry.shared.lookup(sha256Hex: image.sha256Hex) {
            return cached
        }
        return nil
    }
}
