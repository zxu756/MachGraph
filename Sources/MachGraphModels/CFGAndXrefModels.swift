import Foundation

// MARK: - Control Flow Graph (Basic Blocks, Edges, Dominators, Loops)

public enum CFGEdgeKind: Sendable, Codable, Hashable {
    case unconditional
    case conditionalTrue
    case conditionalFalse
    case fallthroughEdge
    case switchCase(value: Int64)

    public var displayLabel: String? {
        switch self {
        case .unconditional: return nil
        case .conditionalTrue: return "T"
        case .conditionalFalse: return "F"
        case .fallthroughEdge: return nil
        case .switchCase(let v): return "case \(v)"
        }
    }
}

public struct CFGEdge: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(sourceBlockID)->\(targetBlockID):\(isBackEdge ? "back" : "fwd")" }
    public let sourceBlockID: Int
    public let targetBlockID: Int
    public let kind: CFGEdgeKind
    public let isBackEdge: Bool

    public init(
        sourceBlockID: Int,
        targetBlockID: Int,
        kind: CFGEdgeKind,
        isBackEdge: Bool = false
    ) {
        self.sourceBlockID = sourceBlockID
        self.targetBlockID = targetBlockID
        self.kind = kind
        self.isBackEdge = isBackEdge
    }
}

public struct BasicBlock: Sendable, Codable, Hashable, Identifiable {
    public let id: Int
    public let functionAddress: VirtualAddress
    public let startAddress: VirtualAddress
    public let endAddress: VirtualAddress
    public let instructions: [A64DecodedInstruction]
    public let predecessorIDs: [Int]
    public let successorIDs: [Int]
    public let isEntry: Bool
    public let isExit: Bool
    public let loopDepth: Int

    public init(
        id: Int,
        functionAddress: VirtualAddress,
        startAddress: VirtualAddress,
        endAddress: VirtualAddress,
        instructions: [A64DecodedInstruction],
        predecessorIDs: [Int] = [],
        successorIDs: [Int] = [],
        isEntry: Bool = false,
        isExit: Bool = false,
        loopDepth: Int = 0
    ) {
        self.id = id
        self.functionAddress = functionAddress
        self.startAddress = startAddress
        self.endAddress = endAddress
        self.instructions = instructions
        self.predecessorIDs = predecessorIDs
        self.successorIDs = successorIDs
        self.isEntry = isEntry
        self.isExit = isExit
        self.loopDepth = loopDepth
    }

    public var byteSize: UInt64 {
        endAddress.rawValue >= startAddress.rawValue ? (endAddress.rawValue - startAddress.rawValue) : 0
    }

    public var label: String {
        isEntry ? "entry_\(startAddress.compactHexString)" : "loc_\(String(startAddress.rawValue, radix: 16))"
    }
}

public struct DominatorTreeNode: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { blockID }
    public let blockID: Int
    public let immediateDominatorID: Int?
    public let dominatedChildrenIDs: [Int]
    public let dominanceFrontierIDs: [Int]
    public let depth: Int

    public init(
        blockID: Int,
        immediateDominatorID: Int?,
        dominatedChildrenIDs: [Int] = [],
        dominanceFrontierIDs: [Int] = [],
        depth: Int = 0
    ) {
        self.blockID = blockID
        self.immediateDominatorID = immediateDominatorID
        self.dominatedChildrenIDs = dominatedChildrenIDs
        self.dominanceFrontierIDs = dominanceFrontierIDs
        self.depth = depth
    }
}

public struct NaturalLoop: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { headerBlockID }
    public let headerBlockID: Int
    public let latchBlockIDs: [Int]
    public let bodyBlockIDs: [Int]
    public let exitBlockIDs: [Int]
    public let nestingDepth: Int

    public init(
        headerBlockID: Int,
        latchBlockIDs: [Int],
        bodyBlockIDs: [Int],
        exitBlockIDs: [Int] = [],
        nestingDepth: Int = 1
    ) {
        self.headerBlockID = headerBlockID
        self.latchBlockIDs = latchBlockIDs
        self.bodyBlockIDs = bodyBlockIDs
        self.exitBlockIDs = exitBlockIDs
        self.nestingDepth = nestingDepth
    }
}

public struct SwitchJumpTable: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { dispatchInstructionAddress.rawValue }
    public let dispatchInstructionAddress: VirtualAddress
    public let tableBaseAddress: VirtualAddress
    public let entryByteSize: Int
    public let targetAddresses: [VirtualAddress]
    public let isInlineInCode: Bool

    public init(
        dispatchInstructionAddress: VirtualAddress,
        tableBaseAddress: VirtualAddress,
        entryByteSize: Int = 4,
        targetAddresses: [VirtualAddress],
        isInlineInCode: Bool = false
    ) {
        self.dispatchInstructionAddress = dispatchInstructionAddress
        self.tableBaseAddress = tableBaseAddress
        self.entryByteSize = entryByteSize
        self.targetAddresses = targetAddresses
        self.isInlineInCode = isInlineInCode
    }

    public var tableByteSize: UInt64 {
        UInt64(max(0, entryByteSize) * targetAddresses.count)
    }

    public var tableEndAddress: VirtualAddress {
        tableBaseAddress.adding(tableByteSize)
    }

    public var tableAddressRange: AddressRange {
        AddressRange(start: tableBaseAddress, size: tableByteSize)
    }
}

// MARK: - Sugiyama Layered CFG Layout Geometry

public struct CFGNodeLayout: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { blockID }
    public let blockID: Int
    public let layer: Int
    public let orderInLayer: Int
    public let frame: CGRectBridge

    public init(blockID: Int, layer: Int, orderInLayer: Int, frame: CGRectBridge) {
        self.blockID = blockID
        self.layer = layer
        self.orderInLayer = orderInLayer
        self.frame = frame
    }
}

public struct CFGEdgeRoute: Sendable, Codable, Hashable, Identifiable {
    public var id: String { edge.id }
    public let edge: CFGEdge
    public let waypoints: [CGPointBridge]
    public let label: String?

    public init(edge: CFGEdge, waypoints: [CGPointBridge], label: String? = nil) {
        self.edge = edge
        self.waypoints = waypoints
        self.label = label
    }
}

public struct SugiyamaCFGLayout: Sendable, Codable, Hashable {
    public let functionAddress: VirtualAddress
    public let canvasWidth: Double
    public let canvasHeight: Double
    public let layerCount: Int
    public let nodes: [CFGNodeLayout]
    public let routes: [CFGEdgeRoute]

    public init(
        functionAddress: VirtualAddress,
        canvasWidth: Double,
        canvasHeight: Double,
        layerCount: Int,
        nodes: [CFGNodeLayout],
        routes: [CFGEdgeRoute]
    ) {
        self.functionAddress = functionAddress
        self.canvasWidth = canvasWidth
        self.canvasHeight = canvasHeight
        self.layerCount = layerCount
        self.nodes = nodes
        self.routes = routes
    }
}

// MARK: - Recovered Function & Cross-Reference Database Models

public struct RecoveredFunction: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let endAddress: VirtualAddress
    public let name: String
    public let demangledName: String
    public let isLeaf: Bool
    public let isThunk: Bool
    public let usesPAC: Bool
    public let stackFrameBytes: Int
    public let blocks: [BasicBlock]
    public let edges: [CFGEdge]
    public let dominatorTree: [DominatorTreeNode]
    public let naturalLoops: [NaturalLoop]
    public let jumpTables: [SwitchJumpTable]
    public let inlineJumpTableRanges: [AddressRange]
    public let cyclomaticComplexity: Int
    public let instructionCount: Int
    public let layout: SugiyamaCFGLayout?

    public init(
        address: VirtualAddress,
        endAddress: VirtualAddress,
        name: String,
        demangledName: String? = nil,
        isLeaf: Bool = false,
        isThunk: Bool = false,
        usesPAC: Bool = false,
        stackFrameBytes: Int = 0,
        blocks: [BasicBlock],
        edges: [CFGEdge],
        dominatorTree: [DominatorTreeNode] = [],
        naturalLoops: [NaturalLoop] = [],
        jumpTables: [SwitchJumpTable] = [],
        inlineJumpTableRanges: [AddressRange]? = nil,
        cyclomaticComplexity: Int? = nil,
        layout: SugiyamaCFGLayout? = nil
    ) {
        self.address = address
        self.endAddress = endAddress
        self.name = name
        self.demangledName = demangledName ?? name
        self.isLeaf = isLeaf
        self.isThunk = isThunk
        self.usesPAC = usesPAC
        self.stackFrameBytes = stackFrameBytes
        self.blocks = blocks
        self.edges = edges
        self.dominatorTree = dominatorTree
        self.naturalLoops = naturalLoops
        self.jumpTables = jumpTables
        self.inlineJumpTableRanges = inlineJumpTableRanges ?? jumpTables.filter(\.isInlineInCode).map(\.tableAddressRange)
        let computedCC = max(1, edges.count - blocks.count + 2)
        self.cyclomaticComplexity = cyclomaticComplexity ?? computedCC
        self.instructionCount = blocks.reduce(0) { $0 + $1.instructions.count }
        self.layout = layout
    }

    public func block(containing vmAddress: VirtualAddress) -> BasicBlock? {
        blocks.first { vmAddress >= $0.startAddress && vmAddress < $0.endAddress }
    }
}

public enum XrefKind: String, Sendable, Codable, Hashable, CaseIterable {
    case directCall = "CALL"
    case indirectCall = "ICALL"
    case unconditionalJump = "JMP"
    case conditionalBranch = "BRANCH"
    case codeReference = "CODE_REF"
    case dataPointerRead = "DATA_READ"
    case dataPointerWrite = "DATA_WRITE"
    case stringReference = "STRING_REF"
    case pageBaseADRP = "ADRP_PAGE"
    case chainedFixupTarget = "FIXUP_PTR"
}

public struct XrefRecord: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let fromAddress: VirtualAddress
    public let fromFunction: VirtualAddress?
    public let toAddress: VirtualAddress
    public let kind: XrefKind
    public let instructionPreview: String

    public init(
        id: UUID = UUID(),
        fromAddress: VirtualAddress,
        fromFunction: VirtualAddress? = nil,
        toAddress: VirtualAddress,
        kind: XrefKind,
        instructionPreview: String
    ) {
        self.id = id
        self.fromAddress = fromAddress
        self.fromFunction = fromFunction
        self.toAddress = toAddress
        self.kind = kind
        self.instructionPreview = instructionPreview
    }
}
