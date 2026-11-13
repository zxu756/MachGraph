import Foundation

// MARK: - JavaScriptCore Reverse-Engineering Plugin SDK Models

public enum MachPluginCapability: String, Sendable, Codable, Hashable, CaseIterable {
    case readBinaryBytes = "binary.read"
    case readSymbolTable = "symbols.read"
    case readControlFlowGraph = "cfg.read"
    case writeDatabaseAnnotations = "annotations.write"
    case emitSecurityFindings = "findings.emit"
    case proposeInlinePatches = "patches.propose"
}

public enum SecurityFindingSeverity: String, Sendable, Codable, Hashable, CaseIterable, Comparable {
    case info = "INFO"
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: SecurityFindingSeverity, rhs: SecurityFindingSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

public struct SecurityAuditFinding: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let pluginID: String
    public let pluginName: String
    public let severity: SecurityFindingSeverity
    public let category: String
    public let title: String
    public let detail: String
    public let address: VirtualAddress?
    public let evidencePreview: String?
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        pluginID: String,
        pluginName: String,
        severity: SecurityFindingSeverity,
        category: String,
        title: String,
        detail: String,
        address: VirtualAddress? = nil,
        evidencePreview: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.pluginID = pluginID
        self.pluginName = pluginName
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.address = address
        self.evidencePreview = evidencePreview
        self.createdAt = createdAt
    }
}

public struct MachPluginManifest: Sendable, Codable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let version: String
    public let author: String
    public let summary: String
    public let capabilities: [MachPluginCapability]
    public let isBuiltIn: Bool
    public var isEnabled: Bool
    public let scriptSource: String

    public init(
        id: String,
        name: String,
        version: String = "1.0.0",
        author: String = "MachGraph Labs",
        summary: String,
        capabilities: [MachPluginCapability],
        isBuiltIn: Bool = true,
        isEnabled: Bool = true,
        scriptSource: String
    ) {
        self.id = id
        self.name = name
        self.version = version
        self.author = author
        self.summary = summary
        self.capabilities = capabilities
        self.isBuiltIn = isBuiltIn
        self.isEnabled = isEnabled
        self.scriptSource = scriptSource
    }
}

public struct MachPluginExecutionResult: Sendable, Codable, Hashable {
    public let pluginID: String
    public let durationMilliseconds: Double
    public let findings: [SecurityAuditFinding]
    public let generatedComments: [UserInlineComment]
    public let generatedBookmarks: [UserBookmark]
    public let consoleLogs: [String]

    public init(
        pluginID: String,
        durationMilliseconds: Double,
        findings: [SecurityAuditFinding] = [],
        generatedComments: [UserInlineComment] = [],
        generatedBookmarks: [UserBookmark] = [],
        consoleLogs: [String] = []
    ) {
        self.pluginID = pluginID
        self.durationMilliseconds = durationMilliseconds
        self.findings = findings
        self.generatedComments = generatedComments
        self.generatedBookmarks = generatedBookmarks
        self.consoleLogs = consoleLogs
    }
}

// MARK: - Workbench Shell & Synchronized Address Cursor Bus

public enum WorkbenchPaneTab: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case cfgGraph = "CFG Graph"
    case disassembly = "Linear Disassembly"
    case pseudoC = "Pseudo-C Decompiler"
    case hexPatcher = "Hex & Patcher"
    case stringsAndObjC = "Strings & Runtime"
    case entropyAndSign = "Entropy & CodeSign"
    case pluginFindings = "Plugin Audit"

    public var id: String { rawValue }

    public var sfSymbolName: String {
        switch self {
        case .cfgGraph: return "point.3.connected.trianglepath.dotted"
        case .disassembly: return "list.number"
        case .pseudoC: return "curlybraces"
        case .hexPatcher: return "00.square"
        case .stringsAndObjC: return "character.book.closed"
        case .entropyAndSign: return "waveform.path.ecg.rectangle"
        case .pluginFindings: return "puzzlepiece.extension"
        }
    }
}

public enum NavigatorSidebarFilter: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case functions = "Functions"
    case symbols = "Symbols"
    case imports = "Imports"
    case strings = "Strings"
    case classes = "ObjC / Swift"
    case bookmarks = "Bookmarks"
    case patches = "Patches"

    public var id: String { rawValue }
}

public struct SynchronizedCursorLocation: Sendable, Codable, Hashable {
    public let virtualAddress: VirtualAddress
    public let fileOffset: FileOffset?
    public let functionAddress: VirtualAddress?
    public let blockID: Int?
    public let originPane: WorkbenchPaneTab

    public init(
        virtualAddress: VirtualAddress,
        fileOffset: FileOffset? = nil,
        functionAddress: VirtualAddress? = nil,
        blockID: Int? = nil,
        originPane: WorkbenchPaneTab = .cfgGraph
    ) {
        self.virtualAddress = virtualAddress
        self.fileOffset = fileOffset
        self.functionAddress = functionAddress
        self.blockID = blockID
        self.originPane = originPane
    }
}

public struct MachProjectStats: Sendable, Codable, Hashable {
    public let projectName: String
    public let binaryPath: String
    public let binarySHA256: String
    public let schemaVersion: Int
    public let sqliteBytes: Int64
    public let walBytes: Int64
    public let functionCount: Int
    public let symbolCount: Int
    public let xrefCount: Int
    public let patchCount: Int
    public let bookmarkCount: Int
    public let commentCount: Int
    public let renameCount: Int
    public let structCount: Int
    public let findingCount: Int
    public let undoDepth: Int
    public let redoDepth: Int

    public init(
        projectName: String,
        binaryPath: String,
        binarySHA256: String,
        schemaVersion: Int,
        sqliteBytes: Int64,
        walBytes: Int64,
        functionCount: Int,
        symbolCount: Int,
        xrefCount: Int,
        patchCount: Int,
        bookmarkCount: Int,
        commentCount: Int,
        renameCount: Int,
        structCount: Int,
        findingCount: Int,
        undoDepth: Int,
        redoDepth: Int
    ) {
        self.projectName = projectName
        self.binaryPath = binaryPath
        self.binarySHA256 = binarySHA256
        self.schemaVersion = schemaVersion
        self.sqliteBytes = sqliteBytes
        self.walBytes = walBytes
        self.functionCount = functionCount
        self.symbolCount = symbolCount
        self.xrefCount = xrefCount
        self.patchCount = patchCount
        self.bookmarkCount = bookmarkCount
        self.commentCount = commentCount
        self.renameCount = renameCount
        self.structCount = structCount
        self.findingCount = findingCount
        self.undoDepth = undoDepth
        self.redoDepth = redoDepth
    }
}
