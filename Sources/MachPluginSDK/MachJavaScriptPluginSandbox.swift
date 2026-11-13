import Foundation
import JavaScriptCore
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine

// MARK: - MachGraphError Convenience Factory for Plugin Execution

extension MachGraphError {
    /// Canonical factory mapping JavaScriptCore sandbox and capability failures to `MachGraphError`.
    public static func pluginExecutionFailed(pluginID: String, message: String) -> MachGraphError {
        .pluginSandboxError(pluginID: pluginID, message: message)
    }
}

// MARK: - Sandbox Configuration, Console Ring Buffer & Proposed Patch Models

public struct MachPluginSandboxConfiguration: Sendable, Codable, Hashable {
    public var maxConsoleEntries: Int
    public var maxReadBytesPerCall: Int
    public var maxTotalReadBytes: Int
    public var maxEmittedFindings: Int
    public var maxGeneratedAnnotations: Int
    public var maxProposedPatches: Int
    public var maxExposedStrings: Int
    public var maxExposedSymbols: Int
    public var maxExposedFunctions: Int
    public var executionTimeoutMilliseconds: Double
    public var enforceCapabilityGates: Bool
    public var throwJSExceptionOnCapabilityDenial: Bool

    public init(
        maxConsoleEntries: Int = 256,
        maxReadBytesPerCall: Int = 65_536,
        maxTotalReadBytes: Int = 4_194_304,
        maxEmittedFindings: Int = 512,
        maxGeneratedAnnotations: Int = 512,
        maxProposedPatches: Int = 128,
        maxExposedStrings: Int = 12_000,
        maxExposedSymbols: Int = 25_000,
        maxExposedFunctions: Int = 10_000,
        executionTimeoutMilliseconds: Double = 5_000.0,
        enforceCapabilityGates: Bool = true,
        throwJSExceptionOnCapabilityDenial: Bool = true
    ) {
        self.maxConsoleEntries = max(16, maxConsoleEntries)
        self.maxReadBytesPerCall = max(64, maxReadBytesPerCall)
        self.maxTotalReadBytes = max(1_024, maxTotalReadBytes)
        self.maxEmittedFindings = max(1, maxEmittedFindings)
        self.maxGeneratedAnnotations = max(1, maxGeneratedAnnotations)
        self.maxProposedPatches = max(1, maxProposedPatches)
        self.maxExposedStrings = max(64, maxExposedStrings)
        self.maxExposedSymbols = max(64, maxExposedSymbols)
        self.maxExposedFunctions = max(32, maxExposedFunctions)
        self.executionTimeoutMilliseconds = max(50.0, executionTimeoutMilliseconds)
        self.enforceCapabilityGates = enforceCapabilityGates
        self.throwJSExceptionOnCapabilityDenial = throwJSExceptionOnCapabilityDenial
    }

    public static let standard = MachPluginSandboxConfiguration()
}

public enum MachPluginConsoleLevel: String, Sendable, Codable, Hashable, CaseIterable {
    case debug = "DEBUG"
    case info = "INFO"
    case warn = "WARN"
    case error = "ERROR"
}

public struct MachPluginConsoleEntry: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let pluginID: String
    public let level: MachPluginConsoleLevel
    public let message: String
    public let elapsedMilliseconds: Double
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        pluginID: String,
        level: MachPluginConsoleLevel,
        message: String,
        elapsedMilliseconds: Double,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.pluginID = pluginID
        self.level = level
        self.message = message
        self.elapsedMilliseconds = elapsedMilliseconds
        self.createdAt = createdAt
    }

    public var formattedLine: String {
        let stamp = String(format: "+%.2fms", elapsedMilliseconds)
        return "[\(level.rawValue) \(stamp)] \(message)"
    }
}

public struct MachPluginConsoleRingBuffer: Sendable, Codable, Hashable {
    public let capacity: Int
    private var storage: [MachPluginConsoleEntry]
    private var headIndex: Int
    public private(set) var totalAppendedCount: Int

    public init(capacity: Int = 256) {
        let clamped = max(8, capacity)
        self.capacity = clamped
        self.storage = []
        self.storage.reserveCapacity(min(clamped, 64))
        self.headIndex = 0
        self.totalAppendedCount = 0
    }

    public var count: Int { storage.count }

    public var evictedCount: Int {
        max(0, totalAppendedCount - storage.count)
    }

    public mutating func append(_ entry: MachPluginConsoleEntry) {
        totalAppendedCount += 1
        if storage.count < capacity {
            storage.append(entry)
        } else {
            storage[headIndex] = entry
            headIndex = (headIndex + 1) % capacity
        }
    }

    public var entries: [MachPluginConsoleEntry] {
        guard !storage.isEmpty else { return [] }
        if storage.count < capacity || headIndex == 0 {
            return storage
        }
        return Array(storage[headIndex...] + storage[..<headIndex])
    }

    public var formattedLines: [String] {
        var lines = entries.map(\.formattedLine)
        if evictedCount > 0 {
            lines.insert("[RING-BUFFER] \(evictedCount) earlier console line(s) rotated out", at: 0)
        }
        return lines
    }

    public mutating func clear() {
        storage.removeAll(keepingCapacity: true)
        headIndex = 0
        totalAppendedCount = 0
    }
}

public struct MachPluginProposedPatch: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let pluginID: String
    public let virtualAddress: VirtualAddress
    public let fileOffset: FileOffset?
    public let patchedBytes: [UInt8]
    public let note: String
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        pluginID: String,
        virtualAddress: VirtualAddress,
        fileOffset: FileOffset?,
        patchedBytes: [UInt8],
        note: String,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.pluginID = pluginID
        self.virtualAddress = virtualAddress
        self.fileOffset = fileOffset
        self.patchedBytes = patchedBytes
        self.note = note
        self.createdAt = createdAt
    }

    public var patchedHex: String {
        patchedBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}

public struct MachPluginDetailedExecutionReport: Sendable, Codable, Hashable {
    public let result: MachPluginExecutionResult
    public let consoleEntries: [MachPluginConsoleEntry]
    public let proposedPatches: [MachPluginProposedPatch]
    public let capabilityDenials: [String]
    public let bridgeCallCount: Int

    public init(
        result: MachPluginExecutionResult,
        consoleEntries: [MachPluginConsoleEntry],
        proposedPatches: [MachPluginProposedPatch] = [],
        capabilityDenials: [String] = [],
        bridgeCallCount: Int = 0
    ) {
        self.result = result
        self.consoleEntries = consoleEntries
        self.proposedPatches = proposedPatches
        self.capabilityDenials = capabilityDenials
        self.bridgeCallCount = bridgeCallCount
    }
}

// MARK: - Single-Run Mutable Collector (Confined to Isolated JSContext Thread)

private final class SandboxExecutionState {
    let manifest: MachPluginManifest
    let grantedCapabilities: Set<MachPluginCapability>
    let configuration: MachPluginSandboxConfiguration
    let analysisIndex: BinaryAnalysisIndex
    let resolvedBinaryData: Data?
    let startTimestamp: CFAbsoluteTime

    var consoleRing: MachPluginConsoleRingBuffer
    var findings: [SecurityAuditFinding] = []
    var findingDedupKeys: Set<String> = []
    var commentsByAddress: [VirtualAddress: UserInlineComment] = [:]
    var orderedCommentAddresses: [VirtualAddress] = []
    var bookmarks: [UserBookmark] = []
    var proposedPatches: [MachPluginProposedPatch] = []
    var capabilityDenials: [String] = []
    var capturedJSExceptionMessage: String?
    var totalReadBytes: Int = 0
    var bridgeCallCount: Int = 0

    // Lazily serialized caches so repeated JS queries inside one plugin run are O(1)
    var cachedImageSummary: [String: Any]?
    var cachedSegments: [[String: Any]]?
    var cachedSections: [[String: Any]]?
    var cachedCodeSignature: [String: Any]?
    var cachedSymbols: [[String: Any]]?
    var cachedImports: [[String: Any]]?
    var cachedImportedLibraries: [[String: Any]]?
    var cachedStrings: [[String: Any]]?
    var cachedObjCClasses: [[String: Any]]?
    var cachedSwiftTypes: [[String: Any]]?
    var cachedFunctions: [[String: Any]]?
    var cachedDangerousSinkPaths: [[String: Any]]?

    init(
        manifest: MachPluginManifest,
        configuration: MachPluginSandboxConfiguration,
        analysisIndex: BinaryAnalysisIndex,
        resolvedBinaryData: Data?,
        startTimestamp: CFAbsoluteTime
    ) {
        self.manifest = manifest
        self.grantedCapabilities = Set(manifest.capabilities)
        self.configuration = configuration
        self.analysisIndex = analysisIndex
        self.resolvedBinaryData = resolvedBinaryData
        self.startTimestamp = startTimestamp
        self.consoleRing = MachPluginConsoleRingBuffer(capacity: configuration.maxConsoleEntries)
    }

    var elapsedMilliseconds: Double {
        max(0.0, (CFAbsoluteTimeGetCurrent() - startTimestamp) * 1000.0)
    }

    func log(_ level: MachPluginConsoleLevel, _ message: String) {
        let entry = MachPluginConsoleEntry(
            pluginID: manifest.id,
            level: level,
            message: message,
            elapsedMilliseconds: elapsedMilliseconds
        )
        consoleRing.append(entry)
    }

    func checkTimeoutAndRecordCall(apiName: String) -> Bool {
        bridgeCallCount += 1
        let elapsed = elapsedMilliseconds
        if elapsed > configuration.executionTimeoutMilliseconds {
            let timeoutMsg = "Execution timeout exceeded (\(String(format: "%.1f", elapsed))ms > \(String(format: "%.1f", configuration.executionTimeoutMilliseconds))ms) during \(apiName)"
            capturedJSExceptionMessage = timeoutMsg
            if let ctx = JSContext.current() {
                ctx.exception = JSValue(newErrorFromMessage: timeoutMsg, in: ctx)
            }
            return false
        }
        return true
    }

    func requireCapability(_ capability: MachPluginCapability, for apiName: String) -> Bool {
        guard checkTimeoutAndRecordCall(apiName: apiName) else { return false }
        guard configuration.enforceCapabilityGates else { return true }
        if grantedCapabilities.contains(capability) {
            return true
        }
        let denial = "CapabilityDenied: plugin '\(manifest.id)' is missing capability '\(capability.rawValue)' required by \(apiName)"
        capabilityDenials.append(denial)
        log(.error, denial)
        if configuration.throwJSExceptionOnCapabilityDenial, let ctx = JSContext.current() {
            ctx.exception = JSValue(newErrorFromMessage: denial, in: ctx)
        }
        return false
    }
}

// MARK: - Per-Plugin Isolated JavaScriptCore Sandbox

public struct MachJavaScriptPluginSandbox: Sendable {
    public let configuration: MachPluginSandboxConfiguration

    public init(configuration: MachPluginSandboxConfiguration = .standard) {
        self.configuration = configuration
    }

    // MARK: Primary Execution Entry Points

    public func execute(
        manifest: MachPluginManifest,
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil
    ) throws -> MachPluginExecutionResult {
        try executeDetailed(
            manifest: manifest,
            analysisIndex: analysisIndex,
            binaryData: binaryData
        ).result
    }

    public func execute(
        manifest: MachPluginManifest,
        image: LoadedBinaryImage,
        binaryData: Data? = nil
    ) throws -> MachPluginExecutionResult {
        let coordinator = BinaryAnalysisCoordinator()
        let index: BinaryAnalysisIndex
        if let binaryData {
            index = coordinator.analyzeBinary(image, data: binaryData)
        } else {
            index = coordinator.analyzeBinary(image)
        }
        return try execute(manifest: manifest, analysisIndex: index, binaryData: binaryData)
    }

    public func executeDetailed(
        manifest: MachPluginManifest,
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil
    ) throws -> MachPluginDetailedExecutionReport {
        let startTime = CFAbsoluteTimeGetCurrent()
        let trimmedSource = manifest.scriptSource.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedSource.isEmpty else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: manifest.id,
                message: "Plugin script source is empty"
            )
        }

        // Create an isolated JSVirtualMachine + JSContext strictly for this single plugin run.
        guard let vm = JSVirtualMachine(),
              let context = JSContext(virtualMachine: vm) else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: manifest.id,
                message: "Failed initializing isolated JSVirtualMachine / JSContext"
            )
        }

        context.name = "MachPluginSandbox<\(manifest.id)>"
        let backingBytes = Self.resolveBackingBinaryData(for: analysisIndex.image, explicitData: binaryData)
        let state = SandboxExecutionState(
            manifest: manifest,
            configuration: configuration,
            analysisIndex: analysisIndex,
            resolvedBinaryData: backingBytes,
            startTimestamp: startTime
        )

        context.exceptionHandler = { _, exceptionValue in
            let formatted = Self.formatJSException(exceptionValue)
            state.capturedJSExceptionMessage = formatted
            state.log(.error, "Uncaught JS exception: \(formatted)")
        }

        Self.hardenAmbientGlobalEnvironment(in: context)
        Self.installConsoleBridge(in: context, state: state)
        Self.installMachNativeBridge(in: context, state: state)

        let sourceURL = URL(string: "machplugin://\(Self.sanitizeURLComponent(manifest.id))/main.js")
        _ = context.evaluateScript(manifest.scriptSource, withSourceURL: sourceURL)

        if let exceptionMessage = state.capturedJSExceptionMessage {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: manifest.id,
                message: exceptionMessage
            )
        }

        // Support optional exported entrypoint function `machPluginMain(mach)` or `runPlugin(mach)` if defined.
        if let mainFn = context.objectForKeyedSubscript("machPluginMain"),
           !mainFn.isUndefined && !mainFn.isNull,
           let machObj = context.objectForKeyedSubscript("mach") {
            _ = mainFn.call(withArguments: [machObj])
            if let exceptionMessage = state.capturedJSExceptionMessage {
                throw MachGraphError.pluginExecutionFailed(
                    pluginID: manifest.id,
                    message: exceptionMessage
                )
            }
        }

        let elapsedMs = max(0.0, (CFAbsoluteTimeGetCurrent() - startTime) * 1000.0)
        if elapsedMs > configuration.executionTimeoutMilliseconds {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: manifest.id,
                message: "Execution exceeded timeout budget (\(String(format: "%.1f", elapsedMs))ms > \(String(format: "%.1f", configuration.executionTimeoutMilliseconds))ms)"
            )
        }

        let orderedComments = state.orderedCommentAddresses.compactMap { state.commentsByAddress[$0] }
        let sortedFindings = Self.sortFindings(state.findings)

        let executionResult = MachPluginExecutionResult(
            pluginID: manifest.id,
            durationMilliseconds: elapsedMs,
            findings: sortedFindings,
            generatedComments: orderedComments,
            generatedBookmarks: state.bookmarks,
            consoleLogs: state.consoleRing.formattedLines
        )

        return MachPluginDetailedExecutionReport(
            result: executionResult,
            consoleEntries: state.consoleRing.entries,
            proposedPatches: state.proposedPatches,
            capabilityDenials: state.capabilityDenials,
            bridgeCallCount: state.bridgeCallCount
        )
    }

    // MARK: - Ambient JS Global Hardening & Console Installation

    private static func hardenAmbientGlobalEnvironment(in context: JSContext) {
        let lockdownScript = """
        (function() {
            "use strict";
            try {
                delete globalThis.XMLHttpRequest;
                delete globalThis.fetch;
                delete globalThis.WebSocket;
                delete globalThis.importScripts;
            } catch (_) {}
        })();
        """
        _ = context.evaluateScript(lockdownScript)
    }

    private static func installConsoleBridge(in context: JSContext, state: SandboxExecutionState) {
        let logDebug: @convention(block) () -> Void = {
            let msg = Self.joinArguments(JSContext.currentArguments())
            state.log(.debug, msg)
        }
        let logInfo: @convention(block) () -> Void = {
            let msg = Self.joinArguments(JSContext.currentArguments())
            state.log(.info, msg)
        }
        let logWarn: @convention(block) () -> Void = {
            let msg = Self.joinArguments(JSContext.currentArguments())
            state.log(.warn, msg)
        }
        let logError: @convention(block) () -> Void = {
            let msg = Self.joinArguments(JSContext.currentArguments())
            state.log(.error, msg)
        }

        guard let consoleObj = JSValue(newObjectIn: context) else { return }
        consoleObj.setObject(logDebug, forKeyedSubscript: "debug" as NSString)
        consoleObj.setObject(logInfo, forKeyedSubscript: "log" as NSString)
        consoleObj.setObject(logInfo, forKeyedSubscript: "info" as NSString)
        consoleObj.setObject(logWarn, forKeyedSubscript: "warn" as NSString)
        consoleObj.setObject(logError, forKeyedSubscript: "error" as NSString)
        context.setObject(consoleObj, forKeyedSubscript: "console" as NSString)
    }

    // MARK: - Native `mach.*` Bridge Installation

    private static func installMachNativeBridge(in context: JSContext, state: SandboxExecutionState) {
        guard let machObj = JSValue(newObjectIn: context) else { return }

        // 0. Ungated Plugin Metadata & Capability Query Helpers
        let getPluginInfoBlock: @convention(block) () -> [String: Any] = {
            guard state.checkTimeoutAndRecordCall(apiName: "mach.getPluginInfo") else { return [:] }
            return [
                "id": state.manifest.id,
                "name": state.manifest.name,
                "version": state.manifest.version,
                "author": state.manifest.author,
                "summary": state.manifest.summary,
                "isBuiltIn": state.manifest.isBuiltIn,
                "capabilities": state.manifest.capabilities.map(\.rawValue)
            ]
        }

        let hasCapabilityBlock: @convention(block) (JSValue) -> Bool = { capVal in
            guard state.checkTimeoutAndRecordCall(apiName: "mach.hasCapability") else { return false }
            guard let raw = Self.extractNonEmptyString(from: capVal),
                  let cap = MachPluginCapability(rawValue: raw) else {
                return false
            }
            return state.grantedCapabilities.contains(cap)
        }

        // 1. Gated by `.readBinaryBytes`
        let getImageSummaryBlock: @convention(block) () -> Any = {
            guard state.requireCapability(.readBinaryBytes, for: "mach.getImageSummary") else {
                return NSNull()
            }
            if let cached = state.cachedImageSummary {
                return cached
            }
            let summary = Self.serializeImageSummary(index: state.analysisIndex)
            state.cachedImageSummary = summary
            return summary
        }

        let getSegmentsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readBinaryBytes, for: "mach.getSegments") else {
                return []
            }
            if let cached = state.cachedSegments {
                return cached
            }
            let built = state.analysisIndex.image.segments.map(Self.serializeSegment)
            state.cachedSegments = built
            return built
        }

        let getSectionsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readBinaryBytes, for: "mach.getSections") else {
                return []
            }
            if let cached = state.cachedSections {
                return cached
            }
            let built = state.analysisIndex.image.sections.map(Self.serializeSection)
            state.cachedSections = built
            return built
        }

        let getCodeSignatureBlock: @convention(block) () -> Any = {
            guard state.requireCapability(.readBinaryBytes, for: "mach.getCodeSignature") else {
                return NSNull()
            }
            if let cached = state.cachedCodeSignature {
                return cached
            }
            let built = Self.serializeCodeSignature(state.analysisIndex.image.codeSignature)
            state.cachedCodeSignature = built
            return built
        }

        let readBytesHexBlock: @convention(block) (JSValue, JSValue) -> Any = { addrVal, lenVal in
            guard state.requireCapability(.readBinaryBytes, for: "mach.readBytesHex") else {
                return NSNull()
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image) else {
                state.log(.warn, "mach.readBytesHex: invalid virtual address '\(addrVal.toString() ?? "nil")'")
                return ""
            }
            let requestedLen = Int(lenVal.toInt32())
            guard requestedLen > 0 else { return "" }

            let clampedLen = min(requestedLen, state.configuration.maxReadBytesPerCall)
            if state.totalReadBytes + clampedLen > state.configuration.maxTotalReadBytes {
                let quotaMsg = "mach.readBytesHex exceeded total byte read budget (\(state.configuration.maxTotalReadBytes) bytes)"
                state.log(.warn, quotaMsg)
                if let ctx = JSContext.current() {
                    ctx.exception = JSValue(newErrorFromMessage: quotaMsg, in: ctx)
                }
                return ""
            }

            let bytes = Self.readMappedBytes(
                at: vmAddress,
                length: clampedLen,
                analysisIndex: state.analysisIndex,
                binaryData: state.resolvedBinaryData
            )
            state.totalReadBytes += bytes.count
            return bytes.map { String(format: "%02x", $0) }.joined()
        }

        let getChainedFixupsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readBinaryBytes, for: "mach.getChainedFixups") else {
                return []
            }
            return state.analysisIndex.image.chainedFixups.prefix(state.configuration.maxExposedSymbols).map { fixup in
                [
                    "locationHex": fixup.location.compactHexString,
                    "fileOffsetHex": fixup.fileOffset.hexString,
                    "kind": fixup.kind.rawValue,
                    "targetAddressHex": fixup.targetAddress?.compactHexString ?? NSNull(),
                    "symbolName": fixup.symbolName ?? NSNull(),
                    "libraryOrdinal": fixup.libraryOrdinal ?? NSNull(),
                    "addend": NSNumber(value: fixup.addend),
                    "pacDiversity": fixup.pacDiversity.map { NSNumber(value: $0) } ?? NSNull(),
                    "pacKey": fixup.pacKey ?? NSNull()
                ]
            }
        }

        let findBytePatternHexBlock: @convention(block) (JSValue) -> [[String: Any]] = { patternVal in
            guard state.requireCapability(.readBinaryBytes, for: "mach.findBytePatternHex") else {
                return []
            }
            guard let rawPattern = Self.extractNonEmptyString(from: patternVal),
                  let compiledPattern = Self.compileWildcardHexPattern(rawPattern) else {
                state.log(.warn, "mach.findBytePatternHex: invalid hex pattern (expected e.g. 'fd 7b ?? a9')")
                return []
            }
            return Self.scanBinaryForWildcardPattern(
                compiledPattern,
                analysisIndex: state.analysisIndex,
                binaryData: state.resolvedBinaryData,
                maxMatches: 128
            )
        }

        // 2. Gated by `.readSymbolTable`
        let getSymbolsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getSymbols") else {
                return []
            }
            if let cached = state.cachedSymbols {
                return cached
            }
            let capped = state.analysisIndex.image.symbols.prefix(state.configuration.maxExposedSymbols)
            let built = capped.map { Self.serializeSymbol($0, libraries: state.analysisIndex.image.importedLibraries) }
            state.cachedSymbols = built
            return built
        }

        let getImportsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getImports") else {
                return []
            }
            if let cached = state.cachedImports {
                return cached
            }
            let built = Self.serializeImports(index: state.analysisIndex)
            state.cachedImports = built
            return built
        }

        let getImportedLibrariesBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getImportedLibraries") else {
                return []
            }
            if let cached = state.cachedImportedLibraries {
                return cached
            }
            let built = state.analysisIndex.image.importedLibraries.map(Self.serializeImportedLibrary)
            state.cachedImportedLibraries = built
            return built
        }

        let getStringsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getStrings") else {
                return []
            }
            if let cached = state.cachedStrings {
                return cached
            }
            let capped = state.analysisIndex.image.strings.prefix(state.configuration.maxExposedStrings)
            let built = capped.map(Self.serializeStringLiteral)
            state.cachedStrings = built
            return built
        }

        let getObjCClassesBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getObjCClasses") else {
                return []
            }
            if let cached = state.cachedObjCClasses {
                return cached
            }
            let built = state.analysisIndex.image.objcClasses.map(Self.serializeObjCClass)
            state.cachedObjCClasses = built
            return built
        }

        let getSwiftTypesBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readSymbolTable, for: "mach.getSwiftTypes") else {
                return []
            }
            if let cached = state.cachedSwiftTypes {
                return cached
            }
            let built = state.analysisIndex.image.swiftTypes.map(Self.serializeSwiftType)
            state.cachedSwiftTypes = built
            return built
        }

        // 3. Gated by `.readControlFlowGraph`
        let getFunctionsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readControlFlowGraph, for: "mach.getFunctions") else {
                return []
            }
            if let cached = state.cachedFunctions {
                return cached
            }
            let capped = state.analysisIndex.functions.prefix(state.configuration.maxExposedFunctions)
            let built = capped.map(Self.serializeFunctionSummary)
            state.cachedFunctions = built
            return built
        }

        let getCFGBlock: @convention(block) (JSValue) -> Any = { addrVal in
            guard state.requireCapability(.readControlFlowGraph, for: "mach.getCFG") else {
                return NSNull()
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image) else {
                return NSNull()
            }
            let matchedFn = state.analysisIndex.function(at: vmAddress)
                ?? state.analysisIndex.function(containing: vmAddress)
            guard let fn = matchedFn else {
                return NSNull()
            }
            return Self.serializeFullCFG(for: fn)
        }

        let getXrefsToBlock: @convention(block) (JSValue) -> [[String: Any]] = { addrVal in
            guard state.requireCapability(.readControlFlowGraph, for: "mach.getXrefsTo") else {
                return []
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image) else {
                return []
            }
            let records = state.analysisIndex.xrefsTo(address: vmAddress)
            return records.map { Self.serializeXref($0, index: state.analysisIndex) }
        }

        let getXrefsFromBlock: @convention(block) (JSValue) -> [[String: Any]] = { addrVal in
            guard state.requireCapability(.readControlFlowGraph, for: "mach.getXrefsFrom") else {
                return []
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image) else {
                return []
            }
            let records = state.analysisIndex.xrefsFrom(address: vmAddress)
            return records.map { Self.serializeXref($0, index: state.analysisIndex) }
        }

        let getDangerousSinkPathsBlock: @convention(block) () -> [[String: Any]] = {
            guard state.requireCapability(.readControlFlowGraph, for: "mach.getDangerousSinkPaths") else {
                return []
            }
            if let cached = state.cachedDangerousSinkPaths {
                return cached
            }
            let built = state.analysisIndex.dangerousSinkPaths.map {
                Self.serializeSinkPath($0, index: state.analysisIndex)
            }
            state.cachedDangerousSinkPaths = built
            return built
        }

        // 4. Gated by `.writeDatabaseAnnotations`
        let addCommentBlock: @convention(block) (JSValue, JSValue) -> Bool = { addrVal, textVal in
            guard state.requireCapability(.writeDatabaseAnnotations, for: "mach.addComment") else {
                return false
            }
            guard state.orderedCommentAddresses.count < state.configuration.maxGeneratedAnnotations else {
                state.log(.warn, "mach.addComment: annotation limit reached")
                return false
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image),
                  let cleanText = Self.extractNonEmptyString(from: textVal) else {
                return false
            }
            if state.commentsByAddress[vmAddress] == nil {
                state.orderedCommentAddresses.append(vmAddress)
            }
            let existing = state.commentsByAddress[vmAddress]
            let mergedText: String
            if let existing, !existing.text.contains(cleanText) {
                mergedText = "\(existing.text) | \(cleanText)"
            } else {
                mergedText = cleanText
            }
            state.commentsByAddress[vmAddress] = UserInlineComment(
                address: vmAddress,
                text: mergedText,
                isRepeatable: false
            )
            return true
        }

        let addBookmarkBlock: @convention(block) (JSValue, JSValue, JSValue) -> Bool = { addrVal, labelVal, colorVal in
            guard state.requireCapability(.writeDatabaseAnnotations, for: "mach.addBookmark") else {
                return false
            }
            guard state.bookmarks.count < state.configuration.maxGeneratedAnnotations else {
                state.log(.warn, "mach.addBookmark: annotation limit reached")
                return false
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image),
                  let cleanLabel = Self.extractNonEmptyString(from: labelVal) else {
                return false
            }
            let colorOrTag = Self.extractNonEmptyString(from: colorVal) ?? "#58A6FF"
            let bookmark = UserBookmark(
                address: vmAddress,
                label: cleanLabel,
                categoryTag: colorOrTag
            )
            state.bookmarks.append(bookmark)
            return true
        }

        // 5. Gated by `.emitSecurityFindings`
        let emitFindingBlock: @convention(block) (JSValue) -> Bool = { payloadVal in
            guard state.requireCapability(.emitSecurityFindings, for: "mach.emitFinding") else {
                return false
            }
            guard state.findings.count < state.configuration.maxEmittedFindings else {
                state.log(.warn, "mach.emitFinding: finding quota (\(state.configuration.maxEmittedFindings)) reached")
                return false
            }
            guard payloadVal.isObject, let dict = payloadVal.toDictionary() else {
                state.log(.warn, "mach.emitFinding expects a dictionary payload")
                return false
            }

            let rawSeverity = (dict["severity"] as? String) ?? "INFO"
            let severity = Self.parseSeverity(rawSeverity)
            let category = ((dict["category"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap {
                $0.isEmpty ? nil : $0
            } ?? "General Audit"
            let title = ((dict["title"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)) ?? ""
            guard !title.isEmpty else {
                state.log(.warn, "mach.emitFinding rejected finding with empty title")
                return false
            }
            let detail = ((dict["detail"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)) ?? ""

            var parsedAddress: VirtualAddress?
            if let addrProp = payloadVal.forProperty("addressHex"), !addrProp.isUndefined && !addrProp.isNull {
                parsedAddress = Self.parseVirtualAddress(from: addrProp, image: state.analysisIndex.image)
            } else if let fallbackProp = payloadVal.forProperty("address"), !fallbackProp.isUndefined && !fallbackProp.isNull {
                parsedAddress = Self.parseVirtualAddress(from: fallbackProp, image: state.analysisIndex.image)
            }

            let evidencePreview: String? = {
                guard let rawEv = dict["evidencePreview"] as? String else { return nil }
                let trimmed = rawEv.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? nil : trimmed
            }()

            let dedupKey = "\(severity.rawValue)|\(category)|\(title)|\(parsedAddress?.hexString ?? "none")"
            guard state.findingDedupKeys.insert(dedupKey).inserted else {
                return false
            }

            let finding = SecurityAuditFinding(
                pluginID: state.manifest.id,
                pluginName: state.manifest.name,
                severity: severity,
                category: category,
                title: title,
                detail: detail,
                address: parsedAddress,
                evidencePreview: evidencePreview
            )
            state.findings.append(finding)
            return true
        }

        // 6. Gated by `.proposeInlinePatches`
        let proposePatchBlock: @convention(block) (JSValue, JSValue, JSValue) -> Bool = { addrVal, hexVal, noteVal in
            guard state.requireCapability(.proposeInlinePatches, for: "mach.proposePatch") else {
                return false
            }
            guard state.proposedPatches.count < state.configuration.maxProposedPatches else {
                state.log(.warn, "mach.proposePatch: proposed patch limit reached")
                return false
            }
            guard let vmAddress = Self.parseVirtualAddress(from: addrVal, image: state.analysisIndex.image),
                  let rawHex = Self.extractNonEmptyString(from: hexVal),
                  let bytes = Self.parseHexByteString(rawHex),
                  !bytes.isEmpty else {
                state.log(.warn, "mach.proposePatch: invalid address or hex byte sequence")
                return false
            }
            let note = Self.extractNonEmptyString(from: noteVal) ?? "Proposed by \(state.manifest.name)"
            let fileOffset = state.analysisIndex.image.fileOffset(for: vmAddress)
            state.proposedPatches.append(
                MachPluginProposedPatch(
                    pluginID: state.manifest.id,
                    virtualAddress: vmAddress,
                    fileOffset: fileOffset,
                    patchedBytes: bytes,
                    note: note
                )
            )
            return true
        }

        machObj.setObject(getPluginInfoBlock, forKeyedSubscript: "getPluginInfo" as NSString)
        machObj.setObject(hasCapabilityBlock, forKeyedSubscript: "hasCapability" as NSString)

        machObj.setObject(getImageSummaryBlock, forKeyedSubscript: "getImageSummary" as NSString)
        machObj.setObject(getSegmentsBlock, forKeyedSubscript: "getSegments" as NSString)
        machObj.setObject(getSectionsBlock, forKeyedSubscript: "getSections" as NSString)
        machObj.setObject(getCodeSignatureBlock, forKeyedSubscript: "getCodeSignature" as NSString)
        machObj.setObject(readBytesHexBlock, forKeyedSubscript: "readBytesHex" as NSString)
        machObj.setObject(getChainedFixupsBlock, forKeyedSubscript: "getChainedFixups" as NSString)
        machObj.setObject(findBytePatternHexBlock, forKeyedSubscript: "findBytePatternHex" as NSString)

        machObj.setObject(getSymbolsBlock, forKeyedSubscript: "getSymbols" as NSString)
        machObj.setObject(getImportsBlock, forKeyedSubscript: "getImports" as NSString)
        machObj.setObject(getImportedLibrariesBlock, forKeyedSubscript: "getImportedLibraries" as NSString)
        machObj.setObject(getStringsBlock, forKeyedSubscript: "getStrings" as NSString)
        machObj.setObject(getObjCClassesBlock, forKeyedSubscript: "getObjCClasses" as NSString)
        machObj.setObject(getSwiftTypesBlock, forKeyedSubscript: "getSwiftTypes" as NSString)

        machObj.setObject(getFunctionsBlock, forKeyedSubscript: "getFunctions" as NSString)
        machObj.setObject(getCFGBlock, forKeyedSubscript: "getCFG" as NSString)
        machObj.setObject(getXrefsToBlock, forKeyedSubscript: "getXrefsTo" as NSString)
        machObj.setObject(getXrefsFromBlock, forKeyedSubscript: "getXrefsFrom" as NSString)
        machObj.setObject(getDangerousSinkPathsBlock, forKeyedSubscript: "getDangerousSinkPaths" as NSString)

        machObj.setObject(addCommentBlock, forKeyedSubscript: "addComment" as NSString)
        machObj.setObject(addBookmarkBlock, forKeyedSubscript: "addBookmark" as NSString)
        machObj.setObject(emitFindingBlock, forKeyedSubscript: "emitFinding" as NSString)
        machObj.setObject(proposePatchBlock, forKeyedSubscript: "proposePatch" as NSString)

        context.setObject(machObj, forKeyedSubscript: "mach" as NSString)
    }

    // MARK: - Domain Model -> JavaScript Bridge Serialization

    private static func serializeImageSummary(index: BinaryAnalysisIndex) -> [String: Any] {
        let image = index.image
        let isARM64E: Bool = {
            if case .arm64e = image.architecture { return true }
            return false
        }()
        return [
            "id": image.id.uuidString,
            "fileName": image.fileName,
            "filePath": image.filePath,
            "fileSize": NSNumber(value: image.fileSize),
            "sha256Hex": image.sha256Hex,
            "containerFormat": image.containerFormat.rawValue,
            "selectedSliceIndex": image.selectedSliceIndex,
            "sliceCount": max(1, image.slices.count),
            "architecture": image.architecture.displayName,
            "isARM64Family": image.architecture.isARM64Family,
            "isARM64E": isARM64E,
            "endianness": image.endianness.rawValue,
            "isPositionIndependent": image.isPositionIndependent,
            "imageBaseHex": image.imageBase.compactHexString,
            "entryPointHex": image.entryPoint?.compactHexString ?? NSNull(),
            "uuidString": image.uuidString ?? NSNull(),
            "platformName": image.platformName,
            "minOSVersion": image.minOSVersion,
            "sdkVersion": image.sdkVersion,
            "overallEntropy": image.overallEntropy,
            "isSigned": image.codeSignature.isSigned,
            "isAdHoc": image.codeSignature.isAdHoc,
            "segmentCount": image.segments.count,
            "sectionCount": image.sections.count,
            "symbolCount": image.symbols.count,
            "importLibraryCount": image.importedLibraries.count,
            "stringCount": image.strings.count,
            "objcClassCount": image.objcClasses.count,
            "swiftTypeCount": image.swiftTypes.count,
            "functionCount": index.functions.count
        ]
    }

    private static func serializeSegment(_ segment: BinarySegment) -> [String: Any] {
        [
            "name": segment.name,
            "vmAddressHex": segment.vmAddress.compactHexString,
            "vmSize": NSNumber(value: segment.vmSize),
            "fileOffsetHex": segment.fileOffset.hexString,
            "fileOffset": NSNumber(value: segment.fileOffset.rawValue),
            "fileSize": NSNumber(value: segment.fileSize),
            "initialProtection": segment.initialProtection.rwxString,
            "maxProtection": segment.maxProtection.rwxString,
            "isReadable": segment.initialProtection.contains(.read),
            "isWritable": segment.initialProtection.contains(.write),
            "isExecutable": segment.initialProtection.contains(.execute),
            "allowsRWX": (segment.initialProtection.contains(.write) && segment.initialProtection.contains(.execute))
                || (segment.maxProtection.contains(.write) && segment.maxProtection.contains(.execute) && segment.name != "__PAGEZERO"),
            "flags": NSNumber(value: segment.flags),
            "sectionCount": segment.sections.count
        ]
    }

    private static func serializeSection(_ section: BinarySection) -> [String: Any] {
        [
            "index": section.index,
            "segmentName": section.segmentName,
            "sectionName": section.sectionName,
            "fullName": section.fullName,
            "vmAddressHex": section.vmAddress.compactHexString,
            "size": NSNumber(value: section.size),
            "fileOffsetHex": section.fileOffset.hexString,
            "fileOffset": NSNumber(value: section.fileOffset.rawValue),
            "alignment": NSNumber(value: section.alignment),
            "flags": NSNumber(value: section.flags),
            "kind": section.kind.rawValue,
            "permissions": section.permissions.rwxString,
            "isWritable": section.permissions.contains(.write),
            "isExecutable": section.permissions.contains(.execute),
            "shannonEntropy": section.shannonEntropy
        ]
    }

    private static func serializeCodeSignature(_ signature: CodeSignatureSummary) -> [String: Any] {
        let flags = signature.flags
        return [
            "isSigned": signature.isSigned,
            "isAdHoc": signature.isAdHoc,
            "identifier": signature.identifier,
            "teamIdentifier": signature.teamIdentifier ?? NSNull(),
            "cdHashHex": signature.cdHashHex,
            "hashAlgorithm": signature.hashAlgorithm,
            "codeDirectoryVersion": NSNumber(value: signature.codeDirectoryVersion),
            "pageSize": signature.pageSize,
            "flags": NSNumber(value: flags),
            "flagsHex": String(format: "0x%08x", flags),
            "hasHardenedRuntime": (flags & CodeSignatureConstants.flagRuntime) != 0,
            "hasLibraryValidation": (flags & CodeSignatureConstants.flagRequireLV) != 0,
            "hasRestrictFlag": (flags & CodeSignatureConstants.flagRestrict) != 0,
            "hasEnforcementFlag": (flags & CodeSignatureConstants.flagEnforcement) != 0,
            "isLinkerSigned": (flags & CodeSignatureConstants.flagLinkerSigned) != 0,
            "entitlementsXML": signature.entitlementsXML ?? NSNull(),
            "entitlements": signature.entitlementsPairs,
            "cmsSignerCommonNames": signature.cmsSignerCommonNames
        ]
    }

    private static func serializeSymbol(
        _ symbol: BinarySymbol,
        libraries: [ImportedLibrary]
    ) -> [String: Any] {
        let libName: String? = {
            guard let ord = symbol.libraryOrdinal, ord > 0 else { return nil }
            return libraries.first(where: { $0.ordinal == ord })?.shortName
        }()
        return [
            "name": symbol.name,
            "demangledName": symbol.demangledName,
            "bareName": stripLeadingUnderscore(symbol.name),
            "kind": symbol.kind.rawValue,
            "binding": symbol.binding.rawValue,
            "addressHex": symbol.address.compactHexString,
            "size": NSNumber(value: symbol.size),
            "sectionIndex": symbol.sectionIndex ?? NSNull(),
            "libraryOrdinal": symbol.libraryOrdinal ?? NSNull(),
            "libraryName": libName ?? NSNull(),
            "isImported": symbol.kind == .importedStub || symbol.binding == .external,
            "isExported": symbol.kind == .exportedEntry || (symbol.binding == .global && symbol.address.rawValue != 0)
        ]
    }

    private static func serializeImportedLibrary(_ lib: ImportedLibrary) -> [String: Any] {
        [
            "ordinal": lib.ordinal,
            "installName": lib.installName,
            "shortName": lib.shortName,
            "currentVersion": lib.currentVersion,
            "compatibilityVersion": lib.compatibilityVersion,
            "isWeak": lib.isWeak,
            "isReexport": lib.isReexport
        ]
    }

    private static func serializeImports(index: BinaryAnalysisIndex) -> [[String: Any]] {
        let image = index.image
        var libByOrdinal: [Int: ImportedLibrary] = [:]
        for lib in image.importedLibraries {
            libByOrdinal[lib.ordinal] = lib
        }

        // Group import call sites by bare symbol name
        var callSitesByBareName: [String: [ImportCallSiteRecord]] = [:]
        for site in index.importCallSites {
            let key = stripLeadingUnderscore(site.importedSymbolName)
            callSitesByBareName[key, default: []].append(site)
        }

        var seenBareNames: Set<String> = []
        var items: [[String: Any]] = []

        for sym in image.symbols where sym.kind == .importedStub || sym.binding == .external {
            let bare = stripLeadingUnderscore(sym.name)
            guard !bare.isEmpty, seenBareNames.insert(bare).inserted else { continue }
            let lib = sym.libraryOrdinal.flatMap { libByOrdinal[$0] }
            let sites = callSitesByBareName[bare] ?? []
            let serializedSites: [[String: Any]] = sites.map { site in
                [
                    "callAddressHex": site.callInstructionAddress.compactHexString,
                    "callerAddressHex": site.callerFunctionAddress?.compactHexString ?? NSNull(),
                    "callerName": site.callerFunctionName ?? NSNull(),
                    "stubOrGOTAddressHex": site.stubOrGOTAddress.compactHexString,
                    "isTailCall": site.isTailCall
                ]
            }
            items.append([
                "name": sym.name,
                "demangledName": sym.demangledName,
                "bareName": bare,
                "addressHex": sym.address.compactHexString,
                "libraryOrdinal": sym.libraryOrdinal ?? NSNull(),
                "libraryInstallName": lib?.installName ?? NSNull(),
                "libraryShortName": lib?.shortName ?? sites.first?.libraryName ?? NSNull(),
                "isWeakLibrary": lib?.isWeak ?? false,
                "callSiteCount": sites.count,
                "callSites": serializedSites
            ])
        }

        // Include any resolved ChainedFixup / stub call sites not already represented in `symbols`
        for (bare, sites) in callSitesByBareName where seenBareNames.insert(bare).inserted {
            guard let first = sites.first else { continue }
            let serializedSites: [[String: Any]] = sites.map { site in
                [
                    "callAddressHex": site.callInstructionAddress.compactHexString,
                    "callerAddressHex": site.callerFunctionAddress?.compactHexString ?? NSNull(),
                    "callerName": site.callerFunctionName ?? NSNull(),
                    "stubOrGOTAddressHex": site.stubOrGOTAddress.compactHexString,
                    "isTailCall": site.isTailCall
                ]
            }
            items.append([
                "name": first.importedSymbolName,
                "demangledName": first.demangledSymbolName,
                "bareName": bare,
                "addressHex": first.stubOrGOTAddress.compactHexString,
                "libraryOrdinal": NSNull(),
                "libraryInstallName": first.libraryName ?? NSNull(),
                "libraryShortName": first.libraryName ?? NSNull(),
                "isWeakLibrary": false,
                "callSiteCount": sites.count,
                "callSites": serializedSites
            ])
        }

        return items.sorted {
            let lhs = ($0["bareName"] as? String) ?? ""
            let rhs = ($1["bareName"] as? String) ?? ""
            return lhs < rhs
        }
    }

    private static func serializeStringLiteral(_ literal: ExtractedStringLiteral) -> [String: Any] {
        [
            "addressHex": literal.address.compactHexString,
            "fileOffsetHex": literal.fileOffset.hexString,
            "encoding": literal.encoding.rawValue,
            "value": literal.value,
            "sectionName": literal.sectionName,
            "lengthBytes": literal.lengthBytes
        ]
    }

    private static func serializeObjCClass(_ cls: ObjCClassMetadata) -> [String: Any] {
        let methods: [[String: Any]] = cls.methods.map { method in
            [
                "selector": method.selector,
                "typeEncoding": method.typeEncoding,
                "implementationAddressHex": method.implementationAddress.compactHexString,
                "isClassMethod": method.isClassMethod
            ]
        }
        let ivars: [[String: Any]] = cls.ivars.map { ivar in
            [
                "name": ivar.name,
                "typeEncoding": ivar.typeEncoding,
                "offset": NSNumber(value: ivar.offset),
                "size": NSNumber(value: ivar.size)
            ]
        }
        return [
            "name": cls.name,
            "superclassName": cls.superclassName ?? NSNull(),
            "addressHex": cls.address.compactHexString,
            "instanceSize": NSNumber(value: cls.instanceSize),
            "flags": NSNumber(value: cls.flags),
            "adoptedProtocols": cls.adoptedProtocols,
            "methods": methods,
            "ivars": ivars
        ]
    }

    private static func serializeSwiftType(_ descriptor: SwiftTypeDescriptor) -> [String: Any] {
        [
            "mangledName": descriptor.mangledName,
            "demangledName": descriptor.demangledName,
            "kind": descriptor.kind.rawValue,
            "addressHex": descriptor.address.compactHexString,
            "fieldNames": descriptor.fieldNames,
            "fieldTypes": descriptor.fieldTypes
        ]
    }

    private static func serializeFunctionSummary(_ fn: RecoveredFunction) -> [String: Any] {
        var flatInsns: [[String: Any]] = []
        flatInsns.reserveCapacity(fn.instructionCount)
        for block in fn.blocks {
            for insn in block.instructions {
                flatInsns.append(serializeCompactInstruction(insn))
            }
        }
        return [
            "addressHex": fn.address.compactHexString,
            "endAddressHex": fn.endAddress.compactHexString,
            "name": fn.name,
            "demangledName": fn.demangledName,
            "isLeaf": fn.isLeaf,
            "isThunk": fn.isThunk,
            "usesPAC": fn.usesPAC,
            "stackFrameBytes": fn.stackFrameBytes,
            "cyclomaticComplexity": fn.cyclomaticComplexity,
            "instructionCount": fn.instructionCount,
            "blockCount": fn.blocks.count,
            "edgeCount": fn.edges.count,
            "loopCount": fn.naturalLoops.count,
            "jumpTableCount": fn.jumpTables.count,
            "instructions": flatInsns
        ]
    }

    private static func serializeCompactInstruction(_ insn: A64DecodedInstruction) -> [String: Any] {
        let isPAC = insn.group == .pacPointerAuth
        var isIndirectJump = false
        var isIndirectCall = false
        var isReturn = false
        var indirectReg: String?
        var targetHex: String?

        switch insn.flow {
        case .indirectJump(let reg):
            isIndirectJump = true
            indirectReg = reg.canonicalName
        case .indirectCall(let reg):
            isIndirectCall = true
            indirectReg = reg.canonicalName
        case .returnControl:
            isReturn = true
        case .directCall(let addr), .unconditionalJump(let addr):
            targetHex = addr.compactHexString
        case .conditionalBranch(let addr, _):
            targetHex = addr.compactHexString
        case .sequential, .trapOrSupervisor:
            break
        }

        return [
            "addressHex": insn.address.compactHexString,
            "rawWordHex": String(format: "0x%08x", insn.rawWord),
            "mnemonic": insn.mnemonicText,
            "operandText": insn.operandText,
            "formatted": insn.formattedDisassembly,
            "group": insn.group.rawValue,
            "isPACInstruction": isPAC,
            "isIndirectJump": isIndirectJump,
            "isIndirectCall": isIndirectCall,
            "isReturn": isReturn,
            "indirectRegister": indirectReg ?? NSNull(),
            "targetAddressHex": targetHex ?? NSNull()
        ]
    }

    private static func serializeFullCFG(for fn: RecoveredFunction) -> [String: Any] {
        let serializedBlocks: [[String: Any]] = fn.blocks.map { block in
            let serializedInsns: [[String: Any]] = block.instructions.map { insn in
                var item = serializeCompactInstruction(insn)
                item["rawWord"] = NSNumber(value: insn.rawWord)
                item["rawBytesHex"] = insn.rawBytesHex
                item["operands"] = insn.operands.map(\.description)
                item["readsRegisters"] = insn.readsRegisters.map(\.canonicalName)
                item["writesRegisters"] = insn.writesRegisters.map(\.canonicalName)
                item["readsFlags"] = insn.readsFlags
                item["writesFlags"] = insn.writesFlags
                item["autoComment"] = insn.autoComment ?? NSNull()
                return item
            }
            return [
                "id": block.id,
                "label": block.label,
                "startAddressHex": block.startAddress.compactHexString,
                "endAddressHex": block.endAddress.compactHexString,
                "byteSize": NSNumber(value: block.byteSize),
                "isEntry": block.isEntry,
                "isExit": block.isExit,
                "loopDepth": block.loopDepth,
                "predecessorIDs": block.predecessorIDs,
                "successorIDs": block.successorIDs,
                "instructions": serializedInsns
            ]
        }

        let serializedEdges: [[String: Any]] = fn.edges.map { edge in
            let kindName: String
            switch edge.kind {
            case .unconditional: kindName = "unconditional"
            case .conditionalTrue: kindName = "conditionalTrue"
            case .conditionalFalse: kindName = "conditionalFalse"
            case .fallthroughEdge: kindName = "fallthrough"
            case .switchCase: kindName = "switchCase"
            }
            return [
                "sourceBlockID": edge.sourceBlockID,
                "targetBlockID": edge.targetBlockID,
                "kind": kindName,
                "label": edge.kind.displayLabel ?? NSNull(),
                "isBackEdge": edge.isBackEdge
            ]
        }

        let serializedLoops: [[String: Any]] = fn.naturalLoops.map { loop in
            [
                "headerBlockID": loop.headerBlockID,
                "latchBlockIDs": loop.latchBlockIDs,
                "bodyBlockIDs": loop.bodyBlockIDs,
                "exitBlockIDs": loop.exitBlockIDs,
                "nestingDepth": loop.nestingDepth
            ]
        }

        let serializedJumpTables: [[String: Any]] = fn.jumpTables.map { jt in
            [
                "dispatchAddressHex": jt.dispatchInstructionAddress.compactHexString,
                "tableBaseAddressHex": jt.tableBaseAddress.compactHexString,
                "entryByteSize": jt.entryByteSize,
                "targetAddressesHex": jt.targetAddresses.map(\.compactHexString)
            ]
        }

        return [
            "functionAddressHex": fn.address.compactHexString,
            "endAddressHex": fn.endAddress.compactHexString,
            "name": fn.name,
            "demangledName": fn.demangledName,
            "isLeaf": fn.isLeaf,
            "isThunk": fn.isThunk,
            "usesPAC": fn.usesPAC,
            "stackFrameBytes": fn.stackFrameBytes,
            "cyclomaticComplexity": fn.cyclomaticComplexity,
            "instructionCount": fn.instructionCount,
            "blocks": serializedBlocks,
            "edges": serializedEdges,
            "naturalLoops": serializedLoops,
            "jumpTables": serializedJumpTables
        ]
    }

    private static func serializeXref(_ xref: XrefRecord, index: BinaryAnalysisIndex) -> [String: Any] {
        let callerFn: RecoveredFunction? = {
            if let fnAddr = xref.fromFunction {
                return index.function(at: fnAddr) ?? index.function(containing: fnAddr)
            }
            return index.function(containing: xref.fromAddress)
        }()
        return [
            "id": xref.id.uuidString,
            "fromAddressHex": xref.fromAddress.compactHexString,
            "fromFunctionHex": (callerFn?.address ?? xref.fromFunction)?.compactHexString ?? NSNull(),
            "fromFunctionName": callerFn?.name ?? NSNull(),
            "fromFunctionDemangledName": callerFn?.demangledName ?? NSNull(),
            "toAddressHex": xref.toAddress.compactHexString,
            "kind": xref.kind.rawValue,
            "instructionPreview": xref.instructionPreview
        ]
    }

    private static func serializeSinkPath(_ route: CallPathRoute, index: BinaryAnalysisIndex) -> [String: Any] {
        let sourceName = index.function(at: route.sourceAddress)?.demangledName
            ?? route.hopNames.first
            ?? route.sourceAddress.compactHexString
        let immediateCallerAddress: VirtualAddress? = route.hopAddresses.count >= 2
            ? route.hopAddresses[route.hopAddresses.count - 2]
            : nil
        let immediateCallSite: VirtualAddress? = route.callSiteChain.last
        return [
            "sourceAddressHex": route.sourceAddress.compactHexString,
            "sourceName": sourceName,
            "sinkAddressHex": route.sinkAddress.compactHexString,
            "sinkName": route.sinkName,
            "bareSinkName": stripLeadingUnderscore(route.sinkName),
            "sinkCategory": route.sinkCategory?.rawValue ?? "External Sink",
            "hopCount": route.hopCount,
            "hopAddressesHex": route.hopAddresses.map(\.compactHexString),
            "hopNames": route.hopNames,
            "callSiteChainHex": route.callSiteChain.map(\.compactHexString),
            "immediateCallerAddressHex": immediateCallerAddress?.compactHexString ?? NSNull(),
            "immediateCallSiteHex": immediateCallSite?.compactHexString ?? NSNull(),
            "formattedSummary": route.formattedSummary
        ]
    }

    // MARK: - Mapped Byte Reader & Parsing Utilities

    private static func resolveBackingBinaryData(
        for image: LoadedBinaryImage,
        explicitData: Data?
    ) -> Data? {
        if let explicitData, !explicitData.isEmpty {
            return explicitData
        }
        if !image.filePath.isEmpty,
           !image.filePath.hasPrefix("<"),
           FileManager.default.fileExists(atPath: image.filePath),
           let diskData = try? Data(contentsOf: URL(fileURLWithPath: image.filePath), options: [.mappedIfSafe]) {
            return diskData
        }
        return nil
    }

    private static func readMappedBytes(
        at vmAddress: VirtualAddress,
        length: Int,
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data?
    ) -> [UInt8] {
        guard length > 0 else { return [] }
        let image = analysisIndex.image

        if let binaryData,
           let fileOff = image.fileOffset(for: vmAddress),
           fileOff.rawValue < UInt64(binaryData.count) {
            let startIdx = binaryData.startIndex + Int(fileOff.rawValue)
            let available = max(0, binaryData.endIndex - startIdx)
            let take = min(length, available)
            if take > 0 {
                return Array(binaryData[startIdx..<(startIdx + take)])
            }
        }

        // Fallback when running purely against an in-memory `BinaryAnalysisIndex` without raw `Data`:
        // reconstruct bytes from decoded instructions or extracted string literals if mapped.
        var reconstructed: [UInt8] = []
        reconstructed.reserveCapacity(min(length, 256))
        var cursor = vmAddress
        var remaining = length
        while remaining > 0 {
            let aligned = cursor.alignedDown(to: 4)
            if let insn = analysisIndex.instruction(at: aligned) {
                let byteInWord = Int(cursor.rawValue - aligned.rawValue)
                let wordBytes = insn.rawBytesLE
                for idx in byteInWord..<4 where remaining > 0 {
                    reconstructed.append(wordBytes[idx])
                    cursor = cursor.adding(UInt64(1))
                    remaining -= 1
                }
            } else if let strLit = image.strings.first(where: {
                cursor >= $0.address && cursor < $0.address.adding(UInt64($0.lengthBytes))
            }) {
                let utf8 = Array(strLit.value.utf8) + [0]
                let offsetInStr = Int(cursor.rawValue - strLit.address.rawValue)
                guard offsetInStr < utf8.count else { break }
                for idx in offsetInStr..<utf8.count where remaining > 0 {
                    reconstructed.append(utf8[idx])
                    cursor = cursor.adding(UInt64(1))
                    remaining -= 1
                }
            } else {
                break
            }
        }
        return reconstructed
    }

    private static func parseVirtualAddress(
        from jsValue: JSValue?,
        image: LoadedBinaryImage
    ) -> VirtualAddress? {
        guard let jsValue, !jsValue.isUndefined, !jsValue.isNull else { return nil }
        if jsValue.isNumber {
            let num = jsValue.toDouble()
            guard num.isFinite && num >= 0 && num <= Double(UInt64.max) else { return nil }
            return VirtualAddress(UInt64(num))
        }
        guard let rawString = jsValue.toString()?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawString.isEmpty else {
            return nil
        }
        let cleaned = rawString.replacingOccurrences(of: "_", with: "")
        if cleaned.lowercased().hasPrefix("0x") {
            let hexBody = String(cleaned.dropFirst(2))
            guard let v = UInt64(hexBody, radix: 16) else { return nil }
            return VirtualAddress(v)
        }
        // Prefer hex when `addressHex` contains hex letters OR matches a mapped section in hex
        let containsHexAlpha = cleaned.unicodeScalars.contains {
            ($0 >= "a" && $0 <= "f") || ($0 >= "A" && $0 <= "F")
        }
        if containsHexAlpha, let v = UInt64(cleaned, radix: 16) {
            return VirtualAddress(v)
        }
        if let hexCandidate = UInt64(cleaned, radix: 16) {
            let vaHex = VirtualAddress(hexCandidate)
            if image.section(containing: vaHex) != nil {
                return vaHex
            }
        }
        return VirtualAddress(hexOrDecimal: cleaned)
    }

    private static func parseSeverity(_ raw: String) -> SecurityFindingSeverity {
        switch raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
        case "CRITICAL", "CRIT": return .critical
        case "HIGH": return .high
        case "MEDIUM", "MED", "MODERATE": return .medium
        case "LOW": return .low
        default: return .info
        }
    }

    private static func parseHexByteString(_ text: String) -> [UInt8]? {
        let stripped = text
            .replacingOccurrences(of: "0x", with: "", options: .caseInsensitive)
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: ",", with: "")
        guard !stripped.isEmpty, stripped.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(stripped.count / 2)
        var idx = stripped.startIndex
        while idx < stripped.endIndex {
            let next = stripped.index(idx, offsetBy: 2)
            guard let byte = UInt8(stripped[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        return bytes
    }

    private static func extractNonEmptyString(from jsValue: JSValue?) -> String? {
        guard let jsValue, !jsValue.isUndefined, !jsValue.isNull else { return nil }
        guard let raw = jsValue.toString()?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        return raw
    }

    private static func joinArguments(_ args: [Any]?) -> String {
        guard let args, !args.isEmpty else { return "" }
        return args.map { item -> String in
            if let jsVal = item as? JSValue {
                if jsVal.isUndefined { return "undefined" }
                if jsVal.isNull { return "null" }
                if jsVal.isObject && !jsVal.isString,
                   let dict = jsVal.toObject(),
                   JSONSerialization.isValidJSONObject(dict),
                   let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]),
                   let json = String(data: data, encoding: .utf8) {
                    return json
                }
                return jsVal.toString() ?? ""
            }
            return String(describing: item)
        }.joined(separator: " ")
    }

    private static func formatJSException(_ exception: JSValue?) -> String {
        guard let exception else { return "Unknown JavaScript exception" }
        let message = exception.toString() ?? "JavaScript execution error"
        let line = exception.forProperty("line")
        let column = exception.forProperty("column")
        if let line, line.isNumber {
            let lineNum = line.toInt32()
            if let column, column.isNumber {
                return "\(message) (line \(lineNum), col \(column.toInt32()))"
            }
            return "\(message) (line \(lineNum))"
        }
        return message
    }

    private static func stripLeadingUnderscore(_ symbol: String) -> String {
        if symbol.hasPrefix("_") && !symbol.hasPrefix("__mh_") {
            return String(symbol.dropFirst())
        }
        return symbol
    }

    private static func sanitizeURLComponent(_ raw: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        return String(raw.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
    }

    internal static func sortFindings(_ findings: [SecurityAuditFinding]) -> [SecurityAuditFinding] {
        findings.sorted { lhs, rhs in
            if lhs.severity != rhs.severity {
                return lhs.severity > rhs.severity
            }
            let lhsAddr = lhs.address?.rawValue ?? UInt64.max
            let rhsAddr = rhs.address?.rawValue ?? UInt64.max
            if lhsAddr != rhsAddr {
                return lhsAddr < rhsAddr
            }
            return lhs.title < rhs.title
        }
    }

    // MARK: - Wildcard Hex Byte Signature Scanner

    private static func compileWildcardHexPattern(_ raw: String) -> [UInt8?]? {
        let tokens = raw
            .replacingOccurrences(of: ",", with: " ")
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
        guard !tokens.isEmpty, tokens.count <= 128 else { return nil }

        var compiled: [UInt8?] = []
        for token in tokens {
            let clean = token.hasPrefix("0x") || token.hasPrefix("0X") ? String(token.dropFirst(2)) : token
            if clean == "??" || clean == "?" || clean == "**" {
                compiled.append(nil)
            } else if clean.count == 2, let b = UInt8(clean, radix: 16) {
                compiled.append(b)
            } else {
                return nil
            }
        }
        guard compiled.contains(where: { $0 != nil }) else { return nil }
        return compiled
    }

    private static func scanBinaryForWildcardPattern(
        _ pattern: [UInt8?],
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data?,
        maxMatches: Int
    ) -> [[String: Any]] {
        guard let binaryData, !binaryData.isEmpty, !pattern.isEmpty else { return [] }
        let patLen = pattern.count
        var matches: [[String: Any]] = []
        let image = analysisIndex.image

        for sec in image.sections where sec.kind != .bss && sec.size >= UInt64(patLen) {
            let absOff = Int(image.sliceFileOffset.rawValue + sec.fileOffset.rawValue)
            let secLen = Int(min(sec.size, 2_097_152))
            guard absOff >= 0, absOff + patLen <= binaryData.count else { continue }
            let upper = min(binaryData.count - patLen, absOff + secLen - patLen)
            guard upper >= absOff else { continue }

            var pos = absOff
            while pos <= upper {
                var matchedAll = true
                for k in 0..<patLen {
                    if let expected = pattern[k], binaryData[binaryData.startIndex + pos + k] != expected {
                        matchedAll = false
                        break
                    }
                }
                if matchedAll {
                    let delta = UInt64(pos - absOff)
                    let hitVA = sec.vmAddress.adding(delta)
                    let fn = analysisIndex.function(containing: hitVA)
                    matches.append([
                        "addressHex": hitVA.compactHexString,
                        "fileOffsetHex": FileOffset(UInt64(pos)).hexString,
                        "sectionName": sec.fullName,
                        "functionName": fn?.demangledName ?? NSNull()
                    ])
                    if matches.count >= maxMatches {
                        return matches
                    }
                    pos += patLen
                } else {
                    pos += 1
                }
            }
        }
        return matches
    }
}

// MARK: - Plugin Manifest Validator & Custom Disk Script Loader

public enum MachPluginManifestValidator: Sendable {

    /// Validates manifest fields and verifies JavaScript syntax inside a disposable `JSContext` without executing user code.
    public static func validate(_ manifest: MachPluginManifest) throws {
        let cleanID = manifest.id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanID.isEmpty else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: "<empty>",
                message: "Plugin manifest ID cannot be empty"
            )
        }
        let cleanName = manifest.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: cleanID,
                message: "Plugin display name cannot be empty"
            )
        }
        let cleanScript = manifest.scriptSource.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanScript.isEmpty else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: cleanID,
                message: "Plugin JavaScript source cannot be empty"
            )
        }

        guard let vm = JSVirtualMachine(),
              let ctx = JSContext(virtualMachine: vm) else {
            return
        }
        var syntaxError: String?
        ctx.exceptionHandler = { _, exc in
            syntaxError = exc?.toString() ?? "JavaScript syntax error"
        }
        ctx.setObject(manifest.scriptSource as NSString, forKeyedSubscript: "__src" as NSString)
        _ = ctx.evaluateScript("new Function(__src);")
        if let syntaxError {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: cleanID,
                message: "JavaScript syntax check failed: \(syntaxError)"
            )
        }
    }

    /// Parses header directives (`// @id ...`, `// @name ...`, `// @capability ...`) from a standalone `.js` plugin file.
    public static func loadManifest(fromJavaScriptFile url: URL) throws -> MachPluginManifest {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw MachGraphError.fileNotFound(url.path)
        }
        let source: String
        do {
            source = try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw MachGraphError.ioFailure("Failed reading JS plugin '\(url.path)': \(error.localizedDescription)")
        }

        let fallbackID = url.deletingPathExtension().lastPathComponent
        var pluginID = fallbackID.isEmpty ? "custom-js-plugin" : fallbackID
        var name = pluginID
        var version = "1.0.0"
        var author = "Custom Analyst"
        var summary = "Custom JavaScriptCore reverse-engineering plugin loaded from \(url.lastPathComponent)."
        var parsedCapabilities: [MachPluginCapability] = []

        for rawLine in source.components(separatedBy: .newlines).prefix(40) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("//") || trimmed.hasPrefix("*") else { continue }
            let commentBody = trimmed
                .trimmingCharacters(in: CharacterSet(charactersIn: "/* "))
            if commentBody.hasPrefix("@id ") {
                pluginID = String(commentBody.dropFirst(4)).trimmingCharacters(in: .whitespaces)
            } else if commentBody.hasPrefix("@name ") {
                name = String(commentBody.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            } else if commentBody.hasPrefix("@version ") {
                version = String(commentBody.dropFirst(9)).trimmingCharacters(in: .whitespaces)
            } else if commentBody.hasPrefix("@author ") {
                author = String(commentBody.dropFirst(8)).trimmingCharacters(in: .whitespaces)
            } else if commentBody.hasPrefix("@summary ") {
                summary = String(commentBody.dropFirst(9)).trimmingCharacters(in: .whitespaces)
            } else if commentBody.hasPrefix("@capability ") {
                let rawCap = String(commentBody.dropFirst(12)).trimmingCharacters(in: .whitespaces)
                if let cap = MachPluginCapability(rawValue: rawCap), !parsedCapabilities.contains(cap) {
                    parsedCapabilities.append(cap)
                }
            }
        }

        if parsedCapabilities.isEmpty {
            parsedCapabilities = [
                .readBinaryBytes,
                .readSymbolTable,
                .readControlFlowGraph,
                .emitSecurityFindings
            ]
        }

        let manifest = MachPluginManifest(
            id: pluginID,
            name: name,
            version: version,
            author: author,
            summary: summary,
            capabilities: parsedCapabilities,
            isBuiltIn: false,
            isEnabled: true,
            scriptSource: source
        )
        try validate(manifest)
        return manifest
    }
}
