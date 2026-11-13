import Foundation
import SQLite3
import MachGraphModels

// MARK: - Portable Analyst Annotation Bundle & Options

public struct MachAnnotationBundle: Sendable, Codable, Hashable {
    public static let currentFormatMagic = "MACHGRAPH_ANNOTATION_BUNDLE_V1"
    public static let currentFormatVersion: Int = 1

    public let formatMagic: String
    public let formatVersion: Int
    public let exportedAt: Date
    public let exporterTool: String
    public let projectName: String
    public let binaryFileName: String
    public let binarySHA256: String
    public let containerFormat: BinaryContainerFormat
    public let architecture: CPUArchitecture
    public let imageBase: VirtualAddress
    public let entryPoint: VirtualAddress?
    public let renames: [UserSymbolRename]
    public let comments: [UserInlineComment]
    public let bookmarks: [UserBookmark]
    public let structs: [CustomStructDefinition]
    public let patches: [BytePatchRecord]
    public let findings: [SecurityAuditFinding]
    public let contentSHA256: String

    private struct DigestEnvelope: Codable {
        let binarySHA256: String
        let imageBase: VirtualAddress
        let renames: [UserSymbolRename]
        let comments: [UserInlineComment]
        let bookmarks: [UserBookmark]
        let structs: [CustomStructDefinition]
        let patches: [BytePatchRecord]
        let findings: [SecurityAuditFinding]
    }

    public init(
        formatMagic: String = Self.currentFormatMagic,
        formatVersion: Int = Self.currentFormatVersion,
        exportedAt: Date = Date(),
        exporterTool: String = "MachGraph MachProjectStore 1.0",
        projectName: String,
        binaryFileName: String,
        binarySHA256: String,
        containerFormat: BinaryContainerFormat = .machO64,
        architecture: CPUArchitecture = .arm64,
        imageBase: VirtualAddress = .zero,
        entryPoint: VirtualAddress? = nil,
        renames: [UserSymbolRename],
        comments: [UserInlineComment],
        bookmarks: [UserBookmark],
        structs: [CustomStructDefinition],
        patches: [BytePatchRecord],
        findings: [SecurityAuditFinding] = [],
        contentSHA256: String? = nil
    ) {
        let sortedRenames = renames.sorted { $0.address < $1.address }
        let sortedComments = comments.sorted { $0.address < $1.address }
        let sortedBookmarks = bookmarks.sorted {
            if $0.address != $1.address { return $0.address < $1.address }
            return $0.id.uuidString < $1.id.uuidString
        }
        let sortedStructs = structs.sorted {
            let cmp = $0.name.localizedCaseInsensitiveCompare($1.name)
            if cmp != .orderedSame { return cmp == .orderedAscending }
            return $0.id.uuidString < $1.id.uuidString
        }
        let sortedPatches = patches.sorted {
            if $0.fileOffset != $1.fileOffset { return $0.fileOffset < $1.fileOffset }
            return $0.id.uuidString < $1.id.uuidString
        }
        let sortedFindings = findings.sorted {
            if $0.severity != $1.severity { return $0.severity > $1.severity }
            return $0.id.uuidString < $1.id.uuidString
        }

        self.formatMagic = formatMagic
        self.formatVersion = formatVersion
        self.exportedAt = exportedAt
        self.exporterTool = exporterTool
        self.projectName = projectName
        self.binaryFileName = binaryFileName
        self.binarySHA256 = binarySHA256
        self.containerFormat = containerFormat
        self.architecture = architecture
        self.imageBase = imageBase
        self.entryPoint = entryPoint
        self.renames = sortedRenames
        self.comments = sortedComments
        self.bookmarks = sortedBookmarks
        self.structs = sortedStructs
        self.patches = sortedPatches
        self.findings = sortedFindings

        if let explicitDigest = contentSHA256, !explicitDigest.isEmpty {
            self.contentSHA256 = explicitDigest
        } else {
            self.contentSHA256 = Self.computeCanonicalDigest(
                binarySHA256: binarySHA256,
                imageBase: imageBase,
                renames: sortedRenames,
                comments: sortedComments,
                bookmarks: sortedBookmarks,
                structs: sortedStructs,
                patches: sortedPatches,
                findings: sortedFindings
            )
        }
    }

    public var totalAnnotationCount: Int {
        renames.count + comments.count + bookmarks.count + structs.count + patches.count
    }

    public var enabledPatchCount: Int {
        patches.filter(\.isEnabled).count
    }

    public var criticalFindingCount: Int {
        findings.filter { $0.severity == .critical }.count
    }

    public func verifyContentDigest() -> Bool {
        let expected = Self.computeCanonicalDigest(
            binarySHA256: binarySHA256,
            imageBase: imageBase,
            renames: renames,
            comments: comments,
            bookmarks: bookmarks,
            structs: structs,
            patches: patches,
            findings: findings
        )
        return expected.lowercased() == contentSHA256.lowercased()
    }

    private static func computeCanonicalDigest(
        binarySHA256: String,
        imageBase: VirtualAddress,
        renames: [UserSymbolRename],
        comments: [UserInlineComment],
        bookmarks: [UserBookmark],
        structs: [CustomStructDefinition],
        patches: [BytePatchRecord],
        findings: [SecurityAuditFinding]
    ) -> String {
        let envelope = DigestEnvelope(
            binarySHA256: binarySHA256,
            imageBase: imageBase,
            renames: renames,
            comments: comments,
            bookmarks: bookmarks,
            structs: structs,
            patches: patches,
            findings: findings
        )
        let data = (try? StoreJSONCoding.makeEncoder(prettyPrinted: false, sortedKeys: true).encode(envelope)) ?? Data()
        return BinaryHashAndEntropy.sha256Hex(of: data)
    }
}

public enum AnnotationConflictResolutionPolicy: String, Sendable, Codable, Hashable, CaseIterable {
    case preferImported = "prefer_imported"
    case keepExisting = "keep_existing"
    case preferNewerTimestamp = "prefer_newer_timestamp"
    case replaceAllExisting = "replace_all_existing"
}

public struct AnnotationImportOptions: Sendable, Codable, Hashable {
    public var conflictPolicy: AnnotationConflictResolutionPolicy
    public var verifyContentDigest: Bool
    public var requireMatchingBinarySHA256: Bool
    public var importSecurityFindings: Bool
    public var recordUndoTransactions: Bool
    public var rebaseAddressesToCurrentImageBase: Bool

    public init(
        conflictPolicy: AnnotationConflictResolutionPolicy = .preferImported,
        verifyContentDigest: Bool = true,
        requireMatchingBinarySHA256: Bool = false,
        importSecurityFindings: Bool = true,
        recordUndoTransactions: Bool = true,
        rebaseAddressesToCurrentImageBase: Bool = false
    ) {
        self.conflictPolicy = conflictPolicy
        self.verifyContentDigest = verifyContentDigest
        self.requireMatchingBinarySHA256 = requireMatchingBinarySHA256
        self.importSecurityFindings = importSecurityFindings
        self.recordUndoTransactions = recordUndoTransactions
        self.rebaseAddressesToCurrentImageBase = rebaseAddressesToCurrentImageBase
    }
}

public struct AnnotationImportSummary: Sendable, Codable, Hashable {
    public let sourceProjectName: String
    public let binarySHA256Matched: Bool
    public let contentDigestVerified: Bool
    public let addressSlideApplied: Int64
    public let importedRenames: Int
    public let skippedRenames: Int
    public let importedComments: Int
    public let skippedComments: Int
    public let importedBookmarks: Int
    public let skippedBookmarks: Int
    public let importedStructs: Int
    public let skippedStructs: Int
    public let importedPatches: Int
    public let skippedPatches: Int
    public let importedFindings: Int
    public let warnings: [String]

    public init(
        sourceProjectName: String,
        binarySHA256Matched: Bool,
        contentDigestVerified: Bool,
        addressSlideApplied: Int64,
        importedRenames: Int,
        skippedRenames: Int,
        importedComments: Int,
        skippedComments: Int,
        importedBookmarks: Int,
        skippedBookmarks: Int,
        importedStructs: Int,
        skippedStructs: Int,
        importedPatches: Int,
        skippedPatches: Int,
        importedFindings: Int,
        warnings: [String]
    ) {
        self.sourceProjectName = sourceProjectName
        self.binarySHA256Matched = binarySHA256Matched
        self.contentDigestVerified = contentDigestVerified
        self.addressSlideApplied = addressSlideApplied
        self.importedRenames = importedRenames
        self.skippedRenames = skippedRenames
        self.importedComments = importedComments
        self.skippedComments = skippedComments
        self.importedBookmarks = importedBookmarks
        self.skippedBookmarks = skippedBookmarks
        self.importedStructs = importedStructs
        self.skippedStructs = skippedStructs
        self.importedPatches = importedPatches
        self.skippedPatches = skippedPatches
        self.importedFindings = importedFindings
        self.warnings = warnings
    }

    public var totalImportedCount: Int {
        importedRenames + importedComments + importedBookmarks + importedStructs + importedPatches + importedFindings
    }
}

public struct GhidraScriptExportOptions: Sendable, Codable, Hashable {
    public var rebaseRelativeToImageBase: Bool
    public var includeBytePatches: Bool
    public var includeDisabledPatchesAsComments: Bool
    public var includeCustomStructs: Bool
    public var includeSecurityFindingsAsBookmarks: Bool
    public var structCategoryPath: String

    public init(
        rebaseRelativeToImageBase: Bool = true,
        includeBytePatches: Bool = true,
        includeDisabledPatchesAsComments: Bool = true,
        includeCustomStructs: Bool = true,
        includeSecurityFindingsAsBookmarks: Bool = true,
        structCategoryPath: String = "/MachGraph"
    ) {
        self.rebaseRelativeToImageBase = rebaseRelativeToImageBase
        self.includeBytePatches = includeBytePatches
        self.includeDisabledPatchesAsComments = includeDisabledPatchesAsComments
        self.includeCustomStructs = includeCustomStructs
        self.includeSecurityFindingsAsBookmarks = includeSecurityFindingsAsBookmarks
        self.structCategoryPath = structCategoryPath
    }
}

public struct MarkdownDossierExportOptions: Sendable, Codable, Hashable {
    public var includeExecutiveTelemetry: Bool
    public var includeSecurityFindings: Bool
    public var includeBookmarks: Bool
    public var includeSymbolRenames: Bool
    public var includeInlineComments: Bool
    public var includeCHeaderStructs: Bool
    public var includeBytePatches: Bool
    public var includeDisabledPatches: Bool
    public var includeTopComplexFunctions: Bool
    public var maxFunctionsListed: Int

    public init(
        includeExecutiveTelemetry: Bool = true,
        includeSecurityFindings: Bool = true,
        includeBookmarks: Bool = true,
        includeSymbolRenames: Bool = true,
        includeInlineComments: Bool = true,
        includeCHeaderStructs: Bool = true,
        includeBytePatches: Bool = true,
        includeDisabledPatches: Bool = true,
        includeTopComplexFunctions: Bool = true,
        maxFunctionsListed: Int = 40
    ) {
        self.includeExecutiveTelemetry = includeExecutiveTelemetry
        self.includeSecurityFindings = includeSecurityFindings
        self.includeBookmarks = includeBookmarks
        self.includeSymbolRenames = includeSymbolRenames
        self.includeInlineComments = includeInlineComments
        self.includeCHeaderStructs = includeCHeaderStructs
        self.includeBytePatches = includeBytePatches
        self.includeDisabledPatches = includeDisabledPatches
        self.includeTopComplexFunctions = includeTopComplexFunctions
        self.maxFunctionsListed = max(1, maxFunctionsListed)
    }
}

// MARK: - Portable Analyst Annotation Codec (JSON / Ghidra Python / IDA IDC / Markdown Dossier)

public final class AnalystAnnotationCodec: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    public let database: MachProjectDatabase
    public let undoRedoController: MachUndoRedoController

    public init(
        database: MachProjectDatabase,
        undoRedoController: MachUndoRedoController? = nil
    ) {
        self.database = database
        self.undoRedoController = undoRedoController ?? MachUndoRedoController(database: database)
    }

    @discardableResult
    private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try database.connection.withExclusiveAccess(body)
    }

    // MARK: Standalone JSON Export (MachAnnotationBundle)

    public func exportAnnotationBundle(includeFindings: Bool = true) throws -> MachAnnotationBundle {
        try synchronized {
            let manifest = try database.readBundleMetadata()
            let summary = try database.loadBinaryImageSummary()
            let renames = try database.allRenames()
            let comments = try database.allComments()
            let bookmarks = try database.allBookmarks()
            let structs = try database.allStructs()
            let patches = try database.allPatches()
            let findings = includeFindings ? (try database.allFindings()) : []

            return MachAnnotationBundle(
                projectName: manifest.projectName,
                binaryFileName: summary?.fileName ?? manifest.binaryFileName,
                binarySHA256: summary?.sha256Hex ?? manifest.binarySHA256,
                containerFormat: summary?.containerFormat ?? manifest.containerFormat,
                architecture: summary?.architecture ?? manifest.architecture,
                imageBase: summary?.imageBase ?? manifest.imageBase,
                entryPoint: summary?.entryPoint ?? manifest.entryPoint,
                renames: renames,
                comments: comments,
                bookmarks: bookmarks,
                structs: structs,
                patches: patches,
                findings: findings
            )
        }
    }

    public func exportBundle(includeFindings: Bool = true) throws -> MachAnnotationBundle {
        try exportAnnotationBundle(includeFindings: includeFindings)
    }

    public func exportJSONData(
        prettyPrinted: Bool = true,
        includeFindings: Bool = true
    ) throws -> Data {
        let bundle = try exportAnnotationBundle(includeFindings: includeFindings)
        do {
            return try StoreJSONCoding.makeEncoder(prettyPrinted: prettyPrinted, sortedKeys: true).encode(bundle)
        } catch {
            throw MachGraphError.ioFailure("Failed encoding MachAnnotationBundle to JSON: \(error.localizedDescription)")
        }
    }

    public func exportJSONString(
        prettyPrinted: Bool = true,
        includeFindings: Bool = true
    ) throws -> String {
        let data = try exportJSONData(prettyPrinted: prettyPrinted, includeFindings: includeFindings)
        return String(decoding: data, as: UTF8.self)
    }

    public func writeAnnotationBundle(
        to fileURL: URL,
        prettyPrinted: Bool = true,
        includeFindings: Bool = true
    ) throws {
        let data = try exportJSONData(prettyPrinted: prettyPrinted, includeFindings: includeFindings)
        let parent = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: parent.path) {
            do {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            } catch {
                throw MachGraphError.ioFailure("Failed creating directory '\(parent.path)': \(error.localizedDescription)")
            }
        }
        do {
            try data.write(to: fileURL, options: .atomic)
        } catch {
            throw MachGraphError.ioFailure("Failed writing bundle to '\(fileURL.path)': \(error.localizedDescription)")
        }
    }

    // MARK: Standalone JSON Decode & Import

    public static func decodeAnnotationBundle(
        from data: Data,
        verifyDigest: Bool = true
    ) throws -> MachAnnotationBundle {
        let bundle: MachAnnotationBundle
        do {
            bundle = try StoreJSONCoding.makeDecoder().decode(MachAnnotationBundle.self, from: data)
        } catch {
            throw MachGraphError.ioFailure("Malformed MachAnnotationBundle JSON: \(error.localizedDescription)")
        }

        guard bundle.formatMagic == MachAnnotationBundle.currentFormatMagic else {
            throw MachGraphError.invalidMagic(
                expected: MachAnnotationBundle.currentFormatMagic,
                actualHex: bundle.formatMagic
            )
        }

        if verifyDigest && !bundle.verifyContentDigest() {
            throw MachGraphError.ioFailure(
                "MachAnnotationBundle content SHA-256 verification failed (expected \(bundle.contentSHA256))"
            )
        }
        return bundle
    }

    @discardableResult
    public func importBundle(
        _ bundle: MachAnnotationBundle,
        options: AnnotationImportOptions = AnnotationImportOptions()
    ) throws -> AnnotationImportSummary {
        try importAnnotationBundle(bundle, options: options)
    }

    @discardableResult
    public func importJSONData(
        _ data: Data,
        options: AnnotationImportOptions = AnnotationImportOptions()
    ) throws -> AnnotationImportSummary {
        let bundle = try Self.decodeAnnotationBundle(
            from: data,
            verifyDigest: options.verifyContentDigest
        )
        return try importAnnotationBundle(bundle, options: options)
    }

    @discardableResult
    public func importAnnotationBundle(
        from fileURL: URL,
        options: AnnotationImportOptions = AnnotationImportOptions()
    ) throws -> AnnotationImportSummary {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw MachGraphError.fileNotFound(fileURL.path)
        }
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw MachGraphError.ioFailure("Failed reading '\(fileURL.path)': \(error.localizedDescription)")
        }
        return try importJSONData(data, options: options)
    }

    @discardableResult
    public func importAnnotationBundle(
        _ bundle: MachAnnotationBundle,
        options: AnnotationImportOptions = AnnotationImportOptions()
    ) throws -> AnnotationImportSummary {
        try synchronized {
            var warnings: [String] = []
            let digestOK = bundle.verifyContentDigest()
            if options.verifyContentDigest && !digestOK {
                throw MachGraphError.ioFailure(
                    "Refusing to import tampered MachAnnotationBundle: SHA-256 digest mismatch"
                )
            } else if !digestOK {
                warnings.append("Content SHA-256 digest did not match canonical bundle digest.")
            }

            let localManifest = try database.readBundleMetadata()
            let localSHA = localManifest.binarySHA256
            let shaMatched: Bool
            if localSHA.isEmpty || bundle.binarySHA256.isEmpty {
                shaMatched = true
            } else {
                shaMatched = (localSHA.lowercased() == bundle.binarySHA256.lowercased())
            }

            if !shaMatched {
                if options.requireMatchingBinarySHA256 {
                    throw MachGraphError.ioFailure(
                        "Binary SHA-256 mismatch: bundle targets \(bundle.binarySHA256), project has \(localSHA)"
                    )
                }
                warnings.append("Binary SHA-256 differs (bundle: \(bundle.binarySHA256.prefix(12))..., local: \(localSHA.prefix(12))...).")
            }

            let slide: Int64
            if options.rebaseAddressesToCurrentImageBase && localManifest.imageBase != .zero && bundle.imageBase != .zero {
                slide = localManifest.imageBase - bundle.imageBase
            } else {
                slide = 0
            }

            return try database.withTransaction {
                var mutations: [(title: String, operation: AnalystMutationOperation)] = []
                let tag = "[Import '\(bundle.projectName)']"

                var importedRenames = 0
                var skippedRenames = 0
                var importedComments = 0
                var skippedComments = 0
                var importedBookmarks = 0
                var skippedBookmarks = 0
                var importedStructs = 0
                var skippedStructs = 0
                var importedPatches = 0
                var skippedPatches = 0
                var importedFindingsCount = 0

                if options.conflictPolicy == .replaceAllExisting {
                    for existing in try database.allRenames() {
                        mutations.append(("\(tag) Clear existing rename", .setRename(previous: existing, updated: nil)))
                    }
                    for existing in try database.allComments() {
                        mutations.append(("\(tag) Clear existing comment", .setComment(previous: existing, updated: nil)))
                    }
                    for existing in try database.allBookmarks() {
                        mutations.append(("\(tag) Clear existing bookmark", .setBookmark(previous: existing, updated: nil)))
                    }
                    for existing in try database.allStructs() {
                        mutations.append(("\(tag) Clear existing struct", .setStruct(previous: existing, updated: nil)))
                    }
                    for existing in try database.allPatches() {
                        mutations.append(("\(tag) Clear existing patch", .setPatch(previous: existing, updated: nil)))
                    }
                }

                // 1. Renames
                for incoming in bundle.renames {
                    let adjusted = UserSymbolRename(
                        address: incoming.address.adding(slide),
                        originalName: incoming.originalName,
                        customName: incoming.customName,
                        signatureOverride: incoming.signatureOverride,
                        updatedAt: incoming.updatedAt
                    )
                    let existing = options.conflictPolicy == .replaceAllExisting
                        ? nil
                        : try database.rename(for: adjusted.address)

                    if Self.shouldApplyIncoming(
                        existingTimestamp: existing?.updatedAt,
                        incomingTimestamp: adjusted.updatedAt,
                        hasExisting: existing != nil,
                        policy: options.conflictPolicy
                    ) {
                        mutations.append((
                            "\(tag) Import rename '\(adjusted.customName)' at \(adjusted.address.compactHexString)",
                            .setRename(previous: existing, updated: adjusted)
                        ))
                        importedRenames += 1
                    } else {
                        skippedRenames += 1
                    }
                }

                // 2. Comments
                for incoming in bundle.comments {
                    let adjusted = UserInlineComment(
                        address: incoming.address.adding(slide),
                        text: incoming.text,
                        isRepeatable: incoming.isRepeatable,
                        updatedAt: incoming.updatedAt
                    )
                    let existing = options.conflictPolicy == .replaceAllExisting
                        ? nil
                        : try database.comment(at: adjusted.address)

                    if Self.shouldApplyIncoming(
                        existingTimestamp: existing?.updatedAt,
                        incomingTimestamp: adjusted.updatedAt,
                        hasExisting: existing != nil,
                        policy: options.conflictPolicy
                    ) {
                        mutations.append((
                            "\(tag) Import comment at \(adjusted.address.compactHexString)",
                            .setComment(previous: existing, updated: adjusted)
                        ))
                        importedComments += 1
                    } else {
                        skippedComments += 1
                    }
                }

                // 3. Bookmarks
                for incoming in bundle.bookmarks {
                    let adjusted = UserBookmark(
                        id: incoming.id,
                        address: incoming.address.adding(slide),
                        label: incoming.label,
                        categoryTag: incoming.categoryTag,
                        createdAt: incoming.createdAt
                    )
                    let existing = options.conflictPolicy == .replaceAllExisting
                        ? nil
                        : try database.bookmark(id: adjusted.id)

                    if Self.shouldApplyIncoming(
                        existingTimestamp: existing?.createdAt,
                        incomingTimestamp: adjusted.createdAt,
                        hasExisting: existing != nil,
                        policy: options.conflictPolicy
                    ) {
                        mutations.append((
                            "\(tag) Import bookmark '\(adjusted.label)'",
                            .setBookmark(previous: existing, updated: adjusted)
                        ))
                        importedBookmarks += 1
                    } else {
                        skippedBookmarks += 1
                    }
                }

                // 4. Custom Structs
                for incoming in bundle.structs {
                    let existing = options.conflictPolicy == .replaceAllExisting
                        ? nil
                        : try database.customStruct(id: incoming.id)

                    if Self.shouldApplyIncoming(
                        existingTimestamp: existing?.updatedAt,
                        incomingTimestamp: incoming.updatedAt,
                        hasExisting: existing != nil,
                        policy: options.conflictPolicy
                    ) {
                        mutations.append((
                            "\(tag) Import struct '\(incoming.name)'",
                            .setStruct(previous: existing, updated: incoming)
                        ))
                        importedStructs += 1
                    } else {
                        skippedStructs += 1
                    }
                }

                // 5. Byte Patches
                for incoming in bundle.patches {
                    let adjusted = BytePatchRecord(
                        id: incoming.id,
                        fileOffset: incoming.fileOffset,
                        virtualAddress: incoming.virtualAddress.map { $0.adding(slide) },
                        originalBytes: incoming.originalBytes,
                        patchedBytes: incoming.patchedBytes,
                        originalAssembly: incoming.originalAssembly,
                        patchedAssembly: incoming.patchedAssembly,
                        note: incoming.note,
                        isEnabled: incoming.isEnabled,
                        createdAt: incoming.createdAt
                    )
                    let existing = options.conflictPolicy == .replaceAllExisting
                        ? nil
                        : try database.patch(id: adjusted.id)

                    if Self.shouldApplyIncoming(
                        existingTimestamp: existing?.createdAt,
                        incomingTimestamp: adjusted.createdAt,
                        hasExisting: existing != nil,
                        policy: options.conflictPolicy
                    ) {
                        mutations.append((
                            "\(tag) Import patch at \(adjusted.fileOffset.hexString)",
                            .setPatch(previous: existing, updated: adjusted)
                        ))
                        importedPatches += 1
                    } else {
                        skippedPatches += 1
                    }
                }

                if !mutations.isEmpty {
                    if options.recordUndoTransactions {
                        _ = try undoRedoController.performBatch(operations: mutations)
                    } else {
                        for m in mutations {
                            try database.applyMutation(m.operation)
                        }
                    }
                }

                // 6. Security Findings (grouped by pluginID)
                if options.importSecurityFindings && !bundle.findings.isEmpty {
                    var byPlugin: [String: [SecurityAuditFinding]] = [:]
                    for f in bundle.findings {
                        let adjustedFinding = SecurityAuditFinding(
                            id: f.id,
                            pluginID: f.pluginID,
                            pluginName: f.pluginName,
                            severity: f.severity,
                            category: f.category,
                            title: f.title,
                            detail: f.detail,
                            address: f.address.map { $0.adding(slide) },
                            evidencePreview: f.evidencePreview,
                            createdAt: f.createdAt
                        )
                        byPlugin[f.pluginID, default: []].append(adjustedFinding)
                    }
                    for (pluginID, pluginFindings) in byPlugin {
                        try database.replaceFindings(forPluginID: pluginID, findings: pluginFindings)
                        importedFindingsCount += pluginFindings.count
                    }
                }

                return AnnotationImportSummary(
                    sourceProjectName: bundle.projectName,
                    binarySHA256Matched: shaMatched,
                    contentDigestVerified: digestOK,
                    addressSlideApplied: slide,
                    importedRenames: importedRenames,
                    skippedRenames: skippedRenames,
                    importedComments: importedComments,
                    skippedComments: skippedComments,
                    importedBookmarks: importedBookmarks,
                    skippedBookmarks: skippedBookmarks,
                    importedStructs: importedStructs,
                    skippedStructs: skippedStructs,
                    importedPatches: importedPatches,
                    skippedPatches: skippedPatches,
                    importedFindings: importedFindingsCount,
                    warnings: warnings
                )
            }
        }
    }

    private static func shouldApplyIncoming(
        existingTimestamp: Date?,
        incomingTimestamp: Date,
        hasExisting: Bool,
        policy: AnnotationConflictResolutionPolicy
    ) -> Bool {
        guard hasExisting else { return true }
        switch policy {
        case .preferImported, .replaceAllExisting:
            return true
        case .keepExisting:
            return false
        case .preferNewerTimestamp:
            guard let existingTimestamp else { return true }
            return incomingTimestamp >= existingTimestamp
        }
    }

    // MARK: Ghidra / PyGhidra Importer Python Script Emitter

    public func exportGhidraImporterScript(
        options: GhidraScriptExportOptions = GhidraScriptExportOptions()
    ) throws -> String {
        let bundle = try exportAnnotationBundle(includeFindings: options.includeSecurityFindingsAsBookmarks)
        return Self.renderGhidraImporterScript(from: bundle, options: options)
    }

    public static func renderGhidraImporterScript(
        from bundle: MachAnnotationBundle,
        options: GhidraScriptExportOptions = GhidraScriptExportOptions()
    ) -> String {
        var out: [String] = []
        out.reserveCapacity(220 + bundle.totalAnnotationCount * 6)

        out.append("# -*- coding: utf-8 -*-")
        out.append("# Auto-generated by MachGraph (AnalystAnnotationCodec)")
        out.append("# @category MachGraph")
        out.append("# @menupath Tools.MachGraph.Import Annotations (\(Self.sanitizeBannerText(bundle.projectName)))")
        out.append("# @runtime PyGhidra")
        out.append("#")
        out.append("# Target Binary : \(Self.sanitizeBannerText(bundle.binaryFileName))")
        out.append("# Binary SHA256 : \(bundle.binarySHA256)")
        out.append("# Architecture  : \(bundle.architecture.displayName)")
        out.append("# Image Base    : \(bundle.imageBase.hexString)")
        out.append("# Content Digest: \(bundle.contentSHA256)")
        out.append("")
        out.append("from ghidra.program.model.symbol import SourceType, SymbolUtilities")
        out.append("from ghidra.program.model.listing import CodeUnit")
        out.append("from ghidra.program.model.data import (")
        out.append("    CategoryPath,")
        out.append("    DataTypeConflictHandler,")
        out.append("    StructureDataType,")
        out.append("    VoidDataType,")
        out.append("    BooleanDataType,")
        out.append("    ByteDataType,")
        out.append("    SignedByteDataType,")
        out.append("    WordDataType,")
        out.append("    ShortDataType,")
        out.append("    DWordDataType,")
        out.append("    IntegerDataType,")
        out.append("    QWordDataType,")
        out.append("    LongLongDataType,")
        out.append("    FloatDataType,")
        out.append("    DoubleDataType,")
        out.append("    CharDataType,")
        out.append("    PointerDataType,")
        out.append(")")
        out.append("")
        out.append("EXPECTED_SHA256 = \(Self.pythonStringLiteral(bundle.binarySHA256.lowercased()))")
        out.append("ORIGINAL_IMAGE_BASE = \(bundle.imageBase.hexString)")
        out.append("REBASE_TO_PROGRAM_BASE = \(options.rebaseRelativeToImageBase ? "True" : "False")")
        out.append("")
        out.append("def _compute_slide(program):")
        out.append("    if not REBASE_TO_PROGRAM_BASE or ORIGINAL_IMAGE_BASE == 0:")
        out.append("        return 0")
        out.append("    return program.getImageBase().getOffset() - ORIGINAL_IMAGE_BASE")
        out.append("")
        out.append("def _to_addr(program, raw_vm_addr, slide):")
        out.append("    addr_space = program.getAddressFactory().getDefaultAddressSpace()")
        out.append("    return addr_space.getAddress((raw_vm_addr + slide) & 0xFFFFFFFFFFFFFFFF)")
        out.append("")
        out.append("def _apply_symbol_rename(program, slide, raw_addr, custom_name, sig_override):")
        out.append("    addr = _to_addr(program, raw_addr, slide)")
        out.append("    safe_name = SymbolUtilities.replaceInvalidChars(custom_name, True)")
        out.append("    fm = program.getFunctionManager()")
        out.append("    fn = fm.getFunctionAt(addr)")
        out.append("    if fn is not None:")
        out.append("        fn.setName(safe_name, SourceType.USER_DEFINED)")
        out.append("        if sig_override:")
        out.append("            fn.setComment('Signature: ' + sig_override)")
        out.append("    else:")
        out.append("        st = program.getSymbolTable()")
        out.append("        st.createLabel(addr, safe_name, SourceType.USER_DEFINED)")
        out.append("        if sig_override:")
        out.append("            program.getListing().setComment(addr, CodeUnit.PLATE_COMMENT, 'Signature: ' + sig_override)")
        out.append("")
        out.append("def _apply_comment(program, slide, raw_addr, text, is_repeatable):")
        out.append("    addr = _to_addr(program, raw_addr, slide)")
        out.append("    comment_type = CodeUnit.REPEATABLE_COMMENT if is_repeatable else CodeUnit.EOL_COMMENT")
        out.append("    program.getListing().setComment(addr, comment_type, text)")
        out.append("")
        out.append("def _apply_bookmark(program, slide, raw_addr, category, label):")
        out.append("    addr = _to_addr(program, raw_addr, slide)")
        out.append("    program.getBookmarkManager().setBookmark(addr, 'Analysis', category, label)")
        out.append("")
        out.append("def _apply_byte_patch(program, slide, raw_addr, expected_orig, patched_bytes, note):")
        out.append("    if raw_addr is None or not patched_bytes:")
        out.append("        return False")
        out.append("    addr = _to_addr(program, raw_addr, slide)")
        out.append("    mem = program.getMemory()")
        out.append("    listing = program.getListing()")
        out.append("    end_addr = addr.add(len(patched_bytes) - 1)")
        out.append("    listing.clearCodeUnits(addr, end_addr, False)")
        out.append("    try:")
        out.append("        from jarray import array as _jarray")
        out.append("        signed_bytes = [((b - 256) if b > 127 else b) for b in patched_bytes]")
        out.append("        mem.setBytes(addr, _jarray(signed_bytes, 'b'))")
        out.append("    except ImportError:")
        out.append("        mem.setBytes(addr, bytearray(patched_bytes))")
        out.append("    if note:")
        out.append("        listing.setComment(addr, CodeUnit.PRE_COMMENT, '[MachGraph Patch] ' + note)")
        out.append("    return True")
        out.append("")
        out.append("def run_machgraph_import():")
        out.append("    prog = currentProgram")
        out.append("    if prog is None:")
        out.append("        print('[MachGraph] ERROR: No active Ghidra program is open.')")
        out.append("        return")
        out.append("    actual_sha = (prog.getExecutableSHA256() or '').lower()")
        out.append("    if EXPECTED_SHA256 and actual_sha and actual_sha != EXPECTED_SHA256:")
        out.append("        print('[MachGraph] WARNING: Binary SHA-256 mismatch! Expected ' + EXPECTED_SHA256 + ', got ' + actual_sha)")
        out.append("    slide = _compute_slide(prog)")
        out.append("    tx_id = prog.startTransaction('Import MachGraph Annotations')")
        out.append("    try:")

        if options.includeCustomStructs && !bundle.structs.isEmpty {
            out.append("        # --- Custom C Struct Definitions (\(bundle.structs.count)) ---")
            out.append("        dtm = prog.getDataTypeManager()")
            out.append("        cat_path = CategoryPath(\(Self.pythonStringLiteral(options.structCategoryPath)))")
            for (idx, st) in bundle.structs.enumerated() {
                let varName = "st_\(idx)"
                out.append("        \(varName) = StructureDataType(cat_path, \(Self.pythonStringLiteral(Self.sanitizeCIdentifier(st.name))), \(max(1, st.totalByteSize)))")
                for field in st.fields.sorted(by: { $0.offset < $1.offset }) {
                    let dtExpr = Self.ghidraDataTypeExpr(for: field.typeExpr, byteSize: field.byteSize)
                    let fieldComment = field.comment.map { Self.pythonStringLiteral($0) } ?? "None"
                    out.append("        \(varName).replaceAtOffset(\(max(0, field.offset)), \(dtExpr), \(max(1, field.byteSize)), \(Self.pythonStringLiteral(Self.sanitizeCIdentifier(field.name))), \(fieldComment))")
                }
                out.append("        dtm.addDataType(\(varName), DataTypeConflictHandler.REPLACE_HANDLER)")
            }
        }

        if !bundle.renames.isEmpty {
            out.append("        # --- Symbol Renames (\(bundle.renames.count)) ---")
            for r in bundle.renames {
                let sigLiteral = r.signatureOverride.map { Self.pythonStringLiteral($0) } ?? "None"
                out.append(
                    "        _apply_symbol_rename(prog, slide, \(r.address.hexString), \(Self.pythonStringLiteral(r.customName)), \(sigLiteral))"
                )
            }
        }

        if !bundle.comments.isEmpty {
            out.append("        # --- Inline Comments (\(bundle.comments.count)) ---")
            for c in bundle.comments {
                out.append(
                    "        _apply_comment(prog, slide, \(c.address.hexString), \(Self.pythonStringLiteral(c.text)), \(c.isRepeatable ? "True" : "False"))"
                )
            }
        }

        if !bundle.bookmarks.isEmpty {
            out.append("        # --- Analyst Bookmarks (\(bundle.bookmarks.count)) ---")
            for b in bundle.bookmarks {
                out.append(
                    "        _apply_bookmark(prog, slide, \(b.address.hexString), \(Self.pythonStringLiteral(b.categoryTag)), \(Self.pythonStringLiteral(b.label)))"
                )
            }
        }

        if options.includeSecurityFindingsAsBookmarks && !bundle.findings.isEmpty {
            let addressableFindings = bundle.findings.filter { $0.address != nil }
            if !addressableFindings.isEmpty {
                out.append("        # --- Security Audit Findings (\(addressableFindings.count)) ---")
                for f in addressableFindings {
                    if let addr = f.address {
                        let cat = "Security/\(f.severity.rawValue)"
                        let desc = "[\(f.pluginName)] \(f.title)"
                        out.append(
                            "        _apply_bookmark(prog, slide, \(addr.hexString), \(Self.pythonStringLiteral(cat)), \(Self.pythonStringLiteral(desc)))"
                        )
                    }
                }
            }
        }

        if options.includeBytePatches && !bundle.patches.isEmpty {
            out.append("        # --- Binary Byte Patches (\(bundle.patches.count)) ---")
            for p in bundle.patches {
                let vmLiteral = p.virtualAddress?.hexString ?? "None"
                let origList = "[" + p.originalBytes.map(String.init).joined(separator: ", ") + "]"
                let patchedList = "[" + p.patchedBytes.map(String.init).joined(separator: ", ") + "]"
                if p.isEnabled {
                    out.append(
                        "        _apply_byte_patch(prog, slide, \(vmLiteral), \(origList), \(patchedList), \(Self.pythonStringLiteral(p.note)))"
                    )
                } else if options.includeDisabledPatchesAsComments {
                    out.append(
                        "        # [Disabled Patch @ file \(p.fileOffset.hexString), vm \(vmLiteral)] \(Self.sanitizeBannerText(p.patchedHex)) — \(Self.sanitizeBannerText(p.note))"
                    )
                }
            }
        }

        out.append("        prog.endTransaction(tx_id, True)")
        out.append("        print('[MachGraph] Successfully imported \(bundle.totalAnnotationCount) annotations from ' + \(Self.pythonStringLiteral(bundle.projectName)))")
        out.append("    except Exception as exc:")
        out.append("        prog.endTransaction(tx_id, False)")
        out.append("        raise exc")
        out.append("")
        out.append("if __name__ == '__main__':")
        out.append("    run_machgraph_import()")
        out.append("")

        return out.joined(separator: "\n")
    }

    private static func ghidraDataTypeExpr(for typeExpr: CTypeExpr, byteSize: Int) -> String {
        switch typeExpr {
        case .voidType:
            return "VoidDataType.dataType"
        case .boolType:
            return "BooleanDataType.dataType"
        case .intType(let bits, let signed):
            switch (bits, signed) {
            case (8, false): return "ByteDataType.dataType"
            case (8, true): return "SignedByteDataType.dataType"
            case (16, false): return "WordDataType.dataType"
            case (16, true): return "ShortDataType.dataType"
            case (32, false): return "DWordDataType.dataType"
            case (32, true): return "IntegerDataType.dataType"
            case (_, false): return "QWordDataType.dataType"
            case (_, true): return "LongLongDataType.dataType"
            }
        case .floatType(let bits):
            return bits <= 32 ? "FloatDataType.dataType" : "DoubleDataType.dataType"
        case .cString:
            return "PointerDataType(CharDataType.dataType)"
        case .pointer(let inner):
            if inner == .voidType {
                return "PointerDataType()"
            }
            return "PointerDataType(\(ghidraDataTypeExpr(for: inner, byteSize: 8)))"
        case .objcObject:
            return "PointerDataType()"
        case .structRef:
            return byteSize <= 4 ? "DWordDataType.dataType" : "QWordDataType.dataType"
        case .unknownBits(let bits):
            if bits <= 8 { return "ByteDataType.dataType" }
            if bits <= 16 { return "WordDataType.dataType" }
            if bits <= 32 { return "DWordDataType.dataType" }
            return "QWordDataType.dataType"
        }
    }

    // MARK: IDA Pro IDC Script Emitter

    public func exportIDAIDCScript(includeBytePatches: Bool = true) throws -> String {
        let bundle = try exportAnnotationBundle(includeFindings: false)
        return Self.renderIDAIDCScript(from: bundle, includeBytePatches: includeBytePatches)
    }

    public static func renderIDAIDCScript(
        from bundle: MachAnnotationBundle,
        includeBytePatches: Bool = true
    ) -> String {
        var lines: [String] = []
        lines.append("// Auto-generated IDA Pro IDC Script — MachGraph AnalystAnnotationCodec")
        lines.append("// Project : \(Self.sanitizeBannerText(bundle.projectName))")
        lines.append("// SHA-256 : \(bundle.binarySHA256)")
        lines.append("#include <idc.idc>")
        lines.append("")
        lines.append("static main(void) {")
        lines.append("    auto slot = 1;")

        for r in bundle.renames {
            lines.append("    set_name(\(r.address.hexString), \(Self.idcStringLiteral(Self.sanitizeCIdentifier(r.customName))), SN_NOWARN);")
            if let sig = r.signatureOverride, !sig.isEmpty {
                lines.append("    apply_type(\(r.address.hexString), parse_decl(\(Self.idcStringLiteral(sig)), PT_SILENT));")
            }
        }

        for c in bundle.comments {
            let flag = c.isRepeatable ? "1" : "0"
            lines.append("    set_cmt(\(c.address.hexString), \(Self.idcStringLiteral(c.text)), \(flag));")
        }

        for b in bundle.bookmarks {
            let note = "[\(b.categoryTag)] \(b.label)"
            lines.append("    put_bookmark(\(b.address.hexString), 0, 0, 0, slot, \(Self.idcStringLiteral(note)));")
            lines.append("    slot = slot + 1;")
        }

        if includeBytePatches {
            for p in bundle.patches where p.isEnabled {
                if let vm = p.virtualAddress {
                    for (idx, byte) in p.patchedBytes.enumerated() {
                        let targetAddr = vm.adding(UInt64(idx)).hexString
                        let hexByte = String(format: "0x%02x", byte)
                        lines.append("    patch_byte(\(targetAddr), \(hexByte));")
                    }
                }
            }
        }

        lines.append("    msg(\"[MachGraph] Imported annotations into IDA database.\\n\");")
        lines.append("}")
        lines.append("")
        return lines.joined(separator: "\n")
    }

    // MARK: Standalone C Header Exporter

    public func exportCHeaderDefinitions() throws -> String {
        let structs = try database.allStructs()
        let renames = try database.allRenames()
        return Self.renderCHeaderDefinitions(structs: structs, renames: renames)
    }

    public static func renderCHeaderDefinitions(
        structs: [CustomStructDefinition],
        renames: [UserSymbolRename]
    ) -> String {
        var lines: [String] = []
        lines.append("/* Auto-generated Reconstructed Types & Prototypes — MachGraph */")
        lines.append("#pragma once")
        lines.append("#include <stdint.h>")
        lines.append("#include <stdbool.h>")
        lines.append("")

        for st in structs.sorted(by: { $0.name < $1.name }) {
            let structIdent = Self.sanitizeCIdentifier(st.name)
            lines.append("/* total size: 0x\(String(st.totalByteSize, radix: 16)) (\(st.totalByteSize) bytes), align: \(st.alignment) */")
            lines.append("typedef struct __attribute__((aligned(\(max(1, st.alignment))))) \(structIdent) {")

            var cursorOffset = 0
            var padIndex = 0
            for field in st.fields.sorted(by: { $0.offset < $1.offset }) {
                if field.offset > cursorOffset {
                    let gap = field.offset - cursorOffset
                    lines.append(String(format: "    uint8_t _pad_%d[0x%x]; /* +0x%02x */", padIndex, gap, cursorOffset))
                    padIndex += 1
                }
                let fieldIdent = Self.sanitizeCIdentifier(field.name)
                let commentSuffix = field.comment.map { " — \($0)" } ?? ""
                let offsetHex = String(format: "0x%02x", field.offset)
                lines.append(
                    "    \(field.typeExpr.cTypeName) \(fieldIdent); /* +\(offsetHex) (\(field.byteSize)B)\(commentSuffix) */"
                )
                cursorOffset = max(cursorOffset, field.offset + max(1, field.byteSize))
            }

            if st.totalByteSize > cursorOffset {
                let tailGap = st.totalByteSize - cursorOffset
                lines.append(String(format: "    uint8_t _tail_pad[0x%x]; /* +0x%02x */", tailGap, cursorOffset))
            }

            lines.append("} \(structIdent)_t;")
            lines.append("")
        }

        let sigOverrides = renames.filter { ($0.signatureOverride ?? "").isEmpty == false }
        if !sigOverrides.isEmpty {
            lines.append("/* Analyst Function Prototypes */")
            for r in sigOverrides {
                if let sig = r.signatureOverride {
                    let terminated = sig.hasSuffix(";") ? sig : "\(sig);"
                    lines.append("/* @ \(r.address.compactHexString) (orig: \(r.originalName)) */")
                    lines.append(terminated)
                }
            }
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }

    // MARK: Analyst Markdown Triage Dossier Emitter

    public func exportMarkdownDossier(
        options: MarkdownDossierExportOptions = MarkdownDossierExportOptions()
    ) throws -> String {
        try synchronized {
            let bundle = try exportAnnotationBundle(includeFindings: options.includeSecurityFindings)
            let stats = try database.computeProjectStats()
            let functions = options.includeTopComplexFunctions
                ? (try database.allFunctionSummaries())
                : []
            return Self.renderMarkdownDossier(
                bundle: bundle,
                stats: stats,
                functionSummaries: functions,
                options: options
            )
        }
    }

    public static func renderMarkdownDossier(
        bundle: MachAnnotationBundle,
        stats: MachProjectStats? = nil,
        functionSummaries: [CachedFunctionSummary] = [],
        options: MarkdownDossierExportOptions = MarkdownDossierExportOptions()
    ) -> String {
        var md: [String] = []
        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime]

        md.append("# MachGraph Reverse-Engineering Triage Dossier: \(bundle.projectName)")
        md.append("")
        md.append("> Generated by `\(bundle.exporterTool)` on `\(isoFormatter.string(from: bundle.exportedAt))`")
        md.append("> Portable shareable dossier — contains zero proprietary target binary executable code blobs.")
        md.append("")

        // Section 1: Binary Identification & Executive Telemetry
        if options.includeExecutiveTelemetry {
            md.append("## 1. Target Binary Identification & Project Telemetry")
            md.append("")
            md.append("| Property | Value |")
            md.append("|---|---|")
            md.append("| **Project Name** | `\(Self.escapeMarkdownCell(bundle.projectName))` |")
            md.append("| **Binary File** | `\(Self.escapeMarkdownCell(bundle.binaryFileName.isEmpty ? "N/A" : bundle.binaryFileName))` |")
            md.append("| **SHA-256 Digest** | `\(bundle.binarySHA256.isEmpty ? "N/A" : bundle.binarySHA256)` |")
            md.append("| **Container Format** | \(bundle.containerFormat.rawValue) |")
            md.append("| **CPU Architecture** | `\(bundle.architecture.displayName)` |")
            md.append("| **Image Base** | `\(bundle.imageBase.hexString)` |")
            if let ep = bundle.entryPoint {
                md.append("| **Entry Point** | `\(ep.hexString)` |")
            }
            md.append("| **Annotation Digest** | `\(bundle.contentSHA256)` |")
            if let stats {
                md.append("| **SQLite Schema** | `v\(stats.schemaVersion)` (DB: \(stats.sqliteBytes) B, WAL: \(stats.walBytes) B) |")
                md.append("| **Recovered CFG Functions** | \(stats.functionCount) |")
                md.append("| **Indexed Symbols / Xrefs** | \(stats.symbolCount) symbols / \(stats.xrefCount) xrefs |")
                md.append("| **Undo / Redo Stack Depth** | \(stats.undoDepth) undo / \(stats.redoDepth) redo |")
            }
            md.append("")
        }

        // Section 2: Security Audit Findings
        if options.includeSecurityFindings {
            md.append("## 2. Security Audit Findings (\(bundle.findings.count))")
            md.append("")
            if bundle.findings.isEmpty {
                md.append("_No security audit findings recorded._")
                md.append("")
            } else {
                md.append("| Severity | Category | Location | Title | Plugin |")
                md.append("|---|---|---|---|---|")
                for f in bundle.findings {
                    let loc = f.address?.compactHexString ?? "Global"
                    md.append(
                        "| **\(f.severity.rawValue)** | \(Self.escapeMarkdownCell(f.category)) | `\(loc)` | \(Self.escapeMarkdownCell(f.title)) | `\(Self.escapeMarkdownCell(f.pluginName))` |"
                    )
                }
                md.append("")

                for f in bundle.findings where f.severity >= .medium {
                    let loc = f.address?.compactHexString ?? "Global"
                    md.append("### [\(f.severity.rawValue)] \(f.title) (`\(loc)`)")
                    md.append("")
                    md.append(f.detail)
                    if let evidence = f.evidencePreview, !evidence.isEmpty {
                        md.append("")
                        md.append("```text")
                        md.append(evidence)
                        md.append("```")
                    }
                    md.append("")
                }
            }
        }

        // Section 3: Analyst Bookmarks
        if options.includeBookmarks {
            md.append("## 3. Triage Bookmarks (\(bundle.bookmarks.count))")
            md.append("")
            if bundle.bookmarks.isEmpty {
                md.append("_No bookmarks recorded._")
                md.append("")
            } else {
                md.append("| Category | Virtual Address | Label | Created |")
                md.append("|---|---|---|---|")
                for b in bundle.bookmarks {
                    md.append(
                        "| `\(Self.escapeMarkdownCell(b.categoryTag))` | `\(b.address.compactHexString)` | **\(Self.escapeMarkdownCell(b.label))** | `\(isoFormatter.string(from: b.createdAt))` |"
                    )
                }
                md.append("")
            }
        }

        // Section 4: Symbol Renames & Reconstructed Prototypes
        if options.includeSymbolRenames {
            md.append("## 4. Analyst Symbol Renames (\(bundle.renames.count))")
            md.append("")
            if bundle.renames.isEmpty {
                md.append("_No custom symbol renames recorded._")
                md.append("")
            } else {
                md.append("| Address | Original Symbol | Analyst Symbol | Signature Override |")
                md.append("|---|---|---|---|")
                for r in bundle.renames {
                    let sig = r.signatureOverride.map { "`\(Self.escapeMarkdownCell($0))`" } ?? "—"
                    md.append(
                        "| `\(r.address.compactHexString)` | `\(Self.escapeMarkdownCell(r.originalName))` | **`\(Self.escapeMarkdownCell(r.customName))`** | \(sig) |"
                    )
                }
                md.append("")
            }
        }

        // Section 5: Inline Disassembly & Decompiler Comments
        if options.includeInlineComments {
            md.append("## 5. Inline Annotations (\(bundle.comments.count))")
            md.append("")
            if bundle.comments.isEmpty {
                md.append("_No inline comments recorded._")
                md.append("")
            } else {
                md.append("| Address | Scope | Comment |")
                md.append("|---|---|---|")
                for c in bundle.comments {
                    let scope = c.isRepeatable ? "Repeatable" : "EOL"
                    md.append(
                        "| `\(c.address.compactHexString)` | `\(scope)` | \(Self.escapeMarkdownCell(c.text)) |"
                    )
                }
                md.append("")
            }
        }

        // Section 6: Reconstructed C Structs
        if options.includeCHeaderStructs && !bundle.structs.isEmpty {
            md.append("## 6. Reconstructed C Data Structures (\(bundle.structs.count))")
            md.append("")
            md.append("```c")
            md.append(renderCHeaderDefinitions(structs: bundle.structs, renames: []))
            md.append("```")
            md.append("")
        }

        // Section 7: Binary Byte Patches Ledger
        if options.includeBytePatches {
            let visiblePatches = options.includeDisabledPatches
                ? bundle.patches
                : bundle.patches.filter(\.isEnabled)
            md.append("## 7. Binary Byte Patches Ledger (\(visiblePatches.count))")
            md.append("")
            if visiblePatches.isEmpty {
                md.append("_No binary byte patches recorded._")
                md.append("")
            } else {
                md.append("| Status | File Offset | VM Address | Original Bytes / ASM | Patched Bytes / ASM | Note |")
                md.append("|---|---|---|---|---|---|")
                for p in visiblePatches {
                    let status = p.isEnabled ? "ACTIVE" : "DISABLED"
                    let vmText = p.virtualAddress?.compactHexString ?? "—"
                    let origDesc = p.originalAssembly.map { "`\(p.originalHex)` (\($0))" } ?? "`\(p.originalHex)`"
                    let patchedDesc = p.patchedAssembly.map { "`\(p.patchedHex)` (\($0))" } ?? "`\(p.patchedHex)`"
                    md.append(
                        "| `\(status)` | `\(p.fileOffset.hexString)` | `\(vmText)` | \(Self.escapeMarkdownCell(origDesc)) | \(Self.escapeMarkdownCell(patchedDesc)) | \(Self.escapeMarkdownCell(p.note)) |"
                    )
                }
                md.append("")
            }
        }

        // Section 8: High-Complexity Recovered Functions
        if options.includeTopComplexFunctions && !functionSummaries.isEmpty {
            let ranked = functionSummaries.sorted {
                if $0.cyclomaticComplexity != $1.cyclomaticComplexity {
                    return $0.cyclomaticComplexity > $1.cyclomaticComplexity
                }
                return $0.instructionCount > $1.instructionCount
            }
            let topSlice = Array(ranked.prefix(options.maxFunctionsListed))
            md.append("## 8. Top Recovered CFG Functions by Complexity (\(topSlice.count) of \(functionSummaries.count))")
            md.append("")
            md.append("| Address | Function | Blocks | Edges | Cyclomatic CC | Instructions | Attributes |")
            md.append("|---|---|---:|---:|---:|---:|---|")
            for fn in topSlice {
                var flags: [String] = []
                if fn.isLeaf { flags.append("LEAF") }
                if fn.isThunk { flags.append("THUNK") }
                if fn.usesPAC { flags.append("PAC") }
                let attrText = flags.isEmpty ? "—" : flags.joined(separator: ", ")
                md.append(
                    "| `\(fn.address.compactHexString)` | `\(Self.escapeMarkdownCell(fn.effectiveDisplayName))` | \(fn.blockCount) | \(fn.edgeCount) | \(fn.cyclomaticComplexity) | \(fn.instructionCount) | \(attrText) |"
                )
            }
            md.append("")
        }

        return md.joined(separator: "\n")
    }

    // MARK: Escaping & Sanitization Utilities

    private static func pythonStringLiteral(_ value: String) -> String {
        var escaped = "\""
        escaped.reserveCapacity(value.count + 8)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x5C: escaped.append("\\\\")
            case 0x22: escaped.append("\\\"")
            case 0x0A: escaped.append("\\n")
            case 0x0D: escaped.append("\\r")
            case 0x09: escaped.append("\\t")
            case 0x00...0x1F, 0x7F:
                escaped.append(String(format: "\\x%02x", scalar.value))
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }
        escaped.append("\"")
        return escaped
    }

    private static func idcStringLiteral(_ value: String) -> String {
        pythonStringLiteral(value)
    }

    private static func sanitizeBannerText(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
    }

    private static func sanitizeCIdentifier(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "_unnamed_sym" }
        var chars: [Character] = []
        chars.reserveCapacity(trimmed.count + 1)
        for (idx, ch) in trimmed.enumerated() {
            let isAlpha = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || ch == "_"
            let isDigit = (ch >= "0" && ch <= "9")
            if idx == 0 {
                if isAlpha {
                    chars.append(ch)
                } else if isDigit {
                    chars.append("_")
                    chars.append(ch)
                } else {
                    chars.append("_")
                }
            } else {
                chars.append((isAlpha || isDigit) ? ch : "_")
            }
        }
        return String(chars)
    }

    private static func escapeMarkdownCell(_ raw: String) -> String {
        raw
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\r\n", with: "<br>")
            .replacingOccurrences(of: "\n", with: "<br>")
            .replacingOccurrences(of: "\r", with: "<br>")
    }
}
