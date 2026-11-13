import Foundation
import SQLite3
import MachGraphModels

// MARK: - .machproj Bundle Manifest & Cached Summary Models

public struct MachProjectBundleMetadata: Sendable, Codable, Hashable {
    public static let currentFormatMagic = "MACHPROJ_BUNDLE_V1"

    public let formatMagic: String
    public let projectID: UUID
    public var projectName: String
    public var binaryFileName: String
    public var binaryPath: String
    public var binarySHA256: String
    public var containerFormat: BinaryContainerFormat
    public var architecture: CPUArchitecture
    public var imageBase: VirtualAddress
    public var entryPoint: VirtualAddress?
    public var schemaVersion: Int
    public let createdAt: Date
    public var updatedAt: Date

    public init(
        formatMagic: String = Self.currentFormatMagic,
        projectID: UUID = UUID(),
        projectName: String,
        binaryFileName: String = "",
        binaryPath: String = "",
        binarySHA256: String = "",
        containerFormat: BinaryContainerFormat = .machO64,
        architecture: CPUArchitecture = .arm64,
        imageBase: VirtualAddress = .zero,
        entryPoint: VirtualAddress? = nil,
        schemaVersion: Int = MachSchemaVersion.latest,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.formatMagic = formatMagic
        self.projectID = projectID
        self.projectName = projectName
        self.binaryFileName = binaryFileName
        self.binaryPath = binaryPath
        self.binarySHA256 = binarySHA256
        self.containerFormat = containerFormat
        self.architecture = architecture
        self.imageBase = imageBase
        self.entryPoint = entryPoint
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct StoredBinaryImageSummary: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let fileName: String
    public let filePath: String
    public let fileSize: UInt64
    public let sha256Hex: String
    public let containerFormat: BinaryContainerFormat
    public let selectedSliceIndex: Int
    public let sliceFileOffset: FileOffset
    public let architecture: CPUArchitecture
    public let endianness: BinaryEndianness
    public let isPositionIndependent: Bool
    public let imageBase: VirtualAddress
    public let entryPoint: VirtualAddress?
    public let uuidString: String?
    public let platformName: String
    public let minOSVersion: String
    public let sdkVersion: String
    public let segmentCount: Int
    public let sectionCount: Int
    public let symbolCount: Int
    public let importedLibraryCount: Int
    public let stringCount: Int
    public let fixupCount: Int
    public let objcClassCount: Int
    public let swiftTypeCount: Int
    public let isSigned: Bool
    public let overallEntropy: Double

    public init(
        id: UUID,
        fileName: String,
        filePath: String,
        fileSize: UInt64,
        sha256Hex: String,
        containerFormat: BinaryContainerFormat,
        selectedSliceIndex: Int,
        sliceFileOffset: FileOffset,
        architecture: CPUArchitecture,
        endianness: BinaryEndianness,
        isPositionIndependent: Bool,
        imageBase: VirtualAddress,
        entryPoint: VirtualAddress?,
        uuidString: String?,
        platformName: String,
        minOSVersion: String,
        sdkVersion: String,
        segmentCount: Int,
        sectionCount: Int,
        symbolCount: Int,
        importedLibraryCount: Int,
        stringCount: Int,
        fixupCount: Int,
        objcClassCount: Int,
        swiftTypeCount: Int,
        isSigned: Bool,
        overallEntropy: Double
    ) {
        self.id = id
        self.fileName = fileName
        self.filePath = filePath
        self.fileSize = fileSize
        self.sha256Hex = sha256Hex
        self.containerFormat = containerFormat
        self.selectedSliceIndex = selectedSliceIndex
        self.sliceFileOffset = sliceFileOffset
        self.architecture = architecture
        self.endianness = endianness
        self.isPositionIndependent = isPositionIndependent
        self.imageBase = imageBase
        self.entryPoint = entryPoint
        self.uuidString = uuidString
        self.platformName = platformName
        self.minOSVersion = minOSVersion
        self.sdkVersion = sdkVersion
        self.segmentCount = segmentCount
        self.sectionCount = sectionCount
        self.symbolCount = symbolCount
        self.importedLibraryCount = importedLibraryCount
        self.stringCount = stringCount
        self.fixupCount = fixupCount
        self.objcClassCount = objcClassCount
        self.swiftTypeCount = swiftTypeCount
        self.isSigned = isSigned
        self.overallEntropy = overallEntropy
    }

    public init(from image: LoadedBinaryImage) {
        self.id = image.id
        self.fileName = image.fileName
        self.filePath = image.filePath
        self.fileSize = image.fileSize
        self.sha256Hex = image.sha256Hex
        self.containerFormat = image.containerFormat
        self.selectedSliceIndex = image.selectedSliceIndex
        self.sliceFileOffset = image.sliceFileOffset
        self.architecture = image.architecture
        self.endianness = image.endianness
        self.isPositionIndependent = image.isPositionIndependent
        self.imageBase = image.imageBase
        self.entryPoint = image.entryPoint
        self.uuidString = image.uuidString
        self.platformName = image.platformName
        self.minOSVersion = image.minOSVersion
        self.sdkVersion = image.sdkVersion
        self.segmentCount = image.segments.count
        self.sectionCount = image.sections.count
        self.symbolCount = image.symbols.count
        self.importedLibraryCount = image.importedLibraries.count
        self.stringCount = image.strings.count
        self.fixupCount = image.chainedFixups.count
        self.objcClassCount = image.objcClasses.count
        self.swiftTypeCount = image.swiftTypes.count
        self.isSigned = image.codeSignature.isSigned
        self.overallEntropy = image.overallEntropy
    }
}

public struct CachedFunctionSummary: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let endAddress: VirtualAddress
    public let name: String
    public let demangledName: String
    public let customName: String?
    public let isLeaf: Bool
    public let isThunk: Bool
    public let usesPAC: Bool
    public let stackFrameBytes: Int
    public let blockCount: Int
    public let edgeCount: Int
    public let cyclomaticComplexity: Int
    public let instructionCount: Int
    public let hasCachedDecompilation: Bool
    public let updatedAt: Date

    public init(
        address: VirtualAddress,
        endAddress: VirtualAddress,
        name: String,
        demangledName: String,
        customName: String? = nil,
        isLeaf: Bool,
        isThunk: Bool,
        usesPAC: Bool,
        stackFrameBytes: Int,
        blockCount: Int,
        edgeCount: Int,
        cyclomaticComplexity: Int,
        instructionCount: Int,
        hasCachedDecompilation: Bool = false,
        updatedAt: Date = Date()
    ) {
        self.address = address
        self.endAddress = endAddress
        self.name = name
        self.demangledName = demangledName
        self.customName = customName
        self.isLeaf = isLeaf
        self.isThunk = isThunk
        self.usesPAC = usesPAC
        self.stackFrameBytes = stackFrameBytes
        self.blockCount = blockCount
        self.edgeCount = edgeCount
        self.cyclomaticComplexity = cyclomaticComplexity
        self.instructionCount = instructionCount
        self.hasCachedDecompilation = hasCachedDecompilation
        self.updatedAt = updatedAt
    }

    public var effectiveDisplayName: String {
        if let customName, !customName.isEmpty {
            return customName
        }
        return demangledName.isEmpty ? name : demangledName
    }

    public var byteSpan: UInt64 {
        endAddress.rawValue >= address.rawValue ? (endAddress.rawValue - address.rawValue) : 0
    }
}

// MARK: - Project Metadata Keys

private enum MetaKeys {
    static let projectID = "project.id"
    static let projectName = "project.name"
    static let createdAt = "project.created_at"
    static let updatedAt = "project.updated_at"
    static let binaryPath = "binary.path"
    static let binaryFileName = "binary.file_name"
    static let binarySHA256 = "binary.sha256"
    static let binarySummaryJSON = "binary.summary_json"
    static let binaryFullImageJSON = "binary.full_image_json"
    static let lastCursorJSON = "workbench.last_cursor_json"
}

// MARK: - High-Level .machproj Repository (MachProjectDatabase)

public final class MachProjectDatabase: @unchecked Sendable {
    public static let bundleExtension = "machproj"
    public static let databaseFileName = "database.sqlite"
    public static let metadataFileName = "metadata.json"

    private let lock = NSRecursiveLock()
    public let bundleURL: URL?
    public let databaseFileURL: URL?
    public let metadataFileURL: URL?
    public let connection: MachSQLiteWALConnection

    // MARK: Lifecycle & Bundle Factory Methods

    public init(
        bundleURL: URL,
        projectName: String? = nil,
        binaryImage: LoadedBinaryImage? = nil,
        configuration: SQLiteConnectionConfiguration = .standardWAL
    ) throws {
        let standardized = bundleURL.standardizedFileURL
        let pathExtension = standardized.pathExtension.lowercased()
        let isDirectSQLiteFile = (pathExtension == "sqlite" || pathExtension == "sqlite3" || pathExtension == "db")

        let resolvedBundleURL: URL?
        let resolvedDBURL: URL
        let resolvedMetaURL: URL?

        if isDirectSQLiteFile {
            resolvedBundleURL = nil
            resolvedDBURL = standardized
            resolvedMetaURL = nil
        } else {
            resolvedBundleURL = standardized
            resolvedDBURL = standardized.appendingPathComponent(Self.databaseFileName, isDirectory: false)
            resolvedMetaURL = standardized.appendingPathComponent(Self.metadataFileName, isDirectory: false)

            if configuration.openMode == .readWriteCreate {
                do {
                    try FileManager.default.createDirectory(at: standardized, withIntermediateDirectories: true)
                } catch {
                    throw MachGraphError.ioFailure(
                        "Failed creating .machproj bundle directory '\(standardized.path)': \(error.localizedDescription)"
                    )
                }
            } else if !FileManager.default.fileExists(atPath: standardized.path) {
                throw MachGraphError.fileNotFound(standardized.path)
            }
        }

        self.bundleURL = resolvedBundleURL
        self.databaseFileURL = resolvedDBURL
        self.metadataFileURL = resolvedMetaURL
        self.connection = try MachSQLiteWALConnection(url: resolvedDBURL, configuration: configuration)

        if configuration.openMode != .readOnly {
            let inferredName = projectName
                ?? Self.inferProjectName(from: standardized, binaryImage: binaryImage)
            try bootstrapMetadataIfNeeded(defaultProjectName: inferredName)
            if let binaryImage {
                try storeBinaryImage(binaryImage, cacheSymbols: false)
            } else {
                try syncBundleMetadataFile()
            }
        }
    }

    public init(
        connection: MachSQLiteWALConnection,
        bundleURL: URL? = nil,
        projectName: String = "InMemoryProject",
        binaryImage: LoadedBinaryImage? = nil
    ) throws {
        self.connection = connection
        self.bundleURL = bundleURL
        if let bundleURL {
            self.databaseFileURL = bundleURL.appendingPathComponent(Self.databaseFileName, isDirectory: false)
            self.metadataFileURL = bundleURL.appendingPathComponent(Self.metadataFileName, isDirectory: false)
        } else {
            self.databaseFileURL = nil
            self.metadataFileURL = nil
        }

        if connection.configuration.openMode != .readOnly {
            if try connection.userSchemaVersion() < MachSchemaVersion.latest {
                _ = try MachSchemaMigrationManager.migrateToLatest(on: connection)
            }
            try bootstrapMetadataIfNeeded(defaultProjectName: projectName)
            if let binaryImage {
                try storeBinaryImage(binaryImage, cacheSymbols: false)
            }
        }
    }

    public static func createOrOpen(
        at bundleURL: URL,
        projectName: String? = nil,
        binaryImage: LoadedBinaryImage? = nil
    ) throws -> MachProjectDatabase {
        try MachProjectDatabase(
            bundleURL: bundleURL,
            projectName: projectName,
            binaryImage: binaryImage,
            configuration: .standardWAL
        )
    }

    public static func createOrOpen(
        bundleURL: URL,
        projectName: String? = nil,
        binaryImage: LoadedBinaryImage? = nil
    ) throws -> MachProjectDatabase {
        try createOrOpen(at: bundleURL, projectName: projectName, binaryImage: binaryImage)
    }

    public static func create(
        at bundleURL: URL,
        projectName: String,
        binaryImage: LoadedBinaryImage? = nil,
        overwrite: Bool = false
    ) throws -> MachProjectDatabase {
        let standardized = bundleURL.standardizedFileURL
        if FileManager.default.fileExists(atPath: standardized.path) {
            if overwrite {
                do {
                    try FileManager.default.removeItem(at: standardized)
                } catch {
                    throw MachGraphError.ioFailure(
                        "Failed overwriting existing project at '\(standardized.path)': \(error.localizedDescription)"
                    )
                }
            } else {
                throw MachGraphError.ioFailure(
                    "Project bundle already exists at '\(standardized.path)'; pass overwrite: true or use createOrOpen"
                )
            }
        }
        return try MachProjectDatabase(
            bundleURL: standardized,
            projectName: projectName,
            binaryImage: binaryImage,
            configuration: .standardWAL
        )
    }

    public static func open(
        at bundleURL: URL,
        readOnly: Bool = false
    ) throws -> MachProjectDatabase {
        var config = SQLiteConnectionConfiguration.standardWAL
        config.openMode = readOnly ? .readOnly : .readWriteExisting
        config.autoMigrateToLatest = !readOnly
        return try MachProjectDatabase(
            bundleURL: bundleURL,
            projectName: nil,
            binaryImage: nil,
            configuration: config
        )
    }

    public static func openInMemory(
        projectName: String = "InMemoryProject",
        binaryImage: LoadedBinaryImage? = nil
    ) throws -> MachProjectDatabase {
        let conn = try MachSQLiteWALConnection(
            path: ":memory:",
            configuration: .inMemoryTesting
        )
        return try MachProjectDatabase(
            connection: conn,
            bundleURL: nil,
            projectName: projectName,
            binaryImage: binaryImage
        )
    }

    public func close() {
        synchronized {
            if connection.isOpen && connection.configuration.openMode != .readOnly {
                try? syncBundleMetadataFile()
            }
            connection.close()
        }
    }

    @discardableResult
    private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try connection.withExclusiveAccess(body)
    }

    @discardableResult
    public func withTransaction<T>(_ body: () throws -> T) throws -> T {
        try synchronized {
            try connection.withTransaction(body)
        }
    }

    @discardableResult
    public func checkpointWAL(mode: WALCheckpointMode = .passive) throws -> WALCheckpointResult {
        try synchronized {
            try connection.checkpointWAL(mode: mode)
        }
    }

    public func verifyIntegrity() throws -> SQLiteIntegrityReport {
        try synchronized {
            try connection.verifyIntegrity()
        }
    }

    // MARK: Bundle Manifest & Project Metadata

    private static func inferProjectName(from bundleURL: URL, binaryImage: LoadedBinaryImage?) -> String {
        let stem = bundleURL.deletingPathExtension().lastPathComponent
        if !stem.isEmpty && stem != "database" {
            return stem
        }
        if let binaryImage, !binaryImage.fileName.isEmpty {
            return binaryImage.fileName
        }
        return "UntitledProject"
    }

    private func bootstrapMetadataIfNeeded(defaultProjectName: String) throws {
        try synchronized {
            let now = Date()
            let existingManifest = try? readBundleMetadataFromDisk()

            if try metaValue(forKey: MetaKeys.projectID) == nil {
                let id = existingManifest?.projectID ?? UUID()
                try setMetaValue(id.uuidString, forKey: MetaKeys.projectID)
            }
            if try metaValue(forKey: MetaKeys.projectName) == nil {
                let name = existingManifest?.projectName ?? defaultProjectName
                try setMetaValue(name, forKey: MetaKeys.projectName)
            }
            if try metaValue(forKey: MetaKeys.createdAt) == nil {
                let created = existingManifest?.createdAt ?? now
                try setMetaValue(String(created.timeIntervalSince1970), forKey: MetaKeys.createdAt)
            }
            if let existingManifest {
                if try metaValue(forKey: MetaKeys.binaryPath) == nil, !existingManifest.binaryPath.isEmpty {
                    try setMetaValue(existingManifest.binaryPath, forKey: MetaKeys.binaryPath)
                }
                if try metaValue(forKey: MetaKeys.binaryFileName) == nil, !existingManifest.binaryFileName.isEmpty {
                    try setMetaValue(existingManifest.binaryFileName, forKey: MetaKeys.binaryFileName)
                }
                if try metaValue(forKey: MetaKeys.binarySHA256) == nil, !existingManifest.binarySHA256.isEmpty {
                    try setMetaValue(existingManifest.binarySHA256, forKey: MetaKeys.binarySHA256)
                }
            }
            try setMetaValue(String(now.timeIntervalSince1970), forKey: MetaKeys.updatedAt)
        }
    }

    private func readBundleMetadataFromDisk() throws -> MachProjectBundleMetadata? {
        guard let metadataFileURL, FileManager.default.fileExists(atPath: metadataFileURL.path) else {
            return nil
        }
        let data: Data
        do {
            data = try Data(contentsOf: metadataFileURL)
        } catch {
            throw MachGraphError.ioFailure("Failed reading '\(metadataFileURL.path)': \(error.localizedDescription)")
        }
        do {
            return try StoreJSONCoding.makeDecoder().decode(MachProjectBundleMetadata.self, from: data)
        } catch {
            throw MachGraphError.ioFailure("Malformed metadata.json at '\(metadataFileURL.path)': \(error.localizedDescription)")
        }
    }

    public func readBundleMetadata() throws -> MachProjectBundleMetadata {
        try synchronized {
            let projectIDString = try metaValue(forKey: MetaKeys.projectID) ?? UUID().uuidString
            let projectID = UUID(uuidString: projectIDString) ?? UUID()
            let name = try projectName()
            let createdEpoch = Double(try metaValue(forKey: MetaKeys.createdAt) ?? "") ?? Date().timeIntervalSince1970
            let updatedEpoch = Double(try metaValue(forKey: MetaKeys.updatedAt) ?? "") ?? Date().timeIntervalSince1970
            let summary = try loadBinaryImageSummary()
            let schemaVer = try connection.userSchemaVersion()

            return MachProjectBundleMetadata(
                projectID: projectID,
                projectName: name,
                binaryFileName: try (metaValue(forKey: MetaKeys.binaryFileName) ?? summary?.fileName ?? ""),
                binaryPath: try (metaValue(forKey: MetaKeys.binaryPath) ?? summary?.filePath ?? ""),
                binarySHA256: try (metaValue(forKey: MetaKeys.binarySHA256) ?? summary?.sha256Hex ?? ""),
                containerFormat: summary?.containerFormat ?? .machO64,
                architecture: summary?.architecture ?? .arm64,
                imageBase: summary?.imageBase ?? .zero,
                entryPoint: summary?.entryPoint,
                schemaVersion: schemaVer,
                createdAt: Date(timeIntervalSince1970: createdEpoch),
                updatedAt: Date(timeIntervalSince1970: updatedEpoch)
            )
        }
    }

    public func syncBundleMetadataFile() throws {
        try synchronized {
            guard let metadataFileURL, connection.configuration.openMode != .readOnly else { return }
            let manifest = try readBundleMetadata()
            let encoded: Data
            do {
                encoded = try StoreJSONCoding.makeEncoder(prettyPrinted: true).encode(manifest)
            } catch {
                throw MachGraphError.ioFailure("Failed encoding metadata.json: \(error.localizedDescription)")
            }
            do {
                try encoded.write(to: metadataFileURL, options: .atomic)
            } catch {
                throw MachGraphError.ioFailure(
                    "Failed writing metadata.json to '\(metadataFileURL.path)': \(error.localizedDescription)"
                )
            }
        }
    }

    public func metaValue(forKey key: String) throws -> String? {
        try synchronized {
            try connection.queryScalarString(
                "SELECT value FROM project_meta WHERE key = ?;",
                bindings: [.text(key)]
            )
        }
    }

    public func setMetaValue(_ value: String, forKey key: String) throws {
        try synchronized {
            _ = try connection.execute(
                """
                INSERT INTO project_meta (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at;
                """,
                bindings: [.text(key), .text(value), .date(Date())]
            )
        }
    }

    public func deleteMetaValue(forKey key: String) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM project_meta WHERE key = ?;",
                bindings: [.text(key)]
            )
        }
    }

    public func allMetaEntries() throws -> [String: String] {
        try synchronized {
            let rows = try connection.query("SELECT key, value FROM project_meta ORDER BY key ASC;")
            var result: [String: String] = [:]
            result.reserveCapacity(rows.count)
            for row in rows {
                result[row.string(0)] = row.string(1)
            }
            return result
        }
    }

    public func projectName() throws -> String {
        try synchronized {
            try metaValue(forKey: MetaKeys.projectName) ?? "UntitledProject"
        }
    }

    public func setProjectName(_ name: String) throws {
        try synchronized {
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolved = trimmed.isEmpty ? "UntitledProject" : trimmed
            try setMetaValue(resolved, forKey: MetaKeys.projectName)
            try setMetaValue(String(Date().timeIntervalSince1970), forKey: MetaKeys.updatedAt)
            try syncBundleMetadataFile()
        }
    }

    public func saveLastCursorLocation(_ cursor: SynchronizedCursorLocation) throws {
        try synchronized {
            let data = try StoreJSONCoding.makeEncoder().encode(cursor)
            try setMetaValue(String(decoding: data, as: UTF8.self), forKey: MetaKeys.lastCursorJSON)
        }
    }

    public func lastCursorLocation() throws -> SynchronizedCursorLocation? {
        try synchronized {
            guard let json = try metaValue(forKey: MetaKeys.lastCursorJSON),
                  let data = json.data(using: .utf8) else {
                return nil
            }
            return try StoreJSONCoding.makeDecoder().decode(SynchronizedCursorLocation.self, from: data)
        }
    }

    // MARK: LoadedBinaryImage Metadata & Snapshot Storage

    public func storeBinaryImage(
        _ image: LoadedBinaryImage,
        cacheSymbols: Bool = false
    ) throws {
        try synchronized {
            let summary = StoredBinaryImageSummary(from: image)
            let encoder = StoreJSONCoding.makeEncoder()
            let summaryData = try encoder.encode(summary)
            let fullData = try encoder.encode(image)

            try connection.withTransaction {
                try setMetaValue(image.filePath, forKey: MetaKeys.binaryPath)
                try setMetaValue(image.fileName, forKey: MetaKeys.binaryFileName)
                try setMetaValue(image.sha256Hex, forKey: MetaKeys.binarySHA256)
                try setMetaValue(String(decoding: summaryData, as: UTF8.self), forKey: MetaKeys.binarySummaryJSON)
                try setMetaValue(String(decoding: fullData, as: UTF8.self), forKey: MetaKeys.binaryFullImageJSON)
                try setMetaValue(String(Date().timeIntervalSince1970), forKey: MetaKeys.updatedAt)

                if cacheSymbols && !image.symbols.isEmpty {
                    try batchInsertSymbols(image.symbols, clearExisting: false)
                }
            }
            try syncBundleMetadataFile()
        }
    }

    public func storeBinaryImageSummary(_ summary: StoredBinaryImageSummary) throws {
        try synchronized {
            let summaryData = try StoreJSONCoding.makeEncoder().encode(summary)
            try connection.withTransaction {
                try setMetaValue(summary.filePath, forKey: MetaKeys.binaryPath)
                try setMetaValue(summary.fileName, forKey: MetaKeys.binaryFileName)
                try setMetaValue(summary.sha256Hex, forKey: MetaKeys.binarySHA256)
                try setMetaValue(String(decoding: summaryData, as: UTF8.self), forKey: MetaKeys.binarySummaryJSON)
                try setMetaValue(String(Date().timeIntervalSince1970), forKey: MetaKeys.updatedAt)
            }
            try syncBundleMetadataFile()
        }
    }

    public func loadBinaryImageSummary() throws -> StoredBinaryImageSummary? {
        try synchronized {
            guard let raw = try metaValue(forKey: MetaKeys.binarySummaryJSON),
                  let data = raw.data(using: .utf8) else {
                return nil
            }
            do {
                return try StoreJSONCoding.makeDecoder().decode(StoredBinaryImageSummary.self, from: data)
            } catch {
                throw MachGraphError.databaseError(
                    code: SQLITE_MISMATCH,
                    message: "Corrupted binary summary metadata in project_meta: \(error.localizedDescription)"
                )
            }
        }
    }

    public func loadCachedBinaryImage() throws -> LoadedBinaryImage? {
        try synchronized {
            guard let raw = try metaValue(forKey: MetaKeys.binaryFullImageJSON),
                  let data = raw.data(using: .utf8) else {
                return nil
            }
            do {
                return try StoreJSONCoding.makeDecoder().decode(LoadedBinaryImage.self, from: data)
            } catch {
                throw MachGraphError.databaseError(
                    code: SQLITE_MISMATCH,
                    message: "Corrupted cached LoadedBinaryImage JSON in project_meta: \(error.localizedDescription)"
                )
            }
        }
    }

    public func ingestFullBinaryAnalysis(
        image: LoadedBinaryImage,
        functions: [RecoveredFunction],
        xrefs: [XrefRecord]
    ) throws {
        try synchronized {
            try connection.withTransaction {
                try storeBinaryImage(image, cacheSymbols: false)
                try batchInsertSymbols(image.symbols, clearExisting: true)
                try batchInsertFunctions(functions, clearExisting: true)
                try batchInsertXrefs(xrefs, clearExisting: true)
            }
        }
    }

    // MARK: Cached Symbols (cached_symbols)

    public func batchInsertSymbols(
        _ symbols: [BinarySymbol],
        clearExisting: Bool = false
    ) throws {
        try synchronized {
            try connection.withTransaction {
                if clearExisting {
                    try connection.execute("DELETE FROM cached_symbols;")
                }
                guard !symbols.isEmpty else { return }

                let sql = """
                INSERT INTO cached_symbols (
                    id, name, demangled_name, kind, binding, address, size, section_index, library_ordinal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    demangled_name = excluded.demangled_name,
                    kind = excluded.kind,
                    binding = excluded.binding,
                    address = excluded.address,
                    size = excluded.size,
                    section_index = excluded.section_index,
                    library_ordinal = excluded.library_ordinal;
                """
                try connection.withPreparedStatement(sql) { stmt in
                    for sym in symbols {
                        try stmt.reset(clearBindings: true)
                        try stmt.bindText(sym.id, at: 1)
                        try stmt.bindText(sym.name, at: 2)
                        try stmt.bindText(sym.demangledName, at: 3)
                        try stmt.bindText(sym.kind.rawValue, at: 4)
                        try stmt.bindText(sym.binding.rawValue, at: 5)
                        try stmt.bindAddress(sym.address, at: 6)
                        try stmt.bindUInt64(sym.size, at: 7)
                        try stmt.bindOptionalInt(sym.sectionIndex, at: 8)
                        try stmt.bindOptionalInt(sym.libraryOrdinal, at: 9)
                        _ = try stmt.step()
                    }
                }
            }
        }
    }

    public func upsertSymbol(_ symbol: BinarySymbol) throws {
        try batchInsertSymbols([symbol], clearExisting: false)
    }

    public func allSymbols(limit: Int? = nil) throws -> [BinarySymbol] {
        try synchronized {
            let sql: String
            let bindings: [SQLiteValue]
            if let limit, limit > 0 {
                sql = """
                SELECT name, demangled_name, kind, binding, address, size, section_index, library_ordinal
                FROM cached_symbols
                ORDER BY address ASC, name ASC
                LIMIT ?;
                """
                bindings = [.int(limit)]
            } else {
                sql = """
                SELECT name, demangled_name, kind, binding, address, size, section_index, library_ordinal
                FROM cached_symbols
                ORDER BY address ASC, name ASC;
                """
                bindings = []
            }
            return try connection.withPreparedStatement(sql) { stmt in
                if !bindings.isEmpty {
                    try stmt.bindValues(bindings)
                }
                var results: [BinarySymbol] = []
                while try stmt.step() {
                    results.append(Self.decodeSymbolRow(stmt))
                }
                return results
            }
        }
    }

    public func symbols(at address: VirtualAddress) throws -> [BinarySymbol] {
        try synchronized {
            let sql = """
            SELECT name, demangled_name, kind, binding, address, size, section_index, library_ordinal
            FROM cached_symbols
            WHERE address = ?
            ORDER BY name ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                var results: [BinarySymbol] = []
                while try stmt.step() {
                    results.append(Self.decodeSymbolRow(stmt))
                }
                return results
            }
        }
    }

    public func symbol(at address: VirtualAddress) throws -> BinarySymbol? {
        try symbols(at: address).first
    }

    public func symbols(ofKind kind: SymbolKind, limit: Int = 500) throws -> [BinarySymbol] {
        try synchronized {
            let capped = max(1, limit)
            let sql = """
            SELECT name, demangled_name, kind, binding, address, size, section_index, library_ordinal
            FROM cached_symbols
            WHERE kind = ?
            ORDER BY address ASC, name ASC
            LIMIT ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(kind.rawValue, at: 1)
                try stmt.bindInt(capped, at: 2)
                var results: [BinarySymbol] = []
                while try stmt.step() {
                    results.append(Self.decodeSymbolRow(stmt))
                }
                return results
            }
        }
    }

    public func searchSymbols(query: String, limit: Int = 200) throws -> [BinarySymbol] {
        try synchronized {
            let capped = max(1, limit)
            let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                return try allSymbols(limit: capped)
            }

            if trimmed.lowercased().hasPrefix("0x"),
               let parsedAddress = VirtualAddress(hexOrDecimal: trimmed) {
                let exactMatches = try symbols(at: parsedAddress)
                if !exactMatches.isEmpty {
                    return Array(exactMatches.prefix(capped))
                }
            }

            let escaped = Self.escapeLikePattern(trimmed)
            let containsPattern = "%\(escaped)%"
            let prefixPattern = "\(escaped)%"

            let sql = """
            SELECT
                s.name,
                s.demangled_name,
                s.kind,
                s.binding,
                s.address,
                s.size,
                s.section_index,
                s.library_ordinal
            FROM cached_symbols s
            LEFT JOIN user_renames r ON r.address = s.address
            WHERE s.name LIKE ? ESCAPE '\\'
               OR s.demangled_name LIKE ? ESCAPE '\\'
               OR (r.custom_name IS NOT NULL AND r.custom_name LIKE ? ESCAPE '\\')
            ORDER BY
                CASE
                    WHEN LOWER(COALESCE(r.custom_name, '')) = LOWER(?) THEN 0
                    WHEN LOWER(s.name) = LOWER(?) OR LOWER(s.demangled_name) = LOWER(?) THEN 1
                    WHEN COALESCE(r.custom_name, '') LIKE ? ESCAPE '\\' THEN 2
                    WHEN s.name LIKE ? ESCAPE '\\' OR s.demangled_name LIKE ? ESCAPE '\\' THEN 3
                    ELSE 4
                END ASC,
                s.address ASC,
                s.name ASC
            LIMIT ?;
            """

            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(containsPattern, at: 1)
                try stmt.bindText(containsPattern, at: 2)
                try stmt.bindText(containsPattern, at: 3)
                try stmt.bindText(trimmed, at: 4)
                try stmt.bindText(trimmed, at: 5)
                try stmt.bindText(trimmed, at: 6)
                try stmt.bindText(prefixPattern, at: 7)
                try stmt.bindText(prefixPattern, at: 8)
                try stmt.bindText(prefixPattern, at: 9)
                try stmt.bindInt(capped, at: 10)

                var results: [BinarySymbol] = []
                while try stmt.step() {
                    results.append(Self.decodeSymbolRow(stmt))
                }
                return results
            }
        }
    }

    public func clearCachedSymbols() throws {
        try synchronized {
            try connection.execute("DELETE FROM cached_symbols;")
        }
    }

    private static func decodeSymbolRow(_ stmt: SQLiteStatement) -> BinarySymbol {
        let name = stmt.columnString(at: 0)
        let demangled = stmt.columnString(at: 1)
        let kind = SymbolKind(rawValue: stmt.columnString(at: 2)) ?? .localSymbol
        let binding = SymbolBinding(rawValue: stmt.columnString(at: 3)) ?? .local
        let address = stmt.columnAddress(at: 4)
        let size = stmt.columnUInt64(at: 5)
        let sectionIndex = stmt.columnOptionalInt(at: 6)
        let libraryOrdinal = stmt.columnOptionalInt(at: 7)
        return BinarySymbol(
            name: name,
            demangledName: demangled,
            kind: kind,
            binding: binding,
            address: address,
            size: size,
            sectionIndex: sectionIndex,
            libraryOrdinal: libraryOrdinal
        )
    }

    // MARK: Cached Functions & Serialized CFG Cache (cached_functions)

    public func batchInsertFunctions(
        _ functions: [RecoveredFunction],
        clearExisting: Bool = false
    ) throws {
        try synchronized {
            let encoder = StoreJSONCoding.makeEncoder(sortedKeys: false)
            let now = Date()

            try connection.withTransaction {
                if clearExisting {
                    try connection.execute("DELETE FROM cached_functions;")
                }
                guard !functions.isEmpty else { return }

                let sql = """
                INSERT INTO cached_functions (
                    address, end_address, name, demangled_name,
                    is_leaf, is_thunk, uses_pac, stack_frame_bytes,
                    block_count, edge_count, cyclomatic_complexity, instruction_count,
                    cfg_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    end_address = excluded.end_address,
                    name = excluded.name,
                    demangled_name = excluded.demangled_name,
                    is_leaf = excluded.is_leaf,
                    is_thunk = excluded.is_thunk,
                    uses_pac = excluded.uses_pac,
                    stack_frame_bytes = excluded.stack_frame_bytes,
                    block_count = excluded.block_count,
                    edge_count = excluded.edge_count,
                    cyclomatic_complexity = excluded.cyclomatic_complexity,
                    instruction_count = excluded.instruction_count,
                    cfg_json = excluded.cfg_json,
                    updated_at = excluded.updated_at;
                """

                try connection.withPreparedStatement(sql) { stmt in
                    for fn in functions {
                        let cfgBlob: Data
                        do {
                            cfgBlob = try encoder.encode(fn)
                        } catch {
                            throw MachGraphError.databaseError(
                                code: SQLITE_MISMATCH,
                                message: "Failed encoding RecoveredFunction at \(fn.address.compactHexString): \(error.localizedDescription)"
                            )
                        }

                        try stmt.reset(clearBindings: true)
                        try stmt.bindAddress(fn.address, at: 1)
                        try stmt.bindAddress(fn.endAddress, at: 2)
                        try stmt.bindText(fn.name, at: 3)
                        try stmt.bindText(fn.demangledName, at: 4)
                        try stmt.bindBool(fn.isLeaf, at: 5)
                        try stmt.bindBool(fn.isThunk, at: 6)
                        try stmt.bindBool(fn.usesPAC, at: 7)
                        try stmt.bindInt(fn.stackFrameBytes, at: 8)
                        try stmt.bindInt(fn.blocks.count, at: 9)
                        try stmt.bindInt(fn.edges.count, at: 10)
                        try stmt.bindInt(fn.cyclomaticComplexity, at: 11)
                        try stmt.bindInt(fn.instructionCount, at: 12)
                        try stmt.bindBlob(cfgBlob, at: 13)
                        try stmt.bindDate(now, at: 14)
                        _ = try stmt.step()
                    }
                }
            }
        }
    }

    public func upsertFunction(_ function: RecoveredFunction) throws {
        try batchInsertFunctions([function], clearExisting: false)
    }

    public func function(at address: VirtualAddress) throws -> RecoveredFunction? {
        try synchronized {
            try connection.withPreparedStatement(
                "SELECT cfg_json FROM cached_functions WHERE address = ?;"
            ) { stmt in
                try stmt.bindAddress(address, at: 1)
                guard try stmt.step() else { return nil }
                return try stmt.columnDecodeJSON(RecoveredFunction.self, at: 0)
            }
        }
    }

    public func functionContaining(address: VirtualAddress) throws -> RecoveredFunction? {
        try synchronized {
            if let exact = try function(at: address) {
                return exact
            }
            let sql = """
            SELECT cfg_json FROM cached_functions
            WHERE address <= ? AND end_address > ?
            ORDER BY address DESC
            LIMIT 1;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                try stmt.bindAddress(address, at: 2)
                guard try stmt.step() else { return nil }
                return try stmt.columnDecodeJSON(RecoveredFunction.self, at: 0)
            }
        }
    }

    public func allFunctions(limit: Int? = nil) throws -> [RecoveredFunction] {
        try synchronized {
            let sql: String
            let bindings: [SQLiteValue]
            if let limit, limit > 0 {
                sql = "SELECT cfg_json FROM cached_functions ORDER BY address ASC LIMIT ?;"
                bindings = [.int(limit)]
            } else {
                sql = "SELECT cfg_json FROM cached_functions ORDER BY address ASC;"
                bindings = []
            }
            return try connection.withPreparedStatement(sql) { stmt in
                if !bindings.isEmpty {
                    try stmt.bindValues(bindings)
                }
                var list: [RecoveredFunction] = []
                while try stmt.step() {
                    list.append(try stmt.columnDecodeJSON(RecoveredFunction.self, at: 0))
                }
                return list
            }
        }
    }

    public func allFunctionSummaries(limit: Int? = nil) throws -> [CachedFunctionSummary] {
        try synchronized {
            var sql = """
            SELECT
                f.address,
                f.end_address,
                f.name,
                f.demangled_name,
                r.custom_name,
                f.is_leaf,
                f.is_thunk,
                f.uses_pac,
                f.stack_frame_bytes,
                f.block_count,
                f.edge_count,
                f.cyclomatic_complexity,
                f.instruction_count,
                CASE WHEN f.decompiled_json IS NOT NULL THEN 1 ELSE 0 END,
                f.updated_at
            FROM cached_functions f
            LEFT JOIN user_renames r ON r.address = f.address
            ORDER BY f.address ASC
            """
            var bindings: [SQLiteValue] = []
            if let limit, limit > 0 {
                sql += " LIMIT ?;"
                bindings.append(.int(limit))
            } else {
                sql += ";"
            }

            return try connection.withPreparedStatement(sql) { stmt in
                if !bindings.isEmpty {
                    try stmt.bindValues(bindings)
                }
                var results: [CachedFunctionSummary] = []
                while try stmt.step() {
                    results.append(Self.decodeFunctionSummaryRow(stmt))
                }
                return results
            }
        }
    }

    public func searchFunctionSummaries(query: String, limit: Int = 200) throws -> [CachedFunctionSummary] {
        try synchronized {
            let capped = max(1, limit)
            let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                return try allFunctionSummaries(limit: capped)
            }

            let escaped = Self.escapeLikePattern(trimmed)
            let containsPattern = "%\(escaped)%"
            let sql = """
            SELECT
                f.address,
                f.end_address,
                f.name,
                f.demangled_name,
                r.custom_name,
                f.is_leaf,
                f.is_thunk,
                f.uses_pac,
                f.stack_frame_bytes,
                f.block_count,
                f.edge_count,
                f.cyclomatic_complexity,
                f.instruction_count,
                CASE WHEN f.decompiled_json IS NOT NULL THEN 1 ELSE 0 END,
                f.updated_at
            FROM cached_functions f
            LEFT JOIN user_renames r ON r.address = f.address
            WHERE f.name LIKE ? ESCAPE '\\'
               OR f.demangled_name LIKE ? ESCAPE '\\'
               OR (r.custom_name IS NOT NULL AND r.custom_name LIKE ? ESCAPE '\\')
            ORDER BY f.address ASC
            LIMIT ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(containsPattern, at: 1)
                try stmt.bindText(containsPattern, at: 2)
                try stmt.bindText(containsPattern, at: 3)
                try stmt.bindInt(capped, at: 4)
                var results: [CachedFunctionSummary] = []
                while try stmt.step() {
                    results.append(Self.decodeFunctionSummaryRow(stmt))
                }
                return results
            }
        }
    }

    public func cacheDecompiledFunction(_ output: DecompiledFunctionOutput) throws {
        try synchronized {
            let blob = try StoreJSONCoding.makeEncoder(sortedKeys: false).encode(output)
            try connection.withPreparedStatement(
                "UPDATE cached_functions SET decompiled_json = ?, updated_at = ? WHERE address = ?;"
            ) { stmt in
                try stmt.bindBlob(blob, at: 1)
                try stmt.bindDate(Date(), at: 2)
                try stmt.bindAddress(output.functionAddress, at: 3)
                _ = try stmt.step()
            }
        }
    }

    public func cachedDecompiledFunction(at functionAddress: VirtualAddress) throws -> DecompiledFunctionOutput? {
        try synchronized {
            try connection.withPreparedStatement(
                "SELECT decompiled_json FROM cached_functions WHERE address = ? AND decompiled_json IS NOT NULL;"
            ) { stmt in
                try stmt.bindAddress(functionAddress, at: 1)
                guard try stmt.step() else { return nil }
                return try stmt.columnDecodeJSON(DecompiledFunctionOutput.self, at: 0)
            }
        }
    }

    public func deleteFunction(at address: VirtualAddress) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM cached_functions WHERE address = ?;",
                bindings: [.address(address)]
            )
        }
    }

    public func clearCachedFunctions() throws {
        try synchronized {
            try connection.execute("DELETE FROM cached_functions;")
        }
    }

    private static func decodeFunctionSummaryRow(_ stmt: SQLiteStatement) -> CachedFunctionSummary {
        CachedFunctionSummary(
            address: stmt.columnAddress(at: 0),
            endAddress: stmt.columnAddress(at: 1),
            name: stmt.columnString(at: 2),
            demangledName: stmt.columnString(at: 3),
            customName: stmt.columnOptionalString(at: 4),
            isLeaf: stmt.columnBool(at: 5),
            isThunk: stmt.columnBool(at: 6),
            usesPAC: stmt.columnBool(at: 7),
            stackFrameBytes: stmt.columnInt(at: 8),
            blockCount: stmt.columnInt(at: 9),
            edgeCount: stmt.columnInt(at: 10),
            cyclomaticComplexity: stmt.columnInt(at: 11),
            instructionCount: stmt.columnInt(at: 12),
            hasCachedDecompilation: stmt.columnBool(at: 13),
            updatedAt: stmt.columnDate(at: 14)
        )
    }

    // MARK: Indexed Cross-References (xrefs)

    public func batchInsertXrefs(
        _ xrefs: [XrefRecord],
        clearExisting: Bool = false
    ) throws {
        try synchronized {
            try connection.withTransaction {
                if clearExisting {
                    try connection.execute("DELETE FROM xrefs;")
                }
                guard !xrefs.isEmpty else { return }

                let sql = """
                INSERT INTO xrefs (
                    id, from_addr, from_func, to_addr, kind, instruction_preview
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    from_addr = excluded.from_addr,
                    from_func = excluded.from_func,
                    to_addr = excluded.to_addr,
                    kind = excluded.kind,
                    instruction_preview = excluded.instruction_preview;
                """
                try connection.withPreparedStatement(sql) { stmt in
                    for xref in xrefs {
                        try stmt.reset(clearBindings: true)
                        try stmt.bindUUID(xref.id, at: 1)
                        try stmt.bindAddress(xref.fromAddress, at: 2)
                        try stmt.bindOptionalAddress(xref.fromFunction, at: 3)
                        try stmt.bindAddress(xref.toAddress, at: 4)
                        try stmt.bindText(xref.kind.rawValue, at: 5)
                        try stmt.bindText(xref.instructionPreview, at: 6)
                        _ = try stmt.step()
                    }
                }
            }
        }
    }

    public func xrefsTo(address: VirtualAddress) throws -> [XrefRecord] {
        try synchronized {
            let sql = """
            SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
            FROM xrefs
            WHERE to_addr = ?
            ORDER BY from_addr ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func xrefsTo(address: VirtualAddress, kind: XrefKind) throws -> [XrefRecord] {
        try synchronized {
            let sql = """
            SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
            FROM xrefs
            WHERE to_addr = ? AND kind = ?
            ORDER BY from_addr ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                try stmt.bindText(kind.rawValue, at: 2)
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func xrefsFrom(address: VirtualAddress) throws -> [XrefRecord] {
        try synchronized {
            let sql = """
            SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
            FROM xrefs
            WHERE from_addr = ?
            ORDER BY to_addr ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func xrefsInFunction(functionAddress: VirtualAddress) throws -> [XrefRecord] {
        try synchronized {
            let sql = """
            SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
            FROM xrefs
            WHERE from_func = ?
            ORDER BY from_addr ASC, to_addr ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(functionAddress, at: 1)
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func xrefs(ofKind kind: XrefKind, limit: Int = 500) throws -> [XrefRecord] {
        try synchronized {
            let capped = max(1, limit)
            let sql = """
            SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
            FROM xrefs
            WHERE kind = ?
            ORDER BY from_addr ASC
            LIMIT ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(kind.rawValue, at: 1)
                try stmt.bindInt(capped, at: 2)
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func allXrefs(limit: Int? = nil) throws -> [XrefRecord] {
        try synchronized {
            let sql: String
            let bindings: [SQLiteValue]
            if let limit, limit > 0 {
                sql = """
                SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
                FROM xrefs
                ORDER BY from_addr ASC, to_addr ASC
                LIMIT ?;
                """
                bindings = [.int(limit)]
            } else {
                sql = """
                SELECT id, from_addr, from_func, to_addr, kind, instruction_preview
                FROM xrefs
                ORDER BY from_addr ASC, to_addr ASC;
                """
                bindings = []
            }
            return try connection.withPreparedStatement(sql) { stmt in
                if !bindings.isEmpty {
                    try stmt.bindValues(bindings)
                }
                var list: [XrefRecord] = []
                while try stmt.step() {
                    list.append(Self.decodeXrefRow(stmt))
                }
                return list
            }
        }
    }

    public func xrefCount(to address: VirtualAddress) throws -> Int {
        try synchronized {
            try connection.queryScalarInt(
                "SELECT COUNT(*) FROM xrefs WHERE to_addr = ?;",
                bindings: [.address(address)]
            )
        }
    }

    public func xrefCount(from address: VirtualAddress) throws -> Int {
        try synchronized {
            try connection.queryScalarInt(
                "SELECT COUNT(*) FROM xrefs WHERE from_addr = ?;",
                bindings: [.address(address)]
            )
        }
    }

    public func clearXrefs() throws {
        try synchronized {
            try connection.execute("DELETE FROM xrefs;")
        }
    }

    private static func decodeXrefRow(_ stmt: SQLiteStatement) -> XrefRecord {
        XrefRecord(
            id: stmt.columnUUID(at: 0),
            fromAddress: stmt.columnAddress(at: 1),
            fromFunction: stmt.columnOptionalAddress(at: 2),
            toAddress: stmt.columnAddress(at: 3),
            kind: XrefKind(rawValue: stmt.columnString(at: 4)) ?? .directCall,
            instructionPreview: stmt.columnString(at: 5)
        )
    }

    // MARK: Analyst Symbol Renames (user_renames)

    public func allRenames() throws -> [UserSymbolRename] {
        try synchronized {
            let sql = """
            SELECT address, original_name, custom_name, signature_override, updated_at
            FROM user_renames
            ORDER BY address ASC;
            """
            let rows = try connection.withPreparedStatement(sql) { stmt in
                var list: [UserSymbolRename] = []
                while try stmt.step() {
                    list.append(Self.decodeRenameRow(stmt))
                }
                return list
            }
            return rows.sorted { $0.address < $1.address }
        }
    }

    public func rename(for address: VirtualAddress) throws -> UserSymbolRename? {
        try synchronized {
            let sql = """
            SELECT address, original_name, custom_name, signature_override, updated_at
            FROM user_renames
            WHERE address = ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                guard try stmt.step() else { return nil }
                return Self.decodeRenameRow(stmt)
            }
        }
    }

    public func upsertRename(_ rename: UserSymbolRename) throws {
        try synchronized {
            let sql = """
            INSERT INTO user_renames (
                address, original_name, custom_name, signature_override, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                original_name = excluded.original_name,
                custom_name = excluded.custom_name,
                signature_override = excluded.signature_override,
                updated_at = excluded.updated_at;
            """
            try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(rename.address, at: 1)
                try stmt.bindText(rename.originalName, at: 2)
                try stmt.bindText(rename.customName, at: 3)
                try stmt.bindOptionalText(rename.signatureOverride, at: 4)
                try stmt.bindDate(rename.updatedAt, at: 5)
                _ = try stmt.step()
            }
        }
    }

    public func deleteRename(at address: VirtualAddress) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM user_renames WHERE address = ?;",
                bindings: [.address(address)]
            )
        }
    }

    public func resolveDisplaySymbolName(
        at address: VirtualAddress,
        fallback: String? = nil
    ) throws -> String? {
        try synchronized {
            if let custom = try rename(for: address) {
                return custom.customName
            }
            if let sym = try symbol(at: address) {
                return sym.demangledName.isEmpty ? sym.name : sym.demangledName
            }
            return fallback
        }
    }

    private static func decodeRenameRow(_ stmt: SQLiteStatement) -> UserSymbolRename {
        UserSymbolRename(
            address: stmt.columnAddress(at: 0),
            originalName: stmt.columnString(at: 1),
            customName: stmt.columnString(at: 2),
            signatureOverride: stmt.columnOptionalString(at: 3),
            updatedAt: stmt.columnDate(at: 4)
        )
    }

    // MARK: Analyst Inline Comments (user_comments)

    public func allComments() throws -> [UserInlineComment] {
        try synchronized {
            let sql = """
            SELECT address, text, is_repeatable, updated_at
            FROM user_comments
            ORDER BY address ASC;
            """
            let rows = try connection.withPreparedStatement(sql) { stmt in
                var list: [UserInlineComment] = []
                while try stmt.step() {
                    list.append(Self.decodeCommentRow(stmt))
                }
                return list
            }
            return rows.sorted { $0.address < $1.address }
        }
    }

    public func comment(at address: VirtualAddress) throws -> UserInlineComment? {
        try synchronized {
            let sql = """
            SELECT address, text, is_repeatable, updated_at
            FROM user_comments
            WHERE address = ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                guard try stmt.step() else { return nil }
                return Self.decodeCommentRow(stmt)
            }
        }
    }

    public func comments(in range: AddressRange) throws -> [UserInlineComment] {
        try synchronized {
            let all = try allComments()
            return all.filter { range.contains($0.address) }
        }
    }

    public func upsertComment(_ comment: UserInlineComment) throws {
        try synchronized {
            let sql = """
            INSERT INTO user_comments (
                address, text, is_repeatable, updated_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                text = excluded.text,
                is_repeatable = excluded.is_repeatable,
                updated_at = excluded.updated_at;
            """
            try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(comment.address, at: 1)
                try stmt.bindText(comment.text, at: 2)
                try stmt.bindBool(comment.isRepeatable, at: 3)
                try stmt.bindDate(comment.updatedAt, at: 4)
                _ = try stmt.step()
            }
        }
    }

    public func deleteComment(at address: VirtualAddress) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM user_comments WHERE address = ?;",
                bindings: [.address(address)]
            )
        }
    }

    private static func decodeCommentRow(_ stmt: SQLiteStatement) -> UserInlineComment {
        UserInlineComment(
            address: stmt.columnAddress(at: 0),
            text: stmt.columnString(at: 1),
            isRepeatable: stmt.columnBool(at: 2),
            updatedAt: stmt.columnDate(at: 3)
        )
    }

    // MARK: Analyst Bookmarks (user_bookmarks)

    public func allBookmarks() throws -> [UserBookmark] {
        try synchronized {
            let sql = """
            SELECT id, address, label, category_tag, created_at
            FROM user_bookmarks
            ORDER BY address ASC, created_at ASC;
            """
            let rows = try connection.withPreparedStatement(sql) { stmt in
                var list: [UserBookmark] = []
                while try stmt.step() {
                    list.append(Self.decodeBookmarkRow(stmt))
                }
                return list
            }
            return rows.sorted {
                if $0.address != $1.address {
                    return $0.address < $1.address
                }
                return $0.createdAt < $1.createdAt
            }
        }
    }

    public func bookmark(id: UUID) throws -> UserBookmark? {
        try synchronized {
            let sql = """
            SELECT id, address, label, category_tag, created_at
            FROM user_bookmarks
            WHERE id = ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(id, at: 1)
                guard try stmt.step() else { return nil }
                return Self.decodeBookmarkRow(stmt)
            }
        }
    }

    public func bookmarks(at address: VirtualAddress) throws -> [UserBookmark] {
        try synchronized {
            let sql = """
            SELECT id, address, label, category_tag, created_at
            FROM user_bookmarks
            WHERE address = ?
            ORDER BY created_at ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                var list: [UserBookmark] = []
                while try stmt.step() {
                    list.append(Self.decodeBookmarkRow(stmt))
                }
                return list
            }
        }
    }

    public func bookmarks(forCategory categoryTag: String) throws -> [UserBookmark] {
        try synchronized {
            let sql = """
            SELECT id, address, label, category_tag, created_at
            FROM user_bookmarks
            WHERE category_tag = ?
            ORDER BY address ASC;
            """
            let rows = try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(categoryTag, at: 1)
                var list: [UserBookmark] = []
                while try stmt.step() {
                    list.append(Self.decodeBookmarkRow(stmt))
                }
                return list
            }
            return rows.sorted { $0.address < $1.address }
        }
    }

    public func upsertBookmark(_ bookmark: UserBookmark) throws {
        try synchronized {
            let sql = """
            INSERT INTO user_bookmarks (
                id, address, label, category_tag, created_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                address = excluded.address,
                label = excluded.label,
                category_tag = excluded.category_tag,
                created_at = excluded.created_at;
            """
            try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(bookmark.id, at: 1)
                try stmt.bindAddress(bookmark.address, at: 2)
                try stmt.bindText(bookmark.label, at: 3)
                try stmt.bindText(bookmark.categoryTag, at: 4)
                try stmt.bindDate(bookmark.createdAt, at: 5)
                _ = try stmt.step()
            }
        }
    }

    public func deleteBookmark(id: UUID) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM user_bookmarks WHERE id = ?;",
                bindings: [.uuid(id)]
            )
        }
    }

    private static func decodeBookmarkRow(_ stmt: SQLiteStatement) -> UserBookmark {
        UserBookmark(
            id: stmt.columnUUID(at: 0),
            address: stmt.columnAddress(at: 1),
            label: stmt.columnString(at: 2),
            categoryTag: stmt.columnString(at: 3),
            createdAt: stmt.columnDate(at: 4)
        )
    }

    // MARK: Custom C Struct Definitions (custom_structs)

    public func allStructs() throws -> [CustomStructDefinition] {
        try synchronized {
            let sql = """
            SELECT id, name, total_byte_size, alignment, fields_json, updated_at
            FROM custom_structs
            ORDER BY name COLLATE NOCASE ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                var list: [CustomStructDefinition] = []
                while try stmt.step() {
                    list.append(try Self.decodeStructRow(stmt))
                }
                return list
            }
        }
    }

    public func customStruct(id: UUID) throws -> CustomStructDefinition? {
        try synchronized {
            let sql = """
            SELECT id, name, total_byte_size, alignment, fields_json, updated_at
            FROM custom_structs
            WHERE id = ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(id, at: 1)
                guard try stmt.step() else { return nil }
                return try Self.decodeStructRow(stmt)
            }
        }
    }

    public func customStruct(named name: String) throws -> CustomStructDefinition? {
        try synchronized {
            let sql = """
            SELECT id, name, total_byte_size, alignment, fields_json, updated_at
            FROM custom_structs
            WHERE name = ? COLLATE NOCASE
            LIMIT 1;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(name, at: 1)
                guard try stmt.step() else { return nil }
                return try Self.decodeStructRow(stmt)
            }
        }
    }

    public func upsertStruct(_ structDef: CustomStructDefinition) throws {
        try synchronized {
            let sql = """
            INSERT INTO custom_structs (
                id, name, total_byte_size, alignment, fields_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                total_byte_size = excluded.total_byte_size,
                alignment = excluded.alignment,
                fields_json = excluded.fields_json,
                updated_at = excluded.updated_at;
            """
            try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(structDef.id, at: 1)
                try stmt.bindText(structDef.name, at: 2)
                try stmt.bindInt(structDef.totalByteSize, at: 3)
                try stmt.bindInt(structDef.alignment, at: 4)
                try stmt.bindCodableJSON(structDef.fields, asBlob: false, at: 5)
                try stmt.bindDate(structDef.updatedAt, at: 6)
                _ = try stmt.step()
            }
        }
    }

    public func deleteStruct(id: UUID) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM custom_structs WHERE id = ?;",
                bindings: [.uuid(id)]
            )
        }
    }

    private static func decodeStructRow(_ stmt: SQLiteStatement) throws -> CustomStructDefinition {
        let fields = try stmt.columnDecodeJSON([CustomStructField].self, at: 4)
        return CustomStructDefinition(
            id: stmt.columnUUID(at: 0),
            name: stmt.columnString(at: 1),
            totalByteSize: stmt.columnInt(at: 2),
            alignment: stmt.columnInt(at: 3),
            fields: fields,
            updatedAt: stmt.columnDate(at: 5)
        )
    }

    // MARK: Binary Byte Patches (byte_patches)

    public func allPatches() throws -> [BytePatchRecord] {
        try synchronized {
            let sql = """
            SELECT
                id, file_offset, virtual_address, original_bytes, patched_bytes,
                original_assembly, patched_assembly, note, is_enabled, created_at
            FROM byte_patches
            ORDER BY file_offset ASC, created_at ASC;
            """
            let rows = try connection.withPreparedStatement(sql) { stmt in
                var list: [BytePatchRecord] = []
                while try stmt.step() {
                    list.append(Self.decodePatchRow(stmt))
                }
                return list
            }
            return rows.sorted {
                if $0.fileOffset != $1.fileOffset {
                    return $0.fileOffset < $1.fileOffset
                }
                return $0.createdAt < $1.createdAt
            }
        }
    }

    public func enabledPatches() throws -> [BytePatchRecord] {
        try allPatches().filter(\.isEnabled)
    }

    public func patch(id: UUID) throws -> BytePatchRecord? {
        try synchronized {
            let sql = """
            SELECT
                id, file_offset, virtual_address, original_bytes, patched_bytes,
                original_assembly, patched_assembly, note, is_enabled, created_at
            FROM byte_patches
            WHERE id = ?;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(id, at: 1)
                guard try stmt.step() else { return nil }
                return Self.decodePatchRow(stmt)
            }
        }
    }

    public func patches(at fileOffset: FileOffset) throws -> [BytePatchRecord] {
        try synchronized {
            let sql = """
            SELECT
                id, file_offset, virtual_address, original_bytes, patched_bytes,
                original_assembly, patched_assembly, note, is_enabled, created_at
            FROM byte_patches
            WHERE file_offset = ?
            ORDER BY created_at ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindFileOffset(fileOffset, at: 1)
                var list: [BytePatchRecord] = []
                while try stmt.step() {
                    list.append(Self.decodePatchRow(stmt))
                }
                return list
            }
        }
    }

    public func patches(atVirtualAddress address: VirtualAddress) throws -> [BytePatchRecord] {
        try synchronized {
            let sql = """
            SELECT
                id, file_offset, virtual_address, original_bytes, patched_bytes,
                original_assembly, patched_assembly, note, is_enabled, created_at
            FROM byte_patches
            WHERE virtual_address = ?
            ORDER BY created_at ASC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindAddress(address, at: 1)
                var list: [BytePatchRecord] = []
                while try stmt.step() {
                    list.append(Self.decodePatchRow(stmt))
                }
                return list
            }
        }
    }

    public func upsertPatch(_ patch: BytePatchRecord) throws {
        try synchronized {
            let sql = """
            INSERT INTO byte_patches (
                id, file_offset, virtual_address, original_bytes, patched_bytes,
                original_assembly, patched_assembly, note, is_enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                file_offset = excluded.file_offset,
                virtual_address = excluded.virtual_address,
                original_bytes = excluded.original_bytes,
                patched_bytes = excluded.patched_bytes,
                original_assembly = excluded.original_assembly,
                patched_assembly = excluded.patched_assembly,
                note = excluded.note,
                is_enabled = excluded.is_enabled,
                created_at = excluded.created_at;
            """
            try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(patch.id, at: 1)
                try stmt.bindFileOffset(patch.fileOffset, at: 2)
                try stmt.bindOptionalAddress(patch.virtualAddress, at: 3)
                try stmt.bindBytes(patch.originalBytes, at: 4)
                try stmt.bindBytes(patch.patchedBytes, at: 5)
                try stmt.bindOptionalText(patch.originalAssembly, at: 6)
                try stmt.bindOptionalText(patch.patchedAssembly, at: 7)
                try stmt.bindText(patch.note, at: 8)
                try stmt.bindBool(patch.isEnabled, at: 9)
                try stmt.bindDate(patch.createdAt, at: 10)
                _ = try stmt.step()
            }
        }
    }

    public func deletePatch(id: UUID) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM byte_patches WHERE id = ?;",
                bindings: [.uuid(id)]
            )
        }
    }

    private static func decodePatchRow(_ stmt: SQLiteStatement) -> BytePatchRecord {
        BytePatchRecord(
            id: stmt.columnUUID(at: 0),
            fileOffset: stmt.columnFileOffset(at: 1),
            virtualAddress: stmt.columnOptionalAddress(at: 2),
            originalBytes: stmt.columnBytes(at: 3),
            patchedBytes: stmt.columnBytes(at: 4),
            originalAssembly: stmt.columnOptionalString(at: 5),
            patchedAssembly: stmt.columnOptionalString(at: 6),
            note: stmt.columnString(at: 7),
            isEnabled: stmt.columnBool(at: 8),
            createdAt: stmt.columnDate(at: 9)
        )
    }

    // MARK: Security Audit Findings (security_findings)

    public func replaceFindings(
        forPluginID pluginID: String,
        findings: [SecurityAuditFinding]
    ) throws {
        try synchronized {
            try connection.withTransaction {
                _ = try connection.execute(
                    "DELETE FROM security_findings WHERE plugin_id = ?;",
                    bindings: [.text(pluginID)]
                )
                guard !findings.isEmpty else { return }

                let sql = """
                INSERT INTO security_findings (
                    id, plugin_id, plugin_name, severity, category,
                    title, detail, address, evidence_preview, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    plugin_id = excluded.plugin_id,
                    plugin_name = excluded.plugin_name,
                    severity = excluded.severity,
                    category = excluded.category,
                    title = excluded.title,
                    detail = excluded.detail,
                    address = excluded.address,
                    evidence_preview = excluded.evidence_preview,
                    created_at = excluded.created_at;
                """
                try connection.withPreparedStatement(sql) { stmt in
                    for finding in findings {
                        try stmt.reset(clearBindings: true)
                        try stmt.bindUUID(finding.id, at: 1)
                        try stmt.bindText(pluginID, at: 2)
                        try stmt.bindText(finding.pluginName, at: 3)
                        try stmt.bindText(finding.severity.rawValue, at: 4)
                        try stmt.bindText(finding.category, at: 5)
                        try stmt.bindText(finding.title, at: 6)
                        try stmt.bindText(finding.detail, at: 7)
                        try stmt.bindOptionalAddress(finding.address, at: 8)
                        try stmt.bindOptionalText(finding.evidencePreview, at: 9)
                        try stmt.bindDate(finding.createdAt, at: 10)
                        _ = try stmt.step()
                    }
                }
            }
        }
    }

    public func allFindings() throws -> [SecurityAuditFinding] {
        try synchronized {
            let sql = """
            SELECT
                id, plugin_id, plugin_name, severity, category,
                title, detail, address, evidence_preview, created_at
            FROM security_findings
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END DESC,
                created_at DESC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                var list: [SecurityAuditFinding] = []
                while try stmt.step() {
                    list.append(Self.decodeFindingRow(stmt))
                }
                return list
            }
        }
    }

    public func findings(forPluginID pluginID: String) throws -> [SecurityAuditFinding] {
        try synchronized {
            let sql = """
            SELECT
                id, plugin_id, plugin_name, severity, category,
                title, detail, address, evidence_preview, created_at
            FROM security_findings
            WHERE plugin_id = ?
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END DESC,
                created_at DESC;
            """
            return try connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(pluginID, at: 1)
                var list: [SecurityAuditFinding] = []
                while try stmt.step() {
                    list.append(Self.decodeFindingRow(stmt))
                }
                return list
            }
        }
    }

    public func findings(atOrAbove minimumSeverity: SecurityFindingSeverity) throws -> [SecurityAuditFinding] {
        try allFindings().filter { $0.severity >= minimumSeverity }
    }

    public func deleteFindings(forPluginID pluginID: String) throws {
        try synchronized {
            _ = try connection.execute(
                "DELETE FROM security_findings WHERE plugin_id = ?;",
                bindings: [.text(pluginID)]
            )
        }
    }

    public func clearAllFindings() throws {
        try synchronized {
            try connection.execute("DELETE FROM security_findings;")
        }
    }

    private static func decodeFindingRow(_ stmt: SQLiteStatement) -> SecurityAuditFinding {
        SecurityAuditFinding(
            id: stmt.columnUUID(at: 0),
            pluginID: stmt.columnString(at: 1),
            pluginName: stmt.columnString(at: 2),
            severity: SecurityFindingSeverity(rawValue: stmt.columnString(at: 3)) ?? .info,
            category: stmt.columnString(at: 4),
            title: stmt.columnString(at: 5),
            detail: stmt.columnString(at: 6),
            address: stmt.columnOptionalAddress(at: 7),
            evidencePreview: stmt.columnOptionalString(at: 8),
            createdAt: stmt.columnDate(at: 9)
        )
    }

    // MARK: Atomic Analyst Mutation Execution

    public func applyMutation(_ operation: AnalystMutationOperation) throws {
        try synchronized {
            switch operation {
            case .setRename(let previous, let updated):
                if let updated {
                    if let previous, previous.address != updated.address {
                        try deleteRename(at: previous.address)
                    }
                    try upsertRename(updated)
                } else if let previous {
                    try deleteRename(at: previous.address)
                }

            case .setComment(let previous, let updated):
                if let updated {
                    if let previous, previous.address != updated.address {
                        try deleteComment(at: previous.address)
                    }
                    try upsertComment(updated)
                } else if let previous {
                    try deleteComment(at: previous.address)
                }

            case .setBookmark(let previous, let updated):
                if let updated {
                    if let previous, previous.id != updated.id {
                        try deleteBookmark(id: previous.id)
                    }
                    try upsertBookmark(updated)
                } else if let previous {
                    try deleteBookmark(id: previous.id)
                }

            case .setPatch(let previous, let updated):
                if let updated {
                    if let previous, previous.id != updated.id {
                        try deletePatch(id: previous.id)
                    }
                    try upsertPatch(updated)
                } else if let previous {
                    try deletePatch(id: previous.id)
                }

            case .setStruct(let previous, let updated):
                if let updated {
                    if let previous, previous.id != updated.id {
                        try deleteStruct(id: previous.id)
                    }
                    try upsertStruct(updated)
                } else if let previous {
                    try deleteStruct(id: previous.id)
                }
            }
        }
    }

    // MARK: Aggregate Project Telemetry (MachProjectStats)

    public func computeProjectStats() throws -> MachProjectStats {
        try synchronized {
            let name = try projectName()
            let summary = try loadBinaryImageSummary()
            let binaryPath = try (metaValue(forKey: MetaKeys.binaryPath) ?? summary?.filePath ?? "")
            let binarySHA256 = try (metaValue(forKey: MetaKeys.binarySHA256) ?? summary?.sha256Hex ?? "")
            let schemaVer = try connection.userSchemaVersion()
            let footprint = connection.inspectStorageFootprint()

            let functionCount = try connection.queryScalarInt("SELECT COUNT(*) FROM cached_functions;")
            let symbolCount = try connection.queryScalarInt("SELECT COUNT(*) FROM cached_symbols;")
            let xrefCount = try connection.queryScalarInt("SELECT COUNT(*) FROM xrefs;")
            let patchCount = try connection.queryScalarInt("SELECT COUNT(*) FROM byte_patches;")
            let bookmarkCount = try connection.queryScalarInt("SELECT COUNT(*) FROM user_bookmarks;")
            let commentCount = try connection.queryScalarInt("SELECT COUNT(*) FROM user_comments;")
            let renameCount = try connection.queryScalarInt("SELECT COUNT(*) FROM user_renames;")
            let structCount = try connection.queryScalarInt("SELECT COUNT(*) FROM custom_structs;")
            let findingCount = try connection.queryScalarInt("SELECT COUNT(*) FROM security_findings;")

            let undoDepth: Int
            let redoDepth: Int
            if schemaVer >= MachSchemaVersion.v4 {
                undoDepth = try connection.queryScalarInt(
                    "SELECT COUNT(*) FROM undo_redo_journal WHERE stack_kind = 'undo';"
                )
                redoDepth = try connection.queryScalarInt(
                    "SELECT COUNT(*) FROM undo_redo_journal WHERE stack_kind = 'redo';"
                )
            } else {
                undoDepth = 0
                redoDepth = 0
            }

            return MachProjectStats(
                projectName: name,
                binaryPath: binaryPath,
                binarySHA256: binarySHA256,
                schemaVersion: schemaVer,
                sqliteBytes: footprint.databaseBytes,
                walBytes: footprint.walBytes,
                functionCount: functionCount,
                symbolCount: symbolCount,
                xrefCount: xrefCount,
                patchCount: patchCount,
                bookmarkCount: bookmarkCount,
                commentCount: commentCount,
                renameCount: renameCount,
                structCount: structCount,
                findingCount: findingCount,
                undoDepth: undoDepth,
                redoDepth: redoDepth
            )
        }
    }

    // MARK: SQL Pattern Helpers

    private static func escapeLikePattern(_ raw: String) -> String {
        var output = ""
        output.reserveCapacity(raw.count)
        for ch in raw {
            switch ch {
            case "\\", "%", "_":
                output.append("\\")
                output.append(ch)
            default:
                output.append(ch)
            }
        }
        return output
    }
}
