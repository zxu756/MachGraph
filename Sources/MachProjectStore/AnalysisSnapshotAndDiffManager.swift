import Foundation
import SQLite3
import MachGraphModels

// MARK: - Checkpoint Snapshot & Semantic Diff Models

public struct AnalysisCheckpointPayload: Sendable, Codable, Hashable {
    public static let currentFormatVersion: Int = 1

    public let formatVersion: Int
    public let projectName: String
    public let binarySHA256: String
    public let capturedAt: Date
    public let renames: [UserSymbolRename]
    public let comments: [UserInlineComment]
    public let bookmarks: [UserBookmark]
    public let structs: [CustomStructDefinition]
    public let patches: [BytePatchRecord]

    public init(
        formatVersion: Int = Self.currentFormatVersion,
        projectName: String,
        binarySHA256: String,
        capturedAt: Date = Date(),
        renames: [UserSymbolRename],
        comments: [UserInlineComment],
        bookmarks: [UserBookmark],
        structs: [CustomStructDefinition],
        patches: [BytePatchRecord]
    ) {
        self.formatVersion = formatVersion
        self.projectName = projectName
        self.binarySHA256 = binarySHA256
        self.capturedAt = capturedAt
        self.renames = renames.sorted { $0.address < $1.address }
        self.comments = comments.sorted { $0.address < $1.address }
        self.bookmarks = bookmarks.sorted {
            if $0.address != $1.address { return $0.address < $1.address }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.structs = structs.sorted {
            let cmp = $0.name.localizedCaseInsensitiveCompare($1.name)
            if cmp != .orderedSame { return cmp == .orderedAscending }
            return $0.id.uuidString < $1.id.uuidString
        }
        self.patches = patches.sorted {
            if $0.fileOffset != $1.fileOffset { return $0.fileOffset < $1.fileOffset }
            return $0.id.uuidString < $1.id.uuidString
        }
    }
}

public struct AnalysisCheckpointSummary: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public var name: String
    public var note: String
    public let binarySHA256: String
    public let renameCount: Int
    public let commentCount: Int
    public let bookmarkCount: Int
    public let structCount: Int
    public let patchCount: Int
    public let payloadSHA256: String
    public let createdAt: Date

    public init(
        id: UUID,
        name: String,
        note: String,
        binarySHA256: String,
        renameCount: Int,
        commentCount: Int,
        bookmarkCount: Int,
        structCount: Int,
        patchCount: Int,
        payloadSHA256: String,
        createdAt: Date
    ) {
        self.id = id
        self.name = name
        self.note = note
        self.binarySHA256 = binarySHA256
        self.renameCount = renameCount
        self.commentCount = commentCount
        self.bookmarkCount = bookmarkCount
        self.structCount = structCount
        self.patchCount = patchCount
        self.payloadSHA256 = payloadSHA256
        self.createdAt = createdAt
    }

    public var totalAnnotationCount: Int {
        renameCount + commentCount + bookmarkCount + structCount + patchCount
    }
}

public struct AnalysisCheckpoint: Sendable, Codable, Hashable, Identifiable {
    public var id: UUID { summary.id }
    public let summary: AnalysisCheckpointSummary
    public let payload: AnalysisCheckpointPayload

    public init(summary: AnalysisCheckpointSummary, payload: AnalysisCheckpointPayload) {
        self.summary = summary
        self.payload = payload
    }
}

public struct CheckpointModifiedItem<Element: Sendable & Codable & Hashable>: Sendable, Codable, Hashable {
    public let before: Element
    public let after: Element
    public let changeHighlights: [String]

    public init(before: Element, after: Element, changeHighlights: [String]) {
        self.before = before
        self.after = after
        self.changeHighlights = changeHighlights
    }
}

public struct CheckpointCategoryDiff<Element: Sendable & Codable & Hashable>: Sendable, Codable, Hashable {
    public let added: [Element]
    public let removed: [Element]
    public let modified: [CheckpointModifiedItem<Element>]
    public let unchangedCount: Int

    public init(
        added: [Element],
        removed: [Element],
        modified: [CheckpointModifiedItem<Element>],
        unchangedCount: Int
    ) {
        self.added = added
        self.removed = removed
        self.modified = modified
        self.unchangedCount = unchangedCount
    }

    public var addedCount: Int { added.count }
    public var removedCount: Int { removed.count }
    public var modifiedCount: Int { modified.count }
    public var totalChanges: Int { added.count + removed.count + modified.count }
    public var hasChanges: Bool { totalChanges > 0 }
}

public struct AnalysisCheckpointDiff: Sendable, Codable, Hashable {
    public let baseCheckpointID: UUID
    public let baseCheckpointName: String
    public let targetCheckpointID: UUID?
    public let targetCheckpointName: String
    public let computedAt: Date
    public let renames: CheckpointCategoryDiff<UserSymbolRename>
    public let comments: CheckpointCategoryDiff<UserInlineComment>
    public let bookmarks: CheckpointCategoryDiff<UserBookmark>
    public let structs: CheckpointCategoryDiff<CustomStructDefinition>
    public let patches: CheckpointCategoryDiff<BytePatchRecord>

    public init(
        baseCheckpointID: UUID,
        baseCheckpointName: String,
        targetCheckpointID: UUID?,
        targetCheckpointName: String,
        computedAt: Date = Date(),
        renames: CheckpointCategoryDiff<UserSymbolRename>,
        comments: CheckpointCategoryDiff<UserInlineComment>,
        bookmarks: CheckpointCategoryDiff<UserBookmark>,
        structs: CheckpointCategoryDiff<CustomStructDefinition>,
        patches: CheckpointCategoryDiff<BytePatchRecord>
    ) {
        self.baseCheckpointID = baseCheckpointID
        self.baseCheckpointName = baseCheckpointName
        self.targetCheckpointID = targetCheckpointID
        self.targetCheckpointName = targetCheckpointName
        self.computedAt = computedAt
        self.renames = renames
        self.comments = comments
        self.bookmarks = bookmarks
        self.structs = structs
        self.patches = patches
    }

    public var totalAddedCount: Int {
        renames.addedCount + comments.addedCount + bookmarks.addedCount + structs.addedCount + patches.addedCount
    }

    public var totalRemovedCount: Int {
        renames.removedCount + comments.removedCount + bookmarks.removedCount + structs.removedCount + patches.removedCount
    }

    public var totalModifiedCount: Int {
        renames.modifiedCount + comments.modifiedCount + bookmarks.modifiedCount + structs.modifiedCount + patches.modifiedCount
    }

    public var totalChangeCount: Int {
        totalAddedCount + totalRemovedCount + totalModifiedCount
    }

    public var isIdentical: Bool {
        totalChangeCount == 0
    }

    public func renderMarkdownReport() -> String {
        var lines: [String] = []
        lines.append("# MachGraph Checkpoint Diff Report")
        lines.append("")
        lines.append("- **Base Checkpoint:** `\(baseCheckpointName)` (`\(baseCheckpointID.uuidString)`)")
        if let targetID = targetCheckpointID {
            lines.append("- **Target Checkpoint:** `\(targetCheckpointName)` (`\(targetID.uuidString)`)")
        } else {
            lines.append("- **Target State:** `\(targetCheckpointName)` (Live Database)")
        }
        lines.append("- **Total Delta:** +\(totalAddedCount) added / -\(totalRemovedCount) removed / ~\(totalModifiedCount) modified")
        lines.append("")

        lines.append("| Domain | Added | Removed | Modified | Unchanged |")
        lines.append("|---|---:|---:|---:|---:|")
        lines.append("| Symbol Renames | \(renames.addedCount) | \(renames.removedCount) | \(renames.modifiedCount) | \(renames.unchangedCount) |")
        lines.append("| Inline Comments | \(comments.addedCount) | \(comments.removedCount) | \(comments.modifiedCount) | \(comments.unchangedCount) |")
        lines.append("| Bookmarks | \(bookmarks.addedCount) | \(bookmarks.removedCount) | \(bookmarks.modifiedCount) | \(bookmarks.unchangedCount) |")
        lines.append("| Custom Structs | \(structs.addedCount) | \(structs.removedCount) | \(structs.modifiedCount) | \(structs.unchangedCount) |")
        lines.append("| Byte Patches | \(patches.addedCount) | \(patches.removedCount) | \(patches.modifiedCount) | \(patches.unchangedCount) |")
        lines.append("")

        if isIdentical {
            lines.append("_No semantic differences detected between the two states._")
            return lines.joined(separator: "\n")
        }

        if renames.hasChanges {
            lines.append("## Symbol Renames")
            for r in renames.added {
                lines.append("- `[+]` `\(r.address.compactHexString)` `\(r.originalName)` -> **`\(r.customName)`**")
            }
            for r in renames.removed {
                lines.append("- `[-]` `\(r.address.compactHexString)` `\(r.originalName)` (was `\(r.customName)`)")
            }
            for m in renames.modified {
                let detail = m.changeHighlights.joined(separator: "; ")
                lines.append("- `[~]` `\(m.after.address.compactHexString)`: \(detail)")
            }
            lines.append("")
        }

        if comments.hasChanges {
            lines.append("## Inline Comments")
            for c in comments.added {
                lines.append("- `[+]` `\(c.address.compactHexString)`: \(c.text)")
            }
            for c in comments.removed {
                lines.append("- `[-]` `\(c.address.compactHexString)`: \(c.text)")
            }
            for m in comments.modified {
                lines.append("- `[~]` `\(m.after.address.compactHexString)`: \(m.changeHighlights.joined(separator: "; "))")
            }
            lines.append("")
        }

        if bookmarks.hasChanges {
            lines.append("## Bookmarks")
            for b in bookmarks.added {
                lines.append("- `[+]` `\(b.address.compactHexString)` [\(b.categoryTag)] **\(b.label)**")
            }
            for b in bookmarks.removed {
                lines.append("- `[-]` `\(b.address.compactHexString)` [\(b.categoryTag)] **\(b.label)**")
            }
            for m in bookmarks.modified {
                lines.append("- `[~]` `\(m.after.address.compactHexString)`: \(m.changeHighlights.joined(separator: "; "))")
            }
            lines.append("")
        }

        if structs.hasChanges {
            lines.append("## Custom C Structs")
            for s in structs.added {
                lines.append("- `[+]` `struct \(s.name)` (\(s.totalByteSize) bytes, \(s.fields.count) fields)")
            }
            for s in structs.removed {
                lines.append("- `[-]` `struct \(s.name)` (\(s.totalByteSize) bytes)")
            }
            for m in structs.modified {
                lines.append("- `[~]` `struct \(m.after.name)`: \(m.changeHighlights.joined(separator: "; "))")
            }
            lines.append("")
        }

        if patches.hasChanges {
            lines.append("## Binary Byte Patches")
            for p in patches.added {
                let loc = p.virtualAddress?.compactHexString ?? p.fileOffset.hexString
                lines.append("- `[+]` `\(loc)` (`\(p.originalHex)` -> `\(p.patchedHex)`) \(p.note)")
            }
            for p in patches.removed {
                let loc = p.virtualAddress?.compactHexString ?? p.fileOffset.hexString
                lines.append("- `[-]` `\(loc)` (`\(p.originalHex)` -> `\(p.patchedHex)`)")
            }
            for m in patches.modified {
                let loc = m.after.virtualAddress?.compactHexString ?? m.after.fileOffset.hexString
                lines.append("- `[~]` `\(loc)`: \(m.changeHighlights.joined(separator: "; "))")
            }
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }
}

public struct CheckpointRestoreResult: Sendable, Codable, Hashable {
    public let restoredCheckpointID: UUID
    public let restoredCheckpointName: String
    public let safetyBackupCheckpointID: UUID?
    public let appliedMutationCount: Int
    public let restoredRenameCount: Int
    public let restoredCommentCount: Int
    public let restoredBookmarkCount: Int
    public let restoredStructCount: Int
    public let restoredPatchCount: Int

    public init(
        restoredCheckpointID: UUID,
        restoredCheckpointName: String,
        safetyBackupCheckpointID: UUID?,
        appliedMutationCount: Int,
        restoredRenameCount: Int,
        restoredCommentCount: Int,
        restoredBookmarkCount: Int,
        restoredStructCount: Int,
        restoredPatchCount: Int
    ) {
        self.restoredCheckpointID = restoredCheckpointID
        self.restoredCheckpointName = restoredCheckpointName
        self.safetyBackupCheckpointID = safetyBackupCheckpointID
        self.appliedMutationCount = appliedMutationCount
        self.restoredRenameCount = restoredRenameCount
        self.restoredCommentCount = restoredCommentCount
        self.restoredBookmarkCount = restoredBookmarkCount
        self.restoredStructCount = restoredStructCount
        self.restoredPatchCount = restoredPatchCount
    }
}

// MARK: - Analysis Snapshot & Diff Manager

public final class AnalysisSnapshotAndDiffManager: @unchecked Sendable {
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

    // MARK: Create, List, Load, Update & Delete Checkpoints

    @discardableResult
    public func createCheckpoint(
        name: String,
        note: String = ""
    ) throws -> AnalysisCheckpointSummary {
        try synchronized {
            let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
            let resolvedName = trimmedName.isEmpty
                ? "Checkpoint \(Self.compactTimestampString(Date()))"
                : trimmedName
            let cleanNote = note.trimmingCharacters(in: .whitespacesAndNewlines)

            return try database.withTransaction {
                let payload = try captureLivePayload(capturedAt: Date())
                let payloadData: Data
                do {
                    payloadData = try StoreJSONCoding.makeEncoder(sortedKeys: true).encode(payload)
                } catch {
                    throw MachGraphError.databaseError(
                        code: SQLITE_MISMATCH,
                        message: "Failed encoding checkpoint payload: \(error.localizedDescription)"
                    )
                }

                let digest = BinaryHashAndEntropy.sha256Hex(of: payloadData)
                let checkpointID = UUID()
                let createdAt = payload.capturedAt

                let sql = """
                INSERT INTO analysis_snapshots (
                    id, name, note, binary_sha256,
                    rename_count, comment_count, bookmark_count, struct_count, patch_count,
                    payload_sha256, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """

                try database.connection.withPreparedStatement(sql) { stmt in
                    try stmt.bindUUID(checkpointID, at: 1)
                    try stmt.bindText(resolvedName, at: 2)
                    try stmt.bindText(cleanNote, at: 3)
                    try stmt.bindText(payload.binarySHA256, at: 4)
                    try stmt.bindInt(payload.renames.count, at: 5)
                    try stmt.bindInt(payload.comments.count, at: 6)
                    try stmt.bindInt(payload.bookmarks.count, at: 7)
                    try stmt.bindInt(payload.structs.count, at: 8)
                    try stmt.bindInt(payload.patches.count, at: 9)
                    try stmt.bindText(digest, at: 10)
                    try stmt.bindBlob(payloadData, at: 11)
                    try stmt.bindDate(createdAt, at: 12)
                    _ = try stmt.step()
                }

                return AnalysisCheckpointSummary(
                    id: checkpointID,
                    name: resolvedName,
                    note: cleanNote,
                    binarySHA256: payload.binarySHA256,
                    renameCount: payload.renames.count,
                    commentCount: payload.comments.count,
                    bookmarkCount: payload.bookmarks.count,
                    structCount: payload.structs.count,
                    patchCount: payload.patches.count,
                    payloadSHA256: digest,
                    createdAt: createdAt
                )
            }
        }
    }

    public func listCheckpoints() throws -> [AnalysisCheckpointSummary] {
        try synchronized {
            let sql = """
            SELECT
                id, name, note, binary_sha256,
                rename_count, comment_count, bookmark_count, struct_count, patch_count,
                payload_sha256, created_at
            FROM analysis_snapshots
            ORDER BY created_at DESC, name ASC;
            """
            return try database.connection.withPreparedStatement(sql) { stmt in
                var list: [AnalysisCheckpointSummary] = []
                while try stmt.step() {
                    list.append(Self.decodeSummaryRow(stmt))
                }
                return list
            }
        }
    }

    public func loadCheckpoint(id: UUID) throws -> AnalysisCheckpoint? {
        try synchronized {
            let sql = """
            SELECT
                id, name, note, binary_sha256,
                rename_count, comment_count, bookmark_count, struct_count, patch_count,
                payload_sha256, created_at, payload_json
            FROM analysis_snapshots
            WHERE id = ?;
            """
            return try database.connection.withPreparedStatement(sql) { stmt in
                try stmt.bindUUID(id, at: 1)
                guard try stmt.step() else { return nil }
                let summary = Self.decodeSummaryRow(stmt)
                let blob = stmt.columnData(at: 11)
                let actualHash = BinaryHashAndEntropy.sha256Hex(of: blob)
                guard actualHash == summary.payloadSHA256 else {
                    throw MachGraphError.databaseError(
                        code: SQLITE_CORRUPT,
                        message: "Checkpoint '\(summary.name)' payload SHA-256 mismatch (expected \(summary.payloadSHA256), got \(actualHash))"
                    )
                }
                let payload: AnalysisCheckpointPayload
                do {
                    payload = try StoreJSONCoding.makeDecoder().decode(AnalysisCheckpointPayload.self, from: blob)
                } catch {
                    throw MachGraphError.databaseError(
                        code: SQLITE_MISMATCH,
                        message: "Failed decoding checkpoint '\(summary.name)': \(error.localizedDescription)"
                    )
                }
                return AnalysisCheckpoint(summary: summary, payload: payload)
            }
        }
    }

    public func findCheckpoint(named name: String) throws -> AnalysisCheckpointSummary? {
        try synchronized {
            let sql = """
            SELECT
                id, name, note, binary_sha256,
                rename_count, comment_count, bookmark_count, struct_count, patch_count,
                payload_sha256, created_at
            FROM analysis_snapshots
            WHERE name = ? COLLATE NOCASE
            ORDER BY created_at DESC
            LIMIT 1;
            """
            return try database.connection.withPreparedStatement(sql) { stmt in
                try stmt.bindText(name, at: 1)
                guard try stmt.step() else { return nil }
                return Self.decodeSummaryRow(stmt)
            }
        }
    }

    public func renameCheckpoint(
        id: UUID,
        newName: String,
        newNote: String? = nil
    ) throws {
        try synchronized {
            let cleanName = newName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !cleanName.isEmpty else {
                throw MachGraphError.databaseError(
                    code: SQLITE_MISUSE,
                    message: "Checkpoint name cannot be empty"
                )
            }
            if let newNote {
                let changed = try database.connection.execute(
                    "UPDATE analysis_snapshots SET name = ?, note = ? WHERE id = ?;",
                    bindings: [.text(cleanName), .text(newNote), .uuid(id)]
                )
                if changed == 0 {
                    throw MachGraphError.databaseError(
                        code: SQLITE_NOTFOUND,
                        message: "Checkpoint \(id.uuidString) not found"
                    )
                }
            } else {
                let changed = try database.connection.execute(
                    "UPDATE analysis_snapshots SET name = ? WHERE id = ?;",
                    bindings: [.text(cleanName), .uuid(id)]
                )
                if changed == 0 {
                    throw MachGraphError.databaseError(
                        code: SQLITE_NOTFOUND,
                        message: "Checkpoint \(id.uuidString) not found"
                    )
                }
            }
        }
    }

    public func deleteCheckpoint(id: UUID) throws {
        try synchronized {
            _ = try database.connection.execute(
                "DELETE FROM analysis_snapshots WHERE id = ?;",
                bindings: [.uuid(id)]
            )
        }
    }

    @discardableResult
    public func pruneCheckpoints(keepingMostRecent maxCount: Int) throws -> Int {
        try synchronized {
            let keep = max(0, maxCount)
            let total = try database.connection.queryScalarInt("SELECT COUNT(*) FROM analysis_snapshots;")
            guard total > keep else { return 0 }
            let excess = total - keep
            return try database.connection.execute(
                """
                DELETE FROM analysis_snapshots
                WHERE id IN (
                    SELECT id FROM analysis_snapshots
                    ORDER BY created_at ASC
                    LIMIT ?
                );
                """,
                bindings: [.int(excess)]
            )
        }
    }

    // MARK: Semantic Diffing Between Checkpoints & Live State

    public func diffBetweenCheckpoints(
        baseID: UUID,
        targetID: UUID
    ) throws -> AnalysisCheckpointDiff {
        try synchronized {
            guard let baseCheckpoint = try loadCheckpoint(id: baseID) else {
                throw MachGraphError.databaseError(
                    code: SQLITE_NOTFOUND,
                    message: "Base checkpoint \(baseID.uuidString) does not exist"
                )
            }
            guard let targetCheckpoint = try loadCheckpoint(id: targetID) else {
                throw MachGraphError.databaseError(
                    code: SQLITE_NOTFOUND,
                    message: "Target checkpoint \(targetID.uuidString) does not exist"
                )
            }

            return Self.computeSemanticDiff(
                baseID: baseCheckpoint.summary.id,
                baseName: baseCheckpoint.summary.name,
                basePayload: baseCheckpoint.payload,
                targetID: targetCheckpoint.summary.id,
                targetName: targetCheckpoint.summary.name,
                targetPayload: targetCheckpoint.payload
            )
        }
    }

    public func diffCheckpointAgainstLiveState(baseID: UUID) throws -> AnalysisCheckpointDiff {
        try synchronized {
            guard let baseCheckpoint = try loadCheckpoint(id: baseID) else {
                throw MachGraphError.databaseError(
                    code: SQLITE_NOTFOUND,
                    message: "Checkpoint \(baseID.uuidString) does not exist"
                )
            }
            let livePayload = try captureLivePayload(capturedAt: Date())
            return Self.computeSemanticDiff(
                baseID: baseCheckpoint.summary.id,
                baseName: baseCheckpoint.summary.name,
                basePayload: baseCheckpoint.payload,
                targetID: nil,
                targetName: "Live Project State",
                targetPayload: livePayload
            )
        }
    }

    // MARK: Atomic Checkpoint Restore (Undo-Integrated)

    @discardableResult
    public func restoreCheckpoint(
        id: UUID,
        createSafetyBackup: Bool = false
    ) throws -> CheckpointRestoreResult {
        try synchronized {
            guard let targetCheckpoint = try loadCheckpoint(id: id) else {
                throw MachGraphError.databaseError(
                    code: SQLITE_NOTFOUND,
                    message: "Cannot restore missing checkpoint \(id.uuidString)"
                )
            }

            return try database.withTransaction {
                var backupID: UUID?
                if createSafetyBackup {
                    let backupSummary = try createCheckpoint(
                        name: "Pre-Restore Backup (before '\(targetCheckpoint.summary.name)')",
                        note: "Automatic safety checkpoint created prior to restoring \(id.uuidString)"
                    )
                    backupID = backupSummary.id
                }

                let livePayload = try captureLivePayload(capturedAt: Date())
                let deltaMutations = Self.planRestoreMutations(
                    from: livePayload,
                    to: targetCheckpoint.payload,
                    checkpointName: targetCheckpoint.summary.name
                )

                if !deltaMutations.isEmpty {
                    _ = try undoRedoController.performBatch(operations: deltaMutations)
                }

                let target = targetCheckpoint.payload
                return CheckpointRestoreResult(
                    restoredCheckpointID: targetCheckpoint.summary.id,
                    restoredCheckpointName: targetCheckpoint.summary.name,
                    safetyBackupCheckpointID: backupID,
                    appliedMutationCount: deltaMutations.count,
                    restoredRenameCount: target.renames.count,
                    restoredCommentCount: target.comments.count,
                    restoredBookmarkCount: target.bookmarks.count,
                    restoredStructCount: target.structs.count,
                    restoredPatchCount: target.patches.count
                )
            }
        }
    }

    // MARK: Pure Semantic Diff & Restore Planner

    public static func computeSemanticDiff(
        baseID: UUID,
        baseName: String,
        basePayload: AnalysisCheckpointPayload,
        targetID: UUID?,
        targetName: String,
        targetPayload: AnalysisCheckpointPayload
    ) -> AnalysisCheckpointDiff {
        let renameDiff = diffKeyedCollection(
            baseItems: basePayload.renames,
            targetItems: targetPayload.renames,
            keyOf: \.address,
            sortOrder: { $0.address < $1.address },
            describeChanges: Self.describeRenameChanges
        )

        let commentDiff = diffKeyedCollection(
            baseItems: basePayload.comments,
            targetItems: targetPayload.comments,
            keyOf: \.address,
            sortOrder: { $0.address < $1.address },
            describeChanges: Self.describeCommentChanges
        )

        let bookmarkDiff = diffKeyedCollection(
            baseItems: basePayload.bookmarks,
            targetItems: targetPayload.bookmarks,
            keyOf: \.id,
            sortOrder: {
                if $0.address != $1.address { return $0.address < $1.address }
                return $0.id.uuidString < $1.id.uuidString
            },
            describeChanges: Self.describeBookmarkChanges
        )

        let structDiff = diffKeyedCollection(
            baseItems: basePayload.structs,
            targetItems: targetPayload.structs,
            keyOf: \.id,
            sortOrder: {
                let cmp = $0.name.localizedCaseInsensitiveCompare($1.name)
                if cmp != .orderedSame { return cmp == .orderedAscending }
                return $0.id.uuidString < $1.id.uuidString
            },
            describeChanges: Self.describeStructChanges
        )

        let patchDiff = diffKeyedCollection(
            baseItems: basePayload.patches,
            targetItems: targetPayload.patches,
            keyOf: \.id,
            sortOrder: {
                if $0.fileOffset != $1.fileOffset { return $0.fileOffset < $1.fileOffset }
                return $0.id.uuidString < $1.id.uuidString
            },
            describeChanges: Self.describePatchChanges
        )

        return AnalysisCheckpointDiff(
            baseCheckpointID: baseID,
            baseCheckpointName: baseName,
            targetCheckpointID: targetID,
            targetCheckpointName: targetName,
            computedAt: Date(),
            renames: renameDiff,
            comments: commentDiff,
            bookmarks: bookmarkDiff,
            structs: structDiff,
            patches: patchDiff
        )
    }

    private static func diffKeyedCollection<Element: Sendable & Codable & Hashable, Key: Hashable>(
        baseItems: [Element],
        targetItems: [Element],
        keyOf: (Element) -> Key,
        sortOrder: (Element, Element) -> Bool,
        describeChanges: (Element, Element) -> [String]
    ) -> CheckpointCategoryDiff<Element> {
        var baseMap: [Key: Element] = [:]
        baseMap.reserveCapacity(baseItems.count)
        for item in baseItems {
            baseMap[keyOf(item)] = item
        }

        var targetMap: [Key: Element] = [:]
        targetMap.reserveCapacity(targetItems.count)
        for item in targetItems {
            targetMap[keyOf(item)] = item
        }

        var added: [Element] = []
        var removed: [Element] = []
        var modified: [CheckpointModifiedItem<Element>] = []
        var unchanged = 0

        for targetItem in targetItems {
            let key = keyOf(targetItem)
            if let baseItem = baseMap[key] {
                let highlights = describeChanges(baseItem, targetItem)
                if highlights.isEmpty {
                    unchanged += 1
                } else {
                    modified.append(
                        CheckpointModifiedItem(
                            before: baseItem,
                            after: targetItem,
                            changeHighlights: highlights
                        )
                    )
                }
            } else {
                added.append(targetItem)
            }
        }

        for baseItem in baseItems {
            let key = keyOf(baseItem)
            if targetMap[key] == nil {
                removed.append(baseItem)
            }
        }

        added.sort(by: sortOrder)
        removed.sort(by: sortOrder)
        modified.sort { sortOrder($0.after, $1.after) }

        return CheckpointCategoryDiff(
            added: added,
            removed: removed,
            modified: modified,
            unchangedCount: unchanged
        )
    }

    // MARK: Domain-Specific Semantic Comparators

    private static func describeRenameChanges(
        _ before: UserSymbolRename,
        _ after: UserSymbolRename
    ) -> [String] {
        var highlights: [String] = []
        if before.customName != after.customName {
            highlights.append("customName: '\(before.customName)' -> '\(after.customName)'")
        }
        if before.originalName != after.originalName {
            highlights.append("originalName: '\(before.originalName)' -> '\(after.originalName)'")
        }
        if before.signatureOverride != after.signatureOverride {
            let lhs = before.signatureOverride ?? "none"
            let rhs = after.signatureOverride ?? "none"
            highlights.append("signatureOverride: '\(lhs)' -> '\(rhs)'")
        }
        return highlights
    }

    private static func describeCommentChanges(
        _ before: UserInlineComment,
        _ after: UserInlineComment
    ) -> [String] {
        var highlights: [String] = []
        if before.text != after.text {
            highlights.append("text: '\(before.text)' -> '\(after.text)'")
        }
        if before.isRepeatable != after.isRepeatable {
            highlights.append("isRepeatable: \(before.isRepeatable) -> \(after.isRepeatable)")
        }
        return highlights
    }

    private static func describeBookmarkChanges(
        _ before: UserBookmark,
        _ after: UserBookmark
    ) -> [String] {
        var highlights: [String] = []
        if before.address != after.address {
            highlights.append("address: \(before.address.compactHexString) -> \(after.address.compactHexString)")
        }
        if before.label != after.label {
            highlights.append("label: '\(before.label)' -> '\(after.label)'")
        }
        if before.categoryTag != after.categoryTag {
            highlights.append("categoryTag: '\(before.categoryTag)' -> '\(after.categoryTag)'")
        }
        return highlights
    }

    private static func describeStructChanges(
        _ before: CustomStructDefinition,
        _ after: CustomStructDefinition
    ) -> [String] {
        var highlights: [String] = []
        if before.name != after.name {
            highlights.append("name: '\(before.name)' -> '\(after.name)'")
        }
        if before.totalByteSize != after.totalByteSize {
            highlights.append("totalByteSize: \(before.totalByteSize) -> \(after.totalByteSize)")
        }
        if before.alignment != after.alignment {
            highlights.append("alignment: \(before.alignment) -> \(after.alignment)")
        }
        if before.fields != after.fields {
            highlights.append("fields: \(before.fields.count) -> \(after.fields.count) member(s) modified")
        }
        return highlights
    }

    private static func describePatchChanges(
        _ before: BytePatchRecord,
        _ after: BytePatchRecord
    ) -> [String] {
        var highlights: [String] = []
        if before.fileOffset != after.fileOffset {
            highlights.append("fileOffset: \(before.fileOffset.hexString) -> \(after.fileOffset.hexString)")
        }
        if before.virtualAddress != after.virtualAddress {
            let lhs = before.virtualAddress?.compactHexString ?? "nil"
            let rhs = after.virtualAddress?.compactHexString ?? "nil"
            highlights.append("virtualAddress: \(lhs) -> \(rhs)")
        }
        if before.originalBytes != after.originalBytes {
            highlights.append("originalBytes: [\(before.originalHex)] -> [\(after.originalHex)]")
        }
        if before.patchedBytes != after.patchedBytes {
            highlights.append("patchedBytes: [\(before.patchedHex)] -> [\(after.patchedHex)]")
        }
        if before.originalAssembly != after.originalAssembly || before.patchedAssembly != after.patchedAssembly {
            let lhs = before.patchedAssembly ?? "raw"
            let rhs = after.patchedAssembly ?? "raw"
            if lhs != rhs {
                highlights.append("patchedAssembly: '\(lhs)' -> '\(rhs)'")
            }
        }
        if before.isEnabled != after.isEnabled {
            highlights.append("isEnabled: \(before.isEnabled) -> \(after.isEnabled)")
        }
        if before.note != after.note {
            highlights.append("note: '\(before.note)' -> '\(after.note)'")
        }
        return highlights
    }

    // MARK: Restore Delta Planner

    private static func planRestoreMutations(
        from live: AnalysisCheckpointPayload,
        to target: AnalysisCheckpointPayload,
        checkpointName: String
    ) -> [(title: String, operation: AnalystMutationOperation)] {
        let diff = computeSemanticDiff(
            baseID: UUID(),
            baseName: "Live",
            basePayload: live,
            targetID: nil,
            targetName: checkpointName,
            targetPayload: target
        )

        var mutations: [(title: String, operation: AnalystMutationOperation)] = []
        let prefix = "[Restore '\(checkpointName)']"

        // 1. Renames
        for removed in diff.renames.removed {
            mutations.append((
                title: "\(prefix) Remove rename '\(removed.customName)' at \(removed.address.compactHexString)",
                operation: .setRename(previous: removed, updated: nil)
            ))
        }
        for mod in diff.renames.modified {
            mutations.append((
                title: "\(prefix) Restore rename '\(mod.after.customName)' at \(mod.after.address.compactHexString)",
                operation: .setRename(previous: mod.before, updated: mod.after)
            ))
        }
        for added in diff.renames.added {
            mutations.append((
                title: "\(prefix) Restore rename '\(added.customName)' at \(added.address.compactHexString)",
                operation: .setRename(previous: nil, updated: added)
            ))
        }

        // 2. Comments
        for removed in diff.comments.removed {
            mutations.append((
                title: "\(prefix) Remove comment at \(removed.address.compactHexString)",
                operation: .setComment(previous: removed, updated: nil)
            ))
        }
        for mod in diff.comments.modified {
            mutations.append((
                title: "\(prefix) Restore comment at \(mod.after.address.compactHexString)",
                operation: .setComment(previous: mod.before, updated: mod.after)
            ))
        }
        for added in diff.comments.added {
            mutations.append((
                title: "\(prefix) Restore comment at \(added.address.compactHexString)",
                operation: .setComment(previous: nil, updated: added)
            ))
        }

        // 3. Bookmarks
        for removed in diff.bookmarks.removed {
            mutations.append((
                title: "\(prefix) Remove bookmark '\(removed.label)'",
                operation: .setBookmark(previous: removed, updated: nil)
            ))
        }
        for mod in diff.bookmarks.modified {
            mutations.append((
                title: "\(prefix) Restore bookmark '\(mod.after.label)'",
                operation: .setBookmark(previous: mod.before, updated: mod.after)
            ))
        }
        for added in diff.bookmarks.added {
            mutations.append((
                title: "\(prefix) Restore bookmark '\(added.label)'",
                operation: .setBookmark(previous: nil, updated: added)
            ))
        }

        // 4. Custom Structs
        for removed in diff.structs.removed {
            mutations.append((
                title: "\(prefix) Remove struct '\(removed.name)'",
                operation: .setStruct(previous: removed, updated: nil)
            ))
        }
        for mod in diff.structs.modified {
            mutations.append((
                title: "\(prefix) Restore struct '\(mod.after.name)'",
                operation: .setStruct(previous: mod.before, updated: mod.after)
            ))
        }
        for added in diff.structs.added {
            mutations.append((
                title: "\(prefix) Restore struct '\(added.name)'",
                operation: .setStruct(previous: nil, updated: added)
            ))
        }

        // 5. Byte Patches
        for removed in diff.patches.removed {
            mutations.append((
                title: "\(prefix) Remove patch at \(removed.fileOffset.hexString)",
                operation: .setPatch(previous: removed, updated: nil)
            ))
        }
        for mod in diff.patches.modified {
            mutations.append((
                title: "\(prefix) Restore patch at \(mod.after.fileOffset.hexString)",
                operation: .setPatch(previous: mod.before, updated: mod.after)
            ))
        }
        for added in diff.patches.added {
            mutations.append((
                title: "\(prefix) Restore patch at \(added.fileOffset.hexString)",
                operation: .setPatch(previous: nil, updated: added)
            ))
        }

        return mutations
    }

    // MARK: Live Capture & Row Decoding Helpers

    private func captureLivePayload(capturedAt: Date) throws -> AnalysisCheckpointPayload {
        let name = try database.projectName()
        let summary = try database.loadBinaryImageSummary()
        let sha256 = try (database.metaValue(forKey: "binary.sha256") ?? summary?.sha256Hex ?? "")

        let renames = try database.allRenames()
        let comments = try database.allComments()
        let bookmarks = try database.allBookmarks()
        let structs = try database.allStructs()
        let patches = try database.allPatches()

        return AnalysisCheckpointPayload(
            projectName: name,
            binarySHA256: sha256,
            capturedAt: capturedAt,
            renames: renames,
            comments: comments,
            bookmarks: bookmarks,
            structs: structs,
            patches: patches
        )
    }

    private static func decodeSummaryRow(_ stmt: SQLiteStatement) -> AnalysisCheckpointSummary {
        AnalysisCheckpointSummary(
            id: stmt.columnUUID(at: 0),
            name: stmt.columnString(at: 1),
            note: stmt.columnString(at: 2),
            binarySHA256: stmt.columnString(at: 3),
            renameCount: stmt.columnInt(at: 4),
            commentCount: stmt.columnInt(at: 5),
            bookmarkCount: stmt.columnInt(at: 6),
            structCount: stmt.columnInt(at: 7),
            patchCount: stmt.columnInt(at: 8),
            payloadSHA256: stmt.columnString(at: 9),
            createdAt: stmt.columnDate(at: 10)
        )
    }

    private static func compactTimestampString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
