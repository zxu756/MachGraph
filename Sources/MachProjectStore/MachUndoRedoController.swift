import Foundation
import SQLite3
import MachGraphModels

// MARK: - Persistent Undo/Redo State & Observer Models

public struct MachUndoRedoStateSnapshot: Sendable, Codable, Hashable {
    public let canUndo: Bool
    public let canRedo: Bool
    public let undoDepth: Int
    public let redoDepth: Int
    public let topUndoTitle: String?
    public let topRedoTitle: String?
    public let recentUndoTitles: [String]
    public let recentRedoTitles: [String]

    public init(
        canUndo: Bool,
        canRedo: Bool,
        undoDepth: Int,
        redoDepth: Int,
        topUndoTitle: String?,
        topRedoTitle: String?,
        recentUndoTitles: [String] = [],
        recentRedoTitles: [String] = []
    ) {
        self.canUndo = canUndo
        self.canRedo = canRedo
        self.undoDepth = undoDepth
        self.redoDepth = redoDepth
        self.topUndoTitle = topUndoTitle
        self.topRedoTitle = topRedoTitle
        self.recentUndoTitles = recentUndoTitles
        self.recentRedoTitles = recentRedoTitles
    }

    public static let empty = MachUndoRedoStateSnapshot(
        canUndo: false,
        canRedo: false,
        undoDepth: 0,
        redoDepth: 0,
        topUndoTitle: nil,
        topRedoTitle: nil
    )
}

public enum MachUndoRedoChangeEvent: Sendable, Hashable {
    case performed(AnalystTransactionRecord)
    case undid(AnalystTransactionRecord)
    case redid(AnalystTransactionRecord)
    case clearedHistory
    case prunedOldest(removedCount: Int)
}

// MARK: - Persistent SQLite WAL Undo/Redo Controller

public final class MachUndoRedoController: @unchecked Sendable {
    public typealias ChangeObserver = @Sendable (MachUndoRedoChangeEvent, MachUndoRedoStateSnapshot) -> Void

    private enum StackKind: String {
        case undo = "undo"
        case redo = "redo"
    }

    private let lock = NSRecursiveLock()
    private var observers: [UUID: ChangeObserver] = [:]

    public let database: MachProjectDatabase
    public let maxHistoryDepth: Int

    public init(
        database: MachProjectDatabase,
        maxHistoryDepth: Int = 1_000
    ) {
        self.database = database
        self.maxHistoryDepth = max(16, maxHistoryDepth)
    }

    // MARK: Lightweight Stack Introspection Properties

    public var canUndo: Bool {
        (try? undoCount()) ?? 0 > 0
    }

    public var canRedo: Bool {
        (try? redoCount()) ?? 0 > 0
    }

    public var undoDepth: Int {
        (try? undoCount()) ?? 0
    }

    public var redoDepth: Int {
        (try? redoCount()) ?? 0
    }

    public var topUndoTitle: String? {
        try? peekTopRecord(in: .undo)?.title
    }

    public var topRedoTitle: String? {
        try? peekTopRecord(in: .redo)?.title
    }

    // MARK: Observer Registration

    @discardableResult
    public func addObserver(_ observer: @escaping ChangeObserver) -> UUID {
        lock.lock()
        defer { lock.unlock() }
        let token = UUID()
        observers[token] = observer
        return token
    }

    public func removeObserver(token: UUID) {
        lock.lock()
        defer { lock.unlock() }
        observers.removeValue(forKey: token)
    }

    private func notifyObservers(event: MachUndoRedoChangeEvent) {
        let registered: [ChangeObserver]
        let snapshot: MachUndoRedoStateSnapshot
        lock.lock()
        registered = Array(observers.values)
        snapshot = (try? stateSnapshot(previewLimit: 10)) ?? .empty
        lock.unlock()

        guard !registered.isEmpty else { return }
        for callback in registered {
            callback(event, snapshot)
        }
    }

    // MARK: Core Atomic Perform / Undo / Redo Engine

    public func perform(title: String, operation: AnalystMutationOperation) throws {
        _ = try performRecording(title: title, operation: operation)
    }

    @discardableResult
    public func performRecording(
        title: String,
        operation: AnalystMutationOperation
    ) throws -> AnalystTransactionRecord {
        let committedRecord: AnalystTransactionRecord = try synchronized {
            let cleanTitle = Self.normalizeTitle(title, fallback: Self.defaultTitle(for: operation))
            let txID = UUID()
            let now = Date()
            let encodedOp = try Self.encodeOperationJSON(operation)

            return try database.withTransaction {
                try database.applyMutation(operation)

                _ = try database.connection.execute(
                    "DELETE FROM undo_redo_journal WHERE stack_kind = ?;",
                    bindings: [.text(StackKind.redo.rawValue)]
                )

                let seq = try insertJournalEntry(
                    txID: txID,
                    stack: .undo,
                    title: cleanTitle,
                    operationJSON: encodedOp,
                    createdAt: now
                )

                _ = try trimUndoStackToLimitInternal(maxCount: maxHistoryDepth)

                return AnalystTransactionRecord(
                    id: txID,
                    sequenceNumber: seq,
                    title: cleanTitle,
                    operation: operation,
                    createdAt: now
                )
            }
        }

        notifyObservers(event: .performed(committedRecord))
        return committedRecord
    }

    @discardableResult
    public func performBatch(
        operations: [(title: String, operation: AnalystMutationOperation)]
    ) throws -> [AnalystTransactionRecord] {
        guard !operations.isEmpty else { return [] }
        let records: [AnalystTransactionRecord] = try synchronized {
            try database.withTransaction {
                var results: [AnalystTransactionRecord] = []
                results.reserveCapacity(operations.count)

                _ = try database.connection.execute(
                    "DELETE FROM undo_redo_journal WHERE stack_kind = ?;",
                    bindings: [.text(StackKind.redo.rawValue)]
                )

                for item in operations {
                    let cleanTitle = Self.normalizeTitle(item.title, fallback: Self.defaultTitle(for: item.operation))
                    let txID = UUID()
                    let now = Date()
                    let encodedOp = try Self.encodeOperationJSON(item.operation)

                    try database.applyMutation(item.operation)
                    let seq = try insertJournalEntry(
                        txID: txID,
                        stack: .undo,
                        title: cleanTitle,
                        operationJSON: encodedOp,
                        createdAt: now
                    )
                    results.append(
                        AnalystTransactionRecord(
                            id: txID,
                            sequenceNumber: seq,
                            title: cleanTitle,
                            operation: item.operation,
                            createdAt: now
                        )
                    )
                }

                _ = try trimUndoStackToLimitInternal(maxCount: maxHistoryDepth)
                return results
            }
        }

        if let last = records.last {
            notifyObservers(event: .performed(last))
        }
        return records
    }

    @discardableResult
    public func undo() throws -> AnalystTransactionRecord? {
        let undoneRecord: AnalystTransactionRecord? = try synchronized {
            try database.withTransaction {
                guard let top = try peekTopJournalRow(in: .undo) else {
                    return nil
                }

                let invertedOp = top.record.operation.inverted
                try database.applyMutation(invertedOp)

                _ = try database.connection.execute(
                    "DELETE FROM undo_redo_journal WHERE sequence_number = ?;",
                    bindings: [.integer(top.record.sequenceNumber)]
                )

                let newSeq = try insertJournalEntry(
                    txID: top.record.id,
                    stack: .redo,
                    title: top.record.title,
                    operationJSON: top.operationJSON,
                    createdAt: top.record.createdAt
                )

                return AnalystTransactionRecord(
                    id: top.record.id,
                    sequenceNumber: newSeq,
                    title: top.record.title,
                    operation: top.record.operation,
                    createdAt: top.record.createdAt
                )
            }
        }

        if let undoneRecord {
            notifyObservers(event: .undid(undoneRecord))
        }
        return undoneRecord
    }

    @discardableResult
    public func redo() throws -> AnalystTransactionRecord? {
        let redoneRecord: AnalystTransactionRecord? = try synchronized {
            try database.withTransaction {
                guard let top = try peekTopJournalRow(in: .redo) else {
                    return nil
                }

                try database.applyMutation(top.record.operation)

                _ = try database.connection.execute(
                    "DELETE FROM undo_redo_journal WHERE sequence_number = ?;",
                    bindings: [.integer(top.record.sequenceNumber)]
                )

                let newSeq = try insertJournalEntry(
                    txID: top.record.id,
                    stack: .undo,
                    title: top.record.title,
                    operationJSON: top.operationJSON,
                    createdAt: top.record.createdAt
                )

                return AnalystTransactionRecord(
                    id: top.record.id,
                    sequenceNumber: newSeq,
                    title: top.record.title,
                    operation: top.record.operation,
                    createdAt: top.record.createdAt
                )
            }
        }

        if let redoneRecord {
            notifyObservers(event: .redid(redoneRecord))
        }
        return redoneRecord
    }

    @discardableResult
    public func undoMultiple(steps count: Int) throws -> [AnalystTransactionRecord] {
        guard count > 0 else { return [] }
        var undone: [AnalystTransactionRecord] = []
        undone.reserveCapacity(count)
        for _ in 0..<count {
            guard let record = try undo() else { break }
            undone.append(record)
        }
        return undone
    }

    @discardableResult
    public func redoMultiple(steps count: Int) throws -> [AnalystTransactionRecord] {
        guard count > 0 else { return [] }
        var redone: [AnalystTransactionRecord] = []
        redone.reserveCapacity(count)
        for _ in 0..<count {
            guard let record = try redo() else { break }
            redone.append(record)
        }
        return redone
    }

    // MARK: Convenience Analyst Mutation APIs

    public func renameSymbol(
        at address: VirtualAddress,
        originalName: String,
        newName: String,
        signature: String? = nil
    ) throws {
        let trimmedNew = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedSig: String? = {
            guard let signature else { return nil }
            let trimmed = signature.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }()

        let previous = try database.rename(for: address)
        let canonicalOriginal: String = {
            if let existingOrig = previous?.originalName, !existingOrig.isEmpty {
                return existingOrig
            }
            let trimmedOrig = originalName.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmedOrig.isEmpty ? "sub_\(String(address.rawValue, radix: 16))" : trimmedOrig
        }()

        if trimmedNew.isEmpty && normalizedSig == nil {
            guard let previous else { return }
            try perform(
                title: "Reset symbol '\(previous.customName)' at \(address.compactHexString)",
                operation: .setRename(previous: previous, updated: nil)
            )
            return
        }

        let resolvedCustomName = trimmedNew.isEmpty ? canonicalOriginal : trimmedNew
        let updated = UserSymbolRename(
            address: address,
            originalName: canonicalOriginal,
            customName: resolvedCustomName,
            signatureOverride: normalizedSig,
            updatedAt: Date()
        )

        try perform(
            title: "Rename '\(previous?.customName ?? canonicalOriginal)' -> '\(resolvedCustomName)' at \(address.compactHexString)",
            operation: .setRename(previous: previous, updated: updated)
        )
    }

    public func clearSymbolRename(at address: VirtualAddress) throws {
        guard let previous = try database.rename(for: address) else { return }
        try perform(
            title: "Clear symbol rename '\(previous.customName)' at \(address.compactHexString)",
            operation: .setRename(previous: previous, updated: nil)
        )
    }

    public func setInlineComment(
        at address: VirtualAddress,
        text: String,
        isRepeatable: Bool = false
    ) throws {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let previous = try database.comment(at: address)

        if trimmed.isEmpty {
            guard let previous else { return }
            try perform(
                title: "Delete comment at \(address.compactHexString)",
                operation: .setComment(previous: previous, updated: nil)
            )
            return
        }

        let updated = UserInlineComment(
            address: address,
            text: trimmed,
            isRepeatable: isRepeatable,
            updatedAt: Date()
        )
        let actionVerb = previous == nil ? "Add" : "Update"
        try perform(
            title: "\(actionVerb) \(isRepeatable ? "repeatable " : "")comment at \(address.compactHexString)",
            operation: .setComment(previous: previous, updated: updated)
        )
    }

    public func deleteInlineComment(at address: VirtualAddress) throws {
        guard let previous = try database.comment(at: address) else { return }
        try perform(
            title: "Delete comment at \(address.compactHexString)",
            operation: .setComment(previous: previous, updated: nil)
        )
    }

    @discardableResult
    public func toggleBookmark(
        at address: VirtualAddress,
        label: String = "Bookmark",
        category: String = "Triage"
    ) throws -> Bool {
        let existingAtAddress = try database.bookmarks(at: address)
        if let existing = existingAtAddress.first {
            try perform(
                title: "Remove bookmark '\(existing.label)' at \(address.compactHexString)",
                operation: .setBookmark(previous: existing, updated: nil)
            )
            return false
        } else {
            let cleanLabel = label.trimmingCharacters(in: .whitespacesAndNewlines)
            let cleanCategory = category.trimmingCharacters(in: .whitespacesAndNewlines)
            let bookmark = UserBookmark(
                address: address,
                label: cleanLabel.isEmpty ? "Bookmark \(address.compactHexString)" : cleanLabel,
                categoryTag: cleanCategory.isEmpty ? "Triage" : cleanCategory,
                createdAt: Date()
            )
            try perform(
                title: "Add bookmark '\(bookmark.label)' at \(address.compactHexString)",
                operation: .setBookmark(previous: nil, updated: bookmark)
            )
            return true
        }
    }

    public func upsertBookmark(_ bookmark: UserBookmark) throws {
        let previous = try database.bookmark(id: bookmark.id)
        let verb = previous == nil ? "Add" : "Update"
        try perform(
            title: "\(verb) bookmark '\(bookmark.label)' at \(bookmark.address.compactHexString)",
            operation: .setBookmark(previous: previous, updated: bookmark)
        )
    }

    public func removeBookmark(id: UUID) throws {
        guard let previous = try database.bookmark(id: id) else { return }
        try perform(
            title: "Remove bookmark '\(previous.label)' at \(previous.address.compactHexString)",
            operation: .setBookmark(previous: previous, updated: nil)
        )
    }

    public func recordBytePatch(_ patch: BytePatchRecord) throws {
        let previous = try database.patch(id: patch.id)
        let locationLabel = patch.virtualAddress?.compactHexString ?? patch.fileOffset.hexString
        let asmDetail: String
        if let patchedAsm = patch.patchedAssembly, !patchedAsm.isEmpty {
            asmDetail = " (\(patchedAsm))"
        } else {
            asmDetail = " (\(patch.byteCount)B)"
        }
        let verb = previous == nil ? "Apply" : "Update"
        try perform(
            title: "\(verb) patch at \(locationLabel)\(asmDetail)",
            operation: .setPatch(previous: previous, updated: patch)
        )
    }

    public func setBytePatchEnabled(id: UUID, isEnabled: Bool) throws {
        guard var updated = try database.patch(id: id) else { return }
        let previous = updated
        guard previous.isEnabled != isEnabled else { return }
        updated.isEnabled = isEnabled
        let locationLabel = updated.virtualAddress?.compactHexString ?? updated.fileOffset.hexString
        try perform(
            title: "\(isEnabled ? "Enable" : "Disable") patch at \(locationLabel)",
            operation: .setPatch(previous: previous, updated: updated)
        )
    }

    public func updateBytePatchNote(id: UUID, note: String) throws {
        guard var updated = try database.patch(id: id) else { return }
        let previous = updated
        updated.note = note
        let locationLabel = updated.virtualAddress?.compactHexString ?? updated.fileOffset.hexString
        try perform(
            title: "Update patch note at \(locationLabel)",
            operation: .setPatch(previous: previous, updated: updated)
        )
    }

    public func removeBytePatch(id: UUID) throws {
        guard let previous = try database.patch(id: id) else { return }
        let locationLabel = previous.virtualAddress?.compactHexString ?? previous.fileOffset.hexString
        try perform(
            title: "Remove patch at \(locationLabel)",
            operation: .setPatch(previous: previous, updated: nil)
        )
    }

    public func saveCustomStruct(_ definition: CustomStructDefinition) throws {
        let previous = try database.customStruct(id: definition.id)
        let verb = previous == nil ? "Define" : "Update"
        try perform(
            title: "\(verb) struct '\(definition.name)' (\(definition.totalByteSize)B, \(definition.fields.count) fields)",
            operation: .setStruct(previous: previous, updated: definition)
        )
    }

    public func removeCustomStruct(id: UUID) throws {
        guard let previous = try database.customStruct(id: id) else { return }
        try perform(
            title: "Delete struct '\(previous.name)'",
            operation: .setStruct(previous: previous, updated: nil)
        )
    }

    // MARK: Persistent Stack Inspection & Maintenance

    public func undoStack(limit: Int? = nil) throws -> [AnalystTransactionRecord] {
        try synchronized {
            try fetchStackRecords(stack: .undo, limit: limit)
        }
    }

    public func redoStack(limit: Int? = nil) throws -> [AnalystTransactionRecord] {
        try synchronized {
            try fetchStackRecords(stack: .redo, limit: limit)
        }
    }

    public func stateSnapshot(previewLimit: Int = 10) throws -> MachUndoRedoStateSnapshot {
        try synchronized {
            let capped = max(1, previewLimit)
            let undoCountVal = try undoCount()
            let redoCountVal = try redoCount()
            let undoPreview = try fetchStackTitles(stack: .undo, limit: capped)
            let redoPreview = try fetchStackTitles(stack: .redo, limit: capped)

            return MachUndoRedoStateSnapshot(
                canUndo: undoCountVal > 0,
                canRedo: redoCountVal > 0,
                undoDepth: undoCountVal,
                redoDepth: redoCountVal,
                topUndoTitle: undoPreview.first,
                topRedoTitle: redoPreview.first,
                recentUndoTitles: undoPreview,
                recentRedoTitles: redoPreview
            )
        }
    }

    public func clearHistory() throws {
        try synchronized {
            try database.connection.execute("DELETE FROM undo_redo_journal;")
        }
        notifyObservers(event: .clearedHistory)
    }

    public func clearRedoStack() throws {
        try synchronized {
            _ = try database.connection.execute(
                "DELETE FROM undo_redo_journal WHERE stack_kind = ?;",
                bindings: [.text(StackKind.redo.rawValue)]
            )
        }
    }

    @discardableResult
    public func pruneUndoHistory(keepingMostRecent maxCount: Int) throws -> Int {
        let removed = try synchronized {
            try trimUndoStackToLimitInternal(maxCount: max(1, maxCount))
        }
        if removed > 0 {
            notifyObservers(event: .prunedOldest(removedCount: removed))
        }
        return removed
    }

    // MARK: Private SQLite Journal Helpers

    @discardableResult
    private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try database.connection.withExclusiveAccess(body)
    }

    private struct RawJournalRow {
        let record: AnalystTransactionRecord
        let operationJSON: String
    }

    private func undoCount() throws -> Int {
        try synchronized {
            try database.connection.queryScalarInt(
                "SELECT COUNT(*) FROM undo_redo_journal WHERE stack_kind = ?;",
                bindings: [.text(StackKind.undo.rawValue)]
            )
        }
    }

    private func redoCount() throws -> Int {
        try synchronized {
            try database.connection.queryScalarInt(
                "SELECT COUNT(*) FROM undo_redo_journal WHERE stack_kind = ?;",
                bindings: [.text(StackKind.redo.rawValue)]
            )
        }
    }

    private func insertJournalEntry(
        txID: UUID,
        stack: StackKind,
        title: String,
        operationJSON: String,
        createdAt: Date
    ) throws -> Int64 {
        let sql = """
        INSERT INTO undo_redo_journal (
            tx_id, stack_kind, title, operation_json, created_at
        ) VALUES (?, ?, ?, ?, ?);
        """
        try database.connection.withPreparedStatement(sql) { stmt in
            try stmt.bindUUID(txID, at: 1)
            try stmt.bindText(stack.rawValue, at: 2)
            try stmt.bindText(title, at: 3)
            try stmt.bindText(operationJSON, at: 4)
            try stmt.bindDate(createdAt, at: 5)
            _ = try stmt.step()
        }
        return database.connection.lastInsertedRowID
    }

    private func peekTopRecord(in stack: StackKind) throws -> AnalystTransactionRecord? {
        try peekTopJournalRow(in: stack)?.record
    }

    private func peekTopJournalRow(in stack: StackKind) throws -> RawJournalRow? {
        let sql = """
        SELECT sequence_number, tx_id, title, operation_json, created_at
        FROM undo_redo_journal
        WHERE stack_kind = ?
        ORDER BY sequence_number DESC
        LIMIT 1;
        """
        return try database.connection.withPreparedStatement(sql) { stmt in
            try stmt.bindText(stack.rawValue, at: 1)
            guard try stmt.step() else { return nil }
            return try Self.decodeJournalRow(stmt)
        }
    }

    private func fetchStackRecords(
        stack: StackKind,
        limit: Int?
    ) throws -> [AnalystTransactionRecord] {
        var sql = """
        SELECT sequence_number, tx_id, title, operation_json, created_at
        FROM undo_redo_journal
        WHERE stack_kind = ?
        ORDER BY sequence_number DESC
        """
        var bindings: [SQLiteValue] = [.text(stack.rawValue)]
        if let limit, limit > 0 {
            sql += " LIMIT ?;"
            bindings.append(.int(limit))
        } else {
            sql += ";"
        }

        return try database.connection.withPreparedStatement(sql) { stmt in
            try stmt.bindValues(bindings)
            var records: [AnalystTransactionRecord] = []
            while try stmt.step() {
                records.append(try Self.decodeJournalRow(stmt).record)
            }
            return records
        }
    }

    private func fetchStackTitles(
        stack: StackKind,
        limit: Int
    ) throws -> [String] {
        let sql = """
        SELECT title
        FROM undo_redo_journal
        WHERE stack_kind = ?
        ORDER BY sequence_number DESC
        LIMIT ?;
        """
        return try database.connection.withPreparedStatement(sql) { stmt in
            try stmt.bindText(stack.rawValue, at: 1)
            try stmt.bindInt(limit, at: 2)
            var titles: [String] = []
            while try stmt.step() {
                titles.append(stmt.columnString(at: 0))
            }
            return titles
        }
    }

    private func trimUndoStackToLimitInternal(maxCount: Int) throws -> Int {
        let currentCount = try undoCount()
        guard currentCount > maxCount else { return 0 }
        let excess = currentCount - maxCount
        let sql = """
        DELETE FROM undo_redo_journal
        WHERE sequence_number IN (
            SELECT sequence_number
            FROM undo_redo_journal
            WHERE stack_kind = ?
            ORDER BY sequence_number ASC
            LIMIT ?
        );
        """
        return try database.connection.execute(
            sql,
            bindings: [.text(StackKind.undo.rawValue), .int(excess)]
        )
    }

    private static func decodeJournalRow(_ stmt: SQLiteStatement) throws -> RawJournalRow {
        let seq = stmt.columnInt64(at: 0)
        let txID = stmt.columnUUID(at: 1)
        let title = stmt.columnString(at: 2)
        let opJSON = stmt.columnString(at: 3)
        let createdAt = stmt.columnDate(at: 4)
        let op = try decodeOperationJSON(opJSON)
        let record = AnalystTransactionRecord(
            id: txID,
            sequenceNumber: seq,
            title: title,
            operation: op,
            createdAt: createdAt
        )
        return RawJournalRow(record: record, operationJSON: opJSON)
    }

    private static func encodeOperationJSON(_ operation: AnalystMutationOperation) throws -> String {
        do {
            let data = try StoreJSONCoding.makeEncoder().encode(operation)
            return String(decoding: data, as: UTF8.self)
        } catch {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Failed JSON-encoding AnalystMutationOperation: \(error.localizedDescription)"
            )
        }
    }

    private static func decodeOperationJSON(_ json: String) throws -> AnalystMutationOperation {
        do {
            let data = Data(json.utf8)
            return try StoreJSONCoding.makeDecoder().decode(AnalystMutationOperation.self, from: data)
        } catch {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Failed JSON-decoding AnalystMutationOperation: \(error.localizedDescription)"
            )
        }
    }

    private static func normalizeTitle(_ title: String, fallback: String) -> String {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? fallback : trimmed
    }

    private static func defaultTitle(for operation: AnalystMutationOperation) -> String {
        switch operation {
        case .setRename(_, let updated):
            if let updated {
                return "Rename symbol to '\(updated.customName)' at \(updated.address.compactHexString)"
            }
            return "Clear symbol rename"
        case .setComment(_, let updated):
            if let updated {
                return "Set comment at \(updated.address.compactHexString)"
            }
            return "Remove comment"
        case .setBookmark(_, let updated):
            if let updated {
                return "Bookmark '\(updated.label)' at \(updated.address.compactHexString)"
            }
            return "Remove bookmark"
        case .setPatch(_, let updated):
            if let updated {
                return "Patch \(updated.byteCount)B at \(updated.fileOffset.hexString)"
            }
            return "Remove byte patch"
        case .setStruct(_, let updated):
            if let updated {
                return "Save struct '\(updated.name)'"
            }
            return "Delete custom struct"
        }
    }
}
