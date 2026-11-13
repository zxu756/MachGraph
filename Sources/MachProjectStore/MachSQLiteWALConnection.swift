import Foundation
import SQLite3
import MachGraphModels

// MARK: - Internal JSON Coding Factory

enum StoreJSONCoding {
    static func makeEncoder(prettyPrinted: Bool = false, sortedKeys: Bool = true) -> JSONEncoder {
        let encoder = JSONEncoder()
        var formatting: JSONEncoder.OutputFormatting = []
        if prettyPrinted {
            formatting.insert(.prettyPrinted)
        }
        if sortedKeys {
            formatting.insert(.sortedKeys)
        }
        formatting.insert(.withoutEscapingSlashes)
        encoder.outputFormatting = formatting
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

// MARK: - SQLite Configuration & Telemetry Models

public enum SQLiteOpenMode: Sendable, Hashable {
    case readWriteCreate
    case readWriteExisting
    case readOnly
    case inMemory
}

public enum SQLiteSynchronousMode: String, Sendable, Codable, Hashable {
    case off = "OFF"
    case normal = "NORMAL"
    case full = "FULL"
    case extra = "EXTRA"
}

public struct SQLiteConnectionConfiguration: Sendable, Hashable {
    public var openMode: SQLiteOpenMode
    public var enableWAL: Bool
    public var synchronousMode: SQLiteSynchronousMode
    public var enforceForeignKeys: Bool
    public var memoryTempStore: Bool
    public var busyTimeoutMilliseconds: Int32
    public var pageCacheSizeKiB: Int32
    public var autoMigrateToLatest: Bool

    public init(
        openMode: SQLiteOpenMode = .readWriteCreate,
        enableWAL: Bool = true,
        synchronousMode: SQLiteSynchronousMode = .normal,
        enforceForeignKeys: Bool = true,
        memoryTempStore: Bool = true,
        busyTimeoutMilliseconds: Int32 = 5_000,
        pageCacheSizeKiB: Int32 = 16_384,
        autoMigrateToLatest: Bool = true
    ) {
        self.openMode = openMode
        self.enableWAL = enableWAL
        self.synchronousMode = synchronousMode
        self.enforceForeignKeys = enforceForeignKeys
        self.memoryTempStore = memoryTempStore
        self.busyTimeoutMilliseconds = busyTimeoutMilliseconds
        self.pageCacheSizeKiB = pageCacheSizeKiB
        self.autoMigrateToLatest = autoMigrateToLatest
    }

    public static let standardWAL = SQLiteConnectionConfiguration()

    public static let inMemoryTesting = SQLiteConnectionConfiguration(
        openMode: .inMemory,
        enableWAL: false,
        synchronousMode: .off,
        enforceForeignKeys: true,
        memoryTempStore: true,
        busyTimeoutMilliseconds: 2_500,
        pageCacheSizeKiB: 8_192,
        autoMigrateToLatest: true
    )
}

public enum WALCheckpointMode: String, Sendable, Codable, Hashable, CaseIterable {
    case passive = "PASSIVE"
    case full = "FULL"
    case restart = "RESTART"
    case truncate = "TRUNCATE"

    var sqliteFlag: Int32 {
        switch self {
        case .passive: return SQLITE_CHECKPOINT_PASSIVE
        case .full: return SQLITE_CHECKPOINT_FULL
        case .restart: return SQLITE_CHECKPOINT_RESTART
        case .truncate: return SQLITE_CHECKPOINT_TRUNCATE
        }
    }
}

public struct WALCheckpointResult: Sendable, Codable, Hashable {
    public let mode: WALCheckpointMode
    public let totalLogFrames: Int32
    public let checkpointedFrames: Int32

    public init(mode: WALCheckpointMode, totalLogFrames: Int32, checkpointedFrames: Int32) {
        self.mode = mode
        self.totalLogFrames = totalLogFrames
        self.checkpointedFrames = checkpointedFrames
    }

    public var isComplete: Bool {
        totalLogFrames >= 0 && checkpointedFrames == totalLogFrames
    }
}

public struct SQLiteIntegrityReport: Sendable, Codable, Hashable {
    public let isOK: Bool
    public let messages: [String]
    public let foreignKeyViolations: Int
    public let pageCount: Int64
    public let pageSize: Int64
    public let freelistCount: Int64
    public let schemaVersion: Int

    public init(
        isOK: Bool,
        messages: [String],
        foreignKeyViolations: Int,
        pageCount: Int64,
        pageSize: Int64,
        freelistCount: Int64,
        schemaVersion: Int
    ) {
        self.isOK = isOK
        self.messages = messages
        self.foreignKeyViolations = foreignKeyViolations
        self.pageCount = pageCount
        self.pageSize = pageSize
        self.freelistCount = freelistCount
        self.schemaVersion = schemaVersion
    }

    public var allocatedDatabaseBytes: Int64 {
        pageCount * pageSize
    }
}

public struct SQLiteStorageFootprint: Sendable, Codable, Hashable {
    public let databasePath: String
    public let databaseBytes: Int64
    public let walBytes: Int64
    public let shmBytes: Int64
    public let journalMode: String

    public init(
        databasePath: String,
        databaseBytes: Int64,
        walBytes: Int64,
        shmBytes: Int64,
        journalMode: String
    ) {
        self.databasePath = databasePath
        self.databaseBytes = databaseBytes
        self.walBytes = walBytes
        self.shmBytes = shmBytes
        self.journalMode = journalMode
    }

    public var totalBytes: Int64 {
        databaseBytes + walBytes + shmBytes
    }
}

public struct SQLiteColumnDefinition: Sendable, Codable, Hashable {
    public let columnIndex: Int
    public let name: String
    public let declaredType: String
    public let isNotNull: Bool
    public let defaultValueLiteral: String?
    public let primaryKeyOrdinal: Int

    public init(
        columnIndex: Int,
        name: String,
        declaredType: String,
        isNotNull: Bool,
        defaultValueLiteral: String?,
        primaryKeyOrdinal: Int
    ) {
        self.columnIndex = columnIndex
        self.name = name
        self.declaredType = declaredType
        self.isNotNull = isNotNull
        self.defaultValueLiteral = defaultValueLiteral
        self.primaryKeyOrdinal = primaryKeyOrdinal
    }
}

// MARK: - SQLite Column Types & Typed Value Representation

public enum SQLiteColumnType: Int32, Sendable, Codable, Hashable {
    case integer = 1 // SQLITE_INTEGER
    case float = 2   // SQLITE_FLOAT
    case text = 3    // SQLITE_TEXT
    case blob = 4    // SQLITE_BLOB
    case null = 5    // SQLITE_NULL

    public init(sqliteCode: Int32) {
        switch sqliteCode {
        case SQLITE_INTEGER: self = .integer
        case SQLITE_FLOAT: self = .float
        case SQLITE_TEXT: self = .text
        case SQLITE_BLOB: self = .blob
        default: self = .null
        }
    }
}

public enum SQLiteValue: Sendable, Hashable, CustomStringConvertible {
    case null
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)

    public static func uint64(_ value: UInt64) -> SQLiteValue {
        .integer(Int64(bitPattern: value))
    }

    public static func int(_ value: Int) -> SQLiteValue {
        .integer(Int64(value))
    }

    public static func bool(_ value: Bool) -> SQLiteValue {
        .integer(value ? 1 : 0)
    }

    public static func uuid(_ value: UUID) -> SQLiteValue {
        .text(value.uuidString)
    }

    public static func date(_ value: Date) -> SQLiteValue {
        .real(value.timeIntervalSince1970)
    }

    public static func address(_ value: VirtualAddress) -> SQLiteValue {
        .integer(Int64(bitPattern: value.rawValue))
    }

    public static func optionalAddress(_ value: VirtualAddress?) -> SQLiteValue {
        guard let value else { return .null }
        return .address(value)
    }

    public static func fileOffset(_ value: FileOffset) -> SQLiteValue {
        .integer(Int64(bitPattern: value.rawValue))
    }

    public static func optionalFileOffset(_ value: FileOffset?) -> SQLiteValue {
        guard let value else { return .null }
        return .fileOffset(value)
    }

    public static func optionalText(_ value: String?) -> SQLiteValue {
        guard let value else { return .null }
        return .text(value)
    }

    public static func optionalInt(_ value: Int?) -> SQLiteValue {
        guard let value else { return .null }
        return .integer(Int64(value))
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    public var int64Value: Int64? {
        switch self {
        case .integer(let v): return v
        case .real(let d): return Int64(d)
        case .text(let s): return Int64(s)
        default: return nil
        }
    }

    public var uint64Value: UInt64? {
        switch self {
        case .integer(let v): return UInt64(bitPattern: v)
        case .text(let s): return VirtualAddress(hexOrDecimal: s)?.rawValue
        default: return nil
        }
    }

    public var doubleValue: Double? {
        switch self {
        case .real(let d): return d
        case .integer(let v): return Double(v)
        case .text(let s): return Double(s)
        default: return nil
        }
    }

    public var stringValue: String? {
        switch self {
        case .text(let s): return s
        case .integer(let v): return String(v)
        case .real(let d): return String(d)
        case .blob(let data): return String(data: data, encoding: .utf8)
        case .null: return nil
        }
    }

    public var dataValue: Data? {
        switch self {
        case .blob(let data): return data
        case .text(let s): return Data(s.utf8)
        default: return nil
        }
    }

    public var description: String {
        switch self {
        case .null: return "NULL"
        case .integer(let v): return "\(v)"
        case .real(let d): return "\(d)"
        case .text(let s): return "'\(s)'"
        case .blob(let data): return "<\(data.count) bytes>"
        }
    }
}

// MARK: - Materialized SQLite Row Reader

public struct SQLiteRow: Sendable, Hashable {
    public let columnNames: [String]
    public let values: [SQLiteValue]
    private let columnIndexLookup: [String: Int]

    public init(columnNames: [String], values: [SQLiteValue]) {
        self.columnNames = columnNames
        self.values = values
        var lookup: [String: Int] = [:]
        lookup.reserveCapacity(columnNames.count)
        for (idx, name) in columnNames.enumerated() {
            lookup[name.lowercased()] = idx
        }
        self.columnIndexLookup = lookup
    }

    public var count: Int { values.count }

    public func index(of column: String) -> Int? {
        columnIndexLookup[column.lowercased()]
    }

    public subscript(index: Int) -> SQLiteValue {
        guard index >= 0 && index < values.count else { return .null }
        return values[index]
    }

    public subscript(column: String) -> SQLiteValue {
        guard let idx = index(of: column) else { return .null }
        return values[idx]
    }

    public func isNull(_ index: Int) -> Bool {
        self[index].isNull
    }

    public func isNull(_ column: String) -> Bool {
        self[column].isNull
    }

    public func int64(_ index: Int) -> Int64 {
        self[index].int64Value ?? 0
    }

    public func int64(_ column: String) -> Int64 {
        self[column].int64Value ?? 0
    }

    public func optionalInt64(_ index: Int) -> Int64? {
        self[index].int64Value
    }

    public func optionalInt64(_ column: String) -> Int64? {
        self[column].int64Value
    }

    public func uint64(_ index: Int) -> UInt64 {
        self[index].uint64Value ?? 0
    }

    public func uint64(_ column: String) -> UInt64 {
        self[column].uint64Value ?? 0
    }

    public func int(_ index: Int) -> Int {
        Int(truncatingIfNeeded: int64(index))
    }

    public func int(_ column: String) -> Int {
        Int(truncatingIfNeeded: int64(column))
    }

    public func optionalInt(_ index: Int) -> Int? {
        optionalInt64(index).map { Int(truncatingIfNeeded: $0) }
    }

    public func optionalInt(_ column: String) -> Int? {
        optionalInt64(column).map { Int(truncatingIfNeeded: $0) }
    }

    public func bool(_ index: Int) -> Bool {
        int64(index) != 0
    }

    public func bool(_ column: String) -> Bool {
        int64(column) != 0
    }

    public func double(_ index: Int) -> Double {
        self[index].doubleValue ?? 0.0
    }

    public func double(_ column: String) -> Double {
        self[column].doubleValue ?? 0.0
    }

    public func string(_ index: Int) -> String {
        self[index].stringValue ?? ""
    }

    public func string(_ column: String) -> String {
        self[column].stringValue ?? ""
    }

    public func optionalString(_ index: Int) -> String? {
        let val = self[index]
        if val.isNull { return nil }
        return val.stringValue
    }

    public func optionalString(_ column: String) -> String? {
        let val = self[column]
        if val.isNull { return nil }
        return val.stringValue
    }

    public func data(_ index: Int) -> Data {
        self[index].dataValue ?? Data()
    }

    public func data(_ column: String) -> Data {
        self[column].dataValue ?? Data()
    }

    public func optionalData(_ index: Int) -> Data? {
        let val = self[index]
        if val.isNull { return nil }
        return val.dataValue
    }

    public func optionalData(_ column: String) -> Data? {
        let val = self[column]
        if val.isNull { return nil }
        return val.dataValue
    }

    public func bytes(_ index: Int) -> [UInt8] {
        Array(data(index))
    }

    public func bytes(_ column: String) -> [UInt8] {
        Array(data(column))
    }

    public func uuid(_ index: Int) -> UUID {
        UUID(uuidString: string(index)) ?? UUID()
    }

    public func uuid(_ column: String) -> UUID {
        UUID(uuidString: string(column)) ?? UUID()
    }

    public func date(_ index: Int) -> Date {
        Date(timeIntervalSince1970: double(index))
    }

    public func date(_ column: String) -> Date {
        Date(timeIntervalSince1970: double(column))
    }

    public func address(_ index: Int) -> VirtualAddress {
        VirtualAddress(uint64(index))
    }

    public func address(_ column: String) -> VirtualAddress {
        VirtualAddress(uint64(column))
    }

    public func optionalAddress(_ index: Int) -> VirtualAddress? {
        guard !isNull(index), let raw = self[index].uint64Value else { return nil }
        return VirtualAddress(raw)
    }

    public func optionalAddress(_ column: String) -> VirtualAddress? {
        guard !isNull(column), let raw = self[column].uint64Value else { return nil }
        return VirtualAddress(raw)
    }

    public func fileOffset(_ index: Int) -> FileOffset {
        FileOffset(uint64(index))
    }

    public func fileOffset(_ column: String) -> FileOffset {
        FileOffset(uint64(column))
    }

    public func optionalFileOffset(_ index: Int) -> FileOffset? {
        guard !isNull(index), let raw = self[index].uint64Value else { return nil }
        return FileOffset(raw)
    }

    public func optionalFileOffset(_ column: String) -> FileOffset? {
        guard !isNull(column), let raw = self[column].uint64Value else { return nil }
        return FileOffset(raw)
    }

    public func decodeJSON<T: Decodable>(_ type: T.Type, at index: Int) throws -> T {
        guard let payload = optionalData(index) else {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Expected JSON payload at column index \(index), got NULL"
            )
        }
        do {
            return try StoreJSONCoding.makeDecoder().decode(T.self, from: payload)
        } catch {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Failed decoding \(T.self) at column \(index): \(error.localizedDescription)"
            )
        }
    }

    public func decodeJSON<T: Decodable>(_ type: T.Type, column: String) throws -> T {
        guard let idx = index(of: column) else {
            throw MachGraphError.databaseError(
                code: SQLITE_RANGE,
                message: "Column '\(column)' not found in SQLite result row"
            )
        }
        return try decodeJSON(type, at: idx)
    }
}

// MARK: - Prepared Statement Wrapper (SQLiteStatement)

public final class SQLiteStatement {
    private var handle: OpaquePointer?
    private let dbHandle: OpaquePointer
    public let sql: String
    public let columnCount: Int
    public let columnNames: [String]

    private static var transientDestructor: sqlite3_destructor_type {
        unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    }

    init(dbHandle: OpaquePointer, sql: String) throws {
        self.dbHandle = dbHandle
        self.sql = sql
        var compiled: OpaquePointer?
        let rc = sql.withCString { cStr in
            sqlite3_prepare_v2(dbHandle, cStr, -1, &compiled, nil)
        }
        guard rc == SQLITE_OK, let stmt = compiled else {
            let msg = Self.extractErrorMessage(from: dbHandle)
            if let compiled {
                sqlite3_finalize(compiled)
            }
            throw MachGraphError.databaseError(
                code: rc,
                message: "Failed preparing SQL [\(sql)]: \(msg)"
            )
        }
        self.handle = stmt
        let count = Int(sqlite3_column_count(stmt))
        self.columnCount = count
        var names: [String] = []
        names.reserveCapacity(count)
        for i in 0..<Int32(count) {
            if let rawName = sqlite3_column_name(stmt, i) {
                names.append(String(cString: rawName))
            } else {
                names.append("col_\(i)")
            }
        }
        self.columnNames = names
    }

    deinit {
        finalize()
    }

    public func finalize() {
        if let stmt = handle {
            sqlite3_finalize(stmt)
            handle = nil
        }
    }

    private func requireHandle() throws -> OpaquePointer {
        guard let stmt = handle else {
            throw MachGraphError.databaseError(
                code: SQLITE_MISUSE,
                message: "Attempted to use finalized SQLiteStatement"
            )
        }
        return stmt
    }

    private static func extractErrorMessage(from db: OpaquePointer) -> String {
        if let errPtr = sqlite3_errmsg(db) {
            return String(cString: errPtr)
        }
        return "Unknown SQLite error"
    }

    private func checkBindResult(_ rc: Int32, index: Int32) throws {
        guard rc == SQLITE_OK else {
            let msg = Self.extractErrorMessage(from: dbHandle)
            throw MachGraphError.databaseError(
                code: rc,
                message: "Failed binding parameter #\(index): \(msg)"
            )
        }
    }

    public var parameterCount: Int {
        guard let stmt = handle else { return 0 }
        return Int(sqlite3_bind_parameter_count(stmt))
    }

    public func parameterIndex(for name: String) throws -> Int32 {
        let stmt = try requireHandle()
        let normalized = (name.hasPrefix(":") || name.hasPrefix("@") || name.hasPrefix("$")) ? name : ":\(name)"
        let idx = normalized.withCString { cName in
            sqlite3_bind_parameter_index(stmt, cName)
        }
        guard idx > 0 else {
            throw MachGraphError.databaseError(
                code: SQLITE_RANGE,
                message: "Named SQL parameter '\(normalized)' does not exist in statement"
            )
        }
        return idx
    }

    // MARK: Positional Binders (1-Based SQLite Parameter Index)

    public func bindNull(at index: Int32) throws {
        let stmt = try requireHandle()
        try checkBindResult(sqlite3_bind_null(stmt, index), index: index)
    }

    public func bindInt64(_ value: Int64, at index: Int32) throws {
        let stmt = try requireHandle()
        try checkBindResult(sqlite3_bind_int64(stmt, index, value), index: index)
    }

    public func bindOptionalInt64(_ value: Int64?, at index: Int32) throws {
        if let value {
            try bindInt64(value, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindUInt64(_ value: UInt64, at index: Int32) throws {
        try bindInt64(Int64(bitPattern: value), at: index)
    }

    public func bindOptionalUInt64(_ value: UInt64?, at index: Int32) throws {
        if let value {
            try bindUInt64(value, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindInt(_ value: Int, at index: Int32) throws {
        try bindInt64(Int64(value), at: index)
    }

    public func bindOptionalInt(_ value: Int?, at index: Int32) throws {
        if let value {
            try bindInt(value, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindInt32(_ value: Int32, at index: Int32) throws {
        let stmt = try requireHandle()
        try checkBindResult(sqlite3_bind_int(stmt, index, value), index: index)
    }

    public func bindBool(_ value: Bool, at index: Int32) throws {
        try bindInt32(value ? 1 : 0, at: index)
    }

    public func bindDouble(_ value: Double, at index: Int32) throws {
        let stmt = try requireHandle()
        try checkBindResult(sqlite3_bind_double(stmt, index, value), index: index)
    }

    public func bindText(_ value: String, at index: Int32) throws {
        let stmt = try requireHandle()
        let utf8 = Array(value.utf8)
        if utf8.isEmpty {
            let rc = "".withCString { emptyPtr in
                sqlite3_bind_text(stmt, index, emptyPtr, 0, Self.transientDestructor)
            }
            try checkBindResult(rc, index: index)
        } else {
            let rc = utf8.withUnsafeBufferPointer { buf in
                buf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buf.count) { cPtr in
                    sqlite3_bind_text(stmt, index, cPtr, Int32(buf.count), Self.transientDestructor)
                }
            }
            try checkBindResult(rc, index: index)
        }
    }

    public func bindOptionalText(_ value: String?, at index: Int32) throws {
        if let value {
            try bindText(value, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindBlob(_ data: Data, at index: Int32) throws {
        let stmt = try requireHandle()
        if data.isEmpty {
            try checkBindResult(sqlite3_bind_zeroblob(stmt, index, 0), index: index)
        } else {
            let rc = data.withUnsafeBytes { rawBuf in
                sqlite3_bind_blob(
                    stmt,
                    index,
                    rawBuf.baseAddress,
                    Int32(rawBuf.count),
                    Self.transientDestructor
                )
            }
            try checkBindResult(rc, index: index)
        }
    }

    public func bindOptionalBlob(_ data: Data?, at index: Int32) throws {
        if let data {
            try bindBlob(data, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindBytes(_ bytes: [UInt8], at index: Int32) throws {
        let stmt = try requireHandle()
        if bytes.isEmpty {
            try checkBindResult(sqlite3_bind_zeroblob(stmt, index, 0), index: index)
        } else {
            let rc = bytes.withUnsafeBytes { rawBuf in
                sqlite3_bind_blob(
                    stmt,
                    index,
                    rawBuf.baseAddress,
                    Int32(rawBuf.count),
                    Self.transientDestructor
                )
            }
            try checkBindResult(rc, index: index)
        }
    }

    public func bindUUID(_ uuid: UUID, at index: Int32) throws {
        try bindText(uuid.uuidString, at: index)
    }

    public func bindDate(_ date: Date, at index: Int32) throws {
        try bindDouble(date.timeIntervalSince1970, at: index)
    }

    public func bindAddress(_ address: VirtualAddress, at index: Int32) throws {
        try bindUInt64(address.rawValue, at: index)
    }

    public func bindOptionalAddress(_ address: VirtualAddress?, at index: Int32) throws {
        if let address {
            try bindAddress(address, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindFileOffset(_ offset: FileOffset, at index: Int32) throws {
        try bindUInt64(offset.rawValue, at: index)
    }

    public func bindOptionalFileOffset(_ offset: FileOffset?, at index: Int32) throws {
        if let offset {
            try bindFileOffset(offset, at: index)
        } else {
            try bindNull(at: index)
        }
    }

    public func bindCodableJSON<T: Encodable>(_ value: T, asBlob: Bool = false, at index: Int32) throws {
        let encoded: Data
        do {
            encoded = try StoreJSONCoding.makeEncoder().encode(value)
        } catch {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Failed JSON-encoding \(T.self) for bind #\(index): \(error.localizedDescription)"
            )
        }
        if asBlob {
            try bindBlob(encoded, at: index)
        } else {
            try bindText(String(decoding: encoded, as: UTF8.self), at: index)
        }
    }

    public func bindValue(_ value: SQLiteValue, at index: Int32) throws {
        switch value {
        case .null:
            try bindNull(at: index)
        case .integer(let v):
            try bindInt64(v, at: index)
        case .real(let d):
            try bindDouble(d, at: index)
        case .text(let s):
            try bindText(s, at: index)
        case .blob(let data):
            try bindBlob(data, at: index)
        }
    }

    public func bindValues(_ values: [SQLiteValue]) throws {
        for (offset, val) in values.enumerated() {
            try bindValue(val, at: Int32(offset + 1))
        }
    }

    public func bindNamed(_ bindings: [String: SQLiteValue]) throws {
        for (name, val) in bindings {
            let idx = try parameterIndex(for: name)
            try bindValue(val, at: idx)
        }
    }

    // MARK: Execution & Row Cursor Readers

    public func step() throws -> Bool {
        let stmt = try requireHandle()
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_ROW {
            return true
        }
        if rc == SQLITE_DONE {
            return false
        }
        let msg = Self.extractErrorMessage(from: dbHandle)
        throw MachGraphError.databaseError(
            code: rc,
            message: "SQLite step failed: \(msg)"
        )
    }

    @discardableResult
    public func stepDone() throws -> Bool {
        try step()
    }

    public func reset(clearBindings shouldClear: Bool = true) throws {
        let stmt = try requireHandle()
        let rc = sqlite3_reset(stmt)
        guard rc == SQLITE_OK else {
            let msg = Self.extractErrorMessage(from: dbHandle)
            throw MachGraphError.databaseError(code: rc, message: "SQLite reset failed: \(msg)")
        }
        if shouldClear {
            let clearRC = sqlite3_clear_bindings(stmt)
            guard clearRC == SQLITE_OK else {
                let msg = Self.extractErrorMessage(from: dbHandle)
                throw MachGraphError.databaseError(code: clearRC, message: "SQLite clear_bindings failed: \(msg)")
            }
        }
    }

    // MARK: Direct Column Readers (0-Based Index)

    public func columnType(at index: Int32) -> SQLiteColumnType {
        guard let stmt = handle else { return .null }
        return SQLiteColumnType(sqliteCode: sqlite3_column_type(stmt, index))
    }

    public func columnIsNull(at index: Int32) -> Bool {
        columnType(at: index) == .null
    }

    public func columnInt64(at index: Int32) -> Int64 {
        guard let stmt = handle else { return 0 }
        return sqlite3_column_int64(stmt, index)
    }

    public func columnOptionalInt64(at index: Int32) -> Int64? {
        guard !columnIsNull(at: index) else { return nil }
        return columnInt64(at: index)
    }

    public func columnUInt64(at index: Int32) -> UInt64 {
        UInt64(bitPattern: columnInt64(at: index))
    }

    public func columnInt(at index: Int32) -> Int {
        Int(truncatingIfNeeded: columnInt64(at: index))
    }

    public func columnOptionalInt(at index: Int32) -> Int? {
        columnOptionalInt64(at: index).map { Int(truncatingIfNeeded: $0) }
    }

    public func columnBool(at index: Int32) -> Bool {
        columnInt64(at: index) != 0
    }

    public func columnDouble(at index: Int32) -> Double {
        guard let stmt = handle else { return 0.0 }
        return sqlite3_column_double(stmt, index)
    }

    public func columnString(at index: Int32) -> String {
        guard let stmt = handle, let cText = sqlite3_column_text(stmt, index) else {
            return ""
        }
        let byteLen = Int(sqlite3_column_bytes(stmt, index))
        guard byteLen > 0 else { return "" }
        let buffer = UnsafeBufferPointer(start: cText, count: byteLen)
        return String(decoding: buffer, as: UTF8.self)
    }

    public func columnOptionalString(at index: Int32) -> String? {
        guard !columnIsNull(at: index) else { return nil }
        return columnString(at: index)
    }

    public func columnData(at index: Int32) -> Data {
        guard let stmt = handle else { return Data() }
        let byteLen = Int(sqlite3_column_bytes(stmt, index))
        guard byteLen > 0, let rawPtr = sqlite3_column_blob(stmt, index) else {
            return Data()
        }
        return Data(bytes: rawPtr, count: byteLen)
    }

    public func columnOptionalData(at index: Int32) -> Data? {
        guard !columnIsNull(at: index) else { return nil }
        return columnData(at: index)
    }

    public func columnBytes(at index: Int32) -> [UInt8] {
        Array(columnData(at: index))
    }

    public func columnUUID(at index: Int32) -> UUID {
        UUID(uuidString: columnString(at: index)) ?? UUID()
    }

    public func columnDate(at index: Int32) -> Date {
        Date(timeIntervalSince1970: columnDouble(at: index))
    }

    public func columnAddress(at index: Int32) -> VirtualAddress {
        VirtualAddress(columnUInt64(at: index))
    }

    public func columnOptionalAddress(at index: Int32) -> VirtualAddress? {
        guard !columnIsNull(at: index) else { return nil }
        return VirtualAddress(columnUInt64(at: index))
    }

    public func columnFileOffset(at index: Int32) -> FileOffset {
        FileOffset(columnUInt64(at: index))
    }

    public func columnOptionalFileOffset(at index: Int32) -> FileOffset? {
        guard !columnIsNull(at: index) else { return nil }
        return FileOffset(columnUInt64(at: index))
    }

    public func columnDecodeJSON<T: Decodable>(_ type: T.Type, at index: Int32) throws -> T {
        let payload: Data
        switch columnType(at: index) {
        case .blob:
            payload = columnData(at: index)
        case .text:
            payload = Data(columnString(at: index).utf8)
        default:
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Expected TEXT or BLOB JSON column at index \(index)"
            )
        }
        do {
            return try StoreJSONCoding.makeDecoder().decode(T.self, from: payload)
        } catch {
            throw MachGraphError.databaseError(
                code: SQLITE_MISMATCH,
                message: "Failed JSON-decoding \(T.self) at column \(index): \(error.localizedDescription)"
            )
        }
    }

    public func currentValue(at index: Int32) -> SQLiteValue {
        switch columnType(at: index) {
        case .null:
            return .null
        case .integer:
            return .integer(columnInt64(at: index))
        case .float:
            return .real(columnDouble(at: index))
        case .text:
            return .text(columnString(at: index))
        case .blob:
            return .blob(columnData(at: index))
        }
    }

    public func materializeRow() -> SQLiteRow {
        var rowValues: [SQLiteValue] = []
        rowValues.reserveCapacity(columnCount)
        for col in 0..<Int32(columnCount) {
            rowValues.append(currentValue(at: col))
        }
        return SQLiteRow(columnNames: columnNames, values: rowValues)
    }
}

// MARK: - Thread-Safe C SQLite3 WAL Connection

public final class MachSQLiteWALConnection: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var dbHandle: OpaquePointer?
    private var transactionDepth: Int = 0
    private var savepointCounter: UInt64 = 0

    public let databasePath: String
    public let configuration: SQLiteConnectionConfiguration

    public init(
        path: String,
        configuration: SQLiteConnectionConfiguration = .standardWAL
    ) throws {
        self.databasePath = path
        self.configuration = configuration

        let openTarget: String
        let flags: Int32
        switch configuration.openMode {
        case .readWriteCreate:
            openTarget = path
            flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE
        case .readWriteExisting:
            openTarget = path
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE
        case .readOnly:
            openTarget = path
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE
        case .inMemory:
            openTarget = ":memory:"
            flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_MEMORY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE
        }

        if configuration.openMode == .readWriteExisting || configuration.openMode == .readOnly {
            if path != ":memory:" && !FileManager.default.fileExists(atPath: path) {
                throw MachGraphError.fileNotFound(path)
            }
        } else if configuration.openMode == .readWriteCreate && path != ":memory:" {
            let parentURL = URL(fileURLWithPath: path).deletingLastPathComponent()
            if !FileManager.default.fileExists(atPath: parentURL.path) {
                do {
                    try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: true)
                } catch {
                    throw MachGraphError.ioFailure("Failed creating SQLite parent directory '\(parentURL.path)': \(error.localizedDescription)")
                }
            }
        }

        var opened: OpaquePointer?
        let rc = openTarget.withCString { cPath in
            sqlite3_open_v2(cPath, &opened, flags, nil)
        }
        guard rc == SQLITE_OK, let handle = opened else {
            let message: String
            if let opened, let errPtr = sqlite3_errmsg(opened) {
                message = String(cString: errPtr)
                sqlite3_close_v2(opened)
            } else {
                message = "sqlite3_open_v2 failed with code \(rc)"
            }
            throw MachGraphError.databaseError(code: rc, message: message)
        }

        self.dbHandle = handle
        sqlite3_busy_timeout(handle, configuration.busyTimeoutMilliseconds)

        do {
            try configurePragmas()
            if configuration.autoMigrateToLatest && configuration.openMode != .readOnly {
                _ = try MachSchemaMigrationManager.migrateToLatest(on: self)
            }
        } catch {
            sqlite3_close_v2(handle)
            self.dbHandle = nil
            throw error
        }
    }

    public convenience init(
        url: URL,
        configuration: SQLiteConnectionConfiguration = .standardWAL
    ) throws {
        try self.init(path: url.path, configuration: configuration)
    }

    deinit {
        close()
    }

    public var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return dbHandle != nil
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        if let handle = dbHandle {
            if configuration.enableWAL && configuration.openMode != .readOnly && configuration.openMode != .inMemory {
                var logFrames: Int32 = 0
                var ckptFrames: Int32 = 0
                _ = sqlite3_wal_checkpoint_v2(handle, nil, SQLITE_CHECKPOINT_PASSIVE, &logFrames, &ckptFrames)
            }
            sqlite3_close_v2(handle)
            dbHandle = nil
            transactionDepth = 0
        }
    }

    private func requireOpenHandle() throws -> OpaquePointer {
        guard let handle = dbHandle else {
            throw MachGraphError.databaseError(
                code: SQLITE_MISUSE,
                message: "MachSQLiteWALConnection is already closed ('\(databasePath)')"
            )
        }
        return handle
    }

    private func configurePragmas() throws {
        if configuration.enableWAL && configuration.openMode != .inMemory && configuration.openMode != .readOnly {
            _ = try queryScalarString("PRAGMA journal_mode = WAL;")
        }
        if configuration.openMode != .readOnly {
            try execute("PRAGMA synchronous = \(configuration.synchronousMode.rawValue);")
        }
        if configuration.enforceForeignKeys {
            try execute("PRAGMA foreign_keys = ON;")
        } else {
            try execute("PRAGMA foreign_keys = OFF;")
        }
        if configuration.memoryTempStore {
            try execute("PRAGMA temp_store = MEMORY;")
        }
        if configuration.pageCacheSizeKiB > 0 {
            try execute("PRAGMA cache_size = -\(configuration.pageCacheSizeKiB);")
        }
    }

    // MARK: Thread-Safe Synchronization & Statement Execution

    public func withExclusiveAccess<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    public func execute(_ sql: String) throws {
        lock.lock()
        defer { lock.unlock() }
        let handle = try requireOpenHandle()
        var errMsgPtr: UnsafeMutablePointer<CChar>?
        let rc = sql.withCString { cSQL in
            sqlite3_exec(handle, cSQL, nil, nil, &errMsgPtr)
        }
        if rc != SQLITE_OK {
            let detail: String
            if let errMsgPtr {
                detail = String(cString: errMsgPtr)
                sqlite3_free(errMsgPtr)
            } else if let ptr = sqlite3_errmsg(handle) {
                detail = String(cString: ptr)
            } else {
                detail = "sqlite3_exec failed"
            }
            throw MachGraphError.databaseError(code: rc, message: detail)
        }
    }

    @discardableResult
    public func execute(_ sql: String, bindings: [SQLiteValue]) throws -> Int {
        lock.lock()
        defer { lock.unlock() }
        let handle = try requireOpenHandle()
        let stmt = try SQLiteStatement(dbHandle: handle, sql: sql)
        defer { stmt.finalize() }
        try stmt.bindValues(bindings)
        _ = try stmt.step()
        return Int(sqlite3_changes(handle))
    }

    public func withPreparedStatement<T>(
        _ sql: String,
        _ body: (SQLiteStatement) throws -> T
    ) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        let handle = try requireOpenHandle()
        let stmt = try SQLiteStatement(dbHandle: handle, sql: sql)
        defer { stmt.finalize() }
        return try body(stmt)
    }

    public func query(_ sql: String, bindings: [SQLiteValue] = []) throws -> [SQLiteRow] {
        try withPreparedStatement(sql) { stmt in
            if !bindings.isEmpty {
                try stmt.bindValues(bindings)
            }
            var rows: [SQLiteRow] = []
            while try stmt.step() {
                rows.append(stmt.materializeRow())
            }
            return rows
        }
    }

    public func queryOne(_ sql: String, bindings: [SQLiteValue] = []) throws -> SQLiteRow? {
        try withPreparedStatement(sql) { stmt in
            if !bindings.isEmpty {
                try stmt.bindValues(bindings)
            }
            guard try stmt.step() else { return nil }
            return stmt.materializeRow()
        }
    }

    public func queryScalarInt64(_ sql: String, bindings: [SQLiteValue] = []) throws -> Int64? {
        try withPreparedStatement(sql) { stmt in
            if !bindings.isEmpty {
                try stmt.bindValues(bindings)
            }
            guard try stmt.step() else { return nil }
            return stmt.columnOptionalInt64(at: 0)
        }
    }

    public func queryScalarInt(_ sql: String, bindings: [SQLiteValue] = []) throws -> Int {
        Int(truncatingIfNeeded: try queryScalarInt64(sql, bindings: bindings) ?? 0)
    }

    public func queryScalarString(_ sql: String, bindings: [SQLiteValue] = []) throws -> String? {
        try withPreparedStatement(sql) { stmt in
            if !bindings.isEmpty {
                try stmt.bindValues(bindings)
            }
            guard try stmt.step() else { return nil }
            return stmt.columnOptionalString(at: 0)
        }
    }

    public var lastInsertedRowID: Int64 {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = dbHandle else { return 0 }
        return sqlite3_last_insert_rowid(handle)
    }

    public var recentChangedRowCount: Int {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = dbHandle else { return 0 }
        return Int(sqlite3_changes(handle))
    }

    // MARK: Nested Transactions (BEGIN IMMEDIATE + SAVEPOINT)

    public var currentTransactionDepth: Int {
        lock.lock()
        defer { lock.unlock() }
        return transactionDepth
    }

    @discardableResult
    public func withTransaction<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        _ = try requireOpenHandle()

        if transactionDepth == 0 {
            try execute("BEGIN IMMEDIATE TRANSACTION;")
            transactionDepth = 1
            do {
                let result = try body()
                transactionDepth = 0
                try execute("COMMIT TRANSACTION;")
                return result
            } catch {
                transactionDepth = 0
                try? execute("ROLLBACK TRANSACTION;")
                throw error
            }
        } else {
            savepointCounter &+= 1
            let spName = "mg_sp_\(transactionDepth)_\(savepointCounter)"
            return try executeSavepointInternal(named: spName, body: body)
        }
    }

    @discardableResult
    public func withSavepoint<T>(named rawName: String, _ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        _ = try requireOpenHandle()
        let sanitized = rawName.unicodeScalars
            .map { CharacterSet.alphanumerics.contains($0) || $0 == "_" ? String($0) : "_" }
            .joined()
        let spName = sanitized.isEmpty ? "mg_savepoint" : sanitized
        return try executeSavepointInternal(named: spName, body: body)
    }

    private func executeSavepointInternal<T>(named spName: String, body: () throws -> T) throws -> T {
        try execute("SAVEPOINT \(spName);")
        transactionDepth += 1
        do {
            let result = try body()
            transactionDepth -= 1
            try execute("RELEASE SAVEPOINT \(spName);")
            return result
        } catch {
            transactionDepth -= 1
            try? execute("ROLLBACK TO SAVEPOINT \(spName);")
            try? execute("RELEASE SAVEPOINT \(spName);")
            throw error
        }
    }

    // MARK: WAL Checkpointing, Integrity Check & Disk Size Inspector

    @discardableResult
    public func checkpointWAL(mode: WALCheckpointMode = .passive) throws -> WALCheckpointResult {
        lock.lock()
        defer { lock.unlock() }
        let handle = try requireOpenHandle()

        if configuration.openMode == .inMemory || databasePath == ":memory:" {
            return WALCheckpointResult(mode: mode, totalLogFrames: 0, checkpointedFrames: 0)
        }

        var totalFrames: Int32 = 0
        var checkpointed: Int32 = 0
        let rc = sqlite3_wal_checkpoint_v2(
            handle,
            nil,
            mode.sqliteFlag,
            &totalFrames,
            &checkpointed
        )
        guard rc == SQLITE_OK else {
            let msg = sqlite3_errmsg(handle).map { String(cString: $0) } ?? "WAL checkpoint failed"
            throw MachGraphError.databaseError(code: rc, message: msg)
        }
        return WALCheckpointResult(
            mode: mode,
            totalLogFrames: totalFrames,
            checkpointedFrames: checkpointed
        )
    }

    public func verifyIntegrity(maxErrors: Int = 100) throws -> SQLiteIntegrityReport {
        lock.lock()
        defer { lock.unlock() }
        _ = try requireOpenHandle()

        let boundedErrors = max(1, min(1_000, maxErrors))
        let rows = try query("PRAGMA integrity_check(\(boundedErrors));")
        let messages = rows.map { $0.string(0) }.filter { !$0.isEmpty }
        let integrityPassed = (messages.count == 1 && messages[0].lowercased() == "ok")

        let fkRows = try query("PRAGMA foreign_key_check;")
        let pageCount = try queryScalarInt64("PRAGMA page_count;") ?? 0
        let pageSize = try queryScalarInt64("PRAGMA page_size;") ?? 4096
        let freelistCount = try queryScalarInt64("PRAGMA freelist_count;") ?? 0
        let userVersion = try queryScalarInt("PRAGMA user_version;")

        return SQLiteIntegrityReport(
            isOK: integrityPassed && fkRows.isEmpty,
            messages: messages,
            foreignKeyViolations: fkRows.count,
            pageCount: pageCount,
            pageSize: pageSize,
            freelistCount: freelistCount,
            schemaVersion: userVersion
        )
    }

    public func inspectStorageFootprint() -> SQLiteStorageFootprint {
        lock.lock()
        defer { lock.unlock() }

        let journal = (try? queryScalarString("PRAGMA journal_mode;"))?.uppercased() ?? "MEMORY"
        guard databasePath != ":memory:" && configuration.openMode != .inMemory else {
            let pageCount = (try? queryScalarInt64("PRAGMA page_count;")) ?? 0
            let pageSize = (try? queryScalarInt64("PRAGMA page_size;")) ?? 4096
            return SQLiteStorageFootprint(
                databasePath: ":memory:",
                databaseBytes: pageCount * pageSize,
                walBytes: 0,
                shmBytes: 0,
                journalMode: journal
            )
        }

        let dbSize = Self.fileSizeInBytes(atPath: databasePath)
        let walSize = Self.fileSizeInBytes(atPath: "\(databasePath)-wal")
        let shmSize = Self.fileSizeInBytes(atPath: "\(databasePath)-shm")

        return SQLiteStorageFootprint(
            databasePath: databasePath,
            databaseBytes: dbSize,
            walBytes: walSize,
            shmBytes: shmSize,
            journalMode: journal
        )
    }

    public func optimizeQueryPlanner() throws {
        try execute("PRAGMA optimize;")
    }

    public func tableExists(_ tableName: String) throws -> Bool {
        let count = try queryScalarInt(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?;",
            bindings: [.text(tableName)]
        )
        return count > 0
    }

    public func indexExists(_ indexName: String) throws -> Bool {
        let count = try queryScalarInt(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?;",
            bindings: [.text(indexName)]
        )
        return count > 0
    }

    public func inspectTableColumns(_ tableName: String) throws -> [SQLiteColumnDefinition] {
        let safeIdentifier = tableName.filter { $0.isLetter || $0.isNumber || $0 == "_" }
        guard !safeIdentifier.isEmpty else { return [] }
        let rows = try query("PRAGMA table_info(\(safeIdentifier));")
        return rows.map { row in
            SQLiteColumnDefinition(
                columnIndex: row.int("cid"),
                name: row.string("name"),
                declaredType: row.string("type"),
                isNotNull: row.bool("notnull"),
                defaultValueLiteral: row.optionalString("dflt_value"),
                primaryKeyOrdinal: row.int("pk")
            )
        }
    }

    public func userSchemaVersion() throws -> Int {
        try queryScalarInt("PRAGMA user_version;")
    }

    public func setUserSchemaVersion(_ version: Int) throws {
        try execute("PRAGMA user_version = \(max(0, version));")
    }

    private static func fileSizeInBytes(atPath path: String) -> Int64 {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let number = attrs[.size] as? NSNumber else {
            return 0
        }
        return number.int64Value
    }
}

// MARK: - Schema Migration Manager (v1 -> v4)

public enum MachSchemaVersion {
    public static let v1: Int = 1
    public static let v2: Int = 2
    public static let v3: Int = 3
    public static let v4: Int = 4
    public static let latest: Int = v4
}

public struct MachSchemaMigrationStep: Sendable {
    public let version: Int
    public let title: String
    public let statements: [String]
    public let expectedTables: [String]
    public let expectedIndexes: [String]

    public init(
        version: Int,
        title: String,
        statements: [String],
        expectedTables: [String],
        expectedIndexes: [String]
    ) {
        self.version = version
        self.title = title
        self.statements = statements
        self.expectedTables = expectedTables
        self.expectedIndexes = expectedIndexes
    }

    public var checksumHex: String {
        let canonical = "\(version)|\(title)|" + statements.joined(separator: "\n;\n")
        return BinaryHashAndEntropy.sha256Hex(of: Data(canonical.utf8))
    }
}

public struct MachSchemaMigrationRecord: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { version }
    public let version: Int
    public let title: String
    public let checksumHex: String
    public let appliedAt: Date

    public init(version: Int, title: String, checksumHex: String, appliedAt: Date) {
        self.version = version
        self.title = title
        self.checksumHex = checksumHex
        self.appliedAt = appliedAt
    }
}

public enum MachSchemaMigrationManager {
    public static let allSteps: [MachSchemaMigrationStep] = [
        migrationStepV1,
        migrationStepV2,
        migrationStepV3,
        migrationStepV4
    ]

    // MARK: v1 — Core Binary Metadata, Cached Symbols, Cached Functions & Indexed Xrefs

    public static let migrationStepV1 = MachSchemaMigrationStep(
        version: MachSchemaVersion.v1,
        title: "Core project metadata, symbol cache, CFG function cache, and indexed cross-references",
        statements: [
            """
            CREATE TABLE IF NOT EXISTS project_meta (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS cached_symbols (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                demangled_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                binding TEXT NOT NULL,
                address INTEGER NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                section_index INTEGER,
                library_ordinal INTEGER
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_cached_symbols_address ON cached_symbols(address);",
            "CREATE INDEX IF NOT EXISTS idx_cached_symbols_name ON cached_symbols(name COLLATE NOCASE);",
            "CREATE INDEX IF NOT EXISTS idx_cached_symbols_demangled ON cached_symbols(demangled_name COLLATE NOCASE);",
            "CREATE INDEX IF NOT EXISTS idx_cached_symbols_kind ON cached_symbols(kind);",
            """
            CREATE TABLE IF NOT EXISTS cached_functions (
                address INTEGER PRIMARY KEY NOT NULL,
                end_address INTEGER NOT NULL,
                name TEXT NOT NULL,
                demangled_name TEXT NOT NULL,
                is_leaf INTEGER NOT NULL DEFAULT 0,
                is_thunk INTEGER NOT NULL DEFAULT 0,
                uses_pac INTEGER NOT NULL DEFAULT 0,
                stack_frame_bytes INTEGER NOT NULL DEFAULT 0,
                block_count INTEGER NOT NULL DEFAULT 0,
                edge_count INTEGER NOT NULL DEFAULT 0,
                cyclomatic_complexity INTEGER NOT NULL DEFAULT 1,
                instruction_count INTEGER NOT NULL DEFAULT 0,
                cfg_json BLOB NOT NULL,
                decompiled_json BLOB,
                updated_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_cached_functions_span ON cached_functions(address, end_address);",
            "CREATE INDEX IF NOT EXISTS idx_cached_functions_name ON cached_functions(name COLLATE NOCASE);",
            """
            CREATE TABLE IF NOT EXISTS xrefs (
                id TEXT PRIMARY KEY NOT NULL,
                from_addr INTEGER NOT NULL,
                from_func INTEGER,
                to_addr INTEGER NOT NULL,
                kind TEXT NOT NULL,
                instruction_preview TEXT NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_xrefs_from_addr ON xrefs(from_addr);",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_to_addr ON xrefs(to_addr);",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_from_func ON xrefs(from_func);",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_kind ON xrefs(kind);",
            "CREATE INDEX IF NOT EXISTS idx_xrefs_to_addr_kind ON xrefs(to_addr, kind);"
        ],
        expectedTables: [
            "project_meta",
            "cached_symbols",
            "cached_functions",
            "xrefs"
        ],
        expectedIndexes: [
            "idx_xrefs_from_addr",
            "idx_xrefs_to_addr",
            "idx_xrefs_from_func",
            "idx_xrefs_kind"
        ]
    )

    // MARK: v2 — Analyst Annotations (Renames, Comments, Bookmarks, Custom Structs)

    public static let migrationStepV2 = MachSchemaMigrationStep(
        version: MachSchemaVersion.v2,
        title: "Analyst symbol renames, inline comments, triage bookmarks, and custom C structs",
        statements: [
            """
            CREATE TABLE IF NOT EXISTS user_renames (
                address INTEGER PRIMARY KEY NOT NULL,
                original_name TEXT NOT NULL,
                custom_name TEXT NOT NULL,
                signature_override TEXT,
                updated_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_user_renames_custom_name ON user_renames(custom_name COLLATE NOCASE);",
            """
            CREATE TABLE IF NOT EXISTS user_comments (
                address INTEGER PRIMARY KEY NOT NULL,
                text TEXT NOT NULL,
                is_repeatable INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS user_bookmarks (
                id TEXT PRIMARY KEY NOT NULL,
                address INTEGER NOT NULL,
                label TEXT NOT NULL,
                category_tag TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_user_bookmarks_address ON user_bookmarks(address);",
            "CREATE INDEX IF NOT EXISTS idx_user_bookmarks_category ON user_bookmarks(category_tag);",
            """
            CREATE TABLE IF NOT EXISTS custom_structs (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                total_byte_size INTEGER NOT NULL,
                alignment INTEGER NOT NULL DEFAULT 8,
                fields_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_custom_structs_name ON custom_structs(name COLLATE NOCASE);"
        ],
        expectedTables: [
            "user_renames",
            "user_comments",
            "user_bookmarks",
            "custom_structs"
        ],
        expectedIndexes: [
            "idx_user_renames_custom_name",
            "idx_user_bookmarks_address",
            "idx_custom_structs_name"
        ]
    )

    // MARK: v3 — Binary Byte Patches & Security Audit Findings

    public static let migrationStepV3 = MachSchemaMigrationStep(
        version: MachSchemaVersion.v3,
        title: "Binary byte patch ledger and sandboxed plugin security audit findings",
        statements: [
            """
            CREATE TABLE IF NOT EXISTS byte_patches (
                id TEXT PRIMARY KEY NOT NULL,
                file_offset INTEGER NOT NULL,
                virtual_address INTEGER,
                original_bytes BLOB NOT NULL,
                patched_bytes BLOB NOT NULL,
                original_assembly TEXT,
                patched_assembly TEXT,
                note TEXT NOT NULL DEFAULT '',
                is_enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_byte_patches_file_offset ON byte_patches(file_offset);",
            "CREATE INDEX IF NOT EXISTS idx_byte_patches_vm_address ON byte_patches(virtual_address);",
            """
            CREATE TABLE IF NOT EXISTS security_findings (
                id TEXT PRIMARY KEY NOT NULL,
                plugin_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                address INTEGER,
                evidence_preview TEXT,
                created_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_security_findings_plugin_id ON security_findings(plugin_id);",
            "CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings(severity);",
            "CREATE INDEX IF NOT EXISTS idx_security_findings_address ON security_findings(address);"
        ],
        expectedTables: [
            "byte_patches",
            "security_findings"
        ],
        expectedIndexes: [
            "idx_byte_patches_file_offset",
            "idx_security_findings_plugin_id",
            "idx_security_findings_severity"
        ]
    )

    // MARK: v4 — Persistent Undo/Redo Journal & Named Analysis Checkpoints

    public static let migrationStepV4 = MachSchemaMigrationStep(
        version: MachSchemaVersion.v4,
        title: "Persistent undo/redo journal and named analyst state snapshots",
        statements: [
            """
            CREATE TABLE IF NOT EXISTS undo_redo_journal (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT NOT NULL UNIQUE,
                stack_kind TEXT NOT NULL CHECK (stack_kind IN ('undo', 'redo')),
                title TEXT NOT NULL,
                operation_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_undo_redo_stack_seq ON undo_redo_journal(stack_kind, sequence_number DESC);",
            """
            CREATE TABLE IF NOT EXISTS analysis_snapshots (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                binary_sha256 TEXT NOT NULL DEFAULT '',
                rename_count INTEGER NOT NULL DEFAULT 0,
                comment_count INTEGER NOT NULL DEFAULT 0,
                bookmark_count INTEGER NOT NULL DEFAULT 0,
                struct_count INTEGER NOT NULL DEFAULT 0,
                patch_count INTEGER NOT NULL DEFAULT 0,
                payload_sha256 TEXT NOT NULL,
                payload_json BLOB NOT NULL,
                created_at REAL NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_analysis_snapshots_created_at ON analysis_snapshots(created_at DESC);"
        ],
        expectedTables: [
            "undo_redo_journal",
            "analysis_snapshots"
        ],
        expectedIndexes: [
            "idx_undo_redo_stack_seq",
            "idx_analysis_snapshots_created_at"
        ]
    )

    // MARK: Migration Execution & Audit Queries

    private static func ensureMigrationsAuditTable(on connection: MachSQLiteWALConnection) throws {
        try connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL,
                title TEXT NOT NULL,
                checksum_hex TEXT NOT NULL,
                applied_at REAL NOT NULL
            );
            """
        )
    }

    @discardableResult
    public static func migrateToLatest(on connection: MachSQLiteWALConnection) throws -> Int {
        try migrate(on: connection, targetVersion: MachSchemaVersion.latest)
    }

    @discardableResult
    public static func migrate(
        on connection: MachSQLiteWALConnection,
        targetVersion: Int
    ) throws -> Int {
        guard targetVersion >= MachSchemaVersion.v1 && targetVersion <= MachSchemaVersion.latest else {
            throw MachGraphError.databaseError(
                code: SQLITE_MISUSE,
                message: "Unsupported target schema version \(targetVersion) (supported 1...\(MachSchemaVersion.latest))"
            )
        }

        return try connection.withExclusiveAccess {
            try ensureMigrationsAuditTable(on: connection)
            var currentVersion = try connection.userSchemaVersion()

            if currentVersion > MachSchemaVersion.latest {
                throw MachGraphError.databaseError(
                    code: SQLITE_SCHEMA,
                    message: "Project database schema v\(currentVersion) is newer than supported v\(MachSchemaVersion.latest)"
                )
            }

            guard currentVersion < targetVersion else {
                try verifySchemaObjects(on: connection, throughVersion: currentVersion)
                return currentVersion
            }

            let pendingSteps = allSteps.filter { $0.version > currentVersion && $0.version <= targetVersion }
            for step in pendingSteps {
                try connection.withTransaction {
                    for ddl in step.statements {
                        try connection.execute(ddl)
                    }
                    try connection.execute(
                        """
                        INSERT INTO schema_migrations (version, title, checksum_hex, applied_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(version) DO UPDATE SET
                            title = excluded.title,
                            checksum_hex = excluded.checksum_hex,
                            applied_at = excluded.applied_at;
                        """,
                        bindings: [
                            .int(step.version),
                            .text(step.title),
                            .text(step.checksumHex),
                            .date(Date())
                        ]
                    )
                    try connection.setUserSchemaVersion(step.version)
                    currentVersion = step.version
                }
            }

            try verifySchemaObjects(on: connection, throughVersion: currentVersion)
            return currentVersion
        }
    }

    public static func verifySchemaObjects(
        on connection: MachSQLiteWALConnection,
        throughVersion version: Int = MachSchemaVersion.latest
    ) throws {
        let applicable = allSteps.filter { $0.version <= version }
        for step in applicable {
            for table in step.expectedTables {
                guard try connection.tableExists(table) else {
                    throw MachGraphError.databaseError(
                        code: SQLITE_SCHEMA,
                        message: "Schema verification failed for v\(step.version): missing table '\(table)'"
                    )
                }
            }
            for index in step.expectedIndexes {
                guard try connection.indexExists(index) else {
                    throw MachGraphError.databaseError(
                        code: SQLITE_SCHEMA,
                        message: "Schema verification failed for v\(step.version): missing index '\(index)'"
                    )
                }
            }
        }
    }

    public static func appliedMigrations(on connection: MachSQLiteWALConnection) throws -> [MachSchemaMigrationRecord] {
        guard try connection.tableExists("schema_migrations") else { return [] }
        let rows = try connection.query(
            "SELECT version, title, checksum_hex, applied_at FROM schema_migrations ORDER BY version ASC;"
        )
        return rows.map { row in
            MachSchemaMigrationRecord(
                version: row.int(0),
                title: row.string(1),
                checksumHex: row.string(2),
                appliedAt: row.date(3)
            )
        }
    }
}
