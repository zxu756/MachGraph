import Foundation
import CryptoKit

// MARK: - VirtualAddress & FileOffset

public struct VirtualAddress: Sendable, Codable, Hashable, Comparable, ExpressibleByIntegerLiteral, CustomStringConvertible {
    public let rawValue: UInt64

    public init(_ rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public init(integerLiteral value: UInt64) {
        self.rawValue = value
    }

    public init?(hexOrDecimal string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "_", with: "")
        if trimmed.lowercased().hasPrefix("0x") {
            let digits = String(trimmed.dropFirst(2))
            guard let parsed = UInt64(digits, radix: 16) else { return nil }
            self.rawValue = parsed
        } else if let parsedDec = UInt64(trimmed, radix: 10) {
            self.rawValue = parsedDec
        } else if let parsedHex = UInt64(trimmed, radix: 16) {
            self.rawValue = parsedHex
        } else {
            return nil
        }
    }

    public static let zero = VirtualAddress(0)

    public var hexString: String {
        String(format: "0x%016llx", rawValue)
    }

    public var compactHexString: String {
        if rawValue <= 0xFFFF_FFFF {
            return String(format: "0x%08llx", rawValue)
        }
        return String(format: "0x%llx", rawValue)
    }

    public var description: String {
        compactHexString
    }

    public func adding(_ delta: Int64) -> VirtualAddress {
        if delta >= 0 {
            return VirtualAddress(rawValue &+ UInt64(bitPattern: delta))
        } else {
            let mag = UInt64(bitPattern: -delta)
            return VirtualAddress(rawValue &- mag)
        }
    }

    public func adding(_ delta: UInt64) -> VirtualAddress {
        VirtualAddress(rawValue &+ delta)
    }

    public func alignedDown(to alignment: UInt64) -> VirtualAddress {
        guard alignment > 1 else { return self }
        return VirtualAddress(rawValue & ~(alignment - 1))
    }

    public func alignedUp(to alignment: UInt64) -> VirtualAddress {
        guard alignment > 1 else { return self }
        let mask = alignment - 1
        return VirtualAddress((rawValue &+ mask) & ~mask)
    }

    public func page4KBase() -> VirtualAddress {
        VirtualAddress(rawValue & ~0xFFF)
    }

    public static func < (lhs: VirtualAddress, rhs: VirtualAddress) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public static func + (lhs: VirtualAddress, rhs: UInt64) -> VirtualAddress {
        VirtualAddress(lhs.rawValue &+ rhs)
    }

    public static func - (lhs: VirtualAddress, rhs: UInt64) -> VirtualAddress {
        VirtualAddress(lhs.rawValue &- rhs)
    }

    public static func - (lhs: VirtualAddress, rhs: VirtualAddress) -> Int64 {
        Int64(bitPattern: lhs.rawValue &- rhs.rawValue)
    }
}

public struct FileOffset: Sendable, Codable, Hashable, Comparable, ExpressibleByIntegerLiteral, CustomStringConvertible {
    public let rawValue: UInt64

    public init(_ rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public init(integerLiteral value: UInt64) {
        self.rawValue = value
    }

    public static let zero = FileOffset(0)

    public var hexString: String {
        String(format: "0x%08llx", rawValue)
    }

    public var description: String {
        hexString
    }

    public func adding(_ delta: UInt64) -> FileOffset {
        FileOffset(rawValue &+ delta)
    }

    public static func < (lhs: FileOffset, rhs: FileOffset) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public struct AddressRange: Sendable, Codable, Hashable {
    public let start: VirtualAddress
    public let size: UInt64

    public init(start: VirtualAddress, size: UInt64) {
        self.start = start
        self.size = size
    }

    public var end: VirtualAddress {
        start.adding(size)
    }

    public func contains(_ address: VirtualAddress) -> Bool {
        address.rawValue >= start.rawValue && address.rawValue < (start.rawValue &+ size)
    }

    public func overlaps(_ other: AddressRange) -> Bool {
        guard size > 0 && other.size > 0 else { return false }
        return start.rawValue < other.end.rawValue && other.start.rawValue < end.rawValue
    }
}

// MARK: - Geometry Bridges (Framework-Independent)

public struct CGPointBridge: Sendable, Codable, Hashable {
    public var x: Double
    public var y: Double

    public init(x: Double, y: Double) {
        self.x = x
        self.y = y
    }
}

public struct CGRectBridge: Sendable, Codable, Hashable {
    public var x: Double
    public var y: Double
    public var width: Double
    public var height: Double

    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x
        self.y = y
        self.width = width
        self.height = height
    }

    public var minX: Double { x }
    public var minY: Double { y }
    public var maxX: Double { x + width }
    public var maxY: Double { y + height }
    public var midX: Double { x + width * 0.5 }
    public var midY: Double { y + height * 0.5 }
}

// MARK: - Errors

public enum MachGraphError: Error, LocalizedError, Sendable, Equatable {
    case fileNotFound(String)
    case ioFailure(String)
    case unexpectedEOF(offset: UInt64, requested: Int, available: Int)
    case invalidMagic(expected: String, actualHex: String)
    case unsupportedContainer(String)
    case unsupportedArchitecture(String)
    case malformedLoadCommand(index: Int, detail: String)
    case malformedHeader(String)
    case invalidFixupChain(String)
    case decoderError(address: VirtualAddress, detail: String)
    case assemblerError(line: Int, instruction: String, reason: String)
    case assemblerUnsupported(mnemonic: String, form: String)
    case cfgAnalysisError(String)
    case decompilerError(String)
    case patchBoundsError(offset: UInt64, length: Int, fileSize: Int)
    case patchFormatError(String)
    case codeSignError(String)
    case databaseError(code: Int32, message: String)
    case pluginSandboxError(pluginID: String, message: String)
    case invalidCLIArguments(String)

    public var errorDescription: String? {
        localizedMessage(in: MachLanguage.resolve())
    }

    public func localizedMessage(in language: MachLanguage) -> String {
        switch self {
        case .fileNotFound(let path):
            return language.select(
                "Binary or project file not found: \(path)",
                "找不到二进制文件或工程文件: \(path)"
            )
        case .ioFailure(let msg):
            return language.select(
                "I/O failure: \(msg)",
                "文件读写失败: \(msg)"
            )
        case .unexpectedEOF(let offset, let requested, let available):
            return language.select(
                "Unexpected EOF / truncated binary at offset 0x\(String(offset, radix: 16)) (requested \(requested) bytes, available \(available))",
                "文件意外结束或已被截断，偏移 0x\(String(offset, radix: 16))（需要 \(requested) 字节，仅剩 \(available) 字节）"
            )
        case .invalidMagic(let expected, let actualHex):
            return language.select(
                "Unsupported or invalid file magic (expected \(expected), got \(actualHex))",
                "不支持或无效的文件魔数（期望 \(expected)，实际为 \(actualHex)）"
            )
        case .unsupportedContainer(let msg):
            let zhDetail: String
            if msg.contains("ET_REL") {
                zhDetail = "不支持 ELF64 可重定位目标文件 (ET_REL)；请传入可执行文件 (ET_EXEC) 或共享库 (ET_DYN)。"
            } else {
                zhDetail = msg
            }
            return language.select(
                "Unsupported binary container: \(msg)",
                "不支持的二进制容器格式: \(zhDetail)"
            )
        case .unsupportedArchitecture(let msg):
            return language.select(
                "Unsupported CPU architecture: \(msg)",
                "不支持的处理器架构: \(msg)"
            )
        case .malformedLoadCommand(let idx, let detail):
            return language.select(
                "Malformed load command #\(idx): \(detail)",
                "损坏的加载命令 #\(idx): \(detail)"
            )
        case .malformedHeader(let detail):
            return language.select(
                "Malformed binary header: \(detail)",
                "损坏的二进制文件头: \(detail)"
            )
        case .invalidFixupChain(let detail):
            return language.select(
                "Invalid dyld chained fixup: \(detail)",
                "无效的 dyld 链式修正记录: \(detail)"
            )
        case .decoderError(let addr, let detail):
            return language.select(
                "Instruction decode error at \(addr.compactHexString): \(detail)",
                "指令解码错误（地址 \(addr.compactHexString)）: \(detail)"
            )
        case .assemblerError(let line, let insn, let reason):
            return language.select(
                "Inline assembler error on line \(line) ('\(insn)'): \(reason)",
                "汇编错误（第 \(line) 行 '\(insn)'）: \(reason)"
            )
        case .assemblerUnsupported(let mnemonic, let form):
            return language.select(
                "Valid A64 instruction syntax '\(form)' (mnemonic '\(mnemonic)') is not yet supported by the MachGraph assembler.",
                "这是合法的 A64 写法 '\(form)'（助记符 '\(mnemonic)'），但 MachGraph 的汇编器还不支持。"
            )
        case .cfgAnalysisError(let msg):
            return language.select(
                "Analysis / target lookup error: \(msg)",
                "静态分析或目标查找失败: \(msg)"
            )
        case .decompilerError(let msg):
            return language.select(
                "Decompiler error: \(msg)",
                "反编译器错误: \(msg)"
            )
        case .patchBoundsError(let offset, let length, let fileSize):
            return language.select(
                "Patch out of bounds at 0x\(String(offset, radix: 16))+\(length) (binary size \(fileSize))",
                "补丁越界 0x\(String(offset, radix: 16))+\(length)（文件大小 \(fileSize)）"
            )
        case .patchFormatError(let msg):
            return language.select(
                "Patch container format error: \(msg)",
                "补丁容器格式错误: \(msg)"
            )
        case .codeSignError(let msg):
            return language.select(
                "Mach-O code signature error: \(msg)",
                "Mach-O 代码签名错误: \(msg)"
            )
        case .databaseError(let code, let msg):
            return language.select(
                "SQLite store error (\(code)): \(msg)",
                "SQLite 存储错误 (\(code)): \(msg)"
            )
        case .pluginSandboxError(let id, let msg):
            return language.select(
                "Plugin '\(id)' sandbox error: \(msg)",
                "插件 '\(id)' 沙箱错误: \(msg)"
            )
        case .invalidCLIArguments(let msg):
            return language.select(
                "Invalid CLI usage: \(msg)",
                "命令行参数用法错误: \(msg)"
            )
        }
    }
}

// MARK: - Binary Endianness & Safe Zero-Copy Slice Reader

public enum BinaryEndianness: String, Sendable, Codable, Hashable {
    case little
    case big
}

public struct BinarySliceReader: Sendable {
    public let data: Data
    public let sliceStart: Int
    public let sliceEnd: Int
    public var endianness: BinaryEndianness
    public private(set) var cursor: Int

    public init(data: Data, endianness: BinaryEndianness = .little) {
        self.data = data
        self.sliceStart = data.startIndex
        self.sliceEnd = data.endIndex
        self.endianness = endianness
        self.cursor = data.startIndex
    }

    public init(data: Data, offset: Int, length: Int, endianness: BinaryEndianness = .little) throws {
        let base = data.startIndex
        guard offset >= 0, length >= 0, base + offset <= data.endIndex else {
            throw MachGraphError.unexpectedEOF(
                offset: UInt64(max(0, offset)),
                requested: length,
                available: max(0, data.count - max(0, offset))
            )
        }
        let end = base + offset + length
        guard end <= data.endIndex else {
            throw MachGraphError.unexpectedEOF(
                offset: UInt64(offset),
                requested: length,
                available: data.endIndex - (base + offset)
            )
        }
        self.data = data
        self.sliceStart = base + offset
        self.sliceEnd = end
        self.endianness = endianness
        self.cursor = base + offset
    }

    public var count: Int { sliceEnd - sliceStart }
    public var position: Int { cursor - sliceStart }
    public var remaining: Int { sliceEnd - cursor }
    public var isAtEnd: Bool { cursor >= sliceEnd }

    public mutating func seek(to relativeOffset: Int) throws {
        guard relativeOffset >= 0, sliceStart + relativeOffset <= sliceEnd else {
            throw MachGraphError.unexpectedEOF(
                offset: UInt64(max(0, relativeOffset)),
                requested: 0,
                available: count
            )
        }
        cursor = sliceStart + relativeOffset
    }

    public mutating func skip(_ byteCount: Int) throws {
        try seek(to: position + byteCount)
    }

    public mutating func align(to alignment: Int) throws {
        guard alignment > 1 else { return }
        let rem = position % alignment
        if rem != 0 {
            try skip(alignment - rem)
        }
    }

    public func subreader(offset: Int, length: Int, endianness: BinaryEndianness? = nil) throws -> BinarySliceReader {
        guard offset >= 0, length >= 0, offset + length <= count else {
            throw MachGraphError.unexpectedEOF(
                offset: UInt64(max(0, offset)),
                requested: length,
                available: max(0, count - max(0, offset))
            )
        }
        return try BinarySliceReader(
            data: data,
            offset: (sliceStart - data.startIndex) + offset,
            length: length,
            endianness: endianness ?? self.endianness
        )
    }

    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: 1, available: remaining)
        }
        let b = data[cursor]
        cursor += 1
        return b
    }

    public mutating func readInt8() throws -> Int8 {
        Int8(bitPattern: try readUInt8())
    }

    public mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: 2, available: remaining)
        }
        let b0 = UInt16(data[cursor])
        let b1 = UInt16(data[cursor + 1])
        cursor += 2
        switch endianness {
        case .little: return b0 | (b1 << 8)
        case .big: return (b0 << 8) | b1
        }
    }

    public mutating func readInt16() throws -> Int16 {
        Int16(bitPattern: try readUInt16())
    }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: 4, available: remaining)
        }
        let b0 = UInt32(data[cursor])
        let b1 = UInt32(data[cursor + 1])
        let b2 = UInt32(data[cursor + 2])
        let b3 = UInt32(data[cursor + 3])
        cursor += 4
        switch endianness {
        case .little:
            return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        case .big:
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }
    }

    public mutating func readInt32() throws -> Int32 {
        Int32(bitPattern: try readUInt32())
    }

    public mutating func readUInt64() throws -> UInt64 {
        guard remaining >= 8 else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: 8, available: remaining)
        }
        var result: UInt64 = 0
        switch endianness {
        case .little:
            for i in 0..<8 {
                result |= UInt64(data[cursor + i]) << UInt64(i * 8)
            }
        case .big:
            for i in 0..<8 {
                result = (result << 8) | UInt64(data[cursor + i])
            }
        }
        cursor += 8
        return result
    }

    public mutating func readInt64() throws -> Int64 {
        Int64(bitPattern: try readUInt64())
    }

    public mutating func readBytes(_ byteCount: Int) throws -> [UInt8] {
        guard byteCount >= 0, remaining >= byteCount else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: byteCount, available: remaining)
        }
        let slice = Array(data[cursor..<(cursor + byteCount)])
        cursor += byteCount
        return slice
    }

    public mutating func readData(_ byteCount: Int) throws -> Data {
        guard byteCount >= 0, remaining >= byteCount else {
            throw MachGraphError.unexpectedEOF(offset: UInt64(position), requested: byteCount, available: remaining)
        }
        let d = Data(data[cursor..<(cursor + byteCount)])
        cursor += byteCount
        return d
    }

    public mutating func readFixedASCII(_ length: Int) throws -> String {
        let bytes = try readBytes(length)
        let trimmed = bytes.prefix { $0 != 0 }
        return String(decoding: trimmed, as: UTF8.self)
    }

    public mutating func readNullTerminatedUTF8(maxBytes: Int = 16_384) throws -> String {
        var bytes: [UInt8] = []
        var scanned = 0
        while cursor < sliceEnd && scanned < maxBytes {
            let b = data[cursor]
            cursor += 1
            scanned += 1
            if b == 0 {
                break
            }
            bytes.append(b)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    public func peekNullTerminatedUTF8(at relativeOffset: Int, maxBytes: Int = 16_384) -> String? {
        guard relativeOffset >= 0, sliceStart + relativeOffset <= sliceEnd else { return nil }
        var idx = sliceStart + relativeOffset
        var bytes: [UInt8] = []
        var scanned = 0
        while idx < sliceEnd && scanned < maxBytes {
            let b = data[idx]
            idx += 1
            scanned += 1
            if b == 0 { break }
            bytes.append(b)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    public mutating func readULEB128() throws -> UInt64 {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            let byte = try readUInt8()
            if shift >= 64 && (byte & 0x7F) > 1 {
                throw MachGraphError.malformedHeader("ULEB128 overflow past 64 bits")
            }
            value |= UInt64(byte & 0x7F) << min(shift, 63)
            if (byte & 0x80) == 0 {
                break
            }
            shift += 7
            if shift > 70 {
                throw MachGraphError.malformedHeader("Unterminated ULEB128 sequence")
            }
        }
        return value
    }

    public mutating func readSLEB128() throws -> Int64 {
        var result: Int64 = 0
        var shift: Int = 0
        var byte: UInt8 = 0
        repeat {
            byte = try readUInt8()
            if shift < 64 {
                result |= Int64(byte & 0x7F) << shift
            }
            shift += 7
            if shift > 70 {
                throw MachGraphError.malformedHeader("Unterminated SLEB128 sequence")
            }
        } while (byte & 0x80) != 0

        if shift < 64 && (byte & 0x40) != 0 {
            result |= (~0 << shift)
        }
        return result
    }
}

// MARK: - Binary Buffer Writer & Hashing Utilities

public struct BinaryBufferWriter: Sendable {
    public private(set) var bytes: [UInt8] = []
    public var endianness: BinaryEndianness

    public init(capacity: Int = 256, endianness: BinaryEndianness = .little) {
        self.endianness = endianness
        self.bytes.reserveCapacity(capacity)
    }

    public var count: Int { bytes.count }
    public var data: Data { Data(bytes) }

    public mutating func appendUInt8(_ value: UInt8) {
        bytes.append(value)
    }

    public mutating func appendUInt16(_ value: UInt16) {
        switch endianness {
        case .little:
            bytes.append(UInt8(truncatingIfNeeded: value))
            bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        case .big:
            bytes.append(UInt8(truncatingIfNeeded: value >> 8))
            bytes.append(UInt8(truncatingIfNeeded: value))
        }
    }

    public mutating func appendUInt32(_ value: UInt32) {
        switch endianness {
        case .little:
            for shift in stride(from: 0, to: 32, by: 8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        case .big:
            for shift in stride(from: 24, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        }
    }

    public mutating func appendUInt64(_ value: UInt64) {
        switch endianness {
        case .little:
            for shift in stride(from: 0, to: 64, by: 8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        case .big:
            for shift in stride(from: 56, through: 0, by: -8) {
                bytes.append(UInt8(truncatingIfNeeded: value >> shift))
            }
        }
    }

    public mutating func appendBytes(_ slice: [UInt8]) {
        bytes.append(contentsOf: slice)
    }

    public mutating func appendData(_ data: Data) {
        bytes.append(contentsOf: data)
    }

    public mutating func appendFixedASCII(_ text: String, length: Int) {
        let utf8 = Array(text.utf8.prefix(length))
        bytes.append(contentsOf: utf8)
        if utf8.count < length {
            bytes.append(contentsOf: repeatElement(0, count: length - utf8.count))
        }
    }

    public mutating func appendCString(_ text: String) {
        bytes.append(contentsOf: text.utf8)
        bytes.append(0)
    }

    public mutating func appendULEB128(_ value: UInt64) {
        var v = value
        repeat {
            var byte = UInt8(v & 0x7F)
            v >>= 7
            if v != 0 {
                byte |= 0x80
            }
            bytes.append(byte)
        } while v != 0
    }

    public mutating func appendSLEB128(_ value: Int64) {
        var v = value
        var more = true
        while more {
            var byte = UInt8(truncatingIfNeeded: v & 0x7F)
            v >>= 7
            let signBitSet = (byte & 0x40) != 0
            if (v == 0 && !signBitSet) || (v == -1 && signBitSet) {
                more = false
            } else {
                byte |= 0x80
            }
            bytes.append(byte)
        }
    }

    public mutating func padToAlignment(_ alignment: Int, filler: UInt8 = 0) {
        guard alignment > 1 else { return }
        let rem = bytes.count % alignment
        if rem != 0 {
            bytes.append(contentsOf: repeatElement(filler, count: alignment - rem))
        }
    }
}

public enum BinaryHashAndEntropy {
    public static func sha256Hex(of data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256Bytes(of data: Data) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    public static func crc32(of bytes: ArraySlice<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for b in bytes {
            crc ^= UInt32(b)
            for _ in 0..<8 {
                let mask = (crc & 1) != 0 ? UInt32(0xEDB8_8320) : 0
                crc = (crc >> 1) ^ mask
            }
        }
        return ~crc
    }

    public static func shannonEntropy(of bytes: ArraySlice<UInt8>) -> Double {
        let n = bytes.count
        guard n > 0 else { return 0.0 }
        var histogram = [Int](repeating: 0, count: 256)
        for b in bytes {
            histogram[Int(b)] &+= 1
        }
        let invN = 1.0 / Double(n)
        var entropy = 0.0
        for count in histogram where count > 0 {
            let p = Double(count) * invN
            entropy -= p * (Foundation.log2(p))
        }
        return max(0.0, min(8.0, entropy))
    }

    public static func shannonEntropy(of data: Data) -> Double {
        shannonEntropy(of: Array(data)[...])
    }
}
