import Foundation
import MachGraphModels

// MARK: - CoW Dirty Extent & Viewport Models

/// A sorted, non-overlapping contiguous byte span in the Copy-on-Write overlay whose bytes override `baseData`.
public struct CoWDirtyExtent: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { startOffset }
    public let startOffset: UInt64
    public let bytes: [UInt8]
    public let contributingPatchIDs: [UUID]

    public init(
        startOffset: UInt64,
        bytes: [UInt8],
        contributingPatchIDs: [UUID] = []
    ) {
        self.startOffset = startOffset
        self.bytes = bytes
        self.contributingPatchIDs = contributingPatchIDs
    }

    public var byteCount: Int { bytes.count }
    public var endOffset: UInt64 { startOffset &+ UInt64(bytes.count) }
    public var fileOffset: FileOffset { FileOffset(startOffset) }
    public var range: Range<UInt64> { startOffset..<endOffset }

    @inline(__always)
    public func contains(_ rawOffset: UInt64) -> Bool {
        rawOffset >= startOffset && rawOffset < endOffset
    }

    @inline(__always)
    public func overlaps(start: UInt64, length: Int) -> Bool {
        guard length > 0 && !bytes.isEmpty else { return false }
        let queryEnd = start &+ UInt64(length)
        return start < endOffset && startOffset < queryEnd
    }

    @inline(__always)
    public func byte(at rawOffset: UInt64) -> UInt8 {
        bytes[Int(rawOffset &- startOffset)]
    }
}

/// Virtualized viewport window for smooth 120 Hz scrolling over multi-hundred-megabyte binaries.
public struct HexViewportWindow: Sendable, Codable, Hashable {
    public let totalFileBytes: UInt64
    public let bytesPerRow: Int
    public let totalRowCount: Int
    public let firstRenderedRowIndex: Int
    public let visibleStartRowIndex: Int
    public let visibleRowCount: Int
    public let rows: [HexRowSlice]

    public init(
        totalFileBytes: UInt64,
        bytesPerRow: Int,
        totalRowCount: Int,
        firstRenderedRowIndex: Int,
        visibleStartRowIndex: Int,
        visibleRowCount: Int,
        rows: [HexRowSlice]
    ) {
        self.totalFileBytes = totalFileBytes
        self.bytesPerRow = bytesPerRow
        self.totalRowCount = totalRowCount
        self.firstRenderedRowIndex = firstRenderedRowIndex
        self.visibleStartRowIndex = visibleStartRowIndex
        self.visibleRowCount = visibleRowCount
        self.rows = rows
    }
}

// MARK: - Search Encodings, Wildcard Patterns & Hit Models

public enum HexStringSearchEncoding: String, Sendable, Codable, Hashable, CaseIterable {
    case ascii = "ASCII"
    case utf8 = "UTF-8"
    case utf16LE = "UTF-16LE"
    case utf16BE = "UTF-16BE"
}

/// Compiled byte + bitmask wildcard pattern supporting IDA/x64dbg/ImHex syntax (`48 8B ?? ?? E8`, `FD 7B ?F A9`).
public struct HexWildcardPattern: Sendable, Codable, Hashable {
    public let sourcePattern: String
    public let patternBytes: [UInt8]
    public let maskBytes: [UInt8]
    public let exactAnchorIndex: Int?
    public let horspoolSkipTable: [Int]

    public init(patternBytes: [UInt8], maskBytes: [UInt8], sourcePattern: String = "") throws {
        guard !patternBytes.isEmpty, patternBytes.count == maskBytes.count else {
            throw MachGraphError.patchFormatError("Wildcard byte pattern and mask must be non-empty and equal length")
        }

        var normalizedBytes = patternBytes
        for i in 0..<normalizedBytes.count {
            normalizedBytes[i] &= maskBytes[i]
        }

        self.sourcePattern = sourcePattern.isEmpty
            ? Self.renderCanonicalPattern(bytes: normalizedBytes, masks: maskBytes)
            : sourcePattern
        self.patternBytes = normalizedBytes
        self.maskBytes = maskBytes

        // Select the rightmost exact byte (mask == 0xFF) as a Boyer-Moore-Horspool skip anchor if available.
        var chosenAnchor: Int?
        for idx in stride(from: maskBytes.count - 1, through: 0, by: -1) {
            if maskBytes[idx] == 0xFF {
                chosenAnchor = idx
                break
            }
        }
        self.exactAnchorIndex = chosenAnchor

        if let anchor = chosenAnchor, anchor > 0 {
            var table = [Int](repeating: anchor + 1, count: 256)
            for idx in 0..<anchor {
                let m = maskBytes[idx]
                let p = normalizedBytes[idx]
                if m == 0xFF {
                    table[Int(p)] = anchor - idx
                } else {
                    // Wildcard or partial-nibble mask at position `idx` can match multiple byte values;
                    // cap their skip distance so no valid alignment is ever skipped.
                    let candidateShift = anchor - idx
                    for byteVal in 0..<256 where (UInt8(byteVal) & m) == p {
                        if candidateShift < table[byteVal] {
                            table[byteVal] = candidateShift
                        }
                    }
                }
            }
            self.horspoolSkipTable = table
        } else {
            self.horspoolSkipTable = []
        }
    }

    public var count: Int { patternBytes.count }

    /// Parses hex wildcard strings such as `"48 8B ?? ?? E8"`, `"1F 20 03 D5"`, `"FD 7B ?F A9"`, or `"0xD5, 0x03, ??, 0x1F"`.
    public static func parse(_ rawPattern: String) throws -> HexWildcardPattern {
        let cleaned = rawPattern
            .replacingOccurrences(of: ",", with: " ")
            .replacingOccurrences(of: ";", with: " ")
            .replacingOccurrences(of: "_", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard !cleaned.isEmpty else {
            throw MachGraphError.patchFormatError("Hex search pattern cannot be empty")
        }

        let rawTokens = cleaned.split(whereSeparator: \.isWhitespace).map(String.init)
        var bytes: [UInt8] = []
        var masks: [UInt8] = []
        bytes.reserveCapacity(rawTokens.count)
        masks.reserveCapacity(rawTokens.count)

        for rawToken in rawTokens {
            var token = rawToken
            if token.lowercased().hasPrefix("0x") && token.count > 2 {
                token = String(token.dropFirst(2))
            }
            if token.hasPrefix("\\x") && token.count > 2 {
                token = String(token.dropFirst(2))
            }

            if token == "?" || token == "*" {
                bytes.append(0x00)
                masks.append(0x00)
                continue
            }

            guard token.count >= 2 && token.count % 2 == 0 else {
                throw MachGraphError.patchFormatError(
                    "Invalid hex pattern token '\(rawToken)' (expected pairs of hex digits or '?')"
                )
            }

            let chars = Array(token)
            var idx = 0
            while idx + 1 < chars.count {
                let hi = try parseNibble(chars[idx], context: rawToken)
                let lo = try parseNibble(chars[idx + 1], context: rawToken)
                let b = (hi.value << 4) | lo.value
                let m = (hi.mask << 4) | lo.mask
                bytes.append(b & m)
                masks.append(m)
                idx += 2
            }
        }

        return try HexWildcardPattern(patternBytes: bytes, maskBytes: masks, sourcePattern: rawPattern)
    }

    /// Builds a 4-byte little-endian ARM64 opcode/mask pattern (e.g. matching `BL` calls via `value=0x94000000, mask=0xFC000000`).
    public static func arm64InstructionMask(opcodeValue: UInt32, opcodeMask: UInt32) throws -> HexWildcardPattern {
        let p: [UInt8] = [
            UInt8(truncatingIfNeeded: opcodeValue),
            UInt8(truncatingIfNeeded: opcodeValue >> 8),
            UInt8(truncatingIfNeeded: opcodeValue >> 16),
            UInt8(truncatingIfNeeded: opcodeValue >> 24)
        ]
        let m: [UInt8] = [
            UInt8(truncatingIfNeeded: opcodeMask),
            UInt8(truncatingIfNeeded: opcodeMask >> 8),
            UInt8(truncatingIfNeeded: opcodeMask >> 16),
            UInt8(truncatingIfNeeded: opcodeMask >> 24)
        ]
        return try HexWildcardPattern(
            patternBytes: p,
            maskBytes: m,
            sourcePattern: String(format: "ARM64(val=0x%08X, mask=0x%08X)", opcodeValue, opcodeMask)
        )
    }

    @inline(__always)
    public func matches(in buffer: UnsafeBufferPointer<UInt8>, at startIndex: Int) -> Bool {
        let len = patternBytes.count
        guard startIndex >= 0 && startIndex + len <= buffer.count else { return false }
        for i in 0..<len {
            if (buffer[startIndex + i] & maskBytes[i]) != patternBytes[i] {
                return false
            }
        }
        return true
    }

    private static func parseNibble(_ ch: Character, context: String) throws -> (value: UInt8, mask: UInt8) {
        if ch == "?" || ch == "." || ch == "*" {
            return (0x00, 0x00)
        }
        guard let hexVal = ch.hexDigitValue else {
            throw MachGraphError.patchFormatError("Invalid hex nibble '\(ch)' in token '\(context)'")
        }
        return (UInt8(hexVal & 0xF), 0x0F)
    }

    private static func renderCanonicalPattern(bytes: [UInt8], masks: [UInt8]) -> String {
        zip(bytes, masks).map { b, m -> String in
            if m == 0x00 { return "??" }
            if m == 0xFF { return String(format: "%02X", b) }
            let hi = (m & 0xF0) == 0xF0 ? String(format: "%X", (b >> 4) & 0xF) : "?"
            let lo = (m & 0x0F) == 0x0F ? String(format: "%X", b & 0xF) : "?"
            return hi + lo
        }.joined(separator: " ")
    }
}

public struct BinarySearchHit: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { fileOffset.rawValue }
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let matchedBytes: [UInt8]
    public let containsModifiedBytes: Bool
    public let sectionName: String?
    public let contextPreviewHex: String
    public let asciiPreview: String

    public init(
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        matchedBytes: [UInt8],
        containsModifiedBytes: Bool = false,
        sectionName: String? = nil,
        contextPreviewHex: String? = nil
    ) {
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.matchedBytes = matchedBytes
        self.containsModifiedBytes = containsModifiedBytes
        self.sectionName = sectionName
        self.contextPreviewHex = contextPreviewHex ?? matchedBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
        self.asciiPreview = String(matchedBytes.map { b -> Character in
            (b >= 0x20 && b <= 0x7E) ? Character(UnicodeScalar(b)) : "."
        })
    }

    public var length: Int { matchedBytes.count }
}

public struct PatchedBinaryExportSummary: Sendable, Codable, Hashable {
    public let destinationPath: String
    public let totalBytesWritten: UInt64
    public let appliedPatchCount: Int
    public let dirtyExtentCount: Int
    public let modifiedByteCount: Int
    public let sha256Hex: String

    public init(
        destinationPath: String,
        totalBytesWritten: UInt64,
        appliedPatchCount: Int,
        dirtyExtentCount: Int,
        modifiedByteCount: Int,
        sha256Hex: String
    ) {
        self.destinationPath = destinationPath
        self.totalBytesWritten = totalBytesWritten
        self.appliedPatchCount = appliedPatchCount
        self.dirtyExtentCount = dirtyExtentCount
        self.modifiedByteCount = modifiedByteCount
        self.sha256Hex = sha256Hex
    }
}

// MARK: - Sparse Copy-on-Write Byte Overlay Buffer

/// Non-destructive Copy-on-Write binary overlay engine backed by immutable `baseData`,
/// an ordered `[BytePatchRecord]` mutation stack, and coalesced non-overlapping `[CoWDirtyExtent]` spans
/// providing $O(\log P)$ random byte/slice reads, virtualized 16-byte `HexRowSlice` windowing,
/// masked wildcard/string/pointer search, and single-pass materialized `Data` export.
public struct SparseCoWByteOverlayBuffer: Sendable {
    public let baseData: Data
    public private(set) var patches: [BytePatchRecord]
    public private(set) var dirtyExtents: [CoWDirtyExtent]
    public private(set) var modifiedByteCount: Int

    // MARK: - Initialization

    public init(baseData: Data, patches: [BytePatchRecord] = []) throws {
        self.baseData = baseData
        self.patches = []
        self.dirtyExtents = []
        self.modifiedByteCount = 0

        if !patches.isEmpty {
            for patch in patches {
                try validatePatchBounds(patch)
            }
            self.patches = patches
            rebuildDirtyExtents()
        }
    }

    public init(baseData: Data, image: LoadedBinaryImage, patches: [BytePatchRecord] = []) throws {
        if image.fileSize > 0 && UInt64(baseData.count) < image.sliceFileOffset.rawValue {
            throw MachGraphError.patchBoundsError(
                offset: image.sliceFileOffset.rawValue,
                length: 1,
                fileSize: baseData.count
            )
        }
        try self.init(baseData: baseData, patches: patches)
    }

    // MARK: - Metrics & Properties

    public var count: Int { baseData.count }
    public var fileSize: UInt64 { UInt64(baseData.count) }
    public var isEmpty: Bool { baseData.isEmpty }

    public var enabledPatchCount: Int {
        patches.reduce(0) { $0 + ($1.isEnabled ? 1 : 0) }
    }

    public var hasUnsavedModifications: Bool {
        modifiedByteCount > 0
    }

    // MARK: - O(log P) Binary Search Helpers on Coalesced Dirty Extents

    /// Returns the index of the unique `CoWDirtyExtent` containing `rawOffset` in $O(\log P)$ time, or `nil`.
    @inline(__always)
    public func dirtyExtentIndex(containing rawOffset: UInt64) -> Int? {
        var low = 0
        var high = dirtyExtents.count - 1
        while low <= high {
            let mid = (low + high) >> 1
            let ext = dirtyExtents[mid]
            if rawOffset < ext.startOffset {
                high = mid - 1
            } else if rawOffset >= ext.endOffset {
                low = mid + 1
            } else {
                return mid
            }
        }
        return nil
    }

    /// Returns the first `dirtyExtents` index whose `endOffset > queryStart` in $O(\log P)$ time.
    @inline(__always)
    private func firstOverlappingExtentIndex(forStart queryStart: UInt64) -> Int {
        var low = 0
        var high = dirtyExtents.count
        while low < high {
            let mid = (low + high) >> 1
            if dirtyExtents[mid].endOffset <= queryStart {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    public func dirtyExtent(containing offset: FileOffset) -> CoWDirtyExtent? {
        guard let idx = dirtyExtentIndex(containing: offset.rawValue) else { return nil }
        return dirtyExtents[idx]
    }

    // MARK: - O(log P) Byte & Slice Reads

    @inline(__always)
    public func readBaseByte(at offset: FileOffset) throws -> UInt8 {
        try readBaseByte(at: offset.rawValue)
    }

    @inline(__always)
    public func readBaseByte(at rawOffset: UInt64) throws -> UInt8 {
        guard rawOffset < UInt64(baseData.count) else {
            throw MachGraphError.patchBoundsError(offset: rawOffset, length: 1, fileSize: baseData.count)
        }
        return baseData[baseData.startIndex + Int(rawOffset)]
    }

    @inline(__always)
    public func readByte(at offset: FileOffset) throws -> UInt8 {
        try readByte(at: offset.rawValue)
    }

    @inline(__always)
    public func readByte(at rawOffset: UInt64) throws -> UInt8 {
        guard rawOffset < UInt64(baseData.count) else {
            throw MachGraphError.patchBoundsError(offset: rawOffset, length: 1, fileSize: baseData.count)
        }
        if let extIdx = dirtyExtentIndex(containing: rawOffset) {
            return dirtyExtents[extIdx].byte(at: rawOffset)
        }
        return baseData[baseData.startIndex + Int(rawOffset)]
    }

    /// Reads `count` overlaid bytes starting at `offset` in $O(\log P + \text{count})$ time without copying untouched file regions.
    public func readBytes(offset: FileOffset, count: Int) throws -> [UInt8] {
        try readBytes(offset: offset.rawValue, count: count)
    }

    public func readBytes(offset rawOffset: UInt64, count: Int) throws -> [UInt8] {
        guard count >= 0 else {
            throw MachGraphError.patchBoundsError(offset: rawOffset, length: count, fileSize: baseData.count)
        }
        if count == 0 {
            guard rawOffset <= UInt64(baseData.count) else {
                throw MachGraphError.patchBoundsError(offset: rawOffset, length: 0, fileSize: baseData.count)
            }
            return []
        }
        guard rawOffset <= UInt64(baseData.count),
              UInt64(count) <= UInt64(baseData.count) - rawOffset else {
            throw MachGraphError.patchBoundsError(offset: rawOffset, length: count, fileSize: baseData.count)
        }

        let startInt = baseData.startIndex + Int(rawOffset)
        var buffer = Array(baseData[startInt..<(startInt + count)])

        guard !dirtyExtents.isEmpty else { return buffer }

        let queryEnd = rawOffset &+ UInt64(count)
        var extIdx = firstOverlappingExtentIndex(forStart: rawOffset)
        while extIdx < dirtyExtents.count {
            let ext = dirtyExtents[extIdx]
            if ext.startOffset >= queryEnd {
                break
            }
            let overlapStart = max(rawOffset, ext.startOffset)
            let overlapEnd = min(queryEnd, ext.endOffset)
            let overlapLen = Int(overlapEnd &- overlapStart)
            if overlapLen > 0 {
                let dstBase = Int(overlapStart &- rawOffset)
                let srcBase = Int(overlapStart &- ext.startOffset)
                for i in 0..<overlapLen {
                    buffer[dstBase + i] = ext.bytes[srcBase + i]
                }
            }
            extIdx += 1
        }

        return buffer
    }

    public func readBaseBytes(offset: FileOffset, count: Int) throws -> [UInt8] {
        guard count >= 0,
              offset.rawValue <= UInt64(baseData.count),
              UInt64(count) <= UInt64(baseData.count) - offset.rawValue else {
            throw MachGraphError.patchBoundsError(offset: offset.rawValue, length: count, fileSize: baseData.count)
        }
        if count == 0 { return [] }
        let start = baseData.startIndex + Int(offset.rawValue)
        return Array(baseData[start..<(start + count)])
    }

    public func readData(offset: FileOffset, count: Int) throws -> Data {
        Data(try readBytes(offset: offset, count: count))
    }

    public func readSliceReader(
        offset: FileOffset,
        length: Int,
        endianness: BinaryEndianness = .little
    ) throws -> BinarySliceReader {
        let overlaid = try readData(offset: offset, count: length)
        return BinarySliceReader(data: overlaid, endianness: endianness)
    }

    public func readBytes(
        at virtualAddress: VirtualAddress,
        count: Int,
        in image: LoadedBinaryImage
    ) throws -> [UInt8] {
        guard let fileOff = image.fileOffset(for: virtualAddress) else {
            throw MachGraphError.decoderError(
                address: virtualAddress,
                detail: "Virtual address \(virtualAddress.compactHexString) is not backed by a file segment"
            )
        }
        return try readBytes(offset: fileOff, count: count)
    }

    public func readUInt16(at offset: FileOffset, endianness: BinaryEndianness = .little) throws -> UInt16 {
        let b = try readBytes(offset: offset, count: 2)
        switch endianness {
        case .little: return UInt16(b[0]) | (UInt16(b[1]) << 8)
        case .big:    return (UInt16(b[0]) << 8) | UInt16(b[1])
        }
    }

    public func readUInt32(at offset: FileOffset, endianness: BinaryEndianness = .little) throws -> UInt32 {
        let b = try readBytes(offset: offset, count: 4)
        switch endianness {
        case .little:
            return UInt32(b[0]) | (UInt32(b[1]) << 8) | (UInt32(b[2]) << 16) | (UInt32(b[3]) << 24)
        case .big:
            return (UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
        }
    }

    public func readUInt64(at offset: FileOffset, endianness: BinaryEndianness = .little) throws -> UInt64 {
        let b = try readBytes(offset: offset, count: 8)
        var acc: UInt64 = 0
        switch endianness {
        case .little:
            for i in 0..<8 { acc |= UInt64(b[i]) << UInt64(i * 8) }
        case .big:
            for i in 0..<8 { acc = (acc << 8) | UInt64(b[i]) }
        }
        return acc
    }

    // MARK: - O(log P) Modification Inspection & Navigation

    /// Checks whether the byte at `offset` currently differs from `baseData` in $O(\log P)$ time.
    @inline(__always)
    public func isByteModified(at offset: FileOffset) -> Bool {
        isByteModified(at: offset.rawValue)
    }

    @inline(__always)
    public func isByteModified(at rawOffset: UInt64) -> Bool {
        guard rawOffset < UInt64(baseData.count),
              let extIdx = dirtyExtentIndex(containing: rawOffset) else {
            return false
        }
        let patchedByte = dirtyExtents[extIdx].byte(at: rawOffset)
        let originalByte = baseData[baseData.startIndex + Int(rawOffset)]
        return patchedByte != originalByte
    }

    public func modifiedMask(offset: FileOffset, count: Int) -> [Bool] {
        guard count > 0, offset.rawValue < UInt64(baseData.count) else { return [] }
        let clampedCount = min(count, Int(UInt64(baseData.count) - offset.rawValue))
        var mask = [Bool](repeating: false, count: clampedCount)
        guard !dirtyExtents.isEmpty else { return mask }

        let rawStart = offset.rawValue
        let rawEnd = rawStart &+ UInt64(clampedCount)
        var extIdx = firstOverlappingExtentIndex(forStart: rawStart)
        let baseStart = baseData.startIndex

        while extIdx < dirtyExtents.count {
            let ext = dirtyExtents[extIdx]
            if ext.startOffset >= rawEnd { break }
            let overlapStart = max(rawStart, ext.startOffset)
            let overlapEnd = min(rawEnd, ext.endOffset)
            var pos = overlapStart
            while pos < overlapEnd {
                let overlayByte = ext.byte(at: pos)
                let origByte = baseData[baseStart + Int(pos)]
                if overlayByte != origByte {
                    mask[Int(pos &- rawStart)] = true
                }
                pos &+= 1
            }
            extIdx += 1
        }

        return mask
    }

    public func patchesAffecting(offset: FileOffset) -> [BytePatchRecord] {
        let target = offset.rawValue
        return patches.filter { rec in
            guard rec.byteCount > 0 else { return false }
            let start = rec.fileOffset.rawValue
            let end = start &+ UInt64(rec.byteCount)
            return target >= start && target < end
        }
    }

    public func patchesOverlapping(offset: FileOffset, length: Int) -> [BytePatchRecord] {
        guard length > 0 else { return [] }
        let qStart = offset.rawValue
        let qEnd = qStart &+ UInt64(length)
        return patches.filter { rec in
            guard rec.byteCount > 0 else { return false }
            let pStart = rec.fileOffset.rawValue
            let pEnd = pStart &+ UInt64(rec.byteCount)
            return qStart < pEnd && pStart < qEnd
        }
    }

    public func nextModifiedOffset(after offset: FileOffset) -> FileOffset? {
        guard !dirtyExtents.isEmpty else { return nil }
        let candidateStart = offset.rawValue &+ 1
        guard candidateStart < UInt64(baseData.count) else { return nil }

        var extIdx = firstOverlappingExtentIndex(forStart: candidateStart)
        let baseStart = baseData.startIndex
        while extIdx < dirtyExtents.count {
            let ext = dirtyExtents[extIdx]
            var pos = max(candidateStart, ext.startOffset)
            while pos < ext.endOffset {
                if ext.byte(at: pos) != baseData[baseStart + Int(pos)] {
                    return FileOffset(pos)
                }
                pos &+= 1
            }
            extIdx += 1
        }
        return nil
    }

    public func previousModifiedOffset(before offset: FileOffset) -> FileOffset? {
        guard !dirtyExtents.isEmpty, offset.rawValue > 0 else { return nil }
        let maxPos = min(offset.rawValue &- 1, UInt64(baseData.count - 1))
        var extIdx = firstOverlappingExtentIndex(forStart: maxPos)
        if extIdx >= dirtyExtents.count || dirtyExtents[extIdx].startOffset > maxPos {
            extIdx -= 1
        }
        let baseStart = baseData.startIndex
        while extIdx >= 0 {
            let ext = dirtyExtents[extIdx]
            var pos = min(maxPos, ext.endOffset &- 1)
            while true {
                if ext.byte(at: pos) != baseData[baseStart + Int(pos)] {
                    return FileOffset(pos)
                }
                if pos == ext.startOffset { break }
                pos &-= 1
            }
            extIdx -= 1
        }
        return nil
    }

    /// Computes sorted unique page indices within a Mach-O slice whose overlaid bytes differ from `baseData`.
    public func dirtyPageIndices(
        pageSize: Int,
        sliceFileOffset: UInt64 = 0,
        codeLimit: UInt64? = nil
    ) -> [Int] {
        guard pageSize > 0, !dirtyExtents.isEmpty else { return [] }
        let sliceLimitEnd: UInt64
        if let limit = codeLimit {
            sliceLimitEnd = min(UInt64(baseData.count), sliceFileOffset &+ limit)
        } else {
            sliceLimitEnd = UInt64(baseData.count)
        }
        guard sliceFileOffset < sliceLimitEnd else { return [] }

        var pageSet = Set<Int>()
        var extIdx = firstOverlappingExtentIndex(forStart: sliceFileOffset)
        let baseStart = baseData.startIndex
        let pageSize64 = UInt64(pageSize)

        while extIdx < dirtyExtents.count {
            let ext = dirtyExtents[extIdx]
            if ext.startOffset >= sliceLimitEnd { break }
            let overlapStart = max(sliceFileOffset, ext.startOffset)
            let overlapEnd = min(sliceLimitEnd, ext.endOffset)
            var pos = overlapStart
            while pos < overlapEnd {
                if ext.byte(at: pos) != baseData[baseStart + Int(pos)] {
                    let rel = pos &- sliceFileOffset
                    pageSet.insert(Int(rel / pageSize64))
                    // Jump directly to the start of the next page for speed!
                    let nextPageRel = ((rel / pageSize64) &+ 1) * pageSize64
                    let nextPos = sliceFileOffset &+ nextPageRel
                    if nextPos <= pos { break }
                    pos = nextPos
                } else {
                    pos &+= 1
                }
            }
            extIdx += 1
        }

        return pageSet.sorted()
    }

    // MARK: - Patch Stack Mutations & CoW Dirty Extent Maintenance

    public mutating func applyPatch(_ patch: BytePatchRecord) throws {
        try validatePatchBounds(patch)
        if let existingIdx = patches.firstIndex(where: { $0.id == patch.id }) {
            patches[existingIdx] = patch
        } else {
            patches.append(patch)
        }
        rebuildDirtyExtents()
    }

    public mutating func applyPatches(_ batch: [BytePatchRecord]) throws {
        for p in batch {
            try validatePatchBounds(p)
        }
        for p in batch {
            if let existingIdx = patches.firstIndex(where: { $0.id == p.id }) {
                patches[existingIdx] = p
            } else {
                patches.append(p)
            }
        }
        rebuildDirtyExtents()
    }

    @discardableResult
    public mutating func writeBytes(
        _ newBytes: [UInt8],
        at offset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        originalAssembly: String? = nil,
        patchedAssembly: String? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard !newBytes.isEmpty else {
            throw MachGraphError.patchFormatError("Cannot create zero-length BytePatchRecord")
        }
        let origBytes = try readBytes(offset: offset, count: newBytes.count)
        let record = BytePatchRecord(
            fileOffset: offset,
            virtualAddress: virtualAddress,
            originalBytes: origBytes,
            patchedBytes: newBytes,
            originalAssembly: originalAssembly,
            patchedAssembly: patchedAssembly,
            note: note,
            isEnabled: true
        )
        try applyPatch(record)
        return record
    }

    @discardableResult
    public mutating func writeBytes(
        _ newBytes: [UInt8],
        at virtualAddress: VirtualAddress,
        in image: LoadedBinaryImage,
        originalAssembly: String? = nil,
        patchedAssembly: String? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard let fileOff = image.fileOffset(for: virtualAddress) else {
            throw MachGraphError.patchBoundsError(
                offset: virtualAddress.rawValue,
                length: newBytes.count,
                fileSize: baseData.count
            )
        }
        return try writeBytes(
            newBytes,
            at: fileOff,
            virtualAddress: virtualAddress,
            originalAssembly: originalAssembly,
            patchedAssembly: patchedAssembly,
            note: note
        )
    }

    @discardableResult
    public mutating func fillBytes(
        at offset: FileOffset,
        count: Int,
        repeating byte: UInt8,
        in image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard count > 0 else {
            throw MachGraphError.patchFormatError("Fill byte count must be positive")
        }
        let va = image?.virtualAddress(for: offset)
        let filled = [UInt8](repeating: byte, count: count)
        let label = note.isEmpty ? String(format: "Fill %d bytes with 0x%02X", count, byte) : note
        return try writeBytes(filled, at: offset, virtualAddress: va, note: label)
    }

    @discardableResult
    public mutating func xorBytes(
        at offset: FileOffset,
        count: Int,
        key: [UInt8],
        in image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard count > 0, !key.isEmpty else {
            throw MachGraphError.patchFormatError("XOR transform requires positive byte count and non-empty key")
        }
        let current = try readBytes(offset: offset, count: count)
        var transformed = [UInt8]()
        transformed.reserveCapacity(count)
        for i in 0..<count {
            transformed.append(current[i] ^ key[i % key.count])
        }
        let va = image?.virtualAddress(for: offset)
        let label = note.isEmpty ? "XOR \(count) bytes" : note
        return try writeBytes(transformed, at: offset, virtualAddress: va, note: label)
    }

    public mutating func setPatchEnabled(id: UUID, isEnabled: Bool) throws {
        guard let idx = patches.firstIndex(where: { $0.id == id }) else {
            throw MachGraphError.patchFormatError("Patch \(id.uuidString) not found in overlay stack")
        }
        if patches[idx].isEnabled != isEnabled {
            patches[idx].isEnabled = isEnabled
            rebuildDirtyExtents()
        }
    }

    @discardableResult
    public mutating func togglePatch(id: UUID) throws -> Bool {
        guard let idx = patches.firstIndex(where: { $0.id == id }) else {
            throw MachGraphError.patchFormatError("Patch \(id.uuidString) not found in overlay stack")
        }
        patches[idx].isEnabled.toggle()
        rebuildDirtyExtents()
        return patches[idx].isEnabled
    }

    public mutating func updatePatchNote(id: UUID, note: String) throws {
        guard let idx = patches.firstIndex(where: { $0.id == id }) else {
            throw MachGraphError.patchFormatError("Patch \(id.uuidString) not found in overlay stack")
        }
        patches[idx].note = note
    }

    @discardableResult
    public mutating func removePatch(id: UUID) -> BytePatchRecord? {
        guard let idx = patches.firstIndex(where: { $0.id == id }) else {
            return nil
        }
        let removed = patches.remove(at: idx)
        rebuildDirtyExtents()
        return removed
    }

    /// Restores `[offset ..< offset + length)` back to the unmodified `baseData` bytes by appending a restoration patch or pruning contained patches.
    public mutating func revertRange(
        offset: FileOffset,
        length: Int,
        in image: LoadedBinaryImage? = nil
    ) throws {
        guard length > 0 else { return }
        let baseBytes = try readBaseBytes(offset: offset, count: length)
        let rStart = offset.rawValue
        let rEnd = rStart &+ UInt64(length)

        // Remove any patches completely enclosed inside the reverted window cleanly.
        patches.removeAll { rec in
            let pStart = rec.fileOffset.rawValue
            let pEnd = pStart &+ UInt64(rec.byteCount)
            return pStart >= rStart && pEnd <= rEnd
        }
        rebuildDirtyExtents()

        // If a larger straddling patch still modifies bytes inside [rStart, rEnd), write baseBytes over that subrange.
        if modifiedMask(offset: offset, count: length).contains(true) {
            let currentBytes = try readBytes(offset: offset, count: length)
            let restoreRecord = BytePatchRecord(
                fileOffset: offset,
                virtualAddress: image?.virtualAddress(for: offset),
                originalBytes: currentBytes,
                patchedBytes: baseBytes,
                note: "Revert \(length) bytes to original image",
                isEnabled: true
            )
            patches.append(restoreRecord)
            rebuildDirtyExtents()
        }
    }

    public mutating func removeAllPatches() {
        patches.removeAll()
        dirtyExtents.removeAll()
        modifiedByteCount = 0
    }

    /// Produces minimal canonical non-overlapping `[BytePatchRecord]` diffs comparing the active overlay directly against `baseData`.
    public func coalescedMinimalPatches(in image: LoadedBinaryImage? = nil) -> [BytePatchRecord] {
        guard !dirtyExtents.isEmpty else { return [] }
        let baseStart = baseData.startIndex
        var output: [BytePatchRecord] = []
        output.reserveCapacity(dirtyExtents.count)

        for ext in dirtyExtents {
            var idx = 0
            let len = ext.bytes.count
            while idx < len {
                let absPos = ext.startOffset &+ UInt64(idx)
                if ext.bytes[idx] == baseData[baseStart + Int(absPos)] {
                    idx += 1
                    continue
                }
                let runStartIdx = idx
                while idx < len {
                    let checkPos = ext.startOffset &+ UInt64(idx)
                    if ext.bytes[idx] == baseData[baseStart + Int(checkPos)] {
                        break
                    }
                    idx += 1
                }
                let runOff = FileOffset(ext.startOffset &+ UInt64(runStartIdx))
                let runLen = idx - runStartIdx
                let origSlice = Array(baseData[(baseStart + Int(runOff.rawValue))..<(baseStart + Int(runOff.rawValue) + runLen)])
                let patchedSlice = Array(ext.bytes[runStartIdx..<idx])
                output.append(
                    BytePatchRecord(
                        fileOffset: runOff,
                        virtualAddress: image?.virtualAddress(for: runOff),
                        originalBytes: origSlice,
                        patchedBytes: patchedSlice,
                        note: "Coalesced overlay diff (\(runLen) bytes)",
                        isEnabled: true
                    )
                )
            }
        }
        return output
    }

    /// Creates an `AnalystTransactionRecord` wrapping a patch mutation for SQLite `.machproj` undo/redo stacks.
    public static func makeTransactionRecord(
        sequenceNumber: Int64 = 0,
        title: String,
        previous: BytePatchRecord?,
        updated: BytePatchRecord?
    ) -> AnalystTransactionRecord {
        AnalystTransactionRecord(
            sequenceNumber: sequenceNumber,
            title: title,
            operation: .setPatch(previous: previous, updated: updated)
        )
    }

    // MARK: - Internal Bounds Validation & Extent Tree Compaction

    private func validatePatchBounds(_ patch: BytePatchRecord) throws {
        let off = patch.fileOffset.rawValue
        let len = patch.patchedBytes.count
        guard len >= 0,
              off <= UInt64(baseData.count),
              UInt64(len) <= UInt64(baseData.count) - off else {
            throw MachGraphError.patchBoundsError(offset: off, length: len, fileSize: baseData.count)
        }
    }

    /// Compiles the ordered stack of enabled `BytePatchRecord` values into sorted, disjoint, coalesced `[CoWDirtyExtent]` spans.
    private mutating func rebuildDirtyExtents() {
        let active = patches.filter { $0.isEnabled && !$0.patchedBytes.isEmpty }
        guard !active.isEmpty else {
            dirtyExtents = []
            modifiedByteCount = 0
            return
        }

        // Collect all interval endpoints so overlapping patches are resolved in exact chronological order without full-file allocation.
        var boundaries: [UInt64] = []
        boundaries.reserveCapacity(active.count * 2)
        for p in active {
            let s = p.fileOffset.rawValue
            let e = s &+ UInt64(p.patchedBytes.count)
            boundaries.append(s)
            boundaries.append(e)
        }
        boundaries.sort()

        // Deduplicate sorted boundary points in-place
        var uniqueBoundaries: [UInt64] = []
        uniqueBoundaries.reserveCapacity(boundaries.count)
        for pt in boundaries {
            if uniqueBoundaries.last != pt {
                uniqueBoundaries.append(pt)
            }
        }

        guard uniqueBoundaries.count >= 2 else {
            dirtyExtents = []
            modifiedByteCount = 0
            return
        }

        // Build elementary intervals [b_i, b_{i+1}) covered by at least one active patch (last-writer-wins).
        struct ElementarySpan {
            var start: UInt64
            var bytes: [UInt8]
            var patchIDs: [UUID]
        }

        var elementary: [ElementarySpan] = []
        elementary.reserveCapacity(uniqueBoundaries.count - 1)
        let baseStart = baseData.startIndex

        for i in 0..<(uniqueBoundaries.count - 1) {
            let segStart = uniqueBoundaries[i]
            let segEnd = uniqueBoundaries[i + 1]
            let segLen = Int(segEnd &- segStart)
            guard segLen > 0 else { continue }

            // Find all active patches covering [segStart, segEnd); since endpoints come from every patch,
            // any patch overlapping [segStart, segEnd) covers it completely!
            var coveringIndices: [Int] = []
            for (pIdx, p) in active.enumerated() {
                let pStart = p.fileOffset.rawValue
                let pEnd = pStart &+ UInt64(p.patchedBytes.count)
                if pStart <= segStart && pEnd >= segEnd {
                    coveringIndices.append(pIdx)
                }
            }
            guard let winningIdx = coveringIndices.last else { continue }

            let winner = active[winningIdx]
            let relStart = Int(segStart &- winner.fileOffset.rawValue)
            let segBytes = Array(winner.patchedBytes[relStart..<(relStart + segLen)])

            // Trim away elementary spans that strictly match baseData everywhere so reverting via patch leaves zero phantom dirty extents.
            var hasDiff = false
            for k in 0..<segLen {
                if segBytes[k] != baseData[baseStart + Int(segStart) + k] {
                    hasDiff = true
                    break
                }
            }
            guard hasDiff else { continue }

            let ids = coveringIndices.map { active[$0].id }
            elementary.append(ElementarySpan(start: segStart, bytes: segBytes, patchIDs: ids))
        }

        guard !elementary.isEmpty else {
            dirtyExtents = []
            modifiedByteCount = 0
            return
        }

        // Coalesce adjacent elementary spans into maximal contiguous non-overlapping CoWDirtyExtents.
        var merged: [CoWDirtyExtent] = []
        merged.reserveCapacity(elementary.count)

        var curStart = elementary[0].start
        var curBytes = elementary[0].bytes
        var curIDs = elementary[0].patchIDs

        for span in elementary.dropFirst() {
            let curEnd = curStart &+ UInt64(curBytes.count)
            if span.start == curEnd {
                curBytes.append(contentsOf: span.bytes)
                for id in span.patchIDs where !curIDs.contains(id) {
                    curIDs.append(id)
                }
            } else {
                merged.append(
                    CoWDirtyExtent(startOffset: curStart, bytes: curBytes, contributingPatchIDs: curIDs)
                )
                curStart = span.start
                curBytes = span.bytes
                curIDs = span.patchIDs
            }
        }
        merged.append(CoWDirtyExtent(startOffset: curStart, bytes: curBytes, contributingPatchIDs: curIDs))

        // Count exact modified bytes across merged extents.
        var diffTotal = 0
        for ext in merged {
            let extBase = baseStart + Int(ext.startOffset)
            for i in 0..<ext.bytes.count {
                if ext.bytes[i] != baseData[extBase + i] {
                    diffTotal += 1
                }
            }
        }

        self.dirtyExtents = merged
        self.modifiedByteCount = diffTotal
    }

    // MARK: - Virtualized 16-Byte HexRowSlice Windowing

    /// Materializes a virtualized window of `HexRowSlice` rows starting at `startOffset`, mapping file offsets to `VirtualAddress` via `LoadedBinaryImage`.
    public func hexRows(
        startOffset: FileOffset,
        rowCount: Int,
        bytesPerRow: Int = 16,
        image: LoadedBinaryImage? = nil
    ) -> [HexRowSlice] {
        let strideBytes = max(1, bytesPerRow)
        guard rowCount > 0, startOffset.rawValue < UInt64(baseData.count) else {
            return []
        }

        let maxAvailableBytes = UInt64(baseData.count) - startOffset.rawValue
        let requestedWindowBytes = UInt64(rowCount) * UInt64(strideBytes)
        let fetchByteCount = Int(min(maxAvailableBytes, requestedWindowBytes))
        guard fetchByteCount > 0,
              let windowBytes = try? readBytes(offset: startOffset, count: fetchByteCount) else {
            return []
        }

        let windowMask = modifiedMask(offset: startOffset, count: fetchByteCount)
        let actualRows = (fetchByteCount + strideBytes - 1) / strideBytes
        var slices: [HexRowSlice] = []
        slices.reserveCapacity(actualRows)

        let translator = FastOffsetAddressTranslator(image: image)

        for rowIdx in 0..<actualRows {
            let relStart = rowIdx * strideBytes
            let relEnd = min(relStart + strideBytes, fetchByteCount)
            let rowOff = startOffset.adding(UInt64(relStart))
            let rowVA = translator.virtualAddress(for: rowOff)
            let rowBytes = Array(windowBytes[relStart..<relEnd])
            let rowModMask = Array(windowMask[relStart..<relEnd])

            slices.append(
                HexRowSlice(
                    fileOffset: rowOff,
                    virtualAddress: rowVA,
                    bytes: rowBytes,
                    modifiedMask: rowModMask
                )
            )
        }

        return slices
    }

    /// Convenience 3-argument signature matching standard 16-byte hex virtualization (`hexRows(startOffset:rowCount:image:)`).
    public func hexRows(
        startOffset: FileOffset,
        rowCount: Int,
        image: LoadedBinaryImage?
    ) -> [HexRowSlice] {
        hexRows(startOffset: startOffset, rowCount: rowCount, bytesPerRow: 16, image: image)
    }

    /// Centers or starts a virtualized `HexRowSlice` window at `virtualAddress` using `image` segment/section mappings.
    public func hexRows(
        aroundAddress virtualAddress: VirtualAddress,
        rowCount: Int,
        leadingContextRows: Int = 0,
        bytesPerRow: Int = 16,
        in image: LoadedBinaryImage
    ) -> [HexRowSlice] {
        guard let targetOffset = image.fileOffset(for: virtualAddress) else {
            return []
        }
        let stride64 = UInt64(max(1, bytesPerRow))
        let alignedRowOffset = (targetOffset.rawValue / stride64) * stride64
        let backBytes = UInt64(max(0, leadingContextRows)) * stride64
        let startRaw = alignedRowOffset >= backBytes ? (alignedRowOffset - backBytes) : 0
        return hexRows(
            startOffset: FileOffset(startRaw),
            rowCount: rowCount,
            bytesPerRow: bytesPerRow,
            image: image
        )
    }

    /// Computes a complete `HexViewportWindow` with overscan buffering for smooth UI scroll views.
    public func hexViewportWindow(
        scrollOffset: FileOffset,
        visibleRowCount: Int,
        overscanRows: Int = 8,
        bytesPerRow: Int = 16,
        image: LoadedBinaryImage? = nil
    ) -> HexViewportWindow {
        let bpr = max(1, bytesPerRow)
        let totalRows = (baseData.count + bpr - 1) / bpr
        guard totalRows > 0 && visibleRowCount > 0 else {
            return HexViewportWindow(
                totalFileBytes: fileSize,
                bytesPerRow: bpr,
                totalRowCount: totalRows,
                firstRenderedRowIndex: 0,
                visibleStartRowIndex: 0,
                visibleRowCount: 0,
                rows: []
            )
        }

        let clampedScrollRow = min(max(0, Int(scrollOffset.rawValue / UInt64(bpr))), max(0, totalRows - 1))
        let firstRow = max(0, clampedScrollRow - max(0, overscanRows))
        let lastRowExclusive = min(totalRows, clampedScrollRow + visibleRowCount + max(0, overscanRows))
        let renderCount = max(0, lastRowExclusive - firstRow)
        let firstOffset = FileOffset(UInt64(firstRow) * UInt64(bpr))

        let rendered = hexRows(
            startOffset: firstOffset,
            rowCount: renderCount,
            bytesPerRow: bpr,
            image: image
        )

        return HexViewportWindow(
            totalFileBytes: fileSize,
            bytesPerRow: bpr,
            totalRowCount: totalRows,
            firstRenderedRowIndex: firstRow,
            visibleStartRowIndex: clampedScrollRow,
            visibleRowCount: min(visibleRowCount, totalRows - clampedScrollRow),
            rows: rendered
        )
    }

    /// Renders a classic textual hex + ASCII dump (`xxd`-free pure Swift) marking patched bytes with `*` when `annotateModified` is enabled.
    public func formatHexDump(
        startOffset: FileOffset,
        byteCount: Int,
        bytesPerRow: Int = 16,
        image: LoadedBinaryImage? = nil,
        annotateModified: Bool = true
    ) -> String {
        let bpr = max(1, bytesPerRow)
        let rowCount = (max(0, byteCount) + bpr - 1) / bpr
        let rows = hexRows(startOffset: startOffset, rowCount: rowCount, bytesPerRow: bpr, image: image)
        guard !rows.isEmpty else { return "" }

        var lines: [String] = []
        lines.reserveCapacity(rows.count)
        var remaining = byteCount

        for row in rows where remaining > 0 {
            let take = min(remaining, row.bytes.count)
            remaining -= take

            let addrPrefix: String
            if let va = row.virtualAddress {
                addrPrefix = "\(row.fileOffset.hexString) (\(va.compactHexString))"
            } else {
                addrPrefix = row.fileOffset.hexString
            }

            var hexTokens: [String] = []
            hexTokens.reserveCapacity(bpr)
            for idx in 0..<bpr {
                if idx < take {
                    let byteHex = String(format: "%02x", row.bytes[idx])
                    if annotateModified && idx < row.modifiedMask.count && row.modifiedMask[idx] {
                        hexTokens.append("\(byteHex)*")
                    } else {
                        hexTokens.append(annotateModified ? "\(byteHex) " : byteHex)
                    }
                } else {
                    hexTokens.append(annotateModified ? "   " : "  ")
                }
            }

            let asciiSub = String(row.asciiColumn.prefix(take))
            lines.append("\(addrPrefix):  \(hexTokens.joined(separator: " "))  |\(asciiSub)|")
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Chunked CoW Search Engine (Wildcard Mask, ARM64 Mask, Strings & Pointers)

    /// Searches the CoW overlay for a wildcard byte pattern (e.g. `"48 8B ?? ?? E8"` or `"FD 7B ?F A9"`).
    public func searchPattern(
        _ patternString: String,
        in searchRange: Range<UInt64>? = nil,
        alignment: Int = 1,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) throws -> [BinarySearchHit] {
        let compiled = try HexWildcardPattern.parse(patternString)
        return searchCompiledPattern(
            compiled,
            in: searchRange,
            alignment: alignment,
            maxResults: maxResults,
            image: image
        )
    }

    /// Searches the CoW overlay using explicit `pattern` and `mask` byte arrays.
    public func searchMaskedBytes(
        pattern: [UInt8],
        mask: [UInt8],
        in searchRange: Range<UInt64>? = nil,
        alignment: Int = 1,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) throws -> [BinarySearchHit] {
        let compiled = try HexWildcardPattern(patternBytes: pattern, maskBytes: mask)
        return searchCompiledPattern(
            compiled,
            in: searchRange,
            alignment: alignment,
            maxResults: maxResults,
            image: image
        )
    }

    /// Executes a chunk-streamed Boyer-Moore-Horspool / masked scan across `baseData` + `dirtyExtents` without copying the full binary.
    public func searchCompiledPattern(
        _ compiled: HexWildcardPattern,
        in searchRange: Range<UInt64>? = nil,
        alignment: Int = 1,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) -> [BinarySearchHit] {
        let patLen = compiled.count
        guard patLen > 0, maxResults > 0, baseData.count >= patLen else { return [] }

        let effectiveStart = min(searchRange?.lowerBound ?? 0, UInt64(baseData.count))
        let effectiveEnd = min(searchRange?.upperBound ?? UInt64(baseData.count), UInt64(baseData.count))
        guard effectiveEnd >= effectiveStart,
              (effectiveEnd - effectiveStart) >= UInt64(patLen) else {
            return []
        }

        let stepAlign = max(1, alignment)
        let chunkCapacity = max(65_536, patLen * 16)
        let overlapBytes = patLen - 1

        let translator = FastOffsetAddressTranslator(image: image)
        var results: [BinarySearchHit] = []

        var chunkStart = effectiveStart
        while chunkStart + UInt64(patLen) <= effectiveEnd && results.count < maxResults {
            let remainingInWindow = Int(min(UInt64(chunkCapacity), effectiveEnd - chunkStart))
            guard let chunkBytes = try? readBytes(offset: chunkStart, count: remainingInWindow) else {
                break
            }

            let limitPos = remainingInWindow - patLen
            chunkBytes.withUnsafeBufferPointer { buf in
                if stepAlign == 1, let anchor = compiled.exactAnchorIndex, anchor > 0, !compiled.horspoolSkipTable.isEmpty {
                    let skipTable = compiled.horspoolSkipTable
                    let anchorByte = compiled.patternBytes[anchor]
                    var idx = 0
                    while idx <= limitPos && results.count < maxResults {
                        let candidateAnchor = buf[idx + anchor]
                        if candidateAnchor == anchorByte && compiled.matches(in: buf, at: idx) {
                            let hitOffset = FileOffset(chunkStart &+ UInt64(idx))
                            results.append(makeSearchHit(at: hitOffset, length: patLen, buffer: buf, localIndex: idx, translator: translator, image: image))
                            idx += 1
                        } else {
                            idx += max(1, skipTable[Int(candidateAnchor)])
                        }
                    }
                } else {
                    // Aligned or pure-wildcard step scan
                    var firstAlignedIdx = 0
                    if stepAlign > 1 {
                        let rem = Int(chunkStart % UInt64(stepAlign))
                        if rem != 0 {
                            firstAlignedIdx = stepAlign - rem
                        }
                    }
                    var idx = firstAlignedIdx
                    while idx <= limitPos && results.count < maxResults {
                        if compiled.matches(in: buf, at: idx) {
                            let hitOffset = FileOffset(chunkStart &+ UInt64(idx))
                            results.append(makeSearchHit(at: hitOffset, length: patLen, buffer: buf, localIndex: idx, translator: translator, image: image))
                        }
                        idx += stepAlign
                    }
                }
            }

            let consumed = remainingInWindow - overlapBytes
            if consumed <= 0 || chunkStart + UInt64(remainingInWindow) >= effectiveEnd {
                break
            }
            chunkStart &+= UInt64(consumed)
        }

        return results
    }

    /// Searches 4-byte aligned ARM64 instructions matching `(word & opcodeMask) == (opcodeValue & opcodeMask)`.
    public func searchARM64InstructionMask(
        opcodeValue: UInt32,
        opcodeMask: UInt32,
        in image: LoadedBinaryImage,
        executableOnly: Bool = true,
        maxResults: Int = 10_000
    ) -> [BinarySearchHit] {
        guard let pattern = try? HexWildcardPattern.arm64InstructionMask(opcodeValue: opcodeValue, opcodeMask: opcodeMask) else {
            return []
        }

        if !executableOnly {
            return searchCompiledPattern(pattern, in: nil, alignment: 4, maxResults: maxResults, image: image)
        }

        var hits: [BinarySearchHit] = []
        for sec in image.executableSections() where sec.kind != .bss && sec.size >= 4 {
            let secStart = image.sliceFileOffset.rawValue &+ sec.fileOffset.rawValue
            let secEnd = min(UInt64(baseData.count), secStart &+ sec.size)
            guard secEnd >= secStart + 4 else { continue }

            let remainingQuota = maxResults - hits.count
            if remainingQuota <= 0 { break }

            let secHits = searchCompiledPattern(
                pattern,
                in: secStart..<secEnd,
                alignment: 4,
                maxResults: remainingQuota,
                image: image
            )
            hits.append(contentsOf: secHits)
        }
        return hits
    }

    /// Searches ASCII, UTF-8, UTF-16LE, or UTF-16BE string literals across the CoW overlay (with optional ASCII case-insensitivity).
    public func searchString(
        _ query: String,
        encoding: HexStringSearchEncoding = .ascii,
        caseInsensitive: Bool = false,
        in searchRange: Range<UInt64>? = nil,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) -> [BinarySearchHit] {
        guard !query.isEmpty, maxResults > 0 else { return [] }

        if !caseInsensitive {
            let encodedBytes = encodeSearchQuery(query, encoding: encoding)
            guard !encodedBytes.isEmpty,
                  let exactPattern = try? HexWildcardPattern(
                      patternBytes: encodedBytes,
                      maskBytes: [UInt8](repeating: 0xFF, count: encodedBytes.count),
                      sourcePattern: query
                  ) else {
                return []
            }
            return searchCompiledPattern(exactPattern, in: searchRange, alignment: 1, maxResults: maxResults, image: image)
        }

        // Case-insensitive ASCII/UTF-16 folding via bitmask 0xDF on ASCII alphabetic bytes ('A'=0x41, 'a'=0x61 -> diff is 0x20!)
        // Wait: 0xDF alone also matches 0x40/'`' or '['/'{' if non-letter, so verify exact case-folded match!
        let upperBytes = encodeSearchQuery(query.uppercased(), encoding: encoding)
        let lowerBytes = encodeSearchQuery(query.lowercased(), encoding: encoding)
        guard !upperBytes.isEmpty, upperBytes.count == lowerBytes.count else { return [] }

        var maskBytes = [UInt8](repeating: 0xFF, count: upperBytes.count)
        for i in 0..<upperBytes.count where upperBytes[i] != lowerBytes[i] {
            maskBytes[i] = ~(upperBytes[i] ^ lowerBytes[i])
        }

        guard let candidatePattern = try? HexWildcardPattern(
            patternBytes: upperBytes,
            maskBytes: maskBytes,
            sourcePattern: query
        ) else {
            return []
        }

        // Over-fetch candidates slightly and filter exact Unicode case-insensitive match to prevent 0xDF false positives on punctuation.
        let rawCandidates = searchCompiledPattern(
            candidatePattern,
            in: searchRange,
            alignment: 1,
            maxResults: maxResults * 2,
            image: image
        )
        let foldedTarget = query.lowercased()
        var verified: [BinarySearchHit] = []
        verified.reserveCapacity(min(rawCandidates.count, maxResults))

        for hit in rawCandidates {
            if let decoded = decodeMatchedString(hit.matchedBytes, encoding: encoding),
               decoded.lowercased() == foldedTarget {
                verified.append(hit)
                if verified.count >= maxResults { break }
            }
        }
        return verified
    }

    /// Searches for 64-bit virtual address pointers (optionally masking out top 16-bit/PAC metadata bits for `arm64e` raw pointer tables).
    public func searchPointer64(
        target: VirtualAddress,
        endianness: BinaryEndianness = .little,
        alignment: Int = 8,
        maskPACHighBits: Bool = false,
        in searchRange: Range<UInt64>? = nil,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) -> [BinarySearchHit] {
        var writer = BinaryBufferWriter(capacity: 8, endianness: endianness)
        writer.appendUInt64(target.rawValue)
        let pBytes = writer.bytes

        var mBytes = [UInt8](repeating: 0xFF, count: 8)
        if maskPACHighBits {
            // Mask lower 48 bits (or 36 bits on arm64echained) -> preserve low 6 bytes exact
            switch endianness {
            case .little:
                mBytes[6] = 0x00
                mBytes[7] = 0x00
            case .big:
                mBytes[0] = 0x00
                mBytes[1] = 0x00
            }
        }

        guard let compiled = try? HexWildcardPattern(patternBytes: pBytes, maskBytes: mBytes) else {
            return []
        }
        return searchCompiledPattern(
            compiled,
            in: searchRange,
            alignment: max(1, alignment),
            maxResults: maxResults,
            image: image
        )
    }

    /// Searches for 32-bit pointers or relative 32-bit values across the CoW overlay.
    public func searchPointer32(
        target: UInt32,
        endianness: BinaryEndianness = .little,
        alignment: Int = 4,
        in searchRange: Range<UInt64>? = nil,
        maxResults: Int = 10_000,
        image: LoadedBinaryImage? = nil
    ) -> [BinarySearchHit] {
        var writer = BinaryBufferWriter(capacity: 4, endianness: endianness)
        writer.appendUInt32(target)
        guard let compiled = try? HexWildcardPattern(
            patternBytes: writer.bytes,
            maskBytes: [0xFF, 0xFF, 0xFF, 0xFF]
        ) else {
            return []
        }
        return searchCompiledPattern(
            compiled,
            in: searchRange,
            alignment: max(1, alignment),
            maxResults: maxResults,
            image: image
        )
    }

    // MARK: - Materialized Data Export & Disk Persistence

    /// Exports the complete patched binary as a contiguous `Data` value in $O(N + \sum |E_i|)$ time.
    public func materializedData() -> Data {
        guard !dirtyExtents.isEmpty else {
            return baseData
        }
        var out = Data(baseData)
        let outBase = out.startIndex
        for ext in dirtyExtents {
            let dstStart = outBase + Int(ext.startOffset)
            let dstEnd = dstStart + ext.bytes.count
            out.replaceSubrange(dstStart..<dstEnd, with: ext.bytes)
        }
        return out
    }

    /// Materializes a contiguous sub-slice `[offset ..< offset + length)` as `Data`.
    public func materializedSlice(offset: FileOffset, length: Int) throws -> Data {
        if dirtyExtents.isEmpty {
            guard length >= 0,
                  offset.rawValue <= UInt64(baseData.count),
                  UInt64(length) <= UInt64(baseData.count) - offset.rawValue else {
                throw MachGraphError.patchBoundsError(offset: offset.rawValue, length: length, fileSize: baseData.count)
            }
            let start = baseData.startIndex + Int(offset.rawValue)
            return Data(baseData[start..<(start + length)])
        }
        return try readData(offset: offset, count: length)
    }

    /// Atomically writes the materialized patched binary to `destinationURL` and optionally marks POSIX `0o755` executable bits.
    public func exportPatchedBinary(
        to destinationURL: URL,
        setExecutablePermissions: Bool = true
    ) throws -> PatchedBinaryExportSummary {
        let outputData = materializedData()
        do {
            try outputData.write(to: destinationURL, options: [.atomic])
            if setExecutablePermissions {
                try FileManager.default.setAttributes(
                    [.posixPermissions: NSNumber(value: Int16(0o755))],
                    ofItemAtPath: destinationURL.path
                )
            }
        } catch {
            throw MachGraphError.ioFailure("Failed to export patched binary to '\(destinationURL.path)': \(error.localizedDescription)")
        }

        return PatchedBinaryExportSummary(
            destinationPath: destinationURL.path,
            totalBytesWritten: UInt64(outputData.count),
            appliedPatchCount: enabledPatchCount,
            dirtyExtentCount: dirtyExtents.count,
            modifiedByteCount: modifiedByteCount,
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: outputData)
        )
    }

    // MARK: - Private Search & String Helpers

    private func makeSearchHit(
        at offset: FileOffset,
        length: Int,
        buffer: UnsafeBufferPointer<UInt8>,
        localIndex: Int,
        translator: FastOffsetAddressTranslator,
        image: LoadedBinaryImage?
    ) -> BinarySearchHit {
        let matched = Array(buffer[localIndex..<(localIndex + length)])
        let va = translator.virtualAddress(for: offset)
        let secName = va.flatMap { image?.section(containing: $0)?.fullName }
        let isMod = modifiedMask(offset: offset, count: length).contains(true)

        let previewEnd = min(buffer.count, localIndex + min(16, max(length, 8)))
        let previewSlice = buffer[localIndex..<previewEnd]
        let previewHex = previewSlice.map { String(format: "%02x", $0) }.joined(separator: " ")

        return BinarySearchHit(
            fileOffset: offset,
            virtualAddress: va,
            matchedBytes: matched,
            containsModifiedBytes: isMod,
            sectionName: secName,
            contextPreviewHex: previewHex
        )
    }

    private func encodeSearchQuery(_ query: String, encoding: HexStringSearchEncoding) -> [UInt8] {
        switch encoding {
        case .ascii:
            return query.unicodeScalars.compactMap { $0.value <= 0x7F ? UInt8($0.value) : nil }
        case .utf8:
            return Array(query.utf8)
        case .utf16LE:
            var out: [UInt8] = []
            out.reserveCapacity(query.utf16.count * 2)
            for unit in query.utf16 {
                out.append(UInt8(truncatingIfNeeded: unit))
                out.append(UInt8(truncatingIfNeeded: unit >> 8))
            }
            return out
        case .utf16BE:
            var out: [UInt8] = []
            out.reserveCapacity(query.utf16.count * 2)
            for unit in query.utf16 {
                out.append(UInt8(truncatingIfNeeded: unit >> 8))
                out.append(UInt8(truncatingIfNeeded: unit))
            }
            return out
        }
    }

    private func decodeMatchedString(_ bytes: [UInt8], encoding: HexStringSearchEncoding) -> String? {
        switch encoding {
        case .ascii, .utf8:
            return String(bytes: bytes, encoding: .utf8)
        case .utf16LE:
            guard bytes.count % 2 == 0 else { return nil }
            var units: [UInt16] = []
            units.reserveCapacity(bytes.count / 2)
            var i = 0
            while i + 1 < bytes.count {
                units.append(UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8))
                i += 2
            }
            return String(utf16CodeUnits: units, count: units.count)
        case .utf16BE:
            guard bytes.count % 2 == 0 else { return nil }
            var units: [UInt16] = []
            units.reserveCapacity(bytes.count / 2)
            var i = 0
            while i + 1 < bytes.count {
                units.append((UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1]))
                i += 2
            }
            return String(utf16CodeUnits: units, count: units.count)
        }
    }
}

// MARK: - Accelerated FileOffset <-> VirtualAddress Translator

/// Pre-indexes file-backed sections and segments from `LoadedBinaryImage` for $O(\log S)$ offset-to-VA lookups across virtualized hex rows and search hits.
internal struct FastOffsetAddressTranslator: Sendable {
    private struct FileSpanEntry: Sendable {
        let absFileStart: UInt64
        let absFileEnd: UInt64
        let vmBase: VirtualAddress
    }

    private let sectionSpans: [FileSpanEntry]
    private let segmentSpans: [FileSpanEntry]

    init(image: LoadedBinaryImage?) {
        guard let image else {
            self.sectionSpans = []
            self.segmentSpans = []
            return
        }

        let sliceBase = image.sliceFileOffset.rawValue
        var secs: [FileSpanEntry] = []
        secs.reserveCapacity(image.sections.count)
        for sec in image.sections where sec.kind != .bss && sec.size > 0 {
            let s = sliceBase &+ sec.fileOffset.rawValue
            secs.append(FileSpanEntry(absFileStart: s, absFileEnd: s &+ sec.size, vmBase: sec.vmAddress))
        }
        secs.sort { $0.absFileStart < $1.absFileStart }

        var segs: [FileSpanEntry] = []
        segs.reserveCapacity(image.segments.count)
        for seg in image.segments where seg.fileSize > 0 {
            let s = sliceBase &+ seg.fileOffset.rawValue
            segs.append(FileSpanEntry(absFileStart: s, absFileEnd: s &+ seg.fileSize, vmBase: seg.vmAddress))
        }
        segs.sort { $0.absFileStart < $1.absFileStart }

        self.sectionSpans = secs
        self.segmentSpans = segs
    }

    @inline(__always)
    func virtualAddress(for offset: FileOffset) -> VirtualAddress? {
        let raw = offset.rawValue
        if let va = binaryLookup(raw, in: sectionSpans) {
            return va
        }
        return binaryLookup(raw, in: segmentSpans)
    }

    @inline(__always)
    private func binaryLookup(_ raw: UInt64, in spans: [FileSpanEntry]) -> VirtualAddress? {
        var low = 0
        var high = spans.count - 1
        while low <= high {
            let mid = (low + high) >> 1
            let entry = spans[mid]
            if raw < entry.absFileStart {
                high = mid - 1
            } else if raw >= entry.absFileEnd {
                low = mid + 1
            } else {
                return entry.vmBase.adding(raw &- entry.absFileStart)
            }
        }
        return nil
    }
}
