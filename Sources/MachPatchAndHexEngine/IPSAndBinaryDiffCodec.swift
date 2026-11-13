import Foundation
import MachGraphModels
import MachA64Decoder

// MARK: - IPS / IPS32 / BPS Patch Container Models

public enum IPSFormatVariant: String, Sendable, Codable, Hashable, CaseIterable {
    case ips24 = "IPS (24-bit, 16 MiB max)"
    case ips32 = "IPS32 (32-bit, 4 GiB max)"
    case auto = "Auto (IPS / IPS32)"
}

public enum IPSHunkPayload: Sendable, Codable, Hashable {
    case literal([UInt8])
    case rle(repeatCount: Int, fillByte: UInt8)

    public var expandedByteCount: Int {
        switch self {
        case .literal(let bytes): return bytes.count
        case .rle(let count, _): return count
        }
    }

    public func materializeBytes() -> [UInt8] {
        switch self {
        case .literal(let bytes):
            return bytes
        case .rle(let count, let fill):
            return [UInt8](repeating: fill, count: max(0, count))
        }
    }
}

public struct IPSPatchHunk: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(index):\(offset)" }
    public let index: Int
    public let offset: UInt64
    public let payload: IPSHunkPayload

    public init(index: Int, offset: UInt64, payload: IPSHunkPayload) {
        self.index = index
        self.offset = offset
        self.payload = payload
    }

    public var byteLength: Int { payload.expandedByteCount }
    public var isRLE: Bool {
        if case .rle = payload { return true }
        return false
    }
}

public struct IPSParsedPatchContainer: Sendable, Codable, Hashable {
    public let format: IPSFormatVariant
    public let hunks: [IPSPatchHunk]
    public let postEOFTruncationLength: UInt64?

    public init(
        format: IPSFormatVariant,
        hunks: [IPSPatchHunk],
        postEOFTruncationLength: UInt64? = nil
    ) {
        self.format = format
        self.hunks = hunks
        self.postEOFTruncationLength = postEOFTruncationLength
    }

    public var totalPatchedBytes: Int {
        hunks.reduce(0) { $0 + $1.byteLength }
    }
}

// MARK: - Pure-Swift IPS / IPS32 / BPS Codec & Unified Binary Diff Engine

/// Full-featured binary patch codec supporting classic **IPS** (`PATCH`...`EOF`, including RLE hunks & `0x454F46` collision avoidance),
/// **IPS32** (`IPS32`...`EEOF`, 32-bit offsets up to 4 GiB), **BPS** (`BPS1` delta stream with IEEE CRC-32 validation),
/// raw binary-to-binary diffing, and unified annotated hex-diff report generation.
public struct IPSPatchCodec: Sendable {
    private static let ipsMagic: [UInt8] = [0x50, 0x41, 0x54, 0x43, 0x48]    // "PATCH"
    private static let ipsEOF: [UInt8] = [0x45, 0x4F, 0x46]                  // "EOF"
    private static let ipsSentinelCollisionOffset: UInt64 = 0x0045_4F46      // "EOF" as 24-bit BE

    private static let ips32Magic: [UInt8] = [0x49, 0x50, 0x53, 0x33, 0x32]  // "IPS32"
    private static let ips32EEOF: [UInt8] = [0x45, 0x45, 0x4F, 0x46]         // "EEOF"
    private static let ips32SentinelCollisionOffset: UInt64 = 0x4545_4F46    // "EEOF" as 32-bit BE

    private static let bpsMagic: [UInt8] = [0x42, 0x50, 0x53, 0x31]          // "BPS1"
    private static let maxChunkLength = 0xFFFF                               // 65,535 bytes per hunk
    private static let minRLEBeneficialLength = 9                            // 3/4-byte header + 2(0)+2(cnt)+1(val) = 8..9 bytes

    public init() {}

    // MARK: - IPS (24-bit) & IPS32 (32-bit) Encoders

    /// Encodes enabled `BytePatchRecord` items into standard 24-bit `PATCH`...`EOF` IPS format (with automatic RLE hunk compression).
    public func exportIPS(patches: [BytePatchRecord]) -> Data {
        encodeIPSStream(patches: patches, is32Bit: false, baseData: nil, enableRLE: true)
    }

    /// Encodes enabled `BytePatchRecord` items into 32-bit `IPS32`...`EEOF` format supporting offsets up to 4 GiB.
    public func exportIPS32(patches: [BytePatchRecord]) -> Data {
        encodeIPSStream(patches: patches, is32Bit: true, baseData: nil, enableRLE: true)
    }

    /// Checked IPS/IPS32 exporter that validates offset limits (`0xFF_FFFF` for IPS24, `0xFFFF_FFFF` for IPS32)
    /// or auto-selects `IPS32` when any patch exceeds the 16 MiB classic IPS ceiling.
    public func exportIPSChecked(
        patches: [BytePatchRecord],
        format: IPSFormatVariant = .auto,
        baseData: Data? = nil,
        enableRLE: Bool = true
    ) throws -> Data {
        let active = patches.filter { $0.isEnabled && !$0.patchedBytes.isEmpty }
        let maxEndOffset = active.map { $0.fileOffset.rawValue &+ UInt64($0.patchedBytes.count) }.max() ?? 0
        let maxStartOffset = active.map(\.fileOffset.rawValue).max() ?? 0

        let use32Bit: Bool
        switch format {
        case .ips24:
            guard maxStartOffset <= 0x00FF_FFFF && maxEndOffset <= 0x0100_FFFF else {
                throw MachGraphError.patchFormatError(
                    String(format: "Patch offset 0x%llx exceeds 24-bit IPS limit (0xFFFFFF); use IPS32 instead", maxStartOffset)
                )
            }
            use32Bit = false
        case .ips32:
            guard maxStartOffset <= 0xFFFF_FFFF else {
                throw MachGraphError.patchFormatError(
                    String(format: "Patch offset 0x%llx exceeds 32-bit IPS32 limit (0xFFFFFFFF)", maxStartOffset)
                )
            }
            use32Bit = true
        case .auto:
            guard maxStartOffset <= 0xFFFF_FFFF else {
                throw MachGraphError.patchFormatError(
                    String(format: "Patch offset 0x%llx exceeds 32-bit IPS32 limit (0xFFFFFFFF)", maxStartOffset)
                )
            }
            use32Bit = maxStartOffset > 0x00FF_FFFF
        }

        return encodeIPSStream(patches: active, is32Bit: use32Bit, baseData: baseData, enableRLE: enableRLE)
    }

    // MARK: - IPS & IPS32 Parser & Importer

    /// Parses raw hunks from either an `IPS` (`PATCH`...`EOF`) or `IPS32` (`IPS32`...`EEOF`) container.
    public func parseContainer(_ data: Data) throws -> IPSParsedPatchContainer {
        guard data.count >= 8 else {
            throw MachGraphError.patchFormatError("IPS patch stream truncated (< 8 bytes)")
        }

        var reader = BinarySliceReader(data: data, endianness: .big)
        let magicBytes = try reader.readBytes(5)

        let is32Bit: Bool
        if magicBytes == Self.ipsMagic {
            is32Bit = false
        } else if magicBytes == Self.ips32Magic {
            is32Bit = true
        } else {
            let hex = magicBytes.map { String(format: "%02X", $0) }.joined()
            throw MachGraphError.invalidMagic(expected: "PATCH or IPS32", actualHex: "0x\(hex)")
        }

        let offsetWidth = is32Bit ? 4 : 3
        let eofMarker = is32Bit ? Self.ips32EEOF : Self.ipsEOF
        var hunks: [IPSPatchHunk] = []
        var sawEOF = false
        var truncationSize: UInt64?

        while reader.remaining >= offsetWidth {
            let rawOffBytes = try reader.readBytes(offsetWidth)
            if rawOffBytes == eofMarker {
                sawEOF = true
                // Classic IPS optional 3-byte post-EOF ROM truncation extension
                if !is32Bit && reader.remaining == 3 {
                    let tBytes = try reader.readBytes(3)
                    truncationSize = (UInt64(tBytes[0]) << 16) | (UInt64(tBytes[1]) << 8) | UInt64(tBytes[2])
                }
                break
            }

            let offset: UInt64
            if is32Bit {
                offset = (UInt64(rawOffBytes[0]) << 24)
                    | (UInt64(rawOffBytes[1]) << 16)
                    | (UInt64(rawOffBytes[2]) << 8)
                    | UInt64(rawOffBytes[3])
            } else {
                offset = (UInt64(rawOffBytes[0]) << 16)
                    | (UInt64(rawOffBytes[1]) << 8)
                    | UInt64(rawOffBytes[2])
            }

            guard reader.remaining >= 2 else {
                throw MachGraphError.patchFormatError(
                    String(format: "Truncated IPS hunk size field at patch offset 0x%llx", offset)
                )
            }
            let hunkSize = Int(try reader.readUInt16())

            if hunkSize == 0 {
                // RLE Hunk: 16-bit big-endian repeat count + 1 fill byte
                guard reader.remaining >= 3 else {
                    throw MachGraphError.patchFormatError(
                        String(format: "Truncated IPS RLE header at patch offset 0x%llx", offset)
                    )
                }
                let rleCount = Int(try reader.readUInt16())
                let fillByte = try reader.readUInt8()
                guard rleCount > 0 else {
                    throw MachGraphError.patchFormatError(
                        String(format: "Zero-length RLE hunk at patch offset 0x%llx", offset)
                    )
                }
                hunks.append(IPSPatchHunk(index: hunks.count, offset: offset, payload: .rle(repeatCount: rleCount, fillByte: fillByte)))
            } else {
                guard reader.remaining >= hunkSize else {
                    throw MachGraphError.patchFormatError(
                        String(format: "Truncated IPS literal payload at offset 0x%llx (declared %d bytes, remaining %d)", offset, hunkSize, reader.remaining)
                    )
                }
                let literalBytes = try reader.readBytes(hunkSize)
                hunks.append(IPSPatchHunk(index: hunks.count, offset: offset, payload: .literal(literalBytes)))
            }
        }

        guard sawEOF else {
            throw MachGraphError.patchFormatError(
                "Missing terminal \(is32Bit ? "EEOF" : "EOF") sentinel in IPS container"
            )
        }

        return IPSParsedPatchContainer(
            format: is32Bit ? .ips32 : .ips24,
            hunks: hunks,
            postEOFTruncationLength: truncationSize
        )
    }

    /// Decodes an `IPS` (`PATCH`...`EOF`), `IPS32` (`IPS32`...`EEOF`), or `BPS` (`BPS1`) patch file against `baseData` into `[BytePatchRecord]`.
    public func importIPS(_ data: Data, baseData: Data) throws -> [BytePatchRecord] {
        try importIPS(data, baseData: baseData, image: nil, annotateARM64Disassembly: true)
    }

    /// Decodes an `IPS`, `IPS32`, or `BPS1` patch container against `baseData` with optional `LoadedBinaryImage` VA mapping and ARM64 disassembly annotations.
    public func importIPS(
        _ data: Data,
        baseData: Data,
        image: LoadedBinaryImage?,
        annotateARM64Disassembly: Bool = true
    ) throws -> [BytePatchRecord] {
        if data.count >= 4 && Array(data.prefix(4)) == Self.bpsMagic {
            return try importBPS(data, baseData: baseData, image: image, annotateARM64Disassembly: annotateARM64Disassembly)
        }

        let parsed = try parseContainer(data)
        let decoder = A64InstructionDecoder()
        let translator = FastOffsetAddressTranslator(image: image)
        var records: [BytePatchRecord] = []
        records.reserveCapacity(parsed.hunks.count)

        let baseStart = baseData.startIndex
        for hunk in parsed.hunks {
            let newBytes = hunk.payload.materializeBytes()
            let len = newBytes.count
            guard hunk.offset <= UInt64(baseData.count),
                  UInt64(len) <= UInt64(baseData.count) - hunk.offset else {
                throw MachGraphError.patchBoundsError(
                    offset: hunk.offset,
                    length: len,
                    fileSize: baseData.count
                )
            }

            let intOff = baseStart + Int(hunk.offset)
            let origBytes = Array(baseData[intOff..<(intOff + len)])
            let fileOffset = FileOffset(hunk.offset)
            let va = translator.virtualAddress(for: fileOffset)

            var origAsm: String?
            var patchedAsm: String?
            if annotateARM64Disassembly,
               len >= 4,
               len <= 64,
               len % 4 == 0,
               (image == nil || image?.architecture.isARM64Family == true) {
                let disasmBase = va ?? VirtualAddress(hunk.offset)
                if (disasmBase.rawValue & 0x3) == 0 {
                    origAsm = decoder.decodeBuffer(Data(origBytes), baseAddress: disasmBase)
                        .map(\.formattedDisassembly)
                        .joined(separator: "; ")
                    patchedAsm = decoder.decodeBuffer(Data(newBytes), baseAddress: disasmBase)
                        .map(\.formattedDisassembly)
                        .joined(separator: "; ")
                }
            }

            let formatLabel = parsed.format == .ips32 ? "IPS32" : "IPS"
            let kindTag = hunk.isRLE ? "RLE" : "Hunk"
            records.append(
                BytePatchRecord(
                    fileOffset: fileOffset,
                    virtualAddress: va,
                    originalBytes: origBytes,
                    patchedBytes: newBytes,
                    originalAssembly: origAsm,
                    patchedAssembly: patchedAsm,
                    note: "Imported \(formatLabel) \(kindTag) #\(hunk.index) (\(len) bytes)",
                    isEnabled: true
                )
            )
        }

        return records
    }

    // MARK: - Pure-Swift BPS1 (Beat Patching System) Encoder & Decoder

    /// Encodes a binary delta between `original` and `modified` into a CRC32-verified `BPS1` patch stream.
    public func exportBPS(original: Data, modified: Data, metadataUTF8: String = "") -> Data {
        var writer = BinaryBufferWriter(capacity: 256, endianness: .little)
        writer.appendBytes(Self.bpsMagic)
        appendBPSVarInt(&writer, UInt64(original.count))
        appendBPSVarInt(&writer, UInt64(modified.count))

        let metaBytes = Array(metadataUTF8.utf8)
        appendBPSVarInt(&writer, UInt64(metaBytes.count))
        writer.appendBytes(metaBytes)

        let origArr = Array(original)
        let modArr = Array(modified)
        let minCount = min(origArr.count, modArr.count)

        var pos = 0
        while pos < modArr.count {
            if pos < minCount && origArr[pos] == modArr[pos] {
                let runStart = pos
                while pos < minCount && origArr[pos] == modArr[pos] {
                    pos += 1
                }
                let runLen = pos - runStart
                // Action 0: SourceRead (copies unmodified bytes from same offset in `original`)
                appendBPSVarInt(&writer, (UInt64(runLen - 1) << 2) | 0)
            } else {
                let litStart = pos
                while pos < modArr.count {
                    // Break back to SourceRead only if >= 4 identical bytes appear ahead
                    if pos + 4 <= minCount,
                       origArr[pos] == modArr[pos],
                       origArr[pos + 1] == modArr[pos + 1],
                       origArr[pos + 2] == modArr[pos + 2],
                       origArr[pos + 3] == modArr[pos + 3] {
                        break
                    }
                    pos += 1
                }
                let litLen = pos - litStart
                // Action 1: TargetRead (literal modified bytes)
                appendBPSVarInt(&writer, (UInt64(litLen - 1) << 2) | 1)
                writer.appendBytes(Array(modArr[litStart..<pos]))
            }
        }

        let sourceCRC = BinaryHashAndEntropy.crc32(of: origArr[...])
        let targetCRC = BinaryHashAndEntropy.crc32(of: modArr[...])
        writer.appendUInt32(sourceCRC)
        writer.appendUInt32(targetCRC)
        let patchCRC = BinaryHashAndEntropy.crc32(of: writer.bytes[...])
        writer.appendUInt32(patchCRC)

        return writer.data
    }

    /// Decodes a `BPS1` patch container (verifying patch & source IEEE CRC-32 checksums) into `[BytePatchRecord]`.
    public func importBPS(
        _ patchData: Data,
        baseData: Data,
        image: LoadedBinaryImage? = nil,
        annotateARM64Disassembly: Bool = true
    ) throws -> [BytePatchRecord] {
        guard patchData.count >= 16 else {
            throw MachGraphError.patchFormatError("BPS1 container shorter than 16-byte minimum")
        }
        let patchBytes = Array(patchData)
        guard Array(patchBytes.prefix(4)) == Self.bpsMagic else {
            throw MachGraphError.invalidMagic(expected: "BPS1", actualHex: "0x" + patchBytes.prefix(4).map { String(format: "%02X", $0) }.joined())
        }

        let footerOffset = patchBytes.count - 12
        let expectedPatchCRC = readUInt32LE(patchBytes, at: patchBytes.count - 4)
        let computedPatchCRC = BinaryHashAndEntropy.crc32(of: patchBytes[0..<(patchBytes.count - 4)])
        guard expectedPatchCRC == computedPatchCRC else {
            throw MachGraphError.patchFormatError(
                String(format: "BPS1 patch CRC-32 mismatch (expected 0x%08X, got 0x%08X)", expectedPatchCRC, computedPatchCRC)
            )
        }

        let expectedSourceCRC = readUInt32LE(patchBytes, at: footerOffset)
        let expectedTargetCRC = readUInt32LE(patchBytes, at: footerOffset + 4)
        let baseArr = Array(baseData)
        let actualSourceCRC = BinaryHashAndEntropy.crc32(of: baseArr[...])
        guard expectedSourceCRC == actualSourceCRC else {
            throw MachGraphError.patchFormatError(
                String(format: "BPS1 source binary CRC-32 mismatch (expected 0x%08X, got 0x%08X)", expectedSourceCRC, actualSourceCRC)
            )
        }

        var cursor = 4
        let sourceSize = Int(try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset))
        let targetSize = Int(try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset))
        guard sourceSize == baseArr.count else {
            throw MachGraphError.patchFormatError("BPS1 expected source size \(sourceSize), got \(baseArr.count)")
        }
        guard targetSize >= 0 && targetSize <= 512 * 1024 * 1024 else {
            throw MachGraphError.patchFormatError("BPS1 target size (\(targetSize)) exceeds safety limit")
        }

        let metaSize = Int(try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset))
        guard metaSize >= 0 && cursor + metaSize <= footerOffset else {
            throw MachGraphError.patchFormatError("BPS1 metadata overflows stream bounds")
        }
        cursor += metaSize

        var targetBytes: [UInt8] = []
        targetBytes.reserveCapacity(targetSize)
        var sourceRelOffset = 0
        var targetRelOffset = 0

        while cursor < footerOffset {
            let cmd = try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset)
            let action = cmd & 3
            let length = Int((cmd >> 2) + 1)
            guard targetBytes.count + length <= targetSize else {
                throw MachGraphError.patchFormatError("BPS1 action overflows declared target size")
            }

            switch action {
            case 0: // SourceRead
                let outPos = targetBytes.count
                guard outPos + length <= baseArr.count else {
                    throw MachGraphError.patchFormatError("BPS1 SourceRead out of bounds")
                }
                targetBytes.append(contentsOf: baseArr[outPos..<(outPos + length)])

            case 1: // TargetRead
                guard cursor + length <= footerOffset else {
                    throw MachGraphError.patchFormatError("BPS1 TargetRead literal truncated")
                }
                targetBytes.append(contentsOf: patchBytes[cursor..<(cursor + length)])
                cursor += length

            case 2: // SourceCopy
                let rawDelta = try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset)
                let signedDelta = ((rawDelta & 1) != 0 ? -1 : 1) * Int(rawDelta >> 1)
                sourceRelOffset += signedDelta
                guard sourceRelOffset >= 0 && sourceRelOffset + length <= baseArr.count else {
                    throw MachGraphError.patchFormatError("BPS1 SourceCopy out of bounds")
                }
                targetBytes.append(contentsOf: baseArr[sourceRelOffset..<(sourceRelOffset + length)])
                sourceRelOffset += length

            default: // TargetCopy
                let rawDelta = try readBPSVarInt(patchBytes, cursor: &cursor, limit: footerOffset)
                let signedDelta = ((rawDelta & 1) != 0 ? -1 : 1) * Int(rawDelta >> 1)
                targetRelOffset += signedDelta
                for _ in 0..<length {
                    guard targetRelOffset >= 0 && targetRelOffset < targetBytes.count else {
                        throw MachGraphError.patchFormatError("BPS1 TargetCopy out of bounds")
                    }
                    targetBytes.append(targetBytes[targetRelOffset])
                    targetRelOffset += 1
                }
            }
        }

        let actualTargetCRC = BinaryHashAndEntropy.crc32(of: targetBytes[...])
        guard actualTargetCRC == expectedTargetCRC else {
            throw MachGraphError.patchFormatError(
                String(format: "BPS1 reconstructed target CRC-32 mismatch (expected 0x%08X, got 0x%08X)", expectedTargetCRC, actualTargetCRC)
            )
        }

        return try diffData(
            original: baseData,
            modified: Data(targetBytes),
            coalesceGapBytes: 0,
            image: image,
            annotateARM64Disassembly: annotateARM64Disassembly
        )
    }

    // MARK: - Binary-to-Binary Diffing & Unified Hex-Diff Reports

    /// Computes minimal `[BytePatchRecord]` diffs between two equal-or-overlapping-size `Data` buffers.
    public func diffData(
        original: Data,
        modified: Data,
        coalesceGapBytes: Int = 0,
        image: LoadedBinaryImage? = nil,
        annotateARM64Disassembly: Bool = true
    ) throws -> [BytePatchRecord] {
        guard modified.count <= original.count else {
            throw MachGraphError.patchBoundsError(
                offset: UInt64(original.count),
                length: modified.count - original.count,
                fileSize: original.count
            )
        }

        let origStart = original.startIndex
        let modStart = modified.startIndex
        let count = modified.count
        let maxGap = max(0, coalesceGapBytes)

        var rawSpans: [(start: Int, end: Int)] = []
        var idx = 0
        while idx < count {
            if original[origStart + idx] == modified[modStart + idx] {
                idx += 1
                continue
            }
            let diffStart = idx
            idx += 1
            while idx < count {
                if original[origStart + idx] != modified[modStart + idx] {
                    idx += 1
                } else if maxGap > 0 {
                    var lookahead = 1
                    while lookahead <= maxGap && (idx + lookahead) < count && original[origStart + idx + lookahead] == modified[modStart + idx + lookahead] {
                        lookahead += 1
                    }
                    if lookahead <= maxGap && (idx + lookahead) < count {
                        idx += lookahead + 1
                    } else {
                        break
                    }
                } else {
                    break
                }
            }
            rawSpans.append((diffStart, idx))
        }

        let translator = FastOffsetAddressTranslator(image: image)
        let decoder = A64InstructionDecoder()
        var patches: [BytePatchRecord] = []
        patches.reserveCapacity(rawSpans.count)

        for (spanIdx, span) in rawSpans.enumerated() {
            let len = span.end - span.start
            let fileOff = FileOffset(UInt64(span.start))
            let va = translator.virtualAddress(for: fileOff)
            let origSlice = Array(original[(origStart + span.start)..<(origStart + span.end)])
            let modSlice = Array(modified[(modStart + span.start)..<(modStart + span.end)])

            var origAsm: String?
            var modAsm: String?
            if annotateARM64Disassembly,
               len >= 4,
               len <= 64,
               len % 4 == 0,
               let disasmVA = va,
               (disasmVA.rawValue & 0x3) == 0 {
                origAsm = decoder.decodeBuffer(Data(origSlice), baseAddress: disasmVA).map(\.formattedDisassembly).joined(separator: "; ")
                modAsm = decoder.decodeBuffer(Data(modSlice), baseAddress: disasmVA).map(\.formattedDisassembly).joined(separator: "; ")
            }

            patches.append(
                BytePatchRecord(
                    fileOffset: fileOff,
                    virtualAddress: va,
                    originalBytes: origSlice,
                    patchedBytes: modSlice,
                    originalAssembly: origAsm,
                    patchedAssembly: modAsm,
                    note: "Binary diff hunk #\(spanIdx) (\(len) bytes)",
                    isEnabled: true
                )
            )
        }

        return patches
    }

    /// Generates a unified `git diff`-style 16-byte-aligned hex & ASCII diff report for `[BytePatchRecord]` over `baseData`.
    public func generateUnifiedHexDiff(
        patches: [BytePatchRecord],
        baseData: Data,
        contextRows: Int = 1,
        image: LoadedBinaryImage? = nil
    ) -> String {
        guard let overlay = try? SparseCoWByteOverlayBuffer(baseData: baseData, patches: patches) else {
            return "--- a/binary\n+++ b/binary\n(no valid patches within image bounds)\n"
        }
        return generateUnifiedHexDiff(overlay: overlay, contextRows: contextRows, image: image)
    }

    /// Generates a unified 16-byte-aligned hex + ASCII + ARM64 assembly diff directly from a `SparseCoWByteOverlayBuffer`.
    public func generateUnifiedHexDiff(
        overlay: SparseCoWByteOverlayBuffer,
        contextRows: Int = 1,
        image: LoadedBinaryImage? = nil
    ) -> String {
        let name = image?.fileName ?? "binary.bin"
        var lines: [String] = [
            "--- a/\(name)",
            "+++ b/\(name)"
        ]

        guard !overlay.dirtyExtents.isEmpty else {
            lines.append("@@ unmodified (0 patched bytes) @@")
            return lines.joined(separator: "\n")
        }

        let totalRows = (overlay.count + 15) / 16
        let ctx = max(0, contextRows)

        // Build merged row intervals around every CoWDirtyExtent.
        var rowWindows: [(firstRow: Int, lastRow: Int)] = []
        for ext in overlay.dirtyExtents {
            let startRow = max(0, Int(ext.startOffset / 16) - ctx)
            let endRow = min(max(0, totalRows - 1), Int((ext.endOffset - 1) / 16) + ctx)
            if let last = rowWindows.last, startRow <= last.lastRow + 1 {
                rowWindows[rowWindows.count - 1].lastRow = max(last.lastRow, endRow)
            } else {
                rowWindows.append((startRow, endRow))
            }
        }

        let translator = FastOffsetAddressTranslator(image: image)
        let baseStart = overlay.baseData.startIndex

        for win in rowWindows {
            let winByteOff = FileOffset(UInt64(win.firstRow * 16))
            let winRowCount = win.lastRow - win.firstRow + 1
            let winVA = translator.virtualAddress(for: winByteOff)
            let vaLabel = winVA.map { " (\($0.compactHexString))" } ?? ""
            lines.append("@@ -\(winByteOff.hexString),+\(winByteOff.hexString) (\(winRowCount) rows)\(vaLabel) @@")

            for rowIdx in win.firstRow...win.lastRow {
                let rowOffRaw = UInt64(rowIdx * 16)
                let rowLen = min(16, overlay.count - Int(rowOffRaw))
                guard rowLen > 0 else { continue }

                let origSlice = Array(overlay.baseData[(baseStart + Int(rowOffRaw))..<(baseStart + Int(rowOffRaw) + rowLen)])
                let newSlice = (try? overlay.readBytes(offset: rowOffRaw, count: rowLen)) ?? origSlice
                let rowOff = FileOffset(rowOffRaw)
                let rowVA = translator.virtualAddress(for: rowOff)

                if origSlice == newSlice {
                    lines.append(" " + formatUnifiedHexLine(offset: rowOff, va: rowVA, bytes: origSlice))
                } else {
                    lines.append("-" + formatUnifiedHexLine(offset: rowOff, va: rowVA, bytes: origSlice))
                    lines.append("+" + formatUnifiedHexLine(offset: rowOff, va: rowVA, bytes: newSlice))
                }
            }
        }

        let activeWithAsm = overlay.patches.filter { $0.isEnabled && ($0.originalAssembly != nil || $0.patchedAssembly != nil) }
        if !activeWithAsm.isEmpty {
            lines.append("")
            lines.append("# Instruction-Level Patch Summary:")
            for rec in activeWithAsm {
                let loc = rec.virtualAddress?.compactHexString ?? rec.fileOffset.hexString
                lines.append("#   @ \(loc): [\(rec.originalAssembly ?? rec.originalHex)] -> [\(rec.patchedAssembly ?? rec.patchedHex)]")
            }
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Internal IPS Hunk Encoding & Collision Helpers

    private func encodeIPSStream(
        patches: [BytePatchRecord],
        is32Bit: Bool,
        baseData: Data?,
        enableRLE: Bool
    ) -> Data {
        let active = patches.filter { $0.isEnabled && !$0.patchedBytes.isEmpty }
        var writer = BinaryBufferWriter(capacity: 128 + active.count * 16, endianness: .big)
        writer.appendBytes(is32Bit ? Self.ips32Magic : Self.ipsMagic)

        let maxAllowedOffset: UInt64 = is32Bit ? 0xFFFF_FFFF : 0x00FF_FFFF
        let collisionOffset = is32Bit ? Self.ips32SentinelCollisionOffset : Self.ipsSentinelCollisionOffset

        for patch in active {
            let baseOffset = patch.fileOffset.rawValue
            guard baseOffset <= maxAllowedOffset else { continue }

            let segments = enableRLE ? segmentIntoLiteralAndRLERuns(patch.patchedBytes) : [.literal(patch.patchedBytes)]
            var relCursor = 0

            for seg in segments {
                let segLen = seg.expandedByteCount
                var segRemaining = segLen
                var segLocalOffset = 0

                while segRemaining > 0 {
                    var chunkLen = min(segRemaining, Self.maxChunkLength)
                    var hunkOff = baseOffset &+ UInt64(relCursor + segLocalOffset)
                    guard hunkOff <= maxAllowedOffset else { break }

                    // Guard against exact sentinel collision (`0x454F46` == "EOF" in IPS, `0x45454F46` == "EEOF" in IPS32).
                    if hunkOff == collisionOffset && hunkOff > 0 {
                        let prevOffset = hunkOff - 1
                        var prefixByte: UInt8?
                        if relCursor + segLocalOffset > 0 {
                            prefixByte = patch.patchedBytes[relCursor + segLocalOffset - 1]
                        } else if let baseData, prevOffset < UInt64(baseData.count) {
                            prefixByte = baseData[baseData.startIndex + Int(prevOffset)]
                        }

                        if let lead = prefixByte {
                            // Emit a safe literal hunk starting at collisionOffset - 1 so header bytes never spell EOF/EEOF!
                            let takeFromSeg = min(segRemaining, Self.maxChunkLength - 1)
                            let subBytes: [UInt8]
                            switch seg {
                            case .literal(let all):
                                subBytes = [lead] + Array(all[segLocalOffset..<(segLocalOffset + takeFromSeg)])
                            case .rle(_, let fill):
                                subBytes = [lead] + [UInt8](repeating: fill, count: takeFromSeg)
                            }
                            appendIPSHunkOffset(&writer, offset: prevOffset, is32Bit: is32Bit)
                            writer.appendUInt16(UInt16(subBytes.count))
                            writer.appendBytes(subBytes)
                            segLocalOffset += takeFromSeg
                            segRemaining -= takeFromSeg
                            continue
                        }
                    }

                    // Also ensure we never split a multi-chunk hunk so the *next* chunk lands right on collisionOffset!
                    if segRemaining > chunkLen && (hunkOff &+ UInt64(chunkLen)) == collisionOffset && chunkLen > 1 {
                        chunkLen -= 1
                    }

                    appendIPSHunkOffset(&writer, offset: hunkOff, is32Bit: is32Bit)
                    switch seg {
                    case .literal(let all):
                        let slice = Array(all[segLocalOffset..<(segLocalOffset + chunkLen)])
                        writer.appendUInt16(UInt16(slice.count))
                        writer.appendBytes(slice)
                    case .rle(_, let fill):
                        writer.appendUInt16(0) // RLE escape
                        writer.appendUInt16(UInt16(chunkLen))
                        writer.appendUInt8(fill)
                    }

                    segLocalOffset += chunkLen
                    segRemaining -= chunkLen
                    hunkOff &+= UInt64(chunkLen)
                }

                relCursor += segLen
            }
        }

        writer.appendBytes(is32Bit ? Self.ips32EEOF : Self.ipsEOF)
        return writer.data
    }

    private func appendIPSHunkOffset(_ writer: inout BinaryBufferWriter, offset: UInt64, is32Bit: Bool) {
        if is32Bit {
            writer.appendUInt32(UInt32(truncatingIfNeeded: offset))
        } else {
            writer.appendUInt8(UInt8(truncatingIfNeeded: offset >> 16))
            writer.appendUInt8(UInt8(truncatingIfNeeded: offset >> 8))
            writer.appendUInt8(UInt8(truncatingIfNeeded: offset))
        }
    }

    private func segmentIntoLiteralAndRLERuns(_ bytes: [UInt8]) -> [IPSHunkPayload] {
        guard bytes.count >= Self.minRLEBeneficialLength else {
            return bytes.isEmpty ? [] : [.literal(bytes)]
        }

        var output: [IPSHunkPayload] = []
        var literalStart = 0
        var i = 0
        let n = bytes.count

        while i < n {
            let runByte = bytes[i]
            var runEnd = i + 1
            while runEnd < n && bytes[runEnd] == runByte {
                runEnd += 1
            }
            let runLen = runEnd - i
            if runLen >= Self.minRLEBeneficialLength {
                if i > literalStart {
                    output.append(.literal(Array(bytes[literalStart..<i])))
                }
                output.append(.rle(repeatCount: runLen, fillByte: runByte))
                i = runEnd
                literalStart = i
            } else {
                i = runEnd
            }
        }

        if literalStart < n {
            output.append(.literal(Array(bytes[literalStart..<n])))
        }
        return output
    }

    private func appendBPSVarInt(_ writer: inout BinaryBufferWriter, _ value: UInt64) {
        var data = value
        while true {
            let x = UInt8(data & 0x7F)
            data >>= 7
            if data == 0 {
                writer.appendUInt8(0x80 | x)
                break
            }
            writer.appendUInt8(x)
            data -= 1
        }
    }

    private func readBPSVarInt(_ bytes: [UInt8], cursor: inout Int, limit: Int) throws -> UInt64 {
        var data: UInt64 = 0
        var shift: UInt64 = 1
        while true {
            guard cursor < limit else {
                throw MachGraphError.patchFormatError("Unexpected EOF inside BPS1 variable-length integer")
            }
            let x = bytes[cursor]
            cursor += 1
            let addend = UInt64(x & 0x7F).multipliedReportingOverflow(by: shift)
            guard !addend.overflow else {
                throw MachGraphError.patchFormatError("BPS1 variable-length integer overflow")
            }
            data &+= addend.partialValue
            if (x & 0x80) != 0 {
                break
            }
            let nextShift = shift.multipliedReportingOverflow(by: 128)
            guard !nextShift.overflow else {
                throw MachGraphError.patchFormatError("BPS1 variable-length shift overflow")
            }
            shift = nextShift.partialValue
            data &+= shift
        }
        return data
    }

    private func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private func formatUnifiedHexLine(offset: FileOffset, va: VirtualAddress?, bytes: [UInt8]) -> String {
        let addrCol = va.map { "\(offset.hexString) (\($0.compactHexString))" } ?? offset.hexString
        var hexCols: [String] = []
        hexCols.reserveCapacity(16)
        for i in 0..<16 {
            if i < bytes.count {
                hexCols.append(String(format: "%02x", bytes[i]))
            } else {
                hexCols.append("  ")
            }
        }
        let ascii = String(bytes.map { b -> Character in
            (b >= 0x20 && b <= 0x7E) ? Character(UnicodeScalar(b)) : "."
        })
        return "\(addrCol): \(hexCols.joined(separator: " "))  |\(ascii)|"
    }
}

// MARK: - Structured Data Inspector Models & Decoder Engine

public struct DataInspectorFieldRow: Sendable, Codable, Hashable, Identifiable {
    public var id: String { label }
    public let label: String
    public let formattedValue: String
    public let byteWidth: Int

    public init(label: String, formattedValue: String, byteWidth: Int) {
        self.label = label
        self.formattedValue = formattedValue
        self.byteWidth = byteWidth
    }
}

public struct EvaluatedStructFieldValue: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(fieldOffset):\(name)" }
    public let name: String
    public let fieldOffset: Int
    public let absoluteFileOffset: FileOffset
    public let byteSize: Int
    public let cTypeName: String
    public let formattedValue: String
    public let rawHex: String
    public let comment: String?

    public init(
        name: String,
        fieldOffset: Int,
        absoluteFileOffset: FileOffset,
        byteSize: Int,
        cTypeName: String,
        formattedValue: String,
        rawHex: String,
        comment: String? = nil
    ) {
        self.name = name
        self.fieldOffset = fieldOffset
        self.absoluteFileOffset = absoluteFileOffset
        self.byteSize = byteSize
        self.cTypeName = cTypeName
        self.formattedValue = formattedValue
        self.rawHex = rawHex
        self.comment = comment
    }
}

public struct DataInspectorValues: Sendable, Codable, Hashable {
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let endianness: BinaryEndianness
    public let availableBytes: Int
    public let rawWindowBytes: [UInt8]

    public let binary8Bits: String?
    public let int8: Int8?
    public let uint8: UInt8?
    public let int16: Int16?
    public let uint16: UInt16?
    public let int24: Int32?
    public let uint24: UInt32?
    public let int32: Int32?
    public let uint32: UInt32?
    public let int64: Int64?
    public let uint64: UInt64?

    public let float16: Float?
    public let float32: Float?
    public let float64: Double?

    public let uleb128: UInt64?
    public let uleb128ByteLength: Int?
    public let sleb128: Int64?
    public let sleb128ByteLength: Int?

    public let unixTimestamp32ISO8601: String?
    public let unixTimestamp64ISO8601: String?
    public let appleCocoaTimestampISO8601: String?

    public let fourCC: String?
    public let asciiStringPreview: String?
    public let utf16LEStringPreview: String?
    public let pointerSymbolName: String?

    public let arm64RawWord: UInt32?
    public let arm64InstructionPreview: String?
    public let arm64InstructionGroup: String?

    public let rows: [DataInspectorFieldRow]

    public init(
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress?,
        endianness: BinaryEndianness,
        availableBytes: Int,
        rawWindowBytes: [UInt8],
        binary8Bits: String?,
        int8: Int8?,
        uint8: UInt8?,
        int16: Int16?,
        uint16: UInt16?,
        int24: Int32?,
        uint24: UInt32?,
        int32: Int32?,
        uint32: UInt32?,
        int64: Int64?,
        uint64: UInt64?,
        float16: Float?,
        float32: Float?,
        float64: Double?,
        uleb128: UInt64?,
        uleb128ByteLength: Int?,
        sleb128: Int64?,
        sleb128ByteLength: Int?,
        unixTimestamp32ISO8601: String?,
        unixTimestamp64ISO8601: String?,
        appleCocoaTimestampISO8601: String?,
        fourCC: String?,
        asciiStringPreview: String?,
        utf16LEStringPreview: String?,
        pointerSymbolName: String?,
        arm64RawWord: UInt32?,
        arm64InstructionPreview: String?,
        arm64InstructionGroup: String?,
        rows: [DataInspectorFieldRow]
    ) {
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.endianness = endianness
        self.availableBytes = availableBytes
        self.rawWindowBytes = rawWindowBytes
        self.binary8Bits = binary8Bits
        self.int8 = int8
        self.uint8 = uint8
        self.int16 = int16
        self.uint16 = uint16
        self.int24 = int24
        self.uint24 = uint24
        self.int32 = int32
        self.uint32 = uint32
        self.int64 = int64
        self.uint64 = uint64
        self.float16 = float16
        self.float32 = float32
        self.float64 = float64
        self.uleb128 = uleb128
        self.uleb128ByteLength = uleb128ByteLength
        self.sleb128 = sleb128
        self.sleb128ByteLength = sleb128ByteLength
        self.unixTimestamp32ISO8601 = unixTimestamp32ISO8601
        self.unixTimestamp64ISO8601 = unixTimestamp64ISO8601
        self.appleCocoaTimestampISO8601 = appleCocoaTimestampISO8601
        self.fourCC = fourCC
        self.asciiStringPreview = asciiStringPreview
        self.utf16LEStringPreview = utf16LEStringPreview
        self.pointerSymbolName = pointerSymbolName
        self.arm64RawWord = arm64RawWord
        self.arm64InstructionPreview = arm64InstructionPreview
        self.arm64InstructionGroup = arm64InstructionGroup
        self.rows = rows
    }
}

/// Multi-representation cursor inspector decoding raw binary bytes simultaneously as integer/FP scalars,
/// `ULEB128`/`SLEB128`, Unix & Apple Cocoa timestamps, `FourCC`, UTF-8/UTF-16 strings, pointers,
/// custom user structs, and live ARM64 disassembly previews.
public struct BinaryStructureInspector: Sendable {
    private let decoder: A64InstructionDecoder

    public init(decoder: A64InstructionDecoder = A64InstructionDecoder()) {
        self.decoder = decoder
    }

    /// Inspects cursor bytes at `offset` inside a `SparseCoWByteOverlayBuffer`.
    public func inspect(
        at offset: FileOffset,
        in overlay: SparseCoWByteOverlayBuffer,
        endianness: BinaryEndianness = .little,
        image: LoadedBinaryImage? = nil
    ) throws -> DataInspectorValues {
        guard offset.rawValue < overlay.fileSize else {
            throw MachGraphError.patchBoundsError(offset: offset.rawValue, length: 1, fileSize: overlay.count)
        }
        let maxFetch = Int(min(64, overlay.fileSize - offset.rawValue))
        let window = try overlay.readBytes(offset: offset, count: maxFetch)
        let va = image?.virtualAddress(for: offset)
        return decodeWindow(
            window,
            fileOffset: offset,
            virtualAddress: va,
            totalAvailableBytes: Int(min(UInt64(Int.max), overlay.fileSize - offset.rawValue)),
            endianness: endianness,
            image: image
        )
    }

    /// Inspects cursor bytes at `offset` inside raw `Data`.
    public func inspect(
        at offset: FileOffset,
        in data: Data,
        endianness: BinaryEndianness = .little,
        image: LoadedBinaryImage? = nil
    ) throws -> DataInspectorValues {
        guard offset.rawValue < UInt64(data.count) else {
            throw MachGraphError.patchBoundsError(offset: offset.rawValue, length: 1, fileSize: data.count)
        }
        let rem = data.count - Int(offset.rawValue)
        let take = min(64, rem)
        let start = data.startIndex + Int(offset.rawValue)
        let window = Array(data[start..<(start + take)])
        let va = image?.virtualAddress(for: offset)
        return decodeWindow(
            window,
            fileOffset: offset,
            virtualAddress: va,
            totalAvailableBytes: rem,
            endianness: endianness,
            image: image
        )
    }

    /// Inspects cursor bytes at `virtualAddress` via `LoadedBinaryImage` segment translation.
    public func inspect(
        at virtualAddress: VirtualAddress,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage,
        endianness: BinaryEndianness = .little
    ) throws -> DataInspectorValues {
        guard let fileOff = image.fileOffset(for: virtualAddress) else {
            throw MachGraphError.decoderError(
                address: virtualAddress,
                detail: "Address \(virtualAddress.compactHexString) has no backing file offset"
            )
        }
        return try inspect(at: fileOff, in: overlay, endianness: endianness, image: image)
    }

    /// Evaluates a user-defined `CustomStructDefinition` over `overlay` starting at `offset`.
    public func evaluateCustomStruct(
        _ definition: CustomStructDefinition,
        at offset: FileOffset,
        in overlay: SparseCoWByteOverlayBuffer,
        endianness: BinaryEndianness = .little,
        image: LoadedBinaryImage? = nil
    ) throws -> [EvaluatedStructFieldValue] {
        var evaluated: [EvaluatedStructFieldValue] = []
        evaluated.reserveCapacity(definition.fields.count)

        for field in definition.fields where field.offset >= 0 && field.byteSize > 0 {
            let fieldFileOff = offset.adding(UInt64(field.offset))
            let bytes = try overlay.readBytes(offset: fieldFileOff, count: field.byteSize)
            let rawHex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
            let formatted = formatFieldBytes(bytes, typeExpr: field.typeExpr, endianness: endianness, image: image)

            evaluated.append(
                EvaluatedStructFieldValue(
                    name: field.name,
                    fieldOffset: field.offset,
                    absoluteFileOffset: fieldFileOff,
                    byteSize: field.byteSize,
                    cTypeName: field.typeExpr.cTypeName,
                    formattedValue: formatted,
                    rawHex: rawHex,
                    comment: field.comment
                )
            )
        }

        return evaluated
    }

    // MARK: - Internal Multi-Width Scalar & Structured Decoding

    private func decodeWindow(
        _ bytes: [UInt8],
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress?,
        totalAvailableBytes: Int,
        endianness: BinaryEndianness,
        image: LoadedBinaryImage?
    ) -> DataInspectorValues {
        let data = Data(bytes)
        var rows: [DataInspectorFieldRow] = []
        rows.reserveCapacity(20)

        // 8-bit scalars
        let u8 = bytes.first
        let i8 = u8.map { Int8(bitPattern: $0) }
        let bin8 = u8.map { b -> String in
            let bits = String(b, radix: 2)
            return String(repeating: "0", count: max(0, 8 - bits.count)) + bits
        }
        if let b = bin8 {
            rows.append(DataInspectorFieldRow(label: "binary (8-bit)", formattedValue: "0b\(b)", byteWidth: 1))
        }
        if let i8, let u8 {
            rows.append(DataInspectorFieldRow(label: "int8 / uint8", formattedValue: "\(i8) / \(u8) (0x\(String(format: "%02X", u8)))", byteWidth: 1))
        }

        // 16-bit scalars + IEEE-754 binary16
        var u16: UInt16?
        var i16: Int16?
        var f16: Float?
        if bytes.count >= 2 {
            var r = BinarySliceReader(data: data, endianness: endianness)
            if let val = try? r.readUInt16() {
                u16 = val
                i16 = Int16(bitPattern: val)
                f16 = Self.decodeFloat16(val)
                rows.append(DataInspectorFieldRow(label: "int16 / uint16", formattedValue: "\(Int16(bitPattern: val)) / \(val) (0x\(String(format: "%04X", val)))", byteWidth: 2))
                if let half = f16, half.isFinite {
                    rows.append(DataInspectorFieldRow(label: "float16", formattedValue: String(format: "%.6g", half), byteWidth: 2))
                }
            }
        }

        // 24-bit scalars (useful for IPS offsets & ARM immediate inspection)
        var u24: UInt32?
        var i24: Int32?
        if bytes.count >= 3 {
            let raw24: UInt32
            switch endianness {
            case .little:
                raw24 = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16)
            case .big:
                raw24 = (UInt32(bytes[0]) << 16) | (UInt32(bytes[1]) << 8) | UInt32(bytes[2])
            }
            u24 = raw24
            let signExt = (raw24 & 0x0080_0000) != 0 ? Int32(bitPattern: raw24 | 0xFF00_0000) : Int32(raw24)
            i24 = signExt
            rows.append(DataInspectorFieldRow(label: "int24 / uint24", formattedValue: "\(signExt) / \(raw24) (0x\(String(format: "%06X", raw24)))", byteWidth: 3))
        }

        // 32-bit scalars, float32, FourCC, Unix32 timestamp, ARM64 instruction
        var u32: UInt32?
        var i32: Int32?
        var f32: Float?
        var unix32Str: String?
        var fourCC: String?
        var arm64Word: UInt32?
        var arm64Preview: String?
        var arm64Group: String?

        if bytes.count >= 4 {
            var r = BinarySliceReader(data: data, endianness: endianness)
            if let val = try? r.readUInt32() {
                u32 = val
                i32 = Int32(bitPattern: val)
                f32 = Float(bitPattern: val)
                rows.append(DataInspectorFieldRow(label: "int32 / uint32", formattedValue: "\(Int32(bitPattern: val)) / \(val) (0x\(String(format: "%08X", val)))", byteWidth: 4))
                if let flt = f32 {
                    rows.append(DataInspectorFieldRow(label: "float32", formattedValue: flt.isNaN ? "NaN" : String(format: "%.8g", flt), byteWidth: 4))
                }
                unix32Str = Self.formatPlausibleUnixSeconds(TimeInterval(val))
                if let ts = unix32Str {
                    rows.append(DataInspectorFieldRow(label: "Unix time (32-bit)", formattedValue: ts, byteWidth: 4))
                }
            }

            if bytes[0..<4].allSatisfy({ $0 >= 0x20 && $0 <= 0x7E }) {
                let direct = String(bytes[0..<4].map { Character(UnicodeScalar($0)) })
                fourCC = direct
                rows.append(DataInspectorFieldRow(label: "FourCC", formattedValue: "'\(direct)'", byteWidth: 4))
            }

            // ARM64 instructions are always 32-bit little-endian regardless of inspector scalar endianness toggle
            let leWord = UInt32(bytes[0])
                | (UInt32(bytes[1]) << 8)
                | (UInt32(bytes[2]) << 16)
                | (UInt32(bytes[3]) << 24)
            arm64Word = leWord
            let insnPC = virtualAddress ?? VirtualAddress(fileOffset.rawValue)
            let symLookup: (@Sendable (VirtualAddress) -> String?)? = {
                guard let image else { return nil }
                var map: [VirtualAddress: String] = [:]
                for s in image.symbols where map[s.address] == nil {
                    map[s.address] = s.demangledName
                }
                let frozenMap = map
                return { frozenMap[$0] }
            }()
            let decodedInsn = decoder.decode(word: leWord, at: insnPC, symbolLookup: symLookup)
            arm64Preview = decodedInsn.formattedDisassembly
            arm64Group = decodedInsn.group.rawValue
            rows.append(DataInspectorFieldRow(label: "ARM64 instruction", formattedValue: decodedInsn.formattedDisassembly, byteWidth: 4))
        }

        // 64-bit scalars, float64, Unix64 / Apple Cocoa timestamps, Symbol pointer lookup
        var u64: UInt64?
        var i64: Int64?
        var f64: Double?
        var unix64Str: String?
        var cocoaStr: String?
        var ptrSym: String?

        if bytes.count >= 8 {
            var r = BinarySliceReader(data: data, endianness: endianness)
            if let val = try? r.readUInt64() {
                u64 = val
                i64 = Int64(bitPattern: val)
                f64 = Double(bitPattern: val)
                rows.append(DataInspectorFieldRow(label: "int64 / uint64", formattedValue: "\(Int64(bitPattern: val)) / \(val) (0x\(String(format: "%016llX", val)))", byteWidth: 8))
                if let dbl = f64 {
                    rows.append(DataInspectorFieldRow(label: "float64", formattedValue: dbl.isNaN ? "NaN" : String(format: "%.12g", dbl), byteWidth: 8))
                }
                if val <= 4_102_444_800 {
                    unix64Str = Self.formatPlausibleUnixSeconds(TimeInterval(val))
                    if let ts64 = unix64Str {
                        rows.append(DataInspectorFieldRow(label: "Unix time (64-bit)", formattedValue: ts64, byteWidth: 8))
                    }
                }
                if let dbl = f64, dbl.isFinite, dbl >= 0 && dbl <= 2_500_000_000 {
                    // Apple CFAbsoluteTime / NSDate reference epoch (2001-01-01 00:00:00 UTC = Unix + 978307200)
                    cocoaStr = Self.formatPlausibleUnixSeconds(dbl + 978_307_200.0)
                    if let cTs = cocoaStr {
                        rows.append(DataInspectorFieldRow(label: "Apple Cocoa Date", formattedValue: cTs, byteWidth: 8))
                    }
                }
                if let image {
                    let candidateVA = VirtualAddress(val)
                    if let exact = image.exactSymbol(at: candidateVA) {
                        ptrSym = exact.demangledName
                        rows.append(DataInspectorFieldRow(label: "Pointer target", formattedValue: "\(candidateVA.compactHexString) <\(exact.demangledName)>", byteWidth: 8))
                    } else if let sec = image.section(containing: candidateVA) {
                        ptrSym = "\(sec.fullName) + 0x\(String(candidateVA.rawValue - sec.vmAddress.rawValue, radix: 16))"
                        rows.append(DataInspectorFieldRow(label: "Pointer target", formattedValue: "\(candidateVA.compactHexString) (\(ptrSym!))", byteWidth: 8))
                    }
                }
            }
        }

        // ULEB128 & SLEB128 variable-length integers
        var ulebVal: UInt64?
        var ulebLen: Int?
        if !bytes.isEmpty {
            var ur = BinarySliceReader(data: data, endianness: .little)
            if let v = try? ur.readULEB128() {
                ulebVal = v
                ulebLen = ur.position
                rows.append(DataInspectorFieldRow(label: "ULEB128", formattedValue: "\(v) (0x\(String(v, radix: 16)), \(ur.position)B)", byteWidth: ur.position))
            }
        }

        var slebVal: Int64?
        var slebLen: Int?
        if !bytes.isEmpty {
            var sr = BinarySliceReader(data: data, endianness: .little)
            if let v = try? sr.readSLEB128() {
                slebVal = v
                slebLen = sr.position
                rows.append(DataInspectorFieldRow(label: "SLEB128", formattedValue: "\(v) (\(sr.position)B)", byteWidth: sr.position))
            }
        }

        // Printable ASCII / UTF-8 & UTF-16LE previews
        let asciiRun = bytes.prefix { $0 >= 0x20 && $0 <= 0x7E }
        let asciiStr: String? = asciiRun.isEmpty ? nil : String(decoding: asciiRun, as: UTF8.self)
        if let s = asciiStr {
            rows.append(DataInspectorFieldRow(label: "ASCII literal", formattedValue: "\"\(s)\"", byteWidth: asciiRun.count))
        }

        var utf16Units: [UInt16] = []
        var uIdx = 0
        while uIdx + 1 < bytes.count {
            let unit = UInt16(bytes[uIdx]) | (UInt16(bytes[uIdx + 1]) << 8)
            if unit < 0x20 || unit == 0x7F || (unit >= 0xD800 && unit <= 0xDFFF) {
                break
            }
            utf16Units.append(unit)
            uIdx += 2
        }
        let utf16Preview: String? = utf16Units.count >= 2 ? String(utf16CodeUnits: utf16Units, count: utf16Units.count) : nil
        if let u16s = utf16Preview {
            rows.append(DataInspectorFieldRow(label: "UTF-16LE literal", formattedValue: "u\"\(u16s)\"", byteWidth: utf16Units.count * 2))
        }

        return DataInspectorValues(
            fileOffset: fileOffset,
            virtualAddress: virtualAddress,
            endianness: endianness,
            availableBytes: totalAvailableBytes,
            rawWindowBytes: bytes,
            binary8Bits: bin8,
            int8: i8,
            uint8: u8,
            int16: i16,
            uint16: u16,
            int24: i24,
            uint24: u24,
            int32: i32,
            uint32: u32,
            int64: i64,
            uint64: u64,
            float16: f16,
            float32: f32,
            float64: f64,
            uleb128: ulebVal,
            uleb128ByteLength: ulebLen,
            sleb128: slebVal,
            sleb128ByteLength: slebLen,
            unixTimestamp32ISO8601: unix32Str,
            unixTimestamp64ISO8601: unix64Str,
            appleCocoaTimestampISO8601: cocoaStr,
            fourCC: fourCC,
            asciiStringPreview: asciiStr,
            utf16LEStringPreview: utf16Preview,
            pointerSymbolName: ptrSym,
            arm64RawWord: arm64Word,
            arm64InstructionPreview: arm64Preview,
            arm64InstructionGroup: arm64Group,
            rows: rows
        )
    }

    private func formatFieldBytes(
        _ bytes: [UInt8],
        typeExpr: CTypeExpr,
        endianness: BinaryEndianness,
        image: LoadedBinaryImage?
    ) -> String {
        var r = BinarySliceReader(data: Data(bytes), endianness: endianness)
        switch typeExpr {
        case .boolType:
            guard let b = bytes.first else { return "false" }
            return b == 0 ? "false (0)" : "true (\(b))"
        case .intType(let bits, let signed):
            switch (bits, signed) {
            case (8, true):   return (try? r.readInt8()).map { "\($0)" } ?? "0"
            case (8, false):  return (try? r.readUInt8()).map { "\($0) (0x\(String(format: "%02x", $0)))" } ?? "0"
            case (16, true):  return (try? r.readInt16()).map { "\($0)" } ?? "0"
            case (16, false): return (try? r.readUInt16()).map { "\($0) (0x\(String(format: "%04x", $0)))" } ?? "0"
            case (32, true):  return (try? r.readInt32()).map { "\($0)" } ?? "0"
            case (32, false): return (try? r.readUInt32()).map { "\($0) (0x\(String(format: "%08x", $0)))" } ?? "0"
            case (_, true):   return (try? r.readInt64()).map { "\($0)" } ?? "0"
            default:          return (try? r.readUInt64()).map { "0x\(String(format: "%016llx", $0))" } ?? "0"
            }
        case .floatType(let bits):
            if bits <= 16, let u = try? r.readUInt16() {
                return String(format: "%.6g", Self.decodeFloat16(u))
            } else if bits <= 32, let u = try? r.readUInt32() {
                return String(format: "%.8g", Float(bitPattern: u))
            } else if let u = try? r.readUInt64() {
                return String(format: "%.12g", Double(bitPattern: u))
            }
            return "0.0"
        case .pointer, .objcObject, .cString:
            if let ptr = try? r.readUInt64() {
                let va = VirtualAddress(ptr)
                if let sym = image?.exactSymbol(at: va) {
                    return "\(va.compactHexString) <\(sym.demangledName)>"
                }
                return va.hexString
            }
            return "NULL"
        case .voidType, .structRef, .unknownBits:
            return "0x" + bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Pure-Swift IEEE-754 binary16 (half-precision) -> `Float` converter handling subnormals, ±Inf, and NaN.
    internal static func decodeFloat16(_ bits: UInt16) -> Float {
        let sign = UInt32(bits & 0x8000) << 16
        let exp = Int((bits >> 10) & 0x1F)
        let mant = UInt32(bits & 0x03FF)

        if exp == 0 {
            if mant == 0 {
                return Float(bitPattern: sign)
            }
            // Normalize subnormal mantissa
            var m = mant
            var e = -14
            while (m & 0x0400) == 0 {
                m <<= 1
                e -= 1
            }
            m &= 0x03FF
            let f32Exp = UInt32(e + 127) << 23
            let f32Mant = m << 13
            return Float(bitPattern: sign | f32Exp | f32Mant)
        } else if exp == 0x1F {
            let f32Mant = mant << 13
            return Float(bitPattern: sign | 0x7F80_0000 | f32Mant)
        } else {
            let f32Exp = UInt32(exp - 15 + 127) << 23
            let f32Mant = mant << 13
            return Float(bitPattern: sign | f32Exp | f32Mant)
        }
    }

    private static func formatPlausibleUnixSeconds(_ seconds: TimeInterval) -> String? {
        // Plausible binary build/file epoch range: 1990-01-01 .. 2100-01-01 UTC
        guard seconds.isFinite && seconds >= 631_152_000 && seconds <= 4_102_444_800 else {
            return nil
        }
        let date = Date(timeIntervalSince1970: seconds)
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
