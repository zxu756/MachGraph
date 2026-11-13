import Foundation
import MachGraphModels

// MARK: - Dyld Chained Fixups Constants & Types

public enum DyldChainedPtrFormat: UInt16, Sendable, Codable, Hashable {
    case arm64e                = 1
    case ptr64                 = 2
    case ptr32                 = 3
    case ptr32Cache            = 4
    case ptr32Firmware         = 5
    case ptr64Offset           = 6
    case arm64eKernel          = 7
    case ptr64KernelCache      = 8
    case arm64eUserland        = 9
    case arm64eFirmware        = 10
    case x86_64KernelCache     = 11
    case arm64eUserland24      = 12
    case arm64eSharedCache     = 13
    case arm64eSegmented       = 14
    case arm64eSharedCacheV3   = 15
    case sharedCacheV2         = 16

    public var strideBytes: Int {
        switch self {
        case .arm64e, .arm64eUserland, .arm64eUserland24, .arm64eSharedCache, .arm64eSharedCacheV3:
            return 8
        case .x86_64KernelCache:
            return 1
        default:
            return 4
        }
    }

    public var isARM64EFamily: Bool {
        switch self {
        case .arm64e, .arm64eKernel, .arm64eUserland, .arm64eFirmware, .arm64eUserland24:
            return true
        default:
            return false
        }
    }

    public var unauthRebaseUsesVMOffset: Bool {
        switch self {
        case .ptr64Offset, .arm64eKernel, .arm64eUserland, .arm64eUserland24:
            return true
        default:
            return false
        }
    }
}

public enum DyldChainedImportFormat: UInt32, Sendable, Codable, Hashable {
    case standard = 1
    case addend   = 2
    case addend64 = 3
}

public struct DyldChainedImportEntry: Sendable, Codable, Hashable {
    public let ordinalIndex: Int
    public let libraryOrdinal: Int
    public let isWeakImport: Bool
    public let symbolName: String
    public let addend: Int64

    public init(
        ordinalIndex: Int,
        libraryOrdinal: Int,
        isWeakImport: Bool,
        symbolName: String,
        addend: Int64
    ) {
        self.ordinalIndex = ordinalIndex
        self.libraryOrdinal = libraryOrdinal
        self.isWeakImport = isWeakImport
        self.symbolName = symbolName
        self.addend = addend
    }
}

// MARK: - Dyld Chained Fixups & Legacy Dyld Info Parser

public enum DyldFixupsAndTrieParser {
    public static let ptrStartNone: UInt16  = 0xFFFF
    public static let ptrStartMulti: UInt16 = 0x8000
    public static let ptrStartLast: UInt16  = 0x8000

    // Legacy Rebase Opcodes
    private static let rebaseOpcodeMask: UInt8                         = 0xF0
    private static let rebaseImmediateMask: UInt8                      = 0x0F
    private static let rebaseOpcodeDone: UInt8                         = 0x00
    private static let rebaseOpcodeSetTypeImm: UInt8                   = 0x10
    private static let rebaseOpcodeSetSegmentAndOffsetULEB: UInt8      = 0x20
    private static let rebaseOpcodeAddAddrULEB: UInt8                  = 0x30
    private static let rebaseOpcodeAddAddrImmScaled: UInt8             = 0x40
    private static let rebaseOpcodeDoRebaseImmTimes: UInt8             = 0x50
    private static let rebaseOpcodeDoRebaseULEBTimes: UInt8            = 0x60
    private static let rebaseOpcodeDoRebaseAddAddrULEB: UInt8          = 0x70
    private static let rebaseOpcodeDoRebaseULEBTimesSkippingULEB: UInt8 = 0x80

    // Legacy Bind Opcodes
    private static let bindOpcodeMask: UInt8                           = 0xF0
    private static let bindImmediateMask: UInt8                        = 0x0F
    private static let bindOpcodeDone: UInt8                           = 0x00
    private static let bindOpcodeSetDylibOrdinalImm: UInt8             = 0x10
    private static let bindOpcodeSetDylibOrdinalULEB: UInt8            = 0x20
    private static let bindOpcodeSetDylibSpecialImm: UInt8             = 0x30
    private static let bindOpcodeSetSymbolTrailingFlagsImm: UInt8      = 0x40
    private static let bindOpcodeSetTypeImm: UInt8                     = 0x50
    private static let bindOpcodeSetAddendSLEB: UInt8                  = 0x60
    private static let bindOpcodeSetSegmentAndOffsetULEB: UInt8        = 0x70
    private static let bindOpcodeAddAddrULEB: UInt8                    = 0x80
    private static let bindOpcodeDoBind: UInt8                         = 0x90
    private static let bindOpcodeDoBindAddAddrULEB: UInt8              = 0xA0
    private static let bindOpcodeDoBindAddAddrImmScaled: UInt8         = 0xB0
    private static let bindOpcodeDoBindULEBTimesSkippingULEB: UInt8    = 0xC0
    private static let bindOpcodeThreaded: UInt8                       = 0xD0
    private static let bindSubopcodeThreadedSetBindOrdinalTableSizeULEB: UInt8 = 0x00
    private static let bindSubopcodeThreadedApply: UInt8               = 0x01

    /// Parses `LC_DYLD_CHAINED_FIXUPS` header, import table, segment starts, and page pointer chains.
    public static func parseChainedFixups(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        fixupsOffset: Int,
        fixupsSize: Int,
        imageBase: VirtualAddress,
        segments: [BinarySegment]
    ) throws -> [ChainedFixupRecord] {
        guard fixupsOffset >= 0, fixupsSize >= 28, fixupsOffset + fixupsSize <= sliceData.count else {
            throw MachGraphError.invalidFixupChain(
                "LC_DYLD_CHAINED_FIXUPS range (0x\(String(fixupsOffset, radix: 16))+\(fixupsSize)) out of bounds"
            )
        }

        var payloadReader = try BinarySliceReader(
            data: sliceData,
            offset: fixupsOffset,
            length: fixupsSize,
            endianness: .little
        )

        let fixupsVersion = try payloadReader.readUInt32()
        let startsOffset = Int(try payloadReader.readUInt32())
        let importsOffset = Int(try payloadReader.readUInt32())
        let symbolsOffset = Int(try payloadReader.readUInt32())
        let importsCount = Int(try payloadReader.readUInt32())
        let importsFormatRaw = try payloadReader.readUInt32()
        let symbolsFormat = try payloadReader.readUInt32()

        guard fixupsVersion == 0 else {
            throw MachGraphError.invalidFixupChain("Unsupported dyld_chained_fixups_header version \(fixupsVersion)")
        }

        // Parse import entries
        let imports = try parseImportTable(
            payloadReader: payloadReader,
            importsOffset: importsOffset,
            symbolsOffset: symbolsOffset,
            importsCount: importsCount,
            importsFormatRaw: importsFormatRaw,
            symbolsFormat: symbolsFormat
        )

        guard startsOffset >= 28 && startsOffset + 4 <= fixupsSize else {
            return []
        }

        try payloadReader.seek(to: startsOffset)
        let segCount = Int(try payloadReader.readUInt32())
        guard segCount >= 0 && segCount <= 512,
              startsOffset + 4 + segCount * 4 <= fixupsSize else {
            throw MachGraphError.invalidFixupChain("Invalid seg_count (\(segCount)) in dyld_chained_starts_in_image")
        }

        var segInfoOffsets: [Int] = []
        segInfoOffsets.reserveCapacity(segCount)
        for _ in 0..<segCount {
            segInfoOffsets.append(Int(try payloadReader.readUInt32()))
        }

        var fixupRecords: [ChainedFixupRecord] = []

        for segIndex in 0..<segCount {
            let relSegInfoOffset = segInfoOffsets[segIndex]
            if relSegInfoOffset == 0 {
                continue
            }

            let absSegInfoOffsetInPayload = startsOffset + relSegInfoOffset
            guard absSegInfoOffsetInPayload + 22 <= fixupsSize else {
                continue
            }

            try payloadReader.seek(to: absSegInfoOffsetInPayload)
            let segInfoSize = Int(try payloadReader.readUInt32())
            let pageSize = Int(try payloadReader.readUInt16())
            let pointerFormatRaw = try payloadReader.readUInt16()
            let segmentVMOffset = try payloadReader.readUInt64()
            _ = try payloadReader.readUInt32() // max_valid_pointer
            let pageCount = Int(try payloadReader.readUInt16())

            guard pageSize > 0, pageCount >= 0 else { continue }
            guard let ptrFormat = DyldChainedPtrFormat(rawValue: pointerFormatRaw) else {
                continue
            }

            let availablePageStarts = min(pageCount, payloadReader.remaining / 2)
            var pageStarts: [UInt16] = []
            pageStarts.reserveCapacity(availablePageStarts)
            for _ in 0..<availablePageStarts {
                pageStarts.append(try payloadReader.readUInt16())
            }

            // Read optional overflow chain_starts array if segInfoSize extends past page_start[pageCount]
            let headerAndPagesBytes = 22 + availablePageStarts * 2
            let extraUint16Count = segInfoSize > headerAndPagesBytes
                ? min((segInfoSize - headerAndPagesBytes) / 2, payloadReader.remaining / 2)
                : 0
            var fullStartsPool = pageStarts
            for _ in 0..<extraUint16Count {
                fullStartsPool.append(try payloadReader.readUInt16())
            }

            let segmentModel: BinarySegment? = segIndex < segments.count ? segments[segIndex] : nil
            let segmentBaseVA = segmentModel?.vmAddress ?? imageBase.adding(segmentVMOffset)

            for pageIdx in 0..<availablePageStarts {
                let rawStart = pageStarts[pageIdx]
                if rawStart == ptrStartNone {
                    continue
                }

                var chainInitialOffsets: [Int] = []
                if (rawStart & ptrStartMulti) != 0 {
                    var poolIdx = Int(rawStart & 0x7FFF)
                    var guardCounter = 0
                    while poolIdx >= 0 && poolIdx < fullStartsPool.count && guardCounter < 1024 {
                        guardCounter += 1
                        let subEntry = fullStartsPool[poolIdx]
                        chainInitialOffsets.append(Int(subEntry & 0x7FFF))
                        if (subEntry & ptrStartLast) != 0 {
                            break
                        }
                        poolIdx += 1
                    }
                } else {
                    chainInitialOffsets.append(Int(rawStart))
                }

                for initialPageOffset in chainInitialOffsets {
                    let pageRecords = walkPageFixupChain(
                        sliceData: sliceData,
                        sliceFileOffset: sliceFileOffset,
                        imageBase: imageBase,
                        segmentModel: segmentModel,
                        segmentBaseVA: segmentBaseVA,
                        segments: segments,
                        pageIndex: pageIdx,
                        pageSize: pageSize,
                        initialOffsetInPage: initialPageOffset,
                        ptrFormat: ptrFormat,
                        imports: imports
                    )
                    fixupRecords.append(contentsOf: pageRecords)
                }
            }
        }

        fixupRecords.sort { $0.location < $1.location }
        return fixupRecords
    }

    private static func parseImportTable(
        payloadReader: BinarySliceReader,
        importsOffset: Int,
        symbolsOffset: Int,
        importsCount: Int,
        importsFormatRaw: UInt32,
        symbolsFormat: UInt32
    ) throws -> [DyldChainedImportEntry] {
        guard importsCount > 0 else { return [] }
        guard let format = DyldChainedImportFormat(rawValue: importsFormatRaw) else {
            throw MachGraphError.invalidFixupChain("Unknown dyld_chained_fixups imports_format \(importsFormatRaw)")
        }

        let entrySize: Int
        switch format {
        case .standard: entrySize = 4
        case .addend:   entrySize = 8
        case .addend64: entrySize = 16
        }

        guard importsOffset >= 0,
              importsOffset + importsCount * entrySize <= payloadReader.count else {
            throw MachGraphError.invalidFixupChain("Chained imports table exceeds payload bounds")
        }

        var impReader = payloadReader
        try impReader.seek(to: importsOffset)

        let canReadSymbols = symbolsFormat == 0 && symbolsOffset >= 0 && symbolsOffset < payloadReader.count
        var entries: [DyldChainedImportEntry] = []
        entries.reserveCapacity(importsCount)

        for idx in 0..<importsCount {
            let libOrdinal: Int
            let isWeak: Bool
            let nameOffset: Int
            let addend: Int64

            switch format {
            case .standard:
                let raw = try impReader.readUInt32()
                libOrdinal = Int(Int8(bitPattern: UInt8(raw & 0xFF)))
                isWeak = ((raw >> 8) & 1) != 0
                nameOffset = Int(raw >> 9)
                addend = 0

            case .addend:
                let raw = try impReader.readUInt32()
                let add32 = try impReader.readInt32()
                libOrdinal = Int(Int8(bitPattern: UInt8(raw & 0xFF)))
                isWeak = ((raw >> 8) & 1) != 0
                nameOffset = Int(raw >> 9)
                addend = Int64(add32)

            case .addend64:
                let raw0 = try impReader.readUInt64()
                let raw1 = try impReader.readUInt64()
                libOrdinal = Int(Int16(bitPattern: UInt16(raw0 & 0xFFFF)))
                isWeak = ((raw0 >> 16) & 1) != 0
                nameOffset = Int(raw0 >> 32)
                addend = Int64(bitPattern: raw1)
            }

            let symName: String
            if canReadSymbols, symbolsOffset + nameOffset < payloadReader.count {
                symName = payloadReader.peekNullTerminatedUTF8(at: symbolsOffset + nameOffset, maxBytes: 4096) ?? ""
            } else {
                symName = "ordinal_\(idx)"
            }

            entries.append(
                DyldChainedImportEntry(
                    ordinalIndex: idx,
                    libraryOrdinal: libOrdinal,
                    isWeakImport: isWeak,
                    symbolName: symName,
                    addend: addend
                )
            )
        }

        return entries
    }

    private static func pacKeyName(_ keyBits: Int) -> String {
        switch keyBits & 0x3 {
        case 0: return "IA"
        case 1: return "IB"
        case 2: return "DA"
        default: return "DB"
        }
    }

    private static func resolveSliceOffset(
        for vmAddr: VirtualAddress,
        segmentModel: BinarySegment?,
        segmentBaseVA: VirtualAddress,
        segments: [BinarySegment]
    ) -> Int? {
        if let seg = segmentModel, vmAddr >= seg.vmAddress {
            let rel = vmAddr.rawValue - seg.vmAddress.rawValue
            if rel < seg.fileSize {
                return Int(seg.fileOffset.rawValue + rel)
            }
        }
        for seg in segments where seg.fileSize > 0 {
            if vmAddr >= seg.vmAddress && (vmAddr.rawValue - seg.vmAddress.rawValue) < seg.fileSize {
                return Int(seg.fileOffset.rawValue + (vmAddr.rawValue - seg.vmAddress.rawValue))
            }
        }
        return nil
    }

    private static func walkPageFixupChain(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        imageBase: VirtualAddress,
        segmentModel: BinarySegment?,
        segmentBaseVA: VirtualAddress,
        segments: [BinarySegment],
        pageIndex: Int,
        pageSize: Int,
        initialOffsetInPage: Int,
        ptrFormat: DyldChainedPtrFormat,
        imports: [DyldChainedImportEntry]
    ) -> [ChainedFixupRecord] {
        var results: [ChainedFixupRecord] = []
        var visitedPageOffsets = Set<Int>()
        var offsetInPage = initialOffsetInPage
        let stride = ptrFormat.strideBytes
        let is32BitPtr = (ptrFormat == .ptr32 || ptrFormat == .ptr32Cache || ptrFormat == .ptr32Firmware)
        let pointerWidth = is32BitPtr ? 4 : 8

        while offsetInPage >= 0 && offsetInPage + pointerWidth <= pageSize {
            if !visitedPageOffsets.insert(offsetInPage).inserted {
                break
            }

            let deltaInSegment = UInt64(pageIndex * pageSize + offsetInPage)
            let locationVA = segmentBaseVA.adding(deltaInSegment)
            guard let localSliceOff = resolveSliceOffset(
                for: locationVA,
                segmentModel: segmentModel,
                segmentBaseVA: segmentBaseVA,
                segments: segments
            ), localSliceOff >= 0, localSliceOff + pointerWidth <= sliceData.count else {
                break
            }

            let absFileOffset = sliceFileOffset.adding(UInt64(localSliceOff))
            var slotReader = BinarySliceReader(data: sliceData, endianness: .little)
            try? slotReader.seek(to: localSliceOff)

            var nextSkip: Int = 0

            switch ptrFormat {
            case .ptr64, .ptr64Offset:
                guard let raw = try? slotReader.readUInt64() else { return results }
                let isBind = ((raw >> 63) & 1) != 0
                nextSkip = Int((raw >> 51) & 0xFFF)

                if isBind {
                    let ordinal = Int(raw & 0x00FF_FFFF)
                    let inlineAddend = Int64((raw >> 24) & 0xFF)
                    let imp = (ordinal >= 0 && ordinal < imports.count) ? imports[ordinal] : nil
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .bind,
                            targetAddress: nil,
                            symbolName: imp?.symbolName ?? "import_#\(ordinal)",
                            libraryOrdinal: imp?.libraryOrdinal,
                            addend: (imp?.addend ?? 0) &+ inlineAddend,
                            pacDiversity: nil,
                            pacKey: nil
                        )
                    )
                } else {
                    let target36 = raw & 0x000F_FFFF_FFFF
                    let high8 = (raw >> 36) & 0xFF
                    let unslidBase = ptrFormat == .ptr64Offset ? (imageBase.rawValue &+ target36) : target36
                    let fullTarget = VirtualAddress((high8 << 56) | unslidBase)
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .rebase,
                            targetAddress: fullTarget,
                            symbolName: nil,
                            libraryOrdinal: nil,
                            addend: 0,
                            pacDiversity: nil,
                            pacKey: nil
                        )
                    )
                }

            case .arm64e, .arm64eKernel, .arm64eUserland, .arm64eFirmware, .arm64eUserland24:
                guard let raw = try? slotReader.readUInt64() else { return results }
                let isAuth = ((raw >> 63) & 1) != 0
                let isBind = ((raw >> 62) & 1) != 0
                nextSkip = Int((raw >> 51) & 0x7FF)
                let usesOrdinal24 = (ptrFormat == .arm64eUserland24)

                switch (isAuth, isBind) {
                case (false, false):
                    // dyld_chained_ptr_arm64e_rebase
                    let target43 = raw & 0x0000_07FF_FFFF_FFFF
                    let high8 = (raw >> 43) & 0xFF
                    let baseTarget = ptrFormat.unauthRebaseUsesVMOffset ? (imageBase.rawValue &+ target43) : target43
                    let targetVA = VirtualAddress((high8 << 56) | baseTarget)
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .rebase,
                            targetAddress: targetVA,
                            symbolName: nil,
                            libraryOrdinal: nil,
                            addend: 0,
                            pacDiversity: nil,
                            pacKey: nil
                        )
                    )

                case (false, true):
                    // dyld_chained_ptr_arm64e_bind / bind24
                    let ordinal = usesOrdinal24 ? Int(raw & 0x00FF_FFFF) : Int(raw & 0xFFFF)
                    let rawAdd19 = (raw >> 32) & 0x7FFFF
                    let signedAdd19: Int64 = (rawAdd19 & 0x40000) != 0
                        ? Int64(bitPattern: rawAdd19 | ~UInt64(0x7FFFF))
                        : Int64(rawAdd19)
                    let imp = (ordinal >= 0 && ordinal < imports.count) ? imports[ordinal] : nil
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .bind,
                            targetAddress: nil,
                            symbolName: imp?.symbolName ?? "import_#\(ordinal)",
                            libraryOrdinal: imp?.libraryOrdinal,
                            addend: (imp?.addend ?? 0) &+ signedAdd19,
                            pacDiversity: nil,
                            pacKey: nil
                        )
                    )

                case (true, false):
                    // dyld_chained_ptr_arm64e_auth_rebase
                    let runtimeOffset = raw & 0xFFFF_FFFF
                    let diversity = UInt16((raw >> 32) & 0xFFFF)
                    let keyBits = Int((raw >> 49) & 0x3)
                    let targetVA = imageBase.adding(runtimeOffset)
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .authRebase,
                            targetAddress: targetVA,
                            symbolName: nil,
                            libraryOrdinal: nil,
                            addend: 0,
                            pacDiversity: diversity,
                            pacKey: pacKeyName(keyBits)
                        )
                    )

                case (true, true):
                    // dyld_chained_ptr_arm64e_auth_bind / auth_bind24
                    let ordinal = usesOrdinal24 ? Int(raw & 0x00FF_FFFF) : Int(raw & 0xFFFF)
                    let diversity = UInt16((raw >> 32) & 0xFFFF)
                    let keyBits = Int((raw >> 49) & 0x3)
                    let imp = (ordinal >= 0 && ordinal < imports.count) ? imports[ordinal] : nil
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .authBind,
                            targetAddress: nil,
                            symbolName: imp?.symbolName ?? "import_#\(ordinal)",
                            libraryOrdinal: imp?.libraryOrdinal,
                            addend: imp?.addend ?? 0,
                            pacDiversity: diversity,
                            pacKey: pacKeyName(keyBits)
                        )
                    )
                }

            case .ptr32:
                guard let raw32 = try? slotReader.readUInt32() else { return results }
                let isBind = ((raw32 >> 31) & 1) != 0
                nextSkip = Int((raw32 >> 26) & 0x1F)
                if isBind {
                    let ordinal = Int(raw32 & 0x000F_FFFF)
                    let add6 = Int64((raw32 >> 20) & 0x3F)
                    let imp = (ordinal >= 0 && ordinal < imports.count) ? imports[ordinal] : nil
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .bind,
                            symbolName: imp?.symbolName ?? "import_#\(ordinal)",
                            libraryOrdinal: imp?.libraryOrdinal,
                            addend: (imp?.addend ?? 0) &+ add6
                        )
                    )
                } else {
                    let target26 = UInt64(raw32 & 0x03FF_FFFF)
                    results.append(
                        ChainedFixupRecord(
                            location: locationVA,
                            fileOffset: absFileOffset,
                            kind: .rebase,
                            targetAddress: VirtualAddress(target26)
                        )
                    )
                }

            default:
                return results
            }

            if nextSkip == 0 {
                break
            }
            offsetInPage += nextSkip * stride
        }

        return results
    }

    // MARK: - Legacy LC_DYLD_INFO / LC_DYLD_INFO_ONLY Opcode State Machines

    public static func parseLegacyDyldInfo(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        rebaseRange: (offset: Int, size: Int),
        bindRange: (offset: Int, size: Int),
        weakBindRange: (offset: Int, size: Int),
        lazyBindRange: (offset: Int, size: Int),
        imageBase: VirtualAddress,
        segments: [BinarySegment]
    ) throws -> [ChainedFixupRecord] {
        var allRecords: [ChainedFixupRecord] = []

        if rebaseRange.size > 0 && rebaseRange.offset >= 0 && rebaseRange.offset + rebaseRange.size <= sliceData.count {
            let rebases = try runRebaseStateMachine(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                offset: rebaseRange.offset,
                size: rebaseRange.size,
                segments: segments
            )
            allRecords.append(contentsOf: rebases)
        }

        if bindRange.size > 0 && bindRange.offset >= 0 && bindRange.offset + bindRange.size <= sliceData.count {
            let binds = try runBindStateMachine(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                offset: bindRange.offset,
                size: bindRange.size,
                segments: segments,
                isLazyStream: false
            )
            allRecords.append(contentsOf: binds)
        }

        if weakBindRange.size > 0 && weakBindRange.offset >= 0 && weakBindRange.offset + weakBindRange.size <= sliceData.count {
            let weakBinds = try runBindStateMachine(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                offset: weakBindRange.offset,
                size: weakBindRange.size,
                segments: segments,
                isLazyStream: false
            )
            allRecords.append(contentsOf: weakBinds)
        }

        if lazyBindRange.size > 0 && lazyBindRange.offset >= 0 && lazyBindRange.offset + lazyBindRange.size <= sliceData.count {
            let lazyBinds = try runBindStateMachine(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                offset: lazyBindRange.offset,
                size: lazyBindRange.size,
                segments: segments,
                isLazyStream: true
            )
            allRecords.append(contentsOf: lazyBinds)
        }

        allRecords.sort { $0.location < $1.location }
        return allRecords
    }

    private static func runRebaseStateMachine(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        offset: Int,
        size: Int,
        segments: [BinarySegment]
    ) throws -> [ChainedFixupRecord] {
        var reader = try BinarySliceReader(data: sliceData, offset: offset, length: size, endianness: .little)
        var records: [ChainedFixupRecord] = []

        var segIndex = 0
        var segOffset: UInt64 = 0
        let ptrSize: UInt64 = 8

        func emitSingleRebase() {
            guard segIndex >= 0 && segIndex < segments.count else { return }
            let seg = segments[segIndex]
            let locVA = seg.vmAddress.adding(segOffset)
            let localFileOff = seg.fileOffset.rawValue &+ segOffset
            let absFileOff = sliceFileOffset.adding(localFileOff)

            var targetVA: VirtualAddress?
            if Int(localFileOff) >= 0 && Int(localFileOff) + 8 <= sliceData.count {
                var ptrReader = BinarySliceReader(data: sliceData, endianness: .little)
                try? ptrReader.seek(to: Int(localFileOff))
                if let rawPtr = try? ptrReader.readUInt64() {
                    targetVA = VirtualAddress(rawPtr & 0x0000_FFFF_FFFF_FFFF)
                }
            }

            records.append(
                ChainedFixupRecord(
                    location: locVA,
                    fileOffset: absFileOff,
                    kind: .rebase,
                    targetAddress: targetVA
                )
            )
        }

        var done = false
        while !reader.isAtEnd && !done {
            let byte = try reader.readUInt8()
            let opcode = byte & rebaseOpcodeMask
            let imm = byte & rebaseImmediateMask

            switch opcode {
            case rebaseOpcodeDone:
                done = true

            case rebaseOpcodeSetTypeImm:
                break

            case rebaseOpcodeSetSegmentAndOffsetULEB:
                segIndex = Int(imm)
                segOffset = try reader.readULEB128()

            case rebaseOpcodeAddAddrULEB:
                let delta = try reader.readULEB128()
                segOffset &+= delta

            case rebaseOpcodeAddAddrImmScaled:
                segOffset &+= UInt64(imm) &* ptrSize

            case rebaseOpcodeDoRebaseImmTimes:
                for _ in 0..<Int(imm) {
                    emitSingleRebase()
                    segOffset &+= ptrSize
                }

            case rebaseOpcodeDoRebaseULEBTimes:
                let count = min(try reader.readULEB128(), 65_536)
                for _ in 0..<count {
                    emitSingleRebase()
                    segOffset &+= ptrSize
                }

            case rebaseOpcodeDoRebaseAddAddrULEB:
                emitSingleRebase()
                let delta = try reader.readULEB128()
                segOffset &+= ptrSize &+ delta

            case rebaseOpcodeDoRebaseULEBTimesSkippingULEB:
                let count = min(try reader.readULEB128(), 65_536)
                let skip = try reader.readULEB128()
                for _ in 0..<count {
                    emitSingleRebase()
                    segOffset &+= ptrSize &+ skip
                }

            default:
                done = true
            }
        }

        return records
    }

    private static func runBindStateMachine(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        offset: Int,
        size: Int,
        segments: [BinarySegment],
        isLazyStream: Bool
    ) throws -> [ChainedFixupRecord] {
        var reader = try BinarySliceReader(data: sliceData, offset: offset, length: size, endianness: .little)
        var records: [ChainedFixupRecord] = []

        var segIndex = 0
        var segOffset: UInt64 = 0
        var dylibOrdinal: Int = 0
        var symbolName: String = ""
        var addend: Int64 = 0
        let ptrSize: UInt64 = 8

        var threadedTable: [(symbolName: String, dylibOrdinal: Int, addend: Int64)] = []
        var isThreadedMode = false

        func emitSingleBind(sym: String, ord: Int, add: Int64) {
            guard segIndex >= 0 && segIndex < segments.count else { return }
            let seg = segments[segIndex]
            let locVA = seg.vmAddress.adding(segOffset)
            let localFileOff = seg.fileOffset.rawValue &+ segOffset
            let absFileOff = sliceFileOffset.adding(localFileOff)
            records.append(
                ChainedFixupRecord(
                    location: locVA,
                    fileOffset: absFileOff,
                    kind: .bind,
                    targetAddress: nil,
                    symbolName: sym,
                    libraryOrdinal: ord,
                    addend: add
                )
            )
        }

        var done = false
        while !reader.isAtEnd && !done {
            let byte = try reader.readUInt8()
            let opcode = byte & bindOpcodeMask
            let imm = byte & bindImmediateMask

            switch opcode {
            case bindOpcodeDone:
                if !isLazyStream {
                    done = true
                }

            case bindOpcodeSetDylibOrdinalImm:
                dylibOrdinal = Int(imm)

            case bindOpcodeSetDylibOrdinalULEB:
                dylibOrdinal = Int(try reader.readULEB128())

            case bindOpcodeSetDylibSpecialImm:
                if imm == 0 {
                    dylibOrdinal = 0
                } else {
                    dylibOrdinal = Int(Int8(bitPattern: 0xF0 | imm))
                }

            case bindOpcodeSetSymbolTrailingFlagsImm:
                symbolName = try reader.readNullTerminatedUTF8()

            case bindOpcodeSetTypeImm:
                break

            case bindOpcodeSetAddendSLEB:
                addend = try reader.readSLEB128()

            case bindOpcodeSetSegmentAndOffsetULEB:
                segIndex = Int(imm)
                segOffset = try reader.readULEB128()

            case bindOpcodeAddAddrULEB:
                let delta = try reader.readULEB128()
                segOffset &+= delta

            case bindOpcodeDoBind:
                if isThreadedMode {
                    threadedTable.append((symbolName, dylibOrdinal, addend))
                } else {
                    emitSingleBind(sym: symbolName, ord: dylibOrdinal, add: addend)
                    segOffset &+= ptrSize
                }

            case bindOpcodeDoBindAddAddrULEB:
                emitSingleBind(sym: symbolName, ord: dylibOrdinal, add: addend)
                let delta = try reader.readULEB128()
                segOffset &+= ptrSize &+ delta

            case bindOpcodeDoBindAddAddrImmScaled:
                emitSingleBind(sym: symbolName, ord: dylibOrdinal, add: addend)
                segOffset &+= ptrSize &+ (UInt64(imm) &* ptrSize)

            case bindOpcodeDoBindULEBTimesSkippingULEB:
                let count = min(try reader.readULEB128(), 65_536)
                let skip = try reader.readULEB128()
                for _ in 0..<count {
                    emitSingleBind(sym: symbolName, ord: dylibOrdinal, add: addend)
                    segOffset &+= ptrSize &+ skip
                }

            case bindOpcodeThreaded:
                if imm == bindSubopcodeThreadedSetBindOrdinalTableSizeULEB {
                    let cap = Int(min(try reader.readULEB128(), 65_536))
                    threadedTable.removeAll(keepingCapacity: true)
                    threadedTable.reserveCapacity(cap)
                    isThreadedMode = true
                } else if imm == bindSubopcodeThreadedApply {
                    // Walk threaded chain starting at (segIndex, segOffset)
                    guard segIndex >= 0 && segIndex < segments.count else { break }
                    let seg = segments[segIndex]
                    var curSegOff = segOffset
                    var chainGuard = 0
                    while chainGuard < 65_536 {
                        chainGuard += 1
                        let localOff = Int(seg.fileOffset.rawValue &+ curSegOff)
                        guard localOff >= 0 && localOff + 8 <= sliceData.count else { break }
                        var pr = BinarySliceReader(data: sliceData, endianness: .little)
                        try? pr.seek(to: localOff)
                        guard let raw64 = try? pr.readUInt64() else { break }

                        let isBind = ((raw64 >> 62) & 1) != 0
                        let nextDelta = ((raw64 >> 51) & 0x7FF) * 8
                        let locVA = seg.vmAddress.adding(curSegOff)
                        let absOff = sliceFileOffset.adding(UInt64(localOff))

                        if isBind {
                            let ord = Int(raw64 & 0xFFFF)
                            if ord >= 0 && ord < threadedTable.count {
                                let item = threadedTable[ord]
                                records.append(
                                    ChainedFixupRecord(
                                        location: locVA,
                                        fileOffset: absOff,
                                        kind: ((raw64 >> 63) & 1) != 0 ? .authBind : .bind,
                                        symbolName: item.symbolName,
                                        libraryOrdinal: item.dylibOrdinal,
                                        addend: item.addend
                                    )
                                )
                            }
                        } else {
                            let inferredBase = segments.first(where: { $0.name == "__TEXT" })?.vmAddress
                                ?? segments.first(where: { $0.name != "__PAGEZERO" })?.vmAddress
                                ?? .zero
                            let target = inferredBase.adding(raw64 & 0xFFFF_FFFF)
                            records.append(
                                ChainedFixupRecord(
                                    location: locVA,
                                    fileOffset: absOff,
                                    kind: ((raw64 >> 63) & 1) != 0 ? .authRebase : .rebase,
                                    targetAddress: target
                                )
                            )
                        }

                        if nextDelta == 0 { break }
                        curSegOff &+= nextDelta
                    }
                }

            default:
                done = true
            }
        }

        return records
    }
}

// MARK: - Cycle-Safe Recursive Mach-O Export Trie Parser & Builder

public enum ExportTrieParser {
    public static let exportKindMask: UInt64           = 0x03
    public static let exportKindRegular: UInt64        = 0x00
    public static let exportKindThreadLocal: UInt64    = 0x01
    public static let exportKindAbsolute: UInt64       = 0x02

    public static let exportWeakDefinition: UInt64     = 0x04
    public static let exportReexport: UInt64           = 0x08
    public static let exportStubAndResolver: UInt64    = 0x10

    /// Walks a ULEB128 Mach-O Export Trie (`LC_DYLD_EXPORTS_TRIE` or `LC_DYLD_INFO.export_off`) into `[BinarySymbol]`.
    public static func parse(
        trieData: Data,
        imageBase: VirtualAddress,
        sections: [BinarySection]
    ) throws -> [BinarySymbol] {
        guard !trieData.isEmpty else { return [] }
        let baseReader = BinarySliceReader(data: trieData, endianness: .little)
        var emitted: [BinarySymbol] = []
        var activeAncestors = Set<Int>()
        var totalVisitedNodes = 0

        try walkNode(
            baseReader: baseReader,
            nodeOffset: 0,
            accumulatedPrefix: "",
            imageBase: imageBase,
            sections: sections,
            activeAncestors: &activeAncestors,
            totalVisitedNodes: &totalVisitedNodes,
            emitted: &emitted
        )

        return emitted
    }

    private static func walkNode(
        baseReader: BinarySliceReader,
        nodeOffset: Int,
        accumulatedPrefix: String,
        imageBase: VirtualAddress,
        sections: [BinarySection],
        activeAncestors: inout Set<Int>,
        totalVisitedNodes: inout Int,
        emitted: inout [BinarySymbol]
    ) throws {
        guard nodeOffset >= 0 && nodeOffset < baseReader.count else { return }
        guard totalVisitedNodes < 32_768 else { return }
        guard activeAncestors.insert(nodeOffset).inserted else {
            throw MachGraphError.malformedHeader("Cycle detected in Mach-O export trie at offset 0x\(String(nodeOffset, radix: 16))")
        }
        defer { activeAncestors.remove(nodeOffset) }
        totalVisitedNodes += 1

        var reader = baseReader
        try reader.seek(to: nodeOffset)

        let terminalSize = Int(try reader.readULEB128())
        let terminalStart = reader.position

        if terminalSize > 0 && terminalStart + terminalSize <= reader.count {
            var termReader = try reader.subreader(offset: terminalStart, length: terminalSize, endianness: .little)
            let flags = try termReader.readULEB128()
            let binding: SymbolBinding = (flags & exportWeakDefinition) != 0 ? .weak : .global

            if (flags & exportReexport) != 0 {
                let dylibOrd = Int(try termReader.readULEB128())
                let importedName = try termReader.readNullTerminatedUTF8()
                let effectiveName = accumulatedPrefix.isEmpty ? importedName : accumulatedPrefix
                if !effectiveName.isEmpty {
                    emitted.append(
                        BinarySymbol(
                            name: effectiveName,
                            demangledName: MachOSymbolDemangler.demangle(effectiveName),
                            kind: .exportedEntry,
                            binding: .external,
                            address: .zero,
                            size: 0,
                            sectionIndex: nil,
                            libraryOrdinal: dylibOrd
                        )
                    )
                }
            } else if (flags & exportStubAndResolver) != 0 {
                let stubOff = try termReader.readULEB128()
                let resolverOff = try termReader.readULEB128()
                let stubVA = imageBase.adding(stubOff)
                let resolverVA = imageBase.adding(resolverOff)
                let stubSecIdx = sections.firstIndex(where: { $0.addressRange.contains(stubVA) })
                let resolverSecIdx = sections.firstIndex(where: { $0.addressRange.contains(resolverVA) })

                if !accumulatedPrefix.isEmpty {
                    emitted.append(
                        BinarySymbol(
                            name: accumulatedPrefix,
                            demangledName: MachOSymbolDemangler.demangle(accumulatedPrefix),
                            kind: .exportedEntry,
                            binding: binding,
                            address: stubVA,
                            size: 0,
                            sectionIndex: stubSecIdx
                        )
                    )
                    emitted.append(
                        BinarySymbol(
                            name: "\(accumulatedPrefix)$resolver",
                            demangledName: "\(MachOSymbolDemangler.demangle(accumulatedPrefix)) (resolver)",
                            kind: .function,
                            binding: .local,
                            address: resolverVA,
                            size: 0,
                            sectionIndex: resolverSecIdx
                        )
                    )
                }
            } else {
                let rawOffset = try termReader.readULEB128()
                let kindBits = flags & exportKindMask
                let symbolVA: VirtualAddress = (kindBits == exportKindAbsolute)
                    ? VirtualAddress(rawOffset)
                    : imageBase.adding(rawOffset)
                let secIdx = sections.firstIndex(where: { $0.addressRange.contains(symbolVA) })
                let sec = secIdx.map { sections[$0] }

                let symKind: SymbolKind
                if sec == nil || sec?.kind == .code || sec?.permissions.contains(.execute) == true {
                    symKind = .exportedEntry
                } else {
                    symKind = .globalVariable
                }

                if !accumulatedPrefix.isEmpty {
                    emitted.append(
                        BinarySymbol(
                            name: accumulatedPrefix,
                            demangledName: MachOSymbolDemangler.demangle(accumulatedPrefix),
                            kind: symKind,
                            binding: binding,
                            address: symbolVA,
                            size: 0,
                            sectionIndex: secIdx
                        )
                    )
                }
            }
        }

        let childrenPos = terminalStart + terminalSize
        guard childrenPos < reader.count else { return }
        try reader.seek(to: childrenPos)
        let childCount = Int(try reader.readUInt8())

        var children: [(edge: String, offset: Int)] = []
        children.reserveCapacity(childCount)
        for _ in 0..<childCount {
            if reader.isAtEnd { break }
            let edgeLabel = try reader.readNullTerminatedUTF8()
            let childOffset = Int(try reader.readULEB128())
            children.append((edgeLabel, childOffset))
        }

        for child in children {
            try walkNode(
                baseReader: baseReader,
                nodeOffset: child.offset,
                accumulatedPrefix: accumulatedPrefix + child.edge,
                imageBase: imageBase,
                sections: sections,
                activeAncestors: &activeAncestors,
                totalVisitedNodes: &totalVisitedNodes,
                emitted: &emitted
            )
        }
    }
}

// MARK: - Compressed Mach-O Export Trie Serializer

public enum ExportTrieBuilder {
    public struct ExportEntry: Sendable, Hashable {
        public let name: String
        public let offsetFromImageBase: UInt64
        public let flags: UInt64

        public init(name: String, offsetFromImageBase: UInt64, flags: UInt64 = 0) {
            self.name = name
            self.offsetFromImageBase = offsetFromImageBase
            self.flags = flags
        }
    }

    private final class TrieNode {
        var terminalEntry: ExportEntry?
        var children: [(edge: String, node: TrieNode)] = []
        var serializedOffset: Int = 0
    }

    /// Serializes a list of exported symbols into a genuine compressed ULEB128 Mach-O Export Trie.
    public static func buildTrie(entries: [ExportEntry]) -> Data {
        guard !entries.isEmpty else {
            return Data([0x00, 0x00])
        }

        let sorted = entries.sorted { $0.name < $1.name }
        let root = TrieNode()

        for entry in sorted where !entry.name.isEmpty {
            insert(entry: entry, remaining: entry.name, into: root)
        }

        // Flatten nodes in topological pre-order and iteratively converge ULEB128 child offsets
        var orderedNodes: [TrieNode] = []
        func collect(_ node: TrieNode) {
            orderedNodes.append(node)
            for child in node.children {
                collect(child.node)
            }
        }
        collect(root)

        var changed = true
        var pass = 0
        while changed && pass < 16 {
            changed = false
            pass += 1
            var runningOffset = 0
            for node in orderedNodes {
                if node.serializedOffset != runningOffset {
                    node.serializedOffset = runningOffset
                    changed = true
                }
                runningOffset += measureNodeByteSize(node)
            }
        }

        var writer = BinaryBufferWriter(capacity: orderedNodes.count * 24, endianness: .little)
        for node in orderedNodes {
            let termBytes = encodeTerminal(node.terminalEntry)
            writer.appendULEB128(UInt64(termBytes.count))
            writer.appendBytes(termBytes)
            writer.appendUInt8(UInt8(min(node.children.count, 255)))
            for child in node.children.prefix(255) {
                writer.appendCString(child.edge)
                writer.appendULEB128(UInt64(child.node.serializedOffset))
            }
        }
        writer.padToAlignment(8)
        return writer.data
    }

    private static func insert(entry: ExportEntry, remaining: String, into node: TrieNode) {
        if remaining.isEmpty {
            node.terminalEntry = entry
            return
        }
        for idx in node.children.indices {
            let existingEdge = node.children[idx].edge
            let common = commonPrefixString(existingEdge, remaining)
            if !common.isEmpty {
                if common.count == existingEdge.count {
                    let rest = String(remaining.dropFirst(common.count))
                    insert(entry: entry, remaining: rest, into: node.children[idx].node)
                    return
                } else {
                    // Split existing edge at longest common prefix
                    let splitNode = TrieNode()
                    let oldSuffix = String(existingEdge.dropFirst(common.count))
                    let existingChild = node.children[idx].node
                    splitNode.children.append((oldSuffix, existingChild))
                    node.children[idx] = (common, splitNode)

                    let newSuffix = String(remaining.dropFirst(common.count))
                    if newSuffix.isEmpty {
                        splitNode.terminalEntry = entry
                    } else {
                        let leaf = TrieNode()
                        leaf.terminalEntry = entry
                        splitNode.children.append((newSuffix, leaf))
                    }
                    splitNode.children.sort { $0.edge < $1.edge }
                    return
                }
            }
        }

        let newChild = TrieNode()
        newChild.terminalEntry = entry
        node.children.append((remaining, newChild))
        node.children.sort { $0.edge < $1.edge }
    }

    private static func commonPrefixString(_ a: String, _ b: String) -> String {
        var ac = a.makeIterator()
        var bc = b.makeIterator()
        var out = ""
        while let ca = ac.next(), let cb = bc.next(), ca == cb {
            out.append(ca)
        }
        return out
    }

    private static func encodeTerminal(_ entry: ExportEntry?) -> [UInt8] {
        guard let entry else { return [] }
        var w = BinaryBufferWriter(capacity: 16, endianness: .little)
        w.appendULEB128(entry.flags)
        w.appendULEB128(entry.offsetFromImageBase)
        return w.bytes
    }

    private static func ulebByteLength(_ value: UInt64) -> Int {
        var v = value
        var len = 0
        repeat {
            v >>= 7
            len += 1
        } while v != 0
        return len
    }

    private static func measureNodeByteSize(_ node: TrieNode) -> Int {
        let termBytes = encodeTerminal(node.terminalEntry)
        var size = ulebByteLength(UInt64(termBytes.count)) + termBytes.count + 1
        for child in node.children.prefix(255) {
            size += child.edge.utf8.count + 1 + ulebByteLength(UInt64(child.node.serializedOffset))
        }
        return size
    }
}
