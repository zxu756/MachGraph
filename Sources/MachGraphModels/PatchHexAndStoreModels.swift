import Foundation

// MARK: - Binary Patching, Hex Rows & Entropy Regions

public struct BytePatchRecord: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let originalBytes: [UInt8]
    public let patchedBytes: [UInt8]
    public let originalAssembly: String?
    public let patchedAssembly: String?
    public var note: String
    public var isEnabled: Bool
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        originalBytes: [UInt8],
        patchedBytes: [UInt8],
        originalAssembly: String? = nil,
        patchedAssembly: String? = nil,
        note: String = "",
        isEnabled: Bool = true,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.originalBytes = originalBytes
        self.patchedBytes = patchedBytes
        self.originalAssembly = originalAssembly
        self.patchedAssembly = patchedAssembly
        self.note = note
        self.isEnabled = isEnabled
        self.createdAt = createdAt
    }

    public var byteCount: Int { patchedBytes.count }

    public var originalHex: String {
        originalBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    public var patchedHex: String {
        patchedBytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}

public struct HexRowSlice: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { fileOffset.rawValue }
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let bytes: [UInt8]
    public let modifiedMask: [Bool]
    public let asciiColumn: String
    public let localEntropy: Double

    public init(
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        bytes: [UInt8],
        modifiedMask: [Bool]
    ) {
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.bytes = bytes
        self.modifiedMask = modifiedMask
        self.asciiColumn = String(bytes.map { b -> Character in
            (b >= 0x20 && b <= 0x7E) ? Character(UnicodeScalar(b)) : "."
        })
        self.localEntropy = BinaryHashAndEntropy.shannonEntropy(of: bytes[...])
    }
}

public enum EntropyClassification: String, Sendable, Codable, Hashable, CaseIterable {
    case nullPadding = "Zero / Alignment Padding"
    case structuredMetadata = "Structured Headers / Tables"
    case printableStrings = "ASCII / UTF-8 Literals"
    case nativeMachineCode = "Native Machine Instructions"
    case compressedOrEncrypted = "Packed / Encrypted / High-Entropy"

    public static func classify(entropy: Double, zeroRatio: Double, printableRatio: Double) -> EntropyClassification {
        if zeroRatio > 0.85 || entropy < 0.35 {
            return .nullPadding
        }
        if entropy >= 7.25 {
            return .compressedOrEncrypted
        }
        if printableRatio >= 0.72 && entropy < 5.6 {
            return .printableStrings
        }
        if entropy >= 5.2 && entropy < 7.25 {
            return .nativeMachineCode
        }
        return .structuredMetadata
    }
}

public struct EntropyRegionSample: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { fileOffset.rawValue }
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let length: Int
    public let sectionName: String
    public let entropyBitsPerByte: Double
    public let zeroByteRatio: Double
    public let printableByteRatio: Double
    public let classification: EntropyClassification

    public init(
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        length: Int,
        sectionName: String,
        entropyBitsPerByte: Double,
        zeroByteRatio: Double,
        printableByteRatio: Double
    ) {
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.length = length
        self.sectionName = sectionName
        self.entropyBitsPerByte = entropyBitsPerByte
        self.zeroByteRatio = zeroByteRatio
        self.printableByteRatio = printableByteRatio
        self.classification = EntropyClassification.classify(
            entropy: entropyBitsPerByte,
            zeroRatio: zeroByteRatio,
            printableRatio: printableByteRatio
        )
    }
}

// MARK: - Analyst Database Models (.machproj SQLite WAL) & Undo/Redo

public struct UserBookmark: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let address: VirtualAddress
    public var label: String
    public var categoryTag: String
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        address: VirtualAddress,
        label: String,
        categoryTag: String = "Triage",
        createdAt: Date = Date()
    ) {
        self.id = id
        self.address = address
        self.label = label
        self.categoryTag = categoryTag
        self.createdAt = createdAt
    }
}

public struct UserInlineComment: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public var text: String
    public var isRepeatable: Bool
    public var updatedAt: Date

    public init(
        address: VirtualAddress,
        text: String,
        isRepeatable: Bool = false,
        updatedAt: Date = Date()
    ) {
        self.address = address
        self.text = text
        self.isRepeatable = isRepeatable
        self.updatedAt = updatedAt
    }
}

public struct UserSymbolRename: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let originalName: String
    public var customName: String
    public var signatureOverride: String?
    public var updatedAt: Date

    public init(
        address: VirtualAddress,
        originalName: String,
        customName: String,
        signatureOverride: String? = nil,
        updatedAt: Date = Date()
    ) {
        self.address = address
        self.originalName = originalName
        self.customName = customName
        self.signatureOverride = signatureOverride
        self.updatedAt = updatedAt
    }
}

public struct CustomStructField: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(offset):\(name)" }
    public let name: String
    public let offset: Int
    public let byteSize: Int
    public let typeExpr: CTypeExpr
    public let comment: String?

    public init(
        name: String,
        offset: Int,
        byteSize: Int,
        typeExpr: CTypeExpr,
        comment: String? = nil
    ) {
        self.name = name
        self.offset = offset
        self.byteSize = byteSize
        self.typeExpr = typeExpr
        self.comment = comment
    }
}

public struct CustomStructDefinition: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public var name: String
    public var totalByteSize: Int
    public var alignment: Int
    public var fields: [CustomStructField]
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        totalByteSize: Int,
        alignment: Int = 8,
        fields: [CustomStructField],
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.totalByteSize = totalByteSize
        self.alignment = alignment
        self.fields = fields
        self.updatedAt = updatedAt
    }
}

public enum AnalystMutationOperation: Sendable, Codable, Hashable {
    case setRename(previous: UserSymbolRename?, updated: UserSymbolRename?)
    case setComment(previous: UserInlineComment?, updated: UserInlineComment?)
    case setBookmark(previous: UserBookmark?, updated: UserBookmark?)
    case setPatch(previous: BytePatchRecord?, updated: BytePatchRecord?)
    case setStruct(previous: CustomStructDefinition?, updated: CustomStructDefinition?)

    public var inverted: AnalystMutationOperation {
        switch self {
        case .setRename(let prev, let next):
            return .setRename(previous: next, updated: prev)
        case .setComment(let prev, let next):
            return .setComment(previous: next, updated: prev)
        case .setBookmark(let prev, let next):
            return .setBookmark(previous: next, updated: prev)
        case .setPatch(let prev, let next):
            return .setPatch(previous: next, updated: prev)
        case .setStruct(let prev, let next):
            return .setStruct(previous: next, updated: prev)
        }
    }
}

public struct AnalystTransactionRecord: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let sequenceNumber: Int64
    public let title: String
    public let operation: AnalystMutationOperation
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        sequenceNumber: Int64 = 0,
        title: String,
        operation: AnalystMutationOperation,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.sequenceNumber = sequenceNumber
        self.title = title
        self.operation = operation
        self.createdAt = createdAt
    }
}
