import Foundation

// MARK: - Container Format & CPU Architecture

public enum BinaryContainerFormat: String, Sendable, Codable, Hashable, CaseIterable {
    case machO64 = "Mach-O 64"
    case universalFat = "Mach-O Universal Fat"
    case elf64 = "ELF 64-bit"
    case pe32Plus = "PE32+ (x64/ARM64)"
    case wasm = "WebAssembly 1.0"
    case rawBinary = "Raw Binary Blob"
}

public enum CPUArchitecture: Sendable, Codable, Hashable, CustomStringConvertible {
    case arm64
    case arm64e
    case x86_64
    case riscv64
    case wasm32
    case unknown(cpuType: Int32, cpuSubType: Int32)

    public var displayName: String {
        switch self {
        case .arm64: return "arm64"
        case .arm64e: return "arm64e (PAC)"
        case .x86_64: return "x86_64"
        case .riscv64: return "riscv64"
        case .wasm32: return "wasm32"
        case .unknown(let t, let s): return "cpu(\(t):\(s))"
        }
    }

    public var isARM64Family: Bool {
        switch self {
        case .arm64, .arm64e: return true
        default: return false
        }
    }

    public var description: String { displayName }
}

public struct UniversalArchSlice: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { index }
    public let index: Int
    public let architecture: CPUArchitecture
    public let cpuType: Int32
    public let cpuSubType: Int32
    public let fileOffset: FileOffset
    public let size: UInt64
    public let alignExponent: UInt32

    public init(
        index: Int,
        architecture: CPUArchitecture,
        cpuType: Int32,
        cpuSubType: Int32,
        fileOffset: FileOffset,
        size: UInt64,
        alignExponent: UInt32
    ) {
        self.index = index
        self.architecture = architecture
        self.cpuType = cpuType
        self.cpuSubType = cpuSubType
        self.fileOffset = fileOffset
        self.size = size
        self.alignExponent = alignExponent
    }
}

// MARK: - Memory Permissions, Segments, Sections

public struct MemoryPermissions: OptionSet, Sendable, Codable, Hashable, CustomStringConvertible {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let read = MemoryPermissions(rawValue: 1 << 0)
    public static let write = MemoryPermissions(rawValue: 1 << 1)
    public static let execute = MemoryPermissions(rawValue: 1 << 2)

    public var rwxString: String {
        let r = contains(.read) ? "r" : "-"
        let w = contains(.write) ? "w" : "-"
        let x = contains(.execute) ? "x" : "-"
        return "\(r)\(w)\(x)"
    }

    public var description: String { rwxString }
}

public enum BinarySectionKind: String, Sendable, Codable, Hashable, CaseIterable {
    case code = "Code"
    case stubs = "Import Stubs"
    case cstring = "C Strings"
    case constData = "Read-Only Data"
    case mutableData = "Mutable Data"
    case got = "GOT / Pointers"
    case objcMetadata = "ObjC Runtime"
    case swiftMetadata = "Swift Metadata"
    case unwindInfo = "Unwind / EH"
    case bss = "Zero-Fill BSS"
    case debug = "Debug / LinkEdit"
    case wasmCustom = "WASM Custom"
    case other = "Other"
}

public struct BinarySection: Sendable, Codable, Hashable, Identifiable {
    public let id: String
    public let index: Int
    public let segmentName: String
    public let sectionName: String
    public let vmAddress: VirtualAddress
    public let size: UInt64
    public let fileOffset: FileOffset
    public let alignment: UInt32
    public let flags: UInt32
    public let kind: BinarySectionKind
    public let permissions: MemoryPermissions
    public let shannonEntropy: Double

    public init(
        index: Int,
        segmentName: String,
        sectionName: String,
        vmAddress: VirtualAddress,
        size: UInt64,
        fileOffset: FileOffset,
        alignment: UInt32 = 4,
        flags: UInt32 = 0,
        kind: BinarySectionKind,
        permissions: MemoryPermissions = [.read],
        shannonEntropy: Double = 0.0
    ) {
        self.id = "\(index):\(segmentName).\(sectionName)"
        self.index = index
        self.segmentName = segmentName
        self.sectionName = sectionName
        self.vmAddress = vmAddress
        self.size = size
        self.fileOffset = fileOffset
        self.alignment = alignment
        self.flags = flags
        self.kind = kind
        self.permissions = permissions
        self.shannonEntropy = shannonEntropy
    }

    public var fullName: String {
        segmentName.isEmpty ? sectionName : "\(segmentName),\(sectionName)"
    }

    public var addressRange: AddressRange {
        AddressRange(start: vmAddress, size: size)
    }
}

public struct BinarySegment: Sendable, Codable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let vmAddress: VirtualAddress
    public let vmSize: UInt64
    public let fileOffset: FileOffset
    public let fileSize: UInt64
    public let initialProtection: MemoryPermissions
    public let maxProtection: MemoryPermissions
    public let flags: UInt32
    public let sections: [BinarySection]

    public init(
        name: String,
        vmAddress: VirtualAddress,
        vmSize: UInt64,
        fileOffset: FileOffset,
        fileSize: UInt64,
        initialProtection: MemoryPermissions,
        maxProtection: MemoryPermissions,
        flags: UInt32 = 0,
        sections: [BinarySection] = []
    ) {
        self.id = "\(name)@\(vmAddress.compactHexString)"
        self.name = name
        self.vmAddress = vmAddress
        self.vmSize = vmSize
        self.fileOffset = fileOffset
        self.fileSize = fileSize
        self.initialProtection = initialProtection
        self.maxProtection = maxProtection
        self.flags = flags
        self.sections = sections
    }

    public var addressRange: AddressRange {
        AddressRange(start: vmAddress, size: vmSize)
    }
}

// MARK: - Imports, Symbols, Strings, Fixups

public struct ImportedLibrary: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { ordinal }
    public let ordinal: Int
    public let installName: String
    public let currentVersion: String
    public let compatibilityVersion: String
    public let isWeak: Bool
    public let isReexport: Bool

    public init(
        ordinal: Int,
        installName: String,
        currentVersion: String = "0.0.0",
        compatibilityVersion: String = "0.0.0",
        isWeak: Bool = false,
        isReexport: Bool = false
    ) {
        self.ordinal = ordinal
        self.installName = installName
        self.currentVersion = currentVersion
        self.compatibilityVersion = compatibilityVersion
        self.isWeak = isWeak
        self.isReexport = isReexport
    }

    public var shortName: String {
        (installName as NSString).lastPathComponent
    }
}

public enum SymbolKind: String, Sendable, Codable, Hashable, CaseIterable {
    case function = "Function"
    case exportedEntry = "Exported Entry"
    case importedStub = "Imported Stub"
    case globalVariable = "Global Variable"
    case objcMethod = "ObjC Method"
    case swiftFunction = "Swift Function"
    case sectionLabel = "Section Label"
    case localSymbol = "Local Symbol"
}

public enum SymbolBinding: String, Sendable, Codable, Hashable, CaseIterable {
    case local = "Local"
    case global = "Global"
    case weak = "Weak"
    case external = "External"
}

public enum SymbolProvenance: String, Sendable, Codable, Hashable, CaseIterable {
    case symtab = "lc_symtab"
    case indirectSymtab = "lc_dysymtab"
    case exportTrie = "lc_dyld_exports_trie"
    case functionStarts = "lc_function_starts"
    case chainedFixups = "lc_dyld_chained_fixups"
    case objcMetadata = "objc_metadata"
    case swiftMetadata = "swift_metadata"
    case entryPoint = "lc_main_entry"
}

public struct BinarySymbol: Sendable, Codable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let demangledName: String
    public let kind: SymbolKind
    public let binding: SymbolBinding
    public let address: VirtualAddress
    public let size: UInt64
    public let sectionIndex: Int?
    public let libraryOrdinal: Int?
    public let provenance: SymbolProvenance

    public var isInferred: Bool {
        provenance != .symtab
    }

    public init(
        name: String,
        demangledName: String? = nil,
        kind: SymbolKind,
        binding: SymbolBinding = .global,
        address: VirtualAddress,
        size: UInt64 = 0,
        sectionIndex: Int? = nil,
        libraryOrdinal: Int? = nil,
        provenance: SymbolProvenance = .symtab
    ) {
        self.id = "\(address.hexString):\(name)"
        self.name = name
        self.demangledName = demangledName ?? name
        self.kind = kind
        self.binding = binding
        self.address = address
        self.size = size
        self.sectionIndex = sectionIndex
        self.libraryOrdinal = libraryOrdinal
        self.provenance = provenance
    }
}

public enum ExtractedStringEncoding: String, Sendable, Codable, Hashable {
    case ascii = "ASCII"
    case utf8 = "UTF-8"
    case utf16LE = "UTF-16LE"
    case objcSelector = "ObjC Selector"
}

public struct ExtractedStringLiteral: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let fileOffset: FileOffset
    public let encoding: ExtractedStringEncoding
    public let value: String
    public let sectionName: String
    public let lengthBytes: Int

    public init(
        address: VirtualAddress,
        fileOffset: FileOffset,
        encoding: ExtractedStringEncoding,
        value: String,
        sectionName: String,
        lengthBytes: Int
    ) {
        self.address = address
        self.fileOffset = fileOffset
        self.encoding = encoding
        self.value = value
        self.sectionName = sectionName
        self.lengthBytes = lengthBytes
    }
}

public enum ChainedFixupKind: String, Sendable, Codable, Hashable {
    case rebase = "DYLD_REBASE"
    case authRebase = "DYLD_AUTH_REBASE"
    case bind = "DYLD_BIND"
    case authBind = "DYLD_AUTH_BIND"
}

public struct ChainedFixupRecord: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { location.rawValue }
    public let location: VirtualAddress
    public let fileOffset: FileOffset
    public let kind: ChainedFixupKind
    public let targetAddress: VirtualAddress?
    public let symbolName: String?
    public let libraryOrdinal: Int?
    public let addend: Int64
    public let pacDiversity: UInt16?
    public let pacKey: String?

    public init(
        location: VirtualAddress,
        fileOffset: FileOffset,
        kind: ChainedFixupKind,
        targetAddress: VirtualAddress? = nil,
        symbolName: String? = nil,
        libraryOrdinal: Int? = nil,
        addend: Int64 = 0,
        pacDiversity: UInt16? = nil,
        pacKey: String? = nil
    ) {
        self.location = location
        self.fileOffset = fileOffset
        self.kind = kind
        self.targetAddress = targetAddress
        self.symbolName = symbolName
        self.libraryOrdinal = libraryOrdinal
        self.addend = addend
        self.pacDiversity = pacDiversity
        self.pacKey = pacKey
    }
}

// MARK: - Code Signature, ObjC & Swift Metadata

public enum EntitlementValue: Sendable, Codable, Hashable {
    case bool(Bool)
    case integer(Int64)
    case unsignedInteger(UInt64)
    case real(Double)
    case string(String)
    case data(Data)
    case date(String)
    case array([EntitlementValue])
    case dictionary([String: EntitlementValue])

    /// Converts this value into a Foundation object suitable for `JSONSerialization` and JavaScriptCore,
    /// keeping `Bool` (`CFBoolean`) distinct from integer `NSNumber`.
    public func toFoundationJSONObject() -> Any {
        switch self {
        case .bool(let b):
            return NSNumber(value: b)
        case .integer(let i):
            return NSNumber(value: i)
        case .unsignedInteger(let u):
            return NSNumber(value: u)
        case .real(let d):
            return NSNumber(value: d)
        case .string(let s):
            return s
        case .data(let raw):
            return raw.base64EncodedString()
        case .date(let iso):
            return iso
        case .array(let items):
            return items.map { $0.toFoundationJSONObject() }
        case .dictionary(let dict):
            return dict.mapValues { $0.toFoundationJSONObject() }
        }
    }

    /// Converts this value into a Foundation object suitable for `PropertyListSerialization`.
    public func toPropertyListObject() -> Any {
        switch self {
        case .bool(let b):
            return NSNumber(value: b)
        case .integer(let i):
            return NSNumber(value: i)
        case .unsignedInteger(let u):
            return NSNumber(value: u)
        case .real(let d):
            return NSNumber(value: d)
        case .string(let s):
            return s
        case .data(let raw):
            return raw
        case .date(let iso):
            return iso
        case .array(let items):
            return items.map { $0.toPropertyListObject() }
        case .dictionary(let dict):
            return dict.mapValues { $0.toPropertyListObject() }
        }
    }
}

public struct CodeSignatureSummary: Sendable, Codable, Hashable {
    public let isSigned: Bool
    public let isAdHoc: Bool
    public let identifier: String
    public let teamIdentifier: String?
    public let cdHashHex: String
    public let hashAlgorithm: String
    public let codeDirectoryVersion: UInt32
    public let pageSize: Int
    public let flags: UInt32
    public let entitlementsXML: String?
    public let entitlements: [String: EntitlementValue]
    public let cmsSignerCommonNames: [String]

    public init(
        isSigned: Bool,
        isAdHoc: Bool = false,
        identifier: String = "",
        teamIdentifier: String? = nil,
        cdHashHex: String = "",
        hashAlgorithm: String = "SHA-256",
        codeDirectoryVersion: UInt32 = 0,
        pageSize: Int = 4096,
        flags: UInt32 = 0,
        entitlementsXML: String? = nil,
        entitlements: [String: EntitlementValue] = [:],
        cmsSignerCommonNames: [String] = []
    ) {
        self.isSigned = isSigned
        self.isAdHoc = isAdHoc
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.cdHashHex = cdHashHex
        self.hashAlgorithm = hashAlgorithm
        self.codeDirectoryVersion = codeDirectoryVersion
        self.pageSize = pageSize
        self.flags = flags
        self.entitlementsXML = entitlementsXML
        self.entitlements = entitlements
        self.cmsSignerCommonNames = cmsSignerCommonNames
    }

    public func entitlementsJSONObject() -> [String: Any] {
        entitlements.mapValues { $0.toFoundationJSONObject() }
    }

    public static let unsigned = CodeSignatureSummary(isSigned: false)
}

public struct ObjCMethodMetadata: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(isClassMethod ? "+" : "-")\(selector)@\(implementationAddress.compactHexString)" }
    public let selector: String
    public let typeEncoding: String
    public let implementationAddress: VirtualAddress
    public let isClassMethod: Bool

    public init(
        selector: String,
        typeEncoding: String,
        implementationAddress: VirtualAddress,
        isClassMethod: Bool = false
    ) {
        self.selector = selector
        self.typeEncoding = typeEncoding
        self.implementationAddress = implementationAddress
        self.isClassMethod = isClassMethod
    }
}

public struct ObjCIvarMetadata: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(name)@\(offset)" }
    public let name: String
    public let typeEncoding: String
    public let offset: UInt32
    public let size: UInt32

    public init(name: String, typeEncoding: String, offset: UInt32, size: UInt32) {
        self.name = name
        self.typeEncoding = typeEncoding
        self.offset = offset
        self.size = size
    }
}

public struct ObjCClassMetadata: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(name)@\(address.compactHexString)" }
    public let name: String
    public let superclassName: String?
    public let address: VirtualAddress
    public let instanceSize: UInt32
    public let flags: UInt32
    public let methods: [ObjCMethodMetadata]
    public let ivars: [ObjCIvarMetadata]
    public let adoptedProtocols: [String]

    public init(
        name: String,
        superclassName: String? = nil,
        address: VirtualAddress,
        instanceSize: UInt32 = 0,
        flags: UInt32 = 0,
        methods: [ObjCMethodMetadata] = [],
        ivars: [ObjCIvarMetadata] = [],
        adoptedProtocols: [String] = []
    ) {
        self.name = name
        self.superclassName = superclassName
        self.address = address
        self.instanceSize = instanceSize
        self.flags = flags
        self.methods = methods
        self.ivars = ivars
        self.adoptedProtocols = adoptedProtocols
    }
}

public struct ObjCCategoryMetadata: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(className)(\(name))@\(address.compactHexString)" }
    public let name: String
    public let className: String
    public let address: VirtualAddress
    public let instanceMethods: [ObjCMethodMetadata]
    public let classMethods: [ObjCMethodMetadata]
    public let adoptedProtocols: [String]

    public init(
        name: String,
        className: String,
        address: VirtualAddress = .zero,
        instanceMethods: [ObjCMethodMetadata] = [],
        classMethods: [ObjCMethodMetadata] = [],
        adoptedProtocols: [String] = []
    ) {
        self.name = name
        self.className = className
        self.address = address
        self.instanceMethods = instanceMethods
        self.classMethods = classMethods
        self.adoptedProtocols = adoptedProtocols
    }
}

public struct ObjCProtocolMetadata: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(name)@\(address.compactHexString)" }
    public let name: String
    public let address: VirtualAddress
    public let adoptedProtocols: [String]
    public let instanceMethods: [ObjCMethodMetadata]
    public let classMethods: [ObjCMethodMetadata]
    public let optionalInstanceMethods: [ObjCMethodMetadata]
    public let optionalClassMethods: [ObjCMethodMetadata]

    public init(
        name: String,
        address: VirtualAddress = .zero,
        adoptedProtocols: [String] = [],
        instanceMethods: [ObjCMethodMetadata] = [],
        classMethods: [ObjCMethodMetadata] = [],
        optionalInstanceMethods: [ObjCMethodMetadata] = [],
        optionalClassMethods: [ObjCMethodMetadata] = []
    ) {
        self.name = name
        self.address = address
        self.adoptedProtocols = adoptedProtocols
        self.instanceMethods = instanceMethods
        self.classMethods = classMethods
        self.optionalInstanceMethods = optionalInstanceMethods
        self.optionalClassMethods = optionalClassMethods
    }
}

public enum SwiftTypeDescriptorKind: String, Sendable, Codable, Hashable {
    case structType = "Struct"
    case classType = "Class"
    case enumType = "Enum"
    case protocolType = "Protocol"
}

public struct SwiftTypeDescriptor: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(mangledName)@\(address.compactHexString)" }
    public let mangledName: String
    public let demangledName: String
    public let kind: SwiftTypeDescriptorKind
    public let address: VirtualAddress
    public let fieldNames: [String]
    public let fieldTypes: [String]

    public init(
        mangledName: String,
        demangledName: String,
        kind: SwiftTypeDescriptorKind,
        address: VirtualAddress,
        fieldNames: [String] = [],
        fieldTypes: [String] = []
    ) {
        self.mangledName = mangledName
        self.demangledName = demangledName
        self.kind = kind
        self.address = address
        self.fieldNames = fieldNames
        self.fieldTypes = fieldTypes
    }
}

// MARK: - Aggregate Loaded Binary Image

public struct LoadedBinaryImage: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let fileName: String
    public let filePath: String
    public let fileSize: UInt64
    public let sha256Hex: String
    public let containerFormat: BinaryContainerFormat
    public let selectedSliceIndex: Int
    public let slices: [UniversalArchSlice]
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
    public let functionStarts: [VirtualAddress]
    public let segments: [BinarySegment]
    public let sections: [BinarySection]
    public let dylibInstallID: ImportedLibrary?
    public let importedLibraries: [ImportedLibrary]
    public let symbols: [BinarySymbol]
    public let strings: [ExtractedStringLiteral]
    public let chainedFixups: [ChainedFixupRecord]
    public let codeSignature: CodeSignatureSummary
    public let objcClasses: [ObjCClassMetadata]
    public let objcCategories: [ObjCCategoryMetadata]
    public let objcProtocols: [ObjCProtocolMetadata]
    public let swiftTypes: [SwiftTypeDescriptor]
    public let overallEntropy: Double

    public init(
        id: UUID = UUID(),
        fileName: String,
        filePath: String,
        fileSize: UInt64,
        sha256Hex: String,
        containerFormat: BinaryContainerFormat,
        selectedSliceIndex: Int = 0,
        slices: [UniversalArchSlice] = [],
        sliceFileOffset: FileOffset = .zero,
        architecture: CPUArchitecture,
        endianness: BinaryEndianness = .little,
        isPositionIndependent: Bool = true,
        imageBase: VirtualAddress,
        entryPoint: VirtualAddress? = nil,
        uuidString: String? = nil,
        platformName: String = "macOS",
        minOSVersion: String = "14.0",
        sdkVersion: String = "15.0",
        functionStarts: [VirtualAddress] = [],
        segments: [BinarySegment],
        sections: [BinarySection],
        dylibInstallID: ImportedLibrary? = nil,
        importedLibraries: [ImportedLibrary] = [],
        symbols: [BinarySymbol] = [],
        strings: [ExtractedStringLiteral] = [],
        chainedFixups: [ChainedFixupRecord] = [],
        codeSignature: CodeSignatureSummary = .unsigned,
        objcClasses: [ObjCClassMetadata] = [],
        objcCategories: [ObjCCategoryMetadata] = [],
        objcProtocols: [ObjCProtocolMetadata] = [],
        swiftTypes: [SwiftTypeDescriptor] = [],
        overallEntropy: Double = 0.0
    ) {
        self.id = id
        self.fileName = fileName
        self.filePath = filePath
        self.fileSize = fileSize
        self.sha256Hex = sha256Hex
        self.containerFormat = containerFormat
        self.selectedSliceIndex = selectedSliceIndex
        self.slices = slices
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
        self.functionStarts = functionStarts
        self.segments = segments
        self.sections = sections
        self.dylibInstallID = dylibInstallID
        self.importedLibraries = importedLibraries
        self.symbols = symbols
        self.strings = strings
        self.chainedFixups = chainedFixups
        self.codeSignature = codeSignature
        self.objcClasses = objcClasses
        self.objcCategories = objcCategories
        self.objcProtocols = objcProtocols
        self.swiftTypes = swiftTypes
        self.overallEntropy = overallEntropy
    }

    /// Translates a virtual address to an absolute file offset (accounting for Fat slice offset).
    public func fileOffset(for vmAddress: VirtualAddress) -> FileOffset? {
        for sec in sections where sec.kind != .bss && sec.size > 0 {
            if sec.addressRange.contains(vmAddress) {
                let delta = vmAddress.rawValue - sec.vmAddress.rawValue
                return FileOffset(sliceFileOffset.rawValue + sec.fileOffset.rawValue + delta)
            }
        }
        for seg in segments where seg.fileSize > 0 {
            let fileBackedRange = AddressRange(start: seg.vmAddress, size: min(seg.vmSize, seg.fileSize))
            if fileBackedRange.contains(vmAddress) {
                let delta = vmAddress.rawValue - seg.vmAddress.rawValue
                return FileOffset(sliceFileOffset.rawValue + seg.fileOffset.rawValue + delta)
            }
        }
        return nil
    }

    /// Translates an absolute file offset to a virtual address within the active slice.
    public func virtualAddress(for absoluteOffset: FileOffset) -> VirtualAddress? {
        guard absoluteOffset.rawValue >= sliceFileOffset.rawValue else { return nil }
        let localOffset = absoluteOffset.rawValue - sliceFileOffset.rawValue
        for sec in sections where sec.kind != .bss && sec.size > 0 {
            if localOffset >= sec.fileOffset.rawValue && localOffset < (sec.fileOffset.rawValue + sec.size) {
                let delta = localOffset - sec.fileOffset.rawValue
                return sec.vmAddress.adding(delta)
            }
        }
        for seg in segments where seg.fileSize > 0 {
            if localOffset >= seg.fileOffset.rawValue && localOffset < (seg.fileOffset.rawValue + seg.fileSize) {
                let delta = localOffset - seg.fileOffset.rawValue
                return seg.vmAddress.adding(delta)
            }
        }
        return nil
    }

    public func section(containing vmAddress: VirtualAddress) -> BinarySection? {
        sections.first { $0.addressRange.contains(vmAddress) }
    }

    public func executableSections() -> [BinarySection] {
        switch containerFormat {
        case .machO64, .universalFat:
            let instructionAttrMask: UInt32 = 0x8000_0400 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
            return sections.filter { ($0.flags & instructionAttrMask) != 0 && $0.size > 0 }
        default:
            return sections.filter { ($0.kind == .code || $0.kind == .stubs || $0.permissions.contains(.execute)) && $0.size > 0 }
        }
    }

    public func exactSymbol(at vmAddress: VirtualAddress) -> BinarySymbol? {
        symbols.first { $0.address == vmAddress }
    }

    public func nearestSymbol(atOrBefore vmAddress: VirtualAddress) -> (symbol: BinarySymbol, delta: UInt64)? {
        var best: BinarySymbol?
        for sym in symbols where sym.address <= vmAddress {
            if let current = best {
                if sym.address > current.address {
                    best = sym
                }
            } else {
                best = sym
            }
        }
        guard let matched = best else { return nil }
        return (matched, vmAddress.rawValue - matched.address.rawValue)
    }
}
