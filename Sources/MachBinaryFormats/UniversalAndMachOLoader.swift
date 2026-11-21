import Foundation
import MachGraphModels

// MARK: - Mach-O 64 & Universal Binary Constants

public enum MachOConstants {
    // Universal Fat Magics (Big-Endian canonical)
    public static let fatMagic: UInt32       = 0xCAFE_BABE
    public static let fatCigam: UInt32       = 0xBEBA_FECA
    public static let fatMagic64: UInt32     = 0xCAFE_BABF
    public static let fatCigam64: UInt32     = 0xBFBA_FECA

    // Mach-O Magics
    public static let mhMagic64: UInt32      = 0xFEED_FACF
    public static let mhCigam64: UInt32      = 0xCFFA_EDFE
    public static let mhMagic32: UInt32      = 0xFEED_FACE
    public static let mhCigam32: UInt32      = 0xCEFA_EDFE

    // CPU Types & Subtypes
    public static let cpuArchABI64: Int32    = 0x0100_0000
    public static let cpuTypeX86_64: Int32   = 0x0100_0007
    public static let cpuTypeARM64: Int32    = 0x0100_000C
    public static let cpuTypeRISCV64: Int32  = 0x0100_0018

    public static let cpuSubTypeARM64All: Int32 = 0
    public static let cpuSubTypeARM64V8: Int32  = 1
    public static let cpuSubTypeARM64E: Int32   = 2
    public static let cpuSubTypeX86_64All: Int32 = 3
    public static let cpuSubTypeMask: UInt32    = 0x00FF_FFFF

    // Mach-O File Types
    public static let mhObject: UInt32       = 0x1
    public static let mhExecute: UInt32      = 0x2
    public static let mhFvmLib: UInt32       = 0x3
    public static let mhCore: UInt32         = 0x4
    public static let mhPreload: UInt32      = 0x5
    public static let mhDylib: UInt32        = 0x6
    public static let mhDylinker: UInt32     = 0x7
    public static let mhBundle: UInt32       = 0x8
    public static let mhDylibStub: UInt32    = 0x9
    public static let mhDsym: UInt32         = 0xA
    public static let mhKextBundle: UInt32   = 0xB
    public static let mhFileset: UInt32      = 0xC

    // Mach-O Header Flags
    public static let mhNoUndefs: UInt32     = 0x0000_0001
    public static let mhDyldLink: UInt32     = 0x0000_0004
    public static let mhTwoLevel: UInt32     = 0x0000_0080
    public static let mhBindsToWeak: UInt32  = 0x0000_8000
    public static let mhAllowStackExecution: UInt32 = 0x0002_0000
    public static let mhPIE: UInt32          = 0x0020_0000
    public static let mhHasTLVDescriptors: UInt32 = 0x0080_0000
    public static let mhNoHeapExecution: UInt32   = 0x0100_0000

    // Load Command Identifiers
    public static let lcReqDyld: UInt32              = 0x8000_0000
    public static let lcSymtab: UInt32               = 0x0000_0002
    public static let lcUnixThread: UInt32           = 0x0000_0005
    public static let lcDysymtab: UInt32             = 0x0000_000B
    public static let lcLoadDylib: UInt32            = 0x0000_000C
    public static let lcIdDylib: UInt32              = 0x0000_000D
    public static let lcLoadDylinker: UInt32         = 0x0000_000E
    public static let lcSubFramework: UInt32         = 0x0000_0012
    public static let lcSegment64: UInt32            = 0x0000_0019
    public static let lcUUID: UInt32                 = 0x0000_001B
    public static let lcRpath: UInt32                = 0x8000_001C
    public static let lcCodeSignature: UInt32        = 0x0000_001D
    public static let lcSegmentSplitInfo: UInt32     = 0x0000_001E
    public static let lcReexportDylib: UInt32        = 0x8000_001F
    public static let lcLazyLoadDylib: UInt32        = 0x0000_0020
    public static let lcEncryptionInfo: UInt32       = 0x0000_0021
    public static let lcDyldInfo: UInt32             = 0x0000_0022
    public static let lcDyldInfoOnly: UInt32         = 0x8000_0022
    public static let lcLoadWeakDylib: UInt32        = 0x8000_0018
    public static let lcLoadUpwardDylib: UInt32      = 0x8000_0023
    public static let lcVersionMinMacOSX: UInt32     = 0x0000_0024
    public static let lcVersionMinIPhoneOS: UInt32   = 0x0000_0025
    public static let lcFunctionStarts: UInt32       = 0x0000_0026
    public static let lcMain: UInt32                 = 0x8000_0028
    public static let lcDataInCode: UInt32           = 0x0000_0029
    public static let lcSourceVersion: UInt32        = 0x0000_002A
    public static let lcEncryptionInfo64: UInt32     = 0x0000_002C
    public static let lcVersionMinTVOS: UInt32       = 0x0000_002F
    public static let lcVersionMinWatchOS: UInt32    = 0x0000_0030
    public static let lcBuildVersion: UInt32         = 0x0000_0032
    public static let lcDyldExportsTrie: UInt32      = 0x8000_0033
    public static let lcDyldChainedFixups: UInt32    = 0x8000_0034
    public static let lcFilesetEntry: UInt32         = 0x8000_0035

    // VM Protections
    public static let vmProtRead: Int32      = 0x01
    public static let vmProtWrite: Int32     = 0x02
    public static let vmProtExecute: Int32   = 0x04

    // Section Types & Attributes
    public static let sectionTypeMask: UInt32             = 0x0000_00FF
    public static let sRegular: UInt32                    = 0x00
    public static let sZerofill: UInt32                   = 0x01
    public static let sCStringLiterals: UInt32            = 0x02
    public static let s4ByteLiterals: UInt32              = 0x03
    public static let s8ByteLiterals: UInt32              = 0x04
    public static let sLiteralPointers: UInt32            = 0x05
    public static let sNonLazySymbolPointers: UInt32      = 0x06
    public static let sLazySymbolPointers: UInt32         = 0x07
    public static let sSymbolStubs: UInt32                = 0x08
    public static let sModInitFuncPointers: UInt32        = 0x09
    public static let sModTermFuncPointers: UInt32        = 0x0A
    public static let sCoalesced: UInt32                  = 0x0B
    public static let sGBZerofill: UInt32                 = 0x0C
    public static let sLazyDylibSymbolPointers: UInt32    = 0x10
    public static let sThreadLocalRegular: UInt32         = 0x11
    public static let sThreadLocalZerofill: UInt32        = 0x12
    public static let sThreadLocalVariables: UInt32       = 0x13
    public static let sInitFuncOffsets: UInt32            = 0x16

    public static let sAttrPureInstructions: UInt32       = 0x8000_0000
    public static let sAttrSomeInstructions: UInt32       = 0x0000_0400

    // Symbol Table (nlist_64) Masks
    public static let nStab: UInt8           = 0xE0
    public static let nPext: UInt8           = 0x10
    public static let nType: UInt8           = 0x0E
    public static let nExt: UInt8            = 0x01

    public static let nUndf: UInt8           = 0x00
    public static let nAbs: UInt8            = 0x02
    public static let nSect: UInt8           = 0x0E
    public static let nPbud: UInt8           = 0x0C
    public static let nIndr: UInt8           = 0x0A

    public static let nWeakRef: UInt16       = 0x0040
    public static let nWeakDef: UInt16       = 0x0080
    public static let nArmThumbDef: UInt16   = 0x0008
    public static let nSymbolResolver: UInt16 = 0x0100

    // Indirect Symbol Special Sentinels
    public static let indirectSymbolLocal: UInt32 = 0x8000_0000
    public static let indirectSymbolAbs: UInt32   = 0x4000_0000

    // Thread Flavors
    public static let armThreadState64: UInt32 = 6
    public static let x86ThreadState64: UInt32 = 4

    public static func mapArchitecture(cpuType: Int32, cpuSubType: Int32) -> CPUArchitecture {
        let maskedSubType = Int32(bitPattern: UInt32(bitPattern: cpuSubType) & cpuSubTypeMask)
        switch cpuType {
        case cpuTypeARM64:
            if maskedSubType == cpuSubTypeARM64E {
                return .arm64e
            }
            return .arm64
        case cpuTypeX86_64:
            return .x86_64
        case cpuTypeRISCV64:
            return .riscv64
        default:
            return .unknown(cpuType: cpuType, cpuSubType: cpuSubType)
        }
    }

    public static func mapPermissions(_ vmProt: Int32) -> MemoryPermissions {
        var perms: MemoryPermissions = []
        if (vmProt & vmProtRead) != 0 { perms.insert(.read) }
        if (vmProt & vmProtWrite) != 0 { perms.insert(.write) }
        if (vmProt & vmProtExecute) != 0 { perms.insert(.execute) }
        return perms
    }

    public static func formatPackedVersion(_ raw: UInt32) -> String {
        let major = (raw >> 16) & 0xFFFF
        let minor = (raw >> 8) & 0xFF
        let patch = raw & 0xFF
        if patch == 0 {
            return "\(major).\(minor)"
        }
        return "\(major).\(minor).\(patch)"
    }

    public static func formatDylibVersion(_ raw: UInt32) -> String {
        let major = (raw >> 16) & 0xFFFF
        let minor = (raw >> 8) & 0xFF
        let patch = raw & 0xFF
        return "\(major).\(minor).\(patch)"
    }

    public static func platformDisplayName(_ platformID: UInt32) -> String {
        switch platformID {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 5: return "bridgeOS"
        case 6: return "Mac Catalyst"
        case 7: return "iOS Simulator"
        case 8: return "tvOS Simulator"
        case 9: return "watchOS Simulator"
        case 10: return "DriverKit"
        case 11: return "visionOS"
        case 12: return "visionOS Simulator"
        default: return "Darwin(\(platformID))"
        }
    }

    public static func classifySection(segmentName: String, sectionName: String, flags: UInt32, permissions: MemoryPermissions) -> BinarySectionKind {
        let secType = flags & sectionTypeMask
        let hasInsnAttr = (flags & (sAttrPureInstructions | sAttrSomeInstructions)) != 0
        let lowerSeg = segmentName.lowercased()
        let lowerSec = sectionName.lowercased()

        if secType == sZerofill || secType == sGBZerofill || secType == sThreadLocalZerofill || lowerSec == "__bss" || lowerSec == "__common" {
            return .bss
        }
        if secType == sSymbolStubs || (hasInsnAttr && (lowerSec.contains("stubs") || lowerSec == "__plt")) {
            return .stubs
        }
        if secType == sCStringLiterals || lowerSec == "__cstring" || lowerSec == "__ustring" || lowerSec == "__oslogstring" {
            return .cstring
        }
        if secType == sNonLazySymbolPointers || secType == sLazySymbolPointers || secType == sLazyDylibSymbolPointers
            || lowerSec == "__got" || lowerSec == "__auth_got" || lowerSec == "__la_symbol_ptr" || lowerSec == "__nl_symbol_ptr" || lowerSec == "__auth_ptr" {
            return .got
        }
        if lowerSec.hasPrefix("__objc_") {
            return .objcMetadata
        }
        if lowerSec.hasPrefix("__swift5_") || lowerSec.hasPrefix("__swift_") {
            return .swiftMetadata
        }
        if lowerSec == "__unwind_info" || lowerSec == "__eh_frame" || lowerSec == "__compact_unwind" || lowerSec == "__gcc_except_tab" {
            return .unwindInfo
        }
        if lowerSeg == "__linkedit" || lowerSeg == "__dwarf" || lowerSec.contains("debug") {
            return .debug
        }
        if hasInsnAttr {
            return .code
        }
        if lowerSeg == "__data_const" || lowerSec == "__const" || (lowerSeg == "__text" && !permissions.contains(.write)) {
            return .constData
        }
        if permissions.contains(.write) || lowerSeg.hasPrefix("__data") {
            return .mutableData
        }
        return .other
    }
}

// MARK: - Pure-Swift Swift 5 / Itanium C++ / C Symbol Demangler

public enum MachOSymbolDemangler {
    private struct CharacterCursor {
        let chars: [Character]
        private(set) var index: Int = 0

        init(_ text: String) {
            self.chars = Array(text)
        }

        var isAtEnd: Bool { index >= chars.count }

        func peek(_ offset: Int = 0) -> Character? {
            let pos = index + offset
            guard pos >= 0 && pos < chars.count else { return nil }
            return chars[pos]
        }

        mutating func advance(_ count: Int = 1) {
            guard count > 0 else { return }
            index = min(chars.count, index + count)
        }

        mutating func restore(_ savedIndex: Int) {
            index = max(0, min(chars.count, savedIndex))
        }

        mutating func readLengthPrefixedIdentifier(maxLength: Int = 4096) -> String? {
            let saved = index
            guard let first = peek(), first.isASCII, first.isNumber, first != "0" else {
                return nil
            }
            var length = 0
            while let ch = peek(), ch.isASCII, let digit = ch.wholeNumberValue {
                length = length * 10 + digit
                advance()
                if length > maxLength {
                    restore(saved)
                    return nil
                }
            }
            guard length > 0, index + length <= chars.count else {
                restore(saved)
                return nil
            }
            let result = String(chars[index..<(index + length)])
            advance(length)
            return result
        }
    }

    public static func demangle(_ rawName: String) -> String {
        guard !rawName.isEmpty else { return rawName }

        // Preserve ObjC method formatting directly
        if rawName.hasPrefix("-[") || rawName.hasPrefix("+[") {
            return rawName
        }

        // Swift 5+ and Swift 4 mangled names (_$s..., $s..., _$S..., $S..., __T0..., _T0...)
        for swiftPrefix in ["_$s", "$s", "_$S", "$S", "__T0", "_T0"] {
            if rawName.hasPrefix(swiftPrefix) {
                let body = String(rawName.dropFirst(swiftPrefix.count))
                if let swiftDemangled = demangleSwift5Body(body), !swiftDemangled.isEmpty {
                    return swiftDemangled
                }
                return rawName
            }
        }

        // Preserve truncated Swift / special '$' symbol prefixes (e.g. "_$") untouched
        if rawName.hasPrefix("_$") {
            return rawName
        }

        // Itanium C++ ABI (__Z... or _Z...)
        if rawName.hasPrefix("__Z") {
            let body = String(rawName.dropFirst(3))
            if let cppDemangled = demangleItaniumCPP(body), !cppDemangled.isEmpty {
                return cppDemangled
            }
            return rawName
        }
        if rawName.hasPrefix("_Z") {
            let body = String(rawName.dropFirst(2))
            if let cppDemangled = demangleItaniumCPP(body), !cppDemangled.isEmpty {
                return cppDemangled
            }
            if let first = body.first {
                if first.isASCII && (first.isNumber || "NSTGZL".contains(first)) {
                    return rawName
                }
            } else {
                return rawName
            }
        }

        // Strip Mach-O single leading C ABI underscore (preserve __ internal prefixes like __mh_execute_header)
        if rawName.hasPrefix("_") && !rawName.hasPrefix("__") && rawName.count > 1 {
            return String(rawName.dropFirst())
        }

        return rawName
    }

    private static func consumeKnownSwiftType(_ cursor: inout CharacterCursor) -> String? {
        let saved = cursor.index
        guard let ch = cursor.peek() else { return nil }

        if ch == "S", let next = cursor.peek(1) {
            switch next {
            case "i": cursor.advance(2); return "Int"
            case "u": cursor.advance(2); return "UInt"
            case "S": cursor.advance(2); return "String"
            case "b": cursor.advance(2); return "Bool"
            case "d": cursor.advance(2); return "Double"
            case "f": cursor.advance(2); return "Float"
            case "v": cursor.advance(2); return "UnsafeMutableRawPointer"
            case "V": cursor.advance(2); return "UnsafeRawPointer"
            case "P": cursor.advance(2); return "UnsafePointer"
            case "p": cursor.advance(2); return "UnsafeMutablePointer"
            case "q": cursor.advance(2); return "Optional"
            case "a": cursor.advance(2); return "Array"
            case "D": cursor.advance(2); return "Dictionary"
            case "h": cursor.advance(2); return "Set"
            default: break
            }
        }

        if ch == "s" {
            cursor.advance()
            if let stdName = cursor.readLengthPrefixedIdentifier(),
               let kind = cursor.peek(),
               "VCOP".contains(kind) {
                cursor.advance()
                return "Swift.\(stdName)"
            }
            cursor.restore(saved)
            return nil
        }

        if ch == "y" {
            if cursor.peek(1) == "t" {
                cursor.advance(2)
            } else {
                cursor.advance()
            }
            return "Void"
        }

        return nil
    }

    private static func parseMetadataSuffix(_ cursor: inout CharacterCursor) -> String? {
        let saved = cursor.index
        guard let ch = cursor.peek() else { return nil }
        if ch == "M" {
            cursor.advance()
            guard let sub = cursor.peek() else {
                cursor.restore(saved)
                return nil
            }
            let tag: String?
            switch sub {
            case "a": tag = " (type metadata accessor)"
            case "n": tag = " (nominal type descriptor)"
            case "f": tag = " (full type metadata)"
            case "N": tag = " (type metadata)"
            default:  tag = nil
            }
            guard let resolved = tag else {
                cursor.restore(saved)
                return nil
            }
            cursor.advance()
            return resolved
        }
        if ch == "N" {
            cursor.advance()
            return " (type metadata)"
        }
        return nil
    }

    private static func demangleSwift5Body(_ body: String) -> String? {
        var cursor = CharacterCursor(body)
        guard !cursor.isAtEnd else { return nil }

        // Standard library nominal type (`$ss6UInt64V`, `$ss6UInt64VMn`, etc.)
        if cursor.peek() == "s" {
            if let stdType = consumeKnownSwiftType(&cursor) {
                if cursor.isAtEnd {
                    return stdType
                }
                if let meta = parseMetadataSuffix(&cursor), cursor.isAtEnd {
                    return stdType + meta
                }
            }
            return nil
        }

        guard let moduleName = cursor.readLengthPrefixedIdentifier() else {
            return nil
        }

        var components: [String] = [moduleName]
        var hasCompleteEntity = false
        var suffixTag: String?
        var paramTypes: [String] = []
        var returnType: String?

        var iterations = 0
        while !cursor.isAtEnd {
            iterations += 1
            if iterations > 64 {
                return nil
            }

            if let ident = cursor.readLengthPrefixedIdentifier() {
                guard let kindChar = cursor.peek() else {
                    // Bare identifier at EOF without nominal/function/variable kind is truncated
                    return nil
                }
                switch kindChar {
                case "V", "C", "O", "P":
                    cursor.advance()
                    components.append(ident)
                    hasCompleteEntity = true
                case "F":
                    cursor.advance()
                    components.append(ident)
                    hasCompleteEntity = true
                    while !cursor.isAtEnd {
                        guard let t = consumeKnownSwiftType(&cursor) else {
                            return nil
                        }
                        if returnType == nil {
                            returnType = t
                        } else {
                            paramTypes.append(t)
                        }
                    }
                case "v":
                    cursor.advance()
                    guard let acc = cursor.peek() else { return nil }
                    switch acc {
                    case "g": suffixTag = ".getter"
                    case "s": suffixTag = ".setter"
                    case "M": suffixTag = ".modify"
                    case "p": suffixTag = " (property descriptor)"
                    default:  return nil
                    }
                    cursor.advance()
                    guard cursor.isAtEnd else { return nil }
                    components.append(ident)
                    hasCompleteEntity = true
                default:
                    return nil
                }
            } else if hasCompleteEntity {
                if let meta = parseMetadataSuffix(&cursor), cursor.isAtEnd {
                    suffixTag = meta
                } else if cursor.peek() == "C", cursor.peek(1) == "f" {
                    cursor.advance(2)
                    guard cursor.isAtEnd else { return nil }
                    suffixTag = ".init"
                } else if cursor.peek() == "f", cursor.peek(1) == "D" {
                    cursor.advance(2)
                    guard cursor.isAtEnd else { return nil }
                    suffixTag = ".deinit"
                } else {
                    return nil
                }
            } else {
                return nil
            }
        }

        guard cursor.isAtEnd, hasCompleteEntity, !components.isEmpty else {
            return nil
        }

        var qualified = components.joined(separator: ".")
        if let tag = suffixTag {
            qualified += tag
        } else if !paramTypes.isEmpty || returnType != nil {
            let paramsJoined = paramTypes.filter { $0 != "Void" }.joined(separator: ", ")
            if let ret = returnType, ret != "Void" {
                qualified += "(\(paramsJoined)) -> \(ret)"
            } else {
                qualified += "(\(paramsJoined))"
            }
        }
        return qualified
    }

    private static func demangleItaniumCPP(_ body: String) -> String? {
        var cursor = CharacterCursor(body)
        guard !cursor.isAtEnd else { return nil }

        var isNested = false
        var isConstMethod = false
        var closedNested = false
        var parts: [String] = []

        if cursor.peek() == "N" {
            isNested = true
            cursor.advance()
            while let q = cursor.peek(), (q == "K" || q == "V") {
                if q == "K" { isConstMethod = true }
                cursor.advance()
            }
        }

        var nameSteps = 0
        while !cursor.isAtEnd {
            nameSteps += 1
            if nameSteps > 128 { return nil }

            if isNested && cursor.peek() == "E" {
                cursor.advance()
                closedNested = true
                break
            }
            if cursor.peek() == "S" && cursor.peek(1) == "t" {
                cursor.advance(2)
                parts.append("std")
                continue
            }
            if cursor.peek() == "C", let v = cursor.peek(1), "123".contains(v), let last = parts.last {
                cursor.advance(2)
                parts.append(last)
                if !isNested { break }
                continue
            }
            if cursor.peek() == "D", let v = cursor.peek(1), "012".contains(v), let last = parts.last {
                cursor.advance(2)
                parts.append("~\(last)")
                if !isNested { break }
                continue
            }
            if cursor.peek() == "I" {
                guard let lastIdx = parts.indices.last else { return nil }
                cursor.advance()
                var depth = 1
                while !cursor.isAtEnd && depth > 0 {
                    if let ch = cursor.peek() {
                        if ch == "I" { depth += 1 }
                        else if ch == "E" { depth -= 1 }
                    }
                    cursor.advance()
                }
                guard depth == 0 else { return nil }
                parts[lastIdx] += "<...>"
                if !isNested { break }
                continue
            }
            if let part = cursor.readLengthPrefixedIdentifier() {
                parts.append(part)
                if !isNested { break }
            } else {
                return nil
            }
        }

        guard !parts.isEmpty else { return nil }
        if isNested && !closedNested { return nil }

        let joinedName = parts.joined(separator: "::")
        if cursor.isAtEnd {
            let constSuffix = isConstMethod ? " const" : ""
            return "\(joinedName)\(constSuffix)"
        }

        var params: [String] = []
        while !cursor.isAtEnd {
            if params.count >= 64 { return nil }
            var prefix = ""
            while let q = cursor.peek(), "PKR".contains(q) {
                switch q {
                case "P": prefix = "*" + prefix
                case "R": prefix = "&" + prefix
                case "K": prefix = "const " + prefix
                default: break
                }
                cursor.advance()
            }
            guard let tChar = cursor.peek() else { return nil }
            let base: String?
            var isVoidAlone = false
            switch tChar {
            case "v":
                cursor.advance()
                if params.isEmpty && prefix.isEmpty && cursor.isAtEnd {
                    isVoidAlone = true
                    base = nil
                } else {
                    base = "void"
                }
            case "b": cursor.advance(); base = "bool"
            case "c", "a": cursor.advance(); base = "char"
            case "h": cursor.advance(); base = "uint8_t"
            case "s": cursor.advance(); base = "int16_t"
            case "t": cursor.advance(); base = "uint16_t"
            case "i": cursor.advance(); base = "int"
            case "j": cursor.advance(); base = "unsigned int"
            case "l": cursor.advance(); base = "long"
            case "m": cursor.advance(); base = "unsigned long"
            case "x": cursor.advance(); base = "int64_t"
            case "y": cursor.advance(); base = "uint64_t"
            case "f": cursor.advance(); base = "float"
            case "d": cursor.advance(); base = "double"
            default:
                if let named = cursor.readLengthPrefixedIdentifier() {
                    base = named
                } else {
                    return nil
                }
            }
            if let b = base {
                params.append(prefix.hasPrefix("const ") ? "\(prefix)\(b)" : "\(b)\(prefix)")
            } else if !isVoidAlone {
                return nil
            }
        }

        let constSuffix = isConstMethod ? " const" : ""
        return "\(joinedName)(\(params.joined(separator: ", ")))\(constSuffix)"
    }
}

// MARK: - Universal Binary Format Dispatcher

public enum UniversalBinaryDispatcher {
    /// Detects the container format of an in-memory binary buffer strictly from its header magic.
    public static func detectFormat(data: Data) -> BinaryContainerFormat {
        guard data.count >= 4 else { return .rawBinary }
        let b0 = data[data.startIndex]
        let b1 = data[data.startIndex + 1]
        let b2 = data[data.startIndex + 2]
        let b3 = data[data.startIndex + 3]

        let be32 = (UInt32(b0) << 24) | (UInt32(b1) << 16) | (UInt32(b2) << 8) | UInt32(b3)
        let le32 = UInt32(b0) | (UInt32(b1) << 8) | (UInt32(b2) << 16) | (UInt32(b3) << 24)

        // Universal Fat / Fat64 (validate nfat_arch <= 32 to avoid Java .class collision)
        if be32 == MachOConstants.fatMagic || be32 == MachOConstants.fatMagic64 {
            if data.count >= 8 {
                let countBE = (UInt32(data[data.startIndex + 4]) << 24)
                    | (UInt32(data[data.startIndex + 5]) << 16)
                    | (UInt32(data[data.startIndex + 6]) << 8)
                    | UInt32(data[data.startIndex + 7])
                if countBE > 0 && countBE <= 32 {
                    return .universalFat
                }
            }
        }
        if le32 == MachOConstants.fatMagic || le32 == MachOConstants.fatMagic64 {
            if data.count >= 8 {
                let countLE = UInt32(data[data.startIndex + 4])
                    | (UInt32(data[data.startIndex + 5]) << 8)
                    | (UInt32(data[data.startIndex + 6]) << 16)
                    | (UInt32(data[data.startIndex + 7]) << 24)
                if countLE > 0 && countLE <= 32 {
                    return .universalFat
                }
            }
        }

        // Mach-O 64
        if le32 == MachOConstants.mhMagic64 || le32 == MachOConstants.mhCigam64 {
            return .machO64
        }

        // ELF ("\x7FELF")
        if b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46 {
            return .elf64
        }

        // WebAssembly ("\0asm")
        if b0 == 0x00 && b1 == 0x61 && b2 == 0x73 && b3 == 0x6D {
            return .wasm
        }

        // DOS MZ -> PE\0\0
        if b0 == 0x4D && b1 == 0x5A && data.count >= 0x40 {
            let lfanewOffset = data.startIndex + 0x3C
            let peOff = Int(
                UInt32(data[lfanewOffset])
                | (UInt32(data[lfanewOffset + 1]) << 8)
                | (UInt32(data[lfanewOffset + 2]) << 16)
                | (UInt32(data[lfanewOffset + 3]) << 24)
            )
            if peOff >= 0 && peOff + 4 <= data.count {
                let p = data.startIndex + peOff
                if data[p] == 0x50 && data[p + 1] == 0x45 && data[p + 2] == 0x00 && data[p + 3] == 0x00 {
                    return .pe32Plus
                }
            }
        }

        return .rawBinary
    }

    /// Parses Universal Fat (`0xCAFEBABE`) and Fat64 (`0xCAFEBABF`) headers into `[UniversalArchSlice]`.
    public static func parseUniversalSlices(data: Data) throws -> [UniversalArchSlice] {
        guard data.count >= 8 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 8, available: data.count)
        }
        var reader = BinarySliceReader(data: data, endianness: .big)
        let magicBE = try reader.readUInt32()

        let is64Bit: Bool
        switch magicBE {
        case MachOConstants.fatMagic:
            is64Bit = false
            reader.endianness = .big
        case MachOConstants.fatMagic64:
            is64Bit = true
            reader.endianness = .big
        case MachOConstants.fatCigam:
            is64Bit = false
            reader.endianness = .little
        case MachOConstants.fatCigam64:
            is64Bit = true
            reader.endianness = .little
        default:
            throw MachGraphError.invalidMagic(
                expected: "0xCAFEBABE / 0xCAFEBABF",
                actualHex: String(format: "0x%08X", magicBE)
            )
        }

        let archCount = try reader.readUInt32()
        guard archCount > 0 && archCount <= 32 else {
            throw MachGraphError.malformedHeader("Universal Fat header reports invalid slice count (\(archCount))")
        }

        var slices: [UniversalArchSlice] = []
        slices.reserveCapacity(Int(archCount))

        for index in 0..<Int(archCount) {
            let cpuType = try reader.readInt32()
            let cpuSubType = try reader.readInt32()
            let sliceOffset: UInt64
            let sliceSize: UInt64
            let alignExp: UInt32

            if is64Bit {
                sliceOffset = try reader.readUInt64()
                sliceSize = try reader.readUInt64()
                alignExp = try reader.readUInt32()
                _ = try reader.readUInt32() // reserved
            } else {
                sliceOffset = UInt64(try reader.readUInt32())
                sliceSize = UInt64(try reader.readUInt32())
                alignExp = try reader.readUInt32()
            }

            guard sliceSize > 0,
                  sliceOffset <= UInt64(data.count),
                  sliceSize <= UInt64(data.count) - sliceOffset else {
                throw MachGraphError.malformedHeader(
                    "Universal slice #\(index) range (0x\(String(sliceOffset, radix: 16))+0x\(String(sliceSize, radix: 16))) exceeds file size (\(data.count))"
                )
            }

            let arch = MachOConstants.mapArchitecture(cpuType: cpuType, cpuSubType: cpuSubType)
            slices.append(
                UniversalArchSlice(
                    index: index,
                    architecture: arch,
                    cpuType: cpuType,
                    cpuSubType: cpuSubType,
                    fileOffset: FileOffset(sliceOffset),
                    size: sliceSize,
                    alignExponent: alignExp
                )
            )
        }

        return slices
    }

    /// Selects the preferred slice index: explicit index if supplied, otherwise `arm64e` -> `arm64` -> `x86_64` -> `0`.
    public static func selectPreferredSliceIndex(in slices: [UniversalArchSlice], preferredSliceIndex: Int?) throws -> Int {
        guard !slices.isEmpty else {
            throw MachGraphError.malformedHeader("Universal Fat container contains zero architecture slices")
        }
        if let explicit = preferredSliceIndex {
            guard explicit >= 0 && explicit < slices.count else {
                throw MachGraphError.unsupportedArchitecture(
                    "Requested slice index \(explicit) out of bounds (available 0..<\(slices.count))"
                )
            }
            return explicit
        }
        if let arm64eIdx = slices.firstIndex(where: { $0.architecture == .arm64e }) {
            return arm64eIdx
        }
        if let arm64Idx = slices.firstIndex(where: { $0.architecture == .arm64 }) {
            return arm64Idx
        }
        if let x64Idx = slices.firstIndex(where: { $0.architecture == .x86_64 }) {
            return x64Idx
        }
        return 0
    }

    /// Loads a binary image from disk URL with automatic format detection and Fat slice selection.
    public static func load(fileURL: URL, preferredSliceIndex: Int? = nil) throws -> LoadedBinaryImage {
        let path = fileURL.path
        guard FileManager.default.fileExists(atPath: path) else {
            throw MachGraphError.fileNotFound(path)
        }
        let data: Data
        do {
            data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        } catch {
            throw MachGraphError.ioFailure("Unable to read '\(path)': \(error.localizedDescription)")
        }
        return try load(
            data: data,
            filePath: path,
            fileName: fileURL.lastPathComponent,
            preferredSliceIndex: preferredSliceIndex
        )
    }

    /// Loads a binary image from a filesystem path string.
    public static func load(filePath: String, preferredSliceIndex: Int? = nil) throws -> LoadedBinaryImage {
        try load(fileURL: URL(fileURLWithPath: filePath), preferredSliceIndex: preferredSliceIndex)
    }

    /// Autodetects Universal Fat, Mach-O 64, ELF64, PE32+, or WebAssembly 1.0 and parses a `LoadedBinaryImage`.
    public static func load(
        data: Data,
        filePath: String = "<in-memory>",
        fileName: String? = nil,
        preferredSliceIndex: Int? = nil
    ) throws -> LoadedBinaryImage {
        guard data.count >= 4 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 4, available: data.count)
        }

        let resolvedFileName: String
        if let explicitName = fileName, !explicitName.isEmpty {
            resolvedFileName = explicitName
        } else {
            let last = (filePath as NSString).lastPathComponent
            resolvedFileName = last.isEmpty ? "binary.bin" : last
        }

        // Explicitly diagnose 32-bit Mach-O before generic dispatch
        let leMagic = UInt32(data[data.startIndex])
            | (UInt32(data[data.startIndex + 1]) << 8)
            | (UInt32(data[data.startIndex + 2]) << 16)
            | (UInt32(data[data.startIndex + 3]) << 24)
        if leMagic == MachOConstants.mhMagic32 || leMagic == MachOConstants.mhCigam32 {
            throw MachGraphError.unsupportedContainer("32-bit Mach-O (0xFEEDFACE) is not supported; 64-bit required")
        }

        let format = detectFormat(data: data)
        switch format {
        case .universalFat:
            let slices = try parseUniversalSlices(data: data)
            let chosenIndex = try selectPreferredSliceIndex(in: slices, preferredSliceIndex: preferredSliceIndex)
            let chosenSlice = slices[chosenIndex]
            return try MachO64Loader.loadSlice(
                wholeData: data,
                sliceOffset: Int(chosenSlice.fileOffset.rawValue),
                sliceSize: Int(chosenSlice.size),
                fileName: resolvedFileName,
                filePath: filePath,
                containerFormat: .universalFat,
                selectedSliceIndex: chosenIndex,
                slices: slices
            )

        case .machO64:
            if let explicit = preferredSliceIndex, explicit != 0 {
                throw MachGraphError.unsupportedArchitecture(
                    "Single-architecture Mach-O has only slice 0 (requested \(explicit))"
                )
            }
            return try MachO64Loader.loadSlice(
                wholeData: data,
                sliceOffset: 0,
                sliceSize: data.count,
                fileName: resolvedFileName,
                filePath: filePath,
                containerFormat: .machO64,
                selectedSliceIndex: 0,
                slices: []
            )

        case .elf64:
            return try ELF64Loader.load(data: data, fileName: resolvedFileName, filePath: filePath)

        case .pe32Plus:
            return try PE32PlusLoader.load(data: data, fileName: resolvedFileName, filePath: filePath)

        case .wasm:
            return try WasmModuleLoader.load(data: data, fileName: resolvedFileName, filePath: filePath)

        case .rawBinary:
            let beMagic = (UInt32(data[data.startIndex]) << 24)
                | (UInt32(data[data.startIndex + 1]) << 16)
                | (UInt32(data[data.startIndex + 2]) << 8)
                | UInt32(data[data.startIndex + 3])
            throw MachGraphError.invalidMagic(
                expected: "Mach-O 64 / Fat / ELF64 / PE32+ / Wasm",
                actualHex: String(format: "0x%08X", beMagic)
            )
        }
    }

    /// Wraps an arbitrary raw firmware or shellcode blob into a flat `LoadedBinaryImage`.
    public static func loadRawBinary(
        data: Data,
        filePath: String = "<raw-blob>",
        fileName: String? = nil,
        baseAddress: VirtualAddress = VirtualAddress(0x1000_0000),
        architecture: CPUArchitecture = .arm64,
        endianness: BinaryEndianness = .little
    ) -> LoadedBinaryImage {
        let resolvedName = fileName ?? ((filePath as NSString).lastPathComponent.isEmpty ? "blob.bin" : (filePath as NSString).lastPathComponent)
        let entropy = StringAndEntropyScanner.overallEntropy(of: data)
        let codeSection = BinarySection(
            index: 0,
            segmentName: "__RAW",
            sectionName: "__blob",
            vmAddress: baseAddress,
            size: UInt64(data.count),
            fileOffset: .zero,
            alignment: 4,
            flags: 0,
            kind: .code,
            permissions: [.read, .execute],
            shannonEntropy: entropy
        )
        let segment = BinarySegment(
            name: "__RAW",
            vmAddress: baseAddress,
            vmSize: UInt64(data.count),
            fileOffset: .zero,
            fileSize: UInt64(data.count),
            initialProtection: [.read, .execute],
            maxProtection: [.read, .write, .execute],
            flags: 0,
            sections: [codeSection]
        )
        let strings = StringAndEntropyScanner.extractStrings(
            sliceData: data,
            sliceFileOffset: .zero,
            sections: [codeSection],
            minLength: 4
        )
        let entrySymbol = BinarySymbol(
            name: "_entry",
            demangledName: "entry",
            kind: .exportedEntry,
            binding: .global,
            address: baseAddress,
            size: UInt64(data.count),
            sectionIndex: 0
        )
        return LoadedBinaryImage(
            fileName: resolvedName,
            filePath: filePath,
            fileSize: UInt64(data.count),
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: data),
            containerFormat: .rawBinary,
            selectedSliceIndex: 0,
            slices: [],
            sliceFileOffset: .zero,
            architecture: architecture,
            endianness: endianness,
            isPositionIndependent: true,
            imageBase: baseAddress,
            entryPoint: baseAddress,
            uuidString: nil,
            platformName: "Raw Firmware",
            minOSVersion: "0.0",
            sdkVersion: "0.0",
            functionStarts: data.isEmpty ? [] : [baseAddress],
            segments: [segment],
            sections: [codeSection],
            importedLibraries: [],
            symbols: data.isEmpty ? [] : [entrySymbol],
            strings: strings,
            chainedFixups: [],
            codeSignature: .unsigned,
            objcClasses: [],
            swiftTypes: [],
            overallEntropy: entropy
        )
    }
}

// MARK: - Mach-O 64 Slice Loader

public enum MachO64Loader {
    private struct RawSectionRecord: Sendable {
        let section: BinarySection
        let reserved1: UInt32
        let reserved2: UInt32
    }

    private struct RawNlistRecord: Sendable {
        let name: String
        let nType: UInt8
        let nSect: UInt8
        let nDesc: UInt16
        let nValue: UInt64
        let libraryOrdinal: Int?
    }

    private struct SymtabCommandRange: Sendable {
        let symoff: Int
        let nsyms: Int
        let stroff: Int
        let strsize: Int
    }

    private struct DysymtabCommandRange: Sendable {
        let indirectsymoff: Int
        let nindirectsyms: Int
    }

    private struct LinkeditBlobRange: Sendable {
        let offset: Int
        let size: Int
    }

    private struct DyldInfoCommandRanges: Sendable {
        let rebase: LinkeditBlobRange
        let bind: LinkeditBlobRange
        let weakBind: LinkeditBlobRange
        let lazyBind: LinkeditBlobRange
        let exportTrie: LinkeditBlobRange
    }

    public static func loadSlice(
        wholeData: Data,
        sliceOffset: Int,
        sliceSize: Int,
        fileName: String,
        filePath: String,
        containerFormat: BinaryContainerFormat,
        selectedSliceIndex: Int,
        slices: [UniversalArchSlice]
    ) throws -> LoadedBinaryImage {
        guard sliceOffset >= 0, sliceSize >= 32, sliceOffset + sliceSize <= wholeData.count else {
            throw MachGraphError.unexpectedEOF(
                offset: UInt64(max(0, sliceOffset)),
                requested: max(32, sliceSize),
                available: max(0, wholeData.count - max(0, sliceOffset))
            )
        }

        let sliceData = Data(wholeData[(wholeData.startIndex + sliceOffset)..<(wholeData.startIndex + sliceOffset + sliceSize)])
        var probeReader = BinarySliceReader(data: sliceData, endianness: .little)
        let rawMagicLE = try probeReader.readUInt32()

        let endianness: BinaryEndianness
        if rawMagicLE == MachOConstants.mhMagic64 {
            endianness = .little
        } else if rawMagicLE == MachOConstants.mhCigam64 {
            endianness = .big
        } else {
            throw MachGraphError.invalidMagic(
                expected: "0xFEEDFACF (MH_MAGIC_64)",
                actualHex: String(format: "0x%08X", rawMagicLE)
            )
        }

        var reader = BinarySliceReader(data: sliceData, endianness: endianness)
        _ = try reader.readUInt32() // magic
        let cpuType = try reader.readInt32()
        let cpuSubType = try reader.readInt32()
        let fileType = try reader.readUInt32()
        let ncmds = try reader.readUInt32()
        let sizeofcmds = try reader.readUInt32()
        let headerFlags = try reader.readUInt32()
        _ = try reader.readUInt32() // reserved

        let headerByteSize = 32
        guard Int(sizeofcmds) >= 0, headerByteSize + Int(sizeofcmds) <= sliceData.count else {
            throw MachGraphError.malformedHeader(
                "mach_header_64 sizeofcmds (\(sizeofcmds)) exceeds slice length (\(sliceData.count))"
            )
        }
        guard ncmds <= 8192 else {
            throw MachGraphError.malformedHeader("Unreasonable load command count (\(ncmds))")
        }

        let architecture = MachOConstants.mapArchitecture(cpuType: cpuType, cpuSubType: cpuSubType)
        let isPIE = (headerFlags & MachOConstants.mhPIE) != 0 || fileType == MachOConstants.mhDylib || fileType == MachOConstants.mhBundle

        // Build single-arch synthetic slice descriptor if non-fat
        let resolvedSlices: [UniversalArchSlice]
        if slices.isEmpty {
            resolvedSlices = [
                UniversalArchSlice(
                    index: 0,
                    architecture: architecture,
                    cpuType: cpuType,
                    cpuSubType: cpuSubType,
                    fileOffset: FileOffset(UInt64(sliceOffset)),
                    size: UInt64(sliceSize),
                    alignExponent: architecture.isARM64Family ? 14 : 12
                )
            ]
        } else {
            resolvedSlices = slices
        }

        var segments: [BinarySegment] = []
        var rawSections: [RawSectionRecord] = []
        var dylibInstallID: ImportedLibrary?
        var importedLibraries: [ImportedLibrary] = []
        var dylibOrdinalCounter = 0

        var uuidString: String?
        var platformName = "macOS"
        var minOSVersion = "14.0"
        var sdkVersion = "15.0"

        var mainEntryOffset: UInt64?
        var unixThreadEntryVA: VirtualAddress?

        var symtabRange: SymtabCommandRange?
        var dysymtabRange: DysymtabCommandRange?
        var functionStartsRange: LinkeditBlobRange?
        var codeSignatureRange: LinkeditBlobRange?
        var dyldInfoRanges: DyldInfoCommandRanges?
        var chainedFixupsRange: LinkeditBlobRange?
        var exportsTrieRange: LinkeditBlobRange?

        // Walk all load commands cleanly
        var lcOffset = headerByteSize
        let lcLimit = headerByteSize + Int(sizeofcmds)

        for cmdIndex in 0..<Int(ncmds) {
            guard lcOffset + 8 <= lcLimit else {
                throw MachGraphError.malformedLoadCommand(
                    index: cmdIndex,
                    detail: "Load command header truncated at offset 0x\(String(lcOffset, radix: 16))"
                )
            }
            try reader.seek(to: lcOffset)
            let cmd = try reader.readUInt32()
            let cmdSize = Int(try reader.readUInt32())

            guard cmdSize >= 8, lcOffset + cmdSize <= lcLimit else {
                throw MachGraphError.malformedLoadCommand(
                    index: cmdIndex,
                    detail: "Invalid cmdsize \(cmdSize) for cmd 0x\(String(cmd, radix: 16))"
                )
            }

            var cmdReader = try reader.subreader(offset: lcOffset, length: cmdSize, endianness: endianness)
            try cmdReader.skip(8) // skip cmd + cmdsize

            switch cmd {
            case MachOConstants.lcSegment64:
                guard cmdSize >= 72 else {
                    throw MachGraphError.malformedLoadCommand(index: cmdIndex, detail: "LC_SEGMENT_64 < 72 bytes")
                }
                let segName = try cmdReader.readFixedASCII(16)
                let vmaddr = try cmdReader.readUInt64()
                let vmsize = try cmdReader.readUInt64()
                let fileoff = try cmdReader.readUInt64()
                let filesize = try cmdReader.readUInt64()
                let maxprot = try cmdReader.readInt32()
                let initprot = try cmdReader.readInt32()
                let nsects = Int(try cmdReader.readUInt32())
                let segFlags = try cmdReader.readUInt32()

                guard 72 + nsects * 80 <= cmdSize else {
                    throw MachGraphError.malformedLoadCommand(
                        index: cmdIndex,
                        detail: "LC_SEGMENT_64 '\(segName)' section table (\(nsects) sections) overflows cmdsize \(cmdSize)"
                    )
                }

                if filesize > 0 {
                    guard fileoff <= UInt64(sliceData.count),
                          filesize <= UInt64(sliceData.count) - fileoff else {
                        let req = Int(min(filesize, UInt64(Int.max)))
                        let avail = fileoff <= UInt64(sliceData.count) ? (sliceData.count - Int(fileoff)) : 0
                        throw MachGraphError.unexpectedEOF(offset: fileoff, requested: req, available: avail)
                    }
                }

                let segInitPerms = MachOConstants.mapPermissions(initprot)
                let segMaxPerms = MachOConstants.mapPermissions(maxprot)
                var segmentSections: [BinarySection] = []
                segmentSections.reserveCapacity(nsects)

                for _ in 0..<nsects {
                    let sectName = try cmdReader.readFixedASCII(16)
                    let sectSegName = try cmdReader.readFixedASCII(16)
                    let sectAddr = try cmdReader.readUInt64()
                    let sectSize = try cmdReader.readUInt64()
                    let sectOffset = try cmdReader.readUInt32()
                    let sectAlign = try cmdReader.readUInt32()
                    _ = try cmdReader.readUInt32() // reloff
                    _ = try cmdReader.readUInt32() // nreloc
                    let sectFlags = try cmdReader.readUInt32()
                    let reserved1 = try cmdReader.readUInt32()
                    let reserved2 = try cmdReader.readUInt32()
                    _ = try cmdReader.readUInt32() // reserved3

                    let resolvedSegName = sectSegName.isEmpty ? segName : sectSegName
                    let kind = MachOConstants.classifySection(
                        segmentName: resolvedSegName,
                        sectionName: sectName,
                        flags: sectFlags,
                        permissions: segInitPerms
                    )
                    if kind != .bss && sectSize > 0 {
                        guard UInt64(sectOffset) <= UInt64(sliceData.count),
                              sectSize <= UInt64(sliceData.count) - UInt64(sectOffset) else {
                            let req = Int(min(sectSize, UInt64(Int.max)))
                            let avail = UInt64(sectOffset) <= UInt64(sliceData.count) ? (sliceData.count - Int(sectOffset)) : 0
                            throw MachGraphError.unexpectedEOF(offset: UInt64(sectOffset), requested: req, available: avail)
                        }
                    }
                    let entropy: Double
                    if kind != .bss && sectSize > 0 {
                        entropy = StringAndEntropyScanner.sectionEntropy(
                            sliceData: sliceData,
                            offset: Int(sectOffset),
                            size: Int(sectSize)
                        )
                    } else {
                        entropy = 0.0
                    }

                    let secIndex = rawSections.count
                    let sectionModel = BinarySection(
                        index: secIndex,
                        segmentName: resolvedSegName,
                        sectionName: sectName,
                        vmAddress: VirtualAddress(sectAddr),
                        size: sectSize,
                        fileOffset: FileOffset(UInt64(sectOffset)),
                        alignment: 1 << min(sectAlign, 20),
                        flags: sectFlags,
                        kind: kind,
                        permissions: segInitPerms,
                        shannonEntropy: entropy
                    )
                    rawSections.append(RawSectionRecord(section: sectionModel, reserved1: reserved1, reserved2: reserved2))
                    segmentSections.append(sectionModel)
                }

                segments.append(
                    BinarySegment(
                        name: segName,
                        vmAddress: VirtualAddress(vmaddr),
                        vmSize: vmsize,
                        fileOffset: FileOffset(fileoff),
                        fileSize: filesize,
                        initialProtection: segInitPerms,
                        maxProtection: segMaxPerms,
                        flags: segFlags,
                        sections: segmentSections
                    )
                )

            case MachOConstants.lcSymtab:
                if cmdSize >= 24 {
                    let symoff = Int(try cmdReader.readUInt32())
                    let nsyms = Int(try cmdReader.readUInt32())
                    let stroff = Int(try cmdReader.readUInt32())
                    let strsize = Int(try cmdReader.readUInt32())
                    symtabRange = SymtabCommandRange(symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize)
                }

            case MachOConstants.lcDysymtab:
                if cmdSize >= 80 {
                    // Skip first 12 UInt32 fields (ilocalsym..nextrefsyms = 48 bytes) to reach indirectsymoff
                    try cmdReader.skip(48)
                    let indirectsymoff = Int(try cmdReader.readUInt32())
                    let nindirectsyms = Int(try cmdReader.readUInt32())
                    dysymtabRange = DysymtabCommandRange(indirectsymoff: indirectsymoff, nindirectsyms: nindirectsyms)
                }

            case MachOConstants.lcMain:
                if cmdSize >= 24 {
                    mainEntryOffset = try cmdReader.readUInt64()
                    _ = try cmdReader.readUInt64() // stacksize
                }

            case MachOConstants.lcUnixThread:
                if cmdSize >= 16 {
                    let flavor = try cmdReader.readUInt32()
                    let wordCount = Int(try cmdReader.readUInt32())
                    if flavor == MachOConstants.armThreadState64 && wordCount >= 66 && cmdReader.remaining >= 264 {
                        // x0..x28 (29*8=232), fp (240), lr (248), sp (256), pc at byte offset 256 in state
                        try cmdReader.skip(32 * 8)
                        let pc = try cmdReader.readUInt64()
                        unixThreadEntryVA = VirtualAddress(pc)
                    } else if flavor == MachOConstants.x86ThreadState64 && wordCount >= 34 && cmdReader.remaining >= 136 {
                        // rax..r15 (16*8=128), rip at byte offset 128 in state
                        try cmdReader.skip(16 * 8)
                        let rip = try cmdReader.readUInt64()
                        unixThreadEntryVA = VirtualAddress(rip)
                    }
                }

            case MachOConstants.lcLoadDylib,
                 MachOConstants.lcLoadWeakDylib,
                 MachOConstants.lcReexportDylib,
                 MachOConstants.lcLazyLoadDylib,
                 MachOConstants.lcLoadUpwardDylib:
                if cmdSize >= 24 {
                    let nameOffset = Int(try cmdReader.readUInt32())
                    _ = try cmdReader.readUInt32() // timestamp
                    let currentVer = try cmdReader.readUInt32()
                    let compatVer = try cmdReader.readUInt32()
                    let rawCmdReader = try reader.subreader(offset: lcOffset, length: cmdSize, endianness: endianness)
                    let installName = rawCmdReader.peekNullTerminatedUTF8(at: nameOffset, maxBytes: cmdSize) ?? "<unknown-dylib>"
                    dylibOrdinalCounter += 1
                    importedLibraries.append(
                        ImportedLibrary(
                            ordinal: dylibOrdinalCounter,
                            installName: installName,
                            currentVersion: MachOConstants.formatDylibVersion(currentVer),
                            compatibilityVersion: MachOConstants.formatDylibVersion(compatVer),
                            isWeak: cmd == MachOConstants.lcLoadWeakDylib,
                            isReexport: cmd == MachOConstants.lcReexportDylib
                        )
                    )
                }

            case MachOConstants.lcIdDylib:
                // Dylib's own install ID; does not increment 1-based imported library ordinals
                if cmdSize >= 24 {
                    let nameOffset = Int(try cmdReader.readUInt32())
                    _ = try cmdReader.readUInt32() // timestamp
                    let currentVer = try cmdReader.readUInt32()
                    let compatVer = try cmdReader.readUInt32()
                    let rawCmdReader = try reader.subreader(offset: lcOffset, length: cmdSize, endianness: endianness)
                    let installName = rawCmdReader.peekNullTerminatedUTF8(at: nameOffset, maxBytes: cmdSize) ?? "<unknown-dylib>"
                    dylibInstallID = ImportedLibrary(
                        ordinal: 0,
                        installName: installName,
                        currentVersion: MachOConstants.formatDylibVersion(currentVer),
                        compatibilityVersion: MachOConstants.formatDylibVersion(compatVer),
                        isWeak: false,
                        isReexport: false
                    )
                }

            case MachOConstants.lcUUID:
                if cmdSize >= 24 {
                    let b = try cmdReader.readBytes(16)
                    uuidString = String(
                        format: "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
                    )
                }

            case MachOConstants.lcBuildVersion:
                if cmdSize >= 24 {
                    let platform = try cmdReader.readUInt32()
                    let minos = try cmdReader.readUInt32()
                    let sdk = try cmdReader.readUInt32()
                    platformName = MachOConstants.platformDisplayName(platform)
                    minOSVersion = MachOConstants.formatPackedVersion(minos)
                    if sdk != 0 {
                        sdkVersion = MachOConstants.formatPackedVersion(sdk)
                    }
                }

            case MachOConstants.lcVersionMinMacOSX,
                 MachOConstants.lcVersionMinIPhoneOS,
                 MachOConstants.lcVersionMinTVOS,
                 MachOConstants.lcVersionMinWatchOS:
                if cmdSize >= 16 {
                    let ver = try cmdReader.readUInt32()
                    let sdk = try cmdReader.readUInt32()
                    switch cmd {
                    case MachOConstants.lcVersionMinIPhoneOS: platformName = "iOS"
                    case MachOConstants.lcVersionMinTVOS: platformName = "tvOS"
                    case MachOConstants.lcVersionMinWatchOS: platformName = "watchOS"
                    default: platformName = "macOS"
                    }
                    minOSVersion = MachOConstants.formatPackedVersion(ver)
                    if sdk != 0 {
                        sdkVersion = MachOConstants.formatPackedVersion(sdk)
                    }
                }

            case MachOConstants.lcFunctionStarts:
                if cmdSize >= 16 {
                    let off = Int(try cmdReader.readUInt32())
                    let size = Int(try cmdReader.readUInt32())
                    functionStartsRange = LinkeditBlobRange(offset: off, size: size)
                }

            case MachOConstants.lcCodeSignature:
                if cmdSize >= 16 {
                    let off = Int(try cmdReader.readUInt32())
                    let size = Int(try cmdReader.readUInt32())
                    codeSignatureRange = LinkeditBlobRange(offset: off, size: size)
                }

            case MachOConstants.lcDyldInfo, MachOConstants.lcDyldInfoOnly:
                if cmdSize >= 48 {
                    let rebaseOff = Int(try cmdReader.readUInt32())
                    let rebaseSize = Int(try cmdReader.readUInt32())
                    let bindOff = Int(try cmdReader.readUInt32())
                    let bindSize = Int(try cmdReader.readUInt32())
                    let weakOff = Int(try cmdReader.readUInt32())
                    let weakSize = Int(try cmdReader.readUInt32())
                    let lazyOff = Int(try cmdReader.readUInt32())
                    let lazySize = Int(try cmdReader.readUInt32())
                    let exportOff = Int(try cmdReader.readUInt32())
                    let exportSize = Int(try cmdReader.readUInt32())
                    dyldInfoRanges = DyldInfoCommandRanges(
                        rebase: LinkeditBlobRange(offset: rebaseOff, size: rebaseSize),
                        bind: LinkeditBlobRange(offset: bindOff, size: bindSize),
                        weakBind: LinkeditBlobRange(offset: weakOff, size: weakSize),
                        lazyBind: LinkeditBlobRange(offset: lazyOff, size: lazySize),
                        exportTrie: LinkeditBlobRange(offset: exportOff, size: exportSize)
                    )
                }

            case MachOConstants.lcDyldChainedFixups:
                if cmdSize >= 16 {
                    let off = Int(try cmdReader.readUInt32())
                    let size = Int(try cmdReader.readUInt32())
                    chainedFixupsRange = LinkeditBlobRange(offset: off, size: size)
                }

            case MachOConstants.lcDyldExportsTrie:
                if cmdSize >= 16 {
                    let off = Int(try cmdReader.readUInt32())
                    let size = Int(try cmdReader.readUInt32())
                    exportsTrieRange = LinkeditBlobRange(offset: off, size: size)
                }

            default:
                break
            }

            lcOffset += cmdSize
        }

        let sections = rawSections.map(\.section)

        // Resolve imageBase (__TEXT vmaddr, or lowest non-__PAGEZERO segment vmaddr)
        let textSegment = segments.first(where: { $0.name == "__TEXT" })
            ?? segments.filter({ $0.name != "__PAGEZERO" && $0.fileSize > 0 }).min(by: { $0.vmAddress < $1.vmAddress })
        let imageBase = textSegment?.vmAddress ?? .zero

        // Resolve entryPoint (LC_MAIN relative to __TEXT, or LC_UNIXTHREAD PC)
        let entryPoint: VirtualAddress?
        if let mainOff = mainEntryOffset {
            entryPoint = imageBase.adding(mainOff)
        } else {
            entryPoint = unixThreadEntryVA
        }

        func ensureSliceBlobBounds(offset: Int, size: Int) throws {
            guard size > 0 else { return }
            guard offset >= 0, offset <= sliceData.count, size <= sliceData.count - offset else {
                let avail = (offset >= 0 && offset <= sliceData.count) ? (sliceData.count - offset) : 0
                throw MachGraphError.unexpectedEOF(
                    offset: UInt64(max(0, offset)),
                    requested: size,
                    available: avail
                )
            }
        }

        // Parse LC_FUNCTION_STARTS ULEB128 delta table
        var functionStarts: [VirtualAddress] = []
        if let fsRange = functionStartsRange, fsRange.size > 0 {
            try ensureSliceBlobBounds(offset: fsRange.offset, size: fsRange.size)
            var fsReader = try BinarySliceReader(
                data: sliceData,
                offset: fsRange.offset,
                length: fsRange.size,
                endianness: .little
            )
            var currentOffset: UInt64 = 0
            while !fsReader.isAtEnd {
                let delta = try fsReader.readULEB128()
                if delta == 0 { continue }
                currentOffset &+= delta
                functionStarts.append(imageBase.adding(currentOffset))
            }
        }

        let sliceFileOffset = FileOffset(UInt64(sliceOffset))

        // Parse Dyld Chained Fixups and/or Legacy LC_DYLD_INFO(_ONLY)
        var chainedFixups: [ChainedFixupRecord] = []
        if let cfRange = chainedFixupsRange, cfRange.size > 0 {
            try ensureSliceBlobBounds(offset: cfRange.offset, size: cfRange.size)
            let parsedFixups = try DyldFixupsAndTrieParser.parseChainedFixups(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                fixupsOffset: cfRange.offset,
                fixupsSize: cfRange.size,
                imageBase: imageBase,
                segments: segments
            )
            chainedFixups.append(contentsOf: parsedFixups)
        }
        if let di = dyldInfoRanges {
            try ensureSliceBlobBounds(offset: di.rebase.offset, size: di.rebase.size)
            try ensureSliceBlobBounds(offset: di.bind.offset, size: di.bind.size)
            try ensureSliceBlobBounds(offset: di.weakBind.offset, size: di.weakBind.size)
            try ensureSliceBlobBounds(offset: di.lazyBind.offset, size: di.lazyBind.size)
            try ensureSliceBlobBounds(offset: di.exportTrie.offset, size: di.exportTrie.size)
            let legacyFixups = try DyldFixupsAndTrieParser.parseLegacyDyldInfo(
                sliceData: sliceData,
                sliceFileOffset: sliceFileOffset,
                rebaseRange: (di.rebase.offset, di.rebase.size),
                bindRange: (di.bind.offset, di.bind.size),
                weakBindRange: (di.weakBind.offset, di.weakBind.size),
                lazyBindRange: (di.lazyBind.offset, di.lazyBind.size),
                imageBase: imageBase,
                segments: segments
            )
            if chainedFixups.isEmpty {
                chainedFixups = legacyFixups
            } else if !legacyFixups.isEmpty {
                let existingLocations = Set(chainedFixups.map(\.location))
                for rec in legacyFixups where !existingLocations.contains(rec.location) {
                    chainedFixups.append(rec)
                }
            }
        }

        // Parse LC_SYMTAB nlist_64 records
        var rawNlistEntries: [RawNlistRecord] = []
        var collectedSymbols: [BinarySymbol] = []
        if let st = symtabRange, st.nsyms > 0 {
            try ensureSliceBlobBounds(offset: st.symoff, size: st.nsyms * 16)
            if st.strsize > 0 {
                try ensureSliceBlobBounds(offset: st.stroff, size: st.strsize)
            }
            let clampedStrSize = max(0, min(st.strsize, sliceData.count - max(0, st.stroff)))
            let strPoolReader = try BinarySliceReader(
                data: sliceData,
                offset: st.stroff,
                length: max(0, clampedStrSize),
                endianness: endianness
            )
            var symReader = try BinarySliceReader(
                data: sliceData,
                offset: st.symoff,
                length: st.nsyms * 16,
                endianness: endianness
            )
            rawNlistEntries.reserveCapacity(st.nsyms)

            for _ in 0..<st.nsyms {
                let nStrx = Int(try symReader.readUInt32())
                let nType = try symReader.readUInt8()
                let nSect = try symReader.readUInt8()
                let nDesc = try symReader.readUInt16()
                let nValue = try symReader.readUInt64()

                let symName: String
                if nStrx > 0 && nStrx < strPoolReader.count {
                    symName = strPoolReader.peekNullTerminatedUTF8(at: nStrx, maxBytes: strPoolReader.count - nStrx) ?? ""
                } else {
                    symName = ""
                }

                let rawOrd = Int(Int8(bitPattern: UInt8(truncatingIfNeeded: nDesc >> 8)))
                let libOrdinal: Int? = (headerFlags & MachOConstants.mhTwoLevel) != 0 && rawOrd > 0 ? rawOrd : nil

                rawNlistEntries.append(
                    RawNlistRecord(
                        name: symName,
                        nType: nType,
                        nSect: nSect,
                        nDesc: nDesc,
                        nValue: nValue,
                        libraryOrdinal: libOrdinal
                    )
                )

                // Skip debug stab entries
                if (nType & MachOConstants.nStab) != 0 {
                    continue
                }
                if symName.isEmpty {
                    continue
                }

                let typeField = nType & MachOConstants.nType
                if typeField == MachOConstants.nSect || typeField == MachOConstants.nAbs {
                    let secIdx: Int? = (nSect >= 1 && Int(nSect) <= sections.count) ? (Int(nSect) - 1) : nil
                    let targetSection = secIdx.map { sections[$0] }
                    let isSwift = symName.hasPrefix("_$s") || symName.hasPrefix("$s") || symName.hasPrefix("_$S")
                    let isObjC = symName.hasPrefix("-[") || symName.hasPrefix("+[")

                    let kind: SymbolKind
                    if isObjC {
                        kind = .objcMethod
                    } else if isSwift && targetSection?.kind == .code {
                        kind = .swiftFunction
                    } else if let entry = entryPoint, entry.rawValue == nValue {
                        kind = .exportedEntry
                    } else if targetSection?.kind == .stubs {
                        kind = .importedStub
                    } else if targetSection?.kind == .code {
                        kind = (nType & MachOConstants.nExt) != 0 ? .function : .localSymbol
                    } else {
                        kind = .globalVariable
                    }

                    let binding: SymbolBinding
                    if (nDesc & (MachOConstants.nWeakDef | MachOConstants.nWeakRef)) != 0 {
                        binding = .weak
                    } else if (nType & MachOConstants.nExt) != 0 && (nType & MachOConstants.nPext) == 0 {
                        binding = .global
                    } else {
                        binding = .local
                    }

                    collectedSymbols.append(
                        BinarySymbol(
                            name: symName,
                            demangledName: MachOSymbolDemangler.demangle(symName),
                            kind: kind,
                            binding: binding,
                            address: VirtualAddress(nValue),
                            size: 0,
                            sectionIndex: secIdx,
                            libraryOrdinal: libOrdinal,
                            provenance: .symtab
                        )
                    )
                }
            }
        }

        // Resolve LC_DYSYMTAB indirect symbol table for __stubs and __got / pointer sections
        if let dysym = dysymtabRange, dysym.nindirectsyms > 0 {
            try ensureSliceBlobBounds(offset: dysym.indirectsymoff, size: dysym.nindirectsyms * 4)
            var indReader = try BinarySliceReader(
                data: sliceData,
                offset: dysym.indirectsymoff,
                length: dysym.nindirectsyms * 4,
                endianness: endianness
            )
            var indirectTable: [UInt32] = []
            indirectTable.reserveCapacity(dysym.nindirectsyms)
            for _ in 0..<dysym.nindirectsyms {
                indirectTable.append(try indReader.readUInt32())
            }

            for rawSec in rawSections {
                let sec = rawSec.section
                let secType = sec.flags & MachOConstants.sectionTypeMask
                if secType == MachOConstants.sSymbolStubs {
                    let stubStride = rawSec.reserved2 > 0
                        ? Int(rawSec.reserved2)
                        : (architecture.isARM64Family ? 12 : 6)
                    guard stubStride > 0 else { continue }
                    let stubCount = Int(sec.size) / stubStride
                    let baseIdx = Int(rawSec.reserved1)
                    for i in 0..<stubCount {
                        let tableIdx = baseIdx + i
                        guard tableIdx >= 0 && tableIdx < indirectTable.count else { break }
                        let symIdx = indirectTable[tableIdx]
                        if (symIdx & (MachOConstants.indirectSymbolLocal | MachOConstants.indirectSymbolAbs)) != 0 {
                            continue
                        }
                        guard Int(symIdx) < rawNlistEntries.count else { continue }
                        let targetNlist = rawNlistEntries[Int(symIdx)]
                        guard !targetNlist.name.isEmpty else { continue }
                        let stubVA = sec.vmAddress.adding(UInt64(i * stubStride))
                        collectedSymbols.append(
                            BinarySymbol(
                                name: targetNlist.name,
                                demangledName: MachOSymbolDemangler.demangle(targetNlist.name),
                                kind: .importedStub,
                                binding: .external,
                                address: stubVA,
                                size: UInt64(stubStride),
                                sectionIndex: sec.index,
                                libraryOrdinal: targetNlist.libraryOrdinal,
                                provenance: .indirectSymtab
                            )
                        )
                    }
                } else if secType == MachOConstants.sNonLazySymbolPointers
                    || secType == MachOConstants.sLazySymbolPointers
                    || secType == MachOConstants.sLazyDylibSymbolPointers {
                    let slotStride = 8
                    let slotCount = Int(sec.size) / slotStride
                    let baseIdx = Int(rawSec.reserved1)
                    for i in 0..<slotCount {
                        let tableIdx = baseIdx + i
                        guard tableIdx >= 0 && tableIdx < indirectTable.count else { break }
                        let symIdx = indirectTable[tableIdx]
                        if (symIdx & (MachOConstants.indirectSymbolLocal | MachOConstants.indirectSymbolAbs)) != 0 {
                            continue
                        }
                        guard Int(symIdx) < rawNlistEntries.count else { continue }
                        let targetNlist = rawNlistEntries[Int(symIdx)]
                        guard !targetNlist.name.isEmpty else { continue }
                        let slotVA = sec.vmAddress.adding(UInt64(i * slotStride))
                        collectedSymbols.append(
                            BinarySymbol(
                                name: "got.\(targetNlist.name)",
                                demangledName: "GOT[\(MachOSymbolDemangler.demangle(targetNlist.name))]",
                                kind: .globalVariable,
                                binding: .external,
                                address: slotVA,
                                size: 8,
                                sectionIndex: sec.index,
                                libraryOrdinal: targetNlist.libraryOrdinal,
                                provenance: .indirectSymtab
                            )
                        )
                    }
                }
            }
        }

        // Infer GOT symbols & ld_prime stub symbols from Chained Fixup binds when indirect table omits them
        let bindFixupsBySlot: [VirtualAddress: ChainedFixupRecord] = Dictionary(
            chainedFixups.compactMap { rec in
                (rec.kind == .bind || rec.kind == .authBind) && rec.symbolName != nil ? (rec.location, rec) : nil
            },
            uniquingKeysWith: { first, _ in first }
        )
        for (slotVA, bindRec) in bindFixupsBySlot {
            guard let symName = bindRec.symbolName, !symName.isEmpty else { continue }
            if let sec = sections.first(where: { $0.addressRange.contains(slotVA) }), sec.kind == .got {
                collectedSymbols.append(
                    BinarySymbol(
                        name: "got.\(symName)",
                        demangledName: "GOT[\(MachOSymbolDemangler.demangle(symName))]",
                        kind: .globalVariable,
                        binding: .external,
                        address: slotVA,
                        size: 8,
                        sectionIndex: sec.index,
                        libraryOrdinal: bindRec.libraryOrdinal,
                        provenance: .chainedFixups
                    )
                )
            }
        }

        // ARM64 stub -> GOT bind fallback for modern ld_prime binaries (__stubs / __auth_stubs)
        if architecture.isARM64Family {
            let existingStubAddresses = Set(collectedSymbols.filter { $0.kind == .importedStub }.map(\.address))
            for sec in sections where sec.kind == .stubs && sec.size >= 12 {
                let secOff = Int(sec.fileOffset.rawValue)
                guard secOff >= 0, secOff + Int(sec.size) <= sliceData.count else { continue }
                let stubReader = try BinarySliceReader(data: sliceData, offset: secOff, length: Int(sec.size), endianness: .little)
                let resolvedStubs = resolveARM64StubsViaGOTBinds(
                    stubReader: stubReader,
                    section: sec,
                    bindFixupsBySlot: bindFixupsBySlot,
                    existingStubs: existingStubAddresses
                )
                collectedSymbols.append(contentsOf: resolvedStubs)
            }
        }

        // Parse Export Trie (LC_DYLD_EXPORTS_TRIE or LC_DYLD_INFO.export_off)
        let activeTrieRange = exportsTrieRange ?? dyldInfoRanges?.exportTrie
        if let trieRange = activeTrieRange, trieRange.size > 0 {
            try ensureSliceBlobBounds(offset: trieRange.offset, size: trieRange.size)
            let trieSlice = Data(sliceData[(sliceData.startIndex + trieRange.offset)..<(sliceData.startIndex + trieRange.offset + trieRange.size)])
            let exportedSymbols = try ExportTrieParser.parse(
                trieData: trieSlice,
                imageBase: imageBase,
                sections: sections
            )
            collectedSymbols.append(contentsOf: exportedSymbols)
        }

        // Parse Code Signature & CMS Certificates
        let codeSignature: CodeSignatureSummary
        if let csRange = codeSignatureRange, csRange.size > 0 {
            try ensureSliceBlobBounds(offset: csRange.offset, size: csRange.size)
            if csRange.size >= 8 {
                let sigSlice = Data(sliceData[(sliceData.startIndex + csRange.offset)..<(sliceData.startIndex + csRange.offset + csRange.size)])
                codeSignature = (try? CodeSignatureAndCMSParser.parse(signatureData: sigSlice)) ?? .unsigned
            } else {
                codeSignature = .unsigned
            }
        } else {
            codeSignature = .unsigned
        }

        // Parse ObjC 2.0 & Swift 5 Runtime Metadata
        let (objcClasses, objcCategories, objcProtocols, objcSymbols) = ObjCAndSwiftMetadataParser.parseObjCMetadata(
            sliceData: sliceData,
            sliceFileOffset: sliceFileOffset,
            imageBase: imageBase,
            segments: segments,
            sections: sections,
            chainedFixups: chainedFixups
        )
        collectedSymbols.append(contentsOf: objcSymbols)

        let (swiftTypes, swiftSymbols) = ObjCAndSwiftMetadataParser.parseSwiftMetadata(
            sliceData: sliceData,
            sliceFileOffset: sliceFileOffset,
            imageBase: imageBase,
            segments: segments,
            sections: sections,
            chainedFixups: chainedFixups
        )
        collectedSymbols.append(contentsOf: swiftSymbols)

        // Ensure entryPoint has a symbol if binary is completely stripped
        if let entry = entryPoint, !collectedSymbols.contains(where: { $0.address == entry }) {
            let secIdx = sections.firstIndex(where: { $0.addressRange.contains(entry) })
            collectedSymbols.append(
                BinarySymbol(
                    name: "_entry",
                    demangledName: "entry",
                    kind: .exportedEntry,
                    binding: .global,
                    address: entry,
                    size: 0,
                    sectionIndex: secIdx,
                    provenance: .entryPoint
                )
            )
        }

        // Merge functionStarts with code symbols and compute deduplicated sorted symbols with inferred sizes
        let finalSymbols = consolidateAndSizeSymbols(
            symbols: collectedSymbols,
            functionStarts: functionStarts,
            sections: sections
        )
        let mergedFunctionStarts = consolidateFunctionStarts(
            explicitStarts: functionStarts,
            symbols: finalSymbols,
            entryPoint: entryPoint
        )

        // Scan Strings & Compute Overall Entropy
        let extractedStrings = StringAndEntropyScanner.extractStrings(
            sliceData: sliceData,
            sliceFileOffset: sliceFileOffset,
            sections: sections,
            minLength: 4
        )
        let overallEntropy = StringAndEntropyScanner.overallEntropy(of: sliceData)

        return LoadedBinaryImage(
            fileName: fileName,
            filePath: filePath,
            fileSize: UInt64(wholeData.count),
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: wholeData),
            containerFormat: containerFormat,
            selectedSliceIndex: selectedSliceIndex,
            slices: resolvedSlices,
            sliceFileOffset: sliceFileOffset,
            architecture: architecture,
            endianness: endianness,
            isPositionIndependent: isPIE,
            imageBase: imageBase,
            entryPoint: entryPoint,
            uuidString: uuidString,
            platformName: platformName,
            minOSVersion: minOSVersion,
            sdkVersion: sdkVersion,
            functionStarts: mergedFunctionStarts,
            segments: segments,
            sections: sections,
            dylibInstallID: dylibInstallID,
            importedLibraries: importedLibraries,
            symbols: finalSymbols,
            strings: extractedStrings,
            chainedFixups: chainedFixups,
            codeSignature: codeSignature,
            objcClasses: objcClasses,
            objcCategories: objcCategories,
            objcProtocols: objcProtocols,
            swiftTypes: swiftTypes,
            overallEntropy: overallEntropy
        )
    }

    // MARK: - Symbol Consolidation & ld_prime Stub Helpers

    private static func resolveARM64StubsViaGOTBinds(
        stubReader: BinarySliceReader,
        section: BinarySection,
        bindFixupsBySlot: [VirtualAddress: ChainedFixupRecord],
        existingStubs: Set<VirtualAddress>
    ) -> [BinarySymbol] {
        guard !bindFixupsBySlot.isEmpty else { return [] }
        var r = stubReader
        let wordCount = r.count / 4
        guard wordCount >= 3 else { return [] }

        var words: [UInt32] = []
        words.reserveCapacity(wordCount)
        for _ in 0..<wordCount {
            guard let w = try? r.readUInt32() else { break }
            words.append(w)
        }

        var inferredStubs: [BinarySymbol] = []
        var idx = 0
        while idx + 2 < words.count {
            let stubVA = section.vmAddress.adding(UInt64(idx * 4))
            if existingStubs.contains(stubVA) {
                idx += 3
                continue
            }
            let w0 = words[idx]
            // ADRP Xd, page: (w0 & 0x9F000000) == 0x90000000
            guard (w0 & 0x9F00_0000) == 0x9000_0000 else {
                idx += 1
                continue
            }
            let immlo = Int64((w0 >> 29) & 0x3)
            let immhi = Int64(Int32(bitPattern: w0 << 8) >> 13) // sign-extend 19-bit immhi
            let pageDelta = ((immhi << 2) | immlo) << 12
            let adrpPage = stubVA.page4KBase().adding(pageDelta)

            let w1 = words[idx + 1]
            var gotTarget: VirtualAddress?
            var stubByteSize: UInt64 = 12

            if (w1 & 0xFFC0_0000) == 0xF940_0000 {
                // Classic 12-byte stub: ADRP X16 + LDR X16, [X16, #imm12*8] + BR X16
                let imm12 = UInt64((w1 >> 10) & 0xFFF) * 8
                gotTarget = adrpPage.adding(imm12)
                stubByteSize = 12
                idx += 3
            } else if (w1 & 0xFF80_0000) == 0x9100_0000 && idx + 3 < words.count {
                // arm64e 16-byte auth stub: ADRP X17 + ADD X17, X17, #imm12 + LDR X16, [X17] + BRAA X16, X17
                let shift = ((w1 >> 22) & 1) == 1 ? 12 : 0
                let imm12 = UInt64((w1 >> 10) & 0xFFF) << shift
                gotTarget = adrpPage.adding(imm12)
                stubByteSize = 16
                idx += 4
            } else {
                idx += 1
                continue
            }

            if let slot = gotTarget,
               let bindRec = bindFixupsBySlot[slot],
               let symName = bindRec.symbolName,
               !symName.isEmpty {
                inferredStubs.append(
                    BinarySymbol(
                        name: symName,
                        demangledName: MachOSymbolDemangler.demangle(symName),
                        kind: .importedStub,
                        binding: .external,
                        address: stubVA,
                        size: stubByteSize,
                        sectionIndex: section.index,
                        libraryOrdinal: bindRec.libraryOrdinal,
                        provenance: .chainedFixups
                    )
                )
            }
        }
        return inferredStubs
    }

    private static func symbolPriority(_ kind: SymbolKind) -> Int {
        switch kind {
        case .importedStub: return 70
        case .objcMethod: return 65
        case .swiftFunction: return 60
        case .exportedEntry: return 55
        case .function: return 50
        case .globalVariable: return 40
        case .localSymbol: return 30
        case .sectionLabel: return 10
        }
    }

    private static func consolidateAndSizeSymbols(
        symbols: [BinarySymbol],
        functionStarts: [VirtualAddress],
        sections: [BinarySection]
    ) -> [BinarySymbol] {
        // Preserve every defined LC_SYMTAB symbol verbatim (including multiple symbols or multiset
        // entries at the same address), and never allow inferred metadata to overwrite LC_SYMTAB names.
        var symtabSymbols: [BinarySymbol] = []
        var symtabAddresses = Set<VirtualAddress>()
        symtabSymbols.reserveCapacity(symbols.count)

        var bestInferredByAddress: [VirtualAddress: BinarySymbol] = [:]

        for sym in symbols where sym.provenance == .symtab {
            symtabSymbols.append(sym)
            symtabAddresses.insert(sym.address)
        }

        for sym in symbols where sym.provenance != .symtab {
            guard !symtabAddresses.contains(sym.address) else { continue }
            if let existing = bestInferredByAddress[sym.address] {
                let newPrio = symbolPriority(sym.kind)
                let oldPrio = symbolPriority(existing.kind)
                let winner = (newPrio > oldPrio || (newPrio == oldPrio && sym.size > existing.size)) ? sym : existing
                bestInferredByAddress[sym.address] = BinarySymbol(
                    name: winner.name,
                    demangledName: winner.demangledName,
                    kind: winner.kind,
                    binding: winner.binding,
                    address: winner.address,
                    size: max(existing.size, sym.size),
                    sectionIndex: winner.sectionIndex ?? existing.sectionIndex,
                    libraryOrdinal: winner.libraryOrdinal ?? existing.libraryOrdinal,
                    provenance: winner.provenance
                )
            } else {
                bestInferredByAddress[sym.address] = sym
            }
        }

        // Infer sub_<hex> entries for stripped functions discovered via LC_FUNCTION_STARTS
        let insnAttrMask = MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions
        for fnStart in functionStarts where !symtabAddresses.contains(fnStart) && bestInferredByAddress[fnStart] == nil {
            if let sec = sections.first(where: { $0.addressRange.contains(fnStart) }),
               (sec.flags & insnAttrMask) != 0 {
                let subName = String(format: "sub_%llx", fnStart.rawValue)
                bestInferredByAddress[fnStart] = BinarySymbol(
                    name: subName,
                    demangledName: subName,
                    kind: .function,
                    binding: .local,
                    address: fnStart,
                    size: 0,
                    sectionIndex: sec.index,
                    provenance: .functionStarts
                )
            }
        }

        var combined: [BinarySymbol] = []
        combined.reserveCapacity(symtabSymbols.count + bestInferredByAddress.count)
        combined.append(contentsOf: symtabSymbols)
        combined.append(contentsOf: bestInferredByAddress.values)

        let sorted = combined.enumerated().sorted { lhs, rhs in
            if lhs.element.address != rhs.element.address {
                return lhs.element.address < rhs.element.address
            }
            return lhs.offset < rhs.offset
        }.map(\.element)
        guard !sorted.isEmpty else { return [] }

        var sized: [BinarySymbol] = []
        sized.reserveCapacity(sorted.count)

        for i in 0..<sorted.count {
            let cur = sorted[i]
            if cur.size > 0 {
                sized.append(cur)
                continue
            }
            guard let secIdx = cur.sectionIndex, secIdx >= 0, secIdx < sections.count else {
                sized.append(cur)
                continue
            }
            let sec = sections[secIdx]
            guard sec.kind == .code else {
                sized.append(cur)
                continue
            }
            var nextIdx = i + 1
            while nextIdx < sorted.count && sorted[nextIdx].address == cur.address {
                nextIdx += 1
            }
            let nextBoundary: VirtualAddress
            if nextIdx < sorted.count,
               sorted[nextIdx].sectionIndex == secIdx,
               sorted[nextIdx].address > cur.address {
                nextBoundary = sorted[nextIdx].address
            } else {
                nextBoundary = sec.addressRange.end
            }
            let computedSize = nextBoundary.rawValue > cur.address.rawValue
                ? (nextBoundary.rawValue - cur.address.rawValue)
                : 0
            sized.append(
                BinarySymbol(
                    name: cur.name,
                    demangledName: cur.demangledName,
                    kind: cur.kind,
                    binding: cur.binding,
                    address: cur.address,
                    size: computedSize,
                    sectionIndex: cur.sectionIndex,
                    libraryOrdinal: cur.libraryOrdinal,
                    provenance: cur.provenance
                )
            )
        }

        return sized
    }

    private static func consolidateFunctionStarts(
        explicitStarts: [VirtualAddress],
        symbols: [BinarySymbol],
        entryPoint: VirtualAddress?
    ) -> [VirtualAddress] {
        var set = Set<VirtualAddress>(explicitStarts)
        for sym in symbols {
            switch sym.kind {
            case .function, .exportedEntry, .objcMethod, .swiftFunction:
                if sym.address != .zero {
                    set.insert(sym.address)
                }
            default:
                break
            }
        }
        if let entry = entryPoint, entry != .zero {
            set.insert(entry)
        }
        return set.sorted()
    }
}
