import Foundation
import MachGraphModels

// MARK: - Code Signature Constants & Detailed Models

public enum CodeSignatureConstants {
    // Big-Endian CSMAGIC Constants
    public static let magicRequirement: UInt32           = 0xFADE_0C00
    public static let magicRequirements: UInt32          = 0xFADE_0C01
    public static let magicCodeDirectory: UInt32         = 0xFADE_0C02
    public static let magicEmbeddedSignature: UInt32     = 0xFADE_0CC0 // CS_SuperBlob
    public static let magicDetachedSignature: UInt32     = 0xFADE_0CC1
    public static let magicBlobWrapper: UInt32           = 0xFADE_0B01 // CMS SignedData (PKCS#7)
    public static let magicEmbeddedEntitlements: UInt32  = 0xFADE_7171 // XML Plist
    public static let magicEmbeddedDEREntitlements: UInt32 = 0xFADE_7172 // ASN.1 DER Entitlements

    // CSSLOT Index Types
    public static let slotCodeDirectory: UInt32          = 0
    public static let slotInfoPlist: UInt32              = 1
    public static let slotRequirements: UInt32           = 2
    public static let slotResourceDir: UInt32            = 3
    public static let slotApplication: UInt32            = 4
    public static let slotEntitlements: UInt32           = 5
    public static let slotDEREntitlements: UInt32        = 7
    public static let slotAlternateCodeDirectoryBase: UInt32 = 0x1000
    public static let slotAlternateCodeDirectoryLimit: UInt32 = 0x1005
    public static let slotCMSWrapper: UInt32             = 0x10000

    // CodeDirectory Flags
    public static let flagValid: UInt32                  = 0x0000_0001
    public static let flagAdhoc: UInt32                  = 0x0000_0002
    public static let flagForceHard: UInt32              = 0x0000_0100
    public static let flagForceKill: UInt32              = 0x0000_0200
    public static let flagForceExpiration: UInt32        = 0x0000_0400
    public static let flagRestrict: UInt32               = 0x0000_0800
    public static let flagEnforcement: UInt32            = 0x0000_1000
    public static let flagRequireLV: UInt32              = 0x0000_2000
    public static let flagRuntime: UInt32                = 0x0001_0000
    public static let flagLinkerSigned: UInt32           = 0x0002_0000

    // CodeDirectory Versions
    public static let versionSupportsScatter: UInt32     = 0x0002_0100
    public static let versionSupportsTeamID: UInt32      = 0x0002_0200
    public static let versionSupportsCodeLimit64: UInt32 = 0x0002_0300
    public static let versionSupportsExecSeg: UInt32     = 0x0002_0400
    public static let versionSupportsRuntime: UInt32     = 0x0002_0500

    // Hash Algorithms
    public static let hashTypeSHA1: UInt8                = 1
    public static let hashTypeSHA256: UInt8              = 2
    public static let hashTypeSHA256Truncated: UInt8     = 3
    public static let hashTypeSHA384: UInt8              = 4
    public static let hashTypeSHA512: UInt8              = 5

    // Executable Segment Flags
    public static let execSegMainBinary: UInt64          = 0x0001
    public static let execSegAllowUnsigned: UInt64       = 0x0010
    public static let execSegDebugger: UInt64            = 0x0020
    public static let execSegJit: UInt64                 = 0x0040

    public static func hashAlgorithmName(_ hashType: UInt8) -> String {
        switch hashType {
        case hashTypeSHA1: return "SHA-1"
        case hashTypeSHA256: return "SHA-256"
        case hashTypeSHA256Truncated: return "SHA-256 (160-bit)"
        case hashTypeSHA384: return "SHA-384"
        case hashTypeSHA512: return "SHA-512"
        default: return "HashType(\(hashType))"
        }
    }
}

public struct CodeDirectoryDetail: Sendable, Codable, Hashable {
    public let slotType: UInt32
    public let version: UInt32
    public let flags: UInt32
    public let identifier: String
    public let teamIdentifier: String?
    public let hashType: UInt8
    public let hashAlgorithm: String
    public let hashByteSize: Int
    public let pageSize: Int
    public let codeLimit: UInt64
    public let nSpecialSlots: Int
    public let nCodeSlots: Int
    public let cdHashHex: String
    public let specialSlotHashesHex: [Int: String]
    public let codeSlotHashesHex: [String]
    public let execSegBase: UInt64
    public let execSegLimit: UInt64
    public let execSegFlags: UInt64

    public init(
        slotType: UInt32,
        version: UInt32,
        flags: UInt32,
        identifier: String,
        teamIdentifier: String?,
        hashType: UInt8,
        hashAlgorithm: String,
        hashByteSize: Int,
        pageSize: Int,
        codeLimit: UInt64,
        nSpecialSlots: Int,
        nCodeSlots: Int,
        cdHashHex: String,
        specialSlotHashesHex: [Int: String],
        codeSlotHashesHex: [String],
        execSegBase: UInt64 = 0,
        execSegLimit: UInt64 = 0,
        execSegFlags: UInt64 = 0
    ) {
        self.slotType = slotType
        self.version = version
        self.flags = flags
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.hashType = hashType
        self.hashAlgorithm = hashAlgorithm
        self.hashByteSize = hashByteSize
        self.pageSize = pageSize
        self.codeLimit = codeLimit
        self.nSpecialSlots = nSpecialSlots
        self.nCodeSlots = nCodeSlots
        self.cdHashHex = cdHashHex
        self.specialSlotHashesHex = specialSlotHashesHex
        self.codeSlotHashesHex = codeSlotHashesHex
        self.execSegBase = execSegBase
        self.execSegLimit = execSegLimit
        self.execSegFlags = execSegFlags
    }
}

// MARK: - Mach-O Code Signature, Entitlements & CMS ASN.1 DER Parser

public enum CodeSignatureAndCMSParser {
    /// Parses a Mach-O `LC_CODE_SIGNATURE` payload (`CS_SuperBlob` or standalone `CS_CodeDirectory`) into `CodeSignatureSummary`.
    public static func parse(signatureData: Data) throws -> CodeSignatureSummary {
        let (summary, _) = try parseDetailed(signatureData: signatureData)
        return summary
    }

    /// Parses both the aggregate `CodeSignatureSummary` and every individual `CodeDirectoryDetail` inside the `CS_SuperBlob`.
    public static func parseDetailed(signatureData: Data) throws -> (summary: CodeSignatureSummary, directories: [CodeDirectoryDetail]) {
        guard signatureData.count >= 8 else {
            return (.unsigned, [])
        }

        var reader = BinarySliceReader(data: signatureData, endianness: .big)
        let topMagic = try reader.readUInt32()
        let topLength = Int(try reader.readUInt32())

        if topMagic == CodeSignatureConstants.magicCodeDirectory {
            let clampedLen = min(max(8, topLength), signatureData.count)
            let cdBlob = Data(signatureData[signatureData.startIndex..<(signatureData.startIndex + clampedLen)])
            let detail = try parseCodeDirectory(blobData: cdBlob, slotType: CodeSignatureConstants.slotCodeDirectory)
            let isAdHoc = (detail.flags & CodeSignatureConstants.flagAdhoc) != 0
            let summary = CodeSignatureSummary(
                isSigned: true,
                isAdHoc: isAdHoc,
                identifier: detail.identifier,
                teamIdentifier: detail.teamIdentifier,
                cdHashHex: detail.cdHashHex,
                hashAlgorithm: detail.hashAlgorithm,
                codeDirectoryVersion: detail.version,
                pageSize: detail.pageSize,
                flags: detail.flags,
                entitlementsXML: nil,
                entitlementsPairs: [:],
                cmsSignerCommonNames: []
            )
            return (summary, [detail])
        }

        guard topMagic == CodeSignatureConstants.magicEmbeddedSignature
            || topMagic == CodeSignatureConstants.magicDetachedSignature else {
            throw MachGraphError.codeSignError(
                String(format: "Unexpected CS_SuperBlob magic 0x%08X (expected 0xFADE0CC0)", topMagic)
            )
        }

        guard signatureData.count >= 12 else {
            throw MachGraphError.codeSignError("Truncated CS_SuperBlob header (< 12 bytes)")
        }

        let superLength = min(max(12, topLength), signatureData.count)
        let blobCount = Int(try reader.readUInt32())
        guard blobCount >= 0 && blobCount <= 256,
              12 + blobCount * 8 <= superLength else {
            throw MachGraphError.codeSignError("Invalid CS_BlobIndex count (\(blobCount)) in CS_SuperBlob")
        }

        var blobEntries: [(slotType: UInt32, offset: Int)] = []
        blobEntries.reserveCapacity(blobCount)
        for _ in 0..<blobCount {
            let slotType = try reader.readUInt32()
            let blobOff = Int(try reader.readUInt32())
            blobEntries.append((slotType, blobOff))
        }

        var codeDirectories: [CodeDirectoryDetail] = []
        var entitlementsXML: String?
        var entitlementsPairs: [String: String] = [:]
        var cmsCommonNames: [String] = []
        var sawNonEmptyCMS = false

        for entry in blobEntries {
            guard entry.offset >= 12 && entry.offset + 8 <= superLength else {
                continue
            }
            var subHeaderReader = try BinarySliceReader(
                data: signatureData,
                offset: entry.offset,
                length: superLength - entry.offset,
                endianness: .big
            )
            let subMagic = try subHeaderReader.readUInt32()
            let subLength = Int(try subHeaderReader.readUInt32())
            guard subLength >= 8 else { continue }
            let safeLen = min(subLength, superLength - entry.offset)
            let blobSlice = Data(
                signatureData[(signatureData.startIndex + entry.offset)..<(signatureData.startIndex + entry.offset + safeLen)]
            )

            switch subMagic {
            case CodeSignatureConstants.magicCodeDirectory:
                if let cd = try? parseCodeDirectory(blobData: blobSlice, slotType: entry.slotType) {
                    codeDirectories.append(cd)
                }

            case CodeSignatureConstants.magicEmbeddedEntitlements:
                if safeLen > 8 {
                    let xmlPayload = Data(blobSlice.dropFirst(8))
                    let trimmedBytes = xmlPayload.prefix { $0 != 0 }
                    let xmlString = String(decoding: trimmedBytes, as: UTF8.self)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    if !xmlString.isEmpty {
                        entitlementsXML = xmlString
                        let parsed = parseXMLEntitlementsPlist(xmlString)
                        for (k, v) in parsed {
                            entitlementsPairs[k] = v
                        }
                    }
                }

            case CodeSignatureConstants.magicEmbeddedDEREntitlements:
                if safeLen > 8 {
                    let derPayload = Data(blobSlice.dropFirst(8))
                    let derPairs = ASN1DERWalker.parseDEREntitlements(derData: derPayload)
                    for (k, v) in derPairs where entitlementsPairs[k] == nil {
                        entitlementsPairs[k] = v
                    }
                }

            case CodeSignatureConstants.magicBlobWrapper:
                if safeLen > 8 {
                    let cmsPayload = Data(blobSlice.dropFirst(8))
                    if !cmsPayload.isEmpty {
                        sawNonEmptyCMS = true
                        let signers = ASN1DERWalker.extractCMSSignerCommonNames(cmsData: cmsPayload)
                        for cn in signers where !cmsCommonNames.contains(cn) {
                            cmsCommonNames.append(cn)
                        }
                    }
                }

            default:
                break
            }
        }

        // Prefer SHA-256 CodeDirectory when agile signing includes both SHA-1 and SHA-256
        guard let preferredCD = selectPreferredCodeDirectory(from: codeDirectories) else {
            return (.unsigned, [])
        }

        let isAdHoc = (preferredCD.flags & CodeSignatureConstants.flagAdhoc) != 0
            || (!sawNonEmptyCMS && cmsCommonNames.isEmpty)

        // Synthesize readable XML representation if binary carries only DER entitlements (0xFADE7172)
        if entitlementsXML == nil && !entitlementsPairs.isEmpty {
            entitlementsXML = synthesizeXMLPlist(from: entitlementsPairs)
        }

        let summary = CodeSignatureSummary(
            isSigned: true,
            isAdHoc: isAdHoc,
            identifier: preferredCD.identifier,
            teamIdentifier: preferredCD.teamIdentifier,
            cdHashHex: preferredCD.cdHashHex,
            hashAlgorithm: preferredCD.hashAlgorithm,
            codeDirectoryVersion: preferredCD.version,
            pageSize: preferredCD.pageSize,
            flags: preferredCD.flags,
            entitlementsXML: entitlementsXML,
            entitlementsPairs: entitlementsPairs,
            cmsSignerCommonNames: cmsCommonNames
        )

        return (summary, codeDirectories)
    }

    private static func selectPreferredCodeDirectory(from directories: [CodeDirectoryDetail]) -> CodeDirectoryDetail? {
        guard !directories.isEmpty else { return nil }
        if let sha256 = directories.first(where: { $0.hashType == CodeSignatureConstants.hashTypeSHA256 }) {
            return sha256
        }
        if let sha384 = directories.first(where: { $0.hashType == CodeSignatureConstants.hashTypeSHA384 }) {
            return sha384
        }
        if let primary = directories.first(where: { $0.slotType == CodeSignatureConstants.slotCodeDirectory }) {
            return primary
        }
        return directories.first
    }

    private static func parseCodeDirectory(blobData: Data, slotType: UInt32) throws -> CodeDirectoryDetail {
        guard blobData.count >= 44 else {
            throw MachGraphError.codeSignError("CS_CodeDirectory shorter than 44-byte minimum (\(blobData.count) bytes)")
        }

        var reader = BinarySliceReader(data: blobData, endianness: .big)
        let magic = try reader.readUInt32()
        guard magic == CodeSignatureConstants.magicCodeDirectory else {
            throw MachGraphError.codeSignError(String(format: "Invalid CS_CodeDirectory magic 0x%08X", magic))
        }

        let declaredLength = Int(try reader.readUInt32())
        let effectiveLength = min(max(44, declaredLength), blobData.count)
        let version = try reader.readUInt32()
        let flags = try reader.readUInt32()
        let hashOffset = Int(try reader.readUInt32())
        let identOffset = Int(try reader.readUInt32())
        let nSpecialSlots = Int(try reader.readUInt32())
        let nCodeSlots = Int(try reader.readUInt32())
        let codeLimit32 = UInt64(try reader.readUInt32())
        let hashSize = Int(try reader.readUInt8())
        let hashType = try reader.readUInt8()
        _ = try reader.readUInt8() // platform
        let pageSizeShift = try reader.readUInt8()
        _ = try reader.readUInt32() // spare2

        var teamOffset: Int = 0
        var codeLimit64: UInt64 = 0
        var execSegBase: UInt64 = 0
        var execSegLimit: UInt64 = 0
        var execSegFlags: UInt64 = 0

        if version >= CodeSignatureConstants.versionSupportsScatter && reader.remaining >= 4 {
            _ = try reader.readUInt32() // scatterOffset
        }
        if version >= CodeSignatureConstants.versionSupportsTeamID && reader.remaining >= 4 {
            teamOffset = Int(try reader.readUInt32())
        }
        if version >= CodeSignatureConstants.versionSupportsCodeLimit64 && reader.remaining >= 12 {
            _ = try reader.readUInt32() // spare3
            codeLimit64 = try reader.readUInt64()
        }
        if version >= CodeSignatureConstants.versionSupportsExecSeg && reader.remaining >= 24 {
            execSegBase = try reader.readUInt64()
            execSegLimit = try reader.readUInt64()
            execSegFlags = try reader.readUInt64()
        }

        let identifier: String
        if identOffset >= 44 && identOffset < effectiveLength {
            identifier = reader.peekNullTerminatedUTF8(at: identOffset, maxBytes: 1024) ?? ""
        } else {
            identifier = ""
        }

        let teamIdentifier: String?
        if teamOffset >= 48 && teamOffset < effectiveLength {
            let parsedTeam = reader.peekNullTerminatedUTF8(at: teamOffset, maxBytes: 256) ?? ""
            teamIdentifier = parsedTeam.isEmpty ? nil : parsedTeam
        } else {
            teamIdentifier = nil
        }

        let pageSize = pageSizeShift > 0 && pageSizeShift < 31 ? (1 << Int(pageSizeShift)) : 0
        let finalCodeLimit = codeLimit64 > 0 ? codeLimit64 : codeLimit32

        // Extract special slot hashes (-nSpecialSlots .. -1) and code slot hashes (0 ..< nCodeSlots)
        var specialHashes: [Int: String] = [:]
        if hashSize > 0 && nSpecialSlots > 0 && nSpecialSlots <= 32 {
            for slotIdx in 1...nSpecialSlots {
                let slotByteStart = hashOffset - (slotIdx * hashSize)
                if slotByteStart >= 44 && slotByteStart + hashSize <= effectiveLength {
                    let slice = blobData[(blobData.startIndex + slotByteStart)..<(blobData.startIndex + slotByteStart + hashSize)]
                    if slice.contains(where: { $0 != 0 }) {
                        specialHashes[-slotIdx] = slice.map { String(format: "%02x", $0) }.joined()
                    }
                }
            }
        }

        var codeHashes: [String] = []
        if hashSize > 0 && nCodeSlots > 0 {
            let cappedSlots = min(nCodeSlots, 4096)
            codeHashes.reserveCapacity(cappedSlots)
            for slotIdx in 0..<cappedSlots {
                let slotByteStart = hashOffset + (slotIdx * hashSize)
                guard slotByteStart >= 44 && slotByteStart + hashSize <= effectiveLength else { break }
                let slice = blobData[(blobData.startIndex + slotByteStart)..<(blobData.startIndex + slotByteStart + hashSize)]
                codeHashes.append(slice.map { String(format: "%02x", $0) }.joined())
            }
        }

        let canonicalCDData = Data(blobData[blobData.startIndex..<(blobData.startIndex + effectiveLength)])
        let cdHashHex = BinaryHashAndEntropy.sha256Hex(of: canonicalCDData)

        return CodeDirectoryDetail(
            slotType: slotType,
            version: version,
            flags: flags,
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            hashType: hashType,
            hashAlgorithm: CodeSignatureConstants.hashAlgorithmName(hashType),
            hashByteSize: hashSize,
            pageSize: pageSize,
            codeLimit: finalCodeLimit,
            nSpecialSlots: nSpecialSlots,
            nCodeSlots: nCodeSlots,
            cdHashHex: cdHashHex,
            specialSlotHashesHex: specialHashes,
            codeSlotHashesHex: codeHashes,
            execSegBase: execSegBase,
            execSegLimit: execSegLimit,
            execSegFlags: execSegFlags
        )
    }

    // MARK: - Handwritten XML Entitlements Plist Parser

    public static func parseXMLEntitlementsPlist(_ xml: String) -> [String: String] {
        var result: [String: String] = [:]
        let tokens = tokenizePlistXML(xml)
        var idx = 0

        // Locate outer <dict>
        while idx < tokens.count {
            if case .openTag("dict") = tokens[idx] {
                idx += 1
                break
            }
            idx += 1
        }

        func parseValueDescription() -> String? {
            guard idx < tokens.count else { return nil }
            switch tokens[idx] {
            case .selfClosingTag("true"):
                idx += 1
                return "true"
            case .selfClosingTag("false"):
                idx += 1
                return "false"
            case .selfClosingTag("string"):
                idx += 1
                return ""
            case .selfClosingTag("array"):
                idx += 1
                return "[]"
            case .selfClosingTag("dict"):
                idx += 1
                return "{}"
            case .openTag(let tagName) where tagName == "string" || tagName == "integer" || tagName == "real" || tagName == "data" || tagName == "date":
                idx += 1
                var textValue = ""
                while idx < tokens.count {
                    if case .closeTag(let closing) = tokens[idx], closing == tagName {
                        idx += 1
                        break
                    } else if case .text(let chunk) = tokens[idx] {
                        textValue += chunk
                    }
                    idx += 1
                }
                return unescapeXML(textValue.trimmingCharacters(in: .whitespacesAndNewlines))
            case .openTag("array"):
                idx += 1
                var items: [String] = []
                while idx < tokens.count {
                    if case .closeTag("array") = tokens[idx] {
                        idx += 1
                        break
                    }
                    if let elem = parseValueDescription() {
                        items.append(elem)
                    } else {
                        idx += 1
                    }
                }
                return "[\(items.joined(separator: ", "))]"
            case .openTag("dict"):
                idx += 1
                var nested: [String] = []
                while idx < tokens.count {
                    if case .closeTag("dict") = tokens[idx] {
                        idx += 1
                        break
                    }
                    if case .openTag("key") = tokens[idx] {
                        idx += 1
                        var subKey = ""
                        while idx < tokens.count {
                            if case .closeTag("key") = tokens[idx] {
                                idx += 1
                                break
                            } else if case .text(let t) = tokens[idx] {
                                subKey += t
                            }
                            idx += 1
                        }
                        let subVal = parseValueDescription() ?? ""
                        nested.append("\(unescapeXML(subKey)): \(subVal)")
                    } else {
                        idx += 1
                    }
                }
                return "{\(nested.joined(separator: ", "))}"
            default:
                return nil
            }
        }

        while idx < tokens.count {
            if case .closeTag("dict") = tokens[idx] {
                break
            }
            if case .openTag("key") = tokens[idx] {
                idx += 1
                var keyText = ""
                while idx < tokens.count {
                    if case .closeTag("key") = tokens[idx] {
                        idx += 1
                        break
                    } else if case .text(let chunk) = tokens[idx] {
                        keyText += chunk
                    }
                    idx += 1
                }
                let cleanKey = unescapeXML(keyText.trimmingCharacters(in: .whitespacesAndNewlines))
                if let val = parseValueDescription(), !cleanKey.isEmpty {
                    result[cleanKey] = val
                }
            } else {
                idx += 1
            }
        }

        return result
    }

    private enum XMLToken {
        case openTag(String)
        case closeTag(String)
        case selfClosingTag(String)
        case text(String)
    }

    private static func tokenizePlistXML(_ xml: String) -> [XMLToken] {
        var tokens: [XMLToken] = []
        let scalars = Array(xml.unicodeScalars)
        var i = 0

        while i < scalars.count {
            if scalars[i] == "<" {
                // Skip comments <!-- ... -->, processing instructions <? ... ?>, and <!DOCTYPE ... >
                if i + 3 < scalars.count && scalars[i + 1] == "!" && scalars[i + 2] == "-" && scalars[i + 3] == "-" {
                    i += 4
                    while i + 2 < scalars.count {
                        if scalars[i] == "-" && scalars[i + 1] == "-" && scalars[i + 2] == ">" {
                            i += 3
                            break
                        }
                        i += 1
                    }
                    continue
                }
                if i + 1 < scalars.count && (scalars[i + 1] == "?" || scalars[i + 1] == "!") {
                    i += 2
                    while i < scalars.count && scalars[i] != ">" {
                        i += 1
                    }
                    if i < scalars.count { i += 1 }
                    continue
                }

                i += 1
                var rawTag = ""
                while i < scalars.count && scalars[i] != ">" {
                    rawTag.unicodeScalars.append(scalars[i])
                    i += 1
                }
                if i < scalars.count { i += 1 }

                let trimmed = rawTag.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.hasPrefix("/") {
                    let name = trimmed.dropFirst().trimmingCharacters(in: .whitespacesAndNewlines)
                    tokens.append(.closeTag(String(name)))
                } else if trimmed.hasSuffix("/") {
                    let core = trimmed.dropLast().trimmingCharacters(in: .whitespacesAndNewlines)
                    let name = core.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? core
                    tokens.append(.selfClosingTag(name))
                } else {
                    let name = trimmed.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? trimmed
                    tokens.append(.openTag(name))
                }
            } else {
                var content = ""
                while i < scalars.count && scalars[i] != "<" {
                    content.unicodeScalars.append(scalars[i])
                    i += 1
                }
                if !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    tokens.append(.text(content))
                }
            }
        }

        return tokens
    }

    private static func unescapeXML(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&amp;", with: "&")
    }

    private static func synthesizeXMLPlist(from pairs: [String: String]) -> String {
        var lines: [String] = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
            "<plist version=\"1.0\">",
            "<dict>"
        ]
        for key in pairs.keys.sorted() {
            let val = pairs[key] ?? ""
            lines.append("    <key>\(key)</key>")
            if val == "true" || val == "false" {
                lines.append("    <\(val)/>")
            } else if Int64(val) != nil {
                lines.append("    <integer>\(val)</integer>")
            } else {
                lines.append("    <string>\(val)</string>")
            }
        }
        lines.append("</dict>")
        lines.append("</plist>")
        return lines.joined(separator: "\n")
    }
}

// MARK: - Handwritten ASN.1 DER / CMS SignedData & CoreEntitlements Walker

public enum ASN1DERWalker {
    public enum TagClass: UInt8, Sendable {
        case universal       = 0
        case application     = 1
        case contextSpecific = 2
        case privateClass    = 3
    }

    public struct Node: Sendable {
        public let tagClass: TagClass
        public let isConstructed: Bool
        public let tagNumber: UInt32
        public let valueBytes: [UInt8]
        public let children: [Node]
    }

    // OID 2.5.4.3 (id-at-commonName) = 55 04 03
    private static let oidCommonName: [UInt8] = [0x55, 0x04, 0x03]
    // OID 1.2.840.113549.1.7.2 (pkcs7-signedData) = 2A 86 48 86 F7 0D 01 07 02
    private static let oidPKCS7SignedData: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]

    /// Parses ASN.1 DER bytes into a tree of `Node` values (depth-bounded and bounds-safe).
    public static func parseNodes(bytes: ArraySlice<UInt8>, depth: Int = 0) -> [Node] {
        guard depth <= 24 else { return [] }
        var nodes: [Node] = []
        var cursor = bytes.startIndex
        let end = bytes.endIndex

        while cursor < end {
            let firstByte = bytes[cursor]
            cursor += 1
            // Stop cleanly at 0x00 0x00 end-of-contents marker
            if firstByte == 0x00 {
                if cursor < end && bytes[cursor] == 0x00 {
                    cursor += 1
                }
                break
            }

            let tagClass = TagClass(rawValue: (firstByte >> 6) & 0x03) ?? .universal
            let isConstructed = ((firstByte >> 5) & 0x01) != 0
            var tagNumber = UInt32(firstByte & 0x1F)

            if tagNumber == 0x1F {
                // High-tag-number form (base-128 big-endian)
                tagNumber = 0
                var guardCount = 0
                while cursor < end && guardCount < 5 {
                    let b = bytes[cursor]
                    cursor += 1
                    guardCount += 1
                    tagNumber = (tagNumber << 7) | UInt32(b & 0x7F)
                    if (b & 0x80) == 0 { break }
                }
            }

            guard cursor < end else { break }
            let lenByte = bytes[cursor]
            cursor += 1

            var contentLength = 0
            var isIndefinite = false

            if lenByte == 0x80 {
                isIndefinite = true
            } else if (lenByte & 0x80) == 0 {
                contentLength = Int(lenByte)
            } else {
                let octets = Int(lenByte & 0x7F)
                guard octets > 0 && octets <= 4 && cursor + octets <= end else { break }
                for _ in 0..<octets {
                    contentLength = (contentLength << 8) | Int(bytes[cursor])
                    cursor += 1
                }
            }

            if isIndefinite {
                // Indefinite-length constructed element: recurse until EOC (00 00)
                let subSlice = bytes[cursor..<end]
                let children = isConstructed ? parseNodes(bytes: subSlice, depth: depth + 1) : []
                let valBytes = Array(subSlice)
                nodes.append(
                    Node(
                        tagClass: tagClass,
                        isConstructed: isConstructed,
                        tagNumber: tagNumber,
                        valueBytes: valBytes,
                        children: children
                    )
                )
                break
            } else {
                guard contentLength >= 0 && cursor + contentLength <= end else { break }
                let valueSlice = bytes[cursor..<(cursor + contentLength)]
                cursor += contentLength
                let children = isConstructed ? parseNodes(bytes: valueSlice, depth: depth + 1) : []
                nodes.append(
                    Node(
                        tagClass: tagClass,
                        isConstructed: isConstructed,
                        tagNumber: tagNumber,
                        valueBytes: Array(valueSlice),
                        children: children
                    )
                )
            }
        }

        return nodes
    }

    /// Extracts X.509 certificate Subject `commonName` (`2.5.4.3`) strings from a CMS `SignedData` (`0xFADE0B01`) blob.
    public static func extractCMSSignerCommonNames(cmsData: Data) -> [String] {
        let rawBytes = Array(cmsData)
        let topNodes = parseNodes(bytes: rawBytes[...])
        guard let contentInfo = topNodes.first else { return [] }

        var subjectCommonNames: [String] = []

        // Navigate PKCS#7 ContentInfo -> [0] EXPLICIT SignedData -> [0] IMPLICIT CertificateSet
        if contentInfo.tagClass == .universal,
           contentInfo.tagNumber == 16,
           contentInfo.children.count >= 2,
           contentInfo.children[0].tagClass == .universal,
           contentInfo.children[0].tagNumber == 6,
           contentInfo.children[0].valueBytes == oidPKCS7SignedData {
            let explicitWrapper = contentInfo.children[1]
            if let signedDataNode = explicitWrapper.children.first(where: { $0.tagClass == .universal && $0.tagNumber == 16 }) {
                for fieldNode in signedDataNode.children {
                    // [0] IMPLICIT CertificateSet
                    if fieldNode.tagClass == .contextSpecific && fieldNode.tagNumber == 0 {
                        for certNode in fieldNode.children {
                            if let cn = extractX509SubjectCommonName(from: certNode),
                               !cn.isEmpty,
                               !subjectCommonNames.contains(cn) {
                                subjectCommonNames.append(cn)
                            }
                        }
                    }
                }
            }
        }

        if !subjectCommonNames.isEmpty {
            return subjectCommonNames
        }

        // Fallback recursive scan for OID 2.5.4.3 AttributeTypeAndValue pairs anywhere in CMS tree
        var fallbackNames: [String] = []
        collectCommonNameAttributesRecursively(nodes: topNodes, into: &fallbackNames)
        return fallbackNames
    }

    private static func extractX509SubjectCommonName(from certificateNode: Node) -> String? {
        // Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm, signatureValue }
        guard certificateNode.tagClass == .universal,
              certificateNode.tagNumber == 16,
              let tbsCert = certificateNode.children.first,
              tbsCert.tagClass == .universal,
              tbsCert.tagNumber == 16 else {
            return nil
        }

        // TBSCertificate ::= SEQUENCE {
        //   [0] EXPLICIT Version OPTIONAL,
        //   serialNumber INTEGER,
        //   signature AlgorithmIdentifier,
        //   issuer Name,
        //   validity Validity,
        //   subject Name, ...
        // }
        var idx = 0
        if idx < tbsCert.children.count,
           tbsCert.children[idx].tagClass == .contextSpecific,
           tbsCert.children[idx].tagNumber == 0 {
            idx += 1 // optional [0] version present
        }
        let subjectIndex = idx + 4 // serial(0), sigAlg(1), issuer(2), validity(3), subject(4)
        guard subjectIndex < tbsCert.children.count else { return nil }
        let subjectNode = tbsCert.children[subjectIndex]

        var names: [String] = []
        collectCommonNameAttributesRecursively(nodes: [subjectNode], into: &names)
        return names.first
    }

    private static func collectCommonNameAttributesRecursively(nodes: [Node], into output: inout [String]) {
        for node in nodes {
            // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
            if node.tagClass == .universal,
               node.tagNumber == 16,
               node.children.count >= 2,
               node.children[0].tagClass == .universal,
               node.children[0].tagNumber == 6,
               node.children[0].valueBytes == oidCommonName {
                if let str = decodeASN1String(node.children[1]), !str.isEmpty, !output.contains(str) {
                    output.append(str)
                }
            }
            if !node.children.isEmpty {
                collectCommonNameAttributesRecursively(nodes: node.children, into: &output)
            }
        }
    }

    public static func decodeASN1String(_ node: Node) -> String? {
        guard node.tagClass == .universal else { return nil }
        switch node.tagNumber {
        case 12, 19, 22, 20, 26, 27:
            // UTF8String (12), PrintableString (19), IA5String (22), TeletexString (20), VisibleString (26)
            return String(decoding: node.valueBytes, as: UTF8.self)
        case 30:
            // BMPString (big-endian UTF-16)
            guard node.valueBytes.count % 2 == 0 else { return nil }
            var units: [UInt16] = []
            units.reserveCapacity(node.valueBytes.count / 2)
            var i = 0
            while i + 1 < node.valueBytes.count {
                units.append((UInt16(node.valueBytes[i]) << 8) | UInt16(node.valueBytes[i + 1]))
                i += 2
            }
            return String(utf16CodeUnits: units, count: units.count)
        default:
            return nil
        }
    }

    /// Parses Apple CoreEntitlements DER (`0xFADE7172`) key-value dictionary entries.
    public static func parseDEREntitlements(derData: Data) -> [String: String] {
        let bytes = Array(derData)
        let top = parseNodes(bytes: bytes[...])
        var pairs: [String: String] = [:]

        func walkEntitlementContainer(_ nodes: [Node]) {
            for node in nodes {
                // Key-value pair in CoreEntitlements DER: SEQUENCE { UTF8String key, value }
                if node.tagClass == .universal,
                   node.tagNumber == 16,
                   node.children.count == 2,
                   let key = decodeASN1String(node.children[0]),
                   !key.isEmpty {
                    let valNode = node.children[1]
                    pairs[key] = describeDEREntitlementValue(valNode)
                } else if !node.children.isEmpty {
                    walkEntitlementContainer(node.children)
                }
            }
        }

        walkEntitlementContainer(top)
        return pairs
    }

    private static func describeDEREntitlementValue(_ node: Node) -> String {
        if node.tagClass == .universal {
            switch node.tagNumber {
            case 1: // BOOLEAN
                return (node.valueBytes.first ?? 0) != 0 ? "true" : "false"
            case 2: // INTEGER
                var acc: Int64 = 0
                for b in node.valueBytes.prefix(8) {
                    acc = (acc << 8) | Int64(b)
                }
                return "\(acc)"
            case 12, 19, 22: // Strings
                return String(decoding: node.valueBytes, as: UTF8.self)
            case 16, 17: // SEQUENCE / SET (Array of strings/ints)
                let items = node.children.map { describeDEREntitlementValue($0) }
                return "[\(items.joined(separator: ", "))]"
            default:
                break
            }
        }
        return "0x" + node.valueBytes.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Pure-Swift Ad-Hoc Code Signature Builder (CS_SuperBlob + SHA-256 CS_CodeDirectory)

public enum AdHocCodeSignatureBuilder {
    /// Generates a byte-accurate, page-hashed SHA-256 ad-hoc `CS_SuperBlob` (`0xFADE0CC0`) suitable for Mach-O `__LINKEDIT`.
    public static func buildSuperBlob(
        binarySliceWithoutSignature: Data,
        identifier: String,
        teamID: String? = nil,
        entitlementsXML: String? = nil,
        execSegBase: UInt64 = 0,
        execSegLimit: UInt64 = 0x4000,
        isExecutable: Bool = true,
        pageSizeShift: UInt8 = 12
    ) -> Data {
        let pageSize = 1 << Int(pageSizeShift)
        let codeLimit = binarySliceWithoutSignature.count
        let nCodeSlots = (codeLimit + pageSize - 1) / pageSize

        // Optional XML entitlements CS_GenericBlob (0xFADE7171) + optional DER entitlements (0xFADE7172)
        var entitlementsBlobBytes: [UInt8]?
        var entitlementsSHA256: [UInt8]?

        if let xml = entitlementsXML, !xml.isEmpty {
            let xmlUTF8 = Array(xml.utf8)
            var entWriter = BinaryBufferWriter(capacity: 8 + xmlUTF8.count, endianness: .big)
            entWriter.appendUInt32(CodeSignatureConstants.magicEmbeddedEntitlements)
            entWriter.appendUInt32(UInt32(8 + xmlUTF8.count))
            entWriter.appendBytes(xmlUTF8)
            entitlementsBlobBytes = entWriter.bytes
            entitlementsSHA256 = BinaryHashAndEntropy.sha256Bytes(of: entWriter.data)
        }

        let nSpecialSlots = entitlementsSHA256 != nil ? 5 : 0
        let hashSize = 32 // SHA-256

        // Build CS_CodeDirectory (version 0x20400 = 88-byte fixed header)
        let cdHeaderSize = 88
        let identUTF8 = Array(identifier.utf8) + [0]
        let teamUTF8: [UInt8] = teamID.map { Array($0.utf8) + [0] } ?? []

        let identOffset = cdHeaderSize
        let teamOffset = teamUTF8.isEmpty ? 0 : (identOffset + identUTF8.count)
        let preHashEnd = identOffset + identUTF8.count + teamUTF8.count
        let alignedSpecialHashesStart = (preHashEnd + 7) & ~7
        let hashOffset = alignedSpecialHashesStart + (nSpecialSlots * hashSize)
        let cdTotalLength = hashOffset + (nCodeSlots * hashSize)

        var cdWriter = BinaryBufferWriter(capacity: cdTotalLength, endianness: .big)
        cdWriter.appendUInt32(CodeSignatureConstants.magicCodeDirectory)
        cdWriter.appendUInt32(UInt32(cdTotalLength))
        cdWriter.appendUInt32(CodeSignatureConstants.versionSupportsExecSeg) // 0x20400
        cdWriter.appendUInt32(CodeSignatureConstants.flagAdhoc | CodeSignatureConstants.flagLinkerSigned)
        cdWriter.appendUInt32(UInt32(hashOffset))
        cdWriter.appendUInt32(UInt32(identOffset))
        cdWriter.appendUInt32(UInt32(nSpecialSlots))
        cdWriter.appendUInt32(UInt32(nCodeSlots))
        cdWriter.appendUInt32(UInt32(codeLimit))
        cdWriter.appendUInt8(UInt8(hashSize))
        cdWriter.appendUInt8(CodeSignatureConstants.hashTypeSHA256)
        cdWriter.appendUInt8(0) // platform
        cdWriter.appendUInt8(pageSizeShift)
        cdWriter.appendUInt32(0) // spare2
        cdWriter.appendUInt32(0) // scatterOffset
        cdWriter.appendUInt32(UInt32(teamOffset))
        cdWriter.appendUInt32(0) // spare3
        cdWriter.appendUInt64(0) // codeLimit64
        cdWriter.appendUInt64(execSegBase)
        cdWriter.appendUInt64(execSegLimit)
        cdWriter.appendUInt64(isExecutable ? CodeSignatureConstants.execSegMainBinary : 0)

        cdWriter.appendBytes(identUTF8)
        if !teamUTF8.isEmpty {
            cdWriter.appendBytes(teamUTF8)
        }
        cdWriter.padToAlignment(8)

        // Special slots (-5 .. -1): slot -5 is CSSLOT_ENTITLEMENTS
        if let entHash = entitlementsSHA256 {
            cdWriter.appendBytes(entHash) // slot -5
            for _ in 0..<4 {
                cdWriter.appendBytes([UInt8](repeating: 0, count: hashSize)) // slots -4, -3, -2, -1
            }
        }

        // Code slots (0 ..< nCodeSlots)
        for pageIdx in 0..<nCodeSlots {
            let start = binarySliceWithoutSignature.startIndex + pageIdx * pageSize
            let end = min(start + pageSize, binarySliceWithoutSignature.endIndex)
            let pageData = Data(binarySliceWithoutSignature[start..<end])
            cdWriter.appendBytes(BinaryHashAndEntropy.sha256Bytes(of: pageData))
        }

        // Empty CMS BlobWrapper (0xFADE0B01, 8 bytes) matching standard ad-hoc signature layout
        var cmsWrapper = BinaryBufferWriter(capacity: 8, endianness: .big)
        cmsWrapper.appendUInt32(CodeSignatureConstants.magicBlobWrapper)
        cmsWrapper.appendUInt32(8)

        var subBlobs: [(slotType: UInt32, bytes: [UInt8])] = [
            (CodeSignatureConstants.slotCodeDirectory, cdWriter.bytes)
        ]
        if let entBytes = entitlementsBlobBytes {
            subBlobs.append((CodeSignatureConstants.slotEntitlements, entBytes))
        }
        subBlobs.append((CodeSignatureConstants.slotCMSWrapper, cmsWrapper.bytes))

        let superHeaderSize = 12 + subBlobs.count * 8
        var runningOffset = superHeaderSize
        var offsets: [Int] = []
        for item in subBlobs {
            offsets.append(runningOffset)
            runningOffset += item.bytes.count
        }

        var superWriter = BinaryBufferWriter(capacity: runningOffset + 16, endianness: .big)
        superWriter.appendUInt32(CodeSignatureConstants.magicEmbeddedSignature)
        superWriter.appendUInt32(UInt32(runningOffset))
        superWriter.appendUInt32(UInt32(subBlobs.count))

        for (idx, item) in subBlobs.enumerated() {
            superWriter.appendUInt32(item.slotType)
            superWriter.appendUInt32(UInt32(offsets[idx]))
        }
        for item in subBlobs {
            superWriter.appendBytes(item.bytes)
        }

        return superWriter.data
    }
}
