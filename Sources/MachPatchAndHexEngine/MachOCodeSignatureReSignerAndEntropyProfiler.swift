import Foundation
import CryptoKit
import MachGraphModels
import MachBinaryFormats

// MARK: - Mach-O Code Signature Verification & Re-Signing Models

public struct CodePageSlotMismatch: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { slotIndex }
    public let slotIndex: Int
    public let sliceRelativeOffset: UInt64
    public let absoluteFileOffset: FileOffset
    public let pageByteLength: Int
    public let expectedHashHex: String
    public let computedHashHex: String

    public init(
        slotIndex: Int,
        sliceRelativeOffset: UInt64,
        absoluteFileOffset: FileOffset,
        pageByteLength: Int,
        expectedHashHex: String,
        computedHashHex: String
    ) {
        self.slotIndex = slotIndex
        self.sliceRelativeOffset = sliceRelativeOffset
        self.absoluteFileOffset = absoluteFileOffset
        self.pageByteLength = pageByteLength
        self.expectedHashHex = expectedHashHex
        self.computedHashHex = computedHashHex
    }
}

public struct SpecialSlotMismatch: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { specialSlotIndex }
    public let specialSlotIndex: Int
    public let slotDescription: String
    public let expectedHashHex: String
    public let computedHashHex: String

    public init(
        specialSlotIndex: Int,
        slotDescription: String,
        expectedHashHex: String,
        computedHashHex: String
    ) {
        self.specialSlotIndex = specialSlotIndex
        self.slotDescription = slotDescription
        self.expectedHashHex = expectedHashHex
        self.computedHashHex = computedHashHex
    }
}

public struct CodeSignatureVerificationReport: Sendable, Codable, Hashable {
    public let isSigned: Bool
    public let isValid: Bool
    public let isAdHoc: Bool
    public let identifier: String
    public let teamIdentifier: String?
    public let hashAlgorithm: String
    public let codeDirectoryVersion: UInt32
    public let flags: UInt32
    public let pageSize: Int
    public let codeLimit: UInt64
    public let signatureFileOffset: FileOffset?
    public let signatureByteSize: Int
    public let totalCodeSlots: Int
    public let verifiedCodeSlots: Int
    public let mismatchedCodeSlots: [CodePageSlotMismatch]
    public let verifiedSpecialSlots: Int
    public let mismatchedSpecialSlots: [SpecialSlotMismatch]
    public let cdHashHex: String
    public let cdHashTruncated40Hex: String
    public let hasNonEmptyCMSSignature: Bool
    public let summaryMessage: String

    public init(
        isSigned: Bool,
        isValid: Bool,
        isAdHoc: Bool = false,
        identifier: String = "",
        teamIdentifier: String? = nil,
        hashAlgorithm: String = "SHA-256",
        codeDirectoryVersion: UInt32 = 0,
        flags: UInt32 = 0,
        pageSize: Int = 4096,
        codeLimit: UInt64 = 0,
        signatureFileOffset: FileOffset? = nil,
        signatureByteSize: Int = 0,
        totalCodeSlots: Int = 0,
        verifiedCodeSlots: Int = 0,
        mismatchedCodeSlots: [CodePageSlotMismatch] = [],
        verifiedSpecialSlots: Int = 0,
        mismatchedSpecialSlots: [SpecialSlotMismatch] = [],
        cdHashHex: String = "",
        hasNonEmptyCMSSignature: Bool = false,
        summaryMessage: String
    ) {
        self.isSigned = isSigned
        self.isValid = isValid
        self.isAdHoc = isAdHoc
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.hashAlgorithm = hashAlgorithm
        self.codeDirectoryVersion = codeDirectoryVersion
        self.flags = flags
        self.pageSize = pageSize
        self.codeLimit = codeLimit
        self.signatureFileOffset = signatureFileOffset
        self.signatureByteSize = signatureByteSize
        self.totalCodeSlots = totalCodeSlots
        self.verifiedCodeSlots = verifiedCodeSlots
        self.mismatchedCodeSlots = mismatchedCodeSlots
        self.verifiedSpecialSlots = verifiedSpecialSlots
        self.mismatchedSpecialSlots = mismatchedSpecialSlots
        self.cdHashHex = cdHashHex
        self.cdHashTruncated40Hex = String(cdHashHex.prefix(40))
        self.hasNonEmptyCMSSignature = hasNonEmptyCMSSignature
        self.summaryMessage = summaryMessage
    }
}

public enum MachOReSignStrategy: String, Sendable, Codable, Hashable, CaseIterable {
    case inPlaceIfPossible = "In-Place Dirty Page Recalculation"
    case rebuildSuperBlob = "Full CS_SuperBlob Rebuild"
}

public struct MachOReSignResult: Sendable, Codable, Hashable {
    public let signedBinaryData: Data
    public let updatedSummary: CodeSignatureSummary
    public let verificationReport: CodeSignatureVerificationReport
    public let previousCDHashHex: String?
    public let updatedCDHashHex: String
    public let recalculatedPageSlotIndices: [Int]
    public let usedInPlaceFastPath: Bool
    public let injectedNewLoadCommand: Bool

    public init(
        signedBinaryData: Data,
        updatedSummary: CodeSignatureSummary,
        verificationReport: CodeSignatureVerificationReport,
        previousCDHashHex: String?,
        updatedCDHashHex: String,
        recalculatedPageSlotIndices: [Int],
        usedInPlaceFastPath: Bool,
        injectedNewLoadCommand: Bool
    ) {
        self.signedBinaryData = signedBinaryData
        self.updatedSummary = updatedSummary
        self.verificationReport = verificationReport
        self.previousCDHashHex = previousCDHashHex
        self.updatedCDHashHex = updatedCDHashHex
        self.recalculatedPageSlotIndices = recalculatedPageSlotIndices
        self.usedInPlaceFastPath = usedInPlaceFastPath
        self.injectedNewLoadCommand = injectedNewLoadCommand
    }
}

// MARK: - Pure-Swift Mach-O Ad-Hoc Re-Signer & CS_CodeDirectory Verifier

/// Pure-Swift Mach-O `LC_CODE_SIGNATURE` cryptographic verifier, incremental in-place SHA-256 page-slot recalculator,
/// and full `CS_SuperBlob` ad-hoc re-signer (`CryptoKit.SHA256` + `AdHocCodeSignatureBuilder`, zero `codesign` CLI invocation).
public struct MachOAdHocReSigner: Sendable {
    public init() {}

    // MARK: - End-to-End Code Signature Cryptographic Verification

    /// Verifies every `CS_CodeDirectory` page slot hash (`0..<nCodeSlots`) and populated special slot hash (`-nSpecialSlots..-1`)
    /// inside a standalone Mach-O 64 binary or a selected Universal Fat slice.
    public func verifyCodeSignature(
        in binaryData: Data,
        sliceIndex: Int? = nil
    ) throws -> CodeSignatureVerificationReport {
        let layout = try inspectMachOSliceLayout(in: binaryData, preferredSliceIndex: sliceIndex)
        guard let sigCmd = layout.codeSignatureCommand else {
            return CodeSignatureVerificationReport(
                isSigned: false,
                isValid: false,
                summaryMessage: "Unsigned Mach-O slice (no LC_CODE_SIGNATURE load command)"
            )
        }

        let absSigStart = layout.sliceOffset + Int(sigCmd.dataOff)
        let absSigEnd = absSigStart + Int(sigCmd.dataSize)
        guard sigCmd.dataSize >= 8, absSigEnd <= layout.sliceOffset + layout.sliceSize, absSigEnd <= binaryData.count else {
            throw MachGraphError.codeSignError(
                "LC_CODE_SIGNATURE payload (0x\(String(sigCmd.dataOff, radix: 16))+0x\(String(sigCmd.dataSize, radix: 16))) exceeds Mach-O slice bounds"
            )
        }

        let sigBlob = Data(binaryData[(binaryData.startIndex + absSigStart)..<(binaryData.startIndex + absSigEnd)])
        let (summary, directories) = try CodeSignatureAndCMSParser.parseDetailed(signatureData: sigBlob)
        guard summary.isSigned, !directories.isEmpty else {
            return CodeSignatureVerificationReport(
                isSigned: false,
                isValid: false,
                signatureFileOffset: FileOffset(UInt64(absSigStart)),
                signatureByteSize: Int(sigCmd.dataSize),
                summaryMessage: "LC_CODE_SIGNATURE present but contains zero valid CS_CodeDirectory structures"
            )
        }

        // Prefer SHA-256 directory for primary verification, matching Darwin kernel `amfid` agile evaluation.
        let primaryDir = directories.first(where: { $0.hashType == CodeSignatureConstants.hashTypeSHA256 })
            ?? directories[0]

        let rawLocations = try locateRawSubBlobs(in: sigBlob)
        guard let cdLoc = rawLocations.codeDirectories.first(where: { $0.slotType == primaryDir.slotType })
            ?? rawLocations.codeDirectories.first else {
            throw MachGraphError.codeSignError("Unable to locate raw CS_CodeDirectory header inside CS_SuperBlob")
        }

        let pageSize = cdLoc.pageSize
        guard pageSize > 0 else {
            throw MachGraphError.codeSignError("Invalid CS_CodeDirectory pageSizeShift (\(cdLoc.pageSizeShift))")
        }

        let codeLimit = min(cdLoc.codeLimit, UInt64(sigCmd.dataOff))
        var mismatchedPages: [CodePageSlotMismatch] = []
        var verifiedPages = 0

        let dataStart = binaryData.startIndex
        for slotIdx in 0..<cdLoc.nCodeSlots {
            let slotBytePos = cdLoc.blobOffsetInSig + cdLoc.hashOffset + slotIdx * cdLoc.hashSize
            guard slotBytePos + cdLoc.hashSize <= sigBlob.count else {
                break
            }
            let expectedSlice = sigBlob[(sigBlob.startIndex + slotBytePos)..<(sigBlob.startIndex + slotBytePos + cdLoc.hashSize)]
            let expectedHex = expectedSlice.map { String(format: "%02x", $0) }.joined()

            let pageRelStart = UInt64(slotIdx) * UInt64(pageSize)
            guard pageRelStart < codeLimit else { break }
            let pageRelEnd = min(pageRelStart + UInt64(pageSize), codeLimit)
            let pageLen = Int(pageRelEnd - pageRelStart)

            let absPageStart = layout.sliceOffset + Int(pageRelStart)
            let pageData = Data(binaryData[(dataStart + absPageStart)..<(dataStart + absPageStart + pageLen)])
            let computedBytes = try computeDigest(of: pageData, hashType: cdLoc.hashType, hashSize: cdLoc.hashSize)
            let computedHex = computedBytes.map { String(format: "%02x", $0) }.joined()

            if expectedHex == computedHex {
                verifiedPages += 1
            } else {
                mismatchedPages.append(
                    CodePageSlotMismatch(
                        slotIndex: slotIdx,
                        sliceRelativeOffset: pageRelStart,
                        absoluteFileOffset: FileOffset(UInt64(absPageStart)),
                        pageByteLength: pageLen,
                        expectedHashHex: expectedHex,
                        computedHashHex: computedHex
                    )
                )
            }
        }

        // Verify populated special slots (-nSpecialSlots .. -1) for embedded sub-blobs (Requirements=-2, Entitlements=-5, DEREntitlements=-7)
        var verifiedSpecial = 0
        var mismatchedSpecial: [SpecialSlotMismatch] = []
        let subBlobSlotToSpecialIndex: [(csslot: UInt32, negIndex: Int, name: String)] = [
            (CodeSignatureConstants.slotRequirements, 2, "CSSLOT_REQUIREMENTS (-2)"),
            (CodeSignatureConstants.slotEntitlements, 5, "CSSLOT_ENTITLEMENTS (-5)"),
            (CodeSignatureConstants.slotDEREntitlements, 7, "CSSLOT_DER_ENTITLEMENTS (-7)")
        ]

        for mapping in subBlobSlotToSpecialIndex where mapping.negIndex <= cdLoc.nSpecialSlots {
            let specialBytePos = cdLoc.blobOffsetInSig + cdLoc.hashOffset - (mapping.negIndex * cdLoc.hashSize)
            guard specialBytePos >= cdLoc.blobOffsetInSig + 44,
                  specialBytePos + cdLoc.hashSize <= sigBlob.count else {
                continue
            }
            let expectedBytes = Array(sigBlob[(sigBlob.startIndex + specialBytePos)..<(sigBlob.startIndex + specialBytePos + cdLoc.hashSize)])
            // Zero-filled special slot means optional sub-blob is unbound.
            guard expectedBytes.contains(where: { $0 != 0 }) else { continue }
            let expectedHex = expectedBytes.map { String(format: "%02x", $0) }.joined()

            if let matchingSub = rawLocations.otherSubBlobs.first(where: { $0.slotType == mapping.csslot }) {
                let subData = Data(sigBlob[(sigBlob.startIndex + matchingSub.offset)..<(sigBlob.startIndex + matchingSub.offset + matchingSub.length)])
                let actualBytes = try computeDigest(of: subData, hashType: cdLoc.hashType, hashSize: cdLoc.hashSize)
                let actualHex = actualBytes.map { String(format: "%02x", $0) }.joined()
                if expectedHex == actualHex {
                    verifiedSpecial += 1
                } else {
                    mismatchedSpecial.append(
                        SpecialSlotMismatch(
                            specialSlotIndex: -mapping.negIndex,
                            slotDescription: mapping.name,
                            expectedHashHex: expectedHex,
                            computedHashHex: actualHex
                        )
                    )
                }
            }
        }

        let canonicalCDSlice = Data(sigBlob[(sigBlob.startIndex + cdLoc.blobOffsetInSig)..<(sigBlob.startIndex + cdLoc.blobOffsetInSig + cdLoc.declaredLength)])
        let cdHashHex = computeCDHashHex(codeDirectoryBlob: canonicalCDSlice, hashType: cdLoc.hashType)
        let hasCMS = rawLocations.cmsWrapper.map { $0.length > 8 } ?? false
        let isValid = mismatchedPages.isEmpty && mismatchedSpecial.isEmpty && verifiedPages == cdLoc.nCodeSlots

        let statusText: String
        if isValid {
            statusText = "VALID \(summary.isAdHoc ? "ad-hoc" : "CMS") \(primaryDir.hashAlgorithm) signature (\(verifiedPages)/\(cdLoc.nCodeSlots) code pages, CDHash \(cdHashHex.prefix(16))…)"
        } else {
            statusText = "INVALID signature: \(mismatchedPages.count) corrupted code page(s), \(mismatchedSpecial.count) special slot mismatch(es)"
        }

        return CodeSignatureVerificationReport(
            isSigned: true,
            isValid: isValid,
            isAdHoc: summary.isAdHoc,
            identifier: summary.identifier,
            teamIdentifier: summary.teamIdentifier,
            hashAlgorithm: primaryDir.hashAlgorithm,
            codeDirectoryVersion: primaryDir.version,
            flags: primaryDir.flags,
            pageSize: pageSize,
            codeLimit: codeLimit,
            signatureFileOffset: FileOffset(UInt64(absSigStart)),
            signatureByteSize: Int(sigCmd.dataSize),
            totalCodeSlots: cdLoc.nCodeSlots,
            verifiedCodeSlots: verifiedPages,
            mismatchedCodeSlots: mismatchedPages,
            verifiedSpecialSlots: verifiedSpecial,
            mismatchedSpecialSlots: mismatchedSpecial,
            cdHashHex: cdHashHex,
            hasNonEmptyCMSSignature: hasCMS,
            summaryMessage: statusText
        )
    }

    /// Verifies the code signature of a `SparseCoWByteOverlayBuffer` directly.
    public func verifyCodeSignature(
        in overlay: SparseCoWByteOverlayBuffer,
        sliceIndex: Int? = nil
    ) throws -> CodeSignatureVerificationReport {
        try verifyCodeSignature(in: overlay.materializedData(), sliceIndex: sliceIndex)
    }

    // MARK: - Incremental In-Place Page-Slot Recalculator & Full Ad-Hoc Re-Signer

    /// Recalculates dirty 4096-byte / 16384-byte SHA-256 page hashes inside `CS_CodeDirectory` in-place
    /// (or rebuilds/injects a canonical ad-hoc `CS_SuperBlob` when unsigned or requested) for a `SparseCoWByteOverlayBuffer`.
    public func reSignOverlay(
        _ overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        strategy: MachOReSignStrategy = .inPlaceIfPossible,
        identifierOverride: String? = nil,
        teamIDOverride: String? = nil,
        entitlementsXMLOverride: String? = nil,
        defaultPageSizeShift: UInt8 = 12
    ) throws -> MachOReSignResult {
        let materialized = overlay.materializedData()
        let sliceIdx = image?.selectedSliceIndex
        let layout = try inspectMachOSliceLayout(in: materialized, preferredSliceIndex: sliceIdx)

        // Compute exact modified page indices relative to the active Mach-O slice if using fast path!
        if strategy == .inPlaceIfPossible,
           identifierOverride == nil,
           teamIDOverride == nil,
           entitlementsXMLOverride == nil,
           let sigCmd = layout.codeSignatureCommand {
            let absSigStart = layout.sliceOffset + Int(sigCmd.dataOff)
            let absSigEnd = absSigStart + Int(sigCmd.dataSize)
            if sigCmd.dataSize >= 44, absSigEnd <= materialized.count {
                let sigSlice = Data(materialized[(materialized.startIndex + absSigStart)..<(materialized.startIndex + absSigEnd)])
                if let rawLocs = try? locateRawSubBlobs(in: sigSlice),
                   rawLocs.codeDirectories.contains(where: { $0.hashType == CodeSignatureConstants.hashTypeSHA256 && $0.pageSize > 0 }) {
                    // Check whether baseData also had the exact same signature structure; if baseData was already valid,
                    // we only need to re-hash dirty pages, otherwise re-hash all pages in-place to guarantee 100% validity!
                    let baseValid = (try? verifyCodeSignature(in: overlay.baseData, sliceIndex: layout.selectedSliceIndex).isValid) ?? false
                    let dirtyRanges: [Range<UInt64>]? = baseValid ? overlay.dirtyExtents.map(\.range) : nil
                    return try performInPlaceRecalculation(
                        patchedBinary: materialized,
                        layout: layout,
                        sigCmd: sigCmd,
                        dirtyFileRanges: dirtyRanges
                    )
                }
            }
        }

        let fallbackIdent = identifierOverride
            ?? image.flatMap { $0.codeSignature.identifier.isEmpty ? nil : $0.codeSignature.identifier }
            ?? image?.fileName
            ?? "com.machgraph.patched.binary"

        return try performFullSuperBlobReSign(
            patchedBinary: materialized,
            layout: layout,
            identifier: fallbackIdent,
            teamID: teamIDOverride,
            entitlementsXML: entitlementsXMLOverride,
            preferredPageSizeShift: defaultPageSizeShift
        )
    }

    /// Applies `patches` (if any) to `binaryData` and re-signs the Mach-O image with a verified SHA-256 ad-hoc signature.
    public func reSignMachO(
        binaryData: Data,
        patches: [BytePatchRecord] = [],
        strategy: MachOReSignStrategy = .inPlaceIfPossible,
        sliceIndex: Int? = nil,
        identifier: String? = nil,
        teamID: String? = nil,
        entitlementsXML: String? = nil,
        defaultPageSizeShift: UInt8 = 12
    ) throws -> MachOReSignResult {
        let overlay = try SparseCoWByteOverlayBuffer(baseData: binaryData, patches: patches)
        let materialized = overlay.materializedData()
        let layout = try inspectMachOSliceLayout(in: materialized, preferredSliceIndex: sliceIndex)

        if strategy == .inPlaceIfPossible,
           identifier == nil,
           teamID == nil,
           entitlementsXML == nil,
           let sigCmd = layout.codeSignatureCommand {
            let absSigStart = layout.sliceOffset + Int(sigCmd.dataOff)
            let absSigEnd = absSigStart + Int(sigCmd.dataSize)
            if sigCmd.dataSize >= 44, absSigEnd <= materialized.count {
                let sigSlice = Data(materialized[(materialized.startIndex + absSigStart)..<(materialized.startIndex + absSigEnd)])
                if let rawLocs = try? locateRawSubBlobs(in: sigSlice),
                   rawLocs.codeDirectories.contains(where: { $0.hashType == CodeSignatureConstants.hashTypeSHA256 && $0.pageSize > 0 }) {
                    let baseValid = patches.isEmpty ? false : ((try? verifyCodeSignature(in: binaryData, sliceIndex: layout.selectedSliceIndex).isValid) ?? false)
                    let dirtyRanges: [Range<UInt64>]? = baseValid ? overlay.dirtyExtents.map(\.range) : nil
                    return try performInPlaceRecalculation(
                        patchedBinary: materialized,
                        layout: layout,
                        sigCmd: sigCmd,
                        dirtyFileRanges: dirtyRanges
                    )
                }
            }
        }

        return try performFullSuperBlobReSign(
            patchedBinary: materialized,
            layout: layout,
            identifier: identifier,
            teamID: teamID,
            entitlementsXML: entitlementsXML,
            preferredPageSizeShift: defaultPageSizeShift
        )
    }

    /// Strict in-place recalculator updating `CS_CodeDirectory` page slots, `CS_ADHOC` flags, and `cdHashHex` without altering file size.
    public func recalculateCodeDirectoryInPlace(
        patchedBinaryData: Data,
        dirtyByteRanges: [Range<UInt64>]? = nil,
        sliceIndex: Int? = nil
    ) throws -> MachOReSignResult {
        let layout = try inspectMachOSliceLayout(in: patchedBinaryData, preferredSliceIndex: sliceIndex)
        guard let sigCmd = layout.codeSignatureCommand else {
            throw MachGraphError.codeSignError("Cannot recalculate LC_CODE_SIGNATURE in-place: binary is unsigned")
        }
        return try performInPlaceRecalculation(
            patchedBinary: patchedBinaryData,
            layout: layout,
            sigCmd: sigCmd,
            dirtyFileRanges: dirtyByteRanges
        )
    }

    // MARK: - Internal In-Place & Rebuild Implementations

    private func performInPlaceRecalculation(
        patchedBinary: Data,
        layout: MachOSliceLayout,
        sigCmd: LinkeditDataCmdInfo,
        dirtyFileRanges: [Range<UInt64>]?
    ) throws -> MachOReSignResult {
        var working = Data(patchedBinary)
        let absSigStart = layout.sliceOffset + Int(sigCmd.dataOff)
        let absSigEnd = absSigStart + Int(sigCmd.dataSize)
        guard absSigEnd <= working.count else {
            throw MachGraphError.codeSignError("LC_CODE_SIGNATURE data range exceeds binary size")
        }

        let origSigData = Data(working[(working.startIndex + absSigStart)..<(working.startIndex + absSigEnd)])
        let previousSummary = try? CodeSignatureAndCMSParser.parse(signatureData: origSigData)
        let rawLocs = try locateRawSubBlobs(in: origSigData)
        guard !rawLocs.codeDirectories.isEmpty else {
            throw MachGraphError.codeSignError("No CS_CodeDirectory found in LC_CODE_SIGNATURE for in-place update")
        }

        var updatedSlotUnion = Set<Int>()
        let sliceStartU64 = UInt64(layout.sliceOffset)

        // Update every CS_CodeDirectory present in the SuperBlob (e.g. primary SHA-256 + any alternate agile directories).
        for cd in rawLocs.codeDirectories where cd.pageSize > 0 && cd.hashSize > 0 {
            let codeLimit = min(cd.codeLimit, UInt64(sigCmd.dataOff))
            let cdAbsBase = working.startIndex + absSigStart + cd.blobOffsetInSig

            // Update CS_CodeDirectory flags (+12 bytes BE) -> ensure CS_ADHOC (0x2) is set.
            let adhocFlags = (cd.flags | CodeSignatureConstants.flagAdhoc) & ~CodeSignatureConstants.flagValid
            writeUInt32BE(adhocFlags, into: &working, at: cdAbsBase + 12)

            // Determine which page slots need rehashing for this directory's pageSize.
            let targetSlots: [Int]
            if let ranges = dirtyFileRanges {
                var slots = Set<Int>()
                let pSize = UInt64(cd.pageSize)
                for r in ranges {
                    let clampedLow = max(r.lowerBound, sliceStartU64)
                    let clampedHigh = min(r.upperBound, sliceStartU64 &+ codeLimit)
                    guard clampedHigh > clampedLow else { continue }
                    let firstPage = Int((clampedLow - sliceStartU64) / pSize)
                    let lastPage = Int((clampedHigh - 1 - sliceStartU64) / pSize)
                    if firstPage <= lastPage {
                        for p in firstPage...min(lastPage, max(0, cd.nCodeSlots - 1)) {
                            slots.insert(p)
                        }
                    }
                }
                targetSlots = slots.sorted()
            } else {
                targetSlots = Array(0..<cd.nCodeSlots)
            }

            for slotIdx in targetSlots where slotIdx >= 0 && slotIdx < cd.nCodeSlots {
                let pageRelStart = UInt64(slotIdx) * UInt64(cd.pageSize)
                guard pageRelStart < codeLimit else { continue }
                let pageRelEnd = min(pageRelStart + UInt64(cd.pageSize), codeLimit)
                let absPageStart = working.startIndex + layout.sliceOffset + Int(pageRelStart)
                let absPageEnd = working.startIndex + layout.sliceOffset + Int(pageRelEnd)
                let pageData = Data(working[absPageStart..<absPageEnd])

                let digestBytes = try computeDigest(of: pageData, hashType: cd.hashType, hashSize: cd.hashSize)
                let slotDstStart = cdAbsBase + cd.hashOffset + (slotIdx * cd.hashSize)
                working.replaceSubrange(slotDstStart..<(slotDstStart + cd.hashSize), with: digestBytes)
                updatedSlotUnion.insert(slotIdx)
            }

            // Recompute special slot hashes (-2, -5, -7) in case sub-blobs exist so special slots are guaranteed consistent.
            let specialMappings: [(slotType: UInt32, negIdx: Int)] = [
                (CodeSignatureConstants.slotRequirements, 2),
                (CodeSignatureConstants.slotEntitlements, 5),
                (CodeSignatureConstants.slotDEREntitlements, 7)
            ]
            for sp in specialMappings where sp.negIdx <= cd.nSpecialSlots {
                if let sub = rawLocs.otherSubBlobs.first(where: { $0.slotType == sp.slotType }) {
                    let absSubStart = working.startIndex + absSigStart + sub.offset
                    let subData = Data(working[absSubStart..<(absSubStart + sub.length)])
                    let spDigest = try computeDigest(of: subData, hashType: cd.hashType, hashSize: cd.hashSize)
                    let spDst = cdAbsBase + cd.hashOffset - (sp.negIdx * cd.hashSize)
                    if spDst >= cdAbsBase + 44 {
                        working.replaceSubrange(spDst..<(spDst + cd.hashSize), with: spDigest)
                    }
                }
            }
        }

        // If a non-empty CMS PKCS#7 BlobWrapper (0xFADE0B01) existed over the unpatched binary,
        // neutralize it to an empty 8-byte ad-hoc BlobWrapper in-place so `amfid` validates as pure CS_ADHOC.
        if let cms = rawLocs.cmsWrapper, cms.length > 8 {
            let absCMSStart = working.startIndex + absSigStart + cms.offset
            writeUInt32BE(CodeSignatureConstants.magicBlobWrapper, into: &working, at: absCMSStart)
            writeUInt32BE(8, into: &working, at: absCMSStart + 4)
            let trailingBytes = cms.length - 8
            if trailingBytes > 0 {
                working.replaceSubrange((absCMSStart + 8)..<(absCMSStart + cms.length), with: repeatElement(UInt8(0), count: trailingBytes))
            }
        }

        let updatedSigData = Data(working[(working.startIndex + absSigStart)..<(working.startIndex + absSigEnd)])
        let newSummary = try CodeSignatureAndCMSParser.parse(signatureData: updatedSigData)
        let verification = try verifyCodeSignature(in: working, sliceIndex: layout.selectedSliceIndex)
        guard verification.isValid else {
            throw MachGraphError.codeSignError("Post-recalculation verification failed: \(verification.summaryMessage)")
        }

        return MachOReSignResult(
            signedBinaryData: working,
            updatedSummary: newSummary,
            verificationReport: verification,
            previousCDHashHex: previousSummary?.cdHashHex,
            updatedCDHashHex: verification.cdHashHex,
            recalculatedPageSlotIndices: updatedSlotUnion.sorted(),
            usedInPlaceFastPath: true,
            injectedNewLoadCommand: false
        )
    }

    private func performFullSuperBlobReSign(
        patchedBinary: Data,
        layout: MachOSliceLayout,
        identifier: String?,
        teamID: String?,
        entitlementsXML: String?,
        preferredPageSizeShift: UInt8
    ) throws -> MachOReSignResult {
        // Multi-slice Fat containers where the selected slice is NOT the final slice cannot safely grow __LINKEDIT without colliding with the next slice;
        // verify bounds if growing is needed.
        let sliceEndInFile = layout.sliceOffset + layout.sliceSize
        let isLastByteOfContainer = (sliceEndInFile == patchedBinary.count)

        var existingSummary: CodeSignatureSummary?
        var existingPageShift: UInt8?
        if let sigCmd = layout.codeSignatureCommand {
            let sStart = layout.sliceOffset + Int(sigCmd.dataOff)
            let sEnd = min(patchedBinary.count, sStart + Int(sigCmd.dataSize))
            if sEnd > sStart + 8 {
                let oldSig = Data(patchedBinary[(patchedBinary.startIndex + sStart)..<(patchedBinary.startIndex + sEnd)])
                existingSummary = try? CodeSignatureAndCMSParser.parse(signatureData: oldSig)
                if let locs = try? locateRawSubBlobs(in: oldSig),
                   let cd = locs.codeDirectories.first,
                   cd.pageSizeShift >= 12 && cd.pageSizeShift <= 16 {
                    existingPageShift = cd.pageSizeShift
                }
            }
        }

        let finalIdentifier = identifier
            ?? (existingSummary?.identifier.isEmpty == false ? existingSummary?.identifier : nil)
            ?? "com.machgraph.adhoc.target"
        let finalTeamID = teamID ?? existingSummary?.teamIdentifier
        let finalEntitlements = entitlementsXML ?? existingSummary?.entitlementsXML
        let finalPageShift = existingPageShift ?? preferredPageSizeShift
        let isMainExec = (layout.machFileType == MachOConstants.mhExecute)

        guard let linkeditSeg = layout.linkeditSegment else {
            throw MachGraphError.codeSignError("Cannot re-sign Mach-O slice without a __LINKEDIT LC_SEGMENT_64 command")
        }

        var working = Data(patchedBinary)
        var didInjectLC = false
        let codeSigSliceRelOffset: Int
        let lcCodeSigCmdAbsOffset: Int

        if let existingSigCmd = layout.codeSignatureCommand {
            codeSigSliceRelOffset = Int(existingSigCmd.dataOff)
            lcCodeSigCmdAbsOffset = layout.sliceOffset + existingSigCmd.cmdOffsetInSlice
        } else {
            // Unsigned Mach-O 64: inject a 16-byte LC_CODE_SIGNATURE command right after existing load commands!
            let headerAndCmdsEnd = 32 + Int(layout.sizeOfCmds)
            guard headerAndCmdsEnd + 16 <= layout.firstSectionOffsetInSlice else {
                throw MachGraphError.codeSignError(
                    "Insufficient Mach-O header padding to inject 16-byte LC_CODE_SIGNATURE (need \(headerAndCmdsEnd + 16), first section starts at \(layout.firstSectionOffsetInSlice))"
                )
            }
            let rawLinkeditEnd = Int(linkeditSeg.fileOff + linkeditSeg.fileSize)
            let alignedSigOff = (rawLinkeditEnd + 15) & ~15
            codeSigSliceRelOffset = alignedSigOff
            lcCodeSigCmdAbsOffset = layout.sliceOffset + headerAndCmdsEnd

            // Update mach_header_64.ncmds (+16) and sizeofcmds (+20)
            let hdrAbs = working.startIndex + layout.sliceOffset
            writeUInt32LE(layout.nCmds + 1, into: &working, at: hdrAbs + 16)
            writeUInt32LE(layout.sizeOfCmds + 16, into: &working, at: hdrAbs + 20)

            // Write initial LC_CODE_SIGNATURE command (16 bytes)
            let cmdAbs = working.startIndex + lcCodeSigCmdAbsOffset
            writeUInt32LE(MachOConstants.lcCodeSignature, into: &working, at: cmdAbs)
            writeUInt32LE(16, into: &working, at: cmdAbs + 4)
            writeUInt32LE(UInt32(codeSigSliceRelOffset), into: &working, at: cmdAbs + 8)
            writeUInt32LE(0, into: &working, at: cmdAbs + 12)
            didInjectLC = true
        }

        // Ensure `working` has padding up to `sliceOffset + codeSigSliceRelOffset` if 16-byte alignment added gap bytes.
        let absSigStart = layout.sliceOffset + codeSigSliceRelOffset
        if absSigStart > working.count {
            guard isLastByteOfContainer else {
                throw MachGraphError.codeSignError("Cannot expand non-final Universal Fat slice in-place")
            }
            working.append(contentsOf: repeatElement(UInt8(0), count: absSigStart - working.count))
        }

        // Two-pass exact sizing: build prototype SuperBlob to learn exact byte size so __LINKEDIT & LC_CODE_SIGNATURE headers
        // in page 0 are finalized BEFORE computing page 0's SHA-256 hash!
        let protoPrefix = Data(working[(working.startIndex + layout.sliceOffset)..<(working.startIndex + absSigStart)])
        let protoSuperBlob = AdHocCodeSignatureBuilder.buildSuperBlob(
            binarySliceWithoutSignature: protoPrefix,
            identifier: finalIdentifier,
            teamID: finalTeamID,
            entitlementsXML: finalEntitlements,
            execSegBase: layout.textSegment?.fileOff ?? 0,
            execSegLimit: layout.textSegment?.vmSize ?? 0x4000,
            isExecutable: isMainExec,
            pageSizeShift: finalPageShift
        )

        let newSigSize = protoSuperBlob.count
        let newSliceSize = codeSigSliceRelOffset + newSigSize
        if !isLastByteOfContainer && newSliceSize > layout.sliceSize {
            throw MachGraphError.codeSignError(
                "Rebuilt CS_SuperBlob (\(newSigSize) bytes) exceeds fixed non-final Fat slice capacity"
            )
        }

        // Patch LC_CODE_SIGNATURE.dataoff & datasize + __LINKEDIT.vmsize & filesize BEFORE computing final SHA-256 page hashes!
        let cmdAbs = working.startIndex + lcCodeSigCmdAbsOffset
        writeUInt32LE(UInt32(codeSigSliceRelOffset), into: &working, at: cmdAbs + 8)
        writeUInt32LE(UInt32(newSigSize), into: &working, at: cmdAbs + 12)

        let newLinkeditFileSize = UInt64(newSliceSize) - linkeditSeg.fileOff
        let pageAlignMask = UInt64((1 << Int(max(12, finalPageShift))) - 1)
        let newLinkeditVMSize = max(linkeditSeg.vmSize, (newLinkeditFileSize + pageAlignMask) & ~pageAlignMask)
        let linkeditCmdAbs = working.startIndex + layout.sliceOffset + linkeditSeg.cmdOffsetInSlice
        // segment_command_64 layout: cmd(0,4), cmdsize(4,4), segname(8,16), vmaddr(24,8), vmsize(32,8), fileoff(40,8), filesize(48,8)
        writeUInt64LE(newLinkeditVMSize, into: &working, at: linkeditCmdAbs + 32)
        writeUInt64LE(newLinkeditFileSize, into: &working, at: linkeditCmdAbs + 48)

        // Update Universal Fat slice size header if this is a Fat container and slice is at the end of the file!
        if let fatEntry = layout.fatSliceHeaderLocation, isLastByteOfContainer {
            let fatEntryAbs = working.startIndex + fatEntry.entryOffset
            if fatEntry.is64Bit {
                // fat_arch_64: cputype(4), cpusubtype(4), offset(8), size(8 @ +16)
                if fatEntry.bigEndian {
                    writeUInt64BE(UInt64(newSliceSize), into: &working, at: fatEntryAbs + 16)
                } else {
                    writeUInt64LE(UInt64(newSliceSize), into: &working, at: fatEntryAbs + 16)
                }
            } else {
                // fat_arch: cputype(4), cpusubtype(4), offset(4), size(4 @ +12)
                if fatEntry.bigEndian {
                    writeUInt32BE(UInt32(newSliceSize), into: &working, at: fatEntryAbs + 12)
                } else {
                    writeUInt32LE(UInt32(newSliceSize), into: &working, at: fatEntryAbs + 12)
                }
            }
        }

        // Pass 2: Now that Mach-O header & load commands in page 0 are 100% final, compute the real SHA-256 SuperBlob!
        let finalPrefix = Data(working[(working.startIndex + layout.sliceOffset)..<(working.startIndex + absSigStart)])
        let finalSuperBlob = AdHocCodeSignatureBuilder.buildSuperBlob(
            binarySliceWithoutSignature: finalPrefix,
            identifier: finalIdentifier,
            teamID: finalTeamID,
            entitlementsXML: finalEntitlements,
            execSegBase: layout.textSegment?.fileOff ?? 0,
            execSegLimit: layout.textSegment?.vmSize ?? 0x4000,
            isExecutable: isMainExec,
            pageSizeShift: finalPageShift
        )

        if isLastByteOfContainer {
            working.removeSubrange((working.startIndex + absSigStart)..<working.endIndex)
            working.append(finalSuperBlob)
        } else {
            let dstStart = working.startIndex + absSigStart
            let oldSliceEnd = working.startIndex + layout.sliceOffset + layout.sliceSize
            working.replaceSubrange(dstStart..<(dstStart + finalSuperBlob.count), with: finalSuperBlob)
            if dstStart + finalSuperBlob.count < oldSliceEnd {
                let padLen = oldSliceEnd - (dstStart + finalSuperBlob.count)
                working.replaceSubrange((dstStart + finalSuperBlob.count)..<oldSliceEnd, with: repeatElement(UInt8(0), count: padLen))
            }
        }

        let newSummary = try CodeSignatureAndCMSParser.parse(signatureData: finalSuperBlob)
        let verification = try verifyCodeSignature(in: working, sliceIndex: layout.selectedSliceIndex)
        guard verification.isValid else {
            throw MachGraphError.codeSignError("Re-signed Mach-O failed self-verification: \(verification.summaryMessage)")
        }

        let pageSize = 1 << Int(finalPageShift)
        let slotCount = (finalPrefix.count + pageSize - 1) / pageSize

        return MachOReSignResult(
            signedBinaryData: working,
            updatedSummary: newSummary,
            verificationReport: verification,
            previousCDHashHex: existingSummary?.cdHashHex,
            updatedCDHashHex: verification.cdHashHex,
            recalculatedPageSlotIndices: Array(0..<slotCount),
            usedInPlaceFastPath: false,
            injectedNewLoadCommand: didInjectLC
        )
    }

    // MARK: - Internal Mach-O Header, SuperBlob & Digest Helpers

    private struct FatEntryLocation {
        let entryOffset: Int
        let is64Bit: Bool
        let bigEndian: Bool
    }

    private struct Segment64CmdInfo {
        let cmdOffsetInSlice: Int
        let name: String
        let vmAddr: UInt64
        let vmSize: UInt64
        let fileOff: UInt64
        let fileSize: UInt64
    }

    private struct LinkeditDataCmdInfo {
        let cmdOffsetInSlice: Int
        let dataOff: UInt32
        let dataSize: UInt32
    }

    private struct MachOSliceLayout {
        let selectedSliceIndex: Int
        let sliceOffset: Int
        let sliceSize: Int
        let machFileType: UInt32
        let nCmds: UInt32
        let sizeOfCmds: UInt32
        let firstSectionOffsetInSlice: Int
        let textSegment: Segment64CmdInfo?
        let linkeditSegment: Segment64CmdInfo?
        let codeSignatureCommand: LinkeditDataCmdInfo?
        let fatSliceHeaderLocation: FatEntryLocation?
    }

    private struct RawCodeDirectoryLoc {
        let slotType: UInt32
        let blobOffsetInSig: Int
        let declaredLength: Int
        let version: UInt32
        let flags: UInt32
        let hashOffset: Int
        let nSpecialSlots: Int
        let nCodeSlots: Int
        let codeLimit: UInt64
        let hashSize: Int
        let hashType: UInt8
        let pageSizeShift: UInt8
        var pageSize: Int { (pageSizeShift > 0 && pageSizeShift < 31) ? (1 << Int(pageSizeShift)) : 0 }
    }

    private struct RawSubBlobLoc {
        let slotType: UInt32
        let offset: Int
        let length: Int
    }

    private struct RawSuperBlobLocations {
        let codeDirectories: [RawCodeDirectoryLoc]
        let cmsWrapper: RawSubBlobLoc?
        let otherSubBlobs: [RawSubBlobLoc]
    }

    private func inspectMachOSliceLayout(
        in data: Data,
        preferredSliceIndex: Int?
    ) throws -> MachOSliceLayout {
        guard data.count >= 32 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 32, available: data.count)
        }

        let format = UniversalBinaryDispatcher.detectFormat(data: data)
        var sliceOffset = 0
        var sliceSize = data.count
        var chosenSlice = 0
        var fatHeaderLoc: FatEntryLocation?

        if format == .universalFat {
            let slices = try UniversalBinaryDispatcher.parseUniversalSlices(data: data)
            chosenSlice = try UniversalBinaryDispatcher.selectPreferredSliceIndex(in: slices, preferredSliceIndex: preferredSliceIndex)
            let s = slices[chosenSlice]
            sliceOffset = Int(s.fileOffset.rawValue)
            sliceSize = Int(s.size)

            var magicReader = BinarySliceReader(data: data, endianness: .big)
            let fatMagic = try magicReader.readUInt32()
            let is64 = (fatMagic == MachOConstants.fatMagic64 || fatMagic == MachOConstants.fatCigam64)
            let isBE = (fatMagic == MachOConstants.fatMagic || fatMagic == MachOConstants.fatMagic64)
            let stride = is64 ? 32 : 20
            fatHeaderLoc = FatEntryLocation(entryOffset: 8 + chosenSlice * stride, is64Bit: is64, bigEndian: isBE)
        } else if format != .machO64 {
            throw MachGraphError.unsupportedContainer("Mach-O ad-hoc re-signer requires Mach-O 64 or Universal Fat container (got \(format.rawValue))")
        }

        var reader = try BinarySliceReader(data: data, offset: sliceOffset, length: sliceSize, endianness: .little)
        let mhMagic = try reader.readUInt32()
        guard mhMagic == MachOConstants.mhMagic64 else {
            throw MachGraphError.invalidMagic(expected: "0xFEEDFACF (MH_MAGIC_64)", actualHex: String(format: "0x%08X", mhMagic))
        }
        _ = try reader.readInt32() // cputype
        _ = try reader.readInt32() // cpusubtype
        let fileType = try reader.readUInt32()
        let nCmds = try reader.readUInt32()
        let sizeOfCmds = try reader.readUInt32()
        _ = try reader.readUInt32() // flags
        _ = try reader.readUInt32() // reserved

        guard 32 + Int(sizeOfCmds) <= sliceSize else {
            throw MachGraphError.malformedHeader("Mach-O sizeofcmds (\(sizeOfCmds)) exceeds slice size (\(sliceSize))")
        }

        var textSeg: Segment64CmdInfo?
        var linkeditSeg: Segment64CmdInfo?
        var codeSigCmd: LinkeditDataCmdInfo?
        var earliestSectionOff = sliceSize

        var cmdCursor = 32
        for cmdIdx in 0..<Int(nCmds) {
            guard cmdCursor + 8 <= 32 + Int(sizeOfCmds) else {
                throw MachGraphError.malformedLoadCommand(index: cmdIdx, detail: "Load command header truncated")
            }
            try reader.seek(to: cmdCursor)
            let cmd = try reader.readUInt32()
            let cmdSize = Int(try reader.readUInt32())
            guard cmdSize >= 8, cmdCursor + cmdSize <= 32 + Int(sizeOfCmds) else {
                throw MachGraphError.malformedLoadCommand(index: cmdIdx, detail: "Invalid cmdsize (\(cmdSize))")
            }

            if cmd == MachOConstants.lcSegment64 && cmdSize >= 72 {
                let segName = try reader.readFixedASCII(16)
                let vmAddr = try reader.readUInt64()
                let vmSize = try reader.readUInt64()
                let fileOff = try reader.readUInt64()
                let fileSize = try reader.readUInt64()
                _ = try reader.readInt32() // maxprot
                _ = try reader.readInt32() // initprot
                let nSects = Int(try reader.readUInt32())
                _ = try reader.readUInt32() // flags

                let info = Segment64CmdInfo(
                    cmdOffsetInSlice: cmdCursor,
                    name: segName,
                    vmAddr: vmAddr,
                    vmSize: vmSize,
                    fileOff: fileOff,
                    fileSize: fileSize
                )
                if segName == "__TEXT" {
                    textSeg = info
                } else if segName == "__LINKEDIT" {
                    linkeditSeg = info
                }

                // Inspect section_64 headers (80 bytes each) to find the earliest non-zero section fileoff after load commands.
                for sIdx in 0..<nSects {
                    let secHdrPos = cmdCursor + 72 + sIdx * 80
                    guard secHdrPos + 80 <= cmdCursor + cmdSize else { break }
                    try reader.seek(to: secHdrPos + 40) // sectname(16)+segname(16)+addr(8) -> size(8 @ +40), offset(4 @ +48)
                    let secSize = try reader.readUInt64()
                    let secOff = Int(try reader.readUInt32())
                    if secSize > 0 && secOff > 32 && secOff < earliestSectionOff {
                        earliestSectionOff = secOff
                    }
                }
            } else if cmd == MachOConstants.lcCodeSignature && cmdSize >= 16 {
                let dataOff = try reader.readUInt32()
                let dataSize = try reader.readUInt32()
                codeSigCmd = LinkeditDataCmdInfo(
                    cmdOffsetInSlice: cmdCursor,
                    dataOff: dataOff,
                    dataSize: dataSize
                )
            }

            cmdCursor += cmdSize
        }

        return MachOSliceLayout(
            selectedSliceIndex: chosenSlice,
            sliceOffset: sliceOffset,
            sliceSize: sliceSize,
            machFileType: fileType,
            nCmds: nCmds,
            sizeOfCmds: sizeOfCmds,
            firstSectionOffsetInSlice: earliestSectionOff,
            textSegment: textSeg,
            linkeditSegment: linkeditSeg,
            codeSignatureCommand: codeSigCmd,
            fatSliceHeaderLocation: fatHeaderLoc
        )
    }

    private func locateRawSubBlobs(in sigBlob: Data) throws -> RawSuperBlobLocations {
        guard sigBlob.count >= 8 else {
            throw MachGraphError.codeSignError("Signature blob shorter than 8 bytes")
        }
        var r = BinarySliceReader(data: sigBlob, endianness: .big)
        let magic = try r.readUInt32()
        let totalLen = min(sigBlob.count, max(8, Int(try r.readUInt32())))

        if magic == CodeSignatureConstants.magicCodeDirectory {
            let cd = try parseRawCDLoc(in: sigBlob, offset: 0, slotType: CodeSignatureConstants.slotCodeDirectory)
            return RawSuperBlobLocations(codeDirectories: [cd], cmsWrapper: nil, otherSubBlobs: [])
        }

        guard magic == CodeSignatureConstants.magicEmbeddedSignature
            || magic == CodeSignatureConstants.magicDetachedSignature else {
            throw MachGraphError.codeSignError(String(format: "Unexpected CS_SuperBlob magic 0x%08X", magic))
        }
        guard totalLen >= 12 else {
            throw MachGraphError.codeSignError("Truncated CS_SuperBlob")
        }

        let count = Int(try r.readUInt32())
        guard count >= 0 && count <= 256 && 12 + count * 8 <= totalLen else {
            throw MachGraphError.codeSignError("Invalid CS_SuperBlob index count (\(count))")
        }

        var entries: [(slot: UInt32, off: Int)] = []
        for _ in 0..<count {
            entries.append((try r.readUInt32(), Int(try r.readUInt32())))
        }

        var cds: [RawCodeDirectoryLoc] = []
        var cmsLoc: RawSubBlobLoc?
        var others: [RawSubBlobLoc] = []

        for item in entries where item.off >= 12 && item.off + 8 <= totalLen {
            var sub = try BinarySliceReader(data: sigBlob, offset: item.off, length: totalLen - item.off, endianness: .big)
            let subMagic = try sub.readUInt32()
            let subLen = min(totalLen - item.off, max(8, Int(try sub.readUInt32())))
            switch subMagic {
            case CodeSignatureConstants.magicCodeDirectory:
                if let cd = try? parseRawCDLoc(in: sigBlob, offset: item.off, slotType: item.slot) {
                    cds.append(cd)
                }
            case CodeSignatureConstants.magicBlobWrapper:
                cmsLoc = RawSubBlobLoc(slotType: item.slot, offset: item.off, length: subLen)
            default:
                others.append(RawSubBlobLoc(slotType: item.slot, offset: item.off, length: subLen))
            }
        }

        return RawSuperBlobLocations(codeDirectories: cds, cmsWrapper: cmsLoc, otherSubBlobs: others)
    }

    private func parseRawCDLoc(in sigBlob: Data, offset: Int, slotType: UInt32) throws -> RawCodeDirectoryLoc {
        guard offset + 44 <= sigBlob.count else {
            throw MachGraphError.codeSignError("Truncated CS_CodeDirectory")
        }
        var r = try BinarySliceReader(data: sigBlob, offset: offset, length: sigBlob.count - offset, endianness: .big)
        let magic = try r.readUInt32()
        guard magic == CodeSignatureConstants.magicCodeDirectory else {
            throw MachGraphError.codeSignError("Invalid CS_CodeDirectory magic")
        }
        let length = min(sigBlob.count - offset, max(44, Int(try r.readUInt32())))
        let version = try r.readUInt32()
        let flags = try r.readUInt32()
        let hashOffset = Int(try r.readUInt32())
        _ = try r.readUInt32() // identOffset
        let nSpecial = Int(try r.readUInt32())
        let nCode = Int(try r.readUInt32())
        let codeLimit32 = UInt64(try r.readUInt32())
        let hashSize = Int(try r.readUInt8())
        let hashType = try r.readUInt8()
        _ = try r.readUInt8() // platform
        let pageShift = try r.readUInt8()
        _ = try r.readUInt32() // spare2

        var codeLimit64: UInt64 = 0
        if version >= CodeSignatureConstants.versionSupportsCodeLimit64 && r.remaining >= 20 {
            _ = try r.readUInt32() // scatter
            _ = try r.readUInt32() // team
            _ = try r.readUInt32() // spare3
            codeLimit64 = try r.readUInt64()
        }

        return RawCodeDirectoryLoc(
            slotType: slotType,
            blobOffsetInSig: offset,
            declaredLength: length,
            version: version,
            flags: flags,
            hashOffset: hashOffset,
            nSpecialSlots: nSpecial,
            nCodeSlots: nCode,
            codeLimit: codeLimit64 > 0 ? codeLimit64 : codeLimit32,
            hashSize: hashSize,
            hashType: hashType,
            pageSizeShift: pageShift
        )
    }

    private func computeDigest(of data: Data, hashType: UInt8, hashSize: Int) throws -> [UInt8] {
        let full: [UInt8]
        switch hashType {
        case CodeSignatureConstants.hashTypeSHA256, CodeSignatureConstants.hashTypeSHA256Truncated:
            full = Array(SHA256.hash(data: data))
        case CodeSignatureConstants.hashTypeSHA384:
            full = Array(SHA384.hash(data: data))
        case CodeSignatureConstants.hashTypeSHA512:
            full = Array(SHA512.hash(data: data))
        case CodeSignatureConstants.hashTypeSHA1:
            full = Array(Insecure.SHA1.hash(data: data))
        default:
            throw MachGraphError.codeSignError("Unsupported CS_CodeDirectory hashType (\(hashType))")
        }
        if hashSize <= full.count {
            return Array(full.prefix(hashSize))
        }
        return full + [UInt8](repeating: 0, count: hashSize - full.count)
    }

    private func computeCDHashHex(codeDirectoryBlob: Data, hashType: UInt8) -> String {
        switch hashType {
        case CodeSignatureConstants.hashTypeSHA384:
            return SHA384.hash(data: codeDirectoryBlob).prefix(32).map { String(format: "%02x", $0) }.joined()
        case CodeSignatureConstants.hashTypeSHA1:
            return Insecure.SHA1.hash(data: codeDirectoryBlob).map { String(format: "%02x", $0) }.joined()
        default:
            return SHA256.hash(data: codeDirectoryBlob).map { String(format: "%02x", $0) }.joined()
        }
    }

    private func writeUInt32BE(_ value: UInt32, into data: inout Data, at index: Int) {
        data[index]     = UInt8(truncatingIfNeeded: value >> 24)
        data[index + 1] = UInt8(truncatingIfNeeded: value >> 16)
        data[index + 2] = UInt8(truncatingIfNeeded: value >> 8)
        data[index + 3] = UInt8(truncatingIfNeeded: value)
    }

    private func writeUInt64BE(_ value: UInt64, into data: inout Data, at index: Int) {
        for i in 0..<8 {
            data[index + i] = UInt8(truncatingIfNeeded: value >> ((7 - i) * 8))
        }
    }

    private func writeUInt32LE(_ value: UInt32, into data: inout Data, at index: Int) {
        data[index]     = UInt8(truncatingIfNeeded: value)
        data[index + 1] = UInt8(truncatingIfNeeded: value >> 8)
        data[index + 2] = UInt8(truncatingIfNeeded: value >> 16)
        data[index + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    private func writeUInt64LE(_ value: UInt64, into data: inout Data, at index: Int) {
        for i in 0..<8 {
            data[index + i] = UInt8(truncatingIfNeeded: value >> (i * 8))
        }
    }
}

// MARK: - High-Resolution Sliding-Window Entropy, Bigram Chi-Square & Anomaly Profiler

public enum HighEntropyPayloadNature: String, Sendable, Codable, Hashable, CaseIterable {
    case sparseZeroPadding = "Zero / Alignment Padding"
    case lowEntropyStructured = "Structured Tables / Text"
    case nativeInstructionStream = "Native Machine Instructions"
    case compressedArchiveStream = "Compressed Stream (Deflate/LZMA/LZFSE)"
    case uniformCryptographicOrPRNG = "Uniform Encrypted / Cryptographic Blob"
}

public struct ChiSquareRandomnessMetrics: Sendable, Codable, Hashable {
    public let sampleByteCount: Int
    public let shannonEntropyBits: Double
    public let minEntropyBits: Double
    public let zeroByteRatio: Double
    public let printableByteRatio: Double
    public let byteChiSquare: Double
    public let byteChiSquarePValue: Double
    public let nibbleBigramChiSquare: Double
    public let bigramConditionalEntropyBits: Double
    public let serialCorrelationCoefficient: Double
    public let monteCarloPiEstimate: Double
    public let monteCarloPiRelativeError: Double
    public let inferredNature: HighEntropyPayloadNature

    public init(
        sampleByteCount: Int,
        shannonEntropyBits: Double,
        minEntropyBits: Double,
        zeroByteRatio: Double,
        printableByteRatio: Double,
        byteChiSquare: Double,
        byteChiSquarePValue: Double,
        nibbleBigramChiSquare: Double,
        bigramConditionalEntropyBits: Double,
        serialCorrelationCoefficient: Double,
        monteCarloPiEstimate: Double,
        monteCarloPiRelativeError: Double,
        inferredNature: HighEntropyPayloadNature
    ) {
        self.sampleByteCount = sampleByteCount
        self.shannonEntropyBits = shannonEntropyBits
        self.minEntropyBits = minEntropyBits
        self.zeroByteRatio = zeroByteRatio
        self.printableByteRatio = printableByteRatio
        self.byteChiSquare = byteChiSquare
        self.byteChiSquarePValue = byteChiSquarePValue
        self.nibbleBigramChiSquare = nibbleBigramChiSquare
        self.bigramConditionalEntropyBits = bigramConditionalEntropyBits
        self.serialCorrelationCoefficient = serialCorrelationCoefficient
        self.monteCarloPiEstimate = monteCarloPiEstimate
        self.monteCarloPiRelativeError = monteCarloPiRelativeError
        self.inferredNature = inferredNature
    }
}

public enum EntropyAnomalyKind: String, Sendable, Codable, Hashable, CaseIterable {
    case packedOrEncryptedCodeSection = "High-Entropy Executable Code Section"
    case cryptographicPayloadBlob = "Uniform Cryptographic / Random Payload"
    case compressedEmbeddedStream = "Embedded Compressed Archive Stream"
    case writableExecutableSegment = "Writable + Executable (RWX) Segment"
    case sharpIntraSectionEntropyCliff = "Sharp Intra-Section Entropy Cliff"
}

public struct EntropySectionAnomaly: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue)@\(fileOffset.hexString)" }
    public let kind: EntropyAnomalyKind
    public let severity: SecurityFindingSeverity
    public let sectionName: String
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress?
    public let byteLength: Int
    public let title: String
    public let detail: String
    public let randomnessMetrics: ChiSquareRandomnessMetrics

    public init(
        kind: EntropyAnomalyKind,
        severity: SecurityFindingSeverity,
        sectionName: String,
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress?,
        byteLength: Int,
        title: String,
        detail: String,
        randomnessMetrics: ChiSquareRandomnessMetrics
    ) {
        self.kind = kind
        self.severity = severity
        self.sectionName = sectionName
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.byteLength = byteLength
        self.title = title
        self.detail = detail
        self.randomnessMetrics = randomnessMetrics
    }
}

public struct BinaryEntropyProfileReport: Sendable, Codable, Hashable {
    public let windowSize: Int
    public let stepSize: Int
    public let overallMetrics: ChiSquareRandomnessMetrics
    public let samples: [EntropyRegionSample]
    public let sectionMetrics: [String: ChiSquareRandomnessMetrics]
    public let anomalies: [EntropySectionAnomaly]

    public init(
        windowSize: Int,
        stepSize: Int,
        overallMetrics: ChiSquareRandomnessMetrics,
        samples: [EntropyRegionSample],
        sectionMetrics: [String: ChiSquareRandomnessMetrics],
        anomalies: [EntropySectionAnomaly]
    ) {
        self.windowSize = windowSize
        self.stepSize = stepSize
        self.overallMetrics = overallMetrics
        self.samples = samples
        self.sectionMetrics = sectionMetrics
        self.anomalies = anomalies
    }
}

/// High-resolution sliding-window Shannon entropy, Pearson byte/bigram $\chi^2$ randomness tester,
/// first-order Markov conditional entropy estimator, and packed/encrypted/compressed section anomaly detector.
public struct SlidingWindowEntropyProfiler: Sendable {
    public let defaultWindowSize: Int
    public let defaultStepSize: Int

    public init(defaultWindowSize: Int = 1_024, defaultStepSize: Int = 512) {
        self.defaultWindowSize = max(16, defaultWindowSize)
        self.defaultStepSize = max(16, defaultStepSize)
    }

    // MARK: - Sliding-Window Entropy Sampling ([EntropyRegionSample])

    /// Computes sliding-window `[EntropyRegionSample]` measurements across `data`, annotating section names and virtual addresses when `image` is supplied.
    public func profile(
        data: Data,
        image: LoadedBinaryImage? = nil,
        windowSize: Int? = nil,
        stepSize: Int? = nil
    ) -> [EntropyRegionSample] {
        guard !data.isEmpty else { return [] }
        let win = max(16, min(windowSize ?? defaultWindowSize, data.count))
        let step = max(8, stepSize ?? min(defaultStepSize, win))

        let translator = FastOffsetAddressTranslator(image: image)
        var samples: [EntropyRegionSample] = []
        samples.reserveCapacity(max(1, (data.count - win) / step + 2))

        let rawBytes = Array(data)
        var pos = 0
        while pos < rawBytes.count {
            let end = min(pos + win, rawBytes.count)
            let slice = rawBytes[pos..<end]
            let len = end - pos
            if len < max(16, win / 4) && !samples.isEmpty {
                break
            }

            let fileOff = FileOffset(UInt64(pos))
            let va = translator.virtualAddress(for: fileOff)
            let secName = resolveSectionLabel(offset: fileOff, va: va, image: image)
            let stats = Self.fastWindowStats(slice)

            samples.append(
                EntropyRegionSample(
                    fileOffset: fileOff,
                    virtualAddress: va,
                    length: len,
                    sectionName: secName,
                    entropyBitsPerByte: stats.entropy,
                    zeroByteRatio: stats.zeroRatio,
                    printableByteRatio: stats.printableRatio
                )
            )

            if end == rawBytes.count { break }
            pos += step
        }

        return samples
    }

    /// Computes sliding-window `[EntropyRegionSample]` measurements directly over a `SparseCoWByteOverlayBuffer`.
    public func profile(
        overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        windowSize: Int? = nil,
        stepSize: Int? = nil
    ) -> [EntropyRegionSample] {
        guard overlay.count > 0 else { return [] }
        let win = max(16, min(windowSize ?? defaultWindowSize, overlay.count))
        let step = max(8, stepSize ?? min(defaultStepSize, win))

        let translator = FastOffsetAddressTranslator(image: image)
        var samples: [EntropyRegionSample] = []
        samples.reserveCapacity(max(1, (overlay.count - win) / step + 2))

        var pos = 0
        while pos < overlay.count {
            let end = min(pos + win, overlay.count)
            let len = end - pos
            if len < max(16, win / 4) && !samples.isEmpty {
                break
            }
            guard let chunk = try? overlay.readBytes(offset: UInt64(pos), count: len) else {
                break
            }

            let fileOff = FileOffset(UInt64(pos))
            let va = translator.virtualAddress(for: fileOff)
            let secName = resolveSectionLabel(offset: fileOff, va: va, image: image)
            let stats = Self.fastWindowStats(chunk[...])

            samples.append(
                EntropyRegionSample(
                    fileOffset: fileOff,
                    virtualAddress: va,
                    length: len,
                    sectionName: secName,
                    entropyBitsPerByte: stats.entropy,
                    zeroByteRatio: stats.zeroRatio,
                    printableByteRatio: stats.printableRatio
                )
            )

            if end == overlay.count { break }
            pos += step
        }

        return samples
    }

    // MARK: - Full Statistical Randomness & Section Anomaly Analysis

    /// Runs sliding-window entropy profiling, per-section Pearson byte/bigram $\chi^2$ randomness tests, and anomaly detection.
    public func analyzeFullProfile(
        data: Data,
        image: LoadedBinaryImage? = nil,
        windowSize: Int? = nil,
        stepSize: Int? = nil
    ) -> BinaryEntropyProfileReport {
        let win = max(16, min(windowSize ?? defaultWindowSize, max(16, data.count)))
        let step = max(8, stepSize ?? min(defaultStepSize, win))
        let samples = profile(data: data, image: image, windowSize: win, stepSize: step)
        let rawBytes = Array(data)
        let overall = computeRandomnessMetrics(bytes: rawBytes[...])

        var perSection: [String: ChiSquareRandomnessMetrics] = [:]
        if let image {
            let sliceBase = Int(image.sliceFileOffset.rawValue)
            for sec in image.sections where sec.kind != .bss && sec.size > 0 {
                let sStart = sliceBase + Int(sec.fileOffset.rawValue)
                let sEnd = min(rawBytes.count, sStart + Int(sec.size))
                guard sStart >= 0 && sEnd > sStart else { continue }
                perSection[sec.fullName] = computeRandomnessMetrics(bytes: rawBytes[sStart..<sEnd])
            }
        }

        let anomalies = detectAnomalies(in: rawBytes, image: image, samples: samples, precomputedSectionMetrics: perSection)
        return BinaryEntropyProfileReport(
            windowSize: win,
            stepSize: step,
            overallMetrics: overall,
            samples: samples,
            sectionMetrics: perSection,
            anomalies: anomalies
        )
    }

    public func analyzeFullProfile(
        overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        windowSize: Int? = nil,
        stepSize: Int? = nil
    ) -> BinaryEntropyProfileReport {
        analyzeFullProfile(
            data: overlay.materializedData(),
            image: image,
            windowSize: windowSize,
            stepSize: stepSize
        )
    }

    /// Computes Shannon entropy, NIST min-entropy, 256-bin byte $\chi^2$ + $p$-value, 256-bin nibble-bigram $\chi^2$,
    /// 65,536-cell byte-bigram conditional entropy $H(X_t \mid X_{t-1})$, lag-1 autocorrelation, and Monte Carlo $\pi$ error.
    public func computeRandomnessMetrics(bytes: ArraySlice<UInt8>) -> ChiSquareRandomnessMetrics {
        let n = bytes.count
        guard n > 0 else {
            return ChiSquareRandomnessMetrics(
                sampleByteCount: 0,
                shannonEntropyBits: 0,
                minEntropyBits: 0,
                zeroByteRatio: 1.0,
                printableByteRatio: 0.0,
                byteChiSquare: 0,
                byteChiSquarePValue: 0,
                nibbleBigramChiSquare: 0,
                bigramConditionalEntropyBits: 0,
                serialCorrelationCoefficient: 0,
                monteCarloPiEstimate: 0,
                monteCarloPiRelativeError: 1.0,
                inferredNature: .sparseZeroPadding
            )
        }

        var hist = [Int](repeating: 0, count: 256)
        var printableCount = 0
        for b in bytes {
            hist[Int(b)] &+= 1
            if b >= 0x20 && b <= 0x7E {
                printableCount &+= 1
            }
        }

        let invN = 1.0 / Double(n)
        let expectedPerByte = Double(n) / 256.0
        var shannon = 0.0
        var maxCount = 0
        var chiSq = 0.0

        for count in hist {
            if count > maxCount { maxCount = count }
            if count > 0 {
                let p = Double(count) * invN
                shannon -= p * Foundation.log2(p)
            }
            let diff = Double(count) - expectedPerByte
            chiSq += (diff * diff) / expectedPerByte
        }
        shannon = max(0.0, min(8.0, shannon))
        let minEnt = maxCount > 0 ? max(0.0, -Foundation.log2(Double(maxCount) * invN)) : 0.0
        let zeroRatio = Double(hist[0]) * invN
        let printableRatio = Double(printableCount) * invN
        let pVal = Self.chiSquareUpperTailPValue(chiSq: chiSq, degreesOfFreedom: 255.0)

        // Byte-bigram joint entropy H(X_{t-1}, X_t), nibble-bigram chi-square (16x16 = 256 cells), and lag-1 serial correlation.
        var nibbleBigramChiSq = 0.0
        var condEntropy = shannon
        var serialCorr = 0.0

        if n >= 2 {
            let pairCount = n - 1
            var nibblePairs = [Int](repeating: 0, count: 256)
            // Sparse or flat 65,536-entry bigram table when n >= 512, else compact Dictionary for tiny slices.
            if pairCount >= 512 {
                var bigramCounts = [Int](repeating: 0, count: 65_536)
                var prev = bytes[bytes.startIndex]
                var sumX = 0.0
                var sumY = 0.0
                var sumXY = 0.0
                var sumX2 = 0.0
                var sumY2 = 0.0

                var idx = bytes.index(after: bytes.startIndex)
                while idx < bytes.endIndex {
                    let cur = bytes[idx]
                    bigramCounts[(Int(prev) << 8) | Int(cur)] &+= 1
                    nibblePairs[Int((prev & 0x0F) << 4) | Int(cur >> 4)] &+= 1

                    let x = Double(prev)
                    let y = Double(cur)
                    sumX += x
                    sumY += y
                    sumXY += x * y
                    sumX2 += x * x
                    sumY2 += y * y

                    prev = cur
                    idx = bytes.index(after: idx)
                }

                let invPairs = 1.0 / Double(pairCount)
                var jointEntropy = 0.0
                for c in bigramCounts where c > 0 {
                    let p = Double(c) * invPairs
                    jointEntropy -= p * Foundation.log2(p)
                }
                condEntropy = max(0.0, min(8.0, jointEntropy - shannon))

                let pd = Double(pairCount)
                let num = pd * sumXY - sumX * sumY
                let denX = pd * sumX2 - sumX * sumX
                let denY = pd * sumY2 - sumY * sumY
                let denom = (denX * denY).squareRoot()
                if denom > 1e-9 {
                    serialCorr = max(-1.0, min(1.0, num / denom))
                }
            } else {
                var pairMap: [UInt16: Int] = [:]
                pairMap.reserveCapacity(pairCount)
                var prev = bytes[bytes.startIndex]
                var sumX = 0.0
                var sumY = 0.0
                var sumXY = 0.0
                var sumX2 = 0.0
                var sumY2 = 0.0

                var idx = bytes.index(after: bytes.startIndex)
                while idx < bytes.endIndex {
                    let cur = bytes[idx]
                    let key = (UInt16(prev) << 8) | UInt16(cur)
                    pairMap[key, default: 0] += 1
                    nibblePairs[Int((prev & 0x0F) << 4) | Int(cur >> 4)] &+= 1

                    let x = Double(prev)
                    let y = Double(cur)
                    sumX += x
                    sumY += y
                    sumXY += x * y
                    sumX2 += x * x
                    sumY2 += y * y

                    prev = cur
                    idx = bytes.index(after: idx)
                }

                let invPairs = 1.0 / Double(pairCount)
                var jointEntropy = 0.0
                for c in pairMap.values {
                    let p = Double(c) * invPairs
                    jointEntropy -= p * Foundation.log2(p)
                }
                condEntropy = max(0.0, min(8.0, jointEntropy - shannon))

                let pd = Double(pairCount)
                let num = pd * sumXY - sumX * sumY
                let denX = pd * sumX2 - sumX * sumX
                let denY = pd * sumY2 - sumY * sumY
                let denom = (denX * denY).squareRoot()
                if denom > 1e-9 {
                    serialCorr = max(-1.0, min(1.0, num / denom))
                }
            }

            let expectedNibblePair = Double(pairCount) / 256.0
            for np in nibblePairs {
                let d = Double(np) - expectedNibblePair
                nibbleBigramChiSq += (d * d) / expectedNibblePair
            }
        }

        // Monte Carlo Pi estimation using 16-bit (x, y) coordinate pairs (4 bytes per dart) inside unit quadrant.
        var mcPi = Double.pi
        var mcRelErr = 0.0
        let quadCount = n / 4
        if quadCount >= 8 {
            var insideCircle = 0
            let radiusSq = 65_535.0 * 65_535.0
            var cursor = bytes.startIndex
            for _ in 0..<quadCount {
                let x0 = UInt16(bytes[cursor])
                let x1 = UInt16(bytes[cursor + 1])
                let y0 = UInt16(bytes[cursor + 2])
                let y1 = UInt16(bytes[cursor + 3])
                cursor += 4
                let x = Double((x0 << 8) | x1)
                let y = Double((y0 << 8) | y1)
                if (x * x + y * y) <= radiusSq {
                    insideCircle &+= 1
                }
            }
            mcPi = 4.0 * Double(insideCircle) / Double(quadCount)
            mcRelErr = abs(mcPi - Double.pi) / Double.pi
        }

        // Discriminate true uniform cryptographic/PRNG ciphertext vs compressed streams vs native code.
        let nature: HighEntropyPayloadNature
        if zeroRatio > 0.85 || shannon < 0.40 {
            nature = .sparseZeroPadding
        } else if shannon >= 7.85 && pVal >= 0.005 && pVal <= 0.995 && abs(serialCorr) < 0.05 {
            nature = .uniformCryptographicOrPRNG
        } else if shannon >= 7.25 {
            nature = .compressedArchiveStream
        } else if shannon >= 5.15 && printableRatio < 0.68 {
            nature = .nativeInstructionStream
        } else {
            nature = .lowEntropyStructured
        }

        return ChiSquareRandomnessMetrics(
            sampleByteCount: n,
            shannonEntropyBits: shannon,
            minEntropyBits: minEnt,
            zeroByteRatio: zeroRatio,
            printableByteRatio: printableRatio,
            byteChiSquare: chiSq,
            byteChiSquarePValue: pVal,
            nibbleBigramChiSquare: nibbleBigramChiSq,
            bigramConditionalEntropyBits: condEntropy,
            serialCorrelationCoefficient: serialCorr,
            monteCarloPiEstimate: mcPi,
            monteCarloPiRelativeError: mcRelErr,
            inferredNature: nature
        )
    }

    /// Converts detected `EntropySectionAnomaly` items into `SecurityAuditFinding` records for the Workbench Audit pane.
    public func toSecurityAuditFindings(
        anomalies: [EntropySectionAnomaly],
        pluginID: String = "com.machgraph.entropy-profiler",
        pluginName: String = "Entropy & Packing Anomaly Profiler"
    ) -> [SecurityAuditFinding] {
        anomalies.map { item in
            SecurityAuditFinding(
                pluginID: pluginID,
                pluginName: pluginName,
                severity: item.severity,
                category: item.kind.rawValue,
                title: item.title,
                detail: item.detail,
                address: item.virtualAddress,
                evidencePreview: String(
                    format: "H=%.3f bits/B, chi2=%.1f (p=%.4f), corr=%.4f [%@]",
                    item.randomnessMetrics.shannonEntropyBits,
                    item.randomnessMetrics.byteChiSquare,
                    item.randomnessMetrics.byteChiSquarePValue,
                    item.randomnessMetrics.serialCorrelationCoefficient,
                    item.randomnessMetrics.inferredNature.rawValue
                )
            )
        }
    }

    // MARK: - Internal Anomaly Detection & Numerical Helpers

    private func detectAnomalies(
        in rawBytes: [UInt8],
        image: LoadedBinaryImage?,
        samples: [EntropyRegionSample],
        precomputedSectionMetrics: [String: ChiSquareRandomnessMetrics]
    ) -> [EntropySectionAnomaly] {
        var anomalies: [EntropySectionAnomaly] = []

        if let image {
            let sliceBase = Int(image.sliceFileOffset.rawValue)

            // 1. RWX segment permissions check
            for seg in image.segments {
                let hasRWX = seg.initialProtection.contains([.read, .write, .execute])
                if hasRWX && seg.fileSize > 0 {
                    let sStart = max(0, min(rawBytes.count, sliceBase + Int(seg.fileOffset.rawValue)))
                    let sEnd = max(sStart, min(rawBytes.count, sStart + Int(seg.fileSize)))
                    let metrics = computeRandomnessMetrics(bytes: rawBytes[sStart..<sEnd])
                    anomalies.append(
                        EntropySectionAnomaly(
                            kind: .writableExecutableSegment,
                            severity: .high,
                            sectionName: seg.name,
                            fileOffset: FileOffset(UInt64(sStart)),
                            virtualAddress: seg.vmAddress,
                            byteLength: sEnd - sStart,
                            title: "Writable + Executable (RWX) segment \(seg.name)",
                            detail: "Segment \(seg.name) carries initial rwx protection (\(String(format: "%.2f", metrics.shannonEntropyBits)) bits/byte), characteristic of self-modifying or runtime-unpacked code.",
                            randomnessMetrics: metrics
                        )
                    )
                }
            }

            // 2. Per-section high-entropy code / encrypted / compressed payload checks
            for sec in image.sections where sec.kind != .bss && sec.size >= 64 {
                guard let metrics = precomputedSectionMetrics[sec.fullName] else { continue }
                let absOff = FileOffset(image.sliceFileOffset.rawValue &+ sec.fileOffset.rawValue)
                let isExec = sec.kind == .code || sec.permissions.contains(.execute)

                if isExec && metrics.shannonEntropyBits >= 7.25 {
                    anomalies.append(
                        EntropySectionAnomaly(
                            kind: .packedOrEncryptedCodeSection,
                            severity: .high,
                            sectionName: sec.fullName,
                            fileOffset: absOff,
                            virtualAddress: sec.vmAddress,
                            byteLength: Int(sec.size),
                            title: "High-entropy executable section \(sec.fullName) (\(String(format: "%.2f", metrics.shannonEntropyBits)) bits/B)",
                            detail: "Executable code section \(sec.fullName) exceeds native ARM64/x86_64 instruction entropy bounds (<= 6.9 bits/B), indicating packed or encrypted instructions.",
                            randomnessMetrics: metrics
                        )
                    )
                } else if metrics.inferredNature == .uniformCryptographicOrPRNG && sec.size >= 256 {
                    anomalies.append(
                        EntropySectionAnomaly(
                            kind: .cryptographicPayloadBlob,
                            severity: .medium,
                            sectionName: sec.fullName,
                            fileOffset: absOff,
                            virtualAddress: sec.vmAddress,
                            byteLength: Int(sec.size),
                            title: "Uniform cryptographic/PRNG blob in \(sec.fullName)",
                            detail: String(
                                format: "Section %@ exhibits near-ideal uniform byte randomness (H=%.3f, chi2=%.1f, p=%.3f).",
                                sec.fullName,
                                metrics.shannonEntropyBits,
                                metrics.byteChiSquare,
                                metrics.byteChiSquarePValue
                            ),
                            randomnessMetrics: metrics
                        )
                    )
                } else if metrics.inferredNature == .compressedArchiveStream && sec.size >= 256 {
                    anomalies.append(
                        EntropySectionAnomaly(
                            kind: .compressedEmbeddedStream,
                            severity: .low,
                            sectionName: sec.fullName,
                            fileOffset: absOff,
                            virtualAddress: sec.vmAddress,
                            byteLength: Int(sec.size),
                            title: "Embedded compressed data stream in \(sec.fullName)",
                            detail: String(
                                format: "Section %@ contains high-entropy non-uniform compressed payload bytes (H=%.3f, chi2=%.1f).",
                                sec.fullName,
                                metrics.shannonEntropyBits,
                                metrics.byteChiSquare
                            ),
                            randomnessMetrics: metrics
                        )
                    )
                }
            }
        }

        // 3. Sliding-window intra-section sharp entropy cliff detector (delta >= 2.2 bits/byte into >= 7.35 high-entropy region)
        if samples.count >= 2 {
            for idx in 1..<samples.count {
                let prev = samples[idx - 1]
                let curr = samples[idx]
                guard prev.sectionName == curr.sectionName,
                      prev.classification != .nullPadding,
                      curr.entropyBitsPerByte >= 7.35,
                      (curr.entropyBitsPerByte - prev.entropyBitsPerByte) >= 2.15 else {
                    continue
                }
                let sStart = Int(curr.fileOffset.rawValue)
                let sEnd = min(rawBytes.count, sStart + curr.length)
                guard sEnd > sStart else { continue }
                let winMetrics = computeRandomnessMetrics(bytes: rawBytes[sStart..<sEnd])

                anomalies.append(
                    EntropySectionAnomaly(
                        kind: .sharpIntraSectionEntropyCliff,
                        severity: .medium,
                        sectionName: curr.sectionName,
                        fileOffset: curr.fileOffset,
                        virtualAddress: curr.virtualAddress,
                        byteLength: curr.length,
                        title: "Sharp entropy jump in \(curr.sectionName) at \(curr.virtualAddress?.compactHexString ?? curr.fileOffset.hexString)",
                        detail: String(
                            format: "Entropy jumps from %.2f to %.2f bits/byte within %@, suggesting an inline stub transitioning into packed/encrypted data.",
                            prev.entropyBitsPerByte,
                            curr.entropyBitsPerByte,
                            curr.sectionName
                        ),
                        randomnessMetrics: winMetrics
                    )
                )
            }
        }

        return anomalies
    }

    private func resolveSectionLabel(offset: FileOffset, va: VirtualAddress?, image: LoadedBinaryImage?) -> String {
        guard let image else { return "__RAW" }
        if let va, let sec = image.section(containing: va) {
            return sec.fullName
        }
        if offset.rawValue >= image.sliceFileOffset.rawValue {
            let local = offset.rawValue - image.sliceFileOffset.rawValue
            for seg in image.segments where seg.fileSize > 0 {
                if local >= seg.fileOffset.rawValue && local < (seg.fileOffset.rawValue + seg.fileSize) {
                    return seg.name
                }
            }
        }
        return "__CONTAINER"
    }

    private static func fastWindowStats(_ bytes: ArraySlice<UInt8>) -> (entropy: Double, zeroRatio: Double, printableRatio: Double) {
        let n = bytes.count
        guard n > 0 else { return (0, 1, 0) }
        var hist = [Int](repeating: 0, count: 256)
        var printable = 0
        for b in bytes {
            hist[Int(b)] &+= 1
            if b >= 0x20 && b <= 0x7E { printable &+= 1 }
        }
        let invN = 1.0 / Double(n)
        var ent = 0.0
        for c in hist where c > 0 {
            let p = Double(c) * invN
            ent -= p * Foundation.log2(p)
        }
        return (max(0.0, min(8.0, ent)), Double(hist[0]) * invN, Double(printable) * invN)
    }

    /// Computes $P(X \ge \chi^2)$ for large degrees of freedom ($k = 255$) via the Wilson-Hilferty cube-root normal transformation
    /// plus Abramowitz-Stegun complementary error function `erfc`.
    internal static func chiSquareUpperTailPValue(chiSq: Double, degreesOfFreedom k: Double) -> Double {
        guard chiSq > 0, k > 0 else { return 1.0 }
        let term = 2.0 / (9.0 * k)
        let ratio = Foundation.pow(chiSq / k, 1.0 / 3.0)
        let z = (ratio - (1.0 - term)) / term.squareRoot()
        // Upper tail 1 - Phi(z) = 0.5 * erfc(z / sqrt(2))
        let p = 0.5 * Foundation.erfc(z / 2.0.squareRoot())
        return max(0.0, min(1.0, p))
    }
}
