import Foundation
import MachGraphModels
import MachA64Decoder

// MARK: - Inline Patch Safety & Preview Models

public enum PatchSafetyHazardKind: String, Sendable, Codable, Hashable, CaseIterable {
    case unalignedVirtualAddress = "Unaligned ARM64 Address"
    case unalignedByteLength = "Non-Multiple-of-4 Patch Size"
    case interiorBranchTarget = "Clobbers Interior Branch Target"
    case interiorFunctionStart = "Clobbers Interior Function Entry"
    case interiorSymbolLabel = "Clobbers Interior Symbol Label"
    case interiorPACOrBTILandingPad = "Clobbers PAC/BTI Landing Pad"
    case crossesSectionBoundary = "Crosses Executable Section Boundary"

    public var blocksWithoutConfirmation: Bool {
        switch self {
        case .unalignedVirtualAddress, .unalignedByteLength:
            return true
        case .interiorBranchTarget, .interiorFunctionStart, .interiorSymbolLabel, .interiorPACOrBTILandingPad, .crossesSectionBoundary:
            return true
        }
    }
}

public struct InteriorBranchHazard: Sendable, Codable, Hashable, Identifiable {
    public var id: String { "\(kind.rawValue)@\(clobberedAddress.hexString):\(sourceAddress?.hexString ?? "sym")" }
    public let kind: PatchSafetyHazardKind
    public let clobberedAddress: VirtualAddress
    public let sourceAddress: VirtualAddress?
    public let sourceDisassembly: String?
    public let detail: String

    public init(
        kind: PatchSafetyHazardKind,
        clobberedAddress: VirtualAddress,
        sourceAddress: VirtualAddress? = nil,
        sourceDisassembly: String? = nil,
        detail: String
    ) {
        self.kind = kind
        self.clobberedAddress = clobberedAddress
        self.sourceAddress = sourceAddress
        self.sourceDisassembly = sourceDisassembly
        self.detail = detail
    }
}

public struct PatchSafetyContext: Sendable {
    public let recoveredFunctions: [RecoveredFunction]
    public let xrefs: [XrefRecord]
    public let scanRadiusInstructions: Int

    public init(
        recoveredFunctions: [RecoveredFunction] = [],
        xrefs: [XrefRecord] = [],
        scanRadiusInstructions: Int = 2_048
    ) {
        self.recoveredFunctions = recoveredFunctions
        self.xrefs = xrefs
        self.scanRadiusInstructions = max(32, scanRadiusInstructions)
    }
}

public struct InstructionPatchSafetyReport: Sendable, Codable, Hashable {
    public let patchStartAddress: VirtualAddress
    public let patchEndAddress: VirtualAddress
    public let patchByteLength: Int
    public let instructionCount: Int
    public let originalInstructions: [A64DecodedInstruction]
    public let hazards: [InteriorBranchHazard]
    public let requiresExplicitConfirmation: Bool
    public let summaryMessage: String

    public init(
        patchStartAddress: VirtualAddress,
        patchByteLength: Int,
        originalInstructions: [A64DecodedInstruction],
        hazards: [InteriorBranchHazard]
    ) {
        self.patchStartAddress = patchStartAddress
        self.patchEndAddress = patchStartAddress.adding(UInt64(max(0, patchByteLength)))
        self.patchByteLength = patchByteLength
        self.instructionCount = max(0, patchByteLength / 4)
        self.originalInstructions = originalInstructions
        self.hazards = hazards
        self.requiresExplicitConfirmation = hazards.contains(where: \.kind.blocksWithoutConfirmation)

        if hazards.isEmpty {
            self.summaryMessage = "Safe \(patchByteLength)-byte (\(patchByteLength / 4)-instruction) ARM64 patch at \(patchStartAddress.compactHexString)"
        } else {
            let titles = hazards.prefix(3).map(\.detail).joined(separator: "; ")
            self.summaryMessage = "\(hazards.count) control-flow safety hazard(s) at \(patchStartAddress.compactHexString): \(titles)"
        }
    }

    public var isClean: Bool { hazards.isEmpty }
}

public struct InlineARM64PatchPreview: Sendable, Codable, Hashable {
    public let fileOffset: FileOffset
    public let virtualAddress: VirtualAddress
    public let originalBytes: [UInt8]
    public let patchedBytes: [UInt8]
    public let originalInstructions: [A64DecodedInstruction]
    public let patchedInstructions: [A64DecodedInstruction]
    public let safetyReport: InstructionPatchSafetyReport

    public init(
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress,
        originalBytes: [UInt8],
        patchedBytes: [UInt8],
        originalInstructions: [A64DecodedInstruction],
        patchedInstructions: [A64DecodedInstruction],
        safetyReport: InstructionPatchSafetyReport
    ) {
        self.fileOffset = fileOffset
        self.virtualAddress = virtualAddress
        self.originalBytes = originalBytes
        self.patchedBytes = patchedBytes
        self.originalInstructions = originalInstructions
        self.patchedInstructions = patchedInstructions
        self.safetyReport = safetyReport
    }

    public var originalDisassemblyText: String {
        originalInstructions.map(\.formattedDisassembly).joined(separator: "; ")
    }

    public var patchedDisassemblyText: String {
        patchedInstructions.map(\.formattedDisassembly).joined(separator: "; ")
    }
}

public enum ConditionalBranchDisposition: String, Sendable, Codable, Hashable, CaseIterable {
    case alwaysTakeBranch = "Always Branch (Unconditional B)"
    case neverTakeBranch = "Never Branch (NOP Fallthrough)"
}

// MARK: - Inline ARM64 Instruction Patcher Engine

/// Pure-Swift ARM64 inline instruction patcher combining `A64MiniAssembler` + `A64InstructionDecoder`
/// with exact `VirtualAddress` PC-relative displacement encoding (`B`, `BL`, `B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`, `ADR`/`ADRP`),
/// 1-click NOP-sled / return-stub / branch-inversion helpers, and interior branch-target clobber verification.
public struct InlineARM64InstructionPatcher: Sendable {
    public static let arm64NOPWord: UInt32 = 0xD503_201F
    public static let arm64NOPBytesLE: [UInt8] = [0x1F, 0x20, 0x03, 0xD5]
    public static let arm64RETWord: UInt32 = 0xD65F_03C0
    public static let arm64RETAAWord: UInt32 = 0xD65F_0BFF

    public let assembler: A64MiniAssembler
    public let decoder: A64InstructionDecoder

    public init(
        assembler: A64MiniAssembler = A64MiniAssembler(),
        decoder: A64InstructionDecoder = A64InstructionDecoder()
    ) {
        self.assembler = assembler
        self.decoder = decoder
    }

    // MARK: - Core Inline Assembly Patching

    /// Assembles one or more ARM64 instructions at `virtualAddress` (encoding exact PC-relative displacements)
    /// and constructs a validated `BytePatchRecord` against `overlay` at `fileOffset`.
    public func patchInstruction(
        at fileOffset: FileOffset,
        virtualAddress: VirtualAddress,
        withAssembly assembly: String,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        padToByteLength: Int? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        let preview = try previewPatch(
            at: fileOffset,
            virtualAddress: virtualAddress,
            withAssembly: assembly,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            padToByteLength: padToByteLength
        )

        try enforceSafety(report: preview.safetyReport, allowClobberingBranchTargets: allowClobberingBranchTargets)

        let resolvedNote = note.isEmpty
            ? "Inline ARM64 patch @ \(virtualAddress.compactHexString): \(preview.patchedDisassemblyText)"
            : note

        return BytePatchRecord(
            fileOffset: fileOffset,
            virtualAddress: virtualAddress,
            originalBytes: preview.originalBytes,
            patchedBytes: preview.patchedBytes,
            originalAssembly: preview.originalDisassemblyText,
            patchedAssembly: preview.patchedDisassemblyText,
            note: resolvedNote,
            isEnabled: true
        )
    }

    /// Convenience overload resolving `fileOffset` automatically from `virtualAddress` via `LoadedBinaryImage`.
    public func patchInstruction(
        at virtualAddress: VirtualAddress,
        withAssembly assembly: String,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        padToByteLength: Int? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        let fileOff = try requireFileOffset(for: virtualAddress, in: image, overlaySize: overlay.count)
        return try patchInstruction(
            at: fileOff,
            virtualAddress: virtualAddress,
            withAssembly: assembly,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            padToByteLength: padToByteLength,
            note: note
        )
    }

    /// Assembles and immediately applies the `BytePatchRecord` into `overlay` (`inout`).
    @discardableResult
    public func applyInstructionPatch(
        at fileOffset: FileOffset? = nil,
        virtualAddress: VirtualAddress,
        withAssembly assembly: String,
        in overlay: inout SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        padToByteLength: Int? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let record = try patchInstruction(
            at: resolvedOffset,
            virtualAddress: virtualAddress,
            withAssembly: assembly,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            padToByteLength: padToByteLength,
            note: note
        )
        try overlay.applyPatch(record)
        return record
    }

    /// Produces a non-destructive `InlineARM64PatchPreview` with full disassembly and safety hazard analysis.
    public func previewPatch(
        at fileOffset: FileOffset,
        virtualAddress: VirtualAddress,
        withAssembly assembly: String,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        padToByteLength: Int? = nil
    ) throws -> InlineARM64PatchPreview {
        guard (virtualAddress.rawValue & 0x3) == 0 else {
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: assembly,
                reason: "ARM64 instruction virtual address \(virtualAddress.compactHexString) must be 4-byte aligned"
            )
        }

        let normalizedSource = Self.normalizeInlineAssembly(assembly, image: image)
        guard !normalizedSource.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MachGraphError.assemblerError(line: 1, instruction: assembly, reason: "Inline assembly input is empty")
        }

        let program = try assembler.assembleProgram(normalizedSource, baseAddress: virtualAddress)
        var patchedBytes = Array(program.bytes)
        guard !patchedBytes.isEmpty, patchedBytes.count % 4 == 0 else {
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: assembly,
                reason: "Assembled output produced zero instructions"
            )
        }

        if let targetLen = padToByteLength {
            guard targetLen >= patchedBytes.count, targetLen % 4 == 0 else {
                throw MachGraphError.patchFormatError(
                    "Assembled sequence requires \(patchedBytes.count) bytes, exceeding fixed slot size of \(targetLen) bytes"
                )
            }
            let extraNOPs = (targetLen - patchedBytes.count) / 4
            for _ in 0..<extraNOPs {
                patchedBytes.append(contentsOf: Self.arm64NOPBytesLE)
            }
        }

        let byteLen = patchedBytes.count
        let originalBytes = try overlay.readBytes(offset: fileOffset, count: byteLen)

        let symbolLookup = Self.makeSymbolLookup(for: image)
        let originalDecoded = decoder.decodeBuffer(Data(originalBytes), baseAddress: virtualAddress, symbolLookup: symbolLookup)
        let patchedDecoded = decoder.decodeBuffer(Data(patchedBytes), baseAddress: virtualAddress, symbolLookup: symbolLookup)

        let safetyReport = verifyPatchSafety(
            at: fileOffset,
            virtualAddress: virtualAddress,
            patchByteLength: byteLen,
            in: overlay,
            image: image,
            safetyContext: safetyContext
        )

        return InlineARM64PatchPreview(
            fileOffset: fileOffset,
            virtualAddress: virtualAddress,
            originalBytes: originalBytes,
            patchedBytes: patchedBytes,
            originalInstructions: originalDecoded,
            patchedInstructions: patchedDecoded,
            safetyReport: safetyReport
        )
    }

    // MARK: - 1-Click NOP-Sled Helpers

    /// Replaces a 4-byte-aligned byte range with ARM64 `NOP` (`0xD503201F`) instructions after verifying interior branch safety.
    public func nopOutRange(
        at fileOffset: FileOffset,
        virtualAddress: VirtualAddress? = nil,
        byteLength: Int,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard byteLength > 0, byteLength % 4 == 0 else {
            throw MachGraphError.patchFormatError("ARM64 NOP range byteLength (\(byteLength)) must be a positive multiple of 4")
        }

        let resolvedVA = virtualAddress ?? image?.virtualAddress(for: fileOffset)
        if let va = resolvedVA {
            guard (va.rawValue & 0x3) == 0 else {
                throw MachGraphError.patchFormatError("ARM64 NOP target \(va.compactHexString) must be 4-byte aligned")
            }
            let report = verifyPatchSafety(
                at: fileOffset,
                virtualAddress: va,
                patchByteLength: byteLength,
                in: overlay,
                image: image,
                safetyContext: safetyContext
            )
            try enforceSafety(report: report, allowClobberingBranchTargets: allowClobberingBranchTargets)
        }

        let origBytes = try overlay.readBytes(offset: fileOffset, count: byteLength)
        let nopCount = byteLength / 4
        var patchedBytes: [UInt8] = []
        patchedBytes.reserveCapacity(byteLength)
        for _ in 0..<nopCount {
            patchedBytes.append(contentsOf: Self.arm64NOPBytesLE)
        }

        let baseAddrForDecode = resolvedVA ?? VirtualAddress(fileOffset.rawValue)
        let symLookup = Self.makeSymbolLookup(for: image)
        let origAsm = decoder.decodeBuffer(Data(origBytes), baseAddress: baseAddrForDecode, symbolLookup: symLookup)
            .map(\.formattedDisassembly)
            .joined(separator: "; ")
        let patchedAsm = Array(repeating: "nop", count: nopCount).joined(separator: "; ")
        let label = note.isEmpty
            ? "NOP-out \(nopCount) instruction(s) (\(byteLength) bytes) @ \((resolvedVA?.compactHexString ?? fileOffset.hexString))"
            : note

        return BytePatchRecord(
            fileOffset: fileOffset,
            virtualAddress: resolvedVA,
            originalBytes: origBytes,
            patchedBytes: patchedBytes,
            originalAssembly: origAsm,
            patchedAssembly: patchedAsm,
            note: label,
            isEnabled: true
        )
    }

    /// Replaces `[startAddress ..< endAddress)` with ARM64 `NOP` (`0xD503201F`) instructions.
    public func nopOutRange(
        startAddress: VirtualAddress,
        endAddress: VirtualAddress,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard endAddress.rawValue > startAddress.rawValue else {
            throw MachGraphError.patchFormatError("NOP range endAddress (\(endAddress.compactHexString)) must exceed startAddress (\(startAddress.compactHexString))")
        }
        let byteLen = Int(endAddress.rawValue - startAddress.rawValue)
        let fileOff = try requireFileOffset(for: startAddress, in: image, overlaySize: overlay.count)
        return try nopOutRange(
            at: fileOff,
            virtualAddress: startAddress,
            byteLength: byteLen,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            note: note
        )
    }

    /// 1-click single-instruction `NOP` (`0xD503201F`) helper at `virtualAddress`.
    public func nopInstruction(
        at virtualAddress: VirtualAddress,
        fileOffset: FileOffset? = nil,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        return try nopOutRange(
            at: resolvedOffset,
            virtualAddress: virtualAddress,
            byteLength: 4,
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true,
            note: note
        )
    }

    // MARK: - 1-Click Return Stub & Immediate Return Helpers

    /// Replaces a function entry or basic block at `virtualAddress` with `MOV w0, #1; RET` (`true`) or `MOV w0, #0; RET` (`false`).
    /// Automatically checks whether `virtualAddress + 4` is an interior branch target unless `allowClobberingBranchTargets` is set.
    public func forceReturnBool(
        at virtualAddress: VirtualAddress,
        value: Bool,
        fileOffset: FileOffset? = nil,
        is64BitRegister: Bool = false,
        usePointerAuthReturn: Bool = false,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        note: String = ""
    ) throws -> BytePatchRecord {
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let destReg = is64BitRegister ? "x0" : "w0"
        let immVal = value ? "#1" : "#0"
        let retMnemonic = usePointerAuthReturn ? "retaa" : "ret"
        let asm = "mov \(destReg), \(immVal)\n\(retMnemonic)"
        let resolvedNote = note.isEmpty
            ? "Force return \(value) (\(destReg) = \(value ? 1 : 0); \(retMnemonic)) @ \(virtualAddress.compactHexString)"
            : note

        return try patchInstruction(
            at: resolvedOffset,
            virtualAddress: virtualAddress,
            withAssembly: asm,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            note: resolvedNote
        )
    }

    /// Synthesizes a minimal multi-instruction integer return stub (`MOVZ`/`MOVN` + optional `MOVK` lanes + `RET`) for arbitrary 32/64-bit constants.
    public func forceReturnInteger(
        at virtualAddress: VirtualAddress,
        returnValue: Int64,
        is64Bit: Bool = true,
        fileOffset: FileOffset? = nil,
        usePointerAuthReturn: Bool = false,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        note: String = ""
    ) throws -> BytePatchRecord {
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let regName = is64Bit ? "x0" : "w0"
        let retInsn = usePointerAuthReturn ? "retaa" : "ret"
        let moveLines = Self.synthesizeConstantMaterialization(
            registerName: regName,
            rawBits: UInt64(bitPattern: returnValue),
            is64Bit: is64Bit
        )
        let fullAsm = (moveLines + [retInsn]).joined(separator: "\n")
        let resolvedNote = note.isEmpty
            ? "Force return \(returnValue) (\(regName)) @ \(virtualAddress.compactHexString)"
            : note

        return try patchInstruction(
            at: resolvedOffset,
            virtualAddress: virtualAddress,
            withAssembly: fullAsm,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            note: resolvedNote
        )
    }

    /// Emits a 1-instruction `RET` (or `RETAA`) early return at `virtualAddress`.
    public func forceReturnVoid(
        at virtualAddress: VirtualAddress,
        fileOffset: FileOffset? = nil,
        usePointerAuthReturn: Bool = false,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let mnem = usePointerAuthReturn ? "retaa" : "ret"
        return try patchInstruction(
            at: resolvedOffset,
            virtualAddress: virtualAddress,
            withAssembly: mnem,
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true,
            note: note.isEmpty ? "Early void return (\(mnem)) @ \(virtualAddress.compactHexString)" : note
        )
    }

    // MARK: - Conditional Branch Inversion & Unconditional Rewriting

    /// Inverts an ARM64 conditional branch in-place (`B.EQ` <-> `B.NE`, `B.GT` <-> `B.LE`, `CBZ` <-> `CBNZ`, `TBZ` <-> `TBNZ`),
    /// preserving exact PC-relative branch displacement and register operands.
    public func invertConditionalBranch(
        at virtualAddress: VirtualAddress,
        fileOffset: FileOffset? = nil,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard (virtualAddress.rawValue & 0x3) == 0 else {
            throw MachGraphError.decoderError(
                address: virtualAddress,
                detail: "Conditional branch address \(virtualAddress.compactHexString) is not 4-byte aligned"
            )
        }
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let origBytes = try overlay.readBytes(offset: resolvedOffset, count: 4)
        let origWord = Self.readUInt32LE(origBytes, at: 0)
        let symLookup = Self.makeSymbolLookup(for: image)
        let origDecoded = decoder.decode(word: origWord, at: virtualAddress, symbolLookup: symLookup)

        let invertedWord: UInt32
        // 1. B.<cond> (01010100_imm19_0_cond): mask 0xFF000010 == 0x54000000
        if (origWord & 0xFF00_0010) == 0x5400_0000 {
            let condNibble = UInt8(origWord & 0xF)
            guard condNibble < 0xE else {
                throw MachGraphError.assemblerError(
                    line: 1,
                    instruction: origDecoded.formattedDisassembly,
                    reason: "B.AL / B.NV unconditional condition nibble cannot be logically inverted"
                )
            }
            invertedWord = origWord ^ 0x1
        }
        // 2. CBZ / CBNZ (sf_011010_op_imm19_Rt): mask 0x7E000000 == 0x34000000
        else if (origWord & 0x7E00_0000) == 0x3400_0000 {
            invertedWord = origWord ^ (1 << 24)
        }
        // 3. TBZ / TBNZ (b5_011011_op_b40_imm14_Rt): mask 0x7E000000 == 0x36000000
        else if (origWord & 0x7E00_0000) == 0x3600_0000 {
            invertedWord = origWord ^ (1 << 24)
        } else {
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: origDecoded.formattedDisassembly,
                reason: "Instruction '\(origDecoded.formattedDisassembly)' at \(virtualAddress.compactHexString) is not an invertible conditional branch (expected B.<cond>, CBZ/CBNZ, or TBZ/TBNZ)"
            )
        }

        let newDecoded = decoder.decode(word: invertedWord, at: virtualAddress, symbolLookup: symLookup)
        let newBytes = Self.writeUInt32LE(invertedWord)
        let resolvedNote = note.isEmpty
            ? "Invert branch \(origDecoded.mnemonicText) -> \(newDecoded.mnemonicText) @ \(virtualAddress.compactHexString)"
            : note

        return BytePatchRecord(
            fileOffset: resolvedOffset,
            virtualAddress: virtualAddress,
            originalBytes: origBytes,
            patchedBytes: newBytes,
            originalAssembly: origDecoded.formattedDisassembly,
            patchedAssembly: newDecoded.formattedDisassembly,
            note: resolvedNote,
            isEnabled: true
        )
    }

    /// Converts a conditional branch (`B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`) into either an unconditional `B target` or a fallthrough `NOP`.
    public func convertConditionalBranch(
        at virtualAddress: VirtualAddress,
        mode: ConditionalBranchDisposition,
        fileOffset: FileOffset? = nil,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard (virtualAddress.rawValue & 0x3) == 0 else {
            throw MachGraphError.decoderError(
                address: virtualAddress,
                detail: "Branch address \(virtualAddress.compactHexString) is not 4-byte aligned"
            )
        }
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: virtualAddress, image: image, overlaySize: overlay.count)
        let origBytes = try overlay.readBytes(offset: resolvedOffset, count: 4)
        let origWord = Self.readUInt32LE(origBytes, at: 0)
        let symLookup = Self.makeSymbolLookup(for: image)
        let origDecoded = decoder.decode(word: origWord, at: virtualAddress, symbolLookup: symLookup)

        let targetAddress: VirtualAddress
        switch origDecoded.flow {
        case .conditionalBranch(let dst, _):
            targetAddress = dst
        default:
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: origDecoded.formattedDisassembly,
                reason: "Instruction '\(origDecoded.formattedDisassembly)' at \(virtualAddress.compactHexString) is not a conditional branch"
            )
        }

        let newWord: UInt32
        switch mode {
        case .neverTakeBranch:
            newWord = Self.arm64NOPWord
        case .alwaysTakeBranch:
            let byteDelta = targetAddress - virtualAddress
            let imm26 = UInt32(bitPattern: Int32(byteDelta >> 2)) & 0x03FF_FFFF
            newWord = 0x1400_0000 | imm26
        }

        let newDecoded = decoder.decode(word: newWord, at: virtualAddress, symbolLookup: symLookup)
        let resolvedNote = note.isEmpty
            ? "\(mode.rawValue): \(origDecoded.formattedDisassembly) -> \(newDecoded.formattedDisassembly)"
            : note

        return BytePatchRecord(
            fileOffset: resolvedOffset,
            virtualAddress: virtualAddress,
            originalBytes: origBytes,
            patchedBytes: Self.writeUInt32LE(newWord),
            originalAssembly: origDecoded.formattedDisassembly,
            patchedAssembly: newDecoded.formattedDisassembly,
            note: resolvedNote,
            isEnabled: true
        )
    }

    /// Emits a 4-byte direct `B`/`BL` if `targetAddress` is within ±128 MiB of `sourceAddress`,
    /// or automatically synthesizes an `ADRP + ADD + BR/BLR` (12-byte) or `MOVZ/MOVK + BR/BLR` veneer when out of direct branch range.
    public func buildBranchOrVeneerStub(
        from sourceAddress: VirtualAddress,
        to targetAddress: VirtualAddress,
        isCall: Bool = false,
        scratchRegister: A64Register = .x(16),
        fileOffset: FileOffset? = nil,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil,
        allowClobberingBranchTargets: Bool = false,
        note: String = ""
    ) throws -> BytePatchRecord {
        guard (targetAddress.rawValue & 0x3) == 0 else {
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: isCall ? "bl" : "b",
                reason: "Branch target \(targetAddress.compactHexString) is not 4-byte aligned"
            )
        }
        let resolvedOffset = try resolveOffset(explicit: fileOffset, virtualAddress: sourceAddress, image: image, overlaySize: overlay.count)
        let delta = targetAddress - sourceAddress
        let maxDirectRange: Int64 = 128 * 1024 * 1024

        let asm: String
        if abs(delta) < maxDirectRange {
            let mnem = isCall ? "bl" : "b"
            asm = "\(mnem) \(targetAddress.hexString)"
        } else {
            let reg = scratchRegister.bitWidth == 64 && !scratchRegister.isStackPointer ? scratchRegister.canonicalName : "x16"
            let pageDelta = (targetAddress.page4KBase() - sourceAddress.page4KBase()) >> 12
            let brMnem = isCall ? "blr" : "br"
            if pageDelta >= -(1 << 20) && pageDelta < (1 << 20) {
                let pageOff = targetAddress.rawValue & 0xFFF
                asm = """
                adrp \(reg), \(targetAddress.page4KBase().hexString)
                add \(reg), \(reg), #0x\(String(pageOff, radix: 16))
                \(brMnem) \(reg)
                """
            } else {
                let movSeq = Self.synthesizeConstantMaterialization(
                    registerName: reg,
                    rawBits: targetAddress.rawValue,
                    is64Bit: true
                )
                asm = (movSeq + ["\(brMnem) \(reg)"]).joined(separator: "\n")
            }
        }

        return try patchInstruction(
            at: resolvedOffset,
            virtualAddress: sourceAddress,
            withAssembly: asm,
            in: overlay,
            image: image,
            safetyContext: safetyContext,
            allowClobberingBranchTargets: allowClobberingBranchTargets,
            note: note.isEmpty ? "Branch stub \(sourceAddress.compactHexString) -> \(targetAddress.compactHexString)" : note
        )
    }

    // MARK: - Multi-Instruction Control-Flow & Branch-Target Safety Verifier

    /// Verifies that overwriting `[virtualAddress ..< virtualAddress + patchByteLength)` does not violate ARM64 alignment,
    /// overflow an executable section, or silently clobber interior branch targets, function prologues, or symbol entry points.
    public func verifyPatchSafety(
        at fileOffset: FileOffset,
        virtualAddress: VirtualAddress,
        patchByteLength: Int,
        in overlay: SparseCoWByteOverlayBuffer,
        image: LoadedBinaryImage? = nil,
        safetyContext: PatchSafetyContext? = nil
    ) -> InstructionPatchSafetyReport {
        var hazards: [InteriorBranchHazard] = []

        if (virtualAddress.rawValue & 0x3) != 0 {
            hazards.append(
                InteriorBranchHazard(
                    kind: .unalignedVirtualAddress,
                    clobberedAddress: virtualAddress,
                    detail: "Address \(virtualAddress.compactHexString) is not 4-byte aligned"
                )
            )
        }
        if patchByteLength <= 0 || (patchByteLength % 4) != 0 {
            hazards.append(
                InteriorBranchHazard(
                    kind: .unalignedByteLength,
                    clobberedAddress: virtualAddress,
                    detail: "Patch byte length (\(patchByteLength)) is not a positive multiple of 4"
                )
            )
        }

        let safeReadableCount = max(0, min(patchByteLength, Int(UInt64(overlay.count) - min(UInt64(overlay.count), fileOffset.rawValue))))
        let origBytes = (try? overlay.readBytes(offset: fileOffset, count: safeReadableCount)) ?? []
        let symLookup = Self.makeSymbolLookup(for: image)
        let origInstructions = decoder.decodeBuffer(Data(origBytes), baseAddress: virtualAddress, symbolLookup: symLookup)

        let patchEndAddress = virtualAddress.adding(UInt64(max(0, patchByteLength)))

        // Check section boundary overflow if image metadata is provided.
        if let image, let containingSec = image.section(containing: virtualAddress) {
            let secEnd = containingSec.vmAddress.adding(containingSec.size)
            if patchEndAddress > secEnd {
                hazards.append(
                    InteriorBranchHazard(
                        kind: .crossesSectionBoundary,
                        clobberedAddress: secEnd,
                        detail: "Patch [\(virtualAddress.compactHexString)..\(patchEndAddress.compactHexString)) overflows section \(containingSec.fullName) end (\(secEnd.compactHexString))"
                    )
                )
            }
        }

        // Single-instruction (4-byte) aligned patches cannot have an interior mid-sequence branch target!
        guard patchByteLength > 4 else {
            return InstructionPatchSafetyReport(
                patchStartAddress: virtualAddress,
                patchByteLength: patchByteLength,
                originalInstructions: origInstructions,
                hazards: hazards
            )
        }

        let interiorRange = AddressRange(
            start: virtualAddress.adding(UInt64(4)),
            size: UInt64(patchByteLength - 4)
        )
        let fullPatchRange = AddressRange(
            start: virtualAddress,
            size: UInt64(patchByteLength)
        )

        var recordedPairs = Set<String>()
        func addHazard(_ hazard: InteriorBranchHazard) {
            if recordedPairs.insert(hazard.id).inserted {
                hazards.append(hazard)
            }
        }

        // 1. Check interior instructions themselves for PAC/BTI landing pads (strong indicator of an indirect jump/call target).
        for insn in origInstructions.dropFirst() {
            switch insn.mnemonic {
            case .bti, .paciasp, .pacibsp:
                addHazard(
                    InteriorBranchHazard(
                        kind: .interiorPACOrBTILandingPad,
                        clobberedAddress: insn.address,
                        sourceDisassembly: insn.formattedDisassembly,
                        detail: "Overwrites interior landing pad '\(insn.formattedDisassembly)' at \(insn.address.compactHexString)"
                    )
                )
            default:
                break
            }
        }

        // 2. Check LoadedBinaryImage functionStarts and symbols inside interiorRange.
        if let image {
            for fnStart in image.functionStarts where interiorRange.contains(fnStart) {
                addHazard(
                    InteriorBranchHazard(
                        kind: .interiorFunctionStart,
                        clobberedAddress: fnStart,
                        detail: "Overwrites interior LC_FUNCTION_STARTS entry at \(fnStart.compactHexString)"
                    )
                )
            }
            for sym in image.symbols where interiorRange.contains(sym.address) {
                addHazard(
                    InteriorBranchHazard(
                        kind: .interiorSymbolLabel,
                        clobberedAddress: sym.address,
                        detail: "Overwrites interior symbol '\(sym.demangledName)' at \(sym.address.compactHexString)"
                    )
                )
            }
        }

        // 3. Check caller-supplied CFG basic block headers and XrefRecords if available.
        if let ctx = safetyContext {
            for fn in ctx.recoveredFunctions {
                for block in fn.blocks where interiorRange.contains(block.startAddress) {
                    // Only flag if at least one predecessor lies outside the overwritten range (or if it's an entry block).
                    let hasExternalPredecessor = block.isEntry || fn.blocks.contains { predBlock in
                        block.predecessorIDs.contains(predBlock.id) && !fullPatchRange.contains(predBlock.startAddress)
                    }
                    if hasExternalPredecessor {
                        addHazard(
                            InteriorBranchHazard(
                                kind: .interiorBranchTarget,
                                clobberedAddress: block.startAddress,
                                detail: "Overwrites CFG basic block leader \(block.label) at \(block.startAddress.compactHexString)"
                            )
                        )
                    }
                }
            }

            for xref in ctx.xrefs where interiorRange.contains(xref.toAddress) && !fullPatchRange.contains(xref.fromAddress) {
                addHazard(
                    InteriorBranchHazard(
                        kind: .interiorBranchTarget,
                        clobberedAddress: xref.toAddress,
                        sourceAddress: xref.fromAddress,
                        sourceDisassembly: xref.instructionPreview,
                        detail: "External \(xref.kind.rawValue) from \(xref.fromAddress.compactHexString) targets interior instruction \(xref.toAddress.compactHexString)"
                    )
                )
            }
        }

        // 4. Direct binary neighborhood scan across the executable section (or ±scanRadiusInstructions around fileOffset)
        // so interior branch clobbers are caught even without pre-built CFG/Xref tables!
        let radiusBytes = UInt64((safetyContext?.scanRadiusInstructions ?? 2_048) * 4)
        let scanBounds: (fileStart: UInt64, vaStart: VirtualAddress, byteCount: Int) = {
            if let image,
               let sec = image.section(containing: virtualAddress),
               sec.kind != .bss,
               sec.size >= 4 {
                let secAbsFileStart = image.sliceFileOffset.rawValue &+ sec.fileOffset.rawValue
                let patchRelInSec = virtualAddress.rawValue >= sec.vmAddress.rawValue
                    ? (virtualAddress.rawValue - sec.vmAddress.rawValue)
                    : 0
                let relLow = patchRelInSec > radiusBytes ? ((patchRelInSec - radiusBytes) & ~3) : 0
                let relHigh = min(sec.size & ~3, ((patchRelInSec &+ UInt64(patchByteLength) &+ radiusBytes) & ~3))
                if relHigh > relLow {
                    let fStart = secAbsFileStart &+ relLow
                    let clampedCount = Int(min(relHigh - relLow, UInt64(overlay.count) - min(UInt64(overlay.count), fStart))) & ~3
                    return (fStart, sec.vmAddress.adding(relLow), clampedCount)
                }
            }

            let alignedOff = fileOffset.rawValue & ~3
            let back = min(alignedOff, min(virtualAddress.rawValue & ~3, radiusBytes))
            let fStart = alignedOff - back
            let vStart = virtualAddress - back
            let maxAvail = UInt64(overlay.count) > fStart ? (UInt64(overlay.count) - fStart) : 0
            let wanted = back &+ UInt64(patchByteLength) &+ radiusBytes
            let count = Int(min(maxAvail, wanted)) & ~3
            return (fStart, vStart, count)
        }()

        if scanBounds.byteCount >= 4,
           let windowBytes = try? overlay.readBytes(offset: scanBounds.fileStart, count: scanBounds.byteCount) {
            let wordCount = windowBytes.count / 4
            for i in 0..<wordCount {
                let insnVA = scanBounds.vaStart.adding(UInt64(i * 4))
                if fullPatchRange.contains(insnVA) {
                    continue
                }
                let word = Self.readUInt32LE(windowBytes, at: i * 4)
                if let targetVA = Self.fastExtractPCRelativeTarget(word: word, pc: insnVA),
                   interiorRange.contains(targetVA) {
                    let decodedBranch = decoder.decode(word: word, at: insnVA, symbolLookup: symLookup)
                    addHazard(
                        InteriorBranchHazard(
                            kind: .interiorBranchTarget,
                            clobberedAddress: targetVA,
                            sourceAddress: insnVA,
                            sourceDisassembly: decodedBranch.formattedDisassembly,
                            detail: "Branch '\(decodedBranch.formattedDisassembly)' at \(insnVA.compactHexString) jumps into patch interior at \(targetVA.compactHexString)"
                        )
                    )
                }
            }
        }

        return InstructionPatchSafetyReport(
            patchStartAddress: virtualAddress,
            patchByteLength: patchByteLength,
            originalInstructions: origInstructions,
            hazards: hazards
        )
    }

    // MARK: - Internal Assembly Normalization, Symbol Binding & Bit Helpers

    private func enforceSafety(
        report: InstructionPatchSafetyReport,
        allowClobberingBranchTargets: Bool
    ) throws {
        // Alignment errors are unconditional hardware invariants and can never be bypassed.
        if let hardError = report.hazards.first(where: { $0.kind == .unalignedVirtualAddress || $0.kind == .unalignedByteLength }) {
            throw MachGraphError.patchFormatError(hardError.detail)
        }
        if !allowClobberingBranchTargets && report.requiresExplicitConfirmation {
            throw MachGraphError.patchFormatError(
                "\(report.summaryMessage). Pass allowClobberingBranchTargets: true after explicit analyst confirmation."
            )
        }
    }

    private func requireFileOffset(
        for virtualAddress: VirtualAddress,
        in image: LoadedBinaryImage,
        overlaySize: Int
    ) throws -> FileOffset {
        guard let off = image.fileOffset(for: virtualAddress) else {
            throw MachGraphError.patchBoundsError(
                offset: virtualAddress.rawValue,
                length: 4,
                fileSize: overlaySize
            )
        }
        return off
    }

    private func resolveOffset(
        explicit: FileOffset?,
        virtualAddress: VirtualAddress,
        image: LoadedBinaryImage?,
        overlaySize: Int
    ) throws -> FileOffset {
        if let explicit {
            return explicit
        }
        if let image, let mapped = image.fileOffset(for: virtualAddress) {
            return mapped
        }
        if virtualAddress.rawValue + 4 <= UInt64(overlaySize) {
            return FileOffset(virtualAddress.rawValue)
        }
        throw MachGraphError.patchBoundsError(
            offset: virtualAddress.rawValue,
            length: 4,
            fileSize: overlaySize
        )
    }

    private static func makeSymbolLookup(for image: LoadedBinaryImage?) -> (@Sendable (VirtualAddress) -> String?)? {
        guard let image, !image.symbols.isEmpty else { return nil }
        var table: [VirtualAddress: String] = [:]
        table.reserveCapacity(image.symbols.count)
        for sym in image.symbols where table[sym.address] == nil {
            table[sym.address] = sym.demangledName
        }
        let frozenTable = table
        return { addr in frozenTable[addr] }
    }

    /// Normalizes semicolon-separated inline ARM64 assembly (e.g. `"MOV w0, #1; RET"`) into clean multi-line statements
    /// while preserving `; comment` annotations and resolving `LoadedBinaryImage` symbol references to hex addresses.
    internal static func normalizeInlineAssembly(_ rawSource: String, image: LoadedBinaryImage?) -> String {
        var rawStatements: [String] = []

        for rawLine in rawSource.components(separatedBy: .newlines) {
            // Strip `//` C-style line comments first.
            let withoutSlashComment: String = {
                let chars = Array(rawLine)
                var out = ""
                var i = 0
                while i < chars.count {
                    if chars[i] == "/" && i + 1 < chars.count && chars[i + 1] == "/" {
                        break
                    }
                    out.append(chars[i])
                    i += 1
                }
                return out
            }()

            let pieces = withoutSlashComment.split(separator: ";", omittingEmptySubsequences: false).map {
                String($0).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            for (pieceIdx, piece) in pieces.enumerated() {
                if piece.isEmpty { continue }
                if pieceIdx == 0 || looksLikeARM64Statement(piece) {
                    rawStatements.append(piece)
                } else {
                    // Remainder after `;` is a human comment rather than an instruction; stop parsing this line.
                    break
                }
            }
        }

        guard let image, !image.symbols.isEmpty else {
            return rawStatements.joined(separator: "\n")
        }

        // Collect local labels defined inside the user's snippet so local labels always shadow image symbols.
        var localLabels = Set<String>()
        for stmt in rawStatements {
            var rest = stmt
            while let colonIdx = rest.firstIndex(of: ":") {
                let prefix = String(rest[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                if prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "$" }) && !prefix.isEmpty {
                    localLabels.insert(prefix)
                    rest = String(rest[rest.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                } else {
                    break
                }
            }
        }

        var symbolMap: [String: VirtualAddress] = [:]
        symbolMap.reserveCapacity(image.symbols.count * 2)
        for sym in image.symbols where sym.address.rawValue != 0 {
            if symbolMap[sym.name] == nil {
                symbolMap[sym.name] = sym.address
            }
            if sym.name.hasPrefix("_") {
                let trimmed = String(sym.name.dropFirst())
                if !trimmed.isEmpty && symbolMap[trimmed] == nil {
                    symbolMap[trimmed] = sym.address
                }
            }
        }

        let resolvedLines = rawStatements.map { stmt -> String in
            substituteImageSymbols(in: stmt, symbolMap: symbolMap, localLabels: localLabels)
        }
        return resolvedLines.joined(separator: "\n")
    }

    private static func looksLikeARM64Statement(_ candidate: String) -> Bool {
        var text = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        while let colonIdx = text.firstIndex(of: ":") {
            let lbl = String(text[..<colonIdx]).trimmingCharacters(in: .whitespaces)
            guard !lbl.isEmpty, lbl.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "$" }) else {
                break
            }
            text = String(text[text.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            if text.isEmpty { return true }
        }

        guard let firstWord = text.split(whereSeparator: \.isWhitespace).first?.lowercased() else {
            return false
        }
        if firstWord.hasPrefix(".") {
            return [".word", ".inst", ".long", ".quad", ".8byte", ".p2align", ".align", ".global", ".globl", ".text"].contains(firstWord)
        }
        if firstWord.hasPrefix("b.") && firstWord.count == 4 {
            return A64ConditionCode.from(text: String(firstWord.dropFirst(2))) != nil
        }
        if firstWord.count == 3 && firstWord.hasPrefix("b") && A64ConditionCode.from(text: String(firstWord.dropFirst())) != nil {
            return true
        }
        return knownAssemblerMnemonics.contains(firstWord)
    }

    private static func substituteImageSymbols(
        in statement: String,
        symbolMap: [String: VirtualAddress],
        localLabels: Set<String>
    ) -> String {
        var prefixLabels = ""
        var body = statement
        while let colonIdx = body.firstIndex(of: ":") {
            let lbl = String(body[..<colonIdx]).trimmingCharacters(in: .whitespaces)
            guard !lbl.isEmpty, lbl.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "$" }) else {
                break
            }
            prefixLabels += "\(lbl): "
            body = String(body[body.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
        }
        guard !body.isEmpty,
              let splitIdx = body.firstIndex(where: \.isWhitespace) else {
            return prefixLabels + body
        }

        let mnemonic = String(body[..<splitIdx])
        let lowerMnem = mnemonic.lowercased()
        let isSymbolBearing = lowerMnem == "b" || lowerMnem == "bl"
            || lowerMnem.hasPrefix("b.")
            || (lowerMnem.count == 3 && lowerMnem.hasPrefix("b") && A64ConditionCode.from(text: String(lowerMnem.dropFirst())) != nil)
            || lowerMnem == "cbz" || lowerMnem == "cbnz"
            || lowerMnem == "tbz" || lowerMnem == "tbnz"
            || lowerMnem == "adr" || lowerMnem == "adrp"
            || lowerMnem == "ldr" || lowerMnem == "ldrsw"
            || lowerMnem == ".word" || lowerMnem == ".quad"

        guard isSymbolBearing else {
            return prefixLabels + body
        }

        let operandText = String(body[splitIdx...]).trimmingCharacters(in: .whitespaces)
        let operands = operandText.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
        guard let lastOp = operands.last, !localLabels.contains(lastOp) else {
            return prefixLabels + body
        }

        if let symAddr = symbolMap[lastOp] {
            var updated = operands
            updated[updated.count - 1] = symAddr.hexString
            return "\(prefixLabels)\(mnemonic) \(updated.joined(separator: ", "))"
        }
        return prefixLabels + body
    }

    private static func synthesizeConstantMaterialization(
        registerName: String,
        rawBits: UInt64,
        is64Bit: Bool
    ) -> [String] {
        let value = is64Bit ? rawBits : (rawBits & 0xFFFF_FFFF)
        let laneCount = is64Bit ? 4 : 2

        if value == 0 {
            return ["movz \(registerName), #0"]
        }

        var nonZeroLanes: [(lane: Int, imm16: UInt16)] = []
        var nonOnesLanes: [(lane: Int, inv16: UInt16)] = []

        for lane in 0..<laneCount {
            let chunk = UInt16(truncatingIfNeeded: value >> (lane * 16))
            if chunk != 0 {
                nonZeroLanes.append((lane, chunk))
            }
            if chunk != 0xFFFF {
                nonOnesLanes.append((lane, ~chunk))
            }
        }

        // Prefer MOVN + MOVK when high lanes are mostly 0xFFFF (e.g. small negative integers like -1).
        if nonOnesLanes.isEmpty {
            return ["movn \(registerName), #0"]
        }
        if nonOnesLanes.count < nonZeroLanes.count {
            var lines: [String] = []
            let first = nonOnesLanes[0]
            let shiftSuffix = first.lane > 0 ? ", lsl #\(first.lane * 16)" : ""
            lines.append("movn \(registerName), #0x\(String(first.inv16, radix: 16))\(shiftSuffix)")
            for extra in nonOnesLanes.dropFirst() {
                let actualChunk = UInt16(truncatingIfNeeded: value >> (extra.lane * 16))
                let extraShift = extra.lane > 0 ? ", lsl #\(extra.lane * 16)" : ""
                lines.append("movk \(registerName), #0x\(String(actualChunk, radix: 16))\(extraShift)")
            }
            return lines
        }

        var lines: [String] = []
        let first = nonZeroLanes[0]
        let firstShift = first.lane > 0 ? ", lsl #\(first.lane * 16)" : ""
        lines.append("movz \(registerName), #0x\(String(first.imm16, radix: 16))\(firstShift)")
        for extra in nonZeroLanes.dropFirst() {
            let extraShift = extra.lane > 0 ? ", lsl #\(extra.lane * 16)" : ""
            lines.append("movk \(registerName), #0x\(String(extra.imm16, radix: 16))\(extraShift)")
        }
        return lines
    }

    /// Fast O(1) bit-level extractor for PC-relative control-flow & `ADR` targets during neighborhood safety scanning.
    @inline(__always)
    private static func fastExtractPCRelativeTarget(word: UInt32, pc: VirtualAddress) -> VirtualAddress? {
        // B / BL: op[30:26] == 0b00101
        if (word & 0x7C00_0000) == 0x1400_0000 {
            let raw26 = UInt64(word & 0x03FF_FFFF)
            let signedWords = signExtend64(raw26, bits: 26)
            return pc.adding(signedWords << 2)
        }
        // B.<cond>: 01010100_imm19_0_cond
        if (word & 0xFF00_0010) == 0x5400_0000 {
            let raw19 = UInt64((word >> 5) & 0x7_FFFF)
            let signedWords = signExtend64(raw19, bits: 19)
            return pc.adding(signedWords << 2)
        }
        // CBZ / CBNZ: x011010x_imm19_Rt
        if (word & 0x7E00_0000) == 0x3400_0000 {
            let raw19 = UInt64((word >> 5) & 0x7_FFFF)
            let signedWords = signExtend64(raw19, bits: 19)
            return pc.adding(signedWords << 2)
        }
        // TBZ / TBNZ: x011011x_b40_imm14_Rt
        if (word & 0x7E00_0000) == 0x3600_0000 {
            let raw14 = UInt64((word >> 5) & 0x3FFF)
            let signedWords = signExtend64(raw14, bits: 14)
            return pc.adding(signedWords << 2)
        }
        // ADR (not ADRP): 0_immlo_10000_immhi_Rd
        if (word & 0x9F00_0000) == 0x1000_0000 {
            let immlo = UInt64((word >> 29) & 0x3)
            let immhi = UInt64((word >> 5) & 0x7_FFFF)
            let signedBytes = signExtend64((immhi << 2) | immlo, bits: 21)
            return pc.adding(signedBytes)
        }
        return nil
    }

    @inline(__always)
    private static func signExtend64(_ value: UInt64, bits: Int) -> Int64 {
        let shift = 64 - bits
        return Int64(bitPattern: value << shift) >> shift
    }

    @inline(__always)
    private static func readUInt32LE(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    @inline(__always)
    private static func writeUInt32LE(_ word: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: word),
            UInt8(truncatingIfNeeded: word >> 8),
            UInt8(truncatingIfNeeded: word >> 16),
            UInt8(truncatingIfNeeded: word >> 24)
        ]
    }

    private static let knownAssemblerMnemonics: Set<String> = [
        "nop", "yield", "wfe", "wfi", "sev", "sevl", "xpaclri",
        "paciasp", "pacibsp", "autiasp", "autibsp", "retaa", "retab",
        "bti", "clrex", "dmb", "dsb", "isb", "mrs", "msr",
        "ret", "br", "blr", "braaz", "brabz", "blraaz", "blrabz",
        "braa", "brab", "blraa", "blrab", "paciza", "pacizb", "autiza", "autizb", "xpaci", "xpacd",
        "svc", "hvc", "smc", "brk", "hlt",
        "b", "bl", "cbz", "cbnz", "tbz", "tbnz", "adr", "adrp",
        "mov", "movz", "movn", "movk",
        "add", "adds", "sub", "subs", "cmp", "cmn", "neg", "negs",
        "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs",
        "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "tst", "mvn",
        "lsl", "lsr", "asr", "ror",
        "ubfm", "sbfm", "bfm", "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "extr",
        "sxtb", "sxth", "sxtw", "uxtb", "uxth",
        "rbit", "rev16", "rev32", "rev", "clz", "cls",
        "mul", "mneg", "madd", "msub", "smull", "smaddl", "smsubl", "smulh",
        "umull", "umaddl", "umsubl", "umulh", "udiv", "sdiv",
        "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "ccmp", "ccmn",
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
        "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
        "str", "strb", "strh", "stur", "sturb", "sturh",
        "ldp", "ldpsw", "ldnp", "stp", "stnp",
        "ldxr", "ldaxr", "ldar", "ldarb", "ldarh", "stxr", "stlxr", "stlr", "stlrb", "stlrh",
        "cas", "casa", "casal", "casl", "swp", "swpa", "swpal", "swpl", "ldadd", "ldadda", "ldaddal", "ldaddl",
        "fmov", "fadd", "fsub", "fmul", "fdiv", "fnmul", "fmadd", "fmsub",
        "fabs", "fneg", "fsqrt", "fmin", "fmax", "fcmp", "fcmpe", "fccmp", "fcsel",
        "fcvt", "scvtf", "ucvtf", "fcvtzs", "fcvtzu", "movi", "dup", "addv", "cmeq"
    ]
}
