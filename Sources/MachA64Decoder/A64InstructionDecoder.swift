import Foundation
import MachGraphModels

// MARK: - Pure Handwritten ARMv8-A / ARMv8.3-A (Apple Silicon arm64 / arm64e) Decoder

public struct A64InstructionDecoder: Sendable {
    public init() {}

    /// Decodes a single 32-bit little-endian ARM64 instruction word at `address`.
    public func decode(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) -> A64DecodedInstruction {
        let op0 = A64BitUtils.extract(word, 28, 25)

        // Top-level A64 encoding group dispatch (ARM DDI 0487 C4.1)
        if (word & 0xFFFF_0000) == 0x0000_0000 {
            return decodeUDF(word: word, at: address)
        } else if (op0 & 0b1110) == 0b1000 {
            if let decoded = decodeDataProcessingImmediate(word: word, at: address, symbolLookup: symbolLookup) {
                return decoded
            }
        } else if (op0 & 0b1110) == 0b1010 {
            if let decoded = decodeBranchExceptionSystem(word: word, at: address, symbolLookup: symbolLookup) {
                return decoded
            }
        } else if (op0 & 0b0101) == 0b0100 {
            if let decoded = decodeLoadsAndStores(word: word, at: address, symbolLookup: symbolLookup) {
                return decoded
            }
        } else if (op0 & 0b0111) == 0b0101 {
            if let decoded = decodeDataProcessingRegister(word: word, at: address) {
                return decoded
            }
        } else if (op0 & 0b0111) == 0b0111 {
            if let decoded = decodeSIMDAndFloatingPoint(word: word, at: address) {
                return decoded
            }
        }

        return makeUnknownInstruction(word: word, at: address)
    }

    /// Linearly decodes a buffer of little-endian 32-bit ARM64 instructions starting at `baseAddress`.
    public func decodeBuffer(
        _ bytes: Data,
        baseAddress: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) -> [A64DecodedInstruction] {
        let wordCount = bytes.count / 4
        guard wordCount > 0 else { return [] }

        var output: [A64DecodedInstruction] = []
        output.reserveCapacity(wordCount)

        let start = bytes.startIndex
        for i in 0..<wordCount {
            let byteOffset = i * 4
            let b0 = UInt32(bytes[start + byteOffset])
            let b1 = UInt32(bytes[start + byteOffset + 1]) << 8
            let b2 = UInt32(bytes[start + byteOffset + 2]) << 16
            let b3 = UInt32(bytes[start + byteOffset + 3]) << 24
            let word = b0 | b1 | b2 | b3
            let insnAddr = baseAddress.adding(UInt64(byteOffset))
            output.append(decode(word: word, at: insnAddr, symbolLookup: symbolLookup))
        }

        return output
    }

    /// Convenience helper for decoding pre-extracted 32-bit words starting at `baseAddress`.
    public func decodeWords(
        _ words: [UInt32],
        baseAddress: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) -> [A64DecodedInstruction] {
        var output: [A64DecodedInstruction] = []
        output.reserveCapacity(words.count)
        for (idx, word) in words.enumerated() {
            let addr = baseAddress.adding(UInt64(idx * 4))
            output.append(decode(word: word, at: addr, symbolLookup: symbolLookup))
        }
        return output
    }

    // MARK: - Shared Instruction Construction Helpers

    private func decodeUDF(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction {
        let imm16 = UInt64(word & 0xFFFF)
        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .unknown,
            mnemonicText: "udf",
            operands: [.unsignedImmediate(imm16)],
            operandText: String(format: "#0x%llx", imm16),
            group: .branchAndSystem,
            flow: .sequential,
            readsRegisters: [],
            writesRegisters: [],
            readsFlags: false,
            writesFlags: false,
            autoComment: "Permanently undefined"
        )
    }

    private func makeUnknownInstruction(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction {
        A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .unknown,
            mnemonicText: ".inst",
            operands: [.unsignedImmediate(UInt64(word))],
            operandText: String(format: "0x%08x", word),
            group: .unknown,
            flow: .sequential,
            readsRegisters: [],
            writesRegisters: [],
            readsFlags: false,
            writesFlags: false,
            autoComment: "Unallocated / raw 32-bit word"
        )
    }

    private func activeRegs(_ regs: [A64Register]) -> [A64Register] {
        var result: [A64Register] = []
        for r in regs where !r.isZeroRegister {
            if !result.contains(r) {
                result.append(r)
            }
        }
        return result
    }

    // MARK: - Class 1: Data Processing — Immediate (op0 = 100x)

    private func decodeDataProcessingImmediate(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64DecodedInstruction? {
        let op1 = A64BitUtils.extract(word, 25, 23)
        switch op1 {
        case 0b000, 0b001:
            return decodePCRelAddressing(word: word, at: address, symbolLookup: symbolLookup)
        case 0b010:
            return decodeAddSubImmediate(word: word, at: address)
        case 0b100:
            return decodeLogicalImmediate(word: word, at: address)
        case 0b101:
            return decodeMoveWideImmediate(word: word, at: address)
        case 0b110:
            return decodeBitfield(word: word, at: address)
        case 0b111:
            return decodeExtract(word: word, at: address)
        default:
            return nil
        }
    }

    private func decodePCRelAddressing(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64DecodedInstruction {
        let isPage = A64BitUtils.flag(word, 31)
        let immlo = UInt64(A64BitUtils.extract(word, 30, 29))
        let immhi = UInt64(A64BitUtils.extract(word, 23, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))
        let rdReg = A64Register.x(rd, allowSP: false)

        let rawImm21 = (immhi << 2) | immlo
        let signedImm = signExtend(rawImm21, bits: 21)

        let target: VirtualAddress
        let mnemonic: A64Mnemonic
        let comment: String?
        if isPage {
            mnemonic = .adrp
            target = address.page4KBase().adding(signedImm << 12)
            if let sym = symbolLookup?(target) {
                comment = "page \(target.compactHexString) (\(sym))"
            } else {
                comment = "page \(target.compactHexString)"
            }
        } else {
            mnemonic = .adr
            target = address.adding(signedImm)
            comment = symbolLookup?(target) ?? "-> \(target.compactHexString)"
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .branchTarget(target)],
            group: .dataProcessingImm,
            flow: .sequential,
            readsRegisters: [],
            writesRegisters: activeRegs([rdReg]),
            autoComment: comment
        )
    }

    private func decodeAddSubImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let isSub = A64BitUtils.flag(word, 30)
        let setsFlags = A64BitUtils.flag(word, 29)
        let sh = A64BitUtils.bit(word, 22)
        let imm12 = UInt64(A64BitUtils.extract(word, 21, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: true)
        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: !setsFlags)

        // Alias: MOV <Xd|SP>, <Xn|SP> when ADD #0, lsl #0 involving SP/WSP
        if !isSub && !setsFlags && sh == 0 && imm12 == 0 && (rd == 31 || rn == 31) {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .mov,
                operands: [.register(rdReg), .register(rnReg)],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: activeRegs([rnReg]),
                writesRegisters: activeRegs([rdReg])
            )
        }

        let immOperand: A64Operand = (sh == 1)
            ? .shiftedImmediate(imm12, shiftBits: 12)
            : .unsignedImmediate(imm12)

        let shiftedComment: String? = (sh == 1 && imm12 != 0)
            ? String(format: "= 0x%llx", imm12 << 12)
            : nil

        // Alias: CMP / CMN when S == 1 and Rd == XZR/WZR (31)
        if setsFlags && rd == 31 {
            let aliasMnemonic: A64Mnemonic = isSub ? .cmp : .cmn
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: aliasMnemonic,
                operands: [.register(rnReg), immOperand],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: activeRegs([rnReg]),
                writesRegisters: [],
                readsFlags: false,
                writesFlags: true,
                autoComment: shiftedComment
            )
        }

        let mnemonic: A64Mnemonic
        switch (isSub, setsFlags) {
        case (false, false): mnemonic = .add
        case (false, true):  mnemonic = .adds
        case (true, false):  mnemonic = .sub
        case (true, true):   mnemonic = .subs
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), immOperand],
            group: .dataProcessingImm,
            flow: .sequential,
            readsRegisters: activeRegs([rnReg]),
            writesRegisters: activeRegs([rdReg]),
            readsFlags: false,
            writesFlags: setsFlags,
            autoComment: shiftedComment
        )
    }

    private func decodeLogicalImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let opc = A64BitUtils.extract(word, 30, 29)
        let immN = A64BitUtils.bit(word, 22)
        let immr = A64BitUtils.extract(word, 21, 16)
        let imms = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        if !is64 && immN != 0 {
            return nil
        }

        let regSize = is64 ? 64 : 32
        guard let masks = DecodeBitMasks(
            immN: immN,
            imms: imms,
            immr: immr,
            immediate: true,
            regSize: regSize
        ) else {
            return nil
        }

        let wmask = masks.wmask
        let setsFlags = (opc == 0b11)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: !setsFlags)

        // Alias: TST <Xn>, #<imm> when ANDS with Rd == XZR/WZR
        if opc == 0b11 && rd == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .tst,
                operands: [.register(rnReg), .unsignedImmediate(wmask)],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: activeRegs([rnReg]),
                writesRegisters: [],
                readsFlags: false,
                writesFlags: true
            )
        }

        // Alias: MOV <Xd|SP>, #<imm> when ORR with Rn == XZR/WZR and !MoveWidePreferred(sf, immN, imms, immr)
        if opc == 0b01 && rn == 31 && !moveWidePreferred(is64: is64, immN: immN, imms: imms, immr: immr) {
            let signedMask: Int64 = is64
                ? Int64(bitPattern: wmask)
                : Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: wmask)))
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .mov,
                operands: [.register(rdReg), .immediate(signedMask)],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: [],
                writesRegisters: activeRegs([rdReg]),
                autoComment: String(format: "bitmask 0x%llx", wmask)
            )
        }

        let mnemonic: A64Mnemonic
        switch opc {
        case 0b00: mnemonic = .and
        case 0b01: mnemonic = .orr
        case 0b10: mnemonic = .eor
        default:   mnemonic = .ands
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(wmask)],
            group: .dataProcessingImm,
            flow: .sequential,
            readsRegisters: activeRegs([rnReg]),
            writesRegisters: activeRegs([rdReg]),
            readsFlags: false,
            writesFlags: setsFlags
        )
    }

    /// ARM DDI 0487 `MoveWidePreferred(sf, immN, imms, immr)`: `true` when the bitmask immediate
    /// can be synthesized by a single `MOVZ` or `MOVN` instruction, suppressing `ORR` -> `MOV`.
    private func moveWidePreferred(is64: Bool, immN: UInt32, imms: UInt32, immr: UInt32) -> Bool {
        let s = Int(imms & 0x3F)
        let r = Int(immr & 0x3F)
        let width = is64 ? 64 : 32

        if is64 && (immN & 1) != 1 {
            return false
        }
        if !is64 && ((immN & 1) != 0 || (s & 0x20) != 0) {
            return false
        }
        if s < 16 {
            return ((16 - (r & 0xF)) & 0xF) <= (15 - s)
        }
        if s >= width - 17 {
            return (r & 0xF) <= (s - (width - 17))
        }
        return false
    }

    private static func formatSignedHexImmediate(_ val: Int64) -> String {
        if val < 0 {
            let mag = 0 &- UInt64(bitPattern: val)
            return "#-0x\(String(mag, radix: 16))"
        }
        return "#0x\(String(UInt64(bitPattern: val), radix: 16))"
    }

    private func decodeMoveWideImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let opc = A64BitUtils.extract(word, 30, 29)
        let hw = A64BitUtils.extract(word, 22, 21)
        let imm16 = UInt64(A64BitUtils.extract(word, 20, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        if !is64 && hw >= 2 {
            return nil
        }
        guard opc != 0b01 else { return nil }

        let shiftBits = UInt8(hw * 16)
        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let immOp: A64Operand = (shiftBits == 0)
            ? .unsignedImmediate(imm16)
            : .shiftedImmediate(imm16, shiftBits: shiftBits)

        switch opc {
        case 0b00: // MOVN
            let rawShifted = imm16 << Int(shiftBits)
            let inverted = is64 ? (~rawShifted) : ((~rawShifted) & 0xFFFF_FFFF)
            let signedVal: Int64 = is64
                ? Int64(bitPattern: inverted)
                : Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: inverted)))
            let keepMovn = (imm16 == 0 && hw != 0) || (!is64 && imm16 == 0xFFFF)
            let mnemonicText: String? = keepMovn ? nil : "mov"
            let operandText: String? = keepMovn
                ? nil
                : "\(rdReg.canonicalName), \(Self.formatSignedHexImmediate(signedVal))"
            let comment = String(
                format: "mov %@, #%lld (0x%llx)",
                rdReg.canonicalName,
                signedVal,
                inverted
            )
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .movn,
                mnemonicText: mnemonicText,
                operands: [.register(rdReg), immOp],
                operandText: operandText,
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: [],
                writesRegisters: activeRegs([rdReg]),
                autoComment: comment
            )

        case 0b10: // MOVZ
            let synthesized = imm16 << Int(shiftBits)
            let signedVal: Int64 = is64
                ? Int64(bitPattern: synthesized)
                : Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: synthesized)))
            let keepMovz = (imm16 == 0 && hw != 0)
            let mnemonicText: String? = keepMovz ? nil : "mov"
            let operandText: String? = keepMovz
                ? nil
                : "\(rdReg.canonicalName), \(Self.formatSignedHexImmediate(signedVal))"
            let comment: String? = (shiftBits > 0 || imm16 >= 16)
                ? String(format: "mov %@, #0x%llx", rdReg.canonicalName, synthesized)
                : nil
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .movz,
                mnemonicText: mnemonicText,
                operands: [.register(rdReg), immOp],
                operandText: operandText,
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: [],
                writesRegisters: activeRegs([rdReg]),
                autoComment: comment
            )

        case 0b11: // MOVK
            let laneMask = UInt64(0xFFFF) << Int(shiftBits)
            let comment = String(format: "insert [bits %d:%d] = 0x%04llx (mask 0x%llx)", Int(shiftBits) + 15, Int(shiftBits), imm16, laneMask)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .movk,
                operands: [.register(rdReg), immOp],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: activeRegs([rdReg]),
                writesRegisters: activeRegs([rdReg]),
                autoComment: comment
            )

        default:
            return nil
        }
    }

    private func decodeBitfield(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let opc = A64BitUtils.extract(word, 30, 29)
        let nBit = A64BitUtils.flag(word, 22)
        let immr = A64BitUtils.extract(word, 21, 16)
        let imms = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        guard is64 == nBit, opc <= 0b10 else { return nil }
        let regBits: UInt32 = is64 ? 64 : 32
        let maxBit = regBits - 1
        guard immr <= maxBit && imms <= maxBit else { return nil }

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)

        switch opc {
        case 0b00: // SBFM -> ASR, SXTB, SXTH, SXTW, SBFIZ, SBFX
            if imms == maxBit {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .asr,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(UInt64(immr))],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if immr == 0 && imms == 7 {
                let srcW = A64Register.w(rn, allowWSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sxtb,
                    operands: [.register(rdReg), .register(srcW)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([srcW]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if immr == 0 && imms == 15 {
                let srcW = A64Register.w(rn, allowWSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sxth,
                    operands: [.register(rdReg), .register(srcW)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([srcW]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if is64 && immr == 0 && imms == 31 {
                let srcW = A64Register.w(rn, allowWSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sxtw,
                    operands: [.register(rdReg), .register(srcW)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([srcW]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if imms < immr {
                let lsb = UInt64((regBits - immr) & maxBit)
                let width = UInt64(imms + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sbfiz,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            } else {
                let lsb = UInt64(immr)
                let width = UInt64(imms - immr + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sbfx,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }

        case 0b01: // BFM -> BFC, BFI, BFXIL
            if rn == 31 && (immr == 0 || imms < immr) {
                let lsb = UInt64((regBits - immr) & maxBit)
                let width = UInt64(imms + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .bfi,
                    mnemonicText: "bfc",
                    operands: [.register(rdReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rdReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if imms < immr {
                let lsb = UInt64((regBits - immr) & maxBit)
                let width = UInt64(imms + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .bfi,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rdReg, rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            } else {
                let lsb = UInt64(immr)
                let width = UInt64(imms - immr + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .bfxil,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rdReg, rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }

        case 0b10: // UBFM -> LSR, LSL, UXTB, UXTH, UBFIZ, UBFX
            if imms == maxBit {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .lsr,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(UInt64(immr))],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if imms + 1 == immr {
                let shift = UInt64(regBits - immr)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .lsl,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(shift)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if !is64 && immr == 0 && imms == 7 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .uxtb,
                    operands: [.register(rdReg), .register(rnReg)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if !is64 && immr == 0 && imms == 15 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .uxth,
                    operands: [.register(rdReg), .register(rnReg)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            if imms < immr {
                let lsb = UInt64((regBits - immr) & maxBit)
                let width = UInt64(imms + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ubfiz,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            } else {
                let lsb = UInt64(immr)
                let width = UInt64(imms - immr + 1)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ubfx,
                    operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(lsb), .unsignedImmediate(width)],
                    group: .dataProcessingImm,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }

        default:
            return nil
        }
    }

    private func decodeExtract(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let op21 = A64BitUtils.extract(word, 30, 29)
        let nBit = A64BitUtils.flag(word, 22)
        let o0 = A64BitUtils.bit(word, 21)
        guard op21 == 0 && o0 == 0 && is64 == nBit else { return nil }

        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let imms = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        if !is64 && imms >= 32 {
            return nil
        }

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)

        if rn == rm {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .ror,
                operands: [.register(rdReg), .register(rnReg), .unsignedImmediate(UInt64(imms))],
                group: .dataProcessingImm,
                readsRegisters: activeRegs([rnReg]),
                writesRegisters: activeRegs([rdReg])
            )
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .extr,
            operands: [.register(rdReg), .register(rnReg), .register(rmReg), .unsignedImmediate(UInt64(imms))],
            group: .dataProcessingImm,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg])
        )
    }

    // MARK: - Class 2: Branches, Exception Generating & System (op0 = 101x)

    private func decodeBranchExceptionSystem(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64DecodedInstruction? {
        // 1. Unconditional Branch Immediate (B / BL): bits[30:26] == 0b00101
        if (word & 0x7C00_0000) == 0x1400_0000 {
            let isLink = A64BitUtils.flag(word, 31)
            let imm26 = UInt64(word & 0x03FF_FFFF)
            let byteOffset = signExtend(imm26, bits: 26) * 4
            let target = address.adding(byteOffset)
            let sym = symbolLookup?(target)
            if isLink {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .bl,
                    operands: [.branchTarget(target)],
                    group: .branchAndSystem,
                    flow: .directCall(target: target),
                    readsRegisters: [],
                    writesRegisters: [.lr],
                    autoComment: sym
                )
            } else {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .b,
                    operands: [.branchTarget(target)],
                    group: .branchAndSystem,
                    flow: .unconditionalJump(target: target),
                    readsRegisters: [],
                    writesRegisters: [],
                    autoComment: sym
                )
            }
        }

        // 2. Compare and Branch Immediate (CBZ / CBNZ): bits[30:25] == 0b011010
        if (word & 0x7E00_0000) == 0x3400_0000 {
            let is64 = A64BitUtils.flag(word, 31)
            let isNonZero = A64BitUtils.flag(word, 24)
            let imm19 = UInt64(A64BitUtils.extract(word, 23, 5))
            let rt = UInt8(A64BitUtils.extract(word, 4, 0))
            let rtReg = A64Register.gp(rt, is64Bit: is64, allowSP: false)

            let byteOffset = signExtend(imm19, bits: 19) * 4
            let target = address.adding(byteOffset)
            let cond: A64ConditionCode = isNonZero ? .ne : .eq

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: isNonZero ? .cbnz : .cbz,
                operands: [.register(rtReg), .branchTarget(target)],
                group: .branchAndSystem,
                flow: .conditionalBranch(target: target, condition: cond),
                readsRegisters: activeRegs([rtReg]),
                writesRegisters: [],
                autoComment: symbolLookup?(target)
            )
        }

        // 3. Test Bit and Branch (TBZ / TBNZ): bits[30:25] == 0b011011
        if (word & 0x7E00_0000) == 0x3600_0000 {
            let b5 = A64BitUtils.bit(word, 31)
            let isNonZero = A64BitUtils.flag(word, 24)
            let b40 = A64BitUtils.extract(word, 23, 19)
            let bitIndex = UInt64((b5 << 5) | b40)
            let imm14 = UInt64(A64BitUtils.extract(word, 18, 5))
            let rt = UInt8(A64BitUtils.extract(word, 4, 0))
            let rtReg = A64Register.gp(rt, is64Bit: b5 == 1, allowSP: false)

            let byteOffset = signExtend(imm14, bits: 14) * 4
            let target = address.adding(byteOffset)
            let cond: A64ConditionCode = isNonZero ? .ne : .eq

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: isNonZero ? .tbnz : .tbz,
                operands: [.register(rtReg), .unsignedImmediate(bitIndex), .branchTarget(target)],
                group: .branchAndSystem,
                flow: .conditionalBranch(target: target, condition: cond),
                readsRegisters: activeRegs([rtReg]),
                writesRegisters: [],
                autoComment: symbolLookup?(target)
            )
        }

        // 4. Conditional Branch Immediate (B.<cond>): bits[31:24] == 0b01010100, bit[4] == 0
        if (word & 0xFF00_0000) == 0x5400_0000 {
            guard !A64BitUtils.flag(word, 4) else { return nil }
            let imm19 = UInt64(A64BitUtils.extract(word, 23, 5))
            let cond = A64ConditionCode(nibble: word & 0xF)
            let byteOffset = signExtend(imm19, bits: 19) * 4
            let target = address.adding(byteOffset)
            let flow: A64FlowSemantics = (cond == .al || cond == .nv)
                ? .unconditionalJump(target: target)
                : .conditionalBranch(target: target, condition: cond)

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .bCond,
                mnemonicText: "b.\(cond.mnemonicSuffix)",
                operands: [.branchTarget(target)],
                group: .branchAndSystem,
                flow: flow,
                readsRegisters: [],
                writesRegisters: [],
                readsFlags: !(cond == .al || cond == .nv),
                writesFlags: false,
                autoComment: symbolLookup?(target)
            )
        }

        // 5. Exception Generation (SVC, HVC, SMC, BRK, HLT): bits[31:24] == 0b11010100
        if (word & 0xFF00_0000) == 0xD400_0000 {
            return decodeExceptionGeneration(word: word, at: address)
        }

        // 6. System Instructions, Hints, Barriers, PAC Hints & MSR/MRS: bits[31:22] == 0b1101010100
        if (word & 0xFFC0_0000) == 0xD500_0000 {
            return decodeSystemAndHints(word: word, at: address)
        }

        // 7. Unconditional Branch Register & ARMv8.3 PAC Branches: bits[31:25] == 0b1101011
        if (word & 0xFE00_0000) == 0xD600_0000 {
            return decodeUnconditionalBranchRegister(word: word, at: address)
        }

        return nil
    }

    private func decodeExceptionGeneration(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let opc = A64BitUtils.extract(word, 23, 21)
        let imm16 = UInt16(A64BitUtils.extract(word, 20, 5))
        let op2 = A64BitUtils.extract(word, 4, 2)
        let ll = A64BitUtils.extract(word, 1, 0)
        guard op2 == 0 else { return nil }

        let immOp = A64Operand.unsignedImmediate(UInt64(imm16))
        switch (opc, ll) {
        case (0b000, 0b01):
            let darwinComment: String? = (imm16 == 0x80)
                ? "Darwin XNU ARM64 supervisor syscall (x16 = syscall number)"
                : "Supervisor call #0x\(String(imm16, radix: 16))"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .svc,
                operands: [immOp],
                group: .branchAndSystem,
                flow: .trapOrSupervisor(immediate: imm16),
                readsRegisters: imm16 == 0x80 ? [.x(16), .x(0), .x(1), .x(2)] : [],
                writesRegisters: imm16 == 0x80 ? [.x(0), .x(1)] : [],
                writesFlags: imm16 == 0x80,
                autoComment: darwinComment
            )

        case (0b000, 0b10):
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .hvc,
                operands: [immOp],
                group: .branchAndSystem,
                flow: .trapOrSupervisor(immediate: imm16),
                autoComment: "Hypervisor call"
            )

        case (0b000, 0b11):
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .smc,
                operands: [immOp],
                group: .branchAndSystem,
                flow: .trapOrSupervisor(immediate: imm16),
                autoComment: "Secure monitor call"
            )

        case (0b001, 0b00):
            let brkComment: String = (imm16 == 1)
                ? "Swift runtime assertion / trap breakpoint (#1)"
                : "Software breakpoint trap"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .brk,
                operands: [immOp],
                group: .branchAndSystem,
                flow: .trapOrSupervisor(immediate: imm16),
                autoComment: brkComment
            )

        case (0b010, 0b00):
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .hlt,
                operands: [immOp],
                group: .branchAndSystem,
                flow: .trapOrSupervisor(immediate: imm16),
                autoComment: "Debug halt trap"
            )

        default:
            return nil
        }
    }

    private func decodeSystemAndHints(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let isRead = A64BitUtils.flag(word, 21)
        let op0 = A64BitUtils.extract(word, 20, 19)
        let op1 = A64BitUtils.extract(word, 18, 16)
        let crn = A64BitUtils.extract(word, 15, 12)
        let crm = A64BitUtils.extract(word, 11, 8)
        let op2 = A64BitUtils.extract(word, 7, 5)
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        // Architectural & PAC Hints (NOP, YIELD, WFE, WFI, SEV, SEVL, DGH, ESB, CSDB, PAC/AUT, BTI)
        if !isRead && op0 == 0 && op1 == 0b011 && crn == 0b0010 && rt == 31 {
            let hintCode = (crm << 3) | op2
            switch hintCode {
            case 0:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .nop, operands: [], group: .branchAndSystem)
            case 1:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .yield, operands: [], group: .branchAndSystem)
            case 2:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .wfe, operands: [], group: .branchAndSystem)
            case 3:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .wfi, operands: [], group: .branchAndSystem)
            case 4:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .sev, operands: [], group: .branchAndSystem)
            case 5:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .sevl, operands: [], group: .branchAndSystem)
            case 6: // DGH (0xD50320DF)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .hint, mnemonicText: "dgh",
                    operands: [], group: .branchAndSystem
                )
            case 7:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .xpaci,
                    mnemonicText: "xpaclri",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr],
                    writesRegisters: [.lr],
                    autoComment: "Strip PAC from LR (x30)"
                )
            case 8: // PACIA1716 (0xD503211F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "pacia1716",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.x(17), .x(16)],
                    writesRegisters: [.x(17)],
                    autoComment: "PAC: Sign x17 with IA key + x16 modifier"
                )
            case 10: // PACIB1716 (0xD503215F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "pacib1716",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.x(17), .x(16)],
                    writesRegisters: [.x(17)],
                    autoComment: "PAC: Sign x17 with IB key + x16 modifier"
                )
            case 12: // AUTIA1716 (0xD503219F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "autia1716",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.x(17), .x(16)],
                    writesRegisters: [.x(17)],
                    autoComment: "PAC: Authenticate x17 with IA key + x16 modifier"
                )
            case 14: // AUTIB1716 (0xD50321DF)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "autib1716",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.x(17), .x(16)],
                    writesRegisters: [.x(17)],
                    autoComment: "PAC: Authenticate x17 with IB key + x16 modifier"
                )
            case 16: // ESB (0xD503221F)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .hint, mnemonicText: "esb",
                    operands: [], group: .branchAndSystem
                )
            case 18: // TSB CSYNC (CRm=2, op2=2)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .hint, mnemonicText: "tsb",
                    operands: [.barrierOption("csync")], group: .branchAndSystem
                )
            case 20: // CSDB (0xD503229F)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .hint, mnemonicText: "csdb",
                    operands: [], group: .branchAndSystem
                )
            case 24: // PACIAZ (0xD503231F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "paciaz",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Sign LR (x30) with IA key + zero modifier"
                )
            case 25: // PACIASP (0xD503233F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .paciasp,
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr, .sp],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Sign LR (x30) with IA key + SP modifier"
                )
            case 26: // PACIBZ (0xD503235F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "pacibz",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Sign LR (x30) with IB key + zero modifier"
                )
            case 27: // PACIBSP (0xD503237F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .pacibsp,
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr, .sp],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Sign LR (x30) with IB key + SP modifier"
                )
            case 28: // AUTIAZ (0xD503239F)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "autiaz",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Authenticate LR (x30) with IA key + zero modifier"
                )
            case 29: // AUTIASP (0xD50323BF)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .autiasp,
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr, .sp],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Authenticate LR (x30) with IA key + SP modifier"
                )
            case 30: // AUTIBZ (0xD50323DF)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    mnemonicText: "autibz",
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Authenticate LR (x30) with IB key + zero modifier"
                )
            case 31: // AUTIBSP (0xD50323FF)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .autibsp,
                    operands: [],
                    group: .pacPointerAuth,
                    readsRegisters: [.lr, .sp],
                    writesRegisters: [.lr],
                    autoComment: "PAC: Authenticate LR (x30) with IB key + SP modifier"
                )
            case 32, 34, 36, 38: // BTI
                let targets: String
                switch (op2 >> 1) & 0x3 {
                case 1: targets = "c"
                case 2: targets = "j"
                case 3: targets = "jc"
                default: targets = ""
                }
                let ops: [A64Operand] = targets.isEmpty ? [] : [.barrierOption(targets)]
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .bti,
                    operands: ops,
                    group: .branchAndSystem,
                    autoComment: "Branch Target Identification landing pad"
                )
            default:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .hint,
                    operands: [.unsignedImmediate(UInt64(hintCode))],
                    group: .branchAndSystem
                )
            }
        }

        // Memory Barriers (CLREX, DSB, SSBB, PSSBB, DMB, ISB, SB, and S0_3_C3_* MSR fallbacks)
        if !isRead && op0 == 0 && op1 == 0b011 && crn == 0b0011 {
            if rt == 31 {
                switch op2 {
                case 0b010:
                    let ops: [A64Operand] = (crm == 15) ? [] : [.unsignedImmediate(UInt64(crm))]
                    let opText: String? = (crm == 15) ? nil : String(format: "#0x%x", crm)
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .clrex,
                        operands: ops,
                        operandText: opText,
                        group: .branchAndSystem
                    )
                case 0b100:
                    if crm == 0 || crm == 4 {
                        let alias = (crm == 0) ? "ssbb" : "pssbb"
                        return A64DecodedInstruction(
                            address: address,
                            rawWord: word,
                            mnemonic: .dsb,
                            mnemonicText: alias,
                            operands: [],
                            group: .branchAndSystem,
                            autoComment: crm == 0 ? "Speculative Store Bypass Barrier" : "Physical Speculative Store Bypass Barrier"
                        )
                    }
                    let opt = A64BarrierOptionTable.name(forCRm: crm)
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .dsb,
                        operands: [.barrierOption(opt)],
                        group: .branchAndSystem,
                        autoComment: "Data Synchronization Barrier (\(A64BarrierOptionTable.architecturalName(forCRm: crm)))"
                    )
                case 0b101:
                    let opt = A64BarrierOptionTable.name(forCRm: crm)
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .dmb,
                        operands: [.barrierOption(opt)],
                        group: .branchAndSystem,
                        autoComment: "Data Memory Barrier (\(A64BarrierOptionTable.architecturalName(forCRm: crm)))"
                    )
                case 0b110:
                    let ops: [A64Operand] = (crm == 15) ? [] : [.unsignedImmediate(UInt64(crm))]
                    let opText: String? = (crm == 15) ? nil : "#\(crm)"
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .isb,
                        operands: ops,
                        operandText: opText,
                        group: .branchAndSystem,
                        autoComment: "Instruction Synchronization Barrier"
                    )
                case 0b111:
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .isb,
                        mnemonicText: "sb",
                        operands: [],
                        group: .branchAndSystem,
                        autoComment: "Speculation Barrier"
                    )
                default:
                    break
                }
            }

            let sysEnc = UInt16((word >> 5) & 0xFFFF)
            let sysName = "S0_3_C3_C\(crm)_\(op2)"
            let xtReg = A64Register.x(rt, allowSP: false)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .msr,
                operands: [.systemRegister(name: sysName, encoding: sysEnc), .register(xtReg)],
                group: .branchAndSystem,
                readsRegisters: activeRegs([xtReg]),
                writesRegisters: []
            )
        }

        // PSTATE Immediate MSR (e.g. MSR SPSel, #imm)
        if !isRead && op0 == 0 && crn == 0b0100 && rt == 31 {
            if let field = A64SystemOpHelpers.pstateFieldName(op1: op1, op2: op2) {
                let enc = A64SystemRegisterTable.packEncoding(op0: 0, op1: op1, crn: crn, crm: crm, op2: op2)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .msr,
                    operands: [.systemRegister(name: field, encoding: enc), .unsignedImmediate(UInt64(crm))],
                    group: .branchAndSystem
                )
            }
        }

        // SYS / SYSL (Cache, TLB & Address Translation maintenance)
        if op0 == 1 {
            let xtReg = A64Register.x(rt, allowSP: false)
            if !isRead, let preferred = A64SystemOpHelpers.sysPreferredAlias(op1: op1, crn: crn, crm: crm, op2: op2) {
                var aliasOperands: [A64Operand] = []
                if let op = preferred.operation {
                    aliasOperands.append(.barrierOption(op))
                }
                if preferred.takesRegister {
                    aliasOperands.append(.register(xtReg))
                }
                let aliasOperandText: String
                switch (preferred.operation, preferred.takesRegister) {
                case (let op?, true):
                    aliasOperandText = "\(op), \(xtReg.canonicalName)"
                case (let op?, false):
                    aliasOperandText = op
                case (nil, true):
                    aliasOperandText = xtReg.canonicalName
                case (nil, false):
                    aliasOperandText = ""
                }
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sys,
                    mnemonicText: preferred.mnemonic,
                    operands: aliasOperands,
                    operandText: aliasOperandText,
                    group: .branchAndSystem,
                    readsRegisters: preferred.takesRegister ? activeRegs([xtReg]) : [],
                    writesRegisters: []
                )
            }

            if isRead {
                let syslStr = "\(xtReg.canonicalName), #\(op1), c\(crn), c\(crm), #\(op2)"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .sys,
                    mnemonicText: "sysl",
                    operands: [
                        .register(xtReg),
                        .unsignedImmediate(UInt64(op1)),
                        .unsignedImmediate(UInt64(crn)),
                        .unsignedImmediate(UInt64(crm)),
                        .unsignedImmediate(UInt64(op2))
                    ],
                    operandText: syslStr,
                    group: .branchAndSystem,
                    readsRegisters: [],
                    writesRegisters: activeRegs([xtReg])
                )
            }

            let opStr = rt == 31
                ? "#\(op1), c\(crn), c\(crm), #\(op2)"
                : "#\(op1), c\(crn), c\(crm), #\(op2), \(xtReg.canonicalName)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .sys,
                mnemonicText: "sys",
                operands: rt == 31
                    ? [.unsignedImmediate(UInt64(op1)), .unsignedImmediate(UInt64(crn)), .unsignedImmediate(UInt64(crm)), .unsignedImmediate(UInt64(op2))]
                    : [.unsignedImmediate(UInt64(op1)), .unsignedImmediate(UInt64(crn)), .unsignedImmediate(UInt64(crm)), .unsignedImmediate(UInt64(op2)), .register(xtReg)],
                operandText: opStr,
                group: .branchAndSystem,
                readsRegisters: activeRegs([xtReg]),
                writesRegisters: []
            )
        }

        // MSR (register) / MRS: op0 in 2...3
        if op0 >= 2 {
            let sysEnc = UInt16((word >> 5) & 0xFFFF)
            let sysName = A64SystemRegisterTable.name(forEncoding: sysEnc, isRead: isRead)
            let rawSummary = A64SystemRegisterTable.lookup(encoding: sysEnc, isRead: isRead)?.summary
            let sysSummary = (rawSummary?.isEmpty == false) ? rawSummary : nil
            let xtReg = A64Register.x(rt, allowSP: false)
            let touchesNZCV = (sysName == "NZCV")

            if isRead {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .mrs,
                    operands: [.register(xtReg), .systemRegister(name: sysName, encoding: sysEnc)],
                    group: .branchAndSystem,
                    readsRegisters: [],
                    writesRegisters: activeRegs([xtReg]),
                    readsFlags: touchesNZCV,
                    writesFlags: false,
                    autoComment: sysSummary
                )
            } else {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .msr,
                    operands: [.systemRegister(name: sysName, encoding: sysEnc), .register(xtReg)],
                    group: .branchAndSystem,
                    readsRegisters: activeRegs([xtReg]),
                    writesRegisters: [],
                    readsFlags: false,
                    writesFlags: touchesNZCV,
                    autoComment: sysSummary
                )
            }
        }

        return nil
    }

    private func decodeUnconditionalBranchRegister(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let opc = A64BitUtils.extract(word, 24, 21)
        let op2 = A64BitUtils.extract(word, 20, 16)
        let op3 = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rm = UInt8(A64BitUtils.extract(word, 4, 0))

        guard op2 == 0b11111 else { return nil }
        let rnReg = A64Register.x(rn, allowSP: false)

        // Standard BR / BLR / RET
        if op3 == 0b000000 && rm == 0b00000 {
            switch opc {
            case 0b0000:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .br,
                    operands: [.register(rnReg)],
                    group: .branchAndSystem,
                    flow: .indirectJump(register: rnReg),
                    readsRegisters: activeRegs([rnReg])
                )
            case 0b0001:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .blr,
                    operands: [.register(rnReg)],
                    group: .branchAndSystem,
                    flow: .indirectCall(register: rnReg),
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: [.lr]
                )
            case 0b0010:
                let ops: [A64Operand] = (rn == 30) ? [] : [.register(rnReg)]
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ret,
                    operands: ops,
                    group: .branchAndSystem,
                    flow: .returnControl,
                    readsRegisters: activeRegs([rnReg])
                )
            default:
                return nil
            }
        }

        // ARMv8.3-A Pointer Authentication Branches (BRAAZ, BRABZ, BLRAAZ, BLRABZ, RETAA, RETAB, BRAA, BRAB, BLRAA, BLRAB)
        if op3 == 0b000010 || op3 == 0b000011 {
            let isKeyB = (op3 == 0b000011)
            let keyLabel = isKeyB ? "IB" : "IA"

            switch opc {
            case 0b0000 where rm == 0b11111:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isKeyB ? .brabz : .braaz,
                    operands: [.register(rnReg)],
                    group: .pacPointerAuth,
                    flow: .indirectJump(register: rnReg),
                    readsRegisters: activeRegs([rnReg]),
                    autoComment: "PAC indirect jump (\(keyLabel) key, zero modifier)"
                )

            case 0b0001 where rm == 0b11111:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isKeyB ? .blrabz : .blraaz,
                    operands: [.register(rnReg)],
                    group: .pacPointerAuth,
                    flow: .indirectCall(register: rnReg),
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: [.lr],
                    autoComment: "PAC indirect call (\(keyLabel) key, zero modifier)"
                )

            case 0b0010 where rn == 0b11111 && rm == 0b11111:
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isKeyB ? .retab : .retaa,
                    operands: [],
                    group: .pacPointerAuth,
                    flow: .returnControl,
                    readsRegisters: [.lr, .sp],
                    autoComment: "PAC authenticated return (\(keyLabel) key + SP)"
                )

            case 0b1000:
                let rmReg = A64Register.x(rm, allowSP: true)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isKeyB ? .brab : .braa,
                    operands: [.register(rnReg), .register(rmReg)],
                    group: .pacPointerAuth,
                    flow: .indirectJump(register: rnReg),
                    readsRegisters: activeRegs([rnReg, rmReg]),
                    autoComment: "PAC indirect jump (\(keyLabel) key + \(rmReg.canonicalName))"
                )

            case 0b1001:
                let rmReg = A64Register.x(rm, allowSP: true)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isKeyB ? .blrab : .blraa,
                    operands: [.register(rnReg), .register(rmReg)],
                    group: .pacPointerAuth,
                    flow: .indirectCall(register: rnReg),
                    readsRegisters: activeRegs([rnReg, rmReg]),
                    writesRegisters: [.lr],
                    autoComment: "PAC indirect call (\(keyLabel) key + \(rmReg.canonicalName))"
                )

            default:
                return nil
            }
        }

        return nil
    }

    // MARK: - Class 3: Loads & Stores (op0 = x1x0)

    private func decodeLoadsAndStores(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64DecodedInstruction? {
        // 1. Load Register (PC-relative literal): bits[29:27] == 0b011, bits[25:24] == 0b00
        if (word & 0x3B00_0000) == 0x1800_0000 {
            return decodeLoadLiteral(word: word, at: address, symbolLookup: symbolLookup)
        }

        // 2. Load/Store Pair (LDP, STP, LDPSW, LDNP, STNP): bits[29:27] == 0b101, bit[25] == 0
        if (word & 0x3A00_0000) == 0x2800_0000 {
            return decodeLoadStorePair(word: word, at: address)
        }

        // 3. Load/Store Register (Unsigned Scaled 12-bit Immediate): bits[29:27] == 0b111, bits[25:24] == 0b01
        if (word & 0x3B00_0000) == 0x3900_0000 {
            return decodeLoadStoreUnsignedImm(word: word, at: address)
        }

        // 4. Load/Store Unscaled, Pre/Post-Index, Register Offset, PAC Load & LSE Atomics: bits[29:27] == 0b111, bits[25:24] == 0b00
        if (word & 0x3B00_0000) == 0x3800_0000 {
            return decodeLoadStoreMiscOrAtomic(word: word, at: address)
        }

        // 5. Load/Store Exclusive, Acquire/Release & LSE CAS: bits[29:24] == 0b001000
        if (word & 0x3F00_0000) == 0x0800_0000 {
            return decodeLoadStoreExclusiveOrCAS(word: word, at: address)
        }

        return nil
    }

    private func decodeLoadLiteral(
        word: UInt32,
        at address: VirtualAddress,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64DecodedInstruction? {
        let opc = A64BitUtils.extract(word, 31, 30)
        let isSIMD = A64BitUtils.flag(word, 26)
        let imm19 = UInt64(A64BitUtils.extract(word, 23, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        let byteOffset = signExtend(imm19, bits: 19) * 4
        let target = address.adding(byteOffset)
        let memOp = A64Operand.memory(.pcRelativeLiteral(target: target))
        let symComment = symbolLookup?(target) ?? "literal @ \(target.compactHexString)"

        if isSIMD {
            let rtReg: A64Register
            switch opc {
            case 0b00: rtReg = .s(rt)
            case 0b01: rtReg = .d(rt)
            case 0b10: rtReg = .q(rt)
            default: return nil
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .ldr,
                operands: [.register(rtReg), memOp],
                group: .loadStore,
                readsRegisters: [],
                writesRegisters: [rtReg],
                autoComment: symComment
            )
        } else {
            switch opc {
            case 0b00:
                let rtReg = A64Register.w(rt, allowWSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ldr,
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    writesRegisters: activeRegs([rtReg]),
                    autoComment: symComment
                )
            case 0b01:
                let rtReg = A64Register.x(rt, allowSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ldr,
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    writesRegisters: activeRegs([rtReg]),
                    autoComment: symComment
                )
            case 0b10:
                let rtReg = A64Register.x(rt, allowSP: false)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ldrsw,
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    writesRegisters: activeRegs([rtReg]),
                    autoComment: symComment
                )
            case 0b11:
                let prfName = A64PrefetchOpTable.name(forCode: UInt32(rt))
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .prfm,
                    operands: [.prefetchOp(prfName), memOp],
                    group: .loadStore,
                    autoComment: symComment
                )
            default:
                return nil
            }
        }
    }

    private func decodeLoadStorePair(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let opc = A64BitUtils.extract(word, 31, 30)
        let isSIMD = A64BitUtils.flag(word, 26)
        let mode = A64BitUtils.extract(word, 24, 23)
        let isLoad = A64BitUtils.flag(word, 22)
        let imm7 = UInt64(A64BitUtils.extract(word, 21, 15))
        let rt2 = UInt8(A64BitUtils.extract(word, 14, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        guard mode <= 0b11 else { return nil }
        let baseReg = A64Register.x(rn, allowSP: true)

        let reg1: A64Register
        let reg2: A64Register
        let scale: Int64
        let mnemonic: A64Mnemonic

        if isSIMD {
            switch opc {
            case 0b00:
                reg1 = .s(rt); reg2 = .s(rt2); scale = 4
            case 0b01:
                reg1 = .d(rt); reg2 = .d(rt2); scale = 8
            case 0b10:
                reg1 = .q(rt); reg2 = .q(rt2); scale = 16
            default:
                return nil
            }
            if mode == 0b00 {
                mnemonic = isLoad ? .ldnp : .stnp
            } else {
                mnemonic = isLoad ? .ldp : .stp
            }
        } else {
            switch opc {
            case 0b00:
                reg1 = .w(rt); reg2 = .w(rt2); scale = 4
                mnemonic = (mode == 0b00) ? (isLoad ? .ldnp : .stnp) : (isLoad ? .ldp : .stp)
            case 0b01:
                guard isLoad && mode != 0b00 else { return nil }
                reg1 = .x(rt); reg2 = .x(rt2); scale = 4
                mnemonic = .ldpsw
            case 0b10:
                reg1 = .x(rt); reg2 = .x(rt2); scale = 8
                mnemonic = (mode == 0b00) ? (isLoad ? .ldnp : .stnp) : (isLoad ? .ldp : .stp)
            default:
                return nil
            }
        }

        let offset = signExtend(imm7, bits: 7) * scale
        let addrMode: A64AddressingMode
        let writesBase: Bool
        switch mode {
        case 0b01:
            addrMode = .postIndex(base: baseReg, offset: offset)
            writesBase = true
        case 0b11:
            addrMode = .preIndex(base: baseReg, offset: offset)
            writesBase = true
        default:
            addrMode = .baseOffset(base: baseReg, offset: offset)
            writesBase = false
        }

        let reads = isLoad ? activeRegs([baseReg]) : activeRegs([baseReg, reg1, reg2])
        var writes: [A64Register] = isLoad ? [reg1, reg2] : []
        if writesBase {
            writes.append(baseReg)
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(reg1), .register(reg2), .memory(addrMode)],
            group: .loadStore,
            readsRegisters: reads,
            writesRegisters: activeRegs(writes)
        )
    }

    private struct SingleMemTransferSpec {
        let mnemonic: A64Mnemonic
        let unscaledMnemonic: A64Mnemonic
        let targetReg: A64Register?
        let prefetchCode: UInt32?
        let isLoad: Bool
        let scaleShift: Int
    }

    private func resolveSingleMemTransferSpec(
        size: UInt32,
        isSIMD: Bool,
        opc: UInt32,
        rt: UInt8
    ) -> SingleMemTransferSpec? {
        if isSIMD {
            switch (size, opc) {
            case (0b00, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .b(rt), prefetchCode: nil, isLoad: false, scaleShift: 0)
            case (0b00, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .b(rt), prefetchCode: nil, isLoad: true, scaleShift: 0)
            case (0b00, 0b10): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .q(rt), prefetchCode: nil, isLoad: false, scaleShift: 4)
            case (0b00, 0b11): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .q(rt), prefetchCode: nil, isLoad: true, scaleShift: 4)
            case (0b01, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .h(rt), prefetchCode: nil, isLoad: false, scaleShift: 1)
            case (0b01, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .h(rt), prefetchCode: nil, isLoad: true, scaleShift: 1)
            case (0b10, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .s(rt), prefetchCode: nil, isLoad: false, scaleShift: 2)
            case (0b10, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .s(rt), prefetchCode: nil, isLoad: true, scaleShift: 2)
            case (0b11, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .d(rt), prefetchCode: nil, isLoad: false, scaleShift: 3)
            case (0b11, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .d(rt), prefetchCode: nil, isLoad: true, scaleShift: 3)
            default: return nil
            }
        } else {
            switch (size, opc) {
            case (0b00, 0b00): return .init(mnemonic: .strb, unscaledMnemonic: .sturb, targetReg: .w(rt), prefetchCode: nil, isLoad: false, scaleShift: 0)
            case (0b00, 0b01): return .init(mnemonic: .ldrb, unscaledMnemonic: .ldurb, targetReg: .w(rt), prefetchCode: nil, isLoad: true, scaleShift: 0)
            case (0b00, 0b10): return .init(mnemonic: .ldrsb, unscaledMnemonic: .ldursb, targetReg: .x(rt), prefetchCode: nil, isLoad: true, scaleShift: 0)
            case (0b00, 0b11): return .init(mnemonic: .ldrsb, unscaledMnemonic: .ldursb, targetReg: .w(rt), prefetchCode: nil, isLoad: true, scaleShift: 0)

            case (0b01, 0b00): return .init(mnemonic: .strh, unscaledMnemonic: .sturh, targetReg: .w(rt), prefetchCode: nil, isLoad: false, scaleShift: 1)
            case (0b01, 0b01): return .init(mnemonic: .ldrh, unscaledMnemonic: .ldurh, targetReg: .w(rt), prefetchCode: nil, isLoad: true, scaleShift: 1)
            case (0b01, 0b10): return .init(mnemonic: .ldrsh, unscaledMnemonic: .ldursh, targetReg: .x(rt), prefetchCode: nil, isLoad: true, scaleShift: 1)
            case (0b01, 0b11): return .init(mnemonic: .ldrsh, unscaledMnemonic: .ldursh, targetReg: .w(rt), prefetchCode: nil, isLoad: true, scaleShift: 1)

            case (0b10, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .w(rt), prefetchCode: nil, isLoad: false, scaleShift: 2)
            case (0b10, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .w(rt), prefetchCode: nil, isLoad: true, scaleShift: 2)
            case (0b10, 0b10): return .init(mnemonic: .ldrsw, unscaledMnemonic: .ldursw, targetReg: .x(rt), prefetchCode: nil, isLoad: true, scaleShift: 2)

            case (0b11, 0b00): return .init(mnemonic: .str, unscaledMnemonic: .stur, targetReg: .x(rt), prefetchCode: nil, isLoad: false, scaleShift: 3)
            case (0b11, 0b01): return .init(mnemonic: .ldr, unscaledMnemonic: .ldur, targetReg: .x(rt), prefetchCode: nil, isLoad: true, scaleShift: 3)
            case (0b11, 0b10): return .init(mnemonic: .prfm, unscaledMnemonic: .prfm, targetReg: nil, prefetchCode: UInt32(rt), isLoad: true, scaleShift: 3)
            default: return nil
            }
        }
    }

    private func decodeLoadStoreUnsignedImm(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let size = A64BitUtils.extract(word, 31, 30)
        let isSIMD = A64BitUtils.flag(word, 26)
        let opc = A64BitUtils.extract(word, 23, 22)
        let imm12 = Int64(A64BitUtils.extract(word, 21, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        guard let spec = resolveSingleMemTransferSpec(size: size, isSIMD: isSIMD, opc: opc, rt: rt) else {
            return nil
        }

        let baseReg = A64Register.x(rn, allowSP: true)
        let scaledOffset = imm12 << spec.scaleShift
        let memOp = A64Operand.memory(.baseOffset(base: baseReg, offset: scaledOffset))

        if let prfCode = spec.prefetchCode {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .prfm,
                operands: [.prefetchOp(A64PrefetchOpTable.name(forCode: prfCode)), memOp],
                group: .loadStore,
                readsRegisters: activeRegs([baseReg])
            )
        }

        guard let targetReg = spec.targetReg else { return nil }
        let reads = spec.isLoad ? activeRegs([baseReg]) : activeRegs([baseReg, targetReg])
        let writes = spec.isLoad ? activeRegs([targetReg]) : []

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: spec.mnemonic,
            operands: [.register(targetReg), memOp],
            group: .loadStore,
            readsRegisters: reads,
            writesRegisters: writes
        )
    }

    private func decodeLoadStoreMiscOrAtomic(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let size = A64BitUtils.extract(word, 31, 30)
        let isSIMD = A64BitUtils.flag(word, 26)
        let opc = A64BitUtils.extract(word, 23, 22)
        let bit21 = A64BitUtils.flag(word, 21)
        let op4 = A64BitUtils.extract(word, 11, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))
        let baseReg = A64Register.x(rn, allowSP: true)

        if !bit21 {
            // Unscaled (op4 == 00), Post-Index (op4 == 01), Unprivileged (op4 == 10), Pre-Index (op4 == 11)
            guard op4 != 0b10 else { return nil }
            guard let spec = resolveSingleMemTransferSpec(size: size, isSIMD: isSIMD, opc: opc, rt: rt) else {
                return nil
            }
            if spec.prefetchCode != nil && op4 != 0b00 {
                return nil
            }

            let imm9 = UInt64(A64BitUtils.extract(word, 20, 12))
            let signedOffset = signExtend(imm9, bits: 9)

            let chosenMnemonic: A64Mnemonic
            let addrMode: A64AddressingMode
            let writesBase: Bool
            switch op4 {
            case 0b00:
                chosenMnemonic = spec.unscaledMnemonic
                addrMode = .baseOffset(base: baseReg, offset: signedOffset)
                writesBase = false
            case 0b01:
                chosenMnemonic = spec.mnemonic
                addrMode = .postIndex(base: baseReg, offset: signedOffset)
                writesBase = true
            case 0b11:
                chosenMnemonic = spec.mnemonic
                addrMode = .preIndex(base: baseReg, offset: signedOffset)
                writesBase = true
            default:
                return nil
            }

            if let prfCode = spec.prefetchCode {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .prfm,
                    mnemonicText: "prfum",
                    operands: [.prefetchOp(A64PrefetchOpTable.name(forCode: prfCode)), .memory(addrMode)],
                    group: .loadStore,
                    readsRegisters: activeRegs([baseReg])
                )
            }

            guard let targetReg = spec.targetReg else { return nil }
            let reads = spec.isLoad ? activeRegs([baseReg]) : activeRegs([baseReg, targetReg])
            var writes: [A64Register] = spec.isLoad ? [targetReg] : []
            if writesBase {
                writes.append(baseReg)
            }

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: chosenMnemonic,
                operands: [.register(targetReg), .memory(addrMode)],
                group: .loadStore,
                readsRegisters: reads,
                writesRegisters: activeRegs(writes)
            )
        } else {
            // bit21 == 1: Register Offset (op4 == 10), LSE Atomics (op4 == 00), PAC Load (op4 == 01/11)
            if op4 == 0b10 {
                let option = A64BitUtils.extract(word, 15, 13)
                guard (option & 0b010) != 0 else { return nil }
                guard let spec = resolveSingleMemTransferSpec(size: size, isSIMD: isSIMD, opc: opc, rt: rt) else {
                    return nil
                }
                let rm = UInt8(A64BitUtils.extract(word, 20, 16))
                let sFlag = A64BitUtils.flag(word, 12)

                if let prfCode = spec.prefetchCode {
                    // FEAT_RPRFM carves out prfop 24..31 (bits[4:3] == 0b11) into RPRFM <rprfop>, <Xm>, [<Xn|SP>]
                    if (prfCode & 0b11000) == 0b11000 {
                        let rprfImm6 = (((option >> 2) & 1) << 5)
                            | ((option & 1) << 4)
                            | ((sFlag ? 1 : 0) << 3)
                            | (prfCode & 0x7)
                        let rprfOpText: String
                        switch rprfImm6 {
                        case 0x00: rprfOpText = "pldkeep"
                        case 0x01: rprfOpText = "pstkeep"
                        case 0x04: rprfOpText = "pldstrm"
                        case 0x05: rprfOpText = "pststrm"
                        default:   rprfOpText = String(format: "#0x%x", rprfImm6)
                        }
                        let xmReg = A64Register.x(rm, allowSP: false)
                        let baseZeroMem = A64Operand.memory(.baseOffset(base: baseReg, offset: 0))
                        return A64DecodedInstruction(
                            address: address,
                            rawWord: word,
                            mnemonic: .prfm,
                            mnemonicText: "rprfm",
                            operands: [.prefetchOp(rprfOpText), .register(xmReg), baseZeroMem],
                            group: .loadStore,
                            readsRegisters: activeRegs([baseReg, xmReg])
                        )
                    }
                }

                let shiftAmt = UInt8(sFlag ? spec.scaleShift : 0)

                let indexIs64 = (option == 0b011 || option == 0b111)
                let indexReg = A64Register.gp(rm, is64Bit: indexIs64, allowSP: false)

                let extendClause: A64ShiftExtend?
                if option == 0b011 {
                    extendClause = sFlag ? .lsl(shiftAmt) : nil
                } else {
                    extendClause = A64ShiftExtendParser.decodeExtendOption(option: option, shift: shiftAmt)
                }

                let addrMode = A64AddressingMode.registerOffset(base: baseReg, index: indexReg, extend: extendClause)

                if let prfCode = spec.prefetchCode {
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .prfm,
                        operands: [.prefetchOp(A64PrefetchOpTable.name(forCode: prfCode)), .memory(addrMode)],
                        group: .loadStore,
                        readsRegisters: activeRegs([baseReg, indexReg])
                    )
                }

                guard let targetReg = spec.targetReg else { return nil }
                let reads = spec.isLoad
                    ? activeRegs([baseReg, indexReg])
                    : activeRegs([baseReg, indexReg, targetReg])
                let writes = spec.isLoad ? activeRegs([targetReg]) : []

                // G50: Byte-width register-offset transfers (scaleShift == 0) with S == 1 print an explicit `#0`
                // on UXTW / SXTW / SXTX (`option != 0b011`; `option == 0b011` already emits `lsl #0`).
                let explicitOperandText: String?
                if sFlag && spec.scaleShift == 0 && option != 0b011, let ext = extendClause {
                    explicitOperandText = "\(targetReg.canonicalName), [\(baseReg.canonicalName), \(indexReg.canonicalName), \(ext.description) #0]"
                } else {
                    explicitOperandText = nil
                }

                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: spec.mnemonic,
                    operands: [.register(targetReg), .memory(addrMode)],
                    operandText: explicitOperandText,
                    group: .loadStore,
                    readsRegisters: reads,
                    writesRegisters: writes
                )
            }

            if op4 == 0b00 && !isSIMD {
                return decodeLSEAtomicMemoryOp(word: word, at: address)
            }

            // ARMv8.3 PAC Load (LDRAA / LDRAB): size == 11, !isSIMD, (op4 == 01 || op4 == 11)
            if size == 0b11 && !isSIMD && (op4 == 0b01 || op4 == 0b11) {
                let isKeyB = A64BitUtils.flag(word, 23)
                let sBit = A64BitUtils.bit(word, 22)
                let imm9 = UInt64(A64BitUtils.extract(word, 20, 12))
                let imm10 = (UInt64(sBit) << 9) | imm9
                let scaledOffset = signExtend(imm10, bits: 10) * 8
                let writeback = (op4 == 0b11)
                let rtReg = A64Register.x(rt, allowSP: false)
                let addrMode: A64AddressingMode = writeback
                    ? .preIndex(base: baseReg, offset: scaledOffset)
                    : .baseOffset(base: baseReg, offset: scaledOffset)
                let mnemText = isKeyB ? "ldrab" : "ldraa"
                var writes: [A64Register] = [rtReg]
                if writeback { writes.append(baseReg) }
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .ldr,
                    mnemonicText: mnemText,
                    operands: [.register(rtReg), .memory(addrMode)],
                    group: .pacPointerAuth,
                    readsRegisters: activeRegs([baseReg]),
                    writesRegisters: activeRegs(writes),
                    autoComment: "PAC authenticated pointer load (\(isKeyB ? "DA/DB" : "DA"))"
                )
            }
        }

        return nil
    }

    private func decodeLSEAtomicMemoryOp(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let size = A64BitUtils.extract(word, 31, 30)
        let isAcquire = A64BitUtils.flag(word, 23)
        let isRelease = A64BitUtils.flag(word, 22)
        let rs = UInt8(A64BitUtils.extract(word, 20, 16))
        let o3 = A64BitUtils.flag(word, 15)
        let opc = A64BitUtils.extract(word, 14, 12)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        let is64 = (size == 0b11)
        let rsReg = A64Register.gp(rs, is64Bit: is64, allowSP: false)
        let rtReg = A64Register.gp(rt, is64Bit: is64, allowSP: false)
        let baseReg = A64Register.x(rn, allowSP: true)
        let memOp = A64Operand.memory(.baseOffset(base: baseReg, offset: 0))

        let orderSuffix: String
        switch (isAcquire, isRelease) {
        case (true, true):   orderSuffix = "al"
        case (true, false):  orderSuffix = "a"
        case (false, true):  orderSuffix = "l"
        case (false, false): orderSuffix = ""
        }

        let widthSuffix: String
        switch size {
        case 0b00: widthSuffix = "b"
        case 0b01: widthSuffix = "h"
        default:   widthSuffix = ""
        }

        if o3 && opc == 0b000 {
            let swpMnemonic: A64Mnemonic
            switch (isAcquire, isRelease) {
            case (true, true):   swpMnemonic = .swpal
            case (true, false):  swpMnemonic = .swpa
            case (false, true):  swpMnemonic = .swpl
            case (false, false): swpMnemonic = .swp
            }
            let text = "swp\(orderSuffix)\(widthSuffix)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: swpMnemonic,
                mnemonicText: text,
                operands: [.register(rsReg), .register(rtReg), memOp],
                group: .atomicLSE,
                readsRegisters: activeRegs([baseReg, rsReg]),
                writesRegisters: activeRegs([rtReg]),
                autoComment: "LSE atomic swap"
            )
        }

        if o3 && opc == 0b100 && isAcquire && !isRelease && rs == 31 {
            let ldaprMnemonic: A64Mnemonic
            switch size {
            case 0b00: ldaprMnemonic = .ldarb
            case 0b01: ldaprMnemonic = .ldarh
            default:   ldaprMnemonic = .ldar
            }
            let text = "ldapr\(widthSuffix)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: ldaprMnemonic,
                mnemonicText: text,
                operands: [.register(rtReg), memOp],
                group: .atomicLSE,
                readsRegisters: activeRegs([baseReg]),
                writesRegisters: activeRegs([rtReg]),
                autoComment: "Load-acquire RCpc"
            )
        }

        if !o3 {
            let opStem: String
            let enumVal: A64Mnemonic
            switch opc {
            case 0b000:
                opStem = "add"
                switch (isAcquire, isRelease) {
                case (true, true):   enumVal = .ldaddal
                case (true, false):  enumVal = .ldadda
                case (false, true):  enumVal = .ldaddl
                case (false, false): enumVal = .ldadd
                }
            case 0b001:
                opStem = "clr"
                enumVal = .ldclr
            case 0b010:
                opStem = "eor"
                enumVal = .ldadd
            case 0b011:
                opStem = "set"
                enumVal = .ldset
            case 0b100:
                opStem = "smax"
                enumVal = .ldadd
            case 0b101:
                opStem = "smin"
                enumVal = .ldadd
            case 0b110:
                opStem = "umax"
                enumVal = .ldadd
            case 0b111:
                opStem = "umin"
                enumVal = .ldadd
            default:
                return nil
            }

            if rt == 31 && !isAcquire {
                let stOrder = isRelease ? "l" : ""
                let stText = "st\(opStem)\(stOrder)\(widthSuffix)"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: enumVal,
                    mnemonicText: stText,
                    operands: [.register(rsReg), memOp],
                    group: .atomicLSE,
                    readsRegisters: activeRegs([baseReg, rsReg]),
                    writesRegisters: [],
                    autoComment: "LSE atomic store read-modify-write"
                )
            }

            let text = "ld\(opStem)\(orderSuffix)\(widthSuffix)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: enumVal,
                mnemonicText: text,
                operands: [.register(rsReg), .register(rtReg), memOp],
                group: .atomicLSE,
                readsRegisters: activeRegs([baseReg, rsReg]),
                writesRegisters: activeRegs([rtReg]),
                autoComment: "LSE atomic read-modify-write"
            )
        }

        return nil
    }

    private func decodeLoadStoreExclusiveOrCAS(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let size = A64BitUtils.extract(word, 31, 30)
        let o2 = A64BitUtils.flag(word, 23)
        let lBit = A64BitUtils.flag(word, 22)
        let o1 = A64BitUtils.flag(word, 21)
        let rs = UInt8(A64BitUtils.extract(word, 20, 16))
        let o0 = A64BitUtils.flag(word, 15)
        let rt2 = UInt8(A64BitUtils.extract(word, 14, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        let is64 = (size == 0b11)
        let rtReg = A64Register.gp(rt, is64Bit: is64, allowSP: false)
        let baseReg = A64Register.x(rn, allowSP: true)
        let memOp = A64Operand.memory(.baseOffset(base: baseReg, offset: 0))
        let widthSuffix: String = (size == 0b00) ? "b" : ((size == 0b01) ? "h" : "")

        // 1. LSE Compare-and-Swap (CAS / CASA / CASAL / CASL + B/H): o2 == 1 && o1 == 1 && rt2 == 31
        if o2 && o1 {
            guard rt2 == 31 else { return nil }
            let rsReg = A64Register.gp(rs, is64Bit: is64, allowSP: false)
            let casMnemonic: A64Mnemonic
            let orderSuffix: String
            switch (lBit, o0) {
            case (false, false): casMnemonic = .cas;   orderSuffix = ""
            case (true, false):  casMnemonic = .casa;  orderSuffix = "a"
            case (true, true):   casMnemonic = .casal; orderSuffix = "al"
            case (false, true):  casMnemonic = .casl;  orderSuffix = "l"
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: casMnemonic,
                mnemonicText: "cas\(orderSuffix)\(widthSuffix)",
                operands: [.register(rsReg), .register(rtReg), memOp],
                group: .atomicLSE,
                readsRegisters: activeRegs([baseReg, rsReg, rtReg]),
                writesRegisters: activeRegs([rsReg]),
                autoComment: "LSE atomic compare-and-swap"
            )
        }

        // 2. Exclusive Register (LDXR, LDAXR, STXR, STLXR + B/H): !o2 && !o1 (G62: Rs/Rt2 soft-ignored per reference)
        if !o2 && !o1 {
            if lBit {
                let mnem: A64Mnemonic = o0 ? .ldaxr : .ldxr
                let prefix = o0 ? "ldaxr" : "ldxr"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
                    mnemonicText: "\(prefix)\(widthSuffix)",
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    readsRegisters: activeRegs([baseReg]),
                    writesRegisters: activeRegs([rtReg])
                )
            } else {
                let statusReg = A64Register.w(rs, allowWSP: false)
                let mnem: A64Mnemonic = o0 ? .stlxr : .stxr
                let prefix = o0 ? "stlxr" : "stxr"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
                    mnemonicText: "\(prefix)\(widthSuffix)",
                    operands: [.register(statusReg), .register(rtReg), memOp],
                    group: .loadStore,
                    readsRegisters: activeRegs([baseReg, rtReg]),
                    writesRegisters: activeRegs([statusReg])
                )
            }
        }

        // 3. LSE Compare-and-Swap Pair (CASP*, size in 0..1) & Exclusive Pair (LDXP/LDAXP/STXP/STLXP, size in 2..3): !o2 && o1
        if !o2 && o1 {
            if size <= 0b01 {
                guard rt2 == 31 && (rs & 1) == 0 && (rt & 1) == 0 else { return nil }
                let pairIs64 = (size == 0b01)
                let rsReg = A64Register.gp(rs, is64Bit: pairIs64, allowSP: false)
                let rsNextReg = A64Register.gp(rs + 1, is64Bit: pairIs64, allowSP: false)
                let rtPairReg = A64Register.gp(rt, is64Bit: pairIs64, allowSP: false)
                let rtNextReg = A64Register.gp(rt + 1, is64Bit: pairIs64, allowSP: false)
                let casMnemonic: A64Mnemonic
                let mnemText: String
                switch (lBit, o0) {
                case (false, false): casMnemonic = .cas;   mnemText = "casp"
                case (true, false):  casMnemonic = .casa;  mnemText = "caspa"
                case (true, true):   casMnemonic = .casal; mnemText = "caspal"
                case (false, true):  casMnemonic = .casl;  mnemText = "caspl"
                }
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: casMnemonic,
                    mnemonicText: mnemText,
                    operands: [.register(rsReg), .register(rsNextReg), .register(rtPairReg), .register(rtNextReg), memOp],
                    group: .atomicLSE,
                    readsRegisters: activeRegs([baseReg, rsReg, rsNextReg, rtPairReg, rtNextReg]),
                    writesRegisters: activeRegs([rsReg, rsNextReg]),
                    autoComment: "LSE atomic compare-and-swap pair"
                )
            } else {
                let pairIs64 = (size == 0b11)
                let rtPairReg = A64Register.gp(rt, is64Bit: pairIs64, allowSP: false)
                let rt2Reg = A64Register.gp(rt2, is64Bit: pairIs64, allowSP: false)
                if lBit {
                    let mnem: A64Mnemonic = o0 ? .ldaxr : .ldxr
                    let mnemText = o0 ? "ldaxp" : "ldxp"
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: mnem,
                        mnemonicText: mnemText,
                        operands: [.register(rtPairReg), .register(rt2Reg), memOp],
                        group: .loadStore,
                        readsRegisters: activeRegs([baseReg]),
                        writesRegisters: activeRegs([rtPairReg, rt2Reg])
                    )
                } else {
                    let statusReg = A64Register.w(rs, allowWSP: false)
                    let mnem: A64Mnemonic = o0 ? .stlxr : .stxr
                    let mnemText = o0 ? "stlxp" : "stxp"
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: mnem,
                        mnemonicText: mnemText,
                        operands: [.register(statusReg), .register(rtPairReg), .register(rt2Reg), memOp],
                        group: .loadStore,
                        readsRegisters: activeRegs([baseReg, rtPairReg, rt2Reg]),
                        writesRegisters: activeRegs([statusReg])
                    )
                }
            }
        }

        // 4. Load-Acquire / Store-Release & LORegion (LDAR*, STLR*, LDLAR*, STLLR*): o2 && !o1 (G62: Rs/Rt2 soft-ignored)
        if o2 && !o1 {
            if lBit {
                let mnem: A64Mnemonic
                switch size {
                case 0b00: mnem = .ldarb
                case 0b01: mnem = .ldarh
                default:   mnem = .ldar
                }
                let prefix = o0 ? "ldar" : "ldlar"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
                    mnemonicText: "\(prefix)\(widthSuffix)",
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    readsRegisters: activeRegs([baseReg]),
                    writesRegisters: activeRegs([rtReg])
                )
            } else {
                let mnem: A64Mnemonic
                switch size {
                case 0b00: mnem = .stlrb
                case 0b01: mnem = .stlrh
                default:   mnem = .stlr
                }
                let prefix = o0 ? "stlr" : "stllr"
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
                    mnemonicText: "\(prefix)\(widthSuffix)",
                    operands: [.register(rtReg), memOp],
                    group: .loadStore,
                    readsRegisters: activeRegs([baseReg, rtReg]),
                    writesRegisters: []
                )
            }
        }

        return nil
    }

    // MARK: - Class 4: Data Processing — Register (op0 = x101)

    private func decodeDataProcessingRegister(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let bit28 = A64BitUtils.flag(word, 28)
        let bit24 = A64BitUtils.flag(word, 24)

        if !bit28 {
            if !bit24 {
                return decodeLogicalShiftedRegister(word: word, at: address)
            } else {
                let isExtended = A64BitUtils.flag(word, 21)
                return isExtended
                    ? decodeAddSubExtendedRegister(word: word, at: address)
                    : decodeAddSubShiftedRegister(word: word, at: address)
            }
        } else {
            if !bit24 {
                let op2 = A64BitUtils.extract(word, 23, 21)
                switch op2 {
                case 0b000:
                    return decodeAddSubWithCarry(word: word, at: address)
                case 0b010:
                    return decodeConditionalCompare(word: word, at: address)
                case 0b100:
                    return decodeConditionalSelect(word: word, at: address)
                case 0b110:
                    return A64BitUtils.flag(word, 30)
                        ? decodeDataProcessing1Source(word: word, at: address)
                        : decodeDataProcessing2Source(word: word, at: address)
                default:
                    return nil
                }
            } else {
                return decodeDataProcessing3Source(word: word, at: address)
            }
        }
    }

    private func buildShiftedRegOperand(
        reg: A64Register,
        shiftType: UInt32,
        amount: UInt8
    ) -> A64Operand {
        if shiftType == 0b00 && amount == 0 {
            return .register(reg)
        }
        let shiftEnum: A64ShiftExtend
        switch shiftType & 0x3 {
        case 0b00: shiftEnum = .lsl(amount)
        case 0b01: shiftEnum = .lsr(amount)
        case 0b10: shiftEnum = .asr(amount)
        default:   shiftEnum = .ror(amount)
        }
        return .shiftedRegister(reg, shiftEnum)
    }

    private func decodeLogicalShiftedRegister(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let opc = A64BitUtils.extract(word, 30, 29)
        let shiftType = A64BitUtils.extract(word, 23, 22)
        let invertRm = A64BitUtils.flag(word, 21)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let imm6 = UInt8(A64BitUtils.extract(word, 15, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        if !is64 && imm6 >= 32 {
            return nil
        }

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)
        let rmOperand = buildShiftedRegOperand(reg: rmReg, shiftType: shiftType, amount: imm6)

        // Alias: MOV <Xd>, <Xm> when ORR <Xd>, XZR, <Xm>, LSL #0
        if opc == 0b01 && !invertRm && rn == 31 && shiftType == 0b00 && imm6 == 0 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .mov,
                operands: [.register(rdReg), .register(rmReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rmReg]),
                writesRegisters: activeRegs([rdReg])
            )
        }

        // Alias: MVN <Xd>, <Xm>{, shift} when ORN <Xd>, XZR, <Xm>
        if opc == 0b01 && invertRm && rn == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .mvn,
                operands: [.register(rdReg), rmOperand],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rmReg]),
                writesRegisters: activeRegs([rdReg])
            )
        }

        // Alias: TST <Xn>, <Xm>{, shift} when ANDS XZR, <Xn>, <Xm>
        if opc == 0b11 && !invertRm && rd == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .tst,
                operands: [.register(rnReg), rmOperand],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: [],
                writesFlags: true
            )
        }

        let mnemonic: A64Mnemonic
        let setsFlags = (opc == 0b11)
        switch (opc, invertRm) {
        case (0b00, false): mnemonic = .and
        case (0b00, true):  mnemonic = .bic
        case (0b01, false): mnemonic = .orr
        case (0b01, true):  mnemonic = .orn
        case (0b10, false): mnemonic = .eor
        case (0b10, true):  mnemonic = .eon
        case (0b11, false): mnemonic = .ands
        default:            mnemonic = .bics
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), rmOperand],
            group: .dataProcessingReg,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg]),
            writesFlags: setsFlags
        )
    }

    private func decodeAddSubShiftedRegister(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let isSub = A64BitUtils.flag(word, 30)
        let setsFlags = A64BitUtils.flag(word, 29)
        let shiftType = A64BitUtils.extract(word, 23, 22)
        guard shiftType <= 0b10 else { return nil } // ROR (0b11) is reserved in Add/Sub shifted

        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let imm6 = UInt8(A64BitUtils.extract(word, 15, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        if !is64 && imm6 >= 32 {
            return nil
        }

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)
        let rmOperand = buildShiftedRegOperand(reg: rmReg, shiftType: shiftType, amount: imm6)

        // Alias: CMP / CMN when S == 1 and Rd == XZR/WZR (and Rn != XZR for SUBS -> NEG/NEGS vs CMP: CMP takes precedence if Rn != 31)
        if setsFlags && rd == 31 && !(isSub && rn == 31) {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: isSub ? .cmp : .cmn,
                operands: [.register(rnReg), rmOperand],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: [],
                writesFlags: true
            )
        }

        // Alias: NEG / NEGS when SUB / SUBS with Rn == XZR/WZR
        if isSub && rn == 31 {
            if setsFlags && rd == 31 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .cmp,
                    operands: [.register(rnReg), rmOperand],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rmReg]),
                    writesRegisters: [],
                    writesFlags: true
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: setsFlags ? .negs : .neg,
                operands: [.register(rdReg), rmOperand],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rmReg]),
                writesRegisters: activeRegs([rdReg]),
                writesFlags: setsFlags
            )
        }

        let mnemonic: A64Mnemonic
        switch (isSub, setsFlags) {
        case (false, false): mnemonic = .add
        case (false, true):  mnemonic = .adds
        case (true, false):  mnemonic = .sub
        case (true, true):   mnemonic = .subs
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), rmOperand],
            group: .dataProcessingReg,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg]),
            writesFlags: setsFlags
        )
    }

    private func decodeAddSubExtendedRegister(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let is64 = A64BitUtils.flag(word, 31)
        let isSub = A64BitUtils.flag(word, 30)
        let setsFlags = A64BitUtils.flag(word, 29)
        let opt = A64BitUtils.extract(word, 23, 22)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let option = A64BitUtils.extract(word, 15, 13)
        let imm3 = UInt8(A64BitUtils.extract(word, 12, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        guard opt == 0 && imm3 <= 4 else { return nil }

        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: true)
        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: !setsFlags)
        let rmIs64 = is64 && (option == 0b011 || option == 0b111)
        let rmReg = A64Register.gp(rm, is64Bit: rmIs64, allowSP: false)

        // G49: When Rd or Rn is SP/WSP and extend matches register width (UXTW for 32-bit, UXTX for 64-bit),
        // the preferred syntax omits the modifier for imm3 == 0 and prints `lsl #imm3` for imm3 in 1...4.
        let involvesSP = rdReg.isStackPointer || rnReg.isStackPointer
        let preferredLSL = involvesSP && (is64 ? (option == 0b011) : (option == 0b010))
        let rmOp: A64Operand
        if preferredLSL {
            rmOp = (imm3 == 0) ? .register(rmReg) : .shiftedRegister(rmReg, .lsl(imm3))
        } else {
            let extEnum = A64ShiftExtendParser.decodeExtendOption(option: option, shift: imm3)
            rmOp = .shiftedRegister(rmReg, extEnum)
        }

        if setsFlags && rd == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: isSub ? .cmp : .cmn,
                operands: [.register(rnReg), rmOp],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: [],
                writesFlags: true
            )
        }

        let mnemonic: A64Mnemonic
        switch (isSub, setsFlags) {
        case (false, false): mnemonic = .add
        case (false, true):  mnemonic = .adds
        case (true, false):  mnemonic = .sub
        case (true, true):   mnemonic = .subs
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), rmOp],
            group: .dataProcessingReg,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg]),
            writesFlags: setsFlags
        )
    }

    private func decodeAddSubWithCarry(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard A64BitUtils.extract(word, 15, 10) == 0 else { return nil }
        let is64 = A64BitUtils.flag(word, 31)
        let isSub = A64BitUtils.flag(word, 30)
        let setsFlags = A64BitUtils.flag(word, 29)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)

        if isSub && rn == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: setsFlags ? .ngcs : .ngc,
                operands: [.register(rdReg), .register(rmReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rmReg]),
                writesRegisters: activeRegs([rdReg]),
                readsFlags: true,
                writesFlags: setsFlags
            )
        }

        let mnemonic: A64Mnemonic
        switch (isSub, setsFlags) {
        case (false, false): mnemonic = .adc
        case (false, true):  mnemonic = .adcs
        case (true, false):  mnemonic = .sbc
        case (true, true):   mnemonic = .sbcs
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
            group: .dataProcessingReg,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg]),
            readsFlags: true,
            writesFlags: setsFlags
        )
    }

    private func decodeConditionalCompare(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard A64BitUtils.flag(word, 29),
              A64BitUtils.bit(word, 10) == 0,
              A64BitUtils.bit(word, 4) == 0
        else {
            return nil
        }

        let is64 = A64BitUtils.flag(word, 31)
        let isSub = A64BitUtils.flag(word, 30)
        let isImm = A64BitUtils.flag(word, 11)
        let rmOrImm5 = A64BitUtils.extract(word, 20, 16)
        let cond = A64ConditionCode(nibble: A64BitUtils.extract(word, 15, 12))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let nzcv = UInt64(A64BitUtils.extract(word, 3, 0))

        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rhsOp: A64Operand
        let reads: [A64Register]
        if isImm {
            rhsOp = .unsignedImmediate(UInt64(rmOrImm5))
            reads = activeRegs([rnReg])
        } else {
            let rmReg = A64Register.gp(UInt8(rmOrImm5), is64Bit: is64, allowSP: false)
            rhsOp = .register(rmReg)
            reads = activeRegs([rnReg, rmReg])
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: isSub ? .ccmp : .ccmn,
            operands: [.register(rnReg), rhsOp, .unsignedImmediate(nzcv), .condition(cond)],
            group: .dataProcessingReg,
            readsRegisters: reads,
            writesRegisters: [],
            readsFlags: true,
            writesFlags: true
        )
    }

    private func decodeConditionalSelect(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard !A64BitUtils.flag(word, 29) else { return nil }
        let is64 = A64BitUtils.flag(word, 31)
        let op = A64BitUtils.flag(word, 30)
        let op2 = A64BitUtils.extract(word, 11, 10)
        guard op2 <= 0b01 else { return nil }

        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let cond = A64ConditionCode(nibble: A64BitUtils.extract(word, 15, 12))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)
        let canInvertCond = (cond != .al && cond != .nv)

        switch (op, op2) {
        case (false, 0b00): // CSEL
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .csel,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .condition(cond)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg]),
                readsFlags: true
            )

        case (false, 0b01): // CSINC -> CSET / CINC
            if rn == 31 && rm == 31 && canInvertCond {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .cset,
                    operands: [.register(rdReg), .condition(cond.inverted)],
                    group: .dataProcessingReg,
                    readsRegisters: [],
                    writesRegisters: activeRegs([rdReg]),
                    readsFlags: true
                )
            }
            if rn == rm && rn != 31 && canInvertCond {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .cinc,
                    operands: [.register(rdReg), .register(rnReg), .condition(cond.inverted)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg]),
                    readsFlags: true
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .csinc,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .condition(cond)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg]),
                readsFlags: true
            )

        case (true, 0b00): // CSINV -> CSETM / CINV
            if rn == 31 && rm == 31 && canInvertCond {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .csetm,
                    operands: [.register(rdReg), .condition(cond.inverted)],
                    group: .dataProcessingReg,
                    readsRegisters: [],
                    writesRegisters: activeRegs([rdReg]),
                    readsFlags: true
                )
            }
            if rn == rm && rn != 31 && canInvertCond {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .cinv,
                    operands: [.register(rdReg), .register(rnReg), .condition(cond.inverted)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg]),
                    readsFlags: true
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .csinv,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .condition(cond)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg]),
                readsFlags: true
            )

        default: // CSNEG -> CNEG
            if rn == rm && rn != 31 && canInvertCond {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .cneg,
                    operands: [.register(rdReg), .register(rnReg), .condition(cond.inverted)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg]),
                    writesRegisters: activeRegs([rdReg]),
                    readsFlags: true
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .csneg,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .condition(cond)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg]),
                readsFlags: true
            )
        }
    }

    private func decodeDataProcessing2Source(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard !A64BitUtils.flag(word, 29) else { return nil }
        let is64 = A64BitUtils.flag(word, 31)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let opcode = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
        let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
        let rmReg = A64Register.gp(rm, is64Bit: is64, allowSP: false)

        let mnemonic: A64Mnemonic
        switch opcode {
        case 0b000010: mnemonic = .udiv
        case 0b000011: mnemonic = .sdiv
        case 0b001000: mnemonic = .lsl
        case 0b001001: mnemonic = .lsr
        case 0b001010: mnemonic = .asr
        case 0b001011: mnemonic = .ror
        case 0b010000 where !is64: mnemonic = .crc32b
        case 0b010001 where !is64: mnemonic = .crc32h
        case 0b010010 where !is64: mnemonic = .crc32w
        case 0b010011 where is64:
            let wRd = A64Register.w(rd)
            let wRn = A64Register.w(rn)
            let xRm = A64Register.x(rm)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .crc32x,
                operands: [.register(wRd), .register(wRn), .register(xRm)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([wRn, xRm]),
                writesRegisters: activeRegs([wRd])
            )
        case 0b010100 where !is64: mnemonic = .crc32cb
        case 0b010101 where !is64: mnemonic = .crc32ch
        case 0b010110 where !is64: mnemonic = .crc32cw
        case 0b010111 where is64:
            let wRd = A64Register.w(rd)
            let wRn = A64Register.w(rn)
            let xRm = A64Register.x(rm)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .crc32cx,
                operands: [.register(wRd), .register(wRn), .register(xRm)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([wRn, xRm]),
                writesRegisters: activeRegs([wRd])
            )
        default:
            return nil
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: mnemonic,
            operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
            group: .dataProcessingReg,
            readsRegisters: activeRegs([rnReg, rmReg]),
            writesRegisters: activeRegs([rdReg])
        )
    }

    private func decodeDataProcessing1Source(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard !A64BitUtils.flag(word, 29) else { return nil }
        let is64 = A64BitUtils.flag(word, 31)
        let opcode2 = A64BitUtils.extract(word, 20, 16)
        let opcode = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        // Standard 1-source bit manipulation (RBIT, REV16, REV32, REV, CLZ, CLS)
        if opcode2 == 0b00000 {
            let rdReg = A64Register.gp(rd, is64Bit: is64, allowSP: false)
            let rnReg = A64Register.gp(rn, is64Bit: is64, allowSP: false)
            let mnemonic: A64Mnemonic
            switch opcode {
            case 0b000000: mnemonic = .rbit
            case 0b000001: mnemonic = .rev16
            case 0b000010: mnemonic = is64 ? .rev32 : .rev
            case 0b000011 where is64: mnemonic = .rev
            case 0b000100: mnemonic = .clz
            case 0b000101: mnemonic = .cls
            default: return nil
            }

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                operands: [.register(rdReg), .register(rnReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg]),
                writesRegisters: activeRegs([rdReg])
            )
        }

        // ARMv8.3-A Pointer Authentication 1-Source (PACI*Z*, PACD*Z*, AUTI*Z*, AUTD*Z*, XPACI, XPACD, PACIA/B, PACDA/B, AUTIA/B, AUTDA/B)
        if opcode2 == 0b00001 && is64 {
            let rdReg = A64Register.x(rd, allowSP: false)
            switch opcode {
            case 0b001000 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .paciza, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Sign code pointer with IA key + zero modifier"
                )
            case 0b001001 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .pacizb, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Sign code pointer with IB key + zero modifier"
                )
            case 0b001010 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .paciza, mnemonicText: "pacdza", operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Sign data pointer with DA key + zero modifier"
                )
            case 0b001011 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .pacizb, mnemonicText: "pacdzb", operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Sign data pointer with DB key + zero modifier"
                )
            case 0b001100 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .autiza, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Authenticate code pointer with IA key + zero modifier"
                )
            case 0b001101 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .autizb, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Authenticate code pointer with IB key + zero modifier"
                )
            case 0b001110 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .autiza, mnemonicText: "autdza", operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Authenticate data pointer with DA key + zero modifier"
                )
            case 0b001111 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .autizb, mnemonicText: "autdzb", operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Authenticate data pointer with DB key + zero modifier"
                )
            case 0b010000 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .xpaci, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Strip instruction PAC tag"
                )
            case 0b010001 where rn == 31:
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .xpacd, operands: [.register(rdReg)],
                    group: .pacPointerAuth, readsRegisters: activeRegs([rdReg]), writesRegisters: activeRegs([rdReg]),
                    autoComment: "Strip data PAC tag"
                )
            case 0b000000...0b000111:
                let modReg = A64Register.x(rn, allowSP: true)
                let names = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"]
                let fallbacks: [A64Mnemonic] = [.paciza, .pacizb, .paciza, .pacizb, .autiza, .autizb, .autiza, .autizb]
                let idx = Int(opcode)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: fallbacks[idx],
                    mnemonicText: names[idx],
                    operands: [.register(rdReg), .register(modReg)],
                    group: .pacPointerAuth,
                    readsRegisters: activeRegs([rdReg, modReg]),
                    writesRegisters: activeRegs([rdReg]),
                    autoComment: "PAC pointer operation (\(names[idx].uppercased()))"
                )
            default:
                return nil
            }
        }

        return nil
    }

    private func decodeDataProcessing3Source(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard A64BitUtils.extract(word, 30, 29) == 0 else { return nil }
        let is64 = A64BitUtils.flag(word, 31)
        let op31 = A64BitUtils.extract(word, 23, 21)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let o0 = A64BitUtils.flag(word, 15)
        let ra = UInt8(A64BitUtils.extract(word, 14, 10))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        switch op31 {
        case 0b000: // MADD, MSUB, MUL, MNEG
            let rdReg = A64Register.gp(rd, is64Bit: is64)
            let rnReg = A64Register.gp(rn, is64Bit: is64)
            let rmReg = A64Register.gp(rm, is64Bit: is64)
            let raReg = A64Register.gp(ra, is64Bit: is64)
            if ra == 31 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: o0 ? .mneg : .mul,
                    operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg, rmReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: o0 ? .msub : .madd,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .register(raReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg, raReg]),
                writesRegisters: activeRegs([rdReg])
            )

        case 0b001 where is64: // SMADDL, SMSUBL, SMULL, SMNEGL
            let rdReg = A64Register.x(rd)
            let rnReg = A64Register.w(rn)
            let rmReg = A64Register.w(rm)
            let raReg = A64Register.x(ra)
            if ra == 31 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: o0 ? .smnegl : .smull,
                    operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg, rmReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: o0 ? .smsubl : .smaddl,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .register(raReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg, raReg]),
                writesRegisters: activeRegs([rdReg])
            )

        case 0b010 where is64 && !o0: // SMULH
            let rdReg = A64Register.x(rd)
            let rnReg = A64Register.x(rn)
            let rmReg = A64Register.x(rm)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .smulh,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg])
            )

        case 0b101 where is64: // UMADDL, UMSUBL, UMULL, UMNEGL
            let rdReg = A64Register.x(rd)
            let rnReg = A64Register.w(rn)
            let rmReg = A64Register.w(rm)
            let raReg = A64Register.x(ra)
            if ra == 31 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: o0 ? .umnegl : .umull,
                    operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
                    group: .dataProcessingReg,
                    readsRegisters: activeRegs([rnReg, rmReg]),
                    writesRegisters: activeRegs([rdReg])
                )
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: o0 ? .umsubl : .umaddl,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .register(raReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg, raReg]),
                writesRegisters: activeRegs([rdReg])
            )

        case 0b110 where is64 && !o0: // UMULH
            let rdReg = A64Register.x(rd)
            let rnReg = A64Register.x(rn)
            let rmReg = A64Register.x(rm)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .umulh,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg)],
                group: .dataProcessingReg,
                readsRegisters: activeRegs([rnReg, rmReg]),
                writesRegisters: activeRegs([rdReg])
            )

        default:
            return nil
        }
    }

    // MARK: - Class 5: Scalar Floating-Point & Advanced SIMD (op0 = x111)

    private func scalarFPRegister(index: UInt8, ftype: UInt32) -> A64Register? {
        switch ftype {
        case 0b00: return .s(index)
        case 0b01: return .d(index)
        case 0b11: return .h(index)
        default:   return nil
        }
    }

    private func decodeSIMDAndFloatingPoint(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        // 1. Scalar FP 3-Source (FMADD / FMSUB / FNMADD / FNMSUB): (word & 0x5F00_0000) == 0x1F00_0000
        if (word & 0x5F00_0000) == 0x1F00_0000 {
            guard (word & 0xA000_0000) == 0 else { return nil }
            let ftype = A64BitUtils.extract(word, 23, 22)
            let o1 = A64BitUtils.flag(word, 21)
            let rm = UInt8(A64BitUtils.extract(word, 20, 16))
            let o0 = A64BitUtils.flag(word, 15)
            let ra = UInt8(A64BitUtils.extract(word, 14, 10))
            let rn = UInt8(A64BitUtils.extract(word, 9, 5))
            let rd = UInt8(A64BitUtils.extract(word, 4, 0))

            guard let rdReg = scalarFPRegister(index: rd, ftype: ftype),
                  let rnReg = scalarFPRegister(index: rn, ftype: ftype),
                  let rmReg = scalarFPRegister(index: rm, ftype: ftype),
                  let raReg = scalarFPRegister(index: ra, ftype: ftype)
            else {
                return nil
            }

            let mnemText: String? = o1 ? (o0 ? "fnmsub" : "fnmadd") : nil
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: o0 ? .fmsub : .fmadd,
                mnemonicText: mnemText,
                operands: [.register(rdReg), .register(rnReg), .register(rmReg), .register(raReg)],
                group: .simdAndFP,
                readsRegisters: [rnReg, rmReg, raReg],
                writesRegisters: [rdReg]
            )
        }

        // 2. Scalar FP Data Processing, Comparisons, Immediates & GP<->FP Conversions: (word & 0x5F20_0000) == 0x1E20_0000
        if (word & 0x5F20_0000) == 0x1E20_0000 {
            if let scalar = decodeScalarFPBlock(word: word, at: address) {
                return scalar
            }
        }

        // 2b. Scalar FP <-> Fixed-Point Conversions (C4.1.95.25): (word & 0x5F20_0000) == 0x1E00_0000
        if (word & 0x5F20_0000) == 0x1E00_0000 {
            return decodeScalarFPFixedPointConversion(word: word, at: address)
        }

        // 2c. AdvSIMD Scalar Copy (C4.1.95.4): (word & 0xDFE0_8400) == 0x5E00_0400
        if (word & 0xDFE0_8400) == 0x5E00_0400 {
            return decodeAdvSIMDScalarCopy(word: word, at: address)
        }

        // 3. AdvSIMD Scalar Three-Register Same (integer, saturating/shift, FP32/FP64, FP16, RDMA):
        //    (word & 0xDF00_0400) == 0x5E00_0400
        if (word & 0xDF00_0400) == 0x5E00_0400 {
            if let advScalar = decodeAdvSIMDScalarThreeSame(word: word, at: address) {
                return advScalar
            }
        }

        // 4. AdvSIMD Scalar Two-Register Miscellaneous (integer, zero-compare, narrowing, FP32/FP64 & FP16):
        //    C4.1.95.10: (word & 0xDF3E_0C00) == 0x5E20_0800
        //    C4.1.95.11: (word & 0xDF7E_0C00) == 0x5E78_0800
        if (word & 0xDF3E_0C00) == 0x5E20_0800 || (word & 0xDF7E_0C00) == 0x5E78_0800 {
            return decodeAdvSIMDScalarTwoRegMisc(word: word, at: address)
        }

        // 5. AdvSIMD Scalar Shift by Immediate (C4.1.95.8 / C4.1.95.9):
        //    (word & 0xDF80_0400) == 0x5F00_0400
        if (word & 0xDF80_0400) == 0x5F00_0400 {
            return decodeAdvSIMDScalarShiftByImmediate(word: word, at: address)
        }

        // 6. Common Advanced SIMD / NEON Vector Operations
        return decodeNEONVectorBlock(word: word, at: address)
    }

    private func decodeScalarFPBlock(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let sf = A64BitUtils.flag(word, 31)
        let sBit = A64BitUtils.flag(word, 29)
        guard !sBit else { return nil }

        let ftype = A64BitUtils.extract(word, 23, 22)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        // A. GP <-> FP Conversions & FMOV GP<->FP: bits[15:10] == 0b000000
        if A64BitUtils.extract(word, 15, 10) == 0b000000 {
            let rmode = A64BitUtils.extract(word, 20, 19)
            let opcode = A64BitUtils.extract(word, 18, 16)
            let gpRd = A64Register.gp(rd, is64Bit: sf)
            let gpRn = A64Register.gp(rn, is64Bit: sf)

            // High 64-bit SIMD lane <-> GP moves: ftype == 0b10, sf == 1, rmode == 0b01, opcode in {0b110, 0b111}
            if sf && ftype == 0b10 && rmode == 0b01 {
                if opcode == 0b110 {
                    let vRn = A64Register.v(rn, arrangement: "d[1]")
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .fmov,
                        operands: [.register(gpRd), .register(vRn)], group: .simdAndFP,
                        readsRegisters: [vRn], writesRegisters: activeRegs([gpRd])
                    )
                }
                if opcode == 0b111 {
                    let vRd = A64Register.v(rd, arrangement: "d[1]")
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .fmov,
                        operands: [.register(vRd), .register(gpRn)], group: .simdAndFP,
                        readsRegisters: activeRegs([vRd, gpRn]), writesRegisters: [vRd]
                    )
                }
                return nil
            }

            guard let fpRd = scalarFPRegister(index: rd, ftype: ftype),
                  let fpRn = scalarFPRegister(index: rn, ftype: ftype)
            else {
                return nil
            }
            let validFMovWidth = (!sf && ftype == 0b00) || (sf && ftype == 0b01) || (ftype == 0b11)

            switch (rmode, opcode) {
            case (0b00, 0b000): // FCVTNS <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzs, mnemonicText: "fcvtns",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b00, 0b001): // FCVTNU <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzu, mnemonicText: "fcvtnu",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b00, 0b010): // SCVTF <FPd>, <GPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .scvtf,
                    operands: [.register(fpRd), .register(gpRn)], group: .simdAndFP,
                    readsRegisters: activeRegs([gpRn]), writesRegisters: [fpRd]
                )
            case (0b00, 0b011): // UCVTF <FPd>, <GPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .ucvtf,
                    operands: [.register(fpRd), .register(gpRn)], group: .simdAndFP,
                    readsRegisters: activeRegs([gpRn]), writesRegisters: [fpRd]
                )
            case (0b00, 0b100): // FCVTAS <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtas,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b00, 0b101): // FCVTAU <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtau,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b01, 0b000): // FCVTPS <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzs, mnemonicText: "fcvtps",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b01, 0b001): // FCVTPU <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzu, mnemonicText: "fcvtpu",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b10, 0b000): // FCVTMS <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzs, mnemonicText: "fcvtms",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b10, 0b001): // FCVTMU <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzu, mnemonicText: "fcvtmu",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b11, 0b000): // FCVTZS <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzs,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b11, 0b001): // FCVTZU <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzu,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b11, 0b110) where !sf && ftype == 0b01: // FJCVTZS <Wd>, <Dn> (FEAT_JSCVT)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fcvtzs, mnemonicText: "fjcvtzs",
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd]), writesFlags: true
                )
            case (0b00, 0b110) where validFMovWidth: // FMOV <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fmov,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b00, 0b111) where validFMovWidth: // FMOV <FPd>, <GPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fmov,
                    operands: [.register(fpRd), .register(gpRn)], group: .simdAndFP,
                    readsRegisters: activeRegs([gpRn]), writesRegisters: [fpRd]
                )
            default:
                return nil
            }
        }

        guard !sf,
              let fpRd = scalarFPRegister(index: rd, ftype: ftype),
              let fpRn = scalarFPRegister(index: rn, ftype: ftype)
        else {
            return nil
        }
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))

        // B. FP Immediate (FMOV <FPd>, #imm): bits[12:10] == 0b100 && rn == 0
        if A64BitUtils.extract(word, 12, 10) == 0b100 && rn == 0 {
            let imm8 = UInt8(A64BitUtils.extract(word, 20, 13))
            let val = decodeVFPExpandImm8(imm8)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fmov,
                operands: [.register(fpRd), .fpImmediate(val)],
                group: .simdAndFP,
                readsRegisters: [],
                writesRegisters: [fpRd]
            )
        }

        // C. FP Compare (FCMP / FCMPE): bits[13:10] == 0b1000 && bits[2:0] == 0
        if A64BitUtils.extract(word, 13, 10) == 0b1000 && A64BitUtils.extract(word, 2, 0) == 0 {
            let opc = A64BitUtils.extract(word, 4, 3)
            let isSignaling = (opc & 0b10) != 0
            let compareWithZero = (opc & 0b01) != 0
            if compareWithZero {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isSignaling ? .fcmpe : .fcmp,
                    operands: [.register(fpRn), .fpImmediate(0.0)],
                    group: .simdAndFP,
                    readsRegisters: [fpRn],
                    writesRegisters: [],
                    writesFlags: true
                )
            } else if let fpRm = scalarFPRegister(index: rm, ftype: ftype) {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: isSignaling ? .fcmpe : .fcmp,
                    operands: [.register(fpRn), .register(fpRm)],
                    group: .simdAndFP,
                    readsRegisters: [fpRn, fpRm],
                    writesRegisters: [],
                    writesFlags: true
                )
            }
        }

        // D. FP 1-Source (FMOV, FABS, FNEG, FSQRT, FCVT, FRINT*): bits[14:10] == 0b10000
        if A64BitUtils.extract(word, 14, 10) == 0b10000 {
            let opcode = A64BitUtils.extract(word, 20, 15)
            switch opcode {
            case 0b000000:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fmov, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b000001:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fabs, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b000010:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fneg, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b000011:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fsqrt, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b000100 where ftype != 0b00: // FCVT to single (D->S, H->S)
                let dstS = A64Register.s(rd)
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fcvt, operands: [.register(dstS), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [dstS])
            case 0b000101 where ftype != 0b01: // FCVT to double (S->D, H->D)
                let dstD = A64Register.d(rd)
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fcvt, operands: [.register(dstD), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [dstD])
            case 0b000111 where ftype != 0b11: // FCVT to half (S->H, D->H)
                let dstH = A64Register.h(rd)
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fcvt, operands: [.register(dstH), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [dstH])
            case 0b001000:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001001:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintp, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001010:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintm, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001011:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintz, operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001100:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, mnemonicText: "frinta", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001110:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, mnemonicText: "frintx", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b001111:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, mnemonicText: "frinti", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b010000 where ftype == 0b00 || ftype == 0b01:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintz, mnemonicText: "frint32z", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b010001 where ftype == 0b00 || ftype == 0b01:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, mnemonicText: "frint32x", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b010010 where ftype == 0b00 || ftype == 0b01:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintz, mnemonicText: "frint64z", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            case 0b010011 where ftype == 0b00 || ftype == 0b01:
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .frintn, mnemonicText: "frint64x", operands: [.register(fpRd), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [fpRd])
            default:
                return nil
            }
        }

        guard let fpRm = scalarFPRegister(index: rm, ftype: ftype) else { return nil }
        let low2 = A64BitUtils.extract(word, 11, 10)

        // E. FP Conditional Compare (FCCMP): bits[11:10] == 0b01
        if low2 == 0b01 {
            let cond = A64ConditionCode(nibble: A64BitUtils.extract(word, 15, 12))
            let isSignaling = A64BitUtils.flag(word, 4)
            let nzcv = UInt64(A64BitUtils.extract(word, 3, 0))
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fccmp,
                mnemonicText: isSignaling ? "fccmpe" : "fccmp",
                operands: [.register(fpRn), .register(fpRm), .unsignedImmediate(nzcv), .condition(cond)],
                group: .simdAndFP,
                readsRegisters: [fpRn, fpRm],
                writesRegisters: [],
                readsFlags: true,
                writesFlags: true
            )
        }

        // F. FP 2-Source Arithmetic (FMUL, FDIV, FADD, FSUB, FMAX, FMIN, FMAXNM, FMINNM, FNMUL): bits[11:10] == 0b10
        if low2 == 0b10 {
            let opcode = A64BitUtils.extract(word, 15, 12)
            let mnemonic: A64Mnemonic
            switch opcode {
            case 0b0000: mnemonic = .fmul
            case 0b0001: mnemonic = .fdiv
            case 0b0010: mnemonic = .fadd
            case 0b0011: mnemonic = .fsub
            case 0b0100: mnemonic = .fmax
            case 0b0101: mnemonic = .fmin
            case 0b0110: mnemonic = .fmaxnm
            case 0b0111: mnemonic = .fminnm
            case 0b1000: mnemonic = .fnmul
            default: return nil
            }
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                operands: [.register(fpRd), .register(fpRn), .register(fpRm)],
                group: .simdAndFP,
                readsRegisters: [fpRn, fpRm],
                writesRegisters: [fpRd]
            )
        }

        // G. FP Conditional Select (FCSEL): bits[11:10] == 0b11
        if low2 == 0b11 {
            let cond = A64ConditionCode(nibble: A64BitUtils.extract(word, 15, 12))
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fcsel,
                operands: [.register(fpRd), .register(fpRn), .register(fpRm), .condition(cond)],
                group: .simdAndFP,
                readsRegisters: [fpRn, fpRm],
                writesRegisters: [fpRd],
                readsFlags: true
            )
        }

        return nil
    }

    private func decodeNEONVectorBlock(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let u = A64BitUtils.flag(word, 29)
        let size = A64BitUtils.extract(word, 23, 22)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        // 1. AdvSIMD Modified Immediate (MOVI, MVNI, ORR, BIC, FMOV): (word & 0x9FF8_0400) == 0x0F00_0400
        if (word & 0x9FF8_0400) == 0x0F00_0400 {
            return decodeAdvSIMDModifiedImmediate(word: word, at: address)
        }

        // 1b. AdvSIMD Vector Shift by Immediate (C4.1.95.19):
        //     (word & 0x9F80_0400) == 0x0F00_0400 with immh (bits[22:19]) != 0
        if (word & 0x9F80_0400) == 0x0F00_0400 {
            return decodeAdvSIMDVectorShiftByImmediate(word: word, at: address)
        }

        // 2. AdvSIMD Copy (DUP, INS, UMOV, SMOV): (word & 0x9FE0_8400) == 0x0E00_0400 (bit[15] == 0)
        if (word & 0x9FE0_0400) == 0x0E00_0400 {
            guard !A64BitUtils.flag(word, 15) else { return nil }
            let imm5 = A64BitUtils.extract(word, 20, 16)
            let imm4 = A64BitUtils.extract(word, 14, 11)
            let tz = imm5.trailingZeroBitCount
            guard tz <= 3 else { return nil }

            let elemNames = ["b", "h", "s", "d"]
            let vecArrsQ0 = ["8b", "4h", "2s", "1d"]
            let vecArrsQ1 = ["16b", "8h", "4s", "2d"]
            let elemChar = elemNames[tz]
            let vecArr = q ? vecArrsQ1[tz] : vecArrsQ0[tz]
            let laneIndex = imm5 >> (tz + 1)

            if !u && imm4 == 0b0001 { // DUP <Vd>.<T>, <R><n>
                guard q || tz < 3 else { return nil }
                let gpRn = A64Register.gp(rn, is64Bit: tz == 3)
                let vRd = A64Register.v(rd, arrangement: vecArr)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .dup,
                    operands: [.register(vRd), .register(gpRn)], group: .simdAndFP,
                    readsRegisters: activeRegs([gpRn]), writesRegisters: [vRd]
                )
            }
            if !u && imm4 == 0b0000 { // DUP <Vd>.<T>, <Vn>.<Ts>[index]
                guard q || tz < 3 else { return nil }
                let vRd = A64Register.v(rd, arrangement: vecArr)
                let vRn = A64Register.v(rn, arrangement: elemChar)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .dup,
                    operands: [.register(vRd), .register(vRn)],
                    operandText: "\(vRd.canonicalName), v\(rn).\(elemChar)[\(laneIndex)]",
                    group: .simdAndFP, readsRegisters: [vRn], writesRegisters: [vRd]
                )
            }
            if !u && imm4 == 0b0111 { // UMOV <Wd|Xd>, <Vn>.<Ts>[index] (preferred alias MOV for .s->Wd and .d->Xd)
                guard (q && tz == 3) || (!q && tz < 3) else { return nil }
                let gpRd = A64Register.gp(rd, is64Bit: q && tz == 3)
                let vRn = A64Register.v(rn, arrangement: elemChar)
                let preferredMnemonic: A64Mnemonic = ((!q && tz == 2) || (q && tz == 3)) ? .mov : .umov
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: preferredMnemonic,
                    operands: [.register(gpRd), .register(vRn)],
                    operandText: "\(gpRd.canonicalName), v\(rn).\(elemChar)[\(laneIndex)]",
                    group: .simdAndFP, readsRegisters: [vRn], writesRegisters: activeRegs([gpRd])
                )
            }
            if !u && imm4 == 0b0101 { // SMOV <Wd|Xd>, <Vn>.<Ts>[index]
                guard tz < (q ? 3 : 2) else { return nil }
                let gpRd = A64Register.gp(rd, is64Bit: q)
                let vRn = A64Register.v(rn, arrangement: elemChar)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .smov,
                    operands: [.register(gpRd), .register(vRn)],
                    operandText: "\(gpRd.canonicalName), v\(rn).\(elemChar)[\(laneIndex)]",
                    group: .simdAndFP, readsRegisters: [vRn], writesRegisters: activeRegs([gpRd])
                )
            }
            if !u && imm4 == 0b0011 { // INS <Vd>.<Ts>[index], <R><n> (preferred alias MOV when Q=1)
                guard q else { return nil }
                let gpRn = A64Register.gp(rn, is64Bit: tz == 3)
                let vRd = A64Register.v(rd, arrangement: elemChar)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .mov,
                    operands: [.register(vRd), .register(gpRn)],
                    operandText: "v\(rd).\(elemChar)[\(laneIndex)], \(gpRn.canonicalName)",
                    group: .simdAndFP, readsRegisters: activeRegs([vRd, gpRn]), writesRegisters: [vRd]
                )
            }
            if u && q { // INS <Vd>.<Ts>[index1], <Vn>.<Ts>[index2] (preferred alias MOV)
                let srcLaneIndex = imm4 >> tz
                let vRd = A64Register.v(rd, arrangement: elemChar)
                let vRn = A64Register.v(rn, arrangement: elemChar)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .mov,
                    operands: [.register(vRd), .register(vRn)],
                    operandText: "v\(rd).\(elemChar)[\(laneIndex)], v\(rn).\(elemChar)[\(srcLaneIndex)]",
                    group: .simdAndFP, readsRegisters: activeRegs([vRd, vRn]), writesRegisters: [vRd]
                )
            }
            return nil
        }

        // 3. AdvSIMD Vector Three-Register Same (integer, bitwise, FP32/FP64, FP16, FHM, RDMA, FCMA):
        //    (word & 0x9F00_0400) == 0x0E00_0400 (excluding AdvSIMD Copy above and Group 29 dot-product)
        if (word & 0x9F00_0400) == 0x0E00_0400 {
            if let decoded = decodeAdvSIMDVectorThreeSame(word: word, at: address) {
                return decoded
            }
        }

        // 4. AdvSIMD Vector Two-Register Miscellaneous (C4.1.95.20 & C4.1.95.21 FP16):
        //    (word & 0x9F3E_0C00) == 0x0E20_0800 || (word & 0x9F7E_0C00) == 0x0E78_0800
        if (word & 0x9F3E_0C00) == 0x0E20_0800 || (word & 0x9F7E_0C00) == 0x0E78_0800 {
            return decodeAdvSIMDVectorTwoRegMisc(word: word, at: address)
        }

        // 5. AdvSIMD Across Lanes (ADDV): (word & 0xBF3F_FC00) == 0x0E31_B800
        if (word & 0xBF3F_FC00) == 0x0E31_B800 {
            let dstScalar: A64Register
            let srcArr: String
            switch (size, q) {
            case (0b00, false): dstScalar = .b(rd); srcArr = "8b"
            case (0b00, true):  dstScalar = .b(rd); srcArr = "16b"
            case (0b01, false): dstScalar = .h(rd); srcArr = "4h"
            case (0b01, true):  dstScalar = .h(rd); srcArr = "8h"
            case (0b10, true):  dstScalar = .s(rd); srcArr = "4s"
            default: return nil
            }
            let vn = A64Register.v(rn, arrangement: srcArr)
            return A64DecodedInstruction(
                address: address, rawWord: word, mnemonic: .addv,
                operands: [.register(dstScalar), .register(vn)],
                group: .simdAndFP, readsRegisters: [vn], writesRegisters: [dstScalar]
            )
        }

        // 6. AdvSIMD Vector Extract (EXT, C4.1.95.12): (word & 0xBF20_8400) == 0x2E00_0000
        if (word & 0xBF20_8400) == 0x2E00_0000 {
            return decodeAdvSIMDVectorExt(word: word, at: address)
        }

        // 7. AdvSIMD Vector Permute (UZP1, TRN1, ZIP1, UZP2, TRN2, ZIP2, C4.1.95.11):
        //    (word & 0xBF20_8C00) == 0x0E00_0800
        if (word & 0xBF20_8C00) == 0x0E00_0800 {
            return decodeAdvSIMDVectorPermute(word: word, at: address)
        }

        // 8. AdvSIMD Vector Table Lookup (TBL, TBX, C4.1.95.10):
        //    (word & 0xBF20_8C00) == 0x0E00_0000
        if (word & 0xBF20_8C00) == 0x0E00_0000 {
            return decodeAdvSIMDVectorTableLookup(word: word, at: address)
        }

        return nil
    }

    private func decodeAdvSIMDVectorThreeSame(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let u = A64BitUtils.flag(word, 29)
        let size = A64BitUtils.extract(word, 23, 22)
        let bit21 = A64BitUtils.flag(word, 21)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let opcode = A64BitUtils.extract(word, 15, 11)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        func emitVec3(
            mnemonic: A64Mnemonic,
            text: String,
            arr: String,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let vd = A64Register.v(rd, arrangement: arr)
            let vn = A64Register.v(rn, arrangement: arr)
            let vm = A64Register.v(rm, arrangement: arr)
            let reads = accumulatesRd ? activeRegs([vd, vn, vm]) : activeRegs([vn, vm])
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(vd), .register(vn), .register(vm)],
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [vd]
            )
        }

        func resolveFPThreeSame(uBit: Bool, szHi: UInt32, opIdx: UInt32) -> (A64Mnemonic, String, Bool)? {
            switch (uBit, szHi, opIdx) {
            case (false, 0, 0b000): return (.fmaxnm, "fmaxnm", false)
            case (false, 0, 0b001): return (.fmul, "fmla", true)
            case (false, 0, 0b010): return (.fadd, "fadd", false)
            case (false, 0, 0b011): return (.fmul, "fmulx", false)
            case (false, 0, 0b100): return (.cmeq, "fcmeq", false)
            case (false, 0, 0b110): return (.fmax, "fmax", false)
            case (false, 0, 0b111): return (.fmul, "frecps", false)

            case (false, 1, 0b000): return (.fminnm, "fminnm", false)
            case (false, 1, 0b001): return (.fmul, "fmls", true)
            case (false, 1, 0b010): return (.fsub, "fsub", false)
            case (false, 1, 0b110): return (.fmin, "fmin", false)
            case (false, 1, 0b111): return (.fmul, "frsqrts", false)

            case (true, 0, 0b000):  return (.fmaxnm, "fmaxnmp", false)
            case (true, 0, 0b010):  return (.fadd, "faddp", false)
            case (true, 0, 0b011):  return (.fmul, "fmul", false)
            case (true, 0, 0b100):  return (.cmeq, "fcmge", false)
            case (true, 0, 0b101):  return (.cmeq, "facge", false)
            case (true, 0, 0b110):  return (.fmax, "fmaxp", false)
            case (true, 0, 0b111):  return (.fdiv, "fdiv", false)

            case (true, 1, 0b000):  return (.fminnm, "fminnmp", false)
            case (true, 1, 0b010):  return (.fsub, "fabd", false)
            case (true, 1, 0b100):  return (.cmeq, "fcmgt", false)
            case (true, 1, 0b101):  return (.cmeq, "facgt", false)
            case (true, 1, 0b110):  return (.fmin, "fminp", false)
            default:                return nil
            }
        }

        if bit21 {
            // A. Bitwise operations (always .8b / .16b): opcode == 0b00011
            if opcode == 0b00011 {
                let byteArr = q ? "16b" : "8b"
                switch (u, size) {
                case (false, 0b00):
                    return emitVec3(mnemonic: .andVec, text: "and", arr: byteArr)
                case (false, 0b01):
                    return emitVec3(mnemonic: .andVec, text: "bic", arr: byteArr)
                case (false, 0b10):
                    if rm == rn {
                        let vd = A64Register.v(rd, arrangement: byteArr)
                        let vn = A64Register.v(rn, arrangement: byteArr)
                        return A64DecodedInstruction(
                            address: address, rawWord: word, mnemonic: .mov,
                            operands: [.register(vd), .register(vn)],
                            group: .simdAndFP, readsRegisters: [vn], writesRegisters: [vd]
                        )
                    }
                    return emitVec3(mnemonic: .orrVec, text: "orr", arr: byteArr)
                case (false, 0b11):
                    return emitVec3(mnemonic: .orrVec, text: "orn", arr: byteArr)
                case (true, 0b00):
                    return emitVec3(mnemonic: .eorVec, text: "eor", arr: byteArr)
                case (true, 0b01):
                    return emitVec3(mnemonic: .orrVec, text: "bsl", arr: byteArr, accumulatesRd: true)
                case (true, 0b10):
                    return emitVec3(mnemonic: .orrVec, text: "bit", arr: byteArr, accumulatesRd: true)
                case (true, 0b11):
                    return emitVec3(mnemonic: .orrVec, text: "bif", arr: byteArr, accumulatesRd: true)
                default:
                    return nil
                }
            }

            // B. Integer three-same operations: opcode < 0b11000
            if opcode < 0b11000 {
                let intArr: String
                switch size {
                case 0b00: intArr = q ? "16b" : "8b"
                case 0b01: intArr = q ? "8h" : "4h"
                case 0b10: intArr = q ? "4s" : "2s"
                case 0b11 where q: intArr = "2d"
                default: return nil
                }

                switch opcode {
                case 0b00000 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "uhadd" : "shadd", arr: intArr)
                case 0b00001:                   return emitVec3(mnemonic: .andVec, text: u ? "uqadd" : "sqadd", arr: intArr)
                case 0b00010 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "urhadd" : "srhadd", arr: intArr)
                case 0b00100 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "uhsub" : "shsub", arr: intArr)
                case 0b00101:                   return emitVec3(mnemonic: .andVec, text: u ? "uqsub" : "sqsub", arr: intArr)
                case 0b00110:                   return emitVec3(mnemonic: .cmeq, text: u ? "cmhi" : "cmgt", arr: intArr)
                case 0b00111:                   return emitVec3(mnemonic: .cmeq, text: u ? "cmhs" : "cmge", arr: intArr)
                case 0b01000:                   return emitVec3(mnemonic: .andVec, text: u ? "ushl" : "sshl", arr: intArr)
                case 0b01001:                   return emitVec3(mnemonic: .andVec, text: u ? "uqshl" : "sqshl", arr: intArr)
                case 0b01010:                   return emitVec3(mnemonic: .andVec, text: u ? "urshl" : "srshl", arr: intArr)
                case 0b01011:                   return emitVec3(mnemonic: .andVec, text: u ? "uqrshl" : "sqrshl", arr: intArr)
                case 0b01100 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "umax" : "smax", arr: intArr)
                case 0b01101 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "umin" : "smin", arr: intArr)
                case 0b01110 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "uabd" : "sabd", arr: intArr)
                case 0b01111 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "uaba" : "saba", arr: intArr, accumulatesRd: true)
                case 0b10000:                   return emitVec3(mnemonic: .andVec, text: u ? "sub" : "add", arr: intArr)
                case 0b10001:                   return emitVec3(mnemonic: .cmeq, text: u ? "cmeq" : "cmtst", arr: intArr)
                case 0b10010 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "mls" : "mla", arr: intArr, accumulatesRd: true)
                case 0b10011 where !u && size < 0b11:
                    return emitVec3(mnemonic: .andVec, text: "mul", arr: intArr)
                case 0b10011 where u && size == 0b00:
                    return emitVec3(mnemonic: .andVec, text: "pmul", arr: intArr)
                case 0b10100 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "umaxp" : "smaxp", arr: intArr)
                case 0b10101 where size < 0b11: return emitVec3(mnemonic: .andVec, text: u ? "uminp" : "sminp", arr: intArr)
                case 0b10110 where size == 0b01 || size == 0b10:
                    return emitVec3(mnemonic: .andVec, text: u ? "sqrdmulh" : "sqdmulh", arr: intArr)
                case 0b10111 where !u:
                    return emitVec3(mnemonic: .andVec, text: "addp", arr: intArr)
                default:
                    return nil
                }
            }

            // C. FP32/FP64 three-same + FEAT_FHM (FMLAL / FMLSL / FMLAL2 / FMLSL2): opcode >= 0b11000
            let szHi = (size >> 1) & 1
            let szLo = size & 1

            if szLo == 0 && ((!u && opcode == 0b11101) || (u && opcode == 0b11001)) {
                let fhmText: String
                if !u {
                    fhmText = (szHi == 0) ? "fmlal" : "fmlsl"
                } else {
                    fhmText = (szHi == 0) ? "fmlal2" : "fmlsl2"
                }
                let vd = A64Register.v(rd, arrangement: q ? "4s" : "2s")
                let vn = A64Register.v(rn, arrangement: q ? "4h" : "2h")
                let vm = A64Register.v(rm, arrangement: q ? "4h" : "2h")
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .fmul,
                    mnemonicText: fhmText,
                    operands: [.register(vd), .register(vn), .register(vm)],
                    group: .simdAndFP,
                    readsRegisters: activeRegs([vd, vn, vm]),
                    writesRegisters: [vd]
                )
            }

            let fpArr: String
            if szLo == 0 {
                fpArr = q ? "4s" : "2s"
            } else if q {
                fpArr = "2d"
            } else {
                return nil
            }

            if let (enumVal, text, accum) = resolveFPThreeSame(uBit: u, szHi: szHi, opIdx: opcode - 0b11000) {
                return emitVec3(mnemonic: enumVal, text: text, arr: fpArr, accumulatesRd: accum)
            }
            return nil
        } else {
            // bit[21] == 0: FP16 three-same (C4.1.95.15) and RDMA / DotProd / FCMA three-register extension (C4.1.95.17)
            guard !(size == 0b00) else { return nil }

            // 1. FP16 three-same: size in {0b01, 0b11} and opcode < 0b01000
            if (size & 1) == 1 && opcode < 0b01000 {
                let szHi = (size >> 1) & 1
                if let (enumVal, text, accum) = resolveFPThreeSame(uBit: u, szHi: szHi, opIdx: opcode) {
                    return emitVec3(mnemonic: enumVal, text: text, arr: q ? "8h" : "4h", accumulatesRd: accum)
                }
                return nil
            }

            // 2. FEAT_RDM: SQRDMLAH / SQRDMLSH (U=1, size in {0b01, 0b10}, opcode in {0b10000, 0b10001})
            if u && (size == 0b01 || size == 0b10) && (opcode == 0b10000 || opcode == 0b10001) {
                let rdmArr = (size == 0b01) ? (q ? "8h" : "4h") : (q ? "4s" : "2s")
                let rdmText = (opcode == 0b10000) ? "sqrdmlah" : "sqrdmlsh"
                return emitVec3(mnemonic: .andVec, text: rdmText, arr: rdmArr, accumulatesRd: true)
            }

            // 3. FEAT_DotProd: SDOT / UDOT (size == 0b10, opcode == 0b10010)
            if size == 0b10 && opcode == 0b10010 {
                let vd = A64Register.v(rd, arrangement: q ? "4s" : "2s")
                let vn = A64Register.v(rn, arrangement: q ? "16b" : "8b")
                let vm = A64Register.v(rm, arrangement: q ? "16b" : "8b")
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .andVec,
                    mnemonicText: u ? "udot" : "sdot",
                    operands: [.register(vd), .register(vn), .register(vm)],
                    group: .simdAndFP,
                    readsRegisters: activeRegs([vd, vn, vm]),
                    writesRegisters: [vd]
                )
            }

            // 4. FEAT_FCMA: FCMLA / FCADD (U=1, opcode >= 0b11000)
            if u && opcode >= 0b11000 {
                let fcArr: String
                switch (size, q) {
                case (0b01, false): fcArr = "4h"
                case (0b01, true):  fcArr = "8h"
                case (0b10, false): fcArr = "2s"
                case (0b10, true):  fcArr = "4s"
                case (0b11, true):  fcArr = "2d"
                default:            return nil
                }

                let fcText: String
                let rotDegrees: UInt64
                let accumulatesRd: Bool
                if opcode <= 0b11011 {
                    fcText = "fcmla"
                    rotDegrees = UInt64((opcode & 0b11) * 90)
                    accumulatesRd = true
                } else if opcode == 0b11100 {
                    fcText = "fcadd"
                    rotDegrees = 90
                    accumulatesRd = false
                } else if opcode == 0b11110 {
                    fcText = "fcadd"
                    rotDegrees = 270
                    accumulatesRd = false
                } else {
                    return nil
                }

                let vd = A64Register.v(rd, arrangement: fcArr)
                let vn = A64Register.v(rn, arrangement: fcArr)
                let vm = A64Register.v(rm, arrangement: fcArr)
                let reads = accumulatesRd ? activeRegs([vd, vn, vm]) : activeRegs([vn, vm])
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .fadd,
                    mnemonicText: fcText,
                    operands: [.register(vd), .register(vn), .register(vm), .unsignedImmediate(rotDegrees)],
                    operandText: "\(vd.canonicalName), \(vn.canonicalName), \(vm.canonicalName), #\(rotDegrees)",
                    group: .simdAndFP,
                    readsRegisters: reads,
                    writesRegisters: [vd]
                )
            }

            return nil
        }
    }

    private func decodeAdvSIMDScalarThreeSame(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let u = A64BitUtils.flag(word, 29)
        let size = A64BitUtils.extract(word, 23, 22)
        let bit21 = A64BitUtils.flag(word, 21)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let opcode = A64BitUtils.extract(word, 15, 11)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        func scalarSIMDReg(_ index: UInt8, sizeCode: UInt32) -> A64Register {
            switch sizeCode {
            case 0b00: return .b(index)
            case 0b01: return .h(index)
            case 0b10: return .s(index)
            default:   return .d(index)
            }
        }

        func emitScalar3(
            mnemonic: A64Mnemonic,
            text: String,
            sizeCode: UInt32,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let sd = scalarSIMDReg(rd, sizeCode: sizeCode)
            let sn = scalarSIMDReg(rn, sizeCode: sizeCode)
            let sm = scalarSIMDReg(rm, sizeCode: sizeCode)
            let reads = accumulatesRd ? activeRegs([sd, sn, sm]) : activeRegs([sn, sm])
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(sd), .register(sn), .register(sm)],
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [sd]
            )
        }

        if bit21 {
            // A. Saturating arithmetic & shifts across B / H / S / D (size = 00..11)
            switch opcode {
            case 0b00001: return emitScalar3(mnemonic: .andVec, text: u ? "uqadd" : "sqadd", sizeCode: size)
            case 0b00101: return emitScalar3(mnemonic: .andVec, text: u ? "uqsub" : "sqsub", sizeCode: size)
            case 0b01001: return emitScalar3(mnemonic: .andVec, text: u ? "uqshl" : "sqshl", sizeCode: size)
            case 0b01011: return emitScalar3(mnemonic: .andVec, text: u ? "uqrshl" : "sqrshl", sizeCode: size)

            // B. 64-bit integer scalar operations (D register only: size == 0b11)
            case 0b00110 where size == 0b11: return emitScalar3(mnemonic: .cmeq, text: u ? "cmhi" : "cmgt", sizeCode: 0b11)
            case 0b00111 where size == 0b11: return emitScalar3(mnemonic: .cmeq, text: u ? "cmhs" : "cmge", sizeCode: 0b11)
            case 0b01000 where size == 0b11: return emitScalar3(mnemonic: .andVec, text: u ? "ushl" : "sshl", sizeCode: 0b11)
            case 0b01010 where size == 0b11: return emitScalar3(mnemonic: .andVec, text: u ? "urshl" : "srshl", sizeCode: 0b11)
            case 0b10000 where size == 0b11: return emitScalar3(mnemonic: .andVec, text: u ? "sub" : "add", sizeCode: 0b11)
            case 0b10001 where size == 0b11: return emitScalar3(mnemonic: .cmeq, text: u ? "cmeq" : "cmtst", sizeCode: 0b11)

            // C. Saturating doubling multiply high (H / S only: size in {0b01, 0b10})
            case 0b10110 where size == 0b01 || size == 0b10:
                return emitScalar3(mnemonic: .andVec, text: u ? "sqrdmulh" : "sqdmulh", sizeCode: size)

            default:
                break
            }

            // D. Scalar FP32/FP64 three-same (S when size<0>==0 -> sizeCode 0b10; D when size<0>==1 -> sizeCode 0b11)
            if opcode >= 0b11000 {
                let szHi = (size >> 1) & 1
                let fpSizeCode: UInt32 = ((size & 1) == 0) ? 0b10 : 0b11
                switch (u, szHi, opcode) {
                case (false, 0, 0b11011): return emitScalar3(mnemonic: .fmul, text: "fmulx", sizeCode: fpSizeCode)
                case (false, 0, 0b11100): return emitScalar3(mnemonic: .cmeq, text: "fcmeq", sizeCode: fpSizeCode)
                case (false, 0, 0b11111): return emitScalar3(mnemonic: .fmul, text: "frecps", sizeCode: fpSizeCode)
                case (false, 1, 0b11111): return emitScalar3(mnemonic: .fmul, text: "frsqrts", sizeCode: fpSizeCode)
                case (true, 0, 0b11100):  return emitScalar3(mnemonic: .cmeq, text: "fcmge", sizeCode: fpSizeCode)
                case (true, 0, 0b11101):  return emitScalar3(mnemonic: .cmeq, text: "facge", sizeCode: fpSizeCode)
                case (true, 1, 0b11010):  return emitScalar3(mnemonic: .fsub, text: "fabd", sizeCode: fpSizeCode)
                case (true, 1, 0b11100):  return emitScalar3(mnemonic: .cmeq, text: "fcmgt", sizeCode: fpSizeCode)
                case (true, 1, 0b11101):  return emitScalar3(mnemonic: .cmeq, text: "facgt", sizeCode: fpSizeCode)
                default:                  return nil
                }
            }
            return nil
        } else {
            // bit[21] == 0: Scalar FP16 three-same (C4.1.95.5) and Scalar RDMA (C4.1.95.7; excludes Scalar Copy size==0b00)
            guard size != 0b00 else { return nil }

            if (size & 1) == 1 && opcode < 0b01000 {
                let szHi = (size >> 1) & 1
                switch (u, szHi, opcode) {
                case (false, 0, 0b011): return emitScalar3(mnemonic: .fmul, text: "fmulx", sizeCode: 0b01)
                case (false, 0, 0b100): return emitScalar3(mnemonic: .cmeq, text: "fcmeq", sizeCode: 0b01)
                case (false, 0, 0b111): return emitScalar3(mnemonic: .fmul, text: "frecps", sizeCode: 0b01)
                case (false, 1, 0b111): return emitScalar3(mnemonic: .fmul, text: "frsqrts", sizeCode: 0b01)
                case (true, 0, 0b100):  return emitScalar3(mnemonic: .cmeq, text: "fcmge", sizeCode: 0b01)
                case (true, 0, 0b101):  return emitScalar3(mnemonic: .cmeq, text: "facge", sizeCode: 0b01)
                case (true, 1, 0b010):  return emitScalar3(mnemonic: .fsub, text: "fabd", sizeCode: 0b01)
                case (true, 1, 0b100):  return emitScalar3(mnemonic: .cmeq, text: "fcmgt", sizeCode: 0b01)
                case (true, 1, 0b101):  return emitScalar3(mnemonic: .cmeq, text: "facgt", sizeCode: 0b01)
                default:                return nil
                }
            }

            if u && (size == 0b01 || size == 0b10) && (opcode == 0b10000 || opcode == 0b10001) {
                let rdmText = (opcode == 0b10000) ? "sqrdmlah" : "sqrdmlsh"
                return emitScalar3(mnemonic: .andVec, text: rdmText, sizeCode: size, accumulatesRd: true)
            }

            return nil
        }
    }

    private func decodeAdvSIMDScalarTwoRegMisc(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let u = A64BitUtils.flag(word, 29)
        let size = A64BitUtils.extract(word, 23, 22)
        let isFP16Subtable = (word & 0xDF7E_0C00) == 0x5E78_0800
        let opcode = A64BitUtils.extract(word, 16, 12)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        func scalarSIMDReg(_ index: UInt8, sizeCode: UInt32) -> A64Register {
            switch sizeCode {
            case 0b00: return .b(index)
            case 0b01: return .h(index)
            case 0b10: return .s(index)
            default:   return .d(index)
            }
        }

        func emitScalar2(
            mnemonic: A64Mnemonic,
            text: String,
            dst: A64Register,
            src: A64Register,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let reads = accumulatesRd ? activeRegs([dst, src]) : activeRegs([src])
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(dst), .register(src)],
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [dst]
            )
        }

        func resolveScalarFPMisc(fpSizeCode: UInt32, szHi: UInt32) -> A64DecodedInstruction? {
            let sd = scalarSIMDReg(rd, sizeCode: fpSizeCode)
            let sn = scalarSIMDReg(rn, sizeCode: fpSizeCode)

            if szHi == 1 {
                switch opcode {
                case 0b01100:
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .cmeq,
                        mnemonicText: u ? "fcmge" : "fcmgt",
                        operands: [.register(sd), .register(sn), .fpImmediate(0.0)],
                        group: .simdAndFP, readsRegisters: [sn], writesRegisters: [sd]
                    )
                case 0b01101:
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .cmeq,
                        mnemonicText: u ? "fcmle" : "fcmeq",
                        operands: [.register(sd), .register(sn), .fpImmediate(0.0)],
                        group: .simdAndFP, readsRegisters: [sn], writesRegisters: [sd]
                    )
                case 0b01110 where !u:
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .cmeq,
                        mnemonicText: "fcmlt",
                        operands: [.register(sd), .register(sn), .fpImmediate(0.0)],
                        group: .simdAndFP, readsRegisters: [sn], writesRegisters: [sd]
                    )
                default:
                    break
                }
            }

            switch (u, szHi, opcode) {
            case (false, 0, 0b11010): return emitScalar2(mnemonic: .fcvtas, text: "fcvtns", dst: sd, src: sn)
            case (false, 1, 0b11010): return emitScalar2(mnemonic: .fcvtas, text: "fcvtps", dst: sd, src: sn)
            case (true,  0, 0b11010): return emitScalar2(mnemonic: .fcvtau, text: "fcvtnu", dst: sd, src: sn)
            case (true,  1, 0b11010): return emitScalar2(mnemonic: .fcvtau, text: "fcvtpu", dst: sd, src: sn)

            case (false, 0, 0b11011): return emitScalar2(mnemonic: .fcvtzs, text: "fcvtms", dst: sd, src: sn)
            case (false, 1, 0b11011): return emitScalar2(mnemonic: .fcvtzs, text: "fcvtzs", dst: sd, src: sn)
            case (true,  0, 0b11011): return emitScalar2(mnemonic: .fcvtzu, text: "fcvtmu", dst: sd, src: sn)
            case (true,  1, 0b11011): return emitScalar2(mnemonic: .fcvtzu, text: "fcvtzu", dst: sd, src: sn)

            case (false, 0, 0b11100): return emitScalar2(mnemonic: .fcvtas, text: "fcvtas", dst: sd, src: sn)
            case (true,  0, 0b11100): return emitScalar2(mnemonic: .fcvtau, text: "fcvtau", dst: sd, src: sn)

            case (false, 0, 0b11101): return emitScalar2(mnemonic: .scvtf, text: "scvtf", dst: sd, src: sn)
            case (true,  0, 0b11101): return emitScalar2(mnemonic: .ucvtf, text: "ucvtf", dst: sd, src: sn)
            case (false, 1, 0b11101): return emitScalar2(mnemonic: .fabs, text: "frecpe", dst: sd, src: sn)
            case (true,  1, 0b11101): return emitScalar2(mnemonic: .fabs, text: "frsqrte", dst: sd, src: sn)

            case (false, 1, 0b11111): return emitScalar2(mnemonic: .fabs, text: "frecpx", dst: sd, src: sn)
            default:                  return nil
            }
        }

        if isFP16Subtable {
            return resolveScalarFPMisc(fpSizeCode: 0b01, szHi: (size >> 1) & 1)
        }

        // C4.1.95.10: integer saturating / zero-compare / narrowing & FP32/FP64 conversions
        switch opcode {
        case 0b00011:
            let regD = scalarSIMDReg(rd, sizeCode: size)
            let regN = scalarSIMDReg(rn, sizeCode: size)
            return emitScalar2(mnemonic: .andVec, text: u ? "usqadd" : "suqadd", dst: regD, src: regN, accumulatesRd: true)

        case 0b00111:
            let regD = scalarSIMDReg(rd, sizeCode: size)
            let regN = scalarSIMDReg(rn, sizeCode: size)
            return emitScalar2(mnemonic: .andVec, text: u ? "sqneg" : "sqabs", dst: regD, src: regN)

        case 0b01000 where size == 0b11:
            let regD = A64Register.d(rd)
            let regN = A64Register.d(rn)
            return A64DecodedInstruction(
                address: address, rawWord: word, mnemonic: .cmeq,
                mnemonicText: u ? "cmge" : "cmgt",
                operands: [.register(regD), .register(regN), .unsignedImmediate(0)],
                group: .simdAndFP, readsRegisters: [regN], writesRegisters: [regD]
            )

        case 0b01001 where size == 0b11:
            let regD = A64Register.d(rd)
            let regN = A64Register.d(rn)
            return A64DecodedInstruction(
                address: address, rawWord: word, mnemonic: .cmeq,
                mnemonicText: u ? "cmle" : "cmeq",
                operands: [.register(regD), .register(regN), .unsignedImmediate(0)],
                group: .simdAndFP, readsRegisters: [regN], writesRegisters: [regD]
            )

        case 0b01010 where size == 0b11 && !u:
            let regD = A64Register.d(rd)
            let regN = A64Register.d(rn)
            return A64DecodedInstruction(
                address: address, rawWord: word, mnemonic: .cmeq,
                mnemonicText: "cmlt",
                operands: [.register(regD), .register(regN), .unsignedImmediate(0)],
                group: .simdAndFP, readsRegisters: [regN], writesRegisters: [regD]
            )

        case 0b01011 where size == 0b11:
            return emitScalar2(mnemonic: .andVec, text: u ? "neg" : "abs", dst: .d(rd), src: .d(rn))

        case 0b10010 where u && size < 0b11:
            let dst = scalarSIMDReg(rd, sizeCode: size)
            let src = scalarSIMDReg(rn, sizeCode: size + 1)
            return emitScalar2(mnemonic: .andVec, text: "sqxtun", dst: dst, src: src)

        case 0b10100 where size < 0b11:
            let dst = scalarSIMDReg(rd, sizeCode: size)
            let src = scalarSIMDReg(rn, sizeCode: size + 1)
            return emitScalar2(mnemonic: .andVec, text: u ? "uqxtn" : "sqxtn", dst: dst, src: src)

        case 0b10110 where u && size == 0b01:
            return emitScalar2(mnemonic: .fcvt, text: "fcvtxn", dst: .s(rd), src: .d(rn))

        default:
            break
        }

        let szHi = (size >> 1) & 1
        let fpSizeCode: UInt32 = ((size & 1) == 0) ? 0b10 : 0b11
        return resolveScalarFPMisc(fpSizeCode: fpSizeCode, szHi: szHi)
    }

    private func decodeAdvSIMDVectorTwoRegMisc(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let u = A64BitUtils.flag(word, 29)
        let size = A64BitUtils.extract(word, 23, 22)
        let isFP16Subtable = (word & 0x9F7E_0C00) == 0x0E78_0800
        let opcode = A64BitUtils.extract(word, 16, 12)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        func emitVec2(
            mnemonic: A64Mnemonic,
            text: String,
            dstArr: String,
            srcArr: String,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let vd = A64Register.v(rd, arrangement: dstArr)
            let vn = A64Register.v(rn, arrangement: srcArr)
            let reads = accumulatesRd ? activeRegs([vd, vn]) : activeRegs([vn])
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(vd), .register(vn)],
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [vd]
            )
        }

        func emitVecZeroCmp(text: String, arr: String, isFP: Bool) -> A64DecodedInstruction {
            let vd = A64Register.v(rd, arrangement: arr)
            let vn = A64Register.v(rn, arrangement: arr)
            let zeroOp: A64Operand = isFP ? .fpImmediate(0.0) : .unsignedImmediate(0)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .cmeq,
                mnemonicText: text,
                operands: [.register(vd), .register(vn), zeroOp],
                group: .simdAndFP,
                readsRegisters: [vn],
                writesRegisters: [vd]
            )
        }

        func resolveCommonVectorFPMisc(arr: String, szHi: UInt32, allowFrintts: Bool) -> A64DecodedInstruction? {
            if szHi == 1 && opcode >= 0b01100 && opcode <= 0b01111 {
                switch opcode {
                case 0b01100: return emitVecZeroCmp(text: u ? "fcmge" : "fcmgt", arr: arr, isFP: true)
                case 0b01101: return emitVecZeroCmp(text: u ? "fcmle" : "fcmeq", arr: arr, isFP: true)
                case 0b01110 where !u: return emitVecZeroCmp(text: "fcmlt", arr: arr, isFP: true)
                case 0b01111: return emitVec2(mnemonic: u ? .fneg : .fabs, text: u ? "fneg" : "fabs", dstArr: arr, srcArr: arr)
                default: return nil
                }
            }

            switch (u, szHi, opcode) {
            case (false, 0, 0b11000): return emitVec2(mnemonic: .frintn, text: "frintn", dstArr: arr, srcArr: arr)
            case (false, 1, 0b11000): return emitVec2(mnemonic: .frintp, text: "frintp", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11000): return emitVec2(mnemonic: .frintn, text: "frinta", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11001): return emitVec2(mnemonic: .frintm, text: "frintm", dstArr: arr, srcArr: arr)
            case (false, 1, 0b11001): return emitVec2(mnemonic: .frintz, text: "frintz", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11001): return emitVec2(mnemonic: .frintn, text: "frintx", dstArr: arr, srcArr: arr)
            case (true,  1, 0b11001): return emitVec2(mnemonic: .frintn, text: "frinti", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11010): return emitVec2(mnemonic: .fcvtas, text: "fcvtns", dstArr: arr, srcArr: arr)
            case (false, 1, 0b11010): return emitVec2(mnemonic: .fcvtas, text: "fcvtps", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11010): return emitVec2(mnemonic: .fcvtau, text: "fcvtnu", dstArr: arr, srcArr: arr)
            case (true,  1, 0b11010): return emitVec2(mnemonic: .fcvtau, text: "fcvtpu", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11011): return emitVec2(mnemonic: .fcvtzs, text: "fcvtms", dstArr: arr, srcArr: arr)
            case (false, 1, 0b11011): return emitVec2(mnemonic: .fcvtzs, text: "fcvtzs", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11011): return emitVec2(mnemonic: .fcvtzu, text: "fcvtmu", dstArr: arr, srcArr: arr)
            case (true,  1, 0b11011): return emitVec2(mnemonic: .fcvtzu, text: "fcvtzu", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11100): return emitVec2(mnemonic: .fcvtas, text: "fcvtas", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11100): return emitVec2(mnemonic: .fcvtau, text: "fcvtau", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11101): return emitVec2(mnemonic: .scvtf, text: "scvtf", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11101): return emitVec2(mnemonic: .ucvtf, text: "ucvtf", dstArr: arr, srcArr: arr)
            case (false, 1, 0b11101): return emitVec2(mnemonic: .fabs, text: "frecpe", dstArr: arr, srcArr: arr)
            case (true,  1, 0b11101): return emitVec2(mnemonic: .fabs, text: "frsqrte", dstArr: arr, srcArr: arr)

            case (false, 0, 0b11110) where allowFrintts:
                return emitVec2(mnemonic: .frintz, text: "frint32z", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11110) where allowFrintts:
                return emitVec2(mnemonic: .frintn, text: "frint32x", dstArr: arr, srcArr: arr)
            case (false, 0, 0b11111) where allowFrintts:
                return emitVec2(mnemonic: .frintz, text: "frint64z", dstArr: arr, srcArr: arr)
            case (true,  0, 0b11111) where allowFrintts:
                return emitVec2(mnemonic: .frintn, text: "frint64x", dstArr: arr, srcArr: arr)

            case (true,  1, 0b11111): return emitVec2(mnemonic: .fsqrt, text: "fsqrt", dstArr: arr, srcArr: arr)
            default:                  return nil
            }
        }

        // 1. C4.1.95.21: FP16 two-register miscellaneous (4h / 8h)
        if isFP16Subtable {
            let hArr = q ? "8h" : "4h"
            return resolveCommonVectorFPMisc(arr: hArr, szHi: (size >> 1) & 1, allowFrintts: false)
        }

        // 2. C4.1.95.20: Integer two-register miscellaneous (opcode < 0b01100)
        if opcode < 0b01100 {
            let stdIntArr: String?
            switch (size, q) {
            case (0b00, false): stdIntArr = "8b"
            case (0b00, true):  stdIntArr = "16b"
            case (0b01, false): stdIntArr = "4h"
            case (0b01, true):  stdIntArr = "8h"
            case (0b10, false): stdIntArr = "2s"
            case (0b10, true):  stdIntArr = "4s"
            case (0b11, true):  stdIntArr = "2d"
            default:            stdIntArr = nil
            }

            switch opcode {
            case 0b00000:
                if !u && size < 0b11, let arr = stdIntArr {
                    return emitVec2(mnemonic: .andVec, text: "rev64", dstArr: arr, srcArr: arr)
                }
                if u && size < 0b10, let arr = stdIntArr {
                    return emitVec2(mnemonic: .andVec, text: "rev32", dstArr: arr, srcArr: arr)
                }
                return nil

            case 0b00001 where !u && size == 0b00:
                let bArr = q ? "16b" : "8b"
                return emitVec2(mnemonic: .andVec, text: "rev16", dstArr: bArr, srcArr: bArr)

            case 0b00010 where size < 0b11,
                 0b00110 where size < 0b11:
                let dstArrsQ0 = ["4h", "2s", "1d"]
                let dstArrsQ1 = ["8h", "4s", "2d"]
                let srcArrsQ0 = ["8b", "4h", "2s"]
                let srcArrsQ1 = ["16b", "8h", "4s"]
                let idx = Int(size)
                let dstArr = q ? dstArrsQ1[idx] : dstArrsQ0[idx]
                let srcArr = q ? srcArrsQ1[idx] : srcArrsQ0[idx]
                let isAccum = (opcode == 0b00110)
                let mnemText = isAccum ? (u ? "uadalp" : "sadalp") : (u ? "uaddlp" : "saddlp")
                return emitVec2(mnemonic: .andVec, text: mnemText, dstArr: dstArr, srcArr: srcArr, accumulatesRd: isAccum)

            case 0b00011:
                guard let arr = stdIntArr else { return nil }
                return emitVec2(mnemonic: .andVec, text: u ? "usqadd" : "suqadd", dstArr: arr, srcArr: arr, accumulatesRd: true)

            case 0b00100 where size < 0b11:
                guard let arr = stdIntArr else { return nil }
                return emitVec2(mnemonic: .andVec, text: u ? "clz" : "cls", dstArr: arr, srcArr: arr)

            case 0b00101:
                let bArr = q ? "16b" : "8b"
                if !u && size == 0b00 {
                    return emitVec2(mnemonic: .andVec, text: "cnt", dstArr: bArr, srcArr: bArr)
                }
                if u && size == 0b00 {
                    return emitVec2(mnemonic: .orrVec, text: "mvn", dstArr: bArr, srcArr: bArr)
                }
                if u && size == 0b01 {
                    return emitVec2(mnemonic: .andVec, text: "rbit", dstArr: bArr, srcArr: bArr)
                }
                return nil

            case 0b00111:
                guard let arr = stdIntArr else { return nil }
                return emitVec2(mnemonic: .andVec, text: u ? "sqneg" : "sqabs", dstArr: arr, srcArr: arr)

            case 0b01000:
                guard let arr = stdIntArr else { return nil }
                return emitVecZeroCmp(text: u ? "cmge" : "cmgt", arr: arr, isFP: false)

            case 0b01001:
                guard let arr = stdIntArr else { return nil }
                return emitVecZeroCmp(text: u ? "cmle" : "cmeq", arr: arr, isFP: false)

            case 0b01010 where !u:
                guard let arr = stdIntArr else { return nil }
                return emitVecZeroCmp(text: "cmlt", arr: arr, isFP: false)

            case 0b01011:
                guard let arr = stdIntArr else { return nil }
                return emitVec2(mnemonic: .andVec, text: u ? "neg" : "abs", dstArr: arr, srcArr: arr)

            default:
                return nil
            }
        }

        // 3. C4.1.95.20: Narrowing & widening vector operations (0b10000...0b10111)
        if opcode >= 0b10000 && opcode < 0b11000 {
            let narrowDstQ0 = ["8b", "4h", "2s"]
            let narrowDstQ1 = ["16b", "8h", "4s"]
            let narrowSrc = ["8h", "4s", "2d"]

            switch opcode {
            case 0b10010 where size < 0b11:
                let idx = Int(size)
                let text = u ? (q ? "sqxtun2" : "sqxtun") : (q ? "xtn2" : "xtn")
                return emitVec2(
                    mnemonic: .andVec,
                    text: text,
                    dstArr: q ? narrowDstQ1[idx] : narrowDstQ0[idx],
                    srcArr: narrowSrc[idx],
                    accumulatesRd: q
                )

            case 0b10011 where u && size < 0b11:
                let idx = Int(size)
                let dstArr = narrowSrc[idx]
                let srcArr = q ? narrowDstQ1[idx] : narrowDstQ0[idx]
                let shiftBits = UInt64(8 << size)
                let vd = A64Register.v(rd, arrangement: dstArr)
                let vn = A64Register.v(rn, arrangement: srcArr)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .andVec,
                    mnemonicText: q ? "shll2" : "shll",
                    operands: [.register(vd), .register(vn), .unsignedImmediate(shiftBits)],
                    operandText: "\(vd.canonicalName), \(vn.canonicalName), #\(shiftBits)",
                    group: .simdAndFP,
                    readsRegisters: [vn],
                    writesRegisters: [vd]
                )

            case 0b10100 where size < 0b11:
                let idx = Int(size)
                let text = u ? (q ? "uqxtn2" : "uqxtn") : (q ? "sqxtn2" : "sqxtn")
                return emitVec2(
                    mnemonic: .andVec,
                    text: text,
                    dstArr: q ? narrowDstQ1[idx] : narrowDstQ0[idx],
                    srcArr: narrowSrc[idx],
                    accumulatesRd: q
                )

            case 0b10110:
                if !u && size < 0b10 {
                    let dstArr = (size == 0b00) ? (q ? "8h" : "4h") : (q ? "4s" : "2s")
                    let srcArr = (size == 0b00) ? "4s" : "2d"
                    return emitVec2(mnemonic: .fcvt, text: q ? "fcvtn2" : "fcvtn", dstArr: dstArr, srcArr: srcArr, accumulatesRd: q)
                }
                if u && size == 0b01 {
                    let dstArr = q ? "4s" : "2s"
                    return emitVec2(mnemonic: .fcvt, text: q ? "fcvtxn2" : "fcvtxn", dstArr: dstArr, srcArr: "2d", accumulatesRd: q)
                }
                return nil

            case 0b10111 where !u && size < 0b10:
                let dstArr = (size == 0b00) ? "4s" : "2d"
                let srcArr = (size == 0b00) ? (q ? "8h" : "4h") : (q ? "4s" : "2s")
                return emitVec2(mnemonic: .fcvt, text: q ? "fcvtl2" : "fcvtl", dstArr: dstArr, srcArr: srcArr)

            default:
                return nil
            }
        }

        // 4. C4.1.95.20: FP32/FP64 zero-compare, FABS/FNEG, rounding, conversions, URECPE/URSQRTE, FSQRT & FRINTTS
        let szHi = (size >> 1) & 1
        let szLo = size & 1

        if opcode == 0b11100 && szHi == 1 {
            guard szLo == 0 else { return nil }
            let sArr = q ? "4s" : "2s"
            return emitVec2(mnemonic: .andVec, text: u ? "ursqrte" : "urecpe", dstArr: sArr, srcArr: sArr)
        }

        let fpArr: String
        if szLo == 0 {
            fpArr = q ? "4s" : "2s"
        } else if q {
            fpArr = "2d"
        } else {
            return nil
        }

        return resolveCommonVectorFPMisc(arr: fpArr, szHi: szHi, allowFrintts: true)
    }

    private func decodeAdvSIMDVectorShiftByImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let u = A64BitUtils.flag(word, 29)
        let immh = A64BitUtils.extract(word, 22, 19)
        guard immh != 0 else { return nil }
        let immb = A64BitUtils.extract(word, 18, 16)
        let opcode = A64BitUtils.extract(word, 15, 11)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let imm7 = (immh << 3) | immb
        let esize: UInt32
        let sizeIdx: Int
        if immh == 1 {
            esize = 8
            sizeIdx = 0
        } else if immh <= 3 {
            esize = 16
            sizeIdx = 1
        } else if immh <= 7 {
            esize = 32
            sizeIdx = 2
        } else {
            esize = 64
            sizeIdx = 3
        }

        let rightAmt = 2 * esize - imm7
        let leftAmt = imm7 - esize

        func emitVecShift(
            mnemonic: A64Mnemonic,
            text: String,
            dstArr: String,
            srcArr: String,
            immVal: UInt32,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let vd = A64Register.v(rd, arrangement: dstArr)
            let vn = A64Register.v(rn, arrangement: srcArr)
            let reads = accumulatesRd ? activeRegs([vd, vn]) : activeRegs([vn])
            let immHex = String(format: "#0x%x", immVal)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(vd), .register(vn), .unsignedImmediate(UInt64(immVal))],
                operandText: "\(vd.canonicalName), \(vn.canonicalName), \(immHex)",
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [vd]
            )
        }

        let sameArr: String?
        switch (sizeIdx, q) {
        case (0, false): sameArr = "8b"
        case (0, true):  sameArr = "16b"
        case (1, false): sameArr = "4h"
        case (1, true):  sameArr = "8h"
        case (2, false): sameArr = "2s"
        case (2, true):  sameArr = "4s"
        case (3, true):  sameArr = "2d"
        default:         sameArr = nil
        }

        switch opcode {
        // 1. Same-width integer shifts & bit inserts
        case 0b00000:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "ushr" : "sshr", dstArr: arr, srcArr: arr, immVal: rightAmt)
        case 0b00010:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "usra" : "ssra", dstArr: arr, srcArr: arr, immVal: rightAmt, accumulatesRd: true)
        case 0b00100:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "urshr" : "srshr", dstArr: arr, srcArr: arr, immVal: rightAmt)
        case 0b00110:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "ursra" : "srsra", dstArr: arr, srcArr: arr, immVal: rightAmt, accumulatesRd: true)
        case 0b01000 where u:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: "sri", dstArr: arr, srcArr: arr, immVal: rightAmt, accumulatesRd: true)
        case 0b01010:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "sli" : "shl", dstArr: arr, srcArr: arr, immVal: leftAmt, accumulatesRd: u)
        case 0b01100 where u:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: "sqshlu", dstArr: arr, srcArr: arr, immVal: leftAmt)
        case 0b01110:
            guard let arr = sameArr else { return nil }
            return emitVecShift(mnemonic: .andVec, text: u ? "uqshl" : "sqshl", dstArr: arr, srcArr: arr, immVal: leftAmt)

        // 2. Narrowing right shifts (immh in 1..7 -> sizeIdx in 0..2)
        case 0b10000, 0b10001, 0b10010, 0b10011:
            guard sizeIdx <= 2 else { return nil }
            let dstArr = (q ? ["16b", "8h", "4s"] : ["8b", "4h", "2s"])[sizeIdx]
            let srcArr = ["8h", "4s", "2d"][sizeIdx]
            let baseText: String
            switch (opcode, u) {
            case (0b10000, false): baseText = "shrn"
            case (0b10000, true):  baseText = "sqshrun"
            case (0b10001, false): baseText = "rshrn"
            case (0b10001, true):  baseText = "sqrshrun"
            case (0b10010, false): baseText = "sqshrn"
            case (0b10010, true):  baseText = "uqshrn"
            case (0b10011, false): baseText = "sqrshrn"
            default:               baseText = "uqrshrn"
            }
            return emitVecShift(
                mnemonic: .andVec,
                text: q ? "\(baseText)2" : baseText,
                dstArr: dstArr,
                srcArr: srcArr,
                immVal: rightAmt,
                accumulatesRd: q
            )

        // 3. Widening left shifts SSHLL / USHLL (immh in 1..7 -> sizeIdx in 0..2; reference keeps sshll/ushll #0x0)
        case 0b10100:
            guard sizeIdx <= 2 else { return nil }
            let dstArr = ["8h", "4s", "2d"][sizeIdx]
            let srcArr = (q ? ["16b", "8h", "4s"] : ["8b", "4h", "2s"])[sizeIdx]
            let baseText = u ? "ushll" : "sshll"
            return emitVecShift(
                mnemonic: .andVec,
                text: q ? "\(baseText)2" : baseText,
                dstArr: dstArr,
                srcArr: srcArr,
                immVal: leftAmt
            )

        // 4. Vector fixed-point <-> FP conversions (immh in 2..15 -> sizeIdx in 1..3; 4h/8h/2s/4s/2d)
        case 0b11100 where sizeIdx >= 1:
            guard let arr = sameArr else { return nil }
            return emitVecShift(
                mnemonic: u ? .ucvtf : .scvtf,
                text: u ? "ucvtf" : "scvtf",
                dstArr: arr,
                srcArr: arr,
                immVal: rightAmt
            )
        case 0b11111 where sizeIdx >= 1:
            guard let arr = sameArr else { return nil }
            return emitVecShift(
                mnemonic: u ? .fcvtzu : .fcvtzs,
                text: u ? "fcvtzu" : "fcvtzs",
                dstArr: arr,
                srcArr: arr,
                immVal: rightAmt
            )

        default:
            return nil
        }
    }

    private func decodeAdvSIMDScalarShiftByImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let u = A64BitUtils.flag(word, 29)
        let immh = A64BitUtils.extract(word, 22, 19)
        guard immh != 0 else { return nil }
        let immb = A64BitUtils.extract(word, 18, 16)
        let opcode = A64BitUtils.extract(word, 15, 11)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let imm7 = (immh << 3) | immb
        let esize: UInt32
        let sizeIdx: Int
        if immh == 1 {
            esize = 8
            sizeIdx = 0
        } else if immh <= 3 {
            esize = 16
            sizeIdx = 1
        } else if immh <= 7 {
            esize = 32
            sizeIdx = 2
        } else {
            esize = 64
            sizeIdx = 3
        }

        let rightAmt = 2 * esize - imm7
        let leftAmt = imm7 - esize

        func scalarSIMDReg(_ index: UInt8, idx: Int) -> A64Register {
            switch idx {
            case 0: return .b(index)
            case 1: return .h(index)
            case 2: return .s(index)
            default: return .d(index)
            }
        }

        func emitScalarShift(
            mnemonic: A64Mnemonic,
            text: String,
            dstIdx: Int,
            srcIdx: Int,
            immVal: UInt32,
            accumulatesRd: Bool = false
        ) -> A64DecodedInstruction {
            let sd = scalarSIMDReg(rd, idx: dstIdx)
            let sn = scalarSIMDReg(rn, idx: srcIdx)
            let reads = accumulatesRd ? activeRegs([sd, sn]) : activeRegs([sn])
            let immHex = String(format: "#0x%x", immVal)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: mnemonic,
                mnemonicText: text,
                operands: [.register(sd), .register(sn), .unsignedImmediate(UInt64(immVal))],
                operandText: "\(sd.canonicalName), \(sn.canonicalName), \(immHex)",
                group: .simdAndFP,
                readsRegisters: reads,
                writesRegisters: [sd]
            )
        }

        switch opcode {
        // 1. 64-bit D-register-only shifts & bit inserts (immh in 8..15 -> sizeIdx == 3)
        case 0b00000 where sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: u ? "ushr" : "sshr", dstIdx: 3, srcIdx: 3, immVal: rightAmt)
        case 0b00010 where sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: u ? "usra" : "ssra", dstIdx: 3, srcIdx: 3, immVal: rightAmt, accumulatesRd: true)
        case 0b00100 where sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: u ? "urshr" : "srshr", dstIdx: 3, srcIdx: 3, immVal: rightAmt)
        case 0b00110 where sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: u ? "ursra" : "srsra", dstIdx: 3, srcIdx: 3, immVal: rightAmt, accumulatesRd: true)
        case 0b01000 where u && sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: "sri", dstIdx: 3, srcIdx: 3, immVal: rightAmt, accumulatesRd: true)
        case 0b01010 where sizeIdx == 3:
            return emitScalarShift(mnemonic: .andVec, text: u ? "sli" : "shl", dstIdx: 3, srcIdx: 3, immVal: leftAmt, accumulatesRd: u)

        // 2. All-width B / H / S / D saturating left shifts (immh in 1..15 -> sizeIdx in 0..3)
        case 0b01100 where u:
            return emitScalarShift(mnemonic: .andVec, text: "sqshlu", dstIdx: sizeIdx, srcIdx: sizeIdx, immVal: leftAmt)
        case 0b01110:
            return emitScalarShift(mnemonic: .andVec, text: u ? "uqshl" : "sqshl", dstIdx: sizeIdx, srcIdx: sizeIdx, immVal: leftAmt)

        // 3. Scalar saturating shift right narrow (immh in 1..7 -> sizeIdx in 0..2: B<-H, H<-S, S<-D)
        case 0b10000 where u && sizeIdx <= 2:
            return emitScalarShift(mnemonic: .andVec, text: "sqshrun", dstIdx: sizeIdx, srcIdx: sizeIdx + 1, immVal: rightAmt)
        case 0b10001 where u && sizeIdx <= 2:
            return emitScalarShift(mnemonic: .andVec, text: "sqrshrun", dstIdx: sizeIdx, srcIdx: sizeIdx + 1, immVal: rightAmt)
        case 0b10010 where sizeIdx <= 2:
            return emitScalarShift(mnemonic: .andVec, text: u ? "uqshrn" : "sqshrn", dstIdx: sizeIdx, srcIdx: sizeIdx + 1, immVal: rightAmt)
        case 0b10011 where sizeIdx <= 2:
            return emitScalarShift(mnemonic: .andVec, text: u ? "uqrshrn" : "sqrshrn", dstIdx: sizeIdx, srcIdx: sizeIdx + 1, immVal: rightAmt)

        // 4. Scalar fixed-point <-> FP conversions (immh in 2..15 -> sizeIdx in 1..3: H / S / D)
        case 0b11100 where sizeIdx >= 1:
            return emitScalarShift(mnemonic: u ? .ucvtf : .scvtf, text: u ? "ucvtf" : "scvtf", dstIdx: sizeIdx, srcIdx: sizeIdx, immVal: rightAmt)
        case 0b11111 where sizeIdx >= 1:
            return emitScalarShift(mnemonic: u ? .fcvtzu : .fcvtzs, text: u ? "fcvtzu" : "fcvtzs", dstIdx: sizeIdx, srcIdx: sizeIdx, immVal: rightAmt)

        default:
            return nil
        }
    }

    private func decodeScalarFPFixedPointConversion(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let sf = A64BitUtils.flag(word, 31)
        let sBit = A64BitUtils.flag(word, 29)
        guard !sBit else { return nil }

        let ftype = A64BitUtils.extract(word, 23, 22)
        let rmode = A64BitUtils.extract(word, 20, 19)
        let opcode = A64BitUtils.extract(word, 18, 16)
        let scale = A64BitUtils.extract(word, 15, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        guard sf || scale >= 32,
              let fpRd = scalarFPRegister(index: rd, ftype: ftype),
              let fpRn = scalarFPRegister(index: rn, ftype: ftype)
        else {
            return nil
        }

        let gpRd = A64Register.gp(rd, is64Bit: sf)
        let gpRn = A64Register.gp(rn, is64Bit: sf)
        let fbits = 64 - scale
        let fbitsHex = String(format: "#0x%x", fbits)

        switch (rmode, opcode) {
        case (0b00, 0b010): // SCVTF <FPd>, <GPn>, #<fbits>
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .scvtf,
                operands: [.register(fpRd), .register(gpRn), .unsignedImmediate(UInt64(fbits))],
                operandText: "\(fpRd.canonicalName), \(gpRn.canonicalName), \(fbitsHex)",
                group: .simdAndFP,
                readsRegisters: activeRegs([gpRn]),
                writesRegisters: [fpRd]
            )
        case (0b00, 0b011): // UCVTF <FPd>, <GPn>, #<fbits>
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .ucvtf,
                operands: [.register(fpRd), .register(gpRn), .unsignedImmediate(UInt64(fbits))],
                operandText: "\(fpRd.canonicalName), \(gpRn.canonicalName), \(fbitsHex)",
                group: .simdAndFP,
                readsRegisters: activeRegs([gpRn]),
                writesRegisters: [fpRd]
            )
        case (0b11, 0b000): // FCVTZS <GPd>, <FPn>, #<fbits>
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fcvtzs,
                operands: [.register(gpRd), .register(fpRn), .unsignedImmediate(UInt64(fbits))],
                operandText: "\(gpRd.canonicalName), \(fpRn.canonicalName), \(fbitsHex)",
                group: .simdAndFP,
                readsRegisters: [fpRn],
                writesRegisters: activeRegs([gpRd])
            )
        case (0b11, 0b001): // FCVTZU <GPd>, <FPn>, #<fbits>
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fcvtzu,
                operands: [.register(gpRd), .register(fpRn), .unsignedImmediate(UInt64(fbits))],
                operandText: "\(gpRd.canonicalName), \(fpRn.canonicalName), \(fbitsHex)",
                group: .simdAndFP,
                readsRegisters: [fpRn],
                writesRegisters: activeRegs([gpRd])
            )
        default:
            return nil
        }
    }

    private func decodeAdvSIMDScalarCopy(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        guard !A64BitUtils.flag(word, 29),
              !A64BitUtils.flag(word, 15),
              A64BitUtils.extract(word, 14, 11) == 0b0000
        else {
            return nil
        }

        let imm5 = A64BitUtils.extract(word, 20, 16)
        let tz = imm5.trailingZeroBitCount
        guard tz <= 3 else { return nil }

        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))
        let laneIndex = imm5 >> (tz + 1)

        let dstScalar: A64Register
        let elemChar: String
        switch tz {
        case 0: dstScalar = .b(rd); elemChar = "b"
        case 1: dstScalar = .h(rd); elemChar = "h"
        case 2: dstScalar = .s(rd); elemChar = "s"
        default: dstScalar = .d(rd); elemChar = "d"
        }

        let vRn = A64Register.v(rn, arrangement: elemChar)
        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .mov,
            operands: [.register(dstScalar), .register(vRn)],
            operandText: "\(dstScalar.canonicalName), v\(rn).\(elemChar)[\(laneIndex)]",
            group: .simdAndFP,
            readsRegisters: [vRn],
            writesRegisters: [dstScalar]
        )
    }

    private func decodeAdvSIMDModifiedImmediate(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let op = A64BitUtils.flag(word, 29)
        let abc = UInt8(A64BitUtils.extract(word, 18, 16))
        let cmode = A64BitUtils.extract(word, 15, 12)
        let o2 = A64BitUtils.flag(word, 11)
        let defgh = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))
        let imm8 = (abc << 5) | defgh
        let immHex = "#0x\(String(imm8, radix: 16))"

        if o2 {
            // Only FP16 vector FMOV (cmode == 0b1111, op == 0) is allocated when o2 == 1.
            guard cmode == 0b1111, !op else { return nil }
            let dst = A64Register.v(rd, arrangement: q ? "8h" : "4h")
            let val = decodeVFPExpandImm8(imm8)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fmov,
                operands: [.register(dst), .fpImmediate(val)],
                group: .simdAndFP,
                readsRegisters: [],
                writesRegisters: [dst]
            )
        }

        switch cmode {
        case 0b0000...0b0111: // 32-bit shifted immediate (MOVI / MVNI / ORR / BIC)
            let dst = A64Register.v(rd, arrangement: q ? "4s" : "2s")
            let shift = UInt8(((cmode >> 1) & 0x3) * 8)
            let immOp: A64Operand = (shift == 0) ? .unsignedImmediate(UInt64(imm8)) : .shiftedImmediate(UInt64(imm8), shiftBits: shift)
            let opText = (shift == 0) ? "\(dst.canonicalName), \(immHex)" : "\(dst.canonicalName), \(immHex), lsl #\(shift)"
            if (cmode & 1) == 0 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .movi,
                    mnemonicText: op ? "mvni" : "movi",
                    operands: [.register(dst), immOp],
                    operandText: opText,
                    group: .simdAndFP,
                    readsRegisters: [],
                    writesRegisters: [dst]
                )
            } else {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: op ? .andVec : .orrVec,
                    mnemonicText: op ? "bic" : "orr",
                    operands: [.register(dst), immOp],
                    operandText: opText,
                    group: .simdAndFP,
                    readsRegisters: [dst],
                    writesRegisters: [dst]
                )
            }

        case 0b1000...0b1011: // 16-bit shifted immediate (MOVI / MVNI / ORR / BIC)
            let dst = A64Register.v(rd, arrangement: q ? "8h" : "4h")
            let shift = UInt8(((cmode >> 1) & 0x1) * 8)
            let immOp: A64Operand = (shift == 0) ? .unsignedImmediate(UInt64(imm8)) : .shiftedImmediate(UInt64(imm8), shiftBits: shift)
            let opText = (shift == 0) ? "\(dst.canonicalName), \(immHex)" : "\(dst.canonicalName), \(immHex), lsl #\(shift)"
            if (cmode & 1) == 0 {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .movi,
                    mnemonicText: op ? "mvni" : "movi",
                    operands: [.register(dst), immOp],
                    operandText: opText,
                    group: .simdAndFP,
                    readsRegisters: [],
                    writesRegisters: [dst]
                )
            } else {
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: op ? .andVec : .orrVec,
                    mnemonicText: op ? "bic" : "orr",
                    operands: [.register(dst), immOp],
                    operandText: opText,
                    group: .simdAndFP,
                    readsRegisters: [dst],
                    writesRegisters: [dst]
                )
            }

        case 0b1100, 0b1101: // 32-bit shifting ones (MOVI / MVNI ..., msl #8|#16)
            let dst = A64Register.v(rd, arrangement: q ? "4s" : "2s")
            let shift: UInt8 = (cmode == 0b1100) ? 8 : 16
            let opText = "\(dst.canonicalName), \(immHex), msl #\(shift)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .movi,
                mnemonicText: op ? "mvni" : "movi",
                operands: [.register(dst), .unsignedImmediate(UInt64(imm8))],
                operandText: opText,
                group: .simdAndFP,
                readsRegisters: [],
                writesRegisters: [dst]
            )

        case 0b1110: // 8-bit MOVI (op=0) or 64-bit byte-mask MOVI (op=1)
            if !op {
                let dst = A64Register.v(rd, arrangement: q ? "16b" : "8b")
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .movi,
                    operands: [.register(dst), .unsignedImmediate(UInt64(imm8))],
                    operandText: "\(dst.canonicalName), \(immHex)",
                    group: .simdAndFP,
                    readsRegisters: [],
                    writesRegisters: [dst]
                )
            } else {
                let expanded = A64BitUtils.expandSIMDByteMaskImmediate(imm8)
                let dst: A64Register = q ? .v(rd, arrangement: "2d") : .d(rd)
                let maskText: String
                if expanded == 0 {
                    maskText = "#0000000000000000"
                } else if imm8 < 0x80 {
                    maskText = String(format: "#0x%014llx", expanded)
                } else {
                    maskText = String(format: "#0x%016llx", expanded)
                }
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .movi,
                    operands: [.register(dst), .unsignedImmediate(expanded)],
                    operandText: "\(dst.canonicalName), \(maskText)",
                    group: .simdAndFP,
                    readsRegisters: [],
                    writesRegisters: [dst]
                )
            }

        case 0b1111: // FP32 (op=0) or FP64 (op=1, Q=1) vector FMOV
            let dst: A64Register
            if !op {
                dst = A64Register.v(rd, arrangement: q ? "4s" : "2s")
            } else if q {
                dst = A64Register.v(rd, arrangement: "2d")
            } else {
                return nil
            }
            let val = decodeVFPExpandImm8(imm8)
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .fmov,
                operands: [.register(dst), .fpImmediate(val)],
                group: .simdAndFP,
                readsRegisters: [],
                writesRegisters: [dst]
            )

        default:
            return nil
        }
    }

    private func decodeAdvSIMDVectorExt(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let op2 = A64BitUtils.extract(word, 23, 22)
        guard op2 == 0b00 else { return nil }

        let imm4 = A64BitUtils.extract(word, 14, 11)
        guard q || (imm4 & 0b1000) == 0 else { return nil }

        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))
        let arr = q ? "16b" : "8b"
        let vd = A64Register.v(rd, arrangement: arr)
        let vn = A64Register.v(rn, arrangement: arr)
        let vm = A64Register.v(rm, arrangement: arr)
        let immHex = String(format: "#0x%x", imm4)

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .andVec,
            mnemonicText: "ext",
            operands: [.register(vd), .register(vn), .register(vm), .unsignedImmediate(UInt64(imm4))],
            operandText: "\(vd.canonicalName), \(vn.canonicalName), \(vm.canonicalName), \(immHex)",
            group: .simdAndFP,
            readsRegisters: activeRegs([vn, vm]),
            writesRegisters: [vd]
        )
    }

    private func decodeAdvSIMDVectorPermute(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let q = A64BitUtils.flag(word, 30)
        let size = A64BitUtils.extract(word, 23, 22)
        let arr: String
        switch (size, q) {
        case (0b00, false): arr = "8b"
        case (0b00, true):  arr = "16b"
        case (0b01, false): arr = "4h"
        case (0b01, true):  arr = "8h"
        case (0b10, false): arr = "2s"
        case (0b10, true):  arr = "4s"
        case (0b11, true):  arr = "2d"
        default:            return nil // size=11 with Q=0 (.1d) is unallocated
        }

        let opcode = A64BitUtils.extract(word, 14, 12)
        let mnemText: String
        switch opcode {
        case 0b001: mnemText = "uzp1"
        case 0b010: mnemText = "trn1"
        case 0b011: mnemText = "zip1"
        case 0b101: mnemText = "uzp2"
        case 0b110: mnemText = "trn2"
        case 0b111: mnemText = "zip2"
        default:    return nil // opcode in {0b000, 0b100} is unallocated
        }

        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))
        let vd = A64Register.v(rd, arrangement: arr)
        let vn = A64Register.v(rn, arrangement: arr)
        let vm = A64Register.v(rm, arrangement: arr)

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .andVec,
            mnemonicText: mnemText,
            operands: [.register(vd), .register(vn), .register(vm)],
            group: .simdAndFP,
            readsRegisters: activeRegs([vn, vm]),
            writesRegisters: [vd]
        )
    }

    private func decodeAdvSIMDVectorTableLookup(word: UInt32, at address: VirtualAddress) -> A64DecodedInstruction? {
        let op2 = A64BitUtils.extract(word, 23, 22)
        guard op2 == 0b00 else { return nil }

        let q = A64BitUtils.flag(word, 30)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let len = Int(A64BitUtils.extract(word, 14, 13))
        let isTbx = A64BitUtils.flag(word, 12)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        let vecArr = q ? "16b" : "8b"
        let vd = A64Register.v(rd, arrangement: vecArr)
        let vm = A64Register.v(rm, arrangement: vecArr)
        let tableRegs = (0...len).map { offset in
            A64Register.v((rn &+ UInt8(offset)) & 31, arrangement: "16b")
        }
        let tableText = tableRegs.map(\.canonicalName).joined(separator: ", ")
        let operands = [.register(vd)] + tableRegs.map(A64Operand.register) + [.register(vm)]
        let reads = isTbx ? activeRegs([vd] + tableRegs + [vm]) : activeRegs(tableRegs + [vm])

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .andVec,
            mnemonicText: isTbx ? "tbx" : "tbl",
            operands: operands,
            operandText: "\(vd.canonicalName), { \(tableText) }, \(vm.canonicalName)",
            group: .simdAndFP,
            readsRegisters: reads,
            writesRegisters: [vd]
        )
    }
}
