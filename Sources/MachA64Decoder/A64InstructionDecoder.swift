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
        if (op0 & 0b1110) == 0b1000 {
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

        // Alias: MOV <Xd|SP>, #<imm> when ORR with Rn == XZR/WZR
        if opc == 0b01 && rn == 31 {
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .mov,
                operands: [.register(rdReg), .unsignedImmediate(wmask)],
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
                operands: [.register(rdReg), immOp],
                group: .dataProcessingImm,
                flow: .sequential,
                readsRegisters: [],
                writesRegisters: activeRegs([rdReg]),
                autoComment: comment
            )

        case 0b10: // MOVZ
            let synthesized = imm16 << Int(shiftBits)
            let comment: String? = (shiftBits > 0 || imm16 >= 16)
                ? String(format: "mov %@, #0x%llx", rdReg.canonicalName, synthesized)
                : nil
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .movz,
                operands: [.register(rdReg), immOp],
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

        case 0b01: // BFM -> BFI, BFXIL (reads both Rd and Rn)
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

        // 4. Conditional Branch Immediate (B.<cond> / BC.<cond>): bits[31:24] == 0b01010100
        if (word & 0xFF00_0000) == 0x5400_0000 {
            let isConsistentHint = A64BitUtils.flag(word, 4)
            let imm19 = UInt64(A64BitUtils.extract(word, 23, 5))
            let cond = A64ConditionCode(nibble: word & 0xF)
            let byteOffset = signExtend(imm19, bits: 19) * 4
            let target = address.adding(byteOffset)
            let prefix = isConsistentHint ? "bc" : "b"
            let flow: A64FlowSemantics = (cond == .al || cond == .nv)
                ? .unconditionalJump(target: target)
                : .conditionalBranch(target: target, condition: cond)

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .bCond,
                mnemonicText: "\(prefix).\(cond.mnemonicSuffix)",
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

        // Memory Barriers (CLREX, DSB, DMB, ISB)
        if !isRead && op0 == 0 && op1 == 0b011 && crn == 0b0011 && rt == 31 {
            switch op2 {
            case 0b010:
                let ops: [A64Operand] = (crm == 15) ? [] : [.unsignedImmediate(UInt64(crm))]
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .clrex, operands: ops, group: .branchAndSystem)
            case 0b100:
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
                let ops: [A64Operand] = (crm == 15) ? [] : [.barrierOption(A64BarrierOptionTable.name(forCRm: crm))]
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .isb,
                    operands: ops,
                    group: .branchAndSystem,
                    autoComment: "Instruction Synchronization Barrier"
                )
            default:
                break
            }
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
            let alias = A64SystemOpHelpers.sysMaintenanceAlias(op1: op1, crn: crn, crm: crm, op2: op2)
            let opStr = rt == 31
                ? "#\(op1), c\(crn), c\(crm), #\(op2)"
                : "#\(op1), c\(crn), c\(crm), #\(op2), \(xtReg.canonicalName)"
            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .sys,
                mnemonicText: isRead ? "sysl" : "sys",
                operands: rt == 31
                    ? [.unsignedImmediate(UInt64(op1)), .unsignedImmediate(UInt64(crn)), .unsignedImmediate(UInt64(crm)), .unsignedImmediate(UInt64(op2))]
                    : [.unsignedImmediate(UInt64(op1)), .unsignedImmediate(UInt64(crn)), .unsignedImmediate(UInt64(crm)), .unsignedImmediate(UInt64(op2)), .register(xtReg)],
                operandText: opStr,
                group: .branchAndSystem,
                readsRegisters: isRead ? [] : activeRegs([xtReg]),
                writesRegisters: isRead ? activeRegs([xtReg]) : [],
                autoComment: alias
            )
        }

        // MSR (register) / MRS: op0 in 2...3
        if op0 >= 2 {
            let sysEnc = UInt16((word >> 5) & 0xFFFF)
            let sysName = A64SystemRegisterTable.name(forEncoding: sysEnc)
            let sysSummary = A64SystemRegisterTable.lookup(encoding: sysEnc)?.summary
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
                guard let spec = resolveSingleMemTransferSpec(size: size, isSIMD: isSIMD, opc: opc, rt: rt) else {
                    return nil
                }
                let rm = UInt8(A64BitUtils.extract(word, 20, 16))
                let option = A64BitUtils.extract(word, 15, 13)
                let sFlag = A64BitUtils.flag(word, 12)
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

                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: spec.mnemonic,
                    operands: [.register(targetReg), .memory(addrMode)],
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
        switch (isAcquire && rt != 31, isRelease) {
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
            let rawOrder = (isAcquire && isRelease) ? "al" : (isAcquire ? "a" : (isRelease ? "l" : ""))
            let text = "swp\(rawOrder)\(widthSuffix)"
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

        if !o3 {
            let baseOpText: String
            let enumVal: A64Mnemonic
            switch opc {
            case 0b000:
                baseOpText = "ldadd"
                switch (isAcquire && rt != 31, isRelease) {
                case (true, true):   enumVal = .ldaddal
                case (true, false):  enumVal = .ldadda
                case (false, true):  enumVal = .ldaddl
                case (false, false): enumVal = .ldadd
                }
            case 0b001:
                baseOpText = "ldclr"
                enumVal = .ldclr
            case 0b010:
                baseOpText = "ldeor"
                enumVal = .ldadd
            case 0b011:
                baseOpText = "ldset"
                enumVal = .ldset
            default:
                return nil
            }

            let text = "\(baseOpText)\(orderSuffix)\(widthSuffix)"
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

        // 1. LSE Compare-and-Swap (CAS / CASA / CASAL / CASL): o2 == 1 && o1 == 1 && rt2 == 31
        if o2 && o1 && rt2 == 31 {
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

        // 2. Exclusive Register (LDXR, LDAXR, STXR, STLXR): !o2 && !o1 && rt2 == 31
        if !o2 && !o1 && rt2 == 31 {
            if lBit {
                guard rs == 31 else { return nil }
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

        // 3. Load-Acquire / Store-Release (LDAR, LDARB, LDARH, STLR, STLRB, STLRH): o2 && !o1 && o0 && rs == 31 && rt2 == 31
        if o2 && !o1 && o0 && rs == 31 && rt2 == 31 {
            if lBit {
                let mnem: A64Mnemonic
                switch size {
                case 0b00: mnem = .ldarb
                case 0b01: mnem = .ldarh
                default:   mnem = .ldar
                }
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
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
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: mnem,
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

        let extEnum = A64ShiftExtendParser.decodeExtendOption(option: option, shift: imm3)
        let rmOp = A64Operand.shiftedRegister(rmReg, extEnum)

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

        // ARMv8.3-A Pointer Authentication 1-Source (PACIZA, PACIZB, AUTIZA, AUTIZB, XPACI, XPACD, PACIA/B, AUTIA/B)
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
        // 1. Scalar FP 3-Source (FMADD / FMSUB): bits[31:24] == 0b00011111
        if (word & 0xFF20_0000) == 0x1F00_0000 {
            let ftype = A64BitUtils.extract(word, 23, 22)
            let o1 = A64BitUtils.flag(word, 21)
            let rm = UInt8(A64BitUtils.extract(word, 20, 16))
            let o0 = A64BitUtils.flag(word, 15)
            let ra = UInt8(A64BitUtils.extract(word, 14, 10))
            let rn = UInt8(A64BitUtils.extract(word, 9, 5))
            let rd = UInt8(A64BitUtils.extract(word, 4, 0))

            guard !o1,
                  let rdReg = scalarFPRegister(index: rd, ftype: ftype),
                  let rnReg = scalarFPRegister(index: rn, ftype: ftype),
                  let rmReg = scalarFPRegister(index: rm, ftype: ftype),
                  let raReg = scalarFPRegister(index: ra, ftype: ftype)
            else {
                return nil
            }

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: o0 ? .fmsub : .fmadd,
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

        // 3. Common Advanced SIMD / NEON Vector Operations
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
            guard let fpRd = scalarFPRegister(index: rd, ftype: ftype),
                  let fpRn = scalarFPRegister(index: rn, ftype: ftype)
            else {
                return nil
            }
            let gpRd = A64Register.gp(rd, is64Bit: sf)
            let gpRn = A64Register.gp(rn, is64Bit: sf)

            switch (rmode, opcode) {
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
            case (0b00, 0b110): // FMOV <GPd>, <FPn>
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .fmov,
                    operands: [.register(gpRd), .register(fpRn)], group: .simdAndFP,
                    readsRegisters: [fpRn], writesRegisters: activeRegs([gpRd])
                )
            case (0b00, 0b111): // FMOV <FPd>, <GPn>
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
            case 0b000100: // FCVT to single
                let dstS = A64Register.s(rd)
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fcvt, operands: [.register(dstS), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [dstS])
            case 0b000101: // FCVT to double
                let dstD = A64Register.d(rd)
                return A64DecodedInstruction(address: address, rawWord: word, mnemonic: .fcvt, operands: [.register(dstD), .register(fpRn)], group: .simdAndFP, readsRegisters: [fpRn], writesRegisters: [dstD])
            case 0b000111: // FCVT to half
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
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rd = UInt8(A64BitUtils.extract(word, 4, 0))

        // 1. AdvSIMD Modified Immediate (MOVI): (word & 0x9FF8_0400) == 0x0F00_0400
        if (word & 0x9FF8_0400) == 0x0F00_0400 {
            let abc = UInt8(A64BitUtils.extract(word, 18, 16))
            let cmode = A64BitUtils.extract(word, 15, 12)
            let o2 = A64BitUtils.bit(word, 11)
            let defgh = UInt8(A64BitUtils.extract(word, 9, 5))
            let imm8 = (abc << 5) | defgh

            if cmode == 0b1110 && o2 == 0 {
                if u {
                    let expanded = A64BitUtils.expandSIMDByteMaskImmediate(imm8)
                    let dst: A64Register = q ? .v(rd, arrangement: "2d") : .d(rd)
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .movi,
                        operands: [.register(dst), .unsignedImmediate(expanded)],
                        group: .simdAndFP,
                        writesRegisters: [dst]
                    )
                } else {
                    let arr = q ? "16b" : "8b"
                    let dst = A64Register.v(rd, arrangement: arr)
                    return A64DecodedInstruction(
                        address: address,
                        rawWord: word,
                        mnemonic: .movi,
                        operands: [.register(dst), .unsignedImmediate(UInt64(imm8))],
                        group: .simdAndFP,
                        writesRegisters: [dst]
                    )
                }
            }
            if (cmode & 0b1001) == 0b0000 && !u && o2 == 0 {
                let shift = UInt8(((cmode >> 1) & 0x3) * 8)
                let dst = A64Register.v(rd, arrangement: q ? "4s" : "2s")
                let immOp: A64Operand = (shift == 0) ? .unsignedImmediate(UInt64(imm8)) : .shiftedImmediate(UInt64(imm8), shiftBits: shift)
                return A64DecodedInstruction(
                    address: address,
                    rawWord: word,
                    mnemonic: .movi,
                    operands: [.register(dst), immOp],
                    group: .simdAndFP,
                    writesRegisters: [dst]
                )
            }
        }

        // 2. AdvSIMD Copy (DUP, INS, UMOV, SMOV): (word & 0x9FE0_0400) == 0x0E00_0400
        if (word & 0x9FE0_0400) == 0x0E00_0400 {
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
                let gpRn = A64Register.gp(rn, is64Bit: tz == 3)
                let vRd = A64Register.v(rd, arrangement: vecArr)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .dup,
                    operands: [.register(vRd), .register(gpRn)], group: .simdAndFP,
                    readsRegisters: activeRegs([gpRn]), writesRegisters: [vRd]
                )
            }
            if !u && imm4 == 0b0000 { // DUP <Vd>.<T>, <Vn>.<Ts>[index]
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
        }

        // 3. AdvSIMD Three-Same Logical & CMEQ: (word & 0x9F20_0400) == 0x0E20_0400
        if (word & 0x9F20_0400) == 0x0E20_0400 {
            let opcode = A64BitUtils.extract(word, 15, 11)
            let byteArr = q ? "16b" : "8b"

            if opcode == 0b00011 {
                if !u && size == 0b00 { // AND.16B / AND.8B
                    let vd = A64Register.v(rd, arrangement: byteArr)
                    let vn = A64Register.v(rn, arrangement: byteArr)
                    let vm = A64Register.v(rm, arrangement: byteArr)
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .andVec, mnemonicText: "and",
                        operands: [.register(vd), .register(vn), .register(vm)],
                        group: .simdAndFP, readsRegisters: [vn, vm], writesRegisters: [vd]
                    )
                }
                if !u && size == 0b10 { // ORR.16B / ORR.8B (preferred alias MOV when Rm == Rn)
                    let vd = A64Register.v(rd, arrangement: byteArr)
                    let vn = A64Register.v(rn, arrangement: byteArr)
                    if rm == rn {
                        return A64DecodedInstruction(
                            address: address, rawWord: word, mnemonic: .mov,
                            operands: [.register(vd), .register(vn)],
                            group: .simdAndFP, readsRegisters: [vn], writesRegisters: [vd]
                        )
                    }
                    let vm = A64Register.v(rm, arrangement: byteArr)
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .orrVec, mnemonicText: "orr",
                        operands: [.register(vd), .register(vn), .register(vm)],
                        group: .simdAndFP, readsRegisters: [vn, vm], writesRegisters: [vd]
                    )
                }
                if u && size == 0b00 { // EOR.16B / EOR.8B
                    let vd = A64Register.v(rd, arrangement: byteArr)
                    let vn = A64Register.v(rn, arrangement: byteArr)
                    let vm = A64Register.v(rm, arrangement: byteArr)
                    return A64DecodedInstruction(
                        address: address, rawWord: word, mnemonic: .eorVec, mnemonicText: "eor",
                        operands: [.register(vd), .register(vn), .register(vm)],
                        group: .simdAndFP, readsRegisters: [vn, vm], writesRegisters: [vd]
                    )
                }
            }

            if u && opcode == 0b10001 { // CMEQ <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
                guard !(size == 0b11 && !q) else { return nil }
                let arrTableQ0 = ["8b", "4h", "2s", "1d"]
                let arrTableQ1 = ["16b", "8h", "4s", "2d"]
                let arr = q ? arrTableQ1[Int(size)] : arrTableQ0[Int(size)]
                let vd = A64Register.v(rd, arrangement: arr)
                let vn = A64Register.v(rn, arrangement: arr)
                let vm = A64Register.v(rm, arrangement: arr)
                return A64DecodedInstruction(
                    address: address, rawWord: word, mnemonic: .cmeq,
                    operands: [.register(vd), .register(vn), .register(vm)],
                    group: .simdAndFP, readsRegisters: [vn, vm], writesRegisters: [vd]
                )
            }
        }

        // 4. AdvSIMD CMEQ #0 (Two-Reg Misc): (word & 0xBF3F_FC00) == 0x0E20_9800
        if (word & 0xBF3F_FC00) == 0x0E20_9800 {
            guard !(size == 0b11 && !q) else { return nil }
            let arrTableQ0 = ["8b", "4h", "2s", "1d"]
            let arrTableQ1 = ["16b", "8h", "4s", "2d"]
            let arr = q ? arrTableQ1[Int(size)] : arrTableQ0[Int(size)]
            let vd = A64Register.v(rd, arrangement: arr)
            let vn = A64Register.v(rn, arrangement: arr)
            return A64DecodedInstruction(
                address: address, rawWord: word, mnemonic: .cmeq,
                operands: [.register(vd), .register(vn), .unsignedImmediate(0)],
                group: .simdAndFP, readsRegisters: [vn], writesRegisters: [vd]
            )
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

        return nil
    }
}
