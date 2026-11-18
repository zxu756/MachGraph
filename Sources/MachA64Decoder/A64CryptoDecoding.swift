import Foundation
import MachGraphModels

// MARK: - Cryptographic Extension Instruction Decoding (ARM DDI 0487 C4.1.95.1–C4.1.95.4)

extension A64InstructionDecoder {
    /// Decodes ARMv8-A / Apple Silicon cryptographic instructions before general SIMD/FP dispatch.
    ///
    /// Each claimed cryptographic encoding class returns either the decoded instruction or an explicit
    /// `.inst` (`A64Mnemonic.unknown`) record so unallocated encodings in these classes never fall
    /// through into subsequent SIMD/FP decoders.
    func decodeCryptographic(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction? {
        // Group 17: Cryptographic AES (ARM DDI 0487 C4.1.95.1): (word & 0xFF3E_0C00) == 0x4E28_0800
        if (word & 0xFF3E_0C00) == 0x4E28_0800 {
            return decodeCryptographicAES(word: word, at: address)
                ?? makeCryptoUnallocatedInstruction(word: word, at: address)
        }

        // Group 23: Cryptographic four-register & XAR (FEAT_SHA3, ARM DDI 0487 C4.1.95.4):
        // Claims the entire 0xCE00_0000..0xCEFF_FFFF cryptographic space so apple-m1 unsupported
        // SM3/SM4, out-of-scope SHA512/RAX1, and unallocated encodings all emit .inst.
        if (word & 0xFF00_0000) == 0xCE00_0000 {
            return decodeCryptographicFourRegAndXAR(word: word, at: address)
                ?? makeCryptoUnallocatedInstruction(word: word, at: address)
        }

        return nil
    }

    // MARK: - Group 17: Cryptographic AES (AESE, AESD, AESMC, AESIMC)

    private func decodeCryptographicAES(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction? {
        let size = extractCryptoBits(word, high: 23, low: 22)
        guard size == 0b00 else { return nil }

        let opcode = extractCryptoBits(word, high: 16, low: 12)
        let rn = UInt8(extractCryptoBits(word, high: 9, low: 5))
        let rd = UInt8(extractCryptoBits(word, high: 4, low: 0))

        let mnemonicText: String
        let readsDestination: Bool
        switch opcode {
        case 0b00100:
            mnemonicText = "aese"
            readsDestination = true
        case 0b00101:
            mnemonicText = "aesd"
            readsDestination = true
        case 0b00110:
            mnemonicText = "aesmc"
            readsDestination = false
        case 0b00111:
            mnemonicText = "aesimc"
            readsDestination = false
        default:
            return nil
        }

        let vd = A64Register.v(rd, arrangement: "16b")
        let vn = A64Register.v(rn, arrangement: "16b")
        let rawReads = readsDestination ? [vd, vn] : [vn]

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: .eorVec,
            mnemonicText: mnemonicText,
            operands: [.register(vd), .register(vn)],
            operandText: "\(vd.canonicalName), \(vn.canonicalName)",
            group: .simdAndFP,
            flow: .sequential,
            readsRegisters: uniqueCryptoRegisters(rawReads),
            writesRegisters: [vd]
        )
    }

    // MARK: - Group 23: Cryptographic Four-Register & XAR (EOR3, BCAX, XAR)

    private func decodeCryptographicFourRegAndXAR(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction? {
        if (word & 0xFF80_0000) == 0xCE00_0000 {
            guard extractCryptoBits(word, high: 15, low: 15) == 0 else { return nil }
            let op0 = extractCryptoBits(word, high: 22, low: 21)
            let mnemonicText: String
            switch op0 {
            case 0b00:
                mnemonicText = "eor3"
            case 0b01:
                mnemonicText = "bcax"
            default:
                // Op0 == 0b10 (SM3SS1, unsupported on apple-m1) and Op0 == 0b11 (unallocated) stay .inst.
                return nil
            }

            let rm = UInt8(extractCryptoBits(word, high: 20, low: 16))
            let ra = UInt8(extractCryptoBits(word, high: 14, low: 10))
            let rn = UInt8(extractCryptoBits(word, high: 9, low: 5))
            let rd = UInt8(extractCryptoBits(word, high: 4, low: 0))

            let vd = A64Register.v(rd, arrangement: "16b")
            let vn = A64Register.v(rn, arrangement: "16b")
            let vm = A64Register.v(rm, arrangement: "16b")
            let va = A64Register.v(ra, arrangement: "16b")

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .eorVec,
                mnemonicText: mnemonicText,
                operands: [.register(vd), .register(vn), .register(vm), .register(va)],
                operandText: "\(vd.canonicalName), \(vn.canonicalName), \(vm.canonicalName), \(va.canonicalName)",
                group: .simdAndFP,
                flow: .sequential,
                readsRegisters: uniqueCryptoRegisters([vn, vm, va]),
                writesRegisters: [vd]
            )
        }

        if (word & 0xFFE0_0000) == 0xCE80_0000 {
            let rm = UInt8(extractCryptoBits(word, high: 20, low: 16))
            let imm6 = extractCryptoBits(word, high: 15, low: 10)
            let rn = UInt8(extractCryptoBits(word, high: 9, low: 5))
            let rd = UInt8(extractCryptoBits(word, high: 4, low: 0))

            let vd = A64Register.v(rd, arrangement: "2d")
            let vn = A64Register.v(rn, arrangement: "2d")
            let vm = A64Register.v(rm, arrangement: "2d")
            let immHex = String(format: "#0x%x", imm6)

            return A64DecodedInstruction(
                address: address,
                rawWord: word,
                mnemonic: .eorVec,
                mnemonicText: "xar",
                operands: [.register(vd), .register(vn), .register(vm), .unsignedImmediate(UInt64(imm6))],
                operandText: "\(vd.canonicalName), \(vn.canonicalName), \(vm.canonicalName), \(immHex)",
                group: .simdAndFP,
                flow: .sequential,
                readsRegisters: uniqueCryptoRegisters([vn, vm]),
                writesRegisters: [vd]
            )
        }

        return nil
    }

    // MARK: - Private Helpers (Public Types Only)

    private func extractCryptoBits(_ word: UInt32, high: Int, low: Int) -> UInt32 {
        let width = high - low + 1
        let mask: UInt32 = (width >= 32) ? UInt32.max : ((UInt32(1) << width) - 1)
        return (word >> low) & mask
    }

    private func uniqueCryptoRegisters(_ regs: [A64Register]) -> [A64Register] {
        var result: [A64Register] = []
        for reg in regs where !reg.isZeroRegister {
            if !result.contains(reg) {
                result.append(reg)
            }
        }
        return result
    }

    private func makeCryptoUnallocatedInstruction(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction {
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
}
