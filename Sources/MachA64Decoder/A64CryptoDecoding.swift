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
