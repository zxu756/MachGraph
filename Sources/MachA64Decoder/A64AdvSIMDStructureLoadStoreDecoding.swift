import Foundation
import MachGraphModels

// MARK: - AdvSIMD Load/Store Structure Decoding (ARM DDI 0487 C4.1.93 / C3.3.5–C3.3.6)

extension A64InstructionDecoder {
    /// Decodes AdvSIMD load/store structure instructions (`0x0C...` / `0x4C...` / `0x0D...` / `0x4D...`).
    ///
    /// Stage 13 implements Group 9 (AdvSIMD load/store single structure: `ld1`–`ld4`, `st1`–`st4`
    /// single-lane forms and `ld1r`–`ld4r`, with no-offset and post-index addressing).
    /// Group 21 (multiple structures, `bit[24] == 0`) remains `nil` here for Stage 13b.
    func decodeAdvSIMDLoadStoreStructure(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction? {
        if (word & 0xBF00_0000) == 0x0D00_0000 {
            return decodeAdvSIMDLoadStoreSingleStructure(word: word, at: address)
        }
        return nil
    }

    // MARK: - Group 9: AdvSIMD Load/Store Single Structure (No-Offset & Post-Index)

    private func decodeAdvSIMDLoadStoreSingleStructure(
        word: UInt32,
        at address: VirtualAddress
    ) -> A64DecodedInstruction? {
        let q = A64BitUtils.bit(word, 30)
        let isPostIndex = A64BitUtils.flag(word, 23)
        let isLoad = A64BitUtils.flag(word, 22)
        let r = A64BitUtils.bit(word, 21)
        let rm = UInt8(A64BitUtils.extract(word, 20, 16))
        let opcode = A64BitUtils.extract(word, 15, 13)
        let s = A64BitUtils.bit(word, 12)
        let size = A64BitUtils.extract(word, 11, 10)
        let rn = UInt8(A64BitUtils.extract(word, 9, 5))
        let rt = UInt8(A64BitUtils.extract(word, 4, 0))

        let selem = Int(((opcode & 1) << 1) | r) + 1
        let scale = opcode >> 1

        let mnemonicText: String
        let arrangement: String
        let laneIndex: UInt32?
        let elemBytes: Int
        let readsDestinationVectors: Bool

        switch scale {
        case 0b00:
            mnemonicText = "\(isLoad ? "ld" : "st")\(selem)"
            arrangement = "b"
            laneIndex = (q << 3) | (s << 2) | size
            elemBytes = 1
            readsDestinationVectors = isLoad
        case 0b01:
            guard (size & 0b01) == 0 else { return nil }
            mnemonicText = "\(isLoad ? "ld" : "st")\(selem)"
            arrangement = "h"
            laneIndex = (q << 2) | (s << 1) | (size >> 1)
            elemBytes = 2
            readsDestinationVectors = isLoad
        case 0b10:
            mnemonicText = "\(isLoad ? "ld" : "st")\(selem)"
            if size == 0b00 {
                arrangement = "s"
                laneIndex = (q << 1) | s
                elemBytes = 4
            } else if size == 0b01 && s == 0 {
                arrangement = "d"
                laneIndex = q
                elemBytes = 8
            } else {
                return nil
            }
            readsDestinationVectors = isLoad
        case 0b11:
            guard isLoad && s == 0 else { return nil }
            mnemonicText = "ld\(selem)r"
            laneIndex = nil
            switch size {
            case 0b00:
                arrangement = (q == 1) ? "16b" : "8b"
                elemBytes = 1
            case 0b01:
                arrangement = (q == 1) ? "8h" : "4h"
                elemBytes = 2
            case 0b10:
                arrangement = (q == 1) ? "4s" : "2s"
                elemBytes = 4
            case 0b11:
                arrangement = (q == 1) ? "2d" : "1d"
                elemBytes = 8
            default:
                return nil
            }
            readsDestinationVectors = false
        default:
            return nil
        }

        let totalTransferBytes = elemBytes * selem
        guard let addressing = decodeAdvSIMDStructureAddressing(
            isPostIndex: isPostIndex,
            rn: rn,
            rm: rm,
            immediateBytes: totalTransferBytes
        ) else {
            return nil
        }

        let vectorRegs = makeAdvSIMDStructureRegisters(
            firstIndex: rt,
            count: selem,
            arrangement: arrangement
        )
        let registerListText = formatAdvSIMDStructureRegisterList(vectorRegs, laneIndex: laneIndex)
        let operandText = "\(registerListText), \(addressing.operandText)"
        let operands = vectorRegs.map(A64Operand.register) + addressing.operands

        var rawReads: [A64Register] = [addressing.baseRegister]
        if let offsetReg = addressing.offsetRegister {
            rawReads.append(offsetReg)
        }
        if !isLoad || readsDestinationVectors {
            rawReads.append(contentsOf: vectorRegs)
        }

        var rawWrites: [A64Register] = isLoad ? vectorRegs : []
        if addressing.writesBase {
            rawWrites.append(addressing.baseRegister)
        }

        return A64DecodedInstruction(
            address: address,
            rawWord: word,
            mnemonic: isLoad ? .ins : .umov,
            mnemonicText: mnemonicText,
            operands: operands,
            operandText: operandText,
            group: .simdAndFP,
            readsRegisters: uniqueActiveStructureRegisters(rawReads),
            writesRegisters: uniqueActiveStructureRegisters(rawWrites)
        )
    }

    // MARK: - Shared Structure Helpers (Single & Multiple Structures)

    private struct AdvSIMDStructureAddressing {
        let baseRegister: A64Register
        let offsetRegister: A64Register?
        let operands: [A64Operand]
        let operandText: String
        let writesBase: Bool
    }

    private func decodeAdvSIMDStructureAddressing(
        isPostIndex: Bool,
        rn: UInt8,
        rm: UInt8,
        immediateBytes: Int
    ) -> AdvSIMDStructureAddressing? {
        let baseReg = A64Register.x(rn, allowSP: true)
        if !isPostIndex {
            // No-offset form requires bits[20:16] == 00000; non-zero Rm is unallocated.
            guard rm == 0 else { return nil }
            return AdvSIMDStructureAddressing(
                baseRegister: baseReg,
                offsetRegister: nil,
                operands: [.memory(.baseOffset(base: baseReg, offset: 0))],
                operandText: "[\(baseReg.canonicalName)]",
                writesBase: false
            )
        }

        if rm == 31 {
            return AdvSIMDStructureAddressing(
                baseRegister: baseReg,
                offsetRegister: nil,
                operands: [.memory(.postIndex(base: baseReg, offset: Int64(immediateBytes)))],
                operandText: "[\(baseReg.canonicalName)], #\(immediateBytes)",
                writesBase: true
            )
        }

        let offsetReg = A64Register.x(rm, allowSP: false)
        return AdvSIMDStructureAddressing(
            baseRegister: baseReg,
            offsetRegister: offsetReg,
            operands: [.memory(.baseOffset(base: baseReg, offset: 0)), .register(offsetReg)],
            operandText: "[\(baseReg.canonicalName)], \(offsetReg.canonicalName)",
            writesBase: true
        )
    }

    private func makeAdvSIMDStructureRegisters(
        firstIndex rt: UInt8,
        count: Int,
        arrangement: String
    ) -> [A64Register] {
        (0..<count).map { offset in
            A64Register.v((rt &+ UInt8(offset)) & 31, arrangement: arrangement)
        }
    }

    private func formatAdvSIMDStructureRegisterList(
        _ registers: [A64Register],
        laneIndex: UInt32? = nil
    ) -> String {
        let body = registers.map(\.canonicalName).joined(separator: ", ")
        if let laneIndex {
            return "{ \(body) }[\(laneIndex)]"
        }
        return "{ \(body) }"
    }

    private func uniqueActiveStructureRegisters(_ regs: [A64Register]) -> [A64Register] {
        var result: [A64Register] = []
        for reg in regs where !reg.isZeroRegister {
            if !result.contains(reg) {
                result.append(reg)
            }
        }
        return result
    }
}
