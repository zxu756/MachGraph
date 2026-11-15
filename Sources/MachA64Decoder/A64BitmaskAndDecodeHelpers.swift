import Foundation
import MachGraphModels

// MARK: - Top-Level Architectural Bitmask, Sign-Extension & FP Immediate Functions

/// Exact ARMv8-A `DecodeBitMasks` implementation per the ARM Architecture Reference Manual.
///
/// Decodes the 13-bit `(immN:immr:imms)` bitmask immediate encoding used by A64 logical-immediate
/// (`AND`, `ORR`, `EOR`, `ANDS`) and bitfield (`BFM`, `SBFM`, `UBFM`) instructions.
///
/// - Parameters:
///   - immN: 1-bit `N` field (`0` or `1`). Must be `0` when `regSize == 32`.
///   - imms: 6-bit `imms` field (`0...63`).
///   - immr: 6-bit `immr` field (`0...63`).
///   - immediate: `true` when decoding a logical bitmask immediate (`AND`/`ORR`/`EOR`/`ANDS`),
///     which rejects all-ones element masks (`(imms & levels) == levels`); `false` for bitfield ops.
///   - regSize: Target register width in bits (`32` or `64`).
/// - Returns: `(wmask, tmask)` replicated to `regSize` bits, or `nil` if the encoding is reserved/undefined.
public func DecodeBitMasks(
    immN: UInt32,
    imms: UInt32,
    immr: UInt32,
    immediate: Bool,
    regSize: Int
) -> (wmask: UInt64, tmask: UInt64)? {
    guard regSize == 32 || regSize == 64 else { return nil }
    let n = immN & 1
    let sField = imms & 0x3F
    let rField = immr & 0x3F

    // Compute log2 of element size: len = HighestSetBit(N : NOT(imms)<5:0>)
    let combined = (n << 6) | ((~sField) & 0x3F)
    let len = A64BitUtils.highestSetBit(combined)
    guard len >= 1 else {
        // Reserved encoding (immN == 0 && imms == 0b111111 or imms == 0b111110)
        return nil
    }

    let esize = 1 << len
    guard esize <= regSize else {
        // 64-bit element size is undefined for 32-bit operations
        return nil
    }

    let levels = UInt32((1 << len) - 1)
    if immediate && (sField & levels) == levels {
        // Logical immediates cannot encode all-zeros or all-ones
        return nil
    }

    let s = Int(sField & levels)
    let r = Int(rField & levels)
    let diff = (s - r) & Int(levels)

    let welem = A64BitUtils.onesMask(s + 1)
    let telem = A64BitUtils.onesMask(diff + 1)

    let wmaskElem = A64BitUtils.rotateRight(welem, by: r, width: esize)
    let tmaskElem = telem

    let wmask = A64BitUtils.replicateElement(wmaskElem, elementWidth: esize, totalWidth: regSize)
    let tmask = A64BitUtils.replicateElement(tmaskElem, elementWidth: esize, totalWidth: regSize)
    return (wmask: wmask, tmask: tmask)
}

/// Lowercase Swift convenience alias for `DecodeBitMasks`.
@inlinable
public func decodeBitMasks(
    immN: UInt32,
    imms: UInt32,
    immr: UInt32,
    immediate: Bool,
    regSize: Int
) -> (wmask: UInt64, tmask: UInt64)? {
    DecodeBitMasks(immN: immN, imms: imms, immr: immr, immediate: immediate, regSize: regSize)
}

/// Inverse of `DecodeBitMasks(..., immediate: true, ...)` for the A64 inline assembler.
///
/// Determines whether `value` can be represented as an ARM64 logical bitmask immediate of width `regSize`
/// (`32` or `64`), returning `(n, imms, immr)` when encodable or `nil` otherwise.
public func encodeBitmaskImmediate(
    _ value: UInt64,
    regSize: Int
) -> (n: UInt32, imms: UInt32, immr: UInt32)? {
    guard regSize == 32 || regSize == 64 else { return nil }

    let normalized64: UInt64
    if regSize == 32 {
        guard (value >> 32) == 0 else { return nil }
        guard value != 0 && value != 0xFFFF_FFFF else { return nil }
        normalized64 = value | (value << 32)
    } else {
        guard value != 0 && value != UInt64.max else { return nil }
        normalized64 = value
    }

    // Find the smallest repeating power-of-two element width in [2, 4, 8, 16, 32, 64]
    var esize = 2
    while esize <= regSize {
        let elemMask = A64BitUtils.onesMask(esize)
        let elem = normalized64 & elemMask
        let replicated = A64BitUtils.replicateElement(elem, elementWidth: esize, totalWidth: 64)
        if replicated == normalized64 {
            let ones = elem.nonzeroBitCount
            if ones > 0 && ones < esize {
                let unrotated = A64BitUtils.onesMask(ones)
                for r in 0..<esize {
                    let candidate = A64BitUtils.rotateRight(unrotated, by: r, width: esize)
                    if candidate == elem {
                        let len = esize.trailingZeroBitCount // 1...6
                        let n: UInt32 = (esize == 64) ? 1 : 0
                        let s = UInt32(ones - 1)
                        let prefix: UInt32 = (len == 6) ? 0 : ((~UInt32((1 << (len + 1)) - 1)) & 0x3F)
                        let imms = (prefix | s) & 0x3F
                        let immr = UInt32(r) & 0x3F
                        return (n: n, imms: imms, immr: immr)
                    }
                }
            }
            // Once the minimal period fails to be a single rotated run of 1s, larger periods
            // are multiple disjoint runs and thus cannot be a single contiguous run either.
            return nil
        }
        esize <<= 1
    }

    return nil
}

/// Sign-extends the lowest `bits` (`1...64`) of `value` into a 64-bit signed integer.
@inlinable
public func signExtend(_ value: UInt64, bits: Int) -> Int64 {
    precondition(bits >= 1 && bits <= 64, "Bit width for signExtend must be in 1...64")
    if bits == 64 {
        return Int64(bitPattern: value)
    }
    let shift = 64 - bits
    let shifted = (value << shift)
    return Int64(bitPattern: shifted) >> shift
}

/// Expands an ARM64 8-bit VFP/SIMD floating-point immediate (`FMOV <Sd|Dd|Hd>, #imm`) to `Double`.
///
/// Architectural definition: `(-1)^imm8<7> * (1 + imm8<3:0>/16) * 2^exp` where `exp` is in `-3...4`.
public func decodeVFPExpandImm8(_ imm8: UInt8) -> Double {
    let signBit = UInt64((imm8 >> 7) & 1) << 63
    let b6 = (imm8 >> 6) & 1
    let notB6 = UInt64(b6 ^ 1)
    let repB6: UInt64 = (b6 == 1) ? 0xFF : 0x00
    let expLow2 = UInt64((imm8 >> 4) & 0x3)
    let exp11 = (notB6 << 10) | (repB6 << 2) | expLow2
    let frac52 = UInt64(imm8 & 0xF) << 48
    let rawIEEE754 = signBit | (exp11 << 52) | frac52
    return Double(bitPattern: rawIEEE754)
}

/// Inverse of `decodeVFPExpandImm8(_:)`: encodes an exact IEEE-754 `Double` into an ARM64 8-bit FP immediate.
///
/// Returns `nil` if `value` is zero, NaN, infinity, or outside the representable 8-bit VFP set.
public func encodeVFPImm8(_ value: Double) -> UInt8? {
    guard value.isFinite && value != 0.0 else { return nil }
    let bits = value.bitPattern
    // Lower 48 fraction bits must be zero (only top 4 mantissa bits are encoded)
    guard (bits & 0x0000_FFFF_FFFF_FFFF) == 0 else { return nil }

    let sign = UInt8((bits >> 63) & 1)
    let biasedExp = Int((bits >> 52) & 0x7FF)
    let unbiasedExp = biasedExp - 1023
    guard (-3...4).contains(unbiasedExp) else { return nil }

    let frac4 = UInt8((bits >> 48) & 0xF)
    // Unbiased exponent mapping:
    // -3 -> 0b100, -2 -> 0b101, -1 -> 0b110, 0 -> 0b111
    // +1 -> 0b000, +2 -> 0b001, +3 -> 0b010, +4 -> 0b011
    let exp3: UInt8
    if unbiasedExp <= 0 {
        exp3 = UInt8(0b100 | (unbiasedExp + 3))
    } else {
        exp3 = UInt8((unbiasedExp - 1) & 0x3)
    }

    return (sign << 7) | (exp3 << 4) | frac4
}

// MARK: - Low-Level Bit & Mask Utilities

public enum A64BitUtils {
    /// Extracts inclusive bit slice `word[msb:lsb]`.
    @inlinable
    public static func extract(_ word: UInt32, _ msb: Int, _ lsb: Int) -> UInt32 {
        let width = msb - lsb + 1
        if width >= 32 {
            return word >> lsb
        }
        let mask = (UInt32(1) << width) - 1
        return (word >> lsb) & mask
    }

    /// Extracts single bit `word[index]` as `0` or `1`.
    @inlinable
    public static func bit(_ word: UInt32, _ index: Int) -> UInt32 {
        (word >> index) & 1
    }

    /// Extracts single bit `word[index]` as `Bool`.
    @inlinable
    public static func flag(_ word: UInt32, _ index: Int) -> Bool {
        ((word >> index) & 1) != 0
    }

    /// Returns index (`0...31`) of the highest set bit, or `-1` if `value == 0`.
    @inlinable
    public static func highestSetBit(_ value: UInt32) -> Int {
        guard value != 0 else { return -1 }
        return 31 - value.leadingZeroBitCount
    }

    /// Returns a mask with the lowest `count` (`0...64`) bits set to `1`.
    @inlinable
    public static func onesMask(_ count: Int) -> UInt64 {
        if count <= 0 { return 0 }
        if count >= 64 { return UInt64.max }
        return (UInt64(1) << count) - 1
    }

    /// Rotates `value` right by `shift` bits within an `width`-bit (`1...64`) lane.
    @inlinable
    public static func rotateRight(_ value: UInt64, by shift: Int, width: Int) -> UInt64 {
        let mask = onesMask(width)
        let v = value & mask
        guard width > 1 else { return v }
        let s = ((shift % width) + width) % width
        guard s != 0 else { return v }
        return ((v >> s) | (v << (width - s))) & mask
    }

    /// Replicates an `elementWidth`-bit pattern across `totalWidth` bits (`32` or `64`).
    @inlinable
    public static func replicateElement(_ elem: UInt64, elementWidth: Int, totalWidth: Int) -> UInt64 {
        let elemMask = onesMask(elementWidth)
        var acc = elem & elemMask
        var w = elementWidth
        while w < totalWidth {
            acc |= (acc << w)
            w <<= 1
        }
        return acc & onesMask(totalWidth)
    }

    /// Evaluates ARM64 AdvSIMD 64-bit modified immediate (`cmode=1110, op=1`: each byte replicated from bit).
    public static func expandSIMDByteMaskImmediate(_ imm8: UInt8) -> UInt64 {
        var result: UInt64 = 0
        for byteIndex in 0..<8 {
            if ((imm8 >> byteIndex) & 1) != 0 {
                result |= UInt64(0xFF) << (byteIndex * 8)
            }
        }
        return result
    }

    /// Inverse of `expandSIMDByteMaskImmediate(_:)`.
    public static func compressSIMDByteMaskImmediate(_ value: UInt64) -> UInt8? {
        var imm8: UInt8 = 0
        for byteIndex in 0..<8 {
            let byte = UInt8(truncatingIfNeeded: value >> (byteIndex * 8))
            if byte == 0xFF {
                imm8 |= (1 << byteIndex)
            } else if byte != 0x00 {
                return nil
            }
        }
        return imm8
    }
}

// MARK: - ARM64 / Apple Silicon System Register Table

public struct A64SystemRegisterDescriptor: Sendable, Codable, Hashable {
    public let name: String
    public let encoding: UInt16
    public let op0: UInt8
    public let op1: UInt8
    public let crn: UInt8
    public let crm: UInt8
    public let op2: UInt8
    public let summary: String

    public init(
        name: String,
        op0: UInt8,
        op1: UInt8,
        crn: UInt8,
        crm: UInt8,
        op2: UInt8,
        summary: String
    ) {
        self.name = name
        self.op0 = op0
        self.op1 = op1
        self.crn = crn
        self.crm = crm
        self.op2 = op2
        self.encoding = A64SystemRegisterTable.packEncoding(
            op0: UInt32(op0),
            op1: UInt32(op1),
            crn: UInt32(crn),
            crm: UInt32(crm),
            op2: UInt32(op2)
        )
        self.summary = summary
    }
}

public enum A64SystemRegisterTable {
    /// Packs `(op0, op1, CRn, CRm, op2)` into the 16-bit system register identifier `word[20:5]`.
    @inlinable
    public static func packEncoding(
        op0: UInt32,
        op1: UInt32,
        crn: UInt32,
        crm: UInt32,
        op2: UInt32
    ) -> UInt16 {
        UInt16(
            ((op0 & 0x3) << 14) |
            ((op1 & 0x7) << 11) |
            ((crn & 0xF) << 7) |
            ((crm & 0xF) << 3) |
            (op2 & 0x7)
        )
    }

    /// Unpacks a 16-bit `word[20:5]` system register identifier into `(op0, op1, CRn, CRm, op2)`.
    @inlinable
    public static func unpackEncoding(
        _ encoding: UInt16
    ) -> (op0: UInt32, op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32) {
        let raw = UInt32(encoding)
        return (
            op0: (raw >> 14) & 0x3,
            op1: (raw >> 11) & 0x7,
            crn: (raw >> 7) & 0xF,
            crm: (raw >> 3) & 0xF,
            op2: raw & 0x7
        )
    }

    public static let allRegisters: [A64SystemRegisterDescriptor] = [
        // Condition Flags, Floating-Point Control & Process State (EL0)
        .init(name: "NZCV", op0: 3, op1: 3, crn: 4, crm: 2, op2: 0, summary: "Condition Flags (N, Z, C, V)"),
        .init(name: "DAIF", op0: 3, op1: 3, crn: 4, crm: 2, op2: 1, summary: "Interrupt Mask Bits (D, A, I, F)"),
        .init(name: "DIT", op0: 3, op1: 3, crn: 4, crm: 2, op2: 5, summary: "Data Independent Timing"),
        .init(name: "SSBS", op0: 3, op1: 3, crn: 4, crm: 2, op2: 6, summary: "Speculative Store Bypass Safe"),
        .init(name: "TCO", op0: 3, op1: 3, crn: 4, crm: 2, op2: 7, summary: "Tag Check Override"),
        .init(name: "FPCR", op0: 3, op1: 3, crn: 4, crm: 4, op2: 0, summary: "Floating-Point Control Register"),
        .init(name: "FPSR", op0: 3, op1: 3, crn: 4, crm: 4, op2: 1, summary: "Floating-Point Status Register"),
        .init(name: "DSPSR_EL0", op0: 3, op1: 3, crn: 4, crm: 5, op2: 0, summary: "Debug Saved Program Status Register"),
        .init(name: "DLR_EL0", op0: 3, op1: 3, crn: 4, crm: 5, op2: 1, summary: "Debug Link Register"),
        .init(name: "CurrentEL", op0: 3, op1: 0, crn: 4, crm: 2, op2: 2, summary: "Current Exception Level"),
        .init(name: "SPSel", op0: 3, op1: 0, crn: 4, crm: 2, op2: 0, summary: "Stack Pointer Select"),
        .init(name: "PAN", op0: 3, op1: 0, crn: 4, crm: 2, op2: 3, summary: "Privileged Access Never"),
        .init(name: "UAO", op0: 3, op1: 0, crn: 4, crm: 2, op2: 4, summary: "User Access Override"),

        // Thread Pointer & Cache/Data-Zero Identification (EL0)
        .init(name: "TPIDR_EL0", op0: 3, op1: 3, crn: 13, crm: 0, op2: 2, summary: "EL0 Read/Write Software Thread ID (TLS base)"),
        .init(name: "TPIDRRO_EL0", op0: 3, op1: 3, crn: 13, crm: 0, op2: 3, summary: "EL0 Read-Only Software Thread ID (pthread self)"),
        .init(name: "TPIDR_EL1", op0: 3, op1: 0, crn: 13, crm: 0, op2: 4, summary: "EL1 Software Thread ID Register"),
        .init(name: "TPIDR_EL2", op0: 3, op1: 4, crn: 13, crm: 0, op2: 2, summary: "EL2 Software Thread ID Register"),
        .init(name: "TPIDR_EL3", op0: 3, op1: 6, crn: 13, crm: 0, op2: 2, summary: "EL3 Software Thread ID Register"),
        .init(name: "CONTEXTIDR_EL1", op0: 3, op1: 0, crn: 13, crm: 0, op2: 1, summary: "Context ID Register (EL1)"),
        .init(name: "CTR_EL0", op0: 3, op1: 3, crn: 0, crm: 0, op2: 1, summary: "Cache Type Register"),
        .init(name: "DCZID_EL0", op0: 3, op1: 3, crn: 0, crm: 0, op2: 7, summary: "Data Cache Zero ID Register"),

        // Generic Timer Registers (EL0)
        .init(name: "CNTFRQ_EL0", op0: 3, op1: 3, crn: 14, crm: 0, op2: 0, summary: "Counter-Timer Frequency Register"),
        .init(name: "CNTPCT_EL0", op0: 3, op1: 3, crn: 14, crm: 0, op2: 1, summary: "Counter-Timer Physical Count Register"),
        .init(name: "CNTVCT_EL0", op0: 3, op1: 3, crn: 14, crm: 0, op2: 2, summary: "Counter-Timer Virtual Count Register (mach_absolute_time)"),
        .init(name: "CNTP_TVAL_EL0", op0: 3, op1: 3, crn: 14, crm: 2, op2: 0, summary: "Counter-Timer Physical Timer TimerValue"),
        .init(name: "CNTP_CTL_EL0", op0: 3, op1: 3, crn: 14, crm: 2, op2: 1, summary: "Counter-Timer Physical Timer Control"),
        .init(name: "CNTP_CVAL_EL0", op0: 3, op1: 3, crn: 14, crm: 2, op2: 2, summary: "Counter-Timer Physical Timer CompareValue"),
        .init(name: "CNTV_TVAL_EL0", op0: 3, op1: 3, crn: 14, crm: 3, op2: 0, summary: "Counter-Timer Virtual Timer TimerValue"),
        .init(name: "CNTV_CTL_EL0", op0: 3, op1: 3, crn: 14, crm: 3, op2: 1, summary: "Counter-Timer Virtual Timer Control"),
        .init(name: "CNTV_CVAL_EL0", op0: 3, op1: 3, crn: 14, crm: 3, op2: 2, summary: "Counter-Timer Virtual Timer CompareValue"),

        // CPU Identification & Feature Registers (EL1)
        .init(name: "MIDR_EL1", op0: 3, op1: 0, crn: 0, crm: 0, op2: 0, summary: "Main ID Register"),
        .init(name: "MPIDR_EL1", op0: 3, op1: 0, crn: 0, crm: 0, op2: 5, summary: "Multiprocessor Affinity Register"),
        .init(name: "REVIDR_EL1", op0: 3, op1: 0, crn: 0, crm: 0, op2: 6, summary: "Revision ID Register"),
        .init(name: "ID_AA64PFR0_EL1", op0: 3, op1: 0, crn: 0, crm: 4, op2: 0, summary: "AArch64 Processor Feature Register 0"),
        .init(name: "ID_AA64PFR1_EL1", op0: 3, op1: 0, crn: 0, crm: 4, op2: 1, summary: "AArch64 Processor Feature Register 1"),
        .init(name: "ID_AA64DFR0_EL1", op0: 3, op1: 0, crn: 0, crm: 5, op2: 0, summary: "AArch64 Debug Feature Register 0"),
        .init(name: "ID_AA64ISAR0_EL1", op0: 3, op1: 0, crn: 0, crm: 6, op2: 0, summary: "AArch64 Instruction Set Attribute Register 0"),
        .init(name: "ID_AA64ISAR1_EL1", op0: 3, op1: 0, crn: 0, crm: 6, op2: 1, summary: "AArch64 Instruction Set Attribute Register 1"),
        .init(name: "ID_AA64ISAR2_EL1", op0: 3, op1: 0, crn: 0, crm: 6, op2: 2, summary: "AArch64 Instruction Set Attribute Register 2"),
        .init(name: "ID_AA64MMFR0_EL1", op0: 3, op1: 0, crn: 0, crm: 7, op2: 0, summary: "AArch64 Memory Model Feature Register 0"),
        .init(name: "ID_AA64MMFR1_EL1", op0: 3, op1: 0, crn: 0, crm: 7, op2: 1, summary: "AArch64 Memory Model Feature Register 1"),
        .init(name: "ID_AA64MMFR2_EL1", op0: 3, op1: 0, crn: 0, crm: 7, op2: 2, summary: "AArch64 Memory Model Feature Register 2"),

        // System Control, MMU & Exception Handling (EL1)
        .init(name: "SCTLR_EL1", op0: 3, op1: 0, crn: 1, crm: 0, op2: 0, summary: "System Control Register (EL1)"),
        .init(name: "ACTLR_EL1", op0: 3, op1: 0, crn: 1, crm: 0, op2: 1, summary: "Auxiliary Control Register (EL1)"),
        .init(name: "CPACR_EL1", op0: 3, op1: 0, crn: 1, crm: 0, op2: 2, summary: "Architectural Feature Access Control Register"),
        .init(name: "TTBR0_EL1", op0: 3, op1: 0, crn: 2, crm: 0, op2: 0, summary: "Translation Table Base Register 0 (EL1)"),
        .init(name: "TTBR1_EL1", op0: 3, op1: 0, crn: 2, crm: 0, op2: 1, summary: "Translation Table Base Register 1 (EL1)"),
        .init(name: "TCR_EL1", op0: 3, op1: 0, crn: 2, crm: 0, op2: 2, summary: "Translation Control Register (EL1)"),
        .init(name: "SPSR_EL1", op0: 3, op1: 0, crn: 4, crm: 0, op2: 0, summary: "Saved Program Status Register (EL1)"),
        .init(name: "ELR_EL1", op0: 3, op1: 0, crn: 4, crm: 0, op2: 1, summary: "Exception Link Register (EL1)"),
        .init(name: "SP_EL0", op0: 3, op1: 0, crn: 4, crm: 1, op2: 0, summary: "Stack Pointer (EL0)"),
        .init(name: "SP_EL1", op0: 3, op1: 4, crn: 4, crm: 1, op2: 0, summary: "Stack Pointer (EL1)"),
        .init(name: "ESR_EL1", op0: 3, op1: 0, crn: 5, crm: 2, op2: 0, summary: "Exception Syndrome Register (EL1)"),
        .init(name: "FAR_EL1", op0: 3, op1: 0, crn: 6, crm: 0, op2: 0, summary: "Fault Address Register (EL1)"),
        .init(name: "PAR_EL1", op0: 3, op1: 0, crn: 7, crm: 4, op2: 0, summary: "Physical Address Register (EL1)"),
        .init(name: "MAIR_EL1", op0: 3, op1: 0, crn: 10, crm: 2, op2: 0, summary: "Memory Attribute Indirection Register (EL1)"),
        .init(name: "VBAR_EL1", op0: 3, op1: 0, crn: 12, crm: 0, op2: 0, summary: "Vector Base Address Register (EL1)"),

        // ARMv8.3 Pointer Authentication Key Registers (EL1)
        .init(name: "APIAKeyLo_EL1", op0: 3, op1: 0, crn: 2, crm: 1, op2: 0, summary: "PAC Instruction Key A (Low 64 bits)"),
        .init(name: "APIAKeyHi_EL1", op0: 3, op1: 0, crn: 2, crm: 1, op2: 1, summary: "PAC Instruction Key A (High 64 bits)"),
        .init(name: "APIBKeyLo_EL1", op0: 3, op1: 0, crn: 2, crm: 1, op2: 2, summary: "PAC Instruction Key B (Low 64 bits)"),
        .init(name: "APIBKeyHi_EL1", op0: 3, op1: 0, crn: 2, crm: 1, op2: 3, summary: "PAC Instruction Key B (High 64 bits)"),
        .init(name: "APDAKeyLo_EL1", op0: 3, op1: 0, crn: 2, crm: 2, op2: 0, summary: "PAC Data Key A (Low 64 bits)"),
        .init(name: "APDAKeyHi_EL1", op0: 3, op1: 0, crn: 2, crm: 2, op2: 1, summary: "PAC Data Key A (High 64 bits)"),
        .init(name: "APDBKeyLo_EL1", op0: 3, op1: 0, crn: 2, crm: 2, op2: 2, summary: "PAC Data Key B (Low 64 bits)"),
        .init(name: "APDBKeyHi_EL1", op0: 3, op1: 0, crn: 2, crm: 2, op2: 3, summary: "PAC Data Key B (High 64 bits)"),
        .init(name: "APGAKeyLo_EL1", op0: 3, op1: 0, crn: 2, crm: 3, op2: 0, summary: "PAC Generic Key A (Low 64 bits)"),
        .init(name: "APGAKeyHi_EL1", op0: 3, op1: 0, crn: 2, crm: 3, op2: 1, summary: "PAC Generic Key A (High 64 bits)"),

        // Performance Monitors (EL0)
        .init(name: "PMCR_EL0", op0: 3, op1: 3, crn: 9, crm: 12, op2: 0, summary: "Performance Monitors Control Register"),
        .init(name: "PMCNTENSET_EL0", op0: 3, op1: 3, crn: 9, crm: 12, op2: 1, summary: "Performance Monitors Count Enable Set"),
        .init(name: "PMCCNTR_EL0", op0: 3, op1: 3, crn: 9, crm: 13, op2: 0, summary: "Performance Monitors Cycle Count Register"),

        // Debug Registers
        .init(name: "MDSCR_EL1", op0: 2, op1: 0, crn: 0, crm: 2, op2: 2, summary: "Monitor Debug System Control Register")
    ]

    private static let byEncoding: [UInt16: A64SystemRegisterDescriptor] = {
        var map: [UInt16: A64SystemRegisterDescriptor] = [:]
        map.reserveCapacity(allRegisters.count)
        for reg in allRegisters {
            map[reg.encoding] = reg
        }
        return map
    }()

    private static let byLowerName: [String: UInt16] = {
        var map: [String: UInt16] = [:]
        map.reserveCapacity(allRegisters.count)
        for reg in allRegisters {
            map[reg.name.lowercased()] = reg.encoding
        }
        return map
    }()

    public static func lookup(encoding: UInt16) -> A64SystemRegisterDescriptor? {
        byEncoding[encoding]
    }

    public static func name(forEncoding encoding: UInt16) -> String {
        if let known = byEncoding[encoding] {
            return known.name
        }
        let parts = unpackEncoding(encoding)
        return "S\(parts.op0)_\(parts.op1)_C\(parts.crn)_C\(parts.crm)_\(parts.op2)"
    }

    /// Parses either a known architectural name (e.g. `TPIDR_EL0`, `nzcv`) or generic `S3_3_C13_C0_2` syntax.
    public static func encoding(forName rawName: String) -> UInt16? {
        let trimmed = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if let known = byLowerName[lower] {
            return known
        }
        // Parse S<op0>_<op1>_C<crn>_C<crm>_<op2>
        let segments = lower.split(separator: "_")
        guard segments.count == 5,
              segments[0].hasPrefix("s"),
              segments[2].hasPrefix("c"),
              segments[3].hasPrefix("c"),
              let op0 = UInt32(segments[0].dropFirst()), (2...3).contains(op0),
              let op1 = UInt32(segments[1]), op1 <= 7,
              let crn = UInt32(segments[2].dropFirst()), crn <= 15,
              let crm = UInt32(segments[3].dropFirst()), crm <= 15,
              let op2 = UInt32(segments[4]), op2 <= 7
        else {
            return nil
        }
        return packEncoding(op0: op0, op1: op1, crn: crn, crm: crm, op2: op2)
    }
}

// MARK: - Barrier Options & Prefetch Operations

public enum A64BarrierOptionTable {
    public static func name(forCRm crm: UInt32) -> String {
        switch crm & 0xF {
        case 0x1: return "oshld"
        case 0x2: return "oshst"
        case 0x3: return "osh"
        case 0x5: return "nshld"
        case 0x6: return "nshst"
        case 0x7: return "nsh"
        case 0x9: return "ishld"
        case 0xA: return "ishst"
        case 0xB: return "ish"
        case 0xD: return "ld"
        case 0xE: return "st"
        case 0xF: return "sy"
        default: return "#\(crm & 0xF)"
        }
    }

    public static func architecturalName(forCRm crm: UInt32) -> String {
        let n = name(forCRm: crm)
        return n.hasPrefix("#") ? n : n.uppercased()
    }

    public static func crm(forText rawText: String) -> UInt32? {
        let lower = rawText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch lower {
        case "oshld": return 0x1
        case "oshst": return 0x2
        case "osh":   return 0x3
        case "nshld": return 0x5
        case "nshst": return 0x6
        case "nsh":   return 0x7
        case "ishld": return 0x9
        case "ishst": return 0xA
        case "ish":   return 0xB
        case "ld":    return 0xD
        case "st":    return 0xE
        case "sy":    return 0xF
        default:
            let stripped = lower.hasPrefix("#") ? String(lower.dropFirst()) : lower
            if stripped.hasPrefix("0x"), let v = UInt32(stripped.dropFirst(2), radix: 16), v <= 15 {
                return v
            }
            if let v = UInt32(stripped, radix: 10), v <= 15 {
                return v
            }
            return nil
        }
    }
}

public enum A64PrefetchOpTable {
    public static func name(forCode code: UInt32) -> String {
        let c = code & 0x1F
        let typePart = (c >> 3) & 0x3
        let targetPart = (c >> 1) & 0x3
        let policyPart = c & 0x1

        let typeStr: String?
        switch typePart {
        case 0: typeStr = "pld"
        case 1: typeStr = "pli"
        case 2: typeStr = "pst"
        default: typeStr = nil
        }

        let targetStr: String?
        switch targetPart {
        case 0: targetStr = "l1"
        case 1: targetStr = "l2"
        case 2: targetStr = "l3"
        default: targetStr = nil
        }

        if let t = typeStr, let tgt = targetStr {
            let pol = (policyPart == 0) ? "keep" : "strm"
            return "\(t)\(tgt)\(pol)"
        }
        return String(format: "#0x%02x", c)
    }

    public static func code(forText rawText: String) -> UInt32? {
        let lower = rawText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for code: UInt32 in 0..<32 {
            if name(forCode: code) == lower {
                return code
            }
        }
        let stripped = lower.hasPrefix("#") ? String(lower.dropFirst()) : lower
        if stripped.hasPrefix("0x"), let v = UInt32(stripped.dropFirst(2), radix: 16), v < 32 {
            return v
        }
        if let v = UInt32(stripped, radix: 10), v < 32 {
            return v
        }
        return nil
    }
}

// MARK: - PSTATE Immediate Fields & System Operation Names

public struct A64SysPreferredAlias: Sendable, Equatable {
    public let mnemonic: String
    public let operation: String?
    public let takesRegister: Bool

    public init(mnemonic: String, operation: String?, takesRegister: Bool) {
        self.mnemonic = mnemonic
        self.operation = operation
        self.takesRegister = takesRegister
    }
}

public enum A64SystemOpHelpers {
    public static func pstateFieldName(op1: UInt32, op2: UInt32) -> String? {
        switch (op1, op2) {
        case (0b000, 0b101): return "SPSel"
        case (0b011, 0b110): return "DAIFSet"
        case (0b011, 0b111): return "DAIFClr"
        case (0b000, 0b011): return "UAO"
        case (0b000, 0b100): return "PAN"
        case (0b011, 0b010): return "DIT"
        case (0b011, 0b001): return "SSBS"
        case (0b011, 0b100): return "TCO"
        default: return nil
        }
    }

    /// Preferred architectural / Apple LLVM alias for `SYS` (`op0 == 0b01`, `L == 0`) by instruction bitfields.
    public static func sysPreferredAlias(op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32) -> A64SysPreferredAlias? {
        switch (op1, crn, crm, op2) {
        // op1 = 0, CRn = 7: IC / DC / AT (EL1)
        case (0, 7, 1, 0):  return .init(mnemonic: "ic", operation: "ialluis", takesRegister: false)
        case (0, 7, 5, 0):  return .init(mnemonic: "ic", operation: "iallu", takesRegister: false)
        case (0, 7, 6, 1):  return .init(mnemonic: "dc", operation: "ivac", takesRegister: true)
        case (0, 7, 6, 2):  return .init(mnemonic: "dc", operation: "isw", takesRegister: true)
        case (0, 7, 8, 0):  return .init(mnemonic: "at", operation: "s1e1r", takesRegister: true)
        case (0, 7, 8, 1):  return .init(mnemonic: "at", operation: "s1e1w", takesRegister: true)
        case (0, 7, 8, 2):  return .init(mnemonic: "at", operation: "s1e0r", takesRegister: true)
        case (0, 7, 8, 3):  return .init(mnemonic: "at", operation: "s1e0w", takesRegister: true)
        case (0, 7, 9, 0):  return .init(mnemonic: "at", operation: "s1e1rp", takesRegister: true)
        case (0, 7, 9, 1):  return .init(mnemonic: "at", operation: "s1e1wp", takesRegister: true)
        case (0, 7, 9, 2):  return .init(mnemonic: "at", operation: "s1e1a", takesRegister: true)
        case (0, 7, 10, 2): return .init(mnemonic: "dc", operation: "csw", takesRegister: true)
        case (0, 7, 14, 2): return .init(mnemonic: "dc", operation: "cisw", takesRegister: true)

        // op1 = 0, CRn = 8: TLBI (EL1)
        case (0, 8, 1, 0):  return .init(mnemonic: "tlbi", operation: "vmalle1os", takesRegister: false)
        case (0, 8, 1, 1):  return .init(mnemonic: "tlbi", operation: "vae1os", takesRegister: true)
        case (0, 8, 1, 2):  return .init(mnemonic: "tlbi", operation: "aside1os", takesRegister: true)
        case (0, 8, 1, 3):  return .init(mnemonic: "tlbi", operation: "vaae1os", takesRegister: true)
        case (0, 8, 1, 5):  return .init(mnemonic: "tlbi", operation: "vale1os", takesRegister: true)
        case (0, 8, 1, 7):  return .init(mnemonic: "tlbi", operation: "vaale1os", takesRegister: true)
        case (0, 8, 2, 1):  return .init(mnemonic: "tlbi", operation: "rvae1is", takesRegister: true)
        case (0, 8, 2, 3):  return .init(mnemonic: "tlbi", operation: "rvaae1is", takesRegister: true)
        case (0, 8, 2, 5):  return .init(mnemonic: "tlbi", operation: "rvale1is", takesRegister: true)
        case (0, 8, 2, 7):  return .init(mnemonic: "tlbi", operation: "rvaale1is", takesRegister: true)
        case (0, 8, 3, 0):  return .init(mnemonic: "tlbi", operation: "vmalle1is", takesRegister: false)
        case (0, 8, 3, 1):  return .init(mnemonic: "tlbi", operation: "vae1is", takesRegister: true)
        case (0, 8, 3, 2):  return .init(mnemonic: "tlbi", operation: "aside1is", takesRegister: true)
        case (0, 8, 3, 3):  return .init(mnemonic: "tlbi", operation: "vaae1is", takesRegister: true)
        case (0, 8, 3, 5):  return .init(mnemonic: "tlbi", operation: "vale1is", takesRegister: true)
        case (0, 8, 3, 7):  return .init(mnemonic: "tlbi", operation: "vaale1is", takesRegister: true)
        case (0, 8, 5, 1):  return .init(mnemonic: "tlbi", operation: "rvae1os", takesRegister: true)
        case (0, 8, 5, 3):  return .init(mnemonic: "tlbi", operation: "rvaae1os", takesRegister: true)
        case (0, 8, 5, 5):  return .init(mnemonic: "tlbi", operation: "rvale1os", takesRegister: true)
        case (0, 8, 5, 7):  return .init(mnemonic: "tlbi", operation: "rvaale1os", takesRegister: true)
        case (0, 8, 6, 1):  return .init(mnemonic: "tlbi", operation: "rvae1", takesRegister: true)
        case (0, 8, 6, 3):  return .init(mnemonic: "tlbi", operation: "rvaae1", takesRegister: true)
        case (0, 8, 6, 5):  return .init(mnemonic: "tlbi", operation: "rvale1", takesRegister: true)
        case (0, 8, 6, 7):  return .init(mnemonic: "tlbi", operation: "rvaale1", takesRegister: true)
        case (0, 8, 7, 0):  return .init(mnemonic: "tlbi", operation: "vmalle1", takesRegister: false)
        case (0, 8, 7, 1):  return .init(mnemonic: "tlbi", operation: "vae1", takesRegister: true)
        case (0, 8, 7, 2):  return .init(mnemonic: "tlbi", operation: "aside1", takesRegister: true)
        case (0, 8, 7, 3):  return .init(mnemonic: "tlbi", operation: "vaae1", takesRegister: true)
        case (0, 8, 7, 5):  return .init(mnemonic: "tlbi", operation: "vale1", takesRegister: true)
        case (0, 8, 7, 7):  return .init(mnemonic: "tlbi", operation: "vaale1", takesRegister: true)

        // op1 = 3, CRn = 7: CFP / DVP / CPP / DC / IC (EL0)
        case (3, 7, 3, 4):  return .init(mnemonic: "cfp", operation: "rctx", takesRegister: true)
        case (3, 7, 3, 5):  return .init(mnemonic: "dvp", operation: "rctx", takesRegister: true)
        case (3, 7, 3, 7):  return .init(mnemonic: "cpp", operation: "rctx", takesRegister: true)
        case (3, 7, 4, 1):  return .init(mnemonic: "dc", operation: "zva", takesRegister: true)
        case (3, 7, 5, 1):  return .init(mnemonic: "ic", operation: "ivau", takesRegister: true)
        case (3, 7, 10, 1): return .init(mnemonic: "dc", operation: "cvac", takesRegister: true)
        case (3, 7, 11, 1): return .init(mnemonic: "dc", operation: "cvau", takesRegister: true)
        case (3, 7, 12, 1): return .init(mnemonic: "dc", operation: "cvap", takesRegister: true)
        case (3, 7, 13, 1): return .init(mnemonic: "dc", operation: "cvadp", takesRegister: true)
        case (3, 7, 14, 1): return .init(mnemonic: "dc", operation: "civac", takesRegister: true)

        // op1 = 4, CRn = 7: AT (EL2)
        case (4, 7, 8, 0):  return .init(mnemonic: "at", operation: "s1e2r", takesRegister: true)
        case (4, 7, 8, 1):  return .init(mnemonic: "at", operation: "s1e2w", takesRegister: true)
        case (4, 7, 8, 4):  return .init(mnemonic: "at", operation: "s12e1r", takesRegister: true)
        case (4, 7, 8, 5):  return .init(mnemonic: "at", operation: "s12e1w", takesRegister: true)
        case (4, 7, 8, 6):  return .init(mnemonic: "at", operation: "s12e0r", takesRegister: true)
        case (4, 7, 8, 7):  return .init(mnemonic: "at", operation: "s12e0w", takesRegister: true)
        case (4, 7, 9, 2):  return .init(mnemonic: "at", operation: "s1e2a", takesRegister: true)

        // op1 = 4, CRn = 8: TLBI (EL2 / Stage 2)
        case (4, 8, 0, 1):  return .init(mnemonic: "tlbi", operation: "ipas2e1is", takesRegister: true)
        case (4, 8, 0, 2):  return .init(mnemonic: "tlbi", operation: "ripas2e1is", takesRegister: true)
        case (4, 8, 0, 5):  return .init(mnemonic: "tlbi", operation: "ipas2le1is", takesRegister: true)
        case (4, 8, 0, 6):  return .init(mnemonic: "tlbi", operation: "ripas2le1is", takesRegister: true)
        case (4, 8, 1, 0):  return .init(mnemonic: "tlbi", operation: "alle2os", takesRegister: false)
        case (4, 8, 1, 1):  return .init(mnemonic: "tlbi", operation: "vae2os", takesRegister: true)
        case (4, 8, 1, 4):  return .init(mnemonic: "tlbi", operation: "alle1os", takesRegister: false)
        case (4, 8, 1, 5):  return .init(mnemonic: "tlbi", operation: "vale2os", takesRegister: true)
        case (4, 8, 1, 6):  return .init(mnemonic: "tlbi", operation: "vmalls12e1os", takesRegister: false)
        case (4, 8, 2, 1):  return .init(mnemonic: "tlbi", operation: "rvae2is", takesRegister: true)
        case (4, 8, 2, 5):  return .init(mnemonic: "tlbi", operation: "rvale2is", takesRegister: true)
        case (4, 8, 3, 0):  return .init(mnemonic: "tlbi", operation: "alle2is", takesRegister: false)
        case (4, 8, 3, 1):  return .init(mnemonic: "tlbi", operation: "vae2is", takesRegister: true)
        case (4, 8, 3, 4):  return .init(mnemonic: "tlbi", operation: "alle1is", takesRegister: false)
        case (4, 8, 3, 5):  return .init(mnemonic: "tlbi", operation: "vale2is", takesRegister: true)
        case (4, 8, 3, 6):  return .init(mnemonic: "tlbi", operation: "vmalls12e1is", takesRegister: false)
        case (4, 8, 4, 0):  return .init(mnemonic: "tlbi", operation: "ipas2e1os", takesRegister: true)
        case (4, 8, 4, 1):  return .init(mnemonic: "tlbi", operation: "ipas2e1", takesRegister: true)
        case (4, 8, 4, 2):  return .init(mnemonic: "tlbi", operation: "ripas2e1", takesRegister: true)
        case (4, 8, 4, 3):  return .init(mnemonic: "tlbi", operation: "ripas2e1os", takesRegister: true)
        case (4, 8, 4, 4):  return .init(mnemonic: "tlbi", operation: "ipas2le1os", takesRegister: true)
        case (4, 8, 4, 5):  return .init(mnemonic: "tlbi", operation: "ipas2le1", takesRegister: true)
        case (4, 8, 4, 6):  return .init(mnemonic: "tlbi", operation: "ripas2le1", takesRegister: true)
        case (4, 8, 4, 7):  return .init(mnemonic: "tlbi", operation: "ripas2le1os", takesRegister: true)
        case (4, 8, 5, 1):  return .init(mnemonic: "tlbi", operation: "rvae2os", takesRegister: true)
        case (4, 8, 5, 5):  return .init(mnemonic: "tlbi", operation: "rvale2os", takesRegister: true)
        case (4, 8, 6, 1):  return .init(mnemonic: "tlbi", operation: "rvae2", takesRegister: true)
        case (4, 8, 6, 5):  return .init(mnemonic: "tlbi", operation: "rvale2", takesRegister: true)
        case (4, 8, 7, 0):  return .init(mnemonic: "tlbi", operation: "alle2", takesRegister: false)
        case (4, 8, 7, 1):  return .init(mnemonic: "tlbi", operation: "vae2", takesRegister: true)
        case (4, 8, 7, 4):  return .init(mnemonic: "tlbi", operation: "alle1", takesRegister: false)
        case (4, 8, 7, 5):  return .init(mnemonic: "tlbi", operation: "vale2", takesRegister: true)
        case (4, 8, 7, 6):  return .init(mnemonic: "tlbi", operation: "vmalls12e1", takesRegister: false)

        // op1 = 6, CRn = 7: APAS / AT (EL3)
        case (6, 7, 0, 0):  return .init(mnemonic: "apas", operation: nil, takesRegister: true)
        case (6, 7, 8, 0):  return .init(mnemonic: "at", operation: "s1e3r", takesRegister: true)
        case (6, 7, 8, 1):  return .init(mnemonic: "at", operation: "s1e3w", takesRegister: true)
        case (6, 7, 9, 2):  return .init(mnemonic: "at", operation: "s1e3a", takesRegister: true)

        // op1 = 6, CRn = 8: TLBI (EL3)
        case (6, 8, 1, 0):  return .init(mnemonic: "tlbi", operation: "alle3os", takesRegister: false)
        case (6, 8, 1, 1):  return .init(mnemonic: "tlbi", operation: "vae3os", takesRegister: true)
        case (6, 8, 1, 5):  return .init(mnemonic: "tlbi", operation: "vale3os", takesRegister: true)
        case (6, 8, 2, 1):  return .init(mnemonic: "tlbi", operation: "rvae3is", takesRegister: true)
        case (6, 8, 2, 5):  return .init(mnemonic: "tlbi", operation: "rvale3is", takesRegister: true)
        case (6, 8, 3, 0):  return .init(mnemonic: "tlbi", operation: "alle3is", takesRegister: false)
        case (6, 8, 3, 1):  return .init(mnemonic: "tlbi", operation: "vae3is", takesRegister: true)
        case (6, 8, 3, 5):  return .init(mnemonic: "tlbi", operation: "vale3is", takesRegister: true)
        case (6, 8, 5, 1):  return .init(mnemonic: "tlbi", operation: "rvae3os", takesRegister: true)
        case (6, 8, 5, 5):  return .init(mnemonic: "tlbi", operation: "rvale3os", takesRegister: true)
        case (6, 8, 6, 1):  return .init(mnemonic: "tlbi", operation: "rvae3", takesRegister: true)
        case (6, 8, 6, 5):  return .init(mnemonic: "tlbi", operation: "rvale3", takesRegister: true)
        case (6, 8, 7, 0):  return .init(mnemonic: "tlbi", operation: "alle3", takesRegister: false)
        case (6, 8, 7, 1):  return .init(mnemonic: "tlbi", operation: "vae3", takesRegister: true)
        case (6, 8, 7, 5):  return .init(mnemonic: "tlbi", operation: "vale3", takesRegister: true)

        default:
            return nil
        }
    }

    public static func sysMaintenanceAlias(op1: UInt32, crn: UInt32, crm: UInt32, op2: UInt32) -> String? {
        guard let preferred = sysPreferredAlias(op1: op1, crn: crn, crm: crm, op2: op2) else {
            return nil
        }
        if let op = preferred.operation {
            return "\(preferred.mnemonic) \(op)"
        }
        return preferred.mnemonic
    }
}

// MARK: - Register, Shift & Extend Text Parsers (Shared with Inline Assembler)

public enum A64RegisterParser {
    /// Parses canonical & ABI register names (`x0`..`x30`, `w0`..`w30`, `fp`, `lr`, `sp`, `wsp`, `xzr`, `wzr`,
    /// `b0`..`b31`, `h0`..`h31`, `s0`..`s31`, `d0`..`d31`, `q0`..`q31`, `v0.16b`, etc.).
    public static func parse(_ rawToken: String) -> A64Register? {
        let lower = rawToken.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch lower {
        case "sp": return .sp
        case "wsp": return .wsp
        case "xzr": return .xzr
        case "wzr": return .wzr
        case "fp": return .x(29)
        case "lr": return .x(30)
        case "pc": return .pc
        case "nzcv": return .nzcv
        default: break
        }

        if lower.hasPrefix("v"), let dotIdx = lower.firstIndex(of: ".") {
            let numStr = lower[lower.index(after: lower.startIndex)..<dotIdx]
            let arrStr = String(lower[lower.index(after: dotIdx)...])
            let validArrs: Set<String> = ["8b", "16b", "4h", "8h", "2s", "4s", "1d", "2d", "b", "h", "s", "d"]
            if let idx = UInt8(numStr), idx <= 31, validArrs.contains(arrStr) {
                return .v(idx, arrangement: arrStr)
            }
            return nil
        }

        guard let prefix = lower.first else { return nil }
        let digits = lower.dropFirst()
        guard let idx = UInt8(digits), idx <= 31 else { return nil }

        switch prefix {
        case "x":
            return idx <= 30 ? .x(idx) : nil
        case "w":
            return idx <= 30 ? .w(idx) : nil
        case "b":
            return .b(idx)
        case "h":
            return .h(idx)
        case "s":
            return .s(idx)
        case "d":
            return .d(idx)
        case "q":
            return .q(idx)
        default:
            return nil
        }
    }
}

public enum A64ShiftExtendParser {
    /// Parses a shift or extend modifier clause such as `"lsl #12"`, `"asr #3"`, `"uxtw #2"`, `"sxtx"`.
    public static func parse(_ rawClause: String) -> A64ShiftExtend? {
        let trimmed = rawClause.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parts = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard let opToken = parts.first else { return nil }

        let amount: UInt8
        if parts.count == 1 {
            amount = 0
        } else if parts.count == 2 {
            var numText = String(parts[1])
            if numText.hasPrefix("#") {
                numText.removeFirst()
            }
            let parsedVal: UInt8?
            if numText.hasPrefix("0x") {
                parsedVal = UInt8(numText.dropFirst(2), radix: 16)
            } else {
                parsedVal = UInt8(numText, radix: 10)
            }
            guard let v = parsedVal, v <= 63 else { return nil }
            amount = v
        } else {
            return nil
        }

        switch opToken {
        case "lsl":
            guard parts.count == 2 else { return nil }
            return .lsl(amount)
        case "lsr":
            guard parts.count == 2 else { return nil }
            return .lsr(amount)
        case "asr":
            guard parts.count == 2 else { return nil }
            return .asr(amount)
        case "ror":
            guard parts.count == 2 else { return nil }
            return .ror(amount)
        case "uxtb": return .uxtb(amount)
        case "uxth": return .uxth(amount)
        case "uxtw": return .uxtw(amount)
        case "uxtx": return .uxtx(amount)
        case "sxtb": return .sxtb(amount)
        case "sxth": return .sxth(amount)
        case "sxtw": return .sxtw(amount)
        case "sxtx": return .sxtx(amount)
        default: return nil
        }
    }

    /// Encodes an extended-register option code (`0...7`) and 3-bit shift (`0...4`).
    public static func encodeExtendOption(_ ext: A64ShiftExtend) -> (option: UInt32, imm3: UInt32)? {
        switch ext {
        case .uxtb(let s) where s <= 4: return (0b000, UInt32(s))
        case .uxth(let s) where s <= 4: return (0b001, UInt32(s))
        case .uxtw(let s) where s <= 4: return (0b010, UInt32(s))
        case .uxtx(let s) where s <= 4: return (0b011, UInt32(s))
        case .sxtb(let s) where s <= 4: return (0b100, UInt32(s))
        case .sxth(let s) where s <= 4: return (0b101, UInt32(s))
        case .sxtw(let s) where s <= 4: return (0b110, UInt32(s))
        case .sxtx(let s) where s <= 4: return (0b111, UInt32(s))
        default: return nil
        }
    }

    /// Decodes a 3-bit `option` and shift amount into `A64ShiftExtend`.
    public static func decodeExtendOption(option: UInt32, shift: UInt8) -> A64ShiftExtend {
        switch option & 0x7 {
        case 0b000: return .uxtb(shift)
        case 0b001: return .uxth(shift)
        case 0b010: return .uxtw(shift)
        case 0b011: return .uxtx(shift)
        case 0b100: return .sxtb(shift)
        case 0b101: return .sxth(shift)
        case 0b110: return .sxtw(shift)
        default:    return .sxtx(shift)
        }
    }
}

// MARK: - Darwin XNU ARM64 BSD/Mach Syscall Metadata Helper

public enum A64DarwinSyscallTable {
    public static func bsdOrMachSyscallName(forX16 rawNumber: Int64) -> String? {
        // Negative numbers on Darwin ARM64 are Mach traps (e.g. -26 = mach_reply_port, -31 = mach_msg_trap)
        if rawNumber < 0 {
            switch rawNumber {
            case -10: return "kernelrpc_mach_vm_allocate_trap"
            case -12: return "kernelrpc_mach_vm_deallocate_trap"
            case -14: return "kernelrpc_mach_vm_protect_trap"
            case -15: return "kernelrpc_mach_vm_map_trap"
            case -16: return "kernelrpc_mach_port_allocate_trap"
            case -18: return "kernelrpc_mach_port_deallocate_trap"
            case -26: return "mach_reply_port"
            case -27: return "thread_self_trap"
            case -28: return "task_self_trap"
            case -29: return "host_self_trap"
            case -31: return "mach_msg_trap"
            case -32: return "mach_msg_overwrite_trap"
            case -36: return "semaphore_wait_trap"
            case -33: return "semaphore_signal_trap"
            case -47: return "mach_msg2_trap"
            default: return nil
            }
        }

        // BSD syscalls (positive or masked with 0x2000000 class prefix)
        let num = rawNumber & 0xFFFF
        switch num {
        case 0: return "syscall"
        case 1: return "exit"
        case 2: return "fork"
        case 3: return "read"
        case 4: return "write"
        case 5: return "open"
        case 6: return "close"
        case 20: return "getpid"
        case 24: return "getuid"
        case 26: return "ptrace"
        case 33: return "access"
        case 37: return "kill"
        case 39: return "getppid"
        case 46: return "sigaction"
        case 54: return "ioctl"
        case 59: return "execve"
        case 73: return "munmap"
        case 74: return "mprotect"
        case 92: return "fcntl"
        case 97: return "socket"
        case 98: return "connect"
        case 197: return "mmap"
        case 202: return "sysctl"
        case 328: return "__pthread_kill"
        case 338: return "stat64"
        case 396: return "open_nocancel"
        case 500: return "getentropy"
        default: return nil
        }
    }
}
