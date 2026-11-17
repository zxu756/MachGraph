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
    public let isReadable: Bool
    public let isWritable: Bool

    public init(
        name: String,
        op0: UInt8,
        op1: UInt8,
        crn: UInt8,
        crm: UInt8,
        op2: UInt8,
        summary: String,
        isReadable: Bool = true,
        isWritable: Bool = true
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
        self.isReadable = isReadable
        self.isWritable = isWritable
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

    private static let curatedSummaries: [String: String] = [
        "MDSCR_EL1": "Monitor Debug System Control Register",
        "MIDR_EL1": "Main ID Register",
        "MPIDR_EL1": "Multiprocessor Affinity Register",
        "REVIDR_EL1": "Revision ID Register",
        "ID_AA64PFR0_EL1": "AArch64 Processor Feature Register 0",
        "ID_AA64PFR1_EL1": "AArch64 Processor Feature Register 1",
        "ID_AA64DFR0_EL1": "AArch64 Debug Feature Register 0",
        "ID_AA64ISAR0_EL1": "AArch64 Instruction Set Attribute Register 0",
        "ID_AA64ISAR1_EL1": "AArch64 Instruction Set Attribute Register 1",
        "ID_AA64ISAR2_EL1": "AArch64 Instruction Set Attribute Register 2",
        "ID_AA64MMFR0_EL1": "AArch64 Memory Model Feature Register 0",
        "ID_AA64MMFR1_EL1": "AArch64 Memory Model Feature Register 1",
        "ID_AA64MMFR2_EL1": "AArch64 Memory Model Feature Register 2",
        "SCTLR_EL1": "System Control Register (EL1)",
        "ACTLR_EL1": "Auxiliary Control Register (EL1)",
        "CPACR_EL1": "Architectural Feature Access Control Register",
        "TTBR0_EL1": "Translation Table Base Register 0 (EL1)",
        "TTBR1_EL1": "Translation Table Base Register 1 (EL1)",
        "TCR_EL1": "Translation Control Register (EL1)",
        "APIAKeyLo_EL1": "PAC Instruction Key A (Low 64 bits)",
        "APIAKeyHi_EL1": "PAC Instruction Key A (High 64 bits)",
        "APIBKeyLo_EL1": "PAC Instruction Key B (Low 64 bits)",
        "APIBKeyHi_EL1": "PAC Instruction Key B (High 64 bits)",
        "APDAKeyLo_EL1": "PAC Data Key A (Low 64 bits)",
        "APDAKeyHi_EL1": "PAC Data Key A (High 64 bits)",
        "APDBKeyLo_EL1": "PAC Data Key B (Low 64 bits)",
        "APDBKeyHi_EL1": "PAC Data Key B (High 64 bits)",
        "APGAKeyLo_EL1": "PAC Generic Key A (Low 64 bits)",
        "APGAKeyHi_EL1": "PAC Generic Key A (High 64 bits)",
        "SPSR_EL1": "Saved Program Status Register (EL1)",
        "ELR_EL1": "Exception Link Register (EL1)",
        "SP_EL0": "Stack Pointer (EL0)",
        "SPSel": "Stack Pointer Select",
        "CurrentEL": "Current Exception Level",
        "PAN": "Privileged Access Never",
        "UAO": "User Access Override",
        "ESR_EL1": "Exception Syndrome Register (EL1)",
        "FAR_EL1": "Fault Address Register (EL1)",
        "PAR_EL1": "Physical Address Register (EL1)",
        "MAIR_EL1": "Memory Attribute Indirection Register (EL1)",
        "VBAR_EL1": "Vector Base Address Register (EL1)",
        "CONTEXTIDR_EL1": "Context ID Register (EL1)",
        "TPIDR_EL1": "EL1 Software Thread ID Register",
        "CTR_EL0": "Cache Type Register",
        "DCZID_EL0": "Data Cache Zero ID Register",
        "NZCV": "Condition Flags (N, Z, C, V)",
        "DAIF": "Interrupt Mask Bits (D, A, I, F)",
        "DIT": "Data Independent Timing",
        "SSBS": "Speculative Store Bypass Safe",
        "FPCR": "Floating-Point Control Register",
        "FPSR": "Floating-Point Status Register",
        "DSPSR_EL0": "Debug Saved Program Status Register",
        "DLR_EL0": "Debug Link Register",
        "PMCR_EL0": "Performance Monitors Control Register",
        "PMCNTENSET_EL0": "Performance Monitors Count Enable Set",
        "PMCCNTR_EL0": "Performance Monitors Cycle Count Register",
        "TPIDR_EL0": "EL0 Read/Write Software Thread ID (TLS base)",
        "TPIDRRO_EL0": "EL0 Read-Only Software Thread ID (pthread self)",
        "CNTFRQ_EL0": "Counter-Timer Frequency Register",
        "CNTPCT_EL0": "Counter-Timer Physical Count Register",
        "CNTVCT_EL0": "Counter-Timer Virtual Count Register (mach_absolute_time)",
        "CNTP_TVAL_EL0": "Counter-Timer Physical Timer TimerValue",
        "CNTP_CTL_EL0": "Counter-Timer Physical Timer Control",
        "CNTP_CVAL_EL0": "Counter-Timer Physical Timer CompareValue",
        "CNTV_TVAL_EL0": "Counter-Timer Virtual Timer TimerValue",
        "CNTV_CTL_EL0": "Counter-Timer Virtual Timer Control",
        "CNTV_CVAL_EL0": "Counter-Timer Virtual Timer CompareValue",
        "SP_EL1": "Stack Pointer (EL1)",
        "TPIDR_EL2": "EL2 Software Thread ID Register",
        "TPIDR_EL3": "EL3 Software Thread ID Register",
    ]

    /// Complete Apple LLVM (`--mcpu=apple-m1 --mattr=+bti`) system-register catalog across all 32,768
    /// `(op0 in 2...3, op1, CRn, CRm, op2)` MRS/MSR encodings (`rw` = read/write, `ro` = MRS-only, `wo` = MSR-only).
    private static let rawCatalog: String = """
    2 0 0 0 2 rw OSDTRRX_EL1
    2 0 0 0 4 rw DBGBVR0_EL1
    2 0 0 0 5 rw DBGBCR0_EL1
    2 0 0 0 6 rw DBGWVR0_EL1
    2 0 0 0 7 rw DBGWCR0_EL1
    2 0 0 1 4 rw DBGBVR1_EL1
    2 0 0 1 5 rw DBGBCR1_EL1
    2 0 0 1 6 rw DBGWVR1_EL1
    2 0 0 1 7 rw DBGWCR1_EL1
    2 0 0 2 0 rw MDCCINT_EL1
    2 0 0 2 2 rw MDSCR_EL1
    2 0 0 2 4 rw DBGBVR2_EL1
    2 0 0 2 5 rw DBGBCR2_EL1
    2 0 0 2 6 rw DBGWVR2_EL1
    2 0 0 2 7 rw DBGWCR2_EL1
    2 0 0 3 2 rw OSDTRTX_EL1
    2 0 0 3 4 rw DBGBVR3_EL1
    2 0 0 3 5 rw DBGBCR3_EL1
    2 0 0 3 6 rw DBGWVR3_EL1
    2 0 0 3 7 rw DBGWCR3_EL1
    2 0 0 4 2 rw MDSELR_EL1
    2 0 0 4 4 rw DBGBVR4_EL1
    2 0 0 4 5 rw DBGBCR4_EL1
    2 0 0 4 6 rw DBGWVR4_EL1
    2 0 0 4 7 rw DBGWCR4_EL1
    2 0 0 5 2 rw MDSTEPOP_EL1
    2 0 0 5 4 rw DBGBVR5_EL1
    2 0 0 5 5 rw DBGBCR5_EL1
    2 0 0 5 6 rw DBGWVR5_EL1
    2 0 0 5 7 rw DBGWCR5_EL1
    2 0 0 6 2 rw OSECCR_EL1
    2 0 0 6 4 rw DBGBVR6_EL1
    2 0 0 6 5 rw DBGBCR6_EL1
    2 0 0 6 6 rw DBGWVR6_EL1
    2 0 0 6 7 rw DBGWCR6_EL1
    2 0 0 7 4 rw DBGBVR7_EL1
    2 0 0 7 5 rw DBGBCR7_EL1
    2 0 0 7 6 rw DBGWVR7_EL1
    2 0 0 7 7 rw DBGWCR7_EL1
    2 0 0 8 4 rw DBGBVR8_EL1
    2 0 0 8 5 rw DBGBCR8_EL1
    2 0 0 8 6 rw DBGWVR8_EL1
    2 0 0 8 7 rw DBGWCR8_EL1
    2 0 0 9 4 rw DBGBVR9_EL1
    2 0 0 9 5 rw DBGBCR9_EL1
    2 0 0 9 6 rw DBGWVR9_EL1
    2 0 0 9 7 rw DBGWCR9_EL1
    2 0 0 10 4 rw DBGBVR10_EL1
    2 0 0 10 5 rw DBGBCR10_EL1
    2 0 0 10 6 rw DBGWVR10_EL1
    2 0 0 10 7 rw DBGWCR10_EL1
    2 0 0 11 4 rw DBGBVR11_EL1
    2 0 0 11 5 rw DBGBCR11_EL1
    2 0 0 11 6 rw DBGWVR11_EL1
    2 0 0 11 7 rw DBGWCR11_EL1
    2 0 0 12 4 rw DBGBVR12_EL1
    2 0 0 12 5 rw DBGBCR12_EL1
    2 0 0 12 6 rw DBGWVR12_EL1
    2 0 0 12 7 rw DBGWCR12_EL1
    2 0 0 13 4 rw DBGBVR13_EL1
    2 0 0 13 5 rw DBGBCR13_EL1
    2 0 0 13 6 rw DBGWVR13_EL1
    2 0 0 13 7 rw DBGWCR13_EL1
    2 0 0 14 4 rw DBGBVR14_EL1
    2 0 0 14 5 rw DBGBCR14_EL1
    2 0 0 14 6 rw DBGWVR14_EL1
    2 0 0 14 7 rw DBGWCR14_EL1
    2 0 0 15 4 rw DBGBVR15_EL1
    2 0 0 15 5 rw DBGBCR15_EL1
    2 0 0 15 6 rw DBGWVR15_EL1
    2 0 0 15 7 rw DBGWCR15_EL1
    2 0 1 0 0 ro MDRAR_EL1
    2 0 1 0 4 wo OSLAR_EL1
    2 0 1 1 4 ro OSLSR_EL1
    2 0 1 3 4 rw OSDLR_EL1
    2 0 1 4 4 rw DBGPRCR_EL1
    2 0 7 8 6 rw DBGCLAIMSET_EL1
    2 0 7 9 6 rw DBGCLAIMCLR_EL1
    2 0 7 14 6 ro DBGAUTHSTATUS_EL1
    2 0 9 13 0 ro SPMCGCR0_EL1
    2 0 9 13 1 ro SPMCGCR1_EL1
    2 0 9 13 3 rw SPMACCESSR_EL1
    2 0 9 13 4 ro SPMIIDR_EL1
    2 0 9 13 5 ro SPMDEVARCH_EL1
    2 0 9 13 6 ro SPMDEVAFF_EL1
    2 0 9 13 7 ro SPMCFGR_EL1
    2 0 9 14 1 rw SPMINTENSET_EL1
    2 0 9 14 2 rw SPMINTENCLR_EL1
    2 0 14 8 0 ro PMEVCNTSVR0_EL1
    2 0 14 8 1 ro PMEVCNTSVR1_EL1
    2 0 14 8 2 ro PMEVCNTSVR2_EL1
    2 0 14 8 3 ro PMEVCNTSVR3_EL1
    2 0 14 8 4 ro PMEVCNTSVR4_EL1
    2 0 14 8 5 ro PMEVCNTSVR5_EL1
    2 0 14 8 6 ro PMEVCNTSVR6_EL1
    2 0 14 8 7 ro PMEVCNTSVR7_EL1
    2 0 14 9 0 ro PMEVCNTSVR8_EL1
    2 0 14 9 1 ro PMEVCNTSVR9_EL1
    2 0 14 9 2 ro PMEVCNTSVR10_EL1
    2 0 14 9 3 ro PMEVCNTSVR11_EL1
    2 0 14 9 4 ro PMEVCNTSVR12_EL1
    2 0 14 9 5 ro PMEVCNTSVR13_EL1
    2 0 14 9 6 ro PMEVCNTSVR14_EL1
    2 0 14 9 7 ro PMEVCNTSVR15_EL1
    2 0 14 10 0 ro PMEVCNTSVR16_EL1
    2 0 14 10 1 ro PMEVCNTSVR17_EL1
    2 0 14 10 2 ro PMEVCNTSVR18_EL1
    2 0 14 10 3 ro PMEVCNTSVR19_EL1
    2 0 14 10 4 ro PMEVCNTSVR20_EL1
    2 0 14 10 5 ro PMEVCNTSVR21_EL1
    2 0 14 10 6 ro PMEVCNTSVR22_EL1
    2 0 14 10 7 ro PMEVCNTSVR23_EL1
    2 0 14 11 0 ro PMEVCNTSVR24_EL1
    2 0 14 11 1 ro PMEVCNTSVR25_EL1
    2 0 14 11 2 ro PMEVCNTSVR26_EL1
    2 0 14 11 3 ro PMEVCNTSVR27_EL1
    2 0 14 11 4 ro PMEVCNTSVR28_EL1
    2 0 14 11 5 ro PMEVCNTSVR29_EL1
    2 0 14 11 6 ro PMEVCNTSVR30_EL1
    2 0 14 11 7 ro PMCCNTSVR_EL1
    2 0 14 12 0 ro PMICNTSVR_EL1
    2 1 0 0 1 rw TRCTRACEIDR
    2 1 0 0 2 rw TRCVICTLR
    2 1 0 0 4 rw TRCSEQEVR0
    2 1 0 0 5 rw TRCCNTRLDVR0
    2 1 0 0 6 ro TRCIDR8
    2 1 0 0 7 rw TRCIMSPEC0
    2 1 0 1 0 rw TRCPRGCTLR
    2 1 0 1 1 rw TRCQCTLR
    2 1 0 1 2 rw TRCVIIECTLR
    2 1 0 1 4 rw TRCSEQEVR1
    2 1 0 1 5 rw TRCCNTRLDVR1
    2 1 0 1 6 ro TRCIDR9
    2 1 0 1 7 rw TRCIMSPEC1
    2 1 0 2 0 rw TRCPROCSELR
    2 1 0 2 2 rw TRCVISSCTLR
    2 1 0 2 4 rw TRCSEQEVR2
    2 1 0 2 5 rw TRCCNTRLDVR2
    2 1 0 2 6 ro TRCIDR10
    2 1 0 2 7 rw TRCIMSPEC2
    2 1 0 3 0 ro TRCSTATR
    2 1 0 3 2 rw TRCVIPCSSCTLR
    2 1 0 3 5 rw TRCCNTRLDVR3
    2 1 0 3 6 ro TRCIDR11
    2 1 0 3 7 rw TRCIMSPEC3
    2 1 0 4 0 rw TRCCONFIGR
    2 1 0 4 5 rw TRCCNTCTLR0
    2 1 0 4 6 ro TRCIDR12
    2 1 0 4 7 rw TRCIMSPEC4
    2 1 0 5 5 rw TRCCNTCTLR1
    2 1 0 5 6 ro TRCIDR13
    2 1 0 5 7 rw TRCIMSPEC5
    2 1 0 6 0 rw TRCAUXCTLR
    2 1 0 6 4 rw TRCSEQRSTEVR
    2 1 0 6 5 rw TRCCNTCTLR2
    2 1 0 6 7 rw TRCIMSPEC6
    2 1 0 7 4 rw TRCSEQSTR
    2 1 0 7 5 rw TRCCNTCTLR3
    2 1 0 7 7 rw TRCIMSPEC7
    2 1 0 8 0 rw TRCEVENTCTL0R
    2 1 0 8 2 rw TRCVDCTLR
    2 1 0 8 4 rw TRCEXTINSELR
    2 1 0 8 5 rw TRCCNTVR0
    2 1 0 8 7 ro TRCIDR0
    2 1 0 9 0 rw TRCEVENTCTL1R
    2 1 0 9 2 rw TRCVDSACCTLR
    2 1 0 9 5 rw TRCCNTVR1
    2 1 0 9 7 ro TRCIDR1
    2 1 0 10 2 rw TRCVDARCCTLR
    2 1 0 10 5 rw TRCCNTVR2
    2 1 0 10 7 ro TRCIDR2
    2 1 0 11 0 rw TRCSTALLCTLR
    2 1 0 11 5 rw TRCCNTVR3
    2 1 0 11 7 ro TRCIDR3
    2 1 0 12 0 rw TRCTSCTLR
    2 1 0 12 7 ro TRCIDR4
    2 1 0 13 0 rw TRCSYNCPR
    2 1 0 13 7 ro TRCIDR5
    2 1 0 14 0 rw TRCCCCTLR
    2 1 0 14 7 ro TRCIDR6
    2 1 0 15 0 rw TRCBBCTLR
    2 1 0 15 7 ro TRCIDR7
    2 1 1 0 1 rw TRCRSCTLR16
    2 1 1 0 2 rw TRCSSCCR0
    2 1 1 0 3 rw TRCSSPCICR0
    2 1 1 0 4 wo TRCOSLAR
    2 1 1 1 1 rw TRCRSCTLR17
    2 1 1 1 2 rw TRCSSCCR1
    2 1 1 1 3 rw TRCSSPCICR1
    2 1 1 1 4 ro TRCOSLSR
    2 1 1 2 0 rw TRCRSCTLR2
    2 1 1 2 1 rw TRCRSCTLR18
    2 1 1 2 2 rw TRCSSCCR2
    2 1 1 2 3 rw TRCSSPCICR2
    2 1 1 3 0 rw TRCRSCTLR3
    2 1 1 3 1 rw TRCRSCTLR19
    2 1 1 3 2 rw TRCSSCCR3
    2 1 1 3 3 rw TRCSSPCICR3
    2 1 1 4 0 rw TRCRSCTLR4
    2 1 1 4 1 rw TRCRSCTLR20
    2 1 1 4 2 rw TRCSSCCR4
    2 1 1 4 3 rw TRCSSPCICR4
    2 1 1 4 4 rw TRCPDCR
    2 1 1 5 0 rw TRCRSCTLR5
    2 1 1 5 1 rw TRCRSCTLR21
    2 1 1 5 2 rw TRCSSCCR5
    2 1 1 5 3 rw TRCSSPCICR5
    2 1 1 5 4 ro TRCPDSR
    2 1 1 6 0 rw TRCRSCTLR6
    2 1 1 6 1 rw TRCRSCTLR22
    2 1 1 6 2 rw TRCSSCCR6
    2 1 1 6 3 rw TRCSSPCICR6
    2 1 1 7 0 rw TRCRSCTLR7
    2 1 1 7 1 rw TRCRSCTLR23
    2 1 1 7 2 rw TRCSSCCR7
    2 1 1 7 3 rw TRCSSPCICR7
    2 1 1 8 0 rw TRCRSCTLR8
    2 1 1 8 1 rw TRCRSCTLR24
    2 1 1 8 2 rw TRCSSCSR0
    2 1 1 9 0 rw TRCRSCTLR9
    2 1 1 9 1 rw TRCRSCTLR25
    2 1 1 9 2 rw TRCSSCSR1
    2 1 1 10 0 rw TRCRSCTLR10
    2 1 1 10 1 rw TRCRSCTLR26
    2 1 1 10 2 rw TRCSSCSR2
    2 1 1 11 0 rw TRCRSCTLR11
    2 1 1 11 1 rw TRCRSCTLR27
    2 1 1 11 2 rw TRCSSCSR3
    2 1 1 12 0 rw TRCRSCTLR12
    2 1 1 12 1 rw TRCRSCTLR28
    2 1 1 12 2 rw TRCSSCSR4
    2 1 1 13 0 rw TRCRSCTLR13
    2 1 1 13 1 rw TRCRSCTLR29
    2 1 1 13 2 rw TRCSSCSR5
    2 1 1 14 0 rw TRCRSCTLR14
    2 1 1 14 1 rw TRCRSCTLR30
    2 1 1 14 2 rw TRCSSCSR6
    2 1 1 15 0 rw TRCRSCTLR15
    2 1 1 15 1 rw TRCRSCTLR31
    2 1 1 15 2 rw TRCSSCSR7
    2 1 2 0 0 rw TRCACVR0
    2 1 2 0 1 rw TRCACVR8
    2 1 2 0 2 rw TRCACATR0
    2 1 2 0 3 rw TRCACATR8
    2 1 2 0 4 rw TRCDVCVR0
    2 1 2 0 5 rw TRCDVCVR4
    2 1 2 0 6 rw TRCDVCMR0
    2 1 2 0 7 rw TRCDVCMR4
    2 1 2 2 0 rw TRCACVR1
    2 1 2 2 1 rw TRCACVR9
    2 1 2 2 2 rw TRCACATR1
    2 1 2 2 3 rw TRCACATR9
    2 1 2 4 0 rw TRCACVR2
    2 1 2 4 1 rw TRCACVR10
    2 1 2 4 2 rw TRCACATR2
    2 1 2 4 3 rw TRCACATR10
    2 1 2 4 4 rw TRCDVCVR1
    2 1 2 4 5 rw TRCDVCVR5
    2 1 2 4 6 rw TRCDVCMR1
    2 1 2 4 7 rw TRCDVCMR5
    2 1 2 6 0 rw TRCACVR3
    2 1 2 6 1 rw TRCACVR11
    2 1 2 6 2 rw TRCACATR3
    2 1 2 6 3 rw TRCACATR11
    2 1 2 8 0 rw TRCACVR4
    2 1 2 8 1 rw TRCACVR12
    2 1 2 8 2 rw TRCACATR4
    2 1 2 8 3 rw TRCACATR12
    2 1 2 8 4 rw TRCDVCVR2
    2 1 2 8 5 rw TRCDVCVR6
    2 1 2 8 6 rw TRCDVCMR2
    2 1 2 8 7 rw TRCDVCMR6
    2 1 2 10 0 rw TRCACVR5
    2 1 2 10 1 rw TRCACVR13
    2 1 2 10 2 rw TRCACATR5
    2 1 2 10 3 rw TRCACATR13
    2 1 2 12 0 rw TRCACVR6
    2 1 2 12 1 rw TRCACVR14
    2 1 2 12 2 rw TRCACATR6
    2 1 2 12 3 rw TRCACATR14
    2 1 2 12 4 rw TRCDVCVR3
    2 1 2 12 5 rw TRCDVCVR7
    2 1 2 12 6 rw TRCDVCMR3
    2 1 2 12 7 rw TRCDVCMR7
    2 1 2 14 0 rw TRCACVR7
    2 1 2 14 1 rw TRCACVR15
    2 1 2 14 2 rw TRCACATR7
    2 1 2 14 3 rw TRCACATR15
    2 1 3 0 0 rw TRCCIDCVR0
    2 1 3 0 1 rw TRCVMIDCVR0
    2 1 3 0 2 rw TRCCIDCCTLR0
    2 1 3 1 2 rw TRCCIDCCTLR1
    2 1 3 2 0 rw TRCCIDCVR1
    2 1 3 2 1 rw TRCVMIDCVR1
    2 1 3 2 2 rw TRCVMIDCCTLR0
    2 1 3 3 2 rw TRCVMIDCCTLR1
    2 1 3 4 0 rw TRCCIDCVR2
    2 1 3 4 1 rw TRCVMIDCVR2
    2 1 3 6 0 rw TRCCIDCVR3
    2 1 3 6 1 rw TRCVMIDCVR3
    2 1 3 8 0 rw TRCCIDCVR4
    2 1 3 8 1 rw TRCVMIDCVR4
    2 1 3 10 0 rw TRCCIDCVR5
    2 1 3 10 1 rw TRCVMIDCVR5
    2 1 3 12 0 rw TRCCIDCVR6
    2 1 3 12 1 rw TRCVMIDCVR6
    2 1 3 14 0 rw TRCCIDCVR7
    2 1 3 14 1 rw TRCVMIDCVR7
    2 1 7 0 4 rw TRCITCTRL
    2 1 7 2 7 ro TRCDEVID
    2 1 7 3 7 ro TRCDEVTYPE
    2 1 7 4 7 ro TRCPIDR4
    2 1 7 5 7 ro TRCPIDR5
    2 1 7 6 7 ro TRCPIDR6
    2 1 7 7 7 ro TRCPIDR7
    2 1 7 8 6 rw TRCCLAIMSET
    2 1 7 8 7 ro TRCPIDR0
    2 1 7 9 6 rw TRCCLAIMCLR
    2 1 7 9 7 ro TRCPIDR1
    2 1 7 10 6 ro TRCDEVAFF0
    2 1 7 10 7 ro TRCPIDR2
    2 1 7 11 6 ro TRCDEVAFF1
    2 1 7 11 7 ro TRCPIDR3
    2 1 7 12 6 wo TRCLAR
    2 1 7 12 7 ro TRCCIDR0
    2 1 7 13 6 ro TRCLSR
    2 1 7 13 7 ro TRCCIDR1
    2 1 7 14 6 ro TRCAUTHSTATUS
    2 1 7 14 7 ro TRCCIDR2
    2 1 7 15 6 ro TRCDEVARCH
    2 1 7 15 7 ro TRCCIDR3
    2 2 0 0 0 rw TEECR32_EL1
    2 2 1 0 0 rw TEEHBR32_EL1
    2 3 0 1 0 ro MDCCSR_EL0
    2 3 0 4 0 rw DBGDTR_EL0
    2 3 0 5 0 ro DBGDTRRX_EL0
    2 3 0 5 0 wo DBGDTRTX_EL0
    2 3 9 12 0 rw SPMCR_EL0
    2 3 9 12 1 rw SPMCNTENSET_EL0
    2 3 9 12 2 rw SPMCNTENCLR_EL0
    2 3 9 12 3 rw SPMOVSCLR_EL0
    2 3 9 12 4 wo SPMZR_EL0
    2 3 9 12 5 rw SPMSELR_EL0
    2 3 9 14 3 rw SPMOVSSET_EL0
    2 3 14 0 0 rw SPMEVCNTR0_EL0
    2 3 14 0 1 rw SPMEVCNTR1_EL0
    2 3 14 0 2 rw SPMEVCNTR2_EL0
    2 3 14 0 3 rw SPMEVCNTR3_EL0
    2 3 14 0 4 rw SPMEVCNTR4_EL0
    2 3 14 0 5 rw SPMEVCNTR5_EL0
    2 3 14 0 6 rw SPMEVCNTR6_EL0
    2 3 14 0 7 rw SPMEVCNTR7_EL0
    2 3 14 1 0 rw SPMEVCNTR8_EL0
    2 3 14 1 1 rw SPMEVCNTR9_EL0
    2 3 14 1 2 rw SPMEVCNTR10_EL0
    2 3 14 1 3 rw SPMEVCNTR11_EL0
    2 3 14 1 4 rw SPMEVCNTR12_EL0
    2 3 14 1 5 rw SPMEVCNTR13_EL0
    2 3 14 1 6 rw SPMEVCNTR14_EL0
    2 3 14 1 7 rw SPMEVCNTR15_EL0
    2 3 14 2 0 rw SPMEVTYPER0_EL0
    2 3 14 2 1 rw SPMEVTYPER1_EL0
    2 3 14 2 2 rw SPMEVTYPER2_EL0
    2 3 14 2 3 rw SPMEVTYPER3_EL0
    2 3 14 2 4 rw SPMEVTYPER4_EL0
    2 3 14 2 5 rw SPMEVTYPER5_EL0
    2 3 14 2 6 rw SPMEVTYPER6_EL0
    2 3 14 2 7 rw SPMEVTYPER7_EL0
    2 3 14 3 0 rw SPMEVTYPER8_EL0
    2 3 14 3 1 rw SPMEVTYPER9_EL0
    2 3 14 3 2 rw SPMEVTYPER10_EL0
    2 3 14 3 3 rw SPMEVTYPER11_EL0
    2 3 14 3 4 rw SPMEVTYPER12_EL0
    2 3 14 3 5 rw SPMEVTYPER13_EL0
    2 3 14 3 6 rw SPMEVTYPER14_EL0
    2 3 14 3 7 rw SPMEVTYPER15_EL0
    2 3 14 4 0 rw SPMEVFILTR0_EL0
    2 3 14 4 1 rw SPMEVFILTR1_EL0
    2 3 14 4 2 rw SPMEVFILTR2_EL0
    2 3 14 4 3 rw SPMEVFILTR3_EL0
    2 3 14 4 4 rw SPMEVFILTR4_EL0
    2 3 14 4 5 rw SPMEVFILTR5_EL0
    2 3 14 4 6 rw SPMEVFILTR6_EL0
    2 3 14 4 7 rw SPMEVFILTR7_EL0
    2 3 14 5 0 rw SPMEVFILTR8_EL0
    2 3 14 5 1 rw SPMEVFILTR9_EL0
    2 3 14 5 2 rw SPMEVFILTR10_EL0
    2 3 14 5 3 rw SPMEVFILTR11_EL0
    2 3 14 5 4 rw SPMEVFILTR12_EL0
    2 3 14 5 5 rw SPMEVFILTR13_EL0
    2 3 14 5 6 rw SPMEVFILTR14_EL0
    2 3 14 5 7 rw SPMEVFILTR15_EL0
    2 3 14 6 0 rw SPMEVFILT2R0_EL0
    2 3 14 6 1 rw SPMEVFILT2R1_EL0
    2 3 14 6 2 rw SPMEVFILT2R2_EL0
    2 3 14 6 3 rw SPMEVFILT2R3_EL0
    2 3 14 6 4 rw SPMEVFILT2R4_EL0
    2 3 14 6 5 rw SPMEVFILT2R5_EL0
    2 3 14 6 6 rw SPMEVFILT2R6_EL0
    2 3 14 6 7 rw SPMEVFILT2R7_EL0
    2 3 14 7 0 rw SPMEVFILT2R8_EL0
    2 3 14 7 1 rw SPMEVFILT2R9_EL0
    2 3 14 7 2 rw SPMEVFILT2R10_EL0
    2 3 14 7 3 rw SPMEVFILT2R11_EL0
    2 3 14 7 4 rw SPMEVFILT2R12_EL0
    2 3 14 7 5 rw SPMEVFILT2R13_EL0
    2 3 14 7 6 rw SPMEVFILT2R14_EL0
    2 3 14 7 7 rw SPMEVFILT2R15_EL0
    2 4 0 7 0 rw DBGVCR32_EL2
    2 4 9 13 3 rw SPMACCESSR_EL2
    2 5 9 13 3 rw SPMACCESSR_EL12
    2 6 9 13 3 rw SPMACCESSR_EL3
    2 6 9 14 7 rw SPMROOTCR_EL3
    2 7 9 14 7 rw SPMSCR_EL1
    3 0 0 0 0 ro MIDR_EL1
    3 0 0 0 5 ro MPIDR_EL1
    3 0 0 0 6 ro REVIDR_EL1
    3 0 0 1 0 ro ID_PFR0_EL1
    3 0 0 1 1 ro ID_PFR1_EL1
    3 0 0 1 2 ro ID_DFR0_EL1
    3 0 0 1 3 ro ID_AFR0_EL1
    3 0 0 1 4 ro ID_MMFR0_EL1
    3 0 0 1 5 ro ID_MMFR1_EL1
    3 0 0 1 6 ro ID_MMFR2_EL1
    3 0 0 1 7 ro ID_MMFR3_EL1
    3 0 0 2 0 ro ID_ISAR0_EL1
    3 0 0 2 1 ro ID_ISAR1_EL1
    3 0 0 2 2 ro ID_ISAR2_EL1
    3 0 0 2 3 ro ID_ISAR3_EL1
    3 0 0 2 4 ro ID_ISAR4_EL1
    3 0 0 2 5 ro ID_ISAR5_EL1
    3 0 0 2 6 ro ID_MMFR4_EL1
    3 0 0 2 7 ro ID_ISAR6_EL1
    3 0 0 3 0 ro MVFR0_EL1
    3 0 0 3 1 ro MVFR1_EL1
    3 0 0 3 2 ro MVFR2_EL1
    3 0 0 3 4 ro ID_PFR2_EL1
    3 0 0 3 5 ro ID_DFR1_EL1
    3 0 0 3 6 ro ID_MMFR5_EL1
    3 0 0 4 0 ro ID_AA64PFR0_EL1
    3 0 0 4 1 ro ID_AA64PFR1_EL1
    3 0 0 4 2 ro ID_AA64PFR2_EL1
    3 0 0 4 7 ro ID_AA64FPFR0_EL1
    3 0 0 5 0 ro ID_AA64DFR0_EL1
    3 0 0 5 1 ro ID_AA64DFR1_EL1
    3 0 0 5 2 ro ID_AA64DFR2_EL1
    3 0 0 5 4 ro ID_AA64AFR0_EL1
    3 0 0 5 5 ro ID_AA64AFR1_EL1
    3 0 0 6 0 ro ID_AA64ISAR0_EL1
    3 0 0 6 1 ro ID_AA64ISAR1_EL1
    3 0 0 6 2 ro ID_AA64ISAR2_EL1
    3 0 0 6 3 ro ID_AA64ISAR3_EL1
    3 0 0 7 0 ro ID_AA64MMFR0_EL1
    3 0 0 7 1 ro ID_AA64MMFR1_EL1
    3 0 0 7 2 ro ID_AA64MMFR2_EL1
    3 0 0 7 3 ro ID_AA64MMFR3_EL1
    3 0 0 7 4 ro ID_AA64MMFR4_EL1
    3 0 1 0 0 rw SCTLR_EL1
    3 0 1 0 1 rw ACTLR_EL1
    3 0 1 0 2 rw CPACR_EL1
    3 0 1 0 3 rw SCTLR2_EL1
    3 0 1 2 1 rw TRFCR_EL1
    3 0 1 4 0 rw SCTLRMASK_EL1
    3 0 1 4 1 rw ACTLRMASK_EL1
    3 0 1 4 2 rw CPACRMASK_EL1
    3 0 1 4 3 rw SCTLR2MASK_EL1
    3 0 1 4 4 rw CPACRALIAS_EL1
    3 0 1 4 5 rw ACTLRALIAS_EL1
    3 0 1 4 6 rw SCTLRALIAS_EL1
    3 0 1 4 7 rw SCTLR2ALIAS_EL1
    3 0 2 0 0 rw TTBR0_EL1
    3 0 2 0 1 rw TTBR1_EL1
    3 0 2 0 2 rw TCR_EL1
    3 0 2 0 3 rw TCR2_EL1
    3 0 2 0 4 rw IRTBRU_EL1
    3 0 2 0 5 rw IRTBRP_EL1
    3 0 2 0 6 rw DPOTBR0_EL1
    3 0 2 0 7 rw DPOTBR1_EL1
    3 0 2 1 0 rw APIAKeyLo_EL1
    3 0 2 1 1 rw APIAKeyHi_EL1
    3 0 2 1 2 rw APIBKeyLo_EL1
    3 0 2 1 3 rw APIBKeyHi_EL1
    3 0 2 1 7 rw LDSTT_EL1
    3 0 2 2 0 rw APDAKeyLo_EL1
    3 0 2 2 1 rw APDAKeyHi_EL1
    3 0 2 2 2 rw APDBKeyLo_EL1
    3 0 2 2 3 rw APDBKeyHi_EL1
    3 0 2 2 4 rw TPMIN0_EL1
    3 0 2 2 5 rw TPMAX0_EL1
    3 0 2 2 6 rw TPMIN1_EL1
    3 0 2 2 7 rw TPMAX1_EL1
    3 0 2 3 0 rw APGAKeyLo_EL1
    3 0 2 3 1 rw APGAKeyHi_EL1
    3 0 2 5 0 rw GCSCR_EL1
    3 0 2 5 1 rw GCSPR_EL1
    3 0 2 5 2 rw GCSCRE0_EL1
    3 0 2 7 2 rw TCRMASK_EL1
    3 0 2 7 3 rw TCR2MASK_EL1
    3 0 2 7 6 rw TCRALIAS_EL1
    3 0 2 7 7 rw TCR2ALIAS_EL1
    3 0 3 2 0 rw FGDTP0_EL1
    3 0 3 2 1 rw FGDTP1_EL1
    3 0 3 2 2 rw FGDTP2_EL1
    3 0 3 2 3 rw FGDTP3_EL1
    3 0 3 2 4 rw FGDTP4_EL1
    3 0 3 2 5 rw FGDTP5_EL1
    3 0 3 2 6 rw FGDTP6_EL1
    3 0 3 2 7 rw FGDTP7_EL1
    3 0 3 3 0 rw FGDTP8_EL1
    3 0 3 3 1 rw FGDTP9_EL1
    3 0 3 3 2 rw FGDTP10_EL1
    3 0 3 3 3 rw FGDTP11_EL1
    3 0 3 3 4 rw FGDTP12_EL1
    3 0 3 3 5 rw FGDTP13_EL1
    3 0 3 3 6 rw FGDTP14_EL1
    3 0 3 3 7 rw FGDTP15_EL1
    3 0 3 4 0 rw FGDTU0_EL1
    3 0 3 4 1 rw FGDTU1_EL1
    3 0 3 4 2 rw FGDTU2_EL1
    3 0 3 4 3 rw FGDTU3_EL1
    3 0 3 4 4 rw FGDTU4_EL1
    3 0 3 4 5 rw FGDTU5_EL1
    3 0 3 4 6 rw FGDTU6_EL1
    3 0 3 4 7 rw FGDTU7_EL1
    3 0 3 5 0 rw FGDTU8_EL1
    3 0 3 5 1 rw FGDTU9_EL1
    3 0 3 5 2 rw FGDTU10_EL1
    3 0 3 5 3 rw FGDTU11_EL1
    3 0 3 5 4 rw FGDTU12_EL1
    3 0 3 5 5 rw FGDTU13_EL1
    3 0 3 5 6 rw FGDTU14_EL1
    3 0 3 5 7 rw FGDTU15_EL1
    3 0 3 6 0 rw AFGDTP0_EL1
    3 0 3 6 1 rw AFGDTP1_EL1
    3 0 3 6 2 rw AFGDTP2_EL1
    3 0 3 6 3 rw AFGDTP3_EL1
    3 0 3 6 4 rw AFGDTP4_EL1
    3 0 3 6 5 rw AFGDTP5_EL1
    3 0 3 6 6 rw AFGDTP6_EL1
    3 0 3 6 7 rw AFGDTP7_EL1
    3 0 3 7 0 rw AFGDTP8_EL1
    3 0 3 7 1 rw AFGDTP9_EL1
    3 0 3 7 2 rw AFGDTP10_EL1
    3 0 3 7 3 rw AFGDTP11_EL1
    3 0 3 7 4 rw AFGDTP12_EL1
    3 0 3 7 5 rw AFGDTP13_EL1
    3 0 3 7 6 rw AFGDTP14_EL1
    3 0 3 7 7 rw AFGDTP15_EL1
    3 0 3 8 0 rw AFGDTU0_EL1
    3 0 3 8 1 rw AFGDTU1_EL1
    3 0 3 8 2 rw AFGDTU2_EL1
    3 0 3 8 3 rw AFGDTU3_EL1
    3 0 3 8 4 rw AFGDTU4_EL1
    3 0 3 8 5 rw AFGDTU5_EL1
    3 0 3 8 6 rw AFGDTU6_EL1
    3 0 3 8 7 rw AFGDTU7_EL1
    3 0 3 9 0 rw AFGDTU8_EL1
    3 0 3 9 1 rw AFGDTU9_EL1
    3 0 3 9 2 rw AFGDTU10_EL1
    3 0 3 9 3 rw AFGDTU11_EL1
    3 0 3 9 4 rw AFGDTU12_EL1
    3 0 3 9 5 rw AFGDTU13_EL1
    3 0 3 9 6 rw AFGDTU14_EL1
    3 0 3 9 7 rw AFGDTU15_EL1
    3 0 4 0 0 rw SPSR_EL1
    3 0 4 0 1 rw ELR_EL1
    3 0 4 0 2 rw STINDEX_EL1
    3 0 4 0 3 rw TINDEX_EL1
    3 0 4 1 0 rw SP_EL0
    3 0 4 2 0 rw SPSel
    3 0 4 2 2 ro CurrentEL
    3 0 4 2 3 rw PAN
    3 0 4 2 4 rw UAO
    3 0 4 3 1 rw PM
    3 0 4 6 0 rw ICC_PMR_EL1
    3 0 5 1 0 rw AFSR0_EL1
    3 0 5 1 1 rw AFSR1_EL1
    3 0 5 2 0 rw ESR_EL1
    3 0 5 3 0 ro ERRIDR_EL1
    3 0 5 3 1 rw ERRSELR_EL1
    3 0 5 4 0 ro ERXFR_EL1
    3 0 5 4 1 rw ERXCTLR_EL1
    3 0 5 4 2 rw ERXSTATUS_EL1
    3 0 5 4 3 rw ERXADDR_EL1
    3 0 5 4 4 ro ERXPFGF_EL1
    3 0 5 4 5 rw ERXPFGCTL_EL1
    3 0 5 4 6 rw ERXPFGCDN_EL1
    3 0 5 5 0 rw ERXMISC0_EL1
    3 0 5 5 1 rw ERXMISC1_EL1
    3 0 5 5 2 rw ERXMISC2_EL1
    3 0 5 5 3 rw ERXMISC3_EL1
    3 0 6 0 0 rw FAR_EL1
    3 0 6 0 5 rw PFAR_EL1
    3 0 7 4 0 rw PAR_EL1
    3 0 9 10 4 rw PMSDSFR_EL1
    3 0 9 10 5 rw PMBMAR_EL1
    3 0 9 13 3 rw PMSSCR_EL1
    3 0 9 14 1 rw PMINTENSET_EL1
    3 0 9 14 2 rw PMINTENCLR_EL1
    3 0 9 14 4 rw PMUACR_EL1
    3 0 9 14 5 rw PMECR_EL1
    3 0 9 14 6 ro PMMIR_EL1
    3 0 9 14 7 rw PMIAR_EL1
    3 0 10 2 0 rw MAIR_EL1
    3 0 10 2 1 rw MAIR2_EL1
    3 0 10 2 2 rw PIRE0_EL1
    3 0 10 2 3 rw PIR_EL1
    3 0 10 2 4 rw POR_EL1
    3 0 10 2 5 rw S2POR_EL1
    3 0 10 2 6 rw TTTBRU_EL1
    3 0 10 2 7 rw TTTBRP_EL1
    3 0 10 3 0 rw AMAIR_EL1
    3 0 10 3 1 rw AMAIR2_EL1
    3 0 10 4 0 rw LORSA_EL1
    3 0 10 4 1 rw LOREA_EL1
    3 0 10 4 2 rw LORN_EL1
    3 0 10 4 3 rw LORC_EL1
    3 0 10 4 4 ro MPAMIDR_EL1
    3 0 10 4 5 ro MPAMBWIDR_EL1
    3 0 10 4 7 ro LORID_EL1
    3 0 10 5 0 rw MPAM1_EL1
    3 0 10 5 1 rw MPAM0_EL1
    3 0 10 5 4 rw MPAMBW1_EL1
    3 0 10 5 5 rw MPAMBW0_EL1
    3 0 10 5 7 rw MPAMBWSM_EL1
    3 0 12 0 0 rw VBAR_EL1
    3 0 12 0 1 ro RVBAR_EL1
    3 0 12 0 2 rw RMR_EL1
    3 0 12 1 0 ro ISR_EL1
    3 0 12 1 1 rw DISR_EL1
    3 0 12 8 0 ro ICC_IAR0_EL1
    3 0 12 8 1 wo ICC_EOIR0_EL1
    3 0 12 8 2 ro ICC_HPPIR0_EL1
    3 0 12 8 3 rw ICC_BPR0_EL1
    3 0 12 8 4 rw ICC_AP0R0_EL1
    3 0 12 8 5 rw ICC_AP0R1_EL1
    3 0 12 8 6 rw ICC_AP0R2_EL1
    3 0 12 8 7 rw ICC_AP0R3_EL1
    3 0 12 9 0 rw ICC_AP1R0_EL1
    3 0 12 9 1 rw ICC_AP1R1_EL1
    3 0 12 9 2 rw ICC_AP1R2_EL1
    3 0 12 9 3 rw ICC_AP1R3_EL1
    3 0 12 11 1 wo ICC_DIR_EL1
    3 0 12 11 3 ro ICC_RPR_EL1
    3 0 12 11 5 wo ICC_SGI1R_EL1
    3 0 12 11 6 wo ICC_ASGI1R_EL1
    3 0 12 11 7 wo ICC_SGI0R_EL1
    3 0 12 12 0 ro ICC_IAR1_EL1
    3 0 12 12 1 wo ICC_EOIR1_EL1
    3 0 12 12 2 ro ICC_HPPIR1_EL1
    3 0 12 12 3 rw ICC_BPR1_EL1
    3 0 12 12 4 rw ICC_CTLR_EL1
    3 0 12 12 5 rw ICC_SRE_EL1
    3 0 12 12 6 rw ICC_IGRPEN0_EL1
    3 0 12 12 7 rw ICC_IGRPEN1_EL1
    3 0 13 0 0 rw TPIDR3_EL1
    3 0 13 0 1 rw CONTEXTIDR_EL1
    3 0 13 0 4 rw TPIDR_EL1
    3 0 13 0 7 rw SCXTNUM_EL1
    3 0 14 1 0 rw CNTKCTL_EL1
    3 1 0 0 0 ro CCSIDR_EL1
    3 1 0 0 1 ro CLIDR_EL1
    3 1 0 0 7 ro AIDR_EL1
    3 2 0 0 0 rw CSSELR_EL1
    3 3 0 0 1 ro CTR_EL0
    3 3 0 0 7 ro DCZID_EL0
    3 3 2 2 4 rw TPMIN0_EL0
    3 3 2 2 5 rw TPMAX0_EL0
    3 3 2 2 6 rw TPMIN1_EL0
    3 3 2 2 7 rw TPMAX1_EL0
    3 3 2 5 1 rw GCSPR_EL0
    3 3 4 0 3 rw TINDEX_EL0
    3 3 4 2 0 rw NZCV
    3 3 4 2 1 rw DAIF
    3 3 4 2 5 rw DIT
    3 3 4 2 6 rw SSBS
    3 3 4 4 0 rw FPCR
    3 3 4 4 1 rw FPSR
    3 3 4 4 2 rw FPMR
    3 3 4 5 0 rw DSPSR_EL0
    3 3 4 5 1 rw DLR_EL0
    3 3 4 5 2 rw DPOCR_EL0
    3 3 9 4 0 rw PMICNTR_EL0
    3 3 9 6 0 rw PMICFILTR_EL0
    3 3 9 12 0 rw PMCR_EL0
    3 3 9 12 1 rw PMCNTENSET_EL0
    3 3 9 12 2 rw PMCNTENCLR_EL0
    3 3 9 12 3 rw PMOVSCLR_EL0
    3 3 9 12 4 wo PMSWINC_EL0
    3 3 9 12 5 rw PMSELR_EL0
    3 3 9 12 6 ro PMCEID0_EL0
    3 3 9 12 7 ro PMCEID1_EL0
    3 3 9 13 0 rw PMCCNTR_EL0
    3 3 9 13 1 rw PMXEVTYPER_EL0
    3 3 9 13 2 rw PMXEVCNTR_EL0
    3 3 9 13 4 wo PMZR_EL0
    3 3 9 14 0 rw PMUSERENR_EL0
    3 3 9 14 3 rw PMOVSSET_EL0
    3 3 10 2 4 rw POR_EL0
    3 3 13 0 0 rw TPIDR3_EL0
    3 3 13 0 2 rw TPIDR_EL0
    3 3 13 0 3 rw TPIDRRO_EL0
    3 3 13 0 7 rw SCXTNUM_EL0
    3 3 13 2 0 rw AMCR_EL0
    3 3 13 2 1 ro AMCFGR_EL0
    3 3 13 2 2 ro AMCGCR_EL0
    3 3 13 2 3 rw AMUSERENR_EL0
    3 3 13 2 4 rw AMCNTENCLR0_EL0
    3 3 13 2 5 rw AMCNTENSET0_EL0
    3 3 13 3 0 rw AMCNTENCLR1_EL0
    3 3 13 3 1 rw AMCNTENSET1_EL0
    3 3 13 4 0 rw AMEVCNTR00_EL0
    3 3 13 4 1 rw AMEVCNTR01_EL0
    3 3 13 4 2 rw AMEVCNTR02_EL0
    3 3 13 4 3 rw AMEVCNTR03_EL0
    3 3 13 6 0 ro AMEVTYPER00_EL0
    3 3 13 6 1 ro AMEVTYPER01_EL0
    3 3 13 6 2 ro AMEVTYPER02_EL0
    3 3 13 6 3 ro AMEVTYPER03_EL0
    3 3 13 12 0 rw AMEVCNTR10_EL0
    3 3 13 12 1 rw AMEVCNTR11_EL0
    3 3 13 12 2 rw AMEVCNTR12_EL0
    3 3 13 12 3 rw AMEVCNTR13_EL0
    3 3 13 12 4 rw AMEVCNTR14_EL0
    3 3 13 12 5 rw AMEVCNTR15_EL0
    3 3 13 12 6 rw AMEVCNTR16_EL0
    3 3 13 12 7 rw AMEVCNTR17_EL0
    3 3 13 13 0 rw AMEVCNTR18_EL0
    3 3 13 13 1 rw AMEVCNTR19_EL0
    3 3 13 13 2 rw AMEVCNTR110_EL0
    3 3 13 13 3 rw AMEVCNTR111_EL0
    3 3 13 13 4 rw AMEVCNTR112_EL0
    3 3 13 13 5 rw AMEVCNTR113_EL0
    3 3 13 13 6 rw AMEVCNTR114_EL0
    3 3 13 13 7 rw AMEVCNTR115_EL0
    3 3 13 14 0 rw AMEVTYPER10_EL0
    3 3 13 14 1 rw AMEVTYPER11_EL0
    3 3 13 14 2 rw AMEVTYPER12_EL0
    3 3 13 14 3 rw AMEVTYPER13_EL0
    3 3 13 14 4 rw AMEVTYPER14_EL0
    3 3 13 14 5 rw AMEVTYPER15_EL0
    3 3 13 14 6 rw AMEVTYPER16_EL0
    3 3 13 14 7 rw AMEVTYPER17_EL0
    3 3 13 15 0 rw AMEVTYPER18_EL0
    3 3 13 15 1 rw AMEVTYPER19_EL0
    3 3 13 15 2 rw AMEVTYPER110_EL0
    3 3 13 15 3 rw AMEVTYPER111_EL0
    3 3 13 15 4 rw AMEVTYPER112_EL0
    3 3 13 15 5 rw AMEVTYPER113_EL0
    3 3 13 15 6 rw AMEVTYPER114_EL0
    3 3 13 15 7 rw AMEVTYPER115_EL0
    3 3 14 0 0 rw CNTFRQ_EL0
    3 3 14 0 1 ro CNTPCT_EL0
    3 3 14 0 2 ro CNTVCT_EL0
    3 3 14 2 0 rw CNTP_TVAL_EL0
    3 3 14 2 1 rw CNTP_CTL_EL0
    3 3 14 2 2 rw CNTP_CVAL_EL0
    3 3 14 3 0 rw CNTV_TVAL_EL0
    3 3 14 3 1 rw CNTV_CTL_EL0
    3 3 14 3 2 rw CNTV_CVAL_EL0
    3 3 14 8 0 rw PMEVCNTR0_EL0
    3 3 14 8 1 rw PMEVCNTR1_EL0
    3 3 14 8 2 rw PMEVCNTR2_EL0
    3 3 14 8 3 rw PMEVCNTR3_EL0
    3 3 14 8 4 rw PMEVCNTR4_EL0
    3 3 14 8 5 rw PMEVCNTR5_EL0
    3 3 14 8 6 rw PMEVCNTR6_EL0
    3 3 14 8 7 rw PMEVCNTR7_EL0
    3 3 14 9 0 rw PMEVCNTR8_EL0
    3 3 14 9 1 rw PMEVCNTR9_EL0
    3 3 14 9 2 rw PMEVCNTR10_EL0
    3 3 14 9 3 rw PMEVCNTR11_EL0
    3 3 14 9 4 rw PMEVCNTR12_EL0
    3 3 14 9 5 rw PMEVCNTR13_EL0
    3 3 14 9 6 rw PMEVCNTR14_EL0
    3 3 14 9 7 rw PMEVCNTR15_EL0
    3 3 14 10 0 rw PMEVCNTR16_EL0
    3 3 14 10 1 rw PMEVCNTR17_EL0
    3 3 14 10 2 rw PMEVCNTR18_EL0
    3 3 14 10 3 rw PMEVCNTR19_EL0
    3 3 14 10 4 rw PMEVCNTR20_EL0
    3 3 14 10 5 rw PMEVCNTR21_EL0
    3 3 14 10 6 rw PMEVCNTR22_EL0
    3 3 14 10 7 rw PMEVCNTR23_EL0
    3 3 14 11 0 rw PMEVCNTR24_EL0
    3 3 14 11 1 rw PMEVCNTR25_EL0
    3 3 14 11 2 rw PMEVCNTR26_EL0
    3 3 14 11 3 rw PMEVCNTR27_EL0
    3 3 14 11 4 rw PMEVCNTR28_EL0
    3 3 14 11 5 rw PMEVCNTR29_EL0
    3 3 14 11 6 rw PMEVCNTR30_EL0
    3 3 14 12 0 rw PMEVTYPER0_EL0
    3 3 14 12 1 rw PMEVTYPER1_EL0
    3 3 14 12 2 rw PMEVTYPER2_EL0
    3 3 14 12 3 rw PMEVTYPER3_EL0
    3 3 14 12 4 rw PMEVTYPER4_EL0
    3 3 14 12 5 rw PMEVTYPER5_EL0
    3 3 14 12 6 rw PMEVTYPER6_EL0
    3 3 14 12 7 rw PMEVTYPER7_EL0
    3 3 14 13 0 rw PMEVTYPER8_EL0
    3 3 14 13 1 rw PMEVTYPER9_EL0
    3 3 14 13 2 rw PMEVTYPER10_EL0
    3 3 14 13 3 rw PMEVTYPER11_EL0
    3 3 14 13 4 rw PMEVTYPER12_EL0
    3 3 14 13 5 rw PMEVTYPER13_EL0
    3 3 14 13 6 rw PMEVTYPER14_EL0
    3 3 14 13 7 rw PMEVTYPER15_EL0
    3 3 14 14 0 rw PMEVTYPER16_EL0
    3 3 14 14 1 rw PMEVTYPER17_EL0
    3 3 14 14 2 rw PMEVTYPER18_EL0
    3 3 14 14 3 rw PMEVTYPER19_EL0
    3 3 14 14 4 rw PMEVTYPER20_EL0
    3 3 14 14 5 rw PMEVTYPER21_EL0
    3 3 14 14 6 rw PMEVTYPER22_EL0
    3 3 14 14 7 rw PMEVTYPER23_EL0
    3 3 14 15 0 rw PMEVTYPER24_EL0
    3 3 14 15 1 rw PMEVTYPER25_EL0
    3 3 14 15 2 rw PMEVTYPER26_EL0
    3 3 14 15 3 rw PMEVTYPER27_EL0
    3 3 14 15 4 rw PMEVTYPER28_EL0
    3 3 14 15 5 rw PMEVTYPER29_EL0
    3 3 14 15 6 rw PMEVTYPER30_EL0
    3 3 14 15 7 rw PMCCFILTR_EL0
    3 4 0 0 0 rw VPIDR_EL2
    3 4 0 0 5 rw VMPIDR_EL2
    3 4 1 0 0 rw SCTLR_EL2
    3 4 1 0 1 rw ACTLR_EL2
    3 4 1 0 3 rw SCTLR2_EL2
    3 4 1 1 0 rw HCR_EL2
    3 4 1 1 1 rw MDCR_EL2
    3 4 1 1 2 rw CPTR_EL2
    3 4 1 1 3 rw HSTR_EL2
    3 4 1 1 7 rw HACR_EL2
    3 4 1 2 1 rw TRFCR_EL2
    3 4 1 3 1 rw SDER32_EL2
    3 4 1 4 0 rw SCTLRMASK_EL2
    3 4 1 4 1 rw ACTLRMASK_EL2
    3 4 1 4 2 rw CPTRMASK_EL2
    3 4 1 4 3 rw SCTLR2MASK_EL2
    3 4 1 5 0 rw NVHCR_EL2
    3 4 1 5 1 rw NVHCRX_EL2
    3 4 1 5 4 rw NVHCRMASK_EL2
    3 4 1 5 5 rw NVHCRXMASK_EL2
    3 4 1 5 6 rw HCRMASK_EL2
    3 4 1 5 7 rw HCRXMASK_EL2
    3 4 2 0 0 rw TTBR0_EL2
    3 4 2 0 1 rw TTBR1_EL2
    3 4 2 0 2 rw TCR_EL2
    3 4 2 0 3 rw TCR2_EL2
    3 4 2 0 4 rw IRTBRU_EL2
    3 4 2 0 5 rw IRTBRP_EL2
    3 4 2 0 6 rw DPOTBR0_EL2
    3 4 2 0 7 rw DPOTBR1_EL2
    3 4 2 1 0 rw VTTBR_EL2
    3 4 2 1 2 rw VTCR_EL2
    3 4 2 1 7 rw LDSTT_EL2
    3 4 2 2 0 rw VNCR_EL2
    3 4 2 2 1 rw VNCCR_EL2
    3 4 2 2 4 rw TPMIN0_EL2
    3 4 2 2 5 rw TPMAX0_EL2
    3 4 2 2 6 rw TPMIN1_EL2
    3 4 2 2 7 rw TPMAX1_EL2
    3 4 2 3 2 rw HDBSSBR_EL2
    3 4 2 3 3 rw HDBSSPROD_EL2
    3 4 2 3 4 rw HACDBSBR_EL2
    3 4 2 3 5 rw HACDBSCONS_EL2
    3 4 2 5 0 rw GCSCR_EL2
    3 4 2 5 1 rw GCSPR_EL2
    3 4 2 6 0 rw VSTTBR_EL2
    3 4 2 6 2 rw VSTCR_EL2
    3 4 2 7 2 rw TCRMASK_EL2
    3 4 2 7 3 rw TCR2MASK_EL2
    3 4 3 0 0 rw DACR32_EL2
    3 4 3 2 0 rw FGDTP0_EL2
    3 4 3 2 1 rw FGDTP1_EL2
    3 4 3 2 2 rw FGDTP2_EL2
    3 4 3 2 3 rw FGDTP3_EL2
    3 4 3 2 4 rw FGDTP4_EL2
    3 4 3 2 5 rw FGDTP5_EL2
    3 4 3 2 6 rw FGDTP6_EL2
    3 4 3 2 7 rw FGDTP7_EL2
    3 4 3 3 0 rw FGDTP8_EL2
    3 4 3 3 1 rw FGDTP9_EL2
    3 4 3 3 2 rw FGDTP10_EL2
    3 4 3 3 3 rw FGDTP11_EL2
    3 4 3 3 4 rw FGDTP12_EL2
    3 4 3 3 5 rw FGDTP13_EL2
    3 4 3 3 6 rw FGDTP14_EL2
    3 4 3 3 7 rw FGDTP15_EL2
    3 4 3 4 0 rw FGDTU0_EL2
    3 4 3 4 1 rw FGDTU1_EL2
    3 4 3 4 2 rw FGDTU2_EL2
    3 4 3 4 3 rw FGDTU3_EL2
    3 4 3 4 4 rw FGDTU4_EL2
    3 4 3 4 5 rw FGDTU5_EL2
    3 4 3 4 6 rw FGDTU6_EL2
    3 4 3 4 7 rw FGDTU7_EL2
    3 4 3 5 0 rw FGDTU8_EL2
    3 4 3 5 1 rw FGDTU9_EL2
    3 4 3 5 2 rw FGDTU10_EL2
    3 4 3 5 3 rw FGDTU11_EL2
    3 4 3 5 4 rw FGDTU12_EL2
    3 4 3 5 5 rw FGDTU13_EL2
    3 4 3 5 6 rw FGDTU14_EL2
    3 4 3 5 7 rw FGDTU15_EL2
    3 4 3 6 0 rw AFGDTP0_EL2
    3 4 3 6 1 rw AFGDTP1_EL2
    3 4 3 6 2 rw AFGDTP2_EL2
    3 4 3 6 3 rw AFGDTP3_EL2
    3 4 3 6 4 rw AFGDTP4_EL2
    3 4 3 6 5 rw AFGDTP5_EL2
    3 4 3 6 6 rw AFGDTP6_EL2
    3 4 3 6 7 rw AFGDTP7_EL2
    3 4 3 7 0 rw AFGDTP8_EL2
    3 4 3 7 1 rw AFGDTP9_EL2
    3 4 3 7 2 rw AFGDTP10_EL2
    3 4 3 7 3 rw AFGDTP11_EL2
    3 4 3 7 4 rw AFGDTP12_EL2
    3 4 3 7 5 rw AFGDTP13_EL2
    3 4 3 7 6 rw AFGDTP14_EL2
    3 4 3 7 7 rw AFGDTP15_EL2
    3 4 3 8 0 rw AFGDTU0_EL2
    3 4 3 8 1 rw AFGDTU1_EL2
    3 4 3 8 2 rw AFGDTU2_EL2
    3 4 3 8 3 rw AFGDTU3_EL2
    3 4 3 8 4 rw AFGDTU4_EL2
    3 4 3 8 5 rw AFGDTU5_EL2
    3 4 3 8 6 rw AFGDTU6_EL2
    3 4 3 8 7 rw AFGDTU7_EL2
    3 4 3 9 0 rw AFGDTU8_EL2
    3 4 3 9 1 rw AFGDTU9_EL2
    3 4 3 9 2 rw AFGDTU10_EL2
    3 4 3 9 3 rw AFGDTU11_EL2
    3 4 3 9 4 rw AFGDTU12_EL2
    3 4 3 9 5 rw AFGDTU13_EL2
    3 4 3 9 6 rw AFGDTU14_EL2
    3 4 3 9 7 rw AFGDTU15_EL2
    3 4 4 0 0 rw SPSR_EL2
    3 4 4 0 1 rw ELR_EL2
    3 4 4 0 2 rw STINDEX_EL2
    3 4 4 0 3 rw TINDEX_EL2
    3 4 4 1 0 rw SP_EL1
    3 4 4 3 0 rw SPSR_irq
    3 4 4 3 1 rw SPSR_abt
    3 4 4 3 2 rw SPSR_und
    3 4 4 3 3 rw SPSR_fiq
    3 4 5 0 1 rw IFSR32_EL2
    3 4 5 1 0 rw AFSR0_EL2
    3 4 5 1 1 rw AFSR1_EL2
    3 4 5 2 0 rw ESR_EL2
    3 4 5 2 3 rw VSESR_EL2
    3 4 5 3 0 rw FPEXC32_EL2
    3 4 6 0 0 rw FAR_EL2
    3 4 6 0 4 rw HPFAR_EL2
    3 4 6 0 5 rw PFAR_EL2
    3 4 9 10 3 rw PMBSR_EL2
    3 4 9 11 3 rw TRBSR_EL2
    3 4 10 1 1 rw MAIR2_EL2
    3 4 10 2 0 rw MAIR_EL2
    3 4 10 2 2 rw PIRE0_EL2
    3 4 10 2 3 rw PIR_EL2
    3 4 10 2 4 rw POR_EL2
    3 4 10 2 5 rw S2PIR_EL2
    3 4 10 2 6 rw TTTBRU_EL2
    3 4 10 2 7 rw TTTBRP_EL2
    3 4 10 3 0 rw AMAIR_EL2
    3 4 10 3 1 rw AMAIR2_EL2
    3 4 10 4 0 rw MPAMHCR_EL2
    3 4 10 4 1 rw MPAMVPMV_EL2
    3 4 10 5 0 rw MPAM2_EL2
    3 4 10 5 4 rw MPAMBW2_EL2
    3 4 10 5 6 rw MPAMBWCAP_EL2
    3 4 10 6 0 rw MPAMVPM0_EL2
    3 4 10 6 1 rw MPAMVPM1_EL2
    3 4 10 6 2 rw MPAMVPM2_EL2
    3 4 10 6 3 rw MPAMVPM3_EL2
    3 4 10 6 4 rw MPAMVPM4_EL2
    3 4 10 6 5 rw MPAMVPM5_EL2
    3 4 10 6 6 rw MPAMVPM6_EL2
    3 4 10 6 7 rw MPAMVPM7_EL2
    3 4 12 0 0 rw VBAR_EL2
    3 4 12 0 1 ro RVBAR_EL2
    3 4 12 0 2 rw RMR_EL2
    3 4 12 1 1 rw VDISR_EL2
    3 4 12 8 0 rw ICH_AP0R0_EL2
    3 4 12 8 1 rw ICH_AP0R1_EL2
    3 4 12 8 2 rw ICH_AP0R2_EL2
    3 4 12 8 3 rw ICH_AP0R3_EL2
    3 4 12 9 0 rw ICH_AP1R0_EL2
    3 4 12 9 1 rw ICH_AP1R1_EL2
    3 4 12 9 2 rw ICH_AP1R2_EL2
    3 4 12 9 3 rw ICH_AP1R3_EL2
    3 4 12 9 5 rw ICC_SRE_EL2
    3 4 12 11 0 rw ICH_HCR_EL2
    3 4 12 11 1 ro ICH_VTR_EL2
    3 4 12 11 2 ro ICH_MISR_EL2
    3 4 12 11 3 ro ICH_EISR_EL2
    3 4 12 11 5 ro ICH_ELRSR_EL2
    3 4 12 11 7 rw ICH_VMCR_EL2
    3 4 12 12 0 rw ICH_LR0_EL2
    3 4 12 12 1 rw ICH_LR1_EL2
    3 4 12 12 2 rw ICH_LR2_EL2
    3 4 12 12 3 rw ICH_LR3_EL2
    3 4 12 12 4 rw ICH_LR4_EL2
    3 4 12 12 5 rw ICH_LR5_EL2
    3 4 12 12 6 rw ICH_LR6_EL2
    3 4 12 12 7 rw ICH_LR7_EL2
    3 4 12 13 0 rw ICH_LR8_EL2
    3 4 12 13 1 rw ICH_LR9_EL2
    3 4 12 13 2 rw ICH_LR10_EL2
    3 4 12 13 3 rw ICH_LR11_EL2
    3 4 12 13 4 rw ICH_LR12_EL2
    3 4 12 13 5 rw ICH_LR13_EL2
    3 4 12 13 6 rw ICH_LR14_EL2
    3 4 12 13 7 rw ICH_LR15_EL2
    3 4 13 0 0 rw TPIDR3_EL2
    3 4 13 0 1 rw CONTEXTIDR_EL2
    3 4 13 0 2 rw TPIDR_EL2
    3 4 13 0 7 rw SCXTNUM_EL2
    3 4 14 0 3 rw CNTVOFF_EL2
    3 4 14 1 0 rw CNTHCTL_EL2
    3 4 14 2 0 rw CNTHP_TVAL_EL2
    3 4 14 2 1 rw CNTHP_CTL_EL2
    3 4 14 2 2 rw CNTHP_CVAL_EL2
    3 4 14 3 0 rw CNTHV_TVAL_EL2
    3 4 14 3 1 rw CNTHV_CTL_EL2
    3 4 14 3 2 rw CNTHV_CVAL_EL2
    3 4 14 4 0 rw CNTHVS_TVAL_EL2
    3 4 14 4 1 rw CNTHVS_CTL_EL2
    3 4 14 4 2 rw CNTHVS_CVAL_EL2
    3 4 14 5 0 rw CNTHPS_TVAL_EL2
    3 4 14 5 1 rw CNTHPS_CTL_EL2
    3 4 14 5 2 rw CNTHPS_CVAL_EL2
    3 5 1 0 0 rw SCTLR_EL12
    3 5 1 0 1 rw ACTLR_EL12
    3 5 1 0 2 rw CPACR_EL12
    3 5 1 0 3 rw SCTLR2_EL12
    3 5 1 2 1 rw TRFCR_EL12
    3 5 1 4 0 rw SCTLRMASK_EL12
    3 5 1 4 1 rw ACTLRMASK_EL12
    3 5 1 4 2 rw CPACRMASK_EL12
    3 5 1 4 3 rw SCTLR2MASK_EL12
    3 5 2 0 0 rw TTBR0_EL12
    3 5 2 0 1 rw TTBR1_EL12
    3 5 2 0 2 rw TCR_EL12
    3 5 2 0 3 rw TCR2_EL12
    3 5 2 0 4 rw IRTBRU_EL12
    3 5 2 0 5 rw IRTBRP_EL12
    3 5 2 0 6 rw DPOTBR0_EL12
    3 5 2 0 7 rw DPOTBR1_EL12
    3 5 2 1 7 rw LDSTT_EL12
    3 5 2 2 4 rw TPMIN0_EL12
    3 5 2 2 5 rw TPMAX0_EL12
    3 5 2 2 6 rw TPMIN1_EL12
    3 5 2 2 7 rw TPMAX1_EL12
    3 5 2 5 0 rw GCSCR_EL12
    3 5 2 5 1 rw GCSPR_EL12
    3 5 2 7 2 rw TCRMASK_EL12
    3 5 2 7 3 rw TCR2MASK_EL12
    3 5 3 2 0 rw FGDTP0_EL12
    3 5 3 2 1 rw FGDTP1_EL12
    3 5 3 2 2 rw FGDTP2_EL12
    3 5 3 2 3 rw FGDTP3_EL12
    3 5 3 2 4 rw FGDTP4_EL12
    3 5 3 2 5 rw FGDTP5_EL12
    3 5 3 2 6 rw FGDTP6_EL12
    3 5 3 2 7 rw FGDTP7_EL12
    3 5 3 3 0 rw FGDTP8_EL12
    3 5 3 3 1 rw FGDTP9_EL12
    3 5 3 3 2 rw FGDTP10_EL12
    3 5 3 3 3 rw FGDTP11_EL12
    3 5 3 3 4 rw FGDTP12_EL12
    3 5 3 3 5 rw FGDTP13_EL12
    3 5 3 3 6 rw FGDTP14_EL12
    3 5 3 3 7 rw FGDTP15_EL12
    3 5 3 4 0 rw FGDTU0_EL12
    3 5 3 4 1 rw FGDTU1_EL12
    3 5 3 4 2 rw FGDTU2_EL12
    3 5 3 4 3 rw FGDTU3_EL12
    3 5 3 4 4 rw FGDTU4_EL12
    3 5 3 4 5 rw FGDTU5_EL12
    3 5 3 4 6 rw FGDTU6_EL12
    3 5 3 4 7 rw FGDTU7_EL12
    3 5 3 5 0 rw FGDTU8_EL12
    3 5 3 5 1 rw FGDTU9_EL12
    3 5 3 5 2 rw FGDTU10_EL12
    3 5 3 5 3 rw FGDTU11_EL12
    3 5 3 5 4 rw FGDTU12_EL12
    3 5 3 5 5 rw FGDTU13_EL12
    3 5 3 5 6 rw FGDTU14_EL12
    3 5 3 5 7 rw FGDTU15_EL12
    3 5 3 6 0 rw AFGDTP0_EL12
    3 5 3 6 1 rw AFGDTP1_EL12
    3 5 3 6 2 rw AFGDTP2_EL12
    3 5 3 6 3 rw AFGDTP3_EL12
    3 5 3 6 4 rw AFGDTP4_EL12
    3 5 3 6 5 rw AFGDTP5_EL12
    3 5 3 6 6 rw AFGDTP6_EL12
    3 5 3 6 7 rw AFGDTP7_EL12
    3 5 3 7 0 rw AFGDTP8_EL12
    3 5 3 7 1 rw AFGDTP9_EL12
    3 5 3 7 2 rw AFGDTP10_EL12
    3 5 3 7 3 rw AFGDTP11_EL12
    3 5 3 7 4 rw AFGDTP12_EL12
    3 5 3 7 5 rw AFGDTP13_EL12
    3 5 3 7 6 rw AFGDTP14_EL12
    3 5 3 7 7 rw AFGDTP15_EL12
    3 5 3 8 0 rw AFGDTU0_EL12
    3 5 3 8 1 rw AFGDTU1_EL12
    3 5 3 8 2 rw AFGDTU2_EL12
    3 5 3 8 3 rw AFGDTU3_EL12
    3 5 3 8 4 rw AFGDTU4_EL12
    3 5 3 8 5 rw AFGDTU5_EL12
    3 5 3 8 6 rw AFGDTU6_EL12
    3 5 3 8 7 rw AFGDTU7_EL12
    3 5 3 9 0 rw AFGDTU8_EL12
    3 5 3 9 1 rw AFGDTU9_EL12
    3 5 3 9 2 rw AFGDTU10_EL12
    3 5 3 9 3 rw AFGDTU11_EL12
    3 5 3 9 4 rw AFGDTU12_EL12
    3 5 3 9 5 rw AFGDTU13_EL12
    3 5 3 9 6 rw AFGDTU14_EL12
    3 5 3 9 7 rw AFGDTU15_EL12
    3 5 4 0 0 rw SPSR_EL12
    3 5 4 0 1 rw ELR_EL12
    3 5 4 0 2 rw STINDEX_EL12
    3 5 4 0 3 rw TINDEX_EL12
    3 5 5 1 0 rw AFSR0_EL12
    3 5 5 1 1 rw AFSR1_EL12
    3 5 5 2 0 rw ESR_EL12
    3 5 6 0 0 rw FAR_EL12
    3 5 6 0 5 rw PFAR_EL12
    3 5 9 10 3 rw PMBSR_EL12
    3 5 9 11 3 rw TRBSR_EL12
    3 5 10 2 0 rw MAIR_EL12
    3 5 10 2 1 rw MAIR2_EL12
    3 5 10 2 2 rw PIRE0_EL12
    3 5 10 2 3 rw PIR_EL12
    3 5 10 2 4 rw POR_EL12
    3 5 10 2 6 rw TTTBRU_EL12
    3 5 10 2 7 rw TTTBRP_EL12
    3 5 10 3 0 rw AMAIR_EL12
    3 5 10 3 1 rw AMAIR2_EL12
    3 5 10 5 0 rw MPAM1_EL12
    3 5 10 5 4 rw MPAMBW1_EL12
    3 5 12 0 0 rw VBAR_EL12
    3 5 13 0 0 rw TPIDR3_EL12
    3 5 13 0 1 rw CONTEXTIDR_EL12
    3 5 13 0 7 rw SCXTNUM_EL12
    3 5 14 1 0 rw CNTKCTL_EL12
    3 5 14 2 0 rw CNTP_TVAL_EL02
    3 5 14 2 1 rw CNTP_CTL_EL02
    3 5 14 2 2 rw CNTP_CVAL_EL02
    3 5 14 3 0 rw CNTV_TVAL_EL02
    3 5 14 3 1 rw CNTV_CTL_EL02
    3 5 14 3 2 rw CNTV_CVAL_EL02
    3 6 1 0 0 rw SCTLR_EL3
    3 6 1 0 1 rw ACTLR_EL3
    3 6 1 0 3 rw SCTLR2_EL3
    3 6 1 1 0 rw SCR_EL3
    3 6 1 1 1 rw SDER32_EL3
    3 6 1 1 2 rw CPTR_EL3
    3 6 1 1 5 rw FGWTE3_EL3
    3 6 1 3 1 rw MDCR_EL3
    3 6 2 0 0 rw TTBR0_EL3
    3 6 2 0 2 rw TCR_EL3
    3 6 2 0 5 rw IRTBRP_EL3
    3 6 2 0 6 rw DPOTBR0_EL3
    3 6 2 1 5 rw GPCBW_EL3
    3 6 2 5 0 rw GCSCR_EL3
    3 6 2 5 1 rw GCSPR_EL3
    3 6 3 2 0 rw FGDTP0_EL3
    3 6 3 2 1 rw FGDTP1_EL3
    3 6 3 2 2 rw FGDTP2_EL3
    3 6 3 2 3 rw FGDTP3_EL3
    3 6 3 2 4 rw FGDTP4_EL3
    3 6 3 2 5 rw FGDTP5_EL3
    3 6 3 2 6 rw FGDTP6_EL3
    3 6 3 2 7 rw FGDTP7_EL3
    3 6 3 3 0 rw FGDTP8_EL3
    3 6 3 3 1 rw FGDTP9_EL3
    3 6 3 3 2 rw FGDTP10_EL3
    3 6 3 3 3 rw FGDTP11_EL3
    3 6 3 3 4 rw FGDTP12_EL3
    3 6 3 3 5 rw FGDTP13_EL3
    3 6 3 3 6 rw FGDTP14_EL3
    3 6 3 3 7 rw FGDTP15_EL3
    3 6 3 6 0 rw AFGDTP0_EL3
    3 6 3 6 1 rw AFGDTP1_EL3
    3 6 3 6 2 rw AFGDTP2_EL3
    3 6 3 6 3 rw AFGDTP3_EL3
    3 6 3 6 4 rw AFGDTP4_EL3
    3 6 3 6 5 rw AFGDTP5_EL3
    3 6 3 6 6 rw AFGDTP6_EL3
    3 6 3 6 7 rw AFGDTP7_EL3
    3 6 3 7 0 rw AFGDTP8_EL3
    3 6 3 7 1 rw AFGDTP9_EL3
    3 6 3 7 2 rw AFGDTP10_EL3
    3 6 3 7 3 rw AFGDTP11_EL3
    3 6 3 7 4 rw AFGDTP12_EL3
    3 6 3 7 5 rw AFGDTP13_EL3
    3 6 3 7 6 rw AFGDTP14_EL3
    3 6 3 7 7 rw AFGDTP15_EL3
    3 6 4 0 0 rw SPSR_EL3
    3 6 4 0 1 rw ELR_EL3
    3 6 4 0 2 rw STINDEX_EL3
    3 6 4 0 3 rw TINDEX_EL3
    3 6 4 1 0 rw SP_EL2
    3 6 5 1 0 rw AFSR0_EL3
    3 6 5 1 1 rw AFSR1_EL3
    3 6 5 2 0 rw ESR_EL3
    3 6 5 2 3 rw VSESR_EL3
    3 6 6 0 0 rw FAR_EL3
    3 6 6 0 5 rw MFAR_EL3
    3 6 9 10 3 rw PMBSR_EL3
    3 6 9 11 3 rw TRBSR_EL3
    3 6 10 1 1 rw MAIR2_EL3
    3 6 10 2 0 rw MAIR_EL3
    3 6 10 2 3 rw PIR_EL3
    3 6 10 2 4 rw POR_EL3
    3 6 10 2 7 rw TTTBRP_EL3
    3 6 10 3 0 rw AMAIR_EL3
    3 6 10 3 1 rw AMAIR2_EL3
    3 6 10 5 0 rw MPAM3_EL3
    3 6 10 5 4 rw MPAMBW3_EL3
    3 6 12 0 0 rw VBAR_EL3
    3 6 12 0 1 ro RVBAR_EL3
    3 6 12 0 2 rw RMR_EL3
    3 6 12 1 1 rw VDISR_EL3
    3 6 12 12 4 rw ICC_CTLR_EL3
    3 6 12 12 5 rw ICC_SRE_EL3
    3 6 12 12 7 rw ICC_IGRPEN1_EL3
    3 6 13 0 0 rw TPIDR3_EL3
    3 6 13 0 2 rw TPIDR_EL3
    3 6 13 0 7 rw SCXTNUM_EL3
    3 7 14 2 0 rw CNTPS_TVAL_EL1
    3 7 14 2 1 rw CNTPS_CTL_EL1
    3 7 14 2 2 rw CNTPS_CVAL_EL1
    """

    public static let allRegisters: [A64SystemRegisterDescriptor] = {
        var result: [A64SystemRegisterDescriptor] = []
        result.reserveCapacity(1248)
        for rawLine in rawCatalog.split(whereSeparator: \.isNewline) {
            let parts = rawLine.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count == 7,
                  let op0 = UInt8(parts[0]),
                  let op1 = UInt8(parts[1]),
                  let crn = UInt8(parts[2]),
                  let crm = UInt8(parts[3]),
                  let op2 = UInt8(parts[4])
            else {
                continue
            }
            let mode = parts[5]
            let name = String(parts[6])
            let isReadable = (mode == "rw" || mode == "ro")
            let isWritable = (mode == "rw" || mode == "wo")
            result.append(
                A64SystemRegisterDescriptor(
                    name: name,
                    op0: op0,
                    op1: op1,
                    crn: crn,
                    crm: crm,
                    op2: op2,
                    summary: curatedSummaries[name] ?? "",
                    isReadable: isReadable,
                    isWritable: isWritable
                )
            )
        }
        return result
    }()

    private static let byReadEncoding: [UInt16: A64SystemRegisterDescriptor] = {
        var map: [UInt16: A64SystemRegisterDescriptor] = [:]
        map.reserveCapacity(allRegisters.count)
        for reg in allRegisters where reg.isReadable {
            map[reg.encoding] = reg
        }
        return map
    }()

    private static let byWriteEncoding: [UInt16: A64SystemRegisterDescriptor] = {
        var map: [UInt16: A64SystemRegisterDescriptor] = [:]
        map.reserveCapacity(allRegisters.count)
        for reg in allRegisters where reg.isWritable {
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
        byReadEncoding[encoding] ?? byWriteEncoding[encoding]
    }

    public static func lookup(encoding: UInt16, isRead: Bool) -> A64SystemRegisterDescriptor? {
        isRead ? byReadEncoding[encoding] : byWriteEncoding[encoding]
    }

    public static func name(forEncoding encoding: UInt16) -> String {
        if let known = lookup(encoding: encoding) {
            return known.name
        }
        let parts = unpackEncoding(encoding)
        return "S\(parts.op0)_\(parts.op1)_C\(parts.crn)_C\(parts.crm)_\(parts.op2)"
    }

    public static func name(forEncoding encoding: UInt16, isRead: Bool) -> String {
        if let known = lookup(encoding: encoding, isRead: isRead) {
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
