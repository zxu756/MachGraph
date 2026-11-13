import Foundation

// MARK: - ARM64 Register File

public enum A64RegisterBank: String, Sendable, Codable, Hashable {
    case gp64
    case gp32
    case stackPointer
    case zeroRegister
    case simdByte
    case simdHalf
    case simdSingle
    case simdDouble
    case simdQuad
    case simdVector
    case special
}

public struct A64Register: Sendable, Codable, Hashable, CustomStringConvertible {
    public let bank: A64RegisterBank
    public let index: UInt8
    public let bitWidth: Int
    public let vectorArrangement: String?

    public init(bank: A64RegisterBank, index: UInt8, bitWidth: Int, vectorArrangement: String? = nil) {
        self.bank = bank
        self.index = index
        self.bitWidth = bitWidth
        self.vectorArrangement = vectorArrangement
    }

    public static func x(_ index: UInt8, allowSP: Bool = false) -> A64Register {
        if index == 31 {
            return allowSP ? .sp : .xzr
        }
        return A64Register(bank: .gp64, index: index & 31, bitWidth: 64)
    }

    public static func w(_ index: UInt8, allowWSP: Bool = false) -> A64Register {
        if index == 31 {
            return allowWSP ? .wsp : .wzr
        }
        return A64Register(bank: .gp32, index: index & 31, bitWidth: 32)
    }

    public static func gp(_ index: UInt8, is64Bit: Bool, allowSP: Bool = false) -> A64Register {
        is64Bit ? .x(index, allowSP: allowSP) : .w(index, allowWSP: allowSP)
    }

    public static func b(_ index: UInt8) -> A64Register { A64Register(bank: .simdByte, index: index & 31, bitWidth: 8) }
    public static func h(_ index: UInt8) -> A64Register { A64Register(bank: .simdHalf, index: index & 31, bitWidth: 16) }
    public static func s(_ index: UInt8) -> A64Register { A64Register(bank: .simdSingle, index: index & 31, bitWidth: 32) }
    public static func d(_ index: UInt8) -> A64Register { A64Register(bank: .simdDouble, index: index & 31, bitWidth: 64) }
    public static func q(_ index: UInt8) -> A64Register { A64Register(bank: .simdQuad, index: index & 31, bitWidth: 128) }
    public static func v(_ index: UInt8, arrangement: String) -> A64Register {
        A64Register(bank: .simdVector, index: index & 31, bitWidth: 128, vectorArrangement: arrangement)
    }

    public static let sp = A64Register(bank: .stackPointer, index: 31, bitWidth: 64)
    public static let wsp = A64Register(bank: .stackPointer, index: 31, bitWidth: 32)
    public static let xzr = A64Register(bank: .zeroRegister, index: 31, bitWidth: 64)
    public static let wzr = A64Register(bank: .zeroRegister, index: 31, bitWidth: 32)
    public static let fp = A64Register(bank: .gp64, index: 29, bitWidth: 64)
    public static let lr = A64Register(bank: .gp64, index: 30, bitWidth: 64)
    public static let pc = A64Register(bank: .special, index: 32, bitWidth: 64)
    public static let nzcv = A64Register(bank: .special, index: 33, bitWidth: 32)

    public var isGeneralPurpose: Bool {
        bank == .gp64 || bank == .gp32 || bank == .stackPointer || bank == .zeroRegister
    }

    public var isZeroRegister: Bool {
        bank == .zeroRegister
    }

    public var isStackPointer: Bool {
        bank == .stackPointer
    }

    public var isSIMD: Bool {
        switch bank {
        case .simdByte, .simdHalf, .simdSingle, .simdDouble, .simdQuad, .simdVector:
            return true
        default:
            return false
        }
    }

    public var canonicalName: String {
        switch bank {
        case .gp64:
            if index == 29 { return "x29" }
            if index == 30 { return "x30" }
            return "x\(index)"
        case .gp32:
            return "w\(index)"
        case .stackPointer:
            return bitWidth == 64 ? "sp" : "wsp"
        case .zeroRegister:
            return bitWidth == 64 ? "xzr" : "wzr"
        case .simdByte:
            return "b\(index)"
        case .simdHalf:
            return "h\(index)"
        case .simdSingle:
            return "s\(index)"
        case .simdDouble:
            return "d\(index)"
        case .simdQuad:
            return "q\(index)"
        case .simdVector:
            if let arr = vectorArrangement {
                return "v\(index).\(arr)"
            }
            return "v\(index)"
        case .special:
            if index == 32 { return "pc" }
            if index == 33 { return "nzcv" }
            return "sys\(index)"
        }
    }

    public var abiDisplayName: String {
        if bank == .gp64 && index == 29 { return "fp" }
        if bank == .gp64 && index == 30 { return "lr" }
        return canonicalName
    }

    public var description: String { canonicalName }
}

// MARK: - Condition Codes, Shifts & Addressing Modes

public enum A64ConditionCode: UInt8, Sendable, Codable, Hashable, CaseIterable, CustomStringConvertible {
    case eq = 0x0
    case ne = 0x1
    case cs = 0x2 // hs
    case cc = 0x3 // lo
    case mi = 0x4
    case pl = 0x5
    case vs = 0x6
    case vc = 0x7
    case hi = 0x8
    case ls = 0x9
    case ge = 0xA
    case lt = 0xB
    case gt = 0xC
    case le = 0xD
    case al = 0xE
    case nv = 0xF

    public init(nibble: UInt32) {
        self = A64ConditionCode(rawValue: UInt8(nibble & 0xF)) ?? .al
    }

    public static func from(text: String) -> A64ConditionCode? {
        switch text.lowercased() {
        case "eq": return .eq
        case "ne": return .ne
        case "cs", "hs": return .cs
        case "cc", "lo": return .cc
        case "mi": return .mi
        case "pl": return .pl
        case "vs": return .vs
        case "vc": return .vc
        case "hi": return .hi
        case "ls": return .ls
        case "ge": return .ge
        case "lt": return .lt
        case "gt": return .gt
        case "le": return .le
        case "al": return .al
        case "nv": return .nv
        default: return nil
        }
    }

    public var mnemonicSuffix: String {
        switch self {
        case .eq: return "eq"
        case .ne: return "ne"
        case .cs: return "hs"
        case .cc: return "lo"
        case .mi: return "mi"
        case .pl: return "pl"
        case .vs: return "vs"
        case .vc: return "vc"
        case .hi: return "hi"
        case .ls: return "ls"
        case .ge: return "ge"
        case .lt: return "lt"
        case .gt: return "gt"
        case .le: return "le"
        case .al: return "al"
        case .nv: return "nv"
        }
    }

    public var inverted: A64ConditionCode {
        A64ConditionCode(rawValue: rawValue ^ 1) ?? .al
    }

    public var cOperatorSymbol: String {
        switch self {
        case .eq: return "=="
        case .ne: return "!="
        case .cs: return ">="
        case .cc: return "<"
        case .mi: return "< 0"
        case .pl: return ">= 0"
        case .vs: return "overflow"
        case .vc: return "!overflow"
        case .hi: return ">"
        case .ls: return "<="
        case .ge: return ">="
        case .lt: return "<"
        case .gt: return ">"
        case .le: return "<="
        case .al: return "true"
        case .nv: return "true"
        }
    }

    public var description: String { mnemonicSuffix }
}

public enum A64ShiftExtend: Sendable, Codable, Hashable, CustomStringConvertible {
    case lsl(UInt8)
    case lsr(UInt8)
    case asr(UInt8)
    case ror(UInt8)
    case uxtb(UInt8)
    case uxth(UInt8)
    case uxtw(UInt8)
    case uxtx(UInt8)
    case sxtb(UInt8)
    case sxth(UInt8)
    case sxtw(UInt8)
    case sxtx(UInt8)

    public var description: String {
        switch self {
        case .lsl(let n): return n == 0 ? "lsl #0" : "lsl #\(n)"
        case .lsr(let n): return "lsr #\(n)"
        case .asr(let n): return "asr #\(n)"
        case .ror(let n): return "ror #\(n)"
        case .uxtb(let n): return n == 0 ? "uxtb" : "uxtb #\(n)"
        case .uxth(let n): return n == 0 ? "uxth" : "uxth #\(n)"
        case .uxtw(let n): return n == 0 ? "uxtw" : "uxtw #\(n)"
        case .uxtx(let n): return n == 0 ? "uxtx" : "uxtx #\(n)"
        case .sxtb(let n): return n == 0 ? "sxtb" : "sxtb #\(n)"
        case .sxth(let n): return n == 0 ? "sxth" : "sxth #\(n)"
        case .sxtw(let n): return n == 0 ? "sxtw" : "sxtw #\(n)"
        case .sxtx(let n): return n == 0 ? "sxtx" : "sxtx #\(n)"
        }
    }
}

public enum A64AddressingMode: Sendable, Codable, Hashable, CustomStringConvertible {
    case baseOffset(base: A64Register, offset: Int64)
    case preIndex(base: A64Register, offset: Int64)
    case postIndex(base: A64Register, offset: Int64)
    case registerOffset(base: A64Register, index: A64Register, extend: A64ShiftExtend?)
    case pcRelativeLiteral(target: VirtualAddress)

    public var description: String {
        switch self {
        case .baseOffset(let base, let offset):
            if offset == 0 {
                return "[\(base.canonicalName)]"
            }
            let sign = offset < 0 ? "-" : ""
            let mag = offset < 0 ? UInt64(bitPattern: -offset) : UInt64(bitPattern: offset)
            let immStr = mag >= 16 ? "0x\(String(mag, radix: 16))" : "\(mag)"
            return "[\(base.canonicalName), #\(sign)\(immStr)]"
        case .preIndex(let base, let offset):
            let sign = offset < 0 ? "-" : ""
            let mag = offset < 0 ? UInt64(bitPattern: -offset) : UInt64(bitPattern: offset)
            let immStr = mag >= 16 ? "0x\(String(mag, radix: 16))" : "\(mag)"
            return "[\(base.canonicalName), #\(sign)\(immStr)]!"
        case .postIndex(let base, let offset):
            let sign = offset < 0 ? "-" : ""
            let mag = offset < 0 ? UInt64(bitPattern: -offset) : UInt64(bitPattern: offset)
            let immStr = mag >= 16 ? "0x\(String(mag, radix: 16))" : "\(mag)"
            return "[\(base.canonicalName)], #\(sign)\(immStr)"
        case .registerOffset(let base, let index, let extend):
            if let ext = extend {
                return "[\(base.canonicalName), \(index.canonicalName), \(ext.description)]"
            }
            return "[\(base.canonicalName), \(index.canonicalName)]"
        case .pcRelativeLiteral(let target):
            return target.compactHexString
        }
    }
}

// MARK: - Operands, Instruction Groups, Flow Semantics & Mnemonics

public enum A64Operand: Sendable, Codable, Hashable, CustomStringConvertible {
    case register(A64Register)
    case immediate(Int64)
    case unsignedImmediate(UInt64)
    case fpImmediate(Double)
    case branchTarget(VirtualAddress)
    case memory(A64AddressingMode)
    case shiftedRegister(A64Register, A64ShiftExtend)
    case shiftedImmediate(UInt64, shiftBits: UInt8)
    case condition(A64ConditionCode)
    case systemRegister(name: String, encoding: UInt16)
    case barrierOption(String)
    case prefetchOp(String)

    public var description: String {
        switch self {
        case .register(let reg):
            return reg.canonicalName
        case .immediate(let val):
            if val < 0 {
                let mag = UInt64(bitPattern: -val)
                return mag >= 16 ? "#-0x\(String(mag, radix: 16))" : "#-\(mag)"
            }
            return val >= 16 ? "#0x\(String(val, radix: 16))" : "#\(val)"
        case .unsignedImmediate(let val):
            return val >= 16 ? "#0x\(String(val, radix: 16))" : "#\(val)"
        case .fpImmediate(let d):
            return String(format: "#%.6g", d)
        case .branchTarget(let addr):
            return addr.compactHexString
        case .memory(let mode):
            return mode.description
        case .shiftedRegister(let reg, let shift):
            return "\(reg.canonicalName), \(shift.description)"
        case .shiftedImmediate(let imm, let shift):
            let immText = imm >= 16 ? "#0x\(String(imm, radix: 16))" : "#\(imm)"
            return shift == 0 ? immText : "\(immText), lsl #\(shift)"
        case .condition(let cond):
            return cond.mnemonicSuffix
        case .systemRegister(let name, _):
            return name
        case .barrierOption(let opt):
            return opt
        case .prefetchOp(let op):
            return op
        }
    }
}

public enum A64InstructionGroup: String, Sendable, Codable, Hashable, CaseIterable {
    case dataProcessingImm = "Data Processing (Immediate)"
    case dataProcessingReg = "Data Processing (Register)"
    case branchAndSystem = "Branch, Exception & System"
    case loadStore = "Loads & Stores"
    case simdAndFP = "SIMD & Floating-Point"
    case pacPointerAuth = "Pointer Authentication (ARMv8.3)"
    case atomicLSE = "Large System Extensions (Atomics)"
    case unknown = "Unallocated / Raw Word"
}

public enum A64FlowSemantics: Sendable, Codable, Hashable {
    case sequential
    case unconditionalJump(target: VirtualAddress)
    case conditionalBranch(target: VirtualAddress, condition: A64ConditionCode)
    case directCall(target: VirtualAddress)
    case indirectJump(register: A64Register)
    case indirectCall(register: A64Register)
    case returnControl
    case trapOrSupervisor(immediate: UInt16)

    public var terminatesBasicBlock: Bool {
        switch self {
        case .sequential, .directCall, .indirectCall:
            return false
        case .unconditionalJump, .conditionalBranch, .indirectJump, .returnControl, .trapOrSupervisor:
            return true
        }
    }
}

public enum A64Mnemonic: String, Sendable, Codable, Hashable, CaseIterable {
    // Arithmetic & Logical
    case add, adds, sub, subs, cmp, cmn, neg, negs
    case adc, adcs, sbc, sbcs, ngc, ngcs
    case and, ands, tst, orr, orn, eor, eon, bic, bics, mvn
    // Moves & PC-relative
    case mov, movz, movn, movk, adr, adrp
    // Bitfield & Shifts
    case bfm, sbfm, ubfm, bfi, bfxil, sbfiz, sbfx, ubfiz, ubfx
    case lsl, lsr, asr, ror, extr
    case sxtb, sxth, sxtw, uxtb, uxth
    // Multiply & Divide
    case madd, msub, mul, mneg, smaddl, smsubl, smnegl, smull, smulh, umaddl, umsubl, umnegl, umull, umulh
    case udiv, sdiv
    // Bit Manipulation & CRC
    case clz, cls, rbit, rev, rev16, rev32
    case crc32b, crc32h, crc32w, crc32x, crc32cb, crc32ch, crc32cw, crc32cx
    // Conditional Select & Compare
    case csel, csinc, csinv, csneg, cset, csetm, cinc, cinv, cneg
    case ccmp, ccmn
    // Branches, Calls & Returns
    case b, bCond = "b.cond", bl, br, blr, ret
    case cbz, cbnz, tbz, tbnz
    // Pointer Authentication (ARMv8.3-A / arm64e)
    case paciasp, pacibsp, autiasp, autibsp, paciza, pacizb, autiza, autizb
    case retaa, retab, braa, brab, braaz, brabz, blraa, blrab, blraaz, blrabz, xpaci, xpacd
    // System, Exceptions & Barriers
    case nop, yield, wfe, wfi, sev, sevl, hint, bti
    case svc, hvc, smc, brk, hlt
    case msr, mrs, dmb, dsb, isb, clrex, sys
    // Loads & Stores
    case ldr, ldrb, ldrh, ldrsb, ldrsh, ldrsw
    case ldur, ldurb, ldurh, ldursb, ldursh, ldursw
    case ldp, ldpsw, ldnp
    case str, strb, strh, stur, sturb, sturh, stp, stnp
    case prfm
    // Exclusive & LSE Atomics
    case ldxr, ldaxr, ldar, ldarb, ldarh
    case stxr, stlxr, stlr, stlrb, stlrh
    case ldadd, ldadda, ldaddal, ldaddl, ldset, ldclr, swp, swpa, swpal, swpl, cas, casa, casal, casl
    // Floating-Point & Scalar/Vector SIMD
    case fmov, fadd, fsub, fmul, fdiv, fnmul, fmadd, fmsub, fabs, fneg, fsqrt
    case fmin, fmax, fminnm, fmaxnm, frintn, frintp, frintm, frintz
    case fcmp, fcmpe, fccmp, fcsel
    case fcvt, scvtf, ucvtf, fcvtzs, fcvtzu, fcvtas, fcvtau
    case dup, ins, umov, smov, movi, eorVec = "eor.vec", orrVec = "orr.vec", andVec = "and.vec", cmeq, addv
    // Fallback
    case unknown = ".inst"
}

public struct A64DecodedInstruction: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { address.rawValue }
    public let address: VirtualAddress
    public let rawWord: UInt32
    public let mnemonic: A64Mnemonic
    public let mnemonicText: String
    public let operands: [A64Operand]
    public let operandText: String
    public let group: A64InstructionGroup
    public let flow: A64FlowSemantics
    public let readsRegisters: [A64Register]
    public let writesRegisters: [A64Register]
    public let readsFlags: Bool
    public let writesFlags: Bool
    public let autoComment: String?

    public init(
        address: VirtualAddress,
        rawWord: UInt32,
        mnemonic: A64Mnemonic,
        mnemonicText: String? = nil,
        operands: [A64Operand],
        operandText: String? = nil,
        group: A64InstructionGroup,
        flow: A64FlowSemantics = .sequential,
        readsRegisters: [A64Register] = [],
        writesRegisters: [A64Register] = [],
        readsFlags: Bool = false,
        writesFlags: Bool = false,
        autoComment: String? = nil
    ) {
        self.address = address
        self.rawWord = rawWord
        self.mnemonic = mnemonic
        self.mnemonicText = mnemonicText ?? mnemonic.rawValue
        self.operands = operands
        self.operandText = operandText ?? operands.map(\.description).joined(separator: ", ")
        self.group = group
        self.flow = flow
        self.readsRegisters = readsRegisters
        self.writesRegisters = writesRegisters
        self.readsFlags = readsFlags
        self.writesFlags = writesFlags
        self.autoComment = autoComment
    }

    public var rawBytesLE: [UInt8] {
        [
            UInt8(truncatingIfNeeded: rawWord),
            UInt8(truncatingIfNeeded: rawWord >> 8),
            UInt8(truncatingIfNeeded: rawWord >> 16),
            UInt8(truncatingIfNeeded: rawWord >> 24)
        ]
    }

    public var rawBytesHex: String {
        String(format: "%02x %02x %02x %02x", rawBytesLE[0], rawBytesLE[1], rawBytesLE[2], rawBytesLE[3])
    }

    public var formattedDisassembly: String {
        if operandText.isEmpty {
            return mnemonicText
        }
        return "\(mnemonicText) \(operandText)"
    }
}
