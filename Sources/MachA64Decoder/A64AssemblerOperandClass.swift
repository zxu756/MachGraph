import Foundation
import MachGraphModels

// MARK: - ARM64 Inline Assembler Operand Lexer, Classifier, Gate & Form Normalizer

enum A64AssemblerOperandClass: Equatable, Hashable, Sendable {
    case gpX                     // x0..x30, xzr, sp, fp, lr
    case gpW                     // w0..w30, wzr, wsp
    case scalarB                 // b0..b31
    case scalarH                 // h0..h31
    case scalarS                 // s0..s31
    case scalarD                 // d0..d31
    case scalarQ                 // q0..q31
    case vector(String)          // v0..v31.<arr> (8b, 16b, 4h, 8h, 2s, 4s, 1d, 2d, 1q, 4b, 2h)
    case vectorElement(String)   // v0..v31.<t>[i] (b, h, s, d, q, 4b, 2h)
    case registerList            // { ... } or { ... }[i]
    case immediate               // #<int|float>
    case shiftOrExtend           // lsl/lsr/asr/ror/msl #n, uxtb..sxtx [#n]
    case memory                  // [...] or [...]!
    case other                   // condition, sysreg, barrier, prfop, bti opt, c<n>, label, ., .±N, bare address

    var isScalarFPOrSIMD: Bool {
        switch self {
        case .scalarB, .scalarH, .scalarS, .scalarD, .scalarQ:
            return true
        default:
            return false
        }
    }

    var isGP: Bool {
        self == .gpX || self == .gpW
    }

    /// SIMD classes: scalar B/H/S/D/Q, vector V.<arrangement>, vector element V.<t>[i], and register list {...}.
    var isSIMD: Bool {
        switch self {
        case .scalarB, .scalarH, .scalarS, .scalarD, .scalarQ,
             .vector, .vectorElement, .registerList:
            return true
        case .gpX, .gpW, .immediate, .shiftOrExtend, .memory, .other:
            return false
        }
    }
}

enum A64AssemblerLexicalError: Error, Equatable, Sendable {
    case message(String)
}

package enum A64AssemblerOperandClassifier {

    package static let validVectorArrangements: Set<String> = [
        "8b", "16b", "4h", "8h", "2s", "4s", "1d", "2d", "1q", "4b", "2h",
    ]

    package static let validVectorElementTypes: Set<String> = [
        "b", "h", "s", "d", "q", "4b", "2h",
    ]

    private static let validRegisterListSpecs: Set<String> = validVectorArrangements.union(validVectorElementTypes)

    private static let shiftKeywords: Set<String> = [
        "lsl", "lsr", "asr", "ror", "msl",
    ]

    private static let extendKeywords: Set<String> = [
        "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
    ]

    // MARK: - Splitting Mnemonic & Operands Outside [...] and {...}

    package static func splitMnemonicAndOperands(_ statement: String) -> (mnemonic: String, operands: [String]) {
        let trimmed = statement.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let splitIdx = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" }) else {
            return (trimmed.lowercased(), [])
        }
        let mnem = String(trimmed[..<splitIdx]).lowercased()
        let rest = String(trimmed[splitIdx...]).trimmingCharacters(in: .whitespaces)
        if rest.isEmpty {
            return (mnem, [])
        }

        var operands: [String] = []
        var current = ""
        var bracketDepth = 0
        var braceDepth = 0
        for ch in rest {
            if ch == "[" {
                bracketDepth += 1
                current.append(ch)
            } else if ch == "]" {
                bracketDepth = max(0, bracketDepth - 1)
                current.append(ch)
            } else if ch == "{" {
                braceDepth += 1
                current.append(ch)
            } else if ch == "}" {
                braceDepth = max(0, braceDepth - 1)
                current.append(ch)
            } else if ch == "," && bracketDepth == 0 && braceDepth == 0 {
                operands.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
            } else {
                current.append(ch)
            }
        }
        operands.append(current.trimmingCharacters(in: .whitespaces))
        return (mnem, operands)
    }

    // MARK: - Lexical Validation & Single-Operand Classification

    static func classifyOperands(
        _ operands: [String],
        labels: [String: VirtualAddress] = [:]
    ) throws -> [A64AssemblerOperandClass] {
        var result: [A64AssemblerOperandClass] = []
        result.reserveCapacity(operands.count)
        for op in operands {
            result.append(try classifyOperand(op, labels: labels))
        }
        return result
    }

    static func classifyOperand(
        _ rawToken: String,
        labels: [String: VirtualAddress] = [:]
    ) throws -> A64AssemblerOperandClass {
        let trimmed = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw A64AssemblerLexicalError.message("Empty operand")
        }

        // 1. Validate balanced [...] and {...} across the operand.
        try verifyBalancedDelimiters(in: trimmed)

        let lower = trimmed.lowercased()

        // 2. Memory: [...] or [...]!
        if lower.hasPrefix("[") {
            let closeIdx = try matchingCloseIndex(in: lower, openChar: "[", closeChar: "]")
            let suffix = String(lower[lower.index(after: closeIdx)...])
            guard suffix.isEmpty || suffix == "!" else {
                throw A64AssemblerLexicalError.message("Malformed memory operand '\(trimmed)'")
            }
            let inner = String(lower[lower.index(after: lower.startIndex)..<closeIdx]).trimmingCharacters(in: .whitespaces)
            guard !inner.isEmpty else {
                throw A64AssemblerLexicalError.message("Empty memory operand '[]'")
            }
            for clause in inner.split(separator: ",", omittingEmptySubsequences: false) {
                let clauseTrimmed = clause.trimmingCharacters(in: .whitespaces)
                guard !clauseTrimmed.isEmpty else {
                    throw A64AssemblerLexicalError.message("Empty clause inside memory operand '\(trimmed)'")
                }
                for word in clauseTrimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }) {
                    let w = String(word)
                    if w.hasPrefix("#") && !isValidImmediateLiteral(w) {
                        throw A64AssemblerLexicalError.message("Invalid immediate '\(w)' in memory operand '\(trimmed)'")
                    }
                    if isVectorLikeToken(w) {
                        _ = try parseVectorOrElementClass(w, rawDisplay: w)
                    }
                }
            }
            return .memory
        }

        // 3. Register list: { ... } or { ... }[i]
        if lower.hasPrefix("{") {
            let closeIdx = try matchingCloseIndex(in: lower, openChar: "{", closeChar: "}")
            let inner = String(lower[lower.index(after: lower.startIndex)..<closeIdx]).trimmingCharacters(in: .whitespaces)
            guard !inner.isEmpty else {
                throw A64AssemblerLexicalError.message("Empty register list '{}'")
            }
            for item in inner.split(whereSeparator: { $0 == "," || $0 == "-" }) {
                let regTok = item.trimmingCharacters(in: .whitespaces)
                guard !regTok.isEmpty, isValidRegisterListEntry(regTok) else {
                    throw A64AssemblerLexicalError.message("Invalid vector register '\(regTok)' in register list '\(trimmed)'")
                }
            }
            let suffix = String(lower[lower.index(after: closeIdx)...]).trimmingCharacters(in: .whitespaces)
            if !suffix.isEmpty {
                guard suffix.hasPrefix("[") && suffix.hasSuffix("]") else {
                    throw A64AssemblerLexicalError.message("Invalid register list suffix '\(suffix)' in '\(trimmed)'")
                }
                let laneStr = String(suffix.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                guard parseUnsignedIndex(laneStr) != nil else {
                    throw A64AssemblerLexicalError.message("Invalid register list lane index '[\(laneStr)]' in '\(trimmed)'")
                }
            }
            return .registerList
        }

        // 4. Immediate: #...
        if lower.hasPrefix("#") {
            guard isValidImmediateLiteral(lower) else {
                throw A64AssemblerLexicalError.message("Invalid immediate '\(trimmed)'")
            }
            return .immediate
        }

        // 5. Shift or extend modifier clause
        let wsParts = lower.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        if wsParts.count >= 2 {
            for part in wsParts where part.hasPrefix("#") {
                guard isValidImmediateLiteral(part) else {
                    throw A64AssemblerLexicalError.message("Invalid immediate '\(part)' in '\(trimmed)'")
                }
            }
            if wsParts.count == 2 {
                let kw = wsParts[0]
                let arg = wsParts[1]
                if shiftKeywords.contains(kw) {
                    if arg.hasPrefix("#") && isValidIntegerLiteral(String(arg.dropFirst())) {
                        return .shiftOrExtend
                    }
                } else if extendKeywords.contains(kw) {
                    let numBody = arg.hasPrefix("#") ? String(arg.dropFirst()) : arg
                    if isValidIntegerLiteral(numBody) {
                        return .shiftOrExtend
                    }
                }
            }
        } else if wsParts.count == 1 && extendKeywords.contains(wsParts[0]) {
            return .shiftOrExtend
        }

        // 6. Defined label in current program/line
        if labels[trimmed] != nil {
            return .other
        }

        // 7. GP and scalar FP/SIMD registers
        switch lower {
        case "xzr", "sp", "fp", "lr":
            return .gpX
        case "wzr", "wsp":
            return .gpW
        default:
            break
        }

        if let first = lower.first, lower.count >= 2 {
            let tail = lower.dropFirst()
            if tail.allSatisfy({ $0.isASCII && $0.isNumber }) {
                switch first {
                case "x":
                    guard let idx = UInt64(tail, radix: 10), idx <= 30 else {
                        throw A64AssemblerLexicalError.message("Invalid register '\(trimmed)'")
                    }
                    return .gpX
                case "w":
                    guard let idx = UInt64(tail, radix: 10), idx <= 30 else {
                        throw A64AssemblerLexicalError.message("Invalid register '\(trimmed)'")
                    }
                    return .gpW
                case "b":
                    guard let idx = UInt64(tail, radix: 10), idx <= 31 else {
                        throw A64AssemblerLexicalError.message("Invalid scalar SIMD register '\(trimmed)'")
                    }
                    return .scalarB
                case "h":
                    guard let idx = UInt64(tail, radix: 10), idx <= 31 else {
                        throw A64AssemblerLexicalError.message("Invalid scalar SIMD register '\(trimmed)'")
                    }
                    return .scalarH
                case "s":
                    guard let idx = UInt64(tail, radix: 10), idx <= 31 else {
                        throw A64AssemblerLexicalError.message("Invalid scalar SIMD register '\(trimmed)'")
                    }
                    return .scalarS
                case "d":
                    guard let idx = UInt64(tail, radix: 10), idx <= 31 else {
                        throw A64AssemblerLexicalError.message("Invalid scalar SIMD register '\(trimmed)'")
                    }
                    return .scalarD
                case "q":
                    guard let idx = UInt64(tail, radix: 10), idx <= 31 else {
                        throw A64AssemblerLexicalError.message("Invalid scalar SIMD register '\(trimmed)'")
                    }
                    return .scalarQ
                default:
                    break
                }
            }
        }

        // 8. Vector V.<arrangement> and element v<n>.<t>[i] (plus malformed v<digit>... spellings)
        if isVectorLikeToken(lower) {
            return try parseVectorOrElementClass(lower, rawDisplay: trimmed)
        }

        return .other
    }

    // MARK: - Gate for Implemented Mnemonics

    /// Set of mnemonics directly dispatched by `A64MiniAssembler.encodeInstruction` (excluding `b.<cond>` / `b<cond>`).
    package static let implementedMnemonics: Set<String> = [
        // Hints, barriers, system registers
        "nop", "yield", "wfe", "wfi", "sev", "sevl", "xpaclri",
        "paciasp", "pacibsp", "autiasp", "autibsp", "retaa", "retab",
        "bti", "clrex", "dmb", "dsb", "isb", "mrs", "msr",
        // Returns, indirect branches & PAC
        "ret", "br", "blr", "braaz", "brabz", "blraaz", "blrabz",
        "braa", "brab", "blraa", "blrab",
        "paciza", "pacizb", "autiza", "autizb", "xpaci", "xpacd",
        "pacia", "pacda",
        // Exceptions & undefined
        "udf", "svc", "hvc", "smc", "brk", "hlt",
        // Direct, compare, test branches & PC-relative
        "b", "bl", "cbz", "cbnz", "tbz", "tbnz", "adr", "adrp",
        // Moves
        "mov", "movz", "movn", "movk",
        // Integer arithmetic & logical
        "add", "adds", "sub", "subs", "cmp", "cmn", "neg", "negs",
        "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs",
        "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "tst", "mvn",
        // Shifts, bitfields & 1-source bit ops
        "lsl", "lsr", "asr", "ror",
        "ubfm", "sbfm", "bfm", "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "extr",
        "sxtb", "sxth", "sxtw", "uxtb", "uxth",
        "rbit", "rev16", "rev32", "rev", "clz", "cls",
        // Multiply, divide & conditional select/compare
        "mul", "mneg", "madd", "msub", "smull", "smaddl", "smsubl", "smulh",
        "umull", "umaddl", "umsubl", "umulh", "udiv", "sdiv",
        "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "ccmp", "ccmn",
        // Loads, stores, pairs & atomics
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
        "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
        "str", "strb", "strh", "stur", "sturb", "sturh",
        "ldp", "ldpsw", "ldnp", "stp", "stnp",
        "ldxr", "ldaxr", "ldar", "ldarb", "ldarh", "stxr", "stlxr", "stlr", "stlrb", "stlrh",
        "cas", "casa", "casal", "casl", "swp", "swpa", "swpal", "swpl",
        "ldadd", "ldadda", "ldaddal", "ldaddl",
        // Scalar FP & implemented NEON vector ops
        "fmov", "fadd", "fsub", "fmul", "fdiv", "fnmul", "fmadd", "fmsub",
        "fabs", "fneg", "fsqrt", "frintp", "frintm", "fmin", "fmax", "fcmp", "fcmpe", "fccmp", "fcsel",
        "fcvt", "scvtf", "ucvtf", "fcvtzs", "fcvtzu",
        "movi", "dup", "umov", "ins", "addv", "cmeq",
    ]

    /// Returns `true` if `classes` may proceed to `A64MiniAssembler`'s encoder for an implemented `mnemonic`,
    /// or `false` if a SIMD operand class is present in an unimplemented operand-class sequence (`assemblerUnsupported`).
    static func allowsOperandClassesForImplementedMnemonic(
        mnemonic: String,
        classes: [A64AssemblerOperandClass]
    ) -> Bool {
        guard classes.contains(where: \.isSIMD) else {
            return true
        }

        switch mnemonic {
        case "fmov":
            guard classes.count == 2 else { return false }
            let c0 = classes[0], c1 = classes[1]
            return (c0.isScalarFPOrSIMD && c1.isScalarFPOrSIMD)
                || (c0.isScalarFPOrSIMD && c1.isGP)
                || (c0.isGP && c1.isScalarFPOrSIMD)
                || (c0.isScalarFPOrSIMD && c1 == .immediate)

        case "fadd", "fsub", "fmul", "fdiv", "fmax", "fmin", "fnmul":
            return classes.count == 3
                && classes[0].isScalarFPOrSIMD
                && classes[1].isScalarFPOrSIMD
                && classes[2].isScalarFPOrSIMD

        case "fmadd", "fmsub":
            return classes.count == 4
                && classes[0].isScalarFPOrSIMD
                && classes[1].isScalarFPOrSIMD
                && classes[2].isScalarFPOrSIMD
                && classes[3].isScalarFPOrSIMD

        case "fabs", "fneg", "fsqrt", "fcvt", "frintp", "frintm":
            return classes.count == 2
                && classes[0].isScalarFPOrSIMD
                && classes[1].isScalarFPOrSIMD

        case "fcmp", "fcmpe":
            return classes.count == 2
                && classes[0].isScalarFPOrSIMD
                && (classes[1].isScalarFPOrSIMD || classes[1] == .immediate)

        case "fccmp":
            return classes.count == 4
                && classes[0].isScalarFPOrSIMD
                && classes[1].isScalarFPOrSIMD
                && classes[2] == .immediate
                && classes[3] == .other

        case "fcsel":
            return classes.count == 4
                && classes[0].isScalarFPOrSIMD
                && classes[1].isScalarFPOrSIMD
                && classes[2].isScalarFPOrSIMD
                && classes[3] == .other

        case "scvtf", "ucvtf":
            return classes.count == 2
                && classes[0].isScalarFPOrSIMD
                && classes[1].isGP

        case "fcvtzs", "fcvtzu":
            return classes.count == 2
                && classes[0].isGP
                && classes[1].isScalarFPOrSIMD

        case "movi":
            if classes.count == 2 && classes[1] == .immediate {
                switch classes[0] {
                case .scalarD,
                     .vector("8b"), .vector("16b"), .vector("2s"), .vector("4s"), .vector("2d"):
                    return true
                default:
                    return false
                }
            }
            if classes.count == 3 && classes[1] == .immediate && classes[2] == .shiftOrExtend {
                return classes[0] == .vector("2s") || classes[0] == .vector("4s")
            }
            return false

        case "dup":
            guard classes.count == 2 else { return false }
            if classes[1].isGP {
                switch classes[0] {
                case .vector("8b"), .vector("16b"),
                     .vector("4h"), .vector("8h"),
                     .vector("2s"), .vector("4s"),
                     .vector("2d"):
                    return true
                default:
                    return false
                }
            }
            switch (classes[0], classes[1]) {
            case (.vector("8b"), .vectorElement("b")),
                 (.vector("16b"), .vectorElement("b")),
                 (.vector("4h"), .vectorElement("h")),
                 (.vector("8h"), .vectorElement("h")),
                 (.vector("2s"), .vectorElement("s")),
                 (.vector("4s"), .vectorElement("s")),
                 (.vector("2d"), .vectorElement("d")):
                return true
            default:
                return false
            }

        case "addv":
            guard classes.count == 2,
                  (classes[0] == .scalarB || classes[0] == .scalarH || classes[0] == .scalarS)
            else { return false }
            switch classes[1] {
            case .vector("8b"), .vector("16b"),
                 .vector("4h"), .vector("8h"),
                 .vector("4s"):
                return true
            default:
                return false
            }

        case "cmeq":
            guard classes.count == 3,
                  case .vector(let t) = classes[0],
                  ["8b", "16b", "4h", "8h", "2s", "4s", "2d"].contains(t),
                  classes[1] == .vector(t)
            else { return false }
            return classes[2] == .vector(t) || classes[2] == .immediate

        case "and", "orr", "eor":
            guard classes.count == 3 else { return false }
            return (classes[0] == .vector("8b") && classes[1] == .vector("8b") && classes[2] == .vector("8b"))
                || (classes[0] == .vector("16b") && classes[1] == .vector("16b") && classes[2] == .vector("16b"))

        case "mov":
            guard classes.count == 2 else { return false }
            return (classes[0] == .vector("8b") && classes[1] == .vector("8b"))
                || (classes[0] == .vector("16b") && classes[1] == .vector("16b"))
                || (classes[0] == .gpW && classes[1] == .vectorElement("s"))
                || (classes[0] == .gpX && classes[1] == .vectorElement("d"))
                || (classes[0] == .vectorElement("b") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("h") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("s") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("d") && classes[1] == .gpX)

        case "ins":
            guard classes.count == 2 else { return false }
            return (classes[0] == .vectorElement("b") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("h") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("s") && classes[1] == .gpW)
                || (classes[0] == .vectorElement("d") && classes[1] == .gpX)

        case "umov":
            guard classes.count == 2 else { return false }
            return (classes[0] == .gpW && classes[1] == .vectorElement("b"))
                || (classes[0] == .gpW && classes[1] == .vectorElement("h"))
                || (classes[0] == .gpW && classes[1] == .vectorElement("s"))
                || (classes[0] == .gpX && classes[1] == .vectorElement("d"))

        case "ldr":
            if classes.count == 2 && classes[0].isScalarFPOrSIMD {
                return classes[1] == .memory || classes[1] == .other || classes[1] == .immediate
            }
            if classes.count == 3 && classes[0].isScalarFPOrSIMD {
                return classes[1] == .memory && classes[2] == .immediate
            }
            return false

        case "str", "ldur", "stur":
            if classes.count == 2 && classes[0].isScalarFPOrSIMD {
                return classes[1] == .memory
            }
            if classes.count == 3 && classes[0].isScalarFPOrSIMD {
                return classes[1] == .memory && classes[2] == .immediate
            }
            return false

        case "ldp", "stp", "ldnp", "stnp":
            if classes.count == 3 && classes[0].isScalarFPOrSIMD && classes[1].isScalarFPOrSIMD {
                return classes[2] == .memory
            }
            if classes.count == 4 && classes[0].isScalarFPOrSIMD && classes[1].isScalarFPOrSIMD {
                return classes[2] == .memory && classes[3] == .immediate
            }
            return false

        default:
            // All other implemented mnemonics are GP-only; any SIMD class is unsupported.
            return false
        }
    }

    // MARK: - Canonical Instruction Shape (`form`) Formatter (Requirement 4)

    /// Formats a statement into its canonical operand-class shape:
    /// - Whole statement lowercased (with comments/labels stripped and whitespace/commas normalized);
    /// - `x0`–`x30`, `w0`–`w30` -> `X`, `W` (`sp`, `wsp`, `xzr`, `wzr` preserved);
    /// - `v<0..31>` -> `V` (arrangement kept);
    /// - `q/d/s/h/b<0..31>` -> `Q/D/S/H/B`;
    /// - Every number (optional `-`, decimal or `0x` hex, including arrangement counts and lane indices) -> `N`.
    package static func formatInstructionForm(mnemonic: String, operands: [String]) -> String {
        let lowerMnem = mnemonic.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !operands.isEmpty else {
            return lowerMnem
        }
        let formattedOps = operands.map { formatSingleOperandShape($0) }
        return "\(lowerMnem) \(formattedOps.joined(separator: ", "))"
    }

    private static func formatSingleOperandShape(_ rawOperand: String) -> String {
        let lower = rawOperand.lowercased()
        let normalized = lower
            .split(separator: ",", omittingEmptySubsequences: false)
            .map { seg in
                seg.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
            }
            .joined(separator: ", ")

        // Pass 1: Replace word-bounded register tokens (x0..x30, w0..w30, v0..v31, q/d/s/h/b0..31).
        let chars = Array(normalized)
        var pass1: [Character] = []
        pass1.reserveCapacity(chars.count)
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            let prevIsWord = (i > 0) && isWordChar(chars[i - 1])
            if !prevIsWord && ((ch >= "a" && ch <= "z") || ch == "_") {
                var j = i + 1
                while j < chars.count && isWordChar(chars[j]) {
                    j += 1
                }
                let word = String(chars[i..<j])
                if let replacement = registerClassLetter(forLowerWord: word) {
                    pass1.append(replacement)
                } else {
                    pass1.append(contentsOf: chars[i..<j])
                }
                i = j
            } else {
                pass1.append(ch)
                i += 1
            }
        }

        // Pass 2: Replace every number (optional '-', hex 0x[0-9a-f]+ or decimal [0-9]+) with 'N'.
        var out = ""
        out.reserveCapacity(pass1.count)
        var k = 0
        while k < pass1.count {
            if pass1[k] == "-", let endIdx = scanUnsignedHexOrDec(in: pass1, from: k + 1) {
                out.append("N")
                k = endIdx
            } else if let endIdx = scanUnsignedHexOrDec(in: pass1, from: k) {
                out.append("N")
                k = endIdx
            } else {
                out.append(pass1[k])
                k += 1
            }
        }
        return out
    }

    private static func isWordChar(_ c: Character) -> Bool {
        (c >= "a" && c <= "z")
            || (c >= "A" && c <= "Z")
            || (c >= "0" && c <= "9")
            || c == "_"
    }

    private static func registerClassLetter(forLowerWord word: String) -> Character? {
        guard word.count >= 2, let first = word.first else { return nil }
        let digits = word.dropFirst()
        guard digits.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let idx = UInt64(digits, radix: 10)
        else { return nil }

        switch first {
        case "x": return idx <= 30 ? "X" : nil
        case "w": return idx <= 30 ? "W" : nil
        case "v": return idx <= 31 ? "V" : nil
        case "q": return idx <= 31 ? "Q" : nil
        case "d": return idx <= 31 ? "D" : nil
        case "s": return idx <= 31 ? "S" : nil
        case "h": return idx <= 31 ? "H" : nil
        case "b": return idx <= 31 ? "B" : nil
        default:  return nil
        }
    }

    private static func scanUnsignedHexOrDec(in chars: [Character], from start: Int) -> Int? {
        guard start < chars.count else { return nil }
        if chars[start] == "0",
           start + 2 < chars.count,
           chars[start + 1] == "x",
           isHexDigit(chars[start + 2]) {
            var p = start + 3
            while p < chars.count && isHexDigit(chars[p]) {
                p += 1
            }
            return p
        }
        if chars[start] >= "0" && chars[start] <= "9" {
            var p = start + 1
            while p < chars.count && chars[p] >= "0" && chars[p] <= "9" {
                p += 1
            }
            return p
        }
        return nil
    }

    private static func isHexDigit(_ c: Character) -> Bool {
        (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F")
    }

    // MARK: - Private Lexical Helpers

    private static func verifyBalancedDelimiters(in text: String) throws {
        var stack: [Character] = []
        for ch in text {
            switch ch {
            case "[", "{":
                stack.append(ch)
            case "]":
                guard stack.popLast() == "[" else {
                    throw A64AssemblerLexicalError.message("Unbalanced ']' in operand '\(text)'")
                }
            case "}":
                guard stack.popLast() == "{" else {
                    throw A64AssemblerLexicalError.message("Unbalanced '}' in operand '\(text)'")
                }
            default:
                break
            }
        }
        if let unclosed = stack.last {
            throw A64AssemblerLexicalError.message("Unclosed '\(unclosed)' in operand '\(text)'")
        }
    }

    private static func matchingCloseIndex(in text: String, openChar: Character, closeChar: Character) throws -> String.Index {
        var depth = 0
        var idx = text.startIndex
        while idx < text.endIndex {
            let ch = text[idx]
            if ch == openChar {
                depth += 1
            } else if ch == closeChar {
                depth -= 1
                if depth == 0 {
                    return idx
                }
            }
            idx = text.index(after: idx)
        }
        throw A64AssemblerLexicalError.message("Unclosed '\(openChar)' in operand '\(text)'")
    }

    private static func isVectorLikeToken(_ lower: String) -> Bool {
        guard lower.hasPrefix("v") else { return false }
        if lower == "v" || lower.hasPrefix("v.") || lower.hasPrefix("v[") {
            return true
        }
        let second = lower[lower.index(after: lower.startIndex)]
        return second.isASCII && second.isNumber
    }

    private static func parseVectorOrElementClass(
        _ lower: String,
        rawDisplay: String
    ) throws -> A64AssemblerOperandClass {
        guard let dotIdx = lower.firstIndex(of: ".") else {
            throw A64AssemblerLexicalError.message("Missing arrangement on vector register '\(rawDisplay)'")
        }
        let numStr = lower[lower.index(after: lower.startIndex)..<dotIdx]
        guard !numStr.isEmpty,
              numStr.allSatisfy({ $0.isASCII && $0.isNumber }),
              let regIdx = UInt64(numStr, radix: 10),
              regIdx <= 31
        else {
            throw A64AssemblerLexicalError.message("Invalid vector register index in '\(rawDisplay)'")
        }

        let afterDot = String(lower[lower.index(after: dotIdx)...])
        if let openBracket = afterDot.firstIndex(of: "[") {
            guard afterDot.hasSuffix("]") else {
                throw A64AssemblerLexicalError.message("Malformed vector element operand '\(rawDisplay)'")
            }
            let elemType = String(afterDot[..<openBracket])
            guard validVectorElementTypes.contains(elemType) else {
                throw A64AssemblerLexicalError.message("Invalid vector element specifier '\(elemType)' in '\(rawDisplay)'")
            }
            let closeBracket = afterDot.index(before: afterDot.endIndex)
            let laneStr = String(afterDot[afterDot.index(after: openBracket)..<closeBracket])
                .trimmingCharacters(in: .whitespaces)
            guard parseUnsignedIndex(laneStr) != nil else {
                throw A64AssemblerLexicalError.message("Invalid vector lane index '[\(laneStr)]' in '\(rawDisplay)'")
            }
            return .vectorElement(elemType)
        }

        guard validVectorArrangements.contains(afterDot) else {
            throw A64AssemblerLexicalError.message("Invalid vector arrangement '\(afterDot)' in '\(rawDisplay)'")
        }
        return .vector(afterDot)
    }

    private static func isValidRegisterListEntry(_ lowerToken: String) -> Bool {
        guard lowerToken.hasPrefix("v") else { return false }
        if let dotIdx = lowerToken.firstIndex(of: ".") {
            let numStr = lowerToken[lowerToken.index(after: lowerToken.startIndex)..<dotIdx]
            let spec = String(lowerToken[lowerToken.index(after: dotIdx)...])
            guard !numStr.isEmpty,
                  numStr.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let idx = UInt64(numStr, radix: 10),
                  idx <= 31
            else { return false }
            return validRegisterListSpecs.contains(spec)
        }
        let numStr = lowerToken.dropFirst()
        guard !numStr.isEmpty,
              numStr.allSatisfy({ $0.isASCII && $0.isNumber }),
              let idx = UInt64(numStr, radix: 10),
              idx <= 31
        else { return false }
        return true
    }

    private static func parseUnsignedIndex(_ s: String) -> UInt64? {
        let clean = s.replacingOccurrences(of: "_", with: "")
        guard !clean.isEmpty else { return nil }
        if clean.hasPrefix("0x") {
            let hex = clean.dropFirst(2)
            guard !hex.isEmpty else { return nil }
            return UInt64(hex, radix: 16)
        }
        guard clean.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return UInt64(clean, radix: 10)
    }

    package static func isValidImmediateLiteral(_ lowerWithHash: String) -> Bool {
        guard lowerWithHash.hasPrefix("#") else { return false }
        let body = String(lowerWithHash.dropFirst())
        guard !body.isEmpty else { return false }
        if isValidIntegerLiteral(body) {
            return true
        }
        return isValidFloatingPointLiteral(body)
    }

    private static func isValidIntegerLiteral(_ lowerBody: String) -> Bool {
        var s = lowerBody.replacingOccurrences(of: "_", with: "")
        if s.hasPrefix("-") || s.hasPrefix("+") {
            s.removeFirst()
        }
        guard !s.isEmpty else { return false }
        if s.hasPrefix("0x") {
            let hex = s.dropFirst(2)
            return !hex.isEmpty && UInt64(hex, radix: 16) != nil
        }
        if s.hasPrefix("0b") {
            let bin = s.dropFirst(2)
            return !bin.isEmpty && UInt64(bin, radix: 2) != nil
        }
        return s.allSatisfy({ $0.isASCII && $0.isNumber }) && UInt64(s, radix: 10) != nil
    }

    private static func isValidFloatingPointLiteral(_ lowerBody: String) -> Bool {
        var s = lowerBody
        if s.hasPrefix("-") || s.hasPrefix("+") {
            s.removeFirst()
        }
        guard !s.isEmpty else { return false }
        let hasDigit = s.contains(where: { $0.isASCII && $0.isNumber })
        let hasFloatMarker = s.contains(".") || s.contains("e") || (s.hasPrefix("0x") && s.contains("p"))
        guard hasDigit && hasFloatMarker else { return false }
        guard let d = Double(lowerBody), d.isFinite else { return false }
        return true
    }
}
