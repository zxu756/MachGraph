import Foundation
import MachGraphModels

// MARK: - Assembled Program Output Model

public struct AssembledProgram: Sendable, Codable, Hashable {
    public let baseAddress: VirtualAddress
    public let words: [UInt32]
    public let bytes: Data
    public let labels: [String: VirtualAddress]
    public let instructions: [A64DecodedInstruction]

    public init(
        baseAddress: VirtualAddress,
        words: [UInt32],
        bytes: Data,
        labels: [String: VirtualAddress],
        instructions: [A64DecodedInstruction]
    ) {
        self.baseAddress = baseAddress
        self.words = words
        self.bytes = bytes
        self.labels = labels
        self.instructions = instructions
    }
}

public typealias A64AssembledProgram = AssembledProgram

// MARK: - Pure Handwritten Two-Pass ARM64 Inline Assembler

public struct A64MiniAssembler: Sendable {
    public init() {}

    /// Assembles a single ARM64 instruction line at `address` into its 32-bit little-endian machine word.
    public func assembleSingle(
        _ instructionText: String,
        at address: VirtualAddress = .zero
    ) throws -> UInt32 {
        let withoutComments = Self.stripComments(from: instructionText).trimmingCharacters(in: .whitespacesAndNewlines)
        let clauses = withoutComments
            .split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard let stripped = clauses.first else {
            throw MachGraphError.assemblerError(line: 1, instruction: instructionText, reason: "Empty instruction text")
        }
        if clauses.count > 1 {
            throw MachGraphError.assemblerError(
                line: 1,
                instruction: instructionText,
                reason: "Multiple semicolon-separated statements passed to assembleSingle; use assembleProgram"
            )
        }

        // Allow optional leading label on single-line input (e.g. "loop: b loop")
        var labels: [String: VirtualAddress] = [:]
        var body = stripped
        while let colonRange = Self.leadingLabelColonIndex(in: body) {
            let labelName = String(body[..<colonRange]).trimmingCharacters(in: .whitespaces)
            labels[labelName] = address
            body = String(body[body.index(after: colonRange)...]).trimmingCharacters(in: .whitespaces)
        }

        guard !body.isEmpty else {
            throw MachGraphError.assemblerError(line: 1, instruction: instructionText, reason: "Label without instruction")
        }

        let (mnemonic, rawOperands) = Self.splitMnemonicAndOperands(body)
        if mnemonic == ".word" || mnemonic == ".inst" {
            guard rawOperands.count == 1, let val = Self.parseSignedOrUnsigned64(rawOperands[0]) else {
                throw MachGraphError.assemblerError(line: 1, instruction: instructionText, reason: "Expected single 32-bit value for \(mnemonic)")
            }
            return UInt32(truncatingIfNeeded: val)
        }

        return try encodeInstruction(
            mnemonic: mnemonic,
            operands: rawOperands,
            at: address,
            labels: labels,
            lineNumber: 1,
            rawSource: instructionText
        )
    }

    /// Two-pass ARM64 program assembler supporting labels (`entry:`, `.L_loop:`), semicolon (`;`) statement separators,
    /// `//` line comments, `.word`/`.inst`/`.quad`/`.p2align` directives, and full decoded instruction round-tripping.
    public func assembleProgram(
        _ source: String,
        baseAddress: VirtualAddress = VirtualAddress(0x1_0000_0000)
    ) throws -> AssembledProgram {
        let rawLines = source.components(separatedBy: .newlines)
        var statements: [ParsedStatement] = []
        var labels: [String: VirtualAddress] = [:]
        var currentOffset: UInt64 = 0

        // Pass 1: Strip // comments, split semicolon-separated statements, collect labels, and compute VirtualAddress
        for (idx, rawLine) in rawLines.enumerated() {
            let lineNum = idx + 1
            let lineWithoutComments = Self.stripComments(from: rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if lineWithoutComments.isEmpty { continue }

            let clauses = lineWithoutComments.split(separator: ";", omittingEmptySubsequences: false)
            for rawClause in clauses {
                var content = String(rawClause).trimmingCharacters(in: .whitespacesAndNewlines)
                if content.isEmpty { continue }

                while let colonIdx = Self.leadingLabelColonIndex(in: content) {
                    let labelName = String(content[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                    guard Self.isValidLabelIdentifier(labelName) else {
                        throw MachGraphError.assemblerError(
                            line: lineNum,
                            instruction: rawLine,
                            reason: "Invalid label identifier '\(labelName)'"
                        )
                    }
                    if labels[labelName] != nil {
                        throw MachGraphError.assemblerError(
                            line: lineNum,
                            instruction: rawLine,
                            reason: "Duplicate label definition '\(labelName)'"
                        )
                    }
                    labels[labelName] = baseAddress.adding(currentOffset)
                    content = String(content[content.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                }

                if content.isEmpty { continue }

                let (mnemonic, operands) = Self.splitMnemonicAndOperands(content)
                let stmtAddr = baseAddress.adding(currentOffset)

                switch mnemonic {
                case ".word", ".inst", ".long":
                    guard !operands.isEmpty else {
                        throw MachGraphError.assemblerError(line: lineNum, instruction: rawLine, reason: "\(mnemonic) requires at least one expression")
                    }
                    statements.append(.wordDirective(values: operands, address: stmtAddr, lineNumber: lineNum, raw: content))
                    currentOffset &+= UInt64(operands.count * 4)

                case ".quad", ".8byte":
                    guard !operands.isEmpty else {
                        throw MachGraphError.assemblerError(line: lineNum, instruction: rawLine, reason: "\(mnemonic) requires at least one 64-bit expression")
                    }
                    statements.append(.quadDirective(values: operands, address: stmtAddr, lineNumber: lineNum, raw: content))
                    currentOffset &+= UInt64(operands.count * 8)

                case ".p2align", ".align":
                    guard let firstOp = operands.first, let power = UInt64(firstOp), power <= 12 else {
                        throw MachGraphError.assemblerError(line: lineNum, instruction: rawLine, reason: "Invalid alignment exponent")
                    }
                    let alignBytes = UInt64(1) << power
                    guard alignBytes >= 4 else { continue }
                    let alignedAddr = stmtAddr.alignedUp(to: alignBytes)
                    let padBytes = alignedAddr.rawValue - stmtAddr.rawValue
                    let nopCount = Int(padBytes / 4)
                    if nopCount > 0 {
                        statements.append(.nopPadding(count: nopCount, address: stmtAddr))
                        currentOffset &+= UInt64(nopCount * 4)
                    }

                case ".global", ".globl", ".text", ".data", ".cfi_startproc", ".cfi_endproc":
                    // Benign assembler metadata directives ignored cleanly
                    continue

                default:
                    statements.append(
                        .instruction(
                            mnemonic: mnemonic,
                            operands: operands,
                            address: stmtAddr,
                            lineNumber: lineNum,
                            raw: content
                        )
                    )
                    currentOffset &+= 4
                }
            }
        }

        // Pass 2: Encode all statements using resolved symbol table
        var words: [UInt32] = []
        words.reserveCapacity(statements.count)

        for stmt in statements {
            switch stmt {
            case .nopPadding(let count, _):
                for _ in 0..<count {
                    words.append(0xD503_201F)
                }

            case .wordDirective(let exprs, _, let lineNum, let raw):
                for expr in exprs {
                    let resolved: UInt64
                    if let labelAddr = labels[expr] {
                        resolved = labelAddr.rawValue
                    } else if let v = Self.parseSignedOrUnsigned64(expr) {
                        resolved = v
                    } else {
                        throw MachGraphError.assemblerError(line: lineNum, instruction: raw, reason: "Cannot evaluate .word expression '\(expr)'")
                    }
                    words.append(UInt32(truncatingIfNeeded: resolved))
                }

            case .quadDirective(let exprs, _, let lineNum, let raw):
                for expr in exprs {
                    let resolved: UInt64
                    if let labelAddr = labels[expr] {
                        resolved = labelAddr.rawValue
                    } else if let v = Self.parseSignedOrUnsigned64(expr) {
                        resolved = v
                    } else {
                        throw MachGraphError.assemblerError(line: lineNum, instruction: raw, reason: "Cannot evaluate .quad expression '\(expr)'")
                    }
                    words.append(UInt32(truncatingIfNeeded: resolved))
                    words.append(UInt32(truncatingIfNeeded: resolved >> 32))
                }

            case .instruction(let mnem, let ops, let addr, let lineNum, let raw):
                let encoded = try encodeInstruction(
                    mnemonic: mnem,
                    operands: ops,
                    at: addr,
                    labels: labels,
                    lineNumber: lineNum,
                    rawSource: raw
                )
                words.append(encoded)
            }
        }

        var writer = BinaryBufferWriter(capacity: words.count * 4, endianness: .little)
        for w in words {
            writer.appendUInt32(w)
        }
        let data = writer.data

        let reverseLabels: [VirtualAddress: String] = {
            var rev: [VirtualAddress: String] = [:]
            for (k, v) in labels {
                if rev[v] == nil {
                    rev[v] = k
                }
            }
            return rev
        }()

        let decoder = A64InstructionDecoder()
        let decoded = decoder.decodeWords(words, baseAddress: baseAddress) { addr in
            reverseLabels[addr]
        }

        return AssembledProgram(
            baseAddress: baseAddress,
            words: words,
            bytes: data,
            labels: labels,
            instructions: decoded
        )
    }

    // MARK: - Internal Statement & Lexer Helpers

    private enum ParsedStatement {
        case instruction(mnemonic: String, operands: [String], address: VirtualAddress, lineNumber: Int, raw: String)
        case wordDirective(values: [String], address: VirtualAddress, lineNumber: Int, raw: String)
        case quadDirective(values: [String], address: VirtualAddress, lineNumber: Int, raw: String)
        case nopPadding(count: Int, address: VirtualAddress)
    }

    private static func stripComments(from line: String) -> String {
        var result = ""
        let chars = Array(line)
        var i = 0
        while i < chars.count {
            if chars[i] == "/" && i + 1 < chars.count && chars[i + 1] == "/" {
                break
            }
            if chars[i] == "/" && i + 1 < chars.count && chars[i + 1] == "*" {
                i += 2
                while i + 1 < chars.count && !(chars[i] == "*" && chars[i + 1] == "/") {
                    i += 1
                }
                i += 2
                continue
            }
            result.append(chars[i])
            i += 1
        }
        return result
    }

    private static func leadingLabelColonIndex(in text: String) -> String.Index? {
        guard let colonIdx = text.firstIndex(of: ":") else { return nil }
        // Make sure colon is before any space/comma/bracket
        for ch in text[..<colonIdx] {
            if ch == " " || ch == "\t" || ch == "," || ch == "[" || ch == "#" {
                return nil
            }
        }
        return colonIdx
    }

    private static func isValidLabelIdentifier(_ name: String) -> Bool {
        guard let first = name.first else { return false }
        guard first.isLetter || first == "_" || first == "." || first == "$" else { return false }
        return name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "$" }
    }

    private static func splitMnemonicAndOperands(_ statement: String) -> (mnemonic: String, operands: [String]) {
        A64AssemblerOperandClassifier.splitMnemonicAndOperands(statement)
    }

    private static func normalizeStatementForm(_ raw: String) -> String {
        let withoutComments = stripComments(from: raw).trimmingCharacters(in: .whitespacesAndNewlines)
        let firstClause = withoutComments
            .split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty } ?? withoutComments

        var body = firstClause
        while let colonRange = leadingLabelColonIndex(in: body) {
            body = String(body[body.index(after: colonRange)...]).trimmingCharacters(in: .whitespaces)
        }

        let (mnem, ops) = splitMnemonicAndOperands(body)
        return A64AssemblerOperandClassifier.formatInstructionForm(mnemonic: mnem, operands: ops)
    }

    private static func parseSignedInt64(_ token: String) -> Int64? {
        var s = token.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "_", with: "")
        if s.hasPrefix("#") {
            s.removeFirst()
        }
        guard !s.isEmpty else { return nil }

        var isNeg = false
        if s.hasPrefix("-") {
            isNeg = true
            s.removeFirst()
        } else if s.hasPrefix("+") {
            s.removeFirst()
        }

        let mag: UInt64?
        if s.lowercased().hasPrefix("0x") {
            mag = UInt64(s.dropFirst(2), radix: 16)
        } else if s.lowercased().hasPrefix("0b") {
            mag = UInt64(s.dropFirst(2), radix: 2)
        } else {
            mag = UInt64(s, radix: 10)
        }
        guard let u = mag else { return nil }
        if isNeg {
            if u == (UInt64(1) << 63) { return Int64.min }
            guard u < (UInt64(1) << 63) else { return nil }
            return -Int64(u)
        }
        return Int64(bitPattern: u)
    }

    private static func parseSignedOrUnsigned64(_ token: String) -> UInt64? {
        guard let signed = parseSignedInt64(token) else { return nil }
        return UInt64(bitPattern: signed)
    }

    private static func parseDoubleImmediate(_ token: String) -> Double? {
        var s = token.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") {
            s.removeFirst()
        }
        return Double(s)
    }

    // MARK: - Top-Level Instruction Encoder Dispatch

    private func err(_ line: Int, _ src: String, _ reason: String) -> MachGraphError {
        .assemblerError(line: line, instruction: src, reason: reason)
    }

    private func requireReg(_ token: String, line: Int, src: String) throws -> A64Register {
        guard let reg = A64RegisterParser.parse(token) else {
            throw err(line, src, "Invalid register '\(token)'")
        }
        return reg
    }

    private func resolveBranchByteOffset(
        token: String,
        pc: VirtualAddress,
        labels: [String: VirtualAddress],
        maxAbsRange: Int64,
        requireWordAligned: Bool,
        line: Int,
        src: String
    ) throws -> Int64 {
        let trimmed = token.trimmingCharacters(in: .whitespaces)
        if let labelAddr = labels[trimmed] {
            let delta = labelAddr - pc
            if requireWordAligned && (delta & 3) != 0 {
                throw err(line, src, "Branch target '\(trimmed)' is not 4-byte aligned")
            }
            guard abs(delta) <= maxAbsRange else {
                throw err(line, src, "Branch target '\(trimmed)' out of range (\(delta) bytes)")
            }
            return delta
        }

        // PC-relative dot syntax: "." or ".+8" or ".-12"
        if trimmed == "." {
            return 0
        }
        if trimmed.hasPrefix(".+") || trimmed.hasPrefix(".-") {
            let relStr = String(trimmed.dropFirst())
            guard let delta = Self.parseSignedInt64(relStr) else {
                throw err(line, src, "Invalid relative offset '\(trimmed)'")
            }
            if requireWordAligned && (delta & 3) != 0 {
                throw err(line, src, "Relative branch offset \(delta) must be a multiple of 4")
            }
            return delta
        }

        // Explicit '#' prefix: negative or small delta is PC-relative; large address near PC is absolute target
        if trimmed.hasPrefix("#") {
            guard let parsed = Self.parseSignedInt64(trimmed) else {
                throw err(line, src, "Invalid branch immediate '\(trimmed)'")
            }
            if parsed < 0 || pc == .zero {
                if requireWordAligned && (parsed & 3) != 0 {
                    throw err(line, src, "Branch offset \(parsed) must be 4-byte aligned")
                }
                return parsed
            }
            let asAddrDelta = VirtualAddress(UInt64(bitPattern: parsed)) - pc
            if abs(asAddrDelta) <= maxAbsRange && abs(parsed) > maxAbsRange {
                if requireWordAligned && (asAddrDelta & 3) != 0 {
                    throw err(line, src, "Target address is not 4-byte aligned")
                }
                return asAddrDelta
            }
            if requireWordAligned && (parsed & 3) != 0 {
                throw err(line, src, "Branch offset \(parsed) must be 4-byte aligned")
            }
            return parsed
        }

        // Bare hex/decimal target address (matches disassembler output e.g. "b 0x100000020")
        guard let rawAddr = Self.parseSignedOrUnsigned64(trimmed) else {
            throw err(line, src, "Unresolved label or invalid target address '\(trimmed)'")
        }
        let delta = VirtualAddress(rawAddr) - pc
        if requireWordAligned && (delta & 3) != 0 {
            throw err(line, src, "Target address 0x\(String(rawAddr, radix: 16)) is not 4-byte aligned")
        }
        guard abs(delta) <= maxAbsRange else {
            throw err(line, src, "Target 0x\(String(rawAddr, radix: 16)) out of branch range from \(pc.compactHexString)")
        }
        return delta
    }

    private func encodeInstruction(
        mnemonic: String,
        operands: [String],
        at pc: VirtualAddress,
        labels: [String: VirtualAddress],
        lineNumber line: Int,
        rawSource src: String
    ) throws -> UInt32 {
        // Conditional branch "b.<cond>" or "b<cond>"
        if mnemonic.hasPrefix("b.") {
            let condStr = String(mnemonic.dropFirst(2))
            guard let cond = A64ConditionCode.from(text: condStr) else {
                throw err(line, src, "Unknown branch condition '\(condStr)'")
            }
            return try encodeConditionalBranch(cond: cond, operands: operands, pc: pc, labels: labels, line: line, src: src)
        }
        if mnemonic.count == 3 && mnemonic.hasPrefix("b") && mnemonic != "bic" && mnemonic != "bfm" && mnemonic != "bfi" && mnemonic != "brk" && mnemonic != "blr" && mnemonic != "bti" {
            let condStr = String(mnemonic.dropFirst())
            if let cond = A64ConditionCode.from(text: condStr) {
                return try encodeConditionalBranch(cond: cond, operands: operands, pc: pc, labels: labels, line: line, src: src)
            }
        }

        // Gate: mnemonic & operand-class validation before per-mnemonic dispatch
        let isImplemented = A64AssemblerOperandClassifier.implementedMnemonics.contains(mnemonic)
        if !isImplemented && !A64KnownMnemonics.all.contains(mnemonic) {
            throw err(line, src, "Unknown ARM64 mnemonic '\(mnemonic)'")
        }

        let operandClasses: [A64AssemblerOperandClass]
        do {
            operandClasses = try A64AssemblerOperandClassifier.classifyOperands(operands, labels: labels)
        } catch let A64AssemblerLexicalError.message(lexReason) {
            throw err(line, src, lexReason)
        }

        if !isImplemented {
            throw MachGraphError.assemblerUnsupported(
                mnemonic: mnemonic,
                form: Self.normalizeStatementForm(src)
            )
        }

        if !A64AssemblerOperandClassifier.allowsOperandClassesForImplementedMnemonic(
            mnemonic: mnemonic,
            classes: operandClasses
        ) {
            throw MachGraphError.assemblerUnsupported(
                mnemonic: mnemonic,
                form: Self.normalizeStatementForm(src)
            )
        }

        // Zero-operand instructions must not carry operands. Accepting and ignoring them would silently
        // discard whatever the caller wrote after the mnemonic (e.g. "nop extra words here").
        switch mnemonic {
        case "nop", "yield", "wfe", "wfi", "sev", "sevl", "xpaclri",
             "paciasp", "pacibsp", "autiasp", "autibsp", "retaa", "retab":
            guard operands.isEmpty else {
                throw err(line, src, "\(mnemonic) takes no operands, got '\(operands.joined(separator: ", "))'")
            }
        case "bti", "clrex", "isb":
            guard operands.count <= 1 else {
                throw err(line, src, "\(mnemonic) takes at most 1 operand, got '\(operands.joined(separator: ", "))'")
            }
        default:
            break
        }

        switch mnemonic {
        // Zero-operand Hints & PAC Hints
        case "nop":     return 0xD503_201F
        case "yield":   return 0xD503_203F
        case "wfe":     return 0xD503_205F
        case "wfi":     return 0xD503_207F
        case "sev":     return 0xD503_209F
        case "sevl":    return 0xD503_20BF
        case "xpaclri": return 0xD503_20FF
        case "paciasp": return 0xD503_233F
        case "pacibsp": return 0xD503_237F
        case "autiasp": return 0xD503_23BF
        case "autibsp": return 0xD503_23FF
        case "retaa":   return 0xD65F_0BFF
        case "retab":   return 0xD65F_0FFF

        case "bti":
            if operands.isEmpty { return 0xD503_241F }
            switch operands[0].lowercased() {
            case "c":  return 0xD503_245F
            case "j":  return 0xD503_249F
            case "jc": return 0xD503_24DF
            default: throw err(line, src, "Invalid BTI landing pad option '\(operands[0])'")
            }

        case "clrex":
            if operands.isEmpty { return 0xD503_3F5F }
            guard let crm = Self.parseSignedOrUnsigned64(operands[0]), crm <= 15 else {
                throw err(line, src, "Invalid CLREX immediate")
            }
            return 0xD503_305F | (UInt32(crm) << 8)

        case "dmb", "dsb":
            guard operands.count == 1, let crm = A64BarrierOptionTable.crm(forText: operands[0]) else {
                throw err(line, src, "Expected barrier option (e.g. ish, sy, osh) for \(mnemonic)")
            }
            let op2: UInt32 = (mnemonic == "dsb") ? 0b100 : 0b101
            return 0xD503_301F | (crm << 8) | (op2 << 5)

        case "isb":
            if operands.isEmpty { return 0xD503_3FDF }
            guard let crm = A64BarrierOptionTable.crm(forText: operands[0]) else {
                throw err(line, src, "Invalid ISB barrier option '\(operands[0])'")
            }
            return 0xD503_30DF | (crm << 8)

        case "mrs":
            guard operands.count == 2 else { throw err(line, src, "MRS expects <Xt>, <sysreg>") }
            let xt = try requireReg(operands[0], line: line, src: src)
            guard xt.bitWidth == 64 && !xt.isStackPointer else { throw err(line, src, "MRS destination must be Xn or XZR") }
            guard let sysEnc = A64SystemRegisterTable.encoding(forName: operands[1]) else {
                throw err(line, src, "Unknown system register '\(operands[1])'")
            }
            return 0xD520_0000 | (UInt32(sysEnc) << 5) | UInt32(xt.index)

        case "msr":
            guard operands.count == 2 else { throw err(line, src, "MSR expects <sysreg>, <Xt>") }
            guard let sysEnc = A64SystemRegisterTable.encoding(forName: operands[0]) else {
                throw err(line, src, "Unknown system register '\(operands[0])'")
            }
            let xt = try requireReg(operands[1], line: line, src: src)
            guard xt.bitWidth == 64 && !xt.isStackPointer else { throw err(line, src, "MSR source must be Xn or XZR") }
            return 0xD500_0000 | (UInt32(sysEnc) << 5) | UInt32(xt.index)

        // Returns & Register Branches (Standard + PAC)
        case "ret":
            if operands.isEmpty { return 0xD65F_03C0 }
            guard operands.count == 1 else { throw err(line, src, "RET takes at most 1 register") }
            let rn = try requireReg(operands[0], line: line, src: src)
            guard rn.bank == .gp64 else { throw err(line, src, "RET requires 64-bit general register") }
            return 0xD65F_0000 | (UInt32(rn.index) << 5)

        case "br", "blr", "braaz", "brabz", "blraaz", "blrabz":
            guard operands.count == 1 else { throw err(line, src, "\(mnemonic) requires 1 target register") }
            let rn = try requireReg(operands[0], line: line, src: src)
            guard rn.bank == .gp64 || rn.isZeroRegister else { throw err(line, src, "\(mnemonic) requires 64-bit Xn") }
            let rnBits = UInt32(rn.index) << 5
            switch mnemonic {
            case "br":     return 0xD61F_0000 | rnBits
            case "blr":    return 0xD63F_0000 | rnBits
            case "braaz":  return 0xD61F_081F | rnBits
            case "brabz":  return 0xD61F_0C1F | rnBits
            case "blraaz": return 0xD63F_081F | rnBits
            default:       return 0xD63F_0C1F | rnBits
            }

        case "braa", "brab", "blraa", "blrab":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) requires <Xn>, <Xm|sp>") }
            let rn = try requireReg(operands[0], line: line, src: src)
            let rm = try requireReg(operands[1], line: line, src: src)
            guard rn.bitWidth == 64 && !rn.isStackPointer, rm.bitWidth == 64 && !rm.isZeroRegister else {
                throw err(line, src, "Invalid registers for \(mnemonic)")
            }
            let regBits = (UInt32(rn.index) << 5) | UInt32(rm.index)
            switch mnemonic {
            case "braa":  return 0xD71F_0800 | regBits
            case "brab":  return 0xD71F_0C00 | regBits
            case "blraa": return 0xD73F_0800 | regBits
            default:      return 0xD73F_0C00 | regBits
            }

        case "paciza", "pacizb", "autiza", "autizb", "xpaci", "xpacd":
            guard operands.count == 1 else { throw err(line, src, "\(mnemonic) requires <Xd>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            guard rd.bank == .gp64 else { throw err(line, src, "\(mnemonic) requires 64-bit Xd") }
            let base: UInt32
            switch mnemonic {
            case "paciza": base = 0xDAC1_23E0
            case "pacizb": base = 0xDAC1_27E0
            case "autiza": base = 0xDAC1_33E0
            case "autizb": base = 0xDAC1_37E0
            case "xpaci":  base = 0xDAC1_43E0
            default:       base = 0xDAC1_47E0
            }
            return base | UInt32(rd.index)

        // Exception Generation & Permanently Undefined
        case "udf":
            guard operands.count == 1,
                  let signed = Self.parseSignedInt64(operands[0]),
                  signed >= 0 && signed <= 0xFFFF
            else {
                throw err(line, src, "udf expects a 16-bit unsigned immediate")
            }
            return UInt32(signed)

        case "svc", "hvc", "smc", "brk", "hlt":
            guard operands.count == 1, let imm = Self.parseSignedOrUnsigned64(operands[0]), imm <= 0xFFFF else {
                throw err(line, src, "\(mnemonic) expects a 16-bit unsigned immediate")
            }
            let immBits = UInt32(imm) << 5
            switch mnemonic {
            case "svc": return 0xD400_0001 | immBits
            case "hvc": return 0xD400_0002 | immBits
            case "smc": return 0xD400_0003 | immBits
            case "brk": return 0xD420_0000 | immBits
            default:    return 0xD440_0000 | immBits
            }

        // Unconditional & Compare/Test Branches
        case "b", "bl":
            guard operands.count == 1 else { throw err(line, src, "\(mnemonic) expects 1 target operand") }
            let delta = try resolveBranchByteOffset(
                token: operands[0],
                pc: pc,
                labels: labels,
                maxAbsRange: 128 * 1024 * 1024,
                requireWordAligned: true,
                line: line,
                src: src
            )
            let imm26 = UInt32(bitPattern: Int32(delta >> 2)) & 0x03FF_FFFF
            return ((mnemonic == "bl") ? 0x9400_0000 : 0x1400_0000) | imm26

        case "cbz", "cbnz":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <Rt>, <target>") }
            let rt = try requireReg(operands[0], line: line, src: src)
            guard rt.isGeneralPurpose && !rt.isStackPointer else { throw err(line, src, "Invalid register for \(mnemonic)") }
            let delta = try resolveBranchByteOffset(
                token: operands[1],
                pc: pc,
                labels: labels,
                maxAbsRange: 1024 * 1024,
                requireWordAligned: true,
                line: line,
                src: src
            )
            let imm19 = UInt32(bitPattern: Int32(delta >> 2)) & 0x7_FFFF
            let sf: UInt32 = (rt.bitWidth == 64) ? (1 << 31) : 0
            let op: UInt32 = (mnemonic == "cbnz") ? (1 << 24) : 0
            return sf | 0x3400_0000 | op | (imm19 << 5) | UInt32(rt.index)

        case "tbz", "tbnz":
            guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <Rt>, #<bit>, <target>") }
            let rt = try requireReg(operands[0], line: line, src: src)
            guard rt.isGeneralPurpose && !rt.isStackPointer,
                  let bitNum = Self.parseSignedOrUnsigned64(operands[1]),
                  bitNum < 64
            else {
                throw err(line, src, "Invalid register or bit index for \(mnemonic)")
            }
            if rt.bitWidth == 32 && bitNum >= 32 {
                throw err(line, src, "Bit index \(bitNum) exceeds 32-bit register width")
            }
            let delta = try resolveBranchByteOffset(
                token: operands[2],
                pc: pc,
                labels: labels,
                maxAbsRange: 32 * 1024,
                requireWordAligned: true,
                line: line,
                src: src
            )
            let imm14 = UInt32(bitPattern: Int32(delta >> 2)) & 0x3FFF
            let b5 = UInt32((bitNum >> 5) & 1) << 31
            let b40 = UInt32(bitNum & 0x1F) << 19
            let op: UInt32 = (mnemonic == "tbnz") ? (1 << 24) : 0
            return b5 | 0x3600_0000 | op | b40 | (imm14 << 5) | UInt32(rt.index)

        // PC-Relative Addressing
        case "adr", "adrp":
            return try encodePCRelative(mnemonic: mnemonic, operands: operands, pc: pc, labels: labels, line: line, src: src)

        // Moves
        case "mov":
            return try encodeMovAlias(operands: operands, line: line, src: src)
        case "movz", "movn", "movk":
            return try encodeMoveWide(mnemonic: mnemonic, operands: operands, line: line, src: src)

        // Arithmetic & Logical
        case "add", "adds", "sub", "subs":
            return try encodeAddSub(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "cmp", "cmn":
            let rewritten = (mnemonic == "cmp") ? "subs" : "adds"
            guard operands.count >= 2 else { throw err(line, src, "\(mnemonic) expects at least 2 operands") }
            let rn = try requireReg(operands[0], line: line, src: src)
            let zr = (rn.bitWidth == 64) ? "xzr" : "wzr"
            return try encodeAddSub(mnemonic: rewritten, operands: [zr] + operands, line: line, src: src)
        case "neg", "negs":
            let rewritten = (mnemonic == "neg") ? "sub" : "subs"
            guard operands.count >= 2 else { throw err(line, src, "\(mnemonic) expects at least 2 operands") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let zr = (rd.bitWidth == 64) ? "xzr" : "wzr"
            return try encodeAddSub(mnemonic: rewritten, operands: [operands[0], zr] + Array(operands.dropFirst()), line: line, src: src)

        case "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs":
            return try encodeCarryArithmetic(mnemonic: mnemonic, operands: operands, line: line, src: src)

        case "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics":
            return try encodeLogicalOrVector(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "tst":
            guard operands.count >= 2 else { throw err(line, src, "TST expects <Rn>, <op2>") }
            let rn = try requireReg(operands[0], line: line, src: src)
            let zr = (rn.bitWidth == 64) ? "xzr" : "wzr"
            return try encodeLogicalOrVector(mnemonic: "ands", operands: [zr] + operands, line: line, src: src)
        case "mvn":
            guard operands.count >= 2 else { throw err(line, src, "MVN expects <Rd>, <Rm>{, shift}") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let zr = (rd.bitWidth == 64) ? "xzr" : "wzr"
            return try encodeLogicalOrVector(mnemonic: "orn", operands: [operands[0], zr] + Array(operands.dropFirst()), line: line, src: src)

        // Shifts, Bitfields & 1-Source Bit Ops
        case "lsl", "lsr", "asr", "ror":
            return try encodeShiftAlias(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "ubfm", "sbfm", "bfm", "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil", "extr",
             "sxtb", "sxth", "sxtw", "uxtb", "uxth":
            return try encodeBitfieldOrExtend(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "rbit", "rev16", "rev32", "rev", "clz", "cls":
            return try encodeOneSourceBitOp(mnemonic: mnemonic, operands: operands, line: line, src: src)

        // Multiply, Divide & Conditional Select/Compare
        case "mul", "mneg", "madd", "msub", "smull", "smaddl", "smsubl", "smulh", "umull", "umaddl", "umsubl", "umulh", "udiv", "sdiv":
            return try encodeMulDiv(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "ccmp", "ccmn":
            return try encodeConditionalSelectOrCompare(mnemonic: mnemonic, operands: operands, line: line, src: src)

        // Loads, Stores, Pairs & Atomics
        case "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
             "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw",
             "str", "strb", "strh", "stur", "sturb", "sturh":
            return try encodeSingleLoadStore(mnemonic: mnemonic, operands: operands, pc: pc, labels: labels, line: line, src: src)
        case "ldp", "ldpsw", "ldnp", "stp", "stnp":
            return try encodeLoadStorePair(mnemonic: mnemonic, operands: operands, line: line, src: src)
        case "ldxr", "ldaxr", "ldar", "ldarb", "ldarh", "stxr", "stlxr", "stlr", "stlrb", "stlrh",
             "cas", "casa", "casal", "casl", "swp", "swpa", "swpal", "swpl", "ldadd", "ldadda", "ldaddal", "ldaddl":
            return try encodeExclusiveOrAtomic(mnemonic: mnemonic, operands: operands, line: line, src: src)

        // Scalar Floating-Point & Common Vector Ops
        case "fmov", "fadd", "fsub", "fmul", "fdiv", "fnmul", "fmadd", "fmsub",
             "fabs", "fneg", "fsqrt", "fmin", "fmax", "fcmp", "fcmpe", "fccmp", "fcsel",
             "fcvt", "scvtf", "ucvtf", "fcvtzs", "fcvtzu",
             "movi", "dup", "addv", "cmeq":
            return try encodeFloatingPointOrSIMD(mnemonic: mnemonic, operands: operands, line: line, src: src)

        default:
            if A64KnownMnemonics.all.contains(mnemonic) {
                throw MachGraphError.assemblerUnsupported(
                    mnemonic: mnemonic,
                    form: Self.normalizeStatementForm(src)
                )
            }
            throw err(line, src, "Unknown ARM64 mnemonic '\(mnemonic)'")
        }
    }

    // MARK: - Specific Family Encoders

    private func encodeConditionalBranch(
        cond: A64ConditionCode,
        operands: [String],
        pc: VirtualAddress,
        labels: [String: VirtualAddress],
        line: Int,
        src: String
    ) throws -> UInt32 {
        guard operands.count == 1 else {
            throw err(line, src, "Conditional branch expects 1 target operand")
        }
        let delta = try resolveBranchByteOffset(
            token: operands[0],
            pc: pc,
            labels: labels,
            maxAbsRange: 1024 * 1024,
            requireWordAligned: true,
            line: line,
            src: src
        )
        let imm19 = UInt32(bitPattern: Int32(delta >> 2)) & 0x7_FFFF
        return 0x5400_0000 | (imm19 << 5) | UInt32(cond.rawValue)
    }

    private func encodePCRelative(
        mnemonic: String,
        operands: [String],
        pc: VirtualAddress,
        labels: [String: VirtualAddress],
        line: Int,
        src: String
    ) throws -> UInt32 {
        guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <Xd>, <target>") }
        let rd = try requireReg(operands[0], line: line, src: src)
        guard rd.bitWidth == 64 && !rd.isStackPointer else {
            throw err(line, src, "\(mnemonic) destination must be 64-bit Xd")
        }

        let targetToken = operands[1].trimmingCharacters(in: .whitespaces)
        if mnemonic == "adr" {
            let delta = try resolveBranchByteOffset(
                token: targetToken,
                pc: pc,
                labels: labels,
                maxAbsRange: 1024 * 1024,
                requireWordAligned: false,
                line: line,
                src: src
            )
            let raw21 = UInt32(bitPattern: Int32(delta)) & 0x1F_FFFF
            let immlo = raw21 & 0x3
            let immhi = (raw21 >> 2) & 0x7_FFFF
            return 0x1000_0000 | (immlo << 29) | (immhi << 5) | UInt32(rd.index)
        } else {
            // ADRP: compute 4KB page difference
            let targetAddr: VirtualAddress
            if let lbl = labels[targetToken] {
                targetAddr = lbl
            } else if targetToken.hasPrefix("#") {
                guard let signedOff = Self.parseSignedInt64(targetToken) else {
                    throw err(line, src, "Invalid ADRP offset '\(targetToken)'")
                }
                if pc == .zero || signedOff < 0 || abs(signedOff) < 0x1_0000_0000 {
                    targetAddr = pc.page4KBase().adding(signedOff)
                } else {
                    targetAddr = VirtualAddress(UInt64(bitPattern: signedOff))
                }
            } else if let rawVal = Self.parseSignedOrUnsigned64(targetToken) {
                targetAddr = VirtualAddress(rawVal)
            } else {
                throw err(line, src, "Unresolved ADRP target '\(targetToken)'")
            }

            let pageDiffBytes = targetAddr.page4KBase() - pc.page4KBase()
            let pageIndex = pageDiffBytes >> 12
            guard pageIndex >= -(1 << 20) && pageIndex < (1 << 20) else {
                throw err(line, src, "ADRP target \(targetAddr.compactHexString) exceeds ±4GB page range")
            }
            let raw21 = UInt32(bitPattern: Int32(pageIndex)) & 0x1F_FFFF
            let immlo = raw21 & 0x3
            let immhi = (raw21 >> 2) & 0x7_FFFF
            return 0x9000_0000 | (immlo << 29) | (immhi << 5) | UInt32(rd.index)
        }
    }

    private func encodeMovAlias(operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 2 || operands.count == 3 else {
            throw err(line, src, "MOV expects <Rd>, <Rm|#imm>")
        }
        let rd = try requireReg(operands[0], line: line, src: src)
        guard rd.isGeneralPurpose else {
            throw err(line, src, "MOV requires general-purpose destination register")
        }
        let is64 = (rd.bitWidth == 64)
        let sf: UInt32 = is64 ? (1 << 31) : 0

        // Register-to-register MOV
        if operands.count == 2, let rm = A64RegisterParser.parse(operands[1]), rm.isGeneralPurpose {
            guard rd.bitWidth == rm.bitWidth else {
                throw err(line, src, "MOV register width mismatch (\(rd.canonicalName) vs \(rm.canonicalName))")
            }
            if rd.isStackPointer || rm.isStackPointer {
                guard !rd.isZeroRegister && !rm.isZeroRegister else {
                    throw err(line, src, "Cannot MOV directly between SP and XZR")
                }
                // ADD <Rd|SP>, <Rm|SP>, #0
                return sf | 0x1100_0000 | (UInt32(rm.index) << 5) | UInt32(rd.index)
            }
            // ORR <Rd>, XZR/WZR, <Rm>
            return sf | 0x2A00_03E0 | (UInt32(rm.index) << 16) | UInt32(rd.index)
        }

        // Shifted wide immediate e.g. "mov x0, #0x1234, lsl #16"
        if operands.count == 3 {
            return try encodeMoveWide(mnemonic: "movz", operands: operands, line: line, src: src)
        }

        // Immediate MOV synthesis: try MOVZ -> MOVN -> Logical Bitmask ORR
        guard let signedImm = Self.parseSignedInt64(operands[1]) else {
            throw err(line, src, "Invalid MOV immediate '\(operands[1])'")
        }
        let raw64 = UInt64(bitPattern: signedImm)
        let masked = is64 ? raw64 : (raw64 & 0xFFFF_FFFF)
        let lanes = is64 ? 4 : 2

        if !rd.isStackPointer {
            if masked == 0 {
                return sf | 0x5280_0000 | UInt32(rd.index) // MOVZ #0
            }
            // Single non-zero 16-bit lane -> MOVZ
            var nonZeroLanes: [(hw: Int, val: UInt16)] = []
            for hw in 0..<lanes {
                let chunk = UInt16(truncatingIfNeeded: masked >> (hw * 16))
                if chunk != 0 {
                    nonZeroLanes.append((hw, chunk))
                }
            }
            if nonZeroLanes.count == 1 {
                let lane = nonZeroLanes[0]
                return sf | 0x5280_0000 | (UInt32(lane.hw) << 21) | (UInt32(lane.val) << 5) | UInt32(rd.index)
            }

            // Single non-0xFFFF 16-bit lane -> MOVN
            let inverted = is64 ? (~masked) : ((~masked) & 0xFFFF_FFFF)
            var invLanes: [(hw: Int, val: UInt16)] = []
            for hw in 0..<lanes {
                let chunk = UInt16(truncatingIfNeeded: inverted >> (hw * 16))
                if chunk != 0 {
                    invLanes.append((hw, chunk))
                }
            }
            if invLanes.count == 1 {
                let lane = invLanes[0]
                return sf | 0x1280_0000 | (UInt32(lane.hw) << 21) | (UInt32(lane.val) << 5) | UInt32(rd.index)
            }
            if invLanes.isEmpty {
                // Constant is all-ones (-1) -> MOVN #0, lsl #0
                return sf | 0x1280_0000 | UInt32(rd.index)
            }
        }

        // Logical bitmask immediate (also supports SP destination!)
        if let bm = encodeBitmaskImmediate(masked, regSize: is64 ? 64 : 32) {
            return sf | 0x3200_03E0 | (bm.n << 22) | (bm.immr << 16) | (bm.imms << 10) | UInt32(rd.index)
        }

        throw err(line, src, "Immediate 0x\(String(masked, radix: 16)) cannot be encoded in a single ARM64 MOV instruction")
    }

    private func encodeMoveWide(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 2 || operands.count == 3 else {
            throw err(line, src, "\(mnemonic) expects <Rd>, #<imm16>{, lsl #<shift>}")
        }
        let rd = try requireReg(operands[0], line: line, src: src)
        guard rd.isGeneralPurpose && !rd.isStackPointer else {
            throw err(line, src, "\(mnemonic) requires non-SP general-purpose register")
        }
        guard let imm = Self.parseSignedOrUnsigned64(operands[1]), imm <= 0xFFFF else {
            throw err(line, src, "\(mnemonic) immediate must fit in 16 unsigned bits (0..0xffff)")
        }

        var hw: UInt32 = 0
        if operands.count == 3 {
            guard let shiftSpec = A64ShiftExtendParser.parse(operands[2]),
                  case .lsl(let shiftAmt) = shiftSpec,
                  shiftAmt % 16 == 0
            else {
                throw err(line, src, "\(mnemonic) shift must be lsl #0, #16, #32, or #48")
            }
            hw = UInt32(shiftAmt / 16)
            if (rd.bitWidth == 32 && hw >= 2) || hw >= 4 {
                throw err(line, src, "Shift lsl #\(shiftAmt) out of range for \(rd.canonicalName)")
            }
        }

        let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
        let opcBase: UInt32
        switch mnemonic {
        case "movn": opcBase = 0x1280_0000
        case "movz": opcBase = 0x5280_0000
        default:     opcBase = 0x7280_0000 // movk
        }
        return sf | opcBase | (hw << 21) | (UInt32(imm) << 5) | UInt32(rd.index)
    }

    private func encodeAddSub(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 3 || operands.count == 4 else {
            throw err(line, src, "\(mnemonic) expects 3 or 4 operands")
        }
        let isSub = mnemonic.hasPrefix("sub")
        let setsFlags = mnemonic.hasSuffix("s")
        let rd = try requireReg(operands[0], line: line, src: src)
        let rn = try requireReg(operands[1], line: line, src: src)
        guard rd.isGeneralPurpose && rn.isGeneralPurpose && rd.bitWidth == rn.bitWidth else {
            throw err(line, src, "Mismatched or invalid general-purpose registers in \(mnemonic)")
        }

        let is64 = (rd.bitWidth == 64)
        let sf: UInt32 = is64 ? (1 << 31) : 0
        let opBit: UInt32 = isSub ? (1 << 30) : 0
        let sBit: UInt32 = setsFlags ? (1 << 29) : 0

        // Case A: Register third operand (Shifted or Extended Register)
        if let rm = A64RegisterParser.parse(operands[2]), rm.isGeneralPurpose {
            var modifier: A64ShiftExtend? = nil
            if operands.count == 4 {
                guard let parsedMod = A64ShiftExtendParser.parse(operands[3]) else {
                    throw err(line, src, "Invalid shift/extend clause '\(operands[3])'")
                }
                modifier = parsedMod
            }

            let involvesSP = rd.isStackPointer || rn.isStackPointer
            let isExplicitExtend: Bool
            if let mod = modifier {
                switch mod {
                case .lsl, .lsr, .asr, .ror: isExplicitExtend = false
                default: isExplicitExtend = true
                }
            } else {
                isExplicitExtend = (rm.bitWidth != rn.bitWidth)
            }

            if involvesSP || isExplicitExtend {
                let ext: A64ShiftExtend
                if let mod = modifier {
                    if case .lsl(let s) = mod {
                        ext = is64 ? .uxtx(s) : .uxtw(s)
                    } else {
                        ext = mod
                    }
                } else {
                    ext = (is64 && rm.bitWidth == 64) ? .uxtx(0) : .uxtw(0)
                }
                guard let (option, imm3) = A64ShiftExtendParser.encodeExtendOption(ext) else {
                    throw err(line, src, "Extend shift in \(mnemonic) must be in 0...4")
                }
                return sf | opBit | sBit | 0x0B20_0000 | (UInt32(rm.index) << 16) | (option << 13) | (imm3 << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
            } else {
                // Shifted Register
                var shiftCode: UInt32 = 0
                var imm6: UInt32 = 0
                if let mod = modifier {
                    switch mod {
                    case .lsl(let n): shiftCode = 0b00; imm6 = UInt32(n)
                    case .lsr(let n): shiftCode = 0b01; imm6 = UInt32(n)
                    case .asr(let n): shiftCode = 0b10; imm6 = UInt32(n)
                    default: throw err(line, src, "ROR shift is not supported in ADD/SUB shifted register")
                    }
                    if (!is64 && imm6 >= 32) || imm6 >= 64 {
                        throw err(line, src, "Shift amount #\(imm6) out of range")
                    }
                }
                return sf | opBit | sBit | 0x0B00_0000 | (shiftCode << 22) | (UInt32(rm.index) << 16) | (imm6 << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
            }
        }

        // Case B: Immediate third operand (supports negative immediate by flipping ADD <-> SUB)
        guard var signedImm = Self.parseSignedInt64(operands[2]) else {
            throw err(line, src, "Invalid immediate or register '\(operands[2])'")
        }
        var effectiveSub = isSub
        if signedImm < 0 {
            effectiveSub.toggle()
            signedImm = -signedImm
        }

        var shBit: UInt32 = 0
        if operands.count == 4 {
            guard let shiftMod = A64ShiftExtendParser.parse(operands[3]),
                  case .lsl(let amt) = shiftMod,
                  (amt == 0 || amt == 12)
            else {
                throw err(line, src, "Immediate ADD/SUB shift must be lsl #0 or lsl #12")
            }
            shBit = (amt == 12) ? (1 << 22) : 0
        } else if signedImm > 0xFFF && (signedImm & 0xFFF) == 0 && (signedImm >> 12) <= 0xFFF {
            signedImm >>= 12
            shBit = (1 << 22)
        }

        guard signedImm >= 0 && signedImm <= 0xFFF else {
            throw err(line, src, "Immediate #\(signedImm) out of 12-bit unsigned range")
        }

        let finalOpBit: UInt32 = effectiveSub ? (1 << 30) : 0
        return sf | finalOpBit | sBit | 0x1100_0000 | shBit | (UInt32(signedImm) << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
    }

    private func encodeCarryArithmetic(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        if mnemonic == "ngc" || mnemonic == "ngcs" {
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rm>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let zr = (rd.bitWidth == 64) ? "xzr" : "wzr"
            let target = (mnemonic == "ngc") ? "sbc" : "sbcs"
            return try encodeCarryArithmetic(mnemonic: target, operands: [operands[0], zr, operands[1]], line: line, src: src)
        }
        guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm>") }
        let rd = try requireReg(operands[0], line: line, src: src)
        let rn = try requireReg(operands[1], line: line, src: src)
        let rm = try requireReg(operands[2], line: line, src: src)
        guard rd.bitWidth == rn.bitWidth && rn.bitWidth == rm.bitWidth && !rd.isStackPointer && !rn.isStackPointer && !rm.isStackPointer else {
            throw err(line, src, "Invalid registers for \(mnemonic)")
        }
        let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
        let op: UInt32 = mnemonic.hasPrefix("sb") ? (1 << 30) : 0
        let s: UInt32 = mnemonic.hasSuffix("s") ? (1 << 29) : 0
        return sf | op | s | 0x1A00_0000 | (UInt32(rm.index) << 16) | (UInt32(rn.index) << 5) | UInt32(rd.index)
    }

    private func encodeLogicalOrVector(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 3 || operands.count == 4 else {
            throw err(line, src, "\(mnemonic) expects 3 or 4 operands")
        }

        // Vector NEON logical (AND.16B / ORR.16B / EOR.16B)
        if let vd = A64RegisterParser.parse(operands[0]), vd.bank == .simdVector {
            guard operands.count == 3,
                  let vn = A64RegisterParser.parse(operands[1]), vn.bank == .simdVector,
                  let vm = A64RegisterParser.parse(operands[2]), vm.bank == .simdVector,
                  vd.vectorArrangement == vn.vectorArrangement,
                  vn.vectorArrangement == vm.vectorArrangement,
                  (vd.vectorArrangement == "16b" || vd.vectorArrangement == "8b")
            else {
                throw err(line, src, "Vector logical \(mnemonic) requires matching .8b or .16b operands")
            }
            let qBit: UInt32 = (vd.vectorArrangement == "16b") ? (1 << 30) : 0
            let base: UInt32
            switch mnemonic {
            case "and": base = 0x0E20_1C00
            case "orr": base = 0x0EA0_1C00
            case "eor": base = 0x2E20_1C00
            default: throw err(line, src, "Unsupported vector logical op '\(mnemonic)'")
            }
            return qBit | base | (UInt32(vm.index) << 16) | (UInt32(vn.index) << 5) | UInt32(vd.index)
        }

        let rd = try requireReg(operands[0], line: line, src: src)
        let rn = try requireReg(operands[1], line: line, src: src)
        guard rd.isGeneralPurpose && rn.isGeneralPurpose && rd.bitWidth == rn.bitWidth && !rn.isStackPointer else {
            throw err(line, src, "Invalid registers in \(mnemonic)")
        }
        let is64 = (rd.bitWidth == 64)
        let sf: UInt32 = is64 ? (1 << 31) : 0

        // Shifted Register Form
        if let rm = A64RegisterParser.parse(operands[2]), rm.isGeneralPurpose {
            guard !rd.isStackPointer && !rm.isStackPointer && rm.bitWidth == rd.bitWidth else {
                throw err(line, src, "Shifted-register \(mnemonic) cannot use SP or mismatched widths")
            }
            var shiftCode: UInt32 = 0
            var imm6: UInt32 = 0
            if operands.count == 4 {
                guard let mod = A64ShiftExtendParser.parse(operands[3]) else {
                    throw err(line, src, "Invalid shift '\(operands[3])'")
                }
                switch mod {
                case .lsl(let n): shiftCode = 0b00; imm6 = UInt32(n)
                case .lsr(let n): shiftCode = 0b01; imm6 = UInt32(n)
                case .asr(let n): shiftCode = 0b10; imm6 = UInt32(n)
                case .ror(let n): shiftCode = 0b11; imm6 = UInt32(n)
                default: throw err(line, src, "Extend modifiers are not valid on logical instructions")
                }
                if (!is64 && imm6 >= 32) || imm6 >= 64 {
                    throw err(line, src, "Shift amount out of range")
                }
            }
            let opc: UInt32
            let nBit: UInt32
            switch mnemonic {
            case "and":  opc = 0b00; nBit = 0
            case "bic":  opc = 0b00; nBit = 1
            case "orr":  opc = 0b01; nBit = 0
            case "orn":  opc = 0b01; nBit = 1
            case "eor":  opc = 0b10; nBit = 0
            case "eon":  opc = 0b10; nBit = 1
            case "ands": opc = 0b11; nBit = 0
            default:     opc = 0b11; nBit = 1 // bics
            }
            return sf | (opc << 29) | 0x0A00_0000 | (shiftCode << 22) | (nBit << 21) | (UInt32(rm.index) << 16) | (imm6 << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        }

        // Logical Bitmask Immediate Form (AND, ORR, EOR, ANDS)
        guard operands.count == 3,
              (mnemonic == "and" || mnemonic == "orr" || mnemonic == "eor" || mnemonic == "ands"),
              let rawImm = Self.parseSignedOrUnsigned64(operands[2])
        else {
            throw err(line, src, "Invalid immediate for \(mnemonic)")
        }
        let maskedImm = is64 ? rawImm : (rawImm & 0xFFFF_FFFF)
        guard let bm = encodeBitmaskImmediate(maskedImm, regSize: is64 ? 64 : 32) else {
            throw err(line, src, "0x\(String(maskedImm, radix: 16)) is not a valid ARM64 bitmask immediate")
        }
        let opc: UInt32
        switch mnemonic {
        case "and":  opc = 0b00
        case "orr":  opc = 0b01
        case "eor":  opc = 0b10
        default:     opc = 0b11
        }
        if opc == 0b11 && rd.isStackPointer {
            throw err(line, src, "ANDS cannot write to SP")
        }
        return sf | (opc << 29) | 0x1200_0000 | (bm.n << 22) | (bm.immr << 16) | (bm.imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
    }

    private func encodeShiftAlias(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm|#shift>") }
        let rd = try requireReg(operands[0], line: line, src: src)
        let rn = try requireReg(operands[1], line: line, src: src)
        guard rd.isGeneralPurpose && rn.isGeneralPurpose && rd.bitWidth == rn.bitWidth && !rd.isStackPointer && !rn.isStackPointer else {
            throw err(line, src, "Invalid registers in \(mnemonic)")
        }
        let is64 = (rd.bitWidth == 64)
        let sf: UInt32 = is64 ? (1 << 31) : 0
        let nBit: UInt32 = is64 ? (1 << 22) : 0
        let regBits: UInt32 = is64 ? 64 : 32

        // Variable shift register (LSLV / LSRV / ASRV / RORV)
        if let rm = A64RegisterParser.parse(operands[2]), rm.isGeneralPurpose {
            guard rm.bitWidth == rd.bitWidth && !rm.isStackPointer else {
                throw err(line, src, "Mismatched register width in \(mnemonic)")
            }
            let op2: UInt32
            switch mnemonic {
            case "lsl": op2 = 0b001000
            case "lsr": op2 = 0b001001
            case "asr": op2 = 0b001010
            default:    op2 = 0b001011 // ror
            }
            return sf | 0x1AC0_0000 | (UInt32(rm.index) << 16) | (op2 << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        }

        // Immediate shift (UBFM / SBFM / EXTR)
        guard let shiftVal = Self.parseSignedOrUnsigned64(operands[2]), shiftVal < UInt64(regBits) else {
            throw err(line, src, "Shift immediate out of range for \(mnemonic)")
        }
        let s = UInt32(shiftVal)
        switch mnemonic {
        case "lsl":
            let immr = (regBits - s) % regBits
            let imms = regBits - 1 - s
            return sf | 0x5300_0000 | nBit | (immr << 16) | (imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        case "lsr":
            let imms = regBits - 1
            return sf | 0x5300_0000 | nBit | (s << 16) | (imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        case "asr":
            let imms = regBits - 1
            return sf | 0x1300_0000 | nBit | (s << 16) | (imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        default: // ror -> extr Rd, Rn, Rn, #s
            return sf | 0x1380_0000 | nBit | (UInt32(rn.index) << 16) | (s << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        }
    }

    private func encodeBitfieldOrExtend(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        switch mnemonic {
        case "sxtb", "sxth", "sxtw", "uxtb", "uxth":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Wn>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let is64 = (mnemonic == "uxtb" || mnemonic == "uxth") ? false : (rd.bitWidth == 64)
            let sf: UInt32 = is64 ? (1 << 31) : 0
            let nBit: UInt32 = is64 ? (1 << 22) : 0
            let opcBase: UInt32 = mnemonic.hasPrefix("u") ? 0x5300_0000 : 0x1300_0000
            let imms: UInt32 = mnemonic.hasSuffix("b") ? 7 : (mnemonic.hasSuffix("h") ? 15 : 31)
            return sf | opcBase | nBit | (imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "extr":
            guard operands.count == 4 else { throw err(line, src, "EXTR expects <Rd>, <Rn>, <Rm>, #<lsb>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            guard let lsb = Self.parseSignedOrUnsigned64(operands[3]) else { throw err(line, src, "Invalid EXTR lsb") }
            let is64 = (rd.bitWidth == 64)
            let sf: UInt32 = is64 ? (1 << 31) : 0
            let nBit: UInt32 = is64 ? (1 << 22) : 0
            return sf | 0x1380_0000 | nBit | (UInt32(rm.index) << 16) | (UInt32(lsb) << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        default:
            guard operands.count == 4 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, #<p1>, #<p2>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            guard let p1 = Self.parseSignedOrUnsigned64(operands[2]),
                  let p2 = Self.parseSignedOrUnsigned64(operands[3])
            else {
                throw err(line, src, "Invalid bitfield immediates")
            }
            let is64 = (rd.bitWidth == 64)
            let regBits: UInt32 = is64 ? 64 : 32
            let sf: UInt32 = is64 ? (1 << 31) : 0
            let nBit: UInt32 = is64 ? (1 << 22) : 0

            let opcBase: UInt32
            let immr: UInt32
            let imms: UInt32
            switch mnemonic {
            case "sbfm":  opcBase = 0x1300_0000; immr = UInt32(p1); imms = UInt32(p2)
            case "bfm":   opcBase = 0x3300_0000; immr = UInt32(p1); imms = UInt32(p2)
            case "ubfm":  opcBase = 0x5300_0000; immr = UInt32(p1); imms = UInt32(p2)
            case "sbfiz": opcBase = 0x1300_0000; immr = (regBits - UInt32(p1)) % regBits; imms = UInt32(p2) - 1
            case "bfi":   opcBase = 0x3300_0000; immr = (regBits - UInt32(p1)) % regBits; imms = UInt32(p2) - 1
            case "ubfiz": opcBase = 0x5300_0000; immr = (regBits - UInt32(p1)) % regBits; imms = UInt32(p2) - 1
            case "sbfx":  opcBase = 0x1300_0000; immr = UInt32(p1); imms = UInt32(p1 + p2) - 1
            case "bfxil": opcBase = 0x3300_0000; immr = UInt32(p1); imms = UInt32(p1 + p2) - 1
            default:      opcBase = 0x5300_0000; immr = UInt32(p1); imms = UInt32(p1 + p2) - 1 // ubfx
            }
            return sf | opcBase | nBit | (immr << 16) | (imms << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        }
    }

    private func encodeOneSourceBitOp(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>") }
        let rd = try requireReg(operands[0], line: line, src: src)
        let rn = try requireReg(operands[1], line: line, src: src)
        guard rd.bitWidth == rn.bitWidth && !rd.isStackPointer && !rn.isStackPointer else {
            throw err(line, src, "Invalid registers in \(mnemonic)")
        }
        let is64 = (rd.bitWidth == 64)
        let sf: UInt32 = is64 ? (1 << 31) : 0
        let opcode: UInt32
        switch mnemonic {
        case "rbit":  opcode = 0b000000
        case "rev16": opcode = 0b000001
        case "rev32":
            guard is64 else { throw err(line, src, "REV32 requires 64-bit registers") }
            opcode = 0b000010
        case "rev":   opcode = is64 ? 0b000011 : 0b000010
        case "clz":   opcode = 0b000100
        default:      opcode = 0b000101 // cls
        }
        return sf | 0x5AC0_0000 | (opcode << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
    }

    private func encodeMulDiv(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        switch mnemonic {
        case "udiv", "sdiv":
            guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let op2: UInt32 = (mnemonic == "sdiv") ? 0b000011 : 0b000010
            return sf | 0x1AC0_0000 | (UInt32(rm.index) << 16) | (op2 << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "mul", "mneg":
            guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let o0: UInt32 = (mnemonic == "mneg") ? (1 << 15) : 0
            return sf | 0x1B00_7C00 | (UInt32(rm.index) << 16) | o0 | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "madd", "msub":
            guard operands.count == 4 else { throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm>, <Ra>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let ra = try requireReg(operands[3], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let o0: UInt32 = (mnemonic == "msub") ? (1 << 15) : 0
            return sf | 0x1B00_0000 | (UInt32(rm.index) << 16) | o0 | (UInt32(ra.index) << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "smull", "umull", "smulh", "umulh":
            guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects 3 registers") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let base: UInt32
            switch mnemonic {
            case "smull": base = 0x9B20_7C00
            case "smulh": base = 0x9B40_7C00
            case "umull": base = 0x9BA0_7C00
            default:      base = 0x9BC0_7C00 // umulh
            }
            return base | (UInt32(rm.index) << 16) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        default: // smaddl, smsubl, umaddl, umsubl
            guard operands.count == 4 else { throw err(line, src, "\(mnemonic) expects 4 registers") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let ra = try requireReg(operands[3], line: line, src: src)
            let isUnsigned = mnemonic.hasPrefix("u")
            let isSub = mnemonic.hasSuffix("subl")
            let base: UInt32 = isUnsigned ? 0x9BA0_0000 : 0x9B20_0000
            let o0: UInt32 = isSub ? (1 << 15) : 0
            return base | (UInt32(rm.index) << 16) | o0 | (UInt32(ra.index) << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)
        }
    }

    private func encodeConditionalSelectOrCompare(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        switch mnemonic {
        case "cset", "csetm":
            guard operands.count == 2, let cond = A64ConditionCode.from(text: operands[1]) else {
                throw err(line, src, "\(mnemonic) expects <Rd>, <cond>")
            }
            let rd = try requireReg(operands[0], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let inv = UInt32(cond.inverted.rawValue) << 12
            let base: UInt32 = (mnemonic == "cset") ? 0x1A9F_07E0 : 0x5A9F_03E0
            return sf | base | inv | UInt32(rd.index)

        case "cinc", "cinv", "cneg":
            guard operands.count == 3, let cond = A64ConditionCode.from(text: operands[2]) else {
                throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <cond>")
            }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let inv = UInt32(cond.inverted.rawValue) << 12
            let base: UInt32
            switch mnemonic {
            case "cinc": base = 0x1A80_0400
            case "cinv": base = 0x5A80_0000
            default:     base = 0x5A80_0400 // cneg
            }
            return sf | base | (UInt32(rn.index) << 16) | inv | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "csel", "csinc", "csinv", "csneg":
            guard operands.count == 4, let cond = A64ConditionCode.from(text: operands[3]) else {
                throw err(line, src, "\(mnemonic) expects <Rd>, <Rn>, <Rm>, <cond>")
            }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let sf: UInt32 = (rd.bitWidth == 64) ? (1 << 31) : 0
            let base: UInt32
            switch mnemonic {
            case "csel":  base = 0x1A80_0000
            case "csinc": base = 0x1A80_0400
            case "csinv": base = 0x5A80_0000
            default:      base = 0x5A80_0400
            }
            return sf | base | (UInt32(rm.index) << 16) | (UInt32(cond.rawValue) << 12) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        default: // ccmp / ccmn
            guard operands.count == 4,
                  let nzcv = Self.parseSignedOrUnsigned64(operands[2]), nzcv <= 15,
                  let cond = A64ConditionCode.from(text: operands[3])
            else {
                throw err(line, src, "\(mnemonic) expects <Rn>, <Rm|#imm5>, #<nzcv>, <cond>")
            }
            let rn = try requireReg(operands[0], line: line, src: src)
            let sf: UInt32 = (rn.bitWidth == 64) ? (1 << 31) : 0
            let opBit: UInt32 = (mnemonic == "ccmp") ? (1 << 30) : 0
            if let rm = A64RegisterParser.parse(operands[1]), rm.isGeneralPurpose {
                return sf | opBit | 0x3A40_0000 | (UInt32(rm.index) << 16) | (UInt32(cond.rawValue) << 12) | (UInt32(rn.index) << 5) | UInt32(nzcv)
            }
            guard let imm5 = Self.parseSignedOrUnsigned64(operands[1]), imm5 <= 31 else {
                throw err(line, src, "CCMP/CCMN immediate must be 0..31")
            }
            return sf | opBit | 0x3A40_0800 | (UInt32(imm5) << 16) | (UInt32(cond.rawValue) << 12) | (UInt32(rn.index) << 5) | UInt32(nzcv)
        }
    }

    // MARK: - Memory Addressing Parser & Load/Store Encoders

    private func parseAddressingMode(
        operandsSlice: ArraySlice<String>,
        line: Int,
        src: String
    ) throws -> A64AddressingMode? {
        guard let first = operandsSlice.first else { return nil }
        let tok = first.trimmingCharacters(in: .whitespaces)
        guard tok.hasPrefix("[") else { return nil }

        // Post-Index: "[base]", "#offset"
        if operandsSlice.count == 2 {
            guard tok.hasSuffix("]") else {
                throw err(line, src, "Malformed post-index base '\(tok)'")
            }
            let baseText = String(tok.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
            let baseReg = try requireReg(baseText, line: line, src: src)
            let postToken = operandsSlice[operandsSlice.index(after: operandsSlice.startIndex)]
            guard let offset = Self.parseSignedInt64(postToken) else {
                throw err(line, src, "Invalid post-index offset '\(postToken)'")
            }
            return .postIndex(base: baseReg, offset: offset)
        }

        guard operandsSlice.count == 1 else {
            throw err(line, src, "Too many operands in memory addressing mode")
        }

        let isPreIndex = tok.hasSuffix("]!")
        guard isPreIndex || tok.hasSuffix("]") else {
            throw err(line, src, "Unclosed '[' in memory operand '\(tok)'")
        }

        let inner = isPreIndex
            ? String(tok.dropFirst().dropLast(2))
            : String(tok.dropFirst().dropLast())
        let parts = inner.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let baseName = parts.first else {
            throw err(line, src, "Missing base register inside '[]'")
        }
        let baseReg = try requireReg(baseName, line: line, src: src)

        if parts.count == 1 {
            return isPreIndex ? .preIndex(base: baseReg, offset: 0) : .baseOffset(base: baseReg, offset: 0)
        }

        if parts.count == 2 {
            if let idxReg = A64RegisterParser.parse(parts[1]), idxReg.isGeneralPurpose {
                guard !isPreIndex else { throw err(line, src, "Register offset does not support '!' pre-indexing") }
                return .registerOffset(base: baseReg, index: idxReg, extend: nil)
            }
            guard let offset = Self.parseSignedInt64(parts[1]) else {
                throw err(line, src, "Invalid memory offset '\(parts[1])'")
            }
            return isPreIndex ? .preIndex(base: baseReg, offset: offset) : .baseOffset(base: baseReg, offset: offset)
        }

        if parts.count == 3 && !isPreIndex {
            let idxReg = try requireReg(parts[1], line: line, src: src)
            guard let ext = A64ShiftExtendParser.parse(parts[2]) else {
                throw err(line, src, "Invalid register offset extend '\(parts[2])'")
            }
            return .registerOffset(base: baseReg, index: idxReg, extend: ext)
        }

        throw err(line, src, "Unsupported memory addressing syntax '\(tok)'")
    }

    private func encodeSingleLoadStore(
        mnemonic: String,
        operands: [String],
        pc: VirtualAddress,
        labels: [String: VirtualAddress],
        line: Int,
        src: String
    ) throws -> UInt32 {
        guard operands.count >= 2 else { throw err(line, src, "\(mnemonic) expects <Rt>, <addr>") }
        let rt = try requireReg(operands[0], line: line, src: src)

        // Determine (size, isSIMD, opc, scaleShift, forceUnscaled)
        let size: UInt32
        let isSIMD = rt.isSIMD
        let opc: UInt32
        let scaleShift: Int
        let forceUnscaled = mnemonic.hasPrefix("ldur") || mnemonic.hasPrefix("stur")

        if isSIMD {
            let isLoad = mnemonic.hasPrefix("ld")
            switch rt.bank {
            case .simdByte:   size = 0b00; opc = isLoad ? 0b01 : 0b00; scaleShift = 0
            case .simdHalf:   size = 0b01; opc = isLoad ? 0b01 : 0b00; scaleShift = 1
            case .simdSingle: size = 0b10; opc = isLoad ? 0b01 : 0b00; scaleShift = 2
            case .simdDouble: size = 0b11; opc = isLoad ? 0b01 : 0b00; scaleShift = 3
            case .simdQuad:   size = 0b00; opc = isLoad ? 0b11 : 0b10; scaleShift = 4
            default: throw err(line, src, "Vector arrangement register not valid in scalar \(mnemonic)")
            }
        } else {
            switch mnemonic {
            case "strb", "sturb":   size = 0b00; opc = 0b00; scaleShift = 0
            case "ldrb", "ldurb":   size = 0b00; opc = 0b01; scaleShift = 0
            case "ldrsb", "ldursb": size = 0b00; opc = (rt.bitWidth == 64) ? 0b10 : 0b11; scaleShift = 0
            case "strh", "sturh":   size = 0b01; opc = 0b00; scaleShift = 1
            case "ldrh", "ldurh":   size = 0b01; opc = 0b01; scaleShift = 1
            case "ldrsh", "ldursh": size = 0b01; opc = (rt.bitWidth == 64) ? 0b10 : 0b11; scaleShift = 1
            case "ldrsw", "ldursw": size = 0b10; opc = 0b10; scaleShift = 2
            case "str", "stur":
                if rt.bitWidth == 64 { size = 0b11; opc = 0b00; scaleShift = 3 }
                else { size = 0b10; opc = 0b00; scaleShift = 2 }
            case "ldr", "ldur":
                if rt.bitWidth == 64 { size = 0b11; opc = 0b01; scaleShift = 3 }
                else { size = 0b10; opc = 0b01; scaleShift = 2 }
            default:
                throw err(line, src, "Unsupported transfer mnemonic '\(mnemonic)'")
            }
        }

        // Check for PC-relative literal load when second operand does not start with '['
        if !operands[1].trimmingCharacters(in: .whitespaces).hasPrefix("[") {
            guard operands.count == 2 && (mnemonic == "ldr" || mnemonic == "ldrsw") else {
                throw err(line, src, "PC-relative literal mode is only supported for LDR and LDRSW")
            }
            let delta = try resolveBranchByteOffset(
                token: operands[1],
                pc: pc,
                labels: labels,
                maxAbsRange: 1024 * 1024,
                requireWordAligned: true,
                line: line,
                src: src
            )
            let imm19 = UInt32(bitPattern: Int32(delta >> 2)) & 0x7_FFFF
            let litOpc: UInt32
            let vBit: UInt32 = isSIMD ? (1 << 26) : 0
            if isSIMD {
                switch rt.bank {
                case .simdSingle: litOpc = 0b00
                case .simdDouble: litOpc = 0b01
                case .simdQuad:   litOpc = 0b10
                default: throw err(line, src, "Literal SIMD LDR only supports S, D, or Q registers")
                }
            } else {
                litOpc = (mnemonic == "ldrsw") ? 0b10 : ((rt.bitWidth == 64) ? 0b01 : 0b00)
            }
            return (litOpc << 30) | vBit | 0x1800_0000 | (imm19 << 5) | UInt32(rt.index)
        }

        guard let addrMode = try parseAddressingMode(operandsSlice: operands[1...], line: line, src: src) else {
            throw err(line, src, "Failed to parse addressing mode")
        }

        let vBit: UInt32 = isSIMD ? (1 << 26) : 0
        let header = (size << 30) | vBit | (opc << 22)

        switch addrMode {
        case .baseOffset(let base, let offset):
            guard base.bitWidth == 64 && !base.isZeroRegister else {
                throw err(line, src, "Base register must be 64-bit Xn or SP")
            }
            let alignMask = Int64((1 << scaleShift) - 1)
            if !forceUnscaled && offset >= 0 && (offset & alignMask) == 0 && (offset >> scaleShift) <= 0xFFF {
                let imm12 = UInt32(offset >> scaleShift) & 0xFFF
                return header | 0x3900_0000 | (imm12 << 10) | (UInt32(base.index) << 5) | UInt32(rt.index)
            }
            // Fall back to 9-bit signed unscaled LDUR/STUR
            guard offset >= -256 && offset <= 255 else {
                throw err(line, src, "Memory offset \(offset) cannot be encoded in scaled 12-bit or unscaled 9-bit form")
            }
            let imm9 = UInt32(bitPattern: Int32(offset)) & 0x1FF
            return header | 0x3800_0000 | (imm9 << 12) | (UInt32(base.index) << 5) | UInt32(rt.index)

        case .preIndex(let base, let offset):
            guard offset >= -256 && offset <= 255 else {
                throw err(line, src, "Pre-index offset \(offset) outside -256...255")
            }
            let imm9 = UInt32(bitPattern: Int32(offset)) & 0x1FF
            return header | 0x3800_0C00 | (imm9 << 12) | (UInt32(base.index) << 5) | UInt32(rt.index)

        case .postIndex(let base, let offset):
            guard offset >= -256 && offset <= 255 else {
                throw err(line, src, "Post-index offset \(offset) outside -256...255")
            }
            let imm9 = UInt32(bitPattern: Int32(offset)) & 0x1FF
            return header | 0x3800_0400 | (imm9 << 12) | (UInt32(base.index) << 5) | UInt32(rt.index)

        case .registerOffset(let base, let index, let extend):
            let option: UInt32
            let sBit: UInt32
            if let ext = extend {
                switch ext {
                case .lsl(let amt):
                    option = 0b011
                    guard amt == 0 || Int(amt) == scaleShift else {
                        throw err(line, src, "Register offset LSL shift must be #0 or #\(scaleShift)")
                    }
                    sBit = (Int(amt) == scaleShift && scaleShift > 0) || (amt == 0 && ext.description == "lsl #0") ? 1 : 0
                case .uxtw(let amt):
                    option = 0b010
                    guard amt == 0 || Int(amt) == scaleShift else { throw err(line, src, "Invalid UXTW shift") }
                    sBit = (amt > 0) ? 1 : 0
                case .sxtw(let amt):
                    option = 0b110
                    guard amt == 0 || Int(amt) == scaleShift else { throw err(line, src, "Invalid SXTW shift") }
                    sBit = (amt > 0) ? 1 : 0
                case .sxtx(let amt):
                    option = 0b111
                    guard amt == 0 || Int(amt) == scaleShift else { throw err(line, src, "Invalid SXTX shift") }
                    sBit = (amt > 0) ? 1 : 0
                default:
                    throw err(line, src, "Unsupported register offset extend '\(ext)'")
                }
            } else {
                option = (index.bitWidth == 64) ? 0b011 : 0b010
                sBit = 0
            }
            return header | 0x3820_0800 | (UInt32(index.index) << 16) | (option << 13) | (sBit << 12) | (UInt32(base.index) << 5) | UInt32(rt.index)

        case .pcRelativeLiteral:
            throw err(line, src, "Unexpected literal mode")
        }
    }

    private func encodeLoadStorePair(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        guard operands.count >= 3 else { throw err(line, src, "\(mnemonic) expects <Rt1>, <Rt2>, <addr>") }
        let r1 = try requireReg(operands[0], line: line, src: src)
        let r2 = try requireReg(operands[1], line: line, src: src)
        guard r1.bank == r2.bank || (r1.isGeneralPurpose && r2.isGeneralPurpose && r1.bitWidth == r2.bitWidth) else {
            throw err(line, src, "\(mnemonic) register pair width/bank mismatch")
        }

        let isSIMD = r1.isSIMD
        let isLoad = mnemonic.hasPrefix("ld")
        let opc: UInt32
        let scale: Int64
        if isSIMD {
            switch r1.bank {
            case .simdSingle: opc = 0b00; scale = 4
            case .simdDouble: opc = 0b01; scale = 8
            case .simdQuad:   opc = 0b10; scale = 16
            default: throw err(line, src, "SIMD \(mnemonic) supports S, D, or Q registers")
            }
        } else if mnemonic == "ldpsw" {
            opc = 0b01; scale = 4
        } else {
            opc = (r1.bitWidth == 64) ? 0b10 : 0b00
            scale = (r1.bitWidth == 64) ? 8 : 4
        }

        guard let addrMode = try parseAddressingMode(operandsSlice: operands[2...], line: line, src: src) else {
            throw err(line, src, "Invalid addressing mode for \(mnemonic)")
        }

        let modeCode: UInt32
        let baseReg: A64Register
        let offset: Int64
        switch addrMode {
        case .baseOffset(let b, let off):
            modeCode = (mnemonic == "ldnp" || mnemonic == "stnp") ? 0b00 : 0b10
            baseReg = b; offset = off
        case .postIndex(let b, let off):
            guard mnemonic != "ldnp" && mnemonic != "stnp" else { throw err(line, src, "\(mnemonic) does not allow post-index") }
            modeCode = 0b01; baseReg = b; offset = off
        case .preIndex(let b, let off):
            guard mnemonic != "ldnp" && mnemonic != "stnp" else { throw err(line, src, "\(mnemonic) does not allow pre-index") }
            modeCode = 0b11; baseReg = b; offset = off
        default:
            throw err(line, src, "\(mnemonic) requires signed immediate offset addressing")
        }

        guard offset % scale == 0 else {
            throw err(line, src, "\(mnemonic) offset \(offset) must be a multiple of \(scale)")
        }
        let scaled = offset / scale
        guard scaled >= -64 && scaled <= 63 else {
            throw err(line, src, "\(mnemonic) scaled offset \(scaled) outside 7-bit signed range (-64...63)")
        }
        let imm7 = UInt32(bitPattern: Int32(scaled)) & 0x7F
        let vBit: UInt32 = isSIMD ? (1 << 26) : 0
        let lBit: UInt32 = isLoad ? (1 << 22) : 0
        return (opc << 30) | vBit | 0x2800_0000 | (modeCode << 23) | lBit | (imm7 << 15) | (UInt32(r2.index) << 10) | (UInt32(baseReg.index) << 5) | UInt32(r1.index)
    }

    private func encodeExclusiveOrAtomic(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        switch mnemonic {
        case "ldxr", "ldaxr", "ldar", "ldarb", "ldarh", "stlr", "stlrb", "stlrh":
            guard operands.count == 2,
                  let addrMode = try parseAddressingMode(operandsSlice: operands[1...], line: line, src: src),
                  case .baseOffset(let base, 0) = addrMode
            else {
                throw err(line, src, "\(mnemonic) expects <Rt>, [<Xn|sp>]")
            }
            let rt = try requireReg(operands[0], line: line, src: src)
            let size: UInt32
            if mnemonic.hasSuffix("b") { size = 0b00 }
            else if mnemonic.hasSuffix("h") { size = 0b01 }
            else { size = (rt.bitWidth == 64) ? 0b11 : 0b10 }

            let baseWord: UInt32
            switch mnemonic {
            case "ldxr":  baseWord = 0x085F_7C00
            case "ldaxr": baseWord = 0x085F_FC00
            case "ldar", "ldarb", "ldarh": baseWord = 0x08DF_FC00
            default:      baseWord = 0x089F_FC00 // stlr*
            }
            return (size << 30) | baseWord | (UInt32(base.index) << 5) | UInt32(rt.index)

        case "stxr", "stlxr":
            guard operands.count == 3,
                  let addrMode = try parseAddressingMode(operandsSlice: operands[2...], line: line, src: src),
                  case .baseOffset(let base, 0) = addrMode
            else {
                throw err(line, src, "\(mnemonic) expects <Ws>, <Rt>, [<Xn|sp>]")
            }
            let ws = try requireReg(operands[0], line: line, src: src)
            let rt = try requireReg(operands[1], line: line, src: src)
            let size: UInt32 = (rt.bitWidth == 64) ? 0b11 : 0b10
            let o0: UInt32 = (mnemonic == "stlxr") ? (1 << 15) : 0
            return (size << 30) | 0x0800_7C00 | (UInt32(ws.index) << 16) | o0 | (UInt32(base.index) << 5) | UInt32(rt.index)

        case "cas", "casa", "casal", "casl":
            guard operands.count == 3,
                  let addrMode = try parseAddressingMode(operandsSlice: operands[2...], line: line, src: src),
                  case .baseOffset(let base, 0) = addrMode
            else {
                throw err(line, src, "\(mnemonic) expects <Rs>, <Rt>, [<Xn|sp>]")
            }
            let rs = try requireReg(operands[0], line: line, src: src)
            let rt = try requireReg(operands[1], line: line, src: src)
            let size: UInt32 = (rt.bitWidth == 64) ? 0b11 : 0b10
            let aBit: UInt32 = (mnemonic == "casa" || mnemonic == "casal") ? (1 << 22) : 0
            let rBit: UInt32 = (mnemonic == "casl" || mnemonic == "casal") ? (1 << 15) : 0
            return (size << 30) | 0x08A0_7C00 | aBit | (UInt32(rs.index) << 16) | rBit | (UInt32(base.index) << 5) | UInt32(rt.index)

        default: // swp*, ldadd*
            guard operands.count == 3,
                  let addrMode = try parseAddressingMode(operandsSlice: operands[2...], line: line, src: src),
                  case .baseOffset(let base, 0) = addrMode
            else {
                throw err(line, src, "\(mnemonic) expects <Rs>, <Rt>, [<Xn|sp>]")
            }
            let rs = try requireReg(operands[0], line: line, src: src)
            let rt = try requireReg(operands[1], line: line, src: src)
            let size: UInt32 = (rt.bitWidth == 64) ? 0b11 : 0b10
            let isSwp = mnemonic.hasPrefix("swp")
            let aBit: UInt32 = (mnemonic.hasSuffix("a") || mnemonic.hasSuffix("al")) ? (1 << 23) : 0
            let rBit: UInt32 = mnemonic.hasSuffix("l") ? (1 << 22) : 0
            let o3: UInt32 = isSwp ? (1 << 15) : 0
            return (size << 30) | 0x3820_0000 | aBit | rBit | (UInt32(rs.index) << 16) | o3 | (UInt32(base.index) << 5) | UInt32(rt.index)
        }
    }

    // MARK: - Scalar Floating-Point & Common NEON Vector Encoder

    private func ftypeBits(for reg: A64Register, line: Int, src: String) throws -> UInt32 {
        switch reg.bank {
        case .simdSingle: return 0b00
        case .simdDouble: return 0b01
        case .simdHalf:   return 0b11
        default: throw err(line, src, "Expected scalar floating-point register Hn, Sn, or Dn, got '\(reg.canonicalName)'")
        }
    }

    private func encodeFloatingPointOrSIMD(mnemonic: String, operands: [String], line: Int, src: String) throws -> UInt32 {
        switch mnemonic {
        case "fmov":
            guard operands.count == 2 else { throw err(line, src, "FMOV expects 2 operands") }
            let dst = try requireReg(operands[0], line: line, src: src)

            // Register-to-register FMOV (FP<->FP or GP<->FP)
            if let srcReg = A64RegisterParser.parse(operands[1]) {
                if dst.isSIMD && srcReg.isSIMD {
                    guard dst.bank == srcReg.bank else {
                        throw err(line, src, "FMOV scalar FP registers must have matching width")
                    }
                    let ft = try ftypeBits(for: dst, line: line, src: src)
                    return 0x1E20_4000 | (ft << 22) | (UInt32(srcReg.index) << 5) | UInt32(dst.index)
                }
                if dst.isSIMD && srcReg.isGeneralPurpose { // GP -> FP
                    guard !srcReg.isStackPointer else {
                        throw err(line, src, "FMOV source cannot be SP/WSP")
                    }
                    let ft = try ftypeBits(for: dst, line: line, src: src)
                    let sf: UInt32 = (srcReg.bitWidth == 64) ? (1 << 31) : 0
                    return sf | 0x1E27_0000 | (ft << 22) | (UInt32(srcReg.index) << 5) | UInt32(dst.index)
                }
                if dst.isGeneralPurpose && srcReg.isSIMD { // FP -> GP
                    guard !dst.isStackPointer else {
                        throw err(line, src, "FMOV destination cannot be SP/WSP")
                    }
                    let ft = try ftypeBits(for: srcReg, line: line, src: src)
                    let sf: UInt32 = (dst.bitWidth == 64) ? (1 << 31) : 0
                    return sf | 0x1E26_0000 | (ft << 22) | (UInt32(srcReg.index) << 5) | UInt32(dst.index)
                }
                throw err(line, src, "Invalid FMOV register combination")
            }

            // FP Immediate (#0.0 uses XZR/WZR move; non-zero uses VFP 8-bit immediate)
            let ft = try ftypeBits(for: dst, line: line, src: src)
            guard let fpVal = Self.parseDoubleImmediate(operands[1]) else {
                throw err(line, src, "Invalid FMOV floating-point immediate '\(operands[1])'")
            }
            if fpVal == 0.0 && !fpVal.sign.rawValue.nonzeroBitCount.words.isEmpty && fpVal.bitPattern == 0 {
                let sf: UInt32 = (dst.bank == .simdDouble) ? (1 << 31) : 0
                return sf | 0x1E27_03E0 | (ft << 22) | UInt32(dst.index)
            }
            guard let imm8 = encodeVFPImm8(fpVal) else {
                throw err(line, src, "Floating-point immediate \(fpVal) is not representable as an 8-bit ARM64 VFP constant")
            }
            return 0x1E20_1000 | (ft << 22) | (UInt32(imm8) << 13) | UInt32(dst.index)

        case "fadd", "fsub", "fmul", "fdiv", "fmax", "fmin", "fnmul":
            guard operands.count == 3 else { throw err(line, src, "\(mnemonic) expects <FPd>, <FPn>, <FPm>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            guard rd.bank == rn.bank && rn.bank == rm.bank else {
                throw err(line, src, "\(mnemonic) scalar FP registers must have matching width")
            }
            let ft = try ftypeBits(for: rd, line: line, src: src)
            let opc: UInt32
            switch mnemonic {
            case "fmul":  opc = 0b0000
            case "fdiv":  opc = 0b0001
            case "fadd":  opc = 0b0010
            case "fsub":  opc = 0b0011
            case "fmax":  opc = 0b0100
            case "fmin":  opc = 0b0101
            default:      opc = 0b1000 // fnmul
            }
            return 0x1E20_0800 | (ft << 22) | (UInt32(rm.index) << 16) | (opc << 12) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "fmadd", "fmsub":
            guard operands.count == 4 else { throw err(line, src, "\(mnemonic) expects <FPd>, <FPn>, <FPm>, <FPa>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            let ra = try requireReg(operands[3], line: line, src: src)
            guard rd.bank == rn.bank && rn.bank == rm.bank && rm.bank == ra.bank else {
                throw err(line, src, "\(mnemonic) scalar FP registers must have matching width")
            }
            let ft = try ftypeBits(for: rd, line: line, src: src)
            let o0: UInt32 = (mnemonic == "fmsub") ? (1 << 15) : 0
            return 0x1F00_0000 | (ft << 22) | (UInt32(rm.index) << 16) | o0 | (UInt32(ra.index) << 10) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "fabs", "fneg", "fsqrt", "fcvt":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects 2 operands") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            if mnemonic != "fcvt" {
                guard rd.bank == rn.bank else {
                    throw err(line, src, "\(mnemonic) scalar FP registers must have matching width")
                }
            }
            let ftSrc = try ftypeBits(for: rn, line: line, src: src)
            let opc: UInt32
            switch mnemonic {
            case "fabs":  opc = 0b000001
            case "fneg":  opc = 0b000010
            case "fsqrt": opc = 0b000011
            default: // fcvt
                switch rd.bank {
                case .simdSingle: opc = 0b000100
                case .simdDouble: opc = 0b000101
                case .simdHalf:   opc = 0b000111
                default: throw err(line, src, "Invalid FCVT destination register")
                }
            }
            return 0x1E20_4000 | (ftSrc << 22) | (opc << 15) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "fcmp", "fcmpe":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects 2 operands") }
            let rn = try requireReg(operands[0], line: line, src: src)
            let ft = try ftypeBits(for: rn, line: line, src: src)
            let sigBit: UInt32 = (mnemonic == "fcmpe") ? (1 << 4) : 0
            if let rm = A64RegisterParser.parse(operands[1]), rm.isSIMD {
                guard rn.bank == rm.bank else {
                    throw err(line, src, "\(mnemonic) scalar FP registers must have matching width")
                }
                return 0x1E20_2000 | (ft << 22) | (UInt32(rm.index) << 16) | (UInt32(rn.index) << 5) | sigBit
            }
            guard let zeroVal = Self.parseDoubleImmediate(operands[1]), zeroVal == 0.0 else {
                throw err(line, src, "FCMP immediate operand must be #0.0")
            }
            return 0x1E20_2008 | (ft << 22) | (UInt32(rn.index) << 5) | sigBit

        case "fccmp":
            guard operands.count == 4,
                  let nzcv = Self.parseSignedOrUnsigned64(operands[2]), nzcv <= 15,
                  let cond = A64ConditionCode.from(text: operands[3])
            else {
                throw err(line, src, "FCCMP expects <FPn>, <FPm>, #<nzcv>, <cond>")
            }
            let rn = try requireReg(operands[0], line: line, src: src)
            let rm = try requireReg(operands[1], line: line, src: src)
            guard rn.bank == rm.bank else {
                throw err(line, src, "FCCMP scalar FP registers must have matching width")
            }
            let ft = try ftypeBits(for: rn, line: line, src: src)
            return 0x1E20_0400 | (ft << 22) | (UInt32(rm.index) << 16) | (UInt32(cond.rawValue) << 12) | (UInt32(rn.index) << 5) | UInt32(nzcv)

        case "fcsel":
            guard operands.count == 4, let cond = A64ConditionCode.from(text: operands[3]) else {
                throw err(line, src, "FCSEL expects <FPd>, <FPn>, <FPm>, <cond>")
            }
            let rd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            let rm = try requireReg(operands[2], line: line, src: src)
            guard rd.bank == rn.bank && rn.bank == rm.bank else {
                throw err(line, src, "FCSEL scalar FP registers must have matching width")
            }
            let ft = try ftypeBits(for: rd, line: line, src: src)
            return 0x1E20_0C00 | (ft << 22) | (UInt32(rm.index) << 16) | (UInt32(cond.rawValue) << 12) | (UInt32(rn.index) << 5) | UInt32(rd.index)

        case "scvtf", "ucvtf":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <FPd>, <GPn>") }
            let fpRd = try requireReg(operands[0], line: line, src: src)
            let gpRn = try requireReg(operands[1], line: line, src: src)
            guard gpRn.isGeneralPurpose && !gpRn.isStackPointer else {
                throw err(line, src, "\(mnemonic) source must be Wn/Xn or WZR/XZR")
            }
            let ft = try ftypeBits(for: fpRd, line: line, src: src)
            let sf: UInt32 = (gpRn.bitWidth == 64) ? (1 << 31) : 0
            let opc: UInt32 = (mnemonic == "ucvtf") ? 0b011 : 0b010
            return sf | 0x1E20_0000 | (ft << 22) | (opc << 16) | (UInt32(gpRn.index) << 5) | UInt32(fpRd.index)

        case "fcvtzs", "fcvtzu":
            guard operands.count == 2 else { throw err(line, src, "\(mnemonic) expects <GPd>, <FPn>") }
            let gpRd = try requireReg(operands[0], line: line, src: src)
            let fpRn = try requireReg(operands[1], line: line, src: src)
            guard gpRd.isGeneralPurpose && !gpRd.isStackPointer else {
                throw err(line, src, "\(mnemonic) destination must be Wd/Xd or WZR/XZR")
            }
            let ft = try ftypeBits(for: fpRn, line: line, src: src)
            let sf: UInt32 = (gpRd.bitWidth == 64) ? (1 << 31) : 0
            let opc: UInt32 = (mnemonic == "fcvtzu") ? 0b001 : 0b000
            return sf | 0x1E38_0000 | (ft << 22) | (opc << 16) | (UInt32(fpRn.index) << 5) | UInt32(gpRd.index)

        case "movi":
            guard operands.count == 2,
                  let dst = A64RegisterParser.parse(operands[0]),
                  let val = Self.parseSignedOrUnsigned64(operands[1])
            else {
                throw err(line, src, "MOVI expects <Vd.arr|Dd>, #<imm>")
            }
            if dst.bank == .simdDouble || (dst.bank == .simdVector && dst.vectorArrangement == "2d") {
                guard let imm8 = A64BitUtils.compressSIMDByteMaskImmediate(val) else {
                    throw err(line, src, "MOVI 64-bit byte mask requires each byte to be 0x00 or 0xFF")
                }
                let qBit: UInt32 = (dst.vectorArrangement == "2d") ? (1 << 30) : 0
                let abc = UInt32((imm8 >> 5) & 0x7) << 16
                let defgh = UInt32(imm8 & 0x1F) << 5
                return qBit | 0x2F00_E400 | abc | defgh | UInt32(dst.index)
            }
            guard dst.bank == .simdVector,
                  let arr = dst.vectorArrangement,
                  (arr == "8b" || arr == "16b" || arr == "2s" || arr == "4s")
            else {
                if dst.isSIMD {
                    throw MachGraphError.assemblerUnsupported(mnemonic: mnemonic, form: Self.normalizeStatementForm(src))
                }
                throw err(line, src, "MOVI expects <Vd.arr|Dd>, #<imm>")
            }
            guard val <= 0xFF else { throw err(line, src, "MOVI byte immediate must be 0..255") }
            let qBit: UInt32 = (arr == "16b" || arr == "4s") ? (1 << 30) : 0
            let cmode: UInt32 = (arr == "4s" || arr == "2s") ? 0b0000 : 0b1110
            let abc = UInt32((val >> 5) & 0x7) << 16
            let defgh = UInt32(val & 0x1F) << 5
            return qBit | 0x0F00_0400 | abc | (cmode << 12) | defgh | UInt32(dst.index)

        case "dup":
            guard operands.count == 2 else { throw err(line, src, "DUP expects <Vd.arr>, <Rn>") }
            let vd = try requireReg(operands[0], line: line, src: src)
            let rn = try requireReg(operands[1], line: line, src: src)
            guard vd.bank == .simdVector, rn.isGeneralPurpose && !rn.isStackPointer else {
                throw err(line, src, "DUP inline assembler expects <Vd.arr>, <Wn|Xn>")
            }
            let qBit: UInt32
            let imm5: UInt32
            let expectedGPBits: Int
            switch vd.vectorArrangement {
            case "8b":  qBit = 0;         imm5 = 0b00001; expectedGPBits = 32
            case "16b": qBit = (1 << 30); imm5 = 0b00001; expectedGPBits = 32
            case "4h":  qBit = 0;         imm5 = 0b00010; expectedGPBits = 32
            case "8h":  qBit = (1 << 30); imm5 = 0b00010; expectedGPBits = 32
            case "2s":  qBit = 0;         imm5 = 0b00100; expectedGPBits = 32
            case "4s":  qBit = (1 << 30); imm5 = 0b00100; expectedGPBits = 32
            case "2d":  qBit = (1 << 30); imm5 = 0b01000; expectedGPBits = 64
            default:
                throw MachGraphError.assemblerUnsupported(mnemonic: mnemonic, form: Self.normalizeStatementForm(src))
            }
            guard rn.bitWidth == expectedGPBits else {
                throw err(line, src, "DUP \(vd.canonicalName) requires \(expectedGPBits)-bit general register")
            }
            return qBit | 0x0E00_0C00 | (imm5 << 16) | (UInt32(rn.index) << 5) | UInt32(vd.index)

        case "addv":
            guard operands.count == 2 else { throw err(line, src, "ADDV expects <B/H/Sd>, <Vn.arr>") }
            let rd = try requireReg(operands[0], line: line, src: src)
            let vn = try requireReg(operands[1], line: line, src: src)
            let qBit: UInt32
            let size: UInt32
            let expectedBank: A64RegisterBank
            switch vn.vectorArrangement {
            case "8b":  qBit = 0;         size = 0b00; expectedBank = .simdByte
            case "16b": qBit = (1 << 30); size = 0b00; expectedBank = .simdByte
            case "4h":  qBit = 0;         size = 0b01; expectedBank = .simdHalf
            case "8h":  qBit = (1 << 30); size = 0b01; expectedBank = .simdHalf
            case "4s":  qBit = (1 << 30); size = 0b10; expectedBank = .simdSingle
            default:
                if vn.isSIMD {
                    throw MachGraphError.assemblerUnsupported(mnemonic: mnemonic, form: Self.normalizeStatementForm(src))
                }
                throw err(line, src, "Unsupported ADDV arrangement")
            }
            guard rd.bank == expectedBank else {
                throw err(line, src, "ADDV scalar destination width does not match vector element width")
            }
            return qBit | 0x0E31_B800 | (size << 22) | (UInt32(vn.index) << 5) | UInt32(rd.index)

        case "cmeq":
            guard operands.count == 3 else { throw err(line, src, "CMEQ expects 3 operands") }
            let vd = try requireReg(operands[0], line: line, src: src)
            let vn = try requireReg(operands[1], line: line, src: src)
            guard vd.bank == .simdVector, vn.bank == .simdVector, vd.vectorArrangement == vn.vectorArrangement else {
                throw err(line, src, "CMEQ requires matching vector arrangements")
            }
            let qBit: UInt32
            let size: UInt32
            switch vd.vectorArrangement {
            case "8b":  qBit = 0;         size = 0b00
            case "16b": qBit = (1 << 30); size = 0b00
            case "4h":  qBit = 0;         size = 0b01
            case "8h":  qBit = (1 << 30); size = 0b01
            case "2s":  qBit = 0;         size = 0b10
            case "4s":  qBit = (1 << 30); size = 0b10
            case "2d":  qBit = (1 << 30); size = 0b11
            default:
                throw MachGraphError.assemblerUnsupported(mnemonic: mnemonic, form: Self.normalizeStatementForm(src))
            }
            if let vm = A64RegisterParser.parse(operands[2]), vm.bank == .simdVector {
                guard vm.vectorArrangement == vd.vectorArrangement else {
                    throw err(line, src, "CMEQ requires matching vector arrangements")
                }
                return qBit | 0x2E20_8C00 | (size << 22) | (UInt32(vm.index) << 16) | (UInt32(vn.index) << 5) | UInt32(vd.index)
            }
            guard let imm = Self.parseSignedOrUnsigned64(operands[2]), imm == 0 else {
                throw err(line, src, "CMEQ immediate must be #0")
            }
            return qBit | 0x0E20_9800 | (size << 22) | (UInt32(vn.index) << 5) | UInt32(vd.index)

        default:
            throw err(line, src, "Unsupported FP/SIMD mnemonic '\(mnemonic)'")
        }
    }
}
