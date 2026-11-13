import Foundation
import MachGraphModels

// MARK: - Symbol Mangling Language Classification & Public Demangler Entry Point

public enum DemangledSymbolLanguage: String, Sendable, Codable, Hashable, CaseIterable {
    case swift = "Swift"
    case cpp = "C++ (Itanium)"
    case objc = "Objective-C"
    case c = "C / System"
    case plain = "Plain"
}

public struct SymbolDemangler: Sendable {
    public static let shared = SymbolDemangler()

    public init() {}

    /// Classifies the ABI mangling scheme of `rawSymbol`.
    public func classify(_ rawSymbol: String) -> DemangledSymbolLanguage {
        let trimmed = rawSymbol.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .plain }

        if trimmed.hasPrefix("-[") || trimmed.hasPrefix("+[") ||
           trimmed.hasPrefix("_OBJC_CLASS_$_") || trimmed.hasPrefix("_OBJC_METACLASS_$_") ||
           trimmed.hasPrefix("_OBJC_IVAR_$_") {
            return .objc
        }

        let core = Self.stripDyldStubSuffix(trimmed)
        if Self.extractSwiftMangledPayload(from: core) != nil {
            return .swift
        }
        if core.hasPrefix("__Z") || core.hasPrefix("_Z") {
            return .cpp
        }
        if core.hasPrefix("_") && core.count > 1 {
            return .c
        }
        return .plain
    }

    /// Demangles Swift 5+ (`$s`, `_$s`, `$S`, `_$S`, `_T0`), Itanium C++ (`_Z`, `__Z`),
    /// Objective-C runtime symbols, and Mach-O underscore-prefixed C symbols in pure Swift 6.
    public func demangle(_ rawSymbol: String) -> String {
        let trimmed = rawSymbol.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return rawSymbol }

        // 1. Preserve Objective-C method signatures intact
        if trimmed.hasPrefix("-[") || trimmed.hasPrefix("+[") {
            return trimmed
        }

        // Handle Objective-C class / metaclass / ivar linker symbols
        if trimmed.hasPrefix("_OBJC_CLASS_$_") {
            return "ObjC class \(trimmed.dropFirst("_OBJC_CLASS_$_".count))"
        }
        if trimmed.hasPrefix("_OBJC_METACLASS_$_") {
            return "ObjC metaclass \(trimmed.dropFirst("_OBJC_METACLASS_$_".count))"
        }
        if trimmed.hasPrefix("_OBJC_IVAR_$_") {
            return "ObjC ivar \(trimmed.dropFirst("_OBJC_IVAR_$_".count))"
        }

        // Preserve optional Mach-O stub / PLT suffix (e.g. "$stub", "@PLT") if present
        let (core, suffixNote) = Self.splitSymbolSuffix(trimmed)

        // 2. Swift 5+ / Swift 4 ABI Demangling
        if let swiftPayload = Self.extractSwiftMangledPayload(from: core) {
            var parser = Swift5ABIDemangler(payload: swiftPayload)
            if let demangled = parser.parseTopLevel() {
                return suffixNote.isEmpty ? demangled : "\(demangled)\(suffixNote)"
            }
        }

        // 3. Itanium C++ ABI Demangling (_Z / __Z)
        if core.hasPrefix("__Z") {
            var parser = ItaniumCppDemangler(mangled: String(core.dropFirst(3)))
            if let demangled = parser.parseEncodingOrSpecial() {
                return suffixNote.isEmpty ? demangled : "\(demangled)\(suffixNote)"
            }
        } else if core.hasPrefix("_Z") {
            var parser = ItaniumCppDemangler(mangled: String(core.dropFirst(2)))
            if let demangled = parser.parseEncodingOrSpecial() {
                return suffixNote.isEmpty ? demangled : "\(demangled)\(suffixNote)"
            }
        }

        // 4. Plain Mach-O C symbol: strip single leading Mach-O ABI underscore '_' when appropriate
        if core.hasPrefix("_") && core.count > 1 {
            let afterUnderscore = core[core.index(after: core.startIndex)...]
            if let first = afterUnderscore.first,
               (first.isLetter || first == "_" || first == "$") {
                let stripped = String(afterUnderscore)
                return suffixNote.isEmpty ? stripped : "\(stripped)\(suffixNote)"
            }
        }

        return trimmed
    }

    // MARK: - Prefix / Suffix Normalization Helpers

    private static func stripDyldStubSuffix(_ symbol: String) -> String {
        splitSymbolSuffix(symbol).core
    }

    private static func splitSymbolSuffix(_ symbol: String) -> (core: String, suffix: String) {
        for marker in ["$stub", "@PLT", "$shim"] {
            if symbol.hasSuffix(marker) {
                let core = String(symbol.dropLast(marker.count))
                return (core, " [stub]")
            }
        }
        return (symbol, "")
    }

    private static func extractSwiftMangledPayload(from symbol: String) -> String? {
        let prefixes = ["_$s", "$s", "_$S", "$S", "__T0", "_T0"]
        for p in prefixes {
            if symbol.hasPrefix(p) && symbol.count > p.count {
                return String(symbol.dropFirst(p.count))
            }
        }
        return nil
    }
}

// MARK: - Handwritten Swift 5+ Postfix ABI Demangler

private struct Swift5ABIDemangler {
    private enum Node {
        case module(String)
        case identifier(String)
        case type(String)
        case nominal(kind: NominalKind, fullName: String)
        case emptyList // 'y'
        case firstElementMarker // '_'
        case tuple([TupleField])
        case functionSig(params: [TupleField], returnType: String, throwsError: Bool)
        case genericConstraint(String)
        case genericSignature(params: [String], constraints: [String])
        case entity(String)

        var displayText: String {
            switch self {
            case .module(let s), .identifier(let s), .type(let s), .entity(let s), .genericConstraint(let s):
                return s
            case .nominal(_, let full):
                return full
            case .emptyList:
                return "Void"
            case .firstElementMarker:
                return "_"
            case .tuple(let fields):
                if fields.isEmpty { return "Void" }
                let body = fields.map { f in
                    if let lbl = f.label, !lbl.isEmpty, lbl != "_" {
                        return "\(lbl): \(f.type)"
                    }
                    return f.type
                }.joined(separator: ", ")
                return "(\(body))"
            case .functionSig(let params, let ret, let throwsErr):
                let paramStr = params.map { f in
                    if let lbl = f.label, !lbl.isEmpty, lbl != "_" {
                        return "\(lbl): \(f.type)"
                    }
                    return f.type
                }.joined(separator: ", ")
                let throwClause = throwsErr ? " throws" : ""
                return "(\(paramStr))\(throwClause) -> \(ret)"
            case .genericSignature(let ps, let cs):
                if cs.isEmpty {
                    return "<\(ps.joined(separator: ", "))>"
                }
                return "<\(ps.joined(separator: ", ")) where \(cs.joined(separator: ", "))>"
            }
        }

        var isTypeLike: Bool {
            switch self {
            case .type, .nominal, .tuple, .functionSig:
                return true
            default:
                return false
            }
        }
    }

    private enum NominalKind: String {
        case classType = "class"
        case structType = "struct"
        case enumType = "enum"
        case protocolType = "protocol"
        case typeAlias = "typealias"
    }

    private struct TupleField {
        var label: String?
        var type: String
    }

    private let chars: [Character]
    private var pos: Int = 0
    private var stack: [Node] = []
    private var substitutions: [Node] = []
    private var words: [String] = []

    init(payload: String) {
        self.chars = Array(payload)
    }

    private var isAtEnd: Bool { pos >= chars.count }

    private func peek(_ offset: Int = 0) -> Character? {
        let idx = pos + offset
        return (idx >= 0 && idx < chars.count) ? chars[idx] : nil
    }

    @discardableResult
    private mutating func advance(_ count: Int = 1) -> Character? {
        guard pos < chars.count else { return nil }
        let ch = chars[pos]
        pos += count
        return ch
    }

    private mutating func match(_ expected: Character) -> Bool {
        if peek() == expected {
            pos += 1
            return true
        }
        return false
    }

    private mutating func readNaturalNumber() -> Int? {
        guard let first = peek(), first.isASCII && first.isNumber else { return nil }
        var val = 0
        while let ch = peek(), let digit = ch.wholeNumberValue {
            val = val * 10 + digit
            pos += 1
            if val > 100_000 { return nil }
        }
        return val
    }

    private mutating func recordWords(from identifier: String) {
        // Record sub-words (camelCase / underscore chunks >= 2 chars) for Swift 5 word-Substitutions
        var current = ""
        for ch in identifier {
            if ch == "_" {
                if current.count >= 2 && words.count < 26 {
                    words.append(current)
                }
                current = ""
            } else if ch.isUppercase && !current.isEmpty && current.last?.isLowercase == true {
                if current.count >= 2 && words.count < 26 {
                    words.append(current)
                }
                current = String(ch)
            } else {
                current.append(ch)
            }
        }
        if current.count >= 2 && words.count < 26 {
            words.append(current)
        }
    }

    mutating func parseTopLevel() -> String? {
        while !isAtEnd {
            if !parseNextOperator() {
                break
            }
        }

        guard !stack.isEmpty else { return nil }
        if stack.count == 1 {
            return stack[0].displayText
        }

        // Combine remaining context + entity nodes cleanly if trailing suffix left two nodes
        let rendered = stack.map(\.displayText).filter { !$0.isEmpty && $0 != "Void" }
        if rendered.isEmpty {
            return stack.last?.displayText
        }
        return rendered.joined(separator: ".")
    }

    private mutating func parseNextOperator() -> Bool {
        guard let ch = peek() else { return false }

        // 1. Length-prefixed identifier (or 0-prefixed word/operator identifier)
        if ch.isASCII && ch.isNumber {
            return parseIdentifier()
        }

        switch ch {
        case "s":
            pos += 1
            stack.append(.module("Swift"))
            return true

        case "S":
            return parseStandardOrMacroSubstitution()

        case "A":
            // Back-reference substitution: A[a-z]*[A-Z]
            return parseBackSubstitution()

        case "C", "V", "O", "P", "a":
            return parseNominalType()

        case "G":
            return parseBoundGeneric()

        case "y":
            pos += 1
            stack.append(.emptyList)
            return true

        case "_":
            pos += 1
            stack.append(.firstElementMarker)
            return true

        case "t":
            return parseTupleOrKnownYType()

        case "p":
            pos += 1
            if let last = stack.last, case .emptyList = last {
                _ = stack.popLast()
                stack.append(.type("Any"))
            }
            return true

        case "z":
            pos += 1
            if let last = stack.popLast() {
                stack.append(.type("inout \(last.displayText)"))
            }
            return true

        case "c":
            pos += 1
            return buildFunctionSignatureNode(throwsError: false)

        case "K":
            pos += 1
            if peek() == "c" {
                pos += 1
                return buildFunctionSignatureNode(throwsError: true)
            }
            if peek() == "F" {
                pos += 1
                return parseFunctionEntity(isStatic: false, throwsError: true)
            }
            return true

        case "F":
            pos += 1
            let isStatic = match("Z")
            return parseFunctionEntity(isStatic: isStatic, throwsError: false)

        case "f":
            return parseFunctionAccessorOrLifecycle()

        case "v":
            return parseVariableOrAccessor()

        case "a" where peek(1) == "u":
            pos += 2
            return parseAddressorEntity()

        case "x":
            pos += 1
            stack.append(.type("T"))
            return true

        case "q":
            pos += 1
            if match("_") {
                stack.append(.type("U"))
                return true
            }
            let idx = readNaturalNumber() ?? 0
            _ = match("_")
            let genericNames = ["U", "V", "W", "X", "Y", "Z"]
            let chosen = idx < genericNames.count ? genericNames[idx] : "T\(idx + 1)"
            stack.append(.type(chosen))
            return true

        case "l":
            pos += 1
            return collectGenericSignature(paramCount: 1)

        case "u":
            pos += 1
            var extraParams = 1
            while let p = peek(), p.isNumber {
                extraParams = (readNaturalNumber() ?? 0) + 2
                break
            }
            if match("_") {}
            _ = match("r")
            return collectGenericSignature(paramCount: max(1, extraParams))

        case "R":
            return parseGenericRequirement()

        case "M":
            return parseMetadataOrDescriptor()

        case "W":
            return parseWitnessTable()

        case "T":
            return parseThunkOrSpecialization()

        case "N":
            pos += 1
            if let top = stack.popLast() {
                stack.append(.entity("type metadata for \(top.displayText)"))
                return true
            }
            return false

        case "E":
            pos += 1
            if stack.count >= 2,
               let extType = stack.popLast(),
               let mod = stack.popLast() {
                stack.append(.module("(extension in \(mod.displayText)):\(extType.displayText)"))
                return true
            }
            return true

        case "Z":
            pos += 1
            if let last = stack.popLast() {
                stack.append(.entity("static \(last.displayText)"))
            }
            return true

        case "X":
            return parseSpecialXEncoding()

        case "B":
            return parseBuiltinType()

        default:
            // Unknown trailing modifier: advance conservatively
            pos += 1
            return true
        }
    }

    private mutating func parseIdentifier() -> Bool {
        if peek() == "0" {
            pos += 1
            // Word-substitution & Punycode/operator identifier fallback
            var built = ""
            while !isAtEnd {
                if let len = readNaturalNumber() {
                    guard pos + len <= chars.count else { return false }
                    let literal = String(chars[pos..<(pos + len)])
                    pos += len
                    built += literal
                } else if let c = peek(), c.isASCII && c.isLowercase {
                    let wordIdx = Int(c.asciiValue! - Character("a").asciiValue!)
                    pos += 1
                    if wordIdx < words.count {
                        built += words[wordIdx]
                    }
                } else if let c = peek(), c.isASCII && c.isUppercase {
                    let wordIdx = Int(c.asciiValue! - Character("A").asciiValue!)
                    pos += 1
                    if wordIdx < words.count {
                        built += words[wordIdx]
                    }
                    break
                } else {
                    break
                }
            }
            let id = built.isEmpty ? "_anon" : built
            recordWords(from: id)
            let isFirstModule = stack.isEmpty && substitutions.isEmpty
            let node: Node = isFirstModule ? .module(id) : .identifier(id)
            if isFirstModule {
                substitutions.append(node)
            }
            stack.append(node)
            return true
        }

        guard let length = readNaturalNumber(), length > 0, pos + length <= chars.count else {
            return false
        }
        let rawIdent = String(chars[pos..<(pos + length)])
        pos += length

        // Check operator identifier suffixes ('o' followed by 'i'/'p'/'P')
        if peek() == "o" {
            pos += 1
            let fixity = advance() // i = infix, p = prefix, P = postfix
            _ = fixity
            let opSymbol = Self.translateSwiftOperatorName(rawIdent)
            stack.append(.identifier(opSymbol))
            return true
        }

        recordWords(from: rawIdent)
        if stack.isEmpty && substitutions.isEmpty {
            let mod = Node.module(rawIdent)
            substitutions.append(mod)
            stack.append(mod)
        } else {
            stack.append(.identifier(rawIdent))
        }
        return true
    }

    private static func translateSwiftOperatorName(_ raw: String) -> String {
        switch raw {
        case "ee": return "=="
        case "ne": return "!="
        case "l":  return "<"
        case "le": return "<="
        case "g":  return ">"
        case "ge": return ">="
        case "p":  return "+"
        case "s":  return "-"
        case "m":  return "*"
        case "d":  return "/"
        case "r":  return "%"
        case "a":  return "&"
        case "o":  return "|"
        case "x":  return "^"
        case "ll": return "<<"
        case "gg": return ">>"
        case "pe": return "+="
        case "se": return "-="
        default:   return raw
        }
    }

    private mutating func parseStandardOrMacroSubstitution() -> Bool {
        pos += 1 // consume 'S'
        guard let next = peek() else { return false }

        // Macro repeat e.g. S2S, S2i, S3f
        if next.isASCII && next.isNumber {
            guard let repeatCount = readNaturalNumber(),
                  let macroCode = advance()
            else {
                return false
            }
            guard let mapped = Self.lookupStandardSubstitution(macroCode) else {
                return false
            }
            for _ in 0..<repeatCount {
                stack.append(mapped)
            }
            return true
        }

        pos += 1
        switch next {
        case "g":
            // Optional sugar suffix: <Type>Sg -> Swift.Optional<Type>
            if let wrapped = stack.popLast() {
                let opt = Node.type("Swift.Optional<\(wrapped.displayText)>")
                substitutions.append(opt)
                stack.append(opt)
                return true
            }
            return false

        case "o":
            stack.append(.module("__C"))
            return true

        case "C":
            stack.append(.module("__C"))
            return true

        case "L":
            let node = Node.nominal(kind: .protocolType, fullName: "Swift.Comparable")
            stack.append(node)
            return true

        case "H":
            let node = Node.nominal(kind: .protocolType, fullName: "Swift.Hashable")
            stack.append(node)
            return true

        case "Q":
            let node = Node.nominal(kind: .protocolType, fullName: "Swift.Equatable")
            stack.append(node)
            return true

        case "e":
            let node = Node.nominal(kind: .protocolType, fullName: "Swift.Decodable")
            stack.append(node)
            return true

        case "E":
            let node = Node.nominal(kind: .protocolType, fullName: "Swift.Encodable")
            stack.append(node)
            return true

        default:
            if let std = Self.lookupStandardSubstitution(next) {
                stack.append(std)
                return true
            }
            return false
        }
    }

    private static func lookupStandardSubstitution(_ code: Character) -> Node? {
        switch code {
        case "i": return .type("Swift.Int")
        case "u": return .type("Swift.UInt")
        case "S": return .type("Swift.String")
        case "b": return .type("Swift.Bool")
        case "d": return .type("Swift.Double")
        case "f": return .type("Swift.Float")
        case "c": return .type("Swift.Unicode.Scalar")
        case "J": return .type("Swift.Character")
        case "a": return .nominal(kind: .structType, fullName: "Swift.Array")
        case "D": return .nominal(kind: .structType, fullName: "Swift.Dictionary")
        case "h": return .nominal(kind: .structType, fullName: "Swift.Set")
        case "q": return .nominal(kind: .enumType, fullName: "Swift.Optional")
        case "p": return .nominal(kind: .structType, fullName: "Swift.UnsafeMutablePointer")
        case "P": return .nominal(kind: .structType, fullName: "Swift.UnsafePointer")
        case "V": return .nominal(kind: .structType, fullName: "Swift.UnsafeRawPointer")
        case "v": return .nominal(kind: .structType, fullName: "Swift.UnsafeMutableRawPointer")
        case "W": return .nominal(kind: .structType, fullName: "Swift.UnsafeRawBufferPointer")
        case "w": return .nominal(kind: .structType, fullName: "Swift.UnsafeMutableRawBufferPointer")
        case "R": return .nominal(kind: .structType, fullName: "Swift.UnsafeBufferPointer")
        case "r": return .nominal(kind: .structType, fullName: "Swift.UnsafeMutableBufferPointer")
        default:  return nil
        }
    }

    private mutating func parseBackSubstitution() -> Bool {
        pos += 1 // consume 'A'
        // Special protocol conformance marker 'AA' when preceded by nominal+protocol+module?
        // In Swift 5 ABI: 'A' followed by base-26 index ([a-z]*[A-Z]) indexes into `substitutions`.
        var index = 0
        while let c = peek(), c.isASCII && c.isLowercase {
            index = index * 26 + Int(c.asciiValue! - Character("a").asciiValue!) + 1
            pos += 1
        }
        guard let term = peek(), term.isASCII && term.isUppercase else {
            return false
        }
        index = index * 26 + Int(term.asciiValue! - Character("A").asciiValue!)
        pos += 1

        if index < substitutions.count {
            stack.append(substitutions[index])
            return true
        }
        // Fallback if index out of bounds (e.g. retroactive conformance marker)
        return true
    }

    private mutating func parseNominalType() -> Bool {
        guard let kindChar = advance() else { return false }
        if kindChar == "a" && peek() == "u" {
            pos += 1
            return parseAddressorEntity()
        }

        let nominalKind: NominalKind
        switch kindChar {
        case "C": nominalKind = .classType
        case "V": nominalKind = .structType
        case "O": nominalKind = .enumType
        case "P": nominalKind = .protocolType
        default:  nominalKind = .typeAlias
        }

        guard let nameNode = stack.popLast() else { return false }
        let contextNode = stack.popLast()

        let fullName: String
        if let ctx = contextNode {
            let ctxText = ctx.displayText
            if ctxText == "__C" {
                fullName = nameNode.displayText
            } else {
                fullName = "\(ctxText).\(nameNode.displayText)"
            }
        } else {
            fullName = nameNode.displayText
        }

        let created = Node.nominal(kind: nominalKind, fullName: fullName)
        substitutions.append(created)
        stack.append(created)
        return true
    }

    private mutating func parseBoundGeneric() -> Bool {
        pos += 1 // consume 'G'
        var typeArgs: [String] = []
        while let top = stack.popLast() {
            if case .emptyList = top {
                break
            }
            typeArgs.append(top.displayText)
        }
        typeArgs.reverse()
        guard let baseNominal = stack.popLast() else { return false }
        let boundName = "\(baseNominal.displayText)<\(typeArgs.joined(separator: ", "))>"
        let created = Node.type(boundName)
        substitutions.append(created)
        stack.append(created)
        return true
    }

    private mutating func parseTupleOrKnownYType() -> Bool {
        pos += 1 // consume 't'
        // Check for 'yt' -> Void
        if let last = stack.last, case .emptyList = last {
            _ = stack.popLast()
            stack.append(.type("Void"))
            return true
        }

        // Collect tuple elements back to firstElementMarker ('_') or emptyList ('y')
        var rawTypes: [String] = []
        while let popped = stack.popLast() {
            switch popped {
            case .firstElementMarker:
                if let firstElem = stack.popLast() {
                    rawTypes.append(firstElem.displayText)
                }
                rawTypes.reverse()
                stack.append(.tuple(rawTypes.map { TupleField(label: nil, type: $0) }))
                return true
            case .emptyList:
                rawTypes.reverse()
                stack.append(.tuple(rawTypes.map { TupleField(label: nil, type: $0) }))
                return true
            default:
                rawTypes.append(popped.displayText)
            }
        }

        rawTypes.reverse()
        stack.append(.tuple(rawTypes.map { TupleField(label: nil, type: $0) }))
        return true
    }

    private mutating func parseSpecialXEncoding() -> Bool {
        pos += 1 // consume 'X'
        if match("l") {
            if let prev = stack.last, case .emptyList = prev {
                _ = stack.popLast()
                stack.append(.type("AnyObject"))
                return true
            }
        }
        return true
    }

    private mutating func parseBuiltinType() -> Bool {
        pos += 1 // consume 'B'
        guard let code = advance() else { return false }
        switch code {
        case "i":
            let bits = readNaturalNumber() ?? 64
            _ = match("_")
            stack.append(.type("Builtin.Int\(bits)"))
        case "f":
            let bits = readNaturalNumber() ?? 64
            _ = match("_")
            stack.append(.type("Builtin.FPIEEE\(bits)"))
        case "p":
            stack.append(.type("Builtin.RawPointer"))
        case "B":
            stack.append(.type("Builtin.UnsafeValueBuffer"))
        case "o":
            stack.append(.type("Builtin.NativeObject"))
        default:
            stack.append(.type("Builtin.Word"))
        }
        return true
    }

    private mutating func popLabelsForParams(count: Int) -> [String?] {
        guard count > 0 else {
            if let top = stack.last, case .emptyList = top {
                _ = stack.popLast()
            }
            return []
        }

        // Check if unlabeled 'y' marker sits directly on top of stack
        if let top = stack.last, case .emptyList = top {
            _ = stack.popLast()
            return Array(repeating: nil, count: count)
        }

        var labels: [String?] = []
        for _ in 0..<count {
            if let top = stack.last {
                switch top {
                case .identifier(let lbl):
                    _ = stack.popLast()
                    labels.append(lbl)
                case .firstElementMarker, .emptyList:
                    _ = stack.popLast()
                    labels.append(nil)
                default:
                    labels.append(nil)
                }
            } else {
                labels.append(nil)
            }
        }
        labels.reverse()
        return labels
    }

    private mutating func buildFunctionSignatureNode(throwsError: Bool) -> Bool {
        guard let paramsNode = stack.popLast() else { return false }
        var fields: [TupleField] = []
        switch paramsNode {
        case .emptyList:
            fields = []
        case .tuple(let tFields):
            fields = tFields
        case .type(let single) where single == "Void":
            fields = []
        default:
            fields = [TupleField(label: nil, type: paramsNode.displayText)]
        }

        let retNode = stack.popLast() ?? .type("Void")
        let retText = retNode.displayText

        let labels = popLabelsForParams(count: fields.count)
        for i in 0..<min(fields.count, labels.count) {
            if fields[i].label == nil {
                fields[i].label = labels[i]
            }
        }

        stack.append(.functionSig(params: fields, returnType: retText, throwsError: throwsError))
        return true
    }

    private mutating func parseFunctionEntity(isStatic: Bool, throwsError: Bool) -> Bool {
        // Optional generic signature sitting above function signature / return+params
        var genericClause = ""
        if let top = stack.last, case .genericSignature = top {
            genericClause = stack.popLast()!.displayText
        }

        if let top = stack.last, case .functionSig = top {
            // Signature already built by 'c'
        } else {
            guard buildFunctionSignatureNode(throwsError: throwsError) else { return false }
        }

        guard let sigNode = stack.popLast() else { return false }
        let nameNode = stack.popLast()
        let contextNode = stack.popLast()

        let prefix = isStatic ? "static " : ""
        let qualifiedName: String
        if let ctx = contextNode, let fn = nameNode {
            qualifiedName = "\(ctx.displayText).\(fn.displayText)"
        } else if let fn = nameNode {
            qualifiedName = fn.displayText
        } else {
            qualifiedName = "<anonymous>"
        }

        stack.append(.entity("\(prefix)\(qualifiedName)\(genericClause)\(sigNode.displayText)"))
        return true
    }

    private mutating func parseFunctionAccessorOrLifecycle() -> Bool {
        pos += 1 // consume 'f'
        guard let kind = advance() else { return false }

        switch kind {
        case "C", "c": // Allocating / non-allocating init
            var genericClause = ""
            if let top = stack.last, case .genericSignature = top {
                genericClause = stack.popLast()!.displayText
            }
            if let top = stack.last, case .functionSig = top {
                // Already built via 'c'
            } else {
                _ = buildFunctionSignatureNode(throwsError: false)
            }
            let sigNode = stack.popLast() ?? .functionSig(params: [], returnType: "Self", throwsError: false)
            let contextNode = stack.popLast()
            let ctxText = contextNode?.displayText ?? "Self"
            stack.append(.entity("\(ctxText).init\(genericClause)\(sigNode.displayText)"))
            return true

        case "d": // deinit
            let ctx = stack.popLast()?.displayText ?? "Self"
            stack.append(.entity("\(ctx).deinit"))
            return true

        case "D": // __deallocating_deinit
            let ctx = stack.popLast()?.displayText ?? "Self"
            stack.append(.entity("\(ctx).__deallocating_deinit"))
            return true

        case "g": // getter
            let propType = stack.popLast()?.displayText ?? "Any"
            if let top = stack.last, case .emptyList = top { _ = stack.popLast() }
            let propName = stack.popLast()?.displayText ?? "property"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).getter : \(propType)"))
            return true

        case "s": // setter
            var propType = "Any"
            if let top = stack.popLast() {
                if case .functionSig(let params, _, _) = top, let first = params.first {
                    propType = first.type
                } else {
                    propType = top.displayText
                }
            }
            if let top = stack.last, case .emptyList = top { _ = stack.popLast() }
            let propName = stack.popLast()?.displayText ?? "property"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).setter : \(propType)"))
            return true

        case "a", "u": // addressor
            return parseAddressorEntity()

        default:
            return true
        }
    }

    private mutating func parseVariableOrAccessor() -> Bool {
        pos += 1 // consume 'v'
        // Check for 'vp' (property), 'vg' (getter), 'vs' (setter), 'vau' (unsafeMutableAddressor), 'vM' (modify)
        if match("g") {
            let propType = stack.popLast()?.displayText ?? "Any"
            let propName = stack.popLast()?.displayText ?? "property"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).getter : \(propType)"))
            return true
        }
        if match("s") {
            let propType = stack.popLast()?.displayText ?? "Any"
            let propName = stack.popLast()?.displayText ?? "property"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).setter : \(propType)"))
            return true
        }
        if peek() == "a" && peek(1) == "u" {
            pos += 2
            return parseAddressorEntity()
        }
        if match("M") {
            let propType = stack.popLast()?.displayText ?? "Any"
            let propName = stack.popLast()?.displayText ?? "property"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).modify : \(propType)"))
            return true
        }
        if match("p") {
            let propType = stack.popLast()?.displayText ?? "Any"
            let propName = stack.popLast()?.displayText ?? "variable"
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full) : \(propType)"))
            return true
        }
        return true
    }

    private mutating func parseAddressorEntity() -> Bool {
        let valType = stack.popLast()?.displayText ?? "Any"
        let varName = stack.popLast()?.displayText ?? "value"
        let ctx = stack.popLast()?.displayText
        let full = ctx != nil ? "\(ctx!).\(varName)" : varName
        stack.append(.entity("\(full).unsafeMutableAddressor : \(valType)"))
        return true
    }

    private mutating func parseGenericRequirement() -> Bool {
        pos += 1 // consume 'R'
        let reqKind = advance()
        switch reqKind {
        case "z": // Conformance constraint on 'T'
            if let proto = stack.popLast() {
                stack.append(.genericConstraint("T: \(proto.displayText)"))
            }
        case "s": // Same-type constraint
            if let rhs = stack.popLast() {
                stack.append(.genericConstraint("T == \(rhs.displayText)"))
            }
        case "l": // AnyObject layout constraint
            stack.append(.genericConstraint("T: AnyObject"))
        default:
            break
        }
        return true
    }

    private mutating func collectGenericSignature(paramCount: Int) -> Bool {
        var constraints: [String] = []
        while let top = stack.last, case .genericConstraint(let c) = top {
            _ = stack.popLast()
            constraints.append(c)
        }
        constraints.reverse()
        let baseNames = ["T", "U", "V", "W", "X", "Y"]
        let params = (0..<paramCount).map { i in i < baseNames.count ? baseNames[i] : "T\(i)" }
        stack.append(.genericSignature(params: params, constraints: constraints))
        return true
    }

    private mutating func parseMetadataOrDescriptor() -> Bool {
        pos += 1 // consume 'M'
        guard let sub = advance() else { return false }
        switch sub {
        case "a":
            if let target = stack.popLast() {
                stack.append(.entity("type metadata accessor for \(target.displayText)"))
            }
        case "n":
            if let target = stack.popLast() {
                stack.append(.entity("nominal type descriptor for \(target.displayText)"))
            }
        case "c":
            // Protocol conformance descriptor: Stack typically has [ConformingType, Protocol, Module]
            let mod = stack.popLast()
            let proto = stack.popLast()
            let conforming = stack.popLast()
            if let c = conforming, let p = proto, let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(c.displayText) : \(p.displayText) in \(m.displayText)"))
            } else if let p = proto, let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(p.displayText) : \(m.displayText)"))
            } else if let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(m.displayText)"))
            }
        case "p":
            if let proto = stack.popLast() {
                stack.append(.entity("protocol descriptor for \(proto.displayText)"))
            }
        case "f":
            if let target = stack.popLast() {
                stack.append(.entity("full type metadata for \(target.displayText)"))
            }
        default:
            break
        }
        return true
    }

    private mutating func parseWitnessTable() -> Bool {
        pos += 1 // consume 'W'
        guard let sub = advance() else { return false }
        switch sub {
        case "P", "a":
            let mod = stack.popLast()
            let proto = stack.popLast()
            let conforming = stack.popLast()
            if let c = conforming, let p = proto, let m = mod {
                stack.append(.entity("protocol witness table for \(c.displayText) : \(p.displayText) in \(m.displayText)"))
            } else if let p = proto, let m = mod {
                stack.append(.entity("protocol witness table for \(p.displayText) : \(m.displayText)"))
            }
        default:
            break
        }
        return true
    }

    private mutating func parseThunkOrSpecialization() -> Bool {
        pos += 1 // consume 'T'
        guard let sub = advance() else { return false }
        switch sub {
        case "W":
            if let target = stack.popLast() {
                stack.append(.entity("protocol witness for \(target.displayText)"))
            }
        case "j":
            if let target = stack.popLast() {
                stack.append(.entity("dispatch thunk of \(target.displayText)"))
            }
        case "q":
            if let target = stack.popLast() {
                stack.append(.entity("method descriptor for \(target.displayText)"))
            }
        case "o":
            if let target = stack.popLast() {
                stack.append(.entity("@objc \(target.displayText)"))
            }
        default:
            break
        }
        return true
    }
}

// MARK: - Handwritten Itanium C++ ABI Demangler (_Z / __Z)

private struct ItaniumCppDemangler {
    private let chars: [Character]
    private var pos: Int = 0
    private var substitutions: [String] = []
    private var templateArgsStack: [[String]] = []

    init(mangled: String) {
        self.chars = Array(mangled)
    }

    private var isAtEnd: Bool { pos >= chars.count }

    private func peek(_ offset: Int = 0) -> Character? {
        let idx = pos + offset
        return (idx >= 0 && idx < chars.count) ? chars[idx] : nil
    }

    @discardableResult
    private mutating func advance(_ count: Int = 1) -> Character? {
        guard pos < chars.count else { return nil }
        let ch = chars[pos]
        pos += count
        return ch
    }

    private mutating func match(_ expected: Character) -> Bool {
        if peek() == expected {
            pos += 1
            return true
        }
        return false
    }

    private mutating func readPositiveDecimal() -> Int? {
        guard let first = peek(), first.isASCII && first.isNumber else { return nil }
        var val = 0
        while let ch = peek(), let d = ch.wholeNumberValue {
            val = val * 10 + d
            pos += 1
            if val > 100_000 { return nil }
        }
        return val
    }

    private mutating func recordSubstitution(_ item: String) {
        guard !item.isEmpty else { return }
        substitutions.append(item)
    }

    // MARK: - Top-Level Entry

    mutating func parseEncodingOrSpecial() -> String? {
        guard !isAtEnd else { return nil }

        // Special vtable / typeinfo / guard variable / thunk prefixes
        if peek() == "T" {
            switch peek(1) {
            case "V":
                pos += 2
                guard let ty = parseType() else { return nil }
                return "vtable for \(ty)"
            case "I":
                pos += 2
                guard let ty = parseType() else { return nil }
                return "typeinfo for \(ty)"
            case "S":
                pos += 2
                guard let ty = parseType() else { return nil }
                return "typeinfo name for \(ty)"
            case "T":
                pos += 2
                guard let ty = parseType() else { return nil }
                return "VTT for \(ty)"
            case "h", "v":
                let isVirtual = (peek(1) == "v")
                pos += 2
                // Skip call offset up to '_'
                while !isAtEnd && advance() != "_" {}
                if isVirtual {
                    while !isAtEnd && peek() != "_" && (peek()?.isNumber == true || peek() == "n") {
                        pos += 1
                    }
                    _ = match("_")
                }
                guard let inner = parseEncoding() else { return nil }
                return "\(isVirtual ? "virtual" : "non-virtual") thunk to \(inner)"
            default:
                break
            }
        }

        if peek() == "G" && peek(1) == "V" {
            pos += 2
            guard let parsedName = parseName() else { return nil }
            return "guard variable for \(parsedName.fullName)"
        }

        return parseEncoding()
    }

    private struct ParsedCppName {
        var fullName: String
        var trailingQualifiers: String
        var isTemplateWithReturnType: Bool
    }

    private mutating func parseEncoding() -> String? {
        guard let nameInfo = parseName() else { return nil }

        // Global variable or bare unparameterized symbol
        if isAtEnd || peek() == "E" {
            return nameInfo.fullName + nameInfo.trailingQualifiers
        }

        // Parse <bare-function-type>
        var types: [String] = []
        while !isAtEnd && peek() != "E" {
            guard let t = parseType() else { return nil }
            types.append(t)
        }
        guard !types.isEmpty else {
            return nameInfo.fullName + nameInfo.trailingQualifiers
        }

        var returnPrefix = ""
        var paramSlice = types[...]
        if nameInfo.isTemplateWithReturnType && types.count >= 1 {
            // Constructors & destructors never encode a return type even if templated
            let baseTail = nameInfo.fullName.split(separator: ":").last.map(String.init) ?? ""
            if !baseTail.contains("~") && !Self.looksLikeCtorCall(fullName: nameInfo.fullName) {
                returnPrefix = "\(types[0]) "
                paramSlice = types.dropFirst()
            }
        }

        let params: [String]
        if paramSlice.count == 1 && paramSlice.first == "void" {
            params = []
        } else {
            params = Array(paramSlice)
        }

        let qualSuffix = nameInfo.trailingQualifiers.isEmpty ? "" : " \(nameInfo.trailingQualifiers)"
        return "\(returnPrefix)\(nameInfo.fullName)(\(params.joined(separator: ", ")))\(qualSuffix)"
    }

    private static func looksLikeCtorCall(fullName: String) -> Bool {
        let segments = Self.splitScopeSegments(fullName)
        guard segments.count >= 2 else { return false }
        let prev = Self.stripTemplateArguments(segments[segments.count - 2])
        let last = Self.stripTemplateArguments(segments[segments.count - 1])
        return !prev.isEmpty && prev == last
    }

    private static func splitScopeSegments(_ s: String) -> [String] {
        var parts: [String] = []
        var cur = ""
        let arr = Array(s)
        var depth = 0
        var i = 0
        while i < arr.count {
            let c = arr[i]
            if c == "<" { depth += 1; cur.append(c); i += 1 }
            else if c == ">" { depth = max(0, depth - 1); cur.append(c); i += 1 }
            else if depth == 0 && c == ":" && i + 1 < arr.count && arr[i + 1] == ":" {
                parts.append(cur)
                cur = ""
                i += 2
            } else {
                cur.append(c)
                i += 1
            }
        }
        if !cur.isEmpty { parts.append(cur) }
        return parts
    }

    private static func stripTemplateArguments(_ seg: String) -> String {
        guard let idx = seg.firstIndex(of: "<") else { return seg }
        return String(seg[..<idx])
    }

    // MARK: - <name>, <nested-name> & <unqualified-name>

    private mutating func parseName(isTopLevelEntity: Bool = true) -> ParsedCppName? {
        if peek() == "N" {
            return parseNestedName(isTopLevelEntity: isTopLevelEntity)
        }

        var prefix = ""
        if peek() == "S" && peek(1) == "t" {
            pos += 2
            prefix = "std::"
        } else if peek() == "S" {
            if let sub = parseSubstitution() {
                prefix = "\(sub)::"
            } else {
                return nil
            }
        }

        guard let unqual = parseUnqualifiedName(currentClassBase: nil) else { return nil }
        var full = prefix + unqual
        var hasTemplate = false

        if peek() == "I" {
            // In Itanium C++ ABI, <unscoped-template-name> is always recorded as a substitution before <template-args>
            recordSubstitution(full)
            guard let targs = parseTemplateArgs() else { return nil }
            if isTopLevelEntity {
                templateArgsStack.append(targs)
            }
            full += "<\(targs.joined(separator: ", "))>"
            hasTemplate = true
        }

        return ParsedCppName(
            fullName: Self.simplifyCommonLibcxxAliases(full),
            trailingQualifiers: "",
            isTemplateWithReturnType: hasTemplate
        )
    }

    private mutating func parseNestedName(isTopLevelEntity: Bool = true) -> ParsedCppName? {
        pos += 1 // consume 'N'

        var cvQuals: [String] = []
        while let q = peek() {
            if q == "r" { cvQuals.append("__restrict"); pos += 1 }
            else if q == "V" { cvQuals.append("volatile"); pos += 1 }
            else if q == "K" { cvQuals.append("const"); pos += 1 }
            else { break }
        }

        var refQual = ""
        if peek() == "R" { refQual = "&"; pos += 1 }
        else if peek() == "O" { refQual = "&&"; pos += 1 }

        var components: [String] = []
        var lastClassBase: String? = nil
        var lastWasTemplated = false

        while !isAtEnd && peek() != "E" {
            if peek() == "S" {
                guard let sub = parseSubstitution() else { return nil }
                components.append(sub)
                lastClassBase = Self.stripTemplateArguments(Self.splitScopeSegments(sub).last ?? sub)
                lastWasTemplated = false

                if peek() == "I" {
                    guard let targs = parseTemplateArgs() else { return nil }
                    if isTopLevelEntity {
                        templateArgsStack.append(targs)
                    }
                    let templated = "\(components.removeLast())<\(targs.joined(separator: ", "))>"
                    components.append(templated)
                    if peek() != "E" {
                        recordSubstitution(components.joined(separator: "::"))
                    }
                    lastWasTemplated = true
                }
                continue
            }

            if peek() == "I" {
                guard !components.isEmpty, let targs = parseTemplateArgs() else { return nil }
                if isTopLevelEntity {
                    templateArgsStack.append(targs)
                }
                let last = components.removeLast()
                let templated = "\(last)<\(targs.joined(separator: ", "))>"
                components.append(templated)
                if peek() != "E" {
                    recordSubstitution(components.joined(separator: "::"))
                }
                lastWasTemplated = true
                continue
            }

            guard let part = parseUnqualifiedName(currentClassBase: lastClassBase) else {
                return nil
            }
            components.append(part)
            lastClassBase = part
            lastWasTemplated = false

            // Every <prefix> or <template-prefix> before 'E' is a substitution candidate
            if peek() != "E" {
                recordSubstitution(components.joined(separator: "::"))
            }
        }

        guard match("E"), !components.isEmpty else { return nil }

        var qualParts = cvQuals
        if !refQual.isEmpty {
            qualParts.append(refQual)
        }

        // Collapse inline libc++ namespace std::__1 -> std
        let filteredComponents = components.filter { $0 != "__1" && $0 != "__cxx11" }
        let joined = (filteredComponents.isEmpty ? components : filteredComponents).joined(separator: "::")

        return ParsedCppName(
            fullName: Self.simplifyCommonLibcxxAliases(joined),
            trailingQualifiers: qualParts.joined(separator: " "),
            isTemplateWithReturnType: lastWasTemplated
        )
    }

    private mutating func parseUnqualifiedName(currentClassBase: String?) -> String? {
        guard let ch = peek() else { return nil }

        // Length-prefixed source identifier
        if ch.isASCII && ch.isNumber {
            guard let len = readPositiveDecimal(), len > 0, pos + len <= chars.count else {
                return nil
            }
            let ident = String(chars[pos..<(pos + len)])
            pos += len
            return ident
        }

        // Constructor (C1, C2, C3)
        if ch == "C", let variant = peek(1), (variant == "1" || variant == "2" || variant == "3") {
            pos += 2
            return currentClassBase ?? "constructor"
        }

        // Destructor (D0, D1, D2)
        if ch == "D", let variant = peek(1), (variant == "0" || variant == "1" || variant == "2") {
            pos += 2
            let cls = currentClassBase ?? "destructor"
            return "~\(cls)"
        }

        // Conversion operator: cv <type>
        if ch == "c" && peek(1) == "v" {
            pos += 2
            guard let targetTy = parseType() else { return nil }
            return "operator \(targetTy)"
        }

        // Two-letter operator codes
        if let second = peek(1) {
            let code = "\(ch)\(second)"
            if let opName = Self.operatorTable[code] {
                pos += 2
                return opName
            }
        }

        return nil
    }

    private static let operatorTable: [String: String] = [
        "nw": "operator new",
        "na": "operator new[]",
        "dl": "operator delete",
        "da": "operator delete[]",
        "ps": "operator+",
        "ng": "operator-",
        "ad": "operator&",
        "de": "operator*",
        "co": "operator~",
        "pl": "operator+",
        "mi": "operator-",
        "ml": "operator*",
        "dv": "operator/",
        "rm": "operator%",
        "an": "operator&",
        "or": "operator|",
        "eo": "operator^",
        "aS": "operator=",
        "pL": "operator+=",
        "mI": "operator-=",
        "mL": "operator*=",
        "dV": "operator/=",
        "rM": "operator%=",
        "aN": "operator&=",
        "oR": "operator|=",
        "eO": "operator^=",
        "ls": "operator<<",
        "rs": "operator>>",
        "lS": "operator<<=",
        "rS": "operator>>=",
        "eq": "operator==",
        "ne": "operator!=",
        "lt": "operator<",
        "gt": "operator>",
        "le": "operator<=",
        "ge": "operator>=",
        "ss": "operator<=>",
        "nt": "operator!",
        "aa": "operator&&",
        "oo": "operator||",
        "pp": "operator++",
        "mm": "operator--",
        "cm": "operator,",
        "pm": "operator->*",
        "pt": "operator->",
        "cl": "operator()",
        "ix": "operator[]",
        "qu": "operator?"
    ]

    // MARK: - <type>, Qualifiers, Pointers, Templates & Substitutions

    private mutating func parseType() -> String? {
        guard let ch = peek() else { return nil }

        // CV-qualifiers (K = const, V = volatile, r = restrict)
        if ch == "K" || ch == "V" || ch == "r" {
            var quals: [String] = []
            while let q = peek() {
                if q == "K" { quals.append("const"); pos += 1 }
                else if q == "V" { quals.append("volatile"); pos += 1 }
                else if q == "r" { quals.append("__restrict"); pos += 1 }
                else { break }
            }
            guard let base = parseType() else { return nil }
            let qualified: String
            if base.hasSuffix("*") || base.hasSuffix("&") {
                qualified = "\(base) \(quals.joined(separator: " "))"
            } else {
                qualified = "\(quals.joined(separator: " ")) \(base)"
            }
            recordSubstitution(qualified)
            return qualified
        }

        // Pointer, L-value reference, R-value reference
        if ch == "P" {
            pos += 1
            // Function pointer P F <ret> <args>... E
            if peek() == "F" {
                pos += 1
                guard let fnPtr = parseFunctionPointerType() else { return nil }
                recordSubstitution(fnPtr)
                return fnPtr
            }
            guard let pointee = parseType() else { return nil }
            let ptr = "\(pointee)*"
            recordSubstitution(ptr)
            return ptr
        }

        if ch == "R" {
            pos += 1
            guard let target = parseType() else { return nil }
            let ref = "\(target)&"
            recordSubstitution(ref)
            return ref
        }

        if ch == "O" {
            pos += 1
            guard let target = parseType() else { return nil }
            let rref = "\(target)&&"
            recordSubstitution(rref)
            return rref
        }

        // Bare function type F <ret> <args>... E
        if ch == "F" {
            pos += 1
            guard let fn = parseBareFunctionTypeFormatted() else { return nil }
            recordSubstitution(fn)
            return fn
        }

        // Fixed-size array A <dim>_ <elemType>
        if ch == "A" {
            pos += 1
            var dimStr = ""
            while let c = peek(), c != "_" {
                dimStr.append(c)
                pos += 1
            }
            _ = match("_")
            guard let elem = parseType() else { return nil }
            let arr = "\(elem)[\(dimStr)]"
            recordSubstitution(arr)
            return arr
        }

        // Template parameter T_, T0_, T1_, ...
        if ch == "T" {
            pos += 1
            let idx: Int
            if match("_") {
                idx = 0
            } else {
                guard let n = readPositiveDecimal(), match("_") else { return nil }
                idx = n + 1
            }
            let resolved: String
            if let activeArgs = templateArgsStack.last, idx < activeArgs.count {
                resolved = activeArgs[idx]
            } else {
                resolved = "T\(idx)"
            }
            recordSubstitution(resolved)
            return resolved
        }

        // Substitution S..., St..., Ss, Sa, etc.
        if ch == "S" {
            if peek(1) == "t" {
                // Scoped std::<name> type
                guard let named = parseName(isTopLevelEntity: false) else { return nil }
                recordSubstitution(named.fullName)
                return named.fullName
            }
            guard let sub = parseSubstitution() else { return nil }
            if peek() == "I" {
                guard let targs = parseTemplateArgs() else { return nil }
                let specialized = Self.simplifyCommonLibcxxAliases("\(sub)<\(targs.joined(separator: ", "))>")
                recordSubstitution(specialized)
                return specialized
            }
            return sub
        }

        // Nested or class/enum named type
        if ch == "N" || (ch.isASCII && ch.isNumber) {
            guard let named = parseName(isTopLevelEntity: false) else { return nil }
            recordSubstitution(named.fullName)
            return named.fullName
        }

        // Extended 'D' builtin types (Dn = std::nullptr_t, Ds = char16_t, Di = char32_t, Du = char8_t, Da = auto)
        if ch == "D" {
            pos += 1
            guard let next = advance() else { return nil }
            switch next {
            case "n": return "std::nullptr_t"
            case "s": return "char16_t"
            case "i": return "char32_t"
            case "u": return "char8_t"
            case "a": return "auto"
            default:  return nil
            }
        }

        // Single-character builtin types (do NOT add builtin primitives to substitution table per Itanium ABI!)
        if let builtin = Self.builtinTypes[ch] {
            pos += 1
            return builtin
        }

        return nil
    }

    private static let builtinTypes: [Character: String] = [
        "v": "void",
        "w": "wchar_t",
        "b": "bool",
        "c": "char",
        "a": "signed char",
        "h": "unsigned char",
        "s": "short",
        "t": "unsigned short",
        "i": "int",
        "j": "unsigned int",
        "l": "long",
        "m": "unsigned long",
        "x": "long long",
        "y": "unsigned long long",
        "n": "__int128",
        "o": "unsigned __int128",
        "f": "float",
        "d": "double",
        "e": "long double",
        "g": "__float128",
        "z": "..."
    ]

    private mutating func parseFunctionPointerType() -> String? {
        guard let ret = parseType() else { return nil }
        var args: [String] = []
        while !isAtEnd && peek() != "E" {
            guard let a = parseType() else { return nil }
            args.append(a)
        }
        guard match("E") else { return nil }
        if args.count == 1 && args[0] == "void" { args = [] }
        return "\(ret) (*)(\(args.joined(separator: ", ")))"
    }

    private mutating func parseBareFunctionTypeFormatted() -> String? {
        guard let ret = parseType() else { return nil }
        var args: [String] = []
        while !isAtEnd && peek() != "E" {
            guard let a = parseType() else { return nil }
            args.append(a)
        }
        guard match("E") else { return nil }
        if args.count == 1 && args[0] == "void" { args = [] }
        return "\(ret) (\(args.joined(separator: ", ")))"
    }

    private mutating func parseTemplateArgs() -> [String]? {
        guard match("I") else { return nil }
        var args: [String] = []
        while !isAtEnd && peek() != "E" {
            if peek() == "L" {
                // Integral / boolean literal template argument: L <type> <value> E
                pos += 1
                let litType = parseType()
                var isNeg = false
                if match("n") { isNeg = true }
                var digits = ""
                while let c = peek(), c != "E" {
                    digits.append(c)
                    pos += 1
                }
                guard match("E") else { return nil }
                if litType == "bool" {
                    args.append(digits == "1" ? "true" : "false")
                } else {
                    args.append(isNeg ? "-\(digits)" : digits)
                }
            } else if peek() == "J" {
                // Parameter pack J <targ>* E
                pos += 1
                while !isAtEnd && peek() != "E" {
                    guard let packElem = parseType() else { return nil }
                    args.append(packElem)
                }
                guard match("E") else { return nil }
            } else {
                guard let ty = parseType() else { return nil }
                args.append(ty)
            }
        }
        guard match("E") else { return nil }
        return args
    }

    private mutating func parseSubstitution() -> String? {
        guard match("S") else { return nil }
        guard let next = peek() else { return nil }

        switch next {
        case "_":
            pos += 1
            return substitutions.first
        case "t":
            pos += 1
            return "std"
        case "a":
            pos += 1
            return "std::allocator"
        case "b":
            pos += 1
            return "std::basic_string"
        case "s":
            pos += 1
            return "std::string"
        case "i":
            pos += 1
            return "std::istream"
        case "o":
            pos += 1
            return "std::ostream"
        case "d":
            pos += 1
            return "std::iostream"
        default:
            // Base-36 sequence ID terminated by '_': S0_ -> subs[1], S1_ -> subs[2], ..., SA_ -> subs[11]
            var seqVal = 0
            var consumedDigits = 0
            while let c = peek(), c != "_" {
                let digit: Int
                if c >= "0" && c <= "9" {
                    digit = Int(c.asciiValue! - Character("0").asciiValue!)
                } else if c >= "A" && c <= "Z" {
                    digit = 10 + Int(c.asciiValue! - Character("A").asciiValue!)
                } else {
                    return nil
                }
                seqVal = seqVal * 36 + digit
                consumedDigits += 1
                pos += 1
            }
            guard consumedDigits > 0, match("_") else { return nil }
            let idx = seqVal + 1
            guard idx < substitutions.count else { return nil }
            return substitutions[idx]
        }
    }

    private static func simplifyCommonLibcxxAliases(_ text: String) -> String {
        text
            .replacingOccurrences(
                of: "std::basic_string<char, std::char_traits<char>, std::allocator<char>>",
                with: "std::string"
            )
            .replacingOccurrences(
                of: "std::basic_string_view<char, std::char_traits<char>>",
                with: "std::string_view"
            )
    }
}
