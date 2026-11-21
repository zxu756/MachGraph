#if canImport(Darwin)
import Darwin
#endif
import Foundation

#if canImport(Darwin)
@_silgen_name("swift_demangle")
private func _machgraph_swift_demangle(
    _ mangledName: UnsafePointer<CChar>,
    _ mangledNameLength: Int,
    _ outputBuffer: UnsafeMutablePointer<CChar>?,
    _ outputBufferSize: UnsafeMutablePointer<Int>?,
    _ flags: UInt32
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("__cxa_demangle")
private func _machgraph_cxa_demangle(
    _ mangledName: UnsafePointer<CChar>,
    _ outputBuffer: UnsafeMutablePointer<CChar>?,
    _ length: UnsafeMutablePointer<Int>?,
    _ status: UnsafeMutablePointer<Int32>?
) -> UnsafeMutablePointer<CChar>?
#endif

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

    private static let swiftPrefixes: [String] = [
        "_$s", "$s", "_$S", "$S", "__T0", "_T0", "_$e", "$e"
    ]

    /// Whether to prefer the in-process Darwin system runtime (`swift_demangle` / `__cxa_demangle`)
    /// before falling back to the pure-Swift handwritten demanglers.
    public let useSystemRuntime: Bool

    public init(useSystemRuntime: Bool = true) {
        self.useSystemRuntime = useSystemRuntime
    }

    /// Classifies the ABI mangling scheme of `rawSymbol`.
    public func classify(_ rawSymbol: String) -> DemangledSymbolLanguage {
        guard !rawSymbol.isEmpty else { return .plain }

        if rawSymbol.hasPrefix("-[") || rawSymbol.hasPrefix("+[") ||
           rawSymbol.hasPrefix("_OBJC_CLASS_$_") || rawSymbol.hasPrefix("_OBJC_METACLASS_$_") ||
           rawSymbol.hasPrefix("_OBJC_IVAR_$_") {
            return .objc
        }

        let core = Self.stripDyldStubSuffix(rawSymbol)
        if Self.hasSwiftMangledPrefix(core) {
            return .swift
        }
        if Self.isLikelyCppSymbol(core) {
            return .cpp
        }
        if core.hasPrefix("_") && core.count > 1 {
            return .c
        }
        return .plain
    }

    /// Demangles Swift (`_$s`, `$s`, `_$S`, `$S`, `_T0`, `__T0`, `_$e`, `$e`) and Itanium C++ (`__Z`, `_Z`, `___Z`)
    /// symbol names in-process without spawning any external subprocesses.
    ///
    /// Guards (M3 D-M3-1 / D-M3-2):
    /// - Incomplete, truncated, or unrecognized mangled names ALWAYS return `rawSymbol` verbatim (never partial output).
    /// - Plain C symbols (such as `_main`, `_ZeroFilesTested`) and Objective-C names NEVER strip leading `_` and return `rawSymbol` verbatim.
    /// - Compiler suffixes (`.cold.<N>`, `.resume.<N>`, `.llvm.<hash>`, etc.) follow `swift-demangle -compact` and `c++filt` rules.
    public func demangle(_ rawSymbol: String) -> String {
        guard !rawSymbol.isEmpty else { return rawSymbol }

        // 1. Objective-C method names and linker symbols are returned verbatim.
        if rawSymbol.hasPrefix("-[") || rawSymbol.hasPrefix("+[") ||
           rawSymbol.hasPrefix("_OBJC_CLASS_$_") || rawSymbol.hasPrefix("_OBJC_METACLASS_$_") ||
           rawSymbol.hasPrefix("_OBJC_IVAR_$_") {
            return rawSymbol
        }

        let (core, stubSuffix) = Self.splitSymbolSuffix(rawSymbol)

        // 2. Swift ABI Demangling (_$s / $s / _$S / $S / __T0 / _T0 / _$e / $e)
        if Self.hasSwiftMangledPrefix(core) {
            guard Self.extractSwiftMangledPayload(from: core) != nil else {
                return rawSymbol
            }
            if useSystemRuntime, let sysOut = Self.demangleSwiftWithSystemRuntime(core) {
                if sysOut != core && !Self.isMerelyUnderscoreStripped(raw: core, candidate: sysOut) {
                    return stubSuffix.isEmpty ? sysOut : "\(sysOut)\(stubSuffix)"
                }
                return rawSymbol
            }
            #if canImport(Darwin)
            if useSystemRuntime {
                // System swift_demangle is linked in-process and rejected the symbol as invalid/truncated.
                return rawSymbol
            }
            #endif
            if let fallbackOut = Self.demangleSwiftWithHandwrittenFallback(core),
               fallbackOut != core,
               !Self.isMerelyUnderscoreStripped(raw: core, candidate: fallbackOut) {
                return stubSuffix.isEmpty ? fallbackOut : "\(fallbackOut)\(stubSuffix)"
            }
            return rawSymbol
        }

        // Preserve any other "_$" prefix untouched.
        if core.hasPrefix("_$") {
            return rawSymbol
        }

        // 3. Itanium C++ ABI Demangling (____Z / ___Z / __Z / _Z)
        if core.hasPrefix("_Z") || core.hasPrefix("__Z") || core.hasPrefix("___Z") || core.hasPrefix("____Z") {
            if useSystemRuntime {
                if let sysCpp = Self.demangleCppWithSystemRuntime(core),
                   sysCpp != core,
                   !Self.isMerelyUnderscoreStripped(raw: core, candidate: sysCpp) {
                    return stubSuffix.isEmpty ? sysCpp : "\(sysCpp)\(stubSuffix)"
                }
                #if canImport(Darwin)
                return rawSymbol
                #endif
            }
            if let fallbackCpp = Self.demangleCppWithHandwrittenFallback(core),
               fallbackCpp != core,
               !Self.isMerelyUnderscoreStripped(raw: core, candidate: fallbackCpp) {
                return stubSuffix.isEmpty ? fallbackCpp : "\(fallbackCpp)\(stubSuffix)"
            }
            return rawSymbol
        }

        // 4. Plain C symbols (e.g. `_main`, `_verify_license`) and all non-mangled strings return verbatim.
        return rawSymbol
    }

    // MARK: - In-Process System Runtime Bridges (`swift_demangle` & `__cxa_demangle`)

    private static func demangleSwiftWithSystemRuntime(_ symbol: String) -> String? {
        #if canImport(Darwin)
        // `__T0` carries an extra Mach-O leading underscore ahead of Swift 4 `_T0`.
        let query: String
        if symbol.hasPrefix("__T0") && symbol.count > 4 {
            query = String(symbol.dropFirst())
        } else {
            query = symbol
        }
        let rawResult: String? = query.utf8CString.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return nil }
            let byteLen = max(0, buf.count - 1)
            guard byteLen > 0 else { return nil }
            guard let outPtr = _machgraph_swift_demangle(base, byteLen, nil, nil, 0) else {
                return nil
            }
            defer { Darwin.free(outPtr) }
            return String(cString: outPtr)
        }
        guard let unwrapped = rawResult, !unwrapped.isEmpty, unwrapped != query, unwrapped != symbol else {
            return nil
        }
        return synthesizeSwiftTypeSugar(unwrapped)
        #else
        return nil
        #endif
    }

    private static func demangleCppWithSystemRuntime(_ symbol: String) -> String? {
        #if canImport(Darwin)
        if let direct = callCxaDemangleForMachOSymbol(symbol) {
            return direct
        }
        // Handle compiler suffixes (.cold.1, .llvm.<hash>, .resume.0, .part.0) matching `/usr/bin/c++filt`.
        if let dotIdx = symbol.firstIndex(of: ".") {
            let basePart = String(symbol[..<dotIdx])
            let dotSuffix = String(symbol[dotIdx...])
            if dotSuffix.count > 1, let baseDemangled = callCxaDemangleForMachOSymbol(basePart) {
                return "\(baseDemangled) (\(dotSuffix))"
            }
        }
        return nil
        #else
        return nil
        #endif
    }

    #if canImport(Darwin)
    private static func callCxaDemangleForMachOSymbol(_ symbol: String) -> String? {
        if symbol.hasPrefix("____Z") && symbol.count > 5 {
            return callRawCxaDemangle(String(symbol.dropFirst()))
        }
        if symbol.hasPrefix("___Z") && symbol.count > 4 {
            if let blk = callRawCxaDemangle(symbol) {
                return blk
            }
            return callRawCxaDemangle(String(symbol.dropFirst()))
        }
        if symbol.hasPrefix("__Z") && symbol.count > 3 {
            return callRawCxaDemangle(String(symbol.dropFirst()))
        }
        if symbol.hasPrefix("_Z") && symbol.count > 2 {
            // Pass `_Z...` directly so plain C symbols like `_ZeroFilesTested` fail `<encoding>` and return nil.
            return callRawCxaDemangle(symbol)
        }
        return nil
    }

    private static func callRawCxaDemangle(_ mangled: String) -> String? {
        mangled.utf8CString.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return nil }
            var status: Int32 = 0
            guard let outPtr = _machgraph_cxa_demangle(base, nil, nil, &status) else {
                return nil
            }
            defer { Darwin.free(outPtr) }
            guard status == 0 else { return nil }
            let text = String(cString: outPtr)
            return text.isEmpty ? nil : text
        }
    }
    #endif

    // MARK: - Swift Syntactic Type Sugar (`xcrun swift-demangle -compact` Parity)

    /// Synthesizes Swift syntactic sugar (`[T]`, `[K : V]`, `T?`, `T!`) on `swift_demangle(..., flags: 0)` output
    /// to match `DemangleOptions::SynthesizeSugarOnTypes` (`xcrun swift-demangle -compact`).
    private static func synthesizeSwiftTypeSugar(_ text: String) -> String {
        guard text.contains("Swift.") else { return text }
        let bytes = Array(text.utf8)
        let outBytes = transformSwiftSugarBytes(bytes, range: 0..<bytes.count)
        return String(decoding: outBytes, as: UTF8.self)
    }

    private static let optionalPrefixUTF8 = Array("Swift.Optional<".utf8)
    private static let iuoPrefixUTF8 = Array("Swift.ImplicitlyUnwrappedOptional<".utf8)
    private static let arrayPrefixUTF8 = Array("Swift.Array<".utf8)
    private static let dictPrefixUTF8 = Array("Swift.Dictionary<".utf8)
    private static let constPropFuncPrefixUTF8 = Array("[Constant Propagated Function : ".utf8)
    private static let whereWordUTF8 = Array("where ".utf8)
    private static let spacedWhereWordUTF8 = Array(" where ".utf8)

    private enum SugarKind {
        case optional
        case iuo
        case array
        case dict
    }

    private static func matchBytes(_ needle: [UInt8], in hay: [UInt8], at pos: Int, end: Int) -> Bool {
        guard pos + needle.count <= end else { return false }
        for k in 0..<needle.count {
            if hay[pos + k] != needle[k] { return false }
        }
        return true
    }

    private static func transformSwiftSugarBytes(_ bytes: [UInt8], range: Range<Int>) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(range.count)
        var i = range.lowerBound
        let end = range.upperBound

        while i < end {
            // `NodePrinter` prints `[Constant Propagated Function : ...]` using unsugared options; copy balanced `[...]` verbatim.
            if matchBytes(constPropFuncPrefixUTF8, in: bytes, at: i, end: end) {
                var bdepth = 1
                var k = i + constPropFuncPrefixUTF8.count
                while k < end && bdepth > 0 {
                    if bytes[k] == 0x2D && k + 1 < end && bytes[k + 1] == 0x3E { // "->"
                        k += 2
                        continue
                    }
                    if bytes[k] == 0x5B { bdepth += 1 }       // '['
                    else if bytes[k] == 0x5D { bdepth -= 1 }  // ']'
                    k += 1
                }
                out.append(contentsOf: bytes[i..<k])
                i = k
                continue
            }

            var matched: (len: Int, kind: SugarKind)? = nil
            if i == range.lowerBound || bytes[i - 1] != 0x2E { // not preceded by '.'
                if matchBytes(optionalPrefixUTF8, in: bytes, at: i, end: end) {
                    matched = (optionalPrefixUTF8.count, .optional)
                } else if matchBytes(iuoPrefixUTF8, in: bytes, at: i, end: end) {
                    matched = (iuoPrefixUTF8.count, .iuo)
                } else if matchBytes(arrayPrefixUTF8, in: bytes, at: i, end: end) {
                    matched = (arrayPrefixUTF8.count, .array)
                } else if matchBytes(dictPrefixUTF8, in: bytes, at: i, end: end) {
                    matched = (dictPrefixUTF8.count, .dict)
                }
            }

            guard let (pfxLen, kind) = matched else {
                out.append(bytes[i])
                i += 1
                continue
            }

            let startInner = i + pfxLen
            var depth = 1
            var j = startInner
            var commasAtDepth1: [Int] = []
            while j < end && depth > 0 {
                let b = bytes[j]
                if b == 0x2D && j + 1 < end && bytes[j + 1] == 0x3E { // "->"
                    j += 2
                    continue
                }
                if b == 0x3C { // '<'
                    depth += 1
                } else if b == 0x3E { // '>'
                    depth -= 1
                    if depth == 0 { break }
                } else if b == 0x28 || b == 0x5B { // '(' or '['
                    depth += 1
                } else if b == 0x29 || b == 0x5D { // ')' or ']'
                    depth -= 1
                } else if b == 0x2C && depth == 1 { // ','
                    commasAtDepth1.append(j)
                }
                j += 1
            }

            guard depth == 0 else {
                out.append(bytes[i])
                i += 1
                continue
            }

            // Extension generic signatures (`Swift.Array<A where ...>` or `Swift.Dictionary< where ...>`) are not bound generics.
            if hasTopLevelWhereClause(bytes, range: startInner..<j) {
                out.append(contentsOf: bytes[i..<startInner])
                out.append(contentsOf: transformSwiftSugarBytes(bytes, range: startInner..<j))
                out.append(0x3E) // '>'
                i = j + 1
                continue
            }

            switch kind {
            case .array where commasAtDepth1.isEmpty:
                let inner = transformSwiftSugarBytes(bytes, range: startInner..<j)
                out.append(0x5B) // '['
                out.append(contentsOf: inner)
                out.append(0x5D) // ']'
                i = j + 1

            case .dict where commasAtDepth1.count == 1:
                let cpos = commasAtDepth1[0]
                let kRange = trimASCIISpaces(bytes, range: startInner..<cpos)
                let vRange = trimASCIISpaces(bytes, range: (cpos + 1)..<j)
                let kTrans = transformSwiftSugarBytes(bytes, range: kRange)
                let vTrans = transformSwiftSugarBytes(bytes, range: vRange)
                out.append(0x5B) // '['
                out.append(contentsOf: kTrans)
                out.append(contentsOf: [0x20, 0x3A, 0x20]) // " : "
                out.append(contentsOf: vTrans)
                out.append(0x5D) // ']'
                i = j + 1

            case .optional where commasAtDepth1.isEmpty, .iuo where commasAtDepth1.isEmpty:
                let inner = transformSwiftSugarBytes(bytes, range: startInner..<j)
                let suffixByte: UInt8 = (kind == .optional) ? 0x3F : 0x21 // '?' or '!'
                if optionalInnerNeedsParentheses(inner) {
                    out.append(0x28) // '('
                    out.append(contentsOf: inner)
                    out.append(0x29) // ')'
                    out.append(suffixByte)
                } else {
                    out.append(contentsOf: inner)
                    out.append(suffixByte)
                }
                i = j + 1

            default:
                out.append(bytes[i])
                i += 1
            }
        }

        return out
    }

    private static func trimASCIISpaces(_ bytes: [UInt8], range: Range<Int>) -> Range<Int> {
        var lo = range.lowerBound
        var hi = range.upperBound
        while lo < hi && bytes[lo] == 0x20 { lo += 1 }
        while hi > lo && bytes[hi - 1] == 0x20 { hi -= 1 }
        return lo..<hi
    }

    private static func hasTopLevelWhereClause(_ bytes: [UInt8], range: Range<Int>) -> Bool {
        let trimmed = trimASCIISpaces(bytes, range: range)
        if matchBytes(whereWordUTF8, in: bytes, at: trimmed.lowerBound, end: trimmed.upperBound) {
            return true
        }
        var depth = 0
        var i = range.lowerBound
        let end = range.upperBound
        while i < end {
            let b = bytes[i]
            if b == 0x2D && i + 1 < end && bytes[i + 1] == 0x3E {
                i += 2
                continue
            }
            if b == 0x3C || b == 0x28 || b == 0x5B {
                depth += 1
            } else if b == 0x3E || b == 0x29 || b == 0x5D {
                depth -= 1
            } else if depth == 0 && matchBytes(spacedWhereWordUTF8, in: bytes, at: i, end: end) {
                return true
            }
            i += 1
        }
        return false
    }

    private static func optionalInnerNeedsParentheses(_ inner: [UInt8]) -> Bool {
        guard !inner.isEmpty else { return false }
        let s = String(decoding: inner, as: UTF8.self)
        if s.hasPrefix("@") || s.hasPrefix("any ") || s.hasPrefix("some ") ||
           s.hasPrefix("sending ") || s.hasPrefix("isolated ") {
            return true
        }
        var depth = 0
        var i = 0
        let n = inner.count
        while i < n {
            let b = inner[i]
            if b == 0x2D && i + 1 < n && inner[i + 1] == 0x3E { // "->"
                if depth == 0 { return true }
                i += 2
                continue
            }
            if b == 0x3C || b == 0x28 || b == 0x5B {
                depth += 1
            } else if b == 0x3E || b == 0x29 || b == 0x5D {
                depth -= 1
            } else if b == 0x26 && depth == 0 && i > 0 && i + 1 < n && inner[i - 1] == 0x20 && inner[i + 1] == 0x20 { // " & "
                return true
            }
            i += 1
        }
        return false
    }

    // MARK: - Handwritten Fallback Entry Points & Prefix/Suffix Helpers

    private static func demangleSwiftWithHandwrittenFallback(_ symbol: String) -> String? {
        if let dotIdx = symbol.firstIndex(of: ".") {
            let basePart = String(symbol[..<dotIdx])
            let dotSuffix = String(symbol[dotIdx...])
            if dotSuffix.count > 1,
               let payload = extractSwiftMangledPayload(from: basePart) {
                var parser = Swift5ABIDemangler(payload: payload)
                if let demangled = parser.parseTopLevel() {
                    return "\(demangled) with unmangled suffix \"\(dotSuffix)\""
                }
            }
            return nil
        }
        guard let payload = extractSwiftMangledPayload(from: symbol) else { return nil }
        var parser = Swift5ABIDemangler(payload: payload)
        return parser.parseTopLevel()
    }

    private static func demangleCppWithHandwrittenFallback(_ symbol: String) -> String? {
        if let direct = runHandwrittenCppParser(symbol) {
            return direct
        }
        if let dotIdx = symbol.firstIndex(of: ".") {
            let basePart = String(symbol[..<dotIdx])
            let dotSuffix = String(symbol[dotIdx...])
            if dotSuffix.count > 1, let baseDemangled = runHandwrittenCppParser(basePart) {
                return "\(baseDemangled) (\(dotSuffix))"
            }
        }
        return nil
    }

    private static func runHandwrittenCppParser(_ symbol: String) -> String? {
        if symbol.hasPrefix("__Z") && symbol.count > 3 {
            var parser = ItaniumCppDemangler(mangled: String(symbol.dropFirst(3)))
            return parser.parseEncodingOrSpecial()
        }
        if symbol.hasPrefix("_Z") && symbol.count > 2 {
            let body = String(symbol.dropFirst(2))
            guard let first = body.first,
                  first.isASCII && (first.isNumber || "NSTGL".contains(first)) else {
                return nil
            }
            var parser = ItaniumCppDemangler(mangled: body)
            return parser.parseEncodingOrSpecial()
        }
        return nil
    }

    private static func isMerelyUnderscoreStripped(raw: String, candidate: String) -> Bool {
        var trimmed = raw
        while trimmed.hasPrefix("_") {
            trimmed.removeFirst()
            if candidate == trimmed {
                return true
            }
        }
        return false
    }

    private static func stripDyldStubSuffix(_ symbol: String) -> String {
        splitSymbolSuffix(symbol).core
    }

    private static func splitSymbolSuffix(_ symbol: String) -> (core: String, suffix: String) {
        for marker in ["$stub", "@PLT", "$shim"] {
            if symbol.hasSuffix(marker) && symbol.count > marker.count {
                let core = String(symbol.dropLast(marker.count))
                return (core, " [stub]")
            }
        }
        return (symbol, "")
    }

    private static func hasSwiftMangledPrefix(_ symbol: String) -> Bool {
        for p in swiftPrefixes where symbol.hasPrefix(p) {
            return true
        }
        return false
    }

    private static func extractSwiftMangledPayload(from symbol: String) -> String? {
        for p in swiftPrefixes {
            if symbol.hasPrefix(p) && symbol.count > p.count {
                return String(symbol.dropFirst(p.count))
            }
        }
        return nil
    }

    private static func isLikelyCppSymbol(_ symbol: String) -> Bool {
        if (symbol.hasPrefix("____Z") && symbol.count > 5) ||
           (symbol.hasPrefix("___Z") && symbol.count > 4) ||
           (symbol.hasPrefix("__Z") && symbol.count > 3) {
            return true
        }
        if symbol.hasPrefix("_Z") && symbol.count > 2 {
            let after = symbol[symbol.index(symbol.startIndex, offsetBy: 2)...]
            if let first = after.first, first.isASCII && (first.isNumber || "NSTGL".contains(first)) {
                return true
            }
        }
        return false
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
                return nil
            }
        }

        guard isAtEnd, stack.count == 1 else { return nil }
        switch stack[0] {
        case .emptyList, .firstElementMarker, .identifier, .module, .genericConstraint, .genericSignature:
            return nil
        case .type(let s) where s == "Void" || s.isEmpty:
            return nil
        default:
            let text = stack[0].displayText
            return text.isEmpty ? nil : text
        }
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
            return false

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
            return false

        case "Z":
            pos += 1
            if let last = stack.popLast() {
                stack.append(.entity("static \(last.displayText)"))
                return true
            }
            return false

        case "X":
            return parseSpecialXEncoding()

        case "B":
            return parseBuiltinType()

        default:
            return false
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
        return false
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
        return false
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
            return false
        }
    }

    private mutating func parseVariableOrAccessor() -> Bool {
        pos += 1 // consume 'v'
        // Check for 'vp' (property), 'vg' (getter), 'vs' (setter), 'vau' (unsafeMutableAddressor), 'vM' (modify)
        if match("g") {
            guard let propTypeNode = stack.popLast(), let propNameNode = stack.popLast() else { return false }
            let propType = propTypeNode.displayText
            let propName = propNameNode.displayText
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).getter : \(propType)"))
            return true
        }
        if match("s") {
            guard let propTypeNode = stack.popLast(), let propNameNode = stack.popLast() else { return false }
            let propType = propTypeNode.displayText
            let propName = propNameNode.displayText
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
            guard let propTypeNode = stack.popLast(), let propNameNode = stack.popLast() else { return false }
            let propType = propTypeNode.displayText
            let propName = propNameNode.displayText
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full).modify : \(propType)"))
            return true
        }
        if match("p") {
            guard let propTypeNode = stack.popLast(), let propNameNode = stack.popLast() else { return false }
            let propType = propTypeNode.displayText
            let propName = propNameNode.displayText
            let ctx = stack.popLast()?.displayText
            let full = ctx != nil ? "\(ctx!).\(propName)" : propName
            stack.append(.entity("\(full) : \(propType)"))
            return true
        }
        return false
    }

    private mutating func parseAddressorEntity() -> Bool {
        guard let valTypeNode = stack.popLast(), let varNameNode = stack.popLast() else { return false }
        let valType = valTypeNode.displayText
        let varName = varNameNode.displayText
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
            guard let proto = stack.popLast() else { return false }
            stack.append(.genericConstraint("T: \(proto.displayText)"))
            return true
        case "s": // Same-type constraint
            guard let rhs = stack.popLast() else { return false }
            stack.append(.genericConstraint("T == \(rhs.displayText)"))
            return true
        case "l": // AnyObject layout constraint
            stack.append(.genericConstraint("T: AnyObject"))
            return true
        default:
            return false
        }
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
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("type metadata accessor for \(target.displayText)"))
            return true
        case "n":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("nominal type descriptor for \(target.displayText)"))
            return true
        case "c":
            // Protocol conformance descriptor: Stack typically has [ConformingType, Protocol, Module]
            let mod = stack.popLast()
            let proto = stack.popLast()
            let conforming = stack.popLast()
            if let c = conforming, let p = proto, let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(c.displayText) : \(p.displayText) in \(m.displayText)"))
                return true
            } else if let p = proto, let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(p.displayText) : \(m.displayText)"))
                return true
            } else if let m = mod {
                stack.append(.entity("protocol conformance descriptor for \(m.displayText)"))
                return true
            }
            return false
        case "p":
            guard let proto = stack.popLast() else { return false }
            stack.append(.entity("protocol descriptor for \(proto.displayText)"))
            return true
        case "f":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("full type metadata for \(target.displayText)"))
            return true
        default:
            return false
        }
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
                return true
            } else if let p = proto, let m = mod {
                stack.append(.entity("protocol witness table for \(p.displayText) : \(m.displayText)"))
                return true
            }
            return false
        default:
            return false
        }
    }

    private mutating func parseThunkOrSpecialization() -> Bool {
        pos += 1 // consume 'T'
        guard let sub = advance() else { return false }
        switch sub {
        case "W":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("protocol witness for \(target.displayText)"))
            return true
        case "j":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("dispatch thunk of \(target.displayText)"))
            return true
        case "q":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("method descriptor for \(target.displayText)"))
            return true
        case "o":
            guard let target = stack.popLast() else { return false }
            stack.append(.entity("@objc \(target.displayText)"))
            return true
        default:
            return false
        }
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
                guard let ty = parseType(), isAtEnd else { return nil }
                return "vtable for \(ty)"
            case "I":
                pos += 2
                guard let ty = parseType(), isAtEnd else { return nil }
                return "typeinfo for \(ty)"
            case "S":
                pos += 2
                guard let ty = parseType(), isAtEnd else { return nil }
                return "typeinfo name for \(ty)"
            case "T":
                pos += 2
                guard let ty = parseType(), isAtEnd else { return nil }
                return "VTT for \(ty)"
            case "h", "v":
                let isVirtual = (peek(1) == "v")
                pos += 2
                while !isAtEnd && advance() != "_" {}
                if isVirtual {
                    while !isAtEnd && peek() != "_" && (peek()?.isNumber == true || peek() == "n") {
                        pos += 1
                    }
                    _ = match("_")
                }
                guard let inner = parseEncoding(), isAtEnd else { return nil }
                return "\(isVirtual ? "virtual" : "non-virtual") thunk to \(inner)"
            default:
                break
            }
        }

        if peek() == "G" && peek(1) == "V" {
            pos += 2
            guard let parsedName = parseName(), isAtEnd else { return nil }
            return "guard variable for \(parsedName.fullName)"
        }

        guard let encoded = parseEncoding(), isAtEnd else { return nil }
        return encoded
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

        // Internal linkage prefix 'L' (e.g. `_ZL15helper_fn...`)
        let hadInternalLinkageL: Bool
        if ch == "L", let next = peek(1), next.isASCII, next.isNumber {
            pos += 1
            hadInternalLinkageL = true
        } else {
            hadInternalLinkageL = false
        }

        // Length-prefixed source identifier
        if let cur = peek(), cur.isASCII && cur.isNumber {
            guard let len = readPositiveDecimal(), len > 0, pos + len <= chars.count else {
                return nil
            }
            let ident = String(chars[pos..<(pos + len)])
            pos += len
            return ident
        }
        if hadInternalLinkageL {
            return nil
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
