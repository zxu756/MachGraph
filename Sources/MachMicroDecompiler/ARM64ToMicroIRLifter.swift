import Foundation
import MachGraphModels
import MachA64Decoder
import MachCFGEngine

// MARK: - Lifter Configuration & Output Models

public struct MicroIRLiftingConfiguration: Sendable, Codable, Hashable {
    public var suppressPrologueEpilogueBoilerplate: Bool
    public var suppressPACInstructions: Bool
    public var synthesizeWideConstants: Bool
    public var resolvePCRelativeStringsAndSymbols: Bool
    public var recoverStackLocalVariables: Bool
    public var recoverABIArgumentCalls: Bool
    public var zeroExtend32BitWrites: Bool

    public init(
        suppressPrologueEpilogueBoilerplate: Bool = true,
        suppressPACInstructions: Bool = true,
        synthesizeWideConstants: Bool = true,
        resolvePCRelativeStringsAndSymbols: Bool = true,
        recoverStackLocalVariables: Bool = true,
        recoverABIArgumentCalls: Bool = true,
        zeroExtend32BitWrites: Bool = true
    ) {
        self.suppressPrologueEpilogueBoilerplate = suppressPrologueEpilogueBoilerplate
        self.suppressPACInstructions = suppressPACInstructions
        self.synthesizeWideConstants = synthesizeWideConstants
        self.resolvePCRelativeStringsAndSymbols = resolvePCRelativeStringsAndSymbols
        self.recoverStackLocalVariables = recoverStackLocalVariables
        self.recoverABIArgumentCalls = recoverABIArgumentCalls
        self.zeroExtend32BitWrites = zeroExtend32BitWrites
    }

    public static let standard = MicroIRLiftingConfiguration()
}

public struct RecoveredStackSlot: Sendable, Codable, Hashable, Identifiable {
    public var id: String { variableName }
    public let variableName: String
    public let frameOffset: Int64
    public let byteSize: Int
    public let inferredType: CTypeExpr
    public let isCalleeSavedSpill: Bool

    public init(
        variableName: String,
        frameOffset: Int64,
        byteSize: Int,
        inferredType: CTypeExpr,
        isCalleeSavedSpill: Bool = false
    ) {
        self.variableName = variableName
        self.frameOffset = frameOffset
        self.byteSize = byteSize
        self.inferredType = inferredType
        self.isCalleeSavedSpill = isCalleeSavedSpill
    }
}

public struct ObjCMethodSignatureContext: Sendable, Codable, Hashable {
    public let className: String
    public let selector: String
    public let isClassMethod: Bool
    public let returnType: CTypeExpr
    public let parameterTypes: [CTypeExpr]
    public let ivarByOffset: [Int64: (name: String, type: CTypeExpr)]

    public init(
        className: String,
        selector: String,
        isClassMethod: Bool,
        returnType: CTypeExpr,
        parameterTypes: [CTypeExpr],
        ivarByOffset: [Int64: (name: String, type: CTypeExpr)] = [:]
    ) {
        self.className = className
        self.selector = selector
        self.isClassMethod = isClassMethod
        self.returnType = returnType
        self.parameterTypes = parameterTypes
        var cleaned: [Int64: (name: String, type: CTypeExpr)] = [:]
        for (k, v) in ivarByOffset {
            cleaned[k] = v
        }
        self.ivarByOffset = cleaned
    }

    private enum CodingKeys: String, CodingKey {
        case className, selector, isClassMethod, returnType, parameterTypes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.className = try c.decode(String.self, forKey: .className)
        self.selector = try c.decode(String.self, forKey: .selector)
        self.isClassMethod = try c.decode(Bool.self, forKey: .isClassMethod)
        self.returnType = try c.decode(CTypeExpr.self, forKey: .returnType)
        self.parameterTypes = try c.decode([CTypeExpr].self, forKey: .parameterTypes)
        self.ivarByOffset = [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(className, forKey: .className)
        try c.encode(selector, forKey: .selector)
        try c.encode(isClassMethod, forKey: .isClassMethod)
        try c.encode(returnType, forKey: .returnType)
        try c.encode(parameterTypes, forKey: .parameterTypes)
    }

    public static func == (lhs: ObjCMethodSignatureContext, rhs: ObjCMethodSignatureContext) -> Bool {
        lhs.className == rhs.className &&
        lhs.selector == rhs.selector &&
        lhs.isClassMethod == rhs.isClassMethod &&
        lhs.returnType == rhs.returnType &&
        lhs.parameterTypes == rhs.parameterTypes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(className)
        hasher.combine(selector)
        hasher.combine(isClassMethod)
        hasher.combine(returnType)
        hasher.combine(parameterTypes)
    }
}

public struct LiftedFunctionIR: Sendable, Codable, Hashable {
    public let functionAddress: VirtualAddress
    public let functionName: String
    public let demangledName: String
    public let microBlocks: [MicroBasicBlock]
    public let stackSlots: [RecoveredStackSlot]
    public let detectedLiveInParameters: [A64Register]
    public let returnsValue: Bool
    public let returnBitWidth: Int
    public let explicitReturnTypeHint: CTypeExpr?
    public let objcContext: ObjCMethodSignatureContext?
    public let prologueAnalysis: A64PrologueEpilogueAnalysis

    public init(
        functionAddress: VirtualAddress,
        functionName: String,
        demangledName: String,
        microBlocks: [MicroBasicBlock],
        stackSlots: [RecoveredStackSlot],
        detectedLiveInParameters: [A64Register],
        returnsValue: Bool,
        returnBitWidth: Int,
        explicitReturnTypeHint: CTypeExpr? = nil,
        objcContext: ObjCMethodSignatureContext? = nil,
        prologueAnalysis: A64PrologueEpilogueAnalysis
    ) {
        self.functionAddress = functionAddress
        self.functionName = functionName
        self.demangledName = demangledName
        self.microBlocks = microBlocks
        self.stackSlots = stackSlots
        self.detectedLiveInParameters = detectedLiveInParameters
        self.returnsValue = returnsValue
        self.returnBitWidth = returnBitWidth
        self.explicitReturnTypeHint = explicitReturnTypeHint
        self.objcContext = objcContext
        self.prologueAnalysis = prologueAnalysis
    }
}

// MARK: - Known Apple / POSIX / C / Runtime Signature Catalog

public struct KnownCalleePrototype: Sendable, Hashable {
    public let cleanName: String
    public let returnType: CTypeExpr
    public let fixedParameterTypes: [CTypeExpr]
    public let isVariadicFormatAtIndex: Int?
    public let isNoReturn: Bool

    public init(
        cleanName: String,
        returnType: CTypeExpr,
        fixedParameterTypes: [CTypeExpr],
        isVariadicFormatAtIndex: Int? = nil,
        isNoReturn: Bool = false
    ) {
        self.cleanName = cleanName
        self.returnType = returnType
        self.fixedParameterTypes = fixedParameterTypes
        self.isVariadicFormatAtIndex = isVariadicFormatAtIndex
        self.isNoReturn = isNoReturn
    }
}

public enum KnownFunctionSignatureCatalog: Sendable {
    public static func normalizeSymbolName(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        for suffix in [" [stub]", "$stub", "@PLT", "$shim"] {
            if s.hasSuffix(suffix) {
                s = String(s.dropLast(suffix.count))
            }
        }
        if s.hasPrefix("imp___stubs__") {
            s = String(s.dropFirst("imp___stubs__".count))
        } else if s.hasPrefix("j__") {
            s = String(s.dropFirst(3))
        } else if s.hasPrefix("_") && !s.hasPrefix("__Z") && !s.hasPrefix("_$s") && !s.hasPrefix("_OBJC_") {
            s.removeFirst()
        }
        return s
    }

    public static func lookup(_ rawName: String) -> KnownCalleePrototype? {
        let clean = normalizeSymbolName(rawName)
        if clean.hasPrefix("objc_msgSend$") {
            let sel = String(clean.dropFirst("objc_msgSend$".count))
            let colonCount = sel.filter { $0 == ":" }.count
            var params: [CTypeExpr] = [.objcObject(className: nil)]
            for _ in 0..<colonCount {
                params.append(.intType(bits: 64, signed: false))
            }
            return KnownCalleePrototype(
                cleanName: clean,
                returnType: .objcObject(className: nil),
                fixedParameterTypes: params
            )
        }
        return table[clean]
    }

    public static func countPrintfFormatSpecifiers(in format: String) -> Int {
        var count = 0
        var idx = format.startIndex
        while idx < format.endIndex {
            let ch = format[idx]
            if ch == "%" {
                let next = format.index(after: idx)
                if next < format.endIndex && format[next] == "%" {
                    idx = format.index(after: next)
                    continue
                }
                count += 1
                var scan = next
                while scan < format.endIndex {
                    let c = format[scan]
                    if c == "*" {
                        count += 1
                    }
                    if "diouxXfFeEgGaAcspn@".contains(c) {
                        scan = format.index(after: scan)
                        break
                    }
                    scan = format.index(after: scan)
                }
                idx = scan
                continue
            }
            idx = format.index(after: idx)
        }
        return count
    }

    public static func parseObjCTypeEncoding(_ encoding: String) -> [CTypeExpr] {
        guard !encoding.isEmpty else { return [] }
        var types: [CTypeExpr] = []
        var idx = encoding.startIndex

        while idx < encoding.endIndex {
            let ch = encoding[idx]
            if ch.isNumber {
                idx = encoding.index(after: idx)
                continue
            }
            switch ch {
            case "v":
                types.append(.voidType)
                idx = encoding.index(after: idx)
            case "B":
                types.append(.boolType)
                idx = encoding.index(after: idx)
            case "c":
                types.append(.intType(bits: 8, signed: true))
                idx = encoding.index(after: idx)
            case "C":
                types.append(.intType(bits: 8, signed: false))
                idx = encoding.index(after: idx)
            case "s":
                types.append(.intType(bits: 16, signed: true))
                idx = encoding.index(after: idx)
            case "S":
                types.append(.intType(bits: 16, signed: false))
                idx = encoding.index(after: idx)
            case "i", "l":
                types.append(.intType(bits: 32, signed: true))
                idx = encoding.index(after: idx)
            case "I", "L":
                types.append(.intType(bits: 32, signed: false))
                idx = encoding.index(after: idx)
            case "q":
                types.append(.intType(bits: 64, signed: true))
                idx = encoding.index(after: idx)
            case "Q":
                types.append(.intType(bits: 64, signed: false))
                idx = encoding.index(after: idx)
            case "f":
                types.append(.floatType(bits: 32))
                idx = encoding.index(after: idx)
            case "d":
                types.append(.floatType(bits: 64))
                idx = encoding.index(after: idx)
            case "*":
                types.append(.cString)
                idx = encoding.index(after: idx)
            case ":":
                types.append(.cString)
                idx = encoding.index(after: idx)
            case "@":
                let afterAt = encoding.index(after: idx)
                if afterAt < encoding.endIndex && encoding[afterAt] == "\"" {
                    let nameStart = encoding.index(after: afterAt)
                    var endQuote = nameStart
                    while endQuote < encoding.endIndex && encoding[endQuote] != "\"" {
                        endQuote = encoding.index(after: endQuote)
                    }
                    let clsName = String(encoding[nameStart..<endQuote])
                    types.append(.objcObject(className: clsName.isEmpty ? nil : clsName))
                    idx = endQuote < encoding.endIndex ? encoding.index(after: endQuote) : endQuote
                } else {
                    types.append(.objcObject(className: nil))
                    idx = afterAt
                }
            case "#":
                types.append(.objcObject(className: nil))
                idx = encoding.index(after: idx)
            case "^":
                types.append(.pointer(to: .voidType))
                idx = encoding.index(after: idx)
                if idx < encoding.endIndex && !encoding[idx].isNumber {
                    idx = encoding.index(after: idx)
                }
            case "r", "n", "N", "o", "O", "R", "V":
                idx = encoding.index(after: idx)
            case "{", "(", "[":
                let closing: Character = (ch == "{") ? "}" : ((ch == "(") ? ")" : "]")
                var depth = 1
                var scan = encoding.index(after: idx)
                while scan < encoding.endIndex && depth > 0 {
                    if encoding[scan] == ch { depth += 1 }
                    else if encoding[scan] == closing { depth -= 1 }
                    scan = encoding.index(after: scan)
                }
                types.append(.pointer(to: .voidType))
                idx = scan
            default:
                idx = encoding.index(after: idx)
            }
        }
        return types
    }

    private static let i32 = CTypeExpr.intType(bits: 32, signed: true)
    private static let u32 = CTypeExpr.intType(bits: 32, signed: false)
    private static let i64 = CTypeExpr.intType(bits: 64, signed: true)
    private static let u64 = CTypeExpr.intType(bits: 64, signed: false)
    private static let voidPtr = CTypeExpr.pointer(to: .voidType)
    private static let cStr = CTypeExpr.cString
    private static let objcId = CTypeExpr.objcObject(className: nil)

    private static let table: [String: KnownCalleePrototype] = [
        // String & memory routines
        "strcmp": .init(cleanName: "strcmp", returnType: i32, fixedParameterTypes: [cStr, cStr]),
        "strncmp": .init(cleanName: "strncmp", returnType: i32, fixedParameterTypes: [cStr, cStr, u64]),
        "strcasecmp": .init(cleanName: "strcasecmp", returnType: i32, fixedParameterTypes: [cStr, cStr]),
        "strncasecmp": .init(cleanName: "strncasecmp", returnType: i32, fixedParameterTypes: [cStr, cStr, u64]),
        "strlen": .init(cleanName: "strlen", returnType: u64, fixedParameterTypes: [cStr]),
        "strnlen": .init(cleanName: "strnlen", returnType: u64, fixedParameterTypes: [cStr, u64]),
        "strcpy": .init(cleanName: "strcpy", returnType: cStr, fixedParameterTypes: [cStr, cStr]),
        "strncpy": .init(cleanName: "strncpy", returnType: cStr, fixedParameterTypes: [cStr, cStr, u64]),
        "strcat": .init(cleanName: "strcat", returnType: cStr, fixedParameterTypes: [cStr, cStr]),
        "strncat": .init(cleanName: "strncat", returnType: cStr, fixedParameterTypes: [cStr, cStr, u64]),
        "strchr": .init(cleanName: "strchr", returnType: cStr, fixedParameterTypes: [cStr, i32]),
        "strrchr": .init(cleanName: "strrchr", returnType: cStr, fixedParameterTypes: [cStr, i32]),
        "strstr": .init(cleanName: "strstr", returnType: cStr, fixedParameterTypes: [cStr, cStr]),
        "strdup": .init(cleanName: "strdup", returnType: cStr, fixedParameterTypes: [cStr]),
        "memcpy": .init(cleanName: "memcpy", returnType: voidPtr, fixedParameterTypes: [voidPtr, voidPtr, u64]),
        "memmove": .init(cleanName: "memmove", returnType: voidPtr, fixedParameterTypes: [voidPtr, voidPtr, u64]),
        "memset": .init(cleanName: "memset", returnType: voidPtr, fixedParameterTypes: [voidPtr, i32, u64]),
        "memcmp": .init(cleanName: "memcmp", returnType: i32, fixedParameterTypes: [voidPtr, voidPtr, u64]),
        "bzero": .init(cleanName: "bzero", returnType: .voidType, fixedParameterTypes: [voidPtr, u64]),
        // Standard I/O & formatting
        "puts": .init(cleanName: "puts", returnType: i32, fixedParameterTypes: [cStr]),
        "putchar": .init(cleanName: "putchar", returnType: i32, fixedParameterTypes: [i32]),
        "printf": .init(cleanName: "printf", returnType: i32, fixedParameterTypes: [cStr], isVariadicFormatAtIndex: 0),
        "fprintf": .init(cleanName: "fprintf", returnType: i32, fixedParameterTypes: [voidPtr, cStr], isVariadicFormatAtIndex: 1),
        "sprintf": .init(cleanName: "sprintf", returnType: i32, fixedParameterTypes: [cStr, cStr], isVariadicFormatAtIndex: 1),
        "snprintf": .init(cleanName: "snprintf", returnType: i32, fixedParameterTypes: [cStr, u64, cStr], isVariadicFormatAtIndex: 2),
        "NSLog": .init(cleanName: "NSLog", returnType: .voidType, fixedParameterTypes: [objcId], isVariadicFormatAtIndex: 0),
        "fopen": .init(cleanName: "fopen", returnType: voidPtr, fixedParameterTypes: [cStr, cStr]),
        "fclose": .init(cleanName: "fclose", returnType: i32, fixedParameterTypes: [voidPtr]),
        "fread": .init(cleanName: "fread", returnType: u64, fixedParameterTypes: [voidPtr, u64, u64, voidPtr]),
        "fwrite": .init(cleanName: "fwrite", returnType: u64, fixedParameterTypes: [voidPtr, u64, u64, voidPtr]),
        // Heap & POSIX
        "malloc": .init(cleanName: "malloc", returnType: voidPtr, fixedParameterTypes: [u64]),
        "calloc": .init(cleanName: "calloc", returnType: voidPtr, fixedParameterTypes: [u64, u64]),
        "realloc": .init(cleanName: "realloc", returnType: voidPtr, fixedParameterTypes: [voidPtr, u64]),
        "free": .init(cleanName: "free", returnType: .voidType, fixedParameterTypes: [voidPtr]),
        "open": .init(cleanName: "open", returnType: i32, fixedParameterTypes: [cStr, i32]),
        "read": .init(cleanName: "read", returnType: i64, fixedParameterTypes: [i32, voidPtr, u64]),
        "write": .init(cleanName: "write", returnType: i64, fixedParameterTypes: [i32, voidPtr, u64]),
        "close": .init(cleanName: "close", returnType: i32, fixedParameterTypes: [i32]),
        "mmap": .init(cleanName: "mmap", returnType: voidPtr, fixedParameterTypes: [voidPtr, u64, i32, i32, i32, i64]),
        "munmap": .init(cleanName: "munmap", returnType: i32, fixedParameterTypes: [voidPtr, u64]),
        "mprotect": .init(cleanName: "mprotect", returnType: i32, fixedParameterTypes: [voidPtr, u64, i32]),
        "dlopen": .init(cleanName: "dlopen", returnType: voidPtr, fixedParameterTypes: [cStr, i32]),
        "dlsym": .init(cleanName: "dlsym", returnType: voidPtr, fixedParameterTypes: [voidPtr, cStr]),
        "getenv": .init(cleanName: "getenv", returnType: cStr, fixedParameterTypes: [cStr]),
        "system": .init(cleanName: "system", returnType: i32, fixedParameterTypes: [cStr]),
        "atoi": .init(cleanName: "atoi", returnType: i32, fixedParameterTypes: [cStr]),
        "atol": .init(cleanName: "atol", returnType: i64, fixedParameterTypes: [cStr]),
        "exit": .init(cleanName: "exit", returnType: .voidType, fixedParameterTypes: [i32], isNoReturn: true),
        "_exit": .init(cleanName: "_exit", returnType: .voidType, fixedParameterTypes: [i32], isNoReturn: true),
        "abort": .init(cleanName: "abort", returnType: .voidType, fixedParameterTypes: [], isNoReturn: true),
        "__stack_chk_fail": .init(cleanName: "__stack_chk_fail", returnType: .voidType, fixedParameterTypes: [], isNoReturn: true),
        // Objective-C & Swift runtime
        "objc_msgSend": .init(cleanName: "objc_msgSend", returnType: objcId, fixedParameterTypes: [objcId, cStr]),
        "objc_msgSendSuper2": .init(cleanName: "objc_msgSendSuper2", returnType: objcId, fixedParameterTypes: [voidPtr, cStr]),
        "objc_retain": .init(cleanName: "objc_retain", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_release": .init(cleanName: "objc_release", returnType: .voidType, fixedParameterTypes: [objcId]),
        "objc_autorelease": .init(cleanName: "objc_autorelease", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_autoreleaseReturnValue": .init(cleanName: "objc_autoreleaseReturnValue", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_retainAutoreleasedReturnValue": .init(cleanName: "objc_retainAutoreleasedReturnValue", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_claimAutoreleasedReturnValue": .init(cleanName: "objc_claimAutoreleasedReturnValue", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_alloc": .init(cleanName: "objc_alloc", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_alloc_init": .init(cleanName: "objc_alloc_init", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_opt_new": .init(cleanName: "objc_opt_new", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_opt_class": .init(cleanName: "objc_opt_class", returnType: objcId, fixedParameterTypes: [objcId]),
        "objc_storeStrong": .init(cleanName: "objc_storeStrong", returnType: .voidType, fixedParameterTypes: [voidPtr, objcId]),
        "swift_bridgeObjectRetain": .init(cleanName: "swift_bridgeObjectRetain", returnType: voidPtr, fixedParameterTypes: [voidPtr]),
        "swift_bridgeObjectRelease": .init(cleanName: "swift_bridgeObjectRelease", returnType: .voidType, fixedParameterTypes: [voidPtr]),
        "swift_retain": .init(cleanName: "swift_retain", returnType: voidPtr, fixedParameterTypes: [voidPtr]),
        "swift_release": .init(cleanName: "swift_release", returnType: .voidType, fixedParameterTypes: [voidPtr]),
        // Common internal demo/utility patterns when symbol-named
        "main": .init(cleanName: "main", returnType: i32, fixedParameterTypes: [i32, .pointer(to: cStr)])
    ]

    internal static let u32Ref = u32
}

// MARK: - Internal Binary Symbol, String, Stub & ObjC Resolution Context

internal struct BinaryLiftingResolutionContext: Sendable {
    let image: LoadedBinaryImage?
    let analysisIndex: BinaryAnalysisIndex?
    let symbolOverrides: [VirtualAddress: String]

    private let stringsByExactAddress: [VirtualAddress: ExtractedStringLiteral]
    private let sortedStrings: [ExtractedStringLiteral]
    private let symbolsByAddress: [VirtualAddress: String]
    private let fixupSymbolsByAddress: [VirtualAddress: String]
    private let fixupTargetsByAddress: [VirtualAddress: VirtualAddress]
    private let importCallBySite: [VirtualAddress: String]
    private let stubTargetSymbolByEntry: [VirtualAddress: String]
    private let calleeLiveInArityByAddress: [VirtualAddress: Int]
    private let calleeReturnsValueByAddress: [VirtualAddress: (returns: Bool, returnType: CTypeExpr)]
    private let objcMethodByIMP: [VirtualAddress: ObjCMethodSignatureContext]
    private let objcClassNameByAddress: [VirtualAddress: String]

    init(
        image: LoadedBinaryImage?,
        analysisIndex: BinaryAnalysisIndex?,
        symbolOverrides: [VirtualAddress: String]
    ) {
        let effectiveImage = image ?? analysisIndex?.image
        self.image = effectiveImage
        self.analysisIndex = analysisIndex
        self.symbolOverrides = symbolOverrides

        let demangler = SymbolDemangler()

        // 1. Index strings (exact + sorted interior range lookup)
        var exactStr: [VirtualAddress: ExtractedStringLiteral] = [:]
        var allStrs: [ExtractedStringLiteral] = []
        if let img = effectiveImage {
            allStrs = img.strings.sorted { $0.address < $1.address }
            for lit in allStrs {
                exactStr[lit.address] = lit
            }
        }
        self.stringsByExactAddress = exactStr
        self.sortedStrings = allStrs

        // 2. Index fixups (GOT binds & rebases)
        var fixSym: [VirtualAddress: String] = [:]
        var fixTgt: [VirtualAddress: VirtualAddress] = [:]
        if let img = effectiveImage {
            for rec in img.chainedFixups {
                if let s = rec.symbolName, !s.isEmpty {
                    fixSym[rec.location] = KnownFunctionSignatureCatalog.normalizeSymbolName(demangler.demangle(s))
                }
                if let t = rec.targetAddress, t != .zero {
                    fixTgt[rec.location] = t
                }
            }
        }
        self.fixupSymbolsByAddress = fixSym
        self.fixupTargetsByAddress = fixTgt

        // 3. Index symbols & ObjC class symbols
        var symMap: [VirtualAddress: String] = [:]
        var clsByAddr: [VirtualAddress: String] = [:]
        if let img = effectiveImage {
            for sym in img.symbols where sym.address != .zero {
                if sym.name.hasPrefix("_OBJC_CLASS_$_") {
                    let cls = String(sym.name.dropFirst("_OBJC_CLASS_$_".count))
                    clsByAddr[sym.address] = cls
                    symMap[sym.address] = cls
                } else {
                    let clean = KnownFunctionSignatureCatalog.normalizeSymbolName(
                        sym.demangledName.isEmpty ? demangler.demangle(sym.name) : sym.demangledName
                    )
                    if symMap[sym.address] == nil || sym.kind == .function || sym.kind == .exportedEntry || sym.kind == .objcMethod {
                        symMap[sym.address] = clean
                    }
                }
            }
            for cls in img.objcClasses {
                clsByAddr[cls.address] = cls.name
                if symMap[cls.address] == nil {
                    symMap[cls.address] = cls.name
                }
            }
        }

        // 4. Index ObjC method implementations & ivars
        var objcByIMP: [VirtualAddress: ObjCMethodSignatureContext] = [:]
        if let img = effectiveImage {
            for cls in img.objcClasses {
                var ivarMap: [Int64: (name: String, type: CTypeExpr)] = [:]
                for ivar in cls.ivars {
                    let parsedTypes = KnownFunctionSignatureCatalog.parseObjCTypeEncoding(ivar.typeEncoding)
                    let ivarType = parsedTypes.first ?? .intType(bits: max(8, Int(ivar.size) * 8), signed: false)
                    ivarMap[Int64(ivar.offset)] = (ivar.name, ivarType)
                }
                for method in cls.methods where method.implementationAddress != .zero {
                    let decodedSig = KnownFunctionSignatureCatalog.parseObjCTypeEncoding(method.typeEncoding)
                    var retType: CTypeExpr = decodedSig.first ?? .objcObject(className: nil)
                    if method.isClassMethod &&
                       (method.selector.hasPrefix("shared") || method.selector == "alloc" || method.selector == "new"),
                       case .objcObject(nil) = retType {
                        retType = .objcObject(className: cls.name)
                    }
                    let colonCount = method.selector.filter { $0 == ":" }.count
                    var paramTypes: [CTypeExpr] = [
                        method.isClassMethod ? .objcObject(className: nil) : .objcObject(className: cls.name),
                        .cString
                    ]
                    for idx in 0..<colonCount {
                        let encodedIdx = 3 + idx
                        if encodedIdx < decodedSig.count {
                            paramTypes.append(decodedSig[encodedIdx])
                        } else {
                            paramTypes.append(.objcObject(className: nil))
                        }
                    }
                    objcByIMP[method.implementationAddress] = ObjCMethodSignatureContext(
                        className: cls.name,
                        selector: method.selector,
                        isClassMethod: method.isClassMethod,
                        returnType: retType,
                        parameterTypes: paramTypes,
                        ivarByOffset: ivarMap
                    )
                }
            }
        }
        self.objcMethodByIMP = objcByIMP
        self.objcClassNameByAddress = clsByAddr

        // 5. Index import call sites & stub thunks + internal callee arities
        var impBySite: [VirtualAddress: String] = [:]
        var stubByEntry: [VirtualAddress: String] = [:]
        var arityMap: [VirtualAddress: Int] = [:]
        var retMap: [VirtualAddress: (returns: Bool, returnType: CTypeExpr)] = [:]

        if let idx = analysisIndex {
            for site in idx.crossReferences.importCallSites {
                let clean = KnownFunctionSignatureCatalog.normalizeSymbolName(site.demangledSymbolName)
                impBySite[site.callInstructionAddress] = clean
                stubByEntry[site.stubOrGOTAddress] = clean
            }
            for fn in idx.functions {
                if symMap[fn.address] == nil {
                    symMap[fn.address] = KnownFunctionSignatureCatalog.normalizeSymbolName(fn.demangledName)
                }
                // Check if stub thunk `ADRP x16, page; LDR x16, [x16, #off]; BR x16`
                let flatInsns = fn.blocks.flatMap(\.instructions)
                if flatInsns.count <= 4,
                   let stubIdiom = A64IdiomRecognizer().recognizeIdioms(in: flatInsns).first(where: { $0.kind == .dyldImportStub }),
                   let gotAddr = stubIdiom.targetAddress,
                   let gotSym = fixSym[gotAddr] ?? symMap[gotAddr] {
                    stubByEntry[fn.address] = gotSym
                } else if fn.isThunk && (fn.name.contains("$stub") || fn.demangledName.contains("[stub]")) {
                    stubByEntry[fn.address] = KnownFunctionSignatureCatalog.normalizeSymbolName(fn.demangledName)
                }

                // Compute live-in GP parameter arity for internal non-thunk functions
                if !fn.isThunk {
                    if let objcSig = objcByIMP[fn.address] {
                        arityMap[fn.address] = objcSig.parameterTypes.count
                        retMap[fn.address] = (objcSig.returnType != .voidType, objcSig.returnType)
                    } else {
                        let liveIn = Self.computeLiveInGPArgumentCount(for: fn)
                        arityMap[fn.address] = liveIn
                        let retInfo = Self.detectReturnBehavior(for: fn)
                        retMap[fn.address] = retInfo
                    }
                }
            }
        }

        // Apply explicit analyst symbol renames with top priority
        for (addr, customName) in symbolOverrides where !customName.isEmpty {
            symMap[addr] = customName
            if stubByEntry[addr] != nil {
                stubByEntry[addr] = customName
            }
        }

        self.symbolsByAddress = symMap
        self.importCallBySite = impBySite
        self.stubTargetSymbolByEntry = stubByEntry
        self.calleeLiveInArityByAddress = arityMap
        self.calleeReturnsValueByAddress = retMap
    }

    func resolveString(at address: VirtualAddress) -> String? {
        if let exact = stringsByExactAddress[address] {
            return exact.value
        }
        // Check if `address` points at a pointer slot (e.g. `__objc_selrefs` or `__const`) rebased to a string!
        if let rebased = fixupTargetsByAddress[address], let str = stringsByExactAddress[rebased] {
            return str.value
        }
        // Check interior C-string offset within `sortedStrings`
        for lit in sortedStrings where lit.encoding == .ascii || lit.encoding == .utf8 || lit.encoding == .objcSelector {
            let start = lit.address.rawValue
            let end = start &+ UInt64(max(0, lit.lengthBytes))
            if address.rawValue > start && address.rawValue < end {
                let byteDelta = Int(address.rawValue - start)
                let utf8 = Array(lit.value.utf8)
                if byteDelta < utf8.count {
                    return String(decoding: utf8[byteDelta...], as: UTF8.self)
                }
            }
        }
        return nil
    }

    func resolveSymbol(at address: VirtualAddress) -> String? {
        if let custom = symbolOverrides[address], !custom.isEmpty {
            return custom
        }
        if let stub = stubTargetSymbolByEntry[address] {
            return stub
        }
        if let fix = fixupSymbolsByAddress[address] {
            return fix
        }
        if let sym = symbolsByAddress[address] {
            return sym
        }
        if let rebased = fixupTargetsByAddress[address] {
            if let cls = objcClassNameByAddress[rebased] {
                return cls
            }
            if let sym = symbolsByAddress[rebased] {
                return sym
            }
        }
        return nil
    }

    func resolveGOTLoadSymbolOrString(at gotOrDataAddress: VirtualAddress) -> MicroExpr {
        if let custom = symbolOverrides[gotOrDataAddress], !custom.isEmpty {
            return .symbolRef(name: custom, address: gotOrDataAddress)
        }
        if let selectorOrStr = resolveString(at: gotOrDataAddress) {
            return .stringLiteral(selectorOrStr, address: gotOrDataAddress)
        }
        if let fixSym = fixupSymbolsByAddress[gotOrDataAddress] {
            return .symbolRef(name: fixSym, address: gotOrDataAddress)
        }
        if let rebased = fixupTargetsByAddress[gotOrDataAddress] {
            if let cls = objcClassNameByAddress[rebased] {
                return .symbolRef(name: cls, address: rebased)
            }
            if let str = resolveString(at: rebased) {
                return .stringLiteral(str, address: rebased)
            }
            if let sym = symbolsByAddress[rebased] {
                return .symbolRef(name: sym, address: rebased)
            }
        }
        if let cls = objcClassNameByAddress[gotOrDataAddress] {
            return .symbolRef(name: cls, address: gotOrDataAddress)
        }
        if let sym = symbolsByAddress[gotOrDataAddress] {
            return .load(
                address: .symbolRef(name: sym, address: gotOrDataAddress),
                bits: 64,
                type: .intType(bits: 64, signed: false)
            )
        }
        let globalName = "g_data_\(String(gotOrDataAddress.rawValue, radix: 16))"
        return .symbolRef(name: globalName, address: gotOrDataAddress)
    }

    func resolveCallTargetName(callSite: VirtualAddress, targetAddress: VirtualAddress) -> String {
        if let override = symbolOverrides[targetAddress], !override.isEmpty {
            return override
        }
        if let impSite = importCallBySite[callSite] {
            return impSite
        }
        if let stubSym = stubTargetSymbolByEntry[targetAddress] {
            return stubSym
        }
        if let sym = symbolsByAddress[targetAddress] {
            return sym
        }
        // Heuristic: if `image` has `__stubs` section and `chainedFixups`, match stub slot index -> GOT slot!
        if let img = image,
           let stubSec = img.sections.first(where: { $0.kind == .stubs && $0.addressRange.contains(targetAddress) }) {
            let slotStride: UInt64 = 12
            let stubIndex = Int((targetAddress.rawValue - stubSec.vmAddress.rawValue) / slotStride)
            if let gotSec = img.sections.first(where: { $0.kind == .got || $0.sectionName == "__got" }) {
                let candidateGOTAddr = gotSec.vmAddress.adding(UInt64(stubIndex * 8))
                if let gotSym = fixupSymbolsByAddress[candidateGOTAddr] ?? symbolsByAddress[candidateGOTAddr] {
                    return gotSym
                }
            }
        }
        return "sub_\(String(targetAddress.rawValue, radix: 16))"
    }

    func objcContext(for functionAddress: VirtualAddress) -> ObjCMethodSignatureContext? {
        objcMethodByIMP[functionAddress]
    }

    func calleeArity(for targetAddress: VirtualAddress) -> Int? {
        calleeLiveInArityByAddress[targetAddress]
    }

    func calleeReturnInfo(for targetAddress: VirtualAddress) -> (returns: Bool, returnType: CTypeExpr)? {
        calleeReturnsValueByAddress[targetAddress]
    }

    // MARK: - Lightweight Intra-Procedural GP Parameter & Return Pre-Scanners

    static func computeLiveInGPArgumentCount(for function: RecoveredFunction) -> Int {
        guard !function.blocks.isEmpty else { return 0 }
        let sortedInsns = function.blocks.flatMap(\.instructions).sorted { $0.address < $1.address }
        let prologue = A64IdiomRecognizer().analyzePrologueAndEpilogue(in: sortedInsns)
        let skippedAddrs = Set(prologue.prologueAddresses).union(prologue.epilogueAddresses)

        var genByBlock: [Int: Set<UInt8>] = [:]
        var killByBlock: [Int: Set<UInt8>] = [:]

        for block in function.blocks {
            var gen = Set<UInt8>()
            var kill = Set<UInt8>()
            for insn in block.instructions where !skippedAddrs.contains(insn.address) {
                for r in insn.readsRegisters where (r.bank == .gp64 || r.bank == .gp32) && r.index < 8 {
                    if !kill.contains(r.index) {
                        gen.insert(r.index)
                    }
                }
                for w in insn.writesRegisters where (w.bank == .gp64 || w.bank == .gp32) && w.index < 8 {
                    kill.insert(w.index)
                }
                switch insn.flow {
                case .directCall, .indirectCall:
                    // Calls clobber volatile registers x0..x7 after reading arguments
                    for idx: UInt8 in 0..<8 {
                        kill.insert(idx)
                    }
                default:
                    break
                }
            }
            genByBlock[block.id] = gen
            killByBlock[block.id] = kill
        }

        var liveIn: [Int: Set<UInt8>] = [:]
        for b in function.blocks { liveIn[b.id] = genByBlock[b.id] ?? [] }

        var changed = true
        var guardIter = 0
        while changed && guardIter < 32 {
            changed = false
            guardIter += 1
            for b in function.blocks.reversed() {
                var liveOut = Set<UInt8>()
                for succ in b.successorIDs {
                    liveOut.formUnion(liveIn[succ] ?? [])
                }
                let updated = (genByBlock[b.id] ?? []).union(liveOut.subtracting(killByBlock[b.id] ?? []))
                if updated != liveIn[b.id] {
                    liveIn[b.id] = updated
                    changed = true
                }
            }
        }

        let entryID = function.blocks.first(where: \.isEntry)?.id ?? function.blocks[0].id
        let entryLive = liveIn[entryID] ?? []
        guard let maxIdx = entryLive.max() else { return 0 }
        return Int(maxIdx) + 1
    }

    static func detectReturnBehavior(for function: RecoveredFunction) -> (returns: Bool, returnType: CTypeExpr) {
        let cleanName = KnownFunctionSignatureCatalog.normalizeSymbolName(function.demangledName)
        if let proto = KnownFunctionSignatureCatalog.lookup(cleanName) {
            return (proto.returnType != .voidType, proto.returnType)
        }

        let sortedInsns = function.blocks.flatMap(\.instructions).sorted { $0.address < $1.address }
        let prologue = A64IdiomRecognizer().analyzePrologueAndEpilogue(in: sortedInsns)
        let skipped = Set(prologue.prologueAddresses).union(prologue.epilogueAddresses)

        var writesX0Width: Int? = nil
        var writesCSetBool = false

        for block in function.blocks {
            for insn in block.instructions where !skipped.contains(insn.address) {
                if insn.mnemonic == .cset,
                   let first = insn.operands.first,
                   case .register(let r) = first,
                   (r.bank == .gp64 || r.bank == .gp32) && r.index == 0 {
                    writesCSetBool = true
                    writesX0Width = 32
                }
                for w in insn.writesRegisters where (w.bank == .gp64 || w.bank == .gp32) && w.index == 0 {
                    writesX0Width = w.bitWidth
                }
                switch insn.flow {
                case .directCall, .indirectCall:
                    if writesX0Width == nil {
                        writesX0Width = 64
                    }
                default:
                    break
                }
            }
        }

        if writesCSetBool {
            return (true, .boolType)
        }
        if let width = writesX0Width {
            return (true, .intType(bits: width, signed: false))
        }
        return (false, .voidType)
    }
}

// MARK: - Condition Flag Comparison State (Eliminates Raw NZCV Bit Soup)

private enum FlagComparisonKind: Sendable {
    case subtract
    case bitwiseTest
    case floatingPoint
}

private struct TrackedFlagComparison: Sendable {
    let lhs: MicroExpr
    let rhs: MicroExpr
    let bitWidth: Int
    let kind: FlagComparisonKind
    let compoundPrefix: (op: MicroBinaryOp, priorExpr: MicroExpr)?
}

// MARK: - Primary ARM64 -> Micro-IR Lifter

public struct ARM64ToMicroIRLifter: Sendable {
    public let configuration: MicroIRLiftingConfiguration
    private let idiomRecognizer: A64IdiomRecognizer

    public init(configuration: MicroIRLiftingConfiguration = .standard) {
        self.configuration = configuration
        self.idiomRecognizer = A64IdiomRecognizer()
    }

    /// Convenience wrapper returning `[MicroBasicBlock]` directly.
    public func liftToBlocks(
        function: RecoveredFunction,
        image: LoadedBinaryImage? = nil,
        analysisIndex: BinaryAnalysisIndex? = nil,
        recognizedIdioms: [A64RecognizedIdiom] = [],
        symbolOverrides: [VirtualAddress: String] = [:]
    ) -> [MicroBasicBlock] {
        lift(
            function: function,
            image: image,
            analysisIndex: analysisIndex,
            recognizedIdioms: recognizedIdioms,
            symbolOverrides: symbolOverrides
        ).microBlocks
    }

    /// Lifts an ARM64 `RecoveredFunction` into high-level Micro-IR basic blocks ready for Cytron SSA construction.
    public func lift(
        function: RecoveredFunction,
        image: LoadedBinaryImage? = nil,
        analysisIndex: BinaryAnalysisIndex? = nil,
        recognizedIdioms: [A64RecognizedIdiom] = [],
        symbolOverrides: [VirtualAddress: String] = [:]
    ) -> LiftedFunctionIR {
        let resolver = BinaryLiftingResolutionContext(
            image: image,
            analysisIndex: analysisIndex,
            symbolOverrides: symbolOverrides
        )

        let allInsns = function.blocks.flatMap(\.instructions).sorted { $0.address < $1.address }
        let prologueInfo = idiomRecognizer.analyzePrologueAndEpilogue(in: allInsns)

        // Handle concise dyld import stub thunks cleanly (`ADRP x16; LDR x16; BR x16`)
        if function.isThunk,
           allInsns.count <= 4,
           let stubTargetName = resolver.resolveSymbol(at: function.address) {
            let cleanStub = KnownFunctionSignatureCatalog.normalizeSymbolName(stubTargetName)
            let proto = KnownFunctionSignatureCatalog.lookup(cleanStub)
            let paramCount = proto?.fixedParameterTypes.count ?? 2
            var stubArgs: [MicroExpr] = []
            var liveRegs: [A64Register] = []
            for idx in 0..<min(paramCount, 8) {
                let reg = A64Register.x(UInt8(idx))
                liveRegs.append(reg)
                let pType = (proto != nil && idx < proto!.fixedParameterTypes.count)
                    ? proto!.fixedParameterTypes[idx]
                    : .intType(bits: 64, signed: false)
                stubArgs.append(.variable(SSAVar(baseName: "x\(idx)", version: 0, bitWidth: 64, inferredType: pType)))
            }
            let retType = proto?.returnType ?? .intType(bits: 64, signed: false)
            let callExpr = MicroExpr.call(
                target: .symbolRef(name: cleanStub, address: function.address),
                arguments: stubArgs,
                returnType: retType
            )
            let stmt: MicroStmt
            if retType == .voidType {
                stmt = MicroStmt(
                    originAddress: function.address,
                    kind: .callStmt(target: .symbolRef(name: cleanStub, address: function.address), arguments: stubArgs)
                )
            } else {
                stmt = MicroStmt(originAddress: function.address, kind: .returnStmt(value: callExpr))
            }
            var stmts = [stmt]
            if retType == .voidType {
                stmts.append(MicroStmt(originAddress: function.address, kind: .returnStmt(value: nil)))
            }
            let soleBlock = MicroBasicBlock(blockID: 0, startAddress: function.address, statements: stmts)
            return LiftedFunctionIR(
                functionAddress: function.address,
                functionName: symbolOverrides[function.address] ?? function.name,
                demangledName: symbolOverrides[function.address] ?? function.demangledName,
                microBlocks: [soleBlock],
                stackSlots: [],
                detectedLiveInParameters: liveRegs,
                returnsValue: retType != .voidType,
                returnBitWidth: 64,
                explicitReturnTypeHint: retType,
                objcContext: nil,
                prologueAnalysis: prologueInfo
            )
        }

        let objcCtx = resolver.objcContext(for: function.address)
        let suppressedSet = buildSuppressedBoilerplateSet(
            function: function,
            prologueInfo: prologueInfo
        )

        // Build per-block multi-instruction idiom tables
        let blockIdiomsByCompleting = buildIdiomIndex(
            for: function,
            extraIdioms: recognizedIdioms,
            resolver: resolver
        )

        // Identify switch jump-table dispatch blocks, selector registers & guard default blocks
        let switchPlansByBlock = buildSwitchDispatchPlans(for: function)

        // Precompute block-level GP register liveness (for accurate call argument arity & x0 return capture)
        let liveness = computeRegisterLiveness(
            for: function,
            suppressedAddresses: suppressedSet,
            objcContext: objcCtx
        )

        let returnBehavior = determineFunctionReturnBehavior(
            function: function,
            objcContext: objcCtx,
            suppressedAddresses: suppressedSet
        )

        // Mutable tracker for recovered stack local slots
        var recoveredStackSlotsByName: [String: RecoveredStackSlot] = [:]
        var outgoingFlagsByBlock: [Int: TrackedFlagComparison] = [:]

        // Process blocks in Reverse Post-Order so predecessor flag states flow cleanly to successor blocks
        let orderedBlocks = orderBlocksRPO(function: function)
        var liftedByID: [Int: MicroBasicBlock] = [:]

        for block in orderedBlocks {
            var incomingFlags: TrackedFlagComparison? = nil
            for predID in block.predecessorIDs {
                if let predFlag = outgoingFlagsByBlock[predID] {
                    incomingFlags = predFlag
                    break
                }
            }

            let lifted = liftBasicBlock(
                block: block,
                function: function,
                prologueInfo: prologueInfo,
                suppressedSet: suppressedSet,
                idiomsByCompleting: blockIdiomsByCompleting.byCompleting,
                consumedIntermediateAddresses: blockIdiomsByCompleting.consumedIntermediates,
                switchPlan: switchPlansByBlock[block.id],
                liveness: liveness,
                returnsValue: returnBehavior.returnsValue,
                returnBitWidth: returnBehavior.bitWidth,
                objcContext: objcCtx,
                resolver: resolver,
                incomingFlags: incomingFlags,
                stackSlotsByName: &recoveredStackSlotsByName,
                outgoingFlagsOut: &outgoingFlagsByBlock[block.id]
            )
            liftedByID[block.id] = lifted
        }

        // Preserve original `function.blocks` array order
        let finalMicroBlocks = function.blocks.compactMap { liftedByID[$0.id] }
        let sortedStackSlots = recoveredStackSlotsByName.values.sorted { $0.frameOffset < $1.frameOffset }

        return LiftedFunctionIR(
            functionAddress: function.address,
            functionName: symbolOverrides[function.address] ?? function.name,
            demangledName: symbolOverrides[function.address] ?? function.demangledName,
            microBlocks: finalMicroBlocks,
            stackSlots: sortedStackSlots,
            detectedLiveInParameters: liveness.liveInParameterRegisters,
            returnsValue: returnBehavior.returnsValue,
            returnBitWidth: returnBehavior.bitWidth,
            explicitReturnTypeHint: returnBehavior.explicitTypeHint,
            objcContext: objcCtx,
            prologueAnalysis: prologueInfo
        )
    }

    // MARK: - Prologue / Epilogue Suppression & Idiom Indexing

    private func buildSuppressedBoilerplateSet(
        function: RecoveredFunction,
        prologueInfo: A64PrologueEpilogueAnalysis
    ) -> Set<VirtualAddress> {
        var suppressed = Set<VirtualAddress>()

        if configuration.suppressPACInstructions {
            for b in function.blocks {
                for insn in b.instructions {
                    switch insn.mnemonic {
                    case .paciasp, .pacibsp, .autiasp, .autibsp, .bti, .nop, .hint:
                        suppressed.insert(insn.address)
                    default:
                        break
                    }
                }
            }
        }

        guard configuration.suppressPrologueEpilogueBoilerplate else {
            return suppressed
        }

        let savedRegIndices = Set(prologueInfo.savedRegisters.map { "\($0.register.bank.rawValue):\($0.register.index)" })

        for addr in prologueInfo.prologueAddresses {
            suppressed.insert(addr)
        }

        for addr in prologueInfo.epilogueAddresses {
            // Do NOT suppress `ret` / `retaa` / `retab` themselves — they emit `.returnStmt`!
            if let insn = function.blocks.lazy.flatMap(\.instructions).first(where: { $0.address == addr }) {
                if case .returnControl = insn.flow {
                    continue
                }
                // Verify single `ldr x19, [sp, #off]` in epilogue actually corresponds to a prologue-saved register
                if insn.mnemonic == .ldr,
                   let first = insn.operands.first,
                   case .register(let r) = first {
                    let key = "\(r.bank.rawValue):\(r.index)"
                    if !savedRegIndices.isEmpty && !savedRegIndices.contains(key) && r.index != 29 && r.index != 30 {
                        continue
                    }
                }
                suppressed.insert(addr)
            }
        }

        return suppressed
    }

    private func buildIdiomIndex(
        for function: RecoveredFunction,
        extraIdioms: [A64RecognizedIdiom],
        resolver: BinaryLiftingResolutionContext
    ) -> (
        byCompleting: [VirtualAddress: A64RecognizedIdiom],
        consumedIntermediates: Set<VirtualAddress>
    ) {
        var byCompleting: [VirtualAddress: A64RecognizedIdiom] = [:]
        var consumed = Set<VirtualAddress>()

        let lookupClosure: @Sendable (VirtualAddress) -> String? = { addr in
            resolver.resolveSymbol(at: addr)
        }

        for block in function.blocks {
            let localIdioms = idiomRecognizer.recognizeIdioms(
                in: block.instructions,
                symbolLookup: lookupClosure
            )
            for idiom in localIdioms {
                byCompleting[idiom.completingAddress] = idiom
            }
        }
        for idiom in extraIdioms where idiom.completingAddress >= function.address && idiom.completingAddress < function.endAddress {
            if byCompleting[idiom.completingAddress] == nil {
                byCompleting[idiom.completingAddress] = idiom
            }
        }

        // Only mark intermediate `ADRP` or `MOVZ`/`MOVK` instructions as consumed if their destination register
        // is not independently read after the idiom completes within the same block (or live-out).
        for block in function.blocks {
            let addrToIdx = Dictionary(uniqueKeysWithValues: block.instructions.enumerated().map { ($1.address, $0) })
            for insn in block.instructions {
                guard let idiom = byCompleting[insn.address] else { continue }
                switch idiom.kind {
                case .movWideConstant where configuration.synthesizeWideConstants:
                    for stepAddr in idiom.instructionAddresses where stepAddr != idiom.completingAddress {
                        consumed.insert(stepAddr)
                    }

                case .adrpAddAddress, .adrpLoadPointer, .adrpStoreData:
                    guard configuration.resolvePCRelativeStringsAndSymbols else { break }
                    let adrpAddr = idiom.startAddress
                    guard adrpAddr != idiom.completingAddress,
                          let adrpIdx = addrToIdx[adrpAddr],
                          let compIdx = addrToIdx[idiom.completingAddress],
                          case .register(let pageReg) = block.instructions[adrpIdx].operands.first
                    else { break }

                    // Ensure `pageReg` isn't reused by a SECOND `add`/`ldr` later in the same block before overwrite
                    var reusedLater = false
                    if compIdx + 1 < block.instructions.count {
                        for laterIdx in (compIdx + 1)..<block.instructions.count {
                            let later = block.instructions[laterIdx]
                            if byCompleting[later.address]?.startAddress == adrpAddr {
                                reusedLater = true
                                break
                            }
                            if later.readsRegisters.contains(where: { $0.isGeneralPurpose && $0.index == pageReg.index }) {
                                reusedLater = true
                                break
                            }
                            if later.writesRegisters.contains(where: { $0.isGeneralPurpose && $0.index == pageReg.index }) {
                                break
                            }
                        }
                    }
                    if !reusedLater {
                        consumed.insert(adrpAddr)
                    }

                default:
                    break
                }
            }
        }

        return (byCompleting, consumed)
    }

    // MARK: - Switch Jump Table Dispatch Plan Recovery

    private struct SwitchDispatchPlan: Sendable {
        let selectorRegister: A64Register
        let selectorBias: Int64
        let cases: [SwitchCaseTarget]
        let defaultBlockID: Int
        let suppressedSetupAddresses: Set<VirtualAddress>
    }

    private func buildSwitchDispatchPlans(for function: RecoveredFunction) -> [Int: SwitchDispatchPlan] {
        guard !function.jumpTables.isEmpty else { return [:] }

        var blockByStart: [VirtualAddress: Int] = [:]
        var blockByID: [Int: BasicBlock] = [:]
        for b in function.blocks {
            blockByStart[b.startAddress] = b.id
            blockByID[b.id] = b
        }

        var outgoingBySource: [Int: [CFGEdge]] = [:]
        for e in function.edges {
            outgoingBySource[e.sourceBlockID, default: []].append(e)
        }

        var plans: [Int: SwitchDispatchPlan] = [:]

        for jt in function.jumpTables {
            guard let dispatchBlock = function.blocks.first(where: {
                $0.instructions.last?.address == jt.dispatchInstructionAddress
            }) else {
                continue
            }

            var suppressedSetup = Set<VirtualAddress>()
            suppressedSetup.insert(jt.dispatchInstructionAddress)

            // Locate index register from `ldrsw/ldrb/ldrh/ldr xOff, [xTable, wIdx, uxtw #s]`
            var selectorReg = A64Register.w(0)
            var selectorBias: Int64 = 0

            let insns = dispatchBlock.instructions
            for (idx, insn) in insns.enumerated().reversed() where insn.address != jt.dispatchInstructionAddress {
                if insn.mnemonic == .adr,
                   let second = insn.operands.dropFirst().first,
                   case .branchTarget(let tgt) = second,
                   tgt == jt.tableBaseAddress {
                    suppressedSetup.insert(insn.address)
                    continue
                }
                if insn.mnemonic == .add && idx == insns.count - 2 {
                    suppressedSetup.insert(insn.address)
                    continue
                }
                if insn.group == .loadStore,
                   insn.operands.count >= 2,
                   case .memory(.registerOffset(_, let indexReg, _)) = insn.operands[1] {
                    selectorReg = indexReg
                    suppressedSetup.insert(insn.address)
                    continue
                }
            }

            // Inspect immediate guard predecessor (`cmp w0, #max; b.hi defaultBlock`) for `defaultBlockID`
            var resolvedDefaultBlockID = -1
            if dispatchBlock.predecessorIDs.count == 1,
               let guardPredID = dispatchBlock.predecessorIDs.first,
               let guardEdges = outgoingBySource[guardPredID],
               guardEdges.count == 2 {
                if let otherEdge = guardEdges.first(where: { $0.targetBlockID != dispatchBlock.id }) {
                    resolvedDefaultBlockID = otherEdge.targetBlockID
                }
                // Also check if guard predecessor biased the index (`sub w8, w0, #minVal`)
                if let guardBlock = blockByID[guardPredID] {
                    for gInsn in guardBlock.instructions where gInsn.mnemonic == .sub && gInsn.operands.count == 3 {
                        if case .register(let dst) = gInsn.operands[0],
                           dst.index == selectorReg.index,
                           case .register(let origReg) = gInsn.operands[1],
                           let imm = Self.extractImmediateInt64(gInsn.operands[2]) {
                            selectorReg = origReg
                            selectorBias = imm
                        }
                    }
                }
            }

            var switchCases: [SwitchCaseTarget] = []
            for (rawIdx, targetAddr) in jt.targetAddresses.enumerated() {
                if let targetBlockID = blockByStart[targetAddr] {
                    let caseVal = Int64(rawIdx) + selectorBias
                    if targetBlockID != resolvedDefaultBlockID {
                        switchCases.append(SwitchCaseTarget(caseValue: caseVal, targetBlockID: targetBlockID))
                    }
                }
            }

            if resolvedDefaultBlockID < 0 {
                resolvedDefaultBlockID = switchCases.last?.targetBlockID ?? dispatchBlock.id
            }

            plans[dispatchBlock.id] = SwitchDispatchPlan(
                selectorRegister: selectorReg,
                selectorBias: 0,
                cases: switchCases,
                defaultBlockID: resolvedDefaultBlockID,
                suppressedSetupAddresses: suppressedSetup
            )
        }

        return plans
    }

    // MARK: - Intra-Procedural Register Liveness Analysis

    private struct FunctionRegisterLiveness: Sendable {
        let liveInByBlock: [Int: Set<UInt8>]
        let liveOutByBlock: [Int: Set<UInt8>]
        let liveInParameterRegisters: [A64Register]
    }

    private func computeRegisterLiveness(
        for function: RecoveredFunction,
        suppressedAddresses: Set<VirtualAddress>,
        objcContext: ObjCMethodSignatureContext?
    ) -> FunctionRegisterLiveness {
        guard !function.blocks.isEmpty else {
            return FunctionRegisterLiveness(liveInByBlock: [:], liveOutByBlock: [:], liveInParameterRegisters: [])
        }

        var genByBlock: [Int: Set<UInt8>] = [:]
        var killByBlock: [Int: Set<UInt8>] = [:]
        var firstReadWidthByReg: [UInt8: Int] = [:]

        for block in function.blocks {
            var gen = Set<UInt8>()
            var kill = Set<UInt8>()

            for insn in block.instructions where !suppressedAddresses.contains(insn.address) {
                for r in insn.readsRegisters where (r.bank == .gp64 || r.bank == .gp32) && r.index <= 30 {
                    if !kill.contains(r.index) {
                        gen.insert(r.index)
                        if firstReadWidthByReg[r.index] == nil {
                            firstReadWidthByReg[r.index] = r.bitWidth
                        }
                    }
                }
                for w in insn.writesRegisters where (w.bank == .gp64 || w.bank == .gp32) && w.index <= 30 {
                    kill.insert(w.index)
                }
                switch insn.flow {
                case .directCall, .indirectCall:
                    for idx: UInt8 in 0...18 {
                        kill.insert(idx)
                    }
                default:
                    break
                }
            }

            genByBlock[block.id] = gen
            killByBlock[block.id] = kill
        }

        var liveIn: [Int: Set<UInt8>] = [:]
        var liveOut: [Int: Set<UInt8>] = [:]
        for b in function.blocks {
            liveIn[b.id] = genByBlock[b.id] ?? []
            liveOut[b.id] = []
        }

        var changed = true
        var iter = 0
        while changed && iter < 48 {
            changed = false
            iter += 1
            for b in function.blocks.reversed() {
                var outSet = Set<UInt8>()
                for succ in b.successorIDs {
                    outSet.formUnion(liveIn[succ] ?? [])
                }
                let inSet = (genByBlock[b.id] ?? []).union(outSet.subtracting(killByBlock[b.id] ?? []))
                if outSet != liveOut[b.id] || inSet != liveIn[b.id] {
                    liveOut[b.id] = outSet
                    liveIn[b.id] = inSet
                    changed = true
                }
            }
        }

        let entryID = function.blocks.first(where: \.isEntry)?.id ?? function.blocks[0].id
        let entryLiveGP = (liveIn[entryID] ?? []).filter { $0 < 8 }

        var paramRegs: [A64Register] = []
        if let objc = objcContext {
            let count = min(8, objc.parameterTypes.count)
            for idx in 0..<count {
                paramRegs.append(.x(UInt8(idx)))
            }
        } else if let maxArgIdx = entryLiveGP.max() {
            for idx in 0...maxArgIdx {
                let width = firstReadWidthByReg[idx] ?? 64
                paramRegs.append(width == 32 ? .w(idx) : .x(idx))
            }
        }

        return FunctionRegisterLiveness(
            liveInByBlock: liveIn,
            liveOutByBlock: liveOut,
            liveInParameterRegisters: paramRegs
        )
    }

    private func determineFunctionReturnBehavior(
        function: RecoveredFunction,
        objcContext: ObjCMethodSignatureContext?,
        suppressedAddresses: Set<VirtualAddress>
    ) -> (returnsValue: Bool, bitWidth: Int, explicitTypeHint: CTypeExpr?) {
        if let objc = objcContext {
            let bits = (objc.returnType == .boolType || objc.returnType == .intType(bits: 32, signed: true) || objc.returnType == .intType(bits: 32, signed: false)) ? 32 : 64
            return (objc.returnType != .voidType, bits, objc.returnType)
        }

        let cleanName = KnownFunctionSignatureCatalog.normalizeSymbolName(function.demangledName)
        if cleanName == "main" {
            return (true, 32, .intType(bits: 32, signed: true))
        }
        if let proto = KnownFunctionSignatureCatalog.lookup(cleanName) {
            return (proto.returnType != .voidType, 64, proto.returnType)
        }

        var lastX0WriteBits: Int? = nil
        var sawCSetX0 = false

        for block in function.blocks {
            for insn in block.instructions where !suppressedAddresses.contains(insn.address) {
                if insn.mnemonic == .cset,
                   let first = insn.operands.first,
                   case .register(let rd) = first,
                   rd.isGeneralPurpose && rd.index == 0 {
                    sawCSetX0 = true
                    lastX0WriteBits = 32
                }
                for w in insn.writesRegisters where (w.bank == .gp64 || w.bank == .gp32) && w.index == 0 {
                    lastX0WriteBits = w.bitWidth
                }
                switch insn.flow {
                case .directCall, .indirectCall:
                    if lastX0WriteBits == nil {
                        lastX0WriteBits = 64
                    }
                default:
                    break
                }
            }
        }

        if sawCSetX0 {
            return (true, 32, .boolType)
        }
        if let bits = lastX0WriteBits {
            return (true, bits, nil)
        }
        return (false, 64, .voidType)
    }

    private func orderBlocksRPO(function: RecoveredFunction) -> [BasicBlock] {
        guard !function.blocks.isEmpty else { return [] }
        let cfgEngine = CFGBuilderEngine()
        let entryID = function.blocks.first(where: \.isEntry)?.id ?? function.blocks[0].id
        let rpoIDs = cfgEngine.computeReversePostOrder(blocks: function.blocks, entryBlockID: entryID).reversePostOrder
        let byID = Dictionary(uniqueKeysWithValues: function.blocks.map { ($0.id, $0) })
        var ordered = rpoIDs.compactMap { byID[$0] }
        let seen = Set(rpoIDs)
        for b in function.blocks where !seen.contains(b.id) {
            ordered.append(b)
        }
        return ordered
    }

    // MARK: - Per-Basic-Block Instruction Lifter

    private func liftBasicBlock(
        block: BasicBlock,
        function: RecoveredFunction,
        prologueInfo: A64PrologueEpilogueAnalysis,
        suppressedSet: Set<VirtualAddress>,
        idiomsByCompleting: [VirtualAddress: A64RecognizedIdiom],
        consumedIntermediateAddresses: Set<VirtualAddress>,
        switchPlan: SwitchDispatchPlan?,
        liveness: FunctionRegisterLiveness,
        returnsValue: Bool,
        returnBitWidth: Int,
        objcContext: ObjCMethodSignatureContext?,
        resolver: BinaryLiftingResolutionContext,
        incomingFlags: TrackedFlagComparison?,
        stackSlotsByName: inout [String: RecoveredStackSlot],
        outgoingFlagsOut: inout TrackedFlagComparison?
    ) -> MicroBasicBlock {
        var stmts: [MicroStmt] = []
        var activeFlags: TrackedFlagComparison? = incomingFlags
        var trackedExprByGPReg: [UInt8: MicroExpr] = [:]
        var definedArgRegsSinceLastCall = Set<UInt8>()

        if block.isEntry {
            for paramReg in liveness.liveInParameterRegisters where paramReg.index < 8 {
                definedArgRegsSinceLastCall.insert(paramReg.index)
            }
        }

        let outgoingEdges = function.edges.filter { $0.sourceBlockID == block.id }

        func trueAndFalseSuccessors() -> (trueID: Int, falseID: Int) {
            let t = outgoingEdges.first(where: { $0.kind == .conditionalTrue })?.targetBlockID
                ?? block.successorIDs.first ?? block.id
            let f = outgoingEdges.first(where: { $0.kind == .conditionalFalse })?.targetBlockID
                ?? block.successorIDs.dropFirst().first ?? t
            return (t, f)
        }

        for (insnIdx, insn) in block.instructions.enumerated() {
            // 1. Suppress prologue/epilogue callee-saved frame setup & consumed intermediate idiom steps
            if suppressedSet.contains(insn.address) || consumedIntermediateAddresses.contains(insn.address) {
                continue
            }

            // 2. Handle Switch Jump Table setup suppression & dispatch emission
            if let swPlan = switchPlan, swPlan.suppressedSetupAddresses.contains(insn.address) {
                if insn.address == block.instructions.last?.address {
                    var selExpr = readRegisterExpr(swPlan.selectorRegister)
                    if swPlan.selectorBias != 0 {
                        selExpr = .binary(
                            .sub,
                            selExpr,
                            .signedConst(swPlan.selectorBias, bits: swPlan.selectorRegister.bitWidth)
                        )
                    }
                    stmts.append(
                        MicroStmt(
                            originAddress: insn.address,
                            kind: .switchJump(
                                selector: selExpr,
                                cases: swPlan.cases,
                                defaultBlockID: swPlan.defaultBlockID
                            )
                        )
                    )
                }
                continue
            }

            // 3. Multi-instruction Idiom Completion (`MOVZ+MOVK`, `ADRP+ADD`, `ADRP+LDR`, `ADRP+STR`, `SVC #0x80`)
            if let idiom = idiomsByCompleting[insn.address] {
                switch idiom.kind {
                case .movWideConstant where configuration.synthesizeWideConstants:
                    if let dstReg = idiom.destinationRegister, let val = idiom.constantValue {
                        let cExpr = makeConstantOrSymbolExpr(
                            value: val,
                            bits: dstReg.bitWidth,
                            at: insn.address,
                            resolver: resolver
                        )
                        emitGPWrite(
                            dstReg,
                            expr: cExpr,
                            at: insn.address,
                            stmts: &stmts,
                            trackedExprByGPReg: &trackedExprByGPReg,
                            definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
                        )
                        continue
                    }

                case .adrpAddAddress where configuration.resolvePCRelativeStringsAndSymbols:
                    if let dstReg = idiom.destinationRegister, let targetAddr = idiom.targetAddress {
                        let resolved = resolveAddressValueExpr(targetAddr, resolver: resolver)
                        emitGPWrite(
                            dstReg,
                            expr: resolved,
                            at: insn.address,
                            stmts: &stmts,
                            trackedExprByGPReg: &trackedExprByGPReg,
                            definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
                        )
                        continue
                    }

                case .adrpLoadPointer where configuration.resolvePCRelativeStringsAndSymbols:
                    if let dstReg = idiom.destinationRegister, let targetAddr = idiom.targetAddress {
                        let loadedExpr = resolver.resolveGOTLoadSymbolOrString(at: targetAddr)
                        emitGPWrite(
                            dstReg,
                            expr: loadedExpr,
                            at: insn.address,
                            stmts: &stmts,
                            trackedExprByGPReg: &trackedExprByGPReg,
                            definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
                        )
                        continue
                    }

                case .adrpStoreData where configuration.resolvePCRelativeStringsAndSymbols:
                    if let targetAddr = idiom.targetAddress,
                       let firstOp = insn.operands.first {
                        let valExpr = liftOperandExpr(firstOp, defaultBits: 64)
                        let addrExpr: MicroExpr
                        if let sym = resolver.resolveSymbol(at: targetAddr) {
                            addrExpr = .symbolRef(name: sym, address: targetAddr)
                        } else {
                            addrExpr = .symbolRef(name: "g_data_\(String(targetAddr.rawValue, radix: 16))", address: targetAddr)
                        }
                        let storeBits = Self.storeBitWidth(for: insn)
                        stmts.append(MicroStmt(originAddress: insn.address, kind: .store(address: addrExpr, value: valExpr, bits: storeBits)))
                        continue
                    }

                case .darwinSyscall:
                    let sysName = idiom.resolvedSymbol ?? "darwin_syscall_\(idiom.constantValue ?? 0)"
                    let arg0 = readRegisterExpr(.x(0))
                    let arg1 = readRegisterExpr(.x(1))
                    let arg2 = readRegisterExpr(.x(2))
                    let callExpr = MicroExpr.call(
                        target: .symbolRef(name: sysName, address: insn.address),
                        arguments: [arg0, arg1, arg2],
                        returnType: .intType(bits: 64, signed: true)
                    )
                    if isX0ReadAfter(insnIndex: insnIdx, in: block, function: function, liveness: liveness, suppressed: suppressedSet, resolver: resolver, functionReturns: returnsValue) {
                        emitGPWrite(
                            .x(0),
                            expr: callExpr,
                            at: insn.address,
                            stmts: &stmts,
                            trackedExprByGPReg: &trackedExprByGPReg,
                            definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
                        )
                    } else {
                        stmts.append(MicroStmt(originAddress: insn.address, kind: .intrinsic(name: sysName, arguments: [arg0, arg1, arg2])))
                    }
                    definedArgRegsSinceLastCall.removeAll()
                    continue

                default:
                    break
                }
            }

            // 4. Individual Instruction Lifting by Mnemonic & Flow
            liftSingleInstruction(
                insn: insn,
                insnIdx: insnIdx,
                block: block,
                function: function,
                prologueInfo: prologueInfo,
                suppressedSet: suppressedSet,
                liveness: liveness,
                returnsValue: returnsValue,
                returnBitWidth: returnBitWidth,
                objcContext: objcContext,
                resolver: resolver,
                trueAndFalseSuccessors: trueAndFalseSuccessors,
                activeFlags: &activeFlags,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts
            )
        }

        // 5. Append explicit fallthrough `.jump(targetBlockID:)` when block does not end in a control-flow terminator
        let hasTerminator = stmts.last.map { Self.isTerminatorStmt($0.kind) } ?? false
        if !hasTerminator {
            if let fallthroughEdge = outgoingEdges.first(where: { $0.kind == .fallthroughEdge || $0.kind == .unconditional }) {
                let origin = block.instructions.last?.address ?? block.startAddress
                stmts.append(MicroStmt(originAddress: origin, kind: .jump(targetBlockID: fallthroughEdge.targetBlockID)))
            } else if block.isExit && block.successorIDs.isEmpty {
                let origin = block.instructions.last?.address ?? block.startAddress
                let retVal: MicroExpr? = returnsValue
                    ? readRegisterExpr(returnBitWidth == 32 ? .w(0) : .x(0))
                    : nil
                stmts.append(MicroStmt(originAddress: origin, kind: .returnStmt(value: retVal)))
            }
        }

        outgoingFlagsOut = activeFlags
        return MicroBasicBlock(
            blockID: block.id,
            startAddress: block.startAddress,
            statements: stmts
        )
    }

    // MARK: - Single ARM64 Instruction Semantics

    private func emitGPWrite(
        _ reg: A64Register,
        expr: MicroExpr,
        at origin: VirtualAddress,
        stmts: inout [MicroStmt],
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>
    ) {
        guard !reg.isZeroRegister else { return }
        let dstVar = Self.makeSSAVar(for: reg)
        let normalizedExpr: MicroExpr
        if reg.bank == .gp32 && configuration.zeroExtend32BitWrites {
            normalizedExpr = Self.coerceWidth(expr, targetBits: 32)
        } else {
            normalizedExpr = expr
        }
        stmts.append(MicroStmt(originAddress: origin, kind: .assign(dest: dstVar, expr: normalizedExpr)))
        if reg.isGeneralPurpose && !reg.isStackPointer && reg.index <= 30 {
            trackedExprByGPReg[reg.index] = normalizedExpr
            if reg.index < 8 {
                definedArgRegsSinceLastCall.insert(reg.index)
            }
        }
    }

    private func liftSingleInstruction(
        insn: A64DecodedInstruction,
        insnIdx: Int,
        block: BasicBlock,
        function: RecoveredFunction,
        prologueInfo: A64PrologueEpilogueAnalysis,
        suppressedSet: Set<VirtualAddress>,
        liveness: FunctionRegisterLiveness,
        returnsValue: Bool,
        returnBitWidth: Int,
        objcContext: ObjCMethodSignatureContext?,
        resolver: BinaryLiftingResolutionContext,
        trueAndFalseSuccessors: () -> (trueID: Int, falseID: Int),
        activeFlags: inout TrackedFlagComparison?,
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>,
        stackSlotsByName: inout [String: RecoveredStackSlot],
        stmts: inout [MicroStmt]
    ) {
        let origin = insn.address

        switch insn.mnemonic {

        // MARK: Moves & PC-Relative Addressing
        case .mov:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let srcExpr = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            emitGPWrite(rd, expr: srcExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .movz:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let val = Self.extractShiftedUnsignedImm(insn.operands[1]) ?? 0
            emitGPWrite(rd, expr: .unsignedConst(val, bits: rd.bitWidth), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .movn:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let raw = Self.extractShiftedUnsignedImm(insn.operands[1]) ?? 0
            let inverted = rd.bitWidth == 32 ? ((~raw) & 0xFFFF_FFFF) : (~raw)
            let signed = rd.bitWidth == 32
                ? Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: inverted)))
                : Int64(bitPattern: inverted)
            emitGPWrite(rd, expr: .signedConst(signed, bits: rd.bitWidth), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .movk:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let (imm16, shift) = Self.extractLaneAndShift(insn.operands[1])
            let clearMask = ~(UInt64(0xFFFF) << Int(shift))
            let maskedPrev = MicroExpr.binary(
                .bitwiseAnd,
                readRegisterExpr(rd),
                .unsignedConst(rd.bitWidth == 32 ? (clearMask & 0xFFFF_FFFF) : clearMask, bits: rd.bitWidth)
            )
            let inserted = MicroExpr.binary(
                .bitwiseOr,
                maskedPrev,
                .unsignedConst(imm16 << Int(shift), bits: rd.bitWidth)
            )
            emitGPWrite(rd, expr: inserted, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .adr:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0],
                  case .branchTarget(let target) = insn.operands[1] else { break }
            let resolved = resolveAddressValueExpr(target, resolver: resolver)
            emitGPWrite(rd, expr: resolved, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .adrp:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0],
                  case .branchTarget(let page) = insn.operands[1] else { break }
            emitGPWrite(rd, expr: .unsignedConst(page.rawValue, bits: 64), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        // MARK: Arithmetic & Flag-Setting Arithmetic
        case .add, .adds, .sub, .subs, .adc, .adcs, .sbc, .sbcs:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0],
                  case .register(let rn) = insn.operands[1] else { break }

            // Check if taking address of stack local variable (`add x0, sp, #off` or `sub x0, x29, #off`)
            if configuration.recoverStackLocalVariables,
               (insn.mnemonic == .add || insn.mnemonic == .sub),
               !rd.isStackPointer,
               let imm = Self.extractImmediateInt64(insn.operands[2]),
               let slotVar = resolveStackLocalVariable(
                   base: rn,
                   byteOffset: insn.mnemonic == .sub ? -imm : imm,
                   accessBits: 64,
                   prologueInfo: prologueInfo,
                   stackSlotsByName: &stackSlotsByName
               ) {
                let addrRef = MicroExpr.symbolRef(name: "&\(slotVar.baseName)", address: origin)
                emitGPWrite(rd, expr: addrRef, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
                break
            }

            let lhs = readRegisterExpr(rn)
            let rhs = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let isSub = (insn.mnemonic == .sub || insn.mnemonic == .subs || insn.mnemonic == .sbc || insn.mnemonic == .sbcs)
            let binOp: MicroBinaryOp = isSub ? .sub : .add
            let expr = MicroExpr.binary(binOp, lhs, rhs)
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

            if insn.writesFlags {
                activeFlags = TrackedFlagComparison(
                    lhs: isSub ? lhs : expr,
                    rhs: isSub ? rhs : .unsignedConst(0, bits: rd.bitWidth),
                    bitWidth: rd.bitWidth,
                    kind: .subtract,
                    compoundPrefix: nil
                )
            }

        case .neg, .negs, .ngc, .ngcs:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let expr = MicroExpr.unary(.negate, src)
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            if insn.writesFlags {
                activeFlags = TrackedFlagComparison(
                    lhs: .signedConst(0, bits: rd.bitWidth),
                    rhs: src,
                    bitWidth: rd.bitWidth,
                    kind: .subtract,
                    compoundPrefix: nil
                )
            }

        // MARK: Comparisons & Conditional Comparisons (`cmp`, `cmn`, `tst`, `ccmp`, `ccmn`, `fcmp`)
        case .cmp:
            guard insn.operands.count >= 2 else { break }
            let width = Self.operandBitWidth(insn.operands[0])
            let lhs = liftOperandExpr(insn.operands[0], defaultBits: width)
            let rhs = liftOperandExpr(insn.operands[1], defaultBits: width)
            activeFlags = TrackedFlagComparison(
                lhs: lhs,
                rhs: rhs,
                bitWidth: width,
                kind: .subtract,
                compoundPrefix: nil
            )

        case .cmn:
            guard insn.operands.count >= 2 else { break }
            let width = Self.operandBitWidth(insn.operands[0])
            let lhs = liftOperandExpr(insn.operands[0], defaultBits: width)
            let rhs = liftOperandExpr(insn.operands[1], defaultBits: width)
            let negRhs: MicroExpr
            if case .unsignedConst(let v, let b) = rhs {
                negRhs = .signedConst(-Int64(bitPattern: v), bits: b)
            } else {
                negRhs = .unary(.negate, rhs)
            }
            activeFlags = TrackedFlagComparison(
                lhs: lhs,
                rhs: negRhs,
                bitWidth: width,
                kind: .subtract,
                compoundPrefix: nil
            )

        case .tst:
            guard insn.operands.count >= 2 else { break }
            let width = Self.operandBitWidth(insn.operands[0])
            let lhs = liftOperandExpr(insn.operands[0], defaultBits: width)
            let rhs = liftOperandExpr(insn.operands[1], defaultBits: width)
            activeFlags = TrackedFlagComparison(
                lhs: .binary(.bitwiseAnd, lhs, rhs),
                rhs: .unsignedConst(0, bits: width),
                bitWidth: width,
                kind: .bitwiseTest,
                compoundPrefix: nil
            )

        case .ccmp, .ccmn:
            // operands: [rn, rmOrImm, #nzcv, cond]
            guard insn.operands.count >= 4,
                  case .condition(let guardCond) = insn.operands[3] else { break }
            let width = Self.operandBitWidth(insn.operands[0])
            let lhs = liftOperandExpr(insn.operands[0], defaultBits: width)
            let rawRhs = liftOperandExpr(insn.operands[1], defaultBits: width)
            let rhs = insn.mnemonic == .ccmn ? MicroExpr.unary(.negate, rawRhs) : rawRhs
            let nzcvFallback = UInt8(truncatingIfNeeded: Self.extractShiftedUnsignedImm(insn.operands[2]) ?? 0)
            let priorCondExpr = materializeCondition(guardCond, flags: activeFlags)
            // Store nzcv bit 1 (`C`) / bit 2 (`Z`) hint via `logicalAnd` vs `logicalOr` resolution when consumed:
            // If nzcv == 0 (most common `a && b` idiom), false guard sets Z=0,C=0,N=0,V=0 -> `eq` fails -> `&&`.
            let combineOp: MicroBinaryOp = (nzcvFallback == 0x4) ? .logicalOr : .logicalAnd
            let prefixExpr = (combineOp == .logicalOr) ? Self.negateConditionExpr(priorCondExpr) : priorCondExpr
            activeFlags = TrackedFlagComparison(
                lhs: lhs,
                rhs: rhs,
                bitWidth: width,
                kind: .subtract,
                compoundPrefix: (op: combineOp, priorExpr: prefixExpr)
            )

        case .fcmp, .fcmpe:
            guard insn.operands.count >= 2 else { break }
            let width = Self.operandBitWidth(insn.operands[0])
            let lhs = liftOperandExpr(insn.operands[0], defaultBits: width)
            let rhs = liftOperandExpr(insn.operands[1], defaultBits: width)
            activeFlags = TrackedFlagComparison(
                lhs: lhs,
                rhs: rhs,
                bitWidth: width,
                kind: .floatingPoint,
                compoundPrefix: nil
            )

        // MARK: Logical & Bitwise Operations
        case .and, .ands, .orr, .eor, .bic, .bics, .orn, .eon:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0],
                  case .register(let rn) = insn.operands[1] else { break }
            let lhs = readRegisterExpr(rn)
            let rawRhs = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let invertsRhs = (insn.mnemonic == .bic || insn.mnemonic == .bics || insn.mnemonic == .orn || insn.mnemonic == .eon)
            let rhs = invertsRhs ? MicroExpr.unary(.bitwiseNot, rawRhs) : rawRhs
            let op: MicroBinaryOp
            switch insn.mnemonic {
            case .and, .ands, .bic, .bics: op = .bitwiseAnd
            case .orr, .orn:               op = .bitwiseOr
            default:                       op = .bitwiseXor
            }
            let expr = MicroExpr.binary(op, lhs, rhs)
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            if insn.writesFlags {
                activeFlags = TrackedFlagComparison(
                    lhs: expr,
                    rhs: .unsignedConst(0, bits: rd.bitWidth),
                    bitWidth: rd.bitWidth,
                    kind: .bitwiseTest,
                    compoundPrefix: nil
                )
            }

        case .mvn:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            emitGPWrite(rd, expr: .unary(.bitwiseNot, src), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        // MARK: Shifts, Bitfields, Sign/Zero Extensions & Byte Reversal
        case .lsl, .lsr, .asr, .ror:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0] else { break }
            let lhs = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let shiftAmt = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let expr: MicroExpr
            switch insn.mnemonic {
            case .lsl:
                expr = .binary(.shiftLeft, lhs, shiftAmt)
            case .lsr:
                expr = .binary(.shiftRightLogical, lhs, shiftAmt)
            case .asr:
                expr = .binary(.shiftRightArithmetic, lhs, shiftAmt)
            default:
                // ROR(x, s) = (x >> s) | (x << (width - s))
                let wConst = MicroExpr.unsignedConst(UInt64(rd.bitWidth), bits: rd.bitWidth)
                let hi = MicroExpr.binary(.shiftLeft, lhs, .binary(.sub, wConst, shiftAmt))
                let lo = MicroExpr.binary(.shiftRightLogical, lhs, shiftAmt)
                expr = .binary(.bitwiseOr, lo, hi)
            }
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .uxtb, .uxth:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: 32)
            let mask: UInt64 = (insn.mnemonic == .uxtb) ? 0xFF : 0xFFFF
            emitGPWrite(rd, expr: .binary(.bitwiseAnd, src, .unsignedConst(mask, bits: rd.bitWidth)), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .sxtb, .sxth, .sxtw:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let srcBits: Int = (insn.mnemonic == .sxtb) ? 8 : ((insn.mnemonic == .sxth) ? 16 : 32)
            let src = liftOperandExpr(insn.operands[1], defaultBits: srcBits)
            let signedNarrow = MicroExpr.cast(src, to: .intType(bits: srcBits, signed: true))
            emitGPWrite(rd, expr: .unary(.signExtend, signedNarrow), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .ubfx, .sbfx, .ubfm, .sbfm:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let lsb = Self.extractShiftedUnsignedImm(insn.operands[2]) ?? 0
            let width = Self.extractShiftedUnsignedImm(insn.operands[3]) ?? 1
            let shifted = (lsb == 0) ? src : MicroExpr.binary(.shiftRightLogical, src, .unsignedConst(lsb, bits: rd.bitWidth))
            let mask: UInt64 = width >= 64 ? UInt64.max : ((UInt64(1) << Int(width)) - 1)
            let extracted = MicroExpr.binary(.bitwiseAnd, shifted, .unsignedConst(mask, bits: rd.bitWidth))
            let isSigned = (insn.mnemonic == .sbfx || insn.mnemonic == .sbfm)
            emitGPWrite(rd, expr: isSigned ? .unary(.signExtend, extracted) : extracted, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .ubfiz, .sbfiz:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let lsb = Self.extractShiftedUnsignedImm(insn.operands[2]) ?? 0
            let width = Self.extractShiftedUnsignedImm(insn.operands[3]) ?? 1
            let mask: UInt64 = width >= 64 ? UInt64.max : ((UInt64(1) << Int(width)) - 1)
            let masked = MicroExpr.binary(.bitwiseAnd, src, .unsignedConst(mask, bits: rd.bitWidth))
            let shifted = (lsb == 0) ? masked : MicroExpr.binary(.shiftLeft, masked, .unsignedConst(lsb, bits: rd.bitWidth))
            emitGPWrite(rd, expr: insn.mnemonic == .sbfiz ? .unary(.signExtend, shifted) : shifted, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .bfi, .bfxil, .bfm:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0] else { break }
            let dstPrev = readRegisterExpr(rd)
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let lsb = Self.extractShiftedUnsignedImm(insn.operands[2]) ?? 0
            let width = Self.extractShiftedUnsignedImm(insn.operands[3]) ?? 1
            let lowMask: UInt64 = width >= 64 ? UInt64.max : ((UInt64(1) << Int(width)) - 1)
            if insn.mnemonic == .bfi {
                let clearMask = ~(lowMask << Int(lsb))
                let cleared = MicroExpr.binary(.bitwiseAnd, dstPrev, .unsignedConst(clearMask, bits: rd.bitWidth))
                let field = MicroExpr.binary(.shiftLeft, .binary(.bitwiseAnd, src, .unsignedConst(lowMask, bits: rd.bitWidth)), .unsignedConst(lsb, bits: rd.bitWidth))
                emitGPWrite(rd, expr: .binary(.bitwiseOr, cleared, field), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            } else {
                let cleared = MicroExpr.binary(.bitwiseAnd, dstPrev, .unsignedConst(~lowMask, bits: rd.bitWidth))
                let shiftedSrc = lsb == 0 ? src : MicroExpr.binary(.shiftRightLogical, src, .unsignedConst(lsb, bits: rd.bitWidth))
                let field = MicroExpr.binary(.bitwiseAnd, shiftedSrc, .unsignedConst(lowMask, bits: rd.bitWidth))
                emitGPWrite(rd, expr: .binary(.bitwiseOr, cleared, field), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            }

        case .extr:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0] else { break }
            let hiSrc = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let loSrc = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let lsb = Self.extractShiftedUnsignedImm(insn.operands[3]) ?? 0
            if lsb == 0 {
                emitGPWrite(rd, expr: loSrc, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            } else {
                let hiPart = MicroExpr.binary(.shiftLeft, hiSrc, .unsignedConst(UInt64(rd.bitWidth) - lsb, bits: rd.bitWidth))
                let loPart = MicroExpr.binary(.shiftRightLogical, loSrc, .unsignedConst(lsb, bits: rd.bitWidth))
                emitGPWrite(rd, expr: .binary(.bitwiseOr, hiPart, loPart), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            }

        case .rev, .rev16, .rev32:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            emitGPWrite(rd, expr: .unary(.byteSwap, src), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .clz, .cls, .rbit:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let fnName = "__builtin_\(insn.mnemonic.rawValue)"
            emitGPWrite(
                rd,
                expr: .call(
                    target: .symbolRef(name: fnName, address: origin),
                    arguments: [src],
                    returnType: .intType(bits: rd.bitWidth, signed: false)
                ),
                at: origin,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )

        // MARK: Multiply & Divide
        case .mul, .smull, .umull, .smulh, .umulh, .mneg, .smnegl, .umnegl:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0] else { break }
            let lhs = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let rhs = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let prod = MicroExpr.binary(.mul, lhs, rhs)
            let isNeg = (insn.mnemonic == .mneg || insn.mnemonic == .smnegl || insn.mnemonic == .umnegl)
            emitGPWrite(rd, expr: isNeg ? .unary(.negate, prod) : prod, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .madd, .msub, .smaddl, .smsubl, .umaddl, .umsubl:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0] else { break }
            let rn = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let rm = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let ra = liftOperandExpr(insn.operands[3], defaultBits: rd.bitWidth)
            let prod = MicroExpr.binary(.mul, rn, rm)
            let isSub = (insn.mnemonic == .msub || insn.mnemonic == .smsubl || insn.mnemonic == .umsubl)
            emitGPWrite(rd, expr: .binary(isSub ? .sub : .add, ra, prod), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .udiv, .sdiv:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0] else { break }
            let lhs = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let rhs = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let op: MicroBinaryOp = (insn.mnemonic == .sdiv) ? .sdiv : .udiv
            emitGPWrite(rd, expr: .binary(op, lhs, rhs), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        // MARK: Conditional Select (`cset`, `csel`, `csinc`, `csinv`, `csneg`, `cinc`, `cinv`, `cneg`)
        case .cset:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0],
                  case .condition(let cond) = insn.operands[1] else { break }
            let condExpr = materializeCondition(cond, flags: activeFlags)
            let dst = SSAVar(baseName: Self.canonicalBaseName(for: rd), version: 0, bitWidth: rd.bitWidth, inferredType: .boolType)
            stmts.append(MicroStmt(originAddress: origin, kind: .assign(dest: dst, expr: condExpr)))
            if rd.index < 8 { definedArgRegsSinceLastCall.insert(rd.index) }

        case .csetm:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0],
                  case .condition(let cond) = insn.operands[1] else { break }
            let condExpr = materializeCondition(cond, flags: activeFlags)
            let expr = MicroExpr.ternary(
                condition: condExpr,
                thenExpr: .signedConst(-1, bits: rd.bitWidth),
                elseExpr: .signedConst(0, bits: rd.bitWidth)
            )
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .cinc, .cinv, .cneg:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0],
                  case .condition(let cond) = insn.operands[2] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let condExpr = materializeCondition(cond, flags: activeFlags)
            let alt: MicroExpr
            switch insn.mnemonic {
            case .cinc: alt = .binary(.add, src, .unsignedConst(1, bits: rd.bitWidth))
            case .cinv: alt = .unary(.bitwiseNot, src)
            default:    alt = .unary(.negate, src)
            }
            emitGPWrite(rd, expr: .ternary(condition: condExpr, thenExpr: alt, elseExpr: src), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .csel, .csinc, .csinv, .csneg, .fcsel:
            guard insn.operands.count >= 4,
                  case .register(let rd) = insn.operands[0],
                  case .condition(let cond) = insn.operands[3] else { break }
            let thenVal = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let rawElse = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let elseVal: MicroExpr
            switch insn.mnemonic {
            case .csinc: elseVal = .binary(.add, rawElse, .unsignedConst(1, bits: rd.bitWidth))
            case .csinv: elseVal = .unary(.bitwiseNot, rawElse)
            case .csneg: elseVal = .unary(.negate, rawElse)
            default:     elseVal = rawElse
            }
            let condExpr = materializeCondition(cond, flags: activeFlags)
            emitGPWrite(rd, expr: .ternary(condition: condExpr, thenExpr: thenVal, elseExpr: elseVal), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        // MARK: Memory Loads & Stores (Including Pre/Post-Index Writeback & Stack Locals & ObjC Ivars)
        case .ldr, .ldrb, .ldrh, .ldrsb, .ldrsh, .ldrsw,
             .ldur, .ldurb, .ldurh, .ldursb, .ldursh, .ldursw,
             .ldar, .ldarb, .ldarh, .ldxr, .ldaxr:
            guard insn.operands.count >= 2,
                  case .register(let rt) = insn.operands[0],
                  case .memory(let mode) = insn.operands[1] else { break }

            let spec = Self.singleLoadSpec(for: insn.mnemonic, destReg: rt)
            liftMemoryLoad(
                destReg: rt,
                mode: mode,
                accessBits: spec.bits,
                loadType: spec.type,
                signExtendResult: spec.signExtend,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                resolver: resolver,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )

        case .ldp, .ldnp, .ldpsw:
            guard insn.operands.count >= 3,
                  case .register(let r1) = insn.operands[0],
                  case .register(let r2) = insn.operands[1],
                  case .memory(let mode) = insn.operands[2] else { break }
            let elemBits = (insn.mnemonic == .ldpsw) ? 32 : r1.bitWidth
            let elemBytes = Int64(max(4, elemBits / 8))
            let elemType: CTypeExpr = r1.isSIMD
                ? .floatType(bits: elemBits)
                : .intType(bits: elemBits, signed: insn.mnemonic == .ldpsw)

            let (firstMode, secondMode, postWriteback) = splitPairAddressingMode(mode, secondDelta: elemBytes)
            liftMemoryLoad(
                destReg: r1,
                mode: firstMode,
                accessBits: elemBits,
                loadType: elemType,
                signExtendResult: insn.mnemonic == .ldpsw,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                resolver: resolver,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )
            liftMemoryLoad(
                destReg: r2,
                mode: secondMode,
                accessBits: elemBits,
                loadType: elemType,
                signExtendResult: insn.mnemonic == .ldpsw,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                resolver: resolver,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )
            if let wb = postWriteback {
                emitGPWrite(wb.base, expr: wb.updatedExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            }

        case .str, .strb, .strh, .stur, .sturb, .sturh, .stlr, .stlrb, .stlrh:
            guard insn.operands.count >= 2,
                  case .memory(let mode) = insn.operands[1] else { break }
            let bits = Self.storeBitWidth(for: insn)
            let valExpr = liftOperandExpr(insn.operands[0], defaultBits: bits)
            liftMemoryStore(
                valueExpr: valExpr,
                mode: mode,
                accessBits: bits,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )

        case .stp, .stnp:
            guard insn.operands.count >= 3,
                  case .register(let r1) = insn.operands[0],
                  case .register(let r2) = insn.operands[1],
                  case .memory(let mode) = insn.operands[2] else { break }
            let elemBits = r1.bitWidth
            let elemBytes = Int64(max(4, elemBits / 8))
            let v1 = readRegisterExpr(r1)
            let v2 = readRegisterExpr(r2)
            let (firstMode, secondMode, postWriteback) = splitPairAddressingMode(mode, secondDelta: elemBytes)
            liftMemoryStore(
                valueExpr: v1,
                mode: firstMode,
                accessBits: elemBits,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )
            liftMemoryStore(
                valueExpr: v2,
                mode: secondMode,
                accessBits: elemBits,
                origin: origin,
                prologueInfo: prologueInfo,
                objcContext: objcContext,
                stackSlotsByName: &stackSlotsByName,
                stmts: &stmts,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall
            )
            if let wb = postWriteback {
                emitGPWrite(wb.base, expr: wb.updatedExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            }

        // MARK: Scalar Floating-Point Operations
        case .fmov, .scvtf, .ucvtf, .fcvtzs, .fcvtzu, .fcvtas, .fcvtau, .fcvt, .fabs, .fneg, .fsqrt:
            guard insn.operands.count >= 2,
                  case .register(let rd) = insn.operands[0] else { break }
            let src = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let expr: MicroExpr
            switch insn.mnemonic {
            case .fmov:
                expr = src
            case .fneg:
                expr = .unary(.negate, src)
            case .scvtf, .ucvtf, .fcvt:
                expr = .cast(src, to: .floatType(bits: rd.bitWidth))
            case .fcvtzs, .fcvtas:
                expr = .cast(src, to: .intType(bits: rd.bitWidth, signed: true))
            case .fcvtzu, .fcvtau:
                expr = .cast(src, to: .intType(bits: rd.bitWidth, signed: false))
            default:
                expr = .call(
                    target: .symbolRef(name: insn.mnemonic.rawValue, address: origin),
                    arguments: [src],
                    returnType: .floatType(bits: rd.bitWidth)
                )
            }
            emitGPWrite(rd, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .fadd, .fsub, .fmul, .fdiv:
            guard insn.operands.count >= 3,
                  case .register(let rd) = insn.operands[0] else { break }
            let lhs = liftOperandExpr(insn.operands[1], defaultBits: rd.bitWidth)
            let rhs = liftOperandExpr(insn.operands[2], defaultBits: rd.bitWidth)
            let op: MicroBinaryOp
            switch insn.mnemonic {
            case .fadd: op = .add
            case .fsub: op = .sub
            case .fmul: op = .mul
            default:    op = .udiv
            }
            emitGPWrite(rd, expr: .binary(op, lhs, rhs), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        // MARK: Conditional & Unconditional Branches, Calls & Returns
        case .cbz, .cbnz:
            guard insn.operands.count >= 1,
                  case .register(let rt) = insn.operands[0] else { break }
            let regExpr = readRegisterExpr(rt)
            let op: MicroBinaryOp = (insn.mnemonic == .cbz) ? .equal : .notEqual
            let cond = MicroExpr.binary(op, regExpr, .unsignedConst(0, bits: rt.bitWidth))
            let (tID, fID) = trueAndFalseSuccessors()
            stmts.append(MicroStmt(originAddress: origin, kind: .conditionalBranch(condition: cond, trueBlockID: tID, falseBlockID: fID)))

        case .tbz, .tbnz:
            guard insn.operands.count >= 2,
                  case .register(let rt) = insn.operands[0] else { break }
            let bitIdx = Self.extractShiftedUnsignedImm(insn.operands[1]) ?? 0
            let regExpr = readRegisterExpr(rt)
            let mask = bitIdx < 64 ? (UInt64(1) << Int(bitIdx)) : 1
            let masked = MicroExpr.binary(.bitwiseAnd, regExpr, .unsignedConst(mask, bits: rt.bitWidth))
            let op: MicroBinaryOp = (insn.mnemonic == .tbz) ? .equal : .notEqual
            let cond = MicroExpr.binary(op, masked, .unsignedConst(0, bits: rt.bitWidth))
            let (tID, fID) = trueAndFalseSuccessors()
            stmts.append(MicroStmt(originAddress: origin, kind: .conditionalBranch(condition: cond, trueBlockID: tID, falseBlockID: fID)))

        case .bCond:
            switch insn.flow {
            case .conditionalBranch(_, let cond):
                let condExpr = materializeCondition(cond, flags: activeFlags)
                let (tID, fID) = trueAndFalseSuccessors()
                stmts.append(MicroStmt(originAddress: origin, kind: .conditionalBranch(condition: condExpr, trueBlockID: tID, falseBlockID: fID)))
            case .unconditionalJump:
                if let succ = block.successorIDs.first {
                    stmts.append(MicroStmt(originAddress: origin, kind: .jump(targetBlockID: succ)))
                }
            default:
                break
            }

        case .b:
            if case .unconditionalJump(let target) = insn.flow {
                // Check if internal jump vs external tail-call optimization (`b _helper` / `b _stub`)
                if target != function.address && (target < function.address || target >= function.endAddress) && block.successorIDs.isEmpty {
                    emitDirectOrIndirectCall(
                        targetAddress: target,
                        indirectTargetExpr: nil,
                        isTailCall: true,
                        insnIdx: insnIdx,
                        origin: origin,
                        block: block,
                        function: function,
                        liveness: liveness,
                        suppressedSet: suppressedSet,
                        returnsValue: returnsValue,
                        resolver: resolver,
                        trackedExprByGPReg: &trackedExprByGPReg,
                        definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                        stmts: &stmts
                    )
                } else if let succ = block.successorIDs.first {
                    stmts.append(MicroStmt(originAddress: origin, kind: .jump(targetBlockID: succ)))
                }
            }

        case .bl:
            if case .directCall(let target) = insn.flow {
                emitDirectOrIndirectCall(
                    targetAddress: target,
                    indirectTargetExpr: nil,
                    isTailCall: false,
                    insnIdx: insnIdx,
                    origin: origin,
                    block: block,
                    function: function,
                    liveness: liveness,
                    suppressedSet: suppressedSet,
                    returnsValue: returnsValue,
                    resolver: resolver,
                    trackedExprByGPReg: &trackedExprByGPReg,
                    definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                    stmts: &stmts
                )
            }

        case .blr, .blraa, .blrab, .blraaz, .blrabz:
            if case .indirectCall(let reg) = insn.flow {
                let targetExpr = trackedExprByGPReg[reg.index] ?? readRegisterExpr(reg)
                emitDirectOrIndirectCall(
                    targetAddress: nil,
                    indirectTargetExpr: targetExpr,
                    isTailCall: false,
                    insnIdx: insnIdx,
                    origin: origin,
                    block: block,
                    function: function,
                    liveness: liveness,
                    suppressedSet: suppressedSet,
                    returnsValue: returnsValue,
                    resolver: resolver,
                    trackedExprByGPReg: &trackedExprByGPReg,
                    definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                    stmts: &stmts
                )
            }

        case .br, .braa, .brab, .braaz, .brabz:
            if case .indirectJump(let reg) = insn.flow {
                let targetExpr = trackedExprByGPReg[reg.index] ?? readRegisterExpr(reg)
                emitDirectOrIndirectCall(
                    targetAddress: nil,
                    indirectTargetExpr: targetExpr,
                    isTailCall: true,
                    insnIdx: insnIdx,
                    origin: origin,
                    block: block,
                    function: function,
                    liveness: liveness,
                    suppressedSet: suppressedSet,
                    returnsValue: returnsValue,
                    resolver: resolver,
                    trackedExprByGPReg: &trackedExprByGPReg,
                    definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                    stmts: &stmts
                )
            }

        case .ret, .retaa, .retab:
            let retVal: MicroExpr? = returnsValue
                ? readRegisterExpr(returnBitWidth == 32 ? .w(0) : .x(0))
                : nil
            stmts.append(MicroStmt(originAddress: origin, kind: .returnStmt(value: retVal)))

        case .brk, .hlt, .svc, .hvc, .smc:
            let imm = insn.operands.first.flatMap { Self.extractShiftedUnsignedImm($0) } ?? 0
            stmts.append(
                MicroStmt(
                    originAddress: origin,
                    kind: .intrinsic(name: "__arm64_\(insn.mnemonic.rawValue)", arguments: [.unsignedConst(imm, bits: 16)])
                )
            )

        case .paciasp, .pacibsp, .autiasp, .autibsp, .bti, .nop, .hint, .prfm, .dmb, .dsb, .isb, .clrex:
            break

        case .paciza, .pacizb, .autiza, .autizb, .xpaci, .xpacd:
            if let first = insn.operands.first, case .register(let rd) = first {
                emitGPWrite(rd, expr: readRegisterExpr(rd), at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            }

        default:
            // Graceful intrinsic fallback so zero instructions are ever dropped silently
            var fallbackArgs: [MicroExpr] = []
            for r in insn.readsRegisters {
                fallbackArgs.append(readRegisterExpr(r))
            }
            if let dst = insn.writesRegisters.first {
                let call = MicroExpr.call(
                    target: .symbolRef(name: "__arm64_\(insn.mnemonicText)", address: origin),
                    arguments: fallbackArgs,
                    returnType: .intType(bits: dst.bitWidth, signed: false)
                )
                emitGPWrite(dst, expr: call, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            } else {
                stmts.append(MicroStmt(originAddress: origin, kind: .intrinsic(name: insn.mnemonicText, arguments: fallbackArgs)))
            }
        }
    }

    // MARK: - Memory Addressing, Stack Local Slots & ObjC Ivar Access

    private func liftMemoryLoad(
        destReg: A64Register,
        mode: A64AddressingMode,
        accessBits: Int,
        loadType: CTypeExpr,
        signExtendResult: Bool,
        origin: VirtualAddress,
        prologueInfo: A64PrologueEpilogueAnalysis,
        objcContext: ObjCMethodSignatureContext?,
        resolver: BinaryLiftingResolutionContext,
        stackSlotsByName: inout [String: RecoveredStackSlot],
        stmts: inout [MicroStmt],
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>
    ) {
        switch mode {
        case .pcRelativeLiteral(let target):
            let expr = resolver.resolveGOTLoadSymbolOrString(at: target)
            emitGPWrite(destReg, expr: expr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .baseOffset(let base, let offset):
            if configuration.recoverStackLocalVariables,
               let slotVar = resolveStackLocalVariable(
                   base: base,
                   byteOffset: offset,
                   accessBits: accessBits,
                   prologueInfo: prologueInfo,
                   stackSlotsByName: &stackSlotsByName
               ) {
                let readExpr = MicroExpr.variable(slotVar)
                emitGPWrite(destReg, expr: signExtendResult ? .unary(.signExtend, readExpr) : readExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
                return
            }

            if let objc = objcContext,
               !objc.isClassMethod,
               base.isGeneralPurpose && base.index == 0,
               let ivar = objc.ivarByOffset[offset] {
                let ivarExpr = MicroExpr.symbolRef(name: "self->\(ivar.name)", address: origin)
                emitGPWrite(destReg, expr: ivarExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
                return
            }

            let addrExpr = buildOffsetAddressExpr(base: base, byteOffset: offset)
            let loadExpr = MicroExpr.load(address: addrExpr, bits: accessBits, type: loadType)
            emitGPWrite(destReg, expr: signExtendResult ? .unary(.signExtend, loadExpr) : loadExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .preIndex(let base, let offset):
            let updatedAddr = buildOffsetAddressExpr(base: base, byteOffset: offset)
            emitGPWrite(base, expr: updatedAddr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            let loadExpr = MicroExpr.load(address: readRegisterExpr(base), bits: accessBits, type: loadType)
            emitGPWrite(destReg, expr: signExtendResult ? .unary(.signExtend, loadExpr) : loadExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .postIndex(let base, let offset):
            let baseAddr = readRegisterExpr(base)
            let loadExpr = MicroExpr.load(address: baseAddr, bits: accessBits, type: loadType)
            emitGPWrite(destReg, expr: signExtendResult ? .unary(.signExtend, loadExpr) : loadExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            let updatedAddr = buildOffsetAddressExpr(baseExpr: baseAddr, byteOffset: offset)
            emitGPWrite(base, expr: updatedAddr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .registerOffset(let base, let index, let extend):
            let baseExpr = readRegisterExpr(base)
            let scaledIndex = liftExtendedIndexExpr(index: index, extend: extend)
            let addrExpr = MicroExpr.binary(.add, baseExpr, scaledIndex)
            let loadExpr = MicroExpr.load(address: addrExpr, bits: accessBits, type: loadType)
            emitGPWrite(destReg, expr: signExtendResult ? .unary(.signExtend, loadExpr) : loadExpr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
        }
    }

    private func liftMemoryStore(
        valueExpr: MicroExpr,
        mode: A64AddressingMode,
        accessBits: Int,
        origin: VirtualAddress,
        prologueInfo: A64PrologueEpilogueAnalysis,
        objcContext: ObjCMethodSignatureContext?,
        stackSlotsByName: inout [String: RecoveredStackSlot],
        stmts: inout [MicroStmt],
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>
    ) {
        switch mode {
        case .pcRelativeLiteral(let target):
            let addrExpr = MicroExpr.symbolRef(name: "g_data_\(String(target.rawValue, radix: 16))", address: target)
            stmts.append(MicroStmt(originAddress: origin, kind: .store(address: addrExpr, value: valueExpr, bits: accessBits)))

        case .baseOffset(let base, let offset):
            if configuration.recoverStackLocalVariables,
               let slotVar = resolveStackLocalVariable(
                   base: base,
                   byteOffset: offset,
                   accessBits: accessBits,
                   prologueInfo: prologueInfo,
                   stackSlotsByName: &stackSlotsByName
               ) {
                stmts.append(MicroStmt(originAddress: origin, kind: .assign(dest: slotVar, expr: valueExpr)))
                return
            }

            if let objc = objcContext,
               !objc.isClassMethod,
               base.isGeneralPurpose && base.index == 0,
               let ivar = objc.ivarByOffset[offset] {
                let ivarVar = SSAVar(baseName: "self->\(ivar.name)", version: 0, bitWidth: accessBits, inferredType: ivar.type)
                stmts.append(MicroStmt(originAddress: origin, kind: .assign(dest: ivarVar, expr: valueExpr)))
                return
            }

            let addrExpr = buildOffsetAddressExpr(base: base, byteOffset: offset)
            stmts.append(MicroStmt(originAddress: origin, kind: .store(address: addrExpr, value: valueExpr, bits: accessBits)))

        case .preIndex(let base, let offset):
            let updatedAddr = buildOffsetAddressExpr(base: base, byteOffset: offset)
            emitGPWrite(base, expr: updatedAddr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)
            stmts.append(MicroStmt(originAddress: origin, kind: .store(address: readRegisterExpr(base), value: valueExpr, bits: accessBits)))

        case .postIndex(let base, let offset):
            let baseAddr = readRegisterExpr(base)
            stmts.append(MicroStmt(originAddress: origin, kind: .store(address: baseAddr, value: valueExpr, bits: accessBits)))
            let updatedAddr = buildOffsetAddressExpr(baseExpr: baseAddr, byteOffset: offset)
            emitGPWrite(base, expr: updatedAddr, at: origin, stmts: &stmts, trackedExprByGPReg: &trackedExprByGPReg, definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall)

        case .registerOffset(let base, let index, let extend):
            let baseExpr = readRegisterExpr(base)
            let scaledIndex = liftExtendedIndexExpr(index: index, extend: extend)
            let addrExpr = MicroExpr.binary(.add, baseExpr, scaledIndex)
            stmts.append(MicroStmt(originAddress: origin, kind: .store(address: addrExpr, value: valueExpr, bits: accessBits)))
        }
    }

    private func splitPairAddressingMode(
        _ mode: A64AddressingMode,
        secondDelta: Int64
    ) -> (
        first: A64AddressingMode,
        second: A64AddressingMode,
        postWriteback: (base: A64Register, updatedExpr: MicroExpr)?
    ) {
        switch mode {
        case .baseOffset(let base, let offset):
            return (.baseOffset(base: base, offset: offset), .baseOffset(base: base, offset: offset + secondDelta), nil)
        case .preIndex(let base, let offset):
            return (.preIndex(base: base, offset: offset), .baseOffset(base: base, offset: secondDelta), nil)
        case .postIndex(let base, let offset):
            let updated = buildOffsetAddressExpr(base: base, byteOffset: offset)
            return (.baseOffset(base: base, offset: 0), .baseOffset(base: base, offset: secondDelta), (base, updated))
        default:
            return (mode, mode, nil)
        }
    }

    private func resolveStackLocalVariable(
        base: A64Register,
        byteOffset: Int64,
        accessBits: Int,
        prologueInfo: A64PrologueEpilogueAnalysis,
        stackSlotsByName: inout [String: RecoveredStackSlot]
    ) -> SSAVar? {
        let isSP = base.isStackPointer
        let isFP = prologueInfo.establishesFramePointer && base.bank == .gp64 && base.index == 29
        guard isSP || isFP else { return nil }

        let canonicalFrameOffset: Int64
        let slotName: String
        if isFP {
            canonicalFrameOffset = byteOffset
            if byteOffset < 0 {
                slotName = "local_\(String(UInt64(bitPattern: -byteOffset), radix: 16))"
            } else if byteOffset >= 16 {
                slotName = "arg_stack_\(String(byteOffset - 16, radix: 16))"
            } else {
                return nil
            }
        } else {
            // `sp`-relative local slot (`[sp, #0x10]` -> `local_10`)
            guard byteOffset >= 0 else { return nil }
            let frameBytes = Int64(max(prologueInfo.stackFrameBytes, 0))
            canonicalFrameOffset = frameBytes > 0 ? (-frameBytes + byteOffset) : byteOffset
            let hexOff = String(byteOffset, radix: 16)
            slotName = "local_\(hexOff)"
        }

        let inferredType = CTypeExpr.intType(bits: accessBits, signed: false)
        if stackSlotsByName[slotName] == nil {
            stackSlotsByName[slotName] = RecoveredStackSlot(
                variableName: slotName,
                frameOffset: canonicalFrameOffset,
                byteSize: max(1, accessBits / 8),
                inferredType: inferredType
            )
        }
        return SSAVar(baseName: slotName, version: 0, bitWidth: accessBits, inferredType: inferredType)
    }

    // MARK: - Apple ARM64 AAPCS64 Call & ObjC Message-Send Recovery

    private func emitDirectOrIndirectCall(
        targetAddress: VirtualAddress?,
        indirectTargetExpr: MicroExpr?,
        isTailCall: Bool,
        insnIdx: Int,
        origin: VirtualAddress,
        block: BasicBlock,
        function: RecoveredFunction,
        liveness: FunctionRegisterLiveness,
        suppressedSet: Set<VirtualAddress>,
        returnsValue: Bool,
        resolver: BinaryLiftingResolutionContext,
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>,
        stmts: inout [MicroStmt]
    ) {
        let resolvedName: String?
        let targetExpr: MicroExpr

        if let tgtAddr = targetAddress {
            let sym = resolver.resolveCallTargetName(callSite: origin, targetAddress: tgtAddr)
            resolvedName = sym
            targetExpr = .symbolRef(name: sym, address: tgtAddr)
        } else if let indExpr = indirectTargetExpr {
            if case .symbolRef(let symName, _) = indExpr {
                resolvedName = symName
            } else {
                resolvedName = nil
            }
            targetExpr = indExpr
        } else {
            resolvedName = nil
            targetExpr = .symbolRef(name: "indirect_call", address: origin)
        }

        // 1. Recover Apple Clang `objc_msgSend$selector` stub OR classic `objc_msgSend(self, sel, ...)`
        if let rawName = resolvedName, rawName.hasPrefix("objc_msgSend$") {
            let selector = String(rawName.dropFirst("objc_msgSend$".count))
            let colonCount = selector.filter { $0 == ":" }.count
            var args: [MicroExpr] = [
                readRegisterExpr(.x(0)),
                .stringLiteral(selector, address: origin)
            ]
            for extra in 0..<min(colonCount, 6) {
                // Note: `objc_msgSend$sel` stubs pass real arguments starting at `x2` (x1 is synthesized by stub!)
                args.append(readRegisterExpr(.x(UInt8(2 + extra))))
            }
            let msgTarget = MicroExpr.symbolRef(name: "objc_msgSend", address: targetAddress ?? origin)
            let retType = CTypeExpr.objcObject(className: nil)
            finishCallEmission(
                callTarget: msgTarget,
                arguments: args,
                returnType: retType,
                isTailCall: isTailCall,
                insnIdx: insnIdx,
                origin: origin,
                block: block,
                function: function,
                liveness: liveness,
                suppressedSet: suppressedSet,
                functionReturnsValue: returnsValue,
                resolver: resolver,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                stmts: &stmts
            )
            return
        }

        if resolvedName == "objc_msgSend" {
            let selExpr = trackedExprByGPReg[1] ?? readRegisterExpr(.x(1))
            var colonCount = 0
            if case .stringLiteral(let selText, _) = selExpr {
                colonCount = selText.filter { $0 == ":" }.count
            } else {
                let maxDef = definedArgRegsSinceLastCall.filter { $0 >= 2 && $0 < 8 }.max()
                colonCount = maxDef != nil ? (Int(maxDef!) - 1) : 0
            }
            var args: [MicroExpr] = [readRegisterExpr(.x(0)), selExpr]
            for extra in 0..<min(colonCount, 6) {
                args.append(readRegisterExpr(.x(UInt8(2 + extra))))
            }
            finishCallEmission(
                callTarget: targetExpr,
                arguments: args,
                returnType: .objcObject(className: nil),
                isTailCall: isTailCall,
                insnIdx: insnIdx,
                origin: origin,
                block: block,
                function: function,
                liveness: liveness,
                suppressedSet: suppressedSet,
                functionReturnsValue: returnsValue,
                resolver: resolver,
                trackedExprByGPReg: &trackedExprByGPReg,
                definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
                stmts: &stmts
            )
            return
        }

        // 2. Determine exact AAPCS64 argument count & return type
        var argCount = 0
        var returnType: CTypeExpr = .intType(bits: 64, signed: false)
        var fixedParamTypes: [CTypeExpr] = []

        if let name = resolvedName, let proto = KnownFunctionSignatureCatalog.lookup(name) {
            returnType = proto.returnType
            fixedParamTypes = proto.fixedParameterTypes
            argCount = proto.fixedParameterTypes.count

            // Variadic format string arity refinement (`printf`, `snprintf`, `NSLog`)
            if let fmtIdx = proto.isVariadicFormatAtIndex, fmtIdx < 8,
               let fmtExpr = trackedExprByGPReg[UInt8(fmtIdx)],
               case .stringLiteral(let fmtString, _) = fmtExpr {
                let extraSpecs = KnownFunctionSignatureCatalog.countPrintfFormatSpecifiers(in: fmtString)
                // On Apple ARM64 (Darwin PCS), variadic arguments spill to stack on real clang, or in hand-assembled /
                // register-passed code live in `x1..x7`; include register args when defined prior to the call!
                if extraSpecs > 0 {
                    argCount = min(8, proto.fixedParameterTypes.count + extraSpecs)
                }
            }
        } else if let tgtAddr = targetAddress, let internalArity = resolver.calleeArity(for: tgtAddr) {
            argCount = min(8, internalArity)
            if let calleeRet = resolver.calleeReturnInfo(for: tgtAddr) {
                returnType = calleeRet.returns ? calleeRet.returnType : .voidType
            }
        } else if configuration.recoverABIArgumentCalls {
            let contiguousCount = Self.contiguousLeadingCount(in: definedArgRegsSinceLastCall)
            argCount = contiguousCount
        }

        var arguments: [MicroExpr] = []
        arguments.reserveCapacity(argCount)
        for idx in 0..<argCount {
            let expectedType: CTypeExpr? = idx < fixedParamTypes.count ? fixedParamTypes[idx] : nil
            let reg: A64Register
            if let expectedType {
                switch expectedType {
                case .intType(let bits, _) where bits <= 32:
                    reg = .w(UInt8(idx))
                case .floatType(let bits):
                    reg = bits <= 32 ? .s(UInt8(idx)) : .d(UInt8(idx))
                default:
                    reg = .x(UInt8(idx))
                }
            } else {
                reg = .x(UInt8(idx))
            }
            arguments.append(readRegisterExpr(reg))
        }

        finishCallEmission(
            callTarget: targetExpr,
            arguments: arguments,
            returnType: returnType,
            isTailCall: isTailCall,
            insnIdx: insnIdx,
            origin: origin,
            block: block,
            function: function,
            liveness: liveness,
            suppressedSet: suppressedSet,
            functionReturnsValue: returnsValue,
            resolver: resolver,
            trackedExprByGPReg: &trackedExprByGPReg,
            definedArgRegsSinceLastCall: &definedArgRegsSinceLastCall,
            stmts: &stmts
        )
    }

    private func finishCallEmission(
        callTarget: MicroExpr,
        arguments: [MicroExpr],
        returnType: CTypeExpr,
        isTailCall: Bool,
        insnIdx: Int,
        origin: VirtualAddress,
        block: BasicBlock,
        function: RecoveredFunction,
        liveness: FunctionRegisterLiveness,
        suppressedSet: Set<VirtualAddress>,
        functionReturnsValue: Bool,
        resolver: BinaryLiftingResolutionContext,
        trackedExprByGPReg: inout [UInt8: MicroExpr],
        definedArgRegsSinceLastCall: inout Set<UInt8>,
        stmts: inout [MicroStmt]
    ) {
        let callExpr = MicroExpr.call(target: callTarget, arguments: arguments, returnType: returnType)

        if isTailCall {
            if returnType == .voidType || !functionReturnsValue {
                stmts.append(MicroStmt(originAddress: origin, kind: .callStmt(target: callTarget, arguments: arguments)))
                stmts.append(MicroStmt(originAddress: origin, kind: .returnStmt(value: nil)))
            } else {
                stmts.append(MicroStmt(originAddress: origin, kind: .returnStmt(value: callExpr)))
            }
        } else {
            let shouldCaptureReturn = returnType != .voidType && isX0ReadAfter(
                insnIndex: insnIdx,
                in: block,
                function: function,
                liveness: liveness,
                suppressed: suppressedSet,
                resolver: resolver,
                functionReturns: functionReturnsValue
            )

            if shouldCaptureReturn {
                let retBits: Int
                if case .intType(let b, _) = returnType, b <= 32 {
                    retBits = 32
                } else if returnType == .boolType {
                    retBits = 32
                } else {
                    retBits = 64
                }
                let dstVar = SSAVar(baseName: "x0", version: 0, bitWidth: retBits, inferredType: returnType)
                stmts.append(MicroStmt(originAddress: origin, kind: .assign(dest: dstVar, expr: callExpr)))
            } else {
                stmts.append(MicroStmt(originAddress: origin, kind: .callStmt(target: callTarget, arguments: arguments)))
            }
        }

        // Clobber volatile caller-saved registers x0..x18 after the call
        for regIdx: UInt8 in 0...18 {
            trackedExprByGPReg.removeValue(forKey: regIdx)
        }
        definedArgRegsSinceLastCall.removeAll()
        if returnType != .voidType {
            definedArgRegsSinceLastCall.insert(0)
        }
    }

    private func isX0ReadAfter(
        insnIndex: Int,
        in block: BasicBlock,
        function: RecoveredFunction,
        liveness: FunctionRegisterLiveness,
        suppressed: Set<VirtualAddress>,
        resolver: BinaryLiftingResolutionContext,
        functionReturns: Bool
    ) -> Bool {
        if insnIndex + 1 < block.instructions.count {
            for laterIdx in (insnIndex + 1)..<block.instructions.count {
                let later = block.instructions[laterIdx]
                if suppressed.contains(later.address) {
                    continue
                }
                if later.readsRegisters.contains(where: { ($0.bank == .gp64 || $0.bank == .gp32) && $0.index == 0 }) {
                    return true
                }
                if case .returnControl = later.flow {
                    return functionReturns
                }
                if case .directCall(let nextCallee) = later.flow {
                    let sym = resolver.resolveCallTargetName(callSite: later.address, targetAddress: nextCallee)
                    if let proto = KnownFunctionSignatureCatalog.lookup(sym) {
                        return !proto.fixedParameterTypes.isEmpty
                    }
                    if let arity = resolver.calleeArity(for: nextCallee) {
                        return arity >= 1
                    }
                    return true
                }
                if case .indirectCall = later.flow {
                    return true
                }
                if later.writesRegisters.contains(where: { ($0.bank == .gp64 || $0.bank == .gp32) && $0.index == 0 }) {
                    return false
                }
            }
        }
        if (liveness.liveOutByBlock[block.id] ?? []).contains(0) {
            return true
        }
        if block.isExit && block.successorIDs.isEmpty {
            return functionReturns
        }
        return false
    }

    // MARK: - Condition Materialization & Operand Helpers

    private func materializeCondition(
        _ cond: A64ConditionCode,
        flags: TrackedFlagComparison?
    ) -> MicroExpr {
        if cond == .al || cond == .nv {
            return .unsignedConst(1, bits: 1)
        }

        guard let f = flags else {
            return .symbolRef(name: "cond_\(cond.mnemonicSuffix)", address: .zero)
        }

        let core: MicroExpr
        switch cond {
        case .eq:
            core = .binary(.equal, f.lhs, f.rhs)
        case .ne:
            core = .binary(.notEqual, f.lhs, f.rhs)
        case .cs:
            core = .binary(.unsignedGreaterEqual, f.lhs, f.rhs)
        case .cc:
            core = .binary(.unsignedLess, f.lhs, f.rhs)
        case .hi:
            core = .binary(.unsignedGreater, f.lhs, f.rhs)
        case .ls:
            core = .binary(.unsignedLessEqual, f.lhs, f.rhs)
        case .ge:
            core = .binary(.signedGreaterEqual, f.lhs, f.rhs)
        case .lt:
            core = .binary(.signedLess, f.lhs, f.rhs)
        case .gt:
            core = .binary(.signedGreater, f.lhs, f.rhs)
        case .le:
            core = .binary(.signedLessEqual, f.lhs, f.rhs)
        case .mi:
            if Self.isZeroConstant(f.rhs) {
                core = .binary(.signedLess, f.lhs, .signedConst(0, bits: f.bitWidth))
            } else {
                core = .binary(.signedLess, .binary(.sub, f.lhs, f.rhs), .signedConst(0, bits: f.bitWidth))
            }
        case .pl:
            if Self.isZeroConstant(f.rhs) {
                core = .binary(.signedGreaterEqual, f.lhs, .signedConst(0, bits: f.bitWidth))
            } else {
                core = .binary(.signedGreaterEqual, .binary(.sub, f.lhs, f.rhs), .signedConst(0, bits: f.bitWidth))
            }
        case .vs:
            core = .symbolRef(name: "__overflow", address: .zero)
        case .vc:
            core = .unary(.logicalNot, .symbolRef(name: "__overflow", address: .zero))
        case .al, .nv:
            core = .unsignedConst(1, bits: 1)
        }

        if let compound = f.compoundPrefix {
            return .binary(compound.op, compound.priorExpr, core)
        }
        return core
    }

    private func resolveAddressValueExpr(
        _ targetAddress: VirtualAddress,
        resolver: BinaryLiftingResolutionContext
    ) -> MicroExpr {
        if let str = resolver.resolveString(at: targetAddress) {
            return .stringLiteral(str, address: targetAddress)
        }
        if let sym = resolver.resolveSymbol(at: targetAddress) {
            return .symbolRef(name: sym, address: targetAddress)
        }
        return .unsignedConst(targetAddress.rawValue, bits: 64)
    }

    private func makeConstantOrSymbolExpr(
        value: UInt64,
        bits: Int,
        at origin: VirtualAddress,
        resolver: BinaryLiftingResolutionContext
    ) -> MicroExpr {
        let _ = origin
        if bits == 64 && value >= 0x100000000 {
            let addr = VirtualAddress(value)
            if let str = resolver.resolveString(at: addr) {
                return .stringLiteral(str, address: addr)
            }
            if let sym = resolver.resolveSymbol(at: addr) {
                return .symbolRef(name: sym, address: addr)
            }
        }
        return .unsignedConst(value, bits: bits)
    }

    private func readRegisterExpr(_ reg: A64Register) -> MicroExpr {
        if reg.isZeroRegister {
            return .unsignedConst(0, bits: reg.bitWidth)
        }
        return .variable(Self.makeSSAVar(for: reg))
    }

    private func liftOperandExpr(_ operand: A64Operand, defaultBits: Int) -> MicroExpr {
        switch operand {
        case .register(let reg):
            return readRegisterExpr(reg)
        case .immediate(let val):
            return .signedConst(val, bits: defaultBits)
        case .unsignedImmediate(let val):
            return .unsignedConst(val, bits: defaultBits)
        case .fpImmediate(let d):
            return .floatConst(d)
        case .branchTarget(let addr):
            return .unsignedConst(addr.rawValue, bits: 64)
        case .shiftedImmediate(let val, let shift):
            return .unsignedConst(val << Int(shift), bits: defaultBits)
        case .shiftedRegister(let reg, let shiftExtend):
            return applyShiftExtend(to: readRegisterExpr(reg), clause: shiftExtend, resultBits: defaultBits)
        case .memory(let mode):
            switch mode {
            case .baseOffset(let b, let off): return buildOffsetAddressExpr(base: b, byteOffset: off)
            case .preIndex(let b, let off):   return buildOffsetAddressExpr(base: b, byteOffset: off)
            case .postIndex(let b, _):        return readRegisterExpr(b)
            case .registerOffset(let b, let idx, let ext):
                return .binary(.add, readRegisterExpr(b), liftExtendedIndexExpr(index: idx, extend: ext))
            case .pcRelativeLiteral(let tgt):
                return .unsignedConst(tgt.rawValue, bits: 64)
            }
        case .condition(let cond):
            return .symbolRef(name: cond.mnemonicSuffix, address: .zero)
        case .systemRegister(let name, _):
            return .symbolRef(name: name, address: .zero)
        case .barrierOption(let opt):
            return .symbolRef(name: opt, address: .zero)
        case .prefetchOp(let op):
            return .symbolRef(name: op, address: .zero)
        }
    }

    private func liftExtendedIndexExpr(index: A64Register, extend: A64ShiftExtend?) -> MicroExpr {
        let raw = readRegisterExpr(index)
        guard let extend else { return raw }
        return applyShiftExtend(to: raw, clause: extend, resultBits: 64)
    }

    private func applyShiftExtend(to expr: MicroExpr, clause: A64ShiftExtend, resultBits: Int) -> MicroExpr {
        switch clause {
        case .lsl(let n):
            return n == 0 ? expr : .binary(.shiftLeft, expr, .unsignedConst(UInt64(n), bits: resultBits))
        case .lsr(let n):
            return n == 0 ? expr : .binary(.shiftRightLogical, expr, .unsignedConst(UInt64(n), bits: resultBits))
        case .asr(let n):
            return n == 0 ? expr : .binary(.shiftRightArithmetic, expr, .unsignedConst(UInt64(n), bits: resultBits))
        case .ror(let n):
            if n == 0 { return expr }
            let hi = MicroExpr.binary(.shiftLeft, expr, .unsignedConst(UInt64(resultBits - Int(n)), bits: resultBits))
            let lo = MicroExpr.binary(.shiftRightLogical, expr, .unsignedConst(UInt64(n), bits: resultBits))
            return .binary(.bitwiseOr, lo, hi)
        case .uxtb(let s):
            let ext = MicroExpr.binary(.bitwiseAnd, expr, .unsignedConst(0xFF, bits: resultBits))
            return s == 0 ? ext : .binary(.shiftLeft, ext, .unsignedConst(UInt64(s), bits: resultBits))
        case .uxth(let s):
            let ext = MicroExpr.binary(.bitwiseAnd, expr, .unsignedConst(0xFFFF, bits: resultBits))
            return s == 0 ? ext : .binary(.shiftLeft, ext, .unsignedConst(UInt64(s), bits: resultBits))
        case .uxtw(let s):
            let ext = MicroExpr.unary(.zeroExtend, expr)
            return s == 0 ? ext : .binary(.shiftLeft, ext, .unsignedConst(UInt64(s), bits: resultBits))
        case .uxtx(let s):
            return s == 0 ? expr : .binary(.shiftLeft, expr, .unsignedConst(UInt64(s), bits: resultBits))
        case .sxtb(let s), .sxth(let s), .sxtw(let s):
            let ext = MicroExpr.unary(.signExtend, expr)
            return s == 0 ? ext : .binary(.shiftLeft, ext, .unsignedConst(UInt64(s), bits: resultBits))
        case .sxtx(let s):
            return s == 0 ? expr : .binary(.shiftLeft, expr, .unsignedConst(UInt64(s), bits: resultBits))
        }
    }

    private func buildOffsetAddressExpr(base: A64Register, byteOffset: Int64) -> MicroExpr {
        buildOffsetAddressExpr(baseExpr: readRegisterExpr(base), byteOffset: byteOffset)
    }

    private func buildOffsetAddressExpr(baseExpr: MicroExpr, byteOffset: Int64) -> MicroExpr {
        if byteOffset == 0 {
            return baseExpr
        }
        if byteOffset > 0 {
            return .binary(.add, baseExpr, .unsignedConst(UInt64(bitPattern: byteOffset), bits: 64))
        }
        return .binary(.sub, baseExpr, .unsignedConst(UInt64(bitPattern: -byteOffset), bits: 64))
    }

    // MARK: - Static Utilities

    internal static func canonicalBaseName(for reg: A64Register) -> String {
        switch reg.bank {
        case .gp64, .gp32:
            return "x\(reg.index)"
        case .stackPointer:
            return "sp"
        case .zeroRegister:
            return "xzr"
        case .simdByte, .simdHalf, .simdSingle, .simdDouble, .simdQuad, .simdVector:
            return "v\(reg.index)"
        case .special:
            return reg.canonicalName
        }
    }

    internal static func makeSSAVar(for reg: A64Register) -> SSAVar {
        let type: CTypeExpr = reg.isSIMD
            ? .floatType(bits: min(64, max(32, reg.bitWidth)))
            : .intType(bits: reg.bitWidth, signed: false)
        return SSAVar(
            baseName: canonicalBaseName(for: reg),
            version: 0,
            bitWidth: reg.bitWidth,
            inferredType: type
        )
    }

    private static func coerceWidth(_ expr: MicroExpr, targetBits: Int) -> MicroExpr {
        switch expr {
        case .unsignedConst(let v, _):
            let mask: UInt64 = targetBits == 32 ? 0xFFFF_FFFF : UInt64.max
            return .unsignedConst(v & mask, bits: targetBits)
        case .signedConst(let v, _):
            if targetBits == 32 {
                let trunc = Int64(Int32(truncatingIfNeeded: v))
                return .signedConst(trunc, bits: 32)
            }
            return expr
        default:
            return expr
        }
    }

    private static func singleLoadSpec(
        for mnemonic: A64Mnemonic,
        destReg: A64Register
    ) -> (bits: Int, type: CTypeExpr, signExtend: Bool) {
        switch mnemonic {
        case .ldrb, .ldurb, .ldarb:
            return (8, .intType(bits: 8, signed: false), false)
        case .ldrsb, .ldursb:
            return (8, .intType(bits: 8, signed: true), true)
        case .ldrh, .ldurh, .ldarh:
            return (16, .intType(bits: 16, signed: false), false)
        case .ldrsh, .ldursh:
            return (16, .intType(bits: 16, signed: true), true)
        case .ldrsw, .ldursw:
            return (32, .intType(bits: 32, signed: true), true)
        default:
            let bits = destReg.bitWidth
            let ty: CTypeExpr = destReg.isSIMD ? .floatType(bits: bits) : .intType(bits: bits, signed: false)
            return (bits, ty, false)
        }
    }

    private static func storeBitWidth(for insn: A64DecodedInstruction) -> Int {
        switch insn.mnemonic {
        case .strb, .sturb, .stlrb: return 8
        case .strh, .sturh, .stlrh: return 16
        default:
            if let first = insn.operands.first, case .register(let r) = first {
                return r.bitWidth
            }
            return 64
        }
    }

    private static func operandBitWidth(_ op: A64Operand) -> Int {
        if case .register(let r) = op {
            return r.bitWidth
        }
        if case .shiftedRegister(let r, _) = op {
            return r.bitWidth
        }
        return 64
    }

    private static func extractShiftedUnsignedImm(_ op: A64Operand) -> UInt64? {
        switch op {
        case .unsignedImmediate(let v):
            return v
        case .immediate(let v):
            return UInt64(bitPattern: v)
        case .shiftedImmediate(let v, let s):
            return v << Int(s)
        default:
            return nil
        }
    }

    private static func extractImmediateInt64(_ op: A64Operand) -> Int64? {
        switch op {
        case .immediate(let v):
            return v
        case .unsignedImmediate(let v):
            return Int64(bitPattern: v)
        case .shiftedImmediate(let v, let s):
            return Int64(bitPattern: v << Int(s))
        default:
            return nil
        }
    }

    private static func extractLaneAndShift(_ op: A64Operand) -> (UInt64, UInt8) {
        switch op {
        case .unsignedImmediate(let v):
            return (v & 0xFFFF, 0)
        case .immediate(let v):
            return (UInt64(bitPattern: v) & 0xFFFF, 0)
        case .shiftedImmediate(let v, let s):
            return (v & 0xFFFF, s)
        default:
            return (0, 0)
        }
    }

    private static func isZeroConstant(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .unsignedConst(0, _), .signedConst(0, _):
            return true
        default:
            return false
        }
    }

    internal static func negateConditionExpr(_ expr: MicroExpr) -> MicroExpr {
        switch expr {
        case .unary(.logicalNot, let inner):
            return inner
        case .binary(let op, let lhs, let rhs):
            switch op {
            case .equal:                return .binary(.notEqual, lhs, rhs)
            case .notEqual:             return .binary(.equal, lhs, rhs)
            case .unsignedLess:         return .binary(.unsignedGreaterEqual, lhs, rhs)
            case .unsignedLessEqual:    return .binary(.unsignedGreater, lhs, rhs)
            case .unsignedGreater:      return .binary(.unsignedLessEqual, lhs, rhs)
            case .unsignedGreaterEqual: return .binary(.unsignedLess, lhs, rhs)
            case .signedLess:           return .binary(.signedGreaterEqual, lhs, rhs)
            case .signedLessEqual:      return .binary(.signedGreater, lhs, rhs)
            case .signedGreater:        return .binary(.signedLessEqual, lhs, rhs)
            case .signedGreaterEqual:   return .binary(.signedLess, lhs, rhs)
            default:                    return .unary(.logicalNot, expr)
            }
        default:
            return .unary(.logicalNot, expr)
        }
    }

    private static func contiguousLeadingCount(in regIndices: Set<UInt8>) -> Int {
        var count = 0
        for i: UInt8 in 0..<8 {
            if regIndices.contains(i) {
                count += 1
            } else {
                break
            }
        }
        return count
    }

    internal static func isTerminatorStmt(_ kind: MicroStmtKind) -> Bool {
        switch kind {
        case .conditionalBranch, .jump, .switchJump, .returnStmt:
            return true
        default:
            return false
        }
    }
}
