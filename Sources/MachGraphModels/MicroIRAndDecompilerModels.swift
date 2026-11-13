import Foundation

// MARK: - C Types & SSA Variables

public indirect enum CTypeExpr: Sendable, Codable, Hashable, CustomStringConvertible {
    case voidType
    case boolType
    case intType(bits: Int, signed: Bool)
    case floatType(bits: Int)
    case pointer(to: CTypeExpr)
    case cString
    case objcObject(className: String?)
    case structRef(name: String)
    case unknownBits(Int)

    public var cTypeName: String {
        switch self {
        case .voidType:
            return "void"
        case .boolType:
            return "bool"
        case .intType(let bits, let signed):
            let prefix = signed ? "int" : "uint"
            switch bits {
            case 8: return "\(prefix)8_t"
            case 16: return "\(prefix)16_t"
            case 32: return "\(prefix)32_t"
            default: return "\(prefix)64_t"
            }
        case .floatType(let bits):
            return bits <= 32 ? "float" : "double"
        case .pointer(let inner):
            if inner == .voidType { return "void *" }
            return "\(inner.cTypeName) *"
        case .cString:
            return "const char *"
        case .objcObject(let cls):
            if let cls { return "\(cls) *" }
            return "id"
        case .structRef(let name):
            return "struct \(name)"
        case .unknownBits(let bits):
            return bits <= 32 ? "uint32_t" : "uint64_t"
        }
    }

    public var description: String { cTypeName }
}

public struct SSAVar: Sendable, Codable, Hashable, CustomStringConvertible {
    public let baseName: String
    public let version: Int
    public let bitWidth: Int
    public let inferredType: CTypeExpr

    public init(
        baseName: String,
        version: Int = 0,
        bitWidth: Int = 64,
        inferredType: CTypeExpr = .intType(bits: 64, signed: false)
    ) {
        self.baseName = baseName
        self.version = version
        self.bitWidth = bitWidth
        self.inferredType = inferredType
    }

    public var displayName: String {
        version == 0 ? baseName : "\(baseName)_\(version)"
    }

    public var description: String { displayName }
}

// MARK: - Micro-IR Expressions & Statements

public enum MicroUnaryOp: String, Sendable, Codable, Hashable {
    case negate = "-"
    case bitwiseNot = "~"
    case logicalNot = "!"
    case zeroExtend = "zext"
    case signExtend = "sext"
    case byteSwap = "bswap"
}

public enum MicroBinaryOp: String, Sendable, Codable, Hashable {
    case add = "+"
    case sub = "-"
    case mul = "*"
    case udiv = "/"
    case sdiv = "/s"
    case umod = "%"
    case bitwiseAnd = "&"
    case bitwiseOr = "|"
    case bitwiseXor = "^"
    case shiftLeft = "<<"
    case shiftRightLogical = ">>"
    case shiftRightArithmetic = ">>s"
    case equal = "=="
    case notEqual = "!="
    case unsignedLess = "<u"
    case unsignedLessEqual = "<=u"
    case unsignedGreater = ">u"
    case unsignedGreaterEqual = ">=u"
    case signedLess = "<"
    case signedLessEqual = "<="
    case signedGreater = ">"
    case signedGreaterEqual = ">="
    case logicalAnd = "&&"
    case logicalOr = "||"

    public var cOperatorText: String {
        switch self {
        case .sdiv: return "/"
        case .shiftRightArithmetic: return ">>"
        case .unsignedLess: return "<"
        case .unsignedLessEqual: return "<="
        case .unsignedGreater: return ">"
        case .unsignedGreaterEqual: return ">="
        default: return rawValue
        }
    }
}

public struct PhiIncoming: Sendable, Codable, Hashable {
    public let predecessorBlockID: Int
    public let variable: SSAVar

    public init(predecessorBlockID: Int, variable: SSAVar) {
        self.predecessorBlockID = predecessorBlockID
        self.variable = variable
    }
}

public indirect enum MicroExpr: Sendable, Codable, Hashable {
    case signedConst(Int64, bits: Int)
    case unsignedConst(UInt64, bits: Int)
    case floatConst(Double)
    case stringLiteral(String, address: VirtualAddress)
    case symbolRef(name: String, address: VirtualAddress)
    case variable(SSAVar)
    case unary(MicroUnaryOp, MicroExpr)
    case binary(MicroBinaryOp, MicroExpr, MicroExpr)
    case load(address: MicroExpr, bits: Int, type: CTypeExpr)
    case call(target: MicroExpr, arguments: [MicroExpr], returnType: CTypeExpr)
    case phi([PhiIncoming])
    case cast(MicroExpr, to: CTypeExpr)
    case ternary(condition: MicroExpr, thenExpr: MicroExpr, elseExpr: MicroExpr)
}

public struct SwitchCaseTarget: Sendable, Codable, Hashable {
    public let caseValue: Int64
    public let targetBlockID: Int

    public init(caseValue: Int64, targetBlockID: Int) {
        self.caseValue = caseValue
        self.targetBlockID = targetBlockID
    }
}

public enum MicroStmtKind: Sendable, Codable, Hashable {
    case assign(dest: SSAVar, expr: MicroExpr)
    case store(address: MicroExpr, value: MicroExpr, bits: Int)
    case callStmt(target: MicroExpr, arguments: [MicroExpr])
    case conditionalBranch(condition: MicroExpr, trueBlockID: Int, falseBlockID: Int)
    case jump(targetBlockID: Int)
    case switchJump(selector: MicroExpr, cases: [SwitchCaseTarget], defaultBlockID: Int)
    case returnStmt(value: MicroExpr?)
    case intrinsic(name: String, arguments: [MicroExpr])
    case nop
}

public struct MicroStmt: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let originAddress: VirtualAddress
    public let kind: MicroStmtKind

    public init(id: UUID = UUID(), originAddress: VirtualAddress, kind: MicroStmtKind) {
        self.id = id
        self.originAddress = originAddress
        self.kind = kind
    }
}

public struct MicroBasicBlock: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { blockID }
    public let blockID: Int
    public let startAddress: VirtualAddress
    public let statements: [MicroStmt]

    public init(blockID: Int, startAddress: VirtualAddress, statements: [MicroStmt]) {
        self.blockID = blockID
        self.startAddress = startAddress
        self.statements = statements
    }
}

// MARK: - Structured Pseudo-C AST & Syntax Highlighted Output

public struct StructuredSwitchArm: Sendable, Codable, Hashable {
    public let caseValues: [Int64]
    public let body: [PseudoCStatement]

    public init(caseValues: [Int64], body: [PseudoCStatement]) {
        self.caseValues = caseValues
        self.body = body
    }
}

public indirect enum PseudoCStatement: Sendable, Codable, Hashable {
    case varDecl(name: String, type: CTypeExpr, initialValue: String?, address: VirtualAddress?)
    case assignment(lhs: String, rhs: String, address: VirtualAddress)
    case exprStmt(expression: String, address: VirtualAddress)
    case ifStmt(condition: String, address: VirtualAddress, thenBody: [PseudoCStatement], elseBody: [PseudoCStatement])
    case whileLoop(condition: String, address: VirtualAddress, body: [PseudoCStatement])
    case doWhileLoop(body: [PseudoCStatement], condition: String, address: VirtualAddress)
    case switchStmt(selector: String, address: VirtualAddress, arms: [StructuredSwitchArm], defaultBody: [PseudoCStatement])
    case returnStmt(expression: String?, address: VirtualAddress)
    case gotoStmt(label: String, address: VirtualAddress)
    case labelDecl(name: String, address: VirtualAddress)
    case breakStmt
    case continueStmt
    case comment(String)
}

public enum PseudoCTokenKind: String, Sendable, Codable, Hashable {
    case keyword
    case typeName
    case functionName
    case variableName
    case numericLiteral
    case stringLiteral
    case punctuation
    case comment
    case plain
}

public struct PseudoCToken: Sendable, Codable, Hashable {
    public let kind: PseudoCTokenKind
    public let text: String

    public init(kind: PseudoCTokenKind, text: String) {
        self.kind = kind
        self.text = text
    }
}

public struct PseudoCLineSpan: Sendable, Codable, Hashable, Identifiable {
    public var id: Int { lineNumber }
    public let lineNumber: Int
    public let indentationLevel: Int
    public let text: String
    public let tokens: [PseudoCToken]
    public let mappedAddress: VirtualAddress?

    public init(
        lineNumber: Int,
        indentationLevel: Int = 0,
        text: String,
        tokens: [PseudoCToken],
        mappedAddress: VirtualAddress? = nil
    ) {
        self.lineNumber = lineNumber
        self.indentationLevel = indentationLevel
        self.text = text
        self.tokens = tokens
        self.mappedAddress = mappedAddress
    }
}

public struct NamedParameterDecl: Sendable, Codable, Hashable {
    public let name: String
    public let type: CTypeExpr

    public init(name: String, type: CTypeExpr) {
        self.name = name
        self.type = type
    }
}

public struct DecompiledFunctionOutput: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { functionAddress.rawValue }
    public let functionAddress: VirtualAddress
    public let functionName: String
    public let signatureLine: String
    public let returnType: CTypeExpr
    public let parameters: [NamedParameterDecl]
    public let localVariables: [NamedParameterDecl]
    public let microBlocks: [MicroBasicBlock]
    public let structuredBody: [PseudoCStatement]
    public let renderedLines: [PseudoCLineSpan]
    public let fullSourceText: String
    public let ghidraSideBySideSource: String?
    public let ssaVariableCount: Int
    public let eliminatedDeadStoreCount: Int
    public let confidenceScore: Double

    public init(
        functionAddress: VirtualAddress,
        functionName: String,
        signatureLine: String,
        returnType: CTypeExpr,
        parameters: [NamedParameterDecl],
        localVariables: [NamedParameterDecl],
        microBlocks: [MicroBasicBlock],
        structuredBody: [PseudoCStatement],
        renderedLines: [PseudoCLineSpan],
        fullSourceText: String,
        ghidraSideBySideSource: String? = nil,
        ssaVariableCount: Int = 0,
        eliminatedDeadStoreCount: Int = 0,
        confidenceScore: Double = 0.92
    ) {
        self.functionAddress = functionAddress
        self.functionName = functionName
        self.signatureLine = signatureLine
        self.returnType = returnType
        self.parameters = parameters
        self.localVariables = localVariables
        self.microBlocks = microBlocks
        self.structuredBody = structuredBody
        self.renderedLines = renderedLines
        self.fullSourceText = fullSourceText
        self.ghidraSideBySideSource = ghidraSideBySideSource
        self.ssaVariableCount = ssaVariableCount
        self.eliminatedDeadStoreCount = eliminatedDeadStoreCount
        self.confidenceScore = confidenceScore
    }
}
