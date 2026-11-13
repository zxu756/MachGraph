import Foundation
import MachGraphModels
import MachA64Decoder
import MachCFGEngine

// MARK: - Out-of-SSA Phi Coalescer & Local Variable Lowering

internal struct OutOfSSALoweredFunction: Sendable {
    let blocks: [MicroBasicBlock]
    let variableNameByKey: [SSAVarKey: String]
    let localVariableDecls: [NamedParameterDecl]
    let coalescedWebCount: Int
}

internal struct OutOfSSACoalescer: Sendable {

    func lowerFromSSA(_ optimized: SSAOptimizedFunctionIR) -> OutOfSSALoweredFunction {
        let blocks = optimized.ssaBlocks
        guard !blocks.isEmpty else {
            return OutOfSSALoweredFunction(
                blocks: [],
                variableNameByKey: [:],
                localVariableDecls: [],
                coalescedWebCount: 0
            )
        }

        let paramKeys = Set(optimized.parameterSSAVars.map { SSAVarKey($0) })
        var typeByKey: [SSAVarKey: CTypeExpr] = [:]
        var nameByKey: [SSAVarKey: String] = [:]
        for (v, ty) in optimized.variableTypes {
            typeByKey[SSAVarKey(v)] = ty
        }
        for (v, nm) in optimized.variableDisplayNames {
            nameByKey[SSAVarKey(v)] = nm
        }

        // Build per-block def & last-use indices to check intra-block interference cleanly
        var defLocByKey: [SSAVarKey: (blockID: Int, stmtIdx: Int)] = [:]
        var usesByKeyInBlock: [SSAVarKey: [Int: [Int]]] = [:]
        var returnedVarKeys = Set<SSAVarKey>()

        for block in blocks {
            for (sIdx, stmt) in block.statements.enumerated() {
                if case .assign(let dest, _) = stmt.kind {
                    defLocByKey[SSAVarKey(dest)] = (block.blockID, sIdx)
                }
                if case .returnStmt(.variable(let rv)?) = stmt.kind {
                    returnedVarKeys.insert(SSAVarKey(rv))
                }
                CytronSSAPhiAndOptimizerEngine.forEachReadVar(in: stmt.kind) { rv in
                    let rk = SSAVarKey(rv)
                    var bMap = usesByKeyInBlock[rk] ?? [:]
                    bMap[block.blockID, default: []].append(sIdx)
                    usesByKeyInBlock[rk] = bMap
                }
            }
        }

        // Identify induction-like Phi nodes (`0` init + `+ 1` / `- 1` step) for idiomatic `i, j, k` naming
        var inductionPhiKeys = Set<SSAVarKey>()
        var defExprByKey: [SSAVarKey: MicroExpr] = [:]
        for block in blocks {
            for stmt in block.statements {
                if case .assign(let dest, let expr) = stmt.kind {
                    defExprByKey[SSAVarKey(dest)] = expr
                }
            }
        }
        for block in blocks {
            for stmt in block.statements {
                guard case .assign(let phiDest, .phi(let incomings)) = stmt.kind,
                      incomings.count == 2 else { continue }
                let phiKey = SSAVarKey(phiDest)
                var sawZeroInit = false
                var sawStep = false
                for inc in incomings {
                    let ik = SSAVarKey(inc.variable)
                    if let rhs = defExprByKey[ik] {
                        if CytronSSAPhiAndOptimizerEngine.isZeroConstant(rhs) {
                            sawZeroInit = true
                        } else if case .binary(let op, .variable(let lv), _) = rhs,
                                  (op == .add || op == .sub),
                                  SSAVarKey(lv) == phiKey {
                            sawStep = true
                        }
                    }
                }
                if sawZeroInit && sawStep {
                    inductionPhiKeys.insert(phiKey)
                }
            }
        }

        // Coalesce Phi congruence webs greedily without merging immutable parameters or interfering live ranges
        var webIDByKey: [SSAVarKey: Int] = [:]
        var membersByWebID: [Int: [SSAVarKey]] = [:]
        var nextWebID = 1

        // Pending predecessor copy insertions when an incoming operand cannot be coalesced into the Phi's web
        var pendingCopiesByPredBlock: [Int: [(origin: VirtualAddress, destVar: SSAVar, srcVar: SSAVar)]] = [:]

        func interfereInSameBlock(_ a: SSAVarKey, _ b: SSAVarKey) -> Bool {
            guard a != b else { return false }
            // Check if `a` is defined in block B at sA while `b` is read AFTER sA in B (and defined before sA or live-in)
            if let defA = defLocByKey[a],
               let usesB = usesByKeyInBlock[b]?[defA.blockID] {
                let defBInSame = defLocByKey[b]?.blockID == defA.blockID ? defLocByKey[b]!.stmtIdx : -1
                if defBInSame < defA.stmtIdx && usesB.contains(where: { $0 > defA.stmtIdx }) {
                    return true
                }
            }
            if let defB = defLocByKey[b],
               let usesA = usesByKeyInBlock[a]?[defB.blockID] {
                let defAInSame = defLocByKey[a]?.blockID == defB.blockID ? defLocByKey[a]!.stmtIdx : -1
                if defAInSame < defB.stmtIdx && usesA.contains(where: { $0 > defB.stmtIdx }) {
                    return true
                }
            }
            return false
        }

        func canJoinWeb(_ candidate: SSAVarKey, webID: Int) -> Bool {
            if paramKeys.contains(candidate) || candidate.version == 0 {
                return false
            }
            if let existingWeb = webIDByKey[candidate] {
                return existingWeb == webID
            }
            for member in membersByWebID[webID] ?? [] {
                if interfereInSameBlock(candidate, member) {
                    return false
                }
            }
            return true
        }

        for block in blocks {
            for stmt in block.statements {
                guard case .assign(let phiDest, .phi(let incomings)) = stmt.kind else { continue }
                let destKey = SSAVarKey(phiDest)
                let webID: Int
                if let existing = webIDByKey[destKey] {
                    webID = existing
                } else {
                    webID = nextWebID
                    nextWebID += 1
                    webIDByKey[destKey] = webID
                    membersByWebID[webID] = [destKey]
                }

                for inc in incomings {
                    let incKey = SSAVarKey(inc.variable)
                    if incKey == destKey {
                        continue
                    }
                    if canJoinWeb(incKey, webID: webID) {
                        if webIDByKey[incKey] == nil {
                            webIDByKey[incKey] = webID
                            membersByWebID[webID, default: []].append(incKey)
                        }
                    } else {
                        // Cannot coalesce directly -> schedule explicit assignment `phiDest = inc.variable` at end of `predecessorBlockID`
                        pendingCopiesByPredBlock[inc.predecessorBlockID, default: []].append(
                            (origin: stmt.originAddress, destVar: phiDest, srcVar: inc.variable)
                        )
                    }
                }
            }
        }

        // Also coalesce non-SSA stack local slots (`local_10_1`, `local_10_2`) sharing the same `local_*` baseName
        var localKeysByBase: [String: [SSAVarKey]] = [:]
        for key in defLocByKey.keys.sorted() where key.baseName.hasPrefix("local_") {
            localKeysByBase[key.baseName, default: []].append(key)
        }
        for (_, keys) in localKeysByBase where keys.count >= 2 {
            let wID = webIDByKey[keys[0]] ?? {
                let id = nextWebID
                nextWebID += 1
                webIDByKey[keys[0]] = id
                membersByWebID[id] = [keys[0]]
                return id
            }()
            for k in keys.dropFirst() where webIDByKey[k] == nil {
                webIDByKey[k] = wID
                membersByWebID[wID, default: []].append(k)
            }
        }

        // Assign clean, meaningful C names to every coalesced Phi web
        var usedNames = Set(paramKeys.compactMap { nameByKey[$0] })
        let loopCounterNames = ["i", "j", "k", "idx"]
        var loopCounterIdx = 0
        var resultNamed = false

        var webNameByID: [Int: String] = [:]
        var webTypeByID: [Int: CTypeExpr] = [:]

        for webID in membersByWebID.keys.sorted() {
            let members = membersByWebID[webID] ?? []
            guard !members.isEmpty else { continue }

            // Compute unified C type for the web
            var mergedType = typeByKey[members[0]] ?? .intType(bits: 64, signed: false)
            for m in members.dropFirst() {
                if let mTy = typeByKey[m],
                   CytronSSAPhiAndOptimizerEngine.typeSpecificityRank(mTy) > CytronSSAPhiAndOptimizerEngine.typeSpecificityRank(mergedType) {
                    mergedType = mTy
                }
            }
            webTypeByID[webID] = mergedType

            let chosenName: String
            if let localMember = members.first(where: { $0.baseName.hasPrefix("local_") }),
               !usedNames.contains(localMember.baseName) {
                chosenName = localMember.baseName
            } else if members.contains(where: { inductionPhiKeys.contains($0) }) && loopCounterIdx < loopCounterNames.count {
                var candidate = loopCounterNames[loopCounterIdx]
                loopCounterIdx += 1
                while usedNames.contains(candidate) && loopCounterIdx < loopCounterNames.count {
                    candidate = loopCounterNames[loopCounterIdx]
                    loopCounterIdx += 1
                }
                chosenName = usedNames.contains(candidate) ? "idx_\(webID)" : candidate
            } else if !resultNamed && members.contains(where: { returnedVarKeys.contains($0) }) && !usedNames.contains("result") {
                chosenName = "result"
                resultNamed = true
            } else {
                var idx = 1
                var candidate = "v\(idx)"
                while usedNames.contains(candidate) {
                    idx += 1
                    candidate = "v\(idx)"
                }
                chosenName = candidate
            }

            usedNames.insert(chosenName)
            webNameByID[webID] = chosenName
            for m in members {
                nameByKey[m] = chosenName
                typeByKey[m] = mergedType
            }
        }

        // Re-assign clean sequential `v1, v2, ...` names to surviving standalone local SSA variables so there are no gaps/collisions
        var standaloneKeys: [SSAVarKey] = []
        for block in blocks {
            for stmt in block.statements {
                if case .assign(let dest, let expr) = stmt.kind {
                    if case .phi = expr { continue }
                    let k = SSAVarKey(dest)
                    if webIDByKey[k] == nil && !paramKeys.contains(k) && !dest.baseName.hasPrefix("self->") {
                        if !standaloneKeys.contains(k) {
                            standaloneKeys.append(k)
                        }
                    }
                }
            }
        }

        var vSeq = 1
        for k in standaloneKeys {
            if k.baseName.hasPrefix("local_") && !usedNames.contains(k.baseName) {
                nameByKey[k] = k.baseName
                usedNames.insert(k.baseName)
            } else if !resultNamed && returnedVarKeys.contains(k) && standaloneKeys.count == 1 && !usedNames.contains("result") {
                nameByKey[k] = "result"
                usedNames.insert("result")
                resultNamed = true
            } else {
                var cand = "v\(vSeq)"
                vSeq += 1
                while usedNames.contains(cand) {
                    cand = "v\(vSeq)"
                    vSeq += 1
                }
                nameByKey[k] = cand
                usedNames.insert(cand)
            }
        }

        // Strip `.phi` statements and materialize any unmerged predecessor copy assignments before block terminators
        var loweredBlocks: [MicroBasicBlock] = []
        loweredBlocks.reserveCapacity(blocks.count)

        for block in blocks {
            var newStmts: [MicroStmt] = []
            newStmts.reserveCapacity(block.statements.count + 2)

            for stmt in block.statements {
                if case .assign(_, .phi) = stmt.kind {
                    continue
                }
                // Drop self-copies (`x = x`) created by web coalescing
                if case .assign(let dest, .variable(let src)) = stmt.kind {
                    let dn = nameByKey[SSAVarKey(dest)] ?? dest.displayName
                    let sn = nameByKey[SSAVarKey(src)] ?? src.displayName
                    if dn == sn {
                        continue
                    }
                }
                newStmts.append(stmt)
            }

            if let copies = pendingCopiesByPredBlock[block.blockID], !copies.isEmpty {
                // Parallel-copy safe staging if two copies read & write overlapping C names
                let copyStmts = buildParallelCopyStatements(copies, nameByKey: nameByKey, defaultOrigin: block.startAddress)
                if let last = newStmts.last, ARM64ToMicroIRLifter.isTerminatorStmt(last.kind) {
                    newStmts.insert(contentsOf: copyStmts, at: newStmts.count - 1)
                } else {
                    newStmts.append(contentsOf: copyStmts)
                }
            }

            loweredBlocks.append(MicroBasicBlock(blockID: block.blockID, startAddress: block.startAddress, statements: newStmts))
        }

        // Collect deduplicated `localVariableDecls` in first-appearance order
        var seenLocalNames = Set<String>()
        var localDecls: [NamedParameterDecl] = []
        let paramNames = Set(optimized.inferredParameters.map(\.name))

        for block in loweredBlocks {
            for stmt in block.statements {
                if case .assign(let dest, _) = stmt.kind {
                    if dest.baseName.hasPrefix("self->") { continue }
                    let k = SSAVarKey(dest)
                    let cName = nameByKey[k] ?? dest.displayName
                    if !paramNames.contains(cName) && seenLocalNames.insert(cName).inserted {
                        let cType = typeByKey[k] ?? dest.inferredType
                        localDecls.append(NamedParameterDecl(name: cName, type: cType))
                    }
                }
            }
        }

        return OutOfSSALoweredFunction(
            blocks: loweredBlocks,
            variableNameByKey: nameByKey,
            localVariableDecls: localDecls,
            coalescedWebCount: membersByWebID.count
        )
    }

    private func buildParallelCopyStatements(
        _ copies: [(origin: VirtualAddress, destVar: SSAVar, srcVar: SSAVar)],
        nameByKey: [SSAVarKey: String],
        defaultOrigin: VirtualAddress
    ) -> [MicroStmt] {
        var filtered: [(origin: VirtualAddress, destVar: SSAVar, srcVar: SSAVar, dstName: String, srcName: String)] = []
        for item in copies {
            let dn = nameByKey[SSAVarKey(item.destVar)] ?? item.destVar.displayName
            let sn = nameByKey[SSAVarKey(item.srcVar)] ?? item.srcVar.displayName
            if dn != sn {
                filtered.append((item.origin, item.destVar, item.srcVar, dn, sn))
            }
        }
        guard !filtered.isEmpty else { return [] }

        // Check if any destination overwrites a source needed by a later copy in the same parallel batch
        var stmts: [MicroStmt] = []
        var writtenSoFar = Set<String>()
        for (idx, item) in filtered.enumerated() {
            let readLater = filtered[(idx + 1)...].contains { $0.srcName == item.dstName }
            if readLater {
                let tmpVar = SSAVar(
                    baseName: "__phi_tmp_\(idx)",
                    version: 1,
                    bitWidth: item.destVar.bitWidth,
                    inferredType: item.destVar.inferredType
                )
                stmts.append(MicroStmt(originAddress: item.origin, kind: .assign(dest: tmpVar, expr: .variable(item.destVar))))
                stmts.append(MicroStmt(originAddress: item.origin, kind: .assign(dest: item.destVar, expr: .variable(item.srcVar))))
                // Rewrite subsequent reads of `item.dstName`
                for laterIdx in (idx + 1)..<filtered.count where filtered[laterIdx].srcName == item.dstName {
                    let l = filtered[laterIdx]
                    stmts.append(MicroStmt(originAddress: l.origin, kind: .assign(dest: l.destVar, expr: .variable(tmpVar))))
                    writtenSoFar.insert(l.dstName)
                }
            } else if !writtenSoFar.contains(item.dstName) {
                stmts.append(MicroStmt(originAddress: item.origin, kind: .assign(dest: item.destVar, expr: .variable(item.srcVar))))
                writtenSoFar.insert(item.dstName)
            }
        }
        let _ = defaultOrigin
        return stmts
    }
}

// MARK: - C Expression Printer (Precedence-Aware + Array Subscript + Custom Struct Field Offsets)

internal struct MicroCExpressionPrinter: Sendable {
    let variableNameByKey: [SSAVarKey: String]
    let variableTypeByKey: [SSAVarKey: CTypeExpr]
    let symbolRenames: [VirtualAddress: String]
    let structDefinitions: [String: CustomStructDefinition]

    // Higher number = tighter binding (ISO C99 precedence)
    private enum Precedence: Int, Comparable {
        case lowest = 0
        case ternary = 2
        case logicalOr = 3
        case logicalAnd = 4
        case bitwiseOr = 5
        case bitwiseXor = 6
        case bitwiseAnd = 7
        case equality = 8
        case relational = 9
        case shift = 10
        case additive = 11
        case multiplicative = 12
        case unaryAndCast = 13
        case postfix = 14
        case primary = 15

        static func < (lhs: Precedence, rhs: Precedence) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    func formatExpr(_ expr: MicroExpr) -> String {
        render(expr, parentPrecedence: .lowest, preferHexConstant: false)
    }

    func formatVariable(_ v: SSAVar) -> String {
        variableNameByKey[SSAVarKey(v)] ?? v.displayName
    }

    func formatStoreLHS(address: MicroExpr, bits: Int) -> String {
        let elemType = CTypeExpr.intType(bits: bits, signed: false)
        return formatDereference(address: address, accessBits: bits, accessType: elemType)
    }

    private func render(
        _ expr: MicroExpr,
        parentPrecedence: Precedence,
        preferHexConstant: Bool
    ) -> String {
        switch expr {
        case .signedConst(let val, _):
            if val < 0 {
                let text = preferHexConstant && val <= -256
                    ? "-0x\(String(UInt64(bitPattern: -val), radix: 16))"
                    : "\(val)"
                return parentPrecedence > .unaryAndCast ? "(\(text))" : text
            }
            return formatUnsignedNumber(UInt64(bitPattern: val), preferHex: preferHexConstant)

        case .unsignedConst(let val, let bits):
            if bits == 1 {
                return val != 0 ? "true" : "false"
            }
            return formatUnsignedNumber(val, preferHex: preferHexConstant)

        case .floatConst(let d):
            if d.isNaN { return "NAN" }
            if d.isInfinite { return d > 0 ? "INFINITY" : "-INFINITY" }
            let formatted = String(format: "%g", d)
            return formatted.contains(".") || formatted.contains("e") ? formatted : "\(formatted).0"

        case .stringLiteral(let str, _):
            return "\"\(Self.escapeCString(str))\""

        case .symbolRef(let name, let addr):
            if addr != .zero, let renamed = symbolRenames[addr], !renamed.isEmpty {
                return renamed
            }
            return name

        case .variable(let v):
            return formatVariable(v)

        case .unary(let op, let sub):
            switch op {
            case .zeroExtend, .signExtend:
                // Transparent width extension in C unless explicit signed narrow cast wraps it
                return render(sub, parentPrecedence: parentPrecedence, preferHexConstant: preferHexConstant)
            case .byteSwap:
                let bits = inferWidth(of: sub)
                let fn = bits <= 16 ? "__builtin_bswap16" : (bits <= 32 ? "__builtin_bswap32" : "__builtin_bswap64")
                return "\(fn)(\(render(sub, parentPrecedence: .lowest, preferHexConstant: preferHexConstant)))"
            case .negate, .bitwiseNot, .logicalNot:
                let inner = render(sub, parentPrecedence: .unaryAndCast, preferHexConstant: op == .bitwiseNot)
                let out = "\(op.rawValue)\(inner)"
                return parentPrecedence > .unaryAndCast ? "(\(out))" : out
            }

        case .binary(let op, let lhs, let rhs):
            let prec = Self.precedence(of: op)
            let hexHint = (op == .bitwiseAnd || op == .bitwiseOr || op == .bitwiseXor)

            // Format pointer equality/inequality against 0 as `NULL`
            if (op == .equal || op == .notEqual) && CytronSSAPhiAndOptimizerEngine.isZeroConstant(rhs) && isPointerExpression(lhs) {
                let lStr = render(lhs, parentPrecedence: prec, preferHexConstant: false)
                let out = "\(lStr) \(op.cOperatorText) NULL"
                return parentPrecedence > prec ? "(\(out))" : out
            }

            let lStr = render(lhs, parentPrecedence: prec, preferHexConstant: hexHint)
            // Right-associative / non-commutative RHS tightening (`a - (b - c)`)
            let rhsMinPrec: Precedence = (op == .sub || op == .udiv || op == .sdiv || op == .umod || op == .shiftLeft || op == .shiftRightLogical || op == .shiftRightArithmetic)
                ? Precedence(rawValue: prec.rawValue + 1) ?? .unaryAndCast
                : prec
            let rStr = render(rhs, parentPrecedence: rhsMinPrec, preferHexConstant: hexHint)
            let out = "\(lStr) \(op.cOperatorText) \(rStr)"
            return parentPrecedence > prec ? "(\(out))" : out

        case .load(let address, let bits, let loadType):
            let deref = formatDereference(address: address, accessBits: bits, accessType: loadType)
            if deref.hasPrefix("*") && parentPrecedence > .unaryAndCast {
                return "(\(deref))"
            }
            return deref

        case .call(let target, let arguments, _):
            let calleeStr = formatCallTarget(target)
            let argStrs = arguments.map { render($0, parentPrecedence: .lowest, preferHexConstant: false) }
            return "\(calleeStr)(\(argStrs.joined(separator: ", ")))"

        case .phi(let incomings):
            let parts = incomings.map { formatVariable($0.variable) }
            return "PHI(\(parts.joined(separator: ", ")))"

        case .cast(let sub, let targetType):
            let inner = render(sub, parentPrecedence: .unaryAndCast, preferHexConstant: false)
            let out = "(\(targetType.cTypeName))\(inner)"
            return parentPrecedence > .unaryAndCast ? "(\(out))" : out

        case .ternary(let c, let t, let e):
            let cStr = render(c, parentPrecedence: .logicalOr, preferHexConstant: false)
            let tStr = render(t, parentPrecedence: .lowest, preferHexConstant: false)
            let eStr = render(e, parentPrecedence: .ternary, preferHexConstant: false)
            let out = "\(cStr) ? \(tStr) : \(eStr)"
            return parentPrecedence > .ternary ? "(\(out))" : out
        }
    }

    private func formatDereference(
        address: MicroExpr,
        accessBits: Int,
        accessType: CTypeExpr
    ) -> String {
        let elemBytes = max(1, accessBits / 8)

        switch address {
        case .symbolRef(let symName, let addr):
            let resolved = (addr != .zero ? symbolRenames[addr] : nil) ?? symName
            if resolved.hasPrefix("g_") || resolved.hasPrefix("_") {
                return resolved
            }
            return "*\(resolved)"

        case .variable(let baseVar):
            let baseName = formatVariable(baseVar)
            let baseType = variableTypeByKey[SSAVarKey(baseVar)] ?? baseVar.inferredType
            if let fieldName = resolveStructField(baseType: baseType, offset: 0, byteSize: elemBytes) {
                return "\(baseName)->\(fieldName)"
            }
            if case .pointer(let pointee) = baseType, pointee == accessType {
                return "*\(baseName)"
            }
            return "*(\(accessType.cTypeName) *)\(baseName)"

        case .binary(.add, let lhs, let rhs):
            // 1. Check `ptr + constOffset` -> struct field `ptr->field` or array `ptr[idx]`
            if case .variable(let baseVar) = lhs {
                let baseName = formatVariable(baseVar)
                let baseType = variableTypeByKey[SSAVarKey(baseVar)] ?? baseVar.inferredType

                if let constOff = CytronSSAPhiAndOptimizerEngine.extractSignedInt64Constant(rhs), constOff >= 0 {
                    if let fieldName = resolveStructField(baseType: baseType, offset: Int(constOff), byteSize: elemBytes) {
                        return "\(baseName)->\(fieldName)"
                    }
                    if case .pointer(let pointee) = baseType,
                       pointee == accessType,
                       elemBytes > 0,
                       Int(constOff) % elemBytes == 0 {
                        let elemIdx = Int(constOff) / elemBytes
                        return "\(baseName)[\(elemIdx)]"
                    }
                }

                // 2. Check `ptr + index` or `ptr + (index << scale)` -> `ptr[index]`!
                if let subscriptExpr = unscaleArrayIndex(rhs, elementBytes: elemBytes) {
                    if case .pointer(let pointee) = baseType,
                       (pointee == accessType || pointee == .voidType) {
                        let idxStr = render(subscriptExpr, parentPrecedence: .lowest, preferHexConstant: false)
                        if pointee == accessType {
                            return "\(baseName)[\(idxStr)]"
                        }
                        return "((\(accessType.cTypeName) *)\(baseName))[\(idxStr)]"
                    }
                    if baseType == .cString && elemBytes == 1 {
                        let idxStr = render(subscriptExpr, parentPrecedence: .lowest, preferHexConstant: false)
                        return "\(baseName)[\(idxStr)]"
                    }
                }
            }

            let addrStr = render(address, parentPrecedence: .lowest, preferHexConstant: true)
            return "*(\(accessType.cTypeName) *)(\(addrStr))"

        default:
            let addrStr = render(address, parentPrecedence: .unaryAndCast, preferHexConstant: true)
            return "*(\(accessType.cTypeName) *)\(addrStr)"
        }
    }

    private func resolveStructField(
        baseType: CTypeExpr,
        offset: Int,
        byteSize: Int
    ) -> String? {
        if case .pointer(.structRef(let structName)) = baseType,
           let def = structDefinitions[structName] {
            if let exact = def.fields.first(where: { $0.offset == offset && $0.byteSize == byteSize }) {
                return exact.name
            }
            if let byOffset = def.fields.first(where: { $0.offset == offset }) {
                return byOffset.name
            }
        }
        if case .objcObject(let clsName?) = baseType,
           let def = structDefinitions[clsName] {
            if let exact = def.fields.first(where: { $0.offset == offset && $0.byteSize == byteSize }) {
                return exact.name
            }
            if let byOffset = def.fields.first(where: { $0.offset == offset }) {
                return byOffset.name
            }
        }
        if case .pointer = baseType, structDefinitions.count == 1, let onlyDef = structDefinitions.values.first {
            if let exact = onlyDef.fields.first(where: { $0.offset == offset && $0.byteSize == byteSize }) {
                return exact.name
            }
        }
        return nil
    }

    private func unscaleArrayIndex(_ indexExpr: MicroExpr, elementBytes: Int) -> MicroExpr? {
        let unwrapped: MicroExpr
        if case .unary(.zeroExtend, let s) = indexExpr {
            unwrapped = s
        } else if case .unary(.signExtend, let s) = indexExpr {
            unwrapped = s
        } else {
            unwrapped = indexExpr
        }

        if elementBytes == 1 {
            return unwrapped
        }
        let expectedShift: UInt64?
        switch elementBytes {
        case 2: expectedShift = 1
        case 4: expectedShift = 2
        case 8: expectedShift = 3
        default: expectedShift = nil
        }

        if let sh = expectedShift,
           case .binary(.shiftLeft, let baseIdx, let shConst) = unwrapped,
           let shVal = CytronSSAPhiAndOptimizerEngine.extractSignedInt64Constant(shConst),
           shVal == Int64(sh) {
            if case .unary(.zeroExtend, let inner) = baseIdx { return inner }
            if case .unary(.signExtend, let inner) = baseIdx { return inner }
            return baseIdx
        }

        if case .binary(.mul, let baseIdx, let mulConst) = unwrapped,
           let mulVal = CytronSSAPhiAndOptimizerEngine.extractSignedInt64Constant(mulConst),
           mulVal == Int64(elementBytes) {
            return baseIdx
        }

        return nil
    }

    private func formatCallTarget(_ target: MicroExpr) -> String {
        switch target {
        case .symbolRef(let name, let addr):
            if addr != .zero, let custom = symbolRenames[addr], !custom.isEmpty {
                return KnownFunctionSignatureCatalog.normalizeSymbolName(custom)
            }
            return KnownFunctionSignatureCatalog.normalizeSymbolName(name)
        default:
            let inner = render(target, parentPrecedence: .postfix, preferHexConstant: false)
            return "(\(inner))"
        }
    }

    private func isPointerExpression(_ expr: MicroExpr) -> Bool {
        switch expr {
        case .stringLiteral:
            return true
        case .variable(let v):
            let ty = variableTypeByKey[SSAVarKey(v)] ?? v.inferredType
            return CytronSSAPhiAndOptimizerEngine.isPointerLike(ty)
        case .cast(_, let ty):
            return CytronSSAPhiAndOptimizerEngine.isPointerLike(ty)
        case .call(_, _, let retTy):
            return CytronSSAPhiAndOptimizerEngine.isPointerLike(retTy)
        default:
            return false
        }
    }

    private func inferWidth(of expr: MicroExpr) -> Int {
        switch expr {
        case .variable(let v): return v.bitWidth
        case .unsignedConst(_, let b), .signedConst(_, let b): return b
        case .load(_, let b, _): return b
        default: return 64
        }
    }

    private func formatUnsignedNumber(_ val: UInt64, preferHex: Bool) -> String {
        if val >= 0x10000 || (preferHex && val >= 0x10) {
            return "0x\(String(val, radix: 16))"
        }
        return "\(val)"
    }

    private static func precedence(of op: MicroBinaryOp) -> Precedence {
        switch op {
        case .logicalOr:
            return .logicalOr
        case .logicalAnd:
            return .logicalAnd
        case .bitwiseOr:
            return .bitwiseOr
        case .bitwiseXor:
            return .bitwiseXor
        case .bitwiseAnd:
            return .bitwiseAnd
        case .equal, .notEqual:
            return .equality
        case .unsignedLess, .unsignedLessEqual, .unsignedGreater, .unsignedGreaterEqual,
             .signedLess, .signedLessEqual, .signedGreater, .signedGreaterEqual:
            return .relational
        case .shiftLeft, .shiftRightLogical, .shiftRightArithmetic:
            return .shift
        case .add, .sub:
            return .additive
        case .mul, .udiv, .sdiv, .umod:
            return .multiplicative
        }
    }

    internal static func escapeCString(_ raw: String) -> String {
        var out = ""
        out.reserveCapacity(raw.count + 4)
        for scalar in raw.unicodeScalars {
            switch scalar.value {
            case 0x0A: out.append("\\n")
            case 0x0D: out.append("\\r")
            case 0x09: out.append("\\t")
            case 0x22: out.append("\\\"")
            case 0x5C: out.append("\\\\")
            case 0x00: out.append("\\0")
            case 0x20...0x7E:
                out.append(Character(scalar))
            default:
                if scalar.value <= 0xFF {
                    out.append(String(format: "\\x%02x", scalar.value))
                } else {
                    out.append(Character(scalar))
                }
            }
        }
        return out
    }
}

// MARK: - Structural Control-Flow Recovery Engine (`MicroBasicBlock` -> `[PseudoCStatement]`)

public struct StructuralControlFlowRecoverer: Sendable {
    private let dominatorAnalyzer: DominatorAndLoopAnalyzer

    public init() {
        self.dominatorAnalyzer = DominatorAndLoopAnalyzer()
    }

    /// Public entry point recovering structured `PseudoCStatement` trees directly from `SSAOptimizedFunctionIR`.
    public func recoverStructuredStatements(
        from ssaOptimized: SSAOptimizedFunctionIR,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> [PseudoCStatement] {
        let lowered = OutOfSSACoalescer().lowerFromSSA(ssaOptimized)
        var variableTypeByKey: [SSAVarKey: CTypeExpr] = [:]
        for (v, ty) in ssaOptimized.variableTypes {
            variableTypeByKey[SSAVarKey(v)] = ty
        }
        let printer = MicroCExpressionPrinter(
            variableNameByKey: lowered.variableNameByKey,
            variableTypeByKey: variableTypeByKey,
            symbolRenames: renames,
            structDefinitions: structDefinitions
        )
        return recoverStructuredStatements(
            blocks: lowered.blocks,
            entryBlockID: ssaOptimized.entryBlockID,
            printer: printer,
            localVariableDecls: lowered.localVariableDecls,
            inlineComments: comments
        )
    }

    /// Public entry point recovering structured `PseudoCStatement` trees directly from `[MicroBasicBlock]`.
    public func recoverStructuredStatements(
        blocks: [MicroBasicBlock],
        entryBlockID: Int = 0,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> [PseudoCStatement] {
        let printer = MicroCExpressionPrinter(
            variableNameByKey: [:],
            variableTypeByKey: [:],
            symbolRenames: renames,
            structDefinitions: structDefinitions
        )
        return recoverStructuredStatements(
            blocks: blocks,
            entryBlockID: entryBlockID,
            printer: printer,
            localVariableDecls: [],
            inlineComments: comments
        )
    }

    internal func recoverStructuredStatements(
        blocks: [MicroBasicBlock],
        entryBlockID: Int,
        printer: MicroCExpressionPrinter,
        localVariableDecls: [NamedParameterDecl],
        inlineComments: [VirtualAddress: String]
    ) -> [PseudoCStatement] {
        guard !blocks.isEmpty else { return [] }

        var blockByID: [Int: MicroBasicBlock] = [:]
        for b in blocks {
            blockByID[b.blockID] = b
        }

        let cfg = CytronSSAPhiAndOptimizerEngine.deriveMicroCFG(from: blocks, entryBlockID: entryBlockID)
        let domAnalysis = dominatorAnalyzer.analyze(
            blocks: cfg.syntheticBasicBlocks,
            edges: cfg.edges,
            entryBlockID: entryBlockID
        )

        var naturalLoopByHeader: [Int: NaturalLoop] = [:]
        for loop in domAnalysis.naturalLoops {
            // If multiple loops share a header, keep the largest inclusive body
            if let prev = naturalLoopByHeader[loop.headerBlockID] {
                if loop.bodyBlockIDs.count > prev.bodyBlockIDs.count {
                    naturalLoopByHeader[loop.headerBlockID] = loop
                }
            } else {
                naturalLoopByHeader[loop.headerBlockID] = loop
            }
        }

        let irreducibleTargets = Set(domAnalysis.irreducibleRetreatEdges.map(\.targetBlockID))

        var state = RecoveryState(
            blockByID: blockByID,
            predecessors: cfg.predecessors,
            successors: cfg.successors,
            postDominatorTree: domAnalysis.postDominatorTree,
            naturalLoopByHeader: naturalLoopByHeader,
            irreducibleTargets: irreducibleTargets,
            printer: printer,
            inlineComments: inlineComments
        )

        let rootScope = StructuringScope(
            stopBlocks: [],
            currentLoop: nil,
            loopBreakTargetID: nil,
            switchBreakTargetID: nil
        )

        var rawStatements = structureRegion(startingAt: entryBlockID, scope: rootScope, state: &state)

        // Emit any remaining reachable multi-entry / unstructured blocks not yet visited
        for b in blocks where !state.visitedBlocks.contains(b.blockID) {
            let tail = structureRegion(startingAt: b.blockID, scope: rootScope, state: &state)
            rawStatements.append(contentsOf: tail)
        }

        // Strip unused `.labelDecl` placeholders; keep ONLY labels targeted by at least one `.gotoStmt`
        let cleanedStatements = Self.pruneUnusedLabels(in: rawStatements, usedLabels: state.referencedGotoLabels)

        // Promote top-level initial assignments to `Type var = init;` and hoist nested-first locals as `Type var;`
        let finalizedStatements = Self.materializeLocalDeclarations(
            in: cleanedStatements,
            localVariables: localVariableDecls
        )

        return finalizedStatements
    }

    // MARK: - Internal Region Structuring State & Scope

    private struct StructuringScope {
        let stopBlocks: Set<Int>
        let currentLoop: NaturalLoop?
        let loopBreakTargetID: Int?
        let switchBreakTargetID: Int?

        func addingStops(_ extras: [Int]) -> StructuringScope {
            StructuringScope(
                stopBlocks: stopBlocks.union(extras),
                currentLoop: currentLoop,
                loopBreakTargetID: loopBreakTargetID,
                switchBreakTargetID: switchBreakTargetID
            )
        }
    }

    private struct RecoveryState {
        let blockByID: [Int: MicroBasicBlock]
        let predecessors: [Int: [Int]]
        let successors: [Int: [Int]]
        let postDominatorTree: [PostDominatorTreeNode]
        let naturalLoopByHeader: [Int: NaturalLoop]
        let irreducibleTargets: Set<Int>
        let printer: MicroCExpressionPrinter
        let inlineComments: [VirtualAddress: String]

        var visitedBlocks = Set<Int>()
        var referencedGotoLabels = Set<String>()
        var emittedCommentAddresses = Set<VirtualAddress>()

        func labelName(for blockID: Int) -> String {
            if let b = blockByID[blockID] {
                return "label_0x\(String(b.startAddress.rawValue, radix: 16))"
            }
            return "label_block_\(blockID)"
        }
    }

    private func structureRegion(
        startingAt blockID: Int,
        scope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        guard let block = state.blockByID[blockID] else { return [] }
        if scope.stopBlocks.contains(blockID) {
            return []
        }
        if state.visitedBlocks.contains(blockID) {
            let lbl = state.labelName(for: blockID)
            state.referencedGotoLabels.insert(lbl)
            return [.gotoStmt(label: lbl, address: block.startAddress)]
        }

        // 1. Check if `blockID` is the header of an unentered Natural Loop
        if let loop = state.naturalLoopByHeader[blockID],
           scope.currentLoop?.headerBlockID != blockID {
            return structureNaturalLoop(loop: loop, headerBlock: block, outerScope: scope, state: &state)
        }

        // Mark `blockID` visited and attach provisional label sentinel (pruned later unless targeted by `goto`)
        state.visitedBlocks.insert(blockID)
        var out: [PseudoCStatement] = [
            .labelDecl(name: state.labelName(for: blockID), address: block.startAddress)
        ]

        // Emit block's linear non-terminator statements
        let nonTermStmts = emitLinearStatements(of: block, state: &state)
        out.append(contentsOf: nonTermStmts)

        guard let lastStmt = block.statements.last,
              ARM64ToMicroIRLifter.isTerminatorStmt(lastStmt.kind) else {
            return out
        }

        let termOrigin = lastStmt.originAddress
        if let cmt = state.inlineComments[termOrigin],
           state.emittedCommentAddresses.insert(termOrigin).inserted {
            out.append(.comment(cmt))
        }

        switch lastStmt.kind {
        case .returnStmt(let retExpr):
            let formatted = retExpr.map { state.printer.formatExpr($0) }
            out.append(.returnStmt(expression: formatted, address: termOrigin))
            return out

        case .jump(let targetID):
            let edgeStmts = emitEdgeTransition(
                from: blockID,
                to: targetID,
                origin: termOrigin,
                scope: scope,
                state: &state
            )
            out.append(contentsOf: edgeStmts)
            return out

        case .switchJump(let selector, let cases, let defaultBlockID):
            let switchStmts = structureSwitchConstruct(
                anchorBlockID: blockID,
                dispatchBlockID: blockID,
                selector: selector,
                cases: cases,
                defaultBlockID: defaultBlockID,
                origin: termOrigin,
                scope: scope,
                state: &state
            )
            out.append(contentsOf: switchStmts)
            return out

        case .conditionalBranch(let cond, let trueID, let falseID):
            // Check Switch Range-Guard Fusion:
            // `cmp w0, #max; b.hi sw_default` falling into single-predecessor jump-table dispatch block!
            if let fusedSwitch = tryFuseRangeGuardedSwitch(
                guardBlockID: blockID,
                trueID: trueID,
                falseID: falseID,
                scope: scope,
                state: &state
            ) {
                out.append(contentsOf: fusedSwitch)
                return out
            }

            let branchStmts = structureConditionalConstruct(
                anchorBlockID: blockID,
                initialCondition: cond,
                initialTrueID: trueID,
                initialFalseID: falseID,
                origin: termOrigin,
                scope: scope,
                state: &state
            )
            out.append(contentsOf: branchStmts)
            return out

        default:
            return out
        }
    }

    // MARK: - Loop Structuring (`while`, `do-while`, `while (true)`)

    private func structureNaturalLoop(
        loop: NaturalLoop,
        headerBlock: MicroBasicBlock,
        outerScope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        let bodySet = Set(loop.bodyBlockIDs)
        let exitBlockID = resolveCanonicalLoopExit(loop: loop, outerScope: outerScope, state: state)

        // Shape A: Pre-tested `while (cond) { ... }` when header has zero non-terminator side effects
        // and branches directly between an in-loop body block and `exitBlockID`.
        let headerLinearCount = headerBlock.statements.filter { !ARM64ToMicroIRLifter.isTerminatorStmt($0.kind) }.count
        if headerLinearCount == 0,
           let term = headerBlock.statements.last,
           case .conditionalBranch(let rawCond, let tID, let fID) = term.kind,
           let exitID = exitBlockID,
           (tID == exitID || fID == exitID) {
            let entersLoopOnTrue = (fID == exitID && bodySet.contains(tID))
            let entersLoopOnFalse = (tID == exitID && bodySet.contains(fID))

            if entersLoopOnTrue || entersLoopOnFalse {
                state.visitedBlocks.insert(headerBlock.blockID)
                var out: [PseudoCStatement] = [
                    .labelDecl(name: state.labelName(for: headerBlock.blockID), address: headerBlock.startAddress)
                ]

                var loopCond = entersLoopOnTrue ? rawCond : Self.negateConditionDeMorgan(rawCond)
                var bodyStartID = entersLoopOnTrue ? tID : fID

                // Fuse compound `while (cond1 && cond2)` header cascades
                while let nextHeader = state.blockByID[bodyStartID],
                      !state.visitedBlocks.contains(bodyStartID),
                      bodyStartID != headerBlock.blockID,
                      (state.predecessors[bodyStartID]?.count ?? 0) == 1,
                      nextHeader.statements.filter({ !ARM64ToMicroIRLifter.isTerminatorStmt($0.kind) }).isEmpty,
                      let nextTerm = nextHeader.statements.last,
                      case .conditionalBranch(let c2, let t2, let f2) = nextTerm.kind,
                      (t2 == exitID || f2 == exitID) {
                    let nextTrueInLoop = (f2 == exitID && bodySet.contains(t2))
                    let nextFalseInLoop = (t2 == exitID && bodySet.contains(f2))
                    guard nextTrueInLoop || nextFalseInLoop else { break }
                    state.visitedBlocks.insert(bodyStartID)
                    let c2Norm = nextTrueInLoop ? c2 : Self.negateConditionDeMorgan(c2)
                    loopCond = .binary(.logicalAnd, loopCond, c2Norm)
                    bodyStartID = nextTrueInLoop ? t2 : f2
                }

                let loopScope = StructuringScope(
                    stopBlocks: outerScope.stopBlocks.union([headerBlock.blockID, exitID]),
                    currentLoop: loop,
                    loopBreakTargetID: exitID,
                    switchBreakTargetID: nil
                )

                var loopBody: [PseudoCStatement]
                if bodyStartID == headerBlock.blockID {
                    loopBody = []
                } else {
                    loopBody = structureRegion(startingAt: bodyStartID, scope: loopScope, state: &state)
                }
                Self.stripTrailingLoopContinue(&loopBody)

                let condText = state.printer.formatExpr(loopCond)
                out.append(.whileLoop(condition: condText, address: term.originAddress, body: loopBody))

                let afterLoop = emitEdgeTransition(
                    from: headerBlock.blockID,
                    to: exitID,
                    origin: term.originAddress,
                    scope: outerScope,
                    state: &state
                )
                out.append(contentsOf: afterLoop)
                return out
            }
        }

        // Shape B: Post-tested `do { ... } while (cond);` when a single conditional latch branches between header and exit
        // (Handles both single-block `latchID == headerBlock.blockID` and multi-block `latchID != headerBlock.blockID` loops!)
        if loop.latchBlockIDs.count == 1,
           let latchID = loop.latchBlockIDs.first,
           let latchBlock = state.blockByID[latchID],
           let latchTerm = latchBlock.statements.last,
           case .conditionalBranch(let latchCond, let ltID, let lfID) = latchTerm.kind,
           let exitID = exitBlockID,
           ((ltID == headerBlock.blockID && lfID == exitID) || (lfID == headerBlock.blockID && ltID == exitID)),
           (latchID == headerBlock.blockID || dominatorAnalyzer.postDominates(latchID, headerBlock.blockID, in: state.postDominatorTree)) {

            state.visitedBlocks.insert(headerBlock.blockID)
            var bodyStmts: [PseudoCStatement] = [
                .labelDecl(name: state.labelName(for: headerBlock.blockID), address: headerBlock.startAddress)
            ]
            bodyStmts.append(contentsOf: emitLinearStatements(of: headerBlock, state: &state))

            if latchID != headerBlock.blockID {
                let doScope = StructuringScope(
                    stopBlocks: outerScope.stopBlocks.union([headerBlock.blockID, exitID, latchID]),
                    currentLoop: loop,
                    loopBreakTargetID: exitID,
                    switchBreakTargetID: nil
                )

                if let hTerm = headerBlock.statements.last {
                    switch hTerm.kind {
                    case .jump(let nextID):
                        bodyStmts.append(contentsOf: emitEdgeTransition(from: headerBlock.blockID, to: nextID, origin: hTerm.originAddress, scope: doScope, state: &state))
                    case .conditionalBranch(let c, let tID, let fID):
                        bodyStmts.append(contentsOf: structureConditionalConstruct(
                            anchorBlockID: headerBlock.blockID,
                            initialCondition: c,
                            initialTrueID: tID,
                            initialFalseID: fID,
                            origin: hTerm.originAddress,
                            scope: doScope,
                            state: &state
                        ))
                    default:
                        break
                    }
                }

                if !state.visitedBlocks.contains(latchID) {
                    state.visitedBlocks.insert(latchID)
                    bodyStmts.append(.labelDecl(name: state.labelName(for: latchID), address: latchBlock.startAddress))
                    bodyStmts.append(contentsOf: emitLinearStatements(of: latchBlock, state: &state))
                }
            }
            Self.stripTrailingLoopContinue(&bodyStmts)

            let repeatCond = (ltID == headerBlock.blockID) ? latchCond : Self.negateConditionDeMorgan(latchCond)
            let condStr = state.printer.formatExpr(repeatCond)

            var out: [PseudoCStatement] = [
                .doWhileLoop(body: bodyStmts, condition: condStr, address: latchTerm.originAddress)
            ]
            out.append(contentsOf: emitEdgeTransition(from: latchID, to: exitID, origin: latchTerm.originAddress, scope: outerScope, state: &state))
            return out
        }

        // Shape C: General `while (true) { ... }` loop with explicit internal `break;` / `continue;`
        state.visitedBlocks.insert(headerBlock.blockID)
        var endlessBody: [PseudoCStatement] = [
            .labelDecl(name: state.labelName(for: headerBlock.blockID), address: headerBlock.startAddress)
        ]
        endlessBody.append(contentsOf: emitLinearStatements(of: headerBlock, state: &state))

        var stops = outerScope.stopBlocks.union([headerBlock.blockID])
        if let exitID = exitBlockID {
            stops.insert(exitID)
        }
        let endlessScope = StructuringScope(
            stopBlocks: stops,
            currentLoop: loop,
            loopBreakTargetID: exitBlockID,
            switchBreakTargetID: nil
        )

        if let hTerm = headerBlock.statements.last {
            switch hTerm.kind {
            case .jump(let t):
                endlessBody.append(contentsOf: emitEdgeTransition(from: headerBlock.blockID, to: t, origin: hTerm.originAddress, scope: endlessScope, state: &state))
            case .conditionalBranch(let c, let tID, let fID):
                endlessBody.append(contentsOf: structureConditionalConstruct(
                    anchorBlockID: headerBlock.blockID,
                    initialCondition: c,
                    initialTrueID: tID,
                    initialFalseID: fID,
                    origin: hTerm.originAddress,
                    scope: endlessScope,
                    state: &state
                ))
            case .returnStmt(let rv):
                endlessBody.append(.returnStmt(expression: rv.map { state.printer.formatExpr($0) }, address: hTerm.originAddress))
            default:
                break
            }
        }
        Self.stripTrailingLoopContinue(&endlessBody)

        var out: [PseudoCStatement] = [
            .whileLoop(condition: "true", address: headerBlock.startAddress, body: endlessBody)
        ]
        if let exitID = exitBlockID {
            out.append(contentsOf: emitEdgeTransition(from: headerBlock.blockID, to: exitID, origin: headerBlock.startAddress, scope: outerScope, state: &state))
        }
        return out
    }

    private func resolveCanonicalLoopExit(
        loop: NaturalLoop,
        outerScope: StructuringScope,
        state: RecoveryState
    ) -> Int? {
        if loop.exitBlockIDs.count == 1 {
            return loop.exitBlockIDs[0]
        }
        let bodySet = Set(loop.bodyBlockIDs)
        // Check header's direct outside successor first
        for succ in state.successors[loop.headerBlockID] ?? [] where !bodySet.contains(succ) {
            return succ
        }
        if let ipdom = dominatorAnalyzer.structuredMergeBlockID(
            forBranchBlock: loop.headerBlockID,
            postDominatorTree: state.postDominatorTree
        ), !bodySet.contains(ipdom) {
            return ipdom
        }
        return loop.exitBlockIDs.first { !outerScope.stopBlocks.contains($0) } ?? loop.exitBlockIDs.first
    }

    // MARK: - Switch Range-Guard Fusion & Multi-Way `switch` Structuring

    private func tryFuseRangeGuardedSwitch(
        guardBlockID: Int,
        trueID: Int,
        falseID: Int,
        scope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement]? {
        let candidates = [(dispatchID: falseID, defaultID: trueID), (dispatchID: trueID, defaultID: falseID)]
        for pair in candidates {
            guard !state.visitedBlocks.contains(pair.dispatchID),
                  !scope.stopBlocks.contains(pair.dispatchID),
                  (state.predecessors[pair.dispatchID]?.count ?? 0) == 1,
                  let dispBlock = state.blockByID[pair.dispatchID],
                  dispBlock.statements.filter({ !ARM64ToMicroIRLifter.isTerminatorStmt($0.kind) }).isEmpty,
                  let dispTerm = dispBlock.statements.last,
                  case .switchJump(let selector, let cases, let swDefID) = dispTerm.kind,
                  swDefID == pair.defaultID else {
                continue
            }

            state.visitedBlocks.insert(pair.dispatchID)
            return structureSwitchConstruct(
                anchorBlockID: guardBlockID,
                dispatchBlockID: pair.dispatchID,
                selector: selector,
                cases: cases,
                defaultBlockID: swDefID,
                origin: dispTerm.originAddress,
                scope: scope,
                state: &state
            )
        }
        return nil
    }

    private func structureSwitchConstruct(
        anchorBlockID: Int,
        dispatchBlockID: Int,
        selector: MicroExpr,
        cases: [SwitchCaseTarget],
        defaultBlockID: Int,
        origin: VirtualAddress,
        scope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        let _ = dispatchBlockID
        let rawMergeID = dominatorAnalyzer.structuredMergeBlockID(
            forBranchBlock: anchorBlockID,
            postDominatorTree: state.postDominatorTree
        )

        // Group case values targeting the same basic block while preserving case order
        var orderedTargets: [Int] = []
        var valuesByTarget: [Int: [Int64]] = [:]
        for c in cases {
            if valuesByTarget[c.targetBlockID] == nil {
                orderedTargets.append(c.targetBlockID)
            }
            valuesByTarget[c.targetBlockID, default: []].append(c.caseValue)
        }

        let mergeID: Int?
        if let candidate = rawMergeID, !orderedTargets.contains(candidate) {
            mergeID = candidate
        } else {
            mergeID = rawMergeID
        }

        var armStopSet = scope.stopBlocks
        if let m = mergeID { armStopSet.insert(m) }
        if defaultBlockID != mergeID {
            armStopSet.insert(defaultBlockID)
        }

        let armScope = StructuringScope(
            stopBlocks: armStopSet,
            currentLoop: scope.currentLoop,
            loopBreakTargetID: scope.loopBreakTargetID,
            switchBreakTargetID: mergeID
        )

        var structuredArms: [StructuredSwitchArm] = []
        for targetID in orderedTargets {
            let vals = (valuesByTarget[targetID] ?? []).sorted()
            var armBody: [PseudoCStatement]
            if targetID == mergeID {
                armBody = [.breakStmt]
            } else {
                // Allow arm to run up to `mergeID` or another case block
                let otherCases = orderedTargets.filter { $0 != targetID }
                let perArmScope = armScope.addingStops(otherCases)
                armBody = structureRegion(startingAt: targetID, scope: perArmScope, state: &state)
                if !Self.endsWithUnconditionalTransfer(armBody) {
                    armBody.append(.breakStmt)
                }
            }
            structuredArms.append(StructuredSwitchArm(caseValues: vals, body: armBody))
        }

        var defaultBody: [PseudoCStatement] = []
        if defaultBlockID != mergeID && !orderedTargets.contains(defaultBlockID) {
            let defScope = StructuringScope(
                stopBlocks: scope.stopBlocks.union(mergeID.map { [$0] } ?? []).union(orderedTargets),
                currentLoop: scope.currentLoop,
                loopBreakTargetID: scope.loopBreakTargetID,
                switchBreakTargetID: mergeID
            )
            defaultBody = structureRegion(startingAt: defaultBlockID, scope: defScope, state: &state)
            if !defaultBody.isEmpty && !Self.endsWithUnconditionalTransfer(defaultBody) {
                defaultBody.append(.breakStmt)
            }
        }

        let selText = state.printer.formatExpr(selector)
        var out: [PseudoCStatement] = [
            .switchStmt(
                selector: selText,
                address: origin,
                arms: structuredArms,
                defaultBody: defaultBody
            )
        ]

        if let mID = mergeID, !scope.stopBlocks.contains(mID) {
            out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: mID, origin: origin, scope: scope, state: &state))
        }

        return out
    }

    // MARK: - Short-Circuit Cascades (`&&` / `||`) & `if / else if / else` Structuring

    private func structureConditionalConstruct(
        anchorBlockID: Int,
        initialCondition: MicroExpr,
        initialTrueID: Int,
        initialFalseID: Int,
        origin: VirtualAddress,
        scope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        var cond = initialCondition
        var tID = initialTrueID
        var fID = initialFalseID

        // 1. Fuse single-predecessor pure conditional cascade blocks into short-circuit `&&` / `||`
        var fusedCascade = true
        while fusedCascade {
            fusedCascade = false

            // Check `false` arm cascading into a pure branch block sharing `tID`
            if !state.visitedBlocks.contains(fID),
               !scope.stopBlocks.contains(fID),
               state.naturalLoopByHeader[fID] == nil,
               (state.predecessors[fID]?.count ?? 0) == 1,
               let fBlock = state.blockByID[fID],
               state.inlineComments[fBlock.startAddress] == nil,
               fBlock.statements.filter({ !ARM64ToMicroIRLifter.isTerminatorStmt($0.kind) }).isEmpty,
               let fTerm = fBlock.statements.last,
               case .conditionalBranch(let condB, let tB, let fB) = fTerm.kind {
                if tB == tID && fB != tID {
                    state.visitedBlocks.insert(fID)
                    cond = .binary(.logicalOr, cond, condB)
                    fID = fB
                    fusedCascade = true
                    continue
                } else if fB == tID && tB != tID {
                    state.visitedBlocks.insert(fID)
                    cond = .binary(.logicalOr, cond, Self.negateConditionDeMorgan(condB))
                    fID = tB
                    fusedCascade = true
                    continue
                }
            }

            // Check `true` arm cascading into a pure branch block sharing `fID`
            if !state.visitedBlocks.contains(tID),
               !scope.stopBlocks.contains(tID),
               state.naturalLoopByHeader[tID] == nil,
               (state.predecessors[tID]?.count ?? 0) == 1,
               let tBlock = state.blockByID[tID],
               state.inlineComments[tBlock.startAddress] == nil,
               tBlock.statements.filter({ !ARM64ToMicroIRLifter.isTerminatorStmt($0.kind) }).isEmpty,
               let tTerm = tBlock.statements.last,
               case .conditionalBranch(let condB, let tB, let fB) = tTerm.kind {
                if fB == fID && tB != fID {
                    state.visitedBlocks.insert(tID)
                    cond = .binary(.logicalAnd, cond, condB)
                    tID = tB
                    fusedCascade = true
                    continue
                } else if tB == fID && fB != fID {
                    state.visitedBlocks.insert(tID)
                    cond = .binary(.logicalAnd, cond, Self.negateConditionDeMorgan(condB))
                    tID = fB
                    fusedCascade = true
                    continue
                }
            }
        }

        // 2. Determine structured immediate post-dominator merge point (`ipdom`),
        // excluding `loopBreakTargetID` so intra-loop exit branches emit explicit `break;` instead of silent fallthrough!
        let rawMergeID = dominatorAnalyzer.structuredMergeBlockID(
            forBranchBlock: anchorBlockID,
            postDominatorTree: state.postDominatorTree
        )
        let mergeID: Int? = (rawMergeID != nil && rawMergeID == scope.loopBreakTargetID) ? nil : rawMergeID

        // 3. Check if either arm is a direct loop/switch `break` or `continue` or `stopBlock`
        let trueIsDirectBoundary = isBoundaryTarget(tID, mergeID: mergeID, scope: scope)
        let falseIsDirectBoundary = isBoundaryTarget(fID, mergeID: mergeID, scope: scope)

        // Triangle Case 1: `fID == mergeID` -> `if (cond) { then }` followed by `mergeID`
        if let mID = mergeID, fID == mID && tID != mID {
            let branchScope = scope.addingStops([mID])
            let thenBody = emitEdgeTransition(from: anchorBlockID, to: tID, origin: origin, scope: branchScope, state: &state)
            var out: [PseudoCStatement] = [
                .ifStmt(condition: state.printer.formatExpr(cond), address: origin, thenBody: thenBody, elseBody: [])
            ]
            if !scope.stopBlocks.contains(mID) {
                out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: mID, origin: origin, scope: scope, state: &state))
            }
            return out
        }

        // Triangle Case 2: `tID == mergeID` -> `if (!cond) { then }` followed by `mergeID`
        if let mID = mergeID, tID == mID && fID != mID {
            let negCond = Self.negateConditionDeMorgan(cond)
            let branchScope = scope.addingStops([mID])
            let thenBody = emitEdgeTransition(from: anchorBlockID, to: fID, origin: origin, scope: branchScope, state: &state)
            var out: [PseudoCStatement] = [
                .ifStmt(condition: state.printer.formatExpr(negCond), address: origin, thenBody: thenBody, elseBody: [])
            ]
            if !scope.stopBlocks.contains(mID) {
                out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: mID, origin: origin, scope: scope, state: &state))
            }
            return out
        }

        // Loop/Switch `break`/`continue` guard: keep `if (guard) { break; }` flat when the other arm continues in-region
        if trueIsDirectBoundary && !falseIsDirectBoundary {
            let guardBody = emitEdgeTransition(from: anchorBlockID, to: tID, origin: origin, scope: scope, state: &state)
            var out: [PseudoCStatement] = [
                .ifStmt(condition: state.printer.formatExpr(cond), address: origin, thenBody: guardBody, elseBody: [])
            ]
            out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: fID, origin: origin, scope: scope, state: &state))
            return out
        }
        if falseIsDirectBoundary && !trueIsDirectBoundary {
            let negCond = Self.negateConditionDeMorgan(cond)
            let guardBody = emitEdgeTransition(from: anchorBlockID, to: fID, origin: origin, scope: scope, state: &state)
            var out: [PseudoCStatement] = [
                .ifStmt(condition: state.printer.formatExpr(negCond), address: origin, thenBody: guardBody, elseBody: [])
            ]
            out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: tID, origin: origin, scope: scope, state: &state))
            return out
        }

        // Full Diamond (`mergeID != nil`) or Dual-Exit (`mergeID == nil`):
        // Prefer lower-address fallthrough path as `thenBody` so forward failure jumps land naturally in `else`!
        if let tBlock = state.blockByID[tID],
           let fBlock = state.blockByID[fID],
           fBlock.startAddress < tBlock.startAddress,
           !state.visitedBlocks.contains(fID) {
            cond = Self.negateConditionDeMorgan(cond)
            swap(&tID, &fID)
        }

        let branchScope = mergeID.map { scope.addingStops([$0]) } ?? scope
        let thenBody = emitEdgeTransition(from: anchorBlockID, to: tID, origin: origin, scope: branchScope, state: &state)
        let elseBody = emitEdgeTransition(from: anchorBlockID, to: fID, origin: origin, scope: branchScope, state: &state)

        var out: [PseudoCStatement] = [
            .ifStmt(
                condition: state.printer.formatExpr(cond),
                address: origin,
                thenBody: thenBody,
                elseBody: elseBody
            )
        ]

        if let mID = mergeID, !scope.stopBlocks.contains(mID) {
            out.append(contentsOf: emitEdgeTransition(from: anchorBlockID, to: mID, origin: origin, scope: scope, state: &state))
        }

        return out
    }

    private func isBoundaryTarget(_ targetID: Int, mergeID: Int?, scope: StructuringScope) -> Bool {
        if targetID == mergeID { return true }
        if targetID == scope.currentLoop?.headerBlockID { return true }
        if targetID == scope.loopBreakTargetID { return true }
        if targetID == scope.switchBreakTargetID { return true }
        if scope.stopBlocks.contains(targetID) { return true }
        return false
    }

    // MARK: - Edge Transition & Linear Block Statement Lowering

    private func emitEdgeTransition(
        from sourceID: Int,
        to targetID: Int,
        origin: VirtualAddress,
        scope: StructuringScope,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        let _ = sourceID
        if let loop = scope.currentLoop, targetID == loop.headerBlockID {
            return [.continueStmt]
        }
        if let swBreak = scope.switchBreakTargetID, targetID == swBreak {
            return [.breakStmt]
        }
        if let lpBreak = scope.loopBreakTargetID, targetID == lpBreak {
            return [.breakStmt]
        }
        if scope.stopBlocks.contains(targetID) {
            return []
        }
        if state.visitedBlocks.contains(targetID) || state.irreducibleTargets.contains(targetID) {
            let lbl = state.labelName(for: targetID)
            state.referencedGotoLabels.insert(lbl)
            return [.gotoStmt(label: lbl, address: origin)]
        }
        return structureRegion(startingAt: targetID, scope: scope, state: &state)
    }

    private func emitLinearStatements(
        of block: MicroBasicBlock,
        state: inout RecoveryState
    ) -> [PseudoCStatement] {
        var stmts: [PseudoCStatement] = []

        if let blockComment = state.inlineComments[block.startAddress],
           state.emittedCommentAddresses.insert(block.startAddress).inserted {
            stmts.append(.comment(blockComment))
        }

        for stmt in block.statements where !ARM64ToMicroIRLifter.isTerminatorStmt(stmt.kind) {
            if let cmt = state.inlineComments[stmt.originAddress],
               state.emittedCommentAddresses.insert(stmt.originAddress).inserted {
                stmts.append(.comment(cmt))
            }

            switch stmt.kind {
            case .assign(let dest, let expr):
                if case .phi = expr { continue }
                let lhs = state.printer.formatVariable(dest)
                let rhs = state.printer.formatExpr(expr)
                if lhs != rhs {
                    stmts.append(.assignment(lhs: lhs, rhs: rhs, address: stmt.originAddress))
                }

            case .store(let addr, let val, let bits):
                let lhs = state.printer.formatStoreLHS(address: addr, bits: bits)
                let rhs = state.printer.formatExpr(val)
                stmts.append(.assignment(lhs: lhs, rhs: rhs, address: stmt.originAddress))

            case .callStmt(let target, let args):
                let callExpr = MicroExpr.call(target: target, arguments: args, returnType: .voidType)
                stmts.append(.exprStmt(expression: state.printer.formatExpr(callExpr), address: stmt.originAddress))

            case .intrinsic(let name, let args):
                let argText = args.map { state.printer.formatExpr($0) }.joined(separator: ", ")
                stmts.append(.exprStmt(expression: "\(name)(\(argText))", address: stmt.originAddress))

            case .nop, .conditionalBranch, .jump, .switchJump, .returnStmt:
                break
            }
        }

        return stmts
    }

    // MARK: - AST Cleanup, De Morgan Condition Negation & Local Variable Declarations

    internal static func negateConditionDeMorgan(_ expr: MicroExpr) -> MicroExpr {
        switch expr {
        case .unary(.logicalNot, let inner):
            return inner
        case .binary(.logicalAnd, let a, let b):
            return .binary(.logicalOr, negateConditionDeMorgan(a), negateConditionDeMorgan(b))
        case .binary(.logicalOr, let a, let b):
            return .binary(.logicalAnd, negateConditionDeMorgan(a), negateConditionDeMorgan(b))
        default:
            return ARM64ToMicroIRLifter.negateConditionExpr(expr)
        }
    }

    private static func stripTrailingLoopContinue(_ body: inout [PseudoCStatement]) {
        if let last = body.last, last == .continueStmt {
            body.removeLast()
        }
    }

    private static func endsWithUnconditionalTransfer(_ stmts: [PseudoCStatement]) -> Bool {
        guard let last = stmts.last else { return false }
        switch last {
        case .returnStmt, .breakStmt, .continueStmt, .gotoStmt:
            return true
        case .ifStmt(_, _, let t, let e) where !t.isEmpty && !e.isEmpty:
            return endsWithUnconditionalTransfer(t) && endsWithUnconditionalTransfer(e)
        default:
            return false
        }
    }

    private static func pruneUnusedLabels(
        in statements: [PseudoCStatement],
        usedLabels: Set<String>
    ) -> [PseudoCStatement] {
        var result: [PseudoCStatement] = []
        result.reserveCapacity(statements.count)

        for stmt in statements {
            switch stmt {
            case .labelDecl(let name, _):
                if usedLabels.contains(name) {
                    result.append(stmt)
                }
            case .ifStmt(let cond, let addr, let tBody, let eBody):
                let pt = pruneUnusedLabels(in: tBody, usedLabels: usedLabels)
                let pe = pruneUnusedLabels(in: eBody, usedLabels: usedLabels)
                result.append(.ifStmt(condition: cond, address: addr, thenBody: pt, elseBody: pe))
            case .whileLoop(let cond, let addr, let body):
                result.append(.whileLoop(condition: cond, address: addr, body: pruneUnusedLabels(in: body, usedLabels: usedLabels)))
            case .doWhileLoop(let body, let cond, let addr):
                result.append(.doWhileLoop(body: pruneUnusedLabels(in: body, usedLabels: usedLabels), condition: cond, address: addr))
            case .switchStmt(let sel, let addr, let arms, let defBody):
                let pArms = arms.map { StructuredSwitchArm(caseValues: $0.caseValues, body: pruneUnusedLabels(in: $0.body, usedLabels: usedLabels)) }
                let pDef = pruneUnusedLabels(in: defBody, usedLabels: usedLabels)
                result.append(.switchStmt(selector: sel, address: addr, arms: pArms, defaultBody: pDef))
            default:
                result.append(stmt)
            }
        }
        return result
    }

    private static func materializeLocalDeclarations(
        in statements: [PseudoCStatement],
        localVariables: [NamedParameterDecl]
    ) -> [PseudoCStatement] {
        guard !localVariables.isEmpty else { return statements }
        var declTypeByName: [String: CTypeExpr] = [:]
        for lv in localVariables {
            declTypeByName[lv.name] = lv.type
        }

        // Variables whose VERY FIRST assignment occurs at top-level (before any nested use) become inline `Type x = rhs;`
        var inlineDeclaredNames = Set<String>()
        var referencedBeforeTopAssign = Set<String>()

        var rewrittenTop: [PseudoCStatement] = []
        rewrittenTop.reserveCapacity(statements.count)

        for stmt in statements {
            if case .assignment(let lhs, let rhs, let addr) = stmt,
               let varType = declTypeByName[lhs],
               !inlineDeclaredNames.contains(lhs),
               !referencedBeforeTopAssign.contains(lhs) {
                inlineDeclaredNames.insert(lhs)
                rewrittenTop.append(.varDecl(name: lhs, type: varType, initialValue: rhs, address: addr))
            } else {
                collectIdentifierMentions(in: stmt, into: &referencedBeforeTopAssign)
                rewrittenTop.append(stmt)
            }
        }

        // Any local variable first assigned inside a nested block (`if`, `switch`, `while`) gets hoisted to top of function!
        var hoistedDecls: [PseudoCStatement] = []
        for lv in localVariables where !inlineDeclaredNames.contains(lv.name) {
            hoistedDecls.append(.varDecl(name: lv.name, type: lv.type, initialValue: nil, address: nil))
        }

        if hoistedDecls.isEmpty {
            return rewrittenTop
        }
        return hoistedDecls + rewrittenTop
    }

    private static func collectIdentifierMentions(in stmt: PseudoCStatement, into set: inout Set<String>) {
        func scanText(_ s: String) {
            var token = ""
            for ch in s {
                if ch.isLetter || ch.isNumber || ch == "_" {
                    token.append(ch)
                } else {
                    if !token.isEmpty { set.insert(token); token = "" }
                }
            }
            if !token.isEmpty { set.insert(token) }
        }

        switch stmt {
        case .varDecl(let name, _, let initVal, _):
            set.insert(name)
            if let initVal { scanText(initVal) }
        case .assignment(let lhs, let rhs, _):
            scanText(lhs); scanText(rhs)
        case .exprStmt(let e, _):
            scanText(e)
        case .ifStmt(let c, _, let t, let e):
            scanText(c)
            t.forEach { collectIdentifierMentions(in: $0, into: &set) }
            e.forEach { collectIdentifierMentions(in: $0, into: &set) }
        case .whileLoop(let c, _, let b):
            scanText(c)
            b.forEach { collectIdentifierMentions(in: $0, into: &set) }
        case .doWhileLoop(let b, let c, _):
            b.forEach { collectIdentifierMentions(in: $0, into: &set) }
            scanText(c)
        case .switchStmt(let s, _, let arms, let def):
            scanText(s)
            for arm in arms { arm.body.forEach { collectIdentifierMentions(in: $0, into: &set) } }
            def.forEach { collectIdentifierMentions(in: $0, into: &set) }
        case .returnStmt(let e, _):
            if let e { scanText(e) }
        case .gotoStmt, .labelDecl, .breakStmt, .continueStmt, .comment:
            break
        }
    }
}

// MARK: - Syntax-Highlighted Pseudo-C Printer (`PseudoCCodeFormatter`)

public struct PseudoCCodeFormatter: Sendable {
    public let indentWidth: Int

    public init(indentWidth: Int = 4) {
        self.indentWidth = max(2, indentWidth)
    }

    public func formatFunction(
        functionAddress: VirtualAddress,
        functionName: String,
        objcContext: ObjCMethodSignatureContext? = nil,
        returnType: CTypeExpr,
        parameters: [NamedParameterDecl],
        body: [PseudoCStatement],
        inlineComments: [VirtualAddress: String] = [:]
    ) -> (signatureLine: String, lines: [PseudoCLineSpan], fullSourceText: String) {
        let knownVariableNames = collectKnownVariableNames(parameters: parameters, body: body)
        let signatureLine = buildSignatureLine(
            functionName: functionName,
            objcContext: objcContext,
            returnType: returnType,
            parameters: parameters
        )

        var rawLines: [(indent: Int, content: String, address: VirtualAddress?)] = []

        if let fnComment = inlineComments[functionAddress] {
            rawLines.append((0, "// \(fnComment)", functionAddress))
        }
        rawLines.append((0, "\(signatureLine) {", functionAddress))

        if body.isEmpty {
            rawLines.append((1, "return;", functionAddress))
        } else {
            emitStatementLines(body, indent: 1, fallbackAddress: functionAddress, into: &rawLines)
        }

        rawLines.append((0, "}", functionAddress))

        var spans: [PseudoCLineSpan] = []
        spans.reserveCapacity(rawLines.count)
        var textLines: [String] = []
        textLines.reserveCapacity(rawLines.count)

        for (idx, item) in rawLines.enumerated() {
            let prefix = String(repeating: " ", count: item.indent * indentWidth)
            let fullLine = prefix + item.content
            let tokens = tokenizeCLine(fullLine, knownVariables: knownVariableNames)
            spans.append(
                PseudoCLineSpan(
                    lineNumber: idx + 1,
                    indentationLevel: item.indent,
                    text: fullLine,
                    tokens: tokens,
                    mappedAddress: item.address
                )
            )
            textLines.append(fullLine)
        }

        return (signatureLine, spans, textLines.joined(separator: "\n"))
    }

    private func buildSignatureLine(
        functionName: String,
        objcContext: ObjCMethodSignatureContext?,
        returnType: CTypeExpr,
        parameters: [NamedParameterDecl]
    ) -> String {
        // Preserve Objective-C `-[Class sel:]` display in signature comment or clean C-callable prototype
        let cleanName: String
        if objcContext != nil && (functionName.hasPrefix("-[") || functionName.hasPrefix("+[")) {
            cleanName = functionName
        } else {
            cleanName = KnownFunctionSignatureCatalog.normalizeSymbolName(functionName)
        }

        let paramText: String
        if parameters.isEmpty {
            paramText = "void"
        } else {
            paramText = parameters.map { decl in
                Self.formatTypedDeclaration(type: decl.type, name: decl.name)
            }.joined(separator: ", ")
        }

        let retText = returnType.cTypeName
        if retText.hasSuffix("*") {
            return "\(retText)\(cleanName)(\(paramText))"
        }
        return "\(retText) \(cleanName)(\(paramText))"
    }

    private func emitStatementLines(
        _ statements: [PseudoCStatement],
        indent: Int,
        fallbackAddress: VirtualAddress?,
        into lines: inout [(indent: Int, content: String, address: VirtualAddress?)]
    ) {
        for stmt in statements {
            switch stmt {
            case .varDecl(let name, let type, let initVal, let addr):
                let decl = Self.formatTypedDeclaration(type: type, name: name)
                if let initVal {
                    lines.append((indent, "\(decl) = \(initVal);", addr ?? fallbackAddress))
                } else {
                    lines.append((indent, "\(decl);", addr ?? fallbackAddress))
                }

            case .assignment(let lhs, let rhs, let addr):
                lines.append((indent, "\(lhs) = \(rhs);", addr))

            case .exprStmt(let expr, let addr):
                lines.append((indent, "\(expr);", addr))

            case .ifStmt(let cond, let addr, let thenBody, let elseBody):
                emitIfChain(
                    prefixKeyword: "if",
                    condition: cond,
                    address: addr,
                    thenBody: thenBody,
                    elseBody: elseBody,
                    indent: indent,
                    into: &lines
                )

            case .whileLoop(let cond, let addr, let body):
                lines.append((indent, "while (\(cond)) {", addr))
                emitStatementLines(body, indent: indent + 1, fallbackAddress: addr, into: &lines)
                lines.append((indent, "}", addr))

            case .doWhileLoop(let body, let cond, let addr):
                lines.append((indent, "do {", addr))
                emitStatementLines(body, indent: indent + 1, fallbackAddress: addr, into: &lines)
                lines.append((indent, "} while (\(cond));", addr))

            case .switchStmt(let selector, let addr, let arms, let defaultBody):
                lines.append((indent, "switch (\(selector)) {", addr))
                for arm in arms {
                    let armAddr = Self.firstStatementAddress(in: arm.body) ?? addr
                    for caseVal in arm.caseValues {
                        lines.append((indent, "case \(caseVal):", armAddr))
                    }
                    emitStatementLines(arm.body, indent: indent + 1, fallbackAddress: armAddr, into: &lines)
                }
                if !defaultBody.isEmpty {
                    let defAddr = Self.firstStatementAddress(in: defaultBody) ?? addr
                    lines.append((indent, "default:", defAddr))
                    emitStatementLines(defaultBody, indent: indent + 1, fallbackAddress: defAddr, into: &lines)
                }
                lines.append((indent, "}", addr))

            case .returnStmt(let expr, let addr):
                if let expr {
                    lines.append((indent, "return \(expr);", addr))
                } else {
                    lines.append((indent, "return;", addr))
                }

            case .gotoStmt(let label, let addr):
                lines.append((indent, "goto \(label);", addr))

            case .labelDecl(let name, let addr):
                lines.append((max(0, indent - 1), "\(name):", addr))

            case .breakStmt:
                lines.append((indent, "break;", fallbackAddress))

            case .continueStmt:
                lines.append((indent, "continue;", fallbackAddress))

            case .comment(let text):
                lines.append((indent, "// \(text)", fallbackAddress))
            }
        }
    }

    private func emitIfChain(
        prefixKeyword: String,
        condition: String,
        address: VirtualAddress,
        thenBody: [PseudoCStatement],
        elseBody: [PseudoCStatement],
        indent: Int,
        into lines: inout [(indent: Int, content: String, address: VirtualAddress?)]
    ) {
        lines.append((indent, "\(prefixKeyword) (\(condition)) {", address))
        emitStatementLines(thenBody, indent: indent + 1, fallbackAddress: address, into: &lines)

        if elseBody.isEmpty {
            lines.append((indent, "}", address))
        } else if elseBody.count == 1,
                  case .ifStmt(let nextCond, let nextAddr, let nextThen, let nextElse) = elseBody[0] {
            emitIfChain(
                prefixKeyword: "} else if",
                condition: nextCond,
                address: nextAddr,
                thenBody: nextThen,
                elseBody: nextElse,
                indent: indent,
                into: &lines
            )
        } else {
            let elseAddr = Self.firstStatementAddress(in: elseBody) ?? address
            lines.append((indent, "} else {", elseAddr))
            emitStatementLines(elseBody, indent: indent + 1, fallbackAddress: elseAddr, into: &lines)
            lines.append((indent, "}", address))
        }
    }

    private static func formatTypedDeclaration(type: CTypeExpr, name: String) -> String {
        let typeStr = type.cTypeName
        if typeStr.hasSuffix("*") {
            return "\(typeStr)\(name)"
        }
        return "\(typeStr) \(name)"
    }

    private static func firstStatementAddress(in stmts: [PseudoCStatement]) -> VirtualAddress? {
        for s in stmts {
            switch s {
            case .varDecl(_, _, _, let a?): return a
            case .assignment(_, _, let a): return a
            case .exprStmt(_, let a): return a
            case .ifStmt(_, let a, _, _): return a
            case .whileLoop(_, let a, _): return a
            case .doWhileLoop(_, _, let a): return a
            case .switchStmt(_, let a, _, _): return a
            case .returnStmt(_, let a): return a
            case .gotoStmt(_, let a): return a
            case .labelDecl(_, let a): return a
            default: continue
            }
        }
        return nil
    }

    // MARK: - Lossless C Lexical Tokenizer (`tokens.map(\.text).joined() == line`)

    private static let cKeywords: Set<String> = [
        "if", "else", "while", "do", "for", "switch", "case", "default",
        "break", "continue", "return", "goto", "struct", "const", "sizeof",
        "true", "false", "NULL"
    ]

    private static let cTypeNames: Set<String> = [
        "void", "bool", "char", "short", "int", "long", "float", "double",
        "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
        "int64_t", "uint64_t", "size_t", "ssize_t", "uintptr_t", "intptr_t",
        "id", "Class", "SEL", "BOOL"
    ]

    public func tokenizeCLine(_ line: String, knownVariables: Set<String> = []) -> [PseudoCToken] {
        guard !line.isEmpty else { return [] }
        let chars = Array(line)
        let n = chars.count
        var i = 0
        var tokens: [PseudoCToken] = []

        while i < n {
            let c = chars[i]

            // 1. Whitespace run
            if c.isWhitespace {
                let start = i
                while i < n && chars[i].isWhitespace {
                    i += 1
                }
                tokens.append(PseudoCToken(kind: .plain, text: String(chars[start..<i])))
                continue
            }

            // 2. Line comment `// ...`
            if c == "/" && i + 1 < n && chars[i + 1] == "/" {
                tokens.append(PseudoCToken(kind: .comment, text: String(chars[i..<n])))
                break
            }

            // 3. String literal `"..."`
            if c == "\"" {
                let start = i
                i += 1
                while i < n {
                    if chars[i] == "\\" && i + 1 < n {
                        i += 2
                        continue
                    }
                    if chars[i] == "\"" {
                        i += 1
                        break
                    }
                    i += 1
                }
                tokens.append(PseudoCToken(kind: .stringLiteral, text: String(chars[start..<i])))
                continue
            }

            // 4. Objective-C method header `-[Class sel:]` / `+[Class sel:]`
            if (c == "-" || c == "+") && i + 1 < n && chars[i + 1] == "[" {
                let start = i
                i += 2
                while i < n && chars[i] != "]" {
                    i += 1
                }
                if i < n && chars[i] == "]" {
                    i += 1
                }
                tokens.append(PseudoCToken(kind: .functionName, text: String(chars[start..<i])))
                continue
            }

            // 5. Numeric literal (`0x...`, decimal, float)
            if c.isNumber {
                let start = i
                if c == "0" && i + 1 < n && (chars[i + 1] == "x" || chars[i + 1] == "X") {
                    i += 2
                    while i < n && chars[i].isHexDigit {
                        i += 1
                    }
                } else {
                    while i < n && (chars[i].isNumber || chars[i] == ".") {
                        i += 1
                    }
                }
                tokens.append(PseudoCToken(kind: .numericLiteral, text: String(chars[start..<i])))
                continue
            }

            // 6. Identifier, keyword, type name, function call, or custom struct/ObjC class type
            if c.isLetter || c == "_" || c == "$" {
                let start = i
                i += 1
                while i < n && (chars[i].isLetter || chars[i].isNumber || chars[i] == "_" || chars[i] == "$") {
                    i += 1
                }
                let word = String(chars[start..<i])

                // Classify identifier
                let kind: PseudoCTokenKind
                if Self.cKeywords.contains(word) {
                    kind = (word == "true" || word == "false" || word == "NULL") ? .numericLiteral : .keyword
                } else if Self.cTypeNames.contains(word) {
                    kind = .typeName
                } else if i < n && chars[i] == "(" {
                    kind = .functionName
                } else if isPrecededByStructOrPointerTypePosition(chars: chars, wordStart: start, wordEnd: i, knownVariables: knownVariables) {
                    kind = .typeName
                } else {
                    kind = .variableName
                }

                tokens.append(PseudoCToken(kind: kind, text: word))
                continue
            }

            // 7. Multi-character operators & punctuation (`->`, `==`, `!=`, `<=`, `>=`, `&&`, `||`, `<<`, `>>`)
            let start = i
            if i + 1 < n {
                let two = String(chars[i...(i + 1)])
                if ["->", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>"].contains(two) {
                    i += 2
                    tokens.append(PseudoCToken(kind: .punctuation, text: two))
                    continue
                }
            }
            i += 1
            tokens.append(PseudoCToken(kind: .punctuation, text: String(chars[start..<i])))
        }

        return tokens
    }

    private func isPrecededByStructOrPointerTypePosition(
        chars: [Character],
        wordStart: Int,
        wordEnd: Int,
        knownVariables: Set<String>
    ) -> Bool {
        let word = String(chars[wordStart..<wordEnd])
        if knownVariables.contains(word) {
            return false
        }
        // Check if followed by ` *` (e.g., `MGAuthController *self`)
        var scan = wordEnd
        while scan < chars.count && chars[scan] == " " {
            scan += 1
        }
        if scan < chars.count && chars[scan] == "*" {
            // Confirm `*` is a pointer declarator/cast (preceded by `(`, `,`, or line start, or `const `) rather than multiplication!
            var back = wordStart - 1
            while back >= 0 && chars[back] == " " {
                back -= 1
            }
            if back < 0 || chars[back] == "(" || chars[back] == "," {
                return true
            }
        }
        // Check if immediately preceded by `struct `
        if wordStart >= 7 && String(chars[(wordStart - 7)..<wordStart]) == "struct " {
            return true
        }
        return false
    }

    private func collectKnownVariableNames(
        parameters: [NamedParameterDecl],
        body: [PseudoCStatement]
    ) -> Set<String> {
        var names = Set(parameters.map(\.name))
        func walk(_ s: PseudoCStatement) {
            switch s {
            case .varDecl(let n, _, _, _):
                names.insert(n)
            case .ifStmt(_, _, let t, let e):
                t.forEach(walk); e.forEach(walk)
            case .whileLoop(_, _, let b), .doWhileLoop(let b, _, _):
                b.forEach(walk)
            case .switchStmt(_, _, let arms, let d):
                arms.forEach { $0.body.forEach(walk) }
                d.forEach(walk)
            default:
                break
            }
        }
        body.forEach(walk)
        return names
    }
}

// MARK: - Primary Pure-Swift Decompiler Facade (`MachMicroDecompilerEngine`)

public struct MachMicroDecompilerEngine: Sendable {
    public let liftingConfiguration: MicroIRLiftingConfiguration
    public let optimizationConfiguration: SSAOptimizationConfiguration

    private let lifter: ARM64ToMicroIRLifter
    private let ssaOptimizer: CytronSSAPhiAndOptimizerEngine
    private let regionRecoverer: StructuralControlFlowRecoverer
    private let codeFormatter: PseudoCCodeFormatter

    public init(
        liftingConfiguration: MicroIRLiftingConfiguration = .standard,
        optimizationConfiguration: SSAOptimizationConfiguration = .standard
    ) {
        self.liftingConfiguration = liftingConfiguration
        self.optimizationConfiguration = optimizationConfiguration
        self.lifter = ARM64ToMicroIRLifter(configuration: liftingConfiguration)
        self.ssaOptimizer = CytronSSAPhiAndOptimizerEngine(configuration: optimizationConfiguration)
        self.regionRecoverer = StructuralControlFlowRecoverer()
        self.codeFormatter = PseudoCCodeFormatter()
    }

    /// Decompiles `function` using full whole-binary `BinaryAnalysisIndex` context (strings, GOT imports, ObjC metadata, idiomatic sequences, and callee arities).
    public func decompile(
        function: RecoveredFunction,
        in analysisIndex: BinaryAnalysisIndex,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:],
        ghidraSideBySideSource: String? = nil
    ) -> DecompiledFunctionOutput {
        runPipeline(
            function: function,
            image: analysisIndex.image,
            analysisIndex: analysisIndex,
            recognizedIdioms: analysisIndex.recognizedIdioms,
            renames: renames,
            comments: comments,
            structDefinitions: structDefinitions,
            ghidraSideBySideSource: ghidraSideBySideSource
        )
    }

    /// Convenience overload accepting persisted `.machproj` model arrays (`[UserSymbolRename]`, `[UserInlineComment]`, `[CustomStructDefinition]`).
    public func decompile(
        function: RecoveredFunction,
        in analysisIndex: BinaryAnalysisIndex,
        symbolRenames: [UserSymbolRename],
        inlineComments: [UserInlineComment] = [],
        customStructs: [CustomStructDefinition] = [],
        ghidraSideBySideSource: String? = nil
    ) -> DecompiledFunctionOutput {
        var renameMap: [VirtualAddress: String] = [:]
        for r in symbolRenames where !r.customName.isEmpty {
            renameMap[r.address] = r.customName
        }
        var commentMap: [VirtualAddress: String] = [:]
        for c in inlineComments where !c.text.isEmpty {
            commentMap[c.address] = c.text
        }
        var structMap: [String: CustomStructDefinition] = [:]
        for s in customStructs {
            structMap[s.name] = s
        }
        return decompile(
            function: function,
            in: analysisIndex,
            renames: renameMap,
            comments: commentMap,
            structDefinitions: structMap,
            ghidraSideBySideSource: ghidraSideBySideSource
        )
    }

    /// Decompiles `function` directly against an optional `LoadedBinaryImage` without requiring a pre-built `BinaryAnalysisIndex`.
    public func decompile(
        function: RecoveredFunction,
        in image: LoadedBinaryImage? = nil,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:],
        ghidraSideBySideSource: String? = nil
    ) -> DecompiledFunctionOutput {
        runPipeline(
            function: function,
            image: image,
            analysisIndex: nil,
            recognizedIdioms: [],
            renames: renames,
            comments: comments,
            structDefinitions: structDefinitions,
            ghidraSideBySideSource: ghidraSideBySideSource
        )
    }

    /// Batch-decompiles all non-thunk (or all) recovered functions in `analysisIndex`.
    public func decompileAllFunctions(
        in analysisIndex: BinaryAnalysisIndex,
        includeThunks: Bool = false,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> [DecompiledFunctionOutput] {
        let targets = includeThunks
            ? analysisIndex.functions
            : analysisIndex.functions.filter { !$0.isThunk }
        return targets.map { fn in
            decompile(
                function: fn,
                in: analysisIndex,
                renames: renames,
                comments: comments,
                structDefinitions: structDefinitions
            )
        }
    }

    /// Batch-decompiles an explicit list of `[RecoveredFunction]` against an optional `LoadedBinaryImage`.
    public func decompileAllFunctions(
        _ functions: [RecoveredFunction],
        in image: LoadedBinaryImage? = nil,
        includeThunks: Bool = false,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:]
    ) -> [DecompiledFunctionOutput] {
        let targets = includeThunks ? functions : functions.filter { !$0.isThunk }
        return targets.map { fn in
            decompile(
                function: fn,
                in: image,
                renames: renames,
                comments: comments,
                structDefinitions: structDefinitions
            )
        }
    }

    // MARK: - End-to-End 4-Stage Decompilation Pipeline

    private func runPipeline(
        function: RecoveredFunction,
        image: LoadedBinaryImage?,
        analysisIndex: BinaryAnalysisIndex?,
        recognizedIdioms: [A64RecognizedIdiom],
        renames: [VirtualAddress: String],
        comments: [VirtualAddress: String],
        structDefinitions: [String: CustomStructDefinition],
        ghidraSideBySideSource: String?
    ) -> DecompiledFunctionOutput {
        // Stage 1: Lift ARM64 CFG + Idioms + Strings/ObjC/Stubs -> Micro-IR
        let lifted = lifter.lift(
            function: function,
            image: image,
            analysisIndex: analysisIndex,
            recognizedIdioms: recognizedIdioms,
            symbolOverrides: renames
        )

        // Stage 2: Cytron Dominance-Frontier SSA Construction + Fixed-Point Optimization + Type Inference
        let ssaOptimized = ssaOptimizer.buildSSAAndOptimize(
            lifted: lifted,
            function: function,
            structDefinitions: structDefinitions
        )

        // Stage 3: Out-of-SSA Phi Coalescing + Structural Region Recovery (`while`, `do-while`, `switch`, `if/else`)
        let lowered = OutOfSSACoalescer().lowerFromSSA(ssaOptimized)

        var variableTypeByKey: [SSAVarKey: CTypeExpr] = [:]
        for (v, ty) in ssaOptimized.variableTypes {
            variableTypeByKey[SSAVarKey(v)] = ty
        }

        let exprPrinter = MicroCExpressionPrinter(
            variableNameByKey: lowered.variableNameByKey,
            variableTypeByKey: variableTypeByKey,
            symbolRenames: renames,
            structDefinitions: structDefinitions
        )

        let structuredStatements = regionRecoverer.recoverStructuredStatements(
            blocks: lowered.blocks,
            entryBlockID: ssaOptimized.entryBlockID,
            printer: exprPrinter,
            localVariableDecls: lowered.localVariableDecls,
            inlineComments: comments
        )

        // Stage 4: Syntax-Highlighted Pseudo-C Emission (`PseudoCLineSpan` + `mappedAddress`)
        let displayFunctionName = renames[function.address] ?? lifted.demangledName
        let formatted = codeFormatter.formatFunction(
            functionAddress: function.address,
            functionName: displayFunctionName,
            objcContext: lifted.objcContext,
            returnType: ssaOptimized.inferredReturnType,
            parameters: ssaOptimized.inferredParameters,
            body: structuredStatements,
            inlineComments: comments
        )

        let confidence = Self.computeStructuralConfidenceScore(
            structuredStatements: structuredStatements,
            ssaBlocks: ssaOptimized.ssaBlocks
        )

        return DecompiledFunctionOutput(
            functionAddress: function.address,
            functionName: displayFunctionName,
            signatureLine: formatted.signatureLine,
            returnType: ssaOptimized.inferredReturnType,
            parameters: ssaOptimized.inferredParameters,
            localVariables: lowered.localVariableDecls,
            microBlocks: ssaOptimized.ssaBlocks,
            structuredBody: structuredStatements,
            renderedLines: formatted.lines,
            fullSourceText: formatted.fullSourceText,
            ghidraSideBySideSource: ghidraSideBySideSource,
            ssaVariableCount: ssaOptimized.metrics.totalSSAVariableCount,
            eliminatedDeadStoreCount: ssaOptimized.metrics.eliminatedDeadStoreCount,
            confidenceScore: confidence
        )
    }

    private static func computeStructuralConfidenceScore(
        structuredStatements: [PseudoCStatement],
        ssaBlocks: [MicroBasicBlock]
    ) -> Double {
        guard !ssaBlocks.isEmpty else { return 0.5 }
        var gotoCount = 0
        var intrinsicCount = 0

        func countGotos(_ stmt: PseudoCStatement) {
            switch stmt {
            case .gotoStmt:
                gotoCount += 1
            case .ifStmt(_, _, let t, let e):
                t.forEach(countGotos); e.forEach(countGotos)
            case .whileLoop(_, _, let b), .doWhileLoop(let b, _, _):
                b.forEach(countGotos)
            case .switchStmt(_, _, let arms, let d):
                arms.forEach { $0.body.forEach(countGotos) }
                d.forEach(countGotos)
            default:
                break
            }
        }
        structuredStatements.forEach(countGotos)

        for b in ssaBlocks {
            for s in b.statements {
                if case .intrinsic = s.kind {
                    intrinsicCount += 1
                }
            }
        }

        let base = 0.96
        let gotoPenalty = Double(gotoCount) * 0.06
        let intrinsicPenalty = Double(intrinsicCount) * 0.03
        return min(0.99, max(0.45, base - gotoPenalty - intrinsicPenalty))
    }
}

// MARK: - Optional Ghidra 12.1.4 Headless Side-by-Side Decompiler Bridge

public struct GhidraHeadlessSideBySideBridge: Sendable {

    public struct InstallationProbe: Sendable, Codable, Hashable {
        public let isAvailable: Bool
        public let ghidraInstallDirectory: String
        public let analyzeHeadlessPath: String
        public let javaHomePath: String
        public let nativeDecompilerPath: String?
        public let ghidraVersion: String?
        public let diagnosticMessage: String

        public init(
            isAvailable: Bool,
            ghidraInstallDirectory: String,
            analyzeHeadlessPath: String,
            javaHomePath: String,
            nativeDecompilerPath: String?,
            ghidraVersion: String?,
            diagnosticMessage: String
        ) {
            self.isAvailable = isAvailable
            self.ghidraInstallDirectory = ghidraInstallDirectory
            self.analyzeHeadlessPath = analyzeHeadlessPath
            self.javaHomePath = javaHomePath
            self.nativeDecompilerPath = nativeDecompilerPath
            self.ghidraVersion = ghidraVersion
            self.diagnosticMessage = diagnosticMessage
        }
    }

    public enum BridgeError: Error, LocalizedError, Sendable, Equatable {
        case ghidraNotInstalled(checkedPath: String)
        case javaRuntimeNotFound(checkedPath: String)
        case binaryFileMissing(path: String)
        case headlessExecutionFailed(exitCode: Int32, stderr: String)
        case functionNotFoundInGhidra(address: VirtualAddress)
        case timedOut(seconds: TimeInterval)

        public var errorDescription: String? {
            switch self {
            case .ghidraNotInstalled(let path):
                return "Ghidra analyzeHeadless executable was not found at \(path)."
            case .javaRuntimeNotFound(let path):
                return "OpenJDK 21 runtime (JAVA_HOME) was not found at \(path)."
            case .binaryFileMissing(let path):
                return "Target binary file does not exist at \(path)."
            case .headlessExecutionFailed(let code, let stderr):
                return "Ghidra analyzeHeadless exited with status \(code): \(stderr)"
            case .functionNotFoundInGhidra(let addr):
                return "Ghidra DecompInterface did not emit C source for function at \(addr.hexString)."
            case .timedOut(let sec):
                return "Ghidra headless side-by-side decompilation timed out after \(Int(sec))s."
            }
        }
    }

    public static var defaultGhidraInstallDirectory: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications/ghidra_12.1.4_PUBLIC")
            .path
    }
    public static let defaultJavaHomeDirectory = "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"

    public let ghidraInstallDirectory: String
    public let javaHomeDirectory: String
    public let timeoutSeconds: TimeInterval

    public init(
        ghidraInstallDirectory: String? = nil,
        javaHomeDirectory: String? = nil,
        timeoutSeconds: TimeInterval = 90.0
    ) {
        let env = ProcessInfo.processInfo.environment
        self.ghidraInstallDirectory = ghidraInstallDirectory
            ?? env["GHIDRA_INSTALL_DIR"]
            ?? Self.defaultGhidraInstallDirectory
        self.javaHomeDirectory = javaHomeDirectory
            ?? env["JAVA_HOME"]
            ?? Self.defaultJavaHomeDirectory
        self.timeoutSeconds = max(5.0, timeoutSeconds)
    }

    /// Non-blocking filesystem probe checking Ghidra 12.1.4 (`analyzeHeadless` + `mac_arm_64/decompile`) and OpenJDK 21 (`JAVA_HOME`).
    public func probeInstallation() -> InstallationProbe {
        let fm = FileManager.default
        let headlessPath = (ghidraInstallDirectory as NSString).appendingPathComponent("support/analyzeHeadless")
        let javaBinPath = (javaHomeDirectory as NSString).appendingPathComponent("bin/java")
        let arm64Decompile = (ghidraInstallDirectory as NSString).appendingPathComponent("Ghidra/Features/Decompiler/os/mac_arm_64/decompile")
        let x86Decompile = (ghidraInstallDirectory as NSString).appendingPathComponent("Ghidra/Features/Decompiler/os/mac_x86_64/decompile")
        let propsPath = (ghidraInstallDirectory as NSString).appendingPathComponent("Ghidra/application.properties")

        let hasHeadless = fm.isExecutableFile(atPath: headlessPath)
        let hasJava = fm.isExecutableFile(atPath: javaBinPath)
        let nativeDecomp: String? = fm.isExecutableFile(atPath: arm64Decompile)
            ? arm64Decompile
            : (fm.isExecutableFile(atPath: x86Decompile) ? x86Decompile : nil)

        var parsedVersion: String? = nil
        if let propsText = try? String(contentsOfFile: propsPath, encoding: .utf8) {
            for line in propsText.split(whereSeparator: \.isNewline) {
                if line.hasPrefix("application.version=") {
                    parsedVersion = String(line.dropFirst("application.version=".count)).trimmingCharacters(in: .whitespaces)
                    break
                }
            }
        }

        let available = hasHeadless && hasJava && nativeDecomp != nil
        let diag: String
        if available {
            diag = "Ghidra \(parsedVersion ?? "12.x") side-by-side headless decompiler ready (\(headlessPath))."
        } else if !hasHeadless {
            diag = "Ghidra analyzeHeadless missing at \(headlessPath); using pure-Swift MachMicroDecompiler."
        } else if !hasJava {
            diag = "OpenJDK 21 missing at \(javaBinPath); using pure-Swift MachMicroDecompiler."
        } else {
            diag = "Ghidra native decompiler binary missing under \(ghidraInstallDirectory); using pure-Swift MachMicroDecompiler."
        }

        return InstallationProbe(
            isAvailable: available,
            ghidraInstallDirectory: ghidraInstallDirectory,
            analyzeHeadlessPath: headlessPath,
            javaHomePath: javaHomeDirectory,
            nativeDecompilerPath: nativeDecomp,
            ghidraVersion: parsedVersion,
            diagnosticMessage: diag
        )
    }

    /// Runs MachGraph's native pure-Swift SSA decompiler immediately and attaches Ghidra 12.1.4's C output side-by-side when available.
    public func decompileSideBySide(
        function: RecoveredFunction,
        in analysisIndex: BinaryAnalysisIndex,
        binaryData: Data,
        renames: [VirtualAddress: String] = [:],
        comments: [VirtualAddress: String] = [:],
        structDefinitions: [String: CustomStructDefinition] = [:],
        decompilerEngine: MachMicroDecompilerEngine = MachMicroDecompilerEngine()
    ) async -> DecompiledFunctionOutput {
        let ghidraSource: String?
        if probeInstallation().isAvailable {
            ghidraSource = try? await decompileFunction(
                inBinaryData: binaryData,
                binaryName: analysisIndex.image.fileName.isEmpty ? "target.macho" : analysisIndex.image.fileName,
                functionAddress: function.address,
                functionName: function.name
            )
        } else {
            ghidraSource = nil
        }

        return decompilerEngine.decompile(
            function: function,
            in: analysisIndex,
            renames: renames,
            comments: comments,
            structDefinitions: structDefinitions,
            ghidraSideBySideSource: ghidraSource
        )
    }

    /// Invokes Ghidra `analyzeHeadless` + `DecompInterface` on in-memory `binaryData` in an isolated ephemeral workspace.
    public func decompileFunction(
        inBinaryData binaryData: Data,
        binaryName: String = "target.macho",
        functionAddress: VirtualAddress,
        functionName: String? = nil
    ) async throws -> String {
        let fm = FileManager.default
        let workDir = fm.temporaryDirectory.appendingPathComponent("machgraph-ghidra-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer {
            try? fm.removeItem(at: workDir)
        }

        let sanitizedName = binaryName.replacingOccurrences(of: "/", with: "_")
        let binURL = workDir.appendingPathComponent(sanitizedName.isEmpty ? "target.macho" : sanitizedName)
        try binaryData.write(to: binURL, options: .atomic)

        return try await runHeadlessDecompile(
            binaryURL: binURL,
            workspaceDirectory: workDir,
            functionAddress: functionAddress,
            functionName: functionName
        )
    }

    /// Invokes Ghidra `analyzeHeadless` + `DecompInterface` on an on-disk Mach-O/ELF/PE binary URL.
    public func decompileFunction(
        atBinaryURL binaryURL: URL,
        functionAddress: VirtualAddress,
        functionName: String? = nil
    ) async throws -> String {
        let fm = FileManager.default
        guard fm.fileExists(atPath: binaryURL.path) else {
            throw BridgeError.binaryFileMissing(path: binaryURL.path)
        }
        let workDir = fm.temporaryDirectory.appendingPathComponent("machgraph-ghidra-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer {
            try? fm.removeItem(at: workDir)
        }

        return try await runHeadlessDecompile(
            binaryURL: binaryURL,
            workspaceDirectory: workDir,
            functionAddress: functionAddress,
            functionName: functionName
        )
    }

    private func runHeadlessDecompile(
        binaryURL: URL,
        workspaceDirectory: URL,
        functionAddress: VirtualAddress,
        functionName: String?
    ) async throws -> String {
        let probe = probeInstallation()
        guard FileManager.default.isExecutableFile(atPath: probe.analyzeHeadlessPath) else {
            throw BridgeError.ghidraNotInstalled(checkedPath: probe.analyzeHeadlessPath)
        }
        let javaExec = (probe.javaHomePath as NSString).appendingPathComponent("bin/java")
        guard FileManager.default.isExecutableFile(atPath: javaExec) else {
            throw BridgeError.javaRuntimeNotFound(checkedPath: javaExec)
        }

        let scriptDir = workspaceDirectory.appendingPathComponent("scripts", isDirectory: true)
        let projectDir = workspaceDirectory.appendingPathComponent("proj", isDirectory: true)
        let outputURL = workspaceDirectory.appendingPathComponent("decompiled.c")
        try FileManager.default.createDirectory(at: scriptDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: projectDir, withIntermediateDirectories: true)

        // Write self-contained Ghidra 12 Java GhidraScript invoking `DecompInterface`
        let scriptURL = scriptDir.appendingPathComponent("MachGraphExportDecomp.java")
        let javaScriptSource = Self.buildGhidraDecompJavaScript()
        try javaScriptSource.write(to: scriptURL, atomically: true, encoding: .utf8)

        let hexTarget = String(format: "0x%llx", functionAddress.rawValue)
        let fallbackName = functionName ?? ""

        let arguments: [String] = [
            projectDir.path,
            "MGTempProj",
            "-import", binaryURL.path,
            "-scriptPath", scriptDir.path,
            "-postScript", "MachGraphExportDecomp.java", hexTarget, outputURL.path, fallbackName,
            "-deleteProject"
        ]

        let timeout = self.timeoutSeconds
        let javaHome = probe.javaHomePath
        let ghidraDir = probe.ghidraInstallDirectory
        let headlessExec = probe.analyzeHeadlessPath

        let executionResult: (status: Int32, stderr: String, timedOut: Bool) = try await Task.detached(priority: .utility) {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: headlessExec)
            proc.arguments = arguments

            var env = ProcessInfo.processInfo.environment
            env["JAVA_HOME"] = javaHome
            env["GHIDRA_INSTALL_DIR"] = ghidraDir
            let existingPath = env["PATH"] ?? "/usr/bin:/bin"
            env["PATH"] = "\(javaHome)/bin:\(existingPath)"
            proc.environment = env

            let outPipe = Pipe()
            let errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe

            try proc.run()

            let deadline = Date().addingTimeInterval(timeout)
            var didTimeout = false
            while proc.isRunning {
                if Date() >= deadline {
                    didTimeout = true
                    proc.terminate()
                    break
                }
                try? await Task.sleep(for: .milliseconds(50))
            }
            proc.waitUntilExit()

            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errStr = String(data: errData, encoding: .utf8) ?? ""
            return (proc.terminationStatus, errStr, didTimeout)
        }.value

        if executionResult.timedOut {
            throw BridgeError.timedOut(seconds: timeout)
        }
        if executionResult.status != 0 && !FileManager.default.fileExists(atPath: outputURL.path) {
            throw BridgeError.headlessExecutionFailed(
                exitCode: executionResult.status,
                stderr: String(executionResult.stderr.suffix(600))
            )
        }

        guard let cSource = try? String(contentsOf: outputURL, encoding: .utf8),
              !cSource.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw BridgeError.functionNotFoundInGhidra(address: functionAddress)
        }

        return cSource.trimmingCharacters(in: .newlines)
    }

    private static func buildGhidraDecompJavaScript() -> String {
        """
        import ghidra.app.decompiler.DecompInterface;
        import ghidra.app.decompiler.DecompileResults;
        import ghidra.app.script.GhidraScript;
        import ghidra.program.model.address.Address;
        import ghidra.program.model.listing.Function;
        import ghidra.program.model.listing.FunctionIterator;
        import java.io.File;
        import java.nio.charset.StandardCharsets;
        import java.nio.file.Files;

        public class MachGraphExportDecomp extends GhidraScript {
            @Override
            protected void run() throws Exception {
                String[] args = getScriptArgs();
                if (args.length < 2) {
                    return;
                }
                String addrStr = args[0];
                String outPath = args[1];
                String fallbackName = args.length >= 3 ? args[2] : "";

                Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
                Function targetFn = null;
                if (addr != null) {
                    targetFn = getFunctionAt(addr);
                    if (targetFn == null) {
                        targetFn = getFunctionContaining(addr);
                    }
                }
                if (targetFn == null && !fallbackName.isEmpty()) {
                    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                    while (it.hasNext()) {
                        Function f = it.next();
                        if (f.getName().equals(fallbackName) || ("_" + f.getName()).equals(fallbackName)) {
                            targetFn = f;
                            break;
                        }
                    }
                }
                if (targetFn == null) {
                    return;
                }

                DecompInterface ifc = new DecompInterface();
                ifc.openProgram(currentProgram);
                try {
                    DecompileResults res = ifc.decompileFunction(targetFn, 30, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        String cCode = res.getDecompiledFunction().getC();
                        Files.write(new File(outPath).toPath(), cCode.getBytes(StandardCharsets.UTF_8));
                    }
                } finally {
                    ifc.dispose();
                }
            }
        }
        """
    }
}
