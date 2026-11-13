import Foundation
import Combine
import MachGraphModels
import MachProjectStore

// MARK: - Go-To-Address / Offset / Symbol Resolution Models

public enum GoToMatchKind: String, Sendable, Codable, Hashable {
    case absoluteVirtualAddress = "Virtual Address"
    case relativeCursorDelta = "Cursor Relative Offset"
    case imageBaseDelta = "Image Base + Offset"
    case entryPointDelta = "Entry Point + Offset"
    case fileOffset = "Binary File Offset"
    case functionOrSymbol = "Symbol / Function"
    case sectionStart = "Section Base"
}

public struct ResolvedGoToTarget: Sendable, Codable, Hashable {
    public let virtualAddress: VirtualAddress
    public let fileOffset: FileOffset?
    public let functionAddress: VirtualAddress?
    public let blockID: Int?
    public let displayLabel: String
    public let sectionSummary: String?
    public let matchKind: GoToMatchKind

    public init(
        virtualAddress: VirtualAddress,
        fileOffset: FileOffset? = nil,
        functionAddress: VirtualAddress? = nil,
        blockID: Int? = nil,
        displayLabel: String,
        sectionSummary: String? = nil,
        matchKind: GoToMatchKind
    ) {
        self.virtualAddress = virtualAddress
        self.fileOffset = fileOffset
        self.functionAddress = functionAddress
        self.blockID = blockID
        self.displayLabel = displayLabel
        self.sectionSummary = sectionSummary
        self.matchKind = matchKind
    }

    public func toCursorLocation(originPane: WorkbenchPaneTab) -> SynchronizedCursorLocation {
        SynchronizedCursorLocation(
            virtualAddress: virtualAddress,
            fileOffset: fileOffset,
            functionAddress: functionAddress,
            blockID: blockID,
            originPane: originPane
        )
    }
}

public enum GoToParseFailure: Error, LocalizedError, Sendable, Equatable {
    case emptyQuery
    case invalidAddressExpression(String)
    case unmappedFileOffset(FileOffset)
    case unknownSymbolOrFunction(String)

    public var errorDescription: String? {
        switch self {
        case .emptyQuery:
            return "Enter a virtual address (0x100001000), relative offset (+0x400), file offset (off:0x1000), or symbol (_verify_license)."
        case .invalidAddressExpression(let expr):
            return "Malformed address or offset expression '\(expr)'."
        case .unmappedFileOffset(let off):
            return "File offset \(off.hexString) does not map into any loaded binary segment."
        case .unknownSymbolOrFunction(let sym):
            return "No symbol, recovered function, custom rename, or section matched '\(sym)'."
        }
    }
}

// MARK: - Stateless Go-To Expression Parser (`G` Shortcut Engine)

public enum MachGoToExpressionParser: Sendable {

    /// Parses and resolves a user Go-To expression such as:
    /// - `0x100001000` / `0x1_0000_1040` (hex virtual address)
    /// - `+0x400` / `-0x20` / `+64` (signed offset from `currentAddress`)
    /// - `base+0x1000` / `entry+0x14` (offset from imageBase or entryPoint)
    /// - `off:0x1000` / `file:0x1000` / `@0x1000` (raw file offset translated to VA)
    /// - `_verify_license` / `_verify_license+0x14` / `-[MGAuthController validateToken:]` (symbol/rename/function + optional addend)
    public static func parse(
        query rawQuery: String,
        currentAddress: VirtualAddress,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        cachedFunctions: [CachedFunctionSummary] = [],
        customRenames: [UserSymbolRename] = []
    ) -> Result<ResolvedGoToTarget, GoToParseFailure> {
        let trimmed = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .failure(.emptyQuery)
        }

        // 1. Relative delta from current cursor (`+0x400`, `-0x20`, `+16`)
        if trimmed.hasPrefix("+") || (trimmed.hasPrefix("-") && !trimmed.hasPrefix("-[")) {
            let isNegative = trimmed.hasPrefix("-")
            let body = String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
            guard let mag = parseUnsignedScalar(body) else {
                return .failure(.invalidAddressExpression(trimmed))
            }
            let signedDelta = isNegative ? -Int64(bitPattern: mag) : Int64(bitPattern: mag)
            let resolvedVA = currentAddress.adding(signedDelta)
            return .success(enrichTarget(
                at: resolvedVA,
                preferredLabel: "\(currentAddress.compactHexString) \(isNegative ? "-" : "+") 0x\(String(mag, radix: 16))",
                matchKind: .relativeCursorDelta,
                image: image,
                functions: functions,
                cachedFunctions: cachedFunctions,
                customRenames: customRenames
            ))
        }

        // 2. Explicit file offset (`off:0x1000`, `file:0x400`, `@0x1000`)
        let lower = trimmed.lowercased()
        if lower.hasPrefix("off:") || lower.hasPrefix("offset:") || lower.hasPrefix("file:") || lower.hasPrefix("@") {
            let rawOffPart: String
            if lower.hasPrefix("offset:") {
                rawOffPart = String(trimmed.dropFirst(7))
            } else if lower.hasPrefix("file:") {
                rawOffPart = String(trimmed.dropFirst(5))
            } else if lower.hasPrefix("off:") {
                rawOffPart = String(trimmed.dropFirst(4))
            } else {
                rawOffPart = String(trimmed.dropFirst(1))
            }
            guard let offVal = parseUnsignedScalar(rawOffPart.trimmingCharacters(in: .whitespaces)) else {
                return .failure(.invalidAddressExpression(trimmed))
            }
            let fileOff = FileOffset(offVal)
            if let image {
                guard let mappedVA = image.virtualAddress(for: fileOff) else {
                    return .failure(.unmappedFileOffset(fileOff))
                }
                return .success(enrichTarget(
                    at: mappedVA,
                    explicitFileOffset: fileOff,
                    preferredLabel: "File \(fileOff.hexString) -> \(mappedVA.compactHexString)",
                    matchKind: .fileOffset,
                    image: image,
                    functions: functions,
                    cachedFunctions: cachedFunctions,
                    customRenames: customRenames
                ))
            } else {
                let directVA = VirtualAddress(offVal)
                return .success(ResolvedGoToTarget(
                    virtualAddress: directVA,
                    fileOffset: fileOff,
                    displayLabel: "Offset \(fileOff.hexString)",
                    matchKind: .fileOffset
                ))
            }
        }

        // 3. `base` / `entry` anchor expressions (`base`, `base+0x1000`, `entry`, `entry+0x10`)
        if let (anchorToken, signedAddend) = splitSymbolAndAddend(trimmed) {
            let anchorLower = anchorToken.lowercased()
            if anchorLower == "base" || anchorLower == "imagebase" || anchorLower == "__mh_execute_header" {
                let baseVA = image?.imageBase ?? .zero
                let targetVA = baseVA.adding(signedAddend)
                return .success(enrichTarget(
                    at: targetVA,
                    preferredLabel: signedAddend == 0 ? "imageBase (\(targetVA.compactHexString))" : "imageBase + 0x\(String(signedAddend, radix: 16))",
                    matchKind: .imageBaseDelta,
                    image: image,
                    functions: functions,
                    cachedFunctions: cachedFunctions,
                    customRenames: customRenames
                ))
            }
            if anchorLower == "entry" || anchorLower == "entrypoint" || anchorLower == "_start" {
                if let entryVA = image?.entryPoint {
                    let targetVA = entryVA.adding(signedAddend)
                    return .success(enrichTarget(
                        at: targetVA,
                        preferredLabel: signedAddend == 0 ? "entryPoint (\(targetVA.compactHexString))" : "entryPoint + 0x\(String(signedAddend, radix: 16))",
                        matchKind: .entryPointDelta,
                        image: image,
                        functions: functions,
                        cachedFunctions: cachedFunctions,
                        customRenames: customRenames
                    ))
                }
            }
        }

        // 4. Direct hex or numeric virtual address (`0x100001000`, `100001000`)
        if lower.hasPrefix("0x") {
            let cleanHex = String(trimmed.dropFirst(2)).replacingOccurrences(of: "_", with: "")
            if let addrVal = UInt64(cleanHex, radix: 16) {
                let va = VirtualAddress(addrVal)
                return .success(enrichTarget(
                    at: va,
                    preferredLabel: nil,
                    matchKind: .absoluteVirtualAddress,
                    image: image,
                    functions: functions,
                    cachedFunctions: cachedFunctions,
                    customRenames: customRenames
                ))
            }
            // Could be `0x100001000+0x10`
            if let (lhsHex, addend) = splitSymbolAndAddend(trimmed),
               lhsHex.lowercased().hasPrefix("0x"),
               let baseVal = UInt64(String(lhsHex.dropFirst(2)).replacingOccurrences(of: "_", with: ""), radix: 16) {
                let va = VirtualAddress(baseVal).adding(addend)
                return .success(enrichTarget(
                    at: va,
                    preferredLabel: nil,
                    matchKind: .absoluteVirtualAddress,
                    image: image,
                    functions: functions,
                    cachedFunctions: cachedFunctions,
                    customRenames: customRenames
                ))
            }
            return .failure(.invalidAddressExpression(trimmed))
        }

        // Bare hex address without `0x` if all characters are hex digits AND length >= 6 and matches a mapped range (or pure digits)
        let strippedUnderscore = trimmed.replacingOccurrences(of: "_", with: "")
        let allHexChars = !strippedUnderscore.isEmpty && strippedUnderscore.unicodeScalars.allSatisfy {
            ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") || ($0 >= "A" && $0 <= "F")
        }
        if allHexChars {
            // Check symbol match first in case a symbol is named e.g. `deadbeef` or `f1`
            if resolveSymbolAddress(
                named: trimmed,
                image: image,
                functions: functions,
                cachedFunctions: cachedFunctions,
                customRenames: customRenames
            ) == nil {
                if let hexVal = UInt64(strippedUnderscore, radix: 16) {
                    let hexVA = VirtualAddress(hexVal)
                    if image?.section(containing: hexVA) != nil || strippedUnderscore.count >= 8 {
                        return .success(enrichTarget(
                            at: hexVA,
                            preferredLabel: nil,
                            matchKind: .absoluteVirtualAddress,
                            image: image,
                            functions: functions,
                            cachedFunctions: cachedFunctions,
                            customRenames: customRenames
                        ))
                    }
                }
                if let decVal = UInt64(strippedUnderscore, radix: 10) {
                    let decVA = VirtualAddress(decVal)
                    return .success(enrichTarget(
                        at: decVA,
                        preferredLabel: nil,
                        matchKind: .absoluteVirtualAddress,
                        image: image,
                        functions: functions,
                        cachedFunctions: cachedFunctions,
                        customRenames: customRenames
                    ))
                }
            }
        }

        // 5. Symbol / Function / Custom Rename / ObjC Method / Section + optional `+0xOffset`
        let (symbolPart, addend) = splitSymbolAndAddend(trimmed) ?? (trimmed, 0)

        if let (symAddr, symDisplay) = resolveSymbolAddress(
            named: symbolPart,
            image: image,
            functions: functions,
            cachedFunctions: cachedFunctions,
            customRenames: customRenames
        ) {
            let finalVA = symAddr.adding(addend)
            let label = addend == 0
                ? symDisplay
                : "\(symDisplay) \(addend >= 0 ? "+" : "-") 0x\(String(addend.magnitude, radix: 16))"
            return .success(enrichTarget(
                at: finalVA,
                preferredLabel: label,
                matchKind: .functionOrSymbol,
                image: image,
                functions: functions,
                cachedFunctions: cachedFunctions,
                customRenames: customRenames
            ))
        }

        // 6. Section name match (`__TEXT,__text`, `__cstring`)
        if let image {
            let norm = symbolPart.lowercased()
            if let sec = image.sections.first(where: {
                $0.fullName.lowercased() == norm || $0.sectionName.lowercased() == norm
            }) {
                let finalVA = sec.vmAddress.adding(addend)
                return .success(enrichTarget(
                    at: finalVA,
                    preferredLabel: sec.fullName,
                    matchKind: .sectionStart,
                    image: image,
                    functions: functions,
                    cachedFunctions: cachedFunctions,
                    customRenames: customRenames
                ))
            }
        }

        return .failure(.unknownSymbolOrFunction(trimmed))
    }

    // MARK: Internal Resolution Helpers

    private static func parseUnsignedScalar(_ text: String) -> UInt64? {
        let clean = text.replacingOccurrences(of: "_", with: "")
        guard !clean.isEmpty else { return nil }
        if clean.lowercased().hasPrefix("0x") {
            return UInt64(String(clean.dropFirst(2)), radix: 16)
        }
        let hasHexLetters = clean.unicodeScalars.contains {
            ($0 >= "a" && $0 <= "f") || ($0 >= "A" && $0 <= "F")
        }
        if hasHexLetters {
            return UInt64(clean, radix: 16)
        }
        return UInt64(clean, radix: 10) ?? UInt64(clean, radix: 16)
    }

    private static func splitSymbolAndAddend(_ expr: String) -> (symbol: String, addend: Int64)? {
        // Avoid splitting Objective-C leading `-[Class sel]` or `+[Class sel]` at index 0
        let startOffset = (expr.hasPrefix("-[") || expr.hasPrefix("+[")) ? 2 : 1
        guard expr.count > startOffset else { return nil }
        let searchStart = expr.index(expr.startIndex, offsetBy: startOffset)
        let tail = expr[searchStart...]

        if let plusIdx = tail.lastIndex(of: "+") {
            let lhs = String(expr[..<plusIdx]).trimmingCharacters(in: .whitespaces)
            let rhs = String(expr[expr.index(after: plusIdx)...]).trimmingCharacters(in: .whitespaces)
            if !lhs.isEmpty, let delta = parseUnsignedScalar(rhs) {
                return (lhs, Int64(bitPattern: delta))
            }
        }
        if let minusIdx = tail.lastIndex(of: "-") {
            let lhs = String(expr[..<minusIdx]).trimmingCharacters(in: .whitespaces)
            let rhs = String(expr[expr.index(after: minusIdx)...]).trimmingCharacters(in: .whitespaces)
            if !lhs.isEmpty, !lhs.hasSuffix("["), let delta = parseUnsignedScalar(rhs) {
                return (lhs, -Int64(bitPattern: delta))
            }
        }
        return (expr, 0)
    }

    private static func resolveSymbolAddress(
        named rawName: String,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction],
        cachedFunctions: [CachedFunctionSummary],
        customRenames: [UserSymbolRename]
    ) -> (VirtualAddress, String)? {
        let query = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return nil }
        let altUnderscore = query.hasPrefix("_") ? String(query.dropFirst()) : "_\(query)"

        // 1. Exact custom analyst rename
        if let ren = customRenames.first(where: {
            $0.customName == query || $0.customName == altUnderscore
        }) {
            return (ren.address, ren.customName)
        }

        // 2. Exact recovered function match
        if let fn = functions.first(where: {
            $0.name == query || $0.demangledName == query ||
            $0.name == altUnderscore || $0.demangledName == altUnderscore
        }) {
            return (fn.address, fn.demangledName)
        }

        // 3. Exact cached function summary match
        if let cached = cachedFunctions.first(where: {
            $0.effectiveDisplayName == query || $0.name == query ||
            $0.demangledName == query || $0.name == altUnderscore
        }) {
            return (cached.address, cached.effectiveDisplayName)
        }

        // 4. Exact BinarySymbol or ObjC method match
        if let image {
            if let sym = image.symbols.first(where: {
                ($0.name == query || $0.demangledName == query ||
                 $0.name == altUnderscore || $0.demangledName == altUnderscore) && $0.address.rawValue != 0
            }) {
                return (sym.address, sym.demangledName)
            }
            for cls in image.objcClasses {
                for m in cls.methods {
                    let fullObjC = "\(m.isClassMethod ? "+" : "-")[\(cls.name) \(m.selector)]"
                    if fullObjC.caseInsensitiveCompare(query) == .orderedSame || m.selector == query {
                        return (m.implementationAddress, fullObjC)
                    }
                }
            }
        }

        // 5. Case-insensitive substring fallback across custom renames, functions, and defined symbols
        let qLower = query.lowercased()
        if let ren = customRenames.first(where: { $0.customName.lowercased().contains(qLower) }) {
            return (ren.address, ren.customName)
        }
        if let fn = functions.first(where: {
            $0.name.lowercased().contains(qLower) || $0.demangledName.lowercased().contains(qLower)
        }) {
            return (fn.address, fn.demangledName)
        }
        if let cached = cachedFunctions.first(where: {
            $0.effectiveDisplayName.lowercased().contains(qLower) || $0.name.lowercased().contains(qLower)
        }) {
            return (cached.address, cached.effectiveDisplayName)
        }
        if let sym = image?.symbols.first(where: {
            $0.address.rawValue != 0 &&
            ($0.name.lowercased().contains(qLower) || $0.demangledName.lowercased().contains(qLower))
        }) {
            return (sym.address, sym.demangledName)
        }

        return nil
    }

    private static func enrichTarget(
        at va: VirtualAddress,
        explicitFileOffset: FileOffset? = nil,
        preferredLabel: String?,
        matchKind: GoToMatchKind,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction],
        cachedFunctions: [CachedFunctionSummary],
        customRenames: [UserSymbolRename]
    ) -> ResolvedGoToTarget {
        let fileOffset = explicitFileOffset ?? image?.fileOffset(for: va)
        let containingFn = functions.first { va >= $0.address && va < $0.endAddress }
        let containingCachedFn = cachedFunctions.first { va >= $0.address && va < $0.endAddress }
        let fnAddr = containingFn?.address ?? containingCachedFn?.address
        let blockID = containingFn?.block(containing: va)?.id
        let sectionSummary = image?.section(containing: va)?.fullName

        let computedLabel: String = {
            if let preferredLabel, !preferredLabel.isEmpty {
                return preferredLabel
            }
            if let fnAddr, let ren = customRenames.first(where: { $0.address == fnAddr }) {
                let delta = va.rawValue >= fnAddr.rawValue ? va.rawValue - fnAddr.rawValue : 0
                return delta == 0 ? ren.customName : "\(ren.customName) + 0x\(String(delta, radix: 16))"
            }
            if let fn = containingFn {
                let delta = va.rawValue - fn.address.rawValue
                return delta == 0 ? fn.demangledName : "\(fn.demangledName) + 0x\(String(delta, radix: 16))"
            }
            if let cfn = containingCachedFn {
                let delta = va.rawValue - cfn.address.rawValue
                return delta == 0 ? cfn.effectiveDisplayName : "\(cfn.effectiveDisplayName) + 0x\(String(delta, radix: 16))"
            }
            if let sym = image?.exactSymbol(at: va) {
                return sym.demangledName
            }
            return va.compactHexString
        }()

        return ResolvedGoToTarget(
            virtualAddress: va,
            fileOffset: fileOffset,
            functionAddress: fnAddr,
            blockID: blockID,
            displayLabel: computedLabel,
            sectionSummary: sectionSummary,
            matchKind: matchKind
        )
    }
}

// MARK: - Synchronized Address Cursor Bus (`@MainActor ObservableObject`)

@MainActor
public final class SynchronizedAddressCursorBus: ObservableObject {

    @Published public private(set) var currentLocation: SynchronizedCursorLocation
    @Published public private(set) var backHistoryStack: [SynchronizedCursorLocation] = []
    @Published public private(set) var forwardHistoryStack: [SynchronizedCursorLocation] = []

    @Published public var activeFunctionAddress: VirtualAddress?
    @Published public var activeBlockID: Int?
    @Published public var activePane: WorkbenchPaneTab
    @Published public var secondarySplitPane: WorkbenchPaneTab?
    @Published public var highlightedSymbolOrRegister: String?
    @Published public private(set) var recentJumpQueries: [String] = []

    public let maxHistoryCapacity: Int
    private weak var attachedDatabase: MachProjectDatabase?

    public init(
        initialLocation: SynchronizedCursorLocation = SynchronizedCursorLocation(
            virtualAddress: VirtualAddress(0x100001000),
            originPane: .cfgGraph
        ),
        activePane: WorkbenchPaneTab = .cfgGraph,
        secondarySplitPane: WorkbenchPaneTab? = nil,
        maxHistoryCapacity: Int = 128
    ) {
        self.currentLocation = initialLocation
        self.activeFunctionAddress = initialLocation.functionAddress
        self.activeBlockID = initialLocation.blockID
        self.activePane = activePane
        self.secondarySplitPane = secondarySplitPane
        self.maxHistoryCapacity = max(16, maxHistoryCapacity)
    }

    // MARK: Database Attachment & Persistence

    public func attachProjectDatabase(_ database: MachProjectDatabase?, restoreSavedCursor: Bool = true) {
        self.attachedDatabase = database
        guard restoreSavedCursor, let database else { return }
        if let saved = try? database.lastCursorLocation() {
            self.currentLocation = saved
            self.activeFunctionAddress = saved.functionAddress
            self.activeBlockID = saved.blockID
            self.activePane = saved.originPane
        }
    }

    // MARK: Navigation History Introspection

    public var canNavigateBack: Bool {
        !backHistoryStack.isEmpty
    }

    public var canNavigateForward: Bool {
        !forwardHistoryStack.isEmpty
    }

    public var isSplitViewActive: Bool {
        secondarySplitPane != nil
    }

    public var historyDepthSummary: String {
        "\(backHistoryStack.count) back · \(forwardHistoryStack.count) fwd"
    }

    // MARK: Synchronized Jump & History Stack Operations

    public func jump(to location: SynchronizedCursorLocation, recordHistory: Bool = true) {
        if recordHistory && location.virtualAddress != currentLocation.virtualAddress {
            backHistoryStack.append(currentLocation)
            if backHistoryStack.count > maxHistoryCapacity {
                backHistoryStack.removeFirst(backHistoryStack.count - maxHistoryCapacity)
            }
            forwardHistoryStack.removeAll(keepingCapacity: true)
        }

        currentLocation = location
        if let fnAddr = location.functionAddress {
            activeFunctionAddress = fnAddr
        }
        activeBlockID = location.blockID
        persistCursorIfAttached(location)
    }

    public func jump(
        toAddress address: VirtualAddress,
        in image: LoadedBinaryImage? = nil,
        functions: [RecoveredFunction] = [],
        originPane: WorkbenchPaneTab? = nil,
        switchToPane: WorkbenchPaneTab? = nil,
        recordHistory: Bool = true
    ) {
        let fileOff = image?.fileOffset(for: address)
        let enclosingFn = functions.first { address >= $0.address && address < $0.endAddress }
            ?? functions.first { $0.address == address }
        let blockID = enclosingFn?.block(containing: address)?.id

        let targetPane = switchToPane ?? originPane ?? activePane
        if let switchToPane {
            activePane = switchToPane
        }

        let location = SynchronizedCursorLocation(
            virtualAddress: address,
            fileOffset: fileOff,
            functionAddress: enclosingFn?.address ?? activeFunctionAddress,
            blockID: blockID,
            originPane: targetPane
        )
        jump(to: location, recordHistory: recordHistory)
    }

    public func selectFunction(
        _ function: RecoveredFunction,
        in image: LoadedBinaryImage? = nil,
        originPane: WorkbenchPaneTab? = nil
    ) {
        let entryBlockID = function.blocks.first(where: \.isEntry)?.id ?? function.blocks.first?.id
        let loc = SynchronizedCursorLocation(
            virtualAddress: function.address,
            fileOffset: image?.fileOffset(for: function.address),
            functionAddress: function.address,
            blockID: entryBlockID,
            originPane: originPane ?? activePane
        )
        activeFunctionAddress = function.address
        jump(to: loc, recordHistory: true)
    }

    @discardableResult
    public func navigateBack() -> SynchronizedCursorLocation? {
        guard let previous = backHistoryStack.popLast() else {
            return nil
        }
        forwardHistoryStack.append(currentLocation)
        currentLocation = previous
        if let fnAddr = previous.functionAddress {
            activeFunctionAddress = fnAddr
        }
        activeBlockID = previous.blockID
        persistCursorIfAttached(previous)
        return previous
    }

    @discardableResult
    public func navigateForward() -> SynchronizedCursorLocation? {
        guard let next = forwardHistoryStack.popLast() else {
            return nil
        }
        backHistoryStack.append(currentLocation)
        currentLocation = next
        if let fnAddr = next.functionAddress {
            activeFunctionAddress = fnAddr
        }
        activeBlockID = next.blockID
        persistCursorIfAttached(next)
        return next
    }

    public func clearNavigationHistory() {
        backHistoryStack.removeAll()
        forwardHistoryStack.removeAll()
    }

    // MARK: Primary / Split-View Pane Orchestration

    /// `Space` shortcut: toggles rapidly between `CFG Graph` and `Linear Disassembly`.
    public func toggleCFGAndLinearDisassembly() {
        if activePane == .cfgGraph {
            activePane = .disassembly
        } else {
            activePane = .cfgGraph
        }
    }

    /// Configures side-by-side split view (e.g., `CFG Graph` on left + `Pseudo-C Decompiler` on right).
    public func enableSideBySideSplit(
        primary: WorkbenchPaneTab? = nil,
        secondary: WorkbenchPaneTab = .pseudoC
    ) {
        if let primary {
            activePane = primary
        }
        if secondary == activePane {
            secondarySplitPane = (activePane == .cfgGraph) ? .pseudoC : .cfgGraph
        } else {
            secondarySplitPane = secondary
        }
    }

    public func disableSplitView() {
        secondarySplitPane = nil
    }

    public func toggleSplitView(defaultSecondary: WorkbenchPaneTab = .pseudoC) {
        if secondarySplitPane != nil {
            secondarySplitPane = nil
        } else {
            enableSideBySideSplit(primary: nil, secondary: defaultSecondary)
        }
    }

    // MARK: `G` Go-To-Address / Offset / Symbol Evaluation & Jump

    public func previewGoToQuery(
        _ query: String,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        cachedFunctions: [CachedFunctionSummary] = [],
        customRenames: [UserSymbolRename] = []
    ) -> Result<ResolvedGoToTarget, GoToParseFailure> {
        MachGoToExpressionParser.parse(
            query: query,
            currentAddress: currentLocation.virtualAddress,
            image: image,
            functions: functions,
            cachedFunctions: cachedFunctions,
            customRenames: customRenames
        )
    }

    @discardableResult
    public func executeGoToQuery(
        _ query: String,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        cachedFunctions: [CachedFunctionSummary] = [],
        customRenames: [UserSymbolRename] = []
    ) -> Result<ResolvedGoToTarget, GoToParseFailure> {
        let outcome = previewGoToQuery(
            query,
            image: image,
            functions: functions,
            cachedFunctions: cachedFunctions,
            customRenames: customRenames
        )
        if case .success(let resolved) = outcome {
            let cleanQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleanQuery.isEmpty {
                recentJumpQueries.removeAll { $0 == cleanQuery }
                recentJumpQueries.insert(cleanQuery, at: 0)
                if recentJumpQueries.count > 12 {
                    recentJumpQueries.removeLast(recentJumpQueries.count - 12)
                }
            }
            jump(to: resolved.toCursorLocation(originPane: activePane), recordHistory: true)
        }
        return outcome
    }

    private func persistCursorIfAttached(_ cursor: SynchronizedCursorLocation) {
        guard let attachedDatabase else { return }
        try? attachedDatabase.saveLastCursorLocation(cursor)
    }
}
