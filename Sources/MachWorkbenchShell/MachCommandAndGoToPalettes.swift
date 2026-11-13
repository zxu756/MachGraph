import Foundation
import SwiftUI
import MachGraphModels
import MachProjectStore

// MARK: - Zero-Latency Subsequence Fuzzy Matcher

public struct FuzzyMatchResult: Sendable, Hashable {
    public let score: Int
    public let matchedCharacterPositions: [Int]

    public init(score: Int, matchedCharacterPositions: [Int]) {
        self.score = score
        self.matchedCharacterPositions = matchedCharacterPositions
    }
}

public enum FuzzySubsequenceMatcher: Sendable {

    /// Scores `query` as a case-insensitive subsequence of `candidate` in O(|candidate|) time.
    /// Awards bonuses for consecutive matches, leading prefix, `_` / `.` / `:` / `[` boundaries, and camelCase transitions.
    public static func match(query rawQuery: String, in candidate: String) -> FuzzyMatchResult? {
        let query = rawQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        if query.isEmpty {
            return FuzzyMatchResult(score: 1, matchedCharacterPositions: [])
        }
        guard !candidate.isEmpty else { return nil }

        let qScalars = Array(query.lowercased().unicodeScalars)
        let cChars = Array(candidate)
        let cLowerScalars = cChars.map { String($0).lowercased().unicodeScalars.first ?? UnicodeScalar(0) }

        guard qScalars.count <= cChars.count else { return nil }

        var qIdx = 0
        var positions: [Int] = []
        positions.reserveCapacity(qScalars.count)
        var totalScore = 0
        var consecutiveStreak = 0
        var prevMatchIdx = -2

        for cIdx in 0..<cChars.count where qIdx < qScalars.count {
            if cLowerScalars[cIdx] == qScalars[qIdx] {
                positions.append(cIdx)
                var charScore = 12

                if cIdx == 0 {
                    charScore += 28
                }
                if cIdx == prevMatchIdx + 1 {
                    consecutiveStreak += 1
                    charScore += 18 + min(consecutiveStreak * 4, 24)
                } else {
                    consecutiveStreak = 0
                }

                if cIdx > 0 {
                    let prevChar = cChars[cIdx - 1]
                    let currChar = cChars[cIdx]
                    if prevChar == "_" || prevChar == "-" || prevChar == ":" || prevChar == "." || prevChar == "[" || prevChar == " " || prevChar == "/" {
                        charScore += 22
                    } else if prevChar.isLowercase && currChar.isUppercase {
                        charScore += 18
                    }
                }

                totalScore += charScore
                prevMatchIdx = cIdx
                qIdx += 1
            }
        }

        guard qIdx == qScalars.count else { return nil }

        // Prefer tighter, shorter candidates when scores are close
        let compactnessBonus = max(0, 32 - (cChars.count - qScalars.count))
        return FuzzyMatchResult(
            score: totalScore + compactnessBonus,
            matchedCharacterPositions: positions
        )
    }

    public static func highlightedAttributedString(
        text: String,
        matchedPositions: [Int],
        baseColor: Color = ColdTungstenPalette.steelWhite,
        highlightColor: Color = ColdTungstenPalette.tungstenSapphire
    ) -> AttributedString {
        guard !matchedPositions.isEmpty else {
            var plain = AttributedString(text)
            plain.foregroundColor = baseColor
            return plain
        }
        let posSet = Set(matchedPositions)
        var out = AttributedString()
        for (idx, ch) in text.enumerated() {
            var part = AttributedString(String(ch))
            part.foregroundColor = posSet.contains(idx) ? highlightColor : baseColor
            out.append(part)
        }
        return out
    }
}

// MARK: - `⌘K` Command & Symbol Palette Models

public enum MachPaletteEntryKind: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case command = "Command"
    case function = "Function"
    case symbol = "Symbol"
    case stringLiteral = "String"
    case objcOrSwift = "ObjC / Swift"
    case bookmark = "Bookmark"
    case finding = "Finding"

    public var id: String { rawValue }

    public var sfSymbol: String {
        switch self {
        case .command: return "terminal"
        case .function: return "function"
        case .symbol: return "tag"
        case .stringLiteral: return "text.quote"
        case .objcOrSwift: return "cube.box"
        case .bookmark: return "bookmark.fill"
        case .finding: return "exclamationmark.shield"
        }
    }

    public var accentColor: Color {
        switch self {
        case .command: return ColdTungstenPalette.tungstenSapphire
        case .function: return ColdTungstenPalette.signalEmerald
        case .symbol: return ColdTungstenPalette.coolPewter
        case .stringLiteral: return ColdTungstenPalette.warmCopper
        case .objcOrSwift: return ColdTungstenPalette.tungstenAmber
        case .bookmark: return ColdTungstenPalette.tungstenSapphire
        case .finding: return ColdTungstenPalette.anodizedCrimson
        }
    }
}

public enum MachWorkbenchActionID: String, Sendable, Codable, Hashable, CaseIterable {
    case openCFGGraph = "pane.cfg"
    case openLinearDisassembly = "pane.disassembly"
    case openPseudoCDecompiler = "pane.pseudoc"
    case openHexPatcher = "pane.hex"
    case openStringsAndRuntime = "pane.strings"
    case openEntropyAndCodeSign = "pane.entropy"
    case openPluginAudit = "pane.plugins"
    case toggleSideBySideSplit = "view.split.cfg_pseudoc"
    case openGoToAddress = "nav.goto_address"
    case openXrefsAtCursor = "nav.xrefs_at_cursor"
    case runSecurityAuditPlugins = "audit.run_all_plugins"
    case createAnalysisSnapshot = "project.create_snapshot"
    case resignMachOAdHoc = "patch.resign_adhoc"
    case undoLastMutation = "edit.undo"
    case redoLastMutation = "edit.redo"
    case toggleBookmarkAtCursor = "edit.toggle_bookmark"
    case openPreferences = "app.preferences"
    case openShortcutsSheet = "app.shortcuts"
}

public struct MachPaletteEntry: Sendable, Hashable, Identifiable {
    public let id: String
    public let kind: MachPaletteEntryKind
    public let title: String
    public let subtitle: String
    public let address: VirtualAddress?
    public let targetPane: WorkbenchPaneTab?
    public let actionID: MachWorkbenchActionID?
    public let shortcutDisplay: String?

    public init(
        id: String,
        kind: MachPaletteEntryKind,
        title: String,
        subtitle: String,
        address: VirtualAddress? = nil,
        targetPane: WorkbenchPaneTab? = nil,
        actionID: MachWorkbenchActionID? = nil,
        shortcutDisplay: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.subtitle = subtitle
        self.address = address
        self.targetPane = targetPane
        self.actionID = actionID
        self.shortcutDisplay = shortcutDisplay
    }
}

public struct ScoredMachPaletteEntry: Sendable, Hashable, Identifiable {
    public var id: String { entry.id }
    public let entry: MachPaletteEntry
    public let score: Int
    public let matchedTitlePositions: [Int]

    public init(entry: MachPaletteEntry, score: Int, matchedTitlePositions: [Int] = []) {
        self.entry = entry
        self.score = score
        self.matchedTitlePositions = matchedTitlePositions
    }
}

@MainActor
public final class MachCommandPaletteController: ObservableObject {
    @Published public var isPresented: Bool = false
    @Published public var query: String = "" {
        didSet { recomputeFilteredResults() }
    }
    @Published public var kindFilter: MachPaletteEntryKind? = nil {
        didSet { recomputeFilteredResults() }
    }
    @Published public var selectedIndex: Int = 0
    @Published public private(set) var filteredResults: [ScoredMachPaletteEntry] = []

    private var allEntries: [MachPaletteEntry] = MachCommandPaletteController.builtInCommandEntries()
    public let maxVisibleResults: Int

    public init(maxVisibleResults: Int = 80) {
        self.maxVisibleResults = max(16, maxVisibleResults)
        recomputeFilteredResults()
    }

    public func openPalette(initialQuery: String = "", filter: MachPaletteEntryKind? = nil) {
        self.kindFilter = filter
        self.query = initialQuery
        self.selectedIndex = 0
        self.isPresented = true
        recomputeFilteredResults()
    }

    public func closePalette() {
        self.isPresented = false
    }

    public func rebuildCatalog(
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        renames: [UserSymbolRename] = [],
        bookmarks: [UserBookmark] = [],
        findings: [SecurityAuditFinding] = []
    ) {
        var renameByAddr: [VirtualAddress: String] = [:]
        for r in renames {
            renameByAddr[r.address] = r.customName
        }

        var entries: [MachPaletteEntry] = Self.builtInCommandEntries()
        entries.reserveCapacity(
            entries.count + functions.count + (image?.symbols.count ?? 0) + bookmarks.count + findings.count
        )

        for fn in functions {
            let name = renameByAddr[fn.address] ?? fn.demangledName
            let pacNote = fn.usesPAC ? " · PAC" : ""
            entries.append(MachPaletteEntry(
                id: "fn:\(fn.address.hexString)",
                kind: .function,
                title: name,
                subtitle: "\(fn.address.compactHexString) · \(fn.blocks.count) BBs · CC \(fn.cyclomaticComplexity)\(pacNote)",
                address: fn.address,
                targetPane: .cfgGraph
            ))
        }

        if let image {
            for sym in image.symbols.prefix(2_500) where sym.address.rawValue != 0 {
                let display = renameByAddr[sym.address] ?? sym.demangledName
                entries.append(MachPaletteEntry(
                    id: "sym:\(sym.id)",
                    kind: .symbol,
                    title: display,
                    subtitle: "\(sym.address.compactHexString) · \(sym.kind.rawValue) (\(sym.binding.rawValue))",
                    address: sym.address
                ))
            }

            for cls in image.objcClasses {
                entries.append(MachPaletteEntry(
                    id: "objc:\(cls.id)",
                    kind: .objcOrSwift,
                    title: "@interface \(cls.name)",
                    subtitle: "\(cls.address.compactHexString) · \(cls.methods.count) methods · \(cls.ivars.count) ivars",
                    address: cls.address,
                    targetPane: .stringsAndObjC
                ))
                for method in cls.methods {
                    let prefix = method.isClassMethod ? "+" : "-"
                    entries.append(MachPaletteEntry(
                        id: "objcm:\(cls.name):\(method.id)",
                        kind: .objcOrSwift,
                        title: "\(prefix)[\(cls.name) \(method.selector)]",
                        subtitle: "IMP \(method.implementationAddress.compactHexString) · \(method.typeEncoding)",
                        address: method.implementationAddress,
                        targetPane: .cfgGraph
                    ))
                }
            }

            for st in image.swiftTypes {
                entries.append(MachPaletteEntry(
                    id: "swift:\(st.id)",
                    kind: .objcOrSwift,
                    title: "\(st.kind.rawValue) \(st.demangledName)",
                    subtitle: "\(st.address.compactHexString) · \(st.fieldNames.count) fields",
                    address: st.address,
                    targetPane: .stringsAndObjC
                ))
            }

            for str in image.strings.prefix(1_500) {
                let cleanVal = str.value
                    .replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\r", with: "\\r")
                let clipped = cleanVal.count > 64 ? String(cleanVal.prefix(61)) + "..." : cleanVal
                entries.append(MachPaletteEntry(
                    id: "str:\(str.address.hexString)",
                    kind: .stringLiteral,
                    title: "\"\(clipped)\"",
                    subtitle: "\(str.address.compactHexString) · \(str.sectionName) (\(str.encoding.rawValue))",
                    address: str.address,
                    targetPane: .stringsAndObjC
                ))
            }
        }

        for bm in bookmarks {
            entries.append(MachPaletteEntry(
                id: "bm:\(bm.id.uuidString)",
                kind: .bookmark,
                title: bm.label,
                subtitle: "\(bm.address.compactHexString) · [\(bm.categoryTag)]",
                address: bm.address
            ))
        }

        for finding in findings {
            let loc = finding.address?.compactHexString ?? "Image-Level"
            entries.append(MachPaletteEntry(
                id: "finding:\(finding.id.uuidString)",
                kind: .finding,
                title: "[\(finding.severity.rawValue)] \(finding.title)",
                subtitle: "\(loc) · \(finding.pluginName)",
                address: finding.address,
                targetPane: .pluginFindings
            ))
        }

        self.allEntries = entries
        recomputeFilteredResults()
    }

    public func moveSelectionUp() {
        guard !filteredResults.isEmpty else { return }
        selectedIndex = max(0, selectedIndex - 1)
    }

    public func moveSelectionDown() {
        guard !filteredResults.isEmpty else { return }
        selectedIndex = min(filteredResults.count - 1, selectedIndex + 1)
    }

    public var currentlySelectedEntry: MachPaletteEntry? {
        guard filteredResults.indices.contains(selectedIndex) else { return nil }
        return filteredResults[selectedIndex].entry
    }

    private func recomputeFilteredResults() {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let pool: [MachPaletteEntry]
        if let kindFilter {
            pool = allEntries.filter { $0.kind == kindFilter }
        } else {
            pool = allEntries
        }

        if trimmed.isEmpty {
            let preview = pool.prefix(maxVisibleResults).enumerated().map { idx, entry in
                ScoredMachPaletteEntry(entry: entry, score: 1000 - idx, matchedTitlePositions: [])
            }
            filteredResults = preview
            selectedIndex = 0
            return
        }

        var scored: [ScoredMachPaletteEntry] = []
        scored.reserveCapacity(min(pool.count, 256))

        for entry in pool {
            if let titleHit = FuzzySubsequenceMatcher.match(query: trimmed, in: entry.title) {
                let kindBoost = (entry.kind == .command || entry.kind == .function) ? 14 : 0
                scored.append(ScoredMachPaletteEntry(
                    entry: entry,
                    score: titleHit.score + kindBoost,
                    matchedTitlePositions: titleHit.matchedCharacterPositions
                ))
            } else if let subHit = FuzzySubsequenceMatcher.match(query: trimmed, in: entry.subtitle) {
                scored.append(ScoredMachPaletteEntry(
                    entry: entry,
                    score: max(1, subHit.score - 12),
                    matchedTitlePositions: []
                ))
            }
        }

        scored.sort {
            if $0.score != $1.score { return $0.score > $1.score }
            return $0.entry.title < $1.entry.title
        }

        filteredResults = Array(scored.prefix(maxVisibleResults))
        selectedIndex = 0
    }

    public static func builtInCommandEntries() -> [MachPaletteEntry] {
        [
            MachPaletteEntry(
                id: "cmd:split_cfg_pseudoc",
                kind: .command,
                title: "Toggle Side-by-Side CFG Graph + Pseudo-C Decompiler",
                subtitle: "Split Inspection Bay",
                actionID: .toggleSideBySideSplit,
                shortcutDisplay: "⌥⌘S"
            ),
            MachPaletteEntry(
                id: "cmd:goto_addr",
                kind: .command,
                title: "Go to Virtual Address, File Offset, or Symbol...",
                subtitle: "Jump to hex VA, +offset, or symbol expression",
                actionID: .openGoToAddress,
                shortcutDisplay: "G"
            ),
            MachPaletteEntry(
                id: "cmd:xrefs_cursor",
                kind: .command,
                title: "Inspect Cross-References (Xrefs To / From) at Cursor",
                subtitle: "Open quick-jump Xref popover",
                actionID: .openXrefsAtCursor,
                shortcutDisplay: "X"
            ),
            MachPaletteEntry(
                id: "cmd:run_plugins",
                kind: .command,
                title: "Run JavaScriptCore Security Audit Plugins",
                subtitle: "Execute all enabled static reverse-engineering & security plugins",
                actionID: .runSecurityAuditPlugins,
                shortcutDisplay: "⇧⌘A"
            ),
            MachPaletteEntry(
                id: "cmd:pane_cfg",
                kind: .command,
                title: "Switch Pane: Control Flow Graph (Sugiyama Layered CFG)",
                subtitle: "Workbench Primary View",
                targetPane: .cfgGraph,
                actionID: .openCFGGraph,
                shortcutDisplay: "⌘1"
            ),
            MachPaletteEntry(
                id: "cmd:pane_disasm",
                kind: .command,
                title: "Switch Pane: Linear ARM64 Disassembly",
                subtitle: "Workbench Primary View",
                targetPane: .disassembly,
                actionID: .openLinearDisassembly,
                shortcutDisplay: "⌘2"
            ),
            MachPaletteEntry(
                id: "cmd:pane_pseudoc",
                kind: .command,
                title: "Switch Pane: Structured Pseudo-C Decompiler",
                subtitle: "Workbench Primary View",
                targetPane: .pseudoC,
                actionID: .openPseudoCDecompiler,
                shortcutDisplay: "⌘3"
            ),
            MachPaletteEntry(
                id: "cmd:pane_hex",
                kind: .command,
                title: "Switch Pane: Sparse CoW Hex & Inline ARM64 Patcher",
                subtitle: "Workbench Primary View",
                targetPane: .hexPatcher,
                actionID: .openHexPatcher,
                shortcutDisplay: "⌘4"
            ),
            MachPaletteEntry(
                id: "cmd:pane_strings",
                kind: .command,
                title: "Switch Pane: Strings, Objective-C & Swift Runtime Metadata",
                subtitle: "Workbench Primary View",
                targetPane: .stringsAndObjC,
                actionID: .openStringsAndRuntime,
                shortcutDisplay: "⌘5"
            ),
            MachPaletteEntry(
                id: "cmd:pane_entropy",
                kind: .command,
                title: "Switch Pane: Shannon Entropy & Mach-O Code Signature",
                subtitle: "Workbench Primary View",
                targetPane: .entropyAndSign,
                actionID: .openEntropyAndCodeSign,
                shortcutDisplay: "⌘6"
            ),
            MachPaletteEntry(
                id: "cmd:create_snapshot",
                kind: .command,
                title: "Capture Analysis Checkpoint Snapshot (.machproj)",
                subtitle: "Save atomic SQLite WAL snapshot of renames, comments, bookmarks & patches",
                actionID: .createAnalysisSnapshot,
                shortcutDisplay: "⇧⌘S"
            ),
            MachPaletteEntry(
                id: "cmd:resign_adhoc",
                kind: .command,
                title: "Re-Sign Patched Mach-O Binary (Ad-Hoc SHA-256 CodeDirectory)",
                subtitle: "Rebuild CS_SuperBlob page hashes over modified slices",
                actionID: .resignMachOAdHoc,
                shortcutDisplay: "⇧⌘R"
            ),
            MachPaletteEntry(
                id: "cmd:toggle_bookmark",
                kind: .command,
                title: "Toggle Analyst Bookmark at Current Cursor Address",
                subtitle: "Persist triage bookmark in .machproj",
                actionID: .toggleBookmarkAtCursor,
                shortcutDisplay: "B"
            ),
            MachPaletteEntry(
                id: "cmd:shortcuts",
                kind: .command,
                title: "Show Reverse-Engineering Keyboard Shortcuts Reference",
                subtitle: "View G, X, N, ;, B, Space, ⌘K cheatsheet",
                actionID: .openShortcutsSheet,
                shortcutDisplay: "?"
            ),
            MachPaletteEntry(
                id: "cmd:preferences",
                kind: .command,
                title: "Open Workbench Preferences & Ghidra / Plugin Settings",
                subtitle: "Configure ABI registers, CFG spacing, Ghidra path & JS sandboxes",
                actionID: .openPreferences,
                shortcutDisplay: "⌘,"
            )
        ]
    }
}

// MARK: - `⌘K` Command Palette Overlay View (Zero Open/Close Lag)

@MainActor
public struct MachCommandPaletteOverlayView: View {
    @ObservedObject public var controller: MachCommandPaletteController
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus
    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]
    public let onTriggerAction: (MachWorkbenchActionID) -> Void

    @FocusState private var isQueryFieldFocused: Bool

    public init(
        controller: MachCommandPaletteController,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage? = nil,
        functions: [RecoveredFunction] = [],
        onTriggerAction: @escaping (MachWorkbenchActionID) -> Void
    ) {
        self.controller = controller
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
        self.onTriggerAction = onTriggerAction
    }

    public var body: some View {
        ZStack(alignment: .top) {
            Color.black.opacity(0.52)
                .ignoresSafeArea()
                .onTapGesture {
                    controller.closePalette()
                }

            VStack(spacing: 0) {
                // Query Input Bar
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                    TextField("Search commands, functions, symbols, strings, ObjC selectors...", text: $controller.query)
                        .textFieldStyle(.plain)
                        .font(ColdTungstenTypography.disassemblyMono(size: 13.0))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .focused($isQueryFieldFocused)
                        .onSubmit {
                            commitSelection()
                        }

                    if !controller.query.isEmpty {
                        Button {
                            controller.query = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                        }
                        .buttonStyle(.plain)
                    }

                    TungstenKeycapBadge("ESC")
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                .background(ColdTungstenPalette.brushedSteel)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                // Scope Filter Strip
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        scopeFilterButton(label: "All", kind: nil)
                        ForEach(MachPaletteEntryKind.allCases) { kind in
                            scopeFilterButton(label: kind.rawValue, kind: kind)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                }
                .background(ColdTungstenPalette.chassisBackground)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                // Results List
                if controller.filteredResults.isEmpty {
                    VStack(spacing: 6) {
                        Text("No matching commands or binary entities")
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                        Text("Tip: Press G to evaluate hex address offsets such as +0x400 or _verify_license+0x14")
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 32)
                    .background(ColdTungstenPalette.gunmetalSlate)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(spacing: 0) {
                                ForEach(Array(controller.filteredResults.enumerated()), id: \.element.id) { idx, item in
                                    paletteRow(item: item, isSelected: idx == controller.selectedIndex)
                                        .id(item.id)
                                        .contentShape(Rectangle())
                                        .onTapGesture {
                                            controller.selectedIndex = idx
                                            commitSelection()
                                        }
                                }
                            }
                        }
                        .frame(maxHeight: 360)
                        .background(ColdTungstenPalette.gunmetalSlate)
                        .onChange(of: controller.selectedIndex) { _, newIdx in
                            if controller.filteredResults.indices.contains(newIdx) {
                                proxy.scrollTo(controller.filteredResults[newIdx].id, anchor: .center)
                            }
                        }
                    }
                }

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                // Footer Bar
                HStack(spacing: 14) {
                    HStack(spacing: 4) {
                        TungstenKeycapBadge("↑↓")
                        Text("Navigate")
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                    }
                    HStack(spacing: 4) {
                        TungstenKeycapBadge("↩")
                        Text("Execute / Jump")
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                    }
                    Spacer()
                    Text("\(controller.filteredResults.count) result(s)")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(ColdTungstenPalette.brushedSteel)
            }
            .frame(width: 680)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
            .padding(.top, 56)
        }
        .onAppear {
            isQueryFieldFocused = true
        }
    }

    private func scopeFilterButton(label: String, kind: MachPaletteEntryKind?) -> some View {
        let active = controller.kindFilter == kind
        return Button {
            controller.kindFilter = kind
        } label: {
            Text(label)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                .foregroundStyle(active ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(active ? ColdTungstenPalette.activeSelectionFill : ColdTungstenPalette.brushedSteel)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(
                            active ? ColdTungstenPalette.tungstenSapphire.opacity(0.75) : ColdTungstenPalette.tungstenSeam,
                            lineWidth: ColdTungstenMetrics.borderHairline
                        )
                )
                .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
                .fixedSize(horizontal: true, vertical: true)
        }
        .buttonStyle(.plain)
    }

    private func paletteRow(item: ScoredMachPaletteEntry, isSelected: Bool) -> some View {
        let entry = item.entry
        return HStack(spacing: 10) {
            Image(systemName: entry.kind.sfSymbol)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(entry.kind.accentColor)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                Text(
                    FuzzySubsequenceMatcher.highlightedAttributedString(
                        text: entry.title,
                        matchedPositions: item.matchedTitlePositions
                    )
                )
                .font(entry.kind == .command ? ColdTungstenTypography.controlLabel : ColdTungstenTypography.disassemblyMono(size: 12.0))

                Text(entry.subtitle)
                    .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
            }

            Spacer(minLength: 8)

            Text(entry.kind.rawValue.uppercased())
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                .foregroundStyle(entry.kind.accentColor)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(ColdTungstenPalette.chassisBackground)
                .clipShape(RoundedRectangle(cornerRadius: 3))
                .fixedSize(horizontal: true, vertical: true)

            if let shortcut = entry.shortcutDisplay {
                TungstenKeycapBadge(shortcut)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(isSelected ? ColdTungstenPalette.activeSelectionFill : Color.clear)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam.opacity(0.45))
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    private func commitSelection() {
        guard let selected = controller.currentlySelectedEntry else { return }
        controller.closePalette()
        if let actionID = selected.actionID {
            onTriggerAction(actionID)
        } else if let addr = selected.address {
            cursorBus.jump(
                toAddress: addr,
                in: image,
                functions: functions,
                switchToPane: selected.targetPane
            )
        }
    }
}

// MARK: - `G` Go-To-Address / Offset / Symbol Modal Overlay

@MainActor
public struct MachGoToAddressModalView: View {
    @Binding public var isPresented: Bool
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus
    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]
    public let cachedFunctions: [CachedFunctionSummary]
    public let customRenames: [UserSymbolRename]

    @State private var expressionText: String = ""
    @FocusState private var isInputFocused: Bool

    public init(
        isPresented: Binding<Bool>,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        cachedFunctions: [CachedFunctionSummary] = [],
        customRenames: [UserSymbolRename] = []
    ) {
        self._isPresented = isPresented
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
        self.cachedFunctions = cachedFunctions
        self.customRenames = customRenames
    }

    private var livePreview: Result<ResolvedGoToTarget, GoToParseFailure> {
        cursorBus.previewGoToQuery(
            expressionText,
            image: image,
            functions: functions,
            cachedFunctions: cachedFunctions,
            customRenames: customRenames
        )
    }

    public var body: some View {
        ZStack(alignment: .top) {
            Color.black.opacity(0.52)
                .ignoresSafeArea()
                .onTapGesture { isPresented = false }

            VStack(alignment: .leading, spacing: 0) {
                TungstenPanelHeaderBar(title: "Go to Address / Offset / Symbol", sfSymbol: "arrow.right.to.line") {
                    TungstenKeycapBadge("G")
                }

                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 8) {
                        Text("Target:")
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                            .fixedSize()

                        TextField("0x100001000, +0x400, off:0x1000, or _verify_license+0x14", text: $expressionText)
                            .textFieldStyle(.plain)
                            .font(ColdTungstenTypography.addressMono(size: 13.0))
                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(ColdTungstenPalette.chassisBackground)
                            .overlay(
                                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                                    .strokeBorder(ColdTungstenPalette.tungstenSapphire.opacity(0.7), lineWidth: ColdTungstenMetrics.borderHairline)
                            )
                            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
                            .focused($isInputFocused)
                            .onSubmit {
                                executeJumpIfValid()
                            }
                    }

                    // Live Resolution Preview Card
                    previewBox

                    // Quick Anchor Buttons
                    HStack(spacing: 8) {
                        Text("Anchors:")
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                            .fixedSize()

                        if let entry = image?.entryPoint {
                            Button("Entry (\(entry.compactHexString))") {
                                expressionText = entry.compactHexString
                                executeJumpIfValid()
                            }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, compact: true))
                        }

                        if let base = image?.imageBase {
                            Button("Image Base (\(base.compactHexString))") {
                                expressionText = base.compactHexString
                                executeJumpIfValid()
                            }
                            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        }

                        ForEach(cursorBus.recentJumpQueries.prefix(3), id: \.self) { recent in
                            Button(recent) {
                                expressionText = recent
                                executeJumpIfValid()
                            }
                            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        }

                        Spacer()
                    }
                }
                .padding(14)
                .background(ColdTungstenPalette.gunmetalSlate)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                HStack {
                    Text("Current cursor: \(cursorBus.currentLocation.virtualAddress.hexString)")
                        .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Spacer()
                    Button("Cancel") {
                        isPresented = false
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                    Button("Jump to Target") {
                        executeJumpIfValid()
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(ColdTungstenPalette.brushedSteel)
            }
            .frame(width: 580)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
            .padding(.top, 84)
        }
        .onAppear {
            expressionText = cursorBus.currentLocation.virtualAddress.compactHexString
            isInputFocused = true
        }
    }

    @ViewBuilder
    private var previewBox: some View {
        switch livePreview {
        case .success(let target):
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("RESOLVED VIRTUAL ADDRESS")
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(target.virtualAddress.hexString)
                        .font(ColdTungstenTypography.addressMono(size: 13.0, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("FILE OFFSET")
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(target.fileOffset?.hexString ?? "unmapped")
                        .font(ColdTungstenTypography.addressMono(size: 12.0))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("SYMBOL / SECTION")
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(
                        target.sectionSummary != nil
                            ? "\(target.displayLabel) (\(target.sectionSummary!))"
                            : target.displayLabel
                    )
                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                }

                Spacer()
            }
            .padding(10)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))

        case .failure(let err):
            HStack(spacing: 8) {
                Image(systemName: expressionText.isEmpty ? "info.circle" : "exclamationmark.triangle")
                    .foregroundStyle(expressionText.isEmpty ? ColdTungstenPalette.coolPewter : ColdTungstenPalette.tungstenAmber)
                Text(err.localizedDescription)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(expressionText.isEmpty ? ColdTungstenPalette.coolPewter : ColdTungstenPalette.tungstenAmber)
                Spacer()
            }
            .padding(10)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
        }
    }

    private func executeJumpIfValid() {
        let res = cursorBus.executeGoToQuery(
            expressionText,
            image: image,
            functions: functions,
            cachedFunctions: cachedFunctions,
            customRenames: customRenames
        )
        if case .success = res {
            isPresented = false
        }
    }
}

// MARK: - `X` Cross-Reference Quick-Jump Popover Model & View

public enum XrefPopoverDirectionFilter: String, Sendable, CaseIterable, Identifiable {
    case incomingTo = "Xrefs To Target"
    case outgoingFrom = "Xrefs From Target"
    case all = "All Xrefs"

    public var id: String { rawValue }
}

@MainActor
public final class MachXrefQuickJumpModel: ObservableObject {
    @Published public var isPresented: Bool = false
    @Published public private(set) var targetAddress: VirtualAddress = .zero
    @Published public private(set) var targetDisplayName: String = ""
    @Published public var directionFilter: XrefPopoverDirectionFilter = .incomingTo {
        didSet { selectedIndex = 0 }
    }
    @Published public var filterQuery: String = "" {
        didSet { selectedIndex = 0 }
    }
    @Published public var selectedIndex: Int = 0

    private var incomingRecords: [XrefRecord] = []
    private var outgoingRecords: [XrefRecord] = []
    private var functionNamesByEntry: [VirtualAddress: String] = [:]

    public init() {}

    public func present(
        for targetAddress: VirtualAddress,
        targetName: String,
        incoming: [XrefRecord],
        outgoing: [XrefRecord],
        functions: [RecoveredFunction] = [],
        renames: [UserSymbolRename] = []
    ) {
        self.targetAddress = targetAddress
        self.targetDisplayName = targetName.isEmpty ? targetAddress.compactHexString : targetName
        self.incomingRecords = incoming
        self.outgoingRecords = outgoing

        var fnMap: [VirtualAddress: String] = [:]
        for fn in functions {
            fnMap[fn.address] = fn.demangledName
        }
        for ren in renames {
            fnMap[ren.address] = ren.customName
        }
        self.functionNamesByEntry = fnMap
        self.directionFilter = incoming.isEmpty && !outgoing.isEmpty ? .outgoingFrom : .incomingTo
        self.filterQuery = ""
        self.selectedIndex = 0
        self.isPresented = true
    }

    public var visibleRecords: [XrefRecord] {
        let base: [XrefRecord]
        switch directionFilter {
        case .incomingTo:
            base = incomingRecords
        case .outgoingFrom:
            base = outgoingRecords
        case .all:
            base = incomingRecords + outgoingRecords
        }
        let trimmed = filterQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return base }
        return base.filter { rec in
            let caller = callerDisplay(for: rec).lowercased()
            return caller.contains(trimmed)
                || rec.fromAddress.compactHexString.lowercased().contains(trimmed)
                || rec.toAddress.compactHexString.lowercased().contains(trimmed)
                || rec.instructionPreview.lowercased().contains(trimmed)
                || rec.kind.rawValue.lowercased().contains(trimmed)
        }
    }

    public func callerDisplay(for xref: XrefRecord) -> String {
        if let fnAddr = xref.fromFunction, let fnName = functionNamesByEntry[fnAddr] {
            let delta = xref.fromAddress.rawValue >= fnAddr.rawValue
                ? (xref.fromAddress.rawValue - fnAddr.rawValue)
                : 0
            return delta == 0 ? fnName : "\(fnName) + 0x\(String(delta, radix: 16))"
        }
        return xref.fromAddress.compactHexString
    }

    public func jumpToRecord(
        _ xref: XrefRecord,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction]
    ) {
        let jumpAddr = (directionFilter == .outgoingFrom && xref.fromAddress == targetAddress)
            ? xref.toAddress
            : xref.fromAddress
        cursorBus.jump(toAddress: jumpAddr, in: image, functions: functions)
        isPresented = false
    }
}

@MainActor
public struct MachXrefQuickJumpPopoverView: View {
    @ObservedObject public var model: MachXrefQuickJumpModel
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus
    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]

    public init(
        model: MachXrefQuickJumpModel,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage? = nil,
        functions: [RecoveredFunction] = []
    ) {
        self.model = model
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
    }

    public var body: some View {
        let records = model.visibleRecords
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(
                title: "Cross-References — \(model.targetDisplayName)",
                sfSymbol: "arrow.triangle.branch",
                countBadge: records.count
            ) {
                TungstenKeycapBadge("X")
            }

            HStack(spacing: 8) {
                ForEach(XrefPopoverDirectionFilter.allCases) { mode in
                    Button(mode.rawValue) {
                        model.directionFilter = mode
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: model.directionFilter == mode ? .accentSapphire : .standard,
                        isActive: model.directionFilter == mode,
                        compact: true
                    ))
                }

                Spacer(minLength: 8)

                TextField("Filter caller or instruction...", text: $model.filterQuery)
                    .textFieldStyle(.plain)
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .frame(width: 210)
                    .background(ColdTungstenPalette.chassisBackground)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
            }
            .padding(9)
            .background(ColdTungstenPalette.chassisBackground)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            if records.isEmpty {
                Text("No cross-references recorded in this direction.")
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 28)
                    .background(ColdTungstenPalette.gunmetalSlate)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(records.enumerated()), id: \.element.id) { idx, xref in
                            let accent = ColdTungstenPalette.color(for: xref.kind)
                            HStack(spacing: 10) {
                                Text(xref.kind.rawValue)
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                                    .foregroundStyle(accent)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 2)
                                    .background(accent.opacity(0.14))
                                    .clipShape(RoundedRectangle(cornerRadius: 3))
                                    .fixedSize()

                                Text(xref.fromAddress.compactHexString)
                                    .font(ColdTungstenTypography.addressMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize()

                                Text(model.callerDisplay(for: xref))
                                    .font(ColdTungstenTypography.controlLabel)
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)

                                Spacer(minLength: 8)

                                Text(xref.instructionPreview)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .background(idx == model.selectedIndex ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                model.selectedIndex = idx
                                model.jumpToRecord(xref, cursorBus: cursorBus, image: image, functions: functions)
                            }
                        }
                    }
                }
                .frame(maxHeight: 280)
                .background(ColdTungstenPalette.gunmetalSlate)
            }
        }
        .frame(width: 620)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }
}
