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

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .command: return language.select("Command", "命令")
        case .function: return language.select("Function", "函数")
        case .symbol: return language.select("Symbol", "符号")
        case .stringLiteral: return language.select("String", "字符串")
        case .objcOrSwift: return language.select("ObjC / Swift", "ObjC / Swift")
        case .bookmark: return language.select("Bookmark", "书签")
        case .finding: return language.select("Finding", "审计发现")
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
    case toggleLanguage = "app.toggle_language"
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
        findings: [SecurityAuditFinding] = [],
        language: MachLanguage? = nil
    ) {
        let lang = language ?? MachLocalizer.shared.language
        var renameByAddr: [VirtualAddress: String] = [:]
        for r in renames {
            renameByAddr[r.address] = r.customName
        }

        var entries: [MachPaletteEntry] = Self.builtInCommandEntries(language: lang)
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
                subtitle: lang.select(
                    "\(fn.address.compactHexString) · \(fn.blocks.count) BBs · CC \(fn.cyclomaticComplexity)\(pacNote)",
                    "\(fn.address.compactHexString) · \(fn.blocks.count) 基本块 · 复杂度 \(fn.cyclomaticComplexity)\(pacNote)"
                ),
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
                    subtitle: lang.select(
                        "\(cls.address.compactHexString) · \(cls.methods.count) methods · \(cls.ivars.count) ivars",
                        "\(cls.address.compactHexString) · \(cls.methods.count) 方法 · \(cls.ivars.count) 实例变量"
                    ),
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
                    subtitle: lang.select(
                        "\(st.address.compactHexString) · \(st.fieldNames.count) fields",
                        "\(st.address.compactHexString) · \(st.fieldNames.count) 字段"
                    ),
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
            let loc = finding.address?.compactHexString ?? lang.select("Image-Level", "镜像级")
            entries.append(MachPaletteEntry(
                id: "finding:\(finding.id.uuidString)",
                kind: .finding,
                title: "[\(finding.severity.localizedBadge(in: lang))] \(finding.title)",
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

    public static func builtInCommandEntries(language: MachLanguage? = nil) -> [MachPaletteEntry] {
        let lang = language ?? MachLocalizer.shared.language
        return [
            MachPaletteEntry(
                id: "cmd:toggle_language",
                kind: .command,
                title: lang.select("Toggle Interface Language (中文 / EN)", "切换界面语言 (中文 / EN)"),
                subtitle: lang.select("Switch between Simplified Chinese and English instantaneously", "在简体中文与英文界面之间即时切换"),
                actionID: .toggleLanguage,
                shortcutDisplay: "⇧⌘L"
            ),
            MachPaletteEntry(
                id: "cmd:split_cfg_pseudoc",
                kind: .command,
                title: lang.select("Toggle Side-by-Side CFG Graph + Pseudo-C Decompiler", "切换并排分屏视图 (控制流图 + 伪C反编译)"),
                subtitle: lang.select("Split Inspection Bay", "同步分屏审查台"),
                actionID: .toggleSideBySideSplit,
                shortcutDisplay: "⌥⌘S"
            ),
            MachPaletteEntry(
                id: "cmd:goto_addr",
                kind: .command,
                title: lang.select("Go to Virtual Address, File Offset, or Symbol...", "跳转至虚拟地址、文件偏移或符号..."),
                subtitle: lang.select("Jump to hex VA, +offset, or symbol expression", "解析十六进制 VA、相对偏移 +offset 或符号表达式"),
                actionID: .openGoToAddress,
                shortcutDisplay: "G"
            ),
            MachPaletteEntry(
                id: "cmd:xrefs_cursor",
                kind: .command,
                title: lang.select("Inspect Cross-References (Xrefs To / From) at Cursor", "检查当前光标处的交叉引用 (引用至此 / 发出引用)"),
                subtitle: lang.select("Open quick-jump Xref popover", "打开交叉引用快速跳转浮窗"),
                actionID: .openXrefsAtCursor,
                shortcutDisplay: "X"
            ),
            MachPaletteEntry(
                id: "cmd:run_plugins",
                kind: .command,
                title: lang.select("Run JavaScriptCore Security Audit Plugins", "运行 JavaScriptCore 安全审计插件套件"),
                subtitle: lang.select("Execute all enabled static reverse-engineering & security plugins", "对当前二进制执行全部已启用的静态安全审计规则"),
                actionID: .runSecurityAuditPlugins,
                shortcutDisplay: "⇧⌘A"
            ),
            MachPaletteEntry(
                id: "cmd:pane_cfg",
                kind: .command,
                title: lang.select("Switch Pane: Control Flow Graph (Sugiyama Layered CFG)", "切换视图: 控制流图 (Sugiyama 分层控制流图)"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .cfgGraph,
                actionID: .openCFGGraph,
                shortcutDisplay: "⌘1"
            ),
            MachPaletteEntry(
                id: "cmd:pane_disasm",
                kind: .command,
                title: lang.select("Switch Pane: Linear ARM64 Disassembly", "切换视图: 线性 ARM64 反汇编"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .disassembly,
                actionID: .openLinearDisassembly,
                shortcutDisplay: "⌘2"
            ),
            MachPaletteEntry(
                id: "cmd:pane_pseudoc",
                kind: .command,
                title: lang.select("Switch Pane: Structured Pseudo-C Decompiler", "切换视图: SSA 结构化伪C反编译"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .pseudoC,
                actionID: .openPseudoCDecompiler,
                shortcutDisplay: "⌘3"
            ),
            MachPaletteEntry(
                id: "cmd:pane_hex",
                kind: .command,
                title: lang.select("Switch Pane: Sparse CoW Hex & Inline ARM64 Patcher", "切换视图: 稀疏CoW十六进制与内联ARM64补丁"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .hexPatcher,
                actionID: .openHexPatcher,
                shortcutDisplay: "⌘4"
            ),
            MachPaletteEntry(
                id: "cmd:pane_strings",
                kind: .command,
                title: lang.select("Switch Pane: Strings, Objective-C & Swift Runtime Metadata", "切换视图: 字符串、ObjC 与 Swift 运行时元数据"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .stringsAndObjC,
                actionID: .openStringsAndRuntime,
                shortcutDisplay: "⌘5"
            ),
            MachPaletteEntry(
                id: "cmd:pane_entropy",
                kind: .command,
                title: lang.select("Switch Pane: Shannon Entropy & Mach-O Code Signature", "切换视图: 香农熵谱与 Mach-O 代码签名"),
                subtitle: lang.select("Workbench Primary View", "工作台主视图"),
                targetPane: .entropyAndSign,
                actionID: .openEntropyAndCodeSign,
                shortcutDisplay: "⌘6"
            ),
            MachPaletteEntry(
                id: "cmd:create_snapshot",
                kind: .command,
                title: lang.select("Capture Analysis Checkpoint Snapshot (.machproj)", "创建分析检查点快照 (.machproj)"),
                subtitle: lang.select("Save atomic SQLite WAL snapshot of renames, comments, bookmarks & patches", "保存包含重命名、注释、书签与补丁的 SQLite WAL 原子快照"),
                actionID: .createAnalysisSnapshot,
                shortcutDisplay: "⇧⌘S"
            ),
            MachPaletteEntry(
                id: "cmd:resign_adhoc",
                kind: .command,
                title: lang.select("Re-Sign Patched Mach-O Binary (Ad-Hoc SHA-256 CodeDirectory)", "重签名补丁后 Mach-O 二进制 (临时 SHA-256 CodeDirectory)"),
                subtitle: lang.select("Rebuild CS_SuperBlob page hashes over modified slices", "重新计算已修改切片上的 CS_SuperBlob 4KB 页哈希"),
                actionID: .resignMachOAdHoc,
                shortcutDisplay: "⇧⌘R"
            ),
            MachPaletteEntry(
                id: "cmd:toggle_bookmark",
                kind: .command,
                title: lang.select("Toggle Analyst Bookmark at Current Cursor Address", "在当前光标地址处切换分析书签"),
                subtitle: lang.select("Persist triage bookmark in .machproj", "将书签持久化写入 .machproj 数据库"),
                actionID: .toggleBookmarkAtCursor,
                shortcutDisplay: "B"
            ),
            MachPaletteEntry(
                id: "cmd:shortcuts",
                kind: .command,
                title: lang.select("Show Reverse-Engineering Keyboard Shortcuts Reference", "显示逆向分析键盘快捷键速查表"),
                subtitle: lang.select("View G, X, N, ;, B, Space, ⌘K, ⇧⌘L cheatsheet", "查看 G、X、N、;、B、Space、⌘K、⇧⌘L 快捷键指南"),
                actionID: .openShortcutsSheet,
                shortcutDisplay: "?"
            ),
            MachPaletteEntry(
                id: "cmd:preferences",
                kind: .command,
                title: lang.select("Open Workbench Preferences & Ghidra / Plugin Settings", "打开工作台偏好设置与语言 / Ghidra / 插件配置"),
                subtitle: lang.select("Configure language, ABI registers, CFG spacing, Ghidra path & JS sandboxes", "配置界面语言、ARM64 ABI 寄存器、CFG 间距、Ghidra 路径与 JS 沙箱"),
                actionID: .openPreferences,
                shortcutDisplay: "⌘,"
            )
        ]
    }
}

// MARK: - `⌘K` Command Palette Overlay View (Zero Open/Close Lag)

@MainActor
public struct MachCommandPaletteOverlayView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
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

                    TextField(
                        localizer.L(
                            "Search commands, functions, symbols, strings, ObjC selectors...",
                            "搜索命令、函数、符号、字符串、ObjC 选择器..."
                        ),
                        text: $controller.query
                    )
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
                        scopeFilterButton(label: localizer.L("All", "全部"), kind: nil)
                        ForEach(MachPaletteEntryKind.allCases) { kind in
                            scopeFilterButton(label: kind.localizedTitle(in: localizer.language), kind: kind)
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
                        Text(localizer.L("No matching commands or binary entities", "未找到匹配的命令或二进制实体"))
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                        Text(
                            localizer.L(
                                "Tip: Press G to evaluate hex address offsets such as +0x400 or _verify_license+0x14",
                                "提示: 按 G 键可直接计算十六进制地址偏移 (例如 +0x400 或 _verify_license+0x14)"
                            )
                        )
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
                        Text(localizer.L("Navigate", "上下导航"))
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                    }
                    HStack(spacing: 4) {
                        TungstenKeycapBadge("↩")
                        Text(localizer.L("Execute / Jump", "执行 / 跳转"))
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                    }
                    Spacer()
                    Text(
                        localizer.L(
                            "\(controller.filteredResults.count) result(s)",
                            "共 \(controller.filteredResults.count) 条结果"
                        )
                    )
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

            Text(entry.kind.localizedTitle(in: localizer.language).uppercased())
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
    @ObservedObject private var localizer: MachLocalizer = .shared
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
                TungstenPanelHeaderBar(
                    title: localizer.L("Go to Address / Offset / Symbol", "跳转至地址 / 偏移 / 符号"),
                    sfSymbol: "arrow.right.to.line"
                ) {
                    TungstenKeycapBadge("G")
                }

                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 8) {
                        Text(localizer.L("Target:", "目标:"))
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                            .fixedSize()

                        TextField(
                            localizer.L(
                                "0x100001000, +0x400, off:0x1000, or _verify_license+0x14",
                                "0x100001000、+0x400、off:0x1000 或 _verify_license+0x14"
                            ),
                            text: $expressionText
                        )
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
                        Text(localizer.L("Anchors:", "锚点:"))
                            .font(ColdTungstenTypography.secondaryCaption)
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                            .fixedSize()

                        if let entry = image?.entryPoint {
                            Button(localizer.L("Entry (\(entry.compactHexString))", "入口 (\(entry.compactHexString))")) {
                                expressionText = entry.compactHexString
                                executeJumpIfValid()
                            }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, compact: true))
                        }

                        if let base = image?.imageBase {
                            Button(localizer.L("Image Base (\(base.compactHexString))", "镜像基址 (\(base.compactHexString))")) {
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
                    Text(
                        localizer.L(
                            "Current cursor: \(cursorBus.currentLocation.virtualAddress.hexString)",
                            "当前光标: \(cursorBus.currentLocation.virtualAddress.hexString)"
                        )
                    )
                        .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Spacer()
                    Button(localizer.L("Cancel", "取消")) {
                        isPresented = false
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                    Button(localizer.L("Jump to Target", "跳转至目标")) {
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
                    Text(localizer.L("RESOLVED VIRTUAL ADDRESS", "解析虚拟地址"))
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(target.virtualAddress.hexString)
                        .font(ColdTungstenTypography.addressMono(size: 13.0, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text(localizer.L("FILE OFFSET", "文件偏移"))
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(target.fileOffset?.hexString ?? localizer.L("unmapped", "未映射"))
                        .font(ColdTungstenTypography.addressMono(size: 12.0))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text(localizer.L("SYMBOL / SECTION", "符号 / 节区"))
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
                Text(err.localizedDescription(in: localizer.language))
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

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .incomingTo:
            return language.select("Xrefs To Target", "引用至此目标")
        case .outgoingFrom:
            return language.select("Xrefs From Target", "此目标发出引用")
        case .all:
            return language.select("All Xrefs", "全部引用")
        }
    }
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
    @ObservedObject private var localizer: MachLocalizer = .shared
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
                title: localizer.L("Cross-References: \(model.targetDisplayName)", "交叉引用: \(model.targetDisplayName)"),
                sfSymbol: "arrow.triangle.branch",
                countBadge: records.count
            ) {
                TungstenKeycapBadge("X")
            }

            HStack(spacing: 8) {
                ForEach(XrefPopoverDirectionFilter.allCases) { mode in
                    Button(mode.localizedTitle(in: localizer.language)) {
                        model.directionFilter = mode
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: model.directionFilter == mode ? .accentSapphire : .standard,
                        isActive: model.directionFilter == mode,
                        compact: true
                    ))
                }

                Spacer(minLength: 8)

                TextField(localizer.L("Filter caller or instruction...", "筛选调用方或指令..."), text: $model.filterQuery)
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
                Text(localizer.L("No cross-references recorded in this direction.", "当前方向暂无交叉引用记录。"))
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
                                Text(xref.kind.localizedBadge(in: localizer.language))
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
