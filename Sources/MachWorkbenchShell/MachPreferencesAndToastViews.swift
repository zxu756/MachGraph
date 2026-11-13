import Foundation
import SwiftUI
import MachGraphModels
import MachPluginSDK

// MARK: - Multi-Tab `⌘,` Preferences Models & Store

public enum MachPreferencesTab: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case disassemblyAndABI = "Disassembly & ABI"
    case cfgLayoutAndEdges = "CFG Layout & Edges"
    case decompilerAndGhidra = "Decompiler & Ghidra Path"
    case securityJSPlugins = "Security JS Plugins"

    public var id: String { rawValue }

    public var sfSymbolName: String {
        switch self {
        case .disassemblyAndABI: return "cpu"
        case .cfgLayoutAndEdges: return "point.3.connected.trianglepath.dotted"
        case .decompilerAndGhidra: return "curlybraces.square"
        case .securityJSPlugins: return "checkmark.shield"
        }
    }

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .disassemblyAndABI:
            return language.select("Disassembly & ABI", "反汇编与ABI")
        case .cfgLayoutAndEdges:
            return language.select("CFG Layout & Edges", "控制流图与边路由")
        case .decompilerAndGhidra:
            return language.select("Decompiler & Ghidra Path", "反编译器与Ghidra")
        case .securityJSPlugins:
            return language.select("Security JS Plugins", "JS安全插件")
        }
    }
}

public struct MachWorkbenchPreferences: Sendable, Codable, Hashable {
    // 1. Disassembly & ABI
    public var useABIRegisterNames: Bool
    public var showRawInstructionBytes: Bool
    public var showAutoComments: Bool
    public var demangleSwiftAndCppSymbols: Bool
    public var uppercaseHexDigits: Bool
    public var disassemblyFontSize: Double

    // 2. CFG Layout & Edges
    public var cfgVerticalLayerSpacing: Double
    public var cfgHorizontalNodeSpacing: Double
    public var highlightLoopBackEdges: Bool
    public var showDominatorDepthBadges: Bool
    public var showCFGOverviewMinimap: Bool
    public var orthogonalSugiyamaRouting: Bool

    // 3. Decompiler & Ghidra Path
    public var enableDeadStoreElimination: Bool
    public var preferStructuredWhileAndSwitch: Bool
    public var emitExplicitTypeCasts: Bool
    public var ghidraInstallPath: String
    public var javaHomePath: String
    public var enableSideBySideGhidraDiff: Bool

    // 4. Security JS Plugins
    public var pluginTimeoutMilliseconds: Double
    public var enforcePluginCapabilityGates: Bool
    public var disabledPluginIDs: Set<String>

    public init(
        useABIRegisterNames: Bool = true,
        showRawInstructionBytes: Bool = true,
        showAutoComments: Bool = true,
        demangleSwiftAndCppSymbols: Bool = true,
        uppercaseHexDigits: Bool = false,
        disassemblyFontSize: Double = 12.5,
        cfgVerticalLayerSpacing: Double = 54.0,
        cfgHorizontalNodeSpacing: Double = 36.0,
        highlightLoopBackEdges: Bool = true,
        showDominatorDepthBadges: Bool = true,
        showCFGOverviewMinimap: Bool = true,
        orthogonalSugiyamaRouting: Bool = true,
        enableDeadStoreElimination: Bool = true,
        preferStructuredWhileAndSwitch: Bool = true,
        emitExplicitTypeCasts: Bool = true,
        ghidraInstallPath: String = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications/ghidra_12.1.4_PUBLIC")
            .path,
        javaHomePath: String = "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
        enableSideBySideGhidraDiff: Bool = false,
        pluginTimeoutMilliseconds: Double = 5_000.0,
        enforcePluginCapabilityGates: Bool = true,
        disabledPluginIDs: Set<String> = []
    ) {
        self.useABIRegisterNames = useABIRegisterNames
        self.showRawInstructionBytes = showRawInstructionBytes
        self.showAutoComments = showAutoComments
        self.demangleSwiftAndCppSymbols = demangleSwiftAndCppSymbols
        self.uppercaseHexDigits = uppercaseHexDigits
        self.disassemblyFontSize = min(18.0, max(10.5, disassemblyFontSize))
        self.cfgVerticalLayerSpacing = min(120.0, max(24.0, cfgVerticalLayerSpacing))
        self.cfgHorizontalNodeSpacing = min(96.0, max(16.0, cfgHorizontalNodeSpacing))
        self.highlightLoopBackEdges = highlightLoopBackEdges
        self.showDominatorDepthBadges = showDominatorDepthBadges
        self.showCFGOverviewMinimap = showCFGOverviewMinimap
        self.orthogonalSugiyamaRouting = orthogonalSugiyamaRouting
        self.enableDeadStoreElimination = enableDeadStoreElimination
        self.preferStructuredWhileAndSwitch = preferStructuredWhileAndSwitch
        self.emitExplicitTypeCasts = emitExplicitTypeCasts
        self.ghidraInstallPath = ghidraInstallPath
        self.javaHomePath = javaHomePath
        self.enableSideBySideGhidraDiff = enableSideBySideGhidraDiff
        self.pluginTimeoutMilliseconds = min(30_000.0, max(250.0, pluginTimeoutMilliseconds))
        self.enforcePluginCapabilityGates = enforcePluginCapabilityGates
        self.disabledPluginIDs = disabledPluginIDs
    }

    public static let standard = MachWorkbenchPreferences()
}

@MainActor
public final class MachWorkbenchPreferencesStore: ObservableObject {
    @Published public var selectedTab: MachPreferencesTab = .disassemblyAndABI
    @Published public var preferences: MachWorkbenchPreferences {
        didSet { persistPreferences() }
    }
    @Published public private(set) var customPlugins: [MachPluginManifest] = []

    private let defaultsKey: String
    private let userDefaults: UserDefaults

    public init(
        userDefaults: UserDefaults = .standard,
        defaultsKey: String = "com.machgraph.workbench.preferences.v1"
    ) {
        self.userDefaults = userDefaults
        self.defaultsKey = defaultsKey
        if let rawData = userDefaults.data(forKey: defaultsKey),
           let decoded = try? JSONDecoder().decode(MachWorkbenchPreferences.self, from: rawData) {
            self.preferences = decoded
        } else {
            self.preferences = .standard
        }
    }

    public var effectivePlugins: [MachPluginManifest] {
        let base = BuiltInMachPluginCatalog.allPlugins + customPlugins
        return base.map { manifest in
            var copy = manifest
            copy.isEnabled = !preferences.disabledPluginIDs.contains(manifest.id)
            return copy
        }
    }

    public func isPluginEnabled(_ pluginID: String) -> Bool {
        !preferences.disabledPluginIDs.contains(pluginID)
    }

    public func setPluginEnabled(_ pluginID: String, isEnabled: Bool) {
        if isEnabled {
            preferences.disabledPluginIDs.remove(pluginID)
        } else {
            preferences.disabledPluginIDs.insert(pluginID)
        }
    }

    public func registerCustomPlugin(_ manifest: MachPluginManifest) {
        if let idx = customPlugins.firstIndex(where: { $0.id == manifest.id }) {
            customPlugins[idx] = manifest
        } else {
            customPlugins.append(manifest)
        }
    }

    public func removeCustomPlugin(id: String) {
        customPlugins.removeAll { $0.id == id }
        preferences.disabledPluginIDs.remove(id)
    }

    public func makePluginRunner() -> MachPluginRunner {
        let config = MachPluginSandboxConfiguration(
            executionTimeoutMilliseconds: preferences.pluginTimeoutMilliseconds,
            enforceCapabilityGates: preferences.enforcePluginCapabilityGates
        )
        let sandbox = MachJavaScriptPluginSandbox(configuration: config)
        let builtIns = BuiltInMachPluginCatalog.allPlugins.map { plugin -> MachPluginManifest in
            var copy = plugin
            copy.isEnabled = !preferences.disabledPluginIDs.contains(plugin.id)
            return copy
        }
        let customs = customPlugins.map { plugin -> MachPluginManifest in
            var copy = plugin
            copy.isEnabled = !preferences.disabledPluginIDs.contains(plugin.id)
            return copy
        }
        return MachPluginRunner(
            sandbox: sandbox,
            builtInPlugins: builtIns,
            customPlugins: customs
        )
    }

    public var isGhidraInstallationDetected: Bool {
        let headPath = (preferences.ghidraInstallPath as NSString).appendingPathComponent("support/analyzeHeadless")
        return FileManager.default.fileExists(atPath: headPath)
            || FileManager.default.fileExists(atPath: preferences.ghidraInstallPath)
    }

    public func resetToDefaults() {
        preferences = .standard
    }

    private func persistPreferences() {
        if let encoded = try? JSONEncoder().encode(preferences) {
            userDefaults.set(encoded, forKey: defaultsKey)
        }
    }
}

// MARK: - Multi-Tab `⌘,` Preferences Window View

@MainActor
public struct MachPreferencesWindowView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    @ObservedObject public var store: MachWorkbenchPreferencesStore
    public let onClose: (() -> Void)?

    public init(
        store: MachWorkbenchPreferencesStore,
        onClose: (() -> Void)? = nil
    ) {
        self.store = store
        self.onClose = onClose
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("MachGraph Workbench Preferences", "MachGraph 工作台偏好设置"),
                sfSymbol: "slider.horizontal.3"
            ) {
                HStack(spacing: 8) {
                    TungstenKeycapBadge("⌘,")
                    if let onClose {
                        Button(localizer.L("Done", "完成")) { onClose() }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                    }
                }
            }

            // Live Bilingual Language Picker Bar (`中文 | EN`)
            HStack(spacing: 12) {
                Image(systemName: "globe")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                VStack(alignment: .leading, spacing: 1) {
                    Text(localizer.L("Interface Language / 界面语言", "界面语言 / Interface Language"))
                        .font(ColdTungstenTypography.controlLabel)
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                    Text(
                        localizer.L(
                            "Live switch across all views, menus, palettes, and shortcuts (persisted in UserDefaults).",
                            "即时切换工作台全部视图、菜单栏、命令面板与快捷键说明 (自动保存至 UserDefaults)。"
                        )
                    )
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                }

                Spacer()

                TungstenKeycapBadge("⇧⌘L")
                TungstenLanguageTogglePill(localizer: localizer, compact: false)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(ColdTungstenPalette.gunmetalSlate)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            // 4-Tab Bar
            HStack(spacing: 6) {
                ForEach(MachPreferencesTab.allCases) { tab in
                    let active = store.selectedTab == tab
                    Button {
                        store.selectedTab = tab
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: tab.sfSymbolName)
                                .font(.system(size: 11.5, weight: .semibold))
                            Text(tab.localizedTitle(in: localizer.language))
                                .font(ColdTungstenTypography.controlLabel)
                        }
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: active ? .accentSapphire : .standard,
                        isActive: active,
                        compact: false
                    ))
                }
                Spacer()
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(ColdTungstenPalette.chassisBackground)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    switch store.selectedTab {
                    case .disassemblyAndABI:
                        disassemblyTabContent
                    case .cfgLayoutAndEdges:
                        cfgLayoutTabContent
                    case .decompilerAndGhidra:
                        decompilerAndGhidraTabContent
                    case .securityJSPlugins:
                        securityPluginsTabContent
                    }
                }
                .padding(16)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(ColdTungstenPalette.gunmetalSlate)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            HStack {
                Text(
                    localizer.L(
                        "Cold Tungsten Steel Engineering Profile · SQLite WAL Synced",
                        "冷钨钢工程主题配置 · SQLite WAL 实时同步"
                    )
                )
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                Spacer()
                Button(localizer.L("Restore Defaults", "恢复默认")) {
                    store.resetToDefaults()
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(ColdTungstenPalette.brushedSteel)
        }
        .frame(width: 720, height: 520)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var disassemblyTabContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            preferenceToggleRow(
                title: localizer.L(
                    "Display Apple ARM64 ABI Register Aliases (fp, lr, sp, xzr)",
                    "显示 Apple ARM64 ABI 寄存器别名 (fp, lr, sp, xzr)"
                ),
                subtitle: localizer.L(
                    "Maps x29 -> fp and x30 -> lr across linear disassembly and CFG basic-block nodes",
                    "在线性反汇编与控制流图基本块节点中将 x29 映射为 fp、x30 映射为 lr"
                ),
                isOn: $store.preferences.useABIRegisterNames
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Show Raw 32-Bit Little-Endian Instruction Bytes Column",
                    "显示 32 位小端原始机器码字节列"
                ),
                subtitle: localizer.L(
                    "Renders hex opcode bytes alongside virtual addresses for rapid patch verification",
                    "在虚拟地址旁渲染十六进制机器码，便于快速核对指令补丁"
                ),
                isOn: $store.preferences.showRawInstructionBytes
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Synthesize Inline ADRP+ADD / Chained Fixup / Literal Comments",
                    "自动合成内联 ADRP+ADD / 链式修复 / 字符串字面量注释"
                ),
                subtitle: localizer.L(
                    "Annotates PC-relative string, selector, and PAC diversity targets automatically",
                    "自动标注 PC 相对字符串、ObjC 选择器与 PAC 多样性修饰符目标"
                ),
                isOn: $store.preferences.showAutoComments
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Demangle Swift ($s...) and Itanium C++ (_Z...) Symbol Names",
                    "反修饰 Swift ($s...) 与 Itanium C++ (_Z...) 符号名称"
                ),
                subtitle: localizer.L(
                    "Applies symbol demangling in Navigator, CFG headers, and Xref quick-jump tables",
                    "在二进制导航、控制流图标题与交叉引用跳转表中自动反修饰符号"
                ),
                isOn: $store.preferences.demangleSwiftAndCppSymbols
            )
            preferenceSliderRow(
                title: localizer.L("Monospaced Disassembly Font Size", "等宽反汇编字号"),
                valueText: String(format: "%.1f pt", store.preferences.disassemblyFontSize),
                value: $store.preferences.disassemblyFontSize,
                range: 10.5...17.0
            )
        }
    }

    private var cfgLayoutTabContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            preferenceToggleRow(
                title: localizer.L(
                    "Orthogonal Sugiyama Layered Edge Routing",
                    "Sugiyama 分层正交边路由"
                ),
                subtitle: localizer.L(
                    "Routes True (#3FB950), False (#F85149), and Unconditional (#D29922) edges along crisp right-angle channels",
                    "沿正交直角通道绘制真分支 (#3FB950)、假分支 (#F85149) 与无条件跳转边 (#D29922)"
                ),
                isOn: $store.preferences.orthogonalSugiyamaRouting
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Highlight Natural Loop Back-Edges in Tungsten Amber",
                    "以钨琥珀色高亮自然循环回边"
                ),
                subtitle: localizer.L(
                    "Emphasizes dominator-tree loop latches for rapid control-flow comprehension",
                    "突出显示支配树循环回边，加速循环控制流结构辨识"
                ),
                isOn: $store.preferences.highlightLoopBackEdges
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Show Dominator Tree Depth & Loop Header Badges on Basic Blocks",
                    "在基本块标题栏显示支配树深度与循环头徽标"
                ),
                subtitle: localizer.L(
                    "Displays structural dominance metadata inside each basic block header bar",
                    "在每个基本块顶部展示支配深度与循环嵌套元数据"
                ),
                isOn: $store.preferences.showDominatorDepthBadges
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Show Interactive Viewport Minimap Overlay",
                    "显示交互式缩略雷达视口浮层"
                ),
                subtitle: localizer.L(
                    "Renders live overview viewport frame in the corner of large CFGs",
                    "在大型控制流图角落渲染实时全局缩略雷达"
                ),
                isOn: $store.preferences.showCFGOverviewMinimap
            )
            preferenceSliderRow(
                title: localizer.L("Vertical Rank Layer Spacing", "分层垂直间距"),
                valueText: "\(Int(store.preferences.cfgVerticalLayerSpacing)) pt",
                value: $store.preferences.cfgVerticalLayerSpacing,
                range: 28.0...110.0
            )
            preferenceSliderRow(
                title: localizer.L("Horizontal Sibling Block Spacing", "同层基本块水平间距"),
                valueText: "\(Int(store.preferences.cfgHorizontalNodeSpacing)) pt",
                value: $store.preferences.cfgHorizontalNodeSpacing,
                range: 18.0...88.0
            )
        }
    }

    private var decompilerAndGhidraTabContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            preferenceToggleRow(
                title: localizer.L(
                    "Run Dead-Store & Flag Elimination Pass on Micro-IR",
                    "在微IR上执行死存储与条件标志消除优化"
                ),
                subtitle: localizer.L(
                    "Folds transient NZCV condition flags into structured C relational expressions",
                    "将瞬态 NZCV 条件标志折叠为结构化 C 关系表达式"
                ),
                isOn: $store.preferences.enableDeadStoreElimination
            )
            preferenceToggleRow(
                title: localizer.L(
                    "Recover Structured if / else, while Loops, and switch Tables",
                    "恢复结构化 if / else、while 循环与 switch 跳转表"
                ),
                subtitle: localizer.L(
                    "Collapses unstructured goto edges into indented C control-flow AST blocks",
                    "将非结构化跳转收敛为缩进清晰的 C 控制流语法树块"
                ),
                isOn: $store.preferences.preferStructuredWhileAndSwitch
            )
            preferencePathRow(
                title: localizer.L("Ghidra 12.1.4 Installation Directory", "Ghidra 12.1.4 安装目录"),
                path: $store.preferences.ghidraInstallPath,
                statusText: store.isGhidraInstallationDetected
                    ? localizer.L("Detected", "已检测")
                    : localizer.L("Not Found", "未找到"),
                statusColor: store.isGhidraInstallationDetected ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber
            )
            preferencePathRow(
                title: localizer.L("OpenJDK 21 JAVA_HOME Path", "OpenJDK 21 JAVA_HOME 路径"),
                path: $store.preferences.javaHomePath,
                statusText: FileManager.default.fileExists(atPath: store.preferences.javaHomePath)
                    ? localizer.L("Detected", "已检测")
                    : localizer.L("Custom", "自定义"),
                statusColor: FileManager.default.fileExists(atPath: store.preferences.javaHomePath)
                    ? ColdTungstenPalette.signalEmerald
                    : ColdTungstenPalette.coolPewter
            )
        }
    }

    private var securityPluginsTabContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            preferenceToggleRow(
                title: localizer.L(
                    "Enforce Strict Manifest Capability Sandbox Gates",
                    "强制执行严格的插件清单权限沙箱门禁"
                ),
                subtitle: localizer.L(
                    "Blocks undeclared mach.* bridge calls (binary.read, symbols.read, cfg.read, findings.emit)",
                    "拦截未声明权限的 mach.* 桥接调用 (binary.read, symbols.read, cfg.read, findings.emit)"
                ),
                isOn: $store.preferences.enforcePluginCapabilityGates
            )
            preferenceSliderRow(
                title: localizer.L("Per-Plugin Execution Timeout Budget", "单插件执行超时预算"),
                valueText: "\(Int(store.preferences.pluginTimeoutMilliseconds)) ms",
                value: $store.preferences.pluginTimeoutMilliseconds,
                range: 500.0...15_000.0
            )

            ForEach(store.effectivePlugins) { manifest in
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8) {
                        Toggle("", isOn: Binding(
                            get: { store.isPluginEnabled(manifest.id) },
                            set: { store.setPluginEnabled(manifest.id, isEnabled: $0) }
                        ))
                        .labelsHidden()
                        .toggleStyle(.switch)
                        .controlSize(.small)

                        Text(manifest.localizedName(in: localizer.language))
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.steelWhite)

                        Text("v\(manifest.version)")
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                        Spacer()

                        Text(manifest.isBuiltIn ? localizer.L("BUILT-IN", "内置") : localizer.L("CUSTOM", "自定义"))
                            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                            .foregroundStyle(manifest.isBuiltIn ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                    }

                    Text(manifest.localizedSummary(in: localizer.language))
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack(spacing: 5) {
                        ForEach(manifest.capabilities, id: \.self) { cap in
                            Text(cap.rawValue)
                                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1.5)
                                .background(ColdTungstenPalette.chassisBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                    }
                }
                .padding(10)
                .background(ColdTungstenPalette.chassisBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )
            }
        }
    }

    private func preferenceToggleRow(title: String, subtitle: String, isOn: Binding<Bool>) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                Text(subtitle)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
    }

    private func preferenceSliderRow(
        title: String,
        valueText: String,
        value: Binding<Double>,
        range: ClosedRange<Double>
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                Spacer()
                Text(valueText)
                    .font(ColdTungstenTypography.addressMono(size: 11.5))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
            }
            Slider(value: value, in: range)
                .tint(ColdTungstenPalette.tungstenSapphire)
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
    }

    private func preferencePathRow(
        title: String,
        path: Binding<String>,
        statusText: String,
        statusColor: Color
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                Spacer()
                Text(statusText.uppercased())
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                    .foregroundStyle(statusColor)
            }
            TextField("", text: path)
                .textFieldStyle(.plain)
                .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
    }
}

// MARK: - Toast Notification Banner Queue & Overlay

public enum MachToastKind: String, Sendable, Codable, Hashable, CaseIterable {
    case info = "INFO"
    case success = "OK"
    case warning = "WARN"
    case error = "ERROR"

    public var accentColor: Color {
        switch self {
        case .info: return ColdTungstenPalette.tungstenSapphire
        case .success: return ColdTungstenPalette.signalEmerald
        case .warning: return ColdTungstenPalette.tungstenAmber
        case .error: return ColdTungstenPalette.anodizedCrimson
        }
    }

    public var sfSymbolName: String {
        switch self {
        case .info: return "info.circle.fill"
        case .success: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }
}

public struct MachToastBannerItem: Sendable, Codable, Hashable, Identifiable {
    public let id: UUID
    public let kind: MachToastKind
    public let title: String
    public let detail: String?
    public let addressLink: VirtualAddress?
    public let durationSeconds: TimeInterval
    public let createdAt: Date

    public init(
        id: UUID = UUID(),
        kind: MachToastKind,
        title: String,
        detail: String? = nil,
        addressLink: VirtualAddress? = nil,
        durationSeconds: TimeInterval = 4.0,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.detail = detail
        self.addressLink = addressLink
        self.durationSeconds = max(1.0, durationSeconds)
        self.createdAt = createdAt
    }
}

@MainActor
public final class MachToastQueueController: ObservableObject {
    @Published public private(set) var activeToasts: [MachToastBannerItem] = []
    public let maxVisibleToasts: Int

    public init(maxVisibleToasts: Int = 4) {
        self.maxVisibleToasts = max(1, maxVisibleToasts)
    }

    @discardableResult
    public func enqueue(
        kind: MachToastKind,
        title: String,
        detail: String? = nil,
        addressLink: VirtualAddress? = nil,
        durationSeconds: TimeInterval = 4.0,
        autoDismiss: Bool = true
    ) -> MachToastBannerItem {
        let item = MachToastBannerItem(
            kind: kind,
            title: title,
            detail: detail,
            addressLink: addressLink,
            durationSeconds: durationSeconds
        )
        activeToasts.append(item)
        if activeToasts.count > maxVisibleToasts {
            activeToasts.removeFirst(activeToasts.count - maxVisibleToasts)
        }

        if autoDismiss {
            let itemID = item.id
            let delayNs = UInt64(item.durationSeconds * 1_000_000_000)
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: delayNs)
                self?.dismiss(id: itemID)
            }
        }
        return item
    }

    public func dismiss(id: UUID) {
        activeToasts.removeAll { $0.id == id }
    }

    public func dismissAll() {
        activeToasts.removeAll()
    }
}

@MainActor
public struct MachToastBannerOverlayView: View {
    @ObservedObject public var queue: MachToastQueueController
    public let onJumpToAddress: ((VirtualAddress) -> Void)?

    public init(
        queue: MachToastQueueController,
        onJumpToAddress: ((VirtualAddress) -> Void)? = nil
    ) {
        self.queue = queue
        self.onJumpToAddress = onJumpToAddress
    }

    public var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            ForEach(queue.activeToasts) { toast in
                HStack(spacing: 10) {
                    Rectangle()
                        .fill(toast.kind.accentColor)
                        .frame(width: 3)

                    Image(systemName: toast.kind.sfSymbolName)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(toast.kind.accentColor)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(toast.title)
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                        if let detail = toast.detail, !detail.isEmpty {
                            Text(detail)
                                .font(ColdTungstenTypography.secondaryCaption)
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Spacer(minLength: 8)

                    if let addr = toast.addressLink, let onJumpToAddress {
                        Button(addr.compactHexString) {
                            onJumpToAddress(addr)
                        }
                        .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                    }

                    Button {
                        queue.dismiss(id: toast.id)
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.trailing, 12)
                .padding(.vertical, 8)
                .frame(width: 420)
                .background(ColdTungstenPalette.brushedSteel)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )
                .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
            }
        }
        .padding(14)
    }
}

// MARK: - Reverse-Engineering Keyboard Shortcut Cheatsheet

public struct MachKeyboardShortcutDescriptor: Sendable, Hashable, Identifiable {
    public var id: String { "\(category):\(keys)" }
    public let category: String
    public let keys: String
    public let actionTitle: String
    public let summary: String

    public init(category: String, keys: String, actionTitle: String, summary: String) {
        self.category = category
        self.keys = keys
        self.actionTitle = actionTitle
        self.summary = summary
    }

    public static var allShortcuts: [MachKeyboardShortcutDescriptor] {
        shortcuts(in: .en)
    }

    public static func shortcuts(in language: MachLanguage) -> [MachKeyboardShortcutDescriptor] {
        let navCat = language.select("Navigation & Inspection", "导航与视图审查")
        let editCat = language.select("Analyst Annotations & Patching", "分析标注与二进制补丁")
        let appCat = language.select("Workbench & Security Audit", "工作台、双语与安全审计")

        return [
            MachKeyboardShortcutDescriptor(
                category: navCat,
                keys: "G",
                actionTitle: language.select("Go to Address / Offset / Symbol", "跳转至地址 / 偏移 / 符号"),
                summary: language.select(
                    "Jump to hex VA (0x100001000), relative delta (+0x400), file offset (off:0x1000), or symbol",
                    "跳转至十六进制虚拟地址 (0x100001000)、相对偏移 (+0x400)、文件偏移 (off:0x1000) 或符号"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: navCat,
                keys: "X",
                actionTitle: language.select("Cross-References at Cursor", "光标处交叉引用"),
                summary: language.select(
                    "Open incoming/outgoing call, branch, ADRP+ADD, and string Xref quick-jump popover",
                    "打开当前地址的调用、分支、ADRP+ADD 与字符串交叉引用快速跳转浮窗"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: navCat,
                keys: "Space",
                actionTitle: language.select("Toggle CFG Graph / Linear Disassembly", "切换控制流图 / 线性反汇编"),
                summary: language.select(
                    "Switch instantaneously between Sugiyama layered CFG and linear ARM64 disassembly",
                    "在 Sugiyama 分层控制流图与线性 ARM64 反汇编视图间即时切换"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: navCat,
                keys: "⌥⌘S",
                actionTitle: language.select("Toggle Split CFG + Pseudo-C Decompiler", "切换并排分屏 (控制流图 + 伪C)"),
                summary: language.select(
                    "Display synchronized Control Flow Graph and structured Pseudo-C side-by-side",
                    "并排同步展示控制流图与结构化 SSA 伪C反编译代码"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: navCat,
                keys: "[ / ]",
                actionTitle: language.select("Navigate Cursor Back / Forward", "光标历史后退 / 前进"),
                summary: language.select(
                    "Traverse synchronized address jump history across panes",
                    "在跨视图同步地址跳转历史栈中后退或前进"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: editCat,
                keys: "N",
                actionTitle: language.select("Rename Function or Symbol", "重命名函数或符号"),
                summary: language.select(
                    "Commit persistent custom symbol name and optional C signature into .machproj",
                    "将自定义符号名与可选 C 函数签名持久化保存至 .machproj"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: editCat,
                keys: ";",
                actionTitle: language.select("Add / Edit Inline Comment", "添加 / 编辑内联注释"),
                summary: language.select(
                    "Attach analyst comment to the current virtual address with Undo/Redo journaling",
                    "在当前虚拟地址附加分析注释并写入撤销/重做日志"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: editCat,
                keys: "B",
                actionTitle: language.select("Toggle Analyst Bookmark", "切换分析书签"),
                summary: language.select(
                    "Bookmark or unbookmark the active cursor address with color/category tag",
                    "为当前光标地址添加或移除带分类颜色标记的分析书签"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: editCat,
                keys: "⌘Z / ⇧⌘Z",
                actionTitle: language.select("Undo / Redo SQLite Mutation", "撤销 / 重做 SQLite 修改"),
                summary: language.select(
                    "Atomically roll back or replay renames, comments, bookmarks, structs, and patches",
                    "原子回滚或重放重命名、注释、书签、C 结构体与字节补丁"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: appCat,
                keys: "⌘K",
                actionTitle: language.select("Fuzzy Command & Symbol Palette", "模糊命令与符号面板"),
                summary: language.select(
                    "Zero-latency subsequence search across commands, functions, symbols, strings, and findings",
                    "零延迟模糊检索全部命令、恢复函数、符号、字符串与安全审计发现"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: appCat,
                keys: "⇧⌘L",
                actionTitle: language.select("Toggle Interface Language (中文 / EN)", "切换界面语言 (中文 / EN)"),
                summary: language.select(
                    "Switch the entire MachGraph workbench live between Simplified Chinese and English",
                    "在简体中文与英文工作台界面之间实时无刷新切换"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: appCat,
                keys: "⇧⌘A",
                actionTitle: language.select("Run JavaScriptCore Security Audit", "运行 JavaScriptCore 安全审计"),
                summary: language.select(
                    "Execute all enabled static security and PAC gadget plugins against active binary",
                    "对当前二进制运行全部已启用的静态安全与 PAC Gadget 审计插件"
                )
            ),
            MachKeyboardShortcutDescriptor(
                category: appCat,
                keys: "⌘,",
                actionTitle: language.select("Open Workbench Preferences", "打开工作台偏好设置"),
                summary: language.select(
                    "Configure language, ARM64 ABI registers, CFG routing, Ghidra 12.1.4 path, and JS sandboxes",
                    "配置界面语言、ARM64 ABI 寄存器、控制流图路由、Ghidra 12.1.4 路径与 JS 沙箱"
                )
            )
        ]
    }
}

@MainActor
public struct MachKeyboardShortcutsCheatsheetView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    public let onClose: (() -> Void)?

    public init(onClose: (() -> Void)? = nil) {
        self.onClose = onClose
    }

    private var activeShortcuts: [MachKeyboardShortcutDescriptor] {
        MachKeyboardShortcutDescriptor.shortcuts(in: localizer.language)
    }

    private var categories: [String] {
        var seen: [String] = []
        for item in activeShortcuts where !seen.contains(item.category) {
            seen.append(item.category)
        }
        return seen
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Reverse-Engineering Keyboard Shortcuts", "逆向分析键盘快捷键速查表"),
                sfSymbol: "keyboard"
            ) {
                if let onClose {
                    Button(localizer.L("Close", "关闭")) { onClose() }
                        .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(categories, id: \.self) { category in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(category.uppercased())
                                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                            ForEach(activeShortcuts.filter { $0.category == category }) { item in
                                HStack(spacing: 12) {
                                    TungstenKeycapBadge(item.keys)
                                        .frame(width: 78, alignment: .leading)

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.actionTitle)
                                            .font(ColdTungstenTypography.controlLabel)
                                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                                        Text(item.summary)
                                            .font(ColdTungstenTypography.secondaryCaption)
                                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                    Spacer()
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 7)
                                .background(ColdTungstenPalette.chassisBackground)
                                .overlay(
                                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                                )
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(ColdTungstenPalette.gunmetalSlate)
        }
        .frame(width: 640, height: 470)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }
}
