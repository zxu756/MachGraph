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
        ghidraInstallPath: String = "/Users/xu/Applications/ghidra_12.1.4_PUBLIC",
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
            TungstenPanelHeaderBar(title: "MachGraph Workbench Preferences", sfSymbol: "slider.horizontal.3") {
                HStack(spacing: 8) {
                    TungstenKeycapBadge("⌘,")
                    if let onClose {
                        Button("Done") { onClose() }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                    }
                }
            }

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
                            Text(tab.rawValue)
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
                Text("Cold Tungsten Steel Engineering Profile · SQLite WAL Synced")
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                Spacer()
                Button("Restore Defaults") {
                    store.resetToDefaults()
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(ColdTungstenPalette.brushedSteel)
        }
        .frame(width: 720, height: 480)
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
                title: "Display Apple ARM64 ABI Register Aliases (fp, lr, sp, xzr)",
                subtitle: "Maps x29 -> fp and x30 -> lr across linear disassembly and CFG basic-block nodes",
                isOn: $store.preferences.useABIRegisterNames
            )
            preferenceToggleRow(
                title: "Show Raw 32-Bit Little-Endian Instruction Bytes Column",
                subtitle: "Renders hex opcode bytes alongside virtual addresses for rapid patch verification",
                isOn: $store.preferences.showRawInstructionBytes
            )
            preferenceToggleRow(
                title: "Synthesize Inline ADRP+ADD / Chained Fixup / Literal Comments",
                subtitle: "Annotates PC-relative string, selector, and PAC diversity targets automatically",
                isOn: $store.preferences.showAutoComments
            )
            preferenceToggleRow(
                title: "Demangle Swift ($s...) and Itanium C++ (_Z...) Symbol Names",
                subtitle: "Applies symbol demangling in Navigator, CFG headers, and Xref quick-jump tables",
                isOn: $store.preferences.demangleSwiftAndCppSymbols
            )
            preferenceSliderRow(
                title: "Monospaced Disassembly Font Size",
                valueText: String(format: "%.1f pt", store.preferences.disassemblyFontSize),
                value: $store.preferences.disassemblyFontSize,
                range: 10.5...17.0
            )
        }
    }

    private var cfgLayoutTabContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            preferenceToggleRow(
                title: "Orthogonal Sugiyama Layered Edge Routing",
                subtitle: "Routes True (#3FB950), False (#F85149), and Unconditional (#D29922) edges along crisp right-angle channels",
                isOn: $store.preferences.orthogonalSugiyamaRouting
            )
            preferenceToggleRow(
                title: "Highlight Natural Loop Back-Edges in Tungsten Amber",
                subtitle: "Emphasizes dominator-tree loop latches for rapid control-flow comprehension",
                isOn: $store.preferences.highlightLoopBackEdges
            )
            preferenceToggleRow(
                title: "Show Dominator Tree Depth & Loop Header Badges on Basic Blocks",
                subtitle: "Displays structural dominance metadata inside each basic block header bar",
                isOn: $store.preferences.showDominatorDepthBadges
            )
            preferenceToggleRow(
                title: "Show Interactive Viewport Minimap Overlay",
                subtitle: "Renders live overview viewport frame in the corner of large CFGs",
                isOn: $store.preferences.showCFGOverviewMinimap
            )
            preferenceSliderRow(
                title: "Vertical Rank Layer Spacing",
                valueText: "\(Int(store.preferences.cfgVerticalLayerSpacing)) pt",
                value: $store.preferences.cfgVerticalLayerSpacing,
                range: 28.0...110.0
            )
            preferenceSliderRow(
                title: "Horizontal Sibling Block Spacing",
                valueText: "\(Int(store.preferences.cfgHorizontalNodeSpacing)) pt",
                value: $store.preferences.cfgHorizontalNodeSpacing,
                range: 18.0...88.0
            )
        }
    }

    private var decompilerAndGhidraTabContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            preferenceToggleRow(
                title: "Run Dead-Store & Flag Elimination Pass on Micro-IR",
                subtitle: "Folds transient NZCV condition flags into structured C relational expressions",
                isOn: $store.preferences.enableDeadStoreElimination
            )
            preferenceToggleRow(
                title: "Recover Structured if / else, while Loops, and switch Tables",
                subtitle: "Collapses unstructured goto edges into indented C control-flow AST blocks",
                isOn: $store.preferences.preferStructuredWhileAndSwitch
            )
            preferencePathRow(
                title: "Ghidra 12.1.4 Installation Directory",
                path: $store.preferences.ghidraInstallPath,
                statusText: store.isGhidraInstallationDetected ? "Detected" : "Not Found",
                statusColor: store.isGhidraInstallationDetected ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber
            )
            preferencePathRow(
                title: "OpenJDK 21 JAVA_HOME Path",
                path: $store.preferences.javaHomePath,
                statusText: FileManager.default.fileExists(atPath: store.preferences.javaHomePath) ? "Detected" : "Custom",
                statusColor: FileManager.default.fileExists(atPath: store.preferences.javaHomePath)
                    ? ColdTungstenPalette.signalEmerald
                    : ColdTungstenPalette.coolPewter
            )
        }
    }

    private var securityPluginsTabContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            preferenceToggleRow(
                title: "Enforce Strict Manifest Capability Sandbox Gates",
                subtitle: "Blocks undeclared mach.* bridge calls (binary.read, symbols.read, cfg.read, findings.emit)",
                isOn: $store.preferences.enforcePluginCapabilityGates
            )
            preferenceSliderRow(
                title: "Per-Plugin Execution Timeout Budget",
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

                        Text(manifest.name)
                            .font(ColdTungstenTypography.controlLabel)
                            .foregroundStyle(ColdTungstenPalette.steelWhite)

                        Text("v\(manifest.version)")
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                        Spacer()

                        Text(manifest.isBuiltIn ? "BUILT-IN" : "CUSTOM")
                            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                            .foregroundStyle(manifest.isBuiltIn ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                    }

                    Text(manifest.summary)
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

    public static let allShortcuts: [MachKeyboardShortcutDescriptor] = [
        MachKeyboardShortcutDescriptor(
            category: "Navigation & Inspection",
            keys: "G",
            actionTitle: "Go to Address / Offset / Symbol",
            summary: "Jump to hex VA (0x100001000), relative delta (+0x400), file offset (off:0x1000), or symbol"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Navigation & Inspection",
            keys: "X",
            actionTitle: "Cross-References at Cursor",
            summary: "Open incoming/outgoing call, branch, ADRP+ADD, and string Xref quick-jump popover"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Navigation & Inspection",
            keys: "Space",
            actionTitle: "Toggle CFG Graph / Linear Disassembly",
            summary: "Switch instantaneously between Sugiyama layered CFG and linear ARM64 disassembly"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Navigation & Inspection",
            keys: "⌥⌘S",
            actionTitle: "Toggle Split CFG + Pseudo-C Decompiler",
            summary: "Display synchronized Control Flow Graph and structured Pseudo-C side-by-side"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Navigation & Inspection",
            keys: "[ / ]",
            actionTitle: "Navigate Cursor Back / Forward",
            summary: "Traverse synchronized address jump history across panes"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Analyst Annotations & Patching",
            keys: "N",
            actionTitle: "Rename Function or Symbol",
            summary: "Commit persistent custom symbol name and optional C signature into .machproj"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Analyst Annotations & Patching",
            keys: ";",
            actionTitle: "Add / Edit Inline Comment",
            summary: "Attach analyst comment to the current virtual address with Undo/Redo journaling"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Analyst Annotations & Patching",
            keys: "B",
            actionTitle: "Toggle Analyst Bookmark",
            summary: "Bookmark or unbookmark the active cursor address with color/category tag"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Analyst Annotations & Patching",
            keys: "⌘Z / ⇧⌘Z",
            actionTitle: "Undo / Redo SQLite Mutation",
            summary: "Atomically roll back or replay renames, comments, bookmarks, structs, and patches"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Workbench & Security Audit",
            keys: "⌘K",
            actionTitle: "Fuzzy Command & Symbol Palette",
            summary: "Zero-latency subsequence search across commands, functions, symbols, strings, and findings"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Workbench & Security Audit",
            keys: "⇧⌘A",
            actionTitle: "Run JavaScriptCore Security Audit",
            summary: "Execute all enabled static security and PAC gadget plugins against active binary"
        ),
        MachKeyboardShortcutDescriptor(
            category: "Workbench & Security Audit",
            keys: "⌘,",
            actionTitle: "Open Workbench Preferences",
            summary: "Configure ARM64 ABI registers, CFG routing, Ghidra 12.1.4 path, and JS sandboxes"
        )
    ]
}

@MainActor
public struct MachKeyboardShortcutsCheatsheetView: View {
    public let onClose: (() -> Void)?

    public init(onClose: (() -> Void)? = nil) {
        self.onClose = onClose
    }

    private var categories: [String] {
        var seen: [String] = []
        for item in MachKeyboardShortcutDescriptor.allShortcuts where !seen.contains(item.category) {
            seen.append(item.category)
        }
        return seen
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(title: "Reverse-Engineering Keyboard Shortcuts", sfSymbol: "keyboard") {
                if let onClose {
                    Button("Close") { onClose() }
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

                            ForEach(MachKeyboardShortcutDescriptor.allShortcuts.filter { $0.category == category }) { item in
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
