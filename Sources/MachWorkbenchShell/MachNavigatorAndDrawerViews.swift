import Foundation
import SwiftUI
import MachGraphModels
import MachProjectStore
import MachPluginSDK

// MARK: - Navigator Sidebar State & Sort Ordering

public enum NavigatorFunctionSortOrder: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case addressAscending = "Address"
    case nameAlphabetical = "Name"
    case complexityDescending = "Complexity"
    case sizeDescending = "Instructions"

    public var id: String { rawValue }

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .addressAscending:
            return language.select("Address", "地址")
        case .nameAlphabetical:
            return language.select("Name", "名称")
        case .complexityDescending:
            return language.select("Complexity", "复杂度")
        case .sizeDescending:
            return language.select("Instructions", "指令数")
        }
    }
}

extension NavigatorSidebarFilter {
    public var sfSymbolName: String {
        switch self {
        case .functions: return "function"
        case .symbols: return "tag"
        case .imports: return "shippingbox"
        case .strings: return "text.quote"
        case .classes: return "cube.box"
        case .bookmarks: return "bookmark"
        case .patches: return "bandage"
        }
    }
}

@MainActor
public final class MachNavigatorSidebarState: ObservableObject {
    @Published public var selectedMode: NavigatorSidebarFilter
    @Published public var filterQuery: String
    @Published public var functionSortOrder: NavigatorFunctionSortOrder
    @Published public var onlyPACFunctions: Bool
    @Published public var hideThunkFunctions: Bool

    public init(
        selectedMode: NavigatorSidebarFilter = .functions,
        filterQuery: String = "",
        functionSortOrder: NavigatorFunctionSortOrder = .addressAscending,
        onlyPACFunctions: Bool = false,
        hideThunkFunctions: Bool = false
    ) {
        self.selectedMode = selectedMode
        self.filterQuery = filterQuery
        self.functionSortOrder = functionSortOrder
        self.onlyPACFunctions = onlyPACFunctions
        self.hideThunkFunctions = hideThunkFunctions
    }
}

// MARK: - Left 7-Mode Binary Navigator Sidebar View

@MainActor
public struct MachBinaryNavigatorSidebarView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    @ObservedObject public var state: MachNavigatorSidebarState
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus

    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]
    public let customRenames: [UserSymbolRename]
    public let bookmarks: [UserBookmark]
    public let patches: [BytePatchRecord]
    public let onDeleteBookmark: ((UserBookmark) -> Void)?
    public let onTogglePatch: ((BytePatchRecord) -> Void)?

    public init(
        state: MachNavigatorSidebarState,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        customRenames: [UserSymbolRename] = [],
        bookmarks: [UserBookmark] = [],
        patches: [BytePatchRecord] = [],
        onDeleteBookmark: ((UserBookmark) -> Void)? = nil,
        onTogglePatch: ((BytePatchRecord) -> Void)? = nil
    ) {
        self.state = state
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
        self.customRenames = customRenames
        self.bookmarks = bookmarks
        self.patches = patches
        self.onDeleteBookmark = onDeleteBookmark
        self.onTogglePatch = onTogglePatch
    }

    private var renameMap: [VirtualAddress: String] {
        var dict: [VirtualAddress: String] = [:]
        for item in customRenames {
            dict[item.address] = item.customName
        }
        return dict
    }

    private var normalizedQuery: String {
        state.filterQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Binary Navigator", "二进制导航"),
                sfSymbol: "sidebar.left",
                countBadge: modeCount(for: state.selectedMode)
            )

            // 7-Mode Selector Strip (Horizontally Scrollable so Zero Truncation Occurs)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 5) {
                    ForEach(NavigatorSidebarFilter.allCases) { mode in
                        modePillButton(mode)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 7)
            }
            .background(ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            // Instant Filter Field + Mode-Specific Auxiliary Controls
            VStack(spacing: 6) {
                HStack(spacing: 7) {
                    Image(systemName: "line.3.horizontal.decrease.circle")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                    TextField(state.selectedMode.localizedFilterPlaceholder(in: localizer.language), text: $state.filterQuery)
                        .textFieldStyle(.plain)
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)

                    if !state.filterQuery.isEmpty {
                        Button {
                            state.filterQuery = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(ColdTungstenPalette.chassisBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )

                if state.selectedMode == .functions {
                    functionSortAndFilterStrip
                }
            }
            .padding(8)
            .background(ColdTungstenPalette.gunmetalSlate)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            // Active Navigator List Content
            Group {
                switch state.selectedMode {
                case .functions:
                    functionsListView
                case .symbols:
                    symbolsListView
                case .imports:
                    importsListView
                case .strings:
                    stringsListView
                case .classes:
                    objcAndSwiftListView
                case .bookmarks:
                    bookmarksListView
                case .patches:
                    patchesListView
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(ColdTungstenPalette.chassisBackground)
        }
        .frame(minWidth: ColdTungstenMetrics.sidebarMinWidth)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(alignment: .trailing) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline)
        }
    }

    // MARK: Mode Header Helpers

    private func modeCount(for mode: NavigatorSidebarFilter) -> Int {
        switch mode {
        case .functions: return filteredFunctions.count
        case .symbols: return filteredSymbols.count
        case .imports: return (image?.importedLibraries.count ?? 0) + filteredImportStubs.count
        case .strings: return filteredStrings.count
        case .classes: return filteredObjCClasses.count + filteredSwiftTypes.count
        case .bookmarks: return filteredBookmarks.count
        case .patches: return filteredPatches.count
        }
    }

    private func modePillButton(_ mode: NavigatorSidebarFilter) -> some View {
        let active = state.selectedMode == mode
        return Button {
            state.selectedMode = mode
        } label: {
            HStack(spacing: 4) {
                Image(systemName: mode.sfSymbolName)
                    .font(.system(size: 10.5, weight: .semibold))
                Text(mode.localizedTitle(in: localizer.language))
                    .font(ColdTungstenTypography.controlLabel)
            }
            .foregroundStyle(active ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(active ? ColdTungstenPalette.activeSelectionFill : ColdTungstenPalette.chassisBackground)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(
                        active ? ColdTungstenPalette.tungstenSapphire.opacity(0.8) : ColdTungstenPalette.tungstenSeam,
                        lineWidth: ColdTungstenMetrics.borderHairline
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
            .fixedSize(horizontal: true, vertical: true)
        }
        .buttonStyle(.plain)
    }

    private var functionSortAndFilterStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 5) {
                ForEach(NavigatorFunctionSortOrder.allCases) { order in
                    let selected = state.functionSortOrder == order
                    Button(order.localizedTitle(in: localizer.language)) {
                        state.functionSortOrder = order
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: selected ? .accentSapphire : .standard,
                        isActive: selected,
                        compact: true
                    ))
                }

                Button("PAC") {
                    state.onlyPACFunctions.toggle()
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: state.onlyPACFunctions ? .cautionAmber : .standard,
                    isActive: state.onlyPACFunctions,
                    compact: true
                ))

                Button(localizer.L("No Thunks", "隐藏跳板")) {
                    state.hideThunkFunctions.toggle()
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: state.hideThunkFunctions ? .positiveEmerald : .standard,
                    isActive: state.hideThunkFunctions,
                    compact: true
                ))
            }
        }
    }

    // MARK: 1. Functions Mode

    private var filteredFunctions: [RecoveredFunction] {
        let renames = renameMap
        let q = normalizedQuery
        var list = functions.filter { fn in
            if state.onlyPACFunctions && !fn.usesPAC { return false }
            if state.hideThunkFunctions && fn.isThunk { return false }
            guard !q.isEmpty else { return true }
            let custom = renames[fn.address]?.lowercased() ?? ""
            return custom.contains(q)
                || fn.demangledName.lowercased().contains(q)
                || fn.name.lowercased().contains(q)
                || fn.address.compactHexString.lowercased().contains(q)
        }

        switch state.functionSortOrder {
        case .addressAscending:
            list.sort { $0.address < $1.address }
        case .nameAlphabetical:
            list.sort {
                let lhs = renames[$0.address] ?? $0.demangledName
                let rhs = renames[$1.address] ?? $1.demangledName
                return lhs.localizedCaseInsensitiveCompare(rhs) == .orderedAscending
            }
        case .complexityDescending:
            list.sort {
                if $0.cyclomaticComplexity != $1.cyclomaticComplexity {
                    return $0.cyclomaticComplexity > $1.cyclomaticComplexity
                }
                return $0.address < $1.address
            }
        case .sizeDescending:
            list.sort {
                if $0.instructionCount != $1.instructionCount {
                    return $0.instructionCount > $1.instructionCount
                }
                return $0.address < $1.address
            }
        }
        return list
    }

    private var functionsListView: some View {
        let items = filteredFunctions
        let renames = renameMap
        return Group {
            if items.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No matching functions recovered.", "未找到匹配的恢复函数。"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(items) { fn in
                            let isActive = cursorBus.activeFunctionAddress == fn.address
                                || cursorBus.currentLocation.virtualAddress == fn.address
                            let displayName = renames[fn.address] ?? fn.demangledName
                            let ccColor: Color = fn.cyclomaticComplexity >= 12
                                ? ColdTungstenPalette.anodizedCrimson
                                : (fn.cyclomaticComplexity >= 6 ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.coolPewter)

                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Text(fn.address.compactHexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                        .fixedSize()

                                    Spacer(minLength: 4)

                                    if fn.usesPAC {
                                        microTagPill("PAC", color: ColdTungstenPalette.tungstenAmber)
                                    }
                                    if fn.isThunk {
                                        microTagPill(localizer.L("THUNK", "跳板"), color: ColdTungstenPalette.coolPewter)
                                    } else if fn.isLeaf {
                                        microTagPill(localizer.L("LEAF", "叶函数"), color: ColdTungstenPalette.signalEmerald)
                                    }
                                    microTagPill("CC:\(fn.cyclomaticComplexity)", color: ccColor)
                                }

                                Text(displayName)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: isActive ? .semibold : .regular))
                                    .foregroundStyle(renames[fn.address] != nil ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)

                                Text(
                                    localizer.L(
                                        "\(fn.blocks.count) BBs · \(fn.instructionCount) insns · frame \(fn.stackFrameBytes)B",
                                        "\(fn.blocks.count) 基本块 · \(fn.instructionCount) 指令 · 栈帧 \(fn.stackFrameBytes)B"
                                    )
                                )
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(isActive ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                            .overlay(alignment: .bottom) {
                                Rectangle()
                                    .fill(ColdTungstenPalette.tungstenSeam.opacity(0.45))
                                    .frame(height: ColdTungstenMetrics.borderHairline)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                cursorBus.selectFunction(fn, in: image)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 2. Symbols Mode

    private var filteredSymbols: [BinarySymbol] {
        guard let image else { return [] }
        let q = normalizedQuery
        let renames = renameMap
        guard !q.isEmpty else { return image.symbols }
        return image.symbols.filter { sym in
            let custom = renames[sym.address]?.lowercased() ?? ""
            return custom.contains(q)
                || sym.demangledName.lowercased().contains(q)
                || sym.name.lowercased().contains(q)
                || sym.kind.rawValue.lowercased().contains(q)
                || sym.address.compactHexString.lowercased().contains(q)
        }
    }

    private var symbolsListView: some View {
        let items = filteredSymbols
        let renames = renameMap
        return Group {
            if items.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No symbols match the current filter.", "未找到匹配的符号。"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(items) { sym in
                            let active = cursorBus.currentLocation.virtualAddress == sym.address && sym.address.rawValue != 0
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(sym.address.rawValue == 0 ? "extern" : sym.address.compactHexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(sym.address.rawValue == 0 ? ColdTungstenPalette.mutedOffsetInk : ColdTungstenPalette.tungstenSapphire)
                                        .fixedSize()
                                    Spacer(minLength: 4)
                                    microTagPill(sym.binding.rawValue.uppercased(), color: ColdTungstenPalette.coolPewter)
                                    microTagPill(sym.kind.rawValue, color: ColdTungstenPalette.tungstenSapphire)
                                }
                                Text(renames[sym.address] ?? sym.demangledName)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(active ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                            .overlay(alignment: .bottom) {
                                Rectangle()
                                    .fill(ColdTungstenPalette.tungstenSeam.opacity(0.4))
                                    .frame(height: ColdTungstenMetrics.borderHairline)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                if sym.address.rawValue != 0 {
                                    cursorBus.jump(toAddress: sym.address, in: image, functions: functions)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 3. Imports Mode (Libraries + Imported Stubs)

    private var filteredLibraries: [ImportedLibrary] {
        guard let image else { return [] }
        let q = normalizedQuery
        guard !q.isEmpty else { return image.importedLibraries }
        return image.importedLibraries.filter {
            $0.installName.lowercased().contains(q) || $0.shortName.lowercased().contains(q)
        }
    }

    private var filteredImportStubs: [BinarySymbol] {
        guard let image else { return [] }
        let q = normalizedQuery
        return image.symbols.filter { sym in
            let isImport = sym.kind == .importedStub || sym.binding == .external
            guard isImport else { return false }
            guard !q.isEmpty else { return true }
            return sym.demangledName.lowercased().contains(q) || sym.name.lowercased().contains(q)
        }
    }

    private var importsListView: some View {
        let libs = filteredLibraries
        let stubs = filteredImportStubs
        return Group {
            if libs.isEmpty && stubs.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No imported dylibs or external symbol stubs.", "无导入动态库或外部符号桩。"))
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(libs) { lib in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text("#\(lib.ordinal)")
                                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    Text(lib.shortName)
                                        .font(ColdTungstenTypography.controlLabel)
                                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    Spacer()
                                    if lib.isWeak {
                                        microTagPill(localizer.L("WEAK", "弱引用"), color: ColdTungstenPalette.tungstenAmber)
                                    }
                                    if lib.isReexport {
                                        microTagPill(localizer.L("REEXPORT", "重导出"), color: ColdTungstenPalette.tungstenSapphire)
                                    }
                                }
                                Text("\(lib.installName) (v\(lib.currentVersion))")
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(ColdTungstenPalette.gunmetalSlate)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam).frame(height: 1)
                            }
                        }

                        ForEach(stubs) { stub in
                            HStack(spacing: 8) {
                                Text(stub.address.rawValue == 0 ? "DYLD_BIND" : stub.address.compactHexString)
                                    .font(ColdTungstenTypography.addressMono(size: 11.0))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize()
                                Text(stub.demangledName)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer()
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.4)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                if stub.address.rawValue != 0 {
                                    cursorBus.jump(toAddress: stub.address, in: image, functions: functions)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 4. Strings Mode

    private var filteredStrings: [ExtractedStringLiteral] {
        guard let image else { return [] }
        let q = normalizedQuery
        guard !q.isEmpty else { return image.strings }
        return image.strings.filter {
            $0.value.lowercased().contains(q)
                || $0.sectionName.lowercased().contains(q)
                || $0.address.compactHexString.lowercased().contains(q)
        }
    }

    private var stringsListView: some View {
        let items = filteredStrings
        return Group {
            if items.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No extracted string literals match filter.", "未找到匹配的字符串常量。"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(items) { str in
                            let isSelected = cursorBus.currentLocation.virtualAddress == str.address
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(str.address.compactHexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                        .fixedSize()
                                    Text(str.sectionName)
                                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    Spacer()
                                    microTagPill(str.encoding.rawValue, color: ColdTungstenPalette.warmCopper)
                                }
                                Text("\"\(str.value.replacingOccurrences(of: "\n", with: "\\n"))\"")
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.warmCopper)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(isSelected ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.4)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                cursorBus.jump(toAddress: str.address, in: image, functions: functions)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 5. ObjC / Swift Runtime Metadata Mode

    private var filteredObjCClasses: [ObjCClassMetadata] {
        guard let image else { return [] }
        let q = normalizedQuery
        guard !q.isEmpty else { return image.objcClasses }
        return image.objcClasses.filter { cls in
            cls.name.lowercased().contains(q)
                || (cls.superclassName?.lowercased().contains(q) ?? false)
                || cls.methods.contains { $0.selector.lowercased().contains(q) }
        }
    }

    private var filteredSwiftTypes: [SwiftTypeDescriptor] {
        guard let image else { return [] }
        let q = normalizedQuery
        guard !q.isEmpty else { return image.swiftTypes }
        return image.swiftTypes.filter { st in
            st.demangledName.lowercased().contains(q)
                || st.mangledName.lowercased().contains(q)
                || st.fieldNames.contains { $0.lowercased().contains(q) }
        }
    }

    private var objcAndSwiftListView: some View {
        let objcList = filteredObjCClasses
        let swiftList = filteredSwiftTypes
        return Group {
            if objcList.isEmpty && swiftList.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No Objective-C classes or Swift nominal descriptors.", "未检测到 Objective-C 类或 Swift 类型描述符。"))
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(objcList) { cls in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    microTagPill("OBJC", color: ColdTungstenPalette.tungstenAmber)
                                    Text(cls.superclassName != nil ? "\(cls.name) : \(cls.superclassName!)" : cls.name)
                                        .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .semibold))
                                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    Spacer()
                                    Text(cls.address.compactHexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                }
                                .contentShape(Rectangle())
                                .onTapGesture {
                                    cursorBus.jump(toAddress: cls.address, in: image, functions: functions)
                                }

                                ForEach(cls.methods) { method in
                                    HStack(spacing: 6) {
                                        Text("\(method.isClassMethod ? "+" : "-")\(method.selector)")
                                            .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                                            .fixedSize(horizontal: false, vertical: true)
                                        Spacer()
                                        Text(method.implementationAddress.compactHexString)
                                            .font(ColdTungstenTypography.addressMono(size: 10.5))
                                            .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    }
                                    .padding(.leading, 10)
                                    .padding(.vertical, 2)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        cursorBus.jump(toAddress: method.implementationAddress, in: image, functions: functions)
                                    }
                                }
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.45)).frame(height: 1)
                            }
                        }

                        ForEach(swiftList) { st in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    microTagPill("SWIFT \(st.kind.rawValue.uppercased())", color: ColdTungstenPalette.signalEmerald)
                                    Spacer()
                                    Text(st.address.compactHexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                }
                                Text(st.demangledName)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .medium))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)
                                if !st.fieldNames.isEmpty {
                                    Text("\(localizer.L("Fields:", "字段:")) \(st.fieldNames.joined(separator: ", "))")
                                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.45)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                cursorBus.jump(toAddress: st.address, in: image, functions: functions)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 6. Bookmarks Mode

    private var filteredBookmarks: [UserBookmark] {
        let q = normalizedQuery
        guard !q.isEmpty else { return bookmarks }
        return bookmarks.filter {
            $0.label.lowercased().contains(q)
                || $0.categoryTag.lowercased().contains(q)
                || $0.address.compactHexString.lowercased().contains(q)
        }
    }

    private var bookmarksListView: some View {
        let items = filteredBookmarks
        return Group {
            if items.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No analyst bookmarks saved. Press B to bookmark cursor.", "暂无分析书签。按 B 键可在当前光标处添加书签。"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(items) { bm in
                            let tagColor = ColdTungstenPalette.parseBookmarkColor(bm.categoryTag)
                            HStack(spacing: 8) {
                                Circle()
                                    .fill(tagColor)
                                    .frame(width: 7, height: 7)

                                VStack(alignment: .leading, spacing: 3) {
                                    HStack(spacing: 6) {
                                        Text(bm.address.compactHexString)
                                            .font(ColdTungstenTypography.addressMono(size: 11.0))
                                            .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                        microTagPill(bm.categoryTag, color: tagColor)
                                    }
                                    Text(bm.label)
                                        .font(ColdTungstenTypography.controlLabel)
                                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                                        .fixedSize(horizontal: false, vertical: true)
                                }

                                Spacer()

                                if let onDeleteBookmark {
                                    Button {
                                        onDeleteBookmark(bm)
                                    } label: {
                                        Image(systemName: "trash")
                                            .font(.system(size: 11))
                                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.45)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                cursorBus.jump(toAddress: bm.address, in: image, functions: functions)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: 7. Patches Mode

    private var filteredPatches: [BytePatchRecord] {
        let q = normalizedQuery
        guard !q.isEmpty else { return patches }
        return patches.filter {
            $0.note.lowercased().contains(q)
                || ($0.patchedAssembly?.lowercased().contains(q) ?? false)
                || $0.fileOffset.hexString.lowercased().contains(q)
                || ($0.virtualAddress?.compactHexString.lowercased().contains(q) ?? false)
        }
    }

    private var patchesListView: some View {
        let items = filteredPatches
        return Group {
            if items.isEmpty {
                emptyNavigatorPlaceholder(localizer.L("No sparse byte or ARM64 instruction patches staged.", "暂无已暂存的稀疏字节或 ARM64 指令补丁。"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(items) { patch in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 6) {
                                    Text(patch.virtualAddress?.compactHexString ?? patch.fileOffset.hexString)
                                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    Text("(\(patch.byteCount)B)")
                                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    Spacer()
                                    if let onTogglePatch {
                                        Button(patch.isEnabled ? localizer.L("ACTIVE", "已启用") : localizer.L("BYPASSED", "已旁路")) {
                                            onTogglePatch(patch)
                                        }
                                        .buttonStyle(TungstenToolbarButtonStyle(
                                            role: patch.isEnabled ? .destructiveCrimson : .standard,
                                            isActive: patch.isEnabled,
                                            compact: true
                                        ))
                                    } else {
                                        microTagPill(
                                            patch.isEnabled ? localizer.L("ACTIVE", "已启用") : localizer.L("BYPASSED", "已旁路"),
                                            color: patch.isEnabled ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.coolPewter
                                        )
                                    }
                                }

                                HStack(spacing: 5) {
                                    Text(patch.originalHex)
                                        .font(ColdTungstenTypography.hexDumpMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    Text("->")
                                        .font(ColdTungstenTypography.hexDumpMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    Text(patch.patchedHex)
                                        .font(ColdTungstenTypography.hexDumpMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                                }

                                if let newAsm = patch.patchedAssembly, !newAsm.isEmpty {
                                    Text("\(patch.originalAssembly ?? "raw") -> \(newAsm)")
                                        .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                if !patch.note.isEmpty {
                                    Text(patch.note)
                                        .font(ColdTungstenTypography.secondaryCaption)
                                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                                }
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.45)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                if let va = patch.virtualAddress {
                                    cursorBus.jump(toAddress: va, in: image, functions: functions, switchToPane: .hexPatcher)
                                } else if let va = image?.virtualAddress(for: patch.fileOffset) {
                                    cursorBus.jump(toAddress: va, in: image, functions: functions, switchToPane: .hexPatcher)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func microTagPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1.5)
            .background(color.opacity(0.14))
            .clipShape(RoundedRectangle(cornerRadius: 3))
            .fixedSize(horizontal: true, vertical: true)
    }

    private func emptyNavigatorPlaceholder(_ message: String) -> some View {
        VStack(spacing: 8) {
            Spacer()
            Text(message)
                .font(ColdTungstenTypography.secondaryCaption)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 16)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - 4-Channel Resizable Bottom Inspection Drawer

public enum WorkbenchBottomDrawerChannel: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case xrefsAtCursor = "Xrefs at Cursor"
    case securityFindings = "Security Findings"
    case undoRedoJournal = "Undo/Redo Journal"
    case pluginConsole = "Plugin Console"

    public var id: String { rawValue }

    public var sfSymbolName: String {
        switch self {
        case .xrefsAtCursor: return "arrow.triangle.branch"
        case .securityFindings: return "exclamationmark.shield"
        case .undoRedoJournal: return "clock.arrow.circlepath"
        case .pluginConsole: return "terminal"
        }
    }

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .xrefsAtCursor:
            return language.select("Xrefs at Cursor", "光标交叉引用")
        case .securityFindings:
            return language.select("Security Findings", "安全审计发现")
        case .undoRedoJournal:
            return language.select("Undo/Redo Journal", "撤销/重做日志")
        case .pluginConsole:
            return language.select("Plugin Console", "插件控制台")
        }
    }
}

@MainActor
public final class MachBottomDrawerState: ObservableObject {
    @Published public var activeChannel: WorkbenchBottomDrawerChannel
    @Published public var isCollapsed: Bool
    @Published public var drawerHeight: CGFloat
    @Published public var findingsSeverityFilter: SecurityFindingSeverity?
    @Published public var consoleEntries: [MachPluginConsoleEntry]

    public init(
        activeChannel: WorkbenchBottomDrawerChannel = .xrefsAtCursor,
        isCollapsed: Bool = false,
        drawerHeight: CGFloat = ColdTungstenMetrics.bottomDrawerDefaultHeight,
        findingsSeverityFilter: SecurityFindingSeverity? = nil,
        consoleEntries: [MachPluginConsoleEntry] = []
    ) {
        self.activeChannel = activeChannel
        self.isCollapsed = isCollapsed
        self.drawerHeight = min(
            ColdTungstenMetrics.bottomDrawerMaxHeight,
            max(ColdTungstenMetrics.bottomDrawerMinHeight, drawerHeight)
        )
        self.findingsSeverityFilter = findingsSeverityFilter
        self.consoleEntries = consoleEntries
    }

    public func appendExecutionResults(_ results: [MachPluginExecutionResult]) {
        for result in results {
            for line in result.consoleLogs {
                let level: MachPluginConsoleLevel
                if line.contains("[ERROR") { level = .error }
                else if line.contains("[WARN") { level = .warn }
                else if line.contains("[DEBUG") { level = .debug }
                else { level = .info }

                consoleEntries.append(MachPluginConsoleEntry(
                    pluginID: result.pluginID,
                    level: level,
                    message: line,
                    elapsedMilliseconds: result.durationMilliseconds
                ))
            }
        }
        if consoleEntries.count > 1_000 {
            consoleEntries.removeFirst(consoleEntries.count - 1_000)
        }
    }

    public func clearConsole() {
        consoleEntries.removeAll()
    }
}

@MainActor
public struct MachBottomInspectionDrawerView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    @ObservedObject public var state: MachBottomDrawerState
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus

    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]
    public let xrefsAtCursor: [XrefRecord]
    public let findings: [SecurityAuditFinding]
    public let undoTransactions: [AnalystTransactionRecord]
    public let redoTransactions: [AnalystTransactionRecord]
    public let onUndo: (() -> Void)?
    public let onRedo: (() -> Void)?
    public let onRunPlugins: (() -> Void)?

    @State private var dragStartHeight: CGFloat?

    public init(
        state: MachBottomDrawerState,
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage? = nil,
        functions: [RecoveredFunction] = [],
        xrefsAtCursor: [XrefRecord] = [],
        findings: [SecurityAuditFinding] = [],
        undoTransactions: [AnalystTransactionRecord] = [],
        redoTransactions: [AnalystTransactionRecord] = [],
        onUndo: (() -> Void)? = nil,
        onRedo: (() -> Void)? = nil,
        onRunPlugins: (() -> Void)? = nil
    ) {
        self.state = state
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
        self.xrefsAtCursor = xrefsAtCursor
        self.findings = findings
        self.undoTransactions = undoTransactions
        self.redoTransactions = redoTransactions
        self.onUndo = onUndo
        self.onRedo = onRedo
        self.onRunPlugins = onRunPlugins
    }

    public var body: some View {
        VStack(spacing: 0) {
            // 4pt Interactive Resize Splitter Seam
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
                .overlay {
                    Color.clear
                        .frame(height: 6)
                        .contentShape(Rectangle())
                        .gesture(
                            DragGesture(minimumDistance: 1)
                                .onChanged { value in
                                    if state.isCollapsed { state.isCollapsed = false }
                                    let base = dragStartHeight ?? state.drawerHeight
                                    if dragStartHeight == nil { dragStartHeight = base }
                                    let proposed = base - value.translation.height
                                    state.drawerHeight = min(
                                        ColdTungstenMetrics.bottomDrawerMaxHeight,
                                        max(ColdTungstenMetrics.bottomDrawerMinHeight, proposed)
                                    )
                                }
                                .onEnded { _ in
                                    dragStartHeight = nil
                                }
                        )
                }

            // Channel Selector Header Rail
            HStack(spacing: 6) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(WorkbenchBottomDrawerChannel.allCases) { channel in
                            channelTabButton(channel)
                        }
                    }
                }

                Spacer(minLength: 8)

                channelTrailingControls

                Button {
                    state.isCollapsed.toggle()
                } label: {
                    Image(systemName: state.isCollapsed ? "chevron.up" : "chevron.down")
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }
            .padding(.horizontal, 10)
            .frame(height: ColdTungstenMetrics.panelHeaderHeight)
            .background(ColdTungstenPalette.brushedSteel)

            if !state.isCollapsed {
                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                Group {
                    switch state.activeChannel {
                    case .xrefsAtCursor:
                        xrefsChannelView
                    case .securityFindings:
                        findingsChannelView
                    case .undoRedoJournal:
                        undoRedoChannelView
                    case .pluginConsole:
                        pluginConsoleChannelView
                    }
                }
                .frame(maxWidth: .infinity)
                .frame(height: state.drawerHeight)
                .background(ColdTungstenPalette.gunmetalSlate)
            }
        }
    }

    private func badgeCount(for channel: WorkbenchBottomDrawerChannel) -> Int {
        switch channel {
        case .xrefsAtCursor: return xrefsAtCursor.count
        case .securityFindings: return findings.count
        case .undoRedoJournal: return undoTransactions.count + redoTransactions.count
        case .pluginConsole: return state.consoleEntries.count
        }
    }

    private func channelTabButton(_ channel: WorkbenchBottomDrawerChannel) -> some View {
        let active = state.activeChannel == channel && !state.isCollapsed
        let count = badgeCount(for: channel)
        return Button {
            state.activeChannel = channel
            if state.isCollapsed { state.isCollapsed = false }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: channel.sfSymbolName)
                    .font(.system(size: 11, weight: .semibold))
                Text(channel.localizedTitle(in: localizer.language))
                    .font(ColdTungstenTypography.controlLabel)
                Text("\(count)")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10, weight: .semibold))
                    .foregroundStyle(
                        channel == .securityFindings && count > 0
                            ? ColdTungstenPalette.anodizedCrimson
                            : ColdTungstenPalette.coolPewter
                    )
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(ColdTungstenPalette.chassisBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 3))
            }
            .foregroundStyle(active ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(active ? ColdTungstenPalette.activeSelectionFill : Color.clear)
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

    @ViewBuilder
    private var channelTrailingControls: some View {
        switch state.activeChannel {
        case .xrefsAtCursor:
            Text("\(localizer.L("Cursor", "光标")) \(cursorBus.currentLocation.virtualAddress.compactHexString)")
                .font(ColdTungstenTypography.addressMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                .fixedSize()
        case .securityFindings:
            HStack(spacing: 4) {
                Button(localizer.L("All", "全部")) { state.findingsSeverityFilter = nil }
                    .buttonStyle(TungstenToolbarButtonStyle(isActive: state.findingsSeverityFilter == nil, compact: true))
                ForEach([SecurityFindingSeverity.critical, .high, .medium, .low], id: \.self) { sev in
                    Button(sev.localizedBadge(in: localizer.language)) {
                        state.findingsSeverityFilter = (state.findingsSeverityFilter == sev) ? nil : sev
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(isActive: state.findingsSeverityFilter == sev, compact: true))
                }
            }
        case .undoRedoJournal:
            HStack(spacing: 6) {
                Button(localizer.L("Undo", "撤销")) { onUndo?() }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .disabled(undoTransactions.isEmpty)
                Button(localizer.L("Redo", "重做")) { onRedo?() }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .disabled(redoTransactions.isEmpty)
            }
        case .pluginConsole:
            HStack(spacing: 6) {
                if let onRunPlugins {
                    Button(localizer.L("Run Audit", "运行审计")) { onRunPlugins() }
                        .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                }
                Button(localizer.L("Clear", "清空")) { state.clearConsole() }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }
        }
    }

    private var xrefsChannelView: some View {
        Group {
            if xrefsAtCursor.isEmpty {
                drawerPlaceholder(
                    localizer.L(
                        "No cross-references indexed for \(cursorBus.currentLocation.virtualAddress.compactHexString).",
                        "当前地址 \(cursorBus.currentLocation.virtualAddress.compactHexString) 暂无交叉引用索引。"
                    )
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(xrefsAtCursor) { xref in
                            let accent = ColdTungstenPalette.color(for: xref.kind)
                            HStack(spacing: 10) {
                                Text(xref.kind.localizedBadge(in: localizer.language))
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10, weight: .bold))
                                    .foregroundStyle(accent)
                                    .frame(width: 96, alignment: .leading)
                                Text("\(xref.fromAddress.compactHexString) -> \(xref.toAddress.compactHexString)")
                                    .font(ColdTungstenTypography.addressMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize()
                                Text(xref.instructionPreview)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                Spacer()
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.4)).frame(height: 1)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                let target = xref.toAddress == cursorBus.currentLocation.virtualAddress
                                    ? xref.fromAddress
                                    : xref.toAddress
                                cursorBus.jump(toAddress: target, in: image, functions: functions)
                            }
                        }
                    }
                }
            }
        }
    }

    private var findingsChannelView: some View {
        let visible = state.findingsSeverityFilter == nil
            ? findings
            : findings.filter { $0.severity == state.findingsSeverityFilter }
        return Group {
            if visible.isEmpty {
                drawerPlaceholder(localizer.L("No security audit findings matching the active filter.", "当前筛选条件下暂无安全审计发现。"))
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(visible) { finding in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 8) {
                                    SeverityBadgePill(severity: finding.severity)
                                    Text(finding.localizedTitle(in: localizer.language))
                                        .font(ColdTungstenTypography.controlLabel)
                                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    Spacer()
                                    Text(finding.localizedCategory(in: localizer.language))
                                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    if let addr = finding.address {
                                        Button(addr.compactHexString) {
                                            cursorBus.jump(toAddress: addr, in: image, functions: functions)
                                        }
                                        .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                                    }
                                }
                                Text(finding.localizedDetail(in: localizer.language))
                                    .font(ColdTungstenTypography.secondaryCaption)
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .fixedSize(horizontal: false, vertical: true)
                                if let evidence = finding.evidencePreview, !evidence.isEmpty {
                                    Text(evidence)
                                        .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                                        .foregroundStyle(ColdTungstenPalette.warmCopper)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.45)).frame(height: 1)
                            }
                        }
                    }
                }
            }
        }
    }

    private var undoRedoChannelView: some View {
        Group {
            if undoTransactions.isEmpty && redoTransactions.isEmpty {
                drawerPlaceholder(
                    localizer.L(
                        "SQLite WAL Undo/Redo journal is clean: renames, comments, bookmarks, and patches appear here.",
                        "SQLite WAL 撤销/重做日志为空: 重命名、注释、书签与字节补丁将记录于此。"
                    )
                )
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(undoTransactions) { tx in
                            transactionRow(tx, stackBadge: localizer.L("UNDO", "可撤销"), badgeColor: ColdTungstenPalette.signalEmerald)
                        }
                        ForEach(redoTransactions) { tx in
                            transactionRow(tx, stackBadge: localizer.L("REDO", "可重做"), badgeColor: ColdTungstenPalette.tungstenAmber)
                        }
                    }
                }
            }
        }
    }

    private func transactionRow(_ tx: AnalystTransactionRecord, stackBadge: String, badgeColor: Color) -> some View {
        HStack(spacing: 10) {
            Text("#\(tx.sequenceNumber)")
                .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                .fixedSize()
            Text(stackBadge)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                .foregroundStyle(badgeColor)
                .padding(.horizontal, 5)
                .padding(.vertical, 1.5)
                .background(badgeColor.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 3))
                .fixedSize()
            Text(tx.localizedTitle(in: localizer.language))
                .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .overlay(alignment: .bottom) {
            Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.4)).frame(height: 1)
        }
    }

    private var pluginConsoleChannelView: some View {
        Group {
            if state.consoleEntries.isEmpty {
                drawerPlaceholder(
                    localizer.L(
                        "JavaScriptCore plugin console idle. Click 'Run Audit' to execute static security rules.",
                        "JavaScriptCore 插件控制台空闲。点击“运行审计”以执行静态安全检测规则。"
                    )
                )
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(state.consoleEntries) { item in
                            let color: Color = {
                                switch item.level {
                                case .error: return ColdTungstenPalette.anodizedCrimson
                                case .warn: return ColdTungstenPalette.tungstenAmber
                                case .info: return ColdTungstenPalette.tungstenSapphire
                                case .debug: return ColdTungstenPalette.coolPewter
                                }
                            }()
                            HStack(alignment: .top, spacing: 8) {
                                Text("[\(item.pluginID)]")
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    .fixedSize()
                                Text(item.message)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(color)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer()
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                        }
                    }
                }
            }
        }
    }

    private func drawerPlaceholder(_ text: String) -> some View {
        HStack {
            Spacer()
            Text(text)
                .font(ColdTungstenTypography.secondaryCaption)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
            Spacer()
        }
        .frame(maxHeight: .infinity)
    }
}

// MARK: - Top Address Breadcrumb & Snapshot / Re-Sign Workbench Toolbar

@MainActor
public struct MachTopWorkbenchToolbarView: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    @ObservedObject public var cursorBus: SynchronizedAddressCursorBus
    public let image: LoadedBinaryImage?
    public let functions: [RecoveredFunction]
    public let customRenames: [UserSymbolRename]
    public let onOpenBinary: (() -> Void)?
    public let onSelectSlice: ((Int) -> Void)?
    public let onOpenGoToModal: () -> Void
    public let onOpenCommandPalette: () -> Void
    public let onRunSecurityAudit: () -> Void
    public let onCaptureSnapshot: () -> Void
    public let onReSignMachO: () -> Void

    public init(
        cursorBus: SynchronizedAddressCursorBus,
        image: LoadedBinaryImage?,
        functions: [RecoveredFunction] = [],
        customRenames: [UserSymbolRename] = [],
        onOpenBinary: (() -> Void)? = nil,
        onSelectSlice: ((Int) -> Void)? = nil,
        onOpenGoToModal: @escaping () -> Void,
        onOpenCommandPalette: @escaping () -> Void,
        onRunSecurityAudit: @escaping () -> Void,
        onCaptureSnapshot: @escaping () -> Void,
        onReSignMachO: @escaping () -> Void
    ) {
        self.cursorBus = cursorBus
        self.image = image
        self.functions = functions
        self.customRenames = customRenames
        self.onOpenBinary = onOpenBinary
        self.onSelectSlice = onSelectSlice
        self.onOpenGoToModal = onOpenGoToModal
        self.onOpenCommandPalette = onOpenCommandPalette
        self.onRunSecurityAudit = onRunSecurityAudit
        self.onCaptureSnapshot = onCaptureSnapshot
        self.onReSignMachO = onReSignMachO
    }

    private var resolvedFunctionBreadcrumb: String? {
        let va = cursorBus.currentLocation.virtualAddress
        if let fn = functions.first(where: { va >= $0.address && va < $0.endAddress }) {
            let name = customRenames.first(where: { $0.address == fn.address })?.customName ?? fn.demangledName
            let delta = va.rawValue - fn.address.rawValue
            return delta == 0 ? name : "\(name)+0x\(String(delta, radix: 16))"
        }
        return image?.exactSymbol(at: va)?.demangledName
    }

    public var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                // Back / Forward Cursor History Buttons
                HStack(spacing: 4) {
                    Button {
                        _ = cursorBus.navigateBack()
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .disabled(!cursorBus.canNavigateBack)

                    Button {
                        _ = cursorBus.navigateForward()
                    } label: {
                        Image(systemName: "chevron.right")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .disabled(!cursorBus.canNavigateForward)
                }

                if let onOpenBinary {
                    Button {
                        onOpenBinary()
                    } label: {
                        Label(localizer.L("Open Binary", "打开二进制"), systemImage: "folder")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                }

                // Format & Architecture Badge + Universal Fat Slice Selector
                if let image {
                    FormatArchBadge(image: image)

                    if image.slices.count > 1, let onSelectSlice {
                        Menu {
                            ForEach(image.slices) { slice in
                                Button(
                                    localizer.L(
                                        "Slice #\(slice.index): \(slice.architecture.displayName) (\(slice.fileOffset.hexString))",
                                        "切片 #\(slice.index): \(slice.architecture.displayName) (\(slice.fileOffset.hexString))"
                                    )
                                ) {
                                    onSelectSlice(slice.index)
                                }
                            }
                        } label: {
                            Label(
                                localizer.L("Slice: \(image.architecture.displayName)", "切片: \(image.architecture.displayName)"),
                                systemImage: "square.stack.3d.up"
                            )
                        }
                        .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, compact: true))
                    }
                }

                // Interactive Synchronized Address Breadcrumb Bar (`G` Modal Trigger)
                breadcrumbBarButton

                // Side-by-Side Split (`CFG + Pseudo-C`) Toggle
                Button {
                    cursorBus.toggleSplitView(defaultSecondary: .pseudoC)
                } label: {
                    Label(
                        cursorBus.isSplitViewActive
                            ? localizer.L("Split: CFG + Pseudo-C", "分屏: 控制流图 + 伪C")
                            : localizer.L("Split View", "分屏视图"),
                        systemImage: "rectangle.split.2x1"
                    )
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: cursorBus.isSplitViewActive ? .accentSapphire : .standard,
                    isActive: cursorBus.isSplitViewActive,
                    compact: true
                ))

                // Command Palette, Audit, Snapshot, Re-Sign & Bilingual Language Cluster
                Button {
                    onOpenCommandPalette()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "command")
                        Text(localizer.L("Palette", "命令面板"))
                        TungstenKeycapBadge("⌘K")
                    }
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                Button {
                    onRunSecurityAudit()
                } label: {
                    Label(localizer.L("Audit", "安全审计"), systemImage: "checkmark.shield")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, compact: true))

                Button {
                    onCaptureSnapshot()
                } label: {
                    Label(localizer.L("Snapshot", "快照"), systemImage: "camera.aperture")
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                Button {
                    onReSignMachO()
                } label: {
                    Label(localizer.L("Re-Sign", "重签名"), systemImage: "signature")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, compact: true))

                TungstenLanguageTogglePill(localizer: localizer, compact: true)
            }
            .padding(.horizontal, 10)
            .frame(height: ColdTungstenMetrics.topToolbarHeight)
        }
        .background(ColdTungstenPalette.brushedSteel)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    private var breadcrumbBarButton: some View {
        let va = cursorBus.currentLocation.virtualAddress
        let fileOff = cursorBus.currentLocation.fileOffset ?? image?.fileOffset(for: va)
        let secName = image?.section(containing: va)?.fullName

        return Button(action: onOpenGoToModal) {
            HStack(spacing: 6) {
                Text(image?.fileName ?? localizer.L("No Binary", "未加载二进制"))
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)

                if let secName {
                    breadcrumbChevron
                    Text(secName)
                        .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                }

                if let fnLabel = resolvedFunctionBreadcrumb {
                    breadcrumbChevron
                    Text(fnLabel)
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.5, weight: .medium))
                        .foregroundStyle(ColdTungstenPalette.signalEmerald)
                }

                breadcrumbChevron

                Text(va.compactHexString)
                    .font(ColdTungstenTypography.addressMono(size: 12.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                if let fileOff {
                    Text(localizer.L("(File \(fileOff.hexString))", "(偏移 \(fileOff.hexString))"))
                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                }

                TungstenKeycapBadge("G")
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
            .fixedSize(horizontal: true, vertical: true)
        }
        .buttonStyle(.plain)
    }

    private var breadcrumbChevron: some View {
        Image(systemName: "chevron.right")
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
    }
}
