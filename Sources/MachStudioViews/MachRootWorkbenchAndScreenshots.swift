import AppKit
import Foundation
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachHeadlessCLI
import MachMicroDecompiler
import MachPatchAndHexEngine
import MachPluginSDK
import MachProjectStore
import MachWorkbenchShell
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Master Cold Tungsten Desktop IDE Root View (`MachWorkbenchRootView`)

@MainActor
public struct MachWorkbenchRootView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    @ObservedObject private var cursorBus: SynchronizedAddressCursorBus
    @ObservedObject private var paletteController: MachCommandPaletteController
    @ObservedObject private var xrefPopoverModel: MachXrefQuickJumpModel
    @ObservedObject private var toastController: MachToastQueueController

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
        self.cursorBus = viewModel.cursorBus
        self.paletteController = viewModel.paletteController
        self.xrefPopoverModel = viewModel.xrefPopoverModel
        self.toastController = viewModel.toastController
    }

    private var shouldShowContextualCFGInspector: Bool {
        guard !cursorBus.isSplitViewActive, viewModel.showRightContextualInspector else {
            return false
        }
        return cursorBus.activePane == .cfgGraph || cursorBus.activePane == .disassembly
    }

    public var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // 1. Primary Cold Tungsten Navigation, Slice, Breadcrumb & Action Toolbar
                adaptiveTopWorkbenchToolbar

                // 2. 7-Tab Studio Workspace Bar + Target Preset & Analyst Quick Actions
                studioWorkspaceTabStrip

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                // 3. Main Workbench Split: Left Navigator + Center Studio + Optional Right CFG Inspector + Bottom Drawer
                HStack(spacing: 0) {
                    MachBinaryNavigatorSidebarView(
                        state: viewModel.navigatorState,
                        cursorBus: cursorBus,
                        image: viewModel.loadedImage,
                        functions: viewModel.functions,
                        customRenames: viewModel.customRenames,
                        bookmarks: viewModel.bookmarks,
                        patches: viewModel.overlayBuffer.patches,
                        onDeleteBookmark: { bm in
                            viewModel.deleteBookmark(bm)
                        },
                        onTogglePatch: { patch in
                            viewModel.togglePatchRecord(patch)
                        }
                    )
                    .frame(width: 306)

                    Rectangle()
                        .fill(ColdTungstenPalette.tungstenSeam)
                        .frame(width: ColdTungstenMetrics.borderHairline)

                    VStack(spacing: 0) {
                        HStack(spacing: 0) {
                            activeCenterStudioContent
                                .frame(maxWidth: .infinity, maxHeight: .infinity)

                            if shouldShowContextualCFGInspector {
                                Rectangle()
                                    .fill(ColdTungstenPalette.tungstenSeam)
                                    .frame(width: ColdTungstenMetrics.borderHairline)

                                MachCFGContextualInspectorView(viewModel: viewModel)
                                    .frame(width: 266)
                            }
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                        MachBottomInspectionDrawerView(
                            state: viewModel.drawerState,
                            cursorBus: cursorBus,
                            image: viewModel.loadedImage,
                            functions: viewModel.functions,
                            xrefsAtCursor: viewModel.xrefsAtCursor,
                            findings: viewModel.securityFindings,
                            undoTransactions: viewModel.undoStackRecords,
                            redoTransactions: viewModel.redoStackRecords,
                            onUndo: {
                                viewModel.performUndo()
                            },
                            onRedo: {
                                viewModel.performRedo()
                            },
                            onRunPlugins: {
                                viewModel.runSecurityAuditSuite(emitToast: true)
                            }
                        )
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                // 4. Precision Bottom Engineering Telemetry Status Bar
                engineeringTelemetryStatusBar
            }
            .background(ColdTungstenPalette.chassisBackground)

            // 5. Modal Overlays (`⌘K` Palette, `G` Go-To, `X` Xrefs, `N` Rename, `;` Comment, `⌘,` Prefs, Shortcuts)
            if paletteController.isPresented {
                MachCommandPaletteOverlayView(
                    controller: paletteController,
                    cursorBus: cursorBus,
                    image: viewModel.loadedImage,
                    functions: viewModel.functions,
                    onTriggerAction: { action in
                        viewModel.handlePaletteAction(action)
                    }
                )
                .zIndex(20)
            }

            if viewModel.isGoToModalPresented {
                MachGoToAddressModalView(
                    isPresented: $viewModel.isGoToModalPresented,
                    cursorBus: cursorBus,
                    image: viewModel.loadedImage,
                    functions: viewModel.functions,
                    customRenames: viewModel.customRenames
                )
                .zIndex(21)
            }

            if xrefPopoverModel.isPresented {
                ZStack {
                    Color.black.opacity(0.50)
                        .ignoresSafeArea()
                        .onTapGesture {
                            xrefPopoverModel.isPresented = false
                        }

                    MachXrefQuickJumpPopoverView(
                        model: xrefPopoverModel,
                        cursorBus: cursorBus,
                        image: viewModel.loadedImage,
                        functions: viewModel.functions
                    )
                }
                .zIndex(22)
            }

            if viewModel.isRenameModalPresented {
                symbolRenameOverlayModal
                    .zIndex(23)
            }

            if viewModel.isCommentModalPresented {
                inlineCommentOverlayModal
                    .zIndex(24)
            }

            if viewModel.isPreferencesPresented {
                ZStack {
                    Color.black.opacity(0.54)
                        .ignoresSafeArea()
                        .onTapGesture {
                            viewModel.isPreferencesPresented = false
                        }

                    MachPreferencesWindowView(
                        store: viewModel.preferencesStore,
                        onClose: {
                            viewModel.isPreferencesPresented = false
                        }
                    )
                    .frame(width: 720, height: 540)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
                }
                .zIndex(25)
            }

            if viewModel.isShortcutsSheetPresented {
                ZStack {
                    Color.black.opacity(0.54)
                        .ignoresSafeArea()
                        .onTapGesture {
                            viewModel.isShortcutsSheetPresented = false
                        }

                    MachKeyboardShortcutsCheatsheetView(
                        onClose: {
                            viewModel.isShortcutsSheetPresented = false
                        }
                    )
                    .frame(width: 680, height: 500)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
                }
                .zIndex(26)
            }

            // 6. Non-Modal Toast Banner Stack (Top-Right)
            VStack {
                HStack {
                    Spacer()
                    MachToastBannerOverlayView(
                        queue: toastController,
                        onJumpToAddress: { addr in
                            cursorBus.jump(
                                toAddress: addr,
                                in: viewModel.loadedImage,
                                functions: viewModel.functions
                            )
                        }
                    )
                    .padding(.top, 78)
                    .padding(.trailing, 14)
                }
                Spacer()
            }
            .allowsHitTesting(!toastController.activeToasts.isEmpty)
            .zIndex(30)
        }
        .preferredColorScheme(.dark)
        .fileImporter(
            isPresented: $viewModel.isFileImporterPresented,
            allowedContentTypes: [.item, .data, .unixExecutable, .executable],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let firstURL = urls.first {
                let accessed = firstURL.startAccessingSecurityScopedResource()
                defer {
                    if accessed { firstURL.stopAccessingSecurityScopedResource() }
                }
                viewModel.loadBinaryFromDisk(url: firstURL, emitToast: true)
            }
        }
    }

    // MARK: - Adaptive Top Workbench Toolbar & Studio Workspace Tab Strip

    private var resolvedToolbarFunctionLabel: String? {
        let va = cursorBus.currentLocation.virtualAddress
        if let fn = viewModel.functions.first(where: { va >= $0.address && va < $0.endAddress }) {
            let name = viewModel.customRenames.first(where: { $0.address == fn.address })?.customName ?? fn.demangledName
            let delta = va.rawValue - fn.address.rawValue
            return delta == 0 ? name : "\(name)+0x\(String(delta, radix: 16))"
        }
        return viewModel.loadedImage?.exactSymbol(at: va)?.demangledName
    }

    private var adaptiveTopWorkbenchToolbar: some View {
        GeometryReader { geo in
            if geo.size.width >= 1540 {
                MachTopWorkbenchToolbarView(
                    cursorBus: cursorBus,
                    image: viewModel.loadedImage,
                    functions: viewModel.functions,
                    customRenames: viewModel.customRenames,
                    onOpenBinary: nil,
                    onSelectSlice: { sliceIdx in
                        viewModel.selectUniversalSlice(index: sliceIdx)
                    },
                    onOpenGoToModal: {
                        viewModel.isGoToModalPresented = true
                    },
                    onOpenCommandPalette: {
                        paletteController.openPalette()
                    },
                    onRunSecurityAudit: {
                        viewModel.runSecurityAuditSuite(emitToast: true)
                        cursorBus.disableSplitView()
                        cursorBus.activePane = .pluginFindings
                    },
                    onCaptureSnapshot: {
                        viewModel.captureSnapshotCheckpoint()
                    },
                    onReSignMachO: {
                        viewModel.reSignActiveMachOBinary()
                    }
                )
            } else {
                compactTopWorkbenchToolbar
            }
        }
        .frame(height: ColdTungstenMetrics.topToolbarHeight)
    }

    private var compactTopWorkbenchToolbar: some View {
        HStack(spacing: 6) {
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
            .fixedSize(horizontal: true, vertical: false)

            if let image = viewModel.loadedImage {
                FormatArchBadge(image: image)
                    .fixedSize(horizontal: true, vertical: false)

                if image.slices.count > 1 {
                    Menu {
                        ForEach(image.slices) { slice in
                            Button("Slice #\(slice.index): \(slice.architecture.displayName) (\(slice.fileOffset.hexString))") {
                                viewModel.selectUniversalSlice(index: slice.index)
                            }
                        }
                    } label: {
                        Label("Slice #\(image.selectedSliceIndex)", systemImage: "square.stack.3d.up")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, compact: true))
                    .fixedSize(horizontal: true, vertical: false)
                }
            }

            compactBreadcrumbBarButton

            Spacer(minLength: 6)

            Button {
                cursorBus.toggleSplitView(defaultSecondary: .pseudoC)
            } label: {
                Label(
                    cursorBus.isSplitViewActive ? "Split: Active" : "Split View",
                    systemImage: "rectangle.split.2x1"
                )
            }
            .buttonStyle(TungstenToolbarButtonStyle(
                role: cursorBus.isSplitViewActive ? .accentSapphire : .standard,
                isActive: cursorBus.isSplitViewActive,
                compact: true
            ))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                paletteController.openPalette()
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "command")
                    Text("Palette")
                    TungstenKeycapBadge("⌘K")
                }
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.runSecurityAuditSuite(emitToast: true)
                cursorBus.disableSplitView()
                cursorBus.activePane = .pluginFindings
            } label: {
                Label("Audit", systemImage: "checkmark.shield")
            }
            .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, compact: true))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.captureSnapshotCheckpoint()
            } label: {
                Label("Snapshot", systemImage: "camera.aperture")
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.reSignActiveMachOBinary()
            } label: {
                Label("Re-Sign", systemImage: "signature")
            }
            .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, compact: true))
            .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity)
        .frame(height: ColdTungstenMetrics.topToolbarHeight)
        .background(ColdTungstenPalette.brushedSteel)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    private var compactBreadcrumbBarButton: some View {
        let va = cursorBus.currentLocation.virtualAddress
        let secShort = viewModel.loadedImage?.section(containing: va)?.sectionName

        return Button {
            viewModel.isGoToModalPresented = true
        } label: {
            HStack(spacing: 5) {
                Text(viewModel.loadedImage?.fileName ?? "No Binary")
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)

                if let secShort {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 8.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(secShort)
                        .font(ColdTungstenTypography.offsetGutterMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                }

                if let fnLabel = resolvedToolbarFunctionLabel {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 8.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(fnLabel)
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.5, weight: .medium))
                        .foregroundStyle(ColdTungstenPalette.signalEmerald)
                }

                Image(systemName: "chevron.right")
                    .font(.system(size: 8.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                Text(va.compactHexString)
                    .font(ColdTungstenTypography.addressMono(size: 12.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                TungstenKeycapBadge("G")
            }
            .padding(.horizontal, 8)
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

    private var studioWorkspaceTabStrip: some View {
        HStack(spacing: 4) {
            ForEach(WorkbenchPaneTab.allCases) { tab in
                workspaceTabButton(tab)
            }

            Spacer(minLength: 4)

            Button {
                viewModel.isFileImporterPresented = true
            } label: {
                Label("Open", systemImage: "folder")
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            // Built-in Multi-Format Binary Target Switcher
            Menu {
                ForEach(MachDemoFixturePreset.allCases) { preset in
                    Button(preset.rawValue) {
                        viewModel.loadPreset(preset, seedDemoState: preset == .arm64eMachO, emitToast: true)
                    }
                }
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: "cpu.fill")
                        .font(.system(size: 10, weight: .semibold))
                    Text("Target: \(shortPresetLabel(viewModel.activeFixturePreset))")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                    Image(systemName: "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                }
                .foregroundStyle(ColdTungstenPalette.signalEmerald)
                .padding(.horizontal, 7)
                .padding(.vertical, 4)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )
                .fixedSize(horizontal: true, vertical: false)
            }
            .menuStyle(.borderlessButton)
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.presentXrefsPopoverAtCursor()
            } label: {
                HStack(spacing: 4) {
                    Text("Xrefs")
                    TungstenKeycapBadge("X")
                }
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.presentRenameModalForCursor()
            } label: {
                HStack(spacing: 4) {
                    Text("Rename")
                    TungstenKeycapBadge("N")
                }
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            if !cursorBus.isSplitViewActive && (cursorBus.activePane == .cfgGraph || cursorBus.activePane == .disassembly) {
                Button {
                    viewModel.showRightContextualInspector.toggle()
                } label: {
                    Label("Inspector", systemImage: "sidebar.right")
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: viewModel.showRightContextualInspector ? .accentSapphire : .standard,
                    isActive: viewModel.showRightContextualInspector,
                    compact: true
                ))
                .fixedSize(horizontal: true, vertical: false)
            }

            Button {
                viewModel.isShortcutsSheetPresented = true
            } label: {
                Image(systemName: "keyboard")
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)

            Button {
                viewModel.isPreferencesPresented = true
            } label: {
                Image(systemName: "gearshape")
            }
            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity)
        .frame(height: 32)
        .background(ColdTungstenPalette.chassisBackground)
    }

    private func workspaceTabButton(_ tab: WorkbenchPaneTab) -> some View {
        let isActive = cursorBus.isSplitViewActive
            ? (tab == cursorBus.activePane || tab == cursorBus.secondarySplitPane)
            : (cursorBus.activePane == tab)

        return Button {
            cursorBus.disableSplitView()
            cursorBus.activePane = tab
        } label: {
            HStack(spacing: 4) {
                Image(systemName: tab.sfSymbolName)
                    .font(.system(size: 10.5, weight: .semibold))
                Text(compactTabLabel(tab))
                    .font(ColdTungstenTypography.controlLabel)
            }
            .foregroundStyle(isActive ? ColdTungstenPalette.steelWhite : ColdTungstenPalette.coolPewter)
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(isActive ? ColdTungstenPalette.activeSelectionFill : ColdTungstenPalette.gunmetalSlate)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(
                        isActive ? ColdTungstenPalette.tungstenSapphire.opacity(0.80) : ColdTungstenPalette.tungstenSeam,
                        lineWidth: ColdTungstenMetrics.borderHairline
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
            .fixedSize(horizontal: true, vertical: false)
        }
        .buttonStyle(.plain)
    }

    private func compactTabLabel(_ tab: WorkbenchPaneTab) -> String {
        switch tab {
        case .cfgGraph: return "CFG Graph"
        case .disassembly: return "Disassembly"
        case .pseudoC: return "Pseudo-C"
        case .hexPatcher: return "Hex & Patch"
        case .stringsAndObjC: return "Strings & ObjC"
        case .entropyAndSign: return "Entropy & Sign"
        case .pluginFindings: return "Plugin Audit"
        }
    }

    private func shortPresetLabel(_ preset: MachDemoFixturePreset) -> String {
        switch preset {
        case .arm64eMachO: return "arm64e"
        case .universalFat: return "Fat"
        case .elf64AArch64: return "ELF64"
        case .pe32PlusARM64: return "PE32+"
        case .wasmModule: return "WASM"
        }
    }

    // MARK: - Active Center Studio Dispatcher

    @ViewBuilder
    private var activeCenterStudioContent: some View {
        if cursorBus.isSplitViewActive {
            SynchronizedDecompilerSplitStudioView(
                viewModel: viewModel,
                leftPaneMode: cursorBus.activePane == .cfgGraph ? .cfgGraph : .disassembly
            )
        } else {
            switch cursorBus.activePane {
            case .cfgGraph:
                InteractiveCFGCanvasStudioView(viewModel: viewModel, compactForSplit: false)
            case .disassembly:
                LinearDisassemblyStudioView(viewModel: viewModel, compactForSplit: false)
            case .pseudoC:
                PseudoCDecompilerStudioView(viewModel: viewModel, compactForSplit: false)
            case .hexPatcher:
                SparseCoWHexAndInlinePatcherStudioView(viewModel: viewModel)
            case .stringsAndObjC:
                StringsAndRuntimeMetadataStudioView(viewModel: viewModel)
            case .entropyAndSign:
                EntropyAndCodeSignStudioView(viewModel: viewModel)
            case .pluginFindings:
                PluginSecurityAuditStudioView(viewModel: viewModel)
            }
        }
    }

    // MARK: - Bottom Engineering Telemetry Status Bar

    private var engineeringTelemetryStatusBar: some View {
        let img = viewModel.loadedImage
        let insnCount = viewModel.analysisIndex?.decodedInstructions.count ?? 0
        let dirtyBytes = viewModel.overlayBuffer.modifiedByteCount
        let shaPrefix = String((img?.sha256Hex ?? "").prefix(16))

        return HStack(spacing: 12) {
            HStack(spacing: 5) {
                Circle()
                    .fill(ColdTungstenPalette.signalEmerald)
                    .frame(width: 6, height: 6)
                Text(".machproj WAL Ready")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
            }
            .fixedSize(horizontal: true, vertical: false)

            Text("SHA-256 \(shaPrefix)")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                .fixedSize(horizontal: true, vertical: false)

            Text("\(viewModel.functions.count) funcs · \(insnCount) insns · \(viewModel.xrefCount) xrefs")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: true, vertical: false)

            if dirtyBytes > 0 {
                Text("CoW Overlay: \(dirtyBytes) B modified")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.warmCopper)
                    .fixedSize(horizontal: true, vertical: false)
            }

            Spacer(minLength: 8)

            Text("Undo \(viewModel.undoStackRecords.count) · Redo \(viewModel.redoStackRecords.count) · Snapshots \(viewModel.checkpoints.count)")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: true, vertical: false)

            Text("Zero-Wrapper Pure Swift Engine")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 12)
        .frame(height: 23)
        .background(ColdTungstenPalette.brushedSteel)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    // MARK: - Inline Analyst Rename (`N`) & Comment (`;`) Modals

    private var symbolRenameOverlayModal: some View {
        ZStack {
            Color.black.opacity(0.52)
                .ignoresSafeArea()
                .onTapGesture { viewModel.isRenameModalPresented = false }

            VStack(alignment: .leading, spacing: 0) {
                TungstenPanelHeaderBar(title: "Rename Function / Symbol", sfSymbol: "character.cursor.ibeam") {
                    TungstenKeycapBadge("N")
                }

                VStack(alignment: .leading, spacing: 10) {
                    Text("Address: \(viewModel.pendingRenameAddress.hexString) (Original: \(viewModel.pendingRenameOriginal))")
                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)

                    TextField("Custom identifier name...", text: $viewModel.pendingRenameInput)
                        .textFieldStyle(.plain)
                        .font(ColdTungstenTypography.disassemblyMono(size: 12.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .padding(8)
                        .background(ColdTungstenPalette.chassisBackground)
                        .overlay(
                            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                                .strokeBorder(ColdTungstenPalette.tungstenSapphire, lineWidth: ColdTungstenMetrics.borderHairline)
                        )
                        .onSubmit {
                            viewModel.commitPendingRename()
                        }

                    TextField("Optional C prototype override (e.g. bool verify_license(uint64_t token))", text: $viewModel.pendingRenameSignature)
                        .textFieldStyle(.plain)
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .padding(8)
                        .background(ColdTungstenPalette.chassisBackground)
                        .overlay(
                            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                        )

                    HStack {
                        Spacer()
                        Button("Cancel") { viewModel.isRenameModalPresented = false }
                            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        Button("Save Rename") { viewModel.commitPendingRename() }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, isActive: true, compact: true))
                    }
                }
                .padding(14)
                .background(ColdTungstenPalette.gunmetalSlate)
            }
            .frame(width: 500)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
        }
    }

    private var inlineCommentOverlayModal: some View {
        ZStack {
            Color.black.opacity(0.52)
                .ignoresSafeArea()
                .onTapGesture { viewModel.isCommentModalPresented = false }

            VStack(alignment: .leading, spacing: 0) {
                TungstenPanelHeaderBar(title: "Inline Disassembly & Pseudo-C Comment", sfSymbol: "text.bubble") {
                    TungstenKeycapBadge(";")
                }

                VStack(alignment: .leading, spacing: 10) {
                    Text("Instruction Address: \(viewModel.pendingCommentAddress.hexString)")
                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)

                    TextField("Analyst annotation...", text: $viewModel.pendingCommentInput)
                        .textFieldStyle(.plain)
                        .font(ColdTungstenTypography.disassemblyMono(size: 12.0))
                        .foregroundStyle(ColdTungstenPalette.signalEmerald)
                        .padding(8)
                        .background(ColdTungstenPalette.chassisBackground)
                        .overlay(
                            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                                .strokeBorder(ColdTungstenPalette.tungstenSapphire, lineWidth: ColdTungstenMetrics.borderHairline)
                        )
                        .onSubmit {
                            viewModel.commitPendingComment()
                        }

                    Toggle("Repeatable comment across incoming Xrefs", isOn: $viewModel.pendingCommentRepeatable)
                        .toggleStyle(.checkbox)
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)

                    HStack {
                        Spacer()
                        Button("Cancel") { viewModel.isCommentModalPresented = false }
                            .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        Button("Save Comment") { viewModel.commitPendingComment() }
                            .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, isActive: true, compact: true))
                    }
                }
                .padding(14)
                .background(ColdTungstenPalette.gunmetalSlate)
            }
            .frame(width: 480)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
        }
    }
}

// MARK: - 2x Retina Offscreen Screenshot & Triage HTML Exporter (`2720 × 1680 px`)

@MainActor
public enum MachRetinaScreenshotExporter {
    public static let pointWidth: CGFloat = 1360
    public static let pointHeight: CGFloat = 840
    public static let retinaScale: Int = 2

    public struct ExportSummary: Sendable {
        public let screenshotPaths: [String]
        public let htmlReportPath: String
    }

    @discardableResult
    public static func exportAllAssets(to outputDirectoryURL: URL) throws -> ExportSummary {
        try FileManager.default.createDirectory(
            at: outputDirectoryURL,
            withIntermediateDirectories: true
        )

        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        app.appearance = NSAppearance(named: .darkAqua)

        let viewModel = MachStudioViewModel(initialBinaryURL: nil, emitStartupToast: false)

        let windowRect = NSRect(x: -12_000, y: -12_000, width: pointWidth, height: pointHeight)
        let window = NSWindow(
            contentRect: windowRect,
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: .darkAqua)
        window.backgroundColor = NSColor(red: 15.0 / 255.0, green: 18.0 / 255.0, blue: 22.0 / 255.0, alpha: 1.0)
        window.hasShadow = false

        let rootView = MachWorkbenchRootView(viewModel: viewModel)
            .frame(width: pointWidth, height: pointHeight)
            .environment(\.colorScheme, .dark)
            .environment(\.displayScale, CGFloat(retinaScale))

        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: pointWidth, height: pointHeight)
        hostingView.appearance = NSAppearance(named: .darkAqua)
        window.contentView = hostingView
        window.orderBack(nil)

        let scenes: [(fileName: String, configure: () -> Void)] = [
            ("screenshot-cfg-canvas.png", { viewModel.configureForCFGCanvasScreenshot() }),
            ("screenshot-decompiler-split.png", { viewModel.configureForDecompilerSplitScreenshot() }),
            ("screenshot-hex-patcher.png", { viewModel.configureForHexPatcherScreenshot() }),
            ("screenshot-entropy-audit.png", { viewModel.configureForEntropyAuditScreenshot() })
        ]

        var writtenPaths: [String] = []
        for scene in scenes {
            scene.configure()
            settleLayoutAndRenderPass(window: window, hostingView: hostingView)
            let destURL = outputDirectoryURL.appendingPathComponent(scene.fileName)
            try capture2xRetinaPNG(from: hostingView, to: destURL)
            writtenPaths.append(destURL.path)
        }

        window.orderOut(nil)
        window.close()

        // Export standalone offline Cold Tungsten HTML Triage Report (`demo-mach-triage.html`)
        guard let index = viewModel.analysisIndex else {
            throw MachGraphError.ioFailure("BinaryAnalysisIndex unavailable during HTML export")
        }
        let orderedDecompiled = index.functions.compactMap { viewModel.decompiledByFunction[$0.address] }
        let rawHTML = try ColdTungstenHTMLReportExporter().exportHTMLReport(
            analysisIndex: index,
            binaryData: viewModel.overlayBuffer.materializedData(),
            decompiledFunctions: orderedDecompiled,
            auditFindings: viewModel.securityFindings
        )
        let htmlString = normalizeColdTungstenHTMLForHallmark(rawHTML)
        let htmlURL = outputDirectoryURL.appendingPathComponent("demo-mach-triage.html")
        try htmlString.write(to: htmlURL, atomically: true, encoding: .utf8)

        return ExportSummary(
            screenshotPaths: writtenPaths,
            htmlReportPath: htmlURL.path
        )
    }

    private static func normalizeColdTungstenHTMLForHallmark(_ raw: String) -> String {
        var html = raw

        // 1. Replace <style>...</style> with Hallmark-clean Cold Tungsten token & 4px grid stylesheet
        if let styleStart = html.range(of: "<style>"),
           let styleEnd = html.range(of: "</style>") {
            let cleanStyle = """
            <style>
              /* Hallmark · v2.0.0 · scope: app · genre: industrial-telemetry · posture: precision · shape: app screen · surface: dark-absolute */
              :root {
                --bg-chassis: #0F1216;
                --bg-panel: #141920;
                --bg-elevated: #1B222C;
                --bg-code: #0B0E12;
                --border-seam: #2A3442;
                --ink-primary: #E6EDF3;
                --ink-secondary: #8B949E;
                --ink-muted: #656D76;
                --accent-sapphire: #58A6FF;
                --status-info-bg: #13233A;
                --status-ok-fg: #3FB950;
                --status-ok-bg: #12261E;
                --status-warn-fg: #D29922;
                --status-warn-bg: #2B2111;
                --status-crit-fg: #F85149;
                --status-crit-bg: #2D1619;
                --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
                --font-mono: ui-monospace, "SF Mono", Menlo, monospace;
              }
              *, *::before, *::after { box-sizing: border-box; }
              html, body {
                overflow-x: clip;
              }
              body {
                margin: 0;
                padding: 32px 24px 56px;
                background: var(--bg-chassis);
                color: var(--ink-primary);
                font-family: var(--font-sans);
                line-height: 1.5;
                font-size: 14px;
              }
              .container {
                max-width: 1180px;
                margin: 0 auto;
              }
              header.masthead {
                background: var(--bg-panel);
                color: var(--ink-primary);
                border: 1px solid var(--border-seam);
                border-top: 4px solid var(--accent-sapphire);
                border-radius: 6px;
                padding: 24px;
                margin-bottom: 16px;
              }
              .eyebrow {
                font-size: 12px;
                font-weight: 600;
                color: var(--accent-sapphire);
                margin: 0 0 8px;
              }
              h1, h2, h3 {
                text-wrap: balance;
                color: var(--ink-primary);
                margin: 0;
              }
              h1 {
                font-size: 24px;
                line-height: 1.25;
                margin-bottom: 8px;
              }
              h2 {
                font-size: 16px;
                line-height: 1.3;
                margin-bottom: 12px;
              }
              .subtitle {
                display: flex;
                flex-wrap: wrap;
                gap: 8px 16px;
                margin: 0;
                color: var(--ink-secondary);
                font-size: 13px;
              }
              .kpi-strip {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(176px, 1fr));
                gap: 12px;
                margin-bottom: 16px;
              }
              .kpi-card {
                background: var(--bg-panel);
                color: var(--ink-primary);
                border: 1px solid var(--border-seam);
                border-radius: 6px;
                padding: 16px;
              }
              .kpi-label {
                font-size: 12px;
                font-weight: 500;
                color: var(--ink-secondary);
              }
              .kpi-value {
                font-family: var(--font-mono);
                font-variant-numeric: tabular-nums;
                font-size: 20px;
                font-weight: 700;
                margin-top: 4px;
                color: var(--ink-primary);
              }
              section.panel {
                background: var(--bg-panel);
                color: var(--ink-primary);
                border: 1px solid var(--border-seam);
                border-radius: 6px;
                padding: 20px 24px;
                margin-bottom: 16px;
              }
              table {
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
              }
              th, td {
                text-align: left;
                padding: 8px 12px;
                border-bottom: 1px solid var(--border-seam);
                vertical-align: top;
              }
              th {
                font-size: 12px;
                font-weight: 600;
                color: var(--ink-secondary);
                background: var(--bg-elevated);
              }
              .mono {
                font-family: var(--font-mono);
                font-variant-numeric: tabular-nums;
                font-size: 13px;
              }
              .num { text-align: right; }
              .muted { color: var(--ink-secondary); }
              .pill {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
                font-family: var(--font-mono);
              }
              .pill-ok { background: var(--status-ok-bg); color: var(--status-ok-fg); }
              .pill-warn { background: var(--status-warn-bg); color: var(--status-warn-fg); }
              .pill-crit { background: var(--status-crit-bg); color: var(--status-crit-fg); }
              .pill-info { background: var(--status-info-bg); color: var(--accent-sapphire); }
              .pill-neutral { background: var(--bg-elevated); color: var(--ink-secondary); }
              .code-card {
                border: 1px solid var(--border-seam);
                border-radius: 6px;
                margin-bottom: 12px;
                overflow: hidden;
              }
              .code-header {
                display: flex;
                justify-content: space-between;
                gap: 12px;
                padding: 8px 12px;
                background: var(--bg-elevated);
                color: var(--ink-primary);
                border-bottom: 1px solid var(--border-seam);
                font-size: 13px;
              }
              pre {
                margin: 0;
                padding: 12px 16px;
                background: var(--bg-code);
                color: var(--ink-primary);
                overflow-x: auto;
                font-family: var(--font-mono);
                font-size: 12px;
                line-height: 1.5;
              }
            </style>
            """
            html.replaceSubrange(styleStart.lowerBound..<styleEnd.upperBound, with: cleanStyle)
        }

        // 2. Replace multi-middle-dot meta chains & sentence-case small badges/identifiers
        html = html.replacingOccurrences(of: " · Entry:", with: "</span><span>Entry:")
        html = html.replacingOccurrences(of: " · CDHash:", with: "</span><span>CDHash:")
        html = html.replacingOccurrences(
            of: "<p class=\"subtitle\">SHA-256:",
            with: "<p class=\"subtitle\"><span>SHA-256:"
        )
        html = html.replacingOccurrences(
            of: "</span></p>\n    </header>",
            with: "</span></span></p>\n    </header>"
        )

        let labelReplacements: [(String, String)] = [
            (">ARM64E-PAC<", ">arm64e-pac<"),
            (">STD-A64<", ">std-a64<"),
            (">CRITICAL<", ">Critical<"),
            (">HIGH<", ">High<"),
            (">MEDIUM<", ">Medium<"),
            (">LOW<", ">Low<"),
            (">INFO<", ">Info<"),
            (">__PAGEZERO<", ">Segment pagezero<"),
            (">__TEXT<", ">Segment text<"),
            (">__DATA_CONST<", ">Segment data_const<"),
            (">__DATA<", ">Segment data<"),
            (">__LINKEDIT<", ">Segment linkedit<"),
            ("...", "")
        ]
        for (oldStr, newStr) in labelReplacements {
            html = html.replacingOccurrences(of: oldStr, with: newStr)
        }

        return html + "\n"
    }

    private static func settleLayoutAndRenderPass(window: NSWindow, hostingView: NSHostingView<some View>) {
        for _ in 0..<4 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.06))
            hostingView.needsLayout = true
            hostingView.layoutSubtreeIfNeeded()
            window.displayIfNeeded()
            hostingView.displayIfNeeded()
        }
    }

    private static func capture2xRetinaPNG(from hostingView: NSHostingView<some View>, to url: URL) throws {
        let pixelsWide = Int(pointWidth) * retinaScale
        let pixelsHigh = Int(pointHeight) * retinaScale

        guard let bitmapRep = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: pixelsWide,
            pixelsHigh: pixelsHigh,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: pixelsWide * 4,
            bitsPerPixel: 32
        ) else {
            throw MachGraphError.ioFailure("Unable to allocate \(pixelsWide)x\(pixelsHigh) NSBitmapImageRep")
        }

        bitmapRep.size = NSSize(width: pointWidth, height: pointHeight)
        let bounds = NSRect(x: 0, y: 0, width: pointWidth, height: pointHeight)
        hostingView.cacheDisplay(in: bounds, to: bitmapRep)

        guard let pngData = bitmapRep.representation(using: .png, properties: [:]) else {
            throw MachGraphError.ioFailure("Failed to encode PNG data for \(url.lastPathComponent)")
        }
        try pngData.write(to: url, options: .atomic)
    }
}
