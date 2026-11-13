import AppKit
import Combine
import Foundation
import MachA64Decoder
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

// MARK: - Search Modes & Metadata Sub-Tabs

public enum HexStudioSearchMode: String, CaseIterable, Identifiable, Sendable {
    case wildcardHex = "Hex Wildcard"
    case asciiString = "ASCII / UTF-8"
    case utf16String = "UTF-16LE"
    case pointer64 = "64-Bit Pointer"

    public var id: String { rawValue }

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .wildcardHex:
            return language.select("Hex Wildcard", "十六进制通配")
        case .asciiString:
            return "ASCII / UTF-8"
        case .utf16String:
            return "UTF-16LE"
        case .pointer64:
            return language.select("64-Bit Pointer", "64位指针")
        }
    }

    public func localizedPlaceholder(in language: MachLanguage) -> String {
        switch self {
        case .wildcardHex:
            return language.select("Wildcard hex (e.g. 7F 23 03 D5 or ?? 03 5F D6)...", "十六进制通配搜索 (如 7F 23 03 D5 或 ?? 03 5F D6)...")
        case .asciiString:
            return language.select("Search ASCII / UTF-8 bytes...", "搜索 ASCII / UTF-8 字符串...")
        case .utf16String:
            return language.select("Search UTF-16LE wide string...", "搜索 UTF-16LE 宽字符串...")
        case .pointer64:
            return language.select("64-bit target address (e.g. 0x100001038)...", "输入 64 位目标地址 (如 0x100001038)...")
        }
    }
}

public enum RuntimeMetadataSubTab: String, CaseIterable, Identifiable, Sendable {
    case cStrings = "Cross-Referenced Strings"
    case objcAndSwift = "ObjC 2.0 & Swift 5 Types"
    case chainedFixups = "Dyld Chained Fixups (PAC)"

    public var id: String { rawValue }

    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .cStrings:
            return language.select("Cross-Referenced Strings", "交叉引用字符串")
        case .objcAndSwift:
            return language.select("ObjC 2.0 & Swift 5 Types", "ObjC 2.0 与 Swift 5 类型")
        case .chainedFixups:
            return language.select("Dyld Chained Fixups (PAC)", "Dyld 链式修复 (PAC)")
        }
    }
}

// MARK: - Master Studio Coordinator (`MachStudioViewModel`)

@MainActor
public final class MachStudioViewModel: ObservableObject {

    // MARK: Workbench Shell Controllers

    public let cursorBus: SynchronizedAddressCursorBus
    public let navigatorState: MachNavigatorSidebarState
    public let drawerState: MachBottomDrawerState
    public let paletteController: MachCommandPaletteController
    public let preferencesStore: MachWorkbenchPreferencesStore
    public let toastController: MachToastQueueController
    public let xrefPopoverModel: MachXrefQuickJumpModel

    // MARK: Persistent `.machproj` SQLite WAL Store & Journaling

    public private(set) var projectDB: MachProjectDatabase
    public private(set) var undoRedo: MachUndoRedoController
    public private(set) var snapshotManager: AnalysisSnapshotAndDiffManager

    // MARK: Core Binary & Static Analysis State

    @Published public private(set) var isDemoMode: Bool = false
    @Published public private(set) var baseBinaryData: Data = Data()
    @Published public private(set) var loadedImage: LoadedBinaryImage?
    @Published public private(set) var analysisIndex: BinaryAnalysisIndex?
    @Published public private(set) var cfgLayoutsByFunction: [VirtualAddress: SugiyamaCFGLayout] = [:]
    @Published public private(set) var decompiledByFunction: [VirtualAddress: DecompiledFunctionOutput] = [:]
    @Published public private(set) var idiomsByAddress: [VirtualAddress: A64RecognizedIdiom] = [:]

    // MARK: Sparse CoW Overlay, Inline Patching, Entropy & Code Signature State

    @Published public private(set) var overlayBuffer: SparseCoWByteOverlayBuffer
    @Published public private(set) var entropyReport: BinaryEntropyProfileReport?
    @Published public private(set) var codeSignatureReport: CodeSignatureVerificationReport?
    @Published public private(set) var baseSignatureReport: CodeSignatureVerificationReport?
    @Published public private(set) var lastReSignResult: MachOReSignResult?

    @Published public var patchTargetAddressText: String = ""
    @Published public var inlineAssemblyInput: String = ""
    @Published public var patchNoteInput: String = ""
    @Published public var allowBranchTargetClobber: Bool = false
    @Published public var padNOPToOriginalInstructionSpan: Bool = false
    @Published public private(set) var livePatchPreview: InlineARM64PatchPreview?
    @Published public private(set) var patchPreviewError: String?
    @Published public private(set) var lastExportedPatchSummary: String = ""
    @Published public private(set) var unifiedHexDiffPreview: String = ""

    @Published public var hexScrollOffset: FileOffset = FileOffset(0)
    @Published public var selectedHexByteOffset: FileOffset = FileOffset(0)
    @Published public var hexInspectorEndianness: BinaryEndianness = .little
    @Published public var selectedStructForHexEvalID: UUID?
    @Published public var hexSearchMode: HexStudioSearchMode = .wildcardHex
    @Published public var hexSearchQuery: String = ""
    @Published public private(set) var hexSearchHits: [BinarySearchHit] = []
    @Published public private(set) var hexSearchErrorMessage: String?

    // MARK: Analyst Annotations & `.machproj` Telemetry

    @Published public private(set) var customRenames: [UserSymbolRename] = []
    @Published public private(set) var inlineComments: [UserInlineComment] = []
    @Published public private(set) var bookmarks: [UserBookmark] = []
    @Published public private(set) var customStructs: [CustomStructDefinition] = []
    @Published public private(set) var undoStackRecords: [AnalystTransactionRecord] = []
    @Published public private(set) var redoStackRecords: [AnalystTransactionRecord] = []
    @Published public private(set) var checkpoints: [AnalysisCheckpointSummary] = []
    @Published public private(set) var projectStats: MachProjectStats?

    // MARK: JavaScriptCore Security Audit & Scratchpad State

    @Published public private(set) var pluginSuiteReport: MachPluginSuiteReport?
    @Published public private(set) var securityFindings: [SecurityAuditFinding] = []
    @Published public var selectedFindingSeverityFilter: SecurityFindingSeverity? = nil
    @Published public var selectedPluginInspectorID: String = BuiltInMachPluginCatalog.hardcodedSecretKeyScannerID
    @Published public var jsScratchpadSource: String = MachStudioViewModel.defaultScratchpadScript
    @Published public private(set) var lastScratchpadResult: MachPluginExecutionResult?
    @Published public private(set) var scratchpadStatusText: String = "JSVirtualMachine sandbox ready (4 built-in plugins verified)"

    // MARK: Decompiler & Ghidra 12.1.4 Side-by-Side State

    @Published public var isGhidraSideBySideEnabled: Bool = false
    @Published public private(set) var isRunningGhidraHeadless: Bool = false
    @Published public private(set) var ghidraProbe: GhidraHeadlessSideBySideBridge.InstallationProbe
    @Published public private(set) var ghidraDecompiledByFunction: [VirtualAddress: String] = [:]
    @Published public private(set) var ghidraStatusText: String = ""

    // MARK: Studio Sub-Tabs & Modal Presentation Flags

    @Published public var runtimeSubTab: RuntimeMetadataSubTab = .objcAndSwift
    @Published public var stringsFilterQuery: String = ""
    @Published public var stringsEncodingFilter: ExtractedStringEncoding? = nil
    @Published public var disassemblyFilterQuery: String = ""
    @Published public var showRightContextualInspector: Bool = true

    @Published public var isGoToModalPresented: Bool = false
    @Published public var isPreferencesPresented: Bool = false
    @Published public var isShortcutsSheetPresented: Bool = false
    @Published public var isFileImporterPresented: Bool = false
    @Published public var isRenameModalPresented: Bool = false
    @Published public var isCommentModalPresented: Bool = false
    @Published public var isStructBuilderModalPresented: Bool = false

    @Published public var pendingRenameAddress: VirtualAddress = .zero
    @Published public var pendingRenameOriginal: String = ""
    @Published public var pendingRenameInput: String = ""
    @Published public var pendingRenameSignature: String = ""

    @Published public var pendingCommentAddress: VirtualAddress = .zero
    @Published public var pendingCommentInput: String = ""
    @Published public var pendingCommentRepeatable: Bool = false

    private var cancellables: Set<AnyCancellable> = []

    // MARK: - Initialization

    public init(initialBinaryURL: URL? = nil, loadDemo: Bool = false, emitStartupToast: Bool = true) {
        self.overlayBuffer = try! SparseCoWByteOverlayBuffer(baseData: Data())

        let memDB = try! MachProjectDatabase.openInMemory(projectName: "Untitled")
        let undoCtrl = MachUndoRedoController(database: memDB)
        let snapMgr = AnalysisSnapshotAndDiffManager(database: memDB, undoRedoController: undoCtrl)

        self.projectDB = memDB
        self.undoRedo = undoCtrl
        self.snapshotManager = snapMgr

        let prefs = MachWorkbenchPreferencesStore()
        self.preferencesStore = prefs
        self.cursorBus = SynchronizedAddressCursorBus(
            initialLocation: SynchronizedCursorLocation(
                virtualAddress: .zero,
                fileOffset: FileOffset(0),
                functionAddress: nil,
                blockID: 0,
                originPane: .cfgGraph
            ),
            activePane: .cfgGraph
        )
        self.navigatorState = MachNavigatorSidebarState(
            selectedMode: .functions,
            filterQuery: "",
            functionSortOrder: .addressAscending
        )
        self.drawerState = MachBottomDrawerState(
            activeChannel: .xrefsAtCursor,
            isCollapsed: false,
            drawerHeight: 156.0
        )
        self.paletteController = MachCommandPaletteController(maxVisibleResults: 96)
        self.toastController = MachToastQueueController(maxVisibleToasts: 3)
        self.xrefPopoverModel = MachXrefQuickJumpModel()

        let bridge = GhidraHeadlessSideBySideBridge(
            ghidraInstallDirectory: prefs.preferences.ghidraInstallPath,
            javaHomeDirectory: prefs.preferences.javaHomePath
        )
        let probe = bridge.probeInstallation()
        self.ghidraProbe = probe
        let loc = MachLocalizer.shared
        self.scratchpadStatusText = loc.L(
            "JSVirtualMachine sandbox ready",
            "JSVirtualMachine 沙箱就绪"
        )
        self.ghidraStatusText = probe.isAvailable
            ? loc.L(
                "Ghidra \(probe.ghidraVersion ?? "12.1.4") + OpenJDK 21 detected",
                "已检测到 Ghidra \(probe.ghidraVersion ?? "12.1.4") + OpenJDK 21"
            )
            : loc.L(
                "Experimental Pseudo-C active (Ghidra not detected)",
                "实验性伪C反编译运行中 (未检测到 Ghidra)"
            )

        bindReactivePipelines()

        if let initialBinaryURL, FileManager.default.fileExists(atPath: initialBinaryURL.path) {
            loadBinaryFromDisk(url: initialBinaryURL, emitToast: emitStartupToast)
        } else if loadDemo {
            loadDemoBinary(emitToast: emitStartupToast)
        }
    }

    // MARK: - Reactive Cursor & Preferences Wiring

    private func bindReactivePipelines() {
        cursorBus.$currentLocation
            .receive(on: RunLoop.main)
            .sink { [weak self] location in
                guard let self else { return }
                if let off = location.fileOffset ?? self.loadedImage?.fileOffset(for: location.virtualAddress) {
                    self.selectedHexByteOffset = off
                    let alignedRow = FileOffset((off.rawValue / 16) * 16)
                    let currentStart = self.hexScrollOffset.rawValue
                    let visibleSpan: UInt64 = 18 * 16
                    if alignedRow.rawValue < currentStart || alignedRow.rawValue >= currentStart + visibleSpan {
                        let contextBack: UInt64 = 3 * 16
                        let targetScroll = alignedRow.rawValue >= contextBack ? (alignedRow.rawValue - contextBack) : 0
                        self.hexScrollOffset = FileOffset(targetScroll)
                    }
                }
            }
            .store(in: &cancellables)

        preferencesStore.$preferences
            .dropFirst()
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                guard let self else { return }
                self.recomputeCFGLayoutsAndDecompilation()
            }
            .store(in: &cancellables)

        MachLocalizer.shared.$language
            .dropFirst()
            .receive(on: RunLoop.main)
            .sink { [weak self] lang in
                guard let self else { return }
                self.paletteController.rebuildCatalog(
                    image: self.loadedImage,
                    functions: self.functions,
                    renames: self.customRenames,
                    bookmarks: self.bookmarks,
                    findings: self.securityFindings,
                    language: lang
                )
                if self.lastScratchpadResult == nil {
                    self.scratchpadStatusText = lang.select(
                        "JSVirtualMachine sandbox ready",
                        "JSVirtualMachine 沙箱就绪"
                    )
                }
                if !self.isRunningGhidraHeadless {
                    self.ghidraStatusText = self.ghidraProbe.isAvailable
                        ? lang.select(
                            "Ghidra \(self.ghidraProbe.ghidraVersion ?? "12.1.4") + OpenJDK 21 detected",
                            "已检测到 Ghidra \(self.ghidraProbe.ghidraVersion ?? "12.1.4") + OpenJDK 21"
                        )
                        : lang.select(
                            "Experimental Pseudo-C active (Ghidra not detected)",
                            "实验性伪C反编译运行中 (未检测到 Ghidra)"
                        )
                }
                self.recomputeCFGLayoutsAndDecompilation()
                self.recomputeLivePatchPreview()
            }
            .store(in: &cancellables)
    }

    // MARK: - Loading Binaries (Disk Files & Explicit Demo Sample)

    public func loadDemoBinary(emitToast: Bool = true) {
        do {
            let demoURL = try MachCLIRunner.locateDemoBinaryURL(language: MachLocalizer.shared.language)
            let data = try Data(contentsOf: demoURL, options: [.mappedIfSafe])
            try ingestBinaryData(
                data,
                filePath: demoURL.path,
                fileName: demoURL.lastPathComponent,
                preferredSliceIndex: nil,
                isDemo: true
            )
            if emitToast, let img = loadedImage {
                toastController.enqueue(
                    kind: .info,
                    title: MGL(
                        "[DEMO] Loaded \(img.fileName) (\(img.architecture.displayName))",
                        "[演示数据] 已加载 \(img.fileName) (\(img.architecture.displayName))"
                    ),
                    detail: MGL(
                        "Sample fixture binary · \(functions.count) functions, \(xrefCount) xrefs",
                        "演示样本二进制 · \(functions.count) 个函数，\(xrefCount) 条交叉引用"
                    ),
                    autoDismiss: true
                )
            }
        } catch {
            toastController.enqueue(
                kind: .error,
                title: MGL("Demo Binary Load Failed", "演示样本加载失败"),
                detail: error.localizedDescription
            )
        }
    }

    public func loadBinaryFromDisk(url: URL, preferredSliceIndex: Int? = nil, emitToast: Bool = true) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }
        do {
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            try ingestBinaryData(
                data,
                filePath: url.path,
                fileName: url.lastPathComponent,
                preferredSliceIndex: preferredSliceIndex,
                isDemo: false
            )
            if emitToast, let img = loadedImage {
                toastController.enqueue(
                    kind: .success,
                    title: MGL("Opened \(img.fileName)", "已打开 \(img.fileName)"),
                    detail: MGL(
                        "\(img.containerFormat.rawValue) · \(img.architecture.displayName) · \(functions.count) functions",
                        "\(img.containerFormat.rawValue) · \(img.architecture.displayName) · \(functions.count) 个函数"
                    ),
                    autoDismiss: true
                )
            }
        } catch {
            toastController.enqueue(
                kind: .error,
                title: MGL("Unable to Open Binary", "无法打开二进制文件"),
                detail: error.localizedDescription
            )
        }
    }

    public func selectUniversalSlice(index: Int) {
        guard !baseBinaryData.isEmpty, let current = loadedImage else { return }
        do {
            try ingestBinaryData(
                baseBinaryData,
                filePath: current.filePath,
                fileName: current.fileName,
                preferredSliceIndex: index,
                isDemo: isDemoMode
            )
            toastController.enqueue(
                kind: .info,
                title: MGL("Switched Universal Slice #\(index)", "已切换通用切片 #\(index)"),
                detail: loadedImage.map { "\($0.architecture.displayName) @ \($0.sliceFileOffset.hexString)" }
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Slice Switch Failed", "切片切换失败"), detail: error.localizedDescription)
        }
    }

    private func ingestBinaryData(
        _ data: Data,
        filePath: String,
        fileName: String,
        preferredSliceIndex: Int?,
        isDemo: Bool
    ) throws {
        let image = try UniversalBinaryDispatcher.load(
            data: data,
            filePath: filePath,
            fileName: fileName,
            preferredSliceIndex: preferredSliceIndex
        )
        BinaryAnalysisCoordinator.registerInMemoryBinaryData(data, sha256Hex: image.sha256Hex)

        let coordinator = BinaryAnalysisCoordinator()
        let index = try coordinator.analyzeBinary(image, data: data)

        let freshDB = try MachProjectDatabase.openInMemory(
            projectName: fileName,
            binaryImage: image
        )
        try freshDB.ingestFullBinaryAnalysis(
            image: image,
            functions: index.functions,
            xrefs: index.crossReferences.allRecords
        )
        let freshUndo = MachUndoRedoController(database: freshDB)
        let freshSnapshots = AnalysisSnapshotAndDiffManager(database: freshDB, undoRedoController: freshUndo)

        self.baseBinaryData = data
        self.isDemoMode = isDemo
        self.projectDB = freshDB
        self.undoRedo = freshUndo
        self.snapshotManager = freshSnapshots
        self.loadedImage = image
        self.analysisIndex = index
        self.overlayBuffer = try SparseCoWByteOverlayBuffer(baseData: data, image: image)
        self.lastReSignResult = nil
        self.ghidraDecompiledByFunction = [:]

        var idiomLookup: [VirtualAddress: A64RecognizedIdiom] = [:]
        for idiom in index.recognizedIdioms {
            idiomLookup[idiom.startAddress] = idiom
        }
        self.idiomsByAddress = idiomLookup

        cursorBus.attachProjectDatabase(freshDB, restoreSavedCursor: false)

        recomputeCFGLayoutsAndDecompilation()
        refreshOverlayDerivedTelemetry()
        runSecurityAuditSuite(emitToast: false)
        refreshDatabaseAnnotationsAndStats()

        let preferredFn = index.function(named: "_main")
            ?? index.functions.first(where: { !$0.isThunk && $0.blocks.count >= 2 })
            ?? index.functions.first

        if let preferredFn {
            cursorBus.selectFunction(preferredFn, in: image, originPane: cursorBus.activePane)
            patchTargetAddressText = preferredFn.address.compactHexString
            inlineAssemblyInput = preferredFn.usesPAC ? "paciasp; mov w0, #1; retaa" : "mov w0, #1; ret"
            if let fnOff = image.fileOffset(for: preferredFn.address) {
                selectedHexByteOffset = fnOff
                hexScrollOffset = FileOffset((fnOff.rawValue / 16) * 16)
            }
        } else if let entry = image.entryPoint {
            cursorBus.jump(toAddress: entry, in: image, functions: index.functions)
            patchTargetAddressText = entry.compactHexString
        }

        cursorBus.clearNavigationHistory()
        recomputeLivePatchPreview()
        executeHexSearch()
    }

    // MARK: - CFG Sugiyama Layout & SSA Pseudo-C Decompilation

    public func recomputeCFGLayoutsAndDecompilation() {
        guard let index = analysisIndex else { return }
        let prefs = preferencesStore.preferences

        let layoutConfig = SugiyamaLayoutConfiguration(
            minNodeWidth: 276.0,
            maxNodeWidth: 520.0,
            characterAdvanceWidth: 7.3,
            nodeHorizontalPadding: 24.0,
            headerBarHeight: 28.0,
            instructionLineHeight: 18.0,
            nodeVerticalPadding: 14.0,
            minNodeHeight: 56.0,
            horizontalNodeSpacing: prefs.cfgHorizontalNodeSpacing,
            baseVerticalLayerSpacing: prefs.cfgVerticalLayerSpacing,
            canvasMargin: 44.0,
            routingMode: prefs.orthogonalSugiyamaRouting ? .orthogonalChannel : .cubicBezierSpline
        )
        let solver = SugiyamaCFGLayoutSolver(configuration: layoutConfig)

        let liftConfig = MicroIRLiftingConfiguration.standard
        var ssaConfig = SSAOptimizationConfiguration.standard
        ssaConfig.enableDeadStoreElimination = prefs.enableDeadStoreElimination
        let decompiler = MachMicroDecompilerEngine(
            liftingConfiguration: liftConfig,
            optimizationConfiguration: ssaConfig
        )

        let renames = (try? projectDB.allRenames()) ?? customRenames
        let comments = (try? projectDB.allComments()) ?? inlineComments
        let structs = (try? projectDB.allStructs()) ?? customStructs
        let activeLang = MachLocalizer.shared.language

        var layouts: [VirtualAddress: SugiyamaCFGLayout] = [:]
        var decompiled: [VirtualAddress: DecompiledFunctionOutput] = [:]

        for fn in index.functions {
            layouts[fn.address] = solver.solveLayout(for: fn)
            if !fn.isThunk {
                let ghidraSrc = ghidraDecompiledByFunction[fn.address]
                let output = decompiler.decompile(
                    function: fn,
                    in: index,
                    symbolRenames: renames,
                    inlineComments: comments,
                    customStructs: structs,
                    ghidraSideBySideSource: ghidraSrc,
                    language: activeLang
                )
                decompiled[fn.address] = output
                try? projectDB.cacheDecompiledFunction(output)
            }
        }

        self.cfgLayoutsByFunction = layouts
        self.decompiledByFunction = decompiled
    }

    // MARK: - Overlay, Entropy, Code Signature & Inline Patching Actions

    public func refreshOverlayDerivedTelemetry() {
        guard let image = loadedImage else { return }
        let profiler = SlidingWindowEntropyProfiler(defaultWindowSize: 256, defaultStepSize: 128)
        let winSize = overlayBuffer.count <= 65_536 ? 256 : 1_024
        let stepSize = overlayBuffer.count <= 65_536 ? 128 : 512
        self.entropyReport = profiler.analyzeFullProfile(
            overlay: overlayBuffer,
            image: image,
            windowSize: winSize,
            stepSize: stepSize
        )

        let resigner = MachOAdHocReSigner()
        self.baseSignatureReport = try? resigner.verifyCodeSignature(
            in: overlayBuffer.baseData,
            sliceIndex: image.selectedSliceIndex
        )
        self.codeSignatureReport = try? resigner.verifyCodeSignature(
            in: overlayBuffer,
            sliceIndex: image.selectedSliceIndex
        )
        self.unifiedHexDiffPreview = IPSPatchCodec().generateUnifiedHexDiff(
            overlay: overlayBuffer,
            contextRows: 1,
            image: image
        )
    }

    public func recomputeLivePatchPreview() {
        let loc = MachLocalizer.shared
        guard let image = loadedImage else {
            livePatchPreview = nil
            patchPreviewError = loc.L("No binary image loaded.", "未加载二进制镜像。")
            return
        }
        let resolvedVA: VirtualAddress
        switch cursorBus.previewGoToQuery(
            patchTargetAddressText,
            image: image,
            functions: functions,
            customRenames: customRenames
        ) {
        case .success(let resolved):
            resolvedVA = resolved.virtualAddress
        case .failure(let err):
            livePatchPreview = nil
            patchPreviewError = err.localizedDescription(in: loc.language)
            return
        }

        guard let fileOff = image.fileOffset(for: resolvedVA) else {
            livePatchPreview = nil
            patchPreviewError = loc.L(
                "Address \(resolvedVA.compactHexString) has no file-backed segment offset.",
                "虚拟地址 \(resolvedVA.compactHexString) 无对应的文件映射偏移。"
            )
            return
        }

        let trimmedAsm = inlineAssemblyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedAsm.isEmpty else {
            livePatchPreview = nil
            patchPreviewError = loc.L(
                "Enter one or more semicolon-separated ARM64 instructions.",
                "请输入一条或多条以分号分隔的 ARM64 汇编指令。"
            )
            return
        }

        let safetyCtx = PatchSafetyContext(
            recoveredFunctions: functions,
            xrefs: analysisIndex?.crossReferences.allRecords ?? []
        )
        do {
            let cleanBaseOverlay = (try? SparseCoWByteOverlayBuffer(baseData: baseBinaryData)) ?? overlayBuffer
            let preview = try InlineARM64InstructionPatcher().previewPatch(
                at: fileOff,
                virtualAddress: resolvedVA,
                withAssembly: trimmedAsm,
                in: cleanBaseOverlay,
                image: image,
                safetyContext: safetyCtx,
                padToByteLength: padNOPToOriginalInstructionSpan ? 16 : nil
            )
            self.livePatchPreview = preview
            self.patchPreviewError = nil
        } catch {
            self.livePatchPreview = nil
            self.patchPreviewError = error.localizedDescription
        }
    }

    public func commitLiveInstructionPatch() {
        guard let image = loadedImage else { return }
        recomputeLivePatchPreview()
        guard let preview = livePatchPreview else {
            if let err = patchPreviewError {
                toastController.enqueue(kind: .error, title: MGL("Cannot Assemble Patch", "无法汇编补丁"), detail: err)
            }
            return
        }

        let safetyCtx = PatchSafetyContext(
            recoveredFunctions: functions,
            xrefs: analysisIndex?.crossReferences.allRecords ?? []
        )
        do {
            let record = try InlineARM64InstructionPatcher().applyInstructionPatch(
                at: preview.fileOffset,
                virtualAddress: preview.virtualAddress,
                withAssembly: inlineAssemblyInput,
                in: &overlayBuffer,
                image: image,
                safetyContext: safetyCtx,
                allowClobberingBranchTargets: allowBranchTargetClobber,
                padToByteLength: padNOPToOriginalInstructionSpan ? 16 : nil,
                note: patchNoteInput
            )
            try undoRedo.recordBytePatch(record)
            refreshOverlayDerivedTelemetry()
            refreshDatabaseAnnotationsAndStats()
            toastController.enqueue(
                kind: .success,
                title: MGL(
                    "Applied \(record.byteCount)-Byte CoW ARM64 Patch",
                    "已应用 \(record.byteCount) 字节 CoW ARM64 补丁"
                ),
                detail: "\(preview.virtualAddress.compactHexString): \(preview.patchedDisassemblyText)",
                addressLink: preview.virtualAddress
            )
        } catch {
            toastController.enqueue(
                kind: .warning,
                title: MGL("Patch Blocked by Safety Verifier", "安全校验器已拦截补丁"),
                detail: error.localizedDescription
            )
        }
    }

    public func applySingleInstructionNOPAtCursor() {
        guard let image = loadedImage else { return }
        let va = cursorBus.currentLocation.virtualAddress
        guard let off = image.fileOffset(for: va) else { return }
        do {
            let rec = try InlineARM64InstructionPatcher().applyInstructionPatch(
                at: off,
                virtualAddress: va,
                withAssembly: "nop",
                in: &overlayBuffer,
                image: image,
                allowClobberingBranchTargets: true,
                note: MGL("NOP instruction at \(va.compactHexString)", "在 \(va.compactHexString) 写入 NOP 指令")
            )
            try undoRedo.recordBytePatch(rec)
            refreshOverlayDerivedTelemetry()
            refreshDatabaseAnnotationsAndStats()
            recomputeLivePatchPreview()
            toastController.enqueue(kind: .info, title: MGL("Wrote ARM64 NOP", "已写入 ARM64 NOP"), detail: va.compactHexString)
        } catch {
            toastController.enqueue(kind: .error, title: MGL("NOP Patch Failed", "NOP 补丁写入失败"), detail: error.localizedDescription)
        }
    }

    public func togglePatchRecord(_ patch: BytePatchRecord) {
        do {
            let newState = try overlayBuffer.togglePatch(id: patch.id)
            try undoRedo.setBytePatchEnabled(id: patch.id, isEnabled: newState)
            refreshOverlayDerivedTelemetry()
            refreshDatabaseAnnotationsAndStats()
            recomputeLivePatchPreview()
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Patch Toggle Failed", "切换补丁状态失败"), detail: error.localizedDescription)
        }
    }

    public func removePatchRecord(_ patch: BytePatchRecord) {
        _ = overlayBuffer.removePatch(id: patch.id)
        try? undoRedo.removeBytePatch(id: patch.id)
        refreshOverlayDerivedTelemetry()
        refreshDatabaseAnnotationsAndStats()
        recomputeLivePatchPreview()
    }

    public func reSignActiveMachOBinary() {
        guard let image = loadedImage else { return }
        do {
            let result = try MachOAdHocReSigner().reSignOverlay(overlayBuffer, image: image)
            self.lastReSignResult = result
            self.codeSignatureReport = result.verificationReport
            toastController.enqueue(
                kind: .success,
                title: MGL("Mach-O Ad-Hoc SHA-256 Signature Rebuilt", "Mach-O 临时 SHA-256 代码签名已重建"),
                detail: MGL(
                    "CDHash \(result.updatedCDHashHex.prefix(24)) (\(result.recalculatedPageSlotIndices.count) page slots updated)",
                    "CDHash \(result.updatedCDHashHex.prefix(24)) (已重算 \(result.recalculatedPageSlotIndices.count) 个代码页槽位)"
                )
            )
        } catch {
            toastController.enqueue(
                kind: .error,
                title: MGL("Mach-O Re-Sign Error", "Mach-O 重签名失败"),
                detail: error.localizedDescription
            )
        }
    }

    public func exportPatchContainer(format: String) {
        let codec = IPSPatchCodec()
        let activePatches = overlayBuffer.coalescedMinimalPatches(in: loadedImage)
        switch format {
        case "IPS":
            let blob = codec.exportIPS(patches: activePatches)
            let hexHead = blob.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
            lastExportedPatchSummary = "IPS container: \(blob.count) bytes (\(activePatches.count) hunk) · [\(hexHead)]"
        case "IPS32":
            let blob = codec.exportIPS32(patches: activePatches)
            let hexHead = blob.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
            lastExportedPatchSummary = "IPS32 container: \(blob.count) bytes (\(activePatches.count) hunk) · [\(hexHead)]"
        default:
            let blob = codec.exportBPS(
                original: overlayBuffer.baseData,
                modified: overlayBuffer.materializedData(),
                metadataUTF8: "MachGraph CoW Patch"
            )
            let hexHead = blob.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
            lastExportedPatchSummary = "BPS CRC32 delta: \(blob.count) bytes · [\(hexHead)]"
        }
        toastController.enqueue(
            kind: .success,
            title: "Generated \(format) Patch Payload",
            detail: lastExportedPatchSummary
        )
    }

    public func executeHexSearch() {
        let query = hexSearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            hexSearchHits = []
            hexSearchErrorMessage = nil
            return
        }
        hexSearchErrorMessage = nil

        switch hexSearchMode {
        case .wildcardHex:
            do {
                hexSearchHits = try overlayBuffer.searchPattern(
                    query,
                    maxResults: 64,
                    image: loadedImage
                )
            } catch {
                hexSearchHits = []
                hexSearchErrorMessage = error.localizedDescription
            }
        case .asciiString:
            hexSearchHits = overlayBuffer.searchString(
                query,
                encoding: .ascii,
                caseInsensitive: true,
                maxResults: 64,
                image: loadedImage
            )
        case .utf16String:
            hexSearchHits = overlayBuffer.searchString(
                query,
                encoding: .utf16LE,
                caseInsensitive: true,
                maxResults: 64,
                image: loadedImage
            )
        case .pointer64:
            if let va = VirtualAddress(hexOrDecimal: query) {
                hexSearchHits = overlayBuffer.searchPointer64(
                    target: va,
                    maskPACHighBits: true,
                    maxResults: 64,
                    image: loadedImage
                )
            } else {
                hexSearchHits = []
                hexSearchErrorMessage = "Enter a 64-bit hex address (e.g. 0x100001038)."
            }
        }
    }

    // MARK: - JavaScriptCore Security Audit & Live Scratchpad Execution

    public func runSecurityAuditSuite(emitToast: Bool = true) {
        guard let index = analysisIndex else { return }
        do {
            let runner = preferencesStore.makePluginRunner()
            let suite = try runner.runSuite(
                against: index,
                binaryData: overlayBuffer.materializedData(),
                continueOnError: true
            )
            self.pluginSuiteReport = suite
            self.securityFindings = suite.findings

            try? projectDB.clearAllFindings()
            for res in suite.results {
                try? projectDB.replaceFindings(forPluginID: res.pluginID, findings: res.findings)
            }

            drawerState.clearConsole()
            drawerState.appendExecutionResults(suite.results)
            refreshDatabaseAnnotationsAndStats()

            if emitToast {
                toastController.enqueue(
                    kind: suite.findings.contains(where: { $0.severity >= .high }) ? .warning : .success,
                    title: MGL(
                        "Security Audit Completed (\(String(format: "%.1f ms", suite.totalDurationMilliseconds)))",
                        "安全审计完成 (\(String(format: "%.1f ms", suite.totalDurationMilliseconds)))"
                    ),
                    detail: MGL(
                        "\(suite.findings.count) findings across \(suite.results.count) JavaScriptCore plugins",
                        "\(suite.results.count) 个 JavaScriptCore 插件共检出 \(suite.findings.count) 项发现"
                    )
                )
            }
        } catch {
            toastController.enqueue(
                kind: .error,
                title: MGL("Plugin Sandbox Suite Error", "插件沙箱套件执行错误"),
                detail: error.localizedDescription
            )
        }
    }

    public func executeJSScratchpad() {
        guard let index = analysisIndex else { return }
        let manifest = MachPluginManifest(
            id: "com.machgraph.studio.scratchpad",
            name: "Analyst JS Scratchpad",
            version: "1.0.0",
            author: "Local Analyst",
            summary: "Interactive JavaScriptCore reverse-engineering query",
            capabilities: MachPluginCapability.allCases,
            isBuiltIn: false,
            isEnabled: true,
            scriptSource: jsScratchpadSource
        )
        let config = MachPluginSandboxConfiguration(
            executionTimeoutMilliseconds: preferencesStore.preferences.pluginTimeoutMilliseconds,
            enforceCapabilityGates: true
        )
        let sandbox = MachJavaScriptPluginSandbox(configuration: config)
        do {
            let result = try sandbox.execute(
                manifest: manifest,
                analysisIndex: index,
                binaryData: overlayBuffer.materializedData()
            )
            self.lastScratchpadResult = result
            self.scratchpadStatusText = String(
                format: "Executed in %.2f ms · %d log lines · %d findings emitted",
                result.durationMilliseconds,
                result.consoleLogs.count,
                result.findings.count
            )
            drawerState.appendExecutionResults([result])
            if !result.findings.isEmpty {
                var merged = securityFindings.filter { $0.pluginID != manifest.id }
                merged.append(contentsOf: result.findings)
                merged.sort { $0.severity > $1.severity }
                self.securityFindings = merged
            }
        } catch {
            self.scratchpadStatusText = "Sandbox error: \(error.localizedDescription)"
            toastController.enqueue(kind: .error, title: "JS Scratchpad Error", detail: error.localizedDescription)
        }
    }

    // MARK: - Optional Ghidra 12.1.4 Side-by-Side Decompiler Invocation

    public func toggleOrRunGhidraComparison() {
        isGhidraSideBySideEnabled.toggle()
        guard isGhidraSideBySideEnabled else { return }
        guard let fn = activeFunction else { return }
        if ghidraDecompiledByFunction[fn.address] != nil {
            return
        }

        let bridge = GhidraHeadlessSideBySideBridge(
            ghidraInstallDirectory: preferencesStore.preferences.ghidraInstallPath,
            javaHomeDirectory: preferencesStore.preferences.javaHomePath
        )
        let probe = bridge.probeInstallation()
        self.ghidraProbe = probe

        if !probe.isAvailable {
            isGhidraSideBySideEnabled = false
            let msg = MGL(
                "Ghidra headless is not installed or configured in Preferences.",
                "未在偏好设置中检测到可用的 Ghidra 无头环境。"
            )
            ghidraStatusText = msg
            toastController.enqueue(
                kind: .error,
                title: MGL("Ghidra Unavailable", "Ghidra 不可用"),
                detail: msg
            )
            return
        }

        isRunningGhidraHeadless = true
        ghidraStatusText = MGL(
            "Running Ghidra 12.1.4 DecompInterface on \(fn.demangledName)...",
            "正在对 \(fn.demangledName) 运行 Ghidra 12.1.4 反编译..."
        )
        let dataCopy = overlayBuffer.materializedData()
        let binName = loadedImage?.fileName ?? "binary"
        let fnAddr = fn.address
        let fnName = fn.name

        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let cSource = try await bridge.decompileFunction(
                    inBinaryData: dataCopy,
                    binaryName: binName,
                    functionAddress: fnAddr,
                    functionName: fnName
                )
                self.ghidraDecompiledByFunction[fnAddr] = cSource
                self.ghidraStatusText = MGL(
                    "Ghidra 12.1.4 DecompInterface synced for \(fnName)",
                    "已同步 \(fnName) 的 Ghidra 12.1.4 反编译结果"
                )
            } catch {
                self.isGhidraSideBySideEnabled = false
                let errMsg = MGL(
                    "Ghidra headless error: \(error.localizedDescription)",
                    "Ghidra 反编译执行失败: \(error.localizedDescription)"
                )
                self.ghidraStatusText = errMsg
                self.toastController.enqueue(
                    kind: .error,
                    title: MGL("Ghidra Decompilation Failed", "Ghidra 反编译失败"),
                    detail: error.localizedDescription
                )
            }
            self.isRunningGhidraHeadless = false
            self.recomputeCFGLayoutsAndDecompilation()
        }
    }

    // MARK: - Persistent Analyst Mutations (`N`, `;`, `B`, Undo/Redo, Snapshots)

    public func refreshDatabaseAnnotationsAndStats() {
        self.customRenames = (try? projectDB.allRenames()) ?? []
        self.inlineComments = (try? projectDB.allComments()) ?? []
        self.bookmarks = (try? projectDB.allBookmarks()) ?? []
        self.customStructs = (try? projectDB.allStructs()) ?? []
        self.undoStackRecords = (try? undoRedo.undoStack(limit: 40)) ?? []
        self.redoStackRecords = (try? undoRedo.redoStack(limit: 40)) ?? []
        self.checkpoints = (try? snapshotManager.listCheckpoints()) ?? []
        self.projectStats = try? projectDB.computeProjectStats()

        paletteController.rebuildCatalog(
            image: loadedImage,
            functions: functions,
            renames: customRenames,
            bookmarks: bookmarks,
            findings: securityFindings,
            language: MachLocalizer.shared.language
        )
    }

    public func presentRenameModalForCursor() {
        let va = activeFunction?.address ?? cursorBus.currentLocation.virtualAddress
        let orig = activeFunction?.demangledName
            ?? loadedImage?.exactSymbol(at: va)?.demangledName
            ?? "sub_\(String(va.rawValue, radix: 16))"
        let existing = customRenames.first(where: { $0.address == va })
        pendingRenameAddress = va
        pendingRenameOriginal = orig
        pendingRenameInput = existing?.customName ?? orig
        pendingRenameSignature = existing?.signatureOverride ?? ""
        isRenameModalPresented = true
    }

    public func commitPendingRename() {
        do {
            try undoRedo.renameSymbol(
                at: pendingRenameAddress,
                originalName: pendingRenameOriginal,
                newName: pendingRenameInput,
                signature: pendingRenameSignature.isEmpty ? nil : pendingRenameSignature
            )
            isRenameModalPresented = false
            refreshDatabaseAnnotationsAndStats()
            recomputeCFGLayoutsAndDecompilation()
            toastController.enqueue(
                kind: .success,
                title: MGL("Symbol Renamed in .machproj", "已在 .machproj 中重命名符号"),
                detail: "\(pendingRenameAddress.compactHexString) -> \(pendingRenameInput)"
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Rename Failed", "符号重命名失败"), detail: error.localizedDescription)
        }
    }

    public func presentCommentModalForCursor() {
        let va = cursorBus.currentLocation.virtualAddress
        let existing = inlineComments.first(where: { $0.address == va })
        pendingCommentAddress = va
        pendingCommentInput = existing?.text ?? ""
        pendingCommentRepeatable = existing?.isRepeatable ?? false
        isCommentModalPresented = true
    }

    public func commitPendingComment() {
        do {
            try undoRedo.setInlineComment(
                at: pendingCommentAddress,
                text: pendingCommentInput,
                isRepeatable: pendingCommentRepeatable
            )
            isCommentModalPresented = false
            refreshDatabaseAnnotationsAndStats()
            recomputeCFGLayoutsAndDecompilation()
            toastController.enqueue(
                kind: .info,
                title: pendingCommentInput.isEmpty
                    ? MGL("Removed Inline Comment", "已移除内联注释")
                    : MGL("Saved Inline Comment", "已保存内联注释"),
                detail: pendingCommentAddress.compactHexString
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Comment Save Failed", "注释保存失败"), detail: error.localizedDescription)
        }
    }

    public func toggleBookmarkAtCursor() {
        let va = cursorBus.currentLocation.virtualAddress
        let defaultLabel = displayFunctionName(at: va) ?? MGL("Cursor \(va.compactHexString)", "光标 \(va.compactHexString)")
        do {
            let added = try undoRedo.toggleBookmark(at: va, label: defaultLabel, category: "Triage")
            refreshDatabaseAnnotationsAndStats()
            toastController.enqueue(
                kind: .info,
                title: added
                    ? MGL("Bookmarked \(va.compactHexString)", "已添加书签 \(va.compactHexString)")
                    : MGL("Removed Bookmark", "已移除书签"),
                detail: defaultLabel
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Bookmark Error", "书签操作失败"), detail: error.localizedDescription)
        }
    }

    public func deleteBookmark(_ bookmark: UserBookmark) {
        try? undoRedo.removeBookmark(id: bookmark.id)
        refreshDatabaseAnnotationsAndStats()
    }

    public func saveStructDefinition(_ definition: CustomStructDefinition) {
        do {
            try undoRedo.saveCustomStruct(definition)
            selectedStructForHexEvalID = definition.id
            refreshDatabaseAnnotationsAndStats()
            recomputeCFGLayoutsAndDecompilation()
            toastController.enqueue(
                kind: .success,
                title: MGL("Saved C Struct '\(definition.name)'", "已保存 C 结构体 '\(definition.name)'"),
                detail: MGL(
                    "\(definition.totalByteSize) bytes · \(definition.fields.count) fields",
                    "\(definition.totalByteSize) 字节 · \(definition.fields.count) 个字段"
                )
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Struct Save Error", "结构体保存失败"), detail: error.localizedDescription)
        }
    }

    public func performUndo() {
        guard let undone = try? undoRedo.undo() else { return }
        syncOverlayPatchesFromDatabase()
        refreshDatabaseAnnotationsAndStats()
        recomputeCFGLayoutsAndDecompilation()
        toastController.enqueue(
            kind: .info,
            title: MGL("Undid Mutation", "已撤销变更"),
            detail: undone.localizedTitle(in: MachLocalizer.shared.language)
        )
    }

    public func performRedo() {
        guard let redone = try? undoRedo.redo() else { return }
        syncOverlayPatchesFromDatabase()
        refreshDatabaseAnnotationsAndStats()
        recomputeCFGLayoutsAndDecompilation()
        toastController.enqueue(
            kind: .info,
            title: MGL("Redid Mutation", "已重做变更"),
            detail: redone.localizedTitle(in: MachLocalizer.shared.language)
        )
    }

    private func syncOverlayPatchesFromDatabase() {
        let dbPatches = (try? projectDB.allPatches()) ?? []
        if let rebuilt = try? SparseCoWByteOverlayBuffer(baseData: baseBinaryData, patches: dbPatches) {
            self.overlayBuffer = rebuilt
            refreshOverlayDerivedTelemetry()
            recomputeLivePatchPreview()
        }
    }

    public func captureSnapshotCheckpoint() {
        let indexNum = checkpoints.count + 1
        do {
            let summary = try snapshotManager.createCheckpoint(
                name: MGL(
                    "Checkpoint #\(indexNum) @ \(cursorBus.currentLocation.virtualAddress.compactHexString)",
                    "快照 #\(indexNum) @ \(cursorBus.currentLocation.virtualAddress.compactHexString)"
                ),
                note: MGL(
                    "\(customRenames.count) renames, \(overlayBuffer.patches.count) patches, \(bookmarks.count) bookmarks",
                    "\(customRenames.count) 个重命名, \(overlayBuffer.patches.count) 个补丁, \(bookmarks.count) 个书签"
                )
            )
            refreshDatabaseAnnotationsAndStats()
            toastController.enqueue(
                kind: .success,
                title: MGL("Saved SQLite WAL Snapshot", "已保存 SQLite WAL 分析快照"),
                detail: summary.name
            )
        } catch {
            toastController.enqueue(kind: .error, title: MGL("Snapshot Failed", "快照保存失败"), detail: error.localizedDescription)
        }
    }

    public func presentXrefsPopoverAtCursor() {
        guard let index = analysisIndex else { return }
        let va = cursorBus.currentLocation.virtualAddress
        let targetAddr = activeFunction?.address == va ? va : va
        let incoming = index.xrefsTo(address: targetAddr)
        let outgoing = index.xrefsFrom(address: targetAddr)
        let label = displaySymbolOrFunction(at: targetAddr)
        xrefPopoverModel.present(
            for: targetAddr,
            targetName: label,
            incoming: incoming,
            outgoing: outgoing,
            functions: functions,
            renames: customRenames
        )
    }

    public func handlePaletteAction(_ action: MachWorkbenchActionID) {
        switch action {
        case .openCFGGraph:
            cursorBus.disableSplitView()
            cursorBus.activePane = .cfgGraph
        case .openLinearDisassembly:
            cursorBus.disableSplitView()
            cursorBus.activePane = .disassembly
        case .openPseudoCDecompiler:
            cursorBus.disableSplitView()
            cursorBus.activePane = .pseudoC
        case .openHexPatcher:
            cursorBus.disableSplitView()
            cursorBus.activePane = .hexPatcher
        case .openStringsAndRuntime:
            cursorBus.disableSplitView()
            cursorBus.activePane = .stringsAndObjC
        case .openEntropyAndCodeSign:
            cursorBus.disableSplitView()
            cursorBus.activePane = .entropyAndSign
        case .openPluginAudit:
            cursorBus.disableSplitView()
            cursorBus.activePane = .pluginFindings
        case .toggleSideBySideSplit:
            cursorBus.toggleSplitView(defaultSecondary: .pseudoC)
        case .openGoToAddress:
            isGoToModalPresented = true
        case .openXrefsAtCursor:
            presentXrefsPopoverAtCursor()
        case .runSecurityAuditPlugins:
            runSecurityAuditSuite(emitToast: true)
        case .createAnalysisSnapshot:
            captureSnapshotCheckpoint()
        case .resignMachOAdHoc:
            reSignActiveMachOBinary()
        case .undoLastMutation:
            performUndo()
        case .redoLastMutation:
            performRedo()
        case .toggleBookmarkAtCursor:
            toggleBookmarkAtCursor()
        case .openPreferences:
            isPreferencesPresented = true
        case .openShortcutsSheet:
            isShortcutsSheetPresented = true
        case .toggleLanguage:
            let next = MachLocalizer.shared.toggleLanguage()
            toastController.enqueue(
                kind: .info,
                title: next.select("Switched Interface to English", "已切换界面语言为简体中文"),
                detail: next.select("Press ⇧⌘L anytime to switch back to 中文", "随时按 ⇧⌘L 可切回 English")
            )
        }
    }

    // MARK: - Convenience Computed Accessors

    public var functions: [RecoveredFunction] {
        analysisIndex?.functions ?? []
    }

    public var xrefCount: Int {
        analysisIndex?.crossReferences.allRecords.count ?? 0
    }

    public var activeFunction: RecoveredFunction? {
        guard let index = analysisIndex else { return nil }
        if let fnAddr = cursorBus.activeFunctionAddress, let fn = index.function(at: fnAddr) {
            return fn
        }
        let va = cursorBus.currentLocation.virtualAddress
        return index.function(containing: va) ?? index.functions.first
    }

    public var activeCFGLayout: SugiyamaCFGLayout? {
        guard let fn = activeFunction else { return nil }
        return cfgLayoutsByFunction[fn.address] ?? fn.layout
    }

    public var activeDecompiledOutput: DecompiledFunctionOutput? {
        guard let fn = activeFunction else { return nil }
        return decompiledByFunction[fn.address]
    }

    public var xrefsAtCursor: [XrefRecord] {
        guard let index = analysisIndex else { return [] }
        let va = cursorBus.currentLocation.virtualAddress
        var combined = index.xrefsTo(address: va) + index.xrefsFrom(address: va)
        if combined.isEmpty, let fn = activeFunction {
            combined = index.xrefsTo(address: fn.address) + index.xrefsFrom(address: fn.address)
        }
        return combined
    }

    public var renameMap: [VirtualAddress: String] {
        var map: [VirtualAddress: String] = [:]
        for item in customRenames {
            map[item.address] = item.customName
        }
        return map
    }

    public var commentMap: [VirtualAddress: UserInlineComment] {
        var map: [VirtualAddress: UserInlineComment] = [:]
        for item in inlineComments {
            map[item.address] = item
        }
        return map
    }

    public func displayFunctionName(_ fn: RecoveredFunction) -> String {
        renameMap[fn.address] ?? fn.demangledName
    }

    public func displayFunctionName(at address: VirtualAddress) -> String? {
        guard let fn = analysisIndex?.function(containing: address) ?? analysisIndex?.function(at: address) else {
            return nil
        }
        return displayFunctionName(fn)
    }

    public func displaySymbolOrFunction(at address: VirtualAddress) -> String {
        if let custom = renameMap[address] { return custom }
        if let fn = analysisIndex?.function(at: address) { return fn.demangledName }
        if let sym = loadedImage?.exactSymbol(at: address) { return sym.demangledName }
        if let fn = analysisIndex?.function(containing: address) {
            let delta = address.rawValue - fn.address.rawValue
            return delta == 0 ? fn.demangledName : "\(fn.demangledName)+0x\(String(delta, radix: 16))"
        }
        return address.compactHexString
    }

    // MARK: - Deterministic Retina Screenshot Scene Presets

    public func configureForCFGCanvasScreenshot() {
        toastController.dismissAll()
        isGoToModalPresented = false
        isPreferencesPresented = false
        isShortcutsSheetPresented = false
        paletteController.closePalette()
        xrefPopoverModel.isPresented = false

        cursorBus.disableSplitView()
        cursorBus.activePane = .cfgGraph
        showRightContextualInspector = true
        navigatorState.selectedMode = .functions
        drawerState.isCollapsed = false
        drawerState.activeChannel = .xrefsAtCursor
        drawerState.drawerHeight = 148.0

        if let verifyFn = analysisIndex?.function(named: "_verify_license") ?? functions.first {
            cursorBus.selectFunction(verifyFn, in: loadedImage, originPane: .cfgGraph)
        }
    }

    public func configureForDecompilerSplitScreenshot() {
        toastController.dismissAll()
        paletteController.closePalette()
        isGoToModalPresented = false

        if let verifyFn = analysisIndex?.function(named: "_verify_license") ?? functions.first {
            cursorBus.selectFunction(verifyFn, in: loadedImage, originPane: .disassembly)
        }
        cursorBus.enableSideBySideSplit(primary: .disassembly, secondary: .pseudoC)
        showRightContextualInspector = false
        navigatorState.selectedMode = .functions
        drawerState.isCollapsed = false
        drawerState.activeChannel = .undoRedoJournal
        drawerState.drawerHeight = 144.0
    }

    public func configureForHexPatcherScreenshot() {
        toastController.dismissAll()
        paletteController.closePalette()
        isGoToModalPresented = false

        cursorBus.disableSplitView()
        cursorBus.activePane = .hexPatcher
        showRightContextualInspector = false
        navigatorState.selectedMode = .patches
        drawerState.isCollapsed = false
        drawerState.activeChannel = .undoRedoJournal
        drawerState.drawerHeight = 142.0

        if let verifyFn = analysisIndex?.function(named: "_verify_license"),
           let off = loadedImage?.fileOffset(for: verifyFn.address) {
            cursorBus.jump(toAddress: verifyFn.address, in: loadedImage, functions: functions, switchToPane: .hexPatcher)
            selectedHexByteOffset = off
            hexScrollOffset = FileOffset((off.rawValue / 16) * 16)
            patchTargetAddressText = verifyFn.address.compactHexString
            inlineAssemblyInput = "paciasp; mov w0, #1; retaa"
            recomputeLivePatchPreview()
        }
    }

    public func configureForEntropyAuditScreenshot() {
        toastController.dismissAll()
        paletteController.closePalette()
        isGoToModalPresented = false

        cursorBus.disableSplitView()
        cursorBus.activePane = .entropyAndSign
        showRightContextualInspector = false
        navigatorState.selectedMode = .classes
        drawerState.isCollapsed = false
        drawerState.activeChannel = .securityFindings
        drawerState.drawerHeight = 168.0
    }

    public static let defaultScratchpadScript: String = """
    // MachGraph JavaScriptCore Static Triage Scratchpad
    const functions = mach.functions();
    const strings = mach.strings();
    mach.log("Auditing " + functions.length + " functions and " + strings.length + " literals");

    for (const fn of functions) {
      if (fn.usesPAC && fn.cyclomaticComplexity >= 3) {
        mach.log("PAC-hardened control gate: " + fn.name + " @ " + fn.address);
      }
    }
    """
}
