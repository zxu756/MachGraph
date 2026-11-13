import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachGraphModels
import MachPatchAndHexEngine
import MachWorkbenchShell
import SwiftUI

// MARK: - Sparse CoW Hex Viewport, Structure Inspector & Inline ARM64 Patcher Studio

@MainActor
public struct SparseCoWHexAndInlinePatcherStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    @ObservedObject private var cursorBus: SynchronizedAddressCursorBus
    @ObservedObject private var localizer: MachLocalizer = .shared

    @State private var inspectorTab: HexBottomInspectorTab = .primitives

    public enum HexBottomInspectorTab: String, CaseIterable, Identifiable {
        case primitives = "Primitives"
        case cStructOverlay = "C Struct"

        public var id: String { rawValue }

        public func localizedTitle(in lang: MachLanguage) -> String {
            switch self {
            case .primitives: return lang == .zhHans ? "基础类型" : "Primitives"
            case .cStructOverlay: return lang == .zhHans ? "C 结构体" : "C Struct"
            }
        }
    }

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
        self.cursorBus = viewModel.cursorBus
    }

    private var viewportWindow: HexViewportWindow {
        viewModel.overlayBuffer.hexViewportWindow(
            scrollOffset: viewModel.hexScrollOffset,
            visibleRowCount: 10,
            overscanRows: 0,
            bytesPerRow: 16,
            image: viewModel.loadedImage
        )
    }

    private var dataInspectorValues: DataInspectorValues? {
        try? BinaryStructureInspector().inspect(
            at: viewModel.selectedHexByteOffset,
            in: viewModel.overlayBuffer,
            endianness: viewModel.hexInspectorEndianness,
            image: viewModel.loadedImage
        )
    }

    private var activeStructDefinition: CustomStructDefinition? {
        if let id = viewModel.selectedStructForHexEvalID,
           let matched = viewModel.customStructs.first(where: { $0.id == id }) {
            return matched
        }
        return viewModel.customStructs.first
    }

    private var evaluatedStructFields: [EvaluatedStructFieldValue] {
        guard let structDef = activeStructDefinition else { return [] }
        return (try? BinaryStructureInspector().evaluateCustomStruct(
            structDef,
            at: viewModel.selectedHexByteOffset,
            in: viewModel.overlayBuffer,
            endianness: viewModel.hexInspectorEndianness,
            image: viewModel.loadedImage
        )) ?? []
    }

    public var body: some View {
        HStack(spacing: 0) {
            leftHexAndInspectorColumn
                .frame(width: 552)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline)

            rightInlineAssemblerAndReSignerColumn
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(ColdTungstenPalette.chassisBackground)
    }

    // MARK: - Left Column: Sparse CoW Hex Matrix + Binary Search + Data Inspector

    private var leftHexAndInspectorColumn: some View {
        VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Sparse CoW Hex & ASCII Viewport", "稀疏CoW十六进制与ASCII视口"),
                sfSymbol: "00.square",
                countBadge: viewModel.overlayBuffer.modifiedByteCount
            ) {
                HStack(spacing: 6) {
                    cowTelemetryPill

                    Button {
                        viewModel.hexInspectorEndianness = (viewModel.hexInspectorEndianness == .little) ? .big : .little
                    } label: {
                        Text(viewModel.hexInspectorEndianness == .little ? "LE" : "BE")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, isActive: true, compact: true))
                    .fixedSize(horizontal: true, vertical: false)
                }
            }

            sectionJumpAndSearchStrip

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            hexMatrixHeaderRow

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(viewportWindow.rows) { row in
                        hexMatrixRowView(row)
                    }
                }
                .padding(.vertical, 3)
            }
            .background(ColdTungstenPalette.chassisBackground)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            bottomDataAndStructInspectorPanel
                .frame(height: 168)
        }
        .background(ColdTungstenPalette.chassisBackground)
    }

    private var cowTelemetryPill: some View {
        let dirtyCount = viewModel.overlayBuffer.modifiedByteCount
        let extentCount = viewModel.overlayBuffer.dirtyExtents.count
        let pillLabel: String = {
            if dirtyCount > 0 {
                return localizer.language == .zhHans
                    ? "\(dirtyCount) 字节已改 (\(extentCount) CoW 区间)"
                    : "\(dirtyCount) B dirty (\(extentCount) CoW extent)"
            }
            return localizer.L("Clean Base Map", "基线镜像未修改")
        }()
        return HStack(spacing: 5) {
            Circle()
                .fill(dirtyCount > 0 ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.signalEmerald)
                .frame(width: 6, height: 6)
            Text(pillLabel)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                .foregroundStyle(dirtyCount > 0 ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.coolPewter)
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            dirtyCount > 0
                ? ColdTungstenPalette.warmCopper.opacity(0.14)
                : ColdTungstenPalette.chassisBackground
        )
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .strokeBorder(
                    dirtyCount > 0 ? ColdTungstenPalette.warmCopper.opacity(0.55) : ColdTungstenPalette.tungstenSeam,
                    lineWidth: ColdTungstenMetrics.borderHairline
                )
        )
        .clipShape(RoundedRectangle(cornerRadius: 3))
        .fixedSize(horizontal: true, vertical: false)
    }

    private var sectionJumpAndSearchStrip: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Row 1: Navigation Stepper + Section Quick Jumps
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 5) {
                    Button("-0x100") { stepHexViewport(by: -0x100) }
                        .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        .fixedSize(horizontal: true, vertical: false)

                    Button("-0x10") { stepHexViewport(by: -0x10) }
                        .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        .fixedSize(horizontal: true, vertical: false)

                    Button(localizer.L("@ Cursor", "@ 光标")) { syncHexViewportToCursor() }
                        .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                        .fixedSize(horizontal: true, vertical: false)

                    Button("+0x10") { stepHexViewport(by: 0x10) }
                        .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        .fixedSize(horizontal: true, vertical: false)

                    Button("+0x100") { stepHexViewport(by: 0x100) }
                        .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                        .fixedSize(horizontal: true, vertical: false)

                    if let sections = viewModel.loadedImage?.sections.prefix(3) {
                        Rectangle()
                            .fill(ColdTungstenPalette.tungstenSeam)
                            .frame(width: 1, height: 14)
                            .padding(.horizontal, 2)

                        ForEach(Array(sections)) { sec in
                            let isCurrent = viewModel.selectedHexByteOffset.rawValue >= sec.fileOffset.rawValue
                                && viewModel.selectedHexByteOffset.rawValue < (sec.fileOffset.rawValue + sec.size)
                            Button(sec.sectionName) {
                                jumpToFileOffset(sec.fileOffset)
                            }
                            .buttonStyle(TungstenToolbarButtonStyle(
                                role: isCurrent ? .accentSapphire : .standard,
                                isActive: isCurrent,
                                compact: true
                            ))
                            .fixedSize(horizontal: true, vertical: false)
                        }
                    }
                }
            }

            // Row 2: Binary Pattern / String / Pointer Search Bar
            HStack(spacing: 6) {
                Menu {
                    ForEach(HexStudioSearchMode.allCases) { mode in
                        Button(mode.localizedTitle(in: localizer.language)) {
                            viewModel.hexSearchMode = mode
                            viewModel.executeHexSearch()
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 10, weight: .semibold))
                        Text(viewModel.hexSearchMode.localizedTitle(in: localizer.language))
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                        Image(systemName: "chevron.down")
                            .font(.system(size: 8, weight: .bold))
                    }
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 4)
                    .background(ColdTungstenPalette.brushedSteel)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .fixedSize(horizontal: true, vertical: false)
                }
                .menuStyle(.borderlessButton)
                .fixedSize(horizontal: true, vertical: false)

                TextField(viewModel.hexSearchMode.localizedPlaceholder(in: localizer.language), text: $viewModel.hexSearchQuery)
                    .textFieldStyle(.plain)
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(ColdTungstenPalette.chassisBackground)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .onSubmit {
                        viewModel.executeHexSearch()
                    }

                Button(localizer.L("Find", "查找")) {
                    viewModel.executeHexSearch()
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, compact: true))
                .fixedSize(horizontal: true, vertical: false)

                if !viewModel.hexSearchHits.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 4) {
                            ForEach(viewModel.hexSearchHits.prefix(6)) { hit in
                                Button {
                                    jumpToFileOffset(hit.fileOffset)
                                } label: {
                                    Text(hit.virtualAddress?.compactHexString ?? hit.fileOffset.hexString)
                                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                                        .foregroundStyle(ColdTungstenPalette.signalEmerald)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(ColdTungstenPalette.signalEmerald.opacity(0.13))
                                        .clipShape(RoundedRectangle(cornerRadius: 3))
                                        .fixedSize(horizontal: true, vertical: false)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    .frame(maxWidth: 155)
                }
            }

            if let searchErr = viewModel.hexSearchErrorMessage {
                Text(searchErr)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(ColdTungstenPalette.gunmetalSlate)
    }

    private var hexMatrixHeaderRow: some View {
        HStack(spacing: 0) {
            Text(localizer.L("OFFSET", "文件偏移"))
                .frame(width: 52, alignment: .leading)
            Text(localizer.L("VIRTUAL ADDR", "虚拟地址"))
                .frame(width: 82, alignment: .leading)

            HStack(spacing: 1.5) {
                ForEach(0..<16, id: \.self) { col in
                    Text(String(format: "%02X", col))
                        .frame(width: 15.5, alignment: .center)
                        .padding(.trailing, col == 7 ? 4 : 0)
                }
            }

            Spacer(minLength: 6)

            Text("ASCII")
                .frame(width: 112, alignment: .leading)
        }
        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(ColdTungstenPalette.brushedSteel)
    }

    private func hexMatrixRowView(_ row: HexRowSlice) -> some View {
        let rowContainsSelection = viewModel.selectedHexByteOffset.rawValue >= row.fileOffset.rawValue
            && viewModel.selectedHexByteOffset.rawValue < (row.fileOffset.rawValue + UInt64(row.bytes.count))
        let rowHasDirty = row.modifiedMask.contains(true)

        return HStack(spacing: 0) {
            Text(String(format: "%06llX", row.fileOffset.rawValue))
                .font(ColdTungstenTypography.offsetGutterMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                .frame(width: 52, alignment: .leading)
                .fixedSize(horizontal: true, vertical: false)

            Text(row.virtualAddress?.compactHexString ?? localizer.L("unmapped", "未映射"))
                .font(ColdTungstenTypography.addressMono(size: 10.0, weight: rowContainsSelection ? .bold : .regular))
                .foregroundStyle(rowContainsSelection ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
                .frame(width: 82, alignment: .leading)
                .fixedSize(horizontal: true, vertical: false)

            HStack(spacing: 1.5) {
                ForEach(Array(row.bytes.enumerated()), id: \.offset) { colIdx, byteVal in
                    let cellOffset = FileOffset(row.fileOffset.rawValue + UInt64(colIdx))
                    let isSelected = cellOffset == viewModel.selectedHexByteOffset
                    let isDirty = row.modifiedMask.indices.contains(colIdx) && row.modifiedMask[colIdx]
                    hexByteCell(
                        byte: byteVal,
                        fileOffset: cellOffset,
                        virtualAddress: row.virtualAddress?.adding(UInt64(colIdx)),
                        isSelected: isSelected,
                        isDirty: isDirty
                    )
                    .padding(.trailing, colIdx == 7 ? 4 : 0)
                }
                if row.bytes.count < 16 {
                    ForEach(row.bytes.count..<16, id: \.self) { colIdx in
                        Text("  ")
                            .font(ColdTungstenTypography.disassemblyMono(size: 10.0))
                            .frame(width: 15.5)
                            .padding(.trailing, colIdx == 7 ? 4 : 0)
                    }
                }
            }

            Spacer(minLength: 6)

            Text(row.asciiColumn)
                .font(ColdTungstenTypography.disassemblyMono(size: 10.0))
                .foregroundStyle(rowHasDirty ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.steelWhite.opacity(0.86))
                .frame(width: 112, alignment: .leading)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2.0)
        .background(
            rowContainsSelection
                ? ColdTungstenPalette.activeSelectionFill.opacity(0.65)
                : (rowHasDirty ? ColdTungstenPalette.warmCopper.opacity(0.06) : Color.clear)
        )
    }

    private func hexByteCell(
        byte: UInt8,
        fileOffset: FileOffset,
        virtualAddress: VirtualAddress?,
        isSelected: Bool,
        isDirty: Bool
    ) -> some View {
        let fgColor: Color = {
            if isDirty { return ColdTungstenPalette.warmCopper }
            if isSelected { return ColdTungstenPalette.steelWhite }
            if byte == 0x00 { return ColdTungstenPalette.mutedOffsetInk }
            return ColdTungstenPalette.steelWhite
        }()

        return Button {
            selectByte(fileOffset: fileOffset, virtualAddress: virtualAddress)
        } label: {
            Text(String(format: "%02X", byte))
                .font(ColdTungstenTypography.disassemblyMono(size: 10.0, weight: (isDirty || isSelected) ? .bold : .regular))
                .foregroundStyle(fgColor)
                .frame(width: 15.5, height: 15)
                .background(
                    RoundedRectangle(cornerRadius: 2.5)
                        .fill(
                            isDirty
                                ? ColdTungstenPalette.warmCopper.opacity(isSelected ? 0.34 : 0.20)
                                : (isSelected ? ColdTungstenPalette.tungstenSapphire.opacity(0.28) : Color.clear)
                        )
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 2.5)
                        .strokeBorder(
                            isSelected
                                ? ColdTungstenPalette.tungstenSapphire
                                : (isDirty ? ColdTungstenPalette.warmCopper.opacity(0.65) : Color.clear),
                            lineWidth: 1.0
                        )
                )
        }
        .buttonStyle(.plain)
    }

    private var bottomDataAndStructInspectorPanel: some View {
        let inspector = dataInspectorValues
        let locHex = inspector?.virtualAddress?.compactHexString ?? inspector?.fileOffset.hexString ?? viewModel.selectedHexByteOffset.hexString
        return VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "tablecells.badge.ellipsis")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                Text(localizer.language == .zhHans ? "结构体检查器 @ \(locHex)" : "Structure Inspector @ \(locHex)")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 6)

                ForEach(HexBottomInspectorTab.allCases) { tab in
                    Button(tab.localizedTitle(in: localizer.language)) {
                        inspectorTab = tab
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: inspectorTab == tab ? .accentSapphire : .standard,
                        isActive: inspectorTab == tab,
                        compact: true
                    ))
                    .fixedSize(horizontal: true, vertical: false)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            ScrollView(.vertical, showsIndicators: true) {
                if inspectorTab == .primitives {
                    LazyVGrid(
                        columns: [
                            GridItem(.flexible(minimum: 230), spacing: 8),
                            GridItem(.flexible(minimum: 230), spacing: 8)
                        ],
                        alignment: .leading,
                        spacing: 5
                    ) {
                        ForEach(curatedInspectorRows(from: inspector?.rows ?? [])) { row in
                            HStack(spacing: 6) {
                                Text(row.label == "ARM64 instruction" ? localizer.L("ARM64 instruction", "ARM64 指令") : row.label)
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .frame(width: 84, alignment: .leading)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(row.formattedValue)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 10.5, weight: .medium))
                                    .foregroundStyle(
                                        row.label.contains("ARM64")
                                            ? ColdTungstenPalette.signalEmerald
                                            : ColdTungstenPalette.steelWhite
                                    )
                                    .fixedSize(horizontal: false, vertical: true)

                                Spacer(minLength: 0)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(ColdTungstenPalette.chassisBackground)
                            .overlay(
                                RoundedRectangle(cornerRadius: 3)
                                    .strokeBorder(ColdTungstenPalette.tungstenSeam.opacity(0.75), lineWidth: ColdTungstenMetrics.borderHairline)
                            )
                        }
                    }
                    .padding(8)
                } else {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 8) {
                            Text(localizer.L("Struct:", "结构体:"))
                                .font(ColdTungstenTypography.secondaryCaption)
                                .foregroundStyle(ColdTungstenPalette.coolPewter)

                            ForEach(viewModel.customStructs) { def in
                                let active = activeStructDefinition?.id == def.id
                                Button("\(def.name) (\(def.totalByteSize)B)") {
                                    viewModel.selectedStructForHexEvalID = def.id
                                }
                                .buttonStyle(TungstenToolbarButtonStyle(
                                    role: active ? .accentSapphire : .standard,
                                    isActive: active,
                                    compact: true
                                ))
                                .fixedSize(horizontal: true, vertical: false)
                            }
                        }

                        ForEach(evaluatedStructFields) { field in
                            HStack(spacing: 8) {
                                Text(String(format: "+0x%02X", field.fieldOffset))
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(field.cTypeName)
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(field.name)
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.0, weight: .semibold))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: true, vertical: false)

                                Spacer(minLength: 6)

                                Text(field.formattedValue)
                                    .font(ColdTungstenTypography.addressMono(size: 11.0))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize(horizontal: true, vertical: false)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(ColdTungstenPalette.chassisBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                        }
                    }
                    .padding(8)
                }
            }
            .background(ColdTungstenPalette.gunmetalSlate)
        }
    }

    // MARK: - Right Column: Inline ARM64 Two-Pass Mini-Assembler + CoW Stack + Mach-O Re-Signer

    private var rightInlineAssemblerAndReSignerColumn: some View {
        VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Inline ARM64 Assembler & CodeDirectory Re-Signer", "内联ARM64汇编与重签名器"),
                sfSymbol: "hammer.fill"
            ) {
                Button {
                    viewModel.applySingleInstructionNOPAtCursor()
                } label: {
                    Label(localizer.L("NOP @ Cursor", "光标处写 NOP"), systemImage: "rectangle.dashed")
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                .fixedSize(horizontal: true, vertical: false)
            }

            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 7) {
                    inlineAssemblerCard
                    liveSafetyAndDiffPreviewCard
                    machOCodeDirectoryReSignerCard
                    activeCoWPatchStackCard
                }
                .padding(8)
            }
            .background(ColdTungstenPalette.gunmetalSlate)
        }
    }

    private var inlineAssemblerCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Label(localizer.L("Two-Pass ARM64 / ARM64e Mini-Assembler", "双遍ARM64内联汇编器"), systemImage: "cpu")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Text(localizer.L("PC-Relative + PAC", "PC相对 + PAC"))
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(ColdTungstenPalette.tungstenAmber.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: 3))
                    .fixedSize(horizontal: true, vertical: false)
            }

            HStack(spacing: 6) {
                Text(localizer.L("Target VA:", "目标虚拟地址:"))
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: true, vertical: false)

                TextField(localizer.L("0x100001038 or _verify_license", "0x100001038 或 _verify_license"), text: $viewModel.patchTargetAddressText)
                    .textFieldStyle(.plain)
                    .font(ColdTungstenTypography.addressMono(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .frame(width: 148)
                    .background(ColdTungstenPalette.chassisBackground)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .onChange(of: viewModel.patchTargetAddressText) { _, _ in
                        viewModel.recomputeLivePatchPreview()
                    }

                Button(localizer.L("Use Cursor", "使用光标")) {
                    viewModel.patchTargetAddressText = cursorBus.currentLocation.virtualAddress.compactHexString
                    viewModel.recomputeLivePatchPreview()
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(localizer.L("ARM64 Instructions (semicolon-separated):", "ARM64 汇编指令 (分号分隔):"))
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)

                TextField("paciasp; mov w0, #1; retaa", text: $viewModel.inlineAssemblyInput)
                    .textFieldStyle(.plain)
                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .medium))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(ColdTungstenPalette.chassisBackground)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSapphire.opacity(0.55), lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .onChange(of: viewModel.inlineAssemblyInput) { _, _ in
                        viewModel.recomputeLivePatchPreview()
                    }
                    .onSubmit {
                        viewModel.commitLiveInstructionPatch()
                    }
            }

            // Preset Assembly Snippets
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 5) {
                    Text(localizer.L("Presets:", "预设:"))
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                        .fixedSize(horizontal: true, vertical: false)

                    assemblerPresetChip(title: localizer.L("PAC True (w0=1; retaa)", "PAC 置真 (w0=1; retaa)"), asm: "paciasp; mov w0, #1; retaa")
                    assemblerPresetChip(title: localizer.L("Zero Stub (w0=0; ret)", "返回零桩 (w0=0; ret)"), asm: "mov w0, #0; ret")
                    assemblerPresetChip(title: localizer.L("2x NOP Sled", "双 NOP 滑板"), asm: "nop; nop")
                }
            }

            HStack(spacing: 10) {
                Toggle(localizer.L("NOP-pad span", "填充 NOP 对齐"), isOn: $viewModel.padNOPToOriginalInstructionSpan)
                    .toggleStyle(.checkbox)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .onChange(of: viewModel.padNOPToOriginalInstructionSpan) { _, _ in
                        viewModel.recomputeLivePatchPreview()
                    }

                Toggle(localizer.L("Allow branch clobber", "允许覆盖跳转目标"), isOn: $viewModel.allowBranchTargetClobber)
                    .toggleStyle(.checkbox)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)

                Spacer(minLength: 4)

                Button {
                    viewModel.commitLiveInstructionPatch()
                } label: {
                    Label(localizer.L("Apply CoW Patch", "应用 CoW 补丁"), systemImage: "bolt.horizontal.fill")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, isActive: true, compact: true))
                .fixedSize(horizontal: true, vertical: false)
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private func assemblerPresetChip(title: String, asm: String) -> some View {
        let active = viewModel.inlineAssemblyInput == asm
        return Button(title) {
            viewModel.inlineAssemblyInput = asm
            viewModel.recomputeLivePatchPreview()
        }
        .buttonStyle(TungstenToolbarButtonStyle(
            role: active ? .accentSapphire : .standard,
            isActive: active,
            compact: true
        ))
        .fixedSize(horizontal: true, vertical: false)
    }

    private var liveSafetyAndDiffPreviewCard: some View {
        VStack(alignment: .leading, spacing: 7) {
            if let preview = viewModel.livePatchPreview {
                let clean = preview.safetyReport.isClean
                HStack(spacing: 7) {
                    Image(systemName: clean ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(clean ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)

                    Text(clean ? localizer.L("SAFETY VERIFIED CLEAN", "安全性校验通过") : localizer.L("CONTROL-FLOW HAZARD DETECTED", "检测到控制流风险"))
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                        .foregroundStyle(clean ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 4)

                    Text(
                        localizer.language == .zhHans
                            ? "\(preview.patchedBytes.count) 字节 (\(preview.patchedInstructions.count) 指令) @ \(preview.virtualAddress.compactHexString)"
                            : "\(preview.patchedBytes.count) B (\(preview.patchedInstructions.count) insns) @ \(preview.virtualAddress.compactHexString)"
                    )
                    .font(ColdTungstenTypography.addressMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: true, vertical: false)
                }

                VStack(alignment: .leading, spacing: 5) {
                    diffLineRow(
                        tag: localizer.L("BASE", "基线"),
                        tagColor: ColdTungstenPalette.coolPewter,
                        bytesHex: preview.originalBytes.map { String(format: "%02X", $0) }.joined(separator: " "),
                        instructions: preview.originalInstructions
                    )

                    diffLineRow(
                        tag: "CoW+",
                        tagColor: ColdTungstenPalette.warmCopper,
                        bytesHex: preview.patchedBytes.map { String(format: "%02X", $0) }.joined(separator: " "),
                        instructions: preview.patchedInstructions
                    )
                }

                if !preview.safetyReport.hazards.isEmpty {
                    ForEach(preview.safetyReport.hazards) { hazard in
                        HStack(alignment: .top, spacing: 6) {
                            Text(hazard.kind.rawValue)
                                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                                .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                                .fixedSize(horizontal: true, vertical: false)

                            Text(hazard.detail)
                                .font(ColdTungstenTypography.secondaryCaption)
                                .foregroundStyle(ColdTungstenPalette.steelWhite)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(6)
                        .background(ColdTungstenPalette.anodizedCrimson.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                }
            } else if let err = viewModel.patchPreviewError {
                HStack(spacing: 6) {
                    Image(systemName: "xmark.octagon.fill")
                        .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                    Text(err)
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private func diffLineRow(tag: String, tagColor: Color, bytesHex: String, instructions: [A64DecodedInstruction]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(tag)
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(tagColor)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1.5)
                    .background(tagColor.opacity(0.15))
                    .clipShape(RoundedRectangle(cornerRadius: 2.5))
                    .fixedSize(horizontal: true, vertical: false)

                Text(bytesHex)
                    .font(ColdTungstenTypography.disassemblyMono(size: 10.5, weight: .semibold))
                    .foregroundStyle(tag == "CoW+" ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 1.5) {
                ForEach(instructions) { insn in
                    Text(
                        ColdTungstenSyntaxHighlighter.attributedDisassembly(
                            for: insn,
                            useABIRegisterNames: true,
                            includeAutoComment: false
                        )
                    )
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.leading, 4)
        }
        .padding(6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(ColdTungstenPalette.gunmetalSlate)
        .clipShape(RoundedRectangle(cornerRadius: 3))
    }

    private var activeCoWPatchStackCard: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(localizer.L("Active CoW Patch Journal & Export", "活动 CoW 补丁日志与导出"), systemImage: "square.stack.3d.down.right")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Button("IPS") { viewModel.exportPatchContainer(format: "IPS") }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .fixedSize(horizontal: true, vertical: false)

                Button("IPS32") { viewModel.exportPatchContainer(format: "IPS32") }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .fixedSize(horizontal: true, vertical: false)

                Button("BPS") { viewModel.exportPatchContainer(format: "BPS") }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                    .fixedSize(horizontal: true, vertical: false)
            }

            if viewModel.overlayBuffer.patches.isEmpty {
                Text(localizer.L(
                    "No CoW overlay patches recorded. Assemble ARM64 instructions above to stage an overlay.",
                    "暂无 CoW 补丁记录。请在上方输入 ARM64 汇编指令生成补丁覆写。"
                ))
                .font(ColdTungstenTypography.secondaryCaption)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(viewModel.overlayBuffer.patches) { patch in
                    HStack(spacing: 8) {
                        Button {
                            viewModel.togglePatchRecord(patch)
                        } label: {
                            Image(systemName: patch.isEnabled ? "checkmark.square.fill" : "square")
                                .foregroundStyle(patch.isEnabled ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.mutedOffsetInk)
                        }
                        .buttonStyle(.plain)

                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(patch.virtualAddress?.compactHexString ?? patch.fileOffset.hexString)
                                    .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .bold))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text("\(patch.byteCount) B")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                                    .foregroundStyle(ColdTungstenPalette.warmCopper)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(ColdTungstenPalette.warmCopper.opacity(0.15))
                                    .clipShape(RoundedRectangle(cornerRadius: 2.5))
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(patch.patchedBytes.map { String(format: "%02X", $0) }.joined(separator: " "))
                                    .font(ColdTungstenTypography.disassemblyMono(size: 10.0))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)
                            }

                            if !patch.note.isEmpty {
                                Text(patch.note)
                                    .font(ColdTungstenTypography.secondaryCaption)
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }

                        Spacer(minLength: 4)

                        Button {
                            jumpToFileOffset(patch.fileOffset)
                        } label: {
                            Image(systemName: "scope")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        }
                        .buttonStyle(.plain)

                        Button {
                            viewModel.removePatchRecord(patch)
                        } label: {
                            Image(systemName: "trash")
                                .font(.system(size: 11))
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(7)
                    .background(ColdTungstenPalette.gunmetalSlate)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                }
            }

            Text(viewModel.lastExportedPatchSummary)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var machOCodeDirectoryReSignerCard: some View {
        let report = viewModel.codeSignatureReport
        let resign = viewModel.lastReSignResult
        let baseHash = (resign?.previousCDHashHex ?? viewModel.baseSignatureReport?.cdHashHex ?? "none").prefix(24)
        let activeHash = (resign?.updatedCDHashHex ?? report?.cdHashHex ?? "unsigned").prefix(24)
        let isValidAfterResign = resign?.verificationReport.isValid ?? report?.isValid ?? false

        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(localizer.L("Mach-O LC_CODE_SIGNATURE SHA-256 Re-Signer", "Mach-O LC_CODE_SIGNATURE SHA-256 重签名"), systemImage: "signature")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Button {
                    viewModel.reSignActiveMachOBinary()
                } label: {
                    Label(localizer.L("Re-Sign Ad-Hoc", "临时重签名"), systemImage: "checkmark.seal.fill")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, isActive: true, compact: true))
                .fixedSize(horizontal: true, vertical: false)
            }

            HStack(spacing: 8) {
                cdHashComparisonBox(
                    label: localizer.L("ORIGINAL CDHASH (SHA-256)", "原始 CDHASH (SHA-256)"),
                    hashPrefix: String(baseHash),
                    accent: ColdTungstenPalette.coolPewter
                )

                cdHashComparisonBox(
                    label: localizer.L("REBUILT CDHASH (AD-HOC)", "重建 CDHASH (临时签名)"),
                    hashPrefix: String(activeHash),
                    accent: isValidAfterResign ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber
                )
            }

            if let verify = resign?.verificationReport ?? report {
                HStack(spacing: 10) {
                    Text(verify.isValid ? localizer.L("VALID AD-HOC", "临时签名有效") : localizer.L("DIRTY PAGE SLOTS", "存在脏页槽位"))
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                        .foregroundStyle(verify.isValid ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background((verify.isValid ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber).opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .fixedSize(horizontal: true, vertical: false)

                    Text(
                        localizer.language == .zhHans
                            ? "槽位: \(verify.verifiedCodeSlots)/\(verify.totalCodeSlots) SHA-256 页"
                            : "Slots: \(verify.verifiedCodeSlots)/\(verify.totalCodeSlots) SHA-256 pages"
                    )
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                    if let resign, !resign.recalculatedPageSlotIndices.isEmpty {
                        Text(
                            localizer.language == .zhHans
                                ? "已重算页 #\(resign.recalculatedPageSlotIndices.map(String.init).joined(separator: ","))"
                                : "Rehashed Page #\(resign.recalculatedPageSlotIndices.map(String.init).joined(separator: ","))"
                        )
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.warmCopper)
                        .fixedSize(horizontal: true, vertical: false)
                    }
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private func cdHashComparisonBox(label: String, hashPrefix: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .bold))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                .fixedSize(horizontal: true, vertical: false)

            Text(hashPrefix)
                .font(ColdTungstenTypography.disassemblyMono(size: 10.5, weight: .semibold))
                .foregroundStyle(accent)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(7)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .strokeBorder(accent.opacity(0.35), lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: 3))
    }

    // MARK: - Viewport & Byte Selection Helpers

    private func curatedInspectorRows(from rows: [DataInspectorFieldRow]) -> [DataInspectorFieldRow] {
        guard rows.count > 6 else { return rows }
        var picked: [DataInspectorFieldRow] = []
        let preferredKeywords = ["int8", "int16", "int32", "int64", "ULEB128", "ARM64"]
        for keyword in preferredKeywords {
            if let match = rows.first(where: { $0.label.localizedCaseInsensitiveContains(keyword) }),
               !picked.contains(where: { $0.id == match.id }) {
                picked.append(match)
            }
        }
        for fallback in rows where picked.count < 6 {
            if !picked.contains(where: { $0.id == fallback.id }) {
                picked.append(fallback)
            }
        }
        return Array(picked.prefix(6))
    }

    private func selectByte(fileOffset: FileOffset, virtualAddress: VirtualAddress?) {
        viewModel.selectedHexByteOffset = fileOffset
        if let va = virtualAddress {
            viewModel.patchTargetAddressText = va.compactHexString
            cursorBus.jump(
                toAddress: va,
                in: viewModel.loadedImage,
                functions: viewModel.functions
            )
            viewModel.recomputeLivePatchPreview()
        }
    }

    private func jumpToFileOffset(_ offset: FileOffset) {
        let total = UInt64(max(1, viewModel.overlayBuffer.count))
        let clamped = min(offset.rawValue, total - 1)
        viewModel.selectedHexByteOffset = FileOffset(clamped)
        viewModel.hexScrollOffset = FileOffset((clamped / 16) * 16)
        if let va = viewModel.loadedImage?.virtualAddress(for: FileOffset(clamped)) {
            cursorBus.jump(toAddress: va, in: viewModel.loadedImage, functions: viewModel.functions)
        }
    }

    private func stepHexViewport(by delta: Int64) {
        let current = Int64(viewModel.hexScrollOffset.rawValue)
        let maxOff = Int64(max(0, viewModel.overlayBuffer.count - 16))
        let next = UInt64(max(0, min(maxOff, current + delta)))
        viewModel.hexScrollOffset = FileOffset((next / 16) * 16)
        viewModel.selectedHexByteOffset = viewModel.hexScrollOffset
    }

    private func syncHexViewportToCursor() {
        let va = cursorBus.currentLocation.virtualAddress
        if let off = viewModel.loadedImage?.fileOffset(for: va) {
            jumpToFileOffset(off)
        }
    }
}
