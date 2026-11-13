import AppKit
import Foundation
import MachCFGEngine
import MachGraphModels
import MachMicroDecompiler
import MachProjectStore
import MachWorkbenchShell
import SwiftUI

// MARK: - Side-by-Side Synchronized Disassembly/CFG <-> Pseudo-C Split Studio View

@MainActor
public struct SynchronizedDecompilerSplitStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    public let leftPaneMode: WorkbenchPaneTab
    @ObservedObject private var localizer: MachLocalizer = .shared

    public init(
        viewModel: MachStudioViewModel,
        leftPaneMode: WorkbenchPaneTab = .disassembly
    ) {
        self.viewModel = viewModel
        self.leftPaneMode = leftPaneMode
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Synchronized Split Status Banner
            HStack(spacing: 8) {
                Image(systemName: "link")
                    .font(.system(size: 10.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)

                Text(localizer.L("SYNCHRONIZED SPLIT BUS", "同步分屏总线"))
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                    .fixedSize()

                if let fn = viewModel.activeFunction {
                    Text(viewModel.displayFunctionName(fn))
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .fixedSize()
                }

                Text("@ \(viewModel.cursorBus.currentLocation.virtualAddress.compactHexString)")
                    .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .fixedSize()

                Spacer(minLength: 8)

                // Left Pane Mode Switcher (`Disassembly` vs `CFG Graph`)
                HStack(spacing: 4) {
                    Button(localizer.L("Left: Disassembly", "左侧: 反汇编")) {
                        viewModel.cursorBus.enableSideBySideSplit(primary: .disassembly, secondary: .pseudoC)
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: leftPaneMode == .disassembly ? .accentSapphire : .standard,
                        isActive: leftPaneMode == .disassembly,
                        compact: true
                    ))

                    Button(localizer.L("Left: CFG Graph", "左侧: 控制流图")) {
                        viewModel.cursorBus.enableSideBySideSplit(primary: .cfgGraph, secondary: .pseudoC)
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: leftPaneMode == .cfgGraph ? .accentSapphire : .standard,
                        isActive: leftPaneMode == .cfgGraph,
                        compact: true
                    ))

                    Button(localizer.L("Exit Split", "退出分屏")) {
                        viewModel.cursorBus.disableSplitView()
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(alignment: .bottom) {
                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)
            }

            // Equal 50/50 Split Columns Separated by 1pt Tungsten Seam
            GeometryReader { geo in
                let halfW = max(240.0, (geo.size.width - 1.0) * 0.5)
                HStack(spacing: 0) {
                    Group {
                        if leftPaneMode == .cfgGraph {
                            InteractiveCFGCanvasStudioView(viewModel: viewModel, compactForSplit: true)
                        } else {
                            LinearDisassemblyStudioView(viewModel: viewModel, compactForSplit: true)
                        }
                    }
                    .frame(width: halfW, height: geo.size.height)

                    Rectangle()
                        .fill(ColdTungstenPalette.tungstenSeam)
                        .frame(width: 1.0, height: geo.size.height)

                    PseudoCDecompilerStudioView(viewModel: viewModel, compactForSplit: true)
                        .frame(width: max(240.0, geo.size.width - halfW - 1.0), height: geo.size.height)
                }
            }
        }
        .background(ColdTungstenPalette.gunmetalSlate)
    }
}

// MARK: - SSA Micro-IR Structured Pseudo-C Decompiler Studio View (`.pseudoC`)

@MainActor
public struct PseudoCDecompilerStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    public let compactForSplit: Bool

    @ObservedObject private var localizer: MachLocalizer = .shared
    @State private var showVariablesAndStructsDeck: Bool = true
    @State private var hoveredLineNumber: Int? = nil
    @State private var showNewStructEditor: Bool = false
    @State private var newStructName: String = "MGPacketFrame"
    @State private var newStructField1Name: String = "opcode"
    @State private var newStructField2Name: String = "payload_ptr"

    public init(viewModel: MachStudioViewModel, compactForSplit: Bool = false) {
        self.viewModel = viewModel
        self.compactForSplit = compactForSplit
    }

    private var decompiled: DecompiledFunctionOutput? {
        viewModel.activeDecompiledOutput
    }

    public var body: some View {
        VStack(spacing: 0) {
            decompilerHeaderBar

            if let output = decompiled {
                ssaMetricsSummaryStrip(output)

                // Main Pseudo-C Source Area (+ Optional Ghidra 12.1.4 Side-by-Side Diff)
                HStack(spacing: 0) {
                    pseudoCCodeViewport(output)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)

                    if viewModel.isGhidraSideBySideEnabled && !compactForSplit {
                        Rectangle()
                            .fill(ColdTungstenPalette.tungstenSeam)
                            .frame(width: 1)

                        ghidraSideBySideColumn(output)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }

                if showVariablesAndStructsDeck {
                    Rectangle()
                        .fill(ColdTungstenPalette.tungstenSeam)
                        .frame(height: 1)

                    variablesAndStructMapperDeck(output)
                }
            } else {
                emptyDecompilerState
            }
        }
        .background(ColdTungstenPalette.gunmetalSlate)
    }

    // MARK: - Header Bar & SSA Metrics Strip

    private var decompilerHeaderBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Image(systemName: "curlybraces")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                Text(compactForSplit ? localizer.L("SSA Pseudo-C", "SSA 伪C") : localizer.L("SSA Micro-IR Pseudo-C Decompiler", "SSA 微IR 伪C反编译器"))
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize()

                // Function Quick-Switch Chips (shown in full-width Pseudo-C view; split mode uses top Split Bus bar)
                if !compactForSplit {
                    ForEach(viewModel.functions.filter { !$0.isThunk }.prefix(4)) { fn in
                        let isSelected = viewModel.activeFunction?.address == fn.address
                        Button(compactSelectorName(viewModel.displayFunctionName(fn))) {
                            viewModel.cursorBus.selectFunction(fn, in: viewModel.loadedImage, originPane: .pseudoC)
                        }
                        .buttonStyle(TungstenToolbarButtonStyle(
                            role: isSelected ? .accentSapphire : .standard,
                            isActive: isSelected,
                            compact: true
                        ))
                    }
                }

                Spacer(minLength: 4)

                Button(showVariablesAndStructsDeck ? localizer.L("Vars & Structs", "变量与结构体") : localizer.L("Show Vars", "显示变量")) {
                    showVariablesAndStructsDeck.toggle()
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: showVariablesAndStructsDeck ? .accentSapphire : .standard,
                    isActive: showVariablesAndStructsDeck,
                    compact: true
                ))

                if !compactForSplit {
                    Button {
                        viewModel.toggleOrRunGhidraComparison()
                    } label: {
                        Label(
                            viewModel.isGhidraSideBySideEnabled
                                ? localizer.L("Ghidra 12.1.4: ON", "Ghidra 12.1.4: 开启")
                                : localizer.L("Ghidra 12.1.4 Diff", "Ghidra 12.1.4 对比"),
                            systemImage: "square.split.2x1"
                        )
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: viewModel.isGhidraSideBySideEnabled ? .cautionAmber : .standard,
                        isActive: viewModel.isGhidraSideBySideEnabled,
                        compact: true
                    ))
                }

                Button {
                    if let src = decompiled?.fullSourceText {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(src, forType: .string)
                        let lineCount = src.components(separatedBy: "\n").count
                        viewModel.toastController.enqueue(
                            kind: .success,
                            title: localizer.L("Copied Structured Pseudo-C", "已复制结构化伪C代码"),
                            detail: localizer.language == .zhHans
                                ? "已复制 \(lineCount) 行代码至剪贴板"
                                : "\(lineCount) lines copied to clipboard"
                        )
                    }
                } label: {
                    Label(localizer.L("Copy C", "复制 C"), systemImage: "doc.on.doc")
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }
            .padding(.horizontal, 10)
            .frame(height: ColdTungstenMetrics.panelHeaderHeight)
        }
        .background(ColdTungstenPalette.brushedSteel)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    private func ssaMetricsSummaryStrip(_ output: DecompiledFunctionOutput) -> some View {
        let confidencePct = Int((output.confidenceScore * 100.0).rounded())
        let confColor: Color = confidencePct >= 88
            ? ColdTungstenPalette.signalEmerald
            : ColdTungstenPalette.tungstenAmber

        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 10) {
                ssaMetricTag(localizer.L("SSA VARS", "SSA 变量"), "\(output.ssaVariableCount)", color: ColdTungstenPalette.tungstenSapphire)
                ssaMetricTag(localizer.L("DEAD STORES", "死存储消除"), "\(output.eliminatedDeadStoreCount)", color: ColdTungstenPalette.signalEmerald)
                ssaMetricTag(localizer.L("CONFIDENCE", "置信度"), "\(confidencePct)%", color: confColor)
                ssaMetricTag(localizer.L("PARAMS", "参数"), "\(output.parameters.count)", color: ColdTungstenPalette.steelWhite)
                ssaMetricTag(localizer.L("LOCALS", "局部变量"), "\(output.localVariables.count)", color: ColdTungstenPalette.coolPewter)
                ssaMetricTag(localizer.L("IR BLOCKS", "IR 块"), "\(output.microBlocks.count)", color: ColdTungstenPalette.coolPewter)
                if !compactForSplit {
                    ssaMetricTag(localizer.L("RETURN", "返回类型"), output.returnType.cTypeName, color: ColdTungstenPalette.tungstenAmber)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
        }
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }

    // MARK: - Syntax-Highlighted Structured Pseudo-C Viewport

    private func pseudoCCodeViewport(_ output: DecompiledFunctionOutput) -> some View {
        let cursorVA = viewModel.cursorBus.currentLocation.virtualAddress

        return ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                // Function Prototype Signature Banner
                HStack(spacing: 8) {
                    Text(localizer.L("// Cytron Dominance-Frontier SSA -> Structured C AST", "// Cytron 支配边界 SSA -> 结构化无 goto 伪C语法树"))
                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                        .fixedSize()
                    Spacer()
                    Text(output.functionAddress.compactHexString)
                        .font(ColdTungstenTypography.addressMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .fixedSize()
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(ColdTungstenPalette.chassisBackground.opacity(0.65))

                ForEach(output.renderedLines) { line in
                    let isCursorMatch = isLineMatchedToCursor(line: line, cursorVA: cursorVA)
                    let isHovered = hoveredLineNumber == line.lineNumber

                    HStack(alignment: .top, spacing: 8) {
                        // Line Number + Address Sync Gutter
                        HStack(spacing: 5) {
                            Rectangle()
                                .fill(isCursorMatch ? ColdTungstenPalette.tungstenSapphire : Color.clear)
                                .frame(width: 2.5, height: 15)

                            Text(String(format: "%02d", line.lineNumber))
                                .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                .frame(width: 20, alignment: .trailing)
                                .fixedSize()

                            if let mapped = line.mappedAddress {
                                Text(compactForSplit ? shortHexAddress(mapped) : mapped.compactHexString)
                                    .font(ColdTungstenTypography.addressMono(size: 10.5))
                                    .foregroundStyle(isCursorMatch ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
                                    .fixedSize()
                            } else {
                                Text(compactForSplit ? "      " : "          ")
                                    .font(ColdTungstenTypography.addressMono(size: 10.5))
                                    .fixedSize()
                            }
                        }
                        .frame(width: compactForSplit ? 78 : 112, alignment: .leading)

                        // Syntax-Highlighted Pseudo-C Tokens (Multi-Line Wrap Safe, Zero `…`)
                        Text(ColdTungstenSyntaxHighlighter.attributedPseudoCLine(line))
                            .font(ColdTungstenTypography.disassemblyMono(size: compactForSplit ? 11.5 : 12.0))
                            .fixedSize(horizontal: false, vertical: true)

                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2.5)
                    .background(
                        isCursorMatch
                            ? ColdTungstenPalette.activeSelectionFill
                            : (isHovered ? ColdTungstenPalette.milledControlHover.opacity(0.55) : Color.clear)
                    )
                    .contentShape(Rectangle())
                    .onHover { inside in
                        hoveredLineNumber = inside ? line.lineNumber : nil
                    }
                    .onTapGesture {
                        if let mapped = line.mappedAddress {
                            viewModel.cursorBus.jump(
                                toAddress: mapped,
                                in: viewModel.loadedImage,
                                functions: viewModel.functions,
                                originPane: .pseudoC,
                                recordHistory: true
                            )
                        }
                    }
                }
            }
            .padding(.bottom, 12)
        }
        .background(ColdTungstenPalette.gunmetalSlate)
    }

    private func isLineMatchedToCursor(line: PseudoCLineSpan, cursorVA: VirtualAddress) -> Bool {
        guard let mapped = line.mappedAddress else { return false }
        if mapped == cursorVA { return true }
        // Highlight compound expressions folded from adjacent ARM64 instructions (e.g. ADRP+ADD or CMP+B.cond)
        if cursorVA.rawValue >= mapped.rawValue && (cursorVA.rawValue - mapped.rawValue) <= 8 {
            return true
        }
        return false
    }

    private func shortHexAddress(_ addr: VirtualAddress) -> String {
        String(format: ":%04llx", addr.rawValue & 0xFFFF)
    }

    // MARK: - Optional Ghidra 12.1.4 Side-by-Side Reference Pane

    private func ghidraSideBySideColumn(_ output: DecompiledFunctionOutput) -> some View {
        let ghidraText = output.ghidraSideBySideSource
            ?? viewModel.ghidraDecompiledByFunction[output.functionAddress]
            ?? localizer.L(
                "/* Click 'Ghidra 12.1.4 Diff' to invoke analyzeHeadless DecompInterface */",
                "/* 点击「Ghidra 12.1.4 对比」调用 analyzeHeadless DecompInterface */"
            )

        return VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Circle()
                    .fill(viewModel.ghidraProbe.isAvailable ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                    .frame(width: 6, height: 6)
                Text("GHIDRA 12.1.4 DECOMPINTERFACE")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                    .fixedSize()
                Spacer()
                Text(viewModel.ghidraProbe.isAvailable ? localizer.L("HEADLESS READY", "无头引擎就绪") : localizer.L("REFERENCE BASELINE", "参考基线"))
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize()
            }
            .padding(.horizontal, 10)
            .frame(height: 26)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(alignment: .bottom) {
                Rectangle().fill(ColdTungstenPalette.tungstenSeam).frame(height: 1)
            }

            ScrollView {
                Text(ghidraText)
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(ColdTungstenPalette.chassisBackground.opacity(0.6))
        }
    }

    // MARK: - Recovered Stack Frame / SSA Variables & Custom C Struct Mapper Deck

    private func variablesAndStructMapperDeck(_ output: DecompiledFunctionOutput) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "memorychip")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                Text(localizer.L("RECOVERED VARIABLES & CUSTOM C STRUCT FIELD MAPPER", "恢复变量与自定义C结构体映射"))
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize()

                Spacer()

                Button(showNewStructEditor ? localizer.L("Close Builder", "关闭构建器") : localizer.L("+ Define C Struct", "+ 定义 C 结构体")) {
                    showNewStructEditor.toggle()
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))
            }

            if showNewStructEditor {
                inlineStructBuilderBar
            }

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(alignment: .top, spacing: 8) {
                    // Recovered Parameters & Locals Chips
                    ForEach(Array(output.parameters.enumerated()), id: \.offset) { idx, param in
                        variableCard(
                            kind: localizer.language == .zhHans ? "参数 x\(idx)" : "ARG x\(idx)",
                            name: param.name,
                            cType: param.type.cTypeName,
                            accent: ColdTungstenPalette.tungstenSapphire
                        )
                    }
                    ForEach(Array(output.localVariables.prefix(6).enumerated()), id: \.offset) { _, local in
                        variableCard(
                            kind: localizer.L("SSA LOCAL", "SSA 局部"),
                            name: local.name,
                            cType: local.type.cTypeName,
                            accent: ColdTungstenPalette.signalEmerald
                        )
                    }

                    // Persisted `.machproj` Custom C Struct Cards
                    ForEach(viewModel.customStructs.prefix(compactForSplit ? 1 : 3)) { def in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 5) {
                                Text("struct \(def.name)")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                                    .fixedSize()
                                Text("(\(def.totalByteSize)B)")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    .fixedSize()
                            }
                            let fieldPreview = def.fields.prefix(2).map { "+\(String(format: "0x%02X", $0.offset)) \($0.name)" }.joined(separator: " · ")
                            Text(fieldPreview)
                                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                                .fixedSize()
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                        .background(ColdTungstenPalette.gunmetalSlate)
                        .overlay(
                            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                                .strokeBorder(ColdTungstenPalette.tungstenAmber.opacity(0.45), lineWidth: 1)
                        )
                    }
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(ColdTungstenPalette.chassisBackground)
    }

    private var inlineStructBuilderBar: some View {
        HStack(spacing: 8) {
            Text("struct")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                .foregroundStyle(ColdTungstenPalette.anodizedCrimson)
                .fixedSize()

            TextField("StructName", text: $newStructName)
                .textFieldStyle(.plain)
                .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .frame(width: 120)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))

            Text("+0x00 uint64_t")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize()

            TextField("field_0", text: $newStructField1Name)
                .textFieldStyle(.plain)
                .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .frame(width: 90)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))

            Text("+0x08 const char *")
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize()

            TextField("field_8", text: $newStructField2Name)
                .textFieldStyle(.plain)
                .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .frame(width: 95)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))

            Button(localizer.L("Commit Struct", "提交结构体")) {
                let cleanName = newStructName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !cleanName.isEmpty else { return }
                let created = CustomStructDefinition(
                    name: cleanName,
                    totalByteSize: 16,
                    alignment: 8,
                    fields: [
                        CustomStructField(name: newStructField1Name, offset: 0, byteSize: 8, typeExpr: .intType(bits: 64, signed: false)),
                        CustomStructField(name: newStructField2Name, offset: 8, byteSize: 8, typeExpr: .cString)
                    ]
                )
                viewModel.saveStructDefinition(created)
                showNewStructEditor = false
            }
            .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, compact: true))

            Spacer()
        }
    }

    private func variableCard(kind: String, name: String, cType: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(kind)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .bold))
                .foregroundStyle(accent)
                .fixedSize()
            HStack(spacing: 5) {
                Text(cType)
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                    .fixedSize()
                Text(name)
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize()
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1)
        )
    }

    private func ssaMetricTag(_ key: String, _ val: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Text(key)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            Text(val)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                .foregroundStyle(color)
        }
        .fixedSize()
    }

    private func compactSelectorName(_ name: String) -> String {
        if name.hasPrefix("-[") || name.hasPrefix("+[") {
            if let sp = name.firstIndex(of: " ") {
                let tail = name[name.index(after: sp)...].replacingOccurrences(of: "]", with: "")
                return "\(name.prefix(2))\(tail)"
            }
        }
        return name
    }

    private var emptyDecompilerState: some View {
        VStack(spacing: 8) {
            Image(systemName: "curlybraces")
                .font(.system(size: 26))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            Text(localizer.L(
                "Select a non-thunk ARM64 function to inspect SSA Micro-IR Structured Pseudo-C.",
                "请选择非跳板 ARM64 函数以查看 SSA 微IR 结构化伪C代码。"
            ))
            .font(ColdTungstenTypography.bodyText)
            .foregroundStyle(ColdTungstenPalette.coolPewter)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
