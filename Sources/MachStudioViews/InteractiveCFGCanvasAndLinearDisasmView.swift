import AppKit
import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachPatchAndHexEngine
import MachWorkbenchShell
import SwiftUI

// MARK: - Interactive Sugiyama Layered CFG Canvas Studio View (`.cfgGraph`)

@MainActor
public struct InteractiveCFGCanvasStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    public let compactForSplit: Bool

    @State private var userZoomMultiplier: CGFloat = 1.0
    @State private var userPanOffset: CGSize = .zero
    @State private var activeDragTranslation: CGSize = .zero
    @State private var trackedFunctionAddress: VirtualAddress? = nil

    public init(viewModel: MachStudioViewModel, compactForSplit: Bool = false) {
        self.viewModel = viewModel
        self.compactForSplit = compactForSplit
    }

    private var activeFunction: RecoveredFunction? {
        viewModel.activeFunction
    }

    private var activeLayout: SugiyamaCFGLayout? {
        viewModel.activeCFGLayout
    }

    private var domDepthByBlockID: [Int: Int] {
        guard let fn = activeFunction else { return [:] }
        var map: [Int: Int] = [:]
        for node in fn.dominatorTree {
            map[node.blockID] = node.depth
        }
        return map
    }

    public var body: some View {
        VStack(spacing: 0) {
            cfgControlHeaderBar
            if !compactForSplit {
                dominatorAndLoopSummaryStrip
            }

            if let fn = activeFunction, let layout = activeLayout, !layout.nodes.isEmpty {
                GeometryReader { geo in
                    let fit = computeViewportTransform(viewport: geo.size, layout: layout)
                    ZStack(alignment: .bottomTrailing) {
                        ZStack(alignment: .topLeading) {
                            // 1. Cold Tungsten Engineering Coordinate Grid + Routed Orthogonal Edges
                            Canvas { context, size in
                                drawEngineeringGrid(context: &context, size: size, scale: fit.scale, offset: fit.offset)
                                drawRoutedCFGEdges(
                                    context: &context,
                                    layout: layout,
                                    scale: fit.scale,
                                    offset: fit.offset,
                                    highlightBackEdges: viewModel.preferencesStore.preferences.highlightLoopBackEdges
                                )
                            }

                            // 2. Crisp Positioned Basic-Block Node Cards
                            ForEach(layout.nodes) { nodeLayout in
                                if let block = fn.blocks.first(where: { $0.id == nodeLayout.blockID }) {
                                    let rect = transformedNodeRect(nodeLayout.frame, scale: fit.scale, offset: fit.offset)
                                    CFGBasicBlockNodeCardView(
                                        block: block,
                                        function: fn,
                                        dominatorDepth: domDepthByBlockID[block.id] ?? 0,
                                        showDomBadge: viewModel.preferencesStore.preferences.showDominatorDepthBadges,
                                        useABIRegisters: viewModel.preferencesStore.preferences.useABIRegisterNames,
                                        activeInstructionAddress: viewModel.cursorBus.currentLocation.virtualAddress,
                                        isSelectedBlock: viewModel.cursorBus.activeBlockID == block.id
                                            || blockContainsCursor(block),
                                        overlayBuffer: viewModel.overlayBuffer,
                                        loadedImage: viewModel.loadedImage,
                                        scale: fit.scale,
                                        onSelectInstruction: { insn in
                                            viewModel.cursorBus.jump(
                                                to: SynchronizedCursorLocation(
                                                    virtualAddress: insn.address,
                                                    fileOffset: viewModel.loadedImage?.fileOffset(for: insn.address),
                                                    functionAddress: fn.address,
                                                    blockID: block.id,
                                                    originPane: .cfgGraph
                                                ),
                                                recordHistory: true
                                            )
                                        }
                                    )
                                    .frame(width: max(120, rect.width), height: max(42, rect.height))
                                    .position(x: rect.midX, y: rect.midY)
                                }
                            }
                        }
                        .frame(width: geo.size.width, height: geo.size.height)
                        .contentShape(Rectangle())
                        .gesture(
                            DragGesture(minimumDistance: 3)
                                .onChanged { value in
                                    activeDragTranslation = value.translation
                                }
                                .onEnded { value in
                                    userPanOffset.width += value.translation.width
                                    userPanOffset.height += value.translation.height
                                    activeDragTranslation = .zero
                                }
                        )
                        .gesture(
                            MagnificationGesture()
                                .onChanged { mag in
                                    userZoomMultiplier = min(2.4, max(0.45, mag))
                                }
                        )

                        // 3. Corner Interactive Minimap Radar
                        if viewModel.preferencesStore.preferences.showCFGOverviewMinimap && !compactForSplit {
                            CFGMinimapRadarOverlayView(
                                function: fn,
                                layout: layout,
                                viewportSize: geo.size,
                                currentScale: fit.scale,
                                currentOffset: fit.offset,
                                activeBlockID: viewModel.cursorBus.activeBlockID,
                                onRecenterAtGraphPoint: { graphPt in
                                    let desiredX = (geo.size.width * 0.5) - (graphPt.x * fit.scale)
                                    let desiredY = (geo.size.height * 0.5) - (graphPt.y * fit.scale)
                                    userPanOffset = CGSize(
                                        width: desiredX - fit.baseOffset.width,
                                        height: desiredY - fit.baseOffset.height
                                    )
                                }
                            )
                            .padding(12)
                        }
                    }
                    .clipped()
                    .background(ColdTungstenPalette.graphCanvas)
                    .onChange(of: fn.address) { _, newAddr in
                        if trackedFunctionAddress != newAddr {
                            trackedFunctionAddress = newAddr
                            userZoomMultiplier = 1.0
                            userPanOffset = .zero
                            activeDragTranslation = .zero
                        }
                    }
                }
            } else {
                emptyCFGStateView
            }
        }
        .background(ColdTungstenPalette.graphCanvas)
    }

    // MARK: - Top CFG Control Header Bar

    private var cfgControlHeaderBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                Text(compactForSplit ? "CFG" : "Sugiyama Layered CFG")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize()

                // Quick Function Selector Pills (Non-Thunk Functions)
                ForEach(viewModel.functions.filter { !$0.isThunk }.prefix(compactForSplit ? 2 : 3)) { fn in
                    let selected = activeFunction?.address == fn.address
                    Button {
                        userZoomMultiplier = 1.0
                        userPanOffset = .zero
                        viewModel.cursorBus.selectFunction(fn, in: viewModel.loadedImage, originPane: .cfgGraph)
                    } label: {
                        Text(shortFunctionChipLabel(viewModel.displayFunctionName(fn)))
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: selected ? .bold : .medium))
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(
                        role: selected ? .accentSapphire : .standard,
                        isActive: selected,
                        compact: true
                    ))
                }

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(width: 1, height: 14)

                // Edge Semantic Legend Pills
                edgeLegendChip(label: "True", color: ColdTungstenPalette.signalEmerald, dashed: false)
                edgeLegendChip(label: "False", color: ColdTungstenPalette.anodizedCrimson, dashed: false)
                edgeLegendChip(label: "Switch", color: ColdTungstenPalette.tungstenAmber, dashed: false)
                edgeLegendChip(label: "Back-Edge", color: ColdTungstenPalette.warmCopper, dashed: true)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(width: 1, height: 14)

                // Zoom & Fit Controls
                HStack(spacing: 4) {
                    Button {
                        userZoomMultiplier = max(0.45, userZoomMultiplier - 0.15)
                    } label: {
                        Image(systemName: "minus.magnifyingglass")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                    Text("\(Int((userZoomMultiplier * 100).rounded()))%")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize()

                    Button {
                        userZoomMultiplier = min(2.4, userZoomMultiplier + 0.15)
                    } label: {
                        Image(systemName: "plus.magnifyingglass")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                    Button("Fit") {
                        userZoomMultiplier = 1.0
                        userPanOffset = .zero
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                }

                if !compactForSplit {
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
                }
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

    // MARK: - Dominator & Natural Loop Structural Summary Strip

    private var dominatorAndLoopSummaryStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 9) {
                if let fn = activeFunction, let layout = activeLayout {
                    cfgMetricPill(title: "FN", value: viewModel.displayFunctionName(fn), accent: ColdTungstenPalette.steelWhite)
                    cfgMetricPill(title: "ENTRY", value: fn.address.compactHexString, accent: ColdTungstenPalette.tungstenSapphire)
                    cfgMetricPill(title: "BLOCKS", value: "\(fn.blocks.count)", accent: ColdTungstenPalette.steelWhite)
                    cfgMetricPill(title: "EDGES", value: "\(fn.edges.count)", accent: ColdTungstenPalette.coolPewter)
                    cfgMetricPill(title: "LAYERS", value: "\(layout.layerCount)", accent: ColdTungstenPalette.coolPewter)
                    cfgMetricPill(
                        title: "COMPLEXITY",
                        value: "CC \(fn.cyclomaticComplexity)",
                        accent: fn.cyclomaticComplexity >= 5 ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.signalEmerald
                    )
                    let maxDomDepth = fn.dominatorTree.map(\.depth).max() ?? 0
                    cfgMetricPill(title: "DOM", value: "D\(maxDomDepth)", accent: ColdTungstenPalette.tungstenSapphire)
                    cfgMetricPill(
                        title: "LOOPS",
                        value: "\(fn.naturalLoops.count)",
                        accent: fn.naturalLoops.isEmpty ? ColdTungstenPalette.mutedOffsetInk : ColdTungstenPalette.warmCopper
                    )
                    if fn.usesPAC {
                        cfgMetricPill(title: "AUTH", value: "ARM64E PAC", accent: ColdTungstenPalette.tungstenAmber)
                    }
                    if !fn.jumpTables.isEmpty {
                        cfgMetricPill(title: "JUMP TABLES", value: "\(fn.jumpTables.count)", accent: ColdTungstenPalette.tungstenAmber)
                    }
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

    // MARK: - Deterministic Auto-Fit Transform & Edge Canvas Rendering

    private struct ViewportTransform {
        let scale: CGFloat
        let baseOffset: CGSize
        let offset: CGSize
    }

    private func computeViewportTransform(viewport: CGSize, layout: SugiyamaCFGLayout) -> ViewportTransform {
        let graphW = max(120.0, CGFloat(layout.canvasWidth))
        let graphH = max(100.0, CGFloat(layout.canvasHeight))
        let padX: CGFloat = compactForSplit ? 18.0 : 28.0
        let padY: CGFloat = compactForSplit ? 18.0 : 24.0
        let availW = max(100.0, viewport.width - padX * 2.0)
        let availH = max(100.0, viewport.height - padY * 2.0)

        let autoFitScale = min(1.06, max(0.54, min(availW / graphW, availH / graphH)))
        let effectiveScale = min(2.4, max(0.42, autoFitScale * userZoomMultiplier))

        let scaledW = graphW * effectiveScale
        let scaledH = graphH * effectiveScale
        let baseOffX = (viewport.width - scaledW) * 0.5
        let baseOffY = max(12.0, (viewport.height - scaledH) * 0.5)

        let totalOff = CGSize(
            width: baseOffX + userPanOffset.width + activeDragTranslation.width,
            height: baseOffY + userPanOffset.height + activeDragTranslation.height
        )
        return ViewportTransform(scale: effectiveScale, baseOffset: CGSize(width: baseOffX, height: baseOffY), offset: totalOff)
    }

    private func transformedNodeRect(_ rect: CGRectBridge, scale: CGFloat, offset: CGSize) -> CGRect {
        CGRect(
            x: CGFloat(rect.x) * scale + offset.width,
            y: CGFloat(rect.y) * scale + offset.height,
            width: CGFloat(rect.width) * scale,
            height: CGFloat(rect.height) * scale
        )
    }

    private func blockContainsCursor(_ block: BasicBlock) -> Bool {
        let va = viewModel.cursorBus.currentLocation.virtualAddress
        return va >= block.startAddress && va < block.endAddress
    }

    private func drawEngineeringGrid(context: inout GraphicsContext, size: CGSize, scale: CGFloat, offset: CGSize) {
        let step = max(18.0, 28.0 * scale)
        let startX = offset.width.truncatingRemainder(dividingBy: step)
        let startY = offset.height.truncatingRemainder(dividingBy: step)

        var gridPath = Path()
        var x = startX
        while x < size.width {
            gridPath.move(to: CGPoint(x: x, y: 0))
            gridPath.addLine(to: CGPoint(x: x, y: size.height))
            x += step
        }
        var y = startY
        while y < size.height {
            gridPath.move(to: CGPoint(x: 0, y: y))
            gridPath.addLine(to: CGPoint(x: size.width, y: y))
            y += step
        }
        context.stroke(
            gridPath,
            with: .color(ColdTungstenPalette.tungstenSeam.opacity(0.22)),
            lineWidth: 0.5
        )
    }

    private func drawRoutedCFGEdges(
        context: inout GraphicsContext,
        layout: SugiyamaCFGLayout,
        scale: CGFloat,
        offset: CGSize,
        highlightBackEdges: Bool
    ) {
        for route in layout.routes where route.waypoints.count >= 2 {
            let edge = route.edge
            let strokeColor = studioEdgeColor(kind: edge.kind, isBackEdge: edge.isBackEdge && highlightBackEdges)

            let pts: [CGPoint] = route.waypoints.map { wp in
                CGPoint(
                    x: CGFloat(wp.x) * scale + offset.width,
                    y: CGFloat(wp.y) * scale + offset.height
                )
            }

            var path = Path()
            path.move(to: pts[0])
            for pt in pts.dropFirst() {
                path.addLine(to: pt)
            }

            let lineWidth: CGFloat = edge.isBackEdge ? 1.85 : 1.55
            if edge.isBackEdge {
                context.stroke(
                    path,
                    with: .color(strokeColor),
                    style: StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round, dash: [5.5, 4.0])
                )
            } else {
                context.stroke(
                    path,
                    with: .color(strokeColor),
                    style: StrokeStyle(lineWidth: lineWidth, lineCap: .round, lineJoin: .round)
                )
            }

            // Directional Arrowhead at Destination Port
            let tip = pts[pts.count - 1]
            let prev = pts[pts.count - 2]
            let dx = tip.x - prev.x
            let dy = tip.y - prev.y
            let segLen = hypot(dx, dy)
            if segLen > 1.0 {
                let ux = dx / segLen
                let uy = dy / segLen
                let arrowLen: CGFloat = max(5.5, 7.5 * min(1.1, scale))
                let arrowHalfW: CGFloat = max(3.2, 4.4 * min(1.1, scale))
                let baseCenter = CGPoint(x: tip.x - ux * arrowLen, y: tip.y - uy * arrowLen)
                let leftWing = CGPoint(x: baseCenter.x - uy * arrowHalfW, y: baseCenter.y + ux * arrowHalfW)
                let rightWing = CGPoint(x: baseCenter.x + uy * arrowHalfW, y: baseCenter.y - ux * arrowHalfW)

                var arrow = Path()
                arrow.move(to: tip)
                arrow.addLine(to: leftWing)
                arrow.addLine(to: rightWing)
                arrow.closeSubpath()
                context.fill(arrow, with: .color(strokeColor))
            }

            // Crisp Edge Semantic Badge (`T`, `F`, `case N`, `LOOP`)
            let badgeText: String? = {
                if edge.isBackEdge { return "LOOP" }
                return route.label ?? edge.kind.displayLabel
            }()
            if let badgeText, scale >= 0.55 {
                let anchor = midpointAlongPolyline(pts)
                let pillW = CGFloat(max(18, badgeText.count * 6 + 10))
                let pillH: CGFloat = 15.0
                let pillRect = CGRect(
                    x: anchor.x - pillW * 0.5,
                    y: anchor.y - pillH * 0.5,
                    width: pillW,
                    height: pillH
                )
                let rounded = Path(roundedRect: pillRect, cornerRadius: 3.0)
                context.fill(rounded, with: .color(ColdTungstenPalette.chassisBackground))
                context.stroke(rounded, with: .color(strokeColor.opacity(0.85)), lineWidth: 1.0)
                let resolvedText = context.resolve(
                    Text(badgeText)
                        .font(.system(size: 9.0, weight: .bold, design: .monospaced))
                        .foregroundColor(strokeColor)
                )
                context.draw(resolvedText, at: anchor, anchor: .center)
            }
        }
    }

    private func studioEdgeColor(kind: CFGEdgeKind, isBackEdge: Bool) -> Color {
        if isBackEdge {
            return ColdTungstenPalette.warmCopper
        }
        switch kind {
        case .conditionalTrue:
            return ColdTungstenPalette.signalEmerald
        case .conditionalFalse:
            return ColdTungstenPalette.anodizedCrimson
        case .switchCase:
            return ColdTungstenPalette.tungstenAmber
        case .unconditional, .fallthroughEdge:
            return ColdTungstenPalette.tungstenSapphire
        }
    }

    private func midpointAlongPolyline(_ points: [CGPoint]) -> CGPoint {
        guard points.count >= 2 else { return points.first ?? .zero }
        if points.count == 2 {
            return CGPoint(x: (points[0].x + points[1].x) * 0.5, y: (points[0].y + points[1].y) * 0.5)
        }
        let midIdx = points.count / 2
        let a = points[midIdx - 1]
        let b = points[midIdx]
        return CGPoint(x: (a.x + b.x) * 0.5, y: (a.y + b.y) * 0.5)
    }

    private func shortFunctionChipLabel(_ fullName: String) -> String {
        if fullName.hasPrefix("-[") || fullName.hasPrefix("+[") {
            if let spaceIdx = fullName.firstIndex(of: " ") {
                let sel = fullName[fullName.index(after: spaceIdx)...].replacingOccurrences(of: "]", with: "")
                return "\(fullName.prefix(2))\(sel)"
            }
        }
        return fullName
    }

    private func edgeLegendChip(label: String, color: Color, dashed: Bool) -> some View {
        HStack(spacing: 4) {
            if dashed {
                HStack(spacing: 1.5) {
                    Rectangle().fill(color).frame(width: 4, height: 2)
                    Rectangle().fill(color).frame(width: 4, height: 2)
                }
            } else {
                Rectangle()
                    .fill(color)
                    .frame(width: 9, height: 2)
            }
            Text(label)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
        }
        .fixedSize()
    }

    private func cfgMetricPill(title: String, value: String, accent: Color) -> some View {
        HStack(spacing: 4) {
            Text(title)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            Text(value)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                .foregroundStyle(accent)
        }
        .fixedSize()
    }

    private var emptyCFGStateView: some View {
        VStack(spacing: 8) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 26))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            Text("Select an executable ARM64 function from the Navigator to render its Sugiyama Control Flow Graph.")
                .font(ColdTungstenTypography.bodyText)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Basic Block Node Card View

@MainActor
private struct CFGBasicBlockNodeCardView: View {
    let block: BasicBlock
    let function: RecoveredFunction
    let dominatorDepth: Int
    let showDomBadge: Bool
    let useABIRegisters: Bool
    let activeInstructionAddress: VirtualAddress
    let isSelectedBlock: Bool
    let overlayBuffer: SparseCoWByteOverlayBuffer
    let loadedImage: LoadedBinaryImage?
    let scale: CGFloat
    let onSelectInstruction: (A64DecodedInstruction) -> Void

    private var blockHasPAC: Bool {
        block.instructions.contains { $0.group == .pacPointerAuth }
    }

    private var borderAccent: Color {
        if isSelectedBlock {
            return ColdTungstenPalette.tungstenSapphire
        }
        if block.loopDepth > 0 {
            return ColdTungstenPalette.warmCopper.opacity(0.75)
        }
        if block.isEntry {
            return ColdTungstenPalette.signalEmerald.opacity(0.65)
        }
        return ColdTungstenPalette.tungstenSeam
    }

    var body: some View {
        let fontSz = max(8.2, min(12.0, 10.8 * scale))
        let headerFontSz = max(8.0, min(11.0, 10.0 * scale))
        let lineH = max(11.0, 16.5 * scale)

        VStack(alignment: .leading, spacing: 0) {
            // Node Header Bar (`#1B222C` Brushed Steel)
            HStack(spacing: 4) {
                Circle()
                    .fill(block.isEntry ? ColdTungstenPalette.signalEmerald : (block.isExit ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.tungstenSapphire))
                    .frame(width: max(4, 6 * scale), height: max(4, 6 * scale))

                Text("BB#\(block.id) · \(block.startAddress.compactHexString)")
                    .font(.system(size: headerFontSz, weight: .semibold, design: .monospaced).monospacedDigit())
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize()

                Spacer(minLength: 2)

                if block.isEntry {
                    tinyNodeBadge("ENTRY", color: ColdTungstenPalette.signalEmerald, scale: scale)
                } else if block.isExit {
                    tinyNodeBadge("EXIT", color: ColdTungstenPalette.anodizedCrimson, scale: scale)
                }

                if block.loopDepth > 0 {
                    tinyNodeBadge("L\(block.loopDepth)", color: ColdTungstenPalette.warmCopper, scale: scale)
                }

                if showDomBadge {
                    tinyNodeBadge("D\(dominatorDepth)", color: ColdTungstenPalette.coolPewter, scale: scale)
                }

                if blockHasPAC {
                    tinyNodeBadge("PAC", color: ColdTungstenPalette.tungstenAmber, scale: scale)
                }
            }
            .padding(.horizontal, max(5, 8 * scale))
            .frame(height: max(18, 25 * scale))
            .background(isSelectedBlock ? ColdTungstenPalette.activeSelectionFill : ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: 1.0)

            // Colored ARM64 Instruction Lines
            VStack(alignment: .leading, spacing: 0) {
                ForEach(block.instructions) { insn in
                    let isCursorRow = insn.address == activeInstructionAddress
                    let isPatched = isInstructionPatched(insn)
                    HStack(spacing: max(4, 6 * scale)) {
                        Text(shortOffsetTail(insn.address))
                            .font(.system(size: max(7.5, fontSz - 1.0), weight: .regular, design: .monospaced).monospacedDigit())
                            .foregroundStyle(isPatched ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.mutedOffsetInk)
                            .fixedSize()

                        Text(ColdTungstenSyntaxHighlighter.attributedDisassembly(
                            for: insn,
                            useABIRegisterNames: useABIRegisters,
                            includeAutoComment: false
                        ))
                        .font(.system(size: fontSz, weight: .regular, design: .monospaced).monospacedDigit())
                        .fixedSize(horizontal: true, vertical: false)

                        Spacer(minLength: 0)

                        if isPatched {
                            tinyNodeBadge("CoW", color: ColdTungstenPalette.warmCopper, scale: scale)
                        }
                    }
                    .padding(.horizontal, max(5, 8 * scale))
                    .frame(height: lineH, alignment: .leading)
                    .background(isCursorRow ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        onSelectInstruction(insn)
                    }
                }
            }
            .padding(.vertical, max(2, 4 * scale))
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(ColdTungstenPalette.chassisBackground)
        }
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(borderAccent, lineWidth: isSelectedBlock ? 1.5 : 1.0)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
    }

    private func shortOffsetTail(_ addr: VirtualAddress) -> String {
        String(format: "%04llx", addr.rawValue & 0xFFFF)
    }

    private func isInstructionPatched(_ insn: A64DecodedInstruction) -> Bool {
        guard let img = loadedImage, let off = img.fileOffset(for: insn.address) else { return false }
        return overlayBuffer.modifiedMask(offset: off, count: 4).contains(true)
    }

    private func tinyNodeBadge(_ text: String, color: Color, scale: CGFloat) -> some View {
        Text(text)
            .font(.system(size: max(7.0, min(9.5, 8.8 * scale)), weight: .bold, design: .monospaced))
            .foregroundStyle(color)
            .padding(.horizontal, max(2.5, 4.0 * scale))
            .padding(.vertical, 1.0)
            .background(color.opacity(0.13))
            .clipShape(RoundedRectangle(cornerRadius: 2.5))
            .fixedSize()
    }
}

// MARK: - Interactive Corner Minimap Radar Overlay

@MainActor
private struct CFGMinimapRadarOverlayView: View {
    let function: RecoveredFunction
    let layout: SugiyamaCFGLayout
    let viewportSize: CGSize
    let currentScale: CGFloat
    let currentOffset: CGSize
    let activeBlockID: Int?
    let onRecenterAtGraphPoint: (CGPoint) -> Void

    private let radarWidth: CGFloat = 172.0
    private let radarHeight: CGFloat = 118.0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 5) {
                Image(systemName: "viewfinder")
                    .font(.system(size: 9.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                Text("MINIMAP RADAR")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize()
                Spacer()
                Text("\(layout.nodes.count) BB")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.0))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize()
            }
            .padding(.horizontal, 7)
            .frame(height: 20)
            .background(ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: 1)

            Canvas { context, size in
                let gW = max(1.0, CGFloat(layout.canvasWidth))
                let gH = max(1.0, CGFloat(layout.canvasHeight))
                let pad: CGFloat = 6.0
                let miniScale = min((size.width - pad * 2) / gW, (size.height - pad * 2) / gH)
                let origX = (size.width - gW * miniScale) * 0.5
                let origY = (size.height - gH * miniScale) * 0.5

                // Edges
                for route in layout.routes where route.waypoints.count >= 2 {
                    var p = Path()
                    let first = route.waypoints[0]
                    p.move(to: CGPoint(x: origX + CGFloat(first.x) * miniScale, y: origY + CGFloat(first.y) * miniScale))
                    for wp in route.waypoints.dropFirst() {
                        p.addLine(to: CGPoint(x: origX + CGFloat(wp.x) * miniScale, y: origY + CGFloat(wp.y) * miniScale))
                    }
                    let col = ColdTungstenPalette.color(for: route.edge.kind, isBackEdge: route.edge.isBackEdge)
                    context.stroke(p, with: .color(col.opacity(0.65)), lineWidth: 1.0)
                }

                // Nodes
                for node in layout.nodes {
                    let r = CGRect(
                        x: origX + CGFloat(node.frame.x) * miniScale,
                        y: origY + CGFloat(node.frame.y) * miniScale,
                        width: max(4.0, CGFloat(node.frame.width) * miniScale),
                        height: max(3.0, CGFloat(node.frame.height) * miniScale)
                    )
                    let block = function.blocks.first { $0.id == node.blockID }
                    let fillCol: Color = {
                        if node.blockID == activeBlockID { return ColdTungstenPalette.tungstenSapphire }
                        if block?.isEntry == true { return ColdTungstenPalette.signalEmerald }
                        if block?.isExit == true { return ColdTungstenPalette.anodizedCrimson }
                        if (block?.loopDepth ?? 0) > 0 { return ColdTungstenPalette.warmCopper }
                        return ColdTungstenPalette.coolPewter
                    }()
                    let path = Path(roundedRect: r, cornerRadius: 1.5)
                    context.fill(path, with: .color(fillCol.opacity(0.32)))
                    context.stroke(path, with: .color(fillCol), lineWidth: 1.0)
                }

                // Active Viewport Lens Rectangle
                if currentScale > 0.01 {
                    let visGraphX = -currentOffset.width / currentScale
                    let visGraphY = -currentOffset.height / currentScale
                    let visGraphW = viewportSize.width / currentScale
                    let visGraphH = viewportSize.height / currentScale
                    let rawLens = CGRect(
                        x: origX + visGraphX * miniScale,
                        y: origY + visGraphY * miniScale,
                        width: visGraphW * miniScale,
                        height: visGraphH * miniScale
                    )
                    let clampedLens = rawLens.intersection(CGRect(origin: .zero, size: size).insetBy(dx: 1.5, dy: 1.5))
                    if !clampedLens.isNull && clampedLens.width > 2 && clampedLens.height > 2 {
                        let lensPath = Path(roundedRect: clampedLens, cornerRadius: 2.0)
                        context.stroke(lensPath, with: .color(ColdTungstenPalette.tungstenSapphire), lineWidth: 1.2)
                    }
                }
            }
            .frame(width: radarWidth, height: radarHeight)
            .background(ColdTungstenPalette.chassisBackground.opacity(0.95))
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onEnded { value in
                        let gW = max(1.0, CGFloat(layout.canvasWidth))
                        let gH = max(1.0, CGFloat(layout.canvasHeight))
                        let pad: CGFloat = 6.0
                        let miniScale = min((radarWidth - pad * 2) / gW, (radarHeight - pad * 2) / gH)
                        let origX = (radarWidth - gW * miniScale) * 0.5
                        let origY = (radarHeight - gH * miniScale) * 0.5
                        let gx = (value.location.x - origX) / miniScale
                        let gy = (value.location.y - origY) / miniScale
                        onRecenterAtGraphPoint(CGPoint(x: gx, y: gy))
                    }
            )
        }
        .frame(width: radarWidth)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
    }
}

// MARK: - Right-Hand CFG & Dominator Contextual Inspector View

@MainActor
public struct MachCFGContextualInspectorView: View {
    @ObservedObject public var viewModel: MachStudioViewModel

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
    }

    private var activeInstruction: A64DecodedInstruction? {
        viewModel.analysisIndex?.instruction(at: viewModel.cursorBus.currentLocation.virtualAddress)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            TungstenPanelHeaderBar(
                title: "Dominator & CFG Inspector",
                sfSymbol: "sidebar.right",
                countBadge: viewModel.activeFunction?.blocks.count
            )

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let fn = viewModel.activeFunction {
                        functionTelemetrySection(fn)
                        dominatorTreeSection(fn)
                        if !fn.naturalLoops.isEmpty || !fn.jumpTables.isEmpty {
                            loopsAndJumpTablesSection(fn)
                        }
                        callGraphNeighborhoodSection(fn)
                    }
                    if let insn = activeInstruction {
                        instructionSemanticsSection(insn)
                    }
                }
                .padding(10)
            }
            .background(ColdTungstenPalette.chassisBackground)
        }
        .frame(width: 288)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline)
        }
    }

    private func functionTelemetrySection(_ fn: RecoveredFunction) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            inspectorSectionHeader("ACTIVE FUNCTION", icon: "function")

            VStack(alignment: .leading, spacing: 5) {
                Text(viewModel.displayFunctionName(fn))
                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 6) {
                    Text(fn.address.compactHexString)
                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .fixedSize()
                    Text("->")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    Text(fn.endAddress.compactHexString)
                        .font(ColdTungstenTypography.addressMono(size: 11.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize()
                }

                HStack(spacing: 8) {
                    statKeyVal("Frame", "\(fn.stackFrameBytes)B")
                    statKeyVal("Insns", "\(fn.instructionCount)")
                    statKeyVal("CC", "\(fn.cyclomaticComplexity)")
                    statKeyVal("PAC", fn.usesPAC ? "Yes" : "No")
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(ColdTungstenPalette.gunmetalSlate)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1)
            )
        }
    }

    private func dominatorTreeSection(_ fn: RecoveredFunction) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            inspectorSectionHeader("LENGAUER-TARJAN DOMINATORS", icon: "list.bullet.indent")

            VStack(alignment: .leading, spacing: 4) {
                ForEach(fn.dominatorTree.prefix(8)) { domNode in
                    let block = fn.blocks.first { $0.id == domNode.blockID }
                    let isCurrent = viewModel.cursorBus.activeBlockID == domNode.blockID
                    Button {
                        if let block {
                            viewModel.cursorBus.jump(
                                to: SynchronizedCursorLocation(
                                    virtualAddress: block.startAddress,
                                    fileOffset: viewModel.loadedImage?.fileOffset(for: block.startAddress),
                                    functionAddress: fn.address,
                                    blockID: block.id,
                                    originPane: viewModel.cursorBus.activePane
                                )
                            )
                        }
                    } label: {
                        HStack(spacing: 5) {
                            Text(String(repeating: "  ", count: min(3, domNode.depth)) + "BB#\(domNode.blockID)")
                                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                                .foregroundStyle(isCurrent ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.steelWhite)
                                .fixedSize()

                            if let idom = domNode.immediateDominatorID {
                                Text("idom:#\(idom)")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .fixedSize()
                            } else {
                                Text("ROOT")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                                    .fixedSize()
                            }

                            Spacer(minLength: 4)

                            if !domNode.dominanceFrontierIDs.isEmpty {
                                let dfText = domNode.dominanceFrontierIDs.map { "#\($0)" }.joined(separator: ",")
                                Text("DF:\(dfText)")
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                                    .fixedSize()
                            }
                        }
                        .padding(.horizontal, 7)
                        .padding(.vertical, 4)
                        .background(isCurrent ? ColdTungstenPalette.activeSelectionFill : ColdTungstenPalette.gunmetalSlate)
                        .overlay(
                            RoundedRectangle(cornerRadius: 3)
                                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1)
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func loopsAndJumpTablesSection(_ fn: RecoveredFunction) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            inspectorSectionHeader("NATURAL LOOPS & SWITCH TABLES", icon: "arrow.2.squarepath")

            ForEach(fn.naturalLoops) { loop in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text("Loop Header BB#\(loop.headerBlockID)")
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                            .foregroundStyle(ColdTungstenPalette.warmCopper)
                            .fixedSize()
                        Spacer()
                        Text("Depth \(loop.nestingDepth)")
                            .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                            .fixedSize()
                    }
                    Text("Body: \(loop.bodyBlockIDs.map { "BB#\($0)" }.joined(separator: ", "))")
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(7)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))
            }

            ForEach(fn.jumpTables) { jt in
                VStack(alignment: .leading, spacing: 3) {
                    Text("Switch @ \(jt.dispatchInstructionAddress.compactHexString)")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                        .fixedSize()
                    Text("Table \(jt.tableBaseAddress.compactHexString) · \(jt.targetAddresses.count) cases")
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(7)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))
            }
        }
    }

    private func callGraphNeighborhoodSection(_ fn: RecoveredFunction) -> some View {
        let callers = viewModel.analysisIndex?.callers(of: fn.address) ?? []
        let callees = viewModel.analysisIndex?.callees(of: fn.address) ?? []

        return VStack(alignment: .leading, spacing: 6) {
            inspectorSectionHeader("CALL GRAPH NEIGHBORS", icon: "arrow.left.arrow.right")

            VStack(alignment: .leading, spacing: 5) {
                Text("Callers (\(callers.count))")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                if callers.isEmpty {
                    Text("Entry / Root or external caller")
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                } else {
                    ForEach(callers.prefix(4)) { caller in
                        Button {
                            viewModel.cursorBus.selectFunction(caller, in: viewModel.loadedImage)
                        } label: {
                            HStack(spacing: 5) {
                                Image(systemName: "arrow.down.right")
                                    .font(.system(size: 9))
                                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                                Text(viewModel.displayFunctionName(caller))
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }

                Divider().overlay(ColdTungstenPalette.tungstenSeam)

                Text("Callees (\(callees.count))")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                if callees.isEmpty {
                    Text("Leaf function (zero outgoing calls)")
                        .font(ColdTungstenTypography.secondaryCaption)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                } else {
                    ForEach(callees.prefix(5)) { callee in
                        Button {
                            viewModel.cursorBus.selectFunction(callee, in: viewModel.loadedImage)
                        } label: {
                            HStack(spacing: 5) {
                                Image(systemName: "arrow.up.right")
                                    .font(.system(size: 9))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                Text(viewModel.displayFunctionName(callee))
                                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .padding(8)
            .background(ColdTungstenPalette.gunmetalSlate)
            .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))
        }
    }

    private func instructionSemanticsSection(_ insn: A64DecodedInstruction) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            inspectorSectionHeader("CURSOR INSTRUCTION", icon: "cpu")

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(insn.address.compactHexString)
                        .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .fixedSize()
                    Spacer()
                    Text(insn.rawBytesHex)
                        .font(ColdTungstenTypography.hexDumpMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize()
                }

                Text(insn.formattedDisassembly)
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: false, vertical: true)

                Text(insn.group.rawValue)
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize(horizontal: false, vertical: true)

                let reads = insn.readsRegisters.map(\.abiDisplayName).joined(separator: ", ")
                let writes = insn.writesRegisters.map(\.abiDisplayName).joined(separator: ", ")
                if !reads.isEmpty || !writes.isEmpty {
                    Text("R: [\(reads.isEmpty ? "-" : reads)] · W: [\(writes.isEmpty ? "-" : writes)]")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(8)
            .background(ColdTungstenPalette.gunmetalSlate)
            .overlay(RoundedRectangle(cornerRadius: 3).strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: 1))
        }
    }

    private func inspectorSectionHeader(_ title: String, icon: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
            Text(title)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize()
        }
    }

    private func statKeyVal(_ key: String, _ val: String) -> some View {
        HStack(spacing: 3) {
            Text("\(key):")
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            Text(val)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
        }
        .fixedSize()
    }
}

// MARK: - Virtualized Linear ARM64 Disassembly Studio View (`.disassembly`)

@MainActor
public struct LinearDisassemblyStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    public let compactForSplit: Bool

    @State private var scopeToActiveFunctionOnly: Bool = false

    public init(viewModel: MachStudioViewModel, compactForSplit: Bool = false) {
        self.viewModel = viewModel
        self.compactForSplit = compactForSplit
        self._scopeToActiveFunctionOnly = State(initialValue: compactForSplit)
    }

    private var displayedFunctions: [RecoveredFunction] {
        let all = viewModel.functions
        if scopeToActiveFunctionOnly, let active = viewModel.activeFunction {
            return [active]
        }
        let q = viewModel.disassemblyFilterQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return all }
        return all.filter { fn in
            viewModel.displayFunctionName(fn).lowercased().contains(q)
                || fn.address.compactHexString.lowercased().contains(q)
                || fn.blocks.contains { blk in
                    blk.instructions.contains { $0.formattedDisassembly.lowercased().contains(q) }
                }
        }
    }

    private var idiomsByCompletingAddress: [VirtualAddress: A64RecognizedIdiom] {
        var dict: [VirtualAddress: A64RecognizedIdiom] = [:]
        for idiom in viewModel.analysisIndex?.recognizedIdioms ?? [] {
            dict[idiom.completingAddress] = idiom
        }
        return dict
    }

    public var body: some View {
        VStack(spacing: 0) {
            disassemblyHeaderToolbar

            // Column Legend Rail
            HStack(spacing: 8) {
                Text("ADDRESS")
                    .frame(width: 88, alignment: .leading)
                if viewModel.preferencesStore.preferences.showRawInstructionBytes && !compactForSplit {
                    Text("LE BYTES")
                        .frame(width: 84, alignment: .leading)
                }
                Text("ARM64 MNEMONIC & OPERANDS")
                Spacer()
                Text(compactForSplit ? "SYNC" : "ANNOTATIONS / XREFS")
            }
            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            .padding(.horizontal, 10)
            .frame(height: 22)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(alignment: .bottom) {
                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: 1)
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(displayedFunctions) { fn in
                            functionBannerHeader(fn)

                            ForEach(fn.blocks) { block in
                                basicBlockLabelRow(block, in: fn)

                                ForEach(block.instructions) { insn in
                                    instructionRow(insn, block: block, function: fn)
                                        .id(insn.address)
                                }
                            }
                        }
                    }
                    .padding(.bottom, 16)
                }
                .background(ColdTungstenPalette.gunmetalSlate)
                .onChange(of: viewModel.cursorBus.currentLocation.virtualAddress) { _, targetVA in
                    withAnimation(.easeOut(duration: 0.14)) {
                        proxy.scrollTo(targetVA, anchor: .center)
                    }
                }
            }
        }
        .background(ColdTungstenPalette.gunmetalSlate)
    }

    private var disassemblyHeaderToolbar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                Image(systemName: "list.number")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                Text(compactForSplit ? "ARM64 Disassembly" : "Linear ARM64 Disassembly")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize()

                Button(scopeToActiveFunctionOnly ? "Active Fn" : "All Functions") {
                    scopeToActiveFunctionOnly.toggle()
                }
                .buttonStyle(TungstenToolbarButtonStyle(
                    role: scopeToActiveFunctionOnly ? .accentSapphire : .standard,
                    isActive: scopeToActiveFunctionOnly,
                    compact: true
                ))

                Button {
                    viewModel.presentRenameModalForCursor()
                } label: {
                    HStack(spacing: 4) {
                        Text("Rename")
                        TungstenKeycapBadge("N")
                    }
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                Button {
                    viewModel.presentCommentModalForCursor()
                } label: {
                    HStack(spacing: 4) {
                        Text("Comment")
                        TungstenKeycapBadge(";")
                    }
                }
                .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                if !compactForSplit {
                    Button {
                        viewModel.presentXrefsPopoverAtCursor()
                    } label: {
                        HStack(spacing: 4) {
                            Text("Xrefs")
                            TungstenKeycapBadge("X")
                        }
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))

                    Button {
                        viewModel.toggleBookmarkAtCursor()
                    } label: {
                        HStack(spacing: 4) {
                            Text("Bookmark")
                            TungstenKeycapBadge("B")
                        }
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(compact: true))
                }
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

    private func functionBannerHeader(_ fn: RecoveredFunction) -> some View {
        let incomingCount = viewModel.analysisIndex?.xrefsTo(address: fn.address).count ?? 0
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Text("; FUNCTION")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                    .fixedSize()

                Text(viewModel.displayFunctionName(fn))
                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: false, vertical: true)

                Text("@ \(fn.address.compactHexString)")
                    .font(ColdTungstenTypography.addressMono(size: 11.0))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .fixedSize()

                if fn.usesPAC {
                    Text("ARM64E PAC")
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                        .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(ColdTungstenPalette.tungstenAmber.opacity(0.14))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .fixedSize()
                }

                Spacer(minLength: 4)

                Text("\(fn.blocks.count) BBs · \(incomingCount) xrefs")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize()
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(alignment: .top) {
            Rectangle().fill(ColdTungstenPalette.tungstenSeam).frame(height: 1)
        }
        .overlay(alignment: .bottom) {
            Rectangle().fill(ColdTungstenPalette.tungstenSeam.opacity(0.6)).frame(height: 1)
        }
    }

    private func basicBlockLabelRow(_ block: BasicBlock, in fn: RecoveredFunction) -> some View {
        HStack(spacing: 8) {
            Text("\(block.label):")
                .font(ColdTungstenTypography.disassemblyMono(size: 11.0, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                .fixedSize()

            if !block.predecessorIDs.isEmpty {
                let preds = block.predecessorIDs.map { "BB#\($0)" }.joined(separator: ", ")
                Text("; preds: \(preds)")
                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize()
            }

            if block.loopDepth > 0 {
                Text("LOOP DEPTH \(block.loopDepth)")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.warmCopper)
                    .fixedSize()
            }
            Spacer()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 3)
        .background(ColdTungstenPalette.chassisBackground.opacity(0.45))
    }

    private func instructionRow(
        _ insn: A64DecodedInstruction,
        block: BasicBlock,
        function: RecoveredFunction
    ) -> some View {
        let isSelected = viewModel.cursorBus.currentLocation.virtualAddress == insn.address
        let fileOff = viewModel.loadedImage?.fileOffset(for: insn.address)
        let patchedBytes: [UInt8]? = {
            guard let off = fileOff, viewModel.overlayBuffer.modifiedMask(offset: off, count: 4).contains(true) else {
                return nil
            }
            return try? viewModel.overlayBuffer.readBytes(offset: off, count: 4)
        }()
        let userComment = viewModel.commentMap[insn.address]?.text
        let idiom = idiomsByCompletingAddress[insn.address]

        return HStack(alignment: .top, spacing: 8) {
            // Address Gutter
            HStack(spacing: 4) {
                Rectangle()
                    .fill(isSelected ? ColdTungstenPalette.tungstenSapphire : Color.clear)
                    .frame(width: 2.5, height: 15)

                Text(insn.address.compactHexString)
                    .font(ColdTungstenTypography.addressMono(size: 11.5, weight: isSelected ? .semibold : .regular))
                    .foregroundStyle(isSelected ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize()
            }
            .frame(width: 88, alignment: .leading)

            // Raw LE Hex Bytes (Highlighting CoW-Patched Bytes in Warm Copper `#FFA657`)
            if viewModel.preferencesStore.preferences.showRawInstructionBytes && !compactForSplit {
                let hexText = patchedBytes.map {
                    String(format: "%02x %02x %02x %02x", $0[0], $0[1], $0[2], $0[3])
                } ?? insn.rawBytesHex

                Text(hexText)
                    .font(ColdTungstenTypography.hexDumpMono(size: 11.0))
                    .foregroundStyle(patchedBytes != nil ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.coolPewter)
                    .frame(width: 84, alignment: .leading)
                    .fixedSize()
            }

            // Syntax-Highlighted Mnemonic & Operands + Wrapping Comment
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(ColdTungstenSyntaxHighlighter.attributedDisassembly(
                        for: insn,
                        useABIRegisterNames: viewModel.preferencesStore.preferences.useABIRegisterNames,
                        includeAutoComment: !compactForSplit && viewModel.preferencesStore.preferences.showAutoComments && userComment == nil
                    ))
                    .font(ColdTungstenTypography.disassemblyMono(size: compactForSplit ? 11.5 : 12.0))
                    .fixedSize(horizontal: false, vertical: true)

                    if patchedBytes != nil {
                        Text("CoW PATCHED")
                            .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .bold))
                            .foregroundStyle(ColdTungstenPalette.warmCopper)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(ColdTungstenPalette.warmCopper.opacity(0.15))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                            .fixedSize()
                    }

                    if let idiom, !compactForSplit {
                        Text(idiomBadgeShortName(idiom.kind))
                            .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .semibold))
                            .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(ColdTungstenPalette.tungstenSapphire.opacity(0.14))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                            .fixedSize()
                    }
                }

                if let userComment, !userComment.isEmpty {
                    Text("; \(userComment)")
                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.signalEmerald)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2.5)
        .background(isSelected ? ColdTungstenPalette.activeSelectionFill : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture {
            viewModel.cursorBus.jump(
                to: SynchronizedCursorLocation(
                    virtualAddress: insn.address,
                    fileOffset: fileOff,
                    functionAddress: function.address,
                    blockID: block.id,
                    originPane: .disassembly
                ),
                recordHistory: true
            )
        }
    }

    private func idiomBadgeShortName(_ kind: A64IdiomKind) -> String {
        let raw = String(describing: kind)
        if raw.lowercased().contains("adrp") { return "ADRP+OFF" }
        if raw.lowercased().contains("mov") { return "MOV-IMM64" }
        if raw.lowercased().contains("pac") { return "PAC-PROLOG" }
        if raw.lowercased().contains("switch") || raw.lowercased().contains("jump") { return "SWITCH-TBL" }
        return "IDIOM"
    }
}
