import Foundation
import AppKit
import SwiftUI
import MachGraphModels

// MARK: - Cold Tungsten Steel Palette (Zero Neon Purple/Cyan, Zero Glassmorphism)

public enum ColdTungstenPalette: Sendable {

    // MARK: Chassis & Structural Surfaces

    /// Primary Chassis Background — Cold Tungsten `#0F1216`
    public static let chassisBackground = Color(red: 0x0F / 255.0, green: 0x12 / 255.0, blue: 0x16 / 255.0)

    /// Elevated Inspection Bay / Graph Canvas — Gunmetal Slate `#141920`
    public static let gunmetalSlate = Color(red: 0x14 / 255.0, green: 0x19 / 255.0, blue: 0x20 / 255.0)
    public static let inspectionBay = gunmetalSlate
    public static let graphCanvas = gunmetalSlate

    /// Panel Header / Rail — Brushed Steel `#1B222C`
    public static let brushedSteel = Color(red: 0x1B / 255.0, green: 0x22 / 255.0, blue: 0x2C / 255.0)
    public static let panelHeader = brushedSteel
    public static let railBackground = brushedSteel

    /// Subtle Interactive Control Rest / Hover Surface — Milled Steel `#222B37`
    public static let milledControlHover = Color(red: 0x22 / 255.0, green: 0x2B / 255.0, blue: 0x37 / 255.0)

    /// Crisp Active Row Fill — Anodized Sapphire Tint `#1A2636`
    public static let activeSelectionFill = Color(red: 0x1A / 255.0, green: 0x26 / 255.0, blue: 0x36 / 255.0)

    /// 1pt Hairline Rule — Tungsten Seam `#2A3442`
    public static let tungstenSeam = Color(red: 0x2A / 255.0, green: 0x34 / 255.0, blue: 0x42 / 255.0)
    public static let hairlineRule = tungstenSeam

    // MARK: Precision Typography Inks

    /// Primary Ink — Steel White `#E6EDF3`
    public static let steelWhite = Color(red: 0xE6 / 255.0, green: 0xED / 255.0, blue: 0xF3 / 255.0)
    public static let primaryInk = steelWhite

    /// Secondary Metadata Ink — Cool Pewter `#8B949E`
    public static let coolPewter = Color(red: 0x8B / 255.0, green: 0x94 / 255.0, blue: 0x9E / 255.0)
    public static let secondaryMetadata = coolPewter

    /// Muted File Offset / Gutter Ink — `#656D76`
    public static let mutedOffsetInk = Color(red: 0x65 / 255.0, green: 0x6D / 255.0, blue: 0x76 / 255.0)

    // MARK: Semantic Reverse-Engineering Accent Tokens

    /// Address / Xref Link Accent — Tungsten Sapphire `#58A6FF`
    public static let tungstenSapphire = Color(red: 0x58 / 255.0, green: 0xA6 / 255.0, blue: 0xFF / 255.0)
    public static let addressLinkAccent = tungstenSapphire

    /// CFG True Branch / Verified CodeSign — Signal Emerald `#3FB950`
    public static let signalEmerald = Color(red: 0x3F / 255.0, green: 0xB9 / 255.0, blue: 0x50 / 255.0)
    public static let cfgTrueBranch = signalEmerald
    public static let verifiedCodeSign = signalEmerald

    /// CFG False Branch / Critical Finding / Patch Modified Byte — Anodized Crimson `#F85149`
    public static let anodizedCrimson = Color(red: 0xF8 / 255.0, green: 0x51 / 255.0, blue: 0x49 / 255.0)
    public static let cfgFalseBranch = anodizedCrimson
    public static let criticalFinding = anodizedCrimson
    public static let patchModifiedByte = anodizedCrimson

    /// Unconditional Edge / PAC / High Entropy Warning — Tungsten Amber `#D29922`
    public static let tungstenAmber = Color(red: 0xD2 / 255.0, green: 0x99 / 255.0, blue: 0x22 / 255.0)
    public static let unconditionalEdge = tungstenAmber
    public static let pacBadgeAccent = tungstenAmber
    public static let highEntropyWarning = tungstenAmber

    /// String Literal Tint — Warm Copper `#FFA657`
    public static let warmCopper = Color(red: 0xFF / 255.0, green: 0xA6 / 255.0, blue: 0x57 / 255.0)
    public static let stringLiteralTint = warmCopper

    // MARK: Canonical Hex Constants (For Exporters & Tests)

    public static let chassisBackgroundHex = "#0F1216"
    public static let gunmetalSlateHex = "#141920"
    public static let brushedSteelHex = "#1B222C"
    public static let tungstenSeamHex = "#2A3442"
    public static let steelWhiteHex = "#E6EDF3"
    public static let coolPewterHex = "#8B949E"
    public static let mutedOffsetInkHex = "#656D76"
    public static let tungstenSapphireHex = "#58A6FF"
    public static let signalEmeraldHex = "#3FB950"
    public static let anodizedCrimsonHex = "#F85149"
    public static let tungstenAmberHex = "#D29922"
    public static let warmCopperHex = "#FFA657"

    // MARK: Semantic Domain Color Resolvers

    public static func color(for severity: SecurityFindingSeverity) -> Color {
        switch severity {
        case .critical:
            return anodizedCrimson
        case .high:
            return warmCopper
        case .medium:
            return tungstenAmber
        case .low:
            return tungstenSapphire
        case .info:
            return coolPewter
        }
    }

    public static func backgroundFill(for severity: SecurityFindingSeverity) -> Color {
        color(for: severity).opacity(0.14)
    }

    public static func color(for edgeKind: CFGEdgeKind, isBackEdge: Bool = false) -> Color {
        if isBackEdge {
            return tungstenAmber
        }
        switch edgeKind {
        case .conditionalTrue:
            return signalEmerald
        case .conditionalFalse:
            return anodizedCrimson
        case .switchCase:
            return tungstenSapphire
        case .unconditional, .fallthroughEdge:
            return tungstenAmber
        }
    }

    public static func color(for xrefKind: XrefKind) -> Color {
        switch xrefKind {
        case .directCall, .indirectCall, .codeReference:
            return tungstenSapphire
        case .conditionalBranch:
            return signalEmerald
        case .unconditionalJump:
            return tungstenAmber
        case .stringReference:
            return warmCopper
        case .dataPointerWrite:
            return anodizedCrimson
        case .dataPointerRead, .pageBaseADRP, .chainedFixupTarget:
            return coolPewter
        }
    }

    public static func color(forEntropy entropyBitsPerByte: Double) -> Color {
        if entropyBitsPerByte >= 7.25 {
            return anodizedCrimson
        } else if entropyBitsPerByte >= 6.4 {
            return tungstenAmber
        } else if entropyBitsPerByte >= 5.0 {
            return tungstenSapphire
        } else if entropyBitsPerByte >= 2.0 {
            return signalEmerald
        } else {
            return mutedOffsetInk
        }
    }

    public static func parseBookmarkColor(_ tagOrHex: String) -> Color {
        let trimmed = tagOrHex.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("#") {
            let hex = String(trimmed.dropFirst())
            if hex.count == 6, let rgb = UInt32(hex, radix: 16) {
                let r = Double((rgb >> 16) & 0xFF) / 255.0
                let g = Double((rgb >> 8) & 0xFF) / 255.0
                let b = Double(rgb & 0xFF) / 255.0
                return Color(red: r, green: g, blue: b)
            }
        }
        switch trimmed.lowercased() {
        case "critical", "vuln", "patch", "danger":
            return anodizedCrimson
        case "crypto", "pac", "warning":
            return tungstenAmber
        case "verified", "entry", "safe":
            return signalEmerald
        case "string", "auth":
            return warmCopper
        default:
            return tungstenSapphire
        }
    }
}

// MARK: - Precision Engineering Layout Metrics

public enum ColdTungstenMetrics: Sendable {
    public static let borderHairline: CGFloat = 1.0
    public static let cornerRadiusCompact: CGFloat = 4.0
    public static let cornerRadiusStandard: CGFloat = 5.0
    public static let cornerRadiusPanel: CGFloat = 6.0

    public static let topToolbarHeight: CGFloat = 42.0
    public static let panelHeaderHeight: CGFloat = 32.0
    public static let sidebarDefaultWidth: CGFloat = 300.0
    public static let sidebarMinWidth: CGFloat = 264.0
    public static let bottomDrawerDefaultHeight: CGFloat = 220.0
    public static let bottomDrawerMinHeight: CGFloat = 132.0
    public static let bottomDrawerMaxHeight: CGFloat = 480.0
}

// MARK: - Cold Tungsten Typography System (Tabular Monospaced + Crisp Sans)

public enum ColdTungstenTypography: Sendable {

    // Monospaced Binary Inspection Fonts (All Tabular Digit Aligned)
    public static func addressMono(size: CGFloat = 12.0, weight: Font.Weight = .medium) -> Font {
        .system(size: size, weight: weight, design: .monospaced).monospacedDigit()
    }

    public static func disassemblyMono(size: CGFloat = 12.5, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced).monospacedDigit()
    }

    public static func hexDumpMono(size: CGFloat = 12.0) -> Font {
        .system(size: size, weight: .regular, design: .monospaced).monospacedDigit()
    }

    public static func offsetGutterMono(size: CGFloat = 11.0) -> Font {
        .system(size: size, weight: .regular, design: .monospaced).monospacedDigit()
    }

    public static func microBadgeMono(size: CGFloat = 10.5, weight: Font.Weight = .semibold) -> Font {
        .system(size: size, weight: weight, design: .monospaced).monospacedDigit()
    }

    // Crisp Sans-Serif Chrome & Control Fonts
    public static let toolbarTitle = Font.system(size: 13.0, weight: .semibold, design: .default)
    public static let panelHeaderTitle = Font.system(size: 11.5, weight: .semibold, design: .default)
    public static let controlLabel = Font.system(size: 12.0, weight: .medium, design: .default)
    public static let sidebarItemTitle = Font.system(size: 12.5, weight: .medium, design: .default)
    public static let bodyText = Font.system(size: 12.5, weight: .regular, design: .default)
    public static let secondaryCaption = Font.system(size: 11.0, weight: .regular, design: .default)
}

// MARK: - ARM64 Assembly & Pseudo-C Syntax Highlighting

public enum ColdTungstenSyntaxHighlighter: Sendable {

    /// Syntax color for an ARM64 `A64Mnemonic` and its `A64InstructionGroup`.
    public static func colorForMnemonic(_ mnemonic: A64Mnemonic, group: A64InstructionGroup) -> Color {
        if group == .pacPointerAuth {
            return ColdTungstenPalette.tungstenAmber
        }
        switch mnemonic {
        case .b, .bl, .br, .blr, .braa, .brab, .braaz, .brabz, .blraa, .blrab, .blraaz, .blrabz:
            return ColdTungstenPalette.tungstenSapphire
        case .bCond, .cbz, .cbnz, .tbz, .tbnz:
            return ColdTungstenPalette.signalEmerald
        case .ret, .retaa, .retab, .brk, .hlt, .svc, .hvc, .smc:
            return ColdTungstenPalette.anodizedCrimson
        case .adr, .adrp:
            return ColdTungstenPalette.warmCopper
        case .ldr, .ldrb, .ldrh, .ldrsb, .ldrsh, .ldrsw, .ldur, .ldurb, .ldurh, .ldursb, .ldursh, .ldursw,
             .ldp, .ldpsw, .ldnp, .str, .strb, .strh, .stur, .sturb, .sturh, .stp, .stnp,
             .ldxr, .ldaxr, .ldar, .ldarb, .ldarh, .stxr, .stlxr, .stlr, .stlrb, .stlrh:
            return Color(red: 0x79 / 255.0, green: 0xC0 / 255.0, blue: 0xFF / 255.0)
        case .nop, .yield, .wfe, .wfi, .hint, .bti:
            return ColdTungstenPalette.mutedOffsetInk
        default:
            return ColdTungstenPalette.steelWhite
        }
    }

    /// Syntax color for an ARM64 `A64Register`.
    public static func colorForRegister(_ register: A64Register) -> Color {
        if register.isStackPointer {
            return ColdTungstenPalette.tungstenAmber
        }
        if register.isZeroRegister {
            return ColdTungstenPalette.mutedOffsetInk
        }
        if register.bank == .gp64 && (register.index == 29 || register.index == 30) {
            return ColdTungstenPalette.tungstenAmber
        }
        if register.bank == .gp64 && register.index <= 7 {
            return ColdTungstenPalette.tungstenSapphire
        }
        if register.bank == .gp32 && register.index <= 7 {
            return ColdTungstenPalette.tungstenSapphire
        }
        if register.isSIMD {
            return ColdTungstenPalette.signalEmerald
        }
        return ColdTungstenPalette.steelWhite
    }

    /// Syntax color for an ARM64 `A64Operand`.
    public static func colorForOperand(_ operand: A64Operand) -> Color {
        switch operand {
        case .register(let reg), .shiftedRegister(let reg, _):
            return colorForRegister(reg)
        case .immediate, .unsignedImmediate, .fpImmediate, .shiftedImmediate:
            return ColdTungstenPalette.warmCopper
        case .branchTarget:
            return ColdTungstenPalette.tungstenSapphire
        case .memory(let mode):
            if case .pcRelativeLiteral = mode {
                return ColdTungstenPalette.tungstenSapphire
            }
            return ColdTungstenPalette.coolPewter
        case .condition:
            return ColdTungstenPalette.signalEmerald
        case .systemRegister, .barrierOption, .prefetchOp:
            return ColdTungstenPalette.tungstenAmber
        }
    }

    /// Syntax color for a structured `PseudoCTokenKind`.
    public static func color(for tokenKind: PseudoCTokenKind) -> Color {
        switch tokenKind {
        case .keyword:
            return ColdTungstenPalette.anodizedCrimson
        case .typeName:
            return ColdTungstenPalette.tungstenAmber
        case .functionName:
            return ColdTungstenPalette.tungstenSapphire
        case .variableName:
            return ColdTungstenPalette.steelWhite
        case .numericLiteral:
            return ColdTungstenPalette.signalEmerald
        case .stringLiteral:
            return ColdTungstenPalette.warmCopper
        case .punctuation:
            return ColdTungstenPalette.coolPewter
        case .comment:
            return ColdTungstenPalette.mutedOffsetInk
        case .plain:
            return ColdTungstenPalette.steelWhite
        }
    }

    /// Builds a syntax-highlighted `AttributedString` for a decoded ARM64 instruction.
    public static func attributedDisassembly(
        for instruction: A64DecodedInstruction,
        useABIRegisterNames: Bool = true,
        includeAutoComment: Bool = true
    ) -> AttributedString {
        var result = AttributedString()

        var mnemAttr = AttributedString(instruction.mnemonicText.padding(toLength: 8, withPad: " ", startingAt: 0))
        mnemAttr.foregroundColor = colorForMnemonic(instruction.mnemonic, group: instruction.group)
        result.append(mnemAttr)

        if !instruction.operands.isEmpty {
            for (idx, op) in instruction.operands.enumerated() {
                if idx > 0 {
                    var sep = AttributedString(", ")
                    sep.foregroundColor = ColdTungstenPalette.coolPewter
                    result.append(sep)
                }
                let text: String = {
                    if useABIRegisterNames, case .register(let reg) = op {
                        return reg.abiDisplayName
                    }
                    return op.description
                }()
                var opAttr = AttributedString(text)
                opAttr.foregroundColor = colorForOperand(op)
                result.append(opAttr)
            }
        } else if !instruction.operandText.isEmpty {
            var fallback = AttributedString(instruction.operandText)
            fallback.foregroundColor = ColdTungstenPalette.steelWhite
            result.append(fallback)
        }

        if includeAutoComment, let comment = instruction.autoComment, !comment.isEmpty {
            var commentAttr = AttributedString("    ; \(comment)")
            commentAttr.foregroundColor = ColdTungstenPalette.mutedOffsetInk
            result.append(commentAttr)
        }

        return result
    }

    /// Builds a syntax-highlighted `AttributedString` for a `PseudoCLineSpan`.
    public static func attributedPseudoCLine(_ line: PseudoCLineSpan) -> AttributedString {
        var result = AttributedString()
        if line.indentationLevel > 0 {
            let indent = String(repeating: "    ", count: line.indentationLevel)
            result.append(AttributedString(indent))
        }
        if line.tokens.isEmpty {
            var raw = AttributedString(line.text)
            raw.foregroundColor = ColdTungstenPalette.steelWhite
            result.append(raw)
            return result
        }
        for tok in line.tokens {
            var span = AttributedString(tok.text)
            span.foregroundColor = color(for: tok.kind)
            result.append(span)
        }
        return result
    }
}

// MARK: - Reusable Cold Tungsten Engineering Badges & Controls

@MainActor
public struct SeverityBadgePill: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    public let severity: SecurityFindingSeverity
    public let count: Int?
    public let isSelected: Bool

    public init(
        severity: SecurityFindingSeverity,
        count: Int? = nil,
        isSelected: Bool = false
    ) {
        self.severity = severity
        self.count = count
        self.isSelected = isSelected
    }

    public var body: some View {
        let accent = ColdTungstenPalette.color(for: severity)
        HStack(spacing: 5) {
            Circle()
                .fill(accent)
                .frame(width: 6, height: 6)
            Text(severity.localizedBadge(in: localizer.language))
                .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .bold))
                .foregroundStyle(accent)
            if let count {
                Text("\(count)")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .padding(.horizontal, 4)
                    .padding(.vertical, 1)
                    .background(ColdTungstenPalette.chassisBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 3))
            }
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(isSelected ? accent.opacity(0.24) : ColdTungstenPalette.backgroundFill(for: severity))
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                .strokeBorder(isSelected ? accent : accent.opacity(0.55), lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
        .fixedSize(horizontal: true, vertical: true)
    }
}

@MainActor
public struct FormatArchBadge: View {
    @ObservedObject private var localizer: MachLocalizer = .shared
    public let containerFormat: BinaryContainerFormat
    public let architecture: CPUArchitecture
    public let isSigned: Bool
    public let isAdHoc: Bool

    public init(
        containerFormat: BinaryContainerFormat,
        architecture: CPUArchitecture,
        isSigned: Bool = false,
        isAdHoc: Bool = false
    ) {
        self.containerFormat = containerFormat
        self.architecture = architecture
        self.isSigned = isSigned
        self.isAdHoc = isAdHoc
    }

    public init(image: LoadedBinaryImage) {
        self.containerFormat = image.containerFormat
        self.architecture = image.architecture
        self.isSigned = image.codeSignature.isSigned
        self.isAdHoc = image.codeSignature.isAdHoc
    }

    private var isARM64E: Bool {
        if case .arm64e = architecture { return true }
        return false
    }

    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "cpu")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

            Text(containerFormat.rawValue)
                .font(ColdTungstenTypography.controlLabel)
                .foregroundStyle(ColdTungstenPalette.steelWhite)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: 1, height: 12)

            Text(architecture.displayName)
                .font(ColdTungstenTypography.microBadgeMono(size: 11, weight: .semibold))
                .foregroundStyle(isARM64E ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.tungstenSapphire)

            if isSigned {
                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(width: 1, height: 12)

                HStack(spacing: 3) {
                    Image(systemName: isAdHoc ? "checkmark.seal" : "checkmark.seal.fill")
                        .font(.system(size: 10, weight: .semibold))
                    Text(isAdHoc ? localizer.L("AD-HOC", "临时签名") : localizer.L("SIGNED", "已签名"))
                        .font(ColdTungstenTypography.microBadgeMono(size: 10, weight: .semibold))
                }
                .foregroundStyle(isAdHoc ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.signalEmerald)
            }
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
        .fixedSize(horizontal: true, vertical: true)
    }
}

/// Crisp Cold-Tungsten-Steel (`#0F1216` / `#1B222C` / `#58A6FF`) `中文 | EN` segmented toggle pill.
@MainActor
public struct TungstenLanguageTogglePill: View {
    @ObservedObject public var localizer: MachLocalizer
    public let compact: Bool

    public init(
        localizer: MachLocalizer = .shared,
        compact: Bool = true
    ) {
        self.localizer = localizer
        self.compact = compact
    }

    public var body: some View {
        HStack(spacing: 0) {
            segmentButton(.zhHans)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline, height: compact ? 16 : 18)

            segmentButton(.en)
        }
        .padding(1)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
        .fixedSize(horizontal: true, vertical: true)
        .help(localizer.L("Toggle Interface Language (⇧⌘L)", "切换界面语言 (⇧⌘L)"))
    }

    private func segmentButton(_ target: MachLanguage) -> some View {
        let active = localizer.language == target
        return Button {
            localizer.setLanguage(target)
        } label: {
            Text(target.badge)
                .font(
                    target == .zhHans
                        ? Font.system(size: compact ? 11.5 : 12.0, weight: active ? .semibold : .medium, design: .default)
                        : ColdTungstenTypography.microBadgeMono(size: compact ? 11.0 : 11.5, weight: active ? .bold : .semibold)
                )
                .foregroundStyle(active ? ColdTungstenPalette.tungstenSapphire : ColdTungstenPalette.coolPewter)
                .padding(.horizontal, compact ? 8 : 10)
                .padding(.vertical, compact ? 3.5 : 4.5)
                .background(active ? ColdTungstenPalette.brushedSteel : Color.clear)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(
                            active ? ColdTungstenPalette.tungstenSapphire.opacity(0.85) : Color.clear,
                            lineWidth: ColdTungstenMetrics.borderHairline
                        )
                )
                .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
                .fixedSize(horizontal: true, vertical: true)
        }
        .buttonStyle(.plain)
    }
}

public enum TungstenButtonRole: Sendable, Hashable {
    case standard
    case accentSapphire
    case positiveEmerald
    case cautionAmber
    case destructiveCrimson
}

public struct TungstenToolbarButtonStyle: ButtonStyle {
    public let role: TungstenButtonRole
    public let isActive: Bool
    public let compact: Bool

    public init(
        role: TungstenButtonRole = .standard,
        isActive: Bool = false,
        compact: Bool = false
    ) {
        self.role = role
        self.isActive = isActive
        self.compact = compact
    }

    private var accentColor: Color {
        switch role {
        case .standard: return ColdTungstenPalette.tungstenSapphire
        case .accentSapphire: return ColdTungstenPalette.tungstenSapphire
        case .positiveEmerald: return ColdTungstenPalette.signalEmerald
        case .cautionAmber: return ColdTungstenPalette.tungstenAmber
        case .destructiveCrimson: return ColdTungstenPalette.anodizedCrimson
        }
    }

    public func makeBody(configuration: Configuration) -> some View {
        let foreground: Color = {
            if isActive { return accentColor }
            if role != .standard { return accentColor }
            return ColdTungstenPalette.steelWhite
        }()

        let fill: Color = {
            if configuration.isPressed {
                return ColdTungstenPalette.milledControlHover
            }
            if isActive {
                return ColdTungstenPalette.activeSelectionFill
            }
            if role != .standard {
                return accentColor.opacity(0.11)
            }
            return ColdTungstenPalette.brushedSteel
        }()

        let border: Color = {
            if isActive || role != .standard {
                return accentColor.opacity(isActive ? 0.85 : 0.45)
            }
            return ColdTungstenPalette.tungstenSeam
        }()

        configuration.label
            .font(ColdTungstenTypography.controlLabel)
            .foregroundStyle(foreground)
            .padding(.horizontal, compact ? 7 : 10)
            .padding(.vertical, compact ? 4 : 5)
            .background(fill)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard)
                    .strokeBorder(border, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusStandard))
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .animation(.easeOut(duration: 0.10), value: configuration.isPressed)
            .fixedSize(horizontal: true, vertical: true)
    }
}

@MainActor
public struct TungstenKeycapBadge: View {
    public let keys: String

    public init(_ keys: String) {
        self.keys = keys
    }

    public var body: some View {
        Text(keys)
            .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
            .foregroundStyle(ColdTungstenPalette.coolPewter)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(ColdTungstenPalette.chassisBackground)
            .overlay(
                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
            )
            .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
            .fixedSize(horizontal: true, vertical: true)
    }
}

@MainActor
public struct TungstenPanelHeaderBar<TrailingContent: View>: View {
    public let title: String
    public let sfSymbol: String?
    public let countBadge: Int?
    private let trailingContent: TrailingContent

    public init(
        title: String,
        sfSymbol: String? = nil,
        countBadge: Int? = nil,
        @ViewBuilder trailing: () -> TrailingContent
    ) {
        self.title = title
        self.sfSymbol = sfSymbol
        self.countBadge = countBadge
        self.trailingContent = trailing()
    }

    public var body: some View {
        HStack(spacing: 8) {
            if let sfSymbol {
                Image(systemName: sfSymbol)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
            }
            Text(title)
                .font(ColdTungstenTypography.panelHeaderTitle)
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .fixedSize(horizontal: true, vertical: false)

            if let countBadge {
                Text("\(countBadge)")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(ColdTungstenPalette.chassisBackground)
                    .overlay(
                        RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                            .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact))
                    .fixedSize(horizontal: true, vertical: true)
            }

            Spacer(minLength: 8)
            trailingContent
        }
        .padding(.horizontal, 10)
        .frame(height: ColdTungstenMetrics.panelHeaderHeight)
        .background(ColdTungstenPalette.brushedSteel)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)
        }
    }
}

extension TungstenPanelHeaderBar where TrailingContent == EmptyView {
    public init(title: String, sfSymbol: String? = nil, countBadge: Int? = nil) {
        self.init(title: title, sfSymbol: sfSymbol, countBadge: countBadge) {
            EmptyView()
        }
    }
}
