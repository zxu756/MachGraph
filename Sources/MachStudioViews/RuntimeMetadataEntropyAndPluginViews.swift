import Foundation
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachPatchAndHexEngine
import MachPluginSDK
import MachWorkbenchShell
import SwiftUI

// MARK: - 1. Strings, ObjC 2.0, Swift 5 Types & Dyld Chained Fixups Studio (`.stringsAndObjC`)

@MainActor
public struct StringsAndRuntimeMetadataStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    @ObservedObject private var cursorBus: SynchronizedAddressCursorBus
    @ObservedObject private var localizer: MachLocalizer = .shared

    @State private var selectedObjCClassID: String?

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
        self.cursorBus = viewModel.cursorBus
    }

    private var filteredStrings: [ExtractedStringLiteral] {
        guard let all = viewModel.loadedImage?.strings else { return [] }
        let query = viewModel.stringsFilterQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return all.filter { item in
            if let enc = viewModel.stringsEncodingFilter, item.encoding != enc {
                return false
            }
            guard !query.isEmpty else { return true }
            return item.value.lowercased().contains(query)
                || item.sectionName.lowercased().contains(query)
                || item.address.compactHexString.lowercased().contains(query)
        }
    }

    private var activeObjCClass: ObjCClassMetadata? {
        guard let classes = viewModel.loadedImage?.objcClasses, !classes.isEmpty else { return nil }
        if let id = selectedObjCClassID, let match = classes.first(where: { $0.id == id }) {
            return match
        }
        return classes.first
    }

    public var body: some View {
        VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Runtime Metadata, Cross-Referenced Strings & PAC Fixups", "运行时元数据、交叉引用字符串与 PAC 修复"),
                sfSymbol: "character.book.closed"
            ) {
                HStack(spacing: 6) {
                    ForEach(RuntimeMetadataSubTab.allCases) { tab in
                        let active = viewModel.runtimeSubTab == tab
                        Button(tab.localizedTitle(in: localizer.language)) {
                            viewModel.runtimeSubTab = tab
                        }
                        .buttonStyle(TungstenToolbarButtonStyle(
                            role: active ? .accentSapphire : .standard,
                            isActive: active,
                            compact: true
                        ))
                        .fixedSize(horizontal: true, vertical: false)
                    }
                }
            }

            switch viewModel.runtimeSubTab {
            case .cStrings:
                cStringsTableContent
            case .objcAndSwift:
                objcAndSwiftSplitContent
            case .chainedFixups:
                chainedFixupsTableContent
            }
        }
        .background(ColdTungstenPalette.chassisBackground)
    }

    // MARK: Sub-Tab A: Cross-Referenced C-Strings & UTF-16 Literals

    private var cStringsTableContent: some View {
        let rows = filteredStrings
        return VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)

                TextField(
                    localizer.L(
                        "Filter extracted UTF-8 / UTF-16 / ObjC selector literals...",
                        "筛选提取的 UTF-8 / UTF-16 / ObjC 选择器字符串..."
                    ),
                    text: $viewModel.stringsFilterQuery
                )
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

                encodingFilterPill(title: localizer.L("All", "全部"), encoding: nil)
                encodingFilterPill(title: "ASCII", encoding: .ascii)
                encodingFilterPill(title: "UTF-8", encoding: .utf8)
                encodingFilterPill(title: "UTF-16LE", encoding: .utf16LE)
                encodingFilterPill(title: localizer.L("Selector", "选择器"), encoding: .objcSelector)

                Spacer(minLength: 6)

                Text(localizer.language == .zhHans ? "\(rows.count) 条字符串" : "\(rows.count) literal(s)")
                    .font(ColdTungstenTypography.microBadgeMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(ColdTungstenPalette.gunmetalSlate)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            HStack(spacing: 10) {
                Text(localizer.L("VIRTUAL ADDR", "虚拟地址")).frame(width: 96, alignment: .leading)
                Text(localizer.L("SECTION", "节区")).frame(width: 132, alignment: .leading)
                Text(localizer.L("ENCODING", "编码")).frame(width: 78, alignment: .leading)
                Text(localizer.L("XREFS", "交叉引用")).frame(width: 58, alignment: .leading)
                Text(localizer.L("LITERAL VALUE", "字面量内容"))
                Spacer()
            }
            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            ScrollView(.vertical, showsIndicators: true) {
                LazyVStack(spacing: 0) {
                    ForEach(rows) { item in
                        let xrefs = viewModel.analysisIndex?.xrefsTo(address: item.address) ?? []
                        let isSelected = cursorBus.currentLocation.virtualAddress == item.address
                        HStack(alignment: .top, spacing: 10) {
                            Text(item.address.compactHexString)
                                .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .semibold))
                                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                .frame(width: 96, alignment: .leading)
                                .fixedSize(horizontal: true, vertical: false)

                            Text(item.sectionName)
                                .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                .foregroundStyle(ColdTungstenPalette.coolPewter)
                                .frame(width: 132, alignment: .leading)
                                .fixedSize(horizontal: true, vertical: false)

                            Text(item.encoding.rawValue)
                                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .semibold))
                                .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                                .frame(width: 78, alignment: .leading)
                                .fixedSize(horizontal: true, vertical: false)

                            Text(localizer.language == .zhHans ? "\(xrefs.count) 引用" : "\(xrefs.count) ref")
                                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                                .foregroundStyle(xrefs.isEmpty ? ColdTungstenPalette.mutedOffsetInk : ColdTungstenPalette.signalEmerald)
                                .frame(width: 58, alignment: .leading)
                                .fixedSize(horizontal: true, vertical: false)

                            VStack(alignment: .leading, spacing: 3) {
                                Text("\"\(item.value)\"")
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.stringLiteralTint)
                                    .fixedSize(horizontal: false, vertical: true)

                                if let firstXref = xrefs.first {
                                    Text(
                                        localizer.language == .zhHans
                                            ? "引用自 \(viewModel.displaySymbolOrFunction(at: firstXref.fromAddress)) (\(firstXref.instructionPreview))"
                                            : "Referenced from \(viewModel.displaySymbolOrFunction(at: firstXref.fromAddress)) (\(firstXref.instructionPreview))"
                                    )
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.0))
                                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                                    .fixedSize(horizontal: false, vertical: true)
                                }
                            }

                            Spacer(minLength: 6)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(isSelected ? ColdTungstenPalette.activeSelectionFill : Color.clear)
                        .overlay(alignment: .bottom) {
                            Rectangle()
                                .fill(ColdTungstenPalette.tungstenSeam.opacity(0.45))
                                .frame(height: ColdTungstenMetrics.borderHairline)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture {
                            let target = xrefs.first?.fromAddress ?? item.address
                            cursorBus.jump(
                                toAddress: target,
                                in: viewModel.loadedImage,
                                functions: viewModel.functions
                            )
                        }
                    }
                }
            }
        }
    }

    private func encodingFilterPill(title: String, encoding: ExtractedStringEncoding?) -> some View {
        let active = viewModel.stringsEncodingFilter == encoding
        return Button(title) {
            viewModel.stringsEncodingFilter = encoding
        }
        .buttonStyle(TungstenToolbarButtonStyle(
            role: active ? .accentSapphire : .standard,
            isActive: active,
            compact: true
        ))
        .fixedSize(horizontal: true, vertical: false)
    }

    // MARK: Sub-Tab B: Objective-C 2.0 Classes/Selectors/Ivars & Swift 5 Nominal Descriptors

    private var objcAndSwiftSplitContent: some View {
        let objcClasses = viewModel.loadedImage?.objcClasses ?? []
        let swiftTypes = viewModel.loadedImage?.swiftTypes ?? []

        return HStack(spacing: 0) {
            // Left: Objective-C 2.0 Classes, Methods & Ivars
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    Label(localizer.L("Objective-C 2.0 Metadata (__objc_classlist)", "Objective-C 2.0 元数据 (__objc_classlist)"), systemImage: "cube.box.fill")
                        .font(ColdTungstenTypography.panelHeaderTitle)
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 4)

                    Text(localizer.language == .zhHans ? "\(objcClasses.count) 个类" : "\(objcClasses.count) class(es)")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(ColdTungstenPalette.gunmetalSlate)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                if objcClasses.isEmpty {
                    Text(localizer.L("No Objective-C metadata sections present in active binary container.", "当前二进制容器未包含 Objective-C 元数据节区。"))
                        .font(ColdTungstenTypography.controlLabel)
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .padding(18)
                    Spacer()
                } else {
                    ScrollView(.vertical, showsIndicators: true) {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(objcClasses) { cls in
                                objcClassDetailCard(cls)
                            }
                        }
                        .padding(10)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline)

            // Right: Swift 5 Nominal Type Descriptors & Imported Libraries
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 8) {
                    Label(localizer.L("Swift 5 Nominal Types (__swift5_types) & Dyld Imports", "Swift 5 名义类型 (__swift5_types) 与动态导入"), systemImage: "swift")
                        .font(ColdTungstenTypography.panelHeaderTitle)
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 4)

                    Text(localizer.language == .zhHans ? "\(swiftTypes.count) 个类型" : "\(swiftTypes.count) type(s)")
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(ColdTungstenPalette.gunmetalSlate)

                Rectangle()
                    .fill(ColdTungstenPalette.tungstenSeam)
                    .frame(height: ColdTungstenMetrics.borderHairline)

                ScrollView(.vertical, showsIndicators: true) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(swiftTypes) { desc in
                            swiftTypeDescriptorCard(desc)
                        }

                        if let libs = viewModel.loadedImage?.importedLibraries, !libs.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(localizer.L("LINKED DYNAMIC LIBRARIES", "链接动态库"))
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                                ForEach(libs) { lib in
                                    HStack(spacing: 8) {
                                        Text("#\(lib.ordinal)")
                                            .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                                            .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                            .fixedSize(horizontal: true, vertical: false)

                                        Text(lib.installName)
                                            .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                                            .fixedSize(horizontal: false, vertical: true)

                                        Spacer(minLength: 4)

                                        Text("v\(lib.currentVersion)")
                                            .font(ColdTungstenTypography.offsetGutterMono(size: 10.0))
                                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                                            .fixedSize(horizontal: true, vertical: false)
                                    }
                                    .padding(7)
                                    .background(ColdTungstenPalette.gunmetalSlate)
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                }
                            }
                            .padding(10)
                            .background(ColdTungstenPalette.chassisBackground)
                            .overlay(
                                RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                                    .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                            )
                        }
                    }
                    .padding(10)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func objcClassDetailCard(_ cls: ObjCClassMetadata) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("@interface \(cls.name) : \(cls.superclassName ?? "NSObject")")
                    .font(ColdTungstenTypography.disassemblyMono(size: 12.0, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.signalEmerald)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 4)

                Text("\(cls.instanceSize) B · \(cls.address.compactHexString)")
                    .font(ColdTungstenTypography.addressMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .fixedSize(horizontal: true, vertical: false)
            }

            if !cls.methods.isEmpty {
                Text(localizer.language == .zhHans ? "方法 (\(cls.methods.count))" : "METHODS (\(cls.methods.count))")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                ForEach(cls.methods) { method in
                    Button {
                        cursorBus.jump(
                            toAddress: method.implementationAddress,
                            in: viewModel.loadedImage,
                            functions: viewModel.functions,
                            switchToPane: .cfgGraph
                        )
                    } label: {
                        HStack(spacing: 8) {
                            Text("\(method.isClassMethod ? "+" : "-")[\(cls.name) \(method.selector)]")
                                .font(ColdTungstenTypography.disassemblyMono(size: 11.0, weight: .semibold))
                                .foregroundStyle(ColdTungstenPalette.steelWhite)
                                .fixedSize(horizontal: false, vertical: true)

                            Spacer(minLength: 6)

                            Text(method.typeEncoding)
                                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                                .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                                .fixedSize(horizontal: true, vertical: false)

                            Text(method.implementationAddress.compactHexString)
                                .font(ColdTungstenTypography.addressMono(size: 10.5, weight: .semibold))
                                .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                .fixedSize(horizontal: true, vertical: false)
                        }
                        .padding(6)
                        .background(ColdTungstenPalette.chassisBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    .buttonStyle(.plain)
                }
            }

            if !cls.ivars.isEmpty {
                Text(localizer.language == .zhHans ? "实例变量 (\(cls.ivars.count))" : "INSTANCE VARIABLES (\(cls.ivars.count))")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                ForEach(cls.ivars) { ivar in
                    HStack(spacing: 8) {
                        Text(String(format: "+0x%02X", ivar.offset))
                            .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                            .fixedSize(horizontal: true, vertical: false)

                        Text(ivar.name)
                            .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                            .fixedSize(horizontal: true, vertical: false)

                        Spacer(minLength: 4)

                        Text("\(ivar.typeEncoding) (\(ivar.size) B)")
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private func swiftTypeDescriptorCard(_ desc: SwiftTypeDescriptor) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(desc.kind.rawValue.uppercased())
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.warmCopper)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(ColdTungstenPalette.warmCopper.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: 3))
                    .fixedSize(horizontal: true, vertical: false)

                Text(desc.demangledName)
                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 4)

                Text(desc.address.compactHexString)
                    .font(ColdTungstenTypography.addressMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    .fixedSize(horizontal: true, vertical: false)
            }

            Text(desc.mangledName)
                .font(ColdTungstenTypography.offsetGutterMono(size: 10.0))
                .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                .fixedSize(horizontal: false, vertical: true)

            if !desc.fieldNames.isEmpty {
                ForEach(Array(desc.fieldNames.enumerated()), id: \.offset) { idx, fieldName in
                    let fieldType = desc.fieldTypes.indices.contains(idx) ? desc.fieldTypes[idx] : "Any"
                    HStack(spacing: 6) {
                        Text("let \(fieldName):")
                            .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                        Text(fieldType)
                            .font(ColdTungstenTypography.disassemblyMono(size: 11.0, weight: .semibold))
                            .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                    }
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    // MARK: Sub-Tab C: Dyld `LC_DYLD_CHAINED_FIXUPS` ARM64e PAC Pointer Table

    private var chainedFixupsTableContent: some View {
        let fixups = viewModel.loadedImage?.chainedFixups ?? []
        return VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text(localizer.L("POINTER VA", "指针虚拟地址")).frame(width: 104, alignment: .leading)
                Text(localizer.L("FILE OFF", "文件偏移")).frame(width: 82, alignment: .leading)
                Text(localizer.L("FIXUP KIND", "修复类型")).frame(width: 140, alignment: .leading)
                Text(localizer.L("PAC KEY / DIV", "PAC 密钥 / 多样因子")).frame(width: 120, alignment: .leading)
                Text(localizer.L("TARGET SYMBOL / ADDRESS", "目标符号 / 地址"))
                Spacer()
            }
            .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
            .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(ColdTungstenPalette.brushedSteel)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(height: ColdTungstenMetrics.borderHairline)

            if fixups.isEmpty {
                Text(localizer.L("No LC_DYLD_CHAINED_FIXUPS pointer chains present in active container.", "当前容器未包含 LC_DYLD_CHAINED_FIXUPS 链式指针表。"))
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .padding(24)
                Spacer()
            } else {
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(spacing: 0) {
                        ForEach(fixups) { item in
                            HStack(spacing: 10) {
                                Text(item.location.compactHexString)
                                    .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .semibold))
                                    .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                                    .frame(width: 104, alignment: .leading)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(item.fileOffset.hexString)
                                    .font(ColdTungstenTypography.offsetGutterMono(size: 10.5))
                                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                                    .frame(width: 82, alignment: .leading)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(item.kind.rawValue)
                                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                                    .foregroundStyle(
                                        item.pacKey != nil
                                            ? ColdTungstenPalette.tungstenAmber
                                            : ColdTungstenPalette.coolPewter
                                    )
                                    .frame(width: 140, alignment: .leading)
                                    .fixedSize(horizontal: true, vertical: false)

                                Text(
                                    item.pacKey != nil
                                        ? "\(item.pacKey ?? "IA") · div 0x\(String(item.pacDiversity ?? 0, radix: 16, uppercase: true))"
                                        : localizer.L("unauthenticated", "未签名指针")
                                )
                                .font(ColdTungstenTypography.microBadgeMono(size: 10.0))
                                .foregroundStyle(item.pacKey != nil ? ColdTungstenPalette.warmCopper : ColdTungstenPalette.mutedOffsetInk)
                                .frame(width: 120, alignment: .leading)
                                .fixedSize(horizontal: true, vertical: false)

                                Text(item.symbolName ?? item.targetAddress?.compactHexString ?? "rebase")
                                    .font(ColdTungstenTypography.disassemblyMono(size: 11.5))
                                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                                    .fixedSize(horizontal: false, vertical: true)

                                Spacer()
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                Rectangle()
                                    .fill(ColdTungstenPalette.tungstenSeam.opacity(0.45))
                                    .frame(height: ColdTungstenMetrics.borderHairline)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                cursorBus.jump(
                                    toAddress: item.targetAddress ?? item.location,
                                    in: viewModel.loadedImage,
                                    functions: viewModel.functions
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// MARK: - 2. Sliding-Window Entropy, Chi-Square & CodeSignature Studio (`.entropyAndSign`)

@MainActor
public struct EntropyAndCodeSignStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    @ObservedObject private var cursorBus: SynchronizedAddressCursorBus
    @ObservedObject private var localizer: MachLocalizer = .shared

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
        self.cursorBus = viewModel.cursorBus
    }

    public var body: some View {
        VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L(
                    "Sliding-Window Shannon Entropy, Chi-Square Randomness & LC_CODE_SIGNATURE",
                    "滑动窗口香农熵、卡方随机性与代码签名"
                ),
                sfSymbol: "waveform.path.ecg.rectangle"
            ) {
                HStack(spacing: 6) {
                    Button {
                        cursorBus.activePane = .pluginFindings
                    } label: {
                        Label(
                            localizer.language == .zhHans
                                ? "插件审计 (\(viewModel.securityFindings.count))"
                                : "Plugin Audit (\(viewModel.securityFindings.count))",
                            systemImage: "puzzlepiece.extension"
                        )
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, compact: true))
                    .fixedSize(horizontal: true, vertical: false)

                    Button {
                        viewModel.reSignActiveMachOBinary()
                    } label: {
                        Label(localizer.L("Verify & Re-Sign", "校验并重签名"), systemImage: "checkmark.seal.fill")
                    }
                    .buttonStyle(TungstenToolbarButtonStyle(role: .positiveEmerald, isActive: true, compact: true))
                    .fixedSize(horizontal: true, vertical: false)
                }
            }

            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 10) {
                    topEntropyKPIRow
                    slidingWindowEntropyCanvasCard
                    HStack(alignment: .top, spacing: 10) {
                        sectionPermissionsAndEntropyCard
                            .frame(maxWidth: .infinity)

                        codeSignatureAndEntitlementsCard
                            .frame(maxWidth: .infinity)
                    }
                }
                .padding(10)
            }
            .background(ColdTungstenPalette.chassisBackground)
        }
    }

    private var topEntropyKPIRow: some View {
        let metrics = viewModel.entropyReport?.overallMetrics
        let sigVerify = viewModel.lastReSignResult?.verificationReport ?? viewModel.codeSignatureReport
        let highCritCount = viewModel.securityFindings.filter { $0.severity >= .high }.count

        return HStack(spacing: 8) {
            kpiTelemetryTile(
                label: localizer.L("SHANNON ENTROPY", "香农熵"),
                primary: String(format: "%.3f b/B", metrics?.shannonEntropyBits ?? 0.0),
                secondary: localizer.language == .zhHans
                    ? "最小熵 \(String(format: "%.2f", metrics?.minEntropyBits ?? 0.0)) b/B · \(viewModel.entropyReport?.samples.count ?? 0) 窗口"
                    : "Min-H \(String(format: "%.2f", metrics?.minEntropyBits ?? 0.0)) b/B · \(viewModel.entropyReport?.samples.count ?? 0) windows",
                accent: ColdTungstenPalette.tungstenSapphire
            )

            kpiTelemetryTile(
                label: localizer.L("PEARSON CHI-SQ", "皮尔逊卡方"),
                primary: String(format: "χ² %.1f", metrics?.byteChiSquare ?? 0.0),
                secondary: String(format: "p = %.4f · r = %+.3f", metrics?.byteChiSquarePValue ?? 0.0, metrics?.serialCorrelationCoefficient ?? 0.0),
                accent: ColdTungstenPalette.warmCopper
            )

            kpiTelemetryTile(
                label: localizer.L("BIGRAM H(Xt|Xt-1)", "二元条件熵 H(Xt|Xt-1)"),
                primary: String(format: "%.3f b/B", metrics?.bigramConditionalEntropyBits ?? 0.0),
                secondary: localizer.language == .zhHans
                    ? String(format: "可见字符 %.0f%% · 零字节 %.0f%%", (metrics?.printableByteRatio ?? 0) * 100, (metrics?.zeroByteRatio ?? 0) * 100)
                    : String(format: "ASCII %.0f%% · Zero %.0f%%", (metrics?.printableByteRatio ?? 0) * 100, (metrics?.zeroByteRatio ?? 0) * 100),
                accent: ColdTungstenPalette.signalEmerald
            )

            kpiTelemetryTile(
                label: localizer.L("CODESIGN SLOTS", "代码签名槽位"),
                primary: sigVerify?.isSigned == true
                    ? "\(sigVerify?.verifiedCodeSlots ?? 0)/\(sigVerify?.totalCodeSlots ?? 0) SHA-256"
                    : localizer.L("Unsigned Image", "未签名镜像"),
                secondary: sigVerify?.isValid == true
                    ? localizer.L("Ad-Hoc CDHash Verified", "临时签名 CDHash 已验证")
                    : localizer.L("Container Unsealed", "容器未封签"),
                accent: sigVerify?.isValid == true ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber
            )

            kpiTelemetryTile(
                label: localizer.L("AUDIT FINDINGS", "安全审计发现"),
                primary: localizer.language == .zhHans
                    ? "共 \(viewModel.securityFindings.count) 项"
                    : "\(viewModel.securityFindings.count) Total",
                secondary: localizer.language == .zhHans
                    ? "4 款 JSC 插件检出 \(highCritCount) 项高危"
                    : "\(highCritCount) Critical/High across 4 JSC plugins",
                accent: highCritCount > 0 ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.signalEmerald
            )
        }
    }

    private func kpiTelemetryTile(label: String, primary: String, secondary: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 5) {
                Circle()
                    .fill(accent)
                    .frame(width: 6, height: 6)
                Text(label)
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    .fixedSize(horizontal: true, vertical: false)
            }

            Text(primary)
                .font(ColdTungstenTypography.disassemblyMono(size: 14.0, weight: .bold))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .fixedSize(horizontal: true, vertical: false)

            Text(secondary)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var slidingWindowEntropyCanvasCard: some View {
        let samples = viewModel.entropyReport?.samples ?? []
        let totalBytes = Double(max(1, viewModel.overlayBuffer.count))
        let sections = viewModel.loadedImage?.sections ?? []

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Label(
                    localizer.language == .zhHans
                        ? "滑动窗口熵谱 (窗口 \(viewModel.entropyReport?.windowSize ?? 256) B · 步长 \(viewModel.entropyReport?.stepSize ?? 128) B)"
                        : "Sliding-Window Entropy Spectrum (Window \(viewModel.entropyReport?.windowSize ?? 256) B · Step \(viewModel.entropyReport?.stepSize ?? 128) B)",
                    systemImage: "chart.xyaxis.line"
                )
                .font(ColdTungstenTypography.panelHeaderTitle)
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 6)

                legendSwatch(color: ColdTungstenPalette.tungstenSapphire, label: localizer.L("Native A64 Code (5.2–7.2)", "原生 A64 代码 (5.2–7.2)"))
                legendSwatch(color: ColdTungstenPalette.signalEmerald, label: localizer.L("ASCII / Literals", "ASCII / 字符串"))
                legendSwatch(color: ColdTungstenPalette.warmCopper, label: localizer.L("Packed / Crypto (≥7.25)", "加壳 / 加密 (≥7.25)"))
                legendSwatch(color: ColdTungstenPalette.coolPewter, label: localizer.L("Headers / Zero Pad", "头部 / 零填充"))
            }

            GeometryReader { geo in
                let plotWidth = max(120, geo.size.width - 42)
                let plotHeight = max(80, geo.size.height - 24)
                let leftAxisWidth: CGFloat = 34

                ZStack(alignment: .topLeading) {
                    Canvas { ctx, size in
                        let rect = CGRect(x: leftAxisWidth, y: 6, width: plotWidth, height: plotHeight)
                        ctx.fill(Path(rect), with: .color(ColdTungstenPalette.chassisBackground))

                        // Horizontal entropy guide lines (0, 2, 4, 6, 7.25 threshold, 8 b/B)
                        let guides: [(Double, Bool)] = [(0, false), (2, false), (4, false), (6, false), (7.25, true), (8, false)]
                        for (bits, isPackedLine) in guides {
                            let y = rect.maxY - CGFloat(bits / 8.0) * rect.height
                            var line = Path()
                            line.move(to: CGPoint(x: rect.minX, y: y))
                            line.addLine(to: CGPoint(x: rect.maxX, y: y))
                            if isPackedLine {
                                ctx.stroke(
                                    line,
                                    with: .color(ColdTungstenPalette.anodizedCrimson.opacity(0.60)),
                                    style: StrokeStyle(lineWidth: 1.0, dash: [5, 4])
                                )
                            } else {
                                ctx.stroke(line, with: .color(ColdTungstenPalette.tungstenSeam.opacity(0.55)), lineWidth: 0.75)
                            }
                            let labelText = Text(bits == 7.25 ? "7.2" : String(format: "%.0f", bits))
                                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                                .foregroundColor(isPackedLine ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.mutedOffsetInk)
                            ctx.draw(labelText, at: CGPoint(x: 16, y: y), anchor: .center)
                        }

                        // Vertical section boundary dividers
                        for sec in sections {
                            let xRatio = Double(sec.fileOffset.rawValue) / totalBytes
                            guard xRatio >= 0.0 && xRatio <= 1.0 else { continue }
                            let x = rect.minX + CGFloat(xRatio) * rect.width
                            var vLine = Path()
                            vLine.move(to: CGPoint(x: x, y: rect.minY))
                            vLine.addLine(to: CGPoint(x: x, y: rect.maxY))
                            ctx.stroke(
                                vLine,
                                with: .color(ColdTungstenPalette.tungstenSapphire.opacity(0.32)),
                                style: StrokeStyle(lineWidth: 1.0, dash: [3, 3])
                            )
                        }

                        // Draw discrete histogram columns + crisp top waveform polyline
                        if !samples.isEmpty {
                            let stepWidth = max(2.0, rect.width / CGFloat(samples.count))
                            var wavePath = Path()

                            for (idx, sample) in samples.enumerated() {
                                let x = rect.minX + CGFloat(idx) * (rect.width / CGFloat(max(1, samples.count)))
                                let clampedH = min(8.0, max(0.0, sample.entropyBitsPerByte))
                                let barHeight = max(2.0, CGFloat(clampedH / 8.0) * rect.height)
                                let y = rect.maxY - barHeight
                                let barColor = colorForClassification(sample.classification)

                                let barRect = CGRect(x: x, y: y, width: max(1.5, stepWidth - 1.0), height: barHeight)
                                ctx.fill(Path(barRect), with: .color(barColor.opacity(0.30)))

                                let midPoint = CGPoint(x: x + stepWidth * 0.5, y: y)
                                if idx == 0 {
                                    wavePath.move(to: midPoint)
                                } else {
                                    wavePath.addLine(to: midPoint)
                                }
                            }

                            ctx.stroke(
                                wavePath,
                                with: .color(ColdTungstenPalette.tungstenSapphire),
                                style: StrokeStyle(lineWidth: 1.75, lineCap: .round, lineJoin: .round)
                            )
                        }

                        ctx.stroke(Path(rect), with: .color(ColdTungstenPalette.tungstenSeam), lineWidth: 1.0)
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { tapLocation in
                        let plotMinX = leftAxisWidth
                        guard tapLocation.x >= plotMinX, !samples.isEmpty else { return }
                        let frac = min(1.0, max(0.0, (tapLocation.x - plotMinX) / plotWidth))
                        let idx = min(samples.count - 1, Int(frac * CGFloat(samples.count)))
                        let picked = samples[idx]
                        viewModel.selectedHexByteOffset = picked.fileOffset
                        viewModel.hexScrollOffset = FileOffset((picked.fileOffset.rawValue / 16) * 16)
                        if let va = picked.virtualAddress {
                            cursorBus.jump(toAddress: va, in: viewModel.loadedImage, functions: viewModel.functions)
                        }
                    }

                    // Bottom section offset strip
                    HStack(spacing: 12) {
                        Text("0x0000")
                        Spacer()
                        ForEach(sections.prefix(4)) { sec in
                            Text("\(sec.sectionName) @ \(sec.fileOffset.hexString)")
                        }
                        Spacer()
                        Text(String(format: "0x%llX", UInt64(totalBytes)))
                    }
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                    .padding(.leading, leftAxisWidth)
                    .padding(.trailing, 8)
                    .frame(maxHeight: .infinity, alignment: .bottom)
                }
            }
            .frame(height: 176)
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private func legendSwatch(color: Color, label: String) -> some View {
        HStack(spacing: 4) {
            RoundedRectangle(cornerRadius: 2)
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: true, vertical: false)
        }
    }

    private func colorForClassification(_ cls: EntropyClassification) -> Color {
        switch cls {
        case .nativeMachineCode:
            return ColdTungstenPalette.tungstenSapphire
        case .printableStrings:
            return ColdTungstenPalette.signalEmerald
        case .compressedOrEncrypted:
            return ColdTungstenPalette.warmCopper
        case .structuredMetadata:
            return ColdTungstenPalette.tungstenAmber
        case .nullPadding:
            return ColdTungstenPalette.coolPewter
        }
    }

    private var sectionPermissionsAndEntropyCard: some View {
        let sections = viewModel.loadedImage?.sections ?? []
        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(localizer.L("Segment / Section RWX Map & Shannon H(X)", "段/节区 RWX 权限与香农熵"), systemImage: "memorychip")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Text(localizer.language == .zhHans ? "\(sections.count) 个节区" : "\(sections.count) sections")
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: true, vertical: false)
            }

            ForEach(sections) { sec in
                let isRWX = sec.permissions.rwxString.contains("w") && sec.permissions.rwxString.contains("x")
                HStack(spacing: 8) {
                    Text(sec.permissions.rwxString)
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                        .foregroundStyle(isRWX ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.signalEmerald)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background((isRWX ? ColdTungstenPalette.anodizedCrimson : ColdTungstenPalette.signalEmerald).opacity(0.14))
                        .clipShape(RoundedRectangle(cornerRadius: 2.5))
                        .fixedSize(horizontal: true, vertical: false)

                    Text(sec.fullName)
                        .font(ColdTungstenTypography.disassemblyMono(size: 11.0, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.steelWhite)
                        .frame(width: 158, alignment: .leading)
                        .fixedSize(horizontal: true, vertical: false)

                    Text(sec.vmAddress.compactHexString)
                        .font(ColdTungstenTypography.addressMono(size: 10.5))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .fixedSize(horizontal: true, vertical: false)

                    Spacer(minLength: 4)

                    Text("\(sec.size) B")
                        .font(ColdTungstenTypography.offsetGutterMono(size: 10.0))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .fixedSize(horizontal: true, vertical: false)

                    Text(String(format: "H=%.2f", sec.shannonEntropy))
                        .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                        .foregroundStyle(
                            sec.shannonEntropy >= 7.25
                                ? ColdTungstenPalette.warmCopper
                                : ColdTungstenPalette.tungstenSapphire
                        )
                        .frame(width: 50, alignment: .trailing)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(ColdTungstenPalette.chassisBackground)
                .clipShape(RoundedRectangle(cornerRadius: 3.5))
                .contentShape(Rectangle())
                .onTapGesture {
                    cursorBus.jump(toAddress: sec.vmAddress, in: viewModel.loadedImage, functions: viewModel.functions)
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var codeSignatureAndEntitlementsCard: some View {
        let summary = viewModel.lastReSignResult?.updatedSummary ?? viewModel.loadedImage?.codeSignature ?? .unsigned
        let verify = viewModel.lastReSignResult?.verificationReport ?? viewModel.codeSignatureReport
        let cleanCDHash = String((verify?.cdHashHex ?? summary.cdHashHex).prefix(32))

        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(localizer.L("LC_CODE_SIGNATURE SuperBlob & Entitlements", "LC_CODE_SIGNATURE 超级块与权限配置"), systemImage: "lock.shield.fill")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Text(
                    summary.isSigned
                        ? (summary.isAdHoc ? localizer.L("AD-HOC SHA-256", "临时签名 SHA-256") : localizer.L("CMS SIGNED", "CMS 签名"))
                        : localizer.L("UNSIGNED", "未签名")
                )
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                .foregroundStyle(summary.isSigned ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background((summary.isSigned ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.tungstenAmber).opacity(0.15))
                .clipShape(RoundedRectangle(cornerRadius: 3))
                .fixedSize(horizontal: true, vertical: false)
            }

            VStack(alignment: .leading, spacing: 4) {
                sigKeyValRow(key: localizer.L("Identifier", "标识符"), value: summary.identifier.isEmpty ? "com.machgraph.target" : summary.identifier)
                sigKeyValRow(key: "CDHash (128b)", value: cleanCDHash.isEmpty ? localizer.L("none", "无") : cleanCDHash)
                sigKeyValRow(
                    key: localizer.L("CodeDirectory", "代码目录"),
                    value: localizer.language == .zhHans
                        ? String(
                            format: "v0x%X · %@ · %d B 页 · %d/%d 槽有效",
                            summary.codeDirectoryVersion,
                            summary.hashAlgorithm,
                            summary.pageSize,
                            verify?.verifiedCodeSlots ?? 0,
                            verify?.totalCodeSlots ?? 0
                        )
                        : String(
                            format: "v0x%X · %@ · %d B page · %d/%d slots valid",
                            summary.codeDirectoryVersion,
                            summary.hashAlgorithm,
                            summary.pageSize,
                            verify?.verifiedCodeSlots ?? 0,
                            verify?.totalCodeSlots ?? 0
                        )
                )
            }
            .padding(8)
            .background(ColdTungstenPalette.chassisBackground)
            .clipShape(RoundedRectangle(cornerRadius: 4))

            if !summary.entitlements.isEmpty {
                Text(localizer.L("EMBEDDED ENTITLEMENTS DER / PLIST", "内嵌权限声明 DER / PLIST"))
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)

                ForEach(summary.entitlements.keys.sorted(), id: \.self) { entKey in
                    let val = summary.entitlements[entKey].map(Self.formatEntitlementBadge) ?? ""
                    let risky = entKey.contains("get-task-allow") || entKey.contains("disable-library-validation") || entKey.contains("cs.allow")
                    HStack(spacing: 6) {
                        Image(systemName: risky ? "exclamationmark.shield.fill" : "checkmark.circle.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(risky ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.signalEmerald)

                        Text(entKey)
                            .font(ColdTungstenTypography.disassemblyMono(size: 10.5))
                            .foregroundStyle(ColdTungstenPalette.steelWhite)
                            .fixedSize(horizontal: false, vertical: true)

                        Spacer(minLength: 4)

                        Text(val)
                            .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .bold))
                            .foregroundStyle(risky ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.tungstenSapphire)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(ColdTungstenPalette.chassisBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 3))
                }
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private static func formatEntitlementBadge(_ value: EntitlementValue) -> String {
        switch value {
        case .bool(let b): return b ? "true" : "false"
        case .integer(let i): return "\(i)"
        case .unsignedInteger(let u): return "\(u)"
        case .real(let d): return "\(d)"
        case .string(let s): return s
        case .data(let raw): return "<\(raw.count) B>"
        case .date(let iso): return iso
        case .array(let items): return "[\(items.count)]"
        case .dictionary(let dict): return "{\(dict.count)}"
        }
    }

    private func sigKeyValRow(key: String, value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(key)
                .font(ColdTungstenTypography.microBadgeMono(size: 10.0, weight: .semibold))
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .frame(width: 96, alignment: .leading)
                .fixedSize(horizontal: true, vertical: false)

            Text(value)
                .font(ColdTungstenTypography.disassemblyMono(size: 10.5, weight: .medium))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .fixedSize(horizontal: false, vertical: true)

            Spacer(minLength: 0)
        }
    }
}

// MARK: - 3. JavaScriptCore Binary Security Audit & Scratchpad Studio (`.pluginFindings`)

@MainActor
public struct PluginSecurityAuditStudioView: View {
    @ObservedObject public var viewModel: MachStudioViewModel
    @ObservedObject private var cursorBus: SynchronizedAddressCursorBus
    @ObservedObject private var preferencesStore: MachWorkbenchPreferencesStore
    @ObservedObject private var localizer: MachLocalizer = .shared

    public init(viewModel: MachStudioViewModel) {
        self.viewModel = viewModel
        self.cursorBus = viewModel.cursorBus
        self.preferencesStore = viewModel.preferencesStore
    }

    private var visibleFindings: [SecurityAuditFinding] {
        guard let filter = viewModel.selectedFindingSeverityFilter else {
            return viewModel.securityFindings
        }
        return viewModel.securityFindings.filter { $0.severity == filter }
    }

    public var body: some View {
        HStack(spacing: 0) {
            leftPluginCatalogAndScratchpadColumn
                .frame(width: 404)

            Rectangle()
                .fill(ColdTungstenPalette.tungstenSeam)
                .frame(width: ColdTungstenMetrics.borderHairline)

            rightAuditFindingsColumn
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(ColdTungstenPalette.chassisBackground)
    }

    private var leftPluginCatalogAndScratchpadColumn: some View {
        VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("JavaScriptCore Sandbox & Plugins", "JavaScriptCore 沙箱与插件"),
                sfSymbol: "puzzlepiece.extension",
                countBadge: BuiltInMachPluginCatalog.allPlugins.count
            ) {
                Button {
                    viewModel.runSecurityAuditSuite(emitToast: true)
                } label: {
                    Label(localizer.L("Run Suite", "运行套件"), systemImage: "play.fill")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .cautionAmber, isActive: true, compact: true))
                .fixedSize(horizontal: true, vertical: false)
            }

            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(BuiltInMachPluginCatalog.allPlugins) { plugin in
                        pluginManifestCard(plugin)
                    }

                    jsScratchpadConsoleCard
                }
                .padding(10)
            }
            .background(ColdTungstenPalette.gunmetalSlate)
        }
    }

    private func pluginManifestCard(_ plugin: MachPluginManifest) -> some View {
        let enabled = preferencesStore.isPluginEnabled(plugin.id)
        let execResult = viewModel.pluginSuiteReport?.results.first(where: { $0.pluginID == plugin.id })

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Button {
                    preferencesStore.setPluginEnabled(plugin.id, isEnabled: !enabled)
                    viewModel.runSecurityAuditSuite(emitToast: false)
                } label: {
                    Image(systemName: enabled ? "checkmark.square.fill" : "square")
                        .foregroundStyle(enabled ? ColdTungstenPalette.signalEmerald : ColdTungstenPalette.mutedOffsetInk)
                }
                .buttonStyle(.plain)

                Text(plugin.localizedName(in: localizer.language))
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 4)

                if let execResult {
                    Text(String(format: "%.1f ms", execResult.durationMilliseconds))
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }

            Text(plugin.localizedSummary(in: localizer.language))
                .font(ColdTungstenTypography.secondaryCaption)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 5) {
                ForEach(plugin.capabilities, id: \.self) { cap in
                    Text(cap.rawValue)
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.0, weight: .semibold))
                        .foregroundStyle(ColdTungstenPalette.coolPewter)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(ColdTungstenPalette.gunmetalSlate)
                        .clipShape(RoundedRectangle(cornerRadius: 2.5))
                        .fixedSize(horizontal: true, vertical: false)
                }

                Spacer(minLength: 4)

                if let count = execResult?.findings.count {
                    Text(localizer.language == .zhHans ? "\(count) 项命中" : "\(count) hit(s)")
                        .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                        .foregroundStyle(count > 0 ? ColdTungstenPalette.tungstenAmber : ColdTungstenPalette.signalEmerald)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }
        }
        .padding(9)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var jsScratchpadConsoleCard: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                Label(localizer.L("Live JSVirtualMachine `mach.*` Scratchpad", "实时 JSVirtualMachine `mach.*` 脚本台"), systemImage: "terminal.fill")
                    .font(ColdTungstenTypography.panelHeaderTitle)
                    .foregroundStyle(ColdTungstenPalette.steelWhite)
                    .fixedSize(horizontal: true, vertical: false)

                Spacer(minLength: 4)

                Button {
                    viewModel.executeJSScratchpad()
                } label: {
                    Label(localizer.L("Run JS", "运行 JS"), systemImage: "bolt.fill")
                }
                .buttonStyle(TungstenToolbarButtonStyle(role: .accentSapphire, isActive: true, compact: true))
                .fixedSize(horizontal: true, vertical: false)
            }

            TextEditor(text: $viewModel.jsScratchpadSource)
                .font(ColdTungstenTypography.disassemblyMono(size: 11.0))
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .scrollContentBackground(.hidden)
                .padding(6)
                .frame(height: 118)
                .background(ColdTungstenPalette.gunmetalSlate)
                .overlay(
                    RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusCompact)
                        .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
                )

            Text(viewModel.scratchpadStatusText)
                .font(ColdTungstenTypography.microBadgeMono(size: 9.5))
                .foregroundStyle(ColdTungstenPalette.signalEmerald)
                .fixedSize(horizontal: false, vertical: true)

            if let logs = viewModel.lastScratchpadResult?.consoleLogs, !logs.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(logs.enumerated()), id: \.offset) { _, line in
                        Text("> \(line)")
                            .font(ColdTungstenTypography.disassemblyMono(size: 10.5))
                            .foregroundStyle(ColdTungstenPalette.coolPewter)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(ColdTungstenPalette.gunmetalSlate)
                .clipShape(RoundedRectangle(cornerRadius: 3))
            }
        }
        .padding(9)
        .background(ColdTungstenPalette.chassisBackground)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }

    private var rightAuditFindingsColumn: some View {
        let items = visibleFindings
        return VStack(spacing: 0) {
            TungstenPanelHeaderBar(
                title: localizer.L("Static Binary Security Audit Findings", "静态二进制安全审计发现"),
                sfSymbol: "exclamationmark.shield.fill",
                countBadge: items.count
            ) {
                HStack(spacing: 5) {
                    severityFilterChip(label: localizer.L("ALL", "全部"), severity: nil)
                    ForEach(SecurityFindingSeverity.allCases.reversed(), id: \.self) { sev in
                        severityFilterChip(label: sev.localizedBadge(in: localizer.language), severity: sev)
                    }
                }
            }

            if items.isEmpty {
                VStack(spacing: 6) {
                    Text(localizer.L(
                        "No security audit findings match the active severity filter.",
                        "当前严重等级筛选下暂无安全审计发现。"
                    ))
                    .font(ColdTungstenTypography.controlLabel)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    Text(localizer.L(
                        "Click 'Run Suite' to execute all 4 JavaScriptCore binary security analyzers.",
                        "点击「运行套件」以执行全部 4 款 JavaScriptCore 二进制安全分析插件。"
                    ))
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.mutedOffsetInk)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(items) { finding in
                            findingDetailCard(finding)
                        }
                    }
                    .padding(10)
                }
            }
        }
    }

    private func severityFilterChip(label: String, severity: SecurityFindingSeverity?) -> some View {
        let active = viewModel.selectedFindingSeverityFilter == severity
        return Button(label) {
            viewModel.selectedFindingSeverityFilter = severity
        }
        .buttonStyle(TungstenToolbarButtonStyle(
            role: active ? .accentSapphire : .standard,
            isActive: active,
            compact: true
        ))
        .fixedSize(horizontal: true, vertical: false)
    }

    private func findingDetailCard(_ finding: SecurityAuditFinding) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                SeverityBadgePill(severity: finding.severity)
                    .fixedSize(horizontal: true, vertical: false)

                Text(finding.localizedCategory(in: localizer.language).uppercased())
                    .font(ColdTungstenTypography.microBadgeMono(size: 9.5, weight: .bold))
                    .foregroundStyle(ColdTungstenPalette.tungstenAmber)
                    .fixedSize(horizontal: true, vertical: false)

                Text("· \(finding.localizedPluginName(in: localizer.language))")
                    .font(ColdTungstenTypography.secondaryCaption)
                    .foregroundStyle(ColdTungstenPalette.coolPewter)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 6)

                if let addr = finding.address {
                    Button {
                        cursorBus.jump(
                            toAddress: addr,
                            in: viewModel.loadedImage,
                            functions: viewModel.functions,
                            switchToPane: .cfgGraph
                        )
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.up.right.square")
                                .font(.system(size: 10, weight: .semibold))
                            Text(addr.compactHexString)
                                .font(ColdTungstenTypography.addressMono(size: 11.0, weight: .bold))
                        }
                        .foregroundStyle(ColdTungstenPalette.tungstenSapphire)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(ColdTungstenPalette.activeSelectionFill)
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .fixedSize(horizontal: true, vertical: false)
                    }
                    .buttonStyle(.plain)
                }
            }

            Text(finding.localizedTitle(in: localizer.language))
                .font(ColdTungstenTypography.panelHeaderTitle)
                .foregroundStyle(ColdTungstenPalette.steelWhite)
                .fixedSize(horizontal: false, vertical: true)

            Text(finding.localizedDetail(in: localizer.language))
                .font(ColdTungstenTypography.secondaryCaption)
                .foregroundStyle(ColdTungstenPalette.coolPewter)
                .fixedSize(horizontal: false, vertical: true)

            if let evidence = finding.evidencePreview, !evidence.isEmpty {
                Text(evidence)
                    .font(ColdTungstenTypography.disassemblyMono(size: 10.5))
                    .foregroundStyle(ColdTungstenPalette.stringLiteralTint)
                    .padding(7)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(ColdTungstenPalette.chassisBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 3.5))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .background(ColdTungstenPalette.gunmetalSlate)
        .overlay(
            RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel)
                .strokeBorder(ColdTungstenPalette.tungstenSeam, lineWidth: ColdTungstenMetrics.borderHairline)
        )
        .clipShape(RoundedRectangle(cornerRadius: ColdTungstenMetrics.cornerRadiusPanel))
    }
}
