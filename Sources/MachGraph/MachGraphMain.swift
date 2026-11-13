import AppKit
import Foundation
import MachGraphModels
import MachHeadlessCLI
import MachStudioViews
import MachWorkbenchShell
import SwiftUI

// MARK: - Unified MachGraph Native macOS Desktop IDE, Retina Exporter & Headless CLI/MCP Entry Point (`v1.1.0`)

@MainActor
@main
struct MachGraphApplication {

    static func main() async {
        let rawArgs = Array(CommandLine.arguments.dropFirst())
        let userArgs = stripAppleSystemLaunchArguments(rawArgs)

        // Bootstrap live language resolution (`--lang zh|en` -> `MACHGRAPH_LANG` -> `UserDefaults` -> `Locale`)
        let activeLanguage = MachLocalizer.shared.bootstrapFromEnvironment(arguments: userArgs)

        // 1. Deterministic 2x Retina Screenshot & Standalone Bilingual HTML Report Exporter
        if let exportIdx = userArgs.firstIndex(of: "--export-screenshots") {
            let outputPath: String
            if userArgs.indices.contains(exportIdx + 1), !userArgs[exportIdx + 1].hasPrefix("--") {
                outputPath = userArgs[exportIdx + 1]
            } else {
                outputPath = FileManager.default.currentDirectoryPath + "/docs"
            }

            let exportLanguage = MachLanguage.extractCLIArgumentLanguage(from: userArgs) ?? activeLanguage

            do {
                let summary = try MachRetinaScreenshotExporter.exportAllAssets(
                    to: URL(fileURLWithPath: outputPath, isDirectory: true),
                    language: exportLanguage
                )
                for shot in summary.screenshotPaths {
                    print("Exported 2x Retina PNG (\(exportLanguage.rawValue)): \(shot)")
                }
                print("Exported Cold Tungsten HTML Report: \(summary.htmlReportPath)")
                Foundation.exit(0)
            } catch {
                FileHandle.standardError.write(Data("Screenshot export failed: \(error.localizedDescription)\n".utf8))
                Foundation.exit(1)
            }
        }

        // 2. Headless Reverse-Engineering CLI & Stdio MCP JSON-RPC Server (single-source dispatch via MachCLIRunner)
        let errPrefix = activeLanguage.select("MachGraph error:", "MachGraph 错误:")
        let argsWithoutLang: [String]
        do {
            _ = try MachCLIRunner.validateAndResolveLanguage(from: userArgs)
            argsWithoutLang = MachCLIRunner.stripLanguageFlags(userArgs)
        } catch let mgErr as MachGraphError {
            FileHandle.standardError.write(Data("\(errPrefix) \(mgErr.localizedMessage(in: activeLanguage))\n".utf8))
            Foundation.exit(2)
        } catch {
            FileHandle.standardError.write(Data("\(errPrefix) \(error.localizedDescription)\n".utf8))
            Foundation.exit(2)
        }

        if MachCLIRunner.isHeadlessInvocation(arguments: userArgs) {
            do {
                let runner = MachCLIRunner()
                let output = try await runner.execute(arguments: userArgs)
                if !output.isEmpty {
                    print(output)
                }
                Foundation.exit(0)
            } catch let mgErr as MachGraphError {
                let resolvedLang = (try? MachCLIRunner.validateAndResolveLanguage(from: userArgs)) ?? activeLanguage
                let prefix = resolvedLang.select("MachGraph error:", "MachGraph 错误:")
                FileHandle.standardError.write(Data("\(prefix) \(mgErr.localizedMessage(in: resolvedLang))\n".utf8))
                if case .invalidCLIArguments = mgErr {
                    Foundation.exit(2)
                }
                Foundation.exit(1)
            } catch {
                let resolvedLang = (try? MachCLIRunner.validateAndResolveLanguage(from: userArgs)) ?? activeLanguage
                let prefix = resolvedLang.select("MachGraph error:", "MachGraph 错误:")
                FileHandle.standardError.write(Data("\(prefix) \(error.localizedDescription)\n".utf8))
                Foundation.exit(1)
            }
        }

        // Reject unrecognized top-level CLI flags instead of silently opening an empty window
        for arg in argsWithoutLang where arg.hasPrefix("-") && arg != "--binary" && arg != "--demo" {
            let msg = activeLanguage.select(
                "Unknown option '\(arg)'. Run 'machgraph --help' for usage.\n",
                "不支持的选项 '\(arg)'。请运行 'machgraph --help' 查看用法。\n"
            )
            FileHandle.standardError.write(Data(msg.utf8))
            Foundation.exit(2)
        }

        // 3. Interactive macOS Cold Tungsten Desktop Workbench (starts empty unless <file>, --binary, or --demo is passed)
        let loadDemo = argsWithoutLang.contains("--demo")
        let initialBinaryURL: URL?
        do {
            initialBinaryURL = try resolveInitialBinaryURL(from: argsWithoutLang, language: activeLanguage)
        } catch let mgErr as MachGraphError {
            FileHandle.standardError.write(Data("MachGraph error: \(mgErr.localizedMessage(in: activeLanguage))\n".utf8))
            Foundation.exit(1)
        } catch {
            FileHandle.standardError.write(Data("MachGraph error: \(error.localizedDescription)\n".utf8))
            Foundation.exit(1)
        }
        launchDesktopWorkbench(initialBinaryURL: initialBinaryURL, loadDemo: loadDemo)
    }

    private static func stripAppleSystemLaunchArguments(_ args: [String]) -> [String] {
        var cleaned: [String] = []
        var index = 0
        while index < args.count {
            let token = args[index]
            if token == "-NSDocumentRevisionsDebugMode" || token == "-ApplePersistenceIgnoreState" {
                index += 2
                continue
            }
            if token == "-AppleLanguages" {
                index += 2
                continue
            }
            if token.hasPrefix("-psn_") {
                index += 1
                continue
            }
            cleaned.append(token)
            index += 1
        }
        return cleaned
    }

    private static func resolveInitialBinaryURL(from args: [String], language: MachLanguage) throws -> URL? {
        if let binFlagIndex = args.firstIndex(of: "--binary") {
            guard args.indices.contains(binFlagIndex + 1) else {
                throw MachGraphError.invalidCLIArguments(
                    language.select("Option '--binary' requires a file path.", "选项 '--binary' 需要提供文件路径。")
                )
            }
            let rawPath = args[binFlagIndex + 1]
            let candidate = URL(fileURLWithPath: rawPath)
            guard FileManager.default.fileExists(atPath: candidate.path) else {
                throw MachGraphError.fileNotFound(rawPath)
            }
            return candidate
        }
        let nonFlags = args.filter { !$0.hasPrefix("-") }
        if let first = nonFlags.first {
            let candidate = URL(fileURLWithPath: first)
            guard FileManager.default.fileExists(atPath: candidate.path) else {
                throw MachGraphError.fileNotFound(first)
            }
            return candidate
        }
        return nil
    }

    private static func launchDesktopWorkbench(initialBinaryURL: URL?, loadDemo: Bool) {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.appearance = NSAppearance(named: .darkAqua)

        let coordinator = MachDesktopAppDelegate(initialBinaryURL: initialBinaryURL, loadDemo: loadDemo)
        app.delegate = coordinator
        app.run()
    }
}

// MARK: - AppKit Window & Menu Bar Coordinator (`1360 × 840 pt` Cold Tungsten Chassis)

@MainActor
final class MachDesktopAppDelegate: NSObject, NSApplicationDelegate {
    private let initialBinaryURL: URL?
    private let loadDemo: Bool
    private var viewModel: MachStudioViewModel?
    private var mainWindow: NSWindow?
    private var languageObserver: NSObjectProtocol?

    init(initialBinaryURL: URL?, loadDemo: Bool = false) {
        self.initialBinaryURL = initialBinaryURL
        self.loadDemo = loadDemo
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let vm = MachStudioViewModel(initialBinaryURL: initialBinaryURL, loadDemo: loadDemo, emitStartupToast: true)
        self.viewModel = vm

        installMainMenuBar()

        let contentRect = NSRect(x: 0, y: 0, width: 1360, height: 840)
        let window = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = localizedWindowTitle()
        window.minSize = NSSize(width: 1180, height: 720)
        window.appearance = NSAppearance(named: .darkAqua)
        window.backgroundColor = NSColor(red: 15.0 / 255.0, green: 18.0 / 255.0, blue: 22.0 / 255.0, alpha: 1.0)
        window.titlebarAppearsTransparent = false

        let rootView = MachWorkbenchRootView(viewModel: vm)
            .frame(minWidth: 1180, minHeight: 720)
            .environment(\.colorScheme, .dark)

        window.contentView = NSHostingView(rootView: rootView)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        self.mainWindow = window

        languageObserver = NotificationCenter.default.addObserver(
            forName: MachLocalizer.languageDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.mainWindow?.title = self?.localizedWindowTitle() ?? "MachGraph"
                self?.installMainMenuBar()
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func localizedWindowTitle() -> String {
        MachLocalizer.shared.L(
            "MachGraph - macOS ARM64 & Mach-O Binary Inspector",
            "MachGraph - macOS ARM64 与 Mach-O 二进制检视工作台"
        )
    }

    // MARK: Native macOS Menu Bar & Keyboard Shortcuts

    private func installMainMenuBar() {
        let loc = MachLocalizer.shared
        let mainMenu = NSMenu()

        // Application Menu
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu

        let prefsItem = NSMenuItem(
            title: loc.L("Preferences...", "偏好设置..."),
            action: #selector(openPreferencesAction),
            keyEquivalent: ","
        )
        prefsItem.target = self
        appMenu.addItem(prefsItem)

        let shortcutsItem = NSMenuItem(
            title: loc.L("Keyboard Shortcuts", "键盘快捷键"),
            action: #selector(openShortcutsAction),
            keyEquivalent: "/"
        )
        shortcutsItem.target = self
        appMenu.addItem(shortcutsItem)

        let langMenuTitle = loc.L("切换语言 / Toggle Language (中文 | EN)", "切换语言 / Toggle Language (中文 | EN)")
        let appLangItem = NSMenuItem(
            title: langMenuTitle,
            action: #selector(toggleLanguageAction),
            keyEquivalent: "l"
        )
        appLangItem.keyEquivalentModifierMask = [.command, .shift]
        appLangItem.target = self
        appMenu.addItem(appLangItem)

        appMenu.addItem(.separator())
        appMenu.addItem(
            NSMenuItem(
                title: loc.L("Quit MachGraph", "退出 MachGraph"),
                action: #selector(NSApplication.terminate(_:)),
                keyEquivalent: "q"
            )
        )

        // File Menu
        let fileMenuItem = NSMenuItem()
        mainMenu.addItem(fileMenuItem)
        let fileMenu = NSMenu(title: loc.L("File", "文件"))
        fileMenuItem.submenu = fileMenu

        let openItem = NSMenuItem(
            title: loc.L("Open Binary...", "打开二进制文件..."),
            action: #selector(openBinaryAction),
            keyEquivalent: "o"
        )
        openItem.target = self
        fileMenu.addItem(openItem)

        let snapshotItem = NSMenuItem(
            title: loc.L("Save SQLite WAL Checkpoint", "保存 SQLite WAL 快照"),
            action: #selector(captureSnapshotAction),
            keyEquivalent: "s"
        )
        snapshotItem.target = self
        fileMenu.addItem(snapshotItem)

        // Edit & Annotations Menu
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: loc.L("Edit", "编辑"))
        editMenuItem.submenu = editMenu

        let undoItem = NSMenuItem(
            title: loc.L("Undo Analyst Mutation", "撤销逆向修改"),
            action: #selector(undoMutationAction),
            keyEquivalent: "z"
        )
        undoItem.target = self
        editMenu.addItem(undoItem)

        let redoItem = NSMenuItem(
            title: loc.L("Redo Analyst Mutation", "重做逆向修改"),
            action: #selector(redoMutationAction),
            keyEquivalent: "Z"
        )
        redoItem.target = self
        editMenu.addItem(redoItem)

        editMenu.addItem(.separator())
        editMenu.addItem(NSMenuItem(title: loc.L("Copy", "拷贝"), action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
        editMenu.addItem(NSMenuItem(title: loc.L("Paste", "粘贴"), action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
        editMenu.addItem(NSMenuItem(title: loc.L("Select All", "全选"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))

        // Navigate & Analysis Menu
        let navMenuItem = NSMenuItem()
        mainMenu.addItem(navMenuItem)
        let navMenu = NSMenu(title: loc.L("Navigate", "导航"))
        navMenuItem.submenu = navMenu

        let paletteItem = NSMenuItem(
            title: loc.L("Command Palette...", "命令面板..."),
            action: #selector(openCommandPaletteAction),
            keyEquivalent: "k"
        )
        paletteItem.target = self
        navMenu.addItem(paletteItem)

        let gotoItem = NSMenuItem(
            title: loc.L("Go to Address / Symbol...", "跳转至地址 / 符号..."),
            action: #selector(openGoToModalAction),
            keyEquivalent: "g"
        )
        gotoItem.target = self
        navMenu.addItem(gotoItem)

        let xrefsItem = NSMenuItem(
            title: loc.L("Cross-References at Cursor", "查看光标处交叉引用"),
            action: #selector(openXrefsAction),
            keyEquivalent: "x"
        )
        xrefsItem.keyEquivalentModifierMask = [.command, .shift]
        xrefsItem.target = self
        navMenu.addItem(xrefsItem)

        let splitItem = NSMenuItem(
            title: loc.L("Toggle Synchronized Decompiler Split", "切换反编译同步分屏"),
            action: #selector(toggleSplitAction),
            keyEquivalent: "d"
        )
        splitItem.keyEquivalentModifierMask = [.command, .shift]
        splitItem.target = self
        navMenu.addItem(splitItem)

        let auditItem = NSMenuItem(
            title: loc.L("Run JavaScriptCore Security Audit", "运行 JavaScriptCore 安全审计"),
            action: #selector(runAuditAction),
            keyEquivalent: "a"
        )
        auditItem.keyEquivalentModifierMask = [.command, .shift]
        auditItem.target = self
        navMenu.addItem(auditItem)

        NSApplication.shared.mainMenu = mainMenu
    }

    @objc private func openPreferencesAction() { viewModel?.isPreferencesPresented = true }
    @objc private func openShortcutsAction() { viewModel?.isShortcutsSheetPresented = true }
    @objc private func openBinaryAction() { viewModel?.isFileImporterPresented = true }
    @objc private func captureSnapshotAction() { viewModel?.captureSnapshotCheckpoint() }
    @objc private func undoMutationAction() { viewModel?.performUndo() }
    @objc private func redoMutationAction() { viewModel?.performRedo() }
    @objc private func openCommandPaletteAction() { viewModel?.paletteController.openPalette() }
    @objc private func openGoToModalAction() { viewModel?.isGoToModalPresented = true }
    @objc private func openXrefsAction() { viewModel?.presentXrefsPopoverAtCursor() }
    @objc private func toggleSplitAction() { viewModel?.cursorBus.toggleSplitView(defaultSecondary: .pseudoC) }
    @objc private func toggleLanguageAction() {
        MachLocalizer.shared.toggleLanguage()
        let next = MachLocalizer.shared.language
        viewModel?.toastController.enqueue(
            kind: .info,
            title: next == .zhHans ? "已切换为简体中文界面" : "Switched to English UI",
            detail: next == .zhHans ? "快捷键 ⇧⌘L 可随时在中英文之间实时切换" : "Press ⇧⌘L anytime to toggle 中文 / EN live"
        )
    }
    @objc private func runAuditAction() {
        viewModel?.runSecurityAuditSuite(emitToast: true)
        viewModel?.cursorBus.disableSplitView()
        viewModel?.cursorBus.activePane = .pluginFindings
    }
}
