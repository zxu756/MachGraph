import AppKit
import Foundation
import MachGraphModels
import MachHeadlessCLI
import MachStudioViews
import MachWorkbenchShell
import SwiftUI

// MARK: - Unified MachGraph Native macOS Desktop IDE, Retina Exporter & Headless CLI/MCP Entry Point

@MainActor
@main
struct MachGraphApplication {

    private static let headlessCommands: Set<String> = [
        "help", "--help", "-h",
        "version", "--version",
        "info", "segments", "symbols", "strings",
        "disasm", "cfg", "decompile", "xrefs",
        "entropy", "codesign", "patch", "resign",
        "audit", "report-html", "mcp"
    ]

    static func main() async {
        let rawArgs = Array(CommandLine.arguments.dropFirst())
        let userArgs = stripAppleSystemLaunchArguments(rawArgs)

        // 1. Deterministic 2x Retina Screenshot & Standalone HTML Report Exporter
        if let exportIdx = userArgs.firstIndex(of: "--export-screenshots") {
            let outputPath: String
            if userArgs.indices.contains(exportIdx + 1) {
                outputPath = userArgs[exportIdx + 1]
            } else {
                outputPath = FileManager.default.currentDirectoryPath + "/docs"
            }

            do {
                let summary = try MachRetinaScreenshotExporter.exportAllAssets(
                    to: URL(fileURLWithPath: outputPath, isDirectory: true)
                )
                for shot in summary.screenshotPaths {
                    print("Exported 2x Retina PNG: \(shot)")
                }
                print("Exported Cold Tungsten HTML Report: \(summary.htmlReportPath)")
                Foundation.exit(0)
            } catch {
                FileHandle.standardError.write(Data("Screenshot export failed: \(error.localizedDescription)\n".utf8))
                Foundation.exit(1)
            }
        }

        // 2. Headless Reverse-Engineering CLI & Stdio MCP JSON-RPC Server
        if let first = userArgs.first, headlessCommands.contains(first) {
            do {
                let runner = MachCLIRunner()
                let output = try await runner.execute(arguments: userArgs)
                if !output.isEmpty {
                    print(output)
                }
                Foundation.exit(0)
            } catch {
                FileHandle.standardError.write(Data("MachGraph CLI error: \(error.localizedDescription)\n".utf8))
                Foundation.exit(1)
            }
        }

        // 3. Interactive macOS Cold Tungsten Desktop Workbench
        let initialBinaryURL = resolveInitialBinaryURL(from: userArgs)
        launchDesktopWorkbench(initialBinaryURL: initialBinaryURL)
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
            if token.hasPrefix("-psn_") {
                index += 1
                continue
            }
            cleaned.append(token)
            index += 1
        }
        return cleaned
    }

    private static func resolveInitialBinaryURL(from args: [String]) -> URL? {
        if let binFlagIndex = args.firstIndex(of: "--binary"),
           args.indices.contains(binFlagIndex + 1) {
            let candidate = URL(fileURLWithPath: args[binFlagIndex + 1])
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        if let first = args.first, !first.hasPrefix("-") {
            let candidate = URL(fileURLWithPath: first)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return nil
    }

    private static func launchDesktopWorkbench(initialBinaryURL: URL?) {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.appearance = NSAppearance(named: .darkAqua)

        let coordinator = MachDesktopAppDelegate(initialBinaryURL: initialBinaryURL)
        app.delegate = coordinator
        app.run()
    }
}

// MARK: - AppKit Window & Menu Bar Coordinator (`1360 × 840 pt` Cold Tungsten Chassis)

@MainActor
final class MachDesktopAppDelegate: NSObject, NSApplicationDelegate {
    private let initialBinaryURL: URL?
    private var viewModel: MachStudioViewModel?
    private var mainWindow: NSWindow?

    init(initialBinaryURL: URL?) {
        self.initialBinaryURL = initialBinaryURL
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let vm = MachStudioViewModel(initialBinaryURL: initialBinaryURL, emitStartupToast: true)
        self.viewModel = vm

        installMainMenuBar()

        let contentRect = NSRect(x: 0, y: 0, width: 1360, height: 840)
        let window = NSWindow(
            contentRect: contentRect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "MachGraph — Native macOS ARM64 / Mach-O / ELF / PE / WASM Reverse-Engineering Workbench"
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
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    // MARK: Native macOS Menu Bar & Keyboard Shortcuts

    private func installMainMenuBar() {
        let mainMenu = NSMenu()

        // Application Menu
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu

        let prefsItem = NSMenuItem(title: "Preferences...", action: #selector(openPreferencesAction), keyEquivalent: ",")
        prefsItem.target = self
        appMenu.addItem(prefsItem)

        let shortcutsItem = NSMenuItem(title: "Keyboard Shortcuts", action: #selector(openShortcutsAction), keyEquivalent: "/")
        shortcutsItem.target = self
        appMenu.addItem(shortcutsItem)

        appMenu.addItem(.separator())
        appMenu.addItem(NSMenuItem(title: "Quit MachGraph", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        // File Menu
        let fileMenuItem = NSMenuItem()
        mainMenu.addItem(fileMenuItem)
        let fileMenu = NSMenu(title: "File")
        fileMenuItem.submenu = fileMenu

        let openItem = NSMenuItem(title: "Open Binary...", action: #selector(openBinaryAction), keyEquivalent: "o")
        openItem.target = self
        fileMenu.addItem(openItem)

        let snapshotItem = NSMenuItem(title: "Save SQLite WAL Checkpoint", action: #selector(captureSnapshotAction), keyEquivalent: "s")
        snapshotItem.target = self
        fileMenu.addItem(snapshotItem)

        // Edit & Annotations Menu
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "Edit")
        editMenuItem.submenu = editMenu

        let undoItem = NSMenuItem(title: "Undo Analyst Mutation", action: #selector(undoMutationAction), keyEquivalent: "z")
        undoItem.target = self
        editMenu.addItem(undoItem)

        let redoItem = NSMenuItem(title: "Redo Analyst Mutation", action: #selector(redoMutationAction), keyEquivalent: "Z")
        redoItem.target = self
        editMenu.addItem(redoItem)

        editMenu.addItem(.separator())
        editMenu.addItem(NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
        editMenu.addItem(NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
        editMenu.addItem(NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))

        // Navigate & Analysis Menu
        let navMenuItem = NSMenuItem()
        mainMenu.addItem(navMenuItem)
        let navMenu = NSMenu(title: "Navigate")
        navMenuItem.submenu = navMenu

        let paletteItem = NSMenuItem(title: "Command Palette...", action: #selector(openCommandPaletteAction), keyEquivalent: "k")
        paletteItem.target = self
        navMenu.addItem(paletteItem)

        let gotoItem = NSMenuItem(title: "Go to Address / Symbol...", action: #selector(openGoToModalAction), keyEquivalent: "g")
        gotoItem.target = self
        navMenu.addItem(gotoItem)

        let xrefsItem = NSMenuItem(title: "Cross-References at Cursor", action: #selector(openXrefsAction), keyEquivalent: "x")
        xrefsItem.keyEquivalentModifierMask = [.command, .shift]
        xrefsItem.target = self
        navMenu.addItem(xrefsItem)

        let splitItem = NSMenuItem(title: "Toggle Synchronized Decompiler Split", action: #selector(toggleSplitAction), keyEquivalent: "d")
        splitItem.keyEquivalentModifierMask = [.command, .shift]
        splitItem.target = self
        navMenu.addItem(splitItem)

        let auditItem = NSMenuItem(title: "Run JavaScriptCore Security Audit", action: #selector(runAuditAction), keyEquivalent: "a")
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
    @objc private func runAuditAction() {
        viewModel?.runSecurityAuditSuite(emitToast: true)
        viewModel?.cursorBus.disableSplitView()
        viewModel?.cursorBus.activePane = .pluginFindings
    }
}
