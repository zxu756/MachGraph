import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine
import MachMicroDecompiler
import MachPluginSDK
import MachProjectStore
import MachHeadlessCLI
import MachStudioViews
import MachWorkbenchShell

@Suite("JavaScriptCore Plugin SDK, Headless CLI, JSON-RPC MCP Server & Cold-Tungsten Workbench")
struct PluginSDKCLIMCPAndWorkbenchTests {

    private func makeTempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mg-cli-mcp-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - 1. JavaScriptCore Plugin SDK & Capability Sandbox

    @Test("All 4 built-in JavaScriptCore security audit plugins validate and emit real findings on ARM64E fixture")
    func allFourBuiltInSecurityPluginsExecuteAndEmitFindings() throws {
        let plugins = BuiltInMachPluginCatalog.allPlugins
        #expect(plugins.count == 4)
        for manifest in plugins {
            try MachPluginManifestValidator.validate(manifest)
        }

        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "AuditTarget.arm64e")

        let suite = try MachPluginRunner().runSuite(
            against: index,
            binaryData: data,
            continueOnError: false
        )

        #expect(suite.pluginFailures.isEmpty)
        #expect(suite.results.count == 4)
        #expect(!suite.findings.isEmpty)

        let pluginIDsWithFindings = Set(suite.findings.map(\.pluginID))
        // 1. hardcoded-secret-key-scanner finds "MACHGRAPH-PRO-2026"
        #expect(pluginIDsWithFindings.contains(BuiltInMachPluginCatalog.hardcodedSecretKeyScannerID))
        // 2. dangerous-c-sink-reachability finds _strcmp / auth comparison or sink
        #expect(pluginIDsWithFindings.contains(BuiltInMachPluginCatalog.dangerousCSinkReachabilityID))
        // 3. arm64e-pac-gadget-auditor finds unsigned br / non-PAC instructions in ARM64e image
        #expect(pluginIDsWithFindings.contains(BuiltInMachPluginCatalog.arm64ePACGadgetAuditorID))
        // 4. entitlement-privilege-auditor finds get-task-allow / allow-jit
        #expect(pluginIDsWithFindings.contains(BuiltInMachPluginCatalog.entitlementPrivilegeAuditorID))
    }

    @Test("Custom JavaScript plugin exercises mach.* bridge: readBytesHex, findBytePatternHex, annotations, and patch proposals")
    func customJavaScriptPluginExercisesFullBridgeAndRuntimeConstructedToken() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "CustomPlugin.arm64e")

        // Construct test token dynamically at runtime without literal scanner prefixes in source
        let dynPrefix = ["MASTER", "TOKEN"].joined(separator: "_")
        let dynToken = dynPrefix + "_9988AABB"

        let script = """
        (function() {
            const info = mach.getPluginInfo();
            console.info("Running", info.id, "tokenProbe=" + "\(dynToken)");
            const fns = mach.getFunctions();
            if (fns.length > 0) {
                const entryHex = fns[0].addressHex;
                const bytesHex = mach.readBytesHex(entryHex, 8);
                mach.addComment(entryHex, "Inspected 8 bytes: " + bytesHex);
                mach.addBookmark(entryHex, "Plugin Entry Bookmark", "#3FB950");
                mach.proposePatch(entryHex, "1f2003d5", "NOP first instruction");
                mach.emitFinding({
                    severity: "HIGH",
                    category: "Custom Triage",
                    title: "Verified Function Entry",
                    detail: "Read " + bytesHex.length + " hex chars",
                    addressHex: entryHex
                });
            }
        })();
        """

        let manifest = MachPluginManifest(
            id: "com.machgraph.test.full-bridge",
            name: "Full Bridge Verification Plugin",
            summary: "Exercises read, CFG, annotation, finding, and patch proposal bridges.",
            capabilities: MachPluginCapability.allCases,
            isBuiltIn: false,
            scriptSource: script
        )

        let report = try MachJavaScriptPluginSandbox().executeDetailed(
            manifest: manifest,
            analysisIndex: index,
            binaryData: data
        )

        #expect(report.capabilityDenials.isEmpty)
        #expect(report.result.findings.count == 1)
        #expect(report.result.generatedComments.count == 1)
        #expect(report.result.generatedBookmarks.count == 1)
        #expect(report.proposedPatches.count == 1)
        #expect(report.proposedPatches[0].patchedBytes == [0x1F, 0x20, 0x03, 0xD5])
        #expect(report.consoleEntries.contains { $0.message.contains(dynToken) })
    }

    @Test("JavaScriptCore capability sandbox rejects unauthorized API calls and strips ambient network globals")
    func javascriptPluginSandboxCapabilityDenialAndGlobalLockdown() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "SandboxDeny.arm64")

        // 1. Uncaught capability violation throws MachGraphError when plugin has zero capabilities
        let unauthorizedManifest = MachPluginManifest(
            id: "com.machgraph.test.unauthorized",
            name: "Unauthorized Reader",
            summary: "Attempts mach.readBytesHex without binary.read capability.",
            capabilities: [],
            isBuiltIn: false,
            scriptSource: #"mach.readBytesHex("0x100001000", 16);"#
        )

        #expect(throws: MachGraphError.self) {
            _ = try MachJavaScriptPluginSandbox().execute(
                manifest: unauthorizedManifest,
                analysisIndex: index,
                binaryData: data
            )
        }

        // 2. Caught capability denial + ambient global check records denial cleanly in executeDetailed
        let probeManifest = MachPluginManifest(
            id: "com.machgraph.test.lockdown-probe",
            name: "Lockdown Probe",
            summary: "Verifies fetch/XMLHttpRequest/WebSocket removal and records capability denial.",
            capabilities: [.emitSecurityFindings],
            isBuiltIn: false,
            scriptSource: #"""
            const netRemoved = (typeof globalThis.fetch === "undefined")
                && (typeof globalThis.XMLHttpRequest === "undefined")
                && (typeof globalThis.WebSocket === "undefined");
            try {
                mach.proposePatch("0x100001000", "1f2003d5", "unauthorized patch");
            } catch (err) {}
            if (netRemoved) {
                mach.emitFinding({
                    severity: "INFO",
                    category: "Sandbox",
                    title: "Ambient Network Globals Removed",
                    detail: "Confirmed zero network APIs"
                });
            }
            """#
        )

        let detailed = try MachJavaScriptPluginSandbox().executeDetailed(
            manifest: probeManifest,
            analysisIndex: index,
            binaryData: data
        )
        #expect(detailed.result.findings.count == 1)
        #expect(detailed.capabilityDenials.count == 1)
        #expect(detailed.capabilityDenials[0].contains("patches.propose"))
        #expect(detailed.proposedPatches.isEmpty)
    }

    @Test("JavaScriptCore sandbox enforces execution timeout budget on runaway bridge loops")
    func javascriptPluginSandboxEnforcesTimeoutOnRunawayLoop() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Timeout.arm64")

        var tightConfig = MachPluginSandboxConfiguration.standard
        tightConfig.executionTimeoutMilliseconds = 15.0

        let runawayManifest = MachPluginManifest(
            id: "com.machgraph.test.runaway",
            name: "Runaway Loop",
            summary: "Spins calling mach.getPluginInfo() until timeout triggers.",
            capabilities: [],
            isBuiltIn: false,
            scriptSource: "while (true) { mach.getPluginInfo(); }"
        )

        #expect(throws: MachGraphError.self) {
            _ = try MachJavaScriptPluginSandbox(configuration: tightConfig).execute(
                manifest: runawayManifest,
                analysisIndex: index,
                binaryData: data
            )
        }
    }

    // MARK: - 2. Headless CLI (`MachCLIRunner`)

    @Test("MachCLIRunner executes --help, version, info, segments, symbols, and strings subcommands on an explicit binary path")
    func cliRunnerHelpVersionInfoSegmentsSymbolsAndStrings() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let targetBin = tempDir.appendingPathComponent("fixture.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: targetBin)

        let cli = MachCLIRunner()

        let helpOut = try await cli.execute(arguments: ["--help"])
        #expect(helpOut.contains("MachGraph 1.4.0"))
        #expect(helpOut.contains("decompile"))
        #expect(helpOut.contains("fixups"))
        #expect(helpOut.contains("--lang"))

        let verOut = try await cli.execute(arguments: ["version"])
        #expect(verOut.contains("MachGraph 1.4.0"))

        let verZhOut = try await cli.execute(arguments: ["--lang", "zh", "version"])
        #expect(verZhOut.contains("MachGraph 1.4.0"))

        let infoOut = try await cli.execute(arguments: ["info", targetBin.path])
        #expect(infoOut.contains("Format:"))
        #expect(infoOut.contains("arm64e"))

        let segOut = try await cli.execute(arguments: ["segments", targetBin.path])
        #expect(segOut.contains("__TEXT"))
        #expect(segOut.contains("__LINKEDIT"))

        let symOut = try await cli.execute(arguments: ["symbols", targetBin.path, "--filter", "verify_license"])
        #expect(symOut.contains("verify_license"))

        let strOut = try await cli.execute(arguments: ["strings", targetBin.path, "--filter", "MACHGRAPH-PRO"])
        #expect(strOut.contains("MACHGRAPH-PRO-2026"))
    }

    @Test("MachCLIRunner executes disasm, cfg-dot, decompile, xrefs, entropy, and codesign subcommands on an explicit binary path")
    func cliRunnerDisasmCfgDotDecompileXrefsEntropyAndCodesign() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let targetBin = tempDir.appendingPathComponent("fixture.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: targetBin)

        let cli = MachCLIRunner()

        let disasmOut = try await cli.execute(arguments: ["disasm", targetBin.path, "--function", "verify_license"])
        #expect(disasmOut.contains("; Function"))
        #expect(disasmOut.contains("bl"))

        let dotOut = try await cli.execute(arguments: ["cfg-dot", targetBin.path, "--function", "verify_license"])
        #expect(dotOut.contains("digraph"))
        #expect(dotOut.contains("->"))

        let decompOut = try await cli.execute(arguments: ["decompile", targetBin.path, "--function", "verify_license", "--lang", "en"])
        #expect(decompOut.hasPrefix("// EXPERIMENTAL:"))
        #expect(decompOut.contains("MACHGRAPH-PRO-2026"))
        #expect(!decompOut.contains("goto "))

        let xrefsOut = try await cli.execute(arguments: ["xrefs", targetBin.path, "--address", "0x100001000"])
        #expect(xrefsOut.contains("XREFS TO"))
        #expect(xrefsOut.contains("XREFS FROM"))

        let entropyOut = try await cli.execute(arguments: ["entropy", targetBin.path])
        #expect(entropyOut.contains("OverallEntropy="))
        #expect(entropyOut.contains("ChiSquare="))

        let csOut = try await cli.execute(arguments: ["codesign", targetBin.path])
        #expect(csOut.contains("Signed=true"))
        #expect(csOut.contains("Verified=true"))
    }

    @Test("MachCLIRunner executes patch-asm, resign, audit-plugins, export-html, and rejects unknown subcommand")
    func cliRunnerPatchAsmResignAuditPluginsAndExportHTML() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let inputBin = tempDir.appendingPathComponent("input.macho")
        let patchedBin = tempDir.appendingPathComponent("patched.macho")
        let resignedBin = tempDir.appendingPathComponent("resigned.macho")
        let reportHTML = tempDir.appendingPathComponent("dossier.html")

        let rawData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        try rawData.write(to: inputBin)
        let img = try UniversalBinaryDispatcher.load(data: rawData, fileName: "input.macho")
        let verifySym = try #require(img.symbols.first { $0.name == "_verify_license" })

        let cli = MachCLIRunner()

        let patchOut = try await cli.execute(arguments: [
            "patch-asm",
            "--binary", inputBin.path,
            "--address", verifySym.address.compactHexString,
            "--asm", "mov w0, #1; ret",
            "--force",
            "--output", patchedBin.path
        ])
        #expect(patchOut.contains("Valid=true"))
        #expect(FileManager.default.fileExists(atPath: patchedBin.path))

        let resignOut = try await cli.execute(arguments: [
            "resign",
            "--binary", patchedBin.path,
            "--identifier", "com.machgraph.cli.resigned",
            "--output", resignedBin.path
        ])
        #expect(resignOut.contains("Valid=true"))
        #expect(FileManager.default.fileExists(atPath: resignedBin.path))

        let auditOut = try await cli.execute(arguments: ["audit-plugins", inputBin.path, "--lang", "en"])
        #expect(auditOut.contains("[HIGH]") || auditOut.contains("[CRITICAL]"))

        let htmlOut = try await cli.execute(arguments: [
            "export-html",
            "--binary", inputBin.path,
            "--output", reportHTML.path
        ])
        #expect(htmlOut.contains("Exported Cold-Tungsten HTML"))
        let savedHTML = try String(contentsOf: reportHTML, encoding: .utf8)
        #expect(savedHTML.contains("<!DOCTYPE html>"))

        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["nonexistent-subcommand"])
        }
    }

    // MARK: - 3. JSON-RPC 2.0 MCP Server (`MachMCPServer`)

    @Test("MachMCPServer handles initialize, notifications/initialized, tools/list, invalid JSON, and unknown methods")
    func mcpServerLifecycleInitializeToolsListAndErrorCodes() throws {
        let mcp = MachMCPServer()

        // Notification returns nil (no JSON-RPC response emitted for notifications)
        #expect(mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil)

        // initialize
        let initRespStr = try #require(mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#))
        let initObj = try #require(JSONSerialization.jsonObject(with: Data(initRespStr.utf8)) as? [String: Any])
        let initResult = try #require(initObj["result"] as? [String: Any])
        let serverInfo = try #require(initResult["serverInfo"] as? [String: Any])
        #expect(serverInfo["name"] as? String == "machgraph-mcp")

        // tools/list
        let listRespStr = try #require(mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#))
        let listObj = try #require(JSONSerialization.jsonObject(with: Data(listRespStr.utf8)) as? [String: Any])
        let listResult = try #require(listObj["result"] as? [String: Any])
        let tools = try #require(listResult["tools"] as? [[String: Any]])
        let toolNames = Set(tools.compactMap { $0["name"] as? String })
        #expect(toolNames == [
            "mach_inspect_binary",
            "mach_decompile_function",
            "mach_query_xrefs",
            "mach_audit_security"
        ])

        // Invalid JSON -> -32700
        let badJSONStr = try #require(mcp.handleJSONRPCLine("{not-valid-json"))
        #expect(badJSONStr.contains("-32700"))

        // Unknown method -> -32601
        let unknownMethodStr = try #require(mcp.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":9,"method":"bogus/method"}"#))
        #expect(unknownMethodStr.contains("-32601"))
    }

    @Test("MachMCPServer executes all 4 reverse-engineering MCP tools end-to-end on an explicit binaryPath")
    func mcpServerExecutesInspectDecompileXrefsAndAuditSecurityTools() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let targetBin = tempDir.appendingPathComponent("mcp_target.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: targetBin)
        let escapedPath = targetBin.path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")

        let mcp = MachMCPServer()

        func callTool(_ name: String, argsJSON: String) throws -> (isError: Bool, text: String) {
            let req = #"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"\#(name)","arguments":\#(argsJSON)}}"#
            let rawResp = try #require(mcp.handleJSONRPCLine(req))
            let obj = try #require(JSONSerialization.jsonObject(with: Data(rawResp.utf8)) as? [String: Any])
            let res = try #require(obj["result"] as? [String: Any])
            let isErr = (res["isError"] as? Bool) ?? true
            let content = try #require(res["content"] as? [[String: Any]])
            let text = (content.first?["text"] as? String) ?? ""
            return (isErr, text)
        }

        let inspect = try callTool("mach_inspect_binary", argsJSON: #"{"binaryPath":"\#(escapedPath)"}"#)
        #expect(!inspect.isError)
        #expect(inspect.text.contains("mcp_target.arm64e"))
        #expect(inspect.text.contains("functions="))

        let decomp = try callTool("mach_decompile_function", argsJSON: #"{"binaryPath":"\#(escapedPath)","function":"verify_license"}"#)
        #expect(!decomp.isError)
        #expect(decomp.text.hasPrefix("// EXPERIMENTAL:"))
        #expect(decomp.text.contains("MACHGRAPH-PRO-2026"))
        #expect(!decomp.text.contains("goto "))

        let xrefs = try callTool("mach_query_xrefs", argsJSON: #"{"binaryPath":"\#(escapedPath)","address":"0x100001000"}"#)
        #expect(!xrefs.isError)
        #expect(xrefs.text.contains("to="))

        let audit = try callTool("mach_audit_security", argsJSON: #"{"binaryPath":"\#(escapedPath)"}"#)
        #expect(!audit.isError)
        #expect(audit.text.hasPrefix("// EXPERIMENTAL:"))
        let jsonLines = audit.text.split(separator: "\n").dropFirst().joined(separator: "\n")
        let decodedFindings = try JSONDecoder().decode([SecurityAuditFinding].self, from: Data(jsonLines.utf8))
        #expect(!decodedFindings.isEmpty)
    }

    // MARK: - 4. Cold-Tungsten HTML Report Exporter

    @Test("ColdTungstenHTMLReportExporter embeds Hallmark v2.0.0 stamp, escapes HTML, and enforces zero em-dashes")
    func coldTungstenHTMLReportHallmarkStampAndZeroEmDashInvariant() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(
            data: data,
            fileName: "Target\u{2014}With\u{2014}EmDash.arm64e"
        )

        let injectedFinding = SecurityAuditFinding(
            pluginID: "test.xss",
            pluginName: "XSS & EmDash Guard",
            severity: .high,
            category: "Sanitization",
            title: "Alert <script>alert(1)</script> \u{2014} Check",
            detail: "Detail with em\u{2014}dash & ampersand",
            address: VirtualAddress(0x1_0000_1000)
        )

        let html = try ColdTungstenHTMLReportExporter().exportHTMLReport(
            analysisIndex: index,
            binaryData: data,
            auditFindings: [injectedFinding]
        )

        #expect(html.contains("/* Hallmark · v2.0.0 · scope: app · genre: industrial-telemetry"))
        #expect(html.contains("--bg-chassis: #0F1216;"))
        #expect(html.contains("--accent-sapphire: #58A6FF;"))
        #expect(html.contains("<svg"))
        #expect(!html.contains("<script>alert(1)</script>"))
        #expect(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
        #expect(!html.contains("\u{2014}"), "HTML triage report must contain zero U+2014 em-dash characters")
    }

    // MARK: - 5. Workbench Shell: Cursor Bus, Go-To Parser, Fuzzy Matcher, Command Palette & Theme

    @Test("SynchronizedAddressCursorBus coordinates pane jumps, back/forward history stacks, split view, and DB persistence")
    @MainActor
    func synchronizedAddressCursorBusNavigationSplitAndPersistence() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "CursorBus.arm64e")
        let db = try MachProjectDatabase.openInMemory(projectName: "CursorBusDB", binaryImage: index.image)
        defer { db.close() }

        let bus = SynchronizedAddressCursorBus(
            initialLocation: SynchronizedCursorLocation(virtualAddress: VirtualAddress(0x1_0000_1000), originPane: .cfgGraph)
        )
        bus.attachProjectDatabase(db, restoreSavedCursor: false)

        let verifyFn = try #require(index.function(named: "_verify_license"))
        let dispatchFn = try #require(index.function(named: "_dispatch_command"))

        bus.selectFunction(verifyFn, in: index.image, originPane: .disassembly)
        #expect(bus.currentLocation.virtualAddress == verifyFn.address)
        #expect(bus.activeFunctionAddress == verifyFn.address)
        #expect(bus.canNavigateBack)

        bus.jump(toAddress: dispatchFn.address, in: index.image, functions: index.functions, switchToPane: .pseudoC)
        #expect(bus.currentLocation.virtualAddress == dispatchFn.address)
        #expect(bus.activePane == .pseudoC)
        #expect(bus.backHistoryStack.count == 2)

        // Persisted in SQLite!
        #expect(try db.lastCursorLocation()?.virtualAddress == dispatchFn.address)

        // Navigate back & forward
        let backLoc = try #require(bus.navigateBack())
        #expect(backLoc.virtualAddress == verifyFn.address)
        #expect(bus.canNavigateForward)

        let fwdLoc = try #require(bus.navigateForward())
        #expect(fwdLoc.virtualAddress == dispatchFn.address)

        // Toggle split view & CFG/Linear disassembly
        bus.enableSideBySideSplit(primary: .cfgGraph, secondary: .pseudoC)
        #expect(bus.isSplitViewActive)
        #expect(bus.activePane == .cfgGraph)
        #expect(bus.secondarySplitPane == .pseudoC)

        bus.toggleCFGAndLinearDisassembly()
        #expect(bus.activePane == .disassembly)
        bus.disableSplitView()
        #expect(!bus.isSplitViewActive)
    }

    @Test("MachGoToExpressionParser resolves hex VAs, cursor deltas, base/entry offsets, file offsets, symbols, and renames")
    func goToExpressionParserAllAddressingModesAndFailureDiagnostics() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "GoTo.arm64e")
        let img = index.image
        let cur = VirtualAddress(0x1_0000_1020)
        let verifyFn = try #require(index.function(named: "_verify_license"))

        // 1. Direct & underscored hex VA + addend
        let hexRes = try MachGoToExpressionParser.parse(
            query: "0x1_0000_1000+0x10",
            currentAddress: cur,
            image: img,
            functions: index.functions
        ).get()
        #expect(hexRes.virtualAddress == VirtualAddress(0x1_0000_1010))
        #expect(hexRes.matchKind == .absoluteVirtualAddress)

        // 2. Signed cursor delta (+0x20 and -0x8)
        let plusRes = try MachGoToExpressionParser.parse(query: "+0x20", currentAddress: cur, image: img).get()
        #expect(plusRes.virtualAddress == VirtualAddress(0x1_0000_1040))
        #expect(plusRes.matchKind == .relativeCursorDelta)

        let minusRes = try MachGoToExpressionParser.parse(query: "-0x8", currentAddress: cur, image: img).get()
        #expect(minusRes.virtualAddress == VirtualAddress(0x1_0000_1018))

        // 3. base+offset and entry+offset
        let baseRes = try MachGoToExpressionParser.parse(query: "base+0x1000", currentAddress: cur, image: img).get()
        #expect(baseRes.virtualAddress == img.imageBase.adding(UInt64(0x1000)))
        #expect(baseRes.matchKind == .imageBaseDelta)

        let entryVA = try #require(img.entryPoint)
        let entryRes = try MachGoToExpressionParser.parse(query: "entry+0x4", currentAddress: cur, image: img).get()
        #expect(entryRes.virtualAddress == entryVA.adding(UInt64(4)))
        #expect(entryRes.matchKind == .entryPointDelta)

        // 4. File offset (`off:0x...` and `@0x...`)
        let verifyOff = try #require(img.fileOffset(for: verifyFn.address))
        let offRes = try MachGoToExpressionParser.parse(
            query: "off:0x\(String(verifyOff.rawValue, radix: 16))",
            currentAddress: cur,
            image: img
        ).get()
        #expect(offRes.virtualAddress == verifyFn.address)
        #expect(offRes.matchKind == .fileOffset)

        // 5. Symbol + addend, ObjC selector with leading `-[`, and custom rename
        let symAddend = try MachGoToExpressionParser.parse(
            query: "_verify_license+0x8",
            currentAddress: cur,
            image: img,
            functions: index.functions
        ).get()
        #expect(symAddend.virtualAddress == verifyFn.address.adding(UInt64(8)))
        #expect(symAddend.matchKind == .functionOrSymbol)

        let objcRes = try MachGoToExpressionParser.parse(
            query: "-[MGAuthController validateToken:]",
            currentAddress: cur,
            image: img,
            functions: index.functions
        ).get()
        #expect(objcRes.matchKind == .functionOrSymbol)

        let customRename = UserSymbolRename(address: verifyFn.address, originalName: verifyFn.name, customName: "gatekeeper_check")
        let renameRes = try MachGoToExpressionParser.parse(
            query: "gatekeeper_check+0x4",
            currentAddress: cur,
            image: img,
            functions: index.functions,
            customRenames: [customRename]
        ).get()
        #expect(renameRes.virtualAddress == verifyFn.address.adding(UInt64(4)))
    }

    @Test("MachGoToExpressionParser returns structured GoToParseFailure on empty, unmapped, or unknown queries")
    func goToExpressionParserFailureCases() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "GoToErr.arm64")
        let cur = VirtualAddress(0x1_0000_1000)

        let emptyRes = MachGoToExpressionParser.parse(query: "   ", currentAddress: cur, image: image)
        #expect(emptyRes == .failure(.emptyQuery))

        let unmappedRes = MachGoToExpressionParser.parse(query: "off:0x99999999", currentAddress: cur, image: image)
        #expect(unmappedRes == .failure(.unmappedFileOffset(FileOffset(0x9999_9999))))

        let unknownRes = MachGoToExpressionParser.parse(query: "totally_nonexistent_symbol_xyz", currentAddress: cur, image: image)
        #expect(unknownRes == .failure(.unknownSymbolOrFunction("totally_nonexistent_symbol_xyz")))
    }

    @Test("FuzzySubsequenceMatcher ranks contiguous/boundary matches above scattered characters and highlights spans")
    func fuzzySubsequenceMatcherScoringAndHighlighting() {
        #expect(FuzzySubsequenceMatcher.match(query: "xyz", in: "verify_license") == nil)

        let boundaryHit = FuzzySubsequenceMatcher.match(query: "vl", in: "_verify_license")
        let scatteredHit = FuzzySubsequenceMatcher.match(query: "vl", in: "_value_multiplier_table")
        #expect(boundaryHit != nil)
        #expect(scatteredHit != nil)
        #expect((boundaryHit?.score ?? 0) >= (scatteredHit?.score ?? 0))
        #expect(boundaryHit?.matchedCharacterPositions.count == 2)

        let highlighted = FuzzySubsequenceMatcher.highlightedAttributedString(
            text: "_verify_license",
            matchedPositions: boundaryHit?.matchedCharacterPositions ?? []
        )
        #expect(String(highlighted.characters) == "_verify_license")
    }

    @Test("MachCommandPaletteController rebuilds catalog, filters by fuzzy query and kind, and navigates selection")
    @MainActor
    func commandPaletteControllerCatalogFilteringAndSelectionNavigation() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "Palette.arm64e")

        let controller = MachCommandPaletteController(maxVisibleResults: 50)
        controller.rebuildCatalog(
            image: index.image,
            functions: index.functions,
            renames: [UserSymbolRename(address: VirtualAddress(0x1_0000_1000), originalName: "_compute_checksum", customName: "custom_fnv1a")],
            bookmarks: [UserBookmark(address: VirtualAddress(0x1_0000_1000), label: "Audit Entry")],
            findings: [
                SecurityAuditFinding(
                    pluginID: "p1",
                    pluginName: "Scanner",
                    severity: .high,
                    category: "Token",
                    title: "Static License Key",
                    detail: "Found token"
                )
            ]
        )

        controller.openPalette(initialQuery: "fnv1a", filter: .function)
        #expect(controller.isPresented)
        #expect(!controller.filteredResults.isEmpty)
        #expect(controller.currentlySelectedEntry?.title == "custom_fnv1a")

        controller.openPalette(initialQuery: "", filter: .command)
        #expect(controller.filteredResults.count >= 3)
        #expect(controller.selectedIndex == 0)
        controller.moveSelectionDown()
        #expect(controller.selectedIndex == 1)
        controller.moveSelectionUp()
        #expect(controller.selectedIndex == 0)
        controller.closePalette()
        #expect(!controller.isPresented)
    }

    @Test("SynchronizedAddressCursorBus executeGoToQuery updates cursor and recentJumpQueries")
    @MainActor
    func cursorBusExecuteGoToQueryUpdatesCursorAndHistory() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "ExecGoTo.arm64")
        let verifyFn = try #require(index.function(named: "_verify_license"))

        let bus = SynchronizedAddressCursorBus()
        let res = try bus.executeGoToQuery(
            "_verify_license",
            image: index.image,
            functions: index.functions
        ).get()

        #expect(res.virtualAddress == verifyFn.address)
        #expect(bus.currentLocation.virtualAddress == verifyFn.address)
        #expect(bus.recentJumpQueries.first == "_verify_license")
    }

    @Test("ColdTungstenPalette and ColdTungstenSyntaxHighlighter map severities, edges, disassembly, and Pseudo-C tokens")
    func coldTungstenPaletteAndSyntaxHighlighterFormatting() throws {
        #expect(ColdTungstenPalette.chassisBackgroundHex == "#0F1216")
        #expect(ColdTungstenPalette.tungstenSapphireHex == "#58A6FF")

        for sev in SecurityFindingSeverity.allCases {
            _ = ColdTungstenPalette.color(for: sev)
            _ = ColdTungstenPalette.backgroundFill(for: sev)
        }
        for xrefKind in XrefKind.allCases {
            _ = ColdTungstenPalette.color(for: xrefKind)
        }
        _ = ColdTungstenPalette.color(forEntropy: 0.1)
        _ = ColdTungstenPalette.color(forEntropy: 7.9)
        _ = ColdTungstenPalette.parseBookmarkColor("#3FB950")
        _ = ColdTungstenPalette.parseBookmarkColor("Crypto")

        let word = try A64MiniAssembler().assembleSingle("bl 0x100001200", at: VirtualAddress(0x1_0000_1000))
        let insn = A64InstructionDecoder().decode(word: word, at: VirtualAddress(0x1_0000_1000)) { _ in "_verify_license" }
        let attrDisasm = ColdTungstenSyntaxHighlighter.attributedDisassembly(for: insn)
        #expect(String(attrDisasm.characters).contains("bl"))

        let tokens = PseudoCCodeFormatter().tokenizeCLine("int32_t ok = verify_license(key);")
        let span = PseudoCLineSpan(lineNumber: 1, indentationLevel: 1, text: "    int32_t ok = verify_license(key);", tokens: tokens)
        let attrLine = ColdTungstenSyntaxHighlighter.attributedPseudoCLine(span)
        #expect(String(attrLine.characters).contains("verify_license"))
    }

    @Test("MachPluginConsoleRingBuffer enforces bounded capacity and tracks evicted entries")
    func pluginConsoleRingBufferBoundedEviction() {
        var ring = MachPluginConsoleRingBuffer(capacity: 8)
        for idx in 1...12 {
            ring.append(
                MachPluginConsoleEntry(
                    pluginID: "ring.test",
                    level: .info,
                    message: "line-\(idx)",
                    elapsedMilliseconds: Double(idx)
                )
            )
        }
        #expect(ring.count == 8)
        #expect(ring.evictedCount == 4)
        #expect(ring.entries.map(\.message) == (5...12).map { "line-\($0)" })
    }

    @Test("MachPluginManifestValidator rejects empty IDs/scripts and loads @machgraph-* header comments from JS file")
    func pluginManifestValidatorAndJSHeaderCommentLoader() throws {
        let invalid = MachPluginManifest(id: "", name: "Bad", summary: "s", capabilities: [], scriptSource: "")
        #expect(throws: MachGraphError.self) {
            try MachPluginManifestValidator.validate(invalid)
        }

        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let jsFile = tempDir.appendingPathComponent("sample-plugin.js")
        let jsSource = """
        // @id com.machgraph.external.sample
        // @name External Sample Auditor
        // @version 1.2.0
        // @summary Audits Mach-O segments
        // @capabilities binary.read, findings.emit
        console.info("loaded external sample");
        """
        try jsSource.write(to: jsFile, atomically: true, encoding: .utf8)

        let loaded = try MachPluginManifestValidator.loadManifest(fromJavaScriptFile: jsFile)
        #expect(!loaded.id.isEmpty)
        #expect(!loaded.scriptSource.isEmpty)
    }

    @Test("MachPluginRunner registers custom plugins, toggles enablement, and sorts findings by descending severity")
    func pluginRunnerCustomRegistrationToggleAndSeveritySorting() {
        var runner = MachPluginRunner(builtInPlugins: [])
        let custom = MachPluginManifest(
            id: "custom.one",
            name: "Custom One",
            summary: "Summary",
            capabilities: [.emitSecurityFindings],
            isBuiltIn: false,
            isEnabled: true,
            scriptSource: "console.log('ok');"
        )
        runner.registerCustomPlugin(custom)
        #expect(runner.enabledPlugins.count == 1)

        runner.setPluginEnabled(id: "custom.one", isEnabled: false)
        #expect(runner.enabledPlugins.isEmpty)

        let unsorted = [
            SecurityAuditFinding(pluginID: "p", pluginName: "P", severity: .low, category: "c", title: "Low", detail: "d"),
            SecurityAuditFinding(pluginID: "p", pluginName: "P", severity: .critical, category: "c", title: "Crit", detail: "d"),
            SecurityAuditFinding(pluginID: "p", pluginName: "P", severity: .high, category: "c", title: "High", detail: "d")
        ]
        let sorted = MachPluginRunner.sortFindingsBySeverity(unsorted)
        #expect(sorted.map(\.severity) == [.critical, .high, .low])
    }

    @Test("SecurityFindingSeverity Comparable ordering and WorkbenchPaneTab SF Symbols")
    func securitySeverityOrderingAndWorkbenchPaneSymbols() {
        #expect(SecurityFindingSeverity.info < .low)
        #expect(SecurityFindingSeverity.low < .medium)
        #expect(SecurityFindingSeverity.medium < .high)
        #expect(SecurityFindingSeverity.high < .critical)

        for tab in WorkbenchPaneTab.allCases {
            #expect(!tab.sfSymbolName.isEmpty)
            #expect(!tab.localizedTitle(in: .en).isEmpty)
            #expect(!tab.localizedTitle(in: .zhHans).isEmpty)
        }
    }

    // MARK: - 6. v1.1.0 Bilingual (`中文 / EN`) Localization & Triage Report Verification

    @Test("MachLanguage resolution priority chain: CLI --lang > MACHGRAPH_LANG > UserDefaults > Chinese Locale auto-detection")
    func machLanguageResolutionOrderAndChineseLocaleAutoDetection() {
        // In-memory store: a real suite leaves a plist in ~/Library/Preferences even after removePersistentDomain.
        let defaults = InMemoryUserDefaults()

        // 1. Auto-detects Simplified Chinese when preferredLanguages starts with "zh"
        let autoZh = MachLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN", "en-US"]
        )
        #expect(autoZh == .zhHans)

        // 2. Falls back to English on non-Chinese system locale
        let autoEn = MachLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["en-US"]
        )
        #expect(autoEn == .en)

        // 3. UserDefaults overrides system locale
        defaults.set("en", forKey: MachLanguage.userDefaultsKey)
        let fromDefaults = MachLanguage.resolve(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN"]
        )
        #expect(fromDefaults == .en)

        // 4. MACHGRAPH_LANG overrides UserDefaults
        let fromEnv = MachLanguage.resolve(
            arguments: [],
            environment: ["MACHGRAPH_LANG": "zh"],
            userDefaults: defaults,
            preferredLanguages: ["en-US"]
        )
        #expect(fromEnv == .zhHans)

        // 5. CLI --lang / --lang= overrides MACHGRAPH_LANG & UserDefaults
        let fromCLI = MachLanguage.resolve(
            arguments: ["--export-screenshots", "/tmp/out", "--lang", "en"],
            environment: ["MACHGRAPH_LANG": "zh"],
            userDefaults: defaults,
            preferredLanguages: ["zh-Hans-CN"]
        )
        #expect(fromCLI == .en)

        let fromCLIEquals = MachLanguage.resolve(
            arguments: ["info", "--lang=zh-CN"],
            environment: ["MACHGRAPH_LANG": "en"],
            userDefaults: defaults,
            preferredLanguages: ["en-US"]
        )
        #expect(fromCLIEquals == .zhHans)
    }

    @Test("MachLocalizer toggles live between zh-Hans and en, persists to UserDefaults, and localizes domain models")
    @MainActor
    func machLocalizerLiveTogglePersistenceAndDomainTranslations() {
        // In-memory store: a real suite leaves a plist in ~/Library/Preferences even after removePersistentDomain.
        let defaults = InMemoryUserDefaults()

        let localizer = MachLocalizer(
            arguments: [],
            environment: [:],
            userDefaults: defaults,
            preferredLanguages: ["en-US"]
        )
        #expect(localizer.language == .en)
        #expect(localizer.language.badge == "EN")
        #expect(localizer.L("CFG Graph", "控制流图") == "CFG Graph")

        localizer.toggleLanguage()
        #expect(localizer.language == .zhHans)
        #expect(localizer.language.badge == "中文")
        #expect(localizer.L("CFG Graph", "控制流图") == "控制流图")
        #expect(defaults.string(forKey: MachLanguage.userDefaultsKey) == "zh-Hans")

        localizer.toggleLanguage()
        #expect(localizer.language == .en)
        #expect(defaults.string(forKey: MachLanguage.userDefaultsKey) == "en")

        for tab in WorkbenchPaneTab.allCases {
            #expect(tab.localizedTitle(in: .en) != tab.localizedTitle(in: .zhHans))
        }
        #expect(NavigatorSidebarFilter.functions.localizedTitle(in: .zhHans) == "函数")
        #expect(NavigatorSidebarFilter.symbols.localizedTitle(in: .zhHans) == "符号")
        #expect(NavigatorSidebarFilter.imports.localizedTitle(in: .zhHans) == "导入")
        #expect(NavigatorSidebarFilter.bookmarks.localizedTitle(in: .zhHans) == "书签")
        for plugin in BuiltInMachPluginCatalog.allPlugins {
            #expect(!plugin.localizedName(in: .zhHans).isEmpty)
            #expect(!plugin.localizedSummary(in: .zhHans).isEmpty)
        }
    }

    @Test("ColdTungstenHTMLReportExporter emits interactive 中文 | EN toggle, localStorage & navigator.language auto-zh, and zero em-dashes")
    func coldTungstenHTMLReportBilingualToggleAndZeroEmDashMarkers() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, fileName: "BilingualDemo.arm64e")

        let html = try ColdTungstenHTMLReportExporter().exportHTMLReport(
            analysisIndex: index,
            binaryData: data
        )

        #expect(html.contains("MachGraph v1.4.0"))
        #expect(html.contains(#"class="lang-toggle""#))
        #expect(html.contains(#"data-set-lang="zh""#))
        #expect(html.contains(#"data-set-lang="en""#))
        #expect(html.contains("data-en="))
        #expect(html.contains("data-zh="))
        #expect(html.contains("machgraph-report-lang"))
        #expect(html.contains("localStorage"))
        #expect(html.contains("navigator.language"))
        #expect(html.contains("startsWith('zh')"))
        #expect(html.contains("冷钨钢二进制逆向分诊报告"))
        #expect(!html.contains("\u{2014}"))
    }

    // MARK: - 7. M0 Honest Contract Tests (G14, G15, G16, G17, G10, G19, MCP)

    @Test("M0 Item 1 (G14/G15/G16): CLI rejects missing binary, unknown options, and missing target function, while supporting positional paths and --demo")
    func cliHonestArgumentsMissingFileUnknownOptionAndMissingTarget() async throws {
        let cli = MachCLIRunner()

        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["info"])
        }
        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["disasm"])
        }
        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["disasm", "/bin/ls", "--nosuchoption"])
        }
        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["disasm", "/bin/ls", "--function", "nosuchfunction"])
        }
        await #expect(throws: MachGraphError.self) {
            _ = try await cli.execute(arguments: ["decompile", "/bin/ls", "--symbol", "nosuchfunction"])
        }

        let posInfo = try await cli.execute(arguments: ["info", "/bin/ls"])
        let flagInfo = try await cli.execute(arguments: ["info", "--binary", "/bin/ls"])
        #expect(posInfo == flagInfo)
        #expect(posInfo.contains("ls"))

        let demoEN = try await cli.execute(arguments: ["info", "--demo", "--lang", "en"])
        #expect(demoEN.contains("[DEMO]"))
        let demoZH = try await cli.execute(arguments: ["info", "--demo", "--lang", "zh"])
        #expect(demoZH.contains("[演示数据]"))
    }

    @Test("M0 Item 2 (G17): Every subcommand listed under Subcommands in --help is recognized by MachCLIRunner")
    func cliAllHelpSubcommandsAreRoutable() async throws {
        let cli = MachCLIRunner()
        let helpOut = try await cli.execute(arguments: ["--help", "--lang", "en"])
        var inSubcommands = false
        var listedCommands: [String] = []
        for rawLine in helpOut.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.hasPrefix("Subcommands:") {
                inSubcommands = true
                continue
            }
            if inSubcommands {
                if !line.hasPrefix("  ") {
                    break
                }
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if let firstToken = trimmed.split(separator: " ").first {
                    listedCommands.append(String(firstToken))
                }
            }
        }
        #expect(!listedCommands.isEmpty)
        for cmd in listedCommands where cmd != "mcp" {
            do {
                _ = try await cli.execute(arguments: [cmd, "/usr/bin/true"])
            } catch {
                let msg = error.localizedDescription
                #expect(!msg.contains("Unknown subcommand"), "Subcommand '\(cmd)' threw Unknown subcommand: \(msg)")
            }
        }
    }

    @Test("M0 Item 6 (G10): info --json, fixups --json, and symbols --json emit real structured output on /bin/ls")
    func cliFixupsAndJSONOutputOnBinLs() async throws {
        let cli = MachCLIRunner()

        let infoJSON = try await cli.execute(arguments: ["info", "/bin/ls", "--json"])
        let infoObj = try #require(JSONSerialization.jsonObject(with: Data(infoJSON.utf8)) as? [String: Any])
        #expect(infoObj["fileName"] as? String == "ls")
        let segs = try #require(infoObj["segments"] as? [[String: Any]])
        let secs = try #require(infoObj["sections"] as? [[String: Any]])
        #expect(!segs.isEmpty)
        #expect(!secs.isEmpty)

        let fixupsJSON = try await cli.execute(arguments: ["fixups", "/bin/ls", "--json"])
        let fixupsObj = try #require(JSONSerialization.jsonObject(with: Data(fixupsJSON.utf8)) as? [String: Any])
        #expect(fixupsObj["fileName"] as? String == "ls")
        #expect(fixupsObj["fixups"] != nil)

        let symsJSON = try await cli.execute(arguments: ["symbols", "/bin/ls", "--json"])
        let symsObj = try #require(JSONSerialization.jsonObject(with: Data(symsJSON.utf8)) as? [String: Any])
        let realSyms = try #require(symsObj["realSymbols"] as? [[String: Any]])
        let inferredSyms = try #require(symsObj["inferredSymbols"] as? [[String: Any]])
        #expect(!realSyms.isEmpty)
        #expect(!inferredSyms.isEmpty)
    }

    @Test("M0 Row 7: MachMCPServer mach_inspect_binary without binaryPath returns isError: true")
    func mcpMissingBinaryPathReturnsIsErrorTrue() throws {
        let mcp = MachMCPServer()
        let req = #"{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{}}}"#
        let rawResp = try #require(mcp.handleJSONRPCLine(req))
        let obj = try #require(JSONSerialization.jsonObject(with: Data(rawResp.utf8)) as? [String: Any])
        let res = try #require(obj["result"] as? [String: Any])
        #expect(res["isError"] as? Bool == true)
    }

    // MARK: - 8. M0 Rework (G27, G30, help/README option parity)

    @Test("G27: patch-asm fails on an unassemblable statement after ';' and writes no output file")
    func cliPatchAsmRejectsBadStatementAfterSemicolonWithoutWritingOutput() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let inputBin = tempDir.appendingPathComponent("sample.macho")
        let outputBin = tempDir.appendingPathComponent("patched.macho")
        let originalData = try RepoFixtures.thinARM64SampleData()
        try originalData.write(to: inputBin)
        let image = try UniversalBinaryDispatcher.load(data: originalData, fileName: "sample.macho")
        let targetSym = try #require(image.symbols.first { $0.name == "_demo_fnv1a32" })
        let address = targetSym.address.compactHexString

        let cli = MachCLIRunner()
        let rejected = [
            "nop; bogus x1",
            "mov x0, #1; garbage",
            "nop; ; nop extra words here",
            "ret ; return to caller",
            "mov w0, #1; ret; set return value to true"
        ]
        for source in rejected {
            for extraFlags in [[String](), ["--force"], ["--json"]] {
                try? FileManager.default.removeItem(at: outputBin)
                var caught: MachGraphError?
                do {
                    _ = try await cli.execute(arguments: [
                        "patch-asm", inputBin.path,
                        "--address", address,
                        "--asm", source,
                        "--output", outputBin.path
                    ] + extraFlags)
                } catch let err as MachGraphError {
                    caught = err
                }
                let label = "\(source.debugDescription) \(extraFlags)"
                if case .assemblerError = caught {
                    // expected: reported as an assembler error (exit code 1 at the process level)
                } else {
                    Issue.record("patch-asm --asm \(label) must fail with assemblerError, got \(String(describing: caught))")
                }
                #expect(!FileManager.default.fileExists(atPath: outputBin.path), "patch-asm --asm \(label) must not write the output file")
                #expect(try Data(contentsOf: inputBin) == originalData, "patch-asm --asm \(label) must not modify the input file")
            }
        }

        // The same entry point still assembles every statement of a valid program.
        let okJSON = try await cli.execute(arguments: [
            "patch-asm", inputBin.path,
            "--address", address,
            "--asm", "mov w0, #1; ret // force true",
            "--force",
            "--output", outputBin.path,
            "--json"
        ])
        let okObj = try #require(JSONSerialization.jsonObject(with: Data(okJSON.utf8)) as? [String: Any])
        #expect(okObj["byteCount"] as? Int == 8)
        #expect(okObj["valid"] as? Bool == true)
        #expect(FileManager.default.fileExists(atPath: outputBin.path))

        // README / --help claim about --force: in the fixture, `cbnz w9, <fn+0x1c>` at fn+0x28 jumps to fn+0x1c,
        // so an 8-byte patch at fn+0x18 has a branch target in its interior. It is refused without --force.
        try FileManager.default.removeItem(at: outputBin)
        let interiorTargetPatch = [
            "patch-asm", inputBin.path,
            "--address", targetSym.address.adding(UInt64(0x18)).compactHexString,
            "--asm", "nop; nop",
            "--output", outputBin.path
        ]
        var refusal: MachGraphError?
        do {
            _ = try await cli.execute(arguments: interiorTargetPatch)
        } catch let err as MachGraphError {
            refusal = err
        }
        if case .patchFormatError(let detail) = refusal {
            #expect(detail.contains("jumps into patch interior"))
        } else {
            Issue.record("patch covering a branch target must be refused without --force, got \(String(describing: refusal))")
        }
        #expect(!FileManager.default.fileExists(atPath: outputBin.path))

        let forced = try await cli.execute(arguments: interiorTargetPatch + ["--force"])
        #expect(forced.contains("Valid=true"))
        #expect(FileManager.default.fileExists(atPath: outputBin.path))
    }

    @Test("G30: a mistyped subcommand is a usage error (exit 2) naming the subcommand; it is never reported as a missing file")
    func desktopLaunchResolutionRejectsMistypedSubcommands() throws {
        // Only this path "exists"; the decision must not depend on what happens to be on the test machine.
        let existing: Set<String> = ["/bin/ls", "/bin/cat"]
        func resolve(_ args: [String], _ lang: MachLanguage = .en) throws -> MachDesktopLaunchRequest {
            try MachCLIRunner.resolveDesktopLaunchRequest(arguments: args, language: lang) { existing.contains($0) }
        }
        func usageError(_ args: [String], _ lang: MachLanguage = .en) -> String? {
            do {
                _ = try resolve(args, lang)
                return nil
            } catch let err as MachGraphError {
                guard case .invalidCLIArguments = err else { return nil }
                #expect(MachCLIRunner.exitCode(for: err) == 2)
                return err.localizedMessage(in: lang)
            } catch {
                return nil
            }
        }

        // 1. `<typo> <file>` and every other shape with more than one argument: unknown subcommand, exit 2.
        let mistyped: [(args: [String], word: String)] = [
            (["inof", "/bin/ls"], "inof"),
            (["dissasm", "/bin/ls", "--demo"], "dissasm"),
            (["inof", "--demo"], "inof"),
            (["inof", "--binary", "/bin/ls"], "inof"),
            (["--binary", "/bin/ls", "inof"], "inof"),
            (["/bin/ls", "/bin/cat"], "/bin/ls"),
            (["nosuchcmd", "/no/such/file"], "nosuchcmd")
        ]
        for (args, word) in mistyped {
            let msgEN = try #require(usageError(args, .en), "\(args) must be a usage error")
            #expect(msgEN.contains("Unknown subcommand '\(word)'"), "\(args) -> \(msgEN)")
            #expect(!msgEN.lowercased().contains("not found"), "\(args) -> \(msgEN)")
            let msgZH = try #require(usageError(args + ["--lang", "zh"], .zhHans), "\(args) must be a usage error (zh)")
            #expect(msgZH.contains("未知子命令 '\(word)'"), "\(args) -> \(msgZH)")
            #expect(!msgZH.contains("找不到"), "\(args) -> \(msgZH)")
        }

        // 2. A lone word that is neither a subcommand nor a file: usage error that names both possibilities.
        for lone in ["inof", "/no/such/file"] {
            let msg = try #require(usageError([lone]), "[\(lone)] must be a usage error")
            #expect(msg.contains("'\(lone)'"))
            #expect(msg.contains("subcommand"))
            #expect(msg.contains("file"))
        }

        // 3. Unknown options stay usage errors; `--binary` keeps its own diagnostics.
        #expect(usageError(["--bogus"]) != nil)
        #expect(usageError(["--binary"]) != nil)
        do {
            _ = try resolve(["--binary", "/no/such/file"])
            Issue.record("--binary with a missing file must fail")
        } catch let err as MachGraphError {
            #expect(err == .fileNotFound("/no/such/file"))
            #expect(MachCLIRunner.exitCode(for: err) == 1)
        }

        // 4. The only argument vectors that may open the workbench.
        #expect(try resolve([]) == MachDesktopLaunchRequest(binaryPath: nil, loadDemo: false))
        #expect(try resolve(["--lang", "zh"]) == MachDesktopLaunchRequest(binaryPath: nil, loadDemo: false))
        #expect(try resolve(["--demo"]) == MachDesktopLaunchRequest(binaryPath: nil, loadDemo: true))
        #expect(try resolve(["/bin/ls"]) == MachDesktopLaunchRequest(binaryPath: "/bin/ls", loadDemo: false))
        #expect(try resolve(["--binary", "/bin/ls"]) == MachDesktopLaunchRequest(binaryPath: "/bin/ls", loadDemo: false))

        // 5. Known subcommands never reach desktop resolution at all.
        #expect(MachCLIRunner.isHeadlessInvocation(arguments: ["info", "/bin/ls"]))
        #expect(MachCLIRunner.isHeadlessInvocation(arguments: ["--lang", "zh", "patch", "/bin/ls"]))
        #expect(!MachCLIRunner.isHeadlessInvocation(arguments: ["inof", "/bin/ls"]))
    }

    @Test("M0 rework: /dev/null and other non-regular files are rejected as such, not as a permission problem")
    func cliAndMCPRejectNonRegularInputFilesWithAccurateReason() async throws {
        let cli = MachCLIRunner()
        for (lang, expected) in [("en", "not a regular file"), ("zh", "不是普通文件")] {
            for subcommand in ["info", "disasm", "export-html"] {
                do {
                    _ = try await cli.execute(arguments: [subcommand, "/dev/null", "--lang", lang])
                    Issue.record("\(subcommand) /dev/null must fail")
                } catch let err as MachGraphError {
                    let msg = err.localizedMessage(in: lang == "zh" ? .zhHans : .en)
                    #expect(msg.contains(expected), "\(subcommand) --lang \(lang): \(msg)")
                    #expect(msg.contains("/dev/null"))
                    #expect(!msg.lowercased().contains("permission"), "\(subcommand) --lang \(lang): \(msg)")
                    #expect(!msg.contains("权限"))
                    #expect(MachCLIRunner.exitCode(for: err) == 1)
                }
            }
        }

        let mcp = MachMCPServer()
        let req = #"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/dev/null"}}}"#
        let rawResp = try #require(mcp.handleJSONRPCLine(req))
        let obj = try #require(JSONSerialization.jsonObject(with: Data(rawResp.utf8)) as? [String: Any])
        let res = try #require(obj["result"] as? [String: Any])
        #expect(res["isError"] as? Bool == true)
        let text = ((res["content"] as? [[String: Any]])?.first?["text"] as? String) ?? ""
        #expect(text.contains("not a regular file"), "MCP: \(text)")
        #expect(!text.lowercased().contains("permission"), "MCP: \(text)")
    }

    @Test("G29: every MachGraph option used in README.md / README.zh-CN.md is listed in --help (EN and ZH)")
    func readmeOptionsAllAppearInHelp() async throws {
        let cli = MachCLIRunner()
        let helpEN = try await cli.execute(arguments: ["--help", "--lang", "en"])
        let helpZH = try await cli.execute(arguments: ["--help", "--lang", "zh"])
        let optionPattern = try NSRegularExpression(pattern: #"(?<![\w-])--[A-Za-z][A-Za-z0-9-]*"#)

        func options(in text: String) -> Set<String> {
            let range = NSRange(text.startIndex..., in: text)
            return Set(optionPattern.matches(in: text, range: range).compactMap { Range($0.range, in: text).map { String(text[$0]) } })
        }

        for readmeName in ["README.md", "README.zh-CN.md"] {
            let readme = try String(contentsOf: RepoFixtures.repositoryRoot.appendingPathComponent(readmeName), encoding: .utf8)
            var used = Set<String>()

            // 1. Fenced code blocks: only command lines that invoke the MachGraph binary (continuations joined).
            let fencedParts = readme.components(separatedBy: "```")
            for (idx, block) in fencedParts.enumerated() where idx % 2 == 1 {
                let joined = block.replacingOccurrences(of: "\\\n", with: " ")
                for line in joined.split(separator: "\n") where line.contains("/MachGraph ") {
                    // Options of other tools in a pipeline come before the binary; keep what follows it.
                    let tail = line.components(separatedBy: "/MachGraph ").dropFirst().joined(separator: " ")
                    used.formUnion(options(in: tail))
                }
            }
            // 2. Inline code spans that are themselves an option, e.g. `--count` or `--lang en|zh`.
            for (idx, part) in fencedParts.enumerated() where idx % 2 == 0 {
                let spans = part.components(separatedBy: "`")
                for (spanIdx, span) in spans.enumerated() where spanIdx % 2 == 1 && span.hasPrefix("--") {
                    used.formUnion(options(in: String(span.prefix { !$0.isWhitespace })))
                }
            }

            #expect(used.count >= 8, "\(readmeName): expected to find the documented options, got \(used.sorted())")
            for option in used.sorted() {
                #expect(helpEN.contains(option), "\(readmeName) uses \(option), which --help (en) does not list")
                #expect(helpZH.contains(option), "\(readmeName) uses \(option), which --help (zh) does not list")
            }
        }
    }

    @Test("M0 Item 9 (G19): MachStudioViewModel starts empty on default launch and sets isDemoMode when loadDemoBinary is called")
    @MainActor
    func studioViewModelStartsEmptyOnDefaultLaunch() throws {
        let vm = MachStudioViewModel(initialBinaryURL: nil, loadDemo: false, emitStartupToast: false)
        #expect(vm.loadedImage == nil)
        #expect(vm.analysisIndex == nil)
        #expect(vm.functions.isEmpty)
        #expect(!vm.isDemoMode)

        vm.loadDemoBinary(emitToast: false)
        #expect(vm.loadedImage != nil)
        #expect(vm.loadedImage?.fileName == "demo_arm64_sample")
        #expect(vm.isDemoMode)
        #expect(!vm.functions.isEmpty)
    }

    @Test("G41: CLI codesign --json and info --json expose CodeDirectory flags and flagsHex")
    func cliCodeSignAndInfoJSONExposeCodeDirectoryFlags() async throws {
        let cli = MachCLIRunner()
        let sshCSRaw = try await cli.execute(arguments: ["codesign", "/usr/bin/ssh", "--json"])
        let sshCS = try #require(JSONSerialization.jsonObject(with: Data(sshCSRaw.utf8)) as? [String: Any])
        #expect((sshCS["flags"] as? NSNumber)?.uint32Value == 0x10000)
        #expect(sshCS["flagsHex"] as? String == "0x10000")

        let lsCSRaw = try await cli.execute(arguments: ["codesign", "/bin/ls", "--json"])
        let lsCS = try #require(JSONSerialization.jsonObject(with: Data(lsCSRaw.utf8)) as? [String: Any])
        #expect((lsCS["flags"] as? NSNumber)?.uint32Value == 0)
        #expect(lsCS["flagsHex"] as? String == "0x0")

        let sshInfoRaw = try await cli.execute(arguments: ["info", "/usr/bin/ssh", "--json"])
        let sshInfo = try #require(JSONSerialization.jsonObject(with: Data(sshInfoRaw.utf8)) as? [String: Any])
        let infoCS = try #require(sshInfo["codeSignature"] as? [String: Any])
        #expect((infoCS["flags"] as? NSNumber)?.uint32Value == 0x10000)
        #expect(infoCS["flagsHex"] as? String == "0x10000")
    }

    // MARK: - 9. M3 Stage 1: CLI symbols --json & info (JSON + text) Dylib Parity

    private static func buildSyntheticDylibFixture() -> Data {
        let textFileOff = 0x1000
        let linkeditFileOff = 0x4000
        var sliceBytes = [UInt8](repeating: 0, count: linkeditFileOff)
        // Two RET instructions in __TEXT,__text at VM 0x1000 and 0x1004
        for off in [textFileOff, textFileOff + 4] {
            sliceBytes[off + 0] = 0xC0
            sliceBytes[off + 1] = 0x03
            sliceBytes[off + 2] = 0x5F
            sliceBytes[off + 3] = 0xD6
        }

        var strPool = BinaryBufferWriter(capacity: 128, endianness: .little)
        strPool.appendUInt8(0)
        var nlist = BinaryBufferWriter(capacity: 32, endianness: .little)
        for symName in ["_alias_alpha", "_alias_beta"] {
            let sOff = UInt32(strPool.count)
            strPool.appendCString(symName)
            nlist.appendUInt32(sOff)
            nlist.appendUInt8(MachOConstants.nSect | MachOConstants.nExt)
            nlist.appendUInt8(1)
            nlist.appendUInt16(0)
            nlist.appendUInt64(0x1000)
        }
        strPool.padToAlignment(8)

        var linkedit = BinaryBufferWriter(capacity: 256, endianness: .little)
        let symtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(nlist.bytes)
        let strtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(strPool.bytes)
        linkedit.padToAlignment(16)

        var lc = BinaryBufferWriter(capacity: 512, endianness: .little)
        var ncmds: UInt32 = 0

        // __TEXT with __text section
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(72 + 80)
        lc.appendFixedASCII("__TEXT", length: 16)
        lc.appendUInt64(0)
        lc.appendUInt64(0x4000)
        lc.appendUInt64(0)
        lc.appendUInt64(0x4000)
        lc.appendUInt32(5)
        lc.appendUInt32(5)
        lc.appendUInt32(1)
        lc.appendUInt32(0)
        lc.appendFixedASCII("__text", length: 16)
        lc.appendFixedASCII("__TEXT", length: 16)
        lc.appendUInt64(0x1000)
        lc.appendUInt64(8)
        lc.appendUInt32(0x1000)
        lc.appendUInt32(2)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        ncmds += 1

        // __LINKEDIT
        lc.appendUInt32(MachOConstants.lcSegment64)
        lc.appendUInt32(72)
        lc.appendFixedASCII("__LINKEDIT", length: 16)
        lc.appendUInt64(0x4000)
        lc.appendUInt64(0x4000)
        lc.appendUInt64(UInt64(linkeditFileOff))
        lc.appendUInt64(UInt64(linkedit.count))
        lc.appendUInt32(1)
        lc.appendUInt32(1)
        lc.appendUInt32(0)
        lc.appendUInt32(0)
        ncmds += 1

        func appendDylib(cmd: UInt32, name: String, current: UInt32, compat: UInt32) {
            let bytes = Array(name.utf8) + [0]
            let sz = (24 + bytes.count + 7) & ~7
            lc.appendUInt32(cmd)
            lc.appendUInt32(UInt32(sz))
            lc.appendUInt32(24)
            lc.appendUInt32(2)
            lc.appendUInt32(current)
            lc.appendUInt32(compat)
            lc.appendBytes(bytes)
            lc.padToAlignment(8)
            ncmds += 1
        }

        appendDylib(cmd: MachOConstants.lcIdDylib, name: "/usr/local/lib/libdemo.1.dylib", current: 0x0002_0300, compat: 0x0001_0000)
        appendDylib(cmd: MachOConstants.lcLoadDylib, name: "/usr/lib/libSystem.B.dylib", current: 0x054B_0000, compat: 0x0001_0000)
        appendDylib(cmd: MachOConstants.lcLoadWeakDylib, name: "/usr/lib/libweak_opt.dylib", current: 0x0004_0000, compat: 0x0002_0000)

        lc.appendUInt32(MachOConstants.lcSymtab)
        lc.appendUInt32(24)
        lc.appendUInt32(UInt32(symtabOff))
        lc.appendUInt32(2)
        lc.appendUInt32(UInt32(strtabOff))
        lc.appendUInt32(UInt32(strPool.count))
        ncmds += 1

        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(0)
        hdr.appendUInt32(MachOConstants.mhDylib)
        hdr.appendUInt32(ncmds)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhTwoLevel)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for (i, b) in hdr.bytes.enumerated() {
            sliceBytes[i] = b
        }
        return Data(sliceBytes + linkedit.bytes)
    }

    @Test("M3 D-M3-3 & D-M3-5: CLI symbols --json preserves same-address symbols and info --json exports compatibilityVersion and installID")
    func m3CLISymbolsAndInfoJSONExportCompatibilityVersionAndInstallID() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let dylibURL = tempDir.appendingPathComponent("libdemo.1.dylib")
        try Self.buildSyntheticDylibFixture().write(to: dylibURL)

        let cli = MachCLIRunner()

        let symsRaw = try await cli.execute(arguments: ["symbols", dylibURL.path, "--json"])
        let symsObj = try #require(JSONSerialization.jsonObject(with: Data(symsRaw.utf8)) as? [String: Any])
        let realSyms = try #require(symsObj["realSymbols"] as? [[String: Any]])
        let realNames = realSyms.compactMap { $0["name"] as? String }.sorted()
        #expect(realNames == ["_alias_alpha", "_alias_beta"])

        let infoRaw = try await cli.execute(arguments: ["info", dylibURL.path, "--json"])
        let infoObj = try #require(JSONSerialization.jsonObject(with: Data(infoRaw.utf8)) as? [String: Any])

        let installID = try #require(infoObj["installID"] as? [String: Any])
        #expect(installID["installName"] as? String == "/usr/local/lib/libdemo.1.dylib")
        #expect(installID["compatibilityVersion"] as? String == "1.0.0")
        #expect(installID["currentVersion"] as? String == "2.3.0")

        let libs = try #require(infoObj["libraries"] as? [[String: Any]])
        #expect(libs.count == 2)
        #expect(libs[0]["installName"] as? String == "/usr/lib/libSystem.B.dylib")
        #expect(libs[0]["compatibilityVersion"] as? String == "1.0.0")
        #expect(libs[0]["currentVersion"] as? String == "1355.0.0")
        #expect(libs[0]["isWeak"] as? Bool == false)
        #expect(libs[1]["installName"] as? String == "/usr/lib/libweak_opt.dylib")
        #expect(libs[1]["compatibilityVersion"] as? String == "2.0.0")
        #expect(libs[1]["currentVersion"] as? String == "4.0.0")
        #expect(libs[1]["isWeak"] as? Bool == true)

        let lsInfoRaw = try await cli.execute(arguments: ["info", "/bin/ls", "--json"])
        let lsInfo = try #require(JSONSerialization.jsonObject(with: Data(lsInfoRaw.utf8)) as? [String: Any])
        #expect(lsInfo["installID"] is NSNull)
        let lsLibs = try #require(lsInfo["libraries"] as? [[String: Any]])
        #expect(!lsLibs.isEmpty)
        for lib in lsLibs {
            let compat = try #require(lib["compatibilityVersion"] as? String)
            let current = try #require(lib["currentVersion"] as? String)
            #expect(compat.split(separator: ".").count == 3)
            #expect(current.split(separator: ".").count == 3)
        }
    }

    @Test("M3 D-M3-5: CLI info text mode prints dependent libraries and MH_DYLIB install ID")
    func m3CLIInfoTextModePrintsLibrariesAndInstallID() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let dylibURL = tempDir.appendingPathComponent("libdemo.1.dylib")
        try Self.buildSyntheticDylibFixture().write(to: dylibURL)

        let cli = MachCLIRunner()
        let dylibText = try await cli.execute(arguments: ["info", dylibURL.path])
        #expect(dylibText.contains("Install ID:    /usr/local/lib/libdemo.1.dylib (compatibility version 1.0.0, current version 2.3.0)"))
        #expect(dylibText.contains("/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1355.0.0)"))
        #expect(dylibText.contains("/usr/lib/libweak_opt.dylib (compatibility version 2.0.0, current version 4.0.0, weak)"))

        let lsText = try await cli.execute(arguments: ["info", "/bin/ls"])
        #expect(lsText.contains("/usr/lib/libSystem.B.dylib"))
        #expect(lsText.contains("compatibility version "))
        #expect(lsText.contains("current version "))
    }

    // MARK: - 10. M3 Stage 2 (D-M3-7): CLI codesign --json Native Entitlements & DER Fallback

    private static func m3DerEncodeLength(_ length: Int) -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        }
        var tmp = length
        var octets: [UInt8] = []
        while tmp > 0 {
            octets.insert(UInt8(tmp & 0xFF), at: 0)
            tmp >>= 8
        }
        return [UInt8(0x80 | octets.count)] + octets
    }

    private static func m3DerTLV(tagByte: UInt8, content: [UInt8]) -> [UInt8] {
        [tagByte] + m3DerEncodeLength(content.count) + content
    }

    private static func m3DerBool(_ value: Bool) -> [UInt8] {
        m3DerTLV(tagByte: 0x01, content: [value ? 0xFF : 0x00])
    }

    private static func m3DerInt(_ value: Int64) -> [UInt8] {
        var v = value
        var bytes: [UInt8] = []
        repeat {
            bytes.insert(UInt8(truncatingIfNeeded: v), at: 0)
            v >>= 8
        } while !((v == 0 && (bytes[0] & 0x80) == 0) || (v == -1 && (bytes[0] & 0x80) != 0))
        return m3DerTLV(tagByte: 0x02, content: bytes)
    }

    private static func m3DerUTF8(_ value: String) -> [UInt8] {
        m3DerTLV(tagByte: 0x0C, content: Array(value.utf8))
    }

    private static func m3DerSequence(_ items: [[UInt8]]) -> [UInt8] {
        m3DerTLV(tagByte: 0x30, content: items.flatMap { $0 })
    }

    private static func m3DerContextDict(_ entries: [(String, [UInt8])]) -> [UInt8] {
        let pairs = entries.map { k, v in m3DerSequence([m3DerUTF8(k), v]) }
        return m3DerTLV(tagByte: 0xB0, content: pairs.flatMap { $0 })
    }

    private static func m3BuildCoreEntitlementsDER(_ entries: [(String, [UInt8])]) -> [UInt8] {
        m3DerTLV(tagByte: 0x70, content: m3DerInt(1) + m3DerContextDict(entries))
    }

    private static func buildSyntheticCodeSignMachO(
        includeSignature: Bool = true,
        xmlPayloadBytes: [UInt8]? = nil,
        derPayloadBytes: [UInt8]? = nil
    ) -> Data {
        let textFileOff = 0x1000
        let linkeditFileOff = 0x4000
        var sliceBytes = [UInt8](repeating: 0, count: linkeditFileOff)
        // Single RET instruction at 0x100001000
        sliceBytes[textFileOff + 0] = 0xC0
        sliceBytes[textFileOff + 1] = 0x03
        sliceBytes[textFileOff + 2] = 0x5F
        sliceBytes[textFileOff + 3] = 0xD6

        var linkedit = BinaryBufferWriter(capacity: 2048, endianness: .little)
        // Minimal symtab (1 symbol _main)
        let symtabOff = linkeditFileOff + linkedit.count
        linkedit.appendUInt32(1)
        linkedit.appendUInt8(0x0F)
        linkedit.appendUInt8(1)
        linkedit.appendUInt16(0)
        linkedit.appendUInt64(0x1_0000_1000)
        let strtabOff = linkeditFileOff + linkedit.count
        let strBytes: [UInt8] = [0] + Array("_main".utf8) + [0]
        linkedit.appendBytes(strBytes)
        linkedit.padToAlignment(16)

        var codeSigOff = 0
        var codeSigSize = 0
        if includeSignature {
            let baseSig = AdHocCodeSignatureBuilder.buildSuperBlob(
                binarySliceWithoutSignature: Data(sliceBytes),
                identifier: "com.machgraph.m3.synthetic"
            )
            var cdBytes: [UInt8] = []
            var reader = BinarySliceReader(data: baseSig, endianness: .big)
            _ = try? reader.readUInt32()
            _ = try? reader.readUInt32()
            let count = Int((try? reader.readUInt32()) ?? 0)
            for _ in 0..<count {
                let slot = (try? reader.readUInt32()) ?? 0xFFFF
                let off = Int((try? reader.readUInt32()) ?? 0)
                if slot == CodeSignatureConstants.slotCodeDirectory, off + 8 <= baseSig.count {
                    let len = (Int(baseSig[off + 4]) << 24)
                        | (Int(baseSig[off + 5]) << 16)
                        | (Int(baseSig[off + 6]) << 8)
                        | Int(baseSig[off + 7])
                    cdBytes = Array(baseSig[off..<(off + len)])
                    break
                }
            }
            var subBlobs: [(slot: UInt32, bytes: [UInt8])] = [
                (CodeSignatureConstants.slotCodeDirectory, cdBytes)
            ]
            if let xb = xmlPayloadBytes {
                var w = BinaryBufferWriter(capacity: 8 + xb.count, endianness: .big)
                w.appendUInt32(CodeSignatureConstants.magicEmbeddedEntitlements)
                w.appendUInt32(UInt32(8 + xb.count))
                w.appendBytes(xb)
                subBlobs.append((CodeSignatureConstants.slotEntitlements, w.bytes))
            }
            if let db = derPayloadBytes {
                var w = BinaryBufferWriter(capacity: 8 + db.count, endianness: .big)
                w.appendUInt32(CodeSignatureConstants.magicEmbeddedDEREntitlements)
                w.appendUInt32(UInt32(8 + db.count))
                w.appendBytes(db)
                subBlobs.append((CodeSignatureConstants.slotDEREntitlements, w.bytes))
            }
            var cms = BinaryBufferWriter(capacity: 8, endianness: .big)
            cms.appendUInt32(CodeSignatureConstants.magicBlobWrapper)
            cms.appendUInt32(8)
            subBlobs.append((CodeSignatureConstants.slotCMSWrapper, cms.bytes))

            var running = 12 + subBlobs.count * 8
            var offsets: [Int] = []
            for item in subBlobs {
                offsets.append(running)
                running += item.bytes.count
            }
            var superW = BinaryBufferWriter(capacity: running, endianness: .big)
            superW.appendUInt32(CodeSignatureConstants.magicEmbeddedSignature)
            superW.appendUInt32(UInt32(running))
            superW.appendUInt32(UInt32(subBlobs.count))
            for (i, item) in subBlobs.enumerated() {
                superW.appendUInt32(item.slot)
                superW.appendUInt32(UInt32(offsets[i]))
            }
            for item in subBlobs {
                superW.appendBytes(item.bytes)
            }
            codeSigOff = linkeditFileOff + linkedit.count
            codeSigSize = superW.count
            linkedit.appendBytes(superW.bytes)
        }
        linkedit.padToAlignment(16)

        let linkeditVMSize = max(0x4000, (linkedit.count + 0x3FFF) & ~0x3FFF)
        var lc = BinaryBufferWriter(capacity: 512, endianness: .little)
        var ncmds: UInt32 = 0

        func writeSeg64(name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64, prot: UInt32, hasTextSec: Bool) {
            let nsects: UInt32 = hasTextSec ? 1 : 0
            let cmdSize: UInt32 = 72 + nsects * 80
            lc.appendUInt32(MachOConstants.lcSegment64)
            lc.appendUInt32(cmdSize)
            lc.appendFixedASCII(name, length: 16)
            lc.appendUInt64(vmaddr)
            lc.appendUInt64(vmsize)
            lc.appendUInt64(fileoff)
            lc.appendUInt64(filesize)
            lc.appendUInt32(prot)
            lc.appendUInt32(prot)
            lc.appendUInt32(nsects)
            lc.appendUInt32(0)
            if hasTextSec {
                lc.appendFixedASCII("__text", length: 16)
                lc.appendFixedASCII("__TEXT", length: 16)
                lc.appendUInt64(0x1_0000_1000)
                lc.appendUInt64(4)
                lc.appendUInt32(UInt32(textFileOff))
                lc.appendUInt32(2)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
            }
            ncmds += 1
        }

        writeSeg64(name: "__PAGEZERO", vmaddr: 0, vmsize: 0x1_0000_0000, fileoff: 0, filesize: 0, prot: 0, hasTextSec: false)
        writeSeg64(name: "__TEXT", vmaddr: 0x1_0000_0000, vmsize: 0x4000, fileoff: 0, filesize: 0x4000, prot: 5, hasTextSec: true)
        writeSeg64(name: "__LINKEDIT", vmaddr: 0x1_0000_4000, vmsize: UInt64(linkeditVMSize), fileoff: UInt64(linkeditFileOff), filesize: UInt64(linkedit.count), prot: 1, hasTextSec: false)

        lc.appendUInt32(MachOConstants.lcSymtab)
        lc.appendUInt32(24)
        lc.appendUInt32(UInt32(symtabOff))
        lc.appendUInt32(1)
        lc.appendUInt32(UInt32(strtabOff))
        lc.appendUInt32(UInt32(strBytes.count))
        ncmds += 1

        if includeSignature {
            lc.appendUInt32(MachOConstants.lcCodeSignature)
            lc.appendUInt32(16)
            lc.appendUInt32(UInt32(codeSigOff))
            lc.appendUInt32(UInt32(codeSigSize))
            ncmds += 1
        }

        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(0)
        hdr.appendUInt32(MachOConstants.mhExecute)
        hdr.appendUInt32(ncmds)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhTwoLevel | MachOConstants.mhPIE)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for (i, b) in hdr.bytes.enumerated() {
            sliceBytes[i] = b
        }
        return Data(sliceBytes + linkedit.bytes)
    }

    private static func isStrictJSONBool(_ value: Any?, expected: Bool) -> Bool {
        guard let num = value as? NSNumber else { return false }
        guard CFGetTypeID(num) == CFBooleanGetTypeID() else { return false }
        return num.boolValue == expected
    }

    private static func isStrictJSONInt(_ value: Any?, expected: Int64) -> Bool {
        guard let num = value as? NSNumber else { return false }
        guard CFGetTypeID(num) != CFBooleanGetTypeID() else { return false }
        guard !CFNumberIsFloatType(num) else { return false }
        return num.int64Value == expected
    }

    @Test("M3 D-M3-7: CLI codesign --json outputs native JSON entitlement types and {} when unsigned or unentitled")
    func m3CLICodeSignJSONExportsNativeEntitlementTypesAndEmptyWhenUnsigned() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let cli = MachCLIRunner()

        // 1) Unsigned binary -> entitlements == {}
        let unsignedURL = tempDir.appendingPathComponent("unsigned.macho")
        try Self.buildSyntheticCodeSignMachO(includeSignature: false).write(to: unsignedURL)
        let unsignedRaw = try await cli.execute(arguments: ["codesign", unsignedURL.path, "--json"])
        let unsignedJSON = try #require(JSONSerialization.jsonObject(with: Data(unsignedRaw.utf8)) as? [String: Any])
        #expect(unsignedJSON["isSigned"] as? Bool == false)
        let unsignedEnt = try #require(unsignedJSON["entitlements"] as? [String: Any])
        #expect(unsignedEnt.isEmpty)

        // 2) Signed binary without entitlements -> entitlements == {}
        let unentitledURL = tempDir.appendingPathComponent("unentitled.macho")
        try Self.buildSyntheticCodeSignMachO(includeSignature: true).write(to: unentitledURL)
        let unentitledRaw = try await cli.execute(arguments: ["codesign", unentitledURL.path, "--json"])
        let unentitledJSON = try #require(JSONSerialization.jsonObject(with: Data(unentitledRaw.utf8)) as? [String: Any])
        let unentitledEnt = try #require(unentitledJSON["entitlements"] as? [String: Any])
        #expect(unentitledEnt.isEmpty)

        // 3) Signed binary with 0xFADE7171 XML slot + trailing NULs -> native Bool, Int, String, Array, Nested Dict
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.app-sandbox</key>
            <true/>
            <key>com.apple.security.cs.allow-dyld-environment-variables</key>
            <false/>
            <key>com.apple.private.amfi.version-restriction</key>
            <integer>1</integer>
            <key>com.machgraph.negative-quota</key>
            <integer>-42</integer>
            <key>com.machgraph.spaced-string</key>
            <string>  preserve leading and trailing  </string>
            <key>keychain-access-groups</key>
            <array>
                <string>com.apple.aea.cli</string>
                <string>item, with, commas</string>
                <integer>9</integer>
                <true/>
            </array>
            <key>com.apple.private.MobileContainerManager.lookup</key>
            <dict>
                <key>daemon</key>
                <array>
                    <string>com.apple.bird</string>
                </array>
                <key>enabled</key>
                <true/>
                <key>emptySub</key>
                <dict/>
            </dict>
        </dict>
        </plist>
        """
        let entitledURL = tempDir.appendingPathComponent("xml_native.macho")
        try Self.buildSyntheticCodeSignMachO(
            includeSignature: true,
            xmlPayloadBytes: Array(xml.utf8) + [0, 0]
        ).write(to: entitledURL)

        let raw = try await cli.execute(arguments: ["codesign", entitledURL.path, "--json"])
        let obj = try #require(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
        let ent = try #require(obj["entitlements"] as? [String: Any])
        #expect(ent.count == 7)
        #expect(Self.isStrictJSONBool(ent["com.apple.security.app-sandbox"], expected: true))
        #expect(Self.isStrictJSONBool(ent["com.apple.security.cs.allow-dyld-environment-variables"], expected: false))
        #expect(Self.isStrictJSONInt(ent["com.apple.private.amfi.version-restriction"], expected: 1))
        #expect(Self.isStrictJSONInt(ent["com.machgraph.negative-quota"], expected: -42))
        #expect(ent["com.machgraph.spaced-string"] as? String == "  preserve leading and trailing  ")

        let arr = try #require(ent["keychain-access-groups"] as? [Any])
        #expect(arr.count == 4)
        #expect(arr[0] as? String == "com.apple.aea.cli")
        #expect(arr[1] as? String == "item, with, commas")
        #expect(Self.isStrictJSONInt(arr[2], expected: 9))
        #expect(Self.isStrictJSONBool(arr[3], expected: true))

        let subDict = try #require(ent["com.apple.private.MobileContainerManager.lookup"] as? [String: Any])
        #expect(subDict["daemon"] as? [String] == ["com.apple.bird"])
        #expect(Self.isStrictJSONBool(subDict["enabled"], expected: true))
        #expect((subDict["emptySub"] as? [String: Any])?.isEmpty == true)
    }

    @Test("M3 D-M3-7: CLI codesign --json preserves leading-space keys and ignores DER slot when XML slot is present")
    func m3CLICodeSignJSONPreservesLeadingSpaceKeysWithoutDERDuplicateMerge() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let cli = MachCLIRunner()

        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key> com.apple.security.app-sandbox</key>
            <true/>
            <key> com.apple.private.spindump.cli</key>
            <true/>
        </dict>
        </plist>
        """
        let der = Self.m3BuildCoreEntitlementsDER([
            (" com.apple.security.app-sandbox", Self.m3DerBool(true)),
            (" com.apple.private.spindump.cli", Self.m3DerBool(true)),
            ("der.extra.must.not.merge", Self.m3DerBool(true))
        ])

        let dualSlotURL = tempDir.appendingPathComponent("wifip2pd_like.macho")
        try Self.buildSyntheticCodeSignMachO(
            includeSignature: true,
            xmlPayloadBytes: Array(xml.utf8) + [0],
            derPayloadBytes: der
        ).write(to: dualSlotURL)

        let raw = try await cli.execute(arguments: ["codesign", dualSlotURL.path, "--json"])
        let obj = try #require(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
        let ent = try #require(obj["entitlements"] as? [String: Any])
        #expect(ent.count == 2)
        #expect(Self.isStrictJSONBool(ent[" com.apple.security.app-sandbox"], expected: true))
        #expect(Self.isStrictJSONBool(ent[" com.apple.private.spindump.cli"], expected: true))
        #expect(ent["com.apple.security.app-sandbox"] == nil)
        #expect(ent["com.apple.private.spindump.cli"] == nil)
        #expect(ent["der.extra.must.not.merge"] == nil)

        // Empty XML <dict/> slot alongside non-empty DER slot (like /usr/bin/mdls) must yield {}
        let emptyXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict/>
        </plist>
        """
        let emptyDictURL = tempDir.appendingPathComponent("mdls_like_empty_xml.macho")
        try Self.buildSyntheticCodeSignMachO(
            includeSignature: true,
            xmlPayloadBytes: Array(emptyXML.utf8) + [0],
            derPayloadBytes: der
        ).write(to: emptyDictURL)

        let emptyRaw = try await cli.execute(arguments: ["codesign", emptyDictURL.path, "--json"])
        let emptyObj = try #require(JSONSerialization.jsonObject(with: Data(emptyRaw.utf8)) as? [String: Any])
        let emptyEnt = try #require(emptyObj["entitlements"] as? [String: Any])
        #expect(emptyEnt.isEmpty)
    }

    @Test("M3 D-M3-7: CLI codesign --json falls back to DER 0xFADE7172 slot with native JSON types when XML slot is absent")
    func m3CLICodeSignJSONParsesDEROnlyEntitlementsSlotWithNativeTypes() async throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let cli = MachCLIRunner()

        let der = Self.m3BuildCoreEntitlementsDER([
            ("com.apple.private.persona-mgmt", Self.m3DerBool(true)),
            ("com.apple.security.cs.disable-library-validation", Self.m3DerBool(false)),
            ("com.apple.private.amfi.version-restriction", Self.m3DerInt(1)),
            ("com.machgraph.negative-quota", Self.m3DerInt(-7)),
            (" com.machgraph.der-spaced", Self.m3DerUTF8(" value with spaces ")),
            ("keychain-access-groups", Self.m3DerSequence([Self.m3DerUTF8("com.apple.aea.cli"), Self.m3DerUTF8("com.machgraph.group")])),
            ("com.apple.private.MobileContainerManager.lookup", Self.m3DerContextDict([
                ("daemon", Self.m3DerSequence([Self.m3DerUTF8("com.apple.bird")])),
                ("appData", Self.m3DerBool(true)),
                ("empty", Self.m3DerContextDict([]))
            ]))
        ])

        let derOnlyURL = tempDir.appendingPathComponent("der_only.macho")
        try Self.buildSyntheticCodeSignMachO(
            includeSignature: true,
            xmlPayloadBytes: nil,
            derPayloadBytes: der
        ).write(to: derOnlyURL)

        let raw = try await cli.execute(arguments: ["codesign", derOnlyURL.path, "--json"])
        let obj = try #require(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
        let ent = try #require(obj["entitlements"] as? [String: Any])
        #expect(ent.count == 7)
        #expect(Self.isStrictJSONBool(ent["com.apple.private.persona-mgmt"], expected: true))
        #expect(Self.isStrictJSONBool(ent["com.apple.security.cs.disable-library-validation"], expected: false))
        #expect(Self.isStrictJSONInt(ent["com.apple.private.amfi.version-restriction"], expected: 1))
        #expect(Self.isStrictJSONInt(ent["com.machgraph.negative-quota"], expected: -7))
        #expect(ent[" com.machgraph.der-spaced"] as? String == " value with spaces ")
        #expect(ent["keychain-access-groups"] as? [String] == ["com.apple.aea.cli", "com.machgraph.group"])
        #expect(ent["daemon"] == nil)

        let nested = try #require(ent["com.apple.private.MobileContainerManager.lookup"] as? [String: Any])
        #expect(nested["daemon"] as? [String] == ["com.apple.bird"])
        #expect(Self.isStrictJSONBool(nested["appData"], expected: true))
        #expect((nested["empty"] as? [String: Any])?.isEmpty == true)
    }
}
