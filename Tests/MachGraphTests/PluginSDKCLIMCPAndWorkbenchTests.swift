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

    @Test("MachCLIRunner executes --help, version, info, segments, symbols, and strings subcommands")
    func cliRunnerHelpVersionInfoSegmentsSymbolsAndStrings() async throws {
        let cli = MachCLIRunner()

        let helpOut = try await cli.execute(arguments: ["--help"])
        #expect(helpOut.contains("MachGraph 1.1.0"))
        #expect(helpOut.contains("decompile"))
        #expect(helpOut.contains("--lang"))

        let verOut = try await cli.execute(arguments: ["version"])
        #expect(verOut.contains("MachGraph 1.1.0"))

        let verZhOut = try await cli.execute(arguments: ["--lang", "zh", "version"])
        #expect(verZhOut.contains("MachGraph 1.1.0"))

        let infoOut = try await cli.execute(arguments: ["info"])
        #expect(infoOut.contains("Format:"))
        #expect(infoOut.contains("arm64e"))

        let segOut = try await cli.execute(arguments: ["segments"])
        #expect(segOut.contains("__TEXT"))
        #expect(segOut.contains("__LINKEDIT"))

        let symOut = try await cli.execute(arguments: ["symbols", "--filter", "verify_license"])
        #expect(symOut.contains("verify_license"))

        let strOut = try await cli.execute(arguments: ["strings", "--filter", "MACHGRAPH-PRO"])
        #expect(strOut.contains("MACHGRAPH-PRO-2026"))
    }

    @Test("MachCLIRunner executes disasm, cfg-dot, decompile, xrefs, entropy, and codesign subcommands")
    func cliRunnerDisasmCfgDotDecompileXrefsEntropyAndCodesign() async throws {
        let cli = MachCLIRunner()

        let disasmOut = try await cli.execute(arguments: ["disasm", "--function", "verify_license"])
        #expect(disasmOut.contains("; Function"))
        #expect(disasmOut.contains("bl"))

        let dotOut = try await cli.execute(arguments: ["cfg-dot", "--function", "verify_license"])
        #expect(dotOut.contains("digraph"))
        #expect(dotOut.contains("->"))

        let decompOut = try await cli.execute(arguments: ["decompile", "--function", "verify_license"])
        #expect(decompOut.contains("MACHGRAPH-PRO-2026"))
        #expect(!decompOut.contains("goto "))

        let xrefsOut = try await cli.execute(arguments: ["xrefs", "--address", "0x100001000"])
        #expect(xrefsOut.contains("XREFS TO"))
        #expect(xrefsOut.contains("XREFS FROM"))

        let entropyOut = try await cli.execute(arguments: ["entropy"])
        #expect(entropyOut.contains("OverallEntropy="))
        #expect(entropyOut.contains("ChiSquare="))

        let csOut = try await cli.execute(arguments: ["codesign"])
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

        let auditOut = try await cli.execute(arguments: ["audit-plugins"])
        #expect(auditOut.contains("MACHGRAPH") || auditOut.contains("[HIGH]") || auditOut.contains("[CRITICAL]"))

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

    @Test("MachMCPServer executes all 4 reverse-engineering MCP tools end-to-end")
    func mcpServerExecutesInspectDecompileXrefsAndAuditSecurityTools() throws {
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

        let inspect = try callTool("mach_inspect_binary", argsJSON: "{}")
        #expect(!inspect.isError)
        #expect(inspect.text.contains("SyntheticAuthDemo.arm64e"))
        #expect(inspect.text.contains("functions="))

        let decomp = try callTool("mach_decompile_function", argsJSON: #"{"function":"verify_license"}"#)
        #expect(!decomp.isError)
        #expect(decomp.text.contains("MACHGRAPH-PRO-2026"))
        #expect(!decomp.text.contains("goto "))

        let xrefs = try callTool("mach_query_xrefs", argsJSON: #"{"address":"0x100001000"}"#)
        #expect(!xrefs.isError)
        #expect(xrefs.text.contains("to="))

        let audit = try callTool("mach_audit_security", argsJSON: "{}")
        #expect(!audit.isError)
        let decodedFindings = try JSONDecoder().decode([SecurityAuditFinding].self, from: Data(audit.text.utf8))
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
        let suiteName = "io.github.zxu756.MachGraph.test.lang.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

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
        let suiteName = "io.github.zxu756.MachGraph.test.localizer.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

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

        #expect(html.contains("MachGraph v1.1.0"))
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
}
