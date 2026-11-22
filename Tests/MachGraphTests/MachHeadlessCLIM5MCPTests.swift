import Foundation
import MachCFGEngine
import MachGraphModels
@testable import MachHeadlessCLI
import Testing

@Suite("MachGraph M5 MCP Tools & CLI Shared Functions")
struct MachHeadlessCLIM5MCPTests {

    private func makeTempDir() throws -> URL {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("machgraph-m5-mcp-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    private func callMCPTool(
        on server: MachMCPServer,
        id: Int = 1,
        name: String,
        arguments: [String: Any]
    ) throws -> (isError: Bool, text: String) {
        let reqObj: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": [
                "name": name,
                "arguments": arguments
            ]
        ]
        let reqData = try JSONSerialization.data(withJSONObject: reqObj, options: [.sortedKeys])
        let reqLine = String(decoding: reqData, as: UTF8.self)
        let respLine = try #require(server.handleJSONRPCLine(reqLine))
        let respObj = try #require(JSONSerialization.jsonObject(with: Data(respLine.utf8)) as? [String: Any])
        let result = try #require(respObj["result"] as? [String: Any])
        let isError = try #require(result["isError"] as? Bool)
        let content = try #require(result["content"] as? [[String: Any]])
        let first = try #require(content.first)
        #expect(first["type"] as? String == "text")
        let text = try #require(first["text"] as? String)
        return (isError, text)
    }

    @Test("tools/list exposes exact 8 tools with complete inputSchema and bilingual unverified descriptions")
    func toolsListExposesEightToolsWithCompleteSchemas() throws {
        for lang in [MachLanguage.en, MachLanguage.zhHans] {
            let server = MachMCPServer(language: lang)
            let respLine = try #require(server.handleJSONRPCLine(#"{"jsonrpc":"2.0","id":10,"method":"tools/list"}"#))
            let respObj = try #require(JSONSerialization.jsonObject(with: Data(respLine.utf8)) as? [String: Any])
            let result = try #require(respObj["result"] as? [String: Any])
            let tools = try #require(result["tools"] as? [[String: Any]])
            #expect(tools.count == 8)

            let names = tools.compactMap { $0["name"] as? String }
            #expect(Set(names) == [
                "mach_inspect_binary",
                "mach_decompile_function",
                "mach_query_xrefs",
                "mach_audit_security",
                "mach_disasm_function",
                "mach_list_symbols",
                "mach_cfg",
                "mach_find_strings"
            ])

            for tool in tools {
                let tName = try #require(tool["name"] as? String)
                let desc = try #require(tool["description"] as? String)
                #expect(!desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                if tName == "mach_decompile_function" || tName == "mach_audit_security" {
                    if lang == .en {
                        #expect(desc.uppercased().contains("EXPERIMENTAL"))
                        #expect(desc.uppercased().contains("UNVERIFIED"))
                    } else {
                        #expect(desc.contains("实验性"))
                        #expect(desc.contains("未通过验收"))
                    }
                }

                let schema = try #require(tool["inputSchema"] as? [String: Any])
                #expect(schema["type"] as? String == "object")
                let props = try #require(schema["properties"] as? [String: [String: Any]])
                let reqs = try #require(schema["required"] as? [String])
                #expect(reqs.contains("binaryPath"))
                for (propName, propSpec) in props {
                    let pType = try #require(propSpec["type"] as? String, "Missing type on \(tName).\(propName)")
                    #expect(["string", "integer", "boolean", "number"].contains(pType))
                    let pDesc = try #require(propSpec["description"] as? String, "Missing description on \(tName).\(propName)")
                    #expect(!pDesc.isEmpty)
                }
            }
        }
    }

    @Test("Four new MCP tools match CLI --json output byte-for-byte including trailing newline")
    func fourNewToolsMatchCLIJSONByteForByte() async throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let binURL = tempDir.appendingPathComponent("m5_sample.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: binURL)

        let cli = MachCLIRunner()
        let mcp = MachMCPServer(language: .en)

        func cliStdout(_ args: [String]) async throws -> String {
            let out = try await cli.execute(arguments: args)
            return out.hasSuffix("\n") ? out : (out + "\n")
        }

        // 1. mach_list_symbols (all + filter)
        let symAllMCP = try callMCPTool(on: mcp, name: "mach_list_symbols", arguments: ["binaryPath": binURL.path])
        #expect(!symAllMCP.isError)
        let symAllCLI = try await cliStdout(["symbols", binURL.path, "--json"])
        #expect(symAllMCP.text == symAllCLI)

        let symFiltMCP = try callMCPTool(on: mcp, name: "mach_list_symbols", arguments: ["binaryPath": binURL.path, "filter": "verify"])
        #expect(!symFiltMCP.isError)
        let symFiltCLI = try await cliStdout(["symbols", binURL.path, "--filter", "verify", "--json"])
        #expect(symFiltMCP.text == symFiltCLI)

        // 2. mach_find_strings (all + filter)
        let strAllMCP = try callMCPTool(on: mcp, name: "mach_find_strings", arguments: ["binaryPath": binURL.path])
        #expect(!strAllMCP.isError)
        let strAllCLI = try await cliStdout(["strings", binURL.path, "--json"])
        #expect(strAllMCP.text == strAllCLI)

        let strFiltMCP = try callMCPTool(on: mcp, name: "mach_find_strings", arguments: ["binaryPath": binURL.path, "filter": "MACHGRAPH"])
        #expect(!strFiltMCP.isError)
        let strFiltCLI = try await cliStdout(["strings", binURL.path, "--filter", "MACHGRAPH", "--json"])
        #expect(strFiltMCP.text == strFiltCLI)

        // 3. mach_disasm_function (symbol, address, count)
        let disSymMCP = try callMCPTool(on: mcp, name: "mach_disasm_function", arguments: ["binaryPath": binURL.path, "symbol": "_verify_license"])
        #expect(!disSymMCP.isError)
        let disSymCLI = try await cliStdout(["disasm", binURL.path, "--symbol", "_verify_license", "--json"])
        #expect(disSymMCP.text == disSymCLI)

        let parsedDis = try #require(JSONSerialization.jsonObject(with: Data(disSymMCP.text.utf8)) as? [String: Any])
        let verifyHex = try #require(parsedDis["addressHex"] as? String)

        let disAddrCountMCP = try callMCPTool(
            on: mcp,
            name: "mach_disasm_function",
            arguments: ["binaryPath": binURL.path, "address": verifyHex, "count": 5]
        )
        #expect(!disAddrCountMCP.isError)
        let disAddrCountCLI = try await cliStdout(["disasm", binURL.path, "--address", verifyHex, "--count", "5", "--json"])
        #expect(disAddrCountMCP.text == disAddrCountCLI)

        // 4. mach_cfg (symbol & address)
        let cfgSymMCP = try callMCPTool(on: mcp, name: "mach_cfg", arguments: ["binaryPath": binURL.path, "symbol": "_dispatch_command"])
        #expect(!cfgSymMCP.isError)
        let cfgSymCLI = try await cliStdout(["cfg", binURL.path, "--symbol", "_dispatch_command", "--json"])
        #expect(cfgSymMCP.text == cfgSymCLI)

        let cfgAddrMCP = try callMCPTool(on: mcp, name: "mach_cfg", arguments: ["binaryPath": binURL.path, "address": verifyHex])
        #expect(!cfgAddrMCP.isError)
        let cfgAddrCLI = try await cliStdout(["cfg", binURL.path, "--address", verifyHex, "--json"])
        #expect(cfgAddrMCP.text == cfgAddrCLI)
    }

    @Test("mach_cfg requires symbol or address and rejects missing/conflicting/invalid selectors with isError: true")
    func machCFGRequiresTargetSelectorAndRejectsInvalidInputs() throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let binURL = tempDir.appendingPathComponent("m5_cfg_err.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: binURL)

        let mcp = MachMCPServer(language: .en)

        let noSelector = try callMCPTool(on: mcp, name: "mach_cfg", arguments: ["binaryPath": binURL.path])
        #expect(noSelector.isError)
        #expect(!noSelector.text.isEmpty)
        #expect(noSelector.text.contains("symbol") && noSelector.text.contains("address"))

        let bothSelectors = try callMCPTool(
            on: mcp,
            name: "mach_cfg",
            arguments: ["binaryPath": binURL.path, "symbol": "_main", "address": "0x100001000"]
        )
        #expect(bothSelectors.isError)
        #expect(!bothSelectors.text.isEmpty)

        let badAddr = try callMCPTool(on: mcp, name: "mach_cfg", arguments: ["binaryPath": binURL.path, "address": "0xZZZ"])
        #expect(badAddr.isError)
        #expect(!badAddr.text.isEmpty)

        let unknownNoBin = try callMCPTool(on: mcp, name: "mach_nonexistent_tool", arguments: [:])
        #expect(unknownNoBin.isError)
        #expect(unknownNoBin.text.contains("Unknown tool"))
    }

    @Test("mach_query_xrefs emits both incoming (<-) and outgoing (->) cross-references")
    func machQueryXrefsEmitsBothIncomingAndOutgoing() throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let binURL = tempDir.appendingPathComponent("m5_xrefs.arm64e")
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        try data.write(to: binURL)

        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: data, filePath: binURL.path, fileName: binURL.lastPathComponent)
        let mcp = MachMCPServer(language: .en)

        // Find an instruction address with outgoing xrefs (e.g. a `bl` call site)
        let outgoingRec = try #require(index.crossReferences.allRecords.first { $0.kind.rawValue == "CALL" })
        let outRes = try callMCPTool(
            on: mcp,
            name: "mach_query_xrefs",
            arguments: ["binaryPath": binURL.path, "address": outgoingRec.fromAddress.hexString]
        )
        #expect(!outRes.isError)
        #expect(outRes.text.contains("-> \(outgoingRec.toAddress.hexString)"))

        // Also test demo binary or any address that has incoming xrefs
        let incomingRec = try #require(index.crossReferences.allRecords.first {
            !index.crossReferences.xrefsTo(address: $0.toAddress).isEmpty
        })
        let inRes = try callMCPTool(
            on: mcp,
            name: "mach_query_xrefs",
            arguments: ["binaryPath": binURL.path, "address": incomingRec.toAddress.hexString]
        )
        #expect(!inRes.isError)
        #expect(inRes.text.contains("<- \(incomingRec.fromAddress.hexString)"))

        // If any address in demo_arm64_sample or synthetic fixture has BOTH incoming and outgoing, verify both appear together
        let demoURL = try MachCLIRunner.locateDemoBinaryURL(language: .en)
        let demoData = try Data(contentsOf: demoURL)
        let demoIdx = try BinaryAnalysisCoordinator().analyzeBinary(data: demoData, filePath: demoURL.path, fileName: demoURL.lastPathComponent)
        let candidateAddrs = Set(demoIdx.crossReferences.allRecords.map(\.fromAddress))
            .intersection(Set(demoIdx.crossReferences.allRecords.map(\.toAddress)))
        if let biAddr = candidateAddrs.sorted().first {
            let biRes = try callMCPTool(
                on: mcp,
                name: "mach_query_xrefs",
                arguments: ["binaryPath": demoURL.path, "address": biAddr.hexString]
            )
            #expect(!biRes.isError)
            #expect(biRes.text.contains("\n<- "))
            #expect(biRes.text.contains("\n-> "))
        }
    }

    @Test("mach_decompile_function and mach_audit_security emit EN and ZH experimental+unverified line-1 banners")
    func unverifiedToolsEmitBilingualBannersAndSharedAuditFormat() async throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let binURL = tempDir.appendingPathComponent("m5_banners.arm64e")
        try SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true).write(to: binURL)

        let cli = MachCLIRunner()
        let mcpEN = MachMCPServer(language: .en)
        let mcpZH = MachMCPServer(language: .zhHans)

        let decompEN = try callMCPTool(on: mcpEN, name: "mach_decompile_function", arguments: ["binaryPath": binURL.path, "function": "_verify_license"])
        #expect(!decompEN.isError)
        let decompENLine1 = String(decompEN.text.split(separator: "\n", omittingEmptySubsequences: false).first ?? "")
        #expect(decompENLine1.contains("EXPERIMENTAL") && decompENLine1.contains("UNVERIFIED"))

        let decompZH = try callMCPTool(on: mcpZH, name: "mach_decompile_function", arguments: ["binaryPath": binURL.path, "function": "_verify_license"])
        #expect(!decompZH.isError)
        let decompZHLine1 = String(decompZH.text.split(separator: "\n", omittingEmptySubsequences: false).first ?? "")
        #expect(decompZHLine1.contains("实验性") && decompZHLine1.contains("未通过验收"))

        let auditEN = try callMCPTool(on: mcpEN, name: "mach_audit_security", arguments: ["binaryPath": binURL.path])
        #expect(!auditEN.isError)
        let auditENLine1 = String(auditEN.text.split(separator: "\n", omittingEmptySubsequences: false).first ?? "")
        #expect(auditENLine1.contains("EXPERIMENTAL") && auditENLine1.contains("UNVERIFIED"))
        let cliAuditEN = try await cli.execute(arguments: ["audit-plugins", binURL.path, "--lang", "en"])
        #expect(auditEN.text == cliAuditEN)

        let auditZH = try callMCPTool(on: mcpZH, name: "mach_audit_security", arguments: ["binaryPath": binURL.path])
        #expect(!auditZH.isError)
        let auditZHLine1 = String(auditZH.text.split(separator: "\n", omittingEmptySubsequences: false).first ?? "")
        #expect(auditZHLine1.contains("实验性") && auditZHLine1.contains("未通过验收"))
        let cliAuditZH = try await cli.execute(arguments: ["audit-plugins", binURL.path, "--lang", "zh"])
        #expect(auditZH.text == cliAuditZH)
    }
}
