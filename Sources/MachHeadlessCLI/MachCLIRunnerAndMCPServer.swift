import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachMicroDecompiler
import MachPatchAndHexEngine
import MachPluginSDK
import MachProjectStore

// MARK: - 15-Subcommand Headless Binary Reverse-Engineering CLI (`MachCLIRunner`)

public struct MachCLIRunner: Sendable {
    public init() {}

    public func execute(arguments: [String]) async throws -> String {
        if let cliLang = MachLanguage.extractCLIArgumentLanguage(from: arguments) {
            await MainActor.run {
                MachLocalizer.shared.setLanguage(cliLang, persist: false)
            }
        }
        let cleanedArgs = Self.stripLanguageFlags(arguments)
        guard let subcommand = cleanedArgs.first else {
            return Self.helpBanner
        }
        let rest = Array(cleanedArgs.dropFirst())

        switch subcommand {
        case "help", "--help", "-h":
            return Self.helpBanner

        case "version", "--version":
            return "MachGraph 1.1.0 (macOS arm64 · Zero-Wrapper Mach-O/ELF/PE/WASM Loader + ARM64 CFG + SSA Pseudo-C Decompiler · 中文/EN)"

        case "info":
            let loaded = try loadAndAnalyze(args: rest)
            let img = loaded.index.image
            var lines: [String] = []
            lines.append("File:          \(img.fileName) (\(img.fileSize) bytes)")
            lines.append("SHA-256:       \(img.sha256Hex)")
            lines.append("Format:        \(img.containerFormat.rawValue)")
            lines.append("Architecture:  \(img.architecture.displayName) (PIE=\(img.isPositionIndependent))")
            lines.append("Image Base:    \(img.imageBase.hexString)")
            lines.append("Entry Point:   \(img.entryPoint?.hexString ?? "none")")
            lines.append("Functions:     \(loaded.index.functions.count)")
            lines.append("Instructions:  \(loaded.index.decodedInstructions.count)")
            lines.append("Xrefs:         \(loaded.index.crossReferences.allRecords.count)")
            lines.append("CodeSign:      signed=\(img.codeSignature.isSigned) adhoc=\(img.codeSignature.isAdHoc) cdhash=\(img.codeSignature.cdHashHex)")
            return lines.joined(separator: "\n")

        case "segments":
            let loaded = try loadAndAnalyze(args: rest)
            return loaded.index.image.segments.map { seg in
                String(
                    format: "%-16@ vm=%@ size=0x%llx off=0x%llx prot=%@/%@ sections=%d",
                    seg.name as NSString,
                    seg.vmAddress.hexString as NSString,
                    seg.vmSize,
                    seg.fileOffset.rawValue,
                    seg.initialProtection.rwxString as NSString,
                    seg.maxProtection.rwxString as NSString,
                    seg.sections.count
                )
            }.joined(separator: "\n")

        case "symbols":
            let loaded = try loadAndAnalyze(args: rest)
            let filter = optionValue("--filter", in: rest)?.lowercased()
            let syms = loaded.index.image.symbols.filter { sym in
                guard let q = filter, !q.isEmpty else { return true }
                return sym.name.lowercased().contains(q) || sym.demangledName.lowercased().contains(q)
            }
            return syms.map { sym in
                "\(sym.address.hexString) [\(sym.kind.rawValue)] \(sym.demangledName)"
            }.joined(separator: "\n")

        case "strings":
            let loaded = try loadAndAnalyze(args: rest)
            let filter = optionValue("--filter", in: rest)?.lowercased()
            let strs = loaded.index.image.strings.filter { lit in
                guard let q = filter, !q.isEmpty else { return true }
                return lit.value.lowercased().contains(q)
            }
            return strs.map { lit in
                "\(lit.address.hexString) (\(lit.sectionName)): \(lit.value)"
            }.joined(separator: "\n")

        case "disasm":
            let loaded = try loadAndAnalyze(args: rest)
            let targetFn = selectFunction(in: loaded.index, args: rest)
            guard let fn = targetFn else {
                return loaded.index.decodedInstructions.prefix(64).map { insn in
                    "\(insn.address.hexString)  \(insn.rawBytesHex)  \(insn.formattedDisassembly)"
                }.joined(separator: "\n")
            }
            var out: [String] = ["; Function \(fn.demangledName) @ \(fn.address.hexString)"]
            for block in fn.blocks {
                out.append("\(block.label):")
                for insn in block.instructions {
                    let commentSuffix = insn.autoComment.map { " ; \($0)" } ?? ""
                    out.append("  \(insn.address.hexString)  \(insn.rawBytesHex)  \(insn.formattedDisassembly)\(commentSuffix)")
                }
            }
            return out.joined(separator: "\n")

        case "cfg-dot":
            let loaded = try loadAndAnalyze(args: rest)
            guard let fn = selectFunction(in: loaded.index, args: rest) ?? loaded.index.functions.first else {
                throw MachGraphError.cfgAnalysisError("No functions recovered to export DOT graph.")
            }
            return exportFunctionDOT(fn)

        case "decompile":
            let loaded = try loadAndAnalyze(args: rest)
            let engine = MachMicroDecompilerEngine()
            if let fn = selectFunction(in: loaded.index, args: rest) {
                return engine.decompile(function: fn, in: loaded.index).fullSourceText
            }
            let outputs = engine.decompileAllFunctions(in: loaded.index, includeThunks: false)
            return outputs.map(\.fullSourceText).joined(separator: "\n\n")

        case "xrefs":
            let loaded = try loadAndAnalyze(args: rest)
            let addrRaw = optionValue("--address", in: rest) ?? loaded.index.functions.first?.address.hexString ?? "0x0"
            let targetAddr = parseHexOrDec(addrRaw)
            let incoming = loaded.index.crossReferences.xrefsTo(address: targetAddr)
            let outgoing = loaded.index.crossReferences.xrefsFrom(address: targetAddr)
            var lines: [String] = ["XREFS TO \(targetAddr.hexString) (\(incoming.count)):"]
            for rec in incoming {
                lines.append("  <- \(rec.fromAddress.hexString) [\(rec.kind.rawValue)] \(rec.instructionPreview)")
            }
            lines.append("XREFS FROM \(targetAddr.hexString) (\(outgoing.count)):")
            for rec in outgoing {
                lines.append("  -> \(rec.toAddress.hexString) [\(rec.kind.rawValue)] \(rec.instructionPreview)")
            }
            return lines.joined(separator: "\n")

        case "entropy":
            let loaded = try loadAndAnalyze(args: rest)
            let report = SlidingWindowEntropyProfiler().analyzeFullProfile(
                data: loaded.data,
                image: loaded.index.image,
                windowSize: 1024,
                stepSize: 512
            )
            return String(
                format: "OverallEntropy=%.4f bits/byte | ChiSquare=%.2f | ZeroRatio=%.3f | Anomalies=%d | Samples=%d",
                report.overallMetrics.shannonEntropyBits,
                report.overallMetrics.byteChiSquare,
                report.overallMetrics.zeroByteRatio,
                report.anomalies.count,
                report.samples.count
            )

        case "codesign":
            let loaded = try loadAndAnalyze(args: rest)
            let cs = loaded.index.image.codeSignature
            let verification = try? MachOAdHocReSigner().verifyCodeSignature(in: loaded.data, sliceIndex: loaded.index.image.selectedSliceIndex)
            return "Signed=\(cs.isSigned) AdHoc=\(cs.isAdHoc) Identifier=\(cs.identifier) CDHash=\(cs.cdHashHex) Hash=\(cs.hashAlgorithm) Verified=\(verification?.isValid ?? false) Entitlements=\(cs.entitlementsPairs.count)"

        case "patch-asm":
            let loaded = try loadAndAnalyze(args: rest)
            guard let addrText = optionValue("--address", in: rest),
                  let asmText = optionValue("--asm", in: rest) else {
                throw MachGraphError.patchFormatError("Usage: machgraph patch-asm [--binary <path>] --address <0x...> --asm \"mov w0, #1; ret\" [--output <out>]")
            }
            let vmAddr = parseHexOrDec(addrText)
            guard let fileOff = loaded.index.image.fileOffset(for: vmAddr) else {
                throw MachGraphError.patchFormatError("Virtual address \(vmAddr.hexString) is not backed by file bytes.")
            }
            let baseOverlay = try SparseCoWByteOverlayBuffer(baseData: loaded.data, image: loaded.index.image)
            let patchRecord = try InlineARM64InstructionPatcher().patchInstruction(
                at: fileOff,
                virtualAddress: vmAddr,
                withAssembly: asmText,
                in: baseOverlay,
                image: loaded.index.image,
                allowClobberingBranchTargets: rest.contains("--force")
            )
            let reSigned = try MachOAdHocReSigner().reSignMachO(
                binaryData: loaded.data,
                patches: [patchRecord],
                sliceIndex: loaded.index.image.selectedSliceIndex
            )
            if let outPath = optionValue("--output", in: rest) {
                try reSigned.signedBinaryData.write(to: URL(fileURLWithPath: outPath), options: .atomic)
            }
            return "Patched \(vmAddr.hexString) (\(patchRecord.originalAssembly ?? "bytes") -> \(patchRecord.patchedAssembly ?? asmText)) | NewCDHash=\(reSigned.updatedCDHashHex) | Valid=\(reSigned.verificationReport.isValid)"

        case "resign":
            let loaded = try loadAndAnalyze(args: rest)
            let reSigned = try MachOAdHocReSigner().reSignMachO(
                binaryData: loaded.data,
                sliceIndex: loaded.index.image.selectedSliceIndex,
                identifier: optionValue("--identifier", in: rest)
            )
            if let outPath = optionValue("--output", in: rest) {
                try reSigned.signedBinaryData.write(to: URL(fileURLWithPath: outPath), options: .atomic)
            }
            return "Ad-hoc re-signed \(loaded.index.image.fileName) | CDHash=\(reSigned.updatedCDHashHex) | Valid=\(reSigned.verificationReport.isValid)"

        case "audit-plugins":
            let loaded = try loadAndAnalyze(args: rest)
            let report = try MachPluginRunner().runSuite(
                against: loaded.index,
                binaryData: loaded.data,
                continueOnError: true
            )
            if report.findings.isEmpty {
                return "0 security findings across \(report.results.count) plugins."
            }
            return report.findings.map { f in
                "[\(f.severity.rawValue)] \(f.address?.hexString ?? "image") (\(f.pluginID)) \(f.title) - \(f.detail)"
            }.joined(separator: "\n")

        case "export-html":
            let outPath = optionValue("--output", in: rest) ?? (rest.first { !$0.hasPrefix("--") } ?? "machgraph-triage.html")
            let loaded = try loadAndAnalyze(args: rest)
            let html = try ColdTungstenHTMLReportExporter().exportHTMLReport(
                analysisIndex: loaded.index,
                binaryData: loaded.data
            )
            try html.write(toFile: outPath, atomically: true, encoding: .utf8)
            return "Exported Cold-Tungsten HTML triage dossier to \(outPath)"

        case "mcp":
            let defaultBinary = optionValue("--binary", in: rest)
            let server = MachMCPServer(defaultBinaryPath: defaultBinary)
            await server.serveStdio()
            return ""

        default:
            throw MachGraphError.ioFailure("Unknown subcommand '\(subcommand)'. Run 'MachGraph --help'.")
        }
    }

    // MARK: - Helpers

    private func loadAndAnalyze(args: [String]) throws -> (data: Data, index: BinaryAnalysisIndex) {
        let coordinator = BinaryAnalysisCoordinator()
        if let path = optionValue("--binary", in: args) {
            let url = URL(fileURLWithPath: path)
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw MachGraphError.fileNotFound(path)
            }
            let data = try Data(contentsOf: url)
            let idx = try coordinator.analyzeBinary(
                data: data,
                filePath: url.path,
                fileName: url.lastPathComponent
            )
            return (data, idx)
        }
        let usePAC = !args.contains("--no-pac")
        let synthetic = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: usePAC)
        let idx = try coordinator.analyzeBinary(
            data: synthetic,
            filePath: "<synthetic-arm64e>",
            fileName: usePAC ? "SyntheticAuthDemo.arm64e" : "SyntheticAuthDemo.arm64"
        )
        return (synthetic, idx)
    }

    private func selectFunction(in index: BinaryAnalysisIndex, args: [String]) -> RecoveredFunction? {
        if let addrRaw = optionValue("--address", in: args) {
            let addr = parseHexOrDec(addrRaw)
            if let exact = index.functions.first(where: { $0.address == addr }) {
                return exact
            }
            return index.functions.first(where: { addr >= $0.address && addr < $0.endAddress })
        }
        if let fnName = optionValue("--function", in: args)?.lowercased() {
            return index.functions.first {
                $0.name.lowercased().contains(fnName) || $0.demangledName.lowercased().contains(fnName)
            }
        }
        return nil
    }

    private func exportFunctionDOT(_ fn: RecoveredFunction) -> String {
        var lines: [String] = [
            "digraph \"\(fn.demangledName)\" {",
            "  rankdir=TB;",
            "  node [shape=box, fontname=\"Menlo\", fontsize=10];"
        ]
        for block in fn.blocks {
            let body = block.instructions.map { "\($0.address.hexString): \($0.formattedDisassembly)" }.joined(separator: "\\l") + "\\l"
            let escaped = body.replacingOccurrences(of: "\"", with: "\\\"")
            lines.append("  b\(block.id) [label=\"\(block.label)\\l\(escaped)\"];")
        }
        for edge in fn.edges {
            let color: String
            switch edge.kind {
            case .conditionalTrue: color = "#3FB950"
            case .conditionalFalse: color = "#F85149"
            case .switchCase: color = "#D29922"
            case .unconditional, .fallthroughEdge: color = edge.isBackEdge ? "#FFA657" : "#58A6FF"
            }
            let labelAttr = edge.kind.displayLabel.map { ", label=\"\($0)\"" } ?? ""
            lines.append("  b\(edge.sourceBlockID) -> b\(edge.targetBlockID) [color=\"\(color)\"\(labelAttr)];")
        }
        lines.append("}")
        return lines.joined(separator: "\n")
    }

    private func parseHexOrDec(_ raw: String) -> VirtualAddress {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("0x") {
            let hex = String(trimmed.dropFirst(2))
            return VirtualAddress(UInt64(hex, radix: 16) ?? 0)
        }
        return VirtualAddress(UInt64(trimmed) ?? 0)
    }

    private func optionValue(_ flag: String, in args: [String]) -> String? {
        guard let idx = args.firstIndex(of: flag), idx + 1 < args.count else { return nil }
        return args[idx + 1]
    }

    public static func stripLanguageFlags(_ args: [String]) -> [String] {
        var result: [String] = []
        var idx = 0
        while idx < args.count {
            let tok = args[idx]
            if tok == "--lang" || tok == "--language" {
                idx += 2
                continue
            }
            if tok.hasPrefix("--lang=") || tok.hasPrefix("--language=") {
                idx += 1
                continue
            }
            result.append(tok)
            idx += 1
        }
        return result
    }

    public static let helpBanner = """
    MachGraph 1.1.0 - Native macOS Binary Reverse-Engineering, ARM64 CFG & SSA Decompiler IDE (中文 / EN)
    Global Options:
      --lang <zh|en>                                      Set workbench or screenshot language (env: MACHGRAPH_LANG=zh|en)
    Subcommands:
      info [--binary <path>]                              Inspect container format, arch, segments, Xrefs & CDHash
      segments [--binary <path>]                          List mapped VM segments & RWX protections
      symbols [--binary <path>] [--filter <q>]            List demangled Swift / C++ / ObjC symbols
      strings [--binary <path>] [--filter <q>]            List extracted UTF-8 / UTF-16 string literals
      disasm [--binary <path>] [--function <name>]        Disassemble recovered basic blocks with A64 idioms
      cfg-dot [--binary <path>] [--function <name>]       Export Graphviz DOT control-flow graph
      decompile [--binary <path>] [--function <name>]     Lift ARM64/ARM64e SSA Micro-IR to structured Pseudo-C
      xrefs [--binary <path>] [--address <0x...>]         Query incoming & outgoing cross-references
      entropy [--binary <path>]                           Compute sliding-window Shannon entropy & chi-square metrics
      codesign [--binary <path>]                          Verify Mach-O SuperBlob, CodeDirectory SHA-256 & entitlements
      patch-asm --address <0x...> --asm "..." [--output]  Assemble inline ARM64 patch & ad-hoc re-sign
      resign [--binary <path>] [--output <out>]           Recalculate Mach-O SHA-256 CodeDirectory page hashes
      audit-plugins [--binary <path>]                     Execute JavaScriptCore binary security audit plugins
      export-html <out.html> [--binary <path>]            Export Hallmark Cold-Tungsten bilingual HTML triage dossier
      mcp [--binary <path>]                               Start JSON-RPC 2.0 reverse-engineering MCP server on stdio
      --export-screenshots <output-dir> [--lang zh|en]    Render 2x Retina Cold-Tungsten workbench screenshots
    """
}

// MARK: - JSON-RPC 2.0 Reverse-Engineering MCP Server (`MachMCPServer`)

public struct MachMCPServer: Sendable {
    public let defaultBinaryPath: String?

    public init(defaultBinaryPath: String? = nil) {
        self.defaultBinaryPath = defaultBinaryPath
    }

    public static var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "mach_inspect_binary",
                "description": "Load a Mach-O / Universal / ELF / PE / WASM binary (or built-in ARM64e fixture) and return architecture, segment, function, Xref, and CodeSignature summary.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string", "description": "Optional path to binary on disk."]
                    ]
                ]
            ],
            [
                "name": "mach_decompile_function",
                "description": "Lift a recovered ARM64/ARM64e function via Cytron SSA Micro-IR into structured Pseudo-C with zero gotos.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string"],
                        "function": ["type": "string", "description": "Function name substring or hex address (e.g. verify_license or 0x100001028)."]
                    ],
                    "required": ["function"]
                ]
            ],
            [
                "name": "mach_query_xrefs",
                "description": "Query incoming and outgoing code/string/pointer cross-references for a virtual address.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string"],
                        "address": ["type": "string", "description": "Hex virtual address (e.g. 0x100001028)."]
                    ],
                    "required": ["address"]
                ]
            ],
            [
                "name": "mach_audit_security",
                "description": "Execute all 4 sandboxed JavaScriptCore binary security plugins (secret xref scanner, dangerous sink reachability, ARM64e PAC auditor, entitlement auditor).",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string"]
                    ]
                ]
            ]
        ]
    }

    public func serveStdio() async {
        while let line = readLine(strippingNewline: true) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty { continue }
            if let response = handleJSONRPCLine(trimmed) {
                print(response)
                fflush(stdout)
            }
        }
    }

    public func handleJSONRPCLine(_ rawLine: String) -> String? {
        guard let data = rawLine.data(using: .utf8),
              let req = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return encodeJSON([
                "jsonrpc": "2.0",
                "id": NSNull(),
                "error": ["code": -32700, "message": "Invalid JSON payload"]
            ])
        }

        let method = (req["method"] as? String) ?? ""
        if method.hasPrefix("notifications/") {
            return nil
        }
        let reqID: Any = req["id"] ?? NSNull()
        let params = (req["params"] as? [String: Any]) ?? [:]

        switch method {
        case "initialize":
            return encodeJSON([
                "jsonrpc": "2.0",
                "id": reqID,
                "result": [
                    "protocolVersion": "2024-11-05",
                    "capabilities": ["tools": ["listChanged": false]],
                    "serverInfo": ["name": "machgraph-mcp", "version": "1.1.0"]
                ]
            ])

        case "tools/list":
            return encodeJSON([
                "jsonrpc": "2.0",
                "id": reqID,
                "result": ["tools": Self.toolDefinitions]
            ])

        case "tools/call":
            let toolName = (params["name"] as? String) ?? ""
            let args = (params["arguments"] as? [String: Any]) ?? [:]
            let resultObj = dispatchTool(name: toolName, arguments: args)
            return encodeJSON([
                "jsonrpc": "2.0",
                "id": reqID,
                "result": resultObj
            ])

        default:
            return encodeJSON([
                "jsonrpc": "2.0",
                "id": reqID,
                "error": ["code": -32601, "message": "Method '\(method)' not found"]
            ])
        }
    }

    private func dispatchTool(name: String, arguments: [String: Any]) -> [String: Any] {
        do {
            let loaded = try resolveBinary(from: arguments)
            switch name {
            case "mach_inspect_binary":
                let img = loaded.index.image
                let summary = "file=\(img.fileName) format=\(img.containerFormat.rawValue) arch=\(img.architecture.displayName) functions=\(loaded.index.functions.count) insns=\(loaded.index.decodedInstructions.count) xrefs=\(loaded.index.crossReferences.allRecords.count) cdhash=\(img.codeSignature.cdHashHex)"
                return textResult(summary, isError: false)

            case "mach_decompile_function":
                let query = (arguments["function"] as? String) ?? ""
                let target: RecoveredFunction?
                if query.lowercased().hasPrefix("0x"),
                   let raw = UInt64(query.dropFirst(2), radix: 16) {
                    let addr = VirtualAddress(raw)
                    target = loaded.index.functions.first { $0.address == addr || (addr >= $0.address && addr < $0.endAddress) }
                } else {
                    target = loaded.index.functions.first {
                        $0.name.lowercased().contains(query.lowercased())
                            || $0.demangledName.lowercased().contains(query.lowercased())
                    }
                }
                guard let fn = target else {
                    return textResult("Function '\(query)' not found in image.", isError: true)
                }
                let output = MachMicroDecompilerEngine().decompile(function: fn, in: loaded.index)
                return textResult(output.fullSourceText, isError: false)

            case "mach_query_xrefs":
                let rawAddr = (arguments["address"] as? String) ?? "0x0"
                let clean = rawAddr.lowercased().hasPrefix("0x") ? String(rawAddr.dropFirst(2)) : rawAddr
                let addr = VirtualAddress(UInt64(clean, radix: 16) ?? 0)
                let toList = loaded.index.crossReferences.xrefsTo(address: addr)
                let fromList = loaded.index.crossReferences.xrefsFrom(address: addr)
                let text = "to=\(toList.count) from=\(fromList.count)\n" +
                    toList.map { "<- \($0.fromAddress.hexString) [\($0.kind.rawValue)] \($0.instructionPreview)" }.joined(separator: "\n")
                return textResult(text, isError: false)

            case "mach_audit_security":
                let suite = try MachPluginRunner().runSuite(
                    against: loaded.index,
                    binaryData: loaded.data,
                    continueOnError: true
                )
                let data = try JSONEncoder().encode(suite.findings)
                return textResult(String(decoding: data, as: UTF8.self), isError: false)

            default:
                return textResult("Unknown tool '\(name)'", isError: true)
            }
        } catch {
            return textResult(error.localizedDescription, isError: true)
        }
    }

    private func resolveBinary(from arguments: [String: Any]) throws -> (data: Data, index: BinaryAnalysisIndex) {
        let coordinator = BinaryAnalysisCoordinator()
        if let path = (arguments["binaryPath"] as? String) ?? defaultBinaryPath, !path.isEmpty {
            let url = URL(fileURLWithPath: path)
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw MachGraphError.fileNotFound(path)
            }
            let data = try Data(contentsOf: url)
            let idx = try coordinator.analyzeBinary(data: data, filePath: url.path, fileName: url.lastPathComponent)
            return (data, idx)
        }
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let idx = try coordinator.analyzeBinary(data: data, filePath: "<synthetic-arm64e>", fileName: "SyntheticAuthDemo.arm64e")
        return (data, idx)
    }

    private func textResult(_ text: String, isError: Bool) -> [String: Any] {
        [
            "isError": isError,
            "content": [
                ["type": "text", "text": text]
            ]
        ]
    }

    private func encodeJSON(_ dict: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]),
              let str = String(data: data, encoding: .utf8) else {
            return #"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Serialization error"}}"#
        }
        return str
    }
}
