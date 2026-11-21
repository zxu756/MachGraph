import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachMicroDecompiler
import MachPatchAndHexEngine
import MachPluginSDK
import MachProjectStore

// MARK: - Canonical Single-Source CLI Subcommand Specification (`CLISubcommandSpec`)

public struct CLISubcommandSpec: Sendable, Hashable {
    public let primaryName: String
    public let aliases: [String]
    public let usageArgsEN: String
    public let usageArgsZH: String
    public let summaryEN: String
    public let summaryZH: String

    public init(
        primaryName: String,
        aliases: [String] = [],
        usageArgsEN: String,
        usageArgsZH: String,
        summaryEN: String,
        summaryZH: String
    ) {
        self.primaryName = primaryName
        self.aliases = aliases
        self.usageArgsEN = usageArgsEN
        self.usageArgsZH = usageArgsZH
        self.summaryEN = summaryEN
        self.summaryZH = summaryZH
    }

    public var allNames: [String] {
        [primaryName] + aliases
    }
}

/// What the desktop workbench should open at launch, resolved from the command line before any window exists.
public struct MachDesktopLaunchRequest: Sendable, Equatable {
    public let binaryPath: String?
    public let loadDemo: Bool

    public init(binaryPath: String?, loadDemo: Bool) {
        self.binaryPath = binaryPath
        self.loadDemo = loadDemo
    }
}

/// Outcome of a headless CLI invocation that may emit normal stdout results while returning a non-zero exit code.
public struct MachCLIOutcome: Sendable, Equatable {
    public let output: String
    public let stderr: String
    public let exitCode: Int32

    public init(output: String, stderr: String = "", exitCode: Int32 = 0) {
        self.output = output
        self.stderr = stderr
        self.exitCode = exitCode
    }
}

// MARK: - Headless Binary Inspection & Reverse-Engineering CLI (`MachCLIRunner`)

public struct MachCLIRunner: Sendable {

    /// Single source of truth for CLI subcommand dispatch AND `--help` output (fixes G17).
    public static let subcommandSpecs: [CLISubcommandSpec] = [
        CLISubcommandSpec(
            primaryName: "info",
            usageArgsEN: "<file> [--json]",
            usageArgsZH: "<文件> [--json]",
            summaryEN: "Inspect Mach-O / Universal headers, segments, sections, UUID & CDHash",
            summaryZH: "检视 Mach-O / 通用二进制头部、段、节区、UUID 与代码签名摘要"
        ),
        CLISubcommandSpec(
            primaryName: "segments",
            usageArgsEN: "<file> [--json]",
            usageArgsZH: "<文件> [--json]",
            summaryEN: "List mapped VM segments, file offsets & RWX protections",
            summaryZH: "列出虚拟内存段映射、文件偏移与 RWX 权限"
        ),
        CLISubcommandSpec(
            primaryName: "symbols",
            usageArgsEN: "<file> [--filter <q>] [--json]",
            usageArgsZH: "<文件> [--filter <关键词>] [--json]",
            summaryEN: "List LC_SYMTAB symbols separately from inferred function starts",
            summaryZH: "分别列出 LC_SYMTAB 真实符号与推断出的函数起点符号"
        ),
        CLISubcommandSpec(
            primaryName: "demangle",
            usageArgsEN: "[<symbol...>] [--json]",
            usageArgsZH: "[<符号...>] [--json]",
            summaryEN: "Demangle Swift and C++ (Itanium) symbol names in-process (reads stdin line-by-line if no symbols are given; returns unrecognized or plain C names unchanged)",
            summaryZH: "在进程内解混淆 Swift 与 C++（Itanium）符号名（未传位置参数时按行读取标准输入；无法解混淆或普通 C 符号原样返回）"
        ),
        CLISubcommandSpec(
            primaryName: "objc",
            usageArgsEN: "<file> [--slice <index>] [--json]",
            usageArgsZH: "<文件> [--slice <序号>] [--json]",
            summaryEN: "List Objective-C classes, methods, ivars, categories & protocols",
            summaryZH: "列出 Objective-C 类、实例与类方法、成员变量、分类与协议"
        ),
        CLISubcommandSpec(
            primaryName: "strings",
            usageArgsEN: "<file> [--filter <q>] [--json]",
            usageArgsZH: "<文件> [--filter <关键词>] [--json]",
            summaryEN: "List extracted UTF-8 / UTF-16 string literals",
            summaryZH: "列出提取的 UTF-8 / UTF-16 字符串字面量"
        ),
        CLISubcommandSpec(
            primaryName: "fixups",
            usageArgsEN: "<file> [--filter <q>] [--json]",
            usageArgsZH: "<文件> [--filter <关键词>] [--json]",
            summaryEN: "List dyld chained fixups (binds, rebases & ARM64e PAC diversity)",
            summaryZH: "列出 dyld 链式修复项（绑定、重定位与 ARM64e PAC 多样性）"
        ),
        CLISubcommandSpec(
            primaryName: "disasm",
            usageArgsEN: "<file> [--symbol <name> | --address <0x...>] [--count <n>] [--json]",
            usageArgsZH: "<文件> [--symbol <名称> | --address <0x...>] [--count <数量>] [--json]",
            summaryEN: "Disassemble ARM64/ARM64e instruction sections or a target function",
            summaryZH: "反汇编 ARM64/ARM64e 指令节区或指定目标函数"
        ),
        CLISubcommandSpec(
            primaryName: "cfg-dot",
            aliases: ["cfg"],
            usageArgsEN: "<file> [--symbol <name> | --address <0x...>] [--json]",
            usageArgsZH: "<文件> [--symbol <名称> | --address <0x...>] [--json]",
            summaryEN: "Export Graphviz DOT control-flow graph for a recovered function",
            summaryZH: "导出已恢复函数的 Graphviz DOT 控制流图"
        ),
        CLISubcommandSpec(
            primaryName: "decompile",
            usageArgsEN: "<file> [--symbol <name> | --address <0x...>] [--json]",
            usageArgsZH: "<文件> [--symbol <名称> | --address <0x...>] [--json]",
            summaryEN: "[Experimental] Emit Pseudo-C from ARM64 CFG (condition expressions unverified)",
            summaryZH: "【实验性】从 ARM64 控制流图生成伪C代码（条件表达式尚未验证）"
        ),
        CLISubcommandSpec(
            primaryName: "xrefs",
            usageArgsEN: "<file> [--address <0x...> | --symbol <name>] [--json]",
            usageArgsZH: "<文件> [--address <0x...> | --symbol <名称>] [--json]",
            summaryEN: "Query incoming & outgoing code/data cross-references (or dump all xrefs when target is omitted)",
            summaryZH: "查询目标地址或符号的传入与传出交叉引用（省略目标时输出全文件交叉引用）"
        ),
        CLISubcommandSpec(
            primaryName: "codesign",
            usageArgsEN: "<file> [--json]",
            usageArgsZH: "<文件> [--json]",
            summaryEN: "Verify Mach-O SuperBlob, CodeDirectory SHA-256 & entitlements",
            summaryZH: "校验 Mach-O SuperBlob、CodeDirectory SHA-256 页哈希与权限项"
        ),
        CLISubcommandSpec(
            primaryName: "entropy",
            usageArgsEN: "<file> [--json]",
            usageArgsZH: "<文件> [--json]",
            summaryEN: "Whole-file Shannon entropy, byte chi-square & sliding-window anomaly count",
            summaryZH: "整个文件的香农熵、字节卡方值与滑动窗口异常计数"
        ),
        CLISubcommandSpec(
            primaryName: "patch-asm",
            aliases: ["patch"],
            usageArgsEN: "<file> --address <0x...> --asm \"...\" [--force] [--output <out>] [--json]",
            usageArgsZH: "<文件> --address <0x...> --asm \"...\" [--force] [--output <输出路径>] [--json]",
            summaryEN: "Assemble inline ARM64 patch & recalculate ad-hoc code signature",
            summaryZH: "汇编内联 ARM64 补丁并重新计算临时代码签名"
        ),
        CLISubcommandSpec(
            primaryName: "asm",
            usageArgsEN: "[--asm \"<insn>; <insn>\"] [--at <0x...>] [--json]",
            usageArgsZH: "[--asm \"<insn>; <insn>\"] [--at <0x...>] [--json]",
            summaryEN: "Assemble ARM64 statements into machine words without reading or writing files (reads stdin if --asm is omitted; 'label:' is local to its own statement)",
            summaryZH: "把 ARM64 语句汇编成机器码，不读写任何文件；不给 --asm 时从标准输入读（语句开头的 '标签:' 只在本条语句里有效，不跨语句）"
        ),
        CLISubcommandSpec(
            primaryName: "resign",
            usageArgsEN: "<file> [--identifier <id>] [--output <out>] [--json]",
            usageArgsZH: "<文件> [--identifier <标识符>] [--output <输出路径>] [--json]",
            summaryEN: "Recalculate Mach-O ad-hoc SHA-256 CodeDirectory page hashes",
            summaryZH: "重新计算 Mach-O 临时 SHA-256 CodeDirectory 代码页哈希"
        ),
        CLISubcommandSpec(
            primaryName: "audit-plugins",
            aliases: ["audit"],
            usageArgsEN: "<file> [--json]",
            usageArgsZH: "<文件> [--json]",
            summaryEN: "[Experimental] Run JavaScriptCore static audit plugins",
            summaryZH: "【实验性】运行 JavaScriptCore 静态安全审计插件"
        ),
        CLISubcommandSpec(
            primaryName: "export-html",
            aliases: ["report-html"],
            usageArgsEN: "<file> [--output <out.html>] [--json]",
            usageArgsZH: "<文件> [--output <输出.html>] [--json]",
            summaryEN: "Export standalone bilingual HTML binary triage report",
            summaryZH: "导出独立离线中英双语 HTML 二进制分诊简报"
        ),
        CLISubcommandSpec(
            primaryName: "mcp",
            usageArgsEN: "[<file>] [--binary <path>]",
            usageArgsZH: "[<文件>] [--binary <路径>]",
            summaryEN: "Start JSON-RPC 2.0 reverse-engineering MCP server on stdio",
            summaryZH: "在标准输入输出上启动 JSON-RPC 2.0 逆向 MCP 服务"
        )
    ]

    /// Every option a subcommand accepts besides the global ones, listed once in `--help`.
    /// README examples may only use options that appear here or under "Global Options".
    public static let subcommandOptionSpecs: [(flags: String, summaryEN: String, summaryZH: String)] = [
        (
            "--json",
            "Print structured JSON instead of text (every subcommand except mcp)",
            "输出结构化 JSON 而不是文本（除 mcp 外的所有子命令）"
        ),
        (
            "--symbol <name>, --function <name>",
            "Select one function by name (disasm, cfg-dot, decompile, xrefs)",
            "按名称选定一个函数（disasm、cfg-dot、decompile、xrefs）"
        ),
        (
            "--address <0x...>",
            "Select a function (or the xrefs target) by virtual address; for patch-asm, the address to write at",
            "按虚拟地址选定函数（或 xrefs 的查询目标）；对 patch-asm 是写入地址"
        ),
        (
            "--count <n>, --limit <n>",
            "Print at most <n> instructions (disasm)",
            "最多输出 <n> 条指令（disasm）"
        ),
        (
            "--filter <q>",
            "Keep only entries containing <q> (symbols, strings, fixups)",
            "只保留包含 <q> 的条目（symbols、strings、fixups）"
        ),
        (
            "--slice <index>",
            "Pick a Universal slice by index (default: arm64e, then arm64)",
            "按序号选择 Universal 切片（默认 arm64e，其次 arm64）"
        ),
        (
            "--asm \"<insn>; <insn>\"",
            "Statements for patch-asm and asm; newlines and ';' separate statements, '//' and '/* */' are comments (in asm, 'label:' applies only to its own statement)",
            "patch-asm 与 asm 的 ARM64 语句；换行与 ';' 分隔语句，'//' 与 '/* */' 为注释（asm 中开头的 '标签:' 只在本条语句里有效，不跨语句）"
        ),
        (
            "--at <0x...>",
            "asm: address of the first statement (+4 for each subsequent statement; default 0x0)",
            "asm：第一条语句的地址，之后每条加 4（默认 0x0）"
        ),
        (
            "--force",
            "patch-asm: override the check that refuses a patch covering a branch target, function start or symbol",
            "patch-asm：跳过安全检查（补丁内部盖住跳转目标、函数起点或符号时，默认拒绝写入）"
        ),
        (
            "--output <path>, -o <path>",
            "Write the result file to <path> (patch-asm, resign, export-html)",
            "把结果文件写到 <path>（patch-asm、resign、export-html）"
        ),
        (
            "--identifier <id>",
            "Code-signing identifier to embed (resign)",
            "写入签名的标识符（resign）"
        )
    ]

    public static let builtinMetaTokens: Set<String> = [
        "help", "--help", "-h",
        "version", "--version", "-v"
    ]

    /// Derived directly from `subcommandSpecs` + `builtinMetaTokens`.
    public static var recognizedHeadlessTokens: Set<String> {
        var tokens = builtinMetaTokens
        for spec in subcommandSpecs {
            for name in spec.allNames {
                tokens.insert(name)
            }
        }
        return tokens
    }

    public static func isHeadlessInvocation(arguments: [String]) -> Bool {
        let stripped = stripLanguageFlags(arguments)
        guard let first = stripped.first else { return false }
        return recognizedHeadlessTokens.contains(first)
    }

    /// Process exit code for a failed invocation: `2` for usage errors, `3` for unsupported A64 assembly, `1` for everything else.
    public static func exitCode(for error: Error) -> Int32 {
        if let mgErr = error as? MachGraphError {
            switch mgErr {
            case .invalidCLIArguments:
                return 2
            case .assemblerUnsupported:
                return 3
            default:
                return 1
            }
        }
        return 1
    }

    /// Decides, without creating any window, whether a non-headless argument vector is a valid request
    /// to open the desktop workbench. The executable calls this before it touches AppKit.
    ///
    /// The workbench accepts exactly these shapes (plus `--lang`): no arguments, `--demo`, `--binary <file>`,
    /// or one existing `<file>` as the only argument. Anything else with a word in subcommand position is a
    /// mistyped subcommand and is reported as such (usage error, exit code 2), never as a missing file.
    public static func resolveDesktopLaunchRequest(
        arguments: [String],
        language: MachLanguage,
        fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) throws -> MachDesktopLaunchRequest {
        let args = stripLanguageFlags(arguments)

        for arg in args where arg.hasPrefix("-") && arg != "--binary" && arg != "--demo" {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Unknown option '\(arg)'. Run 'machgraph --help' for usage.",
                    "不支持的选项 '\(arg)'。请运行 'machgraph --help' 查看用法。"
                )
            )
        }

        let loadDemo = args.contains("--demo")
        var binaryFlagPath: String?
        var positionals: [String] = []
        var idx = 0
        while idx < args.count {
            let tok = args[idx]
            if tok == "--binary" {
                guard idx + 1 < args.count, !args[idx + 1].hasPrefix("-") else {
                    throw MachGraphError.invalidCLIArguments(
                        language.select("Option '--binary' requires a file path.", "选项 '--binary' 需要提供文件路径。")
                    )
                }
                binaryFlagPath = args[idx + 1]
                idx += 2
                continue
            }
            if !tok.hasPrefix("-") {
                positionals.append(tok)
            }
            idx += 1
        }

        func unknownSubcommand(_ word: String) -> MachGraphError {
            .invalidCLIArguments(
                language.select(
                    "Unknown subcommand '\(word)'. Run 'machgraph --help' for usage.",
                    "未知子命令 '\(word)'。请运行 'machgraph --help' 查看用法。"
                )
            )
        }

        if let word = positionals.first {
            // A word next to any other argument can only be a (mistyped) subcommand.
            guard args.count == 1 else {
                throw unknownSubcommand(word)
            }
            guard fileExists(word) else {
                throw MachGraphError.invalidCLIArguments(
                    language.select(
                        "'\(word)' is neither a known subcommand nor an existing file. Run 'machgraph --help' for usage.",
                        "'\(word)' 既不是已知子命令，也不是存在的文件。请运行 'machgraph --help' 查看用法。"
                    )
                )
            }
            return MachDesktopLaunchRequest(binaryPath: word, loadDemo: false)
        }

        if let binaryFlagPath {
            guard fileExists(binaryFlagPath) else {
                throw MachGraphError.fileNotFound(binaryFlagPath)
            }
            return MachDesktopLaunchRequest(binaryPath: binaryFlagPath, loadDemo: loadDemo)
        }
        return MachDesktopLaunchRequest(binaryPath: nil, loadDemo: loadDemo)
    }

    public static func resolveCanonicalSubcommand(_ raw: String) -> String? {
        for spec in subcommandSpecs where spec.allNames.contains(raw) {
            return spec.primaryName
        }
        return nil
    }

    public typealias StdinReader = @Sendable () throws -> String

    private let readStandardInput: StdinReader

    private static let defaultStdinReader: StdinReader = {
        let data = try FileHandle.standardInput.readToEnd() ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    public init() {
        self.readStandardInput = Self.defaultStdinReader
    }

    public init(stdinReader: @escaping StdinReader) {
        self.readStandardInput = stdinReader
    }

    public func execute(arguments: [String]) async throws -> String {
        try await run(arguments: arguments).output
    }

    public func run(arguments: [String]) async throws -> MachCLIOutcome {
        let resolvedLang = try Self.validateAndResolveLanguage(from: arguments)
        await MainActor.run {
            MachLocalizer.shared.setLanguage(resolvedLang, persist: false)
        }

        let cleanedArgs = Self.stripLanguageFlags(arguments)
        guard let rawSubcommand = cleanedArgs.first else {
            return MachCLIOutcome(output: Self.helpBanner(in: resolvedLang))
        }
        let rest = Array(cleanedArgs.dropFirst())

        if ["help", "--help", "-h"].contains(rawSubcommand) {
            return MachCLIOutcome(output: Self.helpBanner(in: resolvedLang))
        }
        if ["version", "--version", "-v"].contains(rawSubcommand) {
            return MachCLIOutcome(output: Self.versionBanner(in: resolvedLang))
        }

        guard let canonical = Self.resolveCanonicalSubcommand(rawSubcommand) else {
            throw MachGraphError.invalidCLIArguments(
                resolvedLang.select(
                    "Unknown subcommand '\(rawSubcommand)'. Run 'machgraph --help' for usage.",
                    "未知子命令 '\(rawSubcommand)'。请运行 'machgraph --help' 查看用法。"
                )
            )
        }

        // Handle `--help` passed after a subcommand name (e.g. `machgraph disasm --help`)
        if rest.contains("--help") || rest.contains("-h") {
            return MachCLIOutcome(output: Self.helpBanner(in: resolvedLang))
        }

        switch canonical {
        case "info":
            return MachCLIOutcome(output: try runInfo(args: rest, language: resolvedLang))
        case "segments":
            return MachCLIOutcome(output: try runSegments(args: rest, language: resolvedLang))
        case "symbols":
            return MachCLIOutcome(output: try runSymbols(args: rest, language: resolvedLang))
        case "demangle":
            return MachCLIOutcome(output: try runDemangle(args: rest, language: resolvedLang))
        case "objc":
            return MachCLIOutcome(output: try runObjC(args: rest, language: resolvedLang))
        case "strings":
            return MachCLIOutcome(output: try runStrings(args: rest, language: resolvedLang))
        case "fixups":
            return MachCLIOutcome(output: try runFixups(args: rest, language: resolvedLang))
        case "disasm":
            return MachCLIOutcome(output: try runDisasm(args: rest, language: resolvedLang))
        case "cfg-dot":
            return MachCLIOutcome(output: try runCFGDot(args: rest, language: resolvedLang))
        case "decompile":
            return MachCLIOutcome(output: try runDecompile(args: rest, language: resolvedLang))
        case "xrefs":
            return MachCLIOutcome(output: try runXrefs(args: rest, language: resolvedLang))
        case "codesign":
            return MachCLIOutcome(output: try runCodeSign(args: rest, language: resolvedLang))
        case "entropy":
            return MachCLIOutcome(output: try runEntropy(args: rest, language: resolvedLang))
        case "patch-asm":
            return MachCLIOutcome(output: try runPatchAsm(args: rest, language: resolvedLang))
        case "asm":
            return try runAsm(args: rest, language: resolvedLang)
        case "resign":
            return MachCLIOutcome(output: try runResign(args: rest, language: resolvedLang))
        case "audit-plugins":
            return MachCLIOutcome(output: try runAuditPlugins(args: rest, language: resolvedLang))
        case "export-html":
            return MachCLIOutcome(output: try runExportHTML(args: rest, language: resolvedLang))
        case "mcp":
            let parsed = try parseArguments(
                rest,
                subcommand: "mcp",
                valueFlags: ["--binary"],
                boolFlags: ["--demo"],
                language: resolvedLang
            )
            let defaultBinary: String?
            if parsed.boolFlags.contains("--demo") {
                defaultBinary = try Self.locateDemoBinaryURL(language: resolvedLang).path
            } else {
                defaultBinary = parsed.values["--binary"] ?? parsed.positionals.first
            }
            let server = MachMCPServer(defaultBinaryPath: defaultBinary, language: resolvedLang)
            await server.serveStdio()
            return MachCLIOutcome(output: "")
        default:
            throw MachGraphError.invalidCLIArguments("Unhandled subcommand '\(canonical)'.")
        }
    }

    // MARK: - Subcommand Implementations

    private func runInfo(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "info",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "info", language: language)
        let img = target.image
        let execSecs = (try? FunctionDiscoveryEngine().decodeExecutableSections(in: img, data: target.data)) ?? []
        let insnCount = execSecs.reduce(0) { $0 + $1.instructions.count }
        let realCount = img.symbols.filter { !$0.isInferred }.count
        let inferredCount = img.symbols.filter { $0.isInferred }.count

        if parsed.isJSON {
            let isMachOContainer = (img.containerFormat == .machO64 || img.containerFormat == .universalFat)
            let reportedFunctionStarts = isMachOContainer ? img.lcFunctionStarts : img.functionStarts
            let dict: [String: Any] = [
                "fileName": img.fileName,
                "filePath": img.filePath,
                "fileSize": img.fileSize,
                "sha256": img.sha256Hex,
                "isDemo": target.isDemo,
                "format": img.containerFormat.rawValue,
                "architecture": img.architecture.displayName,
                "selectedSliceIndex": img.selectedSliceIndex,
                "sliceFileOffset": img.sliceFileOffset.rawValue,
                "isPositionIndependent": img.isPositionIndependent,
                "imageBase": img.imageBase.rawValue,
                "imageBaseHex": img.imageBase.hexString,
                "entryPoint": img.entryPoint.map { AnyHashable($0.rawValue) } ?? NSNull(),
                "entryPointHex": img.entryPoint?.hexString ?? NSNull(),
                "uuid": img.uuidString ?? NSNull(),
                "platform": img.platformName,
                "minOSVersion": img.minOSVersion,
                "sdkVersion": img.sdkVersion,
                "instructionCount": insnCount,
                "functionStartsCount": reportedFunctionStarts.count,
                "functionStarts": reportedFunctionStarts.map(\.rawValue),
                "functionStartsHex": reportedFunctionStarts.map(\.hexString),
                "lcFunctionStarts": img.lcFunctionStarts.map(\.rawValue),
                "realSymbolCount": realCount,
                "inferredSymbolCount": inferredCount,
                "stringCount": img.strings.count,
                "fixupCount": img.chainedFixups.count,
                "segments": img.segments.map { seg in
                    [
                        "name": seg.name,
                        "vmaddr": seg.vmAddress.rawValue,
                        "vmaddrHex": seg.vmAddress.hexString,
                        "vmsize": seg.vmSize,
                        "fileoff": seg.fileOffset.rawValue,
                        "filesize": seg.fileSize,
                        "initprot": seg.initialProtection.rwxString,
                        "maxprot": seg.maxProtection.rwxString,
                        "sectionCount": seg.sections.count
                    ] as [String: Any]
                },
                "sections": img.sections.map { sec in
                    [
                        "segment": sec.segmentName,
                        "section": sec.sectionName,
                        "addr": sec.vmAddress.rawValue,
                        "addrHex": sec.vmAddress.hexString,
                        "size": sec.size,
                        "offset": sec.fileOffset.rawValue,
                        "flags": sec.flags,
                        "isExecutable": img.executableSections().contains(where: { $0.id == sec.id })
                    ] as [String: Any]
                },
                "installID": img.dylibInstallID.map { idLib in
                    [
                        "installName": idLib.installName,
                        "compatibilityVersion": idLib.compatibilityVersion,
                        "currentVersion": idLib.currentVersion
                    ] as [String: Any]
                } ?? NSNull(),
                "libraries": img.importedLibraries.map { lib in
                    [
                        "ordinal": lib.ordinal,
                        "installName": lib.installName,
                        "compatibilityVersion": lib.compatibilityVersion,
                        "currentVersion": lib.currentVersion,
                        "isWeak": lib.isWeak,
                        "isReexport": lib.isReexport
                    ] as [String: Any]
                },
                "codeSignature": [
                    "isSigned": img.codeSignature.isSigned,
                    "isAdHoc": img.codeSignature.isAdHoc,
                    "flags": img.codeSignature.flags,
                    "flagsHex": String(format: "0x%x", img.codeSignature.flags),
                    "identifier": img.codeSignature.identifier,
                    "teamIdentifier": img.codeSignature.teamIdentifier ?? NSNull(),
                    "cdHash": img.codeSignature.cdHashHex,
                    "hashAlgorithm": img.codeSignature.hashAlgorithm,
                    "pageSize": img.codeSignature.pageSize,
                    "codeDirectoryVersion": img.codeSignature.codeDirectoryVersion,
                    "entitlementCount": img.codeSignature.entitlements.count
                ] as [String: Any]
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append("File:          \(img.fileName) (\(img.fileSize) bytes)")
        lines.append("SHA-256:       \(img.sha256Hex)")
        lines.append("Format:        \(img.containerFormat.rawValue)")
        lines.append("Architecture:  \(img.architecture.displayName) (PIE=\(img.isPositionIndependent))")
        if let uuid = img.uuidString {
            lines.append("UUID:          \(uuid)")
        }
        lines.append("Image Base:    \(img.imageBase.hexString)")
        lines.append("Entry Point:   \(img.entryPoint?.hexString ?? "none")")
        lines.append("Segments:      \(img.segments.count) (\(img.sections.count) sections)")
        lines.append("Symbols:       \(realCount) symtab, \(inferredCount) inferred")
        lines.append("Fixups:        \(img.chainedFixups.count)")
        lines.append("Instructions:  \(insnCount)")
        lines.append("CodeSign:      signed=\(img.codeSignature.isSigned) adhoc=\(img.codeSignature.isAdHoc) cdhash=\(img.codeSignature.cdHashHex)")
        if let idLib = img.dylibInstallID {
            lines.append("Install ID:    \(idLib.installName) (compatibility version \(idLib.compatibilityVersion), current version \(idLib.currentVersion))")
        }
        lines.append("Libraries:     \(img.importedLibraries.count)")
        for lib in img.importedLibraries {
            let tagSuffix = lib.isWeak ? ", weak" : (lib.isReexport ? ", reexport" : "")
            lines.append("  \(lib.installName) (compatibility version \(lib.compatibilityVersion), current version \(lib.currentVersion)\(tagSuffix))")
        }
        return lines.joined(separator: "\n")
    }

    private func runSegments(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "segments",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "segments", language: language)
        let img = target.image

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": img.fileName,
                "isDemo": target.isDemo,
                "segments": img.segments.map { seg in
                    [
                        "name": seg.name,
                        "vmaddr": seg.vmAddress.rawValue,
                        "vmaddrHex": seg.vmAddress.hexString,
                        "vmsize": seg.vmSize,
                        "fileoff": seg.fileOffset.rawValue,
                        "filesize": seg.fileSize,
                        "initprot": seg.initialProtection.rwxString,
                        "maxprot": seg.maxProtection.rwxString,
                        "sections": seg.sections.map { sec in
                            [
                                "segment": sec.segmentName,
                                "section": sec.sectionName,
                                "addr": sec.vmAddress.rawValue,
                                "addrHex": sec.vmAddress.hexString,
                                "size": sec.size,
                                "offset": sec.fileOffset.rawValue,
                                "flags": sec.flags
                            ] as [String: Any]
                        }
                    ] as [String: Any]
                }
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        for seg in img.segments {
            lines.append(
                String(
                    format: "%-16@ vm=%@ size=0x%llx off=0x%llx fsz=0x%llx prot=%@/%@ sections=%d",
                    seg.name as NSString,
                    seg.vmAddress.hexString as NSString,
                    seg.vmSize,
                    seg.fileOffset.rawValue,
                    seg.fileSize,
                    seg.initialProtection.rwxString as NSString,
                    seg.maxProtection.rwxString as NSString,
                    seg.sections.count
                )
            )
        }
        return lines.joined(separator: "\n")
    }

    private func runSymbols(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "symbols",
            valueFlags: ["--binary", "--slice", "--filter"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "symbols", language: language)
        let filter = parsed.values["--filter"]?.lowercased()
        let filtered = target.image.symbols.filter { sym in
            guard let q = filter, !q.isEmpty else { return true }
            return sym.name.lowercased().contains(q) || sym.demangledName.lowercased().contains(q)
        }
        let realSyms = filtered.filter { !$0.isInferred }
        let inferredSyms = filtered.filter { $0.isInferred }

        if parsed.isJSON {
            func encodeSymbol(_ sym: BinarySymbol) -> [String: Any] {
                [
                    "name": sym.name,
                    "demangledName": sym.demangledName,
                    "address": sym.address.rawValue,
                    "addressHex": sym.address.hexString,
                    "kind": sym.kind.rawValue,
                    "binding": sym.binding.rawValue,
                    "inferred": sym.isInferred,
                    "source": sym.provenance.rawValue,
                    "libraryOrdinal": sym.libraryOrdinal ?? NSNull()
                ]
            }
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "realCount": realSyms.count,
                "inferredCount": inferredSyms.count,
                "realSymbols": realSyms.map(encodeSymbol),
                "inferredSymbols": inferredSyms.map(encodeSymbol)
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append("# Symtab Symbols (\(realSyms.count)):")
        for sym in realSyms {
            lines.append("\(sym.address.hexString) [\(sym.kind.rawValue)] \(sym.demangledName)")
        }
        if !inferredSyms.isEmpty {
            lines.append("# Inferred Entries (\(inferredSyms.count)):")
            for sym in inferredSyms {
                lines.append("\(sym.address.hexString) [inferred:\(sym.provenance.rawValue)] \(sym.demangledName)")
            }
        }
        return lines.joined(separator: "\n")
    }

    private func runObjC(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "objc",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "objc", language: language)
        let img = target.image

        let instanceMethodCount = img.objcClasses.reduce(0) { acc, cls in
            acc + cls.methods.filter { !$0.isClassMethod }.count
        }
        let classMethodCount = img.objcClasses.reduce(0) { acc, cls in
            acc + cls.methods.filter { $0.isClassMethod }.count
        }
        let categoryMethodCount = img.objcCategories.reduce(0) { acc, cat in
            acc + cat.instanceMethods.count + cat.classMethods.count
        }

        func encodeMethod(_ m: ObjCMethodMetadata, ownerLabel: String) -> [String: Any] {
            let prefix = m.isClassMethod ? "+" : "-"
            return [
                "name": "\(prefix)[\(ownerLabel) \(m.selector)]",
                "selector": m.selector,
                "typeEncoding": m.typeEncoding,
                "address": m.implementationAddress.rawValue,
                "addressHex": m.implementationAddress.hexString,
                "isClassMethod": m.isClassMethod
            ]
        }

        if parsed.isJSON {
            let classesJSON: [[String: Any]] = img.objcClasses.map { cls in
                let instMethods = cls.methods.filter { !$0.isClassMethod }
                let clsMethods = cls.methods.filter { $0.isClassMethod }
                return [
                    "name": cls.name,
                    "superclass": cls.superclassName ?? NSNull(),
                    "address": cls.address.rawValue,
                    "addressHex": cls.address.hexString,
                    "instanceSize": cls.instanceSize,
                    "flags": cls.flags,
                    "adoptedProtocols": cls.adoptedProtocols,
                    "instanceMethods": instMethods.map { encodeMethod($0, ownerLabel: cls.name) },
                    "classMethods": clsMethods.map { encodeMethod($0, ownerLabel: cls.name) },
                    "ivars": cls.ivars.map { ivar in
                        [
                            "name": ivar.name,
                            "typeEncoding": ivar.typeEncoding,
                            "offset": ivar.offset,
                            "size": ivar.size
                        ] as [String: Any]
                    }
                ]
            }

            let categoriesJSON: [[String: Any]] = img.objcCategories.map { cat in
                let ownerLabel = "\(cat.className)(\(cat.name))"
                return [
                    "name": cat.name,
                    "className": cat.className,
                    "address": cat.address.rawValue,
                    "addressHex": cat.address.hexString,
                    "adoptedProtocols": cat.adoptedProtocols,
                    "instanceMethods": cat.instanceMethods.map { encodeMethod($0, ownerLabel: ownerLabel) },
                    "classMethods": cat.classMethods.map { encodeMethod($0, ownerLabel: ownerLabel) }
                ]
            }

            let protocolsJSON: [[String: Any]] = img.objcProtocols.map { proto in
                [
                    "name": proto.name,
                    "address": proto.address.rawValue,
                    "addressHex": proto.address.hexString,
                    "adoptedProtocols": proto.adoptedProtocols,
                    "instanceMethods": proto.instanceMethods.map { encodeMethod($0, ownerLabel: proto.name) },
                    "classMethods": proto.classMethods.map { encodeMethod($0, ownerLabel: proto.name) },
                    "optionalInstanceMethods": proto.optionalInstanceMethods.map { encodeMethod($0, ownerLabel: proto.name) },
                    "optionalClassMethods": proto.optionalClassMethods.map { encodeMethod($0, ownerLabel: proto.name) }
                ]
            }

            let dict: [String: Any] = [
                "fileName": img.fileName,
                "filePath": img.filePath,
                "isDemo": target.isDemo,
                "architecture": img.architecture.displayName,
                "selectedSliceIndex": img.selectedSliceIndex,
                "classCount": img.objcClasses.count,
                "instanceMethodCount": instanceMethodCount,
                "classMethodCount": classMethodCount,
                "methodCount": instanceMethodCount + classMethodCount,
                "categoryCount": img.objcCategories.count,
                "categoryMethodCount": categoryMethodCount,
                "protocolCount": img.objcProtocols.count,
                "classes": classesJSON,
                "categories": categoriesJSON,
                "protocols": protocolsJSON
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append(
            "ObjC Summary: classes=\(img.objcClasses.count) methods=\(instanceMethodCount + classMethodCount) (instance=\(instanceMethodCount), class=\(classMethodCount)) categories=\(img.objcCategories.count) categoryMethods=\(categoryMethodCount) protocols=\(img.objcProtocols.count)"
        )
        lines.append("# Classes (\(img.objcClasses.count)):")
        for cls in img.objcClasses {
            let superPart = cls.superclassName.map { " : \($0)" } ?? ""
            let protoPart = cls.adoptedProtocols.isEmpty ? "" : " <\(cls.adoptedProtocols.joined(separator: ", "))>"
            lines.append("  \(cls.address.hexString) \(cls.name)\(superPart)\(protoPart) (instanceSize=\(cls.instanceSize))")
            for ivar in cls.ivars {
                lines.append("    ivar +\(ivar.offset) \(ivar.name) (\(ivar.typeEncoding), size=\(ivar.size))")
            }
            for m in cls.methods where m.isClassMethod {
                lines.append("    \(m.implementationAddress.hexString) +[\(cls.name) \(m.selector)]")
            }
            for m in cls.methods where !m.isClassMethod {
                lines.append("    \(m.implementationAddress.hexString) -[\(cls.name) \(m.selector)]")
            }
        }
        if !img.objcCategories.isEmpty {
            lines.append("# Categories (\(img.objcCategories.count)):")
            for cat in img.objcCategories {
                let ownerLabel = "\(cat.className)(\(cat.name))"
                let protoPart = cat.adoptedProtocols.isEmpty ? "" : " <\(cat.adoptedProtocols.joined(separator: ", "))>"
                lines.append("  \(cat.address.hexString) \(ownerLabel)\(protoPart)")
                for m in cat.classMethods {
                    lines.append("    \(m.implementationAddress.hexString) +[\(ownerLabel) \(m.selector)]")
                }
                for m in cat.instanceMethods {
                    lines.append("    \(m.implementationAddress.hexString) -[\(ownerLabel) \(m.selector)]")
                }
            }
        }
        if !img.objcProtocols.isEmpty {
            lines.append("# Protocols (\(img.objcProtocols.count)):")
            for proto in img.objcProtocols {
                let protoPart = proto.adoptedProtocols.isEmpty ? "" : " <\(proto.adoptedProtocols.joined(separator: ", "))>"
                lines.append("  \(proto.address.hexString) \(proto.name)\(protoPart)")
                for m in proto.classMethods {
                    lines.append("    +[\(proto.name) \(m.selector)]")
                }
                for m in proto.instanceMethods {
                    lines.append("    -[\(proto.name) \(m.selector)]")
                }
                for m in proto.optionalClassMethods {
                    lines.append("    @optional +[\(proto.name) \(m.selector)]")
                }
                for m in proto.optionalInstanceMethods {
                    lines.append("    @optional -[\(proto.name) \(m.selector)]")
                }
            }
        }
        return lines.joined(separator: "\n")
    }

    private func runStrings(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "strings",
            valueFlags: ["--binary", "--slice", "--filter"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "strings", language: language)
        let filter = parsed.values["--filter"]?.lowercased()
        let strs = target.image.strings.filter { lit in
            guard let q = filter, !q.isEmpty else { return true }
            return lit.value.lowercased().contains(q)
        }

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "count": strs.count,
                "strings": strs.map { lit in
                    [
                        "address": lit.address.rawValue,
                        "addressHex": lit.address.hexString,
                        "fileOffset": lit.fileOffset.rawValue,
                        "section": lit.sectionName,
                        "encoding": lit.encoding.rawValue,
                        "value": lit.value
                    ] as [String: Any]
                }
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        for lit in strs {
            lines.append("\(lit.address.hexString) (\(lit.sectionName)): \(lit.value)")
        }
        return lines.joined(separator: "\n")
    }

    private func runFixups(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "fixups",
            valueFlags: ["--binary", "--slice", "--filter"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "fixups", language: language)
        let filter = parsed.values["--filter"]?.lowercased()
        let entries = target.image.chainedFixups.filter { fx in
            guard let q = filter, !q.isEmpty else { return true }
            return (fx.symbolName?.lowercased().contains(q) == true)
                || fx.kind.rawValue.lowercased().contains(q)
                || fx.location.hexString.lowercased().contains(q)
        }

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "count": entries.count,
                "fixups": entries.map { fx in
                    [
                        "location": fx.location.rawValue,
                        "locationHex": fx.location.hexString,
                        "fileOffset": fx.fileOffset.rawValue,
                        "kind": fx.kind.rawValue,
                        "targetAddress": fx.targetAddress.map { AnyHashable($0.rawValue) } ?? NSNull(),
                        "targetAddressHex": fx.targetAddress?.hexString ?? NSNull(),
                        "symbolName": fx.symbolName ?? NSNull(),
                        "libraryOrdinal": fx.libraryOrdinal ?? NSNull(),
                        "addend": fx.addend,
                        "pacKey": fx.pacKey ?? NSNull(),
                        "pacDiversity": fx.pacDiversity.map { Int($0) } ?? NSNull(),
                        "isPACAuthenticated": fx.pacKey != nil
                    ] as [String: Any]
                }
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        for fx in entries {
            let symPart = fx.symbolName.map { " sym=\($0)" } ?? ""
            let tgtPart = fx.targetAddress.map { " target=\($0.hexString)" } ?? ""
            let pacPart = fx.pacKey.map { " pac=\($0)(div=\(fx.pacDiversity ?? 0))" } ?? ""
            lines.append("\(fx.location.hexString) [\(fx.kind.rawValue)] off=0x\(String(fx.fileOffset.rawValue, radix: 16))\(symPart)\(tgtPart)\(pacPart)")
        }
        return lines.joined(separator: "\n")
    }

    private func runDisasm(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "disasm",
            valueFlags: ["--binary", "--slice", "--function", "--symbol", "--address", "--count", "--limit"],
            boolFlags: ["--json", "--demo"],
            language: language
        )

        let requestedName = parsed.values["--function"] ?? parsed.values["--symbol"]
        let requestedAddr = parsed.values["--address"]
        let limitRaw = parsed.values["--count"] ?? parsed.values["--limit"]
        let maxCount: Int?
        if let limitRaw {
            guard let n = Int(limitRaw), n > 0 else {
                throw MachGraphError.invalidCLIArguments(
                    language.select(
                        "Invalid instruction count '\(limitRaw)'. Expected a positive integer.",
                        "无效的指令数量 '\(limitRaw)'，应为正整数。"
                    )
                )
            }
            maxCount = n
        } else {
            maxCount = nil
        }

        // Targeted function/symbol/address disassembly
        if requestedName != nil || requestedAddr != nil {
            let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "disasm", language: language)
            let fn = try resolveRequiredFunction(
                in: loaded.index,
                symbolQuery: requestedName,
                addressQuery: requestedAddr,
                language: language
            )
            let allFnInsns = fn.blocks.flatMap(\.instructions)
            let cappedInsns = maxCount.map { Array(allFnInsns.prefix($0)) } ?? allFnInsns

            if parsed.isJSON {
                let dict: [String: Any] = [
                    "fileName": loaded.index.image.fileName,
                    "isDemo": loaded.isDemo,
                    "function": fn.name,
                    "demangledName": fn.demangledName,
                    "address": fn.address.rawValue,
                    "addressHex": fn.address.hexString,
                    "instructions": cappedInsns.map(Self.encodeInstructionJSON)
                ]
                return try Self.encodeJSONObject(dict)
            }

            var out: [String] = []
            if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
                out.append(banner)
            }
            out.append("; Function \(fn.demangledName) @ \(fn.address.hexString)")
            var emitted = 0
            outer: for block in fn.blocks {
                out.append("\(block.label):")
                for insn in block.instructions {
                    if let maxCount, emitted >= maxCount { break outer }
                    let commentSuffix = insn.autoComment.map { " ; \($0)" } ?? ""
                    out.append("  \(insn.address.hexString)  \(insn.rawBytesHex)  \(insn.formattedDisassembly)\(commentSuffix)")
                    emitted += 1
                }
            }
            return out.joined(separator: "\n")
        }

        // Full linear disassembly of instruction sections ONLY (fast O(N), skips 2D CFG layout!)
        let target = try loadContainerOnly(parsed: parsed, subcommand: "disasm", language: language)
        let decodedSections = try FunctionDiscoveryEngine().decodeExecutableSections(in: target.image, data: target.data)
        guard !decodedSections.isEmpty else {
            throw MachGraphError.cfgAnalysisError(
                language.select(
                    "No executable instruction sections found in '\(target.image.fileName)'.",
                    "在 '\(target.image.fileName)' 中未找到可执行指令节区。"
                )
            )
        }

        if parsed.isJSON {
            var remaining = maxCount ?? Int.max
            var secArray: [[String: Any]] = []
            for entry in decodedSections where remaining > 0 {
                let slice = Array(entry.instructions.prefix(remaining))
                remaining -= slice.count
                secArray.append([
                    "segment": entry.section.segmentName,
                    "section": entry.section.sectionName,
                    "address": entry.section.vmAddress.rawValue,
                    "addressHex": entry.section.vmAddress.hexString,
                    "instructions": slice.map(Self.encodeInstructionJSON)
                ])
            }
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "sections": secArray
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        var emitted = 0
        outerSec: for entry in decodedSections {
            lines.append("; Section \(entry.section.segmentName),\(entry.section.sectionName) @ \(entry.section.vmAddress.hexString)")
            for insn in entry.instructions {
                if let maxCount, emitted >= maxCount { break outerSec }
                lines.append("\(insn.address.hexString)\t\(String(format: "%08x", insn.rawWord))\t\(insn.mnemonicText)\t\(insn.operandText)")
                emitted += 1
            }
        }
        return lines.joined(separator: "\n")
    }

    private func runCFGDot(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "cfg-dot",
            valueFlags: ["--binary", "--slice", "--function", "--symbol", "--address"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "cfg-dot", language: language)
        let requestedName = parsed.values["--function"] ?? parsed.values["--symbol"]
        let requestedAddr = parsed.values["--address"]

        let fn: RecoveredFunction
        if requestedName != nil || requestedAddr != nil {
            fn = try resolveRequiredFunction(
                in: loaded.index,
                symbolQuery: requestedName,
                addressQuery: requestedAddr,
                language: language
            )
        } else if let entry = loaded.index.image.entryPoint,
                  let entryFn = loaded.index.function(at: entry) ?? loaded.index.function(containing: entry) {
            fn = entryFn
        } else if let first = loaded.index.functions.first(where: { !$0.isThunk }) ?? loaded.index.functions.first {
            fn = first
        } else {
            throw MachGraphError.cfgAnalysisError(
                language.select("No functions recovered in image.", "镜像中未恢复出任何函数。")
            )
        }

        let dot = exportFunctionDOT(fn)
        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": loaded.index.image.fileName,
                "isDemo": loaded.isDemo,
                "function": fn.name,
                "demangledName": fn.demangledName,
                "address": fn.address.rawValue,
                "addressHex": fn.address.hexString,
                "blockCount": fn.blocks.count,
                "edgeCount": fn.edges.count,
                "cyclomaticComplexity": fn.cyclomaticComplexity,
                "loopCount": fn.naturalLoops.count,
                "dot": dot
            ]
            return try Self.encodeJSONObject(dict)
        }
        if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
            return "// \(banner)\n\(dot)"
        }
        return dot
    }

    private func runDecompile(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "decompile",
            valueFlags: ["--binary", "--slice", "--function", "--symbol", "--address"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "decompile", language: language)
        let engine = MachMicroDecompilerEngine()
        let requestedName = parsed.values["--function"] ?? parsed.values["--symbol"]
        let requestedAddr = parsed.values["--address"]

        let targetFunctions: [RecoveredFunction]
        if requestedName != nil || requestedAddr != nil {
            let fn = try resolveRequiredFunction(
                in: loaded.index,
                symbolQuery: requestedName,
                addressQuery: requestedAddr,
                language: language
            )
            targetFunctions = [fn]
        } else {
            let nonThunks = loaded.index.functions.filter { !$0.isThunk }
            targetFunctions = nonThunks.isEmpty ? loaded.index.functions : nonThunks
        }

        guard !targetFunctions.isEmpty else {
            throw MachGraphError.decompilerError(
                language.select("No functions available to decompile.", "没有可供反编译的函数。")
            )
        }

        let outputs = targetFunctions.map { fn in
            engine.decompile(function: fn, in: loaded.index, language: language)
        }
        let warningLine = PseudoCCodeFormatter.experimentalWarningComment(in: language)

        if parsed.isJSON {
            let dict: [String: Any] = [
                "experimental": true,
                "warning": warningLine,
                "fileName": loaded.index.image.fileName,
                "isDemo": loaded.isDemo,
                "functions": outputs.map { out in
                    [
                        "name": out.functionName,
                        "address": out.functionAddress.rawValue,
                        "addressHex": out.functionAddress.hexString,
                        "signature": out.signatureLine,
                        "source": out.fullSourceText
                    ] as [String: Any]
                }
            ]
            return try Self.encodeJSONObject(dict)
        }

        var body = outputs.map(\.fullSourceText).joined(separator: "\n\n")
        if !body.hasPrefix(warningLine) {
            body = warningLine + "\n" + body
        }
        if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
            // Keep experimental warning on line 1 per M0 Item 8!
            let lines = body.components(separatedBy: "\n")
            if let first = lines.first {
                let tail = lines.dropFirst().joined(separator: "\n")
                return "\(first)\n// \(banner)\n\(tail)"
            }
        }
        return body
    }

    private struct CLIXrefRecordPayload: Encodable {
        let fromAddress: UInt64
        let fromAddressHex: String
        let fromFunction: UInt64?
        let toAddress: UInt64
        let toAddressHex: String
        let kind: String
        let instructionPreview: String

        enum CodingKeys: String, CodingKey {
            case fromAddress
            case fromAddressHex
            case fromFunction
            case toAddress
            case toAddressHex
            case kind
            case instructionPreview
        }

        init(_ rec: XrefRecord) {
            self.fromAddress = rec.fromAddress.rawValue
            self.fromAddressHex = rec.fromAddress.hexString
            self.fromFunction = rec.fromFunction?.rawValue
            self.toAddress = rec.toAddress.rawValue
            self.toAddressHex = rec.toAddress.hexString
            self.kind = rec.kind.rawValue
            self.instructionPreview = rec.instructionPreview
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(fromAddress, forKey: .fromAddress)
            try container.encode(fromAddressHex, forKey: .fromAddressHex)
            if let fromFunction {
                try container.encode(fromFunction, forKey: .fromFunction)
            } else {
                try container.encodeNil(forKey: .fromFunction)
            }
            try container.encode(toAddress, forKey: .toAddress)
            try container.encode(toAddressHex, forKey: .toAddressHex)
            try container.encode(kind, forKey: .kind)
            try container.encode(instructionPreview, forKey: .instructionPreview)
        }
    }

    private struct CLIFullXrefsPayload: Encodable {
        let count: Int
        let fileName: String
        let isDemo: Bool
        let xrefCount: Int
        let xrefs: [CLIXrefRecordPayload]
    }

    private func runXrefs(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "xrefs",
            valueFlags: ["--binary", "--slice", "--address", "--function", "--symbol"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "xrefs", language: language)
        let addrRaw = parsed.values["--address"]
        let symRaw = parsed.values["--function"] ?? parsed.values["--symbol"]

        if addrRaw == nil && symRaw == nil {
            let allRecords = loaded.index.crossReferences.allRecords
            if parsed.isJSON {
                let payload = CLIFullXrefsPayload(
                    count: allRecords.count,
                    fileName: loaded.index.image.fileName,
                    isDemo: loaded.isDemo,
                    xrefCount: allRecords.count,
                    xrefs: allRecords.map(CLIXrefRecordPayload.init)
                )
                let data = try JSONEncoder().encode(payload)
                return String(decoding: data, as: UTF8.self)
            }

            var lines: [String] = []
            if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
                lines.append(banner)
            }
            lines.append("XREFS (\(allRecords.count)):")
            for rec in allRecords {
                lines.append("  \(rec.fromAddress.hexString) -> \(rec.toAddress.hexString) [\(rec.kind.rawValue)] \(rec.instructionPreview)")
            }
            return lines.joined(separator: "\n")
        }

        let targetAddr: VirtualAddress
        if let addrRaw {
            targetAddr = try parseStrictAddress(addrRaw, language: language)
        } else if let symRaw {
            let fn = try resolveRequiredFunction(in: loaded.index, symbolQuery: symRaw, addressQuery: nil, language: language)
            targetAddr = fn.address
        } else {
            targetAddr = .zero
        }

        let incoming = loaded.index.crossReferences.xrefsTo(address: targetAddr)
        let outgoing = loaded.index.crossReferences.xrefsFrom(address: targetAddr)

        if parsed.isJSON {
            func encodeXref(_ rec: XrefRecord) -> [String: Any] {
                [
                    "fromAddress": rec.fromAddress.rawValue,
                    "fromAddressHex": rec.fromAddress.hexString,
                    "fromFunction": rec.fromFunction.map { NSNumber(value: $0.rawValue) } ?? NSNull(),
                    "toAddress": rec.toAddress.rawValue,
                    "toAddressHex": rec.toAddress.hexString,
                    "kind": rec.kind.rawValue,
                    "instructionPreview": rec.instructionPreview
                ]
            }
            let dict: [String: Any] = [
                "fileName": loaded.index.image.fileName,
                "isDemo": loaded.isDemo,
                "address": targetAddr.rawValue,
                "addressHex": targetAddr.hexString,
                "incoming": incoming.map(encodeXref),
                "outgoing": outgoing.map(encodeXref)
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append("XREFS TO \(targetAddr.hexString) (\(incoming.count)):")
        for rec in incoming {
            lines.append("  <- \(rec.fromAddress.hexString) [\(rec.kind.rawValue)] \(rec.instructionPreview)")
        }
        lines.append("XREFS FROM \(targetAddr.hexString) (\(outgoing.count)):")
        for rec in outgoing {
            lines.append("  -> \(rec.toAddress.hexString) [\(rec.kind.rawValue)] \(rec.instructionPreview)")
        }
        return lines.joined(separator: "\n")
    }

    private func runCodeSign(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "codesign",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "codesign", language: language)
        let cs = target.image.codeSignature
        let verification = try? MachOAdHocReSigner().verifyCodeSignature(
            in: target.data,
            sliceIndex: target.image.selectedSliceIndex
        )

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "isSigned": cs.isSigned,
                "isAdHoc": cs.isAdHoc,
                "flags": cs.flags,
                "flagsHex": String(format: "0x%x", cs.flags),
                "identifier": cs.identifier,
                "teamIdentifier": cs.teamIdentifier ?? NSNull(),
                "cdHash": cs.cdHashHex,
                "hashAlgorithm": cs.hashAlgorithm,
                "pageSize": cs.pageSize,
                "codeDirectoryVersion": cs.codeDirectoryVersion,
                "verified": verification?.isValid ?? false,
                "entitlements": cs.entitlementsJSONObject(),
                "cmsSigners": cs.cmsSignerCommonNames
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append(
            "Signed=\(cs.isSigned) AdHoc=\(cs.isAdHoc) Identifier=\(cs.identifier) CDHash=\(cs.cdHashHex) Hash=\(cs.hashAlgorithm) Verified=\(verification?.isValid ?? false) Entitlements=\(cs.entitlements.count)"
        )
        return lines.joined(separator: "\n")
    }

    private func runEntropy(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "entropy",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "entropy", language: language)
        let report = SlidingWindowEntropyProfiler().analyzeFullProfile(
            data: target.data,
            image: target.image,
            windowSize: 1024,
            stepSize: 512
        )

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "shannonEntropyBits": report.overallMetrics.shannonEntropyBits,
                "byteChiSquare": report.overallMetrics.byteChiSquare,
                "zeroByteRatio": report.overallMetrics.zeroByteRatio,
                "anomalyCount": report.anomalies.count,
                "sampleCount": report.samples.count
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        if let banner = demoBannerLine(isDemo: target.isDemo, language: language) {
            lines.append(banner)
        }
        lines.append(
            String(
                format: "OverallEntropy=%.4f bits/byte | ChiSquare=%.2f | ZeroRatio=%.3f | Anomalies=%d | Samples=%d",
                report.overallMetrics.shannonEntropyBits,
                report.overallMetrics.byteChiSquare,
                report.overallMetrics.zeroByteRatio,
                report.anomalies.count,
                report.samples.count
            )
        )
        return lines.joined(separator: "\n")
    }

    private func runPatchAsm(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "patch-asm",
            valueFlags: ["--binary", "--slice", "--address", "--asm", "--output", "-o"],
            boolFlags: ["--force", "--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "patch-asm", language: language)
        guard let addrText = parsed.values["--address"],
              let asmText = parsed.values["--asm"] else {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Usage: machgraph patch-asm <file> --address <0x...> --asm \"mov w0, #1; ret\" [--output <out>]",
                    "用法: machgraph patch-asm <文件> --address <0x...> --asm \"mov w0, #1; ret\" [--output <输出路径>]"
                )
            )
        }
        let vmAddr = try parseStrictAddress(addrText, language: language)
        guard let fileOff = target.image.fileOffset(for: vmAddr) else {
            throw MachGraphError.patchFormatError("Virtual address \(vmAddr.hexString) is not backed by file bytes.")
        }
        let baseOverlay = try SparseCoWByteOverlayBuffer(baseData: target.data, image: target.image)
        let patchRecord = try InlineARM64InstructionPatcher().patchInstruction(
            at: fileOff,
            virtualAddress: vmAddr,
            withAssembly: asmText,
            in: baseOverlay,
            image: target.image,
            allowClobberingBranchTargets: parsed.boolFlags.contains("--force")
        )
        let reSigned = try MachOAdHocReSigner().reSignMachO(
            binaryData: target.data,
            patches: [patchRecord],
            sliceIndex: target.image.selectedSliceIndex
        )
        let outPath = parsed.values["--output"] ?? parsed.values["-o"]
        if let outPath {
            try reSigned.signedBinaryData.write(to: URL(fileURLWithPath: outPath), options: .atomic)
        }

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "address": vmAddr.rawValue,
                "addressHex": vmAddr.hexString,
                "originalAssembly": patchRecord.originalAssembly ?? "",
                "patchedAssembly": patchRecord.patchedAssembly ?? asmText,
                "byteCount": patchRecord.byteCount,
                "updatedCDHash": reSigned.updatedCDHashHex,
                "valid": reSigned.verificationReport.isValid,
                "outputPath": outPath ?? NSNull()
            ]
            return try Self.encodeJSONObject(dict)
        }

        return "Patched \(vmAddr.hexString) (\(patchRecord.originalAssembly ?? "bytes") -> \(patchRecord.patchedAssembly ?? asmText)) | NewCDHash=\(reSigned.updatedCDHashHex) | Valid=\(reSigned.verificationReport.isValid)"
    }

    private enum AsmStatementOutcome {
        case ok(word: UInt32)
        case unsupported(mnemonic: String, form: String)
        case error(reason: String)
    }

    private func runAsm(args: [String], language: MachLanguage) throws -> MachCLIOutcome {
        let parsed = try parseArguments(
            args,
            subcommand: "asm",
            valueFlags: ["--asm", "--at"],
            boolFlags: ["--json"],
            language: language
        )
        if let pos = parsed.positionals.first {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Subcommand 'asm' does not accept positional arguments (got '\(pos)'). Pass '--asm \"...\"' or supply statements on standard input.",
                    "子命令 'asm' 不接受位置参数（收到 '\(pos)'）。请传入 '--asm \"...\"' 或通过标准输入提供语句。"
                )
            )
        }

        let baseAddress: VirtualAddress
        if let rawAt = parsed.values["--at"] {
            baseAddress = try parseStrictAddress(rawAt, language: language)
        } else {
            baseAddress = .zero
        }

        let rawSource: String
        if let inlineAsm = parsed.values["--asm"] {
            rawSource = inlineAsm
        } else {
            do {
                rawSource = try readStandardInput()
            } catch let mgErr as MachGraphError {
                throw mgErr
            } catch {
                throw MachGraphError.ioFailure(
                    language.select(
                        "Unable to read standard input: \(error.localizedDescription)",
                        "无法读取标准输入: \(error.localizedDescription)"
                    )
                )
            }
        }

        let statements = A64MiniAssembler.splitStatements(rawSource)
        guard !statements.isEmpty else {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "No assembly statements provided for 'asm'. Pass '--asm \"<insn>\"' or provide statements on standard input.",
                    "未向 'asm' 提供任何汇编语句。请传入 '--asm \"<指令>\"' 或通过标准输入提供语句。"
                )
            )
        }

        let assembler = A64MiniAssembler()
        var okCount = 0
        var unsupportedCount = 0
        var errorCount = 0
        var outcomes: [AsmStatementOutcome] = []
        outcomes.reserveCapacity(statements.count)

        for (idx, stmt) in statements.enumerated() {
            let addr = baseAddress.adding(UInt64(idx) &* 4)
            do {
                let word = try assembler.assembleSingle(stmt, at: addr)
                okCount += 1
                outcomes.append(.ok(word: word))
            } catch let MachGraphError.assemblerUnsupported(mnemonic, form) {
                unsupportedCount += 1
                outcomes.append(.unsupported(mnemonic: mnemonic, form: form))
            } catch let MachGraphError.assemblerError(_, _, reason) {
                errorCount += 1
                outcomes.append(.error(reason: reason))
            } catch let mgErr as MachGraphError {
                errorCount += 1
                outcomes.append(.error(reason: mgErr.localizedMessage(in: language)))
            } catch {
                errorCount += 1
                outcomes.append(.error(reason: error.localizedDescription))
            }
        }

        let exitCode: Int32
        if errorCount > 0 {
            exitCode = 1
        } else if unsupportedCount > 0 {
            exitCode = 3
        } else {
            exitCode = 0
        }

        let stderrSummary: String
        if exitCode == 0 {
            stderrSummary = ""
        } else {
            stderrSummary = language.select(
                "MachGraph asm summary: \(okCount) ok, \(unsupportedCount) unsupported, \(errorCount) error.",
                "MachGraph asm 汇总: 成功 \(okCount) 条，不支持 \(unsupportedCount) 条，错误 \(errorCount) 条。"
            )
        }

        if parsed.isJSON {
            var json = ""
            json.reserveCapacity(statements.count * 108 + 160)
            json.append("{\n  \"at\": \"")
            json.append(Self.formatCompactHex64(baseAddress.rawValue))
            json.append("\",\n  \"summary\": {\"ok\": ")
            json.append(String(okCount))
            json.append(", \"unsupported\": ")
            json.append(String(unsupportedCount))
            json.append(", \"error\": ")
            json.append(String(errorCount))
            json.append("},\n  \"results\": [\n")
            for (idx, stmt) in statements.enumerated() {
                if idx > 0 {
                    json.append(",\n")
                }
                let addrRaw = baseAddress.adding(UInt64(idx) &* 4).rawValue
                json.append("    {\"index\": ")
                json.append(String(idx))
                json.append(", \"address\": \"")
                json.append(Self.formatCompactHex64(addrRaw))
                json.append("\", \"text\": ")
                Self.appendJSONEscapedString(stmt, into: &json)
                switch outcomes[idx] {
                case .ok(let word):
                    json.append(", \"status\": \"ok\", \"word\": \"")
                    json.append(Self.formatHexWord32(word))
                    json.append("\"}")
                case .unsupported(let mnemonic, let form):
                    json.append(", \"status\": \"unsupported\", \"word\": null, \"mnemonic\": ")
                    Self.appendJSONEscapedString(mnemonic, into: &json)
                    json.append(", \"form\": ")
                    Self.appendJSONEscapedString(form, into: &json)
                    json.append("}")
                case .error(let reason):
                    json.append(", \"status\": \"error\", \"word\": null, \"reason\": ")
                    Self.appendJSONEscapedString(reason, into: &json)
                    json.append("}")
                }
            }
            json.append("\n  ]\n}")
            return MachCLIOutcome(output: json, stderr: stderrSummary, exitCode: exitCode)
        }

        var textOut = ""
        textOut.reserveCapacity(statements.count * 56)
        for (idx, stmt) in statements.enumerated() {
            if idx > 0 {
                textOut.append("\n")
            }
            let addrRaw = baseAddress.adding(UInt64(idx) &* 4).rawValue
            textOut.append(Self.formatPaddedHex64(addrRaw))
            textOut.append("\t")
            let cleanStmt = Self.sanitizeSingleLineField(stmt)
            switch outcomes[idx] {
            case .ok(let word):
                textOut.append(Self.formatHexWord32(word))
                textOut.append("\tok\t")
                textOut.append(cleanStmt)
            case .unsupported(_, let form):
                textOut.append("-\tunsupported\t")
                textOut.append(cleanStmt)
                textOut.append("\t")
                textOut.append(Self.sanitizeSingleLineField(form))
            case .error(let reason):
                textOut.append("-\terror\t")
                textOut.append(cleanStmt)
                textOut.append("\t")
                textOut.append(Self.sanitizeSingleLineField(reason))
            }
        }
        return MachCLIOutcome(output: textOut, stderr: stderrSummary, exitCode: exitCode)
    }

    private static let lowerHexDigits: StaticString = "0123456789abcdef"

    private static func formatHexWord32(_ word: UInt32) -> String {
        lowerHexDigits.withUTF8Buffer { digits in
            var bytes: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) = (
                digits[Int((word >> 28) & 0xF)],
                digits[Int((word >> 24) & 0xF)],
                digits[Int((word >> 20) & 0xF)],
                digits[Int((word >> 16) & 0xF)],
                digits[Int((word >> 12) & 0xF)],
                digits[Int((word >> 8) & 0xF)],
                digits[Int((word >> 4) & 0xF)],
                digits[Int(word & 0xF)]
            )
            return withUnsafeBytes(of: &bytes) { raw in
                String(decoding: raw, as: UTF8.self)
            }
        }
    }

    private static func formatPaddedHex64(_ value: UInt64) -> String {
        lowerHexDigits.withUTF8Buffer { digits in
            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 18) { buf in
                buf[0] = 0x30
                buf[1] = 0x78
                for k in 0..<16 {
                    let shift = UInt64((15 - k) * 4)
                    buf[2 + k] = digits[Int((value >> shift) & 0xF)]
                }
                return String(decoding: buf, as: UTF8.self)
            }
        }
    }

    private static func formatCompactHex64(_ value: UInt64) -> String {
        "0x" + String(value, radix: 16)
    }

    private static func sanitizeSingleLineField(_ value: String) -> String {
        var copy = value
        let needsClean = copy.withUTF8 { buf in
            buf.contains { $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }
        }
        guard needsClean else { return value }
        return value
            .replacingOccurrences(of: "\t", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
    }

    private static func appendJSONEscapedString(_ value: String, into out: inout String) {
        out.append("\"")
        var copy = value
        let fastSafe = copy.withUTF8 { buf in
            for b in buf {
                if b < 0x20 || b == 0x22 || b == 0x5C {
                    return false
                }
            }
            return true
        }
        if fastSafe {
            out.append(value)
            out.append("\"")
            return
        }
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: out.append("\\\"")
            case 0x5C: out.append("\\\\")
            case 0x08: out.append("\\b")
            case 0x0C: out.append("\\f")
            case 0x0A: out.append("\\n")
            case 0x0D: out.append("\\r")
            case 0x09: out.append("\\t")
            case 0x00..<0x20:
                out.append(String(format: "\\u%04x", scalar.value))
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        out.append("\"")
    }

    private func runDemangle(args: [String], language: MachLanguage) throws -> String {
        var isJSON = false
        var symbols: [String] = []
        var idx = 0
        while idx < args.count {
            let tok = args[idx]
            if tok == "--" {
                symbols.append(contentsOf: args[(idx + 1)...])
                break
            }
            if tok == "--json" {
                isJSON = true
                idx += 1
                continue
            }
            // Allow Objective-C instance method signatures (`-[Class sel]`) as positional symbols without `--`.
            if tok.hasPrefix("-") && tok != "-" && !tok.hasPrefix("-[") {
                let flagName: String
                if let eqIdx = tok.firstIndex(of: "=") {
                    flagName = String(tok[..<eqIdx])
                } else {
                    flagName = tok
                }
                throw MachGraphError.invalidCLIArguments(
                    language.select(
                        "Unknown option '\(flagName)' for subcommand 'demangle'.",
                        "子命令 'demangle' 不支持选项 '\(flagName)'。"
                    )
                )
            }
            symbols.append(tok)
            idx += 1
        }

        if symbols.isEmpty {
            let rawStdin: String
            do {
                rawStdin = try readStandardInput()
            } catch let mgErr as MachGraphError {
                throw mgErr
            } catch {
                throw MachGraphError.ioFailure(
                    language.select(
                        "Unable to read standard input: \(error.localizedDescription)",
                        "无法读取标准输入: \(error.localizedDescription)"
                    )
                )
            }
            if !rawStdin.isEmpty {
                var body = rawStdin
                if body.hasSuffix("\r\n") {
                    body.removeLast(2)
                } else if body.hasSuffix("\n") || body.hasSuffix("\r") {
                    body.removeLast()
                }
                symbols = body.split(separator: "\n", omittingEmptySubsequences: false).map { slice in
                    if slice.hasSuffix("\r") {
                        return String(slice.dropLast())
                    }
                    return String(slice)
                }
            }
        }

        let demangler = SymbolDemangler.shared
        if isJSON {
            if symbols.isEmpty {
                return "[]"
            }
            var json = "[\n"
            json.reserveCapacity(symbols.count * 96 + 8)
            for (i, inputSym) in symbols.enumerated() {
                if i > 0 {
                    json.append(",\n")
                }
                let outputSym = demangler.demangle(inputSym)
                let wasDemangled = (outputSym != inputSym)
                json.append("  {\"input\": ")
                Self.appendJSONEscapedString(inputSym, into: &json)
                json.append(", \"output\": ")
                Self.appendJSONEscapedString(outputSym, into: &json)
                json.append(", \"demangled\": ")
                json.append(wasDemangled ? "true" : "false")
                json.append("}")
            }
            json.append("\n]")
            return json
        }

        if symbols.isEmpty {
            return ""
        }
        var textOut = ""
        textOut.reserveCapacity(symbols.count * 48)
        for (i, inputSym) in symbols.enumerated() {
            if i > 0 {
                textOut.append("\n")
            }
            textOut.append(demangler.demangle(inputSym))
        }
        return textOut
    }

    private func runResign(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "resign",
            valueFlags: ["--binary", "--slice", "--identifier", "--output", "-o"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let target = try loadContainerOnly(parsed: parsed, subcommand: "resign", language: language)
        let reSigned = try MachOAdHocReSigner().reSignMachO(
            binaryData: target.data,
            sliceIndex: target.image.selectedSliceIndex,
            identifier: parsed.values["--identifier"]
        )
        let outPath = parsed.values["--output"] ?? parsed.values["-o"]
        if let outPath {
            try reSigned.signedBinaryData.write(to: URL(fileURLWithPath: outPath), options: .atomic)
        }

        if parsed.isJSON {
            let dict: [String: Any] = [
                "fileName": target.image.fileName,
                "isDemo": target.isDemo,
                "updatedCDHash": reSigned.updatedCDHashHex,
                "valid": reSigned.verificationReport.isValid,
                "outputPath": outPath ?? NSNull()
            ]
            return try Self.encodeJSONObject(dict)
        }

        return "Ad-hoc re-signed \(target.image.fileName) | CDHash=\(reSigned.updatedCDHashHex) | Valid=\(reSigned.verificationReport.isValid)"
    }

    private func runAuditPlugins(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "audit-plugins",
            valueFlags: ["--binary", "--slice"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "audit-plugins", language: language)
        let report = try MachPluginRunner().runSuite(
            against: loaded.index,
            binaryData: loaded.data,
            continueOnError: true
        )

        if parsed.isJSON {
            let findingsJSON = try JSONEncoder().encode(report.findings)
            let findingsArray = (try? JSONSerialization.jsonObject(with: findingsJSON)) ?? []
            let dict: [String: Any] = [
                "experimental": true,
                "fileName": loaded.index.image.fileName,
                "isDemo": loaded.isDemo,
                "pluginCount": report.results.count,
                "findingCount": report.findings.count,
                "findings": findingsArray
            ]
            return try Self.encodeJSONObject(dict)
        }

        var lines: [String] = []
        lines.append(
            language.select(
                "# EXPERIMENTAL: Static heuristic plugin output — false positives and false negatives are known.",
                "# 【实验性】静态启发式插件输出：已知存在误报与漏报。"
            )
        )
        if let banner = demoBannerLine(isDemo: loaded.isDemo, language: language) {
            lines.append(banner)
        }
        if report.findings.isEmpty {
            lines.append("0 security findings across \(report.results.count) plugins.")
        } else {
            for f in report.findings {
                lines.append("[\(f.severity.rawValue)] \(f.address?.hexString ?? "image") (\(f.pluginID)) \(f.localizedTitle(in: language)) - \(f.localizedDetail(in: language))")
            }
        }
        return lines.joined(separator: "\n")
    }

    private func runExportHTML(args: [String], language: MachLanguage) throws -> String {
        let parsed = try parseArguments(
            args,
            subcommand: "export-html",
            valueFlags: ["--binary", "--slice", "--output", "-o"],
            boolFlags: ["--json", "--demo"],
            language: language
        )
        let loaded = try loadAndAnalyzeCFG(parsed: parsed, subcommand: "export-html", language: language)
        let html = try ColdTungstenHTMLReportExporter().exportHTMLReport(
            analysisIndex: loaded.index,
            binaryData: loaded.data,
            isDemo: loaded.isDemo
        )
        let outPath = parsed.values["--output"] ?? parsed.values["-o"]
        if let outPath {
            try html.write(toFile: outPath, atomically: true, encoding: .utf8)
            if parsed.isJSON {
                return try Self.encodeJSONObject([
                    "fileName": loaded.index.image.fileName,
                    "isDemo": loaded.isDemo,
                    "outputPath": outPath,
                    "byteCount": html.utf8.count
                ])
            }
            return "Exported Cold-Tungsten HTML triage dossier to \(outPath)"
        }
        if parsed.isJSON {
            return try Self.encodeJSONObject([
                "fileName": loaded.index.image.fileName,
                "isDemo": loaded.isDemo,
                "byteCount": html.utf8.count,
                "html": html
            ])
        }
        return html
    }

    // MARK: - Strict CLI Argument Parsing & Binary Loading

    private struct ParsedCLIArguments {
        let positionals: [String]
        let values: [String: String]
        let boolFlags: Set<String>

        var isJSON: Bool { boolFlags.contains("--json") }
        var isDemo: Bool { boolFlags.contains("--demo") }
    }

    private func parseArguments(
        _ args: [String],
        subcommand: String,
        valueFlags: Set<String>,
        boolFlags: Set<String>,
        language: MachLanguage
    ) throws -> ParsedCLIArguments {
        var positionals: [String] = []
        var values: [String: String] = [:]
        var activeBools: Set<String> = []

        var idx = 0
        while idx < args.count {
            let tok = args[idx]
            if tok == "--" {
                positionals.append(contentsOf: args[(idx + 1)...])
                break
            }
            if tok.hasPrefix("-") && tok != "-" {
                if let eqIdx = tok.firstIndex(of: "=") {
                    let flagName = String(tok[..<eqIdx])
                    let flagValue = String(tok[tok.index(after: eqIdx)...])
                    guard valueFlags.contains(flagName) else {
                        throw MachGraphError.invalidCLIArguments(
                            language.select(
                                "Unknown option '\(flagName)' for subcommand '\(subcommand)'.",
                                "子命令 '\(subcommand)' 不支持选项 '\(flagName)'。"
                            )
                        )
                    }
                    values[flagName] = flagValue
                    idx += 1
                    continue
                }
                if valueFlags.contains(tok) {
                    guard idx + 1 < args.count else {
                        throw MachGraphError.invalidCLIArguments(
                            language.select(
                                "Option '\(tok)' requires a value.",
                                "选项 '\(tok)' 需要提供参数值。"
                            )
                        )
                    }
                    values[tok] = args[idx + 1]
                    idx += 2
                    continue
                }
                if boolFlags.contains(tok) {
                    activeBools.insert(tok)
                    idx += 1
                    continue
                }
                throw MachGraphError.invalidCLIArguments(
                    language.select(
                        "Unknown option '\(tok)' for subcommand '\(subcommand)'.",
                        "子命令 '\(subcommand)' 不支持选项 '\(tok)'。"
                    )
                )
            } else {
                positionals.append(tok)
                idx += 1
            }
        }

        if positionals.count > 1 {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Unexpected extra positional argument '\(positionals[1])' for '\(subcommand)'.",
                    "子命令 '\(subcommand)' 收到多余的位置参数 '\(positionals[1])'。"
                )
            )
        }
        if values["--binary"] != nil && !positionals.isEmpty {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Specify either a positional <file> path or '--binary <file>', not both.",
                    "请只指定位置参数 <文件> 或 '--binary <文件>' 之一，不要同时传入。"
                )
            )
        }

        return ParsedCLIArguments(positionals: positionals, values: values, boolFlags: activeBools)
    }

    private func resolveInputFileURL(
        parsed: ParsedCLIArguments,
        subcommand: String,
        language: MachLanguage
    ) throws -> (url: URL, isDemo: Bool) {
        if parsed.isDemo {
            if parsed.values["--binary"] != nil || !parsed.positionals.isEmpty {
                throw MachGraphError.invalidCLIArguments(
                    language.select(
                        "Cannot combine '--demo' with an explicit binary file path.",
                        "不能同时使用 '--demo' 与显式文件路径。"
                    )
                )
            }
            let demoURL = try Self.locateDemoBinaryURL(language: language)
            return (demoURL, true)
        }

        guard let rawPath = parsed.values["--binary"] ?? parsed.positionals.first,
              !rawPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Missing binary file path. Usage: machgraph \(subcommand) <file> (or pass --demo for the sample binary).",
                    "缺少二进制文件路径。用法: machgraph \(subcommand) <文件>（或传入 --demo 载入演示样本）。"
                )
            )
        }

        let url = try Self.validatedRegularInputFileURL(rawPath: rawPath, language: language)
        return (url, false)
    }

    /// Resolves an input path and rejects anything that is not a readable regular file with an accurate reason:
    /// missing paths, directories, and special files such as `/dev/null` (character devices, FIFOs, sockets).
    static func validatedRegularInputFileURL(rawPath: String, language: MachLanguage) throws -> URL {
        let url = URL(fileURLWithPath: rawPath)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
            throw MachGraphError.fileNotFound(rawPath)
        }
        if isDir.boolValue {
            throw MachGraphError.ioFailure(
                language.select(
                    "'\(rawPath)' is a directory; pass the Mach-O binary file path inside it.",
                    "'\(rawPath)' 是目录，请传入其中的 Mach-O 二进制文件路径。"
                )
            )
        }
        // `fileExists` follows symlinks, so inspect the link target as well.
        let resolvedPath = url.resolvingSymlinksInPath().path
        if let fileType = (try? FileManager.default.attributesOfItem(atPath: resolvedPath))?[.type] as? FileAttributeType,
           fileType != .typeRegular {
            let kind: (en: String, zh: String)
            switch fileType {
            case .typeCharacterSpecial: kind = ("a character device", "字符设备")
            case .typeBlockSpecial: kind = ("a block device", "块设备")
            case .typeSocket: kind = ("a socket", "套接字")
            default: kind = ("a special file", "特殊文件")
            }
            throw MachGraphError.ioFailure(
                language.select(
                    "'\(rawPath)' is not a regular file (it is \(kind.en)); pass a Mach-O binary file.",
                    "'\(rawPath)' 不是普通文件（它是\(kind.zh)），请传入 Mach-O 二进制文件。"
                )
            )
        }
        return url
    }

    private func loadContainerOnly(
        parsed: ParsedCLIArguments,
        subcommand: String,
        language: MachLanguage
    ) throws -> (data: Data, image: LoadedBinaryImage, isDemo: Bool) {
        let resolved = try resolveInputFileURL(parsed: parsed, subcommand: subcommand, language: language)
        let sliceIndex: Int?
        if let rawSlice = parsed.values["--slice"] {
            guard let s = Int(rawSlice), s >= 0 else {
                throw MachGraphError.invalidCLIArguments(
                    language.select("Invalid '--slice' index '\(rawSlice)'.", "无效的 '--slice' 切片索引 '\(rawSlice)'。")
                )
            }
            sliceIndex = s
        } else {
            sliceIndex = nil
        }

        let data: Data
        do {
            data = try Data(contentsOf: resolved.url)
        } catch {
            throw MachGraphError.ioFailure(
                language.select(
                    "Unable to read '\(resolved.url.path)': \(error.localizedDescription)",
                    "无法读取文件 '\(resolved.url.path)': \(error.localizedDescription)"
                )
            )
        }
        guard !data.isEmpty else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 4, available: 0)
        }
        let image = try UniversalBinaryDispatcher.load(
            data: data,
            filePath: resolved.url.path,
            fileName: resolved.url.lastPathComponent,
            preferredSliceIndex: sliceIndex
        )
        return (data, image, resolved.isDemo)
    }

    private func loadAndAnalyzeCFG(
        parsed: ParsedCLIArguments,
        subcommand: String,
        language: MachLanguage
    ) throws -> (data: Data, index: BinaryAnalysisIndex, isDemo: Bool) {
        let container = try loadContainerOnly(parsed: parsed, subcommand: subcommand, language: language)
        let cliOptions = BinaryAnalysisOptions(
            computeSugiyamaLayouts: false,
            computePostDominatorTrees: false
        )
        let coordinator = BinaryAnalysisCoordinator(options: cliOptions)
        let index = try coordinator.analyzeBinary(container.image, data: container.data)
        return (container.data, index, container.isDemo)
    }

    private func resolveRequiredFunction(
        in index: BinaryAnalysisIndex,
        symbolQuery: String?,
        addressQuery: String?,
        language: MachLanguage
    ) throws -> RecoveredFunction {
        if let addressQuery {
            let addr = try parseStrictAddress(addressQuery, language: language)
            if let exact = index.functions.first(where: { $0.address == addr }) {
                return exact
            }
            if let containing = index.functions.first(where: { addr >= $0.address && addr < $0.endAddress }) {
                return containing
            }
            throw MachGraphError.cfgAnalysisError(
                language.select(
                    "No function found at address '\(addressQuery)' in '\(index.image.fileName)'.",
                    "在 '\(index.image.fileName)' 中未找到位于地址 '\(addressQuery)' 的函数。"
                )
            )
        }

        if let symbolQuery {
            let trimmed = symbolQuery.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw MachGraphError.invalidCLIArguments(
                    language.select("Function/symbol name must not be empty.", "函数或符号名称不能为空。")
                )
            }
            let qLower = trimmed.lowercased()
            let prefixed = qLower.hasPrefix("_") ? qLower : "_\(qLower)"

            if let exact = index.functions.first(where: {
                let n = $0.name.lowercased()
                let d = $0.demangledName.lowercased()
                return n == qLower || n == prefixed || d == qLower
            }) {
                return exact
            }
            if let partial = index.functions.first(where: {
                $0.name.lowercased().contains(qLower) || $0.demangledName.lowercased().contains(qLower)
            }) {
                return partial
            }
            throw MachGraphError.cfgAnalysisError(
                language.select(
                    "Function or symbol '\(trimmed)' not found in '\(index.image.fileName)'.",
                    "在 '\(index.image.fileName)' 中未找到函数或符号 '\(trimmed)'。"
                )
            )
        }

        throw MachGraphError.invalidCLIArguments(
            language.select("Specify '--symbol <name>' or '--address <0x...>'.", "请指定 '--symbol <名称>' 或 '--address <0x...>'。")
        )
    }

    private func parseStrictAddress(_ raw: String, language: MachLanguage) throws -> VirtualAddress {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("0x") {
            let hex = String(trimmed.dropFirst(2))
            if let val = UInt64(hex, radix: 16) {
                return VirtualAddress(val)
            }
        } else if let val = UInt64(trimmed, radix: 10) {
            return VirtualAddress(val)
        } else if let val = UInt64(trimmed, radix: 16) {
            return VirtualAddress(val)
        }
        throw MachGraphError.invalidCLIArguments(
            language.select(
                "Invalid virtual address '\(raw)'. Expected hexadecimal (0x...) or decimal integer.",
                "无效的虚拟地址 '\(raw)'，应为十六进制 (0x...) 或十进制整数。"
            )
        )
    }

    private func demoBannerLine(isDemo: Bool, language: MachLanguage) -> String? {
        guard isDemo else { return nil }
        return language.select(
            "[DEMO] Loaded sample fixture Fixtures/demo_arm64_sample (explicit --demo mode)",
            "[演示数据] 已载入演示样本 Fixtures/demo_arm64_sample（显式 --demo 模式）"
        )
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

    // MARK: - Demo Fixture Discovery, JSON Encoding & Help Generation

    public static func locateDemoBinaryURL(language: MachLanguage = .en) throws -> URL {
        let fm = FileManager.default
        if let envOverride = ProcessInfo.processInfo.environment["MACHGRAPH_DEMO_BINARY"],
           !envOverride.isEmpty,
           fm.fileExists(atPath: envOverride) {
            return URL(fileURLWithPath: envOverride)
        }
        if let bundled = Bundle.main.url(forResource: "demo_arm64_sample", withExtension: nil),
           fm.fileExists(atPath: bundled.path) {
            return bundled
        }

        var searchRoots: [URL] = [
            URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
        ]
        if let argv0 = CommandLine.arguments.first, !argv0.isEmpty {
            let rawExec = URL(fileURLWithPath: argv0)
            searchRoots.append(rawExec.deletingLastPathComponent())
            searchRoots.append(rawExec.resolvingSymlinksInPath().deletingLastPathComponent())
        }
        for bundle in Bundle.allBundles {
            searchRoots.append(bundle.bundleURL.deletingLastPathComponent())
        }

        for root in searchRoots {
            var cursor = root
            for _ in 0..<6 {
                let candidate = cursor.appendingPathComponent("Fixtures/demo_arm64_sample", isDirectory: false)
                if fm.fileExists(atPath: candidate.path) {
                    return candidate
                }
                let parent = cursor.deletingLastPathComponent()
                if parent.path == cursor.path { break }
                cursor = parent
            }
        }

        throw MachGraphError.fileNotFound(
            language.select(
                "Fixtures/demo_arm64_sample (demo binary fixture not found)",
                "Fixtures/demo_arm64_sample（未找到演示样本二进制文件）"
            )
        )
    }

    private static func encodeInstructionJSON(_ insn: A64DecodedInstruction) -> [String: Any] {
        [
            "address": insn.address.rawValue,
            "addressHex": insn.address.hexString,
            "rawWord": insn.rawWord,
            "rawWordHex": String(format: "%08x", insn.rawWord),
            "mnemonic": insn.mnemonicText,
            "operands": insn.operandText,
            "disassembly": insn.formattedDisassembly
        ]
    }

    fileprivate static func encodeJSONObject(_ object: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    public static func validateAndResolveLanguage(from args: [String]) throws -> MachLanguage {
        var idx = 0
        while idx < args.count {
            let tok = args[idx]
            if tok == "--lang" || tok == "--language" {
                guard idx + 1 < args.count, let parsed = MachLanguage.parse(args[idx + 1]) else {
                    throw MachGraphError.invalidCLIArguments(
                        "Invalid or missing value for '\(tok)'. Expected 'en' or 'zh'."
                    )
                }
                _ = parsed
                idx += 2
                continue
            }
            if tok.hasPrefix("--lang=") || tok.hasPrefix("--language=") {
                let raw = tok.split(separator: "=", maxSplits: 1).dropFirst().first.map(String.init)
                guard let parsed = MachLanguage.parse(raw) else {
                    throw MachGraphError.invalidCLIArguments(
                        "Invalid language value in '\(tok)'. Expected 'en' or 'zh'."
                    )
                }
                _ = parsed
            }
            idx += 1
        }
        return MachLanguage.resolve(arguments: args)
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

    public static func versionBanner(in language: MachLanguage) -> String {
        language.select(
            "MachGraph 1.4.0 (macOS arm64 · Mach-O & Universal Loader + ARM64 Disassembler & CFG · 中文/EN)",
            "MachGraph 1.4.0 (macOS arm64 · Mach-O 与通用二进制加载器 + ARM64 反汇编与控制流图 · 中文/EN)"
        )
    }

    public static var helpBanner: String {
        helpBanner(in: .en)
    }

    public static func helpBanner(in language: MachLanguage) -> String {
        var lines: [String] = []
        lines.append(
            language.select(
                "MachGraph 1.4.0 - macOS ARM64 & Mach-O Binary Inspector, Disassembler & CFG Analyzer (中文 / EN)",
                "MachGraph 1.4.0 - macOS ARM64 与 Mach-O 二进制检视、反汇编与控制流图分析工具 (中文 / EN)"
            )
        )
        lines.append(
            language.select(
                "Usage: machgraph <subcommand> <file> [options]",
                "用法: machgraph <子命令> <文件> [选项]"
            )
        )
        lines.append(language.select("Global Options:", "全局选项:"))
        lines.append(
            language.select(
                "  --lang <en|zh>                                      Set output or UI language (env: MACHGRAPH_LANG=en|zh)",
                "  --lang <en|zh>                                      设置命令行或界面语言 (环境变量: MACHGRAPH_LANG=en|zh)"
            )
        )
        lines.append(
            language.select(
                "  --demo                                              Load sample fixture Fixtures/demo_arm64_sample with [DEMO] tag",
                "  --demo                                              显式载入演示样本 Fixtures/demo_arm64_sample 并标注 [演示数据]"
            )
        )
        lines.append(
            language.select(
                "  --binary <path>                                     Equivalent flag form for positional <file>",
                "  --binary <路径>                                     与位置参数 <文件> 等价的文件路径写法"
            )
        )
        lines.append(
            language.select(
                "  --help, -h                                          Show this help text",
                "  --help, -h                                          显示本帮助说明"
            )
        )
        lines.append(
            language.select(
                "  --version                                           Show version string",
                "  --version                                           显示版本信息"
            )
        )
        lines.append(language.select("Subcommand Options:", "子命令选项:"))
        for option in subcommandOptionSpecs {
            let left = option.flags.padding(toLength: max(52, option.flags.count + 2), withPad: " ", startingAt: 0)
            lines.append("  \(left)\(language.select(option.summaryEN, option.summaryZH))")
        }
        lines.append(language.select("Subcommands:", "子命令:"))
        for spec in subcommandSpecs {
            let argsCol = language.select(spec.usageArgsEN, spec.usageArgsZH)
            let descCol = language.select(spec.summaryEN, spec.summaryZH)
            let left = "\(spec.primaryName) \(argsCol)".trimmingCharacters(in: .whitespaces)
            let padded = left.padding(toLength: max(50, left.count + 2), withPad: " ", startingAt: 0)
            lines.append("  \(padded)\(descCol)")
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - JSON-RPC 2.0 Reverse-Engineering MCP Server (`MachMCPServer`)

public struct MachMCPServer: Sendable {
    public let defaultBinaryPath: String?
    public let language: MachLanguage

    public init(defaultBinaryPath: String? = nil, language: MachLanguage = .en) {
        self.defaultBinaryPath = defaultBinaryPath
        self.language = language
    }

    public static var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "mach_inspect_binary",
                "description": "Load a Mach-O / Universal binary from disk and return architecture, segment, function, Xref, and CodeSignature summary.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string", "description": "Path to binary file on disk."]
                    ],
                    "required": ["binaryPath"]
                ]
            ],
            [
                "name": "mach_decompile_function",
                "description": "[Experimental] Emit Pseudo-C for a recovered ARM64/ARM64e function (condition expressions are known to be unreliable).",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string"],
                        "function": ["type": "string", "description": "Function name or hex address (e.g. _main or 0x100001028)."]
                    ],
                    "required": ["binaryPath", "function"]
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
                    "required": ["binaryPath", "address"]
                ]
            ],
            [
                "name": "mach_audit_security",
                "description": "[Experimental] Execute JavaScriptCore static binary audit plugins.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "binaryPath": ["type": "string"]
                    ],
                    "required": ["binaryPath"]
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
                    "serverInfo": ["name": "machgraph-mcp", "version": "1.4.0"]
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
                let query = ((arguments["function"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                guard !query.isEmpty else {
                    return textResult(
                        language.select("Missing required parameter 'function'.", "缺少必填参数 'function'。"),
                        isError: true
                    )
                }
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
                    return textResult(
                        language.select(
                            "Function '\(query)' not found in '\(loaded.index.image.fileName)'.",
                            "在 '\(loaded.index.image.fileName)' 中未找到函数 '\(query)'。"
                        ),
                        isError: true
                    )
                }
                let output = MachMicroDecompilerEngine().decompile(function: fn, in: loaded.index, language: language)
                return textResult(output.fullSourceText, isError: false)

            case "mach_query_xrefs":
                guard let rawAddr = arguments["address"] as? String, !rawAddr.isEmpty else {
                    return textResult(
                        language.select("Missing required parameter 'address'.", "缺少必填参数 'address'。"),
                        isError: true
                    )
                }
                let clean = rawAddr.lowercased().hasPrefix("0x") ? String(rawAddr.dropFirst(2)) : rawAddr
                guard let parsedVal = UInt64(clean, radix: 16) else {
                    return textResult(
                        language.select("Invalid hex address '\(rawAddr)'.", "无效的十六进制地址 '\(rawAddr)'。"),
                        isError: true
                    )
                }
                let addr = VirtualAddress(parsedVal)
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
                let warning = language.select(
                    "// EXPERIMENTAL: Static heuristic audit findings\n",
                    "// 【实验性】静态启发式安全审计发现\n"
                )
                return textResult(warning + String(decoding: data, as: UTF8.self), isError: false)

            default:
                return textResult("Unknown tool '\(name)'", isError: true)
            }
        } catch let mgErr as MachGraphError {
            return textResult(mgErr.localizedMessage(in: language), isError: true)
        } catch {
            return textResult(error.localizedDescription, isError: true)
        }
    }

    private func resolveBinary(from arguments: [String: Any]) throws -> (data: Data, index: BinaryAnalysisIndex) {
        let rawPath = ((arguments["binaryPath"] as? String) ?? defaultBinaryPath)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let path = rawPath, !path.isEmpty else {
            throw MachGraphError.invalidCLIArguments(
                language.select(
                    "Missing required 'binaryPath' argument for MCP tool call.",
                    "MCP 工具调用缺少必填参数 'binaryPath'。"
                )
            )
        }
        let url = try MachCLIRunner.validatedRegularInputFileURL(rawPath: path, language: language)
        let data = try Data(contentsOf: url)
        let cliOptions = BinaryAnalysisOptions(
            computeSugiyamaLayouts: false,
            computePostDominatorTrees: false
        )
        let coordinator = BinaryAnalysisCoordinator(options: cliOptions)
        let idx = try coordinator.analyzeBinary(data: data, filePath: url.path, fileName: url.lastPathComponent)
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
