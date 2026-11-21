import Combine
import Foundation

// MARK: - Bilingual Language Model & Live In-App Localizer (中文 / EN)

public enum MachLanguage: String, Sendable, Codable, Hashable, CaseIterable, Identifiable {
    case zhHans = "zh-Hans"
    case en = "en"

    public static let userDefaultsKey = "io.github.zxu756.MachGraph.language"
    public static let environmentVariableKey = "MACHGRAPH_LANG"

    public var id: String { rawValue }

    /// Compact pill badge label (`"中文"` or `"EN"`).
    public var badge: String {
        switch self {
        case .zhHans: return "中文"
        case .en: return "EN"
        }
    }

    /// Human-readable display name (`"简体中文"` or `"English"`).
    public var displayName: String {
        switch self {
        case .zhHans: return "简体中文"
        case .en: return "English"
        }
    }

    /// BCP-47 tag suitable for HTML `lang` attribute.
    public var htmlLangTag: String {
        switch self {
        case .zhHans: return "zh-CN"
        case .en: return "en"
        }
    }

    /// Opposite language for quick `中文 <-> EN` toggling.
    public var toggled: MachLanguage {
        self == .zhHans ? .en : .zhHans
    }

    /// Parses common language codes (`zh`, `zh-Hans`, `zh-CN`, `en`, `en-US`, `中文`, `EN`).
    public static func parse(_ raw: String?) -> MachLanguage? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        let lower = trimmed.lowercased()
        if lower == "中文" || lower == "chs" || lower == "chinese" || lower.hasPrefix("zh") {
            return .zhHans
        }
        if lower == "english" || lower.hasPrefix("en") {
            return .en
        }
        return nil
    }

    /// Extracts `--lang <zh|en>` or `--lang=<zh|en>` from command-line arguments.
    public static func extractCLIArgumentLanguage(from arguments: [String]) -> MachLanguage? {
        var resolved: MachLanguage?
        var idx = 0
        while idx < arguments.count {
            let arg = arguments[idx]
            if arg == "--lang", idx + 1 < arguments.count {
                if let parsed = parse(arguments[idx + 1]) {
                    resolved = parsed
                }
                idx += 2
                continue
            } else if arg.hasPrefix("--lang=") {
                let value = String(arg.dropFirst("--lang=".count))
                if let parsed = parse(value) {
                    resolved = parsed
                }
            }
            idx += 1
        }
        return resolved
    }

    /// Deterministic priority chain:
    /// 1. CLI `--lang zh|en`
    /// 2. Env `MACHGRAPH_LANG=zh|en`
    /// 3. `UserDefaults` (`io.github.zxu756.MachGraph.language`)
    /// 4. `Locale.preferredLanguages.first` starting with `"zh"` -> `.zhHans` (else `.en`).
    public static func resolve(
        arguments: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        userDefaults: UserDefaults = .standard,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> MachLanguage {
        if let cliLang = extractCLIArgumentLanguage(from: arguments) {
            return cliLang
        }
        if let envLang = parse(environment[environmentVariableKey]) {
            return envLang
        }
        if let savedRaw = userDefaults.string(forKey: userDefaultsKey),
           let savedLang = parse(savedRaw) {
            return savedLang
        }
        if let primaryLocale = preferredLanguages.first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(),
           primaryLocale.hasPrefix("zh") {
            return .zhHans
        }
        return .en
    }

    /// Inline localization selector without requiring `@MainActor` isolation.
    @inline(__always)
    public func select(_ en: String, _ zh: String) -> String {
        self == .zhHans ? zh : en
    }
}

/// Live observable bilingual localizer driving instant `中文 / EN` SwiftUI & AppKit updates.
@MainActor
public final class MachLocalizer: ObservableObject {
    public static let languageDefaultsKey = MachLanguage.userDefaultsKey
    public static let languageDidChangeNotification = Notification.Name("io.github.zxu756.MachGraph.languageDidChange")

    public static let shared = MachLocalizer()

    private let userDefaults: UserDefaults
    public var persistsToUserDefaults: Bool
    private var suppressNextPersistence = false

    @Published public var language: MachLanguage {
        didSet {
            let shouldPersist = persistsToUserDefaults && !suppressNextPersistence
            suppressNextPersistence = false
            guard oldValue != language else { return }
            if shouldPersist {
                userDefaults.set(language.rawValue, forKey: Self.languageDefaultsKey)
            }
            NotificationCenter.default.post(name: Self.languageDidChangeNotification, object: self)
        }
    }

    public init(
        arguments: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        userDefaults: UserDefaults = .standard,
        preferredLanguages: [String] = Locale.preferredLanguages,
        persistsToUserDefaults: Bool = true
    ) {
        self.userDefaults = userDefaults
        self.persistsToUserDefaults = persistsToUserDefaults
        self.language = MachLanguage.resolve(
            arguments: arguments,
            environment: environment,
            userDefaults: userDefaults,
            preferredLanguages: preferredLanguages
        )
    }

    public var isChinese: Bool {
        language == .zhHans
    }

    /// Primary bilingual string selector (`en` vs `zh`).
    @inline(__always)
    public func L(_ en: String, _ zh: String) -> String {
        language == .zhHans ? zh : en
    }

    /// Updates active language, optionally writing to `UserDefaults`.
    public func setLanguage(_ newLanguage: MachLanguage, persist: Bool = true) {
        if !persist {
            suppressNextPersistence = true
        }
        if language == newLanguage {
            suppressNextPersistence = false
            if persist && persistsToUserDefaults {
                userDefaults.set(newLanguage.rawValue, forKey: Self.languageDefaultsKey)
            }
            return
        }
        language = newLanguage
    }

    /// Toggles between Simplified Chinese (`中文`) and English (`EN`).
    @discardableResult
    public func toggleLanguage(persist: Bool = true) -> MachLanguage {
        let next = language.toggled
        setLanguage(next, persist: persist)
        return next
    }

    /// Re-evaluates CLI/env/defaults/locale priority without clobbering stored user defaults.
    @discardableResult
    public func bootstrapFromEnvironment(
        arguments: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        preferredLanguages: [String] = Locale.preferredLanguages
    ) -> MachLanguage {
        let resolved = MachLanguage.resolve(
            arguments: arguments,
            environment: environment,
            userDefaults: userDefaults,
            preferredLanguages: preferredLanguages
        )
        setLanguage(resolved, persist: false)
        return resolved
    }
}

/// Concise `@MainActor` localization helper forwarding to `MachLocalizer.shared`.
@MainActor
@inline(__always)
public func MGL(_ en: String, _ zh: String) -> String {
    MachLocalizer.shared.L(en, zh)
}

// MARK: - Localized Display Extensions on Shared Workbench Enums

extension WorkbenchPaneTab {
    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .cfgGraph:
            return language.select("CFG Graph", "控制流图")
        case .disassembly:
            return language.select("Disassembly", "反汇编")
        case .pseudoC:
            return language.select("Pseudo-C (Exp)", "伪C (实验)")
        case .hexPatcher:
            return language.select("Hex & Patch", "十六进制与补丁")
        case .stringsAndObjC:
            return language.select("Strings & ObjC", "字符串与ObjC")
        case .entropyAndSign:
            return language.select("Entropy & Sign", "熵谱与签名")
        case .pluginFindings:
            return language.select("Plugin Audit", "插件审计")
        }
    }

    public func localizedFullTitle(in language: MachLanguage) -> String {
        switch self {
        case .cfgGraph:
            return language.select("CFG Graph", "控制流图")
        case .disassembly:
            return language.select("Linear Disassembly", "线性反汇编")
        case .pseudoC:
            return language.select("Pseudo-C Decompiler", "伪C反编译器")
        case .hexPatcher:
            return language.select("Hex & Patcher", "十六进制与补丁")
        case .stringsAndObjC:
            return language.select("Strings & Runtime", "字符串与ObjC")
        case .entropyAndSign:
            return language.select("Entropy & CodeSign", "熵谱与代码签名")
        case .pluginFindings:
            return language.select("Plugin Audit", "插件安全审计")
        }
    }

    @MainActor
    public var localizedTitle: String {
        localizedTitle(in: MachLocalizer.shared.language)
    }

    @MainActor
    public var localizedFullTitle: String {
        localizedFullTitle(in: MachLocalizer.shared.language)
    }
}

extension NavigatorSidebarFilter {
    public func localizedTitle(in language: MachLanguage) -> String {
        switch self {
        case .functions:
            return language.select("Functions", "函数")
        case .symbols:
            return language.select("Symbols", "符号")
        case .imports:
            return language.select("Imports", "导入")
        case .strings:
            return language.select("Strings", "字符串")
        case .classes:
            return language.select("ObjC / Swift", "ObjC / Swift")
        case .bookmarks:
            return language.select("Bookmarks", "书签")
        case .patches:
            return language.select("Patches", "补丁")
        }
    }

    public func localizedFilterPlaceholder(in language: MachLanguage) -> String {
        switch self {
        case .functions:
            return language.select("Filter functions...", "筛选函数...")
        case .symbols:
            return language.select("Filter symbols...", "筛选符号...")
        case .imports:
            return language.select("Filter imports...", "筛选导入符号...")
        case .strings:
            return language.select("Filter strings...", "筛选字符串...")
        case .classes:
            return language.select("Filter ObjC / Swift types...", "筛选 ObjC / Swift 类型...")
        case .bookmarks:
            return language.select("Filter bookmarks...", "筛选书签...")
        case .patches:
            return language.select("Filter patches...", "筛选补丁...")
        }
    }

    @MainActor
    public var localizedTitle: String {
        localizedTitle(in: MachLocalizer.shared.language)
    }

    @MainActor
    public var localizedFilterPlaceholder: String {
        localizedFilterPlaceholder(in: MachLocalizer.shared.language)
    }
}

extension SecurityFindingSeverity {
    public func localizedBadge(in language: MachLanguage) -> String {
        switch self {
        case .info:
            return language.select("INFO", "信息")
        case .low:
            return language.select("LOW", "低危")
        case .medium:
            return language.select("MEDIUM", "中危")
        case .high:
            return language.select("HIGH", "高危")
        case .critical:
            return language.select("CRITICAL", "严重")
        }
    }

    public func localizedSentenceBadge(in language: MachLanguage) -> String {
        switch self {
        case .info:
            return language.select("Info", "信息")
        case .low:
            return language.select("Low", "低危")
        case .medium:
            return language.select("Medium", "中危")
        case .high:
            return language.select("High", "高危")
        case .critical:
            return language.select("Critical", "严重")
        }
    }

    @MainActor
    public var localizedBadge: String {
        localizedBadge(in: MachLocalizer.shared.language)
    }
}

extension XrefKind {
    public func localizedBadge(in language: MachLanguage) -> String {
        switch self {
        case .directCall:
            return language.select("CALL", "直接调用")
        case .indirectCall:
            return language.select("ICALL", "间接调用")
        case .unconditionalJump:
            return language.select("JMP", "无条件跳转")
        case .conditionalBranch:
            return language.select("BRANCH", "条件分支")
        case .codeReference:
            return language.select("CODE_REF", "代码引用")
        case .dataPointerRead:
            return language.select("DATA_READ", "数据读取")
        case .dataPointerWrite:
            return language.select("DATA_WRITE", "数据写入")
        case .stringReference:
            return language.select("STRING_REF", "字符串引用")
        case .pageBaseADRP:
            return language.select("ADRP_PAGE", "页基址")
        case .chainedFixupTarget:
            return language.select("FIXUP_PTR", "链式修复")
        }
    }

    @MainActor
    public var localizedBadge: String {
        localizedBadge(in: MachLocalizer.shared.language)
    }
}

extension MachPluginManifest {
    public func localizedName(in language: MachLanguage) -> String {
        guard language == .zhHans else { return name }
        switch id {
        case "hardcoded-secret-key-scanner":
            return "硬编码凭证、API 密钥与授权令牌扫描器"
        case "dangerous-c-sink-reachability":
            return "内存不安全与命令注入危险调用审计器"
        case "arm64e-pac-gadget-auditor":
            return "ARM64e 指针认证与 JOP/ROP 跳板检查器"
        case "entitlement-privilege-auditor":
            return "macOS 权限声明、进程调试与动态库注入审计器"
        default:
            return name
        }
    }

    public func localizedSummary(in language: MachLanguage) -> String {
        guard language == .zhHans else { return summary }
        switch id {
        case "hardcoded-secret-key-scanner":
            return "扫描字符串常量与交叉引用中的云端/AI API 密钥、PEM 私钥、JWT、Bearer 令牌与内嵌授权码，并关联引用函数。"
        case "dangerous-c-sink-reachability":
            return "审计导入符号与全局 BFS 调用路径中的无界内存拷贝、命令执行 API、动态加载入口、格式化字符串与非常量时间认证比较。"
        case "arm64e-pac-gadget-auditor":
            return "审计 ARM64/ARM64e 函数与基本块中的未签名间接跳转 (br/blr)、未保护栈帧返回 (ret) 及分离式 PAC 验签时间窗。"
        case "entitlement-privilege-auditor":
            return "审计内嵌 Mach-O 代码签名、强化运行时标志、RWX 段以及 get-task-allow、库校验豁免与动态库注入等高风险权限声明。"
        default:
            return summary
        }
    }
}

extension AnalystTransactionRecord {
    public func localizedTitle(in language: MachLanguage) -> String {
        guard language == .zhHans else { return title }
        switch operation {
        case .setRename(_, let updated):
            if let updated {
                return "重命名符号为 '\(updated.customName)' @ \(updated.address.compactHexString)"
            }
            return "清除符号重命名"
        case .setComment(_, let updated):
            if let updated {
                return "设置内联注释 @ \(updated.address.compactHexString)"
            }
            return "移除内联注释"
        case .setBookmark(_, let updated):
            if let updated {
                return "添加书签 '\(updated.label)' @ \(updated.address.compactHexString)"
            }
            return "移除书签"
        case .setPatch(_, let updated):
            if let updated {
                return "写入 \(updated.byteCount) 字节 CoW 补丁 @ \(updated.fileOffset.hexString)"
            }
            return "移除字节补丁"
        case .setStruct(_, let updated):
            if let updated {
                return "保存自定义 C 结构体 '\(updated.name)'"
            }
            return "删除自定义 C 结构体"
        }
    }
}

extension SecurityAuditFinding {
    public func localizedPluginName(in language: MachLanguage) -> String {
        guard language == .zhHans else { return pluginName }
        switch pluginID {
        case "hardcoded-secret-key-scanner":
            return "硬编码凭证与授权令牌扫描器"
        case "dangerous-c-sink-reachability":
            return "危险 C 函数可达性审计器"
        case "arm64e-pac-gadget-auditor":
            return "ARM64e PAC 与控制流完整性检查器"
        case "entitlement-privilege-auditor":
            return "macOS 权限声明与签名审计器"
        default:
            return pluginName
        }
    }

    public func localizedCategory(in language: MachLanguage) -> String {
        guard language == .zhHans else { return category }
        let map: [String: String] = [
            "Cloud Credential Leak": "云凭证泄漏",
            "AI Service Credential Leak": "AI 服务密钥泄漏",
            "Source Control Credential Leak": "源码托管令牌泄漏",
            "Third-Party API Key Leak": "第三方 API 密钥泄漏",
            "Cryptographic Key Material": "密码学私钥材料",
            "Static Bearer Credential": "静态 Bearer 凭证",
            "Hardcoded Auth Secret": "硬编码认证密钥",
            "Hardcoded Static Verification Token": "硬编码静态校验令牌",
            "Internal Endpoint Disclosure": "内部服务端点暴露",
            "Embedded License / Auth Secret": "内嵌授权令牌/密钥",
            "Authentication & Timing Side-Channel (CWE-208)": "认证时序侧信道 (CWE-208)",
            "Format String Audit (CWE-134)": "格式化字符串审计 (CWE-134)",
            "Command Execution Sink (CWE-78)": "命令执行危险点 (CWE-78)",
            "OS Command Execution (CWE-78)": "系统命令执行 (CWE-78)",
            "Unbounded Stack/Heap Buffer Write (CWE-242)": "无界栈/堆缓冲区写入 (CWE-242)",
            "Unbounded Memory Copy (CWE-120)": "无界内存拷贝 (CWE-120)",
            "Unbounded Formatted Write (CWE-120)": "无界格式化缓冲区写入 (CWE-120)",
            "Unbounded Formatted Input (CWE-120)": "无界格式化输入 (CWE-120)",
            "Dynamic Code Loading": "动态代码加载",
            "Dynamic Code Loading (CWE-426)": "动态代码加载 (CWE-426)",
            "Dynamic Symbol Resolution": "动态符号解析",
            "Control-Flow Integrity / PAC": "控制流完整性 / PAC",
            "PAC Signing / Stripping Window": "PAC 验签时间窗",
            "ARM64e Stack Return Hardening": "ARM64e 栈返回加固",
            "ARM64 CFI Hardening Posture": "ARM64 CFI 加固态势",
            "Memory Protection / W^X Violation": "内存保护 / W^X 违规",
            "Code Signing Integrity": "代码签名完整性",
            "Code Signing Trust Chain": "代码签名信任链",
            "Hardened Runtime Posture": "强化运行时态势",
            "Task-for-PID / Debugger Attachment": "进程调试注入权限",
            "Task Port / Debugger Attachment": "调试端口附加权限",
            "System Debugger Privilege": "系统级调试器特权",
            "JIT / Unsigned Executable Memory": "JIT / 未签名可执行内存",
            "JIT Executable Memory": "JIT 可执行内存",
            "Executable Memory Relaxation": "可执行内存保护放宽",
            "Code Integrity Bypass": "代码页签名强制绕过",
            "Dynamic Library Validation Bypass": "动态库签名校验绕过",
            "Dyld Library Validation Bypass": "Dyld 动态库校验绕过",
            "Dyld Environment Variable Injection": "Dyld 环境变量注入",
            "Dyld Environment Injection": "Dyld 环境变量注入",
            "Private TCC Privacy Entitlement": "私有 TCC 隐私权限豁免",
            "Private Apple Platform Entitlement": "受限私有平台权限"
        ]
        return map[category] ?? category
    }

    public func localizedTitle(in language: MachLanguage) -> String {
        guard language == .zhHans else { return title }
        var out = title
        let replacements: [(String, String)] = [
            ("Hardcoded Static Verification / Entitlement Token in Binary", "二进制内硬编码静态授权/校验令牌"),
            ("Embedded AWS IAM Access Key Identifier", "内嵌 AWS IAM 访问密钥标识"),
            ("Embedded OpenAI API Secret Key", "内嵌 OpenAI API 私钥"),
            ("Embedded Anthropic API Secret Key", "内嵌 Anthropic API 私钥"),
            ("Embedded GitHub Personal or Fine-Grained Access Token", "内嵌 GitHub 访问令牌"),
            ("Embedded Cloud / SaaS Provider API Key", "内嵌云端 / SaaS API 密钥"),
            ("Embedded PEM Asymmetric Private Key Header", "内嵌 PEM 非对称私钥头"),
            ("Hardcoded JSON Web Token (JWT) in String Table", "字符串表内硬编码 JWT 令牌"),
            ("Hardcoded Bearer Token or API Secret Assignment", "硬编码 Bearer 令牌或 API 密钥赋值"),
            ("Internal Corporate or Non-TLS Endpoint URL in Binary", "内嵌内部域名或明文 HTTP 端点 URL"),
            ("Embedded Static License / Product Key", "内嵌静态授权码 / 产品密钥"),
            ("Embedded High-Entropy Bearer / API Secret", "内嵌高熵 Bearer / API 密钥"),
            ("Early-Exit String/Memory Comparison", "可提前退出的字符串/内存比较"),
            (" in Security-Sensitive Function ", " (位于安全敏感函数 "),
            (" in Auth Function ", " (位于认证函数 "),
            ("Inherently Unsafe Unbounded Input Sink `gets`", "极高危无界输入函数 `gets`"),
            ("Unbounded String Copy Sink `strcpy`", "无界字符串拷贝函数 `strcpy`"),
            ("Unbounded String Concatenation Sink `strcat`", "无界字符串拼接函数 `strcat`"),
            ("Unbounded Formatted Buffer Sink `sprintf`", "无界格式化缓冲区写入 `sprintf`"),
            ("Unbounded Variadic Buffer Sink `vsprintf`", "无界可变参缓冲区写入 `vsprintf`"),
            ("Potentially Unbounded `scanf` Input Sink", "潜在无界格式化输入 `scanf`"),
            ("Shell Command Execution Sink `system`", "Shell 系统命令执行点 `system`"),
            ("Shell Pipe Command Sink `popen`", "Shell 管道命令执行点 `popen`"),
            ("Runtime Dynamic Library Loader `dlopen`", "运行时动态库加载入口 `dlopen`"),
            ("Dynamic Symbol Lookup `dlsym`", "动态符号查找入口 `dlsym`"),
            (" Reachable from ", " · 可从入口到达: "),
            ("Unsigned Indirect Function Call (", "未启用 PAC 的间接函数调用 ("),
            (") Without PAC", ")"),
            ("Unsigned Switch Jump-Table Dispatch (", "未签名 Switch 跳转表分发 ("),
            ("Unsigned Indirect Jump (", "未签名寄存器间接跳转 ("),
            ("Standalone PAC Strip/Auth Instruction ", "分离式 PAC 剥离/验签指令 "),
            (" in `", " · 位于 `"),
            ("Non-PAC `ret` Epilogues in Stack-Frame Functions on `arm64e` Image", "`arm64e` 镜像栈帧函数存在未启用 PAC 的 `ret` 返回序列"),
            ("Standard `arm64` Slice Without Pointer Authentication (`paciasp`/`retaa`)", "标准 `arm64` 架构切片未启用指针认证 (`paciasp`/`retaa`)"),
            ("Simultaneously Writable & Executable Segment ", "同时具备可写与可执行权限 (RWX) 的段 "),
            ("Unsigned Mach-O Binary (`LC_CODE_SIGNATURE` Missing)", "未签名 Mach-O 二进制 (缺失 `LC_CODE_SIGNATURE`)"),
            ("Ad-Hoc Signed Mach-O Binary (`CS_ADHOC`)", "Mach-O 二进制采用临时签名 (`CS_ADHOC`)"),
            ("Hardened Runtime (`CS_RUNTIME` 0x00010000) Not Enabled", "未启用 macOS 强化运行时 (`CS_RUNTIME` 0x00010000)"),
            ("Debuggable Task Port Entitlement (`get-task-allow`)", "已开启调试任务端口权限 (`get-task-allow`)"),
            ("Debugger / Task-for-PID Entitlement Enabled (`com.apple.security.get-task-allow`)", "已开启调试器进程附加权限 (`com.apple.security.get-task-allow`)"),
            ("Privileged Debugger Entitlement (`cs.debugger`)", "已开启系统级调试器特权 (`cs.debugger`)"),
            ("MAP_JIT Executable Memory Entitlement (`cs.allow-jit`)", "已开启 MAP_JIT 动态代码内存权限 (`cs.allow-jit`)"),
            ("JIT Executable Memory Entitlement Enabled (`com.apple.security.cs.allow-jit`)", "已开启 JIT 可执行内存权限 (`com.apple.security.cs.allow-jit`)"),
            ("Arbitrary Unsigned Executable Memory Enabled (`allow-unsigned-executable-memory`)", "允许映射任意未签名可执行内存 (`allow-unsigned-executable-memory`)"),
            ("Unsigned Executable Memory Allowed (`com.apple.security.cs.allow-unsigned-executable-memory`)", "允许映射未签名可执行内存 (`allow-unsigned-executable-memory`)"),
            ("Library Validation Disabled (`cs.disable-library-validation`)", "已关闭动态库签名校验 (`cs.disable-library-validation`)"),
            ("Library Validation Disabled (`com.apple.security.cs.disable-library-validation`)", "已关闭动态库签名校验 (`disable-library-validation`)"),
            ("Dyld Environment Variables Allowed (`allow-dyld-environment-variables`)", "允许 Dyld 环境变量注入 (`allow-dyld-environment-variables`)"),
            ("Dyld Environment Variable Injection Enabled (`com.apple.security.cs.allow-dyld-environment-variables`)", "允许 Dyld 环境变量注入 (`allow-dyld-environment-variables`)"),
            ("Executable Page Code-Signing Enforcement Disabled", "已禁用可执行页代码签名强制校验"),
            ("Private TCC Bypass Entitlement (", "私有 TCC 隐私豁免权限 ("),
            ("Restricted Private Entitlement (", "受限 Apple 私有平台权限 (")
        ]
        for (src, dst) in replacements {
            out = out.replacingOccurrences(of: src, with: dst)
        }
        if out.contains("(位于安全敏感函数 ") && !out.hasSuffix(")") {
            out += ")"
        }
        return out
    }

    public func localizedDetail(in language: MachLanguage) -> String {
        guard language == .zhHans else { return detail }
        var out = detail
        let replacements: [(String, String)] = [
            ("Referenced by ", "引用函数: "),
            ("Located in ", "位于节区 "),
            (". String literal at ", "。字符串常量位于 "),
            (" bytes). Xref trace: ", " 字节)。交叉引用轨迹: "),
            ("Remediation: Comparing against a static plaintext token embedded in __cstring exposes the secret to trivial string extraction. Use asymmetric cryptographic signature verification (Ed25519 / ECDSA) instead.", "修复建议: 与 __cstring 节内嵌静态明文令牌直接比对极易被字符串提取绕过；建议改用非对称签名校验 (Ed25519 / ECDSA)。"),
            ("Remediation: Load runtime secrets from macOS Keychain Services (SecItemCopyMatching) or environment-isolated configuration.", "修复建议: 请通过 macOS 钥匙串服务 (SecItemCopyMatching) 或隔离配置加载运行时密钥。"),
            ("Remediation: Audit internal staging/telemetry hostnames before release to prevent internal infrastructure reconnaissance.", "修复建议: 发版前请清理测试环境与内部遥测域名，防止内网基础设施暴露。"),
            ("Function invokes ", "函数调用了 "),
            (" call site(s)). Shortest call path: ", " 处调用点)。最短调用链: "),
            (" hop(s)). Standard ", " 跳)。标准库 "),
            (" terminates on the first mismatched byte, leaking prefix match timing and exposing secret material in registers. Remediation: Use `timingsafe_bcmp` / `CCDigest` HMAC verification or asymmetric signature validation.", " 在遇到首个不匹配字节时立即返回，会泄漏前缀比对时序侧信道并在寄存器中暴露明文凭证。修复建议: 改用常量时间比较 `timingsafe_bcmp`、HMAC 摘要校验或非对称签名验证。"),
            ("Instruction `", "指令 `"),
            ("` at ", "` 位于 "),
            (" inside `", " (所属函数 `"),
            ("` transfers control through register `", "`) 通过寄存器 `"),
            ("` without Pointer Authentication (`braa`/`blraa`).", "` 进行间接控制流转移，未启用 PAC 指针认证 (`braa`/`blraa`)。"),
            (" Jump table at ", " 关联跳转表基址 "),
            (" case targets).", " 个分支目标)。"),
            (" Remediation: Compile with `-arch arm64e` or `-mbranch-protection=standard` so indirect call/vtable targets are cryptographically authenticated.", " 修复建议: 使用 `-arch arm64e` 或 `-mbranch-protection=standard` 编译，对间接跳转与虚表目标启用硬件指针签名验证。"),
            ("Binary slice is tagged `arm64e`, yet ", "当前架构切片标记为 `arm64e`，但仍有 "),
            (" non-leaf / stack-allocating function(s) return via unsigned `ret` without `paciasp`/`retaa`: ", " 个非叶子/栈帧分配函数使用未签名的 `ret` 指令返回 (未配对 `paciasp`/`retaa`): "),
            ("Remediation: Enable `-mbranch-protection=pac-ret+leaf` across all translation units and static archives.", "修复建议: 在所有编译单元与静态库中统一开启 `-mbranch-protection=pac-ret+leaf`。"),
            ("Grants `task_for_pid` / debugger attachment rights to same-UID processes, allowing runtime memory inspection, register modification, and credential extraction if left enabled in release builds.", "授予同 UID 进程 `task_for_pid` 调试附加权限；若保留在发布版中，将允许运行时内存读取、寄存器篡改与凭证提取。"),
            ("Enables `MAP_JIT` dynamic code generation pages (`pthread_jit_write_protect_np`). Confirm the binary actually embeds a hardened JS/Wasm JIT runtime; remove if unused.", "允许分配 `MAP_JIT` 动态代码生成页 (`pthread_jit_write_protect_np`)。请确认目标确实内嵌受加固的 JS/Wasm JIT 引擎，否则应在发布版中移除。"),
            ("Remove `", "若非必需，请从发布版 `.entitlements` 配置中移除 `"),
            ("` from release `.entitlements` plists unless strictly required.", "`。"),
            ("Remediation: ", "修复建议: ")
        ]
        for (src, dst) in replacements {
            out = out.replacingOccurrences(of: src, with: dst)
        }
        return out
    }
}

extension A64InstructionGroup {
    public func localizedTitle(in language: MachLanguage) -> String {
        guard language == .zhHans else { return rawValue }
        switch self {
        case .dataProcessingImm: return "数据处理 (立即数)"
        case .dataProcessingReg: return "数据处理 (寄存器)"
        case .branchAndSystem: return "分支、异常与系统指令"
        case .loadStore: return "访存加载与存储"
        case .simdAndFP: return "SIMD 向量与浮点运算"
        case .pacPointerAuth: return "指针认证 (ARMv8.3 PAC)"
        case .atomicLSE: return "原子操作扩展 (LSE)"
        case .unknown: return "未分配 / 原始机器字"
        }
    }
}
