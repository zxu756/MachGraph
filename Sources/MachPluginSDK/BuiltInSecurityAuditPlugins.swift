import Foundation
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine

// MARK: - Built-In JavaScriptCore Reverse-Engineering & Security Audit Plugin Catalog

public enum BuiltInMachPluginCatalog: Sendable {

    public static let hardcodedSecretKeyScannerID = "hardcoded-secret-key-scanner"
    public static let dangerousCSinkReachabilityID = "dangerous-c-sink-reachability"
    public static let arm64ePACGadgetAuditorID = "arm64e-pac-gadget-auditor"
    public static let entitlementPrivilegeAuditorID = "entitlement-privilege-auditor"

    /// All 4 built-in JavaScriptCore security audit plugins in canonical execution order.
    public static var allPlugins: [MachPluginManifest] {
        [
            hardcodedSecretKeyScanner,
            dangerousCSinkReachability,
            arm64ePACGadgetAuditor,
            entitlementPrivilegeAuditor
        ]
    }

    public static var defaultEnabledPluginIDs: Set<String> {
        Set(allPlugins.map(\.id))
    }

    public static func plugin(withID id: String) -> MachPluginManifest? {
        allPlugins.first { $0.id == id }
    }

    // MARK: 1. Hardcoded Credentials, API Keys & License Token Scanner

    public static let hardcodedSecretKeyScanner = MachPluginManifest(
        id: hardcodedSecretKeyScannerID,
        name: "Hardcoded Credentials, API Keys & License Token Scanner",
        version: "1.7.0",
        author: "MachGraph Security Audit Team",
        summary: "Scans extracted string literals and cross-references for cloud/AI API keys, PEM private keys, JWTs, Bearer tokens, and embedded static tokens, correlating each hit to referencing functions.",
        capabilities: [
            .readBinaryBytes,
            .readSymbolTable,
            .readControlFlowGraph,
            .writeDatabaseAnnotations,
            .emitSecurityFindings
        ],
        isBuiltIn: true,
        isEnabled: true,
        scriptSource: hardcodedSecretKeyScannerJS
    )

    // MARK: 2. Memory-Unsafe & Command-Injection Sink Auditor

    public static let dangerousCSinkReachability = MachPluginManifest(
        id: dangerousCSinkReachabilityID,
        name: "Memory-Unsafe & Command-Injection Sink Auditor",
        version: "1.7.0",
        author: "MachGraph Security Audit Team",
        summary: "Audits imported symbols and whole-program BFS call paths for unbounded memory copies, command execution APIs, dynamic loader sinks, variadic format strings, and non-constant-time auth comparisons.",
        capabilities: [
            .readSymbolTable,
            .readControlFlowGraph,
            .writeDatabaseAnnotations,
            .emitSecurityFindings
        ],
        isBuiltIn: true,
        isEnabled: true,
        scriptSource: dangerousCSinkReachabilityJS
    )

    // MARK: 3. ARM64E Pointer Authentication & JOP/ROP Gadget Inspector

    public static let arm64ePACGadgetAuditor = MachPluginManifest(
        id: arm64ePACGadgetAuditorID,
        name: "ARM64E Pointer Authentication & JOP/ROP Gadget Inspector",
        version: "1.7.0",
        author: "MachGraph Security Audit Team",
        summary: "Audits recovered ARM64/ARM64e functions and basic blocks for unsigned indirect branches (br/blr vs braa/blraa), unprotected stack-frame returns (ret vs retaa/retab), and split PAC authentication windows.",
        capabilities: [
            .readBinaryBytes,
            .readControlFlowGraph,
            .writeDatabaseAnnotations,
            .emitSecurityFindings
        ],
        isBuiltIn: true,
        isEnabled: true,
        scriptSource: arm64ePACGadgetAuditorJS
    )

    // MARK: 4. macOS Entitlements, Task-for-PID & Dyld Injection Auditor

    public static let entitlementPrivilegeAuditor = MachPluginManifest(
        id: entitlementPrivilegeAuditorID,
        name: "macOS Entitlements, Task-for-PID & Dyld Injection Auditor",
        version: "1.7.0",
        author: "MachGraph Security Audit Team",
        summary: "Audits embedded Mach-O code signatures, Hardened Runtime flags, RWX segments, and entitlements (get-task-allow, disable-library-validation, allow-dyld-environment-variables, allow-unsigned-executable-memory, cs.debugger, and private TCC entitlements).",
        capabilities: [
            .readBinaryBytes,
            .emitSecurityFindings
        ],
        isBuiltIn: true,
        isEnabled: true,
        scriptSource: entitlementPrivilegeAuditorJS
    )

    // MARK: - Embedded JavaScript Source: Plugin 1 (`hardcoded-secret-key-scanner`)

    private static let hardcodedSecretKeyScannerJS: String = #"""
    (function() {
        "use strict";

        const summary = mach.getImageSummary();
        const strings = mach.getStrings();
        console.info("hardcoded-secret-key-scanner: inspecting", strings.length, "extracted string literals in", summary ? summary.fileName : "<binary>");

        const rules = [
            {
                id: "aws-access-key",
                severity: "CRITICAL",
                category: "Cloud Credential Leak",
                title: "Embedded AWS IAM Access Key Identifier",
                pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
                remediation: "Remove embedded AWS IAM credentials from client/server binaries; issue short-lived STS credentials via IAM roles."
            },
            {
                id: "openai-api-key",
                severity: "CRITICAL",
                category: "AI Service Credential Leak",
                title: "Embedded OpenAI API Secret Key",
                pattern: /\bsk-(?:proj-|svcacct-|live-)?[A-Za-z0-9_-]{20,}\b/,
                remediation: "Revoke exposed API key immediately and proxy model requests through an authenticated backend service."
            },
            {
                id: "anthropic-api-key",
                severity: "CRITICAL",
                category: "AI Service Credential Leak",
                title: "Embedded Anthropic API Secret Key",
                pattern: /\bsk-ant-(?:api03-|admin01-)?[A-Za-z0-9_-]{20,}\b/,
                remediation: "Rotate the Anthropic API key and store secrets in server-side secret managers rather than shipping in binary sections."
            },
            {
                id: "github-pat",
                severity: "CRITICAL",
                category: "Source Control Credential Leak",
                title: "Embedded GitHub Personal or Fine-Grained Access Token",
                pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{22,})\b/,
                remediation: "Revoke the GitHub token and replace static tokens with short-lived GitHub App installation tokens."
            },
            {
                id: "slack-stripe-google-key",
                severity: "HIGH",
                category: "Third-Party API Key Leak",
                title: "Embedded Cloud / SaaS Provider API Key",
                pattern: /\b(?:xox[baprs]-[0-9A-Za-z-]{16,}|sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,}|AIza[0-9A-Za-z_-]{35})\b/,
                remediation: "Rotate the third-party API token and restrict key scopes or move privileged calls behind a server gateway."
            },
            {
                id: "pem-private-key",
                severity: "CRITICAL",
                category: "Cryptographic Key Material",
                title: "Embedded PEM Asymmetric Private Key Header",
                pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----/,
                remediation: "Never embed private signing or TLS keys inside distributable binaries; provision per-device keys in the macOS Keychain / Secure Enclave."
            },
            {
                id: "embedded-jwt",
                severity: "HIGH",
                category: "Static Bearer Credential",
                title: "Hardcoded JSON Web Token (JWT) in String Table",
                pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
                remediation: "Avoid shipping pre-signed JWTs in static data sections; mint short-lived session tokens dynamically after user authentication."
            },
            {
                id: "bearer-or-kv-secret",
                severity: "HIGH",
                category: "Hardcoded Auth Secret",
                title: "Hardcoded Bearer Token or API Secret Assignment",
                pattern: /(?:Bearer\s+[A-Za-z0-9._~+\/-]{14,}|(?:api[_-]?key|client[_-]?secret|auth[_-]?token|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9._~+\/-]{8,})/i,
                remediation: "Load runtime secrets from macOS Keychain Services (SecItemCopyMatching) or environment-isolated configuration."
            },
            {
                id: "static-product-token",
                severity: "HIGH",
                category: "Hardcoded Static Verification Token",
                title: "Hardcoded Static Verification / Entitlement Token in Binary",
                pattern: /\b(?:LICENSE-KEY-[A-Z0-9-]{4,}|MASTER[_-]?TOKEN[_-]?[A-Z0-9]{4,})\b/,
                remediation: "Comparing against a static plaintext token embedded in __cstring exposes the secret to trivial string extraction. Use asymmetric cryptographic signature verification (Ed25519 / ECDSA) instead."
            },
            {
                id: "internal-endpoint-leak",
                severity: "LOW",
                category: "Internal Endpoint Disclosure",
                title: "Internal Corporate or Non-TLS Endpoint URL in Binary",
                pattern: /\bhttps?:\/\/[A-Za-z0-9.-]+\.(?:internal|corp|lan|local)(?::\d+)?(?:\/[^\s"']*)?/i,
                remediation: "Audit internal staging/telemetry hostnames before release to prevent internal infrastructure reconnaissance."
            }
        ];

        function previewString(text) {
            const singleLine = String(text).replace(/\r/g, "\\r").replace(/\n/g, "\\n");
            if (singleLine.length <= 72) {
                return singleLine;
            }
            return singleLine.slice(0, 69) + "...";
        }

        function formatXrefSummary(xrefs) {
            if (!xrefs || xrefs.length === 0) {
                return {
                    primaryAddress: null,
                    summaryText: "No direct instruction Xrefs resolved (unreferenced or table-indexed literal)",
                    callerNames: []
                };
            }
            const seenCallers = [];
            const hopDescriptions = [];
            for (let i = 0; i < xrefs.length; i++) {
                const xr = xrefs[i];
                const fnLabel = xr.fromFunctionDemangledName || xr.fromFunctionName || "unknown_fn";
                if (seenCallers.indexOf(fnLabel) === -1) {
                    seenCallers.push(fnLabel);
                }
                if (hopDescriptions.length < 4) {
                    hopDescriptions.push(fnLabel + " @ " + xr.fromAddressHex + " [" + xr.kind + "]");
                }
            }
            const suffix = xrefs.length > 4 ? " (+" + (xrefs.length - 4) + " more)" : "";
            return {
                primaryAddress: xrefs[0].fromAddressHex,
                summaryText: hopDescriptions.join(", ") + suffix,
                callerNames: seenCallers
            };
        }

        let matchCount = 0;
        for (let i = 0; i < strings.length; i++) {
            const lit = strings[i];
            if (!lit || typeof lit.value !== "string" || lit.value.length < 6) {
                continue;
            }

            for (let r = 0; r < rules.length; r++) {
                const rule = rules[r];
                const matched = rule.pattern.exec(lit.value);
                if (!matched) {
                    continue;
                }

                const xrefs = mach.getXrefsTo(lit.addressHex);
                const xrefInfo = formatXrefSummary(xrefs);
                const reportAddress = xrefInfo.primaryAddress || lit.addressHex;
                const snippet = previewString(lit.value);
                const callerNote = xrefInfo.callerNames.length > 0
                    ? "Referenced by " + xrefInfo.callerNames.join(", ")
                    : "Located in " + lit.sectionName + " (" + lit.encoding + ")";

                const detail =
                    callerNote + ". String literal at " + lit.addressHex +
                    " (" + lit.sectionName + ", " + lit.lengthBytes + " bytes). " +
                    "Xref trace: " + xrefInfo.summaryText + ". " +
                    "Remediation: " + rule.remediation;

                const evidence =
                    "str@" + lit.addressHex + " = \"" + snippet + "\"" +
                    (xrefInfo.primaryAddress ? " <- xref " + xrefInfo.summaryText : "");

                mach.emitFinding({
                    severity: rule.severity,
                    category: rule.category,
                    title: rule.title + (xrefInfo.callerNames.length > 0 ? " (" + xrefInfo.callerNames[0] + ")" : ""),
                    detail: detail,
                    addressHex: reportAddress,
                    evidencePreview: evidence
                });

                mach.addComment(
                    reportAddress,
                    "[Audit:" + rule.severity + "] " + rule.title + " -> \"" + snippet + "\""
                );
                if (rule.severity === "CRITICAL" || rule.severity === "HIGH") {
                    mach.addBookmark(reportAddress, "Secret/Token: " + snippet.slice(0, 28), "#F85149");
                }

                matchCount += 1;
                break;
            }
        }

        console.info("hardcoded-secret-key-scanner: completed with", matchCount, "credential/token finding(s)");
    })();
    """#

    // MARK: - Embedded JavaScript Source: Plugin 2 (`dangerous-c-sink-reachability`)

    private static let dangerousCSinkReachabilityJS: String = #"""
    (function() {
        "use strict";

        const imports = mach.getImports();
        const sinkPaths = mach.getDangerousSinkPaths();
        console.info("dangerous-c-sink-reachability: auditing", imports.length, "imports and", sinkPaths.length, "call-graph sink path(s)");

        const sinkCatalog = {
            "gets": {
                severity: "CRITICAL",
                category: "Unbounded Stack/Heap Buffer Write (CWE-242)",
                title: "Inherently Unsafe Unbounded Input Sink `gets`",
                remediation: "Replace `gets` immediately with `fgets(buf, sizeof(buf), stdin)` and validate newline/EOF handling."
            },
            "strcpy": {
                severity: "HIGH",
                category: "Unbounded Memory Copy (CWE-120)",
                title: "Unbounded String Copy Sink `strcpy`",
                remediation: "Replace `strcpy` with `strlcpy(dst, src, dstSize)` or bounds-checked buffer builders."
            },
            "strcat": {
                severity: "HIGH",
                category: "Unbounded Memory Copy (CWE-120)",
                title: "Unbounded String Concatenation Sink `strcat`",
                remediation: "Replace `strcat` with `strlcat(dst, src, dstSize)` and check truncation return values."
            },
            "sprintf": {
                severity: "HIGH",
                category: "Unbounded Formatted Write (CWE-120)",
                title: "Unbounded Formatted Buffer Sink `sprintf`",
                remediation: "Replace `sprintf` with `snprintf(dst, dstSize, fmt, ...)`."
            },
            "vsprintf": {
                severity: "HIGH",
                category: "Unbounded Formatted Write (CWE-120)",
                title: "Unbounded Variadic Buffer Sink `vsprintf`",
                remediation: "Replace `vsprintf` with `vsnprintf(dst, dstSize, fmt, ap)`."
            },
            "scanf": {
                severity: "HIGH",
                category: "Unbounded Formatted Input (CWE-120)",
                title: "Potentially Unbounded `scanf` Input Sink",
                remediation: "Avoid raw `%s` in `scanf`; enforce explicit field widths or parse bounded line buffers."
            },
            "system": {
                severity: "CRITICAL",
                category: "OS Command Execution (CWE-78)",
                title: "Shell Command Execution Sink `system`",
                remediation: "Avoid invoking `/bin/sh -c` via `system()`; use `posix_spawn` / `Process` with an explicit argument array and strict allowlists."
            },
            "popen": {
                severity: "CRITICAL",
                category: "OS Command Execution (CWE-78)",
                title: "Shell Pipe Command Sink `popen`",
                remediation: "Replace shell-interpreted `popen` with `posix_spawn` + `pipe` without shell metacharacter expansion."
            },
            "dlopen": {
                severity: "MEDIUM",
                category: "Dynamic Code Loading (CWE-426)",
                title: "Runtime Dynamic Library Loader `dlopen`",
                remediation: "Ensure `dlopen` paths are canonical, absolute, protected by Hardened Runtime Library Validation, and never derived from untrusted paths."
            },
            "dlsym": {
                severity: "LOW",
                category: "Dynamic Symbol Resolution",
                title: "Dynamic Symbol Lookup `dlsym`",
                remediation: "Verify dynamically resolved function pointers come only from signed system or Team-ID-validated images."
            }
        };

        const formatSinks = { "printf": true, "fprintf": true, "syslog": true, "NSLog": true, "vprintf": true };
        const timingAuthSinks = { "strcmp": true, "strncmp": true, "strcasecmp": true, "strncasecmp": true, "memcmp": true };
        const authNamePattern = /(?:verify|auth|login|token|license|secret|password|passwd|credential|validate|check_key|hmac|sig)/i;

        // Index shortest BFS paths by bare sink name
        const pathsBySink = {};
        for (let i = 0; i < sinkPaths.length; i++) {
            const p = sinkPaths[i];
            const key = String(p.bareSinkName || p.sinkName || "").replace(/^_+/, "");
            if (!pathsBySink[key]) {
                pathsBySink[key] = [];
            }
            pathsBySink[key].push(p);
        }

        function inspectFormatStringCallSite(callerAddrHex, callAddrHex) {
            if (!callerAddrHex || !callAddrHex) {
                return { isDynamicFormat: false, preview: "call site " + (callAddrHex || "unknown") };
            }
            const cfg = mach.getCFG(callerAddrHex);
            if (!cfg || !cfg.blocks) {
                return { isDynamicFormat: false, preview: "call site " + callAddrHex };
            }
            for (let b = 0; b < cfg.blocks.length; b++) {
                const insns = cfg.blocks[b].instructions || [];
                for (let k = 0; k < insns.length; k++) {
                    if (insns[k].addressHex === callAddrHex) {
                        // Walk backwards up to 4 instructions in the basic block to inspect x0 setup
                        let sawStaticLiteralLoad = false;
                        let x0WriteText = null;
                        for (let p = k - 1; p >= Math.max(0, k - 4); p--) {
                            const prev = insns[p];
                            const writes = prev.writesRegisters || [];
                            if (writes.indexOf("x0") !== -1) {
                                x0WriteText = prev.formatted;
                                if (prev.mnemonic === "add" || prev.mnemonic === "adr" || prev.mnemonic === "adrp") {
                                    sawStaticLiteralLoad = true;
                                }
                                break;
                            }
                        }
                        return {
                            isDynamicFormat: x0WriteText !== null && !sawStaticLiteralLoad,
                            preview: x0WriteText ? (x0WriteText + " -> " + insns[k].formatted) : insns[k].formatted
                        };
                    }
                }
            }
            return { isDynamicFormat: false, preview: "bl @ " + callAddrHex };
        }

        let emitted = 0;
        for (let i = 0; i < imports.length; i++) {
            const imp = imports[i];
            const bare = String(imp.bareName || imp.name || "").replace(/^_+/, "");
            const callSites = imp.callSites || [];
            const matchingPaths = pathsBySink[bare] || [];
            const bestPath = matchingPaths.length > 0 ? matchingPaths[0] : null;
            const primaryCallSite = callSites.length > 0 ? callSites[0] : null;
            const targetAddr = (primaryCallSite && primaryCallSite.callAddressHex)
                || (bestPath && bestPath.immediateCallSiteHex)
                || imp.addressHex;

            const pathTrace = bestPath
                ? bestPath.formattedSummary + " (" + bestPath.hopCount + " hop(s))"
                : (primaryCallSite && primaryCallSite.callerName
                    ? primaryCallSite.callerName + " -> " + imp.name
                    : "Imported symbol " + imp.name + " (stub " + imp.addressHex + ")");

            // Rule Group A: Classic memory-unsafe / command execution / dynamic loader sinks
            if (Object.prototype.hasOwnProperty.call(sinkCatalog, bare)) {
                const meta = sinkCatalog[bare];
                const reachableBoost = (bestPath && meta.severity === "HIGH" && bestPath.hopCount <= 2) ? "HIGH" : meta.severity;
                mach.emitFinding({
                    severity: reachableBoost,
                    category: meta.category,
                    title: meta.title + (bestPath ? " Reachable from `" + bestPath.sourceName + "`" : ""),
                    detail:
                        "Imported `" + imp.name + "` (" + (imp.libraryShortName || "external dylib") + ") has " +
                        callSites.length + " direct call site(s). Shortest call path: " + pathTrace + ". " +
                        meta.remediation,
                    addressHex: targetAddr,
                    evidencePreview: pathTrace + (primaryCallSite ? " @ " + primaryCallSite.callAddressHex : "")
                });
                mach.addComment(targetAddr, "[Sink:" + reachableBoost + "] " + bare + " via " + pathTrace);
                emitted += 1;
                continue;
            }

            // Rule Group B: Variadic format-string functions (`printf`, `fprintf`, `syslog`, `NSLog`)
            if (Object.prototype.hasOwnProperty.call(formatSinks, bare) && (callSites.length > 0 || bestPath)) {
                const fmtCheck = primaryCallSite
                    ? inspectFormatStringCallSite(primaryCallSite.callerAddressHex, primaryCallSite.callAddressHex)
                    : { isDynamicFormat: false, preview: pathTrace };
                const sev = fmtCheck.isDynamicFormat ? "HIGH" : "LOW";
                const titlePrefix = fmtCheck.isDynamicFormat
                    ? "Non-Constant Format Register Passed to `" + bare + "`"
                    : "Variadic Format Output Sink `" + bare + "` Call Site Audited";
                mach.emitFinding({
                    severity: sev,
                    category: "Format String Audit (CWE-134)",
                    title: titlePrefix,
                    detail:
                        "Audited " + callSites.length + " call site(s) to `" + imp.name + "`. " +
                        "Shortest call path: " + pathTrace + ". " +
                        (fmtCheck.isDynamicFormat
                            ? "Register `x0` is populated from a non-literal expression prior to call; verify user input cannot control format specifiers (`%n`, `%s`, `%x`)."
                            : "Format argument appears PC-relative (`adrp`/`add`), which mitigates format-string injection; confirm format specifiers match variadic operand widths."),
                    addressHex: targetAddr,
                    evidencePreview: fmtCheck.preview + " | path: " + pathTrace
                });
                emitted += 1;
                continue;
            }

            // Rule Group C: Non-constant-time secret/authentication comparison (`strcmp`, `strncmp`, `memcmp`)
            if (Object.prototype.hasOwnProperty.call(timingAuthSinks, bare)) {
                let authCallerName = null;
                let authCallAddr = targetAddr;
                for (let c = 0; c < callSites.length; c++) {
                    const cs = callSites[c];
                    if (cs.callerName && authNamePattern.test(cs.callerName)) {
                        authCallerName = cs.callerName;
                        authCallAddr = cs.callAddressHex || targetAddr;
                        break;
                    }
                }
                if (!authCallerName && bestPath && authNamePattern.test(bestPath.formattedSummary)) {
                    authCallerName = bestPath.hopNames.length >= 2
                        ? bestPath.hopNames[bestPath.hopNames.length - 2]
                        : bestPath.sourceName;
                }

                if (authCallerName || callSites.length > 0) {
                    const sev = authCallerName ? "HIGH" : "MEDIUM";
                    const contextLabel = authCallerName
                        ? " in Security-Sensitive Function `" + authCallerName + "`"
                        : "";
                    mach.emitFinding({
                        severity: sev,
                        category: "Authentication & Timing Side-Channel (CWE-208)",
                        title: "Early-Exit String/Memory Comparison `" + bare + "`" + contextLabel,
                        detail:
                            "Function invokes `" + imp.name + "` (" + callSites.length + " call site(s)). " +
                            "Shortest call path: " + pathTrace + ". " +
                            "Standard `" + bare + "` terminates on the first mismatched byte, leaking prefix match timing and exposing secret material in registers. " +
                            "Remediation: Use `timingsafe_bcmp` / `CCDigest` HMAC verification or asymmetric signature validation.",
                        addressHex: authCallAddr,
                        evidencePreview: pathTrace + " @ " + authCallAddr
                    });
                    mach.addComment(authCallAddr, "[AuthSink:" + sev + "] Non-constant-time " + bare + " comparison");
                    emitted += 1;
                }
            }
        }

        console.info("dangerous-c-sink-reachability: completed with", emitted, "sink reachability finding(s)");
    })();
    """#

    // MARK: - Embedded JavaScript Source: Plugin 3 (`arm64e-pac-gadget-auditor`)

    private static let arm64ePACGadgetAuditorJS: String = #"""
    (function() {
        "use strict";

        const summary = mach.getImageSummary();
        const functions = mach.getFunctions();
        if (!summary || !summary.isARM64Family) {
            console.info("arm64e-pac-gadget-auditor: skipping non-ARM64 image (", summary ? summary.architecture : "unknown", ")");
            return;
        }

        const isARM64E = Boolean(summary.isARM64E);
        console.info("arm64e-pac-gadget-auditor: scanning", functions.length, "recovered ARM64 function(s); isARM64E =", isARM64E);

        const standaloneAuthMnemonics = {
            "autiasp": true, "autibsp": true, "autiza": true, "autizb": true,
            "xpaci": true, "xpacd": true
        };
        const pacBranchMnemonics = {
            "braa": true, "brab": true, "braaz": true, "brabz": true,
            "blraa": true, "blrab": true, "blraaz": true, "blrabz": true,
            "retaa": true, "retab": true
        };

        let nonLeafWithoutPAC = [];
        let unsignedIndirectCount = 0;
        let splitGadgetCount = 0;

        for (let f = 0; f < functions.length; f++) {
            const fn = functions[f];
            if (!fn || fn.isThunk) {
                continue;
            }

            const fnDisplay = fn.demangledName || fn.name || fn.addressHex;
            const cfg = mach.getCFG(fn.addressHex);
            const blocks = (cfg && cfg.blocks) ? cfg.blocks : [];
            const jumpTableDispatches = {};
            if (cfg && cfg.jumpTables) {
                for (let j = 0; j < cfg.jumpTables.length; j++) {
                    jumpTableDispatches[cfg.jumpTables[j].dispatchAddressHex] = cfg.jumpTables[j];
                }
            }

            let sawUnsignedRet = false;
            let sawPACRet = false;

            for (let b = 0; b < blocks.length; b++) {
                const insns = blocks[b].instructions || [];
                for (let i = 0; i < insns.length; i++) {
                    const insn = insns[i];
                    const mnem = String(insn.mnemonic || "").toLowerCase();

                    // Rule 1: Unsigned indirect branch / call (`br xN`, `blr xN`) without ARMv8.3-A PAC (`braa`/`blraa`)
                    if (mnem === "br" || mnem === "blr") {
                        const reg = String(insn.indirectRegister || insn.operandText || "");
                        // Skip standard dyld PLT/GOT x16/x17 tiny stub sequences
                        const isStubTrampoline = (fn.instructionCount <= 4 && (reg === "x16" || reg === "x17"));
                        if (!isStubTrampoline) {
                            const jt = jumpTableDispatches[insn.addressHex];
                            const severity = (mnem === "blr") ? "HIGH" : "MEDIUM";
                            const kindTitle = (mnem === "blr")
                                ? "Unsigned Indirect Function Call (`blr " + reg + "`) Without PAC"
                                : (jt
                                    ? "Unsigned Switch Jump-Table Dispatch (`br " + reg + "`) in `" + fnDisplay + "`"
                                    : "Unsigned Indirect Jump (`br " + reg + "`) in `" + fnDisplay + "`");
                            const jtNote = jt
                                ? " Jump table at " + jt.tableBaseAddressHex + " (" + (jt.targetAddressesHex || []).length + " case targets)."
                                : "";

                            mach.emitFinding({
                                severity: severity,
                                category: "Control-Flow Integrity / PAC",
                                title: kindTitle,
                                detail:
                                    "Instruction `" + insn.formatted + "` at " + insn.addressHex + " inside `" + fnDisplay +
                                    "` transfers control through register `" + reg + "` without Pointer Authentication (`braa`/`blraa`)." +
                                    jtNote + " Remediation: Compile with `-arch arm64e` or `-mbranch-protection=standard` so indirect call/vtable targets are cryptographically authenticated.",
                                addressHex: insn.addressHex,
                                evidencePreview: fnDisplay + " @ " + insn.addressHex + ": " + insn.formatted
                            });
                            mach.addComment(insn.addressHex, "[CFI:" + severity + "] Unsigned indirect " + mnem + " (" + reg + ")");
                            unsignedIndirectCount += 1;
                        }
                    }

                    // Rule 2: Track `ret` vs `retaa`/`retab` in frame-allocating / non-leaf functions
                    if (mnem === "ret") {
                        sawUnsignedRet = true;
                    } else if (mnem === "retaa" || mnem === "retab") {
                        sawPACRet = true;
                    }

                    // Rule 3: Standalone pointer authentication / stripping (`autia*` / `xpaci`) separated from branch/return
                    if (Object.prototype.hasOwnProperty.call(standaloneAuthMnemonics, mnem)) {
                        const nextInsn = (i + 1 < insns.length) ? insns[i + 1] : null;
                        const nextMnem = nextInsn ? String(nextInsn.mnemonic || "").toLowerCase() : "";
                        const isCombinedImmediately = Object.prototype.hasOwnProperty.call(pacBranchMnemonics, nextMnem);
                        if (!isCombinedImmediately) {
                            const sev = (mnem === "xpaci" || mnem === "xpacd") ? "HIGH" : "MEDIUM";
                            mach.emitFinding({
                                severity: sev,
                                category: "PAC Signing / Stripping Window",
                                title: "Standalone PAC Strip/Auth Instruction `" + mnem + "` in `" + fnDisplay + "`",
                                detail:
                                    "Instruction `" + insn.formatted + "` at " + insn.addressHex +
                                    " strips or authenticates a pointer separately from a fused branch (`braa`/`retaa`). " +
                                    "Any intermediate register spill or instruction window between `" + mnem + "` and control transfer weakens PAC guarantees.",
                                addressHex: insn.addressHex,
                                evidencePreview: insn.addressHex + ": " + insn.formatted + (nextInsn ? " ; next: " + nextInsn.formatted : "")
                            });
                            splitGadgetCount += 1;
                        }
                    }
                }
            }

            if (sawUnsignedRet && !sawPACRet && (!fn.isLeaf || fn.stackFrameBytes > 0)) {
                nonLeafWithoutPAC.push({
                    name: fnDisplay,
                    addressHex: fn.addressHex,
                    stackBytes: fn.stackFrameBytes
                });
            }
        }

        // Rule 4: Report non-PAC stack-frame epilogues (`ret` instead of `retaa`/`retab`)
        if (nonLeafWithoutPAC.length > 0) {
            const firstFn = nonLeafWithoutPAC[0];
            const previewList = nonLeafWithoutPAC.slice(0, 5).map(function(item) {
                return item.name + " (" + item.addressHex + ", frame=" + item.stackBytes + "B)";
            }).join(", ");
            const moreSuffix = nonLeafWithoutPAC.length > 5 ? " (+" + (nonLeafWithoutPAC.length - 5) + " more)" : "";

            if (isARM64E) {
                // On an arm64e image, frame-spilling functions omitting PAC return protection represent an ABI hardening gap!
                mach.emitFinding({
                    severity: "MEDIUM",
                    category: "ARM64e Stack Return Hardening",
                    title: "Non-PAC `ret` Epilogues in Stack-Frame Functions on `arm64e` Image",
                    detail:
                        "Binary slice is tagged `arm64e`, yet " + nonLeafWithoutPAC.length +
                        " non-leaf / stack-allocating function(s) return via unsigned `ret` without `paciasp`/`retaa`: " +
                        previewList + moreSuffix + ". " +
                        "Remediation: Enable `-mbranch-protection=pac-ret+leaf` across all translation units and static archives.",
                    addressHex: firstFn.addressHex,
                    evidencePreview: previewList + moreSuffix
                });
            } else {
                mach.emitFinding({
                    severity: "LOW",
                    category: "ARM64 CFI Hardening Posture",
                    title: "Standard `arm64` Slice Without Pointer Authentication (`paciasp`/`retaa`)",
                    detail:
                        "Binary is compiled for baseline `arm64` (" + nonLeafWithoutPAC.length +
                        " stack-allocating function(s) spill `x30` and return via plain `ret`: " +
                        previewList + moreSuffix + "). " +
                        "Remediation: Consider `-mbranch-protection=standard` (`paciasp`/`autiasp` NOP-compatible hint space on ARMv8.0+) or shipping an `arm64e` slice where supported.",
                    addressHex: firstFn.addressHex,
                    evidencePreview: previewList + moreSuffix
                });
            }
        }

        console.info(
            "arm64e-pac-gadget-auditor: completed (unsignedIndirect =",
            unsignedIndirectCount,
            ", splitPAC =",
            splitGadgetCount,
            ", nonPACFrameFns =",
            nonLeafWithoutPAC.length,
            ")"
        );
    })();
    """#

    // MARK: - Embedded JavaScript Source: Plugin 4 (`entitlement-privilege-auditor`)

    private static let entitlementPrivilegeAuditorJS: String = #"""
    (function() {
        "use strict";

        const summary = mach.getImageSummary();
        const sig = mach.getCodeSignature();
        const segments = mach.getSegments();

        if (!summary) {
            return;
        }

        const isMachO = String(summary.containerFormat || "").indexOf("Mach-O") !== -1;
        console.info("entitlement-privilege-auditor: auditing", summary.fileName, "(format:", summary.containerFormat, ")");

        const imageAnchor = summary.entryPointHex || summary.imageBaseHex || "0x0";
        let findingCount = 0;

        // 1. Check RWX segments across all container formats
        for (let s = 0; s < segments.length; s++) {
            const seg = segments[s];
            if (seg && seg.allowsRWX) {
                mach.emitFinding({
                    severity: "CRITICAL",
                    category: "Memory Protection / W^X Violation",
                    title: "Simultaneously Writable & Executable Segment `" + seg.name + "`",
                    detail:
                        "Segment `" + seg.name + "` at " + seg.vmAddressHex +
                        " permits both write and execute permissions (init=" + seg.initialProtection +
                        ", max=" + seg.maxProtection + "), violating W^X memory isolation.",
                    addressHex: seg.vmAddressHex,
                    evidencePreview: seg.name + " @ " + seg.vmAddressHex + " prot=" + seg.initialProtection + "/" + seg.maxProtection
                });
                findingCount += 1;
            }
        }

        if (!isMachO || !sig) {
            console.info("entitlement-privilege-auditor: non-Mach-O container; RWX segment check complete");
            return;
        }

        // 2. Signature & Hardened Runtime posture checks
        if (!sig.isSigned) {
            mach.emitFinding({
                severity: "HIGH",
                category: "Code Signing Integrity",
                title: "Unsigned Mach-O Binary (`LC_CODE_SIGNATURE` Missing)",
                detail:
                    "Mach-O image `" + summary.fileName + "` contains no embedded `CS_SuperBlob` code signature. " +
                    "macOS Gatekeeper and Apple Silicon (`arm64`) kernel enforcement reject unsigned native executables.",
                addressHex: imageAnchor,
                evidencePreview: "isSigned=false, sha256=" + String(summary.sha256Hex || "").slice(0, 16) + "..."
            });
            findingCount += 1;
            return;
        }

        if (sig.isAdHoc) {
            mach.emitFinding({
                severity: "MEDIUM",
                category: "Code Signing Trust Chain",
                title: "Ad-Hoc Signed Mach-O Binary (`CS_ADHOC`)",
                detail:
                    "Binary `" + summary.fileName + "` (identifier `" + (sig.identifier || "<empty>") + "`) " +
                    "is ad-hoc signed without an Apple Developer ID CMS certificate chain (`cdhash=" +
                    String(sig.cdHashHex || "").slice(0, 24) + "...`). Suitable for local testing, but lacks Team ID isolation for production distribution.",
                addressHex: imageAnchor,
                evidencePreview: "flags=" + sig.flagsHex + " (CS_ADHOC), id=" + (sig.identifier || "<none>")
            });
            findingCount += 1;
        }

        if (!sig.hasHardenedRuntime) {
            mach.emitFinding({
                severity: "MEDIUM",
                category: "Hardened Runtime Posture",
                title: "Hardened Runtime (`CS_RUNTIME` 0x00010000) Not Enabled",
                detail:
                    "CodeDirectory flags (`" + sig.flagsHex + "`) do not set `CS_RUNTIME` (`0x00010000`). " +
                    "Without Hardened Runtime, macOS notarization is unavailable and default protections against dylib injection and unsigned executable pages are relaxed. " +
                    "Remediation: Sign with `codesign --options runtime`.",
                addressHex: imageAnchor,
                evidencePreview: "CodeDirectory flags=" + sig.flagsHex + ", team=" + (sig.teamIdentifier || "none")
            });
            findingCount += 1;
        }

        // 3. Detailed Entitlement Audit Rules
        const entitlements = sig.entitlements || {};
        const entKeys = Object.keys(entitlements);

        const riskyEntitlementRules = [
            {
                key: "com.apple.security.get-task-allow",
                severity: "HIGH",
                category: "Task Port / Debugger Attachment",
                title: "Debuggable Task Port Entitlement (`get-task-allow`)",
                detail: "Grants `task_for_pid` / debugger attachment rights to same-UID processes, allowing runtime memory inspection, register modification, and credential extraction if left enabled in release builds."
            },
            {
                key: "com.apple.security.cs.debugger",
                severity: "CRITICAL",
                category: "System Debugger Privilege",
                title: "Privileged Debugger Entitlement (`cs.debugger`)",
                detail: "Allows the process to attach to and inspect other processes on the system; tightly restrict to signed developer tools."
            },
            {
                key: "com.apple.security.cs.disable-library-validation",
                severity: "HIGH",
                category: "Dyld Library Validation Bypass",
                title: "Library Validation Disabled (`cs.disable-library-validation`)",
                detail: "Permits loading plug-ins and dynamic libraries signed by any third party (or ad-hoc depending on flags), significantly expanding dylib hijacking / plug-in injection surface."
            },
            {
                key: "com.apple.security.cs.allow-dyld-environment-variables",
                severity: "HIGH",
                category: "Dyld Environment Injection",
                title: "Dyld Environment Variables Allowed (`allow-dyld-environment-variables`)",
                detail: "Honors `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, and `DYLD_FRAMEWORK_PATH` under Hardened Runtime, enabling trivial process code injection."
            },
            {
                key: "com.apple.security.cs.allow-unsigned-executable-memory",
                severity: "HIGH",
                category: "Executable Memory Relaxation",
                title: "Arbitrary Unsigned Executable Memory Enabled (`allow-unsigned-executable-memory`)",
                detail: "Permits `mmap`/`mprotect` creation of writable/executable pages without `MAP_JIT` hardened restrictions; replace with `com.apple.security.cs.allow-jit` if a JIT engine is genuinely required."
            },
            {
                key: "com.apple.security.cs.allow-jit",
                severity: "MEDIUM",
                category: "JIT Executable Memory",
                title: "MAP_JIT Executable Memory Entitlement (`cs.allow-jit`)",
                detail: "Enables `MAP_JIT` dynamic code generation pages (`pthread_jit_write_protect_np`). Confirm the binary actually embeds a hardened JS/Wasm JIT runtime; remove if unused."
            },
            {
                key: "com.apple.security.cs.disable-executable-page-protection",
                severity: "CRITICAL",
                category: "Code Integrity Bypass",
                title: "Executable Page Code-Signing Enforcement Disabled",
                detail: "Disables kernel code-signing page hash enforcement on executable pages (`CS_KILL`/`CS_HARD`), allowing arbitrary in-memory code modification."
            }
        ];

        function isTruthyEntitlement(val) {
            const norm = String(val).trim().toLowerCase();
            return norm === "true" || norm === "1" || norm === "yes";
        }

        for (let r = 0; r < riskyEntitlementRules.length; r++) {
            const rule = riskyEntitlementRules[r];
            if (Object.prototype.hasOwnProperty.call(entitlements, rule.key) && isTruthyEntitlement(entitlements[rule.key])) {
                mach.emitFinding({
                    severity: rule.severity,
                    category: rule.category,
                    title: rule.title,
                    detail: rule.detail + " Remove `" + rule.key + "` from release `.entitlements` plists unless strictly required.",
                    addressHex: imageAnchor,
                    evidencePreview: rule.key + " = " + entitlements[rule.key]
                });
                findingCount += 1;
            }
        }

        // 4. Private Apple / TCC / Sandbox Exemption Entitlements
        for (let k = 0; k < entKeys.length; k++) {
            const key = entKeys[k];
            const val = entitlements[key];
            if (key.indexOf("com.apple.private.tcc.") === 0) {
                mach.emitFinding({
                    severity: "CRITICAL",
                    category: "Private TCC Privacy Entitlement",
                    title: "Private TCC Bypass Entitlement (`" + key + "`)",
                    detail:
                        "Binary declares Apple-internal TCC entitlement `" + key + "` (`" + val + "`), which grants silent access to privacy-protected resources without user consent prompts.",
                    addressHex: imageAnchor,
                    evidencePreview: key + " = " + val
                });
                findingCount += 1;
            } else if (key.indexOf("com.apple.private.") === 0 || key.indexOf("com.apple.rootless.") === 0) {
                mach.emitFinding({
                    severity: "HIGH",
                    category: "Private Apple Platform Entitlement",
                    title: "Restricted Private Entitlement (`" + key + "`)",
                    detail:
                        "Binary declares restricted platform entitlement `" + key + "` (`" + val + "`), which requires Apple system signing or AMFI provisioning.",
                    addressHex: imageAnchor,
                    evidencePreview: key + " = " + val
                });
                findingCount += 1;
            }
        }

        console.info("entitlement-privilege-auditor: completed with", findingCount, "signature/entitlement finding(s)");
    })();
    """#
}

// MARK: - Aggregated Plugin Suite Report & Runner

public struct MachPluginSuiteReport: Sendable, Codable, Hashable {
    public let results: [MachPluginExecutionResult]
    public let findings: [SecurityAuditFinding]
    public let generatedComments: [UserInlineComment]
    public let generatedBookmarks: [UserBookmark]
    public let pluginFailures: [String: String]
    public let totalDurationMilliseconds: Double

    public init(
        results: [MachPluginExecutionResult],
        findings: [SecurityAuditFinding],
        generatedComments: [UserInlineComment] = [],
        generatedBookmarks: [UserBookmark] = [],
        pluginFailures: [String: String] = [:],
        totalDurationMilliseconds: Double
    ) {
        self.results = results
        self.findings = findings
        self.generatedComments = generatedComments
        self.generatedBookmarks = generatedBookmarks
        self.pluginFailures = pluginFailures
        self.totalDurationMilliseconds = totalDurationMilliseconds
    }

    public var criticalCount: Int {
        findings.filter { $0.severity == .critical }.count
    }

    public var highCount: Int {
        findings.filter { $0.severity == .high }.count
    }

    public var mediumCount: Int {
        findings.filter { $0.severity == .medium }.count
    }

    public var lowCount: Int {
        findings.filter { $0.severity == .low }.count
    }

    public var infoCount: Int {
        findings.filter { $0.severity == .info }.count
    }

    public var combinedConsoleLogs: [String] {
        var out: [String] = []
        for res in results {
            for line in res.consoleLogs {
                out.append("[\(res.pluginID)] \(line)")
            }
        }
        return out
    }
}

public struct MachPluginRunner: Sendable {
    public let sandbox: MachJavaScriptPluginSandbox
    public var builtInPlugins: [MachPluginManifest]
    public var customPlugins: [MachPluginManifest]

    public init(
        sandbox: MachJavaScriptPluginSandbox = MachJavaScriptPluginSandbox(),
        builtInPlugins: [MachPluginManifest] = BuiltInMachPluginCatalog.allPlugins,
        customPlugins: [MachPluginManifest] = []
    ) {
        self.sandbox = sandbox
        self.builtInPlugins = builtInPlugins
        self.customPlugins = customPlugins
    }

    public var allPlugins: [MachPluginManifest] {
        builtInPlugins + customPlugins
    }

    public var enabledPlugins: [MachPluginManifest] {
        allPlugins.filter(\.isEnabled)
    }

    public mutating func registerCustomPlugin(_ manifest: MachPluginManifest) {
        if let idx = customPlugins.firstIndex(where: { $0.id == manifest.id }) {
            customPlugins[idx] = manifest
        } else {
            customPlugins.append(manifest)
        }
    }

    public mutating func setPluginEnabled(id: String, isEnabled: Bool) {
        if let idx = builtInPlugins.firstIndex(where: { $0.id == id }) {
            builtInPlugins[idx].isEnabled = isEnabled
        }
        if let idx = customPlugins.firstIndex(where: { $0.id == id }) {
            customPlugins[idx].isEnabled = isEnabled
        }
    }

    // MARK: Suite & Single-Plugin Execution APIs

    /// Executes all enabled built-in and custom plugins against `analysisIndex` (and optional `binaryData`),
    /// returning per-plugin `MachPluginExecutionResult`s and aggregated `SecurityAuditFinding`s sorted by severity descending.
    public func runAllEnabled(
        against analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil,
        additionalPlugins: [MachPluginManifest] = []
    ) throws -> (results: [MachPluginExecutionResult], findings: [SecurityAuditFinding]) {
        let activeList = enabledPlugins + additionalPlugins.filter(\.isEnabled)
        let suite = try runSuite(
            against: analysisIndex,
            binaryData: binaryData,
            plugins: activeList,
            continueOnError: false
        )
        return (suite.results, suite.findings)
    }

    /// Executes the specified plugin list (or `enabledPlugins` when `plugins` is `nil`) and produces a `MachPluginSuiteReport`.
    public func runSuite(
        against analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil,
        plugins explicitPlugins: [MachPluginManifest]? = nil,
        continueOnError: Bool = true
    ) throws -> MachPluginSuiteReport {
        let suiteStart = CFAbsoluteTimeGetCurrent()
        let selected = (explicitPlugins ?? enabledPlugins).filter(\.isEnabled)

        var executionResults: [MachPluginExecutionResult] = []
        executionResults.reserveCapacity(selected.count)
        var allFindings: [SecurityAuditFinding] = []
        var commentsByAddr: [VirtualAddress: UserInlineComment] = [:]
        var commentOrder: [VirtualAddress] = []
        var allBookmarks: [UserBookmark] = []
        var failures: [String: String] = [:]

        for manifest in selected {
            do {
                let res = try sandbox.execute(
                    manifest: manifest,
                    analysisIndex: analysisIndex,
                    binaryData: binaryData
                )
                executionResults.append(res)
                allFindings.append(contentsOf: res.findings)
                for comment in res.generatedComments {
                    if commentsByAddr[comment.address] == nil {
                        commentOrder.append(comment.address)
                        commentsByAddr[comment.address] = comment
                    } else if var existing = commentsByAddr[comment.address],
                              !existing.text.contains(comment.text) {
                        existing.text += " | \(comment.text)"
                        commentsByAddr[comment.address] = existing
                    }
                }
                allBookmarks.append(contentsOf: res.generatedBookmarks)
            } catch {
                if !continueOnError {
                    throw error
                }
                failures[manifest.id] = error.localizedDescription
            }
        }

        let sortedFindings = Self.sortFindingsBySeverity(allFindings)
        let mergedComments = commentOrder.compactMap { commentsByAddr[$0] }
        let totalMs = max(0.0, (CFAbsoluteTimeGetCurrent() - suiteStart) * 1000.0)

        return MachPluginSuiteReport(
            results: executionResults,
            findings: sortedFindings,
            generatedComments: mergedComments,
            generatedBookmarks: allBookmarks,
            pluginFailures: failures,
            totalDurationMilliseconds: totalMs
        )
    }

    /// Convenience runner accepting a `LoadedBinaryImage` directly (runs `BinaryAnalysisCoordinator` automatically).
    public func runSuite(
        against image: LoadedBinaryImage,
        binaryData: Data? = nil,
        plugins explicitPlugins: [MachPluginManifest]? = nil,
        continueOnError: Bool = true
    ) throws -> MachPluginSuiteReport {
        let coordinator = BinaryAnalysisCoordinator()
        let index = binaryData != nil
            ? try coordinator.analyzeBinary(image, data: binaryData)
            : try coordinator.analyzeBinary(image)
        return try runSuite(
            against: index,
            binaryData: binaryData,
            plugins: explicitPlugins,
            continueOnError: continueOnError
        )
    }

    /// Executes a single `MachPluginManifest` against `analysisIndex`.
    public func runPlugin(
        _ manifest: MachPluginManifest,
        against analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil
    ) throws -> MachPluginExecutionResult {
        try sandbox.execute(
            manifest: manifest,
            analysisIndex: analysisIndex,
            binaryData: binaryData
        )
    }

    /// Looks up a built-in or registered custom plugin by `id` and executes it against `analysisIndex`.
    public func runPlugin(
        withID id: String,
        against analysisIndex: BinaryAnalysisIndex,
        binaryData: Data? = nil
    ) throws -> MachPluginExecutionResult {
        guard let manifest = allPlugins.first(where: { $0.id == id }) else {
            throw MachGraphError.pluginExecutionFailed(
                pluginID: id,
                message: "No registered built-in or custom plugin with ID '\(id)'"
            )
        }
        return try sandbox.execute(
            manifest: manifest,
            analysisIndex: analysisIndex,
            binaryData: binaryData
        )
    }

    /// Canonical severity-descending comparator (`.critical` -> `.high` -> `.medium` -> `.low` -> `.info`),
    /// breaking ties deterministically by virtual address ascending, then title ascending.
    public static func sortFindingsBySeverity(_ findings: [SecurityAuditFinding]) -> [SecurityAuditFinding] {
        MachJavaScriptPluginSandbox.sortFindings(findings)
    }
}
