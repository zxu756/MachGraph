import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachMicroDecompiler
import MachPatchAndHexEngine
import MachPluginSDK
import MachProjectStore

// MARK: - Cold Tungsten Steel Standalone Bilingual HTML Triage Dossier Exporter (`v1.7.0`)

public struct ColdTungstenHTMLReportExporter: Sendable {
    public init() {}

    public func exportHTMLReport(
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data,
        decompiledFunctions: [DecompiledFunctionOutput]? = nil,
        auditFindings: [SecurityAuditFinding]? = nil,
        isDemo: Bool = false
    ) throws -> String {
        let image = analysisIndex.image
        let decompiler = MachMicroDecompilerEngine()
        let resolvedDecompiled: [DecompiledFunctionOutput]
        if let provided = decompiledFunctions {
            resolvedDecompiled = provided
        } else {
            resolvedDecompiled = decompiler.decompileAllFunctions(
                in: analysisIndex,
                includeThunks: false
            )
        }

        let resolvedFindings: [SecurityAuditFinding]
        if let provided = auditFindings {
            resolvedFindings = provided
        } else {
            let suite = try MachPluginRunner().runSuite(
                against: analysisIndex,
                binaryData: binaryData,
                continueOnError: true
            )
            resolvedFindings = suite.findings
        }

        let entropyProfile = SlidingWindowEntropyProfiler().analyzeFullProfile(
            data: binaryData,
            image: image,
            windowSize: 1024,
            stepSize: 512
        )

        let titleEn = sanitizeCleanCopy(image.fileName.isEmpty ? "Mach-O ARM64 Target" : image.fileName)
        let titleZh = sanitizeCleanCopy(image.fileName.isEmpty ? "Mach-O ARM64 目标二进制" : image.fileName)
        let archText = sanitizeCleanCopy("\(image.containerFormat.rawValue) / \(image.architecture.displayName)")
        let entryHex = image.entryPoint?.hexString ?? image.imageBase.hexString
        let cdHashEn = image.codeSignature.cdHashHex.isEmpty ? "unsigned" : image.codeSignature.cdHashHex
        let cdHashZh = image.codeSignature.cdHashHex.isEmpty ? "未签名" : image.codeSignature.cdHashHex

        let segmentRows = image.segments.map { seg in
            let perms = "\(seg.initialProtection.rwxString) / \(seg.maxProtection.rwxString)"
            let segLabels = localizedSegmentLabel(seg.name)
            return """
            <tr>
              <td class="mono" data-en="\(escapeHTML(segLabels.en))" data-zh="\(escapeHTML(segLabels.zh))">\(escapeHTML(segLabels.en))</td>
              <td class="mono">\(seg.vmAddress.hexString)</td>
              <td class="mono num">0x\(String(seg.vmSize, radix: 16))</td>
              <td class="mono">0x\(String(seg.fileOffset.rawValue, radix: 16))</td>
              <td class="mono">\(escapeHTML(perms))</td>
              <td class="mono num">\(seg.sections.count)</td>
            </tr>
            """
        }.joined(separator: "\n")

        let functionRows = analysisIndex.functions.prefix(16).map { fn in
            let pacTextEn = fn.usesPAC ? "arm64e-pac" : "std-a64"
            let pacTextZh = fn.usesPAC ? "arm64e-pac" : "标准-a64"
            let badgeClass = fn.usesPAC ? "pill-info" : "pill-neutral"
            return """
            <tr>
              <td class="mono">\(fn.address.hexString)</td>
              <td class="mono">\(escapeHTML(sanitizeCleanCopy(fn.demangledName)))</td>
              <td class="mono num">\(fn.blocks.count)</td>
              <td class="mono num">\(fn.cyclomaticComplexity)</td>
              <td class="mono num">\(fn.naturalLoops.count)</td>
              <td><span class="pill \(badgeClass)" data-en="\(pacTextEn)" data-zh="\(pacTextZh)">\(pacTextEn)</span></td>
            </tr>
            """
        }.joined(separator: "\n")

        let findingRows: String
        if resolvedFindings.isEmpty {
            findingRows = """
            <tr>
              <td colspan="4" data-en="Zero automated findings emitted by JavaScriptCore security plugins." data-zh="JavaScriptCore 安全审计插件未检出自动化风险项。">Zero automated findings emitted by JavaScriptCore security plugins.</td>
            </tr>
            """
        } else {
            findingRows = resolvedFindings.prefix(16).map { finding in
                let sevClass: String
                switch finding.severity {
                case .critical, .high:
                    sevClass = "pill-crit"
                case .medium:
                    sevClass = "pill-warn"
                case .low, .info:
                    sevClass = "pill-ok"
                }
                let sevLabels = localizedSeverityBadge(finding.severity)
                let addrEn = finding.address?.hexString ?? "image"
                let addrZh = finding.address?.hexString ?? "全镜像"
                let fTitleEn = sanitizeCleanCopy(finding.localizedTitle(in: .en))
                let fTitleZh = sanitizeCleanCopy(finding.localizedTitle(in: .zhHans))
                let fDetailEn = sanitizeCleanCopy(finding.detail)
                let fDetailZh = sanitizeCleanCopy(localizedFindingDetailZh(finding))
                return """
                <tr>
                  <td><span class="pill \(sevClass)" data-en="\(escapeHTML(sevLabels.en))" data-zh="\(escapeHTML(sevLabels.zh))">\(escapeHTML(sevLabels.en))</span></td>
                  <td class="mono" data-en="\(escapeHTML(addrEn))" data-zh="\(escapeHTML(addrZh))">\(escapeHTML(addrEn))</td>
                  <td data-en="\(escapeHTML(fTitleEn))" data-zh="\(escapeHTML(fTitleZh))">\(escapeHTML(fTitleEn))</td>
                  <td data-en="\(escapeHTML(fDetailEn))" data-zh="\(escapeHTML(fDetailZh))">\(escapeHTML(fDetailEn))</td>
                </tr>
                """
            }.joined(separator: "\n")
        }

        let pseudoCSections = resolvedDecompiled.prefix(4).map { output in
            let metaEn = "SSA vars: \(output.ssaVariableCount) · DSE: \(output.eliminatedDeadStoreCount)"
            let metaZh = "SSA 变量: \(output.ssaVariableCount) · 死存储消除: \(output.eliminatedDeadStoreCount)"
            return """
            <div class="code-card">
              <div class="code-header">
                <span class="mono">\(output.functionAddress.hexString)</span>
                <span>\(escapeHTML(sanitizeCleanCopy(output.signatureLine)))</span>
                <span class="mono muted" data-en="\(escapeHTML(metaEn))" data-zh="\(escapeHTML(metaZh))">\(escapeHTML(metaEn))</span>
              </div>
              <pre><code>\(escapeHTML(sanitizeCleanCopy(output.fullSourceText)))</code></pre>
            </div>
            """
        }.joined(separator: "\n")

        let svgBars = renderEntropySVG(samples: entropyProfile.samples)
        let demoPrefixEn = isDemo ? "[DEMO] " : ""
        let demoPrefixZh = isDemo ? "[演示数据] " : ""
        let h1En = "\(demoPrefixEn)\(titleEn) (\(archText))"
        let h1Zh = "\(demoPrefixZh)\(titleZh) (\(archText))"

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta name="description" content="MachGraph v1.7.0 Cold-Tungsten macOS ARM64 and Mach-O binary inspection, CFG, and triage report.">
          <title>MachGraph v1.7.0 Binary Triage Dossier: \(escapeHTML(titleEn))</title>
          <style>
            /* Hallmark · v2.0.0 · scope: app · genre: industrial-telemetry · posture: precision · shape: app screen · surface: dark-absolute */
            :root {
              --bg-chassis: #0F1216;
              --bg-panel: #141920;
              --bg-elevated: #1B222C;
              --bg-code: #0B0E12;
              --border-seam: #2A3442;
              --ink-primary: #E6EDF3;
              --ink-secondary: #8B949E;
              --ink-muted: #656D76;
              --accent-sapphire: #58A6FF;
              --status-info-bg: #13233A;
              --status-ok-fg: #3FB950;
              --status-ok-bg: #12261E;
              --status-warn-fg: #D29922;
              --status-warn-bg: #2B2111;
              --status-crit-fg: #F85149;
              --status-crit-bg: #2D1619;
              --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Helvetica Neue", sans-serif;
              --font-mono: ui-monospace, "SF Mono", Menlo, monospace;
            }
            *, *::before, *::after { box-sizing: border-box; }
            html, body {
              overflow-x: clip;
            }
            body {
              margin: 0;
              padding: 32px 24px 56px;
              background: var(--bg-chassis);
              color: var(--ink-primary);
              font-family: var(--font-sans);
              line-height: 1.5;
              font-size: 14px;
            }
            .container {
              max-width: 1180px;
              margin: 0 auto;
            }
            header.masthead {
              background: var(--bg-panel);
              color: var(--ink-primary);
              border: 1px solid var(--border-seam);
              border-top: 4px solid var(--accent-sapphire);
              border-radius: 6px;
              padding: 24px;
              margin-bottom: 16px;
            }
            .masthead-top {
              display: flex;
              justify-content: space-between;
              align-items: flex-start;
              gap: 16px;
              flex-wrap: wrap;
            }
            .lang-toggle {
              display: inline-flex;
              align-items: center;
              gap: 4px;
              padding: 4px;
              background: var(--bg-chassis);
              border: 1px solid var(--border-seam);
              border-radius: 6px;
            }
            .lang-btn {
              appearance: none;
              border: 1px solid transparent;
              background: transparent;
              color: var(--ink-secondary);
              font-family: var(--font-sans);
              font-size: 12px;
              font-weight: 600;
              line-height: 1.2;
              padding: 4px 12px;
              border-radius: 4px;
              cursor: pointer;
            }
            .lang-btn:hover {
              color: var(--ink-primary);
              background: var(--bg-elevated);
            }
            .lang-btn:active {
              color: var(--ink-primary);
              background: var(--status-info-bg);
            }
            .lang-btn:focus-visible {
              outline: 2px solid var(--accent-sapphire);
              outline-offset: 2px;
            }
            .lang-btn:disabled {
              opacity: 0.45;
              cursor: not-allowed;
            }
            .lang-btn.active {
              color: var(--ink-primary);
              background: var(--status-info-bg);
              border-color: var(--accent-sapphire);
            }
            .eyebrow {
              font-size: 12px;
              font-weight: 600;
              color: var(--accent-sapphire);
              margin: 0 0 8px;
            }
            h1, h2, h3 {
              text-wrap: balance;
              color: var(--ink-primary);
              margin: 0;
            }
            h1 {
              font-size: 24px;
              line-height: 1.25;
              margin-bottom: 8px;
            }
            h2 {
              font-size: 16px;
              line-height: 1.3;
              margin-bottom: 12px;
            }
            .subtitle {
              display: flex;
              flex-wrap: wrap;
              gap: 8px 16px;
              margin: 0;
              color: var(--ink-secondary);
              font-size: 13px;
            }
            .kpi-strip {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(176px, 1fr));
              gap: 12px;
              margin-bottom: 16px;
            }
            .kpi-card {
              background: var(--bg-panel);
              color: var(--ink-primary);
              border: 1px solid var(--border-seam);
              border-radius: 6px;
              padding: 16px;
            }
            .kpi-label {
              font-size: 12px;
              font-weight: 500;
              color: var(--ink-secondary);
            }
            .kpi-value {
              font-family: var(--font-mono);
              font-variant-numeric: tabular-nums;
              font-size: 20px;
              font-weight: 700;
              margin-top: 4px;
              color: var(--ink-primary);
            }
            section.panel {
              background: var(--bg-panel);
              color: var(--ink-primary);
              border: 1px solid var(--border-seam);
              border-radius: 6px;
              padding: 20px 24px;
              margin-bottom: 16px;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              font-size: 13px;
            }
            th, td {
              text-align: left;
              padding: 8px 12px;
              border-bottom: 1px solid var(--border-seam);
              vertical-align: top;
            }
            th {
              font-size: 12px;
              font-weight: 600;
              color: var(--ink-secondary);
              background: var(--bg-elevated);
            }
            .mono {
              font-family: var(--font-mono);
              font-variant-numeric: tabular-nums;
              font-size: 13px;
            }
            .num { text-align: right; }
            .muted { color: var(--ink-secondary); }
            .pill {
              display: inline-block;
              padding: 4px 8px;
              border-radius: 4px;
              font-size: 12px;
              font-weight: 600;
              font-family: var(--font-mono);
            }
            .pill-ok { background: var(--status-ok-bg); color: var(--status-ok-fg); }
            .pill-warn { background: var(--status-warn-bg); color: var(--status-warn-fg); }
            .pill-crit { background: var(--status-crit-bg); color: var(--status-crit-fg); }
            .pill-info { background: var(--status-info-bg); color: var(--accent-sapphire); }
            .pill-neutral { background: var(--bg-elevated); color: var(--ink-secondary); }
            .code-card {
              border: 1px solid var(--border-seam);
              border-radius: 6px;
              margin-bottom: 12px;
              overflow: hidden;
            }
            .code-header {
              display: flex;
              justify-content: space-between;
              gap: 12px;
              padding: 8px 12px;
              background: var(--bg-elevated);
              color: var(--ink-primary);
              border-bottom: 1px solid var(--border-seam);
              font-size: 13px;
            }
            pre {
              margin: 0;
              padding: 12px 16px;
              background: var(--bg-code);
              color: var(--ink-primary);
              overflow-x: auto;
              font-family: var(--font-mono);
              font-size: 12px;
              line-height: 1.5;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <header class="masthead">
              <div class="masthead-top">
                <div>
                  <p class="eyebrow" data-en="MachGraph v1.7.0 · Cold-Tungsten Binary Triage Dossier" data-zh="MachGraph v1.7.0 · 冷钨钢二进制逆向分诊报告">MachGraph v1.7.0 · Cold-Tungsten Binary Triage Dossier</p>
                  <h1 data-en="\(escapeHTML(h1En))" data-zh="\(escapeHTML(h1Zh))">\(escapeHTML(h1En))</h1>
                </div>
                <div class="lang-toggle" role="group" aria-label="Language Switcher">
                  <button type="button" class="lang-btn" data-set-lang="zh" aria-pressed="false">中文</button>
                  <button type="button" class="lang-btn active" data-set-lang="en" aria-pressed="true">EN</button>
                </div>
              </div>
              <p class="subtitle">
                <span>SHA-256: <span class="mono">\(escapeHTML(image.sha256Hex))</span></span>
                <span><span data-en="Entry:" data-zh="入口地址:">Entry:</span> <span class="mono">\(entryHex)</span></span>
                <span>CDHash: <span class="mono" data-en="\(escapeHTML(cdHashEn))" data-zh="\(escapeHTML(cdHashZh))">\(escapeHTML(cdHashEn))</span></span>
              </p>
            </header>

            <div class="kpi-strip">
              <div class="kpi-card">
                <div class="kpi-label" data-en="Recovered Functions" data-zh="已恢复函数">Recovered Functions</div>
                <div class="kpi-value">\(analysisIndex.functions.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label" data-en="Decoded A64 Insns" data-zh="已解码 A64 指令">Decoded A64 Insns</div>
                <div class="kpi-value">\(analysisIndex.decodedInstructions.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label" data-en="Cross-References" data-zh="交叉引用总数">Cross-References</div>
                <div class="kpi-value">\(analysisIndex.crossReferences.allRecords.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label" data-en="Shannon Entropy" data-zh="香农信息熵">Shannon Entropy</div>
                <div class="kpi-value">\(String(format: "%.3f b/B", entropyProfile.overallMetrics.shannonEntropyBits))</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label" data-en="Security Findings" data-zh="安全审计发现">Security Findings</div>
                <div class="kpi-value">\(resolvedFindings.count)</div>
              </div>
            </div>

            <section class="panel">
              <h2 data-en="Memory Segments &amp; Protection Matrix" data-zh="内存段映射与 RWX 权限矩阵">Memory Segments &amp; Protection Matrix</h2>
              <table>
                <thead>
                  <tr>
                    <th data-en="Segment" data-zh="内存段">Segment</th>
                    <th data-en="VM Address" data-zh="虚拟地址">VM Address</th>
                    <th class="num" data-en="VM Size" data-zh="虚拟大小">VM Size</th>
                    <th data-en="File Offset" data-zh="文件偏移">File Offset</th>
                    <th data-en="Init / Max Prot" data-zh="初始 / 最大权限">Init / Max Prot</th>
                    <th class="num" data-en="Sections" data-zh="节区数">Sections</th>
                  </tr>
                </thead>
                <tbody>
                  \(segmentRows)
                </tbody>
              </table>
            </section>

            <section class="panel">
              <h2 data-en="Recovered Control-Flow Functions &amp; Loop Complexity" data-zh="已恢复控制流函数与循环复杂度">Recovered Control-Flow Functions &amp; Loop Complexity</h2>
              <table>
                <thead>
                  <tr>
                    <th data-en="Entry" data-zh="入口地址">Entry</th>
                    <th data-en="Symbol" data-zh="函数符号">Symbol</th>
                    <th class="num" data-en="Blocks" data-zh="基本块">Blocks</th>
                    <th class="num" data-en="Cyclomatic" data-zh="圈复杂度">Cyclomatic</th>
                    <th class="num" data-en="Loops" data-zh="自然循环">Loops</th>
                    <th data-en="ISA Mode" data-zh="指令集特征">ISA Mode</th>
                  </tr>
                </thead>
                <tbody>
                  \(functionRows)
                </tbody>
              </table>
            </section>

            <section class="panel">
              <h2 data-en="Experimental Pseudo-C Decompilation (Condition Expressions Unverified)" data-zh="【实验性】伪C反编译输出（条件表达式未经验证）">Experimental Pseudo-C Decompilation (Condition Expressions Unverified)</h2>
              \(pseudoCSections)
            </section>

            <section class="panel">
              <h2 data-en="Sliding-Window Shannon Entropy Profile" data-zh="滑动窗口香农熵分布谱">Sliding-Window Shannon Entropy Profile</h2>
              \(svgBars)
            </section>

            <section class="panel">
              <h2 data-en="JavaScriptCore Security Audit Ledger" data-zh="JavaScriptCore 安全审计台账">JavaScriptCore Security Audit Ledger</h2>
              <table>
                <thead>
                  <tr>
                    <th data-en="Severity" data-zh="严重等级">Severity</th>
                    <th data-en="Address" data-zh="虚拟地址">Address</th>
                    <th data-en="Finding" data-zh="审计发现">Finding</th>
                    <th data-en="Evidence &amp; Reachability Detail" data-zh="静态证据与可达性详情">Evidence &amp; Reachability Detail</th>
                  </tr>
                </thead>
                <tbody>
                  \(findingRows)
                </tbody>
              </table>
            </section>
          </div>
          <script>
            (function () {
              var storageKey = 'machgraph-report-lang';
              function detectLanguage() {
                try {
                  var saved = window.localStorage.getItem(storageKey);
                  if (saved === 'zh' || saved === 'en') {
                    return saved;
                  }
                } catch (err) {}
                var nav = (navigator.language || '').toLowerCase();
                return nav.startsWith('zh') ? 'zh' : 'en';
              }
              function applyLanguage(lang, persist) {
                var activeLang = lang === 'zh' ? 'zh' : 'en';
                document.documentElement.lang = activeLang === 'zh' ? 'zh-CN' : 'en';
                var elements = document.querySelectorAll('[data-en][data-zh]');
                for (var i = 0; i < elements.length; i++) {
                  var node = elements[i];
                  var translated = activeLang === 'zh' ? node.getAttribute('data-zh') : node.getAttribute('data-en');
                  if (translated !== null) {
                    node.textContent = translated;
                  }
                }
                var buttons = document.querySelectorAll('.lang-btn[data-set-lang]');
                for (var j = 0; j < buttons.length; j++) {
                  var button = buttons[j];
                  var isCurrent = button.getAttribute('data-set-lang') === activeLang;
                  if (isCurrent) {
                    button.classList.add('active');
                  } else {
                    button.classList.remove('active');
                  }
                  button.setAttribute('aria-pressed', isCurrent ? 'true' : 'false');
                }
                if (persist) {
                  try {
                    window.localStorage.setItem(storageKey, activeLang);
                  } catch (err) {}
                }
              }
              var toggles = document.querySelectorAll('.lang-btn[data-set-lang]');
              for (var k = 0; k < toggles.length; k++) {
                toggles[k].addEventListener('click', function () {
                  applyLanguage(this.getAttribute('data-set-lang'), true);
                });
              }
              applyLanguage(detectLanguage(), false);
            })();
          </script>
        </body>
        </html>
        """ + "\n"
    }

    private func localizedSegmentLabel(_ rawName: String) -> (en: String, zh: String) {
        switch rawName {
        case "__PAGEZERO":
            return ("Segment pagezero", "零页段 pagezero")
        case "__TEXT":
            return ("Segment text", "代码段 text")
        case "__DATA_CONST":
            return ("Segment data_const", "只读数据段 data_const")
        case "__DATA":
            return ("Segment data", "数据段 data")
        case "__LINKEDIT":
            return ("Segment linkedit", "链接编辑段 linkedit")
        default:
            let normalized = rawName.trimmingCharacters(in: CharacterSet(charactersIn: "_")).lowercased()
            let suffix = normalized.isEmpty ? rawName.lowercased() : normalized
            return ("Segment \(suffix)", "内存段 \(suffix)")
        }
    }

    private func localizedSeverityBadge(_ severity: SecurityFindingSeverity) -> (en: String, zh: String) {
        switch severity {
        case .critical: return ("Critical", "严重")
        case .high: return ("High", "高危")
        case .medium: return ("Medium", "中危")
        case .low: return ("Low", "低危")
        case .info: return ("Info", "信息")
        }
    }

    private func localizedFindingDetailZh(_ finding: SecurityAuditFinding) -> String {
        finding.localizedDetail(in: .zhHans)
    }

    private func renderEntropySVG(samples: [EntropyRegionSample]) -> String {
        let capped = Array(samples.prefix(64))
        guard !capped.isEmpty else {
            return "<p class=\"muted\" data-en=\"Binary size smaller than sliding entropy window.\" data-zh=\"二进制体积小于滑动熵窗口大小。\">Binary size smaller than sliding entropy window.</p>"
        }
        let width = 960.0
        let height = 140.0
        let barW = max(4.0, (width - 20.0) / Double(capped.count))
        var rects: [String] = []
        for (idx, sample) in capped.enumerated() {
            let clamped = min(8.0, max(0.0, sample.entropyBitsPerByte))
            let barH = max(3.0, (clamped / 8.0) * (height - 28.0))
            let x = 10.0 + Double(idx) * barW
            let y = height - 16.0 - barH
            let fill = clamped >= 7.2 ? "#F85149" : (clamped >= 5.8 ? "#D29922" : "#58A6FF")
            rects.append(
                String(
                    format: "<rect x=\"%.1f\" y=\"%.1f\" width=\"%.1f\" height=\"%.1f\" fill=\"%@\" rx=\"1.5\" />",
                    x, y, max(2.0, barW - 2.0), barH, fill
                )
            )
        }
        return """
        <svg viewBox="0 0 960 140" width="100%" height="140" role="img" aria-label="Sliding window Shannon entropy profile">
          <rect x="0" y="0" width="960" height="140" fill="#0B0E12" rx="4" />
          \(rects.joined(separator: "\n  "))
        </svg>
        """
    }

    private func sanitizeCleanCopy(_ text: String) -> String {
        text
            .replacingOccurrences(of: "\u{2014}", with: " - ")
            .replacingOccurrences(of: "\u{2026}", with: "")
            .replacingOccurrences(of: "...", with: "")
    }

    private func escapeHTML(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
