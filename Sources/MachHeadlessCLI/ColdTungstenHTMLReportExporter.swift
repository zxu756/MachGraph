import Foundation
import MachA64Decoder
import MachBinaryFormats
import MachCFGEngine
import MachGraphModels
import MachMicroDecompiler
import MachPatchAndHexEngine
import MachPluginSDK
import MachProjectStore

// MARK: - Cold Tungsten Steel Standalone HTML Triage Dossier Exporter

public struct ColdTungstenHTMLReportExporter: Sendable {
    public init() {}

    public func exportHTMLReport(
        analysisIndex: BinaryAnalysisIndex,
        binaryData: Data,
        decompiledFunctions: [DecompiledFunctionOutput]? = nil,
        auditFindings: [SecurityAuditFinding]? = nil
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

        let title = sanitizeNoEmDash(image.fileName.isEmpty ? "Mach-O ARM64 Target" : image.fileName)
        let archText = sanitizeNoEmDash("\(image.containerFormat.rawValue) / \(image.architecture.displayName)")
        let entryHex = image.entryPoint?.hexString ?? image.imageBase.hexString
        let cdHashText = image.codeSignature.cdHashHex.isEmpty ? "unsigned" : image.codeSignature.cdHashHex

        let segmentRows = image.segments.map { seg in
            let perms = "\(seg.initialProtection.rwxString) / \(seg.maxProtection.rwxString)"
            return """
            <tr>
              <td class="mono">\(escapeHTML(seg.name))</td>
              <td class="mono">\(seg.vmAddress.hexString)</td>
              <td class="mono num">0x\(String(seg.vmSize, radix: 16))</td>
              <td class="mono">0x\(String(seg.fileOffset.rawValue, radix: 16))</td>
              <td class="mono">\(escapeHTML(perms))</td>
              <td class="mono num">\(seg.sections.count)</td>
            </tr>
            """
        }.joined(separator: "\n")

        let functionRows = analysisIndex.functions.prefix(16).map { fn in
            let pacText = fn.usesPAC ? "ARM64E-PAC" : "STD-A64"
            let badgeClass = fn.usesPAC ? "pill-info" : "pill-neutral"
            return """
            <tr>
              <td class="mono">\(fn.address.hexString)</td>
              <td class="mono">\(escapeHTML(sanitizeNoEmDash(fn.demangledName)))</td>
              <td class="mono num">\(fn.blocks.count)</td>
              <td class="mono num">\(fn.cyclomaticComplexity)</td>
              <td class="mono num">\(fn.naturalLoops.count)</td>
              <td><span class="pill \(badgeClass)">\(pacText)</span></td>
            </tr>
            """
        }.joined(separator: "\n")

        let findingRows: String
        if resolvedFindings.isEmpty {
            findingRows = """
            <tr>
              <td colspan="4">Zero automated findings emitted by JavaScriptCore security plugins.</td>
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
                let addrStr = finding.address?.hexString ?? "image"
                return """
                <tr>
                  <td><span class="pill \(sevClass)">\(escapeHTML(finding.severity.rawValue))</span></td>
                  <td class="mono">\(addrStr)</td>
                  <td>\(escapeHTML(sanitizeNoEmDash(finding.title)))</td>
                  <td>\(escapeHTML(sanitizeNoEmDash(finding.detail)))</td>
                </tr>
                """
            }.joined(separator: "\n")
        }

        let pseudoCSections = resolvedDecompiled.prefix(4).map { output in
            return """
            <div class="code-card">
              <div class="code-header">
                <span class="mono">\(output.functionAddress.hexString)</span>
                <span>\(escapeHTML(sanitizeNoEmDash(output.signatureLine)))</span>
                <span class="mono muted">SSA vars: \(output.ssaVariableCount) · DSE: \(output.eliminatedDeadStoreCount)</span>
              </div>
              <pre><code>\(escapeHTML(sanitizeNoEmDash(output.fullSourceText)))</code></pre>
            </div>
            """
        }.joined(separator: "\n")

        let svgBars = renderEntropySVG(samples: entropyProfile.samples)

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <meta name="description" content="MachGraph Cold-Tungsten native binary reverse-engineering, ARM64 CFG, SSA Pseudo-C decompiler, and security plugin audit dossier.">
          <title>MachGraph Binary Triage Dossier: \(escapeHTML(title))</title>
          <style>
          /* Hallmark · v2.0.0 · scope: app · genre: industrial-telemetry · posture: precision · shape: app screen · surface: dark-absolute */
          :root {
            --bg-chassis: #0F1216;
            --bg-panel: #141920;
            --bg-elevated: #1B222C;
            --border-seam: #2A3442;
            --ink-primary: #E6EDF3;
            --ink-secondary: #8B949E;
            --ink-muted: #656D76;
            --accent-sapphire: #58A6FF;
            --status-ok-fg: #3FB950;
            --status-ok-bg: #12261E;
            --status-warn-fg: #D29922;
            --status-warn-bg: #2B2111;
            --status-crit-fg: #F85149;
            --status-crit-bg: #2D1619;
          }
          * { box-sizing: border-box; }
          body {
            margin: 0;
            padding: 32px 24px 56px;
            background: var(--bg-chassis);
            color: var(--ink-primary);
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
            line-height: 1.5;
            font-size: 14px;
          }
          .container {
            max-width: 1180px;
            margin: 0 auto;
          }
          header.masthead {
            background: var(--bg-panel);
            border: 1px solid var(--border-seam);
            border-top: 3px solid var(--accent-sapphire);
            border-radius: 6px;
            padding: 22px 26px;
            margin-bottom: 18px;
          }
          .eyebrow {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--accent-sapphire);
            margin: 0 0 6px;
          }
          h1, h2, h3 {
            text-wrap: balance;
            color: var(--ink-primary);
            margin: 0;
          }
          h1 {
            font-size: 24px;
            line-height: 1.25;
            margin-bottom: 6px;
          }
          h2 {
            font-size: 16px;
            line-height: 1.3;
            margin-bottom: 12px;
            letter-spacing: 0.01em;
          }
          .subtitle {
            margin: 0;
            color: var(--ink-secondary);
            font-size: 13px;
          }
          .kpi-strip {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
          }
          .kpi-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-seam);
            border-radius: 6px;
            padding: 14px 16px;
          }
          .kpi-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--ink-secondary);
          }
          .kpi-value {
            font-family: ui-monospace, "SF Mono", Menlo, monospace;
            font-variant-numeric: tabular-nums;
            font-size: 20px;
            font-weight: 700;
            margin-top: 4px;
            color: var(--ink-primary);
          }
          section.panel {
            background: var(--bg-panel);
            border: 1px solid var(--border-seam);
            border-radius: 6px;
            padding: 20px 22px;
            margin-bottom: 18px;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
          }
          th, td {
            text-align: left;
            padding: 8px 10px;
            border-bottom: 1px solid var(--border-seam);
            vertical-align: top;
          }
          th {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--ink-secondary);
            background: var(--bg-elevated);
          }
          .mono {
            font-family: ui-monospace, "SF Mono", Menlo, monospace;
            font-variant-numeric: tabular-nums;
            font-size: 12px;
          }
          .num { text-align: right; }
          .muted { color: var(--ink-secondary); }
          .pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            font-family: ui-monospace, "SF Mono", Menlo, monospace;
          }
          .pill-ok { background: var(--status-ok-bg); color: var(--status-ok-fg); }
          .pill-warn { background: var(--status-warn-bg); color: var(--status-warn-fg); }
          .pill-crit { background: var(--status-crit-bg); color: var(--status-crit-fg); }
          .pill-info { background: #13233A; color: var(--accent-sapphire); }
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
            border-bottom: 1px solid var(--border-seam);
            font-size: 12px;
          }
          pre {
            margin: 0;
            padding: 12px 14px;
            background: #0B0E12;
            overflow-x: auto;
            font-family: ui-monospace, "SF Mono", Menlo, monospace;
            font-size: 12px;
            line-height: 1.48;
            color: var(--ink-primary);
          }
          </style>
        </head>
        <body>
          <div class="container">
            <header class="masthead">
              <p class="eyebrow">MachGraph v1.0.0 · Cold-Tungsten Binary Triage Dossier</p>
              <h1>\(escapeHTML(title)) (\(escapeHTML(archText)))</h1>
              <p class="subtitle">SHA-256: <span class="mono">\(escapeHTML(image.sha256Hex))</span> · Entry: <span class="mono">\(entryHex)</span> · CDHash: <span class="mono">\(escapeHTML(cdHashText))</span></p>
            </header>

            <div class="kpi-strip">
              <div class="kpi-card">
                <div class="kpi-label">Recovered Functions</div>
                <div class="kpi-value">\(analysisIndex.functions.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Decoded A64 Insns</div>
                <div class="kpi-value">\(analysisIndex.decodedInstructions.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Cross-References</div>
                <div class="kpi-value">\(analysisIndex.crossReferences.allRecords.count)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Shannon Entropy</div>
                <div class="kpi-value">\(String(format: "%.3f b/B", entropyProfile.overallMetrics.shannonEntropyBits))</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Security Findings</div>
                <div class="kpi-value">\(resolvedFindings.count)</div>
              </div>
            </div>

            <section class="panel">
              <h2>Memory Segments &amp; Protection Matrix</h2>
              <table>
                <thead>
                  <tr>
                    <th>Segment</th>
                    <th>VM Address</th>
                    <th class="num">VM Size</th>
                    <th>File Offset</th>
                    <th>Init / Max Prot</th>
                    <th class="num">Sections</th>
                  </tr>
                </thead>
                <tbody>
                  \(segmentRows)
                </tbody>
              </table>
            </section>

            <section class="panel">
              <h2>Recovered Control-Flow Functions &amp; Loop Complexity</h2>
              <table>
                <thead>
                  <tr>
                    <th>Entry</th>
                    <th>Symbol</th>
                    <th class="num">Blocks</th>
                    <th class="num">Cyclomatic</th>
                    <th class="num">Loops</th>
                    <th>ISA Mode</th>
                  </tr>
                </thead>
                <tbody>
                  \(functionRows)
                </tbody>
              </table>
            </section>

            <section class="panel">
              <h2>SSA Micro-IR Structured Pseudo-C Decompilation</h2>
              \(pseudoCSections)
            </section>

            <section class="panel">
              <h2>Sliding-Window Shannon Entropy Profile</h2>
              \(svgBars)
            </section>

            <section class="panel">
              <h2>JavaScriptCore Security Audit Ledger</h2>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Address</th>
                    <th>Finding</th>
                    <th>Evidence &amp; Reachability Detail</th>
                  </tr>
                </thead>
                <tbody>
                  \(findingRows)
                </tbody>
              </table>
            </section>
          </div>
        </body>
        </html>
        """
    }

    private func renderEntropySVG(samples: [EntropyRegionSample]) -> String {
        let capped = Array(samples.prefix(64))
        guard !capped.isEmpty else {
            return "<p class=\"muted\">Binary size smaller than sliding entropy window.</p>"
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

    private func sanitizeNoEmDash(_ text: String) -> String {
        text.replacingOccurrences(of: "\u{2014}", with: " - ")
    }

    private func escapeHTML(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
