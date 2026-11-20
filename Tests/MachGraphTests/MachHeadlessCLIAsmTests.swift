import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachHeadlessCLI

@Suite("M2 Stage 15a & 15c: Headless CLI Assembler Subcommand, Exit Codes & Unsupported Propagation")
struct MachHeadlessCLIAsmTests {

    @Test("15a(d): MachCLIRunner.exitCode(for:) maps assemblerUnsupported to 3, assemblerError to 1, invalidCLIArguments to 2")
    func exitCodeMappingForAssemblerErrorsAndUsageErrors() {
        let unsupported = MachGraphError.assemblerUnsupported(
            mnemonic: "shrn",
            form: "shrn v1.4h, v1.4s, #0x10"
        )
        let asmErr = MachGraphError.assemblerError(
            line: 1,
            instruction: "bogus x1",
            reason: "Unknown ARM64 mnemonic 'bogus'"
        )
        let cliUsageErr = MachGraphError.invalidCLIArguments("Missing binary path")

        #expect(MachCLIRunner.exitCode(for: unsupported) == 3)
        #expect(MachCLIRunner.exitCode(for: asmErr) == 1)
        #expect(MachCLIRunner.exitCode(for: cliUsageErr) == 2)
    }

    @Test("15a(d): patch-asm propagates assemblerUnsupported (exit code 3) without writing output")
    func patchAsmPropagatesAssemblerUnsupportedWithExitCode3() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mg-cli-asm-15a-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let inputBin = tempDir.appendingPathComponent("sample.macho")
        let outputBin = tempDir.appendingPathComponent("patched.macho")
        let originalData = try RepoFixtures.thinARM64SampleData()
        try originalData.write(to: inputBin)
        let image = try UniversalBinaryDispatcher.load(data: originalData, fileName: "sample.macho")
        let targetSym = try #require(image.symbols.first { $0.name == "_demo_fnv1a32" })
        let address = targetSym.address.compactHexString

        let cli = MachCLIRunner()
        var caught: MachGraphError?
        do {
            _ = try await cli.execute(arguments: [
                "patch-asm", inputBin.path,
                "--address", address,
                "--asm", "nop; autdza x16",
                "--output", outputBin.path,
            ])
        } catch let err as MachGraphError {
            caught = err
        }

        if case .assemblerUnsupported(let mnem, _) = caught {
            #expect(mnem == "autdza")
            #expect(MachCLIRunner.exitCode(for: caught!) == 3)
        } else {
            Issue.record("Expected assemblerUnsupported from patch-asm on 'nop; autdza x16', got \(String(describing: caught))")
        }
        #expect(!FileManager.default.fileExists(atPath: outputBin.path))

        // Stage 15b: implemented mnemonic with unsupported SIMD operand sequence also exits with 3 via patch-asm.
        var simdCaught: MachGraphError?
        do {
            _ = try await cli.execute(arguments: [
                "patch-asm", inputBin.path,
                "--address", address,
                "--asm", "nop; mul v2.4s, v2.4s, v4.4s",
                "--output", outputBin.path,
            ])
        } catch let err as MachGraphError {
            simdCaught = err
        }

        if case .assemblerUnsupported(let mnem, let form) = simdCaught {
            #expect(mnem == "mul")
            #expect(form == "mul V.Ns, V.Ns, V.Ns")
            #expect(MachCLIRunner.exitCode(for: simdCaught!) == 3)
        } else {
            Issue.record("Expected assemblerUnsupported from patch-asm on 'nop; mul v2.4s, v2.4s, v4.4s', got \(String(describing: simdCaught))")
        }
        #expect(!FileManager.default.fileExists(atPath: outputBin.path))
    }

    // MARK: - Stage 15c: `machgraph asm` Subcommand Tests

    private final class StdinCallTracker: @unchecked Sendable {
        var count = 0
        let payload: String
        init(_ payload: String = "") {
            self.payload = payload
        }
        func read() -> String {
            count += 1
            return payload
        }
    }

    @Test("15c(1): asm --at 0x100000000 --asm 'mov x0, #42; ret' succeeds with exit 0 in text and --json modes, and default --at is 0")
    func asmBasicTextAndJSONOutputWithSteppingAddresses() async throws {
        let tracker = StdinCallTracker("MUST NOT READ")
        let cli = MachCLIRunner { tracker.read() }

        let textOutcome = try await cli.run(arguments: [
            "asm", "--at", "0x100000000", "--asm", "mov x0, #42; ret",
        ])
        #expect(tracker.count == 0)
        #expect(textOutcome.exitCode == 0)
        #expect(textOutcome.stderr.isEmpty)
        let lines = textOutcome.output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines == [
            "0x0000000100000000\td2800540\tok\tmov x0, #42",
            "0x0000000100000004\td65f03c0\tok\tret",
        ])

        let jsonOutcome = try await cli.run(arguments: [
            "asm", "--at", "0x100000000", "--asm", "mov x0, #42; ret", "--json",
        ])
        #expect(jsonOutcome.exitCode == 0)
        #expect(jsonOutcome.stderr.isEmpty)
        let doc = try #require(JSONSerialization.jsonObject(with: Data(jsonOutcome.output.utf8)) as? [String: Any])
        #expect(doc["at"] as? String == "0x100000000")
        let summary = try #require(doc["summary"] as? [String: Int])
        #expect(summary == ["ok": 2, "unsupported": 0, "error": 0])
        let results = try #require(doc["results"] as? [[String: Any]])
        #expect(results.count == 2)
        #expect(results[0]["index"] as? Int == 0)
        #expect(results[0]["address"] as? String == "0x100000000")
        #expect(results[0]["text"] as? String == "mov x0, #42")
        #expect(results[0]["status"] as? String == "ok")
        #expect(results[0]["word"] as? String == "d2800540")
        #expect(results[1]["index"] as? Int == 1)
        #expect(results[1]["address"] as? String == "0x100000004")
        #expect(results[1]["text"] as? String == "ret")
        #expect(results[1]["status"] as? String == "ok")
        #expect(results[1]["word"] as? String == "d65f03c0")

        // Omitting --at defaults to 0x0.
        let defaultAt = try await cli.run(arguments: ["asm", "--asm", "nop", "--json"])
        #expect(defaultAt.exitCode == 0)
        let defaultDoc = try #require(JSONSerialization.jsonObject(with: Data(defaultAt.output.utf8)) as? [String: Any])
        #expect(defaultDoc["at"] as? String == "0x0")
        let defaultResults = try #require(defaultDoc["results"] as? [[String: Any]])
        #expect(defaultResults.first?["address"] as? String == "0x0")
        #expect(defaultResults.first?["word"] as? String == "d503201f")
    }

    @Test("15c(2): PC-relative branch, statement-local labels, and .inst/.word directives advance by 4 bytes per statement")
    func asmPCRelativeLocalLabelsAndWordDirectives() async throws {
        let cli = MachCLIRunner { "" }

        let pcRel = try await cli.run(arguments: [
            "asm", "--at", "0x100000000", "--asm", "nop; b 0x100000000", "--json",
        ])
        #expect(pcRel.exitCode == 0)
        let doc = try #require(JSONSerialization.jsonObject(with: Data(pcRel.output.utf8)) as? [String: Any])
        let results = try #require(doc["results"] as? [[String: Any]])
        #expect(results.count == 2)
        #expect(results[0]["address"] as? String == "0x100000000")
        #expect(results[0]["word"] as? String == "d503201f")
        #expect(results[1]["address"] as? String == "0x100000004")
        #expect(results[1]["word"] as? String == "17ffffff")

        // Statement-local label works within the same statement, but does not cross statements.
        let localLabel = try await cli.run(arguments: [
            "asm", "--at", "0x1000", "--asm", "self: b self; target: nop; b target", "--json",
        ])
        #expect(localLabel.exitCode == 1)
        let labelDoc = try #require(JSONSerialization.jsonObject(with: Data(localLabel.output.utf8)) as? [String: Any])
        let labelRes = try #require(labelDoc["results"] as? [[String: Any]])
        #expect(labelRes.count == 3)
        #expect(labelRes[0]["status"] as? String == "ok")
        #expect(labelRes[0]["word"] as? String == "14000000")
        #expect(labelRes[1]["status"] as? String == "ok")
        #expect(labelRes[1]["word"] as? String == "d503201f")
        #expect(labelRes[2]["status"] as? String == "error")

        // .inst and .word each occupy 4 bytes as a single word.
        let directives = try await cli.run(arguments: [
            "asm", "--at", "0x2000", "--asm", ".inst 0x01020304; .word 0xaabbccdd; ret",
        ])
        #expect(directives.exitCode == 0)
        let dirLines = directives.output.split(separator: "\n").map(String.init)
        #expect(dirLines == [
            "0x0000000000002000\t01020304\tok\t.inst 0x01020304",
            "0x0000000000002004\taabbccdd\tok\t.word 0xaabbccdd",
            "0x0000000000002008\td65f03c0\tok\tret",
        ])
    }

    @Test("15c(3): unsupported A64 form returns exit code 3 with mnemonic and form in JSON and text")
    func asmUnsupportedReturnsExitCode3WithMnemonicAndForm() async throws {
        let cli = MachCLIRunner { "" }

        let textOut = try await cli.run(arguments: [
            "asm", "--asm", "shrn v1.4h, v1.4s, #0x10", "--lang", "en",
        ])
        #expect(textOut.exitCode == 3)
        #expect(textOut.output == "0x0000000000000000\t-\tunsupported\tshrn v1.4h, v1.4s, #0x10\tshrn V.Nh, V.Ns, #N")
        #expect(textOut.stderr.contains("1 unsupported"))
        #expect(textOut.stderr.contains("0 error"))

        let jsonOut = try await cli.run(arguments: [
            "asm", "--asm", "shrn v1.4h, v1.4s, #0x10", "--json", "--lang", "en",
        ])
        #expect(jsonOut.exitCode == 3)
        #expect(!jsonOut.stderr.isEmpty)
        let doc = try #require(JSONSerialization.jsonObject(with: Data(jsonOut.output.utf8)) as? [String: Any])
        let summary = try #require(doc["summary"] as? [String: Int])
        #expect(summary == ["ok": 0, "unsupported": 1, "error": 0])
        let results = try #require(doc["results"] as? [[String: Any]])
        #expect(results.count == 1)
        let item = results[0]
        #expect(item["index"] as? Int == 0)
        #expect(item["address"] as? String == "0x0")
        #expect(item["text"] as? String == "shrn v1.4h, v1.4s, #0x10")
        #expect(item["status"] as? String == "unsupported")
        #expect(item["word"] is NSNull)
        #expect(item["mnemonic"] as? String == "shrn")
        #expect(item["form"] as? String == "shrn V.Nh, V.Ns, #N")
    }

    @Test("15c(4): error returns exit code 1, takes precedence over unsupported, and still emits all statement results")
    func asmErrorPrecedenceAndAllResultsEmitted() async throws {
        let cli = MachCLIRunner { "" }

        let singleErr = try await cli.run(arguments: [
            "asm", "--asm", "bogus x1", "--lang", "en",
        ])
        #expect(singleErr.exitCode == 1)
        #expect(singleErr.output.hasPrefix("0x0000000000000000\t-\terror\tbogus x1\t"))
        #expect(singleErr.output.contains("Unknown ARM64 mnemonic 'bogus'"))
        #expect(singleErr.stderr.contains("1 error"))

        let mixedText = try await cli.run(arguments: [
            "asm", "--at", "0x100", "--asm", "nop; bogus x1; shrn v1.4h, v1.4s, #0x10", "--lang", "en",
        ])
        #expect(mixedText.exitCode == 1)
        let textLines = mixedText.output.split(separator: "\n").map(String.init)
        #expect(textLines.count == 3)
        #expect(textLines[0] == "0x0000000000000100\td503201f\tok\tnop")
        #expect(textLines[1].hasPrefix("0x0000000000000104\t-\terror\tbogus x1\t"))
        #expect(textLines[2] == "0x0000000000000108\t-\tunsupported\tshrn v1.4h, v1.4s, #0x10\tshrn V.Nh, V.Ns, #N")
        #expect(mixedText.stderr.contains("1 unsupported"))
        #expect(mixedText.stderr.contains("1 error"))

        let mixedJSON = try await cli.run(arguments: [
            "asm", "--at", "0x100", "--asm", "nop; bogus x1; shrn v1.4h, v1.4s, #0x10", "--json", "--lang", "en",
        ])
        #expect(mixedJSON.exitCode == 1)
        let doc = try #require(JSONSerialization.jsonObject(with: Data(mixedJSON.output.utf8)) as? [String: Any])
        let summary = try #require(doc["summary"] as? [String: Int])
        #expect(summary == ["ok": 1, "unsupported": 1, "error": 1])
        let results = try #require(doc["results"] as? [[String: Any]])
        #expect(results.count == 3)
        #expect(results[0]["status"] as? String == "ok")
        #expect(results[0]["word"] as? String == "d503201f")
        #expect(results[1]["status"] as? String == "error")
        #expect(results[1]["word"] is NSNull)
        #expect((results[1]["reason"] as? String)?.contains("bogus") == true)
        #expect(results[2]["status"] as? String == "unsupported")
        #expect(results[2]["word"] is NSNull)
        #expect(results[2]["mnemonic"] as? String == "shrn")
        #expect(results[2]["form"] as? String == "shrn V.Nh, V.Ns, #N")
    }

    @Test("15c(5): usage errors fail with exit code 2 before touching stdin, and empty/comment-only input exits 2")
    func asmUsageErrorsExit2WithoutReadingStdinAndRejectEmptyInput() async throws {
        let preStdinCases: [[String]] = [
            ["asm", "/usr/bin/true"],
            ["asm", "--at", "zz", "--asm", "nop"],
            ["asm", "--at", "zz"],
            ["asm", "--nosuch"],
            ["asm", "--asm", "   // only comment ; /* block */   "],
        ]

        for args in preStdinCases {
            let tracker = StdinCallTracker("nop\n")
            let cli = MachCLIRunner { tracker.read() }
            var caught: Error?
            do {
                _ = try await cli.run(arguments: args)
            } catch {
                caught = error
            }
            let err = try #require(caught as? MachGraphError, "Expected MachGraphError for \(args), got \(String(describing: caught))")
            if case .invalidCLIArguments(let detail) = err {
                #expect(!detail.contains("Unknown subcommand"), "Expected asm-specific usage error for \(args), got \(detail)")
                #expect(MachCLIRunner.exitCode(for: err) == 2)
            } else {
                Issue.record("Expected invalidCLIArguments (exit 2) for \(args), got \(err)")
            }
            #expect(tracker.count == 0, "stdin must not be read when arguments \(args) fail before stdin")
        }

        // Empty stdin and comment-only stdin also fail as usage errors (exit code 2).
        for emptyStdin in ["", "   \n\n  // line comment ; not a statement\n /* multi-line\n comment */ ; \n"] {
            let tracker = StdinCallTracker(emptyStdin)
            let cli = MachCLIRunner { tracker.read() }
            var caught: Error?
            do {
                _ = try await cli.run(arguments: ["asm"])
            } catch {
                caught = error
            }
            #expect(tracker.count == 1)
            let err = try #require(caught as? MachGraphError)
            if case .invalidCLIArguments = err {
                #expect(MachCLIRunner.exitCode(for: err) == 2)
            } else {
                Issue.record("Expected invalidCLIArguments (exit 2) for empty/comment stdin, got \(err)")
            }
        }
    }

    @Test("15c(6): reading statements from injected stdin strips // and /* */ comments and steps addresses continuously")
    func asmReadsFromInjectedStdinAndStripsComments() async throws {
        let tracker = StdinCallTracker("mov x0, #1\n\n// comment; ignored\n/* block ; comment */ ret\n")
        let cli = MachCLIRunner { tracker.read() }

        let outcome = try await cli.run(arguments: ["asm", "--at", "0x4000"])
        #expect(tracker.count == 1)
        #expect(outcome.exitCode == 0)
        #expect(outcome.stderr.isEmpty)
        let lines = outcome.output.split(separator: "\n").map(String.init)
        #expect(lines == [
            "0x0000000000004000\td2800020\tok\tmov x0, #1",
            "0x0000000000004004\td65f03c0\tok\tret",
        ])
    }

    @Test("15c(7) & 15c(8): --lang zh localizes stderr summary & usage diagnostics, and --help (en + zh) lists asm, --at, and local label scope")
    func asmChineseLocalizationAndHelpDocumentation() async throws {
        let cli = MachCLIRunner { "" }

        let zhMixed = try await cli.run(arguments: [
            "asm", "--asm", "nop; bogus x1; shrn v1.4h, v1.4s, #0x10", "--lang", "zh",
        ])
        #expect(zhMixed.exitCode == 1)
        #expect(zhMixed.stderr.contains("汇总"))
        #expect(zhMixed.stderr.contains("不支持"))
        #expect(zhMixed.stderr.contains("错误"))

        var zhUsageErr: MachGraphError?
        do {
            _ = try await cli.run(arguments: ["asm", "/usr/bin/true", "--lang", "zh"])
        } catch let err as MachGraphError {
            zhUsageErr = err
        }
        let usageMsgZH = try #require(zhUsageErr?.localizedMessage(in: .zhHans))
        #expect(usageMsgZH.contains("位置参数"))

        let helpEN = try await cli.execute(arguments: ["--help", "--lang", "en"])
        let helpZH = try await cli.execute(arguments: ["--help", "--lang", "zh"])

        for helpText in [helpEN, helpZH] {
            #expect(helpText.contains("asm [--asm \"<insn>; <insn>\"] [--at <0x...>] [--json]"))
            #expect(helpText.contains("--at <0x...>"))
            #expect(helpText.contains("patch-asm"))
        }
        #expect(helpEN.contains("without reading or writing files"))
        #expect(helpEN.contains("label:"))
        #expect(helpZH.contains("不读写任何文件"))
        #expect(helpZH.contains("第一条语句的地址，之后每条加 4"))
        #expect(helpZH.contains("不跨语句"))
    }
}
