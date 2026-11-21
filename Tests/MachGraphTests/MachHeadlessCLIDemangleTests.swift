import Foundation
import Testing
import MachGraphModels
import MachHeadlessCLI

@Suite("M3 Stage 4: Headless CLI demangle Subcommand (Positional, Stdin Batch, JSON & Bilingual Help)")
struct MachHeadlessCLIDemangleTests {

    @Test("M3 D-M3-2 (Red->Green 5a): machgraph demangle reads stdin line-by-line in text and --json modes")
    func m3CLIDemangleStdinBatchTextAndJSON() async throws {
        let batchLines = [
            "_$sSiN",
            "_$s15icloudmailagent11APNSManagerC8delegateAA0B8Delegate_pSgvM.resume.0",
            "__Z12set_darkbooti.cold.1",
            "_ZeroFilesTested",
            "_main",
            "_$s9MachGraph99Truncated"
        ]
        let stdinPayload = batchLines.joined(separator: "\n") + "\n"
        let cli = MachCLIRunner(stdinReader: { stdinPayload })

        let textOut = try await cli.execute(arguments: ["demangle"])
        let outLines = textOut.components(separatedBy: "\n")
        #expect(outLines == [
            "type metadata for Swift.Int",
            "icloudmailagent.APNSManager.delegate.modify : icloudmailagent.APNSManagerDelegate? with unmangled suffix \".resume.0\"",
            "set_darkboot(int) (.cold.1)",
            "_ZeroFilesTested",
            "_main",
            "_$s9MachGraph99Truncated"
        ])

        let jsonOut = try await cli.execute(arguments: ["demangle", "--json"])
        let parsed = try #require(JSONSerialization.jsonObject(with: Data(jsonOut.utf8)) as? [[String: Any]])
        #expect(parsed.count == 6)

        #expect(parsed[0]["input"] as? String == "_$sSiN")
        #expect(parsed[0]["output"] as? String == "type metadata for Swift.Int")
        #expect(parsed[0]["demangled"] as? Bool == true)

        #expect(parsed[2]["input"] as? String == "__Z12set_darkbooti.cold.1")
        #expect(parsed[2]["output"] as? String == "set_darkboot(int) (.cold.1)")
        #expect(parsed[2]["demangled"] as? Bool == true)

        #expect(parsed[3]["input"] as? String == "_ZeroFilesTested")
        #expect(parsed[3]["output"] as? String == "_ZeroFilesTested")
        #expect(parsed[3]["demangled"] as? Bool == false)

        #expect(parsed[4]["input"] as? String == "_main")
        #expect(parsed[4]["output"] as? String == "_main")
        #expect(parsed[4]["demangled"] as? Bool == false)

        #expect(parsed[5]["input"] as? String == "_$s9MachGraph99Truncated")
        #expect(parsed[5]["output"] as? String == "_$s9MachGraph99Truncated")
        #expect(parsed[5]["demangled"] as? Bool == false)
    }

    @Test("M3 D-M3-2 (Red->Green 5b): machgraph demangle accepts multiple positional symbols, ObjC selectors, empty stdin, bilingual --help, and rejects unknown flags")
    func m3CLIDemanglePositionalSymbolsHelpAndUnknownFlag() async throws {
        let cli = MachCLIRunner(stdinReader: {
            Issue.record("stdinReader must not be called when positional symbols are provided")
            return ""
        })

        let posText = try await cli.execute(arguments: [
            "demangle",
            "_$sSiN",
            "__Z3fooi",
            "_ZeroFilesTested",
            "-[MGAuthController validateToken:error:]"
        ])
        #expect(posText.components(separatedBy: "\n") == [
            "type metadata for Swift.Int",
            "foo(int)",
            "_ZeroFilesTested",
            "-[MGAuthController validateToken:error:]"
        ])

        let posJSON = try await cli.execute(arguments: ["demangle", "_$sSiN", "_main", "--json"])
        let arr = try #require(JSONSerialization.jsonObject(with: Data(posJSON.utf8)) as? [[String: Any]])
        #expect(arr.count == 2)
        #expect(arr[0]["demangled"] as? Bool == true)
        #expect(arr[1]["demangled"] as? Bool == false)

        // Empty stdin produces empty text / empty JSON array without error
        let emptyCLI = MachCLIRunner(stdinReader: { "" })
        #expect(try await emptyCLI.execute(arguments: ["demangle"]) == "")
        #expect(try await emptyCLI.execute(arguments: ["demangle", "--json"]) == "[]")

        // Bilingual --help includes demangle
        let helpEN = try await cli.execute(arguments: ["--help", "--lang", "en"])
        let helpZH = try await cli.execute(arguments: ["--help", "--lang", "zh"])
        #expect(helpEN.contains("demangle"))
        #expect(helpEN.contains("[<symbol...>] [--json]"))
        #expect(helpZH.contains("demangle"))
        #expect(helpZH.contains("[<符号...>] [--json]"))

        // Unknown option fails with exit code 2
        do {
            _ = try await cli.execute(arguments: ["demangle", "--bogus-flag"])
            Issue.record("Expected unknown flag to throw invalidCLIArguments")
        } catch let err as MachGraphError {
            #expect(MachCLIRunner.exitCode(for: err) == 2)
        }
    }
}
