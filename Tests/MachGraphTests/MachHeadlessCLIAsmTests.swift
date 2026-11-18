import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachHeadlessCLI

@Suite("M2 Stage 15a: Headless CLI Assembler Exit Codes & Unsupported Mnemonic Propagation")
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
}
