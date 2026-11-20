import Foundation
import Testing
import MachGraphModels
import MachA64Decoder

@Suite("M2 Stage 15e: Pre-M2 14 Round-Trip Forms & Reference Table Verification")
struct MachA64DecoderStage15eTests {

    private let decoder = A64InstructionDecoder()
    private let assembler = A64MiniAssembler()

    private struct ReferenceRow {
        let word: UInt32
        let refMnemonic: String
        let refOperands: String
    }

    private static func loadReferenceRows(tableFileName: String) throws -> [ReferenceRow] {
        let url = RepoFixtures.repositoryRoot
            .appendingPathComponent("Fixtures", isDirectory: true)
            .appendingPathComponent("a64", isDirectory: true)
            .appendingPathComponent(tableFileName)
        let rawText = try String(contentsOf: url, encoding: .utf8)
        var rows: [ReferenceRow] = []
        for rawLine in rawText.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") {
                continue
            }
            let cols = rawLine.split(separator: "\t", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            guard cols.count >= 2 else { continue }
            let firstCol = cols[0]
            let hexPart = (firstCol.hasPrefix("0x") || firstCol.hasPrefix("0X"))
                ? String(firstCol.dropFirst(2))
                : firstCol
            let word = try #require(UInt32(hexPart, radix: 16), "Invalid word '\(firstCol)' in \(tableFileName)")
            let refMnem = cols[1]
            let refOps = cols.count >= 3 ? cols[2] : ""
            if refMnem == ".long" {
                continue
            }
            rows.append(ReferenceRow(word: word, refMnemonic: refMnem, refOperands: refOps))
        }
        return rows
    }

    private func assertExactRoundTrip(
        word: UInt32,
        expectedText: String? = nil,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_2000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) throws {
        let decoded = decoder.decode(word: word, at: pc)
        #expect(decoded.mnemonicText != ".inst", "Decoder returned .inst for \(String(format: "0x%08x", word))", sourceLocation: sourceLocation)
        if let expectedText {
            #expect(decoded.formattedDisassembly == expectedText, sourceLocation: sourceLocation)
        }
        let encoded = try assembler.assembleSingle(decoded.formattedDisassembly, at: pc)
        #expect(
            encoded == word,
            "Round-trip mismatch for '\(decoded.formattedDisassembly)': expected \(String(format: "0x%08x", word)), got \(String(format: "0x%08x", encoded))",
            sourceLocation: sourceLocation
        )
    }

    private func expectUnsupported(
        _ statement: String,
        mnemonic expectedMnemonic: String,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_2000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            let w = try assembler.assembleSingle(statement, at: pc)
            Issue.record(
                "Expected assemblerUnsupported for '\(statement)', got word \(String(format: "0x%08x", w))",
                sourceLocation: sourceLocation
            )
        } catch let MachGraphError.assemblerUnsupported(mnem, _) {
            #expect(mnem == expectedMnemonic, sourceLocation: sourceLocation)
        } catch {
            Issue.record(
                "Expected assemblerUnsupported for '\(statement)', got \(error)",
                sourceLocation: sourceLocation
            )
        }
    }

    // MARK: - Item 1: Vector `mov Vd.8b/16b, Vn.8b/16b` (ORR alias, G56)

    @Test("15e(1): Vector mov Vd.8b/16b, Vn.8b/16b round-trips corpus example and advsimd_vec_three_same.tsv mov rows")
    func vectorMovByteArrangementsRoundTrip() throws {
        // Corpus example (/usr/bin/ssh @ 0x1000028a8) + 8b counterpart
        try assertExactRoundTrip(
            word: 0x4EA0_1C08,
            expectedText: "mov v8.16b, v0.16b",
            at: VirtualAddress(0x1_0000_28A8)
        )
        try assertExactRoundTrip(
            word: 0x0EA5_1CA3,
            expectedText: "mov v3.8b, v5.8b"
        )

        // All `mov` rows in Fixtures/a64/advsimd_vec_three_same.tsv (2 rows: 8b and 16b)
        let rows = try Self.loadReferenceRows(tableFileName: "advsimd_vec_three_same.tsv")
            .filter { $0.refMnemonic == "mov" }
        #expect(rows.count == 2)
        for row in rows {
            try assertExactRoundTrip(word: row.word)
        }

        // Unimplemented SIMD mov forms remain assemblerUnsupported
        expectUnsupported("mov s10, v2.s[1]", mnemonic: "mov")
        expectUnsupported("mov v1.s[3], v0.s[3]", mnemonic: "mov")
    }

    // MARK: - Item 4: 32-bit Shifted `movi Vd.2s|4s, #imm8, lsl #0|8|16|24`

    private func expectAssemblerError(
        _ statement: String,
        at pc: VirtualAddress = VirtualAddress(0x1_0000_2000),
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            let w = try assembler.assembleSingle(statement, at: pc)
            Issue.record(
                "Expected assemblerError for '\(statement)', got word \(String(format: "0x%08x", w))",
                sourceLocation: sourceLocation
            )
        } catch MachGraphError.assemblerError {
            // Expected
        } catch {
            Issue.record(
                "Expected assemblerError for '\(statement)', got \(error)",
                sourceLocation: sourceLocation
            )
        }
    }

    @Test("15e(4): Shifted movi Vd.2s/4s, #imm8, lsl #0/8/16/24 matches clang-compiled arm64e words and keeps msl/4h/8h unsupported")
    func shiftedMovi32BitImmediateMatchesClangAndRejectsUnimplementedShifts() throws {
        // Corpus example (/usr/bin/ssh @ 0x10003c0c8): 4f006441 -> movi v1.4s, #0x2, lsl #24
        // (Stage 11a Group 11 aligned AdvSIMD modified-immediate disassembly with LLVM's hex #0x2;
        // decimal #2 input must also continue assembling to the exact same machine word.)
        try assertExactRoundTrip(
            word: 0x4F00_6441,
            expectedText: "movi v1.4s, #0x2, lsl #24",
            at: VirtualAddress(0x1_0003_C0C8)
        )
        #expect(
            try assembler.assembleSingle("movi v1.4s, #2, lsl #24", at: VirtualAddress(0x1_0003_C0C8)) == 0x4F00_6441
        )

        // Expected machine words below were obtained by assembling each instruction with:
        //   xcrun clang -c -arch arm64e -mcpu=apple-m1 probe.s -o probe.o
        // and reading the 32-bit little-endian words directly from __TEXT,__text of probe.o
        // across {2s, 4s} x {lsl #0, #8, #16, #24} x {#0, #1, #0x80, #0xff}.
        let clangVerifiedCases: [(String, UInt32)] = [
            ("movi v0.2s, #0, lsl #0",     0x0F00_0400),
            ("movi v1.2s, #1, lsl #0",     0x0F00_0421),
            ("movi v7.2s, #0x80, lsl #0",  0x0F04_0407),
            ("movi v31.2s, #0xff, lsl #0", 0x0F07_07FF),
            ("movi v0.2s, #0, lsl #8",     0x0F00_2400),
            ("movi v1.2s, #1, lsl #8",     0x0F00_2421),
            ("movi v7.2s, #0x80, lsl #8",  0x0F04_2407),
            ("movi v31.2s, #0xff, lsl #8", 0x0F07_27FF),
            ("movi v0.2s, #0, lsl #16",    0x0F00_4400),
            ("movi v1.2s, #1, lsl #16",    0x0F00_4421),
            ("movi v7.2s, #0x80, lsl #16", 0x0F04_4407),
            ("movi v31.2s, #0xff, lsl #16", 0x0F07_47FF),
            ("movi v0.2s, #0, lsl #24",    0x0F00_6400),
            ("movi v1.2s, #1, lsl #24",    0x0F00_6421),
            ("movi v7.2s, #0x80, lsl #24", 0x0F04_6407),
            ("movi v31.2s, #0xff, lsl #24", 0x0F07_67FF),
            ("movi v0.4s, #0, lsl #0",     0x4F00_0400),
            ("movi v1.4s, #1, lsl #0",     0x4F00_0421),
            ("movi v7.4s, #0x80, lsl #0",  0x4F04_0407),
            ("movi v31.4s, #0xff, lsl #0", 0x4F07_07FF),
            ("movi v0.4s, #0, lsl #8",     0x4F00_2400),
            ("movi v1.4s, #1, lsl #8",     0x4F00_2421),
            ("movi v7.4s, #0x80, lsl #8",  0x4F04_2407),
            ("movi v31.4s, #0xff, lsl #8", 0x4F07_27FF),
            ("movi v0.4s, #0, lsl #16",    0x4F00_4400),
            ("movi v1.4s, #1, lsl #16",    0x4F00_4421),
            ("movi v7.4s, #0x80, lsl #16", 0x4F04_4407),
            ("movi v31.4s, #0xff, lsl #16", 0x4F07_47FF),
            ("movi v0.4s, #0, lsl #24",    0x4F00_6400),
            ("movi v1.4s, #1, lsl #24",    0x4F00_6421),
            ("movi v7.4s, #0x80, lsl #24", 0x4F04_6407),
            ("movi v31.4s, #0xff, lsl #24", 0x4F07_67FF),
        ]

        let pc = VirtualAddress(0x1_0000_2000)
        for (stmt, expectedWord) in clangVerifiedCases {
            let encoded = try assembler.assembleSingle(stmt, at: pc)
            #expect(
                encoded == expectedWord,
                "For '\(stmt)', expected \(String(format: "0x%08x", expectedWord)), got \(String(format: "0x%08x", encoded))"
            )
            // For non-zero shifts, decoder disassembly also equals input and round-trips to the exact word.
            if !stmt.hasSuffix("lsl #0") {
                try assertExactRoundTrip(word: expectedWord, at: pc)
            }
        }

        // Unimplemented modified-immediate variants must throw assemblerUnsupported (never mis-encode):
        expectUnsupported("movi v0.2s, #0x3f, msl #8", mnemonic: "movi")
        expectUnsupported("movi v0.4s, #0x3f, msl #16", mnemonic: "movi")
        expectUnsupported("movi v0.4h, #0x5", mnemonic: "movi")
        expectUnsupported("movi v0.8h, #0x1, lsl #8", mnemonic: "movi")
        expectUnsupported("mvni v0.4s, #0x1, lsl #8", mnemonic: "mvni")

        // Invalid shift amounts / immediates / shift kinds remain assemblerError:
        expectAssemblerError("movi v0.4s, #1, lsl #4")
        expectAssemblerError("movi v0.4s, #1, lsl #32")
        expectAssemblerError("movi v0.4s, #0x100, lsl #8")
        expectAssemblerError("movi v0.4s, #1, lsr #8")
        expectAssemblerError("movi v0.2s, #1, msl #4")
    }

    // MARK: - Item 3: Element-to-GP `umov` and `mov` Alias (G56)

    @Test("15e(3): Element-to-GP umov Wd, Vn.b/h/s[i], umov Xd, Vn.d[i], and mov Wd/Xd, Vn.s/d[i] round-trip corpus and advsimd_copy.tsv while smov stays unsupported")
    func elementToGPUMovAndMovAliasRoundTrip() throws {
        // Corpus examples
        try assertExactRoundTrip(
            word: 0x0E02_3C44,
            expectedText: "umov w4, v2.h[0]",
            at: VirtualAddress(0x1_0003_EF3C)
        )
        try assertExactRoundTrip(
            word: 0x0E1C_3C09,
            expectedText: "mov w9, v0.s[3]",
            at: VirtualAddress(0x1_001E_92AC)
        )
        try assertExactRoundTrip(
            word: 0x4E18_3C6C,
            expectedText: "mov x12, v3.d[1]",
            at: VirtualAddress(0x1_0004_0C30)
        )

        // Explicit `umov` spelling on .s and .d (accepted by clang) produces identical machine words
        let pc = VirtualAddress(0x1_0000_2000)
        #expect(try assembler.assembleSingle("umov w9, v0.s[3]", at: pc) == 0x0E1C_3C09)
        #expect(try assembler.assembleSingle("umov x12, v3.d[1]", at: pc) == 0x4E18_3C6C)
        #expect(try assembler.assembleSingle("umov w6, v1.b[15]", at: pc) == 0x0E1F_3C26)
        #expect(try assembler.assembleSingle("umov wzr, v2.h[0]", at: pc) == 0x0E02_3C5F)
        #expect(try assembler.assembleSingle("mov xzr, v3.d[1]", at: pc) == 0x4E18_3C7F)

        // Reference table Fixtures/a64/advsimd_copy.tsv:
        // - all 24 `umov` rows
        // - all 6 `mov W/X, V.s/d[i]` rows
        // - all 52 `smov` rows remain assemblerUnsupported
        let copyRows = try Self.loadReferenceRows(tableFileName: "advsimd_copy.tsv")
        let umovRows = copyRows.filter { $0.refMnemonic == "umov" }
        let movToGPRows = copyRows.filter {
            $0.refMnemonic == "mov" && ($0.refOperands.hasPrefix("w") || $0.refOperands.hasPrefix("x"))
        }
        let smovRows = copyRows.filter { $0.refMnemonic == "smov" }

        #expect(umovRows.count == 24)
        #expect(movToGPRows.count == 6)
        #expect(smovRows.count == 52)

        for row in umovRows + movToGPRows {
            try assertExactRoundTrip(word: row.word)
        }
        for row in smovRows {
            let decoded = decoder.decode(word: row.word, at: pc)
            expectUnsupported(decoded.formattedDisassembly, mnemonic: "smov", at: pc)
        }

        // Out-of-range lane indices and SP/WSP destinations are assemblerError
        expectAssemblerError("umov w0, v1.b[16]")
        expectAssemblerError("umov w0, v1.h[8]")
        expectAssemblerError("mov w0, v1.s[4]")
        expectAssemblerError("umov w0, v1.s[4]")
        expectAssemblerError("mov x0, v1.d[2]")
        expectAssemblerError("umov x0, v1.d[2]")
        expectAssemblerError("umov wsp, v1.h[0]")
        expectAssemblerError("mov sp, v1.d[0]")
    }

    // MARK: - Item 2: GP-to-Element `mov Vd.b/h/s/d[i], Wn/Xn` and `ins` Alias (G56)

    @Test("15e(2): GP-to-element mov Vd.b/h/s[i], Wn and mov Vd.d[i], Xn (plus ins) round-trip corpus and advsimd_copy.tsv while element-to-element stays unsupported")
    func gpToElementMovAndInsAliasRoundTrip() throws {
        // Corpus examples + .b lane example
        try assertExactRoundTrip(
            word: 0x4E0C_1D84,
            expectedText: "mov v4.s[1], w12",
            at: VirtualAddress(0x1_0004_6084)
        )
        try assertExactRoundTrip(
            word: 0x4E18_1D83,
            expectedText: "mov v3.d[1], x12",
            at: VirtualAddress(0x1_0004_0C48)
        )
        try assertExactRoundTrip(
            word: 0x4E06_1DC7,
            expectedText: "mov v7.h[1], w14",
            at: VirtualAddress(0x1_0004_0F98)
        )
        try assertExactRoundTrip(
            word: 0x4E1B_1D25,
            expectedText: "mov v5.b[13], w9"
        )

        // Zero-register GP sources and explicit `ins` spelling (clang-verified)
        let pc = VirtualAddress(0x1_0000_2000)
        #expect(try assembler.assembleSingle("mov v1.s[0], wzr", at: pc) == 0x4E04_1FE1)
        #expect(try assembler.assembleSingle("mov v1.d[1], xzr", at: pc) == 0x4E18_1FE1)
        #expect(try assembler.assembleSingle("ins v4.s[1], w12", at: pc) == 0x4E0C_1D84)
        #expect(try assembler.assembleSingle("ins v3.d[1], x12", at: pc) == 0x4E18_1D83)
        #expect(try assembler.assembleSingle("ins v7.h[1], w14", at: pc) == 0x4E06_1DC7)
        #expect(try assembler.assembleSingle("ins v5.b[13], w9", at: pc) == 0x4E1B_1D25)

        // Reference table Fixtures/a64/advsimd_copy.tsv:
        // - all 30 GP-source element `mov` rows round-trip to exact machine words
        // - all 480 element-to-element `mov` rows throw assemblerUnsupported when assembled from reference text
        let copyRows = try Self.loadReferenceRows(tableFileName: "advsimd_copy.tsv")
        let gpToElemRows = copyRows.filter { row in
            guard row.refMnemonic == "mov", row.refOperands.hasPrefix("v") else { return false }
            let parts = row.refOperands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            return parts.count == 2 && !parts[1].hasPrefix("v")
        }
        let elemToElemRows = copyRows.filter { row in
            guard row.refMnemonic == "mov", row.refOperands.hasPrefix("v") else { return false }
            let parts = row.refOperands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            return parts.count == 2 && parts[1].hasPrefix("v")
        }

        #expect(gpToElemRows.count == 30)
        #expect(elemToElemRows.count == 480)

        for row in gpToElemRows {
            try assertExactRoundTrip(word: row.word)
        }
        for row in elemToElemRows {
            expectUnsupported("mov \(row.refOperands)", mnemonic: "mov", at: pc)
            expectUnsupported("ins \(row.refOperands)", mnemonic: "ins", at: pc)
        }

        // Out-of-range lane indices and SP/WSP sources are assemblerError
        expectAssemblerError("mov v0.b[16], w1")
        expectAssemblerError("mov v0.h[8], w1")
        expectAssemblerError("mov v0.s[4], w1")
        expectAssemblerError("mov v0.d[2], x1")
        expectAssemblerError("mov v0.s[0], wsp")
        expectAssemblerError("mov v0.d[0], sp")
        expectAssemblerError("ins v0.s[4], w1")
        expectAssemblerError("ins v0.d[0], sp")
    }

    // MARK: - Item 5: Element-Source `dup Vd.T, Vn.Ts[i]`

    @Test("15e(5): Element-source dup Vd.T, Vn.Ts[i] round-trips corpus examples and all 58 advsimd_copy.tsv rows while scalar dup stays unsupported")
    func elementSourceDupRoundTrips() throws {
        // Corpus examples
        try assertExactRoundTrip(
            word: 0x4E0C_0444,
            expectedText: "dup v4.4s, v2.s[1]",
            at: VirtualAddress(0x1_0003_EEE4)
        )
        try assertExactRoundTrip(
            word: 0x0E03_04A7,
            expectedText: "dup v7.8b, v5.b[1]",
            at: VirtualAddress(0x1_0004_0F74)
        )

        // All 58 element-source `dup` rows in Fixtures/a64/advsimd_copy.tsv
        let copyRows = try Self.loadReferenceRows(tableFileName: "advsimd_copy.tsv")
        let elemDupRows = copyRows.filter { $0.refMnemonic == "dup" && $0.refOperands.contains("[") }
        #expect(elemDupRows.count == 58)
        for row in elemDupRows {
            try assertExactRoundTrip(word: row.word)
        }

        // Scalar dup (both `dup s10, v2.s[1]` and LLVM's `mov s10, v2.s[1]`) stays assemblerUnsupported
        expectUnsupported("dup s10, v2.s[1]", mnemonic: "dup")
        expectUnsupported("dup d0, v1.d[0]", mnemonic: "dup")
        expectUnsupported("mov s10, v2.s[1]", mnemonic: "mov")

        // Out-of-range lane indices throw assemblerError
        expectAssemblerError("dup v0.8b, v1.b[16]")
        expectAssemblerError("dup v0.16b, v1.b[16]")
        expectAssemblerError("dup v0.4h, v1.h[8]")
        expectAssemblerError("dup v0.8h, v1.h[8]")
        expectAssemblerError("dup v0.2s, v1.s[4]")
        expectAssemblerError("dup v0.4s, v1.s[4]")
        expectAssemblerError("dup v0.2d, v1.d[2]")
    }

    // MARK: - Item 6: Scalar `frintp` and `frintm` (S, D, H)

    @Test("15e(6): Scalar frintp and frintm (S, D, H) round-trip corpus examples and scalar_fp_one_source.tsv while sibling/vector frint* stay unsupported")
    func scalarFrintpAndFrintmRoundTrip() throws {
        // Corpus examples (/usr/bin/vim)
        try assertExactRoundTrip(
            word: 0x1E64_C000,
            expectedText: "frintp d0, d0",
            at: VirtualAddress(0x1_000A_4DA0)
        )
        try assertExactRoundTrip(
            word: 0x1E65_4000,
            expectedText: "frintm d0, d0",
            at: VirtualAddress(0x1_000A_5070)
        )

        // Reference table Fixtures/a64/scalar_fp_one_source.tsv:
        // - 6 rows of `frintp` (S, D, H)
        // - 6 rows of `frintm` (S, D, H)
        // - sibling `frinta`, `frintx`, `frinti`, `frintn`, `frintz` remain assemblerUnsupported
        let fpRows = try Self.loadReferenceRows(tableFileName: "scalar_fp_one_source.tsv")
        let frintpRows = fpRows.filter { $0.refMnemonic == "frintp" }
        let frintmRows = fpRows.filter { $0.refMnemonic == "frintm" }
        #expect(frintpRows.count == 6)
        #expect(frintmRows.count == 6)
        for row in frintpRows + frintmRows {
            try assertExactRoundTrip(word: row.word)
        }

        let pc = VirtualAddress(0x1_0000_2000)
        let unsupportedSiblings: Set<String> = ["frinta", "frintx", "frinti", "frintn", "frintz"]
        let siblingRows = fpRows.filter { unsupportedSiblings.contains($0.refMnemonic) }
        #expect(siblingRows.count == 30)
        for row in siblingRows {
            let decoded = decoder.decode(word: row.word, at: pc)
            expectUnsupported(decoded.formattedDisassembly, mnemonic: row.refMnemonic, at: pc)
        }

        // Vector AdvSIMD frintp/frintm remain assemblerUnsupported
        expectUnsupported("frintp v0.2d, v0.2d", mnemonic: "frintp")
        expectUnsupported("frintm v1.4s, v2.4s", mnemonic: "frintm")

        // Invalid scalar width mismatch / non-FP registers throw assemblerError
        expectAssemblerError("frintp d0, s1")
        expectAssemblerError("frintm s0, h1")
        expectAssemblerError("frintp b0, b0")
        expectAssemblerError("frintm x0, x1")
    }

    // MARK: - Item 7: Pointer Authentication `pacia Xd, Xn|sp` and `pacda Xd, Xn|sp`

    @Test("15e(7): pacia and pacda (Xd|xzr, Xn|sp) round-trip corpus examples and pac_data_ptr.tsv while pacib/pacdb/aut* stay unsupported")
    func paciaAndPacdaRoundTrip() throws {
        // Corpus examples (/usr/bin/ssh)
        try assertExactRoundTrip(
            word: 0xDAC1_01B0,
            expectedText: "pacia x16, x13",
            at: VirtualAddress(0x1_0001_E404)
        )
        try assertExactRoundTrip(
            word: 0xDAC1_0A30,
            expectedText: "pacda x16, x17",
            at: VirtualAddress(0x1_0001_E3E4)
        )

        // Reference table Fixtures/a64/pac_data_ptr.tsv:
        // - 4 rows of `pacia` (including `xzr` destination and `sp` modifier)
        // - 4 rows of `pacda` (including `xzr` destination and `sp` modifier)
        // - 24 rows of `pacib`, `pacdb`, `autia`, `autib`, `autda`, `autdb` remain assemblerUnsupported
        let pacRows = try Self.loadReferenceRows(tableFileName: "pac_data_ptr.tsv")
        let paciaRows = pacRows.filter { $0.refMnemonic == "pacia" }
        let pacdaRows = pacRows.filter { $0.refMnemonic == "pacda" }
        #expect(paciaRows.count == 4)
        #expect(pacdaRows.count == 4)
        for row in paciaRows + pacdaRows {
            try assertExactRoundTrip(word: row.word)
        }

        let pc = VirtualAddress(0x1_0000_2000)
        let unsupportedPAC: Set<String> = ["pacib", "pacdb", "autia", "autib", "autda", "autdb"]
        let otherPACRows = pacRows.filter { unsupportedPAC.contains($0.refMnemonic) }
        #expect(otherPACRows.count == 24)
        for row in otherPACRows {
            let decoded = decoder.decode(word: row.word, at: pc)
            expectUnsupported(decoded.formattedDisassembly, mnemonic: row.refMnemonic, at: pc)
        }

        // Invalid register roles (SP as destination, XZR as modifier, 32-bit GP, wrong arity) throw assemblerError
        expectAssemblerError("pacia sp, x1")
        expectAssemblerError("pacia x1, xzr")
        expectAssemblerError("pacda sp, sp")
        expectAssemblerError("pacda x1, xzr")
        expectAssemblerError("pacia w1, w2")
        expectAssemblerError("pacda x1")
    }
}
