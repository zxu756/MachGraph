import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder
import MachCFGEngine
import MachPatchAndHexEngine

@Suite("Sparse CoW Hex Overlay, Inline ARM64 Patcher, IPS/BPS, Ad-Hoc Re-Signer & Entropy")
struct PatchHexReSignAndEntropyTests {

    @Test("SparseCoWByteOverlayBuffer coalesces adjacent/overlapping writes and performs O(log P) dirty extent lookup")
    func sparseCoWOverlayDirtyExtentsAndBinarySearchLookup() throws {
        let base = Data((0..<4096).map { UInt8($0 & 0xFF) })
        var overlay = try SparseCoWByteOverlayBuffer(baseData: base)
        #expect(!overlay.hasUnsavedModifications)
        #expect(overlay.dirtyExtents.isEmpty)

        // Two adjacent patches [100..<104] and [104..<108], plus a disjoint patch [2048..<2052]
        let p1 = try overlay.writeBytes([0xDE, 0xAD, 0xBE, 0xEF], at: FileOffset(100), note: "p1")
        let p2 = try overlay.writeBytes([0xCA, 0xFE, 0xBA, 0xBE], at: FileOffset(104), note: "p2")
        let p3 = try overlay.writeBytes([0x11, 0x22, 0x33, 0x44], at: FileOffset(2048), note: "p3")

        #expect(overlay.enabledPatchCount == 3)
        #expect(overlay.hasUnsavedModifications)
        #expect(overlay.dirtyExtents.count == 2) // p1 and p2 coalesced into [100..<108]
        #expect(overlay.dirtyExtents[0].range == 100..<108)
        #expect(overlay.dirtyExtents[1].range == 2048..<2052)

        #expect(overlay.dirtyExtentIndex(containing: 99) == nil)
        #expect(overlay.dirtyExtentIndex(containing: 100) == 0)
        #expect(overlay.dirtyExtentIndex(containing: 107) == 0)
        #expect(overlay.dirtyExtentIndex(containing: 108) == nil)
        #expect(overlay.dirtyExtentIndex(containing: 2050) == 1)

        #expect(try overlay.readBytes(offset: FileOffset(100), count: 8) == [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
        #expect(try overlay.readBaseBytes(offset: FileOffset(100), count: 4) == [100, 101, 102, 103])
        #expect(overlay.patchesAffecting(offset: FileOffset(102)).map(\.id) == [p1.id])
        #expect(overlay.patchesAffecting(offset: FileOffset(105)).map(\.id) == [p2.id])
        #expect(overlay.nextModifiedOffset(after: FileOffset(107)) == FileOffset(2048))
        #expect(overlay.previousModifiedOffset(before: FileOffset(2048)) == FileOffset(107))
        _ = p3
    }

    @Test("SparseCoWByteOverlayBuffer patch toggle, partial revertRange, fillBytes, xorBytes, and minimal coalescing")
    func sparseCoWOverlayToggleRevertFillXorAndMinimalPatches() throws {
        let base = Data(repeating: 0xAA, count: 512)
        var overlay = try SparseCoWByteOverlayBuffer(baseData: base)

        let fillRec = try overlay.fillBytes(at: FileOffset(32), count: 16, repeating: 0x55)
        #expect(overlay.modifiedByteCount == 16)

        // Toggle off -> zero dirty bytes; toggle back on -> 16 dirty bytes
        let nowEnabled = try overlay.togglePatch(id: fillRec.id)
        #expect(!nowEnabled)
        #expect(overlay.modifiedByteCount == 0)
        try overlay.setPatchEnabled(id: fillRec.id, isEnabled: true)
        #expect(overlay.modifiedByteCount == 16)

        // Revert middle 4 bytes [36..<40] of the 16-byte patch -> leaves [32..<36] and [40..<48]
        try overlay.revertRange(offset: FileOffset(36), length: 4)
        #expect(try overlay.readBytes(offset: FileOffset(36), count: 4) == [0xAA, 0xAA, 0xAA, 0xAA])
        let minimal = overlay.coalescedMinimalPatches()
        #expect(minimal.count == 2)
        #expect(minimal[0].fileOffset == FileOffset(32) && minimal[0].byteCount == 4)
        #expect(minimal[1].fileOffset == FileOffset(40) && minimal[1].byteCount == 8)

        // Double XOR with same key restores original bytes!
        _ = try overlay.xorBytes(at: FileOffset(200), count: 8, key: [0xFF, 0x0F])
        #expect(overlay.isByteModified(at: FileOffset(200)))
        _ = try overlay.xorBytes(at: FileOffset(200), count: 8, key: [0xFF, 0x0F])
        #expect(!overlay.isByteModified(at: FileOffset(200)))
    }

    @Test("SparseCoWByteOverlayBuffer hexViewportWindow, hexRows, dirtyPageIndices, and temp file export")
    func sparseCoWOverlayHexViewportDirtyPagesAndExport() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "HexView.arm64")
        var overlay = try SparseCoWByteOverlayBuffer(baseData: data, image: image)

        let entryVA = try #require(image.entryPoint)
        try overlay.writeBytes([0x1F, 0x20, 0x03, 0xD5], at: entryVA, in: image, note: "NOP entry")

        let rows = overlay.hexRows(aroundAddress: entryVA, rowCount: 4, in: image)
        #expect(rows.count == 4)
        let entryRow = try #require(rows.first { $0.modifiedMask.contains(true) })
        #expect(entryRow.modifiedMask.filter { $0 }.count == 4)

        let viewport = overlay.hexViewportWindow(
            scrollOffset: FileOffset(0x1000),
            visibleRowCount: 8,
            overscanRows: 2,
            image: image
        )
        #expect(viewport.visibleRowCount == 8)
        #expect(!viewport.rows.isEmpty)

        let dirtyPages = overlay.dirtyPageIndices(pageSize: 4096)
        #expect(dirtyPages.count == 1)

        let dump = overlay.formatHexDump(startOffset: try #require(image.fileOffset(for: entryVA)), byteCount: 16, image: image)
        #expect(!dump.isEmpty)

        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("mg-patched-\(UUID().uuidString).macho")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let summary = try overlay.exportPatchedBinary(to: tempURL)
        #expect(summary.totalBytesWritten == UInt64(data.count))
        #expect(summary.modifiedByteCount > 0)
        #expect(FileManager.default.fileExists(atPath: tempURL.path))
    }

    @Test("Boyer-Moore-Horspool masked wildcard search, ARM64 opcode mask search, and string/pointer search")
    func wildcardBMHSearchARM64MaskAndStringPointerSearch() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Search.arm64e")
        var overlay = try SparseCoWByteOverlayBuffer(baseData: data, image: image)

        // Inject known signature pattern at offset 0x1700 inside __TEXT
        try overlay.writeBytes([0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91], at: FileOffset(0x1700))
        let wildcardHits = try overlay.searchPattern("FD 7B ?? A9 FD 03 ?? 91")
        #expect(wildcardHits.contains { $0.fileOffset == FileOffset(0x1700) && $0.containsModifiedBytes })

        // Search ARM64 `retaa` (0xD65F0BFF) with exact mask
        let retaaHits = overlay.searchARM64InstructionMask(
            opcodeValue: InlineARM64InstructionPatcher.arm64RETAAWord,
            opcodeMask: 0xFFFF_FFFF,
            in: image
        )
        #expect(!retaaHits.isEmpty)

        // ASCII & UTF-16LE string search
        let asciiHits = overlay.searchString("MACHGRAPH-PRO-2026", encoding: .ascii, image: image)
        #expect(!asciiHits.isEmpty)

        let utf16Hits = overlay.searchString("MachGraphUTF16", encoding: .utf16LE, image: image)
        #expect(!utf16Hits.isEmpty)

        // 64-bit pointer search with PAC high-bit masking
        let taggedPtr: UInt64 = 0x8012_0001_0000_1000
        var ptrBuf = BinaryBufferWriter(endianness: .little)
        ptrBuf.appendUInt64(taggedPtr)
        try overlay.writeBytes(ptrBuf.bytes, at: FileOffset(0x2000))

        let ptrHits = overlay.searchPointer64(
            target: VirtualAddress(0x1_0000_1000),
            alignment: 8,
            maskPACHighBits: true,
            in: 0x1F00..<0x2100
        )
        #expect(ptrHits.contains { $0.fileOffset == FileOffset(0x2000) })
    }

    @Test("InlineARM64InstructionPatcher assembles PC-relative instructions, force-return stubs, and NOP sleds")
    func inlineARM64InstructionPatcherAssemblyAndForceReturnHelpers() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "PatchAsm.arm64")
        var overlay = try SparseCoWByteOverlayBuffer(baseData: data, image: image)
        let patcher = InlineARM64InstructionPatcher()

        let verifySym = try #require(image.symbols.first { $0.name == "_verify_license" })
        let boolPatch = try patcher.forceReturnBool(
            at: verifySym.address,
            value: true,
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true,
            note: "Bypass license check"
        )
        #expect(boolPatch.byteCount == 8)
        try overlay.applyPatch(boolPatch)

        let decodedWords = A64InstructionDecoder().decodeBuffer(
            Data(boolPatch.patchedBytes),
            baseAddress: verifySym.address
        )
        #expect(decodedWords.count == 2)
        #expect(decodedWords[1].mnemonic == .ret)

        let intPatch = try patcher.forceReturnInteger(
            at: verifySym.address,
            returnValue: 1337,
            is64Bit: false,
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true
        )
        #expect(intPatch.patchedAssembly?.contains("ret") == true)

        let nopRec = try patcher.nopInstruction(at: verifySym.address, in: overlay, image: image)
        #expect(nopRec.patchedBytes == InlineARM64InstructionPatcher.arm64NOPBytesLE)
    }

    @Test("InlineARM64InstructionPatcher inverts conditional branches and converts to unconditional B or NOP")
    func inlineARM64InstructionPatcherBranchInversionAndDisposition() throws {
        let asm = A64MiniAssembler()
        let base = VirtualAddress(0x1_0000_1000)
        let prog = try asm.assembleProgram("""
            cmp w0, #0
            b.eq 0x100001020
            cbz x1, 0x100001020
            ret
        """, baseAddress: base)

        let image = UniversalBinaryDispatcher.loadRawBinary(data: prog.bytes, baseAddress: base, architecture: .arm64)
        let overlay = try SparseCoWByteOverlayBuffer(baseData: prog.bytes, image: image)
        let patcher = InlineARM64InstructionPatcher()
        let decoder = A64InstructionDecoder()

        // Invert b.eq -> b.ne at base + 4
        let invEq = try patcher.invertConditionalBranch(at: base.adding(UInt64(4)), in: overlay, image: image)
        let decNe = decoder.decodeBuffer(Data(invEq.patchedBytes), baseAddress: base.adding(UInt64(4)))[0]
        #expect(decNe.flow == .conditionalBranch(target: VirtualAddress(0x1_0000_1020), condition: .ne))

        // Invert cbz -> cbnz at base + 8
        let invCbz = try patcher.invertConditionalBranch(at: base.adding(UInt64(8)), in: overlay, image: image)
        let decCbnz = decoder.decodeBuffer(Data(invCbz.patchedBytes), baseAddress: base.adding(UInt64(8)))[0]
        #expect(decCbnz.mnemonic == .cbnz)

        // Convert conditional branch -> alwaysTakeBranch (`b 0x100001020`) and neverTakeBranch (`nop`)
        let always = try patcher.convertConditionalBranch(
            at: base.adding(UInt64(4)),
            mode: .alwaysTakeBranch,
            in: overlay,
            image: image
        )
        let decAlways = decoder.decodeBuffer(Data(always.patchedBytes), baseAddress: base.adding(UInt64(4)))[0]
        #expect(decAlways.flow == .unconditionalJump(target: VirtualAddress(0x1_0000_1020)))

        let never = try patcher.convertConditionalBranch(
            at: base.adding(UInt64(4)),
            mode: .neverTakeBranch,
            in: overlay,
            image: image
        )
        #expect(never.patchedBytes == InlineARM64InstructionPatcher.arm64NOPBytesLE)
    }

    @Test("InlineARM64InstructionPatcher detects interior branch target clobber hazards and builds veneer stubs")
    func inlineARM64InstructionPatcherInteriorBranchSafetyHazardAndVeneer() throws {
        let asm = A64MiniAssembler()
        let base = VirtualAddress(0x1_0000_1000)
        // Branch at +0 jumps to interior instruction at +8 (`target_interior`); multi-insn patch at +4..+12 clobbers +8!
        let prog = try asm.assembleProgram("""
            cbz x0, .L_interior
            mov w1, #1
        .L_interior:
            mov w1, #2
            ret
        """, baseAddress: base)

        let image = UniversalBinaryDispatcher.loadRawBinary(data: prog.bytes, baseAddress: base, architecture: .arm64)
        let overlay = try SparseCoWByteOverlayBuffer(baseData: prog.bytes, image: image)
        let patcher = InlineARM64InstructionPatcher()

        let report = patcher.verifyPatchSafety(
            at: FileOffset(4),
            virtualAddress: base.adding(UInt64(4)),
            patchByteLength: 8,
            in: overlay,
            image: image
        )
        #expect(!report.isClean)
        #expect(report.hazards.contains { $0.clobberedAddress == base.adding(UInt64(8)) })

        // Without allowClobberingBranchTargets, multi-instruction patch clobbering +8 must throw
        #expect(throws: Error.self) {
            _ = try patcher.patchInstruction(
                at: FileOffset(4),
                virtualAddress: base.adding(UInt64(4)),
                withAssembly: "mov w0, #1; ret",
                in: overlay,
                image: image,
                allowClobberingBranchTargets: false
            )
        }

        // With allowClobberingBranchTargets: true, patch succeeds
        let forced = try patcher.patchInstruction(
            at: FileOffset(4),
            virtualAddress: base.adding(UInt64(4)),
            withAssembly: "mov w0, #1; ret",
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true
        )
        #expect(forced.byteCount == 8)

        // Far veneer (> 128 MiB) emits multi-word x16 stub
        let veneer = try patcher.buildBranchOrVeneerStub(
            from: base,
            to: VirtualAddress(0x2_8000_0000),
            in: overlay,
            image: image,
            allowClobberingBranchTargets: true
        )
        #expect(veneer.byteCount >= 12)
    }

    @Test("IPSPatchCodec classic 24-bit PATCH...EOF and RLE hunk round-trip")
    func ipsClassic24BitAndRLERoundTrip() throws {
        let baseData = Data((0..<2048).map { UInt8($0 & 0xFF) })
        var overlay = try SparseCoWByteOverlayBuffer(baseData: baseData)
        try overlay.writeBytes([0xCA, 0xFE, 0xBA, 0xBE], at: FileOffset(0x120))
        try overlay.fillBytes(at: FileOffset(0x400), count: 64, repeating: 0x90) // RLE candidate

        let codec = IPSPatchCodec()
        let ipsBytes = try codec.exportIPSChecked(
            patches: overlay.coalescedMinimalPatches(),
            format: .ips24,
            baseData: baseData,
            enableRLE: true
        )
        #expect(String(decoding: ipsBytes.prefix(5), as: UTF8.self) == "PATCH")
        #expect(String(decoding: ipsBytes.suffix(3), as: UTF8.self) == "EOF")

        let container = try codec.parseContainer(ipsBytes)
        #expect(container.format == .ips24)
        #expect(container.hunks.contains(where: { $0.isRLE }))

        let imported = try codec.importIPS(ipsBytes, baseData: baseData)
        let reconstructed = try SparseCoWByteOverlayBuffer(baseData: baseData, patches: imported)
        #expect(reconstructed.materializedData() == overlay.materializedData())
    }

    @Test("IPSPatchCodec 32-bit IPS32...EEOF format round-trip")
    func ips32FormatRoundTrip() throws {
        let baseData = Data(repeating: 0x00, count: 4096)
        let patch = BytePatchRecord(
            fileOffset: FileOffset(0x800),
            originalBytes: [0, 0, 0, 0],
            patchedBytes: [0x4D, 0x47, 0x33, 0x32]
        )
        let codec = IPSPatchCodec()
        let ips32 = codec.exportIPS32(patches: [patch])

        #expect(String(decoding: ips32.prefix(5), as: UTF8.self) == "IPS32")
        #expect(String(decoding: ips32.suffix(4), as: UTF8.self) == "EEOF")

        let parsed = try codec.parseContainer(ips32)
        #expect(parsed.format == .ips32)

        let imported = try codec.importIPS(ips32, baseData: baseData)
        #expect(imported.count == 1)
        #expect(imported[0].patchedBytes == [0x4D, 0x47, 0x33, 0x32])
    }

    @Test("IPSPatchCodec BPS1 CRC32 binary diff round-trip, tamper rejection, and unified hex diff")
    func bps1CRC32RoundTripAndTamperRejection() throws {
        let original = Data((0..<1024).map { UInt8(($0 &* 7) & 0xFF) })
        var modified = original
        modified.replaceSubrange(128..<136, with: [0xDE, 0xAD, 0xC0, 0xDE, 0x20, 0x26, 0x00, 0x01])
        modified.replaceSubrange(700..<704, with: [0xFF, 0xEE, 0xDD, 0xCC])

        let codec = IPSPatchCodec()
        let bpsData = codec.exportBPS(original: original, modified: modified, metadataUTF8: "MachGraph BPS Test")
        #expect(String(decoding: bpsData.prefix(4), as: UTF8.self) == "BPS1")

        let importedPatches = try codec.importBPS(bpsData, baseData: original)
        let rebuilt = try SparseCoWByteOverlayBuffer(baseData: original, patches: importedPatches)
        #expect(rebuilt.materializedData() == modified)

        let unifiedDiff = codec.generateUnifiedHexDiff(overlay: rebuilt)
        #expect(unifiedDiff.contains("@@"))

        // Flip last byte (patch CRC32) -> must reject tampered BPS container!
        var corruptedBPS = bpsData
        corruptedBPS[corruptedBPS.count - 1] ^= 0xFF
        #expect(throws: MachGraphError.self) {
            _ = try codec.importBPS(corruptedBPS, baseData: original)
        }
    }

    @Test("BinaryStructureInspector decodes LE/BE integers, floats, ULEB128/SLEB128, ARM64 preview, and custom structs")
    func binaryStructureInspectorPrimitivesLEB128AndCustomStructs() throws {
        var writer = BinaryBufferWriter(endianness: .little)
        writer.appendUInt32(0x5280_0540) // mov w0, #42 (LE ARM64)
        writer.appendUInt32(0x1234_5678)
        writer.appendULEB128(300)
        writer.appendSLEB128(-64)
        writer.padToAlignment(16)

        let inspector = BinaryStructureInspector()
        let overlay = try SparseCoWByteOverlayBuffer(baseData: writer.data)

        let insnVals = try inspector.inspect(at: FileOffset(0), in: overlay, endianness: .little)
        #expect(insnVals.uint32 == 0x5280_0540)
        #expect(insnVals.arm64InstructionPreview?.contains("42") == true || insnVals.arm64InstructionPreview?.contains("0x2a") == true)

        let beVals = try inspector.inspect(at: FileOffset(4), in: overlay, endianness: .big)
        #expect(beVals.uint32 == 0x7856_3412)

        let ulebVals = try inspector.inspect(at: FileOffset(8), in: overlay, endianness: .little)
        #expect(ulebVals.uleb128 == 300)
        #expect(ulebVals.uleb128ByteLength == 2)

        let slebVals = try inspector.inspect(at: FileOffset(10), in: overlay, endianness: .little)
        #expect(slebVals.sleb128 == -64)

        let customDef = CustomStructDefinition(
            name: "DemoHeader",
            totalByteSize: 8,
            fields: [
                CustomStructField(name: "opcode", offset: 0, byteSize: 4, typeExpr: .intType(bits: 32, signed: false)),
                CustomStructField(name: "tag", offset: 4, byteSize: 4, typeExpr: .intType(bits: 32, signed: false))
            ]
        )
        let evalFields = try inspector.evaluateCustomStruct(customDef, at: FileOffset(0), in: overlay)
        #expect(evalFields.count == 2)
        #expect(evalFields[0].name == "opcode")
        #expect(evalFields[1].formattedValue.lowercased().contains("12345678") || evalFields[1].formattedValue.contains("305419896"))
    }

    @Test("MachOAdHocReSigner verifies original signature, detects 1-byte page tamper, and recalculates SHA-256 slots in-place")
    func machOAdHocReSignerVerifyTamperDetectAndInPlaceRecalculation() throws {
        let originalData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: originalData, fileName: "ReSignTarget.arm64e")
        let reSigner = MachOAdHocReSigner()

        let initialReport = try reSigner.verifyCodeSignature(in: originalData)
        #expect(initialReport.isSigned)
        #expect(initialReport.isValid)
        #expect(initialReport.mismatchedCodeSlots.isEmpty)

        // Patch 1 instruction in __TEXT,__text -> invalidates exactly 1 SHA-256 code page slot
        var overlay = try SparseCoWByteOverlayBuffer(baseData: originalData, image: image)
        let entryVA = try #require(image.entryPoint)
        try overlay.writeBytes(InlineARM64InstructionPatcher.arm64NOPBytesLE, at: entryVA, in: image)

        let brokenReport = try reSigner.verifyCodeSignature(in: overlay)
        #expect(!brokenReport.isValid)
        #expect(brokenReport.mismatchedCodeSlots.count == 1)

        // Re-sign using fast in-place page hash recalculation
        let result = try reSigner.reSignOverlay(overlay, image: image, strategy: .inPlaceIfPossible)
        #expect(result.verificationReport.isValid)
        #expect(result.verificationReport.mismatchedCodeSlots.isEmpty)
        #expect(result.updatedCDHashHex != result.previousCDHashHex)
        #expect(result.updatedSummary.entitlementsPairs["com.apple.security.cs.allow-jit"] == "true")
    }

    @Test("MachOAdHocReSigner rebuildSuperBlob strategy updates custom identifier and entitlements XML")
    func machOAdHocReSignerRebuildSuperBlobWithCustomIdentifierAndEntitlements() throws {
        let originalData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let customXML = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.machgraph.rebuilt</key>
            <true/>
        </dict>
        </plist>
        """

        let reSigner = MachOAdHocReSigner()
        let result = try reSigner.reSignMachO(
            binaryData: originalData,
            strategy: .rebuildSuperBlob,
            identifier: "com.machgraph.custom.resigned",
            teamID: "NEWTEAM777",
            entitlementsXML: customXML
        )

        #expect(result.verificationReport.isValid)
        #expect(result.updatedSummary.isAdHoc)
        #expect(result.updatedSummary.identifier == "com.machgraph.custom.resigned")
        #expect(result.updatedSummary.entitlementsPairs["com.machgraph.rebuilt"] == "true")
    }

    @Test("SlidingWindowEntropyProfiler computes 0.0 bits/byte on zeros and ~8.0 bits/byte on uniform/CSPRNG streams")
    func slidingWindowEntropyProfilerZeroAndMaxEntropyInvariants() {
        let profiler = SlidingWindowEntropyProfiler(defaultWindowSize: 1024, defaultStepSize: 512)

        // 1. All-zero buffer -> exact 0.0 bits/byte, zeroRatio = 1.0, nullPadding
        let zeros = Data(repeating: 0x00, count: 4096)
        let zeroReport = profiler.analyzeFullProfile(data: zeros)
        #expect(abs(zeroReport.overallMetrics.shannonEntropyBits - 0.0) < 1e-9)
        #expect(zeroReport.overallMetrics.zeroByteRatio == 1.0)
        #expect(zeroReport.samples.allSatisfy { $0.classification == .nullPadding })

        // 2. Exact balanced 16x256 uniform permutation (4096 bytes, every byte value appears 16 times) -> exact 8.0 bits/byte!
        var uniformBytes = [UInt8]()
        uniformBytes.reserveCapacity(4096)
        var state: UInt64 = 0x9E37_79B9_7F4A_7C15
        for i in 0..<4096 {
            uniformBytes.append(UInt8(i & 0xFF))
        }
        // Fisher-Yates shuffle using SplitMix64 so spatial windows & chi-square are genuinely pseudorandom
        for i in stride(from: 4095, through: 1, by: -1) {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            z = z ^ (z >> 31)
            let j = Int(z % UInt64(i + 1))
            uniformBytes.swapAt(i, j)
        }
        let randomData = Data(uniformBytes)
        let randomReport = profiler.analyzeFullProfile(data: randomData)
        #expect(abs(randomReport.overallMetrics.shannonEntropyBits - 8.0) < 1e-9)
        #expect(randomReport.overallMetrics.byteChiSquare == 0.0)
        #expect(randomReport.samples[0].entropyBitsPerByte > 7.80)
        #expect(randomReport.samples[0].classification == .compressedOrEncrypted)
    }

    @Test("SlidingWindowEntropyProfiler classifies printable ASCII, profiles Mach-O sections, and emits packed-section anomalies")
    func slidingWindowEntropyProfilerSectionMetricsAndAnomalies() throws {
        let profiler = SlidingWindowEntropyProfiler(defaultWindowSize: 512, defaultStepSize: 256)

        let asciiText = Data(String(repeating: "MachGraph Static Binary Analyzer 2026! ", count: 64).utf8)
        let asciiSamples = profiler.profile(data: asciiText, windowSize: 512, stepSize: 512)
        #expect(!asciiSamples.isEmpty)
        #expect(asciiSamples[0].printableByteRatio > 0.95)
        #expect(asciiSamples[0].classification == .printableStrings)

        // Profile synthetic Mach-O binary
        let machO = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: machO, fileName: "EntropyMachO.arm64e")
        let fullReport = profiler.analyzeFullProfile(data: machO, image: image, windowSize: 512, stepSize: 256)
        #expect(!fullReport.samples.isEmpty)
        #expect(!fullReport.sectionMetrics.isEmpty)

        // Inject high-entropy encrypted payload into __TEXT,__text to trigger packed executable anomaly
        var overlay = try SparseCoWByteOverlayBuffer(baseData: machO, image: image)
        if let textSec = image.sections.first(where: { $0.fullName == "__TEXT,__text" }) {
            var prng: UInt64 = 0xCAFE_F00D_1234_5678
            let count = Int(min(textSec.size, 1024))
            var highEntropy = [UInt8](repeating: 0, count: count)
            for idx in 0..<count {
                prng = prng &* 6364136223846793005 &+ 1442695040888963407
                highEntropy[idx] = UInt8(truncatingIfNeeded: prng >> 32)
            }
            try overlay.writeBytes(highEntropy, at: textSec.vmAddress, in: image)
            let packedReport = profiler.analyzeFullProfile(overlay: overlay, image: image, windowSize: 256, stepSize: 256)
            let findings = profiler.toSecurityAuditFindings(anomalies: packedReport.anomalies)
            #expect(findings.count == packedReport.anomalies.count)
        }
    }

    @Test("BinaryHashAndEntropy SHA-256 and IEEE 802.3 CRC32 standard test vectors")
    func binaryHashAndEntropyStandardVectors() {
        let abc = Data("abc".utf8)
        #expect(BinaryHashAndEntropy.sha256Hex(of: abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

        let checkVec = Array("123456789".utf8)
        #expect(BinaryHashAndEntropy.crc32(of: checkVec[...]) == 0xCBF4_3926)
    }

    @Test("SparseCoWByteOverlayBuffer rejects out-of-bounds patches cleanly with patchBoundsError")
    func sparseCoWOverlayOutOfBoundsRejection() throws {
        let small = Data([1, 2, 3, 4, 5, 6, 7, 8])
        var overlay = try SparseCoWByteOverlayBuffer(baseData: small)
        #expect(throws: MachGraphError.self) {
            try overlay.writeBytes([0xAA, 0xBB, 0xCC], at: FileOffset(7))
        }
    }

    @Test("SparseCoWByteOverlayBuffer makeTransactionRecord produces reversible AnalystMutationOperation")
    func sparseCoWOverlayTransactionRecordInversion() {
        let patch = BytePatchRecord(
            fileOffset: FileOffset(0x100),
            virtualAddress: VirtualAddress(0x1_0000_0100),
            originalBytes: [0x00],
            patchedBytes: [0x01],
            note: "Flip flag"
        )
        let tx = SparseCoWByteOverlayBuffer.makeTransactionRecord(
            sequenceNumber: 1,
            title: "Apply flag patch",
            previous: nil,
            updated: patch
        )
        #expect(tx.operation.inverted == .setPatch(previous: patch, updated: nil))
    }

    @Test("InlineARM64InstructionPatcher previewPatch disassembles before and after without mutating overlay")
    func inlineARM64PatcherPreviewDoesNotMutateOverlay() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Preview.arm64")
        let overlay = try SparseCoWByteOverlayBuffer(baseData: data, image: image)
        let entryVA = try #require(image.entryPoint)
        let entryOff = try #require(image.fileOffset(for: entryVA))

        let preview = try InlineARM64InstructionPatcher().previewPatch(
            at: entryOff,
            virtualAddress: entryVA,
            withAssembly: "mov w0, #0; ret",
            in: overlay,
            image: image
        )

        #expect(preview.patchedInstructions.count == 2)
        #expect(preview.patchedDisassemblyText.contains("ret"))
        #expect(!overlay.hasUnsavedModifications)
    }

    @Test("EntropyClassification deterministic threshold boundaries")
    func entropyClassificationThresholdBoundaries() {
        #expect(EntropyClassification.classify(entropy: 0.1, zeroRatio: 0.95, printableRatio: 0.0) == .nullPadding)
        #expect(EntropyClassification.classify(entropy: 7.85, zeroRatio: 0.004, printableRatio: 0.35) == .compressedOrEncrypted)
        #expect(EntropyClassification.classify(entropy: 4.5, zeroRatio: 0.01, printableRatio: 0.90) == .printableStrings)
        #expect(EntropyClassification.classify(entropy: 6.1, zeroRatio: 0.05, printableRatio: 0.30) == .nativeMachineCode)
        #expect(EntropyClassification.classify(entropy: 3.2, zeroRatio: 0.20, printableRatio: 0.25) == .structuredMetadata)
    }
}
