import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats

@Suite("Binary Format Loaders & Metadata Parsers")
struct BinaryFormatLoadersTests {

    @Test("Container magic format detection across Mach-O 64, Fat, Fat64, ELF64, PE32+, WASM, and raw blobs")
    func magicFormatDetectionAcrossAllSupportedContainers() {
        let machO = SyntheticBinaryFixtureBuilder.buildMachO64Executable()
        let fat = SyntheticBinaryFixtureBuilder.buildUniversalFatBinary()
        let fat64 = SyntheticBinaryFixtureBuilder.buildUniversalFat64Binary()
        let elf = SyntheticBinaryFixtureBuilder.buildELF64Binary()
        let pe = SyntheticBinaryFixtureBuilder.buildPE32PlusARM64Binary()
        let wasm = SyntheticBinaryFixtureBuilder.buildWasmModule()
        let raw = Data([0x13, 0x37, 0xC0, 0xDE, 0x00, 0x01, 0x02, 0x03])

        #expect(UniversalBinaryDispatcher.detectFormat(data: machO) == .machO64)
        #expect(UniversalBinaryDispatcher.detectFormat(data: fat) == .universalFat)
        #expect(UniversalBinaryDispatcher.detectFormat(data: fat64) == .universalFat)
        #expect(UniversalBinaryDispatcher.detectFormat(data: elf) == .elf64)
        #expect(UniversalBinaryDispatcher.detectFormat(data: pe) == .pe32Plus)
        #expect(UniversalBinaryDispatcher.detectFormat(data: wasm) == .wasm)
        #expect(UniversalBinaryDispatcher.detectFormat(data: raw) == .rawBinary)
    }

    @Test("Universal Fat (0xCAFEBABE) slice enumeration and automatic arm64e slice selection")
    func universalFatBinarySliceEnumerationAndPreferredARM64ESelection() throws {
        let fatData = SyntheticBinaryFixtureBuilder.buildUniversalFatBinary()
        let slices = try UniversalBinaryDispatcher.parseUniversalSlices(data: fatData)

        #expect(slices.count == 2)
        #expect(slices[0].architecture == .x86_64)
        #expect(slices[1].architecture == .arm64e)
        #expect(slices[0].size > 0)
        #expect(slices[1].size > 0)
        #expect(slices[1].fileOffset > slices[0].fileOffset)

        let preferredIndex = try UniversalBinaryDispatcher.selectPreferredSliceIndex(
            in: slices,
            preferredSliceIndex: nil
        )
        #expect(preferredIndex == 1)

        let image = try UniversalBinaryDispatcher.load(
            data: fatData,
            filePath: "/virtual/FatDemo",
            fileName: "FatDemo"
        )
        #expect(image.containerFormat == .universalFat)
        #expect(image.selectedSliceIndex == 1)
        #expect(image.architecture == .arm64e)
        #expect(image.sliceFileOffset == slices[1].fileOffset)
        #expect(image.slices.count == 2)
    }

    @Test("Universal Fat explicit slice selection loads x86_64 slice on demand and rejects out-of-range index")
    func universalFatExplicitX8664SliceSelection() throws {
        let fatData = SyntheticBinaryFixtureBuilder.buildUniversalFatBinary()
        let x86Image = try UniversalBinaryDispatcher.load(
            data: fatData,
            filePath: "/virtual/FatDemo",
            fileName: "FatDemo",
            preferredSliceIndex: 0
        )
        #expect(x86Image.selectedSliceIndex == 0)
        #expect(x86Image.architecture == .x86_64)
        #expect(x86Image.segments.contains { $0.name == "__TEXT" })

        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(
                data: fatData,
                filePath: "/virtual/FatDemo",
                fileName: "FatDemo",
                preferredSliceIndex: 99
            )
        }
    }

    @Test("Universal Fat64 (0xCAFEBABF) 64-bit slice descriptor parsing and arm64e dispatch")
    func universalFat64HeaderParsingAndDispatch() throws {
        let fat64Data = SyntheticBinaryFixtureBuilder.buildUniversalFat64Binary()
        var reader = BinarySliceReader(data: fat64Data, endianness: .big)
        let magic = try reader.readUInt32()
        #expect(magic == MachOConstants.fatMagic64)

        let slices = try UniversalBinaryDispatcher.parseUniversalSlices(data: fat64Data)
        #expect(slices.count == 2)
        #expect(slices[1].architecture == .arm64e)

        let loaded = try UniversalBinaryDispatcher.load(
            data: fat64Data,
            filePath: "/virtual/Fat64Demo",
            fileName: "Fat64Demo"
        )
        #expect(loaded.containerFormat == .universalFat)
        #expect(loaded.architecture == .arm64e)
        #expect(loaded.entryPoint != nil)
    }

    @Test("Mach-O 64 segments, RWX protections, 17 sections, and bidirectional VA <-> FileOffset translation")
    func machO64SegmentsProtectionsSectionsAndAddressTranslation() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Demo.arm64")

        #expect(image.containerFormat == .machO64)
        #expect(image.architecture == .arm64)
        #expect(image.imageBase == VirtualAddress(0x1_0000_0000))
        #expect(image.isPositionIndependent)

        let segNames = image.segments.map(\.name)
        #expect(segNames == ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"])
        #expect(image.sections.count == 17)

        let textSeg = try #require(image.segments.first { $0.name == "__TEXT" })
        #expect(textSeg.initialProtection == [.read, .execute])
        #expect(textSeg.initialProtection.rwxString == "r-x")

        let dataSeg = try #require(image.segments.first { $0.name == "__DATA" })
        #expect(dataSeg.initialProtection == [.read, .write])
        #expect(dataSeg.initialProtection.rwxString == "rw-")

        let textSec = try #require(image.sections.first { $0.fullName == "__TEXT,__text" })
        #expect(textSec.kind == .code)
        #expect(image.executableSections().contains { $0.fullName == "__TEXT,__text" })

        let probeVA = textSec.vmAddress.adding(UInt64(16))
        let mappedOffset = try #require(image.fileOffset(for: probeVA))
        let roundTripVA = try #require(image.virtualAddress(for: mappedOffset))
        #expect(roundTripVA == probeVA)
        #expect(image.section(containing: probeVA)?.fullName == "__TEXT,__text")
        #expect(image.fileOffset(for: VirtualAddress(0x0000_0100)) == nil) // inside __PAGEZERO
    }

    @Test("Mach-O 64 UUID, LC_BUILD_VERSION platform/SDK, LC_MAIN entry point, and imported dylibs")
    func machO64UUIDBuildVersionEntryPointAndImportedLibraries() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Demo.arm64e")

        #expect(image.architecture == .arm64e)
        #expect(image.uuidString == "4D414348-4752-4150-482D-3230323600E1")
        #expect(image.platformName == "macOS")
        #expect(image.minOSVersion == "14.0")
        #expect(image.sdkVersion == "15.0")

        let entryVA = try #require(image.entryPoint)
        let mainSym = try #require(image.exactSymbol(at: entryVA))
        #expect(mainSym.name == "_main")
        #expect(!image.functionStarts.isEmpty)
        #expect(image.functionStarts.contains(entryVA))

        let libNames = image.importedLibraries.map(\.shortName)
        #expect(libNames.contains("libSystem.B.dylib"))
        #expect(libNames.contains("libobjc.A.dylib"))

        let near = try #require(image.nearestSymbol(atOrBefore: entryVA.adding(UInt64(8))))
        #expect(near.symbol.address == entryVA)
        #expect(near.delta == 8)
    }

    @Test("LC_DYLD_CHAINED_FIXUPS standard DYLD_CHAINED_PTR_64 rebase and bind fixup resolution")
    func dyldChainedFixupsStandard64BitRebaseAndBind() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "StdFixups.arm64")

        #expect(!image.chainedFixups.isEmpty)
        let rebases = image.chainedFixups.filter { $0.kind == .rebase }
        let binds = image.chainedFixups.filter { $0.kind == .bind }

        #expect(!rebases.isEmpty)
        #expect(!binds.isEmpty)
        #expect(binds.contains { $0.symbolName == "_strcmp" })
        #expect(binds.contains { $0.symbolName == "_puts" })
        #expect(rebases.allSatisfy { ($0.targetAddress?.rawValue ?? 0) >= image.imageBase.rawValue })
    }

    @Test("LC_DYLD_CHAINED_FIXUPS ARM64E PAC authRebase and authBind diversity & key metadata")
    func dyldChainedFixupsARM64EPointerAuthDiversityAndKeys() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "PACFixups.arm64e")

        let authRebases = image.chainedFixups.filter { $0.kind == .authRebase }
        let authBinds = image.chainedFixups.filter { $0.kind == .authBind }

        #expect(!authRebases.isEmpty)
        #expect(!authBinds.isEmpty)

        let keys = Set(image.chainedFixups.compactMap(\.pacKey))
        #expect(keys.contains("IA") || keys.contains("DA"))

        let diversities = image.chainedFixups.compactMap(\.pacDiversity)
        #expect(!diversities.isEmpty)
        #expect(authBinds.contains { $0.symbolName == "_strcmp" && $0.pacKey != nil })
    }

    @Test("Legacy LC_DYLD_INFO_ONLY rebase and bind opcode stream parser")
    func legacyDyldInfoOpcodeStreamRebaseAndBind() throws {
        let legacyData = SyntheticBinaryFixtureBuilder.buildLegacyDyldInfoMachOBinary()
        let image = try UniversalBinaryDispatcher.load(data: legacyData, fileName: "LegacyDyld.macho")

        #expect(image.containerFormat == .machO64)
        #expect(!image.chainedFixups.isEmpty)
        #expect(image.chainedFixups.contains { $0.kind == .rebase })
        #expect(image.chainedFixups.contains { $0.kind == .bind && $0.symbolName == "_getenv" })
    }

    @Test("Mach-O Export Trie ULEB128 DAG builder and prefix-compressed parser round-trip")
    func exportTrieDAGRoundTripAndPrefixCompression() throws {
        let entries: [ExportTrieBuilder.ExportEntry] = [
            .init(name: "__mh_execute_header", offsetFromImageBase: 0x0),
            .init(name: "_compute_checksum", offsetFromImageBase: 0x1000),
            .init(name: "_compute_crc64", offsetFromImageBase: 0x1080),
            .init(name: "_verify_license", offsetFromImageBase: 0x1100, flags: ExportTrieParser.exportWeakDefinition),
            .init(name: "_main", offsetFromImageBase: 0x1200)
        ]
        let trieBytes = ExportTrieBuilder.buildTrie(entries: entries)
        #expect(!trieBytes.isEmpty)

        let base = VirtualAddress(0x1_0000_0000)
        let textSection = BinarySection(
            index: 1,
            segmentName: "__TEXT",
            sectionName: "__text",
            vmAddress: VirtualAddress(0x1_0000_1000),
            size: 0x1000,
            fileOffset: FileOffset(0x1000),
            kind: .code,
            permissions: [.read, .execute]
        )
        let parsed = try ExportTrieParser.parse(
            trieData: trieBytes,
            imageBase: base,
            sections: [textSection]
        )

        #expect(parsed.count == 5)
        let byName = Dictionary(uniqueKeysWithValues: parsed.map { ($0.name, $0) })
        #expect(byName["_compute_checksum"]?.address == VirtualAddress(0x1_0000_1000))
        #expect(byName["_compute_crc64"]?.address == VirtualAddress(0x1_0000_1080))
        #expect(byName["_verify_license"]?.binding == .weak)
        #expect(byName["_main"]?.address == VirtualAddress(0x1_0000_1200))
    }

    @Test("ExportTrieParser detects cyclic child offset and throws malformedHeader")
    func exportTrieCycleDetectionRejectsMalformedDAG() {
        // Root node at offset 0: terminalSize=0, childCount=1, edge label "a\0", child node ULEB128 offset = 0 (self-cycle!)
        let cyclicTrie = Data([0x00, 0x01, 0x61, 0x00, 0x00])
        #expect(throws: MachGraphError.self) {
            _ = try ExportTrieParser.parse(
                trieData: cyclicTrie,
                imageBase: VirtualAddress(0x1_0000_0000),
                sections: []
            )
        }
    }

    @Test("LC_CODE_SIGNATURE SuperBlob, CodeDirectory SHA-256 slots, CDHash, TeamID, and Entitlements")
    func codeSignatureSuperBlobCodeDirectoryAndEntitlements() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(
            useARM64E: true,
            identifier: "com.machgraph.security.target",
            includeCMSCertificates: false
        )
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Signed.arm64e")
        let cs = image.codeSignature

        #expect(cs.isSigned)
        #expect(cs.identifier == "com.machgraph.security.target")
        #expect(cs.teamIdentifier == "TEAM99XMGH")
        #expect(cs.hashAlgorithm == "SHA-256")
        #expect(cs.pageSize == 16384)
        #expect(cs.cdHashHex.count >= 40)
        #expect(cs.entitlementsPairs["com.apple.security.cs.allow-jit"] == "true")
        #expect(cs.entitlementsPairs["com.apple.security.get-task-allow"] == "true")
        #expect(cs.entitlementsPairs["com.machgraph.analysis-tier"] == "enterprise")
    }

    @Test("CMS PKCS#7 X.509 signer CommonName extraction and detailed CodeDirectory inspection")
    func cmsX509CertificateChainAndDEREntitlementsParsing() throws {
        let payload = Data(repeating: 0xA5, count: 20_480) // > 16 KiB -> 2 Apple Silicon 16 KiB code slots
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.app-sandbox</key>
            <true/>
            <key>com.apple.developer.team-identifier</key>
            <string>TEAM99XMGH</string>
        </dict>
        </plist>
        """
        let expectedSigners = [
            "Apple Development: MachGraph Labs (TEAM99X)",
            "Apple Worldwide Developer Relations Certification Authority"
        ]
        let superBlob = SyntheticBinaryFixtureBuilder.buildCMSSignedSuperBlob(
            binarySliceWithoutSignature: payload,
            identifier: "com.machgraph.cms.test",
            entitlementsXML: xml,
            signerCommonNames: expectedSigners
        )

        let detailed = try CodeSignatureAndCMSParser.parseDetailed(signatureData: superBlob)
        #expect(detailed.summary.isSigned)
        #expect(!detailed.summary.isAdHoc)
        #expect(detailed.summary.identifier == "com.machgraph.cms.test")
        #expect(detailed.summary.cmsSignerCommonNames == expectedSigners)
        #expect(detailed.summary.entitlementsPairs["com.apple.security.app-sandbox"] == "true")
        #expect(detailed.summary.entitlementsPairs["com.apple.developer.team-identifier"] == "TEAM99XMGH")

        let primaryDir = try #require(detailed.directories.first)
        #expect(primaryDir.nCodeSlots == 2)
        #expect(primaryDir.codeSlotHashesHex.count == 2)
        #expect(primaryDir.hashByteSize == 32)
    }

    @Test("Objective-C 2.0 class, superclass, adopted protocols, instance/class methods, and ivar layout")
    func objectiveC2RuntimeClassesMethodsProtocolsAndIvars() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjC.arm64e")

        let authCls = try #require(image.objcClasses.first { $0.name == "MGAuthController" })
        #expect(authCls.superclassName == "NSObject")
        #expect(authCls.adoptedProtocols.contains("NSSecureCoding"))

        let instMethod = try #require(authCls.methods.first { !$0.isClassMethod && $0.selector == "validateToken:" })
        #expect(instMethod.implementationAddress.rawValue >= image.imageBase.rawValue)

        let clsMethod = try #require(authCls.methods.first { $0.isClassMethod && $0.selector == "sharedController" })
        #expect(clsMethod.implementationAddress.rawValue >= image.imageBase.rawValue)

        let sessionKeyIvar = try #require(authCls.ivars.first { $0.name == "_sessionKey" })
        let retryCountIvar = try #require(authCls.ivars.first { $0.name == "_retryCount" })
        #expect(sessionKeyIvar.offset == 8)
        #expect(retryCountIvar.offset == 16)
    }

    @Test("Swift 5 __swift5_types relative-pointer nominal type descriptor and field recovery")
    func swift5NominalTypeDescriptorRelativePointerParsing() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "SwiftMeta.arm64e")

        let licenseType = try #require(image.swiftTypes.first { $0.demangledName.contains("LicensePacket") })
        #expect(licenseType.kind == .structType)
        #expect(licenseType.fieldNames == ["token", "flags", "isValid"])
        #expect(licenseType.address.rawValue >= image.imageBase.rawValue)
    }

    @Test("String literal extraction recovers both ASCII/UTF-8 __cstring and UTF-16LE __data strings")
    func extractedASCIIAndUTF16LEStringLiterals() throws {
        let data = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "Strings.arm64")

        let licenseLit = try #require(image.strings.first { $0.value == "MACHGRAPH-PRO-2026" })
        #expect(licenseLit.sectionName.contains("__cstring"))

        let utf16Lit = try #require(image.strings.first { $0.value == "MachGraphUTF16" })
        #expect(utf16Lit.encoding == .utf16LE)
    }

    @Test("ELF64 AArch64 shared object loader parses segments, dynamic libraries, symbols, and relocations")
    func elf64AArch64SharedObjectLoader() throws {
        let elfData = SyntheticBinaryFixtureBuilder.buildELF64Binary()
        let image = try UniversalBinaryDispatcher.load(data: elfData, fileName: "libframe.so")

        #expect(image.containerFormat == .elf64)
        #expect(image.architecture == .arm64)
        #expect(!image.segments.isEmpty)
        #expect(!image.executableSections().isEmpty)

        let libs = image.importedLibraries.map(\.installName)
        #expect(libs.contains("libc.so.6"))
        #expect(libs.contains("libm.so.6"))

        let symNames = image.symbols.map(\.name)
        #expect(symNames.contains("elf_check_frame"))
        #expect(symNames.contains("_start"))
        #expect(image.strings.contains { $0.value.contains("ELF64-MACHGRAPH-FIXTURE") })
    }

    @Test("PE32+ ARM64 executable loader parses COFF sections, Import Directory, and Export Directory")
    func pe32PlusARM64ExecutableImportsExportsAndSections() throws {
        let peData = SyntheticBinaryFixtureBuilder.buildPE32PlusARM64Binary()
        let image = try UniversalBinaryDispatcher.load(data: peData, fileName: "VerifyTool.exe")

        #expect(image.containerFormat == .pe32Plus)
        #expect(image.architecture == .arm64)
        #expect(image.entryPoint != nil)

        let secNames = image.sections.map(\.sectionName)
        #expect(secNames.contains(".text"))
        #expect(secNames.contains(".rdata"))
        #expect(secNames.contains(".pdata"))

        let dlls = image.importedLibraries.map { $0.installName.uppercased() }
        #expect(dlls.contains("KERNEL32.DLL"))

        let symNames = image.symbols.map(\.name)
        #expect(symNames.contains { $0.contains("GetCurrentProcessId") })
        #expect(symNames.contains { $0.contains("ExitProcess") })
        #expect(symNames.contains("MainEntry"))
        #expect(symNames.contains("VerifyToken"))
    }

    @Test("WebAssembly 1.0 module loader parses imports, exports, code bodies, data segments, and name section")
    func webAssemblyModuleSectionsImportsExportsAndCustomNames() throws {
        let wasmData = SyntheticBinaryFixtureBuilder.buildWasmModule()
        let image = try UniversalBinaryDispatcher.load(data: wasmData, fileName: "validator.wasm")

        #expect(image.containerFormat == .wasm)
        #expect(image.architecture == .wasm32)
        #expect(image.imageBase == WasmModuleLoader.wasmSyntheticBaseAddress)

        let symNames = image.symbols.map(\.name)
        #expect(symNames.contains { $0.contains("host_trace") })
        #expect(symNames.contains("validate_frame"))
        #expect(symNames.contains("_start"))
        #expect(image.strings.contains { $0.value.contains("WASM-MACHGRAPH-MODULE-1.0") })
    }

    @Test("Raw firmware binary fallback loader maps custom base address and architecture")
    func rawBinaryFallbackLoaderAndCustomBaseAddress() {
        let blob = Data([0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]) // mov w0, #1; ret
        let customBase = VirtualAddress(0x8000_0000)
        let image = UniversalBinaryDispatcher.loadRawBinary(
            data: blob,
            filePath: "/tmp/rom.bin",
            fileName: "rom.bin",
            baseAddress: customBase,
            architecture: .arm64
        )

        #expect(image.containerFormat == .rawBinary)
        #expect(image.architecture == .arm64)
        #expect(image.imageBase == customBase)
        #expect(image.fileOffset(for: customBase.adding(UInt64(4))) == FileOffset(4))
        #expect(image.virtualAddress(for: FileOffset(4)) == customBase.adding(UInt64(4)))
    }

    @Test("BinarySliceReader and BinaryBufferWriter round-trip LE/BE integers, ULEB128/SLEB128, and EOF bounds")
    func binarySliceReaderAndBufferWriterLEB128AndBoundsChecks() throws {
        var writer = BinaryBufferWriter(endianness: .little)
        writer.appendUInt16(0xCAFE)
        writer.appendUInt32(0xDEAD_BEEF)
        writer.appendUInt64(0x0123_4567_89AB_CDEF)
        writer.appendULEB128(0)
        writer.appendULEB128(624_485)
        writer.appendULEB128(0xFFFF_FFFF_FFFF)
        writer.appendSLEB128(-123_456)
        writer.appendSLEB128(987_654)
        writer.appendCString("MachGraph")
        writer.padToAlignment(8)

        var reader = BinarySliceReader(data: writer.data, endianness: .little)
        #expect(try reader.readUInt16() == 0xCAFE)
        #expect(try reader.readUInt32() == 0xDEAD_BEEF)
        #expect(try reader.readUInt64() == 0x0123_4567_89AB_CDEF)
        #expect(try reader.readULEB128() == 0)
        #expect(try reader.readULEB128() == 624_485)
        #expect(try reader.readULEB128() == 0xFFFF_FFFF_FFFF)
        #expect(try reader.readSLEB128() == -123_456)
        #expect(try reader.readSLEB128() == 987_654)
        #expect(try reader.readNullTerminatedUTF8() == "MachGraph")
        try reader.align(to: 8)
        #expect(reader.isAtEnd)

        #expect(throws: MachGraphError.self) {
            _ = try reader.readUInt8()
        }
    }

    @Test("Load real macOS /bin/ls Universal/Mach-O binary and verify segments, code section, symbols, and signature")
    func realMacOSSystemBinaryBinLsLoading() throws {
        let lsURL = URL(fileURLWithPath: "/bin/ls")
        try #require(FileManager.default.fileExists(atPath: lsURL.path))

        let image = try UniversalBinaryDispatcher.load(fileURL: lsURL)
        #expect(image.fileName == "ls")
        #expect(image.fileSize > 16_384)
        #expect(image.architecture.isARM64Family || image.architecture == .x86_64)
        #expect(image.segments.contains { $0.name == "__TEXT" })
        #expect(image.sections.contains { $0.fullName == "__TEXT,__text" })
        #expect(!image.executableSections().isEmpty)
        #expect(!image.importedLibraries.isEmpty)
        #expect(!image.symbols.isEmpty)
        #expect(!image.strings.isEmpty)
        #expect(image.codeSignature.isSigned)
    }
}
