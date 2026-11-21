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

    @Test("G5: /usr/bin/ssh __TEXT,__info_plist is classified as constData and excluded from executableSections")
    func sshInfoPlistExcludedFromExecutableSections() throws {
        let sshURL = URL(fileURLWithPath: "/usr/bin/ssh")
        try #require(FileManager.default.fileExists(atPath: sshURL.path))

        let image = try UniversalBinaryDispatcher.load(fileURL: sshURL)
        let infoPlistSection = try #require(image.sections.first { $0.sectionName == "__info_plist" })
        #expect(infoPlistSection.kind != .code)
        #expect(!image.executableSections().contains { $0.sectionName == "__info_plist" })
    }

    @Test("G20: Truncated Mach-O slices (8000 and 30000 bytes), empty files, and plain text files throw MachGraphError")
    func truncatedMachOEmptyAndPlainTextRejected() throws {
        // 1. Empty 0-byte input (/dev/null equivalent)
        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: Data(), fileName: "empty")
        }

        // 2. Plain text input
        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: Data("plain text README line\n".utf8), fileName: "readme.txt")
        }

        // 3. Extract arm64e slice from /bin/ls and truncate to 8000 and 30000 bytes
        let lsWhole = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        let slices = try UniversalBinaryDispatcher.parseUniversalSlices(data: lsWhole)
        let arm64eSlice = try #require(slices.first { $0.architecture == .arm64e } ?? slices.first)
        let start = lsWhole.startIndex + Int(arm64eSlice.fileOffset.rawValue)
        let sliceBytes = Data(lsWhole[start..<(start + Int(arm64eSlice.size))])
        #expect(sliceBytes.count > 30_000)

        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: Data(sliceBytes.prefix(8_000)), fileName: "ls_trunc8k")
        }
        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: Data(sliceBytes.prefix(30_000)), fileName: "ls_trunc30k")
        }
        // Universal Fat /bin/ls truncated to 8000 bytes as well
        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: Data(lsWhole.prefix(8_000)), fileName: "ls_fat_trunc8k")
        }
    }

    // MARK: - G28: thin (single-architecture) Mach-O range checks

    /// Minimal little-endian Mach-O 64 load-command walker used to corrupt one header field at a time.
    private struct ThinMachOEditor {
        var data: Data

        private func u32(_ off: Int) -> UInt32 {
            data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: UInt32.self) }.littleEndian
        }
        private func u64(_ off: Int) -> UInt64 {
            data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: UInt64.self) }.littleEndian
        }
        private mutating func setU32(_ off: Int, _ value: UInt32) {
            withUnsafeBytes(of: value.littleEndian) { data.replaceSubrange(off..<(off + 4), with: $0) }
        }
        private mutating func setU64(_ off: Int, _ value: UInt64) {
            withUnsafeBytes(of: value.littleEndian) { data.replaceSubrange(off..<(off + 8), with: $0) }
        }
        private func fixedName(_ off: Int) -> String {
            String(decoding: data[off..<(off + 16)].prefix { $0 != 0 }, as: UTF8.self)
        }

        /// File offsets of every load command whose `cmd` equals `wanted`.
        private func commandOffsets(_ wanted: UInt32) -> [Int] {
            var found: [Int] = []
            var off = 32
            for _ in 0..<Int(u32(16)) {
                if u32(off) == wanted { found.append(off) }
                off += Int(u32(off + 4))
            }
            return found
        }

        private func segmentOffset(_ name: String) throws -> Int {
            try #require(commandOffsets(0x19).first { fixedName($0 + 8) == name }, "LC_SEGMENT_64 \(name) missing")
        }

        /// Grows `LC_SEGMENT_64.filesize` without growing the file.
        mutating func growSegmentFileSize(_ name: String, by delta: UInt64) throws {
            let seg = try segmentOffset(name)
            setU64(seg + 48, u64(seg + 48) + delta)
        }

        /// Sets `section_64.size` of `segment,section` without touching its segment.
        mutating func setSectionSize(segment: String, section: String, to size: UInt64) throws {
            let seg = try segmentOffset(segment)
            let nsects = Int(u32(seg + 64))
            let sect = try #require(
                (0..<nsects).map { seg + 72 + $0 * 80 }.first { fixedName($0) == section },
                "section \(segment),\(section) missing"
            )
            setU64(sect + 40, size)
        }

        /// Sets the `datasize` field of a `linkedit_data_command` (dataoff @ +8, datasize @ +12).
        mutating func setLinkeditDataSize(command: UInt32, to size: UInt32) throws {
            let cmd = try #require(commandOffsets(command).first, "load command 0x\(String(command, radix: 16)) missing")
            setU32(cmd + 12, size)
        }

        /// Sets `symtab_command.strsize` (stroff @ +16, strsize @ +20).
        mutating func setSymtabStringSize(to size: UInt32) throws {
            let cmd = try #require(commandOffsets(0x2).first, "LC_SYMTAB missing")
            setU32(cmd + 20, size)
        }

        /// Sets `symtab_command.nsyms` (symoff @ +8, nsyms @ +12).
        mutating func setSymtabSymbolCount(to count: UInt32) throws {
            let cmd = try #require(commandOffsets(0x2).first, "LC_SYMTAB missing")
            setU32(cmd + 12, count)
        }
    }

    @Test("G28: a thin arm64 Mach-O truncated at any length is rejected with an error instead of crashing")
    func truncatedThinARM64MachOIsRejectedAtEveryCutPoint() throws {
        let whole = try RepoFixtures.thinARM64SampleData()
        #expect(UniversalBinaryDispatcher.detectFormat(data: whole) == .machO64)

        // Control: the untruncated fixture is a thin arm64 image that loads cleanly.
        let intact = try UniversalBinaryDispatcher.load(data: whole, fileName: "demo_arm64_sample")
        #expect(intact.architecture == .arm64)
        #expect(intact.slices.count == 1)
        #expect(intact.segments.map(\.name) == ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__LINKEDIT"])
        let linkedit = try #require(intact.segments.last)
        #expect(Int(linkedit.fileOffset.rawValue + linkedit.fileSize) == whole.count)

        // Cut points chosen from the fixture's own layout: inside the header, the load commands, each section,
        // segment padding, and each __LINKEDIT blob, plus the exact half and one byte short of the full file.
        let text = try #require(intact.sections.first { $0.sectionName == "__text" })
        let got = try #require(intact.sections.first { $0.sectionName == "__got" })
        var cutPoints: Set<Int> = [
            1, 3, 4, 8, 31, 32, 200,
            Int(text.fileOffset.rawValue) - 1,
            Int(text.fileOffset.rawValue) + 8,
            Int(text.fileOffset.rawValue + text.size),
            8_000,
            Int(got.fileOffset.rawValue),
            Int(got.fileOffset.rawValue) + 4,
            whole.count / 2,
            20_000,
            Int(linkedit.fileOffset.rawValue),
            Int(linkedit.fileOffset.rawValue) + 32,
            whole.count - 400,
            whole.count - 100,
            whole.count - 1
        ]
        // Plus a coarse sweep so no region of the file is left untested.
        cutPoints.formUnion(stride(from: 64, to: whole.count, by: 251))

        for cut in cutPoints.sorted() {
            #expect(cut > 0 && cut < whole.count)
            #expect(throws: MachGraphError.self, "prefix of \(cut) / \(whole.count) bytes must be rejected") {
                _ = try UniversalBinaryDispatcher.load(data: Data(whole.prefix(cut)), fileName: "thin_trunc_\(cut)")
            }
        }
    }

    @Test("G28: segment, section, and __LINKEDIT blob ranges that exceed a thin Mach-O are each rejected on their own")
    func thinMachOSegmentSectionAndBlobRangesBeyondFileAreRejected() throws {
        let whole = try RepoFixtures.thinARM64SampleData()
        let beyond: UInt32 = 0x10_0000 // 1 MiB, far past the 33 KiB fixture

        // 1. Only a segment range exceeds the file (all sections and blobs still fit).
        var segmentOnly = ThinMachOEditor(data: whole)
        try segmentOnly.growSegmentFileSize("__LINKEDIT", by: UInt64(beyond))
        #expect(throws: MachGraphError.self, "segment filesize beyond EOF") {
            _ = try UniversalBinaryDispatcher.load(data: segmentOnly.data, fileName: "seg_beyond_eof")
        }

        // 2. Only a section range exceeds the file (its segment still fits).
        var sectionOnly = ThinMachOEditor(data: whole)
        try sectionOnly.setSectionSize(segment: "__TEXT", section: "__unwind_info", to: UInt64(beyond))
        #expect(throws: MachGraphError.self, "section size beyond EOF") {
            _ = try UniversalBinaryDispatcher.load(data: sectionOnly.data, fileName: "sect_beyond_eof")
        }

        // 3. Only one __LINKEDIT blob exceeds the file (segments and sections still fit).
        let linkeditDataCommands: [(name: String, cmd: UInt32)] = [
            ("LC_FUNCTION_STARTS", 0x26),
            ("LC_CODE_SIGNATURE", 0x1D),
            ("LC_DYLD_CHAINED_FIXUPS", 0x8000_0034),
            ("LC_DYLD_EXPORTS_TRIE", 0x8000_0033)
        ]
        for entry in linkeditDataCommands {
            var blobOnly = ThinMachOEditor(data: whole)
            try blobOnly.setLinkeditDataSize(command: entry.cmd, to: beyond)
            #expect(throws: MachGraphError.self, "\(entry.name) datasize beyond EOF") {
                _ = try UniversalBinaryDispatcher.load(data: blobOnly.data, fileName: "blob_beyond_eof")
            }
        }

        var stringPool = ThinMachOEditor(data: whole)
        try stringPool.setSymtabStringSize(to: beyond)
        #expect(throws: MachGraphError.self, "LC_SYMTAB strsize beyond EOF") {
            _ = try UniversalBinaryDispatcher.load(data: stringPool.data, fileName: "strtab_beyond_eof")
        }

        var symbolTable = ThinMachOEditor(data: whole)
        try symbolTable.setSymtabSymbolCount(to: beyond)
        #expect(throws: MachGraphError.self, "LC_SYMTAB nsyms beyond EOF") {
            _ = try UniversalBinaryDispatcher.load(data: symbolTable.data, fileName: "symtab_beyond_eof")
        }
    }

    @Test("G22: ELF64 relocatable object file (ET_REL, e_type == 1) is rejected with unsupportedContainer")
    func elf64RelocatableObjectRejected() {
        var elfRel = Data(repeating: 0, count: 64)
        elfRel[0] = 0x7F; elfRel[1] = 0x45; elfRel[2] = 0x4C; elfRel[3] = 0x46 // \x7FELF
        elfRel[4] = 2 // ELFCLASS64
        elfRel[5] = 1 // ELFDATA2LSB
        elfRel[6] = 1 // EV_CURRENT
        elfRel[16] = 1; elfRel[17] = 0 // e_type = ET_REL (1)
        elfRel[18] = 183; elfRel[19] = 0 // e_machine = EM_AARCH64 (183)
        elfRel[20] = 1 // e_version = 1

        #expect(throws: MachGraphError.self) {
            _ = try UniversalBinaryDispatcher.load(data: elfRel, fileName: "e1.o")
        }
    }

    @Test("G10: /bin/ls symbols distinguish real LC_SYMTAB symbols from inferred LC_FUNCTION_STARTS and stub/GOT entries")
    func binLsRealSymtabVersusInferredSymbolProvenance() throws {
        let image = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: "/bin/ls"))
        let symtabSymbols = image.symbols.filter { !$0.isInferred }
        let inferredSymbols = image.symbols.filter { $0.isInferred }

        #expect(!symtabSymbols.isEmpty)
        #expect(symtabSymbols.contains { $0.name == "__mh_execute_header" && $0.provenance == .symtab })
        #expect(!inferredSymbols.isEmpty)
        #expect(inferredSymbols.contains { $0.provenance == .functionStarts })
    }

    @Test("G31: MachOSymbolDemangler never traps on unparseable or prefix-truncated Swift/C++ symbols and returns raw mangled names")
    func g31MachOSymbolDemanglerUnparseableAndTruncatedSymbolsReturnRawName() {
        // Exact crashing symbol from /usr/bin/log (`s` at end of body caused Index out of range).
        let logSymbol = "_$sSo9NSScannerC10FoundationE12currentIndexSS0D0Vvs"
        #expect(MachOSymbolDemangler.demangle(logSymbol) == logSymbol)
        for cut in 1..<logSymbol.count {
            let prefix = String(logSymbol.prefix(cut))
            #expect(
                MachOSymbolDemangler.demangle(prefix) == prefix,
                "Prefix of length \(cut) (\(prefix)) must return raw symbol untouched"
            )
        }

        // Additional crashing shapes from the 107 baseline binaries (trailing digits `_Ts5`, `_Tg5`, `.resume.0`,
        // `0`-prefixed word substitutions, generic subscript setters `cis`, optional property setters `Sgvs`).
        let unparseableAtEveryCut = [
            "_$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5",
            "_$sSKsSQ7ElementRpzrlE9lastIndex2of0C0QzSgAB_tFSS8UTF8ViewV_Tg5",
            "_$sSDyq_Sgxcis"
        ]
        for sym in unparseableAtEveryCut {
            #expect(MachOSymbolDemangler.demangle(sym) == sym)
            for cut in 1..<sym.count {
                let prefix = String(sym.prefix(cut))
                #expect(MachOSymbolDemangler.demangle(prefix) == prefix)
            }
        }

        // Symbols whose prefix hits one valid complete nominal boundary (`...V` or `...C`) and is otherwise unparseable.
        let mixedPrefixSymbols: [(symbol: String, validNominalPrefix: String, expectedNominal: String)] = [
            (
                "_$s16FoundationModels17GenerationOptionsV11temperatureSdSgvs",
                "_$s16FoundationModels17GenerationOptionsV",
                "FoundationModels.GenerationOptions"
            ),
            (
                "_$s15icloudmailagent11APNSManagerC8delegateAA0B8Delegate_pSgvM.resume.0",
                "_$s15icloudmailagent11APNSManagerC",
                "icloudmailagent.APNSManager"
            )
        ]
        for item in mixedPrefixSymbols {
            #expect(MachOSymbolDemangler.demangle(item.symbol) == item.symbol)
            for cut in 1..<item.symbol.count {
                let prefix = String(item.symbol.prefix(cut))
                let got = MachOSymbolDemangler.demangle(prefix)
                if prefix == item.validNominalPrefix {
                    #expect(got == item.expectedNominal)
                } else {
                    #expect(
                        got == prefix,
                        "Truncated prefix \(prefix) must return raw mangled name, got \(got)"
                    )
                }
            }
        }

        // Malformed / boundary Swift and Itanium C++ inputs must return raw input untouched.
        let malformedInputs = [
            "", "_", "_$", "_$s", "$s", "_$S", "$S", "_T0", "__T0",
            "_$ss", "_$s0", "_$s99", "_$s9MachGraph", "$ss6UInt64",
            "_Z", "__Z", "_Z99", "_ZN3foo", "_ZN3fooI3bar", "_ZN3foo3barEP"
        ]
        for raw in malformedInputs {
            #expect(MachOSymbolDemangler.demangle(raw) == raw, "Expected raw return for \(raw.debugDescription)")
        }

        // Positive controls: complete supported symbols continue to demangle cleanly.
        #expect(MachOSymbolDemangler.demangle("$s15MachGraphTarget13LicensePacketV") == "MachGraphTarget.LicensePacket")
        #expect(
            MachOSymbolDemangler.demangle("$s15MachGraphTarget13LicensePacketVMn")
                == "MachGraphTarget.LicensePacket (nominal type descriptor)"
        )
        #expect(MachOSymbolDemangler.demangle("$ss6UInt64V") == "Swift.UInt64")
        #expect(MachOSymbolDemangler.demangle("_main") == "main")
        #expect(MachOSymbolDemangler.demangle("__mh_execute_header") == "__mh_execute_header")
    }

    // MARK: - M3 Stage 1: LC_SYMTAB Fidelity & Three-Part Dylib Versions

    private static func buildSyntheticMachOForSymbolAndDylibTests(
        fileType: UInt32 = MachOConstants.mhExecute,
        installID: (name: String, current: UInt32, compat: UInt32)? = nil,
        dylibs: [(cmd: UInt32, name: String, current: UInt32, compat: UInt32)] = [],
        symtabEntries: [(name: String, va: UInt64, ext: Bool)] = [],
        exportTrieEntries: [ExportTrieBuilder.ExportEntry] = []
    ) -> Data {
        let imageBase: UInt64 = (fileType == MachOConstants.mhDylib) ? 0 : 0x1_0000_0000
        let textVA: UInt64 = imageBase + 0x1000
        let linkeditFileOff = 0x4000
        let linkeditVA = imageBase + 0x4000

        var sliceBytes = [UInt8](repeating: 0, count: linkeditFileOff)
        // 8 NOP/RET words in __TEXT,__text at file offset 0x1000
        let insnWords: [UInt32] = [
            0xD503_201F, 0xD65F_03C0, 0xD503_201F, 0xD65F_03C0,
            0xD503_201F, 0xD65F_03C0, 0xD503_201F, 0xD65F_03C0
        ]
        for (idx, w) in insnWords.enumerated() {
            let base = 0x1000 + idx * 4
            sliceBytes[base + 0] = UInt8(truncatingIfNeeded: w)
            sliceBytes[base + 1] = UInt8(truncatingIfNeeded: w >> 8)
            sliceBytes[base + 2] = UInt8(truncatingIfNeeded: w >> 16)
            sliceBytes[base + 3] = UInt8(truncatingIfNeeded: w >> 24)
        }

        var strPool = BinaryBufferWriter(capacity: 256, endianness: .little)
        strPool.appendUInt8(0)
        var nlistWriter = BinaryBufferWriter(capacity: symtabEntries.count * 16, endianness: .little)
        for entry in symtabEntries {
            let strOff = UInt32(strPool.count)
            strPool.appendCString(entry.name)
            nlistWriter.appendUInt32(strOff)
            nlistWriter.appendUInt8(MachOConstants.nSect | (entry.ext ? MachOConstants.nExt : 0))
            nlistWriter.appendUInt8(1) // __TEXT,__text
            nlistWriter.appendUInt16(0)
            nlistWriter.appendUInt64(entry.va)
        }
        strPool.padToAlignment(8)

        let trieData = exportTrieEntries.isEmpty ? Data() : ExportTrieBuilder.buildTrie(entries: exportTrieEntries)

        var linkedit = BinaryBufferWriter(capacity: 512, endianness: .little)
        let trieOff = linkeditFileOff + linkedit.count
        if !trieData.isEmpty {
            linkedit.appendData(trieData)
            linkedit.padToAlignment(8)
        }
        let symtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(nlistWriter.bytes)
        let strtabOff = linkeditFileOff + linkedit.count
        linkedit.appendBytes(strPool.bytes)
        linkedit.padToAlignment(16)
        if linkedit.count == 0 {
            linkedit.appendUInt64(0)
        }

        let linkeditVMSize = (linkedit.count + 0x3FFF) & ~0x3FFF

        var lc = BinaryBufferWriter(capacity: 1024, endianness: .little)
        var ncmds: UInt32 = 0

        func writeSeg64(name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64, prot: Int32, hasTextSec: Bool) {
            let cmdSize: UInt32 = hasTextSec ? (72 + 80) : 72
            lc.appendUInt32(MachOConstants.lcSegment64)
            lc.appendUInt32(cmdSize)
            lc.appendFixedASCII(name, length: 16)
            lc.appendUInt64(vmaddr)
            lc.appendUInt64(vmsize)
            lc.appendUInt64(fileoff)
            lc.appendUInt64(filesize)
            lc.appendUInt32(UInt32(bitPattern: prot))
            lc.appendUInt32(UInt32(bitPattern: prot))
            lc.appendUInt32(hasTextSec ? 1 : 0)
            lc.appendUInt32(0)
            if hasTextSec {
                lc.appendFixedASCII("__text", length: 16)
                lc.appendFixedASCII("__TEXT", length: 16)
                lc.appendUInt64(textVA)
                lc.appendUInt64(UInt64(insnWords.count * 4))
                lc.appendUInt32(0x1000)
                lc.appendUInt32(2)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
            }
            ncmds += 1
        }

        if fileType == MachOConstants.mhExecute {
            writeSeg64(name: "__PAGEZERO", vmaddr: 0, vmsize: imageBase, fileoff: 0, filesize: 0, prot: 0, hasTextSec: false)
        }
        writeSeg64(name: "__TEXT", vmaddr: imageBase, vmsize: 0x4000, fileoff: 0, filesize: 0x4000, prot: 5, hasTextSec: true)
        writeSeg64(name: "__LINKEDIT", vmaddr: linkeditVA, vmsize: UInt64(linkeditVMSize), fileoff: UInt64(linkeditFileOff), filesize: UInt64(linkedit.count), prot: 1, hasTextSec: false)

        func writeDylibCmd(cmd: UInt32, name: String, current: UInt32, compat: UInt32) {
            let nameBytes = Array(name.utf8) + [0]
            let cmdSize = (24 + nameBytes.count + 7) & ~7
            lc.appendUInt32(cmd)
            lc.appendUInt32(UInt32(cmdSize))
            lc.appendUInt32(24)
            lc.appendUInt32(2)
            lc.appendUInt32(current)
            lc.appendUInt32(compat)
            lc.appendBytes(nameBytes)
            lc.padToAlignment(8)
            ncmds += 1
        }

        if let id = installID {
            writeDylibCmd(cmd: MachOConstants.lcIdDylib, name: id.name, current: id.current, compat: id.compat)
        }
        for d in dylibs {
            writeDylibCmd(cmd: d.cmd, name: d.name, current: d.current, compat: d.compat)
        }

        if !trieData.isEmpty {
            lc.appendUInt32(MachOConstants.lcDyldExportsTrie)
            lc.appendUInt32(16)
            lc.appendUInt32(UInt32(trieOff))
            lc.appendUInt32(UInt32(trieData.count))
            ncmds += 1
        }

        lc.appendUInt32(MachOConstants.lcSymtab)
        lc.appendUInt32(24)
        lc.appendUInt32(UInt32(symtabOff))
        lc.appendUInt32(UInt32(symtabEntries.count))
        lc.appendUInt32(UInt32(strtabOff))
        lc.appendUInt32(UInt32(strPool.count))
        ncmds += 1

        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(0)
        hdr.appendUInt32(fileType)
        hdr.appendUInt32(ncmds)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhTwoLevel | MachOConstants.mhPIE)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for (i, b) in hdr.bytes.enumerated() {
            sliceBytes[i] = b
        }
        return Data(sliceBytes + linkedit.bytes)
    }

    @Test("M3 D-M3-3: LC_SYMTAB preserves all defined symbols at the same address including identical-name multiset entries")
    func m3SymtabPreservesSameAddressAliasesAndMultisetDuplicates() throws {
        let data = Self.buildSyntheticMachOForSymbolAndDylibTests(
            symtabEntries: [
                (name: "_bseek.cold.1", va: 0x1_0000_1000, ext: false),
                (name: "_btell.cold.1", va: 0x1_0000_1000, ext: false),
                (name: "_OUTLINED_FUNCTION_1", va: 0x1_0000_1008, ext: false),
                (name: "_OUTLINED_FUNCTION_1", va: 0x1_0000_1008, ext: false)
            ]
        )
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "SameAddrAliases.arm64")
        let symtabSymbols = image.symbols.filter { !$0.isInferred }

        #expect(symtabSymbols.count == 4)
        let at1000 = symtabSymbols.filter { $0.address == VirtualAddress(0x1_0000_1000) }.map(\.name)
        #expect(at1000.sorted() == ["_bseek.cold.1", "_btell.cold.1"])
        let at1008 = symtabSymbols.filter { $0.address == VirtualAddress(0x1_0000_1008) }.map(\.name)
        #expect(at1008 == ["_OUTLINED_FUNCTION_1", "_OUTLINED_FUNCTION_1"])

        if FileManager.default.isReadableFile(atPath: "/bin/csh") {
            let csh = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: "/bin/csh"))
            let cshRealNames = Set(csh.symbols.filter { !$0.isInferred }.map(\.name))
            #expect(cshRealNames.contains("_bseek.cold.1"))
            #expect(cshRealNames.contains("_btell.cold.1"))
        }
    }

    @Test("M3 D-M3-3: Inferred symbols never overwrite LC_SYMTAB symbol names at the same address")
    func m3InferredSymbolsNeverOverwriteRealSymtabNames() throws {
        // Local LC_SYMTAB symbol (.localSymbol, priority 30) collides at 0x100001000 with an Export Trie entry (.function, priority 50).
        let data = Self.buildSyntheticMachOForSymbolAndDylibTests(
            symtabEntries: [
                (name: "_real_symtab_local_thunk", va: 0x1_0000_1000, ext: false)
            ],
            exportTrieEntries: [
                .init(name: "_inferred_export_trie_winner", offsetFromImageBase: 0x1000, flags: 0)
            ]
        )
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "NoInferredOverwrite.arm64")
        let realNames = image.symbols.filter { !$0.isInferred }.map(\.name)
        #expect(realNames == ["_real_symtab_local_thunk"])
        #expect(!realNames.contains("_inferred_export_trie_winner"))

        if FileManager.default.isReadableFile(atPath: "/usr/libexec/cryptexd") {
            let cryptexd = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: "/usr/libexec/cryptexd"))
            let cryptexdRealNames = Set(cryptexd.symbols.filter { !$0.isInferred }.map(\.name))
            #expect(cryptexdRealNames.contains("_$s8cryptexd12DaemonServerC5queueACSo012OS_dispatch_D7_serialC_tKcfcTo"))
            #expect(!cryptexdRealNames.contains("-[TtC8cryptexd12DaemonServer initWithQueue:error:]"))
        }
    }

    @Test("M3 D-M3-5: Imported dylibs format versions as three-part major.minor.patch while preserving minOSVersion")
    func m3DylibVersionsUseThreePartFormatWithoutChangingPlatformVersion() throws {
        let execData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let execImage = try UniversalBinaryDispatcher.load(data: execData, fileName: "Demo.arm64e")

        // Platform versions must continue using compact formatting.
        #expect(execImage.minOSVersion == "14.0")
        #expect(execImage.sdkVersion == "15.0")

        // Dylib versions must always use three-part X.Y.Z formatting matching otool -L.
        let libSys = try #require(execImage.importedLibraries.first { $0.installName == "/usr/lib/libSystem.B.dylib" })
        #expect(libSys.currentVersion == "1355.0.0")
        #expect(libSys.compatibilityVersion == "1.0.0")
    }

    // MARK: - M3 Stage 3 (D-M3-4): ObjC Leading Underscore, Categories, Protocols, Class vs Instance Methods

    internal static func buildSyntheticObjCMetadataFixture() -> Data {
        // Layout (3 pages = 0xC000 bytes):
        // __TEXT       vm=0x100000000..0x100004000 file=0x0000..0x4000
        //   __text           vm=0x100001000 off=0x1000 size=0x20 (4 RET stubs)
        //   __objc_methname  vm=0x100002000 off=0x2000
        //   __objc_classname vm=0x100002200 off=0x2200
        //   __objc_methtype  vm=0x100002400 off=0x2400
        // __DATA_CONST vm=0x100004000..0x100008000 file=0x4000..0x8000
        //   __objc_classlist vm=0x100004000 off=0x4000 size=16 (2 class pointers)
        //   __objc_catlist   vm=0x100004020 off=0x4020 size=8  (1 category pointer)
        //   __objc_protolist vm=0x100004040 off=0x4040 size=24 (3 protocol pointers, 2 pointing to same protocol_t)
        //   __objc_const     vm=0x100004100 off=0x4100 size=0x500
        // __DATA       vm=0x100008000..0x10000C000 file=0x8000..0xC000
        //   __objc_data      vm=0x100008000 off=0x8000 size=160 (2 classes + 2 metaclasses, 40 bytes each)
        //   __objc_selrefs   vm=0x100008100 off=0x8100 size=64  (8 selector reference slots)
        //   __objc_ivar      vm=0x100008200 off=0x8200 size=8
        let imageBase: UInt64 = 0x1_0000_0000
        var buf = [UInt8](repeating: 0, count: 0xC000)

        func putU32(_ fileOff: Int, _ v: UInt32) {
            for b in 0..<4 { buf[fileOff + b] = UInt8(truncatingIfNeeded: v >> (b * 8)) }
        }
        func putU64(_ fileOff: Int, _ v: UInt64) {
            for b in 0..<8 { buf[fileOff + b] = UInt8(truncatingIfNeeded: v >> (b * 8)) }
        }
        func putRel32(_ fieldVA: UInt64, target targetVA: UInt64) {
            let fileOff = Int(fieldVA - imageBase)
            let delta = Int64(bitPattern: targetVA) - Int64(bitPattern: fieldVA)
            putU32(fileOff, UInt32(bitPattern: Int32(truncatingIfNeeded: delta)))
        }
        func putCStr(_ cursor: inout Int, _ s: String) -> UInt64 {
            let startVA = imageBase + UInt64(cursor)
            for byte in s.utf8 {
                buf[cursor] = byte
                cursor += 1
            }
            buf[cursor] = 0
            cursor += 1
            return startVA
        }

        // 4 RET instructions at 0x100001000, +4, +8, +12
        let fnInstVA: UInt64    = 0x1_0000_1000
        let fnClassVA: UInt64   = 0x1_0000_1004
        let fnCatInstVA: UInt64 = 0x1_0000_1008
        let fnCatClsVA: UInt64  = 0x1_0000_100C
        for i in 0..<4 {
            putU32(0x1000 + i * 4, 0xD65F_03C0)
        }

        // __objc_methname strings
        var methCur = 0x2000
        let selAppLaunchVA   = putCStr(&methCur, "applicationWillFinishLaunching:")
        let selSharedInstVA  = putCStr(&methCur, "sharedAppDelegate")
        let selAffineScaleVA = putCStr(&methCur, "affineScale")
        let selIdentityVA    = putCStr(&methCur, "identityTransform")
        let selProtoReqInst  = putCStr(&methCur, "renderDisplay:")
        let selProtoReqCls   = putCStr(&methCur, "defaultDisplayMode")
        let selProtoOptInst  = putCStr(&methCur, "didRefreshDisplay")
        let selProtoOptCls   = putCStr(&methCur, "supportsHDRDisplay")
        let methSize = UInt64(methCur - 0x2000)

        // __objc_selrefs slots at 0x100008100 (slot 0..7 -> selector C-string VAs)
        let selRefsBaseVA: UInt64 = 0x1_0000_8100
        let selVAs = [
            selAppLaunchVA, selSharedInstVA, selAffineScaleVA, selIdentityVA,
            selProtoReqInst, selProtoReqCls, selProtoOptInst, selProtoOptCls
        ]
        for (idx, sva) in selVAs.enumerated() {
            putU64(0x8100 + idx * 8, sva)
        }
        func selSlot(_ idx: Int) -> UInt64 { selRefsBaseVA + UInt64(idx * 8) }

        // __objc_classname strings (including leading-underscore Swift & private ObjC names)
        var clsCur = 0x2200
        let nameBaseClsVA   = putCStr(&clsCur, "_CUIThemeBaseRendition")
        let nameAppDelClsVA = putCStr(&clsCur, "_TtC10Calculator11AppDelegate")
        let nameCatVA       = putCStr(&clsCur, "CGAffineTransform")
        let nameProtoSwift  = putCStr(&clsCur, "_TtP10Calculator15DisplayProtocol_")
        let nameProtoAppDel = putCStr(&clsCur, "NSApplicationDelegate")
        let ivarWindowVA    = putCStr(&clsCur, "_mainWindow")
        let clsSize = UInt64(clsCur - 0x2200)

        // __objc_methtype strings
        var typeCur = 0x2400
        let typeVoidObjVA = putCStr(&typeCur, "v24@0:8@16")
        let typeIdClsVA   = putCStr(&typeCur, "@16@0:8")
        let typeIvarObjVA = putCStr(&typeCur, "@\"NSWindow\"")
        let typeSize = UInt64(typeCur - 0x2400)

        // Helper to write a 1-entry relative small method_list_t (indirect via __objc_selrefs, entsize=12 | 0x80000000)
        func writeRelSmallMethodList(at listVA: UInt64, selRefSlotVA: UInt64, typesVA: UInt64, impVA: UInt64?) {
            let off = Int(listVA - imageBase)
            putU32(off, 0x8000_000C) // smallMethodListFlag | 12 (indirect via __objc_selrefs)
            putU32(off + 4, 1)
            putRel32(listVA + 8, target: selRefSlotVA)
            putRel32(listVA + 12, target: typesVA)
            if let impVA {
                putRel32(listVA + 16, target: impVA)
            } else {
                putU32(off + 16, 0) // protocol method declaration: imp == 0
            }
        }

        // Allocate structures inside __DATA_CONST,__objc_const (base 0x100004100):
        let clsInstListVA: UInt64      = 0x1_0000_4100 // 20 bytes
        let clsMetaListVA: UInt64      = 0x1_0000_4120 // 20 bytes
        let catInstListVA: UInt64      = 0x1_0000_4140 // 20 bytes
        let catMetaListVA: UInt64      = 0x1_0000_4160 // 20 bytes
        let protoReqInstListVA: UInt64 = 0x1_0000_4180 // 20 bytes
        let protoReqClsListVA: UInt64  = 0x1_0000_41A0 // 20 bytes
        let protoOptInstListVA: UInt64 = 0x1_0000_41C0 // 20 bytes
        let protoOptClsListVA: UInt64  = 0x1_0000_41E0 // 20 bytes

        writeRelSmallMethodList(at: clsInstListVA, selRefSlotVA: selSlot(0), typesVA: typeVoidObjVA, impVA: fnInstVA)
        writeRelSmallMethodList(at: clsMetaListVA, selRefSlotVA: selSlot(1), typesVA: typeIdClsVA, impVA: fnClassVA)
        writeRelSmallMethodList(at: catInstListVA, selRefSlotVA: selSlot(2), typesVA: typeIdClsVA, impVA: fnCatInstVA)
        writeRelSmallMethodList(at: catMetaListVA, selRefSlotVA: selSlot(3), typesVA: typeIdClsVA, impVA: fnCatClsVA)
        writeRelSmallMethodList(at: protoReqInstListVA, selRefSlotVA: selSlot(4), typesVA: typeVoidObjVA, impVA: nil)
        writeRelSmallMethodList(at: protoReqClsListVA, selRefSlotVA: selSlot(5), typesVA: typeIdClsVA, impVA: nil)
        writeRelSmallMethodList(at: protoOptInstListVA, selRefSlotVA: selSlot(6), typesVA: typeVoidObjVA, impVA: nil)
        writeRelSmallMethodList(at: protoOptClsListVA, selRefSlotVA: selSlot(7), typesVA: typeIdClsVA, impVA: nil)

        // protocol_t #1: NSApplicationDelegate at 0x100004220 (72 bytes; unused method lists set to imageBase to guard __mh_execute_header)
        let protoAppDelVA: UInt64 = 0x1_0000_4220
        putU64(Int(protoAppDelVA - imageBase) + 0x00, imageBase)
        putU64(Int(protoAppDelVA - imageBase) + 0x08, nameProtoAppDel)
        putU64(Int(protoAppDelVA - imageBase) + 0x10, imageBase) // null-rebased to __mh_execute_header
        putU64(Int(protoAppDelVA - imageBase) + 0x18, imageBase)
        putU64(Int(protoAppDelVA - imageBase) + 0x20, imageBase)
        putU64(Int(protoAppDelVA - imageBase) + 0x28, imageBase)
        putU64(Int(protoAppDelVA - imageBase) + 0x30, imageBase)

        // protocol_list_t for DisplayProtocol adopting NSApplicationDelegate at 0x100004280
        let protoInheritedListVA: UInt64 = 0x1_0000_4280
        putU64(Int(protoInheritedListVA - imageBase) + 0x00, 1)
        putU64(Int(protoInheritedListVA - imageBase) + 0x08, protoAppDelVA)

        // protocol_t #2: _TtP10Calculator15DisplayProtocol_ at 0x1000042A0
        let protoDisplayVA: UInt64 = 0x1_0000_42A0
        putU64(Int(protoDisplayVA - imageBase) + 0x00, imageBase)
        putU64(Int(protoDisplayVA - imageBase) + 0x08, nameProtoSwift)
        putU64(Int(protoDisplayVA - imageBase) + 0x10, protoInheritedListVA)
        putU64(Int(protoDisplayVA - imageBase) + 0x18, protoReqInstListVA)
        putU64(Int(protoDisplayVA - imageBase) + 0x20, protoReqClsListVA)
        putU64(Int(protoDisplayVA - imageBase) + 0x28, protoOptInstListVA)
        putU64(Int(protoDisplayVA - imageBase) + 0x30, protoOptClsListVA)

        // protocol_list_t for _TtC10Calculator11AppDelegate adopting both protocols at 0x100004300
        let clsAdoptedProtosVA: UInt64 = 0x1_0000_4300
        putU64(Int(clsAdoptedProtosVA - imageBase) + 0x00, 2)
        putU64(Int(clsAdoptedProtosVA - imageBase) + 0x08, protoAppDelVA)
        putU64(Int(clsAdoptedProtosVA - imageBase) + 0x10, protoDisplayVA)

        // ivar_list_t at 0x100004320 (1 ivar: _mainWindow at offset 16)
        let ivarOffsetSlotVA: UInt64 = 0x1_0000_8200
        putU32(Int(ivarOffsetSlotVA - imageBase), 16)
        let ivarListVA: UInt64 = 0x1_0000_4320
        putU32(Int(ivarListVA - imageBase) + 0x00, 32)
        putU32(Int(ivarListVA - imageBase) + 0x04, 1)
        putU64(Int(ivarListVA - imageBase) + 0x08, ivarOffsetSlotVA)
        putU64(Int(ivarListVA - imageBase) + 0x10, ivarWindowVA)
        putU64(Int(ivarListVA - imageBase) + 0x18, typeIvarObjVA)
        putU32(Int(ivarListVA - imageBase) + 0x20, 3)
        putU32(Int(ivarListVA - imageBase) + 0x24, 8)

        // Base class _CUIThemeBaseRendition RO (0x100004360) & meta RO (0x1000043B0)
        let baseROVA: UInt64     = 0x1_0000_4360
        let baseMetaROVA: UInt64 = 0x1_0000_43B0
        putU32(Int(baseROVA - imageBase) + 0x08, 8)
        putU64(Int(baseROVA - imageBase) + 0x18, nameBaseClsVA)
        putU32(Int(baseMetaROVA - imageBase) + 0x00, 1)
        putU64(Int(baseMetaROVA - imageBase) + 0x18, nameBaseClsVA)

        // Subclass _TtC10Calculator11AppDelegate RO (0x100004400) & meta RO (0x100004450)
        let appROVA: UInt64     = 0x1_0000_4400
        let appMetaROVA: UInt64 = 0x1_0000_4450
        putU32(Int(appROVA - imageBase) + 0x08, 24)
        putU64(Int(appROVA - imageBase) + 0x18, nameAppDelClsVA)
        putU64(Int(appROVA - imageBase) + 0x20, clsInstListVA)
        putU64(Int(appROVA - imageBase) + 0x28, clsAdoptedProtosVA)
        putU64(Int(appROVA - imageBase) + 0x30, ivarListVA)
        putU32(Int(appMetaROVA - imageBase) + 0x00, 1)
        putU64(Int(appMetaROVA - imageBase) + 0x18, nameAppDelClsVA)
        putU64(Int(appMetaROVA - imageBase) + 0x20, clsMetaListVA)

        // objc_class_t instances in __DATA,__objc_data (0x100008000):
        let baseClsVA: UInt64     = 0x1_0000_8000
        let baseMetaClsVA: UInt64 = 0x1_0000_8028
        let appClsVA: UInt64      = 0x1_0000_8050
        let appMetaClsVA: UInt64  = 0x1_0000_8078

        putU64(Int(baseClsVA - imageBase) + 0x00, baseMetaClsVA)
        putU64(Int(baseClsVA - imageBase) + 0x20, baseROVA)
        putU64(Int(baseMetaClsVA - imageBase) + 0x20, baseMetaROVA)

        putU64(Int(appClsVA - imageBase) + 0x00, appMetaClsVA)
        putU64(Int(appClsVA - imageBase) + 0x08, baseClsVA) // internal superclass with leading `_`!
        putU64(Int(appClsVA - imageBase) + 0x20, appROVA)
        putU64(Int(appMetaClsVA - imageBase) + 0x20, appMetaROVA)

        // category_t at 0x1000044A0 on _CUIThemeBaseRendition
        let catVA: UInt64 = 0x1_0000_44A0
        putU64(Int(catVA - imageBase) + 0x00, nameCatVA)
        putU64(Int(catVA - imageBase) + 0x08, baseClsVA)
        putU64(Int(catVA - imageBase) + 0x10, catInstListVA)
        putU64(Int(catVA - imageBase) + 0x18, catMetaListVA)
        putU64(Int(catVA - imageBase) + 0x20, protoInheritedListVA)

        // Populate __objc_classlist (0x4000), __objc_catlist (0x4020), __objc_protolist (0x4040)
        putU64(0x4000, baseClsVA)
        putU64(0x4008, appClsVA)
        putU64(0x4020, catVA)
        // Duplicate slot in __objc_protolist (like swiftc + clang in Calculator.app) -> must deduplicate by protocol_t VA
        putU64(0x4040, protoDisplayVA)
        putU64(0x4048, protoDisplayVA)
        putU64(0x4050, protoAppDelVA)

        // Build Mach-O 64 load commands
        var lc = BinaryBufferWriter(capacity: 1536, endianness: .little)
        var ncmds: UInt32 = 0

        func writeSeg(
            name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64, filesize: UInt64, prot: UInt32,
            secs: [(sect: String, addr: UInt64, size: UInt64, off: UInt32, align: UInt32, flags: UInt32)]
        ) {
            lc.appendUInt32(MachOConstants.lcSegment64)
            lc.appendUInt32(UInt32(72 + secs.count * 80))
            lc.appendFixedASCII(name, length: 16)
            lc.appendUInt64(vmaddr)
            lc.appendUInt64(vmsize)
            lc.appendUInt64(fileoff)
            lc.appendUInt64(filesize)
            lc.appendUInt32(prot)
            lc.appendUInt32(prot)
            lc.appendUInt32(UInt32(secs.count))
            lc.appendUInt32(0)
            for s in secs {
                lc.appendFixedASCII(s.sect, length: 16)
                lc.appendFixedASCII(name, length: 16)
                lc.appendUInt64(s.addr)
                lc.appendUInt64(s.size)
                lc.appendUInt32(s.off)
                lc.appendUInt32(s.align)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(s.flags)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
                lc.appendUInt32(0)
            }
            ncmds += 1
        }

        writeSeg(
            name: "__TEXT", vmaddr: imageBase, vmsize: 0x4000, fileoff: 0, filesize: 0x4000, prot: 5,
            secs: [
                ("__text", 0x1_0000_1000, 0x20, 0x1000, 2, MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions),
                ("__objc_methname", 0x1_0000_2000, methSize, 0x2000, 0, MachOConstants.sCStringLiterals),
                ("__objc_classname", 0x1_0000_2200, clsSize, 0x2200, 0, MachOConstants.sCStringLiterals),
                ("__objc_methtype", 0x1_0000_2400, typeSize, 0x2400, 0, MachOConstants.sCStringLiterals)
            ]
        )
        writeSeg(
            name: "__DATA_CONST", vmaddr: 0x1_0000_4000, vmsize: 0x4000, fileoff: 0x4000, filesize: 0x4000, prot: 3,
            secs: [
                ("__objc_classlist", 0x1_0000_4000, 16, 0x4000, 3, 0),
                ("__objc_catlist", 0x1_0000_4020, 8, 0x4020, 3, 0),
                ("__objc_protolist", 0x1_0000_4040, 24, 0x4040, 3, 0),
                ("__objc_const", 0x1_0000_4100, 0x500, 0x4100, 3, 0)
            ]
        )
        writeSeg(
            name: "__DATA", vmaddr: 0x1_0000_8000, vmsize: 0x4000, fileoff: 0x8000, filesize: 0x4000, prot: 3,
            secs: [
                ("__objc_data", 0x1_0000_8000, 160, 0x8000, 3, 0),
                ("__objc_selrefs", 0x1_0000_8100, 64, 0x8100, 3, 0),
                ("__objc_ivar", 0x1_0000_8200, 8, 0x8200, 2, 0)
            ]
        )

        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(0)
        hdr.appendUInt32(MachOConstants.mhExecute)
        hdr.appendUInt32(ncmds)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhTwoLevel | MachOConstants.mhPIE)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for (i, b) in hdr.bytes.enumerated() {
            buf[i] = b
        }
        return Data(buf)
    }

    @Test("M3 D-M3-4: ObjC class_ro_t.name and superclass preserve raw leading underscores without Swift demangling")
    func m3ObjCPreservesLeadingUnderscoreInClassAndSuperclassNames() throws {
        let data = Self.buildSyntheticObjCMetadataFixture()
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjCUnderscore.arm64")

        let classNames = Set(image.objcClasses.map(\.name))
        #expect(classNames == ["_CUIThemeBaseRendition", "_TtC10Calculator11AppDelegate"])

        let appDel = try #require(image.objcClasses.first { $0.name == "_TtC10Calculator11AppDelegate" })
        #expect(appDel.superclassName == "_CUIThemeBaseRendition")

        let calcPath = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        if FileManager.default.isReadableFile(atPath: calcPath) {
            let calc = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: calcPath))
            let calcNames = Set(calc.objcClasses.map(\.name))
            #expect(calcNames.count == 33)
            #expect(calcNames.contains("_TtC10Calculator11AppDelegate"))
            #expect(!calcNames.contains("TtC10Calculator11AppDelegate"))
        }

        let assetPath = "/usr/bin/assetutil"
        if FileManager.default.isReadableFile(atPath: assetPath) {
            let asset = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: assetPath))
            let assetNames = Set(asset.objcClasses.map(\.name))
            #expect(assetNames.contains("_CUIThemeNamedColorGradientRendition"))
            #expect(!assetNames.contains("CUIThemeNamedColorGradientRendition"))
        }
    }

    @Test("M3 D-M3-4: ObjC categories from __objc_catlist parse host className, instanceMethods, and classMethods")
    func m3ObjCParsesStructuredCategoriesFromObjCCatlist() throws {
        let data = Self.buildSyntheticObjCMetadataFixture()
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjCCategories.arm64")

        #expect(image.objcCategories.count == 1)
        let cat = try #require(image.objcCategories.first)
        #expect(cat.name == "CGAffineTransform")
        #expect(cat.className == "_CUIThemeBaseRendition")
        #expect(cat.adoptedProtocols == ["NSApplicationDelegate"])
        #expect(cat.instanceMethods.map(\.selector) == ["affineScale"])
        #expect(cat.classMethods.map(\.selector) == ["identityTransform"])

        let assetPath = "/usr/bin/assetutil"
        if FileManager.default.isReadableFile(atPath: assetPath) {
            let asset = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: assetPath))
            #expect(asset.objcCategories.count == 4)
            let cgCat = try #require(asset.objcCategories.first { $0.name == "CGAffineTransform" })
            #expect(cgCat.className == "NSValue")
            #expect(cgCat.instanceMethods.count == 2)
            #expect(cgCat.classMethods.count == 2)
        }
    }

    @Test("M3 D-M3-4: ObjC protocols from __objc_protolist deduplicate slots and parse required/optional method declarations")
    func m3ObjCParsesStructuredProtocolsFromObjCProtolistAndAdoptedProtocols() throws {
        let data = Self.buildSyntheticObjCMetadataFixture()
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjCProtocols.arm64")

        let appDel = try #require(image.objcClasses.first { $0.name == "_TtC10Calculator11AppDelegate" })
        #expect(appDel.adoptedProtocols == ["NSApplicationDelegate", "_TtP10Calculator15DisplayProtocol_"])

        // 3 slots in __objc_protolist pointing to 2 distinct protocol_t addresses -> 2 protocols
        #expect(image.objcProtocols.count == 2)
        let protoNames = Set(image.objcProtocols.map(\.name))
        #expect(protoNames == ["_TtP10Calculator15DisplayProtocol_", "NSApplicationDelegate"])

        let displayProto = try #require(image.objcProtocols.first { $0.name == "_TtP10Calculator15DisplayProtocol_" })
        #expect(displayProto.adoptedProtocols == ["NSApplicationDelegate"])
        #expect(displayProto.instanceMethods.map(\.selector) == ["renderDisplay:"])
        #expect(displayProto.classMethods.map(\.selector) == ["defaultDisplayMode"])
        #expect(displayProto.optionalInstanceMethods.map(\.selector) == ["didRefreshDisplay"])
        #expect(displayProto.optionalClassMethods.map(\.selector) == ["supportsHDRDisplay"])

        let nsAppProto = try #require(image.objcProtocols.first { $0.name == "NSApplicationDelegate" })
        #expect(nsAppProto.instanceMethods.isEmpty)
        #expect(nsAppProto.classMethods.isEmpty)

        let calcPath = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        if FileManager.default.isReadableFile(atPath: calcPath) {
            let calc = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: calcPath))
            #expect(calc.objcProtocols.count == 7)
            #expect(calc.objcProtocols.map(\.name).contains("NSApplicationDelegate"))
        }
    }

    @Test("M3 D-M3-4: ObjC class methods (+[...]) and instance methods (-[...]) remain strictly separated")
    func m3ObjCSeparatesClassAndInstanceMethodsOnClassesAndCategories() throws {
        let data = Self.buildSyntheticObjCMetadataFixture()
        let image = try UniversalBinaryDispatcher.load(data: data, fileName: "ObjCMethodSplit.arm64")

        let appDel = try #require(image.objcClasses.first { $0.name == "_TtC10Calculator11AppDelegate" })
        let instSels = appDel.methods.filter { !$0.isClassMethod }.map(\.selector)
        let clsSels = appDel.methods.filter { $0.isClassMethod }.map(\.selector)
        #expect(instSels == ["applicationWillFinishLaunching:"])
        #expect(clsSels == ["sharedAppDelegate"])

        let cat = try #require(image.objcCategories.first)
        #expect(cat.instanceMethods.allSatisfy { !$0.isClassMethod })
        #expect(cat.classMethods.allSatisfy { $0.isClassMethod })

        let inferredNames = Set(image.symbols.filter { $0.provenance == .objcMetadata }.map(\.name))
        #expect(inferredNames.contains("-[_TtC10Calculator11AppDelegate applicationWillFinishLaunching:]"))
        #expect(inferredNames.contains("+[_TtC10Calculator11AppDelegate sharedAppDelegate]"))
        #expect(inferredNames.contains("-[_CUIThemeBaseRendition(CGAffineTransform) affineScale]"))
        #expect(inferredNames.contains("+[_CUIThemeBaseRendition(CGAffineTransform) identityTransform]"))

        // Multi-kilobyte CoreML ObjC selectors (e.g. /usr/libexec/ospredictiond) must never be truncated at 512 bytes.
        let ospredPath = "/usr/libexec/ospredictiond"
        if FileManager.default.isReadableFile(atPath: ospredPath) {
            let ospred = try UniversalBinaryDispatcher.load(fileURL: URL(fileURLWithPath: ospredPath))
            let longSelectors = ospred.objcClasses.flatMap(\.methods).map(\.selector).filter { $0.utf8.count > 512 }
            #expect(!longSelectors.isEmpty)
            #expect(longSelectors.allSatisfy { $0.hasSuffix(":") })
        }
    }
}
