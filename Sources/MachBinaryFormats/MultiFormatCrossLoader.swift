import Foundation
import MachGraphModels

// MARK: - 64-Bit ELF Loader (System V ABI — AArch64 / x86_64 / RISC-V)

public enum ELF64Loader {
    private static let elfClass64: UInt8          = 2
    private static let elfData2LSB: UInt8         = 1
    private static let elfData2MSB: UInt8         = 2

    private static let etDyn: UInt16              = 3

    private static let emX86_64: UInt16           = 62
    private static let emAArch64: UInt16          = 183
    private static let emRISCV: UInt16            = 243

    private static let ptLoad: UInt32             = 1
    private static let ptDynamic: UInt32          = 2
    private static let ptNote: UInt32             = 4

    private static let pfX: UInt32                = 0x1
    private static let pfW: UInt32                = 0x2
    private static let pfR: UInt32                = 0x4

    private static let shtSymtab: UInt32          = 2
    private static let shtStrtab: UInt32          = 3
    private static let shtRela: UInt32            = 4
    private static let shtDynamic: UInt32         = 6
    private static let shtNote: UInt32            = 7
    private static let shtNobits: UInt32          = 8
    private static let shtDynsym: UInt32          = 11

    private static let shfWrite: UInt64           = 0x1
    private static let shfExecInstr: UInt64       = 0x4

    private static let dtNull: Int64              = 0
    private static let dtNeeded: Int64            = 1
    private static let dtStrTab: Int64            = 5
    private static let dtStrSz: Int64             = 10

    // Relocation types
    private static let rX86_64GlobDat: UInt32     = 6
    private static let rX86_64JumpSlot: UInt32    = 7
    private static let rX86_64Relative: UInt32    = 8
    private static let rAArch64GlobDat: UInt32    = 1025
    private static let rAArch64JumpSlot: UInt32   = 1026
    private static let rAArch64Relative: UInt32   = 1027

    private struct RawSectionHeader: Sendable {
        let nameOffset: Int
        var name: String
        let shType: UInt32
        let shFlags: UInt64
        let shAddr: UInt64
        let shOffset: UInt64
        let shSize: UInt64
        let shLink: UInt32
        let shInfo: UInt32
        let shAddrAlign: UInt64
        let shEntSize: UInt64
    }

    private struct RawProgramHeader: Sendable {
        let pType: UInt32
        let pFlags: UInt32
        let pOffset: UInt64
        let pVAddr: UInt64
        let pFileSz: UInt64
        let pMemSz: UInt64
    }

    public static func load(data: Data, fileName: String, filePath: String) throws -> LoadedBinaryImage {
        guard data.count >= 64 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 64, available: data.count)
        }
        guard data[data.startIndex] == 0x7F,
              data[data.startIndex + 1] == 0x45,
              data[data.startIndex + 2] == 0x4C,
              data[data.startIndex + 3] == 0x46 else {
            throw MachGraphError.invalidMagic(expected: "0x7F454C46 (ELF)", actualHex: "unknown")
        }

        let eiClass = data[data.startIndex + 4]
        guard eiClass == elfClass64 else {
            throw MachGraphError.unsupportedContainer("32-bit ELF (EI_CLASS=\(eiClass)) is not supported; ELF64 required")
        }

        let eiData = data[data.startIndex + 5]
        let endianness: BinaryEndianness
        switch eiData {
        case elfData2LSB: endianness = .little
        case elfData2MSB: endianness = .big
        default:
            throw MachGraphError.malformedHeader("Invalid ELF EI_DATA endianness (\(eiData))")
        }

        let osABI = data[data.startIndex + 7]
        let platformName: String
        switch osABI {
        case 3: platformName = "Linux"
        case 9: platformName = "FreeBSD"
        default: platformName = "System V ELF"
        }

        var reader = BinarySliceReader(data: data, endianness: endianness)
        try reader.seek(to: 16)
        let eType = try reader.readUInt16()
        if eType == 1 {
            throw MachGraphError.unsupportedContainer(
                "ELF64 relocatable object files (ET_REL) are not supported; pass an executable (ET_EXEC) or shared object (ET_DYN)."
            )
        }
        let eMachine = try reader.readUInt16()
        _ = try reader.readUInt32() // e_version
        let eEntry = try reader.readUInt64()
        let ePhOff = try reader.readUInt64()
        let eShOff = try reader.readUInt64()
        _ = try reader.readUInt32() // e_flags
        _ = try reader.readUInt16() // e_ehsize
        let ePhEntSize = Int(try reader.readUInt16())
        let ePhNum = Int(try reader.readUInt16())
        let eShEntSize = Int(try reader.readUInt16())
        let eShNum = Int(try reader.readUInt16())
        let eShStrNdx = Int(try reader.readUInt16())

        let architecture: CPUArchitecture
        switch eMachine {
        case emAArch64: architecture = .arm64
        case emX86_64:  architecture = .x86_64
        case emRISCV:   architecture = .riscv64
        default:        architecture = .unknown(cpuType: Int32(eMachine), cpuSubType: 0)
        }

        // Parse Program Headers
        var programHeaders: [RawProgramHeader] = []
        if ePhNum > 0 && ePhEntSize >= 56 && ePhOff <= UInt64(data.count) {
            let maxPh = min(ePhNum, (data.count - Int(ePhOff)) / ePhEntSize)
            for idx in 0..<maxPh {
                var phReader = try reader.subreader(
                    offset: Int(ePhOff) + idx * ePhEntSize,
                    length: ePhEntSize,
                    endianness: endianness
                )
                let pType = try phReader.readUInt32()
                let pFlags = try phReader.readUInt32()
                let pOffset = try phReader.readUInt64()
                let pVAddr = try phReader.readUInt64()
                _ = try phReader.readUInt64() // p_paddr
                let pFileSz = try phReader.readUInt64()
                let pMemSz = try phReader.readUInt64()
                programHeaders.append(
                    RawProgramHeader(
                        pType: pType,
                        pFlags: pFlags,
                        pOffset: pOffset,
                        pVAddr: pVAddr,
                        pFileSz: pFileSz,
                        pMemSz: pMemSz
                    )
                )
            }
        }

        // Parse Section Headers
        var rawSections: [RawSectionHeader] = []
        if eShNum > 0 && eShEntSize >= 64 && eShOff <= UInt64(data.count) {
            let maxSh = min(eShNum, (data.count - Int(eShOff)) / eShEntSize)
            for idx in 0..<maxSh {
                var shReader = try reader.subreader(
                    offset: Int(eShOff) + idx * eShEntSize,
                    length: eShEntSize,
                    endianness: endianness
                )
                let shNameOff = Int(try shReader.readUInt32())
                let shType = try shReader.readUInt32()
                let shFlags = try shReader.readUInt64()
                let shAddr = try shReader.readUInt64()
                let shOffset = try shReader.readUInt64()
                let shSize = try shReader.readUInt64()
                let shLink = try shReader.readUInt32()
                let shInfo = try shReader.readUInt32()
                let shAddrAlign = try shReader.readUInt64()
                let shEntSize = try shReader.readUInt64()
                rawSections.append(
                    RawSectionHeader(
                        nameOffset: shNameOff,
                        name: "",
                        shType: shType,
                        shFlags: shFlags,
                        shAddr: shAddr,
                        shOffset: shOffset,
                        shSize: shSize,
                        shLink: shLink,
                        shInfo: shInfo,
                        shAddrAlign: shAddrAlign,
                        shEntSize: shEntSize
                    )
                )
            }
        }

        // Resolve section names from .shstrtab
        if eShStrNdx >= 0 && eShStrNdx < rawSections.count {
            let shstr = rawSections[eShStrNdx]
            if shstr.shOffset < UInt64(data.count) {
                let len = min(Int(shstr.shSize), data.count - Int(shstr.shOffset))
                if let strReader = try? reader.subreader(offset: Int(shstr.shOffset), length: max(0, len), endianness: endianness) {
                    for idx in rawSections.indices {
                        let nameOff = rawSections[idx].nameOffset
                        rawSections[idx].name = strReader.peekNullTerminatedUTF8(at: nameOff, maxBytes: 256) ?? ""
                    }
                }
            }
        }

        // Build BinarySection list (skipping SHT_NULL index 0)
        var sections: [BinarySection] = []
        var elfIndexToModelIndex: [Int: Int] = [:]
        var buildIDUUID: String?

        for (elfIdx, sh) in rawSections.enumerated() where elfIdx > 0 {
            var perms: MemoryPermissions = [.read]
            if (sh.shFlags & shfWrite) != 0 { perms.insert(.write) }
            if (sh.shFlags & shfExecInstr) != 0 { perms.insert(.execute) }

            let kind = classifyELFSection(name: sh.name, shType: sh.shType, perms: perms)
            let entropy: Double
            if sh.shType != shtNobits && sh.shSize > 0 && sh.shOffset + sh.shSize <= UInt64(data.count) {
                entropy = StringAndEntropyScanner.sectionEntropy(
                    sliceData: data,
                    offset: Int(sh.shOffset),
                    size: Int(sh.shSize)
                )
            } else {
                entropy = 0.0
            }

            if sh.shType == shtNote && sh.name.contains("build-id") && sh.shOffset + sh.shSize <= UInt64(data.count) {
                buildIDUUID = parseGNUBuildID(data: data, offset: Int(sh.shOffset), size: Int(sh.shSize), endianness: endianness)
            }

            let modelIndex = sections.count
            elfIndexToModelIndex[elfIdx] = modelIndex
            sections.append(
                BinarySection(
                    index: modelIndex,
                    segmentName: "",
                    sectionName: sh.name.isEmpty ? "sec_\(elfIdx)" : sh.name,
                    vmAddress: VirtualAddress(sh.shAddr),
                    size: sh.shSize,
                    fileOffset: FileOffset(sh.shOffset),
                    alignment: UInt32(clamping: max(1, sh.shAddrAlign)),
                    flags: UInt32(truncatingIfNeeded: sh.shFlags),
                    kind: kind,
                    permissions: perms,
                    shannonEntropy: entropy
                )
            )
        }

        // Build BinarySegment list from PT_LOAD headers (or synthesize from sections for ET_REL)
        var segments: [BinarySegment] = []
        let loadPHs = programHeaders.filter { $0.pType == ptLoad }
        if !loadPHs.isEmpty {
            for (loadIdx, ph) in loadPHs.enumerated() {
                var perms: MemoryPermissions = []
                if (ph.pFlags & pfR) != 0 { perms.insert(.read) }
                if (ph.pFlags & pfW) != 0 { perms.insert(.write) }
                if (ph.pFlags & pfX) != 0 { perms.insert(.execute) }

                let segRange = AddressRange(start: VirtualAddress(ph.pVAddr), size: max(ph.pMemSz, ph.pFileSz))
                let childSections = sections.filter { $0.vmAddress != .zero && segRange.contains($0.vmAddress) }
                segments.append(
                    BinarySegment(
                        name: "LOAD_\(loadIdx)",
                        vmAddress: VirtualAddress(ph.pVAddr),
                        vmSize: ph.pMemSz,
                        fileOffset: FileOffset(ph.pOffset),
                        fileSize: ph.pFileSz,
                        initialProtection: perms,
                        maxProtection: perms,
                        flags: ph.pFlags,
                        sections: childSections
                    )
                )
            }
        } else if !sections.isEmpty {
            segments.append(
                BinarySegment(
                    name: "ELF_SECTIONS",
                    vmAddress: sections.first?.vmAddress ?? .zero,
                    vmSize: UInt64(data.count),
                    fileOffset: .zero,
                    fileSize: UInt64(data.count),
                    initialProtection: [.read, .execute],
                    maxProtection: [.read, .write, .execute],
                    flags: 0,
                    sections: sections
                )
            )
        }

        let imageBase = segments.map(\.vmAddress).min() ?? .zero

        // Parse DT_NEEDED shared libraries from .dynamic or PT_DYNAMIC
        let importedLibraries = parseDynamicLibraries(
            data: data,
            endianness: endianness,
            rawSections: rawSections,
            programHeaders: programHeaders,
            segments: segments
        )

        // Parse .dynsym and .symtab symbol tables
        var symbols: [BinarySymbol] = []
        var dynSymNamesByIndex: [Int: String] = [:]

        for sh in rawSections where sh.shType == shtDynsym || sh.shType == shtSymtab {
            let linkIdx = Int(sh.shLink)
            guard linkIdx > 0 && linkIdx < rawSections.count else { continue }
            let strSec = rawSections[linkIdx]
            guard sh.shOffset + sh.shSize <= UInt64(data.count),
                  strSec.shOffset + strSec.shSize <= UInt64(data.count) else {
                continue
            }
            let entSize = sh.shEntSize >= 24 ? Int(sh.shEntSize) : 24
            let symCount = Int(sh.shSize) / entSize
            guard let strReader = try? reader.subreader(offset: Int(strSec.shOffset), length: Int(strSec.shSize), endianness: endianness),
                  var symReader = try? reader.subreader(offset: Int(sh.shOffset), length: Int(sh.shSize), endianness: endianness) else {
                continue
            }

            for symIdx in 0..<symCount {
                try? symReader.seek(to: symIdx * entSize)
                guard symReader.remaining >= 24 else { break }
                let stName = Int(try symReader.readUInt32())
                let stInfo = try symReader.readUInt8()
                _ = try symReader.readUInt8() // st_other
                let stShndx = try symReader.readUInt16()
                let stValue = try symReader.readUInt64()
                let stSize = try symReader.readUInt64()

                let name = stName > 0 ? (strReader.peekNullTerminatedUTF8(at: stName, maxBytes: 2048) ?? "") : ""
                if sh.shType == shtDynsym {
                    dynSymNamesByIndex[symIdx] = name
                }
                guard !name.isEmpty, stShndx != 0, stValue != 0 else { continue }

                let bindCode = stInfo >> 4
                let typeCode = stInfo & 0x0F
                let binding: SymbolBinding
                switch bindCode {
                case 0: binding = .local
                case 2: binding = .weak
                default: binding = .global
                }

                let mappedSecIdx = elfIndexToModelIndex[Int(stShndx)]
                let kind: SymbolKind
                if stValue == eEntry {
                    kind = .exportedEntry
                } else if typeCode == 2 { // STT_FUNC
                    kind = .function
                } else if typeCode == 1 { // STT_OBJECT
                    kind = .globalVariable
                } else {
                    kind = binding == .local ? .localSymbol : .function
                }

                symbols.append(
                    BinarySymbol(
                        name: name,
                        demangledName: MachOSymbolDemangler.demangle(name),
                        kind: kind,
                        binding: binding,
                        address: VirtualAddress(stValue),
                        size: stSize,
                        sectionIndex: mappedSecIdx
                    )
                )
            }
        }

        // Parse .rela.plt / .rela.dyn to emit ChainedFixupRecords and synthesize PLT import stubs
        var fixups: [ChainedFixupRecord] = []
        let pltSection = sections.first { $0.sectionName == ".plt" || $0.sectionName == ".plt.sec" }

        for sh in rawSections where sh.shType == shtRela && sh.shOffset + sh.shSize <= UInt64(data.count) {
            let entSize = sh.shEntSize >= 24 ? Int(sh.shEntSize) : 24
            let relCount = Int(sh.shSize) / entSize
            guard var relReader = try? reader.subreader(offset: Int(sh.shOffset), length: Int(sh.shSize), endianness: endianness) else {
                continue
            }
            let isPLTRela = sh.name.contains("plt")

            for relIdx in 0..<relCount {
                try? relReader.seek(to: relIdx * entSize)
                guard relReader.remaining >= 24 else { break }
                let rOffset = try relReader.readUInt64()
                let rInfo = try relReader.readUInt64()
                let rAddend = try relReader.readInt64()

                let symIdx = Int(rInfo >> 32)
                let relType = UInt32(truncatingIfNeeded: rInfo)
                let locVA = VirtualAddress(rOffset)
                let fileOff = translateELFVA(locVA, segments: segments) ?? .zero

                if relType == rAArch64JumpSlot || relType == rX86_64JumpSlot
                    || relType == rAArch64GlobDat || relType == rX86_64GlobDat {
                    let symName = dynSymNamesByIndex[symIdx] ?? "plt_sym_\(symIdx)"
                    fixups.append(
                        ChainedFixupRecord(
                            location: locVA,
                            fileOffset: fileOff,
                            kind: .bind,
                            symbolName: symName,
                            addend: rAddend
                        )
                    )
                    if isPLTRela, let plt = pltSection {
                        let headerBytes: UInt64 = architecture == .arm64 ? 32 : 16
                        let stubVA = plt.vmAddress.adding(headerBytes + UInt64(relIdx * 16))
                        if plt.addressRange.contains(stubVA) {
                            symbols.append(
                                BinarySymbol(
                                    name: symName,
                                    demangledName: MachOSymbolDemangler.demangle(symName),
                                    kind: .importedStub,
                                    binding: .external,
                                    address: stubVA,
                                    size: 16,
                                    sectionIndex: plt.index
                                )
                            )
                        }
                    }
                } else if relType == rAArch64Relative || relType == rX86_64Relative {
                    fixups.append(
                        ChainedFixupRecord(
                            location: locVA,
                            fileOffset: fileOff,
                            kind: .rebase,
                            targetAddress: VirtualAddress(UInt64(bitPattern: rAddend)),
                            addend: rAddend
                        )
                    )
                }
            }
        }

        let entryPoint: VirtualAddress? = eEntry != 0 ? VirtualAddress(eEntry) : nil
        if let entry = entryPoint, !symbols.contains(where: { $0.address == entry }) {
            let secIdx = sections.firstIndex { $0.addressRange.contains(entry) }
            symbols.append(
                BinarySymbol(
                    name: "_start",
                    demangledName: "_start",
                    kind: .exportedEntry,
                    binding: .global,
                    address: entry,
                    size: 0,
                    sectionIndex: secIdx
                )
            )
        }

        // Deduplicate & sort symbols
        var uniqueByAddr: [VirtualAddress: BinarySymbol] = [:]
        for s in symbols {
            if let existing = uniqueByAddr[s.address] {
                if s.kind == .importedStub || (existing.size == 0 && s.size > 0) {
                    uniqueByAddr[s.address] = s
                }
            } else {
                uniqueByAddr[s.address] = s
            }
        }
        let sortedSymbols = uniqueByAddr.values.sorted { $0.address < $1.address }
        let fnStarts = sortedSymbols
            .filter { $0.kind == .function || $0.kind == .exportedEntry }
            .map(\.address)

        let strings = StringAndEntropyScanner.extractStrings(
            sliceData: data,
            sliceFileOffset: .zero,
            sections: sections,
            minLength: 4
        )
        let entropy = StringAndEntropyScanner.overallEntropy(of: data)

        return LoadedBinaryImage(
            fileName: fileName,
            filePath: filePath,
            fileSize: UInt64(data.count),
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: data),
            containerFormat: .elf64,
            selectedSliceIndex: 0,
            slices: [
                UniversalArchSlice(
                    index: 0,
                    architecture: architecture,
                    cpuType: Int32(eMachine),
                    cpuSubType: 0,
                    fileOffset: .zero,
                    size: UInt64(data.count),
                    alignExponent: 12
                )
            ],
            sliceFileOffset: .zero,
            architecture: architecture,
            endianness: endianness,
            isPositionIndependent: eType == etDyn,
            imageBase: imageBase,
            entryPoint: entryPoint,
            uuidString: buildIDUUID,
            platformName: platformName,
            minOSVersion: "0.0",
            sdkVersion: "0.0",
            functionStarts: fnStarts,
            segments: segments,
            sections: sections,
            importedLibraries: importedLibraries,
            symbols: sortedSymbols,
            strings: strings,
            chainedFixups: fixups,
            codeSignature: .unsigned,
            objcClasses: [],
            swiftTypes: [],
            overallEntropy: entropy
        )
    }

    private static func classifyELFSection(name: String, shType: UInt32, perms: MemoryPermissions) -> BinarySectionKind {
        let lower = name.lowercased()
        if shType == shtNobits || lower == ".bss" || lower == ".tbss" {
            return .bss
        }
        if lower == ".plt" || lower.hasPrefix(".plt.") {
            return .stubs
        }
        if lower == ".got" || lower == ".got.plt" {
            return .got
        }
        if lower == ".rodata" || lower.hasPrefix(".rodata.") {
            return lower.contains("str") ? .cstring : .constData
        }
        if lower == ".eh_frame" || lower == ".eh_frame_hdr" || lower == ".gcc_except_table" {
            return .unwindInfo
        }
        if lower.hasPrefix(".debug") || lower == ".symtab" || lower == ".strtab" || lower == ".shstrtab" {
            return .debug
        }
        if perms.contains(.execute) || lower == ".text" || lower == ".init" || lower == ".fini" {
            return .code
        }
        if perms.contains(.write) || lower == ".data" || lower == ".data.rel.ro" {
            return .mutableData
        }
        return .other
    }

    private static func translateELFVA(_ va: VirtualAddress, segments: [BinarySegment]) -> FileOffset? {
        for seg in segments where seg.fileSize > 0 {
            let range = AddressRange(start: seg.vmAddress, size: min(seg.vmSize, seg.fileSize))
            if range.contains(va) {
                return seg.fileOffset.adding(va.rawValue - seg.vmAddress.rawValue)
            }
        }
        return nil
    }

    private static func parseGNUBuildID(data: Data, offset: Int, size: Int, endianness: BinaryEndianness) -> String? {
        guard var r = try? BinarySliceReader(data: data, offset: offset, length: size, endianness: endianness),
              r.remaining >= 12 else { return nil }
        let nameSz = Int((try? r.readUInt32()) ?? 0)
        let descSz = Int((try? r.readUInt32()) ?? 0)
        let noteType = (try? r.readUInt32()) ?? 0
        let alignedName = (nameSz + 3) & ~3
        guard noteType == 3, descSz > 0, r.remaining >= alignedName + descSz else { return nil }
        try? r.skip(alignedName)
        guard let bytes = try? r.readBytes(descSz) else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func parseDynamicLibraries(
        data: Data,
        endianness: BinaryEndianness,
        rawSections: [RawSectionHeader],
        programHeaders: [RawProgramHeader],
        segments: [BinarySegment]
    ) -> [ImportedLibrary] {
        var dynOffset: Int?
        var dynSize: Int = 0
        var dynStrOffset: Int?
        var dynStrSize: Int = 0

        if let dynSec = rawSections.first(where: { $0.shType == shtDynamic || $0.name == ".dynamic" }) {
            dynOffset = Int(dynSec.shOffset)
            dynSize = Int(dynSec.shSize)
            let link = Int(dynSec.shLink)
            if link > 0 && link < rawSections.count {
                dynStrOffset = Int(rawSections[link].shOffset)
                dynStrSize = Int(rawSections[link].shSize)
            }
        } else if let dynPH = programHeaders.first(where: { $0.pType == ptDynamic }) {
            dynOffset = Int(dynPH.pOffset)
            dynSize = Int(dynPH.pFileSz)
        }

        guard let activeDynOff = dynOffset,
              activeDynOff >= 0,
              dynSize >= 16,
              activeDynOff + dynSize <= data.count,
              var dynReader = try? BinarySliceReader(data: data, offset: activeDynOff, length: dynSize, endianness: endianness) else {
            return []
        }

        var neededOffsets: [Int] = []
        var strTabVA: UInt64?
        var strTabByteSize: UInt64 = 4096

        while dynReader.remaining >= 16 {
            let dTag = (try? dynReader.readInt64()) ?? dtNull
            let dVal = (try? dynReader.readUInt64()) ?? 0
            if dTag == dtNull { break }
            if dTag == dtNeeded {
                neededOffsets.append(Int(dVal))
            } else if dTag == dtStrTab {
                strTabVA = dVal
            } else if dTag == dtStrSz {
                strTabByteSize = dVal
            }
        }

        if dynStrOffset == nil, let va = strTabVA, let resolvedOff = translateELFVA(VirtualAddress(va), segments: segments) {
            dynStrOffset = Int(resolvedOff.rawValue)
            dynStrSize = Int(min(strTabByteSize, UInt64(max(0, data.count - Int(resolvedOff.rawValue)))))
        }

        guard let activeStrOff = dynStrOffset,
              activeStrOff >= 0,
              activeStrOff < data.count else {
            return []
        }

        let safeStrLen = min(dynStrSize > 0 ? dynStrSize : (data.count - activeStrOff), data.count - activeStrOff)
        guard let strReader = try? BinarySliceReader(data: data, offset: activeStrOff, length: safeStrLen, endianness: endianness) else {
            return []
        }

        var libraries: [ImportedLibrary] = []
        for (idx, nameOff) in neededOffsets.enumerated() {
            if let libName = strReader.peekNullTerminatedUTF8(at: nameOff, maxBytes: 512), !libName.isEmpty {
                libraries.append(ImportedLibrary(ordinal: idx + 1, installName: libName))
            }
        }
        return libraries
    }
}

// MARK: - PE32+ (64-Bit Windows Portable Executable — ARM64 / x86_64) Loader

public enum PE32PlusLoader {
    private static let mzMagic: UInt16                 = 0x5A4D
    private static let peSignature: UInt32             = 0x0000_4550
    private static let pe32PlusOptionalMagic: UInt16   = 0x020B

    private static let imageFileMachineAMD64: UInt16   = 0x8664
    private static let imageFileMachineARM64: UInt16   = 0xAA64
    private static let imageFileMachineRISCV64: UInt16 = 0x5064

    private static let dllCharDynamicBase: UInt16      = 0x0040

    private static let scnCntCode: UInt32              = 0x0000_0020
    private static let scnCntUninitData: UInt32        = 0x0000_0080
    private static let scnMemExecute: UInt32           = 0x2000_0000
    private static let scnMemRead: UInt32              = 0x4000_0000
    private static let scnMemWrite: UInt32             = 0x8000_0000

    private struct PESectionRecord: Sendable {
        let name: String
        let virtualSize: UInt32
        let virtualAddressRVA: UInt32
        let sizeOfRawData: UInt32
        let pointerToRawData: UInt32
        let characteristics: UInt32
    }

    public static func load(data: Data, fileName: String, filePath: String) throws -> LoadedBinaryImage {
        guard data.count >= 0x40 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 64, available: data.count)
        }
        var reader = BinarySliceReader(data: data, endianness: .little)
        let dosMagic = try reader.readUInt16()
        guard dosMagic == mzMagic else {
            throw MachGraphError.invalidMagic(expected: "0x5A4D (MZ)", actualHex: String(format: "0x%04X", dosMagic))
        }

        try reader.seek(to: 0x3C)
        let eLfanew = Int(try reader.readUInt32())
        guard eLfanew >= 0 && eLfanew + 24 <= data.count else {
            throw MachGraphError.malformedHeader("PE e_lfanew offset (0x\(String(eLfanew, radix: 16))) out of bounds")
        }

        try reader.seek(to: eLfanew)
        let peSig = try reader.readUInt32()
        guard peSig == peSignature else {
            throw MachGraphError.invalidMagic(expected: "0x00004550 (PE\\0\\0)", actualHex: String(format: "0x%08X", peSig))
        }

        // 20-byte COFF IMAGE_FILE_HEADER
        let machine = try reader.readUInt16()
        let numberOfSections = Int(try reader.readUInt16())
        _ = try reader.readUInt32() // TimeDateStamp
        _ = try reader.readUInt32() // PointerToSymbolTable
        _ = try reader.readUInt32() // NumberOfSymbols
        let sizeOfOptionalHeader = Int(try reader.readUInt16())
        _ = try reader.readUInt16() // Characteristics

        let optHeaderStart = reader.position
        guard sizeOfOptionalHeader >= 112, optHeaderStart + sizeOfOptionalHeader <= data.count else {
            throw MachGraphError.malformedHeader("PE Optional Header truncated (\(sizeOfOptionalHeader) bytes)")
        }

        let optMagic = try reader.readUInt16()
        guard optMagic == pe32PlusOptionalMagic else {
            throw MachGraphError.unsupportedContainer(
                String(format: "Expected PE32+ optional magic 0x020B, got 0x%04X", optMagic)
            )
        }

        try reader.seek(to: optHeaderStart + 16)
        let addressOfEntryPointRVA = try reader.readUInt32()
        _ = try reader.readUInt32() // BaseOfCode
        let imageBaseRaw = try reader.readUInt64()
        let imageBase = VirtualAddress(imageBaseRaw)
        _ = try reader.readUInt32() // SectionAlignment
        _ = try reader.readUInt32() // FileAlignment
        let majorOS = try reader.readUInt16()
        let minorOS = try reader.readUInt16()
        _ = try reader.readUInt32() // ImageVersion
        let majorSubsys = try reader.readUInt16()
        let minorSubsys = try reader.readUInt16()

        try reader.seek(to: optHeaderStart + 70)
        let dllCharacteristics = try reader.readUInt16()

        try reader.seek(to: optHeaderStart + 108)
        let numberOfRvaAndSizes = Int(min(try reader.readUInt32(), 16))
        var dataDirectories: [(rva: UInt32, size: UInt32)] = []
        dataDirectories.reserveCapacity(numberOfRvaAndSizes)
        for _ in 0..<numberOfRvaAndSizes {
            if reader.position + 8 > optHeaderStart + sizeOfOptionalHeader { break }
            let dirRVA = try reader.readUInt32()
            let dirSize = try reader.readUInt32()
            dataDirectories.append((dirRVA, dirSize))
        }

        // Parse Section Table immediately following Optional Header
        let sectionTableStart = optHeaderStart + sizeOfOptionalHeader
        guard numberOfSections >= 0 && numberOfSections <= 128,
              sectionTableStart + numberOfSections * 40 <= data.count else {
            throw MachGraphError.malformedHeader("PE section table exceeds file bounds")
        }

        try reader.seek(to: sectionTableStart)
        var rawSections: [PESectionRecord] = []
        rawSections.reserveCapacity(numberOfSections)

        for _ in 0..<numberOfSections {
            let secName = try reader.readFixedASCII(8)
            let virtualSize = try reader.readUInt32()
            let virtualAddrRVA = try reader.readUInt32()
            let sizeOfRawData = try reader.readUInt32()
            let ptrToRawData = try reader.readUInt32()
            try reader.skip(12) // PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers
            let chars = try reader.readUInt32()
            rawSections.append(
                PESectionRecord(
                    name: secName,
                    virtualSize: virtualSize,
                    virtualAddressRVA: virtualAddrRVA,
                    sizeOfRawData: sizeOfRawData,
                    pointerToRawData: ptrToRawData,
                    characteristics: chars
                )
            )
        }

        func rvaToFileOffset(_ rva: UInt32) -> Int? {
            for sec in rawSections {
                let mappedSpan = max(sec.virtualSize, sec.sizeOfRawData)
                if rva >= sec.virtualAddressRVA && rva < (sec.virtualAddressRVA &+ mappedSpan) {
                    let delta = rva - sec.virtualAddressRVA
                    if delta < sec.sizeOfRawData {
                        let fileOff = Int(sec.pointerToRawData &+ delta)
                        if fileOff >= 0 && fileOff < data.count {
                            return fileOff
                        }
                    }
                }
            }
            if Int(rva) < sectionTableStart + numberOfSections * 40 && Int(rva) < data.count {
                return Int(rva)
            }
            return nil
        }

        var sections: [BinarySection] = []
        var segments: [BinarySegment] = []

        for (idx, rs) in rawSections.enumerated() {
            var perms: MemoryPermissions = []
            if (rs.characteristics & scnMemRead) != 0 { perms.insert(.read) }
            if (rs.characteristics & scnMemWrite) != 0 { perms.insert(.write) }
            if (rs.characteristics & scnMemExecute) != 0 { perms.insert(.execute) }
            if perms.isEmpty { perms = [.read] }

            let kind = classifyPESection(name: rs.name, characteristics: rs.characteristics, perms: perms)
            let vmSize = UInt64(max(rs.virtualSize, rs.sizeOfRawData))
            let secVA = imageBase.adding(UInt64(rs.virtualAddressRVA))

            let entropy: Double
            if kind != .bss && rs.sizeOfRawData > 0 && Int(rs.pointerToRawData) + Int(rs.sizeOfRawData) <= data.count {
                entropy = StringAndEntropyScanner.sectionEntropy(
                    sliceData: data,
                    offset: Int(rs.pointerToRawData),
                    size: Int(rs.sizeOfRawData)
                )
            } else {
                entropy = 0.0
            }

            let secModel = BinarySection(
                index: idx,
                segmentName: "",
                sectionName: rs.name.isEmpty ? "sec_\(idx)" : rs.name,
                vmAddress: secVA,
                size: vmSize,
                fileOffset: FileOffset(UInt64(rs.pointerToRawData)),
                alignment: 16,
                flags: rs.characteristics,
                kind: kind,
                permissions: perms,
                shannonEntropy: entropy
            )
            sections.append(secModel)
            segments.append(
                BinarySegment(
                    name: secModel.sectionName,
                    vmAddress: secVA,
                    vmSize: vmSize,
                    fileOffset: FileOffset(UInt64(rs.pointerToRawData)),
                    fileSize: UInt64(rs.sizeOfRawData),
                    initialProtection: perms,
                    maxProtection: perms,
                    flags: rs.characteristics,
                    sections: [secModel]
                )
            )
        }

        var importedLibraries: [ImportedLibrary] = []
        var symbols: [BinarySymbol] = []
        var fixups: [ChainedFixupRecord] = []
        var functionStarts: [VirtualAddress] = []

        // Parse Import Directory (DataDirectory[1])
        if dataDirectories.count > 1 && dataDirectories[1].rva != 0 && dataDirectories[1].size >= 20,
           let importDirFileOff = rvaToFileOffset(dataDirectories[1].rva) {
            var impCursor = importDirFileOff
            var dllOrdinal = 0

            while impCursor + 20 <= data.count && dllOrdinal < 512 {
                var descReader = try reader.subreader(offset: impCursor, length: 20, endianness: .little)
                let originalFirstThunkRVA = try descReader.readUInt32()
                _ = try descReader.readUInt32() // TimeDateStamp
                _ = try descReader.readUInt32() // ForwarderChain
                let dllNameRVA = try descReader.readUInt32()
                let firstThunkRVA = try descReader.readUInt32()
                impCursor += 20

                if originalFirstThunkRVA == 0 && dllNameRVA == 0 && firstThunkRVA == 0 {
                    break
                }

                let dllName: String
                if let nameOff = rvaToFileOffset(dllNameRVA) {
                    dllName = reader.peekNullTerminatedUTF8(at: nameOff, maxBytes: 256) ?? "unknown.dll"
                } else {
                    dllName = "unknown.dll"
                }

                dllOrdinal += 1
                importedLibraries.append(ImportedLibrary(ordinal: dllOrdinal, installName: dllName))

                let lookupTableRVA = originalFirstThunkRVA != 0 ? originalFirstThunkRVA : firstThunkRVA
                guard lookupTableRVA != 0, let thunkFileStart = rvaToFileOffset(lookupTableRVA) else {
                    continue
                }

                var slotIdx = 0
                while thunkFileStart + (slotIdx + 1) * 8 <= data.count && slotIdx < 4096 {
                    var thunkReader = try reader.subreader(offset: thunkFileStart + slotIdx * 8, length: 8, endianness: .little)
                    let thunkVal = try thunkReader.readUInt64()
                    if thunkVal == 0 { break }

                    let importedSymName: String
                    if (thunkVal & 0x8000_0000_0000_0000) != 0 {
                        let ord = thunkVal & 0xFFFF
                        importedSymName = "\(dllName)!Ordinal_\(ord)"
                    } else {
                        let hintNameRVA = UInt32(thunkVal & 0x7FFF_FFFF)
                        if let hnOff = rvaToFileOffset(hintNameRVA), hnOff + 2 < data.count {
                            importedSymName = reader.peekNullTerminatedUTF8(at: hnOff + 2, maxBytes: 512) ?? "imp_\(slotIdx)"
                        } else {
                            importedSymName = "imp_\(slotIdx)"
                        }
                    }

                    let iatRVA = (firstThunkRVA != 0 ? firstThunkRVA : lookupTableRVA) &+ UInt32(slotIdx * 8)
                    let iatVA = imageBase.adding(UInt64(iatRVA))
                    let iatFileOff = FileOffset(UInt64(rvaToFileOffset(iatRVA) ?? 0))
                    let secIdx = sections.firstIndex { $0.addressRange.contains(iatVA) }

                    symbols.append(
                        BinarySymbol(
                            name: importedSymName,
                            demangledName: importedSymName,
                            kind: .importedStub,
                            binding: .external,
                            address: iatVA,
                            size: 8,
                            sectionIndex: secIdx,
                            libraryOrdinal: dllOrdinal
                        )
                    )
                    fixups.append(
                        ChainedFixupRecord(
                            location: iatVA,
                            fileOffset: iatFileOff,
                            kind: .bind,
                            symbolName: importedSymName,
                            libraryOrdinal: dllOrdinal
                        )
                    )
                    slotIdx += 1
                }
            }
        }

        // Parse Export Directory (DataDirectory[0])
        if !dataDirectories.isEmpty && dataDirectories[0].rva != 0 && dataDirectories[0].size >= 40,
           let expFileOff = rvaToFileOffset(dataDirectories[0].rva),
           expFileOff + 40 <= data.count {
            var expReader = try reader.subreader(offset: expFileOff, length: 40, endianness: .little)
            try expReader.skip(16) // Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Name
            let ordinalBase = try expReader.readUInt32()
            let numFunctions = Int(min(try expReader.readUInt32(), 16_384))
            let numNames = Int(min(try expReader.readUInt32(), 16_384))
            let addrOfFunctionsRVA = try expReader.readUInt32()
            let addrOfNamesRVA = try expReader.readUInt32()
            let addrOfNameOrdinalsRVA = try expReader.readUInt32()

            var nameByFuncIndex: [Int: String] = [:]
            if numNames > 0,
               let namesOff = rvaToFileOffset(addrOfNamesRVA),
               let ordsOff = rvaToFileOffset(addrOfNameOrdinalsRVA) {
                for i in 0..<numNames {
                    guard namesOff + (i + 1) * 4 <= data.count,
                          ordsOff + (i + 1) * 2 <= data.count else { break }
                    var nr = try reader.subreader(offset: namesOff + i * 4, length: 4, endianness: .little)
                    var or = try reader.subreader(offset: ordsOff + i * 2, length: 2, endianness: .little)
                    let strRVA = try nr.readUInt32()
                    let funcIdx = Int(try or.readUInt16())
                    if let strOff = rvaToFileOffset(strRVA),
                       let expName = reader.peekNullTerminatedUTF8(at: strOff, maxBytes: 512),
                       !expName.isEmpty {
                        nameByFuncIndex[funcIdx] = expName
                    }
                }
            }

            if numFunctions > 0, let funcsOff = rvaToFileOffset(addrOfFunctionsRVA) {
                let expDirStart = dataDirectories[0].rva
                let expDirEnd = expDirStart &+ dataDirectories[0].size
                for fnIdx in 0..<numFunctions {
                    guard funcsOff + (fnIdx + 1) * 4 <= data.count else { break }
                    var fr = try reader.subreader(offset: funcsOff + fnIdx * 4, length: 4, endianness: .little)
                    let fnRVA = try fr.readUInt32()
                    if fnRVA == 0 { continue }
                    // Skip forwarded RVA strings pointing inside the export directory itself
                    if fnRVA >= expDirStart && fnRVA < expDirEnd { continue }

                    let fnVA = imageBase.adding(UInt64(fnRVA))
                    let symName = nameByFuncIndex[fnIdx] ?? "Ordinal_\(Int(ordinalBase) + fnIdx)"
                    let secIdx = sections.firstIndex { $0.addressRange.contains(fnVA) }
                    symbols.append(
                        BinarySymbol(
                            name: symName,
                            demangledName: symName,
                            kind: .exportedEntry,
                            binding: .global,
                            address: fnVA,
                            size: 0,
                            sectionIndex: secIdx
                        )
                    )
                    functionStarts.append(fnVA)
                }
            }
        }

        let architecture: CPUArchitecture
        switch machine {
        case imageFileMachineARM64:   architecture = .arm64
        case imageFileMachineAMD64:   architecture = .x86_64
        case imageFileMachineRISCV64: architecture = .riscv64
        default:                      architecture = .unknown(cpuType: Int32(machine), cpuSubType: 0)
        }

        // Parse .pdata Exception Table (DataDirectory[3]) for function start addresses
        if dataDirectories.count > 3 && dataDirectories[3].rva != 0 && dataDirectories[3].size >= 8,
           let pdataOff = rvaToFileOffset(dataDirectories[3].rva) {
            let entryStride = architecture == .arm64 ? 8 : 12
            let maxEntries = min(Int(dataDirectories[3].size) / entryStride, (data.count - pdataOff) / entryStride)
            for i in 0..<min(maxEntries, 16_384) {
                if var pr = try? reader.subreader(offset: pdataOff + i * entryStride, length: 4, endianness: .little),
                   let beginRVA = try? pr.readUInt32(),
                   beginRVA != 0 {
                    functionStarts.append(imageBase.adding(UInt64(beginRVA)))
                }
            }
        }

        let entryPoint: VirtualAddress? = addressOfEntryPointRVA != 0
            ? imageBase.adding(UInt64(addressOfEntryPointRVA))
            : nil
        if let entry = entryPoint {
            functionStarts.append(entry)
            if !symbols.contains(where: { $0.address == entry }) {
                let secIdx = sections.firstIndex { $0.addressRange.contains(entry) }
                symbols.append(
                    BinarySymbol(
                        name: "_EntryPoint",
                        demangledName: "EntryPoint",
                        kind: .exportedEntry,
                        binding: .global,
                        address: entry,
                        size: 0,
                        sectionIndex: secIdx
                    )
                )
            }
        }

        symbols.sort { $0.address < $1.address }
        let uniqueFnStarts = Array(Set(functionStarts)).sorted()
        let strings = StringAndEntropyScanner.extractStrings(
            sliceData: data,
            sliceFileOffset: .zero,
            sections: sections,
            minLength: 4
        )
        let overallEntropy = StringAndEntropyScanner.overallEntropy(of: data)

        return LoadedBinaryImage(
            fileName: fileName,
            filePath: filePath,
            fileSize: UInt64(data.count),
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: data),
            containerFormat: .pe32Plus,
            selectedSliceIndex: 0,
            slices: [
                UniversalArchSlice(
                    index: 0,
                    architecture: architecture,
                    cpuType: Int32(machine),
                    cpuSubType: 0,
                    fileOffset: .zero,
                    size: UInt64(data.count),
                    alignExponent: 12
                )
            ],
            sliceFileOffset: .zero,
            architecture: architecture,
            endianness: .little,
            isPositionIndependent: (dllCharacteristics & dllCharDynamicBase) != 0,
            imageBase: imageBase,
            entryPoint: entryPoint,
            uuidString: nil,
            platformName: "Windows PE32+",
            minOSVersion: "\(majorSubsys).\(minorSubsys)",
            sdkVersion: "\(majorOS).\(minorOS)",
            functionStarts: uniqueFnStarts,
            segments: segments,
            sections: sections,
            importedLibraries: importedLibraries,
            symbols: symbols,
            strings: strings,
            chainedFixups: fixups,
            codeSignature: .unsigned,
            objcClasses: [],
            swiftTypes: [],
            overallEntropy: overallEntropy
        )
    }

    private static func classifyPESection(name: String, characteristics: UInt32, perms: MemoryPermissions) -> BinarySectionKind {
        let lower = name.lowercased()
        if (characteristics & scnCntUninitData) != 0 || lower == ".bss" {
            return .bss
        }
        if lower == ".pdata" || lower == ".xdata" {
            return .unwindInfo
        }
        if lower == ".idata" {
            return .got
        }
        if (characteristics & scnCntCode) != 0 || perms.contains(.execute) || lower == ".text" {
            return .code
        }
        if lower == ".rdata" || !perms.contains(.write) {
            return .constData
        }
        if perms.contains(.write) || lower == ".data" {
            return .mutableData
        }
        return .other
    }
}

// MARK: - WebAssembly 1.0 (.wasm) Binary Module Loader

public enum WasmModuleLoader {
    public static let wasmSyntheticBaseAddress = VirtualAddress(0x1000_0000)

    private struct WasmFuncSignature: Sendable {
        let params: [String]
        let results: [String]

        var displayText: String {
            let p = params.joined(separator: ", ")
            let r = results.isEmpty ? "void" : results.joined(separator: ", ")
            return "(\(p)) -> \(r)"
        }
    }

    public static func load(data: Data, fileName: String, filePath: String) throws -> LoadedBinaryImage {
        guard data.count >= 8 else {
            throw MachGraphError.unexpectedEOF(offset: 0, requested: 8, available: data.count)
        }
        var reader = BinarySliceReader(data: data, endianness: .little)
        let magic = try reader.readBytes(4)
        guard magic == [0x00, 0x61, 0x73, 0x6D] else {
            throw MachGraphError.invalidMagic(expected: "\\0asm (0x0061736D)", actualHex: "unknown")
        }
        let version = try reader.readUInt32()
        guard version == 1 else {
            throw MachGraphError.unsupportedContainer("Unsupported WebAssembly binary version \(version) (expected 1)")
        }

        var sections: [BinarySection] = []
        var signatures: [WasmFuncSignature] = []
        var importedModulesOrdered: [String] = []
        var importedFunctions: [(module: String, field: String, typeIdx: Int, declFileOffset: Int)] = []
        var localFuncTypeIndices: [Int] = []
        var exportedFuncNames: [Int: [String]] = [:]
        var customFuncNames: [Int: String] = [:]
        var startFuncIndex: Int?
        var codeBodies: [(fileOffset: Int, byteSize: Int)] = []

        while !reader.isAtEnd {
            let secID = try reader.readUInt8()
            let payloadLen = Int(try reader.readULEB128())
            let payloadFileOffset = reader.position
            guard payloadLen >= 0 && payloadFileOffset + payloadLen <= data.count else {
                throw MachGraphError.malformedHeader("Wasm section id=\(secID) payload (\(payloadLen)) exceeds module bounds")
            }

            var secReader = try reader.subreader(offset: payloadFileOffset, length: payloadLen, endianness: .little)
            try reader.skip(payloadLen)

            var customNameLabel = ""
            if secID == 0 && !secReader.isAtEnd {
                let nameLen = Int((try? secReader.readULEB128()) ?? 0)
                if nameLen > 0 && secReader.remaining >= nameLen,
                   let nameBytes = try? secReader.readBytes(nameLen) {
                    customNameLabel = String(decoding: nameBytes, as: UTF8.self)
                    if customNameLabel == "name" {
                        parseWasmCustomNameSection(reader: &secReader, into: &customFuncNames)
                    }
                }
            }

            let (sectionTitle, sectionKind, sectionPerms) = describeWasmSection(id: secID, customName: customNameLabel)
            let secEntropy = payloadLen > 0
                ? StringAndEntropyScanner.sectionEntropy(sliceData: data, offset: payloadFileOffset, size: payloadLen)
                : 0.0

            let secModel = BinarySection(
                index: sections.count,
                segmentName: "WASM",
                sectionName: sectionTitle,
                vmAddress: wasmSyntheticBaseAddress.adding(UInt64(payloadFileOffset)),
                size: UInt64(payloadLen),
                fileOffset: FileOffset(UInt64(payloadFileOffset)),
                alignment: 1,
                flags: UInt32(secID),
                kind: sectionKind,
                permissions: sectionPerms,
                shannonEntropy: secEntropy
            )
            sections.append(secModel)

            // Decode section contents
            switch secID {
            case 1: // Type Section
                let count = Int((try? secReader.readULEB128()) ?? 0)
                for _ in 0..<min(count, 4096) {
                    guard let form = try? secReader.readUInt8(), form == 0x60 else { break }
                    let paramCount = Int((try? secReader.readULEB128()) ?? 0)
                    var params: [String] = []
                    for _ in 0..<min(paramCount, 64) {
                        if let vt = try? secReader.readUInt8() {
                            params.append(wasmValTypeName(vt))
                        }
                    }
                    let resCount = Int((try? secReader.readULEB128()) ?? 0)
                    var results: [String] = []
                    for _ in 0..<min(resCount, 64) {
                        if let vt = try? secReader.readUInt8() {
                            results.append(wasmValTypeName(vt))
                        }
                    }
                    signatures.append(WasmFuncSignature(params: params, results: results))
                }

            case 2: // Import Section
                let count = Int((try? secReader.readULEB128()) ?? 0)
                for _ in 0..<min(count, 4096) {
                    let declOff = payloadFileOffset + secReader.position
                    guard let modName = readWasmUTF8(&secReader),
                          let fieldName = readWasmUTF8(&secReader),
                          let kind = try? secReader.readUInt8() else { break }

                    if !importedModulesOrdered.contains(modName) {
                        importedModulesOrdered.append(modName)
                    }

                    switch kind {
                    case 0: // func
                        let sigIdx = Int((try? secReader.readULEB128()) ?? 0)
                        importedFunctions.append((modName, fieldName, sigIdx, declOff))
                    case 1: // table
                        _ = try? secReader.readUInt8() // elemtype
                        skipWasmLimits(&secReader)
                    case 2: // memory
                        skipWasmLimits(&secReader)
                    case 3: // global
                        _ = try? secReader.readUInt8() // valtype
                        _ = try? secReader.readUInt8() // mutability
                    default:
                        break
                    }
                }

            case 3: // Function Section
                let count = Int((try? secReader.readULEB128()) ?? 0)
                for _ in 0..<min(count, 16_384) {
                    if let typeIdx = try? secReader.readULEB128() {
                        localFuncTypeIndices.append(Int(typeIdx))
                    }
                }

            case 7: // Export Section
                let count = Int((try? secReader.readULEB128()) ?? 0)
                for _ in 0..<min(count, 8192) {
                    guard let expName = readWasmUTF8(&secReader),
                          let expKind = try? secReader.readUInt8(),
                          let itemIdx = try? secReader.readULEB128() else { break }
                    if expKind == 0 {
                        exportedFuncNames[Int(itemIdx), default: []].append(expName)
                    }
                }

            case 8: // Start Section
                if let startIdx = try? secReader.readULEB128() {
                    startFuncIndex = Int(startIdx)
                }

            case 10: // Code Section
                let bodyCount = Int((try? secReader.readULEB128()) ?? 0)
                for _ in 0..<min(bodyCount, 16_384) {
                    guard let bodySize = try? secReader.readULEB128() else { break }
                    let bodyLen = Int(bodySize)
                    let bodyAbsOffset = payloadFileOffset + secReader.position
                    guard bodyLen >= 0 && secReader.remaining >= bodyLen else { break }
                    codeBodies.append((bodyAbsOffset, bodyLen))
                    try? secReader.skip(bodyLen)
                }

            default:
                break
            }
        }

        let importedLibraries = importedModulesOrdered.enumerated().map { idx, mod in
            ImportedLibrary(ordinal: idx + 1, installName: mod, currentVersion: "1.0")
        }

        // Synthesize symbols for imported functions and local code functions
        var symbols: [BinarySymbol] = []
        var functionStarts: [VirtualAddress] = []
        let importSecIdx = sections.firstIndex { $0.sectionName == "Import" }
        let codeSecIdx = sections.firstIndex { $0.sectionName == "Code" }

        for (impIdx, imp) in importedFunctions.enumerated() {
            let ord = (importedModulesOrdered.firstIndex(of: imp.module) ?? 0) + 1
            let sigText = imp.typeIdx < signatures.count ? " " + signatures[imp.typeIdx].displayText : ""
            let rawName = "\(imp.module).\(imp.field)"
            let va = wasmSyntheticBaseAddress.adding(UInt64(imp.declFileOffset))
            symbols.append(
                BinarySymbol(
                    name: rawName,
                    demangledName: "\(customFuncNames[impIdx] ?? rawName)\(sigText)",
                    kind: .importedStub,
                    binding: .external,
                    address: va,
                    size: 0,
                    sectionIndex: importSecIdx,
                    libraryOrdinal: ord
                )
            )
        }

        let importedFuncCount = importedFunctions.count
        var resolvedEntryPoint: VirtualAddress?

        for (localIdx, body) in codeBodies.enumerated() {
            let globalFuncIdx = importedFuncCount + localIdx
            let funcVA = wasmSyntheticBaseAddress.adding(UInt64(body.fileOffset))
            functionStarts.append(funcVA)

            let exports = exportedFuncNames[globalFuncIdx] ?? []
            let customName = customFuncNames[globalFuncIdx]
            let primaryName = exports.first ?? customName ?? "wasm_func_\(globalFuncIdx)"

            let sigIdx = localIdx < localFuncTypeIndices.count ? localFuncTypeIndices[localIdx] : -1
            let sigSuffix = (sigIdx >= 0 && sigIdx < signatures.count) ? " " + signatures[sigIdx].displayText : ""
            let isExported = !exports.isEmpty || startFuncIndex == globalFuncIdx

            if startFuncIndex == globalFuncIdx {
                resolvedEntryPoint = funcVA
            } else if resolvedEntryPoint == nil && (exports.contains("_start") || exports.contains("main")) {
                resolvedEntryPoint = funcVA
            }

            symbols.append(
                BinarySymbol(
                    name: primaryName,
                    demangledName: "\(customName ?? primaryName)\(sigSuffix)",
                    kind: isExported ? .exportedEntry : .function,
                    binding: isExported ? .global : .local,
                    address: funcVA,
                    size: UInt64(body.byteSize),
                    sectionIndex: codeSecIdx
                )
            )
        }

        if resolvedEntryPoint == nil {
            resolvedEntryPoint = functionStarts.first
        }

        let moduleSegment = BinarySegment(
            name: "WASM_MODULE",
            vmAddress: wasmSyntheticBaseAddress,
            vmSize: UInt64(data.count),
            fileOffset: .zero,
            fileSize: UInt64(data.count),
            initialProtection: [.read, .execute],
            maxProtection: [.read, .write, .execute],
            flags: 0,
            sections: sections
        )

        let strings = StringAndEntropyScanner.extractStrings(
            sliceData: data,
            sliceFileOffset: .zero,
            sections: sections,
            minLength: 4
        )
        let overallEntropy = StringAndEntropyScanner.overallEntropy(of: data)

        return LoadedBinaryImage(
            fileName: fileName,
            filePath: filePath,
            fileSize: UInt64(data.count),
            sha256Hex: BinaryHashAndEntropy.sha256Hex(of: data),
            containerFormat: .wasm,
            selectedSliceIndex: 0,
            slices: [
                UniversalArchSlice(
                    index: 0,
                    architecture: .wasm32,
                    cpuType: 0,
                    cpuSubType: 0,
                    fileOffset: .zero,
                    size: UInt64(data.count),
                    alignExponent: 0
                )
            ],
            sliceFileOffset: .zero,
            architecture: .wasm32,
            endianness: .little,
            isPositionIndependent: true,
            imageBase: wasmSyntheticBaseAddress,
            entryPoint: resolvedEntryPoint,
            uuidString: nil,
            platformName: "WebAssembly 1.0",
            minOSVersion: "1.0",
            sdkVersion: "1.0",
            functionStarts: functionStarts,
            segments: [moduleSegment],
            sections: sections,
            importedLibraries: importedLibraries,
            symbols: symbols,
            strings: strings,
            chainedFixups: [],
            codeSignature: .unsigned,
            objcClasses: [],
            swiftTypes: [],
            overallEntropy: overallEntropy
        )
    }

    private static func wasmValTypeName(_ byte: UInt8) -> String {
        switch byte {
        case 0x7F: return "i32"
        case 0x7E: return "i64"
        case 0x7D: return "f32"
        case 0x7C: return "f64"
        case 0x7B: return "v128"
        case 0x70: return "funcref"
        case 0x6F: return "externref"
        default:   return String(format: "t0x%02x", byte)
        }
    }

    private static func readWasmUTF8(_ reader: inout BinarySliceReader) -> String? {
        guard let len = try? reader.readULEB128(),
              Int(len) <= reader.remaining,
              let bytes = try? reader.readBytes(Int(len)) else {
            return nil
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func skipWasmLimits(_ reader: inout BinarySliceReader) {
        guard let flags = try? reader.readUInt8() else { return }
        _ = try? reader.readULEB128() // min
        if (flags & 0x01) != 0 {
            _ = try? reader.readULEB128() // max
        }
    }

    private static func parseWasmCustomNameSection(
        reader: inout BinarySliceReader,
        into funcNames: inout [Int: String]
    ) {
        while !reader.isAtEnd {
            guard let subID = try? reader.readUInt8(),
                  let subSize = try? reader.readULEB128() else { break }
            let len = Int(subSize)
            guard len >= 0 && len <= reader.remaining else { break }

            if subID == 1 {
                // Function names map: vec(namemap)
                if var subReader = try? reader.subreader(offset: reader.position, length: len, endianness: .little) {
                    let count = Int((try? subReader.readULEB128()) ?? 0)
                    for _ in 0..<min(count, 16_384) {
                        guard let fnIdx = try? subReader.readULEB128(),
                              let fnName = readWasmUTF8(&subReader) else { break }
                        if !fnName.isEmpty {
                            funcNames[Int(fnIdx)] = fnName
                        }
                    }
                }
            }
            try? reader.skip(len)
        }
    }

    private static func describeWasmSection(id: UInt8, customName: String) -> (String, BinarySectionKind, MemoryPermissions) {
        switch id {
        case 0:
            let label = customName.isEmpty ? "Custom" : "Custom(\(customName))"
            return (label, .wasmCustom, [.read])
        case 1:  return ("Type", .constData, [.read])
        case 2:  return ("Import", .stubs, [.read])
        case 3:  return ("Function", .constData, [.read])
        case 4:  return ("Table", .got, [.read])
        case 5:  return ("Memory", .mutableData, [.read, .write])
        case 6:  return ("Global", .mutableData, [.read, .write])
        case 7:  return ("Export", .constData, [.read])
        case 8:  return ("Start", .constData, [.read])
        case 9:  return ("Element", .constData, [.read])
        case 10: return ("Code", .code, [.read, .execute])
        case 11: return ("Data", .cstring, [.read, .write])
        case 12: return ("DataCount", .constData, [.read])
        default: return ("Section_\(id)", .other, [.read])
        }
    }
}

// MARK: - Printable String, ObjC Selector & Entropy Scanner

public enum StringAndEntropyScanner {
    /// Scans data-bearing sections for ASCII/UTF-8 (`>= minLength`), UTF-16LE literals, and `__objc_methname` selectors.
    public static func extractStrings(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        sections: [BinarySection],
        minLength: Int = 4,
        maxTotalStrings: Int = 8_192
    ) -> [ExtractedStringLiteral] {
        var collected: [ExtractedStringLiteral] = []
        var seenAddresses = Set<VirtualAddress>()

        // Candidate sections: string sections, ObjC selector/class strings, read-only data, mutable data, Wasm Data, or raw blobs
        let candidateSections = sections.filter { sec in
            guard sec.size > 0 && sec.kind != .bss && sec.kind != .stubs && sec.kind != .got && sec.kind != .unwindInfo else {
                return false
            }
            if sec.kind == .code {
                // Only scan raw firmware code blobs if there are no dedicated data/string sections
                return sections.count == 1
            }
            return true
        }

        for sec in candidateSections {
            if collected.count >= maxTotalStrings { break }
            let secStart = Int(sec.fileOffset.rawValue)
            guard secStart >= 0 && secStart < sliceData.count else { continue }
            let clampedLen = min(Int(sec.size), sliceData.count - secStart, 1_048_576)
            guard clampedLen >= 2 else { continue }

            let bytes = Array(sliceData[(sliceData.startIndex + secStart)..<(sliceData.startIndex + secStart + clampedLen)])
            let isObjCMethName = (sec.sectionName == "__objc_methname")
            let isUTF16Section = (sec.sectionName == "__ustring")
            let secLabel = sec.fullName

            if !isUTF16Section {
                scanASCIIAndUTF8(
                    bytes: bytes,
                    section: sec,
                    sectionLabel: secLabel,
                    sliceFileOffset: sliceFileOffset,
                    minLength: isObjCMethName ? max(2, minLength - 1) : minLength,
                    forceObjCSelector: isObjCMethName,
                    maxRemaining: maxTotalStrings - collected.count,
                    seenAddresses: &seenAddresses,
                    into: &collected
                )
            }

            if collected.count < maxTotalStrings && (isUTF16Section || sec.kind == .constData || sec.kind == .cstring || sec.kind == .mutableData) {
                scanUTF16LE(
                    bytes: bytes,
                    section: sec,
                    sectionLabel: secLabel,
                    sliceFileOffset: sliceFileOffset,
                    minLength: minLength,
                    maxRemaining: maxTotalStrings - collected.count,
                    seenAddresses: &seenAddresses,
                    into: &collected
                )
            }
        }

        collected.sort { $0.address < $1.address }
        return collected
    }

    private static func scanASCIIAndUTF8(
        bytes: [UInt8],
        section: BinarySection,
        sectionLabel: String,
        sliceFileOffset: FileOffset,
        minLength: Int,
        forceObjCSelector: Bool,
        maxRemaining: Int,
        seenAddresses: inout Set<VirtualAddress>,
        into output: inout [ExtractedStringLiteral]
    ) {
        var idx = 0
        let n = bytes.count
        var added = 0

        while idx < n && added < maxRemaining {
            let startIdx = idx
            var runBytes: [UInt8] = []
            var sawMultibyteUTF8 = false

            while idx < n && runBytes.count < 1024 {
                let b = bytes[idx]
                if b == 0 {
                    break
                } else if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
                    runBytes.append(b)
                    idx += 1
                } else if b >= 0xC2 && b <= 0xDF && idx + 1 < n && (bytes[idx + 1] & 0xC0) == 0x80 {
                    runBytes.append(b)
                    runBytes.append(bytes[idx + 1])
                    sawMultibyteUTF8 = true
                    idx += 2
                } else if b >= 0xE0 && b <= 0xEF && idx + 2 < n
                            && (bytes[idx + 1] & 0xC0) == 0x80
                            && (bytes[idx + 2] & 0xC0) == 0x80 {
                    runBytes.append(b)
                    runBytes.append(bytes[idx + 1])
                    runBytes.append(bytes[idx + 2])
                    sawMultibyteUTF8 = true
                    idx += 3
                } else if b >= 0xF0 && b <= 0xF4 && idx + 3 < n
                            && (bytes[idx + 1] & 0xC0) == 0x80
                            && (bytes[idx + 2] & 0xC0) == 0x80
                            && (bytes[idx + 3] & 0xC0) == 0x80 {
                    runBytes.append(b)
                    runBytes.append(bytes[idx + 1])
                    runBytes.append(bytes[idx + 2])
                    runBytes.append(bytes[idx + 3])
                    sawMultibyteUTF8 = true
                    idx += 4
                } else {
                    break
                }
            }

            let nullTerminated = (idx < n && bytes[idx] == 0)
            // For non-string sections, require null-termination to suppress random pointer noise
            let acceptRun = forceObjCSelector || section.kind == .cstring || nullTerminated

            if acceptRun && runBytes.count >= minLength,
               let decoded = String(bytes: runBytes, encoding: .utf8) {
                let trimmedCheck = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmedCheck.count >= minLength {
                    let va = section.vmAddress.adding(UInt64(startIdx))
                    if seenAddresses.insert(va).inserted {
                        let absOff = sliceFileOffset.adding(section.fileOffset.rawValue &+ UInt64(startIdx))
                        let enc: ExtractedStringEncoding
                        if forceObjCSelector {
                            enc = .objcSelector
                        } else if sawMultibyteUTF8 {
                            enc = .utf8
                        } else {
                            enc = .ascii
                        }
                        output.append(
                            ExtractedStringLiteral(
                                address: va,
                                fileOffset: absOff,
                                encoding: enc,
                                value: decoded,
                                sectionName: sectionLabel,
                                lengthBytes: runBytes.count
                            )
                        )
                        added += 1
                    }
                }
            }

            idx = max(idx + 1, startIdx + 1)
        }
    }

    private static func scanUTF16LE(
        bytes: [UInt8],
        section: BinarySection,
        sectionLabel: String,
        sliceFileOffset: FileOffset,
        minLength: Int,
        maxRemaining: Int,
        seenAddresses: inout Set<VirtualAddress>,
        into output: inout [ExtractedStringLiteral]
    ) {
        var idx = 0
        let n = bytes.count
        var added = 0

        while idx + 1 < n && added < maxRemaining {
            let startIdx = idx
            var units: [UInt16] = []
            var asciiHighZeroCount = 0

            while idx + 1 < n && units.count < 512 {
                let lo = bytes[idx]
                let hi = bytes[idx + 1]
                let unit = UInt16(lo) | (UInt16(hi) << 8)
                if unit == 0 {
                    break
                }
                if (hi == 0 && ((lo >= 0x20 && lo <= 0x7E) || lo == 0x09 || lo == 0x0A)) {
                    units.append(unit)
                    asciiHighZeroCount += 1
                    idx += 2
                } else if unit >= 0x00A0 && unit <= 0xD7FF && section.sectionName == "__ustring" {
                    units.append(unit)
                    idx += 2
                } else {
                    units.removeAll(keepingCapacity: true)
                    break
                }
            }

            let terminatedByDoubleNull = (idx + 1 < n && bytes[idx] == 0 && bytes[idx + 1] == 0)
            if units.count >= minLength && terminatedByDoubleNull && asciiHighZeroCount >= (units.count / 2) {
                let str = String(utf16CodeUnits: units, count: units.count)
                let va = section.vmAddress.adding(UInt64(startIdx))
                if seenAddresses.insert(va).inserted {
                    let absOff = sliceFileOffset.adding(section.fileOffset.rawValue &+ UInt64(startIdx))
                    output.append(
                        ExtractedStringLiteral(
                            address: va,
                            fileOffset: absOff,
                            encoding: .utf16LE,
                            value: str,
                            sectionName: sectionLabel,
                            lengthBytes: units.count * 2
                        )
                    )
                    added += 1
                }
                idx += 2
            } else {
                idx = startIdx + 2
            }
        }
    }

    /// Computes Shannon entropy in `[0.0, 8.0]` bits/byte for a slice subrange.
    public static func sectionEntropy(sliceData: Data, offset: Int, size: Int) -> Double {
        guard offset >= 0 && size > 0 && offset < sliceData.count else { return 0.0 }
        let clamped = min(size, sliceData.count - offset)
        let bytes = Array(sliceData[(sliceData.startIndex + offset)..<(sliceData.startIndex + offset + clamped)])
        return BinaryHashAndEntropy.shannonEntropy(of: bytes[...])
    }

    /// Computes whole-buffer Shannon entropy.
    public static func overallEntropy(of data: Data) -> Double {
        BinaryHashAndEntropy.shannonEntropy(of: data)
    }

    /// Computes fixed-window `EntropyRegionSample` slices across a loaded binary image for entropy heatmaps.
    public static func computeEntropySamples(
        data: Data,
        image: LoadedBinaryImage,
        windowSize: Int = 256
    ) -> [EntropyRegionSample] {
        let step = max(64, windowSize)
        guard !data.isEmpty else { return [] }
        let rawBytes = Array(data)
        var samples: [EntropyRegionSample] = []
        samples.reserveCapacity((rawBytes.count + step - 1) / step)

        var offset = 0
        while offset < rawBytes.count {
            let end = min(offset + step, rawBytes.count)
            let slice = rawBytes[offset..<end]
            let len = slice.count

            var zeroCount = 0
            var printableCount = 0
            for b in slice {
                if b == 0 { zeroCount += 1 }
                else if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D { printableCount += 1 }
            }

            let fileOff = FileOffset(UInt64(offset))
            let va = image.virtualAddress(for: fileOff)
            let secName = va.flatMap { image.section(containing: $0)?.fullName } ?? "Header / Unmapped"
            let entropy = BinaryHashAndEntropy.shannonEntropy(of: slice)

            samples.append(
                EntropyRegionSample(
                    fileOffset: fileOff,
                    virtualAddress: va,
                    length: len,
                    sectionName: secName,
                    entropyBitsPerByte: entropy,
                    zeroByteRatio: Double(zeroCount) / Double(len),
                    printableByteRatio: Double(printableCount) / Double(len)
                )
            )
            offset += step
        }

        return samples
    }
}
