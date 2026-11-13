import Foundation
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder

// MARK: - Function Discovery Provenance & Configuration Models

public enum FunctionDiscoverySource: String, Sendable, Codable, Hashable, CaseIterable, Comparable {
    case entryPoint = "Entry Point"
    case lcFunctionStarts = "LC_FUNCTION_STARTS"
    case symbolTable = "Symbol Table"
    case objcMethod = "ObjC Method IMP"
    case directCallTarget = "BL Call Target"
    case tailBranchTarget = "External Tail Jump"
    case stubSlot = "Import Stub Slot"
    case prologueHeuristic = "ARM64 Prologue Heuristic"
    case containerFallback = "Container Symbol Fallback"

    private var priorityRank: Int {
        switch self {
        case .entryPoint: return 90
        case .symbolTable: return 85
        case .objcMethod: return 82
        case .lcFunctionStarts: return 80
        case .stubSlot: return 75
        case .directCallTarget: return 70
        case .tailBranchTarget: return 55
        case .prologueHeuristic: return 40
        case .containerFallback: return 30
        }
    }

    public static func < (lhs: FunctionDiscoverySource, rhs: FunctionDiscoverySource) -> Bool {
        lhs.priorityRank < rhs.priorityRank
    }

    public var isAuthoritative: Bool {
        switch self {
        case .entryPoint, .lcFunctionStarts, .symbolTable, .objcMethod, .stubSlot, .directCallTarget:
            return true
        case .tailBranchTarget, .prologueHeuristic, .containerFallback:
            return false
        }
    }
}

public struct FunctionDiscoveryConfiguration: Sendable, Codable, Hashable {
    public var enablePrologueHeuristics: Bool
    public var enableDirectCallTargetDiscovery: Bool
    public var enableTailJumpSplitHeuristics: Bool
    public var enableStubSectionSegmentation: Bool
    public var maxJumpTableEntries: Int
    public var unboundedJumpTableFallbackLimit: Int
    public var trimTrailingZeroPadding: Bool

    public init(
        enablePrologueHeuristics: Bool = true,
        enableDirectCallTargetDiscovery: Bool = true,
        enableTailJumpSplitHeuristics: Bool = true,
        enableStubSectionSegmentation: Bool = true,
        maxJumpTableEntries: Int = 1024,
        unboundedJumpTableFallbackLimit: Int = 64,
        trimTrailingZeroPadding: Bool = true
    ) {
        self.enablePrologueHeuristics = enablePrologueHeuristics
        self.enableDirectCallTargetDiscovery = enableDirectCallTargetDiscovery
        self.enableTailJumpSplitHeuristics = enableTailJumpSplitHeuristics
        self.enableStubSectionSegmentation = enableStubSectionSegmentation
        self.maxJumpTableEntries = max(1, maxJumpTableEntries)
        self.unboundedJumpTableFallbackLimit = max(1, unboundedJumpTableFallbackLimit)
        self.trimTrailingZeroPadding = trimTrailingZeroPadding
    }

    public static let standard = FunctionDiscoveryConfiguration()
}

public struct DiscoveredFunctionBoundary: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { startAddress.rawValue }
    public let startAddress: VirtualAddress
    public let endAddress: VirtualAddress
    public let name: String
    public let demangledName: String
    public let sectionName: String
    public let isStubSection: Bool
    public let sources: [FunctionDiscoverySource]
    public let confidence: Double
    public let resolvedGOTTargetSymbol: String?

    public init(
        startAddress: VirtualAddress,
        endAddress: VirtualAddress,
        name: String,
        demangledName: String? = nil,
        sectionName: String,
        isStubSection: Bool = false,
        sources: [FunctionDiscoverySource],
        confidence: Double = 1.0,
        resolvedGOTTargetSymbol: String? = nil
    ) {
        self.startAddress = startAddress
        self.endAddress = endAddress
        self.name = name
        self.demangledName = demangledName ?? name
        self.sectionName = sectionName
        self.isStubSection = isStubSection
        self.sources = sources.sorted(by: >)
        self.confidence = min(1.0, max(0.0, confidence))
        self.resolvedGOTTargetSymbol = resolvedGOTTargetSymbol
    }

    public var byteSize: UInt64 {
        endAddress.rawValue >= startAddress.rawValue ? (endAddress.rawValue - startAddress.rawValue) : 0
    }

    public var addressRange: AddressRange {
        AddressRange(start: startAddress, size: byteSize)
    }
}

// MARK: - Switch Jump Table Recovery Descriptors

public enum SwitchDispatchPatternKind: String, Sendable, Codable, Hashable, CaseIterable {
    case adrSignedOffsetTable = "ADR + Signed Relative Offset Table"
    case adrpAddSignedOffsetTable = "ADRP+ADD + Signed Relative Offset Table"
    case unsignedScaledDeltaTable = "ADR/ADRP + Unsigned Byte/Half Scaled Table"
    case absolutePointerTable = "64-Bit Pointer / Fixup Jump Table"
    case inlineInstructionBranchTable = "ADR + Computed Inline Branch Table"
}

public struct SwitchJumpTableDescriptor: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { jumpTable.id }
    public let jumpTable: SwitchJumpTable
    public let patternKind: SwitchDispatchPatternKind
    public let indexRegister: A64Register?
    public let indexBias: Int64
    public let upperBoundInclusive: Int64?
    public let defaultTargetAddress: VirtualAddress?
    public let guardBranchAddress: VirtualAddress?
    public let setupInstructionAddresses: [VirtualAddress]

    public init(
        jumpTable: SwitchJumpTable,
        patternKind: SwitchDispatchPatternKind,
        indexRegister: A64Register? = nil,
        indexBias: Int64 = 0,
        upperBoundInclusive: Int64? = nil,
        defaultTargetAddress: VirtualAddress? = nil,
        guardBranchAddress: VirtualAddress? = nil,
        setupInstructionAddresses: [VirtualAddress] = []
    ) {
        self.jumpTable = jumpTable
        self.patternKind = patternKind
        self.indexRegister = indexRegister
        self.indexBias = indexBias
        self.upperBoundInclusive = upperBoundInclusive
        self.defaultTargetAddress = defaultTargetAddress
        self.guardBranchAddress = guardBranchAddress
        self.setupInstructionAddresses = setupInstructionAddresses
    }
}

public struct DecodedExecutableSection: Sendable, Codable, Hashable, Identifiable {
    public var id: String { section.id }
    public let section: BinarySection
    public let instructions: [A64DecodedInstruction]
    public let recognizedIdioms: [A64RecognizedIdiom]

    public init(
        section: BinarySection,
        instructions: [A64DecodedInstruction],
        recognizedIdioms: [A64RecognizedIdiom] = []
    ) {
        self.section = section
        self.instructions = instructions
        self.recognizedIdioms = recognizedIdioms
    }
}

// MARK: - Function Discovery & ARM64 Switch Jump-Table Recovery Engine

public struct FunctionDiscoveryEngine: Sendable {
    public let configuration: FunctionDiscoveryConfiguration
    private let decoder: A64InstructionDecoder
    private let idiomRecognizer: A64IdiomRecognizer
    private let demangler: SymbolDemangler

    public init(configuration: FunctionDiscoveryConfiguration = .standard) {
        self.configuration = configuration
        self.decoder = A64InstructionDecoder()
        self.idiomRecognizer = A64IdiomRecognizer()
        self.demangler = SymbolDemangler()
    }

    // MARK: - 1. Executable Section Decoding (Strict ARM64 / WASM Instruction Sections Only)

    /// Decodes all executable instruction sections into linear instruction streams enriched with multi-instruction idioms and symbol annotations.
    public func decodeExecutableSections(
        in image: LoadedBinaryImage,
        data: Data?,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) throws -> [DecodedExecutableSection] {
        if !image.architecture.isARM64Family && image.containerFormat != .wasm && image.architecture != .wasm32 {
            throw MachGraphError.unsupportedArchitecture(
                "Instruction decoding only supports ARM64/ARM64e (got \(image.architecture.displayName))."
            )
        }

        let execSections = selectExecutableSections(in: image)
        guard !execSections.isEmpty else { return [] }

        let resolvedLookup = symbolLookup ?? makeDefaultSymbolLookup(for: image)
        var results: [DecodedExecutableSection] = []
        results.reserveCapacity(execSections.count)

        for sec in execSections where sec.size > 0 {
            let sectionBytes = try extractSectionBytes(section: sec, image: image, data: data)

            if image.architecture.isARM64Family {
                guard sectionBytes.count >= 4 else {
                    let off = image.fileOffset(for: sec.vmAddress)?.rawValue ?? sec.fileOffset.rawValue
                    throw MachGraphError.unexpectedEOF(
                        offset: off,
                        requested: 4,
                        available: sectionBytes.count
                    )
                }

                let rawDecoded = decoder.decodeBuffer(
                    sectionBytes,
                    baseAddress: sec.vmAddress,
                    symbolLookup: resolvedLookup
                )
                let idioms = idiomRecognizer.recognizeIdioms(in: rawDecoded, symbolLookup: resolvedLookup)
                let enriched = mergeIdiomAutoComments(instructions: rawDecoded, idioms: idioms)
                results.append(
                    DecodedExecutableSection(
                        section: sec,
                        instructions: enriched,
                        recognizedIdioms: idioms
                    )
                )
            } else if image.containerFormat == .wasm || image.architecture == .wasm32 {
                let wasmInsns = try decodeWasmCodeSectionFallback(
                    section: sec,
                    bytes: sectionBytes,
                    image: image,
                    symbolLookup: resolvedLookup
                )
                results.append(DecodedExecutableSection(section: sec, instructions: wasmInsns))
            } else {
                throw MachGraphError.unsupportedArchitecture(
                    "Instruction decoding only supports ARM64/ARM64e (got \(image.architecture.displayName))."
                )
            }
        }

        return results
    }

    // MARK: - 2. Multi-Source Function Boundary Discovery

    /// Combines `LC_FUNCTION_STARTS`, `BinarySymbol` entries, Objective-C `ObjCClassMetadata` method IMPs,
    /// `BL` direct call targets, `__stubs` slot thunks, and ARM64 prologue heuristics to partition code into functions.
    public func discoverFunctions(
        in image: LoadedBinaryImage,
        decodedSections: [DecodedExecutableSection],
        data: Data? = nil
    ) -> [DiscoveredFunctionBoundary] {
        guard !decodedSections.isEmpty else { return [] }

        let execRanges = decodedSections.map(\.section.addressRange)
        func isExecutableAddress(_ addr: VirtualAddress) -> Bool {
            execRanges.contains { $0.contains(addr) }
        }

        // Build lookup tables for naming & GOT fixup resolution
        var gotSymbolByAddress: [VirtualAddress: String] = [:]
        for fixup in image.chainedFixups {
            if let sym = fixup.symbolName, !sym.isEmpty {
                gotSymbolByAddress[fixup.location] = sym
            }
        }
        for sym in image.symbols where sym.kind == .importedStub || sym.kind == .globalVariable {
            if gotSymbolByAddress[sym.address] == nil && !sym.name.isEmpty {
                gotSymbolByAddress[sym.address] = sym.name
            }
        }

        var symbolNameByAddress: [VirtualAddress: (raw: String, demangled: String, kind: SymbolKind)] = [:]
        for sym in image.symbols {
            guard isExecutableAddress(sym.address) else { continue }
            let cleanAddr = normalizeInstructionAddress(sym.address, architecture: image.architecture)
            let existing = symbolNameByAddress[cleanAddr]
            if existing == nil || prefersSymbol(sym, overKind: existing!.kind, existingName: existing!.raw) {
                let dem = sym.demangledName == sym.name ? demangler.demangle(sym.name) : sym.demangledName
                symbolNameByAddress[cleanAddr] = (sym.name, dem, sym.kind)
            }
        }

        var objcNameByAddress: [VirtualAddress: String] = [:]
        for cls in image.objcClasses {
            for method in cls.methods where method.implementationAddress.rawValue != 0 {
                let cleanAddr = normalizeInstructionAddress(method.implementationAddress, architecture: image.architecture)
                guard isExecutableAddress(cleanAddr) else { continue }
                let prefix = method.isClassMethod ? "+" : "-"
                objcNameByAddress[cleanAddr] = "\(prefix)[\(cls.name) \(method.selector)]"
            }
        }

        // Accumulate seed starts with provenance sets
        var seedsByAddress: [VirtualAddress: Set<FunctionDiscoverySource>] = [:]
        func recordSeed(_ rawAddr: VirtualAddress, source: FunctionDiscoverySource) {
            let addr = normalizeInstructionAddress(rawAddr, architecture: image.architecture)
            guard isExecutableAddress(addr) else { return }
            seedsByAddress[addr, default: []].insert(source)
        }

        // Pass A: Entry Point
        if let entry = image.entryPoint, entry.rawValue != 0 {
            recordSeed(entry, source: .entryPoint)
        }

        // Pass B: LC_FUNCTION_STARTS / PE .pdata / WASM code starts
        for fnStart in image.functionStarts where fnStart.rawValue != 0 {
            recordSeed(fnStart, source: .lcFunctionStarts)
        }

        // Pass C: Symbol Table Functions / Exports / Stubs
        for sym in image.symbols {
            switch sym.kind {
            case .function, .exportedEntry, .importedStub, .objcMethod, .swiftFunction:
                recordSeed(sym.address, source: .symbolTable)
            case .localSymbol:
                if !isCompilerLocalBlockLabel(sym.name) {
                    recordSeed(sym.address, source: .symbolTable)
                }
            case .globalVariable, .sectionLabel:
                break
            }
        }

        // Pass D: Objective-C Method Implementations
        for addr in objcNameByAddress.keys {
            recordSeed(addr, source: .objcMethod)
        }

        // Pass E: Direct BL Call Targets & Stub Slot Segmentation (ARM64)
        var stubTargetSymbolByStart: [VirtualAddress: String] = [:]
        var allIntraSectionBranchSpans: [(minAddr: UInt64, maxAddr: UInt64)] = []

        if image.architecture.isARM64Family {
            for decodedSec in decodedSections {
                let insns = decodedSec.instructions
                guard !insns.isEmpty else { continue }

                // Segment Mach-O __stubs / ELF .plt slots cleanly
                if configuration.enableStubSectionSegmentation && decodedSec.section.kind == .stubs {
                    let stubStarts = segmentARM64StubSection(
                        instructions: insns,
                        gotSymbolByAddress: gotSymbolByAddress
                    )
                    for stub in stubStarts {
                        recordSeed(stub.startAddress, source: .stubSlot)
                        if let targetSym = stub.targetSymbol {
                            stubTargetSymbolByStart[stub.startAddress] = targetSym
                        }
                    }
                }

                // Scan BL direct calls across all code
                if configuration.enableDirectCallTargetDiscovery {
                    for insn in insns {
                        if case .directCall(let target) = insn.flow {
                            recordSeed(target, source: .directCallTarget)
                        }
                        // Record short forward conditional branch spans so heuristic prologues never split across live conditional branches
                        if case .conditionalBranch(let target, _) = insn.flow,
                           decodedSec.section.addressRange.contains(target) {
                            let lo = min(insn.address.rawValue, target.rawValue)
                            let hi = max(insn.address.rawValue, target.rawValue)
                            if hi - lo <= 0x2000 {
                                allIntraSectionBranchSpans.append((lo, hi))
                            }
                        }
                    }
                }
            }

            // Pass F: ARM64 Prologue Heuristics in Unclaimed Regions
            if configuration.enablePrologueHeuristics {
                for decodedSec in decodedSections where decodedSec.section.kind != .stubs {
                    let heuristicStarts = scanARM64PrologueHeuristics(
                        in: decodedSec.instructions,
                        existingAuthoritativeSeeds: Set(seedsByAddress.keys),
                        protectedSpans: allIntraSectionBranchSpans
                    )
                    for candidate in heuristicStarts {
                        recordSeed(candidate, source: .prologueHeuristic)
                    }
                }
            }

            // Pass G: Unconditional Tail-Call Targets (`B target` jumping from inside one known function to an unclaimed prologue)
            if configuration.enableTailJumpSplitHeuristics {
                let preliminarySorted = seedsByAddress.keys.sorted()
                for decodedSec in decodedSections where decodedSec.section.kind != .stubs {
                    for insn in decodedSec.instructions {
                        guard case .unconditionalJump(let target) = insn.flow,
                              decodedSec.section.addressRange.contains(target),
                              seedsByAddress[target] == nil else {
                            continue
                        }
                        let srcOwner = binarySearchFloor(in: preliminarySorted, value: insn.address)
                        let dstOwner = binarySearchFloor(in: preliminarySorted, value: target)
                        if srcOwner != dstOwner,
                           let targetIdx = binarySearchExactInstruction(in: decodedSec.instructions, address: target),
                           looksLikeARM64FunctionEntry(in: decodedSec.instructions, at: targetIdx) {
                            recordSeed(target, source: .tailBranchTarget)
                        }
                    }
                }
            }
        }

        // Fallback: if an executable section has instructions/bytes right at its base and ZERO seeds inside it,
        // create a section-root fallback function so raw shellcode / stripped blobs still analyze cleanly.
        for decodedSec in decodedSections where !decodedSec.instructions.isEmpty {
            let secRange = decodedSec.section.addressRange
            let hasSeedInSection = seedsByAddress.keys.contains { secRange.contains($0) }
            if !hasSeedInSection {
                recordSeed(decodedSec.instructions[0].address, source: .containerFallback)
            }
        }

        // Partition each executable section into contiguous non-overlapping function ranges
        var boundaries: [DiscoveredFunctionBoundary] = []
        for decodedSec in decodedSections {
            let sec = decodedSec.section
            let secRange = sec.addressRange
            let sectionSeeds = seedsByAddress.keys
                .filter { secRange.contains($0) }
                .sorted()

            guard !sectionSeeds.isEmpty else { continue }

            for (idx, startAddr) in sectionSeeds.enumerated() {
                let rawEnd: VirtualAddress = (idx + 1 < sectionSeeds.count)
                    ? sectionSeeds[idx + 1]
                    : secRange.end
                guard rawEnd > startAddr else { continue }

                let trimmedEnd: VirtualAddress
                if configuration.trimTrailingZeroPadding && image.architecture.isARM64Family && sec.kind != .stubs {
                    trimmedEnd = trimARM64FunctionEnd(
                        startAddress: startAddr,
                        rawEndAddress: rawEnd,
                        sectionInstructions: decodedSec.instructions
                    )
                } else {
                    trimmedEnd = rawEnd
                }

                let sources = Array(seedsByAddress[startAddr] ?? [.containerFallback])
                let confidence = computeBoundaryConfidence(sources: sources)

                // Resolve stub target symbol even if LC_FUNCTION_STARTS seeded the stub earlier
                var stubTargetSym = stubTargetSymbolByStart[startAddr]
                if stubTargetSym == nil && sec.kind == .stubs && image.architecture.isARM64Family {
                    let sliceInsns = sliceInstructions(
                        in: decodedSec.instructions,
                        from: startAddr,
                        to: trimmedEnd
                    )
                    stubTargetSym = resolveStubTargetSymbol(
                        in: sliceInsns,
                        gotSymbolByAddress: gotSymbolByAddress
                    )
                }

                let (rawName, demangledName) = synthesizeFunctionName(
                    at: startAddr,
                    entryPoint: image.entryPoint,
                    isStubSection: sec.kind == .stubs,
                    symbolInfo: symbolNameByAddress[startAddr],
                    objcMethodName: objcNameByAddress[startAddr],
                    stubTargetSymbol: stubTargetSym
                )

                boundaries.append(
                    DiscoveredFunctionBoundary(
                        startAddress: startAddr,
                        endAddress: trimmedEnd,
                        name: rawName,
                        demangledName: demangledName,
                        sectionName: sec.fullName,
                        isStubSection: sec.kind == .stubs,
                        sources: sources,
                        confidence: confidence,
                        resolvedGOTTargetSymbol: stubTargetSym
                    )
                )
            }
        }

        boundaries.sort { $0.startAddress < $1.startAddress }
        return boundaries
    }

    // MARK: - 3. ARM64 Switch Jump-Table Recovery Engine

    /// Recovers `[SwitchJumpTable]` instances inside a function's decoded instruction stream by matching
    /// bounds-checked PC-relative and pointer-table dispatch idioms and reading slice bytes from `data`.
    public func recoverJumpTables(
        in instructions: [A64DecodedInstruction],
        functionStart: VirtualAddress,
        functionEnd: VirtualAddress,
        image: LoadedBinaryImage,
        data: Data?
    ) -> [SwitchJumpTable] {
        recoverJumpTableDescriptors(
            in: instructions,
            functionStart: functionStart,
            functionEnd: functionEnd,
            image: image,
            data: data
        ).map(\.jumpTable)
    }

    /// Full jump-table descriptor recovery returning bounds metadata, index register, default target, and resolved targets.
    public func recoverJumpTableDescriptors(
        in instructions: [A64DecodedInstruction],
        functionStart: VirtualAddress,
        functionEnd: VirtualAddress,
        image: LoadedBinaryImage,
        data: Data?
    ) -> [SwitchJumpTableDescriptor] {
        guard image.architecture.isARM64Family, !instructions.isEmpty else {
            return []
        }

        var descriptors: [SwitchJumpTableDescriptor] = []

        for (brIdx, brInsn) in instructions.enumerated() {
            guard case .indirectJump(let jumpReg) = brInsn.flow else { continue }
            // Skip x16/x17 single-thunk import stubs (handled as dyld import stubs)
            if instructions.count <= 5 && (jumpReg.index == 16 || jumpReg.index == 17) {
                if idiomRecognizer.recognizeIdioms(in: instructions).contains(where: { $0.kind == .dyldImportStub }) {
                    continue
                }
            }

            if let descriptor = matchSwitchDispatchAtIndirectBranch(
                brIndex: brIdx,
                jumpRegister: jumpReg,
                instructions: instructions,
                functionStart: functionStart,
                functionEnd: functionEnd,
                image: image,
                data: data
            ) {
                descriptors.append(descriptor)
            }
        }

        return descriptors
    }

    // MARK: - Internal Switch Pattern Matcher & Binary Table Reader

    private enum TableEntryEncoding {
        case signedRelative(byteSize: Int, postLoadShift: Int)
        case unsignedRelative(byteSize: Int, postLoadShift: Int)
        case absolutePointer64
        case inlineInstructionOffset(scaleShift: Int)

        var entryByteSize: Int {
            switch self {
            case .signedRelative(let b, _): return b
            case .unsignedRelative(let b, _): return b
            case .absolutePointer64: return 8
            case .inlineInstructionOffset: return 4
            }
        }
    }

    private struct ResolvedDispatchPattern {
        let patternKind: SwitchDispatchPatternKind
        let tableBaseAddress: VirtualAddress
        let anchorAddress: VirtualAddress
        let indexRegister: A64Register?
        let encoding: TableEntryEncoding
        let setupAddresses: [VirtualAddress]
    }

    private struct BoundsGuardInfo {
        let indexRegister: A64Register
        let indexBias: Int64
        let upperBoundInclusive: Int64
        let defaultTargetAddress: VirtualAddress?
        let guardBranchAddress: VirtualAddress?
    }

    private func matchSwitchDispatchAtIndirectBranch(
        brIndex: Int,
        jumpRegister: A64Register,
        instructions: [A64DecodedInstruction],
        functionStart: VirtualAddress,
        functionEnd: VirtualAddress,
        image: LoadedBinaryImage,
        data: Data?
    ) -> SwitchJumpTableDescriptor? {
        let brInsn = instructions[brIndex]
        let windowStart = max(0, brIndex - 14)

        guard let dispatch = analyzeBackwardDispatchSlice(
            windowStart: windowStart,
            brIndex: brIndex,
            jumpRegister: jumpRegister,
            instructions: instructions
        ) else {
            return nil
        }

        // Recover bounds check (CMP wIdx, #max + B.HI / B.HS / B.LS ...)
        let boundsStart = max(0, windowStart - 10)
        let boundsInfo = findSwitchBoundsGuard(
            searchStart: boundsStart,
            brIndex: brIndex,
            dispatchAddress: brInsn.address,
            expectedIndexRegister: dispatch.indexRegister,
            instructions: instructions
        )

        let determinedCount: Int?
        if let bounds = boundsInfo, bounds.upperBoundInclusive >= 0 {
            let count64 = bounds.upperBoundInclusive + 1
            determinedCount = Int(min(Int64(configuration.maxJumpTableEntries), count64))
        } else {
            determinedCount = nil
        }

        let targets = readJumpTableTargets(
            dispatch: dispatch,
            exactCount: determinedCount,
            functionStart: functionStart,
            functionEnd: functionEnd,
            image: image,
            data: data
        )

        guard !targets.isEmpty else { return nil }

        let jumpTable = SwitchJumpTable(
            dispatchInstructionAddress: brInsn.address,
            tableBaseAddress: dispatch.tableBaseAddress,
            entryByteSize: dispatch.encoding.entryByteSize,
            targetAddresses: targets
        )

        var setupAddrs = dispatch.setupAddresses
        if let guardAddr = boundsInfo?.guardBranchAddress, !setupAddrs.contains(guardAddr) {
            setupAddrs.insert(guardAddr, at: 0)
        }
        if !setupAddrs.contains(brInsn.address) {
            setupAddrs.append(brInsn.address)
        }

        return SwitchJumpTableDescriptor(
            jumpTable: jumpTable,
            patternKind: dispatch.patternKind,
            indexRegister: boundsInfo?.indexRegister ?? dispatch.indexRegister,
            indexBias: boundsInfo?.indexBias ?? 0,
            upperBoundInclusive: boundsInfo?.upperBoundInclusive ?? Int64(targets.count - 1),
            defaultTargetAddress: boundsInfo?.defaultTargetAddress,
            guardBranchAddress: boundsInfo?.guardBranchAddress,
            setupInstructionAddresses: setupAddrs
        )
    }

    /// Symbolic backward dataflow slice over registers in `[windowStart ..< brIndex]` to resolve
    /// Clang/Swiftc/GCC ARM64 switch idioms:
    ///   Pattern A: `ADR/ADRP+ADD xBase, tbl` -> `LDRSW/LDRSH/LDRSB/LDRB/LDRH rOff, [xBase, rIdx, extend]` -> `ADD xJmp, xAnchor, rOff{, shift}` -> `BR xJmp`
    ///   Pattern B: `ADRP+ADD/ADR xBase, tbl` -> `LDR xJmp, [xBase, rIdx, LSL #3]` -> `BR xJmp`
    ///   Pattern C: `ADR xBase, inlineTbl` -> `ADD xJmp, xBase, rIdx, LSL #2` -> `BR xJmp`
    private func analyzeBackwardDispatchSlice(
        windowStart: Int,
        brIndex: Int,
        jumpRegister: A64Register,
        instructions: [A64DecodedInstruction]
    ) -> ResolvedDispatchPattern? {
        // Forward miniature symbolic evaluator across `[windowStart ..< brIndex]`
        enum SymVal {
            case adrpPage(page: VirtualAddress, insnAddr: VirtualAddress)
            case pcAddress(addr: VirtualAddress, viaADRP: Bool, insnAddrs: [VirtualAddress])
            case tableOffsetLoad(
                tableBase: VirtualAddress,
                viaADRP: Bool,
                indexReg: A64Register,
                byteSize: Int,
                isSigned: Bool,
                insnAddrs: [VirtualAddress]
            )
            case absoluteTargetLoad(
                tableBase: VirtualAddress,
                indexReg: A64Register,
                insnAddrs: [VirtualAddress]
            )
            case computedJumpTarget(
                patternKind: SwitchDispatchPatternKind,
                tableBase: VirtualAddress,
                anchor: VirtualAddress,
                indexReg: A64Register?,
                encoding: TableEntryEncoding,
                insnAddrs: [VirtualAddress]
            )
        }

        var regEnv: [UInt8: SymVal] = [:]

        for idx in windowStart..<brIndex {
            let insn = instructions[idx]

            switch insn.mnemonic {
            case .adr:
                if insn.operands.count == 2,
                   case .register(let rd) = insn.operands[0],
                   case .branchTarget(let addr) = insn.operands[1] {
                    regEnv[rd.index] = .pcAddress(addr: addr, viaADRP: false, insnAddrs: [insn.address])
                }

            case .adrp:
                if insn.operands.count == 2,
                   case .register(let rd) = insn.operands[0],
                   case .branchTarget(let page) = insn.operands[1] {
                    regEnv[rd.index] = .adrpPage(page: page, insnAddr: insn.address)
                }

            case .add:
                guard insn.operands.count == 3,
                      case .register(let rd) = insn.operands[0],
                      case .register(let rn) = insn.operands[1] else {
                    break
                }

                // Case 1: ADRP + ADD #pageoff -> pcAddress
                if let immDelta = extractAddImmediate(insn.operands[2]),
                   let rnVal = regEnv[rn.index] {
                    switch rnVal {
                    case .adrpPage(let page, let adrpAddr):
                        regEnv[rd.index] = .pcAddress(
                            addr: page.adding(immDelta),
                            viaADRP: true,
                            insnAddrs: [adrpAddr, insn.address]
                        )
                        continue
                    case .pcAddress(let baseAddr, let viaADRP, let addrs):
                        regEnv[rd.index] = .pcAddress(
                            addr: baseAddr.adding(immDelta),
                            viaADRP: viaADRP,
                            insnAddrs: addrs + [insn.address]
                        )
                        continue
                    default:
                        break
                    }
                }

                // Case 2: ADD xTarget, xAnchor, rOff{, shift/extend}
                if let (rmReg, postShift) = extractRegisterAndShift(insn.operands[2]) {
                    if let anchorVal = regEnv[rn.index],
                       case .pcAddress(let anchorAddr, let anchorADRP, let anchorAddrs) = anchorVal {
                        if let rmVal = regEnv[rmReg.index],
                           case .tableOffsetLoad(let tblBase, let tblADRP, let idxReg, let byteSz, let isSigned, let loadAddrs) = rmVal {
                            let enc: TableEntryEncoding = isSigned
                                ? .signedRelative(byteSize: byteSz, postLoadShift: postShift)
                                : .unsignedRelative(byteSize: byteSz, postLoadShift: postShift)
                            let pKind: SwitchDispatchPatternKind
                            if !isSigned {
                                pKind = .unsignedScaledDeltaTable
                            } else if tblADRP || anchorADRP {
                                pKind = .adrpAddSignedOffsetTable
                            } else {
                                pKind = .adrSignedOffsetTable
                            }
                            regEnv[rd.index] = .computedJumpTarget(
                                patternKind: pKind,
                                tableBase: tblBase,
                                anchor: anchorAddr,
                                indexReg: idxReg,
                                encoding: enc,
                                insnAddrs: mergeUniqueAddresses(anchorAddrs, loadAddrs + [insn.address])
                            )
                            continue
                        } else if postShift == 2 {
                            // Pattern C: Inline instruction table `ADR xBase, tbl` + `ADD xTarget, xBase, xIdx, LSL #2`
                            regEnv[rd.index] = .computedJumpTarget(
                                patternKind: .inlineInstructionBranchTable,
                                tableBase: anchorAddr,
                                anchor: anchorAddr,
                                indexReg: rmReg,
                                encoding: .inlineInstructionOffset(scaleShift: postShift),
                                insnAddrs: anchorAddrs + [insn.address]
                            )
                            continue
                        }
                    }

                    // Commuted operand order: ADD xTarget, rOff, xAnchor
                    if postShift == 0,
                       let rnVal = regEnv[rn.index],
                       case .tableOffsetLoad(let tblBase, let tblADRP, let idxReg, let byteSz, let isSigned, let loadAddrs) = rnVal,
                       let rmVal = regEnv[rmReg.index],
                       case .pcAddress(let anchorAddr, let anchorADRP, let anchorAddrs) = rmVal {
                        let enc: TableEntryEncoding = isSigned
                            ? .signedRelative(byteSize: byteSz, postLoadShift: 0)
                            : .unsignedRelative(byteSize: byteSz, postLoadShift: 0)
                        let pKind: SwitchDispatchPatternKind = !isSigned
                            ? .unsignedScaledDeltaTable
                            : ((tblADRP || anchorADRP) ? .adrpAddSignedOffsetTable : .adrSignedOffsetTable)
                        regEnv[rd.index] = .computedJumpTarget(
                            patternKind: pKind,
                            tableBase: tblBase,
                            anchor: anchorAddr,
                            indexReg: idxReg,
                            encoding: enc,
                            insnAddrs: mergeUniqueAddresses(loadAddrs, anchorAddrs + [insn.address])
                        )
                        continue
                    }
                }

                regEnv.removeValue(forKey: rd.index)

            case .ldrsw, .ldrsh, .ldrsb, .ldrb, .ldrh, .ldr:
                guard insn.operands.count == 2,
                      case .register(let rt) = insn.operands[0],
                      case .memory(.registerOffset(let baseReg, let idxReg, _)) = insn.operands[1],
                      let baseVal = regEnv[baseReg.index],
                      case .pcAddress(let tblBase, let viaADRP, let baseAddrs) = baseVal else {
                    if let first = insn.operands.first, case .register(let rt) = first {
                        regEnv.removeValue(forKey: rt.index)
                    }
                    break
                }

                switch insn.mnemonic {
                case .ldrsw:
                    regEnv[rt.index] = .tableOffsetLoad(
                        tableBase: tblBase,
                        viaADRP: viaADRP,
                        indexReg: idxReg,
                        byteSize: 4,
                        isSigned: true,
                        insnAddrs: baseAddrs + [insn.address]
                    )
                case .ldrsh:
                    regEnv[rt.index] = .tableOffsetLoad(
                        tableBase: tblBase,
                        viaADRP: viaADRP,
                        indexReg: idxReg,
                        byteSize: 2,
                        isSigned: true,
                        insnAddrs: baseAddrs + [insn.address]
                    )
                case .ldrsb:
                    regEnv[rt.index] = .tableOffsetLoad(
                        tableBase: tblBase,
                        viaADRP: viaADRP,
                        indexReg: idxReg,
                        byteSize: 1,
                        isSigned: true,
                        insnAddrs: baseAddrs + [insn.address]
                    )
                case .ldrh:
                    regEnv[rt.index] = .tableOffsetLoad(
                        tableBase: tblBase,
                        viaADRP: viaADRP,
                        indexReg: idxReg,
                        byteSize: 2,
                        isSigned: false,
                        insnAddrs: baseAddrs + [insn.address]
                    )
                case .ldrb:
                    regEnv[rt.index] = .tableOffsetLoad(
                        tableBase: tblBase,
                        viaADRP: viaADRP,
                        indexReg: idxReg,
                        byteSize: 1,
                        isSigned: false,
                        insnAddrs: baseAddrs + [insn.address]
                    )
                case .ldr:
                    if rt.bitWidth == 64 {
                        regEnv[rt.index] = .absoluteTargetLoad(
                            tableBase: tblBase,
                            indexReg: idxReg,
                            insnAddrs: baseAddrs + [insn.address]
                        )
                    } else {
                        regEnv[rt.index] = .tableOffsetLoad(
                            tableBase: tblBase,
                            viaADRP: viaADRP,
                            indexReg: idxReg,
                            byteSize: 4,
                            isSigned: false,
                            insnAddrs: baseAddrs + [insn.address]
                        )
                    }
                default:
                    break
                }

            case .mov:
                if insn.operands.count == 2,
                   case .register(let rd) = insn.operands[0],
                   case .register(let rm) = insn.operands[1],
                   let val = regEnv[rm.index] {
                    regEnv[rd.index] = val
                } else if let first = insn.operands.first, case .register(let rd) = first {
                    regEnv.removeValue(forKey: rd.index)
                }

            default:
                for wReg in insn.writesRegisters where !wReg.isZeroRegister && !wReg.isStackPointer {
                    regEnv.removeValue(forKey: wReg.index)
                }
            }
        }

        guard let finalVal = regEnv[jumpRegister.index] else { return nil }
        switch finalVal {
        case .computedJumpTarget(let kind, let tblBase, let anchor, let idxReg, let enc, let addrs):
            return ResolvedDispatchPattern(
                patternKind: kind,
                tableBaseAddress: tblBase,
                anchorAddress: anchor,
                indexRegister: idxReg,
                encoding: enc,
                setupAddresses: addrs
            )
        case .absoluteTargetLoad(let tblBase, let idxReg, let addrs):
            return ResolvedDispatchPattern(
                patternKind: .absolutePointerTable,
                tableBaseAddress: tblBase,
                anchorAddress: tblBase,
                indexRegister: idxReg,
                encoding: .absolutePointer64,
                setupAddresses: addrs
            )
        default:
            return nil
        }
    }

    private func findSwitchBoundsGuard(
        searchStart: Int,
        brIndex: Int,
        dispatchAddress: VirtualAddress,
        expectedIndexRegister: A64Register?,
        instructions: [A64DecodedInstruction]
    ) -> BoundsGuardInfo? {
        var latestCmpReg: A64Register?
        var latestCmpImm: Int64?
        var indexBiasByReg: [UInt8: Int64] = [:]
        var bestGuard: BoundsGuardInfo?

        for i in searchStart..<brIndex {
            let insn = instructions[i]

            // Track optional bias normalization: `SUB wIdx, wOrig, #minCase`
            if insn.mnemonic == .sub,
               insn.operands.count == 3,
               case .register(let rd) = insn.operands[0],
               let delta = extractAddImmediate(insn.operands[2]) {
                indexBiasByReg[rd.index] = delta
            }

            // Match `CMP wIdx/xIdx, #imm` (or `SUBS wzr/wTmp, wIdx, #imm`)
            if (insn.mnemonic == .cmp || insn.mnemonic == .subs),
               insn.writesFlags {
                if insn.mnemonic == .cmp,
                   insn.operands.count == 2,
                   case .register(let rn) = insn.operands[0],
                   let imm = extractAddImmediate(insn.operands[1]) {
                    latestCmpReg = rn
                    latestCmpImm = imm
                } else if insn.mnemonic == .subs,
                          insn.operands.count == 3,
                          case .register(let rn) = insn.operands[1],
                          let imm = extractAddImmediate(insn.operands[2]) {
                    latestCmpReg = rn
                    latestCmpImm = imm
                }
                continue
            }

            // Match conditional branch consuming CMP flags
            if case .conditionalBranch(let branchTarget, let cond) = insn.flow,
               insn.readsFlags,
               let cmpReg = latestCmpReg,
               let cmpImm = latestCmpImm,
               cmpImm >= 0 && cmpImm <= Int64(configuration.maxJumpTableEntries) {

                // Check register compatibility if index register is known (allow alias via mov/uxtw if needed)
                if let expected = expectedIndexRegister, expected.index != cmpReg.index {
                    // Still accept if no closer matching CMP was found yet, as Clang often copies w0 -> w8 after CMP w0, #N!
                }

                let bias = indexBiasByReg[cmpReg.index] ?? 0
                switch cond {
                case .hi, .gt:
                    // `cmp idx, #max ; b.hi default` -> valid indices 0...max (inclusive)
                    bestGuard = BoundsGuardInfo(
                        indexRegister: cmpReg,
                        indexBias: bias,
                        upperBoundInclusive: cmpImm,
                        defaultTargetAddress: branchTarget,
                        guardBranchAddress: insn.address
                    )
                case .cs:
                    // `cmp idx, #count ; b.hs default` -> valid indices 0..<(count), upperBound = count - 1
                    if cmpImm >= 1 {
                        bestGuard = BoundsGuardInfo(
                            indexRegister: cmpReg,
                            indexBias: bias,
                            upperBoundInclusive: cmpImm - 1,
                            defaultTargetAddress: branchTarget,
                            guardBranchAddress: insn.address
                        )
                    }
                case .ls, .le:
                    // `cmp idx, #max ; b.ls dispatch_block` (followed by fallthrough to default or `b default`)
                    if branchTarget <= dispatchAddress {
                        var fallbackDefault: VirtualAddress?
                        if i + 1 < instructions.count,
                           case .unconditionalJump(let defTgt) = instructions[i + 1].flow {
                            fallbackDefault = defTgt
                        }
                        bestGuard = BoundsGuardInfo(
                            indexRegister: cmpReg,
                            indexBias: bias,
                            upperBoundInclusive: cmpImm,
                            defaultTargetAddress: fallbackDefault,
                            guardBranchAddress: insn.address
                        )
                    }
                case .cc, .lt:
                    // `cmp idx, #count ; b.lo dispatch_block`
                    if cmpImm >= 1 && branchTarget <= dispatchAddress {
                        var fallbackDefault: VirtualAddress?
                        if i + 1 < instructions.count,
                           case .unconditionalJump(let defTgt) = instructions[i + 1].flow {
                            fallbackDefault = defTgt
                        }
                        bestGuard = BoundsGuardInfo(
                            indexRegister: cmpReg,
                            indexBias: bias,
                            upperBoundInclusive: cmpImm - 1,
                            defaultTargetAddress: fallbackDefault,
                            guardBranchAddress: insn.address
                        )
                    }
                default:
                    break
                }
            }
        }

        return bestGuard
    }

    private func readJumpTableTargets(
        dispatch: ResolvedDispatchPattern,
        exactCount: Int?,
        functionStart: VirtualAddress,
        functionEnd: VirtualAddress,
        image: LoadedBinaryImage,
        data: Data?
    ) -> [VirtualAddress] {
        let maxEntries = exactCount ?? configuration.unboundedJumpTableFallbackLimit
        guard maxEntries > 0 else { return [] }

        let execSections = selectExecutableSections(in: image)
        func isValidCodeTarget(_ addr: VirtualAddress) -> Bool {
            guard addr.rawValue % 4 == 0 else { return false }
            if addr >= functionStart && addr < functionEnd {
                return true
            }
            if exactCount != nil {
                return execSections.contains { $0.addressRange.contains(addr) }
            }
            return false
        }

        // Inline computed branch table (`ADR xBase, tbl; ADD xTarget, xBase, xIdx, LSL #2; BR xTarget`)
        if case .inlineInstructionOffset(let scaleShift) = dispatch.encoding {
            let strideBytes = UInt64(1 << scaleShift)
            var inlineTargets: [VirtualAddress] = []
            for i in 0..<maxEntries {
                let entryVA = dispatch.tableBaseAddress.adding(UInt64(i) * strideBytes)
                guard isValidCodeTarget(entryVA) else { break }
                inlineTargets.append(entryVA)
            }
            return inlineTargets
        }

        // Pre-index ChainedFixup rebases for 64-bit pointer tables in __DATA_CONST
        var rebaseByLocation: [VirtualAddress: VirtualAddress] = [:]
        if case .absolutePointer64 = dispatch.encoding {
            for fixup in image.chainedFixups {
                if let tgt = fixup.targetAddress {
                    rebaseByLocation[fixup.location] = tgt
                }
            }
        }

        let entrySize = dispatch.encoding.entryByteSize
        var resolvedTargets: [VirtualAddress] = []
        resolvedTargets.reserveCapacity(min(maxEntries, 64))

        for i in 0..<maxEntries {
            let entryVA = dispatch.tableBaseAddress.adding(UInt64(i * entrySize))

            let candidateTarget: VirtualAddress?
            switch dispatch.encoding {
            case .signedRelative(let byteSize, let shift):
                guard let rawSigned = readSignedInteger(
                    at: entryVA,
                    byteSize: byteSize,
                    endianness: image.endianness,
                    image: image,
                    data: data
                ) else {
                    candidateTarget = nil
                    break
                }
                let scaledDelta = rawSigned << shift
                candidateTarget = dispatch.anchorAddress.adding(scaledDelta)

            case .unsignedRelative(let byteSize, let shift):
                guard let rawUnsigned = readUnsignedInteger(
                    at: entryVA,
                    byteSize: byteSize,
                    endianness: image.endianness,
                    image: image,
                    data: data
                ) else {
                    candidateTarget = nil
                    break
                }
                let scaledDelta = Int64(bitPattern: rawUnsigned << UInt64(shift))
                candidateTarget = dispatch.anchorAddress.adding(scaledDelta)

            case .absolutePointer64:
                if let rebased = rebaseByLocation[entryVA] {
                    candidateTarget = rebased
                } else if let rawPtr = readUnsignedInteger(
                    at: entryVA,
                    byteSize: 8,
                    endianness: image.endianness,
                    image: image,
                    data: data
                ) {
                    // Mask potential high-bit dyld chained rebase encoding if raw pointer wasn't rebased
                    let direct = VirtualAddress(rawPtr)
                    if isValidCodeTarget(direct) {
                        candidateTarget = direct
                    } else {
                        let low36 = image.imageBase.adding(rawPtr & 0x0000_000F_FFFF_FFFF)
                        candidateTarget = isValidCodeTarget(low36) ? low36 : nil
                    }
                } else {
                    candidateTarget = nil
                }

            case .inlineInstructionOffset:
                candidateTarget = nil
            }

            guard let target = candidateTarget, isValidCodeTarget(target) else {
                break
            }
            resolvedTargets.append(target)
        }

        // If unbounded, require at least 2 valid entries to avoid false-positive indirect tail calls
        if exactCount == nil && resolvedTargets.count < 2 {
            return []
        }

        return resolvedTargets
    }

    // MARK: - Internal Stub, Prologue & Padding Helpers

    private struct DiscoveredStubSlot {
        let startAddress: VirtualAddress
        let targetSymbol: String?
    }

    private func segmentARM64StubSection(
        instructions: [A64DecodedInstruction],
        gotSymbolByAddress: [VirtualAddress: String]
    ) -> [DiscoveredStubSlot] {
        guard !instructions.isEmpty else { return [] }
        var stubs: [DiscoveredStubSlot] = []
        var currentStartIdx = 0

        for i in 0..<instructions.count {
            let insn = instructions[i]
            let isStubTerminator: Bool
            switch insn.flow {
            case .indirectJump, .unconditionalJump, .returnControl:
                isStubTerminator = true
            default:
                isStubTerminator = false
            }

            if isStubTerminator {
                let slice = Array(instructions[currentStartIdx...i])
                if !slice.isEmpty {
                    let sym = resolveStubTargetSymbol(in: slice, gotSymbolByAddress: gotSymbolByAddress)
                    stubs.append(DiscoveredStubSlot(startAddress: slice[0].address, targetSymbol: sym))
                }
                currentStartIdx = i + 1
                // Skip optional NOP padding between stubs
                while currentStartIdx < instructions.count && instructions[currentStartIdx].mnemonic == .nop {
                    currentStartIdx += 1
                }
            }
        }

        if stubs.isEmpty {
            stubs.append(DiscoveredStubSlot(startAddress: instructions[0].address, targetSymbol: nil))
        }
        return stubs
    }

    private func resolveStubTargetSymbol(
        in stubInstructions: [A64DecodedInstruction],
        gotSymbolByAddress: [VirtualAddress: String]
    ) -> String? {
        let idioms = idiomRecognizer.recognizeIdioms(in: stubInstructions)
        for idiom in idioms {
            if let ptrAddr = idiom.targetAddress, let sym = gotSymbolByAddress[ptrAddr] {
                return sym
            }
        }
        // Direct pair check fallback
        for i in 0..<(stubInstructions.count > 0 ? stubInstructions.count - 1 : 0) {
            if let ptr = idiomRecognizer.resolveAdrpLoad(adrp: stubInstructions[i], load: stubInstructions[i + 1]),
               let sym = gotSymbolByAddress[ptr] {
                return sym
            }
            if let ptr = idiomRecognizer.resolveAdrpAdd(adrp: stubInstructions[i], add: stubInstructions[i + 1]),
               let sym = gotSymbolByAddress[ptr] {
                return sym
            }
        }
        return nil
    }

    private func scanARM64PrologueHeuristics(
        in instructions: [A64DecodedInstruction],
        existingAuthoritativeSeeds: Set<VirtualAddress>,
        protectedSpans: [(minAddr: UInt64, maxAddr: UInt64)]
    ) -> [VirtualAddress] {
        guard instructions.count >= 2 else { return [] }
        var discovered: [VirtualAddress] = []

        func isInsideProtectedBranchSpan(_ addr: VirtualAddress) -> Bool {
            let raw = addr.rawValue
            return protectedSpans.contains { raw > $0.minAddr && raw <= $0.maxAddr }
        }

        var prevWasHardBarrier = true
        for idx in 0..<instructions.count {
            let insn = instructions[idx]

            // Skip zero-word or NOP alignment sleds after a barrier while preserving barrier status
            if prevWasHardBarrier && (insn.rawWord == 0 || insn.mnemonic == .nop) {
                continue
            }

            if prevWasHardBarrier &&
               !existingAuthoritativeSeeds.contains(insn.address) &&
               !isInsideProtectedBranchSpan(insn.address) &&
               looksLikeARM64FunctionEntry(in: instructions, at: idx) {
                discovered.append(insn.address)
            }

            switch insn.flow {
            case .returnControl, .unconditionalJump, .indirectJump:
                prevWasHardBarrier = true
            case .trapOrSupervisor:
                prevWasHardBarrier = (insn.mnemonic == .brk || insn.mnemonic == .hlt)
            default:
                prevWasHardBarrier = false
            }
        }

        return discovered
    }

    private func looksLikeARM64FunctionEntry(
        in instructions: [A64DecodedInstruction],
        at index: Int
    ) -> Bool {
        guard index >= 0 && index < instructions.count else { return false }
        let first = instructions[index]

        // 1. PACIASP / PACIBSP
        if first.mnemonic == .paciasp || first.mnemonic == .pacibsp {
            return true
        }

        // 2. BTI landing pad (`bti c` / `bti jc`) followed by prologue instruction
        if first.mnemonic == .bti && index + 1 < instructions.count {
            let second = instructions[index + 1]
            if second.mnemonic == .paciasp || second.mnemonic == .pacibsp || isFrameSetupInstruction(second) {
                return true
            }
        }

        // 3. STP x29, x30, [sp, #-N]!
        if isFrameLinkPreIndexPush(first) {
            return true
        }

        // 4. SUB sp, sp, #N followed shortly by STP [sp, #offset] (including x29, x30)
        if isStackPointerSubAllocation(first) {
            let lookaheadEnd = min(instructions.count, index + 5)
            for k in (index + 1)..<lookaheadEnd {
                if isCalleeSaveStackStorePair(instructions[k]) {
                    return true
                }
                if instructions[k].flow != .sequential {
                    break
                }
            }
        }

        return false
    }

    private func isFrameSetupInstruction(_ insn: A64DecodedInstruction) -> Bool {
        isFrameLinkPreIndexPush(insn) || isStackPointerSubAllocation(insn)
    }

    private func isFrameLinkPreIndexPush(_ insn: A64DecodedInstruction) -> Bool {
        guard insn.mnemonic == .stp,
              insn.operands.count == 3,
              case .register(let r1) = insn.operands[0],
              case .register(let r2) = insn.operands[1],
              case .memory(.preIndex(let base, let offset)) = insn.operands[2] else {
            return false
        }
        guard base.isStackPointer && offset < 0 else { return false }
        return (r1.index == 29 && r2.index == 30) || (r1.index >= 19 && r1.index <= 30)
    }

    private func isStackPointerSubAllocation(_ insn: A64DecodedInstruction) -> Bool {
        guard insn.mnemonic == .sub,
              insn.operands.count == 3,
              case .register(let rd) = insn.operands[0], rd.isStackPointer,
              case .register(let rn) = insn.operands[1], rn.isStackPointer,
              let delta = extractAddImmediate(insn.operands[2]) else {
            return false
        }
        return delta >= 16 && (delta % 16 == 0)
    }

    private func isCalleeSaveStackStorePair(_ insn: A64DecodedInstruction) -> Bool {
        guard insn.mnemonic == .stp,
              insn.operands.count == 3,
              case .register(let r1) = insn.operands[0],
              case .register(let r2) = insn.operands[1],
              case .memory(.baseOffset(let base, let offset)) = insn.operands[2] else {
            return false
        }
        return base.isStackPointer && offset >= 0 && ((r1.index == 29 && r2.index == 30) || (r1.index >= 19 && r2.index >= 19))
    }

    private func trimARM64FunctionEnd(
        startAddress: VirtualAddress,
        rawEndAddress: VirtualAddress,
        sectionInstructions: [A64DecodedInstruction]
    ) -> VirtualAddress {
        let slice = sliceInstructions(in: sectionInstructions, from: startAddress, to: rawEndAddress)
        guard slice.count >= 2 else { return rawEndAddress }

        // Collect internal branch targets so we never trim away an in-range landing block
        var maxReferencedAddress = startAddress
        for insn in slice {
            switch insn.flow {
            case .unconditionalJump(let tgt), .conditionalBranch(let tgt, _):
                if tgt >= startAddress && tgt < rawEndAddress && tgt > maxReferencedAddress {
                    maxReferencedAddress = tgt
                }
            default:
                break
            }
        }

        var lastKeepIdx = slice.count - 1
        while lastKeepIdx > 0 {
            let candidate = slice[lastKeepIdx]
            if candidate.address <= maxReferencedAddress {
                break
            }
            let isZeroOrTrapPadding = (candidate.rawWord == 0x0000_0000) || (candidate.rawWord == 0xD420_0020 && slice[lastKeepIdx - 1].flow.terminatesBasicBlock)
            let isNopAfterReturn: Bool = {
                guard candidate.mnemonic == .nop else { return false }
                let prev = slice[lastKeepIdx - 1]
                switch prev.flow {
                case .returnControl, .unconditionalJump, .indirectJump:
                    return true
                default:
                    return false
                }
            }()

            if isZeroOrTrapPadding || isNopAfterReturn {
                lastKeepIdx -= 1
            } else {
                break
            }
        }

        return slice[lastKeepIdx].address.adding(UInt64(4))
    }

    // MARK: - WebAssembly 1.0 Bytecode Instructionizer

    /// Lightweight pure-Swift WebAssembly 1.0 bytecode instructionizer so `.wasm` modules produce real
    /// structured instructions, call edges (`call $idx`), conditional branches (`if` / `br_if`), and CFGs!
    private func decodeWasmCodeSectionFallback(
        section: BinarySection,
        bytes: Data,
        image: LoadedBinaryImage,
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) throws -> [A64DecodedInstruction] {
        _ = symbolLookup
        let wasmFuncSymbols = image.symbols
            .filter { $0.kind == .function || $0.kind == .exportedEntry || $0.kind == .importedStub }
            .sorted { $0.address < $1.address }

        guard !bytes.isEmpty else {
            throw MachGraphError.cfgAnalysisError("WASM code section \(section.sectionName) is empty.")
        }

        // Map WASM function indices 0..<N to VirtualAddress in symbol order (imports first, then code functions)
        let importedFuncs = image.symbols.filter { $0.kind == .importedStub }.sorted { $0.address < $1.address }
        let localFuncs = image.symbols
            .filter { ($0.kind == .function || $0.kind == .exportedEntry) && section.addressRange.contains($0.address) }
            .sorted { $0.address < $1.address }
        let orderedWasmFunctionTable = importedFuncs + localFuncs

        var output: [A64DecodedInstruction] = []
        var reader = BinarySliceReader(data: bytes, endianness: .little)
        guard let bodyCount64 = try? reader.readULEB128(), bodyCount64 > 0, bodyCount64 <= 65_536 else {
            throw MachGraphError.malformedHeader("Invalid WASM code section function count in \(section.sectionName).")
        }

        for bodyIdx in 0..<Int(bodyCount64) {
            let bodyRelOffset = reader.position
            guard let bodySize64 = try? reader.readULEB128() else { break }
            let bodySize = Int(bodySize64)
            let bodyStartPos = reader.position
            guard bodySize > 0, bodyStartPos + bodySize <= reader.count else { break }

            let fnBaseVA: VirtualAddress
            if bodyIdx < localFuncs.count {
                fnBaseVA = localFuncs[bodyIdx].address
            } else {
                fnBaseVA = section.vmAddress.adding(UInt64(bodyRelOffset))
            }

            // Skip WASM local variable declarations vector
            if let localDeclGroups = try? reader.readULEB128(), localDeclGroups <= 256 {
                for _ in 0..<localDeclGroups {
                    _ = try? reader.readULEB128()
                    _ = try? reader.readUInt8()
                }
            }

            // Decode WASM stack opcodes at synthetic 4-byte aligned virtual slots if tightly packed,
            // or exact byte offsets inside body range
            var insnOffsetInBody: UInt64 = 0
            while reader.position < bodyStartPos + bodySize {
                let opStart = reader.position
                guard let opcode = try? reader.readUInt8() else { break }
                let insnVA = fnBaseVA.adding(UInt64(opStart - bodyRelOffset))
                _ = insnOffsetInBody
                insnOffsetInBody += 1

                switch opcode {
                case 0x00: // unreachable
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "wasm.unreachable", operands: "", flow: .trapOrSupervisor(immediate: 0)))
                case 0x01: // nop
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "wasm.nop", operands: "", flow: .sequential))
                case 0x02, 0x03, 0x04: // block / loop / if
                    _ = try? reader.readSLEB128() // blocktype
                    let mnem = opcode == 0x02 ? "wasm.block" : (opcode == 0x03 ? "wasm.loop" : "wasm.if")
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: mnem, operands: "", flow: .sequential))
                case 0x0B: // end
                    let isFinalEnd = (reader.position >= bodyStartPos + bodySize)
                    output.append(
                        makeSyntheticWasmInsn(
                            at: insnVA,
                            raw: UInt32(opcode),
                            text: isFinalEnd ? "wasm.end_func" : "wasm.end",
                            operands: "",
                            flow: isFinalEnd ? .returnControl : .sequential
                        )
                    )
                case 0x0F: // return
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "wasm.return", operands: "", flow: .returnControl))
                case 0x0C, 0x0D: // br / br_if
                    let depth = (try? reader.readULEB128()) ?? 0
                    let mnem = opcode == 0x0C ? "wasm.br" : "wasm.br_if"
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: mnem, operands: "\(depth)", flow: .sequential))
                case 0x10: // call <funcidx>
                    let calleeIdx = Int((try? reader.readULEB128()) ?? 0)
                    let targetVA: VirtualAddress
                    let comment: String?
                    if calleeIdx >= 0 && calleeIdx < orderedWasmFunctionTable.count {
                        targetVA = orderedWasmFunctionTable[calleeIdx].address
                        comment = orderedWasmFunctionTable[calleeIdx].demangledName
                    } else if calleeIdx >= 0 && calleeIdx < wasmFuncSymbols.count {
                        targetVA = wasmFuncSymbols[calleeIdx].address
                        comment = wasmFuncSymbols[calleeIdx].demangledName
                    } else {
                        targetVA = VirtualAddress(UInt64(0xFFFF_0000 + calleeIdx * 4))
                        comment = "func[\(calleeIdx)]"
                    }
                    output.append(
                        A64DecodedInstruction(
                            address: insnVA,
                            rawWord: UInt32(opcode),
                            mnemonic: .bl,
                            mnemonicText: "wasm.call",
                            operands: [.branchTarget(targetVA)],
                            operandText: comment ?? "func_\(calleeIdx)",
                            group: .branchAndSystem,
                            flow: .directCall(target: targetVA),
                            autoComment: comment
                        )
                    )
                case 0x20, 0x21, 0x22, 0x23, 0x24: // local/global get/set/tee
                    let idx = (try? reader.readULEB128()) ?? 0
                    let name: String
                    switch opcode {
                    case 0x20: name = "local.get"
                    case 0x21: name = "local.set"
                    case 0x22: name = "local.tee"
                    case 0x23: name = "global.get"
                    default:   name = "global.set"
                    }
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: name, operands: "$\(idx)", flow: .sequential))
                case 0x41: // i32.const
                    let val = (try? reader.readSLEB128()) ?? 0
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "i32.const", operands: "\(val)", flow: .sequential))
                case 0x42: // i64.const
                    let val = (try? reader.readSLEB128()) ?? 0
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "i64.const", operands: "\(val)", flow: .sequential))
                case 0x6A:
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "i32.add", operands: "", flow: .sequential))
                case 0x6B:
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "i32.sub", operands: "", flow: .sequential))
                case 0x73:
                    output.append(makeSyntheticWasmInsn(at: insnVA, raw: UInt32(opcode), text: "i32.xor", operands: "", flow: .sequential))
                default:
                    output.append(
                        makeSyntheticWasmInsn(
                            at: insnVA,
                            raw: UInt32(opcode),
                            text: String(format: "wasm.op_0x%02x", opcode),
                            operands: "",
                            flow: .sequential
                        )
                    )
                }
            }
            try? reader.seek(to: bodyStartPos + bodySize)
        }

        guard !output.isEmpty else {
            throw MachGraphError.cfgAnalysisError("WASM code section \(section.sectionName) decoded zero instructions.")
        }
        return output
    }

    private func makeSyntheticWasmInsn(
        at address: VirtualAddress,
        raw: UInt32,
        text: String,
        operands: String,
        flow: A64FlowSemantics
    ) -> A64DecodedInstruction {
        let mnem: A64Mnemonic
        switch flow {
        case .returnControl: mnem = .ret
        case .trapOrSupervisor: mnem = .brk
        default: mnem = .nop
        }
        return A64DecodedInstruction(
            address: address,
            rawWord: raw,
            mnemonic: mnem,
            mnemonicText: text,
            operands: [],
            operandText: operands,
            group: .dataProcessingReg,
            flow: flow
        )
    }

    // MARK: - Shared Low-Level Byte & Symbol Utilities

    private func selectExecutableSections(in image: LoadedBinaryImage) -> [BinarySection] {
        image.executableSections().sorted { $0.vmAddress < $1.vmAddress }
    }

    private func extractSectionBytes(
        section: BinarySection,
        image: LoadedBinaryImage,
        data: Data?
    ) throws -> Data {
        guard let data, !data.isEmpty else {
            throw MachGraphError.cfgAnalysisError(
                "Missing raw binary bytes for executable section \(section.segmentName),\(section.sectionName)."
            )
        }
        guard section.size > 0, section.kind != .bss else {
            return Data()
        }
        guard let absOff = image.fileOffset(for: section.vmAddress) else {
            throw MachGraphError.cfgAnalysisError(
                "Unable to map virtual address \(section.vmAddress.compactHexString) to file offset for \(section.segmentName),\(section.sectionName)."
            )
        }
        guard section.size <= UInt64(Int.max) else {
            throw MachGraphError.malformedHeader("Executable section \(section.segmentName),\(section.sectionName) size overflows Int.")
        }
        let start = Int(absOff.rawValue)
        let requested = Int(section.size)
        guard start >= 0, start <= data.count, requested <= data.count - start else {
            let avail = start >= 0 && start <= data.count ? (data.count - start) : 0
            throw MachGraphError.unexpectedEOF(offset: absOff.rawValue, requested: requested, available: avail)
        }
        let baseIdx = data.startIndex + start
        return Data(data[baseIdx..<(baseIdx + requested)])
    }

    private func readUnsignedInteger(
        at vmAddress: VirtualAddress,
        byteSize: Int,
        endianness: BinaryEndianness,
        image: LoadedBinaryImage,
        data: Data?
    ) -> UInt64? {
        guard let data, byteSize > 0, byteSize <= 8,
              let fileOff = image.fileOffset(for: vmAddress) else {
            return nil
        }
        let off = Int(fileOff.rawValue)
        guard off >= 0, off + byteSize <= data.count else { return nil }
        let base = data.startIndex + off

        var value: UInt64 = 0
        switch endianness {
        case .little:
            for i in 0..<byteSize {
                value |= UInt64(data[base + i]) << UInt64(i * 8)
            }
        case .big:
            for i in 0..<byteSize {
                value = (value << 8) | UInt64(data[base + i])
            }
        }
        return value
    }

    private func readSignedInteger(
        at vmAddress: VirtualAddress,
        byteSize: Int,
        endianness: BinaryEndianness,
        image: LoadedBinaryImage,
        data: Data?
    ) -> Int64? {
        guard let raw = readUnsignedInteger(
            at: vmAddress,
            byteSize: byteSize,
            endianness: endianness,
            image: image,
            data: data
        ) else {
            return nil
        }
        switch byteSize {
        case 1:
            return Int64(Int8(bitPattern: UInt8(truncatingIfNeeded: raw)))
        case 2:
            return Int64(Int16(bitPattern: UInt16(truncatingIfNeeded: raw)))
        case 4:
            return Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: raw)))
        case 8:
            return Int64(bitPattern: raw)
        default:
            return nil
        }
    }

    private func makeDefaultSymbolLookup(for image: LoadedBinaryImage) -> (@Sendable (VirtualAddress) -> String?) {
        var map: [VirtualAddress: String] = [:]
        for sym in image.symbols where !sym.name.isEmpty {
            if map[sym.address] == nil {
                map[sym.address] = sym.demangledName
            }
        }
        for cls in image.objcClasses {
            for m in cls.methods where m.implementationAddress.rawValue != 0 {
                if map[m.implementationAddress] == nil {
                    map[m.implementationAddress] = "\(m.isClassMethod ? "+" : "-")[\(cls.name) \(m.selector)]"
                }
            }
        }
        for fixup in image.chainedFixups {
            if let sym = fixup.symbolName, !sym.isEmpty, map[fixup.location] == nil {
                map[fixup.location] = sym
            }
        }
        for s in image.strings where map[s.address] == nil {
            let preview = s.value.count > 36 ? String(s.value.prefix(36)) + "..." : s.value
            let escaped = preview.replacingOccurrences(of: "\n", with: "\\n")
            map[s.address] = "\"\(escaped)\""
        }
        let immutableMap = map
        return { addr in immutableMap[addr] }
    }

    private func mergeIdiomAutoComments(
        instructions: [A64DecodedInstruction],
        idioms: [A64RecognizedIdiom]
    ) -> [A64DecodedInstruction] {
        guard !idioms.isEmpty else { return instructions }
        var notesByAddress: [VirtualAddress: [String]] = [:]
        for idiom in idioms {
            notesByAddress[idiom.completingAddress, default: []].append(idiom.summary)
        }
        return instructions.map { insn in
            guard let extra = notesByAddress[insn.address], !extra.isEmpty else { return insn }
            let joined = extra.joined(separator: "; ")
            let combined: String
            if let existing = insn.autoComment, !existing.isEmpty {
                if existing.contains(joined) {
                    return insn
                }
                combined = "\(existing) | \(joined)"
            } else {
                combined = joined
            }
            return A64DecodedInstruction(
                address: insn.address,
                rawWord: insn.rawWord,
                mnemonic: insn.mnemonic,
                mnemonicText: insn.mnemonicText,
                operands: insn.operands,
                operandText: insn.operandText,
                group: insn.group,
                flow: insn.flow,
                readsRegisters: insn.readsRegisters,
                writesRegisters: insn.writesRegisters,
                readsFlags: insn.readsFlags,
                writesFlags: insn.writesFlags,
                autoComment: combined
            )
        }
    }

    private func normalizeInstructionAddress(_ address: VirtualAddress, architecture: CPUArchitecture) -> VirtualAddress {
        if architecture.isARM64Family {
            return VirtualAddress(address.rawValue & ~UInt64(0x3))
        }
        return address
    }

    private func isCompilerLocalBlockLabel(_ name: String) -> Bool {
        name.hasPrefix("LBB") || name.hasPrefix("ltmp") || name.hasPrefix(".LBB") || name.hasPrefix(".Ltmp")
    }

    private func prefersSymbol(_ candidate: BinarySymbol, overKind existingKind: SymbolKind, existingName: String) -> Bool {
        if existingName.hasPrefix("sub_") && !candidate.name.hasPrefix("sub_") {
            return true
        }
        if existingKind == .localSymbol && candidate.kind != .localSymbol {
            return true
        }
        return false
    }

    private func computeBoundaryConfidence(sources: [FunctionDiscoverySource]) -> Double {
        if sources.contains(where: \.isAuthoritative) {
            return 1.0
        }
        if sources.contains(.tailBranchTarget) && sources.contains(.prologueHeuristic) {
            return 0.92
        }
        if sources.contains(.tailBranchTarget) {
            return 0.85
        }
        if sources.contains(.prologueHeuristic) {
            return 0.78
        }
        return 0.65
    }

    private func synthesizeFunctionName(
        at startAddress: VirtualAddress,
        entryPoint: VirtualAddress?,
        isStubSection: Bool,
        symbolInfo: (raw: String, demangled: String, kind: SymbolKind)?,
        objcMethodName: String?,
        stubTargetSymbol: String?
    ) -> (raw: String, demangled: String) {
        if let sym = symbolInfo, !sym.raw.isEmpty {
            return (sym.raw, sym.demangled)
        }
        if let objc = objcMethodName, !objc.isEmpty {
            return (objc, objc)
        }
        if let stubSym = stubTargetSymbol, !stubSym.isEmpty {
            let rawStub = stubSym.hasSuffix("$stub") ? stubSym : "\(stubSym)$stub"
            let demStub = demangler.demangle(rawStub)
            return (rawStub, demStub)
        }
        if let ep = entryPoint, ep == startAddress {
            return ("_entry", "entry")
        }
        let hex = String(startAddress.rawValue, radix: 16)
        if isStubSection {
            return ("stub_\(hex)", "stub_\(hex)")
        }
        return ("sub_\(hex)", "sub_\(hex)")
    }

    private func extractAddImmediate(_ operand: A64Operand) -> Int64? {
        switch operand {
        case .unsignedImmediate(let v):
            return Int64(bitPattern: v)
        case .immediate(let s):
            return s
        case .shiftedImmediate(let v, let shift):
            return Int64(bitPattern: v << Int(shift))
        default:
            return nil
        }
    }

    private func extractRegisterAndShift(_ operand: A64Operand) -> (register: A64Register, leftShift: Int)? {
        switch operand {
        case .register(let r):
            return (r, 0)
        case .shiftedRegister(let r, let shiftExt):
            switch shiftExt {
            case .lsl(let n), .uxtw(let n), .uxtx(let n), .sxtw(let n), .sxtx(let n), .uxth(let n), .uxtb(let n), .sxth(let n), .sxtb(let n):
                return (r, Int(n))
            default:
                return nil
            }
        default:
            return nil
        }
    }

    private func mergeUniqueAddresses(_ first: [VirtualAddress], _ second: [VirtualAddress]) -> [VirtualAddress] {
        var seen = Set<VirtualAddress>()
        var out: [VirtualAddress] = []
        for a in first + second {
            if seen.insert(a).inserted {
                out.append(a)
            }
        }
        return out
    }

    private func binarySearchFloor(in sortedAddresses: [VirtualAddress], value: VirtualAddress) -> VirtualAddress? {
        guard !sortedAddresses.isEmpty else { return nil }
        var lo = 0
        var hi = sortedAddresses.count - 1
        var best: VirtualAddress?
        while lo <= hi {
            let mid = (lo + hi) >> 1
            if sortedAddresses[mid] <= value {
                best = sortedAddresses[mid]
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return best
    }

    private func binarySearchExactInstruction(
        in instructions: [A64DecodedInstruction],
        address: VirtualAddress
    ) -> Int? {
        var lo = 0
        var hi = instructions.count - 1
        while lo <= hi {
            let mid = (lo + hi) >> 1
            let midAddr = instructions[mid].address
            if midAddr == address {
                return mid
            } else if midAddr < address {
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return nil
    }

    public func sliceInstructions(
        in sortedSectionInstructions: [A64DecodedInstruction],
        from startAddress: VirtualAddress,
        to endAddress: VirtualAddress
    ) -> [A64DecodedInstruction] {
        guard !sortedSectionInstructions.isEmpty, endAddress > startAddress else { return [] }
        // Lower bound binary search for startAddress
        var lo = 0
        var hi = sortedSectionInstructions.count
        while lo < hi {
            let mid = (lo + hi) >> 1
            if sortedSectionInstructions[mid].address < startAddress {
                lo = mid + 1
            } else {
                hi = mid
            }
        }
        let firstIdx = lo
        guard firstIdx < sortedSectionInstructions.count else { return [] }

        var lastIdx = firstIdx
        while lastIdx < sortedSectionInstructions.count && sortedSectionInstructions[lastIdx].address < endAddress {
            lastIdx += 1
        }
        guard lastIdx > firstIdx else { return [] }
        return Array(sortedSectionInstructions[firstIdx..<lastIdx])
    }
}
