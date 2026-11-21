import Foundation
import MachGraphModels
import MachA64Decoder

// MARK: - Authoritative Known Noreturn Symbols & Bounded Fixed-Point Propagation

/// Canonical table of C / POSIX / BSD-Darwin / C++ ABI / Objective-C / Swift runtime functions
/// guaranteed never to return to their caller (`_Noreturn` / `__dead2` / `[[noreturn]]` / `-> Never`).
///
/// Sources:
/// - ISO C11 / C23 `<stdlib.h>`, `<setjmp.h>`, `<threads.h>`:
///   `abort`, `exit`, `_Exit`, `quick_exit`, `longjmp`, `thrd_exit`
/// - POSIX.1-2017 `<unistd.h>`, `<setjmp.h>`, `<pthread.h>`:
///   `_exit`, `_longjmp`, `siglongjmp`, `pthread_exit`
/// - BSD & Apple Darwin `<err.h>`, `<assert.h>`, `<os/assumes.h>`, `<System/sys/reason.h>`,
///   `<dispatch/dispatch.h>`, and LLVM compiler-rt stack protector:
///   `err`, `errx`, `errc`, `verr`, `verrx`, `verrc`, `__stack_chk_fail`, `__assert_rtn`,
///   `__assert_fail`, `abort_report_np`, `abort_with_reason`, `abort_with_payload`,
///   `exit_with_payload`, `terminate_with_reason`, `terminate_with_payload`,
///   `_os_crash`, `_os_crash_fmt`, `_os_crash_msg`, `dispatch_main`
/// - Itanium C++ ABI & libc++abi `<cxxabi.h>`, `<exception>`:
///   `__cxa_throw`, `__cxa_rethrow`, `__cxa_bad_cast`, `__cxa_bad_typeid`,
///   `__cxa_pure_virtual`, `__cxa_deleted_virtual`, `__cxa_call_unexpected`,
///   `__cxa_call_terminate`, `__clang_call_terminate`, `_ZSt9terminatev`,
///   `_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE`
/// - Apple Objective-C Runtime `<objc/objc-exception.h>`:
///   `objc_exception_throw`, `objc_exception_rethrow`, `objc_terminate`
/// - Swift Runtime `swift/Runtime/Debug.h` & `ErrorObject.h`:
///   `swift_unexpectedError`, `swift_errorInMain`, `swift_fatalError`,
///   `swift_deletedMethodError`, `swift_deletedAsyncMethodError`,
///   `_swift_stdlib_reportFatalError`, `_swift_stdlib_reportFatalErrorInFile`,
///   `_swift_stdlib_reportUnimplementedInitializer`, `_swift_stdlib_reportUnimplementedInitializerInFile`
public enum KnownNoreturnSymbols {
    public static let maxPropagationIterations: Int = 16

    public static let unprefixedNames: Set<String> = [
        // ISO C & POSIX
        "abort", "exit", "_exit", "_Exit", "quick_exit", "thrd_exit",
        "longjmp", "_longjmp", "siglongjmp", "pthread_exit",
        // BSD / Darwin Libsystem & compiler-rt SSP
        "err", "errx", "errc", "verr", "verrx", "verrc",
        "__stack_chk_fail", "__assert_rtn", "__assert_fail",
        "abort_report_np", "abort_with_reason", "abort_with_payload",
        "exit_with_payload", "terminate_with_reason", "terminate_with_payload",
        "_os_crash", "_os_crash_fmt", "_os_crash_msg", "dispatch_main",
        // Itanium C++ ABI / libc++abi
        "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid",
        "__cxa_pure_virtual", "__cxa_deleted_virtual",
        "__cxa_call_unexpected", "__cxa_call_terminate", "__clang_call_terminate",
        "_ZSt9terminatev",
        "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE",
        // Objective-C Runtime
        "objc_exception_throw", "objc_exception_rethrow", "objc_terminate",
        // Swift Runtime
        "swift_unexpectedError", "swift_errorInMain", "swift_fatalError",
        "swift_deletedMethodError", "swift_deletedAsyncMethodError",
        "_swift_stdlib_reportFatalError", "_swift_stdlib_reportFatalErrorInFile",
        "_swift_stdlib_reportUnimplementedInitializer", "_swift_stdlib_reportUnimplementedInitializerInFile"
    ]

    /// Checks whether a Mach-O / ELF / stub symbol name refers to a known `noreturn` function.
    public static func matchesSymbolName(_ rawName: String) -> Bool {
        var cleaned = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return false }

        if cleaned.hasSuffix("$stub") {
            cleaned.removeLast(5)
        }
        if let atRange = cleaned.range(of: "@") {
            cleaned = String(cleaned[..<atRange.lowerBound])
        }
        if let dollarIdx = cleaned.firstIndex(of: "$") {
            let suffix = cleaned[dollarIdx...]
            if suffix.hasPrefix("$UNIX") || suffix.hasPrefix("$DARWIN") || suffix.hasPrefix("$INODE") || suffix.hasPrefix("$NOCANCEL") {
                cleaned = String(cleaned[..<dollarIdx])
            }
        }
        guard !cleaned.isEmpty else { return false }

        if unprefixedNames.contains(cleaned) {
            return true
        }
        if cleaned.hasPrefix("_") {
            let strippedOnce = String(cleaned.dropFirst())
            if unprefixedNames.contains(strippedOnce) {
                return true
            }
        }
        return false
    }

    /// Computes all `noreturn` function entry addresses in `image` by seeding imported/symbol-named
    /// noreturn functions and running bounded fixed-point propagation (`maxIterations`) over internal
    /// wrapper functions whose every reachable path terminates in a noreturn call, noreturn tail-jump, or trap.
    public static func resolveNoreturnAddresses(
        image: LoadedBinaryImage,
        boundaries: [DiscoveredFunctionBoundary],
        instructionsByFunction: [VirtualAddress: [A64DecodedInstruction]],
        jumpTablesByFunction: [VirtualAddress: [SwitchJumpTable]] = [:],
        maxIterations: Int = maxPropagationIterations
    ) -> Set<VirtualAddress> {
        let isARM64 = image.architecture.isARM64Family
        func norm(_ addr: VirtualAddress) -> VirtualAddress {
            isARM64 ? VirtualAddress(addr.rawValue & ~UInt64(0x3)) : addr
        }

        var noreturnSet = Set<VirtualAddress>()
        for sym in image.symbols where sym.address != .zero {
            if matchesSymbolName(sym.name) {
                noreturnSet.insert(norm(sym.address))
            }
        }
        for boundary in boundaries {
            if matchesSymbolName(boundary.name) ||
               (boundary.resolvedGOTTargetSymbol.map(matchesSymbolName) == true) {
                noreturnSet.insert(boundary.startAddress)
            }
        }

        guard isARM64, maxIterations > 0, !noreturnSet.isEmpty else {
            return noreturnSet
        }

        var definitelyCanReturn = Set<VirtualAddress>()
        let cap = max(1, maxIterations)

        for _ in 0..<cap {
            var addedInRound = false
            for boundary in boundaries {
                let fnStart = boundary.startAddress
                if noreturnSet.contains(fnStart) || definitelyCanReturn.contains(fnStart) {
                    continue
                }
                guard let insns = instructionsByFunction[fnStart], !insns.isEmpty else {
                    definitelyCanReturn.insert(fnStart)
                    continue
                }
                let jts = jumpTablesByFunction[fnStart] ?? []
                switch evaluateReturnability(
                    functionStart: fnStart,
                    instructions: insns,
                    jumpTables: jts,
                    knownNoreturn: noreturnSet
                ) {
                case .definitelyNoreturn:
                    noreturnSet.insert(fnStart)
                    addedInRound = true
                case .definitelyReturnsWithoutUnresolvedCalls:
                    definitelyCanReturn.insert(fnStart)
                case .mayReturnViaUnresolvedCall:
                    break
                }
            }
            if !addedInRound {
                break
            }
        }

        return noreturnSet
    }

    private enum ReturnabilityVerdict {
        case definitelyNoreturn
        case definitelyReturnsWithoutUnresolvedCalls
        case mayReturnViaUnresolvedCall
    }

    private static func evaluateReturnability(
        functionStart: VirtualAddress,
        instructions: [A64DecodedInstruction],
        jumpTables: [SwitchJumpTable],
        knownNoreturn: Set<VirtualAddress>
    ) -> ReturnabilityVerdict {
        var addrToIdx: [VirtualAddress: Int] = [:]
        addrToIdx.reserveCapacity(instructions.count)
        for (i, insn) in instructions.enumerated() where addrToIdx[insn.address] == nil {
            addrToIdx[insn.address] = i
        }

        var jtByDispatch: [VirtualAddress: SwitchJumpTable] = [:]
        for jt in jumpTables {
            jtByDispatch[jt.dispatchInstructionAddress] = jt
        }

        let entryIdx = addrToIdx[functionStart] ?? 0
        var visited = [Bool](repeating: false, count: instructions.count)
        var worklist: [Int] = [entryIdx]
        visited[entryIdx] = true
        var sawUnresolvedCallOrJump = false
        var canReturnOrFallOff = false

        func enqueue(_ idx: Int) {
            if !visited[idx] {
                visited[idx] = true
                worklist.append(idx)
            }
        }

        while let idx = worklist.popLast() {
            let insn = instructions[idx]
            switch insn.flow {
            case .returnControl:
                canReturnOrFallOff = true

            case .sequential:
                if idx + 1 < instructions.count {
                    enqueue(idx + 1)
                } else {
                    canReturnOrFallOff = true
                }

            case .indirectCall:
                sawUnresolvedCallOrJump = true
                if idx + 1 < instructions.count {
                    enqueue(idx + 1)
                } else {
                    canReturnOrFallOff = true
                }

            case .directCall(let target):
                if knownNoreturn.contains(target) {
                    // Path terminates at noreturn callee; do not fall through to idx + 1.
                    break
                }
                sawUnresolvedCallOrJump = true
                if idx + 1 < instructions.count {
                    enqueue(idx + 1)
                } else {
                    canReturnOrFallOff = true
                }

            case .unconditionalJump(let target):
                if let tgtIdx = addrToIdx[target] {
                    enqueue(tgtIdx)
                } else if knownNoreturn.contains(target) {
                    break
                } else {
                    sawUnresolvedCallOrJump = true
                    canReturnOrFallOff = true
                }

            case .conditionalBranch(let target, _):
                if let tgtIdx = addrToIdx[target] {
                    enqueue(tgtIdx)
                } else if !knownNoreturn.contains(target) {
                    sawUnresolvedCallOrJump = true
                    canReturnOrFallOff = true
                }
                if idx + 1 < instructions.count {
                    enqueue(idx + 1)
                } else {
                    canReturnOrFallOff = true
                }

            case .indirectJump:
                if let jt = jtByDispatch[insn.address], !jt.targetAddresses.isEmpty {
                    for caseTarget in jt.targetAddresses {
                        if let cIdx = addrToIdx[caseTarget] {
                            enqueue(cIdx)
                        } else if !knownNoreturn.contains(caseTarget) {
                            sawUnresolvedCallOrJump = true
                            canReturnOrFallOff = true
                        }
                    }
                } else {
                    canReturnOrFallOff = true
                }

            case .trapOrSupervisor(let imm):
                if insn.mnemonic == .svc {
                    let isExitSyscall = (imm == 0x80 && idx > 0 && isDarwinExitSyscallSetup(instructions[idx - 1]))
                    if !isExitSyscall {
                        if idx + 1 < instructions.count {
                            enqueue(idx + 1)
                        } else {
                            canReturnOrFallOff = true
                        }
                    }
                }
                // brk, hlt, udf, and exit svc do not return.
            }

            if canReturnOrFallOff && !sawUnresolvedCallOrJump {
                return .definitelyReturnsWithoutUnresolvedCalls
            }
        }

        if !canReturnOrFallOff {
            return .definitelyNoreturn
        }
        return sawUnresolvedCallOrJump ? .mayReturnViaUnresolvedCall : .definitelyReturnsWithoutUnresolvedCalls
    }

    private static func isDarwinExitSyscallSetup(_ prev: A64DecodedInstruction) -> Bool {
        guard (prev.mnemonic == .mov || prev.mnemonic == .movz),
              prev.operands.count == 2,
              case .register(let rd) = prev.operands[0],
              rd.index == 16 else {
            return false
        }
        switch prev.operands[1] {
        case .unsignedImmediate(let v) where v == 1 || v == 431:
            return true
        case .immediate(let v) where v == 1 || v == 431:
            return true
        default:
            return false
        }
    }
}

// MARK: - Directed Block Pair & CFG Builder Configuration

public struct CFGDirectedPair: Sendable, Codable, Hashable {
    public let sourceBlockID: Int
    public let targetBlockID: Int

    public init(sourceBlockID: Int, targetBlockID: Int) {
        self.sourceBlockID = sourceBlockID
        self.targetBlockID = targetBlockID
    }
}

public struct CFGBuilderConfiguration: Sendable, Codable, Hashable {
    public var treatSupervisorCallsAsBlockBoundaries: Bool
    public var splitBasicBlocksAfterDirectCalls: Bool
    public var pruneDeadAlignmentPaddingBlocks: Bool
    public var pruneAllUnreachableBlocks: Bool

    public init(
        treatSupervisorCallsAsBlockBoundaries: Bool = true,
        splitBasicBlocksAfterDirectCalls: Bool = false,
        pruneDeadAlignmentPaddingBlocks: Bool = true,
        pruneAllUnreachableBlocks: Bool = false
    ) {
        self.treatSupervisorCallsAsBlockBoundaries = treatSupervisorCallsAsBlockBoundaries
        self.splitBasicBlocksAfterDirectCalls = splitBasicBlocksAfterDirectCalls
        self.pruneDeadAlignmentPaddingBlocks = pruneDeadAlignmentPaddingBlocks
        self.pruneAllUnreachableBlocks = pruneAllUnreachableBlocks
    }

    public static let standard = CFGBuilderConfiguration()
}

// MARK: - Structural Complexity & Intermediate CFG Representation

public struct CFGStructuralMetrics: Sendable, Codable, Hashable {
    public let blockCount: Int
    public let edgeCount: Int
    public let entryBlockCount: Int
    public let exitBlockCount: Int
    public let conditionalBranchBlockCount: Int
    public let switchDispatchBlockCount: Int
    public let unreachableBlockCount: Int
    public let instructionCount: Int
    public let cyclomaticComplexity: Int
    public let maxInDegree: Int
    public let maxOutDegree: Int
    public let averageInstructionsPerBlock: Double

    public init(
        blockCount: Int,
        edgeCount: Int,
        entryBlockCount: Int,
        exitBlockCount: Int,
        conditionalBranchBlockCount: Int,
        switchDispatchBlockCount: Int,
        unreachableBlockCount: Int,
        instructionCount: Int,
        cyclomaticComplexity: Int,
        maxInDegree: Int,
        maxOutDegree: Int,
        averageInstructionsPerBlock: Double
    ) {
        self.blockCount = blockCount
        self.edgeCount = edgeCount
        self.entryBlockCount = entryBlockCount
        self.exitBlockCount = exitBlockCount
        self.conditionalBranchBlockCount = conditionalBranchBlockCount
        self.switchDispatchBlockCount = switchDispatchBlockCount
        self.unreachableBlockCount = unreachableBlockCount
        self.instructionCount = instructionCount
        self.cyclomaticComplexity = cyclomaticComplexity
        self.maxInDegree = maxInDegree
        self.maxOutDegree = maxOutDegree
        self.averageInstructionsPerBlock = averageInstructionsPerBlock
    }
}

public struct BuiltFunctionCFG: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { functionAddress.rawValue }
    public let functionAddress: VirtualAddress
    public let endAddress: VirtualAddress
    public let name: String
    public let demangledName: String
    public let blocks: [BasicBlock]
    public let edges: [CFGEdge]
    public let jumpTables: [SwitchJumpTable]
    public let prologueAnalysis: A64PrologueEpilogueAnalysis
    public let isLeaf: Bool
    public let isThunk: Bool
    public let usesPAC: Bool
    public let stackFrameBytes: Int
    public let cyclomaticComplexity: Int
    public let unreachableBlockIDs: [Int]
    public let tailCallTargets: [VirtualAddress]
    public let metrics: CFGStructuralMetrics

    public init(
        functionAddress: VirtualAddress,
        endAddress: VirtualAddress,
        name: String,
        demangledName: String? = nil,
        blocks: [BasicBlock],
        edges: [CFGEdge],
        jumpTables: [SwitchJumpTable] = [],
        prologueAnalysis: A64PrologueEpilogueAnalysis,
        isLeaf: Bool,
        isThunk: Bool,
        usesPAC: Bool,
        stackFrameBytes: Int,
        cyclomaticComplexity: Int,
        unreachableBlockIDs: [Int] = [],
        tailCallTargets: [VirtualAddress] = [],
        metrics: CFGStructuralMetrics
    ) {
        self.functionAddress = functionAddress
        self.endAddress = endAddress
        self.name = name
        self.demangledName = demangledName ?? name
        self.blocks = blocks
        self.edges = edges
        self.jumpTables = jumpTables
        self.prologueAnalysis = prologueAnalysis
        self.isLeaf = isLeaf
        self.isThunk = isThunk
        self.usesPAC = usesPAC
        self.stackFrameBytes = stackFrameBytes
        self.cyclomaticComplexity = cyclomaticComplexity
        self.unreachableBlockIDs = unreachableBlockIDs
        self.tailCallTargets = tailCallTargets
        self.metrics = metrics
    }
}

// MARK: - Basic Block Partitioning & Control Flow Graph Construction Engine

public struct CFGBuilderEngine: Sendable {
    public let configuration: CFGBuilderConfiguration
    private let idiomRecognizer: A64IdiomRecognizer

    public init(configuration: CFGBuilderConfiguration = .standard) {
        self.configuration = configuration
        self.idiomRecognizer = A64IdiomRecognizer()
    }

    // MARK: - Primary CFG Construction Entry Points

    /// Builds a complete `BuiltFunctionCFG` from a `DiscoveredFunctionBoundary`, decoded instructions, and recovered switch tables.
    public func buildCFG(
        boundary: DiscoveredFunctionBoundary,
        instructions: [A64DecodedInstruction],
        jumpTables: [SwitchJumpTable] = [],
        jumpTableDescriptors: [SwitchJumpTableDescriptor] = [],
        noreturnAddresses: Set<VirtualAddress> = [],
        defaultInstructionByteStride: UInt64 = 4
    ) -> BuiltFunctionCFG {
        buildCFG(
            functionAddress: boundary.startAddress,
            endAddress: boundary.endAddress,
            name: boundary.name,
            demangledName: boundary.demangledName,
            instructions: instructions,
            jumpTables: jumpTables,
            jumpTableDescriptors: jumpTableDescriptors,
            noreturnAddresses: noreturnAddresses,
            isStubSection: boundary.isStubSection,
            defaultInstructionByteStride: defaultInstructionByteStride
        )
    }

    /// Leader-identification pass + basic block partitioning + control-flow edge construction + ABI frame/PAC inspection.
    public func buildCFG(
        functionAddress: VirtualAddress,
        endAddress: VirtualAddress? = nil,
        name: String,
        demangledName: String? = nil,
        instructions: [A64DecodedInstruction],
        jumpTables: [SwitchJumpTable] = [],
        jumpTableDescriptors: [SwitchJumpTableDescriptor] = [],
        noreturnAddresses: Set<VirtualAddress> = [],
        isStubSection: Bool = false,
        defaultInstructionByteStride: UInt64 = 4
    ) -> BuiltFunctionCFG {
        let sortedInsns = instructions.sorted { $0.address < $1.address }
        let resolvedEndAddress: VirtualAddress = {
            if let explicit = endAddress, explicit > functionAddress {
                return explicit
            }
            if let last = sortedInsns.last {
                return last.address.adding(max(1, defaultInstructionByteStride))
            }
            return functionAddress.adding(max(1, defaultInstructionByteStride))
        }()

        let effectiveJumpTables = jumpTables.isEmpty
            ? jumpTableDescriptors.map(\.jumpTable)
            : jumpTables

        let partitioned = partitionBasicBlocks(
            functionAddress: functionAddress,
            endAddress: resolvedEndAddress,
            instructions: sortedInsns,
            jumpTables: effectiveJumpTables,
            jumpTableDescriptors: jumpTableDescriptors,
            noreturnAddresses: noreturnAddresses,
            defaultInstructionByteStride: defaultInstructionByteStride
        )

        var blocks = partitioned.blocks
        var edges = partitioned.edges
        var unreachableIDs = partitioned.unreachableBlockIDs

        // Optionally prune unreachable zero/NOP alignment blocks or all unreachable blocks
        if !unreachableIDs.isEmpty && (configuration.pruneDeadAlignmentPaddingBlocks || configuration.pruneAllUnreachableBlocks) {
            let pruned = pruneSelectedUnreachableBlocks(
                blocks: blocks,
                edges: edges,
                unreachableIDs: Set(unreachableIDs),
                pruneAll: configuration.pruneAllUnreachableBlocks
            )
            blocks = pruned.blocks
            edges = pruned.edges
            unreachableIDs = pruned.remainingUnreachableIDs
        }

        // Analyze function prologue/epilogue, stack allocation, PAC usage, leaf status, and thunk nature
        let prologueInfo = idiomRecognizer.analyzePrologueAndEpilogue(in: sortedInsns)

        let hasAnyCallInstruction = sortedInsns.contains { insn in
            switch insn.flow {
            case .directCall, .indirectCall:
                return true
            default:
                return false
            }
        }

        let hasPACInstruction = prologueInfo.usesPAC || sortedInsns.contains { insn in
            insn.group == .pacPointerAuth
        }

        let detectedIsThunk = computeIsThunk(
            isStubSection: isStubSection,
            prologueInfo: prologueInfo,
            blocks: blocks,
            instructions: sortedInsns,
            tailCallTargets: partitioned.tailCallTargets
        )

        let detectedIsLeaf = !hasAnyCallInstruction && prologueInfo.isLeaf && (!detectedIsThunk || partitioned.tailCallTargets.isEmpty)
        let stackBytes = max(prologueInfo.stackFrameBytes, scanSupplementaryStackAllocation(in: sortedInsns))

        let rpo = computeReversePostOrder(blocks: blocks, entryBlockID: blocks.first?.id)
        let metrics = computeStructuralMetrics(
            blocks: blocks,
            edges: edges,
            reachableBlockIDs: rpo.reachableBlockIDs
        )

        return BuiltFunctionCFG(
            functionAddress: functionAddress,
            endAddress: resolvedEndAddress,
            name: name,
            demangledName: demangledName ?? name,
            blocks: blocks,
            edges: edges,
            jumpTables: effectiveJumpTables,
            prologueAnalysis: prologueInfo,
            isLeaf: detectedIsLeaf,
            isThunk: detectedIsThunk,
            usesPAC: hasPACInstruction,
            stackFrameBytes: stackBytes,
            cyclomaticComplexity: metrics.cyclomaticComplexity,
            unreachableBlockIDs: unreachableIDs,
            tailCallTargets: partitioned.tailCallTargets,
            metrics: metrics
        )
    }

    // MARK: - Core Leader Identification & Block/Edge Partitioning

    public func partitionBasicBlocks(
        functionAddress: VirtualAddress,
        endAddress: VirtualAddress,
        instructions: [A64DecodedInstruction],
        jumpTables: [SwitchJumpTable] = [],
        jumpTableDescriptors: [SwitchJumpTableDescriptor] = [],
        noreturnAddresses: Set<VirtualAddress> = [],
        defaultInstructionByteStride: UInt64 = 4
    ) -> (
        blocks: [BasicBlock],
        edges: [CFGEdge],
        tailCallTargets: [VirtualAddress],
        unreachableBlockIDs: [Int]
    ) {
        // Handle degenerate empty instruction list with a single synthetic entry/exit block
        guard !instructions.isEmpty else {
            let emptyEntry = BasicBlock(
                id: 0,
                functionAddress: functionAddress,
                startAddress: functionAddress,
                endAddress: max(endAddress, functionAddress.adding(UInt64(4))),
                instructions: [],
                predecessorIDs: [],
                successorIDs: [],
                isEntry: true,
                isExit: true,
                loopDepth: 0
            )
            return ([emptyEntry], [], [], [])
        }

        // Index instruction addresses -> array index
        var addressToIndex: [VirtualAddress: Int] = [:]
        addressToIndex.reserveCapacity(instructions.count)
        for (idx, insn) in instructions.enumerated() {
            if addressToIndex[insn.address] == nil {
                addressToIndex[insn.address] = idx
            }
        }

        // Index jump tables by their indirect dispatch instruction address (`br xN`)
        var jumpTableByDispatch: [VirtualAddress: SwitchJumpTable] = [:]
        for jt in jumpTables {
            jumpTableByDispatch[jt.dispatchInstructionAddress] = jt
        }

        var descriptorByDispatch: [VirtualAddress: SwitchJumpTableDescriptor] = [:]
        for desc in jumpTableDescriptors {
            descriptorByDispatch[desc.jumpTable.dispatchInstructionAddress] = desc
            if jumpTableByDispatch[desc.jumpTable.dispatchInstructionAddress] == nil {
                jumpTableByDispatch[desc.jumpTable.dispatchInstructionAddress] = desc.jumpTable
            }
        }

        // Step 1: Identify all basic block leader instruction indices
        var leaderIndices: Set<Int> = [0]
        if let explicitEntryIdx = addressToIndex[functionAddress] {
            leaderIndices.insert(explicitEntryIdx)
        }

        for (idx, insn) in instructions.enumerated() {
            // Also split if there is an address gap (e.g. stripped inline jump-table data) between idx and idx + 1
            if defaultInstructionByteStride == 4,
               idx + 1 < instructions.count,
               instructions[idx + 1].address != insn.address.adding(UInt64(4)) {
                leaderIndices.insert(idx + 1)
            }

            switch insn.flow {
            case .sequential:
                break

            case .directCall(let target):
                if (configuration.splitBasicBlocksAfterDirectCalls || noreturnAddresses.contains(target)) && (idx + 1 < instructions.count) {
                    leaderIndices.insert(idx + 1)
                }

            case .indirectCall:
                if configuration.splitBasicBlocksAfterDirectCalls && (idx + 1 < instructions.count) {
                    leaderIndices.insert(idx + 1)
                }

            case .unconditionalJump(let target):
                if let tgtIdx = addressToIndex[target] {
                    leaderIndices.insert(tgtIdx)
                }
                if idx + 1 < instructions.count {
                    leaderIndices.insert(idx + 1)
                }

            case .conditionalBranch(let target, _):
                if let tgtIdx = addressToIndex[target] {
                    leaderIndices.insert(tgtIdx)
                }
                if idx + 1 < instructions.count {
                    leaderIndices.insert(idx + 1)
                }

            case .indirectJump:
                if let jt = jumpTableByDispatch[insn.address] {
                    for caseTarget in jt.targetAddresses {
                        if let tgtIdx = addressToIndex[caseTarget] {
                            leaderIndices.insert(tgtIdx)
                        }
                    }
                }
                if let desc = descriptorByDispatch[insn.address],
                   let defTarget = desc.defaultTargetAddress,
                   let defIdx = addressToIndex[defTarget] {
                    leaderIndices.insert(defIdx)
                }
                if idx + 1 < instructions.count {
                    leaderIndices.insert(idx + 1)
                }

            case .returnControl:
                if idx + 1 < instructions.count {
                    leaderIndices.insert(idx + 1)
                }

            case .trapOrSupervisor:
                if configuration.treatSupervisorCallsAsBlockBoundaries ||
                   insn.mnemonic == .brk ||
                   insn.mnemonic == .hlt ||
                   insn.mnemonicText == "udf" {
                    if idx + 1 < instructions.count {
                        leaderIndices.insert(idx + 1)
                    }
                }
            }
        }

        // Step 2: Slice instructions into preliminary basic blocks (ensuring entry block is marked accurately)
        let sortedLeaderIndices = leaderIndices.sorted()
        let entryLeaderIdx = addressToIndex[functionAddress] ?? 0

        struct RawBlockSpan {
            let blockID: Int
            let firstInsnIdx: Int
            let lastInsnIdxExclusive: Int
            let startAddress: VirtualAddress
            let endAddress: VirtualAddress
            let slice: [A64DecodedInstruction]
            let isEntry: Bool
        }

        var rawSpans: [RawBlockSpan] = []
        rawSpans.reserveCapacity(sortedLeaderIndices.count)

        // Place entry block at id == 0 if entryLeaderIdx == 0 (standard case); if entryLeaderIdx > 0, mark isEntry accurately
        for bIdx in 0..<sortedLeaderIndices.count {
            let startI = sortedLeaderIndices[bIdx]
            let endI = (bIdx + 1 < sortedLeaderIndices.count) ? sortedLeaderIndices[bIdx + 1] : instructions.count
            let blockSlice = Array(instructions[startI..<endI])
            let bStart = blockSlice[0].address
            let lastInsnEnd = blockSlice[blockSlice.count - 1].address.adding(max(1, defaultInstructionByteStride))
            let bEnd: VirtualAddress
            if defaultInstructionByteStride == 4 {
                bEnd = lastInsnEnd
            } else if bIdx + 1 < sortedLeaderIndices.count {
                bEnd = instructions[sortedLeaderIndices[bIdx + 1]].address
            } else {
                bEnd = max(lastInsnEnd, endAddress)
            }
            let isEntryBlock = (startI == entryLeaderIdx)
            rawSpans.append(
                RawBlockSpan(
                    blockID: bIdx,
                    firstInsnIdx: startI,
                    lastInsnIdxExclusive: endI,
                    startAddress: bStart,
                    endAddress: bEnd,
                    slice: blockSlice,
                    isEntry: isEntryBlock
                )
            )
        }
        _ = sortedLeaderIndices.count

        var blockIDByStartAddress: [VirtualAddress: Int] = [:]
        blockIDByStartAddress.reserveCapacity(rawSpans.count)
        for span in rawSpans {
            blockIDByStartAddress[span.startAddress] = span.blockID
        }

        // Step 3: Emit Control-Flow Edges with Unique (sourceBlockID, targetBlockID) Pairs
        var edges: [CFGEdge] = []
        var seenPairs = Set<CFGDirectedPair>()
        var explicitExitFlags = [Bool](repeating: false, count: rawSpans.count)
        var tailCallTargets: [VirtualAddress] = []
        var seenTailTargets = Set<VirtualAddress>()

        func appendUniqueEdge(from src: Int, to dst: Int, kind: CFGEdgeKind) {
            let pair = CFGDirectedPair(sourceBlockID: src, targetBlockID: dst)
            guard seenPairs.insert(pair).inserted else { return }
            edges.append(CFGEdge(sourceBlockID: src, targetBlockID: dst, kind: kind, isBackEdge: false))
        }

        for (spanIdx, span) in rawSpans.enumerated() {
            guard let terminator = span.slice.last else {
                explicitExitFlags[spanIdx] = true
                continue
            }
            let nextBlockID: Int? = {
                guard spanIdx + 1 < rawSpans.count else { return nil }
                let nxt = rawSpans[spanIdx + 1]
                if defaultInstructionByteStride == 4 && nxt.startAddress != terminator.address.adding(UInt64(4)) {
                    return nil
                }
                return nxt.blockID
            }()

            switch terminator.flow {
            case .directCall(let target):
                if noreturnAddresses.contains(target) {
                    explicitExitFlags[spanIdx] = true
                } else if let nextID = nextBlockID {
                    appendUniqueEdge(from: span.blockID, to: nextID, kind: .fallthroughEdge)
                } else {
                    explicitExitFlags[spanIdx] = true
                }

            case .sequential, .indirectCall:
                if let nextID = nextBlockID {
                    appendUniqueEdge(from: span.blockID, to: nextID, kind: .fallthroughEdge)
                } else {
                    explicitExitFlags[spanIdx] = true
                }

            case .unconditionalJump(let target):
                if let targetBlockID = blockIDByStartAddress[target] {
                    appendUniqueEdge(from: span.blockID, to: targetBlockID, kind: .unconditional)
                } else {
                    // External tail jump (e.g. tail-call optimization `b _helper` or stub)
                    explicitExitFlags[spanIdx] = true
                    if seenTailTargets.insert(target).inserted {
                        tailCallTargets.append(target)
                    }
                }

            case .conditionalBranch(let target, _):
                let trueBlockID = blockIDByStartAddress[target]
                if let trueID = trueBlockID {
                    if let fallthroughID = nextBlockID, trueID == fallthroughID {
                        // Degenerate conditional branch whose target equals fallthrough instruction
                        appendUniqueEdge(from: span.blockID, to: trueID, kind: .unconditional)
                    } else {
                        appendUniqueEdge(from: span.blockID, to: trueID, kind: .conditionalTrue)
                        if let falseID = nextBlockID {
                            appendUniqueEdge(from: span.blockID, to: falseID, kind: .conditionalFalse)
                        }
                    }
                } else {
                    // Conditional tail-branch outside current function: fallthrough continues inside function
                    if seenTailTargets.insert(target).inserted {
                        tailCallTargets.append(target)
                    }
                    if let falseID = nextBlockID {
                        appendUniqueEdge(from: span.blockID, to: falseID, kind: .conditionalFalse)
                    } else {
                        explicitExitFlags[spanIdx] = true
                    }
                }

            case .indirectJump:
                if let jt = jumpTableByDispatch[terminator.address], !jt.targetAddresses.isEmpty {
                    var emittedAnyCase = false
                    for (caseIdx, caseAddr) in jt.targetAddresses.enumerated() {
                        if let caseBlockID = blockIDByStartAddress[caseAddr] {
                            appendUniqueEdge(
                                from: span.blockID,
                                to: caseBlockID,
                                kind: .switchCase(value: Int64(caseIdx))
                            )
                            emittedAnyCase = true
                        }
                    }
                    if !emittedAnyCase {
                        explicitExitFlags[spanIdx] = true
                    }
                } else {
                    // Indirect return/thunk/tail dispatch (`br x16`, `braa x16, x17`, etc.)
                    explicitExitFlags[spanIdx] = true
                }

            case .returnControl:
                explicitExitFlags[spanIdx] = true

            case .trapOrSupervisor(let imm):
                if isRecoverableSupervisorCall(terminator, immediate: imm, in: span.slice),
                   let nextID = nextBlockID {
                    appendUniqueEdge(from: span.blockID, to: nextID, kind: .fallthroughEdge)
                } else {
                    explicitExitFlags[spanIdx] = true
                }
            }
        }

        // Step 4: Populate predecessorIDs, successorIDs, isEntry, isExit
        var predsByBlock = Array(repeating: [Int](), count: rawSpans.count)
        var succsByBlock = Array(repeating: [Int](), count: rawSpans.count)

        for edge in edges {
            if !succsByBlock[edge.sourceBlockID].contains(edge.targetBlockID) {
                succsByBlock[edge.sourceBlockID].append(edge.targetBlockID)
            }
            if !predsByBlock[edge.targetBlockID].contains(edge.sourceBlockID) {
                predsByBlock[edge.targetBlockID].append(edge.sourceBlockID)
            }
        }

        var blocks: [BasicBlock] = []
        blocks.reserveCapacity(rawSpans.count)
        for (idx, span) in rawSpans.enumerated() {
            let preds = predsByBlock[idx].sorted()
            let succs = succsByBlock[idx]
            let isExit = explicitExitFlags[idx] || succs.isEmpty
            blocks.append(
                BasicBlock(
                    id: span.blockID,
                    functionAddress: functionAddress,
                    startAddress: span.startAddress,
                    endAddress: span.endAddress,
                    instructions: span.slice,
                    predecessorIDs: preds,
                    successorIDs: succs,
                    isEntry: span.isEntry,
                    isExit: isExit,
                    loopDepth: 0
                )
            )
        }

        let entryID = blocks.first(where: \.isEntry)?.id ?? 0
        let rpo = computeReversePostOrder(blocks: blocks, entryBlockID: entryID)
        let unreachableIDs = blocks
            .map(\.id)
            .filter { !rpo.reachableBlockIDs.contains($0) }

        return (blocks, edges, tailCallTargets, unreachableIDs)
    }

    // MARK: - Graph Traversal, Loop/Back-Edge Annotation & Pruning

    /// Computes DFS Post-Order, Reverse Post-Order (RPO), and the set of reachable `blockID`s from `entryBlockID`.
    public func computeReversePostOrder(
        blocks: [BasicBlock],
        entryBlockID: Int? = nil
    ) -> (reversePostOrder: [Int], postOrder: [Int], reachableBlockIDs: Set<Int>) {
        guard !blocks.isEmpty else { return ([], [], []) }

        var blockByID: [Int: BasicBlock] = [:]
        blockByID.reserveCapacity(blocks.count)
        for b in blocks {
            blockByID[b.id] = b
        }

        let resolvedEntry = entryBlockID
            ?? blocks.first(where: \.isEntry)?.id
            ?? blocks[0].id
        guard blockByID[resolvedEntry] != nil else {
            return ([], [], [])
        }

        var visited: Set<Int> = []
        var postOrder: [Int] = []
        postOrder.reserveCapacity(blocks.count)

        // Iterative explicit-stack DFS to avoid recursion depth limits on huge obfuscated CFGs
        var stack: [(blockID: Int, nextSuccIdx: Int)] = [(resolvedEntry, 0)]
        visited.insert(resolvedEntry)

        while let top = stack.last {
            let succs = blockByID[top.blockID]?.successorIDs ?? []
            if top.nextSuccIdx < succs.count {
                stack[stack.count - 1].nextSuccIdx += 1
                let childID = succs[top.nextSuccIdx]
                if blockByID[childID] != nil && visited.insert(childID).inserted {
                    stack.append((childID, 0))
                }
            } else {
                _ = stack.popLast()
                postOrder.append(top.blockID)
            }
        }

        let rpo = Array(postOrder.reversed())
        return (rpo, postOrder, visited)
    }

    /// Annotates `BasicBlock.loopDepth` and `CFGEdge.isBackEdge` using Lengauer-Tarjan natural loop results,
    /// assembling a finalized `RecoveredFunction`.
    public func finalizeRecoveredFunction(
        from cfg: BuiltFunctionCFG,
        dominatorTree: [DominatorTreeNode],
        naturalLoops: [NaturalLoop],
        backEdgePairs: Set<CFGDirectedPair>,
        layout: SugiyamaCFGLayout? = nil
    ) -> RecoveredFunction {
        let annotated = annotateLoopAndBackEdgeMetadata(
            blocks: cfg.blocks,
            edges: cfg.edges,
            naturalLoops: naturalLoops,
            backEdgePairs: backEdgePairs
        )

        return RecoveredFunction(
            address: cfg.functionAddress,
            endAddress: cfg.endAddress,
            name: cfg.name,
            demangledName: cfg.demangledName,
            isLeaf: cfg.isLeaf,
            isThunk: cfg.isThunk,
            usesPAC: cfg.usesPAC,
            stackFrameBytes: cfg.stackFrameBytes,
            blocks: annotated.blocks,
            edges: annotated.edges,
            dominatorTree: dominatorTree,
            naturalLoops: naturalLoops,
            jumpTables: cfg.jumpTables,
            cyclomaticComplexity: cfg.cyclomaticComplexity,
            layout: layout
        )
    }

    /// Pure transformation updating `BasicBlock.loopDepth` and `CFGEdge.isBackEdge`.
    public func annotateLoopAndBackEdgeMetadata(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        naturalLoops: [NaturalLoop],
        backEdgePairs: Set<CFGDirectedPair>
    ) -> (blocks: [BasicBlock], edges: [CFGEdge]) {
        var depthByBlockID: [Int: Int] = [:]
        for loop in naturalLoops {
            for bID in loop.bodyBlockIDs {
                depthByBlockID[bID, default: 0] += 1
            }
        }

        let updatedBlocks = blocks.map { b in
            let loopDepth = depthByBlockID[b.id] ?? 0
            guard loopDepth != b.loopDepth else { return b }
            return BasicBlock(
                id: b.id,
                functionAddress: b.functionAddress,
                startAddress: b.startAddress,
                endAddress: b.endAddress,
                instructions: b.instructions,
                predecessorIDs: b.predecessorIDs,
                successorIDs: b.successorIDs,
                isEntry: b.isEntry,
                isExit: b.isExit,
                loopDepth: loopDepth
            )
        }

        let updatedEdges = edges.map { e in
            let isBack = backEdgePairs.contains(CFGDirectedPair(sourceBlockID: e.sourceBlockID, targetBlockID: e.targetBlockID))
            guard isBack != e.isBackEdge else { return e }
            return CFGEdge(
                sourceBlockID: e.sourceBlockID,
                targetBlockID: e.targetBlockID,
                kind: e.kind,
                isBackEdge: isBack
            )
        }

        return (updatedBlocks, updatedEdges)
    }

    /// Identifies SSA critical edges: edges `(u -> v)` where `u` has multiple successors AND `v` has multiple predecessors.
    public func criticalEdges(in cfg: BuiltFunctionCFG) -> [CFGEdge] {
        var outDeg: [Int: Int] = [:]
        var inDeg: [Int: Int] = [:]
        for b in cfg.blocks {
            outDeg[b.id] = b.successorIDs.count
            inDeg[b.id] = b.predecessorIDs.count
        }
        return cfg.edges.filter { edge in
            (outDeg[edge.sourceBlockID] ?? 0) > 1 && (inDeg[edge.targetBlockID] ?? 0) > 1
        }
    }

    /// Removes all unreachable blocks from `cfg`, optionally compacting block IDs to `0..<count`.
    public func pruneUnreachableBlocks(
        in cfg: BuiltFunctionCFG,
        renumberCompactly: Bool = true
    ) -> BuiltFunctionCFG {
        let entryID = cfg.blocks.first(where: \.isEntry)?.id ?? 0
        let rpo = computeReversePostOrder(blocks: cfg.blocks, entryBlockID: entryID)
        let unreachable = Set(cfg.blocks.map(\.id)).subtracting(rpo.reachableBlockIDs)
        guard !unreachable.isEmpty else { return cfg }

        let pruned = pruneSelectedUnreachableBlocks(
            blocks: cfg.blocks,
            edges: cfg.edges,
            unreachableIDs: unreachable,
            pruneAll: true,
            renumberCompactly: renumberCompactly
        )
        let newRPO = computeReversePostOrder(blocks: pruned.blocks, entryBlockID: pruned.blocks.first(where: \.isEntry)?.id)
        let newMetrics = computeStructuralMetrics(
            blocks: pruned.blocks,
            edges: pruned.edges,
            reachableBlockIDs: newRPO.reachableBlockIDs
        )

        return BuiltFunctionCFG(
            functionAddress: cfg.functionAddress,
            endAddress: cfg.endAddress,
            name: cfg.name,
            demangledName: cfg.demangledName,
            blocks: pruned.blocks,
            edges: pruned.edges,
            jumpTables: cfg.jumpTables,
            prologueAnalysis: cfg.prologueAnalysis,
            isLeaf: cfg.isLeaf,
            isThunk: cfg.isThunk,
            usesPAC: cfg.usesPAC,
            stackFrameBytes: cfg.stackFrameBytes,
            cyclomaticComplexity: newMetrics.cyclomaticComplexity,
            unreachableBlockIDs: pruned.remainingUnreachableIDs,
            tailCallTargets: cfg.tailCallTargets,
            metrics: newMetrics
        )
    }

    public func computeStructuralMetrics(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        reachableBlockIDs: Set<Int>
    ) -> CFGStructuralMetrics {
        let blockCount = blocks.count
        let edgeCount = edges.count
        var entryCount = 0
        var exitCount = 0
        var condCount = 0
        var switchCount = 0
        var insnTotal = 0
        var maxIn = 0
        var maxOut = 0

        for b in blocks {
            if b.isEntry { entryCount += 1 }
            if b.isExit { exitCount += 1 }
            insnTotal += b.instructions.count
            maxIn = max(maxIn, b.predecessorIDs.count)
            maxOut = max(maxOut, b.successorIDs.count)

            if let last = b.instructions.last {
                switch last.flow {
                case .conditionalBranch:
                    condCount += 1
                case .indirectJump where b.successorIDs.count >= 1:
                    switchCount += 1
                default:
                    break
                }
            }
        }

        let unreachableCount = max(0, blockCount - reachableBlockIDs.count)
        let cc = max(1, edgeCount - blockCount + 2)
        let avgInsns = blockCount > 0 ? (Double(insnTotal) / Double(blockCount)) : 0.0

        return CFGStructuralMetrics(
            blockCount: blockCount,
            edgeCount: edgeCount,
            entryBlockCount: entryCount,
            exitBlockCount: exitCount,
            conditionalBranchBlockCount: condCount,
            switchDispatchBlockCount: switchCount,
            unreachableBlockCount: unreachableCount,
            instructionCount: insnTotal,
            cyclomaticComplexity: cc,
            maxInDegree: maxIn,
            maxOutDegree: maxOut,
            averageInstructionsPerBlock: avgInsns
        )
    }

    // MARK: - Internal Helpers

    private func pruneSelectedUnreachableBlocks(
        blocks: [BasicBlock],
        edges: [CFGEdge],
        unreachableIDs: Set<Int>,
        pruneAll: Bool,
        renumberCompactly: Bool = true
    ) -> (blocks: [BasicBlock], edges: [CFGEdge], remainingUnreachableIDs: [Int]) {
        var dropSet = Set<Int>()
        for b in blocks where unreachableIDs.contains(b.id) && !b.isEntry {
            if pruneAll || isPureAlignmentOrTrapPaddingBlock(b) {
                dropSet.insert(b.id)
            }
        }
        if !pruneAll && !dropSet.isEmpty {
            // Never drop a padding block that is targeted by a surviving (non-dropped) block,
            // preserving fallthrough and branch target invariants on unreachable code blocks.
            var changed = true
            while changed {
                changed = false
                for e in edges where !dropSet.contains(e.sourceBlockID) && dropSet.contains(e.targetBlockID) {
                    dropSet.remove(e.targetBlockID)
                    changed = true
                }
            }
        }
        guard !dropSet.isEmpty else {
            return (blocks, edges, unreachableIDs.sorted())
        }

        let survivingBlocks = blocks.filter { !dropSet.contains($0.id) }
        guard !survivingBlocks.isEmpty else {
            return (blocks, edges, unreachableIDs.sorted())
        }

        var idRemap: [Int: Int] = [:]
        for (newIdx, b) in survivingBlocks.enumerated() {
            idRemap[b.id] = renumberCompactly ? newIdx : b.id
        }

        let survivingEdges: [CFGEdge] = edges.compactMap { e in
            guard let src = idRemap[e.sourceBlockID],
                  let dst = idRemap[e.targetBlockID] else {
                return nil
            }
            return CFGEdge(
                sourceBlockID: src,
                targetBlockID: dst,
                kind: e.kind,
                isBackEdge: e.isBackEdge
            )
        }

        var predsMap: [Int: [Int]] = [:]
        var succsMap: [Int: [Int]] = [:]
        for e in survivingEdges {
            if !(succsMap[e.sourceBlockID]?.contains(e.targetBlockID) ?? false) {
                succsMap[e.sourceBlockID, default: []].append(e.targetBlockID)
            }
            if !(predsMap[e.targetBlockID]?.contains(e.sourceBlockID) ?? false) {
                predsMap[e.targetBlockID, default: []].append(e.sourceBlockID)
            }
        }

        let rebuiltBlocks: [BasicBlock] = survivingBlocks.map { old in
            let newID = idRemap[old.id] ?? old.id
            let preds = (predsMap[newID] ?? []).sorted()
            let succs = succsMap[newID] ?? []
            return BasicBlock(
                id: newID,
                functionAddress: old.functionAddress,
                startAddress: old.startAddress,
                endAddress: old.endAddress,
                instructions: old.instructions,
                predecessorIDs: preds,
                successorIDs: succs,
                isEntry: old.isEntry,
                isExit: old.isExit || succs.isEmpty,
                loopDepth: old.loopDepth
            )
        }

        let remainingUnreachable = unreachableIDs
            .subtracting(dropSet)
            .compactMap { idRemap[$0] }
            .sorted()

        return (rebuiltBlocks, survivingEdges, remainingUnreachable)
    }

    private func isPureAlignmentOrTrapPaddingBlock(_ block: BasicBlock) -> Bool {
        guard !block.instructions.isEmpty else { return true }
        return block.instructions.allSatisfy { insn in
            insn.rawWord == 0x0000_0000 ||
            insn.mnemonic == .nop ||
            insn.mnemonic == .brk ||
            insn.mnemonic == .hlt
        }
    }

    private func isRecoverableSupervisorCall(
        _ insn: A64DecodedInstruction,
        immediate: UInt16,
        in blockInstructions: [A64DecodedInstruction]
    ) -> Bool {
        guard insn.mnemonic == .svc else { return false }
        // Check if Darwin syscall #1 (`exit`) or #37 (`kill` abort) was loaded into x16/w16 right before `svc #0x80`
        if immediate == 0x80 && blockInstructions.count >= 2 {
            let prev = blockInstructions[blockInstructions.count - 2]
            if (prev.mnemonic == .mov || prev.mnemonic == .movz),
               prev.operands.count == 2,
               case .register(let rd) = prev.operands[0],
               rd.index == 16 {
                switch prev.operands[1] {
                case .unsignedImmediate(let v) where v == 1 || v == 431: // SYS_exit / SYS_abort_with_payload
                    return false
                case .immediate(let v) where v == 1 || v == 431:
                    return false
                default:
                    break
                }
            }
        }
        return true
    }

    private func computeIsThunk(
        isStubSection: Bool,
        prologueInfo: A64PrologueEpilogueAnalysis,
        blocks: [BasicBlock],
        instructions: [A64DecodedInstruction],
        tailCallTargets: [VirtualAddress]
    ) -> Bool {
        if isStubSection || prologueInfo.isThunk {
            return true
        }
        // Short 1-block tail-jump trampoline without stack frame (`b _real_impl` or `bti c; b _real_impl`)
        if blocks.count == 1 &&
           prologueInfo.stackFrameBytes == 0 &&
           instructions.count <= 4 &&
           !tailCallTargets.isEmpty {
            let nonTrivial = instructions.filter { $0.mnemonic != .bti && $0.mnemonic != .nop }
            if nonTrivial.count == 1, case .unconditionalJump = nonTrivial[0].flow {
                return true
            }
        }
        return false
    }

    private func scanSupplementaryStackAllocation(in instructions: [A64DecodedInstruction]) -> Int {
        var accumulated: Int64 = 0
        let limit = min(instructions.count, 24)
        for i in 0..<limit {
            let insn = instructions[i]
            if insn.mnemonic == .sub,
               insn.operands.count == 3,
               case .register(let rd) = insn.operands[0], rd.isStackPointer,
               case .register(let rn) = insn.operands[1], rn.isStackPointer {
                switch insn.operands[2] {
                case .unsignedImmediate(let v):
                    accumulated += Int64(bitPattern: v)
                case .immediate(let s) where s > 0:
                    accumulated += s
                case .shiftedImmediate(let v, let sh):
                    accumulated += Int64(bitPattern: v << Int(sh))
                default:
                    break
                }
            } else if insn.mnemonic == .stp,
                      insn.operands.count == 3,
                      case .memory(.preIndex(let base, let off)) = insn.operands[2],
                      base.isStackPointer && off < 0 {
                accumulated += (-off)
            }
            if insn.flow != .sequential {
                break
            }
        }
        return Int(max(0, accumulated))
    }
}
