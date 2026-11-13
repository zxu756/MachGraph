import Foundation
import MachGraphModels

// MARK: - Multi-Instruction Idiom & Prologue/Epilogue Models

public enum A64IdiomKind: String, Sendable, Codable, Hashable, CaseIterable {
    case adrpAddAddress = "ADRP+ADD Page Offset Address"
    case adrpLoadPointer = "ADRP+LDR GOT/Pointer Load"
    case adrpStoreData = "ADRP+STR Global Data Store"
    case movWideConstant = "MOVZ/MOVN+MOVK Wide Constant"
    case darwinSyscall = "Darwin XNU Supervisor Syscall"
    case dyldImportStub = "Mach-O Import Stub Thunk"
    case switchTableDispatch = "PC-Relative Switch Table Dispatch"
}

public struct A64RecognizedIdiom: Sendable, Codable, Hashable, Identifiable {
    public var id: UInt64 { completingAddress.rawValue }
    public let kind: A64IdiomKind
    public let startAddress: VirtualAddress
    public let completingAddress: VirtualAddress
    public let instructionAddresses: [VirtualAddress]
    public let destinationRegister: A64Register?
    public let targetAddress: VirtualAddress?
    public let constantValue: UInt64?
    public let resolvedSymbol: String?
    public let xrefKind: XrefKind?
    public let summary: String

    public init(
        kind: A64IdiomKind,
        startAddress: VirtualAddress,
        completingAddress: VirtualAddress,
        instructionAddresses: [VirtualAddress],
        destinationRegister: A64Register? = nil,
        targetAddress: VirtualAddress? = nil,
        constantValue: UInt64? = nil,
        resolvedSymbol: String? = nil,
        xrefKind: XrefKind? = nil,
        summary: String
    ) {
        self.kind = kind
        self.startAddress = startAddress
        self.completingAddress = completingAddress
        self.instructionAddresses = instructionAddresses
        self.destinationRegister = destinationRegister
        self.targetAddress = targetAddress
        self.constantValue = constantValue
        self.resolvedSymbol = resolvedSymbol
        self.xrefKind = xrefKind
        self.summary = summary
    }
}

public struct A64SavedRegisterSlot: Sendable, Codable, Hashable {
    public let register: A64Register
    public let spOffsetFromEntry: Int64
    public let instructionAddress: VirtualAddress

    public init(register: A64Register, spOffsetFromEntry: Int64, instructionAddress: VirtualAddress) {
        self.register = register
        self.spOffsetFromEntry = spOffsetFromEntry
        self.instructionAddress = instructionAddress
    }
}

public struct A64PrologueEpilogueAnalysis: Sendable, Codable, Hashable {
    public let hasPrologue: Bool
    public let hasEpilogue: Bool
    public let usesPAC: Bool
    public let pacKey: String?
    public let hasBTILandingPad: Bool
    public let establishesFramePointer: Bool
    public let stackFrameBytes: Int
    public let savedRegisters: [A64SavedRegisterSlot]
    public let prologueAddresses: [VirtualAddress]
    public let epilogueAddresses: [VirtualAddress]
    public let isLeaf: Bool
    public let isThunk: Bool
    public let thunkTargetAddress: VirtualAddress?

    public init(
        hasPrologue: Bool,
        hasEpilogue: Bool,
        usesPAC: Bool,
        pacKey: String? = nil,
        hasBTILandingPad: Bool = false,
        establishesFramePointer: Bool = false,
        stackFrameBytes: Int = 0,
        savedRegisters: [A64SavedRegisterSlot] = [],
        prologueAddresses: [VirtualAddress] = [],
        epilogueAddresses: [VirtualAddress] = [],
        isLeaf: Bool = true,
        isThunk: Bool = false,
        thunkTargetAddress: VirtualAddress? = nil
    ) {
        self.hasPrologue = hasPrologue
        self.hasEpilogue = hasEpilogue
        self.usesPAC = usesPAC
        self.pacKey = pacKey
        self.hasBTILandingPad = hasBTILandingPad
        self.establishesFramePointer = establishesFramePointer
        self.stackFrameBytes = stackFrameBytes
        self.savedRegisters = savedRegisters
        self.prologueAddresses = prologueAddresses
        self.epilogueAddresses = epilogueAddresses
        self.isLeaf = isLeaf
        self.isThunk = isThunk
        self.thunkTargetAddress = thunkTargetAddress
    }
}

// MARK: - Multi-Instruction ARM64 Idiom & Constant Propagation Engine

public struct A64IdiomRecognizer: Sendable {
    public init() {}

    // MARK: - Direct Pair & Chain Resolvers

    /// Resolves `ADRP xN, page` + `ADD/SUB xM, xN, #pageoff` into an exact 64-bit `VirtualAddress`.
    public func resolveAdrpAdd(
        adrp: A64DecodedInstruction,
        add: A64DecodedInstruction
    ) -> VirtualAddress? {
        guard adrp.mnemonic == .adrp,
              adrp.operands.count == 2,
              case .register(let pageReg) = adrp.operands[0],
              pageReg.bank == .gp64,
              case .branchTarget(let pageBase) = adrp.operands[1]
        else {
            return nil
        }

        guard (add.mnemonic == .add || add.mnemonic == .sub),
              add.operands.count == 3,
              case .register(let srcReg) = add.operands[1],
              srcReg.bank == .gp64,
              srcReg.index == pageReg.index,
              let delta = Self.extractAddSubImmediateDelta(from: add.operands[2])
        else {
            return nil
        }

        let signedOffset = (add.mnemonic == .sub) ? -delta : delta
        return pageBase.adding(signedOffset)
    }

    /// Resolves `ADRP xN, page` + `LDR* rDst, [xN, #pageoff]` into an exact GOT / global pointer `VirtualAddress`.
    public func resolveAdrpLoad(
        adrp: A64DecodedInstruction,
        load: A64DecodedInstruction
    ) -> VirtualAddress? {
        guard adrp.mnemonic == .adrp,
              adrp.operands.count == 2,
              case .register(let pageReg) = adrp.operands[0],
              pageReg.bank == .gp64,
              case .branchTarget(let pageBase) = adrp.operands[1]
        else {
            return nil
        }

        guard Self.isSingleLoadMnemonic(load.mnemonic),
              load.operands.count == 2,
              case .memory(.baseOffset(let baseReg, let byteOffset)) = load.operands[1],
              baseReg.bank == .gp64,
              baseReg.index == pageReg.index
        else {
            return nil
        }

        return pageBase.adding(byteOffset)
    }

    /// Synthesizes an exact 64-bit constant from a `MOVZ`/`MOVN` + `MOVK` instruction chain targeting the same GP register.
    public func resolveMovWideChain(
        _ chain: [A64DecodedInstruction]
    ) -> UInt64? {
        guard let first = chain.first,
              let seed = Self.extractMoveWideSeed(from: first)
        else {
            return nil
        }

        var acc = seed.value
        let targetIndex = seed.reg.index
        var sawFollowup = false

        for insn in chain.dropFirst() {
            guard insn.mnemonic == .movk,
                  insn.operands.count == 2,
                  case .register(let rd) = insn.operands[0],
                  rd.isGeneralPurpose,
                  !rd.isStackPointer,
                  !rd.isZeroRegister,
                  rd.index == targetIndex,
                  let (imm16, shift) = Self.extractWideLane(from: insn.operands[1])
            else {
                return nil
            }
            let clearMask = ~(UInt64(0xFFFF) << Int(shift))
            acc = (acc & clearMask) | (imm16 << Int(shift))
            if rd.bitWidth == 32 {
                acc &= 0xFFFF_FFFF
            }
            sawFollowup = true
        }

        return sawFollowup || chain.count == 1 ? acc : nil
    }

    // MARK: - Full Sequence Idiom & Constant Propagation Scanner

    private enum TrackedRegState {
        case pageBase(page: VirtualAddress, adrpAddress: VirtualAddress)
        case computedAddress(address: VirtualAddress, startAddress: VirtualAddress, addresses: [VirtualAddress])
        case wideConst(
            register: A64Register,
            value: UInt64,
            startAddress: VirtualAddress,
            addresses: [VirtualAddress]
        )
    }

    /// Scans a decoded instruction stream using forward per-register constant and page propagation
    /// to recover `ADRP+ADD`, `ADRP+LDR`, `ADRP+STR`, `MOVZ/MOVN+MOVK`, Darwin syscalls, import thunks, and switch dispatches.
    public func recognizeIdioms(
        in instructions: [A64DecodedInstruction],
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) -> [A64RecognizedIdiom] {
        guard !instructions.isEmpty else { return [] }

        var idioms: [A64RecognizedIdiom] = []

        // Check if the entire buffer is a concise Mach-O dyld import stub thunk
        if let stubIdiom = detectImportStubThunk(in: instructions, symbolLookup: symbolLookup) {
            idioms.append(stubIdiom)
        }

        // Collect internal branch target addresses so register states reset conservatively at merge points
        var branchTargets = Set<VirtualAddress>()
        for insn in instructions {
            switch insn.flow {
            case .unconditionalJump(let tgt), .conditionalBranch(let tgt, _):
                branchTargets.insert(tgt)
            default:
                break
            }
        }

        var regStates: [UInt8: TrackedRegState] = [:]

        func flushPendingWideChain(for regIdx: UInt8) {
            guard let state = regStates[regIdx],
                  case .wideConst(let reg, let val, let startAddr, let addrs) = state,
                  addrs.count >= 2,
                  let lastAddr = addrs.last
            else {
                return
            }
            let sym = symbolLookup?(VirtualAddress(val))
            let summary: String
            if let sym {
                summary = "\(reg.canonicalName) = 0x\(String(val, radix: 16)) (\(sym))"
            } else {
                summary = "\(reg.canonicalName) = 0x\(String(val, radix: 16)) (\(Int64(bitPattern: val)))"
            }
            idioms.append(
                A64RecognizedIdiom(
                    kind: .movWideConstant,
                    startAddress: startAddr,
                    completingAddress: lastAddr,
                    instructionAddresses: addrs,
                    destinationRegister: reg,
                    targetAddress: sym != nil ? VirtualAddress(val) : nil,
                    constantValue: val,
                    resolvedSymbol: sym,
                    xrefKind: nil,
                    summary: summary
                )
            )
        }

        func flushAllPendingWideChains() {
            for idx in regStates.keys.sorted() {
                flushPendingWideChain(for: idx)
            }
        }

        for (idx, insn) in instructions.enumerated() {
            if idx > 0 && branchTargets.contains(insn.address) {
                flushAllPendingWideChains()
                regStates.removeAll(keepingCapacity: true)
            }

            // 1. ADRP xRd, page
            if insn.mnemonic == .adrp,
               insn.operands.count == 2,
               case .register(let rd) = insn.operands[0],
               rd.bank == .gp64,
               case .branchTarget(let page) = insn.operands[1] {
                flushPendingWideChain(for: rd.index)
                regStates[rd.index] = .pageBase(page: page, adrpAddress: insn.address)
                continue
            }

            // 2. ADR xRd, target (tracks exact PC-relative base for switch jump tables)
            if insn.mnemonic == .adr,
               insn.operands.count == 2,
               case .register(let rd) = insn.operands[0],
               rd.bank == .gp64,
               case .branchTarget(let target) = insn.operands[1] {
                flushPendingWideChain(for: rd.index)
                regStates[rd.index] = .computedAddress(
                    address: target,
                    startAddress: insn.address,
                    addresses: [insn.address]
                )
                continue
            }

            // 3. ADD / SUB immediate on a tracked ADRP page register -> exact 64-bit address
            if (insn.mnemonic == .add || insn.mnemonic == .sub),
               insn.operands.count == 3,
               case .register(let rd) = insn.operands[0],
               case .register(let rn) = insn.operands[1],
               rn.bank == .gp64,
               let delta = Self.extractAddSubImmediateDelta(from: insn.operands[2]),
               case .pageBase(let page, let adrpAddr) = regStates[rn.index] {
                let signedDelta = (insn.mnemonic == .sub) ? -delta : delta
                let resolvedAddr = page.adding(signedDelta)
                let sym = symbolLookup?(resolvedAddr)
                let summary = sym != nil
                    ? "\(rd.canonicalName) -> \(resolvedAddr.compactHexString) (\(sym!))"
                    : "\(rd.canonicalName) -> \(resolvedAddr.compactHexString)"

                idioms.append(
                    A64RecognizedIdiom(
                        kind: .adrpAddAddress,
                        startAddress: adrpAddr,
                        completingAddress: insn.address,
                        instructionAddresses: [adrpAddr, insn.address],
                        destinationRegister: rd,
                        targetAddress: resolvedAddr,
                        constantValue: resolvedAddr.rawValue,
                        resolvedSymbol: sym,
                        xrefKind: .stringReference,
                        summary: summary
                    )
                )

                if !rd.isStackPointer && !rd.isZeroRegister {
                    flushPendingWideChain(for: rd.index)
                    regStates[rd.index] = .computedAddress(
                        address: resolvedAddr,
                        startAddress: adrpAddr,
                        addresses: [adrpAddr, insn.address]
                    )
                }
                continue
            }

            // 4. LDR* from a tracked ADRP page register -> GOT / global pointer load
            if Self.isSingleLoadMnemonic(insn.mnemonic),
               insn.operands.count == 2,
               case .register(let rt) = insn.operands[0],
               case .memory(.baseOffset(let baseReg, let off)) = insn.operands[1],
               baseReg.bank == .gp64,
               case .pageBase(let page, let adrpAddr) = regStates[baseReg.index] {
                let targetAddr = page.adding(off)
                let sym = symbolLookup?(targetAddr)
                let summary = sym != nil
                    ? "\(rt.canonicalName) = *(\(targetAddr.compactHexString)) [\(sym!)]"
                    : "\(rt.canonicalName) = *(\(targetAddr.compactHexString))"

                idioms.append(
                    A64RecognizedIdiom(
                        kind: .adrpLoadPointer,
                        startAddress: adrpAddr,
                        completingAddress: insn.address,
                        instructionAddresses: [adrpAddr, insn.address],
                        destinationRegister: rt,
                        targetAddress: targetAddr,
                        constantValue: nil,
                        resolvedSymbol: sym,
                        xrefKind: .dataPointerRead,
                        summary: summary
                    )
                )

                if rt.isGeneralPurpose && !rt.isZeroRegister && !rt.isStackPointer {
                    flushPendingWideChain(for: rt.index)
                    regStates.removeValue(forKey: rt.index)
                }
                continue
            }

            // 5. STR* into a tracked ADRP page register -> global variable store
            if Self.isSingleStoreMnemonic(insn.mnemonic),
               insn.operands.count == 2,
               case .memory(.baseOffset(let baseReg, let off)) = insn.operands[1],
               baseReg.bank == .gp64,
               case .pageBase(let page, let adrpAddr) = regStates[baseReg.index] {
                let targetAddr = page.adding(off)
                let sym = symbolLookup?(targetAddr)
                let summary = sym != nil
                    ? "*(\(targetAddr.compactHexString)) [\(sym!)] = \(insn.operands[0].description)"
                    : "*(\(targetAddr.compactHexString)) = \(insn.operands[0].description)"

                idioms.append(
                    A64RecognizedIdiom(
                        kind: .adrpStoreData,
                        startAddress: adrpAddr,
                        completingAddress: insn.address,
                        instructionAddresses: [adrpAddr, insn.address],
                        destinationRegister: nil,
                        targetAddress: targetAddr,
                        constantValue: nil,
                        resolvedSymbol: sym,
                        xrefKind: .dataPointerWrite,
                        summary: summary
                    )
                )
                continue
            }

            // 6. MOVZ / MOVN / MOV immediate constant seed
            if let seed = Self.extractMoveWideSeed(from: insn) {
                flushPendingWideChain(for: seed.reg.index)
                regStates[seed.reg.index] = .wideConst(
                    register: seed.reg,
                    value: seed.value,
                    startAddress: insn.address,
                    addresses: [insn.address]
                )
                continue
            }

            // 7. MOVK continuation on an active wide constant
            if insn.mnemonic == .movk,
               insn.operands.count == 2,
               case .register(let rd) = insn.operands[0],
               rd.isGeneralPurpose, !rd.isStackPointer, !rd.isZeroRegister,
               let (imm16, shift) = Self.extractWideLane(from: insn.operands[1]),
               case .wideConst(_, let prevVal, let startAddr, var addrs) = regStates[rd.index] {
                let clearMask = ~(UInt64(0xFFFF) << Int(shift))
                var updated = (prevVal & clearMask) | (imm16 << Int(shift))
                if rd.bitWidth == 32 {
                    updated &= 0xFFFF_FFFF
                }
                addrs.append(insn.address)
                regStates[rd.index] = .wideConst(
                    register: rd,
                    value: updated,
                    startAddress: startAddr,
                    addresses: addrs
                )
                continue
            }

            // 8. Darwin XNU ARM64 Syscall (SVC #0x80 with known x16/w16 constant)
            if insn.mnemonic == .svc,
               case .trapOrSupervisor(0x80) = insn.flow,
               case .wideConst(_, let rawSysNum, let startAddr, let addrs) = regStates[16] {
                let signedSys = Int64(bitPattern: rawSysNum)
                let sysName = A64DarwinSyscallTable.bsdOrMachSyscallName(forX16: signedSys)
                let label = sysName != nil ? "\(sysName!) (\(signedSys))" : "syscall #\(signedSys)"
                var allAddrs = addrs
                allAddrs.append(insn.address)
                idioms.append(
                    A64RecognizedIdiom(
                        kind: .darwinSyscall,
                        startAddress: startAddr,
                        completingAddress: insn.address,
                        instructionAddresses: allAddrs,
                        destinationRegister: .x(0),
                        targetAddress: nil,
                        constantValue: rawSysNum,
                        resolvedSymbol: sysName,
                        xrefKind: nil,
                        summary: "Darwin syscall: \(label)"
                    )
                )
            }

            // 9. PC-Relative Switch Table Dispatch: ADD xTarget, xTable, xEntry + BR xTarget
            if insn.mnemonic == .br,
               case .indirectJump(let targetReg) = insn.flow,
               idx >= 2 {
                let prevAdd = instructions[idx - 1]
                if prevAdd.mnemonic == .add,
                   prevAdd.operands.count == 3,
                   case .register(let addDst) = prevAdd.operands[0],
                   addDst.index == targetReg.index,
                   case .register(let baseReg) = prevAdd.operands[1],
                   case .computedAddress(let tableAddr, let startAddr, var addrs) = regStates[baseReg.index] {
                    addrs.append(prevAdd.address)
                    addrs.append(insn.address)
                    idioms.append(
                        A64RecognizedIdiom(
                            kind: .switchTableDispatch,
                            startAddress: startAddr,
                            completingAddress: insn.address,
                            instructionAddresses: addrs,
                            destinationRegister: targetReg,
                            targetAddress: tableAddr,
                            constantValue: tableAddr.rawValue,
                            resolvedSymbol: symbolLookup?(tableAddr),
                            xrefKind: .dataPointerRead,
                            summary: "Switch jump table dispatch via \(tableAddr.compactHexString)"
                        )
                    )
                }
            }

            // Invalidate overwritten GP registers
            for written in insn.writesRegisters where written.isGeneralPurpose && !written.isStackPointer && !written.isZeroRegister {
                flushPendingWideChain(for: written.index)
                regStates.removeValue(forKey: written.index)
            }

            // Calls clobber caller-saved volatile GP registers x0..x18 (AAPCS64)
            switch insn.flow {
            case .directCall, .indirectCall:
                for volatileIdx: UInt8 in 0...18 {
                    flushPendingWideChain(for: volatileIdx)
                    regStates.removeValue(forKey: volatileIdx)
                }
            case .unconditionalJump, .indirectJump, .returnControl, .trapOrSupervisor:
                flushAllPendingWideChains()
                regStates.removeAll(keepingCapacity: true)
            case .sequential, .conditionalBranch:
                break
            }
        }

        flushAllPendingWideChains()
        return idioms
    }

    /// Returns a copy of `instructions` whose `autoComment` fields are enriched with multi-instruction idiom resolutions.
    public func annotateInstructions(
        _ instructions: [A64DecodedInstruction],
        symbolLookup: (@Sendable (VirtualAddress) -> String?)? = nil
    ) -> [A64DecodedInstruction] {
        let idioms = recognizeIdioms(in: instructions, symbolLookup: symbolLookup)
        guard !idioms.isEmpty else { return instructions }

        var byCompletingAddress: [VirtualAddress: [String]] = [:]
        for idiom in idioms {
            byCompletingAddress[idiom.completingAddress, default: []].append(idiom.summary)
        }

        return instructions.map { insn in
            guard let extraNotes = byCompletingAddress[insn.address], !extraNotes.isEmpty else {
                return insn
            }
            let joined = extraNotes.joined(separator: "; ")
            let mergedComment: String
            if let existing = insn.autoComment, !existing.isEmpty {
                mergedComment = "\(existing) | \(joined)"
            } else {
                mergedComment = joined
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
                autoComment: mergedComment
            )
        }
    }

    // MARK: - Function Prologue, Epilogue, Stack Frame & PAC Analyzer

    /// Analyzes an ARM64/ARM64e function instruction stream to detect prologue/epilogue structure,
    /// stack frame allocation size (`stackFrameBytes`), saved callee registers, frame pointer setup, PAC usage, and thunk status.
    public func analyzePrologueAndEpilogue(
        in instructions: [A64DecodedInstruction]
    ) -> A64PrologueEpilogueAnalysis {
        guard !instructions.isEmpty else {
            return A64PrologueEpilogueAnalysis(hasPrologue: false, hasEpilogue: false, usesPAC: false)
        }

        // Check for short import/trampoline thunk first
        if let stub = detectImportStubThunk(in: instructions, symbolLookup: nil) {
            let usesPAC = instructions.contains { $0.group == .pacPointerAuth }
            return A64PrologueEpilogueAnalysis(
                hasPrologue: false,
                hasEpilogue: false,
                usesPAC: usesPAC,
                pacKey: usesPAC ? "IA" : nil,
                hasBTILandingPad: instructions.first?.mnemonic == .bti,
                establishesFramePointer: false,
                stackFrameBytes: 0,
                savedRegisters: [],
                prologueAddresses: [],
                epilogueAddresses: [],
                isLeaf: true,
                isThunk: true,
                thunkTargetAddress: stub.targetAddress
            )
        }

        if instructions.count == 1,
           case .unconditionalJump(let target) = instructions[0].flow {
            return A64PrologueEpilogueAnalysis(
                hasPrologue: false,
                hasEpilogue: false,
                usesPAC: false,
                stackFrameBytes: 0,
                isLeaf: true,
                isThunk: true,
                thunkTargetAddress: target
            )
        }

        var usesPAC = false
        var pacKey: String? = nil
        var hasBTI = false
        var establishesFP = false
        var currentSPAllocation: Int64 = 0
        var maxPrologueFrameBytes: Int64 = 0
        var savedSlots: [A64SavedRegisterSlot] = []
        var prologueAddrs: [VirtualAddress] = []
        var epilogueAddrs: [VirtualAddress] = []
        var hasCalls = false

        for insn in instructions {
            switch insn.flow {
            case .directCall, .indirectCall:
                hasCalls = true
            default:
                break
            }
            if insn.mnemonic == .paciasp || insn.mnemonic == .autiasp || insn.mnemonic == .retaa {
                usesPAC = true
                if pacKey == nil { pacKey = "IA" }
            } else if insn.mnemonic == .pacibsp || insn.mnemonic == .autibsp || insn.mnemonic == .retab {
                usesPAC = true
                if pacKey == nil { pacKey = "IB" }
            }
        }

        // Scan entry prologue window (up to first 16 instructions before any branch/call/return)
        let prologueLimit = min(instructions.count, 16)
        for i in 0..<prologueLimit {
            let insn = instructions[i]

            if insn.mnemonic == .bti && i <= 1 {
                hasBTI = true
                prologueAddrs.append(insn.address)
                continue
            }

            if (insn.mnemonic == .paciasp || insn.mnemonic == .pacibsp) && i <= 2 {
                prologueAddrs.append(insn.address)
                continue
            }

            // SUB sp, sp, #imm{, lsl #12}
            if insn.mnemonic == .sub,
               insn.operands.count == 3,
               case .register(let rd) = insn.operands[0], rd.isStackPointer,
               case .register(let rn) = insn.operands[1], rn.isStackPointer,
               let delta = Self.extractAddSubImmediateDelta(from: insn.operands[2]),
               delta > 0 {
                currentSPAllocation += delta
                maxPrologueFrameBytes = max(maxPrologueFrameBytes, currentSPAllocation)
                prologueAddrs.append(insn.address)
                continue
            }

            // STP reg1, reg2, [sp, #-frame]! (pre-index stack push) or [sp, #offset]
            if insn.mnemonic == .stp,
               insn.operands.count == 3,
               case .register(let r1) = insn.operands[0],
               case .register(let r2) = insn.operands[1] {
                let slotWidth: Int64 = Int64(max(4, r1.bitWidth / 8))
                switch insn.operands[2] {
                case .memory(.preIndex(let base, let negOffset)) where base.isStackPointer && negOffset < 0:
                    currentSPAllocation += (-negOffset)
                    maxPrologueFrameBytes = max(maxPrologueFrameBytes, currentSPAllocation)
                    let baseFromEntry = -currentSPAllocation
                    savedSlots.append(.init(register: r1, spOffsetFromEntry: baseFromEntry, instructionAddress: insn.address))
                    savedSlots.append(.init(register: r2, spOffsetFromEntry: baseFromEntry + slotWidth, instructionAddress: insn.address))
                    prologueAddrs.append(insn.address)
                    continue

                case .memory(.baseOffset(let base, let posOffset)) where base.isStackPointer && currentSPAllocation > 0:
                    let baseFromEntry = -currentSPAllocation + posOffset
                    if Self.isCalleeSavedOrLink(r1) || Self.isCalleeSavedOrLink(r2) {
                        savedSlots.append(.init(register: r1, spOffsetFromEntry: baseFromEntry, instructionAddress: insn.address))
                        savedSlots.append(.init(register: r2, spOffsetFromEntry: baseFromEntry + slotWidth, instructionAddress: insn.address))
                        prologueAddrs.append(insn.address)
                        continue
                    }

                default:
                    break
                }
            }

            // Single STR x30, [sp, #-16]! or [sp, #offset]
            if insn.mnemonic == .str,
               insn.operands.count == 2,
               case .register(let rt) = insn.operands[0],
               Self.isCalleeSavedOrLink(rt) {
                switch insn.operands[1] {
                case .memory(.preIndex(let base, let negOffset)) where base.isStackPointer && negOffset < 0:
                    currentSPAllocation += (-negOffset)
                    maxPrologueFrameBytes = max(maxPrologueFrameBytes, currentSPAllocation)
                    savedSlots.append(.init(register: rt, spOffsetFromEntry: -currentSPAllocation, instructionAddress: insn.address))
                    prologueAddrs.append(insn.address)
                    continue

                case .memory(.baseOffset(let base, let posOffset)) where base.isStackPointer && currentSPAllocation > 0:
                    savedSlots.append(.init(register: rt, spOffsetFromEntry: -currentSPAllocation + posOffset, instructionAddress: insn.address))
                    prologueAddrs.append(insn.address)
                    continue

                default:
                    break
                }
            }

            // Frame pointer establishment: ADD x29, sp, #off OR MOV x29, sp
            if (insn.mnemonic == .add || insn.mnemonic == .mov),
               let firstOp = insn.operands.first,
               case .register(let rd) = firstOp,
               rd.bank == .gp64 && rd.index == 29,
               insn.operands.count >= 2,
               case .register(let rn) = insn.operands[1],
               rn.isStackPointer {
                establishesFP = true
                prologueAddrs.append(insn.address)
                continue
            }

            if insn.flow != .sequential {
                break
            }
        }

        // Scan epilogue sequences backwards from every return instruction
        for (idx, insn) in instructions.enumerated() {
            guard case .returnControl = insn.flow else { continue }
            epilogueAddrs.append(insn.address)

            let windowStart = max(0, idx - 8)
            if idx > 0 {
                for backIdx in stride(from: idx - 1, through: windowStart, by: -1) {
                    let prev = instructions[backIdx]
                    if prev.flow != .sequential { break }

                    if prev.mnemonic == .autiasp || prev.mnemonic == .autibsp {
                        epilogueAddrs.append(prev.address)
                        continue
                    }
                    if prev.mnemonic == .add,
                       prev.operands.count == 3,
                       case .register(let rd) = prev.operands[0], rd.isStackPointer,
                       case .register(let rn) = prev.operands[1], rn.isStackPointer {
                        epilogueAddrs.append(prev.address)
                        continue
                    }
                    if prev.mnemonic == .ldp,
                       prev.operands.count == 3,
                       case .register(let r1) = prev.operands[0],
                       case .register(let r2) = prev.operands[1],
                       (Self.isCalleeSavedOrLink(r1) || Self.isCalleeSavedOrLink(r2)) {
                        epilogueAddrs.append(prev.address)
                        continue
                    }
                    if prev.mnemonic == .ldr,
                       prev.operands.count == 2,
                       case .register(let rt) = prev.operands[0],
                       Self.isCalleeSavedOrLink(rt) {
                        epilogueAddrs.append(prev.address)
                        continue
                    }
                }
            }
        }

        epilogueAddrs.sort()
        let savesLinkRegister = savedSlots.contains { $0.register.bank == .gp64 && $0.register.index == 30 }

        return A64PrologueEpilogueAnalysis(
            hasPrologue: !prologueAddrs.isEmpty && (maxPrologueFrameBytes > 0 || establishesFP || usesPAC),
            hasEpilogue: !epilogueAddrs.isEmpty,
            usesPAC: usesPAC,
            pacKey: pacKey,
            hasBTILandingPad: hasBTI,
            establishesFramePointer: establishesFP,
            stackFrameBytes: Int(max(0, maxPrologueFrameBytes)),
            savedRegisters: savedSlots,
            prologueAddresses: prologueAddrs,
            epilogueAddresses: epilogueAddrs,
            isLeaf: !hasCalls && !savesLinkRegister,
            isThunk: false,
            thunkTargetAddress: nil
        )
    }

    // MARK: - Import Stub Thunk Recognition

    private func detectImportStubThunk(
        in instructions: [A64DecodedInstruction],
        symbolLookup: (@Sendable (VirtualAddress) -> String?)?
    ) -> A64RecognizedIdiom? {
        guard instructions.count >= 3 && instructions.count <= 6 else { return nil }
        let startIdx = (instructions[0].mnemonic == .bti) ? 1 : 0
        let slice = Array(instructions[startIdx...])
        guard slice.count >= 3 else { return nil }

        // Pattern 1 (arm64): adrp x16, page ; ldr x16, [x16, #off] ; br x16 (or braaz x16)
        if slice.count == 3 || (slice.count == 4 && slice[2].mnemonic == .nop) {
            let adrpInsn = slice[0]
            let ldrInsn = slice[1]
            let brInsn = slice[slice.count - 1]
            if (brInsn.mnemonic == .br || brInsn.mnemonic == .braaz || brInsn.mnemonic == .brabz),
               let ptrAddr = resolveAdrpLoad(adrp: adrpInsn, load: ldrInsn) {
                let sym = symbolLookup?(ptrAddr)
                let summary = sym != nil
                    ? "Import stub -> \(sym!) (GOT @ \(ptrAddr.compactHexString))"
                    : "Import stub via GOT @ \(ptrAddr.compactHexString)"
                return A64RecognizedIdiom(
                    kind: .dyldImportStub,
                    startAddress: instructions[0].address,
                    completingAddress: brInsn.address,
                    instructionAddresses: instructions.map(\.address),
                    destinationRegister: .x(16),
                    targetAddress: ptrAddr,
                    constantValue: nil,
                    resolvedSymbol: sym,
                    xrefKind: .indirectCall,
                    summary: summary
                )
            }
        }

        // Pattern 2 (arm64e auth stub): adrp x17, page ; add x17, x17, #off ; ldr x16, [x17] ; braa x16, x17
        if slice.count == 4 {
            let adrpInsn = slice[0]
            let addInsn = slice[1]
            let ldrInsn = slice[2]
            let braaInsn = slice[3]
            if (braaInsn.mnemonic == .braa || braaInsn.mnemonic == .brab),
               ldrInsn.mnemonic == .ldr,
               let ptrAddr = resolveAdrpAdd(adrp: adrpInsn, add: addInsn) {
                let sym = symbolLookup?(ptrAddr)
                let summary = sym != nil
                    ? "PAC Auth Import stub -> \(sym!) (GOT @ \(ptrAddr.compactHexString))"
                    : "PAC Auth Import stub via GOT @ \(ptrAddr.compactHexString)"
                return A64RecognizedIdiom(
                    kind: .dyldImportStub,
                    startAddress: instructions[0].address,
                    completingAddress: braaInsn.address,
                    instructionAddresses: instructions.map(\.address),
                    destinationRegister: .x(16),
                    targetAddress: ptrAddr,
                    constantValue: nil,
                    resolvedSymbol: sym,
                    xrefKind: .indirectCall,
                    summary: summary
                )
            }
        }

        return nil
    }

    // MARK: - Internal Extraction Helpers

    private static func extractAddSubImmediateDelta(from operand: A64Operand) -> Int64? {
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

    private static func extractWideLane(from operand: A64Operand) -> (imm16: UInt64, shift: UInt8)? {
        switch operand {
        case .unsignedImmediate(let v):
            return (v & 0xFFFF, 0)
        case .immediate(let s) where s >= 0:
            return (UInt64(s) & 0xFFFF, 0)
        case .shiftedImmediate(let v, let shift):
            return (v & 0xFFFF, shift)
        default:
            return nil
        }
    }

    private static func extractMoveWideSeed(from insn: A64DecodedInstruction) -> (reg: A64Register, value: UInt64)? {
        guard insn.operands.count == 2,
              case .register(let rd) = insn.operands[0],
              rd.isGeneralPurpose, !rd.isStackPointer, !rd.isZeroRegister
        else {
            return nil
        }

        switch insn.mnemonic {
        case .movz:
            guard let (imm16, shift) = extractWideLane(from: insn.operands[1]) else { return nil }
            let val = imm16 << Int(shift)
            return (rd, rd.bitWidth == 32 ? (val & 0xFFFF_FFFF) : val)

        case .movn:
            guard let (imm16, shift) = extractWideLane(from: insn.operands[1]) else { return nil }
            let inv = ~(imm16 << Int(shift))
            return (rd, rd.bitWidth == 32 ? (inv & 0xFFFF_FFFF) : inv)

        case .mov:
            switch insn.operands[1] {
            case .unsignedImmediate(let v):
                return (rd, rd.bitWidth == 32 ? (v & 0xFFFF_FFFF) : v)
            case .immediate(let s):
                let u = UInt64(bitPattern: s)
                return (rd, rd.bitWidth == 32 ? (u & 0xFFFF_FFFF) : u)
            default:
                return nil
            }

        default:
            return nil
        }
    }

    private static func isSingleLoadMnemonic(_ m: A64Mnemonic) -> Bool {
        switch m {
        case .ldr, .ldrb, .ldrh, .ldrsb, .ldrsh, .ldrsw,
             .ldur, .ldurb, .ldurh, .ldursb, .ldursh, .ldursw:
            return true
        default:
            return false
        }
    }

    private static func isSingleStoreMnemonic(_ m: A64Mnemonic) -> Bool {
        switch m {
        case .str, .strb, .strh, .stur, .sturb, .sturh:
            return true
        default:
            return false
        }
    }

    private static func isCalleeSavedOrLink(_ reg: A64Register) -> Bool {
        switch reg.bank {
        case .gp64, .gp32:
            return (19...30).contains(reg.index)
        case .simdDouble, .simdQuad:
            return (8...15).contains(reg.index)
        default:
            return false
        }
    }
}
