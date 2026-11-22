import Foundation
import MachGraphModels

// MARK: - Virtual Address Space & Chained Pointer Resolver

internal struct BinaryMappedMemoryReader: Sendable {
    enum ResolvedPointer: Sendable {
        case null
        case internalAddress(VirtualAddress)
        case externalBind(symbolName: String, addend: Int64)
    }

    let sliceData: Data
    let imageBase: VirtualAddress
    let segments: [BinarySegment]
    let sections: [BinarySection]
    let fixupsByLocation: [VirtualAddress: ChainedFixupRecord]

    init(
        sliceData: Data,
        imageBase: VirtualAddress,
        segments: [BinarySegment],
        sections: [BinarySection],
        chainedFixups: [ChainedFixupRecord]
    ) {
        self.sliceData = sliceData
        self.imageBase = imageBase
        self.segments = segments
        self.sections = sections
        var map: [VirtualAddress: ChainedFixupRecord] = [:]
        map.reserveCapacity(chainedFixups.count)
        for rec in chainedFixups {
            map[rec.location] = rec
        }
        self.fixupsByLocation = map
    }

    func localSliceOffset(for vmAddress: VirtualAddress) -> Int? {
        for sec in sections where sec.kind != .bss && sec.size > 0 {
            if sec.addressRange.contains(vmAddress) {
                let delta = vmAddress.rawValue - sec.vmAddress.rawValue
                let off = sec.fileOffset.rawValue &+ delta
                if off < UInt64(sliceData.count) {
                    return Int(off)
                }
            }
        }
        for seg in segments where seg.fileSize > 0 {
            let backedSize = min(seg.vmSize, seg.fileSize)
            let range = AddressRange(start: seg.vmAddress, size: backedSize)
            if range.contains(vmAddress) {
                let delta = vmAddress.rawValue - seg.vmAddress.rawValue
                let off = seg.fileOffset.rawValue &+ delta
                if off < UInt64(sliceData.count) {
                    return Int(off)
                }
            }
        }
        return nil
    }

    func isValidMappedAddress(_ vmAddress: VirtualAddress) -> Bool {
        localSliceOffset(for: vmAddress) != nil
    }

    func section(containing vmAddress: VirtualAddress) -> BinarySection? {
        sections.first { $0.addressRange.contains(vmAddress) }
    }

    func readUInt16(at vmAddress: VirtualAddress) -> UInt16? {
        guard let off = localSliceOffset(for: vmAddress), off + 2 <= sliceData.count else { return nil }
        var r = BinarySliceReader(data: sliceData, endianness: .little)
        try? r.seek(to: off)
        return try? r.readUInt16()
    }

    func readUInt32(at vmAddress: VirtualAddress) -> UInt32? {
        guard let off = localSliceOffset(for: vmAddress), off + 4 <= sliceData.count else { return nil }
        var r = BinarySliceReader(data: sliceData, endianness: .little)
        try? r.seek(to: off)
        return try? r.readUInt32()
    }

    func readInt32(at vmAddress: VirtualAddress) -> Int32? {
        guard let u = readUInt32(at: vmAddress) else { return nil }
        return Int32(bitPattern: u)
    }

    func readUInt64(at vmAddress: VirtualAddress) -> UInt64? {
        guard let off = localSliceOffset(for: vmAddress), off + 8 <= sliceData.count else { return nil }
        var r = BinarySliceReader(data: sliceData, endianness: .little)
        try? r.seek(to: off)
        return try? r.readUInt64()
    }

    func readCString(at vmAddress: VirtualAddress, maxBytes: Int = 2048) -> String? {
        guard let off = localSliceOffset(for: vmAddress), off < sliceData.count else { return nil }
        let r = BinarySliceReader(data: sliceData, endianness: .little)
        guard let str = r.peekNullTerminatedUTF8(at: off, maxBytes: maxBytes), !str.isEmpty else {
            return nil
        }
        return str
    }

    func readRawBytes(at vmAddress: VirtualAddress, maxLength: Int) -> [UInt8] {
        guard let off = localSliceOffset(for: vmAddress), off < sliceData.count else { return [] }
        let len = min(maxLength, sliceData.count - off)
        return Array(sliceData[(sliceData.startIndex + off)..<(sliceData.startIndex + off + len)])
    }

    func resolvePointer(at fieldAddress: VirtualAddress) -> ResolvedPointer {
        if let fixup = fixupsByLocation[fieldAddress] {
            switch fixup.kind {
            case .rebase, .authRebase:
                if let target = fixup.targetAddress, target != .zero {
                    return .internalAddress(target)
                }
                return .null
            case .bind, .authBind:
                if let sym = fixup.symbolName, !sym.isEmpty {
                    return .externalBind(symbolName: sym, addend: fixup.addend)
                }
                return .null
            }
        }

        guard let raw = readUInt64(at: fieldAddress) else {
            return .null
        }
        if raw == 0 {
            return .null
        }

        let directVA = VirtualAddress(raw)
        if isValidMappedAddress(directVA) {
            return .internalAddress(directVA)
        }

        // Strip ARM64E PAC / dyld chained high bits (43-bit canonical user VA)
        let stripped43 = VirtualAddress(raw & 0x0000_07FF_FFFF_FFFF)
        if stripped43 != .zero && isValidMappedAddress(stripped43) {
            return .internalAddress(stripped43)
        }

        // Check 36-bit runtime offset from imageBase (DYLD_CHAINED_PTR_64_OFFSET / ARM64E_USERLAND)
        let offset36 = raw & 0x0000_000F_FFFF_FFFF
        if offset36 != 0 {
            let rebased = imageBase.adding(offset36)
            if isValidMappedAddress(rebased) {
                return .internalAddress(rebased)
            }
        }

        return .null
    }

    func resolveIndirectableRelativePointer(at fieldAddress: VirtualAddress) -> ResolvedPointer {
        guard let rel = readInt32(at: fieldAddress), rel != 0 else {
            return .null
        }
        if (rel & 1) != 0 {
            let indirectSlot = fieldAddress.adding(Int64(rel & ~1))
            return resolvePointer(at: indirectSlot)
        } else {
            let directTarget = fieldAddress.adding(Int64(rel))
            return .internalAddress(directTarget)
        }
    }
}

// MARK: - Objective-C 2.0 & Swift 5 Metadata Parser

enum ObjCAndSwiftMetadataParser {
    // ObjC 2.0 class_ro_t constants
    private static let fastDataMask64: UInt64            = 0x0000_7FFF_FFFF_FFF8
    private static let smallMethodListFlag: UInt32       = 0x8000_0000
    private static let directSelectorMethodFlag: UInt32  = 0x4000_0000

    /// Walks Objective-C 2.0 `__objc_classlist`, `__objc_nlclslist`, `__objc_catlist`, `__objc_nlcatlist`, and `__objc_protolist` sections.
    static func parseObjCMetadata(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        imageBase: VirtualAddress,
        segments: [BinarySegment],
        sections: [BinarySection],
        chainedFixups: [ChainedFixupRecord]
    ) -> (
        classes: [ObjCClassMetadata],
        categories: [ObjCCategoryMetadata],
        protocols: [ObjCProtocolMetadata],
        methodSymbols: [BinarySymbol]
    ) {
        let _ = sliceFileOffset
        let classListSections = sections.filter {
            $0.sectionName == "__objc_classlist" || $0.sectionName == "__objc_nlclslist"
        }
        let categoryListSections = sections.filter {
            $0.sectionName == "__objc_catlist" || $0.sectionName == "__objc_nlcatlist"
        }
        let protocolListSections = sections.filter {
            $0.sectionName == "__objc_protolist"
        }

        guard !classListSections.isEmpty || !categoryListSections.isEmpty || !protocolListSections.isEmpty else {
            return ([], [], [], [])
        }

        let memory = BinaryMappedMemoryReader(
            sliceData: sliceData,
            imageBase: imageBase,
            segments: segments,
            sections: sections,
            chainedFixups: chainedFixups
        )

        var parsedClasses: [ObjCClassMetadata] = []
        var parsedCategories: [ObjCCategoryMetadata] = []
        var parsedProtocols: [ObjCProtocolMetadata] = []
        var methodSymbols: [BinarySymbol] = []
        var visitedClassAddresses = Set<VirtualAddress>()
        var visitedCategoryAddresses = Set<VirtualAddress>()
        var visitedProtocolAddresses = Set<VirtualAddress>()

        for clsSection in classListSections {
            let ptrCount = Int(clsSection.size / 8)
            for i in 0..<min(ptrCount, 16_384) {
                let slotVA = clsSection.vmAddress.adding(UInt64(i * 8))
                guard let classVA = nonHeaderInternalAddress(memory.resolvePointer(at: slotVA), memory: memory) else {
                    continue
                }
                guard visitedClassAddresses.insert(classVA).inserted else {
                    continue
                }
                if let clsMeta = parseObjCClass(at: classVA, memory: memory) {
                    parsedClasses.append(clsMeta)
                    for method in clsMeta.methods where method.implementationAddress != .zero {
                        let prefix = method.isClassMethod ? "+" : "-"
                        let fullSymName = "\(prefix)[\(clsMeta.name) \(method.selector)]"
                        let secIdx = sections.firstIndex { $0.addressRange.contains(method.implementationAddress) }
                        methodSymbols.append(
                            BinarySymbol(
                                name: fullSymName,
                                demangledName: fullSymName,
                                kind: .objcMethod,
                                binding: .local,
                                address: method.implementationAddress,
                                size: 0,
                                sectionIndex: secIdx,
                                provenance: .objcMetadata
                            )
                        )
                    }
                }
            }
        }

        // Harvest structured categories and category method symbols from __objc_catlist / __objc_nlcatlist
        for catSection in categoryListSections {
            let ptrCount = Int(catSection.size / 8)
            for i in 0..<min(ptrCount, 8192) {
                let slotVA = catSection.vmAddress.adding(UInt64(i * 8))
                guard let catVA = nonHeaderInternalAddress(memory.resolvePointer(at: slotVA), memory: memory) else {
                    continue
                }
                guard visitedCategoryAddresses.insert(catVA).inserted else {
                    continue
                }
                if let (catMeta, catMethods) = parseObjCCategory(at: catVA, memory: memory, sections: sections) {
                    parsedCategories.append(catMeta)
                    methodSymbols.append(contentsOf: catMethods)
                }
            }
        }

        // Harvest structured protocols from __objc_protolist (deduplicated by protocol_t VA)
        for protoSection in protocolListSections {
            let ptrCount = Int(protoSection.size / 8)
            for i in 0..<min(ptrCount, 8192) {
                let slotVA = protoSection.vmAddress.adding(UInt64(i * 8))
                guard let protoVA = nonHeaderInternalAddress(memory.resolvePointer(at: slotVA), memory: memory) else {
                    continue
                }
                guard visitedProtocolAddresses.insert(protoVA).inserted else {
                    continue
                }
                if let protoMeta = parseObjCProtocol(at: protoVA, memory: memory) {
                    parsedProtocols.append(protoMeta)
                }
            }
        }

        return (parsedClasses, parsedCategories, parsedProtocols, methodSymbols)
    }

    private static func nonHeaderInternalAddress(
        _ resolved: BinaryMappedMemoryReader.ResolvedPointer,
        memory: BinaryMappedMemoryReader
    ) -> VirtualAddress? {
        guard case .internalAddress(let va) = resolved,
              va != .zero,
              va != memory.imageBase else {
            return nil
        }
        return va
    }

    private static func parseObjCClass(
        at classVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> ObjCClassMetadata? {
        // objc_class_t (64-bit):
        // +0x00 isa
        // +0x08 superclass
        // +0x10 cache_buckets
        // +0x18 cache_mask
        // +0x20 bits (class_ro_t* & FAST_DATA_MASK)
        let isaResolved = memory.resolvePointer(at: classVA)
        let superResolved = memory.resolvePointer(at: classVA + 0x08)
        let bitsResolved = memory.resolvePointer(at: classVA + 0x20)

        let roVA: VirtualAddress
        switch bitsResolved {
        case .internalAddress(let rawRO):
            roVA = VirtualAddress(rawRO.rawValue & fastDataMask64)
        case .null, .externalBind:
            return nil
        }

        guard roVA != .zero,
              roVA != memory.imageBase,
              memory.isValidMappedAddress(roVA),
              let roFlags = memory.readUInt32(at: roVA),
              let instanceSize = memory.readUInt32(at: roVA + 0x08) else {
            return nil
        }

        // class_ro_t (64-bit):
        // +0x00 flags (4)
        // +0x04 instanceStart (4)
        // +0x08 instanceSize (4)
        // +0x0C reserved (4)
        // +0x10 ivarLayout (8)
        // +0x18 name (8)
        // +0x20 baseMethodList (8)
        // +0x28 baseProtocols (8)
        // +0x30 ivars (8)
        guard let nameVA = nonHeaderInternalAddress(memory.resolvePointer(at: roVA + 0x18), memory: memory),
              let className = memory.readCString(at: nameVA, maxBytes: 16_384),
              !className.isEmpty else {
            return nil
        }

        let superclassName = resolveSuperclassName(superResolved, memory: memory)

        var methods: [ObjCMethodMetadata] = []
        if let methodListVA = nonHeaderInternalAddress(memory.resolvePointer(at: roVA + 0x20), memory: memory) {
            let instanceMethods = parseObjCMethodList(at: methodListVA, isClassMethod: false, memory: memory)
            methods.append(contentsOf: instanceMethods)
        }

        // Walk metaclass for +[ClassName method] class methods
        if let metaClassVA = nonHeaderInternalAddress(isaResolved, memory: memory), metaClassVA != classVA {
            if case .internalAddress(let rawMetaRO) = memory.resolvePointer(at: metaClassVA + 0x20) {
                let metaROVA = VirtualAddress(rawMetaRO.rawValue & fastDataMask64)
                if metaROVA != .zero,
                   metaROVA != memory.imageBase,
                   let classMethodListVA = nonHeaderInternalAddress(memory.resolvePointer(at: metaROVA + 0x20), memory: memory) {
                    let classMethods = parseObjCMethodList(at: classMethodListVA, isClassMethod: true, memory: memory)
                    methods.append(contentsOf: classMethods)
                }
            }
        }

        var protocols: [String] = []
        if let protoListVA = nonHeaderInternalAddress(memory.resolvePointer(at: roVA + 0x28), memory: memory) {
            protocols = parseObjCProtocolList(at: protoListVA, memory: memory)
        }

        var ivars: [ObjCIvarMetadata] = []
        if let ivarListVA = nonHeaderInternalAddress(memory.resolvePointer(at: roVA + 0x30), memory: memory) {
            ivars = parseObjCIvarList(at: ivarListVA, memory: memory)
        }

        return ObjCClassMetadata(
            name: className,
            superclassName: superclassName,
            address: classVA,
            instanceSize: instanceSize,
            flags: roFlags,
            methods: methods,
            ivars: ivars,
            adoptedProtocols: protocols
        )
    }

    private static func resolveSuperclassName(
        _ resolved: BinaryMappedMemoryReader.ResolvedPointer,
        memory: BinaryMappedMemoryReader
    ) -> String? {
        switch resolved {
        case .null:
            return nil
        case .externalBind(let symName, _):
            if let range = symName.range(of: "_OBJC_CLASS_$_") {
                return String(symName[range.upperBound...])
            }
            if let range = symName.range(of: "OBJC_CLASS_$_") {
                return String(symName[range.upperBound...])
            }
            return symName
        case .internalAddress(let superClassVA):
            guard superClassVA != .zero,
                  superClassVA != memory.imageBase,
                  case .internalAddress(let rawSuperRO) = memory.resolvePointer(at: superClassVA + 0x20) else {
                return nil
            }
            let superROVA = VirtualAddress(rawSuperRO.rawValue & fastDataMask64)
            guard superROVA != .zero,
                  superROVA != memory.imageBase,
                  let superNameVA = nonHeaderInternalAddress(memory.resolvePointer(at: superROVA + 0x18), memory: memory),
                  let name = memory.readCString(at: superNameVA, maxBytes: 16_384) else {
                return nil
            }
            return name
        }
    }

    private static func parseObjCMethodList(
        at listVA: VirtualAddress,
        isClassMethod: Bool,
        memory: BinaryMappedMemoryReader
    ) -> [ObjCMethodMetadata] {
        guard listVA != .zero,
              listVA != memory.imageBase,
              let entsizeAndFlags = memory.readUInt32(at: listVA),
              let rawCount = memory.readUInt32(at: listVA + 4),
              rawCount > 0 else {
            return []
        }

        let count = Int(min(rawCount, 4096))
        let isRelativeSmall = (entsizeAndFlags & smallMethodListFlag) != 0
        let isDirectSelector = (entsizeAndFlags & directSelectorMethodFlag) != 0
        var methods: [ObjCMethodMetadata] = []
        methods.reserveCapacity(count)

        if isRelativeSmall {
            let maskedSize = Int(entsizeAndFlags & 0xFFFC)
            let stride = maskedSize >= 12 ? maskedSize : 12

            for idx in 0..<count {
                let entryVA = listVA.adding(UInt64(8 + idx * stride))
                guard let nameRel = memory.readInt32(at: entryVA),
                      let typesRel = memory.readInt32(at: entryVA + 4),
                      let impRel = memory.readInt32(at: entryVA + 8) else {
                    break
                }

                let nameTargetVA = entryVA.adding(Int64(nameRel))
                let selector: String?
                if isDirectSelector {
                    selector = memory.readCString(at: nameTargetVA, maxBytes: 16_384)
                } else if let targetSec = memory.section(containing: nameTargetVA),
                          targetSec.sectionName == "__objc_methname" || targetSec.kind == .cstring {
                    selector = memory.readCString(at: nameTargetVA, maxBytes: 16_384)
                } else if case .internalAddress(let selStrVA) = memory.resolvePointer(at: nameTargetVA),
                          let derefSel = memory.readCString(at: selStrVA, maxBytes: 16_384) {
                    selector = derefSel
                } else {
                    selector = memory.readCString(at: nameTargetVA, maxBytes: 16_384)
                }

                guard let cleanSelector = selector, !cleanSelector.isEmpty else {
                    continue
                }

                let typeEncoding: String
                if typesRel != 0 {
                    let typesVA = (entryVA + 4).adding(Int64(typesRel))
                    typeEncoding = memory.readCString(at: typesVA, maxBytes: 16_384) ?? ""
                } else {
                    typeEncoding = ""
                }

                let impVA: VirtualAddress = impRel != 0
                    ? (entryVA + 8).adding(Int64(impRel))
                    : .zero

                methods.append(
                    ObjCMethodMetadata(
                        selector: cleanSelector,
                        typeEncoding: typeEncoding,
                        implementationAddress: impVA,
                        isClassMethod: isClassMethod
                    )
                )
            }
        } else {
            let maskedSize = Int(entsizeAndFlags & ~UInt32(3))
            let stride = maskedSize >= 24 ? maskedSize : 24

            for idx in 0..<count {
                let entryVA = listVA.adding(UInt64(8 + idx * stride))
                guard let selVA = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA), memory: memory) else {
                    continue
                }
                let rawSelector: String?
                if let targetSec = memory.section(containing: selVA),
                   targetSec.sectionName == "__objc_selrefs",
                   let derefVA = nonHeaderInternalAddress(memory.resolvePointer(at: selVA), memory: memory),
                   let derefStr = memory.readCString(at: derefVA, maxBytes: 16_384) {
                    rawSelector = derefStr
                } else {
                    rawSelector = memory.readCString(at: selVA, maxBytes: 16_384)
                }
                guard let selector = rawSelector, !selector.isEmpty else {
                    continue
                }

                let typeEncoding: String
                if let typesVA = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA + 8), memory: memory) {
                    typeEncoding = memory.readCString(at: typesVA, maxBytes: 16_384) ?? ""
                } else {
                    typeEncoding = ""
                }

                let impVA: VirtualAddress
                if let resolvedImp = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA + 16), memory: memory) {
                    impVA = resolvedImp
                } else {
                    impVA = .zero
                }

                methods.append(
                    ObjCMethodMetadata(
                        selector: selector,
                        typeEncoding: typeEncoding,
                        implementationAddress: impVA,
                        isClassMethod: isClassMethod
                    )
                )
            }
        }

        return methods
    }

    private static func parseObjCIvarList(
        at listVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> [ObjCIvarMetadata] {
        guard let rawEntsize = memory.readUInt32(at: listVA),
              let rawCount = memory.readUInt32(at: listVA + 4),
              rawCount > 0 else {
            return []
        }

        let stride = max(32, Int(rawEntsize & ~UInt32(3)))
        let count = Int(min(rawCount, 2048))
        var ivars: [ObjCIvarMetadata] = []
        ivars.reserveCapacity(count)

        for idx in 0..<count {
            let entryVA = listVA.adding(UInt64(8 + idx * stride))
            // ivar_t (64-bit):
            // +0x00 int32_t *offset
            // +0x08 const char *name
            // +0x10 const char *type
            // +0x18 uint32_t alignment_raw
            // +0x1C uint32_t size
            guard let nameVA = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA + 0x08), memory: memory),
                  let ivarName = memory.readCString(at: nameVA, maxBytes: 16_384),
                  !ivarName.isEmpty else {
                continue
            }

            let ivarOffset: UInt32
            if let offsetPtrVA = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA), memory: memory) {
                ivarOffset = memory.readUInt32(at: offsetPtrVA) ?? 0
            } else {
                ivarOffset = 0
            }

            let typeEnc: String
            if let typeVA = nonHeaderInternalAddress(memory.resolvePointer(at: entryVA + 0x10), memory: memory) {
                typeEnc = memory.readCString(at: typeVA, maxBytes: 16_384) ?? ""
            } else {
                typeEnc = ""
            }

            let ivarSize = memory.readUInt32(at: entryVA + 0x1C) ?? 0
            ivars.append(
                ObjCIvarMetadata(
                    name: ivarName,
                    typeEncoding: typeEnc,
                    offset: ivarOffset,
                    size: ivarSize
                )
            )
        }

        return ivars
    }

    private static func parseObjCProtocolList(
        at listVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> [String] {
        guard listVA != .zero,
              listVA != memory.imageBase,
              let rawCount = memory.readUInt64(at: listVA),
              rawCount > 0 else {
            return []
        }
        let count = Int(min(rawCount, 256))
        var names: [String] = []
        names.reserveCapacity(count)

        for idx in 0..<count {
            let slotVA = listVA.adding(UInt64(8 + idx * 8))
            // protocol_t: +0x00 isa, +0x08 mangledName
            if let protoVA = nonHeaderInternalAddress(memory.resolvePointer(at: slotVA), memory: memory),
               let nameVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x08), memory: memory),
               let protoName = memory.readCString(at: nameVA, maxBytes: 16_384),
               !protoName.isEmpty,
               !names.contains(protoName) {
                names.append(protoName)
            }
        }

        return names
    }

    private static func parseObjCCategory(
        at categoryVA: VirtualAddress,
        memory: BinaryMappedMemoryReader,
        sections: [BinarySection]
    ) -> (ObjCCategoryMetadata, [BinarySymbol])? {
        // category_t (64-bit):
        // +0x00 const char *name
        // +0x08 classref_t cls
        // +0x10 method_list_t *instanceMethods
        // +0x18 method_list_t *classMethods
        // +0x20 protocol_list_t *protocols
        guard let catNameVA = nonHeaderInternalAddress(memory.resolvePointer(at: categoryVA), memory: memory),
              let catName = memory.readCString(at: catNameVA, maxBytes: 16_384),
              !catName.isEmpty else {
            return nil
        }

        let hostClassName = resolveSuperclassName(memory.resolvePointer(at: categoryVA + 0x08), memory: memory) ?? "UnknownClass"
        var instanceMethods: [ObjCMethodMetadata] = []
        var classMethods: [ObjCMethodMetadata] = []
        var adoptedProtocols: [String] = []
        var symbols: [BinarySymbol] = []

        if let instMethodsVA = nonHeaderInternalAddress(memory.resolvePointer(at: categoryVA + 0x10), memory: memory) {
            instanceMethods = parseObjCMethodList(at: instMethodsVA, isClassMethod: false, memory: memory)
            for m in instanceMethods where m.implementationAddress != .zero {
                let symName = "-[\(hostClassName)(\(catName)) \(m.selector)]"
                let secIdx = sections.firstIndex { $0.addressRange.contains(m.implementationAddress) }
                symbols.append(
                    BinarySymbol(
                        name: symName,
                        demangledName: symName,
                        kind: .objcMethod,
                        binding: .local,
                        address: m.implementationAddress,
                        size: 0,
                        sectionIndex: secIdx,
                        provenance: .objcMetadata
                    )
                )
            }
        }

        if let clsMethodsVA = nonHeaderInternalAddress(memory.resolvePointer(at: categoryVA + 0x18), memory: memory) {
            classMethods = parseObjCMethodList(at: clsMethodsVA, isClassMethod: true, memory: memory)
            for m in classMethods where m.implementationAddress != .zero {
                let symName = "+[\(hostClassName)(\(catName)) \(m.selector)]"
                let secIdx = sections.firstIndex { $0.addressRange.contains(m.implementationAddress) }
                symbols.append(
                    BinarySymbol(
                        name: symName,
                        demangledName: symName,
                        kind: .objcMethod,
                        binding: .local,
                        address: m.implementationAddress,
                        size: 0,
                        sectionIndex: secIdx,
                        provenance: .objcMetadata
                    )
                )
            }
        }

        if let protoListVA = nonHeaderInternalAddress(memory.resolvePointer(at: categoryVA + 0x20), memory: memory) {
            adoptedProtocols = parseObjCProtocolList(at: protoListVA, memory: memory)
        }

        let metadata = ObjCCategoryMetadata(
            name: catName,
            className: hostClassName,
            address: categoryVA,
            instanceMethods: instanceMethods,
            classMethods: classMethods,
            adoptedProtocols: adoptedProtocols
        )
        return (metadata, symbols)
    }

    private static func parseObjCProtocol(
        at protoVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> ObjCProtocolMetadata? {
        // protocol_t (64-bit):
        // +0x00 id isa
        // +0x08 const char *mangledName
        // +0x10 protocol_list_t *protocols
        // +0x18 method_list_t *instanceMethods
        // +0x20 method_list_t *classMethods
        // +0x28 method_list_t *optionalInstanceMethods
        // +0x30 method_list_t *optionalClassMethods
        guard let nameVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x08), memory: memory),
              let protoName = memory.readCString(at: nameVA, maxBytes: 16_384),
              !protoName.isEmpty else {
            return nil
        }

        var adoptedProtocols: [String] = []
        if let protoListVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x10), memory: memory) {
            adoptedProtocols = parseObjCProtocolList(at: protoListVA, memory: memory)
        }

        var instanceMethods: [ObjCMethodMetadata] = []
        if let instVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x18), memory: memory) {
            instanceMethods = parseObjCMethodList(at: instVA, isClassMethod: false, memory: memory)
        }

        var classMethods: [ObjCMethodMetadata] = []
        if let clsVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x20), memory: memory) {
            classMethods = parseObjCMethodList(at: clsVA, isClassMethod: true, memory: memory)
        }

        var optionalInstanceMethods: [ObjCMethodMetadata] = []
        if let optInstVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x28), memory: memory) {
            optionalInstanceMethods = parseObjCMethodList(at: optInstVA, isClassMethod: false, memory: memory)
        }

        var optionalClassMethods: [ObjCMethodMetadata] = []
        if let optClsVA = nonHeaderInternalAddress(memory.resolvePointer(at: protoVA + 0x30), memory: memory) {
            optionalClassMethods = parseObjCMethodList(at: optClsVA, isClassMethod: true, memory: memory)
        }

        return ObjCProtocolMetadata(
            name: protoName,
            address: protoVA,
            adoptedProtocols: adoptedProtocols,
            instanceMethods: instanceMethods,
            classMethods: classMethods,
            optionalInstanceMethods: optionalInstanceMethods,
            optionalClassMethods: optionalClassMethods
        )
    }

    // MARK: - Swift 5 Runtime Type & Field Descriptor Extractor

    /// Walks `__swift5_types`, `__swift5_protos`, and `__swift5_fieldmd` relative-offset descriptors.
    static func parseSwiftMetadata(
        sliceData: Data,
        sliceFileOffset: FileOffset,
        imageBase: VirtualAddress,
        segments: [BinarySegment],
        sections: [BinarySection],
        chainedFixups: [ChainedFixupRecord]
    ) -> (types: [SwiftTypeDescriptor], metadataSymbols: [BinarySymbol]) {
        let _ = sliceFileOffset
        let typeSections = sections.filter {
            $0.sectionName == "__swift5_types" || $0.sectionName == "__swift5_protos"
        }
        guard !typeSections.isEmpty else {
            return ([], [])
        }

        let memory = BinaryMappedMemoryReader(
            sliceData: sliceData,
            imageBase: imageBase,
            segments: segments,
            sections: sections,
            chainedFixups: chainedFixups
        )

        var descriptors: [SwiftTypeDescriptor] = []
        var helperSymbols: [BinarySymbol] = []
        var visitedDescriptors = Set<VirtualAddress>()

        for sec in typeSections {
            let entryCount = Int(sec.size / 4)
            for i in 0..<min(entryCount, 16_384) {
                let slotVA = sec.vmAddress.adding(UInt64(i * 4))
                guard case .internalAddress(let descVA) = memory.resolveIndirectableRelativePointer(at: slotVA) else {
                    continue
                }
                guard visitedDescriptors.insert(descVA).inserted else {
                    continue
                }

                if let (parsedType, accessorSym) = parseSwiftContextDescriptor(
                    at: descVA,
                    memory: memory,
                    sections: sections
                ) {
                    descriptors.append(parsedType)
                    if let sym = accessorSym {
                        helperSymbols.append(sym)
                    }
                }
            }
        }

        return (descriptors, helperSymbols)
    }

    private static func parseSwiftContextDescriptor(
        at descVA: VirtualAddress,
        memory: BinaryMappedMemoryReader,
        sections: [BinarySection]
    ) -> (SwiftTypeDescriptor, BinarySymbol?)? {
        guard let flags = memory.readUInt32(at: descVA) else {
            return nil
        }

        let kindBits = flags & 0x1F
        let descriptorKind: SwiftTypeDescriptorKind
        switch kindBits {
        case 3:
            descriptorKind = .protocolType
        case 16:
            descriptorKind = .classType
        case 17:
            descriptorKind = .structType
        case 18:
            descriptorKind = .enumType
        default:
            return nil
        }

        // +0x08: RelativeDirectPointer<const char> Name
        guard let nameRel = memory.readInt32(at: descVA + 8), nameRel != 0 else {
            return nil
        }
        let nameVA = (descVA + 8).adding(Int64(nameRel))
        guard let shortName = memory.readCString(at: nameVA, maxBytes: 512), !shortName.isEmpty else {
            return nil
        }

        // Walk parent context chain (+0x04) to recover Module.OuterType qualification
        let parentChain = resolveParentContextNames(startingAt: descVA, memory: memory)
        let qualifiedName = (parentChain + [shortName]).joined(separator: ".")
        let syntheticMangled = synthesizeCanonicalSwiftMangledName(
            parents: parentChain,
            shortName: shortName,
            kind: descriptorKind
        )

        var fieldNames: [String] = []
        var fieldTypes: [String] = []
        var accessorSymbol: BinarySymbol?

        if descriptorKind != .protocolType {
            // TargetTypeContextDescriptor:
            // +0x0C AccessFunctionPtr (Int32 relative)
            // +0x10 Fields (Int32 relative to FieldDescriptor in __swift5_fieldmd)
            if let accessRel = memory.readInt32(at: descVA + 12), accessRel != 0 {
                let accessVA = (descVA + 12).adding(Int64(accessRel))
                if memory.isValidMappedAddress(accessVA) {
                    let secIdx = sections.firstIndex { $0.addressRange.contains(accessVA) }
                    accessorSymbol = BinarySymbol(
                        name: "_\(syntheticMangled)Ma",
                        demangledName: "type metadata accessor for \(qualifiedName)",
                        kind: .swiftFunction,
                        binding: .local,
                        address: accessVA,
                        size: 0,
                        sectionIndex: secIdx,
                        provenance: .swiftMetadata
                    )
                }
            }

            if let fieldsRel = memory.readInt32(at: descVA + 16), fieldsRel != 0 {
                let fieldDescVA = (descVA + 16).adding(Int64(fieldsRel))
                let parsedFields = parseSwiftFieldDescriptor(at: fieldDescVA, memory: memory)
                fieldNames = parsedFields.names
                fieldTypes = parsedFields.types
            }
        }

        let model = SwiftTypeDescriptor(
            mangledName: syntheticMangled,
            demangledName: qualifiedName,
            kind: descriptorKind,
            address: descVA,
            fieldNames: fieldNames,
            fieldTypes: fieldTypes
        )
        return (model, accessorSymbol)
    }

    private static func resolveParentContextNames(
        startingAt descVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> [String] {
        var names: [String] = []
        var currentVA = descVA
        var depth = 0

        while depth < 6 {
            depth += 1
            guard case .internalAddress(let parentVA) = memory.resolveIndirectableRelativePointer(at: currentVA + 4),
                  parentVA != currentVA,
                  let parentFlags = memory.readUInt32(at: parentVA) else {
                break
            }

            let parentKind = parentFlags & 0x1F
            // Module (0), Protocol (3), Class (16), Struct (17), Enum (18) carry Name at +0x08
            if parentKind == 0 || parentKind == 3 || (parentKind >= 16 && parentKind <= 18) {
                if let rel = memory.readInt32(at: parentVA + 8), rel != 0 {
                    let pNameVA = (parentVA + 8).adding(Int64(rel))
                    if let pName = memory.readCString(at: pNameVA, maxBytes: 256), !pName.isEmpty {
                        names.insert(pName, at: 0)
                    }
                }
            }
            currentVA = parentVA
        }

        return names
    }

    private static func synthesizeCanonicalSwiftMangledName(
        parents: [String],
        shortName: String,
        kind: SwiftTypeDescriptorKind
    ) -> String {
        var out = "$s"
        for p in parents {
            out += "\(p.utf8.count)\(p)"
        }
        let suffix: String
        switch kind {
        case .structType: suffix = "V"
        case .classType: suffix = "C"
        case .enumType: suffix = "O"
        case .protocolType: suffix = "P"
        }
        out += "\(shortName.utf8.count)\(shortName)\(suffix)"
        return out
    }

    private static func parseSwiftFieldDescriptor(
        at fieldDescVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> (names: [String], types: [String]) {
        // FieldDescriptor:
        // +0x00 MangledTypeName (Int32)
        // +0x04 Superclass (Int32)
        // +0x08 Kind (UInt16)
        // +0x0A FieldRecordSize (UInt16)
        // +0x0C NumFields (UInt32)
        guard let recordSizeRaw = memory.readUInt16(at: fieldDescVA + 10),
              let numFieldsRaw = memory.readUInt32(at: fieldDescVA + 12),
              numFieldsRaw > 0 else {
            return ([], [])
        }

        let recordStride = recordSizeRaw >= 12 ? Int(recordSizeRaw) : 12
        let count = Int(min(numFieldsRaw, 512))

        var names: [String] = []
        var types: [String] = []
        names.reserveCapacity(count)
        types.reserveCapacity(count)

        for idx in 0..<count {
            let recordVA = fieldDescVA.adding(UInt64(16 + idx * recordStride))
            // FieldRecord:
            // +0x00 Flags (UInt32)
            // +0x04 MangledTypeName (Int32 relative)
            // +0x08 FieldName (Int32 relative)
            guard let nameRel = memory.readInt32(at: recordVA + 8) else {
                break
            }

            let fieldName: String
            if nameRel != 0 {
                let fnVA = (recordVA + 8).adding(Int64(nameRel))
                fieldName = memory.readCString(at: fnVA, maxBytes: 256) ?? "field_\(idx)"
            } else {
                fieldName = "case_\(idx)"
            }

            let fieldType: String
            if let typeRel = memory.readInt32(at: recordVA + 4), typeRel != 0 {
                let typeRefVA = (recordVA + 4).adding(Int64(typeRel))
                fieldType = decodeSwiftSymbolicTypeRef(at: typeRefVA, memory: memory)
            } else {
                fieldType = "Void"
            }

            names.append(fieldName)
            types.append(fieldType)
        }

        return (names, types)
    }

    private static func decodeSwiftSymbolicTypeRef(
        at typeRefVA: VirtualAddress,
        memory: BinaryMappedMemoryReader
    ) -> String {
        let rawBytes = memory.readRawBytes(at: typeRefVA, maxLength: 128)
        guard let first = rawBytes.first, first != 0 else {
            return "Any"
        }

        // Direct (0x01) or Indirect (0x02) symbolic context descriptor reference in __swift5_typeref
        if (first == 0x01 || first == 0x02) && rawBytes.count >= 5 {
            let b0 = UInt32(rawBytes[1])
            let b1 = UInt32(rawBytes[2]) << 8
            let b2 = UInt32(rawBytes[3]) << 16
            let b3 = UInt32(rawBytes[4]) << 24
            let rel = Int32(bitPattern: b0 | b1 | b2 | b3)
            let refSlotVA = typeRefVA + 1
            let targetDescVA: VirtualAddress?
            if first == 0x01 {
                targetDescVA = refSlotVA.adding(Int64(rel))
            } else {
                let indSlot = refSlotVA.adding(Int64(rel))
                if case .internalAddress(let resolved) = memory.resolvePointer(at: indSlot) {
                    targetDescVA = resolved
                } else {
                    targetDescVA = nil
                }
            }
            if let descVA = targetDescVA,
               let nameRel = memory.readInt32(at: descVA + 8),
               nameRel != 0,
               let targetName = memory.readCString(at: (descVA + 8).adding(Int64(nameRel)), maxBytes: 256) {
                let parents = resolveParentContextNames(startingAt: descVA, memory: memory)
                return (parents + [targetName]).joined(separator: ".")
            }
        }

        // Extract printable ASCII mangled type spelling
        let asciiSlice = rawBytes.prefix { $0 >= 0x20 && $0 <= 0x7E }
        let mangled = String(decoding: asciiSlice, as: UTF8.self)
        guard !mangled.isEmpty else { return "OpaqueType" }

        return humanizeSwiftMangledTypeSpelling(mangled)
    }

    static func humanizeSwiftMangledTypeSpelling(_ mangled: String) -> String {
        switch mangled {
        case "Si": return "Int"
        case "Su": return "UInt"
        case "SS": return "String"
        case "Sb": return "Bool"
        case "Sd": return "Double"
        case "Sf": return "Float"
        case "SV": return "UnsafeRawPointer"
        case "Sv": return "UnsafeMutableRawPointer"
        case "yp": return "Any"
        case "yt": return "Void"
        case "s5Int64V": return "Int64"
        case "s6UInt64V": return "UInt64"
        case "s5Int32V": return "Int32"
        case "s6UInt32V": return "UInt32"
        case "s5Int16V": return "Int16"
        case "s6UInt16V": return "UInt16"
        case "s4Int8V": return "Int8"
        case "s5UInt8V": return "UInt8"
        case "10Foundation4UUIDV": return "Foundation.UUID"
        case "10Foundation4DataV": return "Foundation.Data"
        case "10Foundation3URLV": return "Foundation.URL"
        default:
            if mangled.hasSuffix("Sg") && mangled.count > 2 {
                let inner = String(mangled.dropLast(2))
                return "\(humanizeSwiftMangledTypeSpelling(inner))?"
            }
            if mangled.hasPrefix("Say") && mangled.hasSuffix("G") && mangled.count > 4 {
                let inner = String(mangled.dropFirst(3).dropLast(1))
                return "[\(humanizeSwiftMangledTypeSpelling(inner))]"
            }
            let demangled = MachOSymbolDemangler.demangle("$s" + mangled)
            if demangled != "$s" + mangled && demangled != mangled {
                return demangled
            }
            return mangled
        }
    }
}

// MARK: - Objective-C Type Encoding Humanizer

public enum ObjCTypeEncodingFormatter {
    /// Decodes compact ObjC `@encode(...)` type strings (e.g. `"B24@0:8@16"` or `@"NSString"`) into readable C/ObjC types.
    public static func describeType(_ encoding: String) -> String {
        let trimmed = encoding.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "id" }

        if trimmed.hasPrefix("@\"") && trimmed.hasSuffix("\"") && trimmed.count > 3 {
            let cls = String(trimmed.dropFirst(2).dropLast(1))
            return "\(cls) *"
        }

        let chars = Array(trimmed)
        var idx = 0
        while idx < chars.count && ("rnNoORV".contains(chars[idx])) {
            idx += 1
        }
        guard idx < chars.count else { return trimmed }

        switch chars[idx] {
        case "v": return "void"
        case "B": return "BOOL"
        case "c": return "char"
        case "C": return "unsigned char"
        case "s": return "int16_t"
        case "S": return "uint16_t"
        case "i": return "int32_t"
        case "I": return "uint32_t"
        case "l": return "long"
        case "L": return "unsigned long"
        case "q": return "int64_t"
        case "Q": return "uint64_t"
        case "f": return "float"
        case "d": return "double"
        case "@": return "id"
        case "#": return "Class"
        case ":": return "SEL"
        case "*": return "char *"
        case "^":
            let rest = String(chars[(idx + 1)...])
            return rest.isEmpty ? "void *" : "\(describeType(rest)) *"
        default:
            return trimmed
        }
    }
}
