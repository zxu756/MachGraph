import Foundation
@testable import MachBinaryFormats
import MachGraphModels

// MARK: - Byte-Accurate ARM64 Instruction Block Emitter (Fixture Helper)

internal struct SyntheticA64Assembler {
    private enum FixupKind {
        case b(label: String)
        case bl(label: String)
        case bCond(cond: UInt32, label: String)
        case cbz(rt: UInt32, isNonZero: Bool, label: String)
        case adr(rd: UInt32, targetVA: UInt64)
        case adrp(rd: UInt32, targetVA: UInt64)
        case blExternal(targetVA: UInt64)
    }

    let baseVA: UInt64
    private(set) var words: [UInt32] = []
    private var labels: [String: Int] = [:]
    private var pendingFixups: [(wordIndex: Int, kind: FixupKind)] = []

    init(baseVA: UInt64) {
        self.baseVA = baseVA
    }

    var currentVA: UInt64 {
        baseVA + UInt64(words.count * 4)
    }

    mutating func bind(_ label: String) {
        labels[label] = words.count
    }

    mutating func emit(_ word: UInt32) {
        words.append(word)
    }

    mutating func nop() { emit(0xD503_201F) }
    mutating func paciasp() { emit(0xD503_233F) }
    mutating func autiasp() { emit(0xD503_23BF) }
    mutating func ret() { emit(0xD65F_03C0) }
    mutating func retaa() { emit(0xD65F_0BFF) }

    mutating func stpPre64(rt1: UInt32, rt2: UInt32, rn: UInt32, byteOffset: Int) {
        let imm7 = UInt32(bitPattern: Int32(byteOffset / 8)) & 0x7F
        emit(0xA980_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31))
    }

    mutating func ldpPost64(rt1: UInt32, rt2: UInt32, rn: UInt32, byteOffset: Int) {
        let imm7 = UInt32(bitPattern: Int32(byteOffset / 8)) & 0x7F
        emit(0xA8C0_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31))
    }

    mutating func str64Imm(rt: UInt32, rn: UInt32, byteOffset: UInt32) {
        let imm12 = (byteOffset / 8) & 0xFFF
        emit(0xF900_0000 | (imm12 << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    mutating func ldr64Imm(rt: UInt32, rn: UInt32, byteOffset: UInt32) {
        let imm12 = (byteOffset / 8) & 0xFFF
        emit(0xF940_0000 | (imm12 << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    mutating func movX29SP() {
        // ADD X29, SP, #0
        emit(0x9100_03FD)
    }

    mutating func mov64(rd: UInt32, rm: UInt32) {
        emit(0xAA00_03E0 | ((rm & 31) << 16) | (rd & 31))
    }

    mutating func mov32(wd: UInt32, wm: UInt32) {
        emit(0x2A00_03E0 | ((wm & 31) << 16) | (wd & 31))
    }

    mutating func movz32(wd: UInt32, imm16: UInt16) {
        emit(0x5280_0000 | (UInt32(imm16) << 5) | (wd & 31))
    }

    mutating func movz64(xd: UInt32, imm16: UInt16) {
        emit(0xD280_0000 | (UInt32(imm16) << 5) | (xd & 31))
    }

    mutating func add64Imm(rd: UInt32, rn: UInt32, imm12: UInt32) {
        emit(0x9100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5) | (rd & 31))
    }

    mutating func add64Reg(rd: UInt32, rn: UInt32, rm: UInt32) {
        emit(0x8B00_0000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31))
    }

    mutating func eor32Reg(wd: UInt32, wn: UInt32, wm: UInt32) {
        emit(0x4A00_0000 | ((wm & 31) << 16) | ((wn & 31) << 5) | (wd & 31))
    }

    mutating func cmp32Imm(wn: UInt32, imm12: UInt32) {
        emit(0x7100_0000 | ((imm12 & 0xFFF) << 10) | ((wn & 31) << 5) | 31)
    }

    mutating func cmp64Reg(xn: UInt32, xm: UInt32) {
        emit(0xEB00_001F | ((xm & 31) << 16) | ((xn & 31) << 5))
    }

    mutating func ldrbReg(wt: UInt32, xn: UInt32, xm: UInt32) {
        emit(0x3860_6800 | ((xm & 31) << 16) | ((xn & 31) << 5) | (wt & 31))
    }

    mutating func ldrswJumpTableUXTW2(xt: UInt32, xn: UInt32, wm: UInt32) {
        // LDRSW Xt, [Xn, Wm, UXTW #2]
        emit(0xB8A0_5800 | ((wm & 31) << 16) | ((xn & 31) << 5) | (xt & 31))
    }

    mutating func br(xn: UInt32) {
        emit(0xD61F_0000 | ((xn & 31) << 5))
    }

    mutating func b(_ label: String) {
        pendingFixups.append((words.count, .b(label: label)))
        words.append(0x1400_0000)
    }

    mutating func blLabel(_ label: String) {
        pendingFixups.append((words.count, .bl(label: label)))
        words.append(0x9400_0000)
    }

    mutating func blAddress(_ targetVA: UInt64) {
        pendingFixups.append((words.count, .blExternal(targetVA: targetVA)))
        words.append(0x9400_0000)
    }

    mutating func bCond(cond: UInt32, label: String) {
        pendingFixups.append((words.count, .bCond(cond: cond & 0xF, label: label)))
        words.append(0x5400_0000)
    }

    mutating func cbz64(rt: UInt32, label: String) {
        pendingFixups.append((words.count, .cbz(rt: rt & 31, isNonZero: false, label: label)))
        words.append(0xB400_0000)
    }

    mutating func cbnz64(rt: UInt32, label: String) {
        pendingFixups.append((words.count, .cbz(rt: rt & 31, isNonZero: true, label: label)))
        words.append(0xB500_0000)
    }

    mutating func adr(rd: UInt32, targetVA: UInt64) {
        pendingFixups.append((words.count, .adr(rd: rd & 31, targetVA: targetVA)))
        words.append(0x1000_0000)
    }

    mutating func adrp(rd: UInt32, targetVA: UInt64) {
        pendingFixups.append((words.count, .adrp(rd: rd & 31, targetVA: targetVA)))
        words.append(0x9000_0000)
    }

    func addressOfLabel(_ label: String) -> UInt64 {
        let wordIdx = labels[label] ?? 0
        return baseVA + UInt64(wordIdx * 4)
    }

    mutating func finalizeBytes() -> [UInt8] {
        for item in pendingFixups {
            let pc = baseVA + UInt64(item.wordIndex * 4)
            switch item.kind {
            case .b(let label):
                let dst = addressOfLabel(label)
                let imm26 = Int32((Int64(bitPattern: dst) - Int64(bitPattern: pc)) >> 2)
                words[item.wordIndex] = 0x1400_0000 | (UInt32(bitPattern: imm26) & 0x03FF_FFFF)

            case .bl(let label):
                let dst = addressOfLabel(label)
                let imm26 = Int32((Int64(bitPattern: dst) - Int64(bitPattern: pc)) >> 2)
                words[item.wordIndex] = 0x9400_0000 | (UInt32(bitPattern: imm26) & 0x03FF_FFFF)

            case .blExternal(let dst):
                let imm26 = Int32((Int64(bitPattern: dst) - Int64(bitPattern: pc)) >> 2)
                words[item.wordIndex] = 0x9400_0000 | (UInt32(bitPattern: imm26) & 0x03FF_FFFF)

            case .bCond(let cond, let label):
                let dst = addressOfLabel(label)
                let imm19 = Int32((Int64(bitPattern: dst) - Int64(bitPattern: pc)) >> 2)
                words[item.wordIndex] = 0x5400_0000 | ((UInt32(bitPattern: imm19) & 0x7FFFF) << 5) | cond

            case .cbz(let rt, let isNZ, let label):
                let dst = addressOfLabel(label)
                let imm19 = Int32((Int64(bitPattern: dst) - Int64(bitPattern: pc)) >> 2)
                let baseOp: UInt32 = isNZ ? 0xB500_0000 : 0xB400_0000
                words[item.wordIndex] = baseOp | ((UInt32(bitPattern: imm19) & 0x7FFFF) << 5) | rt

            case .adr(let rd, let dst):
                let imm21 = Int32(Int64(bitPattern: dst) - Int64(bitPattern: pc))
                let raw = UInt32(bitPattern: imm21)
                let immlo = raw & 0x3
                let immhi = (raw >> 2) & 0x7FFFF
                words[item.wordIndex] = 0x1000_0000 | (immlo << 29) | (immhi << 5) | rd

            case .adrp(let rd, let dst):
                let pcPage = Int64(bitPattern: pc & ~UInt64(0xFFF))
                let dstPage = Int64(bitPattern: dst & ~UInt64(0xFFF))
                let pageDelta = Int32((dstPage - pcPage) >> 12)
                let raw = UInt32(bitPattern: pageDelta)
                let immlo = raw & 0x3
                let immhi = (raw >> 2) & 0x7FFFF
                words[item.wordIndex] = 0x9000_0000 | (immlo << 29) | (immhi << 5) | rd
            }
        }

        var out = BinaryBufferWriter(capacity: words.count * 4, endianness: .little)
        for w in words {
            out.appendUInt32(w)
        }
        return out.bytes
    }
}

// MARK: - Synthetic Multi-Format Binary Fixture Builder

public enum SyntheticBinaryFixtureBuilder {

    // MARK: - 1. Full Single-Arch ARM64 / ARM64e Mach-O 64 Executable

    /// Convenience default demo ARM64 Mach-O 64 executable with real CFG, switch table, chained fixups, export trie, ObjC/Swift metadata, and ad-hoc code signature.
    public static func buildMachO64Executable() -> Data {
        buildARM64MachOExecutable(useARM64E: false)
    }

    /// Constructs a byte-accurate 64-bit ARM64 (`arm64` or `arm64e`) Mach-O executable image in memory.
    public static func buildARM64MachOExecutable(
        useARM64E: Bool = false,
        identifier: String = "com.machgraph.demo.target",
        includeCMSCertificates: Bool = false
    ) -> Data {
        let imageBase: UInt64 = 0x0000_0001_0000_0000
        let textFileOff = 0x0000
        let dataConstFileOff = 0x4000
        let dataFileOff = 0x8000
        let linkeditFileOff = 0xC000

        let textVA: UInt64 = imageBase + 0x1000
        let stubsVA: UInt64 = imageBase + 0x1400
        let constVA: UInt64 = imageBase + 0x1500
        let cstringVA: UInt64 = imageBase + 0x2000
        let objcMethnameVA: UInt64 = imageBase + 0x2200
        let objcClassnameVA: UInt64 = imageBase + 0x2280
        let objcMethtypeVA: UInt64 = imageBase + 0x2300
        let swiftReflStrVA: UInt64 = imageBase + 0x2380
        let swiftTyperefVA: UInt64 = imageBase + 0x2400
        let swiftFieldmdVA: UInt64 = imageBase + 0x2480
        let swiftTypesVA: UInt64 = imageBase + 0x2540

        let gotVA: UInt64 = imageBase + 0x4000
        let objcClasslistVA: UInt64 = imageBase + 0x4020
        let objcConstVA: UInt64 = imageBase + 0x4100

        let objcDataVA: UInt64 = imageBase + 0x8000
        let objcIvarVA: UInt64 = imageBase + 0x8060
        let mutableDataVA: UInt64 = imageBase + 0x8080

        // Build __TEXT,__cstring pool
        var cstringPool = BinaryBufferWriter(capacity: 256, endianness: .little)
        let strLicenseKeyVA = cstringVA + UInt64(cstringPool.count)
        cstringPool.appendCString("MACHGRAPH-PRO-2026")
        let strVerifiedFmtVA = cstringVA + UInt64(cstringPool.count)
        cstringPool.appendCString("License verified: %s")
        let strInvalidVA = cstringVA + UInt64(cstringPool.count)
        cstringPool.appendCString("Invalid license token")
        let strReadyFmtVA = cstringVA + UInt64(cstringPool.count)
        cstringPool.appendCString("MachGraph Ready: status=%d\n")
        let _ = cstringVA + UInt64(cstringPool.count)
        cstringPool.appendCString("https://telemetry.machgraph.internal/v1/heartbeat")
        cstringPool.appendCString(["MASTER", "TOKEN", "2026", "DEMO"].joined(separator: "_"))

        // Build __TEXT,__stubs (3 stubs x 12 bytes = 36 bytes: _printf, _puts, _strcmp)
        let printfStubVA = stubsVA + 0
        let putsStubVA   = stubsVA + 12
        let strcmpStubVA = stubsVA + 24

        var stubsAsm = SyntheticA64Assembler(baseVA: stubsVA)
        // Stub 0: _printf -> GOT[0] (0x100004000)
        stubsAsm.adrp(rd: 16, targetVA: gotVA)
        stubsAsm.ldr64Imm(rt: 16, rn: 16, byteOffset: 0)
        stubsAsm.br(xn: 16)
        // Stub 1: _puts -> GOT[1] (0x100004008)
        stubsAsm.adrp(rd: 16, targetVA: gotVA + 8)
        stubsAsm.ldr64Imm(rt: 16, rn: 16, byteOffset: 8)
        stubsAsm.br(xn: 16)
        // Stub 2: _strcmp -> GOT[2] (0x100004010)
        stubsAsm.adrp(rd: 16, targetVA: gotVA + 16)
        stubsAsm.ldr64Imm(rt: 16, rn: 16, byteOffset: 16)
        stubsAsm.br(xn: 16)
        let stubsBytes = stubsAsm.finalizeBytes()

        // Assemble 6 realistic ARM64 functions in __TEXT,__text
        var asm = SyntheticA64Assembler(baseVA: textVA)

        // Function 1: _compute_checksum(const uint8_t *buf, size_t len) -> uint32_t (natural loop!)
        asm.bind("_compute_checksum")
        asm.movz32(wd: 2, imm16: 0x5A)
        asm.movz64(xd: 3, imm16: 0)
        asm.bind("checksum_loop")
        asm.cmp64Reg(xn: 3, xm: 1)
        asm.bCond(cond: 0x2, label: "checksum_done") // b.hs
        asm.ldrbReg(wt: 4, xn: 0, xm: 3)
        asm.eor32Reg(wd: 2, wn: 2, wm: 4)
        asm.add64Imm(rd: 3, rn: 3, imm12: 1)
        asm.b("checksum_loop")
        asm.bind("checksum_done")
        asm.mov32(wd: 0, wm: 2)
        asm.ret()

        // Function 2: _verify_license(const char *candidate) -> int (PAC + diamond branch + string xrefs + calls)
        asm.bind("_verify_license")
        if useARM64E { asm.paciasp() }
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -32)
        asm.movX29SP()
        asm.str64Imm(rt: 19, rn: 31, byteOffset: 16)
        asm.cbz64(rt: 0, label: "verify_fail")
        asm.mov64(rd: 19, rm: 0)
        asm.adrp(rd: 1, targetVA: strLicenseKeyVA)
        asm.add64Imm(rd: 1, rn: 1, imm12: UInt32(strLicenseKeyVA & 0xFFF))
        asm.blAddress(strcmpStubVA)
        asm.cbnz64(rt: 0, label: "verify_fail")
        asm.mov64(rd: 0, rm: 19)
        asm.movz64(xd: 1, imm16: 18)
        asm.blLabel("_compute_checksum")
        asm.adrp(rd: 0, targetVA: strVerifiedFmtVA)
        asm.add64Imm(rd: 0, rn: 0, imm12: UInt32(strVerifiedFmtVA & 0xFFF))
        asm.blAddress(putsStubVA)
        asm.movz32(wd: 0, imm16: 1)
        asm.b("verify_epilogue")
        asm.bind("verify_fail")
        asm.adrp(rd: 0, targetVA: strInvalidVA)
        asm.add64Imm(rd: 0, rn: 0, imm12: UInt32(strInvalidVA & 0xFFF))
        asm.blAddress(putsStubVA)
        asm.movz32(wd: 0, imm16: 0)
        asm.bind("verify_epilogue")
        asm.ldr64Imm(rt: 19, rn: 31, byteOffset: 16)
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 32)
        if useARM64E { asm.retaa() } else { asm.ret() }

        // Function 3: _dispatch_command(uint32_t op) -> int (4-way switch jump table at constVA!)
        asm.bind("_dispatch_command")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.cmp32Imm(wn: 0, imm12: 3)
        asm.bCond(cond: 0x8, label: "sw_default") // b.hi
        asm.adr(rd: 8, targetVA: constVA)
        asm.ldrswJumpTableUXTW2(xt: 9, xn: 8, wm: 0)
        asm.add64Reg(rd: 8, rn: 8, rm: 9)
        asm.br(xn: 8)
        asm.bind("sw_case0")
        asm.movz32(wd: 0, imm16: 100)
        asm.b("sw_exit")
        asm.bind("sw_case1")
        asm.movz32(wd: 0, imm16: 200)
        asm.b("sw_exit")
        asm.bind("sw_case2")
        asm.movz32(wd: 0, imm16: 300)
        asm.b("sw_exit")
        asm.bind("sw_case3")
        asm.movz32(wd: 0, imm16: 400)
        asm.b("sw_exit")
        asm.bind("sw_default")
        asm.movz32(wd: 0, imm16: 999)
        asm.bind("sw_exit")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()

        // Function 4: -[MGAuthController validateToken:] (self=x0, _cmd=x1, token=x2)
        asm.bind("objc_validateToken")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.mov64(rd: 0, rm: 2)
        asm.blLabel("_verify_license")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()

        // Function 5: +[MGAuthController sharedController]
        asm.bind("objc_sharedController")
        asm.adrp(rd: 8, targetVA: mutableDataVA)
        asm.ldr64Imm(rt: 0, rn: 8, byteOffset: UInt32(mutableDataVA & 0xFFF))
        asm.ret()

        // Function 6: _main (LC_MAIN entry point)
        asm.bind("_main")
        if useARM64E { asm.paciasp() }
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.adrp(rd: 0, targetVA: strLicenseKeyVA)
        asm.add64Imm(rd: 0, rn: 0, imm12: UInt32(strLicenseKeyVA & 0xFFF))
        asm.blLabel("_verify_license")
        asm.blLabel("_dispatch_command")
        asm.mov32(wd: 1, wm: 0)
        asm.adrp(rd: 0, targetVA: strReadyFmtVA)
        asm.add64Imm(rd: 0, rn: 0, imm12: UInt32(strReadyFmtVA & 0xFFF))
        asm.blAddress(printfStubVA)
        asm.movz32(wd: 0, imm16: 0)
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        if useARM64E { asm.retaa() } else { asm.ret() }

        let textBytes = asm.finalizeBytes()

        let fnChecksumVA = asm.addressOfLabel("_compute_checksum")
        let fnVerifyVA   = asm.addressOfLabel("_verify_license")
        let fnDispatchVA = asm.addressOfLabel("_dispatch_command")
        let fnObjcInstVA = asm.addressOfLabel("objc_validateToken")
        let fnObjcClsVA  = asm.addressOfLabel("objc_sharedController")
        let fnMainVA     = asm.addressOfLabel("_main")

        // Build __TEXT,__const jump table (4 x Int32 relative to constVA)
        var constPool = BinaryBufferWriter(capacity: 16, endianness: .little)
        for caseLabel in ["sw_case0", "sw_case1", "sw_case2", "sw_case3"] {
            let targetVA = asm.addressOfLabel(caseLabel)
            let rel32 = Int32(Int64(bitPattern: targetVA) - Int64(bitPattern: constVA))
            constPool.appendUInt32(UInt32(bitPattern: rel32))
        }

        // Build ObjC string pools in __TEXT
        var objcMethPool = BinaryBufferWriter(capacity: 64, endianness: .little)
        let selValidateVA = objcMethnameVA + UInt64(objcMethPool.count)
        objcMethPool.appendCString("validateToken:")
        let selSharedVA = objcMethnameVA + UInt64(objcMethPool.count)
        objcMethPool.appendCString("sharedController")

        var objcClassPool = BinaryBufferWriter(capacity: 64, endianness: .little)
        let clsNameAuthVA = objcClassnameVA + UInt64(objcClassPool.count)
        objcClassPool.appendCString("MGAuthController")
        let protoNameCodingVA = objcClassnameVA + UInt64(objcClassPool.count)
        objcClassPool.appendCString("NSSecureCoding")

        var objcTypePool = BinaryBufferWriter(capacity: 64, endianness: .little)
        let typeValidateVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("B24@0:8@16")
        let typeSharedVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("@16@0:8")
        let ivarNameSessionVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("_sessionKey")
        let ivarTypeSessionVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("@\"NSString\"")
        let ivarNameRetryVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("_retryCount")
        let ivarTypeRetryVA = objcMethtypeVA + UInt64(objcTypePool.count)
        objcTypePool.appendCString("Q")

        // Build Swift 5 metadata sections in __TEXT
        var swiftReflPool = BinaryBufferWriter(capacity: 64, endianness: .little)
        let swField0NameVA = swiftReflStrVA + UInt64(swiftReflPool.count)
        swiftReflPool.appendCString("token")
        let swField1NameVA = swiftReflStrVA + UInt64(swiftReflPool.count)
        swiftReflPool.appendCString("flags")
        let swField2NameVA = swiftReflStrVA + UInt64(swiftReflPool.count)
        swiftReflPool.appendCString("isValid")

        var swiftTyperefPool = BinaryBufferWriter(capacity: 64, endianness: .little)
        let swModNameVA = swiftTyperefVA + UInt64(swiftTyperefPool.count)
        swiftTyperefPool.appendCString("MachGraphTarget")
        let swStructNameVA = swiftTyperefVA + UInt64(swiftTyperefPool.count)
        swiftTyperefPool.appendCString("LicensePacket")
        let swTypeSSVA = swiftTyperefVA + UInt64(swiftTyperefPool.count)
        swiftTyperefPool.appendCString("SS")
        let swTypeU64VA = swiftTyperefVA + UInt64(swiftTyperefPool.count)
        swiftTyperefPool.appendCString("s6UInt64V")
        let swTypeBoolVA = swiftTyperefVA + UInt64(swiftTyperefPool.count)
        swiftTyperefPool.appendCString("Sb")

        // __swift5_fieldmd at swiftFieldmdVA (16-byte header + 3 * 12-byte FieldRecord = 52 bytes)
        var swiftFieldmdPool = BinaryBufferWriter(capacity: 64, endianness: .little)
        swiftFieldmdPool.appendUInt32(relOffset32(from: swiftFieldmdVA + 0, to: swStructNameVA)) // MangledTypeName
        swiftFieldmdPool.appendUInt32(0) // Superclass
        swiftFieldmdPool.appendUInt16(0) // FieldDescriptorKind::Struct
        swiftFieldmdPool.appendUInt16(12) // FieldRecordSize
        swiftFieldmdPool.appendUInt32(3) // NumFields

        let fieldSpecs: [(typeVA: UInt64, nameVA: UInt64)] = [
            (swTypeSSVA, swField0NameVA),
            (swTypeU64VA, swField1NameVA),
            (swTypeBoolVA, swField2NameVA)
        ]
        for (idx, fSpec) in fieldSpecs.enumerated() {
            let recBase = swiftFieldmdVA + UInt64(16 + idx * 12)
            swiftFieldmdPool.appendUInt32(0x2) // IsVar
            swiftFieldmdPool.appendUInt32(relOffset32(from: recBase + 4, to: fSpec.typeVA))
            swiftFieldmdPool.appendUInt32(relOffset32(from: recBase + 8, to: fSpec.nameVA))
        }

        // ModuleContextDescriptor (16 bytes) + StructDescriptor (24 bytes) right after fieldmd at swiftFieldmdVA + 0x40
        let swiftModDescVA = swiftFieldmdVA + 0x40
        let swiftStructDescVA = swiftFieldmdVA + 0x50
        while swiftFieldmdPool.count < 0x40 { swiftFieldmdPool.appendUInt8(0) }
        // ModuleContextDescriptor (kind = 0)
        swiftFieldmdPool.appendUInt32(0) // flags: Module = 0
        swiftFieldmdPool.appendUInt32(0) // parent = null
        swiftFieldmdPool.appendUInt32(relOffset32(from: swiftModDescVA + 8, to: swModNameVA))
        swiftFieldmdPool.appendUInt32(0)
        // TargetStructDescriptor (kind = 17)
        swiftFieldmdPool.appendUInt32(0x0000_0051) // flags: Struct(17) | unique(0x40)
        swiftFieldmdPool.appendUInt32(relOffset32(from: swiftStructDescVA + 4, to: swiftModDescVA))
        swiftFieldmdPool.appendUInt32(relOffset32(from: swiftStructDescVA + 8, to: swStructNameVA))
        swiftFieldmdPool.appendUInt32(0) // AccessFunctionPtr
        swiftFieldmdPool.appendUInt32(relOffset32(from: swiftStructDescVA + 16, to: swiftFieldmdVA))
        swiftFieldmdPool.appendUInt32(3) // NumFields

        // __swift5_types (4 bytes pointing to swiftStructDescVA)
        var swiftTypesPool = BinaryBufferWriter(capacity: 4, endianness: .little)
        swiftTypesPool.appendUInt32(relOffset32(from: swiftTypesVA, to: swiftStructDescVA))

        // Collect Chained Fixups for Segment 2 (__DATA_CONST) and Segment 3 (__DATA)
        // Imports table ordinals:
        // 0: _printf (lib 1)
        // 1: _puts (lib 1)
        // 2: _strcmp (lib 1)
        // 3: _OBJC_CLASS_$_NSObject (lib 2)
        // 4: _OBJC_METACLASS_$_NSObject (lib 2)
        struct PendingChainFixup {
            let segIndex: Int
            let segOffset: Int
            let isBind: Bool
            let isAuth: Bool
            let targetVAOrOrdinal: UInt64
            let pacDiversity: UInt16
            let pacKeyBits: UInt64
        }
        var chainFixups: [PendingChainFixup] = []

        // Build __DATA_CONST structures:
        // 0x0000..0x0018: __got (3 binds)
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0000, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 0, pacDiversity: 0x101, pacKeyBits: 0))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0008, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 1, pacDiversity: 0x102, pacKeyBits: 0))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0010, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 2, pacDiversity: 0x103, pacKeyBits: 0))

        // 0x0020..0x0028: __objc_classlist -> rebase to objcDataVA (0x100008000)
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0020, isBind: false, isAuth: false, targetVAOrOrdinal: objcDataVA, pacDiversity: 0, pacKeyBits: 2))

        // Build __objc_const at offset 0x0100 inside __DATA_CONST (objcConstVA = 0x100004100):
        // +0x000 (0x100004100): instance small relative method_list_t (20 bytes -> padded to 0x20)
        // +0x020 (0x100004120): metaclass small relative method_list_t (20 bytes -> padded to 0x40)
        // +0x040 (0x100004140): protocol_t NSSecureCoding (24 bytes -> padded to 0x60)
        // +0x060 (0x100004160): protocol_list_t (16 bytes -> padded to 0x80)
        // +0x080 (0x100004180): ivar_list_t (8 + 2*32 = 72 bytes -> padded to 0xD0)
        // +0x0D0 (0x1000041D0): class_ro_t MGAuthController (72 bytes -> padded to 0x120)
        // +0x120 (0x100004220): metaclass class_ro_t MGAuthController (72 bytes -> 0x168)
        let instMethodListVA  = objcConstVA + 0x000
        let classMethodListVA = objcConstVA + 0x020
        let protoObjVA        = objcConstVA + 0x040
        let protoListVA       = objcConstVA + 0x060
        let ivarListVA        = objcConstVA + 0x080
        let classROVA         = objcConstVA + 0x0D0
        let metaClassROVA     = objcConstVA + 0x120

        var objcConstBuf = [UInt8](repeating: 0, count: 0x170)
        func writeU32(_ buf: inout [UInt8], at off: Int, _ val: UInt32) {
            for s in 0..<4 { buf[off + s] = UInt8(truncatingIfNeeded: val >> (s * 8)) }
        }
        func writeU64(_ buf: inout [UInt8], at off: Int, _ val: UInt64) {
            for s in 0..<8 { buf[off + s] = UInt8(truncatingIfNeeded: val >> (s * 8)) }
        }

        // Instance relative method_list_t (SMALL | DIRECT_SEL | 12 = 0xC000000C)
        writeU32(&objcConstBuf, at: 0x000, 0xC000_000C)
        writeU32(&objcConstBuf, at: 0x004, 1)
        writeU32(&objcConstBuf, at: 0x008, relOffset32(from: instMethodListVA + 8, to: selValidateVA))
        writeU32(&objcConstBuf, at: 0x00C, relOffset32(from: instMethodListVA + 12, to: typeValidateVA))
        writeU32(&objcConstBuf, at: 0x010, relOffset32(from: instMethodListVA + 16, to: fnObjcInstVA))

        // Metaclass relative method_list_t
        writeU32(&objcConstBuf, at: 0x020, 0xC000_000C)
        writeU32(&objcConstBuf, at: 0x024, 1)
        writeU32(&objcConstBuf, at: 0x028, relOffset32(from: classMethodListVA + 8, to: selSharedVA))
        writeU32(&objcConstBuf, at: 0x02C, relOffset32(from: classMethodListVA + 12, to: typeSharedVA))
        writeU32(&objcConstBuf, at: 0x030, relOffset32(from: classMethodListVA + 16, to: fnObjcClsVA))

        // protocol_t (+0x08 mangledName -> protoNameCodingVA)
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x048, isBind: false, isAuth: false, targetVAOrOrdinal: protoNameCodingVA, pacDiversity: 0, pacKeyBits: 2))

        // protocol_list_t (count = 1, slot 0 -> protoObjVA)
        writeU64(&objcConstBuf, at: 0x060, 1)
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x068, isBind: false, isAuth: false, targetVAOrOrdinal: protoObjVA, pacDiversity: 0, pacKeyBits: 2))

        // ivar_list_t (entsize = 32, count = 2)
        writeU32(&objcConstBuf, at: 0x080, 32)
        writeU32(&objcConstBuf, at: 0x084, 2)
        // ivar 0 at 0x088: _sessionKey
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x088, isBind: false, isAuth: false, targetVAOrOrdinal: objcIvarVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x090, isBind: false, isAuth: false, targetVAOrOrdinal: ivarNameSessionVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x098, isBind: false, isAuth: false, targetVAOrOrdinal: ivarTypeSessionVA, pacDiversity: 0, pacKeyBits: 2))
        writeU32(&objcConstBuf, at: 0x0A0, 3)
        writeU32(&objcConstBuf, at: 0x0A4, 8)
        // ivar 1 at 0x0A8: _retryCount
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0A8, isBind: false, isAuth: false, targetVAOrOrdinal: objcIvarVA + 4, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0B0, isBind: false, isAuth: false, targetVAOrOrdinal: ivarNameRetryVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0B8, isBind: false, isAuth: false, targetVAOrOrdinal: ivarTypeRetryVA, pacDiversity: 0, pacKeyBits: 2))
        writeU32(&objcConstBuf, at: 0x0C0, 3)
        writeU32(&objcConstBuf, at: 0x0C4, 8)

        // class_ro_t at 0x0D0 (MGAuthController)
        writeU32(&objcConstBuf, at: 0x0D0, 0x00) // flags
        writeU32(&objcConstBuf, at: 0x0D4, 8)    // instanceStart
        writeU32(&objcConstBuf, at: 0x0D8, 24)   // instanceSize
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0E8, isBind: false, isAuth: false, targetVAOrOrdinal: clsNameAuthVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0F0, isBind: false, isAuth: false, targetVAOrOrdinal: instMethodListVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x0F8, isBind: false, isAuth: false, targetVAOrOrdinal: protoListVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x100, isBind: false, isAuth: false, targetVAOrOrdinal: ivarListVA, pacDiversity: 0, pacKeyBits: 2))

        // metaclass class_ro_t at 0x120
        writeU32(&objcConstBuf, at: 0x120, 0x01) // RO_META
        writeU32(&objcConstBuf, at: 0x124, 40)
        writeU32(&objcConstBuf, at: 0x128, 40)
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x138, isBind: false, isAuth: false, targetVAOrOrdinal: clsNameAuthVA, pacDiversity: 0, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 2, segOffset: 0x0100 + 0x140, isBind: false, isAuth: false, targetVAOrOrdinal: classMethodListVA, pacDiversity: 0, pacKeyBits: 2))

        // Build Segment 3 (__DATA) fixups:
        // 0x0000: MGAuthController objc_class_t (40 bytes)
        // 0x0028: MGAuthController metaclass objc_class_t (40 bytes)
        let metaClassVA = objcDataVA + 0x28
        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0000, isBind: false, isAuth: useARM64E, targetVAOrOrdinal: metaClassVA, pacDiversity: 0x201, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0008, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 3, pacDiversity: 0x202, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0020, isBind: false, isAuth: false, targetVAOrOrdinal: classROVA, pacDiversity: 0, pacKeyBits: 2))

        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0028, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 4, pacDiversity: 0x203, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0030, isBind: true, isAuth: useARM64E, targetVAOrOrdinal: 4, pacDiversity: 0x204, pacKeyBits: 2))
        chainFixups.append(PendingChainFixup(segIndex: 3, segOffset: 0x0048, isBind: false, isAuth: false, targetVAOrOrdinal: metaClassROVA, pacDiversity: 0, pacKeyBits: 2))

        // Assemble 3 pages (__TEXT 0x4000 + __DATA_CONST 0x4000 + __DATA 0x4000 = 0xC000 bytes)
        var sliceBytes = [UInt8](repeating: 0, count: 0xC000)

        func copyIntoSlice(at offset: Int, _ src: [UInt8]) {
            for i in 0..<src.count {
                sliceBytes[offset + i] = src[i]
            }
        }

        copyIntoSlice(at: 0x1000, textBytes)
        copyIntoSlice(at: 0x1400, stubsBytes)
        copyIntoSlice(at: 0x1500, constPool.bytes)
        copyIntoSlice(at: 0x2000, cstringPool.bytes)
        copyIntoSlice(at: 0x2200, objcMethPool.bytes)
        copyIntoSlice(at: 0x2280, objcClassPool.bytes)
        copyIntoSlice(at: 0x2300, objcTypePool.bytes)
        copyIntoSlice(at: 0x2380, swiftReflPool.bytes)
        copyIntoSlice(at: 0x2400, swiftTyperefPool.bytes)
        copyIntoSlice(at: 0x2480, swiftFieldmdPool.bytes)
        copyIntoSlice(at: 0x2540, swiftTypesPool.bytes)
        copyIntoSlice(at: dataConstFileOff + 0x0100, objcConstBuf)

        // Populate __DATA,__objc_ivar offsets (8 and 16) and __DATA,__data UTF-16LE literal
        writeU32(&sliceBytes, at: dataFileOff + 0x0060, 8)
        writeU32(&sliceBytes, at: dataFileOff + 0x0064, 16)
        writeU64(&sliceBytes, at: dataFileOff + 0x0080, 0xCAFE_BEEF_0000_0001)
        let utf16Text = "MachGraphUTF16"
        var utf16Offset = dataFileOff + 0x0088
        for unit in utf16Text.utf16 {
            sliceBytes[utf16Offset] = UInt8(truncatingIfNeeded: unit)
            sliceBytes[utf16Offset + 1] = UInt8(truncatingIfNeeded: unit >> 8)
            utf16Offset += 2
        }

        // Write encoded Chained Pointer words into __DATA_CONST (seg 2) and __DATA (seg 3) and build LC_DYLD_CHAINED_FIXUPS payload
        let ptrFormat: DyldChainedPtrFormat = useARM64E ? .arm64eUserland : .ptr64
        let stride = ptrFormat.strideBytes

        var pageFirstStartBySeg: [Int: UInt16] = [:]
        for segIdx in [2, 3] {
            let segBaseFileOff = (segIdx == 2) ? dataConstFileOff : dataFileOff
            let segChain = chainFixups.filter { $0.segIndex == segIdx }.sorted { $0.segOffset < $1.segOffset }
            guard let first = segChain.first else { continue }
            pageFirstStartBySeg[segIdx] = UInt16(first.segOffset)

            for idx in segChain.indices {
                let cur = segChain[idx]
                let nextSkip: UInt64
                if idx + 1 < segChain.count {
                    nextSkip = UInt64((segChain[idx + 1].segOffset - cur.segOffset) / stride)
                } else {
                    nextSkip = 0
                }

                let encodedWord: UInt64
                if useARM64E {
                    // DYLD_CHAINED_PTR_ARM64E_USERLAND (stride 8)
                    switch (cur.isAuth, cur.isBind) {
                    case (false, false):
                        let vmOff = (cur.targetVAOrOrdinal - imageBase) & 0x0000_07FF_FFFF_FFFF
                        encodedWord = vmOff | ((nextSkip & 0x7FF) << 51)
                    case (false, true):
                        let ord = cur.targetVAOrOrdinal & 0xFFFF
                        encodedWord = ord | ((nextSkip & 0x7FF) << 51) | (1 << 62)
                    case (true, false):
                        let vmOff32 = (cur.targetVAOrOrdinal - imageBase) & 0xFFFF_FFFF
                        let div = UInt64(cur.pacDiversity) << 32
                        let key = (cur.pacKeyBits & 0x3) << 49
                        encodedWord = vmOff32 | div | (1 << 48) | key | ((nextSkip & 0x7FF) << 51) | (1 << 63)
                    case (true, true):
                        let ord = cur.targetVAOrOrdinal & 0xFFFF
                        let div = UInt64(cur.pacDiversity) << 32
                        let key = (cur.pacKeyBits & 0x3) << 49
                        encodedWord = ord | div | (1 << 48) | key | ((nextSkip & 0x7FF) << 51) | (1 << 62) | (1 << 63)
                    }
                } else {
                    // DYLD_CHAINED_PTR_64 (stride 4)
                    if cur.isBind {
                        let ord = cur.targetVAOrOrdinal & 0x00FF_FFFF
                        encodedWord = ord | ((nextSkip & 0xFFF) << 51) | (1 << 63)
                    } else {
                        let target36 = cur.targetVAOrOrdinal & 0x000F_FFFF_FFFF
                        encodedWord = target36 | ((nextSkip & 0xFFF) << 51)
                    }
                }
                writeU64(&sliceBytes, at: segBaseFileOff + cur.segOffset, encodedWord)
            }
        }

        // Build LC_DYLD_CHAINED_FIXUPS blob
        let chainedFixupsData = buildChainedFixupsPayload(
            ptrFormat: ptrFormat,
            seg2FirstStart: pageFirstStartBySeg[2] ?? 0xFFFF,
            seg3FirstStart: pageFirstStartBySeg[3] ?? 0xFFFF
        )

        // Build LC_DYLD_EXPORTS_TRIE blob
        let exportsTrieData = ExportTrieBuilder.buildTrie(entries: [
            .init(name: "__mh_execute_header", offsetFromImageBase: 0, flags: 0),
            .init(name: "_compute_checksum", offsetFromImageBase: fnChecksumVA - imageBase, flags: 0),
            .init(name: "_verify_license", offsetFromImageBase: fnVerifyVA - imageBase, flags: 0),
            .init(name: "_dispatch_command", offsetFromImageBase: fnDispatchVA - imageBase, flags: 0),
            .init(name: "_main", offsetFromImageBase: fnMainVA - imageBase, flags: 0)
        ])

        // Build LC_FUNCTION_STARTS ULEB128 delta table
        var fnStartsWriter = BinaryBufferWriter(capacity: 32, endianness: .little)
        let fnAddresses = [fnChecksumVA, fnVerifyVA, fnDispatchVA, fnObjcInstVA, fnObjcClsVA, fnMainVA]
        var prevOff: UInt64 = 0
        for va in fnAddresses {
            let off = va - imageBase
            fnStartsWriter.appendULEB128(off - prevOff)
            prevOff = off
        }
        fnStartsWriter.padToAlignment(8)
        let functionStartsData = fnStartsWriter.data

        // Build LC_SYMTAB (nlist_64 + string table) & LC_DYSYMTAB (indirect symbols)
        var symStrPool = BinaryBufferWriter(capacity: 256, endianness: .little)
        symStrPool.appendUInt8(0)
        func internSym(_ name: String) -> UInt32 {
            let off = UInt32(symStrPool.count)
            symStrPool.appendCString(name)
            return off
        }

        // Defined symbols (0..5) + Undefined external symbols (6..10)
        let definedSyms: [(name: String, nSect: UInt8, va: UInt64, ext: Bool)] = [
            ("__mh_execute_header", 1, imageBase, true),
            ("_compute_checksum", 1, fnChecksumVA, true),
            ("_verify_license", 1, fnVerifyVA, true),
            ("_dispatch_command", 1, fnDispatchVA, true),
            ("_main", 1, fnMainVA, true),
            ("_OBJC_CLASS_$_MGAuthController", 14, objcDataVA, true)
        ]
        let undefSyms: [(name: String, libOrd: UInt8)] = [
            ("_printf", 1),
            ("_puts", 1),
            ("_strcmp", 1),
            ("_OBJC_CLASS_$_NSObject", 2),
            ("_OBJC_METACLASS_$_NSObject", 2)
        ]

        var nlistWriter = BinaryBufferWriter(capacity: (definedSyms.count + undefSyms.count) * 16, endianness: .little)
        for def in definedSyms {
            nlistWriter.appendUInt32(internSym(def.name))
            nlistWriter.appendUInt8(MachOConstants.nSect | (def.ext ? MachOConstants.nExt : 0))
            nlistWriter.appendUInt8(def.nSect)
            nlistWriter.appendUInt16(0)
            nlistWriter.appendUInt64(def.va)
        }
        for und in undefSyms {
            nlistWriter.appendUInt32(internSym(und.name))
            nlistWriter.appendUInt8(MachOConstants.nUndf | MachOConstants.nExt)
            nlistWriter.appendUInt8(0)
            nlistWriter.appendUInt16(UInt16(und.libOrd) << 8)
            nlistWriter.appendUInt64(0)
        }
        symStrPool.padToAlignment(8)

        // Indirect symbol table: indices 0..2 for __TEXT,__stubs, indices 3..5 for __DATA_CONST,__got -> nlist indices 6, 7, 8
        var indirectWriter = BinaryBufferWriter(capacity: 24, endianness: .little)
        for idx in [UInt32(6), 7, 8, 6, 7, 8] {
            indirectWriter.appendUInt32(idx)
        }

        // Pack __LINKEDIT starting at file offset 0xC000
        var linkeditWriter = BinaryBufferWriter(capacity: 2048, endianness: .little)
        let chainedOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendData(chainedFixupsData)
        linkeditWriter.padToAlignment(8)

        let exportsOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendData(exportsTrieData)
        linkeditWriter.padToAlignment(8)

        let fnStartsOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendData(functionStartsData)
        linkeditWriter.padToAlignment(8)

        let symtabOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendBytes(nlistWriter.bytes)

        let indirectOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendBytes(indirectWriter.bytes)

        let strtabOff = linkeditFileOff + linkeditWriter.count
        linkeditWriter.appendBytes(symStrPool.bytes)
        linkeditWriter.padToAlignment(16)

        let codeSigOff = linkeditFileOff + linkeditWriter.count

        // Assemble Load Commands into __TEXT header before computing real SHA-256 page hashes!
        let entitlementsPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>com.apple.security.cs.allow-jit</key>
            <true/>
            <key>com.apple.security.get-task-allow</key>
            <true/>
            <key>com.machgraph.analysis-tier</key>
            <string>enterprise</string>
        </dict>
        </plist>
        """

        // Pre-size signature by running once on placeholder, then writing exact header + signature!
        let prePrefix = Data(sliceBytes + linkeditWriter.bytes)
        let protoSig: Data
        if includeCMSCertificates {
            protoSig = buildCMSSignedSuperBlob(
                binarySliceWithoutSignature: prePrefix,
                identifier: identifier,
                entitlementsXML: entitlementsPlist,
                signerCommonNames: ["Apple Development: MachGraph Labs (TEAM99X)", "Apple Worldwide Developer Relations Certification Authority"]
            )
        } else {
            protoSig = AdHocCodeSignatureBuilder.buildSuperBlob(
                binarySliceWithoutSignature: prePrefix,
                identifier: identifier,
                teamID: "TEAM99XMGH",
                entitlementsXML: entitlementsPlist,
                execSegBase: 0,
                execSegLimit: 0x4000,
                isExecutable: true,
                pageSizeShift: 14
            )
        }

        let totalLinkeditSize = linkeditWriter.count + protoSig.count
        let linkeditVMSize = (totalLinkeditSize + 0x3FFF) & ~0x3FFF

        // Write Mach-O 64 header + Load Commands into sliceBytes[0...]
        var lcWriter = BinaryBufferWriter(capacity: 2048, endianness: .little)
        var loadCmdCount: UInt32 = 0

        // 1. LC_SEGMENT_64 __PAGEZERO
        appendSegment64Command(
            &lcWriter,
            name: "__PAGEZERO",
            vmaddr: 0,
            vmsize: imageBase,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            sections: []
        )
        loadCmdCount += 1

        // 2. LC_SEGMENT_64 __TEXT (11 sections)
        let textSections: [MachOSectionSpec] = [
            .init(sect: "__text", seg: "__TEXT", addr: textVA, size: UInt64(textBytes.count), offset: 0x1000, align: 2, flags: MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions, r1: 0, r2: 0),
            .init(sect: "__stubs", seg: "__TEXT", addr: stubsVA, size: UInt64(stubsBytes.count), offset: 0x1400, align: 2, flags: MachOConstants.sSymbolStubs | MachOConstants.sAttrPureInstructions | MachOConstants.sAttrSomeInstructions, r1: 0, r2: 12),
            .init(sect: "__const", seg: "__TEXT", addr: constVA, size: UInt64(constPool.count), offset: 0x1500, align: 2, flags: 0, r1: 0, r2: 0),
            .init(sect: "__cstring", seg: "__TEXT", addr: cstringVA, size: UInt64(cstringPool.count), offset: 0x2000, align: 0, flags: MachOConstants.sCStringLiterals, r1: 0, r2: 0),
            .init(sect: "__objc_methname", seg: "__TEXT", addr: objcMethnameVA, size: UInt64(objcMethPool.count), offset: 0x2200, align: 0, flags: MachOConstants.sCStringLiterals, r1: 0, r2: 0),
            .init(sect: "__objc_classname", seg: "__TEXT", addr: objcClassnameVA, size: UInt64(objcClassPool.count), offset: 0x2280, align: 0, flags: MachOConstants.sCStringLiterals, r1: 0, r2: 0),
            .init(sect: "__objc_methtype", seg: "__TEXT", addr: objcMethtypeVA, size: UInt64(objcTypePool.count), offset: 0x2300, align: 0, flags: MachOConstants.sCStringLiterals, r1: 0, r2: 0),
            .init(sect: "__swift5_reflstr", seg: "__TEXT", addr: swiftReflStrVA, size: UInt64(swiftReflPool.count), offset: 0x2380, align: 0, flags: 0, r1: 0, r2: 0),
            .init(sect: "__swift5_typeref", seg: "__TEXT", addr: swiftTyperefVA, size: UInt64(swiftTyperefPool.count), offset: 0x2400, align: 0, flags: 0, r1: 0, r2: 0),
            .init(sect: "__swift5_fieldmd", seg: "__TEXT", addr: swiftFieldmdVA, size: UInt64(swiftFieldmdPool.count), offset: 0x2480, align: 2, flags: 0, r1: 0, r2: 0),
            .init(sect: "__swift5_types", seg: "__TEXT", addr: swiftTypesVA, size: UInt64(swiftTypesPool.count), offset: 0x2540, align: 2, flags: 0, r1: 0, r2: 0)
        ]
        appendSegment64Command(
            &lcWriter,
            name: "__TEXT",
            vmaddr: imageBase,
            vmsize: 0x4000,
            fileoff: UInt64(textFileOff),
            filesize: 0x4000,
            maxprot: 5,
            initprot: 5,
            sections: textSections
        )
        loadCmdCount += 1

        // 3. LC_SEGMENT_64 __DATA_CONST (3 sections: #12 __got, #13 __objc_classlist, #14 __objc_const)
        let dataConstSections: [MachOSectionSpec] = [
            .init(sect: "__got", seg: "__DATA_CONST", addr: gotVA, size: 24, offset: 0x4000, align: 3, flags: MachOConstants.sNonLazySymbolPointers, r1: 3, r2: 0),
            .init(sect: "__objc_classlist", seg: "__DATA_CONST", addr: objcClasslistVA, size: 8, offset: 0x4020, align: 3, flags: 0, r1: 0, r2: 0),
            .init(sect: "__objc_const", seg: "__DATA_CONST", addr: objcConstVA, size: UInt64(objcConstBuf.count), offset: 0x4100, align: 3, flags: 0, r1: 0, r2: 0)
        ]
        appendSegment64Command(
            &lcWriter,
            name: "__DATA_CONST",
            vmaddr: imageBase + 0x4000,
            vmsize: 0x4000,
            fileoff: UInt64(dataConstFileOff),
            filesize: 0x4000,
            maxprot: 3,
            initprot: 3,
            sections: dataConstSections
        )
        loadCmdCount += 1

        // 4. LC_SEGMENT_64 __DATA (3 sections: #15 __objc_data, #16 __objc_ivar, #17 __data)
        let dataSections: [MachOSectionSpec] = [
            .init(sect: "__objc_data", seg: "__DATA", addr: objcDataVA, size: 80, offset: 0x8000, align: 3, flags: 0, r1: 0, r2: 0),
            .init(sect: "__objc_ivar", seg: "__DATA", addr: objcIvarVA, size: 8, offset: 0x8060, align: 2, flags: 0, r1: 0, r2: 0),
            .init(sect: "__data", seg: "__DATA", addr: mutableDataVA, size: 48, offset: 0x8080, align: 3, flags: 0, r1: 0, r2: 0)
        ]
        appendSegment64Command(
            &lcWriter,
            name: "__DATA",
            vmaddr: imageBase + 0x8000,
            vmsize: 0x4000,
            fileoff: UInt64(dataFileOff),
            filesize: 0x4000,
            maxprot: 3,
            initprot: 3,
            sections: dataSections
        )
        loadCmdCount += 1

        // 5. LC_SEGMENT_64 __LINKEDIT
        appendSegment64Command(
            &lcWriter,
            name: "__LINKEDIT",
            vmaddr: imageBase + 0xC000,
            vmsize: UInt64(linkeditVMSize),
            fileoff: UInt64(linkeditFileOff),
            filesize: UInt64(totalLinkeditSize),
            maxprot: 1,
            initprot: 1,
            sections: []
        )
        loadCmdCount += 1

        // 6. LC_UUID
        lcWriter.appendUInt32(MachOConstants.lcUUID)
        lcWriter.appendUInt32(24)
        lcWriter.appendBytes([0x4D, 0x41, 0x43, 0x48, 0x47, 0x52, 0x41, 0x50, 0x48, 0x2D, 0x32, 0x30, 0x32, 0x36, 0x00, useARM64E ? 0xE1 : 0x64])
        loadCmdCount += 1

        // 7. LC_BUILD_VERSION (macOS 14.0, SDK 15.0)
        lcWriter.appendUInt32(MachOConstants.lcBuildVersion)
        lcWriter.appendUInt32(24)
        lcWriter.appendUInt32(1) // PLATFORM_MACOS
        lcWriter.appendUInt32(0x000E_0000) // 14.0
        lcWriter.appendUInt32(0x000F_0000) // 15.0
        lcWriter.appendUInt32(0) // ntools
        loadCmdCount += 1

        // 8..10. LC_LOAD_DYLIB (3 dylibs)
        for dylib in [
            "/usr/lib/libSystem.B.dylib",
            "/usr/lib/libobjc.A.dylib",
            "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
        ] {
            appendLoadDylibCommand(&lcWriter, installName: dylib, cmd: MachOConstants.lcLoadDylib)
            loadCmdCount += 1
        }

        // 11. LC_MAIN
        lcWriter.appendUInt32(MachOConstants.lcMain)
        lcWriter.appendUInt32(24)
        lcWriter.appendUInt64(fnMainVA - imageBase)
        lcWriter.appendUInt64(0)
        loadCmdCount += 1

        // 12. LC_SYMTAB
        lcWriter.appendUInt32(MachOConstants.lcSymtab)
        lcWriter.appendUInt32(24)
        lcWriter.appendUInt32(UInt32(symtabOff))
        lcWriter.appendUInt32(UInt32(definedSyms.count + undefSyms.count))
        lcWriter.appendUInt32(UInt32(strtabOff))
        lcWriter.appendUInt32(UInt32(symStrPool.count))
        loadCmdCount += 1

        // 13. LC_DYSYMTAB
        lcWriter.appendUInt32(MachOConstants.lcDysymtab)
        lcWriter.appendUInt32(80)
        lcWriter.appendUInt32(0) // ilocalsym
        lcWriter.appendUInt32(0) // nlocalsym
        lcWriter.appendUInt32(0) // iextdefsym
        lcWriter.appendUInt32(UInt32(definedSyms.count)) // nextdefsym
        lcWriter.appendUInt32(UInt32(definedSyms.count)) // iundefsym
        lcWriter.appendUInt32(UInt32(undefSyms.count))   // nundefsym
        for _ in 0..<6 { lcWriter.appendUInt32(0) } // tocoff..nextrefsyms
        lcWriter.appendUInt32(UInt32(indirectOff))
        lcWriter.appendUInt32(6) // nindirectsyms
        for _ in 0..<4 { lcWriter.appendUInt32(0) } // extreloff..nlocrel
        loadCmdCount += 1

        // 14. LC_FUNCTION_STARTS
        appendLinkeditDataCommand(&lcWriter, cmd: MachOConstants.lcFunctionStarts, offset: fnStartsOff, size: functionStartsData.count)
        loadCmdCount += 1

        // 15. LC_DYLD_CHAINED_FIXUPS
        appendLinkeditDataCommand(&lcWriter, cmd: MachOConstants.lcDyldChainedFixups, offset: chainedOff, size: chainedFixupsData.count)
        loadCmdCount += 1

        // 16. LC_DYLD_EXPORTS_TRIE
        appendLinkeditDataCommand(&lcWriter, cmd: MachOConstants.lcDyldExportsTrie, offset: exportsOff, size: exportsTrieData.count)
        loadCmdCount += 1

        // 17. LC_CODE_SIGNATURE
        appendLinkeditDataCommand(&lcWriter, cmd: MachOConstants.lcCodeSignature, offset: codeSigOff, size: protoSig.count)
        loadCmdCount += 1

        // Write mach_header_64 (32 bytes) + lcWriter.bytes into sliceBytes[0...]
        var hdrWriter = BinaryBufferWriter(capacity: 32 + lcWriter.count, endianness: .little)
        hdrWriter.appendUInt32(MachOConstants.mhMagic64)
        hdrWriter.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        let subType: UInt32 = useARM64E ? 0x8000_0002 : 0x0000_0000
        hdrWriter.appendUInt32(subType)
        hdrWriter.appendUInt32(MachOConstants.mhExecute)
        hdrWriter.appendUInt32(loadCmdCount)
        hdrWriter.appendUInt32(UInt32(lcWriter.count))
        hdrWriter.appendUInt32(MachOConstants.mhNoUndefs | MachOConstants.mhDyldLink | MachOConstants.mhTwoLevel | MachOConstants.mhPIE)
        hdrWriter.appendUInt32(0)
        hdrWriter.appendBytes(lcWriter.bytes)

        copyIntoSlice(at: 0, hdrWriter.bytes)

        // Now recompute final cryptographic CS_SuperBlob over the exact finalized prefix!
        let finalizedPrefix = Data(sliceBytes + linkeditWriter.bytes)
        let finalSig: Data
        if includeCMSCertificates {
            finalSig = buildCMSSignedSuperBlob(
                binarySliceWithoutSignature: finalizedPrefix,
                identifier: identifier,
                entitlementsXML: entitlementsPlist,
                signerCommonNames: ["Apple Development: MachGraph Labs (TEAM99X)", "Apple Worldwide Developer Relations Certification Authority"]
            )
        } else {
            finalSig = AdHocCodeSignatureBuilder.buildSuperBlob(
                binarySliceWithoutSignature: finalizedPrefix,
                identifier: identifier,
                teamID: "TEAM99XMGH",
                entitlementsXML: entitlementsPlist,
                execSegBase: 0,
                execSegLimit: 0x4000,
                isExecutable: true,
                pageSizeShift: 14
            )
        }

        var fullImage = finalizedPrefix
        fullImage.append(finalSig)
        return fullImage
    }

    // MARK: - 2. Universal Fat (x86_64 + arm64e) & Fat64 Binaries

    /// Builds a valid Universal Fat (`0xCAFEBABE`) binary containing `x86_64` (slice 0) and `arm64e` (slice 1).
    public static func buildUniversalFatBinary() -> Data {
        buildUniversalContainer(useFat64: false)
    }

    /// Builds a valid 64-bit Universal Fat64 (`0xCAFEBABF`) binary containing `x86_64` (slice 0) and `arm64e` (slice 1).
    public static func buildUniversalFat64Binary() -> Data {
        buildUniversalContainer(useFat64: true)
    }

    private static func buildUniversalContainer(useFat64: Bool) -> Data {
        let x86Slice = buildMinimalX86_64MachOSlice()
        let arm64eSlice = buildARM64MachOExecutable(useARM64E: true, identifier: "com.machgraph.universal.demo")

        let slice0Off = 0x4000
        let slice1Off = ((slice0Off + x86Slice.count + 0x3FFF) & ~0x3FFF)

        var fat = BinaryBufferWriter(capacity: slice1Off + arm64eSlice.count, endianness: .big)
        fat.appendUInt32(useFat64 ? MachOConstants.fatMagic64 : MachOConstants.fatMagic)
        fat.appendUInt32(2) // nfat_arch

        if useFat64 {
            // Slice 0: x86_64
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeX86_64))
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuSubTypeX86_64All))
            fat.appendUInt64(UInt64(slice0Off))
            fat.appendUInt64(UInt64(x86Slice.count))
            fat.appendUInt32(14)
            fat.appendUInt32(0)
            // Slice 1: arm64e
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
            fat.appendUInt32(0x8000_0002)
            fat.appendUInt64(UInt64(slice1Off))
            fat.appendUInt64(UInt64(arm64eSlice.count))
            fat.appendUInt32(14)
            fat.appendUInt32(0)
        } else {
            // Slice 0: x86_64
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeX86_64))
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuSubTypeX86_64All))
            fat.appendUInt32(UInt32(slice0Off))
            fat.appendUInt32(UInt32(x86Slice.count))
            fat.appendUInt32(14)
            // Slice 1: arm64e
            fat.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
            fat.appendUInt32(0x8000_0002)
            fat.appendUInt32(UInt32(slice1Off))
            fat.appendUInt32(UInt32(arm64eSlice.count))
            fat.appendUInt32(14)
        }

        fat.padToAlignment(slice0Off)
        fat.appendData(x86Slice)
        while fat.count < slice1Off { fat.appendUInt8(0) }
        fat.appendData(arm64eSlice)
        return fat.data
    }

    private static func buildMinimalX86_64MachOSlice() -> Data {
        let imageBase: UInt64 = 0x0000_0001_0000_0000
        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let x86Code: [UInt8] = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]

        var lc = BinaryBufferWriter(capacity: 256, endianness: .little)
        appendSegment64Command(
            &lc,
            name: "__TEXT",
            vmaddr: imageBase,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            maxprot: 5,
            initprot: 5,
            sections: [
                .init(sect: "__text", seg: "__TEXT", addr: imageBase + 0x200, size: UInt64(x86Code.count), offset: 0x200, align: 4, flags: MachOConstants.sAttrPureInstructions, r1: 0, r2: 0)
            ]
        )
        lc.appendUInt32(MachOConstants.lcMain)
        lc.appendUInt32(24)
        lc.appendUInt64(0x200)
        lc.appendUInt64(0)

        var slice = [UInt8](repeating: 0, count: 0x1000)
        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeX86_64))
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuSubTypeX86_64All))
        hdr.appendUInt32(MachOConstants.mhExecute)
        hdr.appendUInt32(2)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhPIE | MachOConstants.mhDyldLink)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for i in 0..<hdr.bytes.count { slice[i] = hdr.bytes[i] }
        for i in 0..<x86Code.count { slice[0x200 + i] = x86Code[i] }
        return Data(slice)
    }

    // MARK: - 3. Legacy LC_DYLD_INFO_ONLY Mach-O 64 Fixture

    /// Constructs a valid ARM64 Mach-O 64 image utilizing legacy `LC_DYLD_INFO_ONLY` rebase & bind opcode streams.
    public static func buildLegacyDyldInfoMachOBinary() -> Data {
        let imageBase: UInt64 = 0x0000_0001_0000_0000
        var asm = SyntheticA64Assembler(baseVA: imageBase + 0x400)
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.movz32(wd: 0, imm16: 42)
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()
        let codeBytes = asm.finalizeBytes()

        // Rebase stream: SET_TYPE_IMM(1) + SET_SEGMENT_AND_OFFSET_ULEB(1, 0x00) + DO_REBASE_IMM_TIMES(1) + DONE
        var rebase = BinaryBufferWriter(capacity: 16, endianness: .little)
        rebase.appendUInt8(0x11)
        rebase.appendUInt8(0x21)
        rebase.appendULEB128(0x00)
        rebase.appendUInt8(0x51)
        rebase.appendUInt8(0x00)
        rebase.padToAlignment(8)

        // Bind stream: SET_DYLIB_ORDINAL_IMM(1) + SET_SYMBOL("_getenv") + SET_TYPE_IMM(1) + SET_SEG_OFF(1, 0x08) + DO_BIND + DONE
        var bind = BinaryBufferWriter(capacity: 32, endianness: .little)
        bind.appendUInt8(0x11)
        bind.appendUInt8(0x40)
        bind.appendCString("_getenv")
        bind.appendUInt8(0x51)
        bind.appendUInt8(0x71)
        bind.appendULEB128(0x08)
        bind.appendUInt8(0x90)
        bind.appendUInt8(0x00)
        bind.padToAlignment(8)

        let rebaseOff = 0x2000
        let bindOff = rebaseOff + rebase.count
        let linkeditSize = rebase.count + bind.count

        var lc = BinaryBufferWriter(capacity: 512, endianness: .little)
        appendSegment64Command(
            &lc,
            name: "__TEXT",
            vmaddr: imageBase,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0x1000,
            maxprot: 5,
            initprot: 5,
            sections: [
                .init(sect: "__text", seg: "__TEXT", addr: imageBase + 0x400, size: UInt64(codeBytes.count), offset: 0x400, align: 2, flags: MachOConstants.sAttrPureInstructions, r1: 0, r2: 0)
            ]
        )
        appendSegment64Command(
            &lc,
            name: "__DATA",
            vmaddr: imageBase + 0x1000,
            vmsize: 0x1000,
            fileoff: 0x1000,
            filesize: 0x1000,
            maxprot: 3,
            initprot: 3,
            sections: [
                .init(sect: "__got", seg: "__DATA", addr: imageBase + 0x1000, size: 16, offset: 0x1000, align: 3, flags: MachOConstants.sNonLazySymbolPointers, r1: 0, r2: 0)
            ]
        )
        appendSegment64Command(
            &lc,
            name: "__LINKEDIT",
            vmaddr: imageBase + 0x2000,
            vmsize: 0x1000,
            fileoff: 0x2000,
            filesize: UInt64(linkeditSize),
            maxprot: 1,
            initprot: 1,
            sections: []
        )
        appendLoadDylibCommand(&lc, installName: "/usr/lib/libSystem.B.dylib", cmd: MachOConstants.lcLoadDylib)

        // LC_DYLD_INFO_ONLY (48 bytes)
        lc.appendUInt32(MachOConstants.lcDyldInfoOnly)
        lc.appendUInt32(48)
        lc.appendUInt32(UInt32(rebaseOff))
        lc.appendUInt32(UInt32(rebase.count))
        lc.appendUInt32(UInt32(bindOff))
        lc.appendUInt32(UInt32(bind.count))
        for _ in 0..<6 { lc.appendUInt32(0) }

        lc.appendUInt32(MachOConstants.lcMain)
        lc.appendUInt32(24)
        lc.appendUInt64(0x400)
        lc.appendUInt64(0)

        var image = [UInt8](repeating: 0, count: 0x2000 + linkeditSize)
        var hdr = BinaryBufferWriter(capacity: 32 + lc.count, endianness: .little)
        hdr.appendUInt32(MachOConstants.mhMagic64)
        hdr.appendUInt32(UInt32(bitPattern: MachOConstants.cpuTypeARM64))
        hdr.appendUInt32(0)
        hdr.appendUInt32(MachOConstants.mhExecute)
        hdr.appendUInt32(6)
        hdr.appendUInt32(UInt32(lc.count))
        hdr.appendUInt32(MachOConstants.mhPIE | MachOConstants.mhDyldLink | MachOConstants.mhTwoLevel)
        hdr.appendUInt32(0)
        hdr.appendBytes(lc.bytes)

        for i in 0..<hdr.bytes.count { image[i] = hdr.bytes[i] }
        for i in 0..<codeBytes.count { image[0x400 + i] = codeBytes[i] }
        // Rebase raw target at 0x1000 -> imageBase + 0x400
        let rawTarget = imageBase + 0x400
        for s in 0..<8 { image[0x1000 + s] = UInt8(truncatingIfNeeded: rawTarget >> (s * 8)) }
        for i in 0..<rebase.bytes.count { image[rebaseOff + i] = rebase.bytes[i] }
        for i in 0..<bind.bytes.count { image[bindOff + i] = bind.bytes[i] }

        return Data(image)
    }

    // MARK: - 4. Minimal Valid ELF64 (AArch64) Binary

    /// Constructs a valid 64-bit AArch64 ELF (`ET_DYN`) shared/PIE image with `.text`, `.rodata`, `.dynamic` (`DT_NEEDED`), and `.symtab`.
    public static func buildELF64Binary() -> Data {
        let baseVA: UInt64 = 0x0040_0000
        let textOff = 0x0200
        let rodataOff = 0x0280
        let dynstrOff = 0x0300
        let dynsymOff = 0x0380
        let dynamicOff = 0x0400
        let symtabOff = 0x0480
        let strtabOff = 0x0520
        let shstrtabOff = 0x0580
        let shdrOff = 0x0600

        var asm = SyntheticA64Assembler(baseVA: baseVA + UInt64(textOff))
        asm.bind("elf_check_frame")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.cmp32Imm(wn: 0, imm12: 0)
        asm.bCond(cond: 0x0, label: "elf_zero")
        asm.add64Imm(rd: 0, rn: 0, imm12: 7)
        asm.b("elf_ret")
        asm.bind("elf_zero")
        asm.movz32(wd: 0, imm16: 1)
        asm.bind("elf_ret")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()

        asm.bind("_start")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.movz32(wd: 0, imm16: 10)
        asm.blLabel("elf_check_frame")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()
        let textBytes = asm.finalizeBytes()
        let entryVA = asm.addressOfLabel("_start")
        let checkFnVA = asm.addressOfLabel("elf_check_frame")

        var rodata = BinaryBufferWriter(capacity: 64, endianness: .little)
        rodata.appendCString("ELF64-MACHGRAPH-FIXTURE")
        rodata.appendCString("aarch64-linux-gnu")

        var dynstr = BinaryBufferWriter(capacity: 64, endianness: .little)
        dynstr.appendUInt8(0)
        let libcOff = UInt32(dynstr.count)
        dynstr.appendCString("libc.so.6")
        let libmOff = UInt32(dynstr.count)
        dynstr.appendCString("libm.so.6")
        let putsNameOff = UInt32(dynstr.count)
        dynstr.appendCString("puts")

        // .dynsym: [0] NULL, [1] puts (UND)
        var dynsym = BinaryBufferWriter(capacity: 48, endianness: .little)
        dynsym.appendBytes([UInt8](repeating: 0, count: 24))
        dynsym.appendUInt32(putsNameOff)
        dynsym.appendUInt8(0x12) // STB_GLOBAL | STT_FUNC
        dynsym.appendUInt8(0)
        dynsym.appendUInt16(0)   // SHN_UNDEF
        dynsym.appendUInt64(0)
        dynsym.appendUInt64(0)

        // .dynamic: DT_NEEDED(libc), DT_NEEDED(libm), DT_STRTAB, DT_STRSZ, DT_NULL
        var dynamic = BinaryBufferWriter(capacity: 80, endianness: .little)
        dynamic.appendUInt64(1); dynamic.appendUInt64(UInt64(libcOff))
        dynamic.appendUInt64(1); dynamic.appendUInt64(UInt64(libmOff))
        dynamic.appendUInt64(5); dynamic.appendUInt64(baseVA + UInt64(dynstrOff))
        dynamic.appendUInt64(10); dynamic.appendUInt64(UInt64(dynstr.count))
        dynamic.appendUInt64(0); dynamic.appendUInt64(0)

        var strtab = BinaryBufferWriter(capacity: 64, endianness: .little)
        strtab.appendUInt8(0)
        let symCheckOff = UInt32(strtab.count)
        strtab.appendCString("elf_check_frame")
        let symStartOff = UInt32(strtab.count)
        strtab.appendCString("_start")

        var symtab = BinaryBufferWriter(capacity: 72, endianness: .little)
        symtab.appendBytes([UInt8](repeating: 0, count: 24))
        // elf_check_frame
        symtab.appendUInt32(symCheckOff)
        symtab.appendUInt8(0x12) // STB_GLOBAL | STT_FUNC
        symtab.appendUInt8(0)
        symtab.appendUInt16(1) // .text
        symtab.appendUInt64(checkFnVA)
        symtab.appendUInt64(entryVA - checkFnVA)
        // _start
        symtab.appendUInt32(symStartOff)
        symtab.appendUInt8(0x12)
        symtab.appendUInt8(0)
        symtab.appendUInt16(1)
        symtab.appendUInt64(entryVA)
        symtab.appendUInt64(24)

        var shstr = BinaryBufferWriter(capacity: 96, endianness: .little)
        shstr.appendUInt8(0)
        func internSh(_ s: String) -> UInt32 {
            let o = UInt32(shstr.count)
            shstr.appendCString(s)
            return o
        }
        let nText = internSh(".text")
        let nRodata = internSh(".rodata")
        let nDynstr = internSh(".dynstr")
        let nDynsym = internSh(".dynsym")
        let nDynamic = internSh(".dynamic")
        let nSymtab = internSh(".symtab")
        let nStrtab = internSh(".strtab")
        let nShstr = internSh(".shstrtab")

        let sectionCount = 9 // 0=NULL + 8 sections
        let totalSize = shdrOff + sectionCount * 64
        var elf = [UInt8](repeating: 0, count: totalSize)
        func put(_ off: Int, _ bytes: [UInt8]) {
            for i in 0..<bytes.count { elf[off + i] = bytes[i] }
        }

        // Elf64_Ehdr (64 bytes) + 2 Elf64_Phdr (2 * 56 = 112 bytes at 0x40)
        var ehdr = BinaryBufferWriter(capacity: 176, endianness: .little)
        ehdr.appendBytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0])
        ehdr.appendUInt16(3)   // ET_DYN
        ehdr.appendUInt16(183) // EM_AARCH64
        ehdr.appendUInt32(1)
        ehdr.appendUInt64(entryVA)
        ehdr.appendUInt64(64)  // e_phoff
        ehdr.appendUInt64(UInt64(shdrOff))
        ehdr.appendUInt32(0)
        ehdr.appendUInt16(64)
        ehdr.appendUInt16(56)
        ehdr.appendUInt16(2)   // e_phnum (PT_LOAD + PT_DYNAMIC)
        ehdr.appendUInt16(64)
        ehdr.appendUInt16(UInt16(sectionCount))
        ehdr.appendUInt16(8)   // e_shstrndx

        // PHDR 0: PT_LOAD covering file
        ehdr.appendUInt32(1) // PT_LOAD
        ehdr.appendUInt32(5) // PF_R | PF_X
        ehdr.appendUInt64(0)
        ehdr.appendUInt64(baseVA)
        ehdr.appendUInt64(baseVA)
        ehdr.appendUInt64(UInt64(shdrOff))
        ehdr.appendUInt64(UInt64(shdrOff))
        ehdr.appendUInt64(0x1000)

        // PHDR 1: PT_DYNAMIC
        ehdr.appendUInt32(2) // PT_DYNAMIC
        ehdr.appendUInt32(6) // PF_R | PF_W
        ehdr.appendUInt64(UInt64(dynamicOff))
        ehdr.appendUInt64(baseVA + UInt64(dynamicOff))
        ehdr.appendUInt64(baseVA + UInt64(dynamicOff))
        ehdr.appendUInt64(UInt64(dynamic.count))
        ehdr.appendUInt64(UInt64(dynamic.count))
        ehdr.appendUInt64(8)

        put(0, ehdr.bytes)
        put(textOff, textBytes)
        put(rodataOff, rodata.bytes)
        put(dynstrOff, dynstr.bytes)
        put(dynsymOff, dynsym.bytes)
        put(dynamicOff, dynamic.bytes)
        put(symtabOff, symtab.bytes)
        put(strtabOff, strtab.bytes)
        put(shstrtabOff, shstr.bytes)

        var shdrs = BinaryBufferWriter(capacity: sectionCount * 64, endianness: .little)
        func addSh(name: UInt32, type: UInt32, flags: UInt64, addr: UInt64, off: Int, size: Int, link: UInt32 = 0, entsize: UInt64 = 0) {
            shdrs.appendUInt32(name)
            shdrs.appendUInt32(type)
            shdrs.appendUInt64(flags)
            shdrs.appendUInt64(addr)
            shdrs.appendUInt64(UInt64(off))
            shdrs.appendUInt64(UInt64(size))
            shdrs.appendUInt32(link)
            shdrs.appendUInt32(0)
            shdrs.appendUInt64(8)
            shdrs.appendUInt64(entsize)
        }
        addSh(name: 0, type: 0, flags: 0, addr: 0, off: 0, size: 0) // [0] NULL
        addSh(name: nText, type: 1, flags: 0x6, addr: baseVA + UInt64(textOff), off: textOff, size: textBytes.count) // [1] .text
        addSh(name: nRodata, type: 1, flags: 0x2, addr: baseVA + UInt64(rodataOff), off: rodataOff, size: rodata.count) // [2] .rodata
        addSh(name: nDynstr, type: 3, flags: 0x2, addr: baseVA + UInt64(dynstrOff), off: dynstrOff, size: dynstr.count) // [3] .dynstr
        addSh(name: nDynsym, type: 11, flags: 0x2, addr: baseVA + UInt64(dynsymOff), off: dynsymOff, size: dynsym.count, link: 3, entsize: 24) // [4] .dynsym
        addSh(name: nDynamic, type: 6, flags: 0x3, addr: baseVA + UInt64(dynamicOff), off: dynamicOff, size: dynamic.count, link: 3, entsize: 16) // [5] .dynamic
        addSh(name: nSymtab, type: 2, flags: 0, addr: 0, off: symtabOff, size: symtab.count, link: 7, entsize: 24) // [6] .symtab
        addSh(name: nStrtab, type: 3, flags: 0, addr: 0, off: strtabOff, size: strtab.count) // [7] .strtab
        addSh(name: nShstr, type: 3, flags: 0, addr: 0, off: shstrtabOff, size: shstr.count) // [8] .shstrtab

        put(shdrOff, shdrs.bytes)
        return Data(elf)
    }

    // MARK: - 5. Minimal Valid PE32+ (ARM64) Portable Executable

    /// Alias for `buildPE32PlusARM64Binary()`.
    public static func buildPE32PlusBinary() -> Data {
        buildPE32PlusARM64Binary()
    }

    /// Constructs a valid 64-bit Windows PE32+ (`IMAGE_FILE_MACHINE_ARM64 = 0xAA64`) image with `.text`, `.rdata` (Imports + Exports + Strings), and `.pdata`.
    public static func buildPE32PlusARM64Binary() -> Data {
        let imageBase: UInt64 = 0x0000_0001_4000_0000
        let textRVA: UInt32  = 0x1000
        let rdataRVA: UInt32 = 0x2000
        let pdataRVA: UInt32 = 0x3000

        let textFileOff  = 0x0400
        let rdataFileOff = 0x0600
        let pdataFileOff = 0x0A00
        let totalFileSize = 0x0C00

        var asm = SyntheticA64Assembler(baseVA: imageBase + UInt64(textRVA))
        asm.bind("VerifyToken")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.cmp32Imm(wn: 0, imm12: 1)
        asm.bCond(cond: 0x0, label: "pe_ok")
        asm.movz32(wd: 0, imm16: 0)
        asm.b("pe_done")
        asm.bind("pe_ok")
        asm.movz32(wd: 0, imm16: 1)
        asm.bind("pe_done")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()

        asm.bind("MainEntry")
        asm.stpPre64(rt1: 29, rt2: 30, rn: 31, byteOffset: -16)
        asm.movX29SP()
        asm.movz32(wd: 0, imm16: 1)
        asm.blLabel("VerifyToken")
        asm.ldpPost64(rt1: 29, rt2: 30, rn: 31, byteOffset: 16)
        asm.ret()
        let textBytes = asm.finalizeBytes()
        let verifyRVA = UInt32(asm.addressOfLabel("VerifyToken") - imageBase)
        let entryRVA  = UInt32(asm.addressOfLabel("MainEntry") - imageBase)

        // Layout .rdata (offset 0x0600, RVA 0x2000, size 0x0400):
        // +0x000: Import Descriptor[0] (KERNEL32.dll) + Null Descriptor (40 bytes)
        // +0x030: ILT (3 x UInt64 = 24 bytes)
        // +0x050: IAT (3 x UInt64 = 24 bytes)
        // +0x070: DLL name + Hint/Name entries
        // +0x100: Export Directory (40 bytes) + AddressOfFunctions(8) + AddressOfNames(8) + Ordinals(4) + Strings
        var rdata = [UInt8](repeating: 0, count: 0x0400)
        func rput32(_ off: Int, _ val: UInt32) {
            for s in 0..<4 { rdata[off + s] = UInt8(truncatingIfNeeded: val >> (s * 8)) }
        }
        func rput64(_ off: Int, _ val: UInt64) {
            for s in 0..<8 { rdata[off + s] = UInt8(truncatingIfNeeded: val >> (s * 8)) }
        }
        func rputCStr(_ off: Int, _ s: String) -> Int {
            let utf8 = Array(s.utf8)
            for i in 0..<utf8.count { rdata[off + i] = utf8[i] }
            rdata[off + utf8.count] = 0
            return off + utf8.count + 1
        }

        let dllNameOff = 0x070
        var strCur = rputCStr(dllNameOff, "KERNEL32.dll")
        strCur = (strCur + 1) & ~1
        let hnGetProcIdOff = strCur
        strCur += 2 // Hint = 0
        strCur = rputCStr(strCur, "GetCurrentProcessId")
        strCur = (strCur + 1) & ~1
        let hnExitProcOff = strCur
        strCur += 2
        strCur = rputCStr(strCur, "ExitProcess")
        _ = rputCStr(strCur, "PE32PLUS-ARM64-MACHGRAPH")

        // Import Descriptor[0] at +0x000
        rput32(0x000, rdataRVA + 0x030) // OriginalFirstThunk
        rput32(0x00C, rdataRVA + UInt32(dllNameOff)) // Name
        rput32(0x010, rdataRVA + 0x050) // FirstThunk (IAT)

        // ILT & IAT
        rput64(0x030, UInt64(rdataRVA + UInt32(hnGetProcIdOff)))
        rput64(0x038, UInt64(rdataRVA + UInt32(hnExitProcOff)))
        rput64(0x050, UInt64(rdataRVA + UInt32(hnGetProcIdOff)))
        rput64(0x058, UInt64(rdataRVA + UInt32(hnExitProcOff)))

        // Export Directory at +0x100 (RVA 0x2100)
        let expModNameOff = 0x150
        var expStrCur = rputCStr(expModNameOff, "machgraph_arm64.exe")
        let expName0Off = expStrCur
        expStrCur = rputCStr(expStrCur, "MainEntry")
        let expName1Off = expStrCur
        _ = rputCStr(expStrCur, "VerifyToken")

        rput32(0x10C, rdataRVA + UInt32(expModNameOff)) // Name
        rput32(0x110, 1) // Base
        rput32(0x114, 2) // NumberOfFunctions
        rput32(0x118, 2) // NumberOfNames
        rput32(0x11C, rdataRVA + 0x128) // AddressOfFunctions
        rput32(0x120, rdataRVA + 0x130) // AddressOfNames
        rput32(0x124, rdataRVA + 0x138) // AddressOfNameOrdinals

        rput32(0x128, entryRVA)
        rput32(0x12C, verifyRVA)
        rput32(0x130, rdataRVA + UInt32(expName0Off))
        rput32(0x134, rdataRVA + UInt32(expName1Off))
        rdata[0x138] = 0; rdata[0x139] = 0
        rdata[0x13A] = 1; rdata[0x13B] = 0

        // .pdata ARM64 RUNTIME_FUNCTION entries (2 * 8 = 16 bytes)
        var pdata = BinaryBufferWriter(capacity: 16, endianness: .little)
        pdata.appendUInt32(verifyRVA)
        pdata.appendUInt32(0x0000_0001)
        pdata.appendUInt32(entryRVA)
        pdata.appendUInt32(0x0000_0001)

        var pe = [UInt8](repeating: 0, count: totalFileSize)
        // DOS Header
        pe[0] = 0x4D; pe[1] = 0x5A // "MZ"
        pe[0x3C] = 0x80            // e_lfanew = 0x80

        var hdr = BinaryBufferWriter(capacity: 512, endianness: .little)
        hdr.appendUInt32(0x0000_4550) // "PE\0\0"
        // COFF Header (20 bytes)
        hdr.appendUInt16(0xAA64)      // IMAGE_FILE_MACHINE_ARM64
        hdr.appendUInt16(3)           // NumberOfSections (.text, .rdata, .pdata)
        hdr.appendUInt32(0x6700_0000) // TimeDateStamp
        hdr.appendUInt32(0)
        hdr.appendUInt32(0)
        hdr.appendUInt16(240)         // SizeOfOptionalHeader (PE32+)
        hdr.appendUInt16(0x0022)      // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

        // Optional Header PE32+ (240 bytes)
        hdr.appendUInt16(0x020B)      // PE32+
        hdr.appendUInt8(14); hdr.appendUInt8(0)
        hdr.appendUInt32(UInt32(textBytes.count))
        hdr.appendUInt32(0x0400)
        hdr.appendUInt32(0)
        hdr.appendUInt32(entryRVA)    // AddressOfEntryPoint
        hdr.appendUInt32(textRVA)     // BaseOfCode
        hdr.appendUInt64(imageBase)   // ImageBase
        hdr.appendUInt32(0x1000)      // SectionAlignment
        hdr.appendUInt32(0x0200)      // FileAlignment
        hdr.appendUInt16(10); hdr.appendUInt16(0) // OS Version 10.0
        hdr.appendUInt16(1); hdr.appendUInt16(0)
        hdr.appendUInt16(10); hdr.appendUInt16(0) // Subsystem 10.0
        hdr.appendUInt32(0)
        hdr.appendUInt32(0x4000)      // SizeOfImage
        hdr.appendUInt32(0x0400)      // SizeOfHeaders
        hdr.appendUInt32(0)
        hdr.appendUInt16(3)           // IMAGE_SUBSYSTEM_WINDOWS_CUI
        hdr.appendUInt16(0x8160)      // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        hdr.appendUInt64(0x100000)
        hdr.appendUInt64(0x1000)
        hdr.appendUInt64(0x100000)
        hdr.appendUInt64(0x1000)
        hdr.appendUInt32(0)
        hdr.appendUInt32(16)          // NumberOfRvaAndSizes

        // 16 Data Directories
        hdr.appendUInt32(rdataRVA + 0x100); hdr.appendUInt32(0x80) // [0] Export
        hdr.appendUInt32(rdataRVA + 0x000); hdr.appendUInt32(40)   // [1] Import
        hdr.appendUInt32(0); hdr.appendUInt32(0)                   // [2] Resource
        hdr.appendUInt32(pdataRVA); hdr.appendUInt32(16)           // [3] Exception (.pdata)
        for _ in 4..<12 { hdr.appendUInt32(0); hdr.appendUInt32(0) }
        hdr.appendUInt32(rdataRVA + 0x050); hdr.appendUInt32(24)   // [12] IAT
        for _ in 13..<16 { hdr.appendUInt32(0); hdr.appendUInt32(0) }

        // Section Headers (3 * 40 = 120 bytes)
        func addPESec(_ name: String, vsize: UInt32, rva: UInt32, rawSz: UInt32, rawPtr: UInt32, chars: UInt32) {
            hdr.appendFixedASCII(name, length: 8)
            hdr.appendUInt32(vsize)
            hdr.appendUInt32(rva)
            hdr.appendUInt32(rawSz)
            hdr.appendUInt32(rawPtr)
            hdr.appendUInt32(0); hdr.appendUInt32(0); hdr.appendUInt32(0)
            hdr.appendUInt32(chars)
        }
        addPESec(".text", vsize: UInt32(textBytes.count), rva: textRVA, rawSz: 0x0200, rawPtr: UInt32(textFileOff), chars: 0x6000_0020)
        addPESec(".rdata", vsize: 0x0400, rva: rdataRVA, rawSz: 0x0400, rawPtr: UInt32(rdataFileOff), chars: 0x4000_0040)
        addPESec(".pdata", vsize: 16, rva: pdataRVA, rawSz: 0x0200, rawPtr: UInt32(pdataFileOff), chars: 0x4000_0040)

        for i in 0..<hdr.bytes.count { pe[0x80 + i] = hdr.bytes[i] }
        for i in 0..<textBytes.count { pe[textFileOff + i] = textBytes[i] }
        for i in 0..<rdata.count { pe[rdataFileOff + i] = rdata[i] }
        for i in 0..<pdata.bytes.count { pe[pdataFileOff + i] = pdata.bytes[i] }

        return Data(pe)
    }

    // MARK: - 6. Minimal Valid WebAssembly 1.0 (.wasm) Module

    /// Alias for `buildWasmBinary()`.
    public static func buildWasmModule() -> Data {
        buildWasmBinary()
    }

    /// Constructs a valid WebAssembly 1.0 binary module containing Type, Import, Function, Memory, Global, Export, Start, Code, Data, and Custom `name` sections.
    public static func buildWasmBinary() -> Data {
        var wasm = BinaryBufferWriter(capacity: 512, endianness: .little)
        wasm.appendBytes([0x00, 0x61, 0x73, 0x6D]) // \0asm
        wasm.appendUInt32(1) // version 1

        func appendSection(id: UInt8, _ build: (inout BinaryBufferWriter) -> Void) {
            var payload = BinaryBufferWriter(capacity: 64, endianness: .little)
            build(&payload)
            wasm.appendUInt8(id)
            wasm.appendULEB128(UInt64(payload.count))
            wasm.appendBytes(payload.bytes)
        }
        func appendWasmStr(_ w: inout BinaryBufferWriter, _ s: String) {
            let utf8 = Array(s.utf8)
            w.appendULEB128(UInt64(utf8.count))
            w.appendBytes(utf8)
        }

        // Section 1: Type — sig 0: (i32) -> () , sig 1: (i32, i32) -> (i32), sig 2: () -> ()
        appendSection(id: 1) { s in
            s.appendULEB128(3)
            s.appendBytes([0x60, 0x01, 0x7F, 0x00])
            s.appendBytes([0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F])
            s.appendBytes([0x60, 0x00, 0x00])
        }

        // Section 2: Import — env.host_trace : func(sig 0) -> func index 0
        appendSection(id: 2) { s in
            s.appendULEB128(1)
            appendWasmStr(&s, "env")
            appendWasmStr(&s, "host_trace")
            s.appendUInt8(0x00) // func
            s.appendULEB128(0)  // type 0
        }

        // Section 3: Function — local func 1 (sig 1), local func 2 (sig 2)
        appendSection(id: 3) { s in
            s.appendULEB128(2)
            s.appendULEB128(1)
            s.appendULEB128(2)
        }

        // Section 5: Memory — 1 min page, 4 max pages
        appendSection(id: 5) { s in
            s.appendULEB128(1)
            s.appendUInt8(0x01)
            s.appendULEB128(1)
            s.appendULEB128(4)
        }

        // Section 6: Global — i32 mutable initialized to 0x1000
        appendSection(id: 6) { s in
            s.appendULEB128(1)
            s.appendUInt8(0x7F)
            s.appendUInt8(0x01)
            s.appendUInt8(0x41) // i32.const
            s.appendSLEB128(0x1000)
            s.appendUInt8(0x0B) // end
        }

        // Section 7: Export — memory, validate_frame (func 1), _start (func 2)
        appendSection(id: 7) { s in
            s.appendULEB128(3)
            appendWasmStr(&s, "memory")
            s.appendUInt8(0x02); s.appendULEB128(0)
            appendWasmStr(&s, "validate_frame")
            s.appendUInt8(0x00); s.appendULEB128(1)
            appendWasmStr(&s, "_start")
            s.appendUInt8(0x00); s.appendULEB128(2)
        }

        // Section 8: Start — func 2 (_start)
        appendSection(id: 8) { s in
            s.appendULEB128(2)
        }

        // Section 10: Code — bodies for func 1 and func 2
        appendSection(id: 10) { s in
            s.appendULEB128(2)
            // Body 0 (func 1: local.get 0; local.get 1; i32.xor; end)
            let body0: [UInt8] = [0x00, 0x20, 0x00, 0x20, 0x01, 0x73, 0x0B]
            s.appendULEB128(UInt64(body0.count))
            s.appendBytes(body0)
            // Body 1 (func 2: i32.const 7; i32.const 3; call 1; call 0; end)
            let body1: [UInt8] = [0x00, 0x41, 0x07, 0x41, 0x03, 0x10, 0x01, 0x10, 0x00, 0x0B]
            s.appendULEB128(UInt64(body1.count))
            s.appendBytes(body1)
        }

        // Section 11: Data — active segment at mem[0x40] containing string literal
        appendSection(id: 11) { s in
            s.appendULEB128(1)
            s.appendUInt8(0x00) // active mem 0
            s.appendUInt8(0x41) // i32.const 64
            s.appendSLEB128(64)
            s.appendUInt8(0x0B)
            let lit = Array("WASM-MACHGRAPH-MODULE-1.0\0".utf8)
            s.appendULEB128(UInt64(lit.count))
            s.appendBytes(lit)
        }

        // Section 0: Custom "name" section (subsection 1: function names)
        appendSection(id: 0) { s in
            appendWasmStr(&s, "name")
            var sub = BinaryBufferWriter(capacity: 64, endianness: .little)
            sub.appendULEB128(3)
            sub.appendULEB128(0); appendWasmStr(&sub, "host_trace")
            sub.appendULEB128(1); appendWasmStr(&sub, "validate_frame")
            sub.appendULEB128(2); appendWasmStr(&sub, "_start")
            s.appendUInt8(1) // subsection 1 = function names
            s.appendULEB128(UInt64(sub.count))
            s.appendBytes(sub.bytes)
        }

        return wasm.data
    }

    // MARK: - 7. Synthetic CMS X.509 Certificate-Chain CS_SuperBlob Helper

    /// Builds a `CS_SuperBlob` containing a SHA-256 `CS_CodeDirectory`, XML + DER Entitlements, and a DER PKCS#7 CMS `SignedData` (`0xFADE0B01`) certificate chain.
    public static func buildCMSSignedSuperBlob(
        binarySliceWithoutSignature: Data,
        identifier: String,
        entitlementsXML: String? = nil,
        signerCommonNames: [String]
    ) -> Data {
        let baseAdhoc = AdHocCodeSignatureBuilder.buildSuperBlob(
            binarySliceWithoutSignature: binarySliceWithoutSignature,
            identifier: identifier,
            teamID: "TEAM99XMGH",
            entitlementsXML: entitlementsXML,
            execSegBase: 0,
            execSegLimit: 0x4000,
            isExecutable: true,
            pageSizeShift: 14
        )
        guard !signerCommonNames.isEmpty else { return baseAdhoc }

        // Parse base SuperBlob sub-blobs and replace empty CMS wrapper + clear CS_ADHOC bit
        var reader = BinarySliceReader(data: baseAdhoc, endianness: .big)
        _ = try? reader.readUInt32()
        _ = try? reader.readUInt32()
        let count = Int((try? reader.readUInt32()) ?? 0)
        var slots: [(type: UInt32, off: Int)] = []
        for _ in 0..<count {
            if let t = try? reader.readUInt32(), let o = try? reader.readUInt32() {
                slots.append((t, Int(o)))
            }
        }

        var rebuiltBlobs: [(type: UInt32, bytes: [UInt8])] = []
        for s in slots where s.type != CodeSignatureConstants.slotCMSWrapper {
            guard s.off + 8 <= baseAdhoc.count else { continue }
            var sr = BinarySliceReader(data: baseAdhoc, endianness: .big)
            try? sr.seek(to: s.off + 4)
            let len = Int((try? sr.readUInt32()) ?? 0)
            guard s.off + len <= baseAdhoc.count else { continue }
            var raw = Array(baseAdhoc[(baseAdhoc.startIndex + s.off)..<(baseAdhoc.startIndex + s.off + len)])
            if s.type == CodeSignatureConstants.slotCodeDirectory && raw.count >= 16 {
                // Clear CS_ADHOC (0x2) in flags big-endian UInt32 at +12
                raw[15] &= ~UInt8(0x02)
            }
            rebuiltBlobs.append((s.type, raw))
        }

        // Encode DER PKCS#7 ContentInfo -> SignedData -> CertificateSet with X.509 certificates carrying OID 2.5.4.3 CNs
        let cmsDER = encodeMinimalPKCS7SignedData(commonNames: signerCommonNames)
        var cmsBlob = BinaryBufferWriter(capacity: 8 + cmsDER.count, endianness: .big)
        cmsBlob.appendUInt32(CodeSignatureConstants.magicBlobWrapper)
        cmsBlob.appendUInt32(UInt32(8 + cmsDER.count))
        cmsBlob.appendBytes(cmsDER)
        rebuiltBlobs.append((CodeSignatureConstants.slotCMSWrapper, cmsBlob.bytes))

        let headerLen = 12 + rebuiltBlobs.count * 8
        var curOff = headerLen
        var out = BinaryBufferWriter(capacity: headerLen + 1024, endianness: .big)
        out.appendUInt32(CodeSignatureConstants.magicEmbeddedSignature)
        let totalSize = rebuiltBlobs.reduce(headerLen) { $0 + $1.bytes.count }
        out.appendUInt32(UInt32(totalSize))
        out.appendUInt32(UInt32(rebuiltBlobs.count))
        for b in rebuiltBlobs {
            out.appendUInt32(b.type)
            out.appendUInt32(UInt32(curOff))
            curOff += b.bytes.count
        }
        for b in rebuiltBlobs {
            out.appendBytes(b.bytes)
        }
        return out.data
    }

    // MARK: - Internal Serialization Helpers

    private struct MachOSectionSpec {
        let sect: String
        let seg: String
        let addr: UInt64
        let size: UInt64
        let offset: UInt32
        let align: UInt32
        let flags: UInt32
        let r1: UInt32
        let r2: UInt32
    }

    private static func relOffset32(from sourceFieldVA: UInt64, to targetVA: UInt64) -> UInt32 {
        let delta = Int64(bitPattern: targetVA) - Int64(bitPattern: sourceFieldVA)
        return UInt32(bitPattern: Int32(truncatingIfNeeded: delta))
    }

    private static func appendSegment64Command(
        _ w: inout BinaryBufferWriter,
        name: String,
        vmaddr: UInt64,
        vmsize: UInt64,
        fileoff: UInt64,
        filesize: UInt64,
        maxprot: Int32,
        initprot: Int32,
        sections: [MachOSectionSpec]
    ) {
        let cmdSize = 72 + sections.count * 80
        w.appendUInt32(MachOConstants.lcSegment64)
        w.appendUInt32(UInt32(cmdSize))
        w.appendFixedASCII(name, length: 16)
        w.appendUInt64(vmaddr)
        w.appendUInt64(vmsize)
        w.appendUInt64(fileoff)
        w.appendUInt64(filesize)
        w.appendUInt32(UInt32(bitPattern: maxprot))
        w.appendUInt32(UInt32(bitPattern: initprot))
        w.appendUInt32(UInt32(sections.count))
        w.appendUInt32(0)

        for s in sections {
            w.appendFixedASCII(s.sect, length: 16)
            w.appendFixedASCII(s.seg, length: 16)
            w.appendUInt64(s.addr)
            w.appendUInt64(s.size)
            w.appendUInt32(s.offset)
            w.appendUInt32(s.align)
            w.appendUInt32(0)
            w.appendUInt32(0)
            w.appendUInt32(s.flags)
            w.appendUInt32(s.r1)
            w.appendUInt32(s.r2)
            w.appendUInt32(0)
        }
    }

    private static func appendLoadDylibCommand(_ w: inout BinaryBufferWriter, installName: String, cmd: UInt32) {
        let strBytes = Array(installName.utf8) + [0]
        let rawLen = 24 + strBytes.count
        let cmdSize = (rawLen + 7) & ~7
        w.appendUInt32(cmd)
        w.appendUInt32(UInt32(cmdSize))
        w.appendUInt32(24) // name offset
        w.appendUInt32(2)  // timestamp
        w.appendUInt32(0x054B_0000) // current version 1355.0.0
        w.appendUInt32(0x0001_0000) // compat version 1.0.0
        w.appendBytes(strBytes)
        w.padToAlignment(8)
    }

    private static func appendLinkeditDataCommand(_ w: inout BinaryBufferWriter, cmd: UInt32, offset: Int, size: Int) {
        w.appendUInt32(cmd)
        w.appendUInt32(16)
        w.appendUInt32(UInt32(offset))
        w.appendUInt32(UInt32(size))
    }

    private static func buildChainedFixupsPayload(
        ptrFormat: DyldChainedPtrFormat,
        seg2FirstStart: UInt16,
        seg3FirstStart: UInt16
    ) -> Data {
        // 5 segments: 0=__PAGEZERO, 1=__TEXT, 2=__DATA_CONST, 3=__DATA, 4=__LINKEDIT
        // dyld_chained_starts_in_image: seg_count(4) + 5*4(20) = 24 bytes
        // Each dyld_chained_starts_in_segment (1 page): 22 + 2 = 24 bytes
        var starts = BinaryBufferWriter(capacity: 96, endianness: .little)
        starts.appendUInt32(5) // seg_count
        starts.appendUInt32(0) // seg 0: none
        starts.appendUInt32(0) // seg 1: none
        starts.appendUInt32(24) // seg 2 (__DATA_CONST) at +24
        starts.appendUInt32(48) // seg 3 (__DATA) at +48
        starts.appendUInt32(0) // seg 4: none

        func appendSegStarts(segVMOffset: UInt64, firstStart: UInt16) {
            starts.appendUInt32(24) // size
            starts.appendUInt16(0x4000) // page_size = 16KB
            starts.appendUInt16(ptrFormat.rawValue)
            starts.appendUInt64(segVMOffset)
            starts.appendUInt32(0)
            starts.appendUInt16(1) // page_count = 1
            starts.appendUInt16(firstStart)
        }
        appendSegStarts(segVMOffset: 0x4000, firstStart: seg2FirstStart)
        appendSegStarts(segVMOffset: 0x8000, firstStart: seg3FirstStart)
        starts.padToAlignment(8)

        // Symbol string pool & DYLD_CHAINED_IMPORT entries
        let importedSpecs: [(ord: UInt8, name: String)] = [
            (1, "_printf"),
            (1, "_puts"),
            (1, "_strcmp"),
            (2, "_OBJC_CLASS_$_NSObject"),
            (2, "_OBJC_METACLASS_$_NSObject")
        ]

        var symPool = BinaryBufferWriter(capacity: 128, endianness: .little)
        symPool.appendUInt8(0)
        var imports = BinaryBufferWriter(capacity: importedSpecs.count * 4, endianness: .little)

        for spec in importedSpecs {
            let nameOff = UInt32(symPool.count)
            symPool.appendCString(spec.name)
            let packed = UInt32(spec.ord) | (nameOff << 9)
            imports.appendUInt32(packed)
        }
        symPool.padToAlignment(8)

        let headerSize = 32 // 28-byte header padded to 32
        let startsOffset = headerSize
        let importsOffset = startsOffset + starts.count
        let symbolsOffset = importsOffset + imports.count

        var payload = BinaryBufferWriter(capacity: symbolsOffset + symPool.count, endianness: .little)
        payload.appendUInt32(0) // fixups_version = 0
        payload.appendUInt32(UInt32(startsOffset))
        payload.appendUInt32(UInt32(importsOffset))
        payload.appendUInt32(UInt32(symbolsOffset))
        payload.appendUInt32(UInt32(importedSpecs.count))
        payload.appendUInt32(DyldChainedImportFormat.standard.rawValue)
        payload.appendUInt32(0) // uncompressed symbols
        payload.appendUInt32(0) // alignment pad to 32

        payload.appendBytes(starts.bytes)
        payload.appendBytes(imports.bytes)
        payload.appendBytes(symPool.bytes)
        return payload.data
    }

    private static func derTLV(tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        let len = content.count
        if len < 0x80 {
            out.append(UInt8(len))
        } else if len <= 0xFF {
            out.append(0x81)
            out.append(UInt8(len))
        } else {
            out.append(0x82)
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(contentsOf: content)
        return out
    }

    private static func encodeMinimalPKCS7SignedData(commonNames: [String]) -> [UInt8] {
        func encodeX509Name(_ cn: String) -> [UInt8] {
            let oidCN = derTLV(tag: 0x06, [0x55, 0x04, 0x03])
            let utf8CN = derTLV(tag: 0x0C, Array(cn.utf8))
            let atv = derTLV(tag: 0x30, oidCN + utf8CN)
            let rdn = derTLV(tag: 0x31, atv)
            return derTLV(tag: 0x30, rdn)
        }

        var certBytesConcat: [UInt8] = []
        for (idx, cn) in commonNames.enumerated() {
            let versionExplicit = derTLV(tag: 0xA0, derTLV(tag: 0x02, [0x02])) // v3
            let serial = derTLV(tag: 0x02, [UInt8(idx + 1)])
            let sigAlg = derTLV(tag: 0x30, derTLV(tag: 0x06, [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
            let issuer = encodeX509Name("Apple Code Signing Root CA")
            let validity = derTLV(tag: 0x30, derTLV(tag: 0x17, Array("260101000000Z".utf8)) + derTLV(tag: 0x17, Array("360101000000Z".utf8)))
            let subject = encodeX509Name(cn)
            let tbs = derTLV(tag: 0x30, versionExplicit + serial + sigAlg + issuer + validity + subject)
            let sigVal = derTLV(tag: 0x03, [0x00, 0xDE, 0xAD, 0xBE, 0xEF])
            let cert = derTLV(tag: 0x30, tbs + sigAlg + sigVal)
            certBytesConcat.append(contentsOf: cert)
        }

        let sdVersion = derTLV(tag: 0x02, [0x01])
        let digestAlgs = derTLV(tag: 0x31, [])
        let encapContent = derTLV(tag: 0x30, derTLV(tag: 0x06, [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]))
        let certSetImplicit0 = derTLV(tag: 0xA0, certBytesConcat)
        let signerInfos = derTLV(tag: 0x31, [])
        let signedData = derTLV(tag: 0x30, sdVersion + digestAlgs + encapContent + certSetImplicit0 + signerInfos)

        let oidSignedData = derTLV(tag: 0x06, [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        let explicit0 = derTLV(tag: 0xA0, signedData)
        return derTLV(tag: 0x30, oidSignedData + explicit0)
    }
}
