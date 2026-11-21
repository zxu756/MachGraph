import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachA64Decoder

@Suite("M3 Stage 4: Unified SymbolDemangler In-Process Runtime, Guards & Handwritten Fallback")
struct MachA64DecoderM3DemanglerTests {

    @Test("M3 D-M3-1/2 (Red->Green 1): Truncated or unsupported Swift/C++ inputs return verbatim input, never partial output")
    func m3PartialOrTruncatedMangledSymbolsReturnVerbatimInput() {
        let demangler = SymbolDemangler()

        // Truncated mid-identifier Swift symbol must return verbatim on both system and fallback paths.
        let partialSwift = "_$s18TimeMachinePrivate10CopyEngineCA2A0dE13BlockDelegateVRs0_rlE4cop"
        #expect(demangler.demangle(partialSwift) == partialSwift)
        #expect(MachOSymbolDemangler.demangle(partialSwift) == partialSwift)

        // SURVEY.md 3.2 Category 3 exact symbol: previously emitted partial stack "TimeMachinePrivate.CopyEngine".
        let tmutilCopySym = "_$s18TimeMachinePrivate10CopyEngineCA2A0dE13BlockDelegateVRs0_rlE4copy4from2to7options07preItemF004postmF009itemErrorF0y10Foundation3URLV_AoA0D6PolicyVAA06ClientM10ResolutionOSgAA0dM0V_AOtYbKcSgyAV_AOs0P0_pSgtYbKcSgyAYYbKcSgtYaKFZ"
        #expect(SymbolDemangler(useSystemRuntime: false).demangle(tmutilCopySym) == tmutilCopySym)
        #expect(demangler.demangle(tmutilCopySym).hasPrefix("static (extension in TimeMachinePrivate):TimeMachinePrivate.CopyEngine<"))
        #expect(demangler.demangle(tmutilCopySym).hasSuffix("async throws -> ()"))

        // Previously fell through to C underscore stripper and emitted "$s9MachGraph99Truncated".
        let invalidLenSwift = "_$s9MachGraph99Truncated"
        #expect(demangler.demangle(invalidLenSwift) == invalidLenSwift)
        #expect(MachOSymbolDemangler.demangle(invalidLenSwift) == invalidLenSwift)

        // Truncated Itanium C++ pointer / function pointer types must return verbatim (never strip leading '_').
        let truncatedCpp1 = "_ZN3foo3barEP"
        let truncatedCpp2 = "__Z16nbtdg_chore_initPK12netbios_namedPFvP15nb_chore_base_tPKv"
        #expect(demangler.demangle(truncatedCpp1) == truncatedCpp1)
        #expect(demangler.demangle(truncatedCpp2) == truncatedCpp2)
        #expect(MachOSymbolDemangler.demangle(truncatedCpp1) == truncatedCpp1)
        #expect(MachOSymbolDemangler.demangle(truncatedCpp2) == truncatedCpp2)

        // Non-mangled input with surrounding whitespace is preserved verbatim, never trimmed.
        let padded = "  not_a_mangled_symbol  "
        #expect(demangler.demangle(padded) == padded)
    }

    @Test("M3 D-M3-2 (Red->Green 2): Plain C symbols (including _Z* C identifiers and _main) never strip leading underscore")
    func m3PlainCSymbolsPreserveLeadingUnderscoreVerbatim() {
        let demangler = SymbolDemangler()
        let plainCSymbols = [
            "_ZeroFilesTested",
            "_Zfirst",
            "_ZhuGeCopyValue",
            "_ZinComputeProgramAlign",
            "_main",
            "_verify_license",
            "__mh_execute_header",
            "_TtC10Calculator11AppDelegate",
            "_OBJC_CLASS_$_NSObject",
            "-[MGAuthController validateToken:error:]",
            "+[MGAuthController sharedController]"
        ]

        for sym in plainCSymbols {
            #expect(demangler.demangle(sym) == sym, "SymbolDemangler modified plain/ObjC symbol \(sym)")
            #expect(MachOSymbolDemangler.demangle(sym) == sym, "MachOSymbolDemangler modified plain/ObjC symbol \(sym)")
        }
    }

    @Test("M3 D-M3-1 (Red->Green 3): In-process swift_demangle & __cxa_demangle match swift-demangle -compact and c++filt including suffixes")
    func m3SystemRuntimeInProcessDemanglesComplexSwiftAndItaniumCpp() {
        let demangler = SymbolDemangler.shared

        let swiftCases: [(mangled: String, expected: String)] = [
            (
                "_$s10AppIntents11EntityQueryP17suggestedEntities6ResultQzyYaKFTq",
                "method descriptor for AppIntents.EntityQuery.suggestedEntities() async throws -> A.Result"
            ),
            (
                "_$s10AppIntents11EntityQueryP8entities3forSay0C0QzGSayAF_2IDQZG_tYaKFTq",
                "method descriptor for AppIntents.EntityQuery.entities(for: [A.Entity.ID]) async throws -> [A.Entity]"
            ),
            (
                "_$s10AppIntents21DisplayRepresentationV5title8subtitle5imageAC10Foundation23LocalizedStringResourceV_AISgAC5ImageVSgtcfC",
                "AppIntents.DisplayRepresentation.init(title: Foundation.LocalizedStringResource, subtitle: Foundation.LocalizedStringResource?, image: AppIntents.DisplayRepresentation.Image?) -> AppIntents.DisplayRepresentation"
            ),
            (
                "_$s15icloudmailagent11APNSManagerC8delegateAA0B8Delegate_pSgvM.resume.0",
                "icloudmailagent.APNSManager.delegate.modify : icloudmailagent.APNSManagerDelegate? with unmangled suffix \".resume.0\""
            ),
            (
                "_T04main5helloSSyF",
                "main.hello() -> Swift.String"
            )
        ]

        for item in swiftCases {
            #expect(demangler.demangle(item.mangled) == item.expected)
            #expect(MachOSymbolDemangler.demangle(item.mangled) == item.expected)
        }

        let cppCases: [(mangled: String, expected: String)] = [
            (
                "__Z10IsValidAclPK4_ACL",
                "IsValidAcl(_ACL const*)"
            ),
            (
                "__ZL15update_wg_bb_fnPKcS0_iS0_iPv",
                "update_wg_bb_fn(char const*, char const*, int, char const*, int, void*)"
            ),
            (
                "__Z12set_darkbooti.cold.1",
                "set_darkboot(int) (.cold.1)"
            ),
            (
                "___ZN4Test3runEv_block_invoke",
                "invocation function for block in Test::run()"
            ),
            (
                "__ZZ31-[_ANEServer handleIOKitEvent:]E9onceToken",
                "-[_ANEServer handleIOKitEvent:]::onceToken"
            )
        ]

        for item in cppCases {
            #expect(demangler.demangle(item.mangled) == item.expected)
            #expect(MachOSymbolDemangler.demangle(item.mangled) == item.expected)
        }
    }

    @Test("M3 D-M3-1/2 (Red->Green 4): Handwritten fallback demangles supported symbols, formats .cold/.resume suffixes, and returns raw on unconsumed input")
    func m3HandwrittenFallbackDemanglesSupportedAndGuardsUnsupportedAndSuffixes() {
        let fallback = SymbolDemangler(useSystemRuntime: false)

        // Supported Swift & C++ with compiler suffixes
        let swiftResume = "_$s15MachGraphTarget13LicensePacketV.resume.0"
        #expect(
            fallback.demangle(swiftResume)
                == "MachGraphTarget.LicensePacket with unmangled suffix \".resume.0\""
        )

        let cppCold = "__Z12set_darkbooti.cold.1"
        #expect(fallback.demangle(cppCold) == "set_darkboot(int) (.cold.1)")

        // Unconsumed / malformed inputs must return verbatim raw symbol without stripping '_'
        for raw in [
            "_$s9MachGraph99Truncated",
            "_$s18TimeMachinePrivate10CopyEngineCA2A0dE13BlockDelegateVRs0_rlE4copy",
            "_ZN3foo3barEP",
            "_ZeroFilesTested",
            "_main"
        ] {
            #expect(fallback.demangle(raw) == raw)
        }
    }
}
