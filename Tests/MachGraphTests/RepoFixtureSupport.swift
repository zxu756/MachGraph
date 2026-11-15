import Foundation

// MARK: - Shared test support: repository fixtures & in-memory preferences

/// Locates files checked into the repository relative to this test source file,
/// so tests never depend on the current working directory or on paths outside the repo.
enum RepoFixtures {
    /// `<repo>/` derived from `<repo>/Tests/MachGraphTests/RepoFixtureSupport.swift`.
    static let repositoryRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // MachGraphTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // <repo>

    /// `Fixtures/demo_arm64_sample`: a thin (single-architecture) arm64 Mach-O executable built with
    /// `clang -arch arm64` from `Fixtures/demo_arm64_sample.c`. It is linker-signed, so it carries
    /// LC_SEGMENT_64 segments, sections, and __LINKEDIT blobs (symtab, function starts, code signature).
    static var thinARM64SampleURL: URL {
        repositoryRoot.appendingPathComponent("Fixtures/demo_arm64_sample", isDirectory: false)
    }

    static func thinARM64SampleData() throws -> Data {
        try Data(contentsOf: thinARM64SampleURL)
    }

    /// `Fixtures/sys_crn7_8_llvm_table.tsv`: all 2,048 `SYS` (`op0=1, L=0`) encodings across
    /// `op1=0..7`, `CRn in {7,8}`, `CRm=0..15`, `op2=0..7` paired with real `llvm-objdump` mnemonics.
    static var sysAliasTableURL: URL {
        repositoryRoot.appendingPathComponent("Fixtures/sys_crn7_8_llvm_table.tsv", isDirectory: false)
    }

    /// `Fixtures/hint_llvm_table.tsv`: all 128 `HINT` (`op0=0, op1=3, CRn=2, Rt=31, L=0`) encodings across
    /// `CRm=0..15`, `op2=0..7` paired with real `llvm-objdump` mnemonics.
    static var hintAliasTableURL: URL {
        repositoryRoot.appendingPathComponent("Fixtures/hint_llvm_table.tsv", isDirectory: false)
    }
}

/// A `UserDefaults` stand-in that keeps every value in process memory.
///
/// `UserDefaults(suiteName:)` followed by `removePersistentDomain(forName:)` still leaves an empty
/// 42-byte `<suite>.plist` behind in `~/Library/Preferences` (cfprefsd flushes the emptied domain),
/// so tests must not touch a real preferences domain at all.
final class InMemoryUserDefaults: UserDefaults, @unchecked Sendable {
    private var storage: [String: Any] = [:]
    private let lock = NSLock()

    init() {
        // `suiteName: nil` only attaches the default search list; nothing is written unless a setter
        // reaches `super`, and every accessor used by the product code is overridden below.
        super.init(suiteName: nil)!
    }

    override func object(forKey defaultName: String) -> Any? {
        lock.lock()
        defer { lock.unlock() }
        return storage[defaultName]
    }

    override func string(forKey defaultName: String) -> String? {
        object(forKey: defaultName) as? String
    }

    override func data(forKey defaultName: String) -> Data? {
        object(forKey: defaultName) as? Data
    }

    override func set(_ value: Any?, forKey defaultName: String) {
        lock.lock()
        defer { lock.unlock() }
        if let value {
            storage[defaultName] = value
        } else {
            storage.removeValue(forKey: defaultName)
        }
    }

    override func removeObject(forKey defaultName: String) {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: defaultName)
    }
}
