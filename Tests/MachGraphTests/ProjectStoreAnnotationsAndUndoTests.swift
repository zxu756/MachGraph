import Foundation
import Testing
import MachGraphModels
import MachBinaryFormats
import MachCFGEngine
import MachMicroDecompiler
import MachProjectStore

@Suite("SQLite WAL Project Store, Migrations v1..v4, Undo/Redo, Codec & Snapshots")
struct ProjectStoreAnnotationsAndUndoTests {

    private final class LockedEventRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [MachUndoRedoChangeEvent] = []

        func append(_ event: MachUndoRedoChangeEvent) {
            lock.lock()
            defer { lock.unlock() }
            storage.append(event)
        }

        var events: [MachUndoRedoChangeEvent] {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
    }

    private func makeTempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("mg-projstore-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("MachSQLiteWALConnection enables WAL journal mode, prepared statements, savepoints, and integrity checks")
    func sqliteWALConnectionSavepointsCheckpointsAndIntegrity() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let dbPath = tempDir.appendingPathComponent("wal-test.sqlite").path
        let conn = try MachSQLiteWALConnection(path: dbPath, configuration: .standardWAL)
        defer { conn.close() }

        #expect(conn.isOpen)
        let footprint = conn.inspectStorageFootprint()
        #expect(footprint.journalMode.lowercased() == "wal")

        // Nested savepoint rollback preserves outer transaction row!
        try conn.withTransaction {
            _ = try conn.execute(
                "INSERT INTO project_meta (key, value, updated_at) VALUES (?, ?, ?);",
                bindings: [.text("outer_key"), .text("committed"), .real(1.0)]
            )
            do {
                try conn.withSavepoint(named: "sp_inner") {
                    _ = try conn.execute(
                        "INSERT INTO project_meta (key, value, updated_at) VALUES (?, ?, ?);",
                        bindings: [.text("inner_key"), .text("aborted"), .real(2.0)]
                    )
                    throw MachGraphError.ioFailure("Trigger savepoint rollback")
                }
            } catch {}
        }

        let outerVal = try conn.queryScalarString(
            "SELECT value FROM project_meta WHERE key = ?;",
            bindings: [.text("outer_key")]
        )
        let innerVal = try conn.queryScalarString(
            "SELECT value FROM project_meta WHERE key = ?;",
            bindings: [.text("inner_key")]
        )
        #expect(outerVal == "committed")
        #expect(innerVal == nil)

        let ckpt = try conn.checkpointWAL(mode: .truncate)
        #expect(ckpt.isComplete)

        let integrity = try conn.verifyIntegrity()
        #expect(integrity.isOK)
        #expect(integrity.foreignKeyViolations == 0)
        #expect(integrity.schemaVersion == MachSchemaVersion.v4)
    }

    @Test("Incremental SQLite schema migrations step cleanly from v0 -> v1 -> v2 -> v3 -> v4 with verified checksums")
    func incrementalSchemaMigrationsV1ThroughV4() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        var manualConfig = SQLiteConnectionConfiguration.standardWAL
        manualConfig.autoMigrateToLatest = false
        let conn = try MachSQLiteWALConnection(
            path: tempDir.appendingPathComponent("incremental.sqlite").path,
            configuration: manualConfig
        )
        defer { conn.close() }

        #expect(try conn.userSchemaVersion() == 0)

        for stepVersion in [MachSchemaVersion.v1, MachSchemaVersion.v2, MachSchemaVersion.v3, MachSchemaVersion.v4] {
            let appliedVer = try MachSchemaMigrationManager.migrate(on: conn, targetVersion: stepVersion)
            #expect(appliedVer == stepVersion)
            #expect(try conn.userSchemaVersion() == stepVersion)
            try MachSchemaMigrationManager.verifySchemaObjects(on: conn, throughVersion: stepVersion)
        }

        let records = try MachSchemaMigrationManager.appliedMigrations(on: conn)
        #expect(records.map(\.version) == [1, 2, 3, 4])
        for (record, step) in zip(records, MachSchemaMigrationManager.allSteps) {
            #expect(record.checksumHex == step.checksumHex)
        }
    }

    @Test(".machproj bundle creation syncs metadata.json and ingests full binary analysis index")
    func machprojBundleCreationAndFullBinaryAnalysisIngestion() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let binData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: true)
        let index = try BinaryAnalysisCoordinator().analyzeBinary(data: binData, fileName: "Ingest.arm64e")

        let bundleURL = tempDir.appendingPathComponent("DemoTarget.machproj")
        let db = try MachProjectDatabase.create(
            at: bundleURL,
            projectName: "DemoTarget",
            binaryImage: index.image
        )
        defer { db.close() }

        try db.ingestFullBinaryAnalysis(
            image: index.image,
            functions: index.functions,
            xrefs: index.xrefs
        )

        let verifyFn = try #require(index.function(named: "_verify_license"))
        let decomp = MachMicroDecompilerEngine().decompile(function: verifyFn, in: index)
        try db.cacheDecompiledFunction(decomp)

        let meta = try db.readBundleMetadata()
        #expect(meta.formatMagic == MachProjectBundleMetadata.currentFormatMagic)
        #expect(meta.projectName == "DemoTarget")
        #expect(meta.schemaVersion == MachSchemaVersion.v4)

        let cachedImage = try #require(try db.loadCachedBinaryImage())
        #expect(cachedImage.sha256Hex == index.image.sha256Hex)

        let cachedFn = try #require(try db.function(at: verifyFn.address))
        #expect(cachedFn.name == verifyFn.name)
        #expect(try db.functionContaining(address: verifyFn.address.adding(UInt64(8)))?.address == verifyFn.address)

        let cachedDecomp = try #require(try db.cachedDecompiledFunction(at: verifyFn.address))
        #expect(cachedDecomp.fullSourceText == decomp.fullSourceText)

        let stats = try db.computeProjectStats()
        #expect(stats.functionCount == index.functions.count)
        #expect(stats.symbolCount == index.image.symbols.count)
        #expect(stats.xrefCount == index.xrefs.count)
    }

    @Test("CRUD operations on symbol renames and display symbol resolution")
    func crudSymbolRenamesAndDisplayNameResolution() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "RenameTest")
        defer { db.close() }

        let addr = VirtualAddress(0x1_0000_1080)
        let rename = UserSymbolRename(
            address: addr,
            originalName: "_sub_100001080",
            customName: "decrypt_license_block",
            signatureOverride: "int decrypt_license_block(uint8_t *buf)"
        )
        try db.upsertRename(rename)

        #expect(try db.allRenames().count == 1)
        #expect(try db.rename(for: addr)?.customName == "decrypt_license_block")
        #expect(try db.resolveDisplaySymbolName(at: addr, fallback: "_sub") == "decrypt_license_block")

        try db.deleteRename(at: addr)
        #expect(try db.rename(for: addr) == nil)
        #expect(try db.resolveDisplaySymbolName(at: addr, fallback: "_sub") == "_sub")
    }

    @Test("CRUD operations on inline comments including address-range queries")
    func crudInlineCommentsAndRangeQueries() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "CommentTest")
        defer { db.close() }

        try db.upsertComment(UserInlineComment(address: VirtualAddress(0x1_0000_1000), text: "Entry prologue", isRepeatable: true))
        try db.upsertComment(UserInlineComment(address: VirtualAddress(0x1_0000_1010), text: "Loop header"))
        try db.upsertComment(UserInlineComment(address: VirtualAddress(0x1_0000_2000), text: "Far function"))

        let inWindow = try db.comments(in: AddressRange(start: VirtualAddress(0x1_0000_1000), size: 0x40))
        #expect(inWindow.count == 2)
        #expect(inWindow[0].isRepeatable)

        try db.deleteComment(at: VirtualAddress(0x1_0000_1010))
        #expect(try db.allComments().count == 2)
    }

    @Test("CRUD operations on bookmarks with category filtering and custom C structs")
    func crudBookmarksAndCustomStructs() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "BookmarkStructTest")
        defer { db.close() }

        let bm1 = UserBookmark(address: VirtualAddress(0x1_0000_1000), label: "Crypto Entry", categoryTag: "Crypto")
        let bm2 = UserBookmark(address: VirtualAddress(0x1_0000_1200), label: "Auth Gate", categoryTag: "Auth")
        try db.upsertBookmark(bm1)
        try db.upsertBookmark(bm2)

        #expect(try db.bookmarks(forCategory: "Crypto").map(\.id) == [bm1.id])
        try db.deleteBookmark(id: bm1.id)
        #expect(try db.allBookmarks().map(\.id) == [bm2.id])

        let structDef = CustomStructDefinition(
            name: "SessionContext",
            totalByteSize: 24,
            alignment: 8,
            fields: [
                CustomStructField(name: "tokenPtr", offset: 0, byteSize: 8, typeExpr: .cString),
                CustomStructField(name: "expiresAt", offset: 8, byteSize: 8, typeExpr: .intType(bits: 64, signed: true)),
                CustomStructField(name: "flags", offset: 16, byteSize: 4, typeExpr: .intType(bits: 32, signed: false))
            ]
        )
        try db.upsertStruct(structDef)
        let fetched = try #require(try db.customStruct(named: "SessionContext"))
        #expect(fetched.fields.count == 3)
        try db.deleteStruct(id: structDef.id)
        #expect(try db.allStructs().isEmpty)
    }

    @Test("CRUD operations on byte patches (enabled vs disabled) and security audit findings by severity")
    func crudBytePatchesAndSecurityAuditFindings() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "PatchFindingTest")
        defer { db.close() }

        let pEnabled = BytePatchRecord(
            fileOffset: FileOffset(0x1000),
            virtualAddress: VirtualAddress(0x1_0000_1000),
            originalBytes: [0x00],
            patchedBytes: [0x01],
            isEnabled: true
        )
        let pDisabled = BytePatchRecord(
            fileOffset: FileOffset(0x1004),
            virtualAddress: VirtualAddress(0x1_0000_1004),
            originalBytes: [0x02],
            patchedBytes: [0x03],
            isEnabled: false
        )
        try db.upsertPatch(pEnabled)
        try db.upsertPatch(pDisabled)

        #expect(try db.allPatches().count == 2)
        #expect(try db.enabledPatches().map(\.id) == [pEnabled.id])
        #expect(try db.patches(atVirtualAddress: VirtualAddress(0x1_0000_1000)).count == 1)

        let findings = [
            SecurityAuditFinding(pluginID: "p1", pluginName: "Scanner", severity: .critical, category: "Keys", title: "Critical Key", detail: "d1"),
            SecurityAuditFinding(pluginID: "p1", pluginName: "Scanner", severity: .low, category: "Info", title: "Low Note", detail: "d2")
        ]
        try db.replaceFindings(forPluginID: "p1", findings: findings)
        #expect(try db.allFindings().count == 2)
        #expect(try db.findings(atOrAbove: .high).count == 1)
        try db.deleteFindings(forPluginID: "p1")
        #expect(try db.allFindings().isEmpty)
    }

    @Test("MachUndoRedoController multi-step undo, redo, batch mutations, and redo-stack truncation on new edit")
    func undoRedoControllerMultiStepBatchAndDivergentEditTruncation() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "UndoTest")
        defer { db.close() }
        let undoer = MachUndoRedoController(database: db)

        let recorder = LockedEventRecorder()
        let token = undoer.addObserver { event, _ in
            recorder.append(event)
        }
        defer { undoer.removeObserver(token: token) }

        let addr = VirtualAddress(0x1_0000_1000)
        try undoer.renameSymbol(at: addr, originalName: "_fn", newName: "verify_token")
        try undoer.setInlineComment(at: addr, text: "Check HMAC")
        let addedBM = try undoer.toggleBookmark(at: addr, label: "Gate")
        #expect(addedBM)
        #expect(undoer.undoDepth == 3)
        #expect(undoer.redoDepth == 0)

        // Undo 2 steps (bookmark + comment)
        let undone = try undoer.undoMultiple(steps: 2)
        #expect(undone.count == 2)
        #expect(try db.allBookmarks().isEmpty)
        #expect(try db.comment(at: addr) == nil)
        #expect(try db.rename(for: addr)?.customName == "verify_token")
        #expect(undoer.undoDepth == 1)
        #expect(undoer.redoDepth == 2)

        // Redo 1 step (comment comes back)
        _ = try undoer.redo()
        #expect(try db.comment(at: addr)?.text == "Check HMAC")
        #expect(undoer.redoDepth == 1)

        // Performing a new mutation truncates the remaining redo stack!
        try undoer.setInlineComment(at: addr.adding(UInt64(4)), text: "Branch check")
        #expect(undoer.redoDepth == 0)
        #expect(!recorder.events.isEmpty)
    }

    @Test("MachUndoRedoController persists undo and redo stacks across cold SQLite database reopen")
    func undoRedoControllerPersistsAcrossColdDatabaseReopen() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let bundleURL = tempDir.appendingPathComponent("PersistentUndo.machproj")
        let addr = VirtualAddress(0x1_0000_1100)

        do {
            let db1 = try MachProjectDatabase.create(at: bundleURL, projectName: "PersistentUndo")
            let undo1 = MachUndoRedoController(database: db1)
            try undo1.renameSymbol(at: addr, originalName: "_orig", newName: "step_one")
            try undo1.renameSymbol(at: addr, originalName: "_orig", newName: "step_two")
            _ = try undo1.undo() // Reverts to "step_one", leaving "step_two" on persistent redo stack!
            #expect(try db1.rename(for: addr)?.customName == "step_one")
            db1.close()
        }

        // Cold reopen from disk in a brand-new database & controller instance
        let db2 = try MachProjectDatabase.open(at: bundleURL)
        defer { db2.close() }
        let undo2 = MachUndoRedoController(database: db2)

        #expect(undo2.canUndo)
        #expect(undo2.canRedo)
        #expect(undo2.undoDepth == 1)
        #expect(undo2.redoDepth == 1)

        // Redo across process restart -> restores "step_two"
        _ = try undo2.redo()
        #expect(try db2.rename(for: addr)?.customName == "step_two")

        // Undo twice across process restart -> restores original unrenamed state
        _ = try undo2.undoMultiple(steps: 2)
        #expect(try db2.rename(for: addr) == nil)
    }

    @Test("MachProjectDatabase persists and restores last synchronized cursor location")
    func projectDatabaseSavesAndRestoresCursorLocation() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "CursorStore")
        defer { db.close() }

        let loc = SynchronizedCursorLocation(
            virtualAddress: VirtualAddress(0x1_0000_1420),
            fileOffset: FileOffset(0x1420),
            functionAddress: VirtualAddress(0x1_0000_1400),
            blockID: 3,
            originPane: .pseudoC
        )
        try db.saveLastCursorLocation(loc)
        let loaded = try #require(try db.lastCursorLocation())
        #expect(loaded == loc)
    }

    @Test("AnalystAnnotationCodec JSON bundle export, SHA-256 content digest verification, and tamper rejection")
    func analystAnnotationCodecJSONExportDigestAndTamperRejection() throws {
        let dbSource = try MachProjectDatabase.openInMemory(projectName: "ExportSource")
        defer { dbSource.close() }

        let addr = VirtualAddress(0x1_0000_1000)
        try dbSource.upsertRename(UserSymbolRename(address: addr, originalName: "_f", customName: "verified_entry"))
        try dbSource.upsertComment(UserInlineComment(address: addr, text: "Verified"))
        try dbSource.upsertBookmark(UserBookmark(address: addr, label: "Entry"))

        let codecSource = AnalystAnnotationCodec(database: dbSource)
        let jsonData = try codecSource.exportJSONData(prettyPrinted: true)
        let bundle = try AnalystAnnotationCodec.decodeAnnotationBundle(from: jsonData, verifyDigest: true)
        #expect(bundle.verifyContentDigest())
        #expect(bundle.totalAnnotationCount == 3)

        // Import into clean target database
        let dbTarget = try MachProjectDatabase.openInMemory(projectName: "ImportTarget")
        defer { dbTarget.close() }
        let summary = try AnalystAnnotationCodec(database: dbTarget).importJSONData(jsonData)
        #expect(summary.contentDigestVerified)
        #expect(summary.importedRenames == 1)
        #expect(summary.importedComments == 1)
        #expect(summary.importedBookmarks == 1)
        #expect(try dbTarget.rename(for: addr)?.customName == "verified_entry")

        // Tamper with JSON text while keeping old contentSHA256 -> must fail digest verification!
        let tamperedString = try codecSource.exportJSONString().replacingOccurrences(of: "verified_entry", with: "evil_override_")
        #expect(throws: MachGraphError.self) {
            _ = try AnalystAnnotationCodec.decodeAnnotationBundle(
                from: Data(tamperedString.utf8),
                verifyDigest: true
            )
        }
    }

    @Test("AnalystAnnotationCodec conflict resolution policies (.keepExisting vs .preferImported) and ASLR slide rebasing")
    func analystAnnotationCodecConflictPoliciesAndASLRSlideRebasing() throws {
        let binData = SyntheticBinaryFixtureBuilder.buildARM64MachOExecutable(useARM64E: false)
        let baseImg = try UniversalBinaryDispatcher.load(data: binData, fileName: "SlideBase.arm64")

        let dbA = try MachProjectDatabase.openInMemory(projectName: "BaseProj", binaryImage: baseImg)
        defer { dbA.close() }
        let origAddr = VirtualAddress(0x1_0000_1000)
        try dbA.upsertRename(UserSymbolRename(address: origAddr, originalName: "_fn", customName: "imported_name"))
        let exportedBundle = try AnalystAnnotationCodec(database: dbA).exportBundle()

        // 1. keepExisting policy preserves pre-existing rename
        let dbKeep = try MachProjectDatabase.openInMemory(projectName: "KeepProj", binaryImage: baseImg)
        defer { dbKeep.close() }
        try dbKeep.upsertRename(UserSymbolRename(address: origAddr, originalName: "_fn", customName: "local_name"))

        var keepOpts = AnnotationImportOptions(conflictPolicy: .keepExisting)
        keepOpts.rebaseAddressesToCurrentImageBase = false
        let keepSum = try AnalystAnnotationCodec(database: dbKeep).importBundle(exportedBundle, options: keepOpts)
        #expect(keepSum.skippedRenames == 1)
        #expect(try dbKeep.rename(for: origAddr)?.customName == "local_name")

        // 2. Rebase onto slid imageBase (0x1_0000_0000 -> 0x1_0400_0000, slide +0x400_0000)
        let slidImg = UniversalBinaryDispatcher.loadRawBinary(
            data: Data([0x00, 0x00, 0x00, 0x00]),
            baseAddress: VirtualAddress(0x1_0400_0000)
        )
        let dbSlid = try MachProjectDatabase.openInMemory(projectName: "SlidProj", binaryImage: slidImg)
        defer { dbSlid.close() }

        let rebaseOpts = AnnotationImportOptions(conflictPolicy: .preferImported, rebaseAddressesToCurrentImageBase: true)
        let rebaseSum = try AnalystAnnotationCodec(database: dbSlid).importBundle(exportedBundle, options: rebaseOpts)
        #expect(rebaseSum.addressSlideApplied == 0x0400_0000)
        #expect(try dbSlid.rename(for: VirtualAddress(0x1_0400_1000))?.customName == "imported_name")
    }

    @Test("AnalystAnnotationCodec exports Ghidra script, IDA IDC script, C header structs, and Markdown dossier")
    func analystAnnotationCodecExportsGhidraIDACHeaderAndMarkdown() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "InteropExport")
        defer { db.close() }

        let addr = VirtualAddress(0x1_0000_1000)
        try db.upsertRename(UserSymbolRename(address: addr, originalName: "_main", customName: "app_entry"))
        try db.upsertComment(UserInlineComment(address: addr, text: "Main entry"))
        try db.upsertStruct(
            CustomStructDefinition(
                name: "AuthFrame",
                totalByteSize: 8,
                fields: [CustomStructField(name: "version", offset: 0, byteSize: 4, typeExpr: .intType(bits: 32, signed: false))]
            )
        )

        let codec = AnalystAnnotationCodec(database: db)
        let ghidraScript = try codec.exportGhidraImporterScript()
        #expect(ghidraScript.contains("app_entry"))
        #expect(ghidraScript.contains("AuthFrame"))

        let idaScript = try codec.exportIDAIDCScript()
        #expect(idaScript.contains("set_name") || idaScript.contains("MakeName"))
        #expect(idaScript.contains("app_entry"))

        let cHeader = try codec.exportCHeaderDefinitions()
        #expect(cHeader.contains("typedef struct"))
        #expect(cHeader.contains("AuthFrame"))
        #expect(cHeader.contains("AuthFrame_t"))
        #expect(cHeader.contains("uint32_t version"))

        let dossier = try codec.exportMarkdownDossier()
        #expect(dossier.contains("InteropExport"))
        #expect(dossier.contains("app_entry"))
    }

    @Test("AnalysisSnapshotAndDiffManager creates checkpoints, diffs live state, and renders Markdown diff report")
    func snapshotManagerCreateCheckpointAndSemanticDiff() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "SnapshotDiff")
        defer { db.close() }
        let manager = AnalysisSnapshotAndDiffManager(database: db)

        let addr1 = VirtualAddress(0x1_0000_1000)
        let addr2 = VirtualAddress(0x1_0000_1040)
        try db.upsertRename(UserSymbolRename(address: addr1, originalName: "_f1", customName: "initial_fn"))
        try db.upsertComment(UserInlineComment(address: addr1, text: "Old note"))

        let cp1 = try manager.createCheckpoint(name: "Baseline Triage", note: "Initial pass")
        #expect(cp1.renameCount == 1)
        #expect(cp1.commentCount == 1)

        // Mutate live state: modify addr1 rename, delete addr1 comment, add addr2 rename
        try db.upsertRename(UserSymbolRename(address: addr1, originalName: "_f1", customName: "refined_fn"))
        try db.deleteComment(at: addr1)
        try db.upsertRename(UserSymbolRename(address: addr2, originalName: "_f2", customName: "helper_fn"))

        let liveDiff = try manager.diffCheckpointAgainstLiveState(baseID: cp1.id)
        #expect(!liveDiff.isIdentical)
        #expect(liveDiff.renames.addedCount == 1)
        #expect(liveDiff.renames.modifiedCount == 1)
        #expect(liveDiff.comments.removedCount == 1)

        let md = liveDiff.renderMarkdownReport()
        #expect(md.contains("Baseline Triage"))
        #expect(md.contains("refined_fn"))
        #expect(md.contains("helper_fn"))
    }

    @Test("AnalysisSnapshotAndDiffManager restores earlier checkpoint atomically with safety backup")
    func snapshotManagerRestoreCheckpointWithSafetyBackup() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "SnapshotRestore")
        defer { db.close() }
        let undoer = MachUndoRedoController(database: db)
        let manager = AnalysisSnapshotAndDiffManager(database: db, undoRedoController: undoer)

        let addr = VirtualAddress(0x1_0000_1200)
        try undoer.renameSymbol(at: addr, originalName: "_fn", newName: "golden_state")
        let goldenCP = try manager.createCheckpoint(name: "Golden")

        // Mutate away from golden state
        try undoer.renameSymbol(at: addr, originalName: "_fn", newName: "accidental_edit")
        try undoer.setInlineComment(at: addr, text: "Temporary scratch")

        let restoreRes = try manager.restoreCheckpoint(id: goldenCP.id, createSafetyBackup: true)
        #expect(restoreRes.safetyBackupCheckpointID != nil)
        #expect(try db.rename(for: addr)?.customName == "golden_state")
        #expect(try db.comment(at: addr) == nil)
        #expect(try manager.listCheckpoints().count == 2)
    }

    @Test("AnalysisSnapshotAndDiffManager rename, delete, and pruneCheckpoints retention")
    func snapshotManagerRenameDeleteAndPruneRetention() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "SnapshotPrune")
        defer { db.close() }
        let manager = AnalysisSnapshotAndDiffManager(database: db)

        let cpA = try manager.createCheckpoint(name: "CP-A")
        let cpB = try manager.createCheckpoint(name: "CP-B")
        let cpC = try manager.createCheckpoint(name: "CP-C")
        _ = cpB

        try manager.renameCheckpoint(id: cpC.id, newName: "CP-C-Latest", newNote: "Tagged")
        #expect(try manager.findCheckpoint(named: "CP-C-Latest")?.id == cpC.id)

        let prunedCount = try manager.pruneCheckpoints(keepingMostRecent: 2)
        #expect(prunedCount == 1)
        #expect(try manager.loadCheckpoint(id: cpA.id) == nil)

        try manager.deleteCheckpoint(id: cpC.id)
        #expect(try manager.listCheckpoints().count == 1)
    }

    @Test("MachProjectDatabase Xref and symbol search queries")
    func projectDatabaseXrefAndSymbolSearchQueries() throws {
        let db = try MachProjectDatabase.openInMemory(projectName: "XrefSymQuery")
        defer { db.close() }

        let sym1 = BinarySymbol(name: "_verify_license", demangledName: "verify_license", kind: .function, address: VirtualAddress(0x1_0000_1000))
        let sym2 = BinarySymbol(name: "_compute_checksum", demangledName: "compute_checksum", kind: .function, address: VirtualAddress(0x1_0000_1100))
        try db.batchInsertSymbols([sym1, sym2], clearExisting: true)

        let matchedSyms = try db.searchSymbols(query: "license")
        #expect(matchedSyms.map(\.name) == ["_verify_license"])

        let xref = XrefRecord(
            fromAddress: VirtualAddress(0x1_0000_1020),
            fromFunction: sym1.address,
            toAddress: sym2.address,
            kind: .directCall,
            instructionPreview: "bl _compute_checksum"
        )
        try db.batchInsertXrefs([xref], clearExisting: true)
        #expect(try db.xrefCount(to: sym2.address) == 1)
        #expect(try db.xrefsTo(address: sym2.address, kind: .directCall).count == 1)
        #expect(try db.xrefsInFunction(functionAddress: sym1.address).count == 1)
    }

    @Test("AnalystAnnotationCodec file-based writeAnnotationBundle and importAnnotationBundle round-trip")
    func analystAnnotationCodecFileWriteAndImportRoundTrip() throws {
        let tempDir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let jsonURL = tempDir.appendingPathComponent("annotations.json")

        let db1 = try MachProjectDatabase.openInMemory(projectName: "FileExport")
        defer { db1.close() }
        try db1.upsertBookmark(UserBookmark(address: VirtualAddress(0x1_0000_1500), label: "Switch Table"))
        try AnalystAnnotationCodec(database: db1).writeAnnotationBundle(to: jsonURL)

        let db2 = try MachProjectDatabase.openInMemory(projectName: "FileImport")
        defer { db2.close() }
        let summary = try AnalystAnnotationCodec(database: db2).importAnnotationBundle(from: jsonURL)
        #expect(summary.importedBookmarks == 1)
        #expect(try db2.allBookmarks().first?.label == "Switch Table")
    }
}
