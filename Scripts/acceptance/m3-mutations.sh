#!/usr/bin/env bash
# M3 Destructive Mutation Verification Suite (Stage 6b)
#
# Applies each M3 single-defect patch under Scripts/acceptance/mutations/ inside an isolated
# temporary copy of the repository (leaving the real working tree completely untouched),
# builds the release MachGraph binary, runs the corresponding minimal m3-metadata-differential.py
# subcheck, and verifies that every mutation exits non-zero and reports the expected class of
# discrepancy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MUTATIONS_DIR="$REPO_ROOT/Scripts/acceptance/mutations"
DIFF_SCRIPT="$REPO_ROOT/Scripts/acceptance/m3-metadata-differential.py"

TMP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m3-mutations.XXXXXX")"
cleanup() {
    local ec=$?
    rm -rf "$TMP_WORK"
    exit "$ec"
}
trap cleanup EXIT

TMP_REPO="$TMP_WORK/repo"
TMP_HOME="$TMP_WORK/home"
mkdir -p "$TMP_REPO" "$TMP_HOME"

INITIAL_SOURCE_DIFF="$(git -C "$REPO_ROOT" diff -- Package.swift Sources Tests Fixtures)"
INITIAL_SOURCE_UNTRACKED="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- Package.swift Sources Tests Fixtures)"

# Copy only buildable package inputs into the temporary directory (never copy .git or touch REPO_ROOT).
cp "$REPO_ROOT/Package.swift" "$TMP_REPO/Package.swift"
if [[ -f "$REPO_ROOT/Package.resolved" ]]; then
    cp "$REPO_ROOT/Package.resolved" "$TMP_REPO/Package.resolved"
fi
cp -R "$REPO_ROOT/Sources" "$TMP_REPO/Sources"
cp -R "$REPO_ROOT/Tests" "$TMP_REPO/Tests"
if [[ -d "$REPO_ROOT/Fixtures" ]]; then
    cp -R "$REPO_ROOT/Fixtures" "$TMP_REPO/Fixtures"
fi

# Build a tiny real Mach-O fixture carrying the truncated Swift symbol `_$s9MachGraph99Truncated`
# named in SURVEY.md section 5.4 (2b), so m3-metadata-differential.py can test the verbatim-on-failure
# guard directly through nm -> swift-demangle -> machgraph demangle.
TRUNC_C="$TMP_WORK/truncated_swift_fixture.c"
TRUNC_BIN="$TMP_WORK/truncated_swift_fixture"
cat > "$TRUNC_C" <<'EOF'
extern void truncated_swift_sym(void) __asm__("_$s9MachGraph99Truncated");
__attribute__((used)) void truncated_swift_sym(void) {}
int main(void) {
    truncated_swift_sym();
    return 0;
}
EOF
xcrun clang -arch arm64 -O0 -o "$TRUNC_BIN" "$TRUNC_C"

echo "=== MachGraph M3 Mutation Verification Suite ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "System:     $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo ""
echo "[setup] Building initial unmutated release MachGraph in temporary workspace..."
HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
    swift build --package-path "$TMP_REPO" -c release --product MachGraph >/dev/null
TMP_REL_BIN="$TMP_REPO/.build/release/MachGraph"

# Sanity-check that the unmutated binary passes on the 2b fixture + /usr/bin/archiveutil before mutating.
SANITY_JSON="$TMP_WORK/sanity_2b.json"
if ! MACHGRAPH_ISOLATED_HOME="$TMP_HOME" python3 -I "$DIFF_SCRIPT" \
    "$TRUNC_BIN" /usr/bin/archiveutil --only demangle \
    --machgraph "$TMP_REL_BIN" --json-out "$SANITY_JSON" >/dev/null 2>&1; then
    echo "[FAIL] Unmutated release binary failed baseline demangle check on truncated_swift_fixture + /usr/bin/archiveutil" >&2
    exit 1
fi
echo "[setup] Baseline unmutated release build Ready (2b fixture baseline PASS)."
echo ""

TOTAL=0
PASSED=0

run_mutation() {
    local id="$1"
    local patch_file="$2"
    local mutated_where="$3"
    local expected_check="$4"
    local validator_kind="$5"
    shift 5
    local -a diff_args=("$@")

    TOTAL=$((TOTAL + 1))
    local patch_path="$MUTATIONS_DIR/$patch_file"
    if [[ ! -f "$patch_path" ]]; then
        echo "[FAIL] Missing patch file: Scripts/acceptance/mutations/$patch_file" >&2
        exit 1
    fi

    # 1. Apply patch forward in temporary copy (git apply handles line offsets without leaving .orig backups)
    if ! git -C "$TMP_REPO" apply "$patch_path"; then
        echo "[FAIL] Mutation $id: patch failed to apply cleanly: Scripts/acceptance/mutations/$patch_file" >&2
        exit 1
    fi

    # 2. Rebuild release MachGraph incrementally in temporary copy
    if ! HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
        swift build --package-path "$TMP_REPO" -c release --product MachGraph >/dev/null 2>&1; then
        echo "[FAIL] Mutation $id: mutated source failed to compile ($patch_file)" >&2
        git -C "$TMP_REPO" apply -R "$patch_path" || true
        exit 1
    fi

    # 3. Run minimal m3-metadata-differential.py check and expect non-zero exit
    local out_json="$TMP_WORK/mut_${id}.json"
    local out_txt="$TMP_WORK/mut_${id}.txt"
    set +e
    MACHGRAPH_ISOLATED_HOME="$TMP_HOME" python3 -I "$DIFF_SCRIPT" \
        "${diff_args[@]}" --machgraph "$TMP_REL_BIN" --json-out "$out_json" > "$out_txt" 2>&1
    local rc=$?
    set -e

    # Format display command without exposing host-specific temp directories
    local display_args=()
    for a in "${diff_args[@]}"; do
        if [[ "$a" == "$TRUNC_BIN" ]]; then
            display_args+=("<tmp>/truncated_swift_fixture")
        else
            display_args+=("$a")
        fi
    done
    local display_cmd="python3 -I Scripts/acceptance/m3-metadata-differential.py ${display_args[*]} --machgraph <tmp>/.build/release/MachGraph"

    if [[ "$rc" -eq 0 ]]; then
        echo "[FAIL] Mutation $id ($patch_file): differential check unexpectedly PASSED (exit 0)!" >&2
        echo "  Command: $display_cmd" >&2
        git -C "$TMP_REPO" apply -R "$patch_path" || true
        exit 1
    fi

    # 4. Validate the specific failure mode and extract a one-line summary from the JSON output
    local summary_line
    if ! summary_line="$(python3 -I - "$validator_kind" "$expected_check" "$out_json" "$out_txt" <<'PY'
import json
import sys

kind, expected_check, json_path, txt_path = sys.argv[1:5]
with open(json_path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
with open(txt_path, "r", encoding="utf-8") as fh:
    txt = fh.read()

assert doc.get("verdict") == "FAIL", f"expected verdict FAIL, got {doc.get('verdict')}"
assert not doc.get("failures"), f"unexpected crash/tool failure instead of diff mismatch: {doc.get('failures')}"
chk = doc["checks"][expected_check]
assert chk["mismatched_files"] > 0 or chk["total_diffs"] > 0, f"subcheck {expected_check} did not fail: {chk}"
examples = chk.get("examples", [])

if kind == "01_symbols":
    missing = [e for e in examples if e.get("kind") == "missing_in_machgraph"]
    assert missing, f"expected missing_in_machgraph symbol examples, got {examples[:3]}"
    assert "_btell.cold.1" in txt or any("cold" in str(e.get("name", "")) or e.get("name", "").startswith("_") for e in missing), examples[:3]
    btell_note = " (including _btell.cold.1)" if "_btell.cold.1" in json.dumps(doc) else ""
    first_ex = f"{missing[0].get('address')} {missing[0].get('name')}"
    print(f"/bin/csh ref_items={chk['total_ref_items']} vs mg_items={chk['total_mg_items']} (total_diffs={chk['total_diffs']}); missing local symbols e.g. {first_ex}{btell_note}")

elif kind == "02a_swift_rate":
    sw = chk["swift"]
    assert sw["equal_pct"] < 99.0 and sw["wrong"] > 0, f"expected Swift equal_pct < 99% and wrong > 0, got {sw}"
    ex = next((e for e in examples if e.get("bucket") == "swift" and "Swift_" in e.get("mg", "")), None)
    assert ex is not None, f"expected Swift_ corrupted output example, got {examples[:3]}"
    print(f"Swift equal={sw['equal']}/{sw['unique_symbols']} ({sw['equal_pct']}% < 99%), wrong={sw['wrong']}; e.g. {ex['symbol']} -> '{ex['mg'][:64]}'")

elif kind == "02b_swift_verbatim":
    sw = chk["swift"]
    assert sw["equal_pct"] >= 99.0 and sw["wrong"] == 1, f"expected equal_pct >= 99% with wrong == 1, got {sw}"
    ex = next((e for e in examples if e.get("symbol") == "_$s9MachGraph99Truncated"), None)
    assert ex is not None and ex.get("mg") == "$s9MachGraph99Truncated" and ex.get("ref") == "_$s9MachGraph99Truncated", f"unexpected 2b example: {examples}"
    print(f"Swift equal={sw['equal']}/{sw['unique_symbols']} ({sw['equal_pct']}% >= 99%) yet wrong={sw['wrong']}: _$s9MachGraph99Truncated -> '{ex['mg']}' (violates verbatim fallback)")

elif kind == "03_cpp_plain_z":
    pz = chk["plain_c_z"]
    assert pz["wrong"] > 0, f"expected plain_c_z wrong > 0, got {pz}"
    ex = next((e for e in examples if e.get("symbol") == "_ZeroFilesTested"), examples[0] if examples else None)
    assert ex is not None and ex.get("mg") == ex.get("symbol", "")[1:], f"expected stripped _Z C symbol, got {examples[:3]}"
    print(f"Plain C _Z equal={pz['equal']}/{pz['unique_symbols']}, wrong={pz['wrong']}; e.g. {ex['symbol']} -> '{ex['mg']}' (expected '{ex['ref']}')")

elif kind == "04_objc":
    missing = [e for e in examples if "missing" in str(e.get("kind", "")) and "+[" in str(e.get("item", ""))]
    assert missing, f"expected missing +[Class sel] class methods, got {examples[:3]}"
    print(f"objc matched={chk['matched_files']}/{chk['compared_files']}, total_diffs={chk['total_diffs']} (ref={chk['total_ref_items']} vs mg={chk['total_mg_items']}); missing class methods e.g. {missing[0].get('item')}")

elif kind == "05_dylibs":
    assert chk["total_diffs"] > 0, chk
    ex = next((e for e in examples if e.get("kind") == "library_entry_mismatch"), examples[0])
    ot = ex.get("otool") or {}
    mg = ex.get("mg") or {}
    assert ".0" in json.dumps(ex), f"expected version .0 mismatch in dylibs, got {ex}"
    print(
        f"dylibs matched={chk['matched_files']}/{chk['compared_files']}, total_diffs={chk['total_diffs']}; "
        f"e.g. {ex.get('file')} {mg.get('installName')}: mg currentVersion='{mg.get('currentVersion')}' vs otool '{ot.get('currentVersion')}'"
    )

elif kind == "06a_xrefs_bl":
    missing = [e for e in examples if e.get("kind") == "missing_call_in_machgraph"]
    assert missing, f"expected missing_call_in_machgraph edges, got {examples[:3]}"
    e0 = missing[0]
    print(f"/bin/ls CALL edges ref={chk['total_ref_items']} vs mg={chk['total_mg_items']} (missing={chk['total_diffs']} __auth_stubs bl edges, e.g. {e0.get('from')} -> {e0.get('to')})")

elif kind == "06b_xrefs_g25":
    non_str = chk.get("non_string_section_string_refs", 0)
    assert non_str >= 24, f"expected >= 24 non-string STRING_REFs on /bin/ls, got {non_str} ({chk})"
    bad_ex = [e for e in examples if e.get("kind") == "string_ref_outside_string_section"]
    assert bad_ex, f"expected string_ref_outside_string_section examples, got {examples[:5]}"
    text_ex = [e for e in bad_ex if e.get("target_section") == "__TEXT,__text"]
    e0 = text_ex[0] if text_ex else bad_ex[0]
    print(f"/bin/ls non_string_section_string_refs={non_str} (illegal STRING_REF outside string sections, e.g. {e0.get('from')} -> {e0.get('to')} in {e0.get('target_section')})")

elif kind == "07_entitlements":
    assert chk["mismatched_files"] >= 1 and chk["total_diffs"] > 0, f"expected entitlements failure, got {chk}"
    ex = next((e for e in examples if e.get("ref_type") == "bool" and e.get("mg_type") == "str"), examples[0] if examples else None)
    assert ex is not None, f"expected bool vs str entitlement mismatch, got {examples[:3]}"
    print(f"entitlements matched={chk['matched_files']}/{chk['compared_files']}, total_diffs={chk['total_diffs']}; e.g. {ex.get('file')} key '{ex.get('key')}': ref={ex.get('ref_value')!r} ({ex.get('ref_type')}) != mg={ex.get('mg_value')!r} ({ex.get('mg_type')})")

elif kind == "08_other_underscore":
    sw, cp, pz, ot = chk["swift"], chk["cpp"], chk["plain_c_z"], chk["other"]
    assert sw["wrong"] == 0 and cp["wrong"] == 0 and pz["wrong"] == 0, f"expected buckets 1-3 unaffected, got swift={sw} cpp={cp} plain_z={pz}"
    assert ot["wrong"] > 0, f"expected 4th bucket 'other' wrong > 0, got {ot}"
    main_ex = next((e for e in examples if e.get("symbol") == "_main"), examples[0] if examples else None)
    ex_str = f"{main_ex['symbol']} -> '{main_ex['mg']}'" if main_ex else "stripped leading '_'"
    print(f"Buckets 1-3 100.00% (wrong=0), 4th bucket 'Other verbatim' equal={ot['equal']}/{ot['unique_symbols']} wrong={ot['wrong']} (e.g. {ex_str})")

else:
    raise AssertionError(f"unknown validator_kind {kind}")
PY
)"; then
        echo "[FAIL] Mutation $id ($patch_file): failed with exit $rc, but output did not match expected discrepancy!" >&2
        cat "$out_txt" >&2
        git -C "$TMP_REPO" apply -R "$patch_path" || true
        exit 1
    fi

    # 5. Reverse patch and verify temporary Sources/ matches clean REPO_ROOT/Sources/ byte-for-byte
    if ! git -C "$TMP_REPO" apply -R "$patch_path"; then
        echo "[FAIL] Mutation $id: failed to reverse patch $patch_file" >&2
        exit 1
    fi
    if ! diff -qr "$REPO_ROOT/Sources" "$TMP_REPO/Sources" >/dev/null; then
        echo "[FAIL] Mutation $id: temporary Sources/ differs from repository Sources/ after reversing $patch_file" >&2
        exit 1
    fi

    PASSED=$((PASSED + 1))
    echo "[PASS] Mutation $id — Scripts/acceptance/mutations/$patch_file"
    echo "  Mutated:        $mutated_where"
    echo "  Command:        $display_cmd"
    echo "  Failed check:   $expected_check (exit code $rc)"
    echo "  Summary:        $summary_line"
    echo ""
}

run_mutation "1" \
    "01-symbols-skip-local.patch" \
    "Sources/MachBinaryFormats/UniversalAndMachOLoader.swift:1258 (MachO64Loader.loadSlice: skip binding == .local)" \
    "symbols" \
    "01_symbols" \
    /bin/csh --only symbols

run_mutation "2a" \
    "02a-swift-demangle-prefix.patch" \
    'Sources/MachGraphModels/SymbolDemangler.swift:170 (SymbolDemangler.demangleSwiftWithSystemRuntime: _$s Swift. -> Swift_)' \
    "demangle" \
    "02a_swift_rate" \
    /usr/bin/archiveutil --only demangle

run_mutation "2b" \
    "02b-swift-demangle-verbatim.patch" \
    "Sources/MachGraphModels/SymbolDemangler.swift:106,114 (SymbolDemangler.demangle: strip leading '_' on rejected Swift symbol)" \
    "demangle" \
    "02b_swift_verbatim" \
    "$TRUNC_BIN" /usr/bin/archiveutil --only demangle

run_mutation "3" \
    "03-cpp-demangle-plain-z.patch" \
    "Sources/MachGraphModels/SymbolDemangler.swift:131 (SymbolDemangler.demangle: strip leading '_' on single-'_Z' plain C symbols)" \
    "demangle" \
    "03_cpp_plain_z" \
    /usr/bin/unzip --only demangle

run_mutation "4" \
    "04-objc-skip-metaclass.patch" \
    "Sources/MachBinaryFormats/ObjCAndSwiftMetadataParser.swift:362 (ObjCAndSwiftMetadataParser.parseObjCClass: skip metaClassVA)" \
    "objc" \
    "04_objc" \
    objc --only objc

run_mutation "5" \
    "05-dylibs-drop-zero-patch.patch" \
    "Sources/MachBinaryFormats/UniversalAndMachOLoader.swift:183 (MachOConstants.formatDylibVersion: drop .0 when patch == 0)" \
    "dylibs" \
    "05_dylibs" \
    standard --only dylibs

run_mutation "6a" \
    "06a-xrefs-skip-auth-stubs.patch" \
    "Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift:1444 (buildCrossReferenceTable: skip .directCall to __auth_stubs)" \
    "xrefs" \
    "06a_xrefs_bl" \
    quick --only xrefs

run_mutation "6b" \
    "06b-xrefs-g25-string-ref.patch" \
    "Sources/MachA64Decoder/A64SequenceIdiomsRecognizer.swift:347 + Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift:1426 (restore unconditional .stringReference on ADRP+ADD)" \
    "xrefs" \
    "06b_xrefs_g25" \
    quick --only xrefs

run_mutation "7" \
    "07-entitlements-bool-as-string.patch" \
    "Sources/MachBinaryFormats/CodeSignatureAndCMSParser.swift:465 (convertPropertyListValue: emit string 'true'/'false' for CFBoolean)" \
    "entitlements" \
    "07_entitlements" \
    /usr/libexec/wifip2pd /bin/ps --only entitlements

run_mutation "8" \
    "08-demangle-strip-other-underscore.patch" \
    "Sources/MachGraphModels/SymbolDemangler.swift:143 (SymbolDemangler.demangle: strip leading '_' on ordinary C symbols)" \
    "demangle" \
    "08_other_underscore" \
    /bin/csh --only demangle

# Verify product source tree in REPO_ROOT was never touched during this run
AFTER_SOURCE_DIFF="$(git -C "$REPO_ROOT" diff -- Package.swift Sources Tests Fixtures)"
AFTER_SOURCE_UNTRACKED="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- Package.swift Sources Tests Fixtures)"
if [[ "$AFTER_SOURCE_DIFF" != "$INITIAL_SOURCE_DIFF" || "$AFTER_SOURCE_UNTRACKED" != "$INITIAL_SOURCE_UNTRACKED" ]]; then
    echo "[FAIL] Repository product/test sources have unexpected modifications!" >&2
    exit 1
fi

echo "=== ALL $PASSED/$TOTAL M3 MUTATIONS CAUGHT AS EXPECTED (8 capability groups, 10 patches; repo Sources/ clean) ==="
