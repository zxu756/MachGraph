#!/usr/bin/env bash
# M4 Destructive Mutation Verification Suite (Stage 4a, Acceptance Row 6)
#
# Applies each M4 single-defect patch under Scripts/acceptance/mutations/ inside an isolated
# temporary copy of the repository (leaving the real working tree and .git completely untouched),
# builds the release MachGraph binary, runs the corresponding minimal m4-cfg-acceptance.py
# subcheck with an explicit --machgraph path, and verifies that every mutation exits non-zero
# and reports the expected class of discrepancy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MUTATIONS_DIR="$REPO_ROOT/Scripts/acceptance/mutations"
ACCEPT_SCRIPT="$REPO_ROOT/Scripts/acceptance/m4-cfg-acceptance.py"

TMP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m4-mutations.XXXXXX")"
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

# Build a tiny real ARM64 Mach-O fixture carrying an untargeted non-NOP instruction immediately
# after an unconditional `b` (SURVEY.md section 5.4 item 2a: Clang -O2 eliminates dead instructions
# after `b`, so every `idx + 1` in system binaries already has an incoming branch/jump-table target
# in `leaderIndices`).
UNREACH_B_C="$TMP_WORK/untargeted_after_b_fixture.c"
UNREACH_B_BIN="$TMP_WORK/untargeted_after_b_fixture"
cat > "$UNREACH_B_C" <<'EOF'
__attribute__((used, noinline)) int unreach_after_b(int x) {
    __asm__ volatile(
        "b 1f\n\t"
        "add x9, x9, #1\n"
        "1:\n"
        ::: "x9"
    );
    return x + 1;
}
int main(void) {
    return unreach_after_b(0);
}
EOF
HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
    xcrun clang -arch arm64 -O0 -o "$UNREACH_B_BIN" "$UNREACH_B_C"

echo "=== MachGraph M4 Mutation Verification Suite ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "System:     $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo ""
echo "[setup] Verifying all M4 patches with git apply --check..."
for patch_name in \
    m4-01-function-starts-drop-last.patch \
    m4-02a-i1-no-split-after-b.patch \
    m4-02b-i1-no-split-after-bcond.patch \
    m4-03-i2-cond-branch-no-leader.patch \
    m4-04-domtree-skip-lt-step4.patch \
    m4-05-loops-fixed-depth-one.patch \
    m4-06a-switch-csel-bound-minus-one.patch \
    m4-06b-switch-bhi-bound-minus-one.patch \
    m4-07-noreturn-drop-stack-chk-fail.patch; do
    git -C "$REPO_ROOT" apply --check "$MUTATIONS_DIR/$patch_name"
done
echo "[setup] Building initial unmutated release MachGraph in temporary workspace..."
HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
    swift build --package-path "$TMP_REPO" -c release --product MachGraph >/dev/null
TMP_REL_BIN="$TMP_REPO/.build/release/MachGraph"

# Sanity-check that the unmutated binary passes on the 2a fixture + /bin/ls before mutating.
SANITY_JSON="$TMP_WORK/sanity_baseline.json"
if ! HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" python3 -I "$ACCEPT_SCRIPT" \
    "$UNREACH_B_BIN" /bin/ls --only function-starts,invariants \
    --machgraph "$TMP_REL_BIN" --json-out "$SANITY_JSON" >/dev/null 2>&1; then
    echo "[FAIL] Unmutated release binary failed baseline function-starts/invariants check on untargeted_after_b_fixture + /bin/ls" >&2
    exit 1
fi
echo "[setup] Baseline unmutated release build Ready (2a fixture + /bin/ls baseline PASS)."
echo ""

TOTAL=0
PASSED=0
UNCAUGHT_IDS=()

reverse_and_verify_clean() {
    local id="$1"
    local patch_file="$2"
    local patch_path="$MUTATIONS_DIR/$patch_file"
    if ! git -C "$TMP_REPO" apply -R "$patch_path"; then
        echo "[FAIL] Mutation $id: failed to reverse patch $patch_file" >&2
        exit 1
    fi
    if ! diff -qr "$REPO_ROOT/Sources" "$TMP_REPO/Sources" >/dev/null; then
        echo "[FAIL] Mutation $id: temporary Sources/ differs from repository Sources/ after reversing $patch_file" >&2
        exit 1
    fi
}

run_mutation() {
    local id="$1"
    local patch_file="$2"
    local mutated_where="$3"
    local expected_check="$4"
    local validator_kind="$5"
    shift 5
    local -a accept_args=("$@")

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

    # 3. Run minimal m4-cfg-acceptance.py check with explicit --machgraph and expect non-zero exit
    local out_json="$TMP_WORK/mut_${id}.json"
    local out_txt="$TMP_WORK/mut_${id}.txt"
    set +e
    HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" python3 -I "$ACCEPT_SCRIPT" \
        "${accept_args[@]}" --machgraph "$TMP_REL_BIN" --json-out "$out_json" > "$out_txt" 2>&1
    local rc=$?
    set -e

    # Format display command without exposing host-specific temp directories
    local display_args=()
    for a in "${accept_args[@]}"; do
        if [[ "$a" == "$UNREACH_B_BIN" ]]; then
            display_args+=("<tmp>/untargeted_after_b_fixture")
        else
            display_args+=("$a")
        fi
    done
    local display_cmd="python3 -I Scripts/acceptance/m4-cfg-acceptance.py ${display_args[*]} --machgraph <tmp>/.build/release/MachGraph"

    if [[ "$rc" -eq 0 ]]; then
        local pass_detail
        pass_detail="$(python3 -I - "$expected_check" "$out_json" <<'PY'
import json
import sys

expected_check, json_path = sys.argv[1:3]
with open(json_path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
chk = doc.get("checks", {}).get(expected_check, {})
print(
    f"verdict={doc.get('verdict')} total_diffs={chk.get('total_diffs')} "
    f"edges={chk.get('total_edges')} noreturn_exits={chk.get('noreturn_exit_calls_verified')} "
    f"violations={chk.get('violations_by_invariant')}"
)
PY
)"
        echo "[FAIL] Mutation $id — Scripts/acceptance/mutations/$patch_file (ESCAPED: exit code 0)"
        echo "  Mutated:        $mutated_where"
        echo "  Command:        $display_cmd"
        echo "  Expected fail:  $expected_check (non-zero exit), but check PASSED ($pass_detail)"
        echo ""
        reverse_and_verify_clean "$id" "$patch_file"
        UNCAUGHT_IDS+=("$id")
        return 0
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
assert chk.get("mismatched_files", 0) > 0 or chk.get("total_diffs", 0) > 0 or chk.get("diff_count", 0) > 0, (
    f"subcheck {expected_check} did not fail: {chk}"
)
examples = chk.get("examples", [])

if kind == "01_function_starts":
    ex = next((e for e in examples if e.get("kind") == "CFG_TEXT_UNION_INLINE_JT_MISMATCH"), None)
    assert ex is not None and ex.get("missing"), f"expected CFG_TEXT_UNION_INLINE_JT_MISMATCH with missing start, got {examples[:3]}"
    print(
        f"/bin/ls ref_in_text={ex['ref_in_text_count']} vs mg=({ex['text_fn_count']} text + "
        f"{ex['inline_jt_in_text_count']} inline_jt); missing={ex['missing']}"
    )

elif kind == "02a_i1_interior_b":
    v_i1 = chk.get("violations_by_invariant", {}).get("I1", 0)
    ex = next((e for e in examples if e.get("kind") == "INTERIOR_TERMINATOR" and e.get("insnKind") == "b"), None)
    assert v_i1 > 0 and ex is not None, f"expected I1 INTERIOR_TERMINATOR on 'b', got {examples[:3]}"
    print(
        f"I1 violations={v_i1}: INTERIOR_TERMINATOR in {ex.get('function')} blockID={ex.get('blockID')} "
        f"pc={ex.get('pc')} insnKind={ex.get('insnKind')}"
    )

elif kind == "02b_i1_interior_bcond":
    v_i1 = chk.get("violations_by_invariant", {}).get("I1", 0)
    ex = next((e for e in examples if e.get("kind") == "INTERIOR_TERMINATOR" and e.get("insnKind") == "cond_branch"), None)
    assert v_i1 > 0 and ex is not None, f"expected I1 INTERIOR_TERMINATOR on 'cond_branch', got {examples[:3]}"
    print(
        f"/bin/ls I1 violations={v_i1} (total_diffs={chk['total_diffs']}): INTERIOR_TERMINATOR in "
        f"{ex.get('function')} blockID={ex.get('blockID')} pc={ex.get('pc')} insnKind={ex.get('insnKind')}"
    )

elif kind == "03_i2_cond_target":
    v_i2 = chk.get("violations_by_invariant", {}).get("I2", 0)
    ex = next((e for e in examples if e.get("kind") == "INTRA_FN_COND_BRANCH_TARGET_NOT_BLOCK_START"), None)
    assert v_i2 > 0 and ex is not None, f"expected I2 INTRA_FN_COND_BRANCH_TARGET_NOT_BLOCK_START, got {examples[:3]}"
    print(
        f"/bin/ls I2 violations={v_i2} (total_diffs={chk['total_diffs']}): "
        f"INTRA_FN_COND_BRANCH_TARGET_NOT_BLOCK_START in {ex.get('function')} pc={ex.get('pc')} -> target={ex.get('target')}"
    )

elif kind == "04_domtree_lt":
    v_i4 = chk.get("violations_by_invariant", {}).get("I4", 0)
    dom_ex = next(
        (e for e in examples if e.get("kind") in ("IDOM_MISMATCH", "DOM_FRONTIER_MISMATCH", "DOM_CHILDREN_MISMATCH", "DOM_DEPTH_MISMATCH")),
        None,
    )
    assert v_i4 > 0 and dom_ex is not None, f"expected I4 dominator mismatch, got {examples[:3]}"
    print(
        f"/bin/ls I4 dominator violations={v_i4}: {dom_ex.get('kind')} in {dom_ex.get('function')} "
        f"blockID={dom_ex.get('blockID')} reported={dom_ex.get('reported')} vs expected={dom_ex.get('expected')}"
    )

elif kind == "05_loops_depth":
    assert chk.get("status") == "fail" and chk.get("matched_cases", 8) < chk.get("total_cases", 8), chk
    case_ex = next((e for e in examples if e.get("symbol") == "_fn_nested_loop"), None)
    assert case_ex is not None and "loop_nesting_depths" in case_ex.get("mismatches", {}), f"expected _fn_nested_loop depth mismatch, got {examples}"
    mm = case_ex["mismatches"]["loop_nesting_depths"]
    print(
        f"known-c matched={chk['matched_cases']}/{chk['total_cases']} (diffs={chk['diff_count']}): "
        f"_fn_nested_loop loop_nesting_depths actual={mm['actual']} != expected={mm['expected']}"
    )

elif kind == "06a_csel_bound":
    v_i2 = chk.get("violations_by_invariant", {}).get("I2", 0)
    ex = next((e for e in examples if e.get("kind") == "INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION"), None)
    assert v_i2 > 0 and ex is not None, f"expected I2 INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION on ssh, got {examples[:3]}"
    print(
        f"/usr/bin/ssh I2 violations={v_i2}: INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION in "
        f"{ex.get('function')} tableBase={ex.get('tableBase')} alignedEnd={ex.get('alignedEnd')} postWord={ex.get('postWord')}"
    )

elif kind == "06b_switch10_bound":
    assert chk.get("status") == "fail", chk
    case_ex = next((e for e in examples if e.get("symbol") == "_fn_switch10_jumptable"), None)
    udf_ex = next((e for e in examples if e.get("kind") == "INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION"), None)
    assert case_ex is not None and udf_ex is not None, f"expected _fn_switch10_jumptable target + udf mismatch, got {examples}"
    jt_mm = case_ex["mismatches"].get("jump_table_targets", {})
    print(
        f"known-c matched={chk['matched_cases']}/{chk['total_cases']}: _fn_switch10_jumptable "
        f"jump_table_targets actual={jt_mm.get('actual')} != expected={jt_mm.get('expected')} + INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION"
    )

elif kind == "07_noreturn":
    v_i1 = chk.get("violations_by_invariant", {}).get("I1", 0)
    assert v_i1 > 0 or chk.get("total_diffs", 0) > 0, f"expected I1 noreturn violation on /usr/bin/ssh, got {chk}"
    e0 = examples[0] if examples else {}
    print(
        f"/usr/bin/ssh invariants total_diffs={chk['total_diffs']} (violations={chk.get('violations_by_invariant')}); "
        f"e.g. {e0.get('kind')} in {e0.get('function')} pc={e0.get('pc')}"
    )

else:
    raise AssertionError(f"unknown validator_kind {kind}")
PY
)"; then
        echo "[FAIL] Mutation $id ($patch_file): failed with exit $rc, but output did not match expected discrepancy!" >&2
        cat "$out_txt" >&2
        reverse_and_verify_clean "$id" "$patch_file"
        exit 1
    fi

    # 5. Reverse patch and verify temporary Sources/ matches clean REPO_ROOT/Sources/ byte-for-byte
    reverse_and_verify_clean "$id" "$patch_file"

    PASSED=$((PASSED + 1))
    echo "[PASS] Mutation $id — Scripts/acceptance/mutations/$patch_file"
    echo "  Mutated:        $mutated_where"
    echo "  Command:        $display_cmd"
    echo "  Failed check:   $expected_check (exit code $rc)"
    echo "  Summary:        $summary_line"
    echo ""
}

run_mutation "1" \
    "m4-01-function-starts-drop-last.patch" \
    "Sources/MachCFGEngine/FunctionBoundaryAndJumpTableAnalyzer.swift:556 (discoverFunctionsWithJumpTables: drop last LC_FUNCTION_STARTS entry)" \
    "function-starts" \
    "01_function_starts" \
    quick --only function-starts

run_mutation "2a" \
    "m4-02a-i1-no-split-after-b.patch" \
    "Sources/MachCFGEngine/BasicBlockAndCFGBuilder.swift:679 (partitionBasicBlocks: omit leaderIndices.insert(idx + 1) after unconditional 'b')" \
    "invariants" \
    "02a_i1_interior_b" \
    "$UNREACH_B_BIN" /bin/ls --only invariants

run_mutation "2b" \
    "m4-02b-i1-no-split-after-bcond.patch" \
    "Sources/MachCFGEngine/BasicBlockAndCFGBuilder.swift:687 (partitionBasicBlocks: omit leaderIndices.insert(idx + 1) after conditional branch)" \
    "invariants" \
    "02b_i1_interior_bcond" \
    quick --only invariants

run_mutation "3" \
    "m4-03-i2-cond-branch-no-leader.patch" \
    "Sources/MachCFGEngine/BasicBlockAndCFGBuilder.swift:684 (partitionBasicBlocks: omit conditionalBranch target from leaderIndices)" \
    "invariants" \
    "03_i2_cond_target" \
    quick --only invariants

run_mutation "4" \
    "m4-04-domtree-skip-lt-step4.patch" \
    "Sources/MachCFGEngine/LengauerTarjanDominatorAndLoopAnalyzer.swift:1109 (runLengauerTarjanCore: comment out Step 4 idom[w] = idom[idom[w]])" \
    "invariants" \
    "04_domtree_lt" \
    quick --only invariants

run_mutation "5" \
    "m4-05-loops-fixed-depth-one.patch" \
    "Sources/MachCFGEngine/LengauerTarjanDominatorAndLoopAnalyzer.swift:593 (recoverNaturalLoops: hardcode nestingDepth to 1)" \
    "known-c" \
    "05_loops_depth" \
    known-c

run_mutation "6a" \
    "m4-06a-switch-csel-bound-minus-one.patch" \
    "Sources/MachCFGEngine/FunctionBoundaryAndJumpTableAnalyzer.swift:1386 (findSwitchBoundsGuard: csel clamp upperBoundInclusive - 1)" \
    "invariants" \
    "06a_csel_bound" \
    /usr/bin/ssh --only invariants

run_mutation "6b" \
    "m4-06b-switch-bhi-bound-minus-one.patch" \
    "Sources/MachCFGEngine/FunctionBoundaryAndJumpTableAnalyzer.swift:1278 (findSwitchBoundsGuard: b.hi/b.gt upperBoundInclusive - 1)" \
    "known-c" \
    "06b_switch10_bound" \
    known-c

run_mutation "7" \
    "m4-07-noreturn-drop-stack-chk-fail.patch" \
    "Sources/MachCFGEngine/BasicBlockAndCFGBuilder.swift:42 (KnownNoreturnSymbols.unprefixedNames: remove __stack_chk_fail)" \
    "invariants" \
    "07_noreturn" \
    /usr/bin/ssh --only invariants

# Verify product source tree in REPO_ROOT was never touched during this run
AFTER_SOURCE_DIFF="$(git -C "$REPO_ROOT" diff -- Package.swift Sources Tests Fixtures)"
AFTER_SOURCE_UNTRACKED="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- Package.swift Sources Tests Fixtures)"
if [[ "$AFTER_SOURCE_DIFF" != "$INITIAL_SOURCE_DIFF" || "$AFTER_SOURCE_UNTRACKED" != "$INITIAL_SOURCE_UNTRACKED" ]]; then
    echo "[FAIL] Repository product/test sources have unexpected modifications!" >&2
    exit 1
fi

if [[ "${#UNCAUGHT_IDS[@]}" -gt 0 ]]; then
    echo "=== M4 MUTATION VERIFICATION FAILED: $PASSED/$TOTAL CAUGHT, ${#UNCAUGHT_IDS[@]}/$TOTAL ESCAPED (uncaught IDs: ${UNCAUGHT_IDS[*]}; repo Sources/ clean) ===" >&2
    exit 1
fi

echo "=== ALL $PASSED/$TOTAL M4 MUTATIONS CAUGHT AS EXPECTED (7 capability groups, 9 patches; repo Sources/ clean) ==="
