#!/usr/bin/env bash
# M5 Destructive Mutation Verification Suite (Stage 3a, Acceptance Row 6)
#
# Applies each M5 single-defect mutation spec under Scripts/acceptance/mutations/m5-*.json
# inside an isolated temporary copy of the repository (leaving the real working tree and .git
# untouched), rebuilds the release MachGraph binary, runs the corresponding acceptance harness
# (m5-mcp-acceptance.py or m5-lib-examples.py), and verifies that every mutation exits non-zero
# and reports the expected discrepancy.
#
# Patch rule: every replacement enforces strict exact-once matching (count == 1). If the target
# snippet occurs 0 times or more than once, the script fails immediately without silent skipping.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MUTATIONS_DIR="$REPO_ROOT/Scripts/acceptance/mutations"
MCP_SCRIPT="$REPO_ROOT/Scripts/acceptance/m5-mcp-acceptance.py"
LIB_SCRIPT="$REPO_ROOT/Scripts/acceptance/m5-lib-examples.py"

SPEC_FILES=(
    "m5-01a-mcp-disasm-ignore-count.json"
    "m5-01b-mcp-audit-drop-unverified-marker.json"
    "m5-02a-a64-drop-exported-models.json"
    "m5-02b-elf64loader-leak-public.json"
    "m5-02c-cfg-fileurl-ignore-selector.json"
    "m5-02d-asn1derwalker-leak-public.json"
    "m5-02e-package-readd-decompiler-product.json"
    "m5-02f-cfg-drop-exported-models.json"
)

apply_or_reverse_spec() {
    local mode="$1"
    local spec_path="$2"
    local target_root="$3"
    python3 -I - "$mode" "$spec_path" "$target_root" <<'PY'
import json
import os
import sys

mode, spec_path, target_root = sys.argv[1:4]
if not os.path.isfile(spec_path):
    print(f"[FAIL] Missing mutation spec file: {spec_path}", file=sys.stderr)
    sys.exit(1)

with open(spec_path, "r", encoding="utf-8") as fh:
    spec = json.load(fh)

mut_id = spec.get("id", "<unknown>")
replacements = spec.get("replacements", [])
if not replacements:
    print(f"[FAIL] Mutation {mut_id}: spec has empty replacements list", file=sys.stderr)
    sys.exit(1)

# Phase 1: validate every replacement has exact count == 1 in memory before modifying any file
buffers = {}
ordered = list(enumerate(replacements))
if mode == "reverse":
    ordered.reverse()

for idx, rep in ordered:
    rel_file = rep["file"]
    needle = rep["old"] if mode == "apply" else rep["new"]
    replacement = rep["new"] if mode == "apply" else rep["old"]
    full_path = os.path.join(target_root, rel_file)
    if full_path not in buffers:
        if not os.path.isfile(full_path):
            print(
                f"[FAIL] Mutation {mut_id} ({mode} #{idx + 1}): target file not found: {rel_file}",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(full_path, "r", encoding="utf-8") as fh:
            buffers[full_path] = fh.read()
    src = buffers[full_path]
    occ = src.count(needle)
    if occ != 1:
        print(
            f"[FAIL] Mutation {mut_id} ({mode} #{idx + 1}): expected exact-once match (1 occurrence) "
            f"in {rel_file}, found {occ} occurrences",
            file=sys.stderr,
        )
        sys.exit(1)
    buffers[full_path] = src.replace(needle, replacement, 1)

# Phase 2: write atomically once all checks pass
for full_path, updated in buffers.items():
    with open(full_path, "w", encoding="utf-8") as fh:
        fh.write(updated)
PY
}

verify_all_specs_against_repo() {
    local check_tmp
    check_tmp="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m5-spec-check.XXXXXX")"
    mkdir -p "$check_tmp/repo"
    cp "$REPO_ROOT/Package.swift" "$check_tmp/repo/Package.swift"
    cp -R "$REPO_ROOT/Sources" "$check_tmp/repo/Sources"
    for spec_name in "${SPEC_FILES[@]}"; do
        local sp="$MUTATIONS_DIR/$spec_name"
        if ! apply_or_reverse_spec "apply" "$sp" "$check_tmp/repo"; then
            rm -rf "$check_tmp"
            exit 1
        fi
        if ! apply_or_reverse_spec "reverse" "$sp" "$check_tmp/repo"; then
            rm -rf "$check_tmp"
            exit 1
        fi
        if ! cmp -s "$REPO_ROOT/Package.swift" "$check_tmp/repo/Package.swift" || \
           ! diff -qr "$REPO_ROOT/Sources" "$check_tmp/repo/Sources" >/dev/null; then
            echo "[FAIL] Spec roundtrip left residual diff: $spec_name" >&2
            rm -rf "$check_tmp"
            exit 1
        fi
    done
    rm -rf "$check_tmp"
}

if [[ "${1:-}" == "--apply-spec" ]]; then
    if [[ "$#" -ne 3 ]]; then
        echo "Usage: $0 --apply-spec <spec.json> <target_repo_dir>" >&2
        exit 2
    fi
    apply_or_reverse_spec "apply" "$2" "$3"
    exit 0
fi

if [[ "${1:-}" == "--reverse-spec" ]]; then
    if [[ "$#" -ne 3 ]]; then
        echo "Usage: $0 --reverse-spec <spec.json> <target_repo_dir>" >&2
        exit 2
    fi
    apply_or_reverse_spec "reverse" "$2" "$3"
    exit 0
fi

if [[ "${1:-}" == "--verify-specs" ]]; then
    verify_all_specs_against_repo
    echo "[PASS] Verified all ${#SPEC_FILES[@]} M5 mutation specs match repository sources with exact count == 1."
    exit 0
fi

if [[ "$#" -ne 0 ]]; then
    echo "Usage: $0 [--verify-specs | --apply-spec <spec.json> <dir> | --reverse-spec <spec.json> <dir>]" >&2
    exit 2
fi

TMP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m5-mutations.XXXXXX")"
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

# Copy only buildable package and documentation inputs into the temporary workspace (never copy .git or touch REPO_ROOT).
cp "$REPO_ROOT/Package.swift" "$TMP_REPO/Package.swift"
if [[ -f "$REPO_ROOT/Package.resolved" ]]; then
    cp "$REPO_ROOT/Package.resolved" "$TMP_REPO/Package.resolved"
fi
cp -R "$REPO_ROOT/Sources" "$TMP_REPO/Sources"
cp -R "$REPO_ROOT/Tests" "$TMP_REPO/Tests"
if [[ -d "$REPO_ROOT/Fixtures" ]]; then
    cp -R "$REPO_ROOT/Fixtures" "$TMP_REPO/Fixtures"
fi
if [[ -d "$REPO_ROOT/docs" ]]; then
    cp -R "$REPO_ROOT/docs" "$TMP_REPO/docs"
fi
if [[ -f "$REPO_ROOT/README.md" ]]; then
    cp "$REPO_ROOT/README.md" "$TMP_REPO/README.md"
fi
if [[ -f "$REPO_ROOT/README.zh-CN.md" ]]; then
    cp "$REPO_ROOT/README.zh-CN.md" "$TMP_REPO/README.zh-CN.md"
fi

echo "=== MachGraph M5 Mutation Verification Suite ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "System:     $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo ""
echo "[setup] Verifying exact-once occurrence for all ${#SPEC_FILES[@]} M5 mutation specs..."
verify_all_specs_against_repo
echo "[setup] Building initial unmutated release MachGraph in temporary workspace..."
HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
    swift build --package-path "$TMP_REPO" -c release --product MachGraph >/dev/null
TMP_REL_BIN="$TMP_REPO/.build/release/MachGraph"

SANITY_JSON="$TMP_WORK/sanity_protocol.json"
if ! HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" python3 -I "$MCP_SCRIPT" \
    protocol --machgraph "$TMP_REL_BIN" --json-out "$SANITY_JSON" >/dev/null 2>&1; then
    echo "[FAIL] Unmutated release binary failed baseline MCP protocol sanity check" >&2
    exit 1
fi
echo "[setup] Baseline unmutated release build Ready (MCP protocol baseline PASS)."
echo ""

TOTAL=0
PASSED=0
UNCAUGHT_IDS=()

reverse_and_verify_clean() {
    local id="$1"
    local spec_file="$2"
    local spec_path="$MUTATIONS_DIR/$spec_file"
    if ! apply_or_reverse_spec "reverse" "$spec_path" "$TMP_REPO"; then
        echo "[FAIL] Mutation $id: failed to reverse spec $spec_file" >&2
        exit 1
    fi
    if ! cmp -s "$REPO_ROOT/Package.swift" "$TMP_REPO/Package.swift"; then
        echo "[FAIL] Mutation $id: temporary Package.swift differs from repository Package.swift after reversing $spec_file" >&2
        exit 1
    fi
    if ! diff -qr "$REPO_ROOT/Sources" "$TMP_REPO/Sources" >/dev/null; then
        echo "[FAIL] Mutation $id: temporary Sources/ differs from repository Sources/ after reversing $spec_file" >&2
        exit 1
    fi
}

run_mutation() {
    local id="$1"
    local spec_file="$2"
    local mutated_file="$3"
    local harness_kind="$4"
    local validator_kind="$5"
    shift 5
    local -a harness_args=("$@")

    TOTAL=$((TOTAL + 1))
    local spec_path="$MUTATIONS_DIR/$spec_file"

    # 1. Apply exact-once replacement spec in temporary copy
    apply_or_reverse_spec "apply" "$spec_path" "$TMP_REPO"

    # 2. Rebuild release MachGraph incrementally in temporary copy
    if ! HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" \
        swift build --package-path "$TMP_REPO" -c release --product MachGraph >/dev/null 2>&1; then
        echo "[FAIL] Mutation $id: mutated workspace failed release build ($spec_file)" >&2
        reverse_and_verify_clean "$id" "$spec_file"
        exit 1
    fi

    # 3. Run corresponding acceptance harness and expect non-zero exit
    local out_json="$TMP_WORK/mut_${id}.json"
    local out_txt="$TMP_WORK/mut_${id}.txt"
    local display_script=""
    local rc=0
    set +e
    if [[ "$harness_kind" == "mcp" ]]; then
        display_script="Scripts/acceptance/m5-mcp-acceptance.py ${harness_args[*]} --machgraph <tmp>/.build/release/MachGraph"
        HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" python3 -I "$MCP_SCRIPT" \
            "${harness_args[@]}" --machgraph "$TMP_REL_BIN" --json-out "$out_json" > "$out_txt" 2>&1
        rc=$?
    elif [[ "$harness_kind" == "lib" ]]; then
        display_script="Scripts/acceptance/m5-lib-examples.py --repo-root <tmp>/repo"
        HOME="$TMP_HOME" CFFIXED_USER_HOME="$TMP_HOME" python3 -I "$LIB_SCRIPT" \
            --repo-root "$TMP_REPO" --json-out "$out_json" > "$out_txt" 2>&1
        rc=$?
    else
        echo "[FAIL] Unknown harness_kind '$harness_kind'" >&2
        exit 1
    fi
    set -e

    if [[ "$rc" -eq 0 ]]; then
        echo "[FAIL] Mutation $id — Scripts/acceptance/mutations/$spec_file (ESCAPED: exit code 0)"
        echo "  File:           $mutated_file"
        echo "  Script:         $display_script"
        echo "  Exit code:      $rc"
        echo ""
        reverse_and_verify_clean "$id" "$spec_file"
        UNCAUGHT_IDS+=("$id")
        return 0
    fi

    # 4. Validate expected failure class and extract the first caught diff line (sanitized)
    local first_diff_line
    if ! first_diff_line="$(python3 -I - "$validator_kind" "$out_json" "$out_txt" <<'PY'
import json
import os
import re
import sys

kind, json_path, txt_path = sys.argv[1:4]
with open(json_path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
with open(txt_path, "r", encoding="utf-8") as fh:
    txt = fh.read()


def clean_line(s: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "/":
        s = s.replace(home, "<HOME>")
    s = re.sub(r"/private/var/folders/[^\s\"']+", "<TMP>", s)
    s = re.sub(r"/var/folders/[^\s\"']+", "<TMP>", s)
    s = re.sub(r"/tmp/[^\s\"']+", "<TMP>", s)
    s = " ".join(s.splitlines())
    return s[:220]


if kind == "1a_mcp_disasm_count":
    assert doc.get("verdict") == "FAIL", f"expected FAIL, got {doc.get('verdict')}"
    chk = doc["checks"]["tools"]
    exs = chk.get("examples", [])
    hit = next((e for e in exs if e.get("kind") == "BYTE_MISMATCH" and "disasm" in str(e.get("case", ""))), None)
    assert hit is not None, f"expected BYTE_MISMATCH on disasm, got {exs[:3]}"
    print(clean_line(
        f"BYTE_MISMATCH case={hit.get('case')} tool={hit.get('tool')} "
        f"mcp_bytes={hit.get('mcp_bytes')} != cli_bytes={hit.get('cli_bytes')}"
    ))

elif kind == "1b_mcp_audit_marker":
    assert doc.get("verdict") == "FAIL", f"expected FAIL, got {doc.get('verdict')}"
    chk = doc["checks"]["legacy"]
    exs = chk.get("examples", [])
    hit = next((e for e in exs if e.get("kind") == "MISSING_UNVERIFIED_MARKER" and e.get("tool") == "mach_audit_security"), None)
    assert hit is not None, f"expected MISSING_UNVERIFIED_MARKER on mach_audit_security, got {exs[:3]}"
    print(clean_line(
        f"MISSING_UNVERIFIED_MARKER tool={hit.get('tool')} lang={hit.get('lang')} "
        f"first_line={hit.get('first_line')!r}"
    ))

elif kind == "2a_a64_exported":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "BUILD_FAILED" and d.get("target") == "MachA64Decoder"), None)
    assert hit is not None, f"expected BUILD_FAILED on MachA64Decoder, got {diffs[:3]}"
    print(clean_line(f"BUILD_FAILED target={hit.get('target')} returncode={hit.get('returncode')} (missing @_exported MachGraphModels)"))

elif kind == "2b_elf64_public":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED" and d.get("symbol") == "ELF64Loader"), None)
    assert hit is not None, f"expected NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED on ELF64Loader, got {diffs[:3]}"
    print(clean_line(f"NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe={hit.get('probe')} symbol={hit.get('symbol')}: {hit.get('detail')}"))

elif kind == "2c_cfg_ignore_selector":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "RUNTIME_OUTPUT_MISMATCH" and d.get("module") == "MachCFGEngine"), None)
    assert hit is not None, f"expected RUNTIME_OUTPUT_MISMATCH on MachCFGEngine, got {diffs[:3]}"
    print(clean_line(
        f"RUNTIME_OUTPUT_MISMATCH module={hit.get('module')} actual={hit.get('actual')!r} != reference={hit.get('reference')!r}"
    ))

elif kind == "2d_asn1_public":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED" and d.get("symbol") == "ASN1DERWalker"), None)
    assert hit is not None, f"expected NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED on ASN1DERWalker, got {diffs[:3]}"
    print(clean_line(f"NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe={hit.get('probe')} symbol={hit.get('symbol')}: {hit.get('detail')}"))

elif kind == "2e_decompiler_product":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED" and d.get("symbol") == "MachMicroDecompiler"), None)
    assert hit is not None, f"expected NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED on MachMicroDecompiler, got {diffs[:3]}"
    print(clean_line(f"NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED probe={hit.get('probe')} symbol={hit.get('symbol')}: {hit.get('detail')}"))

elif kind == "2f_cfg_exported":
    assert doc.get("passed") is False, f"expected passed=False, got {doc.get('passed')}"
    diffs = doc.get("diffs", [])
    hit = next((d for d in diffs if d.get("kind") == "BUILD_FAILED" and d.get("target") == "MachCFGEngine"), None)
    assert hit is not None, f"expected BUILD_FAILED on MachCFGEngine, got {diffs[:3]}"
    print(clean_line(f"BUILD_FAILED target={hit.get('target')} returncode={hit.get('returncode')} (missing @_exported MachGraphModels)"))

else:
    raise AssertionError(f"Unknown validator_kind {kind}")
PY
)"; then
        echo "[FAIL] Mutation $id ($spec_file): exited $rc, but output did not match expected discrepancy!" >&2
        cat "$out_txt" >&2
        reverse_and_verify_clean "$id" "$spec_file"
        exit 1
    fi

    # 5. Reverse spec and verify temporary Sources/ & Package.swift match clean REPO_ROOT byte-for-byte
    reverse_and_verify_clean "$id" "$spec_file"

    PASSED=$((PASSED + 1))
    echo "[PASS] Mutation $id — Scripts/acceptance/mutations/$spec_file"
    echo "  File:           $mutated_file"
    echo "  Script:         $display_script"
    echo "  Exit code:      $rc"
    echo "  First diff:     $first_diff_line"
    echo ""
}

run_mutation "1a" \
    "m5-01a-mcp-disasm-ignore-count.json" \
    "Sources/MachHeadlessCLI/MachCLIRunnerAndMCPServer.swift" \
    "mcp" \
    "1a_mcp_disasm_count" \
    tools

run_mutation "1b" \
    "m5-01b-mcp-audit-drop-unverified-marker.json" \
    "Sources/MachHeadlessCLI/MachCLIRunnerAndMCPServer.swift" \
    "mcp" \
    "1b_mcp_audit_marker" \
    legacy

run_mutation "2a" \
    "m5-02a-a64-drop-exported-models.json" \
    "Sources/MachA64Decoder/SymbolDemangler.swift" \
    "lib" \
    "2a_a64_exported"

run_mutation "2b" \
    "m5-02b-elf64loader-leak-public.json" \
    "Sources/MachBinaryFormats/MultiFormatCrossLoader.swift" \
    "lib" \
    "2b_elf64_public"

run_mutation "2c" \
    "m5-02c-cfg-fileurl-ignore-selector.json" \
    "Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift" \
    "lib" \
    "2c_cfg_ignore_selector"

run_mutation "2d" \
    "m5-02d-asn1derwalker-leak-public.json" \
    "Sources/MachBinaryFormats/CodeSignatureAndCMSParser.swift" \
    "lib" \
    "2d_asn1_public"

run_mutation "2e" \
    "m5-02e-package-readd-decompiler-product.json" \
    "Package.swift" \
    "lib" \
    "2e_decompiler_product"

run_mutation "2f" \
    "m5-02f-cfg-drop-exported-models.json" \
    "Sources/MachCFGEngine/CrossReferenceAndCallGraphDatabase.swift" \
    "lib" \
    "2f_cfg_exported"

# Verify product source tree in REPO_ROOT was never touched during this run
AFTER_SOURCE_DIFF="$(git -C "$REPO_ROOT" diff -- Package.swift Sources Tests Fixtures)"
AFTER_SOURCE_UNTRACKED="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- Package.swift Sources Tests Fixtures)"
if [[ "$AFTER_SOURCE_DIFF" != "$INITIAL_SOURCE_DIFF" || "$AFTER_SOURCE_UNTRACKED" != "$INITIAL_SOURCE_UNTRACKED" ]]; then
    echo "[FAIL] Repository product/test sources have unexpected modifications!" >&2
    exit 1
fi

if [[ "${#UNCAUGHT_IDS[@]}" -gt 0 ]]; then
    echo "=== $PASSED/$TOTAL 条被抓到 (M5 MUTATION VERIFICATION FAILED: ${#UNCAUGHT_IDS[@]}/$TOTAL ESCAPED: ${UNCAUGHT_IDS[*]}; repo Sources/ clean) ===" >&2
    exit 1
fi

echo "=== $PASSED/$TOTAL 条被抓到 (ALL $PASSED/$TOTAL M5 MUTATIONS CAUGHT AS EXPECTED; repo Sources/ clean) ==="
