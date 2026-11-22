#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <ModuleOrFilter...>
  Scripts/test.sh milestone <N> [--record]
  Scripts/test.sh mutations
  Scripts/test.sh release

milestone writes the acceptance logs to a temporary directory and leaves the work tree untouched.
Pass --record to refresh the committed copies under reports/ (the README cites those numbers).
EOF
    exit 2
}

map_scope_filter() {
    case "$1" in
        MachGraphModels)
            echo "BinaryFormatLoadersTests|MachGraphModels"
            ;;
        MachBinaryFormats)
            echo "BinaryFormatLoadersTests|MachBinaryFormats"
            ;;
        MachA64Decoder)
            echo "ARM64DecoderAssemblerAndDemanglerTests|MachA64Decoder"
            ;;
        MachCFGEngine)
            echo "CFGDominatorsSugiyamaAndXrefsTests|MachCFGEngine"
            ;;
        MachMicroDecompiler)
            echo "MicroIRSSAPseudoCDecompilerTests|MachMicroDecompiler"
            ;;
        MachPatchAndHexEngine)
            echo "PatchHexReSignAndEntropyTests|MachPatchAndHexEngine"
            ;;
        MachProjectStore)
            echo "ProjectStoreAnnotationsAndUndoTests|MachProjectStore"
            ;;
        MachPluginSDK)
            echo "PluginSDKCLIMCPAndWorkbenchTests|MachPluginSDK"
            ;;
        MachHeadlessCLI)
            echo "PluginSDKCLIMCPAndWorkbenchTests|MachHeadlessCLI"
            ;;
        MachWorkbenchShell)
            echo "PluginSDKCLIMCPAndWorkbenchTests|MachWorkbenchShell"
            ;;
        MachStudioViews)
            echo "PluginSDKCLIMCPAndWorkbenchTests|MachStudioViews"
            ;;
        *)
            echo "$1"
            ;;
    esac
}

run_scope() {
    if [ "$#" -lt 1 ]; then
        usage
    fi
    local combined=""
    for item in "$@"; do
        local mapped
        mapped="$(map_scope_filter "$item")"
        if [ -z "$combined" ]; then
            combined="$mapped"
        else
            combined="${combined}|${mapped}"
        fi
    done
    echo "==> [scope] swift test --no-parallel --filter (${combined})"
    swift test --no-parallel --filter "(${combined})"
}

if [ "$#" -lt 1 ]; then
    usage
fi

MODE="$1"
shift

case "$MODE" in
    scope)
        run_scope "$@"
        ;;
    milestone)
        RECORD=0
        MS=""
        for arg in "$@"; do
            case "$arg" in
                --record) RECORD=1 ;;
                -*) usage ;;
                *)
                    if [ -n "$MS" ]; then
                        usage
                    fi
                    MS="$arg"
                    ;;
            esac
        done
        if [ -z "$MS" ]; then
            usage
        fi
        if [ "$RECORD" -eq 1 ] && [ -n "$(git status --porcelain)" ]; then
            echo "[FAIL] --record refused: git worktree has uncommitted changes (commit all changes before recording into reports/)." >&2
            exit 1
        fi
        case "$MS" in
            0|m0|M0)
                echo "==> [milestone 0] Scoped unit tests for M0-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachMicroDecompiler \
                    MachPatchAndHexEngine \
                    MachPluginSDK \
                    MachHeadlessCLI \
                    MachStudioViews
                echo "==> [milestone 0] Building MachGraph CLI binary"
                swift build --product MachGraph >/dev/null
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m0-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                fi
                echo "==> [milestone 0] Running Scripts/acceptance/m0-quick.sh -> $OUT_LABEL/m0-quick.txt"
                "$ROOT_DIR/Scripts/acceptance/m0-quick.sh" | tee "$OUT_DIR/m0-quick.txt"
                echo "==> [milestone 0] Running Scripts/acceptance/readme-commands.sh -> $OUT_LABEL/readme-commands.txt"
                "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" | tee "$OUT_DIR/readme-commands.txt"
                if [ "$RECORD" -eq 1 ]; then
                    echo "==> [milestone 0] Recorded logs under reports/ (commit them together with any README number change)"
                else
                    echo "==> [milestone 0] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            1|m1|M1)
                echo "==> [milestone 1] Scoped unit tests for M1-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachHeadlessCLI
                echo "==> [milestone 1] Differential harness unit tests"
                python3 "$ROOT_DIR/Scripts/acceptance/test_differential_harnesses.py"
                echo "==> [milestone 1] Building release MachGraph CLI binary"
                swift build -c release --product MachGraph >/dev/null
                REL_BIN="$ROOT_DIR/.build/release/MachGraph"
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m1-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                fi
                echo "==> [milestone 1] Running Scripts/acceptance/differential.py quick -> $OUT_LABEL/differential-quick.txt"
                python3 "$ROOT_DIR/Scripts/acceptance/differential.py" quick --machgraph "$REL_BIN" | tee "$OUT_DIR/differential-quick.txt"
                echo "==> [milestone 1] Running Scripts/acceptance/differential.py standard -> $OUT_LABEL/differential-standard.txt"
                python3 "$ROOT_DIR/Scripts/acceptance/differential.py" standard --machgraph "$REL_BIN" | tee "$OUT_DIR/differential-standard.txt"
                echo "==> [milestone 1] Running Scripts/acceptance/macho-differential.py quick -> $OUT_LABEL/macho-differential-quick.txt"
                python3 "$ROOT_DIR/Scripts/acceptance/macho-differential.py" quick --machgraph "$REL_BIN" | tee "$OUT_DIR/macho-differential-quick.txt"
                echo "==> [milestone 1] Running Scripts/acceptance/macho-differential.py standard -> $OUT_LABEL/macho-differential-standard.txt"
                python3 "$ROOT_DIR/Scripts/acceptance/macho-differential.py" standard --machgraph "$REL_BIN" | tee "$OUT_DIR/macho-differential-standard.txt"
                if [ "$RECORD" -eq 1 ]; then
                    echo "==> [milestone 1] Recorded logs under reports/"
                else
                    echo "==> [milestone 1] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            2|m2|M2)
                echo "==> [milestone 2] Scoped unit tests for M2-touched modules"
                run_scope \
                    MachA64Decoder \
                    MachHeadlessCLI
                echo "==> [milestone 2] Acceptance harness unit tests"
                python3 -I "$ROOT_DIR/Scripts/acceptance/test_differential_harnesses.py"
                python3 -I "$ROOT_DIR/Scripts/acceptance/test_asm_harnesses.py"
                echo "==> [milestone 2] Building release MachGraph CLI binary"
                swift build -c release --product MachGraph >/dev/null
                REL_BIN="$ROOT_DIR/.build/release/MachGraph"
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m2-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                fi
                echo "==> [milestone 2] Running Scripts/acceptance/differential.py standard -> $OUT_LABEL/differential-standard.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/differential.py" standard --machgraph "$REL_BIN" | tee "$OUT_DIR/differential-standard.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/encoding-table.py check --all -> $OUT_LABEL/encoding-table-check.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-table.py" check --all --machgraph "$REL_BIN" | tee "$OUT_DIR/encoding-table-check.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/encoding-fuzz.py --seed 20261117 -> $OUT_LABEL/encoding-fuzz-20261117.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-fuzz.py" --seed 20261117 --count 100000 --machgraph "$REL_BIN" | tee "$OUT_DIR/encoding-fuzz-20261117.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/encoding-fuzz.py --seed 17 -> $OUT_LABEL/encoding-fuzz-17.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-fuzz.py" --seed 17 --count 100000 --machgraph "$REL_BIN" | tee "$OUT_DIR/encoding-fuzz-17.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/asm-roundtrip.py standard -> $OUT_LABEL/asm-roundtrip-standard.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/asm-roundtrip.py" standard --machgraph "$REL_BIN" | tee "$OUT_DIR/asm-roundtrip-standard.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/asm-clang.py standard -> $OUT_LABEL/asm-clang-standard.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/asm-clang.py" standard --machgraph "$REL_BIN" | tee "$OUT_DIR/asm-clang-standard.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/asm-clang.py Fixtures/asm-cases.s -> $OUT_LABEL/asm-clang-cases.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/asm-clang.py" "Fixtures/asm-cases.s" --machgraph "$REL_BIN" | tee "$OUT_DIR/asm-clang-cases.txt"
                echo "==> [milestone 2] Running Scripts/acceptance/known-mnemonics.py check -> $OUT_LABEL/known-mnemonics-check.txt"
                python3 -I "$ROOT_DIR/Scripts/acceptance/known-mnemonics.py" check | tee "$OUT_DIR/known-mnemonics-check.txt"
                if [ "$RECORD" -eq 1 ]; then
                    echo "==> [milestone 2] Recorded logs under reports/"
                else
                    echo "==> [milestone 2] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            3|m3|M3)
                echo "==> [milestone 3] Scoped unit tests for M3-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachHeadlessCLI
                echo "==> [milestone 3] Acceptance harness unit tests"
                python3 -I "$ROOT_DIR/Scripts/acceptance/test_m3_harnesses.py"
                echo "==> [milestone 3] Building release MachGraph CLI binary"
                swift build -c release --product MachGraph >/dev/null
                REL_BIN="$ROOT_DIR/.build/release/MachGraph"
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                    STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m3-stage.XXXXXX")"
                    REC_DATE="$(date -u +%Y-%m-%d)"
                    echo "==> [milestone 3] Running Scripts/acceptance/m3-metadata-differential.py standard -> $OUT_LABEL/m3-metadata-standard.txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" standard --machgraph "$REL_BIN" | tee "$STAGE_DIR/m3-metadata-standard.txt"
                    echo "==> [milestone 3] Running Scripts/acceptance/m3-metadata-differential.py objc --only objc -> $OUT_LABEL/m3-metadata-objc.txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" objc --only objc --machgraph "$REL_BIN" | tee "$STAGE_DIR/m3-metadata-objc.txt"
                    echo "==> [milestone 3] Running Scripts/acceptance/m3-metadata-differential.py full --record -> $OUT_LABEL/m3-metadata-full-${REC_DATE}.json & .txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" full --record --json-out "$OUT_DIR/m3-metadata-full-${REC_DATE}.json" --machgraph "$REL_BIN" | tee "$STAGE_DIR/m3-metadata-full.txt"
                    cp "$STAGE_DIR/m3-metadata-full.txt" "$OUT_DIR/m3-metadata-full-${REC_DATE}.txt"
                    cp "$STAGE_DIR/m3-metadata-standard.txt" "$OUT_DIR/m3-metadata-standard.txt"
                    cp "$STAGE_DIR/m3-metadata-objc.txt" "$OUT_DIR/m3-metadata-objc.txt"
                    rm -rf "$STAGE_DIR"
                    echo "==> [milestone 3] Recorded logs under reports/"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m3-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                    echo "==> [milestone 3] Running Scripts/acceptance/m3-metadata-differential.py standard -> $OUT_LABEL/m3-metadata-standard.txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" standard --machgraph "$REL_BIN" --json-out "$OUT_DIR/m3-metadata-standard.json" | tee "$OUT_DIR/m3-metadata-standard.txt"
                    echo "==> [milestone 3] Running Scripts/acceptance/m3-metadata-differential.py objc --only objc -> $OUT_LABEL/m3-metadata-objc.txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" objc --only objc --machgraph "$REL_BIN" --json-out "$OUT_DIR/m3-metadata-objc.json" | tee "$OUT_DIR/m3-metadata-objc.txt"
                    echo "==> [milestone 3] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            4|m4|M4)
                echo "==> [milestone 4] Scoped unit tests for M4-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachHeadlessCLI
                echo "==> [milestone 4] Acceptance harness unit tests"
                python3 -I "$ROOT_DIR/Scripts/acceptance/test_m4_harnesses.py"
                echo "==> [milestone 4] Building release MachGraph CLI binary"
                swift build -c release --product MachGraph >/dev/null
                REL_BIN="$ROOT_DIR/.build/release/MachGraph"
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                    echo "==> [milestone 4] Running Scripts/acceptance/m4-cfg-acceptance.py standard --record -> $OUT_LABEL/m4-cfg-acceptance.json & .txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" standard --record --machgraph "$REL_BIN"
                    echo "==> [milestone 4] Recorded logs under reports/"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m4-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                    echo "==> [milestone 4] Running Scripts/acceptance/m4-cfg-acceptance.py standard -> $OUT_LABEL/m4-cfg-acceptance.json & .txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" standard --machgraph "$REL_BIN" --json-out "$OUT_DIR/m4-cfg-acceptance.json" --txt-out "$OUT_DIR/m4-cfg-acceptance.txt"
                    echo "==> [milestone 4] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            5|m5|M5)
                echo "==> [milestone 5] Scoped unit tests for M5-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachMicroDecompiler \
                    MachHeadlessCLI
                echo "==> [milestone 5] Acceptance harness unit tests"
                python3 -I "$ROOT_DIR/Scripts/acceptance/test_m5_harnesses.py"
                echo "==> [milestone 5] Building release MachGraph CLI binary"
                swift build -c release --product MachGraph >/dev/null
                REL_BIN="$ROOT_DIR/.build/release/MachGraph"
                if [ "$RECORD" -eq 1 ]; then
                    OUT_DIR="$ROOT_DIR/reports"
                    OUT_LABEL="reports"
                    mkdir -p "$OUT_DIR"
                    echo "==> [milestone 5] Running Scripts/acceptance/m5-mcp-acceptance.py (protocol, tools, legacy, perf) --record -> $OUT_LABEL/"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" protocol --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-protocol.txt" --json-out "$OUT_DIR/m5-mcp-protocol.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" tools --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-tools.txt" --json-out "$OUT_DIR/m5-mcp-tools.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" legacy --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-legacy.txt" --json-out "$OUT_DIR/m5-mcp-legacy.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" perf --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-perf.txt" --json-out "$OUT_DIR/m5-mcp-perf.json"
                    echo "==> [milestone 5] Running Scripts/acceptance/m5-lib-examples.py -> $OUT_LABEL/m5-lib-examples.json & .txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-lib-examples.py" --json-out "$OUT_DIR/m5-lib-examples.json" --txt-out "$OUT_DIR/m5-lib-examples.txt"
                    echo "==> [milestone 5] Recorded logs under reports/"
                else
                    OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m5-logs.XXXXXX")"
                    OUT_LABEL="$OUT_DIR"
                    echo "==> [milestone 5] Running Scripts/acceptance/m5-mcp-acceptance.py (protocol, tools, legacy, perf) -> $OUT_LABEL/"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" protocol --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-protocol.txt" --json-out "$OUT_DIR/m5-mcp-protocol.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" tools --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-tools.txt" --json-out "$OUT_DIR/m5-mcp-tools.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" legacy --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-legacy.txt" --json-out "$OUT_DIR/m5-mcp-legacy.json"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" perf --machgraph "$REL_BIN" --txt-out "$OUT_DIR/m5-mcp-perf.txt" --json-out "$OUT_DIR/m5-mcp-perf.json"
                    echo "==> [milestone 5] Running Scripts/acceptance/m5-lib-examples.py -> $OUT_LABEL/m5-lib-examples.json & .txt"
                    python3 -I "$ROOT_DIR/Scripts/acceptance/m5-lib-examples.py" --json-out "$OUT_DIR/m5-lib-examples.json" --txt-out "$OUT_DIR/m5-lib-examples.txt"
                    echo "==> [milestone 5] Logs kept in $OUT_DIR (work tree untouched; pass --record to refresh reports/)"
                fi
                ;;
            *)
                echo "Error: unsupported milestone '$MS' (supported: 0, 1, 2, 3, 4, 5)." >&2
                exit 2
                ;;
        esac
        ;;
    mutations)
        echo "==> [mutations] Running Scripts/acceptance/m3-mutations.sh"
        "$ROOT_DIR/Scripts/acceptance/m3-mutations.sh"
        echo "==> [mutations] Running Scripts/acceptance/m4-mutations.sh"
        "$ROOT_DIR/Scripts/acceptance/m4-mutations.sh"
        ;;
    release)
        echo "==> [release] Full unit test suite"
        swift test --no-parallel
        echo "==> [release] Building debug and release MachGraph CLI binaries"
        swift build --product MachGraph >/dev/null
        swift build -c release --product MachGraph >/dev/null
        REL_BIN="$ROOT_DIR/.build/release/MachGraph"
        if [ -x "$ROOT_DIR/Scripts/acceptance/m0-quick.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/m0-quick.sh"
            "$ROOT_DIR/Scripts/acceptance/m0-quick.sh"
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/readme-commands.sh"
            "$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/test_differential_harnesses.py" ]; then
            echo "==> [release] Running Scripts/acceptance/test_differential_harnesses.py"
            python3 "$ROOT_DIR/Scripts/acceptance/test_differential_harnesses.py"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/test_m3_harnesses.py" ]; then
            echo "==> [release] Running Scripts/acceptance/test_m3_harnesses.py"
            python3 -I "$ROOT_DIR/Scripts/acceptance/test_m3_harnesses.py"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/test_m4_harnesses.py" ]; then
            echo "==> [release] Running Scripts/acceptance/test_m4_harnesses.py"
            python3 -I "$ROOT_DIR/Scripts/acceptance/test_m4_harnesses.py"
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/differential.py" ]; then
            echo "==> [release] Running Scripts/acceptance/differential.py standard"
            python3 "$ROOT_DIR/Scripts/acceptance/differential.py" standard --machgraph "$REL_BIN"
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/macho-differential.py" ]; then
            echo "==> [release] Running Scripts/acceptance/macho-differential.py standard"
            python3 "$ROOT_DIR/Scripts/acceptance/macho-differential.py" standard --machgraph "$REL_BIN"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" ]; then
            echo "==> [release] Running Scripts/acceptance/m3-metadata-differential.py standard"
            python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" standard --machgraph "$REL_BIN"
            echo "==> [release] Running Scripts/acceptance/m3-metadata-differential.py objc --only objc"
            python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" objc --only objc --machgraph "$REL_BIN"
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/m3-mutations.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/m3-mutations.sh"
            "$ROOT_DIR/Scripts/acceptance/m3-mutations.sh"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" ]; then
            echo "==> [release] Running Scripts/acceptance/m4-cfg-acceptance.py standard"
            python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" standard --machgraph "$REL_BIN"
        fi
        if [ -f "$ROOT_DIR/Scripts/acceptance/m4-ghidra-differential.py" ]; then
            echo "==> [release] Running Scripts/acceptance/m4-ghidra-differential.py /bin/ls"
            gh_rc=0
            python3 -I "$ROOT_DIR/Scripts/acceptance/m4-ghidra-differential.py" /bin/ls --machgraph "$REL_BIN" || gh_rc=$?
            if [ "$gh_rc" -eq 77 ]; then
                echo "SKIPPED (m4-ghidra-differential.py: 已跳过、不算通过)"
            elif [ "$gh_rc" -ne 0 ]; then
                exit "$gh_rc"
            fi
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/m4-mutations.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/m4-mutations.sh"
            "$ROOT_DIR/Scripts/acceptance/m4-mutations.sh"
        fi
        if [ "${MACHGRAPH_CORPUS:-}" = "full" ]; then
            echo "==> [release] Running Scripts/acceptance/differential.py full"
            python3 "$ROOT_DIR/Scripts/acceptance/differential.py" full --machgraph "$REL_BIN"
            echo "==> [release] Running Scripts/acceptance/macho-differential.py full"
            python3 "$ROOT_DIR/Scripts/acceptance/macho-differential.py" full --machgraph "$REL_BIN"
            if [ -f "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" ]; then
                echo "==> [release] Running Scripts/acceptance/m3-metadata-differential.py full"
                python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" full --machgraph "$REL_BIN"
            fi
            if [ -f "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" ]; then
                echo "==> [release] Running Scripts/acceptance/m4-cfg-acceptance.py full"
                python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" full --machgraph "$REL_BIN"
            fi
        else
            echo "SKIPPED (MACHGRAPH_CORPUS!=full)"
        fi
        ;;
    *)
        usage
        ;;
esac
