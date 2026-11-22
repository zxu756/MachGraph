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
  Scripts/test.sh release [--only <step>[,<step>...]] [--list-steps]

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
        echo "==> [mutations] Running Scripts/acceptance/m5-mutations.sh"
        "$ROOT_DIR/Scripts/acceptance/m5-mutations.sh"
        ;;
    release)
        RELEASE_STEP_SPECS=(
            "swift-test|always|swift test --no-parallel"
            "build-debug|always|swift build --product MachGraph"
            "build-release|always|swift build -c release --product MachGraph"
            "m0-quick|always|Scripts/acceptance/m0-quick.sh"
            "readme-commands|always|Scripts/acceptance/readme-commands.sh"
            "test-differential-harnesses|always|python3 -I Scripts/acceptance/test_differential_harnesses.py"
            "test-asm-harnesses|always|python3 -I Scripts/acceptance/test_asm_harnesses.py"
            "test-m3-harnesses|always|python3 -I Scripts/acceptance/test_m3_harnesses.py"
            "test-m4-harnesses|always|python3 -I Scripts/acceptance/test_m4_harnesses.py"
            "test-m5-harnesses|always|python3 -I Scripts/acceptance/test_m5_harnesses.py"
            "differential-standard|always|python3 -I Scripts/acceptance/differential.py standard --machgraph .build/release/MachGraph"
            "macho-differential-standard|always|python3 -I Scripts/acceptance/macho-differential.py standard --machgraph .build/release/MachGraph"
            "encoding-table|always|python3 -I Scripts/acceptance/encoding-table.py check --all --machgraph .build/release/MachGraph"
            "encoding-fuzz-20261117|always|python3 -I Scripts/acceptance/encoding-fuzz.py --seed 20261117 --count 100000 --machgraph .build/release/MachGraph"
            "encoding-fuzz-17|always|python3 -I Scripts/acceptance/encoding-fuzz.py --seed 17 --count 100000 --machgraph .build/release/MachGraph"
            "asm-roundtrip-standard|always|python3 -I Scripts/acceptance/asm-roundtrip.py standard --machgraph .build/release/MachGraph"
            "asm-clang-standard|always|python3 -I Scripts/acceptance/asm-clang.py standard --machgraph .build/release/MachGraph"
            "asm-clang-cases|always|python3 -I Scripts/acceptance/asm-clang.py Fixtures/asm-cases.s --machgraph .build/release/MachGraph"
            "known-mnemonics|always|python3 -I Scripts/acceptance/known-mnemonics.py check"
            "m3-metadata-standard|always|python3 -I Scripts/acceptance/m3-metadata-differential.py standard --machgraph .build/release/MachGraph"
            "m3-metadata-objc|always|python3 -I Scripts/acceptance/m3-metadata-differential.py objc --only objc --machgraph .build/release/MachGraph"
            "m3-mutations|always|Scripts/acceptance/m3-mutations.sh"
            "m4-cfg-standard|always|python3 -I Scripts/acceptance/m4-cfg-acceptance.py standard --machgraph .build/release/MachGraph"
            "m4-ghidra|ghidra|python3 -I Scripts/acceptance/m4-ghidra-differential.py /bin/ls --machgraph .build/release/MachGraph"
            "m4-mutations|always|Scripts/acceptance/m4-mutations.sh"
            "m5-mcp-protocol|always|python3 -I Scripts/acceptance/m5-mcp-acceptance.py protocol --machgraph .build/release/MachGraph"
            "m5-mcp-tools|always|python3 -I Scripts/acceptance/m5-mcp-acceptance.py tools --machgraph .build/release/MachGraph"
            "m5-mcp-legacy|always|python3 -I Scripts/acceptance/m5-mcp-acceptance.py legacy --machgraph .build/release/MachGraph"
            "m5-mcp-perf|always|python3 -I Scripts/acceptance/m5-mcp-acceptance.py perf --machgraph .build/release/MachGraph"
            "m5-lib-examples|always|python3 -I Scripts/acceptance/m5-lib-examples.py"
            "m5-mutations|always|Scripts/acceptance/m5-mutations.sh"
            "differential-full|corpus_full|python3 -I Scripts/acceptance/differential.py full --machgraph .build/release/MachGraph"
            "macho-differential-full|corpus_full|python3 -I Scripts/acceptance/macho-differential.py full --machgraph .build/release/MachGraph"
            "m3-metadata-full|corpus_full|python3 -I Scripts/acceptance/m3-metadata-differential.py full --machgraph .build/release/MachGraph"
            "m4-cfg-full|corpus_full|python3 -I Scripts/acceptance/m4-cfg-acceptance.py full --machgraph .build/release/MachGraph"
        )

        find_release_spec() {
            local target="$1"
            local entry
            for entry in "${RELEASE_STEP_SPECS[@]}"; do
                local sid="${entry%%|*}"
                if [ "$sid" = "$target" ]; then
                    echo "$entry"
                    return 0
                fi
            done
            return 1
        }

        LIST_STEPS=0
        ONLY_ARGS=()
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --list-steps)
                    LIST_STEPS=1
                    shift
                    ;;
                --only)
                    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                        echo "Error: --only requires a non-empty comma-separated step list." >&2
                        exit 2
                    fi
                    ONLY_ARGS+=("$2")
                    shift 2
                    ;;
                --only=*)
                    val="${1#--only=}"
                    if [ -z "$val" ]; then
                        echo "Error: --only requires a non-empty comma-separated step list." >&2
                        exit 2
                    fi
                    ONLY_ARGS+=("$val")
                    shift
                    ;;
                *)
                    echo "Error: unsupported release argument '$1'." >&2
                    usage
                    ;;
            esac
        done

        if [ "$LIST_STEPS" -eq 1 ]; then
            for entry in "${RELEASE_STEP_SPECS[@]}"; do
                sid="${entry%%|*}"
                rest="${entry#*|}"
                sgate="${rest%%|*}"
                sdesc="${rest#*|}"
                printf "%s\t%s\t%s\n" "$sid" "$sgate" "$sdesc"
            done
            exit 0
        fi

        SELECTED_STEPS=()
        if [ "${#ONLY_ARGS[@]}" -gt 0 ]; then
            for raw_csv in "${ONLY_ARGS[@]}"; do
                OLD_IFS="$IFS"
                IFS=','
                for tok in $raw_csv; do
                    IFS="$OLD_IFS"
                    tok="$(printf "%s" "$tok" | tr -d '[:space:]')"
                    if [ -z "$tok" ]; then
                        continue
                    fi
                    if ! find_release_spec "$tok" >/dev/null; then
                        echo "Error: unknown release step '$tok' (run 'Scripts/test.sh release --list-steps' to inspect valid step names)." >&2
                        exit 2
                    fi
                    already=0
                    if [ "${#SELECTED_STEPS[@]}" -gt 0 ]; then
                        for ex_s in "${SELECTED_STEPS[@]}"; do
                            if [ "$ex_s" = "$tok" ]; then
                                already=1
                                break
                            fi
                        done
                    fi
                    if [ "$already" -eq 0 ]; then
                        SELECTED_STEPS+=("$tok")
                    fi
                done
                IFS="$OLD_IFS"
            done
            if [ "${#SELECTED_STEPS[@]}" -eq 0 ]; then
                echo "Error: --only resolved to zero steps." >&2
                exit 2
            fi
        else
            for entry in "${RELEASE_STEP_SPECS[@]}"; do
                SELECTED_STEPS+=("${entry%%|*}")
            done
        fi

        # Default MACHGRAPH_CORPUS to 'full' in release mode when unset or empty.
        RELEASE_CORPUS="${MACHGRAPH_CORPUS:-full}"
        export MACHGRAPH_CORPUS="$RELEASE_CORPUS"
        REL_BIN="$ROOT_DIR/.build/release/MachGraph"

        build_debug_quiet() {
            swift build --product MachGraph >/dev/null
        }
        build_release_quiet() {
            swift build -c release --product MachGraph >/dev/null
        }

        exec_release_cmd() {
            local step_id="$1"
            shift
            if [ -n "${MACHGRAPH_RELEASE_STUB_SCRIPT:-}" ]; then
                "$MACHGRAPH_RELEASE_STUB_SCRIPT" "$step_id" "$@"
            else
                "$@"
            fi
        }

        dispatch_release_step_cmd() {
            local step_id="$1"
            case "$step_id" in
                swift-test)
                    exec_release_cmd "$step_id" swift test --no-parallel
                    ;;
                build-debug)
                    exec_release_cmd "$step_id" build_debug_quiet
                    ;;
                build-release)
                    exec_release_cmd "$step_id" build_release_quiet
                    ;;
                m0-quick)
                    exec_release_cmd "$step_id" "$ROOT_DIR/Scripts/acceptance/m0-quick.sh"
                    ;;
                readme-commands)
                    exec_release_cmd "$step_id" "$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
                    ;;
                test-differential-harnesses)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/test_differential_harnesses.py"
                    ;;
                test-asm-harnesses)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/test_asm_harnesses.py"
                    ;;
                test-m3-harnesses)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/test_m3_harnesses.py"
                    ;;
                test-m4-harnesses)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/test_m4_harnesses.py"
                    ;;
                test-m5-harnesses)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/test_m5_harnesses.py"
                    ;;
                differential-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/differential.py" standard --machgraph "$REL_BIN"
                    ;;
                macho-differential-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/macho-differential.py" standard --machgraph "$REL_BIN"
                    ;;
                encoding-table)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-table.py" check --all --machgraph "$REL_BIN"
                    ;;
                encoding-fuzz-20261117)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-fuzz.py" --seed 20261117 --count 100000 --machgraph "$REL_BIN"
                    ;;
                encoding-fuzz-17)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/encoding-fuzz.py" --seed 17 --count 100000 --machgraph "$REL_BIN"
                    ;;
                asm-roundtrip-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/asm-roundtrip.py" standard --machgraph "$REL_BIN"
                    ;;
                asm-clang-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/asm-clang.py" standard --machgraph "$REL_BIN"
                    ;;
                asm-clang-cases)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/asm-clang.py" "Fixtures/asm-cases.s" --machgraph "$REL_BIN"
                    ;;
                known-mnemonics)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/known-mnemonics.py" check
                    ;;
                m3-metadata-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" standard --machgraph "$REL_BIN"
                    ;;
                m3-metadata-objc)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" objc --only objc --machgraph "$REL_BIN"
                    ;;
                m3-mutations)
                    exec_release_cmd "$step_id" "$ROOT_DIR/Scripts/acceptance/m3-mutations.sh"
                    ;;
                m4-cfg-standard)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" standard --machgraph "$REL_BIN"
                    ;;
                m4-ghidra)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m4-ghidra-differential.py" /bin/ls --machgraph "$REL_BIN"
                    ;;
                m4-mutations)
                    exec_release_cmd "$step_id" "$ROOT_DIR/Scripts/acceptance/m4-mutations.sh"
                    ;;
                m5-mcp-protocol)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" protocol --machgraph "$REL_BIN"
                    ;;
                m5-mcp-tools)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" tools --machgraph "$REL_BIN"
                    ;;
                m5-mcp-legacy)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" legacy --machgraph "$REL_BIN"
                    ;;
                m5-mcp-perf)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m5-mcp-acceptance.py" perf --machgraph "$REL_BIN"
                    ;;
                m5-lib-examples)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m5-lib-examples.py"
                    ;;
                m5-mutations)
                    exec_release_cmd "$step_id" "$ROOT_DIR/Scripts/acceptance/m5-mutations.sh"
                    ;;
                differential-full)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/differential.py" full --machgraph "$REL_BIN"
                    ;;
                macho-differential-full)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/macho-differential.py" full --machgraph "$REL_BIN"
                    ;;
                m3-metadata-full)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m3-metadata-differential.py" full --machgraph "$REL_BIN"
                    ;;
                m4-cfg-full)
                    exec_release_cmd "$step_id" python3 -I "$ROOT_DIR/Scripts/acceptance/m4-cfg-acceptance.py" full --machgraph "$REL_BIN"
                    ;;
                *)
                    echo "Internal error: unhandled release step '$step_id'." >&2
                    return 2
                    ;;
            esac
        }

        STEP_IDS=()
        STEP_STATUSES=()
        STEP_RCS=()
        STEP_ELAPSED=()
        SKIPPED_STEPS=()
        FAILED_STEPS=()
        FIRST_FAIL_RC=0
        SUITE_T0="$(python3 -I -c 'import time; print(f"{time.time():.6f}")')"

        for step_id in "${SELECTED_STEPS[@]}"; do
            spec_entry="$(find_release_spec "$step_id")"
            rest="${spec_entry#*|}"
            sgate="${rest%%|*}"
            sdesc="${rest#*|}"

            echo "==> [release:$step_id] $sdesc"
            t0="$(python3 -I -c 'import time; print(f"{time.time():.6f}")')"
            rc=0
            if [ "$sgate" = "corpus_full" ] && [ "$RELEASE_CORPUS" != "full" ]; then
                echo "[SKIPPED] $step_id: 已跳过、不算通过 (MACHGRAPH_CORPUS=$RELEASE_CORPUS != full)"
                rc=77
            else
                set +e
                dispatch_release_step_cmd "$step_id"
                rc=$?
                set -e
                if [ "$rc" -eq 77 ]; then
                    echo "[SKIPPED] $step_id: 已跳过、不算通过 (exit 77)"
                fi
            fi
            t1="$(python3 -I -c 'import time; print(f"{time.time():.6f}")')"
            elapsed="$(python3 -I -c "print(f'{max(0.0, $t1 - $t0):.3f}')")"

            STEP_IDS+=("$step_id")
            STEP_RCS+=("$rc")
            STEP_ELAPSED+=("$elapsed")
            if [ "$rc" -eq 0 ]; then
                STEP_STATUSES+=("PASS")
            elif [ "$rc" -eq 77 ]; then
                STEP_STATUSES+=("SKIPPED")
                SKIPPED_STEPS+=("$step_id")
            else
                STEP_STATUSES+=("FAIL")
                FAILED_STEPS+=("$step_id")
                if [ "$FIRST_FAIL_RC" -eq 0 ]; then
                    FIRST_FAIL_RC="$rc"
                fi
            fi
        done

        SUITE_T1="$(python3 -I -c 'import time; print(f"{time.time():.6f}")')"
        TOTAL_ELAPSED="$(python3 -I -c "print(f'{max(0.0, $SUITE_T1 - $SUITE_T0):.3f}')")"

        echo ""
        echo "=== Release Step Summary (MACHGRAPH_CORPUS=$RELEASE_CORPUS) ==="
        printf "%-28s %-9s %5s %11s\n" "Step" "Status" "Exit" "Elapsed(s)"
        printf "%-28s %-9s %5s %11s\n" "----------------------------" "---------" "-----" "-----------"
        idx=0
        while [ "$idx" -lt "${#STEP_IDS[@]}" ]; do
            printf "%-28s %-9s %5d %11s\n" \
                "${STEP_IDS[$idx]}" \
                "${STEP_STATUSES[$idx]}" \
                "${STEP_RCS[$idx]}" \
                "${STEP_ELAPSED[$idx]}"
            idx=$((idx + 1))
        done
        printf "%-28s %-9s %5s %11s\n" "----------------------------" "---------" "-----" "-----------"
        echo "Total steps: ${#STEP_IDS[@]} | passed: $(( ${#STEP_IDS[@]} - ${#SKIPPED_STEPS[@]} - ${#FAILED_STEPS[@]} )) | skipped: ${#SKIPPED_STEPS[@]} | failed: ${#FAILED_STEPS[@]} | elapsed: ${TOTAL_ELAPSED}s"

        if [ "${#SKIPPED_STEPS[@]}" -gt 0 ]; then
            echo "[SKIPPED] Skipped step(s) (已跳过、不算通过): ${SKIPPED_STEPS[*]}"
        fi

        if [ "${#FAILED_STEPS[@]}" -gt 0 ]; then
            echo "[FAIL] Failed step(s): ${FAILED_STEPS[*]}" >&2
            if [ "$FIRST_FAIL_RC" -eq 0 ] || [ "$FIRST_FAIL_RC" -eq 77 ]; then
                exit 1
            fi
            exit "$FIRST_FAIL_RC"
        fi

        if [ "${#SKIPPED_STEPS[@]}" -gt 0 ]; then
            echo "[SKIPPED] Release did not run all required checks — exiting 77 (已跳过、不算通过)." >&2
            exit 77
        fi

        echo "[PASS] All ${#STEP_IDS[@]} release step(s) passed (exit 0)."
        ;;
    *)
        usage
        ;;
esac
