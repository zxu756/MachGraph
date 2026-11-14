#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <ModuleOrFilter...>
  Scripts/test.sh milestone <N> [--record]
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
            *)
                echo "Error: unsupported milestone '$MS' (only milestone 0 is implemented on m0/honest)." >&2
                exit 2
                ;;
        esac
        ;;
    release)
        echo "==> [release] Full unit test suite"
        swift test --no-parallel
        echo "==> [release] Building MachGraph CLI binary"
        swift build --product MachGraph >/dev/null
        if [ -x "$ROOT_DIR/Scripts/acceptance/m0-quick.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/m0-quick.sh"
            "$ROOT_DIR/Scripts/acceptance/m0-quick.sh"
        fi
        if [ -x "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" ]; then
            echo "==> [release] Running Scripts/acceptance/readme-commands.sh"
            "$ROOT_DIR/Scripts/acceptance/readme-commands.sh"
        fi
        if [ "${MACHGRAPH_CORPUS:-}" = "full" ]; then
            if [ -x "$ROOT_DIR/Scripts/acceptance/differential.py" ]; then
                python3 "$ROOT_DIR/Scripts/acceptance/differential.py" full
            else
                echo "SKIPPED (differential.py full belongs to M1; not yet implemented in M0)"
            fi
        else
            echo "SKIPPED (MACHGRAPH_CORPUS!=full)"
        fi
        ;;
    *)
        usage
        ;;
esac
