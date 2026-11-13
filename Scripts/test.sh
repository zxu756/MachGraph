#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <ModuleOrFilter...>
  Scripts/test.sh milestone <N>
  Scripts/test.sh release
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
        if [ "$#" -ne 1 ]; then
            usage
        fi
        MS="$1"
        case "$MS" in
            0|m0|M0)
                echo "==> [milestone 0] Scoped unit tests for M0-touched modules"
                run_scope \
                    MachGraphModels \
                    MachBinaryFormats \
                    MachA64Decoder \
                    MachCFGEngine \
                    MachMicroDecompiler \
                    MachPluginSDK \
                    MachHeadlessCLI \
                    MachStudioViews
                echo "==> [milestone 0] Building MachGraph CLI binary"
                swift build --product MachGraph >/dev/null
                mkdir -p "$ROOT_DIR/reports"
                echo "==> [milestone 0] Running Scripts/acceptance/m0-quick.sh -> reports/m0-quick.txt"
                "$ROOT_DIR/Scripts/acceptance/m0-quick.sh" | tee "$ROOT_DIR/reports/m0-quick.txt"
                echo "==> [milestone 0] Running Scripts/acceptance/readme-commands.sh -> reports/readme-commands.txt"
                "$ROOT_DIR/Scripts/acceptance/readme-commands.sh" | tee "$ROOT_DIR/reports/readme-commands.txt"
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
