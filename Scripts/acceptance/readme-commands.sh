#!/usr/bin/env bash
# Replays the CLI examples that README.md and README.zh-CN.md actually contain.
# The commands are read from the READMEs at run time by readme_commands.py; none are copied here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x ".build/debug/MachGraph" ]]; then
    swift build --product MachGraph >/dev/null
fi

echo "=== MachGraph README Commands Replay (README.md + README.zh-CN.md) ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "macOS:      $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo ""

exec python3 "${REPO_ROOT}/Scripts/acceptance/readme_commands.py"
