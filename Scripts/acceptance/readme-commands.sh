#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x ".build/debug/MachGraph" ]]; then
    swift build --product MachGraph >/dev/null
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-readme-cmds.XXXXXX")"
cleanup() {
    rm -rf "${TMP_DIR}"
    rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched /tmp/machgraph_ls_triage.html
}
trap cleanup EXIT

echo "=== MachGraph README Commands Replay (EN + ZH) ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "macOS:      $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo ""

# 1. Verify README.md and README.zh-CN.md contain identical .build/debug/MachGraph command blocks
python3 - <<'PY'
import re

def extract_mg_blocks(path):
    txt = open(path, "r", encoding="utf-8").read()
    blocks = re.findall(r"```bash\n(.*?)```", txt, flags=re.S)
    mg_cmds = []
    for blk in blocks:
        lines = []
        buf = ""
        for raw in blk.splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if s.endswith("\\"):
                buf += s[:-1].strip() + " "
            else:
                buf += s
                lines.append(" ".join(buf.split()))
                buf = ""
        if any("MachGraph" in ln and "swift build" not in ln for ln in lines):
            mg_cmds.extend(lines)
    return mg_cmds

en_cmds = extract_mg_blocks("README.md")
zh_cmds = extract_mg_blocks("README.zh-CN.md")
assert len(en_cmds) >= 14, f"Expected >=14 CLI lines in README.md, got {len(en_cmds)}"
assert en_cmds == zh_cmds, f"README.md vs README.zh-CN.md CLI example drift:\nEN={en_cmds}\nZH={zh_cmds}"
print(f"[PASS] Parity check: {len(en_cmds)} verbatim CLI commands match between README.md and README.zh-CN.md")
PY

# 2. Replay every command verbatim and verify honest, real outputs

echo "$ .build/debug/MachGraph info /bin/ls"
.build/debug/MachGraph info /bin/ls > "${TMP_DIR}/info.txt"
grep -q "File:          ls" "${TMP_DIR}/info.txt"
grep -q "Segments:      5 (11 sections)" "${TMP_DIR}/info.txt"
echo "  -> OK (ls, 5 segments, 11 sections)"

echo "$ .build/debug/MachGraph info /bin/ls --json"
.build/debug/MachGraph info /bin/ls --json > "${TMP_DIR}/info.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["fileName"]=="ls" and d["isDemo"] is False' "${TMP_DIR}/info.json"
echo "  -> OK (JSON fileName=ls, isDemo=false)"

echo "$ .build/debug/MachGraph segments /bin/ls"
.build/debug/MachGraph segments /bin/ls > "${TMP_DIR}/segments.txt"
grep -q "__TEXT" "${TMP_DIR}/segments.txt"
grep -q "__LINKEDIT" "${TMP_DIR}/segments.txt"
echo "  -> OK (__TEXT .. __LINKEDIT)"

echo "$ .build/debug/MachGraph fixups /bin/ls --json"
.build/debug/MachGraph fixups /bin/ls --json > "${TMP_DIR}/fixups.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["fileName"]=="ls" and d["count"]>0' "${TMP_DIR}/fixups.json"
echo "  -> OK (fixups JSON parsed)"

echo "$ .build/debug/MachGraph symbols /bin/ls"
.build/debug/MachGraph symbols /bin/ls > "${TMP_DIR}/symbols.txt"
grep -q "# Symtab Symbols" "${TMP_DIR}/symbols.txt"
grep -q "# Inferred Entries" "${TMP_DIR}/symbols.txt"
echo "  -> OK (symtab & [inferred:...] separated)"

echo "$ .build/debug/MachGraph codesign /bin/ls"
.build/debug/MachGraph codesign /bin/ls > "${TMP_DIR}/codesign.txt"
grep -q "Signed=true" "${TMP_DIR}/codesign.txt"
grep -q "Identifier=com.apple.ls" "${TMP_DIR}/codesign.txt"
echo "  -> OK (Signed=true Identifier=com.apple.ls)"

echo "$ .build/debug/MachGraph disasm /bin/ls --symbol entry --count 12"
.build/debug/MachGraph disasm /bin/ls --symbol entry --count 12 > "${TMP_DIR}/disasm_ls.txt"
python3 -c '
import sys
lines = [ln for ln in open(sys.argv[1]) if ln.strip().startswith("0x")]
assert len(lines) == 12, f"expected 12 instructions, got {len(lines)}"
' "${TMP_DIR}/disasm_ls.txt"
echo "  -> OK (12 ARM64e instructions decoded from /bin/ls entry)"

echo "$ .build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10"
.build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10 > "${TMP_DIR}/disasm_fixture.txt"
grep -q "0x0000000100000460" "${TMP_DIR}/disasm_fixture.txt"
echo "  -> OK (10 ARM64 instructions decoded at 0x100000460)"

echo "$ cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample && .build/debug/MachGraph patch-asm ..."
cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample
.build/debug/MachGraph patch-asm /tmp/machgraph_readme_sample \
  --address 0x100000460 \
  --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" \
  --force \
  --output /tmp/machgraph_readme_patched \
  --json > "${TMP_DIR}/patch.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["byteCount"]==16 and d["valid"] is True' "${TMP_DIR}/patch.json"
codesign --verify --strict /tmp/machgraph_readme_patched
rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched
echo "  -> OK (16 bytes assembled, valid=true, codesign --verify --strict passed)"

echo "$ .build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html"
.build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html > "${TMP_DIR}/export.txt"
grep -q "<!DOCTYPE html>" /tmp/machgraph_ls_triage.html
grep -q "中文" /tmp/machgraph_ls_triage.html
rm -f /tmp/machgraph_ls_triage.html
echo "  -> OK (standalone bilingual HTML triage report generated)"

echo "$ .build/debug/MachGraph --help --lang zh"
.build/debug/MachGraph --help --lang zh > "${TMP_DIR}/help_zh.txt"
grep -q "子命令:" "${TMP_DIR}/help_zh.txt"
echo "  -> OK (Simplified Chinese --help verified)"

echo "$ .build/debug/MachGraph info --demo --lang zh"
.build/debug/MachGraph info --demo --lang zh > "${TMP_DIR}/demo_zh.txt"
grep -q "\[演示数据\]" "${TMP_DIR}/demo_zh.txt"
echo "  -> OK (explicit --demo emits [演示数据] banner)"

echo "$ printf '{...mach_inspect_binary /bin/ls...}' | .build/debug/MachGraph mcp"
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/bin/ls"}}}\n' \
  | .build/debug/MachGraph mcp > "${TMP_DIR}/mcp.out"
python3 -c '
import json, sys
lines = [ln for ln in open(sys.argv[1]) if ln.strip()]
resp = json.loads(lines[-1])
assert resp["result"]["isError"] is False, resp
assert "file=ls" in resp["result"]["content"][0]["text"], resp
' "${TMP_DIR}/mcp.out"
echo "  -> OK (MCP mach_inspect_binary returned real /bin/ls payload with isError=false)"

echo ""
echo "=== ALL README COMMANDS PASSED (EN + ZH) ==="
