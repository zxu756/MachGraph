#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

START_NS="$(python3 -c 'import time; print(time.time_ns())')"

BIN="${MACHGRAPH_BIN:-${REPO_ROOT}/.build/debug/MachGraph}"
if [[ ! -x "${BIN}" ]]; then
    swift build --product MachGraph >/dev/null
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/machgraph-m0-quick.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Every product invocation runs with a throwaway HOME so the acceptance run cannot read or write the
# user's real preferences. `mg` is the only way this script starts the binary from bash; the Python
# rows receive the same environment through MACHGRAPH_ISOLATED_HOME.
export MACHGRAPH_ISOLATED_HOME="${TMP_DIR}/home"
mkdir -p "${MACHGRAPH_ISOLATED_HOME}"
mg() {
    HOME="${MACHGRAPH_ISOLATED_HOME}" CFFIXED_USER_HOME="${MACHGRAPH_ISOLATED_HOME}" "${BIN}" "$@"
}

echo "=== MachGraph M0 Quick Acceptance ==="
echo "Date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "macOS:      $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo "Binary:     ${BIN#"${REPO_ROOT}/"}"
echo ""

# ------------------------------------------------------------------------------
# Row 1: machgraph info /bin/ls --json vs otool -arch arm64e -l /bin/ls
# ------------------------------------------------------------------------------
mg info /bin/ls --json > "${TMP_DIR}/ls.info.json"
python3 - "${TMP_DIR}/ls.info.json" <<'PY'
import json, re, subprocess, sys

info_path = sys.argv[1]
with open(info_path, "r", encoding="utf-8") as fh:
    mg = json.load(fh)

assert mg.get("fileName") == "ls", f"expected fileName=='ls', got {mg.get('fileName')!r}"
assert mg.get("isDemo") is False, "expected isDemo==False"

otool_out = subprocess.run(
    ["otool", "-arch", "arm64e", "-l", "/bin/ls"],
    capture_output=True,
    text=True,
    check=True,
).stdout

ref_segs = []
ref_secs = []
for blk in otool_out.split("Load command ")[1:]:
    if "cmd LC_SEGMENT_64" in blk:
        seg_name = re.search(r"segname (\S+)", blk).group(1)
        vmaddr = int(re.search(r"\svmaddr (\S+)", blk).group(1), 16)
        vmsize = int(re.search(r"\svmsize (\S+)", blk).group(1), 16)
        fileoff = int(re.search(r"\sfileoff (\d+)", blk).group(1), 10)
        filesize = int(re.search(r"\sfilesize (\d+)", blk).group(1), 10)
        ref_segs.append((seg_name, vmaddr, vmsize, fileoff, filesize))
        for sblk in re.split(r"Section\n", blk)[1:]:
            s_seg = re.search(r"segname (\S+)", sblk).group(1)
            s_sec = re.search(r"sectname (\S+)", sblk).group(1)
            s_addr = int(re.search(r"addr (\S+)", sblk).group(1), 16)
            s_size = int(re.search(r"size (\S+)", sblk).group(1), 16)
            s_off = int(re.search(r"offset (\d+)", sblk).group(1), 10)
            ref_secs.append((s_seg, s_sec, s_addr, s_size, s_off))

mg_segs = [
    (s["name"], int(s["vmaddr"]), int(s["vmsize"]), int(s["fileoff"]), int(s["filesize"]))
    for s in mg["segments"]
]
mg_secs = [
    (s["segment"], s["section"], int(s["addr"]), int(s["size"]), int(s["offset"]))
    for s in mg["sections"]
]

assert mg_segs == ref_segs, f"segment mismatch:\n  mg={mg_segs}\n  otool={ref_segs}"
assert mg_secs == ref_secs, f"section mismatch:\n  mg={mg_secs}\n  otool={ref_secs}"
print(f"[PASS] Row 1: info /bin/ls --json matches otool -arch arm64e -l ({len(mg_segs)} segments, {len(mg_secs)} sections, fileName=ls)")
PY

# ------------------------------------------------------------------------------
# Row 2: machgraph disasm /bin/ls vs xcrun llvm-objdump -d --arch=arm64e /bin/ls
# ------------------------------------------------------------------------------
# Normalization rules live in mnemonic-agreement.py (movz/movn -> mov, udf -> .inst, vector suffix dropped).
python3 "${REPO_ROOT}/Scripts/acceptance/mnemonic-agreement.py" /bin/ls \
    --arch arm64e --machgraph "${BIN}" --min-agreement 99.9 --max-wrong 0 \
    --label "Row 2: disasm /bin/ls vs llvm-objdump"

# ------------------------------------------------------------------------------
# Helper for exit-code + empty-stdout + localized-stderr checks
# ------------------------------------------------------------------------------
check_cli_failure() {
    local expected_rc="$1"
    local expect_zh="$2"
    shift 2
    local out_file="${TMP_DIR}/cmd.out"
    local err_file="${TMP_DIR}/cmd.err"
    set +e
    mg "$@" >"${out_file}" 2>"${err_file}"
    local rc=$?
    set -e
    if [[ "${expected_rc}" == "nonzero" ]]; then
        if [[ "${rc}" -eq 0 ]]; then
            echo "[FAIL] Expected non-zero exit for: ${BIN} $*" >&2
            exit 1
        fi
    else
        if [[ "${rc}" -ne "${expected_rc}" ]]; then
            echo "[FAIL] Expected exit ${expected_rc}, got ${rc} for: ${BIN} $*" >&2
            cat "${err_file}" >&2
            exit 1
        fi
    fi
    if [[ -s "${out_file}" ]]; then
        echo "[FAIL] Expected empty stdout on failure for: ${BIN} $*" >&2
        head -n 5 "${out_file}" >&2
        exit 1
    fi
    if [[ ! -s "${err_file}" ]]; then
        echo "[FAIL] Expected non-empty stderr on failure for: ${BIN} $*" >&2
        exit 1
    fi
    if [[ "${expect_zh}" == "zh" ]]; then
        python3 - "${err_file}" <<'PY'
import re, sys
txt = open(sys.argv[1], "r", encoding="utf-8").read()
assert re.search(r"[\u4e00-\u9fff]", txt), f"expected Chinese error message, got: {txt!r}"
PY
    fi
}

# ------------------------------------------------------------------------------
# Row 3: machgraph info / disasm without file -> exit code 2 (EN + ZH)
# ------------------------------------------------------------------------------
check_cli_failure 2 en info --lang en
check_cli_failure 2 zh info --lang zh
check_cli_failure 2 en disasm --lang en
check_cli_failure 2 zh disasm --lang zh
echo "[PASS] Row 3: info and disasm without file exit 2 with empty stdout (EN + ZH)"

# ------------------------------------------------------------------------------
# Row 4: machgraph disasm /bin/ls --nosuchoption -> exit code 2 (EN + ZH)
# ------------------------------------------------------------------------------
check_cli_failure 2 en disasm /bin/ls --nosuchoption --lang en
check_cli_failure 2 zh disasm /bin/ls --nosuchoption --lang zh
echo "[PASS] Row 4: disasm /bin/ls --nosuchoption exits 2 with empty stdout (EN + ZH)"

# ------------------------------------------------------------------------------
# Row 5: missing --function in disasm & decompile -> non-zero, zero stdout (EN + ZH)
#        + experimental line-1 warning on decompile (EN + ZH)
# ------------------------------------------------------------------------------
check_cli_failure nonzero en disasm /bin/ls --function nosuchfunction --lang en
check_cli_failure nonzero zh disasm /bin/ls --function nosuchfunction --lang zh
check_cli_failure nonzero en decompile /bin/ls --function nosuchfunction --lang en
check_cli_failure nonzero zh decompile /bin/ls --function nosuchfunction --lang zh

DECOMP_EN_LINE1="$(mg decompile --demo --function demo_fnv1a32 --lang en | head -n 1)"
DECOMP_ZH_LINE1="$(mg decompile --demo --function demo_fnv1a32 --lang zh | head -n 1)"
if [[ "${DECOMP_EN_LINE1}" != "// EXPERIMENTAL:"* ]]; then
    echo "[FAIL] Expected English experimental banner on line 1, got: ${DECOMP_EN_LINE1}" >&2
    exit 1
fi
if [[ "${DECOMP_ZH_LINE1}" != "// 【实验性】"* ]]; then
    echo "[FAIL] Expected Chinese experimental banner on line 1, got: ${DECOMP_ZH_LINE1}" >&2
    exit 1
fi
echo "[PASS] Row 5: missing function exits non-zero with empty stdout; decompile emits line-1 warning (EN + ZH)"

# ------------------------------------------------------------------------------
# Row 6: Every subcommand listed in --help runs on /usr/bin/true without Unknown subcommand or GUI
# ------------------------------------------------------------------------------
python3 - "${BIN}" <<'PY'
import os, subprocess, sys

bin_path = sys.argv[1]
home = os.environ["MACHGRAPH_ISOLATED_HOME"]
env = dict(os.environ, HOME=home, CFFIXED_USER_HOME=home)

def extract_subcommands(lang, header_prefix):
    out = subprocess.run([bin_path, "--help", "--lang", lang], capture_output=True, text=True, check=True, env=env).stdout
    in_sub = False
    cmds = []
    for line in out.splitlines():
        if line.startswith(header_prefix):
            in_sub = True
            continue
        if in_sub:
            if not line.startswith("  "):
                break
            tok = line.strip().split()[0]
            cmds.append(tok)
    return cmds

cmds_en = extract_subcommands("en", "Subcommands:")
cmds_zh = extract_subcommands("zh", "子命令:")
assert len(cmds_en) >= 15, f"too few subcommands in EN --help: {cmds_en}"
assert cmds_en == cmds_zh, f"EN/ZH subcommand list mismatch: {cmds_en} vs {cmds_zh}"

for cmd in cmds_en:
    proc = subprocess.run(
        [bin_path, cmd, "/usr/bin/true"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5.0,
        env=env,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    assert "Unknown subcommand" not in combined and "未知子命令" not in combined, (
        f"Subcommand {cmd!r} reported unknown subcommand: {combined}"
    )

print(f"[PASS] Row 6: all {len(cmds_en)} subcommands in --help (EN + ZH) route headlessly on /usr/bin/true")
PY

# ------------------------------------------------------------------------------
# Row 7: MCP mach_inspect_binary without binaryPath -> isError:true
# ------------------------------------------------------------------------------
python3 - "${BIN}" <<'PY'
import json, os, subprocess, sys

bin_path = sys.argv[1]
home = os.environ["MACHGRAPH_ISOLATED_HOME"]
env = dict(os.environ, HOME=home, CFFIXED_USER_HOME=home)
payload = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{}}}\n'
)
proc = subprocess.run(
    [bin_path, "mcp"],
    input=payload,
    capture_output=True,
    text=True,
    timeout=5.0,
    check=True,
    env=env,
)
lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
assert len(lines) >= 2, f"expected >=2 JSON-RPC responses, got: {proc.stdout!r}"
resp = json.loads(lines[-1])
assert resp.get("result", {}).get("isError") is True, f"expected isError:true, got: {resp}"
print("[PASS] Row 7: MCP mach_inspect_binary without binaryPath returns isError:true")
PY

# ------------------------------------------------------------------------------
# Row 8: machgraph disasm /usr/bin/ssh has zero lines from __info_plist
# ------------------------------------------------------------------------------
mg disasm /usr/bin/ssh > "${TMP_DIR}/ssh.disasm.txt"
python3 - "${TMP_DIR}/ssh.disasm.txt" <<'PY'
import re, subprocess, sys

disasm_path = sys.argv[1]
otool_ssh = subprocess.run(
    ["otool", "-arch", "arm64e", "-l", "/usr/bin/ssh"],
    capture_output=True,
    text=True,
    check=True,
).stdout

plist_range = None
for sblk in re.split(r"Section\n", otool_ssh)[1:]:
    m_sec = re.search(r"sectname (\S+)", sblk)
    if m_sec and m_sec.group(1) == "__info_plist":
        addr = int(re.search(r"addr (\S+)", sblk).group(1), 16)
        size = int(re.search(r"size (\S+)", sblk).group(1), 16)
        plist_range = (addr, addr + size)
        break

insn_count = 0
with open(disasm_path, "r", encoding="utf-8") as fh:
    for line in fh:
        assert "__info_plist" not in line, f"unexpected __info_plist line: {line}"
        if line.startswith("0x"):
            addr = int(line.split("\t", 1)[0], 16)
            insn_count += 1
            if plist_range is not None:
                assert not (plist_range[0] <= addr < plist_range[1]), (
                    f"decoded non-instruction byte in __info_plist at 0x{addr:x}"
                )

assert insn_count > 100000, f"expected >100k ssh instructions, got {insn_count}"
print(f"[PASS] Row 8: disasm /usr/bin/ssh decoded {insn_count} instructions with 0 lines from __info_plist")
PY

# ------------------------------------------------------------------------------
# Row 9: /dev/null, plain text, truncated /bin/ls (8000 & 30000 B), and ELF ET_REL -> non-zero & zero stdout
# ------------------------------------------------------------------------------
: > "${TMP_DIR}/empty_0b.bin"
printf 'This is plain UTF-8 text, not a Mach-O binary.\n' > "${TMP_DIR}/plain.txt"
head -c 8000 /bin/ls > "${TMP_DIR}/ls_trunc_8000"
head -c 30000 /bin/ls > "${TMP_DIR}/ls_trunc_30000"
printf 'int add(int a,int b){return a+b;}\n' > "${TMP_DIR}/etrel.c"
xcrun clang --target=aarch64-unknown-linux-gnu -ffreestanding -c "${TMP_DIR}/etrel.c" -o "${TMP_DIR}/etrel.o"

for bad_input in /dev/null "${TMP_DIR}/empty_0b.bin" "${TMP_DIR}/plain.txt" "${TMP_DIR}/ls_trunc_8000" "${TMP_DIR}/ls_trunc_30000" "${TMP_DIR}/etrel.o"; do
    check_cli_failure nonzero en disasm "${bad_input}" --lang en
    check_cli_failure nonzero zh disasm "${bad_input}" --lang zh
done
echo "[PASS] Row 9: /dev/null, 0-byte file, plain text, truncated /bin/ls (8000/30000 B), and ELF ET_REL rejected with empty stdout (EN + ZH)"

# ------------------------------------------------------------------------------
# Row 10: Semicolon-separated 4-instruction program assembles all 4 words (16 bytes)
# ------------------------------------------------------------------------------
cp "${REPO_ROOT}/Fixtures/demo_arm64_sample" "${TMP_DIR}/demo_copy"
DEMO_ENTRY_HEX="$(mg info "${TMP_DIR}/demo_copy" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["entryPointHex"])')"
PATCH_JSON="$(mg patch-asm "${TMP_DIR}/demo_copy" --address "${DEMO_ENTRY_HEX}" --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" --force --output "${TMP_DIR}/demo_patched" --json)"
python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["byteCount"] == 16, f"expected 16 bytes (4 words), got {d}"
assert d["valid"] is True, f"expected valid re-signed Mach-O, got {d}"
' "${PATCH_JSON}"
echo "[PASS] Row 10: semicolon-separated 4-statement A64 program assembled all 4 words (16 bytes)"

# ------------------------------------------------------------------------------
# Row 11: GUI default startup loads zero binary (verified via @MainActor ViewModel test)
# ------------------------------------------------------------------------------
# One test-runner start covers Row 11 and Row 15 (both are windowless unit tests; no app is launched).
swift test --no-parallel --skip-build \
    --filter 'studioViewModelStartsEmptyOnDefaultLaunch|desktopLaunchResolutionRejectsMistypedSubcommands' \
    > "${TMP_DIR}/unit-rows.txt" 2>&1 || {
    tail -n 40 "${TMP_DIR}/unit-rows.txt" >&2
    echo "[FAIL] Row 11 / Row 15 unit tests failed" >&2
    exit 1
}
grep -q 'Test run with 2 tests .* passed' "${TMP_DIR}/unit-rows.txt" || {
    tail -n 40 "${TMP_DIR}/unit-rows.txt" >&2
    echo "[FAIL] Row 11 / Row 15: expected exactly 2 unit tests to run and pass" >&2
    exit 1
}
echo "[PASS] Row 11: MachStudioViewModel default startup loads zero binary unless file or Load Demo is requested"

# ------------------------------------------------------------------------------
# Row 12: Zero matches for SyntheticAuthDemo, Synthesized, synthesizeFallback, MACHGRAPH-PRO in Sources/
# ------------------------------------------------------------------------------
python3 - "${REPO_ROOT}" <<'PY'
import os, re, sys

root = sys.argv[1]
pattern = re.compile(r"SyntheticAuthDemo|Synthesized|synthesizeFallback|MACHGRAPH-PRO")
hits = []

scan_targets = [
    os.path.join(root, "Sources"),
    os.path.join(root, "README.md"),
    os.path.join(root, "README.zh-CN.md"),
    os.path.join(root, "docs", "demo-mach-triage.html"),
]

for target in scan_targets:
    if os.path.isfile(target):
        txt = open(target, "r", encoding="utf-8", errors="replace").read()
        for idx, line in enumerate(txt.splitlines(), 1):
            if pattern.search(line):
                hits.append(f"{os.path.relpath(target, root)}:{idx}: {line.strip()}")
    elif os.path.isdir(target):
        for dirpath, _, filenames in os.walk(target):
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                txt = open(full, "r", encoding="utf-8", errors="replace").read()
                for idx, line in enumerate(txt.splitlines(), 1):
                    if pattern.search(line):
                        hits.append(f"{os.path.relpath(full, root)}:{idx}: {line.strip()}")

assert not hits, "Forbidden synthetic strings found:\n  " + "\n  ".join(hits)
print("[PASS] Row 12: 0 matches for SyntheticAuthDemo/Synthesized/synthesizeFallback/MACHGRAPH-PRO in Sources/, README*, docs/")
PY

# ==============================================================================
# Rework rows (flagship-acceptance/06-m0-review.md): G27, G28, G30
# ==============================================================================

# ------------------------------------------------------------------------------
# Row 13 (G27): patch-asm rejects an unassemblable statement after ';' and writes no file
# ------------------------------------------------------------------------------
"${REPO_ROOT}/Scripts/acceptance/patch-bad-stmt.sh" "${BIN}" > "${TMP_DIR}/patch-bad-stmt.txt" || {
    cat "${TMP_DIR}/patch-bad-stmt.txt" >&2
    echo "[FAIL] Row 13: patch-asm accepted an unassemblable statement after ';'" >&2
    exit 1
}
if [[ "$(grep -c '^ok:' "${TMP_DIR}/patch-bad-stmt.txt")" -ne 3 ]]; then
    cat "${TMP_DIR}/patch-bad-stmt.txt" >&2
    echo "[FAIL] Row 13: expected 3 ok lines from patch-bad-stmt.sh" >&2
    exit 1
fi
echo "[PASS] Row 13 (G27): patch-asm exits non-zero and writes no file for 3 inputs with an unassemblable statement after ';'"

# ------------------------------------------------------------------------------
# Row 14 (G28): a truncated thin (single-architecture) arm64 Mach-O is an error with exit code 1, never a crash
# ------------------------------------------------------------------------------
THIN_SIZE="$(wc -c < "${REPO_ROOT}/Fixtures/demo_arm64_sample" | tr -d ' ')"
THIN_CUTS=""
for cut in 200 1200 8000 "$((THIN_SIZE / 2))" 20000 "$((THIN_SIZE - 400))" "$((THIN_SIZE - 1))"; do
    head -c "${cut}" "${REPO_ROOT}/Fixtures/demo_arm64_sample" > "${TMP_DIR}/thin_trunc_${cut}"
    for sub in info disasm; do
        check_cli_failure 1 en "${sub}" "${TMP_DIR}/thin_trunc_${cut}" --lang en
        check_cli_failure 1 zh "${sub}" "${TMP_DIR}/thin_trunc_${cut}" --lang zh
    done
    THIN_CUTS="${THIN_CUTS} ${cut}"
done
echo "[PASS] Row 14 (G28): thin arm64 Mach-O (${THIN_SIZE} B) truncated to${THIN_CUTS} B: info and disasm exit 1 with empty stdout (EN + ZH)"

# ------------------------------------------------------------------------------
# Row 15 (G30): a mistyped subcommand is a usage error naming the subcommand.
# Verified through the launch-resolution unit test only: an acceptance script must never start the
# binary with arguments that are not a known subcommand, because that path leads to the desktop app.
# ------------------------------------------------------------------------------
# (The unit test itself ran together with Row 11 above.)
grep -q 'mistyped subcommand.*passed' "${TMP_DIR}/unit-rows.txt" || {
    echo "[FAIL] Row 15: the G30 launch-resolution unit test did not report a pass" >&2
    exit 1
}
echo "[PASS] Row 15 (G30): launch resolution reports a mistyped subcommand as 'Unknown subcommand' (usage error, exit code 2) in EN + ZH"

END_NS="$(python3 -c 'import time; print(time.time_ns())')"
ELAPSED_S="$(python3 -c "print(f'{(${END_NS} - ${START_NS}) / 1e9:.2f}')")"

echo ""
if python3 -c "import sys; sys.exit(0 if float('${ELAPSED_S}') > 10.0 else 1)"; then
    echo "[WARN] m0-quick.sh elapsed ${ELAPSED_S}s (> 10.00s reference budget); exit status depends only on functional checks"
    echo "=== ALL 12 M0 ACCEPTANCE CHECKS AND 3 REWORK CHECKS PASSED in ${ELAPSED_S}s (> 10.00s reference budget; [WARN] only) ==="
else
    echo "=== ALL 12 M0 ACCEPTANCE CHECKS AND 3 REWORK CHECKS PASSED in ${ELAPSED_S}s (<= 10.00s reference budget) ==="
fi
