#!/usr/bin/env python3
"""Replay the CLI examples that README.md and README.zh-CN.md actually contain.

The commands are read from the fenced ```bash blocks of both READMEs at run time; nothing is copied into
this script. Editing a README example therefore changes what runs here.

Checks, in order:
  1. Both READMEs contain the same commands in the same order (comments may differ per language).
  2. Every MachGraph option used in either README (in a command or as an inline `--option` span)
     is listed in `--help`, in English and in Chinese.
  3. Every expectation below still belongs to a command that the README contains (no stale entries).
  4. No README command would open the desktop app: the first argument after the binary must be a
     subcommand listed in `--help` (or --help / --version). Such a command is refused, not executed.
  5. Each example command exits 0 when executed verbatim from the repository root; commands with a
     registered expectation also have their output checked against the real input.

Blocks that only contain build / test entry points (`swift build`, `./Scripts/...`) are not replayed,
because this script is itself one of them; the referenced script files are checked for existence instead.
"""

import atexit
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
READMES = ["README.md", "README.zh-CN.md"]
BIN = ".build/debug/MachGraph"
HELPER_PROGRAMS = {"cp", "rm", "printf"}
META_TOKENS = {"--help", "-h", "help", "--version", "version"}
OPTION_RE = re.compile(r"(?<![\w-])--[A-Za-z][A-Za-z0-9-]*")
RUN_ENV = None


def fail(message: str) -> None:
    print(f"[FAIL] {message}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------------------------------
# README parsing
# ---------------------------------------------------------------------------------------------------

def read(name: str) -> str:
    with open(os.path.join(REPO_ROOT, name), "r", encoding="utf-8") as fh:
        return fh.read()


def command_blocks(text: str) -> list:
    """Each ```bash block as a list of commands: comments and blank lines dropped, `\\` continuations joined."""
    blocks = []
    for body in re.findall(r"```bash\n(.*?)```", text, flags=re.S):
        commands, pending = [], ""
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("\\"):
                pending += line[:-1].strip() + " "
            else:
                commands.append(" ".join((pending + line).split()))
                pending = ""
        if pending:
            commands.append(" ".join(pending.split()))
        if commands:
            blocks.append(commands)
    return blocks


def simple_commands(command: str) -> list:
    """Split one shell line into simple commands (argv lists) at |, &&, ||, ;. Redirections are not allowed."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    parts, current = [], []
    for token in lexer:
        if token in ("|", "&&", "||", ";"):
            parts.append(current)
            current = []
        elif token and set(token) <= set("<>&|;()"):
            fail(f"README command uses shell operator {token!r}, which this replay does not allow: {command}")
        else:
            current.append(token)
    parts.append(current)
    return [p for p in parts if p]


def machgraph_options(text: str) -> set:
    used = set()
    parts = text.split("```")
    for idx, part in enumerate(parts):
        if idx % 2 == 1:  # fenced block: options that follow the MachGraph binary on a command line
            for line in part.replace("\\\n", " ").splitlines():
                if BIN + " " in line:
                    used.update(OPTION_RE.findall(line.split(BIN + " ", 1)[1]))
        else:  # prose: inline code spans that are themselves an option, e.g. `--count` or `--lang en|zh`
            for span_idx, span in enumerate(part.split("`")):
                if span_idx % 2 == 1 and span.startswith("--"):
                    used.update(OPTION_RE.findall(span.split()[0]))
    return used


# ---------------------------------------------------------------------------------------------------
# Output expectations for commands that README contains (keyed by the command exactly as written there)
# ---------------------------------------------------------------------------------------------------

def instruction_lines(out: str) -> list:
    return [ln for ln in out.splitlines() if ln.strip().startswith("0x")]


def expect_info_text(out):
    assert "File:          ls" in out, out[:200]
    assert "Segments:      5 (11 sections)" in out, out[:400]
    return "ls, 5 segments, 11 sections"


def expect_info_json(out):
    doc = json.loads(out)
    assert doc["fileName"] == "ls" and doc["isDemo"] is False, doc
    return "JSON fileName=ls, isDemo=false"


def expect_segments(out):
    assert "__TEXT" in out and "__LINKEDIT" in out, out[:200]
    return "__TEXT .. __LINKEDIT"


def expect_fixups_json(out):
    doc = json.loads(out)
    assert doc["fileName"] == "ls" and doc["count"] > 0, {k: doc[k] for k in ("fileName", "count")}
    return f"{doc['count']} fixups"


def expect_symbols(out):
    assert "# Symtab Symbols" in out and "# Inferred Entries" in out, out[:200]
    return "symtab and [inferred:...] listed separately"


def expect_codesign(out):
    assert "Signed=true" in out and "Identifier=com.apple.ls" in out, out[:200]
    return "Signed=true Identifier=com.apple.ls"


def expect_disasm_ls(out):
    count = len(instruction_lines(out))
    assert count == 12, f"expected 12 instructions, got {count}"
    return "12 instructions from the /bin/ls entry function"


def expect_disasm_fixture(out):
    lines = instruction_lines(out)
    assert len(lines) == 10, f"expected 10 instructions, got {len(lines)}"
    assert "0x0000000100000460" in out, out[:200]
    return "10 instructions starting at 0x100000460"


def expect_cfg_ls_json(out):
    doc = json.loads(out)
    assert doc["schema"] == "machgraph.cfg/1", doc.get("schema")
    assert doc["fileName"] == "ls" and doc["isDemo"] is False, doc["fileName"]
    assert len(doc["lcFunctionStarts"]) == 50, len(doc["lcFunctionStarts"])
    assert len(doc["inlineJumpTableStarts"]) == 1 and len(doc["inlineJumpTableRanges"]) == 1
    assert doc["functionCount"] == 133 and len(doc["functions"]) == 133, doc["functionCount"]
    total_blocks = sum(len(fn["blocks"]) for fn in doc["functions"])
    total_edges = sum(len(fn["edges"]) for fn in doc["functions"])
    assert total_blocks == 871 and total_edges == 1110, (total_blocks, total_edges)
    return "schema=machgraph.cfg/1, 133 functions (50 LC_FUNCTION_STARTS, 1 inline jump table), 871 blocks, 1110 edges"


def expect_cfg_ls_symbol_json(out):
    doc = json.loads(out)
    assert doc["schema"] == "machgraph.cfg/1" and doc["functionCount"] == 1 and len(doc["functions"]) == 1
    fn = doc["functions"][0]
    assert fn["name"] == "_entry" and len(fn["blocks"]) == 154 and len(fn["edges"]) == 259, fn["name"]
    assert len(fn["dominatorTree"]) == 154 and fn["dominatorTree"][0]["immediateDominatorID"] is None
    assert len(fn["naturalLoops"]) == 1 and len(fn["jumpTables"]) == 1 and len(fn["inlineJumpTableRanges"]) == 1
    missing = subprocess.run(
        [BIN, "cfg", "/bin/ls", "--symbol", "__nosuch_symbol_m4__", "--json"],
        cwd=REPO_ROOT,
        env=RUN_ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert missing.returncode == 1, f"expected exit 1 on missing --symbol, got {missing.returncode}"
    assert missing.stdout == "", f"expected empty stdout on missing --symbol, got {missing.stdout[:200]!r}"
    assert missing.stderr.strip(), "expected non-empty stderr on missing --symbol"
    return "schema=machgraph.cfg/1, _entry: 154 blocks, 259 edges, 1 loop, 1 jump table; missing --symbol exits 1 with empty stdout"


def expect_cfg_dot_ls_symbol(out):
    assert out.startswith('digraph "entry" {') and "b0 -> " in out, out[:200]
    return 'Graphviz DOT for _entry (digraph "entry")'


def expect_patch(out):
    doc = json.loads(out)
    assert doc["byteCount"] == 16 and doc["valid"] is True, doc
    subprocess.run(["codesign", "--verify", "--strict", doc["outputPath"]], check=True)
    return "16 bytes assembled, valid=true, codesign --verify --strict passed"


def expect_asm(out):
    doc = json.loads(out)
    assert doc["at"] == "0x100000460", doc
    assert doc["summary"] == {"ok": 3, "unsupported": 0, "error": 0}, doc["summary"]
    results = doc["results"]
    assert [r["status"] for r in results] == ["ok", "ok", "ok"], results
    assert [r["word"] for r in results] == ["a9bf7bfd", "d2800540", "14000002"], results
    assert [r["address"] for r in results] == ["0x100000460", "0x100000464", "0x100000468"], results
    return "3 ok words: a9bf7bfd, d2800540, 14000002 @ 0x100000460..0x100000468"


def expect_export_html(out):
    with open("/tmp/machgraph_ls_triage.html", "r", encoding="utf-8") as fh:
        html = fh.read()
    assert "<!DOCTYPE html>" in html and "中文" in html
    with open("/bin/ls", "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    assert digest in html, "the report does not contain the SHA-256 of /bin/ls"
    return f"{len(html)} bytes of HTML containing the SHA-256 of /bin/ls"


def expect_help_zh(out):
    assert "子命令:" in out and "子命令选项:" in out, out[:200]
    return "Chinese help"


def expect_demo_zh(out):
    assert "[演示数据]" in out, out[:200]
    return "[演示数据] banner present"


def expect_mcp(out):
    lines = [ln for ln in out.splitlines() if ln.strip()]
    resp = json.loads(lines[-1])
    assert resp["result"]["isError"] is False, resp
    assert "file=ls" in resp["result"]["content"][0]["text"], resp
    return "mach_inspect_binary returned the /bin/ls summary, isError=false"


MCP_COMMAND = (
    "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\\n"
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"mach_inspect_binary\","
    "\"arguments\":{\"binaryPath\":\"/bin/ls\"}}}\\n' | .build/debug/MachGraph mcp"
)

EXPECTATIONS = {
    f"{BIN} info /bin/ls": expect_info_text,
    f"{BIN} info /bin/ls --json": expect_info_json,
    f"{BIN} segments /bin/ls": expect_segments,
    f"{BIN} fixups /bin/ls --json": expect_fixups_json,
    f"{BIN} symbols /bin/ls": expect_symbols,
    f"{BIN} codesign /bin/ls": expect_codesign,
    f"{BIN} disasm /bin/ls --symbol entry --count 12": expect_disasm_ls,
    f"{BIN} disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10": expect_disasm_fixture,
    f"{BIN} cfg /bin/ls --json": expect_cfg_ls_json,
    f"{BIN} cfg /bin/ls --symbol _entry --json": expect_cfg_ls_symbol_json,
    f"{BIN} cfg-dot /bin/ls --symbol _entry": expect_cfg_dot_ls_symbol,
    (
        f"{BIN} patch-asm /tmp/machgraph_readme_sample --address 0x100000460 "
        "--asm \"pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab\" "
        "--force --output /tmp/machgraph_readme_patched --json"
    ): expect_patch,
    (
        f"{BIN} asm --at 0x100000460 "
        "--asm \"stp x29, x30, [sp, #-16]!; mov x0, #42; b .+8\" --json"
    ): expect_asm,
    f"{BIN} export-html /bin/ls --output /tmp/machgraph_ls_triage.html": expect_export_html,
    f"{BIN} --help --lang zh": expect_help_zh,
    f"{BIN} info --demo --lang zh": expect_demo_zh,
    MCP_COMMAND: expect_mcp,
}


# ---------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------

def main() -> int:
    os.chdir(REPO_ROOT)
    if not os.access(BIN, os.X_OK):
        fail(f"{BIN} is missing; build it first (swift build --product MachGraph)")

    # Product commands run with a throwaway HOME (removed on exit) so they cannot touch real preferences.
    home = tempfile.mkdtemp(prefix="machgraph-readme-home.")
    atexit.register(shutil.rmtree, home, ignore_errors=True)
    env = dict(os.environ, HOME=home, CFFIXED_USER_HOME=home)
    global RUN_ENV
    RUN_ENV = env

    def help_text(lang: str) -> str:
        return subprocess.run([BIN, "--help", "--lang", lang], capture_output=True, text=True, check=True, env=env).stdout

    help_en, help_zh = help_text("en"), help_text("zh")
    subcommands = set()
    in_section = False
    for line in help_en.splitlines():
        if line.startswith("Subcommands:"):
            in_section = True
        elif in_section and line.startswith("  "):
            subcommands.add(line.split()[0])
        elif in_section:
            break
    if len(subcommands) < 10:
        fail(f"could not read the subcommand list from --help: {sorted(subcommands)}")

    # 1. Same commands in both READMEs
    texts = {name: read(name) for name in READMES}
    blocks = {name: command_blocks(text) for name, text in texts.items()}
    if blocks[READMES[0]] != blocks[READMES[1]]:
        en = [c for b in blocks[READMES[0]] for c in b]
        zh = [c for b in blocks[READMES[1]] for c in b]
        only_en = [c for c in en if c not in zh]
        only_zh = [c for c in zh if c not in en]
        fail(
            "README.md and README.zh-CN.md do not contain the same commands in the same order.\n"
            f"  only in README.md: {only_en}\n  only in README.zh-CN.md: {only_zh}"
        )
    all_blocks = blocks[READMES[0]]
    example_blocks = [b for b in all_blocks if any(BIN in c for c in b)]
    other_blocks = [b for b in all_blocks if b not in example_blocks]
    example_commands = [c for b in example_blocks for c in b]
    cli_count = sum(1 for c in example_commands if BIN in c)
    if cli_count < 10:
        fail(f"expected the READMEs to contain at least 10 MachGraph example commands, found {cli_count}")
    print(f"[PASS] README.md and README.zh-CN.md contain the same {sum(len(b) for b in all_blocks)} commands "
          f"({cli_count} MachGraph invocations)")

    # 2. Every option used in a README is listed in --help (EN + ZH)
    for name, text in texts.items():
        used = machgraph_options(text)
        if len(used) < 8:
            fail(f"{name}: found only {sorted(used)} as documented options; the option scan is broken")
        missing = sorted(o for o in used if o not in help_en or o not in help_zh)
        if missing:
            fail(f"{name} uses option(s) that --help does not list: {missing}")
        print(f"[PASS] {name}: all {len(used)} MachGraph options it uses are listed in --help (en + zh): {' '.join(sorted(used))}")

    # 3. No stale expectations
    stale = [cmd for cmd in EXPECTATIONS if cmd not in example_commands]
    if stale:
        fail("this script still has output expectations for commands the README no longer contains:\n  " + "\n  ".join(stale))

    # 4. Refuse anything that is not a known headless invocation (it could open the desktop app)
    for command in example_commands:
        for argv in simple_commands(command):
            program, args = argv[0], argv[1:]
            if program == BIN:
                rest = list(args)
                while rest and (rest[0] == "--lang" or rest[0].startswith("--lang=")):
                    rest = rest[2:] if rest[0] == "--lang" else rest[1:]
                first = rest[0] if rest else None
                if first not in subcommands and first not in META_TOKENS:
                    fail(
                        f"README command would not run a headless subcommand (first argument {first!r}) and could "
                        f"open the desktop app, so it was not executed: {command}"
                    )
            elif program not in HELPER_PROGRAMS:
                fail(f"README example uses program {program!r}, which this replay does not run: {command}")
    print(f"[PASS] every MachGraph example starts with a subcommand listed in --help; none can open the desktop app")

    # 5. Execute verbatim
    try:
        for command in example_commands:
            print(f"$ {command}")
            proc = subprocess.run(
                ["bash", "-c", command],
                cwd=REPO_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                fail(f"exit {proc.returncode}: {command}\n{proc.stderr.strip()[:600]}")
            note = "exit 0"
            if command in EXPECTATIONS:
                try:
                    note = EXPECTATIONS[command](proc.stdout)
                except Exception as exc:  # noqa: BLE001 - report any failed expectation with its command
                    fail(f"unexpected output from: {command}\n  {type(exc).__name__}: {exc}")
            elif BIN in command:
                if not proc.stdout.strip():
                    fail(f"no output from: {command}")
                if " --json" in command:
                    json.loads(proc.stdout)
                    note = "exit 0, valid JSON (no specific expectation registered)"
                else:
                    note = "exit 0, non-empty output (no specific expectation registered)"
            print(f"  -> OK ({note})")
    finally:
        for leftover in ("/tmp/machgraph_readme_sample", "/tmp/machgraph_readme_patched", "/tmp/machgraph_ls_triage.html"):
            try:
                os.remove(leftover)
            except FileNotFoundError:
                pass

    # Build / test entry points: not replayed (this script is one of them); check that they exist.
    for block in other_blocks:
        for command in block:
            argv = shlex.split(command)
            if argv[0].startswith("./Scripts/"):
                path = os.path.join(REPO_ROOT, argv[0][2:])
                if not os.access(path, os.X_OK):
                    fail(f"README refers to {argv[0]}, which is missing or not executable")
                print(f"[NOT REPLAYED] {command}  (build/test entry point; {argv[0]} exists and is executable)")
            elif argv[:2] == ["swift", "build"]:
                print(f"[NOT REPLAYED] {command}  (build entry point)")
            else:
                fail(f"README contains a command this replay does not know how to treat: {command}")

    print("")
    print(f"=== ALL {len(example_commands)} README EXAMPLE COMMANDS PASSED (README.md + README.zh-CN.md) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
