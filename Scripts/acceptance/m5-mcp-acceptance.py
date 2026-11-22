#!/usr/bin/env python3
"""MCP server acceptance suite for MachGraph M5 (Stage 1: protocol, tools, legacy, perf).

Usage:
  Scripts/acceptance/m5-mcp-acceptance.py [<protocol|tools|legacy|perf|all|standard>]
      [--only <check,...>] [--machgraph <path>] [--json-out <path>] [--txt-out <path>]
      [--record] [--verbose]

Subcommands / checks:
  - protocol:
      Verifies MCP JSON-RPC 2.0 handshake (`initialize`), silent `notifications/initialized`,
      `tools/list` exposing the exact 8 tools with complete `inputSchema` definitions and
      bilingual experimental/unverified descriptions, `-32700` on malformed JSON, `-32601`
      on unknown methods, and `isError: true` with non-empty diagnostic text across missing
      parameters, missing files, `/dev/null`, unknown tools, missing `mach_cfg` selector,
      stripped `_main` on `/bin/ls`, and invalid addresses.
  - tools:
      Independently computes `LC_MAIN` entry addresses for `/bin/ls` and `/usr/bin/ssh`
      from `xcrun otool -arch <slice> -l` (without reading MachGraph output), confirms
      `/bin/ls` has no `_main` via `xcrun nm`, and verifies strict byte-for-byte equality
      between MCP `result.content[0].text` and CLI `machgraph <subcmd> ... --json` stdout
      across `mach_disasm_function`, `mach_list_symbols`, `mach_cfg`, and `mach_find_strings`.
  - legacy:
      Verifies `mach_inspect_binary` `cdhash` against `codesign -dvvv`, verifies
      `mach_query_xrefs` emits both incoming (`<-`) and outgoing (`->`) cross-references,
      and verifies `mach_decompile_function` and `mach_audit_security` emit bilingual
      (`--lang en` and `--lang zh`) experimental + unverified line-1 banners (with
      `mach_audit_security` matching CLI `audit-plugins` text output rather than raw JSON).
  - perf:
      Records 3-run median wall-clock latencies (and `uptime` before/after) for the 4 new
      tools on `/usr/bin/ssh` and `/usr/bin/vim`, failing only on tool errors or >30s hangs.
"""

import argparse
import datetime
import json
import os
import re
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

AVAILABLE_CHECKS: Tuple[str, ...] = ("protocol", "tools", "legacy", "perf")

EXPECTED_MCP_TOOLS: Dict[str, Dict[str, Any]] = {
    "mach_inspect_binary": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "slice"},
        "unverified": False,
    },
    "mach_list_symbols": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "filter", "slice"},
        "unverified": False,
    },
    "mach_find_strings": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "filter", "slice"},
        "unverified": False,
    },
    "mach_disasm_function": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "symbol", "address", "count", "slice"},
        "unverified": False,
    },
    "mach_cfg": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "symbol", "address", "slice"},
        "unverified": False,
    },
    "mach_query_xrefs": {
        "required": ["binaryPath", "address"],
        "properties": {"binaryPath", "address", "slice"},
        "unverified": False,
    },
    "mach_decompile_function": {
        "required": ["binaryPath", "function"],
        "properties": {"binaryPath", "function", "slice"},
        "unverified": True,
    },
    "mach_audit_security": {
        "required": ["binaryPath"],
        "properties": {"binaryPath", "slice"},
        "unverified": True,
    },
}

PROTOCOL_ERROR_CALL_SPECS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    "missing_binary_path": ("mach_inspect_binary", {}),
    "nonexistent_path": (
        "mach_inspect_binary",
        {"binaryPath": "/nonexistent/machgraph_m5_missing_input"},
    ),
    "dev_null": ("mach_inspect_binary", {"binaryPath": "/dev/null"}),
    "unknown_tool_empty": ("mach_no_such_tool", {}),
    "unknown_tool_with_path": ("mach_no_such_tool", {"binaryPath": "/bin/ls"}),
    "cfg_missing_selector": ("mach_cfg", {"binaryPath": "/bin/ls"}),
    "cfg_conflicting_selector": (
        "mach_cfg",
        {"binaryPath": "/bin/ls", "symbol": "_entry", "address": "0x100000960"},
    ),
    "disasm_missing_selector": ("mach_disasm_function", {"binaryPath": "/bin/ls"}),
    "disasm_invalid_count": (
        "mach_disasm_function",
        {"binaryPath": "/bin/ls", "symbol": "_entry", "count": 0},
    ),
    "ls_missing_main": (
        "mach_disasm_function",
        {"binaryPath": "/bin/ls", "symbol": "_main"},
    ),
    "invalid_address_disasm": (
        "mach_disasm_function",
        {"binaryPath": "/bin/ls", "address": "0xNOT_HEX"},
    ),
    "unmapped_address_disasm": (
        "mach_disasm_function",
        {"binaryPath": "/bin/ls", "address": "0xdeadbeef0000"},
    ),
    "invalid_address_cfg": (
        "mach_cfg",
        {"binaryPath": "/bin/ls", "address": "0xNOT_HEX"},
    ),
    "invalid_address_xrefs": (
        "mach_query_xrefs",
        {"binaryPath": "/bin/ls", "address": "not_an_address"},
    ),
    "decompile_missing_function": (
        "mach_decompile_function",
        {"binaryPath": "/bin/ls"},
    ),
    "xrefs_missing_address": (
        "mach_query_xrefs",
        {"binaryPath": "/bin/ls"},
    ),
}

PERF_RUN_COUNT = 3
HANG_FAIL_SECONDS = 30.0
SUBPROCESS_TIMEOUT_SECONDS = 60.0
MAX_EXAMPLES_PER_CHECK = 8

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0x00FFFFFF

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+\x40[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_USERS_PREFIX = os.sep + "Users" + os.sep
_USERS_PATH_RE = re.compile(re.escape(_USERS_PREFIX) + r"[^/\s\"']+")


# ---------------------------------------------------------------------------
# Sanitization, Environment & Subprocess Helpers
# ---------------------------------------------------------------------------


def decode_utf8_safe(raw: Optional[bytes]) -> Tuple[str, bool]:
    if not raw:
        return ("", False)
    try:
        return (raw.decode("utf-8"), False)
    except UnicodeDecodeError:
        return (raw.decode("utf-8", errors="replace"), True)


def sanitize_display_path(path: str, repo_root: Optional[str] = None) -> str:
    root = os.path.abspath(repo_root if repo_root is not None else REPO_ROOT)
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, root)
        if rel == "." or (not rel.startswith("..") and not os.path.isabs(rel)):
            return rel
    except ValueError:
        pass
    home_dir = os.path.expanduser("~")
    if (home_dir and home_dir != "/" and abs_path.startswith(home_dir)) or abs_path.startswith(
        _USERS_PREFIX
    ):
        return os.path.basename(abs_path) or "binary"
    return abs_path


def sanitize_text(text: str) -> str:
    out = text
    home_dir = os.path.expanduser("~")
    if home_dir and home_dir != "/":
        out = out.replace(home_dir, "<home>")
    out = _USERS_PATH_RE.sub("<home>", out)
    out = _EMAIL_RE.sub("<redacted-email>", out)
    return out


def default_machgraph_bin() -> str:
    env_bin = os.environ.get("MACHGRAPH_BIN")
    if env_bin:
        return env_bin
    candidates = [
        os.path.join(REPO_ROOT, ".build", "release", "MachGraph"),
        os.path.join(REPO_ROOT, ".build", "debug", "MachGraph"),
    ]
    existing = [p for p in candidates if os.path.isfile(p) and os.access(p, os.X_OK)]
    if existing:
        existing.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return existing[0]
    return candidates[0]


def is_worktree_clean(repo_root: Optional[str] = None) -> bool:
    root = repo_root if repo_root is not None else REPO_ROOT
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        cwd=root,
    )
    if res.returncode != 0:
        return False
    return res.stdout.decode("utf-8", errors="replace").strip() == ""


def make_isolated_env(isolated_home: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = isolated_home
    env["CFFIXED_USER_HOME"] = isolated_home
    if "DEVELOPER_DIR" not in env and os.path.isdir("/Applications/Xcode.app/Contents/Developer"):
        env["DEVELOPER_DIR"] = "/Applications/Xcode.app/Contents/Developer"
    return env


def select_arm64_slice_name(path: str) -> Optional[str]:
    """Independently inspects Mach-O / Fat header bytes to pick 'arm64e' (preferred) or 'arm64'."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if len(head) < 8:
        return None
    magic_be = struct.unpack(">I", head[:4])[0]
    if magic_be in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic_be == FAT_MAGIC else "<"
        narch = struct.unpack(endian + "I", head[4:8])[0]
        found_arm64 = False
        off = 8
        for _ in range(min(narch, 32)):
            if off + 20 > len(head):
                break
            cputype, cpusubtype, _, _, _ = struct.unpack(endian + "iiIII", head[off : off + 20])
            off += 20
            if (cputype & 0xFFFFFFFF) == CPU_TYPE_ARM64:
                if (cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E:
                    return "arm64e"
                found_arm64 = True
        return "arm64" if found_arm64 else None
    if magic_be in (FAT_MAGIC_64, FAT_CIGAM_64):
        endian = ">" if magic_be == FAT_MAGIC_64 else "<"
        narch = struct.unpack(endian + "I", head[4:8])[0]
        found_arm64 = False
        off = 8
        for _ in range(min(narch, 32)):
            if off + 32 > len(head):
                break
            cputype, cpusubtype = struct.unpack(endian + "ii", head[off : off + 8])
            off += 32
            if (cputype & 0xFFFFFFFF) == CPU_TYPE_ARM64:
                if (cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E:
                    return "arm64e"
                found_arm64 = True
        return "arm64" if found_arm64 else None
    magic_le = struct.unpack("<I", head[:4])[0]
    if magic_le in (MH_MAGIC_64, MH_CIGAM_64):
        endian = "<" if magic_le == MH_MAGIC_64 else ">"
        cputype, cpusubtype = struct.unpack(endian + "ii", head[4:12])
        if (cputype & 0xFFFFFFFF) == CPU_TYPE_ARM64:
            if (cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E:
                return "arm64e"
            return "arm64"
    return None


# ---------------------------------------------------------------------------
# Independent Reference Tool Parsers (`otool -l`, `nm`, `codesign -dvvv`)
# ---------------------------------------------------------------------------


def parse_otool_lc_main_entry(otool_text: str) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Extracts (__TEXT vmaddr, LC_MAIN entryoff, computed entry VA) from `otool -l` output."""
    text_vmaddr: Optional[int] = None
    entryoff: Optional[int] = None
    lines = otool_text.splitlines()
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped == "cmd LC_SEGMENT_64":
            segname: Optional[str] = None
            vmaddr: Optional[int] = None
            j = idx + 1
            while (
                j < len(lines)
                and not lines[j].strip().startswith("Load command")
                and not lines[j].strip().startswith("Section")
            ):
                tok = lines[j].strip()
                if tok.startswith("segname "):
                    parts = tok.split()
                    if len(parts) >= 2:
                        segname = parts[1]
                elif tok.startswith("vmaddr "):
                    parts = tok.split()
                    if len(parts) >= 2:
                        try:
                            vmaddr = int(parts[1], 0)
                        except ValueError:
                            vmaddr = int(parts[1], 16)
                j += 1
            if segname == "__TEXT" and vmaddr is not None:
                text_vmaddr = vmaddr
        elif stripped.startswith("cmd LC_MAIN"):
            j = idx + 1
            while j < len(lines) and not lines[j].strip().startswith("Load command"):
                tok = lines[j].strip()
                if tok.startswith("entryoff "):
                    parts = tok.split()
                    if len(parts) >= 2:
                        entryoff = int(parts[1], 0)
                j += 1
        idx += 1

    if text_vmaddr is not None and entryoff is not None:
        return (text_vmaddr, entryoff, text_vmaddr + entryoff)
    return (text_vmaddr, entryoff, None)


def compute_entry_address_via_otool(
    binary_path: str, env: Dict[str, str], timeout: float = 30.0
) -> Tuple[Optional[int], Optional[str]]:
    arch = select_arm64_slice_name(binary_path)
    cmd = ["xcrun", "otool"]
    if arch:
        cmd.extend(["-arch", arch])
    cmd.extend(["-l", binary_path])
    proc = subprocess.run(
        cmd,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        env=env,
    )
    if proc.returncode != 0:
        err_txt, _ = decode_utf8_safe(proc.stderr)
        return (None, f"otool -l failed (rc={proc.returncode}): {err_txt.strip()}")
    stdout_txt, _ = decode_utf8_safe(proc.stdout)
    _, _, entry_va = parse_otool_lc_main_entry(stdout_txt)
    if entry_va is None:
        return (None, f"Failed to parse __TEXT vmaddr + LC_MAIN entryoff from otool -l on {binary_path}")
    return (entry_va, None)


def parse_codesign_dvvv(stderr_text: str, returncode: int = 0) -> Dict[str, Any]:
    lowered = stderr_text.lower()
    if returncode != 0 and "not signed" in lowered:
        return {"is_signed": False, "cdhash_full": None, "cdhash_short": None}
    cdhash_full: Optional[str] = None
    cdhash_short: Optional[str] = None
    for raw_line in stderr_text.splitlines():
        line = raw_line.strip()
        if line.startswith("CandidateCDHashFull ") and "=" in line:
            cdhash_full = line.split("=", 1)[1].strip().lower()
        elif line.startswith("CDHash="):
            cdhash_short = line.split("=", 1)[1].strip().lower()
    return {
        "is_signed": cdhash_full is not None or cdhash_short is not None or returncode == 0,
        "cdhash_full": cdhash_full,
        "cdhash_short": cdhash_short,
    }


def run_codesign_dvvv(
    binary_path: str, env: Dict[str, str], timeout: float = 30.0
) -> Dict[str, Any]:
    arch = select_arm64_slice_name(binary_path)
    cmd = ["/usr/bin/codesign"]
    if arch:
        cmd.extend(["-a", arch])
    cmd.extend(["-dvvv", binary_path])
    proc = subprocess.run(
        cmd,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        env=env,
    )
    stderr_txt, _ = decode_utf8_safe(proc.stdout + proc.stderr)
    return parse_codesign_dvvv(stderr_txt, proc.returncode)


# ---------------------------------------------------------------------------
# Pure Validation Functions (Unit-Tested by `test_m5_harnesses.py`)
# ---------------------------------------------------------------------------


def validate_protocol_transcript(
    *,
    responses_by_tag: Dict[str, Any],
    raw_line_count: int,
    expected_line_count: int,
    lang: str = "en",
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []

    if raw_line_count != expected_line_count:
        diffs.append(
            {
                "kind": "NOTIFICATION_OR_LINE_COUNT_MISMATCH",
                "lang": lang,
                "expected_lines": expected_line_count,
                "actual_lines": raw_line_count,
            }
        )

    # 1. initialize
    init_resp = responses_by_tag.get("initialize")
    if not isinstance(init_resp, dict) or not isinstance(init_resp.get("result"), dict):
        diffs.append({"kind": "INVALID_INITIALIZE_RESPONSE", "lang": lang, "response": init_resp})
    else:
        init_res = init_resp["result"]
        if init_res.get("protocolVersion") != "2024-11-05":
            diffs.append(
                {
                    "kind": "PROTOCOL_VERSION_MISMATCH",
                    "lang": lang,
                    "actual": init_res.get("protocolVersion"),
                }
            )
        srv_info = init_res.get("serverInfo")
        if not isinstance(srv_info, dict) or srv_info.get("name") != "machgraph-mcp":
            diffs.append({"kind": "INVALID_SERVER_INFO", "lang": lang, "serverInfo": srv_info})
        caps = init_res.get("capabilities")
        if not isinstance(caps, dict) or not isinstance(caps.get("tools"), dict):
            diffs.append({"kind": "INVALID_CAPABILITIES", "lang": lang, "capabilities": caps})

    # 2. tools/list
    list_resp = responses_by_tag.get("tools_list")
    tools = (
        list_resp.get("result", {}).get("tools")
        if isinstance(list_resp, dict) and isinstance(list_resp.get("result"), dict)
        else None
    )
    if not isinstance(tools, list):
        diffs.append({"kind": "TOOLS_LIST_MISMATCH", "lang": lang, "reason": "missing tools list"})
    else:
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        expected_set = set(EXPECTED_MCP_TOOLS.keys())
        if len(tools) != 8 or len(set(names)) != 8 or set(names) != expected_set:
            diffs.append(
                {
                    "kind": "TOOLS_LIST_MISMATCH",
                    "lang": lang,
                    "expected": sorted(expected_set),
                    "actual": names,
                }
            )
        for tool in tools:
            if not isinstance(tool, dict):
                diffs.append({"kind": "INVALID_INPUT_SCHEMA", "lang": lang, "reason": "non-dict tool"})
                continue
            tname = tool.get("name")
            if tname not in EXPECTED_MCP_TOOLS:
                continue
            spec = EXPECTED_MCP_TOOLS[tname]
            desc = tool.get("description")
            if not isinstance(desc, str) or not desc.strip():
                diffs.append(
                    {"kind": "INVALID_TOOL_DESCRIPTION", "lang": lang, "tool": tname}
                )
            elif spec["unverified"]:
                if lang == "zh":
                    if "实验性" not in desc or "未通过验收" not in desc:
                        diffs.append(
                            {
                                "kind": "DESCRIPTION_MISSING_UNVERIFIED",
                                "lang": lang,
                                "tool": tname,
                                "description": desc,
                            }
                        )
                else:
                    up = desc.upper()
                    if "EXPERIMENTAL" not in up or "UNVERIFIED" not in up:
                        diffs.append(
                            {
                                "kind": "DESCRIPTION_MISSING_UNVERIFIED",
                                "lang": lang,
                                "tool": tname,
                                "description": desc,
                            }
                        )

            schema = tool.get("inputSchema")
            if not isinstance(schema, dict) or schema.get("type") != "object":
                diffs.append(
                    {
                        "kind": "INVALID_INPUT_SCHEMA",
                        "lang": lang,
                        "tool": tname,
                        "reason": "inputSchema.type != object",
                    }
                )
                continue
            props = schema.get("properties")
            reqs = schema.get("required")
            if not isinstance(props, dict) or not props:
                diffs.append(
                    {
                        "kind": "INVALID_INPUT_SCHEMA",
                        "lang": lang,
                        "tool": tname,
                        "reason": "missing properties",
                    }
                )
                continue
            if not spec["properties"].issubset(set(props.keys())):
                diffs.append(
                    {
                        "kind": "INVALID_INPUT_SCHEMA",
                        "lang": lang,
                        "tool": tname,
                        "reason": "missing expected properties",
                        "expected": sorted(spec["properties"]),
                        "actual": sorted(props.keys()),
                    }
                )
            for pname, pval in props.items():
                if not isinstance(pval, dict):
                    diffs.append(
                        {
                            "kind": "INVALID_INPUT_SCHEMA",
                            "lang": lang,
                            "tool": tname,
                            "property": pname,
                            "reason": "property schema not dict",
                        }
                    )
                    continue
                ptype = pval.get("type")
                pdesc = pval.get("description")
                if ptype not in ("string", "integer", "boolean", "number", "array", "object"):
                    diffs.append(
                        {
                            "kind": "INVALID_INPUT_SCHEMA",
                            "lang": lang,
                            "tool": tname,
                            "property": pname,
                            "reason": f"invalid property type {ptype!r}",
                        }
                    )
                if not isinstance(pdesc, str) or not pdesc.strip():
                    diffs.append(
                        {
                            "kind": "INVALID_INPUT_SCHEMA",
                            "lang": lang,
                            "tool": tname,
                            "property": pname,
                            "reason": "missing property description",
                        }
                    )
            if not isinstance(reqs, list) or sorted(reqs) != sorted(spec["required"]):
                diffs.append(
                    {
                        "kind": "INVALID_INPUT_SCHEMA",
                        "lang": lang,
                        "tool": tname,
                        "reason": "required list mismatch",
                        "expected": spec["required"],
                        "actual": reqs,
                    }
                )

    # 3. JSON-RPC error codes (-32700 & -32601)
    for tag, expected_code in (("invalid_json", -32700), ("unknown_method", -32601)):
        resp = responses_by_tag.get(tag)
        err_obj = resp.get("error") if isinstance(resp, dict) else None
        if (
            not isinstance(err_obj, dict)
            or err_obj.get("code") != expected_code
            or not isinstance(err_obj.get("message"), str)
            or not err_obj.get("message", "").strip()
        ):
            diffs.append(
                {
                    "kind": "WRONG_JSONRPC_ERROR_CODE",
                    "lang": lang,
                    "case": tag,
                    "expected_code": expected_code,
                    "response": resp,
                }
            )

    # 4. Tool-level error cases -> isError: True & non-empty text
    for err_tag in PROTOCOL_ERROR_CALL_SPECS:
        resp = responses_by_tag.get(err_tag)
        res_obj = resp.get("result") if isinstance(resp, dict) else None
        content = res_obj.get("content") if isinstance(res_obj, dict) else None
        first_item = content[0] if isinstance(content, list) and content else None
        msg_text = first_item.get("text") if isinstance(first_item, dict) else None
        if (
            not isinstance(res_obj, dict)
            or res_obj.get("isError") is not True
            or not isinstance(first_item, dict)
            or first_item.get("type") != "text"
            or not isinstance(msg_text, str)
            or not msg_text.strip()
        ):
            diffs.append(
                {
                    "kind": "EXPECTED_TOOL_ERROR",
                    "lang": lang,
                    "case": err_tag,
                    "response": resp,
                }
            )

    return diffs


def compare_mcp_tool_with_cli_bytes(
    *,
    case_name: str,
    mcp_resp: Optional[Dict[str, Any]],
    cli_returncode: int,
    cli_stdout: bytes,
    cli_stderr: bytes,
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    if cli_returncode != 0:
        err_txt, _ = decode_utf8_safe(cli_stderr)
        diffs.append(
            {
                "kind": "CLI_FAILED",
                "case": case_name,
                "cli_returncode": cli_returncode,
                "stderr": sanitize_text(err_txt[:300]),
            }
        )
        return diffs

    res_obj = mcp_resp.get("result") if isinstance(mcp_resp, dict) else None
    if not isinstance(res_obj, dict) or res_obj.get("isError") is not False:
        diffs.append(
            {
                "kind": "MCP_TOOL_ERROR",
                "case": case_name,
                "response": mcp_resp,
            }
        )
        return diffs

    content = res_obj.get("content")
    first_item = content[0] if isinstance(content, list) and content else None
    mcp_text = first_item.get("text") if isinstance(first_item, dict) else None
    if not isinstance(mcp_text, str):
        diffs.append({"kind": "MCP_MISSING_TEXT", "case": case_name})
        return diffs

    try:
        json.loads(mcp_text)
    except Exception as exc:
        diffs.append(
            {
                "kind": "MCP_INVALID_JSON_PAYLOAD",
                "case": case_name,
                "error": str(exc),
            }
        )
        return diffs

    mcp_bytes = mcp_text.encode("utf-8")
    if mcp_bytes != cli_stdout:
        first_diff_offset = next(
            (
                i
                for i in range(min(len(mcp_bytes), len(cli_stdout)))
                if mcp_bytes[i] != cli_stdout[i]
            ),
            min(len(mcp_bytes), len(cli_stdout)),
        )
        diffs.append(
            {
                "kind": "BYTE_MISMATCH",
                "case": case_name,
                "mcp_bytes": len(mcp_bytes),
                "cli_bytes": len(cli_stdout),
                "first_diff_offset": first_diff_offset,
            }
        )
    return diffs


def validate_legacy_inspect_cdhash(
    binary_label: str,
    mcp_resp: Optional[Dict[str, Any]],
    codesign_info: Dict[str, Any],
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    res_obj = mcp_resp.get("result") if isinstance(mcp_resp, dict) else None
    content = res_obj.get("content") if isinstance(res_obj, dict) else None
    text = (
        content[0].get("text")
        if isinstance(content, list) and content and isinstance(content[0], dict)
        else None
    )
    if not isinstance(res_obj, dict) or res_obj.get("isError") is not False or not isinstance(text, str):
        return [{"kind": "INSPECT_CALL_FAILED", "binary": binary_label, "response": mcp_resp}]

    for required_tok in ("file=", "format=", "arch=", "functions=", "insns=", "cdhash="):
        if required_tok not in text:
            diffs.append(
                {
                    "kind": "INSPECT_MISSING_FIELD",
                    "binary": binary_label,
                    "missing": required_tok,
                    "text": sanitize_text(text),
                }
            )
    m = re.search(r"\bcdhash=([0-9a-fA-F]+)\b", text)
    actual_cdhash = m.group(1).lower() if m else ""
    ref_full = codesign_info.get("cdhash_full")
    ref_short = codesign_info.get("cdhash_short")
    if ref_full:
        if actual_cdhash != ref_full:
            diffs.append(
                {
                    "kind": "CDHASH_MISMATCH",
                    "binary": binary_label,
                    "expected": ref_full,
                    "actual": actual_cdhash,
                }
            )
    elif ref_short:
        if not actual_cdhash.startswith(ref_short):
            diffs.append(
                {
                    "kind": "CDHASH_MISMATCH",
                    "binary": binary_label,
                    "expected_prefix": ref_short,
                    "actual": actual_cdhash,
                }
            )
    else:
        diffs.append({"kind": "CODESIGN_REF_UNAVAILABLE", "binary": binary_label})
    return diffs


def validate_legacy_xrefs_bidirectional(
    binary_label: str,
    address_hex: str,
    mcp_resp: Optional[Dict[str, Any]],
    cli_xrefs_json: Dict[str, Any],
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    res_obj = mcp_resp.get("result") if isinstance(mcp_resp, dict) else None
    content = res_obj.get("content") if isinstance(res_obj, dict) else None
    text = (
        content[0].get("text")
        if isinstance(content, list) and content and isinstance(content[0], dict)
        else None
    )
    if not isinstance(res_obj, dict) or res_obj.get("isError") is not False or not isinstance(text, str):
        return [{"kind": "XREFS_CALL_FAILED", "binary": binary_label, "address": address_hex}]

    incoming_ref = cli_xrefs_json.get("incoming", [])
    outgoing_ref = cli_xrefs_json.get("outgoing", [])
    if not incoming_ref or not outgoing_ref:
        diffs.append(
            {
                "kind": "TARGET_NOT_BIDIRECTIONAL",
                "binary": binary_label,
                "address": address_hex,
                "incoming_count": len(incoming_ref),
                "outgoing_count": len(outgoing_ref),
            }
        )
        return diffs

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    expected_header = f"to={len(incoming_ref)} from={len(outgoing_ref)}"
    if not lines or lines[0] != expected_header:
        diffs.append(
            {
                "kind": "XREFS_HEADER_MISMATCH",
                "binary": binary_label,
                "address": address_hex,
                "expected": expected_header,
                "actual": lines[0] if lines else "",
            }
        )

    incoming_lines = [ln for ln in lines[1:] if ln.startswith("<- ")]
    outgoing_lines = [ln for ln in lines[1:] if ln.startswith("-> ")]

    if len(incoming_lines) != len(incoming_ref):
        diffs.append(
            {
                "kind": "MISSING_INCOMING_XREFS",
                "binary": binary_label,
                "address": address_hex,
                "expected_count": len(incoming_ref),
                "actual_count": len(incoming_lines),
            }
        )
    if len(outgoing_lines) != len(outgoing_ref):
        diffs.append(
            {
                "kind": "MISSING_OUTGOING_XREFS",
                "binary": binary_label,
                "address": address_hex,
                "expected_count": len(outgoing_ref),
                "actual_count": len(outgoing_lines),
            }
        )

    for rec in incoming_ref:
        expected_frag = f"<- {rec['fromAddressHex']} [{rec['kind']}]"
        if not any(ln.startswith(expected_frag) for ln in incoming_lines):
            diffs.append(
                {
                    "kind": "MISSING_INCOMING_XREFS",
                    "binary": binary_label,
                    "address": address_hex,
                    "missing_edge": expected_frag,
                }
            )
    for rec in outgoing_ref:
        expected_frag = f"-> {rec['toAddressHex']} [{rec['kind']}]"
        if not any(ln.startswith(expected_frag) for ln in outgoing_lines):
            diffs.append(
                {
                    "kind": "MISSING_OUTGOING_XREFS",
                    "binary": binary_label,
                    "address": address_hex,
                    "missing_edge": expected_frag,
                }
            )
    return diffs


def validate_unverified_banner(
    tool_name: str,
    lang: str,
    mcp_resp: Optional[Dict[str, Any]],
    expected_cli_audit_text: Optional[str] = None,
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    res_obj = mcp_resp.get("result") if isinstance(mcp_resp, dict) else None
    content = res_obj.get("content") if isinstance(res_obj, dict) else None
    text = (
        content[0].get("text")
        if isinstance(content, list) and content and isinstance(content[0], dict)
        else None
    )
    if not isinstance(res_obj, dict) or res_obj.get("isError") is not False or not isinstance(text, str):
        return [{"kind": "UNVERIFIED_TOOL_CALL_FAILED", "tool": tool_name, "lang": lang}]

    lines = text.splitlines()
    first_line = lines[0].strip() if lines else ""
    if not first_line or not (first_line.startswith("//") or first_line.startswith("#")):
        diffs.append(
            {
                "kind": "MISSING_UNVERIFIED_MARKER",
                "tool": tool_name,
                "lang": lang,
                "first_line": sanitize_text(first_line[:200]),
                "reason": "line 1 is not a comment banner",
            }
        )
    elif lang == "zh":
        if "实验性" not in first_line or "未通过验收" not in first_line:
            diffs.append(
                {
                    "kind": "MISSING_UNVERIFIED_MARKER",
                    "tool": tool_name,
                    "lang": lang,
                    "first_line": sanitize_text(first_line[:200]),
                }
            )
    else:
        up = first_line.upper()
        if "EXPERIMENTAL" not in up or "UNVERIFIED" not in up:
            diffs.append(
                {
                    "kind": "MISSING_UNVERIFIED_MARKER",
                    "tool": tool_name,
                    "lang": lang,
                    "first_line": sanitize_text(first_line[:200]),
                }
            )

    if tool_name == "mach_audit_security":
        second_line = lines[1].strip() if len(lines) > 1 else ""
        if second_line.startswith("[{") or second_line.startswith("[]"):
            diffs.append(
                {
                    "kind": "AUDIT_RAW_JSON_LEAK",
                    "tool": tool_name,
                    "lang": lang,
                    "second_line": sanitize_text(second_line[:120]),
                }
            )
        if expected_cli_audit_text is not None:
            if text.rstrip("\n") != expected_cli_audit_text.rstrip("\n"):
                diffs.append(
                    {
                        "kind": "AUDIT_CLI_MISMATCH",
                        "tool": tool_name,
                        "lang": lang,
                        "mcp_len": len(text),
                        "cli_len": len(expected_cli_audit_text),
                    }
                )
    return diffs


# ---------------------------------------------------------------------------
# Subprocess MCP & CLI Drivers
# ---------------------------------------------------------------------------


def run_mcp_batch(
    machgraph_bin: str,
    raw_lines_to_send: Sequence[str],
    *,
    lang: str,
    env: Dict[str, str],
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    payload = "\n".join(raw_lines_to_send) + "\n"
    proc = subprocess.run(
        [machgraph_bin, "mcp", "--lang", lang],
        input=payload.encode("utf-8"),
        capture_output=True,
        timeout=timeout,
        env=env,
    )
    if proc.returncode != 0:
        err_txt, _ = decode_utf8_safe(proc.stderr)
        return ([], f"machgraph mcp exited with {proc.returncode}: {sanitize_text(err_txt[:300])}")
    stdout_txt, had_bad = decode_utf8_safe(proc.stdout)
    if had_bad:
        return ([], "machgraph mcp emitted invalid UTF-8 bytes")
    parsed: List[Dict[str, Any]] = []
    for ln in stdout_txt.splitlines():
        if not ln.strip():
            continue
        try:
            parsed.append(json.loads(ln))
        except Exception as exc:
            return ([], f"Failed to parse MCP JSON-RPC response line: {exc}")
    return (parsed, None)


def evaluate_protocol_suite(machgraph_bin: str, env: Dict[str, str]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    all_diffs: List[Dict[str, Any]] = []

    # Independently confirm `/bin/ls` has no `_main` symbol via `xcrun nm`
    ls_arch = select_arm64_slice_name("/bin/ls")
    nm_cmd = ["xcrun", "nm", "--no-dyldinfo"]
    if ls_arch:
        nm_cmd.extend(["-arch", ls_arch])
    nm_cmd.append("/bin/ls")
    nm_proc = subprocess.run(nm_cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=30.0, env=env)
    nm_txt, _ = decode_utf8_safe(nm_proc.stdout)
    defined_main = [
        ln
        for ln in nm_txt.splitlines()
        if ln.strip().endswith(" _main") and " U " not in ln
    ]
    if nm_proc.returncode != 0 or defined_main:
        all_diffs.append(
            {
                "kind": "LS_NM_PRECONDITION_FAILED",
                "returncode": nm_proc.returncode,
                "defined_main": defined_main,
            }
        )

    for lang in ("en", "zh"):
        lines_to_send: List[str] = []
        id_to_tag: Dict[int, str] = {}

        lines_to_send.append(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        id_to_tag[1] = "initialize"

        # Notification must NOT produce a response line
        lines_to_send.append(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))

        lines_to_send.append(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
        id_to_tag[2] = "tools_list"

        lines_to_send.append("{malformed-json-line")

        lines_to_send.append(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "bogus/method", "params": {}}))
        id_to_tag[4] = "unknown_method"

        next_id = 10
        for err_tag, (tool_name, tool_args) in PROTOCOL_ERROR_CALL_SPECS.items():
            lines_to_send.append(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": next_id,
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": tool_args},
                    }
                )
            )
            id_to_tag[next_id] = err_tag
            next_id += 1

        expected_lines = len(id_to_tag) + 1  # +1 for invalid_json
        responses, run_err = run_mcp_batch(machgraph_bin, lines_to_send, lang=lang, env=env)
        if run_err is not None:
            all_diffs.append({"kind": "MCP_PROCESS_ERROR", "lang": lang, "error": run_err})
            continue

        responses_by_tag: Dict[str, Any] = {}
        for resp in responses:
            rid = resp.get("id")
            if rid is None and isinstance(resp.get("error"), dict):
                responses_by_tag["invalid_json"] = resp
            elif isinstance(rid, int) and rid in id_to_tag:
                responses_by_tag[id_to_tag[rid]] = resp

        all_diffs.extend(
            validate_protocol_transcript(
                responses_by_tag=responses_by_tag,
                raw_line_count=len(responses),
                expected_line_count=expected_lines,
                lang=lang,
            )
        )

    elapsed = time.perf_counter() - t0
    return {
        "status": "pass" if not all_diffs else "fail",
        "diff_count": len(all_diffs),
        "seconds": round(elapsed, 4),
        "examples": all_diffs[:MAX_EXAMPLES_PER_CHECK],
    }


def evaluate_tools_suite(machgraph_bin: str, env: Dict[str, str]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    diffs: List[Dict[str, Any]] = []

    ls_entry, ls_err = compute_entry_address_via_otool("/bin/ls", env)
    ssh_entry, ssh_err = compute_entry_address_via_otool("/usr/bin/ssh", env)
    if ls_entry is None:
        diffs.append({"kind": "OTOOL_ENTRY_ERROR", "binary": "/bin/ls", "error": ls_err})
    if ssh_entry is None:
        diffs.append({"kind": "OTOOL_ENTRY_ERROR", "binary": "/usr/bin/ssh", "error": ssh_err})
    if diffs:
        return {
            "status": "fail",
            "diff_count": len(diffs),
            "seconds": round(time.perf_counter() - t0, 4),
            "examples": diffs,
        }

    ls_entry_hex = f"0x{ls_entry:x}"
    ssh_entry_hex = f"0x{ssh_entry:x}"

    cases: List[Tuple[str, str, Dict[str, Any], List[str]]] = [
        (
            "ls_disasm_entry_full",
            "mach_disasm_function",
            {"binaryPath": "/bin/ls", "address": ls_entry_hex},
            ["disasm", "/bin/ls", "--address", ls_entry_hex, "--json"],
        ),
        (
            "ls_disasm_entry_count12",
            "mach_disasm_function",
            {"binaryPath": "/bin/ls", "address": ls_entry_hex, "count": 12},
            ["disasm", "/bin/ls", "--address", ls_entry_hex, "--count", "12", "--json"],
        ),
        (
            "ls_symbols_all",
            "mach_list_symbols",
            {"binaryPath": "/bin/ls"},
            ["symbols", "/bin/ls", "--json"],
        ),
        (
            "ls_symbols_filter_entry",
            "mach_list_symbols",
            {"binaryPath": "/bin/ls", "filter": "entry"},
            ["symbols", "/bin/ls", "--filter", "entry", "--json"],
        ),
        (
            "ls_cfg_entry",
            "mach_cfg",
            {"binaryPath": "/bin/ls", "address": ls_entry_hex},
            ["cfg", "/bin/ls", "--address", ls_entry_hex, "--json"],
        ),
        (
            "ls_strings_all",
            "mach_find_strings",
            {"binaryPath": "/bin/ls"},
            ["strings", "/bin/ls", "--json"],
        ),
        (
            "ls_strings_filter_usage",
            "mach_find_strings",
            {"binaryPath": "/bin/ls", "filter": "usage"},
            ["strings", "/bin/ls", "--filter", "usage", "--json"],
        ),
        (
            "ssh_disasm_entry_full",
            "mach_disasm_function",
            {"binaryPath": "/usr/bin/ssh", "address": ssh_entry_hex},
            ["disasm", "/usr/bin/ssh", "--address", ssh_entry_hex, "--json"],
        ),
        (
            "ssh_disasm_entry_count16",
            "mach_disasm_function",
            {"binaryPath": "/usr/bin/ssh", "address": ssh_entry_hex, "count": 16},
            ["disasm", "/usr/bin/ssh", "--address", ssh_entry_hex, "--count", "16", "--json"],
        ),
        (
            "ssh_symbols_all",
            "mach_list_symbols",
            {"binaryPath": "/usr/bin/ssh"},
            ["symbols", "/usr/bin/ssh", "--json"],
        ),
        (
            "ssh_symbols_filter_ssh",
            "mach_list_symbols",
            {"binaryPath": "/usr/bin/ssh", "filter": "ssh"},
            ["symbols", "/usr/bin/ssh", "--filter", "ssh", "--json"],
        ),
        (
            "ssh_cfg_entry_addr",
            "mach_cfg",
            {"binaryPath": "/usr/bin/ssh", "address": ssh_entry_hex},
            ["cfg", "/usr/bin/ssh", "--address", ssh_entry_hex, "--json"],
        ),
        (
            "ssh_cfg_entry_symbol",
            "mach_cfg",
            {"binaryPath": "/usr/bin/ssh", "symbol": "_entry"},
            ["cfg", "/usr/bin/ssh", "--symbol", "_entry", "--json"],
        ),
        (
            "ssh_strings_filter_openssh",
            "mach_find_strings",
            {"binaryPath": "/usr/bin/ssh", "filter": "OpenSSH"},
            ["strings", "/usr/bin/ssh", "--filter", "OpenSSH", "--json"],
        ),
    ]

    mcp_lines: List[str] = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    ]
    for idx, (_, tool_name, tool_args, _) in enumerate(cases, start=10):
        mcp_lines.append(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                }
            )
        )

    responses, run_err = run_mcp_batch(machgraph_bin, mcp_lines, lang="en", env=env, timeout=120.0)
    if run_err is not None:
        diffs.append({"kind": "MCP_PROCESS_ERROR", "error": run_err})
        return {
            "status": "fail",
            "diff_count": len(diffs),
            "total_cases": len(cases),
            "matched_cases": 0,
            "seconds": round(time.perf_counter() - t0, 4),
            "examples": diffs,
        }

    resp_by_id = {r.get("id"): r for r in responses if isinstance(r, dict)}
    matched = 0
    for idx, (case_name, _, _, cli_args) in enumerate(cases, start=10):
        cli_proc = subprocess.run(
            [machgraph_bin] + cli_args,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=env,
        )
        case_diffs = compare_mcp_tool_with_cli_bytes(
            case_name=case_name,
            mcp_resp=resp_by_id.get(idx),
            cli_returncode=cli_proc.returncode,
            cli_stdout=cli_proc.stdout,
            cli_stderr=cli_proc.stderr,
        )
        if not case_diffs:
            matched += 1
        else:
            diffs.extend(case_diffs)

    return {
        "status": "pass" if not diffs and matched == len(cases) else "fail",
        "total_cases": len(cases),
        "matched_cases": matched,
        "diff_count": len(diffs),
        "ls_entry_hex": ls_entry_hex,
        "ssh_entry_hex": ssh_entry_hex,
        "seconds": round(time.perf_counter() - t0, 4),
        "examples": diffs[:MAX_EXAMPLES_PER_CHECK],
    }


def _find_bidirectional_xref_address(
    machgraph_bin: str, binary_path: str, env: Dict[str, str]
) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """Finds an address in `binary_path` that has both incoming and outgoing xrefs."""
    all_proc = subprocess.run(
        [machgraph_bin, "xrefs", binary_path, "--json"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
        env=env,
    )
    if all_proc.returncode != 0:
        err_txt, _ = decode_utf8_safe(all_proc.stderr)
        return (None, None, f"cli xrefs --json failed: {sanitize_text(err_txt[:200])}")
    txt, _ = decode_utf8_safe(all_proc.stdout)
    data = json.loads(txt)
    records = data.get("xrefs", [])
    from_set = {r["fromAddress"] for r in records}
    to_set = {r["toAddress"] for r in records}
    both = sorted(from_set & to_set)
    if not both:
        return (None, None, f"No address in {binary_path} has both incoming and outgoing xrefs")
    chosen_hex = f"0x{both[0]:x}"
    single_proc = subprocess.run(
        [machgraph_bin, "xrefs", binary_path, "--address", chosen_hex, "--json"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
        env=env,
    )
    if single_proc.returncode != 0:
        err_txt, _ = decode_utf8_safe(single_proc.stderr)
        return (None, None, f"cli xrefs --address {chosen_hex} failed: {sanitize_text(err_txt[:200])}")
    single_txt, _ = decode_utf8_safe(single_proc.stdout)
    return (chosen_hex, json.loads(single_txt), None)


def evaluate_legacy_suite(machgraph_bin: str, env: Dict[str, str]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    diffs: List[Dict[str, Any]] = []

    ls_entry, ls_err = compute_entry_address_via_otool("/bin/ls", env)
    if ls_entry is None:
        return {
            "status": "fail",
            "diff_count": 1,
            "seconds": round(time.perf_counter() - t0, 4),
            "examples": [{"kind": "OTOOL_ENTRY_ERROR", "error": ls_err}],
        }
    ls_entry_hex = f"0x{ls_entry:x}"

    # 1. codesign -dvvv reference for /bin/ls & /usr/bin/ssh
    cs_ls = run_codesign_dvvv("/bin/ls", env)
    cs_ssh = run_codesign_dvvv("/usr/bin/ssh", env)

    # 2. Bidirectional xref target on /bin/ls
    bi_addr_hex, cli_xrefs_obj, bi_err = _find_bidirectional_xref_address(
        machgraph_bin, "/bin/ls", env
    )
    if bi_err is not None or bi_addr_hex is None or cli_xrefs_obj is None:
        diffs.append({"kind": "XREFS_REF_ERROR", "error": bi_err})

    # 3. Run EN MCP session (inspect ls/ssh, xrefs, decompile EN, audit EN)
    en_reqs = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "mach_inspect_binary", "arguments": {"binaryPath": "/bin/ls"}},
            }
        ),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "mach_inspect_binary", "arguments": {"binaryPath": "/usr/bin/ssh"}},
            }
        ),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "mach_query_xrefs",
                    "arguments": {"binaryPath": "/bin/ls", "address": bi_addr_hex or "0x100000fe0"},
                },
            }
        ),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "mach_decompile_function",
                    "arguments": {"binaryPath": "/bin/ls", "function": ls_entry_hex},
                },
            }
        ),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {"name": "mach_audit_security", "arguments": {"binaryPath": "/bin/ls"}},
            }
        ),
    ]
    en_resps, en_err = run_mcp_batch(machgraph_bin, en_reqs, lang="en", env=env, timeout=120.0)
    if en_err is not None:
        diffs.append({"kind": "MCP_PROCESS_ERROR", "lang": "en", "error": en_err})
    else:
        en_map = {r.get("id"): r for r in en_resps if isinstance(r, dict)}
        diffs.extend(validate_legacy_inspect_cdhash("/bin/ls", en_map.get(10), cs_ls))
        diffs.extend(validate_legacy_inspect_cdhash("/usr/bin/ssh", en_map.get(11), cs_ssh))
        if bi_addr_hex is not None and cli_xrefs_obj is not None:
            diffs.extend(
                validate_legacy_xrefs_bidirectional(
                    "/bin/ls", bi_addr_hex, en_map.get(12), cli_xrefs_obj
                )
            )
        diffs.extend(
            validate_unverified_banner("mach_decompile_function", "en", en_map.get(13))
        )
        cli_audit_en_proc = subprocess.run(
            [machgraph_bin, "audit-plugins", "/bin/ls", "--lang", "en"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=env,
        )
        cli_audit_en_txt, _ = decode_utf8_safe(cli_audit_en_proc.stdout)
        diffs.extend(
            validate_unverified_banner(
                "mach_audit_security",
                "en",
                en_map.get(14),
                expected_cli_audit_text=cli_audit_en_txt,
            )
        )

    # 4. Run ZH MCP session (decompile ZH, audit ZH)
    zh_reqs = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "mach_decompile_function",
                    "arguments": {"binaryPath": "/bin/ls", "function": ls_entry_hex},
                },
            }
        ),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "mach_audit_security", "arguments": {"binaryPath": "/bin/ls"}},
            }
        ),
    ]
    zh_resps, zh_err = run_mcp_batch(machgraph_bin, zh_reqs, lang="zh", env=env, timeout=120.0)
    if zh_err is not None:
        diffs.append({"kind": "MCP_PROCESS_ERROR", "lang": "zh", "error": zh_err})
    else:
        zh_map = {r.get("id"): r for r in zh_resps if isinstance(r, dict)}
        diffs.extend(
            validate_unverified_banner("mach_decompile_function", "zh", zh_map.get(20))
        )
        cli_audit_zh_proc = subprocess.run(
            [machgraph_bin, "audit-plugins", "/bin/ls", "--lang", "zh"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            env=env,
        )
        cli_audit_zh_txt, _ = decode_utf8_safe(cli_audit_zh_proc.stdout)
        diffs.extend(
            validate_unverified_banner(
                "mach_audit_security",
                "zh",
                zh_map.get(21),
                expected_cli_audit_text=cli_audit_zh_txt,
            )
        )

    return {
        "status": "pass" if not diffs else "fail",
        "diff_count": len(diffs),
        "bidirectional_xref_address": bi_addr_hex,
        "seconds": round(time.perf_counter() - t0, 4),
        "examples": diffs[:MAX_EXAMPLES_PER_CHECK],
    }


def _read_uptime() -> str:
    proc = subprocess.run(["/usr/bin/uptime"], capture_output=True, stdin=subprocess.DEVNULL)
    txt, _ = decode_utf8_safe(proc.stdout)
    return sanitize_text(txt.strip())


def evaluate_perf_suite(machgraph_bin: str, env: Dict[str, str]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    uptime_before = _read_uptime()
    failures: List[Dict[str, Any]] = []
    benchmarks: Dict[str, Any] = {}

    ssh_entry, ssh_err = compute_entry_address_via_otool("/usr/bin/ssh", env)
    vim_entry, vim_err = compute_entry_address_via_otool("/usr/bin/vim", env)
    if ssh_entry is None:
        failures.append({"kind": "OTOOL_ENTRY_ERROR", "binary": "/usr/bin/ssh", "error": ssh_err})
    if vim_entry is None:
        failures.append({"kind": "OTOOL_ENTRY_ERROR", "binary": "/usr/bin/vim", "error": vim_err})
    if failures:
        return {
            "status": "fail",
            "diff_count": len(failures),
            "uptime_before": uptime_before,
            "uptime_after": _read_uptime(),
            "benchmarks": benchmarks,
            "seconds": round(time.perf_counter() - t0, 4),
            "examples": failures,
        }

    ssh_entry_hex = f"0x{ssh_entry:x}"
    vim_entry_hex = f"0x{vim_entry:x}"

    bench_specs: List[Tuple[str, str, Dict[str, Any]]] = [
        ("ssh_list_symbols", "mach_list_symbols", {"binaryPath": "/usr/bin/ssh"}),
        ("ssh_find_strings", "mach_find_strings", {"binaryPath": "/usr/bin/ssh", "filter": "OpenSSH"}),
        ("ssh_cfg_entry", "mach_cfg", {"binaryPath": "/usr/bin/ssh", "address": ssh_entry_hex}),
        (
            "ssh_disasm_entry",
            "mach_disasm_function",
            {"binaryPath": "/usr/bin/ssh", "address": ssh_entry_hex},
        ),
        ("vim_list_symbols", "mach_list_symbols", {"binaryPath": "/usr/bin/vim"}),
        ("vim_find_strings", "mach_find_strings", {"binaryPath": "/usr/bin/vim", "filter": "VIM"}),
        ("vim_cfg_entry", "mach_cfg", {"binaryPath": "/usr/bin/vim", "address": vim_entry_hex}),
        (
            "vim_disasm_entry",
            "mach_disasm_function",
            {"binaryPath": "/usr/bin/vim", "address": vim_entry_hex},
        ),
    ]

    for label, tool_name, tool_args in bench_specs:
        samples: List[float] = []
        payload_bytes = 0
        for run_idx in range(PERF_RUN_COUNT):
            req_lines = [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": tool_args},
                    }
                ),
            ]
            start = time.perf_counter()
            try:
                resps, err = run_mcp_batch(
                    machgraph_bin,
                    req_lines,
                    lang="en",
                    env=env,
                    timeout=HANG_FAIL_SECONDS + 5.0,
                )
            except subprocess.TimeoutExpired:
                failures.append(
                    {
                        "kind": "PERF_HANG_TIMEOUT",
                        "benchmark": label,
                        "run": run_idx + 1,
                        "limit_seconds": HANG_FAIL_SECONDS,
                    }
                )
                break
            dur = time.perf_counter() - start
            samples.append(round(dur, 4))
            if err is not None:
                failures.append({"kind": "PERF_MCP_ERROR", "benchmark": label, "error": err})
                break
            resp_map = {r.get("id"): r for r in resps if isinstance(r, dict)}
            call_res = resp_map.get(2, {}).get("result", {})
            content = call_res.get("content", [])
            txt = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
            if call_res.get("isError") is not False or not txt:
                failures.append({"kind": "PERF_TOOL_ERROR", "benchmark": label, "response": resp_map.get(2)})
                break
            try:
                json.loads(txt)
            except Exception as exc:
                failures.append({"kind": "PERF_INVALID_JSON", "benchmark": label, "error": str(exc)})
                break
            payload_bytes = len(txt.encode("utf-8"))

        med = round(statistics.median(samples), 4) if samples else None
        if med is not None and med > HANG_FAIL_SECONDS:
            failures.append(
                {
                    "kind": "PERF_HANG_THRESHOLD_EXCEEDED",
                    "benchmark": label,
                    "median_seconds": med,
                    "limit_seconds": HANG_FAIL_SECONDS,
                }
            )
        benchmarks[label] = {
            "tool": tool_name,
            "samples_seconds": samples,
            "median_seconds": med,
            "payload_bytes": payload_bytes,
        }

    uptime_after = _read_uptime()
    return {
        "status": "pass" if not failures else "fail",
        "diff_count": len(failures),
        "uptime_before": uptime_before,
        "uptime_after": uptime_after,
        "benchmarks": benchmarks,
        "seconds": round(time.perf_counter() - t0, 4),
        "examples": failures[:MAX_EXAMPLES_PER_CHECK],
    }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def parse_only_checks(only_arg: Optional[str]) -> Optional[List[str]]:
    if only_arg is None:
        return None
    items = [tok.strip() for tok in only_arg.split(",") if tok.strip()]
    if not items:
        raise ValueError("--only requires at least one check name")
    for item in items:
        if item not in AVAILABLE_CHECKS:
            raise ValueError(
                f"Unknown check '{item}' in --only (expected subset of {','.join(AVAILABLE_CHECKS)})"
            )
    dedup: List[str] = []
    for item in items:
        if item not in dedup:
            dedup.append(item)
    return dedup


def collect_environment_metadata(machgraph_bin: str) -> Dict[str, Any]:
    def run_text(cmd: Sequence[str], cwd: Optional[str] = None) -> str:
        r = subprocess.run(list(cmd), capture_output=True, stdin=subprocess.DEVNULL, cwd=cwd)
        txt, _ = decode_utf8_safe(r.stdout)
        return sanitize_text(txt.strip())

    commit_sha = run_text(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT) or "unknown"
    return {
        "macos_product_name": run_text(["sw_vers", "-productName"]),
        "macos_version": run_text(["sw_vers", "-productVersion"]),
        "macos_build": run_text(["sw_vers", "-buildVersion"]),
        "machine": run_text(["uname", "-m"]),
        "machgraph_commit": commit_sha,
        "worktree_clean": is_worktree_clean(),
        "machgraph_binary": sanitize_display_path(machgraph_bin),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "subcommand",
        nargs="?",
        default="standard",
        help="'protocol', 'tools', 'legacy', 'perf', or 'standard'/'all' (default)",
    )
    parser.add_argument(
        "--only",
        default=None,
        help=f"comma-separated subset of checks ({','.join(AVAILABLE_CHECKS)})",
    )
    parser.add_argument(
        "--machgraph",
        default=default_machgraph_bin(),
        help="path to MachGraph CLI executable",
    )
    parser.add_argument("--json-out", default=None, help="optional JSON report output path")
    parser.add_argument("--txt-out", default=None, help="optional text report output path")
    parser.add_argument(
        "--record",
        action="store_true",
        help="write report to reports/m5-mcp-acceptance.json and .txt (requires clean worktree)",
    )
    parser.add_argument("--verbose", action="store_true", help="verbose output")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        explicit_only = parse_only_checks(args.only)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2

    sub = args.subcommand.strip().lower()
    if sub in AVAILABLE_CHECKS:
        selected_checks = explicit_only if explicit_only is not None else [sub]
        mode_label = sub
    elif sub in ("standard", "all"):
        selected_checks = explicit_only if explicit_only is not None else list(AVAILABLE_CHECKS)
        mode_label = "standard"
    else:
        print(
            f"[FAIL] Unsupported subcommand '{args.subcommand}'. Expected one of: "
            f"{', '.join(AVAILABLE_CHECKS)}, standard, all.",
            file=sys.stderr,
        )
        return 2

    if args.record and not is_worktree_clean():
        print(
            "[FAIL] --record refused: git worktree has uncommitted changes.",
            file=sys.stderr,
        )
        return 1

    machgraph_bin = os.path.abspath(args.machgraph)
    if not (os.path.isfile(machgraph_bin) and os.access(machgraph_bin, os.X_OK)):
        print(
            f"[FAIL] MachGraph binary not found or not executable: {sanitize_display_path(machgraph_bin)}",
            file=sys.stderr,
        )
        return 1

    json_out_path = args.json_out
    txt_out_path = args.txt_out
    if args.record:
        reports_dir = os.path.join(REPO_ROOT, "reports")
        base_name = (
            "m5-mcp-acceptance"
            if mode_label == "standard"
            else f"m5-mcp-acceptance-{mode_label}"
        )
        if json_out_path is None:
            json_out_path = os.path.join(reports_dir, base_name + ".json")
        if txt_out_path is None:
            txt_out_path = os.path.join(reports_dir, base_name + ".txt")

    lines_out: List[str] = []

    def emit(line: str) -> None:
        clean = sanitize_text(line)
        lines_out.append(clean)
        print(clean)

    utc_now = datetime.datetime.now(datetime.timezone.utc)
    env_meta = collect_environment_metadata(machgraph_bin)
    emit(
        f"==> M5 MCP Acceptance ({mode_label}): checks={','.join(selected_checks)} "
        f"bin={env_meta['machgraph_binary']} commit={env_meta['machgraph_commit']}"
    )

    t_start = time.perf_counter()
    check_results: Dict[str, Any] = {}
    all_ok = True

    with tempfile.TemporaryDirectory(prefix="machgraph-m5-home-") as isolated_home:
        env = make_isolated_env(isolated_home)
        for chk in selected_checks:
            if chk == "protocol":
                res = evaluate_protocol_suite(machgraph_bin, env)
            elif chk == "tools":
                res = evaluate_tools_suite(machgraph_bin, env)
            elif chk == "legacy":
                res = evaluate_legacy_suite(machgraph_bin, env)
            elif chk == "perf":
                res = evaluate_perf_suite(machgraph_bin, env)
            else:
                res = {"status": "fail", "diff_count": 1, "seconds": 0.0, "examples": []}
            check_results[chk] = res
            ok = res["status"] == "pass"
            if not ok:
                all_ok = False
            tag = "PASS" if ok else "FAIL"
            if chk == "tools":
                emit(
                    f"[{tag}] Check 'tools': matched={res.get('matched_cases', 0)}/{res.get('total_cases', 0)} "
                    f"ls_entry={res.get('ls_entry_hex')} ssh_entry={res.get('ssh_entry_hex')} "
                    f"diffs={res['diff_count']} elapsed={res['seconds']:.2f}s"
                )
            elif chk == "perf":
                b = res.get("benchmarks", {})
                summary_parts = [
                    f"{k}={v.get('median_seconds')}s" for k, v in b.items()
                ]
                emit(
                    f"[{tag}] Check 'perf': {' '.join(summary_parts)} "
                    f"failures={res['diff_count']} elapsed={res['seconds']:.2f}s"
                )
                emit(f"  uptime_before: {res.get('uptime_before', '')}")
                emit(f"  uptime_after:  {res.get('uptime_after', '')}")
            else:
                emit(
                    f"[{tag}] Check '{chk}': diffs={res['diff_count']} elapsed={res['seconds']:.2f}s"
                )
            for ex in res.get("examples", [])[:MAX_EXAMPLES_PER_CHECK]:
                emit(f"  example: {json.dumps(ex, ensure_ascii=False)}")

    total_elapsed = round(time.perf_counter() - t_start, 4)
    verdict = "PASS" if all_ok else "FAIL"
    emit(f"[{verdict}] Summary ({mode_label}): checks={len(selected_checks)} elapsed={total_elapsed:.2f}s")

    if json_out_path:
        out_dir = os.path.dirname(os.path.abspath(json_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        payload = {
            "schema": "machgraph.m5.mcp_acceptance/1",
            "date": utc_now.strftime("%Y-%m-%d"),
            "generated_at_utc": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": mode_label,
            "selected_checks": selected_checks,
            "verdict": verdict,
            "environment": env_meta,
            "elapsed_seconds": total_elapsed,
            "checks": check_results,
        }
        with open(json_out_path, "w", encoding="utf-8") as fh:
            fh.write(sanitize_text(json.dumps(payload, indent=2, ensure_ascii=False)) + "\n")

    if txt_out_path:
        out_dir = os.path.dirname(os.path.abspath(txt_out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(txt_out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines_out) + "\n")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
