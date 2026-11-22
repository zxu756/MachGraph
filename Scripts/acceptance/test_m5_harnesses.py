#!/usr/bin/env python3
"""Unit tests for `m5-mcp-acceptance.py` using handcrafted synthetic fixtures."""

import copy
import importlib.util
import json
import os
import sys
import unittest
from typing import Any, Dict, List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_m5_module():
    path = os.path.join(SCRIPT_DIR, "m5-mcp-acceptance.py")
    spec = importlib.util.spec_from_file_location("m5_mcp_acceptance_mod", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["m5_mcp_acceptance_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


m5_acc = _load_m5_module()


def _make_valid_tools_list(lang: str = "en") -> List[Dict[str, Any]]:
    if lang == "zh":
        decomp_desc = "【实验性・未通过验收】[EXPERIMENTAL / UNVERIFIED] 为恢复的函数生成伪 C 代码。"
        audit_desc = "【实验性・未通过验收】[EXPERIMENTAL / UNVERIFIED] 运行静态安全审计插件。"
    else:
        decomp_desc = "[EXPERIMENTAL / UNVERIFIED] Emit Pseudo-C for a recovered ARM64/ARM64e function."
        audit_desc = "[EXPERIMENTAL / UNVERIFIED] Execute JavaScriptCore static binary audit plugins."

    def prop(p_type: str, desc: str) -> Dict[str, str]:
        return {"type": p_type, "description": desc}

    return [
        {
            "name": "mach_inspect_binary",
            "description": "Load a Mach-O / Universal binary and return container & code-signature summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
        {
            "name": "mach_list_symbols",
            "description": "List symtab and inferred symbols as JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "filter": prop("string", "Optional symbol substring filter."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
        {
            "name": "mach_find_strings",
            "description": "Extract string literals as JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "filter": prop("string", "Optional string substring filter."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
        {
            "name": "mach_disasm_function",
            "description": "Disassemble a single function by symbol or address as JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "symbol": prop("string", "Function symbol name."),
                    "address": prop("string", "Function virtual address."),
                    "count": prop("integer", "Optional instruction cap."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
        {
            "name": "mach_cfg",
            "description": "Build single-function CFG, dominator tree, and natural loops as JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "symbol": prop("string", "Function symbol name."),
                    "address": prop("string", "Function virtual address."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
        {
            "name": "mach_query_xrefs",
            "description": "Query incoming and outgoing cross-references for a virtual address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "address": prop("string", "Virtual address."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath", "address"],
            },
        },
        {
            "name": "mach_decompile_function",
            "description": decomp_desc,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "function": prop("string", "Function name or hex address."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath", "function"],
            },
        },
        {
            "name": "mach_audit_security",
            "description": audit_desc,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "binaryPath": prop("string", "Path to binary file."),
                    "slice": prop("integer", "Optional slice index."),
                },
                "required": ["binaryPath"],
            },
        },
    ]


def _make_mcp_tool_resp(req_id: int, text: str, is_error: bool = False) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "isError": is_error,
            "content": [{"type": "text", "text": text}],
        },
    }


def _make_valid_protocol_bundle(lang: str = "en") -> Dict[str, Any]:
    responses_by_tag: Dict[str, Any] = {
        "initialize": {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "machgraph-mcp", "version": "1.4.0"},
            },
        },
        "tools_list": {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": _make_valid_tools_list(lang)},
        },
        "invalid_json": {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Invalid JSON payload"},
        },
        "unknown_method": {
            "jsonrpc": "2.0",
            "id": 4,
            "error": {"code": -32601, "message": "Method 'bogus/method' not found"},
        },
    }
    next_id = 10
    for err_tag in m5_acc.PROTOCOL_ERROR_CALL_SPECS:
        responses_by_tag[err_tag] = _make_mcp_tool_resp(
            next_id, f"Simulated error diagnostic for {err_tag}", is_error=True
        )
        next_id += 1
    expected_lines = len(responses_by_tag)
    return {
        "responses_by_tag": responses_by_tag,
        "raw_line_count": expected_lines,
        "expected_line_count": expected_lines,
        "lang": lang,
    }


class TestOtoolAndCodesignParsers(unittest.TestCase):
    def test_parse_otool_lc_main_entry_ls(self) -> None:
        sample = """/bin/ls:
Load command 0
      cmd LC_SEGMENT_64
  cmdsize 72
  segname __PAGEZERO
   vmaddr 0x0000000000000000
   vmsize 0x0000000100000000
Load command 1
      cmd LC_SEGMENT_64
  cmdsize 712
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000000008000
Section
  sectname __text
   segname __TEXT
      addr 0x0000000100000960
Load command 12
       cmd LC_MAIN
   cmdsize 24
  entryoff 2400
 stacksize 0
"""
        vmaddr, entryoff, entry_va = m5_acc.parse_otool_lc_main_entry(sample)
        self.assertEqual(vmaddr, 0x100000000)
        self.assertEqual(entryoff, 2400)
        self.assertEqual(entry_va, 0x100000960)

    def test_parse_otool_lc_main_missing_returns_none(self) -> None:
        sample = """/tmp/libfoo.dylib:
Load command 0
      cmd LC_SEGMENT_64
  segname __TEXT
   vmaddr 0x0000000180000000
"""
        vmaddr, entryoff, entry_va = m5_acc.parse_otool_lc_main_entry(sample)
        self.assertEqual(vmaddr, 0x180000000)
        self.assertIsNone(entryoff)
        self.assertIsNone(entry_va)

    def test_parse_codesign_dvvv_extracts_full_and_short_cdhash(self) -> None:
        stderr = (
            "Executable=/bin/ls\n"
            "Identifier=com.apple.ls\n"
            "CodeDirectory v=20400 size=790 flags=0x0(none) hashes=18+5 location=embedded\n"
            "CDHash=54097a160b61765dca72b46d0beb36ddf7bbde75\n"
            "CandidateCDHash sha256=54097a160b61765dca72b46d0beb36ddf7bbde75\n"
            "CandidateCDHashFull sha256=54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce\n"
        )
        parsed = m5_acc.parse_codesign_dvvv(stderr, returncode=0)
        self.assertTrue(parsed["is_signed"])
        self.assertEqual(parsed["cdhash_short"], "54097a160b61765dca72b46d0beb36ddf7bbde75")
        self.assertEqual(
            parsed["cdhash_full"],
            "54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce",
        )


class TestProtocolValidation(unittest.TestCase):
    def test_valid_protocol_transcript_passes_en_and_zh(self) -> None:
        for lang in ("en", "zh"):
            bundle = _make_valid_protocol_bundle(lang)
            diffs = m5_acc.validate_protocol_transcript(
                responses_by_tag=bundle["responses_by_tag"],
                raw_line_count=bundle["raw_line_count"],
                expected_line_count=bundle["expected_line_count"],
                lang=lang,
            )
            self.assertEqual(diffs, [], f"unexpected diffs for {lang}: {diffs}")

    def test_notification_emitting_line_fails(self) -> None:
        bundle = _make_valid_protocol_bundle("en")
        diffs = m5_acc.validate_protocol_transcript(
            responses_by_tag=bundle["responses_by_tag"],
            raw_line_count=bundle["expected_line_count"] + 1,
            expected_line_count=bundle["expected_line_count"],
            lang="en",
        )
        self.assertTrue(any(d["kind"] == "NOTIFICATION_OR_LINE_COUNT_MISMATCH" for d in diffs))

    def test_missing_tool_or_incomplete_schema_fails(self) -> None:
        bundle = _make_valid_protocol_bundle("en")
        tools = copy.deepcopy(bundle["responses_by_tag"]["tools_list"]["result"]["tools"])
        # Drop mach_cfg -> 7 tools
        bundle["responses_by_tag"]["tools_list"]["result"]["tools"] = [
            t for t in tools if t["name"] != "mach_cfg"
        ]
        diffs = m5_acc.validate_protocol_transcript(
            responses_by_tag=bundle["responses_by_tag"],
            raw_line_count=bundle["raw_line_count"],
            expected_line_count=bundle["expected_line_count"],
            lang="en",
        )
        self.assertTrue(any(d["kind"] == "TOOLS_LIST_MISMATCH" for d in diffs))

        # Restore 8 tools, remove description on binaryPath property
        bundle2 = _make_valid_protocol_bundle("en")
        del bundle2["responses_by_tag"]["tools_list"]["result"]["tools"][0]["inputSchema"]["properties"]["binaryPath"]["description"]
        diffs2 = m5_acc.validate_protocol_transcript(
            responses_by_tag=bundle2["responses_by_tag"],
            raw_line_count=bundle2["raw_line_count"],
            expected_line_count=bundle2["expected_line_count"],
            lang="en",
        )
        self.assertTrue(any(d["kind"] == "INVALID_INPUT_SCHEMA" for d in diffs2))

    def test_missing_unverified_in_tool_description_fails(self) -> None:
        bundle = _make_valid_protocol_bundle("en")
        for t in bundle["responses_by_tag"]["tools_list"]["result"]["tools"]:
            if t["name"] == "mach_decompile_function":
                t["description"] = "[Experimental] Emit Pseudo-C."
        diffs = m5_acc.validate_protocol_transcript(
            responses_by_tag=bundle["responses_by_tag"],
            raw_line_count=bundle["raw_line_count"],
            expected_line_count=bundle["expected_line_count"],
            lang="en",
        )
        self.assertTrue(any(d["kind"] == "DESCRIPTION_MISSING_UNVERIFIED" for d in diffs))

    def test_wrong_error_codes_and_false_is_error_fail(self) -> None:
        bundle = _make_valid_protocol_bundle("en")
        bundle["responses_by_tag"]["invalid_json"]["error"]["code"] = -32600
        bundle["responses_by_tag"]["unknown_method"]["error"]["code"] = -32000
        first_err_tag = next(iter(m5_acc.PROTOCOL_ERROR_CALL_SPECS))
        bundle["responses_by_tag"][first_err_tag] = _make_mcp_tool_resp(99, "ok", is_error=False)
        diffs = m5_acc.validate_protocol_transcript(
            responses_by_tag=bundle["responses_by_tag"],
            raw_line_count=bundle["raw_line_count"],
            expected_line_count=bundle["expected_line_count"],
            lang="en",
        )
        kinds = {d["kind"] for d in diffs}
        self.assertIn("WRONG_JSONRPC_ERROR_CODE", kinds)
        self.assertIn("EXPECTED_TOOL_ERROR", kinds)


class TestToolsByteComparison(unittest.TestCase):
    def test_exact_byte_match_passes_and_single_byte_diff_fails(self) -> None:
        cli_json = json.dumps(
            {
                "address": 4294969696,
                "addressHex": "0x0000000100000960",
                "fileName": "ls",
                "function": "_entry",
                "instructions": [
                    {"address": 4294969696, "disassembly": "pacibsp"},
                    {"address": 4294969700, "disassembly": "stp x28, x27, [sp, #-0x60]!"},
                ],
                "isDemo": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
        mcp_ok = _make_mcp_tool_resp(1, cli_json, is_error=False)
        diffs_ok = m5_acc.compare_mcp_tool_with_cli_bytes(
            case_name="ls_disasm_entry",
            mcp_resp=mcp_ok,
            cli_returncode=0,
            cli_stdout=cli_json.encode("utf-8"),
            cli_stderr=b"",
        )
        self.assertEqual(diffs_ok, [])

        # Mutation 1a simulation: drop last instruction -> must fail BYTE_MISMATCH
        truncated_json = json.dumps(
            {
                "address": 4294969696,
                "addressHex": "0x0000000100000960",
                "fileName": "ls",
                "function": "_entry",
                "instructions": [
                    {"address": 4294969696, "disassembly": "pacibsp"},
                ],
                "isDemo": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
        mcp_mut = _make_mcp_tool_resp(1, truncated_json, is_error=False)
        diffs_mut = m5_acc.compare_mcp_tool_with_cli_bytes(
            case_name="ls_disasm_entry",
            mcp_resp=mcp_mut,
            cli_returncode=0,
            cli_stdout=cli_json.encode("utf-8"),
            cli_stderr=b"",
        )
        self.assertTrue(any(d["kind"] == "BYTE_MISMATCH" for d in diffs_mut))

        # Even a missing trailing newline must fail strict byte-for-byte comparison
        mcp_no_nl = _make_mcp_tool_resp(1, cli_json.rstrip("\n"), is_error=False)
        diffs_nl = m5_acc.compare_mcp_tool_with_cli_bytes(
            case_name="ls_disasm_entry",
            mcp_resp=mcp_no_nl,
            cli_returncode=0,
            cli_stdout=cli_json.encode("utf-8"),
            cli_stderr=b"",
        )
        self.assertTrue(any(d["kind"] == "BYTE_MISMATCH" for d in diffs_nl))


class TestLegacyChecks(unittest.TestCase):
    def test_inspect_cdhash_matches_and_detects_mismatch(self) -> None:
        full_hash = "54097a160b61765dca72b46d0beb36ddf7bbde75266276c007734fadffa899ce"
        cs_info = {
            "is_signed": True,
            "cdhash_full": full_hash,
            "cdhash_short": full_hash[:40],
        }
        mcp_ok = _make_mcp_tool_resp(
            1,
            f"file=ls format=Mach-O Universal Fat arch=arm64e (PAC) functions=50 insns=4090 cdhash={full_hash}",
        )
        self.assertEqual(m5_acc.validate_legacy_inspect_cdhash("/bin/ls", mcp_ok, cs_info), [])

        mcp_bad = _make_mcp_tool_resp(
            1,
            "file=ls format=Mach-O Universal Fat arch=arm64e (PAC) functions=50 insns=4090 cdhash=deadbeef",
        )
        diffs = m5_acc.validate_legacy_inspect_cdhash("/bin/ls", mcp_bad, cs_info)
        self.assertTrue(any(d["kind"] == "CDHASH_MISMATCH" for d in diffs))

    def test_xrefs_bidirectional_catches_missing_outgoing(self) -> None:
        cli_xrefs_obj = {
            "address": 0x100000FE0,
            "addressHex": "0x0000000100000fe0",
            "incoming": [
                {
                    "fromAddress": 0x100000B30,
                    "fromAddressHex": "0x0000000100000b30",
                    "toAddress": 0x100000FE0,
                    "toAddressHex": "0x0000000100000fe0",
                    "kind": "JMP",
                    "instructionPreview": "br x16",
                }
            ],
            "outgoing": [
                {
                    "fromAddress": 0x100000FE0,
                    "fromAddressHex": "0x0000000100000fe0",
                    "toAddress": 0x1000042EC,
                    "toAddressHex": "0x00000001000042ec",
                    "kind": "CALL",
                    "instructionPreview": "bl 0x1000042ec",
                }
            ],
        }
        good_text = (
            "to=1 from=1\n"
            "<- 0x0000000100000b30 [JMP] br x16\n"
            "-> 0x00000001000042ec [CALL] bl 0x1000042ec"
        )
        self.assertEqual(
            m5_acc.validate_legacy_xrefs_bidirectional(
                "/bin/ls", "0x100000fe0", _make_mcp_tool_resp(1, good_text), cli_xrefs_obj
            ),
            [],
        )

        # Pre-M5 bug: outgoing omitted despite from=1
        buggy_text = "to=1 from=1\n<- 0x0000000100000b30 [JMP] br x16"
        diffs = m5_acc.validate_legacy_xrefs_bidirectional(
            "/bin/ls", "0x100000fe0", _make_mcp_tool_resp(1, buggy_text), cli_xrefs_obj
        )
        self.assertTrue(any(d["kind"] == "MISSING_OUTGOING_XREFS" for d in diffs))

    def test_unverified_banners_and_audit_format_en_and_zh(self) -> None:
        decomp_en = _make_mcp_tool_resp(
            1,
            "// EXPERIMENTAL: [EXPERIMENTAL / UNVERIFIED] Decompiler output has not passed acceptance.\nint _entry(void) {\n    return 0;\n}",
        )
        decomp_zh = _make_mcp_tool_resp(
            2,
            "// 【实验性】【未通过验收】反编译输出尚未通过验收：已知条件表达式还原不可靠。\nint _entry(void) {\n    return 0;\n}",
        )
        self.assertEqual(m5_acc.validate_unverified_banner("mach_decompile_function", "en", decomp_en), [])
        self.assertEqual(m5_acc.validate_unverified_banner("mach_decompile_function", "zh", decomp_zh), [])

        cli_audit_en = (
            "# [EXPERIMENTAL / UNVERIFIED] Static heuristic plugin output has not passed acceptance.\n"
            "[HIGH] 0x00000001000044b0 (builtin.unsafe-c) Unsafe C API - strcpy usage"
        )
        cli_audit_zh = (
            "# 【实验性・未通过验收】静态启发式安全审计插件尚未通过验收：已知存在误报与漏报。\n"
            "[HIGH] 0x00000001000044b0 (builtin.unsafe-c) 不安全 C 函数 - strcpy"
        )
        self.assertEqual(
            m5_acc.validate_unverified_banner(
                "mach_audit_security",
                "en",
                _make_mcp_tool_resp(3, cli_audit_en),
                expected_cli_audit_text=cli_audit_en,
            ),
            [],
        )
        self.assertEqual(
            m5_acc.validate_unverified_banner(
                "mach_audit_security",
                "zh",
                _make_mcp_tool_resp(4, cli_audit_zh),
                expected_cli_audit_text=cli_audit_zh,
            ),
            [],
        )

        # Mutation 1b: drop UNVERIFIED / 未通过验收 on line 1 -> must fail
        old_decomp_en = _make_mcp_tool_resp(
            5, "// EXPERIMENTAL: Decompiler output — condition expressions are known to be unreliable.\nint f(void) {}"
        )
        diffs_en = m5_acc.validate_unverified_banner("mach_decompile_function", "en", old_decomp_en)
        self.assertTrue(any(d["kind"] == "MISSING_UNVERIFIED_MARKER" for d in diffs_en))

        old_decomp_zh = _make_mcp_tool_resp(
            6, "// 【实验性】反编译输出：已知条件表达式还原不可靠。\nint f(void) {}"
        )
        diffs_zh = m5_acc.validate_unverified_banner("mach_decompile_function", "zh", old_decomp_zh)
        self.assertTrue(any(d["kind"] == "MISSING_UNVERIFIED_MARKER" for d in diffs_zh))

        # Pre-M5 audit raw JSON leak -> must fail
        raw_json_audit = _make_mcp_tool_resp(
            7, "// [EXPERIMENTAL / UNVERIFIED] Audit\n[{\"pluginID\":\"x\"}]"
        )
        diffs_raw = m5_acc.validate_unverified_banner(
            "mach_audit_security",
            "en",
            raw_json_audit,
            expected_cli_audit_text=cli_audit_en,
        )
        kinds = {d["kind"] for d in diffs_raw}
        self.assertTrue("AUDIT_RAW_JSON_LEAK" in kinds or "AUDIT_CLI_MISMATCH" in kinds)

    def test_sanitize_text_redacts_home_and_email(self) -> None:
        fake_user_path = os.sep + "Users" + os.sep + "alice/secret/bin"
        fake_email = "alice" + "\x40" + "example.com"
        cleaned = m5_acc.sanitize_text(f"ran on {fake_user_path} by {fake_email}")
        self.assertNotIn("alice", cleaned)
        self.assertIn("<home>", cleaned)
        self.assertIn("<redacted-email>", cleaned)


if __name__ == "__main__":
    unittest.main()
