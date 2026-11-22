#!/usr/bin/env python3
"""Unit tests for `m5-mcp-acceptance.py` using handcrafted synthetic fixtures."""

import contextlib
import copy
import importlib.util
import io
import json
import os
import sys
import unittest
from typing import Any, Dict, List
from unittest import mock

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


def _load_m5_lib_examples_module():
    path = os.path.join(SCRIPT_DIR, "m5-lib-examples.py")
    spec = importlib.util.spec_from_file_location("m5_lib_examples_mod", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["m5_lib_examples_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


m5_acc = _load_m5_module()
m5_lib = _load_m5_lib_examples_module()


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


def _make_sample_lib_markdown(lang: str = "en") -> str:
    heading = "# Library Examples" if lang == "en" else "# 库使用示例"
    prose1 = "Read header:" if lang == "en" else "读取头部："
    prose2 = "Decode A64:" if lang == "en" else "解码指令："
    prose3 = "Build CFG:" if lang == "en" else "构建控制流图："
    return f"""{heading}

Optional Package.swift snippet that must be ignored by example extraction:

```swift
// swift-tools-version: 6.0
import PackageDescription
```

## 1. MachBinaryFormats
{prose1}

```swift
import MachBinaryFormats

@main
struct BinaryFormatsDemo {{
    static func main() throws {{
        let image = try UniversalBinaryDispatcher.load(filePath: "/bin/ls")
        print("format=\\(image.containerFormat.rawValue)")
    }}
}}
```

```text
format=Mach-O Universal Fat
```

## 2. MachA64Decoder
{prose2}

```swift
import MachA64Decoder

@main
struct A64DecoderDemo {{
    static func main() throws {{
        let base = VirtualAddress(0x1_0000_0000)
        let insn = A64InstructionDecoder().decode(word: 0xd65f03c0, at: base)
        print("\\(insn.address.hexString)  \\(insn.formattedDisassembly)")
    }}
}}
```

```text
0x0000000100000000  ret
```

## 3. MachCFGEngine
{prose3}

```swift
import Foundation
import MachCFGEngine

@main
struct CFGEngineDemo {{
    static func main() throws {{
        let snapshot = try BinaryAnalysisCoordinator().analyzeCFGOnly(
            fileURL: URL(fileURLWithPath: "/bin/ls"),
            selector: .address(VirtualAddress(0x1_0000_0960))
        )
        print("functions=\\(snapshot.boundariesByAddress.count)")
    }}
}}
```

```text
functions=133
```
"""


class TestLibExamplesMarkdownAndChecks(unittest.TestCase):
    def test_extract_and_validate_bilingual_examples_passes_and_skips_package_manifest(self) -> None:
        md_en = _make_sample_lib_markdown("en")
        md_zh = _make_sample_lib_markdown("zh")
        blocks_en = m5_lib.extract_swift_example_blocks(md_en)
        blocks_zh = m5_lib.extract_swift_example_blocks(md_zh)
        self.assertEqual(len(blocks_en), 3)
        self.assertEqual([b["module"] for b in blocks_en], ["MachBinaryFormats", "MachA64Decoder", "MachCFGEngine"])
        diffs = m5_lib.validate_markdown_example_pair(blocks_en, blocks_zh)
        self.assertEqual(diffs, [])

    def test_bilingual_code_mismatch_over_20_lines_and_explicit_models_import_fail(self) -> None:
        md_en = _make_sample_lib_markdown("en")
        md_zh_diff = _make_sample_lib_markdown("zh").replace("0xd65f03c0", "0xd503201f")
        diffs_mismatch = m5_lib.validate_markdown_example_pair(
            m5_lib.extract_swift_example_blocks(md_en),
            m5_lib.extract_swift_example_blocks(md_zh_diff),
        )
        self.assertTrue(any(d["kind"] == "DOC_CODE_MISMATCH" for d in diffs_mismatch))

        # > 20 lines in example 2
        long_lines = "\n".join(f"        let v{i} = {i}" for i in range(18))
        md_too_long = md_en.replace(
            "        let base = VirtualAddress(0x1_0000_0000)",
            f"        let base = VirtualAddress(0x1_0000_0000)\n{long_lines}",
        )
        blocks_long = m5_lib.extract_swift_example_blocks(md_too_long)
        diffs_long = m5_lib.validate_markdown_example_pair(blocks_long, blocks_long)
        self.assertTrue(any(d["kind"] == "EXAMPLE_TOO_LONG" for d in diffs_long))

        # Explicit `import MachGraphModels` must be rejected (examples must rely on @_exported)
        md_explicit_models = md_en.replace(
            "import MachA64Decoder",
            "import MachA64Decoder\nimport MachGraphModels",
        )
        blocks_models = m5_lib.extract_swift_example_blocks(md_explicit_models)
        diffs_models = m5_lib.validate_markdown_example_pair(blocks_models, blocks_models)
        self.assertTrue(any(d["kind"] == "FORBIDDEN_IMPORT" for d in diffs_models))

    def test_build_warnings_and_output_comparison_catch_regressions(self) -> None:
        self.assertEqual(
            m5_lib.validate_clean_swift_build("DemoA64", returncode=0, stdout="Build complete!\n", stderr=""),
            [],
        )
        warn_diffs = m5_lib.validate_clean_swift_build(
            "DemoA64",
            returncode=0,
            stdout="",
            stderr="/tmp/Demo.swift:4:9: warning: initialization of immutable value 'x' was never used\n",
        )
        self.assertTrue(any(d["kind"] == "BUILD_WARNING" for d in warn_diffs))

        # Output comparison: exact match passes; stride 4->8 truncation (Mutation 2a) fails
        ref_out = (
            "0x0000000100000000  d10043ff  sub sp, sp, #0x10\n"
            "0x0000000100000004  52800540  mov w0, #0x2a\n"
        )
        self.assertEqual(
            m5_lib.validate_example_output(
                module_name="MachA64Decoder",
                actual_returncode=0,
                actual_stdout=ref_out,
                actual_stderr="",
                reference_stdout=ref_out,
                doc_en_expected=ref_out.strip(),
                doc_zh_expected=ref_out.strip(),
            ),
            [],
        )
        diffs_mut2a = m5_lib.validate_example_output(
            module_name="MachA64Decoder",
            actual_returncode=0,
            actual_stdout="0x0000000100000000  d10043ff  sub sp, sp, #0x10\n",
            actual_stderr="",
            reference_stdout=ref_out,
            doc_en_expected=ref_out.strip(),
            doc_zh_expected=ref_out.strip(),
        )
        self.assertTrue(any(d["kind"] == "RUNTIME_OUTPUT_MISMATCH" for d in diffs_mut2a))

        diffs_doc_out = m5_lib.validate_example_output(
            module_name="MachA64Decoder",
            actual_returncode=0,
            actual_stdout=ref_out,
            actual_stderr="",
            reference_stdout=ref_out,
            doc_en_expected="wrong expected output",
            doc_zh_expected=ref_out.strip(),
        )
        self.assertTrue(any(d["kind"] == "DOC_EXPECTED_OUTPUT_MISMATCH" for d in diffs_doc_out))

    def test_negative_probe_validator_enforces_nonzero_and_access_level_diagnostic(self) -> None:
        # 1. Valid `package` protection level error -> passes
        self.assertEqual(
            m5_lib.validate_negative_probe_result(
                probe_name="ELF64Loader_package",
                symbol="ELF64Loader",
                module="MachBinaryFormats",
                returncode=1,
                stdout="",
                stderr="main.swift:3:28: error: 'ELF64Loader' is inaccessible due to 'package' protection level\n",
            ),
            [],
        )
        # 2. Valid `internal` stripped symbol error -> passes
        self.assertEqual(
            m5_lib.validate_negative_probe_result(
                probe_name="signExtend_internal",
                symbol="signExtend",
                module="MachA64Decoder",
                returncode=1,
                stdout="",
                stderr="main.swift:2:7: error: cannot find 'signExtend' in scope\n",
            ),
            [],
        )
        self.assertEqual(
            m5_lib.validate_negative_probe_result(
                probe_name="signExtend_qualified",
                symbol="signExtend",
                module="MachA64Decoder",
                returncode=1,
                stdout="",
                stderr="main.swift:2:22: error: module 'MachA64Decoder' has no member named 'signExtend'\n",
            ),
            [],
        )
        # 3. Valid removed product error -> passes
        self.assertEqual(
            m5_lib.validate_negative_probe_result(
                probe_name="removed_product_MachMicroDecompiler",
                symbol="MachMicroDecompiler",
                module="MachGraph",
                returncode=1,
                stdout="",
                stderr="error: product 'MachMicroDecompiler' required by package 'neg' target 'T' not found in package 'MachGraph'.\n",
            ),
            [],
        )
        # 4. Mutation 2b: symbol leaked back as `public` -> returncode == 0 MUST FAIL
        leaked_diffs = m5_lib.validate_negative_probe_result(
            probe_name="ELF64Loader_package",
            symbol="ELF64Loader",
            module="MachBinaryFormats",
            returncode=0,
            stdout="Build complete!\n",
            stderr="",
        )
        self.assertTrue(any(d["kind"] == "NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED" for d in leaked_diffs))

        # 5. Non-zero exit due to syntax error or wrong symbol MUST FAIL (not an access-level rejection)
        syntax_diffs = m5_lib.validate_negative_probe_result(
            probe_name="ELF64Loader_package",
            symbol="ELF64Loader",
            module="MachBinaryFormats",
            returncode=1,
            stdout="",
            stderr="main.swift:3:50: error: expected ')' in argument list\n",
        )
        self.assertTrue(any(d["kind"] == "NEGATIVE_PROBE_WRONG_DIAGNOSTIC" for d in syntax_diffs))

    def test_default_doc_paths_are_bilingual_readmes_and_expected_outputs_match_verbatim(self) -> None:
        captured: Dict[str, Any] = {}

        def fake_suite(repo_root: str, en_doc_path: str, zh_doc_path: str, verbose: bool = False) -> Dict[str, Any]:
            captured["repo_root"] = repo_root
            captured["en_doc_path"] = en_doc_path
            captured["zh_doc_path"] = zh_doc_path
            return {
                "passed": True,
                "en_doc": "README.md",
                "zh_doc": "README.zh-CN.md",
                "examples": [
                    {
                        "module": mod,
                        "line_count": 12,
                        "build_returncode": 0,
                        "build_elapsed_s": 0.1,
                        "run_returncode": 0,
                        "run_elapsed_s": 0.01,
                        "actual_output": "ok",
                        "reference_output": "ok",
                    }
                    for mod in ("MachBinaryFormats", "MachA64Decoder", "MachCFGEngine")
                ],
                "negative_probes": [],
                "diffs": [],
                "elapsed_s": 0.3,
                "timestamp_utc": "2026-11-22T12:00:00Z",
            }

        with tempfile.TemporaryDirectory(prefix="test-m5-default-readme-") as tmp:
            with mock.patch.object(m5_lib, "run_acceptance_suite", side_effect=fake_suite), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc = m5_lib.main(["--repo-root", tmp])
            self.assertEqual(rc, 0)
            self.assertEqual(captured["en_doc_path"], os.path.join(os.path.abspath(tmp), "README.md"))
            self.assertEqual(captured["zh_doc_path"], os.path.join(os.path.abspath(tmp), "README.zh-CN.md"))

        # Verbatim equality across EN and ZH READMEs must also hold for adjacent expected-output blocks
        md_en = _make_sample_lib_markdown("en")
        md_zh_out_diff = _make_sample_lib_markdown("zh").replace("functions=133", "functions=134")
        diffs_out = m5_lib.validate_markdown_example_pair(
            m5_lib.extract_swift_example_blocks(md_en),
            m5_lib.extract_swift_example_blocks(md_zh_out_diff),
        )
        self.assertTrue(
            any(d["kind"] == "DOC_EXPECTED_OUTPUT_MISMATCH_EN_ZH" for d in diffs_out),
            f"Expected DOC_EXPECTED_OUTPUT_MISMATCH_EN_ZH when EN/ZH expected outputs differ, got {diffs_out}",
        )


import subprocess  # noqa: E402
import tempfile  # noqa: E402
from typing import Optional, Tuple  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def _load_m5_mutations_test_module():
    path = os.path.join(SCRIPT_DIR, "test_m5_mutations.py")
    spec = importlib.util.spec_from_file_location("test_m5_mutations_mod", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["test_m5_mutations_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


TestM5MutationsSuite = _load_m5_mutations_test_module().TestM5MutationsSuite


class TestReleaseGateAndStepScheduler(unittest.TestCase):
    """Self-tests for Scripts/test.sh release step wiring, --only, skip=77, and exit-code precedence."""

    TEST_SH = os.path.join(REPO_ROOT, "Scripts", "test.sh")

    def _make_stub_script(self, tmp_dir: str) -> Tuple[str, str]:
        log_file = os.path.join(tmp_dir, "invoked_steps.log")
        stub_path = os.path.join(tmp_dir, "release_stub.sh")
        with open(stub_path, "w", encoding="utf-8") as fh:
            fh.write(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'step="$1"\n'
                "shift\n"
                f'echo "$step" >> "{log_file}"\n'
                'if [ "$step" = "m4-ghidra" ]; then\n'
                '    if [ -z "${GHIDRA_INSTALL_DIR:-}" ] || [ -z "${JAVA_HOME:-}" ]; then\n'
                '        exec "$@"\n'
                "    fi\n"
                "fi\n"
                'if [ "${STUB_FAIL_STEP:-}" = "$step" ]; then\n'
                '    exit "${STUB_FAIL_RC:-1}"\n'
                "fi\n"
                "exit 0\n"
            )
        os.chmod(stub_path, 0o755)
        return stub_path, log_file

    def _run_release(
        self,
        args: List[str],
        extra_env: Dict[str, Optional[str]],
    ) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        for k, v in extra_env.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return subprocess.run(
            ["bash", self.TEST_SH, "release", *args],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=30,
        )

    def test_mutations_and_release_step_inventory_include_m2_and_m5(self) -> None:
        with open(self.TEST_SH, "r", encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("Scripts/acceptance/m5-mutations.sh", src)

        res = subprocess.run(
            ["bash", self.TEST_SH, "release", "--list-steps"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, f"--list-steps failed: {res.stderr}")
        step_ids = [
            line.split("\t", 1)[0].strip()
            for line in res.stdout.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        expected_subset = [
            # M2 7 items (dual fuzz seeds = 8 steps)
            "test-asm-harnesses",
            "encoding-table",
            "encoding-fuzz-20261117",
            "encoding-fuzz-17",
            "asm-roundtrip-standard",
            "asm-clang-standard",
            "asm-clang-cases",
            "known-mnemonics",
            # M4 Ghidra
            "m4-ghidra",
            # M5 items + mutations
            "test-m5-harnesses",
            "m5-mcp-protocol",
            "m5-mcp-tools",
            "m5-mcp-legacy",
            "m5-mcp-perf",
            "m5-lib-examples",
            "m5-mutations",
            # Full corpus steps
            "differential-full",
            "macho-differential-full",
            "m3-metadata-full",
            "m4-cfg-full",
        ]
        for req in expected_subset:
            self.assertIn(req, step_ids, f"Missing release step '{req}' in --list-steps")

    def test_unknown_only_step_is_rejected(self) -> None:
        res = self._run_release(["--only", "nonexistent-step"], {})
        self.assertEqual(res.returncode, 2)

    def test_five_release_exit_and_skip_scenarios_with_stubs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="test-m5-release-gate-") as tmp:
            stub_path, log_file = self._make_stub_script(tmp)
            fake_ghidra = os.path.join(tmp, "ghidra")
            fake_java = os.path.join(tmp, "jdk")
            os.makedirs(os.path.join(fake_ghidra, "support"), exist_ok=True)
            os.makedirs(os.path.join(fake_java, "bin"), exist_ok=True)
            headless = os.path.join(fake_ghidra, "support", "analyzeHeadless")
            java_bin = os.path.join(fake_java, "bin", "java")
            for p in (headless, java_bin):
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\nexit 0\n")
                os.chmod(p, 0o755)

            # 1) All pass -> exit 0 (MACHGRAPH_CORPUS unset defaults to full, so differential-full runs!)
            r_pass = self._run_release(
                ["--only", "m0-quick,m4-ghidra,differential-full"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": None,
                    "GHIDRA_INSTALL_DIR": fake_ghidra,
                    "JAVA_HOME": fake_java,
                    "STUB_FAIL_STEP": None,
                },
            )
            self.assertEqual(r_pass.returncode, 0, f"Scenario 1 failed:\n{r_pass.stdout}\n{r_pass.stderr}")
            self.assertIn("m0-quick", r_pass.stdout)
            self.assertIn("m4-ghidra", r_pass.stdout)
            self.assertIn("differential-full", r_pass.stdout)
            with open(log_file, "r", encoding="utf-8") as fh:
                ran_1 = fh.read().splitlines()
            self.assertEqual(ran_1, ["m0-quick", "m4-ghidra", "differential-full"])

            # 2) One step fails -> non-zero (and != 77), remaining steps still run and table printed
            open(log_file, "w", encoding="utf-8").close()
            r_fail = self._run_release(
                ["--only", "m0-quick,encoding-table,known-mnemonics"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "full",
                    "GHIDRA_INSTALL_DIR": fake_ghidra,
                    "JAVA_HOME": fake_java,
                    "STUB_FAIL_STEP": "encoding-table",
                    "STUB_FAIL_RC": "1",
                },
            )
            self.assertNotEqual(r_fail.returncode, 0)
            self.assertNotEqual(r_fail.returncode, 77)
            with open(log_file, "r", encoding="utf-8") as fh:
                ran_2 = fh.read().splitlines()
            self.assertEqual(ran_2, ["m0-quick", "encoding-table", "known-mnemonics"])

            # 3) Missing Ghidra env vars -> rest of steps run, exits 77, prints skipped step name
            open(log_file, "w", encoding="utf-8").close()
            r_gh_skip = self._run_release(
                ["--only", "m0-quick,m4-ghidra,known-mnemonics"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "full",
                    "GHIDRA_INSTALL_DIR": None,
                    "JAVA_HOME": None,
                    "STUB_FAIL_STEP": None,
                },
            )
            self.assertEqual(r_gh_skip.returncode, 77, f"Scenario 3 failed:\n{r_gh_skip.stdout}\n{r_gh_skip.stderr}")
            self.assertIn("m4-ghidra", r_gh_skip.stdout)
            self.assertIn("SKIPPED", r_gh_skip.stdout)
            with open(log_file, "r", encoding="utf-8") as fh:
                ran_3 = fh.read().splitlines()
            self.assertEqual(ran_3, ["m0-quick", "m4-ghidra", "known-mnemonics"])

            # 4) MACHGRAPH_CORPUS=standard -> full steps marked skipped without executing, exits 77
            open(log_file, "w", encoding="utf-8").close()
            r_corpus_skip = self._run_release(
                ["--only", "m0-quick,differential-full,m4-cfg-full"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "standard",
                    "GHIDRA_INSTALL_DIR": fake_ghidra,
                    "JAVA_HOME": fake_java,
                    "STUB_FAIL_STEP": None,
                },
            )
            self.assertEqual(
                r_corpus_skip.returncode,
                77,
                f"Scenario 4 failed:\n{r_corpus_skip.stdout}\n{r_corpus_skip.stderr}",
            )
            self.assertIn("differential-full", r_corpus_skip.stdout)
            self.assertIn("m4-cfg-full", r_corpus_skip.stdout)
            with open(log_file, "r", encoding="utf-8") as fh:
                ran_4 = fh.read().splitlines()
            self.assertEqual(ran_4, ["m0-quick"], "full steps must not execute when MACHGRAPH_CORPUS!=full")

            # 5a) One step skipped + one step failed (skip first, fail second) -> non-zero and != 77
            open(log_file, "w", encoding="utf-8").close()
            r_both_a = self._run_release(
                ["--only", "m4-ghidra,encoding-table"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "full",
                    "GHIDRA_INSTALL_DIR": None,
                    "JAVA_HOME": None,
                    "STUB_FAIL_STEP": "encoding-table",
                    "STUB_FAIL_RC": "1",
                },
            )
            self.assertNotEqual(r_both_a.returncode, 0)
            self.assertNotEqual(r_both_a.returncode, 77)

            # 5b) One step failed + one step skipped (fail first, skip second) -> non-zero and != 77
            open(log_file, "w", encoding="utf-8").close()
            r_both_b = self._run_release(
                ["--only", "encoding-table,differential-full"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "standard",
                    "GHIDRA_INSTALL_DIR": fake_ghidra,
                    "JAVA_HOME": fake_java,
                    "STUB_FAIL_STEP": "encoding-table",
                    "STUB_FAIL_RC": "1",
                },
            )
            self.assertNotEqual(r_both_b.returncode, 0)
            self.assertNotEqual(r_both_b.returncode, 77)

    def test_stub_mode_prints_warnings_at_start_and_summary_and_never_claims_release_passed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="test-m5-release-stub-warn-") as tmp:
            stub_path, _ = self._make_stub_script(tmp)
            r_stub = self._run_release(
                ["--only", "m0-quick,known-mnemonics"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": stub_path,
                    "MACHGRAPH_CORPUS": "full",
                    "STUB_FAIL_STEP": None,
                },
            )
            self.assertEqual(r_stub.returncode, 0, f"Stub self-test should still exit 0:\n{r_stub.stdout}\n{r_stub.stderr}")
            lines = [ln.strip() for ln in r_stub.stdout.splitlines() if ln.strip()]
            self.assertGreaterEqual(len(lines), 4, r_stub.stdout)

            # 1) Prominent warning at the very start (before step execution)
            first_step_idx = next(i for i, ln in enumerate(lines) if ln.startswith("==> [release:"))
            header_lines = "\n".join(lines[:first_step_idx])
            self.assertIn("STUB", header_lines.upper())
            self.assertIn("自测用的替身", header_lines)
            self.assertIn("不是真的发版检查", header_lines)

            # 2) Prominent warning in the summary block
            summary_idx = next(i for i, ln in enumerate(lines) if ln.startswith("=== Release Step Summary"))
            summary_lines = "\n".join(lines[summary_idx:])
            self.assertIn("STUB", summary_lines.upper())
            self.assertIn("自测用的替身", summary_lines)
            self.assertIn("不是真的发版检查", summary_lines)

            # 3) Final line must NOT claim release passed
            last_line = lines[-1]
            self.assertNotIn("[PASS]", last_line)
            self.assertNotIn("passed", last_line.lower())
            self.assertNotIn("通过", last_line)
            self.assertIn("STUB", last_line.upper())

            # 4) Without MACHGRAPH_RELEASE_STUB_SCRIPT, a real fast step prints [PASS] and no stub warning
            r_real = self._run_release(
                ["--only", "known-mnemonics"],
                {
                    "MACHGRAPH_RELEASE_STUB_SCRIPT": None,
                    "MACHGRAPH_CORPUS": "full",
                },
            )
            self.assertEqual(r_real.returncode, 0, f"Real known-mnemonics step failed:\n{r_real.stdout}\n{r_real.stderr}")
            self.assertNotIn("自测用的替身", r_real.stdout)
            real_lines = [ln.strip() for ln in r_real.stdout.splitlines() if ln.strip()]
            self.assertTrue(real_lines[-1].startswith("[PASS] All 1 release step(s) passed"), real_lines[-1])


if __name__ == "__main__":
    unittest.main()
