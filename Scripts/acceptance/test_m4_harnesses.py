#!/usr/bin/env python3
"""Unit tests for `m4-cfg-acceptance.py` and `m4-ghidra-differential.py` using small synthetic fixtures."""

import contextlib
import importlib.util
import io
import os
import struct
import sys
import unittest
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_module(mod_name: str, filename: str):
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


m4_acc = _load_module("m4_cfg_acceptance_mod", "m4-cfg-acceptance.py")
m4_gh = _load_module("m4_ghidra_differential_mod", "m4-ghidra-differential.py")


# ---------------------------------------------------------------------------
# Helpers to encode synthetic ARM64 words & tiny Mach-O slices
# ---------------------------------------------------------------------------


def _encode_uleb128(val: int) -> bytes:
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _encode_b(pc: int, target: int) -> int:
    imm26 = ((target - pc) // 4) & 0x03FFFFFF
    return 0x14000000 | imm26


def _encode_bl(pc: int, target: int) -> int:
    imm26 = ((target - pc) // 4) & 0x03FFFFFF
    return 0x94000000 | imm26


def _encode_b_cond(pc: int, target: int, cond: int = 0) -> int:
    imm19 = ((target - pc) // 4) & 0x7FFFF
    return 0x54000000 | (imm19 << 5) | (cond & 0xF)


def _encode_adr(pc: int, target: int, rd: int) -> int:
    imm21 = (target - pc) & 0x1FFFFF
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _encode_adrp(pc: int, target_page: int, rd: int) -> int:
    imm21 = (((target_page & ~0xFFF) - (pc & ~0xFFF)) >> 12) & 0x1FFFFF
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _encode_add_imm64(rd: int, rn: int, imm12: int, shift12: bool = False) -> int:
    sh = 1 if shift12 else 0
    return 0x91000000 | (sh << 22) | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_br(rn: int) -> int:
    return 0xD61F0000 | ((rn & 0x1F) << 5)


INSN_NOP = 0xD503201F
INSN_RET = 0xD65F03C0
INSN_RETAB = 0xD65F0FFF
INSN_PACIBSP = 0xD503237F
INSN_STP_FP_LR_PRE = 0xA9BF7BFD  # stp x29, x30, [sp, #-0x10]!
INSN_BRK_1 = 0xD4200020
INSN_BRAA_X16_X17 = 0xD71F0A11


def _build_synthetic_macho64(
    text_words: Sequence[int],
    lc_starts_addrs: Sequence[int],
    *,
    cpusubtype: int = 2,
    text_va: int = 0x100000400,
    objc_stub_words: Sequence[int] = (),
    objc_stubs_va: int = 0x100000800,
) -> bytes:
    """Build a minimal valid 64-bit ARM64 Mach-O slice with `__TEXT,__text`, optional
    `__TEXT,__objc_stubs`, and `LC_FUNCTION_STARTS`."""
    base_va = 0x100000000
    text_foff = text_va - base_va
    text_bytes = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in text_words)

    sections_bin = bytearray()
    nsects = 1
    # Section 1: __TEXT,__text (sizeof(section_64) == 80 bytes)
    sections_bin += struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00" + b"\x00" * 9,
        b"__TEXT\x00" + b"\x00" * 9,
        text_va,
        len(text_bytes),
        text_foff,
        2,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )

    objc_bytes = b""
    objc_foff = objc_stubs_va - base_va
    if objc_stub_words:
        nsects += 1
        objc_bytes = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in objc_stub_words)
        sections_bin += struct.pack(
            "<16s16sQQIIIIIIII",
            b"__objc_stubs\x00\x00\x00\x00",
            b"__TEXT\x00" + b"\x00" * 9,
            objc_stubs_va,
            len(objc_bytes),
            objc_foff,
            2,
            0,
            0,
            0x80000408,
            0,
            0,
            0,
        )

    # Encode LC_FUNCTION_STARTS ULEB128 deltas relative to base_va
    fs_blob = bytearray()
    prev = base_va
    for addr in lc_starts_addrs:
        fs_blob += _encode_uleb128(addr - prev)
        prev = addr
    fs_blob += b"\x00\x00\x00\x00"  # trailing zero padding

    raw_end = max(text_foff + len(text_bytes), (objc_foff + len(objc_bytes)) if objc_bytes else 0, 0x400)
    fs_foff = (raw_end + 15) & ~15
    total_size = fs_foff + len(fs_blob)

    seg_cmdsize = 72 + 80 * nsects
    seg_cmd = (
        struct.pack(
            "<II16sQQQQiiII",
            0x19,  # LC_SEGMENT_64
            seg_cmdsize,
            b"__TEXT\x00" + b"\x00" * 9,
            base_va,
            max(0x4000, total_size),
            0,
            total_size,
            5,
            5,
            nsects,
            0,
        )
        + bytes(sections_bin)
    )
    fs_cmd = struct.pack("<IIII", 0x26, 16, fs_foff, len(fs_blob))
    cmds = seg_cmd + fs_cmd
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, cpusubtype, 2, 2, len(cmds), 0x85, 0)

    buf = bytearray(total_size)
    buf[: len(hdr) + len(cmds)] = hdr + cmds
    buf[text_foff : text_foff + len(text_bytes)] = text_bytes
    if objc_bytes:
        buf[objc_foff : objc_foff + len(objc_bytes)] = objc_bytes
    buf[fs_foff : fs_foff + len(fs_blob)] = fs_blob
    return bytes(buf)


def _make_cfg_block(
    bid: int,
    insns: Sequence[int],
    preds: Sequence[int],
    succs: Sequence[int],
    *,
    is_entry: bool = False,
    is_exit: bool = False,
    loop_depth: int = 0,
) -> Dict:
    return {
        "id": bid,
        "startAddress": insns[0],
        "endAddress": insns[-1] + 4,
        "isEntry": is_entry,
        "isExit": is_exit,
        "loopDepth": loop_depth,
        "predecessorIDs": list(preds),
        "successorIDs": list(succs),
        "instructionCount": len(insns),
        "instructionAddresses": list(insns),
    }


def _attach_valid_dom_and_loops(fn_dict: Dict) -> Dict:
    blocks = fn_dict["blocks"]
    edges = fn_dict["edges"]
    entry_id = next(b["id"] for b in blocks if b["isEntry"])
    indep = m4_acc.solve_dominators_and_loops_independent(
        [b["id"] for b in blocks],
        entry_id,
        [(e["sourceBlockID"], e["targetBlockID"]) for e in edges],
    )
    fn_dict["dominatorTree"] = [
        {
            "blockID": b["id"],
            "immediateDominatorID": indep["idom"][b["id"]],
            "dominatedChildrenIDs": indep["children"][b["id"]],
            "dominanceFrontierIDs": indep["dominance_frontiers"][b["id"]],
            "depth": indep["depth"][b["id"]],
        }
        for b in blocks
    ]
    fn_dict["naturalLoops"] = indep["natural_loops"]
    for e in edges:
        e["isBackEdge"] = (e["sourceBlockID"], e["targetBlockID"]) in indep["natural_back_edges"]
    return fn_dict


# ---------------------------------------------------------------------------
# 1. ULEB128, Mach-O / Fat slice & Row 1 (`function-starts`) tests
# ---------------------------------------------------------------------------


class TestULEB128AndFunctionStarts(unittest.TestCase):
    def test_uleb128_and_lc_function_starts_decoding(self) -> None:
        base = 0x100000000
        expected = [0x100000400, 0x10000040C, 0x1000249F0]
        blob = (
            _encode_uleb128(0x400)
            + _encode_uleb128(0x0C)
            + _encode_uleb128(0x245E4)
            + b"\x00\x00\x00"
        )
        self.assertEqual(m4_acc.decode_lc_function_starts_blob(blob, base), expected)

        with self.assertRaises(ValueError):
            m4_acc.decode_uleb128_stream(b"\x81\x82")  # truncated continuation bit

        with self.assertRaises(ValueError):
            m4_acc.decode_uleb128_stream(b"\x80" * 10 + b"\x02")  # >64-bit overflow

    def test_fat_binary_prefers_arm64e_and_parses_lc_function_starts(self) -> None:
        arm64_slice = _build_synthetic_macho64([INSN_RET], [0x100000400], cpusubtype=0)
        arm64e_slice = _build_synthetic_macho64(
            [INSN_PACIBSP, INSN_RETAB, INSN_RET],
            [0x100000400, 0x100000408],
            cpusubtype=2 | (-2147483648),  # 0x80000002 AppleSilicon arm64e
        )
        off0 = 64
        off1 = (off0 + len(arm64_slice) + 15) & ~15
        fat = bytearray(off1 + len(arm64e_slice))
        fat[:8] = struct.pack(">II", 0xCAFEBABE, 2)
        fat[8:28] = struct.pack(">iiIII", 0x0100000C, 0, off0, len(arm64_slice), 4)
        fat[28:48] = struct.pack(">iiIII", 0x0100000C, -2147483646, off1, len(arm64e_slice), 4)
        fat[off0 : off0 + len(arm64_slice)] = arm64_slice
        fat[off1 : off1 + len(arm64e_slice)] = arm64e_slice

        view = m4_acc.parse_macho_arm64_slice(bytes(fat))
        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view.arch, "arm64e")
        self.assertEqual(view.lc_function_starts, [0x100000400, 0x100000408])

    def test_function_starts_subcheck_pass_and_failure_modes(self) -> None:
        # Two 32-byte ObjC stubs ending with `braa x16, x17; brk #1; brk #1`
        stub_slot = [
            _encode_adrp(0x100000800, 0x100004000, 1),
            INSN_NOP,
            _encode_adrp(0x100000808, 0x100004000, 17),
            _encode_add_imm64(17, 17, 0x10),
            INSN_NOP,
            INSN_BRAA_X16_X17,
            INSN_BRK_1,
            INSN_BRK_1,
        ]
        lc_starts = [0x100000400, 0x100000408, 0x100000410]  # 2 code fns + 1 inline jump table
        macho = _build_synthetic_macho64(
            [INSN_NOP, INSN_RET, INSN_NOP, INSN_RET, 0x00000010, 0x00000014],
            lc_starts,
            objc_stub_words=stub_slot + stub_slot,
        )
        view = m4_acc.parse_macho_arm64_slice(macho)
        assert view is not None

        dyld_text = (
            "/tmp/test [arm64e]:\n"
            "    -function_starts:\n"
            "        0x100000400  __TEXT,__text\n"
            "        0x100000408  __TEXT,__text+8\n"
            "        0x100000410  __TEXT,__text+16\n"
        )
        dyld_starts = m4_acc.parse_dyld_info_function_starts_text(dyld_text)
        self.assertEqual(dyld_starts, lc_starts)

        good_info = {
            "functionStartsCount": 3,
            "functionStarts": lc_starts,
            "lcFunctionStarts": lc_starts,
        }
        good_cfg = {
            "lcFunctionStarts": lc_starts,
            "inlineJumpTableStarts": [0x100000410],
            "functions": [
                {"address": 0x100000400, "section": "__TEXT,__text", "isStub": False},
                {"address": 0x100000408, "section": "__TEXT,__text", "isStub": False},
                {"address": 0x100000800, "section": "__TEXT,__objc_stubs", "isStub": True},
                {"address": 0x100000820, "section": "__TEXT,__objc_stubs", "isStub": True},
            ],
        }
        res_ok = m4_acc.check_function_starts_on_loaded(view, dyld_starts, good_info, good_cfg)
        self.assertEqual(res_ok["status"], "pass")
        self.assertEqual(res_ok["diff_count"], 0)

        # Mutation A: `0x100000000` leaked into `info --json`
        bad_info = {
            "functionStartsCount": 4,
            "functionStarts": [0x100000000] + lc_starts,
            "lcFunctionStarts": lc_starts,
        }
        res_hdr = m4_acc.check_function_starts_on_loaded(view, dyld_starts, bad_info, good_cfg)
        self.assertEqual(res_hdr["status"], "fail")
        self.assertTrue(any(e["kind"] == "INFO_CONTAINS_IMAGE_BASE_HEADER" for e in res_hdr["examples"]))

        # Mutation B: MachGraph drops one `__text` function start
        bad_cfg_missing = {
            **good_cfg,
            "functions": [f for f in good_cfg["functions"] if f["address"] != 0x100000408],
        }
        res_miss = m4_acc.check_function_starts_on_loaded(view, dyld_starts, good_info, bad_cfg_missing)
        self.assertEqual(res_miss["status"], "fail")
        self.assertTrue(any(e["kind"] == "CFG_TEXT_UNION_INLINE_JT_MISMATCH" for e in res_miss["examples"]))

        # Mutation C: `__objc_stubs` split at `brk #0x1` (`0x100000818`)
        bad_cfg_objc = {
            **good_cfg,
            "functions": good_cfg["functions"]
            + [{"address": 0x100000818, "name": "fake_brk", "section": "__TEXT,__objc_stubs", "isStub": True}],
        }
        res_objc = m4_acc.check_function_starts_on_loaded(view, dyld_starts, good_info, bad_cfg_objc)
        self.assertEqual(res_objc["status"], "fail")
        self.assertTrue(any(e["kind"] == "OBJC_STUB_FAKE_PADDING_FUNCTION" for e in res_objc["examples"]))


# ---------------------------------------------------------------------------
# 2. `adr` / `adrp+add` / page-aligned `adrp` & inline jump-table checks
# ---------------------------------------------------------------------------


class TestAddressIdiomsAndInlineJumpTables(unittest.TestCase):
    def test_adr_and_adrp_add_target_calculation(self) -> None:
        # Positive & negative `adr`
        pc1 = 0x100001234
        t_pos = 0x100001570
        t_neg = 0x100000960
        w_adr_pos = _encode_adr(pc1, t_pos, rd=8)
        w_adr_neg = _encode_adr(pc1 + 4, t_neg, rd=9)
        self.assertEqual(m4_acc.decode_arm64_insn(w_adr_pos, pc1)["target"], t_pos)
        self.assertEqual(m4_acc.decode_arm64_insn(w_adr_neg, pc1 + 4)["target"], t_neg)

        # `adrp + add` + page-aligned `adrp`
        w_adrp = _encode_adrp(0x10000f3b4, 0x100012000, rd=16)
        w_add = _encode_add_imm64(rd=16, rn=16, imm12=0x838)
        w_adrp_page0 = _encode_adrp(0x10000f3bc, 0x100020000, rd=10)

        refs = m4_acc.compute_referenced_code_addresses(
            [
                (pc1, w_adr_pos),
                (pc1 + 4, w_adr_neg),
                (0x10000f3b4, w_adrp),
                (0x10000f3b8, w_add),
                (0x10000f3bc, w_adrp_page0),
            ]
        )
        self.assertIn(t_pos, refs)
        self.assertIn(t_neg, refs)
        self.assertIn(0x100012838, refs)
        self.assertIn(0x100020000, refs)  # page-aligned table without `add #0`

    def test_inline_jump_table_reference_and_udf_truncation_guard(self) -> None:
        # Function @ 0x100000400..0x100000414:
        #   0x100000400: adrp x10, 0x100000000
        #   0x100000404: add  x10, x10, #0x414   (points to inline jump table at 0x100000414)
        #   0x100000408: br   x8                 (dispatch to 0x10000040c, 0x100000410)
        #   0x10000040c: ret
        #   0x100000410: ret
        #   0x100000414: 0x00000004 (udf #0x4 — table entry 0)
        #   0x100000418: 0x00000008 (udf #0x8 — table entry 1)
        #   0x10000041c: pacibsp    (next function @ 0x10000041c, NOT udf)
        #   0x100000420: retab
        words = [
            _encode_adrp(0x100000400, 0x100000000, rd=10),
            _encode_add_imm64(rd=10, rn=10, imm12=0x414),
            _encode_br(8),
            INSN_RET,
            INSN_RET,
            0x00000004,
            0x00000008,
            INSN_PACIBSP,
            INSN_RETAB,
        ]
        macho = _build_synthetic_macho64(words, [0x100000400, 0x100000414, 0x10000041C])
        view = m4_acc.parse_macho_arm64_slice(macho)
        assert view is not None

        fn0 = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x100000414,
                "name": "_sw_fn",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [
                    _make_cfg_block(0, [0x100000400, 0x100000404, 0x100000408], [], [1, 2], is_entry=True),
                    _make_cfg_block(1, [0x10000040C], [0], [], is_exit=True),
                    _make_cfg_block(2, [0x100000410], [0], [], is_exit=True),
                ],
                "edges": [
                    {"sourceBlockID": 0, "targetBlockID": 1, "kind": "switchCase"},
                    {"sourceBlockID": 0, "targetBlockID": 2, "kind": "switchCase"},
                ],
                "jumpTables": [
                    {
                        "dispatchInstructionAddress": 0x100000408,
                        "tableBaseAddress": 0x100000414,
                        "entryByteSize": 4,
                        "isInlineInCode": True,
                        "targetAddresses": [0x10000040C, 0x100000410],
                    }
                ],
                "inlineJumpTableRanges": [{"start": 0x100000414, "end": 0x10000041C, "size": 8}],
            }
        )
        fn1 = _attach_valid_dom_and_loops(
            {
                "address": 0x10000041C,
                "endAddress": 0x100000424,
                "name": "_next_fn",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [_make_cfg_block(0, [0x10000041C, 0x100000420], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        good_cfg = {
            "inlineJumpTableRanges": [{"start": 0x100000414, "end": 0x10000041C, "size": 8}],
            "functions": [fn0, fn1],
        }
        res_ok = m4_acc.check_invariants_on_loaded(view, good_cfg, {})
        self.assertEqual(res_ok["status"], "pass")

        # Truncate jump table to 1 entry (`0x100000414..0x100000418`), leaving `0x00000008` (`udf #0x8`) right after!
        fn0_trunc = _attach_valid_dom_and_loops(
            {
                **fn0,
                "blocks": [
                    _make_cfg_block(0, [0x100000400, 0x100000404, 0x100000408], [], [1], is_entry=True),
                    _make_cfg_block(1, [0x10000040C], [0], [], is_exit=True),
                ],
                "edges": [{"sourceBlockID": 0, "targetBlockID": 1, "kind": "switchCase"}],
                "jumpTables": [
                    {
                        "dispatchInstructionAddress": 0x100000408,
                        "tableBaseAddress": 0x100000414,
                        "entryByteSize": 4,
                        "isInlineInCode": True,
                        "targetAddresses": [0x10000040C],
                    }
                ],
                "inlineJumpTableRanges": [{"start": 0x100000414, "end": 0x100000418, "size": 4}],
            }
        )
        trunc_cfg = {
            "inlineJumpTableRanges": [{"start": 0x100000414, "end": 0x100000418, "size": 4}],
            "functions": [fn0_trunc, fn1],
        }
        res_trunc = m4_acc.check_invariants_on_loaded(view, trunc_cfg, {})
        self.assertEqual(res_trunc["status"], "fail")
        self.assertTrue(
            any(e["kind"] == "INLINE_JT_FOLLOWED_BY_UDF_POSSIBLE_TRUNCATION" for e in res_trunc["examples"])
        )

        # Wrong `tableBaseAddress` not referenced by `adr` / `adrp+add`
        bad_base_cfg = {
            "inlineJumpTableRanges": [{"start": 0x100000418, "end": 0x10000041C, "size": 4}],
            "functions": [
                {
                    **fn0,
                    "jumpTables": [
                        {
                            "dispatchInstructionAddress": 0x100000408,
                            "tableBaseAddress": 0x100000418,
                            "entryByteSize": 4,
                            "isInlineInCode": True,
                            "targetAddresses": [0x10000040C, 0x100000410],
                        }
                    ],
                },
                fn1,
            ],
        }
        res_unreferenced = m4_acc.check_invariants_on_loaded(view, bad_base_cfg, {})
        self.assertEqual(res_unreferenced["status"], "fail")
        self.assertTrue(
            any(e["kind"] == "INLINE_JT_NOT_REFERENCED_BY_ADR_OR_ADRP_ADD" for e in res_unreferenced["examples"])
        )


# ---------------------------------------------------------------------------
# 3. I1–I4 & Noreturn Verification tests
# ---------------------------------------------------------------------------


class TestCFGInvariantsI1ToI4(unittest.TestCase):
    def _build_noreturn_test_slice(self):
        # Layout:
        #   0x100000400 (_caller):
        #       0x100000400: b.eq 0x10000040c
        #       0x100000404: nop
        #       0x100000408: ret
        #       0x10000040c: bl 0x100000410 (_fatal_wrap)
        #   0x100000410 (_fatal_wrap):
        #       0x100000410: nop
        #       0x100000414: bl 0x100000420 (stub ___stack_chk_fail)
        #   0x100000418 (_normal_callee):
        #       0x100000418: nop
        #       0x10000041c: ret
        #   0x100000420 (stub ___stack_chk_fail):
        #       0x100000420: braa x16, x17
        #   0x100000424 (stub _printf):
        #       0x100000424: braa x16, x17
        words = [
            _encode_b_cond(0x100000400, 0x10000040C),
            INSN_NOP,
            INSN_RET,
            _encode_bl(0x10000040C, 0x100000410),
            INSN_NOP,
            _encode_bl(0x100000414, 0x100000420),
            INSN_NOP,
            INSN_RET,
            INSN_BRAA_X16_X17,
            INSN_BRAA_X16_X17,
        ]
        macho = _build_synthetic_macho64(words, [0x100000400, 0x100000410, 0x100000418])
        view = m4_acc.parse_macho_arm64_slice(macho)
        assert view is not None
        imports = {0x100000420: "___stack_chk_fail", 0x100000424: "_printf"}
        return view, imports

    def test_valid_cfg_with_internal_noreturn_wrapper_passes_i1_to_i4(self) -> None:
        view, imports = self._build_noreturn_test_slice()
        caller = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x100000410,
                "name": "_caller",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [
                    _make_cfg_block(0, [0x100000400], [], [2, 1], is_entry=True),
                    _make_cfg_block(1, [0x100000404, 0x100000408], [0], [], is_exit=True),
                    _make_cfg_block(2, [0x10000040C], [0], [], is_exit=True),
                ],
                "edges": [
                    {"sourceBlockID": 0, "targetBlockID": 2, "kind": "conditionalTrue"},
                    {"sourceBlockID": 0, "targetBlockID": 1, "kind": "conditionalFalse"},
                ],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        fatal_wrap = _attach_valid_dom_and_loops(
            {
                "address": 0x100000410,
                "endAddress": 0x100000418,
                "name": "_fatal_wrap",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [_make_cfg_block(0, [0x100000410, 0x100000414], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        normal_fn = _attach_valid_dom_and_loops(
            {
                "address": 0x100000418,
                "endAddress": 0x100000420,
                "name": "_normal_callee",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [_make_cfg_block(0, [0x100000418, 0x10000041C], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        stub1 = _attach_valid_dom_and_loops(
            {
                "address": 0x100000420,
                "endAddress": 0x100000424,
                "name": "___stack_chk_fail",
                "section": "__TEXT,__auth_stubs",
                "isStub": True,
                "blocks": [_make_cfg_block(0, [0x100000420], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        stub2 = _attach_valid_dom_and_loops(
            {
                "address": 0x100000424,
                "endAddress": 0x100000428,
                "name": "_printf",
                "section": "__TEXT,__auth_stubs",
                "isStub": True,
                "blocks": [_make_cfg_block(0, [0x100000424], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )

        cfg_ok = {"inlineJumpTableRanges": [], "functions": [caller, fatal_wrap, normal_fn, stub1, stub2]}
        res = m4_acc.check_invariants_on_loaded(view, cfg_ok, imports)
        self.assertEqual(res["status"], "pass")
        self.assertEqual(res["diff_count"], 0)
        self.assertEqual(res["noreturn_exit_calls_verified"], 2)

    def test_i1_catches_unverified_noreturn_bl_and_interior_terminator(self) -> None:
        # 1) `bl _printf` (not noreturn!) treated as exit block without fallthrough -> must FAIL I1!
        words = [_encode_bl(0x100000400, 0x100000408), INSN_RET, INSN_BRAA_X16_X17]
        macho = _build_synthetic_macho64(words, [0x100000400])
        view = m4_acc.parse_macho_arm64_slice(macho)
        assert view is not None
        bad_noreturn_fn = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x100000408,
                "name": "_bad_printf_exit",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [
                    _make_cfg_block(0, [0x100000400], [], [], is_entry=True, is_exit=True),
                    _make_cfg_block(1, [0x100000404], [], [], is_exit=True),
                ],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        res = m4_acc.check_invariants_on_loaded(
            view, {"inlineJumpTableRanges": [], "functions": [bad_noreturn_fn]}, {0x100000408: "_printf"}
        )
        self.assertEqual(res["status"], "fail")
        self.assertGreater(res["violations_by_invariant"]["I1"], 0)
        self.assertTrue(any(e["kind"] == "UNVERIFIED_NORETURN_BL_EXIT" for e in res["examples"]))

        # 2) Interior terminator (`b` inside a block before `ret`) -> must FAIL I1!
        words2 = [_encode_b(0x100000400, 0x100000404), INSN_RET]
        view2 = m4_acc.parse_macho_arm64_slice(_build_synthetic_macho64(words2, [0x100000400]))
        assert view2 is not None
        interior_term_fn = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x100000408,
                "name": "_interior_b",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [_make_cfg_block(0, [0x100000400, 0x100000404], [], [], is_entry=True, is_exit=True)],
                "edges": [],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        res2 = m4_acc.check_invariants_on_loaded(view2, {"inlineJumpTableRanges": [], "functions": [interior_term_fn]}, {})
        self.assertEqual(res2["status"], "fail")
        self.assertTrue(any(e["kind"] == "INTERIOR_TERMINATOR" for e in res2["examples"]))

    def test_i2_i3_and_i4_catch_branch_target_overlap_and_idom_errors(self) -> None:
        # Branch `b.eq 0x100000408` lands in the MIDDLE of B1 (`0x100000404..0x10000040c`) -> FAIL I2!
        words = [_encode_b_cond(0x100000400, 0x100000408), INSN_NOP, INSN_RET]
        view = m4_acc.parse_macho_arm64_slice(_build_synthetic_macho64(words, [0x100000400]))
        assert view is not None
        fn_i2 = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x10000040C,
                "name": "_mid_block_branch",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [
                    _make_cfg_block(0, [0x100000400], [], [1], is_entry=True),
                    _make_cfg_block(1, [0x100000404, 0x100000408], [0], [], is_exit=True),
                ],
                "edges": [{"sourceBlockID": 0, "targetBlockID": 1, "kind": "conditionalFalse"}],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        res_i2 = m4_acc.check_invariants_on_loaded(view, {"inlineJumpTableRanges": [], "functions": [fn_i2]}, {})
        self.assertEqual(res_i2["status"], "fail")
        self.assertGreater(res_i2["violations_by_invariant"]["I2"], 0)

        # Overlapping blocks -> FAIL I3; corrupted `immediateDominatorID` -> FAIL I4
        words_d = [
            _encode_b_cond(0x100000400, 0x10000040C),
            _encode_b(0x100000404, 0x100000410),
            INSN_NOP,
            INSN_NOP,
            INSN_RET,
        ]
        view_d = m4_acc.parse_macho_arm64_slice(_build_synthetic_macho64(words_d, [0x100000400]))
        assert view_d is not None
        diamond_fn = _attach_valid_dom_and_loops(
            {
                "address": 0x100000400,
                "endAddress": 0x100000414,
                "name": "_diamond",
                "section": "__TEXT,__text",
                "isStub": False,
                "blocks": [
                    _make_cfg_block(0, [0x100000400], [], [2, 1], is_entry=True),
                    _make_cfg_block(1, [0x100000404], [0], [3]),
                    _make_cfg_block(2, [0x10000040C], [0], [3]),
                    _make_cfg_block(3, [0x100000410], [1, 2], [], is_exit=True),
                ],
                "edges": [
                    {"sourceBlockID": 0, "targetBlockID": 2, "kind": "conditionalTrue"},
                    {"sourceBlockID": 0, "targetBlockID": 1, "kind": "conditionalFalse"},
                    {"sourceBlockID": 1, "targetBlockID": 3, "kind": "unconditional"},
                    {"sourceBlockID": 2, "targetBlockID": 3, "kind": "fallthroughEdge"},
                ],
                "jumpTables": [],
                "inlineJumpTableRanges": [],
            }
        )
        # Corrupt `idom[3]` from `0` to `1`
        for d in diamond_fn["dominatorTree"]:
            if d["blockID"] == 3:
                d["immediateDominatorID"] = 1
        res_i4 = m4_acc.check_invariants_on_loaded(view_d, {"inlineJumpTableRanges": [], "functions": [diamond_fn]}, {})
        self.assertEqual(res_i4["status"], "fail")
        self.assertGreater(res_i4["violations_by_invariant"]["I4"], 0)
        self.assertTrue(any(e["kind"] == "IDOM_MISMATCH" for e in res_i4["examples"]))


# ---------------------------------------------------------------------------
# 4. Independent Iterative Dominator-Set & Natural-Loop Solver tests
# ---------------------------------------------------------------------------


class TestDominatorAndLoopSolver(unittest.TestCase):
    def test_nontrivial_semidominator_graph_and_unreachable_block(self) -> None:
        # Classic graph where Lengauer-Tarjan `semi(w) != idom(w)` + unreachable block 99:
        #   0 -> 1, 0 -> 2
        #   1 -> 4
        #   2 -> 3, 2 -> 5
        #   3 -> 4
        #   5 -> 1
        # Here node 4 is reachable via 0->1->4, 0->2->5->1->4, 0->2->3->4, so `idom[4] == 0` and `idom[1] == 0`!
        block_ids = [0, 1, 2, 3, 4, 5, 99]
        edges = [(0, 1), (0, 2), (1, 4), (2, 3), (2, 5), (3, 4), (5, 1)]
        sol = m4_acc.solve_dominators_and_loops_independent(block_ids, 0, edges)
        self.assertEqual(sol["idom"][0], None)
        self.assertEqual(sol["idom"][1], 0)
        self.assertEqual(sol["idom"][2], 0)
        self.assertEqual(sol["idom"][3], 2)
        self.assertEqual(sol["idom"][4], 0)
        self.assertEqual(sol["idom"][5], 2)
        self.assertEqual(sol["idom"][99], None)
        self.assertEqual(sol["depth"][99], 0)

    def test_nested_loops_and_multi_latch_header(self) -> None:
        # Outer loop header 1 (latch 5 -> 1), inner loop header 2 (latches 3 -> 2 and 4 -> 2), exit 6
        block_ids = [0, 1, 2, 3, 4, 5, 6]
        edges = [
            (0, 1),
            (1, 2),
            (1, 6),
            (2, 3),
            (2, 4),
            (2, 5),
            (3, 2),
            (4, 2),
            (5, 1),
        ]
        sol = m4_acc.solve_dominators_and_loops_independent(block_ids, 0, edges)
        self.assertEqual(sol["natural_back_edges"], {(3, 2), (4, 2), (5, 1)})
        loops = sol["natural_loops"]
        self.assertEqual(len(loops), 2)
        outer = next(lp for lp in loops if lp["headerBlockID"] == 1)
        inner = next(lp for lp in loops if lp["headerBlockID"] == 2)
        self.assertEqual(outer["nestingDepth"], 1)
        self.assertEqual(outer["latchBlockIDs"], [5])
        self.assertEqual(outer["exitBlockIDs"], [6])
        self.assertEqual(inner["nestingDepth"], 2)
        self.assertEqual(inner["latchBlockIDs"], [3, 4])
        self.assertEqual(inner["bodyBlockIDs"], [2, 3, 4])
        self.assertEqual(inner["exitBlockIDs"], [5])


# ---------------------------------------------------------------------------
# 5. Ghidra Differential Environment Gate & Difference Classifier tests
# ---------------------------------------------------------------------------


class TestGhidraDifferentialClassification(unittest.TestCase):
    def test_missing_env_prints_skipped_and_returns_exit_77(self) -> None:
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "", "JAVA_HOME": ""}, clear=False):
            with contextlib.redirect_stdout(buf):
                rc = m4_gh.main(["/bin/ls"])
        self.assertEqual(rc, m4_gh.EXIT_SKIPPED)
        self.assertIn("已跳过、不算通过", buf.getvalue())

    def test_classifies_pac_prologue_split_and_switch_dispatch_isolation_as_non_errors(self) -> None:
        # Fn A @ 0x100000400..0x100000414:
        #   0x100000400: nop
        #   0x100000404: br x16 (switch dispatch -> 0x100000408, 0x10000040c)
        #   0x100000408: ret
        #   0x10000040c: ret
        # Fn B @ 0x100000410..0x10000041c:
        #   0x100000410: pacibsp
        #   0x100000414: stp x29, x30, [sp, #-0x10]!
        #   0x100000418: retab
        words = [
            INSN_NOP,
            _encode_br(16),
            INSN_RET,
            INSN_RET,
            INSN_PACIBSP,
            INSN_STP_FP_LR_PRE,
            INSN_RETAB,
        ]
        macho = _build_synthetic_macho64(words, [0x100000400, 0x100000410])
        view = m4_acc.parse_macho_arm64_slice(macho)
        assert view is not None

        mg_cfg = {
            "inlineJumpTableStarts": [],
            "functions": [
                {
                    "address": 0x100000400,
                    "endAddress": 0x100000410,
                    "name": "_entry_like",
                    "blocks": [
                        {"id": 0, "startAddress": 0x100000400, "endAddress": 0x100000408},
                        {"id": 1, "startAddress": 0x100000408, "endAddress": 0x10000040C},
                        {"id": 2, "startAddress": 0x10000040C, "endAddress": 0x100000410},
                    ],
                    "jumpTables": [
                        {
                            "dispatchInstructionAddress": 0x100000404,
                            "targetAddresses": [0x100000408, 0x10000040C],
                        }
                    ],
                },
                {
                    "address": 0x100000410,
                    "endAddress": 0x10000041C,
                    "name": "_pac_fn",
                    "blocks": [{"id": 0, "startAddress": 0x100000410, "endAddress": 0x10000041C}],
                    "jumpTables": [],
                },
            ],
        }
        gh_export = {
            "functions": [
                {
                    "name": "entry",
                    "entry": "0x100000400",
                    "minAddr": "0x100000400",
                    "maxAddr": "0x10000040f",
                    "numRanges": 1,
                    "byteCount": 16,
                    "isExternal": False,
                    "memoryBlock": "__text",
                    "blockCount": 4,
                    "blocks": [
                        {"start": "0x100000400", "endMax": "0x100000403"},
                        {"start": "0x100000404", "endMax": "0x100000407"},  # isolated `br x16`
                        {"start": "0x100000408", "endMax": "0x10000040b"},
                        {"start": "0x10000040c", "endMax": "0x10000040f"},
                    ],
                },
                {
                    "name": "FUN_100000410",
                    "entry": "0x100000410",
                    "minAddr": "0x100000410",
                    "maxAddr": "0x100000413",
                    "numRanges": 1,
                    "byteCount": 4,
                    "isExternal": False,
                    "memoryBlock": "__text",
                    "blockCount": 1,
                    "blocks": [{"start": "0x100000410", "endMax": "0x100000413"}],
                },
                {
                    "name": "FUN_100000414",
                    "entry": "0x100000414",
                    "minAddr": "0x100000414",
                    "maxAddr": "0x10000041b",
                    "numRanges": 1,
                    "byteCount": 8,
                    "isExternal": False,
                    "memoryBlock": "__text",
                    "blockCount": 1,
                    "blocks": [{"start": "0x100000414", "endMax": "0x10000041b"}],
                },
                {
                    "name": "_exit",
                    "entry": "0x200000000",
                    "minAddr": "0x200000000",
                    "maxAddr": "0x200000000",
                    "numRanges": 1,
                    "byteCount": 1,
                    "isExternal": True,
                    "memoryBlock": "EXTERNAL",
                    "blockCount": 0,
                    "blocks": [],
                },
            ]
        }

        rep = m4_gh.compare_and_classify_ghidra_vs_machgraph(view, mg_cfg, gh_export)
        self.assertEqual(rep["verdict"], "PASS")
        self.assertEqual(rep["machgraph_error_count"], 0)
        self.assertEqual(
            rep["differences_by_category"],
            {
                "TOOL_DIFF_GHIDRA_PAC_PROLOGUE_SPLIT": 1,
                "TOOL_DIFF_GHIDRA_PAC_PROLOGUE_TRUNCATION": 1,
                "TOOL_DIFF_GHIDRA_SWITCH_DISPATCH_ISOLATION": 1,
            },
        )

        # Now inject a genuine MachGraph bug: drop switch case block `0x10000040c`!
        mg_cfg_broken = {
            "inlineJumpTableStarts": [],
            "functions": [
                {
                    **mg_cfg["functions"][0],
                    "blocks": mg_cfg["functions"][0]["blocks"][:2],
                    "jumpTables": [
                        {
                            "dispatchInstructionAddress": 0x100000404,
                            "targetAddresses": [0x100000408],
                        }
                    ],
                },
                mg_cfg["functions"][1],
            ],
        }
        rep_bad = m4_gh.compare_and_classify_ghidra_vs_machgraph(view, mg_cfg_broken, gh_export)
        self.assertEqual(rep_bad["verdict"], "FAIL")
        self.assertGreater(rep_bad["machgraph_error_count"], 0)
        self.assertIn("MACHGRAPH_ERROR_BLOCK_PARTITION_MISMATCH", rep_bad["differences_by_category"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
