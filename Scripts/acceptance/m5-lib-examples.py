#!/usr/bin/env python3
"""Library public-interface & external Swift package acceptance suite for MachGraph M5.

Usage:
  Scripts/acceptance/m5-lib-examples.py [en_doc] [zh_doc]
      [--en-doc <path>] [--zh-doc <path>] [--repo-root <path>]
      [--json-out <path>] [--txt-out <path>] [--verbose]

Checks performed:
  1. Extracts the three `<= 20`-line `swift` library example code blocks (and their adjacent
     expected-output `text` blocks) from the English and Simplified Chinese Markdown files
     (defaults: `docs/library-examples.md` and `docs/library-examples.zh-CN.md`; Stage 3 may
     pass `README.md` and `README.zh-CN.md`), verifying exact verbatim equality across both
     languages, `<= 20` lines per block, and that each block imports only its target library
     module (`MachBinaryFormats`, `MachA64Decoder`, `MachCFGEngine`) without explicitly
     importing `MachGraphModels`.
  2. Copies `Package.swift` + `Sources/` of `--repo-root` into an isolated `mktemp -d`
     workspace (zero network access, isolated `HOME` / `CFFIXED_USER_HOME`), creates three
     separate empty Swift packages depending via `.package(path:)` solely on the target
     library product, verifies `swift build` succeeds with 0 warnings, executes each built
     binary, and compares both runtime stdout and documented expected output against
     independent reference values computed solely from system tools (`xcrun otool -l`,
     `otool -Iv`, `codesign -dvvv`, `clang`, `llvm-objdump`) and raw Mach-O bytes.
  3. Compiles dedicated negative probes from an external Swift package against tightened
     `internal` and `package` symbols (`ELF64Loader`, `PE32PlusLoader`, `WasmModuleLoader`,
     `UniversalBinaryDispatcher.loadRawBinary`, `ASN1DERWalker`, `MachO64Loader`,
     `signExtend`, `DecodeBitMasks`, `A64BitUtils`, `A64SystemRegisterTable`,
     `PostDominatorTreeNode`, `SugiyamaCFGLayoutSolver`, `KnownNoreturnSymbols`) plus a
     removed frozen `.library` product (`MachMicroDecompiler`), verifying each fails to
     build (`returncode != 0`) specifically due to Swift access-control / module-visibility
     restrictions.
"""

import argparse
import datetime
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))

EXPECTED_EXAMPLE_MODULES: Tuple[str, ...] = (
    "MachBinaryFormats",
    "MachA64Decoder",
    "MachCFGEngine",
)
MAX_EXAMPLE_LINES = 20
BUILD_TIMEOUT_SECONDS = 300.0
RUN_TIMEOUT_SECONDS = 60.0

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+\x40[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_USERS_PREFIX = os.sep + "Users" + os.sep
_USERS_PATH_RE = re.compile(re.escape(_USERS_PREFIX) + r"[^/\s\"']+")
_WARNING_LINE_RE = re.compile(r"(?im)^(?:[^\n]*?:\d+(?::\d+)?:\s*)?warning:\s+(.+)$")

NEGATIVE_SYMBOL_PROBES: Tuple[Dict[str, str], ...] = (
    {
        "name": "ELF64Loader_package",
        "module": "MachBinaryFormats",
        "symbol": "ELF64Loader",
        "expected_access": "package",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            '_ = try? MachBinaryFormats.ELF64Loader.load(data: Data(), fileName: "a", filePath: "a")\n'
        ),
    },
    {
        "name": "PE32PlusLoader_package",
        "module": "MachBinaryFormats",
        "symbol": "PE32PlusLoader",
        "expected_access": "package",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            '_ = try? MachBinaryFormats.PE32PlusLoader.load(data: Data(), fileName: "a", filePath: "a")\n'
        ),
    },
    {
        "name": "WasmModuleLoader_package",
        "module": "MachBinaryFormats",
        "symbol": "WasmModuleLoader",
        "expected_access": "package",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            '_ = try? MachBinaryFormats.WasmModuleLoader.load(data: Data(), fileName: "a", filePath: "a")\n'
        ),
    },
    {
        "name": "loadRawBinary_package",
        "module": "MachBinaryFormats",
        "symbol": "loadRawBinary",
        "expected_access": "package",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            "_ = UniversalBinaryDispatcher.loadRawBinary(data: Data())\n"
        ),
    },
    {
        "name": "ASN1DERWalker_internal",
        "module": "MachBinaryFormats",
        "symbol": "ASN1DERWalker",
        "expected_access": "internal",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            "_ = MachBinaryFormats.ASN1DERWalker.extractCMSSignerCommonNames(cmsData: Data())\n"
        ),
    },
    {
        "name": "MachO64Loader_internal",
        "module": "MachBinaryFormats",
        "symbol": "MachO64Loader",
        "expected_access": "internal",
        "source": (
            "import Foundation\n"
            "import MachBinaryFormats\n"
            "_ = try? MachBinaryFormats.MachO64Loader.loadSlice(\n"
            "    wholeData: Data(), sliceOffset: 0, sliceSize: 0,\n"
            '    fileName: "a", filePath: "a", containerFormat: .machO64,\n'
            "    selectedSliceIndex: 0, slices: []\n"
            ")\n"
        ),
    },
    {
        "name": "signExtend_internal",
        "module": "MachA64Decoder",
        "symbol": "signExtend",
        "expected_access": "internal",
        "source": (
            "import MachA64Decoder\n"
            "_ = MachA64Decoder.signExtend(0x80, bits: 8)\n"
        ),
    },
    {
        "name": "DecodeBitMasks_internal",
        "module": "MachA64Decoder",
        "symbol": "DecodeBitMasks",
        "expected_access": "internal",
        "source": (
            "import MachA64Decoder\n"
            "_ = MachA64Decoder.DecodeBitMasks(immN: 0, imms: 0, immr: 0, immediate: true, regSize: 64)\n"
        ),
    },
    {
        "name": "A64BitUtils_internal",
        "module": "MachA64Decoder",
        "symbol": "A64BitUtils",
        "expected_access": "internal",
        "source": (
            "import MachA64Decoder\n"
            "_ = MachA64Decoder.A64BitUtils.onesMask(8)\n"
        ),
    },
    {
        "name": "A64SystemRegisterTable_package",
        "module": "MachA64Decoder",
        "symbol": "A64SystemRegisterTable",
        "expected_access": "package",
        "source": (
            "import MachA64Decoder\n"
            '_ = MachA64Decoder.A64SystemRegisterTable.encoding(forName: "nzcv")\n'
        ),
    },
    {
        "name": "PostDominatorTreeNode_package",
        "module": "MachCFGEngine",
        "symbol": "PostDominatorTreeNode",
        "expected_access": "package",
        "source": (
            "import MachCFGEngine\n"
            "_ = MachCFGEngine.PostDominatorTreeNode(blockID: 0, immediatePostDominatorID: nil)\n"
        ),
    },
    {
        "name": "SugiyamaCFGLayoutSolver_package",
        "module": "MachCFGEngine",
        "symbol": "SugiyamaCFGLayoutSolver",
        "expected_access": "package",
        "source": (
            "import MachCFGEngine\n"
            "_ = MachCFGEngine.SugiyamaCFGLayoutSolver()\n"
        ),
    },
    {
        "name": "KnownNoreturnSymbols_package",
        "module": "MachCFGEngine",
        "symbol": "KnownNoreturnSymbols",
        "expected_access": "package",
        "source": (
            "import MachCFGEngine\n"
            '_ = MachCFGEngine.KnownNoreturnSymbols.matchesSymbolName("_exit")\n'
        ),
    },
)

REMOVED_LIBRARY_PRODUCTS: Tuple[str, ...] = (
    "MachMicroDecompiler",
    "MachPatchAndHexEngine",
    "MachProjectStore",
    "MachPluginSDK",
    "MachWorkbenchShell",
    "MachStudioViews",
)


# ---------------------------------------------------------------------------
# Sanitization & Isolated Subprocess Helpers
# ---------------------------------------------------------------------------


def sanitize_text(text: str) -> str:
    out = text
    home_dir = os.path.expanduser("~")
    if home_dir and home_dir != "/":
        out = out.replace(home_dir, "<home>")
    out = _USERS_PATH_RE.sub("<home>", out)
    out = _EMAIL_RE.sub("<redacted-email>", out)
    return out


def sanitize_display_path(path: str, repo_root: Optional[str] = None) -> str:
    root = os.path.abspath(repo_root if repo_root is not None else REPO_ROOT)
    abs_path = os.path.abspath(path)
    try:
        rel = os.path.relpath(abs_path, root)
        if rel == "." or (not rel.startswith("..") and not os.path.isabs(rel)):
            return rel
    except ValueError:
        pass
    return sanitize_text(abs_path)


def make_isolated_env(isolated_home: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = isolated_home
    env["CFFIXED_USER_HOME"] = isolated_home
    if "DEVELOPER_DIR" not in env and os.path.isdir("/Applications/Xcode.app/Contents/Developer"):
        env["DEVELOPER_DIR"] = "/Applications/Xcode.app/Contents/Developer"
    return env


def run_cmd(
    cmd: Sequence[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input_text: Optional[str] = None,
    timeout: float = BUILD_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    t0 = time.monotonic()
    proc = subprocess.run(
        list(cmd),
        cwd=cwd,
        env=env,
        input=input_text.encode("utf-8") if input_text is not None else None,
        stdin=subprocess.DEVNULL if input_text is None else None,
        capture_output=True,
        timeout=timeout,
    )
    elapsed = time.monotonic() - t0
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout.decode("utf-8", errors="replace"),
        "stderr": proc.stderr.decode("utf-8", errors="replace"),
        "elapsed_s": round(elapsed, 4),
    }


def _load_sibling_module(mod_name: str, filename: str) -> Any:
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {filename} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1. Markdown Extraction & Bilingual / Line-Count / Import Validation
# ---------------------------------------------------------------------------

_FENCED_BLOCK_RE = re.compile(r"```([A-Za-z0-9_+-]*)\n(.*?)```", re.DOTALL)


def extract_swift_example_blocks(markdown_text: str) -> List[Dict[str, Any]]:
    """Extracts executable Swift library example blocks (and adjacent `text` expected output).

    Ignores `Package.swift` manifest snippets containing `import PackageDescription`.
    """
    all_fenced: List[Tuple[str, str]] = []
    for m in _FENCED_BLOCK_RE.finditer(markdown_text):
        lang = m.group(1).strip().lower()
        body = m.group(2)
        if body.endswith("\n"):
            body = body[:-1]
        all_fenced.append((lang, body))

    examples: List[Dict[str, Any]] = []
    for idx, (lang, body) in enumerate(all_fenced):
        if lang != "swift":
            continue
        imports = [
            ln.strip()
            for ln in body.splitlines()
            if ln.strip().startswith("import ") or ln.strip().startswith("@_exported import ")
        ]
        if any("PackageDescription" in imp for imp in imports):
            continue

        imported_modules = []
        for imp in imports:
            toks = imp.split()
            if toks:
                imported_modules.append(toks[-1])

        target_mod: Optional[str] = None
        for cand in EXPECTED_EXAMPLE_MODULES:
            if cand in imported_modules:
                target_mod = cand
                break

        expected_output: Optional[str] = None
        if idx + 1 < len(all_fenced) and all_fenced[idx + 1][0] in ("text", "plaintext", ""):
            expected_output = all_fenced[idx + 1][1].strip()

        lines = body.splitlines()
        examples.append(
            {
                "code": body,
                "line_count": len(lines),
                "module": target_mod,
                "imported_modules": imported_modules,
                "expected_output": expected_output,
            }
        )
    return examples


def validate_markdown_example_pair(
    blocks_en: Sequence[Dict[str, Any]],
    blocks_zh: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Pure validation of extracted EN & ZH Swift example blocks."""
    diffs: List[Dict[str, Any]] = []

    if len(blocks_en) != 3 or len(blocks_zh) != 3:
        diffs.append(
            {
                "kind": "WRONG_EXAMPLE_COUNT",
                "en_count": len(blocks_en),
                "zh_count": len(blocks_zh),
                "expected": 3,
            }
        )
        return diffs

    for idx, expected_mod in enumerate(EXPECTED_EXAMPLE_MODULES):
        b_en = blocks_en[idx]
        b_zh = blocks_zh[idx]

        if b_en["code"] != b_zh["code"]:
            diffs.append(
                {
                    "kind": "DOC_CODE_MISMATCH",
                    "example_index": idx + 1,
                    "expected_module": expected_mod,
                }
            )

        for lang_label, blk in (("en", b_en), ("zh", b_zh)):
            if blk["line_count"] < 1 or blk["line_count"] > MAX_EXAMPLE_LINES:
                diffs.append(
                    {
                        "kind": "EXAMPLE_TOO_LONG",
                        "lang": lang_label,
                        "example_index": idx + 1,
                        "line_count": blk["line_count"],
                        "max_lines": MAX_EXAMPLE_LINES,
                    }
                )

            if blk["module"] != expected_mod:
                diffs.append(
                    {
                        "kind": "WRONG_TARGET_MODULE",
                        "lang": lang_label,
                        "example_index": idx + 1,
                        "expected_module": expected_mod,
                        "actual_module": blk["module"],
                    }
                )

            allowed_imports = {expected_mod, "Foundation"}
            forbidden = [m for m in blk["imported_modules"] if m not in allowed_imports]
            if forbidden:
                diffs.append(
                    {
                        "kind": "FORBIDDEN_IMPORT",
                        "lang": lang_label,
                        "example_index": idx + 1,
                        "forbidden_imports": forbidden,
                        "detail": "Examples must import only the target module (and Foundation if needed), relying on @_exported import MachGraphModels.",
                    }
                )

            if not blk.get("expected_output"):
                diffs.append(
                    {
                        "kind": "MISSING_EXPECTED_OUTPUT_BLOCK",
                        "lang": lang_label,
                        "example_index": idx + 1,
                    }
                )

    return diffs


# ---------------------------------------------------------------------------
# 2. Build Warning, Output Comparison & Negative Probe Pure Validators
# ---------------------------------------------------------------------------


def validate_clean_swift_build(
    label: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    combined = (stdout or "") + "\n" + (stderr or "")
    if returncode != 0:
        diffs.append(
            {
                "kind": "BUILD_FAILED",
                "target": label,
                "returncode": returncode,
                "stderr_snippet": sanitize_text(combined.strip()[-600:]),
            }
        )
        return diffs

    warnings = [m.group(0).strip() for m in _WARNING_LINE_RE.finditer(combined)]
    if warnings:
        diffs.append(
            {
                "kind": "BUILD_WARNING",
                "target": label,
                "warning_count": len(warnings),
                "warnings": [sanitize_text(w) for w in warnings[:5]],
            }
        )
    return diffs


def validate_example_output(
    module_name: str,
    actual_returncode: int,
    actual_stdout: str,
    actual_stderr: str,
    reference_stdout: str,
    doc_en_expected: Optional[str],
    doc_zh_expected: Optional[str],
) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    if actual_returncode != 0:
        diffs.append(
            {
                "kind": "EXAMPLE_RUNTIME_ERROR",
                "module": module_name,
                "returncode": actual_returncode,
                "stderr_snippet": sanitize_text((actual_stderr or "").strip()[:400]),
            }
        )
        return diffs

    norm_actual = actual_stdout.strip()
    norm_ref = reference_stdout.strip()

    if norm_actual != norm_ref:
        diffs.append(
            {
                "kind": "RUNTIME_OUTPUT_MISMATCH",
                "module": module_name,
                "actual": sanitize_text(norm_actual),
                "reference": sanitize_text(norm_ref),
            }
        )

    for lang_label, doc_exp in (("en", doc_en_expected), ("zh", doc_zh_expected)):
        if doc_exp is None or doc_exp.strip() != norm_ref:
            diffs.append(
                {
                    "kind": "DOC_EXPECTED_OUTPUT_MISMATCH",
                    "module": module_name,
                    "lang": lang_label,
                    "documented": None if doc_exp is None else sanitize_text(doc_exp.strip()),
                    "reference": sanitize_text(norm_ref),
                }
            )
    return diffs


def validate_negative_probe_result(
    probe_name: str,
    symbol: str,
    module: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> List[Dict[str, Any]]:
    """Verifies an external negative probe fails to compile due specifically to access control / visibility."""
    if returncode == 0:
        return [
            {
                "kind": "NEGATIVE_PROBE_UNEXPECTEDLY_COMPILED",
                "probe": probe_name,
                "module": module,
                "symbol": symbol,
                "detail": f"External package compiled '{symbol}' with exit code 0 (symbol leaked as public).",
            }
        ]

    combined = (stdout or "") + "\n" + (stderr or "")
    sym_esc = re.escape(symbol)
    mod_esc = re.escape(module)
    access_patterns = (
        rf"'{sym_esc}' is inaccessible due to '(?:internal|package|private|fileprivate)' protection level",
        rf"cannot find (?:type )?'{sym_esc}' in scope",
        rf"module '{mod_esc}' has no member named '{sym_esc}'",
        rf"'{sym_esc}' is not a member type of (?:module|enum|struct) '{mod_esc}",
        rf"product '{sym_esc}' required by package .*? not found",
    )
    if any(re.search(pat, combined) for pat in access_patterns):
        return []

    return [
        {
            "kind": "NEGATIVE_PROBE_WRONG_DIAGNOSTIC",
            "probe": probe_name,
            "module": module,
            "symbol": symbol,
            "returncode": returncode,
            "diagnostic_snippet": sanitize_text(combined.strip()[-500:]),
        }
    ]


# ---------------------------------------------------------------------------
# 3. Independent Reference Computations (System Tools Only — Zero MachGraph)
# ---------------------------------------------------------------------------


def compute_independent_references(isolated_env: Dict[str, str]) -> Dict[str, str]:
    """Computes exact expected outputs for the 3 examples using only system tools & raw bytes."""
    m4 = _load_sibling_module("_m5_lib_m4_cfg_helper", "m4-cfg-acceptance.py")
    m5_mcp = _load_sibling_module("_m5_lib_m5_mcp_helper", "m5-mcp-acceptance.py")

    ls_path = "/bin/ls"
    with open(ls_path, "rb") as fh:
        ls_bytes = fh.read()

    sv = m4.parse_macho_arm64_slice(ls_bytes, "arm64e")
    if sv is None:
        raise RuntimeError("Unable to locate arm64/arm64e Mach-O slice in /bin/ls")
    arch = sv.arch

    otool_l = run_cmd(["xcrun", "otool", "-arch", arch, "-l", ls_path], env=isolated_env, timeout=60.0)
    if otool_l["returncode"] != 0:
        raise RuntimeError(f"otool -l failed on {ls_path}: {otool_l['stderr']}")
    _, _, entry_va = m5_mcp.parse_otool_lc_main_entry(otool_l["stdout"])
    if entry_va is None:
        raise RuntimeError("Could not parse LC_MAIN entry from otool -l /bin/ls")

    cs_res = run_cmd(["/usr/bin/codesign", "-a", arch, "-dvvv", ls_path], env=isolated_env, timeout=60.0)
    cs_info = m5_mcp.parse_codesign_dvvv(cs_res["stderr"], cs_res["returncode"])

    seg_names: List[str] = []
    for blk in otool_l["stdout"].split("Load command ")[1:]:
        if "cmd LC_SEGMENT_64" in blk:
            m_seg = re.search(r"segname (\S+)", blk)
            if m_seg:
                seg_names.append(m_seg.group(1))

    fn_starts_res = run_cmd(
        ["xcrun", "llvm-objdump", "--macho", "--function-starts", f"--arch={arch}", ls_path],
        env=isolated_env,
        timeout=60.0,
    )
    if fn_starts_res["returncode"] != 0:
        raise RuntimeError(f"llvm-objdump --function-starts failed: {fn_starts_res['stderr']}")
    lc_fn_starts = sorted(
        int(ln.strip(), 16)
        for ln in fn_starts_res["stdout"].splitlines()
        if re.match(r"^[0-9a-fA-F]{8,}$", ln.strip())
    )

    magic_be = struct.unpack(">I", ls_bytes[:4])[0]
    fmt_str = (
        "Mach-O Universal Fat"
        if magic_be in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64)
        else "Mach-O 64-bit"
    )
    arch_display = "arm64e (PAC)" if arch == "arm64e" else arch

    ref_binary_formats = (
        f"format={fmt_str} arch={arch_display}\n"
        f"entry=0x{entry_va:016x} segments={len(seg_names)} [{','.join(seg_names)}]\n"
        f"lcFunctionStarts={len(lc_fn_starts)}\n"
        f"signed={'true' if cs_info['is_signed'] else 'false'} cdhash={cs_info['cdhash_full']}\n"
    )

    # --- Reference 2: MachA64Decoder via `xcrun clang` + `xcrun llvm-objdump -d` ---
    with tempfile.TemporaryDirectory(prefix="machgraph-m5-a64-ref-") as tmp_asm:
        obj_file = os.path.join(tmp_asm, "ref.o")
        asm_input = "sub sp, sp, #16\nmov w0, #42\nadd sp, sp, #16\nret\n"
        c_res = run_cmd(
            ["xcrun", "clang", "-arch", "arm64", "-c", "-x", "assembler", "-", "-o", obj_file],
            env=isolated_env,
            input_text=asm_input,
            timeout=60.0,
        )
        if c_res["returncode"] != 0:
            raise RuntimeError(f"clang assembler failed: {c_res['stderr']}")
        d_res = run_cmd(["xcrun", "llvm-objdump", "-d", obj_file], env=isolated_env, timeout=60.0)
        if d_res["returncode"] != 0:
            raise RuntimeError(f"llvm-objdump -d failed: {d_res['stderr']}")

        a64_lines: List[str] = []
        base_va = 0x100000000
        for ln in d_res["stdout"].splitlines():
            m_hex = re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(\S+)\s*(.*)$", ln)
            if m_hex:
                off = int(m_hex.group(1), 16)
                word_hex = m_hex.group(2).lower()
                mnem = m_hex.group(3).strip().lower()
                ops = re.sub(r"\s+", " ", m_hex.group(4).split(";")[0].strip())
                dis = f"{mnem} {ops}" if ops else mnem
                a64_lines.append(f"0x{base_va + off:016x}  {word_hex}  {dis}")
        if len(a64_lines) != 4:
            raise RuntimeError(f"Expected 4 disassembled instructions from clang/llvm-objdump, got {a64_lines}")
        ref_a64_decoder = "\n".join(a64_lines) + "\n"

    # --- Reference 3: MachCFGEngine single-function CFG on `/bin/ls` entry ---
    text_sec = sv.find_section("__TEXT", "__text")
    if text_sec is None:
        raise RuntimeError("Missing __TEXT,__text in /bin/ls")
    text_start = int(text_sec["addr"])
    text_end = text_start + int(text_sec["size"])

    objdump_ls = run_cmd(
        ["xcrun", "llvm-objdump", "-d", f"--arch={arch}", ls_path],
        env=isolated_env,
        timeout=60.0,
    )
    if objdump_ls["returncode"] != 0:
        raise RuntimeError(f"llvm-objdump -d /bin/ls failed: {objdump_ls['stderr']}")
    dis_by_addr: Dict[int, Tuple[str, str]] = {}
    for ln in objdump_ls["stdout"].splitlines():
        m_byte = re.match(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+){4}\s*(\S+)\s*(.*)$", ln)
        m_word = None if m_byte else re.match(r"^\s*([0-9a-fA-F]+):\s+[0-9a-fA-F]{8}\s+(\S+)\s*(.*)$", ln)
        m_any = m_byte or m_word
        if m_any:
            dis_by_addr[int(m_any.group(1), 16)] = (
                m_any.group(2).lower(),
                m_any.group(3).split(";")[0].strip(),
            )

    # First locate inline jump tables in __TEXT,__text so table words are excluded from code scanning
    all_text_addrs = list(range(text_start, text_end, 4))
    inline_jt_ranges: List[Tuple[int, int]] = []
    jt_targets_by_br: Dict[int, List[int]] = {}
    for i, a in enumerate(all_text_addrs):
        mn, _ = dis_by_addr.get(a, ("", ""))
        if mn == "br":
            window = [
                (all_text_addrs[j], dis_by_addr.get(all_text_addrs[j], ("", "")))
                for j in range(max(0, i - 10), i)
            ]
            upper = page = page_off = anchor = None
            for wa, (wmn, wops) in window:
                if wmn == "cmp" and "#" in wops:
                    upper = int(wops.split("#")[-1].strip(), 0)
                elif wmn == "adrp":
                    w_val = sv.read_u32(wa)
                    if w_val is not None:
                        page = m4.decode_arm64_insn(w_val, wa).get("target")
                elif wmn == "add" and "#" in wops and page is not None and page_off is None:
                    page_off = int(wops.split("#")[-1].strip(), 0)
                elif wmn == "adr":
                    anchor = wa + int(wops.split("#")[-1].strip(), 0)
            if upper is not None and page is not None and page_off is not None and anchor is not None:
                tbl_va = page + page_off
                cnt = upper + 1
                if text_start <= tbl_va < text_end:
                    inline_jt_ranges.append((tbl_va, tbl_va + cnt * 4))
                dedup: List[int] = []
                for k in range(cnt):
                    u32 = sv.read_u32(tbl_va + k * 4)
                    if u32 is None:
                        break
                    s32 = struct.unpack("<i", struct.pack("<I", u32))[0]
                    tgt = (anchor + s32) & 0xFFFFFFFFFFFFFFFF
                    if tgt not in dedup:
                        dedup.append(tgt)
                jt_targets_by_br[a] = dedup

    def in_inline_jt(va: int) -> bool:
        return any(lo <= va < hi for lo, hi in inline_jt_ranges)

    # Function boundaries = LC_FUNCTION_STARTS union direct BL call targets in __TEXT,__text + segmented stubs
    fn_starts_set = {s for s in lc_fn_starts if not in_inline_jt(s)}
    for a in all_text_addrs:
        if in_inline_jt(a):
            continue
        w = sv.read_u32(a)
        if w is None:
            continue
        d = m4.decode_arm64_insn(w, a)
        if d["kind"] == "bl" and text_start <= d["target"] < text_end and not in_inline_jt(d["target"]):
            fn_starts_set.add(d["target"])

    sorted_text_starts = sorted(fn_starts_set)
    fn_list: List[Dict[str, Any]] = []
    for i, s in enumerate(sorted_text_starts):
        raw_e = sorted_text_starts[i + 1] if i + 1 < len(sorted_text_starts) else text_end
        insn_addrs = [pc for pc in range(s, raw_e, 4) if not in_inline_jt(pc)]
        eff_e = (insn_addrs[-1] + 4) if insn_addrs else raw_e
        jts_for_fn = [
            {"dispatchInstructionAddress": br_a, "targetAddresses": tgts}
            for br_a, tgts in jt_targets_by_br.items()
            if s <= br_a < raw_e
        ]
        fn_list.append(
            {
                "address": s,
                "endAddress": eff_e,
                "name": "_entry" if s == entry_va else f"sub_{s:x}",
                "isStub": False,
                "blocks": [{"instructionAddresses": insn_addrs}],
                "jumpTables": jts_for_fn,
            }
        )

    for sec in sv.executable_sections:
        if sec["sectname"] in ("__stubs", "__auth_stubs"):
            cur = int(sec["addr"])
            sec_end = cur + int(sec["size"])
            for a in range(cur, sec_end, 4):
                w = sv.read_u32(a)
                if w is None:
                    break
                d = m4.decode_arm64_insn(w, a)
                if d["kind"] in ("indirect_jump", "b", "ret", "udf", "brk"):
                    fn_list.append(
                        {
                            "address": cur,
                            "endAddress": a + 4,
                            "name": f"stub_{cur:x}",
                            "isStub": True,
                        }
                    )
                    cur = a + 4

    imports_by_addr, imp_err, _ = m4.resolve_import_symbols_for_binary(ls_path, arch, sv, fn_list)
    if imp_err:
        raise RuntimeError(f"Failed to resolve imports on /bin/ls: {imp_err}")
    noreturn_addrs = m4.solve_independent_noreturn_functions(sv, fn_list, imports_by_addr)

    entry_fn = next(f for f in fn_list if f["address"] == entry_va)
    entry_insns = [
        (pc, m4.decode_arm64_insn(sv.read_u32(pc), pc))
        for pc in entry_fn["blocks"][0]["instructionAddresses"]
    ]
    addr_set = {pc for pc, _ in entry_insns}
    leaders = {entry_va}
    for idx_i, (pc, d) in enumerate(entry_insns):
        k = d["kind"]
        t = d.get("target")
        is_nr_call = k == "bl" and t in noreturn_addrs
        if k in ("b", "cond_branch"):
            if t in addr_set:
                leaders.add(t)
            if idx_i + 1 < len(entry_insns):
                leaders.add(entry_insns[idx_i + 1][0])
        elif pc in jt_targets_by_br:
            for jt_t in jt_targets_by_br[pc]:
                if jt_t in addr_set:
                    leaders.add(jt_t)
            if idx_i + 1 < len(entry_insns):
                leaders.add(entry_insns[idx_i + 1][0])
        elif k in ("ret", "udf", "brk", "hlt", "indirect_jump") or is_nr_call:
            if idx_i + 1 < len(entry_insns):
                leaders.add(entry_insns[idx_i + 1][0])

    sorted_leaders = sorted(leaders)
    bid_by_start = {s: i for i, s in enumerate(sorted_leaders)}
    pos_by_pc = {pc: i for i, (pc, _) in enumerate(entry_insns)}
    edges: List[Tuple[int, int]] = []
    for i, b_start in enumerate(sorted_leaders):
        b_end = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else entry_fn["endAddress"]
        b_slice = [(pc, d) for pc, d in entry_insns if b_start <= pc < b_end]
        last_pc, last_d = b_slice[-1]
        k = last_d["kind"]
        t = last_d.get("target")
        nxt_pos = pos_by_pc[last_pc] + 1
        nxt_pc = entry_insns[nxt_pos][0] if nxt_pos < len(entry_insns) else None
        fall_bid = bid_by_start.get(nxt_pc) if nxt_pc is not None else None

        succs: List[int] = []
        if k == "b":
            if t in bid_by_start:
                succs.append(bid_by_start[t])
        elif k == "cond_branch":
            if t in bid_by_start:
                succs.append(bid_by_start[t])
            if fall_bid is not None and fall_bid not in succs:
                succs.append(fall_bid)
        elif last_pc in jt_targets_by_br:
            for jt_t in jt_targets_by_br[last_pc]:
                if jt_t in bid_by_start and bid_by_start[jt_t] not in succs:
                    succs.append(bid_by_start[jt_t])
        elif k in ("ret", "udf", "brk", "hlt", "indirect_jump") or (k == "bl" and t in noreturn_addrs):
            pass
        else:
            if fall_bid is not None:
                succs.append(fall_bid)

        for dst in succs:
            edges.append((i, dst))

    dom_info = m4.solve_dominators_and_loops_independent(list(range(len(sorted_leaders))), 0, edges)
    ref_cfg_engine = (
        f"functions={len(fn_list)} entry=_entry@0x{entry_va:016x}\n"
        f"blocks={len(sorted_leaders)} edges={len(edges)} "
        f"dom={len(dom_info['idom'])} loops={len(dom_info['natural_loops'])}\n"
    )

    return {
        "MachBinaryFormats": ref_binary_formats,
        "MachA64Decoder": ref_a64_decoder,
        "MachCFGEngine": ref_cfg_engine,
    }


# ---------------------------------------------------------------------------
# 4. External Swift Package Builder & Runner (`mktemp -d`)
# ---------------------------------------------------------------------------


def _write_single_product_package_swift(pkg_dir: str, pkg_name: str, target_name: str, product_name: str) -> None:
    manifest = f"""// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "{pkg_name}",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../MachGraph")
    ],
    targets: [
        .executableTarget(
            name: "{target_name}",
            dependencies: [
                .product(name: "{product_name}", package: "MachGraph")
            ]
        )
    ]
)
"""
    with open(os.path.join(pkg_dir, "Package.swift"), "w", encoding="utf-8") as fh:
        fh.write(manifest)


def run_acceptance_suite(
    repo_root: str,
    en_doc_path: str,
    zh_doc_path: str,
    verbose: bool = False,
) -> Dict[str, Any]:
    start_ts = time.monotonic()
    diffs: List[Dict[str, Any]] = []
    example_reports: List[Dict[str, Any]] = []
    probe_reports: List[Dict[str, Any]] = []

    if not os.path.isfile(en_doc_path):
        diffs.append({"kind": "MISSING_DOC_FILE", "path": sanitize_display_path(en_doc_path, repo_root)})
    if not os.path.isfile(zh_doc_path):
        diffs.append({"kind": "MISSING_DOC_FILE", "path": sanitize_display_path(zh_doc_path, repo_root)})
    if diffs:
        return {
            "passed": False,
            "diffs": diffs,
            "examples": example_reports,
            "negative_probes": probe_reports,
            "elapsed_s": round(time.monotonic() - start_ts, 3),
        }

    with open(en_doc_path, "r", encoding="utf-8") as fh:
        en_md = fh.read()
    with open(zh_doc_path, "r", encoding="utf-8") as fh:
        zh_md = fh.read()

    blocks_en = extract_swift_example_blocks(en_md)
    blocks_zh = extract_swift_example_blocks(zh_md)
    diffs.extend(validate_markdown_example_pair(blocks_en, blocks_zh))
    if diffs:
        return {
            "passed": False,
            "diffs": diffs,
            "examples": example_reports,
            "negative_probes": probe_reports,
            "elapsed_s": round(time.monotonic() - start_ts, 3),
        }

    with tempfile.TemporaryDirectory(prefix="machgraph-m5-lib-examples-") as work_root:
        isolated_home = os.path.join(work_root, "isolated_home")
        os.makedirs(isolated_home, exist_ok=True)
        env = make_isolated_env(isolated_home)

        # Compute independent reference outputs without touching MachGraph
        refs = compute_independent_references(env)

        # Copy working tree's Package.swift + Sources/ into temporary copy named `MachGraph` (SwiftPM package identity)
        mg_copy_dir = os.path.join(work_root, "MachGraph")
        os.makedirs(mg_copy_dir, exist_ok=True)
        shutil.copy2(os.path.join(repo_root, "Package.swift"), os.path.join(mg_copy_dir, "Package.swift"))
        shutil.copytree(os.path.join(repo_root, "Sources"), os.path.join(mg_copy_dir, "Sources"))

        # Build & run each of the 3 examples in its own standalone empty Swift package
        for idx, mod_name in enumerate(EXPECTED_EXAMPLE_MODULES):
            b_en = blocks_en[idx]
            b_zh = blocks_zh[idx]
            pkg_name = f"ExternalConsumer_{mod_name}"
            target_name = f"Run_{mod_name}"
            pkg_dir = os.path.join(work_root, pkg_name)
            src_dir = os.path.join(pkg_dir, "Sources", target_name)
            os.makedirs(src_dir, exist_ok=True)
            _write_single_product_package_swift(pkg_dir, pkg_name, target_name, mod_name)
            with open(os.path.join(src_dir, "Demo.swift"), "w", encoding="utf-8") as fh:
                fh.write(b_en["code"] + "\n")

            build_res = run_cmd(["swift", "build"], cwd=pkg_dir, env=env, timeout=BUILD_TIMEOUT_SECONDS)
            b_diffs = validate_clean_swift_build(
                label=mod_name,
                returncode=build_res["returncode"],
                stdout=build_res["stdout"],
                stderr=build_res["stderr"],
            )
            diffs.extend(b_diffs)

            run_res: Optional[Dict[str, Any]] = None
            if build_res["returncode"] == 0:
                exe_path = os.path.join(pkg_dir, ".build", "debug", target_name)
                run_res = run_cmd([exe_path], cwd=pkg_dir, env=env, timeout=RUN_TIMEOUT_SECONDS)
                o_diffs = validate_example_output(
                    module_name=mod_name,
                    actual_returncode=run_res["returncode"],
                    actual_stdout=run_res["stdout"],
                    actual_stderr=run_res["stderr"],
                    reference_stdout=refs[mod_name],
                    doc_en_expected=b_en["expected_output"],
                    doc_zh_expected=b_zh["expected_output"],
                )
                diffs.extend(o_diffs)

            example_reports.append(
                {
                    "module": mod_name,
                    "line_count": b_en["line_count"],
                    "build_returncode": build_res["returncode"],
                    "build_elapsed_s": build_res["elapsed_s"],
                    "run_returncode": None if run_res is None else run_res["returncode"],
                    "run_elapsed_s": None if run_res is None else run_res["elapsed_s"],
                    "actual_output": None if run_res is None else sanitize_text(run_res["stdout"].strip()),
                    "reference_output": sanitize_text(refs[mod_name].strip()),
                }
            )
            if verbose:
                print(
                    f"  [example] {mod_name}: lines={b_en['line_count']} "
                    f"build_rc={build_res['returncode']} ({build_res['elapsed_s']}s)"
                )

        # Negative probes 1..N: tightened internal & package symbols (1 target per probe)
        neg_pkg = os.path.join(work_root, "NegativeSymbolProbes")
        os.makedirs(neg_pkg, exist_ok=True)
        target_entries: List[str] = []
        for probe in NEGATIVE_SYMBOL_PROBES:
            t_name = f"Neg_{probe['name']}"
            t_dir = os.path.join(neg_pkg, "Sources", t_name)
            os.makedirs(t_dir, exist_ok=True)
            with open(os.path.join(t_dir, "main.swift"), "w", encoding="utf-8") as fh:
                fh.write(probe["source"])
            target_entries.append(
                f'        .executableTarget(name: "{t_name}", dependencies: [.product(name: "{probe["module"]}", package: "MachGraph")])'
            )

        neg_manifest = (
            "// swift-tools-version: 6.0\n"
            "import PackageDescription\n\n"
            "let package = Package(\n"
            '    name: "NegativeSymbolProbes",\n'
            "    platforms: [.macOS(.v14)],\n"
            '    dependencies: [.package(path: "../MachGraph")],\n'
            "    targets: [\n" + ",\n".join(target_entries) + "\n    ]\n)\n"
        )
        with open(os.path.join(neg_pkg, "Package.swift"), "w", encoding="utf-8") as fh:
            fh.write(neg_manifest)

        for probe in NEGATIVE_SYMBOL_PROBES:
            t_name = f"Neg_{probe['name']}"
            p_res = run_cmd(["swift", "build", "--target", t_name], cwd=neg_pkg, env=env, timeout=BUILD_TIMEOUT_SECONDS)
            p_diffs = validate_negative_probe_result(
                probe_name=probe["name"],
                symbol=probe["symbol"],
                module=probe["module"],
                returncode=p_res["returncode"],
                stdout=p_res["stdout"],
                stderr=p_res["stderr"],
            )
            diffs.extend(p_diffs)
            probe_reports.append(
                {
                    "probe": probe["name"],
                    "module": probe["module"],
                    "symbol": probe["symbol"],
                    "expected_access": probe["expected_access"],
                    "returncode": p_res["returncode"],
                    "elapsed_s": p_res["elapsed_s"],
                    "rejected_as_expected": len(p_diffs) == 0,
                }
            )
            if verbose:
                print(
                    f"  [neg-probe] {probe['name']}: rc={p_res['returncode']} "
                    f"rejected={len(p_diffs) == 0} ({p_res['elapsed_s']}s)"
                )

        # Negative product probe: removed frozen library product (`MachMicroDecompiler`)
        rem_prod = REMOVED_LIBRARY_PRODUCTS[0]
        rem_pkg = os.path.join(work_root, "NegativeProductProbe")
        rem_src = os.path.join(rem_pkg, "Sources", "TryRemovedProduct")
        os.makedirs(rem_src, exist_ok=True)
        _write_single_product_package_swift(rem_pkg, "NegativeProductProbe", "TryRemovedProduct", rem_prod)
        with open(os.path.join(rem_src, "main.swift"), "w", encoding="utf-8") as fh:
            fh.write(f"import {rem_prod}\n")
        rem_res = run_cmd(["swift", "build"], cwd=rem_pkg, env=env, timeout=BUILD_TIMEOUT_SECONDS)
        rem_diffs = validate_negative_probe_result(
            probe_name=f"removed_product_{rem_prod}",
            symbol=rem_prod,
            module="MachGraph",
            returncode=rem_res["returncode"],
            stdout=rem_res["stdout"],
            stderr=rem_res["stderr"],
        )
        diffs.extend(rem_diffs)
        probe_reports.append(
            {
                "probe": f"removed_product_{rem_prod}",
                "module": "MachGraph",
                "symbol": rem_prod,
                "expected_access": "unexported_product",
                "returncode": rem_res["returncode"],
                "elapsed_s": rem_res["elapsed_s"],
                "rejected_as_expected": len(rem_diffs) == 0,
            }
        )

    return {
        "passed": len(diffs) == 0,
        "en_doc": sanitize_display_path(en_doc_path, repo_root),
        "zh_doc": sanitize_display_path(zh_doc_path, repo_root),
        "examples": example_reports,
        "negative_probes": probe_reports,
        "diffs": diffs,
        "elapsed_s": round(time.monotonic() - start_ts, 3),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="m5-lib-examples.py",
        description="Verify MachGraph M5 bilingual library examples and public API boundary in isolated Swift packages.",
    )
    p.add_argument("docs", nargs="*", help="optional positional [en_doc] [zh_doc] markdown paths")
    p.add_argument("--en-doc", default=None, help="English markdown file (default: docs/library-examples.md)")
    p.add_argument("--zh-doc", default=None, help="Chinese markdown file (default: docs/library-examples.zh-CN.md)")
    p.add_argument("--repo-root", default=REPO_ROOT, help="MachGraph repository root to copy and test")
    p.add_argument("--json-out", default=None, help="optional path to write structured JSON report")
    p.add_argument("--txt-out", default=None, help="optional path to write plain-text summary report")
    p.add_argument("--verbose", action="store_true", help="print per-example and per-probe progress")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    repo_root = os.path.abspath(args.repo_root)
    if len(args.docs) > 2:
        parser.error("at most two positional markdown files ([en_doc] [zh_doc]) may be provided")

    en_doc = args.en_doc or (args.docs[0] if len(args.docs) >= 1 else os.path.join(repo_root, "docs", "library-examples.md"))
    zh_doc = args.zh_doc or (args.docs[1] if len(args.docs) >= 2 else os.path.join(repo_root, "docs", "library-examples.zh-CN.md"))

    report = run_acceptance_suite(
        repo_root=repo_root,
        en_doc_path=en_doc,
        zh_doc_path=zh_doc,
        verbose=args.verbose,
    )

    lines: List[str] = [
        "=== MachGraph M5 Library Examples & Public API Boundary Acceptance ===",
        f"Timestamp (UTC): {report.get('timestamp_utc', '')}",
        f"Docs:            {report.get('en_doc', '')} | {report.get('zh_doc', '')}",
        f"Examples:        {len(report['examples'])}/3 built & verified",
        f"Negative probes: {sum(1 for p in report['negative_probes'] if p['rejected_as_expected'])}/{len(report['negative_probes'])} rejected as expected",
        f"Elapsed:         {report['elapsed_s']:.2f}s",
    ]
    for ex in report["examples"]:
        lines.append(
            f"  [EXAMPLE] {ex['module']}: lines={ex['line_count']}/{MAX_EXAMPLE_LINES} "
            f"build_rc={ex['build_returncode']} ({ex['build_elapsed_s']}s) "
            f"run_rc={ex['run_returncode']} ({ex['run_elapsed_s']}s)"
        )
    if report["passed"]:
        lines.append(
            f"[PASS] m5-lib-examples: examples=3/3 probes={len(report['negative_probes'])}/{len(report['negative_probes'])} "
            f"diffs=0 elapsed={report['elapsed_s']:.2f}s"
        )
    else:
        lines.append(f"[FAIL] m5-lib-examples: diffs={len(report['diffs'])} elapsed={report['elapsed_s']:.2f}s")
        for d in report["diffs"][:12]:
            lines.append("  DIFF: " + sanitize_text(json.dumps(d, ensure_ascii=False, sort_keys=True)))

    txt_payload = "\n".join(lines) + "\n"
    print(txt_payload, end="")

    if args.txt_out:
        out_dir = os.path.dirname(os.path.abspath(args.txt_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.txt_out, "w", encoding="utf-8") as fh:
            fh.write(txt_payload)

    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
