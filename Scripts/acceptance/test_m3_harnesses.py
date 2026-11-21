#!/usr/bin/env python3
"""Unit tests for `Scripts/acceptance/m3-metadata-differential.py` (M3 Stage 1: symbols & dylibs)."""

import contextlib
import importlib.util
import io
import json
import os
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))


def _load_m3_harness():
    path = os.path.join(SCRIPT_DIR, "m3-metadata-differential.py")
    spec = importlib.util.spec_from_file_location("m3_metadata_differential_mod", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["m3_metadata_differential_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


m3_diff = _load_m3_harness()


def _read_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_thin_arm64_header(path: str, filetype: int = 2, with_lc_id_dylib: bool = False) -> None:
    lc_bytes = b""
    ncmds = 0
    if with_lc_id_dylib:
        name = b"/usr/local/lib/libdemo.1.dylib\x00\x00"
        cmd_size = 24 + len(name)
        lc_bytes = struct.pack("<IIIIII", 0xD, cmd_size, 24, 2, 0x00020300, 0x00010000) + name
        ncmds = 1
    hdr = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        2,
        filetype,
        ncmds,
        len(lc_bytes),
        0x80,
        0,
    )
    with open(path, "wb") as fh:
        fh.write(hdr + lc_bytes + b"\x00" * 64)


def _make_executable_script(directory: str, filename: str, body: str) -> str:
    p = os.path.join(directory, filename)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


class TestM3SymbolsSubcheck(unittest.TestCase):
    """Verify `(address, name)` multiset comparison, `U`/`<redacted function N>` filtering, and diff examples."""

    def test_symbols_multiset_pass_ignores_undefined_and_redacted_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "sample_exec")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "out.json")

            nm_stdout = (
                b"                 U _malloc\n"
                b"                 u _weak_import\n"
                b"0000000100001000 t <redacted function 0>\n"
                b"0000000100001010 t _bseek.cold.1\n"
                b"0000000100001010 t _btell.cold.1\n"
                b"0000000100001020 t _OUTLINED_FUNCTION_1\n"
                b"0000000100001020 t _OUTLINED_FUNCTION_1\n"
            )
            mg_symbols_payload = {
                "fileName": "sample_exec",
                "isDemo": False,
                "realCount": 4,
                "inferredCount": 1,
                "realSymbols": [
                    {"name": "_bseek.cold.1", "address": 0x100001010, "inferred": False, "source": "lc_symtab"},
                    {"name": "_btell.cold.1", "address": 0x100001010, "inferred": False, "source": "lc_symtab"},
                    {"name": "_OUTLINED_FUNCTION_1", "address": 0x100001020, "inferred": False, "source": "lc_symtab"},
                    {"name": "_OUTLINED_FUNCTION_1", "address": 0x100001020, "inferred": False, "source": "lc_symtab"},
                ],
                "inferredSymbols": [
                    {"name": "sub_100001000", "address": 0x100001000, "inferred": True, "source": "lc_function_starts"}
                ],
            }

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"x86_64 arm64e arm64e.x1\n", stderr=b"")
                if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                    self.assertEqual(cmd[3:5], ["-arch", "arm64e"])
                    return subprocess.CompletedProcess(cmd, 0, stdout=nm_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "symbols":
                    return subprocess.CompletedProcess(
                        cmd, 0, stdout=json.dumps(mg_symbols_payload).encode("utf-8"), stderr=b""
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([bin_path, "--only", "symbols", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 0, buf.getvalue())
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["checks"]["symbols"]["total_diffs"], 0)
            self.assertEqual(report["checks"]["symbols"]["total_mg_items"], 4)

    def test_symbols_multiset_detects_same_address_dedup_and_caps_examples_at_five(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "dedup_bug")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "out.json")

            # 7 symbols missing in MachGraph (including a multiset count 2 -> 1 mismatch) -> examples capped at 5
            nm_lines = [
                b"0000000100001000 t _dup_sym\n",
                b"0000000100001000 t _dup_sym\n",
            ] + [f"00000001000010{i:02x} T _missing_{i}\n".encode("ascii") for i in range(1, 7)]
            mg_payload = {
                "fileName": "dedup_bug",
                "isDemo": False,
                "realCount": 1,
                "inferredCount": 0,
                "realSymbols": [
                    {"name": "_dup_sym", "address": 0x100001000, "inferred": False, "source": "lc_symtab"}
                ],
                "inferredSymbols": [],
            }

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                    self.assertEqual(cmd[3:5], ["-arch", "arm64"])
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"".join(nm_lines), stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "symbols":
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(mg_payload).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([bin_path, "--only", "symbols", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 1)
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["checks"]["symbols"]["total_diffs"], 7)
            self.assertEqual(len(report["checks"]["symbols"]["examples"]), 5)


class TestM3DylibsSubcheck(unittest.TestCase):
    """Verify ordered dylib tuple comparison, `MH_DYLIB` `installID` handling, and `info` text mode check."""

    def test_mh_dylib_compares_first_otool_line_against_install_id_and_remaining_against_libraries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dylib_path = os.path.join(tmp, "libdemo.1.dylib")
            _write_thin_arm64_header(dylib_path, filetype=6, with_lc_id_dylib=True)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "out.json")

            otool_stdout = (
                f"{dylib_path}:\n"
                "\t/usr/local/lib/libdemo.1.dylib (compatibility version 1.0.0, current version 2.3.0)\n"
                "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1359.0.0)\n"
                "\t/usr/lib/libweak.dylib (compatibility version 2.0.0, current version 4.5.0, weak)\n"
                "\t/usr/lib/libreexport.dylib (compatibility version 1.0.0, current version 3.0.0, reexport)\n"
            ).encode("utf-8")

            mg_info_json = {
                "fileName": "libdemo.1.dylib",
                "architecture": "arm64e (PAC)",
                "installID": {
                    "installName": "/usr/local/lib/libdemo.1.dylib",
                    "compatibilityVersion": "1.0.0",
                    "currentVersion": "2.3.0",
                },
                "libraries": [
                    {
                        "ordinal": 1,
                        "installName": "/usr/lib/libSystem.B.dylib",
                        "compatibilityVersion": "1.0.0",
                        "currentVersion": "1359.0.0",
                        "isWeak": False,
                        "isReexport": False,
                    },
                    {
                        "ordinal": 2,
                        "installName": "/usr/lib/libweak.dylib",
                        "compatibilityVersion": "2.0.0",
                        "currentVersion": "4.5.0",
                        "isWeak": True,
                        "isReexport": False,
                    },
                    {
                        "ordinal": 3,
                        "installName": "/usr/lib/libreexport.dylib",
                        "compatibilityVersion": "1.0.0",
                        "currentVersion": "3.0.0",
                        "isWeak": False,
                        "isReexport": True,
                    },
                ],
            }
            mg_info_text = (
                "File:          libdemo.1.dylib\n"
                "Install ID:    /usr/local/lib/libdemo.1.dylib (compatibility version 1.0.0, current version 2.3.0)\n"
                "Libraries:     3\n"
                "  /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1359.0.0)\n"
                "  /usr/lib/libweak.dylib (compatibility version 2.0.0, current version 4.5.0, weak)\n"
                "  /usr/lib/libreexport.dylib (compatibility version 1.0.0, current version 3.0.0, reexport)\n"
            ).encode("utf-8")

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "otool"] and "-L" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=otool_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "info":
                    if "--json" in cmd:
                        return subprocess.CompletedProcess(
                            cmd, 0, stdout=json.dumps(mg_info_json).encode("utf-8"), stderr=b""
                        )
                    return subprocess.CompletedProcess(cmd, 0, stdout=mg_info_text, stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([dylib_path, "--only", "dylibs", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 0, buf.getvalue())

            # 1) Mutate text output to omit libraries -> must fail!
            def fake_run_missing_text(cmd, *args, **kwargs):
                if cmd[0] == fake_mg and cmd[1] == "info" and "--json" not in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"File: libdemo.1.dylib\n", stderr=b"")
                return fake_run(cmd, *args, **kwargs)

            with mock.patch.object(
                m3_diff.subprocess, "run", side_effect=fake_run_missing_text
            ), contextlib.redirect_stdout(io.StringIO()):
                rc_bad_text = m3_diff.main([dylib_path, "--only", "dylibs", "--machgraph", fake_mg])
            self.assertEqual(rc_bad_text, 1)

            # 2) Mutate order of libraries (swap index 1 and 2) -> must fail ordered comparison!
            swapped = dict(mg_info_json)
            swapped["libraries"] = [mg_info_json["libraries"][0], mg_info_json["libraries"][2], mg_info_json["libraries"][1]]

            def fake_run_swapped(cmd, *args, **kwargs):
                if cmd[0] == fake_mg and cmd[1] == "info" and "--json" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(swapped).encode("utf-8"), stderr=b"")
                return fake_run(cmd, *args, **kwargs)

            with mock.patch.object(
                m3_diff.subprocess, "run", side_effect=fake_run_swapped
            ), contextlib.redirect_stdout(io.StringIO()):
                rc_swapped = m3_diff.main([dylib_path, "--only", "dylibs", "--machgraph", fake_mg])
            self.assertEqual(rc_swapped, 1)


class TestM3NonUTF8CrashesConcurrencyAndRecord(unittest.TestCase):
    """Verify non-UTF-8 tolerance, crash/timeout failure handling, `<= 6` subprocess cap, and `--record` hygiene."""

    def test_non_utf8_bytes_and_home_or_email_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "nonutf8_bin")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "out.json")

            nm_raw = b"\xff\xfe header:\n0000000100000000 T __mh_execute_header\n"
            mg_syms = {
                "fileName": "nonutf8_bin",
                "isDemo": False,
                "realCount": 1,
                "inferredCount": 0,
                "realSymbols": [
                    {"name": "__mh_execute_header", "address": 0x100000000, "inferred": False, "source": "lc_symtab"}
                ],
                "inferredSymbols": [],
            }

            sample_home = os.path.expanduser("~")
            sample_mail = "dev" + chr(64) + "example.invalid"

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"\xff\xfe")
                if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout=nm_raw, stderr=b"\x80\x81")
                if cmd[:2] == ["xcrun", "nm"] and "--version" in cmd:
                    ver_line = f"Apple LLVM version 17.0.0 ({sample_home}/toolchain {sample_mail})\n".encode("utf-8")
                    return subprocess.CompletedProcess(cmd, 0, stdout=ver_line, stderr=b"")
                if cmd[0] == fake_mg:
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(mg_syms).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc = m3_diff.main([bin_path, "--only", "symbols", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 0)
            payload = _read_json(out_json)
            serialized = json.dumps(payload)
            self.assertEqual(payload["summary"]["non_utf8_output_files"], 1)
            self.assertNotIn(sample_home, serialized)
            self.assertNotIn(sample_mail, serialized)

    def test_crash_and_timeout_both_fail_and_concurrent_subprocesses_never_exceed_six(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            files = []
            for i in range(14):
                p = os.path.join(tmp, f"bin_{i:02d}")
                _write_thin_arm64_header(p, filetype=2)
                files.append(p)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")

            lock = threading.Lock()
            active = 0
            peak_active = 0

            def tracked_run(cmd, *args, **kwargs):
                nonlocal active, peak_active
                with lock:
                    active += 1
                    if active > peak_active:
                        peak_active = active
                try:
                    time.sleep(0.01)
                    if cmd[0] == "lipo":
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                    if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")
                    if cmd[0] == fake_mg and "bin_03" in cmd[2]:
                        return subprocess.CompletedProcess(cmd, -11, stdout=b"", stderr=b"segmentation fault")
                    if cmd[0] == fake_mg and "bin_07" in cmd[2]:
                        raise subprocess.TimeoutExpired(cmd=cmd, timeout=60.0)
                    if cmd[0] == fake_mg:
                        empty = {
                            "fileName": os.path.basename(cmd[2]),
                            "isDemo": False,
                            "realCount": 0,
                            "inferredCount": 0,
                            "realSymbols": [],
                            "inferredSymbols": [],
                        }
                        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(empty).encode("utf-8"), stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")
                finally:
                    with lock:
                        active -= 1

            out_json = os.path.join(tmp, "conc.json")
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=tracked_run), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(io.StringIO()):
                rc = m3_diff.main(
                    [*files, "--only", "symbols", "--workers", "16", "--machgraph", fake_mg, "--json-out", out_json]
                )

            self.assertEqual(rc, 1)
            self.assertLessEqual(peak_active, 6, f"Peak concurrent subprocesses {peak_active} exceeded limit 6")
            payload = _read_json(out_json)
            self.assertEqual(payload["verdict"], "FAIL")
            self.assertEqual(payload["summary"]["crashes_or_failures"], 2)

    def test_record_writes_m3_metadata_date_json_when_clean_and_refuses_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "clean_bin")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")

            with contextlib.redirect_stderr(io.StringIO()):
                rc_bad_only = m3_diff.main(["quick", "--only", "nosuchcheck", "--machgraph", fake_mg])
            self.assertEqual(rc_bad_only, 2)

            with mock.patch.object(m3_diff, "is_worktree_clean", return_value=False), mock.patch.object(
                m3_diff, "evaluate_one_binary", side_effect=AssertionError("must not run on dirty --record")
            ), contextlib.redirect_stderr(io.StringIO()):
                rc_dirty = m3_diff.main(["quick", "--record", "--machgraph", fake_mg])
            self.assertEqual(rc_dirty, 1)

            # Verify default_record_path uses reports/m3-metadata-<YYYY-MM-DD>.json
            rec_path = m3_diff.default_record_path("2026-11-21", repo_root=tmp)
            self.assertEqual(rec_path, os.path.join(tmp, "reports", "m3-metadata-2026-11-21.json"))
            self.assertEqual(m3_diff.resolve_targets(["quick"]), ("quick", ["/bin/ls"]))
            self.assertEqual(m3_diff.resolve_targets(["standard"]), ("standard", ["/bin/ls", "/usr/bin/ssh", "/usr/bin/vim"]))


class TestM3EntitlementsSubcheck(unittest.TestCase):
    """Verify native JSON type equality (`True` vs `1` vs `"true"`), leading-space keys, and empty/unsigned `{}`."""

    def test_entitlements_pass_on_native_types_leading_space_empty_and_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            entitled_bin = os.path.join(tmp, "entitled_bin")
            unentitled_bin = os.path.join(tmp, "unentitled_bin")
            unsigned_bin = os.path.join(tmp, "unsigned_bin")
            for p in (entitled_bin, unentitled_bin, unsigned_bin):
                _write_thin_arm64_header(p, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "ent_pass.json")

            ref_dict = {
                " com.apple.security.app-sandbox": True,
                "com.apple.security.cs.allow-dyld-environment-variables": False,
                "com.apple.private.amfi.version-restriction": 1,
                "keychain-access-groups": ["com.apple.aea.cli", "group, with, comma"],
                "com.apple.private.MobileContainerManager.lookup": {
                    "daemon": ["com.apple.bird"],
                    "enabled": True,
                    "empty": {},
                },
            }
            xml_bytes = plistlib.dumps(ref_dict, fmt=plistlib.FMT_XML) + b"\x00\x00"

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[0] == "/usr/bin/codesign":
                    target = cmd[-1]
                    if target == entitled_bin:
                        return subprocess.CompletedProcess(cmd, 0, stdout=xml_bytes, stderr=b"Executable=" + target.encode())
                    if target == unentitled_bin:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"Executable=" + target.encode())
                    return subprocess.CompletedProcess(
                        cmd, 1, stdout=b"", stderr=f"{target}: code object is not signed at all\n".encode("utf-8")
                    )
                if cmd[0] == fake_mg and cmd[1] == "codesign":
                    target = cmd[2]
                    if target == entitled_bin:
                        payload = {"fileName": "entitled_bin", "isSigned": True, "entitlements": ref_dict}
                    elif target == unentitled_bin:
                        payload = {"fileName": "unentitled_bin", "isSigned": True, "entitlements": {}}
                    else:
                        payload = {"fileName": "unsigned_bin", "isSigned": False, "entitlements": {}}
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main(
                    [
                        entitled_bin,
                        unentitled_bin,
                        unsigned_bin,
                        "--only",
                        "entitlements",
                        "--machgraph",
                        fake_mg,
                        "--json-out",
                        out_json,
                    ]
                )

            self.assertEqual(rc, 0, buf.getvalue())
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["checks"]["entitlements"]["matched_files"], 3)
            self.assertEqual(report["checks"]["entitlements"]["total_ref_items"], 5)
            self.assertEqual(report["checks"]["entitlements"]["total_mg_items"], 5)
            self.assertEqual(report["checks"]["entitlements"]["total_diffs"], 0)

    def test_entitlements_strict_type_comparison_distinguishes_bool_true_from_int_one_and_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "type_check_bin")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")

            ref_dict = {
                "flag_bool": True,
                "ver_int": 1,
                "nested_list": [True, 0],
            }
            xml_bytes = plistlib.dumps(ref_dict, fmt=plistlib.FMT_XML)

            bad_mg_dicts = [
                # 1) Bool replaced by int 1 (Python `True == 1` trap!)
                {"flag_bool": 1, "ver_int": 1, "nested_list": [True, 0]},
                # 2) Int 1 replaced by Bool True
                {"flag_bool": True, "ver_int": True, "nested_list": [True, 0]},
                # 3) Nested list Bool True replaced by int 1, or int 0 replaced by False
                {"flag_bool": True, "ver_int": 1, "nested_list": [True, False]},
                # 4) Flattened strings ("true", "1")
                {"flag_bool": "true", "ver_int": "1", "nested_list": "[true, 0]"},
            ]

            for idx, bad_ent in enumerate(bad_mg_dicts):
                out_json = os.path.join(tmp, f"bad_{idx}.json")

                def fake_run(cmd, *args, _bad=bad_ent, **kwargs):
                    if cmd[0] == "lipo":
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                    if cmd[0] == "/usr/bin/codesign":
                        return subprocess.CompletedProcess(cmd, 0, stdout=xml_bytes, stderr=b"")
                    if cmd[0] == fake_mg and cmd[1] == "codesign":
                        payload = {"fileName": "type_check_bin", "isSigned": True, "entitlements": _bad}
                        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload).encode("utf-8"), stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

                with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                    io.StringIO()
                ):
                    rc = m3_diff.main(
                        [bin_path, "--only", "entitlements", "--machgraph", fake_mg, "--json-out", out_json]
                    )

                self.assertEqual(rc, 1, f"Expected mutation #{idx} ({bad_ent}) to fail strict type check")
                report = _read_json(out_json)
                self.assertEqual(report["verdict"], "FAIL")
                self.assertGreaterEqual(report["checks"]["entitlements"]["total_diffs"], 1)

    def test_entitlements_detects_trimmed_leading_space_and_duplicate_der_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "wifip2pd_bug")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "space_bug.json")

            ref_dict = {" com.apple.security.app-sandbox": True}
            xml_bytes = plistlib.dumps(ref_dict, fmt=plistlib.FMT_XML)
            mg_buggy = {
                " com.apple.security.app-sandbox": True,
                "com.apple.security.app-sandbox": True,
            }

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[0] == "/usr/bin/codesign":
                    return subprocess.CompletedProcess(cmd, 0, stdout=xml_bytes, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "codesign":
                    payload = {"fileName": "wifip2pd_bug", "isSigned": True, "entitlements": mg_buggy}
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc = m3_diff.main([bin_path, "--only", "entitlements", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 1)
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["checks"]["entitlements"]["total_diffs"], 1)
            self.assertEqual(report["checks"]["entitlements"]["examples"][0]["kind"], "extra_in_machgraph")


class TestM3DemangleSubcheck(unittest.TestCase):
    """Verify corpus-level Swift (`xcrun swift-demangle -compact` stdin) and C++ (`/usr/bin/c++filt`) gates."""

    def test_demangle_passes_above_99_pct_with_zero_wrong_and_100_pct_plain_z_and_empty_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_a = os.path.join(tmp, "swift_cpp_bin")
            bin_empty = os.path.join(tmp, "pure_c_bin")
            _write_thin_arm64_header(bin_a, filetype=2)
            _write_thin_arm64_header(bin_empty, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "demangle_pass.json")

            swift_syms = [f"_$s4Demo4Func{i}yyF" for i in range(99)] + ["_T04Demo6LegacyyyF"]
            cpp_zz_syms = [f"__Z4func{i}i" for i in range(99)] + ["__Z8fallbackv"]
            plain_z_syms = ["_ZeroFilesTested", "_Zfirst", "_ZinComputeProgramAlign"]

            nm_lines = [b"                 U " + s.encode("ascii") + b"\n" for s in swift_syms[:50]]
            nm_lines += [f"000000010000{i:04x} T {s}\n".encode("ascii") for i, s in enumerate(swift_syms[50:], 1)]
            nm_lines += [f"000000010001{i:04x} T {s}\n".encode("ascii") for i, s in enumerate(cpp_zz_syms, 1)]
            nm_lines += [f"000000010002{i:04x} D {s}\n".encode("ascii") for i, s in enumerate(plain_z_syms, 1)]
            nm_lines.append(b"0000000100030000 T _main\n")

            def ref_demangle_one(sym: str) -> str:
                if sym.startswith("_$s4Demo4Func"):
                    return f"Demo.Func{sym[13:-3]}() -> ()"
                if sym == "_T04Demo6LegacyyyF":
                    return "Demo.Legacy() -> ()"
                if sym.startswith("__Z4func"):
                    return f"func{sym[8:-1]}(int)"
                if sym == "__Z8fallbackv":
                    return "fallback()"
                return sym

            def mg_demangle_one(sym: str) -> str:
                # 1 raw fallback out of 100 in Swift (99.0% equal, 0 wrong) and 1 raw fallback out of 100 in C++ (99.0% equal, 0 wrong)
                if sym in ("_T04Demo6LegacyyyF", "__Z8fallbackv"):
                    return sym
                return ref_demangle_one(sym)

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                    target = cmd[-1]
                    if target == bin_a:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"".join(nm_lines), stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"0000000100001000 T _main\n", stderr=b"")
                if cmd[:3] == ["xcrun", "swift-demangle", "-compact"]:
                    raw_in = kwargs.get("input", b"").decode("utf-8").splitlines()
                    out = "\n".join(ref_demangle_one(s) for s in raw_in) + ("\n" if raw_in else "")
                    return subprocess.CompletedProcess(cmd, 0, stdout=out.encode("utf-8"), stderr=b"")
                if cmd[0] == "/usr/bin/c++filt":
                    arg_syms = cmd[2:] if len(cmd) >= 2 and cmd[1] == "--" else cmd[1:]
                    if not arg_syms and kwargs.get("input"):
                        arg_syms = kwargs["input"].decode("utf-8").splitlines()
                    out = "\n".join(ref_demangle_one(s) for s in arg_syms) + ("\n" if arg_syms else "")
                    return subprocess.CompletedProcess(cmd, 0, stdout=out.encode("utf-8"), stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "demangle":
                    raw_in = kwargs.get("input", b"").decode("utf-8").splitlines()
                    if "--json" in cmd:
                        arr = [
                            {"input": s, "output": mg_demangle_one(s), "demangled": mg_demangle_one(s) != s}
                            for s in raw_in
                        ]
                        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(arr).encode("utf-8"), stderr=b"")
                    out = "\n".join(mg_demangle_one(s) for s in raw_in) + ("\n" if raw_in else "")
                    return subprocess.CompletedProcess(cmd, 0, stdout=out.encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([bin_a, "--only", "demangle", "--machgraph", fake_mg, "--json-out", out_json])
            self.assertEqual(rc, 0, buf.getvalue())
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "PASS")
            dem = report["checks"]["demangle"]
            self.assertEqual(dem["swift"]["equal"], 99)
            self.assertEqual(dem["swift"]["raw_passthrough"], 1)
            self.assertEqual(dem["swift"]["wrong"], 0)
            self.assertEqual(dem["cpp"]["equal"], 99)
            self.assertEqual(dem["cpp"]["raw_passthrough"], 1)
            self.assertEqual(dem["cpp"]["wrong"], 0)
            self.assertEqual(dem["plain_c_z"]["equal"], 3)
            self.assertEqual(dem["plain_c_z"]["wrong"], 0)

            # Empty Swift/C++ buckets (e.g. pure C binary /bin/ls) must also pass cleanly
            out_empty = os.path.join(tmp, "demangle_empty.json")
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc_empty = m3_diff.main(
                    [bin_empty, "--only", "demangle", "--machgraph", fake_mg, "--json-out", out_empty]
                )
            self.assertEqual(rc_empty, 0)

    def test_demangle_fails_on_single_wrong_output_or_plain_z_underscore_strip_or_below_99_pct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "mutated_bin")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")

            swift_syms = [f"_$s4Demo4Func{i}yyF" for i in range(100)]
            cpp_syms = [f"__Z4func{i}i" for i in range(100)]
            nm_stdout = "".join(
                [f"000000010000{i:04x} T {s}\n" for i, s in enumerate(swift_syms + cpp_syms, 1)]
                + ["0000000100090000 D _ZeroFilesTested\n"]
            ).encode("ascii")

            def ref_one(s: str) -> str:
                if s.startswith("_$s4Demo4Func"):
                    return f"Demo.Func{s[13:-3]}() -> ()"
                if s.startswith("__Z4func"):
                    return f"func{s[8:-1]}(int)"
                return s

            # Case 1: 99% Swift equal, 0% raw, 1% wrong (stripped '_' instead of verbatim) -> MUST FAIL (wrong > 0)!
            # Case 2: 100% Swift & C++, but _ZeroFilesTested -> ZeroFilesTested -> MUST FAIL!
            # Case 3: 98% Swift equal, 2% raw passthrough, 0 wrong -> MUST FAIL (< 99.0%)!
            cases = [
                ("swift_wrong_non_raw", lambda s: s[1:] if s == "_$s4Demo4Func0yyF" else ref_one(s)),
                ("plain_z_stripped", lambda s: "ZeroFilesTested" if s == "_ZeroFilesTested" else ref_one(s)),
                ("below_99_threshold", lambda s: s if s in ("_$s4Demo4Func0yyF", "_$s4Demo4Func1yyF") else ref_one(s)),
            ]

            for label, mutator in cases:
                out_json = os.path.join(tmp, f"{label}.json")

                def fake_run(cmd, *args, _mut=mutator, **kwargs):
                    if cmd[0] == "lipo":
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                    if cmd[:3] == ["xcrun", "nm", "--no-dyldinfo"]:
                        return subprocess.CompletedProcess(cmd, 0, stdout=nm_stdout, stderr=b"")
                    if cmd[:3] == ["xcrun", "swift-demangle", "-compact"]:
                        lines = kwargs.get("input", b"").decode("utf-8").splitlines()
                        return subprocess.CompletedProcess(
                            cmd, 0, stdout=("\n".join(ref_one(x) for x in lines) + "\n").encode("utf-8"), stderr=b""
                        )
                    if cmd[0] == "/usr/bin/c++filt":
                        syms = cmd[2:] if len(cmd) >= 2 and cmd[1] == "--" else cmd[1:]
                        if not syms and kwargs.get("input"):
                            syms = kwargs["input"].decode("utf-8").splitlines()
                        return subprocess.CompletedProcess(
                            cmd, 0, stdout=("\n".join(ref_one(x) for x in syms) + "\n").encode("utf-8"), stderr=b""
                        )
                    if cmd[0] == fake_mg and cmd[1] == "demangle":
                        lines = kwargs.get("input", b"").decode("utf-8").splitlines()
                        if "--json" in cmd:
                            arr = [{"input": x, "output": _mut(x), "demangled": _mut(x) != x} for x in lines]
                            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(arr).encode("utf-8"), stderr=b"")
                        return subprocess.CompletedProcess(
                            cmd, 0, stdout=("\n".join(_mut(x) for x in lines) + "\n").encode("utf-8"), stderr=b""
                        )
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

                with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                    io.StringIO()
                ):
                    rc = m3_diff.main([bin_path, "--only", "demangle", "--machgraph", fake_mg, "--json-out", out_json])
                self.assertEqual(rc, 1, f"Case {label} must fail")
                rep = _read_json(out_json)
                self.assertEqual(rep["verdict"], "FAIL")


def _write_thin_arm64_with_sections(path: str) -> None:
    """Write a minimal thin ARM64e Mach-O header with __TEXT (__text, __cstring) and __DATA (__data, __cfstring)."""
    secs = [
        (b"__text", b"__TEXT", 0x100001000, 0x1000, 0x80000400),
        (b"__cstring", b"__TEXT", 0x100003000, 0x200, 0x00000002),
        (b"__objc_methname", b"__TEXT", 0x100003200, 0x100, 0x00000002),
        (b"__cfstring", b"__DATA_CONST", 0x100004000, 0x80, 0x00000000),
        (b"__data", b"__DATA", 0x100008000, 0x200, 0x00000000),
    ]
    seg_hdr = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72 + len(secs) * 80,
        b"__TEXT\x00" + b"\x00" * 9,
        0x100000000,
        0x10000,
        0,
        0x1000,
        5,
        5,
        len(secs),
        0,
    )
    sec_blobs = []
    for sect, seg, addr, size, flags in secs:
        sec_blobs.append(
            struct.pack(
                "<16s16sQQIIIIIIII",
                sect.ljust(16, b"\x00"),
                seg.ljust(16, b"\x00"),
                addr,
                size,
                0,
                2,
                0,
                0,
                flags,
                0,
                0,
                0,
            )
        )
    lc_bytes = seg_hdr + b"".join(sec_blobs)
    mh = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 2, 2, 1, len(lc_bytes), 0x85, 0)
    with open(path, "wb") as fh:
        fh.write(mh + lc_bytes + b"\x00" * 128)


class TestM3XrefsSubcheck(unittest.TestCase):
    """Verify `bl` CALL edge equality, G25 `STRING_REF` target section enforcement, and `kind_counts` recording."""

    def test_xrefs_pass_exact_bl_edges_valid_string_sections_and_kind_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "xrefs_ok")
            _write_thin_arm64_with_sections(bin_path)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "xrefs_ok.json")

            objdump_stdout = (
                b"(__TEXT,__text) section\n"
                b"100001000:\tb\t0x100001040\n"
                b"100001004:\tbl\t0x100001200\n"
                b"100001008:\tblraa\tx16, x17\n"
                b"10000100c:\tbl\t0x100001300 ; stub\n"
            )
            mg_xrefs_payload = {
                "fileName": "xrefs_ok",
                "isDemo": False,
                "xrefCount": 7,
                "xrefs": [
                    {"fromAddress": 0x100001000, "toAddress": 0x100001040, "kind": "JMP"},
                    {"fromAddress": 0x100001004, "toAddress": 0x100001200, "kind": "CALL"},
                    {"fromAddress": 0x10000100C, "toAddress": 0x100001300, "kind": "CALL"},
                    {"fromAddress": 0x100001010, "toAddress": 0x100001500, "kind": "CODE_REF"},
                    {"fromAddress": 0x100001014, "toAddress": 0x100008020, "kind": "DATA_READ"},
                    {"fromAddress": 0x100001018, "toAddress": 0x100003010, "kind": "STRING_REF"},
                    {"fromAddress": 0x10000101C, "toAddress": 0x100004000, "kind": "STRING_REF"},
                ],
            }

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "llvm-objdump"] and "-d" in cmd:
                    self.assertIn("--arch=arm64e", cmd)
                    self.assertIn("--mcpu=apple-m1", cmd)
                    self.assertIn("--mattr=+bti", cmd)
                    return subprocess.CompletedProcess(cmd, 0, stdout=objdump_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "xrefs":
                    return subprocess.CompletedProcess(
                        cmd, 0, stdout=json.dumps(mg_xrefs_payload).encode("utf-8"), stderr=b""
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([bin_path, "--only", "xrefs", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 0, buf.getvalue())
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "PASS")
            xchk = report["checks"]["xrefs"]
            self.assertEqual(xchk["total_ref_items"], 2)
            self.assertEqual(xchk["total_mg_items"], 2)
            self.assertEqual(xchk["total_diffs"], 0)
            self.assertEqual(xchk["total_xrefs"], 7)
            self.assertEqual(xchk["non_string_section_string_refs"], 0)
            self.assertEqual(
                xchk["kind_counts"],
                {"CALL": 2, "CODE_REF": 1, "DATA_READ": 1, "JMP": 1, "STRING_REF": 2},
            )
            self.assertEqual(
                xchk["string_ref_sections"],
                {"__DATA_CONST,__cfstring": 1, "__TEXT,__cstring": 1},
            )

    def test_xrefs_fails_on_missing_or_extra_bl_edges_and_g25_non_string_section_string_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "xrefs_bad")
            _write_thin_arm64_with_sections(bin_path)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")

            objdump_stdout = (
                b"100001004:\tbl\t0x100001200\n"
                b"10000100c:\tbl\t0x100001300\n"
            )

            # Case A: G25 bug - STRING_REF pointing into __TEXT,__text and __DATA,__data
            g25_payload = {
                "fileName": "xrefs_bad",
                "isDemo": False,
                "xrefs": [
                    {"fromAddress": 0x100001004, "toAddress": 0x100001200, "kind": "CALL"},
                    {"fromAddress": 0x10000100C, "toAddress": 0x100001300, "kind": "CALL"},
                    {"fromAddress": 0x100001010, "toAddress": 0x100001500, "kind": "STRING_REF"},
                    {"fromAddress": 0x100001014, "toAddress": 0x100008020, "kind": "STRING_REF"},
                ],
            }
            out_g25 = os.path.join(tmp, "g25_fail.json")

            def fake_run_g25(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "llvm-objdump"] and "-d" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=objdump_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "xrefs":
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(g25_payload).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run_g25), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc_g25 = m3_diff.main([bin_path, "--only", "xrefs", "--machgraph", fake_mg, "--json-out", out_g25])

            self.assertEqual(rc_g25, 1)
            rep_g25 = _read_json(out_g25)
            self.assertEqual(rep_g25["verdict"], "FAIL")
            self.assertEqual(rep_g25["checks"]["xrefs"]["non_string_section_string_refs"], 2)
            self.assertEqual(rep_g25["checks"]["xrefs"]["total_diffs"], 2)
            self.assertEqual(rep_g25["checks"]["xrefs"]["examples"][0]["target_section"], "__TEXT,__text")

            # Case B: Missing bl edge + extra CALL edge
            edge_diff_payload = {
                "fileName": "xrefs_bad",
                "isDemo": False,
                "xrefs": [
                    {"fromAddress": 0x100001004, "toAddress": 0x100001200, "kind": "CALL"},
                    {"fromAddress": 0x100001020, "toAddress": 0x100001999, "kind": "CALL"},
                ],
            }
            out_edge = os.path.join(tmp, "edge_fail.json")

            def fake_run_edge(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "llvm-objdump"] and "-d" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=objdump_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "xrefs":
                    return subprocess.CompletedProcess(
                        cmd, 0, stdout=json.dumps(edge_diff_payload).encode("utf-8"), stderr=b""
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run_edge), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc_edge = m3_diff.main([bin_path, "--only", "xrefs", "--machgraph", fake_mg, "--json-out", out_edge])

            self.assertEqual(rc_edge, 1)
            rep_edge = _read_json(out_edge)
            self.assertEqual(rep_edge["checks"]["xrefs"]["total_diffs"], 2)

            # Case C: Old single-address CLI JSON without `xrefs` array -> must fail!
            old_cli_payload = {"fileName": "xrefs_bad", "isDemo": False, "incoming": [], "outgoing": []}
            out_old = os.path.join(tmp, "old_cli_fail.json")

            def fake_run_old(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "llvm-objdump"] and "-d" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=objdump_stdout, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "xrefs":
                    return subprocess.CompletedProcess(
                        cmd, 0, stdout=json.dumps(old_cli_payload).encode("utf-8"), stderr=b""
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run_old), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc_old = m3_diff.main([bin_path, "--only", "xrefs", "--machgraph", fake_mg, "--json-out", out_old])

            self.assertEqual(rc_old, 1)
            rep_old = _read_json(out_old)
            self.assertEqual(rep_old["checks"]["xrefs"]["examples"][0]["kind"], "invalid_xrefs_field")

if __name__ == "__main__":
    unittest.main()
