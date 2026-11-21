#!/usr/bin/env python3
"""Unit tests for `Scripts/acceptance/m3-metadata-differential.py` (M3 Stage 1: symbols & dylibs)."""

import contextlib
import importlib.util
import io
import json
import os
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


class TestM3ObjCSubcheck(unittest.TestCase):
    """Verify ObjC `otool -ov` + `otool -l` relative `__objc_selrefs` extraction and 4-set comparison."""

    def _sample_otool_and_mg(self):
        otool_l = (
            b"Section\n"
            b"  sectname __objc_selrefs\n"
            b"   segname __DATA\n"
            b"      addr 0x0000000100153540\n"
            b"      size 0x0000000000000020\n"
        )
        otool_ov = (
            b"Contents of (__DATA_CONST,__objc_classlist) section\n"
            b"0000000100140000 0x100150000\n"
            b"    isa        0x100150028\n"
            b"    superclass 0x0 _OBJC_CLASS_$_NSObject\n"
            b"    cache      0x0\n"
            b"    vtable     0x0\n"
            b"    data       0x100148000\n"
            b"        flags          0x80\n"
            b"        instanceStart  8\n"
            b"        instanceSize   16\n"
            b"        reserved       0x0\n"
            b"        ivarLayout     0x0\n"
            b"        name           0x100130000 _TtC10Calculator11AppDelegate\n"
            b"        baseMethods    0x100103518\n"
            b"            entsize 12 (relative)\n"
            b"            count   1\n"
            b"            name    0x50028 (0x100153540)\n"
            b"            types   0x31ed2 (0x1001353f6) v24@0:8@16\n"
            b"            imp     0xfff01c38 (0x100005160)\n"
            b"        ivars          0x0\n"
            b"        weakIvarLayout 0x0\n"
            b"        baseProperties 0x0\n"
            b"Meta Class\n"
            b"    isa        0x0 _OBJC_METACLASS_$_NSObject\n"
            b"    superclass 0x0 _OBJC_METACLASS_$_NSObject\n"
            b"    cache      0x0\n"
            b"    vtable     0x0\n"
            b"    data       0x100148048\n"
            b"        flags          0x81\n"
            b"        instanceStart  40\n"
            b"        instanceSize   40\n"
            b"        reserved       0x0\n"
            b"        ivarLayout     0x0\n"
            b"        name           0x100130000 _TtC10Calculator11AppDelegate\n"
            b"        baseMethods    0x100103530\n"
            b"            entsize 12 (relative)\n"
            b"            count   1\n"
            b"            name    0x50018 (0x100153548)\n"
            b"            types   0x31ee0 (0x100135410) @16@0:8\n"
            b"            imp     0xfff01c50 (0x100005180)\n"
            b"Contents of (__DATA_CONST,__objc_catlist) section\n"
            b"0000000100140010 0x100151000\n"
            b"    name      0x100130040 CGAffineTransform\n"
            b"    cls       0x0 _OBJC_CLASS_$_NSValue\n"
            b"    instanceMethods 0x100103600\n"
            b"        entsize 12 (relative)\n"
            b"        count   1\n"
            b"        name    0x4ff50 (0x100153550)\n"
            b"        types   0x31ef0 (0x100135420) {CGAffineTransform=dddddd}16@0:8\n"
            b"        imp     0xfff01d00 (0x100005300)\n"
            b"    classMethods 0x100103620\n"
            b"        entsize 12 (relative)\n"
            b"        count   1\n"
            b"        name    0x4ff38 (0x100153558)\n"
            b"        types   0x31f10 (0x100135440) @64@0:8{CGAffineTransform=dddddd}16\n"
            b"        imp     0xfff01d20 (0x100005320)\n"
            b"Contents of (__DATA_CONST,__objc_protolist) section\n"
            b"0000000100140020 0x100152000\n"
            b"    isa       0x100000000 __mh_execute_header\n"
            b"    name      0x100130080 _TtP10Calculator15DisplayProtocol_\n"
            b"    protocols 0x100152100\n"
            b"        count    1\n"
            b"        list[0]  0x100152060\n"
            b"            isa       0x100000000 __mh_execute_header\n"
            b"            name      0x1001300c0 NSApplicationDelegate\n"
            b"            protocols 0x100000000 __mh_execute_header\n"
            b"    instanceMethods 0x100000000 __mh_execute_header\n"
            b"0000000100140028 0x100152000\n"
            b"    isa       0x100000000 __mh_execute_header\n"
            b"    name      0x100130080 _TtP10Calculator15DisplayProtocol_\n"
            b"0000000100140030 0x100152060\n"
            b"    isa       0x100000000 __mh_execute_header\n"
            b"    name      0x1001300c0 NSApplicationDelegate\n"
            b"Contents of (__DATA,__objc_selrefs) section\n"
            b"0000000100153540  0x100133000 applicationWillFinishLaunching:\n"
            b"0000000100153548  0x100133020 sharedAppDelegate\n"
            b"0000000100153550  0x100133040 cgAffineTransformValue\n"
            b"0000000100153558  0x100133060 valueWithCGAffineTransform:\n"
        )
        mg_objc = {
            "fileName": "sample_objc",
            "classCount": 1,
            "instanceMethodCount": 1,
            "classMethodCount": 1,
            "methodCount": 2,
            "categoryCount": 1,
            "categoryMethodCount": 2,
            "protocolCount": 2,
            "classes": [
                {
                    "name": "_TtC10Calculator11AppDelegate",
                    "superclass": "NSObject",
                    "adoptedProtocols": [],
                    "instanceMethods": [
                        {
                            "name": "-[_TtC10Calculator11AppDelegate applicationWillFinishLaunching:]",
                            "selector": "applicationWillFinishLaunching:",
                            "isClassMethod": False,
                        }
                    ],
                    "classMethods": [
                        {
                            "name": "+[_TtC10Calculator11AppDelegate sharedAppDelegate]",
                            "selector": "sharedAppDelegate",
                            "isClassMethod": True,
                        }
                    ],
                    "ivars": [],
                }
            ],
            "categories": [
                {
                    "name": "CGAffineTransform",
                    "className": "NSValue",
                    "instanceMethods": [
                        {
                            "name": "-[NSValue(CGAffineTransform) cgAffineTransformValue]",
                            "selector": "cgAffineTransformValue",
                            "isClassMethod": False,
                        }
                    ],
                    "classMethods": [
                        {
                            "name": "+[NSValue(CGAffineTransform) valueWithCGAffineTransform:]",
                            "selector": "valueWithCGAffineTransform:",
                            "isClassMethod": True,
                        }
                    ],
                }
            ],
            "protocols": [
                {"name": "_TtP10Calculator15DisplayProtocol_"},
                {"name": "NSApplicationDelegate"},
            ],
        }
        return otool_l, otool_ov, mg_objc

    def test_objc_subcheck_resolves_relative_selrefs_and_matches_all_four_sets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "sample_objc")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            out_json = os.path.join(tmp, "out.json")
            otool_l, otool_ov, mg_objc = self._sample_otool_and_mg()

            def fake_run(cmd, *args, **kwargs):
                if cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if cmd[:2] == ["xcrun", "otool"] and "-l" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=otool_l, stderr=b"")
                if cmd[:2] == ["xcrun", "otool"] and "-ov" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, stdout=otool_ov, stderr=b"")
                if cmd[0] == fake_mg and cmd[1] == "objc":
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(mg_objc).encode("utf-8"), stderr=b"")
                return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

            buf = io.StringIO()
            with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(buf):
                rc = m3_diff.main([bin_path, "--only", "objc", "--machgraph", fake_mg, "--json-out", out_json])

            self.assertEqual(rc, 0, buf.getvalue())
            report = _read_json(out_json)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["checks"]["objc"]["total_diffs"], 0)
            # 1 class + 2 class/inst methods + 2 category methods + 2 protocols = 7 items
            self.assertEqual(report["checks"]["objc"]["total_ref_items"], 7)
            self.assertEqual(report["checks"]["objc"]["total_mg_items"], 7)

    def test_objc_subcheck_detects_stripped_underscore_method_kind_swap_category_and_protocol_diffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "sample_objc")
            _write_thin_arm64_header(bin_path, filetype=2)
            fake_mg = _make_executable_script(tmp, "fake-mg", "#!/usr/bin/env python3\n")
            otool_l, otool_ov, base_mg = self._sample_otool_and_mg()

            # 1. Stripped leading underscore on class name -> FAIL
            mut_cls = json.loads(json.dumps(base_mg))
            mut_cls["classes"][0]["name"] = "TtC10Calculator11AppDelegate"

            # 2. Class method put into instanceMethods (`-` instead of `+`) -> FAIL
            mut_kind = json.loads(json.dumps(base_mg))
            mut_kind["classes"][0]["instanceMethods"].extend(mut_kind["classes"][0]["classMethods"])
            mut_kind["classes"][0]["classMethods"] = []

            # 3. Missing category method -> FAIL
            mut_cat = json.loads(json.dumps(base_mg))
            mut_cat["categories"][0]["instanceMethods"] = []

            # 4. Missing protocol -> FAIL
            mut_proto = json.loads(json.dumps(base_mg))
            mut_proto["protocols"] = [{"name": "NSApplicationDelegate"}]

            for label, mutated_payload in [
                ("stripped_underscore", mut_cls),
                ("method_kind_swap", mut_kind),
                ("missing_category_method", mut_cat),
                ("missing_protocol", mut_proto),
            ]:
                def fake_run(cmd, *args, _payload=mutated_payload, **kwargs):
                    if cmd[0] == "lipo":
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                    if cmd[:2] == ["xcrun", "otool"] and "-l" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=otool_l, stderr=b"")
                    if cmd[:2] == ["xcrun", "otool"] and "-ov" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=otool_ov, stderr=b"")
                    if cmd[0] == fake_mg and cmd[1] == "objc":
                        return subprocess.CompletedProcess(
                            cmd, 0, stdout=json.dumps(_payload).encode("utf-8"), stderr=b""
                        )
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"ok\n", stderr=b"")

                with mock.patch.object(m3_diff.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(
                    io.StringIO()
                ):
                    rc = m3_diff.main([bin_path, "--only", "objc", "--machgraph", fake_mg])
                self.assertEqual(rc, 1, f"Mutation '{label}' should have caused check_objc_for_binary to fail")

    def test_objc_default_targets_include_calculator_assetutil_screencapture_and_log(self) -> None:
        tier, paths = m3_diff.resolve_targets(["objc"])
        self.assertEqual(tier, "objc")
        self.assertIn("/System/Applications/Calculator.app/Contents/MacOS/Calculator", paths)
        self.assertIn("/usr/bin/assetutil", paths)
        self.assertIn("/usr/sbin/screencapture", paths)
        self.assertIn("/usr/bin/log", paths)


if __name__ == "__main__":
    unittest.main()
