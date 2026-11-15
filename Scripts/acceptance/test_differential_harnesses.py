#!/usr/bin/env python3
"""Unit and regression tests for MachGraph M1 differential acceptance harnesses (G32, G33, G36, G39, G41)."""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import mnemonic_normalization  # noqa: E402


def _load_script_module(module_name: str, filename: str):
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


differential = _load_script_module("differential_mod", "differential.py")
mnemonic_agreement = _load_script_module("mnemonic_agreement_mod", "mnemonic-agreement.py")
macho_differential = _load_script_module("macho_differential_mod", "macho-differential.py")


class TestItem1MachOReferenceCommand(unittest.TestCase):
    """G32 (part 1) + G42: shared reference command includes --macho and --mcpu=apple-m1 across all slices."""

    def test_shared_reference_command_has_macho_and_handles_thin_macho(self):
        expected_template = (
            "xcrun llvm-objdump --macho -d --no-show-raw-insn --arch=<slice> "
            "--mcpu=apple-m1 --mattr=+bti --section=__TEXT,__text <file>"
        )
        self.assertTrue(
            hasattr(mnemonic_normalization, "REFERENCE_COMMAND_TEMPLATE"),
            "mnemonic_normalization must define REFERENCE_COMMAND_TEMPLATE",
        )
        self.assertTrue(
            hasattr(mnemonic_normalization, "build_reference_command"),
            "mnemonic_normalization must define build_reference_command",
        )
        self.assertEqual(mnemonic_normalization.REFERENCE_COMMAND_TEMPLATE, expected_template)
        self.assertEqual(differential.REFERENCE_COMMAND_TEMPLATE, expected_template)
        self.assertIs(differential.build_reference_command, mnemonic_normalization.build_reference_command)
        self.assertIs(mnemonic_agreement.build_reference_command, mnemonic_normalization.build_reference_command)

        cmd = mnemonic_normalization.build_reference_command("/usr/libexec/rosetta/oahd-helper", "arm64")
        self.assertIn("--macho", cmd)
        self.assertIn("--mcpu=apple-m1", cmd)
        self.assertEqual(len(mnemonic_normalization.NORMALIZATION_RULES), 3)

        # Single-architecture arm64 Mach-O must yield >0 reference instructions
        thin_bin = "/usr/libexec/rosetta/oahd-helper"
        if os.path.isfile(thin_bin):
            ref = mnemonic_agreement.reference_listing(thin_bin, "arm64")
            self.assertGreater(len(ref), 10000, "thin arm64 binary must yield >10k reference instructions with --macho")

        # Pure arm64 Rosetta runtime must decode LSE/CRC32 instructions under --mcpu=apple-m1 (G42)
        runtime_bin = "/usr/libexec/rosetta/runtime"
        if os.path.isfile(runtime_bin):
            ref_rt = mnemonic_agreement.reference_listing(runtime_bin, "arm64")
            self.assertEqual(ref_rt.get(0x5394), "ldset", "G42: 0x5394 in rosetta/runtime must decode as ldset with --mcpu=apple-m1")
            self.assertEqual(ref_rt.get(0x669C), "crc32cx", "G42: 0x669c in rosetta/runtime must decode as crc32cx with --mcpu=apple-m1")


def _make_fake_machgraph_script(directory: str, disasm_stdout: str) -> str:
    script_path = os.path.join(directory, "fake-machgraph.py")
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write(
            "#!/usr/bin/env python3\n"
            f"import sys\nsys.stdout.write({disasm_stdout!r})\n"
        )
    os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR)
    return script_path


class TestItem2ZeroReferenceFails(unittest.TestCase):
    """G32 (part 2): reference count == 0 while MachGraph decodes >0 instructions must fail, never PASS."""

    def test_differential_zero_reference_with_machgraph_insns_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "sample.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            mg_out = (
                "; Section __TEXT,__text @ 0x100000460\n"
                "0x0000000100000460\td503201f\tnop\t\n"
                "0x0000000100000464\td65f03c0\tret\t\n"
            )
            fake_mg = _make_fake_machgraph_script(tmp, mg_out)
            report_json = os.path.join(tmp, "report.json")

            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 17.0.0\n", stderr=b"")
                    # Simulate llvm-objdump producing 0 instructions with exit 0
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=b"\nsample.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n",
                        stderr=b"",
                    )
                return real_run(cmd, *args, **kwargs)

            import io
            from contextlib import redirect_stdout, redirect_stderr

            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys, "argv", ["differential.py", fake_bin, "--machgraph", fake_mg, "--json-out", report_json]
            ), redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = differential.main()

            stdout_txt = buf_out.getvalue()
            self.assertEqual(rc, 1, f"Expected exit 1 on empty reference with >0 MG insns, got {rc}:\n{stdout_txt}")
            self.assertNotIn("[PASS]", stdout_txt)
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["verdict"], "FAIL")
            self.assertEqual(payload["summary"]["crashes_or_failures"], 1)
            self.assertEqual(payload["summary"]["zero_instruction_reference_files"], 1)

    def test_differential_both_empty_text_section_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "empty_text.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            fake_mg = _make_fake_machgraph_script(tmp, "; Section __TEXT,__text @ 0x1000\n")

            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")
                return real_run(cmd, *args, **kwargs)

            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run):
                row = differential.compare_one_binary(fake_bin, fake_mg, tmp)
            self.assertNotIn("failure", row)
            self.assertEqual(row["total"], 0)

    def test_mnemonic_agreement_both_empty_vs_ref_empty_only(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        # ref == 0 while mine > 0 -> exit 1
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value={}), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value={0x1000: "nop"}
        ), mock.patch.object(sys, "argv", ["mnemonic-agreement.py", "/bin/ls"]), redirect_stdout(
            io.StringIO()
        ), redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(mnemonic_agreement.main(), 1)

        # ref == 0 and mine == 0 (truly empty __TEXT,__text) -> exit 0 without ZeroDivisionError
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value={}), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value={}
        ), mock.patch.object(sys, "argv", ["mnemonic-agreement.py", "/bin/ls"]), redirect_stdout(
            io.StringIO()
        ), redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(mnemonic_agreement.main(), 0)


class TestItem3BidirectionalAddresses(unittest.TestCase):
    """G33: bidirectional address check in __TEXT,__text."""

    def test_machgraph_only_inst_counted_separately_and_passes(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin1 = os.path.join(tmp, "b1.bin")
            fake_bin2 = os.path.join(tmp, "b2.bin")
            for p in (fake_bin1, fake_bin2):
                with open(p, "wb") as fh:
                    fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

            # Reference has 0x1000 (nop) and 0x1008 (ret); omits 0x1004 (warning skipped word).
            # MachGraph emits .inst at 0x1004 on b1.bin (2 extra .inst words) and 0 extra on b2.bin.
            ref_stdout = (
                b"\nb:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
                b"1008:\tret\n"
            )
            mg_script = os.path.join(tmp, "fake-mg.py")
            with open(mg_script, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/usr/bin/env python3\n"
                    "import sys\n"
                    "target = sys.argv[2]\n"
                    "print('; Section __TEXT,__text @ 0x1000')\n"
                    "print('0x0000000000001000\\td503201f\\tnop\\t')\n"
                    "if target.endswith('b1.bin'):\n"
                    "    print('0x0000000000001004\\tdeadbeef\\t.inst\\t0xdeadbeef')\n"
                    "    print('0x000000000000100c\\tcafebabe\\t.inst\\t0xcafebabe')\n"
                    "print('0x0000000000001008\\td65f03c0\\tret\\t')\n"
                )
            os.chmod(mg_script, os.stat(mg_script).st_mode | stat.S_IXUSR)
            report_json = os.path.join(tmp, "report.json")

            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 17.0.0\n", stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_stdout, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            buf_out = io.StringIO()
            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys,
                "argv",
                ["differential.py", fake_bin1, fake_bin2, "--workers", "1", "--machgraph", mg_script, "--json-out", report_json],
            ), redirect_stdout(buf_out), redirect_stderr(io.StringIO()):
                rc = differential.main()

            stdout_txt = buf_out.getvalue()
            self.assertEqual(rc, 0, f"MachGraph-only .inst must not fail: {stdout_txt}")
            self.assertIn("machgraph_only_inst=2 (files=1)", stdout_txt)
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["summary"]["unknown_instructions"], 0)
            self.assertEqual(payload["summary"]["wrong_instructions"], 0)
            self.assertEqual(payload["summary"]["machgraph_only_inst_instructions"], 2)
            self.assertEqual(payload["summary"]["machgraph_only_inst_files"], 1)
            by_path = {f["path"]: f for f in payload["files"]}
            self.assertEqual(by_path[fake_bin1]["machgraph_only_inst"], 2)
            self.assertEqual(by_path[fake_bin2]["machgraph_only_inst"], 0)

    def test_machgraph_only_non_inst_counted_as_wrong_and_fails(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "bad.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

            ref_stdout = (
                b"\nb:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
            )
            # MachGraph decodes 0x1004 (which llvm-objdump omitted!) as a concrete mnemonic 'smov' instead of '.inst'
            mg_out = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\t4e082c00\tsmov\tx0, v0.d[0]\n"
            )
            fake_mg = _make_fake_machgraph_script(tmp, mg_out)
            report_json = os.path.join(tmp, "report.json")

            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 17.0.0\n", stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_stdout, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys,
                "argv",
                ["differential.py", fake_bin, "--machgraph", fake_mg, "--json-out", report_json],
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = differential.main()

            self.assertEqual(rc, 1, "MachGraph-only non-.inst must be classified as wrong and exit 1")
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["verdict"], "FAIL")
            self.assertEqual(payload["summary"]["wrong_instructions"], 1)
            self.assertEqual(payload["summary"]["machgraph_only_inst_instructions"], 0)
            self.assertEqual(len(payload["wrong_by_mnemonic_pair"]), 1)
            wp = payload["wrong_by_mnemonic_pair"][0]
            self.assertEqual(wp["llvm_mnemonic"], "<omitted>")
            self.assertEqual(wp["machgraph_mnemonic"], "smov")
            self.assertEqual(wp["count"], 1)
            self.assertEqual(wp["example"]["address"], "0x1004")
            self.assertEqual(wp["example"]["word"], "4e082c00")

        # Also check mnemonic-agreement.py catches MachGraph-only non-.inst when --max-wrong 0 is set
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value={0x1000: "nop"}), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value={0x1000: "nop", 0x1004: "smov"}
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--max-wrong", "0"]
        ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(mnemonic_agreement.main(), 1)


class TestItem4WorktreeCleanAndRecordGuard(unittest.TestCase):
    """G36: JSON environment records machgraph_commit + worktree_clean; --record refuses on dirty worktree."""

    def test_environment_records_commit_and_worktree_clean_bool(self):
        self.assertTrue(
            hasattr(differential, "is_worktree_clean"),
            "differential.py must define is_worktree_clean()",
        )
        with mock.patch.object(differential, "is_worktree_clean", return_value=True):
            meta_clean = differential.collect_environment_metadata("/bin/ls")
        self.assertIn("machgraph_commit", meta_clean)
        self.assertNotEqual(meta_clean["machgraph_commit"], "unknown")
        self.assertIs(meta_clean.get("worktree_clean"), True)

        with mock.patch.object(differential, "is_worktree_clean", return_value=False):
            meta_dirty = differential.collect_environment_metadata("/bin/ls")
        self.assertIs(meta_dirty.get("worktree_clean"), False)

    def test_record_refuses_immediately_when_worktree_dirty(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_mg = _make_fake_machgraph_script(tmp, "")
            fake_reports = os.path.join(tmp, "reports")
            err_buf = io.StringIO()
            with mock.patch.object(differential, "is_worktree_clean", return_value=False), mock.patch.object(
                differential, "REPO_ROOT", tmp
            ), mock.patch.object(
                differential, "compare_one_binary", side_effect=AssertionError("must not run comparisons when --record is refused")
            ), mock.patch.object(
                sys, "argv", ["differential.py", "quick", "--record", "--machgraph", fake_mg]
            ), redirect_stdout(
                io.StringIO()
            ), redirect_stderr(
                err_buf
            ):
                rc = differential.main()

            self.assertNotEqual(rc, 0, "--record must exit non-zero on dirty worktree")
            self.assertFalse(os.path.exists(fake_reports), "--record must not create/write reports/ on dirty worktree")
            self.assertIn("worktree", err_buf.getvalue().lower())


class TestItem5HangProtectionAndSoloRetry(unittest.TestCase):
    """G39: file-size-scaled per-file timeout + solo retry after parallel timeout."""

    def test_timeout_scales_with_file_size(self):
        self.assertTrue(
            hasattr(differential, "per_file_timeout_seconds"),
            "differential.py must define per_file_timeout_seconds(path)",
        )
        self.assertTrue(
            hasattr(macho_differential, "per_file_timeout_seconds"),
            "macho-differential.py must define per_file_timeout_seconds(path)",
        )
        with tempfile.TemporaryDirectory() as tmp:
            small = os.path.join(tmp, "small.bin")
            with open(small, "wb") as fh:
                fh.write(b"\x00" * 4096)
            t_small = differential.per_file_timeout_seconds(small)
            self.assertGreaterEqual(t_small, 60.0)

        # Mock 56 MiB file stat (like /usr/libexec/AssetCache/AssetCache)
        fake_stat = mock.Mock(st_size=56 * 1024 * 1024)
        with mock.patch.object(differential.os, "stat", return_value=fake_stat):
            t_large = differential.per_file_timeout_seconds("/fake/AssetCache")
        self.assertGreaterEqual(t_large, 240.0, f"56 MiB file should get >=240s timeout, got {t_large}")

    def test_parallel_timeout_retries_solo_before_failing(self):
        self.assertTrue(
            hasattr(differential, "run_with_solo_retry"),
            "differential.py must define run_with_solo_retry",
        )
        calls = []

        def flaky_under_load(path: str):
            calls.append(path)
            # First call on 'b' times out (simulating parallel load), second call (solo retry) succeeds
            if path == "b" and calls.count("b") == 1:
                return {"path": "b", "failure": "machgraph timed out", "timed_out": True, "exit_code": 124}
            if path == "hang":
                return {"path": "hang", "failure": "machgraph timed out", "timed_out": True, "exit_code": 124}
            return {"path": path, "total": 10, "agree": 10, "wrong_total": 0, "missing": 0, "exit_code": 0}

        # Case 1: transient parallel timeout recovers on solo retry
        rows = differential.run_with_solo_retry(["a", "b"], 2, flaky_under_load)
        self.assertEqual(len(rows), 2)
        self.assertNotIn("failure", rows[1])
        self.assertTrue(rows[1].get("retried_after_timeout"))
        self.assertEqual(calls.count("b"), 2)

        # Case 2: genuine hang times out on solo retry too and stays a failure
        rows_hang = differential.run_with_solo_retry(["a", "hang"], 2, flaky_under_load)
        self.assertIn("failure", rows_hang[1])
        self.assertTrue(rows_hang[1].get("timed_out"))
        self.assertEqual(calls.count("hang"), 2)


class TestItem6MachODifferentialLibrariesFlagsAndFixups(unittest.TestCase):
    """G41: macho-differential compares imported libraries, codesign flags, and full fixup mismatch counts."""

    def _sample_otool_stdout(self) -> bytes:
        return (
            b"/bin/fake:\n"
            b"Load command 0\n"
            b"      cmd LC_SEGMENT_64\n"
            b"  cmdsize 152\n"
            b"  segname __TEXT\n"
            b"   vmaddr 0x0000000100000000\n"
            b"   vmsize 0x0000000000004000\n"
            b"  fileoff 0\n"
            b" filesize 16384\n"
            b"Section\n"
            b"  sectname __text\n"
            b"   segname __TEXT\n"
            b"      addr 0x0000000100000460\n"
            b"      size 0x0000000000000100\n"
            b"    offset 1120\n"
            b"Load command 1\n"
            b"     cmd LC_ID_DYLIB\n"
            b" cmdsize 48\n"
            b"    name /usr/lib/libSelf.dylib (offset 24)\n"
            b"   current version 1.0.0\n"
            b"Load command 2\n"
            b"          cmd LC_LOAD_DYLIB\n"
            b"      cmdsize 56\n"
            b"         name /usr/lib/libutil.dylib (offset 24)\n"
            b"   time stamp 2 Thu Jan  1 00:00:02 1970\n"
            b"      current version 1.0.0\n"
            b"compatibility version 1.0.0\n"
            b"Load command 3\n"
            b"          cmd LC_LOAD_WEAK_DYLIB\n"
            b"      cmdsize 56\n"
            b"         name /usr/lib/libSystem.B.dylib (offset 24)\n"
            b"   time stamp 2 Thu Jan  1 00:00:02 1970\n"
            b"      current version 1351.0.0\n"
            b"compatibility version 1.0.0\n"
            b"Load command 4\n"
            b"     cmd LC_UUID\n"
            b" cmdsize 24\n"
            b"    uuid 11223344-5566-7788-99AA-BBCCDDEEFF00\n"
            b"Load command 5\n"
            b"       cmd LC_MAIN\n"
            b"   cmdsize 24\n"
            b"  entryoff 1120\n"
            b"Load command 6\n"
            b"      cmd LC_DYLD_CHAINED_FIXUPS\n"
            b"  cmdsize 16\n"
        )

    def _sample_codesign_stderr(self) -> bytes:
        return (
            b"Executable=/bin/fake\n"
            b"Identifier=com.apple.fake\n"
            b"Format=Mach-O universal (arm64e)\n"
            b"CodeDirectory v=20400 size=1067 flags=0x10002(adhoc,runtime) hashes=27+7 location=embedded\n"
            b"Hash type=sha256 size=32\n"
            b"CandidateCDHashFull sha256=54097a1600000000000000000000000000000000000000000000000000000001\n"
            b"CDHash=54097a1600000000000000000000000000000000\n"
            b"Signature=adhoc\n"
            b"TeamIdentifier=not set\n"
        )

    def _base_mg_payloads(self):
        mg_info = {
            "fileName": "fake",
            "architecture": "arm64e (PAC)",
            "segments": [{"name": "__TEXT", "vmaddr": 0x100000000, "vmsize": 0x4000, "fileoff": 0, "filesize": 16384}],
            "sections": [{"segment": "__TEXT", "section": "__text", "addr": 0x100000460, "size": 0x100, "offset": 1120}],
            "uuid": "11223344-5566-7788-99AA-BBCCDDEEFF00",
            "entryPoint": 0x100000460,
            "libraries": [
                {"ordinal": 1, "installName": "/usr/lib/libutil.dylib", "currentVersion": "1.0", "isWeak": False, "isReexport": False},
                {"ordinal": 2, "installName": "/usr/lib/libSystem.B.dylib", "currentVersion": "1351.0", "isWeak": True, "isReexport": False},
            ],
        }
        mg_fx = {
            "count": 4,
            "fixups": [
                {"location": 0x100004000, "kind": "DYLD_REBASE", "targetAddress": 0x100000460, "targetAddressHex": "0x100000460", "symbolName": None},
                {"location": 0x100004008, "kind": "DYLD_AUTH_REBASE", "targetAddress": 0x100000480, "targetAddressHex": "0x100000480", "symbolName": None},
                {"location": 0x100004010, "kind": "DYLD_BIND", "targetAddress": None, "targetAddressHex": None, "symbolName": "_printf"},
                {"location": 0x100004018, "kind": "DYLD_AUTH_BIND", "targetAddress": None, "targetAddressHex": None, "symbolName": "_exit"},
            ],
        }
        mg_cs = {
            "isSigned": True,
            "isAdHoc": True,
            "flags": 0x10002,
            "flagsHex": "0x10002",
            "identifier": "com.apple.fake",
            "teamIdentifier": None,
            "cdHash": "54097a1600000000000000000000000000000000000000000000000000000001",
        }
        ref_fixups = {
            0x100004000: ("DYLD_REBASE", 0x100000460, None),
            0x100004008: ("DYLD_AUTH_REBASE", 0x100000480, None),
            0x100004010: ("DYLD_BIND", None, "_printf"),
            0x100004018: ("DYLD_AUTH_BIND", None, "_exit"),
        }
        return mg_info, mg_fx, mg_cs, ref_fixups

    def test_otool_libraries_and_codesign_flags_parsed_and_compared(self):
        with mock.patch.object(
            macho_differential.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["otool"], 0, stdout=self._sample_otool_stdout(), stderr=b""),
        ):
            parsed_otool = macho_differential.parse_otool_load_commands("/bin/fake", "arm64e")
        self.assertIn("libraries", parsed_otool, "parse_otool_load_commands must extract imported libraries")
        self.assertEqual(len(parsed_otool["libraries"]), 2)

        with mock.patch.object(
            macho_differential.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["codesign"], 0, stdout=b"", stderr=self._sample_codesign_stderr()),
        ):
            parsed_cs = macho_differential.parse_codesign_ref("/bin/fake", "arm64e")
        self.assertEqual(parsed_cs.get("flags"), 0x10002, "parse_codesign_ref must extract CodeDirectory flags")

        # Baseline match -> 0 mismatches
        mg_info, mg_fx, mg_cs, ref_fixups = self._base_mg_payloads()

        def fake_mg_json(_bin, subcmd, _path, _env, _timeout):
            if subcmd == "info":
                return (mg_info, None, False)
            if subcmd == "fixups":
                return (mg_fx, None, False)
            return (mg_cs, None, False)

        with mock.patch.object(macho_differential, "select_slice", return_value="arm64e"), mock.patch.object(
            macho_differential, "parse_otool_load_commands", return_value=parsed_otool
        ), mock.patch.object(
            macho_differential, "parse_codesign_ref", return_value=parsed_cs
        ), mock.patch.object(
            macho_differential, "parse_dyld_info_fixups", return_value=ref_fixups
        ), mock.patch.object(
            macho_differential, "run_mg_json", side_effect=fake_mg_json
        ):
            row_ok = macho_differential.check_one_binary("/bin/fake", "/fake/mg", "/tmp")
            self.assertEqual(row_ok["mismatches"], [])

            # Mutate imported library -> must report info.libraries mismatch
            mg_info["libraries"][0]["installName"] = "/usr/lib/libWrong.dylib"
            row_bad_lib = macho_differential.check_one_binary("/bin/fake", "/fake/mg", "/tmp")
            self.assertTrue(
                any("info.libraries" in m for m in row_bad_lib["mismatches"]),
                f"Expected info.libraries mismatch, got {row_bad_lib['mismatches']}",
            )
            mg_info["libraries"][0]["installName"] = "/usr/lib/libutil.dylib"

            # Mutate codesign flags -> must report codesign.flags mismatch
            mg_cs["flags"] = 0x2
            row_bad_cs = macho_differential.check_one_binary("/bin/fake", "/fake/mg", "/tmp")
            self.assertTrue(
                any("codesign.flags" in m for m in row_bad_cs["mismatches"]),
                f"Expected codesign.flags mismatch, got {row_bad_cs['mismatches']}",
            )

    def test_fixups_counts_all_mismatches_without_stopping_at_first(self):
        with mock.patch.object(
            macho_differential.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["otool"], 0, stdout=self._sample_otool_stdout(), stderr=b""),
        ):
            parsed_otool = macho_differential.parse_otool_load_commands("/bin/fake", "arm64e")
        with mock.patch.object(
            macho_differential.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["codesign"], 0, stdout=b"", stderr=self._sample_codesign_stderr()),
        ):
            parsed_cs = macho_differential.parse_codesign_ref("/bin/fake", "arm64e")

        mg_info, mg_fx, mg_cs, ref_fixups = self._base_mg_payloads()
        # Mutate 3 out of 4 fixup entries across kind, targetAddress, and symbolName
        mg_fx["fixups"][0]["kind"] = "DYLD_AUTH_REBASE"
        mg_fx["fixups"][1]["targetAddress"] = 0x100009999
        mg_fx["fixups"][1]["targetAddressHex"] = "0x100009999"
        mg_fx["fixups"][3]["symbolName"] = "_abort"

        def fake_mg_json(_bin, subcmd, _path, _env, _timeout):
            if subcmd == "info":
                return (mg_info, None, False)
            if subcmd == "fixups":
                return (mg_fx, None, False)
            return (mg_cs, None, False)

        with mock.patch.object(macho_differential, "select_slice", return_value="arm64e"), mock.patch.object(
            macho_differential, "parse_otool_load_commands", return_value=parsed_otool
        ), mock.patch.object(
            macho_differential, "parse_codesign_ref", return_value=parsed_cs
        ), mock.patch.object(
            macho_differential, "parse_dyld_info_fixups", return_value=ref_fixups
        ), mock.patch.object(
            macho_differential, "run_mg_json", side_effect=fake_mg_json
        ):
            row = macho_differential.check_one_binary("/bin/fake", "/fake/mg", "/tmp")
        joined = "; ".join(row["mismatches"])
        self.assertIn("3", joined, f"Expected total mismatch count 3 reported for fixups, got: {row['mismatches']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
