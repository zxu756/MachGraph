#!/usr/bin/env python3
"""Unit and regression tests for MachGraph M1 differential acceptance harnesses (G32, G33, G36, G39, G41, G44, G45)."""

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
            "xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands "
            "--arch=<slice> --mcpu=apple-m1 --mattr=+bti "
            "-mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>"
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
        self.assertEqual(len(mnemonic_normalization.NORMALIZATION_RULES), 0)

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

        # ref == 0 and mine == 0 -> must ALSO exit 1 under restored >=100 floor (G45), never 100% PASS
        out_both_empty = io.StringIO()
        err_both_empty = io.StringIO()
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value={}), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value={}
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--min-agreement", "99.9", "--max-wrong", "0"]
        ), redirect_stdout(
            out_both_empty
        ), redirect_stderr(
            err_both_empty
        ):
            self.assertEqual(mnemonic_agreement.main(), 1)
        self.assertNotIn("[PASS]", out_both_empty.getvalue())
        self.assertNotIn("100.00%", out_both_empty.getvalue())


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


class TestItem7RecordFilenameIncludesCorpusTier(unittest.TestCase):
    """G44: --record report filename includes corpus tier (quick, standard, full) so tiers never overwrite each other."""

    def test_record_full_then_quick_leaves_full_report_untouched(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin1 = os.path.join(tmp, "bin1")
            fake_bin2 = os.path.join(tmp, "bin2")
            for p in (fake_bin1, fake_bin2):
                with open(p, "wb") as fh:
                    fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            fake_mg = _make_fake_machgraph_script(tmp, "")

            def fake_compare(path: str, _mg: str, _home: str):
                return {
                    "path": path,
                    "arch": "arm64e",
                    "total": 10,
                    "agree": 10,
                    "unknown_total": 0,
                    "wrong_total": 0,
                    "missing": 0,
                    "machgraph_only_inst": 0,
                    "machgraph_only_wrong": 0,
                    "missing_examples": [],
                    "unknown": {},
                    "wrong_pairs": {},
                    "wrong_pair_examples": {},
                    "wrong_shapes": {},
                    "wrong_shape_examples": {},
                    "non_utf8_reference": False,
                    "non_utf8_machgraph": False,
                    "exit_code": 0,
                    "seconds": 0.01,
                }

            fake_env_meta = {
                "macos_product_name": "macOS",
                "macos_version": "27.0.1",
                "macos_build": "26A434",
                "machine": "arm64",
                "llvm_objdump_version": "Apple LLVM version 21.0.0",
                "machgraph_commit": "0123456789abcdef0123456789abcdef01234567",
                "worktree_clean": True,
                "machgraph_binary": "MachGraph",
            }

            with mock.patch.object(differential, "REPO_ROOT", tmp), mock.patch.object(
                differential, "is_worktree_clean", return_value=True
            ), mock.patch.object(
                differential, "collect_environment_metadata", return_value=fake_env_meta
            ), mock.patch.object(
                differential, "discover_full_candidates", return_value=[fake_bin1, fake_bin2]
            ), mock.patch.object(
                differential, "QUICK_FILES", [fake_bin1]
            ), mock.patch.object(
                differential, "STANDARD_FILES", [fake_bin1, fake_bin2]
            ), mock.patch.object(
                differential, "compare_one_binary", side_effect=fake_compare
            ):
                with mock.patch.object(
                    sys, "argv", ["differential.py", "full", "--workers", "1", "--record", "--machgraph", fake_mg]
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_full = differential.main()
                self.assertEqual(rc_full, 0)

                reports_dir = os.path.join(tmp, "reports")
                after_full_files = sorted(os.listdir(reports_dir))
                self.assertEqual(len(after_full_files), 1)
                full_filename = after_full_files[0]
                full_report_path = os.path.join(reports_dir, full_filename)
                with open(full_report_path, "rb") as fh:
                    full_bytes_before = fh.read()
                full_json = json.loads(full_bytes_before.decode("utf-8"))
                self.assertEqual(full_json["corpus"], "full")
                self.assertEqual(full_json["summary"]["compared_files"], 2)

                with mock.patch.object(
                    sys, "argv", ["differential.py", "quick", "--record", "--machgraph", fake_mg]
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_quick = differential.main()
                self.assertEqual(rc_quick, 0)

                self.assertTrue(os.path.isfile(full_report_path), "full report file disappeared")
                with open(full_report_path, "rb") as fh:
                    full_bytes_after_quick = fh.read()
                self.assertEqual(
                    full_bytes_after_quick,
                    full_bytes_before,
                    "Running quick --record must not modify the full report",
                )
                self.assertIn("full", full_filename, f"Expected 'full' in report filename, got {full_filename}")

                with mock.patch.object(
                    sys, "argv", ["differential.py", "standard", "--workers", "1", "--record", "--machgraph", fake_mg]
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    rc_std = differential.main()
                self.assertEqual(rc_std, 0)

                after_all_files = sorted(os.listdir(reports_dir))
                self.assertEqual(len(after_all_files), 3, f"Expected separate full/quick/standard reports, got {after_all_files}")
                with open(full_report_path, "rb") as fh:
                    full_bytes_after = fh.read()
                self.assertEqual(
                    full_bytes_after,
                    full_bytes_before,
                    "Running quick/standard --record must not modify the full report",
                )

            # Verify macho-differential.py --record also separates full and quick filenames
            def fake_check_macho(path: str, _mg: str, _home: str):
                return {
                    "path": path,
                    "arch": "arm64e",
                    "segments": 5,
                    "sections": 11,
                    "libraries": 3,
                    "fixups": 10,
                    "has_chained_fixups": True,
                    "is_signed": True,
                    "codesign_flags_hex": "0x0",
                    "mismatches": [],
                    "seconds": 0.01,
                }

            with mock.patch.object(macho_differential, "REPO_ROOT", tmp), mock.patch.object(
                macho_differential, "is_worktree_clean", return_value=True
            ), mock.patch.object(
                macho_differential,
                "collect_environment_metadata",
                return_value={"machgraph_commit": "0123456789abcdef", "worktree_clean": True, "machgraph_binary": "MachGraph"},
            ), mock.patch.object(
                macho_differential, "discover_full_candidates", return_value=[fake_bin1, fake_bin2]
            ), mock.patch.object(
                macho_differential, "QUICK_FILES", [fake_bin1]
            ), mock.patch.object(
                macho_differential, "check_one_binary", side_effect=fake_check_macho
            ):
                with mock.patch.object(
                    sys, "argv", ["macho-differential.py", "full", "--workers", "1", "--record", "--machgraph", fake_mg]
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(macho_differential.main(), 0)
                macho_full_files = sorted(f for f in os.listdir(reports_dir) if f.startswith("macho-differential-"))
                self.assertEqual(len(macho_full_files), 1)
                self.assertIn("full", macho_full_files[0])
                macho_full_path = os.path.join(reports_dir, macho_full_files[0])
                with open(macho_full_path, "rb") as fh:
                    macho_full_before = fh.read()

                with mock.patch.object(
                    sys, "argv", ["macho-differential.py", "quick", "--record", "--machgraph", fake_mg]
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(macho_differential.main(), 0)
                with open(macho_full_path, "rb") as fh:
                    self.assertEqual(fh.read(), macho_full_before)


class TestItem8MnemonicAgreementMinimumReferenceFloor(unittest.TestCase):
    """G45: mnemonic-agreement.py enforces reference instruction count >= 100 (fails on 0/0 and <100)."""

    def test_zero_and_under_100_reference_instructions_fail(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        # Case 1: both reference and MachGraph have 0 instructions -> must fail (exit 1), never 100% PASS
        for extra_args in ([], ["--min-agreement", "99.9", "--max-wrong", "0"]):
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with mock.patch.object(mnemonic_agreement, "reference_listing", return_value={}), mock.patch.object(
                mnemonic_agreement, "machgraph_listing", return_value={}
            ), mock.patch.object(
                sys, "argv", ["mnemonic-agreement.py", "/bin/ls", *extra_args]
            ), redirect_stdout(
                out_buf
            ), redirect_stderr(
                err_buf
            ):
                rc = mnemonic_agreement.main()
            self.assertEqual(rc, 1, f"0/0 instructions must exit 1 with args={extra_args}, got stdout={out_buf.getvalue()!r}")
            self.assertNotIn("[PASS]", out_buf.getvalue())
            self.assertNotIn("100.00%", out_buf.getvalue())
            self.assertIn("[FAIL]", err_buf.getvalue())

        # Case 2: 99 reference instructions (< 100 floor) -> must fail (exit 1)
        ref_99 = {0x1000 + 4 * i: "nop" for i in range(99)}
        out_99 = io.StringIO()
        err_99 = io.StringIO()
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value=ref_99), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value=dict(ref_99)
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--min-agreement", "99.9", "--max-wrong", "0"]
        ), redirect_stdout(
            out_99
        ), redirect_stderr(
            err_99
        ):
            self.assertEqual(mnemonic_agreement.main(), 1)
        self.assertNotIn("[PASS]", out_99.getvalue())

        # Case 3: 100 reference instructions (>= 100 floor) -> passes when thresholds met
        ref_100 = {0x1000 + 4 * i: "nop" for i in range(100)}
        out_100 = io.StringIO()
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value=ref_100), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value=dict(ref_100)
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--min-agreement", "99.9", "--max-wrong", "0"]
        ), redirect_stdout(
            out_100
        ), redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(mnemonic_agreement.main(), 0)
        self.assertIn("[PASS]", out_100.getvalue())


class TestItem9M2ReferenceCommandFlags(unittest.TestCase):
    """M2 Stage 1 (D-M2-1, G53, G54): reference command adds --no-symbolic-operands and generic Neon syntax."""

    def test_reference_command_flags_and_json_report_field(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        expected_template = (
            "xcrun llvm-objdump --macho -d --no-show-raw-insn --no-symbolic-operands "
            "--arch=<slice> --mcpu=apple-m1 --mattr=+bti "
            "-mllvm=-aarch64-neon-syntax=generic --section=__TEXT,__text <file>"
        )
        cmd = mnemonic_normalization.build_reference_command("/bin/ls", "arm64e")
        self.assertEqual(
            cmd,
            [
                "xcrun",
                "llvm-objdump",
                "--macho",
                "-d",
                "--no-show-raw-insn",
                "--no-symbolic-operands",
                "--arch=arm64e",
                "--mcpu=apple-m1",
                "--mattr=+bti",
                "-mllvm=-aarch64-neon-syntax=generic",
                "--section=__TEXT,__text",
                "/bin/ls",
            ],
        )

        # Verify JSON report records the updated reference_command field verbatim
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "sample.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            mg_out = "; Section __TEXT,__text @ 0x1000\n0x0000000000001000\td503201f\tnop\t\n"
            fake_mg = _make_fake_machgraph_script(tmp, mg_out)
            report_json = os.path.join(tmp, "report.json")
            ref_stdout = b"\nsample.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n1000:\tnop\n"
            real_run = subprocess.run

            def fake_run(c, *args, **kwargs):
                if c and c[0] == "lipo":
                    return subprocess.CompletedProcess(c, 0, stdout=b"arm64\n", stderr=b"")
                if len(c) >= 2 and c[0] == "xcrun" and c[1] == "llvm-objdump":
                    if "--version" in c:
                        return subprocess.CompletedProcess(c, 0, stdout=b"Apple LLVM version 21.0.0\n", stderr=b"")
                    return subprocess.CompletedProcess(c, 0, stdout=ref_stdout, stderr=b"")
                return real_run(c, *args, **kwargs)

            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys, "argv", ["differential.py", fake_bin, "--machgraph", fake_mg, "--json-out", report_json]
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(differential.main(), 0)

            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["reference_command"], expected_template)

        # Verify on real unstripped /bin/csh that bl targets are numeric addresses and Neon uses generic syntax
        if os.path.isfile("/bin/csh"):
            proc = subprocess.run(
                mnemonic_normalization.build_reference_command("/bin/csh", "arm64e"),
                capture_output=True,
                text=True,
                errors="replace",
                check=True,
            )
            bl_targets = []
            saw_generic_neon = False
            for line in proc.stdout.splitlines():
                if line.strip() == "Contents of (__TEXT,__text) section":
                    break
                parts = line.split("\t")
                if len(parts) >= 3 and parts[0].strip().endswith(":"):
                    mnem = parts[1].strip().lower()
                    ops = parts[2].split(";")[0].strip()
                    if mnem == "bl":
                        bl_targets.append(ops)
                    if mnem == "movi" and "v0.2d" in ops:
                        saw_generic_neon = True
            self.assertGreater(len(bl_targets), 100)
            self.assertTrue(
                all(t.startswith("0x") for t in bl_targets),
                f"Expected numeric bl targets under --no-symbolic-operands, got sample: {bl_targets[:5]}",
            )
            self.assertTrue(saw_generic_neon, "Expected generic Neon syntax 'movi v0.2d, ...' in /bin/csh")


class TestItem10DropRule3AndGenericNeonSelfCheck(unittest.TestCase):
    """M2 Stage 1: delete Rule 3 (vector arrangement suffix) and fail hard if reference output is not generic syntax."""

    def test_rule3_removed_and_arrangement_suffix_not_normalized(self):
        self.assertEqual(len(mnemonic_normalization.NORMALIZATION_RULES), 0)
        rule_ids = [r["id"] for r in mnemonic_normalization.NORMALIZATION_RULES]
        self.assertEqual(rule_ids, [])
        self.assertNotIn("vector suffix", mnemonic_normalization.NORMALIZATION_SUMMARY)

        # Without Rules 1, 2, or 3, non-identical mnemonics must NOT be normalized to agree
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("mov", "movz")[0], "wrong")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("mov", "movn")[0], "wrong")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("udf", ".inst")[0], "unknown")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("udf", "udf")[0], "agree")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("mov.16b", "mov")[0], "wrong")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("fmov.2d", "fmov")[0], "wrong")
        # Conditional branches remain exact matches
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("b.eq", "b.eq")[0], "agree")
        self.assertEqual(mnemonic_normalization.classify_mnemonic_pair("b.hs", "b.hs")[0], "agree")

    def test_startup_self_check_detects_non_generic_neon_syntax(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        self.assertTrue(
            hasattr(mnemonic_normalization, "verify_reference_generic_neon_syntax"),
            "mnemonic_normalization must define verify_reference_generic_neon_syntax",
        )
        # Real /bin/ls under build_reference_command must pass the generic-syntax self-check
        self.assertIsNone(mnemonic_normalization.verify_reference_generic_neon_syntax("/bin/ls", "arm64e"))

        # Simulated regression: llvm-objdump ignores -mllvm=-aarch64-neon-syntax=generic and emits movi.2d
        apple_syntax_out = (
            b"/bin/ls:\n"
            b"100001af4:\tmovi.2d\tv0, #0000000000000000\n"
            b"100001af8:\tret\n"
        )
        with mock.patch.object(
            mnemonic_normalization.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["xcrun"], 0, stdout=apple_syntax_out, stderr=b""),
        ):
            err = mnemonic_normalization.verify_reference_generic_neon_syntax("/bin/ls", "arm64e")
        self.assertIsNotNone(err)
        self.assertIn("movi.2d", err)

        # Simulated regression: >=100 instructions in sample binary with zero generic vN.<arr> operands
        scalar_only_120 = b"/bin/ls:\n" + b"".join(
            f"{0x1000 + 4 * i:x}:\tnop\n".encode("ascii") for i in range(120)
        )
        with mock.patch.object(
            mnemonic_normalization.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["xcrun"], 0, stdout=scalar_only_120, stderr=b""),
        ):
            err_no_vec = mnemonic_normalization.verify_reference_generic_neon_syntax("/bin/ls", "arm64e")
        self.assertIsNotNone(err_no_vec)

        # Even if the target binary itself is purely scalar (e.g., /usr/bin/true), differential.py exits 1
        # when the startup generic-syntax self-check fails.
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "scalar.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            fake_mg = _make_fake_machgraph_script(
                tmp, "; Section __TEXT,__text @ 0x1000\n0x0000000000001000\td503201f\tnop\t\n"
            )
            err_buf = io.StringIO()
            with mock.patch.object(
                differential, "verify_reference_generic_neon_syntax", return_value="Darwin syntax detected"
            ), mock.patch.object(
                sys, "argv", ["differential.py", fake_bin, "--machgraph", fake_mg]
            ), redirect_stdout(
                io.StringIO()
            ), redirect_stderr(
                err_buf
            ):
                rc = differential.main()
            self.assertEqual(rc, 1)
            self.assertIn("Darwin syntax detected", err_buf.getvalue())

    def test_per_file_reference_check_rejects_darwin_suffix_even_for_unknown_insn(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "neon_unknown.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            # MachGraph emits .inst at 0x1004; if Rule 3 or silent unknown classification were active,
            # 'sub.2d' vs '.inst' would be counted as unknown and exit 0 instead of failing!
            mg_out = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\t6ee18401\t.inst\t0x6ee18401\n"
            )
            fake_mg = _make_fake_machgraph_script(tmp, mg_out)
            report_json = os.path.join(tmp, "report.json")
            ref_stdout = (
                b"\nneon_unknown.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
                b"1004:\tsub.2d\tv1, v0, v1\n"
            )
            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 21.0.0\n", stderr=b"")
                    if "/bin/ls" in cmd:
                        return real_run(cmd, *args, **kwargs)
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_stdout, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys, "argv", ["differential.py", fake_bin, "--machgraph", fake_mg, "--json-out", report_json]
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = differential.main()

            self.assertEqual(rc, 1, "Reference output with 'sub.2d' must fail hard, not pass as unknown")
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["verdict"], "FAIL")
            self.assertEqual(payload["summary"]["crashes_or_failures"], 1)
            self.assertIn("sub.2d", payload["failures"][0]["error"])

        # Same check for mnemonic-agreement.py
        ref_101 = {0x1000 + 4 * i: "nop" for i in range(100)}
        ref_101[0x1190] = "sub.2d"
        mg_101 = {0x1000 + 4 * i: "nop" for i in range(100)}
        mg_101[0x1190] = ".inst"
        err_ma = io.StringIO()
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value=ref_101), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value=mg_101
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--max-wrong", "0"]
        ), redirect_stdout(
            io.StringIO()
        ), redirect_stderr(
            err_ma
        ):
            self.assertEqual(mnemonic_agreement.main(), 1)
        self.assertIn("sub.2d", err_ma.getvalue())


class TestItem11ReferenceLongMachGraphInstBucket(unittest.TestCase):
    """M2 Stage 1 (G55): reference `.long` + MachGraph `.inst` goes to `reference_long_machgraph_inst`, not `unknown`."""

    def test_classify_mnemonic_pair_buckets_ref_long_with_mg_inst_and_marks_non_inst_wrong(self):
        self.assertEqual(
            mnemonic_normalization.classify_mnemonic_pair(".long", ".inst"),
            ("reference_long_machgraph_inst", ".long", ".inst"),
        )
        self.assertEqual(
            mnemonic_normalization.classify_mnemonic_pair(".long", "smov"),
            ("wrong", ".long", "smov"),
        )
        self.assertEqual(
            mnemonic_normalization.classify_mnemonic_pair(".long", ".long"),
            ("wrong", ".long", ".long"),
        )

    def test_differential_buckets_reference_long_separately_and_keeps_total_unchanged(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin1 = os.path.join(tmp, "has_long.bin")
            fake_bin2 = os.path.join(tmp, "no_long.bin")
            for p in (fake_bin1, fake_bin2):
                with open(p, "wb") as fh:
                    fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

            ref_b1 = (
                b"\nhas_long.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
                b"1004:\t.long\t0xffffff64\n"
                b"1008:\t.long\t0xffffff70\n"
                b"100c:\tadd\tv0.2d, v1.2d, v0.2d\n"
                b"1010:\tret\n"
            )
            ref_b2 = (
                b"\nno_long.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
                b"1004:\tret\n"
            )
            mg_script = os.path.join(tmp, "fake-mg.py")
            with open(mg_script, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/usr/bin/env python3\n"
                    "import sys\n"
                    "target = sys.argv[2]\n"
                    "print('; Section __TEXT,__text @ 0x1000')\n"
                    "if target.endswith('has_long.bin'):\n"
                    "    print('0x0000000000001000\\td503201f\\tnop\\t')\n"
                    "    print('0x0000000000001004\\tffffff64\\t.inst\\t0xffffff64')\n"
                    "    print('0x0000000000001008\\tffffff70\\t.inst\\t0xffffff70')\n"
                    "    print('0x000000000000100c\\t4ee08420\\t.inst\\t0x4ee08420')\n"
                    "    print('0x0000000000001010\\td65f03c0\\tret\\t')\n"
                    "else:\n"
                    "    print('0x0000000000001000\\td503201f\\tnop\\t')\n"
                    "    print('0x0000000000001004\\td65f03c0\\tret\\t')\n"
                )
            os.chmod(mg_script, os.stat(mg_script).st_mode | stat.S_IXUSR)
            report_json = os.path.join(tmp, "report.json")
            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 21.0.0\n", stderr=b"")
                    if "/bin/ls" in cmd:
                        return real_run(cmd, *args, **kwargs)
                    if cmd[-1].endswith("has_long.bin"):
                        return subprocess.CompletedProcess(cmd, 0, stdout=ref_b1, stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_b2, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            out_buf = io.StringIO()
            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys,
                "argv",
                ["differential.py", fake_bin1, fake_bin2, "--workers", "1", "--machgraph", mg_script, "--json-out", report_json],
            ), redirect_stdout(out_buf), redirect_stderr(io.StringIO()):
                rc = differential.main()

            self.assertEqual(rc, 0, out_buf.getvalue())
            self.assertIn("reference_long_machgraph_inst=2 (files=1)", out_buf.getvalue())
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            summary = payload["summary"]
            self.assertEqual(summary["total_instructions"], 7)
            self.assertEqual(summary["agreed_instructions"], 4)
            self.assertEqual(summary["unknown_instructions"], 1)
            self.assertEqual(summary["reference_long_machgraph_inst"], 2)
            self.assertEqual(summary["reference_long_machgraph_inst_files"], 1)
            self.assertEqual(summary["wrong_instructions"], 0)
            self.assertEqual(
                payload["unknown_by_reference_mnemonic"],
                [{"llvm_mnemonic": "add", "count": 1, "file_count": 1}],
            )
            by_path = {f["path"]: f for f in payload["files"]}
            self.assertEqual(by_path[fake_bin1]["instructions"], 5)
            self.assertEqual(by_path[fake_bin1]["agree"], 2)
            self.assertEqual(by_path[fake_bin1]["unknown"], 1)
            self.assertEqual(by_path[fake_bin1]["reference_long_machgraph_inst"], 2)
            self.assertEqual(by_path[fake_bin2]["reference_long_machgraph_inst"], 0)

    def test_differential_and_mnemonic_agreement_fail_when_ref_long_decoded_as_instruction(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = os.path.join(tmp, "bad_long.bin")
            with open(fake_bin, "wb") as fh:
                fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
            ref_stdout = (
                b"\nbad_long.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tnop\n"
                b"1004:\t.long\t0x54000050\n"
            )
            mg_out = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\t54000050\tbc.eq\t0x100c\n"
            )
            fake_mg = _make_fake_machgraph_script(tmp, mg_out)
            report_json = os.path.join(tmp, "report.json")
            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 21.0.0\n", stderr=b"")
                    if "/bin/ls" in cmd:
                        return real_run(cmd, *args, **kwargs)
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_stdout, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys, "argv", ["differential.py", fake_bin, "--machgraph", fake_mg, "--json-out", report_json]
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = differential.main()

            self.assertEqual(rc, 1)
            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["verdict"], "FAIL")
            self.assertEqual(payload["summary"]["wrong_instructions"], 1)
            self.assertEqual(payload["wrong_by_mnemonic_pair"][0]["llvm_mnemonic"], ".long")
            self.assertEqual(payload["wrong_by_mnemonic_pair"][0]["machgraph_mnemonic"], "bc.eq")

        # mnemonic-agreement.py: .long + .inst separated from unknown/agree, .long + non-.inst is wrong
        ref_102 = {0x1000 + 4 * i: "nop" for i in range(100)}
        ref_102[0x1190] = ".long"
        ref_102[0x1194] = ".long"
        mg_ok = {0x1000 + 4 * i: "nop" for i in range(100)}
        mg_ok[0x1190] = ".inst"
        mg_ok[0x1194] = ".inst"
        out_ok = io.StringIO()
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value=ref_102), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value=mg_ok
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--max-wrong", "0"]
        ), redirect_stdout(
            out_ok
        ), redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(mnemonic_agreement.main(), 0)
        self.assertIn("total=102 agree=100 (98.04%) unknown=0 ref_long_mg_inst=2 wrong=0", out_ok.getvalue())

        mg_bad = dict(mg_ok)
        mg_bad[0x1194] = "bc.eq"
        with mock.patch.object(mnemonic_agreement, "reference_listing", return_value=ref_102), mock.patch.object(
            mnemonic_agreement, "machgraph_listing", return_value=mg_bad
        ), mock.patch.object(
            sys, "argv", ["mnemonic-agreement.py", "/bin/ls", "--max-wrong", "0"]
        ), redirect_stdout(
            io.StringIO()
        ), redirect_stderr(
            io.StringIO()
        ):
            self.assertEqual(mnemonic_agreement.main(), 1)


class TestItem12OperandNormalizationRules(unittest.TestCase):
    """M2 Stage 2: `operand_normalization.py` implements only O1-O4, each with positive and negative tests."""

    def _mod(self):
        return _load_script_module("operand_normalization_mod", "operand_normalization.py")

    def test_rule_table_has_only_o1_through_o4_and_cannot_grow(self):
        op_norm = self._mod()
        self.assertTrue(hasattr(op_norm, "OPERAND_NORMALIZATION_RULES"))
        self.assertLessEqual(len(op_norm.OPERAND_NORMALIZATION_RULES), 4)
        self.assertEqual(len(op_norm.OPERAND_NORMALIZATION_RULES), 4)
        self.assertLessEqual(len(mnemonic_normalization.NORMALIZATION_RULES), 0)
        self.assertEqual(len(mnemonic_normalization.NORMALIZATION_RULES), 0)
        ids = [r["id"] for r in op_norm.OPERAND_NORMALIZATION_RULES]
        self.assertEqual(ids, ["O1", "O2", "O3", "O4"])
        for rule in op_norm.OPERAND_NORMALIZATION_RULES:
            self.assertTrue(rule.get("reason", "").strip(), f"Rule {rule['id']} must document its rationale")

    def test_o1_whitespace_and_case_same(self):
        op_norm = self._mod()
        self.assertTrue(op_norm.operands_equal("st1", "{ v0.h }[1], [x8], #2", "{v0.h}[1],[X8],#2"))
        self.assertTrue(op_norm.operands_equal("st2", "{ v1.16b, v2.16b }, [x11]", "{v1.16b,v2.16b}, [x11]"))
        self.assertTrue(op_norm.operands_equal("mrs", "x0, TPIDRRO_EL0", "X0, tpidrro_el0"))

    def test_o1_whitespace_and_case_different(self):
        op_norm = self._mod()
        self.assertFalse(op_norm.operands_equal("st1", "{ v0.h }[1], [x8]", "v0.h[1], [x8]"))
        self.assertFalse(op_norm.operands_equal("add", "x0, x1, x2", "x0, x1, x3"))
        self.assertFalse(op_norm.operands_equal("add", "x0, x1, x2, lsl #2", "x0, x1, x2, lsr #2"))
        self.assertFalse(op_norm.operands_equal("add", "lsl x0", "lslx0"))

    def test_o2_numeric_value_same(self):
        op_norm = self._mod()
        self.assertTrue(op_norm.operands_equal("ldr", "x8, [x1, #0x10]", "x8, [x1, #16]"))
        self.assertTrue(op_norm.operands_equal("stp", "x29, x30, [sp, #-0x10]!", "x29, x30, [sp, #-16]!"))
        self.assertTrue(op_norm.operands_equal("hint", "#0x9", "#9"))
        self.assertTrue(op_norm.operands_equal("movi", "v0.2d, #0000000000000000", "v0.2d, #0"))
        self.assertTrue(op_norm.operands_equal("fmov", "d1, #1.00000000", "d1, #1"))
        self.assertTrue(op_norm.operands_equal("fcmp", "d8, #0.0", "d8, #0"))
        self.assertTrue(op_norm.operands_equal("fmov", "s0, #-0.12500000", "s0, #-0.125"))
        self.assertTrue(op_norm.operands_equal("hint", "#16", "#0x10"))

    def test_o2_numeric_value_different(self):
        op_norm = self._mod()
        self.assertFalse(op_norm.operands_equal("ldr", "x8, [x1, #0x10]", "x8, [x1, #10]"))
        self.assertFalse(op_norm.operands_equal("udf", "#0xc", "0xc"))
        self.assertFalse(op_norm.operands_equal("udf", "#0xc", "0x0000000c"))
        # G48(a): signed negative immediate vs unsigned 64-bit bit-pattern must NOT compare equal
        self.assertFalse(op_norm.operands_equal("mov", "x8, #-0x3333333333333334", "x8, #0xcccccccccccccccc"))
        # G47: %.6g precision loss (0.132812 != 0.13281250) must NOT compare equal
        self.assertFalse(op_norm.operands_equal("fmov", "d0, #0.13281250", "d0, #0.132812"))
        # Register indices and vector arrangements are identifiers, not standalone numeric literals
        self.assertFalse(op_norm.operands_equal("mov", "v0.16b, v1.16b", "v0.0x10b, v1.16b"))
        self.assertFalse(op_norm.operands_equal("mov", "x1, x2", "x01, x2"))

    def test_o2_hash_prefix_must_match(self):
        op_norm = self._mod()
        self.assertFalse(op_norm.operands_equal("udf", "#0xc", "0xc"))
        self.assertFalse(op_norm.operands_equal("mov", "x0, #16", "x0, 0x10"))
        self.assertTrue(op_norm.operands_equal("hint", "#16", "#0x10"))
        self.assertTrue(op_norm.operands_equal("b", "16", "0x10"))
        o2_rule = next(r for r in op_norm.OPERAND_NORMALIZATION_RULES if r["id"] == "O2")
        self.assertIn("#", o2_rule["reason"])
        self.assertIn("match", o2_rule["reason"].lower())

    def test_o3_adrp_comment_address_same(self):
        op_norm = self._mod()
        self.assertTrue(
            op_norm.operands_equal("adrp", "x8, 12 ; 0x10000c000", "x8, 0x10000c000", address=0x10000075C)
        )
        self.assertTrue(
            op_norm.operands_equal("adrp", "x16, -1 ; 0x100000000", "x16, 0x100000000", address=0x100001220)
        )

    def test_o3_adrp_comment_address_different(self):
        op_norm = self._mod()
        self.assertFalse(
            op_norm.operands_equal("adrp", "x8, 12 ; 0x10000d000", "x8, 0x10000c000", address=0x10000075C)
        )
        self.assertFalse(
            op_norm.operands_equal("adrp", "x9, 12 ; 0x10000c000", "x8, 0x10000c000", address=0x10000075C)
        )
        self.assertFalse(
            op_norm.operands_equal("adrp", "x8, 12", "x8, 0x10000c000", address=0x10000075C)
        )
        self.assertFalse(
            op_norm.operands_equal("adrp", "x8, _foo@PAGE ; 0x10000c000", "x8, 0x10000c000", address=0x10000075C)
        )
        self.assertFalse(
            op_norm.operands_equal("add", "x8, #12 ; 0x10000c000", "x8, 0x10000c000", address=0x10000075C)
        )

    def test_o4_pc_relative_offset_same(self):
        op_norm = self._mod()
        self.assertTrue(op_norm.operands_equal("adr", "x17, #0", "x17, 0x100000b28", address=0x100000B28))
        self.assertTrue(op_norm.operands_equal("adr", "x3, #-60", "x3, 0x00001720", address=0x175C))
        self.assertTrue(op_norm.operands_equal("ldr", "x10, #-0x2ce08", "x10, 0x1000031f8", address=0x100030000))
        self.assertTrue(op_norm.operands_equal("ldr", "q24, 0x11a0", "q24, 0x000011a0", address=0x11EC))
        self.assertTrue(op_norm.operands_equal("ldrsw", "x8, #0x40", "x8, 0x100001040", address=0x100001000))
        self.assertTrue(
            op_norm.operands_equal("prfm", "pldl1keep, #-0x20", "pldl1keep, 0x100000fe0", address=0x100001000)
        )

    def test_o4_pc_relative_offset_different(self):
        op_norm = self._mod()
        self.assertFalse(op_norm.operands_equal("adr", "x17, #4", "x17, 0x100000b28", address=0x100000B28))
        self.assertFalse(op_norm.operands_equal("ldr", "x10, #-0x2ce08", "x10, 0x1000031fc", address=0x100030000))
        # Post-indexed bracketed ldr must NEVER add PC to the writeback immediate
        self.assertFalse(op_norm.operands_equal("ldr", "x8, [x1], #8", "x8, [x1], 0x1008", address=0x1000))
        # Non-PC-relative instructions must NEVER add PC to #imm
        self.assertFalse(op_norm.operands_equal("add", "x0, #0x10", "x0, 0x1010", address=0x1000))

    def test_outside_rules_remain_different(self):
        op_norm = self._mod()
        self.assertFalse(op_norm.operands_equal("mov", "w0, #-0x1", "w0, #0"))
        self.assertFalse(op_norm.operands_equal("sub", "x19, sp, x23, lsl #4", "x19, sp, x23, uxtx #4"))
        self.assertFalse(op_norm.operands_equal("ldrb", "w18, [x0, w1, sxtw #0]", "w18, [x0, w1, sxtw]"))
        self.assertFalse(op_norm.operands_equal("sysl", "x21, #0x1, c15, c1, #0x3", "#1, c15, c1, #3, x21"))
        self.assertFalse(op_norm.operands_equal("csel", "x0, x1, x2, cs", "x0, x1, x2, hs"))
        self.assertFalse(op_norm.operands_equal("bl", "_malloc", "0x1000042ec"))


class TestItem13DifferentialOperandComparisonAndReporting(unittest.TestCase):
    """M2 Stage 2: `differential.py` compares operands on agreed mnemonics and reports counts, categories, and examples."""

    def test_differential_compares_agreed_operands_records_categories_and_examples_without_changing_verdict(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin1 = os.path.join(tmp, "op1.bin")
            fake_bin2 = os.path.join(tmp, "op2.bin")
            for p in (fake_bin1, fake_bin2):
                with open(p, "wb") as fh:
                    fh.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

            ref_b1 = (
                b"\nop1.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"1000:\tadrp\tx8, 12 ; 0x10000c000\n"
                b"1004:\tadr\tx17, #-4\n"
                b"1008:\tldr\tx10, #0x20\n"
                b"100c:\tst1\t{ v0.h }[1], [x8], #0x2\n"
                b"1010:\tfmov\td1, #1.00000000\n"
                b"1014:\tmov\tw0, #-0x1\n"
                b"1018:\tmov\tw2, #-0x2\n"
                b"101c:\tmov\tx8, #-0x3333333333333334\n"
                b"1020:\t.long\t0xffffff64\n"
                b"1024:\tadd\tv0.2d, v1.2d, v0.2d\n"
            )
            ref_b2 = (
                b"\nop2.bin:\tfile format mach-o arm64\n\nDisassembly of section __TEXT,__text:\n"
                b"2000:\tnop\n"
                b"2004:\tmov\tw5, #-0x1\n"
            )
            mg_script = os.path.join(tmp, "fake-mg.py")
            with open(mg_script, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/usr/bin/env python3\n"
                    "import sys\n"
                    "target = sys.argv[2]\n"
                    "print('; Section __TEXT,__text @ 0x1000')\n"
                    "if target.endswith('op1.bin'):\n"
                    "    print('0x0000000000001000\\t90000068\\tadrp\\tx8, 0x10000c000')\n"
                    "    print('0x0000000000001004\\t10fffff1\\tadr\\tx17, 0x00001000')\n"
                    "    print('0x0000000000001008\\t5800010a\\tldr\\tx10, 0x00001028')\n"
                    "    print('0x000000000000100c\\t0d9f4100\\tst1\\t{v0.h}[1], [X8], #2')\n"
                    "    print('0x0000000000001010\\t1e6e1001\\tfmov\\td1, #1')\n"
                    "    print('0x0000000000001014\\t12800000\\tmov\\tw0, #0')\n"
                    "    print('0x0000000000001018\\t12800022\\tmov\\tw2, #1')\n"
                    "    print('0x000000000000101c\\tb202e7e8\\tmov\\tx8, #0xcccccccccccccccc')\n"
                    "    print('0x0000000000001020\\tffffff64\\t.inst\\t0xffffff64')\n"
                    "    print('0x0000000000001024\\t4ee08420\\t.inst\\t0x4ee08420')\n"
                    "else:\n"
                    "    print('0x0000000000002000\\td503201f\\tnop\\t')\n"
                    "    print('0x0000000000002004\\t12800005\\tmov\\tw5, #0')\n"
                )
            os.chmod(mg_script, os.stat(mg_script).st_mode | stat.S_IXUSR)
            report_json = os.path.join(tmp, "report.json")
            real_run = subprocess.run

            def fake_run(cmd, *args, **kwargs):
                if cmd and cmd[0] == "lipo":
                    return subprocess.CompletedProcess(cmd, 0, stdout=b"arm64e\n", stderr=b"")
                if len(cmd) >= 2 and cmd[0] == "xcrun" and cmd[1] == "llvm-objdump":
                    if "--version" in cmd:
                        return subprocess.CompletedProcess(cmd, 0, stdout=b"Apple LLVM version 21.0.0\n", stderr=b"")
                    if "/bin/ls" in cmd:
                        return real_run(cmd, *args, **kwargs)
                    if cmd[-1].endswith("op1.bin"):
                        return subprocess.CompletedProcess(cmd, 0, stdout=ref_b1, stderr=b"")
                    return subprocess.CompletedProcess(cmd, 0, stdout=ref_b2, stderr=b"")
                return real_run(cmd, *args, **kwargs)

            out_buf = io.StringIO()
            with mock.patch.object(differential.subprocess, "run", side_effect=fake_run), mock.patch.object(
                sys,
                "argv",
                ["differential.py", fake_bin1, fake_bin2, "--workers", "1", "--machgraph", mg_script, "--json-out", report_json],
            ), redirect_stdout(out_buf), redirect_stderr(io.StringIO()):
                rc = differential.main()

            stdout_txt = out_buf.getvalue()
            self.assertEqual(rc, 0, f"Operand differences must not alter mnemonic pass verdict:\n{stdout_txt}")
            self.assertIn("operands=6/10 (60.0000%) mismatch=4 (files=2)", stdout_txt)

            with open(report_json, "r", encoding="utf-8") as fh:
                payload = json.load(fh)

            self.assertEqual(payload["verdict"], "PASS")
            self.assertEqual(len(payload["operand_normalization_rules"]), 4)

            summary = payload["summary"]
            self.assertEqual(summary["total_instructions"], 12)
            self.assertEqual(summary["agreed_instructions"], 10)
            self.assertEqual(summary["unknown_instructions"], 1)
            self.assertEqual(summary["reference_long_machgraph_inst"], 1)
            self.assertEqual(summary["wrong_instructions"], 0)
            self.assertEqual(summary["operand_compared"], 10)
            self.assertEqual(summary["operand_equal"], 6)
            self.assertEqual(summary["operand_mismatch"], 4)
            self.assertEqual(summary["operand_mismatch_files"], 2)
            self.assertEqual(summary["operand_agreement_pct"], 60.0)

            diffs = payload["operand_differences"]
            self.assertEqual(len(diffs), 2)

            d0 = diffs[0]
            self.assertEqual(d0["llvm_mnemonic"], "mov")
            self.assertEqual(d0["machgraph_mnemonic"], "mov")
            self.assertEqual(d0["llvm_shape"], "W, #-N")
            self.assertEqual(d0["machgraph_shape"], "W, #N")
            self.assertEqual(d0["count"], 3)
            self.assertEqual(d0["file_count"], 2)
            self.assertEqual(len(d0["examples"]), 3)
            self.assertEqual(d0["examples"][0]["address"], "0x1014")
            self.assertEqual(d0["examples"][0]["llvm"], "mov w0, #-0x1")
            self.assertEqual(d0["examples"][0]["machgraph"], "mov w0, #0")
            self.assertEqual(d0["examples"][1]["address"], "0x1018")
            self.assertEqual(d0["examples"][2]["address"], "0x2004")

            d1 = diffs[1]
            self.assertEqual(d1["llvm_mnemonic"], "mov")
            self.assertEqual(d1["machgraph_mnemonic"], "mov")
            self.assertEqual(d1["llvm_shape"], "X, #-N")
            self.assertEqual(d1["machgraph_shape"], "X, #N")
            self.assertEqual(d1["count"], 1)
            self.assertEqual(d1["file_count"], 1)
            self.assertEqual(d1["examples"][0]["address"], "0x101c")

            by_path = {f["path"]: f for f in payload["files"]}
            self.assertEqual(by_path[fake_bin1]["operand_compared"], 8)
            self.assertEqual(by_path[fake_bin1]["operand_equal"], 5)
            self.assertEqual(by_path[fake_bin1]["operand_mismatch"], 3)
            self.assertEqual(by_path[fake_bin2]["operand_compared"], 2)
            self.assertEqual(by_path[fake_bin2]["operand_equal"], 1)
            self.assertEqual(by_path[fake_bin2]["operand_mismatch"], 1)


class TestItem14EncodingTableHarness(unittest.TestCase):
    """M2 Stage 3: `encoding-table.py` table generation format, check exit codes (0/1/2), and mismatch reporting."""

    def _mod(self):
        return _load_script_module("encoding_table_mod", "encoding-table.py")

    def _invoke(self, mod, argv):
        import io
        from contextlib import redirect_stderr, redirect_stdout

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        try:
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                rc = mod.main(argv)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_encoding_table_generate_format_and_shared_reference_command(self):
        enc_table = self._mod()
        self.assertIs(enc_table.build_reference_command, mnemonic_normalization.build_reference_command)

        for required_group in ("move_wide_imm", "logical_imm", "load_store_reg_offset"):
            self.assertIn(required_group, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[required_group].generate_words()
            self.assertGreater(len(words), 0)
            self.assertLessEqual(len(words), 4096)

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table, ["generate", "move_wide_imm", "--out-dir", tmp]
            )
            self.assertEqual(rc, 0, f"generate failed: stdout={stdout_txt}\nstderr={stderr_txt}")

            tsv_path = os.path.join(tmp, "move_wide_imm.tsv")
            self.assertTrue(os.path.isfile(tsv_path))
            with open(tsv_path, "r", encoding="utf-8") as fh:
                raw_lines = fh.read().splitlines()

            comment_lines = [ln for ln in raw_lines if ln.startswith("#")]
            data_lines = [ln for ln in raw_lines if ln and not ln.startswith("#")]
            joined_comments = "\n".join(comment_lines)

            self.assertIn("Apple LLVM version", joined_comments)
            self.assertIn("xcrun clang", joined_comments)
            self.assertIn("--no-symbolic-operands", joined_comments)
            self.assertIn("-mllvm=-aarch64-neon-syntax=generic", joined_comments)
            self.assertIn("Scripts/acceptance/encoding-table.py generate move_wide_imm", joined_comments)

            home_dir = os.path.expanduser("~")
            self.assertNotIn(home_dir, "\n".join(raw_lines))
            self.assertNotIn(tmp, "\n".join(raw_lines))

            self.assertEqual(len(data_lines), 128)
            seen_mnemonics = set()
            for ln in data_lines:
                parts = ln.split("\t", 2)
                self.assertIn(len(parts), (2, 3), f"Malformed TSV row: {ln!r}")
                self.assertRegex(parts[0], r"^0x[0-9a-f]{8}$")
                self.assertTrue(parts[1].strip())
                self.assertFalse(mnemonic_normalization.has_neon_arrangement_suffix(parts[1]))
                seen_mnemonics.add(parts[1])

            for expected_mnem in (".long", "mov", "movz", "movn", "movk"):
                self.assertIn(expected_mnem, seen_mnemonics)

    def test_stage4_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        expected_counts = {
            "cond_branch_imm": 256,
            "advsimd_copy": 4096,
            "bitfield": 3072,
            "lse_atomic": 1024,
        }
        for grp_name, expected_len in expected_counts.items():
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), expected_len)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table, ["generate", "cond_branch_imm", "--out-dir", tmp]
            )
            self.assertEqual(rc, 0, f"generate cond_branch_imm failed: {stdout_txt}\n{stderr_txt}")
            _, rows = enc_table.load_reference_table(os.path.join(tmp, "cond_branch_imm.tsv"))
            self.assertEqual(len(rows), 256)
            mnems = {m for _, m, _ in rows}
            self.assertIn(".long", mnems)
            self.assertIn("b.eq", mnems)
            self.assertNotIn("bc.eq", mnems)

    def test_stage5_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        expected_counts = {
            "fp_imm": 1152,
            "add_sub_ext_reg": 4096,
            "system_instr": 4096,
            "sysreg_mrs_op1_0": 4096,
            "sysreg_mrs_op1_1": 4096,
            "sysreg_mrs_op1_2": 4096,
            "sysreg_mrs_op1_3": 4096,
            "sysreg_mrs_op1_4": 4096,
            "sysreg_mrs_op1_5": 4096,
            "sysreg_mrs_op1_6": 4096,
            "sysreg_mrs_op1_7": 4096,
            "sysreg_msr_op1_0": 4096,
            "sysreg_msr_op1_1": 4096,
            "sysreg_msr_op1_3": 4096,
        }
        for grp_name, expected_len in expected_counts.items():
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), expected_len)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")

        # Verify the 8 MRS slices partition all 32,768 MRS system-register encodings with no overlap
        mrs_all_words = []
        for op1 in range(8):
            mrs_all_words.extend(enc_table.ENCODING_GROUPS[f"sysreg_mrs_op1_{op1}"].generate_words())
        self.assertEqual(len(mrs_all_words), 32768)
        self.assertEqual(len(set(mrs_all_words)), 32768)

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table, ["generate", "fp_imm", "--out-dir", tmp]
            )
            self.assertEqual(rc, 0, f"generate fp_imm failed: {stdout_txt}\n{stderr_txt}")
            _, rows = enc_table.load_reference_table(os.path.join(tmp, "fp_imm.tsv"))
            self.assertEqual(len(rows), 1152)
            fcmp_zero_ops = [ops for _, m, ops in rows if m in ("fcmp", "fcmpe") and "#" in ops]
            self.assertTrue(fcmp_zero_ops)
            self.assertTrue(all(ops.endswith("#0.0") for ops in fcmp_zero_ops))

    def test_stage6_udf_encoding_group_registered_and_generates_udf_and_counterexamples(self):
        enc_table = self._mod()
        self.assertIn("udf", enc_table.ENCODING_GROUPS)
        words = enc_table.ENCODING_GROUPS["udf"].generate_words()
        self.assertLessEqual(len(words), 4096)
        self.assertEqual(len(set(words)), len(words), "duplicate words in udf")
        udf_words = [w for w in words if (w >> 16) == 0]
        counter_words = [w for w in words if (w >> 16) != 0]
        self.assertGreaterEqual(len(udf_words), 512)
        self.assertGreaterEqual(len(counter_words), 16)
        for boundary in (0x00000000, 0x00000001, 0x0000000F, 0x00000010, 0x00007FFF, 0x00008000, 0x0000FFFF):
            self.assertIn(boundary, udf_words)

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table, ["generate", "udf", "--out-dir", tmp]
            )
            self.assertEqual(rc, 0, f"generate udf failed: {stdout_txt}\n{stderr_txt}")
            comments, rows = enc_table.load_reference_table(os.path.join(tmp, "udf.tsv"))
            self.assertEqual(len(rows), len(words))
            self.assertTrue(any("encoding-table.py generate udf" in c for c in comments))
            for w, mnem, ops in rows:
                if (w >> 16) == 0:
                    self.assertEqual(mnem, "udf")
                    self.assertEqual(ops, f"#0x{w & 0xFFFF:x}")
                else:
                    self.assertEqual(mnem, ".long")

    def test_stage7_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        expected_counts = {
            "advsimd_vec_three_same": 880,
            "advsimd_scalar_three_same": 480,
            "advsimd_dot_product": 96,
        }
        for grp_name, expected_len in expected_counts.items():
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), expected_len)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")

        # Verify distinct-register Group 1 (864) + Group 29 (96) + Copy bit[15]=0 (64) partition all 1,024
        # non-register combinations of (word & 0x9f000400) == 0x0e000400 with zero overlap:
        reg_mask = ~((0x1F << 16) | (0x1F << 5) | 0x1F) & 0xFFFFFFFF
        g1_nonreg = {w & reg_mask for w in enc_table.ENCODING_GROUPS["advsimd_vec_three_same"].generate_words()[:864]}
        g29_nonreg = {w & reg_mask for w in enc_table.ENCODING_GROUPS["advsimd_dot_product"].generate_words()}
        copy_nonreg = {
            w & reg_mask
            for w in enc_table.ENCODING_GROUPS["advsimd_copy"].generate_words()
            if ((w >> 15) & 1) == 0
        }
        self.assertEqual(len(g1_nonreg), 864)
        self.assertEqual(len(g29_nonreg), 96)
        self.assertEqual(len(copy_nonreg), 64)
        self.assertTrue(g1_nonreg.isdisjoint(g29_nonreg))
        self.assertTrue(g1_nonreg.isdisjoint(copy_nonreg))
        self.assertTrue(g29_nonreg.isdisjoint(copy_nonreg))
        self.assertEqual(len(g1_nonreg | g29_nonreg | copy_nonreg), 1024)

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table,
                ["generate", "advsimd_vec_three_same", "advsimd_scalar_three_same", "advsimd_dot_product", "--out-dir", tmp],
            )
            self.assertEqual(rc, 0, f"generate stage 7 tables failed: {stdout_txt}\n{stderr_txt}")
            comments, rows = enc_table.load_reference_table(os.path.join(tmp, "advsimd_vec_three_same.tsv"))
            self.assertEqual(len(rows), 880)
            self.assertTrue(any("encoding-table.py generate advsimd_vec_three_same" in c for c in comments))
            mnems = {m for _, m, _ in rows}
            for expected_mnem in ("add", "sub", "mul", "orr", "mov", "fadd", "fmlal", "sqrdmlah", "fcmla", ".long"):
                self.assertIn(expected_mnem, mnems)

            s_comments, s_rows = enc_table.load_reference_table(os.path.join(tmp, "advsimd_scalar_three_same.tsv"))
            self.assertEqual(len(s_rows), 480)
            self.assertTrue(any("encoding-table.py generate advsimd_scalar_three_same" in c for c in s_comments))
            s_mnems = {m for _, m, _ in s_rows}
            for expected_mnem in ("sqadd", "uqshl", "add", "sub", "cmgt", "cmhi", "fabd", "fmulx", "sqrdmlah", ".long"):
                self.assertIn(expected_mnem, s_mnems)

            d_comments, d_rows = enc_table.load_reference_table(os.path.join(tmp, "advsimd_dot_product.tsv"))
            self.assertEqual(len(d_rows), 96)
            self.assertTrue(any("encoding-table.py generate advsimd_dot_product" in c for c in d_comments))
            d_mnems = [m for _, m, _ in d_rows if m != ".long"]
            self.assertEqual(sorted(d_mnems), ["sdot", "sdot", "udot", "udot"])

    def test_stage8_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        enc_fuzz = _load_script_module("encoding_fuzz_stage8_check", "encoding-fuzz.py")

        # Verify Group 2 (AdvSIMD scalar two-register misc) classification in encoding-fuzz.py
        # keeps C4.1.95.10/11 opcodes (including FCVTZS/FCVTMS/FCMEQ #0.0/FCMGT #0.0) in Group 2
        # while keeping C4.1.95.9 ADDP/FADDP in Group 24 (AdvSIMD scalar pairwise):
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5EA1B841), "AdvSIMD scalar two-register misc")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5EA0C841), "AdvSIMD scalar two-register misc")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5EF8C841), "AdvSIMD scalar two-register misc")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5EF1B841), "AdvSIMD scalar pairwise")

        expected_counts = {
            "advsimd_scalar_two_reg_misc": 512,
            "advsimd_vec_two_reg_misc": 1024,
        }
        for grp_name, expected_len in expected_counts.items():
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), expected_len)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table,
                ["generate", "advsimd_scalar_two_reg_misc", "advsimd_vec_two_reg_misc", "--out-dir", tmp],
            )
            self.assertEqual(rc, 0, f"generate stage 8 tables failed: {stdout_txt}\n{stderr_txt}")
            s_comments, s_rows = enc_table.load_reference_table(os.path.join(tmp, "advsimd_scalar_two_reg_misc.tsv"))
            self.assertEqual(len(s_rows), 512)
            self.assertTrue(any("encoding-table.py generate advsimd_scalar_two_reg_misc" in c for c in s_comments))
            s_mnems = {m for _, m, _ in s_rows}
            for expected_mnem in (
                "scvtf",
                "ucvtf",
                "fcvtzs",
                "fcvtzu",
                "fcvtns",
                "fcvtms",
                "fcvtps",
                "fcvtas",
                "fcvtxn",
                "sqxtn",
                "sqxtun",
                "uqxtn",
                "abs",
                "neg",
                "cmeq",
                "fcmeq",
                "frecpe",
                "frecpx",
                "frsqrte",
                ".long",
            ):
                self.assertIn(expected_mnem, s_mnems)

            v_comments, v_rows = enc_table.load_reference_table(os.path.join(tmp, "advsimd_vec_two_reg_misc.tsv"))
            self.assertEqual(len(v_rows), 1024)
            self.assertTrue(any("encoding-table.py generate advsimd_vec_two_reg_misc" in c for c in v_comments))
            v_mnems = {m for _, m, _ in v_rows}
            for expected_mnem in (
                "rev64",
                "rev32",
                "rev16",
                "cnt",
                "mvn",
                "rbit",
                "cls",
                "clz",
                "saddlp",
                "uadalp",
                "abs",
                "neg",
                "cmeq",
                "fcmeq",
                "xtn",
                "xtn2",
                "sqxtn",
                "sqxtn2",
                "shll",
                "shll2",
                "fcvtn",
                "fcvtl2",
                "fcvtxn2",
                "frintn",
                "frint32z",
                "frint64x",
                "urecpe",
                "frecpe",
                "fsqrt",
                ".long",
            ):
                self.assertIn(expected_mnem, v_mnems)

    def test_stage9_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        enc_fuzz = _load_script_module("encoding_fuzz_stage9_check", "encoding-fuzz.py")

        # Verify bit[23] / bit[10] / immh boundaries in encoding-fuzz.py:
        #   - bit[23]==0, bit[10]==1, immh!=0 (vec) -> AdvSIMD vector shift by immediate (Group 3)
        #   - bit[23]==0, bit[10]==1, immh==0 (vec) -> AdvSIMD vector modified immediate (Group 11)
        #   - bit[23]==0, bit[10]==0 (vec) -> AdvSIMD vector indexed element (Group 13)
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x2F20A442), "AdvSIMD vector shift by immediate")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x0F01C7E1), "AdvSIMD vector modified immediate")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x0F401041), "AdvSIMD vector indexed element")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5F6454A6), "AdvSIMD scalar shift by immediate")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x5F49D380), "AdvSIMD scalar indexed element")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x1E02C000), "Scalar FP <-> fixed-point conversions")

        g3_slices = (
            "advsimd_vec_shift_imm_q0_u0",
            "advsimd_vec_shift_imm_q0_u1",
            "advsimd_vec_shift_imm_q1_u0",
            "advsimd_vec_shift_imm_q1_u1",
        )
        all_g3_words = []
        for grp_name in g3_slices:
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), 3840)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")
            all_g3_words.extend(words)

        # All 4 slices are disjoint and partition all 2 x 2 x 15 x 8 x 32 = 15,360 non-register combinations:
        self.assertEqual(len(all_g3_words), 15360)
        self.assertEqual(len(set(all_g3_words)), 15360)
        for w in all_g3_words[::128]:
            self.assertEqual(enc_fuzz.classify_a64_encoding_group(w), "AdvSIMD vector shift by immediate")

        g30_slices = (
            "advsimd_scalar_shift_imm_u0",
            "advsimd_scalar_shift_imm_u1",
        )
        all_g30_words = []
        for grp_name in g30_slices:
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), 4096)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")
            all_g30_words.extend(words)

        # Both slices are disjoint and partition all 2 x 16 x 8 x 32 = 8,192 non-register combinations:
        self.assertEqual(len(all_g30_words), 8192)
        self.assertEqual(len(set(all_g30_words)), 8192)
        for w in all_g30_words[::128]:
            self.assertEqual(enc_fuzz.classify_a64_encoding_group(w), "AdvSIMD scalar shift by immediate")

        self.assertIn("scalar_fp_fixed_point", enc_table.ENCODING_GROUPS)
        g12_words = enc_table.ENCODING_GROUPS["scalar_fp_fixed_point"].generate_words()
        self.assertEqual(len(g12_words), 3776)
        self.assertLessEqual(len(g12_words), 4096)
        self.assertEqual(len(set(g12_words)), len(g12_words), "duplicate words in scalar_fp_fixed_point")
        for w in g12_words[::64]:
            self.assertEqual(enc_fuzz.classify_a64_encoding_group(w), "Scalar FP <-> fixed-point conversions")

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table,
                [
                    "generate",
                    "advsimd_vec_shift_imm_q0_u0",
                    "advsimd_vec_shift_imm_q1_u1",
                    "advsimd_scalar_shift_imm_u0",
                    "advsimd_scalar_shift_imm_u1",
                    "scalar_fp_fixed_point",
                    "--out-dir",
                    tmp,
                ],
            )
            self.assertEqual(rc, 0, f"generate stage 9 slices failed: {stdout_txt}\n{stderr_txt}")
            c00, r00 = enc_table.load_reference_table(os.path.join(tmp, "advsimd_vec_shift_imm_q0_u0.tsv"))
            self.assertEqual(len(r00), 3840)
            self.assertTrue(any("encoding-table.py generate advsimd_vec_shift_imm_q0_u0" in c for c in c00))
            m00 = {m for _, m, _ in r00}
            for expected_mnem in ("sshr", "ssra", "srshr", "srsra", "shl", "sqshl", "shrn", "rshrn", "sqshrn", "sqrshrn", "sshll", "scvtf", "fcvtzs", ".long"):
                self.assertIn(expected_mnem, m00)

            c11, r11 = enc_table.load_reference_table(os.path.join(tmp, "advsimd_vec_shift_imm_q1_u1.tsv"))
            self.assertEqual(len(r11), 3840)
            self.assertTrue(any("encoding-table.py generate advsimd_vec_shift_imm_q1_u1" in c for c in c11))
            m11 = {m for _, m, _ in r11}
            for expected_mnem in ("ushr", "usra", "urshr", "ursra", "sri", "sli", "sqshlu", "uqshl", "sqshrun2", "sqrshrun2", "uqshrn2", "uqrshrn2", "ushll2", "ucvtf", "fcvtzu", ".long"):
                self.assertIn(expected_mnem, m11)

            sc0, sr0 = enc_table.load_reference_table(os.path.join(tmp, "advsimd_scalar_shift_imm_u0.tsv"))
            self.assertEqual(len(sr0), 4096)
            self.assertTrue(any("encoding-table.py generate advsimd_scalar_shift_imm_u0" in c for c in sc0))
            sm0 = {m for _, m, _ in sr0}
            for expected_mnem in ("sshr", "ssra", "srshr", "srsra", "shl", "sqshl", "sqshrn", "sqrshrn", "scvtf", "fcvtzs", ".long"):
                self.assertIn(expected_mnem, sm0)

            sc1, sr1 = enc_table.load_reference_table(os.path.join(tmp, "advsimd_scalar_shift_imm_u1.tsv"))
            self.assertEqual(len(sr1), 4096)
            self.assertTrue(any("encoding-table.py generate advsimd_scalar_shift_imm_u1" in c for c in sc1))
            sm1 = {m for _, m, _ in sr1}
            for expected_mnem in ("ushr", "usra", "urshr", "ursra", "sri", "sli", "sqshlu", "uqshl", "sqshrun", "sqrshrun", "uqshrn", "uqrshrn", "ucvtf", "fcvtzu", ".long"):
                self.assertIn(expected_mnem, sm1)

            fc, fr = enc_table.load_reference_table(os.path.join(tmp, "scalar_fp_fixed_point.tsv"))
            self.assertEqual(len(fr), 3776)
            self.assertTrue(any("encoding-table.py generate scalar_fp_fixed_point" in c for c in fc))
            fm = {m for _, m, _ in fr}
            self.assertEqual(fm, {"scvtf", "ucvtf", "fcvtzs", "fcvtzu", ".long"})

    def test_stage10_encoding_groups_registered_and_unique_within_row_limit(self):
        enc_table = self._mod()
        enc_fuzz = _load_script_module("encoding_fuzz_stage10_check", "encoding-fuzz.py")

        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0xDAC13BF0), "PAC data/instruction pointer")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x38BFC108), "LDAPR (RCpc) and LSE atomic")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x9E690009), "Scalar FP <-> integer conversions")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x1E664000), "Scalar FP data-processing (1 source)")
        self.assertEqual(enc_fuzz.classify_a64_encoding_group(0x1F608020), "Scalar FP data-processing (3 source)")
        expected_counts = {
            "pac_data_ptr": 3200,
            "rcpc_ldapr": 512,
            "scalar_fp_int_conv": 1536,
            "scalar_fp_one_source": 1120,
            "scalar_fp_three_source": 128,
        }
        for grp_name, expected_len in expected_counts.items():
            self.assertIn(grp_name, enc_table.ENCODING_GROUPS)
            words = enc_table.ENCODING_GROUPS[grp_name].generate_words()
            self.assertEqual(len(words), expected_len)
            self.assertLessEqual(len(words), 4096)
            self.assertEqual(len(set(words)), len(words), f"duplicate words in {grp_name}")

        with tempfile.TemporaryDirectory() as tmp:
            rc, stdout_txt, stderr_txt = self._invoke(
                enc_table,
                [
                    "generate",
                    "pac_data_ptr",
                    "rcpc_ldapr",
                    "scalar_fp_int_conv",
                    "scalar_fp_one_source",
                    "scalar_fp_three_source",
                    "--out-dir",
                    tmp,
                ],
            )
            self.assertEqual(rc, 0, f"generate stage 10 tables failed: {stdout_txt}\n{stderr_txt}")
            pc, pr = enc_table.load_reference_table(os.path.join(tmp, "pac_data_ptr.tsv"))
            self.assertEqual(len(pr), 3200)
            self.assertTrue(any("encoding-table.py generate pac_data_ptr" in c for c in pc))
            pm = {m for _, m, _ in pr}
            for expected_mnem in (
                "pacia",
                "pacib",
                "pacda",
                "pacdb",
                "autia",
                "autib",
                "autda",
                "autdb",
                "paciza",
                "pacizb",
                "pacdza",
                "pacdzb",
                "autiza",
                "autizb",
                "autdza",
                "autdzb",
                "xpaci",
                "xpacd",
                "rbit",
                "rev",
                "clz",
                "cls",
                ".long",
            ):
                self.assertIn(expected_mnem, pm)

            lc, lr = enc_table.load_reference_table(os.path.join(tmp, "rcpc_ldapr.tsv"))
            self.assertEqual(len(lr), 512)
            self.assertTrue(any("encoding-table.py generate rcpc_ldapr" in c for c in lc))
            lm = {m for _, m, _ in lr}
            for expected_mnem in ("ldaprb", "ldaprh", "ldapr", "swpb", "swp", ".long"):
                self.assertIn(expected_mnem, lm)

            ic, ir = enc_table.load_reference_table(os.path.join(tmp, "scalar_fp_int_conv.tsv"))
            self.assertEqual(len(ir), 1536)
            self.assertTrue(any("encoding-table.py generate scalar_fp_int_conv" in c for c in ic))
            im = {m for _, m, _ in ir}
            for expected_mnem in (
                "fcvtns",
                "fcvtnu",
                "scvtf",
                "ucvtf",
                "fcvtas",
                "fcvtau",
                "fcvtps",
                "fcvtpu",
                "fcvtms",
                "fcvtmu",
                "fcvtzs",
                "fcvtzu",
                "fjcvtzs",
                "fmov",
                ".long",
            ):
                self.assertIn(expected_mnem, im)

            oc, orows = enc_table.load_reference_table(os.path.join(tmp, "scalar_fp_one_source.tsv"))
            self.assertEqual(len(orows), 1120)
            self.assertTrue(any("encoding-table.py generate scalar_fp_one_source" in c for c in oc))
            om = {m for _, m, _ in orows}
            for expected_mnem in (
                "fmov",
                "fabs",
                "fneg",
                "fsqrt",
                "fcvt",
                "frintn",
                "frintp",
                "frintm",
                "frintz",
                "frinta",
                "frintx",
                "frinti",
                "frint32z",
                "frint32x",
                "frint64z",
                "frint64x",
                ".long",
            ):
                self.assertIn(expected_mnem, om)

            tc, trows = enc_table.load_reference_table(os.path.join(tmp, "scalar_fp_three_source.tsv"))
            self.assertEqual(len(trows), 128)
            self.assertTrue(any("encoding-table.py generate scalar_fp_three_source" in c for c in tc))
            tm = {m for _, m, _ in trows}
            for expected_mnem in ("fmadd", "fmsub", "fnmadd", "fnmsub", ".long"):
                self.assertIn(expected_mnem, tm)

    def test_encoding_table_check_exit_codes_0_1_2_and_mismatch_listing(self):
        enc_table = self._mod()

        # Usage errors must return exit code 2
        for bad_argv in (
            [],
            ["bogus_cmd", "move_wide_imm"],
            ["generate"],
            ["check"],
            ["check", "nonexistent_group_name"],
            ["check", "move_wide_imm", "--all"],
            ["check", "--unknown-flag"],
        ):
            rc, _, _ = self._invoke(enc_table, bad_argv)
            self.assertEqual(rc, 2, f"Expected exit code 2 for usage error argv={bad_argv}, got {rc}")

        with tempfile.TemporaryDirectory() as tmp:
            # Build a real 4-word table via clang + llvm-objdump (zero dependency on system binaries):
            #   0xd503201f -> nop
            #   0x32800001 -> .long 0x32800001 (unallocated Move Wide opc=01)
            #   0xd2800201 -> mov x1, #0x10
            #   0x91004041 -> add x1, x2, #0x10
            sample_words = [0xD503201F, 0x32800001, 0xD2800201, 0x91004041]
            tsv_path = os.path.join(tmp, "mini_group.tsv")
            enc_table.write_reference_table(
                words=sample_words,
                output_path=tsv_path,
                group_name="mini_group",
                header_notes=["Test mini group generated via clang Mach-O"],
            )

            def make_disasm_stub(filename: str, rows_by_word: dict) -> str:
                # Reads the compiled Mach-O via llvm-objdump or parses section to emit exact addresses,
                # or simpler: uses otool/llvm-objdump -d --section=__TEXT,__text to find _main base address!
                stub_path = os.path.join(tmp, filename)
                with open(stub_path, "w", encoding="utf-8") as fh:
                    fh.write(
                        "#!/usr/bin/env python3\n"
                        "import subprocess, sys\n"
                        "bin_path = sys.argv[2]\n"
                        "proc = subprocess.run(['xcrun', 'llvm-objdump', '--macho', '-d', '--arch=arm64e', '--section=__TEXT,__text', bin_path], capture_output=True, text=True, check=True)\n"
                        "addrs = []\n"
                        "for ln in proc.stdout.splitlines():\n"
                        "    parts = ln.split('\\t')\n"
                        "    if len(parts) >= 2 and parts[0].strip().endswith(':'):\n"
                        "        try:\n"
                        "            addrs.append(int(parts[0].strip()[:-1], 16))\n"
                        "        except ValueError:\n"
                        "            pass\n"
                        f"rows = {rows_by_word!r}\n"
                        "print(f'; Section __TEXT,__text @ 0x{addrs[0]:x}')\n"
                        "for addr, (w_hex, mnem, ops) in zip(addrs, rows):\n"
                        "    print(f'0x{addr:016x}\\t{w_hex}\\t{mnem}\\t{ops}')\n"
                    )
                os.chmod(stub_path, os.stat(stub_path).st_mode | stat.S_IXUSR)
                return stub_path

            # 1. All 4 rows match (including exact mov mnemonic, O2 #16 == #0x10, and .long -> .inst) -> exit 0
            mg_ok = make_disasm_stub(
                "mg_ok.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", ".inst", "0x32800001"),
                    ("d2800201", "mov", "x1, #16"),
                    ("91004041", "add", "x1, x2, #16"),
                ],
            )
            rc_ok, out_ok, err_ok = self._invoke(
                enc_table, ["check", "--table", tsv_path, "--machgraph", mg_ok]
            )
            self.assertEqual(rc_ok, 0, f"Expected exit 0 when all rows match:\n{out_ok}\n{err_ok}")

            # 2. Reference `.long` decoded as non-`.inst` -> exit 1 and lists word + both sides
            mg_bad_long = make_disasm_stub(
                "mg_bad_long.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", "movn", "w1, #0"),
                    ("d2800201", "mov", "x1, #16"),
                    ("91004041", "add", "x1, x2, #16"),
                ],
            )
            rc_long, out_long, err_long = self._invoke(
                enc_table, ["check", "--table", tsv_path, "--machgraph", mg_bad_long]
            )
            self.assertEqual(rc_long, 1)
            combined_long = out_long + "\n" + err_long
            self.assertIn("0x32800001", combined_long)
            self.assertIn(".long", combined_long)
            self.assertIn("movn", combined_long)

            # 3. Operand mismatch (missing '#' under tightened O2) -> exit 1 and lists word + both sides
            mg_bad_op = make_disasm_stub(
                "mg_bad_op.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", ".inst", "0x32800001"),
                    ("d2800201", "mov", "x1, #16"),
                    ("91004041", "add", "x1, x2, 16"),
                ],
            )
            rc_op, out_op, err_op = self._invoke(
                enc_table, ["check", "--table", tsv_path, "--machgraph", mg_bad_op]
            )
            self.assertEqual(rc_op, 1)
            combined_op = out_op + "\n" + err_op
            self.assertIn("0x91004041", combined_op)
            self.assertIn("add x1, x2, #0x10", combined_op)
            self.assertIn("add x1, x2, 16", combined_op)

            # 4. Reference instruction decoded as `.inst` by MachGraph (`unknown`) -> exit 1
            mg_unknown = make_disasm_stub(
                "mg_unknown.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", ".inst", "0x32800001"),
                    ("d2800201", "mov", "x1, #16"),
                    ("91004041", ".inst", "0x91004041"),
                ],
            )
            rc_unk, out_unk, err_unk = self._invoke(
                enc_table, ["check", "--table", tsv_path, "--machgraph", mg_unknown]
            )
            self.assertEqual(rc_unk, 1)
            self.assertIn("0x91004041", out_unk + "\n" + err_unk)

            # 5. Oversized table (> 4096 rows) and headerless table -> exit 1
            no_hdr_tsv = os.path.join(tmp, "no_header.tsv")
            with open(no_hdr_tsv, "w", encoding="utf-8") as fh:
                fh.write("0xd503201f\tnop\n")
            rc_no_hdr, _, _ = self._invoke(
                enc_table, ["check", "--table", no_hdr_tsv, "--machgraph", mg_ok]
            )
            self.assertEqual(rc_no_hdr, 1)

            oversized_tsv = os.path.join(tmp, "oversized.tsv")
            with open(oversized_tsv, "w", encoding="utf-8") as fh:
                fh.write("# Reference tool version: Apple LLVM version 21.0.0\n")
                fh.write("# Assembly command: xcrun clang -arch arm64e a.s -o a.macho\n")
                fh.write("# Reference command: xcrun llvm-objdump --macho -d a.macho\n")
                for _ in range(4097):
                    fh.write("0xd503201f\tnop\n")
            rc_over, _, _ = self._invoke(
                enc_table, ["check", "--table", oversized_tsv, "--machgraph", mg_ok]
            )
            self.assertEqual(rc_over, 1)


class TestItem15EncodingFuzzHarness(unittest.TestCase):
    """M2 Stage 3: `encoding-fuzz.py` RNG determinism, 5-way bucket classification on clang Mach-O, and exit codes."""

    def _mod(self):
        return _load_script_module("encoding_fuzz_mod", "encoding-fuzz.py")

    def _invoke(self, mod, argv):
        import io
        from contextlib import redirect_stderr, redirect_stdout

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        try:
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                rc = mod.main(argv)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_encoding_fuzz_seed_rng_and_five_way_classification_with_clang_macho(self):
        import random as py_random

        enc_fuzz = self._mod()
        self.assertIs(enc_fuzz.build_reference_command, mnemonic_normalization.build_reference_command)

        rng = py_random.Random()
        rng.seed(17)
        expected_words = [rng.getrandbits(32) for _ in range(10)]
        self.assertEqual(enc_fuzz.generate_random_words(17, 10), expected_words)

        # Controlled 6 words compiled into a real clang Mach-O (no dependency on system binaries):
        #  0: 0xd503201f -> nop (agree, operand equal)
        #  1: 0x91004041 -> add x1, x2, #0x10 (agree, operand equal with #16)
        #  2: 0x32800001 -> .long 0x32800001 (both unrecognized: .long + .inst)
        #  3: 0x4ee08420 -> add v0.2d, v1.2d, v0.2d (unknown: MG emits .inst, AdvSIMD vector three-register same)
        #  4: 0x54000050 -> .long 0x54000050 (wrong: MG emits bc.eq)
        #  5: 0xd2a00021 -> mov x1, #0x10000 (agree on mov, operand mismatch: stub emits mov x1, #1, lsl #16)
        controlled_words = [
            0xD503201F,
            0x91004041,
            0x32800001,
            0x4EE08420,
            0x54000050,
            0xD2A00021,
        ]

        with tempfile.TemporaryDirectory() as tmp:
            mg_rows = [
                ("d503201f", "nop", ""),
                ("91004041", "add", "x1, x2, #16"),
                ("32800001", ".inst", "0x32800001"),
                ("4ee08420", ".inst", "0x4ee08420"),
                ("54000050", "bc.eq", "0x100000300"),
                ("d2a00021", "mov", "x1, #1, lsl #16"),
            ]
            stub_mg = os.path.join(tmp, "fake_mg.py")
            with open(stub_mg, "w", encoding="utf-8") as fh:
                fh.write(
                    "#!/usr/bin/env python3\n"
                    "import subprocess, sys\n"
                    "bin_path = sys.argv[2]\n"
                    "proc = subprocess.run(['xcrun', 'llvm-objdump', '--macho', '-d', '--arch=arm64e', '--section=__TEXT,__text', bin_path], capture_output=True, text=True, check=True)\n"
                    "addrs = []\n"
                    "for ln in proc.stdout.splitlines():\n"
                    "    parts = ln.split('\\t')\n"
                    "    if len(parts) >= 2 and parts[0].strip().endswith(':'):\n"
                    "        try:\n"
                    "            addrs.append(int(parts[0].strip()[:-1], 16))\n"
                    "        except ValueError:\n"
                    "            pass\n"
                    f"rows = {mg_rows!r}\n"
                    "print(f'; Section __TEXT,__text @ 0x{addrs[0]:x}')\n"
                    "for addr, (w_hex, mnem, ops) in zip(addrs, rows):\n"
                    "    print(f'0x{addr:016x}\\t{w_hex}\\t{mnem}\\t{ops}')\n"
                )
            os.chmod(stub_mg, os.stat(stub_mg).st_mode | stat.S_IXUSR)
            json_out = os.path.join(tmp, "fuzz.json")

            with mock.patch.object(enc_fuzz, "generate_random_words", return_value=controlled_words):
                rc, out_txt, err_txt = self._invoke(
                    enc_fuzz,
                    ["--seed", "42", "--count", "6", "--machgraph", stub_mg, "--json-out", json_out],
                )

            self.assertEqual(rc, 1, f"Expected exit 1 when wrong>0 or operand_mismatch>0:\n{out_txt}\n{err_txt}")
            with open(json_out, "r", encoding="utf-8") as fh:
                payload = json.load(fh)

            summary = payload["summary"]
            self.assertEqual(summary["seed"], 42)
            self.assertEqual(summary["count"], 6)
            self.assertEqual(summary["agreed_instructions"], 3)
            self.assertEqual(summary["both_unrecognized"], 1)
            self.assertEqual(summary["unknown_instructions"], 1)
            self.assertEqual(summary["wrong_instructions"], 1)
            self.assertEqual(summary["operand_compared"], 3)
            self.assertEqual(summary["operand_equal"], 2)
            self.assertEqual(summary["operand_mismatch"], 1)

            unk_groups = {g["encoding_group"]: g["count"] for g in payload["unknown_by_encoding_group"]}
            self.assertEqual(unk_groups, {"AdvSIMD vector three-register same": 1})

            wrong_pairs = payload["wrong_by_mnemonic_pair"]
            self.assertEqual(len(wrong_pairs), 1)
            self.assertEqual(wrong_pairs[0]["llvm_mnemonic"], ".long")
            self.assertEqual(wrong_pairs[0]["machgraph_mnemonic"], "bc.eq")
            self.assertEqual(wrong_pairs[0]["count"], 1)

            op_diffs = payload["operand_differences"]
            self.assertEqual(len(op_diffs), 1)
            self.assertEqual(op_diffs[0]["category"], "mov|mov: X, #N != X, #N, lsl #N")
            self.assertEqual(op_diffs[0]["count"], 1)

    def test_encoding_fuzz_exit_codes_0_1_2(self):
        enc_fuzz = self._mod()

        # Usage errors must exit 2
        for bad_argv in (
            [],
            ["--seed", "17"],
            ["--count", "10"],
            ["--seed", "17", "--count", "0"],
            ["--seed", "17", "--count", "-3"],
            ["--seed", "notanint", "--count", "10"],
            ["--seed", "17", "--count", "10", "--unknown-opt"],
        ):
            rc, _, _ = self._invoke(enc_fuzz, bad_argv)
            self.assertEqual(rc, 2, f"Expected exit code 2 for usage error argv={bad_argv}, got {rc}")

        with tempfile.TemporaryDirectory() as tmp:
            # 4 words where wrong==0 and operand_mismatch==0 (even with unknown==1 and both_unrecognized==1) -> exit 0!
            words_clean = [0xD503201F, 0x32800001, 0x4EE08420, 0x91004041]

            def make_mg(name, rows):
                p = os.path.join(tmp, name)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(
                        "#!/usr/bin/env python3\n"
                        "import subprocess, sys\n"
                        "bin_path = sys.argv[2]\n"
                        "proc = subprocess.run(['xcrun', 'llvm-objdump', '--macho', '-d', '--arch=arm64e', '--section=__TEXT,__text', bin_path], capture_output=True, text=True, check=True)\n"
                        "addrs = []\n"
                        "for ln in proc.stdout.splitlines():\n"
                        "    parts = ln.split('\\t')\n"
                        "    if len(parts) >= 2 and parts[0].strip().endswith(':'):\n"
                        "        try:\n"
                        "            addrs.append(int(parts[0].strip()[:-1], 16))\n"
                        "        except ValueError:\n"
                        "            pass\n"
                        f"rows = {rows!r}\n"
                        "print(f'; Section __TEXT,__text @ 0x{addrs[0]:x}')\n"
                        "for addr, (w_hex, mnem, ops) in zip(addrs, rows):\n"
                        "    print(f'0x{addr:016x}\\t{w_hex}\\t{mnem}\\t{ops}')\n"
                    )
                os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
                return p

            mg_pass = make_mg(
                "mg_pass.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", ".inst", "0x32800001"),
                    ("4ee08420", ".inst", "0x4ee08420"),
                    ("91004041", "add", "x1, x2, #16"),
                ],
            )
            with mock.patch.object(enc_fuzz, "generate_random_words", return_value=words_clean):
                rc_pass, out_pass, err_pass = self._invoke(
                    enc_fuzz, ["--seed", "1", "--count", "4", "--machgraph", mg_pass]
                )
            self.assertEqual(rc_pass, 0, f"Expected exit 0 when wrong==0 and operand_mismatch==0:\n{out_pass}\n{err_pass}")

            # Operand mismatch alone (wrong==0, operand_mismatch==1) -> exit 1
            mg_op_fail = make_mg(
                "mg_op_fail.py",
                [
                    ("d503201f", "nop", ""),
                    ("32800001", ".inst", "0x32800001"),
                    ("4ee08420", ".inst", "0x4ee08420"),
                    ("91004041", "add", "x1, x2, #99"),
                ],
            )
            with mock.patch.object(enc_fuzz, "generate_random_words", return_value=words_clean):
                rc_op_fail, _, _ = self._invoke(
                    enc_fuzz, ["--seed", "1", "--count", "4", "--machgraph", mg_op_fail]
                )
            self.assertEqual(rc_op_fail, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
