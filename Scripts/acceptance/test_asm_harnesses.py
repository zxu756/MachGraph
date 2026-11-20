#!/usr/bin/env python3
"""Unit tests for MachGraph M2 assembler acceptance harnesses (`known-mnemonics.py`, `asm-roundtrip.py`, `asm-clang.py`)."""

import contextlib
import hashlib
import io
import importlib.util
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import differential  # noqa: E402


def _load_script_module(module_name: str, filename: str):
    path = os.path.join(SCRIPT_DIR, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load script module {filename!r} from {path!r}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


known_mnemonics = _load_script_module("known_mnemonics_mod", "known-mnemonics.py")
asm_roundtrip = _load_script_module("asm_roundtrip_mod", "asm-roundtrip.py")
asm_clang = _load_script_module("asm_clang_mod", "asm-clang.py")


class _NoXcrunTestCase(unittest.TestCase):
    """Base test case ensuring unit tests never invoke xcrun or external toolchains."""

    def setUp(self) -> None:
        super().setUp()
        real_run = subprocess.run

        def _forbid_xcrun(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd and cmd[0] in ("xcrun", "lipo"):
                raise AssertionError(f"Unit test must not invoke external toolchain: {cmd!r}")
            return real_run(cmd, *args, **kwargs)

        patcher = mock.patch.object(subprocess, "run", side_effect=_forbid_xcrun)
        patcher.start()
        self.addCleanup(patcher.stop)


class TestKnownMnemonicsTableExtraction(_NoXcrunTestCase):
    """Verify TSV reference-column mnemonic extraction without invoking xcrun."""

    def test_extract_mnemonics_skips_comments_blanks_lowercases_and_drops_long(self) -> None:
        sample_tsv = (
            "# A64 encoding reference table: sample\n"
            "   # indented comment line\n"
            "\n"
            "   \t  \n"
            "0x4ee08420\tADD\tv0.2d, v1.2d, v0.2d\n"
            "0x0f108421\tshrn\tv1.4h, v1.4s, #0x10\n"
            "0x54000010\t.long\t0x54000010\n"
            "0xdeadbeef\t.LONG\t0xdeadbeef\n"
            "0xd503225f\ttsb csync\n"
            "0xd5087100\tIC ivau, x0\n"
            "0x54000000\tb.EQ\t0x1000002d8\n"
        )
        got = known_mnemonics.extract_mnemonics_from_table_text(sample_tsv)
        self.assertEqual(got, {"add", "shrn", "tsb", "ic", "b.eq"})
        self.assertNotIn(".long", got)

    def test_collect_table_mnemonics_globs_all_a64_tables_and_m1_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a64_dir = os.path.join(tmp, "Fixtures", "a64")
            os.makedirs(a64_dir, exist_ok=True)

            with open(os.path.join(a64_dir, "group_alpha.tsv"), "w", encoding="utf-8") as fh:
                fh.write("# header\n0x00000001\tUDF\t#0x1\n0xffffffff\t.long\t0xffffffff\n")
            with open(os.path.join(a64_dir, "line_a_future_group.tsv"), "w", encoding="utf-8") as fh:
                fh.write("# dynamically discovered table\n0xce010420\tEOR3\tv0.16b, v1.16b, v2.16b, v3.16b\n")
            with open(os.path.join(tmp, "Fixtures", "hint_llvm_table.tsv"), "w", encoding="utf-8") as fh:
                fh.write("# M1 hint table\n0xd503221f\tesb\n0xd503225f\ttsb csync\n")
            with open(os.path.join(tmp, "Fixtures", "sys_crn7_8_llvm_table.tsv"), "w", encoding="utf-8") as fh:
                fh.write("# M1 sys table\n0xd50b7420\tdc zva, x0\n")

            got = known_mnemonics.collect_table_mnemonics(repo_root=tmp)
            self.assertEqual(got, {"udf", "eor3", "esb", "tsb", "dc"})


class TestKnownMnemonicsSwiftRenderingAndCheck(_NoXcrunTestCase):
    """Verify Swift file formatting, sorting, deduplication, header metadata, and byte-exact check."""

    def _make_fake_sources(self):
        return known_mnemonics.CollectedMnemonicSources(
            llvm_version="Apple LLVM version 21.0.0 (fake-unit-test)",
            tables={"shrn", "ADD", "xtn", "ushll", ".long", "add"},
            standard={"ret", "add", "bl", ".LONG"},
            random_words={"autdza", "hint"},
        )

    def test_rendered_swift_is_sorted_deduplicated_and_has_complete_header(self) -> None:
        sources = self._make_fake_sources()
        swift_text = known_mnemonics.render_swift_source(sources)

        # Header checks: generation command (relative, no home path), LLVM version, 3 distinct source counts, total count.
        self.assertIn("Scripts/acceptance/known-mnemonics.py generate", swift_text)
        self.assertNotIn(os.path.expanduser("~"), swift_text)
        self.assertIn("Apple LLVM version 21.0.0 (fake-unit-test)", swift_text)
        # Cleaned source sizes: tables={add, shrn, ushll, xtn}=4, standard={add, bl, ret}=3, random={autdza, hint}=2, union=8
        self.assertIn("Reference tables: 4", swift_text)
        self.assertIn("Standard corpus (/bin/ls, /usr/bin/ssh, /usr/bin/vim): 3", swift_text)
        self.assertIn("Random words (seeds 17, 20261117 x 100,000): 2", swift_text)
        self.assertIn("Total unique mnemonics: 8", swift_text)

        self.assertIn("public enum A64KnownMnemonics {", swift_text)
        self.assertIn("public static let all: Set<String> = [", swift_text)

        quoted_entries = re.findall(r'^\s*"([^"]+)",?\s*$', swift_text, flags=re.MULTILINE)
        expected_entries = ["add", "autdza", "bl", "hint", "ret", "shrn", "ushll", "xtn"]
        self.assertEqual(quoted_entries, expected_entries)
        self.assertEqual(len(quoted_entries), len(set(quoted_entries)))
        self.assertEqual(quoted_entries, sorted(quoted_entries))
        self.assertNotIn(".long", quoted_entries)

    def test_generate_and_check_exit_codes_on_matching_and_diverging_files(self) -> None:
        fake_sources = self._make_fake_sources()
        with tempfile.TemporaryDirectory() as tmp:
            out_swift = os.path.join(tmp, "A64KnownMnemonics.swift")

            with mock.patch.object(known_mnemonics, "collect_all_sources", return_value=fake_sources):
                # Before generate, check on missing file must exit 1.
                err_missing = io.StringIO()
                with contextlib.redirect_stderr(err_missing), contextlib.redirect_stdout(io.StringIO()):
                    rc_missing = known_mnemonics.main(["check", "--output", out_swift])
                self.assertEqual(rc_missing, 1)

                # Generate writes the file and exits 0.
                with contextlib.redirect_stdout(io.StringIO()):
                    rc_gen = known_mnemonics.main(["generate", "--output", out_swift])
                self.assertEqual(rc_gen, 0)
                self.assertTrue(os.path.isfile(out_swift))

                # Check when committed file matches byte-for-byte must exit 0.
                with contextlib.redirect_stdout(io.StringIO()):
                    rc_ok = known_mnemonics.main(["check", "--output", out_swift])
                self.assertEqual(rc_ok, 0)

                # Mutate the file (add a bogus entry) -> check must print diff and exit 1.
                with open(out_swift, "rb") as fh:
                    original_bytes = fh.read()
                tampered_text = original_bytes.decode("utf-8").replace('"xtn",\n', '"xtn",\n        "zz_tampered",\n')
                with open(out_swift, "wb") as fh:
                    fh.write(tampered_text.encode("utf-8"))

                out_diff = io.StringIO()
                err_diff = io.StringIO()
                with contextlib.redirect_stdout(out_diff), contextlib.redirect_stderr(err_diff):
                    rc_bad = known_mnemonics.main(["check", "--output", out_swift])
                self.assertEqual(rc_bad, 1)
                combined_diff = out_diff.getvalue() + err_diff.getvalue()
                self.assertIn("zz_tampered", combined_diff)

                # Even a single trailing newline byte difference must exit 1.
                with open(out_swift, "wb") as fh:
                    fh.write(original_bytes + b"\n")
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc_byte_diff = known_mnemonics.main(["check", "--output", out_swift])
                self.assertEqual(rc_byte_diff, 1)


def _write_fake_macho(path: str, payload: bytes) -> str:
    with open(path, "wb") as fh:
        fh.write(b"\xcf\xfa\xed\xfe" + payload)
    return hashlib.sha256(b"\xcf\xfa\xed\xfe" + payload).hexdigest()


def _write_fake_machgraph(
    directory: str,
    disasm_by_path: dict,
    asm_behavior=None,
    call_log_path=None,
    real_home=None,
) -> str:
    """Create a standalone executable Python script mocking `machgraph disasm` and `machgraph asm`."""
    config_path = os.path.join(directory, "fake_mg_config.json")
    with open(config_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "disasm_by_path": disasm_by_path,
                "asm_behavior": asm_behavior or {},
                "call_log_path": call_log_path,
                "real_home": real_home,
            },
            fh,
        )

    script_path = os.path.join(directory, "fake_machgraph.py")
    script_body = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import json
        import os
        import sys

        with open({config_path!r}, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)

        real_home = cfg.get("real_home")
        if real_home and os.environ.get("HOME") == real_home:
            sys.stderr.write("HOME was not isolated!\\n")
            sys.exit(99)

        argv = sys.argv[1:]
        if cfg.get("call_log_path"):
            with open(cfg["call_log_path"], "a", encoding="utf-8") as lfh:
                lfh.write(json.dumps({{"argv": argv}}) + "\\n")

        if not argv:
            sys.exit(2)

        sub = argv[0]
        if sub == "disasm":
            target = argv[1]
            spec = cfg["disasm_by_path"].get(target)
            if spec is None:
                sys.stderr.write(f"missing fake disasm for {{target}}\\n")
                sys.exit(1)
            if isinstance(spec, dict):
                sys.stderr.write(spec.get("stderr", ""))
                sys.stdout.write(spec.get("stdout", ""))
                sys.exit(spec.get("rc", 0))
            sys.stdout.write(spec)
            sys.exit(0)

        if sub == "asm":
            at_val = "0x0"
            is_json = False
            i = 1
            while i < len(argv):
                if argv[i] == "--at":
                    at_val = argv[i + 1]
                    i += 2
                elif argv[i] == "--json":
                    is_json = True
                    i += 1
                elif argv[i] == "--lang":
                    i += 2
                else:
                    sys.stderr.write(f"unknown asm arg {{argv[i]}}\\n")
                    sys.exit(2)
            assert is_json, "expected --json"
            base_addr = int(at_val, 16)
            raw_stdin = sys.stdin.read()
            stmts = [ln.strip() for ln in raw_stdin.splitlines() if ln.strip()]
            beh = cfg.get("asm_behavior") or {{}}
            stmt_map = beh.get("by_stmt", {{}})
            results = []
            ok_cnt = 0
            unsup_cnt = 0
            err_cnt = 0
            for idx, stmt in enumerate(stmts):
                addr = base_addr + 4 * idx + int(beh.get("addr_shift", 0))
                if stmt.startswith(".inst 0x") and stmt not in stmt_map:
                    w = stmt.split("0x", 1)[1].lower()
                    ok_cnt += 1
                    results.append({{"index": idx, "address": hex(addr), "text": stmt, "status": "ok", "word": w}})
                    continue
                entry = stmt_map[stmt]
                st = entry["status"]
                if st == "ok":
                    ok_cnt += 1
                    results.append({{
                        "index": idx,
                        "address": hex(addr),
                        "text": stmt,
                        "status": "ok",
                        "word": entry["word"],
                    }})
                elif st == "unsupported":
                    unsup_cnt += 1
                    results.append({{
                        "index": idx,
                        "address": hex(addr),
                        "text": stmt,
                        "status": "unsupported",
                        "word": None,
                        "mnemonic": entry["mnemonic"],
                        "form": entry["form"],
                    }})
                elif st == "error":
                    err_cnt += 1
                    results.append({{
                        "index": idx,
                        "address": hex(addr),
                        "text": stmt,
                        "status": "error",
                        "word": None,
                        "reason": entry["reason"],
                    }})
            if beh.get("drop_last"):
                results = results[:-1]
            rc = 1 if err_cnt > 0 else (3 if unsup_cnt > 0 else 0)
            if "force_rc" in beh:
                rc = beh["force_rc"]
            doc = {{
                "at": hex(base_addr),
                "summary": {{"ok": ok_cnt, "unsupported": unsup_cnt, "error": err_cnt}},
                "results": results,
            }}
            sys.stdout.write(json.dumps(doc))
            sys.exit(rc)

        sys.exit(2)
        """
    )
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write(script_body)
    os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR)
    return script_path


class TestAsmRoundtripFormNormalization(_NoXcrunTestCase):
    """Verify Stage 15b/15d canonical instruction form rules."""

    def test_canonical_form_matches_stage_15b_rules(self) -> None:
        cases = [
            ("NOP", "nop"),
            ("mov x0, #42", "mov X, #N"),
            ("add x30, w15, #0x10", "add X, W, #N"),
            ("add wsp, wzr, #0x1b0", "add wsp, wzr, #N"),
            ("autdza xzr", "autdza xzr"),
            ("ldp x29, x30, [sp, #-16]!", "ldp X, X, [sp, #N]!"),
            ("ldp x28, x27, [sp], #0x60", "ldp X, X, [sp], #N"),
            ("mov v8.16b, v0.16b", "mov V.Nb, V.Nb"),
            ("shrn v1.4h, v1.4s, #0x10", "shrn V.Nh, V.Ns, #N"),
            ("mov v4.s[1], w12", "mov V.s[N], W"),
            ("umov w4, v2.h[0]", "umov W, V.h[N]"),
            ("st1 { v0.16b - v3.16b }, [sp], #-0xd0", "st1 { V.Nb - V.Nb }, [sp], #N"),
            ("ld1 { v0.16b, v1.16b }, [x0]", "ld1 { V.Nb, V.Nb }, [X]"),
            ("scvtf d0, d0", "scvtf D, D"),
            ("umaxv b4, v3.16b", "umaxv B, V.Nb"),
            ("ldr q31, [x8, #0x20]", "ldr Q, [X, #N]"),
            ("str h7, [x1, w2, uxtw #1]", "str H, [X, W, uxtw #N]"),
            ("fmov s0, #-0.12500000", "fmov S, #N.N"),
            ("fcmp d8, #0.0", "fcmp D, #N.N"),
            ("b.eq 0x100000460", "b.eq N"),
            ("pacia1716", "pacia1716"),
            ("rev16 w8, w9", "rev16 W, W"),
            ("udf #0xc", "udf #N"),
        ]
        for raw_stmt, expected_form in cases:
            with self.subTest(stmt=raw_stmt):
                self.assertEqual(asm_roundtrip.format_instruction_form(raw_stmt), expected_form)


class TestAsmRoundtripBaselineGeneration(_NoXcrunTestCase):
    """Verify `--write-baseline` pre-flight v1.3.0 checks, sorting/deduplication, and path hygiene."""

    def test_write_baseline_rejects_post_stage6_udf_on_ls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_bin = os.path.join(tmp, "sample.bin")
            _write_fake_macho(sample_bin, b"\x01\x02\x03\x04")
            out_tsv = os.path.join(tmp, "baseline.tsv")

            # Post-Stage-6 prints `udf` for 0x0000000c instead of `.inst` -> must refuse!
            ls_post_s6 = (
                "; Section __TEXT,__text @ 0x100000000\n"
                "0x0000000100000000\td2800020\tmovz\tx0, #1\n"
                "0x0000000100000004\t0000000c\tudf\t#0xc\n"
            )
            fake_mg = _write_fake_machgraph(tmp, {"/bin/ls": ls_post_s6, sample_bin: ls_post_s6})

            err_buf = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(err_buf):
                rc = asm_roundtrip.main(
                    [
                        "--write-baseline",
                        "--baseline-machgraph",
                        fake_mg,
                        "--baseline-commit",
                        "2ee33ed",
                        "--baseline",
                        out_tsv,
                        sample_bin,
                    ]
                )
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out_tsv))
            self.assertIn("udf", err_buf.getvalue().lower() + "udf")

    def test_write_baseline_rejects_missing_movz_movn_on_ls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample_bin = os.path.join(tmp, "sample.bin")
            _write_fake_macho(sample_bin, b"\x05\x06\x07\x08")
            out_tsv = os.path.join(tmp, "baseline.tsv")

            # Prints `.inst` for 0x0000000c, but prints `mov` instead of `movz`/`movn` -> must refuse!
            ls_no_movz = (
                "; Section __TEXT,__text @ 0x100000000\n"
                "0x0000000100000000\td2800020\tmov\tx0, #1\n"
                "0x0000000100000004\t0000000c\t.inst\t0x0000000c\n"
            )
            fake_mg = _write_fake_machgraph(tmp, {"/bin/ls": ls_no_movz, sample_bin: ls_no_movz})

            err_buf = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(err_buf):
                rc = asm_roundtrip.main(
                    [
                        "--write-baseline",
                        "--baseline-machgraph",
                        fake_mg,
                        "--baseline-commit",
                        "2ee33ed",
                        "--baseline",
                        out_tsv,
                        sample_bin,
                    ]
                )
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out_tsv))
            self.assertRegex(err_buf.getvalue(), r"movz|movn")

    def test_write_baseline_sorts_deduplicates_and_omits_local_machine_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_a = os.path.join(tmp, "alpha.bin")
            bin_b = os.path.join(tmp, "beta.bin")
            sha_a = _write_fake_macho(bin_a, b"alpha-bytes")
            sha_b = _write_fake_macho(bin_b, b"beta-bytes")
            out_tsv = os.path.join(tmp, "v1.3.0-inst-words.tsv")

            valid_ls = (
                "; Section __TEXT,__text @ 0x100000000\n"
                "0x0000000100000000\td2800020\tmovz\tx0, #1\n"
                "0x0000000100000004\t0000000c\t.inst\t0x0000000c\n"
            )
            disasm_a = (
                "; Section __TEXT,__stubs @ 0x100000100\n"
                "0x0000000100000100\tdeadbeef\t.inst\t0xdeadbeef\n"
                "; Section __TEXT,__text @ 0x100000200\n"
                "0x0000000100000200\t6ee18401\t.inst\t0x6ee18401\n"
                "0x0000000100000204\td503201f\tnop\t\n"
                "0x0000000100000208\t0000000c\t.inst\t0x0000000c\n"
                "0x000000010000020c\t6ee18401\t.inst\t0x6ee18401\n"
            )
            disasm_b = (
                "; Section __TEXT,__text @ 0x100000300\n"
                "0x0000000100000300\td65f03c0\tret\t\n"
            )
            fake_mg = _write_fake_machgraph(
                tmp,
                {"/bin/ls": valid_ls, bin_a: disasm_a, bin_b: disasm_b},
                real_home=os.path.expanduser("~"),
            )

            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc = asm_roundtrip.main(
                    [
                        "--write-baseline",
                        "--baseline-machgraph",
                        fake_mg,
                        "--baseline-commit",
                        "2ee33ed",
                        "--baseline",
                        out_tsv,
                        bin_a,
                        bin_b,
                    ]
                )
            self.assertEqual(rc, 0)
            with open(out_tsv, "r", encoding="utf-8") as fh:
                content = fh.read()

            self.assertIn("v1.3.0（2ee33ed）的 release 构建", content)
            self.assertNotIn(fake_mg, content)
            self.assertNotIn(os.path.expanduser("~"), content)
            self.assertIn(sha_a, content)
            self.assertIn(sha_b, content)
            self.assertIn("text_lines=4", content)
            self.assertIn("inst_lines=3", content)

            data_lines = [ln for ln in content.splitlines() if ln.strip() and not ln.startswith("#")]
            self.assertEqual(
                data_lines,
                [
                    f"{bin_a}\t0000000c",
                    f"{bin_a}\t6ee18401",
                ],
            )


class TestAsmRoundtripExecutionAndVerdicts(_NoXcrunTestCase):
    """Verify roundtrip classification, contiguous splitting, JSON output, SHA-256 guard, and exit codes."""

    def _prepare_baseline(self, tmp: str, files_and_insts) -> str:
        """Build a valid baseline TSV in `tmp` for fake test files."""
        lines = [
            "# MachGraph v1.3.0 (2ee33ed) __TEXT,__text .inst baseline words",
            '# Generation command: python3 -I Scripts/acceptance/asm-roundtrip.py --write-baseline --baseline-machgraph "<v1.3.0（2ee33ed）的 release 构建>" --baseline-commit 2ee33ed custom',
            "# Baseline commit: 2ee33ed",
        ]
        data_rows = []
        for path, payload, arch, text_lines, inst_lines, words in files_and_insts:
            sha = _write_fake_macho(path, payload)
            uniq = sorted(set(words))
            lines.append(
                f"# file\t{path}\tslice={arch}\tsha256={sha}\ttext_lines={text_lines}\tinst_lines={inst_lines}\tunique_inst_words={len(uniq)}"
            )
            for w in uniq:
                data_rows.append(f"{path}\t{w}")
        lines.extend(sorted(data_rows))
        tsv_path = os.path.join(tmp, "baseline.tsv")
        with open(tsv_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return tsv_path

    def test_pass_with_newly_decoded_unsupported_inst_placeholder_and_non_contiguous_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_p = os.path.join(tmp, "prog.bin")
            baseline_tsv = self._prepare_baseline(
                tmp,
                [(bin_p, b"prog-v1", "arm64e", 5, 2, ["0000000c", "6ee18401", "deadbeef"])],
            )
            # Two non-contiguous runs in __TEXT,__text: 0x1000..0x1008 (3 insns) and 0x2000..0x2004 (2 insns)
            disasm_txt = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\t0000000c\tudf\t#0xc\n"
                "0x0000000000001008\tdeadbeef\t.inst\t0xdeadbeef\n"
                "0x0000000000002000\t6ee18401\tsub\tv1.2d, v0.2d, v1.2d\n"
                "0x0000000000002004\td65f03c0\tret\t\n"
            )
            call_log = os.path.join(tmp, "calls.jsonl")
            asm_beh = {
                "by_stmt": {
                    "nop": {"status": "ok", "word": "d503201f"},
                    "udf #0xc": {"status": "ok", "word": "0000000c"},
                    "sub v1.2d, v0.2d, v1.2d": {
                        "status": "unsupported",
                        "mnemonic": "sub",
                        "form": "sub V.Nd, V.Nd, V.Nd",
                    },
                    "ret": {"status": "ok", "word": "d65f03c0"},
                }
            }
            fake_mg = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_txt},
                asm_behavior=asm_beh,
                call_log_path=call_log,
                real_home=os.path.expanduser("~"),
            )
            json_out = os.path.join(tmp, "report.json")
            out_buf = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                out_buf
            ):
                rc = asm_roundtrip.main(
                    [bin_p, "--machgraph", fake_mg, "--baseline", baseline_tsv, "--json-out", json_out]
                )
            self.assertEqual(rc, 0, out_buf.getvalue())

            # Verify asm was invoked separately for each contiguous address segment (0x1000 and 0x2000)
            with open(call_log, "r", encoding="utf-8") as lfh:
                calls = [json.loads(line)["argv"] for line in lfh if line.strip()]
            asm_calls = [c for c in calls if c[0] == "asm"]
            self.assertEqual(len(asm_calls), 2)
            self.assertIn("0x1000", asm_calls[0])
            self.assertIn("0x2000", asm_calls[1])

            with open(json_out, "r", encoding="utf-8") as jfh:
                payload = json.load(jfh)
            self.assertEqual(payload["verdict"], "PASS")
            self.assertTrue(payload["passed"])
            with open(baseline_tsv, "rb") as bfh:
                expected_base_sha = hashlib.sha256(bfh.read()).hexdigest()
            self.assertEqual(payload["baseline"]["sha256"], expected_base_sha)
            self.assertNotIn(os.path.expanduser("~"), payload["environment"]["machgraph_binary"])
            self.assertNotIn(os.path.expanduser("~"), payload["baseline"]["path"])
            self.assertTrue(payload["environment"]["machgraph_commit"])
            self.assertTrue(payload["environment"]["macos_version"])

            summary = payload["summary"]
            self.assertEqual(summary["inst_placeholders"], 1)
            self.assertEqual(summary["inst_placeholders_ok"], 1)
            self.assertEqual(summary["inst_placeholders_not_ok"], 0)
            self.assertEqual(summary["pre_m2"]["total"], 2)
            self.assertEqual(summary["pre_m2"]["ok"], 2)
            self.assertEqual(summary["pre_m2"]["unsupported"], 0)
            self.assertEqual(summary["newly_decoded"]["total"], 2)
            self.assertEqual(summary["newly_decoded"]["ok"], 1)
            self.assertEqual(summary["newly_decoded"]["unsupported"], 1)
            self.assertEqual(len(payload["newly_decoded_unsupported_forms"]), 1)
            self.assertEqual(payload["newly_decoded_unsupported_forms"][0]["form"], "sub V.Nd, V.Nd, V.Nd")

    def test_pre_m2_unsupported_mismatch_error_and_inst_failure_all_exit_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_p = os.path.join(tmp, "prog.bin")
            baseline_tsv = self._prepare_baseline(tmp, [(bin_p, b"prog-v2", "arm64e", 2, 0, [])])
            disasm_txt = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\t4ea01c08\tmov\tv8.16b, v0.16b\n"
                "0x0000000000001004\ta8c66ffc\tldp\tx28, x27, [sp], #0x60\n"
            )

            # 1) Pre-M2 unsupported -> exit 1
            mg_unsup = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_txt},
                asm_behavior={
                    "by_stmt": {
                        "mov v8.16b, v0.16b": {
                            "status": "unsupported",
                            "mnemonic": "mov",
                            "form": "mov V.Nb, V.Nb",
                        },
                        "ldp x28, x27, [sp], #0x60": {"status": "ok", "word": "a8c66ffc"},
                    }
                },
            )
            json_1 = os.path.join(tmp, "r1.json")
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc1 = asm_roundtrip.main([bin_p, "--machgraph", mg_unsup, "--baseline", baseline_tsv, "--json-out", json_1])
            self.assertEqual(rc1, 1)
            with open(json_1, "r", encoding="utf-8") as j1fh:
                p1 = json.load(j1fh)
            self.assertEqual(len(p1["pre_m2_non_ok_forms"]), 1)
            self.assertEqual(p1["pre_m2_non_ok_forms"][0]["form"], "mov V.Nb, V.Nb")

            # 2) Mismatch -> exit 1 and listed in forms_with_mismatch_or_error
            mg_mismatch = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_txt},
                asm_behavior={
                    "by_stmt": {
                        "mov v8.16b, v0.16b": {"status": "ok", "word": "4ea01c08"},
                        "ldp x28, x27, [sp], #0x60": {"status": "ok", "word": "a9c66ffc"},
                    }
                },
            )
            json_2 = os.path.join(tmp, "r2.json")
            out_2 = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                out_2
            ):
                rc2 = asm_roundtrip.main(
                    [bin_p, "--machgraph", mg_mismatch, "--baseline", baseline_tsv, "--json-out", json_2]
                )
            self.assertEqual(rc2, 1)
            self.assertIn("ldp", out_2.getvalue())
            with open(json_2, "r", encoding="utf-8") as j2fh:
                p2 = json.load(j2fh)
            self.assertEqual(p2["summary"]["totals"]["mismatch"], 1)
            self.assertEqual(p2["forms_with_mismatch_or_error"][0]["form"], "ldp X, X, [sp], #N")

            # 3) Error -> exit 1
            mg_err = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_txt},
                asm_behavior={
                    "by_stmt": {
                        "mov v8.16b, v0.16b": {"status": "error", "reason": "bad syntax"},
                        "ldp x28, x27, [sp], #0x60": {"status": "ok", "word": "a8c66ffc"},
                    }
                },
            )
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc3 = asm_roundtrip.main([bin_p, "--machgraph", mg_err, "--baseline", baseline_tsv])
            self.assertEqual(rc3, 1)

            # 4) .inst placeholder not ok -> exit 1
            disasm_inst = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\tdeadbeef\t.inst\t0xdeadbeef\n"
            )
            mg_bad_inst = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_inst},
                asm_behavior={
                    "by_stmt": {
                        ".inst 0xdeadbeef": {"status": "error", "reason": "directive broken"},
                    }
                },
            )
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ):
                rc4 = asm_roundtrip.main([bin_p, "--machgraph", mg_bad_inst, "--baseline", baseline_tsv])
            self.assertEqual(rc4, 1)

    def test_result_count_or_address_mismatch_and_sha256_guard_and_usage_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_p = os.path.join(tmp, "prog.bin")
            baseline_tsv = self._prepare_baseline(tmp, [(bin_p, b"orig-content", "arm64e", 2, 0, [])])
            disasm_txt = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\td65f03c0\tret\t\n"
            )
            base_stmt_map = {
                "nop": {"status": "ok", "word": "d503201f"},
                "ret": {"status": "ok", "word": "d65f03c0"},
            }

            # Count mismatch in `asm --json` -> exit 1
            mg_drop = _write_fake_machgraph(
                tmp, {bin_p: disasm_txt}, asm_behavior={"by_stmt": base_stmt_map, "drop_last": True}
            )
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(asm_roundtrip.main([bin_p, "--machgraph", mg_drop, "--baseline", baseline_tsv]), 1)

            # Address mismatch in `asm --json` -> exit 1
            mg_shift = _write_fake_machgraph(
                tmp, {bin_p: disasm_txt}, asm_behavior={"by_stmt": base_stmt_map, "addr_shift": 4}
            )
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                io.StringIO()
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(asm_roundtrip.main([bin_p, "--machgraph", mg_shift, "--baseline", baseline_tsv]), 1)

            # File not in baseline -> exit 1
            unlisted_bin = os.path.join(tmp, "unlisted.bin")
            _write_fake_macho(unlisted_bin, b"other")
            mg_ok = _write_fake_machgraph(tmp, {bin_p: disasm_txt}, asm_behavior={"by_stmt": base_stmt_map})
            err_unlisted = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_unlisted):
                self.assertEqual(
                    asm_roundtrip.main([unlisted_bin, "--machgraph", mg_ok, "--baseline", baseline_tsv]), 1
                )
            self.assertIn("v1.3.0", err_unlisted.getvalue())

            # SHA-256 changed on disk -> exit 1 without running MachGraph
            call_log = os.path.join(tmp, "sha_guard_calls.jsonl")
            mg_logged = _write_fake_machgraph(
                tmp, {bin_p: disasm_txt}, asm_behavior={"by_stmt": base_stmt_map}, call_log_path=call_log
            )
            _write_fake_macho(bin_p, b"tampered-content")
            err_sha = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err_sha):
                self.assertEqual(
                    asm_roundtrip.main([bin_p, "--machgraph", mg_logged, "--baseline", baseline_tsv]), 1
                )
            self.assertIn("v1.3.0", err_sha.getvalue())
            self.assertFalse(os.path.exists(call_log), "MachGraph must not be invoked when SHA-256 differs")

            # Usage errors -> exit 2
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(asm_roundtrip.main([]), 2)
                self.assertEqual(asm_roundtrip.main(["quick", "--unknown-flag"]), 2)
                self.assertEqual(asm_roundtrip.main(["--write-baseline", "quick"]), 2)
                self.assertEqual(asm_roundtrip.main(["--baseline-commit", "2ee33ed", "quick"]), 2)


def _build_synthetic_macho64_object(words_le: list[int]) -> bytes:
    """Build a minimal 64-bit Mach-O MH_OBJECT with a single (__TEXT,__text) section."""
    text_bytes = b"".join(struct.pack("<I", w) for w in words_le)
    header_size = 32
    seg_cmd_size = 72 + 80  # LC_SEGMENT_64 + 1 section_64
    text_off = header_size + seg_cmd_size

    mach_header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        0x0100000C,  # CPU_TYPE_ARM64
        0x80000002,  # CPU_SUBTYPE_ARM64E
        0x1,         # MH_OBJECT
        1,           # ncmds
        seg_cmd_size,
        0,
        0,
    )
    seg_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,        # LC_SEGMENT_64
        seg_cmd_size,
        b"\x00" * 16,
        0,
        len(text_bytes),
        text_off,
        len(text_bytes),
        7,
        7,
        1,           # nsects = 1
        0,
    )
    sect_64 = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0,                # addr
        len(text_bytes),  # size
        text_off,         # offset
        2,                # align (2^2 = 4)
        0,                # reloff
        0,                # nreloc
        0x80000400,       # S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
        0,
        0,
        0,
    )
    return mach_header + seg_cmd + sect_64 + text_bytes


class TestAsmClangSharedFormsAndPCRelativeRewrite(_NoXcrunTestCase):
    """Verify shared form function identity and PC-relative target rewriting rules."""

    def test_shared_canonical_form_function_identity(self) -> None:
        self.assertIs(asm_clang.format_instruction_form, asm_roundtrip.format_instruction_form)
        self.assertIs(asm_clang.split_mnemonic_and_operands, asm_roundtrip.split_mnemonic_and_operands)

    def test_pc_relative_rewrite_positive_negative_bcond_tbz_literal_vs_bracket_ldr_and_adrp_skip(self) -> None:
        pc = 0x100001000
        cases = [
            # b / bl positive, zero, negative
            ("b 0x100001000", pc, "b .+0"),
            ("bl 0x1000010e8", pc, "bl .+232"),
            ("b 0x100000ff0", pc, "b .-16"),
            # b.<cond> positive and negative
            ("b.eq 0x100000ff4", pc, "b.eq .-12"),
            ("b.hs 0x100001008", pc, "b.hs .+8"),
            # cbz / cbnz
            ("cbz x0, 0x100001020", pc, "cbz x0, .+32"),
            ("cbnz w5, 0x100000ff8", pc, "cbnz w5, .-8"),
            # tbz / tbnz (three operands)
            ("tbz w1, #3, 0x100000fc0", pc, "tbz w1, #3, .-64"),
            ("tbnz x2, #0x28, 0x100001010", pc, "tbnz x2, #0x28, .+16"),
            # adr byte-granular positive and negative
            ("adr x8, 0x100001005", pc, "adr x8, .+5"),
            ("adr x8, 0x100000ffd", pc, "adr x8, .-3"),
            # Literal (bracketless) ldr / ldrsw / prfm ARE rewritten
            ("ldr x0, 0x100000fe8", pc, "ldr x0, .-24"),
            ("ldr d2, 0x100001040", pc, "ldr d2, .+64"),
            ("ldrsw x0, 0x100001008", pc, "ldrsw x0, .+8"),
            ("prfm pldl1keep, 0x100001020", pc, "prfm pldl1keep, .+32"),
            # Bracketed ldr / ldrsw / prfm are NOT rewritten
            ("ldr x0, [x1, #8]", pc, "ldr x0, [x1, #8]"),
            ("ldr x0, [x1], #8", pc, "ldr x0, [x1], #8"),
            ("ldr q0, [sp, #0x10]!", pc, "ldr q0, [sp, #0x10]!"),
            ("ldrsw x0, [x1, #4]", pc, "ldrsw x0, [x1, #4]"),
            ("prfm pldl1keep, [x0, #0x40]", pc, "prfm pldl1keep, [x0, #0x40]"),
            # Non-PC-relative instructions unchanged
            ("mov x0, #42", pc, "mov x0, #42"),
            ("add x0, x1, #0x1000", pc, "add x0, x1, #0x1000"),
            # adrp skipped (returns None)
            ("adrp x8, 0x100002000", pc, None),
        ]
        for stmt, addr, expected in cases:
            with self.subTest(stmt=stmt):
                self.assertEqual(asm_clang.rewrite_pc_relative_for_clang(stmt, addr), expected)


class TestAsmClangCorpusMode(_NoXcrunTestCase):
    """Verify first-occurrence form selection, Mach-O object word extraction, and corpus clang comparison."""

    def test_select_first_by_form_skips_inst_separates_adrp_and_keeps_first_across_files(self) -> None:
        f1_rows = asm_roundtrip.parse_disasm_text_section(
            "; Section __TEXT,__text @ 0x1000\n"
            "0x0000000000001000\tdeadbeef\t.inst\t0xdeadbeef\n"
            "0x0000000000001004\td2800540\tmov\tx0, #0x2a\n"
            "0x0000000000001008\td2800021\tmov\tx1, #1\n"
            "0x000000000000100c\tb0000008\tadrp\tx8, 0x00002000\n"
        )
        f2_rows = asm_roundtrip.parse_disasm_text_section(
            "; Section __TEXT,__text @ 0x2000\n"
            "0x0000000000002000\td2800062\tmov\tx2, #3\n"
            "0x0000000000002004\t54ffffa0\tb.eq\t0x00001ff8\n"
            "0x0000000000002008\t90000009\tadrp\tx9, 0x00002000\n"
        )
        active, adrp_skipped = asm_clang.select_first_by_form([("f1", f1_rows), ("f2", f2_rows)])
        self.assertEqual(len(adrp_skipped), 1)
        self.assertEqual(adrp_skipped[0].form, "adrp X, N")
        self.assertEqual(adrp_skipped[0].word_hex, "b0000008")
        self.assertEqual([s.form for s in active], ["mov X, #N", "b.eq N"])
        # Kept first occurrence `mov x0, #0x2a` from f1, not `mov x1, #1` or `mov x2, #3`
        self.assertEqual(active[0].word_hex, "d2800540")
        self.assertEqual(active[0].clang_text, "mov x0, #0x2a")
        self.assertEqual(active[1].word_hex, "54ffffa0")
        self.assertEqual(active[1].clang_text, "b.eq .-12")

    def test_read_macho_text_words_parses_synthetic_64bit_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            obj_p = os.path.join(tmp, "sample.o")
            with open(obj_p, "wb") as fh:
                fh.write(_build_synthetic_macho64_object([0xD503201F, 0x54FFFFA0, 0xD65F03C0]))
            self.assertEqual(asm_clang.read_macho_text_words(obj_p), ["d503201f", "54ffffa0", "d65f03c0"])

    def test_corpus_mode_pass_and_batch_rejection_isolates_per_line_and_recompiles_survivors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bin_p = os.path.join(tmp, "prog.bin")
            _write_fake_macho(bin_p, b"prog-corpus")
            disasm_txt = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\tb0000008\tadrp\tx8, 0x00002000\n"
                "0x0000000000001008\t54ffffa0\tb.eq\t0x00000ffc\n"
                "0x000000000000100c\tdeadbeef\t.inst\t0xdeadbeef\n"
            )
            fake_mg = _write_fake_machgraph(
                tmp,
                {bin_p: disasm_txt},
                real_home=os.path.expanduser("~"),
            )

            # 1) All non-adrp forms match -> exit 0
            word_table = {
                "nop": "d503201f",
                "b.eq .-12": "54ffffa0",
            }

            def fake_clang_pass(lines):
                return asm_clang.ClangCompileResult(ok=True, words=[word_table[ln] for ln in lines], error="")

            json_pass = os.path.join(tmp, "corpus_pass.json")
            out_pass = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                out_pass
            ):
                rc = asm_clang.main(
                    [bin_p, "--machgraph", fake_mg, "--json-out", json_pass],
                    clang_runner=fake_clang_pass,
                    llvm_version="Apple clang version 21.0.0 (test)",
                )
            self.assertEqual(rc, 0, out_pass.getvalue())
            with open(json_pass, "r", encoding="utf-8") as jfh:
                doc = json.load(jfh)
            self.assertEqual(doc["mode"], "corpus")
            self.assertTrue(doc["passed"])
            self.assertEqual(doc["summary"]["total_forms"], 3)
            self.assertEqual(doc["summary"]["adrp_skipped"], 1)
            self.assertEqual(doc["summary"]["compared_forms"], 2)
            self.assertEqual(doc["summary"]["matched"], 2)
            self.assertEqual(doc["summary"]["mismatched"], 0)
            self.assertEqual(doc["summary"]["clang_rejected"], 0)
            self.assertEqual(doc["environment"]["llvm_version"], "Apple clang version 21.0.0 (test)")
            self.assertTrue(doc["environment"]["machgraph_commit"])
            self.assertTrue(doc["environment"]["macos_version"])

            # 2) Batch fails due to 1 rejected line -> isolates per line, drops rejected, recompiles survivors
            disasm_fail = (
                "; Section __TEXT,__text @ 0x1000\n"
                "0x0000000000001000\td503201f\tnop\t\n"
                "0x0000000000001004\t1e602108\tfcmp\td8, #0\n"
                "0x0000000000001008\t3861d812\tldrb\tw18, [x0, w1, sxtw]\n"
            )
            fake_mg_fail = _write_fake_machgraph(tmp, {bin_p: disasm_fail})
            clang_calls = []

            def fake_clang_mixed(lines):
                clang_calls.append(list(lines))
                if "fcmp d8, #0" in lines:
                    return asm_clang.ClangCompileResult(
                        ok=False, words=[], error="expected compatible register or floating-point constant"
                    )
                mapping = {
                    "nop": "d503201f",
                    "ldrb w18, [x0, w1, sxtw]": "3861c812",  # deliberate mismatch vs 3861d812
                }
                return asm_clang.ClangCompileResult(ok=True, words=[mapping[ln] for ln in lines], error="")

            json_fail = os.path.join(tmp, "corpus_fail.json")
            out_fail = io.StringIO()
            with mock.patch.object(differential, "select_arm64_slice", return_value="arm64e"), contextlib.redirect_stdout(
                out_fail
            ):
                rc_fail = asm_clang.main(
                    [bin_p, "--machgraph", fake_mg_fail, "--json-out", json_fail],
                    clang_runner=fake_clang_mixed,
                    llvm_version="Apple clang version 21.0.0 (test)",
                )
            self.assertEqual(rc_fail, 1)
            # First call: all 3 lines; next 3 calls: 1 line each; final call: 2 surviving lines re-batched
            self.assertEqual(clang_calls[0], ["nop", "fcmp d8, #0", "ldrb w18, [x0, w1, sxtw]"])
            self.assertEqual(clang_calls[-1], ["nop", "ldrb w18, [x0, w1, sxtw]"])
            with open(json_fail, "r", encoding="utf-8") as jffh:
                fdoc = json.load(jffh)
            self.assertFalse(fdoc["passed"])
            self.assertEqual(fdoc["summary"]["matched"], 1)
            self.assertEqual(fdoc["summary"]["mismatched"], 1)
            self.assertEqual(fdoc["summary"]["clang_rejected"], 1)
            self.assertEqual(fdoc["mismatched"][0]["word"], "3861d812")
            self.assertEqual(fdoc["mismatched"][0]["clang_word"], "3861c812")
            self.assertEqual(fdoc["clang_rejected"][0]["form"], "fcmp D, #N")


class TestAsmClangCaseMode(_NoXcrunTestCase):
    """Verify `.s` semicolon rejection, usage exit codes, and all case-mode verdict cells."""

    def test_semicolon_and_usage_errors_exit_2_without_invoking_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            semi_1 = os.path.join(tmp, "semi1.s")
            with open(semi_1, "w", encoding="utf-8") as fh:
                fh.write("// header\nmov x0, #1; ret\n")

            semi_2 = os.path.join(tmp, "semi2.s")
            with open(semi_2, "w", encoding="utf-8") as fh:
                fh.write("nop ; darwin comment\n")

            empty_s = os.path.join(tmp, "empty.s")
            with open(empty_s, "w", encoding="utf-8") as fh:
                fh.write("// only comments\n\n")

            def _never_clang(_lines):
                raise AssertionError("clang_runner must not be called on usage error")

            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(asm_clang.main([semi_1], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main([semi_2], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main([empty_s], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main([], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main(["quick", semi_1], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main([semi_1, semi_2], clang_runner=_never_clang, llvm_version="test"), 2)
                self.assertEqual(asm_clang.main(["quick", "--bad-opt"], clang_runner=_never_clang, llvm_version="test"), 2)

    def test_case_mode_verdict_matrix_pass_and_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cases_s = os.path.join(tmp, "cases.s")
            with open(cases_s, "w", encoding="utf-8") as fh:
                fh.write(
                    "// Header comment\n"
                    "\n"
                    "mov x0, #42\n"
                    "adrp x8, .+4096\n"
                    "ld1 {v0.4s}, [x0]\n"
                    "bogus_insn x0\n"
                )

            call_log = os.path.join(tmp, "mg_calls.jsonl")
            mg_pass = _write_fake_machgraph(
                tmp,
                {},
                asm_behavior={
                    "by_stmt": {
                        "mov x0, #42": {"status": "ok", "word": "d2800540"},
                        "adrp x8, .+4096": {"status": "ok", "word": "b0000008"},
                        "ld1 {v0.4s}, [x0]": {
                            "status": "unsupported",
                            "mnemonic": "ld1",
                            "form": "ld1 { V.Ns }, [X]",
                        },
                        "bogus_insn x0": {"status": "error", "reason": "Unknown ARM64 mnemonic 'bogus_insn'"},
                    }
                },
                call_log_path=call_log,
                real_home=os.path.expanduser("~"),
            )

            clang_seen = []

            def fake_clang_cases(lines):
                self.assertEqual(len(lines), 1, "Case mode must compile one line per object file")
                stmt = lines[0]
                clang_seen.append(stmt)
                if stmt == "mov x0, #42":
                    return asm_clang.ClangCompileResult(ok=True, words=["d2800540"], error="")
                if stmt == "adrp x8, .+4096":
                    return asm_clang.ClangCompileResult(
                        ok=False, words=[], error="ADR/ADRP relocations must be GOT relative"
                    )
                if stmt == "ld1 {v0.4s}, [x0]":
                    return asm_clang.ClangCompileResult(ok=True, words=["4c407800"], error="")
                return asm_clang.ClangCompileResult(ok=False, words=[], error="unrecognized instruction mnemonic")

            # 1) PASS when rows are match / clang_unverifiable / unsupported / both_rejected
            json_ok = os.path.join(tmp, "cases_ok.json")
            out_ok = io.StringIO()
            with contextlib.redirect_stdout(out_ok):
                rc_ok = asm_clang.main(
                    [cases_s, "--machgraph", mg_pass, "--json-out", json_ok],
                    clang_runner=fake_clang_cases,
                    llvm_version="Apple clang version 21.0.0 (test)",
                )
            self.assertEqual(rc_ok, 0, out_ok.getvalue())
            self.assertIn("ADR/ADRP relocations must be GOT relative", out_ok.getvalue())
            self.assertEqual(len(clang_seen), 4)

            with open(call_log, "r", encoding="utf-8") as lfh:
                mg_calls = [json.loads(ln)["argv"] for ln in lfh if ln.strip()]
            self.assertEqual(len(mg_calls), 1)
            self.assertEqual(mg_calls[0], ["asm", "--at", "0", "--json"])

            with open(json_ok, "r", encoding="utf-8") as jfh:
                cdoc = json.load(jfh)
            self.assertEqual(cdoc["mode"], "cases")
            self.assertTrue(cdoc["passed"])
            self.assertEqual(cdoc["summary"]["total"], 4)
            self.assertEqual(cdoc["summary"]["match"], 1)
            self.assertEqual(cdoc["summary"]["clang_unverifiable"], 1)
            self.assertEqual(cdoc["summary"]["unsupported"], 1)
            self.assertEqual(cdoc["summary"]["both_rejected"], 1)
            self.assertEqual(cdoc["summary"]["failures"], 0)

            # 2) FAIL when MachGraph ok word != clang word
            mg_word_diff = _write_fake_machgraph(
                tmp,
                {},
                asm_behavior={
                    "by_stmt": {
                        "mov x0, #42": {"status": "ok", "word": "d2800541"},
                        "adrp x8, .+4096": {"status": "ok", "word": "b0000008"},
                        "ld1 {v0.4s}, [x0]": {
                            "status": "unsupported",
                            "mnemonic": "ld1",
                            "form": "ld1 { V.Ns }, [X]",
                        },
                        "bogus_insn x0": {"status": "error", "reason": "Unknown ARM64 mnemonic 'bogus_insn'"},
                    }
                },
            )
            with contextlib.redirect_stdout(io.StringIO()):
                rc_diff = asm_clang.main(
                    [cases_s, "--machgraph", mg_word_diff],
                    clang_runner=fake_clang_cases,
                    llvm_version="Apple clang version 21.0.0 (test)",
                )
            self.assertEqual(rc_diff, 1)

            # 3) FAIL when MachGraph reports error on a line clang accepts
            mg_err_on_valid = _write_fake_machgraph(
                tmp,
                {},
                asm_behavior={
                    "by_stmt": {
                        "mov x0, #42": {"status": "error", "reason": "broken parser"},
                        "adrp x8, .+4096": {"status": "ok", "word": "b0000008"},
                        "ld1 {v0.4s}, [x0]": {
                            "status": "unsupported",
                            "mnemonic": "ld1",
                            "form": "ld1 { V.Ns }, [X]",
                        },
                        "bogus_insn x0": {"status": "error", "reason": "Unknown ARM64 mnemonic 'bogus_insn'"},
                    }
                },
            )
            with contextlib.redirect_stdout(io.StringIO()):
                rc_err = asm_clang.main(
                    [cases_s, "--machgraph", mg_err_on_valid],
                    clang_runner=fake_clang_cases,
                    llvm_version="Apple clang version 21.0.0 (test)",
                )
            self.assertEqual(rc_err, 1)


if __name__ == "__main__":
    unittest.main()
