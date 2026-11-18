#!/usr/bin/env python3
"""Unit tests for MachGraph M2 assembler acceptance harnesses (`known-mnemonics.py`)."""

import contextlib
import io
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


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


if __name__ == "__main__":
    unittest.main()
