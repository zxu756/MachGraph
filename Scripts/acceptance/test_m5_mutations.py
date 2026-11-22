#!/usr/bin/env python3
"""Unit tests for Scripts/acceptance/m5-mutations.sh and M5 mutation specs.

Run with:
  python3 -I Scripts/acceptance/test_m5_mutations.py
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
M5_MUTATIONS_SH = SCRIPT_DIR / "m5-mutations.sh"
MUTATIONS_DIR = SCRIPT_DIR / "mutations"

EXPECTED_SPEC_IDS = ("1a", "1b", "2a", "2b", "2c", "2d", "2e", "2f")


class TestM5MutationsSuite(unittest.TestCase):
    def test_script_exists_and_is_executable(self) -> None:
        self.assertTrue(
            M5_MUTATIONS_SH.is_file(),
            f"Missing M5 mutation runner: {M5_MUTATIONS_SH.name}",
        )
        self.assertTrue(
            os.access(M5_MUTATIONS_SH, os.X_OK),
            f"M5 mutation runner is not executable: {M5_MUTATIONS_SH.name}",
        )

    def test_all_eight_m5_specs_exist_and_match_repo_exactly_once(self) -> None:
        self.assertTrue(M5_MUTATIONS_SH.is_file(), "Missing m5-mutations.sh")
        res = subprocess.run(
            ["bash", str(M5_MUTATIONS_SH), "--verify-specs"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"--verify-specs failed (rc={res.returncode}):\nstdout={res.stdout}\nstderr={res.stderr}",
        )
        spec_files = sorted(MUTATIONS_DIR.glob("m5-*.json"))
        self.assertGreaterEqual(len(spec_files), 8)
        found_ids = []
        for sf in spec_files:
            doc = json.loads(sf.read_text(encoding="utf-8"))
            found_ids.append(doc["id"])
            self.assertTrue(doc.get("replacements"), f"Empty replacements in {sf.name}")
            for rep in doc["replacements"]:
                target_path = REPO_ROOT / rep["file"]
                self.assertTrue(target_path.is_file(), f"Missing target {rep['file']}")
                src = target_path.read_text(encoding="utf-8")
                self.assertEqual(
                    src.count(rep["old"]),
                    1,
                    f"Expected exact-once match for spec {doc['id']} in {rep['file']}",
                )
        for req_id in EXPECTED_SPEC_IDS:
            self.assertIn(req_id, found_ids, f"Missing required mutation ID {req_id}")

    def test_exact_once_patcher_rejects_missing_and_duplicate_targets(self) -> None:
        self.assertTrue(M5_MUTATIONS_SH.is_file(), "Missing m5-mutations.sh")
        with tempfile.TemporaryDirectory(prefix="test-m5-mut-patcher-") as tmp:
            tmp_p = Path(tmp)
            repo_dir = tmp_p / "repo"
            repo_dir.mkdir()
            sample = repo_dir / "Sample.swift"

            spec_path = tmp_p / "spec.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "id": "test-1",
                        "description": "unit test spec",
                        "replacements": [
                            {
                                "file": "Sample.swift",
                                "old": "package enum Foo {}",
                                "new": "public enum Foo {}",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            # Case 1: 0 occurrences -> must fail non-zero and leave file untouched
            orig_zero = "internal enum Bar {}\n"
            sample.write_text(orig_zero, encoding="utf-8")
            r0 = subprocess.run(
                ["bash", str(M5_MUTATIONS_SH), "--apply-spec", str(spec_path), str(repo_dir)],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            self.assertNotEqual(r0.returncode, 0, "0 occurrences must fail non-zero")
            self.assertIn("0", r0.stdout + r0.stderr)
            self.assertEqual(sample.read_text(encoding="utf-8"), orig_zero)

            # Case 2: 2 occurrences -> must fail non-zero and NOT silently patch first match
            orig_two = "package enum Foo {}\npackage enum Foo {}\n"
            sample.write_text(orig_two, encoding="utf-8")
            r2 = subprocess.run(
                ["bash", str(M5_MUTATIONS_SH), "--apply-spec", str(spec_path), str(repo_dir)],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            self.assertNotEqual(r2.returncode, 0, "2 occurrences must fail non-zero")
            self.assertIn("2", r2.stdout + r2.stderr)
            self.assertEqual(sample.read_text(encoding="utf-8"), orig_two)

            # Case 3: Exactly 1 occurrence -> apply succeeds, reverse restores byte-for-byte
            orig_one = "// header\npackage enum Foo {}\n// footer\n"
            sample.write_text(orig_one, encoding="utf-8")
            r1 = subprocess.run(
                ["bash", str(M5_MUTATIONS_SH), "--apply-spec", str(spec_path), str(repo_dir)],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            self.assertEqual(r1.returncode, 0, f"apply failed: {r1.stderr}")
            self.assertEqual(
                sample.read_text(encoding="utf-8"),
                "// header\npublic enum Foo {}\n// footer\n",
            )

            rev = subprocess.run(
                ["bash", str(M5_MUTATIONS_SH), "--reverse-spec", str(spec_path), str(repo_dir)],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            self.assertEqual(rev.returncode, 0, f"reverse failed: {rev.stderr}")
            self.assertEqual(sample.read_text(encoding="utf-8"), orig_one)


if __name__ == "__main__":
    unittest.main()
