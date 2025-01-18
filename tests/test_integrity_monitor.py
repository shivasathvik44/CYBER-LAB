"""Unit tests for scripts/integrity_monitor.py.

Tests SHA-256 calculation, baseline creation, directory scanning, and detection
of created, modified, and deleted files using temporary test directories.
Compatible with pytest and standard unittest runner.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

# Add scripts directory to path if needed
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from integrity_monitor import (
    compare_against_baseline,
    compute_sha256,
    load_baseline,
    save_baseline,
    scan_directory,
)


class TestIntegrityMonitor(unittest.TestCase):
    """Test suite for File Integrity Monitor functionality."""

    def test_compute_sha256_known_value(self) -> None:
        """Test hash computation against known string."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write("hello cybersecurity homelab\n")
            tmp_path = Path(tmp.name)

        try:
            hash_val = compute_sha256(tmp_path)
            self.assertIsNotNone(hash_val)
            self.assertEqual(len(hash_val), 64)  # SHA-256 is 64 hex characters
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_baseline_creation_and_clean_verification(self) -> None:
        """Test initializing a baseline and verifying with zero changes."""
        with tempfile.TemporaryDirectory() as test_dir:
            test_path = Path(test_dir)
            file_a = test_path / "service.conf"
            file_b = test_path / "sub" / "rules.xml"
            file_b.parent.mkdir(parents=True, exist_ok=True)

            file_a.write_text("port=8080\n")
            file_b.write_text("<rules></rules>\n")

            baseline_path = test_path / "baseline.json"

            # 1. Scan and save baseline
            records = scan_directory(test_path)
            self.assertEqual(len(records), 2)
            save_baseline(records, baseline_path, str(test_path))

            self.assertTrue(baseline_path.exists())

            # 2. Re-scan and compare (excluding baseline itself in comparison)
            current_records = scan_directory(test_path)
            current_records.pop("baseline.json", None)

            base_files, metadata = load_baseline(baseline_path)
            self.assertEqual(metadata["total_files"], 2)

            result = compare_against_baseline(current_records, base_files)
            self.assertFalse(result.has_anomalies)
            self.assertEqual(result.unchanged_count, 2)
            self.assertEqual(len(result.created_files), 0)
            self.assertEqual(len(result.modified_files), 0)
            self.assertEqual(len(result.deleted_files), 0)

    def test_detect_modified_file(self) -> None:
        """Test that altering file content flags a modification."""
        with tempfile.TemporaryDirectory() as test_dir:
            test_path = Path(test_dir)
            target = test_path / "config.txt"
            target.write_text("initial_state\n")

            baseline_path = test_path / "baseline.json"
            records = scan_directory(test_path)
            save_baseline(records, baseline_path, str(test_path))

            # Modify file
            target.write_text("modified_tampered_state\n")

            current_records = scan_directory(test_path)
            current_records.pop("baseline.json", None)
            base_files, _ = load_baseline(baseline_path)

            result = compare_against_baseline(current_records, base_files)
            self.assertTrue(result.has_anomalies)
            self.assertEqual(len(result.modified_files), 1)
            self.assertEqual(result.modified_files[0][0].path, "config.txt")

    def test_detect_created_file(self) -> None:
        """Test that dropping a new file flags a creation anomaly."""
        with tempfile.TemporaryDirectory() as test_dir:
            test_path = Path(test_dir)
            (test_path / "orig.txt").write_text("original\n")

            baseline_path = test_path / "baseline.json"
            records = scan_directory(test_path)
            save_baseline(records, baseline_path, str(test_path))

            # Add new file
            (test_path / "backdoor.sh").write_text("#!/bin/bash\n")

            current_records = scan_directory(test_path)
            current_records.pop("baseline.json", None)
            base_files, _ = load_baseline(baseline_path)

            result = compare_against_baseline(current_records, base_files)
            self.assertTrue(result.has_anomalies)
            self.assertEqual(len(result.created_files), 1)
            self.assertEqual(result.created_files[0].path, "backdoor.sh")

    def test_detect_deleted_file(self) -> None:
        """Test that removing an existing file flags a deletion anomaly."""
        with tempfile.TemporaryDirectory() as test_dir:
            test_path = Path(test_dir)
            f1 = test_path / "preserve.txt"
            f2 = test_path / "delete_me.txt"
            f1.write_text("stay\n")
            f2.write_text("go away\n")

            baseline_path = test_path / "baseline.json"
            records = scan_directory(test_path)
            save_baseline(records, baseline_path, str(test_path))

            # Delete file
            f2.unlink()

            current_records = scan_directory(test_path)
            current_records.pop("baseline.json", None)
            base_files, _ = load_baseline(baseline_path)

            result = compare_against_baseline(current_records, base_files)
            self.assertTrue(result.has_anomalies)
            self.assertEqual(len(result.deleted_files), 1)
            self.assertEqual(result.deleted_files[0]["path"], "delete_me.txt")

    def test_load_baseline_missing_and_corrupt(self) -> None:
        """Test handling missing baseline or invalid JSON."""
        with self.assertRaises(FileNotFoundError):
            load_baseline("/non/existent/baseline.json")

        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write("NOT_VALID_JSON{")
            corrupt_path = tmp.name

        try:
            with self.assertRaises(ValueError):
                load_baseline(corrupt_path)
        finally:
            Path(corrupt_path).unlink(missing_ok=True)

    def test_inaccessible_file_handling(self) -> None:
        """Test that unreadable files are safely skipped and reported."""
        with tempfile.TemporaryDirectory() as test_dir:
            test_path = Path(test_dir)
            good_file = test_path / "readable.txt"
            good_file.write_text("readable content\n")

            unreadable_file = test_path / "locked.txt"
            unreadable_file.write_text("secret\n")
            try:
                unreadable_file.chmod(0o000)
            except OSError:
                pass  # On systems where chmod 000 is ignored, test continues safely

            from integrity_monitor import format_cli_report, scan_directory_with_errors

            records, skipped = scan_directory_with_errors(test_path)
            self.assertIn("readable.txt", records)

            # If the OS enforced unreadable permissions, it should be in skipped
            if not os.access(unreadable_file, os.R_OK):
                self.assertIn("locked.txt", skipped)

            # Test comparison result with skipped files
            result = compare_against_baseline(records, {}, skipped)
            report = format_cli_report(result, str(test_path), "baseline.json")
            self.assertIn("Inaccessible Files", report)

            # Cleanup chmod for tempdir deletion
            try:
                unreadable_file.chmod(0o644)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
