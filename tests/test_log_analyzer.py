"""Unit tests for scripts/log_analyzer.py.

Tests parsing of authentication log formats, aggregation by IP and user,
threshold filtering, malformed line handling, and JSON serialization.
Compatible with pytest and standard unittest runner.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

# Add scripts directory to path if needed
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from log_analyzer import (
    analyze_auth_log,
    export_json_report,
    format_text_report,
    parse_log_line,
)


class TestLogAnalyzer(unittest.TestCase):
    """Test suite for authentication log parsing and analysis."""

    def setUp(self) -> None:
        """Create sample log content fixtures."""
        self.valid_log_lines = [
            "Nov 14 10:00:01 endpoint sshd[1001]: Failed password for invalid user admin from 192.168.1.100 port 55123 ssh2\n",
            "Nov 14 10:00:02 endpoint sshd[1002]: Failed password for invalid user admin from 192.168.1.100 port 55124 ssh2\n",
            "Nov 14 10:00:03 endpoint sshd[1003]: Failed password for root from 192.168.1.100 port 55125 ssh2\n",
            "Nov 14 10:00:04 endpoint sshd[1004]: Failed password for user1 from 10.0.0.50 port 44100 ssh2\n",
            "Nov 14 10:00:05 endpoint sshd[1005]: Accepted password for deploy from 10.0.0.50 port 44101 ssh2\n",
            "Nov 14 10:00:06 endpoint systemd[1]: Started Session 42 of user root.\n",  # Non-ssh line
            "   \n",  # Empty whitespace line
            "GARBAGE_LOG_LINE_WITH_NO_MATCHING_PATTERNS\n",  # Malformed line
        ]

    def test_parse_log_line_valid_failed_password(self) -> None:
        """Test parsing a standard SSH failed password line."""
        line = "Nov 14 10:00:01 endpoint sshd[1001]: Failed password for invalid user admin from 192.168.1.100 port 55123 ssh2"
        res = parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res.source_ip, "192.168.1.100")
        self.assertEqual(res.user, "admin")
        self.assertEqual(res.port, "55123")

    def test_parse_log_line_pam_failure(self) -> None:
        """Test parsing PAM authentication failure format."""
        line = "Nov 14 10:05:00 endpoint sshd[2000]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.20.0.99 user=root"
        res = parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res.source_ip, "172.20.0.99")
        self.assertEqual(res.user, "root")

    def test_parse_log_line_non_matching(self) -> None:
        """Test that accepted logins, systemd messages, or random text return None."""
        accepted = "Nov 14 10:00:05 endpoint sshd[1005]: Accepted password for deploy from 10.0.0.50 port 44101 ssh2"
        self.assertIsNone(parse_log_line(accepted))

        random_line = "Nov 14 10:00:06 endpoint kernel: [123.456] eth0: link up"
        self.assertIsNone(parse_log_line(random_line))

        self.assertIsNone(parse_log_line(""))

    def test_analyze_auth_log_threshold_filtering(self) -> None:
        """Test aggregation and threshold filtering."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(self.valid_log_lines)
            tmp_path = tmp.name

        try:
            # Threshold 3: 192.168.1.100 has 3 failures -> flagged
            # 10.0.0.50 has 1 failure -> not flagged
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=3)
            self.assertEqual(total_lines, 8)
            self.assertEqual(total_failures, 4)
            self.assertIn("192.168.1.100", flagged)
            self.assertNotIn("10.0.0.50", flagged)
            self.assertEqual(flagged["192.168.1.100"].total_failures, 3)
            self.assertEqual(flagged["192.168.1.100"].targeted_users["admin"], 2)
            self.assertEqual(flagged["192.168.1.100"].targeted_users["root"], 1)

            # Threshold 4: Nothing should be flagged
            flagged_high, _, _ = analyze_auth_log(tmp_path, threshold=4)
            self.assertEqual(len(flagged_high), 0)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_analyze_auth_log_missing_file_raises_error(self) -> None:
        """Test that querying a non-existent log file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            analyze_auth_log("/non/existent/path/to/log.txt", threshold=5)

    def test_format_text_and_json_reports(self) -> None:
        """Test report generation in text and JSON formats."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(self.valid_log_lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=2)
            text_rep = format_text_report(flagged, tmp_path, 2, total_lines, total_failures)
            self.assertIn("192.168.1.100", text_rep)
            self.assertIn("Threshold Filter", text_rep)

            json_rep = export_json_report(flagged, tmp_path, 2, total_lines, total_failures)
            self.assertEqual(json_rep["metadata"]["suspicious_ip_count"], 1)
            self.assertEqual(json_rep["suspicious_ips"][0]["source_ip"], "192.168.1.100")
        finally:
            Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
