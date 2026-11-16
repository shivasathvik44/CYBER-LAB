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
    parse_success_line,
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

    def test_parse_success_line(self) -> None:
        """Test parsing accepted SSH authentication lines."""
        pwd_line = "Nov 14 10:00:05 endpoint sshd[1005]: Accepted password for deploy from 10.0.0.50 port 44101 ssh2"
        res_pwd = parse_success_line(pwd_line)
        self.assertIsNotNone(res_pwd)
        self.assertEqual(res_pwd.user, "deploy")
        self.assertEqual(res_pwd.source_ip, "10.0.0.50")
        self.assertEqual(res_pwd.auth_method, "password")

        key_line = "Nov 14 10:00:06 endpoint sshd[1006]: Accepted publickey for ubuntu from 192.168.1.50 port 52123 ssh2: RSA SHA256:abc"
        res_key = parse_success_line(key_line)
        self.assertIsNotNone(res_key)
        self.assertEqual(res_key.user, "ubuntu")
        self.assertEqual(res_key.auth_method, "publickey")

        failed_line = "Nov 14 10:00:01 endpoint sshd[1001]: Failed password for admin from 192.168.1.100 port 55123 ssh2"
        self.assertIsNone(parse_success_line(failed_line))

    def test_single_failed_login_below_threshold(self) -> None:
        """Test that single isolated failure is not flagged when below threshold."""
        lines = [
            "Nov 14 10:00:01 endpoint sshd[1001]: Failed password for user1 from 192.0.2.10 port 40001 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=3)
            self.assertEqual(total_lines, 1)
            self.assertEqual(total_failures, 1)
            self.assertEqual(len(flagged), 0)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_repeated_failures_ssh_brute_force(self) -> None:
        """Test that repeated failures >= threshold are flagged as SSH_BRUTE_FORCE."""
        lines = [
            f"Nov 14 10:00:0{i} endpoint sshd[100{i}]: Failed password for root from 198.51.100.10 port 5000{i} ssh2\n"
            for i in range(1, 6)
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=5)
            self.assertIn("198.51.100.10", flagged)
            summary = flagged["198.51.100.10"]
            self.assertEqual(summary.total_failures, 5)
            self.assertIn("SSH_BRUTE_FORCE", summary.detections)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_password_spraying_detection(self) -> None:
        """Test detection of password spraying across multiple usernames from a single IP."""
        users = ["alice", "bob", "carol", "dave"]
        lines = [
            f"Nov 14 10:10:0{i} endpoint sshd[200{i}]: Failed password for {u} from 203.0.113.45 port 5100{i} ssh2\n"
            for i, u in enumerate(users, start=1)
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            # threshold=5 (failures=4 is below threshold), but spray_threshold=3 (users=4 >= 3)
            flagged, _, _ = analyze_auth_log(tmp_path, threshold=5, spray_threshold=3)
            self.assertIn("203.0.113.45", flagged)
            summary = flagged["203.0.113.45"]
            self.assertTrue(summary.password_spray)
            self.assertIn("PASSWORD_SPRAYING", summary.detections)
            self.assertEqual(len(summary.targeted_users), 4)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_success_after_repeated_failures(self) -> None:
        """Test detection of successful login following repeated failures (potential compromise)."""
        lines = [
            "Nov 14 10:20:01 endpoint sshd[3001]: Failed password for deploy from 198.51.100.77 port 41001 ssh2\n",
            "Nov 14 10:20:02 endpoint sshd[3002]: Failed password for deploy from 198.51.100.77 port 41002 ssh2\n",
            "Nov 14 10:20:05 endpoint sshd[3003]: Accepted password for deploy from 198.51.100.77 port 41003 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, _, _ = analyze_auth_log(tmp_path, threshold=2)
            self.assertIn("198.51.100.77", flagged)
            summary = flagged["198.51.100.77"]
            self.assertTrue(summary.success_after_failure)
            self.assertIn("SUCCESS_AFTER_FAILURES", summary.detections)
            self.assertEqual(summary.total_successes, 1)
            self.assertEqual(summary.total_failures, 2)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_multiple_attacker_ips_aggregated_correctly(self) -> None:
        """Test that multiple distinct source IPs are tracked independently."""
        lines = [
            "Nov 14 10:00:01 endpoint sshd[101]: Failed password for root from 198.51.100.1 port 5001 ssh2\n",
            "Nov 14 10:00:02 endpoint sshd[102]: Failed password for root from 198.51.100.1 port 5002 ssh2\n",
            "Nov 14 10:00:03 endpoint sshd[103]: Failed password for admin from 198.51.100.2 port 6001 ssh2\n",
            "Nov 14 10:00:04 endpoint sshd[104]: Failed password for admin from 198.51.100.2 port 6002 ssh2\n",
            "Nov 14 10:00:05 endpoint sshd[105]: Failed password for admin from 198.51.100.2 port 6003 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=3)
            self.assertEqual(total_lines, 5)
            self.assertEqual(total_failures, 5)
            # 198.51.100.1 had 2 failures (< 3)
            self.assertNotIn("198.51.100.1", flagged)
            # 198.51.100.2 had 3 failures (>= 3)
            self.assertIn("198.51.100.2", flagged)
            self.assertEqual(flagged["198.51.100.2"].total_failures, 3)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_threshold_tuning_variations(self) -> None:
        """Test behavior across thresholds 3, 5, and 10."""
        lines = []
        for i in range(4):
            lines.append(f"Nov 14 11:00:{i:02d} endpoint sshd[{100+i}]: Failed password for root from 192.0.2.1 port 500{i} ssh2\n")
        for i in range(7):
            lines.append(f"Nov 14 11:05:{i:02d} endpoint sshd[{200+i}]: Failed password for root from 192.0.2.2 port 600{i} ssh2\n")
        for i in range(12):
            lines.append(f"Nov 14 11:10:{i:02d} endpoint sshd[{300+i}]: Failed password for root from 192.0.2.3 port 700{i} ssh2\n")

        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            f3, _, _ = analyze_auth_log(tmp_path, threshold=3)
            self.assertEqual(set(f3.keys()), {"192.0.2.1", "192.0.2.2", "192.0.2.3"})

            f5, _, _ = analyze_auth_log(tmp_path, threshold=5)
            self.assertEqual(set(f5.keys()), {"192.0.2.2", "192.0.2.3"})

            f10, _, _ = analyze_auth_log(tmp_path, threshold=10)
            self.assertEqual(set(f10.keys()), {"192.0.2.3"})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_empty_log_file(self) -> None:
        """Test handling of completely empty log file."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=3)
            self.assertEqual(total_lines, 0)
            self.assertEqual(total_failures, 0)
            self.assertEqual(len(flagged), 0)

            rep = format_text_report(flagged, tmp_path, 3, 0, 0)
            self.assertIn("No source IP exceeded threat criteria", rep)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_malformed_and_mixed_log_lines(self) -> None:
        """Test that malformed lines, cron events, sudo sessions are skipped safely."""
        lines = [
            "Nov 14 12:00:01 endpoint CRON[5500]: (root) CMD (/usr/local/bin/backup.sh)\n",
            "Nov 14 12:00:02 endpoint sudo: capslock : TTY=pts/0 ; PWD=/home/capslock ; USER=root ; COMMAND=/bin/ls\n",
            "This is completely arbitrary corrupted text without any structure\n",
            "   \n",
            "Nov 14 12:00:03 endpoint sshd[5501]: Corrupted sshd log without standard fields\n",
            "Nov 14 12:00:04 endpoint sshd[5502]: Failed password for testuser from 192.0.2.55 port 22222 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=1)
            self.assertEqual(total_lines, 6)
            self.assertEqual(total_failures, 1)
            self.assertIn("192.0.2.55", flagged)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_success_after_repeated_failures_detected_at_threshold_10(self) -> None:
        """Prove that 5 failures followed by a login is detected even when threshold=10."""
        lines = [
            f"Nov 16 10:20:0{i} endpoint sshd[{1400+i}]: Failed password for ubuntu from 198.51.100.77 port {48100+i} ssh2\n"
            for i in range(1, 6)
        ] + [
            "Nov 16 10:20:18 endpoint sshd[1406]: Accepted password for ubuntu from 198.51.100.77 port 48106 ssh2\n"
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            # Set high brute-force threshold of 10
            flagged, _, _ = analyze_auth_log(tmp_path, threshold=10, repeat_failure_threshold=2)
            self.assertIn("198.51.100.77", flagged)
            summary = flagged["198.51.100.77"]
            # Volumetric brute force not flagged (5 < 10)
            self.assertNotIn("SSH_BRUTE_FORCE", summary.detections)
            # Compromise warning IS flagged (5 failures >= repeat threshold 2)
            self.assertIn("SUCCESS_AFTER_FAILURES", summary.detections)
            self.assertTrue(summary.success_after_failure)
            self.assertEqual(summary.total_failures, 5)
            self.assertEqual(summary.total_successes, 1)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_password_spraying_triggers_without_reaching_brute_force_threshold(self) -> None:
        """Prove that password spraying triggers on account count even when failures < threshold."""
        users = ["user1", "user2", "user3", "user4"]
        lines = [
            f"Nov 16 09:15:0{i} endpoint sshd[{1200+i}]: Failed password for invalid user {u} from 203.0.113.45 port {55100+i} ssh2\n"
            for i, u in enumerate(users, start=1)
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            # threshold=10 (failures=4 < 10), spray_threshold=3 (users=4 >= 3)
            flagged, _, _ = analyze_auth_log(tmp_path, threshold=10, spray_threshold=3)
            self.assertIn("203.0.113.45", flagged)
            summary = flagged["203.0.113.45"]
            self.assertNotIn("SSH_BRUTE_FORCE", summary.detections)
            self.assertIn("PASSWORD_SPRAYING", summary.detections)
            self.assertTrue(summary.password_spray)
            self.assertEqual(len(summary.targeted_users), 4)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_normal_single_failed_login_does_not_generate_compromise_alert(self) -> None:
        """Prove that a normal single typo (1 failure then success) is suppressed."""
        lines = [
            "Nov 16 08:14:22 endpoint sshd[1050]: Failed password for dev_alice from 192.168.1.99 port 54101 ssh2\n",
            "Nov 16 08:14:35 endpoint sshd[1052]: Accepted password for dev_alice from 192.168.1.99 port 54102 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(tmp_path, threshold=5, repeat_failure_threshold=2)
            self.assertEqual(total_lines, 2)
            self.assertEqual(total_failures, 1)
            # Not flagged under brute force, spray, or compromise
            self.assertEqual(len(flagged), 0)
            self.assertNotIn("192.168.1.99", flagged)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_detection_reasons_accurately_represented_in_json(self) -> None:
        """Prove that detection reasons and metadata are accurately populated in JSON report."""
        lines = [
            # High volume brute force
            "Nov 16 09:00:01 endpoint sshd[101]: Failed password for root from 198.51.100.10 port 5001 ssh2\n",
            "Nov 16 09:00:02 endpoint sshd[102]: Failed password for root from 198.51.100.10 port 5002 ssh2\n",
            "Nov 16 09:00:03 endpoint sshd[103]: Failed password for root from 198.51.100.10 port 5003 ssh2\n",
            # Password spraying
            "Nov 16 09:10:01 endpoint sshd[201]: Failed password for user1 from 203.0.113.45 port 6001 ssh2\n",
            "Nov 16 09:10:02 endpoint sshd[202]: Failed password for user2 from 203.0.113.45 port 6002 ssh2\n",
            "Nov 16 09:10:03 endpoint sshd[203]: Failed password for user3 from 203.0.113.45 port 6003 ssh2\n",
            # Success after repeated failures
            "Nov 16 09:20:01 endpoint sshd[301]: Failed password for admin from 198.51.100.77 port 7001 ssh2\n",
            "Nov 16 09:20:02 endpoint sshd[302]: Failed password for admin from 198.51.100.77 port 7002 ssh2\n",
            "Nov 16 09:20:05 endpoint sshd[303]: Accepted password for admin from 198.51.100.77 port 7003 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            flagged, total_lines, total_failures = analyze_auth_log(
                tmp_path, threshold=3, spray_threshold=3, repeat_failure_threshold=2
            )
            json_rep = export_json_report(
                flagged, tmp_path, 3, total_lines, total_failures, spray_threshold=3, repeat_failure_threshold=2
            )

            self.assertEqual(json_rep["metadata"]["threshold"], 3)
            self.assertEqual(json_rep["metadata"]["spray_threshold"], 3)
            self.assertEqual(json_rep["metadata"]["repeat_failure_threshold"], 2)
            self.assertEqual(json_rep["metadata"]["suspicious_ip_count"], 3)
            self.assertEqual(json_rep["metadata"]["compromise_warnings_count"], 1)
            self.assertEqual(json_rep["metadata"]["password_spray_count"], 1)

            ip_map = {ip["source_ip"]: ip for ip in json_rep["suspicious_ips"]}

            # 198.51.100.10: brute force reason
            self.assertIn("SSH_BRUTE_FORCE", ip_map["198.51.100.10"]["detections"])
            self.assertTrue(any("reached brute-force threshold" in r for r in ip_map["198.51.100.10"]["detection_reasons"]))

            # 203.0.113.45: spray reason
            self.assertIn("PASSWORD_SPRAYING", ip_map["203.0.113.45"]["detections"])
            self.assertTrue(any("distinct usernames" in r for r in ip_map["203.0.113.45"]["detection_reasons"]))

            # 198.51.100.77: compromise reason
            self.assertIn("SUCCESS_AFTER_FAILURES", ip_map["198.51.100.77"]["detections"])
            self.assertTrue(any("CRITICAL: Successful login" in r for r in ip_map["198.51.100.77"]["detection_reasons"]))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_threshold_changes_do_not_disable_other_detections(self) -> None:
        """Prove that changing one threshold does not disable other detection types."""
        lines = [
            # Spraying (3 accounts, 3 failures)
            "Nov 16 09:10:01 endpoint sshd[201]: Failed password for user1 from 203.0.113.45 port 6001 ssh2\n",
            "Nov 16 09:10:02 endpoint sshd[202]: Failed password for user2 from 203.0.113.45 port 6002 ssh2\n",
            "Nov 16 09:10:03 endpoint sshd[203]: Failed password for user3 from 203.0.113.45 port 6003 ssh2\n",
            # Compromise (2 failures then success)
            "Nov 16 09:20:01 endpoint sshd[301]: Failed password for admin from 198.51.100.77 port 7001 ssh2\n",
            "Nov 16 09:20:02 endpoint sshd[302]: Failed password for admin from 198.51.100.77 port 7002 ssh2\n",
            "Nov 16 09:20:05 endpoint sshd[303]: Accepted password for admin from 198.51.100.77 port 7003 ssh2\n",
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.writelines(lines)
            tmp_path = tmp.name

        try:
            # Huge brute-force threshold (100) does NOT disable spraying or compromise detection
            f_huge_bf, _, _ = analyze_auth_log(tmp_path, threshold=100, spray_threshold=3, repeat_failure_threshold=2)
            self.assertIn("203.0.113.45", f_huge_bf)
            self.assertIn("PASSWORD_SPRAYING", f_huge_bf["203.0.113.45"].detections)
            self.assertIn("198.51.100.77", f_huge_bf)
            self.assertIn("SUCCESS_AFTER_FAILURES", f_huge_bf["198.51.100.77"].detections)

            # Huge spray threshold (100) does NOT disable compromise detection
            f_huge_spray, _, _ = analyze_auth_log(tmp_path, threshold=100, spray_threshold=100, repeat_failure_threshold=2)
            self.assertNotIn("203.0.113.45", f_huge_spray)
            self.assertIn("198.51.100.77", f_huge_spray)
            self.assertIn("SUCCESS_AFTER_FAILURES", f_huge_spray["198.51.100.77"].detections)

            # Huge compromise threshold (100) does NOT disable spray detection
            f_huge_comp, _, _ = analyze_auth_log(tmp_path, threshold=100, spray_threshold=3, repeat_failure_threshold=100)
            self.assertIn("203.0.113.45", f_huge_comp)
            self.assertIn("PASSWORD_SPRAYING", f_huge_comp["203.0.113.45"].detections)
            self.assertNotIn("198.51.100.77", f_huge_comp)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
