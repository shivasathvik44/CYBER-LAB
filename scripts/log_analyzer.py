#!/usr/bin/env python3
"""Linux Authentication Log Analyzer for Cybersecurity Homelab.

Parses OpenSSH authentication logs (/var/log/secure, /var/log/auth.log, sample logs),
extracts repeated failed login attempts, groups events by source IP and targeted accounts,
detects brute-force attacks, password spraying patterns, and successful logins following
repeated failures (potential host compromise). Produces human-readable summary reports
and structured JSON outputs for defensive analysis.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class FailedAttempt:
    """Represents a single parsed authentication failure event."""

    timestamp: str
    source_ip: str
    user: str
    port: str | None = None
    raw_message: str = ""


@dataclass
class SuccessfulAttempt:
    """Represents a single parsed authentication success event."""

    timestamp: str
    source_ip: str
    user: str
    port: str | None = None
    auth_method: str = "password"
    raw_message: str = ""


@dataclass
class IPSummary:
    """Aggregated statistics and threat detections for a specific source IP address."""

    source_ip: str
    total_failures: int = 0
    targeted_users: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    first_seen: str | None = None
    last_seen: str | None = None
    total_successes: int = 0
    successful_users: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    success_after_failure: bool = False
    password_spray: bool = False
    detections: list[str] = field(default_factory=list)
    detection_reasons: list[str] = field(default_factory=list)
    failure_timestamps: list[str] = field(default_factory=list)
    success_timestamps: list[str] = field(default_factory=list)


# Regex patterns matching standard OpenSSH syslog / systemd-journal formats:
# 1. Failed password for [invalid user ]<user> from <ip> port <port> ssh2
# 2. authentication failure; ... rhost=<ip> [user=<user>]
FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\w\.\+\-]+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)

PAM_AUTH_FAILURE_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\w\.\+\-]+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+pam_unix\(sshd:auth\):\s+authentication failure;.*?"
    r"rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)(?:.*?user=(?P<user>\S+))?",
    re.IGNORECASE,
)

# Pattern matching accepted / successful OpenSSH logins
ACCEPTED_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\w\.\+\-]+)\s+"
    r"(?:\S+\s+)?sshd\[\d+\]:\s+Accepted\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)


def parse_log_line(line: str) -> FailedAttempt | None:
    """Parse a single log line to extract authentication failure details.

    Args:
        line: Raw log line string.

    Returns:
        FailedAttempt if matched, None otherwise.
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = FAILED_PASSWORD_PATTERN.search(stripped)
    if match:
        return FailedAttempt(
            timestamp=match.group("timestamp"),
            source_ip=match.group("ip"),
            user=match.group("user"),
            port=match.group("port"),
            raw_message=stripped,
        )

    pam_match = PAM_AUTH_FAILURE_PATTERN.search(stripped)
    if pam_match:
        return FailedAttempt(
            timestamp=pam_match.group("timestamp"),
            source_ip=pam_match.group("ip"),
            user=pam_match.group("user") or "unknown",
            port=None,
            raw_message=stripped,
        )

    return None


def parse_success_line(line: str) -> SuccessfulAttempt | None:
    """Parse a single log line to extract authentication success details.

    Args:
        line: Raw log line string.

    Returns:
        SuccessfulAttempt if matched, None otherwise.
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = ACCEPTED_AUTH_PATTERN.search(stripped)
    if match:
        return SuccessfulAttempt(
            timestamp=match.group("timestamp"),
            source_ip=match.group("ip"),
            user=match.group("user"),
            port=match.group("port"),
            auth_method=match.group("method").lower(),
            raw_message=stripped,
        )

    return None


def analyze_auth_log(
    file_path: Path | str,
    threshold: int = 5,
    spray_threshold: int = 3,
    repeat_failure_threshold: int = 2,
) -> tuple[dict[str, IPSummary], int, int]:
    """Analyze an authentication log file and detect brute-force and attack patterns.

    Args:
        file_path: Path to the log file.
        threshold: Minimum failed attempts to flag volumetric brute force (default: 5).
        spray_threshold: Minimum distinct usernames targeted from an IP to flag spraying (default: 3).
        repeat_failure_threshold: Minimum failed attempts preceding a successful login
            to flag a critical host compromise warning (default: 2). An isolated single
            typo (1 failure followed by success) is excluded to avoid false positives.

    Returns:
        A tuple of (flagged_summaries, total_lines_processed, total_failures_found).

    Raises:
        FileNotFoundError: If log file does not exist.
        PermissionError: If read permissions are lacking.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Target log file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    summaries: dict[str, IPSummary] = {}
    total_lines = 0
    total_failures = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1

            # 1. Check for failed authentication
            attempt = parse_log_line(line)
            if attempt:
                total_failures += 1
                ip = attempt.source_ip
                if ip not in summaries:
                    summaries[ip] = IPSummary(source_ip=ip, first_seen=attempt.timestamp)

                summary = summaries[ip]
                summary.total_failures += 1
                summary.targeted_users[attempt.user] += 1
                summary.failure_timestamps.append(attempt.timestamp)
                summary.last_seen = attempt.timestamp
                continue

            # 2. Check for successful authentication
            success = parse_success_line(line)
            if success:
                ip = success.source_ip
                if ip not in summaries:
                    summaries[ip] = IPSummary(source_ip=ip, first_seen=success.timestamp)

                summary = summaries[ip]
                summary.total_successes += 1
                summary.successful_users[success.user] += 1
                summary.success_timestamps.append(success.timestamp)
                summary.last_seen = success.timestamp

                # Flag if this IP had previous failures
                if summary.total_failures > 0:
                    summary.success_after_failure = True
                continue

    # Evaluate detections and filter summaries by threat criteria
    flagged_summaries: dict[str, IPSummary] = {}

    for ip, summary in summaries.items():
        is_flagged = False

        # Detection 1: High-Frequency / Volume Brute Force
        if summary.total_failures >= threshold:
            is_flagged = True
            summary.detections.append("SSH_BRUTE_FORCE")
            summary.detection_reasons.append(
                f"Failed attempts ({summary.total_failures}) reached brute-force threshold ({threshold})"
            )

        # Detection 2: Password Spraying Pattern (distinct accounts targeted)
        if len(summary.targeted_users) >= spray_threshold and summary.total_failures >= spray_threshold:
            is_flagged = True
            summary.password_spray = True
            summary.detections.append("PASSWORD_SPRAYING")
            summary.detection_reasons.append(
                f"Targeted {len(summary.targeted_users)} distinct usernames across {summary.total_failures} attempts (spray threshold: {spray_threshold})"
            )

        # Detection 3: Successful Login After Repeated Failures (Potential Host Compromise)
        # Evaluated independently of the volumetric brute-force threshold.
        # A single failure before success (1 typo) is benign; >= repeat_failure_threshold indicates compromise.
        if summary.success_after_failure and summary.total_failures >= repeat_failure_threshold:
            is_flagged = True
            summary.detections.append("SUCCESS_AFTER_FAILURES")
            succ_users = ", ".join(sorted(summary.successful_users.keys()))
            summary.detection_reasons.append(
                f"CRITICAL: Successful login for account(s) [{succ_users}] following {summary.total_failures} failed attempts (repeated failure threshold: {repeat_failure_threshold})"
            )

        if is_flagged:
            flagged_summaries[ip] = summary

    return flagged_summaries, total_lines, total_failures


def format_text_report(
    summaries: dict[str, IPSummary],
    log_file: str,
    threshold: int,
    total_lines: int,
    total_failures: int,
    spray_threshold: int = 3,
    repeat_failure_threshold: int = 2,
) -> str:
    """Generate a clean ASCII table summary report with detection indicators."""
    compromise_count = sum(1 for s in summaries.values() if "SUCCESS_AFTER_FAILURES" in s.detections)
    spray_count = sum(1 for s in summaries.values() if "PASSWORD_SPRAYING" in s.detections)

    lines = [
        "=" * 84,
        "CYBERSECURITY HOMELAB - AUTHENTICATION LOG ANALYSIS REPORT",
        "=" * 84,
        f"Log Source Path       : {log_file}",
        f"Threshold Filter      : >= {threshold} failed attempts",
        f"Spray Threshold       : >= {spray_threshold} distinct targeted usernames",
        f"Compromise Threshold  : >= {repeat_failure_threshold} failed attempts followed by login",
        f"Total Lines Processed : {total_lines}",
        f"Total Failed Logins   : {total_failures}",
        f"Suspicious IPs Flagged: {len(summaries)}",
        f"Compromise Warnings   : {compromise_count} (Successful login after repeated failures)",
        f"Spray Campaigns Found : {spray_count}",
        "-" * 84,
    ]

    if not summaries:
        lines.append(
            f"No source IP exceeded threat criteria (Brute-Force: {threshold}, "
            f"Spray: {spray_threshold}, Compromise: {repeat_failure_threshold})."
        )
        lines.append("=" * 84)
        return "\n".join(lines)

    lines.append(f"{'Source IP':<18} {'Failures':<10} {'Success':<9} {'First Seen':<16} {'Detections'}")
    lines.append("-" * 84)

    # Sort descending by failure count
    sorted_ips = sorted(summaries.values(), key=lambda s: s.total_failures, reverse=True)
    for s in sorted_ips:
        first_ts = (s.first_seen or "N/A")[:15]
        det_tags = ", ".join(s.detections) if s.detections else "NONE"
        lines.append(f"{s.source_ip:<18} {s.total_failures:<10} {s.total_successes:<9} {first_ts:<16} {det_tags}")

    lines.append("-" * 84)
    lines.append("DETECTION DETAILS & TARGETED ACCOUNTS:")

    for s in sorted_ips:
        users_str = ", ".join(f"{u} ({cnt})" for u, cnt in sorted(s.targeted_users.items()))
        lines.append(f"\n[*] Source IP: {s.source_ip}")
        lines.append(f"    - Failures : {s.total_failures} | Successes: {s.total_successes}")
        lines.append(f"    - Targeted Accounts : {users_str}")
        if s.successful_users:
            succ_str = ", ".join(f"{u} ({cnt})" for u, cnt in sorted(s.successful_users.items()))
            lines.append(f"    - Authenticated As  : {succ_str}")
        for r in s.detection_reasons:
            prefix = "[CRITICAL COMPROMISE]" if "CRITICAL" in r else "[DETECTED]"
            lines.append(f"    - {prefix} {r}")

    lines.append("=" * 84)
    lines.append("RECOMMENDED ACTIONS:")
    lines.append("1. Block high-frequency brute-force IPs via host firewall or Wazuh Active Response.")
    lines.append("2. Immediately investigate and rotate credentials for accounts with SUCCESS_AFTER_FAILURES.")
    lines.append("3. Enforce public-key SSH authentication and disable password logins in sshd_config.")
    lines.append("=" * 84)
    return "\n".join(lines)


def export_json_report(
    summaries: dict[str, IPSummary],
    log_file: str,
    threshold: int,
    total_lines: int,
    total_failures: int,
    spray_threshold: int = 3,
    total_successes: int = 0,
    repeat_failure_threshold: int = 2,
) -> dict:
    """Generate a structured JSON dictionary."""
    compromise_count = sum(1 for s in summaries.values() if "SUCCESS_AFTER_FAILURES" in s.detections)
    spray_count = sum(1 for s in summaries.values() if "PASSWORD_SPRAYING" in s.detections)

    return {
        "metadata": {
            "log_file": str(log_file),
            "threshold": threshold,
            "spray_threshold": spray_threshold,
            "repeat_failure_threshold": repeat_failure_threshold,
            "total_lines_processed": total_lines,
            "total_failures_detected": total_failures,
            "total_successes_detected": total_successes,
            "suspicious_ip_count": len(summaries),
            "compromise_warnings_count": compromise_count,
            "password_spray_count": spray_count,
        },
        "suspicious_ips": [asdict(s) for s in summaries.values()],
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for repeated login failures, brute-force attacks, and password spraying.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "positional_file",
        nargs="?",
        default=None,
        help="Optional path to authentication log file (can be passed positionally or via -f/--file)",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="log_file",
        default="/var/log/secure",
        help="Path to authentication log file (e.g. /var/log/secure or /var/log/auth.log)",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        dest="threshold",
        type=int,
        default=5,
        help="Alert threshold for volumetric failed attempts from a single IP",
    )
    parser.add_argument(
        "-s",
        "--spray-threshold",
        dest="spray_threshold",
        type=int,
        default=3,
        help="Minimum distinct targeted usernames to flag a password spraying campaign",
    )
    parser.add_argument(
        "-r",
        "--repeat-threshold",
        dest="repeat_failure_threshold",
        type=int,
        default=2,
        help="Minimum failed attempts preceding a successful login to flag host compromise",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output structured JSON instead of human-readable text",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=str,
        default=None,
        help="Optional destination path to write report output",
    )
    return parser.parse_args()


def main() -> int:
    """CLI execution entrypoint."""
    args = parse_arguments()
    effective_log_file = args.positional_file if args.positional_file else args.log_file

    if args.threshold < 1:
        print("[!] Error: Threshold must be a positive integer greater than or equal to 1.", file=sys.stderr)
        return 1

    if args.repeat_failure_threshold < 1:
        print("[!] Error: Repeat failure threshold must be a positive integer >= 1.", file=sys.stderr)
        return 1

    try:
        flagged, total_lines, total_failures = analyze_auth_log(
            effective_log_file,
            threshold=args.threshold,
            spray_threshold=args.spray_threshold,
            repeat_failure_threshold=args.repeat_failure_threshold,
        )
    except FileNotFoundError as e:
        print(f"[!] File Error: {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"[!] Permission Error: Access denied reading {effective_log_file} ({e}). Run with sudo or test on readable sample.", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[!] Unexpected error during analysis: {e}", file=sys.stderr)
        return 4

    total_successes = sum(s.total_successes for s in flagged.values())

    if args.json_output:
        report_data = export_json_report(
            flagged,
            effective_log_file,
            args.threshold,
            total_lines,
            total_failures,
            spray_threshold=args.spray_threshold,
            total_successes=total_successes,
            repeat_failure_threshold=args.repeat_failure_threshold,
        )
        output_str = json.dumps(report_data, indent=2)
    else:
        output_str = format_text_report(
            flagged,
            effective_log_file,
            args.threshold,
            total_lines,
            total_failures,
            spray_threshold=args.spray_threshold,
            repeat_failure_threshold=args.repeat_failure_threshold,
        )

    if args.output_file:
        try:
            Path(args.output_file).write_text(output_str, encoding="utf-8")
            print(f"[+] Report written to {args.output_file}")
        except Exception as e:
            print(f"[!] Error writing output to {args.output_file}: {e}", file=sys.stderr)
            return 5
    else:
        print(output_str)

    return 0


if __name__ == "__main__":
    sys.exit(main())
