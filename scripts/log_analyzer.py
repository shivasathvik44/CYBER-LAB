#!/usr/bin/env python3
"""Linux Authentication Log Analyzer for Cybersecurity Homelab.

Parses OpenSSH authentication logs (/var/log/secure, /var/log/auth.log), extracts
repeated failed login attempts, groups events by source IP and targeted accounts,
and produces human-readable summary tables or structured JSON reports.
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
class IPSummary:
    """Aggregated statistics for a specific source IP address."""

    source_ip: str
    total_failures: int = 0
    targeted_users: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    first_seen: str | None = None
    last_seen: str | None = None


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


def analyze_auth_log(
    file_path: Path | str, threshold: int = 5
) -> tuple[dict[str, IPSummary], int, int]:
    """Analyze an authentication log file and detect brute-force patterns.

    Args:
        file_path: Path to the log file.
        threshold: Minimum failed attempts to consider an IP suspicious.

    Returns:
        A tuple of (ip_summaries, total_lines_processed, total_failures_found).

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
            attempt = parse_log_line(line)
            if not attempt:
                continue

            total_failures += 1
            ip = attempt.source_ip
            if ip not in summaries:
                summaries[ip] = IPSummary(source_ip=ip, first_seen=attempt.timestamp)

            summary = summaries[ip]
            summary.total_failures += 1
            summary.targeted_users[attempt.user] += 1
            summary.last_seen = attempt.timestamp

    # Filter summaries by threshold
    flagged_summaries = {
        ip: summary for ip, summary in summaries.items() if summary.total_failures >= threshold
    }

    return flagged_summaries, total_lines, total_failures


def format_text_report(
    summaries: dict[str, IPSummary],
    log_file: str,
    threshold: int,
    total_lines: int,
    total_failures: int,
) -> str:
    """Generate a clean ASCII table summary report."""
    lines = [
        "=" * 80,
        "CYBERSECURITY HOMELAB - AUTHENTICATION LOG ANALYSIS REPORT",
        "=" * 80,
        f"Log Source Path       : {log_file}",
        f"Threshold Filter      : >= {threshold} failed attempts",
        f"Total Lines Processed : {total_lines}",
        f"Total Failed Logins   : {total_failures}",
        f"Suspicious IPs Flagged: {len(summaries)}",
        "-" * 80,
    ]

    if not summaries:
        lines.append(f"No source IP exceeded the failure threshold of {threshold}.")
        lines.append("=" * 80)
        return "\n".join(lines)

    lines.append(f"{'Source IP':<18} {'Failures':<10} {'First Seen':<16} {'Target Accounts'}")
    lines.append("-" * 80)

    # Sort descending by failure count
    sorted_ips = sorted(summaries.values(), key=lambda s: s.total_failures, reverse=True)
    for s in sorted_ips:
        users_str = ", ".join(f"{u} ({cnt})" for u, cnt in sorted(s.targeted_users.items()))
        first_ts = (s.first_seen or "N/A")[:15]
        lines.append(f"{s.source_ip:<18} {s.total_failures:<10} {first_ts:<16} {users_str}")

    lines.append("=" * 80)
    lines.append("RECOMMENDATION: Review firewall rules or apply Wazuh Active Response block.")
    lines.append("=" * 80)
    return "\n".join(lines)


def export_json_report(
    summaries: dict[str, IPSummary],
    log_file: str,
    threshold: int,
    total_lines: int,
    total_failures: int,
) -> dict:
    """Generate a structured JSON dictionary."""
    return {
        "metadata": {
            "log_file": str(log_file),
            "threshold": threshold,
            "total_lines_processed": total_lines,
            "total_failures_detected": total_failures,
            "suspicious_ip_count": len(summaries),
        },
        "suspicious_ips": [asdict(s) for s in summaries.values()],
    }


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for repeated login failures & brute-force attacks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
        help="Alert threshold for failed attempts from a single IP",
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

    if args.threshold < 1:
        print("[!] Error: Threshold must be a positive integer greater than or equal to 1.", file=sys.stderr)
        return 1

    try:
        flagged, total_lines, total_failures = analyze_auth_log(
            args.log_file, threshold=args.threshold
        )
    except FileNotFoundError as e:
        print(f"[!] File Error: {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"[!] Permission Error: Access denied reading {args.log_file} ({e}). Run with sudo or test on readable sample.", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[!] Unexpected error during analysis: {e}", file=sys.stderr)
        return 4

    if args.json_output:
        report_data = export_json_report(
            flagged, args.log_file, args.threshold, total_lines, total_failures
        )
        output_str = json.dumps(report_data, indent=2)
    else:
        output_str = format_text_report(
            flagged, args.log_file, args.threshold, total_lines, total_failures
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

    # Return exit code 0 if normal, or return 10 if threats exceeded threshold for automation pipelines
    return 10 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
