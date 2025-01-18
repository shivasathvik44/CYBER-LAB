#!/usr/bin/env python3
"""File Integrity Monitor (FIM) for Cybersecurity Homelab.

Computes SHA-256 cryptographic hashes for files in a monitored directory,
establishes baseline snapshots in JSON, and compares current state against
the baseline to detect created, modified, or deleted files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class FileRecord:
    """Metadata and hash for a single monitored file."""

    path: str
    sha256: str
    size_bytes: int
    modified_time_iso: str


@dataclass
class ComparisonResult:
    """Outcome of comparing directory against baseline snapshot."""

    created_files: list[FileRecord]
    modified_files: list[tuple[FileRecord, str]]  # (current_record, baseline_sha256)
    deleted_files: list[dict]
    unchanged_count: int
    inaccessible_files: list[str] = field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        """True if any changes were detected."""
        return bool(self.created_files or self.modified_files or self.deleted_files)


def compute_sha256(file_path: Path, block_size: int = 65536) -> str | None:
    """Compute SHA-256 hash of a file safely in chunks.

    Args:
        file_path: Path to the target file.
        block_size: Buffer chunk size in bytes.

    Returns:
        Hexadecimal hash string or None if unreadable.
    """
    hasher = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except (OSError, PermissionError) as e:
        print(f"[!] Warning: Cannot read '{file_path}': {e}", file=sys.stderr)
        return None


def scan_directory_with_errors(target_dir: Path | str) -> tuple[dict[str, FileRecord], list[str]]:
    """Recursively scan a directory and compute metadata/hashes for all files.

    Args:
        target_dir: Root directory path to monitor.

    Returns:
        Tuple of (records_dict, skipped_inaccessible_paths).
    """
    root_path = Path(target_dir).resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise ValueError(f"Target directory does not exist or is not a directory: {root_path}")

    records: dict[str, FileRecord] = {}
    skipped: list[str] = []

    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            full_path = Path(dirpath) / name

            # Skip broken symlinks safely
            if full_path.is_symlink() and not full_path.exists():
                continue

            rel_path = str(full_path.relative_to(root_path))
            try:
                stat = full_path.stat()
                file_hash = compute_sha256(full_path)
                if file_hash is None:
                    skipped.append(rel_path)
                    continue

                mtime_iso = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

                records[rel_path] = FileRecord(
                    path=rel_path,
                    sha256=file_hash,
                    size_bytes=stat.st_size,
                    modified_time_iso=mtime_iso,
                )
            except (OSError, PermissionError) as err:
                print(f"[!] Warning: Skipped {full_path}: {err}", file=sys.stderr)
                skipped.append(rel_path)
                continue

    return records, skipped


def scan_directory(target_dir: Path | str) -> dict[str, FileRecord]:
    """Recursively scan a directory and compute metadata/hashes for all files.

    Args:
        target_dir: Root directory path to monitor.

    Returns:
        Dictionary mapping relative file paths to FileRecord objects.
    """
    records, _ = scan_directory_with_errors(target_dir)
    return records


def save_baseline(records: dict[str, FileRecord], baseline_file: Path | str, target_dir: str) -> None:
    """Save scanned directory records to a baseline JSON file."""
    output_path = Path(baseline_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "metadata": {
            "target_directory": str(Path(target_dir).resolve()),
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "total_files": len(records),
            "algorithm": "sha256",
        },
        "files": {path: asdict(rec) for path, rec in sorted(records.items())},
    }

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_baseline(baseline_file: Path | str) -> tuple[dict[str, dict], dict]:
    """Load baseline JSON file.

    Returns:
        Tuple of (files_dict, metadata_dict).
    """
    path = Path(baseline_file)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    try:
        content = json.loads(path.read_text(encoding="utf-8"))
        return content.get("files", {}), content.get("metadata", {})
    except json.JSONDecodeError as e:
        raise ValueError(f"Baseline file is corrupted or not valid JSON: {e}") from e


def compare_against_baseline(
    current_records: dict[str, FileRecord],
    baseline_records: dict[str, dict],
    inaccessible_files: list[str] | None = None,
) -> ComparisonResult:
    """Compare active file records against the baseline."""
    created: list[FileRecord] = []
    modified: list[tuple[FileRecord, str]] = []
    deleted: list[dict] = []
    unchanged = 0

    current_keys = set(current_records.keys())
    baseline_keys = set(baseline_records.keys())

    # Detect created files
    for k in sorted(current_keys - baseline_keys):
        created.append(current_records[k])

    # Detect deleted files
    for k in sorted(baseline_keys - current_keys):
        deleted.append(baseline_records[k])

    # Detect modified files
    for k in sorted(current_keys & baseline_keys):
        curr = current_records[k]
        base = baseline_records[k]
        if curr.sha256 != base.get("sha256"):
            modified.append((curr, base.get("sha256", "UNKNOWN")))
        else:
            unchanged += 1

    return ComparisonResult(
        created_files=created,
        modified_files=modified,
        deleted_files=deleted,
        unchanged_count=unchanged,
        inaccessible_files=inaccessible_files or [],
    )


def format_cli_report(
    res: ComparisonResult, target_dir: str, baseline_path: str
) -> str:
    """Format comparison result as human-readable terminal report."""
    status = "⚠️  TAMPERING DETECTED" if res.has_anomalies else "✅ INTEGRITY VERIFIED (CLEAN)"
    lines = [
        "=" * 80,
        "CYBERSECURITY HOMELAB - FILE INTEGRITY MONITOR REPORT",
        "=" * 80,
        f"Monitored Directory : {target_dir}",
        f"Baseline File       : {baseline_path}",
        f"Status              : {status}",
        "-" * 80,
        f"Created Files       : {len(res.created_files)}",
        f"Modified Files      : {len(res.modified_files)}",
        f"Deleted Files       : {len(res.deleted_files)}",
        f"Unchanged Files     : {res.unchanged_count}",
        f"Inaccessible Files  : {len(res.inaccessible_files)}",
        "=" * 80,
    ]

    if res.created_files:
        lines.append("\n[+] NEW / CREATED FILES:")
        for rec in res.created_files:
            lines.append(f"    + {rec.path} (SHA-256: {rec.sha256[:16]}...)")

    if res.modified_files:
        lines.append("\n[!] MODIFIED FILES:")
        for curr, base_hash in res.modified_files:
            lines.append(f"    ! {curr.path}")
            lines.append(f"        Expected: {base_hash}")
            lines.append(f"        Current : {curr.sha256}")

    if res.deleted_files:
        lines.append("\n[-] DELETED FILES:")
        for d in res.deleted_files:
            lines.append(f"    - {d.get('path')} (Expected SHA-256: {d.get('sha256', '')[:16]}...)")

    if res.inaccessible_files:
        lines.append("\n[?] INACCESSIBLE / SKIPPED FILES:")
        for f in res.inaccessible_files:
            lines.append(f"    ? {f} (Read error / permission denied)")

    lines.append("=" * 80)
    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitoring (FIM) baseline generator and anomaly checker.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="target_dir",
        required=True,
        help="Target directory to monitor",
    )
    parser.add_argument(
        "-b",
        "--baseline",
        dest="baseline_file",
        default="baseline.json",
        help="Path to baseline JSON snapshot file",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--init",
        action="store_true",
        help="Generate a new cryptographic baseline from the current directory state",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Compare current directory against existing baseline snapshot",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results in JSON format",
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

    try:
        if args.init:
            records, skipped = scan_directory_with_errors(args.target_dir)
            save_baseline(records, args.baseline_file, args.target_dir)
            print(f"[+] Baseline successfully created for '{args.target_dir}' ({len(records)} files).")
            if skipped:
                print(f"[!] Note: Skipped {len(skipped)} inaccessible files during baseline creation.")
            print(f"[+] Saved baseline to: {args.baseline_file}")
            return 0

        if args.check:
            current_records, skipped = scan_directory_with_errors(args.target_dir)
            # If baseline_file is located inside target_dir, exclude it from active comparison
            try:
                rel_base = str(
                    Path(args.baseline_file).resolve().relative_to(Path(args.target_dir).resolve())
                )
                current_records.pop(rel_base, None)
            except ValueError:
                pass  # Baseline file is outside target directory

            baseline_records, _ = load_baseline(args.baseline_file)
            result = compare_against_baseline(current_records, baseline_records, skipped)

            if args.json_output:
                output_dict = {
                    "has_anomalies": result.has_anomalies,
                    "created": [asdict(r) for r in result.created_files],
                    "modified": [
                        {"file": asdict(curr), "expected_sha256": exp}
                        for curr, exp in result.modified_files
                    ],
                    "deleted": result.deleted_files,
                    "unchanged_count": result.unchanged_count,
                    "inaccessible_files": result.inaccessible_files,
                }
                output_content = json.dumps(output_dict, indent=2)
            else:
                output_content = format_cli_report(result, args.target_dir, args.baseline_file)

            if args.output_file:
                try:
                    Path(args.output_file).write_text(output_content, encoding="utf-8")
                    print(f"[+] Report successfully written to {args.output_file}")
                except Exception as e:
                    print(f"[!] Error writing to {args.output_file}: {e}", file=sys.stderr)
                    return 1
            else:
                print(output_content)

            return 2 if result.has_anomalies else 0

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
