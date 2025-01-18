# Unit Tests & Continuous Integration

This directory contains automated unit tests for the Python automation scripts (`scripts/log_analyzer.py` and `scripts/integrity_monitor.py`).

---

## Test Organization

- `test_log_analyzer.py`: Validates OpenSSH / PAM log parsing, IP grouping, account correlation, threshold filtering, missing file handling, and JSON report generation.
- `test_integrity_monitor.py`: Validates SHA-256 chunked hashing, directory baseline creation, comparison logic (created, modified, deleted files), and filesystem exception handling.

---

## Running the Tests Locally

The tests are designed to be run seamlessly using either **pytest** or Python's built-in **unittest** module (zero external dependencies required).

### Option 1: Using Python's Built-In Test Runner
From the repository root:
```bash
python3 -m unittest discover -s tests -v
```

### Option 2: Using Pytest
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run pytest with verbose reporting
pytest -v tests/
```

### Option 3: Linting with Ruff
```bash
ruff check .
```

---

## GitHub Actions CI Pipeline

The repository includes a continuous integration workflow at `.github/workflows/python-tests.yml` that automatically runs Ruff and Pytest against Python 3.10, 3.11, and 3.12 on every push and pull request to the `main` branch.
