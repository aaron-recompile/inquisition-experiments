"""
Run all negative/sensitivity tests and persist results.

Usage:
  PYTHONPATH=. python3 scripts/run_negative_suite.py

Output:
  results/negative_test_results.md (appended run section)
"""

from __future__ import annotations

import datetime as dt
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT_FILE = ROOT / "results" / "negative_test_results.md"

CASES = [
    ("CSFS bad_msg", ["experiments/csfs_negative.py", "--case", "bad_msg"]),
    ("CSFS bad_sig", ["experiments/csfs_negative.py", "--case", "bad_sig"]),
    ("CSFS bad_pubkey", ["experiments/csfs_negative.py", "--case", "bad_pubkey"]),
    ("CTV wrong_amount", ["experiments/ctv_negative.py", "--case", "wrong_amount"]),
    ("CTV wrong_sequence", ["experiments/ctv_negative.py", "--case", "wrong_sequence"]),
]


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_one(args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable] + args
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )


def append_results(lines: list[str]) -> None:
    if not RESULT_FILE.exists():
        RESULT_FILE.write_text("# Negative Test Results\n\n", encoding="utf-8")
    with RESULT_FILE.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    ts = now_utc()
    out_lines: list[str] = []
    out_lines.append("---")
    out_lines.append("")
    out_lines.append(f"## Suite run @ {ts}")
    out_lines.append("")
    out_lines.append("| Case | Exit code | Allowed? |")
    out_lines.append("|------|-----------|----------|")

    fail_count = 0

    for title, rel_args in CASES:
        cp = run_one(rel_args)
        stdout = (cp.stdout or "").strip()
        stderr = (cp.stderr or "").strip()
        combined = (stdout + ("\n" + stderr if stderr else "")).strip()

        allowed = "unknown"
        if '"allowed": false' in combined or '"allowed":false' in combined:
            allowed = "false (expected)"
        elif '"allowed": true' in combined or '"allowed":true' in combined:
            allowed = "true (unexpected)"
        elif "ModuleNotFoundError" in combined:
            allowed = "n/a (dependency missing)"
        elif combined:
            allowed = "n/a (no parsed allowed)"

        out_lines.append(f"| {title} | `{cp.returncode}` | {allowed} |")

        out_lines.append("")
        out_lines.append(f"### {title}")
        out_lines.append("")
        out_lines.append(f"- Command: `{sys.executable} {' '.join(rel_args)}`")
        out_lines.append(f"- Exit code: `{cp.returncode}`")
        out_lines.append("")
        out_lines.append("```text")
        out_lines.append(combined if combined else "(no output)")
        out_lines.append("```")
        out_lines.append("")

        if cp.returncode != 0:
            fail_count += 1

    append_results(out_lines)
    print(f"Suite run saved to: {RESULT_FILE}")
    if fail_count:
        print(f"Completed with {fail_count} failing case(s). See markdown report.")
    else:
        print("Completed with all cases returning exit code 0.")


if __name__ == "__main__":
    main()

