#!/usr/bin/env python3
"""Create a small vulnerable git repo for manual CLI / MCP testing.

Usage:
    python scripts/seed_test_repo.py /tmp/vuln
    cd /tmp/vuln
    cluescan review            # (needs llm.api_key configured)
"""
import sys
import subprocess
from pathlib import Path


def main():
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/cluescan_vuln")
    target.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(a, cwd=str(target), check=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("git", "init", "-q")
    run("git", "config", "user.email", "dev@example.com")
    run("git", "config", "user.name", "dev")
    # committed (clean) version
    (target / "app.py").write_text(
        'def get_user(uid):\n'
        '    return query("SELECT * FROM users WHERE id = %s", uid)\n'
    )
    run("git", "add", "-A")
    run("git", "commit", "-qm", "init")
    # uncommitted vulnerable change -> the diff ClueScan will review
    (target / "app.py").write_text(
        'def get_user(uid):\n'
        '    order = request.args.get("order", "id")\n'
        '    return query("SELECT * FROM users WHERE id = " + str(uid) + " ORDER BY " + order)\n'
    )
    print(f"Seeded vulnerable repo at {target}")
    print("Uncommitted diff introduces SQL injection (ORDER BY from user input).")
    print("Next: configure llm.api_key, then run  cluescan review  (or the security-review skill).")


if __name__ == "__main__":
    main()
