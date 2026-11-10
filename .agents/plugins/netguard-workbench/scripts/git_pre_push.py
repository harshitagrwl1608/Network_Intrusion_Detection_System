#!/usr/bin/env python3
"""
NetGuard Local Git Pre-Push Hook.
Enforces layered Git discipline directly within Git's native execution lifecycle.
Prevents direct pushes, deletions, and force pushes to protected branches.

Installed to: .git/hooks/pre-push
"""

import sys

PROTECTED_BRANCHES = {"refs/heads/main", "refs/heads/master", "main", "master"}
AUTHORIZED_SOURCE_BRANCH = "refs/heads/antigravity/overnight-work"
ZERO_SHA = "0" * 40


def inspect_push_line(line: str) -> tuple[bool, str]:
    parts = line.strip().split()
    if len(parts) < 4:
        return True, ""  # Not enough info, allow normal git processing

    local_ref, local_sha, remote_ref, remote_sha = parts[:4]

    # 1. Prohibit remote deletion of protected branches
    if remote_ref in PROTECTED_BRANCHES:
        if local_ref == "(delete)" or local_sha == ZERO_SHA:
            return False, f"Deletion of protected branch '{remote_ref}' is prohibited."

    # 2. Prohibit direct pushes to main/master
    if remote_ref in PROTECTED_BRANCHES:
        return False, (
            f"Direct push to protected branch '{remote_ref}' is strictly prohibited. "
            "All changes must reach main through reviewed pull requests from 'antigravity/overnight-work'."
        )

    # 3. Warn or guard if pushing to unauthorized branch
    # NetGuard autonomous development is restricted to antigravity/overnight-work
    return True, ""


def main():
    remote_name = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    remote_url = sys.argv[2] if len(sys.argv) > 2 else "unknown"

    lines = sys.stdin.readlines()
    if not lines:
        sys.exit(0)

    for line in lines:
        allowed, reason = inspect_push_line(line)
        if not allowed:
            sys.stderr.write(f"\n[NetGuard Git Discipline Blocked] {reason}\n")
            sys.stderr.write(f"Remote: {remote_name} ({remote_url})\n\n")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()

