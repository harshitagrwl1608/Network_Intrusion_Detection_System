#!/usr/bin/env python3
"""
Installer for NetGuard Local Git Pre-Push Hook.
Symlinks or copies git_pre_push.py to .git/hooks/pre-push with executable permissions.
"""

import os
import shutil
import stat
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
HOOK_SOURCE = os.path.join(SCRIPTS_DIR, "git_pre_push.py")


def find_git_dir():
    d = SCRIPTS_DIR
    while d and d != os.path.dirname(d):
        git_dir = os.path.join(d, ".git")
        if os.path.isdir(git_dir):
            return git_dir
        d = os.path.dirname(d)
    return None


def install():
    git_dir = find_git_dir()
    if not git_dir:
        sys.stderr.write("Error: Could not locate .git directory.\n")
        return 1

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    target_hook = os.path.join(hooks_dir, "pre-push")

    # Copy hook script
    shutil.copy2(HOOK_SOURCE, target_hook)

    # Set executable permissions (chmod +x)
    current_mode = os.stat(target_hook).st_mode
    os.chmod(target_hook, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Successfully installed NetGuard pre-push hook to: {target_hook}")
    return 0


if __name__ == "__main__":
    sys.exit(install())
