#!/usr/bin/env python3
"""
PreToolUse Safety Hook for NetGuard Engineering Workbench.
Enforces Git discipline, prevents force pushes, protects main branch,
and blocks destructive deletions and resets.
"""

import json
import re
import shlex
import sys


def split_pipeline(cmd_str: str):
    """
    Split complex command strings on shell delimiters (&&, ||, ;, |),
    accounting for quotes.
    """
    # Regex splits on delimiters outside quotes
    pattern = r"(?:&&|\|\||;|\|)"
    tokens = re.split(pattern, cmd_str)
    return [t.strip() for t in tokens if t.strip()]


def inspect_command_tokens(tokens):
    """
    Inspect tokenized command list and return (is_blocked, reason).
    """
    if not tokens:
        return False, ""

    prog = tokens[0].lower()
    
    # Handle wrapped commands like bash -c "..." or sh -c "..."
    if prog in ("bash", "sh", "zsh") and len(tokens) >= 3 and tokens[1] in ("-c", "-lc"):
        sub_cmd = tokens[2]
        sub_blocked, sub_reason = evaluate_command_string(sub_cmd)
        if sub_blocked:
            return True, sub_reason

    # Git command inspection
    if prog == "git" and len(tokens) > 1:
        subcmd = tokens[1].lower()

        # Check for push violations
        if subcmd == "push":
            args = tokens[2:]
            # Check for force push flags
            for a in args:
                if a in ("-f", "--force", "--force-with-lease", "--force-if-includes"):
                    return True, "Force push detected. Force-pushing is strictly prohibited by NetGuard discipline."
                if a == "--delete":
                    return True, "Remote branch deletion via git push --delete is prohibited."
            
            # Check for push to main branch
            for a in args:
                # Matches push to main directly, refspecs like HEAD:main or local:main
                if a == "main" or a.endswith(":main") or a == "origin/main":
                    return True, "Direct push to 'main' is prohibited. Push strictly to 'origin/antigravity/overnight-work'."

        # Check for reset violations
        if subcmd == "reset":
            for a in tokens[2:]:
                if a == "--hard":
                    return True, "Destructive 'git reset --hard' is prohibited to prevent data loss."

        # Check for branch deletion
        if subcmd == "branch":
            for a in tokens[2:]:
                if a in ("-D", "-d", "--delete"):
                    return True, "Branch deletion is prohibited by NetGuard discipline."

        # Check for aggressive clean
        if subcmd == "clean":
            args = tokens[2:]
            if any("-f" in a or "-x" in a or "-d" in a for a in args):
                return True, "Unsafe 'git clean' detected. May delete untracked datasets or evaluation fixtures."

        # Check for checkout or switch to main with mutation
        if subcmd in ("checkout", "switch") and len(tokens) > 2:
            target = tokens[2].lower()
            if target == "main" and any(arg in tokens for arg in ("-B", "-b")):
                return True, "Cannot overwrite or recreate 'main' branch."

    # File deletion inspection (rm, unlink)
    if prog in ("rm", "/bin/rm", "/usr/bin/rm"):
        args = tokens[1:]
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]

        has_recursive = any("r" in f or "R" in f for f in flags)
        has_force = any("f" in f for f in flags)

        for p in paths:
            raw_p = p.strip("'\"")
            clean_p = raw_p.rstrip("/") if raw_p != "/" else "/"
            # Root or home deletion
            if clean_p in ("/", "~", "$HOME", "*", "/*", "") and raw_p in ("/", "/*", "*"):
                return True, "Catastrophic directory deletion blocked."
            if clean_p in ("/", "~", "$HOME", "*", "/*"):
                return True, "Catastrophic directory deletion blocked."
            # Dataset and evaluation directory protection
            if "ids_project/evaluation/datasets" in raw_p and (has_recursive or has_force):
                return True, "Destructive deletion of evaluation datasets directory is strictly prohibited."
            if clean_p in ("ids_project", "ids_project/engine", "ids_project/evaluation") and has_recursive:
                return True, f"Recursive deletion of core NetGuard directory '{clean_p}' is prohibited."

    return False, ""


def evaluate_command_string(cmd_str: str):
    """
    Evaluates a full command string, splitting compound commands and analyzing tokens.
    """
    sub_commands = split_pipeline(cmd_str)
    for sub in sub_commands:
        try:
            tokens = shlex.split(sub)
        except Exception:
            # Fallback simple whitespace split if shlex fails on unclosed quotes
            tokens = sub.split()
        
        is_blocked, reason = inspect_command_tokens(tokens)
        if is_blocked:
            return True, reason

    return False, ""


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except Exception:
        data = {}

    tool_call = data.get("toolCall", {})
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {})

    if tool_name == "run_command":
        cmd_str = args.get("CommandLine", "")
        is_blocked, reason = evaluate_command_string(cmd_str)
        if is_blocked:
            response = {
                "decision": "deny",
                "reason": f"NetGuard Workbench Guardrail: {reason}"
            }
            json.dump(response, sys.stdout)
            sys.exit(0)

    # Safe to proceed
    response = {
        "decision": "allow"
    }
    json.dump(response, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
