#!/usr/bin/env python3
"""
PreToolUse Safety Hook for NetGuard Engineering Workbench.
Enforces Git discipline, prevents force pushes, protects the protected 'main' branch,
and blocks destructive file deletions, resets, and cleans.

NOTE: This hook operates as an engineering guardrail within the Antigravity agent
execution loop to prevent unintended or destructive commands. It is NOT an
OS-level security boundary or sandbox.
"""

import json
import os
import re
import shlex
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.abspath(os.path.join(SCRIPTS_DIR, ".."))


def find_workspace_root():
    d = PLUGIN_DIR
    while d and d != os.path.dirname(d):
        if os.path.exists(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return PLUGIN_DIR


WORKSPACE_ROOT = find_workspace_root()
LOGS_DIR = os.path.join(PLUGIN_DIR, "logs")


def log_guard_audit(decision: str, reason: str, cmd_summary: str = ""):
    """Appends guardrail decisions to the audit log safely."""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        log_file = os.path.join(LOGS_DIR, "workbench_audit.log")
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hook": "PreToolUse",
            "decision": decision.lower(),
            "reason": reason,
            "summary": cmd_summary[:100] if cmd_summary else "",
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def is_unattended_mode() -> bool:
    """Detects if NetGuard is running in autonomous unattended campaign mode."""
    if os.environ.get("NETGUARD_UNATTENDED") in ("1", "true", "True"):
        return True
    state_file = os.path.join(WORKSPACE_ROOT, "docs", "autonomy", "state.json")
    if os.path.isfile(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("status") == "running" or data.get("implementation_lock") is True
        except Exception:
            pass
    return False


def strip_env_and_wrappers(tokens):
    """
    Strips leading environment variable assignments (e.g. VAR=val)
    and execution wrappers like 'env', 'sudo', 'nohup', 'nice', 'time', 'exec'.
    """
    idx = 0
    wrapper_names = {"env", "sudo", "nohup", "nice", "time", "exec"}
    while idx < len(tokens):
        tok = tokens[idx]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tok):
            idx += 1
            continue
        if tok.lower() in wrapper_names:
            idx += 1
            # Skip any wrapper flags like -i, -u user, -n, etc.
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] in ("-u", "-g", "--user", "--group") and idx + 1 < len(tokens):
                    idx += 2
                else:
                    idx += 1
            continue
        break
    return tokens[idx:]


def extract_git_subcommand_and_args(tokens):
    """
    Extracts the Git subcommand and its arguments, skipping any global options.
    e.g. ['git', '-C', '/path', '-c', 'foo=bar', 'push', 'origin', 'main']
    -> ('push', ['origin', 'main'])
    """
    options_with_arg = {
        "-C", "-c", "--git-dir", "--work-tree", "--namespace",
        "--super-prefix", "--exec-path"
    }
    boolean_options = {
        "--bare", "--no-pager", "-p", "-P", "--version", "--help",
        "--html-path", "--man-path", "--info-path", "--no-replace-objects",
        "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
        "--icase-pathspecs"
    }

    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if not tok.startswith("-"):
            # Subcommand identified
            return tok.lower(), tokens[idx + 1:]

        if "=" in tok:
            idx += 1
            continue
        elif tok in options_with_arg:
            idx += 2
            continue
        elif tok in boolean_options:
            idx += 1
            continue
        else:
            idx += 1

    return "", []


def is_refspec_targeting_main(ref: str) -> bool:
    """Checks if a Git refspec pushes to or affects the protected 'main' branch."""
    clean = ref.lstrip("+").strip().lower()
    if clean in ("main", "origin/main", "refs/heads/main"):
        return True
    if clean.endswith(":main") or clean.endswith(":refs/heads/main"):
        return True
    if clean == ":main" or clean == ":refs/heads/main":
        return True
    return False


def inspect_command_tokens(raw_tokens):
    """
    Inspects tokenized command list and returns (is_blocked, reason).
    """
    tokens = strip_env_and_wrappers(raw_tokens)
    if not tokens:
        return False, ""

    prog = tokens[0].lower()

    # 1. Shell wrappers & nested execution (bash -c "...", sh -c "...", zsh -c "...", eval ...)
    if prog in ("bash", "sh", "zsh", "ksh", "dash") and len(tokens) >= 3:
        for i in range(1, len(tokens) - 1):
            if tokens[i] in ("-c", "-lc", "-s"):
                sub_cmd = tokens[i + 1]
                sub_blocked, sub_reason = evaluate_command_string(sub_cmd)
                if sub_blocked:
                    return True, f"Nested shell command blocked: {sub_reason}"
                break

    if prog == "eval" and len(tokens) > 1:
        sub_cmd = " ".join(tokens[1:])
        sub_blocked, sub_reason = evaluate_command_string(sub_cmd)
        if sub_blocked:
            return True, f"Evaluated command blocked: {sub_reason}"

    # 2. Interpreters with inline scripts (python3 -c "...", node -e "...", perl -e "...", ruby -e "...")
    interpreter_names = {
        "python", "python3", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14",
        "pypy", "pypy3", "node", "nodejs", "perl", "ruby"
    }
    if prog in interpreter_names and len(tokens) >= 3:
        for i in range(1, len(tokens) - 1):
            if tokens[i] in ("-c", "-e", "-eval", "--eval"):
                inline_script = tokens[i + 1]
                s = inline_script.lower()

                # Semantic checks for dangerous inline commands
                if "git" in s:
                    if "push" in s and "main" in s:
                        return True, "Inline script attempts git push targeting main"
                    if "push" in s and any(f in s for f in ("-f", "--force")):
                        return True, "Inline script attempts git force push"
                    if "reset" in s and "--hard" in s:
                        return True, "Inline script attempts git reset --hard"
                    if "branch" in s and any(f in s for f in ("-d", "--delete")):
                        return True, "Inline script attempts git branch deletion"
                    if "clean" in s and any(f in s for f in ("-f", "-x", "-d")):
                        return True, "Inline script attempts git clean"

                if "rm" in s and ("datasets" in s or "ids_project" in s or "rmtree" in s):
                    return True, "Inline script attempts destructive directory deletion"

                if is_unattended_mode():
                    # In unattended mode, block ambiguous inline execution containing git mutation or rm
                    if any(w in s for w in ("git", "rm", "shutil", "unlink")) and any(w in s for w in ("push", "reset", "delete", "rmtree")):
                        return True, "Ambiguous mutation script blocked in unattended autonomous mode."
                break

    # 3. Git command inspection
    if prog == "git" and len(tokens) > 1:
        subcmd, args = extract_git_subcommand_and_args(tokens)

        # Check push violations
        if subcmd == "push":
            for a in args:
                # Force push check
                if a in ("-f", "--force", "--force-with-lease", "--force-if-includes"):
                    return True, "Force push detected. Force-pushing is strictly prohibited by NetGuard discipline."
                if a.startswith("+"):
                    return True, f"Force push detected via '+' refspec prefix ('{a}'). Strictly prohibited."
                if a in ("--delete", "-d"):
                    return True, "Remote branch deletion via git push --delete is prohibited."
                if a == "--mirror":
                    return True, "Push with --mirror is strictly prohibited."
                if a == "--all":
                    return True, "Push with --all is prohibited. Push strictly to 'origin/antigravity/overnight-work'."

                # Target main branch check
                if is_refspec_targeting_main(a):
                    return True, (
                        "Direct push to 'main' is prohibited. Changes must reach main via reviewed pull requests. "
                        "Push strictly to 'origin/antigravity/overnight-work'."
                    )

        # Check reset violations
        if subcmd == "reset":
            for a in args:
                if a in ("--hard", "--merge", "--keep"):
                    return True, f"Destructive 'git reset {a}' is prohibited to prevent uncommitted data loss."

        # Check branch deletion
        if subcmd == "branch":
            for a in args:
                if a in ("-D", "-d", "--delete"):
                    return True, "Branch deletion is prohibited by NetGuard discipline."

        # Check aggressive clean
        if subcmd == "clean":
            if any("-f" in a or "-x" in a or "-d" in a or a == "--force" for a in args):
                return True, "Unsafe 'git clean' detected. May delete untracked datasets or evaluation fixtures."

        # Check checkout or switch mutating main
        if subcmd in ("checkout", "switch") and len(args) > 0:
            for i, a in enumerate(args):
                if a.lower() == "main":
                    if any(flag in args for flag in ("-B", "-b", "--orphan")):
                        return True, "Cannot overwrite, recreate, or orphan 'main' branch."

    # 4. File deletion inspection (rm, unlink)
    if prog in ("rm", "/bin/rm", "/usr/bin/rm"):
        args = tokens[1:]
        flags = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]

        has_recursive = any("r" in f or "R" in f for f in flags)
        has_force = any("f" in f for f in flags)

        for p in paths:
            raw_p = p.strip("'\"")
            clean_p = raw_p.rstrip("/") if raw_p != "/" else "/"

            # Catastrophic directory deletions
            if clean_p in ("/", "~", "$HOME", "*", "/*", ".", ".."):
                return True, "Catastrophic directory deletion blocked."

            # Evaluation datasets protection
            if "ids_project/evaluation/datasets" in raw_p and (has_recursive or has_force):
                return True, "Destructive deletion of evaluation datasets directory is strictly prohibited."

            # Core code directory protection
            if clean_p in ("ids_project", "ids_project/engine", "ids_project/evaluation") and has_recursive:
                return True, f"Recursive deletion of core NetGuard directory '{clean_p}' is prohibited."

    return False, ""


def split_pipeline_tokens(cmd_str: str):
    """
    Parses a shell command string into token groups split on shell delimiters
    (&&, ||, ;, |, &), while respecting quotes POSIX-compliantly.
    """
    try:
        lexer = shlex.shlex(cmd_str, posix=True, punctuation_chars=True)
        raw_tokens = list(lexer)
    except Exception as e:
        # Unclosed quotes or syntax error in shell command
        return None, f"Shell syntax error in command string: {e}"

    sub_cmds = []
    current = []
    delimiters = {"&&", "||", ";", "|", "&"}
    for tok in raw_tokens:
        if tok in delimiters:
            if current:
                sub_cmds.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        sub_cmds.append(current)

    return sub_cmds, None


def evaluate_command_string(cmd_str: str):
    """
    Evaluates a full command string, splitting compound commands and analyzing tokens.
    """
    sub_cmds, err = split_pipeline_tokens(cmd_str)
    if err:
        return True, err

    for tokens in sub_cmds:
        is_blocked, reason = inspect_command_tokens(tokens)
        if is_blocked:
            return True, reason

    return False, ""


def fail_closed_deny(reason: str, summary: str = ""):
    """Emits a safe fail-closed denial response."""
    log_guard_audit("DENY", reason, summary)
    sys.stderr.write(f"[NetGuard Guardrail Blocked] {reason}\n")
    response = {
        "decision": "deny",
        "reason": f"NetGuard Workbench Guardrail: {reason}"
    }
    json.dump(response, sys.stdout)
    sys.exit(0)


def main():
    # 1. Strict input validation — handle empty stdin safely
    raw_input = ""
    try:
        if not sys.stdin.isatty():
            raw_input = sys.stdin.read()
    except Exception as e:
        fail_closed_deny(f"Failed reading hook payload from stdin: {e}")

    if not raw_input or not raw_input.strip():
        fail_closed_deny("Empty hook input payload on stdin. Failing closed for safety.")

    # 2. Parse JSON payload
    try:
        data = json.loads(raw_input)
    except Exception as e:
        fail_closed_deny(f"Malformed JSON payload on stdin: {e}. Failing closed for safety.")

    if not isinstance(data, dict):
        fail_closed_deny("Hook payload must be a valid JSON object.")

    # 3. Validate toolCall structure
    tool_call = data.get("toolCall")
    if not isinstance(tool_call, dict):
        fail_closed_deny("Missing or invalid 'toolCall' object in hook payload.")

    tool_name = tool_call.get("name")
    if not isinstance(tool_name, str):
        fail_closed_deny("Missing or invalid 'toolCall.name' in hook payload.")

    args = tool_call.get("args")

    # 4. Inspect run_command tool calls
    if tool_name == "run_command":
        if not isinstance(args, dict):
            fail_closed_deny("run_command 'args' must be a JSON object.")

        cmd_str = args.get("CommandLine")
        if not isinstance(cmd_str, str) or not cmd_str.strip():
            fail_closed_deny("run_command 'CommandLine' is missing or empty.")

        try:
            is_blocked, reason = evaluate_command_string(cmd_str)
        except Exception as e:
            # Internal evaluation exception — fail closed!
            fail_closed_deny(f"Internal exception inspecting command safety: {e}. Failing closed.", cmd_str)

        if is_blocked:
            fail_closed_deny(reason, cmd_str)

    # 5. Allow safe execution
    json.dump({"decision": "allow"}, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
