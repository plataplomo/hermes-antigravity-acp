"""Fail-closed subprocess admission for the disposable Gateway fixture.

The original Core scratch pruner enumerates unrelated processes, even with an
empty scratch target. Exact argv/path checks do NOT confine a Python -I child.
Without an independently verified process namespace it must remain BLOCKED.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Sequence

PRUNE_BODY = ("import sys; sys.path[:] = sys.argv[3:]; "
              "import hermes_constants_scratch_detach as d; d.run(*sys.argv[1:3])")

# Core f578714 version fingerprinting probes (issue #28 Hosted diagnosis, spy runs
# run-spy-1794678130 / run-spy-1794677408; sources hermes_cli/version_info.py,
# hermes_cli/boot_bootstrap.py, hermes_cli/main_web_build.py, hermes_cli/plugin_catalog.py,
# tui_gateway/git_probe.py). Verbs alone are unsafe: `branch <name>`/`branch -D`, `tag <name>`
# /`tag -d`, `symbolic-ref <ref> <target>` mutate, and `rev-list --output=<file>` demonstrably
# creates files inside the git child. Admission is the exact confirmed argv shape with bounded
# validated variable parts; anything else -- unknown option, config injection, malformed argv,
# unobserved verb -- defaults to deny. Widening any shape below is a policy change.
GIT_OBJECT_ID = re.compile(r"[0-9a-fA-F]{7,40}")
GIT_CATFILE_COMMIT = re.compile(r"[0-9a-fA-F]{7,40}(?:\^\{commit\})?")
GIT_REVLIST_RANGE = re.compile(r"v[0-9]{1,16}(?:\.[0-9]{1,16}){2}\.\.HEAD")


def readonly_git_verdict(command: Sequence[str], core: Path) -> bool:
    """True only for the exact confirmed read-only git forms; every other argv is refused.

    The admitted set is enumerated verb by verb below and mirrors the spy-recorded Core
    forms. Deny is the default (no block list): a form not spelled out here is refused even
    when the verb itself is read-only.
    """
    if not isinstance(command, (list, tuple)) or not command:
        return False
    try:
        # The observed Core probes use PATH lookup or the fixed system binary.
        # An arbitrary executable merely named "git" is not a read-only git probe.
        if os.fsdecode(command[0]) not in {"git", "/usr/bin/git", "/bin/git"}:
            return False
        args = [os.fsdecode(value) for value in command[1:]]
    except (TypeError, ValueError):
        return False
    no_locks = args[:1] == ["--no-optional-locks"]
    if no_locks:
        args = args[1:]
    if args[:1] == ["-C"]:
        if len(args) < 3:
            return False
        try:
            if Path(args[1]).resolve() != core.resolve():
                return False
        except OSError:
            return False
        args = args[2:]
    if not args:
        return False
    verb, flags = args[0], args[1:]
    if verb == "rev-parse":
        # version_info.py:210/256/375, boot_bootstrap.py:49, git_probe.py:38.
        return flags in (["HEAD"], ["--short=7", "HEAD"], ["--short", "HEAD"])
    if verb == "rev-list":
        # version_info.py:252. --count only: --output=<file> writes, --objects/--all stream
        # the whole object graph, and git's prefix spelling (--out) never reaches an admit.
        return (len(flags) == 2 and flags[0] == "--count"
                and bool(GIT_REVLIST_RANGE.fullmatch(flags[1])))
    if verb == "describe":
        # version_info.py:105, exact flag order and bounded --match glob.
        return flags == ["--tags", "--long", "--match", "v2[0-9][0-9][0-9].*", "HEAD"]
    if verb == "cat-file":
        # main_web_build.py:64 existence probe; -e prints nothing and writes nothing.
        # -p/--batch variants stream object payloads: not confirmed, not admitted.
        return (len(flags) == 2 and flags[0] == "-e"
                and bool(GIT_CATFILE_COMMIT.fullmatch(flags[1])))
    if verb == "status":
        # Without --no-optional-locks git refreshes the index, a write outside the root
        # that the in-process audit cannot observe in the git child.
        # version_info.py:226-228: --porcelain, plus -uno on the include_untracked=False path.
        return no_locks and flags in (["--porcelain"], ["--porcelain", "-uno"])
    if verb == "log":
        # version_info.py:214 and plugin_catalog.py:490 use these two fixed forms.
        return flags in (["-1", "--format=%ct", "HEAD"], ["-1", "--format=%ct", "--", "plugin-catalog"])
    if verb == "diff":
        # main_web_build.py:69 deleted-files listing: fixed read-only flag order, first rev
        # an object id, tip HEAD. --ext-diff/--textconv/--output never match this shape.
        return (len(flags) == 6
                and flags[:4] == ["--name-only", "--no-renames", "--diff-filter=D", "-z"]
                and (flags[4] == "HEAD" or bool(GIT_OBJECT_ID.fullmatch(flags[4])))
                and flags[5] == "HEAD")
    if verb == "branch":
        return flags == ["--show-current"]
    if verb == "tag":
        return flags == ["--merged", "HEAD", "--list", "v[0-9]*"]
    return False


def canonical_owned_path(value: str, root: Path) -> Path | None:
    """Require exact absolute spelling, no dot segments, aliases or symlink components."""
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        return None
    path = Path(value)
    if value != os.fspath(path) or any(part in {".", ".."} for part in path.parts):
        return None
    try:
        if not path.is_relative_to(root) or path.resolve(strict=True) != path:
            return None
        if any(component.is_symlink() for component in (path, *path.parents)):
            return None
        if path.stat().st_uid != os.getuid():
            return None
    except (OSError, RuntimeError):
        return None
    return path


def scratch_command_verdict(
    executable: str, argv: Sequence[str], root: Path, core: Path, python: str,
    expected_sys_path: Sequence[str],
) -> str:
    """Check original Core argv precisely, then refuse its unconfined process scan.

    No opt-in flag can manufacture namespace proof. A future isolated-runner
    implementation needs independently exercised confinement, not another boolean.
    """
    if not isinstance(argv, (list, tuple)) or len(argv) != 7 + len(expected_sys_path):
        return "scratch_argv_mismatch"
    if executable != python or argv[0] != python:
        return "scratch_executable_mismatch"
    try:
        # Interpreter symlinks are normal venv launchers, but the exact launcher and
        # resolved executable must be the source-attested running interpreter.
        if Path(executable).resolve(strict=True) != Path(python).resolve(strict=True):
            return "scratch_executable_mismatch"
    except OSError:
        return "scratch_executable_missing"
    if list(argv[1:5]) != ["-I", "-B", "-c", PRUNE_BODY]:
        return "scratch_argv_mismatch"
    target = canonical_owned_path(argv[5], root)
    targets = {root / "hermes" / "cache" / "scratch",
               root / "hermes" / "profiles" / "phasec" / "cache" / "scratch"}
    if target not in targets:
        return "scratch_target_escape_or_alias"
    if list(argv[7:]) != list(expected_sys_path) or not expected_sys_path or expected_sys_path[0] != str(core):
        return "scratch_import_path_mismatch"
    # lineage in argv[6] includes ancestors outside this fixture. Passing through the
    # original command allows process_iter over the HOST: a target-path check cannot
    # grant the stronger no-outside-process-access property.
    return "scratch_process_namespace_unverified"


def shutdown_command_verified(executable: str, argv: Sequence[str], core: Path, pid: int) -> bool:
    """Match only the original source's literal/f-string diagnostic, never eval it."""
    if (len(argv) != 5 or list(argv[1:4]) != ["5", "bash", "-c"] or argv[0] != executable
            or executable not in {"/usr/bin/timeout", "/bin/timeout"}
            or Path(executable).resolve() != Path("/usr/bin/timeout").resolve()):
        return False
    try:
        source = ast.parse((core / "gateway" / "shutdown_forensics.py").read_text())
        function = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                        and node.name == "_async_diagnostic_script")
        expression = next(node.value for node in function.body if isinstance(node, ast.Return))
        if not isinstance(expression, ast.JoinedStr):
            return False
        for signum in ("SIGINT", "SIGTERM"):
            parts = []
            for node in expression.values:
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    parts.append(node.value)
                elif (isinstance(node, ast.FormattedValue) and isinstance(node.value, ast.Name)
                      and node.value.id in {"signal_name", "self_pid"}
                      and node.conversion == -1 and node.format_spec is None):
                    parts.append(signum if node.value.id == "signal_name" else str(pid))
                else:
                    return False
            if argv[4] == "".join(parts):
                return True
    except (OSError, SyntaxError, StopIteration):
        return False
    return False
