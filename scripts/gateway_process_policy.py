"""Fail-closed subprocess admission for the disposable Gateway fixture.

The original Core scratch pruner enumerates unrelated processes, even with an
empty scratch target. Exact argv/path checks do NOT confine a Python -I child.
Without an independently verified process namespace it must remain BLOCKED.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Sequence

PRUNE_BODY = ("import sys; sys.path[:] = sys.argv[3:]; "
              "import hermes_constants_scratch_detach as d; d.run(*sys.argv[1:3])")

# Core e8bef69f version fingerprinting probes (issue #28 Hosted diagnosis). Widening this
# set beyond read-only plumbing verbs is a policy change, not a compatibility fix.
READONLY_GIT_SUBCOMMANDS = frozenset({"rev-parse", "describe", "status", "symbolic-ref",
                                      "log", "diff", "tag", "branch", "rev-list"})


def readonly_git_verdict(command: Sequence[str], core: Path) -> bool:
    """True only for read-only git probes; mutation verbs and foreign -C targets stay refused."""
    if not isinstance(command, (list, tuple)) or not command:
        return False
    if Path(os.fsdecode(command[0])).name != "git":
        return False
    args = [os.fsdecode(value) for value in command[1:]]
    if args[:1] == ["--no-optional-locks"]:
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
    return bool(args) and args[0] in READONLY_GIT_SUBCOMMANDS


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
