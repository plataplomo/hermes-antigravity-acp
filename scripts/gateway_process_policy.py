"""Fail-closed subprocess admission for the disposable Gateway fixture.

The original Core scratch pruner enumerates unrelated processes, even with an
empty scratch target. Exact argv/path checks do NOT confine a Python -I child.
Without an independently verified process namespace it must remain BLOCKED.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Sequence

# Source-reviewed Core startup mutations at 5e9c0cd. Identifiers carry no
# environment names or values. This map is diagnostic, never an admission list.
SYSTEMCTL_ENV_IDS = {
    "AI_AGENT": "a", "HERMES_AGENT": "b", "PYTHONUTF8": "c", "PYTHONIOENCODING": "d",
    "NO_COLOR": "e", "_HERMES_GATEWAY": "f", "HERMES_QUIET": "g", "HERMES_TURN_LEASE_TIMEOUT": "h",
    "XDG_RUNTIME_DIR": "i", "HERMES_HOME": "j", "HERMES_REDACT_SECRETS": "k",
    "HERMES_MAX_ITERATIONS": "l", "TERMINAL_ENV": "m", "MALLOC_ARENA_MAX": "n",
}
SYSTEMCTL_ENV_TOKENS = frozenset(
    f"env_{identifier}_{change}" for identifier in SYSTEMCTL_ENV_IDS.values() for change in ("add", "change", "delete")
) | {"env_unknown"}

# Only these literal tokens may leave the disposable runner as refusal diagnostics.
DIAGNOSTIC_EXECUTABLES = frozenset({"python", "git", "sh", "bash", "dash", "uname", "which", "ps", "rg",
                                    "timeout", "gtimeout", "lsof", "hostname", "stty", "tty", "systemctl",
                                    "loginctl", "launchctl", "journalctl", "systemctl_status_user",
                                    "systemctl_status_system", "systemctl_block_shape", "systemctl_block_env_type",
                                    "systemctl_block_path", "systemctl_block_env", "systemctl_block_env_core_markers",
                                    "systemctl_block_env_unsafe",
                                    "systemctl_block_cwd", "systemctl_block_runtime", "systemctl_block_bus",
                                    "systemctl_block_binary", "systemctl_block_error", "other"}) | SYSTEMCTL_ENV_TOKENS
DIAGNOSTIC_MISMATCHES = frozenset({"executable_argv0", "unapproved_executable", "both"})
DIAGNOSTIC_CORE_FILES = {
    "gateway/run.py": "gateway_run", "gateway/run_shutdown.py": "gateway_run_shutdown",
    "gateway/shutdown_forensics.py": "gateway_shutdown_forensics", "gateway/status.py": "gateway_status",
    "hermes_cli/main.py": "cli_main", "hermes_cli/gateway.py": "cli_gateway",
    "hermes_cli/version_info.py": "cli_version_info", "hermes_cli/boot_bootstrap.py": "cli_boot_bootstrap",
    "hermes_cli/main_web_build.py": "cli_main_web_build", "hermes_cli/plugin_catalog.py": "cli_plugin_catalog",
    "hermes_constants_scratch.py": "scratch", "hermes_constants_scratch_detach.py": "scratch_detach",
    "tui_gateway/git_probe.py": "tui_git_probe", "run_agent.py": "run_agent",
}
DIAGNOSTIC_GATEWAY_FUNCTIONS = {
    "_get_service_pids": "cli_gateway_service_pids", "_get_parent_pid": "cli_gateway_parent_pid",
    "_scan_gateway_pids": "cli_gateway_scan_pids", "_run_systemctl": "cli_gateway_systemctl",
    "_launchd_print_service_pid": "cli_gateway_launchd_print", "_launchd_service_registered": "cli_gateway_launchd_registered",
    "get_systemd_linger_status": "cli_gateway_linger_status", "_loginctl_enable_linger": "cli_gateway_linger_enable",
    "systemd_status": "cli_gateway_systemd_status", "_spawn_gateway_restart_watcher": "cli_gateway_restart_watcher",
}
DIAGNOSTIC_CALLSITES = frozenset((*DIAGNOSTIC_CORE_FILES.values(), *DIAGNOSTIC_GATEWAY_FUNCTIONS.values(),
                                  "cli_gateway_systemd_operational", "other"))
DIAGNOSTIC_MARKER = "PHASEC_REFUSAL_DIAGNOSTIC"


def safe_diagnostic(value: object) -> tuple[str, str, str] | None:
    if not isinstance(value, (list, tuple)) or len(value) != 3 or not all(isinstance(v, str) for v in value):
        return None
    executable, mismatch, callsite = value
    if (executable not in DIAGNOSTIC_EXECUTABLES or mismatch not in DIAGNOSTIC_MISMATCHES
            or callsite not in DIAGNOSTIC_CALLSITES):
        return None
    return executable, mismatch, callsite


def mismatch_diagnostic(executable: object, argv0: object, python: str, core: Path, frames: list,
                        command=None) -> tuple[str, str, str]:
    """Map inputs and Core frames to constants; never publish source strings or paths."""
    first, actual = str(argv0), str(executable)
    name = Path(os.fsdecode(argv0)).name
    category = ("python" if first == python or name in {"python", "python3", "python3.14"}
                else name if name in DIAGNOSTIC_EXECUTABLES else "other")
    mismatch_argv = actual != first
    mismatch_executable = first != python and name != "git"
    mismatch = ("both" if mismatch_argv and mismatch_executable else
                "executable_argv0" if mismatch_argv else "unapproved_executable")
    callsite = "other"
    for frame in reversed(frames):
        for path, token in DIAGNOSTIC_CORE_FILES.items():
            if frame.filename == str(core / path):
                callsite = (DIAGNOSTIC_GATEWAY_FUNCTIONS.get(frame.name, token)
                            if token == "cli_gateway" else token)
                break
        if callsite != "other":
            break
    if category == "systemctl":
        if command == ["systemctl", "--user", "is-system-running"]:
            category = "systemctl_status_user"
        elif command == ["systemctl", "is-system-running"]:
            category = "systemctl_status_system"
    if callsite == "cli_gateway_systemctl" and any(
        frame.filename == str(core / "hermes_cli/gateway.py") and frame.name == "_systemd_operational"
        for frame in frames
    ):
        callsite = "cli_gateway_systemd_operational"
    return category, mismatch, callsite


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


# A read-only argv does not make the git *process* read-only. git selects its repository
# from the launch cwd, resolves helpers through PATH and GIT_EXEC_PATH, and can exec
# external programs from inherited configuration -- none of which argv spelling constrains.
# The envelope's audit hook sees all three only as Popen arguments, so admission pins the
# launch context too. Reproduced against real git in evidence/probe_admitted_git_vectors.py:
# a PATH swap runs a foreign binary, GIT_TRACE writes a file, and a hostile repository chosen
# by the Popen cwd alone executes core.fsmonitor -- all under argv the shape policy admits.
# Core's version_info.py:63 probes pass cwd= with no -C, so cwd is the only repo selector.
GIT_SYSTEM_EXECUTABLES = ("/usr/bin/git", "/bin/git")

# git settings that name a program or hook to run. The values are the inert spellings Core's
# own noninteractive_git_env() produces (_subprocess_compat.py:289-303); the same key with
# any other value is an execution channel. Keys are lower-cased (git folds them); values are
# compared exactly, because git does NOT fold configuration values.
GIT_EXEC_CAPABLE_CONFIG = {
    "credential.helper": frozenset({""}),
    "core.askpass": frozenset({""}),
    "core.fsmonitor": frozenset({"false", ""}),
    "core.hookspath": frozenset({os.devnull, "/dev/null"}),
    "core.pager": frozenset({"cat"}),
    "core.editor": frozenset({"true"}),
    "sequence.editor": frozenset({"true"}),
    "diff.external": frozenset({""}),
    "core.sshcommand": frozenset({"ssh -o BatchMode=yes"}),
}
GIT_EXEC_CAPABLE_CONFIG_PREFIXES = ("filter.", "alias.", "difftool.", "mergetool.",
                                    "credential.", "pager.")
GIT_EXEC_CAPABLE_CONFIG_SUFFIXES = (".process", ".clean", ".smudge", ".textconv",
                                    ".command", ".hookpath")
GIT_EXEC_CAPABLE_CONFIG_KEYS = frozenset({"core.attributesfile"})
# git config directives that pull further files into the effective configuration. The include
# graph is not modelled here, so a config that widens itself is not admitted: reproduced with
# real git, `[include] path=<file>` (and the GIT_CONFIG_KEY_0=include.path injection form)
# loads a second file whose core.fsmonitor git then execs, while a scan of the first file
# alone sees nothing executable.
GIT_INCLUDE_PATH_KEY = "include.path"
GIT_INCLUDE_IF_PREFIX = "includeif."
GIT_CONFIG_SECTION = re.compile(r'^([^\s"\]]+)(?:\s+"([^"]*)")?\s*$')

# Variables that relocate the repository or redirect git's config lookup outright.
GIT_RELOCATING_ENV = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG_PARAMETERS",
    "GIT_ATTR_SOURCE", "GIT_CEILING_DIRECTORIES", "GIT_SHELL",
})
# Config-channel variables, admitted only in the inert form Core itself sets.
GIT_CONFIG_ENV = {
    "GIT_CONFIG_GLOBAL": frozenset({os.devnull, "/dev/null"}),
    "GIT_CONFIG_SYSTEM": frozenset({os.devnull, "/dev/null"}),
    "GIT_CONFIG_NOSYSTEM": frozenset({"1"}),
}
# Program-selection and behaviour variables, admitted only at Core's own values.
GIT_PROGRAM_ENV = {
    "GIT_PAGER": frozenset({"cat"}), "PAGER": frozenset({"cat"}),
    "GIT_EDITOR": frozenset({"true"}), "GIT_SEQUENCE_EDITOR": frozenset({"true"}),
}
GIT_INERT_ENV = {
    "GIT_TERMINAL_PROMPT": frozenset({"0"}), "GCM_INTERACTIVE": frozenset({"Never"}),
    "GIT_NO_LAZY_FETCH": frozenset({"1"}), "GIT_OPTIONAL_LOCKS": frozenset({"0", "1"}),
    "GIT_ATTR_NOSYSTEM": frozenset({"1"}),
}
GIT_CONFIG_INJECT_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
# Structural members of the config-injection block: validated as a set, not by value table.
GIT_STRUCTURAL_ENV = frozenset({"GIT_CONFIG_COUNT"})
# Everything a probe may legitimately add or change. Any other variable it introduces is an
# unverified execution or relocation channel -- reproduced: LD_PRELOAD, LD_LIBRARY_PATH,
# EDITOR and SSH_ASKPASS all reached an admitted git child under a name-scoped screen.
GIT_PROBE_ENV = {**GIT_CONFIG_ENV, **GIT_PROGRAM_ENV, **GIT_INERT_ENV}
# The only git config keys the GIT_CONFIG_KEY_n channel may carry: Core's hardening overrides
# (_subprocess_compat.py:289-303) plus the safe.directory replay it appends. Deny by default,
# so an injected key cannot lean on "not known to be dangerous".
GIT_CONFIG_OVERRIDE_KEYS = frozenset(GIT_EXEC_CAPABLE_CONFIG) | {"core.untrackedcache",
                                                                 "safe.directory"}
# The environment the envelope process was launched with. The policed Gateway runs in-process
# and can mutate os.environ freely -- CPython emits no audit event for that -- so the diff that
# decides what a probe *changed* must be taken against this snapshot. Reproduced: with the
# baseline read live, `os.environ["GIT_DIR"] = ...` followed by a probe that inherits the
# environment produced an admit, while the same GIT_DIR passed explicitly was refused.
BASELINE_ENV: dict = dict(os.environ)


def _config_pair_verdict(env: dict) -> str:
    """Validate the GIT_CONFIG_COUNT block: Core's hardening replay channel, nothing else."""
    names = [name for name in env if name.startswith(GIT_CONFIG_INJECT_PREFIXES)]
    if not names:
        return "" if "GIT_CONFIG_COUNT" not in env else "git_config_injection"
    try:
        count = int(env["GIT_CONFIG_COUNT"])
    except (KeyError, ValueError):
        return "git_config_injection"
    if not 0 <= count <= 64:
        return "git_config_injection"
    pairs = {}
    for name in names:
        prefix, _, suffix = name.rpartition("_")
        try:
            index = int(suffix)
        except ValueError:
            return "git_config_injection"
        if prefix not in {"GIT_CONFIG_KEY", "GIT_CONFIG_VALUE"} or not 0 <= index < count:
            return "git_config_injection"
        pairs.setdefault(index, {})[prefix] = env[name]
    if len(pairs) != count or any(set(pair) != {"GIT_CONFIG_KEY", "GIT_CONFIG_VALUE"}
                                  for pair in pairs.values()):
        return "git_config_injection"
    for pair in pairs.values():
        name = pair["GIT_CONFIG_KEY"].strip().lower()
        value = pair["GIT_CONFIG_VALUE"].strip().strip('"')
        if name not in GIT_CONFIG_OVERRIDE_KEYS:
            return "git_config_injection"
        if name not in GIT_EXEC_CAPABLE_CONFIG:
            continue  # safe.directory / core.untrackedcache: admitted, and not an exec channel
        if value not in GIT_EXEC_CAPABLE_CONFIG[name]:
            return "git_config_injection"
    return ""


def _config_section_header(body: str) -> str | None:
    """Normalise a git section header body, or None when git itself would reject it."""
    match = GIT_CONFIG_SECTION.match(body.strip())
    if match is None:
        return None
    section = match.group(1).lower()
    subsection = match.group(2)
    return f"{section}.{subsection.lower()}" if subsection else section


def _config_text_exec_capable(text: str) -> bool:
    """True when git config text names a program/hook git would run, in a non-inert value."""
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            # git ends the header at the first ']' -- and then keeps parsing the *same line*
            # as an assignment. Reproduced against real git: a single line
            # `[core] fsmonitor = <hook>` is a setting git reports and executes, while a parser
            # that consumed only the header saw an inert file. A comment after the bracket is
            # still just a comment.
            end = line.find("]")
            parsed = _config_section_header(line[1:end]) if end > 0 else None
            if parsed is None:
                return True  # git rejects this file too; refuse rather than guess a section
            section = parsed
            line = line[end + 1:].lstrip()
            if not line or line.startswith(("#", ";")):
                continue
        if "=" not in line:
            return True  # git rejects this line too; refuse rather than guess what it sets
        option, _, value = line.partition("=")
        name = f"{section}.{option.strip().lower()}"
        value = value.strip().strip('"')
        if _config_key_widens_or_executes(name):
            if name not in GIT_EXEC_CAPABLE_CONFIG or value not in GIT_EXEC_CAPABLE_CONFIG[name]:
                return True
    return False


def _config_key_widens_or_executes(name: str) -> bool:
    """True for a config key that runs a program or silently widens the effective config."""
    if name in GIT_EXEC_CAPABLE_CONFIG or name in GIT_EXEC_CAPABLE_CONFIG_KEYS:
        return True
    if name.startswith(GIT_EXEC_CAPABLE_CONFIG_PREFIXES):
        return True
    if name.endswith(GIT_EXEC_CAPABLE_CONFIG_SUFFIXES):
        return True
    return (name == GIT_INCLUDE_PATH_KEY
            or (name.startswith(GIT_INCLUDE_IF_PREFIX) and name.endswith(".path")))


def _config_file_exec_capable(path: Path) -> bool:
    """An unreadable config file is treated as capable: it cannot be cleared, so it is not admitted."""
    try:
        if not path.is_file() or path.stat().st_size == 0:
            return False
        return _config_text_exec_capable(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, UnicodeError):
        return True


def _repo_config_paths(repo: Path) -> list | None:
    """The repository-level config files git will load, following a worktree `gitdir:` pointer.

    A linked worktree has no config of its own. git loads `<commondir>/config`, where the
    common directory is named by the `commondir` file inside the worktree gitdir, plus
    `<gitdir>/config.worktree` when extensions.worktreeConfig is enabled. Reproduced: scanning
    only `<gitdir>/config` — a file that does not exist for a linked worktree — admitted a
    probe whose common config carried `core.fsmonitor`, and real git executed it. All three
    spellings are scanned rather than probing the extension, so the set is a superset of what
    git will read and a missing file is simply inert.
    """
    git_dir = repo / ".git"
    try:
        if git_dir.is_file():
            text = git_dir.read_text(encoding="utf-8", errors="replace").strip()
            if not text.startswith("gitdir:"):
                return None
            target = Path(text.split(":", 1)[1].strip())
            git_dir = target if target.is_absolute() else (repo / target).resolve()
    except (OSError, UnicodeError):
        return None
    paths = [git_dir / "config", git_dir / "config.worktree"]
    try:
        common = git_dir / "commondir"
        if common.is_file():
            value = common.read_text(encoding="utf-8", errors="replace").strip()
            if not value:
                return None
            target = Path(value)
            common_dir = target if target.is_absolute() else (git_dir / target).resolve()
            paths.append(common_dir / "config")
    except (OSError, UnicodeError):
        return None
    return paths


def _effective_config_exec_capable(child: dict, repo: Path) -> bool:
    """Every config file the admitted git child will actually load, not just the repo's.

    Reproduced: with the container's writable fixture HOME and an inherited environment, a
    planted ~/.gitconfig carrying core.fsmonitor makes the admitted read-only
    `--no-optional-locks status --porcelain` execute an external program. Pinning
    GIT_CONFIG_GLOBAL to the null device is what keeps Core's own probes out of this path, so
    the files are only consulted when the child does not pin them away.
    """
    candidates = []
    repo_configs = _repo_config_paths(repo)
    if repo_configs is None:
        return True
    candidates.extend(repo_configs)
    if child.get("GIT_CONFIG_GLOBAL") not in (os.devnull, "/dev/null"):
        # HOME and XDG_CONFIG_HOME are already required to equal the baseline, so the child's
        # own values are the ones git will use; the live os.environ is not a trustworthy read.
        home = Path(child.get("HOME") or "/nonexistent")
        candidates.append(home / ".gitconfig")
        candidates.append(Path(child.get("XDG_CONFIG_HOME") or home / ".config") / "git" / "config")
    system = child.get("GIT_CONFIG_SYSTEM") or None
    if child.get("GIT_CONFIG_NOSYSTEM") != "1":
        candidates.append(Path(system) if system not in (None, os.devnull, "/dev/null")
                          else Path("/etc/gitconfig"))
    return any(_config_file_exec_capable(path) for path in candidates)


def _system_git_realpaths() -> frozenset:
    paths = set()
    for candidate in GIT_SYSTEM_EXECUTABLES:
        try:
            paths.add(Path(candidate).resolve(strict=True))
        except OSError:
            continue
    return frozenset(paths)


SYSTEM_GIT_REALPATHS = _system_git_realpaths()


def git_probe_context_verdict(command: Sequence[str], core: Path, cwd, env,
                              baseline: dict | None = None) -> str:
    """Return "" when an argv-admitted git probe is also safe to launch; else a fixed reason.

    `readonly_git_verdict` proves the argv shape. It cannot see which binary PATH resolves,
    which repository the launch cwd selects, or which configuration and helpers the child
    inherits -- and git takes writes and external program execution from all three. This is
    the other half of the same admission decision, not a separate framework: every check
    below closes one reproduced channel, and unknown values deny by default.

    `baseline` is the environment the envelope was launched with (`BASELINE_ENV` by default).
    It is not read from live `os.environ`: the policed Gateway shares this process and can
    rewrite `os.environ` with no audit event at all.
    """
    if not isinstance(command, (list, tuple)) or not command:
        return "git_argv_unreadable"
    if env is not None and (not isinstance(env, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in env.items())):
        return "git_environment_unreadable"
    child = dict(os.environ) if env is None else env
    ambient = BASELINE_ENV if baseline is None else baseline
    changed = {name: value for name, value in child.items() if ambient.get(name) != value}
    # PATH and identity are what select the binary and the user's ~/.gitconfig. They are
    # never a probe parameter, in either direction.
    for name, reason in (("PATH", "git_path_overridden"),
                         ("HOME", "git_home_overridden"),
                         ("XDG_CONFIG_HOME", "git_home_overridden")):
        if child.get(name) != ambient.get(name):
            return reason
    if any(name.startswith("GIT_TRACE") for name in changed):
        return "git_trace_enabled"
    if "GIT_EXEC_PATH" in changed:
        return "git_exec_path_overridden"
    if GIT_RELOCATING_ENV & set(changed):
        return "git_config_injection"
    for name, allowed in GIT_CONFIG_ENV.items():
        if name in changed and child[name] not in allowed:
            return "git_config_injection"
    verdict = _config_pair_verdict({name: child[name] for name in changed})
    if verdict:
        return verdict
    # Deny by default over everything the probe introduced: a variable that merely exists in
    # the baseline is the driver's choice, one the caller adds or edits is not. Screening only
    # GIT_* names let LD_PRELOAD, LD_LIBRARY_PATH, EDITOR and SSH_ASKPASS reach the child.
    for name in changed:
        if name.startswith(GIT_CONFIG_INJECT_PREFIXES) or name in GIT_STRUCTURAL_ENV:
            continue  # validated as a block by _config_pair_verdict above
        allowed = GIT_PROBE_ENV.get(name)
        if allowed is None or child[name] not in allowed:
            return "git_environment_override_unverified"
    # Dropping a git-relevant variable is an edit too (it re-enables a default git would use).
    if any(name not in child for name in ambient
           if name.startswith("GIT_") or name in GIT_PROBE_ENV):
        return "git_environment_override_unverified"
    try:
        argv0 = os.fsdecode(command[0])
        resolved = argv0 if "/" in argv0 else shutil.which(argv0)
        if resolved is None:
            return "git_executable_untrusted"
        executable = Path(resolved).resolve(strict=True)
        stat = executable.stat()
    except (OSError, TypeError, ValueError):
        return "git_executable_untrusted"
    if executable not in SYSTEM_GIT_REALPATHS or stat.st_uid == os.getuid() \
            or stat.st_mode & 0o022:
        return "git_executable_untrusted"
    args = [os.fsdecode(value) for value in command[1:]]
    target = os.getcwd() if cwd is None else os.fsdecode(cwd)
    if args[:1] == ["-C"] and len(args) > 1:
        target = args[1]
    try:
        if Path(target).resolve(strict=True) != core.resolve(strict=True):
            return "git_probe_repo_unpinned"
        repo = Path(target).resolve(strict=True)
    except (OSError, TypeError, ValueError):
        return "git_probe_repo_unpinned"
    if _effective_config_exec_capable(child, repo):
        return "git_effective_config_exec_capable"
    return ""


def _trusted_systemctl(path: str) -> bool:
    """The immutable, root-owned runner executable, never a same-named shim."""
    try:
        target = Path(path).resolve(strict=True)
        expected = Path("/usr/bin/systemctl").resolve(strict=True)
        info = target.stat()
        return target == expected and info.st_uid == 0 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022
    except (OSError, RuntimeError):
        return False


def systemctl_status_reason(executable, command, cwd, env, root: Path, confined: bool, *, baseline=None,
                            diagnostics=None) -> str:
    """Fixed refusal class for the two observed Core probes; empty means admitted.

    Child audit hooks are not inherited. Network/bus isolation relies on the verified
    Docker boundary; the fixture has no system bus and refuses any local bus endpoint.
    """
    if (not confined or executable != "systemctl" or not isinstance(command, list)
            or command not in (["systemctl", "is-system-running"], ["systemctl", "--user", "is-system-running"])):
        return "shape"
    if env is not None and (not isinstance(env, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in env.items())):
        return "env_type"
    child = dict(os.environ) if env is None else env
    ambient = BASELINE_ENV if baseline is None else baseline
    # Core gateway.py appends missing standard service-search paths on import.
    # Permit only that deterministic suffix, then independently pin the resolved binary.
    baseline_path = ambient.get("PATH")
    if not isinstance(baseline_path, str):
        return "path"
    missing = {"/bin", "/usr/bin", "/usr/sbin", "/sbin"} - set(baseline_path.split(os.pathsep))
    core_path = baseline_path + os.pathsep + os.pathsep.join(sorted(missing)) if missing else baseline_path
    if (child.get("PATH") not in {baseline_path, core_path}
            or any(not item or not os.path.isabs(item) for item in child["PATH"].split(os.pathsep))):
        return "path"
    if {k: v for k, v in child.items() if k != "PATH"} != {k: v for k, v in ambient.items() if k != "PATH"}:
        if diagnostics is not None:
            for key in set(child) | set(ambient):
                if key == "PATH" or key in child and key in ambient and child[key] == ambient[key]:
                    continue
                identifier = SYSTEMCTL_ENV_IDS.get(key)
                if identifier is None:
                    diagnostics.add("env_unknown")
                else:
                    change = "add" if key not in ambient else "delete" if key not in child else "change"
                    diagnostics.add(f"env_{identifier}_{change}")
        # Diagnostic classification only: no environment name or value is emitted.
        markers = {"AI_AGENT": "hermes-agent", "HERMES_AGENT": "true", "PYTHONUTF8": "1",
                   "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "_HERMES_GATEWAY": "1",
                   "HERMES_QUIET": "1", "HERMES_TURN_LEASE_TIMEOUT": "5"}
        changes = {key for key in set(child) | set(ambient) if key != "PATH" and child.get(key) != ambient.get(key)}
        if changes and all(key not in ambient and key in markers and child.get(key) == markers[key] for key in changes):
            return "env_core_markers"
        return "env"
    if any(name.startswith("SYSTEMD_") or name.startswith("DBUS_")
           or name in {"LD_PRELOAD", "LD_LIBRARY_PATH"} for name in child):
        return "env_unsafe"
    try:
        # PATH entries inside the writable fixture cannot be trusted between audit and exec.
        if any(Path(item).resolve().is_relative_to(root) for item in child["PATH"].split(os.pathsep)):
            return "path"
        if Path(cwd if cwd is not None else os.getcwd()).resolve(strict=True) != root:
            return "cwd"
        runtime = root / "runtime"
        if child.get("XDG_RUNTIME_DIR") != str(runtime) or runtime.resolve(strict=True) != runtime:
            return "runtime"
        if any(os.path.lexists(path) for path in (runtime / "bus", runtime / "systemd" / "private",
                                                  "/run/dbus/system_bus_socket", "/run/systemd/private")):
            return "bus"
        resolved = shutil.which("systemctl", path=child.get("PATH", ""))
        return "" if resolved is not None and _trusted_systemctl(resolved) else "binary"
    except (OSError, TypeError, ValueError, RuntimeError):
        return "error"


def systemctl_status_verdict(executable, command, cwd, env, root: Path, confined: bool, *, baseline=None) -> bool:
    return not systemctl_status_reason(executable, command, cwd, env, root, confined, baseline=baseline)


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
