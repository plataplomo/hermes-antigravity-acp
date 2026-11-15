"""Exact scratch argv/path negatives. No Core imports, GC, namespace or host process scans."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

from scripts.gateway_process_policy import (PRUNE_BODY, canonical_owned_path,
                                            git_probe_context_verdict, readonly_git_verdict,
                                            scratch_command_verdict)

# The exact object id from the issue #28 Hosted spy (run-spy-1794678130).
SPY_SHA = "e8bef69f505554154c158aed0a27c429c11791c0"

# A hermetic git identity for throwaway fixture repos; never the operator's config.
_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1", "HOME": os.devnull, "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


class GitProbeContextTests(unittest.TestCase):
    """argv shape alone cannot make a git child read-only: the launch context decides.

    Reproduced against real git in a temp repo (evidence/probe_admitted_git_vectors.py):
    a PATH swap runs a foreign binary, GIT_TRACE*/GIT_TRACE2_EVENT write a file, and a
    hostile repo chosen only by the Popen cwd executes core.fsmonitor -- all under argv
    the shape policy admits. Core's version_info.py:63 probes pass cwd= with no -C, so
    the cwd is the only thing selecting the repository.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-git-ctx-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        # The container's fixture HOME is a fresh directory; the operator's ~/.gitconfig is
        # not part of this policy's baseline, so pin a clean identity home for the run.
        home = self.base / "os-home"
        home.mkdir()
        patcher = mock.patch.dict(os.environ, {"HOME": str(home), "XDG_CONFIG_HOME": ""})
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"):
            os.environ.pop(key, None)  # patch.dict restores them on stop
        self.home = home
        self.core = self.base / "core"
        self.core.mkdir()
        for step in (["init", "-q", str(self.core)], ["-C", str(self.core), "add", "f"],
                     ["-C", str(self.core), "commit", "-qm", "c1"]):
            if step[0] == "init":
                (self.core / "f").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", *step], check=True, capture_output=True, env=_GIT_ENV)

    def verdict(self, argv, cwd=None, env=None, command=None, baseline=None, repo=None):
        # The baseline is the environment the envelope was launched with; in-process mutation
        # of os.environ is a separate case tested explicitly below, so each case here states
        # its own starting environment.
        return git_probe_context_verdict(command or ["git", *argv], self.core if repo is None
                                         else repo, cwd, env,
                                         dict(os.environ) if baseline is None else baseline)

    def test_core_probe_shapes_admitted_in_their_real_launch_context(self):
        for argv, cwd, env in (
            (["rev-parse", "HEAD"], self.core, None),
            (["--no-optional-locks", "status", "--porcelain", "-uno"], self.core, None),
            (["-C", str(self.core), "rev-parse", "HEAD"], None, None),
            (["-C", str(self.core), "rev-parse", "HEAD"], None,
             {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
              "GIT_CONFIG_NOSYSTEM": "1", "GIT_PAGER": "cat", "GIT_EDITOR": "true",
              "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
              "GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "core.fsmonitor",
              "GIT_CONFIG_VALUE_0": "false", "GIT_CONFIG_KEY_1": "core.hooksPath",
              "GIT_CONFIG_VALUE_1": os.devnull, "GIT_CONFIG_KEY_2": "safe.directory",
              "GIT_CONFIG_VALUE_2": str(self.core)}),
        ):
            with self.subTest(argv=argv, explicit_env=env is not None):
                self.assertEqual("", self.verdict(argv, cwd=cwd, env=env))

    def test_cwd_must_be_the_pinned_core_checkout(self):
        hostile = self.base / "hostile"
        hostile.mkdir()
        for cwd in (None, self.base, hostile, self.core / "missing"):
            with self.subTest(cwd=str(cwd)):
                self.assertEqual("git_probe_repo_unpinned",
                                 self.verdict(["rev-parse", "HEAD"], cwd=cwd))
        # A -C that disagrees with the launch cwd is not the pinned checkout either.
        self.assertEqual("git_probe_repo_unpinned",
                         self.verdict([], cwd=self.core,
                                      command=["git", "-C", str(hostile), "rev-parse", "HEAD"]))

    def test_path_swap_runs_a_foreign_binary_and_is_refused(self):
        fake = self.base / "bin"
        fake.mkdir()
        marker = self.base / "pwned"
        shim = fake / "git"
        shim.write_text(f"#!/bin/sh\ntouch {marker}\necho {'a' * 40}\n", encoding="utf-8")
        shim.chmod(0o755)
        env = {**os.environ, "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"}
        self.assertEqual("git_path_overridden",
                         self.verdict(["rev-parse", "HEAD"], cwd=self.core, env=env))
        # The refusal is not theoretical: the identical launch really runs the foreign file.
        subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.core, env=env, capture_output=True)
        self.assertTrue(marker.exists())

    def test_absolute_path_named_git_outside_the_system_set_is_refused(self):
        system_git = shutil.which("git")
        if system_git is None:
            self.skipTest("git binary required")
        copy = self.base / "git"
        copy.write_bytes(Path(system_git).read_bytes())
        copy.chmod(0o755)
        self.assertEqual("git_executable_untrusted",
                         self.verdict([], cwd=self.core,
                                      command=[str(copy), "-C", str(self.core), "rev-parse", "HEAD"]))

    def test_trace_exec_path_and_identity_redirection_are_refused(self):
        cases = (
            ("GIT_TRACE", str(self.base / "trace.log"), "git_trace_enabled"),
            ("GIT_TRACE2_EVENT", str(self.base / "t2"), "git_trace_enabled"),
            ("GIT_TRACE_PERFORMANCE", str(self.base / "t3"), "git_trace_enabled"),
            ("GIT_EXEC_PATH", str(self.base), "git_exec_path_overridden"),
            ("GIT_CONFIG_NOSYSTEM", "0", "git_config_injection"),
            ("GIT_CONFIG_GLOBAL", str(self.base / "cfg"), "git_config_injection"),
            ("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=/tmp/x'", "git_config_injection"),
            ("GIT_PAGER", "/tmp/evil", "git_environment_override_unverified"),
            ("GIT_SSH_COMMAND", "/tmp/evil", "git_environment_override_unverified"),
            ("PATH", "/tmp/only", "git_path_overridden"),
            ("HOME", str(self.base), "git_home_overridden"),
            ("XDG_CONFIG_HOME", str(self.base), "git_home_overridden"),
        )
        for key, value, reason in cases:
            with self.subTest(key=key):
                self.assertEqual(reason, self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                                      env={**os.environ, key: value}))

    def test_trace_write_through_an_admitted_probe_is_reproduced_then_refused(self):
        trace = self.base / "trace.log"
        env = {**os.environ, "GIT_TRACE": str(trace)}
        self.assertEqual("git_trace_enabled",
                         self.verdict(["rev-parse", "HEAD"], cwd=self.core, env=env))
        subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.core, env=env, capture_output=True)
        self.assertTrue(trace.is_file() and trace.stat().st_size > 0)

    def test_hostile_repo_selected_only_by_cwd_really_executes_fsmonitor(self):
        hostile = self.base / "hostile"
        hostile.mkdir()
        subprocess.run(["git", "init", "-q", str(hostile)], check=True, capture_output=True,
                       env=_GIT_ENV)
        hook, marker = self.base / "fm.sh", self.base / "fsmonitor-ran"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
        hook.chmod(0o755)
        subprocess.run(["git", "-C", str(hostile), "config", "core.fsmonitor", str(hook)],
                       check=True, capture_output=True, env=_GIT_ENV)
        (hostile / "untracked").write_text("u\n", encoding="utf-8")
        argv = ["--no-optional-locks", "status", "--porcelain"]
        self.assertEqual("git_probe_repo_unpinned", self.verdict(argv, cwd=hostile))
        # Reproduce the execution the policy must refuse; the pinned checkout stays clean.
        subprocess.run(["git", *argv], cwd=hostile, capture_output=True)
        self.assertTrue(marker.exists())
        self.assertEqual("", self.verdict(argv, cwd=self.core))

    def test_exec_capable_config_injection_is_refused_but_core_hardening_is_not(self):
        for name, value in (("core.fsmonitor", "/tmp/evil"), ("core.hooksPath", "/tmp/hooks"),
                            ("core.pager", "/tmp/evil"), ("filter.evil.process", "/tmp/evil"),
                            ("alias.x", "!/tmp/evil"), ("credential.helper", "/tmp/evil")):
            with self.subTest(name=name):
                self.assertEqual("git_config_injection",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                              env={**os.environ, "GIT_CONFIG_COUNT": "1",
                                                   "GIT_CONFIG_KEY_0": name,
                                                   "GIT_CONFIG_VALUE_0": value}))
        for name, value in (("core.fsmonitor", "false"), ("core.hooksPath", os.devnull),
                            ("core.pager", "cat"), ("safe.directory", str(self.core)),
                            ("core.untrackedCache", "false")):
            with self.subTest(hardening=name):
                self.assertEqual("", self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                                  env={**os.environ, "GIT_CONFIG_COUNT": "1",
                                                       "GIT_CONFIG_KEY_0": name,
                                                       "GIT_CONFIG_VALUE_0": value}))

    def test_exec_capable_setting_in_the_pinned_repo_config_is_refused(self):
        config = self.core / ".git" / "config"
        config.write_text(config.read_text(encoding="utf-8") + "[core]\n\tfsmonitor = /tmp/x\n",
                          encoding="utf-8")
        self.assertEqual("git_effective_config_exec_capable",
                         self.verdict(["rev-parse", "HEAD"], cwd=self.core))

    def test_planted_global_config_reaches_an_inherited_probe_and_is_refused(self):
        # Reproduced against real git: with the fixture HOME writable (it lives under the
        # container's only writable mount) and an inherited environment, a planted global
        # config turns the admitted read-only status probe into an external program run.
        hook, marker = self.base / "fm.sh", self.base / "fsmonitor-ran"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
        hook.chmod(0o755)
        self.home.joinpath(".gitconfig").write_text(
            f"[core]\n\tfsmonitor = {hook}\n", encoding="utf-8")
        argv = ["--no-optional-locks", "status", "--porcelain"]
        self.assertEqual("git_effective_config_exec_capable", self.verdict(argv, cwd=self.core))
        subprocess.run(["git", *argv], cwd=self.core, capture_output=True)
        self.assertTrue(marker.exists())
        # Core's own probes pin the global file away, so the same baseline admits them.
        self.assertEqual("", self.verdict(argv, cwd=self.core,
                                          env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                                               "GIT_CONFIG_SYSTEM": os.devnull,
                                               "GIT_CONFIG_NOSYSTEM": "1"}))

    def test_config_include_directive_is_refused_and_really_widens(self):
        # git loads the included file into its effective config, so a scanned file that looks
        # inert is not evidence: reproduced with real git, the included core.fsmonitor runs.
        hook, marker = self.base / "fm.sh", self.base / "fsmonitor-ran"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
        hook.chmod(0o755)
        included = self.base / "extra.cfg"
        included.write_text(f"[core]\n\tfsmonitor = {hook}\n", encoding="utf-8")
        self.home.joinpath(".gitconfig").write_text(
            f"[include]\n\tpath = {included}\n", encoding="utf-8")
        argv = ["--no-optional-locks", "status", "--porcelain"]
        self.assertEqual("git_effective_config_exec_capable", self.verdict(argv, cwd=self.core))
        subprocess.run(["git", *argv], cwd=self.core, capture_output=True)
        self.assertTrue(marker.exists())

    def test_include_injection_through_the_config_block_is_refused(self):
        for name in ("include.path", "includeif.gitdir:/gw.path"):
            with self.subTest(name=name):
                self.assertEqual("git_config_injection",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                              env={**os.environ, "GIT_CONFIG_COUNT": "1",
                                                   "GIT_CONFIG_KEY_0": name,
                                                   "GIT_CONFIG_VALUE_0": str(self.base / "x.cfg")}))

    def test_planted_xdg_config_is_refused(self):
        xdg = self.base / "xdg" / "git"
        xdg.mkdir(parents=True)
        (xdg / "config").write_text("[core]\n\thooksPath = /tmp/hooks\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.base / "xdg")}):
            self.assertEqual("git_effective_config_exec_capable",
                             self.verdict(["rev-parse", "HEAD"], cwd=self.core))

    def test_inert_global_config_is_not_refused(self):
        self.home.joinpath(".gitconfig").write_text(
            "[user]\n\tname = t\n\temail = t@t\n", encoding="utf-8")
        self.assertEqual("", self.verdict(["rev-parse", "HEAD"], cwd=self.core))

    def test_non_git_environment_injection_is_refused(self):
        # A name-scoped screen (GIT_*, PAGER) let all of these reach the admitted git child.
        for key, value in (("LD_PRELOAD", str(self.base / "evil.so")),
                           ("LD_LIBRARY_PATH", str(self.base)),
                           ("EDITOR", str(self.base / "evil")),
                           ("VISUAL", str(self.base / "evil")),
                           ("SSH_ASKPASS", str(self.base / "evil")),
                           ("TMPDIR", str(self.base))):
            with self.subTest(key=key):
                self.assertEqual("git_environment_override_unverified",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                              env={**os.environ, key: value}))

    def test_runtime_environment_mutation_is_not_the_launch_baseline(self):
        # The policed Gateway shares this process and CPython emits no audit event for an
        # os.environ write, so the diff must be against the launch snapshot, not live state.
        snapshot = dict(os.environ)
        os.environ["GIT_DIR"] = str(self.base / "evil.git")
        try:
            self.assertEqual("git_config_injection",
                             self.verdict(["rev-parse", "HEAD"], cwd=self.core, baseline=snapshot))
            os.environ["GIT_TRACE2_PERF"] = str(self.base / "trace")
            self.assertEqual("git_trace_enabled",
                             self.verdict(["rev-parse", "HEAD"], cwd=self.core, baseline=snapshot))
        finally:
            os.environ.pop("GIT_DIR", None)
            os.environ.pop("GIT_TRACE2_PERF", None)

    def test_dropping_a_git_variable_is_an_unverified_edit(self):
        os.environ["GIT_OPTIONAL_LOCKS"] = "0"
        self.addCleanup(os.environ.pop, "GIT_OPTIONAL_LOCKS", None)
        self.assertEqual("git_environment_override_unverified",
                         self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                      env={key: value for key, value in os.environ.items()
                                           if key != "GIT_OPTIONAL_LOCKS"}))

    def test_unknown_key_in_the_config_injection_block_is_refused(self):
        for name in ("core.anything", "credential.https://x.helper", "diff.x.textconv",
                     "core.attributesFile"):
            with self.subTest(name=name):
                self.assertEqual("git_config_injection",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core,
                                              env={**os.environ, "GIT_CONFIG_COUNT": "1",
                                                   "GIT_CONFIG_KEY_0": name,
                                                   "GIT_CONFIG_VALUE_0": "whatever"}))

    def test_config_values_are_compared_case_sensitively(self):
        # git folds config keys but not config values, so `pager = CAT` is not `pager = cat`.
        config = self.core / ".git" / "config"
        config.write_text(config.read_text(encoding="utf-8") + "[core]\n\tpager = CAT\n",
                          encoding="utf-8")
        self.assertEqual("git_effective_config_exec_capable",
                         self.verdict(["rev-parse", "HEAD"], cwd=self.core))

    def test_section_header_variants_git_accepts_are_still_parsed(self):
        config = self.core / ".git" / "config"
        original = config.read_text(encoding="utf-8")
        self.addCleanup(config.write_text, original, "utf-8")
        for header, option, value in (("[core] ; trailing comment", "fsmonitor", "/tmp/x"),
                                      ("[core]\t", "fsmonitor", "/tmp/x"),
                                      ('[filter\t"evil"]', "process", "/tmp/x"),
                                      ("[core]", "hooksPath", "/tmp/hooks")):
            with self.subTest(header=header):
                config.write_text(original + f"{header}\n\t{option} = {value}\n",
                                  encoding="utf-8")
                self.assertEqual("git_effective_config_exec_capable",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core))

    def test_assignment_on_the_section_header_line_is_still_parsed(self):
        # git keeps parsing the same line after the header's closing bracket. Reproduced
        # against real git: a single `[core] fsmonitor = <hook>` line is reported by
        # `git config --get core.fsmonitor` and executed by the admitted read-only probe,
        # while a parser that consumed only the header rated the file inert. The same blind
        # spot hid the one-line `[include] path = <file>` form the include rule denies.
        config = self.core / ".git" / "config"
        original = config.read_text(encoding="utf-8")
        self.addCleanup(config.write_text, original, "utf-8")
        for label, line in (("fsmonitor", "[core] fsmonitor = /tmp/planted-fsmonitor"),
                            ("pager", "[core] pager = /tmp/planted-pager"),
                            ("include", "[include] path = /tmp/planted-include"),
                            ("no-space", "[core]fsmonitor=/tmp/planted-fsmonitor")):
            with self.subTest(form=label):
                config.write_text(original + line + "\n", encoding="utf-8")
                self.assertEqual("git_effective_config_exec_capable",
                                 self.verdict(["--no-optional-locks", "status", "--porcelain"],
                                              cwd=self.core))
                config.write_text(original, encoding="utf-8")

    def test_a_line_git_cannot_parse_is_refused_not_ignored(self):
        config = self.core / ".git" / "config"
        original = config.read_text(encoding="utf-8")
        self.addCleanup(config.write_text, original, "utf-8")
        config.write_text(original + "[core]\n\tfsmonitor\n", encoding="utf-8")
        self.assertEqual("git_effective_config_exec_capable",
                         self.verdict(["--no-optional-locks", "status", "--porcelain"],
                                      cwd=self.core))

    def test_linked_worktree_common_and_worktree_configs_are_scanned(self):
        # A linked worktree has no <gitdir>/config at all: git loads the common dir's config
        # (named by the gitdir's `commondir` file) plus <gitdir>/config.worktree when
        # extensions.worktreeConfig is on. Reproduced against real git: scanning only the
        # worktree gitdir admitted a probe whose common config carried core.fsmonitor, and the
        # admitted read-only status probe executed it.
        worktree = self.base / "wt"
        subprocess.run(["git", "-C", str(self.core), "worktree", "add", "-q", str(worktree),
                        "HEAD"], check=True, capture_output=True, env=_GIT_ENV)
        gitdir = Path((worktree / ".git").read_text(encoding="utf-8").split("gitdir:", 1)[1].strip())
        common_config = self.core / ".git" / "config"
        original = common_config.read_text(encoding="utf-8")
        self.addCleanup(common_config.write_text, original, "utf-8")
        for label, path, text in (
                ("common config", common_config,
                 original + "[core]\n\tfsmonitor = /tmp/planted-fsmonitor\n"),
                ("config.worktree", gitdir / "config.worktree",
                 "[extensions]\n\tworktreeConfig = true\n"
                 "[core]\n\tfsmonitor = /tmp/planted-fsmonitor\n")):
            with self.subTest(config=label):
                path.write_text(text, encoding="utf-8")
                self.assertEqual("git_effective_config_exec_capable",
                                 self.verdict(["--no-optional-locks", "status", "--porcelain"],
                                              cwd=worktree, repo=worktree))
                if path == common_config:
                    path.write_text(original, encoding="utf-8")
                else:
                    path.unlink()
                self.assertEqual("", self.verdict(["--no-optional-locks", "status", "--porcelain"],
                                                  cwd=worktree, repo=worktree))

    def test_unreadable_environment_or_argv_fails_closed(self):
        for env in (object(), ["not", "a", "mapping"], 7, {"GIT_TRACE": 5}):
            with self.subTest(env=repr(env)[:18]):
                self.assertEqual("git_environment_unreadable",
                                 self.verdict(["rev-parse", "HEAD"], cwd=self.core, env=env))


class ScratchAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.core = self.root / "core"
        self.target = self.root / "hermes" / "profiles" / "phasec" / "cache" / "scratch"
        self.target.mkdir(parents=True)
        self.core.mkdir()
        self.paths = [str(self.core), str(Path(sys.prefix))]
        self.argv = [sys.executable, "-I", "-B", "-c", PRUNE_BODY, str(self.target), "-", *self.paths]

    def verdict(self, argv=None, executable=None):
        return scratch_command_verdict(executable or sys.executable, self.argv if argv is None else argv,
                                       self.root, self.core, sys.executable, self.paths)

    def test_original_command_is_blocked_without_process_namespace_proof(self):
        self.assertEqual("scratch_process_namespace_unverified", self.verdict())

    def test_foreign_python_same_basename_is_not_trusted(self):
        bad = list(self.argv)
        bad[0] = str(self.root / "python")
        self.assertEqual("scratch_executable_mismatch", self.verdict(bad, bad[0]))

    def test_argv_and_import_path_changes_rejected(self):
        for index, value in ((1, "-E"), (2, "-S"), (4, "print('arbitrary')"), (7, "/outside")):
            with self.subTest(index=index):
                bad = list(self.argv)
                bad[index] = value
                self.assertNotEqual("scratch_process_namespace_unverified", self.verdict(bad))
        for bad in ([], self.argv + ["extra"], self.argv[:-1]):
            self.assertEqual("scratch_argv_mismatch", self.verdict(bad))

    def test_absolute_canonical_owned_target_recognized_but_not_confined(self):
        self.assertEqual(self.target, canonical_owned_path(str(self.target), self.root))
        self.assertIsNone(canonical_owned_path(str(self.root.parent), self.root))

    def test_relative_dots_double_slashes_and_symlink_alias_rejected(self):
        alias = self.root / "alias"
        if os.name != "nt":
            alias.symlink_to(self.target, target_is_directory=True)
        for path in ("hermes/cache/scratch", str(self.target) + "/.",
                     str(self.target.parent) + "/../cache/scratch", str(self.target).replace("/hermes/", "//hermes/"),
                     str(alias), str(self.root / "missing")):
            with self.subTest(path=path):
                self.assertIsNone(canonical_owned_path(path, self.root))

    def test_symlink_escape_never_admitted(self):
        if os.name == "nt":
            self.skipTest("POSIX symlink negative; driver only targets Linux x86_64")
        with tempfile.TemporaryDirectory(prefix="gw-policy-outside-") as other:
            alias = self.root / "escape"
            alias.symlink_to(Path(other).resolve(), target_is_directory=True)
            bad = list(self.argv)
            bad[5] = str(alias)
            self.assertEqual("scratch_target_escape_or_alias", self.verdict(bad))


class ReadonlyGitAdmissionTests(unittest.TestCase):
    """Core f578714 version fingerprinting probes read the fixture checkout only.

    Admitted forms are the exact argv shapes recorded by the issue #28 Hosted spy
    (diag run-spy-1794678130 / run-spy-1794677408) and their source call sites:
    hermes_cli/version_info.py, hermes_cli/boot_bootstrap.py, hermes_cli/main_web_build.py,
    hermes_cli/plugin_catalog.py, tui_gateway/git_probe.py. Everything else defaults to deny.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-git-policy-")
        self.addCleanup(self.temp.cleanup)
        self.core = Path(self.temp.name).resolve() / "core"
        self.core.mkdir()

    def test_current_readonly_version_probes_are_admitted(self):
        for command in (["git", "branch", "--show-current"],
                        ["git", "rev-list", "--count", "v0.23.1..HEAD"],
                        ["git", "--no-optional-locks", "status", "--porcelain", "-uno"],
                        ["git", "-C", str(self.core), "rev-parse", "HEAD"],
                        ["git", "tag", "--merged", "HEAD", "--list", "v[0-9]*"],
                        ["git", "log", "-1", "--format=%ct", "HEAD"],
                        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=D", "-z",
                         "e8bef69f", "HEAD"],
                        ["git", "describe", "--tags", "--long", "--match", "v2[0-9][0-9][0-9].*",
                         "HEAD"]):
            with self.subTest(command=command):
                self.assertTrue(readonly_git_verdict(command, self.core))

    def test_spy_recorded_gateway_forms_are_admitted(self):
        # Exact argv from spy-popens.jsonl run-spy-1794678130 / run-spy-1794677408 plus the
        # source-verified gateway fallbacks (git_probe detached HEAD, plugin_catalog sweep,
        # version_info include_untracked status, write-free main_desktop rev-parse).
        system_git = shutil.which("git") or "/usr/bin/git"
        for command in (["git", "-C", str(self.core), "cat-file", "-e", f"{SPY_SHA}^{{commit}}"],
                        [system_git, "-C", str(self.core), "rev-parse", "HEAD"],
                        ["git", "-C", str(self.core), "diff", "--name-only", "--no-renames",
                         "--diff-filter=D", "-z", SPY_SHA, "HEAD"],
                        ["git", "rev-parse", "--short=7", "HEAD"],
                        ["git", "-C", str(self.core), "rev-parse", "--short", "HEAD"],
                        ["git", "--no-optional-locks", "status", "--porcelain"],
                        ["git", "-C", str(self.core), "log", "-1", "--format=%ct", "--",
                         "plugin-catalog"],
                        ["git", "rev-parse", "HEAD"]):
            with self.subTest(command=command):
                self.assertTrue(readonly_git_verdict(command, self.core))

    def test_mutating_foreign_or_incomplete_git_never_admitted(self):
        for command in (["git"], ["git", "commit", "-m", "x"], ["git", "checkout", "main"],
                        ["git", "-C", str(self.core.parent), "status"], ["git", "-C", str(self.core)],
                        ["git", "--no-optional-locks"], ["git", "-c", "user.name=x", "commit"],
                        ["python", "status"], [str(self.core / "git"), "rev-parse", "HEAD"],
                        ["./git", "rev-parse", "HEAD"], [], "git status",
                        ["git", "branch", "-D", "main"], ["git", "branch", "new-branch"],
                        ["git", "branch", "-m", "old", "new"], ["git", "tag", "v1.0"],
                        ["git", "tag", "-d", "v1.0"], ["git", "tag", "-a", "-m", "x", "v1"],
                        ["git", "symbolic-ref", "HEAD", "refs/heads/main"],
                        ["git", "symbolic-ref", "-d", "HEAD"], ["git", "status"],
                        ["git", "status", "--porcelain"],
                        ["git", "log", "--output=/tmp/x"], ["git", "diff", "--ext-diff"],
                        ["git", "diff", "--textconv"], ["git", "-C", str(self.core), "-C",
                        "/etc", "status"]):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))

    def test_write_capable_and_unknown_option_forms_default_denied(self):
        # Deny is the default for any argv not enumerated above; these are the write-capable
        # or unknown-option neighbours of admitted verbs, not a block list.
        for command in (["git", "rev-list", "--count", "--output=/tmp/leak", "HEAD"],
                        ["git", "-C", str(self.core), "rev-list", "--count", "--out", "/tmp/leak",
                         "HEAD"],  # git's unambiguous-prefix spelling of --output
                        ["git", "rev-list", "--count"], ["git", "rev-list", "--objects", "HEAD"],
                        ["git", "rev-list", "--all"], ["git", "rev-list", "--count", "-output"],
                        ["git", "rev-list", "--count", "--", "v1..HEAD"],
                        ["git", "rev-list", "--count", "-x..HEAD"],
                        ["git", "rev-list", "--count", "v" + "0" * 200 + "..HEAD"],
                        ["git", "rev-parse", "--git-dir"], ["git", "rev-parse", "--show-toplevel"],
                        ["git", "rev-parse", "--revs-only", "--all"],
                        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                        ["git", "rev-parse", "--short=99", "HEAD"],
                        ["git", "rev-parse", "HEAD", "extra"], ["git", "rev-parse"],
                        ["git", "describe", "--broken"], ["git", "describe", "--tags"],
                        ["git", "describe", "--tags", "--long", "--match", "v2[0-9][0-9][0-9].*"],
                        ["git", "describe", "--match", "x", "--tags", "--long", "HEAD"],
                        ["git", "describe", "--tags", "--long", "--match", ";rm -rf /", "HEAD"],
                        ["git", "cat-file", "-p", "HEAD"], ["git", "cat-file", "--batch", "HEAD"],
                        ["git", "cat-file", "--batch-all-objects", "-e", SPY_SHA],
                        ["git", "cat-file", "-e"], ["git", "cat-file", "-e", "HEAD"],
                        ["git", "cat-file", "-e", "--output=/tmp/leak"],
                        ["git", "cat-file", "-e", SPY_SHA + "z"],
                        ["git", "cat-file", "-e", "abc12"],  # below git's 7-char minimum
                        ["git", "cat-file", "-e", SPY_SHA + "^{tree}"],
                        ["git", "cat-file", "-e", "refs/tags/v1^{commit}"],
                        ["git", "log", "-1", "--format=%H", "HEAD"],
                        ["git", "log", "-2", "--format=%ct", "HEAD"],
                        ["git", "log", "--format=%ct", "HEAD"],
                        ["git", "log", "-1", "--format=%ct", "--", "../../etc/passwd"],
                        ["git", "log", "-1", "--format=%ct", "--", "-output"],
                        ["git", "log", "-1", "--format=%ct", "--", "a/../b"],
                        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=AMD", "-z",
                         SPY_SHA, "HEAD"],
                        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=D", "-z",
                         "main", "HEAD"],
                        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=D", "-z",
                         "HEAD"],
                        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=D", "-z",
                         SPY_SHA, "HEAD", "extra"],
                        ["git", "--no-optional-locks", "status", "--ignored"],
                        ["git", "--no-optional-locks", "status", "--porcelain", "-uall"],
                        ["git", "--no-optional-locks", "status", "--porcelain", "-uno", "extra"]):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))

    def test_config_injection_and_ambiguous_forms_denied(self):
        # -c/--config can rewrite diff/pager/external behaviour; abbreviated long options let
        # git resolve a spelling the policy never admitted to a write-capable long option.
        for command in (["git", "-c", "core.pager=cat", "rev-parse", "HEAD"],
                        ["git", "-c", "diff.external=/bin/touch", "diff", "--name-only",
                         "--no-renames", "--diff-filter=D", "-z", SPY_SHA, "HEAD"],
                        ["git", "--no-optional-locks", "-c", "x.y=z", "status", "--porcelain"],
                        ["git", "-C", str(self.core), "-c", "protocol.ext.allow=always", "fetch"],
                        ["git", "config", "--get", "user.name"],
                        ["git", "config", "user.name", "x"],
                        ["git", "--config", "core.fsmonitor=false", "status"],
                        ["git", "rev-list", "--count", "--output", "/tmp/leak", "HEAD"]):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))

    def test_unobserved_verbs_default_denied(self):
        # Present in Core sources but never in the fixture spy: admission is a deliberate,
        # evidence-backed widening, never a side effect of a neighbouring verb.
        for command in (["git", "show", "v1.0:pyproject.toml"],
                        ["git", "symbolic-ref", "HEAD"], ["git", "tag"],
                        ["git", "branch", "--list"], ["git", "tag", "--list"],
                        ["git", "rev-parse", "--show-cdup"], ["git", "fetch", "origin"],
                        ["git", "push"], ["git", "gc"], ["git", "maintenance", "run"],
                        ["git", "clean", "-n"], ["git", "stash"], ["git", "worktree", "list"],
                        ["git", "ls-files"], ["git", "cat-file", "-t", SPY_SHA]):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))

    def test_malformed_argv_never_admitted(self):
        for command in (["git", 5], ["git", None], ["git", ""], ["git", "-C", 5, "rev-parse",
                                                                "HEAD"],
                        ["git", b"\xff\xfe"], ["git", "-C", str(self.core), 5]):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))


@unittest.skipIf(shutil.which("git") is None, "git binary required for write ground truth")
class GitOutputRedirectWriteTests(unittest.TestCase):
    """`--output=<file>` is a real write performed inside the git child, invisible to the
    in-process audit. The policy must refuse these forms and stay refused: this test proves
    the refused argv genuinely creates a file, so no future widening can re-admit it blindly."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-git-write-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "repo"
        self.repo.mkdir()
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        for probe in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "seed"]):
            subprocess.run(["git", "-C", str(self.repo), *probe], env=env, check=True,
                           capture_output=True)
        self.commit = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                     capture_output=True, text=True, check=True).stdout.strip()

    def assert_refused_and_actually_writes(self, argv, out):
        self.assertFalse(readonly_git_verdict(argv, self.repo), argv)
        subprocess.run(argv, check=True, capture_output=True)  # ground truth, confined to temp
        self.assertTrue(out.exists(), f"{argv} did not create {out.name}")

    def test_rev_list_original_output_redirect_writes_file_and_is_refused(self):
        out = self.repo / "rev-list-original.leak"
        out.write_text("sentinel", encoding="utf-8")
        argv = ["git", "-C", str(self.repo), "rev-list", f"--output={out}", "HEAD"]
        self.assertFalse(readonly_git_verdict(argv, self.repo))
        subprocess.run(argv, check=True, capture_output=True)
        self.assertNotEqual("sentinel", out.read_text(encoding="utf-8"))

    def test_rev_list_output_redirect_writes_file_and_is_refused(self):
        out = self.repo / "rev-list.leak"
        self.assert_refused_and_actually_writes(
            ["git", "-C", str(self.repo), "rev-list", "--count", f"--output={out}", "HEAD"], out)

    def test_log_output_redirect_writes_file_and_is_refused(self):
        out = self.repo / "log.leak"
        self.assert_refused_and_actually_writes(
            ["git", "-C", str(self.repo), "log", f"--output={out}", "-1", "HEAD"], out)

    def test_diff_output_redirect_writes_file_and_is_refused(self):
        out = self.repo / "diff.leak"
        self.assert_refused_and_actually_writes(
            ["git", "-C", str(self.repo), "diff", f"--output={out}", "--name-only",
             self.commit, "HEAD"], out)


if __name__ == "__main__":
    unittest.main()
