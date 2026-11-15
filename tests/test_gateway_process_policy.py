"""Exact scratch argv/path negatives. No Core imports, GC, namespace or host process scans."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.gateway_process_policy import (PRUNE_BODY, canonical_owned_path, readonly_git_verdict,
                                            scratch_command_verdict)

# The exact object id from the issue #28 Hosted spy (run-spy-1794678130).
SPY_SHA = "e8bef69f505554154c158aed0a27c429c11791c0"


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
