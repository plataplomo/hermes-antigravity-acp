"""Exact scratch argv/path negatives. No Core imports, GC, namespace or host process scans."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

from scripts.gateway_process_policy import (PRUNE_BODY, canonical_owned_path, readonly_git_verdict,
                                            scratch_command_verdict)


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
    """Core e8bef69f version fingerprinting probes read the fixture checkout only."""

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
                        ["git", "log", "-1", "--format=%ct", "HEAD"]):
            with self.subTest(command=command):
                self.assertTrue(readonly_git_verdict(command, self.core))

    def test_mutating_foreign_or_incomplete_git_never_admitted(self):
        for command in (["git"], ["git", "commit", "-m", "x"], ["git", "checkout", "main"],
                        ["git", "-C", str(self.core.parent), "status"], ["git", "-C", str(self.core)],
                        ["git", "--no-optional-locks"], ["git", "-c", "user.name=x", "commit"],
                        ["python", "status"], [], "git status"):
            with self.subTest(command=command):
                self.assertFalse(readonly_git_verdict(command, self.core))


if __name__ == "__main__":
    unittest.main()
