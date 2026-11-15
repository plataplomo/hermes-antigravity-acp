"""Child-observation bookkeeping is separate from subprocess admission.

Fixed private fixtures only: no Core import, no Gateway, no process-namespace
claim, no denied launch. The only real children are trivial interpreter
one-liners used to exercise start-identity and exit evidence. The point of
these tests is that housekeeping receipt evidence requires a token the audit
hook noted after a full verdict; PRUNE_BODY or "bash" membership in a command
alone must never classify a child as verified scratch/shutdown work.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load():
    # gateway_cli_envelope uses flat sibling imports of its boundary modules.
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import gateway_cli_envelope
    from gateway_process_policy import PRUNE_BODY
    return gateway_cli_envelope, PRUNE_BODY


envelope, PRUNE_BODY = _load()


class _FakePopen:
    def __init__(self, pid, args, returncode=None):
        self.pid = pid
        self.args = args
        self._returncode = returncode

    def poll(self):
        return self._returncode


class ChildLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gw-child-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.ledger = envelope._ChildLedger(self.root, start_time=lambda pid: "1234567")

    def scratch_argv(self, target=None):
        return [sys.executable, "-I", "-B", "-c", PRUNE_BODY,
                str(self.root if target is None else target), "lineage", str(self.root / "core")]

    def shutdown_argv(self):
        return ["/usr/bin/timeout", "5", "bash", "-c", "kill -SIGINT 4242; sleep 5"]

    def observations(self):
        path = self.root / "owned-core-children.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_prune_body_membership_alone_is_not_scratch_evidence(self):
        # A fixture-admitted child embedding the exact pruner argv shape was never
        # verified by the audit hook: it must not become scratch receipt evidence.
        record = self.ledger.observe(_FakePopen(4101, self.scratch_argv()))
        self.assertEqual("other", record["kind"])
        self.assertEqual([], self.ledger.housekeeping())
        self.assertEqual([], self.ledger.owned_processes)
        # Observability still applies to admitted non-housekeeping launches.
        self.assertEqual([{"pid": 4101, "started": "1234567", "exit_code": None, "kind": "other"}],
                         self.observations())
        self.assertEqual({"1234567"}, set(self.ledger.owned_pids.values()))

    def test_bash_membership_alone_is_not_shutdown_evidence(self):
        for argv in (self.shutdown_argv(), [sys.executable, str(self.root / "fake-acp.py"), str(self.root), "bash"]):
            with self.subTest(argv=argv[:2]):
                record = self.ledger.observe(_FakePopen(4102, argv))
                self.assertEqual("other", record["kind"])
        self.assertEqual([], self.ledger.housekeeping())

    def test_verified_scratch_launch_is_tracked_once_with_its_target(self):
        argv = self.scratch_argv()
        self.ledger.note_verified_launch("scratch", argv)
        child = _FakePopen(4103, argv)
        record = self.ledger.observe(child)
        self.assertEqual("scratch", record["kind"])
        self.assertEqual([{"kind": "scratch", "target": str(self.root), "returncode": None}],
                         self.ledger.housekeeping())
        # The token is one-shot: a second child with the same command is not a
        # second verified launch.
        self.assertEqual("other", self.ledger.observe(_FakePopen(4104, argv))["kind"])
        self.assertEqual(1, len(self.ledger.housekeeping()))

    def test_verified_shutdown_launch_is_tracked(self):
        argv = self.shutdown_argv()
        self.ledger.note_verified_launch("shutdown", argv)
        self.assertEqual("shutdown", self.ledger.observe(_FakePopen(4105, argv))["kind"])
        self.assertEqual([{"kind": "shutdown", "target": "", "returncode": None}],
                         self.ledger.housekeeping())

    def test_target_swap_is_not_verified_housekeeping(self):
        self.ledger.note_verified_launch("scratch", self.scratch_argv())
        forged = self.scratch_argv()
        forged[5] = str(self.root / "elsewhere")
        self.assertEqual("other", self.ledger.observe(_FakePopen(4106, forged))["kind"])
        self.assertEqual([], self.ledger.housekeeping())

    def test_receipt_housekeeping_shape_and_liveness_tracking(self):
        argv = self.shutdown_argv()
        self.ledger.note_verified_launch("shutdown", argv)
        child = _FakePopen(4107, argv)
        self.ledger.observe(child)
        entry, = self.ledger.housekeeping()
        self.assertEqual({"kind", "target", "returncode"}, set(entry))
        self.assertIsNone(entry["returncode"])  # still live at observation time
        child._returncode = 0  # exited before the receipt was written
        self.assertEqual(0, self.ledger.housekeeping()[0]["returncode"])

    def test_rejected_child_never_produces_housekeeping_evidence(self):
        # Rejection means the audit hook raised before spawn, so no token exists
        # and the profile hook never observes a return. With no tokens noted, no
        # observed command can yield housekeeping evidence.
        for argv in (self.scratch_argv(), self.shutdown_argv()):
            self.ledger.observe(_FakePopen(4108, argv))
        self.assertEqual([], self.ledger.housekeeping())
        self.assertEqual([], self.ledger._verified_launches)

    def test_live_child_without_start_identity_is_refused(self):
        def gone(pid):
            raise FileNotFoundError(pid)
        ledger = envelope._ChildLedger(self.root, start_time=gone)
        with self.assertRaises(envelope._ChildIdentityUnavailable):
            ledger.observe(_FakePopen(4109, self.scratch_argv(), returncode=None))
        self.assertNotIn(4109, ledger.owned_pids)
        self.assertEqual([], self.observations())  # refusal happens before the evidence line

    def test_exited_child_without_start_identity_is_still_recorded(self):
        def gone(pid):
            raise FileNotFoundError(pid)
        ledger = envelope._ChildLedger(self.root, start_time=gone)
        record = ledger.observe(_FakePopen(4110, self.scratch_argv(), returncode=0))
        self.assertEqual({"pid": 4110, "started": None, "exit_code": 0, "kind": "other"}, record)
        self.assertNotIn(4110, ledger.owned_pids)
        self.assertEqual(1, len(self.observations()))

    def test_malformed_process_objects_are_not_observed(self):
        for process in (None, object(), _FakePopen(None, ["x"]), _FakePopen("7", ["x"])):
            with self.subTest(process=type(process).__name__):
                self.assertIsNone(self.ledger.observe(process))
        self.assertEqual([], self.observations())
        self.assertEqual({}, self.ledger.owned_pids)
        # A live pid with a malformed command is observed as unclassified, not a crash.
        record = self.ledger.observe(_FakePopen(4111, None))
        self.assertEqual("other", record["kind"])
        self.assertEqual([], self.ledger.housekeeping())

    def test_foreign_pid_is_not_kill_authorized(self):
        self.ledger.observe(_FakePopen(4112, self.scratch_argv()))
        self.assertIsNone(self.ledger.owned_pids.get(999_999))

    @unittest.skipUnless(sys.platform == "linux", "start identity comes from /proc")
    def test_real_children_start_identity_and_exit_evidence(self):
        ledger = envelope._ChildLedger(self.root)  # default real /proc start-time reader
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(lambda: (live.kill(), live.wait()))
        record = ledger.observe(live)
        self.assertEqual("other", record["kind"])
        self.assertIsInstance(record["started"], str)
        self.assertIsNone(record["exit_code"])
        self.assertIn(live.pid, ledger.owned_pids)
        live.kill()
        live.wait()
        exited = subprocess.Popen([sys.executable, "-c", "pass"])
        exited.wait()
        record = ledger.observe(exited)
        self.assertIsNone(record["started"])  # reaped: /proc entry is gone
        self.assertEqual(0, record["exit_code"])
        kinds = [line["kind"] for line in self.observations()]
        self.assertEqual(["other", "other"], kinds)


if __name__ == "__main__":
    unittest.main()
