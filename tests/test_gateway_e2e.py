"""Offline contract tests for the real-Gateway driver; no Core import or operating home."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.gateway_docker import CHECKS

from scripts import gateway_e2e as gateway


class GatewayEvidenceTests(unittest.TestCase):
    def receipt(self):
        return {"schema_version": 2, "status": "PASS", "candidate_sha": "a" * 40,
                "boundary_refusal_reasons": [],
                "owned_child_count": 2, "live_owned_children_after_exit": 0,
                "hermes_commit": "b" * 40, "candidate_source_dirty": False,
                "provider_origin": {"status": "PASS", "candidate_sha": "a" * 40, "tree_sha256": "3" * 64,
                                    "home_sha256": "4" * 64, "frozen_copies": 0, "errors": []},
                "scratch_cleanup": {"status": "PASS", "launch_count": 1},
                "shutdown_diagnostic": {"status": "PASS", "launch_count": 1},
                "confinement": {"status": "PASS", "checks": {name: True for name in CHECKS}, "pid_namespace_sha256": "1" * 64, "host_pid_namespace_sha256": "2" * 64},
                "docker_execution": {"status": "PASS", "config_verified": True, "owned_pid_namespace_verified": True, "outside_canary_unchanged": True,
                                     "container_removed": True, "image_removed": True},
                "docker_contract_version": 2, "checkout_sha": "a" * 40,
                "final_namespace_live_count": 1, "final_namespace_process_count": 1,
                "stages": {name: {"status": "PASS", "detail": "executed"} for name in gateway.REQUIRED_STAGES}}

    def test_complete_receipt_is_accepted(self):
        self.assertEqual([], gateway.validate_receipt(self.receipt(), "a" * 40))

    def test_schema_one_and_unrecorded_refusals_fail_closed(self):
        value = self.receipt()
        value["schema_version"] = 1
        self.assertIn("invalid_schema", gateway.validate_receipt(value, "a" * 40))
        value = self.receipt()
        del value["boundary_refusal_reasons"]
        self.assertIn("boundary_refusals_unrecorded", gateway.validate_receipt(value, "a" * 40))

    def test_boundary_refusal_reasons_publish_enum_only(self):
        self.assertEqual(["mutation_outside_disposable_root", "unapproved_subprocess"],
                         gateway.boundary_refusal_reasons(
                             [{"refusals": ["unapproved_subprocess", "mutation_outside_disposable_root",
                                            "/secret/path/x.py", "with space", 7, None]},
                              {"refusals": ["unapproved_subprocess"]}, {}]))

    def test_origin_missing_wrong_sha_unbound_home_or_bad_tree_never_passes(self):
        value = self.receipt()
        del value["provider_origin"]
        self.assertIn("provider_origin_not_verified", gateway.validate_receipt(value, "a" * 40))
        for key, bad in (("status", "NOT_RUN"), ("candidate_sha", "b" * 40), ("errors", ["drift"]),
                         ("tree_sha256", ""), ("home_sha256", None), ("frozen_copies", True), ("frozen_copies", -1)):
            with self.subTest(key=key, bad=bad):
                value = self.receipt()
                value["provider_origin"][key] = bad
                self.assertIn("provider_origin_not_verified", gateway.validate_receipt(value, "a" * 40))

    def test_every_required_stage_missing_or_nonpass_fails_closed(self):
        for stage in gateway.REQUIRED_STAGES:
            for status in (None, "FAIL", "BLOCKED", "NOT_RUN", "SKIP", "", True):
                with self.subTest(stage=stage, status=status):
                    receipt = self.receipt()
                    if status is None:
                        receipt["stages"].pop(stage)
                    else:
                        receipt["stages"][stage]["status"] = status
                    self.assertTrue(gateway.validate_receipt(receipt, "a" * 40))

    def test_wrong_candidate_core_and_malformed_receipts_rejected(self):
        for bad in (None, [], {}, True):
            self.assertTrue(gateway.validate_receipt(bad, "a" * 40))
        for key, value in (("candidate_sha", "c" * 40), ("hermes_commit", "main"),
                           ("status", "BLOCKED"), ("schema_version", True), ("stages", [])):
            receipt = deepcopy(self.receipt())
            receipt[key] = value
            self.assertTrue(gateway.validate_receipt(receipt, "a" * 40))

    def test_ready_requires_live_pid_and_ready_state_not_http200(self):
        good = {"pid": 101, "status": "ok", "gateway_state": "running"}
        self.assertTrue(gateway.is_ready(good, 101))
        for value in ({"status": "ok"}, {**good, "pid": 102}, {**good, "status": "starting"},
                      {**good, "gateway_state": "startup_failed"}, {**good, "pid": True}, None):
            self.assertFalse(gateway.is_ready(value, 101))

    def test_readiness_diagnostics_only_publish_fixed_statuses_not_payloads(self):
        secret = "credential-or-session-must-not-escape"
        value = {"pid": 101, "status": "degraded", "gateway_state": "running",
                 "prompt": secret, "readiness": {"status": "degraded", "checks": {
                     "state_db": {"status": "degraded", "detail": "OperationalError"},
                     "disk": {"status": "ok", "path": secret},
                     "config": {"status": secret, "detail": secret},
                     secret: {"status": "ok"}}}}
        actual = gateway.readiness_observation(value, 101, 200)
        self.assertEqual("degraded", actual["status"])
        self.assertTrue(actual["expected_pid"])
        self.assertEqual("degraded", actual["checks"]["state_db"])
        self.assertEqual("unrecognized", actual["checks"]["config"])
        self.assertNotIn(secret, str(actual))
        self.assertNotIn("detail", str(actual))

    def test_transport_diagnostics_distinguish_errors_without_exception_text(self):
        import urllib.error
        for error, expected in ((ConnectionRefusedError("secret"), "connection_refused"),
                                (ConnectionResetError("secret"), "connection_reset"),
                                (TimeoutError("secret"), "timeout"),
                                (OSError("secret"), "unavailable")):
            for wrapped in (error, urllib.error.URLError(error)):
                with self.subTest(expected=expected, wrapped=type(wrapped).__name__):
                    value = gateway.transport_observation(wrapped)
                    self.assertEqual({"transport": expected}, value)
                    self.assertNotIn("secret", str(value))

    def test_bad_readiness_observation_never_reports_expected_pid(self):
        for value in (None, [], {}, {"pid": True}, {"pid": 102}):
            with self.subTest(value=value):
                observation = gateway.readiness_observation(value, 101, 503)
                self.assertFalse(observation["expected_pid"])
                self.assertEqual(503, observation["http_status"])
                self.assertFalse(gateway.is_ready(value, 101))

    def test_api_server_dependency_preflight_fails_closed_before_any_launch(self):
        import importlib.util
        from pathlib import Path
        import tempfile
        import unittest.mock
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "receipt.json"
            with unittest.mock.patch.object(importlib.util, "find_spec", return_value=None):
                self.assertEqual(1, gateway.main(["--hermes-root", temp, "--candidate-sha",
                                                  "a" * 40, "--output", str(output)]))
        self.assertFalse(output.exists())

    def test_stage_fails_instead_of_promoting_cleanup_or_ready_to_success(self):
        receipt = self.receipt()
        for stage in ("candidate_install", "gateway_ready", "provider_factory", "initialize",
                      "ownership_conflict", "permission_denial", "cancellation", "child_cleanup", "isolation"):
            bad = deepcopy(receipt)
            bad["stages"][stage] = {"status": "FAIL", "detail": "synthetic_negative"}
            self.assertTrue(gateway.validate_receipt(bad, "a" * 40))

    def test_recorded_boundary_refusal_denies_success(self):
        # A PASS receipt can never coexist with recorded denials: cleanup() forces
        # isolation BLOCKED sticky_boundary_refusal, so any non-empty enum is forged.
        for reasons in (["unapproved_subprocess"], ["subprocess_executable_mismatch"],
                        ["mutation_outside_disposable_root", "unapproved_subprocess"]):
            with self.subTest(reasons=reasons):
                receipt = self.receipt()
                receipt["boundary_refusal_reasons"] = reasons
                self.assertIn("boundary_refusal_contradicts_pass",
                              gateway.validate_receipt(receipt, "a" * 40))

    def test_live_owned_children_must_be_exact_int_zero(self):
        # bools and floats equal zero; only exact-int typing plus the zero gate holds.
        for bad in (1, 3, -1, True, False, 0.0, "0", None):
            with self.subTest(live=bad):
                receipt = self.receipt()
                receipt["live_owned_children_after_exit"] = bad
                self.assertIn("live_owned_children_not_zero", gateway.validate_receipt(receipt, "a" * 40))
        missing = self.receipt()
        del missing["live_owned_children_after_exit"]
        self.assertIn("live_owned_children_not_zero", gateway.validate_receipt(missing, "a" * 40))

    def test_owned_child_count_requires_observed_process_evidence(self):
        # An empty owned-pid set makes child_cleanup pass vacuously; PASS needs count >= 1.
        for bad in (0, -1, True, False, 1.0, "2", None):
            with self.subTest(owned=bad):
                receipt = self.receipt()
                receipt["owned_child_count"] = bad
                self.assertIn("owned_child_count_not_observed", gateway.validate_receipt(receipt, "a" * 40))
        missing = self.receipt()
        del missing["owned_child_count"]
        self.assertIn("owned_child_count_not_observed", gateway.validate_receipt(missing, "a" * 40))

    def test_schema_three_extension_is_rejected(self):
        # No schema extension: schema 3 (refusal-spawn fingerprints) never validates here.
        receipt = self.receipt()
        receipt["schema_version"] = 3
        receipt["boundary_refusal_spawns"] = []
        self.assertIn("invalid_schema", gateway.validate_receipt(receipt, "a" * 40))


class GatewayCleanupObservationTests(unittest.TestCase):
    """cleanup() must never promote an empty owned-child observation to success."""

    def run_object(self, root: Path):
        run = object.__new__(gateway.Run)
        run.contender = run.process = None
        run.root = root
        run.home = root / "hermes"
        run.profile = root / "hermes" / "profiles" / "phasec"
        run.record = {"stages": {name: {"status": "NOT_RUN", "detail": "not_executed"}
                                 for name in gateway.REQUIRED_STAGES}}
        return run

    def test_empty_owned_child_set_never_marks_child_cleanup_success(self):
        with tempfile.TemporaryDirectory() as temp:
            run = self.run_object(Path(temp))
            run.cleanup()
            self.assertEqual(0, run.record["owned_child_count"])
            self.assertEqual(0, run.record["live_owned_children_after_exit"])
            self.assertEqual("FAIL", run.record["stages"]["child_cleanup"]["status"])
            self.assertEqual("no_owned_child_process_evidence",
                             run.record["stages"]["child_cleanup"]["detail"])

    def test_reaped_owned_child_yields_counted_zero_live_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reaped = subprocess.Popen([sys.executable, "-c", "pass"])
            reaped.wait()
            (root / "owned-core-children.jsonl").write_text(
                json.dumps({"pid": reaped.pid, "started": "0"}) + "\n",
                encoding="utf-8")
            run = self.run_object(root)
            run.cleanup()
            self.assertEqual(1, run.record["owned_child_count"])
            self.assertEqual(0, run.record["live_owned_children_after_exit"])
            self.assertEqual("PASS", run.record["stages"]["child_cleanup"]["status"])

    def test_live_owned_child_forces_fail_and_nonzero_live_count(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                     start_new_session=True)
            try:
                started = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[22 - 3]
                (root / "owned-core-children.jsonl").write_text(
                    json.dumps({"pid": child.pid, "started": started}) + "\n", encoding="utf-8")
                run = self.run_object(root)
                run.cleanup()  # bounded 6-second wait, then records the residual
                self.assertEqual(1, run.record["owned_child_count"])
                self.assertEqual(1, run.record["live_owned_children_after_exit"])
                self.assertEqual("FAIL", run.record["stages"]["child_cleanup"]["status"])
            finally:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
