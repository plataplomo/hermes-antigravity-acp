"""CI consumes executed, same-SHA Gateway evidence, never an enclosing success alone."""
from __future__ import annotations

import json
import unittest

from scripts.gateway_docker import CHECKS

from scripts import gateway_attestation as attest
from scripts.gateway_e2e import REQUIRED_STAGES


class GatewayAttestationTests(unittest.TestCase):
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
                "final_namespace_live_count": 1, "final_namespace_process_count": 1, "stages": {name: {"status": "PASS"} for name in REQUIRED_STAGES}}

    def outputs(self) -> dict[str, object]:
        return {"attested_sha": "a" * 40, "gateway_core": "b" * 40, "gateway_result": "success", "gateway_record": json.dumps(self.receipt())}

    def test_executed_same_sha_receipt_accepted(self):
        self.assertEqual([], attest.check_outputs(self.outputs(), required=True, candidate="a" * 40))

    def test_enclosing_job_success_without_executed_receipt_never_passes(self):
        for result in ("skipped", "failure", "cancelled", "", None):
            output = self.outputs()
            output["gateway_result"] = result
            self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))
        self.assertTrue(attest.check_outputs({"attested_sha": "a" * 40}, required=True, candidate="a" * 40))

    def test_wrong_sha_malformed_and_all_incomplete_stages_rejected(self):
        for record in ("", "{}", "null", "[]", "not json"):
            output = self.outputs()
            output["gateway_record"] = record
            self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))
        self.assertTrue(attest.check_outputs(self.outputs(), required=True, candidate="c" * 40))
        for name in REQUIRED_STAGES:
            for status in ("BLOCKED", "FAIL", "NOT_RUN", "skipped", True, None):
                receipt = self.receipt()
                receipt["stages"][name]["status"] = status
                output = self.outputs()
                output["gateway_record"] = json.dumps(receipt)
                self.assertTrue(attest.check_outputs(output, required=True, candidate="a" * 40))

    def test_only_explicit_unrequired_skip_is_accepted(self):
        self.assertEqual([], attest.check_outputs({"gateway_result": "skipped", "gateway_record": ""}, required=False))
        self.assertTrue(attest.check_outputs({}, required=False))
        self.assertTrue(attest.check_outputs({"gateway_result": "failure"}, required=False))

    def test_refusal_and_residual_child_contradictions_never_attest(self):
        for key, value in (("boundary_refusal_reasons", ["unapproved_subprocess"]),
                           ("live_owned_children_after_exit", 3),
                           ("live_owned_children_after_exit", -1),
                           ("live_owned_children_after_exit", True),
                           ("live_owned_children_after_exit", "0"),
                           ("owned_child_count", 0),
                           ("owned_child_count", -2),
                           ("owned_child_count", False)):
            with self.subTest(key=key, value=value):
                receipt = self.receipt()
                receipt[key] = value
                outputs = self.outputs()
                outputs["gateway_record"] = json.dumps(receipt)
                self.assertTrue(attest.check_outputs(outputs, required=True, candidate="a" * 40))

    def test_preserved_red_cases_reject_both_validator_and_attestation(self):
        # The historical four-case reproducer imports immutable old schema-2 and
        # abandoned schema-3 code. Test both contradictions at both CURRENT gates.
        for key, value in (("boundary_refusal_reasons", ["subprocess_executable_mismatch"]),
                           ("live_owned_children_after_exit", 3)):
            for gate in ("validator", "attestation"):
                with self.subTest(key=key, gate=gate):
                    receipt = self.receipt()
                    receipt[key] = value
                    if gate == "validator":
                        from scripts.gateway_e2e import validate_receipt
                        errors = validate_receipt(receipt, "a" * 40)
                    else:
                        outputs = self.outputs()
                        outputs["gateway_record"] = json.dumps(receipt)
                        errors = attest.check_outputs(outputs, required=True, candidate="a" * 40)
                    self.assertTrue(errors)

    def test_missing_child_count_evidence_never_attests(self):
        for key in ("live_owned_children_after_exit", "owned_child_count"):
            with self.subTest(key=key):
                receipt = self.receipt()
                del receipt[key]
                outputs = self.outputs()
                outputs["gateway_record"] = json.dumps(receipt)
                self.assertTrue(attest.check_outputs(outputs, required=True, candidate="a" * 40))


if __name__ == "__main__":
    unittest.main()
