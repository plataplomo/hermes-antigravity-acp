#!/usr/bin/env python3
"""Run and verify one expected Gateway failure; never certify it as normal success."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

try:
    from gateway_docker import validate_docker_receipt
    from gateway_e2e import HEX40, REQUIRED_STAGES, validate_receipt
except ImportError:
    from scripts.gateway_docker import validate_docker_receipt
    from scripts.gateway_e2e import HEX40, REQUIRED_STAGES, validate_receipt


NOT_RUN = ("permission_denial", "cancellation", "ownership_conflict", "owner_survives")


def validate_fault(record: object, candidate: str, core: str, run_id: str, attempt: str, exit_code: int) -> list[str]:
    """Require the precise injected failure plus the unchanged cleanup boundaries."""
    if (not isinstance(record, dict) or not isinstance(candidate, str) or not HEX40.fullmatch(candidate)
            or not isinstance(core, str) or not HEX40.fullmatch(core)):
        return ["fault_receipt_or_identity_invalid"]
    problems = []
    expected_positive_errors = {"overall_not_pass", *(f"required_stage_not_pass:{stage}" for stage in NOT_RUN)}
    if set(validate_receipt(record, candidate)) != expected_positive_errors:
        problems.append("normal_receipt_rejection_mismatch")
    problems.extend(validate_docker_receipt(record))
    if (type(exit_code) is not int or exit_code != 1 or record.get("status") != "FAIL" or record.get("checkout_sha") != candidate
            or record.get("hermes_commit") != core or record.get("run_id") != run_id
            or record.get("run_attempt") != attempt or not run_id.isdigit() or int(run_id) < 1
            or not attempt.isdigit() or int(attempt) < 1):
        problems.append("fault_execution_identity_mismatch")
    if record.get("fault_observation") != {"scenario": "prompt_held_driver_error", "held_tree_live": True}:
        problems.append("fault_injection_not_observed")
    stages = record.get("stages")
    if (not isinstance(stages, dict) or set(stages) != set(REQUIRED_STAGES) | {"injected_fault"}
            or stages.get("injected_fault") != {"status": "FAIL", "detail": "injected_fault_while_prompt_held"}):
        problems.append("fault_stage_mismatch")
    if not isinstance(stages, dict) or any(stages.get(stage) != {"status": "NOT_RUN", "detail": "not_executed"}
                                           for stage in NOT_RUN):
        problems.append("fault_unexecuted_stages_mismatch")
    cleanup = record.get("cleanup_diagnostics")
    fixture = cleanup.get("fixture_exit") if isinstance(cleanup, dict) else None
    if (not isinstance(cleanup, dict) or cleanup.get("owner_exit") != "zero" or cleanup.get("forced_reasons") != []
            or not isinstance(fixture, dict) or fixture.get("status") != "complete" or fixture.get("unmet") != []):
        problems.append("fault_cleanup_not_graceful")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--core-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    driver = Path(__file__).with_name("gateway_docker.py")
    completed = subprocess.run([sys.executable, str(driver), "--hermes-root", str(args.hermes_root),
                                "--candidate-sha", args.candidate_sha, "--output", str(args.output),
                                "--inject-held-fault"], capture_output=True, check=False)
    try:
        record = json.loads(args.output.read_text())
    except (OSError, ValueError):
        print("fault verification: FAIL (receipt_missing_or_invalid)")
        return 1
    errors = validate_fault(record, args.candidate_sha, args.core_sha,
                            os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                            completed.returncode)
    print("fault verification:", "FAIL " + ",".join(errors) if errors else "PASS (expected failure; cleanup verified)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
