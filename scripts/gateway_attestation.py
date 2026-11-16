#!/usr/bin/env python3
"""Validate real executed Gateway receipts before CI/Release approval."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

try:
    from gateway_e2e import validate_receipt
    from gateway_docker import validate_docker_receipt
except ImportError:
    from scripts.gateway_e2e import validate_receipt
    from scripts.gateway_docker import validate_docker_receipt


def stable_baseline() -> dict[str, str]:
    """Load the exact official source and image identity; malformed policy fails closed."""
    policy = json.loads((Path(__file__).resolve().parent.parent / "release/hermes-core-baseline.json").read_text())
    if (not isinstance(policy, dict) or set(policy) != {"tag", "commit", "docker_image"}
            or not isinstance(policy["tag"], str) or not re.fullmatch(r"v\d+\.\d+\.\d+", policy["tag"])
            or not isinstance(policy["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", policy["commit"])
            or not isinstance(policy["docker_image"], str)
            or not re.fullmatch(r"docker\.io/nousresearch/hermes-agent@sha256:[0-9a-f]{64}", policy["docker_image"])):
        raise ValueError("stable_core_baseline_invalid")
    return policy


def check_outputs(outputs: dict, *, required: bool, candidate: str | None = None,
                  stable: bool = False) -> list[str]:
    if not isinstance(outputs, dict):
        return ["gateway_outputs_malformed"]
    outcome = outputs.get("gateway_result")
    if outcome == "skipped" and not required and not outputs.get("gateway_record"):
        return []
    if outcome != "success":
        return ["gateway_execution_not_success"]
    try:
        record = json.loads(outputs.get("gateway_record", ""))
    except (TypeError, ValueError):
        return ["gateway_record_malformed"]
    sha = candidate if candidate is not None else outputs.get("attested_sha", "")
    if not isinstance(sha, str):
        return ["gateway_candidate_missing"]
    if not isinstance(record, dict):
        return ["gateway_record_malformed"]
    problems = [*validate_receipt(record, sha), *validate_docker_receipt(record)]
    if outputs.get("attested_sha") != sha or record.get("checkout_sha") != sha:
        problems.append("gateway_checkout_identity_mismatch")
    if not isinstance(outputs.get("gateway_core"), str) or record.get("hermes_commit") != outputs["gateway_core"]:
        problems.append("gateway_core_identity_mismatch")
    if stable and outputs.get("gateway_core") != stable_baseline()["commit"]:
        problems.append("gateway_core_not_stable_baseline")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--core", required=True)
    args = parser.parse_args()
    record = json.loads(args.record.read_text(encoding="utf-8"))
    problems = validate_receipt(record, args.candidate)
    if not isinstance(record, dict):
        print("Gateway attestation refused: receipt_not_object")
        return 1
    problems.extend(validate_docker_receipt(record))
    if record.get("hermes_commit") != args.core:
        problems.append("gateway_core_identity_mismatch")
    if problems:
        print("Gateway attestation refused: " + ",".join(problems))
        return 1
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("record=" + json.dumps(record, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
