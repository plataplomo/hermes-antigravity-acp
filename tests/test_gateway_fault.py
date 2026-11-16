"""Fail-closed validation of the single hosted Gateway fault receipt."""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

from scripts import gateway_e2e
from scripts.gateway_fault_check import validate_fault
from tests import test_gateway_e2e as evidence

CANDIDATE = "a" * 40
CORE = "b" * 40


def good_receipt():
    record = evidence.GatewayEvidenceTests().receipt()
    record.update(status="FAIL", run_id="123", run_attempt="1", checkout_sha=CANDIDATE,
                  fault_observation={"scenario": "prompt_held_driver_error", "held_tree_live": True},
                  cleanup_diagnostics={"owner_exit": "zero", "forced_reasons": [], "owner_exit_seconds": 12.5,
                                       "fixture_exit": {"status": "complete", "unmet": []}})
    for name in ("permission_denial", "cancellation", "ownership_conflict", "owner_survives"):
        record["stages"][name] = {"status": "NOT_RUN", "detail": "not_executed"}
    record["stages"]["injected_fault"] = {"status": "FAIL", "detail": "injected_fault_while_prompt_held"}
    return record


def test_driver_reports_injected_failure_after_observing_live_held_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway_e2e, "_git", lambda *_: CORE)
    monkeypatch.setattr(gateway_e2e, "_snapshot", lambda *_: "unchanged")
    monkeypatch.setattr(gateway_e2e, "namespace_verified", lambda: False)
    monkeypatch.setattr(gateway_e2e, "_live", lambda *_: True)
    origin = {"tree_sha256": "3" * 64, "home_sha256": "4" * 64, "errors": [], "frozen_copies": 0}
    monkeypatch.setattr(gateway_e2e, "ProviderOrigin", lambda *_: SimpleNamespace(receipt=lambda: origin))
    run = gateway_e2e.Run(tmp_path, tmp_path, tmp_path, CANDIDATE, 1, inject_fault=True)
    run.plugin.mkdir(parents=True)
    (run.plugin / "__init__.py").write_text("candidate")
    digest = hashlib.sha256((run.plugin / "__init__.py").read_bytes()).hexdigest()
    (tmp_path / "gateway-envelope.json").write_text(json.dumps({"core_bootstrap_from_requested_source": True,
                                                               "loaded_provider_sha256": [digest],
                                                               "provider_origin": origin}))
    run.prepare = lambda: None
    run.start = lambda: SimpleNamespace(pid=123)
    run.ready = lambda: True
    run.verify_reply = lambda: None
    counts = iter((0, 1))
    run.event_count = lambda name: 1 if name == "initialize" else next(counts)
    run.control = lambda _: None
    run.http = lambda *_args, **_kwargs: {"run_id": "synthetic"}
    run.events = lambda: [{"event": "server_started", "pid": 41, "started": "1", "grandchild_pid": 42,
                           "grandchild_started": "2"}, {"event": "prompt_held", "pid": 41}]
    run.wait = lambda predicate, _detail: predicate()
    run.cleanup = lambda: None
    result = run.execute()
    assert result["status"] == "FAIL"
    assert result["stages"]["injected_fault"] == {"status": "FAIL", "detail": "injected_fault_while_prompt_held"}
    assert result["fault_observation"] == {"scenario": "prompt_held_driver_error", "held_tree_live": True}
    assert gateway_e2e.validate_receipt(result, CANDIDATE)


def test_expected_failure_and_complete_cleanup_are_accepted():
    assert validate_fault(good_receipt(), CANDIDATE, CORE, "123", "1", 1) == []


def test_contradictory_or_incomplete_evidence_is_rejected():
    original = good_receipt()
    mutants = []
    for key, value in (("status", "PASS"), ("candidate_sha", "c" * 40), ("checkout_sha", "c" * 40),
                       ("hermes_commit", "c" * 40), ("run_id", "456"), ("candidate_source_dirty", True),
                       ("boundary_refusal_reasons", ["unapproved_subprocess"]),
                       ("live_owned_children_after_exit", 1), ("owned_child_count", 0),
                       ("final_namespace_live_count", 2), ("final_namespace_process_count", 2)):
        value_record = deepcopy(original)
        value_record[key] = value
        mutants.append(value_record)
    for section, key, value in (("fault_observation", "held_tree_live", False),
                                ("cleanup_diagnostics", "owner_exit", "signal"),
                                ("cleanup_diagnostics", "owner_exit_seconds", None),
                                ("cleanup_diagnostics", "owner_exit_seconds", 0),
                                ("cleanup_diagnostics", "forced_reasons", ["fixture_child_alive"]),
                                ("docker_execution", "container_removed", False),
                                ("docker_execution", "image_removed", False),
                                ("docker_execution", "outside_canary_unchanged", False)):
        value_record = deepcopy(original)
        value_record[section][key] = value
        mutants.append(value_record)
    for stage, status in (("injected_fault", "PASS"), ("gateway_ready", "FAIL"),
                          ("request_response", "NOT_RUN"), ("permission_denial", "PASS"),
                          ("shutdown", "FAIL"), ("child_cleanup", "FAIL"), ("source_unchanged", "FAIL")):
        value_record = deepcopy(original)
        value_record["stages"][stage]["status"] = status
        mutants.append(value_record)
    for mutant in mutants:
        assert validate_fault(mutant, CANDIDATE, CORE, "123", "1", 1)
    assert validate_fault(original, CANDIDATE, CORE, "123", "1", 0)
    assert validate_fault(original, CANDIDATE, CORE, "123", "1", 2)
    assert validate_fault({}, CANDIDATE, CORE, "123", "1", 1)
