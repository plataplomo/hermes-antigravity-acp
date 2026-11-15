"""Bounded hosted refusal diagnostics never publish raw audit data."""
import json
from pathlib import Path
from types import SimpleNamespace

from scripts.gateway_docker import sanitized_diagnostics
from scripts.gateway_e2e import refusal_diagnostics
from scripts.gateway_process_policy import mismatch_diagnostic, safe_diagnostic


def test_mismatch_classifies_without_raw_values():
    core = Path('/private/core')
    frames = [SimpleNamespace(filename='/private/core/hermes_cli/version_info.py'),
              SimpleNamespace(filename='/private/core/unknown-secret.py')]
    assert mismatch_diagnostic('/bin/uname', '/bin/uname', '/python', core, frames) == (
        'uname', 'unapproved_executable', 'cli_version_info')
    assert mismatch_diagnostic('/evil/secret', '/private/secret', '/python', core, frames) == (
        'other', 'both', 'cli_version_info')
    assert mismatch_diagnostic('/evil/git', 'git', '/python', core, []) == (
        'git', 'executable_argv0', 'other')
    # A suffix match is not an official Core frame.
    frames = [SimpleNamespace(filename='/other/hermes_cli/version_info.py')]
    assert mismatch_diagnostic('/bin/uname', '/bin/uname', '/python', core, frames)[2] == 'other'


def test_audit_to_host_filters_every_untrusted_field(tmp_path):
    good = ['uname', 'unapproved_executable', 'cli_version_info']
    rows = [
        {'reason': 'subprocess_executable_mismatch', 'diagnostic': good, 'frames': [{'file': '/private/secret'}]},
        {'reason': 'subprocess_executable_mismatch', 'diagnostic': ['secret', *good[1:]]},
        {'reason': 'other', 'diagnostic': good},
        {'reason': 'subprocess_executable_mismatch', 'diagnostic': [*good, 'secret']},
    ]
    (tmp_path / 'audit-refusals.jsonl').write_text('\n'.join(map(json.dumps, rows)) + '\nnot-json\n')
    assert refusal_diagnostics(tmp_path) == {tuple(good)}
    log = tmp_path / 'container.log'
    log.write_text('secret /private/secret\nPHASEC_REFUSAL_DIAGNOSTIC ' + ' '.join(good) +
                   '\nPHASEC_REFUSAL_DIAGNOSTIC uname unapproved_executable secret\n' +
                   'PHASEC_REFUSAL_DIAGNOSTIC uname unapproved_executable cli_version_info /secret\n')
    assert sanitized_diagnostics(log) == {tuple(good)}
    assert safe_diagnostic(['uname', 'unapproved_executable', '/private/secret']) is None
