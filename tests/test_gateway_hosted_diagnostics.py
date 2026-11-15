"""Bounded hosted refusal diagnostics never publish raw audit data."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts import gateway_process_policy as policy

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
    frames = [SimpleNamespace(filename='/private/core/hermes_cli/gateway.py', name='_get_service_pids')]
    assert mismatch_diagnostic('systemctl', 'systemctl', '/python', core, frames) == (
        'systemctl', 'unapproved_executable', 'cli_gateway_service_pids')
    frames[0].name = 'secret'
    assert mismatch_diagnostic('systemctl', 'systemctl', '/python', core, frames)[2] == 'cli_gateway'
    frames = [SimpleNamespace(filename='/private/core/hermes_cli/gateway.py', name='_systemd_operational'),
              SimpleNamespace(filename='/private/core/hermes_cli/gateway.py', name='_run_systemctl')]
    command = ['systemctl', '--user', 'is-system-running']
    value = mismatch_diagnostic('systemctl', command[0], '/python', core, frames, command)
    assert value == ('systemctl_status_user', 'unapproved_executable', 'cli_gateway_systemd_operational')
    assert safe_diagnostic(value) == value
    command.append('secret')
    assert mismatch_diagnostic('systemctl', command[0], '/python', core, frames, command)[0] == 'systemctl'
    assert mismatch_diagnostic('systemctl', 'systemctl', '/python', core, frames,
                               ['systemctl', 'is-system-running'])[0] == 'systemctl_status_system'


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


@pytest.mark.parametrize('command', [
    ['systemctl', 'is-system-running'], ['systemctl', '--user', 'is-system-running'],
])
def test_systemctl_status_exact_commands_and_context(tmp_path, command):
    root = tmp_path.resolve()
    runtime = root / 'runtime'
    runtime.mkdir()
    env = {'PATH': '/usr/bin:/bin', 'XDG_RUNTIME_DIR': str(runtime)}
    exists = policy.os.path.lexists

    def no_host_bus(path):
        return False if str(path).startswith('/run/') else exists(path)

    with patch.object(policy.os.path, 'lexists', side_effect=no_host_bus), patch.object(
        policy.shutil, 'which', return_value='/usr/bin/systemctl'), patch.object(
        policy, '_trusted_systemctl', return_value=True):
        def check(c=command, e=env, b=env, **kw):
            return policy.systemctl_status_verdict(
                kw.get('executable', 'systemctl'), c, kw.get('cwd', root), e, root,
                kw.get('confined', True), baseline=b)
        assert check()
        assert policy.systemctl_status_reason('systemctl', command, root, {**env, 'SECRET': 'value'},
                                              root, True, baseline=env) == 'env'
        assert policy.systemctl_status_reason('systemctl', command, root, {**env, 'PYTHONUTF8': '1'},
                                              root, True, baseline=env) == 'env_core_markers'
        assert policy.systemctl_status_reason('systemctl', command, root, {**env, 'PYTHONUTF8': 'secret'},
                                              root, True, baseline=env) == 'env'
        assert safe_diagnostic(('systemctl_block_env_core_markers', 'unapproved_executable',
                                'cli_gateway_systemd_operational')) is not None
        assert safe_diagnostic(('systemctl_block_env', 'unapproved_executable',
                                'cli_gateway_systemd_operational')) is not None
        assert safe_diagnostic(('systemctl_block_SECRET', 'unapproved_executable',
                                'cli_gateway_systemd_operational')) is None
        # The official Core gateway module appends these exact missing system dirs
        # at import time; the resolved executable must still be pinned below.
        core_path = env['PATH'] + ':/sbin:/usr/sbin'
        assert check(e={**env, 'PATH': core_path})
        assert not check(e={**env, 'PATH': '/attacker:' + core_path})
        assert not check(e={**env, 'PATH': env['PATH'] + ':/usr/sbin:/sbin'})
        assert not check(e={**env, 'PATH': core_path + ':/attacker'})
        for unsafe in (':/usr/bin:/bin', '/usr/bin::/bin', '/usr/bin:/bin:', 'relative:/usr/bin:/bin',
                       f'{runtime}:/usr/bin:/bin'):
            poisoned = {**env, 'PATH': unsafe}
            assert not check(e=poisoned, b=poisoned)
        for verb in ('start', 'stop', 'restart', 'daemon-reload', 'enable', 'reset-failed', 'show', 'is-active'):
            assert not check(['systemctl', verb])
        for option in ('--host=elsewhere', '--machine=x', '--root=/', '--no-pager'):
            assert not check(['systemctl', option, 'is-system-running'])
        assert not check(['systemctl', 'is-system-running', 'extra'])
        assert not check(executable='/tmp/systemctl')
        assert not check(confined=False)
        assert not check(cwd=runtime)
        for key in ('PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DBUS_SESSION_BUS_ADDRESS',
                    'DBUS_SYSTEM_BUS_ADDRESS', 'SYSTEMD_BUS_ADDRESS'):
            assert not check(e={**env, key: 'untrusted'})
        assert not check(e={k: v for k, v in env.items() if k != 'PATH'})
        (runtime / 'bus').touch()
        assert not check()


def test_systemctl_status_refuses_wrong_binary(tmp_path):
    root = tmp_path.resolve()
    (root / 'runtime').mkdir()
    env = {'PATH': '/tmp', 'XDG_RUNTIME_DIR': str(root / 'runtime')}
    with patch.object(policy.os.path, 'lexists', return_value=False), patch.object(
        policy.shutil, 'which', return_value='/tmp/systemctl'), patch.object(
        policy, '_trusted_systemctl', return_value=False):
        assert not policy.systemctl_status_verdict('systemctl', ['systemctl', 'is-system-running'],
                                                   root, env, root, True, baseline=env)
