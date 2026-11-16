"""Offline boundary contract negatives. Never use a Docker daemon or import Core."""
from __future__ import annotations

from copy import deepcopy
import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

from scripts import gateway_docker as docker
from scripts.gateway_process_policy import shutdown_command_verified


class DockerBoundaryTests(unittest.TestCase):
    def facts(self):
        return {"Config": {"User": "1001:1001"}, "HostConfig": {
            "Privileged": False, "Init": False, "ReadonlyRootfs": True, "NetworkMode": "none", "PidMode": "", "IpcMode": "none",
            "PidsLimit": 128, "Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3, "NanoCpus": 2 * 10**9,
            "PortBindings": {}, "CapAdd": None, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
            "Devices": [], "DeviceRequests": []},
            "Mounts": [{"Destination": "/source", "Source": "/source", "RW": False},
                       {"Destination": docker.MASK_DESTINATION, "Source": str(docker.MASK_SOURCE), "RW": False},
                       {"Destination": "/gw", "Source": "/private/work", "RW": True},
                       {"Destination": docker.POLICY, "Source": "/private/policy", "RW": False}]}

    def verify(self, facts):
        return docker.config_verified(facts, 1001, 1001, [Path("/source")], Path("/private/work"), Path("/private/policy"))

    def test_options_have_no_privilege_network_socket_or_port_escape(self):
        options = docker.docker_options(1001, 1001, [Path("/source")], Path("/private/work"), Path("/private/policy"))
        for required in ("--cap-drop=ALL", "--network=none", "--read-only", "--security-opt=no-new-privileges",
                         "--pids-limit", "--memory=2g", "--cpus=2", "--restart=no", "--pull=never", "--init=false"):
            self.assertIn(required, options)
        for forbidden in ("--privileged", "--pid=host", "--network=host", "--publish", "docker.sock", "--cap-add"):
            self.assertNotIn(forbidden, " ".join(options))
        with self.assertRaises(ValueError):
            docker.docker_options(0, 0, [], Path("/private/work"), Path("/private/policy"))

    def test_init_null_is_not_false_and_missing_is_not_a_default(self):
        def checks(facts):
            return docker.config_checks(facts, 1001, 1001, [Path("/source")], Path("/private/work"), Path("/private/policy"))
        facts = self.facts()
        self.assertTrue(all(status == "PASS" for status in checks(facts).values()))
        for value, status in ((None, "MISMATCH"), (False, "PASS"), (True, "MISMATCH"), (0, "MISMATCH")):
            with self.subTest(init=value):
                facts["HostConfig"]["Init"] = value
                self.assertEqual(status, checks(facts)["HostConfig.Init"])
                self.assertEqual(value is False, self.verify(facts))
        for section, key in (("Config", "User"), *(("HostConfig", key) for key in self.facts()["HostConfig"])):
            with self.subTest(missing=f"{section}.{key}"):
                facts = self.facts()
                del facts[section][key]
                self.assertEqual("MISSING", checks(facts)[f"{section}.{key}"])
                self.assertFalse(self.verify(facts))
        facts = self.facts()
        facts["Config"]["Env"] = ["PRIVATE=must-not-be-serialized"]
        rendered = str(checks(facts))
        for forbidden in ("must-not-be-serialized", "/private/", "/source", "1001"):
            self.assertNotIn(forbidden, rendered)
        facts["HostConfig"]["SecurityOpt"] = ["no-new-privileges=true"]
        self.assertTrue(self.verify(facts))

    def test_removal_requires_successful_structured_absence_readback(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        for kind, identity in (("container", "a" * 64), ("image", "sha256:" + "b" * 64)):
            for rm_code, list_code, residual, expected in ((0, 0, False, True), (1, 0, False, False),
                                                          (0, 1, False, False), (0, 0, True, False)):
                with self.subTest(kind=kind, rm_code=rm_code, list_code=list_code, residual=residual):
                    caller = Mock(side_effect=[SimpleNamespace(returncode=rm_code), SimpleNamespace(
                        returncode=list_code, stdout=identity.encode() + b"\n" if residual else b"", stderr=b"Error: no such object")])
                    self.assertEqual(expected, docker.remove_owned(caller, kind, identity))
                    arguments = caller.call_args_list[1].args
                    self.assertIn("--no-trunc", arguments)
                    self.assertEqual((kind, "ls"), arguments[:2])
                    if kind == "container":
                        self.assertIn("id=" + identity, arguments)
        with self.assertRaises(ValueError):
            docker.remove_owned(Mock(), "unknown", "unused")

    def test_real_inspect_contract_rejects_each_relaxed_boundary(self):
        self.assertTrue(self.verify(self.facts()))
        for key, value in (("Privileged", True), ("Init", True), ("ReadonlyRootfs", False), ("NetworkMode", "host"),
                           ("PidMode", "host"), ("IpcMode", "host"), ("PidsLimit", 0), ("Memory", 0),
                           ("MemorySwap", -1), ("NanoCpus", 0), ("CapDrop", []), ("SecurityOpt", []),
                           ("CapAdd", ["SYS_ADMIN"]), ("PortBindings", {"8080/tcp": []}),
                           ("Devices", ["/dev/kmsg"]), ("DeviceRequests", [{}])):
            with self.subTest(key=key):
                facts = deepcopy(self.facts())
                facts["HostConfig"][key] = value
                self.assertFalse(self.verify(facts))
        facts = self.facts()
        facts["Config"]["User"] = "0"
        self.assertFalse(self.verify(facts))

    def test_ro_source_and_exact_mount_set_required(self):
        for changed in ("writable", "socket", "missing"):
            facts = self.facts()
            if changed == "writable":
                facts["Mounts"][0]["RW"] = True
            elif changed == "socket":
                facts["Mounts"].append({"Destination": "/var/run/docker.sock", "Source": "/var/run/docker.sock", "RW": True})
            else:
                facts["Mounts"].pop()
            self.assertFalse(self.verify(facts))

    def test_mask_is_required_exact_readonly_mount(self):
        expected = f'type=bind,src={docker.MASK_SOURCE},dst={docker.MASK_DESTINATION},readonly'
        options = docker.docker_options(1001, 1001, [Path('/source')], Path('/private/work'), Path('/private/policy'))
        self.assertIn(expected, options)
        for change in ('missing', 'writable', 'foreign', 'duplicate'):
            facts = self.facts()
            if change == 'missing':
                facts['Mounts'].pop(1)
            elif change == 'writable':
                facts['Mounts'][1]['RW'] = True
            elif change == 'foreign':
                facts['Mounts'][1]['Source'] = '/attacker'
            else:
                facts['Mounts'].append(dict(facts['Mounts'][1]))
            self.assertFalse(self.verify(facts), change)

    def test_mask_inputs_require_root_owned_regular_nonexecutable_file(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        import stat
        source = MagicMock()
        source.resolve.return_value = source
        source.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1)
        target = MagicMock()
        target.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch.object(docker, 'MASK_SOURCE', source), patch.object(docker, 'Path', return_value=target):
            self.assertTrue(docker.mask_inputs_verified())
            for mode, uid in ((stat.S_IFREG | 0o755, 0), (stat.S_IFREG | 0o666, 0),
                              (stat.S_IFLNK | 0o644, 0), (stat.S_IFREG | 0o644, 1001)):
                source.lstat.return_value = SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=1)
                self.assertFalse(docker.mask_inputs_verified())
            source.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1)
            target.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
            self.assertFalse(docker.mask_inputs_verified())

    def test_container_mask_identity_permissions_and_exec_denial(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        import stat
        source = MagicMock()
        source.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1,
                                                   st_dev=7, st_ino=19)
        matched = SimpleNamespace(st_dev=7, st_ino=19)
        with patch.object(docker, 'MASK_SOURCE', source), patch.object(docker.os, 'geteuid', return_value=1001), \
             patch.object(docker.os, 'stat', return_value=matched) as actual, \
             patch.object(docker.os, 'access', return_value=False), \
             patch.object(docker, '_open_denied', return_value=True), \
             patch.object(docker.subprocess, 'run', side_effect=PermissionError) as run:
            self.assertTrue(docker.systemctl_mask_verified())
            self.assertEqual(run.call_count, 3)
            actual.return_value = SimpleNamespace(st_dev=7, st_ino=20)
            self.assertFalse(docker.systemctl_mask_verified())
            actual.return_value = matched
            source.stat.return_value.st_nlink = 2
            self.assertFalse(docker.systemctl_mask_verified())
            source.stat.return_value.st_nlink = 1
            source.stat.return_value.st_uid = 1001
            self.assertFalse(docker.systemctl_mask_verified())
            source.stat.return_value.st_uid = 0
            source.stat.return_value.st_mode = stat.S_IFREG | 0o664
            self.assertFalse(docker.systemctl_mask_verified())
            source.stat.return_value.st_mode = stat.S_IFREG | 0o644
            run.side_effect = None
            self.assertFalse(docker.systemctl_mask_verified())

    def test_service_checks_fail_closed_on_binary_or_bus(self):
        with patch.dict('os.environ', {'PATH': '/usr/bin:/bin'}, clear=True), patch.object(
            docker.shutil, 'which', return_value=None) as which, patch.object(
            docker.os.path, 'lexists', return_value=False) as exists, patch.object(
            Path, 'read_text', return_value='python\n') as proc:
            self.assertEqual((True, True), docker.system_services_unavailable())
            self.assertEqual(which.call_count, 2)
            which.side_effect = [None, '/usr/sbin/systemctl']
            self.assertEqual((False, True), docker.system_services_unavailable())
            which.side_effect = None
            exists.side_effect = lambda path: str(path) == '/run/dbus/system_bus_socket'
            self.assertEqual((True, False), docker.system_services_unavailable())
            exists.side_effect = None
            proc.return_value = 'systemd\n'
            self.assertEqual((True, False), docker.system_services_unavailable())
            proc.return_value = 'python\n'
            with patch.dict('os.environ', {'DBUS_SESSION_BUS_ADDRESS': 'unsafe'}):
                self.assertEqual((True, False), docker.system_services_unavailable())

    def test_no_boolean_opt_in_can_manufacture_namespace_proof(self):
        with patch.dict("os.environ", {"PHASE_C_DOCKER_POLICY": "true"}, clear=True):
            self.assertFalse(docker.namespace_verified())
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(docker.namespace_verified())

    def test_missing_or_false_actual_confinement_check_fails(self):
        good = {"confinement": {"status": "PASS", "checks": {name: True for name in docker.CHECKS}, "pid_namespace_sha256": "1" * 64, "host_pid_namespace_sha256": "2" * 64}}
        self.assertEqual([], docker.validate_confinement(good))
        for name in docker.CHECKS:
            for value in (False, "true", None):
                bad = deepcopy(good)
                bad["confinement"]["checks"][name] = value
                self.assertTrue(docker.validate_confinement(bad))
        self.assertTrue(docker.validate_confinement({}))
        self.assertTrue(docker.validate_docker_receipt(good))

    def test_rootfs_lib64_symlink_resolves_to_mounted_linker_dir(self):
        import io
        import tarfile
        from pathlib import Path as P
        if not P("/lib64/ld-linux-x86-64.so.2").exists():
            self.skipTest("x86_64 linker path absent on this host")
        with tarfile.open(fileobj=io.BytesIO(docker.rootfs_bytes(1001, 1001))) as archive:
            targets = {member.name: member.linkname for member in archive.getmembers() if member.issym()}
        self.assertEqual(targets["lib64"], str(P("/lib64/ld-linux-x86-64.so.2").resolve(strict=True).parent).lstrip("/"))
        self.assertTrue((P("/") / targets["lib64"] / "ld-linux-x86-64.so.2").is_file())

    def test_source_absence_is_not_write_protection_evidence(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="gw-denial-control-") as directory:
            missing = str(Path(directory) / "missing-source")
            import os
            self.assertFalse(docker._open_denied(missing, os.O_WRONLY))
            self.assertTrue(docker._open_denied(missing, os.O_WRONLY, missing_ok=True))

    def test_outer_attestation_cleanup_and_contract_are_mandatory(self):
        good = {"candidate_sha": "a" * 40, "confinement": {"status": "PASS", "checks": {name: True for name in docker.CHECKS},
                                "pid_namespace_sha256": "1" * 64, "host_pid_namespace_sha256": "2" * 64},
                "docker_execution": {"status": "PASS", "config_verified": True, "owned_pid_namespace_verified": True,
                                     "outside_canary_unchanged": True, "container_removed": True, "image_removed": True},
                "docker_contract_version": 2, "checkout_sha": "a" * 40,
                "final_namespace_live_count": 1, "final_namespace_process_count": 1}
        self.assertEqual([], docker.validate_docker_receipt(good))
        for key in ("docker_execution", "docker_contract_version", "checkout_sha", "final_namespace_live_count", "final_namespace_process_count", "confinement"):
            with self.subTest(missing=key):
                bad = deepcopy(good)
                bad.pop(key)
                self.assertTrue(docker.validate_docker_receipt(bad))
        bad = deepcopy(good)
        bad["confinement"]["host_pid_namespace_sha256"] = "1" * 64
        self.assertTrue(docker.validate_docker_receipt(bad))
        for key in ("config_verified", "owned_pid_namespace_verified", "outside_canary_unchanged", "container_removed", "image_removed"):
            bad = deepcopy(good)
            bad["docker_execution"][key] = False
            self.assertTrue(docker.validate_docker_receipt(bad))

    def test_rootfs_has_no_host_credentials_or_operating_files(self):
        with tarfile.open(fileobj=io.BytesIO(docker.rootfs_bytes(1001, 1001))) as rootfs:
            files = {item.name for item in rootfs if item.isfile()}
            self.assertEqual({"etc/passwd", "etc/group", "etc/nsswitch.conf"}, files)
            stream = rootfs.extractfile("etc/passwd")
            self.assertIsNotNone(stream)
            assert stream is not None
            self.assertIn(b"fixture:x:1001:1001", stream.read())

    def test_shutdown_admission_never_evaluates_source_calls(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="gw-shutdown-policy-") as directory:
            core = Path(directory)
            (core / "gateway").mkdir()
            source = core / "gateway/shutdown_forensics.py"
            source.write_text('def _async_diagnostic_script(signal_name, self_pid):\n    return f"fixed {signal_name} {self_pid}"\n')
            good = ["/usr/bin/timeout", "5", "bash", "-c", "fixed SIGINT 12"]
            self.assertTrue(shutdown_command_verified(good[0], good, core, 12))
            for bad in (good + ["extra"], [*good[:4], "arbitrary"], [good[0], "50", *good[2:]]):
                self.assertFalse(shutdown_command_verified(bad[0], bad, core, 12))
            source.write_text('def _async_diagnostic_script(signal_name, self_pid):\n    return dangerous_call()\n')
            self.assertFalse(shutdown_command_verified(good[0], good, core, 12))


if __name__ == "__main__":
    unittest.main()
