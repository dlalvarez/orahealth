import json

from orahealthcheck.connectors import LocalConnector, SSHConnector, build_os_connector
from orahealthcheck.engine import CheckRunner
from orahealthcheck.models import ConnectionProfile
from fakes import FakeOSConnector


def _results(output):
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    return {r["check_id"]: r for r in evidence["results"]}


def test_factory_selects_connector_by_profile_type():
    assert isinstance(build_os_connector(ConnectionProfile("l", "local", "local")), LocalConnector)
    assert isinstance(build_os_connector(ConnectionProfile("s", "ssh", "password", {"host": "x"})), SSHConnector)


def test_factory_rejects_unknown_type():
    try:
        build_os_connector(ConnectionProfile("w", "winrm", "password"))
    except ValueError as exc:
        assert "winrm" in str(exc)
    else:
        raise AssertionError("se esperaba ValueError")


def test_os_checks_use_target_connection_not_local_host(example_config):
    used = []

    def factory(profile):
        connector = FakeOSConnector(profile=profile)
        used.append(connector)
        return connector

    output = CheckRunner(example_config, os_connector_factory=factory).run_target("example_standalone")
    results = _results(output)
    assert used, "el runner debe construir el conector desde el perfil OS del target"
    assert used[0].profile.connection_id == "local_oracle"
    assert any(cmd.startswith("df -P -k") for cmd in used[0].commands)
    assert results["os_filesystem_usage"]["status"] == "PASS"
    assert used[0].closed, "las conexiones OS deben cerrarse al terminar la ejecución"


def test_os_filesystem_threshold_uses_remote_values(example_config):
    outputs = {"df -P -k": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sdb1 100 97 3 97% /u01\n"}
    output = CheckRunner(example_config, os_connector_factory=lambda p: FakeOSConnector(outputs, p)).run_target("example_standalone")
    assert _results(output)["os_filesystem_usage"]["status"] == "CRITICAL"


def test_os_checks_skip_without_os_connection(example_config):
    example_config["targets"]["example_standalone"].operating_system = {"platform": "linux"}
    results = _results(CheckRunner(example_config).run_target("example_standalone"))
    for check_id in ("os_cpu", "os_memory", "os_filesystem_usage"):
        if check_id in results:
            assert results[check_id]["status"] == "SKIPPED"


def test_local_connector_reports_timeout_as_structured_error():
    result = LocalConnector().run_command("sleep 2", timeout=1)
    assert result["success"] is False
    assert result["exit_code"] is None
    assert result["error"]["type"] == "TimeoutExpired"
