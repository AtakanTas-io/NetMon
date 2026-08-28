from types import SimpleNamespace

import pytest

from backend import deep_discovery as module


def test_windows_scan_without_management_dependencies_returns_no_hardware(monkeypatch):
    monkeypatch.setattr(module, "HAS_WINRM", False)
    monkeypatch.setattr(module, "HAS_WMI", False)
    result = module.scan_windows_deep("10.0.0.2")
    assert result["status"] == "Failed"
    assert result["hardware"] == {}


def test_windows_winrm_success_returns_measured_inventory(monkeypatch):
    payload = b'{"ComputerName":"PC1","Manufacturer":"ACME","Model":"M1","SerialNumber":"S1","OS":"Windows","OSVersion":"11","RAM_GB":16,"CPU":"CPU","Cores":8}'
    response = SimpleNamespace(status_code=0, std_out=payload)
    monkeypatch.setattr(module, "HAS_WINRM", True)
    monkeypatch.setattr(
        module, "winrm", SimpleNamespace(Session=lambda *a, **k: SimpleNamespace(run_ps=lambda script: response))
    )
    result = module.scan_windows_deep("10.0.0.2", "user", "secret")
    assert result["status"] == "Success"
    assert result["hardware"]["ram_gb"] == 16


def test_ssh_dependency_missing(monkeypatch):
    monkeypatch.setattr(module, "HAS_PARAMIKO", False)
    assert module.test_ssh_access("10.0.0.2", "user")["error_code"] == "ssh_dependency_missing"


def test_ssh_username_is_required(monkeypatch):
    monkeypatch.setattr(module, "HAS_PARAMIKO", True)
    assert module.test_ssh_access("10.0.0.2", "")["error_code"] == "missing_credentials"


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("Authentication failed", "ssh_auth_failed"),
        ("Host key not found in known_hosts", "ssh_host_key_rejected"),
        ("Connection timed out", "ssh_unreachable"),
    ],
)
def test_ssh_errors_are_classified(monkeypatch, message, code):
    class Client:
        def load_system_host_keys(self):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *a, **k):
            raise RuntimeError(message)

        def close(self):
            pass

    monkeypatch.setattr(module, "HAS_PARAMIKO", True)
    monkeypatch.setattr(module, "paramiko", SimpleNamespace(SSHClient=Client, RejectPolicy=lambda: object()))
    assert module.test_ssh_access("10.0.0.2", "user")["error_code"] == code


def test_ssh_success_reports_server_version(monkeypatch):
    class Client:
        def load_system_host_keys(self):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *a, **k):
            pass

        def get_transport(self):
            return SimpleNamespace(remote_version="SSH-2.0-Mock")

        def close(self):
            pass

    monkeypatch.setattr(module, "HAS_PARAMIKO", True)
    monkeypatch.setattr(module, "paramiko", SimpleNamespace(SSHClient=Client, RejectPolicy=lambda: object()))
    result = module.test_ssh_access("10.0.0.2", "user")
    assert result["status"] == "Success"
    assert result["server_version"] == "SSH-2.0-Mock"


def test_snmp_requires_explicit_community():
    result = module.scan_snmp_deep("10.0.0.2", community="")
    assert result["status"] == "Failed"
    assert "community" in result["error"]


@pytest.mark.parametrize(("ports", "scanner"), [([135], "windows"), ([22], "linux"), ([161], "snmp")])
def test_decision_engine_selects_observed_protocol(monkeypatch, ports, scanner):
    called = []
    monkeypatch.setattr(
        module,
        "scan_windows_deep",
        lambda *a, **k: called.append("windows") or {"status": "Success", "hardware": {"cpu": "x"}},
    )
    monkeypatch.setattr(
        module,
        "scan_linux_deep",
        lambda *a, **k: called.append("linux") or {"status": "Success", "hardware": {"cpu": "x"}},
    )
    monkeypatch.setattr(
        module,
        "scan_snmp_deep",
        lambda *a, **k: called.append("snmp") or {"status": "Success", "hardware": {"model": "x"}},
    )
    result = module.integrate_discovery_flow({"ip": "10.0.0.2", "open_ports": ports})
    assert called == [scanner]
    assert result["deep_inventory"]["status"] == "Success"


def test_decision_engine_does_not_invent_inventory_without_protocol():
    result = module.integrate_discovery_flow({"ip": "10.0.0.2", "open_ports": []})
    assert result["deep_inventory"]["status"] == "Unavailable"
    assert "fallback_inventory" not in result


def test_decision_engine_contains_scanner_exception(monkeypatch):
    monkeypatch.setattr(module, "scan_linux_deep", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("mock failure")))
    result = module.integrate_discovery_flow({"ip": "10.0.0.2", "open_ports": [22]})
    assert result["deep_inventory"]["status"] == "Failed"
    assert "mock failure" in result["deep_inventory"]["error"]


def test_parallel_flow_preserves_input_order(monkeypatch):
    monkeypatch.setattr(module, "integrate_discovery_flow", lambda device, credentials=None: dict(device, done=True))
    devices = [{"ip": "10.0.0.2"}, {"ip": "10.0.0.1"}]
    results = module.parallel_integrate_discovery_flow(devices, max_workers=2)
    assert [item["ip"] for item in results] == ["10.0.0.2", "10.0.0.1"]


def test_linux_inventory_parses_hardware_packages_and_storage(monkeypatch):
    outputs = iter(
        [
            "Linux host 6.8",
            "Ubuntu 24.04",
            "Mock CPU",
            "16384",
            "8",
            "ACME",
            "Model X",
            "SERIAL1",
            "host1",
            "x86_64",
            "alice",
            "Status: active",
            "/dev/sda1 107374182400 53687091200 53687091200 50% /",
            "curl 8.0\npython3 3.12",
        ]
    )

    class Stream:
        def __init__(self, value):
            self.value = value

        def read(self):
            return self.value.encode()

    class Client:
        def load_system_host_keys(self):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *a, **k):
            pass

        def exec_command(self, command, timeout):
            return None, Stream(next(outputs)), Stream("")

        def close(self):
            pass

    monkeypatch.setattr(module, "HAS_PARAMIKO", True)
    monkeypatch.setattr(module, "paramiko", SimpleNamespace(SSHClient=Client, RejectPolicy=lambda: object()))
    result = module.scan_linux_deep("10.0.0.2", "user", "secret")
    assert result["status"] == "Success"
    assert result["hardware"]["ram_gb"] == 16
    assert result["software"]["installed_programs"][0]["name"] == "curl"
    assert result["storage"][0]["drive_letter"] == "/"


def test_linux_inventory_connection_failure_is_safe(monkeypatch):
    class Client:
        def load_system_host_keys(self):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *a, **k):
            raise RuntimeError("denied")

        def close(self):
            pass

    monkeypatch.setattr(module, "HAS_PARAMIKO", True)
    monkeypatch.setattr(module, "paramiko", SimpleNamespace(SSHClient=Client, RejectPolicy=lambda: object()))
    result = module.scan_linux_deep("10.0.0.2", "user", "secret")
    assert result["status"] == "Failed"
    assert result["error"] == "denied"


def test_snmp_success_parses_observed_strings(monkeypatch):
    responses = iter([b"\x04\x0bMock Router", b"\x04\x05edge1"])

    class FakeSocket:
        def settimeout(self, value):
            assert value == 0.5

        def sendto(self, payload, target):
            assert target == ("10.0.0.2", 161)

        def recvfrom(self, size):
            return next(responses), ("10.0.0.2", 161)

        def close(self):
            pass

    monkeypatch.setattr(module.socket, "socket", lambda *a: FakeSocket())
    result = module.scan_snmp_deep("10.0.0.2", "public", timeout=1.0)
    assert result["status"] == "Success"
    assert result["system"]["sys_name"] == "edge1"


def test_parallel_flow_returns_empty_for_empty_input():
    assert module.parallel_integrate_discovery_flow([]) == []
