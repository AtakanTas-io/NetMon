from types import SimpleNamespace

import pytest

from backend import wmi_scanner as module


@pytest.mark.parametrize("message", ["Access is denied", "Erişim Engellendi", "COM 0x80070005"])
def test_access_denied_variants_are_normalized(message):
    assert module.classify_wmi_error(message)[0] == "access_denied"


@pytest.mark.parametrize("message", ["RPC server unavailable", "COM 0x800706ba"])
def test_rpc_variants_are_normalized(message):
    assert module.classify_wmi_error(message)[0] == "rpc_unavailable"


def test_unknown_wmi_error_keeps_safe_summary():
    code, summary = module.classify_wmi_error("unexpected provider failure")
    assert code == "wmi_error"
    assert "unexpected provider failure" in summary


def test_explanation_does_not_include_credentials():
    explanation = module.explain_wmi_error("Access is denied 0x80070005")
    assert explanation["error_code"] == "access_denied"
    assert explanation["os_error_code"] == "0x80070005"
    assert explanation["recommended_actions"]


@pytest.mark.parametrize(("given", "expected"), [(1, 5), (120, 60)])
def test_scanner_timeout_is_bounded(given, expected):
    assert module.WmiNetworkScanner(timeout=given).timeout == expected


def test_remote_target_with_closed_management_ports_fails_without_inventory(monkeypatch):
    scanner = module.WmiNetworkScanner()
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})
    monkeypatch.setattr(scanner, "_probe_management_ports", lambda ip: set())
    result = scanner._scan_single_ip("10.0.0.8")
    assert result["status"] == "Failed"
    assert result["error_code"] == "management_ports_closed"
    assert "hardware" not in result


def test_scan_network_preserves_order_and_contains_thread_failure(monkeypatch):
    scanner = module.WmiNetworkScanner(timeout=5)

    def scan(ip):
        if ip.endswith("2"):
            raise RuntimeError("mock failure")
        return {"ip_address": ip, "status": "Success"}

    monkeypatch.setattr(scanner, "_scan_single_ip", scan)
    results = scanner.scan_network(["10.0.0.1", "10.0.0.2"], max_workers=2)
    assert [item["ip_address"] for item in results] == ["10.0.0.1", "10.0.0.2"]
    assert results[1]["error_code"] == "thread_exception"


def test_winrm_success_is_used_when_wmi_dependency_is_missing(monkeypatch):
    scanner = module.WmiNetworkScanner("user", "secret")
    monkeypatch.setattr(module, "WMI_AVAILABLE", False)
    monkeypatch.setattr(module, "WINRM_AVAILABLE", True)
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})
    monkeypatch.setattr(scanner, "_probe_management_ports", lambda ip: {5985})
    response = SimpleNamespace(status_code=0, std_out=b"HOST01", std_err=b"")
    monkeypatch.setattr(module, "winrm", SimpleNamespace(Session=lambda *a, **k: SimpleNamespace(run_ps=lambda script: response)))
    result = scanner.test_access("10.0.0.9")
    assert result["status"] == "Success"
    assert result["computer_name"] == "HOST01"
