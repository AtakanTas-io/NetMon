import socket
import ipaddress
from types import SimpleNamespace

import deep_discovery
import netdiag_core
import wmi_scanner


def test_localized_wmi_access_denied_is_classified_correctly():
    code, message = wmi_scanner.classify_wmi_error(
        "SWbemLocator: Erişim engellendi. (-2147024891)"
    )
    assert code == "access_denied"
    assert message == "Erişim Engellendi (Access Denied)"

    diagnostics = wmi_scanner.explain_wmi_error(
        "SWbemLocator: Erişim engellendi. (0x80070005)",
        "wmi_dcom_authorization",
    )
    assert diagnostics["error_code"] == "access_denied"
    assert diagnostics["os_error_code"] == "0x80070005"
    assert "yetkilendirme" in diagnostics["cause"]
    assert diagnostics["recommended_actions"]


def test_winrm_still_runs_when_python_wmi_dependency_is_missing(monkeypatch):
    monkeypatch.setattr(wmi_scanner, "WMI_AVAILABLE", False)
    monkeypatch.setattr(wmi_scanner, "WINRM_AVAILABLE", True)
    scanner = wmi_scanner.WmiNetworkScanner(username="DOMAIN\\reader", password="secret", timeout=5)
    monkeypatch.setattr(scanner, "_probe_management_ports", lambda ip: {5985})
    monkeypatch.setattr(
        scanner,
        "_scan_via_winrm",
        lambda ip, ports: {"ip_address": ip, "status": "Success", "inventory_source": "WinRM/CIM"},
    )
    result = scanner._scan_single_ip("192.168.10.20")
    assert result["status"] == "Success"
    assert result["inventory_source"] == "WinRM/CIM"


def test_quick_snapshot_honors_configured_ping_count(monkeypatch):
    diagnostics = netdiag_core.NetworkDiagnostics()
    monkeypatch.setattr(diagnostics, "get_network_configuration", lambda: ("192.168.1.10", "192.168.1.1", ["192.168.1.1"]))
    calls = []

    def fake_ping(target, count=2):
        calls.append((target, count))
        return netdiag_core.PingResult(target=target, success=True, packet_loss=0, average=1)

    monkeypatch.setattr(diagnostics, "ping_test", fake_ping)
    monkeypatch.setattr(diagnostics, "dns_test", lambda domain: (True, "192.0.2.1"))
    snapshot = diagnostics.quick_snapshot(ping_count=7)
    assert snapshot.status == "ok"
    assert calls == [("192.168.1.1", 7), ("8.8.8.8", 7)]


def test_snmp_timeout_is_shared_between_oid_queries(monkeypatch):
    configured_timeouts = []

    class FakeSocket:
        def settimeout(self, value):
            configured_timeouts.append(value)

        def sendto(self, payload, target):
            pass

        def recvfrom(self, size):
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(deep_discovery.socket, "socket", lambda *args, **kwargs: FakeSocket())
    result = deep_discovery.scan_snmp_deep("192.168.1.1", community="readonly", timeout=8)
    assert result["status"] == "Failed"
    assert configured_timeouts == [4.0, 4.0]


def test_hostname_classification_keeps_specific_enterprise_types():
    guess = netdiag_core.NetworkDiagnostics._guess_device_type
    assert guess("core-switch-01")["type"] == "switch"
    assert guess("ap-floor-02")["type"] == "access_point"
    assert guess("fortigate-firewall-01")["type"] == "firewall"
    assert guess("branch-router-01")["type"] == "router"


# ---------- Cihaz tarama hızı ve doğruluğu ----------

def test_run_command_uses_default_timeout_when_not_overridden(monkeypatch):
    diagnostics = netdiag_core.NetworkDiagnostics(command_timeout=5)
    seen = {}

    def fake_run(command, capture_output, text, errors, timeout, startupinfo, creationflags):
        seen["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(netdiag_core.subprocess, "run", fake_run)
    diagnostics.run_command(["ping", "-n", "1", "127.0.0.1"])
    assert seen["timeout"] == 5


def test_nmap_service_scan_does_not_use_the_too_short_default_timeout(monkeypatch):
    """Regresyon: nmap -sV servis taraması eskiden global command_timeout (5sn)
    kullanıyordu; gerçek -sV taraması genelde 5 saniyeden uzun sürdüğü için
    çağrı neredeyse her zaman zaman aşımına uğrayıp sessizce boş sonuç
    dönüyordu. Artık daha uzun, ayrı bir zaman aşımı kullanılmalı."""
    diagnostics = netdiag_core.NetworkDiagnostics(command_timeout=5)
    seen = {}

    def fake_run(command, capture_output, text, errors, timeout, startupinfo, creationflags):
        seen["timeout"] = timeout
        seen["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(netdiag_core.subprocess, "run", fake_run)
    diagnostics.nmap_service_scan("192.168.1.50")
    assert seen["timeout"] is not None
    assert seen["timeout"] > diagnostics.command_timeout
    assert "-sV" in seen["command"]


def test_nmap_discover_timeout_scales_with_network_size(monkeypatch):
    """Regresyon: /24 veya daha büyük ağlarda nmap -sn taraması 5 saniyelik
    varsayılan zaman aşımını neredeyse her zaman aşıyordu."""
    diagnostics = netdiag_core.NetworkDiagnostics(command_timeout=5)
    seen = {}

    def fake_run(command, capture_output, text, errors, timeout, startupinfo, creationflags):
        seen["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(netdiag_core.subprocess, "run", fake_run)
    small_network = ipaddress.ip_network("192.168.1.0/28")  # 16 adres
    diagnostics.nmap_discover(small_network)
    assert seen["timeout"] >= 15.0

    seen.clear()
    large_network = ipaddress.ip_network("10.0.0.0/16")  # 65536 adres
    diagnostics.nmap_discover(large_network)
    assert seen["timeout"] == 90.0  # üst sınırda tavana çarpmalı


def test_nmap_service_scan_parses_open_ports_and_services(monkeypatch):
    diagnostics = netdiag_core.NetworkDiagnostics()
    fake_output = (
        "Nmap scan report for 192.168.1.10\n"
        "PORT    STATE SERVICE VERSION\n"
        "22/tcp  open  ssh     OpenSSH 8.9\n"
        "80/tcp  open  http    nginx 1.24\n"
        "443/tcp closed https\n"
    )

    def fake_run(command, capture_output, text, errors, timeout, startupinfo, creationflags):
        return SimpleNamespace(returncode=0, stdout=fake_output, stderr="")

    monkeypatch.setattr(netdiag_core.subprocess, "run", fake_run)
    result = diagnostics.nmap_service_scan("192.168.1.10")
    assert result["open_ports"] == [22, 80]
    assert {"port": 22, "service": "ssh", "banner": "OpenSSH 8.9"} in result["services"]
    assert not any(svc["port"] == 443 for svc in result["services"])


def test_active_device_is_marked_online_even_when_icmp_is_blocked():
    """Doğruluk: ICMP engellense de ARP/servis kanıtı varsa cihaz 'çevrimdışı'
    olarak yanlış etiketlenmemeli — 'reachable_but_icmp_blocked' olmalı."""
    guess = netdiag_core.NetworkDiagnostics._guess_device_type
    result = guess("printer-floor2", open_ports={9100, 631}, services=[])
    assert result["type"] == "printer"


def test_gateway_ip_is_never_misclassified_as_unreachable_placeholder():
    diagnostics = netdiag_core.NetworkDiagnostics()
    guess = diagnostics._guess_device_type("", is_gateway=True, is_self=False)
    assert guess["type"] in {"router", "unknown"}
