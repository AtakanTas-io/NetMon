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
    monkeypatch.setattr(
        module, "winrm", SimpleNamespace(Session=lambda *a, **k: SimpleNamespace(run_ps=lambda script: response))
    )
    result = scanner.test_access("10.0.0.9")
    assert result["status"] == "Success"
    assert result["computer_name"] == "HOST01"


def test_winrm_inventory_payload_is_parsed(monkeypatch):
    scanner = module.WmiNetworkScanner("user", "secret")
    payload = b'{"computer_name":"PC1","hardware":{"ram_gb":16},"software":{"os_name":"Windows"}}'
    response = SimpleNamespace(status_code=0, std_out=payload, std_err=b"")
    monkeypatch.setattr(module, "WINRM_AVAILABLE", True)
    monkeypatch.setattr(
        module, "winrm", SimpleNamespace(Session=lambda *a, **k: SimpleNamespace(run_ps=lambda script: response))
    )
    result = scanner._scan_via_winrm("10.0.0.9", {5985})
    assert result["status"] == "Success"
    assert result["inventory_source"] == "WinRM/CIM"


def test_registry_software_is_deduplicated():
    class Registry:
        def EnumKey(self, **kwargs):
            return 0, ["one", "two"]

        def GetStringValue(self, sValueName, **kwargs):
            return (0, "App") if sValueName == "DisplayName" else (0, "1.0")

    result = module.WmiNetworkScanner()._get_software_from_registry(SimpleNamespace(StdRegProv=Registry()))
    assert result == [{"name": "App", "version": "1.0"}]


def test_local_wmi_inventory_success(monkeypatch):
    gib = 1024**3
    computer = SimpleNamespace(
        Name="PC1",
        UserName="DOMAIN\\user",
        TotalPhysicalMemory=str(16 * gib),
        PCSystemType=2,
        DomainRole=1,
    )
    os_info = SimpleNamespace(Caption="Windows 11", BuildNumber="26100", OSArchitecture="64-bit", ProductType=1)
    cpu = SimpleNamespace(Name=" Mock CPU ", NumberOfLogicalProcessors=8, NumberOfCores=4)
    board = SimpleNamespace(Manufacturer="ACME", Product="Board")
    enclosure = SimpleNamespace(ChassisTypes=[10])
    disk = SimpleNamespace(Size=str(100 * gib), FreeSpace=str(40 * gib), DeviceID="C:")
    gpu = SimpleNamespace(Name="Mock GPU")
    license_item = SimpleNamespace(OA3xOriginalProductKey=None)

    class Connection:
        def Win32_ComputerSystem(self):
            return [computer]

        def Win32_OperatingSystem(self):
            return [os_info]

        def Win32_Processor(self):
            return [cpu]

        def Win32_VideoController(self):
            return [gpu]

        def Win32_BaseBoard(self):
            return [board]

        def Win32_SystemEnclosure(self):
            return [enclosure]

        def Win32_LogicalDisk(self, **kwargs):
            return [disk]

        def SoftwareLicensingService(self):
            return [license_item]

    class SecurityConnection:
        def AntiVirusProduct(self):
            return [SimpleNamespace(displayName="Mock AV")]

    calls = []

    def wmi_factory(*args, **kwargs):
        calls.append(kwargs.get("namespace"))
        if kwargs.get("namespace") == r"root\SecurityCenter2":
            return SecurityConnection()
        if kwargs.get("namespace") == r"root\default":
            return SimpleNamespace(StdRegProv=SimpleNamespace(EnumKey=lambda **k: (0, [])))
        return Connection()

    scanner = module.WmiNetworkScanner()
    monkeypatch.setattr(module, "WMI_AVAILABLE", True)
    monkeypatch.setattr(module, "wmi", SimpleNamespace(WMI=wmi_factory))
    monkeypatch.setattr(module, "_ensure_com_initialized", lambda: None)
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})
    monkeypatch.setattr(module.gc, "collect", lambda: 0)
    result = scanner._scan_single_ip("127.0.0.1")
    assert result["status"] == "Success"
    assert result["hardware"]["ram_gb"] == 16
    assert result["security"]["antivirus"] == "Mock AV"


def test_wmi_access_failure_is_classified(monkeypatch):
    scanner = module.WmiNetworkScanner()
    monkeypatch.setattr(module, "WMI_AVAILABLE", True)
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})
    monkeypatch.setattr(module, "_ensure_com_initialized", lambda: None)
    monkeypatch.setattr(
        module, "wmi", SimpleNamespace(WMI=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("Access is denied")))
    )
    result = scanner.test_access("127.0.0.1")
    assert result["error_code"] == "access_denied"


def test_local_wmi_access_test_succeeds(monkeypatch):
    scanner = module.WmiNetworkScanner()
    connection = SimpleNamespace(Win32_OperatingSystem=lambda fields: [SimpleNamespace(Caption="Windows 11")])
    monkeypatch.setattr(module, "WMI_AVAILABLE", True)
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})
    monkeypatch.setattr(module, "_ensure_com_initialized", lambda: None)
    monkeypatch.setattr(module, "wmi", SimpleNamespace(WMI=lambda *a, **k: connection))
    result = scanner.test_access("127.0.0.1")
    assert result["status"] == "Success"
    assert result["os_caption"] == "Windows 11"


def test_management_port_probe_returns_only_open_ports(monkeypatch):
    scanner = module.WmiNetworkScanner()
    monkeypatch.setattr(module, "_local_ips", lambda: {"127.0.0.1"})

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def create_connection(target, timeout):
        if target[1] in {135, 5985}:
            return Connection()
        raise OSError("closed")

    monkeypatch.setattr(module.socket, "create_connection", create_connection)
    assert scanner._probe_management_ports("10.0.0.8") == {135, 5985}
