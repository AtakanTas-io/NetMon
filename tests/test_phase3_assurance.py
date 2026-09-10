from types import SimpleNamespace

import server
from test_server_security import _bootstrap_admin
from test_server_security import isolated_server as isolated_server

from backend.core.assurance import correlate_cves, evaluate_compliance, parse_neighbor_table, target_is_exempt


def test_cve_correlation_requires_product_and_version_evidence():
    devices = [
        {
            "ip": "10.0.0.10",
            "hostname": "web-old",
            "classification": {
                "open_ports": [22, 80],
                "services": [
                    {"port": 80, "service": "http", "banner": "Apache/2.4.49 (Unix)"},
                    {"port": 22, "service": "ssh", "banner": "OpenSSH_9.3p2"},
                ],
            },
        },
        {"ip": "10.0.0.11", "classification": {"open_ports": [80], "services": []}},
    ]

    findings, evidence_count = correlate_cves(devices)

    assert evidence_count == 2
    assert {item["cve_id"] for item in findings} == {"CVE-2021-41773", "CVE-2021-42013"}
    assert all(item["confidence"] == "high" for item in findings)
    assert not any(item["product"] == "OpenSSH" for item in findings)


def test_compliance_reports_failed_controls_without_returning_config():
    config = """
hostname EDGE-1
transport input ssh telnet
snmp-server community public ro
service password-encryption
"""

    result = evaluate_compliance(config, "network_device_level1")

    failed = {item["id"] for item in result["controls"] if item["status"] == "fail"}
    assert {"SSH_V2", "NO_TELNET", "REMOTE_LOGGING", "NTP_SERVER", "NO_DEFAULT_SNMP"} <= failed
    assert "config" not in result


def test_neighbor_parser_and_exemption_support_windows_and_cidr():
    parsed = parse_neighbor_table(
        "  10.0.0.7       aa-bb-cc-dd-ee-ff     dynamic\n10.0.0.8 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
    )

    assert parsed == [
        {"ip": "10.0.0.7", "mac": "AA:BB:CC:DD:EE:FF", "source": "neighbor_table"},
        {"ip": "10.0.0.8", "mac": "11:22:33:44:55:66", "source": "neighbor_table"},
    ]
    assert target_is_exempt("10.0.0.8", ["10.0.0.0/28"])
    assert not target_is_exempt("10.0.0.20", ["10.0.0.0/28"])


def test_phase3_api_runs_cve_credential_passive_and_exemptions(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = [
        {
            "ip": "10.0.0.10",
            "hostname": "edge",
            "classification": {"services": [{"port": 22, "service": "ssh", "banner": "OpenSSH_9.2p1"}]},
        }
    ]

    cve = client.post("/api/security/cve-scan", headers=headers)
    assert cve.status_code == 200
    assert [item["cve_id"] for item in cve.json()["findings"]] == ["CVE-2023-38408"]

    denied = client.post("/api/security/credential-audit", headers=headers, json={})
    assert denied.status_code == 400
    monkeypatch.setattr(
        server.diag,
        "_snmp_sysdescr",
        lambda ip, timeout, community: "Cisco IOS" if community == "public" else None,
    )
    credential = client.post(
        "/api/security/credential-audit",
        headers=headers,
        json={"targets": ["10.0.0.10"], "acknowledge_authorized": True},
    )
    assert credential.status_code == 200
    assert credential.json()["findings"][0]["credential"] == "public"

    added = client.post(
        "/api/discovery/exemptions",
        headers=headers,
        json={"target": "10.0.0.20", "reason": "kritik plc"},
    )
    assert added.status_code == 200
    monkeypatch.setattr(
        server.diag,
        "run_command",
        lambda command: SimpleNamespace(
            stdout=("10.0.0.20 aa-bb-cc-dd-ee-20 dynamic\n10.0.0.21 aa-bb-cc-dd-ee-21 dynamic\n")
        ),
    )
    passive = client.post("/api/discovery/passive-snapshot", headers=headers)
    assert passive.status_code == 200
    assert [item["ip"] for item in passive.json()["new_devices"]] == ["10.0.0.21"]
    assert passive.json()["exempted"] == 1

    summary = client.get("/api/security/assurance/summary", headers=headers).json()
    assert {run["kind"] for run in summary["runs"]} >= {
        "cve_correlation",
        "default_credential_audit",
        "passive_neighbor_snapshot",
    }


def test_ncm_compliance_uses_saved_config_and_persists_run(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    config = """
ip ssh version 2
service password-encryption
transport input ssh
logging host 10.0.0.5
ntp server 10.0.0.6
snmp-server community netmon-ro ro
"""
    backup = client.post(
        "/api/ncm/backup",
        headers=headers,
        json={"ip": "10.0.0.30", "manual_config": config, "version_label": "baseline-test"},
    )
    assert backup.status_code == 200

    response = client.post(
        "/api/ncm/compliance",
        headers=headers,
        json={"ip": "10.0.0.30", "config_id": backup.json()["id"], "baseline_id": "network_device_level1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["score"] == 100
    assert body["failed"] == 0
    assert body["version_label"] == "baseline-test"


def test_discovery_nmap_receives_exclusion_argument(monkeypatch):
    diagnostics = server.NetworkDiagnostics()
    seen = {}

    def run(command, timeout=None):
        seen["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(diagnostics, "run_command", run)
    diagnostics.nmap_discover(server.ipaddress.ip_network("10.0.0.0/24"), ("10.0.0.7", "10.0.0.16/28"))

    assert seen["command"] == ["nmap", "-sn", "--exclude", "10.0.0.7,10.0.0.16/28", "10.0.0.0/24"]
