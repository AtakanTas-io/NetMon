"""Faz 3 güvence taramaları için saf, kanıta dayalı analiz yardımcıları."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class CveRule:
    cve_id: str
    product: str
    severity: str
    cvss: float
    pattern: re.Pattern[str]
    affected: Callable[[tuple[int, ...], str], bool]
    summary: str
    reference: str


def _version_tuple(raw: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", raw)[:4])


def _openssh_before_93p2(version: tuple[int, ...], raw: str) -> bool:
    if version[:2] < (9, 3):
        return True
    if version[:2] > (9, 3):
        return False
    patch_match = re.search(r"9\.3p(\d+)", raw, re.IGNORECASE)
    return patch_match is None or int(patch_match.group(1)) < 2


CVE_RULES = (
    CveRule(
        cve_id="CVE-2021-41773",
        product="Apache HTTP Server",
        severity="critical",
        cvss=9.8,
        pattern=re.compile(r"(?:apache(?:/|\s+)|apache httpd\s+)(2\.4\.49)\b", re.IGNORECASE),
        affected=lambda version, raw: version[:3] == (2, 4, 49),
        summary="Apache HTTP Server 2.4.49 yol geçişi açığı",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    ),
    CveRule(
        cve_id="CVE-2021-42013",
        product="Apache HTTP Server",
        severity="critical",
        cvss=9.8,
        pattern=re.compile(r"(?:apache(?:/|\s+)|apache httpd\s+)(2\.4\.(?:49|50))\b", re.IGNORECASE),
        affected=lambda version, raw: version[:3] in {(2, 4, 49), (2, 4, 50)},
        summary="Apache HTTP Server 2.4.49/2.4.50 yol geçişi açığı",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
    ),
    CveRule(
        cve_id="CVE-2023-38408",
        product="OpenSSH",
        severity="critical",
        cvss=9.8,
        pattern=re.compile(r"openssh[_\s/-](\d+\.\d+(?:p\d+)?)", re.IGNORECASE),
        affected=_openssh_before_93p2,
        summary="Agent forwarding kullanılan OpenSSH sürümlerinde kod çalıştırma riski",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
    ),
)


def device_service_evidence(device: dict) -> list[dict]:
    """Cihaz kaydındaki servis ve banner kanıtlarını tekilleştir."""
    classification = device.get("classification") or {}
    services = classification.get("services") or device.get("services") or []
    banners = device.get("banners") or {}
    evidence: list[dict] = []
    seen: set[tuple[int | None, str]] = set()
    for service in services:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        text = " ".join(str(service.get(key) or "") for key in ("service", "product", "version", "banner")).strip()
        key = (int(str(port)) if str(port).isdigit() else None, text.casefold())
        if text and key not in seen:
            seen.add(key)
            evidence.append({"port": key[0], "text": text})
    for raw_port, banner in banners.items():
        text = str(banner or "").strip()
        key = (int(raw_port) if str(raw_port).isdigit() else None, text.casefold())
        if text and key not in seen:
            seen.add(key)
            evidence.append({"port": key[0], "text": text})
    return evidence


def correlate_cves(devices: list[dict]) -> tuple[list[dict], int]:
    """Kesin ürün+sürüm banner'larını küçük, yerel NVD kataloğuyla eşleştir."""
    findings: list[dict] = []
    evidence_count = 0
    emitted: set[tuple[str, str, int | None]] = set()
    for device in devices:
        asset = device.get("hostname") or device.get("friendly_name") or device.get("ip") or "Bilinmeyen cihaz"
        for evidence in device_service_evidence(device):
            evidence_count += 1
            for rule in CVE_RULES:
                match = rule.pattern.search(evidence["text"])
                if not match:
                    continue
                raw_version = match.group(1)
                if not rule.affected(_version_tuple(raw_version), raw_version):
                    continue
                key = (str(device.get("ip") or asset), rule.cve_id, evidence["port"])
                if key in emitted:
                    continue
                emitted.add(key)
                findings.append(
                    {
                        "cve_id": rule.cve_id,
                        "asset": asset,
                        "ip": device.get("ip"),
                        "port": evidence["port"],
                        "product": rule.product,
                        "version": raw_version,
                        "severity": rule.severity,
                        "cvss": rule.cvss,
                        "summary": rule.summary,
                        "evidence": evidence["text"][:500],
                        "confidence": "high",
                        "reference": rule.reference,
                    }
                )
    findings.sort(key=lambda item: (-float(item["cvss"]), str(item["asset"]), str(item["cve_id"])))
    return findings, evidence_count


COMPLIANCE_BASELINES = {
    "network_device_level1": {
        "name": "Ağ Cihazı Temel Güvenlik L1",
        "description": "Cisco-benzeri running-config için salt-okuma, genel güvenlik kontrolleri.",
        "rules": (
            ("SSH_V2", "SSH sürüm 2 etkin", "high", r"(?im)^\s*ip ssh version 2\s*$", True),
            ("NO_TELNET", "VTY hatlarında Telnet kapalı", "critical", r"(?im)^\s*transport input .*\btelnet\b", False),
            (
                "PASSWORD_ENCRYPTION",
                "Parola şifreleme etkin",
                "medium",
                r"(?im)^\s*service password-encryption\s*$",
                True,
            ),
            (
                "REMOTE_LOGGING",
                "Uzak syslog hedefi tanımlı",
                "medium",
                r"(?im)^\s*logging (?:host\s+)?(?:\d{1,3}\.){3}\d{1,3}\s*$",
                True,
            ),
            ("NTP_SERVER", "NTP sunucusu tanımlı", "medium", r"(?im)^\s*ntp server\s+\S+", True),
            (
                "NO_DEFAULT_SNMP",
                "Varsayılan SNMP community kullanılmıyor",
                "critical",
                r"(?im)^\s*snmp-server community\s+(?:public|private)\b",
                False,
            ),
            (
                "NO_PLAIN_PASSWORD",
                "Düz metin password komutu yok",
                "high",
                r"(?im)^\s*(?:enable\s+)?password\s+\S+",
                False,
            ),
        ),
    }
}


def evaluate_compliance(config_text: str, baseline_id: str) -> dict:
    baseline = COMPLIANCE_BASELINES[baseline_id]
    controls = []
    for raw_control in baseline["rules"]:
        control_id, title, severity, pattern = (str(raw_control[index]) for index in range(4))
        expected_present = bool(raw_control[4])
        matched = bool(re.search(pattern, config_text))
        passed = matched == expected_present
        controls.append(
            {
                "id": control_id,
                "title": title,
                "severity": severity,
                "status": "pass" if passed else "fail",
                "evidence": "Beklenen ayar bulundu."
                if passed and expected_present
                else "Yasaklanan ayar bulunmadı."
                if passed
                else "Temel çizgiden sapma bulundu.",
            }
        )
    passed_count = sum(1 for item in controls if item["status"] == "pass")
    return {
        "baseline_id": baseline_id,
        "baseline_name": baseline["name"],
        "score": round(100 * passed_count / len(controls)) if controls else 100,
        "passed": passed_count,
        "failed": len(controls) - passed_count,
        "controls": controls,
    }


def parse_neighbor_table(text: str) -> list[dict]:
    """Windows arp -a ve Linux ip neigh/arp çıktılarını trafik üretmeden ayrıştır."""
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        mac_match = re.search(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", line)
        if not ip_match or not mac_match:
            continue
        ip, mac = ip_match.group(0), mac_match.group(0).replace("-", ":").upper()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.version == 4 and not (address.is_multicast or address.is_unspecified) and mac != "00:00:00:00:00:00":
            found[ip] = mac
    return [{"ip": ip, "mac": mac, "source": "neighbor_table"} for ip, mac in sorted(found.items())]


def target_is_exempt(ip: str, targets: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for target in targets:
        try:
            if "/" in target and address in ipaddress.ip_network(target, strict=False):
                return True
            if address == ipaddress.ip_address(target):
                return True
        except ValueError:
            continue
    return False
