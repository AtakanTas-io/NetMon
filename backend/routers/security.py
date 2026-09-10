"""Güvenlik görünürlüğü, bulgular ve kontrollü simülasyon API uçları."""

import json
import re
import time
from typing import Literal

from fastapi import APIRouter, Depends

RISKY_PORTS = {21: "FTP düz metin", 23: "Telnet düz metin", 445: "SMB", 3389: "RDP", 5900: "VNC"}


def _device_ports(device: dict) -> set[int]:
    ports = (device.get("classification") or {}).get("open_ports") or device.get("open_ports") or []
    if isinstance(ports, str):
        try:
            ports = json.loads(ports)
        except (TypeError, ValueError):
            ports = re.findall(r"\d+", ports)
    return {int(port) for port in ports if str(port).isdigit()}


def _posture_findings(devices: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for device in devices:
        exposed = sorted(_device_ports(device) & set(RISKY_PORTS))
        if exposed:
            findings.append(
                {
                    "severity": "high" if any(port in (23, 445, 3389) for port in exposed) else "medium",
                    "asset": device.get("hostname") or device.get("ip") or "Bilinmeyen cihaz",
                    "ip": device.get("ip"),
                    "title": "İncelenmesi gereken yönetim/legacy servisi",
                    "evidence": ", ".join(f"TCP/{port} {RISKY_PORTS[port]}" for port in exposed),
                    "recommendation": (
                        "Servisin iş gereksinimini doğrulayın; kaynak IP kısıtı, VPN veya güvenli alternatif uygulayın."
                    ),
                }
            )
        if (device.get("type") or "unknown") == "unknown":
            findings.append(
                {
                    "severity": "medium",
                    "asset": device.get("hostname") or device.get("ip") or "Bilinmeyen",
                    "ip": device.get("ip"),
                    "title": "Kimliği doğrulanmamış cihaz",
                    "evidence": "Cihaz tipi ve sahibi doğrulanmadı.",
                    "recommendation": "Envanter yetki testi yapın ve varlık sahibini/lokasyonunu kaydedin.",
                }
            )
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: rank.get(str(item.get("severity") or ""), 9))
    return findings


def _downsample(rows: list[tuple], max_points: int = 240) -> list[tuple]:
    if len(rows) <= max_points:
        return rows
    step = (len(rows) + max_points - 1) // max_points
    return [rows[min(index + step - 1, len(rows) - 1)] for index in range(0, len(rows), step)]


def _network_quality_points(rows: list[tuple]) -> list[dict]:
    points = []
    for ts, raw_data in _downsample(rows):
        try:
            payload = json.loads(raw_data)
        except (TypeError, ValueError):
            continue
        internet = payload.get("internet_test") or {}
        gateway = payload.get("gateway_test") or {}
        points.append(
            {
                "ts": ts,
                "status": payload.get("status") or "unknown",
                "internet_latency_ms": internet.get("average"),
                "gateway_latency_ms": gateway.get("average"),
                "packet_loss_pct": internet.get("packet_loss"),
            }
        )
    return points


def _network_quality_stats(points: list[dict]) -> dict:
    latencies = [float(point["internet_latency_ms"]) for point in points if point["internet_latency_ms"] is not None]
    losses = [float(point["packet_loss_pct"]) for point in points if point["packet_loss_pct"] is not None]
    jitter_samples = [abs(right - left) for left, right in zip(latencies, latencies[1:])]
    return {
        "samples": len(points),
        "average_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "jitter_ms": round(sum(jitter_samples) / len(jitter_samples), 1) if jitter_samples else None,
        "average_packet_loss_pct": round(sum(losses) / len(losses), 1) if losses else None,
        "latest": points[-1] if points else None,
    }


def _security_score(
    devices: list[dict], findings: list[dict], certificates: list[dict], firewall: dict, dhcp: dict
) -> dict:
    deductions = []
    total_deduction = 0

    def deduct(code: str, label: str, points: int, count: int = 1):
        nonlocal total_deduction
        if points > 0:
            deductions.append({"code": code, "label": label, "points": points, "count": count})
            total_deduction += points

    risky_assets = sum(1 for device in devices if _device_ports(device) & set(RISKY_PORTS))
    unknown_assets = sum(1 for device in devices if (device.get("type") or "unknown") == "unknown")
    expired = sum(1 for cert in certificates if cert["days_left"] is not None and cert["days_left"] < 0)
    expiring = sum(1 for cert in certificates if cert["days_left"] is not None and 0 <= cert["days_left"] <= 30)
    deduct("RISKY_SERVICES", "Riskli/legacy servis bulunan cihaz", min(30, risky_assets * 8), risky_assets)
    deduct("UNKNOWN_ASSETS", "Kimliği doğrulanmamış cihaz", min(10, unknown_assets * 2), unknown_assets)
    deduct("EXPIRED_CERTIFICATES", "Süresi dolmuş sertifika", min(30, expired * 15), expired)
    deduct("EXPIRING_CERTIFICATES", "30 gün içinde dolacak sertifika", min(15, expiring * 5), expiring)
    firewall_state = str(firewall.get("state") or "unknown")
    deduct(
        "FIREWALL_STATE",
        "Yerel güvenlik duvarı kapalı" if firewall_state == "disabled" else "Güvenlik duvarı durumu doğrulanamadı",
        20 if firewall_state == "disabled" else 5 if firewall_state not in {"enabled"} else 0,
    )
    rogue_count = int(dhcp.get("rogue_detected_count") or 0)
    deduct("ROGUE_DHCP", "Yetkisiz DHCP teklifi", 25 if rogue_count else 0, rogue_count)
    score = max(0, 100 - total_deduction)
    return {
        "score": score,
        "label": "İyi" if score >= 85 else "İzlenmeli" if score >= 65 else "Kritik",
        "deductions": deductions,
        "method": "Kanıta dayalı ağırlıklı kesinti modeli",
    }


def create_security_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/alerts")
    def get_alerts(limit: int = 20, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT ts, level, message FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [{"ts": row[0], "level": row[1], "message": row[2]} for row in rows]

    @router.get("/api/firewall/status")
    def get_firewall_status(user: dict = Depends(ctx.get_current_user)):
        return ctx._cached_firewall_status()

    @router.get("/api/ssl-certs")
    def get_ssl_certs(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT ip, hostname, issuer, valid_from, valid_to, days_left, last_checked "
            "FROM ssl_certificates ORDER BY days_left ASC"
        ).fetchall()
        conn.close()
        return {
            "certs": [
                {
                    "ip": row[0],
                    "hostname": row[1],
                    "issuer": row[2],
                    "valid_from": row[3],
                    "valid_to": row[4],
                    "days_left": row[5],
                    "last_checked": row[6],
                }
                for row in rows
            ]
        }

    @router.get("/api/security")
    def get_security(user: dict = Depends(ctx.get_current_user)):
        try:
            return ctx.diag.get_security_analysis()
        except Exception:
            ctx.logger.exception("[SECURITY] Güvenlik analizi alınamadı")
            return {
                "firewall_desc": "",
                "webfilter_desc": "",
                "rules": [],
                "error": "Güvenlik analizi şu anda alınamıyor.",
            }

    @router.get("/api/security/posture")
    def get_security_posture(user: dict = Depends(ctx.require_permission("security.manage"))):
        devices = ctx._devices_cache.get("data", [])
        findings = _posture_findings(devices)
        return {
            "generated_at": time.time(),
            "assets_evaluated": len(devices),
            "findings": findings[:200],
            "counts": {
                level: sum(1 for finding in findings if finding["severity"] == level)
                for level in ("critical", "high", "medium", "low")
            },
            "scope_note": (
                "Bulgular yalnızca keşfedilmiş gerçek port ve envanter kanıtlarından üretilir; "
                "zafiyet sömürüsü veya izinsiz saldırı testi yapılmaz."
            ),
        }

    @router.get("/api/visibility/summary")
    def get_visibility_summary(
        range: Literal["1h", "24h", "7d"] = "24h",
        user: dict = Depends(ctx.get_current_user),
    ):
        seconds = {"1h": 3600, "24h": 86400, "7d": 7 * 86400}[range]
        conn = ctx.db_conn()
        snapshot_rows = conn.execute(
            "SELECT ts,data FROM snapshots WHERE ts>=? ORDER BY ts",
            (time.time() - seconds,),
        ).fetchall()
        certificate_rows = conn.execute(
            "SELECT ip,hostname,issuer,valid_to,days_left,last_checked FROM ssl_certificates ORDER BY days_left ASC"
        ).fetchall()
        conn.close()
        points = _network_quality_points(snapshot_rows)
        certificates = [
            {
                "ip": row[0],
                "hostname": row[1],
                "issuer": row[2],
                "valid_to": row[3],
                "days_left": row[4],
                "last_checked": row[5],
            }
            for row in certificate_rows
        ]
        expiring = [cert for cert in certificates if cert["days_left"] is not None and cert["days_left"] <= 30]
        devices = ctx._devices_cache.get("data", [])
        findings = _posture_findings(devices)
        dhcp_state = ctx.get_dhcp_monitor_status()
        dhcp = {
            "running": bool(dhcp_state.get("running")),
            "thread_alive": bool(dhcp_state.get("thread_alive")),
            "authorized_server_count": len(ctx._authorized_dhcp_servers()),
            "last_event_ts": dhcp_state.get("last_event_ts"),
            "last_source_ip": dhcp_state.get("last_source_ip"),
            "last_rogue_ts": dhcp_state.get("last_rogue_ts"),
            "last_rogue_source": dhcp_state.get("last_rogue_source"),
            "rogue_detected_count": int(dhcp_state.get("rogue_detected_count") or 0),
            "error": "DHCP dinleyicisi başlatılamadı." if dhcp_state.get("error") else None,
            "pool_utilization_pct": None,
            "pool_note": "DHCP lease kaynağı bağlı değil; IPAM doluluğu gözlenen adres kullanımını gösterir.",
        }
        firewall = ctx._cached_firewall_status()
        return {
            "generated_at": time.time(),
            "range": range,
            "network_quality": {
                "points": points,
                "stats": _network_quality_stats(points),
                "source": "Periyodik ICMP tanı snapshot'ları",
            },
            "security": {
                **_security_score(devices, findings, certificates, firewall, dhcp),
                "assets_evaluated": len(devices),
                "findings_count": len(findings),
            },
            "certificates": {
                "total": len(certificates),
                "expired": sum(1 for cert in certificates if cert["days_left"] is not None and cert["days_left"] < 0),
                "expiring_30d": sum(
                    1 for cert in certificates if cert["days_left"] is not None and 0 <= cert["days_left"] <= 30
                ),
                "attention": expiring[:20],
            },
            "dhcp": dhcp,
            "scope_note": (
                "Gecikme ve kayıp NetMon sunucusunun tanı hedeflerine yaptığı ölçümlerden; güvenlik skoru ise "
                "keşfedilmiş port, sertifika, firewall ve DHCP kanıtlarından hesaplanır."
            ),
        }

    router.add_api_route("/api/simulate/scenarios", ctx.list_scenarios, methods=["GET"])
    router.add_api_route("/api/simulate/start", ctx.start_simulation, methods=["POST"])
    router.add_api_route("/api/simulate/stop", ctx.stop_simulation, methods=["POST"])
    router.add_api_route("/api/simulate/state", ctx.get_simulation_state, methods=["GET"])
    router.add_api_route("/api/admin/xoc/metrics", ctx.get_admin_xoc_metrics, methods=["GET"])
    router.add_api_route("/api/admin/xoc/blacklist/add", ctx.add_to_blacklist, methods=["POST"])
    router.add_api_route("/api/admin/xoc/blacklist/remove", ctx.remove_from_blacklist, methods=["POST"])
    router.add_api_route("/api/admin/xoc/simulate-dos", ctx.start_dos_simulation, methods=["POST"])
    return router
