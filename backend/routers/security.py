"""Güvenlik görünürlüğü, bulgular ve kontrollü simülasyon API uçları."""

import json
import re
import time

from fastapi import APIRouter, Depends


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
        except Exception as exc:
            return {"firewall_desc": "", "webfilter_desc": "", "rules": [], "error": str(exc)}

    @router.get("/api/security/posture")
    def get_security_posture(user: dict = Depends(ctx.require_permission("security.manage"))):
        risky_ports = {21: "FTP düz metin", 23: "Telnet düz metin", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        findings = []
        devices = ctx._devices_cache.get("data", [])
        for device in devices:
            ports = (device.get("classification") or {}).get("open_ports") or device.get("open_ports") or []
            if isinstance(ports, str):
                try:
                    ports = json.loads(ports)
                except (TypeError, ValueError):
                    ports = [int(value) for value in re.findall(r"\d+", ports)]
            exposed = sorted({int(port) for port in ports if str(port).isdigit()} & set(risky_ports))
            if exposed:
                findings.append(
                    {
                        "severity": "high" if any(port in (23, 445, 3389) for port in exposed) else "medium",
                        "asset": device.get("hostname") or device.get("ip") or "Bilinmeyen cihaz",
                        "ip": device.get("ip"),
                        "title": "İncelenmesi gereken yönetim/legacy servisi",
                        "evidence": ", ".join(f"TCP/{port} {risky_ports[port]}" for port in exposed),
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
        findings.sort(key=lambda item: rank.get(item["severity"], 9))
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

    router.add_api_route("/api/simulate/scenarios", ctx.list_scenarios, methods=["GET"])
    router.add_api_route("/api/simulate/start", ctx.start_simulation, methods=["POST"])
    router.add_api_route("/api/simulate/stop", ctx.stop_simulation, methods=["POST"])
    router.add_api_route("/api/simulate/state", ctx.get_simulation_state, methods=["GET"])
    router.add_api_route("/api/admin/xoc/metrics", ctx.get_admin_xoc_metrics, methods=["GET"])
    router.add_api_route("/api/admin/xoc/blacklist/add", ctx.add_to_blacklist, methods=["POST"])
    router.add_api_route("/api/admin/xoc/blacklist/remove", ctx.remove_from_blacklist, methods=["POST"])
    router.add_api_route("/api/admin/xoc/simulate-dos", ctx.start_dos_simulation, methods=["POST"])
    return router
