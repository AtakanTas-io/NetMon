"""Ağ analisti, korelasyon ve bilgi tabanı API uçları."""

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _device_status(device):
    return str(
        device.get("status")
        or device.get("connectivity_status")
        or ("online" if device.get("online") else "unknown")
    ).lower()


def _classification(device):
    value = device.get("classification")
    return value if isinstance(value, dict) else {}


def _exposure_for_device(device):
    ports = sorted({int(port) for port in (_classification(device).get("open_ports") or []) if str(port).isdigit()})
    findings = []
    for port in ports:
        if port in {21, 23, 445, 3389}:
            findings.append(
                {
                    "severity": "review",
                    "port": port,
                    "title": f"Hassas servis portu {port} erişilebilir",
                    "reason": "Bu port kurumsal ağlarda politika kapsamında ayrıca değerlendirilmelidir.",
                }
            )
        elif port in {80, 8080, 8000}:
            findings.append(
                {
                    "severity": "info",
                    "port": port,
                    "title": f"HTTP servisi {port} üzerinde görüldü",
                    "reason": "Şifrelenmemiş HTTP erişiminin gerekip gerekmediğini doğrulayın.",
                }
            )
    risk = "medium" if any(item["severity"] == "review" for item in findings) else "low"
    return {"risk": risk, "open_ports": ports, "findings": findings}


def _inventory_completeness(asset):
    fields = ["hostname", "ip_address", "mac_address", "vendor", "device_type", "os_name", "os_version"]
    present = sum(1 for field in fields if asset.get(field) not in (None, "", "unknown"))
    if asset.get("hardware"):
        present += 1
    if asset.get("software"):
        present += 1
    return round(present * 100 / (len(fields) + 2))


def _analyst_recommendations(device, exposure, completeness):
    recommendations = []
    if _device_status(device) in {"offline", "stale"}:
        recommendations.append("Cihazın son görülme zamanını ve fiziksel/ağ bağlantısını doğrula.")
    if not device.get("hostname"):
        recommendations.append("Hostname alınamadı; DNS/LLMNR/mDNS veya yetkili envanter kaynağını kontrol et.")
    if not device.get("mac"):
        recommendations.append("MAC bilgisi yok; switch/ARP/neighbor tablosu veya SNMP ile doğrulamayı değerlendir.")
    if completeness < 70:
        recommendations.append("Yetkili derin envanter çalıştırılarak donanım/yazılım kapsamı artırılabilir.")
    if exposure["risk"] == "medium":
        recommendations.append(
            "Hassas görünen servisleri kurum politikasına göre doğrula; "
            "gereksiz servisleri kapatma kararı yönetici tarafından verilmelidir."
        )
    confidence = _safe_float(_classification(device).get("confidence"))
    if confidence is not None and confidence < 0.70:
        recommendations.append(
            "Cihaz sınıfını doğrulamak için SNMP/LLDP/CDP/OS fingerprint gibi ek kanıt kaynakları kullanılabilir."
        )
    return recommendations


def _analyst_device(device):
    exposure = _exposure_for_device(device)
    completeness = _inventory_completeness(device)
    classification = _classification(device)
    confidence = _safe_float(classification.get("confidence")) or 0.0
    confidence_pct = round(confidence * 100 if confidence <= 1 else confidence)
    return {
        "ip": device.get("ip"),
        "mac": device.get("mac"),
        "hostname": device.get("hostname"),
        "vendor": device.get("vendor"),
        "status": _device_status(device),
        "device_type": device.get("type") or classification.get("raw_type") or "unknown",
        "confidence": confidence_pct,
        "classification_source": device.get("classification_source", "auto"),
        "evidence": classification.get("evidence") or [],
        "discovery_sources": device.get("discovery_sources") or [],
        "completeness": completeness,
        "exposure": exposure,
        "recommendations": _analyst_recommendations(device, exposure, completeness),
        "last_seen": device.get("last_seen") or device.get("last_discovered") or device.get("timestamp"),
        "latency_ms": _safe_float(device.get("latency")),
        "packet_loss": _safe_float(device.get("packet_loss")),
    }


def _analyst_correlation(device):
    classification = _classification(device)
    signals = [str(item) for item in (classification.get("evidence") or [])]
    for source in [str(item) for item in (device.get("discovery_sources") or [])]:
        if source not in signals:
            signals.append(f"Discovery: {source}")
    inventory = device.get("unified_inventory") or {}
    if inventory.get("verified"):
        signals.append(f"Doğrulanmış envanter: {inventory.get('inventory_source', 'yetkili kaynak')}")
    if device.get("vendor"):
        signals.append(f"Vendor: {device.get('vendor')}")
    if device.get("hostname"):
        signals.append("Hostname mevcut")
    ports = sorted({int(item) for item in (classification.get("open_ports") or []) if str(item).isdigit()})
    if ports:
        signals.append(f"Gözlenen portlar: {', '.join(map(str, ports[:20]))}")
    score = min(100, 35 + len(signals) * 8)
    if device.get("mac"):
        score += 8
    if device.get("hostname"):
        score += 5
    if inventory.get("verified"):
        score += 10
    return {"score": min(100, score), "signals": signals[:20], "method": "multi-source correlation"}


def _review_priority(analysis):
    score = 0
    reasons = []
    if analysis["status"] in {"offline", "stale"}:
        score += 15
        reasons.append("Cihaz şu an aktif doğrulanmadı")
    if analysis["confidence"] < 70:
        score += 20
        reasons.append("Cihaz kimliği/sınıfı düşük güvenli")
    if analysis["completeness"] < 70:
        score += 15
        reasons.append("Envanter eksik")
    if analysis["exposure"]["risk"] == "medium":
        score += 25
        reasons.append("İnceleme gerektiren servis bulundu")
    if not analysis.get("hostname"):
        score += 5
        reasons.append("Hostname bilinmiyor")
    score = min(100, score)
    return {"score": score, "level": "high" if score >= 50 else "medium" if score >= 25 else "low", "reasons": reasons}


def create_analyst_router(ctx) -> APIRouter:
    router = APIRouter()

    def devices():
        return ctx._devices_cache.get("data") or []

    def take_snapshot():
        analyzed = [_analyst_device(device) for device in devices()]
        total = len(analyzed)
        online = sum(item["status"] == "online" for item in analyzed)
        offline = sum(item["status"] in {"offline", "stale"} for item in analyzed)
        unknown = sum(item["device_type"] in {None, "", "unknown"} for item in analyzed)
        completeness = round(sum(item["completeness"] for item in analyzed) / total, 1) if total else 0
        review = sum(item["exposure"]["risk"] == "medium" for item in analyzed)
        health = 100 - min(30, unknown * 2) - min(20, review * 3) - min(15, offline * 15 / total) if total else 0
        conn = ctx.db_conn()
        conn.execute(
            "INSERT INTO analyst_snapshots(created_at,total,online,offline,unknown,health,completeness,security_review,payload) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                ctx.time.time(), total, online, offline, unknown, max(0, round(health, 1)),
                completeness, review, json.dumps({"by_type": {}}),
            ),
        )
        conn.commit()
        conn.close()

    @router.get("/api/analyst/correlation")
    def analyst_correlation(user: dict = Depends(ctx.get_current_user)):
        result = []
        for device in devices():
            analysis = _analyst_device(device)
            analysis["correlation"] = _analyst_correlation(device)
            analysis["review_priority"] = _review_priority(analysis)
            result.append(analysis)
        result.sort(key=lambda item: item["review_priority"]["score"], reverse=True)
        return {"devices": result}

    @router.get("/api/analyst/trends")
    def analyst_trends(limit: int = 30, user: dict = Depends(ctx.get_current_user)):
        limit = max(1, min(limit, 200))
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT created_at,total,online,offline,unknown,health,completeness,security_review "
            "FROM analyst_snapshots ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        keys = ["created_at", "total", "online", "offline", "unknown", "health", "completeness", "security_review"]
        return {"points": [dict(zip(keys, row)) for row in reversed(rows)]}

    @router.post("/api/analyst/snapshot")
    def analyst_snapshot(user: dict = Depends(ctx.get_current_user)):
        if user.get("role") != "admin":
            raise ctx._AuthError(403, "Analiz snapshot için yönetici yetkisi gerekiyor.")
        take_snapshot()
        ctx._audit(user["username"], "analyst_snapshot", "Network intelligence snapshot")
        return {"ok": True}

    @router.get("/api/analyst/topology-evidence")
    def analyst_topology_evidence(user: dict = Depends(ctx.get_current_user)):
        edges = []
        for device in devices():
            name = device.get("hostname") or device.get("friendly_name") or device.get("ip")
            for key in ("lldp_neighbors", "cdp_neighbors", "neighbors"):
                values = device.get(key) or (device.get("network_intelligence") or {}).get(key) or []
                if isinstance(values, dict):
                    values = [values]
                for neighbor in values:
                    if not isinstance(neighbor, dict):
                        continue
                    peer = neighbor.get("ip") or neighbor.get("management_address") or neighbor.get("hostname") or neighbor.get("device_id")
                    if peer:
                        edges.append(
                            {
                                "source": name, "target": str(peer),
                                "port": neighbor.get("local_port") or neighbor.get("port"),
                                "protocol": key.upper().replace("_NEIGHBORS", ""),
                            }
                        )
        return {"edges": edges, "evidence_only": True}

    @router.get("/api/analyst/baseline")
    def analyst_baseline(user: dict = Depends(ctx.get_current_user)):
        result = []
        for device in devices():
            analysis = _analyst_device(device)
            checks = [
                ("Kimlik", bool(device.get("ip") and (device.get("mac") or device.get("hostname")))),
                ("Hostname", bool(device.get("hostname"))),
                ("Envanter", analysis["completeness"] >= 70),
                ("Güvenlik görünürlüğü", not analysis["exposure"]["findings"]),
                ("Erişilebilirlik", analysis["status"] == "online"),
            ]
            passed = sum(item[1] for item in checks)
            result.append(
                {
                    "ip": analysis["ip"], "hostname": analysis["hostname"],
                    "score": round(passed * 100 / len(checks)),
                    "checks": [{"name": item[0], "ok": item[1]} for item in checks],
                }
            )
        return {"devices": result}

    @router.get("/api/analyst/report")
    def analyst_report(user: dict = Depends(ctx.get_current_user)):
        analyzed = [_analyst_device(device) for device in devices()]
        lines = [
            "NETMON NETWORK ANALYST RAPORU",
            f"Oluşturulma: {ctx.time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Toplam cihaz: {len(analyzed)}",
            "",
        ]
        for item in analyzed:
            lines.append(
                f"- {item['hostname'] or item['ip']} | {item['device_type']} | {item['status']} | "
                f"Güven %{item['confidence']} | Envanter %{item['completeness']}"
            )
            lines.extend(f"  * {recommendation}" for recommendation in item["recommendations"][:3])
        return PlainTextResponse(
            "\n".join(lines),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=netmon-analyst-report.txt"},
        )

    @router.get("/api/analyst/summary")
    def analyst_summary(user: dict = Depends(ctx.get_current_user)):
        analyzed = [_analyst_device(device) for device in devices()]
        online = [item for item in analyzed if item["status"] == "online"]
        offline = [item for item in analyzed if item["status"] in {"offline", "stale"}]
        unknown = [item for item in analyzed if item["device_type"] in {None, "", "unknown"}]
        review = [item for item in analyzed if item["exposure"]["risk"] == "medium"]
        latencies = [item["latency_ms"] for item in analyzed if item["latency_ms"] is not None]
        losses = [item["packet_loss"] for item in analyzed if item["packet_loss"] is not None and item["status"] == "online"]
        completeness = round(sum(item["completeness"] for item in analyzed) / len(analyzed)) if analyzed else 0
        health = 100 - min(20, len(unknown) * 2) - min(25, len(review) * 3)
        if losses and sum(losses) / len(losses) > 2:
            health -= 10
        if offline and analyzed:
            health -= min(15, round(len(offline) * 15 / len(analyzed)))
        by_type = {}
        for item in analyzed:
            by_type[item["device_type"]] = by_type.get(item["device_type"], 0) + 1
        health = max(0, health)
        return {
            "health": {"score": health, "label": "Sağlıklı" if health >= 85 else "İzlenmeli" if health >= 65 else "Sorunlu"},
            "inventory": {
                "total": len(analyzed), "online": len(online), "offline": len(offline),
                "unknown_type": len(unknown), "completeness": completeness,
            },
            "security": {
                "review_items": len(review),
                "devices_with_exposure": len([item for item in analyzed if item["exposure"]["findings"]]),
            },
            "performance": {
                "average_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
                "average_packet_loss": round(sum(losses) / len(losses), 2) if losses else None,
            },
            "by_type": by_type,
            "top_recommendations": list(dict.fromkeys(value for item in analyzed for value in item["recommendations"]))[:10],
            "generated_at": ctx.time.time(),
        }

    @router.get("/api/analyst/devices")
    def analyst_devices(user: dict = Depends(ctx.get_current_user)):
        return {"devices": [_analyst_device(device) for device in devices()]}

    @router.get("/api/analyst/device/{ip}")
    def analyst_device(ip: str, user: dict = Depends(ctx.get_current_user)):
        for device in devices():
            if device.get("ip") == ip:
                return {"analysis": _analyst_device(device)}
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı")

    @router.get("/api/analyst/anomalies")
    def analyst_anomalies(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        try:
            rows = conn.execute(
                "SELECT asset_id,event_type,field_name,old_value,new_value,source,created_at "
                "FROM inventory_history ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
        finally:
            conn.close()
        return {
            "anomalies": [
                {
                    "asset_id": row[0], "event": row[1], "field": row[2], "old": row[3],
                    "new": row[4], "source": row[5], "created_at": row[6], "severity": "info",
                }
                for row in rows
            ]
        }

    @router.get("/api/analyst/exposure")
    def analyst_exposure(user: dict = Depends(ctx.get_current_user)):
        result = []
        for device in devices():
            analysis = _analyst_device(device)
            if analysis["exposure"]["findings"]:
                result.append(analysis)
        return {"devices": result}

    @router.get("/api/knowledge/network")
    def knowledge_network(user: dict = Depends(ctx.get_current_user)):
        return {"topics": [
            {"id": "discovery", "title": "Ağ keşfi", "text": "NetMon tek bir yönteme güvenmez; ARP/Neighbor, ICMP, DNS, Nmap, SNMP ve uygun olduğunda LLDP/CDP gibi kaynakları birleştirir."},
            {"id": "identity", "title": "Cihaz kimliği", "text": "IP değişebilir. Bu nedenle MAC, hostname, vendor ve diğer fingerprint kanıtları birlikte değerlendirilir."},
            {"id": "status", "title": "Durumlar", "text": "Çevrimiçi ağda doğrulanmış cihazı, görüldü keşfedilmiş ama ICMP ile doğrulanmamış cihazı, çevrimdışı önceki envanter kaydını, stale ise uzun süredir görülmeyen kaydı ifade eder."},
            {"id": "snmp", "title": "SNMP", "text": "Yetkili salt-okuma SNMP; sistem kimliği, interface ve bazı ağ cihazı metrikleri sağlayabilir. Erişim yoksa NetMon tahmin yapmaz."},
            {"id": "lldp", "title": "LLDP/CDP", "text": "Komşuluk protokolleri cihazlar arasındaki bağlantıyı kanıtlamaya yardımcı olur. Kanıt yoksa topolojide fiziksel bağlantı uydurulmaz."},
            {"id": "inventory", "title": "Agentless ve yetkili envanter", "text": "Ağdan görülebilen bilgiler ile yetkili WMI/WinRM/SSH/SNMP/API bilgilerinin kapsamı farklıdır. Eksik alanlar UNKNOWN olarak tutulur."},
            {"id": "security", "title": "Güvenlik görünürlüğü", "text": "Açık port veya servis görmek tek başına güvenlik açığı bulunduğunu kanıtlamaz. NetMon bunları inceleme gerektiren gözlemler olarak sunar."},
            {"id": "anomaly", "title": "Anomali", "text": "Yeni cihaz, IP değişikliği, yeni port veya envanter değişikliği gibi olaylar analiste inceleme sinyali verir; otomatik saldırı hükmü verilmez."},
        ]}

    return router
