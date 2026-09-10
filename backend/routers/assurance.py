"""Faz 3: zafiyet korelasyonu, kontrollü kimlik denetimi ve pasif keşif API'leri."""

from __future__ import annotations

import ipaddress
import json
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

try:
    from ..core.assurance import correlate_cves, parse_neighbor_table, target_is_exempt
except ImportError:
    from core.assurance import correlate_cves, parse_neighbor_table, target_is_exempt  # type: ignore[no-redef]


class CredentialAuditRequest(BaseModel):
    targets: list[str] = Field(default_factory=list, max_length=32)
    communities: list[str] = Field(default_factory=lambda: ["public", "private"], max_length=2)
    acknowledge_authorized: bool = False


class ExemptionRequest(BaseModel):
    target: str
    reason: str = "Hassas/kritik sistem"


def _save_run(ctx, kind: str, username: str, targets: int, findings: list[dict], started_at: float) -> int:
    finished_at = time.time()
    conn = ctx.db_conn()
    cursor = conn.execute(
        "INSERT INTO assurance_scan_runs "
        "(kind,started_at,finished_at,requested_by,status,target_count,finding_count,result_json) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (kind, started_at, finished_at, username, "completed", targets, len(findings), json.dumps(findings)),
    )
    conn.commit()
    run_id = int(cursor.lastrowid)
    conn.close()
    return run_id


def _exemptions(ctx) -> list[dict]:
    conn = ctx.db_conn()
    rows = conn.execute(
        "SELECT id,target,reason,created_by,created_at FROM scan_exemptions ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [
        {"id": row[0], "target": row[1], "reason": row[2], "created_by": row[3], "created_at": row[4]} for row in rows
    ]


def create_assurance_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/security/assurance/summary")
    def assurance_summary(user: dict = Depends(ctx.require_permission("security.manage"))):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,kind,started_at,finished_at,status,target_count,finding_count "
            "FROM assurance_scan_runs ORDER BY started_at DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return {
            "runs": [
                {
                    "id": row[0],
                    "kind": row[1],
                    "started_at": row[2],
                    "finished_at": row[3],
                    "status": row[4],
                    "target_count": row[5],
                    "finding_count": row[6],
                }
                for row in rows
            ],
            "cve_catalog": {"source": "NVD doğrulamalı yerel kural kataloğu", "rules": 3, "live_feed": False},
            "scope_note": "CVE sonucu yalnız ürün ve sürüm içeren servis banner kanıtıyla üretilir.",
        }

    @router.post("/api/security/cve-scan")
    def cve_scan(user: dict = Depends(ctx.require_permission("security.manage"))):
        started_at = time.time()
        devices = list(ctx._devices_cache.get("data") or [])
        findings, evidence_count = correlate_cves(devices)
        run_id = _save_run(ctx, "cve_correlation", user["username"], len(devices), findings, started_at)
        ctx._audit(user["username"], "cve_scan", f"run_id={run_id} assets={len(devices)} findings={len(findings)}")
        return {
            "run_id": run_id,
            "assets_evaluated": len(devices),
            "service_evidence_evaluated": evidence_count,
            "findings": findings,
            "catalog": "NVD doğrulamalı yerel başlangıç kataloğu",
            "scope_note": "Açık port tek başına CVE kanıtı sayılmaz; canlı NVD akışı bağlı değildir.",
        }

    @router.post("/api/security/credential-audit")
    def credential_audit(
        req: CredentialAuditRequest,
        user: dict = Depends(ctx.require_permission("security.manage")),
    ):
        if not req.acknowledge_authorized:
            raise HTTPException(status_code=400, detail="Yalnız yetkili cihazlarda denetim yapıldığını onaylayın.")
        communities = [item.casefold().strip() for item in req.communities]
        if not communities or any(item not in {"public", "private"} for item in communities):
            raise HTTPException(
                status_code=400, detail="Yalnız public/private varsayılan SNMP değerleri denetlenebilir."
            )
        devices = {str(item.get("ip")): item for item in (ctx._devices_cache.get("data") or []) if item.get("ip")}
        targets = req.targets or list(devices)
        if len(targets) > 32:
            raise HTTPException(status_code=400, detail="Tek denetimde en fazla 32 hedef kullanılabilir.")
        exemptions = [item["target"] for item in _exemptions(ctx)]
        normalized = []
        for target in targets:
            try:
                address = ipaddress.ip_address(target)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Geçersiz hedef: {target}") from exc
            if target not in devices or not ctx._is_allowed_inventory_ip(address):
                raise HTTPException(status_code=400, detail=f"Hedef keşfedilmiş yerel envanterde değil: {target}")
            if target_is_exempt(target, exemptions):
                continue
            normalized.append(target)
        started_at = time.time()
        findings = []
        for target in normalized:
            for community in communities:
                try:
                    response = ctx.diag._snmp_sysdescr(target, timeout=0.7, community=community)
                except Exception:
                    ctx.logger.exception("[ASSURANCE] SNMP varsayılan kimlik denetimi başarısız: %s", target)
                    response = None
                if response:
                    findings.append(
                        {
                            "asset": devices[target].get("hostname") or target,
                            "ip": target,
                            "severity": "critical",
                            "title": "Varsayılan SNMP community kabul edildi",
                            "credential": community,
                            "evidence": str(response)[:300],
                            "recommendation": "Benzersiz salt-okuma community veya tercihen SNMPv3 kullanın.",
                        }
                    )
        run_id = _save_run(ctx, "default_credential_audit", user["username"], len(normalized), findings, started_at)
        ctx._audit(
            user["username"], "credential_audit", f"run_id={run_id} targets={len(normalized)} findings={len(findings)}"
        )
        return {
            "run_id": run_id,
            "targets_tested": len(normalized),
            "findings": findings,
            "exempted": len(targets) - len(normalized),
        }

    @router.get("/api/discovery/exemptions")
    def get_exemptions(user: dict = Depends(ctx.get_current_user)):
        return {"exemptions": _exemptions(ctx)}

    @router.post("/api/discovery/exemptions")
    def add_exemption(req: ExemptionRequest, user: dict = Depends(ctx.require_permission("discovery.schedule.manage"))):
        target = req.target.strip()
        try:
            parsed = ipaddress.ip_network(target, strict=False) if "/" in target else ipaddress.ip_address(target)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Geçerli bir özel IP veya CIDR girin.") from exc
        if not parsed.is_private or parsed.version != 4:
            raise HTTPException(
                status_code=400, detail="Tarama muafiyeti yalnız özel IPv4 hedefleri için kullanılabilir."
            )
        canonical = str(parsed)
        conn = ctx.db_conn()
        conn.execute(
            "INSERT INTO scan_exemptions (target,reason,created_by,created_at) VALUES (?,?,?,?) "
            "ON CONFLICT(target) DO UPDATE SET reason=excluded.reason,created_by=excluded.created_by,created_at=excluded.created_at",
            (canonical, req.reason.strip()[:300], user["username"], time.time()),
        )
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "scan_exemption_add", f"target={canonical}")
        return {"ok": True, "target": canonical}

    @router.delete("/api/discovery/exemptions/{exemption_id}")
    def delete_exemption(exemption_id: int, user: dict = Depends(ctx.require_permission("discovery.schedule.manage"))):
        conn = ctx.db_conn()
        cursor = conn.execute("DELETE FROM scan_exemptions WHERE id=?", (exemption_id,))
        conn.commit()
        removed = cursor.rowcount > 0
        conn.close()
        if not removed:
            raise HTTPException(status_code=404, detail="Tarama muafiyeti bulunamadı.")
        ctx._audit(user["username"], "scan_exemption_delete", f"id={exemption_id}")
        return {"ok": True}

    @router.post("/api/discovery/passive-snapshot")
    def passive_snapshot(user: dict = Depends(ctx.require_permission("inventory.scan"))):
        command = ["arp", "-a"] if ctx.platform.system().lower() == "windows" else ["ip", "neigh"]
        result = ctx.diag.run_command(command)
        observations = parse_neighbor_table(result.stdout or "")
        exemptions = [item["target"] for item in _exemptions(ctx)]
        visible = [item for item in observations if not target_is_exempt(item["ip"], exemptions)]
        known_ips = {str(item.get("ip")) for item in (ctx._devices_cache.get("data") or [])}
        for item in visible:
            item["known"] = item["ip"] in known_ips
        started_at = time.time()
        new_items = [item for item in visible if not item["known"]]
        run_id = _save_run(ctx, "passive_neighbor_snapshot", user["username"], len(visible), new_items, started_at)
        ctx._audit(
            user["username"], "passive_discovery", f"run_id={run_id} observed={len(visible)} new={len(new_items)}"
        )
        return {
            "run_id": run_id,
            "observed": visible,
            "new_devices": new_items,
            "exempted": len(observations) - len(visible),
            "scope_note": "Yalnız işletim sistemi komşu/ARP önbelleği okundu; ICMP, port veya kimlik denemesi yapılmadı.",
        }

    return router
