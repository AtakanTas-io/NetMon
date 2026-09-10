"""Ağ cihazı yapılandırma yedekleme ve sürüm farkı API uçları."""

import difflib
import hashlib
import ipaddress
import json
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

try:
    from ..core.assurance import COMPLIANCE_BASELINES, evaluate_compliance
except ImportError:
    from core.assurance import COMPLIANCE_BASELINES, evaluate_compliance  # type: ignore[no-redef]


class NcmBackupRequest(BaseModel):
    ip: str
    version_label: str | None = None
    manual_config: str | None = None


class NcmComplianceRequest(BaseModel):
    ip: str
    config_id: int | None = None
    baseline_id: str = "network_device_level1"


class ChangeRequestInput(BaseModel):
    config_id: int
    title: str
    reason: str = ""
    risk: str = "medium"


class ChangeDecisionInput(BaseModel):
    decision: str
    note: str = ""


def create_ncm_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/ncm/status")
    def get_ncm_status(user: dict = Depends(ctx.get_current_user)):
        return {
            **ctx._ncm_auto_state,
            "enabled": ctx.NCM_AUTO_BACKUP_ENABLED,
            "interval_seconds": ctx.NCM_BACKUP_INTERVAL,
            "ssh_account_configured": bool(ctx.SSH_USERNAME and ctx.SSH_PASSWORD),
            "can_manage": ctx._has_permission(user, "ncm.manage"),
            "required_permission": "ncm.manage",
            "least_privilege_note": (
                "Hesap yalnızca running-config/show configuration okumalı; "
                "yapılandırma değiştirme yetkisi verilmemelidir."
            ),
        }

    @router.post("/api/ncm/backup")
    def post_ncm_backup(
        req: NcmBackupRequest,
        user: dict = Depends(ctx.require_permission("ncm.manage")),
    ):
        ip = req.ip.strip()
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Geçerli bir IP adresi gereklidir.") from exc
        if not ctx._is_allowed_inventory_ip(parsed_ip):
            raise HTTPException(status_code=400, detail="NCM yalnızca yerel/özel ağ cihazlarında kullanılabilir.")

        device = next((item for item in ctx._devices_cache.get("data", []) if item.get("ip") == ip), None)
        hostname = (device or {}).get("hostname") or (device or {}).get("friendly_name") or ip
        device_type = (device or {}).get("type") or "unknown"
        if req.manual_config:
            config_text = req.manual_config
            config_source = "manual"
            source_command = None
        else:
            try:
                config_text, source_command = ctx._fetch_running_config_ssh(ip)
                config_source = "ssh"
            except Exception as exc:
                ctx._audit(
                    user["username"],
                    "ncm_backup",
                    f"ip={ip} fetch_failed={str(exc)[:180]}",
                    success=False,
                )
                raise HTTPException(status_code=503, detail=f"Gerçek cihaz konfigürasyonu alınamadı: {exc}") from exc

        if len(config_text.encode("utf-8")) > 2_000_000:
            raise HTTPException(status_code=413, detail="Konfigürasyon 2 MB sınırını aşıyor.")
        config_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
        label = req.version_label or f"Backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        created_at = time.time()
        conn = ctx.db_conn()
        conn.execute(
            "INSERT INTO device_configs "
            "(ip, hostname, device_type, config_text, config_hash, version_label, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ip, hostname, device_type, config_text, config_hash, label, created_at),
        )
        conn.commit()
        config_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        ctx._audit(
            user["username"],
            "ncm_backup",
            f"ip={ip} source={config_source} config_id={config_id} hash={config_hash[:8]}",
        )
        return {
            "ok": True,
            "id": config_id,
            "ip": ip,
            "hostname": hostname,
            "version_label": label,
            "hash": config_hash,
            "created_at": created_at,
            "source": config_source,
            "source_command": source_command,
        }

    @router.get("/api/ncm/configs")
    def get_ncm_configs(ip: str | None = None, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        select_sql = (
            "SELECT id, ip, hostname, device_type, config_hash, version_label, created_at, "
            "LENGTH(config_text) as size_bytes FROM device_configs"
        )
        if ip:
            rows = conn.execute(select_sql + " WHERE ip=? ORDER BY created_at DESC", (ip,)).fetchall()
        else:
            rows = conn.execute(select_sql + " ORDER BY created_at DESC LIMIT 100").fetchall()
        conn.close()
        return {
            "configs": [
                {
                    "id": row[0],
                    "ip": row[1],
                    "hostname": row[2],
                    "device_type": row[3],
                    "hash": row[4],
                    "version_label": row[5],
                    "created_at": row[6],
                    "created_at_fmt": datetime.fromtimestamp(row[6]).strftime("%Y-%m-%d %H:%M:%S"),
                    "size_bytes": row[7],
                }
                for row in rows
            ]
        }

    @router.get("/api/ncm/baselines")
    def get_ncm_baselines(user: dict = Depends(ctx.get_current_user)):
        return {
            "baselines": [
                {
                    "id": baseline_id,
                    "name": baseline["name"],
                    "description": baseline["description"],
                    "control_count": len(baseline["rules"]),
                }
                for baseline_id, baseline in COMPLIANCE_BASELINES.items()
            ]
        }

    @router.post("/api/ncm/compliance")
    def run_ncm_compliance(
        req: NcmComplianceRequest,
        user: dict = Depends(ctx.require_permission("ncm.manage")),
    ):
        ip = req.ip.strip()
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Geçerli bir IP adresi gereklidir.") from exc
        if not ctx._is_allowed_inventory_ip(parsed_ip):
            raise HTTPException(status_code=400, detail="Uyumluluk yalnız yerel/özel ağ cihazlarında çalıştırılabilir.")
        if req.baseline_id not in COMPLIANCE_BASELINES:
            raise HTTPException(status_code=400, detail="Desteklenmeyen temel çizgi.")
        conn = ctx.db_conn()
        if req.config_id is None:
            row = conn.execute(
                "SELECT id,hostname,config_text,version_label,created_at FROM device_configs "
                "WHERE ip=? ORDER BY created_at DESC LIMIT 1",
                (ip,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id,hostname,config_text,version_label,created_at FROM device_configs WHERE id=? AND ip=?",
                (req.config_id, ip),
            ).fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Uyumluluk için kayıtlı konfigürasyon bulunamadı.")
        started_at = time.time()
        result = evaluate_compliance(row[2], req.baseline_id)
        findings = [item for item in result["controls"] if item["status"] == "fail"]
        cursor = conn.execute(
            "INSERT INTO assurance_scan_runs "
            "(kind,started_at,finished_at,requested_by,status,target_count,finding_count,result_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                "ncm_compliance",
                started_at,
                time.time(),
                user["username"],
                "completed",
                1,
                len(findings),
                json.dumps({"ip": ip, "config_id": row[0], **result}),
            ),
        )
        conn.commit()
        run_id = int(cursor.lastrowid)
        conn.close()
        ctx._audit(
            user["username"],
            "ncm_compliance",
            f"run_id={run_id} ip={ip} config_id={row[0]} baseline={req.baseline_id} failed={len(findings)}",
        )
        return {
            "run_id": run_id,
            "ip": ip,
            "hostname": row[1],
            "config_id": row[0],
            "version_label": row[3],
            "config_created_at": row[4],
            **result,
        }

    @router.get("/api/ncm/diff")
    def get_ncm_diff(
        ip: str,
        v1_id: int,
        v2_id: int,
        user: dict = Depends(ctx.get_current_user),
    ):
        conn = ctx.db_conn()
        row1 = conn.execute(
            "SELECT id, version_label, config_text, created_at FROM device_configs WHERE id=? AND ip=?",
            (v1_id, ip),
        ).fetchone()
        row2 = conn.execute(
            "SELECT id, version_label, config_text, created_at FROM device_configs WHERE id=? AND ip=?",
            (v2_id, ip),
        ).fetchone()
        conn.close()
        if not row1 or not row2:
            raise HTTPException(status_code=404, detail="Karşılaştırılacak konfigürasyon sürümleri bulunamadı.")

        diff = list(
            difflib.unified_diff(
                row1[2].splitlines(keepends=True),
                row2[2].splitlines(keepends=True),
                fromfile=f"{row1[1]} ({datetime.fromtimestamp(row1[3]).strftime('%Y-%m-%d %H:%M')})",
                tofile=f"{row2[1]} ({datetime.fromtimestamp(row2[3]).strftime('%Y-%m-%d %H:%M')})",
                lineterm="",
            )
        )
        parsed_lines: list[dict[str, object]] = []
        additions = deletions = old_line = new_line = 0
        for line in diff:
            if line.startswith(("---", "+++")):
                parsed_lines.append({"type": "header", "content": line, "old_ln": None, "new_ln": None})
            elif line.startswith("@@"):
                parsed_lines.append({"type": "chunk_header", "content": line, "old_ln": None, "new_ln": None})
            elif line.startswith("+"):
                additions += 1
                new_line += 1
                parsed_lines.append({"type": "add", "content": line[1:], "old_ln": None, "new_ln": new_line})
            elif line.startswith("-"):
                deletions += 1
                old_line += 1
                parsed_lines.append({"type": "delete", "content": line[1:], "old_ln": old_line, "new_ln": None})
            else:
                old_line += 1
                new_line += 1
                parsed_lines.append(
                    {
                        "type": "context",
                        "content": line[1:] if line.startswith(" ") else line,
                        "old_ln": old_line,
                        "new_ln": new_line,
                    }
                )
        return {
            "ip": ip,
            "config_before": row1[2],
            "config_after": row2[2],
            "v1": {
                "id": row1[0],
                "label": row1[1],
                "date": datetime.fromtimestamp(row1[3]).strftime("%Y-%m-%d %H:%M:%S"),
            },
            "v2": {
                "id": row2[0],
                "label": row2[1],
                "date": datetime.fromtimestamp(row2[3]).strftime("%Y-%m-%d %H:%M:%S"),
            },
            "stats": {
                "additions": additions,
                "deletions": deletions,
                "total_diff_lines": len(parsed_lines),
            },
            "diff_lines": parsed_lines,
        }

    @router.get("/api/ncm/change-requests")
    def list_change_requests(ip: str | None = None, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        query = (
            "SELECT r.id,r.config_id,c.ip,c.hostname,c.version_label,r.title,r.reason,r.risk,r.status,"
            "r.requested_by,r.reviewed_by,r.review_note,r.created_at,r.reviewed_at "
            "FROM change_requests r JOIN device_configs c ON c.id=r.config_id"
        )
        params: tuple[object, ...] = ()
        if ip:
            query += " WHERE c.ip=?"
            params = (ip,)
        rows = conn.execute(query + " ORDER BY r.created_at DESC LIMIT 100", params).fetchall()
        conn.close()
        keys = (
            "id",
            "config_id",
            "ip",
            "hostname",
            "version_label",
            "title",
            "reason",
            "risk",
            "status",
            "requested_by",
            "reviewed_by",
            "review_note",
            "created_at",
            "reviewed_at",
        )
        return {"requests": [dict(zip(keys, row)) for row in rows], "current_user": user["username"]}

    @router.post("/api/ncm/change-requests")
    def create_change_request(body: ChangeRequestInput, user: dict = Depends(ctx.require_permission("ncm.manage"))):
        title = body.title.strip()
        reason = body.reason.strip()
        if not 3 <= len(title) <= 120 or len(reason) > 1000:
            raise HTTPException(status_code=400, detail="Başlık 3-120, gerekçe en fazla 1000 karakter olmalıdır.")
        if body.risk not in {"low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="Geçersiz risk seviyesi.")
        conn = ctx.db_conn()
        if not conn.execute("SELECT 1 FROM device_configs WHERE id=?", (body.config_id,)).fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="Konfigürasyon sürümü bulunamadı.")
        now = time.time()
        cursor = conn.execute(
            "INSERT INTO change_requests(config_id,title,reason,risk,status,requested_by,created_at) "
            "VALUES(?,?,?,?, 'pending', ?,?)",
            (body.config_id, title, reason, body.risk, user["username"], now),
        )
        conn.commit()
        request_id = int(cursor.lastrowid)
        conn.close()
        ctx._audit(user["username"], "ncm_change_request", f"request_id={request_id} config_id={body.config_id}")
        return {"ok": True, "id": request_id, "status": "pending"}

    @router.post("/api/ncm/change-requests/{request_id}/decision")
    def decide_change_request(
        request_id: int,
        body: ChangeDecisionInput,
        user: dict = Depends(ctx.require_permission("ncm.manage")),
    ):
        if body.decision not in {"approved", "rejected"} or len(body.note.strip()) > 1000:
            raise HTTPException(
                status_code=400, detail="Karar approved/rejected olmalı; not en fazla 1000 karakterdir."
            )
        conn = ctx.db_conn()
        row = conn.execute("SELECT requested_by,status FROM change_requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            conn.close()
            raise HTTPException(status_code=404, detail="Değişiklik talebi bulunamadı.")
        if row[1] != "pending":
            conn.close()
            raise HTTPException(status_code=409, detail="Bu talep daha önce sonuçlandırılmış.")
        if row[0].casefold() == user["username"].casefold():
            conn.close()
            raise HTTPException(status_code=409, detail="Talebi oluşturan kullanıcı kendi talebini onaylayamaz.")
        now = time.time()
        conn.execute(
            "UPDATE change_requests SET status=?,reviewed_by=?,review_note=?,reviewed_at=? WHERE id=?",
            (body.decision, user["username"], body.note.strip(), now, request_id),
        )
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "ncm_change_decision", f"request_id={request_id} decision={body.decision}")
        return {"ok": True, "id": request_id, "status": body.decision, "reviewed_by": user["username"]}

    return router
