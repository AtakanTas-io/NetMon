"""Ağ cihazı yapılandırma yedekleme ve sürüm farkı API uçları."""

import difflib
import hashlib
import ipaddress
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel


class NcmBackupRequest(BaseModel):
    ip: str
    version_label: str | None = None
    manual_config: str | None = None


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

    return router
