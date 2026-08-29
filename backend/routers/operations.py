"""Alarm, geçmiş, rapor, site ve API anahtarı uçları."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    from ..core import operations as ops
except ImportError:
    from core import operations as ops  # type: ignore[no-redef]


class AlertRuleInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    rule_type: str
    threshold_seconds: int = Field(default=0, ge=0, le=31_536_000)
    target: str = Field(default="", max_length=255)
    level: Literal["info", "warning", "critical"] = "warning"
    channels: list[Literal["email", "webhook"]] = Field(default_factory=list)
    cooldown_seconds: int = Field(default=900, ge=30, le=604_800)
    enabled: bool = True


class SiteInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)
    cidrs: list[str] = Field(default_factory=list)
    active: bool = True


class ReportScheduleInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    format: Literal["pdf", "xlsx"] = "xlsx"
    interval_seconds: int = Field(ge=3600, le=31_536_000)
    recipient: str = Field(default="", max_length=320)
    site_id: int | None = None
    enabled: bool = True


class ApiKeyInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    permissions: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    rate_limit_per_minute: int = Field(default=60, ge=5, le=600)


def _rule_dict(row) -> dict:
    return {
        "id": row[0],
        "name": row[1],
        "rule_type": row[2],
        "threshold_seconds": row[3],
        "target": row[4] or "",
        "level": row[5],
        "channels": json.loads(row[6] or "[]"),
        "cooldown_seconds": row[7],
        "enabled": bool(row[8]),
        "last_evaluated_at": row[9],
        "last_triggered_at": row[10],
    }


def create_operations_router(ctx) -> APIRouter:
    router = APIRouter()

    def _site_overlap(conn, cidrs: list[str], exclude_id: int | None = None) -> str | None:
        networks = [ipaddress.ip_network(cidr) for cidr in cidrs]
        for site in ops.load_sites(conn):
            if site["id"] == exclude_id:
                continue
            for existing in map(ipaddress.ip_network, site["cidrs"]):
                if any(network.overlaps(existing) for network in networks):
                    return f"Subnet kapsamı '{site['name']}' sitesiyle çakışıyor: {existing}"
        return None

    @router.get("/api/alert-rules")
    def list_alert_rules(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,name,rule_type,threshold_seconds,target,level,channels_json,cooldown_seconds,enabled,"
            "last_evaluated_at,last_triggered_at FROM alert_rules ORDER BY id"
        ).fetchall()
        conn.close()
        return {"rules": [_rule_dict(row) for row in rows], "supported_types": sorted(ops.RULE_TYPES)}

    @router.post("/api/alert-rules")
    def create_alert_rule(body: AlertRuleInput, user: dict = Depends(ctx.require_permission("security.manage"))):
        if body.rule_type not in ops.RULE_TYPES:
            raise HTTPException(status_code=400, detail="Desteklenmeyen alarm kuralı türü.")
        now = time.time()
        conn = ctx.db_conn()
        cursor = conn.execute(
            "INSERT INTO alert_rules(name,rule_type,threshold_seconds,target,level,channels_json,cooldown_seconds,enabled,"
            "last_evaluated_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                body.name.strip(),
                body.rule_type,
                body.threshold_seconds,
                body.target.strip(),
                body.level,
                json.dumps(sorted(set(body.channels))),
                body.cooldown_seconds,
                int(body.enabled),
                now if body.rule_type == "new_device" else None,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "alert_rule_create", f"rule_id={cursor.lastrowid} type={body.rule_type}")
        return {"ok": True, "id": cursor.lastrowid}

    @router.put("/api/alert-rules/{rule_id}")
    def update_alert_rule(
        rule_id: int, body: AlertRuleInput, user: dict = Depends(ctx.require_permission("security.manage"))
    ):
        if body.rule_type not in ops.RULE_TYPES:
            raise HTTPException(status_code=400, detail="Desteklenmeyen alarm kuralı türü.")
        conn = ctx.db_conn()
        cursor = conn.execute(
            "UPDATE alert_rules SET name=?,rule_type=?,threshold_seconds=?,target=?,level=?,channels_json=?,"
            "cooldown_seconds=?,enabled=?,updated_at=? WHERE id=?",
            (
                body.name.strip(),
                body.rule_type,
                body.threshold_seconds,
                body.target.strip(),
                body.level,
                json.dumps(sorted(set(body.channels))),
                body.cooldown_seconds,
                int(body.enabled),
                time.time(),
                rule_id,
            ),
        )
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Alarm kuralı bulunamadı.")
        ctx._audit(user["username"], "alert_rule_update", f"rule_id={rule_id}")
        return {"ok": True}

    @router.delete("/api/alert-rules/{rule_id}")
    def delete_alert_rule(rule_id: int, user: dict = Depends(ctx.require_permission("security.manage"))):
        conn = ctx.db_conn()
        cursor = conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Alarm kuralı bulunamadı.")
        ctx._audit(user["username"], "alert_rule_delete", f"rule_id={rule_id}")
        return {"ok": True}

    @router.post("/api/alert-rules/evaluate")
    def evaluate_alert_rules(user: dict = Depends(ctx.require_permission("security.manage"))):
        conn = ctx.db_conn()
        events = ops.evaluate_rules(conn, ctx._devices_cache.get("data", []))
        ops.deliver_events(conn, events, ctx.get_all_settings())
        conn.close()
        ctx._audit(user["username"], "alert_rules_evaluate", f"events={len(events)}")
        return {"evaluated": True, "events": events}

    @router.get("/api/alert-events")
    def list_alert_events(limit: int = Query(default=100, ge=1, le=500), user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT e.id,e.rule_id,e.ts,e.level,e.message,e.evidence_json,e.delivery_json,r.name "
            "FROM alert_events e JOIN alert_rules r ON r.id=e.rule_id ORDER BY e.ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return {
            "events": [
                {
                    "id": row[0],
                    "rule_id": row[1],
                    "ts": row[2],
                    "level": row[3],
                    "message": row[4],
                    "evidence": json.loads(row[5]),
                    "delivery": json.loads(row[6] or "{}"),
                    "rule_name": row[7],
                }
                for row in rows
            ]
        }

    @router.get("/api/history")
    def get_history(
        range: Literal["24h", "7d", "30d"] = "24h",
        site_id: int | None = None,
        user: dict = Depends(ctx.require_permission("reports.view")),
    ):
        seconds = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}[range]
        conn = ctx.db_conn()
        query = (
            "SELECT ts,site_id,device_count,online_count,open_port_count,traffic_bps,source "
            "FROM operational_snapshots WHERE ts>=?"
        )
        params: tuple = (time.time() - seconds,)
        if site_id is not None:
            query += " AND site_id=?"
            params += (site_id,)
        rows = conn.execute(query + " ORDER BY ts", params).fetchall()
        conn.close()
        return {
            "range": range,
            "site_id": site_id,
            "points": [
                {
                    "ts": row[0],
                    "site_id": row[1],
                    "devices": row[2],
                    "online": row[3],
                    "open_ports": row[4],
                    "traffic_bps": row[5],
                    "source": row[6],
                }
                for row in rows
            ],
        }

    @router.post("/api/history/snapshot")
    def create_history_snapshot(user: dict = Depends(ctx.require_permission("reports.view"))):
        conn = ctx.db_conn()
        count = ops.collect_snapshot(conn, ctx._devices_cache.get("data", []))
        conn.close()
        return {"ok": True, "inserted": count}

    @router.get("/api/sites")
    def list_sites(user: dict = Depends(ctx.require_permission("locations.view"))):
        conn = ctx.db_conn()
        sites = ops.load_sites(conn, active_only=False)
        counts = dict(conn.execute("SELECT site_id,COUNT(*) FROM inventory_assets GROUP BY site_id").fetchall())
        conn.close()
        for site in sites:
            site["asset_count"] = counts.get(site["id"], 0)
        return {"sites": sites, "unassigned_assets": counts.get(None, 0)}

    @router.post("/api/sites")
    def create_site(body: SiteInput, user: dict = Depends(ctx.require_permission("locations.manage"))):
        try:
            cidrs = ops.parse_cidrs(body.cidrs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        now = time.time()
        conn = ctx.db_conn()
        try:
            if body.active:
                overlap = _site_overlap(conn, cidrs)
                if overlap:
                    conn.close()
                    raise HTTPException(status_code=409, detail=overlap)
            cursor = conn.execute(
                "INSERT INTO sites(name,description,cidrs_json,active,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (body.name.strip(), body.description.strip(), json.dumps(cidrs), int(body.active), now, now),
            )
            _assign_assets_to_sites(conn)
            conn.commit()
        except ctx.sqlite3.IntegrityError as exc:
            conn.close()
            raise HTTPException(status_code=409, detail="Bu site adı zaten kullanılıyor.") from exc
        conn.close()
        ctx._audit(user["username"], "site_create", f"site_id={cursor.lastrowid}")
        return {"ok": True, "id": cursor.lastrowid}

    def _assign_assets_to_sites(conn) -> None:
        sites = ops.load_sites(conn)
        rows = conn.execute("SELECT asset_id,ip_address FROM inventory_assets").fetchall()
        for asset_id, ip in rows:
            conn.execute(
                "UPDATE inventory_assets SET site_id=? WHERE asset_id=?", (ops.site_for_ip(ip, sites), asset_id)
            )

    @router.put("/api/sites/{site_id}")
    def update_site(site_id: int, body: SiteInput, user: dict = Depends(ctx.require_permission("locations.manage"))):
        try:
            cidrs = ops.parse_cidrs(body.cidrs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        conn = ctx.db_conn()
        if body.active:
            overlap = _site_overlap(conn, cidrs, site_id)
            if overlap:
                conn.close()
                raise HTTPException(status_code=409, detail=overlap)
        cursor = conn.execute(
            "UPDATE sites SET name=?,description=?,cidrs_json=?,active=?,updated_at=? WHERE id=?",
            (body.name.strip(), body.description.strip(), json.dumps(cidrs), int(body.active), time.time(), site_id),
        )
        if cursor.rowcount:
            _assign_assets_to_sites(conn)
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Site bulunamadı.")
        ctx._audit(user["username"], "site_update", f"site_id={site_id}")
        return {"ok": True}

    @router.delete("/api/sites/{site_id}")
    def delete_site(site_id: int, user: dict = Depends(ctx.require_permission("locations.manage"))):
        conn = ctx.db_conn()
        conn.execute("UPDATE inventory_assets SET site_id=NULL WHERE site_id=?", (site_id,))
        cursor = conn.execute("DELETE FROM sites WHERE id=?", (site_id,))
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Site bulunamadı.")
        ctx._audit(user["username"], "site_delete", f"site_id={site_id}")
        return {"ok": True}

    @router.get("/api/reports/export")
    def export_report(
        format: Literal["pdf", "xlsx"] = "xlsx",
        site_id: int | None = None,
        user: dict = Depends(ctx.require_permission("reports.view")),
    ):
        conn = ctx.db_conn()
        content, media_type, filename = ops.build_report_file(ops.operations_report_data(conn, site_id), format)
        conn.close()
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-NetMon-Data-Source": "stored-observations",
            },
        )

    @router.get("/api/report-schedules")
    def list_report_schedules(user: dict = Depends(ctx.require_permission("reports.view"))):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,name,format,interval_seconds,recipient,site_id,enabled,last_run_at,next_run_at "
            "FROM report_schedules ORDER BY id"
        ).fetchall()
        conn.close()
        return {
            "schedules": [
                dict(
                    zip(
                        [
                            "id",
                            "name",
                            "format",
                            "interval_seconds",
                            "recipient",
                            "site_id",
                            "enabled",
                            "last_run_at",
                            "next_run_at",
                        ],
                        [*row[:6], bool(row[6]), *row[7:]],
                        strict=True,
                    )
                )
                for row in rows
            ]
        }

    @router.post("/api/report-schedules")
    def create_report_schedule(
        body: ReportScheduleInput, user: dict = Depends(ctx.require_permission("system.settings.manage"))
    ):
        now = time.time()
        conn = ctx.db_conn()
        cursor = conn.execute(
            "INSERT INTO report_schedules(name,format,interval_seconds,recipient,site_id,enabled,next_run_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                body.name.strip(),
                body.format,
                body.interval_seconds,
                body.recipient.strip(),
                body.site_id,
                int(body.enabled),
                now + body.interval_seconds,
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
        return {"ok": True, "id": cursor.lastrowid}

    @router.put("/api/report-schedules/{schedule_id}")
    def update_report_schedule(
        schedule_id: int,
        body: ReportScheduleInput,
        user: dict = Depends(ctx.require_permission("system.settings.manage")),
    ):
        now = time.time()
        conn = ctx.db_conn()
        cursor = conn.execute(
            "UPDATE report_schedules SET name=?,format=?,interval_seconds=?,recipient=?,site_id=?,enabled=?,"
            "next_run_at=?,updated_at=? WHERE id=?",
            (
                body.name.strip(),
                body.format,
                body.interval_seconds,
                body.recipient.strip(),
                body.site_id,
                int(body.enabled),
                now + body.interval_seconds,
                now,
                schedule_id,
            ),
        )
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Rapor programı bulunamadı.")
        ctx._audit(user["username"], "report_schedule_update", f"schedule_id={schedule_id}")
        return {"ok": True}

    @router.delete("/api/report-schedules/{schedule_id}")
    def delete_report_schedule(
        schedule_id: int,
        user: dict = Depends(ctx.require_permission("system.settings.manage")),
    ):
        conn = ctx.db_conn()
        cursor = conn.execute("DELETE FROM report_schedules WHERE id=?", (schedule_id,))
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Rapor programı bulunamadı.")
        ctx._audit(user["username"], "report_schedule_delete", f"schedule_id={schedule_id}")
        return {"ok": True}

    @router.get("/api/report-runs")
    def list_report_runs(
        limit: int = Query(default=50, ge=1, le=500),
        user: dict = Depends(ctx.require_permission("reports.view")),
    ):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,schedule_id,ts,format,status,recipient,error FROM report_runs ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return {
            "runs": [
                dict(
                    zip(
                        ["id", "schedule_id", "ts", "format", "status", "recipient", "error"],
                        row,
                        strict=True,
                    )
                )
                for row in rows
            ]
        }

    @router.post("/api/report-schedules/run-due")
    def run_scheduled_reports(user: dict = Depends(ctx.require_permission("system.settings.manage"))):
        conn = ctx.db_conn()
        count = ops.run_due_reports(conn, ctx.get_all_settings())
        conn.close()
        return {"ok": True, "processed": count}

    @router.get("/api/api-keys")
    def list_api_keys(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,name,key_prefix,permissions_json,rate_limit_per_minute,created_at,expires_at,last_used_at,revoked_at "
            "FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
        conn.close()
        return {
            "keys": [
                {
                    "id": row[0],
                    "name": row[1],
                    "prefix": row[2],
                    "permissions": json.loads(row[3]),
                    "rate_limit_per_minute": row[4],
                    "created_at": row[5],
                    "expires_at": row[6],
                    "last_used_at": row[7],
                    "revoked": row[8] is not None,
                }
                for row in rows
            ]
        }

    @router.post("/api/api-keys")
    def create_api_key(body: ApiKeyInput, user: dict = Depends(ctx.get_current_user)):
        allowed = set(user.get("permissions") or ctx._role_permissions(user["role"]))
        requested = set(body.permissions)
        if "*" not in allowed and not requested.issubset(allowed):
            raise HTTPException(status_code=403, detail="API anahtarı kullanıcıdan daha geniş yetki alamaz.")
        permissions = sorted(requested or allowed)
        raw_key = "nm_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        now = time.time()
        expires_at = now + body.expires_in_days * 86400 if body.expires_in_days else None
        conn = ctx.db_conn()
        cursor = conn.execute(
            "INSERT INTO api_keys(user_id,name,key_prefix,key_hash,permissions_json,rate_limit_per_minute,created_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                user["id"],
                body.name.strip(),
                raw_key[:11],
                digest,
                json.dumps(permissions),
                body.rate_limit_per_minute,
                now,
                expires_at,
            ),
        )
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "api_key_create", f"key_id={cursor.lastrowid} permissions={permissions}")
        return {"id": cursor.lastrowid, "key": raw_key, "prefix": raw_key[:11], "permissions": permissions}

    @router.delete("/api/api-keys/{key_id}")
    def revoke_api_key(key_id: int, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        cursor = conn.execute(
            "UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
            (time.time(), key_id, user["id"]),
        )
        conn.commit()
        conn.close()
        if not cursor.rowcount:
            raise HTTPException(status_code=404, detail="Etkin API anahtarı bulunamadı.")
        ctx._audit(user["username"], "api_key_revoke", f"key_id={key_id}")
        return {"ok": True}

    return router
