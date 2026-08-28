"""Normalize envanter okuma ve varlık metadata API uçları."""

import ipaddress
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class AssetMetadataRequest(BaseModel):
    asset_tag: str | None = None
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    status: str | None = None
    warranty_until: str | None = None
    notes: str | None = None


class WmiScanRequest(BaseModel):
    ip_list: list[str]
    username: str = ""
    password: str = ""
    timeout: int = 20


class AuthorizedInventoryRequest(BaseModel):
    ip: str
    protocol: str = "auto"
    username: str = ""
    password: str = ""
    snmp_community: str = ""
    timeout: int = 20


class NetworkScanRequest(BaseModel):
    mode: str = "agentless"


def create_inventory_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/devices")
    def get_devices(force: bool = False, user: dict = Depends(ctx.get_current_user)):
        if force and user.get("role") != "admin":
            raise ctx._AuthError(403, "Zorunlu ağ taraması için yönetici yetkisi gerekiyor.")
        now = time.time()
        if not force and ctx._devices_cache["data"] and now - ctx._devices_cache["ts"] < ctx.DEVICES_CACHE_SECONDS:
            devices = ctx._devices_cache["data"]
            for device in devices:
                ctx._enrich_device_inventory(device)
            return {"devices": devices, "cached": True, "error": ctx._devices_cache.get("error")}
        if not ctx._device_scan_lock.acquire(blocking=False):
            return {
                "devices": ctx._devices_cache.get("data") or [],
                "cached": True,
                "scanning": True,
                "error": ctx._devices_cache.get("error"),
            }
        ctx._devices_cache["scan_status"] = "running"
        try:
            try:
                devices = ctx._discover_configured_devices()
                devices = ctx.enrich_devices(devices)
                devices = ctx.merge_scan_into_inventory(devices)
                ctx._devices_cache["error"] = None
            except ctx.NetworkDiscoveryError as exc:
                ctx.logger.warning("[API] Device scan failed: %s", exc)
                devices = []
                ctx._devices_cache["error"] = str(exc)
            except Exception as exc:
                ctx.logger.exception("[API] Unexpected error during device scan")
                devices = []
                ctx._devices_cache["error"] = f"Beklenmeyen hata: {exc}"
            if devices:
                for device in devices:
                    ctx._enrich_device_inventory(device)
                    ctx._sync_normalized_inventory(
                        device,
                        {
                            "status": "Success",
                            "ip_address": device.get("ip"),
                            "mac_address": device.get("mac"),
                            "computer_name": device.get("hostname"),
                            "inventory_source": "Agentless Discovery",
                        },
                        "Agentless Discovery",
                    )
            ctx._devices_cache["data"] = devices
            ctx._devices_cache["ts"] = now
            return {"devices": devices, "cached": False, "error": ctx._devices_cache["error"]}
        finally:
            ctx._devices_cache["scan_status"] = "idle"
            ctx._device_scan_lock.release()

    @router.post("/api/scan_wmi_inventory")
    def trigger_wmi_scan(
        req: WmiScanRequest,
        user: dict = Depends(ctx.require_permission("inventory.scan")),
    ):
        if not 5 <= req.timeout <= 60:
            return JSONResponse(status_code=400, content={"error": "Zaman aşımı 5-60 saniye arasında olmalıdır."})
        if not req.ip_list or len(req.ip_list) > 64:
            return JSONResponse(status_code=400, content={"error": "Bir istekte 1-64 hedef IP gönderilebilir."})
        targets = []
        for raw in req.ip_list:
            try:
                parsed = ipaddress.ip_address(raw.strip())
            except ValueError:
                return JSONResponse(status_code=400, content={"error": f"Geçersiz IP adresi: {raw}"})
            if not ctx._is_allowed_inventory_ip(parsed):
                return JSONResponse(
                    status_code=400,
                    content={"error": f"Yalnızca yerel/özel IPv4 hedefleri taranabilir: {raw}"},
                )
            targets.append(str(parsed))
        username = req.username if req.username else ctx.WMI_USERNAME
        password = req.password if req.password else ctx.WMI_PASSWORD
        scanner = ctx.WmiNetworkScanner(
            username=username if username else None,
            password=password if password else None,
            timeout=req.timeout,
            verify_tls=ctx.WINRM_VERIFY_TLS,
        )
        results = scanner.scan_network(targets, max_workers=10)
        if ctx._devices_cache.get("data") and results:
            results_by_ip = {result.get("ip_address"): result for result in results}
            for device in ctx._devices_cache["data"]:
                if device.get("ip") in results_by_ip:
                    result = results_by_ip[device["ip"]]
                    if result.get("status") == "Success":
                        device["wmi_inventory"] = result
                        device.pop("inventory_error", None)
                        ctx._persist_device_inventory(device, result, result.get("inventory_source") or "WMI/WinRM")
                    else:
                        device["inventory_error"] = {
                            "code": result.get("error_code"),
                            "message": result.get("error_message"),
                            "ts": time.time(),
                        }
        ctx._devices_cache["ts"] = time.time()
        ctx.manager.broadcast_threadsafe(
            {"type": "devices", "devices": ctx._devices_cache.get("data", []), "ts": ctx._devices_cache.get("ts", 0)}
        )
        succeeded = sum(1 for result in results if result.get("status") == "Success")
        ctx._audit(user["username"], "wmi_scan", f"targets={len(targets)} success={succeeded}")
        return {
            "ok": True,
            "results": results,
            "summary": {"total": len(results), "success": succeeded, "failed": len(results) - succeeded},
        }

    @router.post("/api/devices/scan")
    def trigger_network_scan(
        req: NetworkScanRequest | None = None,
        user: dict = Depends(ctx.require_permission("inventory.scan")),
    ):
        if not ctx._device_scan_lock.acquire(blocking=False):
            return JSONResponse(status_code=409, content={"error": "Tarama zaten devam ediyor."})
        scan_mode = req.mode if req and req.mode in ("agentless", "deep") else "agentless"
        ctx._devices_cache["scan_status"] = "running"
        scan_started = time.time()
        scan_run_id = None
        try:
            conn = ctx.db_conn()
            cursor = conn.execute(
                "INSERT INTO inventory_scan_runs(started_at,mode,requested_by) VALUES(?,?,?)",
                (scan_started, scan_mode, user.get("username")),
            )
            scan_run_id = cursor.lastrowid
            conn.commit()
            conn.close()
        except Exception as exc:
            ctx.logger.warning("[INVENTORY] scan run kaydı açılamadı: %s", exc)
        ctx.manager.broadcast_threadsafe({"type": "scan", "status": "started", "mode": scan_mode})
        ctx.manager.broadcast_threadsafe(
            {"type": "scan_wave", "wave": 1, "label": "Wave 1: ARP & ICMP Sweep", "progress": 33}
        )
        try:
            ctx.manager.broadcast_threadsafe(
                {
                    "type": "scan_wave",
                    "wave": 2,
                    "label": "Wave 2: DNS, mDNS, SSDP, SNMP, NetBIOS & LLDP",
                    "progress": 66,
                }
            )
            devices = ctx._discover_configured_devices()
            devices = ctx.enrich_devices(devices)
            devices = ctx.merge_scan_into_inventory(devices)
            ctx.manager.broadcast_threadsafe(
                {
                    "type": "scan_wave",
                    "wave": 3,
                    "label": "Wave 3: Service Probing & Unified Inventory",
                    "progress": 100,
                }
            )
            ctx._update_switch_mac_tables(devices)
            if devices:
                if scan_mode == "deep":
                    ctx._run_windows_inventory_on_devices(devices)
                for device in devices:
                    ctx._enrich_device_inventory(device, allow_deep=scan_mode == "deep")
            ctx._devices_cache.update(
                data=devices,
                ts=time.time(),
                error=None,
                scan_mode=scan_mode,
            )
            if scan_run_id:
                try:
                    success_count = sum(
                        1
                        for device in devices
                        if device.get("wmi_inventory", {}).get("status") == "Success"
                        or device.get("deep_inventory", {}).get("status") == "Success"
                        or device.get("status") in {"online", "discovered"}
                    )
                    conn = ctx.db_conn()
                    conn.execute(
                        "UPDATE inventory_scan_runs SET finished_at=?, total=?, success=?, failed=? WHERE id=?",
                        (time.time(), len(devices), success_count, 0, scan_run_id),
                    )
                    conn.commit()
                    conn.close()
                except Exception as exc:
                    ctx.logger.warning("[INVENTORY] scan run tamamlanamadı: %s", exc)
            online_devices = [device for device in devices if device.get("status") == "online"]
            discovered_devices = [device for device in devices if device.get("status") == "discovered"]
            offline_devices = [device for device in devices if device.get("status") in {"offline", "stale"}]
            by_type: dict[str, int] = {}
            for device in devices:
                device_type = device.get("type") or "unknown"
                by_type[device_type] = by_type.get(device_type, 0) + 1
            scan_result = {
                "status": "done",
                "devices": devices,
                "online_devices": online_devices,
                "discovered_devices": discovered_devices,
                "offline_devices": offline_devices,
                "by_type": by_type,
                "ts": ctx._devices_cache["ts"],
                "mode": scan_mode,
                "error": None,
            }
            ctx.manager.broadcast_threadsafe({"type": "devices", **scan_result})
            return scan_result
        except ctx.NetworkDiscoveryError as exc:
            ctx.logger.warning("[API] Manual scan failed: %s", exc)
            ctx._devices_cache["error"] = str(exc)
            return JSONResponse(status_code=503, content={"status": "error", "devices": [], "error": str(exc)})
        except Exception as exc:
            ctx.logger.exception("[API] Unexpected error during manual scan")
            ctx._devices_cache["error"] = f"Beklenmeyen hata: {exc}"
            return JSONResponse(
                status_code=500,
                content={"status": "error", "devices": [], "error": ctx._devices_cache["error"]},
            )
        finally:
            ctx._devices_cache["scan_status"] = "idle"
            ctx.manager.broadcast_threadsafe({"type": "scan", "status": "done"})
            ctx._device_scan_lock.release()

    @router.get("/api/inventory/summary")
    def inventory_summary(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        total, online, offline, avg = conn.execute(
            """SELECT COUNT(*),
            SUM(CASE WHEN status IN ('online','discovered') THEN 1 ELSE 0 END),
            SUM(CASE WHEN status IN ('offline','stale') THEN 1 ELSE 0 END),
            COALESCE(AVG(completeness),0) FROM inventory_assets"""
        ).fetchone()
        conn.close()
        return {
            "total": total or 0,
            "online": online or 0,
            "offline": offline or 0,
            "completeness": round(avg or 0, 1),
        }

    @router.get("/api/inventory/scans")
    def inventory_scan_runs(limit: int = 20, user: dict = Depends(ctx.get_current_user)):
        limit = max(1, min(limit, 100))
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,started_at,finished_at,mode,requested_by,total,success,failed,error "
            "FROM inventory_scan_runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        keys = ["id", "started_at", "finished_at", "mode", "requested_by", "total", "success", "failed", "error"]
        return {"scans": [dict(zip(keys, row)) for row in rows]}

    @router.get("/api/inventory/assets")
    def inventory_assets(limit: int = 500, user: dict = Depends(ctx.get_current_user)):
        limit = max(1, min(limit, 2000))
        conn = ctx.db_conn()
        rows = conn.execute(
            """SELECT asset_id,hostname,ip_address,mac_address,vendor,device_type,os_name,os_version,status,
            first_seen,last_seen,inventory_source,completeness
            FROM inventory_assets ORDER BY last_seen DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        keys = [
            "asset_id",
            "hostname",
            "ip_address",
            "mac_address",
            "vendor",
            "device_type",
            "os_name",
            "os_version",
            "status",
            "first_seen",
            "last_seen",
            "inventory_source",
            "completeness",
        ]
        return {"assets": [dict(zip(keys, row)) for row in rows]}

    @router.get("/api/inventory/assets/{asset_id}")
    def inventory_asset_detail(asset_id: int, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        asset = conn.execute("SELECT * FROM inventory_assets WHERE asset_id=?", (asset_id,)).fetchone()
        if not asset:
            conn.close()
            raise HTTPException(status_code=404, detail="Varlık bulunamadı")
        columns = [description[0] for description in conn.execute("SELECT * FROM inventory_assets LIMIT 0").description]
        item = dict(zip(columns, asset))
        hardware = conn.execute(
            "SELECT cpu,ram_gb,gpu,motherboard,disk_json,serial_number,collected_at "
            "FROM inventory_hardware WHERE asset_id=?",
            (asset_id,),
        ).fetchone()
        hardware_keys = ["cpu", "ram_gb", "gpu", "motherboard", "disk_json", "serial_number", "collected_at"]
        item["hardware"] = dict(zip(hardware_keys, hardware)) if hardware else {}
        item["interfaces"] = [
            dict(zip(["id", "interface_name", "ip_address", "mac_address", "gateway", "subnet", "collected_at"], row))
            for row in conn.execute(
                "SELECT id,interface_name,ip_address,mac_address,gateway,subnet,collected_at "
                "FROM inventory_interfaces WHERE asset_id=? ORDER BY id",
                (asset_id,),
            ).fetchall()
        ]
        item["software"] = [
            dict(zip(["id", "name", "version", "publisher", "collected_at"], row))
            for row in conn.execute(
                "SELECT id,name,version,publisher,collected_at FROM inventory_software WHERE asset_id=? ORDER BY name",
                (asset_id,),
            ).fetchall()
        ]
        item["history"] = [
            dict(zip(["id", "event_type", "field_name", "old_value", "new_value", "source", "created_at"], row))
            for row in conn.execute(
                "SELECT id,event_type,field_name,old_value,new_value,source,created_at "
                "FROM inventory_history WHERE asset_id=? ORDER BY created_at DESC LIMIT 100",
                (asset_id,),
            ).fetchall()
        ]
        conn.close()
        return item

    @router.get("/api/inventory/assets/{asset_id}/metadata")
    def inventory_asset_metadata(asset_id: int, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        row = conn.execute(
            "SELECT asset_id,asset_tag,owner,department,location,status,warranty_until,notes,updated_at "
            "FROM asset_metadata WHERE asset_id=?",
            (asset_id,),
        ).fetchone()
        exists = conn.execute("SELECT 1 FROM inventory_assets WHERE asset_id=?", (asset_id,)).fetchone()
        conn.close()
        if not exists:
            raise HTTPException(status_code=404, detail="Varlık bulunamadı")
        keys = [
            "asset_id",
            "asset_tag",
            "owner",
            "department",
            "location",
            "status",
            "warranty_until",
            "notes",
            "updated_at",
        ]
        return dict(zip(keys, row)) if row else {"asset_id": asset_id}

    @router.put("/api/inventory/assets/{asset_id}/metadata")
    def update_inventory_asset_metadata(
        asset_id: int,
        body: AssetMetadataRequest,
        user: dict = Depends(ctx.get_current_user),
    ):
        conn = ctx.db_conn()
        exists = conn.execute("SELECT 1 FROM inventory_assets WHERE asset_id=?", (asset_id,)).fetchone()
        if not exists:
            conn.close()
            raise HTTPException(status_code=404, detail="Varlık bulunamadı")
        now = time.time()
        values = body.model_dump()
        fields = ["asset_tag", "owner", "department", "location", "status", "warranty_until", "notes"]
        old = conn.execute(
            "SELECT asset_tag,owner,department,location,status,warranty_until,notes "
            "FROM asset_metadata WHERE asset_id=?",
            (asset_id,),
        ).fetchone()
        if old is None:
            conn.execute(
                "INSERT INTO asset_metadata(asset_id,asset_tag,owner,department,location,status,warranty_until,notes,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    asset_id,
                    values.get("asset_tag"),
                    values.get("owner"),
                    values.get("department"),
                    values.get("location"),
                    values.get("status") or "managed",
                    values.get("warranty_until"),
                    values.get("notes"),
                    now,
                ),
            )
        else:
            current = dict(zip(fields, old))
            merged = {key: values[key] if values[key] is not None else current[key] for key in current}
            conn.execute(
                "UPDATE asset_metadata SET asset_tag=?,owner=?,department=?,location=?,status=?,warranty_until=?,notes=?,updated_at=? "
                "WHERE asset_id=?",
                (
                    merged["asset_tag"],
                    merged["owner"],
                    merged["department"],
                    merged["location"],
                    merged["status"],
                    merged["warranty_until"],
                    merged["notes"],
                    now,
                    asset_id,
                ),
            )
        conn.commit()
        conn.close()
        ctx._audit(user["username"], "asset_metadata_update", f"asset_id={asset_id}")
        return {"ok": True, "asset_id": asset_id, "updated_at": now}

    # Yetkili protokol akışlarının servis gövdeleri ortak çekirdek ayrıştırılana
    # kadar ana modülde kalır; HTTP route sahipliği inventory router'ındadır.
    router.add_api_route(
        "/api/devices/inventory/preflight",
        ctx.preflight_authorized_inventory,
        methods=["POST"],
    )
    router.add_api_route(
        "/api/devices/inventory",
        ctx.scan_authorized_device_inventory,
        methods=["POST"],
    )
    router.add_api_route("/api/devices/rename", ctx.rename_device, methods=["POST"])
    router.add_api_route("/api/devices/known", ctx.list_known_devices, methods=["GET"])
    return router
