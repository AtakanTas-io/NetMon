"""Uygulama ayarları ve gizli değer yönetimi API uçları."""

import ipaddress
import json
import platform
import re

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class SettingsUpdate(BaseModel):
    ping_target: str | None = None
    dns_domain: str | None = None
    subnet: str | None = None
    ping_count: int | None = None
    diagnostics_interval: int | None = None
    scan_interval: int | None = None
    retention_hours: int | None = None
    wmi_username: str | None = None
    wmi_password: str | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None
    snmp_community: str | None = None
    public_ip_lookup: bool | None = None
    winrm_verify_tls: bool | None = None
    ncm_auto_backup_enabled: bool | None = None
    ncm_backup_interval: int | None = None
    authorized_dhcp_servers: str | None = None
    ad_server: str | None = None
    ad_domain: str | None = None


def _validate_settings_update(ctx, updates: dict) -> str | None:
    bounds = {
        "ping_count": (1, 20),
        "diagnostics_interval": (5, 3600),
        "scan_interval": (60, 86400),
        "retention_hours": (1, 8760),
        "ncm_backup_interval": (900, 604800),
    }
    for key, (lower, upper) in bounds.items():
        if key in updates and not lower <= updates[key] <= upper:
            return f"{key} değeri {lower}-{upper} aralığında olmalıdır."

    for key in ("ping_target", "dns_domain"):
        if key in updates:
            value = str(updates[key]).strip()
            if not value or len(value) > 253 or re.search(r"\s", value):
                return f"{key} geçerli bir IP/alan adı olmalıdır."
            updates[key] = value

    if "subnet" in updates:
        raw_subnets = [item.strip() for item in str(updates["subnet"] or "").split(",") if item.strip()]
        if len(raw_subnets) > 16:
            return "En fazla 16 subnet tanımlanabilir."
        normalized = []
        for raw in raw_subnets:
            parts = raw.split("=", 1)
            net_str = parts[0].strip()
            name_str = ("=" + parts[1].strip()) if len(parts) > 1 else ""
            try:
                network = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                return f"Geçersiz subnet: {net_str}"
            if not ctx._is_allowed_inventory_network(network):
                return f"Yalnızca yerel/özel IPv4 subnetleri kullanılabilir: {net_str}"
            if network.prefixlen < 16:
                return f"Çok geniş subnet desteklenmiyor (en geniş /16): {net_str}"
            normalized.append(str(network) + name_str)
        updates["subnet"] = ",".join(normalized)

    if "authorized_dhcp_servers" in updates:
        normalized_servers = []
        for raw in re.split(r"[,;\s]+", str(updates["authorized_dhcp_servers"] or "")):
            if not raw:
                continue
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                return f"Geçersiz yetkili DHCP IP adresi: {raw}"
            if address.version != 4:
                return "Yetkili DHCP listesinde yalnız IPv4 adresleri kullanılabilir."
            normalized_servers.append(str(address))
        if len(normalized_servers) > 32:
            return "En fazla 32 yetkili DHCP sunucusu tanımlanabilir."
        updates["authorized_dhcp_servers"] = ",".join(sorted(set(normalized_servers)))

    for key in ("ad_server", "ad_domain"):
        if key in updates:
            value = str(updates[key] or "").strip()
            if value and (len(value) > 253 or re.search(r"[^A-Za-z0-9._:-]", value)):
                return f"{key} geçerli bir IP veya alan adı olmalıdır."
            updates[key] = value

    for key in ("wmi_username", "ssh_username"):
        if key in updates:
            updates[key] = str(updates[key]).strip()
            if len(updates[key]) > 256:
                return f"{key} en fazla 256 karakter olabilir."
    if "wmi_username" in updates and "/" in updates["wmi_username"]:
        return "WMI kullanıcı adı DOMAIN\\kullanıcı veya kullanıcı@domain biçiminde olmalıdır; '/' kullanmayın."
    for key in ctx.SECRET_SETTING_KEYS:
        if key in updates and len(str(updates[key])) > 1024:
            return f"{key} en fazla 1024 karakter olabilir."
    return None


def create_settings_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/settings")
    def api_get_settings(user: dict = Depends(ctx.get_current_user)):
        settings = ctx.get_all_settings()
        can_manage = ctx._has_permission(user, "system.settings.manage")
        return {
            "settings": ctx._public_settings(settings, include_management_metadata=can_manage),
            "version": "2.5.0",
            "platform": platform.platform(),
            "db_path": str(ctx.DB_PATH) if can_manage else None,
        }

    @router.post("/api/settings")
    def api_set_settings(body: SettingsUpdate, user: dict = Depends(ctx.require_permission("system.settings.manage"))):
        updates = body.model_dump(exclude_none=True)
        validation_error = _validate_settings_update(ctx, updates)
        if validation_error:
            return JSONResponse(status_code=400, content={"error": validation_error})
        for key, value in updates.items():
            ctx.set_setting(key, value)
        new_settings = ctx.get_all_settings()
        ctx.apply_settings_to_runtime(new_settings)
        audit_updates = {key: ("***" if key in ctx.SECRET_SETTING_KEYS else value) for key, value in updates.items()}
        ctx._audit(user["username"], "settings_update", json.dumps(audit_updates, ensure_ascii=False))
        return {"ok": True, "settings": ctx._public_settings(new_settings)}

    @router.post("/api/settings/reset")
    def api_reset_settings(user: dict = Depends(ctx.require_permission("system.settings.manage"))):
        conn = ctx.db_conn()
        conn.execute("DELETE FROM settings")
        conn.commit()
        conn.close()
        ctx.apply_settings_to_runtime(ctx.DEFAULT_SETTINGS)
        ctx._audit(user["username"], "settings_reset")
        return {"ok": True}

    return router
