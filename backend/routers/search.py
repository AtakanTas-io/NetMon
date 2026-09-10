"""Faz 4 birleşik ağ araması, indeksleme ve kayıtlı sorgu API'leri."""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    from ..core.search_engine import SearchQueryError, compile_query, document_matches, matched_fields
except ImportError:
    from core.search_engine import (  # type: ignore[no-redef]
        SearchQueryError,
        compile_query,
        document_matches,
        matched_fields,
    )


class SavedSearchRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=1000)
    sort: str = "last_seen"
    order: Literal["asc", "desc"] = "desc"


SORT_FIELDS = {"hostname", "ip", "last_seen", "latency", "packet_loss", "status", "device_type", "vendor"}
CATEGORY_FIELDS = {
    "identity": {"text", "ip", "mac", "hostname", "device_type", "vendor", "status"},
    "network": {"site", "subnet", "switch_port", "vlan", "open_ports"},
    "inventory": {"os_text", "software_text", "service_text", "banner_text", "verified"},
    "security": {"cert_status", "cves"},
    "configuration": {"config_text", "config_changed"},
    "performance": {"latency", "packet_loss", "uptime", "last_seen"},
}


def _json_list(raw) -> list:
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def _build_documents(ctx) -> list[dict]:
    conn = ctx.db_conn()
    assets = conn.execute(
        "SELECT ia.asset_id,ia.hostname,ia.ip_address,ia.mac_address,ia.vendor,ia.device_type,"
        "ia.os_name,ia.os_version,ia.status,ia.last_seen,ia.completeness,am.owner,am.department,"
        "am.location,s.name "
        "FROM inventory_assets ia LEFT JOIN asset_metadata am ON am.asset_id=ia.asset_id "
        "LEFT JOIN sites s ON s.id=ia.site_id"
    ).fetchall()
    software_rows = conn.execute("SELECT asset_id,name,version FROM inventory_software ORDER BY name").fetchall()
    interface_rows = conn.execute(
        "SELECT asset_id,interface_name,subnet FROM inventory_interfaces ORDER BY collected_at DESC"
    ).fetchall()
    config_rows = conn.execute(
        "SELECT d.ip,d.config_text,d.created_at,"
        "(SELECT COUNT(DISTINCT d2.config_hash) FROM device_configs d2 WHERE d2.ip=d.ip) "
        "FROM device_configs d WHERE d.id=(SELECT d3.id FROM device_configs d3 WHERE d3.ip=d.ip ORDER BY d3.created_at DESC LIMIT 1)"
    ).fetchall()
    cert_rows = conn.execute("SELECT ip,days_left FROM ssl_certificates").fetchall()
    cve_row = conn.execute(
        "SELECT result_json FROM assurance_scan_runs WHERE kind='cve_correlation' AND status='completed' "
        "ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    conn.close()

    by_asset_software: dict[int, list[str]] = {}
    for asset_id, name, version in software_rows:
        by_asset_software.setdefault(asset_id, []).append(" ".join(part for part in (name, version) if part))
    by_asset_interface: dict[int, dict] = {}
    for asset_id, interface_name, subnet in interface_rows:
        by_asset_interface.setdefault(asset_id, {"interface": interface_name, "subnet": subnet})
    configs = {row[0]: {"text": row[1], "changed": row[3] > 1, "ts": row[2]} for row in config_rows}
    certs = {
        row[0]: "expired"
        if row[1] is not None and row[1] < 0
        else "expiring"
        if row[1] is not None and row[1] <= 30
        else "valid"
        for row in cert_rows
    }
    cves_by_ip: dict[str, list[str]] = {}
    for finding in _json_list(cve_row[0] if cve_row else None):
        if isinstance(finding, dict) and finding.get("ip") and finding.get("cve_id"):
            cves_by_ip.setdefault(str(finding["ip"]), []).append(str(finding["cve_id"]))

    discovery = {}
    for item in ctx._devices_cache.get("data") or []:
        if item.get("ip"):
            discovery[str(item["ip"])] = item
    documents: dict[str, dict] = {}

    def service_fields(observed: dict) -> tuple[list[str], list[str]]:
        services = (observed.get("classification") or {}).get("services") or observed.get("services") or []
        names, banners = [], []
        for service in services:
            if not isinstance(service, dict):
                continue
            if service.get("service"):
                names.append(str(service["service"]))
            banner = " ".join(str(service.get(key) or "") for key in ("product", "version", "banner")).strip()
            if banner:
                banners.append(banner)
        banners.extend(str(value) for value in (observed.get("banners") or {}).values() if value)
        return names, banners

    for row in assets:
        (
            asset_id,
            hostname,
            ip,
            mac,
            vendor,
            device_type,
            os_name,
            os_version,
            status,
            last_seen,
            completeness,
            owner,
            department,
            location,
            site,
        ) = row
        observed = discovery.get(str(ip), {})
        classification = observed.get("classification") or {}
        service_names, banners = service_fields(observed)
        interface = by_asset_interface.get(asset_id, {})
        config = configs.get(str(ip), {})
        key = f"asset:{asset_id}"
        documents[key] = {
            "id": key,
            "asset_id": asset_id,
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "status": status,
            "last_seen": last_seen,
            "latency": observed.get("latency"),
            "packet_loss": observed.get("packet_loss"),
            "site": site or location,
            "subnet": interface.get("subnet") or observed.get("last_network"),
            "switch_port": observed.get("switch_port") or interface.get("interface"),
            "vlan": observed.get("vlan"),
            "open_ports": classification.get("open_ports") or observed.get("open_ports") or [],
            "os_text": " ".join(part for part in (os_name, os_version) if part),
            "software_text": by_asset_software.get(asset_id, []),
            "service_text": service_names,
            "banner_text": banners,
            "verified": float(completeness or 0) >= 70,
            "owner": owner,
            "department": department,
            "cert_status": certs.get(str(ip)),
            "cves": cves_by_ip.get(str(ip), []),
            "config_text": config.get("text", ""),
            "config_changed": bool(config.get("changed")),
            "updated_at": time.time(),
        }
    indexed_ips = {str(item.get("ip")) for item in documents.values() if item.get("ip")}
    for ip, item in discovery.items():
        if ip in indexed_ips:
            continue
        classification = item.get("classification") or {}
        service_names, banners = service_fields(item)
        config = configs.get(ip, {})
        key = f"device:{item.get('mac') or ip}"
        documents[key] = {
            "id": key,
            "asset_id": None,
            "hostname": item.get("hostname") or item.get("friendly_name"),
            "ip": ip,
            "mac": item.get("mac"),
            "vendor": item.get("vendor"),
            "device_type": item.get("type"),
            "status": item.get("status"),
            "last_seen": item.get("last_seen"),
            "latency": item.get("latency"),
            "packet_loss": item.get("packet_loss"),
            "site": item.get("location"),
            "subnet": item.get("last_network"),
            "switch_port": item.get("switch_port"),
            "vlan": item.get("vlan"),
            "open_ports": classification.get("open_ports") or item.get("open_ports") or [],
            "os_text": item.get("os_fingerprint") or "",
            "software_text": [],
            "service_text": service_names,
            "banner_text": banners,
            "verified": False,
            "owner": item.get("owner"),
            "department": None,
            "cert_status": certs.get(ip),
            "cves": cves_by_ip.get(ip, []),
            "config_text": config.get("text", ""),
            "config_changed": bool(config.get("changed")),
            "updated_at": time.time(),
        }
    indexed_ips = {str(item.get("ip")) for item in documents.values() if item.get("ip")}
    for ip in sorted((set(configs) | set(certs) | set(cves_by_ip)) - indexed_ips):
        if ip in indexed_ips:
            continue
        config = configs.get(ip, {})
        key = f"source:{ip}"
        documents[key] = {
            "id": key,
            "asset_id": None,
            "hostname": None,
            "ip": ip,
            "mac": None,
            "vendor": None,
            "device_type": "unknown",
            "status": "unknown",
            "last_seen": config.get("ts"),
            "latency": None,
            "packet_loss": None,
            "site": None,
            "subnet": None,
            "switch_port": None,
            "vlan": None,
            "open_ports": [],
            "os_text": "",
            "software_text": [],
            "service_text": [],
            "banner_text": [],
            "verified": False,
            "owner": None,
            "department": None,
            "cert_status": certs.get(ip),
            "cves": cves_by_ip.get(ip, []),
            "config_text": config.get("text", ""),
            "config_changed": bool(config.get("changed")),
            "updated_at": time.time(),
        }
    return list(documents.values())


def _store_documents(ctx, documents: list[dict]) -> None:
    conn = ctx.db_conn()
    conn.execute("DELETE FROM search_documents")
    conn.executemany(
        "INSERT INTO search_documents(document_id,category,title,ip,mac,hostname,device_type,vendor,status,last_seen,document_json,updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                item["id"],
                "device",
                item.get("hostname") or item.get("ip") or item["id"],
                item.get("ip"),
                item.get("mac"),
                item.get("hostname"),
                item.get("device_type"),
                item.get("vendor"),
                item.get("status"),
                item.get("last_seen"),
                json.dumps(item),
                item["updated_at"],
            )
            for item in documents
        ],
    )
    conn.commit()
    conn.close()


def _load_documents(ctx) -> list[dict]:
    documents = _build_documents(ctx)
    _store_documents(ctx, documents)
    return documents


def _public_result(document: dict, fields: list[str]) -> dict:
    categories = [name for name, category_fields in CATEGORY_FIELDS.items() if set(fields) & category_fields]
    return {
        key: document.get(key)
        for key in (
            "id",
            "asset_id",
            "hostname",
            "ip",
            "mac",
            "vendor",
            "device_type",
            "status",
            "last_seen",
            "latency",
            "packet_loss",
            "site",
            "subnet",
            "switch_port",
            "vlan",
            "open_ports",
            "os_text",
            "verified",
            "cert_status",
            "cves",
            "config_changed",
        )
    } | {"matched_fields": fields, "categories": categories or ["identity"]}


def _search(ctx, query: str, sort: str, order: str) -> list[dict]:
    if sort not in SORT_FIELDS:
        raise SearchQueryError(f"Desteklenmeyen sıralama alanı: {sort}")
    expression = compile_query(query)
    documents = _load_documents(ctx)
    results = [
        _public_result(item, matched_fields(item, expression))
        for item in documents
        if document_matches(item, expression)
    ]
    results.sort(
        key=lambda item: (
            item.get(sort) is None,
            str(item.get(sort) or "").casefold() if isinstance(item.get(sort), str) else item.get(sort) or 0,
        ),
        reverse=order == "desc",
    )
    results.sort(key=lambda item: item.get(sort) is None)
    return results


def create_search_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/search")
    def search(
        q: str = "",
        page: int = 1,
        page_size: int = 25,
        sort: str = "last_seen",
        order: Literal["asc", "desc"] = "desc",
        user: dict = Depends(ctx.get_current_user),
    ):
        page, page_size = max(1, page), max(1, min(page_size, 100))
        try:
            results = _search(ctx, q, sort, order)
        except SearchQueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        start = (page - 1) * page_size
        groups = {name: sum(name in item["categories"] for item in results) for name in CATEGORY_FIELDS}
        index_conn = ctx.db_conn()
        document_count = index_conn.execute("SELECT COUNT(*) FROM search_documents").fetchone()[0]
        index_conn.close()
        return {
            "query": q,
            "page": page,
            "page_size": page_size,
            "total": len(results),
            "pages": max(1, (len(results) + page_size - 1) // page_size),
            "sort": sort,
            "order": order,
            "groups": groups,
            "results": results[start : start + page_size],
            "index": {"documents": document_count, "source": "search_documents"},
        }

    @router.get("/api/search/export")
    def export_search(
        q: str = "",
        format: Literal["json", "csv"] = "csv",
        sort: str = "last_seen",
        order: Literal["asc", "desc"] = "desc",
        user: dict = Depends(ctx.get_current_user),
    ):
        try:
            results = _search(ctx, q, sort, order)[:5000]
        except SearchQueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if format == "json":
            return Response(json.dumps(results, ensure_ascii=False), media_type="application/json")
        stream = io.StringIO()
        fields = [
            "hostname",
            "ip",
            "mac",
            "vendor",
            "device_type",
            "status",
            "site",
            "open_ports",
            "cves",
            "cert_status",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for item in results:
            writer.writerow(
                {
                    **item,
                    "open_ports": ",".join(map(str, item["open_ports"] or [])),
                    "cves": ",".join(item["cves"] or []),
                }
            )
        return Response(
            stream.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=netmon-search.csv"},
        )

    @router.get("/api/search/saved")
    def saved_searches(user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT id,name,query,sort_field,sort_order,created_at,updated_at FROM saved_searches WHERE user_id=? ORDER BY name",
            (user["id"],),
        ).fetchall()
        conn.close()
        keys = ["id", "name", "query", "sort", "order", "created_at", "updated_at"]
        return {"searches": [dict(zip(keys, row)) for row in rows]}

    @router.post("/api/search/saved")
    def save_search(req: SavedSearchRequest, user: dict = Depends(ctx.get_current_user)):
        if req.sort not in SORT_FIELDS:
            raise HTTPException(status_code=400, detail="Desteklenmeyen sıralama alanı.")
        try:
            compile_query(req.query)
        except SearchQueryError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        now = time.time()
        conn = ctx.db_conn()
        conn.execute(
            "INSERT INTO saved_searches(user_id,name,query,sort_field,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(user_id,name) DO UPDATE SET query=excluded.query,sort_field=excluded.sort_field,"
            "sort_order=excluded.sort_order,updated_at=excluded.updated_at",
            (user["id"], req.name.strip(), req.query.strip(), req.sort, req.order, now, now),
        )
        conn.commit()
        saved_id = int(
            conn.execute(
                "SELECT id FROM saved_searches WHERE user_id=? AND name=?", (user["id"], req.name.strip())
            ).fetchone()[0]
        )
        conn.close()
        return {"ok": True, "id": saved_id}

    @router.delete("/api/search/saved/{saved_id}")
    def delete_saved_search(saved_id: int, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        cursor = conn.execute("DELETE FROM saved_searches WHERE id=? AND user_id=?", (saved_id, user["id"]))
        conn.commit()
        removed = cursor.rowcount > 0
        conn.close()
        if not removed:
            raise HTTPException(status_code=404, detail="Kayıtlı arama bulunamadı.")
        return {"ok": True}

    return router
