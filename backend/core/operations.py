"""Faz 4 operasyon tabloları ve veri kaynağına bağlı değerlendirme yardımcıları."""

from __future__ import annotations

import ipaddress
import json
import smtplib
import sqlite3
import time
from collections import defaultdict
from email.message import EmailMessage
from io import BytesIO
from typing import Any, Iterable
from urllib.request import Request, urlopen

RULE_TYPES = {"offline_duration", "new_device", "rogue_dhcp", "ip_conflict", "config_diff"}


def ensure_operations_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            cidrs_json TEXT NOT NULL DEFAULT '[]',
            active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operational_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            site_id INTEGER,
            device_count INTEGER NOT NULL,
            online_count INTEGER NOT NULL,
            open_port_count INTEGER NOT NULL,
            traffic_bps REAL,
            source TEXT NOT NULL,
            FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_operational_snapshots_ts
            ON operational_snapshots(ts DESC, site_id);
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            threshold_seconds INTEGER NOT NULL DEFAULT 0,
            target TEXT DEFAULT '',
            level TEXT NOT NULL DEFAULT 'warning',
            channels_json TEXT NOT NULL DEFAULT '[]',
            cooldown_seconds INTEGER NOT NULL DEFAULT 900,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_evaluated_at REAL,
            last_triggered_at REAL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            ts REAL NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            delivery_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts DESC, rule_id);
        CREATE TABLE IF NOT EXISTS alert_user_states (
            user_id INTEGER NOT NULL,
            alert_ts REAL NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            suppressed INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL,
            PRIMARY KEY(user_id, alert_ts),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_alert_user_states_user
            ON alert_user_states(user_id, is_read, suppressed);
        CREATE TABLE IF NOT EXISTS report_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'xlsx',
            interval_seconds INTEGER NOT NULL,
            recipient TEXT DEFAULT '',
            site_id INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run_at REAL,
            next_run_at REAL NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS report_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            schedule_id INTEGER,
            ts REAL NOT NULL,
            format TEXT NOT NULL,
            status TEXT NOT NULL,
            recipient TEXT,
            error TEXT,
            FOREIGN KEY(schedule_id) REFERENCES report_schedules(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            permissions_json TEXT NOT NULL,
            rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
            created_at REAL NOT NULL,
            expires_at REAL,
            last_used_at REAL,
            revoked_at REAL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id, revoked_at);
        """
    )
    asset_columns = {row[1] for row in conn.execute("PRAGMA table_info(inventory_assets)").fetchall()}
    if "site_id" not in asset_columns:
        conn.execute("ALTER TABLE inventory_assets ADD COLUMN site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL")


def parse_cidrs(raw: Iterable[str]) -> list[str]:
    networks: list[str] = []
    for value in raw:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
        if network.version != 4 or not network.is_private or network.prefixlen < 16:
            raise ValueError(f"Yalnızca /16 veya daha dar özel IPv4 ağı desteklenir: {value}")
        networks.append(str(network))
    if len(networks) > 32:
        raise ValueError("Bir site için en fazla 32 subnet tanımlanabilir.")
    return sorted(set(networks))


def site_for_ip(ip: str | None, sites: list[dict[str, Any]]) -> int | None:
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    for site in sites:
        for cidr in site.get("cidrs", []):
            if address in ipaddress.ip_network(cidr, strict=False):
                return int(site["id"])
    return None


def load_sites(conn: sqlite3.Connection, active_only: bool = True) -> list[dict[str, Any]]:
    query = "SELECT id,name,description,cidrs_json,active,created_at,updated_at FROM sites"
    if active_only:
        query += " WHERE active=1"
    rows = conn.execute(query + " ORDER BY name").fetchall()
    return [
        {
            "id": row[0],
            "name": row[1],
            "description": row[2] or "",
            "cidrs": json.loads(row[3] or "[]"),
            "active": bool(row[4]),
            "created_at": row[5],
            "updated_at": row[6],
        }
        for row in rows
    ]


def collect_snapshot(conn: sqlite3.Connection, devices: list[dict[str, Any]], now: float | None = None) -> int:
    now = now or time.time()
    sites = load_sites(conn)
    grouped: dict[int | None, list[dict[str, Any]]] = defaultdict(list)
    for device in devices:
        grouped[site_for_ip(device.get("ip"), sites)].append(device)
    if not grouped:
        grouped[None] = []
    traffic_row = conn.execute(
        "SELECT wifi_sent,wifi_recv,eth_sent,eth_recv FROM traffic ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    traffic_bps = sum(float(value or 0) for value in traffic_row) if traffic_row else None
    inserted = 0
    for site_id, items in grouped.items():
        open_ports: set[int] = set()
        for device in items:
            ports = device.get("classification", {}).get("open_ports") or device.get("open_ports") or []
            if isinstance(ports, str):
                try:
                    ports = json.loads(ports)
                except json.JSONDecodeError:
                    ports = []
            open_ports.update(int(port) for port in ports if str(port).isdigit())
        online = sum(1 for item in items if item.get("status") == "online" or item.get("online") is True)
        conn.execute(
            "INSERT INTO operational_snapshots "
            "(ts,site_id,device_count,online_count,open_port_count,traffic_bps,source) VALUES(?,?,?,?,?,?,?)",
            (now, site_id, len(items), online, len(open_ports), traffic_bps, "measured_and_discovered"),
        )
        inserted += 1
    conn.commit()
    return inserted


def _rule_evidence(
    conn: sqlite3.Connection,
    rule_type: str,
    threshold: int,
    target: str,
    last_evaluated: float,
    devices: list[dict[str, Any]],
    now: float,
) -> list[dict[str, Any]]:
    if rule_type == "offline_duration":
        cutoff = now - max(60, threshold)
        rows = conn.execute(
            "SELECT mac,last_ip,hostname,last_seen,last_status FROM known_devices "
            "WHERE last_seen<=? AND last_status IN ('offline','stale')",
            (cutoff,),
        ).fetchall()
        return [
            {"mac": row[0], "ip": row[1], "hostname": row[2], "last_seen": row[3], "status": row[4]}
            for row in rows
            if not target or target in {row[0], row[1], row[2]}
        ]
    if rule_type == "new_device":
        rows = conn.execute(
            "SELECT mac,last_ip,hostname,first_seen FROM known_devices WHERE first_seen>?",
            (last_evaluated,),
        ).fetchall()
        return [{"mac": row[0], "ip": row[1], "hostname": row[2], "first_seen": row[3]} for row in rows]
    if rule_type == "rogue_dhcp":
        rows = conn.execute(
            "SELECT ts,message,source FROM alerts WHERE ts>? AND LOWER(message) LIKE '%rogue dhcp%'",
            (last_evaluated,),
        ).fetchall()
        return [{"ts": row[0], "message": row[1], "source": row[2]} for row in rows]
    if rule_type == "ip_conflict":
        by_ip: dict[str, set[str]] = defaultdict(set)
        for device in devices:
            if device.get("ip") and device.get("mac"):
                by_ip[str(device["ip"])].add(str(device["mac"]))
        return [{"ip": ip, "macs": sorted(macs)} for ip, macs in by_ip.items() if len(macs) > 1]
    if rule_type == "config_diff":
        rows = conn.execute(
            """SELECT ip, COUNT(DISTINCT config_hash), MAX(created_at)
               FROM device_configs GROUP BY ip
               HAVING COUNT(DISTINCT config_hash)>1 AND MAX(created_at)>?""",
            (last_evaluated,),
        ).fetchall()
        return [{"ip": row[0], "different_versions": row[1], "last_change": row[2]} for row in rows]
    return []


def evaluate_rules(
    conn: sqlite3.Connection, devices: list[dict[str, Any]], now: float | None = None
) -> list[dict[str, Any]]:
    now = now or time.time()
    rows = conn.execute(
        "SELECT id,name,rule_type,threshold_seconds,target,level,cooldown_seconds,last_evaluated_at,last_triggered_at "
        "FROM alert_rules WHERE enabled=1 ORDER BY id"
    ).fetchall()
    events = []
    for row in rows:
        rule_id, name, rule_type, threshold, target, level, cooldown, last_eval, last_trigger = row
        evidence = _rule_evidence(conn, rule_type, threshold, target or "", last_eval or 0, devices, now)
        can_trigger = not last_trigger or now - last_trigger >= cooldown
        if evidence and can_trigger:
            message = f"{name}: {len(evidence)} doğrulanmış eşleşme"
            cursor = conn.execute(
                "INSERT INTO alert_events(rule_id,ts,level,message,evidence_json) VALUES(?,?,?,?,?)",
                (rule_id, now, level, message, json.dumps(evidence, ensure_ascii=False)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO alerts(ts,level,message,source) VALUES(?,?,?,?)",
                (now + rule_id / 1_000_000, level, message, f"alert_rule:{rule_id}"),
            )
            conn.execute("UPDATE alert_rules SET last_triggered_at=? WHERE id=?", (now, rule_id))
            events.append(
                {
                    "id": cursor.lastrowid,
                    "rule_id": rule_id,
                    "name": name,
                    "level": level,
                    "message": message,
                    "evidence": evidence,
                }
            )
        conn.execute("UPDATE alert_rules SET last_evaluated_at=?,updated_at=? WHERE id=?", (now, now, rule_id))
    conn.commit()
    return events


def operations_report_data(conn: sqlite3.Connection, site_id: int | None = None) -> dict[str, Any]:
    if site_id is None:
        assets = conn.execute(
            "SELECT ia.asset_id,ia.hostname,ia.ip_address,ia.mac_address,ia.device_type,ia.status,ia.last_seen,"
            "s.name FROM inventory_assets ia LEFT JOIN sites s ON s.id=ia.site_id "
            "ORDER BY ia.hostname,ia.ip_address"
        ).fetchall()
    else:
        assets = conn.execute(
            "SELECT ia.asset_id,ia.hostname,ia.ip_address,ia.mac_address,ia.device_type,ia.status,ia.last_seen,"
            "s.name FROM inventory_assets ia LEFT JOIN sites s ON s.id=ia.site_id "
            "WHERE ia.site_id=? ORDER BY ia.hostname,ia.ip_address",
            (site_id,),
        ).fetchall()
    since = time.time() - 30 * 86400
    if site_id is None:
        snapshots = conn.execute(
            "SELECT ts,device_count,online_count,open_port_count,traffic_bps FROM operational_snapshots "
            "WHERE ts>=? ORDER BY ts",
            (since,),
        ).fetchall()
    else:
        snapshots = conn.execute(
            "SELECT ts,device_count,online_count,open_port_count,traffic_bps FROM operational_snapshots "
            "WHERE ts>=? AND site_id=? ORDER BY ts",
            (since, site_id),
        ).fetchall()
    alerts = conn.execute(
        "SELECT ts,level,message,source FROM alerts WHERE ts>=? ORDER BY ts DESC LIMIT 200",
        (since,),
    ).fetchall()
    return {
        "generated_at": time.time(),
        "site_id": site_id,
        "assets": [
            {
                "asset_id": row[0],
                "hostname": row[1],
                "ip": row[2],
                "mac": row[3],
                "type": row[4],
                "status": row[5],
                "last_seen": row[6],
                "site": row[7],
                "data_source": "inventory_assets",
            }
            for row in assets
        ],
        "snapshots": [
            {
                "ts": row[0],
                "devices": row[1],
                "online": row[2],
                "open_ports": row[3],
                "traffic_bps": row[4],
                "data_source": "operational_snapshots",
            }
            for row in snapshots
        ],
        "alerts": [{"ts": row[0], "level": row[1], "message": row[2], "source": row[3] or "alerts"} for row in alerts],
    }


def build_report_file(data: dict[str, Any], report_format: str) -> tuple[bytes, str, str]:
    if report_format == "xlsx":
        from openpyxl import Workbook

        workbook = Workbook()
        assets_sheet = workbook.active
        assets_sheet.title = "Envanter"
        headers = ["Asset ID", "Hostname", "IP", "MAC", "Tür", "Durum", "Son Görülme", "Site", "Veri Kaynağı"]
        assets_sheet.append(headers)
        for item in data["assets"]:
            assets_sheet.append(
                [
                    item["asset_id"],
                    item["hostname"],
                    item["ip"],
                    item["mac"],
                    item["type"],
                    item["status"],
                    item["last_seen"],
                    item["site"],
                    item["data_source"],
                ]
            )
        history_sheet = workbook.create_sheet("Geçmiş")
        history_sheet.append(["Zaman", "Cihaz", "Çevrimiçi", "Açık Port", "Trafik bps", "Veri Kaynağı"])
        for item in data["snapshots"]:
            history_sheet.append(
                [
                    item["ts"],
                    item["devices"],
                    item["online"],
                    item["open_ports"],
                    item["traffic_bps"],
                    item["data_source"],
                ]
            )
        output = BytesIO()
        workbook.save(output)
        return (
            output.getvalue(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "netmon-report.xlsx",
        )
    if report_format == "pdf":
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        output = BytesIO()
        pdf = canvas.Canvas(output, pagesize=A4)
        width, height = A4
        y = height - 50
        pdf.setTitle("NetMon Operasyon Raporu")
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(40, y, "NetMon Operasyon Raporu")
        y -= 28
        pdf.setFont("Helvetica", 10)
        pdf.drawString(
            40,
            y,
            f"Envanter kaydi: {len(data['assets'])} | Snapshot: {len(data['snapshots'])} | Alarm: {len(data['alerts'])}",
        )
        y -= 24
        pdf.drawString(40, y, "Veri kaynaklari: inventory_assets, operational_snapshots, alerts")
        for item in data["assets"][:45]:
            y -= 15
            if y < 45:
                pdf.showPage()
                pdf.setFont("Helvetica", 9)
                y = height - 45
            line = f"{item['hostname'] or '-'} | {item['ip'] or '-'} | {item['type'] or '-'} | {item['status'] or '-'} | {item['site'] or '-'}"
            pdf.drawString(40, y, line[:105])
        pdf.save()
        return output.getvalue(), "application/pdf", "netmon-report.pdf"
    raise ValueError("Rapor formatı pdf veya xlsx olmalıdır.")


def _send_email(
    settings: dict[str, Any], recipient: str, subject: str, body: str, attachment: tuple[bytes, str, str] | None = None
) -> None:
    host = str(settings.get("smtp_host") or "").strip()
    if not host or not recipient:
        raise RuntimeError("SMTP sunucusu ve alıcı yapılandırılmalıdır.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.get("smtp_from") or settings.get("smtp_username") or "netmon@localhost"
    message["To"] = recipient
    message.set_content(body)
    if attachment:
        content, media_type, filename = attachment
        main_type, sub_type = media_type.split("/", 1)
        message.add_attachment(content, maintype=main_type, subtype=sub_type, filename=filename)
    port = int(settings.get("smtp_port") or 587)
    use_tls = str(settings.get("smtp_tls", True)).lower() in {"1", "true", "yes", "on"}
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        username = str(settings.get("smtp_username") or "")
        password = str(settings.get("smtp_password") or "")
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


def deliver_events(conn: sqlite3.Connection, events: list[dict[str, Any]], settings: dict[str, Any]) -> None:
    for event in events:
        channels_row = conn.execute("SELECT channels_json FROM alert_rules WHERE id=?", (event["rule_id"],)).fetchone()
        channels = json.loads(channels_row[0] or "[]") if channels_row else []
        delivery: dict[str, Any] = {}
        if "webhook" in channels:
            try:
                url = str(settings.get("webhook_url") or "").strip()
                if not url.startswith(("https://", "http://")):
                    raise RuntimeError("Webhook URL yapılandırılmamış.")
                payload = json.dumps(
                    {"text": event["message"], "level": event["level"], "evidence": event["evidence"]},
                    ensure_ascii=False,
                ).encode("utf-8")
                request = Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(request, timeout=10) as response:  # nosec B310 - URL is admin-configured and validated.
                    delivery["webhook"] = {"ok": 200 <= response.status < 300, "status": response.status}
            except Exception as exc:
                delivery["webhook"] = {"ok": False, "error": type(exc).__name__}
        if "email" in channels:
            try:
                _send_email(
                    settings,
                    str(settings.get("notification_email") or ""),
                    f"NetMon alarmı: {event['name']}",
                    event["message"] + "\n\nKanıt: " + json.dumps(event["evidence"], ensure_ascii=False, indent=2),
                )
                delivery["email"] = {"ok": True}
            except Exception as exc:
                delivery["email"] = {"ok": False, "error": type(exc).__name__}
        conn.execute("UPDATE alert_events SET delivery_json=? WHERE id=?", (json.dumps(delivery), event["id"]))
    conn.commit()


def run_due_reports(conn: sqlite3.Connection, settings: dict[str, Any], now: float | None = None) -> int:
    now = now or time.time()
    rows = conn.execute(
        "SELECT id,format,interval_seconds,recipient,site_id FROM report_schedules "
        "WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at",
        (now,),
    ).fetchall()
    completed = 0
    for schedule_id, report_format, interval, recipient, site_id in rows:
        status = "generated"
        error = None
        try:
            report = build_report_file(operations_report_data(conn, site_id), report_format)
            if recipient:
                _send_email(settings, recipient, "NetMon zamanlanmış raporu", "Rapor ekte sunulmuştur.", report)
                status = "emailed"
        except Exception as exc:
            status = "failed"
            error = f"{type(exc).__name__}: {str(exc)[:200]}"
        conn.execute(
            "INSERT INTO report_runs(schedule_id,ts,format,status,recipient,error) VALUES(?,?,?,?,?,?)",
            (schedule_id, now, report_format, status, recipient, error),
        )
        conn.execute(
            "UPDATE report_schedules SET last_run_at=?,next_run_at=?,updated_at=? WHERE id=?",
            (now, now + interval, now, schedule_id),
        )
        completed += 1
    conn.commit()
    return completed
