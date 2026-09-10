import json
import time

import pytest
import server
from test_server_security import _bootstrap_admin
from test_server_security import isolated_server as isolated_server

from backend.core.search_engine import SearchQueryError, compile_query, document_matches


def test_query_language_supports_boolean_cidr_range_and_numeric_filters():
    document = {
        "ip": "10.20.1.25",
        "hostname": "SW-CORE-01",
        "device_type": "switch",
        "status": "online",
        "latency": 42,
        "packet_loss": 3.5,
        "open_ports": [22, 443],
        "last_seen": time.time() - 30,
    }

    assert document_matches(document, compile_query("ip:10.20.1.0/24 AND type:switch AND NOT status:offline"))
    assert document_matches(document, compile_query("ip:10.20.1.20-30 AND (port:443 OR port:8443)"))
    assert document_matches(document, compile_query("latency:>40 loss:>=3 last_seen:<1h"))
    assert not document_matches(document, compile_query("latency:<10 OR status:offline"))


def test_regex_is_scoped_and_rejects_expensive_constructs():
    document = {"hostname": "SW-CORE-01", "config_text": "hostname SW-CORE-01"}

    assert document_matches(document, compile_query(r"hostname:/^SW-CORE-\d{2}$/"))
    assert not document_matches(document, compile_query(r"hostname:/^DB-/"))
    with pytest.raises(SearchQueryError, match="iç içe nicelik"):
        compile_query(r"hostname:/(a+)+$/")
    with pytest.raises(SearchQueryError, match="Desteklenmeyen alan"):
        compile_query("secret:value")


def _seed_search_sources(db_path):
    now = time.time()
    with server.sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO device_configs(ip,hostname,device_type,config_text,config_hash,version_label,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                "10.20.0.10",
                "SW-CORE-01",
                "switch",
                "hostname SW-CORE-01\naccess-list 101 permit ip any any",
                "hash1",
                "v1",
                now,
            ),
        )
        conn.execute(
            "INSERT INTO device_configs(ip,hostname,device_type,config_text,config_hash,version_label,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("10.20.0.99", "", "unknown", "hostname ARCHIVE-ONLY\nntp server 10.0.0.1", "hash2", "archive", now - 60),
        )
        conn.execute(
            "INSERT INTO ssl_certificates(ip,hostname,issuer,valid_to,days_left,last_checked) VALUES(?,?,?,?,?,?)",
            ("10.20.0.10", "SW-CORE-01", "Test CA", "2026-09-10", 5, now),
        )
        conn.execute(
            "INSERT INTO assurance_scan_runs(kind,started_at,finished_at,requested_by,status,target_count,finding_count,result_json) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                "cve_correlation",
                now,
                now,
                "admin",
                "completed",
                1,
                1,
                json.dumps([{"ip": "10.20.0.10", "cve_id": "CVE-2023-38408"}]),
            ),
        )


def test_search_api_combines_discovery_security_and_ncm_sources(isolated_server):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _seed_search_sources(db_path)
    server._devices_cache["data"] = [
        {
            "ip": "10.20.0.10",
            "mac": "AA:BB:CC:DD:EE:01",
            "hostname": "SW-CORE-01",
            "vendor": "Cisco",
            "type": "switch",
            "status": "online",
            "latency": 12,
            "packet_loss": 0,
            "last_seen": time.time(),
            "last_network": "10.20.0.0/24",
            "switch_port": "Gi0/1",
            "classification": {"open_ports": [22, 443]},
        },
        {
            "ip": "10.20.0.11",
            "mac": "AA:BB:CC:DD:EE:02",
            "hostname": "PC-01",
            "type": "computer",
            "status": "offline",
            "latency": 90,
            "packet_loss": 10,
            "last_seen": time.time() - 7200,
            "classification": {"open_ports": [445]},
        },
    ]

    response = client.get(
        "/api/search",
        headers=headers,
        params={"q": 'type:switch AND port:443 AND cve:CVE-2023-38408 AND config:"access-list 101"'},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["index"] == {"documents": 3, "source": "search_documents"}
    assert body["results"][0]["hostname"] == "SW-CORE-01"
    assert {"network", "security", "configuration"} <= set(body["results"][0]["categories"])
    assert "config_text" not in body["results"][0]

    ranged = client.get(
        "/api/search",
        headers=headers,
        params={"q": "ip:10.20.0.1-20 AND NOT status:offline", "page": 1, "page_size": 1},
    ).json()
    assert ranged["total"] == 1
    assert ranged["page_size"] == 1

    archived = client.get("/api/search", headers=headers, params={"q": "config:ARCHIVE-ONLY"}).json()
    assert archived["total"] == 1
    assert archived["results"][0]["ip"] == "10.20.0.99"


def test_search_validation_saved_search_and_export_round_trip(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache["data"] = [
        {
            "ip": "10.0.0.5",
            "hostname": "edge",
            "type": "router",
            "status": "online",
            "classification": {"open_ports": [22]},
        }
    ]

    invalid = client.get("/api/search", headers=headers, params={"q": "hostname:/(a+)+$/"})
    assert invalid.status_code == 400
    assert invalid.json()["code"] == "BAD_REQUEST"

    saved = client.post(
        "/api/search/saved",
        headers=headers,
        json={"name": "Çekirdek cihazlar", "query": "type:router OR type:switch", "sort": "hostname", "order": "asc"},
    )
    assert saved.status_code == 200
    saved_id = saved.json()["id"]
    listed = client.get("/api/search/saved", headers=headers).json()["searches"]
    assert listed[0]["name"] == "Çekirdek cihazlar"

    exported = client.get("/api/search/export", headers=headers, params={"q": "type:router", "format": "csv"})
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "edge" in exported.text

    assert client.delete(f"/api/search/saved/{saved_id}", headers=headers).status_code == 200
    assert client.get("/api/search/saved", headers=headers).json()["searches"] == []
