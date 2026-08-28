import sqlite3

import pytest

import server
from conftest import persistent_test_client


@pytest.fixture()
def isolated_server(tmp_path, monkeypatch):
    db_path = tmp_path / "netmon-test.db"
    password_path = tmp_path / "initial-admin.txt"
    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "INITIAL_PASSWORD_PATH", password_path)
    server._devices_cache.update({"ts": 0, "data": [], "error": None, "scan_status": "idle"})
    server._local_wmi_cache.update({"ts": 0, "data": None})
    server.init_db()
    with persistent_test_client(server.app) as client:
        yield client, db_path, password_path


def _bootstrap_admin(client, password_path):
    initial_password = password_path.read_text(encoding="utf-8").splitlines()[1]
    login = client.post("/api/auth/login", json={"username": "admin", "password": initial_password})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post(
        "/api/auth/change-password",
        headers=headers,
        json={"current_password": initial_password, "new_password": "New-Company-Pass-2026!"},
    )
    return headers


def _seed_asset(dev=None, inv=None, source="Agentless Discovery"):
    dev = dev or {
        "ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:20", "hostname": "printer-01",
        "vendor": "Example", "status": "online", "type": "printer",
    }
    inv = inv or {
        "status": "Success", "ip_address": dev["ip"], "mac_address": dev["mac"],
        "computer_name": dev["hostname"], "inventory_source": source,
    }
    server._sync_normalized_inventory(dev, inv, source)


# ---------- Envanter (inventory) uçları ----------

def test_inventory_summary_reflects_seeded_assets(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _seed_asset()
    response = client.get("/api/inventory/summary", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["online"] == 1


def test_inventory_assets_list_and_detail_round_trip(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _seed_asset()
    listing = client.get("/api/inventory/assets", headers=headers)
    assert listing.status_code == 200
    assets = listing.json()["assets"]
    assert len(assets) == 1
    asset_id = assets[0]["asset_id"]
    assert assets[0]["hostname"] == "printer-01"

    detail = client.get(f"/api/inventory/assets/{asset_id}", headers=headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["hostname"] == "printer-01"
    assert "hardware" in body and "interfaces" in body and "software" in body and "history" in body


def test_inventory_assets_limit_is_clamped(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    over = client.get("/api/inventory/assets?limit=999999", headers=headers)
    assert over.status_code == 200
    under = client.get("/api/inventory/assets?limit=0", headers=headers)
    assert under.status_code == 200


def test_asset_metadata_defaults_when_never_set(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _seed_asset()
    asset_id = client.get("/api/inventory/assets", headers=headers).json()["assets"][0]["asset_id"]
    meta = client.get(f"/api/inventory/assets/{asset_id}/metadata", headers=headers)
    assert meta.status_code == 200
    assert meta.json() == {"asset_id": asset_id}


def test_asset_metadata_update_persists_and_merges_partial_fields(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _seed_asset()
    asset_id = client.get("/api/inventory/assets", headers=headers).json()["assets"][0]["asset_id"]

    first = client.put(
        f"/api/inventory/assets/{asset_id}/metadata",
        headers=headers,
        json={"owner": "IT Departmanı", "location": "Kat 3"},
    )
    assert first.status_code == 200

    second = client.put(
        f"/api/inventory/assets/{asset_id}/metadata",
        headers=headers,
        json={"owner": "Muhasebe"},
    )
    assert second.status_code == 200

    meta = client.get(f"/api/inventory/assets/{asset_id}/metadata", headers=headers).json()
    assert meta["owner"] == "Muhasebe"
    assert meta["location"] == "Kat 3"  # önceki değer korunmalı, silinmemeli


def test_network_scopes_only_lists_private_ranges(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    import ipaddress
    monkeypatch.setattr(server.diag, "_local_ipv4_networks", lambda: [ipaddress.ip_network("192.168.1.0/24")])
    response = client.get("/api/network/scopes", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["scopes"] == ["192.168.1.0/24"]
    assert body["policy"] == "local-private-networks-only"


def test_network_scopes_failure_returns_empty_not_crash(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)

    def boom():
        raise RuntimeError("interface enumeration failed")

    monkeypatch.setattr(server.diag, "_local_ipv4_networks", boom)
    response = client.get("/api/network/scopes", headers=headers)
    assert response.status_code == 200
    assert response.json()["scopes"] == []


def test_inventory_scan_runs_empty_when_none_recorded(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/inventory/scans", headers=headers)
    assert response.status_code == 200
    assert response.json()["scans"] == []


# ---------- Analyst raporlama uçları ----------

def test_analyst_summary_with_no_devices_does_not_crash(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/analyst/summary", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["inventory"]["total"] == 0


def test_analyst_devices_and_correlation_reflect_cache(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [{
            "ip": "192.168.1.30", "mac": "AA:BB:CC:DD:EE:30", "hostname": "srv-db-01",
            "status": "online", "type": "server", "classification_source": "auto",
            "classification": {"confidence": 0.8, "open_ports": [3306], "evidence": []},
            "discovery_sources": ["arp", "dns"],
        }],
        "error": None, "scan_status": "idle",
    })
    devices = client.get("/api/analyst/devices", headers=headers)
    assert devices.status_code == 200
    assert len(devices.json()["devices"]) == 1

    correlation = client.get("/api/analyst/correlation", headers=headers)
    assert correlation.status_code == 200
    result = correlation.json()["devices"][0]
    assert "correlation" in result and "review_priority" in result


def test_analyst_exposure_does_not_fabricate_vulnerability_claims(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [{"ip": "192.168.1.40", "status": "online", "type": "server",
                   "classification": {"open_ports": [445, 3389]}}],
        "error": None, "scan_status": "idle",
    })
    response = client.get("/api/analyst/exposure", headers=headers)
    assert response.status_code == 200


def test_analyst_snapshot_requires_admin_role(isolated_server):
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    client.post("/api/admin/users", headers=admin_headers, json={
        "username": "viewer.user", "password": "Temporary-Pass-2026!", "role": "user"
    })
    login = client.post("/api/auth/login", json={"username": "viewer.user", "password": "Temporary-Pass-2026!"})
    user_headers = {"Authorization": f"Bearer {login.json()['token']}"}
    client.post(
        "/api/auth/change-password", headers=user_headers,
        json={"current_password": "Temporary-Pass-2026!", "new_password": "Viewer-New-Pass-2026!"},
    )
    denied = client.post("/api/analyst/snapshot", headers=user_headers)
    assert denied.status_code == 403
    allowed = client.post("/api/analyst/snapshot", headers=admin_headers)
    assert allowed.status_code == 200


def test_analyst_trends_records_snapshot_history(isolated_server, db_path=None):
    client, db_path, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    client.post("/api/analyst/snapshot", headers=headers)
    client.post("/api/analyst/snapshot", headers=headers)
    response = client.get("/api/analyst/trends", headers=headers)
    assert response.status_code == 200
    points = response.json()["points"]
    assert len(points) == 2
    # En eski kayıt en başta olmalı (grafikte kronolojik sıra için)
    assert points[0]["created_at"] <= points[1]["created_at"]


def test_analyst_report_is_plain_text_attachment(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    response = client.get("/api/analyst/report", headers=headers)
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    assert "NETMON NETWORK ANALYST RAPORU" in response.text


def test_analyst_topology_evidence_only_uses_real_neighbor_data(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [{
            "ip": "192.168.1.1", "hostname": "core-switch-01", "status": "online",
            "lldp_neighbors": [{"ip": "192.168.1.2", "local_port": "Gi0/1"}],
        }],
        "error": None, "scan_status": "idle",
    })
    response = client.get("/api/analyst/topology-evidence", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["evidence_only"] is True
    assert body["edges"] == [{"source": "core-switch-01", "target": "192.168.1.2", "port": "Gi0/1", "protocol": "LLDP"}]


def test_analyst_baseline_scores_missing_hostname_lower(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    server._devices_cache.update({
        "ts": 0,
        "data": [
            {"ip": "192.168.1.50", "hostname": "known-pc", "status": "online",
             "classification": {"confidence": 0.9}, "type": "computer"},
            {"ip": "192.168.1.51", "hostname": None, "status": "unknown",
             "classification": {"confidence": 0.1}, "type": "unknown"},
        ],
        "error": None, "scan_status": "idle",
    })
    response = client.get("/api/analyst/baseline", headers=headers)
    assert response.status_code == 200
    devices = {d["ip"]: d["score"] for d in response.json()["devices"]}
    assert devices["192.168.1.50"] > devices["192.168.1.51"]


def test_academy_modules_and_quiz_flow(isolated_server):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    modules = client.get("/api/academy/modules", headers=headers)
    assert modules.status_code == 200
    assert len(modules.json()["modules"]) > 0

    detail = client.get("/api/academy/modules/ports", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["title"] == "Portlar"

    missing = client.get("/api/academy/modules/does-not-exist", headers=headers)
    assert missing.status_code == 404

    correct = client.post("/api/academy/quiz", headers=headers, json={"module_id": "ip", "answer": 0})
    assert correct.status_code == 200
    assert correct.json()["correct"] is True

    wrong = client.post("/api/academy/quiz", headers=headers, json={"module_id": "ip", "answer": 1})
    assert wrong.status_code == 200
    assert wrong.json()["correct"] is False


# ---------- Başlangıçta "sıfırdan" görünme sorunu ----------

def test_startup_loads_last_known_devices_from_db_not_empty(isolated_server):
    """Regresyon: uygulama her açılışta _devices_cache'i boş başlatıyordu,
    ilk tarama bitene kadar arayüz cihaz listesini sıfırdan gösteriyordu."""
    client, _, _ = isolated_server
    _seed_asset()
    assert server._devices_cache["data"] == []  # henüz yüklenmedi

    server._load_last_known_devices_into_cache()

    assert len(server._devices_cache["data"]) == 1
    device = server._devices_cache["data"][0]
    assert device["ip"] == "192.168.1.20"
    assert device["hostname"] == "printer-01"
    assert device["stale"] is True  # tarama henüz doğrulamadı, bayat veri olarak işaretli


def test_startup_with_empty_inventory_leaves_cache_empty(isolated_server):
    client, _, _ = isolated_server
    server._load_last_known_devices_into_cache()
    assert server._devices_cache["data"] == []


def test_startup_cache_load_failure_does_not_crash(isolated_server, monkeypatch):
    client, _, _ = isolated_server

    def boom():
        raise sqlite3.OperationalError("db locked")

    monkeypatch.setattr(server, "db_conn", boom)
    server._load_last_known_devices_into_cache()  # exception fırlatmamalı
    assert server._devices_cache["data"] == []


# ---------- /api/tools/network-cmd: yeni eklenen komutlar ----------

def _fake_subprocess_run(monkeypatch, stdout="ok", returncode=0):
    calls = []

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    return calls


def test_route_print_and_nbtstat_n_need_no_target(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    calls = _fake_subprocess_run(monkeypatch)

    route_resp = client.post("/api/tools/network-cmd", headers=headers, json={"action": "route_print"})
    assert route_resp.status_code == 200
    assert calls[-1] == ["route", "print"]

    nbtstat_resp = client.post("/api/tools/network-cmd", headers=headers, json={"action": "nbtstat_n"})
    assert nbtstat_resp.status_code == 200
    assert calls[-1] == ["nbtstat", "-n"]


def test_nbtstat_a_and_pathping_require_valid_target(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    calls = _fake_subprocess_run(monkeypatch)

    nbtstat_a = client.post("/api/tools/network-cmd", headers=headers, json={"action": "nbtstat_a", "target": "192.168.1.5"})
    assert nbtstat_a.status_code == 200
    assert calls[-1] == ["nbtstat", "-A", "192.168.1.5"]

    pathping = client.post("/api/tools/network-cmd", headers=headers, json={"action": "pathping", "target": "8.8.8.8"})
    assert pathping.status_code == 200
    assert calls[-1] == ["pathping", "-n", "-q", "4", "8.8.8.8"]

    missing_target = client.post("/api/tools/network-cmd", headers=headers, json={"action": "pathping", "target": ""})
    assert missing_target.status_code == 400


def test_target_required_commands_reject_shell_metacharacters(isolated_server, monkeypatch):
    """Doğruluk/güvenlik: hedef alanına flag/özel karakter enjekte edilirse reddedilmeli."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _fake_subprocess_run(monkeypatch)

    for bad_target in ("; rm -rf /", "8.8.8.8 && whoami", "-n 999", "$(id)"):
        response = client.post("/api/tools/network-cmd", headers=headers, json={"action": "pathping", "target": bad_target})
        assert response.status_code == 400, f"beklenmedik kabul: {bad_target!r}"


def test_nslookup_with_record_type_builds_correct_command(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    calls = _fake_subprocess_run(monkeypatch)

    response = client.post("/api/tools/network-cmd", headers=headers, json={
        "action": "nslookup", "target": "example.com", "record_type": "mx"
    })
    assert response.status_code == 200
    assert calls[-1] == ["nslookup", "-type=MX", "example.com"]


def test_nslookup_rejects_unknown_record_type(isolated_server, monkeypatch):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    _fake_subprocess_run(monkeypatch)

    response = client.post("/api/tools/network-cmd", headers=headers, json={
        "action": "nslookup", "target": "example.com", "record_type": "DROP"
    })
    assert response.status_code == 400


def test_nslookup_without_record_type_still_works_as_before(isolated_server, monkeypatch):
    """Regresyon: mevcut nslookup davranışı (record_type olmadan) bozulmamalı."""
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    calls = _fake_subprocess_run(monkeypatch)

    response = client.post("/api/tools/network-cmd", headers=headers, json={"action": "nslookup", "target": "example.com"})
    assert response.status_code == 200
    assert calls[-1] == ["nslookup", "example.com"]


def test_route_print_and_nbtstat_do_not_require_admin_role(isolated_server, monkeypatch):
    """Bunlar salt-okunur teşhis komutları; sadece ipconfig release/renew/flushdns admin-only olmalı."""
    client, _, password_path = isolated_server
    admin_headers = _bootstrap_admin(client, password_path)
    created = client.post("/api/admin/users", headers=admin_headers, json={
        "username": "readonly.viewer", "password": "Temporary-Pass-2026!", "role": "user"
    })
    assert created.status_code == 200
    login = client.post("/api/auth/login", json={"username": "readonly.viewer", "password": "Temporary-Pass-2026!"})
    user_headers = {"Authorization": f"Bearer {login.json()['token']}"}
    client.post("/api/auth/change-password", headers=user_headers, json={
        "current_password": "Temporary-Pass-2026!", "new_password": "Viewer-New-Pass-2026!"
    })
    _fake_subprocess_run(monkeypatch)
    assert client.post("/api/tools/network-cmd", headers=user_headers, json={"action": "route_print"}).status_code == 200
    assert client.post("/api/tools/network-cmd", headers=user_headers, json={"action": "nbtstat_n"}).status_code == 200
    assert client.post("/api/tools/network-cmd", headers=user_headers, json={"action": "flushdns"}).status_code == 403
