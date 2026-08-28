from types import SimpleNamespace

from backend import snmp_switch_mapper as module


def _install_fake_snmp(monkeypatch, rows):
    monkeypatch.setattr(module, "HAS_PYSNMP", True)
    for name in ("SnmpEngine", "CommunityData", "UdpTransportTarget", "ContextData", "ObjectType", "ObjectIdentity"):
        monkeypatch.setattr(module, name, lambda *a, **k: object(), raising=False)
    monkeypatch.setattr(module, "nextCmd", lambda *a, **k: iter(rows), raising=False)


def test_fetch_returns_empty_when_dependency_missing(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", False)
    assert module.fetch_switch_mac_table("10.0.0.2", "public") == {}


def test_fetch_parses_mac_and_bridge_port(monkeypatch):
    oid = SimpleNamespace(asTuple=lambda: (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2, 170, 187, 204, 221, 238, 255))
    _install_fake_snmp(monkeypatch, [(None, None, None, [(oid, 7)])])
    assert module.fetch_switch_mac_table("10.0.0.2", "public") == {"AA:BB:CC:DD:EE:FF": "7"}


def test_fetch_stops_on_error_indication(monkeypatch):
    _install_fake_snmp(monkeypatch, [("timeout", None, None, [])])
    assert module.fetch_switch_mac_table("10.0.0.2", "public") == {}


def test_fetch_handles_iterator_exception(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", True)
    monkeypatch.setattr(module, "nextCmd", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad response")), raising=False)
    monkeypatch.setattr(module, "SnmpEngine", lambda: object(), raising=False)
    assert module.fetch_switch_mac_table("10.0.0.2", "public") == {}


def test_update_is_noop_without_dependency(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", False)
    devices = [{"ip": "10.0.0.2", "type": "switch"}]
    module.update_switch_mac_tables(devices)
    assert devices[0]["type"] == "switch"


def test_update_is_noop_without_switch_candidate(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", True)
    monkeypatch.setattr(module, "fetch_switch_mac_table", lambda *a: (_ for _ in ()).throw(AssertionError()))
    module.update_switch_mac_tables([{"ip": "10.0.0.9", "type": "computer"}])


def test_port_161_marks_candidate_as_switch(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", True)
    monkeypatch.setattr(module, "get_snmp_community", lambda: "secret")
    monkeypatch.setattr(module, "fetch_switch_mac_table", lambda ip, community: {"AA:BB:CC:DD:EE:FF": "5"})
    monkeypatch.setattr(module, "_mac_to_switch_port", {})
    fake_conn = SimpleNamespace(execute=lambda *a: None, commit=lambda: None, close=lambda: None)
    import server
    monkeypatch.setattr(server, "db_conn", lambda: fake_conn)
    devices = [
        {"ip": "10.0.0.2", "type": "unknown", "classification": {"open_ports": [161]}},
        {"ip": "10.0.0.3", "mac": "aa:bb:cc:dd:ee:ff", "type": "computer"},
    ]
    module.update_switch_mac_tables(devices)
    assert devices[0]["type"] == "switch"
    assert devices[1]["switch_port"] == "5"


def test_switch_without_ip_is_skipped(monkeypatch):
    monkeypatch.setattr(module, "HAS_PYSNMP", True)
    monkeypatch.setattr(module, "_mac_to_switch_port", {})
    monkeypatch.setattr(module, "fetch_switch_mac_table", lambda *a: (_ for _ in ()).throw(AssertionError()))
    module.update_switch_mac_tables([{"type": "switch"}])


def test_default_community_is_public_when_server_state_unavailable(monkeypatch):
    monkeypatch.delitem(__import__("sys").modules, "server", raising=False)
    assert module.get_snmp_community() in {"public", None}
