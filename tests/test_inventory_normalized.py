import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))
import server


def test_inventory_identity_survives_ip_change(tmp_path, monkeypatch):
    db = tmp_path / "inventory.db"
    monkeypatch.setattr(server, "DB_PATH", db)
    server.init_db()

    dev = {
        "ip": "192.168.1.10",
        "mac": "AA:BB:CC:DD:EE:01",
        "hostname": "PC-01",
        "vendor": "Test",
        "type": "computer",
        "status": "online",
    }
    inv = {
        "status": "Success",
        "ip_address": dev["ip"],
        "mac_address": dev["mac"],
        "computer_name": dev["hostname"],
        "inventory_source": "Agentless Discovery",
    }
    first = server._sync_normalized_inventory(dev, inv, "Agentless Discovery")

    changed = dict(dev, ip="192.168.1.20")
    second = server._sync_normalized_inventory(changed, dict(inv, ip_address=changed["ip"]), "Agentless Discovery")

    conn = sqlite3.connect(db)
    assert first == second
    assert conn.execute("SELECT COUNT(*) FROM inventory_assets").fetchone()[0] == 1
    assert conn.execute("SELECT ip_address FROM inventory_assets").fetchone()[0] == "192.168.1.20"
    assert conn.execute("SELECT COUNT(*) FROM inventory_history WHERE field_name='ip_address'").fetchone()[0] == 1
    conn.close()
