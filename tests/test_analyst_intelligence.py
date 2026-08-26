from server import _analyst_device, _exposure_for_device, _inventory_completeness


def test_analyst_device_explains_classification_and_exposure():
    dev = {
        "ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:20", "hostname": "printer-01",
        "vendor": "Example", "status": "online", "type": "printer",
        "classification_source": "auto",
        "classification": {"confidence": 0.92, "open_ports": [80, 9100],
                           "evidence": [{"text": "hostname printer", "source": "dns"}]},
        "discovery_sources": ["arp", "dns", "nmap"],
    }
    a = _analyst_device(dev)
    assert a["device_type"] == "printer"
    assert a["confidence"] == 92
    assert a["completeness"] >= 20
    assert a["exposure"]["findings"]
    assert a["evidence"]


def test_unknown_device_gets_actionable_recommendation():
    dev = {"ip": "192.168.1.50", "status": "discovered", "type": "unknown", "classification": {"confidence": 0.2}}
    a = _analyst_device(dev)
    assert a["confidence"] == 20
    assert any("hostname" in x.lower() or "sınıf" in x.lower() for x in a["recommendations"])


def test_exposure_does_not_claim_vulnerability():
    dev = {"classification": {"open_ports": [445, 3389]}}
    e = _exposure_for_device(dev)
    assert e["risk"] == "medium"
    assert all("açık" in x["title"].lower() or "erişilebilir" in x["title"].lower() for x in e["findings"])
