from backend.server import _analyst_correlation, _review_priority, _analyst_device

def test_correlation_and_priority():
    d={"ip":"192.168.1.10","hostname":"SW-01","mac":"AA:BB:CC:DD:EE:FF","vendor":"Cisco","status":"online","type":"switch","classification":{"confidence":0.95,"evidence":["SNMP sysDescr","LLDP neighbor"],"open_ports":[22,443]},"discovery_sources":["ARP","SNMP","LLDP"]}
    a=_analyst_device(d)
    c=_analyst_correlation(d)
    p=_review_priority(a)
    assert c["score"] >= 70
    assert p["level"] in {"low","medium"}
    assert a["device_type"] == "switch"
