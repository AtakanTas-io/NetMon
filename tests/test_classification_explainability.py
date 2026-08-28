from netdiag_core import NetworkDiagnostics


def test_classification_has_explainable_scores():
    r = NetworkDiagnostics._guess_device_type(
        hostname="camera-lobby",
        vendor="Hikvision",
        open_ports={554},
        services=[{"service": "rtsp", "banner": "Hikvision RTSP"}],
    )
    assert r["type"] == "camera"
    assert 0.0 < r["confidence"] <= 0.99
    assert r["confidence_label"] in {"yüksek", "orta", "düşük"}
    assert r["score_breakdown"]
    assert r["score_breakdown"][0]["type"] == "camera"
    assert "margin" in r


def test_weak_single_vendor_does_not_claim_high_confidence_mobile():
    r = NetworkDiagnostics._guess_device_type(hostname="device-01", vendor="Apple")
    assert r["confidence"] < 0.80
