import sqlite3
from unittest.mock import Mock

import pytest
import server
from test_server_security import isolated_server, _bootstrap_admin


@pytest.mark.parametrize("target", ["", "   ", "-help", "example.com;whoami", "host name"])
@pytest.mark.parametrize("endpoint", ["traceroute", "network-cmd"])
def test_diagnostic_targets_rejected_before_subprocess(isolated_server, monkeypatch, target, endpoint):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock()
    monkeypatch.setattr(server.subprocess, "run", run)
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post(f"/api/tools/{endpoint}", headers=headers, json={"target": target, "action": "nslookup"})
    assert response.status_code == 400
    run.assert_not_called()


@pytest.mark.parametrize("max_hops", [-100, 0, 65, 1000000])
def test_traceroute_hop_bounds(isolated_server, monkeypatch, max_hops):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock()
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post("/api/tools/traceroute", headers=headers, json={"max_hops": max_hops})
    assert response.status_code == 400
    run.assert_not_called()


@pytest.mark.parametrize("max_hops", [1, 64])
def test_traceroute_cleans_target_and_bounds_timeout(isolated_server, monkeypatch, max_hops):
    client, _, password_path = isolated_server
    headers = _bootstrap_admin(client, password_path)
    run = Mock(return_value="")
    monkeypatch.setattr(server.subprocess, "check_output", run)
    response = client.post("/api/tools/traceroute", headers=headers,
                           json={"target": " example.com/path ", "max_hops": max_hops})
    assert response.status_code == 200
    assert run.call_args.args[0][-1] == "example.com"
    assert run.call_args.kwargs["timeout"] == max_hops * 2 + 10
