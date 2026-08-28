from types import SimpleNamespace

from backend import dhcp_monitor as module


def test_authorized_servers_are_empty_without_provider(monkeypatch):
    monkeypatch.setattr(module, "_authorized_provider", None)
    assert module.get_authorized_dhcp() == []


def test_authorized_servers_are_trimmed_sorted_and_deduplicated(monkeypatch):
    monkeypatch.setattr(module, "_authorized_provider", lambda: [" 10.0.0.2 ", "10.0.0.1", "10.0.0.2", ""])
    assert module.get_authorized_dhcp() == ["10.0.0.1", "10.0.0.2"]


def test_provider_failure_returns_empty_list(monkeypatch):
    monkeypatch.setattr(module, "_authorized_provider", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert module.get_authorized_dhcp() == []


def test_status_reports_dead_thread(monkeypatch):
    monkeypatch.setattr(module, "_dhcp_thread", None)
    assert module.get_dhcp_monitor_status()["thread_alive"] is False


def test_bind_failure_sets_monitor_error(monkeypatch):
    monkeypatch.setattr(module.socket, "socket", lambda *a: (_ for _ in ()).throw(OSError("permission denied")))
    module._dhcp_monitor_loop()
    assert module._monitor_state["running"] is False
    assert "permission denied" in module._monitor_state["error"]


def test_non_bootreply_packet_is_ignored(monkeypatch):
    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, *args):
            pass

        def settimeout(self, *args):
            pass

        def recvfrom(self, size):
            module._stop_event.set()
            return b"\x01ignored", ("10.0.0.3", 67)

        def close(self):
            pass

    module._stop_event.clear()
    monkeypatch.setattr(module.socket, "socket", lambda *a: FakeSocket())
    module._dhcp_monitor_loop()
    assert module._monitor_state["running"] is False


def test_authorized_bootreply_updates_last_source_without_alert(monkeypatch):
    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, *args):
            pass

        def settimeout(self, *args):
            pass

        def recvfrom(self, size):
            module._stop_event.set()
            return b"\x02offer", ("10.0.0.1", 67)

        def close(self):
            pass

    module._stop_event.clear()
    monkeypatch.setattr(module.socket, "socket", lambda *a: FakeSocket())
    monkeypatch.setattr(module, "_authorized_provider", lambda: ["10.0.0.1"])
    module._dhcp_monitor_loop()
    assert module._monitor_state["last_source_ip"] == "10.0.0.1"


def test_start_does_not_duplicate_live_thread(monkeypatch):
    live = SimpleNamespace(is_alive=lambda: True)
    monkeypatch.setattr(module, "_dhcp_thread", live)
    module.start_dhcp_monitor()
    assert module._dhcp_thread is live


def test_stop_sets_event_and_running_false(monkeypatch):
    thread = SimpleNamespace(join=lambda timeout: None)
    monkeypatch.setattr(module, "_dhcp_thread", thread)
    module._stop_event.clear()
    module._monitor_state["running"] = True
    module.stop_dhcp_monitor()
    assert module._stop_event.is_set()
    assert module._monitor_state["running"] is False


def test_rogue_offer_is_persisted_and_broadcast(monkeypatch):
    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def bind(self, *args):
            pass

        def settimeout(self, *args):
            pass

        def recvfrom(self, size):
            module._stop_event.set()
            return b"\x02offer", ("10.0.0.66", 67)

        def close(self):
            pass

    class FakeConnection:
        def __init__(self):
            self.executed = []
            self.committed = False

        def execute(self, sql, params):
            self.executed.append((sql, params))
            return SimpleNamespace(fetchone=lambda: None)

        def commit(self):
            self.committed = True

        def close(self):
            pass

    import server

    connection = FakeConnection()
    events = []
    monkeypatch.setattr(server, "db_conn", lambda: connection)
    monkeypatch.setattr(server.manager, "broadcast_threadsafe", events.append)
    monkeypatch.setattr(module.socket, "socket", lambda *a: FakeSocket())
    monkeypatch.setattr(module, "_authorized_provider", lambda: ["10.0.0.1"])
    module._stop_event.clear()
    module._dhcp_monitor_loop()
    assert connection.committed is True
    assert events[0]["level"] == "critical"


def test_start_creates_daemon_thread(monkeypatch):
    created = []

    class FakeThread:
        def __init__(self, target, daemon):
            created.append((target, daemon))
            self.started = False

        def is_alive(self):
            return False

        def start(self):
            self.started = True

    monkeypatch.setattr(module.threading, "Thread", FakeThread)
    monkeypatch.setattr(module, "_dhcp_thread", None)
    module.start_dhcp_monitor()
    assert created[0][1] is True
    assert module._dhcp_thread.started is True
