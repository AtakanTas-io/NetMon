import socket
import struct
import threading
import time
import logging
from typing import Callable, Iterable, Optional

logger = logging.getLogger("netmon.dhcp")

_stop_event = threading.Event()
_dhcp_thread = None
_authorized_provider: Optional[Callable[[], Iterable[str]]] = None
_monitor_state = {"running": False, "error": None, "last_event_ts": None, "last_source_ip": None}


def configure_authorized_dhcp_provider(provider: Callable[[], Iterable[str]]):
    """Server ayar katmanını bu modüle gevşek bağlı bir callback ile bağla."""
    global _authorized_provider
    _authorized_provider = provider


def get_dhcp_monitor_status():
    return {**_monitor_state, "thread_alive": bool(_dhcp_thread and _dhcp_thread.is_alive())}

def get_authorized_dhcp():
    if _authorized_provider is None:
        return []
    try:
        values = _authorized_provider() or []
        return sorted({str(value).strip() for value in values if str(value).strip()})
    except Exception as exc:
        logger.warning("Yetkili DHCP listesi alınamadı: %s", exc)
        return []

def _dhcp_monitor_loop():
    # Bind to UDP 68 to listen for BOOTP replies
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # In Windows, we can use SO_BROADCAST to listen to broadcasts too
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("0.0.0.0", 68))
        s.settimeout(2.0)
    except Exception as e:
        logger.error(f"Failed to bind DHCP monitor on UDP 68: {e}")
        _monitor_state.update(running=False, error=str(e)[:300])
        return

    logger.info("DHCP monitor started on UDP 68")
    _monitor_state.update(running=True, error=None)
    
    while not _stop_event.is_set():
        try:
            data, addr = s.recvfrom(4096)
            source_ip = addr[0]
            
            # BOOTP messages start with op (1 byte) where 2 = BOOTREPLY
            if data and data[0] == 2:
                # This is a DHCP offer / ACK from a server
                auth_servers = get_authorized_dhcp()
                _monitor_state.update(last_event_ts=time.time(), last_source_ip=source_ip)
                
                # We need to extract the actual server IP from the DHCP options (Option 54)
                # But as a fallback we can use the source IP
                if source_ip not in auth_servers and auth_servers:
                    # Rogue DHCP detected!
                    logger.warning(f"Rogue DHCP offer detected from {source_ip}")
                    
                    try:
                        from server import db_conn, manager
                        conn = db_conn()
                        msg = f"Rogue DHCP / Yabanci Ag Saglayicisi tespit edildi: {source_ip}"
                        
                        # Check if we already alerted in the last 10 minutes to avoid spam
                        row = conn.execute("SELECT ts FROM alerts WHERE message=? ORDER BY ts DESC LIMIT 1", (msg,)).fetchone()
                        now = time.time()
                        if not row or (now - row[0]) > 600:
                            conn.execute("INSERT INTO alerts (ts, level, message) VALUES (?, ?, ?)", (now, "critical", msg))
                            conn.commit()
                            manager.broadcast_threadsafe({"type": "alert", "ts": now, "level": "critical", "message": msg, "simulated": False})
                        conn.close()
                    except Exception as e:
                        logger.error(f"DHCP Alert DB error: {e}")
        except socket.timeout:
            pass
        except Exception as e:
            if not _stop_event.is_set():
                logger.debug(f"DHCP monitor error: {e}")
            time.sleep(1)
            
    s.close()
    _monitor_state["running"] = False

def start_dhcp_monitor():
    global _dhcp_thread
    if _dhcp_thread is None or not _dhcp_thread.is_alive():
        _stop_event.clear()
        _dhcp_thread = threading.Thread(target=_dhcp_monitor_loop, daemon=True)
        _dhcp_thread.start()

def stop_dhcp_monitor():
    _stop_event.set()
    if _dhcp_thread:
        _dhcp_thread.join(timeout=3)
    _monitor_state["running"] = False
