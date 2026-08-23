import socket
import struct
import threading
import time
import logging

logger = logging.getLogger("netmon.dhcp")

_stop_event = threading.Event()
_dhcp_thread = None

def get_authorized_dhcp():
    try:
        from server import _settings_cache
        val = _settings_cache.get("authorized_dhcp")
        if val:
            return str(val).split(",")
    except Exception:
        pass
    # If not configured, we just assume the default gateway is the only authorized DHCP
    try:
        from server import _last_status
        gw = _last_status.get("gateway")
        if gw:
            return [gw]
    except:
        pass
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
        return

    logger.info("DHCP monitor started on UDP 68")
    
    while not _stop_event.is_set():
        try:
            data, addr = s.recvfrom(4096)
            source_ip = addr[0]
            
            # BOOTP messages start with op (1 byte) where 2 = BOOTREPLY
            if data and data[0] == 2:
                # This is a DHCP offer / ACK from a server
                auth_servers = get_authorized_dhcp()
                
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
