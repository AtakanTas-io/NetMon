import asyncio
import logging
from typing import Any, Dict, List

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        nextCmd,
    )

    HAS_PYSNMP = True
except ImportError:
    nextCmd = None
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            walk_cmd,
        )

        HAS_PYSNMP = True
    except ImportError:
        HAS_PYSNMP = False

logger = logging.getLogger("netmon.snmp_mapper")

# Cache to store the mac to switch port mapping: { "mac": {"switch_ip": "1.2.3.4", "port": "GigabitEthernet1/0/1"} }
_mac_to_switch_port: dict[str, dict[str, str]] = {}


async def _walk_async(ip: str, community: str) -> list[tuple[Any, Any, Any, Any]]:
    target = await UdpTransportTarget.create((ip, 161), timeout=2.0, retries=1)
    rows = []
    async for row in walk_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.17.4.3.1.2")),
        lexicographicMode=False,
    ):
        rows.append(row)
    return rows


def get_snmp_community():
    try:
        from server import _settings_cache

        if "snmp_community" in _settings_cache:
            val = _settings_cache["snmp_community"]
            if val and str(val).startswith("dpapi:"):
                import base64

                import win32crypt

                enc = base64.b64decode(val[6:])
                return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1].decode("utf-8")
            return val
    except Exception:
        pass
    return "public"


def fetch_switch_mac_table(ip: str, community: str) -> Dict[str, str]:
    """Fetches dot1dTpFdbPort and maps MAC address (hex string) to Port number"""
    if not HAS_PYSNMP:
        return {}

    mac_to_port = {}

    try:
        if nextCmd is None:
            iterator = asyncio.run(_walk_async(ip, community))
        else:
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=2.0, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.17.4.3.1.2")),
                lexicographicMode=False,
            )

        for errorIndication, errorStatus, _errorIndex, varBinds in iterator:
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                oid = varBind[0]
                port = int(varBind[1])

                # OID is 1.3.6.1.2.1.17.4.3.1.2.X.X.X.X.X.X (where X is decimal MAC bytes)
                mac_bytes = oid.asTuple()[-6:]
                mac_str = ":".join(f"{b:02x}" for b in mac_bytes).upper()
                mac_to_port[mac_str] = str(port)

    except Exception as e:
        logger.debug(f"SNMP MAC table fetch failed for {ip}: {e}")

    return mac_to_port


def update_switch_mac_tables(devices: List[Dict]):
    """
    Called after wave 3 in scanning.
    Identifies switches (devices with port 161 open or type=switch),
    fetches their MAC tables, and updates known_devices with physical port mappings.
    """
    if not HAS_PYSNMP:
        return

    community = get_snmp_community()

    switches = [
        d
        for d in devices
        if d.get("type") in ("switch", "router") or 161 in (d.get("classification", {}).get("open_ports") or [])
    ]

    if not switches:
        return

    global _mac_to_switch_port

    for switch in switches:
        ip = switch.get("ip")
        if not ip:
            continue

        mac_table = fetch_switch_mac_table(ip, community)
        if mac_table:
            switch["type"] = "switch"  # Upgrade type if it was unknown
            for mac, port in mac_table.items():
                _mac_to_switch_port[mac] = {"switch_ip": ip, "port": port}

    if not _mac_to_switch_port:
        return

    try:
        from server import db_conn

        conn = db_conn()
        for dev in devices:
            mac = str(dev.get("mac") or "").upper()
            if mac in _mac_to_switch_port:
                sw_ip = _mac_to_switch_port[mac]["switch_ip"]
                sw_port = _mac_to_switch_port[mac]["port"]

                dev["switch_ip"] = sw_ip
                dev["switch_port"] = sw_port

                conn.execute("UPDATE known_devices SET switch_ip=?, switch_port=? WHERE mac=?", (sw_ip, sw_port, mac))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update switch ports in DB: {e}")
