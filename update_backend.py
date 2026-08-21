import re

with open('backend/server.py', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. Fix parsing in _discover_configured_devices
old_discovery = 'subnets = [item.strip() for item in (SUBNET_OVERRIDE or "").split(",") if item.strip()]'
new_discovery = 'subnets = [item.split("=")[0].strip() for item in (SUBNET_OVERRIDE or "").split(",") if item.strip()]'
c = c.replace(old_discovery, new_discovery)

# 2. Fix parsing in update_settings validation
old_val = '''        normalized = []
        for raw in raw_subnets:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                return f"Geçersiz subnet: {raw}"
            if not _is_allowed_inventory_network(network):
                return f"Yalnızca yerel/özel IPv4 subnetleri kullanılabilir: {raw}"
            if network.prefixlen < 16:
                return f"Çok geniş subnet desteklenmiyor (en geniş /16): {raw}"
            normalized.append(str(network))
        updates["subnet"] = ",".join(normalized)'''

new_val = '''        normalized = []
        for raw in raw_subnets:
            parts = raw.split("=", 1)
            net_str = parts[0].strip()
            name_str = ("=" + parts[1].strip()) if len(parts) > 1 else ""
            try:
                network = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                return f"Geçersiz subnet: {net_str}"
            if not _is_allowed_inventory_network(network):
                return f"Yalnızca yerel/özel IPv4 subnetleri kullanılabilir: {net_str}"
            if network.prefixlen < 16:
                return f"Çok geniş subnet desteklenmiyor (en geniş /16): {net_str}"
            normalized.append(str(network) + name_str)
        updates["subnet"] = ",".join(normalized)'''
c = c.replace(old_val, new_val)

with open('backend/server.py', 'w', encoding='utf-8') as f:
    f.write(c)

print("Backend updated for Named Subnets.")
