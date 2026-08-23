import re
import json

source = open(r'c:\Users\tasat\Desktop\Projects\Netmon\backend\server.py', encoding='utf-8').read()

old_select = 'identification_status, last_network FROM known_devices WHERE mac=?'
new_select = 'identification_status, last_network, open_ports FROM known_devices WHERE mac=?'
source = source.replace(old_select, new_select)

old_unpack = '''                 previous_sources, previous_connectivity, previous_identification, previous_network) = row'''
new_unpack = '''                 previous_sources, previous_connectivity, previous_identification, previous_network, previous_open_ports) = row
                
                # Check for new ports
                current_ports = classification.get('open_ports', [])
                if previous_open_ports:
                    import json
                    try:
                        prev_ports_list = json.loads(previous_open_ports)
                        new_ports = [p for p in current_ports if p not in prev_ports_list]
                        if new_ports:
                            alert_msg = f"{device.get('ip')} ({hostname or mac}) cihazi uzerinde YENI PORT(LAR) tespit edildi: {', '.join(map(str, new_ports))}"
                            conn.execute("INSERT INTO alerts (ts, level, message) VALUES (?, ?, ?)", (time.time(), "warning", alert_msg))
                    except: pass'''
source = source.replace(old_unpack, new_unpack)

old_insert = 'identification_status, last_network) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
new_insert = 'identification_status, last_network, open_ports) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
source = source.replace(old_insert, new_insert)

old_insert_params = '''                     device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                     current_network),'''
new_insert_params = '''                     device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                     current_network, json.dumps(classification.get('open_ports', []))),'''
source = source.replace(old_insert_params, new_insert_params)

old_update = 'identification_status=?, last_network=? WHERE mac=?'
new_update = 'identification_status=?, last_network=?, open_ports=? WHERE mac=?'
source = source.replace(old_update, new_update)

old_update_params = '''                 device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                 current_network, mac),'''
new_update_params = '''                 device.get("connectivity_status", "unknown"), device.get("identification_status", "unknown"),
                 current_network, json.dumps(classification.get('open_ports', [])), mac),'''
source = source.replace(old_update_params, new_update_params)

open(r'c:\Users\tasat\Desktop\Projects\Netmon\backend\server.py', 'w', encoding='utf-8').write(source)
print('Updated server.py for new ports alarm')
