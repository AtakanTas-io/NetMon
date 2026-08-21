import sys

with open('backend/server.py', 'r', encoding='utf-8') as f:
    content = f.read()

export_code = '''
from fastapi.responses import StreamingResponse
import io
import csv

@app.get("/api/export/devices")
def export_devices_csv(user: dict = Depends(get_current_user)):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, hostname, vendor, type, os_name, os_version, cpu_name, ram_gb, disk_gb, motherboard_maker, motherboard_model, gpu_name, serial_number, antivirus, firewall, unified_inventory, last_seen FROM devices ORDER BY ip")
        rows = cursor.fetchall()
        
        output = io.StringIO()
        # Add UTF-8 BOM for Excel compatibility
        output.write('\\ufeff')
        
        writer = csv.writer(output, delimiter=';')
        writer.writerow([
            "IP Adresi", "MAC Adresi", "Hostname", "Üretici", "Cihaz Tipi", 
            "İşletim Sistemi", "OS Versiyon", "İşlemci (CPU)", "RAM (GB)", "Disk (GB)",
            "Anakart", "Model", "Ekran Kartı (GPU)", "Seri No", 
            "Antivirüs", "Güvenlik Duvarı", "Envanter Durumu", "Son Görülme"
        ])
        
        import json
        for r in rows:
            inv = {}
            if r["unified_inventory"]:
                try:
                    inv = json.loads(r["unified_inventory"])
                except:
                    pass
                    
            status_text = "Yetkili (WMI/SSH)" if inv.get("verified") else "Ağ Profili"
            
            writer.writerow([
                r["ip"], r["mac"], r["hostname"], r["vendor"], r["type"],
                r["os_name"], r["os_version"], r["cpu_name"], r["ram_gb"], r["disk_gb"],
                r["motherboard_maker"], r["motherboard_model"], r["gpu_name"], r["serial_number"],
                r["antivirus"], r["firewall"], status_text, r["last_seen"]
            ])
            
        conn.close()
        
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=netmon_envanter.csv"}
        )
    except Exception as e:
        return {"error": str(e)}
'''

if "/api/export/devices" not in content:
    idx = content.find('@app.get("/api/devices")')
    if idx != -1:
        new_content = content[:idx] + export_code + "\n" + content[idx:]
        with open('backend/server.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("Export endpoint added.")
    else:
        print("Could not find insertion point.")
else:
    print("Endpoint already exists.")
