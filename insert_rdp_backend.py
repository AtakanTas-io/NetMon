import re

with open('backend/server.py', 'r', encoding='utf-8') as f:
    c = f.read()

if '/api/rdp' not in c:
    rdp_route = '''
@app.get("/api/rdp")
def api_download_rdp(ip: str, name: str = ""):
    content = f"auto connect:i:1\\nfull address:s:{ip}\\nprompt for credentials:i:1\\n"
    import urllib.parse
    safe_name = urllib.parse.quote(name or ip)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8\\'\\'{safe_name}.rdp"
    }
    return Response(content=content, media_type="application/x-rdp", headers=headers)
'''
    c = c.replace('@app.get("/api/export/devices")', rdp_route + '\n@app.get("/api/export/devices")')

    with open('backend/server.py', 'w', encoding='utf-8') as f:
        f.write(c)

print("Backend RDP route added.")
