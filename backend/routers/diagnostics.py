"""Ağ teşhisi ve kontrollü aktif test API uçları."""

import re

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class PingRequest(BaseModel):
    target: str = "8.8.8.8"
    count: int = 4


class PortScanRequest(BaseModel):
    target: str
    preset: str = "common"


class TraceRequest(BaseModel):
    target: str = "google.com"
    max_hops: int = 20


class NetworkCmdRequest(BaseModel):
    action: str
    target: str = ""
    record_type: str = ""


_PING_TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms", re.IGNORECASE)
COMMON_TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
ALLOWED_NETWORK_COMMANDS = {
    "flushdns": (["ipconfig", "/flushdns"], "DNS Önbelleği Temizleme"),
    "ipconfig_all": (["ipconfig", "/all"], "Detaylı Ağ Yapılandırması"),
    "release": (["ipconfig", "/release"], "IP Adresi Serbest Bırakma"),
    "renew": (["ipconfig", "/renew"], "IP Adresi Yenileme"),
    "arp_a": (["arp", "-a"], "ARP Önbellek Tablosu"),
    "netstat_an": (["netstat", "-an"], "Aktif Bağlantılar ve Dinlenen Portlar"),
    "getmac": (["getmac"], "Ağ Kartı MAC Adresleri"),
    "hostname": (["hostname"], "Bilgisayar Adı"),
    "net_share": (["net", "share"], "Paylaşılan Kaynaklar"),
    "route_print": (["route", "print"], "IP Yönlendirme (Routing) Tablosu"),
    "nbtstat_n": (["nbtstat", "-n"], "Yerel NetBIOS Adları"),
}
_TARGET_REQUIRED_COMMANDS = {
    "nbtstat_a": (lambda target: ["nbtstat", "-A", target], "Uzak NetBIOS Adları"),
    "pathping": (lambda target: ["pathping", "-n", "-q", "4", target], "Ayrıntılı Yol Analizi (PathPing)"),
}
_HOSTNAME_OR_IP_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-:]{0,253}[A-Za-z0-9])?$")
_NSLOOKUP_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "ANY"}


def _clean_command_target(raw: str) -> str:
    target = (raw or "").strip().split(":")[0].split("/")[0]
    if not target or not _HOSTNAME_OR_IP_RE.match(target):
        return ""
    return target


def create_diagnostics_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.post("/api/tools/ping")
    def run_ping(req: PingRequest, user: dict = Depends(ctx.get_current_user)):
        target = req.target.strip().split(":")[0].split("/")[0]
        count = max(1, min(req.count, 20))
        if not target:
            return {"error": "Hedef adresi boş olamaz."}

        if ctx.platform.system().lower() == "windows":
            cmd = ["ping", "-n", str(count), "-w", "1200", target]
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", target]
        try:
            result = ctx.subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=count * 2 + 5,
                **ctx._hidden_subprocess_kwargs(),
            )
            output = (result.stdout or "") + "\n" + (result.stderr or "")
        except Exception:
            return {"error": f"'{target}' adresine ping atılamadı. Hedef adı veya IP adresini kontrol edin."}

        lower_out = output.lower()
        if any(
            marker in lower_out
            for marker in ("could not find host", "bilinen bir ana bilgisayar", "unknown host", "name or service not known")
        ):
            return {"error": f"'{target}' adresi çözümlenemedi (DNS hatası). IP adresini veya alan adını kontrol edin."}

        times = [float(match) for match in _PING_TIME_RE.findall(output)]
        if not times:
            return {
                "success": False, "alive": False, "received": 0, "sent": count,
                "times": [], "average": None, "avg_rtt": None, "loss": 100,
                "packet_loss": 100,
                "error": f"'{target}' adresinden yanıt alınamadı (zaman aşımı / erişilemiyor).",
            }
        average = sum(times) / len(times)
        loss = max(0, int(round(((count - len(times)) / count) * 100)))
        return {
            "success": True, "alive": True, "received": len(times), "sent": count,
            "times": [round(value, 1) for value in times], "average": round(average, 1),
            "avg_rtt": round(average, 1), "loss": loss, "packet_loss": loss,
            "quality": "cok_iyi" if average < 30 else "iyi" if average < 80 else "orta" if average < 150 else "kotu",
            "min": round(min(times), 1), "max": round(max(times), 1),
        }

    @router.post("/api/tools/speedtest")
    def run_speedtest_api(user: dict = Depends(ctx.get_current_user)):
        if ctx.speedtest is None:
            return {"error": "Sunucuda 'speedtest-cli' kurulu değil. Lütfen terminalden 'pip install speedtest-cli' çalıştırın."}
        try:
            test = ctx.speedtest.Speedtest()
            test.get_best_server()
            download = test.download() / 1_000_000
            upload = test.upload() / 1_000_000
            ping = test.results.ping
            server_name = test.results.server.get("name")
            timestamp = ctx.time.time()
            conn = ctx.db_conn()
            conn.execute(
                "INSERT OR REPLACE INTO speedtests (ts, download, upload, ping, server) VALUES (?, ?, ?, ?, ?)",
                (timestamp, round(download, 2), round(upload, 2), round(ping, 2), server_name),
            )
            conn.commit()
            conn.close()
            return {
                "download": round(download, 2), "upload": round(upload, 2),
                "ping": round(ping, 2), "server": server_name, "ts": timestamp,
            }
        except Exception as exc:
            return {"error": f"Hız testi başarısız: {exc}"}

    @router.get("/api/tools/speedtest/history")
    def speedtest_history(limit: int = 15, user: dict = Depends(ctx.get_current_user)):
        conn = ctx.db_conn()
        rows = conn.execute(
            "SELECT ts, download, upload, ping, server FROM speedtests ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [
            {"ts": row[0], "download": row[1], "upload": row[2], "ping": row[3], "server": row[4]}
            for row in rows
        ]

    @router.post("/api/tools/portscan")
    def run_portscan(req: PortScanRequest, user: dict = Depends(ctx.require_permission("diagnostics.run"))):
        target = (req.target or "127.0.0.1").strip()
        if len(target) > 253 or req.preset not in {"common", "web", "full"}:
            return JSONResponse(status_code=400, content={"error": "Geçersiz hedef veya tarama profili."})
        try:
            resolved_target = ctx.socket.gethostbyname(target)
            parsed_target = ctx.ipaddress.ip_address(resolved_target)
        except (OSError, ValueError):
            return JSONResponse(status_code=400, content={"error": "Hedef çözümlenemedi."})
        if not ctx._is_allowed_inventory_ip(parsed_target):
            return JSONResponse(status_code=400, content={"error": "Port taraması yalnızca yerel/özel IPv4 hedeflerinde kullanılabilir."})

        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080]
        if req.preset == "web":
            ports = [80, 443, 8080, 8443]
        elif req.preset == "full":
            ports = list(range(1, 1025))

        def scan_port(port):
            sock = ctx.socket.socket(ctx.socket.AF_INET, ctx.socket.SOCK_STREAM)
            sock.settimeout(0.3)
            started = ctx.time.time()
            result = sock.connect_ex((resolved_target, port))
            elapsed = int((ctx.time.time() - started) * 1000)
            sock.close()
            if result != 0:
                return None
            try:
                service = ctx.socket.getservbyport(port, "tcp")
            except OSError:
                service = "Bilinmeyen"
            return {"port": port, "service": service, "ms": elapsed}

        with ctx.concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            open_ports = [result for result in executor.map(scan_port, ports) if result]
        ctx._audit(user["username"], "portscan", f"target={resolved_target} preset={req.preset} open={len(open_ports)}")
        return {
            "target": target, "ip": resolved_target, "open": open_ports,
            "closed": len(ports) - len(open_ports), "scanned": len(ports),
        }

    @router.post("/api/tools/deep-scan")
    def run_deep_scan(user: dict = Depends(ctx.require_permission("diagnostics.run"))):
        devices = ctx._devices_cache.get("data") or []
        targets = [device for device in devices if device.get("ip") and device.get("status") in ("online", "discovered")]

        def scan_one(device):
            ip = device["ip"]

            def scan_port(port):
                sock = ctx.socket.socket(ctx.socket.AF_INET, ctx.socket.SOCK_STREAM)
                sock.settimeout(0.35)
                try:
                    if sock.connect_ex((ip, port)) == 0:
                        try:
                            service = ctx.socket.getservbyport(port, "tcp")
                        except OSError:
                            service = "Bilinmeyen"
                        return {"port": port, "service": service}
                finally:
                    sock.close()
                return None

            with ctx.concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                open_ports = [result for result in executor.map(scan_port, COMMON_TOP_PORTS) if result]
            return {
                "ip": ip, "mac": device.get("mac"),
                "hostname": device.get("hostname") or device.get("friendly_name"),
                "device_type": device.get("device_type"), "open_ports": open_ports,
            }

        with ctx.concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(scan_one, targets))
        ctx._audit(user["username"], "deep_scan", f"hosts={len(results)}")
        return {"scanned_hosts": len(results), "results": results, "generated_at": ctx.time.time()}

    @router.post("/api/tools/traceroute")
    def run_traceroute_api(req: TraceRequest, user: dict = Depends(ctx.get_current_user)):
        if ctx.platform.system().lower() == "windows":
            cmd = ["tracert", "-d", "-h", str(req.max_hops), "-w", "500", req.target]
        else:
            cmd = ["traceroute", "-n", "-m", str(req.max_hops), "-w", "1", req.target]
        try:
            output = ctx.subprocess.check_output(
                cmd,
                universal_newlines=True,
                stderr=ctx.subprocess.STDOUT,
                timeout=req.max_hops * 2 + 10,
                **ctx._hidden_subprocess_kwargs(),
            )
            hops = []
            for raw_line in output.split("\n"):
                line = raw_line.strip()
                if not line or "Tracing" in line or "traceroute" in line or "complete" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
                    ms_match = re.findall(r"(\d+)\s*ms", line)
                    hops.append(
                        {
                            "hop": int(parts[0]), "ip": ip_match.group() if ip_match else None,
                            "ms": int(ms_match[0]) if ms_match else None, "timeout": "*" in line,
                        }
                    )
            return {"hops": hops}
        except Exception:
            return {"error": "Traceroute işlemi başarısız.", "hops": []}

    @router.post("/api/tools/network-cmd")
    def run_network_cmd_api(req: NetworkCmdRequest, user: dict = Depends(ctx.get_current_user)):
        key = req.action.strip().lower()
        if key in {"release", "renew", "flushdns"} and user.get("role") != "admin":
            return JSONResponse(status_code=403, content={"error": "Ağ yapılandırmasını değiştiren komutlar için yönetici yetkisi gerekir."})
        if key == "nslookup":
            target = req.target.strip() or "google.com"
            record_type = req.record_type.strip().upper()
            if record_type:
                if record_type not in _NSLOOKUP_RECORD_TYPES:
                    return JSONResponse(status_code=400, content={"error": "Desteklenmeyen DNS kayıt tipi."})
                cmd = ["nslookup", f"-type={record_type}", target]
                label = f"DNS Sorgusu ({target}, {record_type})"
            else:
                cmd = ["nslookup", target]
                label = f"DNS Sorgusu ({target})"
        elif key in _TARGET_REQUIRED_COMMANDS:
            target = _clean_command_target(req.target)
            if not target:
                return JSONResponse(status_code=400, content={"error": "Geçerli bir hedef adresi/hostname girin."})
            builder, label_prefix = _TARGET_REQUIRED_COMMANDS[key]
            cmd = builder(target)
            label = f"{label_prefix} ({target})"
        elif key in ALLOWED_NETWORK_COMMANDS:
            cmd, label = ALLOWED_NETWORK_COMMANDS[key]
        else:
            return JSONResponse(status_code=400, content={"error": "Desteklenmeyen veya geçersiz ağ komutu."})

        try:
            result = ctx.subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                **ctx._hidden_subprocess_kwargs(),
            )
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            ctx._audit(user["username"], "network_cmd", f"action={key} target={req.target}")
            return {
                "action": key, "label": label, "command": " ".join(cmd),
                "output": output.strip(), "returncode": result.returncode, "ts": ctx.time.time(),
            }
        except Exception as exc:
            return {"error": f"Komut çalıştırılamadı: {exc}"}

    @router.get("/api/diagnostics")
    def get_diagnostics(user: dict = Depends(ctx.get_current_user)):
        try:
            return ctx.diag.run_troubleshooting_wizard(ctx.PING_TARGET, ctx.DNS_DOMAIN, ctx.PING_COUNT)
        except Exception as exc:
            return {
                "adapter": False, "gateway": False, "dns": False, "internet": False,
                "issue": "Teşhis çalıştırılamadı", "recommendation": str(exc),
            }

    @router.get("/api/flow")
    def get_flow(user: dict = Depends(ctx.get_current_user)):
        try:
            return {"steps": ctx.diag.simulate_connection_flow(), "simulated": True}
        except Exception as exc:
            return {"steps": [], "error": str(exc)}

    return router
