import ipaddress
import logging
import platform
import re
import shutil
import socket
import time
import subprocess
import urllib.request
import urllib.error

# Varsayılan konfigürasyon ve veri dosyaları
import concurrent.futures
import struct
import defusedxml.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# [DISCOVERY] tarama zincirinin her aşamasını izlemek için ayrı bir logger.
# server.py çalışırken konsola (calistir.bat / python server.py) ya da
# --onefile exe log dosyasına akar; kullanıcı bilgisi/şifre gibi hassas
# veriler asla loglanmaz (yalnızca IP/MAC/hostname/aşama durumu).
logger = logging.getLogger("netmon.discovery")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


class NetworkDiscoveryError(Exception):
    """Cihaz taraması gerçek bir nedenle başarısız olduğunda fırlatılır.
    server.py bunu yakalayıp kullanıcıya gerçek sebebi gösterir; asla
    sessizce boş liste dönmek için kullanılmaz."""
    pass

# Reverse DNS (gethostbyaddr) OS resolver çağrısı Python'dan iptal
# edilemez/timeout uygulanamaz; bu yüzden ayrı, sabit boyutlu bir havuzda
# çalıştırılıp future.result(timeout=...) ile üst sınır konuyor. Havuz modül
# seviyesinde tek sefer oluşturulur; her tarama için yeniden yaratılmaz.
_HOSTNAME_RESOLVER_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=32, thread_name_prefix="hostname-resolve"
)

@dataclass
class PingResult:
    target: str
    success: bool
    packet_loss: Optional[int] = None
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    average: Optional[int] = None
    error: Optional[str] = None

@dataclass
class DiagnosticSnapshot:
    timestamp: str
    local_ip: Optional[str] = None
    public_ip: Optional[str] = None
    gateway: Optional[str] = None
    dns_servers: list = field(default_factory=list)
    gateway_test: Optional[dict] = None
    internet_test: Optional[dict] = None
    dns_test: Optional[dict] = None
    diagnosis: Optional[str] = None
    status: str = "unknown"

    def to_dict(self):
        return asdict(self)

class NetworkDiagnostics:
    def __init__(self, command_timeout: int = 5, http_timeout: int = 4):
        self.os_name = platform.system()
        self.command_timeout = command_timeout
        self.http_timeout = http_timeout

    def run_command(self, command: list, timeout: float | None = None):
        try:
            startupinfo = None
            creationflags = 0
            if self.os_name == "Windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                creationflags = subprocess.CREATE_NO_WINDOW

            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout if timeout is not None else self.command_timeout,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
        except Exception as exc:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(exc))

    def get_network_context(self):
        """Yerel arayüz ve ağ kimliğini gerçek işletim sistemi verisinden döndürür.
        CIDR, subnet maskesi ve arayüz adı sabit varsayımlardan üretilmez.
        """
        local_ip, gateway, dns_servers = self.get_network_configuration()
        netmask = None
        interface = None
        local_mac = None
        cidr = None
        if HAS_PSUTIL:
            try:
                for if_name, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if getattr(a, "family", None) == socket.AF_INET and a.address == local_ip:
                            interface = if_name
                            netmask = a.netmask
                            break
                    if interface:
                        for a in addrs:
                            candidate = (getattr(a, "address", "") or "").replace("-", ":").upper().strip()
                            if candidate and candidate != "00:00:00:00:00:00" and re.fullmatch(r"([0-9A-FA-F]{2}:){5}[0-9A-FA-F]{2}", candidate):
                                local_mac = candidate
                                break
                        break
            except Exception:
                pass
        if not local_mac:
            try:
                import uuid
                mac_num = uuid.getnode()
                if (mac_num >> 40) % 2 == 0:
                    local_mac = ":".join(f"{(mac_num >> (8 * i)) & 0xff:02X}" for i in range(5, -1, -1))
            except Exception:
                pass
        if local_ip and netmask:
            try:
                cidr = str(ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False))
            except ValueError:
                cidr = None
        return {
            "local_ip": local_ip,
            "gateway": gateway,
            "dns_servers": dns_servers,
            "netmask": netmask,
            "cidr": cidr,
            "interface": interface,
            "local_mac": local_mac,
        }

    def get_network_configuration(self):
        local_ip, gateway = None, None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except OSError:
            pass

        gateway = self._get_gateway_fallback()
        dns_servers = self._get_dns_servers_fallback()
        return local_ip, gateway, dns_servers

    def _get_gateway_fallback(self):
        if self.os_name == "Windows":
            result = self.run_command(["ipconfig"])
            match = re.search(r"(?:Default Gateway|Varsay[ıi]lan A[ğg] Geçidi)[^:]*:\s*([\d.]+)", result.stdout)
            return match.group(1) if match else None
        return None

    def _get_dns_servers_fallback(self):
        dns_servers = []
        if self.os_name == "Windows":
            result = self.run_command(["ipconfig", "/all"])
            capture = False
            for line in result.stdout.splitlines():
                if re.search(r"DNS Servers|DNS Sunucular[ıi]", line):
                    capture = True
                    candidates = [line.split(":", 1)[-1].strip()]
                elif capture:
                    stripped = line.strip()
                    if not stripped:
                        capture = False
                        continue
                    candidates = [stripped]
                else:
                    continue
                for value in candidates:
                    value = value.split("%", 1)[0]
                    try:
                        parsed = ipaddress.ip_address(value)
                    except ValueError:
                        if capture and ":" in value and not re.fullmatch(r"[0-9a-fA-F:]+", value):
                            capture = False
                        continue
                    normalized = str(parsed)
                    if normalized not in dns_servers:
                        dns_servers.append(normalized)
        return dns_servers

    def get_public_ip(self):
        try:
            request = urllib.request.Request("https://api.ipify.org?format=text", headers={"User-Agent": "NetMon/2.5.0"})
            # URL sabit kodlanmış, kullanıcı girdisi yok
            return urllib.request.urlopen(request, timeout=self.http_timeout).read().decode("utf-8")  # nosec B310
        except Exception:
            return None

    def ping_test(self, target: str, count: int = 2) -> PingResult:
        command = ["ping", "-n", str(count), target] if self.os_name == "Windows" else ["ping", "-c", str(count), target]
        result = self.run_command(command)
        success = result.returncode == 0
        avg = None
        try:
            out = result.stdout
            # Windows (TR/EN): "Ortalama = 12ms" / "Average = 12ms"
            m = re.search(r"(?:Ortalama|Average)\s*=\s*(\d+)\s*ms", out, re.IGNORECASE)
            if not m:
                # Linux/mac: "min/avg/max/mdev = 10.1/12.3/15.0/1.2 ms"
                m2 = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+", out)
                if m2:
                    avg = round(float(m2.group(1)))
            else:
                avg = int(m.group(1))
        except Exception:
            avg = None
        loss = None
        try:
            lm = re.search(r"(\d+)%\s*(?:loss|kayıp)", result.stdout, re.IGNORECASE)
            if lm:
                loss = int(lm.group(1))
        except Exception:
            loss = None
        return PingResult(target=target, success=success, average=avg, packet_loss=loss if loss is not None else (0 if success else 100))

    def dns_test(self, domain: str):
        try:
            return True, socket.gethostbyname(domain)
        except socket.gaierror as exc:
            return False, str(exc)

    def diagnose(self, gateway_ok, internet_ok, dns_ok):
        if not gateway_ok:
            return ("Ağ geçidine (Gateway) ulaşılamıyor.", "fail")
        elif not internet_ok:
            return ("İnternet erişimi yok.", "fail")
        elif not dns_ok:
            return ("DNS çözümlenemiyor.", "warn")
        return ("Ağ bağlantınız stabil ve sorunsuz çalışıyor.", "ok")

    def quick_snapshot(
        self,
        ping_target="8.8.8.8",
        dns_domain="google.com",
        lookup_public_ip=False,
        ping_count=2,
    ) -> DiagnosticSnapshot:
        local_ip, gateway, dns_servers = self.get_network_configuration()
        public_ip = self.get_public_ip() if lookup_public_ip else None
        ping_count = max(1, min(int(ping_count or 2), 20))
        gateway_result = self.ping_test(gateway, count=ping_count) if gateway else None
        internet_result = self.ping_test(ping_target, count=ping_count)
        dns_ok, dns_info = self.dns_test(dns_domain)

        gateway_ok = gateway_result is not None and gateway_result.success
        internet_ok = internet_result.success
        diagnosis, status = self.diagnose(gateway_ok, internet_ok, dns_ok)

        return DiagnosticSnapshot(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            local_ip=local_ip, public_ip=public_ip, gateway=gateway, dns_servers=dns_servers,
            gateway_test=asdict(gateway_result) if gateway_result else None,
            internet_test=asdict(internet_result), dns_test={"success": dns_ok, "result": dns_info},
            diagnosis=diagnosis, status=status
        )

    # Bir taramada denenecek azami adres sayısı. ipaddress ile hesaplanan ağ
    # bunun üzerindeyse (ör. yanlışlıkla /8 girilirse) tarama bu sayıyla
    # sınırlandırılır; yoksa tarama dakikalarca sürebilir / cihazı yorabilir.
    MAX_SCAN_HOSTS = 1024
    INVALID_MACS = {"", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}

    def _get_local_network(self, local_ip: str, subnet_override: str = ""):
        """Taranacak ağı belirler: önce kullanıcının Ayarlar panelinden
        girdiği subnet_override (ör. '10.33.0.0/16' ya da sade '10.33.0.0'),
        yoksa işletim sisteminden gerçek alt ağ maskesini (ör. 255.255.0.0),
        o da yoksa standart ev ağı varsayımı olan /24'ü kullanır.

        Eskiden kod her zaman IP'nin ilk 3 bloğunu sabit /24 kabul ediyordu;
        bu yüzden 255.255.0.0 (/16) gibi kurumsal ağlarda ağın büyük kısmı
        taranmadan atlanıyordu. ipaddress kütüphanesi burada asıl maskeyi
        (ya da kullanıcının verdiği override'ı) dinamik olarak kullanmayı
        mümkün kılıyor.
        """
        if subnet_override:
            try:
                return ipaddress.ip_network(subnet_override, strict=False)
            except ValueError:
                pass  # geçersiz girişse otomatik tespite düş

        if HAS_PSUTIL:
            try:
                for addrs in psutil.net_if_addrs().values():
                    for a in addrs:
                        if getattr(a, "family", None) == socket.AF_INET and a.address == local_ip and a.netmask:
                            return ipaddress.ip_network(f"{local_ip}/{a.netmask}", strict=False)
            except Exception:
                pass

        return ipaddress.ip_network(f"{local_ip}/24", strict=False)

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS ile hostname bulur; Windows'ta başarısız olursa NetBIOS dener.

        DÜZELTME: socket.gethostbyaddr() işletim sisteminin çözümleyicisini
        çağıran bloklayan bir işlemdir; socket.setdefaulttimeout() bu çağrıyı
        etkilemez (Python'ın bilinen bir kısıtı). PTR kaydı olmayan yerel IP'ler
        için bu çağrı Windows'ta host başına 5-20+ saniye sürebiliyordu; tarama
        onlarca host için bunu sırayla/paralel çalıştırınca "Ağ taranıyor..."
        ekranı pratikte süresiz asılı kalıyordu. Artık çağrı ayrı bir thread'de
        çalıştırılıp sabit bir süre (1.2 sn) içinde sonuç beklenmiyorsa
        (thread arka planda bırakılıp) hostname'siz devam ediliyor.
        """
        try:
            future = _HOSTNAME_RESOLVER_POOL.submit(socket.gethostbyaddr, ip)
            hostname, _, _ = future.result(timeout=1.2)
            if hostname and hostname != ip:
                return hostname.split(".")[0]
        except Exception:
            pass

        if self.os_name == "Windows":
            try:
                result = self.run_command(["nbtstat", "-A", ip])
                for line in result.stdout.splitlines():
                    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                    if match:
                        name = match.group(1).strip()
                        if name.upper() not in {"WORKGROUP", "MSBROWSE"}:
                            return name
            except Exception:
                pass
        return None

    @staticmethod
    def _guess_device_type(hostname: Optional[str], is_gateway: bool = False,
                           is_self: bool = False, open_ports: Optional[set[int]] = None,
                           services: Optional[list[dict]] = None, vendor: str = "",
                           mdns_services: Optional[list[str]] = None,
                           ssdp: Optional[dict] = None, mac: str = "") -> dict:
        """Birden fazla kanıta dayalı cihaz parmak izi çıkarır.

        Tek bir ipucuna güvenmek yerine hostname + OUI/vendor + servisler +
        mDNS/SSDP kullanılır. Böylece örneğin Apple üreticisi tek başına
        'iPhone' demek için yeterli olmaz.
        """
        name = (hostname or "").lower()
        vend = (vendor or "").lower()
        ports = open_ports or set()
        svcs = services or []
        svc_names = [str(x.get("service", "")).lower() for x in svcs]
        banners = [str(x.get("banner", "")).lower() for x in svcs]
        mdns = [str(x).lower() for x in (mdns_services or [])]
        ssdp_text = " ".join(str(v).lower() for v in (ssdp or {}).values())

        if is_gateway:
            if any(x in name + " " + vend + " " + ssdp_text for x in
                   ("fortigate", "fortinet", "firewall", "pfsense", "opnsense", "sophos", "watchguard")):
                return {"type": "firewall", "confidence": 0.97, "methods": ["gateway", "identity"]}
            return {"type": "router", "confidence": 0.94, "methods": ["gateway"]}

        if is_self:
            return {"type": "computer", "confidence": 1.0, "methods": ["self"]}

        scores = {k: 0.0 for k in (
            "computer", "laptop", "phone", "tablet", "printer", "server",
            "router", "firewall", "switch", "access_point", "smart_tv", "camera", "nas", "iot", "network_device", "unknown"
        )}
        evidence = []

        def add(kind, score, reason):
            scores[kind] += score
            if reason not in evidence:
                evidence.append(reason)

        if name:
            evidence.append("hostname")
            if any(x in name for x in ("iphone", "android", "galaxy", "pixel", "redmi", "xiaomi", "oppo", "vivo", "oneplus", "realme")):
                add("phone", 0.86, "hostname: mobile")
            if any(x in name for x in ("ipad", "tablet", "tab-", "galaxy-tab")):
                add("tablet", 0.86, "hostname: tablet")
            if any(x in name for x in ("laptop", "notebook", "macbook")):
                add("laptop", 0.82, "hostname: laptop")
            if any(x in name for x in ("pc", "desktop", "win-", "mac-", "workstation", "computer")):
                add("computer", 0.78, "hostname: computer")
            if any(x in name for x in ("printer", "print", "yazici", "epson", "canon", "brother", "xerox", "laserjet")):
                add("printer", 0.92, "hostname: printer")
            if any(x in name for x in ("server", "srv", "dc-", "proliant")):
                add("server", 0.90, "hostname: server")
            if any(x in name for x in ("nas", "storage", "synology", "qnap", "truenas")):
                add("nas", 0.92, "hostname: nas/storage")
            if any(x in name for x in ("tv", "smarttv", "smart-tv", "bravia", "webos", "tizen", "roku", "chromecast")):
                add("smart_tv", 0.88, "hostname: smart tv")
            if any(x in name for x in ("camera", "cam-", "ipcam", "cctv", "hikvision", "dahua", "reolink", "axis")):
                add("camera", 0.91, "hostname: camera")
            if any(x in name for x in ("fortigate", "fortinet", "firewall", "pfsense", "opnsense", "sophos", "watchguard", "paloalto", "pan-os")):
                add("firewall", 0.94, "hostname: firewall")
            if any(x in name for x in ("router", "modem", "mikrotik", "gateway")):
                add("router", 0.88, "hostname: router")
            if any(x in name for x in ("accesspoint", "access-point", "wireless-ap", "wifi-ap", "ap-", "wap-")):
                add("access_point", 0.90, "hostname: access point")
            if any(x in name for x in ("switch", "sw-", "core-sw", "edge-sw", "catalyst", "quidway", "cloudengine", "s57", "s67", "s27", "s37", "s17")):
                add("switch", 0.92, "hostname: switch")
            if any(x in name for x in ("ubiquiti", "unifi", "cisco", "juniper", "aruba", "zyxel", "netgear", "d-link", "tp-link", "h3c", "ruijie", "brocade", "extreme")):
                add("network_device", 0.65, "hostname: network device")

        if vend:
            evidence.append("oui")
            if any(x in vend for x in ("apple", "samsung", "xiaomi", "oppo", "vivo", "oneplus", "realme")):
                add("phone", 0.40, f"vendor: {vendor}")
                add("tablet", 0.35, f"vendor: {vendor}")
            if any(x in vend for x in ("hp", "hewlett", "canon", "epson", "brother", "xerox", "ricoh", "kyocera")):
                add("printer", 0.35, f"vendor: {vendor}")
                add("computer", 0.08, f"vendor: {vendor}")
            if any(x in vend for x in ("dell", "lenovo", "acer", "asus", "intel", "microsoft", "gigabyte", "msi", "azurewave", "compal", "micro-star")):
                add("computer", 0.35, f"vendor: {vendor}")
            if any(x in vend for x in (
                "cisco", "fortinet", "fortigate", "mikrotik", "ubiquiti", "tp-link", "zyxel",
                "netgear", "d-link", "aruba", "juniper", "hpe", "hewlett packard enterprise",
                "tenda", "huawei", "h3c", "ruijie", "brocade", "extreme", "arista", "alcatel",
                "allied telesis", "bray", "lite-on"
            )):
                add("switch", 0.52, f"vendor: {vendor}")
                add("network_device", 0.50, f"vendor: {vendor}")
                add("router", 0.42, f"vendor: {vendor}")
            if any(x in vend for x in ("fortinet", "fortigate", "palo alto", "watchguard", "sophos", "checkpoint", "check point")):
                add("firewall", 0.65, f"vendor: {vendor}")
            if any(x in vend for x in ("synology", "qnap", "netapp", "western digital", "nas")):
                add("nas", 0.52, f"vendor: {vendor}")
            if any(x in vend for x in ("samsung", "lg", "sony", "vizio", "roku", "hisense", "tcl")):
                add("smart_tv", 0.42, f"vendor: {vendor}")
            if any(x in vend for x in ("hikvision", "dahua", "reolink", "axis", "amcrest")):
                add("camera", 0.55, f"vendor: {vendor}")
            if any(x in vend for x in ("raspberry", "espressif", "tuya", "ring", "amazon", "google")):
                add("iot", 0.45, f"vendor: {vendor}")

        if not vend and mac:
            evidence.append("mac_privacy")
            try:
                first_octet = int(mac.split(":")[0].split("-")[0], 16)
                is_locally_administered = bool(first_octet & 0x02)
            except (ValueError, IndexError):
                is_locally_administered = False
            if is_locally_administered:
                add("phone", 0.45, "mac: gizlilik/rastgele adres (WiFi privacy MAC)")
                add("tablet", 0.30, "mac: gizlilik/rastgele adres (WiFi privacy MAC)")

        if ports or svcs:
            evidence.append("services")
            if 23 in ports or "telnet" in svc_names:
                add("router", 0.75, "service: telnet")
            if 161 in ports or "snmp" in svc_names:
                add("switch", 0.65, "service: snmp")
                add("network_device", 0.65, "service: snmp")
            if 830 in ports or "netconf" in svc_names:
                add("switch", 0.90, "service: netconf")
                add("router", 0.85, "service: netconf")
            if 9100 in ports or 631 in ports or 515 in ports or any(x in svc_names for x in ("printer", "ipp", "jetdirect")):
                add("printer", 0.96, "service: printer")
            if any(p in ports for p in (3306, 5432, 1433, 6379, 27017)) or "database" in svc_names:
                add("server", 0.88, "service: database")
            if 3389 in ports or 445 in ports or 139 in ports or "microsoft-ds" in svc_names:
                add("computer", 0.72, "service: windows")
            if 22 in ports and (80 in ports or 443 in ports):
                if any(x in vend for x in ("huawei", "cisco", "juniper", "mikrotik", "ubiquiti", "zyxel", "aruba", "h3c")):
                    add("switch", 0.85, "service: ssh+web (managed switch)")
                    add("router", 0.80, "service: ssh+web (router)")
                else:
                    add("server", 0.68, "service: ssh+web")
            if 53 in ports and (80 in ports or 443 in ports):
                add("network_device", 0.68, "service: dns+web")
            if 554 in ports or "rtsp" in svc_names:
                add("camera", 0.78, "service: rtsp")
            if banners:
                banner = " ".join(banners)
                if any(x in banner for x in ("printer", "epson", "canon", "brother")):
                    add("printer", 0.80, "service banner: printer")
                if any(x in banner for x in ("vrp", "huawei", "cisco", "switch", "routeros", "junos", "catalyst", "quidway")):
                    add("switch", 0.90, "service banner: network os")

        if mdns:
            evidence.append("mdns")
            joined = " ".join(mdns)
            if any(x in joined for x in ("_airplay", "_raop", "iphone", "ipad", "ios")):
                add("phone", 0.55, "mDNS: Apple/mobile")
            if "_ipp" in joined or "_printer" in joined:
                add("printer", 0.70, "mDNS: printer")
            if "_googlecast" in joined or "chromecast" in joined:
                add("iot", 0.65, "mDNS: Google Cast")
            if "_http" in joined or "_https" in joined:
                add("network_device", 0.18, "mDNS: web service")

        if ssdp:
            evidence.append("ssdp")
            if any(x in ssdp_text for x in ("printer", "epson", "canon", "brother")):
                add("printer", 0.72, "SSDP: printer")
            if any(x in ssdp_text for x in ("router", "gateway", "upnp", "internetgatewaydevice")):
                add("router", 0.55, "SSDP: gateway")
            if any(x in ssdp_text for x in ("roku", "chromecast", "smarttv", "samsung", "lg electronics", "mediarenderer")):
                add("iot", 0.62, "SSDP: media device")

        # DÜZELTME: best_type/confidence hiç hesaplanmıyordu, bu da her
        # gerçek (gateway/self olmayan) cihaz için NameError ile taramanın
        # tamamen çökmesine ve mobil/PC/diğer ayrımının hiç çalışmamasına
        # neden oluyordu. En yüksek puanlı türü seçiyoruz; hiç kanıt yoksa
        # "unknown" + düşük güven döndürülür.
        ranked = sorted(((k, float(v)) for k, v in scores.items() if k != "unknown" and v > 0), key=lambda x: x[1], reverse=True)
        best_type = ranked[0][0] if ranked else "unknown"
        top_score = ranked[0][1] if ranked else 0.0
        second_score = ranked[1][1] if len(ranked) > 1 else 0.0
        # Güven yalnızca toplam puan değil, ikinci adayla arasındaki farkı da
        # dikkate alır. Böylece Apple OUI gibi zayıf tek kanıtlar yanlış
        # şekilde %90+ güven üretemez.
        margin = max(0.0, top_score - second_score)
        confidence = min(0.99, max(0.15, top_score * 0.72 + min(margin, 0.45) * 0.55)) if ranked else 0.15
        if top_score < 0.25:
            best_type = "unknown"
            confidence = 0.15

        score_breakdown = [
            {"type": kind, "score": round(score, 2)}
            for kind, score in ranked[:4]
        ]

        # Ayrıntılı kurumsal türleri kaybetme. Önceki eşleme firewall'ı router,
        # access point'i switch ve tablet'i telefon olarak daraltıyordu.
        final_type = best_type if best_type in scores and best_type != "unknown" else "unknown"
        return {
            "type": final_type,
            "raw_type": best_type,
            "confidence": round(confidence, 2),
            "confidence_label": "yüksek" if confidence >= 0.80 else ("orta" if confidence >= 0.55 else "düşük"),
            "score_breakdown": score_breakdown,
            "margin": round(margin, 2),
            "methods": evidence,
            "evidence": [{"text": item, "source": (
                "hostname" if item.startswith("hostname:")
                else "oui" if item.startswith("vendor:")
                else "services" if item.startswith(("service:", "service banner:"))
                else "mdns" if item.startswith("mDNS:")
                else "ssdp" if item.startswith("SSDP:")
                else "other"
            )} for item in evidence],
        }

    def _get_local_mac(self, local_ip: Optional[str]) -> Optional[str]:
        if not local_ip:
            return None
        if HAS_PSUTIL:
            try:
                for _, addrs in psutil.net_if_addrs().items():
                    ip_addr = next((a.address for a in addrs if getattr(a, "family", None) == socket.AF_INET), None)
                    if ip_addr != local_ip:
                        continue
                    for a in addrs:
                        candidate = (getattr(a, "address", "") or "").replace("-", ":").upper().strip()
                        if candidate and candidate != "00:00:00:00:00:00" and re.fullmatch(r"([0-9A-FA-F]{2}:){5}[0-9A-FA-F]{2}", candidate):
                            return candidate
            except Exception:
                pass
        try:
            import uuid
            mac_num = uuid.getnode()
            if (mac_num >> 40) % 2 == 0:
                return ":".join(f"{(mac_num >> (8 * i)) & 0xff:02X}" for i in range(5, -1, -1))
        except Exception:
            pass
        return None

    def _get_mac_vendor(self, mac: str) -> str:
        """MAC OUI için yerleşik veya gömülü JSON sözlüğü kullanır."""
        if not mac:
            return ""
        mac = mac.upper()
        prefix = mac[:8] # Format XX:XX:XX
        
        # Load oui.json on first access
        if not hasattr(self, "_oui_cache"):
            self._oui_cache = {}
            try:
                import json
                import os
                import sys
                
                # Check if frozen
                if getattr(sys, 'frozen', False):
                    base_path = sys._MEIPASS
                else:
                    base_path = os.path.dirname(os.path.abspath(__file__))
                    
                oui_path = os.path.join(base_path, 'oui.json')
                
                if os.path.exists(oui_path):
                    with open(oui_path, 'r', encoding='utf-8') as f:
                        self._oui_cache = json.load(f)
            except Exception as e:
                logger.error(f"OUI yuklenemedi: {e}")
                
        # Hardcoded fallbacks if JSON failed
        vendors = self._oui_cache or {
            "00:03:93":"Apple", "3C:5A:B4":"Samsung", "28:FF:3C":"Xiaomi",
            "00:E0:FC":"Huawei", "00:1B:21":"Intel", "00:1C:42":"Dell",
            "00:23:24":"HP", "00:1C:25":"Lenovo", "00:0C:6E":"ASUS",
            "00:00:0C":"Cisco", "00:1D:A1":"D-Link", "00:0D:3A":"Microsoft",
            "B8:27:EB":"Raspberry Pi", "DC:A6:32":"Raspberry Pi",
            "EC:1A:59":"Belkin", "00:01:42":"Cisco", "CC:2D:21":"Xiaomi",
        }
        
        return vendors.get(prefix, "")

    @staticmethod
    def _dns_name(name: str) -> bytes:
        parts = name.strip('.').split('.')
        return b''.join(bytes([len(p)]) + p.encode('ascii', 'ignore') for p in parts) + b'\x00'

    def _mdns_discover(self, timeout: float = 1.2) -> dict[str, list[str]]:
        """Yerel mDNS servislerini pasif/standart sorgu ile keşfeder.
        Windows'ta güvenlik duvarı/istemci izolasyonu nedeniyle boş dönebilir.
        """
        queries = ("_device-info._tcp.local", "_airplay._tcp.local", "_ipp._tcp.local", "_http._tcp.local", "_googlecast._tcp.local")
        found: dict[str, list[str]] = {}
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.settimeout(0.25)
            for qname in queries:
                packet = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + self._dns_name(qname) + b'\x00\x0c\x00\x01'
                try:
                    sock.sendto(packet, ('224.0.0.251', 5353))
                except OSError:
                    continue
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                ip = addr[0]
                text = data.lower()
                services = []
                for q in queries:
                    if q.encode('ascii') in text:
                        services.append(q.split('.')[0])
                # Raw DNS packets contain compressed names; service hints are enough for fingerprinting.
                if b'_airplay' in text or b'_raop' in text: services.append('_airplay')
                if b'_ipp' in text or b'_printer' in text: services.append('_ipp')
                if b'_googlecast' in text: services.append('_googlecast')
                if b'_http' in text: services.append('_http')
                if services:
                    found.setdefault(ip, [])
                    found[ip] = sorted(set(found[ip] + services))
        except OSError:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        logger.info('[mDNS] Hosts with service hints: %d', len(found))
        return found

    def _ssdp_discover(self, timeout: float = 1.2) -> dict[str, dict]:
        """UPnP/SSDP M-SEARCH ile yerel ağdaki medya, yazıcı ve gateway cihazlarını keşfeder."""
        found: dict[str, dict] = {}
        msg = ('M-SEARCH * HTTP/1.1\r\n'
               'HOST: 239.255.255.250:1900\r\n'
               'MAN: "ssdp:discover"\r\n'
               'MX: 1\r\n'
               'ST: ssdp:all\r\n\r\n').encode('ascii')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.25)
            sock.sendto(msg, ('239.255.255.250', 1900))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                ip = addr[0]
                headers = {}
                for line in data.decode('latin-1', 'ignore').splitlines()[1:]:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.strip().lower()] = v.strip()
                found[ip] = {
                    'server': headers.get('server', ''),
                    'st': headers.get('st', ''),
                    'location': headers.get('location', ''),
                    'usn': headers.get('usn', '')
                }
        except OSError:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        logger.info('[SSDP] Hosts discovered: %d', len(found))
        return found

    def _fetch_ssdp_xml(self, location_url: str, timeout: float = 1.0) -> dict:
        info = {}
        if not location_url or not location_url.lower().startswith(("http://", "https://")):
            return info
        try:
            req = urllib.request.Request(location_url, headers={'User-Agent': 'Mozilla/5.0'})
            # şema http/https ile yukarıda sınırlandı
            with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310
                xml_data = response.read()
                root = ET.fromstring(xml_data)
                for elem in root.iter():
                    tag = elem.tag.split('}')[-1]
                    if tag in ('friendlyName', 'manufacturer', 'modelName', 'modelDescription'):
                        if elem.text:
                            info[tag] = elem.text.strip()
        except Exception:
            pass
        return info

    def _netbios_query(self, ip: str, timeout: float = 0.5) -> Optional[str]:
        req = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
              b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
              b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" \
              b"\x41\x41\x41\x00\x00\x21\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(req, (ip, 137))
            data, _ = sock.recvfrom(1024)
            if len(data) > 56:
                num_names = data[56]
                offset = 57
                for _ in range(num_names):
                    if offset + 18 > len(data): break
                    name = data[offset:offset+15].decode('ascii', 'ignore').strip()
                    flags = struct.unpack('>H', data[offset+16:offset+18])[0]
                    if not (flags & 0x8000):
                        return name
                    offset += 18
        except Exception:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        return None

    def _snmp_sysdescr(self, ip: str, timeout: float = 0.5, community: str = "public") -> Optional[str]:
        comm_bytes = community.encode('ascii')
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
        varbind = b"\x30" + bytes([2 + len(oid) + 2]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        pdu = b"\xa0" + bytes([len(varbind_list) + 14]) + \
              b"\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00" + varbind_list
        msg = b"\x30" + bytes([len(pdu) + len(comm_bytes) + 7]) + \
              b"\x02\x01\x00\x04" + bytes([len(comm_bytes)]) + comm_bytes + pdu
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (ip, 161))
            data, _ = sock.recvfrom(2048)
            idx = data.rfind(b"\x04")
            if idx != -1 and idx + 1 < len(data):
                length = data[idx+1]
                if idx + 2 + length <= len(data):
                    return data[idx+2:idx+2+length].decode('ascii', 'ignore').strip()
        except Exception:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        return None

    def _snmp_get_oid(self, ip: str, oid_bytes: bytes, timeout: float = 0.5, community: str = "public") -> Optional[str]:
        comm_bytes = community.encode('ascii')
        varbind = b"\x30" + bytes([2 + len(oid_bytes) + 2]) + b"\x06" + bytes([len(oid_bytes)]) + oid_bytes + b"\x05\x00"
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        pdu = b"\xa0" + bytes([len(varbind_list) + 14]) + \
              b"\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00" + varbind_list
        msg = b"\x30" + bytes([len(pdu) + len(comm_bytes) + 7]) + \
              b"\x02\x01\x00\x04" + bytes([len(comm_bytes)]) + comm_bytes + pdu
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, (ip, 161))
            data, _ = sock.recvfrom(2048)
            idx = data.rfind(b"\x04")
            if idx != -1 and idx + 1 < len(data):
                length = data[idx+1]
                if idx + 2 + length <= len(data):
                    return data[idx+2:idx+2+length].decode('ascii', 'ignore').strip()
        except Exception:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        return None

    def _snmp_lldp_cdp_query(self, ip: str, timeout: float = 0.5, community: str = "public") -> dict:
        """Queries SNMP for sysName, sysObjectID, and LLDP/CDP neighbor descriptors."""
        sys_name = self._snmp_get_oid(ip, b"\x2b\x06\x01\x02\x01\x01\x05\x00", timeout, community)
        sys_descr = self._snmp_sysdescr(ip, timeout, community)
        sys_object_id = self._snmp_get_oid(ip, b"\x2b\x06\x01\x02\x01\x01\x02\x00", timeout, community)
        
        is_infrastructure = False
        neighbors = []
        if sys_descr:
            sd_low = sys_descr.lower()
            if any(k in sd_low for k in ("switch", "catalyst", "cisco", "juniper", "aruba", "mikrotik", "ubiquiti", "routeros", "procurve")):
                is_infrastructure = True

        return {
            "sys_name": sys_name,
            "sys_descr": sys_descr,
            "sys_object_id": sys_object_id,
            "is_infrastructure": is_infrastructure,
            "neighbors": neighbors
        }

    def _grab_banner(self, ip: str, port: int, timeout: float = 0.3) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
            if data:
                lines = data.decode('ascii', 'ignore').splitlines()
                if lines:
                    if port in (80, 443, 8080, 8443):
                        for line in lines:
                            if line.lower().startswith("server:"):
                                return line[7:].strip()
                        return lines[0][:50]
                    return lines[0][:50]
        except Exception:
            pass
        finally:
            try: sock.close()
            except Exception: pass
        return None


    def _local_ipv4_networks(self):
        """Return locally attached IPv4 networks. No OS-specific assumptions."""
        nets = []
        if HAS_PSUTIL:
            try:
                for if_name, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if getattr(a, "family", None) != socket.AF_INET:
                            continue
                        ip = (a.address or "").split("%", 1)[0]
                        mask = a.netmask
                        if not ip or not mask:
                            continue
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.is_loopback or ip_obj.is_link_local:
                                continue
                            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            if net.is_private and net not in nets:
                                nets.append(net)
                        except ValueError:
                            continue
            except Exception:
                pass
        return nets

    def _get_gateway_cross_platform(self):
        """Best-effort default gateway discovery on Windows/Linux/macOS."""
        if self.os_name == "Windows":
            return self._get_gateway_fallback()
        for command in (["ip", "route"], ["route", "-n"]):
            try:
                result = self.run_command(command)
                text = result.stdout or ""
                m = re.search(r"(?:default|0\.0\.0\.0)\s+(?:via\s+)?(\d{1,3}(?:\.\d{1,3}){3})", text, re.I)
                if m:
                    return m.group(1)
            except Exception:
                continue
        return None

    def _get_connected_devices_generic(self, subnet_override: str = "", fast: bool = False):
        """Cross-platform L2/L3 discovery for Linux/macOS and other Unix-like OSes.

        This intentionally discovers only networks attached to local interfaces.
        It never treats the public Internet as a scan target.
        """
        networks = []
        if subnet_override:
            try:
                networks = [ipaddress.ip_network(subnet_override, strict=False)]
            except ValueError as exc:
                raise NetworkDiscoveryError(f"Geçersiz subnet: {subnet_override}") from exc
        else:
            networks = self._local_ipv4_networks()

        if not networks:
            raise NetworkDiscoveryError("Yerel IPv4 ağı tespit edilemedi.")

        local_ctx = self.get_network_context()
        local_ip = local_ctx.get("local_ip")
        local_mac = local_ctx.get("local_mac")
        gateway = self._get_gateway_cross_platform()
        local_hostname = socket.gethostname() or None

        def allowed(ip):
            obj = ipaddress.ip_address(ip)
            return obj.version == 4 and any(obj in n for n in networks)

        # Read the kernel ARP/neighbour table first. This is the strongest
        # source for devices that are actually present on the local L2 segment.
        neigh = {}
        commands = [["ip", "neigh"], ["arp", "-an"]]
        for command in commands:
            try:
                result = self.run_command(command)
                text = result.stdout or ""
                for line in text.splitlines():
                    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
                    if not ips:
                        continue
                    ip = ips[0]
                    if not allowed(ip):
                        continue
                    mac_m = re.search(r"(?i)\b([0-9a-f]{2}(?::|-)){5}[0-9a-f]{2}\b", line)
                    if mac_m:
                        mac = mac_m.group(0).replace("-", ":").upper()
                        if mac != "00:00:00:00:00:00":
                            neigh[ip] = mac
            except Exception:
                continue

        # Probe only directly attached private networks. For large networks,
        # cap the fallback sweep; Nmap can perform the full local CIDR discovery.
        discovered = set(neigh)
        for network in networks:
            hosts = list(network.hosts())
            if len(hosts) > self.MAX_SCAN_HOSTS:
                # Avoid an accidental massive scan when Nmap is unavailable.
                hosts = hosts[:self.MAX_SCAN_HOSTS]

            def ping_one(ip):
                if self.os_name == "Windows":
                    cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
                else:
                    cmd = ["ping", "-c", "1", "-W", "0.35" if fast else "1", str(ip)]
                try:
                    r = self.run_command(cmd)
                    return str(ip) if r.returncode == 0 else None
                except Exception:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                for ip in ex.map(ping_one, hosts):
                    if ip:
                        discovered.add(ip)

            # If Nmap exists, use host discovery on the complete directly
            # attached CIDR (not service scanning) to catch ICMP-filtered hosts.
            if self.nmap_available():
                try:
                    for ip in self.nmap_discover(network):
                        if allowed(ip):
                            discovered.add(ip)
                except Exception as exc:
                    logger.info("[DISCOVERY] Nmap host discovery skipped: %s", exc)

        results = []
        for ip in sorted(discovered, key=lambda x: tuple(map(int, x.split(".")))):
            try:
                hostname = None if fast and not (ip == local_ip or ip == gateway) else self._resolve_hostname(ip)
            except Exception:
                hostname = None
            mac = neigh.get(ip)
            is_self = ip == local_ip
            is_gateway = bool(gateway and ip == gateway)
            if is_self and local_mac:
                mac = local_mac
            vendor = self._get_mac_vendor(mac) if mac else ""
            results.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname if hostname and (not local_hostname or hostname.casefold() != local_hostname.casefold() or is_self) else (local_hostname if is_self else None),
                "vendor": vendor,
                "type": "router" if is_gateway else "computer" if is_self else "unknown",
                "status": "online" if is_self or is_gateway or ip in discovered else "discovered",
                "connectivity_status": "online",
                "identification_status": "identified" if mac or hostname else "discovered",
                "is_self": is_self,
                "is_gateway": is_gateway,
                "latency": None,
                "packet_loss": None,
                "discovery_sources": ["local_interface", "neighbor_table"] if ip in neigh else ["icmp_or_nmap"],
            })
        logger.info("[DISCOVERY] Cross-platform discovery found %d devices across %d local networks.", len(results), len(networks))
        return results

    def get_connected_devices(self, subnet_override: str = "", fast: bool = False):
        logger.info("[DISCOVERY] Starting enhanced scan")
        if self.os_name != "Windows":
            if fast:
                return self._get_connected_devices_generic(subnet_override, fast=True)
            return self._get_connected_devices_generic(subnet_override)

        context = self.get_network_context()
        local_ip, gateway = context.get("local_ip"), context.get("gateway")
        local_mac = context.get("local_mac") or self._get_local_mac(local_ip)
        local_hostname = socket.gethostname() or None
        logger.info("[NETWORK] Local IP: %s | Gateway: %s | CIDR: %s | Interface: %s",
                    local_ip, gateway, context.get("cidr"), context.get("interface"))
        if not local_ip:
            raise NetworkDiscoveryError("Yerel ağ arayüzü tespit edilemedi. Wi-Fi/Ethernet bağlantınızı kontrol edin.")

        network = self._get_local_network(local_ip, subnet_override)

        # Büyük kurumsal ağlarda (ör. /16) ilk 1024 adresi taramak teknik
        # olarak yanlış sonuç üretir: 10.33.254.x gibi yerel cihazlar listenin
        # çok ilerisine düştüğü için yalnızca bu bilgisayar görünür.
        # Tam ağ keşfi için Nmap varsa tam CIDR Nmap'e bırakılır; yerleşik
        # ping taraması ise kullanıcının bulunduğu /24'e odaklanır. Böylece
        # tarama süresi makul kalırken yerel segmentteki cihazlar kaçırılmaz.
        scan_network = network
        if network.num_addresses - 2 > self.MAX_SCAN_HOSTS and not self.nmap_available():
            try:
                local_net24 = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                if local_net24.subnet_of(network):
                    scan_network = local_net24
            except ValueError:
                pass
        hosts = list(scan_network.hosts())
        if len(hosts) > self.MAX_SCAN_HOSTS:
            hosts = hosts[: self.MAX_SCAN_HOSTS]
        logger.info("[NETWORK] Discovery subnet: %s | ICMP sweep: %s | hosts: %d", network, scan_network, len(hosts))

        def valid_discovery_ip(ip: str) -> bool:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if ip_obj.version != 4:
                return False
            if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                return False
            if ip_obj == network.network_address or ip_obj == network.broadcast_address:
                return False
            return ip_obj in network or ip in (local_ip, gateway)

        def valid_discovery_mac(mac: str) -> bool:
            return (mac or "").upper() not in self.INVALID_MACS

        def check_host(ip):
            result = self.run_command(["ping", "-n", "1", "-w", "180" if fast else "300", str(ip)])
            success = result.returncode == 0
            avg = None
            ttl = None
            m = re.search(r"(?:Average|Ortalama)\s*=\s*(\d+)\s*ms", result.stdout, re.I)
            if m:
                avg = int(m.group(1))
            m2 = re.search(r"TTL=(\d+)", result.stdout, re.I)
            if m2:
                ttl = int(m2.group(1))
            
            # Active ARP Request for local network devices to bypass ICMP drop (Smartphones, Firewalls)
            arp_mac = None
            try:
                import ctypes
                import struct
                import socket
                dest_ip = ctypes.c_ulong(struct.unpack('<L', socket.inet_aton(str(ip)))[0])
                mac_addr = ctypes.c_buffer(6)
                mac_len = ctypes.c_ulong(6)
                if ctypes.windll.iphlpapi.SendARP(dest_ip, 0, mac_addr, ctypes.byref(mac_len)) == 0:
                    arp_mac = ":".join(f"{b:02X}" for b in mac_addr.raw)
            except Exception:
                pass

            return str(ip), success, avg, ttl, arp_mac

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            ping_results = {}
            active_arps = {}
            for ip, ok, avg, ttl, arp_mac in executor.map(check_host, hosts):
                ping_results[ip] = {'success': ok, 'latency': avg, 'ttl': ttl}
                if arp_mac:
                    active_arps[ip] = arp_mac
        logger.info("[PING & ARP] Sweep completed over %d hosts. Active ARPs: %d", len(hosts), len(active_arps))

        # ARP remains the strongest local-L2 source for IP/MAC identity.
        result = self.run_command(["arp", "-a"])
        raw_map: dict[str, str] = {}
        for line in result.stdout.splitlines():
            low = line.lower()
            if not any(x in low for x in ("dynamic", "dinamik", "static", "statik")):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, mac = parts[0], parts[1].replace('-', ':').upper()
            if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                continue
            if not valid_discovery_ip(ip) or not valid_discovery_mac(mac):
                continue
            raw_map[ip] = mac
        logger.info("[ARP] Entries found: %d", len(raw_map))

        # Optional Nmap host discovery catches hosts that don't populate ARP/ICMP in the expected way.
        nmap_exists = self.nmap_available()
        if nmap_exists:
            # Nmap tam CIDR'yi keşfedebilir; böylece /16 ağlarda yalnızca
            # ilk 1024 adresi değil tüm ağ kapsanabilir.
            for ip in self.nmap_discover(scan_network):
                if valid_discovery_ip(ip):
                    raw_map.setdefault(ip, "")

        # Aktif SendARP ile bulduğumuz MAC'leri de raw_map'e ekleyelim
        for ip, mac in active_arps.items():
            if valid_discovery_ip(ip) and valid_discovery_mac(mac) and ip not in raw_map:
                raw_map[ip] = mac

        mdns_map = {} if fast else self._mdns_discover()
        ssdp_map = {} if fast else self._ssdp_discover()
        # Only resolve devices that were actively discovered (ARP, ICMP ping success, mDNS, SSDP, or self/gateway)
        # to prevent running reverse DNS and port probing over hundreds of unreachable IP addresses.
        discovered_set = set(raw_map) | set(active_arps) | set(mdns_map) | set(ssdp_map) | {ip for ip, info in ping_results.items() if info.get("success")} | {x for x in (local_ip, gateway) if x}
        discovery_ips = []
        for ip in discovered_set:
            if valid_discovery_ip(ip):
                discovery_ips.append(ip)

        def resolve(ip):
            mac = raw_map.get(ip, '')
            is_self = ip == local_ip
            is_gateway = bool(gateway and ip == gateway)
            hostname = self._resolve_hostname(ip)
            # Yerel makinenin hostname'i başka bir IP/MAC'e taşınamaz.
            if not is_self and hostname and local_hostname and hostname.casefold() == local_hostname.casefold():
                hostname = None
            vendor = self._get_mac_vendor(mac)
            mdns_services = mdns_map.get(ip, [])
            ssdp_info = ssdp_map.get(ip, {})

            # Do not manufacture a hostname from vendor; expose vendor separately.
            open_ports = set()
            services = []
            banners = {}
            if not is_self and not is_gateway and not fast:
                if nmap_exists:
                    nmap_data = self.nmap_service_scan(ip)
                    open_ports = set(nmap_data.get('open_ports', []))
                    services = nmap_data.get('services', [])
                else:
                    probe_ports = (22, 80, 135, 443, 445, 631, 3389, 5985, 5986, 9100, 3306, 5432, 554)
                    def probe(port):
                        try:
                            with socket.create_connection((ip, port), timeout=0.20):
                                return port
                        except OSError:
                            return None
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pe:
                        for port in pe.map(probe, probe_ports):
                            if port is not None:
                                open_ports.add(port)
                                b = self._grab_banner(ip, port)
                                if b: banners[str(port)] = b

            netbios_name = self._netbios_query(ip) if not is_self and not fast else None
            snmp_info = self._snmp_lldp_cdp_query(ip) if not is_self and not fast and (161 in open_ports or not nmap_exists) else {}
            snmp_descr = snmp_info.get("sys_descr")
            snmp_name = snmp_info.get("sys_name")
            if snmp_descr or snmp_name:
                open_ports.add(161)
                services.append({"port": 161, "protocol": "udp", "service": "snmp", "banner": snmp_descr or snmp_name})
            
            if 'location' in ssdp_info:
                xml_info = self._fetch_ssdp_xml(ssdp_info['location'])
                ssdp_info.update(xml_info)

            classification_data = self._guess_device_type(
                hostname or netbios_name or snmp_name, is_gateway=is_gateway, is_self=is_self,
                open_ports=open_ports, services=services, vendor=vendor,
                mdns_services=mdns_services, ssdp=ssdp_info, mac=mac
            )
            sources = []
            if ip in raw_map: sources.append('arp')
            if ping_results.get(ip, {}).get('success'): sources.append('icmp')
            if hostname: sources.append('dns')
            if netbios_name: sources.append('netbios')
            if vendor: sources.append('oui')
            if mdns_services: sources.append('mdns')
            if ssdp_info: sources.append('ssdp')
            if snmp_descr or snmp_name: sources.append('snmp')
            if snmp_info.get("neighbors"): sources.append('lldp')
            if nmap_exists and ip in discovery_ips: sources.append('nmap')
            if open_ports: sources.append('services')

            reason = list(classification_data.get('methods') or [])
            if not reason:
                reason = ['yeterli kanıt bulunamadı']

            icmp_ok = bool(ping_results.get(ip, {}).get('success'))
            arp_seen = ip in raw_map
            active_arp_seen = ip in active_arps
            discovered_by_other = bool(mdns_services or ssdp_info or (nmap_exists and ip in discovery_ips))
            if is_self:
                status = 'online'
                connectivity_status = 'online'
                status_reason = 'yerel cihaz'
            elif is_gateway:
                status = 'online' if icmp_ok else ('online' if active_arp_seen or arp_seen else 'discovered')
                connectivity_status = 'online' if icmp_ok else ('reachable_but_icmp_blocked' if active_arp_seen or arp_seen else 'unknown')
                status_reason = 'gateway ve ICMP yanıtı alındı' if icmp_ok else ('gateway aktif; ICMP yanıtı yok' if active_arp_seen or arp_seen else 'gateway için yeterli kanıt yok')
            elif icmp_ok:
                status = 'online'
                connectivity_status = 'online'
                status_reason = 'ICMP yanıtı alındı'
            elif active_arp_seen:
                status = 'online'
                connectivity_status = 'reachable_but_icmp_blocked'
                status_reason = 'ARP yanıtı alındı (Cihaz aktif); ICMP engelleniyor'
            elif arp_seen or discovered_by_other:
                status = 'discovered'
                connectivity_status = 'reachable_but_icmp_blocked'
                status_reason = 'Ağda önbellekte veya servis yayınında görüldü; ICMP yanıtı yok (Discovery Limitation)'
            else:
                status = 'unknown'
                connectivity_status = 'unknown'
                status_reason = 'yeterli erişilebilirlik kanıtı yok'

            identification_status = 'identified' if classification_data['type'] != 'unknown' else 'unknown'
            identification_reason = ('Cihaz tipi birden fazla kanıta göre belirlendi.' if identification_status == 'identified'
                                     else 'Cihaz ağda görüldü ancak tipi için yeterli kanıt yok.')
            now_seen = time.time()
            ttl_val = ping_results.get(ip, {}).get('ttl')
            os_fingerprint = "Windows" if ttl_val and ttl_val > 64 and ttl_val <= 128 else ("Linux/Mac" if ttl_val and ttl_val <= 64 else ("Cisco/Network" if ttl_val and ttl_val > 128 else None))

            return {
                'ip': ip,
                'mac': mac or None,
                'hostname': hostname,
                'netbios_name': netbios_name,
                'os_fingerprint': os_fingerprint,
                'ttl': ttl_val,
                'snmp_sysdescr': snmp_descr,
                'banners': banners,
                'vendor': vendor or None,
                'type': classification_data['type'],
                'online': status == 'online',
                'status': status,
                'connectivity_status': connectivity_status,
                'identification_status': identification_status,
                'status_reason': status_reason,
                'identification_reason': identification_reason,
                'icmp_reachable': icmp_ok,
                'arp_seen': arp_seen,
                'is_self': is_self,
                'wmi_info': None,
                'is_gateway': is_gateway,
                'latency': ping_results.get(ip, {}).get('latency'),
                # Tek ICMP probe başarısızlığını ağ paket kaybı olarak göstermiyoruz.
                'packet_loss': 0 if icmp_ok else None,
                'icmp_packet_loss': 0 if icmp_ok else 100,
                'last_seen': now_seen,
                'last_icmp_seen': now_seen if icmp_ok else None,
                'last_arp_seen': now_seen if arp_seen else None,
                'last_hostname_seen': now_seen if hostname else None,
                'discovery_sources': sorted(set(sources)),
                'classification': {
                    'method': classification_data['methods'],
                    'confidence': classification_data['confidence'],
                    'reason': reason,
                    'open_ports': sorted(open_ports),
                    'services': services,
                    'mdns_services': mdns_services,
                    'ssdp': ssdp_info,
                    'evidence': classification_data.get('evidence', []),
                },
            }

        # DÜZELTME: 20 worker + nmap -sV başına 20sn zaman aşımı, çok sayıda
        # aktif cihaz olan ağlarda (örn. 100 cihaz) taramayı 100 saniyeye
        # kadar uzatabiliyordu (5 dalga x 20sn). I/O-bound bekleme olduğu
        # için worker sayısını artırmak CPU maliyeti eklemeden hızı artırır.
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            devices = list(executor.map(resolve, discovery_ips))

        # Always include the local machine even if ARP is empty.
        if not any(d.get('is_self') for d in devices):
            local_class = self._guess_device_type(local_hostname, is_self=True)
            devices.insert(0, {
                'ip': local_ip, 'mac': local_mac, 'hostname': local_hostname,
                'netbios_name': None, 'os_fingerprint': "Local OS", 'ttl': None,
                'snmp_sysdescr': None, 'banners': {},
                'vendor': self._get_mac_vendor(local_mac or '') or None,
                'type': local_class['type'], 'online': True,
                'status': 'online', 'status_reason': 'yerel cihaz', 'icmp_reachable': True, 'arp_seen': True,
                'latency': 0, 'packet_loss': 0, 'icmp_packet_loss': 0,
                'connectivity_status': 'online', 'identification_status': 'identified',
                'identification_reason': 'Yerel işletim sistemi kimliği.',
                'last_seen': time.time(), 'last_icmp_seen': time.time(), 'last_arp_seen': time.time(),
                'last_hostname_seen': time.time(),
                'classification': {'method': local_class['methods'], 'confidence': local_class['confidence'], 'reason': ['yerel cihaz'], 'evidence': [{'text': 'yerel cihaz', 'source': 'self'}], 'open_ports': [], 'services': []},
                'discovery_sources': ['self'], 'is_self': True, 'is_gateway': False,
                'wmi_info': None,
            })

        # Stable ordering: gateway first, local machine second, then IP.
        devices.sort(key=lambda d: (0 if d.get('is_gateway') else 1 if d.get('is_self') else 2, d.get('ip') or ''))
        logger.info('[DISCOVERY] Enhanced scan returned %d devices', len(devices))
        return devices
    # ------------------------------------------------------------
    # NMAP ENTEGRASYONU (opsiyonel — kurulu değilse sessizce devre dışı)
    # ------------------------------------------------------------
    def get_firewall_status(self) -> dict:
        """Yalnızca YEREL makine için gerçek firewall durumu tespiti.
        Uzak cihazlarda kesin sonuç iddia edilmez (bkz. server.py firewall
        endpoint'i). Hata durumunda uygulama çökmeden 'unknown' döner."""
        try:
            if self.os_name == "Windows":
                result = self.run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
                if result.returncode != 0:
                    return {"state": "unknown", "profiles": {}, "source": "windows_netsh", "error": (result.stderr or "")[:200]}
                profiles = {}
                current = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if "domain profile" in low:
                        current = "domain"
                    elif "private profile" in low:
                        current = "private"
                    elif "public profile" in low:
                        current = "public"
                    elif current and low.startswith("state"):
                        val = line.split()[-1].strip().upper()
                        profiles[current] = "enabled" if val == "ON" else ("disabled" if val == "OFF" else "unknown")
                        current = None
                if not profiles:
                    return {"state": "unknown", "profiles": {}, "source": "windows_netsh"}
                overall = "enabled" if any(v == "enabled" for v in profiles.values()) else (
                    "disabled" if all(v == "disabled" for v in profiles.values()) else "unknown")
                return {"state": overall, "profiles": profiles, "source": "windows_netsh"}

            if self.os_name == "Linux":
                if shutil.which("ufw"):
                    result = self.run_command(["ufw", "status"])
                    if result.returncode == 0:
                        low = result.stdout.lower()
                        state = "enabled" if "status: active" in low else ("disabled" if "status: inactive" in low else "unknown")
                        return {"state": state, "profiles": {}, "source": "ufw"}
                if shutil.which("firewall-cmd"):
                    result = self.run_command(["firewall-cmd", "--state"])
                    if result.returncode == 0:
                        state = "enabled" if "running" in (result.stdout or "").lower() else "disabled"
                        return {"state": state, "profiles": {}, "source": "firewalld"}
                if shutil.which("nft"):
                    result = self.run_command(["nft", "list", "ruleset"])
                    if result.returncode == 0:
                        state = "enabled" if (result.stdout or "").strip() else "disabled"
                        return {"state": state, "profiles": {}, "source": "nftables"}
                return {"state": "unknown", "profiles": {}, "source": "none_detected"}

            return {"state": "unknown", "profiles": {}, "source": f"unsupported_os:{self.os_name}"}
        except Exception as exc:
            logger.warning("[FIREWALL] detection failed: %s", exc)
            return {"state": "unknown", "profiles": {}, "source": "error", "error": str(exc)[:200]}

    def nmap_available(self) -> bool:
        """nmap PATH'te var mı diye bakar. Binary'yi projeye gömmüyoruz,
        yalnızca kullanıcının kendi kurduğu nmap'i (varsa) çağırıyoruz."""
        if not shutil.which("nmap"):
            return False
        result = self.run_command(["nmap", "--version"])
        return result.returncode == 0

    def nmap_discover(self, network) -> set[str]:
        """`nmap -sn SUBNET` ile host discovery. Başarısız olursa boş set
        döner (çağıran taraf ARP/ping sweep sonucuna geri düşer).

        DÜZELTME: Önceden global command_timeout (5 sn) kullanılıyordu; bir
        /24 ağda bile `nmap -sn` çoğunlukla 5 saniyeden uzun sürdüğü için bu
        çağrı neredeyse her zaman zaman aşımına uğrayıp sessizce boş
        dönüyordu (nmap kurulu olsa da hiç fayda sağlamıyordu). Zaman aşımı
        artık ağ boyutuna göre ölçeklenir."""
        timeout = min(90.0, max(15.0, network.num_addresses * 0.05))
        try:
            result = self.run_command(["nmap", "-sn", str(network)], timeout=timeout)
        except Exception as exc:
            logger.warning("[NMAP] host discovery failed: %s", exc)
            return set()
        if result.returncode != 0:
            logger.warning("[NMAP] host discovery non-zero exit: %s", (result.stderr or "")[:200])
            return set()
        found = set(re.findall(r"Nmap scan report for (?:[\w.-]+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?", result.stdout))
        logger.info("[NMAP] Hosts discovered: %d", len(found))
        return found

    def nmap_service_scan(self, ip: str) -> dict:
        """Yalnızca AKTİF olduğu zaten bilinen tek bir hedefte hafif servis
        tespiti (`--top-ports 100`). Tüm subnet'te otomatik çalıştırılmaz —
        yalnızca ping/ARP ile canlı bulunan cihazlar için, ayrı ayrı çağrılır.

        DÜZELTME: Önceden global command_timeout (5 sn) kullanılıyordu.
        `-sV` servis/versiyon tespiti tek hedefte bile genelde 5 saniyeden
        uzun sürer; bu yüzden komut neredeyse her zaman zaman aşımına
        uğrayıp boş sonuç dönüyordu ve nmap'in asıl faydası (doğru servis/
        port bilgisi) hiç kullanıcıya ulaşmıyordu."""
        out = {"open_ports": [], "services": []}
        try:
            result = self.run_command(["nmap", "-sV", "--top-ports", "100", ip], timeout=20.0)
        except Exception as exc:
            logger.warning("[NMAP] service scan failed for %s: %s", ip, exc)
            return out
        if result.returncode != 0:
            return out
        for line in result.stdout.splitlines():
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
            if m:
                port, svc, banner = int(m.group(1)), m.group(2), (m.group(3) or "").strip()
                out["open_ports"].append(port)
                out["services"].append({"port": port, "service": svc, "banner": banner})
        return out

    def simulate_connection_flow(self):
        local_ip, gateway, _ = self.get_network_configuration()
        return [
            {"step": 1, "title": "Fiziksel / Link Katmanı", "desc": "[KAVRAMSAL] Ağ bağdaştırıcısı ve fiziksel link kontrol edilir."},
            {"step": 2, "title": "DHCP Keşfi (Discover)", "desc": "[KAVRAMSAL] İstemci DHCP sunucusuna yayın ile IP talebi gönderir."},
            {"step": 3, "title": "IP Tahsisi", "desc": f"[YEREL ÖLÇÜM] Şu an görülen yerel IP: {local_ip or 'Doğrulanamadı'}"},
            {"step": 4, "title": "Gateway ARP Çözümlemesi", "desc": f"[YEREL ÖLÇÜM] Şu an görülen ağ geçidi: {gateway or 'Doğrulanamadı'}"},
            {"step": 5, "title": "DNS Çözümlemesi", "desc": "[KAVRAMSAL] Alan adı için yapılandırılmış DNS sunucusuna sorgu gönderilir."},
            {"step": 6, "title": "TCP 3-Way Handshake", "desc": "[KAVRAMSAL] Uygulama trafiği öncesinde hedefle TCP el sıkışması yapılabilir."}
        ]

    def get_security_analysis(self):
        analysis = {
            "firewall_desc": "Sisteminize giren ve çıkan veri paketlerini belirli güvenlik kurallarına göre filtreleyen savunma mekanizmasıdır.",
            "webfilter_desc": "Zararlı veya şirket politikalarına aykırı web sitelerine erişimi ağ seviyesinde engelleyen sistemdir.",
            "rules": []
        }
        firewall = self.get_firewall_status()
        fw_state = firewall.get("state", "unknown")
        analysis["rules"].append({
            "name": "Yerel Güvenlik Duvarı",
            "status": {"enabled": "Açık", "disabled": "Kapalı"}.get(fw_state, "Doğrulanamadı"),
            "color": "text-green-400" if fw_state == "enabled" else "text-red-400" if fw_state == "disabled" else "text-yellow-400",
            "icon": "fa-shield",
            "source": firewall.get("source"),
        })
        local_ip, gateway, dns_servers = self.get_network_configuration()
        analysis["rules"].append({
            "name": "Ağ Geçidi Yapılandırması", "status": "Mevcut" if gateway else "Bulunamadı",
            "color": "text-green-400" if gateway else "text-yellow-400", "icon": "fa-route",
            "source": "local_network_configuration",
        })
        analysis["rules"].append({
            "name": "DNS Yapılandırması", "status": ", ".join(dns_servers) if dns_servers else "Doğrulanamadı",
            "color": "text-green-400" if dns_servers else "text-yellow-400", "icon": "fa-server",
            "source": "local_network_configuration",
        })

        return analysis

    def run_troubleshooting_wizard(self, ping_target="8.8.8.8", dns_domain="google.com", ping_count=2):
        """Otomatik Hata Tespiti ve Çözüm Sihirbazı"""
        local_ip, gateway, _ = self.get_network_configuration()

        adapter_ok = bool(local_ip)
        ping_count = max(1, min(int(ping_count or 2), 20))
        gateway_ping = self.ping_test(gateway, count=ping_count) if gateway else None
        gateway_ok = gateway_ping.success if gateway_ping else False
        dns_ok, _ = self.dns_test(dns_domain)
        internet_ok = self.ping_test(ping_target, count=ping_count).success

        issue_found = None
        recommendation = ""

        if not adapter_ok:
            issue_found = "Ağ Bağdaştırıcısı Hatası"
            recommendation = "> ipconfig /renew komutunu çalıştırın veya kabloyu kontrol edin."
        elif not gateway_ok:
            issue_found = "Ağ Geçidi (Gateway) Ulaşılamaz"
            recommendation = f"> ping {gateway} başarısız. Modem kapalı veya IP havuzu hatalı olabilir."
        elif not dns_ok:
            issue_found = "DNS Çözümleme Hatası"
            recommendation = f"> nslookup {dns_domain} komutunu çalıştırın ve yapılandırılmış DNS sunucularını kontrol edin."
        elif not internet_ok:
            issue_found = "İnternet Test Hedefine Ulaşılamadı"
            recommendation = f"> {ping_target} ICMP yanıtı vermedi. ICMP filtresi, güvenlik duvarı, rota veya İSS durumunu ayrı ayrı kontrol edin."
        else:
            issue_found = "Temel Bağlantı Kontrolleri Başarılı"
            recommendation = "Bağdaştırıcı, gateway, DNS ve seçili internet test hedefi bu ölçümde erişilebilir."

        return {
            "adapter": adapter_ok,
            "gateway": gateway_ok,
            "dns": dns_ok,
            "internet": internet_ok,
            "issue": issue_found,
            "recommendation": recommendation
        }
