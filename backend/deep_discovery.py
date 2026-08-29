"""
deep_discovery.py
Ağ cihazları için ajansız (agentless) derin envanter ve teşhis modülü.
Windows (WinRM/WMI), Linux (Paramiko/SSH) ve Ağ Cihazları (SNMP) için
bağımsız derin tarama fonksiyonları ve akıllı entegrasyon motoru içerir.
"""

import concurrent.futures
import gc
import logging
import socket
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("netmon.deep_discovery")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# Opsiyonel 3. parti kütüphanelerin dinamik kontrolü (yoksa fallback yöntemler çalışır)
try:
    import winrm

    HAS_WINRM = True
except ImportError:
    HAS_WINRM = False

try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import pythoncom
    import wmi

    HAS_WMI = True
except ImportError:
    HAS_WMI = False

_com_state = threading.local()


def _ensure_com_initialized():
    if not getattr(_com_state, "initialized", False):
        pythoncom.CoInitialize()
        _com_state.initialized = True


# ============================================================
# 1. WINDOWS DERİN TARAMA MODÜLÜ (WinRM / WMI)
# ============================================================
def scan_windows_deep(ip: str, username: str = "", password: str = "", timeout: int = 6) -> Dict[str, Any]:
    """
    Windows cihazlar için pywinrm veya WMI/PowerShell kullanarak Donanım & Yazılım detaylarını çeker.
    (CPU, RAM, Seri No, Yüklü Yazılımlar, İşletim Sistemi)
    """
    result: Dict[str, Any] = {
        "status": "Failed",
        "os_family": "Windows",
        "error": "",
        "hardware": {},
        "software": {},
        "system": {},
    }

    # 1. Yöntem: WinRM kütüphanesi (Port 5985/5986)
    if HAS_WINRM and username and password:
        try:
            session = winrm.Session(
                f"http://{ip}:5985/wsman",
                auth=(username, password),
                transport="ntlm",
                server_cert_validation="ignore",
                operation_timeout_sec=max(5, timeout - 1),
                read_timeout_sec=timeout,
            )
            ps_script = """
            $sys = Get-CimInstance Win32_ComputerSystem
            $bios = Get-CimInstance Win32_BIOS
            $os = Get-CimInstance Win32_OperatingSystem
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            @{
                ComputerName = $sys.Name
                Manufacturer = $sys.Manufacturer
                Model = $sys.Model
                SerialNumber = $bios.SerialNumber
                OS = $os.Caption
                OSVersion = $os.Version
                RAM_GB = [math]::Round($sys.TotalPhysicalMemory / 1GB, 2)
                CPU = $cpu.Name
                Cores = $cpu.NumberOfCores
            } | ConvertTo-Json
            """
            res = session.run_ps(ps_script)
            if res.status_code == 0 and res.std_out:
                import json

                data = json.loads(res.std_out.decode("utf-8", "ignore"))
                result["hardware"] = {
                    "cpu_model": data.get("CPU"),
                    "cores": data.get("Cores"),
                    "ram_gb": data.get("RAM_GB"),
                    "motherboard_maker": data.get("Manufacturer"),
                    "motherboard_model": data.get("Model"),
                    "serial_number": data.get("SerialNumber"),
                }
                result["system"] = {
                    "computer_name": data.get("ComputerName"),
                    "os_name": data.get("OS"),
                    "os_build": data.get("OSVersion"),
                }
                result["software"] = {
                    "os_name": data.get("OS"),
                    "os_build": data.get("OSVersion"),
                    "installed_programs": [],
                }
                result["status"] = "Success"
                result["inventory_source"] = "WinRM/CIM"
                return result
        except Exception as exc:
            logger.debug(f"[WinRM] {ip} bağlantı hatası: {exc}")

    # 2. Yöntem: WMI (pywin32 / wmi)
    if HAS_WMI and ip in ("127.0.0.1", "localhost", "::1"):
        try:
            _ensure_com_initialized()
            try:
                c = wmi.WMI()
                cs = c.Win32_ComputerSystem()[0]
                bios = c.Win32_BIOS()[0]
                os_info = c.Win32_OperatingSystem()[0]
                cpu = c.Win32_Processor()[0]
                result["hardware"] = {
                    "cpu_model": cpu.Name.strip(),
                    "cores": getattr(cpu, "NumberOfCores", None),
                    "ram_gb": round(int(cs.TotalPhysicalMemory) / (1024**3), 2),
                    "motherboard_maker": cs.Manufacturer,
                    "motherboard_model": cs.Model,
                    "serial_number": getattr(bios, "SerialNumber", None),
                }
                result["system"] = {"computer_name": cs.Name, "os_name": os_info.Caption, "os_build": os_info.Version}
                result["status"] = "Success"
                result["inventory_source"] = "Local WMI"
                return result
            finally:
                c = cs = bios = os_info = cpu = None
                gc.collect()
        except Exception as exc:
            logger.debug(f"[WMI Local] {ip} hatası: {exc}")

    # Erişim yoksa donanım değeri üretme; yalnızca açık bir hata döndür.
    result["error"] = "Kimlik bilgisi verilmedi veya WinRM/WMI erişimi engellendi."
    result["status"] = "Failed"
    return result


# ============================================================
# 2. LINUX DERİN TARAMA MODÜLÜ (Paramiko / SSH)
# ============================================================
def test_ssh_access(ip: str, username: str, password: str = "", timeout: int = 5) -> Dict[str, Any]:
    """Validate SSH connectivity/authentication without collecting inventory."""
    result: Dict[str, Any] = {"status": "Failed", "error_code": "ssh_failed", "error": ""}
    if not HAS_PARAMIKO:
        result.update({"error_code": "ssh_dependency_missing", "error": "Paramiko SSH bağımlılığı kurulu değil."})
        return result
    if not username:
        result.update({"error_code": "missing_credentials", "error": "SSH kullanıcı adı gerekli."})
        return result
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            ip,
            port=22,
            username=username,
            password=password or None,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        transport = client.get_transport()
        result.update(
            {
                "status": "Success",
                "error_code": "",
                "server_version": getattr(transport, "remote_version", None),
            }
        )
    except Exception as exc:
        message = str(exc)
        lowered = message.casefold()
        if "authentication failed" in lowered or "permission denied" in lowered:
            code = "ssh_auth_failed"
        elif "host key" in lowered or "not found in known_hosts" in lowered:
            code = "ssh_host_key_rejected"
        elif "timed out" in lowered or "refused" in lowered or "unreachable" in lowered:
            code = "ssh_unreachable"
        else:
            code = "ssh_failed"
        result.update({"error_code": code, "error": message[:1200]})
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result


def scan_linux_deep(
    ip: str, username: str = "root", password: str = "", key_filename: Optional[str] = None, timeout: int = 5
) -> Dict[str, Any]:
    """
    Linux cihazlar için Paramiko (SSH) veya sistem SSH istemcisi kullanarak
    'uname', 'lshw', 'dpkg'/'rpm' gibi komutlarla Donanım ve Yazılım detaylarını çeker.
    """
    result: Dict[str, Any] = {
        "status": "Failed",
        "os_family": "Linux",
        "error": "",
        "hardware": {},
        "software": {},
        "system": {},
    }

    if HAS_PARAMIKO and username:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                ip,
                port=22,
                username=username,
                password=password if password else None,
                key_filename=key_filename,
                timeout=timeout,
                banner_timeout=timeout,
            )

            # SSH komutlarını yürüt
            def run_cmd(cmd):
                # cmd her zaman sabit kodlanmış literal; kullanıcı girdisi karışmıyor
                stdin, stdout, stderr = client.exec_command(cmd, timeout=3)  # nosec B601
                return stdout.read().decode("utf-8", "ignore").strip()

            uname = run_cmd("uname -a")
            os_rel = run_cmd("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'")
            cpu_name = run_cmd(
                "lscpu 2>/dev/null | grep 'Model name' | cut -d':' -f2 | sed 's/^[[:space:]]*//' || cat /proc/cpuinfo | grep 'model name' | head -n1 | cut -d':' -f2"
            )
            ram_info = run_cmd("free -m 2>/dev/null | grep Mem | awk '{print $2}'")
            cpu_cores = run_cmd("nproc 2>/dev/null")
            manufacturer = run_cmd("cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
            model = run_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null")
            serial_no = run_cmd("cat /sys/class/dmi/id/product_serial 2>/dev/null")
            host_name = run_cmd("hostname 2>/dev/null")
            architecture = run_cmd("uname -m 2>/dev/null")
            active_user = run_cmd("who 2>/dev/null | awk 'NR==1 {print $1}'")
            firewall = run_cmd(
                "if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -n1; elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>/dev/null; elif command -v nft >/dev/null 2>&1; then nft list ruleset 2>/dev/null | head -n1; fi"
            )
            disk_info = run_cmd("df -B1 -P -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2")
            pkgs = run_cmd(
                "dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | head -n 500 || rpm -qa 2>/dev/null | head -n 500"
            )

            ram_gb = round(int(ram_info) / 1024, 2) if ram_info.isdigit() else None

            installed_sw = []
            for line in pkgs.splitlines():
                parts = line.split()
                if parts:
                    installed_sw.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else None})

            storage = []
            for line in disk_info.splitlines():
                parts = line.split(None, 5)
                if len(parts) < 6 or not all(value.isdigit() for value in parts[1:4]):
                    continue
                total_bytes, used_bytes, free_bytes = map(int, parts[1:4])
                storage.append(
                    {
                        "drive_letter": parts[5],
                        "filesystem": parts[0],
                        "total_gb": round(total_bytes / (1024**3), 2),
                        "used_gb": round(used_bytes / (1024**3), 2),
                        "free_gb": round(free_bytes / (1024**3), 2),
                    }
                )

            result["hardware"] = {
                "cpu_model": cpu_name.strip() or None,
                "cores": int(cpu_cores) if cpu_cores.isdigit() else None,
                "ram_gb": ram_gb,
                "motherboard_maker": manufacturer or None,
                "motherboard_model": model or None,
                "serial_number": serial_no or None,
            }
            result["system"] = {
                "computer_name": host_name or None,
                "os_name": os_rel or None,
                "kernel": uname or None,
                "architecture": architecture or None,
            }
            result["software"] = {"os_name": os_rel or None, "installed_programs": installed_sw}
            result["storage"] = storage
            result["security"] = {
                "active_user": active_user or None,
                "firewall": firewall or "Bilinmiyor",
                "antivirus": "Bilinmiyor",
            }
            result["status"] = "Success"
            result["inventory_source"] = "SSH"
            return result
        except Exception as exc:
            logger.debug(f"[Paramiko SSH] {ip} bağlantı hatası: {exc}")
            result["error"] = str(exc)
        finally:
            try:
                client.close()
            except Exception:
                pass

    if not result.get("error"):
        result["error"] = "SSH kimlik bilgisi, bilinen host anahtarı veya Paramiko eksik."
    result["status"] = "Failed"
    return result


# ============================================================
# 3. AĞ CİHAZLARI MODÜLÜ (PySNMP / SNMP)
# ============================================================
def scan_snmp_deep(ip: str, community: str = "public", timeout: float = 1.0) -> Dict[str, Any]:
    """
    Yazıcı, Router, Switch ve Access Point gibi ağ cihazları için SNMP ile
    sysDescr, sysName, sysObjectID ve donanım tanımlarını çeker.
    """
    result: Dict[str, Any] = {
        "status": "Failed",
        "os_family": "Network Firmware",
        "hardware": {},
        "system": {},
        "software": {},
    }

    if not community:
        result["error"] = "SNMP salt-okuma community yapılandırılmamış."
        return result

    sys_descr = None
    sys_name = None
    # İki OID art arda sorgulandığı için kullanıcıdan gelen süreyi her
    # sokete aynen vermek toplam beklemeyi iki katına çıkarıyordu. Süreyi
    # OID'ler arasında bölerek fonksiyonun toplam zaman aşımına uymasını sağla.
    per_oid_timeout = max(0.2, float(timeout) / 2.0)

    # Socket-based lightweight BER-SNMP GET
    def snmp_get_oid(oid_bytes: bytes) -> Optional[str]:
        comm_bytes = community.encode("ascii", "ignore")
        varbind = (
            b"\x30" + bytes([2 + len(oid_bytes) + 2]) + b"\x06" + bytes([len(oid_bytes)]) + oid_bytes + b"\x05\x00"
        )
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        pdu = (
            b"\xa0"
            + bytes([len(varbind_list) + 14])
            + b"\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00"
            + varbind_list
        )
        msg = (
            b"\x30"
            + bytes([len(pdu) + len(comm_bytes) + 7])
            + b"\x02\x01\x00\x04"
            + bytes([len(comm_bytes)])
            + comm_bytes
            + pdu
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(per_oid_timeout)
        try:
            sock.sendto(msg, (ip, 161))
            data, _ = sock.recvfrom(2048)
            idx = data.rfind(b"\x04")
            if idx != -1 and idx + 1 < len(data):
                length = data[idx + 1]
                if idx + 2 + length <= len(data):
                    return data[idx + 2 : idx + 2 + length].decode("ascii", "ignore").strip()
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    sys_descr = snmp_get_oid(b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    sys_name = snmp_get_oid(b"\x2b\x06\x01\x02\x01\x01\x05\x00")

    if sys_descr or sys_name:
        descr = sys_descr or ""
        result["hardware"] = {"cpu_model": None, "ram_gb": None, "motherboard_maker": None, "serial_number": None}
        result["system"] = {"sys_name": sys_name, "sys_descr": descr or None, "os_name": None}
        result["status"] = "Success"
        result["inventory_source"] = "SNMP"
        return result

    result["error"] = "SNMP yanıtı alınamadı; community/ACL/UDP 161 ayarlarını kontrol edin."
    result["status"] = "Failed"
    return result


# ============================================================
# 4. AKILLI KARAR MOTORU (INTEGRATION FLOW)
# ============================================================
def integrate_discovery_flow(
    device_data: Dict[str, Any], credentials: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Cihazın IP ve açık portlarını analiz eder:
    - Port 135 veya 5985 açık ise -> Windows (WinRM/WMI) modülünü tetikler.
    - Port 22 açık ise -> Linux (SSH/Paramiko) modülünü tetikler.
    - Port 161 açık ise -> SNMP modülünü tetikler.
    - Portlar kapalıysa veya kimlik doğrulaması başarısız olursa (Try-Except),
      uygulama ASLA çökmez; mevcut temel bilgiler (IP, MAC, Tahmini OS) korunur.
    """
    if not credentials:
        credentials = {}

    ip = device_data.get("ip") or ""
    open_ports = set(device_data.get("open_ports") or [])
    if isinstance(device_data.get("classification"), dict):
        open_ports.update(device_data["classification"].get("open_ports") or [])

    w_user = credentials.get("wmi_username") or credentials.get("username") or ""
    w_pass = credentials.get("wmi_password") or credentials.get("password") or ""
    l_user = credentials.get("ssh_username") or "root"
    l_pass = credentials.get("ssh_password") or ""
    snmp_comm = credentials.get("snmp_community") or ""

    deep_info: Dict[str, Any] = {"status": "Unavailable", "hardware": {}, "software": {}, "system": {}}

    try:
        # Karar 1: Windows (Port 135 veya 5985)
        if 135 in open_ports or 5985 in open_ports or 5986 in open_ports or 445 in open_ports or 3389 in open_ports:
            logger.info(f"[DECISION ENGINE] Triggering Windows deep scan for {ip}")
            deep_info = scan_windows_deep(ip, username=w_user, password=w_pass)

        # Karar 2: Linux (Port 22)
        elif 22 in open_ports:
            logger.info(f"[DECISION ENGINE] Triggering Linux SSH deep scan for {ip}")
            deep_info = scan_linux_deep(ip, username=l_user, password=l_pass)

        # Karar 3: Network Device (Port 161)
        elif 161 in open_ports:
            logger.info(f"[DECISION ENGINE] Triggering SNMP deep scan for {ip}")
            deep_info = scan_snmp_deep(ip, community=snmp_comm)

        # Karar 4: doğrulanabilir bir yönetim protokolü yok.
        else:
            logger.info(f"[DECISION ENGINE] No authorized management protocol for {ip}")
            deep_info = {
                "status": "Unavailable",
                "hardware": {},
                "software": {},
                "system": {},
                "error": "WMI/WinRM, SSH veya SNMP erişimi doğrulanamadı.",
            }

    except Exception as exc:
        logger.warning(f"[DECISION ENGINE] Safe exception catch for {ip}: {exc}")
        deep_info["status"] = "Failed"
        deep_info["error"] = str(exc)

    # Temel cihaz verisiyle birleştir ve döndür
    merged = dict(device_data)
    merged["deep_inventory"] = deep_info
    if deep_info.get("status") == "Success" and deep_info.get("hardware"):
        merged["fallback_inventory"] = {
            "status": deep_info.get("status", "Unavailable"),
            "hardware": deep_info.get("hardware"),
            "software": deep_info.get("software", {}),
            "security": {
                "active_user": deep_info.get("system", {}).get("computer_name"),
                "firewall": deep_info.get("security", {}).get("firewall", "Bilinmiyor"),
                "antivirus": deep_info.get("security", {}).get("antivirus", "Bilinmiyor"),
            },
        }
    return merged


def parallel_integrate_discovery_flow(
    devices_list: List[Dict[str, Any]], credentials: Optional[Dict[str, Any]] = None, max_workers: int = 15
) -> List[Dict[str, Any]]:
    """
    Ağdaki tüm cihazlar için ThreadPoolExecutor kullanarak asenkron/paralel derin tarama yürütür.
    """
    if not devices_list:
        return []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(integrate_discovery_flow, dev, credentials) for dev in devices_list]
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception as exc:
                logger.warning(f"[PARALLEL DISCOVERY] Thread exception: {exc}")

    # Orijinal IP sırasını koru
    ip_order = {d.get("ip"): i for i, d in enumerate(devices_list)}
    results.sort(key=lambda x: ip_order.get(x.get("ip"), 999))
    return results
