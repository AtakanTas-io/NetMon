import concurrent.futures
import datetime
import gc
import json
import logging
import math
import socket
import threading
import time

# DÜZELTME: Bu modüller (wmi, pythoncom = pywin32) eksikse eskiden
# import anında ServerException fırlatıp TÜM backend'in (server.py) açılışını
# çökertiyordu — sadece WMI özelliği değil. Artık eksikse WMI taraması net bir
# hata mesajıyla devre dışı kalır, uygulamanın geri kalanı çalışmaya devam eder.
try:
    import pythoncom
    import wmi

    WMI_AVAILABLE = True
except ImportError:
    wmi = None
    pythoncom = None
    WMI_AVAILABLE = False

try:
    import winrm

    WINRM_AVAILABLE = True
except ImportError:
    winrm = None
    WINRM_AVAILABLE = False

# --- LOGGING YAPILANDIRMASI ---
logger = logging.getLogger("WMIScanner")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

_com_state = threading.local()


def classify_wmi_error(error: object) -> tuple[str, str]:
    """Normalize localized COM/WMI failures into stable diagnostic codes."""
    message = str(error)
    lowered = message.casefold()
    if any(
        marker in lowered
        for marker in (
            "access is denied",
            "erişim engellendi",
            "0x80070005",
            "-2147024891",
        )
    ):
        return "access_denied", "Erişim Engellendi (Access Denied)"
    if "rpc" in lowered or "0x800706ba" in lowered or "-2147023174" in lowered:
        return "rpc_unavailable", "Sunucu Kullanılamıyor veya Kapalı (RPC Error)"
    return "wmi_error", f"Hata: {message}"


def explain_wmi_error(error: object, stage: str = "wmi_dcom") -> dict:
    """Return actionable, secret-free evidence for a Windows inventory failure."""
    code, summary = classify_wmi_error(error)
    native = str(error).strip() or error.__class__.__name__
    os_error = None
    for marker in ("0x80070005", "0x800706ba", "0x8009030e", "0x80338126"):
        if marker.casefold() in native.casefold():
            os_error = marker
            break
    if code == "access_denied":
        cause = "Hedef Windows cihazı kimliği aldı ancak WMI/DCOM yetkilendirme aşamasında reddetti."
        actions = [
            "Hesabın hedef cihazın yerel Administrators grubunda veya yetkili bir domain grubunda olduğunu doğrulayın.",
            "Yerel hesap kullanılıyorsa kullanıcı adını HEDEF\\kullanıcı biçiminde deneyin; domain hesabında DOMAIN\\kullanıcı kullanın.",
            "Uzak UAC token filtering, DCOM erişim izinleri ve root\\cimv2 WMI namespace Remote Enable iznini kontrol edin.",
            "Hedefte Windows Management Instrumentation ve Remote Procedure Call servislerinin çalıştığını doğrulayın.",
        ]
    elif code == "rpc_unavailable":
        cause = "Kimlik doğrulama başlamadan önce RPC/DCOM bağlantısı kurulamadı."
        actions = [
            "TCP 135 ile dinamik RPC portlarını NetMon sunucusundan hedefe açın.",
            "Windows Güvenlik Duvarı'nda Windows Management Instrumentation (WMI-In) kural grubunu etkinleştirin.",
            "Hedefin açık, IP adresinin doğru ve RPC servisinin çalışır olduğunu doğrulayın.",
        ]
    else:
        cause = "Windows yönetim sağlayıcısı beklenmeyen bir hata döndürdü."
        actions = [
            "Ham hata ayrıntısını Windows olay günlükleri ve WMI-Activity/Operational kaydıyla eşleştirin.",
            "WinRM kullanılıyorsa listener, TrustedHosts/domain güveni ve HTTPS sertifikasını kontrol edin.",
        ]
    return {
        "stage": stage,
        "error_code": code,
        "summary": summary,
        "cause": cause,
        "native_error": native[:1200],
        "os_error_code": os_error,
        "recommended_actions": actions,
    }


def _ensure_com_initialized():
    """COM'u thread başına bir kez başlat; thread sonlandığında Windows temizler.

    wmi paketinin ürettiği bazı proxy sınıfları fonksiyon dönüşünden sonra da
    yaşayabildiğinden erken CoUninitialize, pywin32 IUnknown uyarılarına yol açar.
    """
    if not getattr(_com_state, "initialized", False):
        pythoncom.CoInitialize()
        _com_state.initialized = True


def _local_ips() -> set:
    """Bu makinenin sahip olduğu tüm IPv4 adreslerini döndürür (localhost dahil)."""
    ips = {"127.0.0.1", "localhost", "::1"}
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        import psutil

        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET:
                    ips.add(a.address)
    except Exception:
        pass
    return ips


class WmiNetworkScanner:
    """
    WMI/DCOM ve WinRM/CIM destekli paralel Windows envanter tarayıcısı.
    """

    MANAGEMENT_PORTS = (135, 445, 5985, 5986)

    def test_access(self, ip: str) -> dict:
        """Test Windows management authorization without collecting inventory."""
        ports = self._probe_management_ports(ip)
        base = {
            "ip_address": ip,
            "status": "Failed",
            "management_ports": sorted(ports),
            "diagnostics": {
                "target": ip,
                "management_ports": sorted(ports),
                "transport_attempts": [],
                "wmi_dependency_available": WMI_AVAILABLE,
                "winrm_dependency_available": WINRM_AVAILABLE,
            },
        }
        if ip not in _local_ips() and not ports:
            base.update(
                {
                    "error_code": "management_ports_closed",
                    "error_message": "Windows yönetim portlarına erişilemiyor.",
                }
            )
            return base

        if ip not in _local_ips() and (5985 in ports or 5986 in ports) and WINRM_AVAILABLE:
            port = 5986 if 5986 in ports else 5985
            scheme = "https" if port == 5986 else "http"
            base["diagnostics"]["transport_attempts"].append(f"WinRM {scheme.upper()}")
            try:
                session = winrm.Session(
                    f"{scheme}://{ip}:{port}/wsman",
                    auth=(self.username, self.password),
                    transport="ntlm",
                    server_cert_validation="validate" if self.verify_tls else "ignore",
                    operation_timeout_sec=max(5, self.timeout - 2),
                    read_timeout_sec=self.timeout,
                )
                response = session.run_ps("$env:COMPUTERNAME")
                if int(response.status_code or 0) == 0:
                    return {
                        **base,
                        "status": "Success",
                        "inventory_source": "WinRM access test",
                        "computer_name": response.std_out.decode("utf-8", "ignore").strip() or None,
                        "diagnostics": {**base["diagnostics"], "selected_transport": "WinRM"},
                    }
                stderr = response.std_err.decode("utf-8", "ignore").strip()
                raise RuntimeError(stderr or f"WinRM status code: {response.status_code}")
            except Exception as exc:
                base["diagnostics"]["winrm_failure"] = explain_wmi_error(exc, "winrm_auth_or_session")

        if not WMI_AVAILABLE:
            base.update(
                {
                    "error_code": "wmi_dependency_missing",
                    "error_message": "WinRM testi başarısız ve WMI bağımlılığı kurulu değil.",
                }
            )
            return base

        base["diagnostics"]["transport_attempts"].append("Local WMI" if ip in _local_ips() else "WMI/DCOM")
        try:
            _ensure_com_initialized()
            if ip in _local_ips():
                connection = wmi.WMI()
            elif self.username and self.password:
                connection = wmi.WMI(ip, user=self.username, password=self.password)
            else:
                connection = wmi.WMI(ip)
            systems = connection.Win32_OperatingSystem(["Caption"])
            return {
                **base,
                "status": "Success",
                "inventory_source": "WMI/DCOM access test",
                "os_caption": getattr(systems[0], "Caption", None) if systems else None,
                "diagnostics": {**base["diagnostics"], "selected_transport": "WMI/DCOM"},
            }
        except Exception as exc:
            failure = explain_wmi_error(exc, "wmi_dcom_authorization")
            base.update(
                {
                    "error_code": failure["error_code"],
                    "error_message": failure["summary"],
                }
            )
            base["diagnostics"]["failure"] = failure
            return base

    def __init__(self, username=None, password=None, timeout=20, verify_tls=True):
        self.username = username
        self.password = password
        self.timeout = max(5, min(int(timeout or 20), 60))
        self.verify_tls = bool(verify_tls)

    def _probe_management_ports(self, ip):
        """Hedefte hangi Windows yönetim kanallarının erişilebilir olduğunu bul."""
        if ip in _local_ips():
            return set(self.MANAGEMENT_PORTS)
        open_ports = set()

        def probe(port):
            try:
                with socket.create_connection((ip, port), timeout=0.8):
                    return port
            except OSError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            for port in executor.map(probe, self.MANAGEMENT_PORTS):
                if port:
                    open_ports.add(port)
        return open_ports

    def _scan_via_winrm(self, ip, open_ports):
        """WinRM açıksa ayrıntılı envanteri tek bir PowerShell/CIM çağrısıyla al."""
        if not (WINRM_AVAILABLE and self.username and self.password):
            return None
        port = 5986 if 5986 in open_ports else 5985 if 5985 in open_ports else None
        if not port:
            return None
        scheme = "https" if port == 5986 else "http"
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(self.username, self.password),
            transport="ntlm",
            server_cert_validation="validate" if self.verify_tls else "ignore",
            operation_timeout_sec=max(5, self.timeout - 2),
            read_timeout_sec=self.timeout,
        )
        script = r"""
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$board = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$chassisTypes = @()
try { $chassisTypes = @((Get-CimInstance Win32_SystemEnclosure | Select-Object -First 1).ChassisTypes) } catch {}
$gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    [ordered]@{
        drive_letter = $_.DeviceID
        total_gb = [math]::Round($_.Size / 1GB, 2)
        free_gb = [math]::Round($_.FreeSpace / 1GB, 2)
        used_gb = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
    }
})
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$programs = @(Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object DisplayName | Sort-Object DisplayName -Unique |
    Select-Object -First 500 | ForEach-Object {
        [ordered]@{ name = $_.DisplayName; version = $_.DisplayVersion }
    })
$firewall = 'Bilinmiyor'
try {
    $enabled = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object Enabled)
    $firewall = if ($enabled.Count -gt 0) { 'Açık' } else { 'Kapalı' }
} catch {}
$antivirus = 'Bilinmiyor'
try {
    $names = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object displayName)
    if ($names.Count -gt 0) { $antivirus = $names -join ', ' }
} catch {}
[ordered]@{
    computer_name = $cs.Name
    system = [ordered]@{
        computer_name = $cs.Name
        pc_system_type = $cs.PCSystemType
        domain_role = $cs.DomainRole
        os_product_type = $os.ProductType
        chassis_types = $chassisTypes
    }
    hardware = [ordered]@{
        motherboard_maker = $board.Manufacturer
        motherboard_model = $board.Product
        cpu_model = $cpu.Name
        cores = $cpu.NumberOfLogicalProcessors
        ram_gb = [math]::Ceiling($cs.TotalPhysicalMemory / 1GB)
        gpu = $gpus -join ', '
    }
    storage = $disks
    software = [ordered]@{
        os_name = $os.Caption
        os_build = $os.BuildNumber
        os_architecture = $os.OSArchitecture
        installed_programs = $programs
        product_key = (Get-CimInstance SoftwareLicensingService | Select-Object -ExpandProperty OA3xOriginalProductKey -ErrorAction SilentlyContinue)
    }
    security = [ordered]@{
        active_user = $cs.UserName
        firewall = $firewall
        antivirus = $antivirus
    }
} | ConvertTo-Json -Depth 7 -Compress
"""
        response = session.run_ps(script)
        if response.status_code != 0:
            error = (response.std_err or b"").decode("utf-8", "ignore").strip()
            raise RuntimeError(error or f"WinRM status {response.status_code}")
        payload = json.loads((response.std_out or b"").decode("utf-8-sig", "ignore"))
        payload.update(
            {
                "ip_address": ip,
                "status": "Success",
                "inventory_source": "WinRM/CIM",
                "last_scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        )
        return payload

    def _get_software_from_registry(self, c_wmi):
        """Uzak bilgisayarın kayıt defterini okuyarak yazılım listesini hızla çeker."""
        software_list = []
        try:
            # StdRegProv üzerinden uzak kayıt defteri (HKLM) sorgusu
            registry = c_wmi.StdRegProv
            hDefKey = 0x80000002  # HKEY_LOCAL_MACHINE
            uninstall_paths = (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            )
            seen = set()
            for root_path in uninstall_paths:
                result, subkeys = registry.EnumKey(hDefKey=hDefKey, sSubKeyName=root_path)
                if result != 0 or not subkeys:
                    continue
                for subkey in subkeys:
                    path = root_path + "\\" + subkey
                    res_name, disp_name = registry.GetStringValue(
                        hDefKey=hDefKey, sSubKeyName=path, sValueName="DisplayName"
                    )
                    normalized_name = (disp_name or "").strip()
                    if res_name != 0 or not normalized_name or normalized_name.casefold() in seen:
                        continue
                    seen.add(normalized_name.casefold())
                    _, version = registry.GetStringValue(hDefKey=hDefKey, sSubKeyName=path, sValueName="DisplayVersion")
                    software_list.append({"name": normalized_name, "version": version or None})
        except Exception as e:
            logger.debug(f"Registry okuma hatası: {e}")
        return software_list

    def _scan_single_ip(self, ip):
        """Tek bir IP adresine bağlanıp tüm donanım, yazılım ve güvenlik verilerini toplar."""
        device_data = {
            "ip_address": ip,
            "status": "Failed",
            "error_message": "",
            "error_code": "",
            "last_scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        open_ports = self._probe_management_ports(ip)
        device_data["management_ports"] = sorted(open_ports)
        device_data["diagnostics"] = {
            "target": ip,
            "management_ports": sorted(open_ports),
            "transport_attempts": [],
            "wmi_dependency_available": WMI_AVAILABLE,
            "winrm_dependency_available": WINRM_AVAILABLE,
        }
        if ip not in _local_ips() and not open_ports:
            device_data["error_code"] = "management_ports_closed"
            device_data["error_message"] = (
                "Hedefte Windows yönetim portlarına erişilemiyor. Hedefin Windows olduğundan, "
                "çevrimiçi olduğundan ve WMI (TCP 135 + RPC) veya WinRM (5985/5986) "
                "güvenlik duvarı kurallarının tarayıcı IP'sine açık olduğundan emin olun."
            )
            return device_data

        if ip not in _local_ips() and (5985 in open_ports or 5986 in open_ports):
            try:
                device_data["diagnostics"]["transport_attempts"].append(
                    "WinRM HTTPS" if 5986 in open_ports else "WinRM HTTP"
                )
                winrm_data = self._scan_via_winrm(ip, open_ports)
                if winrm_data:
                    winrm_data.setdefault("diagnostics", device_data["diagnostics"])["selected_transport"] = "WinRM"
                    logger.info(f"[{ip}] WinRM taraması başarılı: {winrm_data.get('computer_name', ip)}")
                    return winrm_data
            except Exception as exc:
                device_data["diagnostics"]["winrm_failure"] = explain_wmi_error(exc, "winrm_auth_or_session")
                logger.warning(f"[{ip}] WinRM başarısız, WMI/DCOM deneniyor: {exc}")

        # WinRM, Python WMI paketinden bağımsızdır. Bu kontrol WinRM denemesinden
        # sonra yapılmalıdır; aksi halde yalnız WinRM açılmış hedefler hiç taranmaz.
        if not WMI_AVAILABLE:
            device_data["error_code"] = "wmi_dependency_missing"
            device_data["error_message"] = (
                "WinRM ile envanter alınamadı ve WMI desteği kurulu değil (pywin32/wmi paketleri eksik)."
            )
            return device_data

        _ensure_com_initialized()
        connection = registry_connection = sec_conn = None
        cs = os_info = cpu = baseboard = disk = av_products = None
        try:
            device_data["diagnostics"]["transport_attempts"].append("Local WMI" if ip in _local_ips() else "WMI/DCOM")
            # WMI Bağlantısı (5sn Timeout destekli via wmi.WMI connect timeout)
            # Standart 'wmi' modülünde timeout ayarı WbemScripting üzerinden yapılır fakat pywin32 DCOM timeout globaldir.
            # Kodun kilitlenmesini ThreadPoolExecutor yönetir.
            # DÜZELTME: Kendi bilgisayarınızın LAN IP'sine (örn. 192.168.1.102)
            # wmi.WMI(ip) ile bağlanmak DCOM/RPC üzerinden "uzak" bağlantı
            # sayılır ve kimlik bilgisi ister — kendi makineniz olsa bile.
            # Sadece parametresiz wmi.WMI() yerel/in-process COM kullanır ve
            # kimlik bilgisi istemez. Bu yüzden kendi IP'niz için kimlik
            # bilgisi girmeden "Access Denied" alınıyordu.
            if ip in _local_ips():
                connection = wmi.WMI()
            elif self.username and self.password:
                connection = wmi.WMI(ip, user=self.username, password=self.password)
            else:
                connection = wmi.WMI(ip)

            # --- DONANIM BİLGİLERİ ---
            cs = connection.Win32_ComputerSystem()[0]
            os_info = connection.Win32_OperatingSystem()[0]
            cpu = connection.Win32_Processor()[0]

            try:
                gpu_list = [g.Name for g in connection.Win32_VideoController()]
                gpu_name = gpu_list[0] if gpu_list else "Bilinmiyor"
            except Exception:
                gpu_name = "Bilinmiyor"

            try:
                baseboard = connection.Win32_BaseBoard()[0]
                mb_maker = baseboard.Manufacturer
                mb_model = baseboard.Product
            except Exception:
                mb_maker, mb_model = "Bilinmiyor", "Bilinmiyor"

            try:
                enclosure = connection.Win32_SystemEnclosure()[0]
                chassis_types = [int(value) for value in (enclosure.ChassisTypes or [])]
            except Exception:
                chassis_types = []

            # Disk Bilgileri
            disks = []
            for disk in connection.Win32_LogicalDisk(DriveType=3):
                total_gb = round(int(disk.Size) / (1024**3), 2) if disk.Size else 0
                free_gb = round(int(disk.FreeSpace) / (1024**3), 2) if disk.FreeSpace else 0
                disks.append(
                    {
                        "drive_letter": disk.DeviceID,
                        "total_gb": total_gb,
                        "free_gb": free_gb,
                        "used_gb": round(total_gb - free_gb, 2),
                    }
                )

            # --- YAZILIM BİLGİLERİ ---
            try:
                if ip in _local_ips():
                    registry_connection = wmi.WMI(namespace=r"root\default")
                elif self.username and self.password:
                    registry_connection = wmi.WMI(
                        ip, namespace=r"root\default", user=self.username, password=self.password
                    )
                else:
                    registry_connection = wmi.WMI(ip, namespace=r"root\default")
                software_list = self._get_software_from_registry(registry_connection)
            except Exception:
                software_list = []

            # --- GÜVENLİK BİLGİLERİ ---
            active_user = cs.UserName or "Oturum Açılmamış"

            # Antivirüs (ROOT\SecurityCenter2)
            av_name = "Bulunamadı"
            try:
                if ip in _local_ips():
                    sec_conn = wmi.WMI(namespace=r"root\SecurityCenter2")
                elif self.username and self.password:
                    sec_conn = wmi.WMI(
                        ip, namespace=r"root\SecurityCenter2", user=self.username, password=self.password
                    )
                else:
                    sec_conn = wmi.WMI(ip, namespace=r"root\SecurityCenter2")

                av_products = sec_conn.AntiVirusProduct()
                if av_products:
                    av_name = ", ".join([av.displayName for av in av_products])
            except Exception:
                av_name = "Erişim Yok veya Kurum Dışı"

            # Firewall durumu standart CIMv2 sınıflarıyla güvenilir biçimde
            # belirlenemez. Yanlış "Açık" sonucu üretmek yerine bilinmiyor bırakılır.
            fw_status = "Bilinmiyor"

            # Verileri Topla
            device_data.update(
                {
                    "status": "Success",
                    "inventory_source": "WMI/DCOM" if ip not in _local_ips() else "Local WMI",
                    "computer_name": cs.Name,
                    "system": {
                        "computer_name": cs.Name,
                        "pc_system_type": getattr(cs, "PCSystemType", None),
                        "domain_role": getattr(cs, "DomainRole", None),
                        "os_product_type": getattr(os_info, "ProductType", None),
                        "chassis_types": chassis_types,
                    },
                    "hardware": {
                        "motherboard_maker": mb_maker,
                        "motherboard_model": mb_model,
                        "cpu_model": cpu.Name.strip(),
                        "cores": cpu.NumberOfLogicalProcessors or cpu.NumberOfCores,
                        "ram_gb": math.ceil(int(cs.TotalPhysicalMemory) / (1024**3)),
                        "gpu": gpu_name,
                    },
                    "storage": disks,
                    "software": {
                        "os_name": os_info.Caption,
                        "os_build": os_info.BuildNumber,
                        "os_architecture": os_info.OSArchitecture,
                        "installed_programs": software_list,
                        "product_key": getattr(connection.SoftwareLicensingService()[0], "OA3xOriginalProductKey", None)
                        if connection.SoftwareLicensingService()
                        else None,
                    },
                    "security": {"active_user": active_user, "firewall": fw_status, "antivirus": av_name},
                }
            )
            device_data["diagnostics"]["selected_transport"] = "Local WMI" if ip in _local_ips() else "WMI/DCOM"
            logger.info(f"[{ip}] Tarama başarılı: {cs.Name}")

        except Exception as e:
            error_code, msg = classify_wmi_error(e)
            device_data["error_code"] = error_code
            device_data["error_message"] = msg
            device_data["diagnostics"]["failure"] = explain_wmi_error(e, "wmi_dcom_authorization")
            logger.error(f"[{ip}] Tarama hatası: {msg}")

        finally:
            av_products = disk = baseboard = cpu = os_info = cs = None
            sec_conn = registry_connection = connection = None
            gc.collect()

        return device_data

    def scan_network(self, ip_list, max_workers=10):
        """
        Verilen IP listesini ThreadPoolExecutor ile paralel olarak tarar.
        """
        logger.info(f"{len(ip_list)} adet IP için tarama başlatılıyor (Max Thread: {max_workers})...")
        max_workers = max(1, min(int(max_workers or 10), 25))
        semaphore = threading.Semaphore(max_workers)
        slots = [None] * len(ip_list)

        def worker(index, ip):
            with semaphore:
                try:
                    slots[index] = self._scan_single_ip(ip)
                except Exception as exc:
                    logger.error(f"[{ip}] Beklenmedik thread hatası: {exc}")
                    slots[index] = {
                        "ip_address": ip,
                        "status": "Failed",
                        "error_code": "thread_exception",
                        "error_message": str(exc),
                    }

        threads = []
        for index, ip in enumerate(ip_list):
            thread = threading.Thread(target=worker, args=(index, ip), daemon=True)
            thread.start()
            threads.append(thread)

        deadline = time.monotonic() + self.timeout + 3
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))

        results = []
        for ip, data in zip(ip_list, slots):
            results.append(
                data
                or {
                    "ip_address": ip,
                    "status": "Failed",
                    "error_code": "timeout",
                    "error_message": f"WMI/WinRM taraması {self.timeout} saniye içinde tamamlanmadı.",
                }
            )

        logger.info("Tarama işlemi tamamlandı.")
        return results
