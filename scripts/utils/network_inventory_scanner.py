#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 Kurumsal Ag Topolojisi & Varlik Envanter Tarayici (Enterprise Network Inventory)
================================================================================
 Rol: Kidemli Ag Muhendisi & Siber Guvenlik / SOC Analisti
 Amac: Sirket yerel agindaki (LAN/VLAN) tum cihazlari ajansiz (agentless),
       yasal sinirlar icinde (Polite Scanning), agda DoS/yuk olusturmadan,
       en derin teknik metaveriyle (IP, MAC, OUI, Hostname, Portlar, Banner, OS)
       tespit edip JSON/CSV olarak CMDB veya veri tabani icin disa aktarmak.
================================================================================
"""

import sys
import os
import time
import socket
import ssl
import json
import csv
import ipaddress
import platform
import subprocess
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional

COMMON_PORTS = {
    21: "FTP",
    22: "SSH (Yonetim)",
    23: "Telnet (Eski Yonetim)",
    53: "DNS",
    80: "HTTP (Web Arayuzu)",
    135: "RPC / MS-RPC",
    139: "NetBIOS",
    443: "HTTPS (Guvenli Web)",
    445: "SMB (Dosya Paylasimi)",
    554: "RTSP (IP Kamera Akisi)",
    631: "IPP (Yazdirma Protokolu)",
    1433: "MS SQL Server",
    3306: "MySQL / MariaDB",
    3389: "RDP (Uzak Masaustu)",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy / Web Yonetim",
    8443: "HTTPS-Alt / Yonetim",
    9100: "RAW JetDirect (Yazici)"
}

OUI_DATABASE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "F0:9F:C2": "Ubiquiti Networks",
    "24:5A:4C": "Ubiquiti Networks",
    "00:1A:A0": "Dell Inc.",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:04:F2": "Polycom",
    "00:11:32": "Synology Inc.",
    "00:08:9B": "QNAP Systems",
    "00:1E:67": "Intel Corporation",
    "3C:D9:2B": "Hewlett Packard Enterprise",
    "00:17:88": "Philips Lighting / Hue",
    "00:26:08": "Apple Inc.",
    "A4:83:E7": "Apple Inc.",
    "BC:D0:74": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "00:1A:2B": "Cisco Systems",
    "00:27:0D": "Cisco Systems",
    "CC:D5:39": "Cisco Systems",
    "48:8B:0A": "Hikvision Digital Tech (IP Camera)",
    "BC:54:51": "Dahua Technology (IP Camera)",
    "00:80:77": "Brother Industries (Printer)",
    "00:00:48": "Epson (Printer)",
    "00:1B:A9": "Canon Inc. (Printer)"
}

def get_arp_table() -> Dict[str, str]:
    arp_map = {}
    try:
        is_win = platform.system().lower() == "windows"
        cmd = ["arp", "-a"] if is_win else ["arp", "-n"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3).decode("latin-1", errors="ignore")
        ip_mac_pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
        for line in output.splitlines():
            m = ip_mac_pattern.search(line)
            if m:
                ip, mac = m.group(1), m.group(2).upper().replace("-", ":")
                arp_map[ip] = mac
    except Exception:
        pass
    return arp_map

def lookup_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Bilinmeyen Uretici"
    prefix = mac.upper()[:8]
    return OUI_DATABASE.get(prefix, "Bilinmeyen / Ozel Uretici")

def reverse_dns_lookup(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""

def get_ping_ttl(ip: str) -> Optional[int]:
    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", "500", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=1.5).decode("latin-1", errors="ignore")
        ttl_match = re.search(r"TTL=(\d+)", res, re.IGNORECASE)
        if ttl_match:
            return int(ttl_match.group(1))
        return None
    except Exception:
        return None

def grab_http_banner(ip: str, port: int) -> Dict[str, str]:
    banner = {"server": "", "title": "", "tls_subject": ""}
    scheme = "https" if port in (443, 8443) else "http"
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=0.8) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert and "subject" in cert:
                        for sub in cert["subject"]:
                            for k, v in sub:
                                if k in ("commonName", "organizationName"):
                                    banner["tls_subject"] = v
        except Exception:
            pass

    try:
        with socket.create_connection((ip, port), timeout=0.8) as s:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetMon-Auditor/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            resp = s.recv(1024).decode("latin-1", errors="ignore")
            for line in resp.splitlines():
                if line.lower().startswith("server:"):
                    banner["server"] = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass
    return banner

def grab_tcp_banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=0.8) as s:
            s.settimeout(0.8)
            banner = s.recv(512).decode("latin-1", errors="ignore").strip()
            return banner
    except Exception:
        return ""

def classify_device(ports: List[int], ttl: Optional[int], vendor: str, hostname: str, banners: Dict[str, Any]) -> str:
    h_lower = hostname.lower()
    v_lower = vendor.lower()
    if 9100 in ports or 631 in ports or 515 in ports or "printer" in h_lower or any(p in v_lower for p in ("canon", "brother", "epson", "xerox")):
        return "Yazici (Network Printer)"
    if 554 in ports or "camera" in h_lower or "hikvision" in v_lower or "dahua" in v_lower:
        return "IP Kamera / NVR"
    if (ttl and ttl > 200) or any(w in v_lower for w in ("cisco", "ubiquiti", "mikrotik", "juniper", "fortinet")) or "router" in h_lower or "switch" in h_lower:
        if "switch" in h_lower:
            return "Yonetilebilir Switch"
        return "Router / Ag Gecidi"
    if (445 in ports and 3389 in ports and 135 in ports) or 1433 in ports or 5432 in ports or 3306 in ports or "srv" in h_lower or "server" in h_lower:
        if ttl and ttl > 100:
            return "Windows Server"
        return "Linux / Veritabani Sunucusu"
    if 3389 in ports or 445 in ports or 139 in ports or (ttl and 100 < ttl <= 128):
        return "Windows Istemci (PC/Laptop)"
    if ttl and ttl <= 64:
        if "apple" in v_lower:
            return "Apple Cihaz (Mac / iPhone)"
        return "Linux / Unix / Mobil Istemci"
    return "Bilinmeyen Ag Varligi"

def inspect_host(ip: str, arp_cache: Dict[str, str]) -> Optional[Dict[str, Any]]:
    ttl = get_ping_ttl(ip)
    mac = arp_cache.get(ip, "")
    open_ports = []
    port_banners = {}

    for port, service_name in COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.25)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    if port in (80, 443, 8080, 8443):
                        b = grab_http_banner(ip, port)
                        if b.get("server") or b.get("tls_subject"):
                            port_banners[str(port)] = b
                    elif port in (21, 22):
                        b_txt = grab_tcp_banner(ip, port)
                        if b_txt:
                            port_banners[str(port)] = b_txt
        except Exception:
            pass

    if ttl is None and not mac and not open_ports:
        return None

    hostname = reverse_dns_lookup(ip)
    vendor = lookup_vendor(mac) if mac else "Bilinmeyen (ARP Yok)"
    dev_type = classify_device(open_ports, ttl, vendor, hostname, port_banners)

    os_est = "Bilinmeyen"
    if ttl:
        if ttl <= 64:
            os_est = "Linux / Unix / macOS / Embedded"
        elif ttl <= 128:
            os_est = "Microsoft Windows (NT Kernel)"
        else:
            os_est = "Cisco IOS / Network OS"

    return {
        "ip_address": ip,
        "mac_address": mac or "N/A",
        "vendor": vendor,
        "hostname": hostname or "N/A",
        "device_type": dev_type,
        "os_family_estimate": os_est,
        "icmp_ttl": ttl if ttl else "N/A",
        "status": "Online",
        "open_ports": open_ports,
        "services": [f"{p} ({COMMON_PORTS[p]})" for p in open_ports],
        "banners": port_banners,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

class NetworkInventoryScanner:
    def __init__(self, subnet_cidr: str, max_threads: int = 50):
        self.subnet_cidr = subnet_cidr
        self.max_threads = max_threads
        self.results: List[Dict[str, Any]] = []

    def run_scan(self) -> List[Dict[str, Any]]:
        print(f"\n[*] Tarama Baslatiliyor: {self.subnet_cidr}")
        print(f"[*] Eszamanli Is Parcacigi (Threads): {self.max_threads}")
        start_time = time.time()
        try:
            net = ipaddress.ip_network(self.subnet_cidr, strict=False)
            target_ips = [str(ip) for ip in net.hosts()]
        except Exception as e:
            print(f"[!] Hatali Subnet formati ({self.subnet_cidr}): {e}")
            return []

        print(f"[*] Toplam Taranacak IP Sayisi: {len(target_ips)}")
        print("[*] Yerel ARP Tablosu onbellekleniyor...")
        arp_cache = get_arp_table()

        print("[*] Paralel Kibar (Polite) Kesif yapiliyor...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(inspect_host, ip, arp_cache): ip for ip in target_ips}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    self.results.append(res)
                    print(f" [+] Kesfedildi: {res['ip_address']} | {res['hostname']} | {res['device_type']} | Portlar: {res['open_ports']}")

        elapsed = round(time.time() - start_time, 2)
        print(f"\n[?] Tarama Tamamlandi! Sure: {elapsed} saniye | Bulunan Aktif Cihaz: {len(self.results)}")
        return self.results

    def export_json(self, filename: str = "network_inventory.json"):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({
                "scan_metadata": {
                    "subnet": self.subnet_cidr,
                    "total_devices_found": len(self.results),
                    "generated_at": datetime.now().isoformat()
                },
                "assets": self.results
            }, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON Raporu Kaydedildi: {filename}")

    def export_csv(self, filename: str = "network_inventory.csv"):
        if not self.results:
            return
        keys = ["ip_address", "mac_address", "vendor", "hostname", "device_type", "os_family_estimate", "icmp_ttl", "services", "scanned_at"]
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for r in self.results:
                row = {k: r.get(k, "") for k in keys}
                if isinstance(row["services"], list):
                    row["services"] = ", ".join(row["services"])
                writer.writerow(row)
        print(f"[+] CSV Raporu Kaydedildi: {filename}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Kurumsal Ag Varlik Envanter Tarayicisi (NetMon)")
    parser.add_argument("--subnet", "-s", type=str, default="192.168.1.0/24", help="Taranacak Subnet CIDR (Orn: 192.168.1.0/24)")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Eszamanli is parcacigi sayisi")
    parser.add_argument("--json", "-j", type=str, default="network_inventory.json", help="JSON cikti dosyasi")
    parser.add_argument("--csv", "-c", type=str, default="network_inventory.csv", help="CSV cikti dosyasi")
    args = parser.parse_args()

    scanner = NetworkInventoryScanner(subnet_cidr=args.subnet, max_threads=args.threads)
    scanner.run_scan()
    scanner.export_json(args.json)
    scanner.export_csv(args.csv)
