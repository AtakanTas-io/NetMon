"""IP adres yönetimi, subnet kapasitesi ve çakışma API uçları."""

import collections
import ipaddress

from fastapi import APIRouter, Depends


def create_ipam_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/ipam")
    def get_ipam_data(user: dict = Depends(ctx.get_current_user)):
        devices = ctx._devices_cache.get("data", [])
        gateway = ctx._last_status.get("gateway") or ""

        ip_to_macs: dict[str, set[str]] = {}
        ip_to_devices: dict[str, list[dict]] = {}
        for device in devices:
            ip = device.get("ip")
            mac = device.get("mac")
            if ip and mac:
                ip_to_macs.setdefault(ip, set()).add(mac)
                ip_to_devices.setdefault(ip, []).append(device)

        conflicts = []
        for ip, macs in ip_to_macs.items():
            if len(macs) <= 1:
                continue
            matching_devices = ip_to_devices.get(ip, [])
            sorted_macs = sorted(macs)
            conflicts.append(
                {
                    "ip": ip,
                    "macs": sorted_macs,
                    "hostnames": [
                        device.get("hostname") or device.get("friendly_name") or "Bilinmeyen"
                        for device in matching_devices
                    ],
                    "severity": "critical",
                    "message": (
                        f"{ip} adresi {len(macs)} farklı MAC adresi "
                        f"({', '.join(sorted_macs)}) tarafından aynı anda talep ediliyor!"
                    ),
                }
            )

        try:
            network_context = ctx.diag.get_network_context() or {}
        except Exception:
            network_context = {}

        observed_ips: list[ipaddress.IPv4Address] = []
        for device in devices:
            try:
                observed_ip = ipaddress.ip_address(device.get("ip") or "")
                if (
                    isinstance(observed_ip, ipaddress.IPv4Address)
                    and not observed_ip.is_loopback
                    and not observed_ip.is_multicast
                ):
                    observed_ips.append(observed_ip)
            except ValueError:
                continue

        network: ipaddress.IPv4Network | None = None
        subnet_source = None
        try:
            context_network = ipaddress.ip_network(network_context.get("cidr") or "", strict=False)
            if isinstance(context_network, ipaddress.IPv4Network):
                network = context_network
                subnet_source = "local_interface"
        except ValueError:
            pass

        if observed_ips and (network is None or not any(ip in network for ip in observed_ips)):
            buckets = collections.Counter(
                ipaddress.IPv4Network(f"{ip}/24", strict=False) for ip in observed_ips if ip.is_private
            )
            if buckets:
                network = buckets.most_common(1)[0][0]
                subnet_source = "derived_from_observations"

        if network is not None:
            reserved_hosts = 2 if network.prefixlen <= 30 else 0
            total_ips = max(0, network.num_addresses - reserved_hosts)
            used_set = {
                ip
                for ip in observed_ips
                if ip in network and ip not in (network.network_address, network.broadcast_address)
            }
            effective_gateway = None
            gateway_candidates = [gateway, network_context.get("gateway")]
            gateway_candidates.extend(device.get("ip") for device in devices if device.get("is_gateway"))
            for gateway_candidate in gateway_candidates:
                try:
                    gateway_ip = ipaddress.IPv4Address(gateway_candidate or "")
                    if gateway_ip in network:
                        effective_gateway = str(gateway_ip)
                        used_set.add(gateway_ip)
                        break
                except ValueError:
                    continue
            used_ips = len(used_set)
            free_ips = max(0, total_ips - used_ips)
            utilization_pct = round(used_ips / total_ips * 100, 1) if total_ips else 0
        else:
            reserved_hosts = 0
            total_ips = used_ips = free_ips = 0
            utilization_pct = 0.0
            effective_gateway = None

        status = "normal"
        if conflicts:
            status = "conflict"
        elif utilization_pct >= 90:
            status = "critical"
        elif utilization_pct >= 75:
            status = "warning"

        subnets = (
            []
            if network is None
            else [
                {
                    "cidr": str(network),
                    "source": subnet_source,
                    "gateway": effective_gateway,
                    "total_hosts": total_ips,
                    "used_hosts": used_ips,
                    "free_hosts": free_ips,
                    "free_hosts_are_observed": False,
                    "reserved_hosts": reserved_hosts,
                    "utilization_pct": utilization_pct,
                    "status": status,
                    "dhcp_range": None,
                    "dns_servers": network_context.get("dns_servers") or [],
                    "note": "Boş IP sayısı son keşifte gözlenmeyen adresleri gösterir; DHCP tahsis kaydı değildir.",
                }
            ]
        )

        allocations = [
            {
                "ip": device.get("ip"),
                "mac": device.get("mac"),
                "hostname": device.get("hostname") or device.get("friendly_name") or "İsimsiz Cihaz",
                "type": device.get("type") or "unknown",
                "status": device.get("status") or "unknown",
                "allocation_type": "Infrastructure" if device.get("is_gateway") else "Observed",
                "last_seen": device.get("last_seen"),
                "discovery_sources": device.get("discovery_sources") or [],
            }
            for device in devices[:50]
        ]
        return {
            "subnets": subnets,
            "conflicts": conflicts,
            "total_devices_tracked": len(devices),
            "total_conflicts": len(conflicts),
            "allocations": allocations,
        }

    return router
