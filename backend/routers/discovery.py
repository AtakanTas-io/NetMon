"""Ağ keşfi, kapsam, topoloji ve tarama zamanlaması API uçları."""

from fastapi import APIRouter, Depends


def create_discovery_router(ctx) -> APIRouter:
    router = APIRouter()

    @router.get("/api/network/scopes")
    def network_scopes(user: dict = Depends(ctx.get_current_user)):
        try:
            scopes = [str(network) for network in ctx.diag._local_ipv4_networks()]
        except Exception as exc:
            return {"scopes": [], "error": str(exc)}
        return {"scopes": scopes, "count": len(scopes), "policy": "local-private-networks-only"}

    @router.get("/api/discovery/schedule")
    def get_discovery_schedule(user: dict = Depends(ctx.get_current_user)):
        last_finished = ctx._discovery_schedule_state.get("last_finished")
        return {
            **ctx._discovery_schedule_state,
            "enabled": True,
            "interval_seconds": ctx.SCAN_INTERVAL,
            "target_subnet": ctx.SUBNET_OVERRIDE or "Otomatik yerel ağ",
            "next_run": last_finished + max(60, ctx.SCAN_INTERVAL) if last_finished else None,
            "can_manage": ctx._has_permission(user, "discovery.schedule.manage"),
            "required_permission": "discovery.schedule.manage",
        }

    router.add_api_route("/api/network-info", ctx.get_network_info, methods=["GET"])
    router.add_api_route("/api/topology", ctx.get_topology, methods=["GET"])
    router.add_api_route("/api/tools/nmap/status", ctx.get_nmap_status, methods=["GET"])
    return router
