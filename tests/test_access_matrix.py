"""Her rolün tüm hassas yetkiler karşısındaki beklenen davranışı."""

import pytest
import server

from backend.core.access import ROLE_DEFINITIONS, has_permission, role_permissions

EXPECTED_ROLE_PERMISSIONS = {
    "admin": {"*"},
    "noc_operator": {
        "connections.view",
        "devices.manage",
        "diagnostics.run",
        "discovery.schedule.manage",
        "inventory.scan",
        "locations.view",
        "logs.manage",
        "ncm.manage",
        "reports.view",
    },
    "inventory_specialist": {
        "devices.manage",
        "inventory.scan",
        "locations.manage",
        "locations.view",
        "reports.view",
    },
    "security_analyst": {
        "connections.view",
        "diagnostics.run",
        "locations.view",
        "reports.view",
        "security.manage",
    },
    "viewer": set(),
    "user": set(),
}

SENSITIVE_PERMISSIONS = sorted(
    {
        "connections.view",
        "devices.manage",
        "diagnostics.run",
        "discovery.schedule.manage",
        "inventory.scan",
        "locations.manage",
        "locations.view",
        "logs.manage",
        "ncm.manage",
        "reports.view",
        "security.manage",
        "system.admin",
        "system.settings.manage",
        "users.manage",
    }
)


@pytest.mark.parametrize("role", sorted(EXPECTED_ROLE_PERMISSIONS))
def test_role_permission_catalog_is_explicit_and_stable(role):
    assert role in ROLE_DEFINITIONS
    assert set(role_permissions(role)) == EXPECTED_ROLE_PERMISSIONS[role]


@pytest.mark.parametrize(
    ("role", "permission"),
    [(role, permission) for role in sorted(EXPECTED_ROLE_PERMISSIONS) for permission in SENSITIVE_PERMISSIONS],
)
def test_every_role_permission_combination(role, permission):
    expected = "*" in EXPECTED_ROLE_PERMISSIONS[role] or permission in EXPECTED_ROLE_PERMISSIONS[role]
    user = {"role": role, "permissions": role_permissions(role)}
    assert has_permission(user, permission) is expected


def iter_routes(router):
    for route in router.routes:
        included_router = getattr(route, "original_router", None)
        if included_router is not None:
            yield from iter_routes(included_router)
        else:
            yield route


PROTECTED_ENDPOINTS = [
    (f"{sorted(route.methods)[0]} {route.path}", dependency.call.required_permission, dependency.call)
    for route in iter_routes(server.app)
    if hasattr(route, "dependant")
    for dependency in route.dependant.dependencies
    if hasattr(dependency.call, "required_permission")
]


def test_permission_matrix_discovers_protected_endpoints():
    assert len(PROTECTED_ENDPOINTS) >= 30
    assert {permission for _, permission, _ in PROTECTED_ENDPOINTS} >= {
        "diagnostics.run",
        "inventory.scan",
        "locations.manage",
        "ncm.manage",
        "security.manage",
        "system.settings.manage",
        "users.manage",
    }


@pytest.mark.parametrize("role", sorted(EXPECTED_ROLE_PERMISSIONS))
@pytest.mark.parametrize(("endpoint", "permission", "dependency"), PROTECTED_ENDPOINTS)
def test_every_role_and_protected_endpoint_combination(role, endpoint, permission, dependency):
    user = {"role": role, "permissions": role_permissions(role)}
    expected = "*" in EXPECTED_ROLE_PERMISSIONS[role] or permission in EXPECTED_ROLE_PERMISSIONS[role]
    if expected:
        assert dependency(user=user) is user
    else:
        with pytest.raises(server._AuthError) as raised:
            dependency(user=user)
        assert raised.value.status_code == 403
        assert permission in raised.value.message
