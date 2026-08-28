"""Rol tanımları ve saf yetki yardımcıları."""

ROLE_DEFINITIONS = {
    "admin": {"label": "Sistem Yöneticisi", "permissions": {"*"}},
    "noc_operator": {
        "label": "NOC Operatörü",
        "permissions": {
            "inventory.scan",
            "discovery.schedule.manage",
            "devices.manage",
            "diagnostics.run",
            "logs.manage",
            "ncm.manage",
            "reports.view",
            "locations.view",
        },
    },
    "inventory_specialist": {
        "label": "Envanter Uzmanı",
        "permissions": {
            "inventory.scan",
            "devices.manage",
            "reports.view",
            "locations.view",
            "locations.manage",
        },
    },
    "security_analyst": {
        "label": "Güvenlik Analisti",
        "permissions": {"diagnostics.run", "security.manage", "reports.view", "locations.view"},
    },
    "viewer": {"label": "Salt Okunur", "permissions": set()},
    "user": {"label": "Standart Kullanıcı", "permissions": set()},
}


def role_definition(role: str) -> dict:
    return ROLE_DEFINITIONS.get(role, ROLE_DEFINITIONS["viewer"])


def role_permissions(role: str) -> list[str]:
    permissions = role_definition(role)["permissions"]
    return ["*"] if "*" in permissions else sorted(permissions)


def has_permission(user: dict, permission: str) -> bool:
    permissions = set(user.get("permissions") or role_permissions(user.get("role", "viewer")))
    return "*" in permissions or permission in permissions
