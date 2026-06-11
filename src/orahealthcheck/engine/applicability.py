from orahealthcheck.models import Check, Inventory, Target


def _version(value: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in value.split(".") if part.isdigit())
    except (AttributeError, TypeError):
        return None


class ApplicabilityEngine:
    def evaluate(self, check: Check, target: Target, inventory: Inventory) -> tuple[bool, str | None]:
        applies = check.applies_to or {}
        if applies.get("architectures") and target.expected_architecture not in applies["architectures"]:
            return False, f"La arquitectura {target.expected_architecture} no aplica"
        platform = inventory.operating_system.get("platform", target.operating_system.get("platform"))
        if applies.get("platforms") and platform not in applies["platforms"]:
            return False, f"La plataforma {platform} no aplica"
        db = inventory.database
        if applies.get("database_roles") and db.get("role") not in applies["database_roles"]:
            return False, f"El rol de base de datos {db.get('role')} no aplica"
        if applies.get("open_modes") and db.get("open_mode") not in applies["open_modes"]:
            return False, f"El modo de apertura {db.get('open_mode')} no aplica"
        versions = applies.get("oracle_versions") or {}
        current = _version(str(db.get("version", "")))
        if current and versions.get("min") and current < _version(str(versions["min"])):
            return False, f"La versión Oracle {current} es menor que el mínimo {versions['min']}"
        if current and versions.get("max") and current > _version(str(versions["max"])):
            return False, f"La versión Oracle {current} es mayor que el máximo {versions['max']}"
        requires = applies.get("requires") or {}
        if requires.get("database_connection") and not target.database.get("primary_connection"):
            return False, "Se requiere conexión a base de datos"
        if requires.get("os_connection") and not target.operating_system.get("connections"):
            return False, "Se requiere conexión al sistema operativo"
        for feature in ("awr", "diagnostic_pack", "sysdba"):
            if requires.get(feature) and not inventory.features.get(feature):
                return False, f"La característica requerida {feature} no está habilitada"
        return True, None
