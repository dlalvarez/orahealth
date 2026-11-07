"""Requisitos declarados por los checks (conexiones y vistas Oracle)."""

from orahealthcheck.models import Check

# Vistas mínimas sin las cuales no es posible identificar la base (rol, open mode,
# versión). Si no son accesibles, ningún check de base de datos es confiable.
CORE_VIEWS = ("v$database", "v$instance")


def required_views(check: Check) -> list[str]:
    """Vistas declaradas en ``applies_to.requires.views`` del check (en minúsculas)."""
    requires = (check.applies_to or {}).get("requires") or {}
    views = requires.get("views") or []
    if isinstance(views, str):
        views = [views]
    return [str(view).strip().lower() for view in views if str(view).strip()]


def requires_database(check: Check) -> bool:
    requires = (check.applies_to or {}).get("requires") or {}
    return bool(requires.get("database_connection"))
