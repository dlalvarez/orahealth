"""Construcción de conectores de sistema operativo a partir de perfiles de conexión."""

from __future__ import annotations

from typing import Any

from .local_connector import LocalConnector
from .ssh_connector import SSHConnector

LOCAL_TYPES = {"local"}
SSH_TYPES = {"ssh"}


def build_os_connector(profile: Any) -> Any:
    """Retorna el conector adecuado para un perfil de conexión de sistema operativo.

    El tipo declarado en ``connection_profiles.yaml`` decide el conector: ``local``
    ejecuta comandos en la máquina donde corre OraHealthCheck y ``ssh`` los ejecuta
    en el servidor remoto. Un tipo desconocido es un error de configuración.
    """
    connection_type = str(getattr(profile, "type", "") or "").lower()
    if connection_type in LOCAL_TYPES:
        return LocalConnector()
    if connection_type in SSH_TYPES:
        return SSHConnector(profile)
    raise ValueError(
        f"Tipo de conexión de sistema operativo no soportado: '{connection_type}' "
        f"(perfil {getattr(profile, 'connection_id', '?')})"
    )
