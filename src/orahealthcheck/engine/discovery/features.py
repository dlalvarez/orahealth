"""Detección de características Oracle (RAC, ASM, Data Guard, CDB, ...).

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.engine.discovery.common import CommonMixin


class FeaturesMixin(CommonMixin):
    def _discover_oracle_feature_signals(self, connector: Any) -> dict[str, Any]:
        signals: dict[str, Any] = {}
        fra = self._query_one(connector, "FRA para detección de características", """
            select space_limit as fra_space_limit
            from v$recovery_file_dest
        """)
        if fra:
            signals.update(fra)
        remote_destinations = self._query_rows(connector, "destinos remotos de archive para bases standby", """
            select dest_id, status, target, destination
            from v$archive_dest
            where status <> 'INACTIVE'
              and target = 'STANDBY'
        """)
        if remote_destinations:
            signals["remote_archive_destinations"] = remote_destinations
        return signals

    def _detect_oracle_features_from_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        parameters = database.get("parameters", {}) if isinstance(database.get("parameters"), dict) else {}
        cluster_value = str((parameters.get("cluster_database") or {}).get("value", "FALSE")).upper()
        rac_detected = cluster_value == "TRUE"

        cdb_value = str(database.get("cdb", "NO")).upper()
        multitenant_detected = cdb_value == "YES"

        database_role = str(database.get("role", database.get("database_role", "PRIMARY"))).upper()
        dg_info = self._default_dataguard_inventory(database)
        standby_detected = bool(dg_info.get("standby_detected"))

        fra_space_limit = database.get("fra_space_limit")
        if fra_space_limit is None:
            fra_space_limit = database.get("recovery_file_dest_size")
        if fra_space_limit is None and isinstance(database.get("storage"), dict):
            fra_space_limit = (database["storage"].get("fra") or {}).get("space_limit") or (database["storage"].get("fra") or {}).get("recovery_file_dest_size")
        fra_detected = bool(database.get("fra_configured")) or self._safe_number(fra_space_limit) > 0

        flashback_value = str(database.get("flashback_on", "NO")).upper()
        asm_info = self._default_asm_inventory(database)
        asm_detected = bool(asm_info.get("usa_asm"))
        asm_diskgroups = asm_info.get("diskgroups_detectados") or []
        return {
            "oracle_rac": {
                "detected": rac_detected,
                "status": "detected" if rac_detected else "not_detected",
                "source": "V$PARAMETER.CLUSTER_DATABASE",
                "value": cluster_value,
                "reason": f"cluster_database = {cluster_value}",
            },
            "multitenant": {
                "detected": multitenant_detected,
                "status": "detected" if multitenant_detected else "not_detected",
                "source": "V$DATABASE.CDB",
                "value": cdb_value,
                "reason": "La base de datos está configurada como CDB." if multitenant_detected else "La base de datos no está configurada como CDB.",
            },
            "standby_configuration": {
                "detected": standby_detected,
                "status": "detected" if standby_detected else "not_detected",
                "source": "V$DATABASE.DATABASE_ROLE / V$ARCHIVE_DEST / V$PARAMETER",
                "database_role": database_role,
                "protection_mode": database.get("protection_mode"),
                "protection_level": database.get("protection_level"),
                "signals": dg_info.get("signals") or [],
                "reason": "Configuración de bases standby detectada." if standby_detected else "No se detectaron señales locales de configuración con bases standby.",
            },
            "fra_configured": {
                "detected": fra_detected,
                "status": "detected" if fra_detected else "not_detected",
                "source": "V$RECOVERY_FILE_DEST",
                "space_limit": self._safe_number(fra_space_limit),
                "reason": "FRA configurada." if fra_detected else "FRA no configurada o space_limit = 0.",
            },
            "flashback_database": {
                "detected": flashback_value == "YES",
                "status": "detected" if flashback_value == "YES" else "not_detected",
                "source": "V$DATABASE.FLASHBACK_ON",
                "value": flashback_value,
                "reason": "Flashback Database está habilitado." if flashback_value == "YES" else "Flashback Database no está habilitado.",
            },
            "asm": {
                "detected": asm_detected,
                "status": "detected" if asm_detected else "not_detected",
                "source": "V$DATAFILE/V$TEMPFILE/V$LOGFILE/V$CONTROLFILE/V$PARAMETER/V$RECOVERY_FILE_DEST",
                "diskgroups": asm_diskgroups,
                "reason": f"Se encontraron archivos de base de datos sobre diskgroups ASM: {', '.join(asm_diskgroups)}" if asm_detected else "No se encontraron archivos de base de datos sobre ASM desde la conexión actual.",
            },
        }
