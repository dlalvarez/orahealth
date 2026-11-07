"""Descubrimiento y construcción de evidencia del grupo security.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin
from orahealthcheck.engine.discovery.constants import ORACLE_DBA_ROLE_ALLOWED_GRANTEES, ORACLE_EXPECTED_ADMIN_USERS, ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES


class SecurityMixin(CommonMixin):
    def _discover_security_inventory(self, connector: Any) -> dict[str, Any]:
        security: dict[str, Any] = {}
        default_accounts = "'ANONYMOUS','APEX_PUBLIC_USER','CTXSYS','DBSNMP','DIP','EXFSYS','FLOWS_FILES','GSMADMIN_INTERNAL','MDSYS','MGMT_VIEW','OLAPSYS','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','WMSYS','XDB'"
        security["locked_users"] = self._query_rows(connector, "usuarios bloqueados", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where account_status like '%LOCKED%'
            order by username
        """)
        security["expired_users"] = self._query_rows(connector, "usuarios expirados", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where account_status like 'EXPIRED%'
              and account_status not like '%LOCKED%'
            order by username
        """)
        security["default_open_users"] = self._query_rows(connector, "usuarios default abiertos", f"""
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where username in ({default_accounts})
              and account_status = 'OPEN'
            order by username
        """)
        default_profile_users, default_profile_error = self._query_rows_with_error(connector, "usuarios con perfil DEFAULT", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where profile = 'DEFAULT'
              and account_status = 'OPEN'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') = 'N'
            order by username
        """, log_warning=False)
        if default_profile_error:
            default_profile_users = self._query_rows(connector, "usuarios con perfil DEFAULT sin columna oracle_maintained", """
                select username, account_status, profile, null as oracle_maintained, null as common
                from dba_users
                where profile = 'DEFAULT'
                  and account_status = 'OPEN'
                  and username not in ('SYS', 'SYSTEM')
                order by username
            """)
        security["default_profile_users"] = default_profile_users
        allowed_dba_grantees = self._sql_in_list(ORACLE_DBA_ROLE_ALLOWED_GRANTEES)
        security["dba_role_users"] = self._query_rows(connector, "usuarios o roles no esperados con rol DBA", f"""
            select
              rp.grantee,
              rp.granted_role,
              rp.admin_option,
              rp.default_role,
              u.account_status,
              u.oracle_maintained,
              u.common,
              u.profile,
              case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_role_privs rp
            left join dba_users u on u.username = rp.grantee
            where rp.granted_role = 'DBA'
              and rp.grantee not in ({allowed_dba_grantees})
            order by rp.grantee
        """)
        security["critical_privilege_users"] = self._query_rows(connector, "usuarios o roles no esperados con privilegios críticos", f"""
            select
              sp.grantee,
              sp.privilege,
              sp.admin_option,
              u.account_status,
              u.oracle_maintained,
              u.common,
              u.profile,
              r.oracle_maintained as role_oracle_maintained,
              case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.privilege in (
              'ALTER SYSTEM','ALTER DATABASE','CREATE ANY DIRECTORY','CREATE ANY LIBRARY',
              'CREATE ANY PROCEDURE','CREATE ANY TABLE','DROP ANY TABLE','GRANT ANY PRIVILEGE',
              'GRANT ANY ROLE','SELECT ANY DICTIONARY','SELECT ANY TABLE'
            )
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """)
        security["permissive_failed_login_profiles"] = self._query_rows(connector, "perfiles con failed_login_attempts permisivo", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'FAILED_LOGIN_ATTEMPTS'
              and (limit = 'UNLIMITED' or limit = 'DEFAULT' or regexp_like(limit, '^[0-9]+$') and to_number(limit) > 10)
            order by profile
        """)
        security["unlimited_password_life_profiles"] = self._query_rows(connector, "perfiles con password_life_time ilimitado", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'PASSWORD_LIFE_TIME'
              and limit in ('UNLIMITED','DEFAULT')
            order by profile
        """)
        security["missing_password_verify_profiles"] = self._query_rows(connector, "perfiles sin password_verify_function", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'PASSWORD_VERIFY_FUNCTION'
              and limit in ('NULL','DEFAULT')
            order by profile
        """)
        security["common_accounts_not_locked_or_expired"] = self._query_rows(connector, "cuentas comunes no bloqueadas", f"""
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where username in ({default_accounts})
              and account_status not like '%LOCKED%'
            order by username
        """)
        self._set_security_query(security, "oracle_maintained_open_users", connector, "usuarios Oracle-maintained abiertos", """
            select username, account_status, authentication_type, common, oracle_maintained
            from dba_users
            where oracle_maintained = 'Y'
              and username not in ('SYS', 'SYSTEM')
              and account_status = 'OPEN'
            order by username
        """, log_warning=False)
        admin_privilege_columns = self._available_pwfile_admin_columns(connector)
        admin_privilege_select = ", ".join(["username", *admin_privilege_columns])
        admin_privilege_predicate = " or ".join(f"{column.lower()} = 'TRUE'" for column in admin_privilege_columns)
        self._set_security_query(security, "admin_privilege_users", connector, "usuarios con privilegios administrativos especiales", f"""
            select {admin_privilege_select}
            from v$pwfile_users
            where username not in ('SYS', 'SYSTEM')
              and ({admin_privilege_predicate})
            order by username
        """, log_warning=False)
        self._set_security_query(security, "external_authenticated_users", connector, "usuarios con autenticación externa", """
            select username, account_status, authentication_type, external_name, common, oracle_maintained
            from dba_users
            where authentication_type = 'EXTERNAL'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
            order by username
        """, log_warning=False)
        self._set_security_query(security, "proxy_users_configured", connector, "relaciones de autenticación proxy", """
            select proxy, client, authentication, authorization_constraint, role
            from dba_proxies
            order by proxy, client, role
        """, log_warning=False)
        self._set_security_query(security, "any_privilege_users", connector, "usuarios o roles no esperados con privilegios ANY", """
            select sp.grantee, sp.privilege, sp.admin_option, u.account_status, u.oracle_maintained, u.common, r.oracle_maintained as role_oracle_maintained,
                   case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.privilege in (
              'ALTER ANY TABLE','DROP ANY PROCEDURE','CREATE ANY TRIGGER','ALTER ANY TRIGGER','DROP ANY TRIGGER',
              'CREATE ANY SYNONYM','CREATE ANY VIEW','ALTER ANY INDEX','DROP ANY INDEX','UPDATE ANY TABLE','DELETE ANY TABLE',
              'EXECUTE ANY PROCEDURE','ALTER ANY PROCEDURE'
            )
              and sp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """, log_warning=False)
        self._set_security_query(security, "admin_option_grants", connector, "privilegios de sistema con admin option", """
            select sp.grantee, sp.privilege, sp.admin_option, u.account_status, u.oracle_maintained, r.oracle_maintained as role_oracle_maintained,
                   case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.admin_option = 'YES'
              and sp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """, log_warning=False)
        self._set_security_query(security, "grant_option_object_privileges", connector, "privilegios de objeto con grant option", """
            select tp.grantee, tp.owner, tp.table_name, tp.privilege, tp.grantable, tp.type
            from dba_tab_privs tp
            left join dba_users owner_u on owner_u.username = tp.owner
            left join dba_users grantee_u on grantee_u.username = tp.grantee
            where tp.grantable = 'YES'
              and nvl(owner_u.oracle_maintained, 'N') <> 'Y'
              and nvl(grantee_u.oracle_maintained, 'N') <> 'Y'
              and tp.grantee not in ('SYS', 'SYSTEM')
            order by tp.grantee, tp.owner, tp.table_name, tp.privilege
        """, log_warning=False)
        self._set_security_query(security, "legacy_roles_assigned", connector, "roles legacy asignados directamente", """
            select rp.grantee, rp.granted_role, rp.admin_option, rp.default_role, u.account_status, u.oracle_maintained
            from dba_role_privs rp
            left join dba_users u on u.username = rp.grantee
            where rp.granted_role in ('CONNECT', 'RESOURCE')
              and rp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
            order by rp.grantee, rp.granted_role
        """, log_warning=False)
        expected_dictionary_grantees = self._sql_in_list(ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES)
        self._set_security_query(security, "dictionary_access_privileges", connector, "acceso sensible al diccionario", f"""
            select grantee, access_name, option_flag, source
            from (
              select sp.grantee, sp.privilege as access_name, sp.admin_option as option_flag, 'DBA_SYS_PRIVS' as source
              from dba_sys_privs sp
              left join dba_users u on u.username = sp.grantee
              left join dba_roles r on r.role = sp.grantee
              where sp.privilege = 'SELECT ANY DICTIONARY'
                and sp.grantee not in ({expected_dictionary_grantees})
                and nvl(u.oracle_maintained, 'N') <> 'Y'
                and nvl(r.oracle_maintained, 'N') <> 'Y'
              union all
              select rp.grantee, rp.granted_role as access_name, rp.admin_option as option_flag, 'DBA_ROLE_PRIVS' as source
              from dba_role_privs rp
              left join dba_users u on u.username = rp.grantee
              left join dba_roles r on r.role = rp.grantee
              where rp.granted_role in ('SELECT_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE')
                and rp.grantee not in ({expected_dictionary_grantees})
                and nvl(u.oracle_maintained, 'N') <> 'Y'
                and nvl(r.oracle_maintained, 'N') <> 'Y'
            )
            order by grantee, access_name
        """, log_warning=False)
        self._set_security_query(security, "inactive_users_by_last_login", connector, "usuarios abiertos inactivos por último login", """
            select username, account_status, last_login, authentication_type, common, oracle_maintained
            from dba_users
            where account_status = 'OPEN'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
              and (last_login is null or last_login < systimestamp - interval '90' day)
            order by username
        """, log_warning=False)
        self._set_security_query(security, "legacy_password_versions", connector, "usuarios con versiones antiguas de contraseña", """
            select username, account_status, password_versions, authentication_type, common, oracle_maintained
            from dba_users
            where password_versions like '%10G%'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
            order by username
        """, log_warning=False)
        return {"security": security}

    def _available_pwfile_admin_columns(self, connector: Any) -> list[str]:
        candidate_columns = ["SYSDBA", "SYSOPER", "SYSASM", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC"]
        rows, error = self._query_rows_with_error(connector, "columnas disponibles de V$PWFILE_USERS", """
            select column_name
            from all_tab_columns
            where owner = 'SYS'
              and table_name = 'V_$PWFILE_USERS'
              and column_name in ('SYSDBA','SYSOPER','SYSASM','SYSBACKUP','SYSDG','SYSKM','SYSRAC')
            order by column_id
        """, log_warning=False)
        if not error and rows:
            available = {str(row.get("column_name") or row.get("COLUMN_NAME") or "").upper() for row in rows}
            columns = [column for column in candidate_columns if column in available]
            if columns:
                return columns
        return [column for column in candidate_columns if column != "SYSRAC"]

    def _set_security_query(self, security: dict[str, Any], field: str, connector: Any, label: str, sql: str, log_warning: bool = True) -> None:
        rows, error = self._query_rows_with_error(connector, label, sql, log_warning=log_warning)
        security[field] = rows
        if error:
            security[f"{field}_error"] = error

    def _build_security_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        security = database.get("security") if isinstance(database.get("security"), dict) else {}
        field = check.collector.get("field", check.check_id)
        rows = security.get(field, [])
        if rows is None:
            rows = []
        original_rows = rows if isinstance(rows, list) else [rows]
        filtered_rows = self._filter_security_rows(check.check_id, original_rows)
        evidence = {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario de seguridad Oracle"),
            "affected_count": len(filtered_rows),
            "rows": filtered_rows,
        }
        if filtered_rows != original_rows and check.check_id in ("dba_role_users", "critical_privilege_users"):
            evidence["inventory_count"] = len(original_rows)
            evidence["excluded_count"] = len(original_rows) - len(filtered_rows)
            evidence["classification_note"] = "Se excluyeron usuarios o roles Oracle-maintained esperados del hallazgo principal."
        if security.get(f"{field}_error"):
            evidence["collection_error"] = security.get(f"{field}_error")
        return evidence

    def _filter_security_rows(self, check_id: str, rows: list[Any]) -> list[Any]:
        if check_id == "default_profile_users":
            return [row for row in rows if not self._is_expected_oracle_security_row(row)]
        if check_id == "dba_role_users":
            return [row for row in rows if not self._is_allowed_dba_grantee(row)]
        if check_id == "critical_privilege_users":
            return [row for row in rows if not self._is_allowed_critical_privilege_grantee(row)]
        if check_id == "dictionary_access_privileges":
            return [row for row in rows if not self._is_expected_dictionary_access_grantee(row)]
        if check_id in {"admin_privilege_users", "any_privilege_users", "admin_option_grants", "legacy_roles_assigned", "external_authenticated_users", "legacy_password_versions", "inactive_users_by_last_login"}:
            return [row for row in rows if not self._is_expected_oracle_security_row(row)]
        if check_id == "oracle_maintained_open_users":
            return [row for row in rows if str(row.get("username", "")).upper() not in ORACLE_EXPECTED_ADMIN_USERS] if all(isinstance(row, dict) for row in rows) else rows
        return rows

    def _is_expected_dictionary_access_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        grantee = str(row.get("grantee", "")).upper()
        return grantee in ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES or self._is_expected_oracle_security_row(row)

    def _is_expected_oracle_security_row(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        principal = str(row.get("grantee") or row.get("username") or "").upper()
        oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
        role_oracle_maintained = str(row.get("role_oracle_maintained", "")).upper() == "Y"
        return principal in ORACLE_EXPECTED_ADMIN_USERS or oracle_maintained or role_oracle_maintained

    def _is_allowed_dba_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        return str(row.get("grantee", "")).upper() in ORACLE_DBA_ROLE_ALLOWED_GRANTEES

    def _is_allowed_critical_privilege_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        grantee = str(row.get("grantee", "")).upper()
        grantee_type = str(row.get("grantee_type", "")).upper()
        oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
        role_oracle_maintained = str(row.get("role_oracle_maintained", "")).upper() == "Y"
        return oracle_maintained or role_oracle_maintained
