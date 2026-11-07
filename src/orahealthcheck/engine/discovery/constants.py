"""Constantes compartidas por el motor y los proveedores de descubrimiento."""

# Allowlists de seguridad Oracle para reducir falsos positivos de cuentas internas
# esperadas por diseño. No incluyen usuarios de aplicación ni roles custom.
ORACLE_DBA_ROLE_ALLOWED_GRANTEES = {"SYS", "SYSTEM"}

ORACLE_EXPECTED_ADMIN_USERS = {"SYS", "SYSTEM"}

ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES = {
    "SYS", "SYSTEM", "DBA", "SELECT_CATALOG_ROLE", "EXECUTE_CATALOG_ROLE",
    "EXP_FULL_DATABASE", "IMP_FULL_DATABASE", "OEM_MONITOR", "SYSBACKUP",
    "SYSDG", "SYSKM", "SYSRAC", "SYSASM",
}

ORACLE_INTERNAL_SCHEMAS = {
    "SYS", "SYSTEM", "XDB", "MDSYS", "CTXSYS", "ORDSYS", "ORDDATA", "ORDPLUGINS",
    "WMSYS", "OUTLN", "DBSNMP", "GSMADMIN_INTERNAL", "AUDSYS", "OJVMSYS",
    "DVSYS", "DVF", "LBACSYS", "OLAPSYS", "MDDATA", "SI_INFORMTN_SCHEMA",
    "ANONYMOUS", "APEX_PUBLIC_USER", "FLOWS_FILES", "DIP", "EXFSYS", "MGMT_VIEW",
}

