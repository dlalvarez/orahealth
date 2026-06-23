# OraHealthCheck - Check Groups

## 1. Purpose

This document defines the functional check groups that OraHealthCheck must support.

Checks must not be managed as one flat list. They must be organized by purpose so profiles and targets can activate complete groups and override only exceptional checks.

Core principle:

```text
Target -> Profile -> Check Groups -> Checks -> Standards
```

---

## 2. Required Check Groups

OraHealthCheck must support the following groups:

```text
configuration_general
performance
alert_log
storage
schema_objects
operational_readiness
security
rac
dataguard
asm
os
capacity
patching
```

Each group must be independently executable from the CLI and usable inside profiles.

Example:

```bash
orahealthcheck run --target medaprod --groups security,storage
```

### Reconciliación Fase 4A para `performance` y `capacity`

Desde Fase 4A existen los grupos formales `performance` y `capacity`, pero comienzan sin checks propios. La cobertura relacionada que ya fue implementada antes de esta fase permanece en sus grupos originales. Esta decisión evita romper compatibilidad, evita duplicar hallazgos equivalentes y mantiene estable la historia de cada check.

Reglas vigentes:

- No mover checks existentes desde `oracle_resources`, `io_redo_archive`, `configuration_general`, `operational_readiness` ni `storage`.
- No duplicar checks existentes bajo `performance` o `capacity`.
- No crear checks dummy ni checks vacíos para rellenar grupos.
- No activar AWR, ASH ni `DBA_HIST%` por defecto; cualquier uso futuro debe ser opcional, condicionado a licenciamiento explícito y deshabilitado por defecto.
- No introducir SQLite ni repositorio histórico interno para capacidad.
- Mantener `capacity` como fotografía actual por defecto.

Cobertura adelantada que se reconoce como relacionada:

- `oracle_resources`: sesiones bloqueadas/bloqueantes, sesiones inactivas, jobs Scheduler/DBA Jobs, PGA, SGA, procesos, sesiones y transacciones contra límites. Cubre parcialmente rendimiento, capacidad y operación básica de recursos, pero debe permanecer en `oracle_resources`.
- `io_redo_archive`: archive destinations, generación de archived logs, I/O básico por `V$FILESTAT`/`V$SYSSTAT`, flashback, FRA, nologging/unrecoverable y redo logs. Cubre parcialmente rendimiento, capacidad, recuperabilidad, almacenamiento operativo y redo/archive/FRA, pero debe permanecer en `io_redo_archive`.
- `configuration_general`: `open_cursors`, `processes`, `sessions`, `optimizer_features_enable`, `filesystemio_options` y `db_block_size` aportan contexto de rendimiento/capacidad, pero deben permanecer en `configuration_general`.
- `operational_readiness`: `plsql_optimize_level`, `plsql_code_type`, `sql_trace`, `timed_statistics`, `timed_os_statistics`, `result_cache_mode`, `result_cache_max_result`, `optimizer_capture_sql_plan_baselines` y `optimizer_use_invisible_indexes` son parámetros operativos relacionados, pero deben permanecer en `operational_readiness`.

Estrategia futura:

- Fase 4B agregará únicamente gaps reales de rendimiento básico sin AWR, por ejemplo uptime, sesiones activas actuales, esperas actuales, parse ratio, cache/library cache, SQL activo, long operations y eventos actuales por sesión.
- Fase 4C agregará únicamente gaps reales de capacidad tipo fotografía actual, por ejemplo tamaño actual de BD, datafiles/tablespaces, segmentos grandes, TEMP/UNDO, límites de sesiones/procesos/transacciones, PGA/SGA y FRA/archive.


---

## 3. Group: configuration_general

### Purpose

Validate Oracle initialization parameters, core database configuration, redo configuration, memory configuration, optimizer-related settings, AWR settings, and configuration items that affect stability, performance, compatibility, security, and maintainability.

### Important design rule

Many configuration checks are policy-based. Do not hardcode one universal recommendation for every Oracle version and workload. Expected values must come from standards and profile overrides.

### Checks to include

#### Parameter inventory and hygiene

- Initialization parameters with default values.
- Deprecated non-default initialization parameters.
- Obsolete parameters.
- Hidden parameters if visible and allowed.
- Parameters modified from default.
- Parameters inconsistent across RAC instances.

#### Version alignment

- `compatible` aligned with Oracle major/minor version or defined standard.
- `optimizer_features_enable` aligned with Oracle version or defined standard.

#### Optimizer-related parameters

- `optimizer_index_caching`.
- `optimizer_index_cost_adj`.
- `cursor_sharing`.
- `query_rewrite_enabled`.
- `star_transformation_enabled`.
- `optimizer_capture_sql_plan_baselines`.
- `optimizer_use_invisible_indexes`.

#### Memory-related parameters

- Parameters incompatible with `pga_aggregate_target`.
- Parameters incompatible with `memory_target`.
- `db_cache_size` vs legacy `db_block_buffers`.
- Buffer cache size.
- Large pool size.
- KEEP cache configuration.
- KEEP cache used by objects.
- RECYCLE cache configuration.
- RECYCLE cache used by objects.
- `db_nk_cache_size` without matching tablespaces.
- Tablespaces with non-default block size without matching cache.
- `sga_target`.
- `sga_max_size`.
- `pga_aggregate_target`.
- `memory_target`.
- `memory_max_target`.

#### Storage and I/O parameters

- `db_block_size`.
- `db_multiblock_read_count`.
- `disk_asynch_io`.
- `filesystemio_options`.
- Direct I/O and asynchronous I/O policy.

#### Transaction and cursor parameters

- `dml_locks`.
- `open_cursors`.
- `session_cached_cursors`.
- `processes`.
- `sessions`.
- `transactions`.

#### Recovery and redo configuration

- Number of control files.
- Multiplexed control files.
- Redo log group count.
- Redo members per group.
- Redo log size.
- Redo log status.
- `fast_start_mttr_target`.
- `log_checkpoint_timeout`.
- `log_checkpoint_interval`.
- Archivelog configuration.

#### Trace and diagnostics

- `max_dump_file_size`.
- `sql_trace`.
- `timed_statistics`.
- `timed_os_statistics`.
- `trace_enabled`.
- Diagnostic destination.
- ADR base.

#### Security-sensitive parameters

- `remote_login_passwordfile`.
- `sec_case_sensitive_logon`.
- `remote_os_authent`.
- `o7_dictionary_accessibility`.
- `sql92_security`.

#### Miscellaneous

- `recyclebin`.
- Inaccessible DB Links.
- `SYS.AUD$` location outside SYSTEM tablespace.
- AWR snapshot interval.
- AWR retention.

### Implemented in Phase 2A

The current `configuration_general` group includes these implemented checks:

- `database_status` — instance status from inventory/Oracle discovery.
- `database_open_mode` — open mode from `v$database`.
- `archivelog_mode` — archive log mode from `v$database`.
- `compatible` — parameter value from `v$parameter`.
- `optimizer_features_enable` — parameter value compared with policy when configured.
- `db_block_size` — parameter value compared with policy when configured.
- `open_cursors` — parameter value compared with a minimum policy.
- `processes` — parameter value compared with a minimum policy.
- `sessions` — parameter value compared with a minimum policy.
- `audit_trail` — parameter value checked against disabled/non-compliant values or policy.
- `remote_login_passwordfile` — parameter value compared with policy.
- `recyclebin` — parameter value reported and compared with policy when configured.
- `filesystemio_options` — parameter value reported and compared with policy when configured.
- `control_files_multiplexed` — control file count from `v$controlfile`.
- `redo_log_group_count` — redo group count from `v$log`.
- `redo_log_members_multiplexed` — minimum member count per redo group from `v$logfile`.
- `force_logging` — database force logging flag from `v$database`.

These checks use regular dynamic performance views and do not require Diagnostic Pack, AWR, or additional Oracle licensing. Missing views/privileges result in controlled `ERROR` evidence for the affected check.

### Typical collectors

```text
oracle_sql
plugin
```

### Typical evaluators

```text
expected_value
threshold
row_count_threshold
empty_result_pass
comparison
custom
```

---

## 4. Group: performance

### Purpose

Identify performance symptoms and configuration issues that may affect response time, throughput, concurrency, memory efficiency, I/O balance, and SQL execution.

### Checks to include

#### Basic performance and connection

- Connection time.
- Oracle version and basic instance information.
- Database uptime.
- Instance startup time.
- Session count.
- Active session count.
- Process usage.

#### Memory

- SGA usage.
- SGA component distribution.
- PGA usage.
- Shared pool pressure.
- Buffer cache advisory if available.
- SGA advisory if available.
- Library cache waits.
- Hard parses.
- Parse ratio.

#### Redo and archivelog

- Archivelog mode.
- Archivelog generation.
- Excessive archive generation.
- Redo generation rate.
- Log switch frequency.
- Redo log wait symptoms.

#### I/O

- I/O distribution by datafile.
- Datafiles with high physical reads.
- Datafiles with high writes.
- Hot datafiles.
- Temp I/O.
- Undo I/O.

#### Undo and TEMP

- Undo usage.
- Undo retention risk.
- Undo waits.
- Rollback/undo segment waits.
- TEMP usage.
- TEMP pressure.
- Sessions consuming TEMP.

#### Sessions and locks

- Blocking sessions.
- Blocked sessions.
- Long-running sessions.
- High inactive session count.
- Sessions waiting on critical events.
- Row lock waits.

#### Wait events

- Top wait events.
- Top wait classes.
- I/O waits.
- Concurrency waits.
- Commit waits.
- Network waits.
- RAC GC waits when applicable.

#### SQL performance

- High CPU SQL when permissions allow.
- High elapsed time SQL when permissions allow.
- High buffer gets SQL when permissions allow.
- High disk reads SQL when permissions allow.
- SQL with many executions and high total cost.

#### Statistics and internal objects

- SYS/SYSTEM tables not analyzed.
- SYS/SYSTEM table partitions not analyzed.
- SYS/SYSTEM indexes not analyzed.
- SYS/SYSTEM index partitions not analyzed.
- `SYS.AUDSES$` cache size for high login rates.

### Estado Fase 4A

Desde Fase 4B el grupo formal `performance` contiene 9 checks propios de performance básico actual sin AWR/ASH. La cobertura adelantada previa permanece en `oracle_resources`, `io_redo_archive`, `configuration_general` y `operational_readiness`, sin mover ni duplicar checks. El análisis WAIT_CLASS/EVENT se basa en `V$SESSION`; los segundos son observados en la fotografía actual, no DB Time histórico. Los thresholds de wait class son configurables por clase, `Idle` se excluye por defecto, `SQL` actual no equivale a top SQL histórico y `capacity` sigue pendiente.

Los primeros checks propios deben agregarse en Fase 4B solo para gaps reales y con consultas actuales no licenciadas por defecto.

### Licensing rule

Checks using AWR, ASH, or `DBA_HIST_%` views must declare:

```yaml
requires:
  awr: true
  diagnostic_pack: true
```

If the user does not enable such checks, they must be `SKIPPED`.

### Typical collectors

```text
oracle_sql
plugin
```

### Typical evaluators

```text
threshold
row_count_threshold
expected_value
comparison
custom
```

---

## 5. Group: alert_log

### Propósito

Analizar la muestra de alert log disponible en el inventario para detectar familias de eventos relevantes de salud preventiva sin convertir OraHealthCheck en una herramienta de RCA avanzado.

### Checks implementados

- `alert_log_ora_errors_basic`: check general conservado para compatibilidad.
- `alert_log_internal_errors`: detecta ORA-00600 y ORA-07445 con severidad `CRITICAL`.
- `alert_log_memory_errors`: detecta ORA-04031 y ORA-04030 con severidad `FAIL`.
- `alert_log_space_errors`: detecta ORA-00257, ORA-01652, ORA-01653 y ORA-01654 con severidad `FAIL`.
- `alert_log_snapshot_undo_errors`: detecta ORA-01555 con severidad `WARNING`.
- `alert_log_corruption_errors`: detecta ORA-01578, ORA-01110 y textos de corrupción o DBVERIFY con severidad `CRITICAL`.
- `alert_log_redo_archive_errors`: detecta errores de archive, archiver, ARC/LGWR con error o fallo, checkpoint incompleto, archival required, ORA-00257 y asignación anómala de redo; los switches normales no generan hallazgo.
- `alert_log_recent_summary`: resumen `INFO` con conteos por familia; no penaliza score ni genera acción correctiva por sí mismo.

### Alcance y evidencia

Los checks consumen una estructura común de eventos de alert log. La recolección intenta primero `V$DIAG_ALERT_EXT`; si esa fuente no está disponible por privilegios o versión, intenta ubicar el archivo `alert_<INSTANCE_NAME>.log` bajo `Diag Trace` con `V$DIAG_INFO`; si tampoco es posible, calcula una ruta de fallback con `diagnostic_dest`, `DB_UNIQUE_NAME` o `DB_NAME` e `INSTANCE_NAME`.

Si no hay privilegios sobre `V$DIAG_ALERT_EXT` ni conexión OS/SSH/local para leer el archivo, los checks quedan `SKIPPED` con explicación y no penalizan score. Si existe conexión OS/SSH/local y la lectura del archivo calculado falla por permisos, ruta, timeout o comando, el resultado es `ERROR` técnico.

La evidencia incluye fuente usada, patrón detectado, conteos, timestamps cuando están disponibles, líneas o mensajes de muestra, límite aplicado y marca de truncamiento cuando existen más ocurrencias que líneas reportadas. `X$DBGALERTEXT` no se usa por defecto porque es una tabla fija interna y puede requerir privilegios altos; podrá documentarse como alternativa avanzada futura, pero no es dependencia del grupo `alert_log`.

Los textos relacionados con standby, MRP, RFS o FAL se reportan solo como coincidencias textuales dentro del resumen informativo. Este grupo no evalúa la salud de Data Guard; esa validación corresponde al grupo futuro `dataguard` cuando esté implementado y aplique.

## 6. Group: storage

### Purpose

Validate tablespaces, datafiles, tempfiles, segments, FRA, ASM diskgroups, filesystems, and growth risks.

### Checks to include

#### User tablespace configuration

- Users with SYSTEM as temporary tablespace.
- Users except SYS with SYSTEM as default tablespace.
- Users with non-existing temporary tablespace.
- Users with non-existing default tablespace.

#### Tablespaces

- Tablespaces with low free space.
- Tablespaces with low free space considering autoextend.
- Tablespaces with autoextend disabled.
- Tablespaces close to maxsize.
- Tablespaces managed by dictionary.
- Tablespace fragmentation.
- Bigfile tablespace usage.
- Temporary tablespace usage.
- Undo tablespace usage.

#### Datafiles and tempfiles

- Datafiles near maxsize.
- Datafiles without autoextend where policy requires it.
- Tempfiles near maxsize.
- Datafiles in recover status.
- Offline datafiles.

#### Segments

- Objects unable to extend.
- Segments with NEXT_EXTENT too large or too small relative to total size.
- Segments with less than configured extent availability.
- Segments with more than 1000 extents.
- Segment growth risk.

#### FRA and archive

- FRA usage.
- FRA reclaimable space.
- Archive destination usage.
- Archive log generation pressure.

#### ASM

- ASM diskgroup usage.
- Diskgroup free space.
- Diskgroup redundancy.
- Offline ASM disks.

#### OS filesystems

- Oracle Base filesystem usage.
- Oracle Home filesystem usage.
- Diagnostic destination usage.
- Audit destination usage.
- Trace destination usage.
- Archive destination usage.
- Backup/stage filesystem usage if configured.


### Implementado en Fase 2B

El grupo `storage` actual incluye estos checks implementados:

- `tablespace_free_pct` — porcentaje libre mínimo por tablespace permanente, con MB totales/usados/libres, porcentaje libre/usado, indicador de autoextend, peor tablespace y umbrales de política.
- `tablespace_used_pct` — porcentaje usado máximo por tablespace, con peor tablespace y umbrales configurables de advertencia/fallo.
- `datafiles_autoextend_disabled` — datafiles con `AUTOEXTENSIBLE = NO`; por defecto genera `WARNING` porque los datafiles fijos pueden ser intencionales.
- `datafiles_near_maxsize` — datafiles autoextensibles cercanos al `MAXSIZE` configurado.
- `datafiles_status` — datafiles con `STATUS` u `ONLINE_STATUS` anómalo, como estados offline/recover/unavailable.
- `tempfiles_status` — verifica que existan tempfiles y que estén en estado aceptable.
- `temp_usage_pct` — porcentaje de uso activo de tablespaces temporales usando `dba_temp_files` más `v$tempseg_usage`; la evidencia fallback de `v$temp_space_header` se marca claramente y se omite del thresholding para evitar falsos positivos.
- `undo_tablespace_status` — valida metadatos del tablespace UNDO actual, retención, estado y evidencia de tamaño/uso cuando está disponible.
- `fra_configured` — informa si FRA está configurada; si falta, queda `SKIPPED` por defecto salvo que un estándar cambie la política.
- `fra_usage` — porcentajes de uso y espacio reclaimable de FRA, con comportamiento `SKIPPED` claro cuando FRA no está configurada.

Estos checks reutilizan una estructura de inventario `database.storage` con detalles de tablespaces, datafiles, tempfiles, uso temporal, FRA y UNDO. La implementación evita vistas AWR y Diagnostic Pack, mantiene compatibilidad con `example_standalone` y conserva las remediaciones únicamente en `corrective_actions.html`.

### Implementado en Fase 2P

La Fase 2P agrega una primera tanda conservadora de gaps de almacenamiento del roadmap inicial, sin crear grupos nuevos ni modificar `config/targets.yaml`:

- `users_system_default_tablespace` — detecta usuarios abiertos de aplicación con `SYSTEM` como tablespace por defecto, excluyendo cuentas internas mantenidas por Oracle.
- `users_system_temp_tablespace` — detecta usuarios con `SYSTEM` como tablespace temporal.
- `users_missing_default_tablespace` — validación defensiva para usuarios sin tablespace por defecto existente.
- `users_missing_temp_tablespace` — validación defensiva para usuarios sin tablespace temporal existente.
- `dictionary_managed_tablespaces` — detecta tablespaces con `EXTENT_MANAGEMENT = 'DICTIONARY'`.

Permanecen pendientes para fases posteriores fragmentación avanzada, objetos sin posibilidad de extender y análisis de crecimiento de segmentos.

### Typical collectors

```text
oracle_sql
os_adapter
ssh_command
plugin
```

### Typical evaluators

```text
threshold
row_count_threshold
empty_result_pass
not_empty_fail
custom
```

---

## 7. Group: schema_objects

### Purpose

Validate schema design, object health, indexing, constraints, statistics, partitioning, jobs, synonyms, segment structure, and invalid or disabled objects.

### Checks to include

#### Table design

- Tables without primary key.
- Tables without unique key or index.
- Tables with more than configured number of indexes.
- Tables with more than configured number of columns.
- Tables with LONG or LONG RAW columns.
- Tables with row length greater than block size.
- Objects with mixed case or quoted names.

#### Index design

- Indexes with more than configured number of columns.
- Redundant indexes with same leading columns.
- Primary keys or unique constraints using non-unique indexes.
- Unusable indexes.
- Unusable index partitions.
- Unusable index subpartitions.

#### Constraints

- Foreign keys without corresponding index.
- Foreign keys with unusable index.
- Foreign keys with non-matching column definitions.
- Foreign keys mixing nullable and non-nullable columns.
- Unique keys with nullable columns.
- Disabled constraints.

#### Triggers

- Disabled triggers.
- Invalid triggers.

#### Statistics

- Schemas with tables not analyzed.
- Table partitions not analyzed.
- Indexes not analyzed.
- Index partitions not analyzed.
- Stale statistics.
- Missing statistics.

#### Partitioning

- Partitioned tables with non-partitioned indexes.
- Hash partitions whose count is not a power of two.
- Partition row chaining.
- Subpartition health when applicable.

#### Row chaining

- Tables with row chaining above configured threshold.
- Table partitions with row chaining above configured threshold.

#### Jobs

- DBMS_JOB status.
- DBMS_SCHEDULER jobs.
- Failed jobs.
- Disabled jobs.
- Jobs with long runtime.
- Broken jobs.

#### Synonyms and privileges

- Objects with privileges granted but without corresponding synonyms.
- Invalid public synonyms.
- Invalid private synonyms.

#### Invalid objects

- Invalid objects.
- Package bodies without package specification.
- Invalid dependencies.

### Implementado en Fase 2P

La Fase 2P agrega una primera tanda conservadora de gaps de objetos de esquema del roadmap inicial, reutilizando filtros de esquemas internos y evitando consultas a tablas de negocio:

- `tables_without_primary_key` — detecta tablas de aplicación no temporales sin llave primaria.
- `foreign_keys_without_index` — detecta llaves foráneas habilitadas sin índice compatible en las columnas iniciales y en el mismo orden.
- `tables_with_long_columns` — detecta columnas `LONG` o `LONG RAW` en tablas de aplicación.
- `indexes_too_many_columns` — detecta índices de aplicación que superan el umbral conservador de columnas configurado en el check.

Permanecen pendientes para fases posteriores índices redundantes, particionamiento avanzado, row chaining avanzado y validaciones complejas de fragmentación o crecimiento.

### Typical collectors

```text
oracle_sql
plugin
```

### Typical evaluators

```text
row_count_threshold
empty_result_pass
not_empty_fail
threshold
custom
```

---

## 8. Grupo: operational_readiness

### Purpose

Validar parámetros y configuraciones operativas recomendadas para que una base de datos esté preparada para operar de forma estable y controlada en ambientes críticos. Este grupo no representa un perfil ni un ambiente específico.

### Checks to include

#### Audit and traceability

- `audit_trail`.
- SYS operations audit.
- Minimum audit policy.
- Audit table location.

#### PL/SQL and code execution

- `plsql_optimize_level`.
- `plsql_code_type`.
- `plsql_debug`.

#### Diagnostics and performance overhead

- `timed_os_statistics`.
- `sql_trace`.
- Trace settings.
- Excessive diagnostic settings.
- `max_dump_file_size`.

#### Result cache

- Client result cache lag.
- Result cache size.
- `result_cache_max_result`.
- `result_cache_mode`.
- `result_cache_remote_expiration`.

#### Safety and optimizer

- `db_ultra_safe`.
- `optimizer_capture_sql_plan_baselines`.
- `optimizer_use_invisible_indexes`.

#### Production baseline

- `recyclebin`.
- Archivelog mode.
- Flashback if required by standard.
- Force logging if required by standard.
- Critical jobs enabled.
- Backup recency if configured.

### Typical collectors

```text
oracle_sql
plugin
```

### Typical evaluators

```text
expected_value
threshold
row_count_threshold
custom
```

---

## 9. Group: security

### Purpose

Identify security weaknesses, excessive privileges, risky profiles, default users, default passwords, unsafe parameters, public grants, and audit gaps.

### Checks to include

#### Privileges and grants

- Redundant object privileges with `GRANT OPTION`.
- Object privileges with `GRANT OPTION`.
- System privileges with `ADMIN OPTION`.
- Roles with `ADMIN OPTION`.
- Powerful system privileges granted directly.
- Powerful roles granted directly.
- Direct grants on `V$` views.
- Direct grants on SYS tables.
- Powerful SYS packages granted to PUBLIC.

#### Roles

- Unassigned roles.
- Nested roles.
- Use of `CONNECT` role.
- Use of `RESOURCE` role.
- Use of `DBA` role.

#### Users

- OS-authenticated users.
- Active default Oracle users.
- Default users not locked.
- Users with default passwords.
- Users with SYSDBA privilege.
- Users with SYSOPER privilege.
- Users with SYSASM privilege.
- Open accounts with no recent usage when data is available.
- Expired accounts.
- Locked accounts as informational.

#### Profiles

- Vulnerable profiles.
- `FAILED_LOGIN_ATTEMPTS`.
- `PASSWORD_LIFE_TIME`.
- `PASSWORD_GRACE_TIME`.
- `PASSWORD_REUSE_TIME`.
- `PASSWORD_REUSE_MAX`.
- `PASSWORD_VERIFY_FUNCTION`.
- Users with DEFAULT profile in production if standard requires a custom profile.

#### Parameters

- `SEC_CASE_SENSITIVE_LOGON`.
- `REMOTE_OS_AUTHENT`.
- `O7_DICTIONARY_ACCESSIBILITY`.
- `SQL92_SECURITY`.
- Insecure remote authentication parameters.

#### Synonyms

- Invalid public synonyms.
- Invalid private synonyms.

#### Protocol and banner

- Security protocol error handling.
- Security protocol tracing.
- Server version banner exposure.

#### Audit

- Audit trail enabled.
- SYS operations audited.
- Minimum audit policies if defined.

### Implementado en Fase 2C

La fase 2C implementa checks de seguridad Oracle basados en vistas de diccionario y parámetros estándar, sin usar AWR, ASH ni Diagnostic Pack:

- `locked_users` — inventario informativo de usuarios bloqueados desde `DBA_USERS` con `ACCOUNT_STATUS like '%LOCKED%'`.
- `expired_users` — usuarios expirados desde `DBA_USERS`, excluyendo cuentas bloqueadas.
- `default_open_users` — cuentas default abiertas.
- `default_profile_users` — usuarios abiertos con perfil `DEFAULT`.
- `dba_role_users` — usuarios o roles con rol `DBA` otorgado.
- `critical_privilege_users` — privilegios críticos otorgados directamente.
- `remote_login_passwordfile_security` — política de `remote_login_passwordfile`.
- `sec_case_sensitive_logon` — validación condicionada por versión para `sec_case_sensitive_logon`.
- `audit_trail_security` — configuración básica de auditoría.
- `permissive_failed_login_profiles` — perfiles con `FAILED_LOGIN_ATTEMPTS` permisivo.
- `unlimited_password_life_profiles` — perfiles con `PASSWORD_LIFE_TIME` ilimitado o heredado.
- `missing_password_verify_profiles` — perfiles sin función efectiva de verificación de contraseña.
- `common_accounts_not_locked_or_expired` — cuentas comunes/default que deberían estar bloqueadas; una cuenta expirada sin bloqueo sigue siendo hallazgo.

### Implementado en Fase 3B

La fase 3B amplía el grupo `security` sin mover ni duplicar checks existentes. Se agregan checks conservadores para:

- `oracle_maintained_open_users` — cuentas `ORACLE_MAINTAINED='Y'` distintas de `SYS` y `SYSTEM` que permanecen `OPEN`; se reportan como revisión preventiva.
- `admin_privilege_users` — usuarios no esperados con privilegios administrativos del password file como `SYSDBA`, `SYSOPER`, `SYSASM`, `SYSBACKUP`, `SYSDG`, `SYSKM` o `SYSRAC`.
- `external_authenticated_users` — usuarios no internos con autenticación externa.
- `proxy_users_configured` — relaciones de proxy authentication configuradas.
- `any_privilege_users` — privilegios amplios tipo `ANY` no cubiertos por `critical_privilege_users`.
- `admin_option_grants` — privilegios de sistema con `ADMIN OPTION`.
- `grant_option_object_privileges` — privilegios de objeto con `GRANT OPTION`.
- `legacy_roles_assigned` — asignaciones directas de `CONNECT` o `RESOURCE`.
- `dictionary_access_privileges` — acceso sensible al diccionario mediante `SELECT ANY DICTIONARY`, `SELECT_CATALOG_ROLE` o `EXECUTE_CATALOG_ROLE`.
- `inactive_users_by_last_login` — usuarios abiertos no internos con `LAST_LOGIN` antiguo o no registrado cuando la columna está disponible.
- `legacy_password_versions` — usuarios no internos con versiones antiguas de contraseña como `10G`.

Reglas de clasificación de Fase 3B:

- `SYS` y `SYSTEM` se excluyen de hallazgos por privilegios elevados esperados para evitar falsos positivos.
- Los usuarios y roles Oracle-maintained se excluyen de checks de privilegios elevados esperados cuando la vista expone `ORACLE_MAINTAINED`.
- Las cuentas Oracle-maintained abiertas distintas de `SYS` y `SYSTEM` se revisan únicamente en `oracle_maintained_open_users`.
- Si columnas dependientes de versión como `ORACLE_MAINTAINED` o `LAST_LOGIN` no están disponibles, el check queda omitido o con error controlado según su configuración; no debe producir traceback.
- No se usaron AWR, ASH, `DBA_HIST%`, Diagnostic Pack, Tuning Pack, SQLite ni vistas internas `X$`.

Siguen pendientes para fases futuras revisiones avanzadas de Unified Audit Trail, fallos históricos de login, Database Vault, redacción de datos, TDE avanzado, OLS, SQL Firewall, sesiones históricas, roles anidados/no asignados y paquetes SYS a PUBLIC.

### Typical collectors

```text
oracle_sql
plugin
```

### Typical evaluators

```text
empty_result_pass
not_empty_fail
row_count_threshold
expected_value
custom
```

---

## 10. Group: rac

### Purpose

Validate Oracle RAC health, clusterware status, service distribution, interconnect, OCR, voting disks, node consistency, and RAC-specific performance symptoms.

### Checks to include

#### Clusterware

- CRS status.
- OHASD status.
- Cluster resources offline.
- Cluster resources in intermediate state.
- Auto-start resources disabled.
- GIMR status if applicable.

#### Nodes and instances

- Nodes online.
- Instances active.
- Instance status by node.
- Parameter differences between RAC instances.
- Patch differences between nodes.

#### Services

- RAC services status.
- Services not running.
- Services running on unexpected instances.
- Service balance.
- Preferred and available instance configuration.

#### Network

- SCAN status.
- SCAN listeners.
- VIPs.
- Local listeners.
- Interconnect.
- Interconnect MTU.
- Private network.
- Name resolution.

#### Storage and cluster metadata

- OCR status.
- OCR location.
- Voting disk status.
- Voting disk location.
- ASM per node.
- Diskgroups visible by node.

#### Time synchronization

- CTSS.
- NTP.
- Chrony.
- Clock differences across nodes.

#### RAC performance

- Global Cache waits.
- `gc current block busy`.
- `gc cr block busy`.
- Session distribution by instance.
- Load distribution by instance.
- Hot blocks when available.

### Typical collectors

```text
oracle_sql
ssh_command
os_adapter
plugin
```

### Typical evaluators

```text
expected_value
row_count_threshold
comparison
regex
custom
```

---

## 11. Group: dataguard

### Purpose

Validate Data Guard transport, apply, protection, role, broker, lag, standby redo, readiness for switchover/failover, and DRP operability.

### Checks to include

#### Role and protection

- Database role.
- Primary/standby role consistency.
- Protection mode.
- Protection level.
- Open mode.
- Force logging.
- Supplemental logging if required by standard.

#### Transport and apply

- Transport lag.
- Apply lag.
- Apply rate.
- MRP status.
- RFS status.
- Archive destinations.
- Errors in `v$archive_dest_status`.
- Gaps.
- Primary sequence vs standby sequence.

#### Broker

- Broker enabled.
- Broker status.
- Configuration status.
- Database status under broker.
- Fast Start Failover.
- Observer status.

#### Standby redo logs

- Standby redo logs exist.
- Standby redo logs per thread.
- Standby redo log size.
- Standby redo log status.

#### Real-time apply and recovery

- Real-time apply.
- Flashback database.
- Managed recovery.
- Recovery errors.

#### Parameters

- `log_archive_config`.
- `log_archive_dest_n`.
- `fal_server`.
- `fal_client`.
- `standby_file_management`.
- `db_file_name_convert`.
- `log_file_name_convert`.

#### Capacity

- FRA primary.
- FRA standby.
- Archive destination space.
- Archive deletion policy if enabled.

#### Readiness

- Switchover readiness.
- Failover readiness.
- DRP precheck status.

### DRP behavior

Data Guard checks must respect DRP conditions:

- If the standby database is mounted, checks that support mounted mode should run.
- If the standby database is closed or inaccessible but OS/ASM are available, OS and ASM checks should still run.
- Checks requiring an open database must be `SKIPPED`, not failed.
- Reports must clearly explain limitations.

### Typical collectors

```text
oracle_sql
ssh_command
plugin
```

### Typical evaluators

```text
threshold
expected_value
comparison
row_count_threshold
custom
```

---

## 12. Group: asm

### Purpose

Validate ASM instance availability, diskgroup health, capacity, redundancy, compatibility, rebalance, and storage risks.

### Checks to include

#### ASM instance

- ASM instance up.
- ASM instance status.
- ASM version.
- ASM spfile.
- ASM listener.

#### Diskgroups

- Diskgroups mounted.
- Diskgroup usage.
- Diskgroup free space.
- Diskgroup redundancy.
- Diskgroup state.
- Diskgroup compatibility ASM.
- Diskgroup compatibility RDBMS.
- Diskgroup sector size if available.

#### Disks

- Offline disks.
- Warning disks.
- Failed disks.
- Disk path consistency.
- Failgroups.
- Header status.

#### Rebalance

- Rebalance in progress.
- Rebalance power.
- Long-running rebalance.

#### Cluster metadata

- Voting disks in ASM.
- OCR in ASM.

#### Logs

- ASM alert log errors.
- Diskgroup mount errors.
- ASM I/O errors.

### Typical collectors

```text
oracle_sql
ssh_command
os_adapter
plugin
```

### Typical evaluators

```text
threshold
expected_value
row_count_threshold
regex
custom
```

---

## 13. Group: os

### Purpose

Validate operating system health, Oracle host readiness, filesystem usage, CPU, memory, swap, network, time synchronization, Oracle processes, platform parameters, and storage path health.

### Important design rule

Generic OS checks must use OS adapter methods. Do not hardcode Linux commands into generic OS checks. AIX must be handled as an independent platform.

### Common OS checks

- OS version.
- Kernel version.
- Architecture.
- CPU count.
- CPU usage.
- Memory usage.
- Swap usage.
- Filesystem usage.
- Mount points.
- Ulimits.
- Oracle processes.
- ASM processes.
- Listener processes.
- Oracle environment variables.
- Time synchronization.
- Network interfaces.
- Routing table.
- DNS/name resolution when configured.
- System errors.
- Multipath status.
- Storage paths.
- Oracle Base space.
- Oracle Home space.
- Diagnostic destination space.
- Audit destination space.
- Trace destination space.

### Linux-specific checks

- HugePages.
- Transparent HugePages.
- `sysctl` values.
- `limits.conf` values.
- `tuned` profile.
- Chrony status.
- Timedatectl status.
- Multipath status.
- Systemd services relevant to Oracle.
- Kernel parameters required by Oracle.

### AIX-specific checks

- `oslevel`.
- `vmo` values.
- `ioo` values.
- `schedo` values.
- `no` values.
- `svmon` memory status.
- `errpt` errors.
- `lspath` path status.
- `lsmpio` MPIO status.
- `lsvg` volume groups.
- `lslv` logical volumes.
- `lspv` physical volumes.
- `xntpd` status.
- `lslpp` installed packages.
- `instfix` maintenance level.

### Typical collectors

```text
os_adapter
ssh_command
local_command
plugin
```

### Typical evaluators

```text
threshold
expected_value
regex
row_count_threshold
custom
```

---

## 14. Group: capacity

### Purpose

Evaluate current capacity and saturation risk. This group must not require an internal historical repository.

### Checks to include

#### Database capacity

- Tablespace usage.
- Datafile usage.
- Tempfile usage.
- FRA usage.
- Archive destination usage.
- Undo usage.
- TEMP usage.
- Sessions usage.
- Processes usage.
- Redo generation rate.
- Archive generation rate.

#### ASM capacity

- Diskgroup usage.
- Diskgroup free space.
- Diskgroup usable file MB.
- Diskgroup imbalance if available.

#### OS capacity

- Filesystem usage.
- CPU usage.
- Memory usage.
- Swap usage.
- Storage path status.

#### Optional trend

Trend analysis may use data already available in Oracle, such as AWR, only when explicitly enabled and licensed. If no historical data is available, the report must indicate that the analysis is a current snapshot.

### Estado Fase 4A

El grupo formal `capacity` existe desde Fase 4A con `checks: []`. No contiene checks propios todavía. La cobertura adelantada se documenta como existente en `storage`, `oracle_resources`, `io_redo_archive`, `configuration_general` y `operational_readiness`, sin mover ni duplicar checks.

Los primeros checks propios deben agregarse en Fase 4C como fotografía actual. No debe introducirse SQLite, repositorio histórico interno ni tendencia basada en AWR/ASH/`DBA_HIST%` por defecto.

### Typical collectors

```text
oracle_sql
os_adapter
plugin
```

### Typical evaluators

```text
threshold
comparison
custom
```

---

## 15. Group: patching

### Purpose

Validate Oracle patch inventory, SQL patch application, RAC patch consistency, and readiness for maintenance windows.

### Checks to include

#### Inventory

- Oracle Database version.
- Grid Infrastructure version.
- OPatch version.
- Installed interim patches.
- Installed RU/RUR when identifiable.
- Oracle inventory readability.
- Oracle Home path.
- Grid Home path.

#### SQL patching

- SQL patches installed.
- `datapatch` status.
- Invalid SQL patch entries.
- Components needing SQL patch.

#### RAC consistency

- Patch differences across RAC nodes.
- OPatch version differences across nodes.
- Oracle Home differences across nodes.
- Grid Home differences across nodes.

#### Maintenance readiness

- Free space in Oracle Home filesystem.
- Free space in Grid Home filesystem.
- Free space in staging filesystem.
- Invalid objects before patching.
- CRS status before patching.
- ASM status before patching.
- Data Guard status before patching.
- PDB open status before patching.
- Backup status if configured.

### Typical collectors

```text
oracle_sql
ssh_command
os_adapter
plugin
```

### Typical evaluators

```text
expected_value
comparison
row_count_threshold
regex
custom
```

---

## 16. Recommended Profiles and Group Mapping

### standalone_basic

```yaml
enabled_groups:
  - configuration_general
  - storage
  - os
```

### standalone_full

```yaml
enabled_groups:
  - configuration_general
  - performance
  - alert_log
  - storage
  - schema_objects
  - operational_readiness
  - security
  - os
  - capacity
```

### rac_full

```yaml
enabled_groups:
  - configuration_general
  - performance
  - alert_log
  - storage
  - schema_objects
  - operational_readiness
  - security
  - rac
  - asm
  - os
  - capacity
```

### dataguard_full

```yaml
enabled_groups:
  - configuration_general
  - performance
  - alert_log
  - storage
  - operational_readiness
  - security
  - dataguard
  - os
  - capacity
```

### rac_dataguard_full

```yaml
enabled_groups:
  - configuration_general
  - performance
  - alert_log
  - storage
  - schema_objects
  - operational_readiness
  - security
  - rac
  - asm
  - dataguard
  - os
  - capacity
```

### security_audit

```yaml
enabled_groups:
  - security
  - operational_readiness
```

### capacity_performance

```yaml
enabled_groups:
  - performance
  - capacity
  - storage
  - os
```

### patching_readiness

```yaml
enabled_groups:
  - patching
  - storage
  - os
  - rac
  - asm
  - dataguard
```

### drp_precheck_compare

```yaml
enabled_groups:
  - dataguard
  - asm
  - os
  - storage
  - capacity
```

Special DRP rules:

- Allow database mounted mode.
- Do not fail checks that require open database.
- Run OS and ASM checks when available.
- Explain skipped checks clearly.

---

## 17. Check Metadata Requirements

Every check should include remediation metadata:

```yaml
remediation:
  summary:
  actions:
    - action 1
    - action 2
  validation:
    - validation step
  owner: DBA | OS | Storage | Network | Security | Application | Mixed
  requires_window: true | false
  outage_risk: low | medium | high
```

Every check should include technical metadata:

```yaml
tags:
  - oracle
  - production
  - security
  - storage
```

Optional references:

```yaml
references:
  - Oracle documentation reference or internal standard
```

---

## 18. Severity Guidelines

Use severities consistently:

### INFO

Use for inventory and informational checks.

### WARNING

Use for preventive findings or deviations that should be reviewed.

### FAIL

Use for clear noncompliance that can affect stability, security, performance, or maintainability.

### CRITICAL

Use for immediate or high risk situations, such as:

- FRA nearly full.
- Archive destination full.
- Data Guard apply stopped.
- MRP not running when required.
- Critical ASM diskgroup space issue.
- ORA-00600 or ORA-07445 in alert log.
- Database not in expected role.
- Critical cluster resource offline.
- Severe security exposure.

---

## 19. First Implementation Minimal Check Set

The first phase should include only these checks to validate the architecture:

```text
database_status
database_open_mode
archivelog_mode
tablespace_free_pct
fra_usage
invalid_objects
os_filesystem_usage
os_memory
os_cpu
alert_log_ora_errors_basic
```

After these work correctly, implement each group progressively.

---

## 20. Final Rule for Check Group Maintainability

Do not place hundreds of checks directly in target configuration.

The correct pattern is:

```text
Target chooses Profile.
Profile enables Check Groups.
Check Groups list Checks.
Standards define thresholds.
Target overrides exceptions only.
```

This keeps OraHealthCheck powerful while remaining maintainable.

---

## Nota de evolución controlada de grupos

Además de los grupos requeridos originalmente en este documento, el proyecto acepta y conserva los siguientes grupos adicionales implementados por evolución controlada:

```text
oracle_resources
io_redo_archive
recoverability_drp
multitenant
```

Estos grupos no eliminan ni reemplazan la lista original de grupos requeridos. Se conservan porque documentan funcionalidad ya implementada y serán reconciliados documentalmente con el roadmap y las fases futuras según `docs/IMPLEMENTATION_STATUS.md`.

---

## Actualización Fase 3A.1 - Grupo operational_readiness

El grupo antes llamado `production_readiness` fue reemplazado por `operational_readiness` para evitar confusión entre grupos técnicos y perfiles de ejecución. `operational_readiness` es un grupo de checks, no un perfil.

El grupo contiene inicialmente checks basados en `V$PARAMETER` para:

```text
plsql_optimize_level
plsql_code_type
plsql_debug
sql_trace
timed_statistics
timed_os_statistics
result_cache_mode
result_cache_max_result
result_cache_remote_expiration
db_ultra_safe
optimizer_capture_sql_plan_baselines
optimizer_use_invisible_indexes
```

No se movieron ni duplicaron checks existentes. Checks como `archivelog_mode`, `force_logging`, `audit_trail`, `audit_trail_security`, `recyclebin`, `flashback_status`, `remote_login_passwordfile` y `sec_case_sensitive_logon` permanecen en los grupos donde fueron creados originalmente.

Esta fase no agrega AWR, ASH, `DBA_HIST%`, Diagnostic Pack, Tuning Pack, SQLite ni repositorio histórico interno.

---

## Actualización Fase 3A - Perfiles standalone y separación topología/almacenamiento

Se agrega el perfil `standalone_all` para ejecutar una revisión amplia de bases standalone con todos los grupos ya implementados y razonablemente aplicables a esa topología. Este perfil incluye `operational_readiness` para evitar omisiones por configuración de perfiles cuando se requiere una evaluación amplia.

Diferencia conceptual de perfiles:

```text
standalone_basic:
  Perfil básico y liviano para health check general de una base standalone.
  No pretende ejecutar todos los checks existentes.

standalone_all:
  Perfil amplio para ejecutar los grupos ya implementados y razonablemente aplicables a una base standalone.
  Incluye operational_readiness.
  Debe entenderse como standalone sobre filesystem o standalone sobre ASM.
  No significa filesystem-only.

```


Separación conceptual:

```text
Grupo de checks = dominio técnico que se valida.
Perfil = combinación de grupos ejecutada según intención, topología o alcance.
```

Ejemplos de perfiles:

```text
standalone_basic
standalone_all
rac_full
drp_precheck_compare
security_audit
```

Ejemplos de grupos técnicos:

```text
configuration_general
storage
security
schema_objects
alert_log
operational_readiness
```

OraHealthCheck separa topología de base de datos y tipo de almacenamiento.

Topología:

- `standalone`.
- `rac`.

Almacenamiento:

- ASM.
- filesystem.

Reglas conceptuales para fases futuras:

- Una base standalone puede estar sobre filesystem o sobre ASM.
- ASM no implica RAC.
- RAC moderno debe asumirse como ASM.
- Los checks ASM no deben depender de que la base sea RAC.
- Los checks RAC sí deben depender de que la base sea RAC.
- Cuando exista el grupo ASM, debe poder aplicarse tanto a standalone con ASM como a RAC con ASM.
- El caso RAC sobre filesystem se considera histórico o legacy y no es el objetivo principal del diseño moderno del proyecto.

Esta actualización no crea el grupo `asm`, no agrega checks ASM, no agrega checks RAC y no modifica `config/targets.yaml` ni `standalone_basic`.

### Actualización Fase 4C para `capacity`

Desde Fase 4C el grupo `capacity` contiene 8 checks propios y deja de estar vacío. Su alcance es un fotografía actual de capacidad y margen: tamaño total, uso actual, margen disponible, límite efectivo, riesgo de saturación actual y principales consumidores de espacio.

Checks implementados:

- `capacity_database_size_snapshot`
- `capacity_tablespace_margen`
- `capacity_datafile_margen`
- `capacity_segments_top_size`
- `capacity_temp_capacity_snapshot`
- `capacity_undo_capacity_snapshot`
- `capacity_resource_limits_margen`
- `capacity_fra_archive_margen`

`capacity` no reemplaza a `storage`, `oracle_resources` ni `io_redo_archive`; consolida capacidad actual y margen sin duplicar el mismo hallazgo puntual. No introduce SQLite, no crea repositorio histórico interno y no usa AWR/ASH/`DBA_HIST%` por defecto. TEMP y UNDO quedan incluidos explícitamente en la fotografía de capacidad. Cualquier tendencia futura basada en AWR deberá ser opcional y condicionada a licenciamiento explícito.

### Actualización Fase 5A para `asm`

Desde Fase 5A el grupo `asm` existe con 8 checks reales y aplicabilidad feature-aware. Los checks son:

- `asm_database_uses_asm`
- `asm_database_files_on_asm`
- `asm_diskgroup_inventory_db_view`
- `asm_diskgroup_usage_db_view`
- `asm_diskgroup_state_db_view`
- `asm_diskgroup_free_headroom_db_view`
- `asm_disk_status_db_view`
- `asm_rebalance_operations_db_view`

ASM se evalúa desde la conexión Oracle de la base de datos evaluada. No se conecta a la instancia ASM, no requiere SYSASM/Grid y no usa asmcmd, crsctl ni srvctl. La evaluación se centra en archivos ASM propios de la base, diskgroups relevantes, capacidad y estado observables desde la conexión actual, discos visibles y rebalance. Si no se detectan archivos de base sobre ASM, los checks quedan `SKIPPED` como no aplicables, sin hallazgos ni penalización. `standalone_all` incluye `asm` porque una base standalone puede residir sobre ASM; ASM no implica RAC. La conexión dedicada ASM/Grid queda reservada para una fase avanzada futura.
