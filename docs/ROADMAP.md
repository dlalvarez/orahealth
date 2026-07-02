# OraHealthCheck - Roadmap

## 1. Roadmap Purpose

This roadmap defines a phased implementation plan for OraHealthCheck.

The framework must be built progressively. The first goal is not to implement every Oracle check. The first goal is to build a stable architecture where checks, groups, profiles, standards, connectors, adapters, and reports can grow without redesign.

---

## 2. Implementation Strategy

The implementation must follow these principles:

1. Build the framework foundation first.
2. Add check groups progressively.
3. Keep every phase independently testable.
4. Avoid large, unreviewable changes.
5. Avoid hardcoding values that should belong to standards or profiles.
6. Keep report generation working from Phase 1 onward.
7. Keep compatibility with Linux and AIX from the beginning.
8. Keep support for Oracle standalone, RAC, Data Guard, and ASM in the architecture even if full checks are added later.
9. Do not implement SQLite or internal historical storage.
10. Always generate reports and evidence under `output/<target_id>_<timestamp>/`.

---

## 3. Phase 1 - Framework Foundation

### Objective

Create the base architecture, project structure, CLI, configuration loader, connectors, OS adapters, execution engine, evaluators, initial reports, and a small set of example checks.

### Scope

Implement:

- Python project structure.
- `pyproject.toml`.
- `README.md`.
- `docs/ARCHITECTURE.md`.
- `docs/ROADMAP.md`.
- `docs/CHECK_GROUPS.md`.
- `config/` structure.
- `src/orahealthcheck/` package.
- CLI.
- Configuration loader.
- Configuration validator.
- Models.
- Oracle connector.
- SSH connector.
- Local connector.
- Base OS adapter.
- Linux adapter.
- AIX adapter.
- Collector interfaces.
- Evaluator interfaces.
- Execution engine.
- Applicability engine.
- Basic scoring.
- HTML report generator.
- Output folder generation.
- Initial tests.

### Required CLI commands

```text
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck list-profiles
orahealthcheck list-groups
orahealthcheck list-checks
orahealthcheck run --target <target_id>
```

### Required connectors

- `OracleConnector` using `python-oracledb`.
- `SSHConnector` using `paramiko` or equivalent.
- `LocalConnector` for local commands.

### Required authentication support

Database:

- Username/password in file.
- Password from environment variable.
- SYSDBA mode.
- Wallet structure prepared for later use.
- OS authentication structure prepared for later use.

Operating system:

- SSH username/password.
- SSH private key.
- SSH private key with passphrase.
- Local execution.

### Required OS adapters

- `BaseOSAdapter`.
- `LinuxAdapter`.
- `AIXAdapter`.

Minimum adapter methods:

```text
get_os_info
get_cpu_info
get_memory_info
get_swap_info
get_filesystem_usage
get_ulimits
get_processes
get_oracle_processes
get_time_sync_status
```

### Required evaluators

- `threshold`.
- `expected_value`.
- `empty_result_pass`.
- `not_empty_fail`.
- `row_count_threshold`.
- `regex`.

### Required result statuses

```text
PASS
INFO
WARNING
FAIL
CRITICAL
SKIPPED
ERROR
```

### Required initial reports

Generate:

```text
executive_report.html
technical_report.html
corrective_actions.html
inventory.json
evidence.json
execution.log
```

### Initial checks

Implement at least these checks:

1. `database_status`.
2. `database_open_mode`.
3. `archivelog_mode`.
4. `tablespace_free_pct`.
5. `fra_usage`.
6. `invalid_objects`.
7. `os_filesystem_usage`.
8. `os_memory`.
9. `os_cpu`.
10. `alert_log_ora_errors_basic`.

### Acceptance criteria

The following must work:

```bash
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck run --target example_standalone
```

The run must generate:

```text
output/example_standalone_YYYYMMDD_HHMMSS/
  executive_report.html
  technical_report.html
  corrective_actions.html
  inventory.json
  evidence.json
  execution.log
```

### Out of scope for Phase 1

- Full security checklist.
- Full RAC checks.
- Full Data Guard checks.
- Full ASM checks.
- Full performance and AWR analysis.
- Patching inventory.
- Advanced report UI.
- Historical repository.
- SQLite.

---

## 4. Phase 2 - Configuration, Storage, Schema Objects, and Alert Log

### Objective

Implement the first major set of database health checks based on configuration, storage, schema/object health, and alert log review.

### Groups to implement

- `configuration_general`.
- `storage`.
- `schema_objects` basic.
- `alert_log` basic to intermediate.

### configuration_general checks

Implement checks for:

- Default initialization parameters.
- Deprecated non-default parameters.
- `compatible` vs Oracle version.
- `optimizer_features_enable` vs Oracle version.
- `optimizer_index_caching`.
- `optimizer_index_cost_adj`.
- Parameters incompatible with memory management.
- Number of control files.
- `cpu_count` policy.
- `cursor_sharing` policy.
- `db_cache_size` vs `db_block_buffers`.
- Buffer cache size.
- Large pool size.
- KEEP cache usage.
- RECYCLE cache usage.
- `db_nk_cache_size` usage.
- `db_block_size` policy.
- `db_multiblock_read_count` policy.
- `disk_asynch_io`.
- `dml_locks`.
- `filesystemio_options`.
- `fast_start_mttr_target`.
- `max_dump_file_size`.
- `open_cursors`.
- `query_rewrite_enabled`.
- `recyclebin`.
- `remote_login_passwordfile`.
- `session_cached_cursors`.
- `sga_target` and `sga_max_size`.
- `star_transformation_enabled`.
- `sql_trace`.
- `timed_os_statistics`.
- `timed_statistics`.
- `trace_enabled`.
- Inaccessible DB Links.
- Redo log groups and members.
- `SYS.AUD$` location.
- AWR interval and retention.

Important: values must be policy-driven. Do not hardcode one universal recommendation for all versions and architectures.

#### Phase 2A - Implemented: configuration_general real Oracle checks

Implemented an initial expanded set of real, license-safe Oracle configuration checks for `configuration_general`:

- `compatible` from `v$parameter`.
- `optimizer_features_enable` from `v$parameter`.
- `db_block_size` from `v$parameter`.
- `open_cursors` from `v$parameter`.
- `processes` from `v$parameter`.
- `sessions` from `v$parameter`.
- `audit_trail` from `v$parameter`.
- `remote_login_passwordfile` from `v$parameter`.
- `recyclebin` from `v$parameter`.
- `filesystemio_options` from `v$parameter`.
- `control_files_multiplexed` from `v$controlfile`.
- `redo_log_group_count` from `v$log`.
- `redo_log_members_multiplexed` from `v$logfile`.
- `force_logging` from `v$database`.

The implementation keeps mock target compatibility, stores expected values and thresholds in standards/profile policies, avoids Diagnostic Pack/AWR sources, and handles missing metrics as controlled `ERROR` results instead of tracebacks.

### storage checks

Implement checks for:

- Users with SYSTEM as temporary tablespace.
- Users with SYSTEM as default tablespace.
- Users with missing temporary tablespace.
- Users with missing default tablespace.
- Tablespace fragmentation.
- Tablespaces with low free space considering autoextend.
- Objects unable to extend.
- Dictionary-managed tablespaces.
- Datafiles near maxsize.
- Tempfiles.
- TEMP usage.
- UNDO usage.
- FRA usage.
- Filesystem usage where OS access is available.


#### Fase 2B - Implementado: checks de almacenamiento Oracle

Se implementó un grupo `storage` ampliado y seguro desde el punto de vista de licenciamiento, enfocado en inventario Oracle reutilizable y evidencia accionable para DBA:

- `tablespace_free_pct` con evidencia por tablespace de total, usado, libre, porcentaje libre, porcentaje usado y autoextend.
- `tablespace_used_pct` con peor tablespace y umbrales configurables de porcentaje usado.
- `datafiles_autoextend_disabled` para datafiles de tamaño fijo, con advertencia por defecto porque puede ser intencional.
- `datafiles_near_maxsize` para datafiles autoextensibles cercanos a `MAXSIZE`.
- `datafiles_status` para datafiles fuera de estados aceptables AVAILABLE/ONLINE.
- `tempfiles_status` para tempfiles faltantes o anómalos.
- `temp_usage_pct` con evidencia de uso activo de segmentos temporales y fallback controlado cuando `v$tempseg_usage` no está disponible.
- `undo_tablespace_status` con tablespace UNDO actual, retención, estado y tamaño cuando está disponible.
- `fra_configured` con comportamiento configurable cuando FRA no es obligatoria.
- `fra_usage` con porcentaje de FRA y detalles de espacio reclaimable cuando FRA existe.

La fase usa vistas dinámicas y de diccionario estándar (`dba_tablespaces`, `dba_data_files`, `dba_free_space`, `dba_temp_files`, `v$tempseg_usage`, `v$temp_space_header`, `v$parameter` y `v$recovery_file_dest`) y evita intencionalmente AWR, Diagnostic Pack y vistas históricas licenciadas. Los privilegios faltantes o vistas no disponibles se manejan como resultados controlados de evidencia/estado, no como tracebacks sin manejar.

### schema_objects basic checks

Implement checks for:

- Tables without primary key.
- Tables without unique key or index.
- Tables with too many indexes.
- Tables with too many columns.
- Indexes with too many columns.
- LONG and LONG RAW columns.
- Partitioned tables with non-partitioned indexes.
- Redundant indexes.
- Foreign keys without indexes.
- Unusable indexes.
- Invalid objects.
- Disabled constraints.
- Disabled triggers.
- Failed scheduler jobs.

### alert_log checks

Implement checks for:

- ORA-00600.
- ORA-07445.
- ORA-01555.
- ORA-01652.
- ORA-01653.
- ORA-00257.
- ORA-04031.
- ORA-04030.
- Corruption messages.
- Archive errors.
- Redo errors.
- Standby database errors when found.
- ASM errors when found.

### Phase 2 acceptance criteria

- Groups can be executed independently using CLI.
- Report groups display cleanly.
- Corrective actions include findings from these groups.
- Checks with missing permissions are marked as `ERROR` and do not stop the run.

---

## 5. Phase 3 - Security and Operational Readiness

### Objective

Implement security and production-readiness checks.

### Groups to implement

- `security`.
- `operational_readiness`.

### security checks

Implement checks for:

- Redundant object privileges with `GRANT OPTION`.
- Invalid public synonyms.
- Invalid private synonyms.
- Unassigned roles.
- Nested roles.
- OS-authenticated users.
- Powerful system privileges granted directly.
- Powerful roles granted directly.
- Object privileges with `GRANT OPTION`.
- System privileges with `ADMIN OPTION`.
- Roles with `ADMIN OPTION`.
- Direct grants on `V$` views.
- Direct grants on SYS tables.
- Vulnerable profiles.
- Powerful SYS packages granted to PUBLIC.
- Use of `CONNECT` role.
- Use of `RESOURCE` role.
- Use of `DBA` role.
- Insecure parameters.
- Active default Oracle users.
- Default users not locked.
- Users with default passwords.
- `FAILED_LOGIN_ATTEMPTS`.
- `PASSWORD_LIFE_TIME`.
- `PASSWORD_GRACE_TIME`.
- `PASSWORD_REUSE_TIME`.
- `PASSWORD_REUSE_MAX`.
- `PASSWORD_VERIFY_FUNCTION`.
- `SEC_CASE_SENSITIVE_LOGON`.
- `REMOTE_OS_AUTHENT`.
- `O7_DICTIONARY_ACCESSIBILITY`.
- `SQL92_SECURITY`.
- Users with SYSDBA, SYSOPER, or SYSASM.
- Open accounts with no recent usage, where data is available.

### operational_readiness checks

Implement checks for:

- `audit_trail`.
- SYS operations audit.
- `plsql_optimize_level`.
- `plsql_code_type`.
- `plsql_debug`.
- `timed_os_statistics`.
- Client result cache lag.
- Result cache size.
- `db_ultra_safe`.
- `optimizer_capture_sql_plan_baselines`.
- `optimizer_use_invisible_indexes`.
- `recyclebin`.
- `result_cache_max_result`.
- `result_cache_mode`.
- `result_cache_remote_expiration`.
- Production trace settings.
- Diagnostic settings.
- Archive mode in production.
- Force logging when required by standard.
- Flashback when required by standard.

### Phase 3 acceptance criteria

- A `security_audit` profile can run only security checks.
- A `operational_readiness` profile can run readiness checks.
- The corrective report must identify owner, risk, action, validation, and whether a window is required.

---

## 6. Phase 4 - Performance and Capacity

### Ajuste Fase 4A

Antes de implementar checks nuevos de rendimiento y capacidad, Fase 4A reconcilia la cobertura adelantada existente en `oracle_resources`, `io_redo_archive`, `configuration_general`, `operational_readiness` y `storage`. Esta fase crea los grupos formales `performance` y `capacity` sin checks propios, no mueve checks existentes, no duplica checks, no modifica perfiles activos y no introduce AWR/ASH/`DBA_HIST%`, SQLite ni repositorio histórico interno.

Las fases posteriores quedan separadas así:

- Fase 4B: rendimiento básico sin AWR por defecto.
- Fase 4C: capacidad como fotografía actual sin histórico interno.

### Objective

Implement performance and capacity checks while respecting Oracle licensing boundaries.

### Groups to implement

- `performance`.
- `capacity`.

### performance checks

Implement checks for:

- Connection time.
- Oracle version and basic compatibility information.
- SGA usage.
- SGA distribution.
- Archivelog mode.
- Archivelog generation.
- I/O distribution by datafile.
- Datafiles with high I/O.
- Undo or rollback waits.
- SYS/SYSTEM objects not analyzed.
- SYS/SYSTEM partitions not analyzed.
- SYS/SYSTEM indexes not analyzed.
- `SYS.AUDSES$` cache.
- Active sessions.
- Blocking sessions.
- Long-running sessions.
- Top wait events.
- Wait classes.
- TEMP usage.
- UNDO usage.
- PGA usage.
- SGA advisory if available.
- Buffer cache advisory if available.
- Shared pool pressure.
- Library cache issues.
- Hard parses.
- High-consumption SQL if permissions allow it.

### Licensing rule

Checks requiring AWR, ASH, or `DBA_HIST_%` views must declare:

```yaml
requires:
  awr: true
  diagnostic_pack: true
```

If not enabled in configuration, these checks must be `SKIPPED`.

### capacity checks

Implement checks for:

- Tablespace usage.
- Datafile usage.
- FRA usage.
- ASM usage.
- Filesystem usage.
- Redo generation rate.
- Archive generation.
- TEMP usage.
- UNDO usage.
- Concurrent sessions.
- Processes.
- CPU usage.
- Memory usage.
- Current saturation risk.

No internal history or SQLite should be implemented. If trend analysis is required, use data available inside Oracle, such as AWR, only when enabled and authorized.

### Phase 4 acceptance criteria

- Performance and capacity checks run without requiring AWR by default.
- AWR-based checks are explicitly optional.
- Reports clearly indicate when a trend is based on historical DB data or only current snapshot data.

---

## 7. Phase 5 - RAC, ASM, and Data Guard

### Objective

Implement cluster, ASM, and disaster recovery checks.

### Groups to implement

- `rac`.
- `asm`.
- `dataguard`.

### RAC checks

Implement checks for:

- CRS status.
- OHASD status.
- Offline resources.
- Resources in intermediate state.
- RAC services.
- Service balance.
- Active instances.
- SCAN.
- SCAN listeners.
- VIPs.
- Listeners.
- Interconnect.
- Interconnect MTU.
- Private network.
- Global Cache waits.
- `gc current block busy`.
- `gc cr block busy`.
- Session distribution by instance.
- Service distribution by instance.
- Parameter differences across instances.
- Patch differences across nodes.
- OCR status.
- Voting disks.
- CTSS/NTP/chrony.
- ASM per node.
- Diskgroups per node.
- GIMR status if applicable.

### ASM checks

Implement checks for:

- ASM instance status.
- Mounted diskgroups.
- Diskgroup usage.
- Offline disks.
- Warning disks.
- Rebalance operations.
- Failgroups.
- Redundancy.
- ASM compatibility.
- RDBMS compatibility.
- Voting disks in ASM.
- OCR in ASM.
- ASM alert log.
- ASM spfile.
- ASM listener.
- Available capacity.
- Space exhaustion risk.

### Data Guard checks

Implement checks for:

- Primary/standby role.
- Protection mode.
- Protection level.
- Database open mode.
- Transport lag.
- Apply lag.
- Apply rate.
- MRP status.
- RFS status.
- Archive destinations.
- Errors in `v$archive_dest_status`.
- Gaps.
- Current primary sequence vs standby sequence.
- Broker enabled.
- Broker status.
- Fast Start Failover.
- Observer status.
- Standby redo logs.
- Standby redo logs per thread.
- Real-time apply.
- Flashback.
- Force logging.
- Supplemental logging if required by standard.
- Data Guard parameters.
- FRA on primary.
- FRA on standby.
- Archive deletion policy if enabled.
- Switchover readiness.
- Failover readiness.

### DRP profile behavior

Implement `drp_precheck_compare` with these rules:

- ASM checks may run even if the database is not open.
- OS checks may run even if the database is not open.
- DB checks requiring open mode must be `SKIPPED` if the DB is mounted or closed.
- The report must explain the limitation instead of marking it as failure.
- Primary vs standby comparison must run only when enough data is available.

### Phase 5 acceptance criteria

- RAC, ASM, and Data Guard groups can be executed independently.
- Standalone targets automatically skip RAC/Data Guard/ASM checks unless explicitly configured.
- DRP profile handles mounted or inaccessible DB conditions correctly.

---

## 8. Phase 6 - Patching and Readiness

### Objective

Implement patch inventory and maintenance readiness checks.

### Group to implement

- `patching`.

### patching checks

Implement checks for:

- Oracle Database version.
- Grid Infrastructure version.
- OPatch version.
- Installed patches.
- SQL patches.
- `datapatch` status.
- Patch differences across RAC nodes.
- Oracle inventory.
- Oracle Home.
- Grid Home.
- Available space for patching.
- Invalid objects before maintenance.
- CRS state before maintenance.
- Standby database state before maintenance when applicable.
- ASM state before maintenance.
- Open PDBs before maintenance if applicable.

### Phase 6 acceptance criteria

- Patching checks work for standalone and RAC.
- SQL patch information is reported clearly.
- RAC node differences are highlighted.
- Corrective action report includes pre-window tasks.

---

## 9. Phase 7 - Report Refinement and User Experience

### Objective

Improve report usability and visual quality.

### Scope

Enhance:

- Executive summary.
- Technical detail navigation.
- Corrective action prioritization.
- Group summaries.
- Severity filters.
- Collapsible evidence sections.
- Print-friendly layout.
- Optional logo and customer metadata.
- Optional direct links between executive findings and technical details.
- Improved CSS.

### Acceptance criteria

- Reports must look professional and suitable for customer delivery.
- Reports must be readable by both technical and executive audiences.
- Corrective actions must be easy to convert into an action plan.

---

## 10. Phase 8 - Hardening, Testing, and Packaging

### Objective

Stabilize the framework for repeated use.

### Scope

Implement or improve:

- Unit tests.
- Integration tests with mock Oracle/SSH outputs.
- Sample configurations.
- Sample reports.
- Error handling.
- Logging.
- Packaging.
- Documentation.
- Installation instructions.
- Developer contribution guidelines.

### Tests required

- Configuration loading.
- Profile merging.
- Check group resolution.
- Check overrides.
- Applicability logic.
- Evaluators.
- OS adapters.
- Oracle connector error handling.
- SSH connector error handling.
- Report context generation.
- Scoring.

---

## 11. Suggested Task Breakdown for Codex

Use small implementation tasks rather than one large task.

### Task 1

Create project skeleton, configuration loader, CLI, models, and initial tests.

### Task 2

Implement OracleConnector, SSHConnector, LocalConnector, and connection tests.

### Task 3

Implement OS adapters for Linux and AIX with basic methods.

### Task 4

Implement execution engine, applicability engine, evaluators, and result model.

### Task 5

Implement basic HTML reports and output folder generation.

### Task 6

Add the first 10 checks and example configuration.

### Task 7

Implement `configuration_general` and `storage` groups.

### Task 8

Implement `schema_objects` and `alert_log` groups.

### Task 9

Implement `security` and `operational_readiness` groups.

### Task 10

Implement `performance` and `capacity` groups.

### Task 11

Implement `rac`, `asm`, and `dataguard` groups.

### Task 12

Implement `patching` group.

### Task 13

Refine reports and documentation.

---

## 12. Non-Negotiable Roadmap Rules

1. Do not implement SQLite.
2. Do not implement an internal historical database.
3. Do not hardcode credentials in code.
4. Do not print passwords in logs or reports.
5. Do not stop the whole run because one check fails.
6. Do not mark non-applicable checks as failures.
7. Do not treat AIX as Linux.
8. Do not hardcode all checks into Python.
9. Do not make every target list hundreds of checks.
10. Do not implement all checks before the base framework is stable.

---

## 13. Definition of Done for the Framework Foundation

The foundation is done when:

- CLI works.
- Config validation works.
- Target/profile/group/check loading works.
- Oracle and SSH connectors are available.
- Linux and AIX adapters exist.
- Applicability works.
- Evaluators work.
- Reports are generated.
- Evidence JSON is generated.
- Inventory JSON is generated.
- Execution log is generated.
- At least 10 checks run successfully or skip/error correctly.
- Tests cover core logic.


---

## Nota de alineación posterior a Fase 2M

Después de la Fase 2M se incorporó la Fase 2N como una auditoría documental de alineación entre el roadmap inicial, los grupos definidos originalmente y el estado real implementado. El resultado queda registrado en `docs/IMPLEMENTATION_STATUS.md` y no elimina ni revierte funcionalidades ya implementadas.

### Nota Fase 4A.1 - Política de features no aplicables y perfiles amplios

Los perfiles amplios pueden incluir grupos feature-aware para preservar trazabilidad, aunque la feature no esté presente en un target concreto. En ese caso, los checks dependientes deben terminar como `SKIPPED` con razón clara, sin hallazgos y sin penalización de score. El inventario de features debe seguir mostrando las features no detectadas. Como ajuste menor del PR #29, `standalone_basic` queda como perfil básico standalone sin grupos feature-aware no esenciales, mientras que `standalone_all` conserva grupos feature-aware ya implementados como `rac` y `multitenant` para trazabilidad `SKIPPED`.

La UX esperada queda definida así: el reporte ejecutivo muestra inventario de features y hallazgos reales, sin listar checks `SKIPPED` por check; el reporte técnico resume como bloque compacto los grupos completamente no aplicables por una misma feature requerida no detectada, sin listar cada check omitido; el reporte de evidencias conserva el detalle completo, incluyendo cada check `SKIPPED`; y el reporte de acciones correctivas muestra solo elementos corregibles, sin `SKIPPED`. Las features no detectadas no son hallazgos, no generan penalización y pueden aparecer como checks feature-aware omitidos en perfiles amplios para preservar trazabilidad.

Quedan para fases futuras los perfiles específicos para RAC, ASM, configuraciones con bases standby/Data Guard real y posibles perfiles de auditoría completa. No deben crearse perfiles como `rac_all`, `rac_full`, `asm_all`, `asm_full`, `dataguard_all`, `dataguard_full`, `oracle_full`, `audit_all` o similares hasta que los grupos correspondientes existan, tengan checks reales y cuenten con aplicabilidad clara y pruebas representativas.

### Fase 4B completada - Performance básico actual sin AWR/ASH

Se implementa el grupo `performance` con 9 checks iniciales basados en vistas dinámicas actuales permitidas (`V$INSTANCE`, `V$SESSION`, `V$SESSION_LONGOPS`, `V$SYSSTAT`, `V$LIBRARYCACHE` y `V$SQL`). Esta fase excluye AWR, ASH, `DBA_HIST%`, `DBMS_WORKLOAD_REPOSITORY`, `DBA_ADVISOR`, `DBA_SQLTUNE`, SQL Monitor licenciado, vistas `X$`, SQLite y cualquier repositorio histórico interno.

El foco principal queda en la fotografía actual de esperas por `WAIT_CLASS` y `EVENT`. Los segundos de espera agregados se documentan como segundos observados en la muestra actual, no como DB Time histórico. Los thresholds por `WAIT_CLASS` son configurables desde estándares, con `Idle` excluido por defecto y configuración `default` para wait classes no declaradas. El SQL actual se reporta como actividad presente y no como top SQL histórico. `capacity` continúa pendiente para una fase posterior.

### Actualización Fase 4C - Capacity fotografía actual sin histórico interno

Fase 4C queda implementada como fotografía actual de capacidad, sin proyección ni repositorio interno. Se agregan checks reales al grupo `capacity` para tamaño de base de datos, margen de tablespaces/datafiles, segmentos principales, TEMP, UNDO, límites de recursos y FRA/archive. `standalone_all` incluye `capacity`; `standalone_basic` permanece sin cambios.

La implementación mantiene las restricciones de licenciamiento: no usa AWR, ASH, `DBA_HIST%`, `DBMS_WORKLOAD_REPOSITORY`, SQL Monitor licenciado, `DBA_ADVISOR`, `DBA_SQLTUNE`, SQLite ni vistas `X$`. Las tendencias futuras basadas en AWR solo podrán ser opcionales, explícitas y condicionadas a licenciamiento.

### Nota Fase 5A - ASM básico feature-aware desde conexión de base de datos

Fase 5A implementa el grupo real `asm` con checks iniciales feature-aware ejecutados desde la misma conexión Oracle de la base evaluada. Esta fase no se conecta a la instancia ASM, no requiere SYSASM ni usuario Grid, y no usa asmcmd, crsctl ni srvctl. El alcance se limita a archivos ASM realmente usados por el target, diskgroups relevantes, capacidad/estado observable, discos visibles y rebalance desde vistas dinámicas permitidas. Si ASM no se detecta, los checks quedan `SKIPPED` sin hallazgos ni penalización. `standalone_all` incluye `asm` porque una base standalone puede usar ASM y ASM no implica RAC; la conexión dedicada ASM/Grid queda fuera de alcance para una fase avanzada futura.

## Fase 5B.1 — Data Guard básico feature-aware

Estado: implementada. Se crea el grupo `dataguard` con 8 checks reales para configuraciones Oracle Data Guard con bases standby. La aplicabilidad usa la feature `standby_configuration`; bases sin señales standby quedan SKIPPED sin hallazgos ni penalización. El alcance se limita a vistas SQL estándar no licenciadas y no usa AWR, ASH, DBA_HIST ni X$. Broker/DGMGRL, FSFO y Observer quedan fuera de alcance para una fase avanzada.

### Fase 5B.2 — Data Guard avanzado y Broker readiness

Estado: implementada. El grupo `dataguard` se amplía de 8 a 16 checks reales, manteniendo aplicabilidad `standby_configuration` para que bases sin standby queden omitidas sin hallazgos, acciones correctivas ni penalización. La fase agrega readiness SQL básico para Broker, FSFO, Observer, procesos gestionados, switchover, consistencia de protección y transporte redo hacia standby.

Broker, FSFO y Observer se evalúan solo cuando hay evidencia SQL y aplicabilidad. Broker no habilitado y FSFO no habilitado no son fallos automáticos. No se invocan herramientas externas de Broker ni fuentes de packs diagnósticos; tampoco se usan AWR, ASH, DBA_HIST ni X$.
