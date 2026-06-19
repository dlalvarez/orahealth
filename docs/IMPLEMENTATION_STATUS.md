# OraHealthCheck - Estado de implementación y alineación del roadmap

## 1. Propósito

Este documento registra el estado real de implementación de OraHealthCheck frente a los documentos rectores iniciales: `docs/ROADMAP.md`, `docs/CHECK_GROUPS.md` y `docs/ARCHITECTURE.md`.

La Fase 2N no agrega checks Oracle nuevos ni rediseña el motor. Su objetivo es dejar una foto oficial del avance actual, identificar funcionalidades completas, parciales, pendientes o adelantadas, y formalizar las desviaciones aceptadas para continuar el roadmap sin romper compatibilidad.

## 2. Regla de conservación

```text
No se elimina nada de lo ya implementado.
Las funcionalidades adelantadas o adicionales se conservan.
Las desviaciones aceptadas se documentan.
El roadmap se continúa completando sin romper compatibilidad.
```

Esta regla aplica explícitamente a los grupos `oracle_resources`, `io_redo_archive`, `recoverability_drp`, `multitenant`, al soporte básico de `rac`, a la detección de features, a la visualización de features en reportes, al reporte dedicado de evidencias y a la limpieza de nomenclatura Data Guard ya realizada.

## 3. Estado por fase

| Fase | Nombre | Estado | Implementado | Parcial | Pendiente | Observaciones |
| --- | --- | --- | --- | --- | --- | --- |
| Fase 1 | Framework Foundation | PARCIAL | Estructura Python, CLI base, loader/validator, modelos, conectores Oracle/SSH/Local, adaptadores Linux/AIX, engine, aplicabilidad, scoring, reportes HTML/JSON/log, checks iniciales y pruebas. | Faltan o requieren ampliación comandos avanzados y evaluadores base `comparison`/`contains`/`custom`; algunos collectors declarados en arquitectura todavía no existen como módulos separados. | Completar paridad con todos los comandos, collectors y evaluadores definidos originalmente. | La base funcional está operativa y validada, pero no cubre todo el alcance fundacional descrito en arquitectura. |
| Fase 2 | Configuration, Storage, Schema Objects, Alert Log | PARCIAL | `configuration_general`, `storage`, `schema_objects` y `alert_log` existen; se implementaron checks reales y seguros de licencia para configuración, almacenamiento, objetos, FRA, UNDO, TEMP y cierre funcional preventivo de alert log por familias de errores. | Persisten gaps de detalle en configuración, storage y schema objects fuera del alcance de la fase 2O. | Completar tablespaces/usuarios, fragmentación, objetos sin PK/FK, redundancia de índices y errores específicos no cubiertos por grupos posteriores. | Se adelantaron `io_redo_archive` y parte de recoverability como apoyo conceptual de storage/redo/DRP. |
| Fase 3 | Security and Operational Readiness | INICIADA | `security` existe con checks de cuentas, perfiles, privilegios y parámetros; `operational_readiness` queda iniciado con checks conservadores de parámetros operativos. | `security` no cubre todo el checklist original; `operational_readiness` aún no incluye readiness avanzado de jobs, backups, patching ni operación extendida. | Ampliar seguridad y completar readiness operativo en fases futuras sin mover checks existentes. | Seguridad se adelantó antes del cierre formal de Fase 3 y se conserva; Fase 3A crea el grupo formal de preparación operativa sin duplicar cobertura existente. |
| Fase 4 | Performance and Capacity | INICIADA 4A | Existen checks adelantados en `oracle_resources`, `io_redo_archive`, `configuration_general` y `operational_readiness`; Fase 4A crea los grupos formales `performance` y `capacity` sin checks propios. | La cobertura propia de rendimiento y capacidad queda pendiente para 4B/4C. | Implementar checks nuevos solo para gaps reales, sin AWR/ASH/`DBA_HIST%` por defecto y sin histórico interno. | No se movieron ni duplicaron checks; no se introdujo SQLite. |
| Fase 5 | RAC, ASM, Data Guard | INICIADA | `rac` básico existe con checks de instancias, servicios, threads, undo, interconnect y parámetro cluster_database. | `asm` y `dataguard` reales no existen como grupos; `recoverability_drp` cubre preparación de recuperación, no Data Guard real. | ASM básico feature-aware, Data Guard real feature-aware, DRP profile behavior y RAC avanzado. | El uso de “Data Guard” queda reservado para primary/standby real. |
| Fase 6 | Patching and Readiness | PENDIENTE | Sin grupo `patching` implementado. | No aplica. | Inventario OPatch/DBA_REGISTRY, PSU/RU y readiness de patching. | Debe implementarse en fase futura sin romper perfiles existentes. |
| Fase 7 | Report Refinement and User Experience | ADELANTADA | Reportes HTML, evidencia JSON, inventario JSON, corrective actions, visualización de features y reporte dedicado de evidencias ya existen. | Falta refinamiento visual/profesional final y UX avanzada. | Mejoras visuales, navegación, filtros y sample reports. | Lo adelantado se acepta y se conserva. |
| Fase 8 | Hardening, Testing, and Packaging | PARCIAL | Suite de pruebas automatizadas existente y validaciones CLI operativas. | Falta hardening final, packaging completo, CI/CD, documentación final, sample reports y developer guide. | Cierre de empaquetado, pipeline y documentación de entrega. | La base de pruebas crece por fases y debe mantenerse compatible. |

## 4. Estado por grupo funcional requerido originalmente

| Grupo | Existe | Checks implementados | Estado | Principales checks implementados | Principales checks pendientes |
| --- | --- | ---: | --- | --- | --- |
| `configuration_general` | Sí | 17 | PARCIAL | `database_status`, `database_open_mode`, `archivelog_mode`, `compatible`, `optimizer_features_enable`, `db_block_size`, `open_cursors`, `processes`, `sessions`, `audit_trail`, `remote_login_passwordfile`, `recyclebin`, `filesystemio_options`, `control_files_multiplexed`, `redo_log_group_count`, `redo_log_members_multiplexed`, `force_logging`. | Parámetros deprecated/obsolete/hidden, `optimizer_index_caching`, `optimizer_index_cost_adj`, memoria avanzada, `cursor_sharing`, `session_cached_cursors`, `fast_start_mttr_target`, trazas, DB links, `SYS.AUD$`, AWR interval/retention solo con reglas de licencia. |
| `performance` | Sí | 0 | FORMAL 4A | Grupo formal vacío; la cobertura adelantada vive en `oracle_resources`, `io_redo_archive`, `configuration_general` y `operational_readiness`. | Fase 4B: uptime, sesiones activas, waits básicos actuales, parse ratio, cache/library cache y SQL activo sin AWR por defecto. |
| `alert_log` | Sí | 8 | COMPLETO FUNCIONAL | `alert_log_ora_errors_basic` conservado; nuevos checks por internos, memoria, espacio, undo/snapshot, corrupción/recovery, redo/archive y resumen informativo. | Ventana avanzada por timestamp, ADR/trace avanzado, ASM detallado y salud real de Data Guard quedan fuera del alcance preventivo actual. |
| `storage` | Sí | 15 | PARCIAL | `tablespace_free_pct`, `tablespace_used_pct`, `datafiles_autoextend_disabled`, `datafiles_near_maxsize`, `datafiles_status`, `tempfiles_status`, `temp_usage_pct`, `undo_tablespace_status`, `fra_configured`, `fra_usage`, `users_system_default_tablespace`, `users_system_temp_tablespace`, `users_missing_default_tablespace`, `users_missing_temp_tablespace`, `dictionary_managed_tablespaces`. | Tablespace fragmentation avanzada, objetos sin posibilidad de extender, segmentos con riesgo y filesystems Oracle específicos. |
| `schema_objects` | Sí | 15 | PARCIAL | `invalid_objects`, `invalid_objects_detail`, `invalid_synonyms`, `disabled_constraints`, `disabled_triggers`, `missing_table_statistics`, `stale_table_statistics`, `locked_table_statistics`, `unusable_indexes`, `unusable_index_partitions`, `recyclebin_objects`, `tables_without_primary_key`, `foreign_keys_without_index`, `tables_with_long_columns`, `indexes_too_many_columns`. | Tablas sin unique key o índice, índices redundantes, particionamiento, row chaining avanzado, jobs avanzados y privilegios/sinónimos adicionales. |
| `operational_readiness` | Sí | 12 | INICIADA | `plsql_optimize_level`, `plsql_code_type`, `plsql_debug`, `sql_trace`, `timed_statistics`, `timed_os_statistics`, `result_cache_mode`, `result_cache_max_result`, `result_cache_remote_expiration`, `db_ultra_safe`, `optimizer_capture_sql_plan_baselines`, `optimizer_use_invisible_indexes`. | Readiness avanzado de jobs, backups, patching, operación extendida, servicios y criterios adicionales por ambiente. |
| `security` | Sí | 24 | AMPLIADA 3B | `audit_trail_security`, `remote_login_passwordfile_security`, `sec_case_sensitive_logon`, cuentas default/open/expired/locked, perfiles permisivos, roles DBA, privilegios críticos, cuentas Oracle-maintained abiertas, privilegios administrativos, autenticación externa, proxy users, privilegios ANY adicionales, ADMIN/GRANT OPTION, roles CONNECT/RESOURCE, acceso a diccionario, inactividad por último login y password versions antiguas. | Auditoría avanzada, fallos históricos de login, Database Vault, redacción, TDE avanzado, OLS, SQL Firewall, paquetes SYS a PUBLIC, roles anidados/no asignados y default passwords detallados. |
| `rac` | Sí | 7 | INICIADA | `rac_cluster_database_parameter`, `rac_instance_count`, `rac_instances_status`, `rac_interconnect_info`, `rac_services_basic`, `rac_threads_status`, `rac_undo_configuration_basic`. | Consistencia avanzada entre instancias, servicios/policies, interconnect detallado, parámetros inconsistentes, OCR/voting/clusterware cuando se agregue soporte OS/Grid. |
| `dataguard` | No | 0 | PENDIENTE | No existe grupo real. | Primary/standby real, transport/apply lag, MRP/RFS/FAL, gaps, protección, broker y estado standby. |
| `asm` | No | 0 | PENDIENTE | No existe grupo formal. | Diskgroups, espacio libre, redundancia, discos offline, rebalance, ASM instance y errores de storage. |
| `os` | Sí | 3 | PARCIAL | `os_cpu`, `os_memory`, `os_filesystem_usage`. | Ulimits, swap, procesos Oracle, time sync, Oracle Base/Home/diag/audit/archive filesystems y cobertura AIX/Linux más completa. |
| `capacity` | Sí | 0 | FORMAL 4A | Grupo formal vacío; la cobertura adelantada vive en `storage`, `oracle_resources`, `io_redo_archive`, `configuration_general` y `operational_readiness`. | Fase 4C: fotografía actual de tamaño, datafiles/tablespaces, segmentos grandes, TEMP/UNDO, límites de sesiones/procesos/transacciones, PGA/SGA y FRA/archive sin SQLite. |
| `patching` | No | 0 | PENDIENTE | No existe grupo formal. | OPatch, DBA_REGISTRY, componentes inválidos, RU/PSU, datapatch y readiness. |

## 5. Grupos adicionales aceptados

| Grupo adicional | Motivo de existencia | Relación con roadmap original | Decisión de conservación | Posible mapeo conceptual futuro |
| --- | --- | --- | --- | --- |
| `oracle_resources` | Agrupa checks operativos de sesiones, procesos, transacciones, memoria SGA/PGA y jobs. | Se relaciona con performance, capacity y production readiness. | Se conserva; no debe revertirse ni renombrarse sin fase específica. | Reconciliar con `performance` y `capacity` en Fase 4A. |
| `io_redo_archive` | Agrupa checks de I/O básico, redo, archive, flashback y objetos nologging/unrecoverable. | Se relaciona con storage, performance, recoverability y DRP. | Se conserva como evolución controlada. | Mapear parcialmente a storage/performance/recoverability durante reconciliación futura. |
| `recoverability_drp` | Agrupa evidencias de backups, recoverability, restore points, controlfile record keep time y archivos que requieren recovery. | Se relaciona con production readiness, DRP y Fase 5. | Se conserva; no representa Data Guard real. | Integrar con `drp_precheck_compare` y readiness de recuperación en fases 5C/3A. |
| `multitenant` | Agrega soporte básico CDB/PDB feature-aware. | `CHECK_GROUPS.md` no lo listaba como grupo requerido independiente, pero `ARCHITECTURE.md` exige soporte para CDB/PDB. | Se acepta como grupo adicional válido y se conserva. | Mantener como grupo propio o mapear a configuración/capacidad multitenant según evolucione el roadmap. |

## 6. Desviaciones aceptadas frente al roadmap inicial

- Seguridad se implementó antes de la Fase 3 formal mediante el grupo `security` y checks asociados.
- Recursos Oracle e I/O/redo/archive se implementaron antes de cerrar formalmente performance/capacity mediante `oracle_resources` e `io_redo_archive`.
- RAC básico se implementó antes de completar ASM y Data Guard.
- Multitenant se agregó como grupo adicional porque la arquitectura exige soporte CDB/PDB.
- Reportes de evidencias y visualización de features se adelantaron respecto a la fase de refinamiento de reportes.

Estas desviaciones son aceptadas formalmente y no deben revertirse. La ruta correcta es documentarlas, conservarlas, reconciliarlas con el roadmap y completar los pendientes sin romper compatibilidad.

## 7. Gaps principales detectados

### Fase 1 / Foundation

- `list-targets`, `list-profiles`, `list-groups` y `list-checks` existen en CLI, pero los comandos avanzados definidos por arquitectura todavía pueden requerir ampliación futura.
- `LocalConnector` existe.
- `AIXAdapter` existe, pero la cobertura real debe ampliarse con pruebas y métodos completos por plataforma.
- Evaluadores base presentes: `threshold`, `expected_value`, `empty_result_pass`, `not_empty_fail`, `row_count_threshold`, `regex` y evaluadores especializados. Permanecen pendientes `comparison`, `contains` y `custom` como evaluadores genéricos si se requiere paridad estricta con arquitectura.
- Algunos collectors descritos en arquitectura, como `plugin_collector`, `manual_info_collector`, `local_command_collector` y `os_adapter_collector`, no aparecen todavía como módulos separados.

### Fase 2

- `configuration_general`: faltan parámetros de memoria, optimizer, trace, DB links, parámetros deprecated/obsolete/hidden, `SYS.AUD$` y políticas avanzadas.
- `storage`: Fase 2P cubre usuarios con `SYSTEM` como default/temp, default/temp inexistentes y tablespaces dictionary-managed. Permanecen pendientes fragmentación avanzada, objetos sin posibilidad de extender, segmentos con riesgo y filesystems Oracle.
- `schema_objects`: Fase 2P cubre tablas sin primary key, foreign keys sin índice compatible, columnas LONG/LONG RAW e índices con demasiadas columnas. Permanecen pendientes tablas sin unique key o índice, índices redundantes, row chaining avanzado, particionamiento y jobs avanzados.
- `alert_log`: cerrado funcionalmente en fase 2O para health check preventivo mediante familias de errores internos, memoria, espacio, undo/snapshot, corrupción/recovery, redo/archive y resumen informativo. No realiza RCA avanzado, ADR/trace avanzado ni evaluación real de Data Guard.

### Fase 3

- El grupo formal `operational_readiness` existe con 12 checks conservadores; no es un perfil.
- Falta ampliar `security` con grants, roles, usuarios administrativos, paquetes SYS a PUBLIC, roles heredados y políticas de contraseña completas.

### Fase 4

- Falta el grupo formal `performance`.
- Falta el grupo formal `capacity`.
- Falta reconciliar `oracle_resources` e `io_redo_archive` con performance/capacity sin eliminar lo existente.

### Fase 5

- Falta `asm`.
- Falta `dataguard` real para ambientes primary/standby.
- Falta `drp_precheck_compare` formal.
- Falta RAC avanzado.

### Fase 6

- Falta `patching`.

### Fase 7

- Falta refinamiento visual/profesional de reportes.

### Fase 8

- Falta hardening.
- Falta packaging.
- Falta CI/CD.
- Falta documentación final.
- Faltan sample reports.
- Falta developer guide.

## 8. Ruta recomendada corregida

```text
2N - Auditoría de alineación roadmap/grupos/estado real
2O - Alert log intermedio
2P - Cierre de gaps storage/schema_objects de Fase 2
3A - Production readiness básico
3B - Security ampliado
4A - Reconciliación performance/capacity con grupos actuales
4B - Performance básico sin AWR
4C - Capacity snapshot sin histórico interno
5A - ASM básico feature-aware
5B - Data Guard real feature-aware
5C - DRP profile behavior
6A - Patching básico
7A - Report UX final
8A - Hardening/packaging/CI
```

Esta ruta no reemplaza el roadmap original. Lo realinea con el estado actual ya implementado, conserva las funcionalidades adelantadas y ordena los pendientes para completar el alcance original sin romper perfiles, reportes, checks ni pruebas existentes.

## 9. Reglas de continuidad

- No eliminar grupos existentes.
- No eliminar checks existentes.
- No mover o renombrar grupos sin fase específica y justificación.
- No romper compatibilidad con perfiles existentes.
- No modificar `config/targets.yaml` salvo fase específica aprobada.
- No introducir SQLite ni histórico interno.
- No usar AWR/ASH/DBA_HIST por defecto.
- Cualquier check que use AWR/ASH/DBA_HIST en el futuro debe declarar explícitamente requisitos de licenciamiento y quedar `SKIPPED` si no está habilitado.
- Checks no aplicables deben quedar `SKIPPED`, no `FAIL`.
- Errores técnicos deben ser `ERROR`, no findings de salud.
- Todo texto visible debe estar en español.
- “Data Guard” solo debe usarse para temas reales de standby/primary-standby.

## 10. Actualización Fase 3A.1 - Operational Readiness básico

La Fase 3A.1 renombra el grupo `production_readiness` a `operational_readiness` para evitar confusión entre grupos técnicos y perfiles de ejecución. `operational_readiness` es un grupo de checks, no un perfil, y mantiene la misma tanda conservadora de checks basados en `V$PARAMETER` sin cambiar su lógica funcional.

Checks relacionados con preparación operativa que ya existían en otros grupos, como `archivelog_mode`, `force_logging`, `audit_trail`, `audit_trail_security`, `recyclebin`, `flashback_status`, `remote_login_passwordfile` y `sec_case_sensitive_logon`, se conservan en sus grupos originales. La cobertura relacionada se documenta como existente, pero no se recrea bajo `operational_readiness`.

El alcance de esta fase no introduce AWR, ASH, `DBA_HIST%`, Diagnostic Pack, Tuning Pack, repositorio histórico interno ni SQLite. Tampoco crea grupos ajenos al alcance ni modifica `config/targets.yaml`.

## 11. Actualización Fase 3A - Perfil standalone_all y matriz conceptual ASM/RAC

Se agrega el perfil `standalone_all` como perfil amplio para bases standalone. A diferencia de `standalone_basic`, que sigue siendo un perfil básico y liviano, `standalone_all` incluye todos los grupos ya implementados y razonablemente aplicables a una base standalone, incluyendo `operational_readiness`. No existe perfil `operational_readiness`; los perfiles representan intención, topología o alcance.

`standalone_basic` no se modifica y no se agrega `operational_readiness` a ese perfil. `config/targets.yaml` tampoco se modifica, por lo que ningún target existente cambia su perfil por defecto.

Los perfiles representan intención, topología o alcance, por ejemplo `standalone_basic`, `standalone_all`, `rac_full`, `drp_precheck_compare` o `security_audit`. Los grupos representan dominios técnicos de validación, por ejemplo `configuration_general`, `storage`, `security`, `schema_objects`, `alert_log` u `operational_readiness`.


La documentación conceptual queda alineada con Oracle moderno: OraHealthCheck separa topología de base de datos (`standalone` o `rac`) y tipo de almacenamiento (ASM o filesystem). Una base standalone puede usar filesystem o ASM; ASM no implica RAC; RAC moderno debe asumirse como ASM. Cuando exista el grupo ASM, sus checks deberán poder aplicar tanto a standalone con ASM como a RAC con ASM, sin depender de que la base sea RAC.

Esta fase no implementa checks ASM nuevos, no implementa checks RAC nuevos, no crea grupos futuros como `asm`, `performance`, `capacity` o `patching`, y no mueve ni duplica checks existentes.

## Nota Fase 3B - Security ampliado

Fase 3B agrega once checks al grupo `security` y mantiene los checks existentes en su ubicación original, sin duplicar `dba_role_users` ni `critical_privilege_users`. Los checks de privilegios elevados excluyen `SYS`, `SYSTEM` y usuarios/roles Oracle-maintained cuando corresponde, mientras que `oracle_maintained_open_users` revisa específicamente cuentas internas Oracle distintas de `SYS` y `SYSTEM` que estén `OPEN`.

La fase no modifica `config/targets.yaml`, no modifica el perfil `standalone_basic`, no usa AWR/ASH/`DBA_HIST%`, Diagnostic Pack, Tuning Pack, SQLite ni vistas internas `X$`, y no abre alcance de performance, capacity, ASM, RAC avanzado, Data Guard, patching ni report UX avanzado.

## 12. Actualización Fase 4A - Reconciliación performance/capacity

La Fase 4A formaliza la reconciliación entre el roadmap original de `performance`/`capacity` y la cobertura que ya fue adelantada en grupos existentes. Se crean los grupos formales `performance` y `capacity` con lista de checks vacía porque el framework soporta grupos sin checks: `CheckGroup` define `checks` con lista por defecto, el validador solo verifica referencias presentes y los perfiles activos no fueron modificados para incluir estos grupos.

La cobertura adelantada se conserva en sus grupos originales y no se mueve ni se duplica:

- `oracle_resources`: `blocked_sessions_basic`, `blocking_sessions_basic`, `inactive_sessions_high`, `legacy_dba_jobs_broken`, `pga_aggregate_limit_configured`, `pga_aggregate_target_configured`, `pga_memory_usage_info`, `processes_usage_pct`, `scheduler_broken_jobs`, `scheduler_disabled_jobs`, `scheduler_failed_jobs_recent`, `sessions_usage_pct`, `sga_memory_info`, `sga_target_configured` y `transactions_usage_pct`. Esta cobertura apoya rendimiento, capacidad y operación básica de recursos.
- `io_redo_archive`: `archive_dest_errors`, `archive_dest_status`, `archivelog_generation_recent`, `filestat_io_basic`, `flashback_log_usage`, `flashback_status`, `fra_reclaimable_space`, `fra_usage_advanced`, `nologging_objects_basic`, `redo_log_size_assessment`, `redo_log_status`, `redo_log_switch_frequency`, `redo_logfile_status`, `sysstat_io_basic` y `unrecoverable_datafiles`. Esta cobertura apoya rendimiento, capacidad, recuperabilidad, almacenamiento operativo y redo/archive/FRA.
- `configuration_general`: `open_cursors`, `processes`, `sessions`, `optimizer_features_enable`, `filesystemio_options` y `db_block_size` apoyan indirectamente rendimiento y capacidad, pero permanecen en configuración general.
- `operational_readiness`: `plsql_optimize_level`, `plsql_code_type`, `sql_trace`, `timed_statistics`, `timed_os_statistics`, `result_cache_mode`, `result_cache_max_result`, `optimizer_capture_sql_plan_baselines` y `optimizer_use_invisible_indexes` apoyan parámetros operativos relacionados, pero permanecen en preparación operativa.

Queda pendiente para Fase 4B implementar rendimiento básico sin AWR por defecto: uptime de instancia, sesiones activas actuales, esperas actuales desde `V$SESSION`/`V$SYSTEM_EVENT`, wait classes actuales, parse ratio con `V$SYSSTAT`, lecturas lógicas/buffer cache básicas, library cache, latches/mutex solo si son de bajo ruido, SQL actualmente activo, long operations y eventos de espera actuales por sesión.

Queda pendiente para Fase 4C implementar capacidad como fotografía actual sin histórico interno: tamaño actual de BD, crecimiento actual por datafiles/tablespaces cuando derive de datos actuales, segmentos grandes, TEMP/UNDO, sesiones/procesos/transacciones contra límites, PGA/SGA y FRA/archivelog. Si en el futuro se requiere tendencia, debe venir de datos Oracle existentes y solo con autorización y licenciamiento explícitos; por defecto no se usa histórico licenciado.

Esta fase no modifica `config/targets.yaml`, no modifica `standalone_basic`, no mueve checks existentes, no duplica checks, no crea checks dummy, no usa AWR/ASH/`DBA_HIST%`, no usa vistas internas `X$`, no implementa SQLite y no crea repositorio histórico interno.

## 13. Actualización Fase 4A.1 - Visibilidad de features no aplicables en perfiles amplios

La Fase 4A.1 formaliza la política de visibilidad para features no aplicables. Una feature no detectada no genera hallazgos, no penaliza el score y debe seguir apareciendo en el inventario de features como no detectada. En perfiles amplios, los checks feature-aware pueden incluirse para conservar trazabilidad técnica y quedar `SKIPPED` con una razón clara cuando la feature requerida no está detectada.

Para aplicar esta política, `standalone_all` incluye los grupos feature-aware ya implementados `rac` y `multitenant`, además de los grupos amplios ya aplicables. En bases standalone no RAC/CDB, esos checks quedan omitidos por `requires_feature`, con evidencia y razón de omisión. Como ajuste menor del PR #29, `standalone_basic` queda limpio como perfil básico standalone y no incluye grupos feature-aware no esenciales como `rac`, `multitenant` ni `operational_readiness`; `config/targets.yaml` permanece sin cambios.

La política de UX por reporte queda definida así:

- El reporte ejecutivo mantiene el inventario de features detectadas/no detectadas, pero no debe listar checks `SKIPPED` masivos como hallazgos ni acciones.
- El reporte técnico conserva trazabilidad sin ruido visual: cuando un grupo completo queda `SKIPPED` por la misma feature requerida no detectada, muestra un bloque compacto de grupo no aplicable con feature, razón y cantidad de validaciones omitidas, y no lista cada check individualmente.
- El reporte de evidencias conserva el detalle completo de checks omitidos y su `skipped_reason`, incluyendo `check_id`, `group_id`, `required_feature`, metadata y evidencia.
- El reporte de acciones correctivas muestra solo elementos corregibles y no debe generar acciones para checks `SKIPPED` por features no detectadas.

La Fase 4A.2 ajusta únicamente la visualización del reporte técnico para resumir grupos no aplicables por feature. Las features no detectadas no son hallazgos ni riesgos, no generan penalización y pueden aparecer como `SKIPPED` en perfiles amplios; el detalle completo permanece en evidencias para auditoría.

Quedan pendientes para fases posteriores la definición, creación y prueba de perfiles amplios específicos para topologías/features, únicamente cuando los grupos correspondientes existan y tengan checks reales con aplicabilidad clara:

- Crear y probar un perfil amplio para RAC, por ejemplo `rac_all` o `rac_full`, cuando RAC avanzado esté implementado.
- Crear y probar un perfil amplio para ASM, por ejemplo `asm_all` o `asm_full`, cuando el grupo `asm` exista con checks reales.
- Crear y probar un perfil amplio para configuraciones con bases standby, por ejemplo `dataguard_all` o `dataguard_full`, cuando el grupo `dataguard` exista y esté estrictamente limitado a bases standby/Data Guard real.
- Evaluar más adelante si se necesita un perfil de auditoría completa, por ejemplo `oracle_full` o `audit_all`, que incluya todos los grupos feature-aware y deje que la aplicabilidad marque `SKIPPED` cuando no corresponda.

Estos perfiles futuros no deben crearse antes de que sus grupos/checks existan, no deben contener checks dummy, no deben duplicar ni mover checks existentes, deben probarse contra ambientes reales o simulados representativos, deben mantener la regla de no penalizar features no detectadas, deben conservar trazabilidad técnica mediante `SKIPPED` en reportes técnicos/evidencias y deben evitar ruido en reportes ejecutivos/correctivos.

## 13. Actualización Fase 4B - Performance básico actual sin AWR/ASH

La Fase 4B implementa los primeros 9 checks reales del grupo `performance`, enfocados en una fotografía actual de rendimiento sin AWR, sin ASH, sin `DBA_HIST%`, sin vistas internas `X$`, sin SQLite y sin repositorio histórico interno. La cobertura prioriza sesiones activas de usuario, esperas actuales por `WAIT_CLASS` y `EVENT`, operaciones largas activas, parse ratio básico acumulado desde startup, library cache básico y SQL actualmente activo.

El análisis por `WAIT_CLASS`/`EVENT` se basa en `V$SESSION`; los segundos reportados son `total_observed_wait_seconds` observados en la fotografía actual entre sesiones, no DB Time histórico. Los thresholds de `performance_wait_class_snapshot` son configurables por `WAIT_CLASS`, con exclusión de `Idle` por defecto y fallback `default` para clases no configuradas. `performance_sql_current_activity` muestra SQL activo actual y no equivale a top SQL histórico.

`standalone_all` incorpora `performance` porque el grupo deja de estar vacío. `standalone_basic` permanece sin `performance`. `capacity` sigue pendiente para una fase posterior y no se implementan checks de capacidad en esta fase.

## 15. Actualización Fase 4C - Capacity fotografía actual sin histórico interno

La Fase 4C inicia la cobertura propia del grupo formal `capacity` con 8 checks reales: tamaño actual de base de datos, margen de tablespaces, margen de datafiles, segmentos principales de aplicación, fotografía de TEMP, fotografía de UNDO, margen consolidado de `V$RESOURCE_LIMIT` y margen de FRA/archive. El grupo deja de estar vacío y pasa de estado formal reservado a cobertura iniciada.

`capacity` se define como una fotografía actual de tamaño, uso, margen disponible, límite efectivo y riesgo de saturación actual. No reemplaza a `storage`, `oracle_resources` ni `io_redo_archive`: esos grupos mantienen validaciones puntuales, mientras `capacity` consolida margen y contexto de capacidad.

La fase no introduce SQLite, no crea repositorio histórico interno, no usa AWR, no usa ASH, no usa `DBA_HIST%`, no usa `DBMS_WORKLOAD_REPOSITORY` y no usa vistas internas `X$`. TEMP y UNDO forman parte explícita del fotografía actual. Cualquier tendencia futura basada en AWR deberá ser opcional, declarada y condicionada a licenciamiento explícito.
