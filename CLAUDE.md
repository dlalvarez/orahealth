# CLAUDE.md — OraHealthCheck

Guía para Claude Code en este repositorio. Léela completa antes de cambiar código.

## Qué es

OraHealthCheck (paquete `orahealthcheck`) es un framework Python para evaluar la salud de
bases de datos Oracle y de su sistema operativo (Linux/AIX). Lo usa un DBA en un entorno
bancario: **la confiabilidad del resultado importa más que la cantidad de checks**.

Jerarquía: `Target -> Profile -> Check Groups -> Checks` + `Standards` (umbrales/políticas).
Cada ejecución genera en `output/<target_id>_<timestamp>/`: `executive_report.html`,
`technical_report.html`, `corrective_actions.html`, `evidence_report.html`,
`evidence.json`, `inventory.json` y `execution.log`.

Documentos rectores (léelos según la tarea):
- `docs/ARCHITECTURE.md` — diseño objetivo.
- `docs/ROADMAP.md` y `docs/CHECK_GROUPS.md` — alcance por fase y por grupo.
- `docs/IMPLEMENTATION_STATUS.md` — estado real, desviaciones aceptadas y notas por fase.

## Comandos

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"            # agregar ,oracle,ssh para conexiones reales
python -m pytest -q                 # toda la suite debe pasar antes de cualquier commit
orahealthcheck validate-config
orahealthcheck list-profiles
orahealthcheck run --target example_standalone [--profile standalone_all]
```

`example_standalone` usa `mock_inventory` (datos simulados): los reportes lo indican.
Configuración local con credenciales reales va en `config/*.local.yaml` (ignorados por git);
ver los `.example`. **Nunca** commitear credenciales.

## Estructura del código

```
src/orahealthcheck/
  cli.py                     CLI
  config_loader/             carga y validación de YAML (con capas *.local.yaml)
  models/                    Check, CheckGroup, Profile, Target, Result, Inventory...
  connectors/                OracleConnector, SSHConnector, LocalConnector, build_os_connector
  os_adapters/               LinuxAdapter, AIXAdapter (comandos OS; nunca hardcodear en checks)
  engine/
    runner.py                orquestación: conexiones, compuertas de evidencia, ejecución
    requirements.py          CORE_VIEWS, required_views(), requires_database()
    applicability.py         SKIPPED por arquitectura/rol/open mode/versión/feature
    scoring.py               puntaje de salud + cobertura de evidencia
    discovery/<grupo>.py     descubrimiento (SQL) y construcción de evidencia por grupo
  evaluators/                lógica PASS/WARNING/FAIL/CRITICAL por tipo de evaluador
  reports/html_reporter.py   reportes (plantillas en templates/html/*.j2)
config/
  app_settings.yaml  connection_profiles.yaml  targets.yaml
  profiles/  standards/  check_groups/  checks/<grupo>/<check_id>.yaml
```

Flujo de un check: el `collector.type` del YAML selecciona la sección de descubrimiento
(`COLLECTOR_SECTIONS` en `runner.py`) y el constructor de evidencia del mixin del grupo;
`evaluator.type` selecciona el evaluador. Solo se descubren las secciones que necesitan los
checks del perfil (descubrimiento perezoso; dependencias en `SECTION_DEPENDENCIES`).

## Reglas no negociables

1. **Sin dato confiable no hay PASS.** Si una consulta falla o una vista no es accesible, el
   check debe terminar en `ERROR` con el motivo exacto (vista + ORA-), nunca en PASS por
   "lista vacía". No inventar valores (`OPEN`, `READ WRITE`, `PRIMARY`...) para bases reales;
   los valores por defecto solo existen para `mock_inventory`.
2. **Todo check de base declara sus vistas** en `applies_to.requires.views`. Una prueba lo
   exige. Las vistas se verifican con un preflight (`select 1 from <vista> where 1 = 0`).
   Vistas solo opcionales/con fallback no se declaran (ver `test_evidence_integrity.py`).
3. **Estados:** `PASS`, `INFO`, `WARNING`, `FAIL`, `CRITICAL` son hallazgos de salud;
   `SKIPPED` = no aplica (no penaliza); `ERROR` = fallo técnico (no penaliza salud, reduce la
   cobertura de evidencia; con cobertura < `min_evidence_coverage_pct` el estado global es
   `ERROR`, evaluación no concluyente).
4. **Licenciamiento:** no usar AWR, ASH, `DBA_HIST%`, `DBMS_WORKLOAD_REPOSITORY`, advisors,
   Diagnostic/Tuning Pack ni vistas `X$` por defecto. Cualquier uso futuro debe ser opcional,
   declarar `requires: {diagnostic_pack: true}` y quedar `SKIPPED` si no está habilitado.
5. **Sin histórico interno:** no SQLite ni repositorio propio; todo sale como archivos.
6. **Compatibilidad:** no eliminar, renombrar ni mover grupos, checks, `check_id` ni perfiles
   existentes sin una fase aprobada. No modificar `config/targets.yaml` salvo fase aprobada.
   `standalone_basic` es un perfil liviano: no agregarle grupos feature-aware.
7. **Feature-aware:** checks de RAC, ASM, Data Guard, multitenant quedan `SKIPPED` cuando la
   característica no está detectada; no son hallazgos ni generan acciones correctivas.
   "Data Guard" se usa solo para configuraciones primary/standby reales.
8. **Idioma:** todo texto visible (títulos, mensajes, remediación, reportes) en español.
   Identificadores, código y commits técnicos pueden ir en español o inglés; preferir español.
9. **OS:** los checks OS usan la conexión del target (`operating_system.connections` u
   `hosts[].connection_profile`) vía `build_os_connector`; nunca `LocalConnector()` directo.
10. **Seguridad operativa:** las consultas son solo lectura. No ejecutar DML/DDL ni comandos
    que modifiquen el servidor. Evitar consultas costosas sin filtros en producción.

## Cómo agregar un check

1. Crear `config/checks/<grupo>/<check_id>.yaml` con `check_id`, `group_id`, `title`,
   `severity`, `collector`, `evaluator`, `applies_to` (incluye `requires.views`),
   `remediation` (summary, actions, owner, requires_window, outage_risk) y `tags`.
2. Agregar el `check_id` a `config/check_groups/<grupo>.yaml`.
3. Si requiere datos nuevos: consulta en `engine/discovery/<grupo>.py` (usar
   `_query_rows`/`_query_rows_with_error`, que registran fallos) y evidencia en el
   `_build_<grupo>_evidence` del mismo módulo; lógica en `evaluators/<grupo>.py`.
4. Pruebas en `tests/test_<grupo>.py`: caso sano, caso con hallazgo, caso sin privilegios
   (debe dar ERROR) y caso no aplicable (SKIPPED).
5. Documentar la fase en `docs/IMPLEMENTATION_STATUS.md`.

## Pruebas

- `tests/fakes.py`: `FakeOSConnector` (salidas OS fijas; se inyecta por defecto en
  `conftest.py`, ninguna prueba ejecuta comandos reales) y `NoPrivilegeOracleConnector`.
- `tests/test_evidence_integrity.py`: sin privilegios => cero resultados de salud.
- `tests/test_lazy_discovery.py`: equivalencia entre descubrimiento perezoso y completo.

## Flujo de trabajo

- Rama por fase desde `develop` (`claude/<fase>-<descripcion>`), PR hacia `develop`.
  `main` solo recibe versiones estables desde `develop`.
- Cambios pequeños y revisables; un PR por fase. Toda la suite en verde antes de abrir PR.
- La descripción del PR explica el problema, el cambio, el impacto en compatibilidad y las
  pruebas.

## Estado y próximos pasos

Completado recientemente (ver `docs/IMPLEMENTATION_STATUS.md`):
- **C1** (PR #37): integridad de evidencia, preflight de vistas, cobertura de evidencia,
  checks OS sobre la conexión del target.
- **C2** (PR #38): `runner.py` dividido en `engine/discovery/`, descubrimiento perezoso.

Pendiente, en orden sugerido:
- **C2b:** collector `oracle_sql` genérico para checks simples definidos solo en YAML.
- **C3:** OS remoto completo (SSH con verificación de host key, métodos de adaptador
  faltantes: swap, ulimits, time sync, procesos Oracle, kernel; cobertura AIX).
- Gaps de grupos según `IMPLEMENTATION_STATUS.md` sección 7.
- **7A:** UX final de reportes. **8A:** hardening, packaging, CI (GitHub Actions con pytest).
- Validación contra una base Oracle 19c real de desarrollo con un usuario de solo lectura
  y documentación del grant mínimo (derivable de `requires.views`).
