# OraHealthCheck - Architecture

## 1. Purpose

OraHealthCheck is a modular Python framework for performing Oracle database health, capacity, performance, configuration, security, storage, object, RAC, ASM, operating system, patching, and Data Guard assessments.

The framework must be able to connect to previously configured Oracle databases and to the operating system hosts where they run. It must generate professional HTML reports with an executive summary, a technical report, and a corrective action plan.

The architecture must support:

- Oracle standalone databases.
- Oracle RAC databases.
- Oracle Data Guard environments.
- Oracle RAC with Data Guard.
- ASM.
- CDB and PDB architectures.
- Oracle Linux.
- Red Hat Enterprise Linux.
- Compatible Linux distributions such as Rocky Linux, AlmaLinux, CentOS, and SUSE where applicable.
- IBM AIX.
- DRP environments where ASM may be available but the database may be mounted, closed, inaccessible, or located on read-only disks.

OraHealthCheck must not be implemented as a monolithic script. It must be a stable, extensible, configuration-driven framework.

---

## 2. Core Design Principles

1. Keep the engine generic and reusable.
2. Keep checks configurable and extensible.
3. Organize checks by functional groups.
4. Let profiles activate groups instead of forcing targets to list hundreds of checks.
5. Let targets select a profile and define only environment-specific exceptions.
6. Do not store execution history in SQLite or any internal database.
7. Generate all deliverables as files under an output directory.
8. Support multiple database and operating system authentication methods.
9. Distinguish between a health finding and a technical execution error.
10. Mark non-applicable checks as `SKIPPED`, not as failures.
11. Support Linux and AIX through operating system adapters.
12. Do not hardcode Linux commands into generic OS checks.
13. Support declarative YAML checks and Python plugin checks.
14. Keep reporting separate from collection and evaluation.
15. Make the first implementation stable and minimal; add check coverage progressively.

---

## 3. High-Level Architecture

The main conceptual hierarchy is:

```text
Target
  -> Profile
      -> Check Groups
          -> Checks
```

A second concept, `Standard`, provides expected values and thresholds:

```text
Standard
  -> version policies
  -> environment policies
  -> architecture policies
  -> security policies
  -> threshold policies
```

The full relationship is:

```text
Target
  uses a Profile

Profile
  enables Check Groups
  applies Standards
  applies check overrides
  disables groups or checks when required

Check Group
  organizes Checks by purpose

Check
  defines what to collect, how to evaluate it, and how to remediate failures

Standard
  defines expected values and thresholds by Oracle version, environment, architecture, or corporate policy
```

This prevents unmanageable target configurations. A target should usually select a profile and only override exceptional items.

---

## 4. Main Runtime Flow

A normal run must follow this sequence:

```text
1. Load global settings.
2. Load connection profiles.
3. Load targets.
4. Load profiles.
5. Load standards.
6. Load check groups.
7. Load checks.
8. Validate configuration consistency.
9. Resolve the requested target.
10. Resolve the effective profile.
11. Merge standards, profile overrides, group definitions, and target overrides.
12. Connect to Oracle and/or OS endpoints as required.
13. Discover database, RAC, Data Guard, ASM, and OS inventory.
14. Evaluate check applicability.
15. Execute applicable checks.
16. Mark non-applicable checks as SKIPPED with a clear reason.
17. Evaluate results.
18. Calculate score and global status.
19. Generate evidence.json.
20. Generate inventory.json.
21. Generate execution.log.
22. Generate executive_report.html.
23. Generate technical_report.html.
24. Generate corrective_actions.html.
```

---

## 5. Recommended Project Structure

```text
orahealthcheck/
  README.md
  pyproject.toml
  .gitignore

  docs/
    ARCHITECTURE.md
    ROADMAP.md
    CHECK_GROUPS.md

  config/
    app_settings.yaml
    connection_profiles.yaml
    targets.yaml

    credentials/
      db_credentials.yaml
      os_credentials.yaml

    standards/
      oracle_11g.yaml
      oracle_12c.yaml
      oracle_19c.yaml
      oracle_21c.yaml
      oracle_23ai.yaml
      production.yaml
      development.yaml
      test.yaml
      rac.yaml
      dataguard.yaml
      linux.yaml
      aix.yaml

    profiles/
      standalone_basic.yaml
      standalone_full.yaml
      rac_basic.yaml
      rac_full.yaml
      dataguard_basic.yaml
      dataguard_full.yaml
      rac_dataguard_full.yaml
      security_audit.yaml
      production_readiness.yaml
      capacity_performance.yaml
      patching_readiness.yaml
      drp_precheck_compare.yaml

    check_groups/
      configuration_general.yaml
      performance.yaml
      alert_log.yaml
      storage.yaml
      schema_objects.yaml
      production_readiness.yaml
      security.yaml
      rac.yaml
      dataguard.yaml
      asm.yaml
      os.yaml
      capacity.yaml
      patching.yaml

    checks/
      configuration_general/
      performance/
      alert_log/
      storage/
      schema_objects/
      production_readiness/
      security/
      rac/
      dataguard/
      asm/
      os/
      capacity/
      patching/

  src/
    orahealthcheck/
      __init__.py
      cli.py

      config_loader/
        __init__.py
        loader.py
        validators.py
        mergers.py

      models/
        __init__.py
        target.py
        profile.py
        check.py
        check_group.py
        standard.py
        result.py
        inventory.py
        connection.py
        report.py

      connectors/
        __init__.py
        oracle_connector.py
        ssh_connector.py
        local_connector.py

      discovery/
        __init__.py
        oracle_discovery.py
        rac_discovery.py
        dataguard_discovery.py
        asm_discovery.py
        os_discovery.py

      os_adapters/
        __init__.py
        base.py
        linux.py
        oracle_linux.py
        redhat.py
        aix.py

      collectors/
        __init__.py
        oracle_sql_collector.py
        ssh_command_collector.py
        local_command_collector.py
        os_adapter_collector.py
        plugin_collector.py
        manual_info_collector.py

      evaluators/
        __init__.py
        base.py
        threshold.py
        expected_value.py
        empty_result_pass.py
        not_empty_fail.py
        row_count_threshold.py
        regex.py
        comparison.py
        contains.py
        custom.py

      engine/
        __init__.py
        runner.py
        applicability.py
        scheduler.py
        scoring.py
        result_builder.py

      reports/
        __init__.py
        html_reporter.py
        report_context.py
        executive_summary.py
        corrective_actions.py

      plugins/
        __init__.py
        base.py
        rac/
        dataguard/
        performance/
        capacity/

      utils/
        __init__.py
        logging.py
        masking.py
        time.py
        filesystem.py
        sql.py

  templates/
    html/
      assets/
        style.css
      executive_report.html.j2
      technical_report.html.j2
      corrective_actions.html.j2
      partials/
        header.html.j2
        footer.html.j2
        summary_cards.html.j2
        check_table.html.j2
        evidence_block.html.j2

  output/
  tests/
```

---

## 6. Configuration Files

### 6.1 app_settings.yaml

Global settings should include output path, time zone, logging level, report options, and security behavior.

```yaml
app:
  name: OraHealthCheck
  default_output_dir: output
  timezone: America/Bogota
  log_level: INFO
  mask_secrets_in_logs: true
  max_parallel_checks: 5
  default_command_timeout_seconds: 60
  default_sql_timeout_seconds: 60

reports:
  generate_executive: true
  generate_technical: true
  generate_corrective_actions: true
  include_sql_text: false
  include_command_text: true
  include_raw_evidence: true
  theme: light

security:
  allow_passwords_in_files: true
  mask_passwords_in_output: true
```

### 6.2 connection_profiles.yaml

Must support multiple authentication mechanisms for Oracle and OS.

```yaml
db_connections:
  prod_medaprod:
    type: oracle
    host: srvdb01
    port: 1521
    service_name: MEDAPROD
    username: system
    auth_method: password
    password: "password_en_archivo"
    mode: normal
    connect_timeout: 15

  prod_medaprod_sys:
    type: oracle
    host: srvdb01
    port: 1521
    service_name: MEDAPROD
    username: sys
    auth_method: env
    password_env: PROD_SYS_PASSWORD
    mode: sysdba

  prod_wallet:
    type: oracle
    auth_method: wallet
    wallet_alias: PRODDB

os_connections:
  srvdb01_oracle:
    type: ssh
    host: srvdb01
    port: 22
    username: oracle
    auth_method: password
    password: "password_en_archivo"
    sudo: false

  srvdb01_grid:
    type: ssh
    host: srvdb01
    port: 22
    username: grid
    auth_method: private_key
    private_key_path: ~/.ssh/id_rsa
    private_key_passphrase: null
    sudo: false

  local_oracle:
    type: local
    username: oracle
```

Database authentication methods to support:

```text
password
env
wallet
external
os_auth
```

Operating system authentication methods to support:

```text
password
private_key
private_key_with_passphrase
local
```

### 6.3 targets.yaml

A target represents a database environment to assess.

Standalone example:

```yaml
targets:
  - target_id: medaprod_standalone
    name: MEDAPROD Standalone Produccion
    environment: production
    expected_architecture: standalone
    profile: standalone_full

    database:
      primary_connection: prod_medaprod

    os:
      hosts:
        - name: srvdb01
          connection_profile: srvdb01_oracle
          platform: linux
          distribution: oracle_linux
```

RAC example:

```yaml
targets:
  - target_id: core_rac_prod
    name: CORE RAC Produccion
    environment: production
    expected_architecture: rac
    profile: rac_full

    database:
      primary_connection: core_rac_service

    rac:
      enabled: true
      nodes:
        - name: racnode1
          oracle_connection_profile: racnode1_oracle
          grid_connection_profile: racnode1_grid
          platform: linux
          distribution: redhat
        - name: racnode2
          oracle_connection_profile: racnode2_oracle
          grid_connection_profile: racnode2_grid
          platform: linux
          distribution: redhat
```

AIX example:

```yaml
targets:
  - target_id: fin_aix_prod
    name: FIN Produccion AIX
    environment: production
    expected_architecture: standalone
    profile: standalone_full

    database:
      primary_connection: fin_prod_db

    os:
      hosts:
        - name: aixdb01
          connection_profile: aixdb01_oracle
          platform: aix
```

### 6.4 profiles

Profiles activate groups and apply standards.

```yaml
profile_id: standalone_full
name: Standalone Full Health Check
description: Analisis completo para base Oracle standalone productiva.

standards:
  - oracle_19c
  - production

enabled_groups:
  - configuration_general
  - performance
  - alert_log
  - storage
  - schema_objects
  - production_readiness
  - security
  - os
  - capacity

disabled_groups:
  - rac
  - dataguard
  - asm

disabled_checks:
  - parameter_star_transformation_enabled

check_overrides:
  tablespace_free_pct:
    warning: 15
    critical: 10

  parameter_cursor_sharing:
    expected: EXACT
    severity: info
```

---

## 7. Core Models

### 7.1 Check

A check is a single validation unit.

Required fields:

```yaml
id:
name:
description:
category:
group:
scope:
collector:
severity:
enabled:
applies_to:
evaluation:
remediation:
```

Optional fields:

```yaml
sql:
command:
adapter_method:
plugin:
references:
tags:
```

Example:

```yaml
id: users_system_default_tablespace
name: Usuarios con SYSTEM como tablespace por defecto
description: Identifica usuarios no administrativos que tienen SYSTEM como tablespace por defecto.
category: storage
group: storage
scope: database
collector: oracle_sql
severity: warning
enabled: true

applies_to:
  architectures:
    - standalone
    - rac
    - dataguard
    - rac_dataguard
  database_roles:
    - PRIMARY
  open_modes:
    - READ WRITE
    - READ ONLY
    - READ ONLY WITH APPLY
  requires:
    database_connection: true

sql: |
  select username, default_tablespace
  from dba_users
  where username not in ('SYS','SYSTEM')
    and default_tablespace = 'SYSTEM'
    and account_status not like 'LOCKED%'

evaluation:
  type: empty_result_pass
  fail_status: WARNING

remediation:
  summary: Cambiar el tablespace por defecto de usuarios no administrativos.
  actions:
    - Crear o identificar un tablespace de datos adecuado.
    - Ejecutar ALTER USER usuario DEFAULT TABLESPACE tablespace_correcto.
    - Validar que nuevos objetos no se creen en SYSTEM.
  validation:
    - Reejecutar el check y confirmar que no existan usuarios no administrativos con SYSTEM como default tablespace.
  owner: DBA
  requires_window: false
  outage_risk: low
```

### 7.2 CheckGroup

Groups organize checks by purpose.

```yaml
group_id: storage
name: Almacenamiento
description: Validaciones de tablespaces, datafiles, segmentos, FRA, ASM y filesystem.
enabled: true

checks:
  - users_system_temp_tablespace
  - users_system_default_tablespace
  - users_missing_temp_tablespace
  - tablespace_free_pct
  - objects_unable_to_extend
  - dictionary_managed_tablespaces
  - fra_usage
  - datafiles_autoextend_risk
```

### 7.3 Result

Every check result must contain:

```json
{
  "id": "tablespace_free_pct",
  "name": "Tablespaces con poco espacio",
  "group": "storage",
  "status": "WARNING",
  "severity": "WARNING",
  "finding": "...",
  "expected": "...",
  "actual": "...",
  "evidence": [],
  "remediation": [],
  "elapsed_ms": 120,
  "error": null,
  "skipped_reason": null
}
```

---

## 8. Result Statuses

The framework must support:

```text
PASS
INFO
WARNING
FAIL
CRITICAL
SKIPPED
ERROR
```

Meaning:

- `PASS`: Expected condition is met.
- `INFO`: Informational result; no compliance issue.
- `WARNING`: Preventive or minor issue.
- `FAIL`: Relevant noncompliance or risk.
- `CRITICAL`: High risk for availability, data loss, performance, security, or operability.
- `SKIPPED`: Check does not apply due to platform, version, role, open mode, architecture, license, or missing optional configuration.
- `ERROR`: Check should have run but failed due to a technical problem such as permissions, connection error, timeout, invalid SQL, or command failure.

`SKIPPED` must not reduce health score.

`ERROR` must be reported separately from health findings.

---

## 9. Applicability Engine

Before running a check, the engine must decide whether it applies.

A check may declare applicability based on:

```yaml
applies_to:
  architectures:
    - standalone
    - rac
    - dataguard
    - rac_dataguard
  database_roles:
    - PRIMARY
    - PHYSICAL STANDBY
  open_modes:
    - READ WRITE
    - READ ONLY
    - READ ONLY WITH APPLY
    - MOUNTED
  oracle_versions:
    min: "11.2"
    max: null
  platforms:
    - linux
    - aix
  requires:
    database_connection: true
    os_connection: false
    sysdba: false
    awr: false
    diagnostic_pack: false
```

Examples:

- SCAN checks do not apply to standalone.
- MRP checks do not apply to primary.
- PDB checks do not apply to non-CDB databases.
- Linux HugePages checks do not apply to AIX.
- AIX VMM checks do not apply to Linux.
- Checks requiring an open database must be skipped when the database is mounted.
- Checks requiring Diagnostic Pack must be skipped unless explicitly enabled.

The skipped reason must be clear and included in the technical report.

---

## 10. Connectors

### 10.1 OracleConnector

Use `python-oracledb`.

Must support:

- Thin mode.
- Optional Thick mode.
- Host, port, service name.
- SID.
- TNS alias.
- Wallet.
- Username/password.
- Password from environment variable.
- OS authentication.
- SYSDBA mode.
- CDB root connection.
- PDB connection.
- Timeout.
- Retries.
- Structured error handling.

Successful SQL execution response:

```json
{
  "success": true,
  "rows": [],
  "columns": [],
  "elapsed_ms": 123,
  "error": null
}
```

Error response:

```json
{
  "success": false,
  "rows": [],
  "columns": [],
  "elapsed_ms": 123,
  "error": {
    "type": "DatabaseError",
    "code": "ORA-01031",
    "message": "insufficient privileges"
  }
}
```

### 10.2 SSHConnector

Use `paramiko` or an equivalent library.

Must support:

- Username/password.
- Private key.
- Private key with passphrase.
- Port.
- Timeout.
- Optional sudo.
- Optional environment variables.
- stdout, stderr, exit_code.
- Structured errors.

Command response:

```json
{
  "success": true,
  "stdout": "...",
  "stderr": "",
  "exit_code": 0,
  "elapsed_ms": 456,
  "error": null
}
```

### 10.3 LocalConnector

Executes local commands when the framework runs directly on the Oracle server.

---

## 11. Operating System Adapters

Operating system compatibility must be implemented through adapters.

```text
BaseOSAdapter
  -> LinuxAdapter
      -> OracleLinuxAdapter
      -> RedHatAdapter
  -> AIXAdapter
```

Generic OS checks must call adapter methods, not hardcoded Linux commands.

### 11.1 BaseOSAdapter interface

Minimum required methods:

```python
class BaseOSAdapter:
    def detect_platform(self): ...
    def get_os_info(self): ...
    def get_cpu_info(self): ...
    def get_memory_info(self): ...
    def get_swap_info(self): ...
    def get_filesystem_usage(self): ...
    def get_mounts(self): ...
    def get_network_info(self): ...
    def get_ulimits(self): ...
    def get_processes(self): ...
    def get_oracle_processes(self): ...
    def get_oracle_environment(self): ...
    def get_time_sync_status(self): ...
    def get_kernel_parameters(self): ...
    def get_multipath_status(self): ...
    def get_system_errors(self): ...
```

### 11.2 LinuxAdapter

Must cover Oracle Linux, RHEL, Rocky Linux, AlmaLinux, CentOS, and compatible distributions.

Typical commands:

```text
cat /etc/os-release
uname -a
lscpu
free -m
cat /proc/meminfo
df -P
df -h
lsblk
mount
ip addr
ip route
ss -lntp
ps -ef
ulimit -a
sysctl -a
chronyc tracking
timedatectl
ntpq -p
multipath -ll
dmesg
journalctl
```

### 11.3 AIXAdapter

Must support IBM AIX as an independent platform, not as a Linux variant.

Typical commands:

```text
oslevel -s
uname -a
prtconf
lsattr
lsdev
vmstat
svmon
df -g
mount
lsvg
lslv
lspv
ifconfig -a
netstat -rn
entstat
ps -ef
ulimit -a
vmo -a
ioo -a
schedo -a
no -a
lspath
lsmpio
errpt
lssrc -s xntpd
ntpq -p
lslpp
instfix
```

Example OS adapter check:

```yaml
id: os_filesystem_usage
name: Uso de filesystems
description: Valida filesystems con alto porcentaje de uso.
category: os
group: os
scope: host
collector: os_adapter
adapter_method: get_filesystem_usage
severity: warning
enabled: true

applies_to:
  platforms:
    - linux
    - aix
  requires:
    os_connection: true

evaluation:
  type: threshold
  metric: used_pct
  operator: ">="
  warning: 80
  critical: 90

remediation:
  summary: Liberar espacio o ampliar filesystem.
  actions:
    - Identificar directorios con mayor consumo.
    - Limpiar logs antiguos si aplica.
    - Ampliar filesystem si el crecimiento es legítimo.
  owner: OS
  requires_window: false
  outage_risk: medium
```

---

## 12. Discovery Layer

Inventory discovery must run before checks.

### 12.1 Oracle discovery

Collect:

- Database name.
- DBID.
- DB_UNIQUE_NAME.
- Instance name.
- Host name.
- Oracle version.
- Edition when possible.
- Open mode.
- Database role.
- Protection mode.
- Force logging.
- Archivelog mode.
- Flashback status.
- CDB/non-CDB.
- PDB list.
- RAC flag.
- Instance number.
- Startup time.
- Character set.
- Time zone.
- Control files.
- Redo log configuration.
- FRA configuration.
- Tablespaces.
- Datafiles.
- Tempfiles.

### 12.2 RAC discovery

Collect:

- Cluster name.
- Nodes.
- Instances.
- Services.
- SCAN.
- SCAN listeners.
- VIPs.
- Listeners.
- Interconnect.
- CRS status.
- Cluster resources.
- OCR.
- Voting disks.
- ASM instances.
- Diskgroups.

### 12.3 Data Guard discovery

Collect:

- Primary database.
- Standby databases.
- Database role.
- Protection mode.
- Broker status.
- Apply lag.
- Transport lag.
- MRP status.
- RFS status.
- Archive destinations.
- Standby redo logs.
- Real-time apply.
- Flashback status.
- Gaps.

### 12.4 ASM discovery

Collect:

- ASM instance status.
- Mounted diskgroups.
- Diskgroup usage.
- Offline disks.
- Failgroups.
- Rebalance operations.
- ASM compatibility.
- RDBMS compatibility.
- ASM alert log location when possible.

### 12.5 OS discovery

Collect:

- OS type.
- OS version.
- Architecture.
- CPU.
- Memory.
- Swap.
- Filesystems.
- Mount points.
- Network interfaces.
- Routes.
- Ulimits.
- Time synchronization.
- Oracle processes.
- ASM processes.
- Listener processes.
- Oracle environment variables when possible.

Inventory must be written to:

```text
output/<target_id>_<timestamp>/inventory.json
```

---

## 13. Collectors

Supported collectors:

```text
oracle_sql
ssh_command
local_command
os_adapter
plugin
manual_info
```

- `oracle_sql`: runs SQL against Oracle.
- `ssh_command`: runs commands over SSH.
- `local_command`: runs local OS commands.
- `os_adapter`: calls a platform-specific adapter method.
- `plugin`: calls custom Python logic.
- `manual_info`: records informational items without runtime collection.

---

## 14. Evaluators

Required evaluators:

```text
threshold
expected_value
empty_result_pass
not_empty_fail
row_count_threshold
regex
comparison
contains
custom
```

Examples:

```yaml
evaluation:
  type: threshold
  metric: used_pct
  operator: ">="
  warning: 80
  critical: 90
```

```yaml
evaluation:
  type: expected_value
  metric: log_mode
  expected: ARCHIVELOG
```

```yaml
evaluation:
  type: empty_result_pass
```

```yaml
evaluation:
  type: regex
  pattern: "ORA-00600|ORA-07445"
  match_status: CRITICAL
  no_match_status: PASS
```

---

## 15. Plugins

Use plugins for complex logic that should not be forced into YAML.

Good plugin candidates:

- Data Guard primary vs standby comparison.
- RAC parameter comparison across instances.
- RAC service distribution analysis.
- Index redundancy analysis.
- Capacity analysis using AWR when enabled.
- Complex alert log parsing.
- Patching consistency across RAC nodes.

Conceptual interface:

```python
class CheckPlugin:
    id: str

    def collect(self, context):
        pass

    def evaluate(self, evidence, context):
        pass
```

---

## 16. Scoring

Implement a 0 to 100 score.

Suggested behavior:

```text
PASS: no penalty
INFO: no penalty
WARNING: low penalty
FAIL: medium penalty
CRITICAL: high penalty
ERROR: medium penalty, reported separately
SKIPPED: no penalty
```

Visual levels:

```text
90-100: Green
75-89: Yellow
60-74: Orange
0-59: Red
```

Ceiling rules:

- If at least one `CRITICAL` exists, the global status cannot be green.
- If several `FAIL` results exist, the global status cannot be green.
- If execution errors exist, the report must show an execution quality warning.
- `SKIPPED` checks must not penalize the score.

---

## 17. Output and Reports

Each execution must generate:

```text
executive_report.html
technical_report.html
corrective_actions.html
inventory.json
evidence.json
execution.log
```

Output path:

```text
output/<target_id>_<timestamp>/
```

Example:

```text
output/MEDAPROD_20260602_153000/
```

No SQLite or internal historical database must be implemented.

### 17.1 executive_report.html

Must include:

- Optional configurable logo.
- Optional customer name.
- Target name.
- Run date and time.
- Environment.
- Detected architecture.
- Oracle version.
- Global status.
- Score.
- Traffic-light visual indicator.
- Total checks.
- PASS count.
- INFO count.
- WARNING count.
- FAIL count.
- CRITICAL count.
- SKIPPED count.
- ERROR count.
- Top findings.
- Main risks.
- Executive conclusion.
- General recommendation.
- Result distribution by check group.

### 17.2 technical_report.html

Must include:

- Full inventory.
- Used connections without passwords.
- Standalone/RAC/Data Guard topology.
- Results by group.
- Results by severity.
- Check-by-check details.
- Evidence.
- Actual value.
- Expected value.
- Threshold.
- SQL or command when enabled by report settings.
- Technical error when it occurs.
- Duration.
- Recommendation.
- Status.
- SKIPPED reason.

### 17.3 corrective_actions.html

Must include only:

```text
WARNING
FAIL
CRITICAL
ERROR, in a separate execution issues section
```

For each finding:

- Check ID.
- Check name.
- Group.
- Severity.
- Finding.
- Risk.
- Recommended action.
- Suggested steps.
- Post-fix validation.
- Suggested owner.
- Whether a maintenance window is required.
- Outage risk.
- Priority.

---

## 18. Report Visual Design

Reports must use:

- Light theme by default.
- Soft colors.
- Green for PASS.
- Blue for INFO.
- Yellow for WARNING.
- Orange for FAIL.
- Red for CRITICAL.
- Gray for SKIPPED.
- Purple or neutral color for ERROR execution issues.
- Summary cards.
- Badges.
- Clean tables.
- Bullets.
- Optional collapsible technical sections.
- Progress bars or score indicators.
- Clear grouping by check group.

---

## 19. CLI

Required commands:

```text
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck list-profiles
orahealthcheck list-groups
orahealthcheck list-checks
orahealthcheck list-checks --group security
orahealthcheck run --target <target_id>
orahealthcheck run --target <target_id> --profile <profile_id>
orahealthcheck run --target <target_id> --groups security,storage
orahealthcheck run --target <target_id> --skip-groups schema_objects
orahealthcheck run --target <target_id> --checks db_invalid_objects,tablespace_free_pct
orahealthcheck run --target <target_id> --output-dir <path>
```

Optional future commands:

```text
orahealthcheck show-inventory --target <target_id>
orahealthcheck test-connection --target <target_id>
orahealthcheck test-db-connection <connection_id>
orahealthcheck test-os-connection <connection_id>
```

---

## 20. Secrets and Masking

Even though passwords in files are allowed, the framework must:

- Mask passwords in logs.
- Mask passwords in reports.
- Avoid printing full connect strings with passwords.
- Avoid logging sensitive environment variables.
- Support environment variables for passwords.
- Support wallet-based database authentication.
- Keep credential files separate when configured.
- Validate credential file permissions where possible.

Masking example:

```text
password: ********
```

---

## 21. Configuration Validation

`orahealthcheck validate-config` must validate:

- YAML syntax.
- Target references.
- Profile references.
- Group references.
- Check references.
- Connection profile references.
- Authentication methods.
- Platform names.
- Required check fields.
- Evaluator names.
- Collector names.
- Overrides pointing to existing checks.
- Numeric thresholds.
- Duplicate IDs.

---

## 22. Error Handling

A failed check must not stop the entire run.

If a SQL query fails due to missing privileges:

- Mark result as `ERROR` unless the check is optional/licensed and should be `SKIPPED`.
- Include the Oracle error code.
- Include a clear explanation in the technical report.
- Continue with the next check.

If a command fails:

- Capture stdout.
- Capture stderr.
- Capture exit code.
- Capture elapsed time.
- Mark `ERROR` if the command was required.
- Mark `SKIPPED` if the command is not available and the check is optional for that platform.

---

## 23. DRP Profile Behavior

The `drp_precheck_compare` profile must support cases where:

- ASM is up.
- The database is not open.
- The database may be mounted only.
- The destination database may be down.
- Disks may be read-only.
- Some DB checks do not apply.
- OS and ASM checks still apply.

Rules:

- Do not fail checks that require open database if the profile allows mounted or closed DB.
- Mark those checks as `SKIPPED` with clear reason.
- Run ASM checks when ASM is available.
- Run OS checks when OS is reachable.
- Compare with primary only when enough information exists.
- Explain analysis limitations in the reports.

---

## 24. Dependencies

Suggested dependencies:

```text
oracledb
paramiko
PyYAML
Jinja2
pydantic
typer or click
rich
```

Prefer:

- `pydantic` for models and validation.
- `typer` for CLI, unless `click` is preferred for simplicity.
- `Jinja2` for HTML reports.
- `oracledb` for Oracle connections.
- `paramiko` for SSH.

---

## 25. First Delivery Acceptance Criteria

The first implementation is successful when the following works:

```bash
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck run --target example_standalone
```

And the framework generates:

```text
output/example_standalone_YYYYMMDD_HHMMSS/
  executive_report.html
  technical_report.html
  corrective_actions.html
  inventory.json
  evidence.json
  execution.log
```

The first delivery must include only a small initial set of checks. The goal is to establish a stable architecture, not to implement every final check immediately.

---

## 26. Final Architecture Rule

The architectural rule that must guide all implementation work is:

```text
The target selects a profile.
The profile selects groups.
Groups contain checks.
Checks use standards.
Standards define thresholds and expected values.
Collectors gather evidence.
Evaluators decide status.
OS adapters solve platform differences.
Reports present results professionally.
```
