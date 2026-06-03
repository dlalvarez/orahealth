# OraHealthCheck

OraHealthCheck is a modular, configuration-driven Python framework for Oracle and OS health checks.

## Phase 1 commands

```bash
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck list-profiles
orahealthcheck list-groups
orahealthcheck list-checks
orahealthcheck run --target example_standalone
```

Generated execution artifacts are written to `output/<target_id>_<timestamp>/`.

## Example target behavior

`example_standalone` is intended to validate the Phase 1 framework without requiring a live Oracle database. It uses mock database inventory values from `config/targets.yaml` and local OS adapter collection for OS checks. Replace the example connection profile and inventory discovery settings before using OraHealthCheck against a real database.
