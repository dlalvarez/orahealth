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
