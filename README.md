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

## Local, non-versioned configuration

The repository keeps safe base configuration in these versioned files:

- `config/connection_profiles.yaml`
- `config/targets.yaml`

For real laboratory or client environments, create optional local override files:

- `config/connection_profiles.local.yaml`
- `config/targets.local.yaml`

OraHealthCheck loads the base files first and then loads the `.local.yaml` files if they exist. Local files can add new entries or replace base entries:

- `connection_profiles.local.yaml` can add or overwrite `db_connections` and `os_connections` by connection name.
- `targets.local.yaml` can add or overwrite `targets` by `target_id`.

The local files are ignored by Git through `config/*.local.yaml`, so real hosts, usernames, connection IDs, and credential references can stay outside version control. Backup files such as `config/*.bak` are ignored too.

Template files are provided as a starting point:

```bash
cp config/connection_profiles.local.yaml.example config/connection_profiles.local.yaml
cp config/targets.local.yaml.example config/targets.local.yaml
```

Edit only the copied `.local.yaml` files for real environments. Do not put real passwords in the example files or in the versioned base files.

## Passwords through environment variables

Prefer environment variables for real database passwords. In `config/connection_profiles.local.yaml`, set the connection to `auth_method: env` and point `password_env` to the variable name:

```yaml
db_connections:
  lab_oracle:
    type: oracle
    host: lab-db.example.com
    port: 1521
    service_name: LABPDB1
    username: system
    auth_method: env
    password_env: ORAHEALTHCHECK_LAB_DB_PASSWORD
    mode: normal
```

Export the password in your shell before running OraHealthCheck:

```bash
export ORAHEALTHCHECK_LAB_DB_PASSWORD='change-me-outside-git'
```

## Testing with a real target without exposing credentials

1. Copy the local templates:

   ```bash
   cp config/connection_profiles.local.yaml.example config/connection_profiles.local.yaml
   cp config/targets.local.yaml.example config/targets.local.yaml
   ```

2. Edit `config/connection_profiles.local.yaml` with the real host, service name, username, and `password_env` variable name. Keep `auth_method: env` for database passwords.

3. Edit `config/targets.local.yaml` so the target references the local connection names:

   ```yaml
   targets:
     - target_id: lab_standalone
       name: Lab Standalone Database
       environment: lab
       expected_architecture: standalone
       profile: standalone_basic
       database:
         primary_connection: lab_oracle
       operating_system:
         platform: linux
         connections:
           - lab_oracle_host
   ```

4. Export the password variable in the shell where you will run the check:

   ```bash
   export ORAHEALTHCHECK_LAB_DB_PASSWORD='real-password-kept-outside-git'
   ```

5. Validate the final combined configuration and confirm the local target is visible:

   ```bash
   orahealthcheck validate-config
   orahealthcheck list-targets
   ```

6. Run against the real target:

   ```bash
   orahealthcheck run --target lab_standalone
   ```

Before committing, run `git status --short` and verify that `config/connection_profiles.local.yaml` and `config/targets.local.yaml` do not appear as tracked changes.
