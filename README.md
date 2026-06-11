# OraHealthCheck

OraHealthCheck es un framework modular y basado en configuración para health checks de Oracle y sistema operativo.

## Comandos de Fase 1

```bash
orahealthcheck validate-config
orahealthcheck list-targets
orahealthcheck list-profiles
orahealthcheck list-groups
orahealthcheck list-checks
orahealthcheck run --target example_standalone
```

Los artefactos generados por cada ejecución se escriben en `output/<target_id>_<timestamp>/`.

## Comportamiento del target de ejemplo

`example_standalone` está diseñado para validar el framework sin requerir una base de datos Oracle real. Usa valores mock de inventario de base de datos desde `config/targets.yaml` y recolección local mediante adaptadores OS para los checks de sistema operativo. Reemplace el perfil de conexión de ejemplo y la configuración de descubrimiento de inventario antes de usar OraHealthCheck contra una base de datos real.

## Configuración local no versionada

El repositorio mantiene configuración base segura en estos archivos versionados:

- `config/connection_profiles.yaml`
- `config/targets.yaml`

Para ambientes reales de laboratorio o cliente, cree archivos locales opcionales de override:

- `config/connection_profiles.local.yaml`
- `config/targets.local.yaml`

OraHealthCheck carga primero los archivos base y luego carga los archivos `.local.yaml` si existen. Los archivos locales pueden agregar entradas nuevas o reemplazar entradas base:

- `connection_profiles.local.yaml` puede agregar o sobrescribir `db_connections` y `os_connections` por nombre de conexión.
- `targets.local.yaml` puede agregar o sobrescribir `targets` por `target_id`.

Los archivos locales son ignorados por Git mediante `config/*.local.yaml`, por lo que hosts reales, usuarios, connection IDs y referencias a credenciales pueden permanecer fuera del control de versiones. Los archivos de respaldo como `config/*.bak` también se ignoran.

Se proveen archivos de plantilla como punto de partida:

```bash
cp config/connection_profiles.local.yaml.example config/connection_profiles.local.yaml
cp config/targets.local.yaml.example config/targets.local.yaml
```

Para ambientes reales, edite solo los archivos `.local.yaml` copiados. No coloque passwords reales en los archivos de ejemplo ni en los archivos base versionados.

## Passwords mediante variables de entorno

Prefiera variables de entorno para passwords reales de base de datos. En `config/connection_profiles.local.yaml`, configure la conexión con `auth_method: env` y apunte `password_env` al nombre de la variable:

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

Exporte el password en su shell antes de ejecutar OraHealthCheck:

```bash
export ORAHEALTHCHECK_LAB_DB_PASSWORD='change-me-outside-git'
```

## Pruebas con un target real sin exponer credenciales

1. Copie las plantillas locales:

   ```bash
   cp config/connection_profiles.local.yaml.example config/connection_profiles.local.yaml
   cp config/targets.local.yaml.example config/targets.local.yaml
   ```

2. Edite `config/connection_profiles.local.yaml` con el host real, service name, username y nombre de variable `password_env`. Mantenga `auth_method: env` para passwords de base de datos.

3. Edite `config/targets.local.yaml` para que el target referencie los nombres de conexión locales:

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

4. Exporte la variable de password en el shell donde ejecutará el check:

   ```bash
   export ORAHEALTHCHECK_LAB_DB_PASSWORD='real-password-kept-outside-git'
   ```

5. Valide la configuración combinada final y confirme que el target local esté visible:

   ```bash
   orahealthcheck validate-config
   orahealthcheck list-targets
   ```

6. Ejecute contra el target real:

   ```bash
   orahealthcheck run --target lab_standalone
   ```

Antes de hacer commit, ejecute `git status --short` y verifique que `config/connection_profiles.local.yaml` y `config/targets.local.yaml` no aparezcan como cambios trackeados.

## Idioma de los reportes y textos visibles

OraHealthCheck debe presentar en español todos los textos visibles para el usuario final, incluyendo reportes HTML, títulos de checks, mensajes, remediaciones, acciones correctivas, salidas de comandos CLI orientadas al usuario y documentación funcional.

Los identificadores internos, claves JSON, nombres de archivos, nombres de funciones, comandos, vistas Oracle, parámetros Oracle y constantes internas pueden mantenerse en inglés o en su forma técnica original cuando corresponda.
