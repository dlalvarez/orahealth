from pathlib import Path
from typing import Any
import re


class ConfigValidationError(Exception):
    pass


class ConfigSyntaxError(ConfigValidationError):
    def __init__(self, path: str | Path, message: str, line: int | None = None, column: int | None = None) -> None:
        self.path = Path(path)
        self.line = line
        self.column = column
        self.message = message
        location = ""
        if line is not None:
            location = f":{line}"
            if column is not None:
                location += f":{column}"
        super().__init__(f"Invalid YAML in {self.path}{location}: {message}")


class ConfigValidator:
    _UNQUOTED_OPERATOR = re.compile(r"^\s*operator:\s*(>=|<=|>|<)\s*(?:#.*)?$")

    def validate(self, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        errors.extend(self._validate_operator_quoting(Path(config.get("_config_dir", "config"))))
        targets = config["targets"]
        profiles = config["profiles"]
        groups = config["groups"]
        checks = config["checks"]
        connections = config["connections"]

        for target in targets.values():
            if target.profile not in profiles:
                errors.append(f"Target {target.target_id} references missing profile {target.profile}")
            db_conn = target.database.get("primary_connection")
            if db_conn and db_conn not in connections["db_connections"]:
                errors.append(f"Target {target.target_id} references missing DB connection {db_conn}")
            for os_conn in target.operating_system.get("connections", []):
                if os_conn not in connections["os_connections"]:
                    errors.append(f"Target {target.target_id} references missing OS connection {os_conn}")

        for profile in profiles.values():
            for group_id in profile.enabled_groups:
                if group_id not in groups:
                    errors.append(f"Profile {profile.profile_id} references missing group {group_id}")

        for group in groups.values():
            for check_id in group.checks:
                if check_id not in checks:
                    errors.append(f"Group {group.group_id} references missing check {check_id}")

        for check in checks.values():
            if check.group_id not in groups:
                errors.append(f"Check {check.check_id} references missing group {check.group_id}")

        if errors:
            raise ConfigValidationError("\n".join(errors))
        return errors

    def _validate_operator_quoting(self, config_dir: Path) -> list[str]:
        errors: list[str] = []
        if not config_dir.exists():
            return errors
        for path in sorted(config_dir.glob("**/*.yaml")):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                match = self._UNQUOTED_OPERATOR.match(line)
                if match:
                    errors.append(
                        f'{path}:{line_number}: YAML comparison operator {match.group(1)!r} must be quoted, '
                        f'for example operator: "{match.group(1)}"'
                    )
        return errors
