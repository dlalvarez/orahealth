from typing import Any


class ConfigValidationError(Exception):
    pass


class ConfigValidator:
    def validate(self, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []
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
