from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - fallback for minimal environments
    from orahealthcheck.utils import simple_yaml as yaml

from orahealthcheck.models import Check, CheckGroup, ConnectionProfile, Profile, Standard, Target


class ConfigLoader:
    def __init__(self, config_dir: str | Path = "config") -> None:
        self.config_dir = Path(config_dir)

    def _read_yaml(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def load_app_settings(self) -> dict[str, Any]:
        return self._read_yaml(self.config_dir / "app_settings.yaml")

    def load_connections(self) -> dict[str, dict[str, ConnectionProfile]]:
        data = self._read_yaml(self.config_dir / "connection_profiles.yaml")
        return {
            "db_connections": {k: ConnectionProfile.from_mapping(k, v) for k, v in data.get("db_connections", {}).items()},
            "os_connections": {k: ConnectionProfile.from_mapping(k, v) for k, v in data.get("os_connections", {}).items()},
        }

    def load_targets(self) -> dict[str, Target]:
        data = self._read_yaml(self.config_dir / "targets.yaml")
        return {item["target_id"]: Target.from_mapping(item) for item in data.get("targets", [])}

    def load_profiles(self) -> dict[str, Profile]:
        profiles: dict[str, Profile] = {}
        for path in sorted((self.config_dir / "profiles").glob("*.yaml")):
            data = self._read_yaml(path)
            profile_id = data.get("profile_id", path.stem)
            profiles[profile_id] = Profile.from_mapping(profile_id, data)
        return profiles

    def load_standards(self) -> dict[str, Standard]:
        standards: dict[str, Standard] = {}
        for path in sorted((self.config_dir / "standards").glob("*.yaml")):
            data = self._read_yaml(path)
            standard_id = data.get("standard_id", path.stem)
            standards[standard_id] = Standard.from_mapping(standard_id, data)
        return standards

    def load_check_groups(self) -> dict[str, CheckGroup]:
        groups: dict[str, CheckGroup] = {}
        for path in sorted((self.config_dir / "check_groups").glob("*.yaml")):
            data = self._read_yaml(path)
            group_id = data.get("group_id", path.stem)
            groups[group_id] = CheckGroup.from_mapping(group_id, data)
        return groups

    def load_checks(self) -> dict[str, Check]:
        checks: dict[str, Check] = {}
        for path in sorted((self.config_dir / "checks").glob("**/*.yaml")):
            data = self._read_yaml(path)
            check = Check.from_mapping(data)
            checks[check.check_id] = check
        return checks

    def load_all(self) -> dict[str, Any]:
        return {
            "settings": self.load_app_settings(),
            "connections": self.load_connections(),
            "targets": self.load_targets(),
            "profiles": self.load_profiles(),
            "standards": self.load_standards(),
            "groups": self.load_check_groups(),
            "checks": self.load_checks(),
        }
