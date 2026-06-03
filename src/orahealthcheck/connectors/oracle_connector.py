from typing import Any

from orahealthcheck.models import ConnectionProfile


class OracleConnector:
    def __init__(self, profile: ConnectionProfile | None) -> None:
        self.profile = profile
        self.connection: Any = None

    def connect(self) -> None:
        if not self.profile:
            return
        try:
            import oracledb  # type: ignore
        except ImportError as exc:
            raise RuntimeError("python-oracledb is required for live Oracle connections") from exc
        if self.profile.auth_method in {"wallet", "external", "os_auth"}:
            raise NotImplementedError(f"Oracle auth method {self.profile.auth_method} is prepared but not active in Phase 1")
        password = self.profile.settings.get("password")
        if self.profile.auth_method == "env":
            import os
            password = os.environ.get(self.profile.settings.get("password_env", ""))
        mode = oracledb.AUTH_MODE_SYSDBA if self.profile.settings.get("mode") == "sysdba" else oracledb.AUTH_MODE_DEFAULT
        self.connection = oracledb.connect(
            user=self.profile.settings.get("username"),
            password=password,
            host=self.profile.settings.get("host"),
            port=self.profile.settings.get("port", 1521),
            service_name=self.profile.settings.get("service_name"),
            mode=mode,
        )

    def query(self, sql: str) -> list[dict[str, Any]]:
        if not self.connection:
            raise RuntimeError("Oracle connection is not established")
        with self.connection.cursor() as cursor:
            cursor.execute(sql)
            columns = [col[0].lower() for col in cursor.description or []]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def close(self) -> None:
        if self.connection:
            self.connection.close()
