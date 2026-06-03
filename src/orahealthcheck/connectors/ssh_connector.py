from typing import Any

from orahealthcheck.models import ConnectionProfile


class SSHConnector:
    def __init__(self, profile: ConnectionProfile) -> None:
        self.profile = profile
        self.client: Any = None

    def connect(self) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError("paramiko is required for live SSH connections") from exc
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": self.profile.settings.get("host"),
            "port": self.profile.settings.get("port", 22),
            "username": self.profile.settings.get("username"),
            "timeout": self.profile.settings.get("connect_timeout", 15),
        }
        if self.profile.auth_method == "password":
            kwargs["password"] = self.profile.settings.get("password")
        elif self.profile.auth_method in {"private_key", "private_key_with_passphrase"}:
            kwargs["key_filename"] = self.profile.settings.get("private_key_path")
            kwargs["passphrase"] = self.profile.settings.get("private_key_passphrase")
        self.client.connect(**kwargs)

    def run_command(self, command: str, timeout: int = 60) -> dict[str, Any]:
        if not self.client:
            self.connect()
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        return {"stdout": stdout.read().decode(), "stderr": stderr.read().decode(), "exit_code": stdout.channel.recv_exit_status()}

    def close(self) -> None:
        if self.client:
            self.client.close()
