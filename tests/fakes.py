"""Dobles de prueba para conectores. Mantienen las pruebas independientes del host que las ejecuta."""

from typing import Any

DEFAULT_OS_OUTPUTS = {
    "uname -a": "Linux srvdb01 5.15.0-200.el8uek.x86_64 #2 SMP x86_64 GNU/Linux\nNAME=\"Oracle Linux Server\"\nVERSION=\"8.9\"\n",
    "nproc": "8\n",
    "free -m": (
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:          64000       20000       10000         100       34000       42000\n"
        "Swap:          8191           0        8191\n"
    ),
    "df -P -k": (
        "Filesystem     1024-blocks      Used Available Capacity Mounted on\n"
        "/dev/sda1        52403200  20961280  31441920      40% /\n"
        "/dev/sdb1       209612800 125767680  83845120      60% /u01\n"
    ),
}


class FakeOSConnector:
    """Responde comandos por prefijo con salidas fijas; registra lo ejecutado."""

    def __init__(self, outputs: dict[str, str] | None = None, profile: Any = None) -> None:
        self.outputs = dict(DEFAULT_OS_OUTPUTS if outputs is None else outputs)
        self.profile = profile
        self.commands: list[str] = []
        self.closed = False

    def connect(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def run_command(self, command: str, timeout: int = 60) -> dict[str, Any]:
        self.commands.append(command)
        for prefix, stdout in self.outputs.items():
            if command.startswith(prefix):
                return {"stdout": stdout, "stderr": "", "exit_code": 0, "success": True, "error": None}
        return {"stdout": "", "stderr": f"comando no simulado: {command}", "exit_code": 127, "success": False,
                "error": {"type": "CommandFailed", "message": "comando no simulado"}}


class NoPrivilegeOracleConnector:
    """Conector Oracle donde toda consulta falla con ORA-01031."""

    def __init__(self, profile: Any = None) -> None:
        self.profile = profile

    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None

    def query(self, sql: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        raise Exception("ORA-01031: insufficient privileges")
