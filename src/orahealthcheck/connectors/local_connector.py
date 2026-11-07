import subprocess
import time
from typing import Any


class LocalConnector:
    """Ejecuta comandos en la máquina donde corre OraHealthCheck.

    Retorna siempre una respuesta estructurada; los errores técnicos (timeout,
    comando inexistente) se reportan en ``error`` en lugar de propagarse.
    """

    def connect(self) -> None:  # interfaz homogénea con SSHConnector
        return None

    def close(self) -> None:
        return None

    def run_command(self, command: str, timeout: int = 60) -> dict[str, Any]:
        start = time.monotonic()
        try:
            completed = subprocess.run(command, shell=True, check=False, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {
                "stdout": "", "stderr": "", "exit_code": None, "success": False,
                "elapsed_ms": int((time.monotonic() - start) * 1000),
                "error": {"type": "TimeoutExpired", "message": f"El comando superó el timeout de {timeout}s"},
            }
        return {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
            "success": completed.returncode == 0,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
            "error": None if completed.returncode == 0 else {"type": "CommandFailed", "message": completed.stderr.strip()[:500]},
        }
