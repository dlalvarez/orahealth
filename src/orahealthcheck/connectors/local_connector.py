import subprocess
from typing import Any


class LocalConnector:
    def run_command(self, command: str, timeout: int = 60) -> dict[str, Any]:
        completed = subprocess.run(command, shell=True, check=False, capture_output=True, text=True, timeout=timeout)
        return {"stdout": completed.stdout, "stderr": completed.stderr, "exit_code": completed.returncode}
