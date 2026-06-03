from typing import Any

from .base import BaseOSAdapter


class AIXAdapter(BaseOSAdapter):
    def get_os_info(self) -> dict[str, Any]:
        return {"platform": "aix", "raw": self._run("oslevel -s; uname -a")}

    def get_cpu_info(self) -> dict[str, Any]:
        return {"raw": self._run("prtconf | grep -i 'Number Of Processors'")}

    def get_memory_info(self) -> dict[str, Any]:
        return {"raw": self._run("svmon -G")}

    def get_swap_info(self) -> dict[str, Any]:
        return {"raw": self._run("lsps -a")}

    def get_filesystem_usage(self) -> list[dict[str, Any]]:
        result = self._run("df -Pk")
        rows = []
        for line in result["stdout"].splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 7:
                rows.append({"filesystem": parts[0], "used_pct": int(parts[3].rstrip("%")), "mount": parts[-1]})
        return rows

    def get_ulimits(self) -> dict[str, Any]:
        return {"raw": self._run("ulimit -a")}

    def get_processes(self) -> list[dict[str, Any]]:
        return [{"raw": self._run("ps -ef | head -200")}]

    def get_oracle_processes(self) -> list[dict[str, Any]]:
        return [{"raw": self._run("ps -ef | egrep 'ora_|asm_|tnslsnr' | grep -v egrep") }]

    def get_time_sync_status(self) -> dict[str, Any]:
        return {"raw": self._run("lssrc -s xntpd; ntpq -p 2>/dev/null")}
