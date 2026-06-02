from typing import Any

from .base import BaseOSAdapter


class LinuxAdapter(BaseOSAdapter):
    def get_os_info(self) -> dict[str, Any]:
        return {"platform": "linux", "raw": self._run("uname -a && cat /etc/os-release 2>/dev/null")}

    def get_cpu_info(self) -> dict[str, Any]:
        result = self._run("nproc 2>/dev/null || getconf _NPROCESSORS_ONLN")
        try:
            count = int(result["stdout"].strip().splitlines()[0])
        except (ValueError, IndexError):
            count = 0
        return {"cpu_count": count, "raw": result}

    def get_memory_info(self) -> dict[str, Any]:
        result = self._run("free -m")
        total = available = 0
        for line in result["stdout"].splitlines():
            if line.lower().startswith("mem:"):
                parts = line.split()
                total = int(parts[1]); available = int(parts[6] if len(parts) > 6 else parts[3])
        return {"total_mb": total, "available_mb": available, "raw": result}

    def get_swap_info(self) -> dict[str, Any]:
        return {"raw": self._run("free -m | awk '/^Swap:/ {print $2,$3,$4}'")}

    def get_filesystem_usage(self) -> list[dict[str, Any]]:
        result = self._run("df -P -k")
        rows = []
        for line in result["stdout"].splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                rows.append({"filesystem": parts[0], "used_pct": int(parts[4].rstrip("%")), "mount": parts[5]})
        return rows

    def get_ulimits(self) -> dict[str, Any]:
        return {"raw": self._run("ulimit -a")}

    def get_processes(self) -> list[dict[str, Any]]:
        return [{"raw": self._run("ps -eo user,pid,comm | head -200")}]

    def get_oracle_processes(self) -> list[dict[str, Any]]:
        return [{"raw": self._run("ps -eo user,pid,comm | awk '/ora_|asm_|tnslsnr/ {print}'") }]

    def get_time_sync_status(self) -> dict[str, Any]:
        return {"raw": self._run("timedatectl status 2>/dev/null || chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null")}
