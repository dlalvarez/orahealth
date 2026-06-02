from typing import Any, Protocol

from orahealthcheck.models import Check, Inventory, Target


class Collector(Protocol):
    def collect(self, check: Check, target: Target, inventory: Inventory) -> Any: ...
