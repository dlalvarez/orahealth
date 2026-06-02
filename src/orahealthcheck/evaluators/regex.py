import re
from typing import Any

from orahealthcheck.models import ResultStatus


class RegexEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        pattern = config["pattern"]
        text = evidence if isinstance(evidence, str) else str(evidence)
        matched = re.search(pattern, text, re.MULTILINE) is not None
        mode = config.get("mode", "must_match")
        if (mode == "must_match" and matched) or (mode == "must_not_match" and not matched):
            return ResultStatus.PASS, "Regex condition passed"
        return ResultStatus(config.get("failure_status", "FAIL")), "Regex condition failed"
