from .empty_result_pass import EmptyResultPassEvaluator
from .expected_value import ExpectedValueEvaluator
from .not_empty_fail import NotEmptyFailEvaluator
from .oracle_config import OracleConfigEvaluator
from .oracle_security import OracleSecurityEvaluator
from .regex import RegexEvaluator
from .row_count_threshold import RowCountThresholdEvaluator
from .threshold import ThresholdEvaluator
from .storage import StorageEvaluator

EVALUATORS = {
    "threshold": ThresholdEvaluator(),
    "expected_value": ExpectedValueEvaluator(),
    "empty_result_pass": EmptyResultPassEvaluator(),
    "not_empty_fail": NotEmptyFailEvaluator(),
    "oracle_config": OracleConfigEvaluator(),
    "oracle_security": OracleSecurityEvaluator(),
    "row_count_threshold": RowCountThresholdEvaluator(),
    "regex": RegexEvaluator(),
    "storage": StorageEvaluator(),
}

__all__ = ["EVALUATORS"]
