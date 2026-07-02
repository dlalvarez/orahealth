from .alert_log import AlertLogEvaluator
from .asm import AsmEvaluator
from .empty_result_pass import EmptyResultPassEvaluator
from .expected_value import ExpectedValueEvaluator
from .not_empty_fail import NotEmptyFailEvaluator
from .oracle_config import OracleConfigEvaluator
from .oracle_security import OracleSecurityEvaluator
from .oracle_resources import OracleResourcesEvaluator
from .performance import PerformanceEvaluator
from .capacity import CapacityEvaluator
from .dataguard import DataGuardEvaluator
from .io_redo_archive import IoRedoArchiveEvaluator
from .multitenant import MultitenantEvaluator
from .recoverability_drp import RecoverabilityDrpEvaluator
from .rac import RacEvaluator
from .regex import RegexEvaluator
from .schema_objects import SchemaObjectsEvaluator
from .row_count_threshold import RowCountThresholdEvaluator
from .threshold import ThresholdEvaluator
from .storage import StorageEvaluator

EVALUATORS = {
    "alert_log_family": AlertLogEvaluator(),
    "asm": AsmEvaluator(),
    "threshold": ThresholdEvaluator(),
    "expected_value": ExpectedValueEvaluator(),
    "empty_result_pass": EmptyResultPassEvaluator(),
    "not_empty_fail": NotEmptyFailEvaluator(),
    "oracle_config": OracleConfigEvaluator(),
    "oracle_security": OracleSecurityEvaluator(),
    "oracle_resources": OracleResourcesEvaluator(),
    "performance": PerformanceEvaluator(),
    "capacity": CapacityEvaluator(),
    "dataguard": DataGuardEvaluator(),
    "io_redo_archive": IoRedoArchiveEvaluator(),
    "multitenant": MultitenantEvaluator(),
    "recoverability_drp": RecoverabilityDrpEvaluator(),
    "rac": RacEvaluator(),
    "row_count_threshold": RowCountThresholdEvaluator(),
    "regex": RegexEvaluator(),
    "schema_objects": SchemaObjectsEvaluator(),
    "storage": StorageEvaluator(),
}

__all__ = ["EVALUATORS"]
