from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import ResultStatus


def test_expected_value_passes():
    status, _ = EVALUATORS["expected_value"].evaluate("OPEN", {"expected": "OPEN"})
    assert status == ResultStatus.PASS


def test_threshold_warns():
    status, _ = EVALUATORS["threshold"].evaluate(90, {"operator": ">=", "warning": 80})
    assert status == ResultStatus.WARNING


def test_regex_must_not_match():
    status, _ = EVALUATORS["regex"].evaluate("all good", {"pattern": "ORA-00600", "mode": "must_not_match"})
    assert status == ResultStatus.PASS


def test_threshold_returns_controlled_error_for_none_metric():
    status, message = EVALUATORS["threshold"].evaluate(None, {"field": "tablespace_min_free_pct", "operator": "<=", "warning": 10})
    assert status == ResultStatus.ERROR
    assert message == "Metric tablespace_min_free_pct was not found in evidence"


def test_threshold_returns_controlled_error_for_missing_field():
    status, message = EVALUATORS["threshold"].evaluate({}, {"field": "fra_used_pct", "operator": ">=", "warning": 80})
    assert status == ResultStatus.ERROR
    assert message == "Metric fra_used_pct was not found in evidence"
