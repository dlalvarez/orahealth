from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators.rac import RacEvaluator
from orahealthcheck.models import Inventory, ResultStatus, Target


def test_rac_group_and_yaml_load():
    config = ConfigLoader("config").load_all()
    assert ConfigValidator().validate(config) == []
    assert "rac" in config["groups"]
    group = config["groups"]["rac"]
    assert group.name == "Oracle RAC básico"
    assert "rac_cluster_database_parameter" in group.checks
    assert set(group.checks).issubset(config["checks"])


def test_all_rac_checks_require_oracle_rac_feature():
    config = ConfigLoader("config").load_all()
    for check_id in config["groups"]["rac"].checks:
        assert config["checks"][check_id].applicability == {"requires_feature": "oracle_rac"}


def test_list_checks_includes_rac(capsys):
    from orahealthcheck.cli import main
    assert main(["list-checks"]) == 0
    output = capsys.readouterr().out
    assert "rac_cluster_database_parameter" in output
    assert "Parámetro cluster_database RAC" in output


def _run_rac_checks_with_features(features):
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    target = Target("t1", "T1", "dev", "standalone", "standalone_basic", database={"primary_connection": "mock"})
    inventory = Inventory("t1", "standalone", "dev", database={"parameters": {}}, features=features)
    return [runner._run_check(config["checks"][cid], target, inventory) for cid in config["groups"]["rac"].checks]


def test_rac_checks_skipped_when_feature_not_detected():
    results = _run_rac_checks_with_features({"oracle_rac": {"detected": False, "status": "not_detected", "reason": "cluster_database = FALSE"}})
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all("no está detectada" in (r.skipped_reason or "") for r in results)


def test_rac_checks_skipped_when_feature_unknown():
    results = _run_rac_checks_with_features({"oracle_rac": {"deted": False, "status": "unknown", "reason": "sin privilegios"}})
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all("no pudo determinarse" in (r.skipped_reason or "") for r in results)


def test_rac_checks_skipped_when_feature_missing():
    results = _run_rac_checks_with_features({})
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all("no existe en el inventario" in (r.skipped_reason or "") for r in results)


def test_checks_without_applicability_still_run():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    check = config["checks"]["database_status"]
    target = Target("t1", "T1", "dev", "standalone", "standalone_basic", database={"primary_connection": "mock"})
    inventory = Inventory("t1", "standalone", "dev", database={"status": "OPEN"})
    result = runner._run_check(check, target, inventory)
    assert result.status == ResultStatus.PASS


def test_rac_evaluator_rules():
    ev = RacEvaluator()
    assert ev.evaluate({"metric": "rac_instances_status", "rows": [{"status": "OPEN", "active_state": "NORMAL"}]}, {})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "rac_instances_status", "rows": [{"status": "MOUNTED", "active_state": "NORMAL"}]}, {})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "rac_instance_count", "instance_count": 1, "min_instances": 2}, {})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "rac_threads_status", "rows": [{"status": "OPEN", "enabled": "PUBLIC"}]}, {})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "rac_threads_status", "rows": [{"status": "OPEN", "enabled": "DISABLED"}]}, {})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "rac_undo_configuration_basic", "rows": [{"value": "UNDOTBS1"}]}, {})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "rac_undo_configuration_basic", "rows": [{"value": ""}]}, {})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "rac_services_basic", "rows": []}, {})[0] == ResultStatus.INFO
    assert ev.evaluate({"metric": "rac_interconnect_info", "rows": []}, {})[0] == ResultStatus.INFO
