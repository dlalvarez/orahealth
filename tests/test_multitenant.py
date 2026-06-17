from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators.multitenant import MultitenantEvaluator
from orahealthcheck.models import Inventory, ResultStatus, Target


def test_multitenant_group_and_yaml_load():
    config = ConfigLoader("config").load_all()
    assert ConfigValidator().validate(config) == []
    assert "multitenant" in config["groups"]
    group = config["groups"]["multitenant"]
    assert group.name == "Multitenant / CDB-PDB básico"
    assert "multitenant_pdb_inventory" in group.checks
    assert set(group.checks).issubset(config["checks"])


def test_all_multitenant_checks_require_multitenant_feature():
    config = ConfigLoader("config").load_all()
    for check_id in config["groups"]["multitenant"].checks:
        assert config["checks"][check_id].applicability == {"requires_feature": "multitenant"}


def test_list_checks_includes_multitenant(capsys):
    from orahealthcheck.cli import main
    assert main(["list-checks"]) == 0
    output = capsys.readouterr().out
    assert "multitenant_pdb_inventory" in output
    assert "Inventario básico de PDBs" in output


def _run_multitenant_checks_with_features(features):
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    target = Target("t1", "T1", "dev", "standalone", "standalone_basic", database={"primary_connection": "mock"})
    inventory = Inventory("t1", "standalone", "dev", database={"parameters": {}}, features=features)
    return [runner._run_check(config["checks"][cid], target, inventory) for cid in config["groups"]["multitenant"].checks]


def test_multitenant_checks_skipped_when_feature_not_detected():
    results = _run_multitenant_checks_with_features({"multitenant": {"detected": False, "status": "not_detected", "reason": "La base de datos no está configurada como CDB."}})
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all("no está detectada" in (r.skipped_reason or "") for r in results)


def test_multitenant_checks_skipped_when_feature_missing():
    results = _run_multitenant_checks_with_features({})
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all("no existe en el inventario" in (r.skipped_reason or "") for r in results)


def test_multitenant_evaluator_rules():
    ev = MultitenantEvaluator()
    rows_ok = [{"name": "APP1", "con_id": 3, "open_mode": "READ WRITE", "status": "NORMAL", "restricted": "NO"}]
    rows_bad = [{"name": "APP1", "con_id": 3, "open_mode": "MOUNTED", "status": "NORMAL", "restricted": "NO"}]
    rows_restricted = [{"name": "APP1", "con_id": 3, "open_mode": "READ WRITE", "status": "NORMAL", "restricted": "YES"}]
    seed_only = [{"name": "PDB$SEED", "con_id": 2, "open_mode": "READ ONLY", "status": "NORMAL", "restricted": "NO"}]
    assert ev.evaluate({"metric": "multitenant_pdb_inventory", "rows": rows_ok, "pdb_count": 1}, {})[0] == ResultStatus.INFO
    assert ev.evaluate({"metric": "multitenant_pdb_open_state", "rows": rows_ok}, {})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "multitenant_pdb_open_state", "rows": rows_bad}, {})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "multitenant_pdb_open_state", "rows": seed_only}, {})[0] == ResultStatus.INFO
    status, message = ev.evaluate({"metric": "multitenant_pdb_restricted_mode", "rows": rows_restricted}, {})
    assert status == ResultStatus.WARNING
    assert "modo restringido" in message


def test_multitenant_real_inventory_queries_only_for_cdb():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)

    class Connector:
        queries = []
        def __init__(self, profile):
            pass
        def connect(self):
            pass
        def close(self):
            pass
        def query(self, query):
            self.queries.append(query.lower())
            return []

    connector = Connector({})
    result = runner._discover_multitenant_inventory(connector, "NO")
    assert result == {"multitenant": {"pdbs": []}}
    assert Connector.queries == []
