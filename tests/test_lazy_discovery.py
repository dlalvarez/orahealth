"""Fase C2 - El descubrimiento solo consulta lo que el perfil necesita."""

import json

from orahealthcheck.engine import CheckRunner
from orahealthcheck.engine.runner import ALWAYS_SECTIONS


class RecordingConnector:
    """Base identificable que registra cada SQL ejecutado y devuelve filas vacías."""

    queries: list[str] = []

    def __init__(self, profile=None):
        self.profile = profile

    def connect(self):
        return None

    def close(self):
        return None

    def query(self, sql, *args, **kwargs):
        q = " ".join(sql.lower().split())
        RecordingConnector.queries.append(q)
        if "1 = 0" in q:
            return []
        if "from v$database" in q:
            return [{"db_name": "ORCL", "open_mode": "READ WRITE", "role": "PRIMARY", "cdb": "NO"}]
        if "from v$instance" in q:
            return [{"status": "OPEN", "version": "19.0.0.0.0", "instance_name": "orcl"}]
        return []


def _real(config):
    target = config["targets"]["example_standalone"]
    target.database = {k: v for k, v in target.database.items() if k != "mock_inventory"}
    target.operating_system = {"platform": "linux"}


def _run(config, profile):
    RecordingConnector.queries = []
    output = CheckRunner(config, oracle_connector_factory=RecordingConnector).run_target("example_standalone", profile)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    return evidence, inventory, list(RecordingConnector.queries)


def _queried(queries, view):
    return any(f"from {view} " in q + " " or f"from {view}\n" in q for q in queries if "1 = 0" not in q)


def test_basic_profile_skips_heavy_discovery(example_config):
    _real(example_config)
    _, inventory, queries = _run(example_config, "standalone_basic")
    sections = set(inventory["database"]["discovered_sections"])
    # standalone_basic no incluye capacity, performance, patching ni rac
    assert not sections & {"capacity", "performance", "patching", "rac"}
    assert not _queried(queries, "v$sql")
    assert not _queried(queries, "v$session_longops")
    assert not _queried(queries, "dba_registry_sqlpatch")
    assert not _queried(queries, "gv$instance")
    assert set(ALWAYS_SECTIONS) <= sections


def test_capacity_pulls_its_dependencies():
    runner = CheckRunner({})

    class Fake:
        def __init__(self, ctype):
            self.collector = {"type": ctype}

    assert runner._sections_for([Fake("capacity")]) >= {"capacity", "storage", "oracle_resources"}
    assert runner._sections_for([Fake("patching")]) >= {"patching", "multitenant"}
    assert runner._sections_for(None) is None


def test_lazy_results_match_full_discovery(example_config, monkeypatch):
    _real(example_config)
    lazy, _, lazy_queries = _run(example_config, "standalone_all")
    monkeypatch.setattr(CheckRunner, "_sections_for", lambda self, checks: None)
    full, _, full_queries = _run(example_config, "standalone_all")
    as_status = lambda ev: {r["check_id"]: (r["status"], r.get("message")) for r in ev["results"]}  # noqa: E731
    assert as_status(lazy) == as_status(full)
    assert len(lazy_queries) <= len(full_queries)


def test_basic_profile_runs_fewer_queries_than_full(example_config):
    _real(example_config)
    _, _, basic = _run(example_config, "standalone_basic")
    _, _, full = _run(example_config, "standalone_all")
    assert len(basic) < len(full)
