import json
from pathlib import Path

from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine import CheckRunner


def _run_example(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    return CheckRunner(config).run_target("example_standalone")


def test_runner_generates_required_files(tmp_path):
    output = _run_example(tmp_path)
    expected = {
        "executive_report.html",
        "technical_report.html",
        "corrective_actions.html",
        "inventory.json",
        "evidence.json",
        "execution.log",
    }
    assert expected.issubset({path.name for path in Path(output).iterdir()})


def test_evidence_json_has_minimum_structure(tmp_path):
    output = _run_example(tmp_path)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))

    assert set(evidence) == {"summary", "results"}
    assert evidence["summary"]["global_status"]
    assert isinstance(evidence["summary"]["score"], int)
    assert len(evidence["results"]) == 10
    first_result = evidence["results"][0]
    assert {"check_id", "group_id", "status", "failure_severity", "evidence", "duration_ms"}.issubset(first_result)
    assert isinstance(first_result["duration_ms"], int)


def test_execution_log_contains_run_metadata(tmp_path):
    output = _run_example(tmp_path)
    log_text = (output / "execution.log").read_text(encoding="utf-8")

    assert "Target: example_standalone" in log_text
    assert "Profile: standalone_basic" in log_text
    assert "Enabled groups:" in log_text
    assert "Loaded checks (10):" in log_text
    assert "Executed checks (10):" in log_text
    assert "Skipped checks (0):" in log_text
    assert "Status summary:" in log_text
    assert f"Output directory: {output}" in log_text
    assert "Total duration_ms:" in log_text
