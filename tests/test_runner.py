from pathlib import Path

from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine import CheckRunner


def test_runner_generates_required_files(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    output = CheckRunner(config).run_target("example_standalone")
    expected = {
        "executive_report.html",
        "technical_report.html",
        "corrective_actions.html",
        "inventory.json",
        "evidence.json",
        "execution.log",
    }
    assert expected.issubset({path.name for path in Path(output).iterdir()})
