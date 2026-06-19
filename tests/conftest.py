import json

import pytest

from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine import CheckRunner


@pytest.fixture
def example_config(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    return config


def run_example_and_results(config):
    output = CheckRunner(config).run_target("example_standalone")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    return {result["check_id"]: result for result in evidence["results"]}
