from orahealthcheck.config_loader import ConfigLoader, ConfigValidator


def test_example_config_is_valid():
    config = ConfigLoader("config").load_all()
    assert ConfigValidator().validate(config) == []
    assert "example_standalone" in config["targets"]
    assert "database_status" in config["checks"]
