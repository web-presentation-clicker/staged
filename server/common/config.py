import yaml
import os

_config_path = os.getenv('SERVER_CONFIG_PATH', '/opt/staged/config.yml')


def read_config() -> dict:
    with open(_config_path) as f:
        return yaml.safe_load(f)
