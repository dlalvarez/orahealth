from typing import Any

SECRET_MARKERS = ("password", "passphrase", "secret", "token")


def mask_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if any(marker in k.lower() for marker in SECRET_MARKERS) else mask_secrets(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_secrets(item) for item in value]
    return value
