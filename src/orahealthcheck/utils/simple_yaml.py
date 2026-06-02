from __future__ import annotations

from typing import Any


def safe_load(text: str) -> Any:
    if hasattr(text, "read"):
        text = text.read()
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))
    value, _ = _parse_block(lines, 0, 0)
    return value


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    is_list = lines[index][1].startswith("- ")
    if is_list:
        result = []
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            item = lines[index][1][2:].strip()
            if not item:
                value, index = _parse_block(lines, index + 1, indent + 2)
                result.append(value)
            elif ":" in item and not item.startswith(('"', "'")):
                key, raw_value = item.split(":", 1)
                mapping: dict[str, Any] = {}
                if raw_value.strip():
                    mapping[key.strip()] = _scalar(raw_value.strip())
                    index += 1
                else:
                    value, index = _parse_block(lines, index + 1, indent + 2)
                    mapping[key.strip()] = value
                while index < len(lines) and lines[index][0] == indent + 2 and not lines[index][1].startswith("- "):
                    k, v = lines[index][1].split(":", 1)
                    if v.strip():
                        mapping[k.strip()] = _scalar(v.strip())
                        index += 1
                    else:
                        child, index = _parse_block(lines, index + 1, indent + 4)
                        mapping[k.strip()] = child
                result.append(mapping)
            else:
                result.append(_scalar(item))
                index += 1
        return result, index
    result: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith("- "):
        key, raw_value = lines[index][1].split(":", 1)
        if raw_value.strip():
            result[key.strip()] = _scalar(raw_value.strip())
            index += 1
        else:
            value, index = _parse_block(lines, index + 1, indent + 2)
            result[key.strip()] = value
    return result, index


def _scalar(value: str) -> Any:
    value = value.strip()
    if value in {"null", "None", "~"}:
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part.strip()) for part in inner.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
