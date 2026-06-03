from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SimpleYAMLError(Exception):
    problem: str
    line: int | None = None
    column: int | None = None

    def __str__(self) -> str:
        location = ""
        if self.line is not None:
            location = f" at line {self.line}"
            if self.column is not None:
                location += f", column {self.column}"
        return f"{self.problem}{location}"


def safe_load(text: str) -> Any:
    if hasattr(text, "read"):
        text = text.read()
    lines = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2 != 0:
            raise SimpleYAMLError("Indentation must use multiples of two spaces", line_number, indent + 1)
        lines.append((indent, raw.strip(), line_number, indent + 1))
    value, index = _parse_block(lines, 0, 0)
    if index != len(lines):
        _, _, line, column = lines[index]
        raise SimpleYAMLError("Unexpected YAML content", line, column)
    return value


def _parse_block(lines: list[tuple[int, str, int, int]], index: int, indent: int) -> tuple[Any, int]:
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
                    mapping[key.strip()] = _scalar(raw_value.strip(), lines[index][2], lines[index][3])
                    index += 1
                else:
                    value, index = _parse_block(lines, index + 1, indent + 2)
                    mapping[key.strip()] = value
                while index < len(lines) and lines[index][0] == indent + 2 and not lines[index][1].startswith("- "):
                    if ":" not in lines[index][1]:
                        raise SimpleYAMLError("Expected key: value mapping", lines[index][2], lines[index][3])
                    k, v = lines[index][1].split(":", 1)
                    if v.strip():
                        mapping[k.strip()] = _scalar(v.strip(), lines[index][2], lines[index][3])
                        index += 1
                    else:
                        child, index = _parse_block(lines, index + 1, indent + 4)
                        mapping[k.strip()] = child
                result.append(mapping)
            else:
                result.append(_scalar(item, lines[index][2], lines[index][3]))
                index += 1
        return result, index
    result: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith("- "):
        if ":" not in lines[index][1]:
            raise SimpleYAMLError("Expected key: value mapping", lines[index][2], lines[index][3])
        key, raw_value = lines[index][1].split(":", 1)
        if raw_value.strip():
            result[key.strip()] = _scalar(raw_value.strip(), lines[index][2], lines[index][3])
            index += 1
        else:
            value, index = _parse_block(lines, index + 1, indent + 2)
            result[key.strip()] = value
    return result, index


def _scalar(value: str, line: int, column: int) -> Any:
    value = value.strip()
    if value in {"null", "None", "~"}:
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.startswith("["):
        if not value.endswith("]"):
            raise SimpleYAMLError("Unclosed inline list", line, column)
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part.strip(), line, column) for part in inner.split(",")]
    if value.endswith("]") and not value.startswith("["):
        raise SimpleYAMLError("Unexpected closing bracket", line, column)
    if (value.startswith('"') and not value.endswith('"')) or (value.startswith("'") and not value.endswith("'")):
        raise SimpleYAMLError("Unclosed quoted scalar", line, column)
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
