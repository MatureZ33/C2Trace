from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any, Mapping


class SchemaValidationError(ValueError):
    """Raised when an in-tree v4 JSON contract is invalid."""


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "null": value is None,
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
    }.get(expected, False)


def _resolve_local_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(
            f"only local JSON Schema references are supported: {reference}"
        )
    value: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, Mapping) or token not in value:
            raise SchemaValidationError(f"unresolvable JSON Schema reference: {reference}")
        value = value[token]
    if not isinstance(value, Mapping):
        raise SchemaValidationError(f"JSON Schema reference is not an object: {reference}")
    return value


def validate_instance(
    instance: Any,
    schema: Mapping[str, Any],
    *,
    root_schema: Mapping[str, Any] | None = None,
    path: str = "$",
) -> list[str]:
    """Validate the deterministic JSON Schema subset used by Bench v4."""

    root = root_schema or schema
    current = dict(schema)
    errors: list[str] = []
    if "$ref" in current:
        try:
            referenced = _resolve_local_ref(root, str(current["$ref"]))
        except SchemaValidationError as exc:
            return [f"{path}: {exc}"]
        errors.extend(validate_instance(instance, referenced, root_schema=root, path=path))
        current.pop("$ref", None)

    if "const" in current and instance != current["const"]:
        errors.append(f"{path}: expected constant {current['const']!r}, got {instance!r}")
    if "enum" in current and instance not in current["enum"]:
        errors.append(f"{path}: value {instance!r} is not in {current['enum']!r}")

    expected_types = current.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    if isinstance(expected_types, list) and not any(
        _type_matches(instance, str(expected)) for expected in expected_types
    ):
        errors.append(
            f"{path}: expected type {expected_types!r}, got {type(instance).__name__}"
        )
        return errors

    if isinstance(instance, Mapping):
        for key in current.get("required") or []:
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        if "minProperties" in current and len(instance) < int(current["minProperties"]):
            errors.append(f"{path}: expected at least {current['minProperties']} properties")
        properties = current.get("properties") or {}
        for key, value in instance.items():
            child_path = f"{path}.{key}"
            if key in properties:
                errors.extend(
                    validate_instance(
                        value, properties[key], root_schema=root, path=child_path
                    )
                )
            elif current.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(current.get("additionalProperties"), Mapping):
                errors.extend(
                    validate_instance(
                        value,
                        current["additionalProperties"],
                        root_schema=root,
                        path=child_path,
                    )
                )

    if isinstance(instance, list):
        if len(instance) < int(current.get("minItems") or 0):
            errors.append(f"{path}: expected at least {current['minItems']} items")
        if current.get("uniqueItems"):
            encoded = [
                json.dumps(value, ensure_ascii=False, sort_keys=True) for value in instance
            ]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: array items must be unique")
        if isinstance(current.get("items"), Mapping):
            for index, value in enumerate(instance):
                errors.extend(
                    validate_instance(
                        value,
                        current["items"],
                        root_schema=root,
                        path=f"{path}[{index}]",
                    )
                )

    if isinstance(instance, str):
        if len(instance) < int(current.get("minLength") or 0):
            errors.append(f"{path}: string is shorter than {current['minLength']}")
        pattern = current.get("pattern")
        if pattern is not None and re.search(str(pattern), instance) is None:
            errors.append(f"{path}: string {instance!r} does not match {pattern!r}")
        if current.get("format") == "date-time":
            try:
                datetime.fromisoformat(instance.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: {instance!r} is not an ISO-8601 date-time")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in current and instance < current["minimum"]:
            errors.append(
                f"{path}: value {instance!r} is below minimum {current['minimum']!r}"
            )

    for child in current.get("allOf") or []:
        errors.extend(validate_instance(instance, child, root_schema=root, path=path))
    if current.get("anyOf"):
        branches = [
            validate_instance(instance, child, root_schema=root, path=path)
            for child in current["anyOf"]
        ]
        if all(branch for branch in branches):
            errors.append(f"{path}: value does not satisfy anyOf")
    if current.get("oneOf"):
        branches = [
            validate_instance(instance, child, root_schema=root, path=path)
            for child in current["oneOf"]
        ]
        if sum(not branch for branch in branches) != 1:
            errors.append(f"{path}: value must satisfy exactly one oneOf branch")
    return errors


def require_valid(instance: Any, schema: Mapping[str, Any], *, label: str = "document") -> None:
    errors = validate_instance(instance, schema)
    if errors:
        raise SchemaValidationError(f"{label} failed schema validation: " + "; ".join(errors))
