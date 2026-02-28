import json
import re
from pathlib import Path
from typing import Any


_IO_CONFIG_FILENAME = "io_config.json"


def _get_io_config_path() -> Path:
    return Path(__file__).resolve().parent / _IO_CONFIG_FILENAME


def load_io_config() -> dict[str, Any]:
    io_config_path = _get_io_config_path()
    with io_config_path.open("r", encoding="utf-8") as io_config_file:
        return json.load(io_config_file)


def _get_models() -> list[dict[str, Any]]:
    config = load_io_config()
    return config.get("models", [])


def _get_model_by_shortname(shortname: str) -> dict[str, Any] | None:
    for model in _get_models():
        if model.get("shortname") == shortname:
            return model
    return None


def get_hardware_profile_labels() -> list[tuple[str, str]]:
    labels = []
    for model in _get_models():
        shortname = model.get("shortname")
        if not shortname:
            continue
        platform = model.get("platform", "").strip()
        variant = model.get("variant", "").strip()
        label = f"{platform} {variant}".strip() or shortname
        labels.append((shortname, label))
    return labels


def get_hardware_profile_label(profile: str) -> str | None:
    model = _get_model_by_shortname(profile)
    if not model:
        return None
    platform = model.get("platform", "").strip()
    variant = model.get("variant", "").strip()
    return f"{platform} {variant}".strip() or profile


def get_hardware_pin_mapping(profile: str) -> dict[str, Any]:
    model = _get_model_by_shortname(profile)
    if not model:
        raise KeyError(f"Unknown hardware profile: {profile}")
    return model


def detect_runtime_profile(device_model: str) -> str | None:
    for model in _get_models():
        patterns = model.get("regex", [])
        runtime_profile = model.get("runtime_profile")
        if not runtime_profile:
            shortname = model.get("shortname", "")
            runtime_profile = shortname.lower() if shortname else None
        for pattern in patterns:
            if re.search(pattern, device_model, flags=re.IGNORECASE):
                return runtime_profile
    return None


def runtime_profile_to_hardware_profile(runtime_profile: str) -> str | None:
    for model in _get_models():
        if model.get("runtime_profile") == runtime_profile:
            return model.get("shortname")
    return None
