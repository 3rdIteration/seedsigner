import re
from typing import Any


# Hardware IO mapping source of truth.
#
# Luckfox profiles include inline comments with header-pin references (where known)
# and a simple GPIO-bank notation based on gpiochip index:
#   gpiochip0 -> bank A, gpiochip1 -> bank B, gpiochip2 -> bank C,
#   gpiochip3 -> bank D, gpiochip4 -> bank E.
IO_CONFIG: dict[str, list[dict[str, Any]]] = {
    "models": [
        {
            "platform": "Raspberry Pi",
            "variant": "40-pin",
            "shortname": "RPI_40",
            "runtime_profile": "rpi_40",
            "regex": [
                r"raspberry pi model b plus rev 1\.[0-9]+",
                r"raspberry pi model a plus rev 1\.[0-9]+",
                r"raspberry pi 2 model b rev 1\.[0-9]+",
                r"raspberry pi 3 model b rev 1\.[0-9]+",
                r"raspberry pi 3 model b plus rev 1\.[0-9]+",
                r"raspberry pi 3 model a plus rev 1\.[0-9]+",
                r"raspberry pi 4 model b rev 1\.[0-9]+",
                r"raspberry pi 5 model b rev 1\.[0-9]+",
                r"raspberry pi zero rev 1\.[0-9]+",
                r"raspberry pi zero w rev 1\.[0-9]+",
                r"raspberry pi zero 2 w rev 1\.[0-9]+",
                r"raspberry pi 400 rev 1\.[0-9]+",
            ],
            "display": {
                "dc": ["/dev/gpiochip0", 25],
                "rst": ["/dev/gpiochip0", 27],
                "bl": ["/dev/gpiochip0", 24],
                "spi_bus": 0,
                "spi_device": 0,
            },
            "buttons": {
                "KEY_UP": ["/dev/gpiochip0", 6, "pull_up"],
                "KEY_DOWN": ["/dev/gpiochip0", 19, "pull_up"],
                "KEY_LEFT": ["/dev/gpiochip0", 5, "pull_up"],
                "KEY_RIGHT": ["/dev/gpiochip0", 26, "pull_up"],
                "KEY_PRESS": ["/dev/gpiochip0", 13, "pull_up"],
                "KEY1": ["/dev/gpiochip0", 21, "pull_up"],
                "KEY2": ["/dev/gpiochip0", 20, "pull_up"],
                "KEY3": ["/dev/gpiochip0", 16, "pull_up"],
            },
            "camera": {
                "device": "/dev/video0",
                "resolution": [1280, 720],
                "pixelformat": "YUYV",
                "framerate": 4,
            },
        },
        {
            "platform": "Raspberry Pi",
            "variant": "26-pin",
            "shortname": "RPI_26",
            "runtime_profile": "rpi_26",
            "regex": [
                r"raspberry pi model b rev 1\.[0-9]+",
                r"raspberry pi model a rev 1\.[0-9]+",
            ],
            "display": {
                "dc": ["/dev/gpiochip0", 25],
                "rst": ["/dev/gpiochip0", 27],
                "bl": ["/dev/gpiochip0", 24],
                "spi_bus": 0,
                "spi_device": 0,
            },
            "buttons": {
                "KEY_UP": ["/dev/gpiochip0", 3, "pull_up"],
                "KEY_DOWN": ["/dev/gpiochip0", 17, "pull_up"],
                "KEY_LEFT": ["/dev/gpiochip0", 2, "pull_up"],
                "KEY_RIGHT": ["/dev/gpiochip0", 22, "pull_up"],
                "KEY_PRESS": ["/dev/gpiochip0", 4, "pull_up"],
                "KEY1": ["/dev/gpiochip0", 23, "pull_up"],
                "KEY2": ["/dev/gpiochip0", 18, "pull_up"],
                "KEY3": ["/dev/gpiochip0", 14, "pull_up"],
            },
            "camera": {
                "device": "/dev/video0",
                "resolution": [1280, 720],
                "pixelformat": "YUYV",
                "framerate": 4,
            },
        },
        {
            "platform": "Luckfox Pico",
            "variant": "22-pin",
            "shortname": "FOX_22",
            "runtime_profile": "luckfox_22",
            "regex": ["luckfox pico mini"],
            "display": {
                "dc": ["/dev/gpiochip1", 20],  # bank B, line 20
                "rst": ["/dev/gpiochip1", 19],  # bank B, line 19
                "bl": ["/dev/gpiochip1", 11],  # bank B, line 11
                "spi_bus": 0,
                "spi_device": 0,
            },
            "buttons": {
                "KEY_UP": ["/dev/gpiochip1", 25],  # bank B, line 25
                "KEY_DOWN": ["/dev/gpiochip1", 27],  # bank B, line 27
                "KEY_LEFT": ["/dev/gpiochip1", 24],  # bank B, line 24
                "KEY_RIGHT": ["/dev/gpiochip1", 22],  # bank B, line 22
                "KEY_PRESS": ["/dev/gpiochip1", 26],  # bank B, line 26
                "KEY1": ["/dev/gpiochip1", 23],  # bank B, line 23
                "KEY2": ["/dev/gpiochip0", 4],  # bank A, line 4
                "KEY3": ["/dev/gpiochip1", 21],  # bank B, line 21
            },
            "camera": {
                "device": "/dev/video12",
                "resolution": [800, 600],
                "pixelformat": "GREY",
                "framerate": 6,
            },
        },
        {
            "platform": "Luckfox Pico",
            "variant": "40-pin",
            "shortname": "FOX_40",
            "runtime_profile": "luckfox_40",
            "regex": ["luckfox pico pro max"],
            "display": {
                "dc": ["/dev/gpiochip1", 24],  # bank B, line 24
                "rst": ["/dev/gpiochip1", 25],  # bank B, line 25
                "bl": ["/dev/gpiochip2", 8],  # bank C, line 8
                "spi_bus": 0,
                "spi_device": 0,
            },
            "buttons": {
                "KEY_UP": [58],  # global line 58
                "KEY_DOWN": [53],  # global line 53
                "KEY_LEFT": [59],  # global line 59
                "KEY_RIGHT": [54],  # global line 54
                "KEY_PRESS": [52],  # global line 52
                "KEY1": [55],  # global line 55
                "KEY2": [43],  # global line 43
                "KEY3": [42],  # global line 42
            },
            "camera": {
                "device": "/dev/video12",
                "resolution": [800, 600],
                "pixelformat": "GREY",
                "framerate": 6,
            },
        },
        {
            "platform": "Luckfox Pico",
            "variant": "Pi",
            "shortname": "FOX_PI",
            "runtime_profile": "luckfox_pi",
            "regex": ["luckfox pico pi"],
            "display": {
                "dc": ["/dev/gpiochip1", 27],  # pin 22, bank B, line 27
                "rst": ["/dev/gpiochip1", 24],  # pin 13, bank B, line 24
                "bl": ["/dev/gpiochip2", 6],  # pin 18, bank C, line 6
                "spi_bus": 0,
                "spi_device": 0,
            },
            "buttons": {
                "KEY_UP": ["/dev/gpiochip3", 26, "pull_up"],  # pin 31, bank D, line 26
                "KEY_DOWN": ["/dev/gpiochip1", 20, "pull_up"],  # pin 35, bank B, line 20
                "KEY_LEFT": ["/dev/gpiochip0", 1, "pull_up"],  # pin 29, bank A, line 1
                "KEY_RIGHT": ["/dev/gpiochip3", 25, "pull_up"],  # pin 37, bank D, line 25
                "KEY_PRESS": ["/dev/gpiochip0", 0, "pull_up"],  # pin 33, bank A, line 0
                "KEY1": ["/dev/gpiochip4", 17, "pull_up"],  # pin 40, bank E, line 17
                "KEY2": ["/dev/gpiochip3", 27, "pull_up"],  # pin 38, bank D, line 27
                "KEY3": ["/dev/gpiochip1", 23, "pull_up"],  # pin 36, bank B, line 23
            },
            "camera": {
                "device": "/dev/video12",
                "resolution": [800, 600],
                "pixelformat": "GREY",
                "framerate": 6,
            },
        },
    ]
}


def load_io_config() -> dict[str, Any]:
    return IO_CONFIG


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
