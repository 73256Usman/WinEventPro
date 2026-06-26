"""
WinEvent Pro — Settings
Stores and loads user configuration from the home directory.
No settings are ever hardcoded or bundled with the application.
"""

import json
import os
from typing import List

# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), "wineventpro_settings.json")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    # Which event log channels to monitor
    "channels": ["Security", "System", "Application"],

    # How many hours back a historical scan covers by default
    "hours_back": 24,

    # How often the live monitor polls for new events (seconds)
    "poll_interval": 4.0,

    # How many failed logons within the window triggers a brute force alert
    "brute_force_threshold": 5,

    # The rolling window for brute force detection (seconds)
    "brute_force_window": 120,

    # Maximum events to read per channel in a historical scan
    "max_events": 2000,

    # Where PDF reports are saved (empty string means Desktop)
    "report_output_dir": "",

    # Whether to start live monitoring automatically on launch
    "auto_start_live": True,

    # Whether to display timestamps in 24-hour format (True) or 12-hour AM/PM (False)
    "time_format_24h": True,
}


# ---------------------------------------------------------------------------
# Settings class
# ---------------------------------------------------------------------------

class Settings:
    """
    Thin wrapper around a JSON file in the user's home directory.
    Missing keys fall back to DEFAULTS so the app works on first run
    with no settings file present.
    """

    def __init__(self, path: str = SETTINGS_PATH):
        self.path = path
        self._data: dict = {}
        self.load()

    # ── Persistence ─────────────────────────────────────────────────────────

    def load(self):
        """Load settings from disk. Missing keys are filled from DEFAULTS."""
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                # Merge saved values over defaults so new keys always exist
                self._data = {**DEFAULTS, **saved}
            except (json.JSONDecodeError, OSError):
                self._data = dict(DEFAULTS)
        else:
            self._data = dict(DEFAULTS)

    def save(self):
        """Write current settings to disk."""
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except OSError as e:
            raise RuntimeError(f"Could not save settings to {self.path}: {e}")

    def reset(self):
        """Restore all settings to their default values and save."""
        self._data = dict(DEFAULTS)
        self.save()

    # ── Accessors ───────────────────────────────────────────────────────────

    def get(self, key: str):
        return self._data.get(key, DEFAULTS.get(key))

    def set(self, key: str, value):
        self._data[key] = value

    # ── Typed properties ────────────────────────────────────────────────────

    @property
    def channels(self) -> List[str]:
        return self._data.get("channels", DEFAULTS["channels"])

    @channels.setter
    def channels(self, value: List[str]):
        self._data["channels"] = value

    @property
    def hours_back(self) -> int:
        return int(self._data.get("hours_back", DEFAULTS["hours_back"]))

    @hours_back.setter
    def hours_back(self, value: int):
        self._data["hours_back"] = int(value)

    @property
    def poll_interval(self) -> float:
        return float(self._data.get("poll_interval", DEFAULTS["poll_interval"]))

    @poll_interval.setter
    def poll_interval(self, value: float):
        self._data["poll_interval"] = float(value)

    @property
    def brute_force_threshold(self) -> int:
        return int(self._data.get("brute_force_threshold", DEFAULTS["brute_force_threshold"]))

    @brute_force_threshold.setter
    def brute_force_threshold(self, value: int):
        self._data["brute_force_threshold"] = int(value)

    @property
    def brute_force_window(self) -> int:
        return int(self._data.get("brute_force_window", DEFAULTS["brute_force_window"]))

    @brute_force_window.setter
    def brute_force_window(self, value: int):
        self._data["brute_force_window"] = int(value)

    @property
    def max_events(self) -> int:
        return int(self._data.get("max_events", DEFAULTS["max_events"]))

    @max_events.setter
    def max_events(self, value: int):
        self._data["max_events"] = int(value)

    @property
    def report_output_dir(self) -> str:
        val = self._data.get("report_output_dir", "")
        if not val:
            return os.path.join(os.path.expanduser("~"), "Desktop")
        return val

    @report_output_dir.setter
    def report_output_dir(self, value: str):
        self._data["report_output_dir"] = value

    @property
    def auto_start_live(self) -> bool:
        return bool(self._data.get("auto_start_live", DEFAULTS["auto_start_live"]))

    @auto_start_live.setter
    def auto_start_live(self, value: bool):
        self._data["auto_start_live"] = bool(value)

    @property
    def time_format_24h(self) -> bool:
        return bool(self._data.get("time_format_24h", DEFAULTS["time_format_24h"]))

    @time_format_24h.setter
    def time_format_24h(self, value: bool):
        self._data["time_format_24h"] = bool(value)