from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shlex
import sys

DEFAULT_ENV_FILE = "/etc/default/gips"
ADVANCED_UI_ENV_MARKERS = (
    "TERM_PROGRAM",
    "VTE_VERSION",
    "KONSOLE_VERSION",
    "KITTY_WINDOW_ID",
    "WT_SESSION",
    "TMUX",
)
ENV_ASSIGNMENT_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


@dataclass(slots=True)
class ShellUICapability:
    advanced: bool
    reason: str

    @property
    def mode(self) -> str:
        return "advanced" if self.advanced else "plain"

    def as_dict(self) -> dict[str, object]:
        return {"advanced": self.advanced, "mode": self.mode, "reason": self.reason}


def parse_env_file(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = ENV_ASSIGNMENT_RE.match(line)
        if not match:
            continue

        key = match.group(1)
        raw_value = match.group(2).strip()
        if raw_value == "":
            values[key] = ""
            continue

        try:
            parsed = shlex.split(raw_value, posix=True)
        except ValueError:
            values[key] = raw_value
            continue

        if not parsed:
            values[key] = ""
        elif len(parsed) == 1:
            values[key] = parsed[0]
        else:
            values[key] = " ".join(parsed)
    return values


def load_env_file(path: str = DEFAULT_ENV_FILE) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_env_file(handle.read())
    except FileNotFoundError:
        return {}


def apply_env_defaults(path: str = DEFAULT_ENV_FILE, environ: dict[str, str] | None = None) -> dict[str, str]:
    target = os.environ if environ is None else environ
    loaded = load_env_file(path)
    for key, value in loaded.items():
        target.setdefault(key, value)
    return loaded


def detect_shell_ui_capability(
    *,
    env: dict[str, str] | None = None,
    stdin_tty: bool | None = None,
    stdout_tty: bool | None = None,
    term: str | None = None,
) -> ShellUICapability:
    source_env = os.environ if env is None else env
    stdin_is_tty = sys.stdin.isatty() if stdin_tty is None else stdin_tty
    stdout_is_tty = sys.stdout.isatty() if stdout_tty is None else stdout_tty
    current_term = source_env.get("TERM", "unknown") if term is None else term

    if source_env.get("GIPS_PLAIN_UI", "") == "1":
        return ShellUICapability(False, "forced_plain")
    if source_env.get("PROMPT_TOOLKIT_NO_CPR", "") == "1":
        return ShellUICapability(False, "cpr_disabled")
    if not stdin_is_tty or not stdout_is_tty:
        return ShellUICapability(False, "non_tty")
    if current_term in {"", "dumb", "unknown"}:
        return ShellUICapability(False, "limited_terminal")
    if not any(marker in source_env for marker in ADVANCED_UI_ENV_MARKERS):
        return ShellUICapability(False, "cpr_unverified")
    return ShellUICapability(True, "supported")


def apply_shell_ui_defaults(
    capability: ShellUICapability,
    environ: dict[str, str] | None = None,
) -> None:
    target = os.environ if environ is None else environ
    if not capability.advanced:
        target.setdefault("PROMPT_TOOLKIT_NO_CPR", "1")
