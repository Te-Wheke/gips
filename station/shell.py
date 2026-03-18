from __future__ import annotations

import json
import shlex
import time

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import InMemoryHistory

    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PromptSession = None
    WordCompleter = None
    HTML = None
    InMemoryHistory = None
    PROMPT_TOOLKIT_AVAILABLE = False

from . import FEATURES, __version__
from .diagnostics import (
    DependencyReport,
    ProbeBundle,
    collect_dependency_report,
    python_runtime_report,
    quick_network_status,
    run_probe_bundle,
)
from .geoip import GeoIPError, read_db_metadata
from .intel import (
    DEFAULT_ENRICHMENTS,
    collect_lookup_rows,
    is_supported_target,
    load_batch_targets,
    parse_enrichments,
    render_csv_payload,
    render_json_payload,
    render_jsonl_payload,
)
from .render import (
    build_console,
    render_banner,
    render_dependency_lines,
    render_doctor_lines,
    render_lookup_line,
    render_probe_lines,
    render_shell_help,
    render_status_lines,
    render_toolbar,
    render_version_lines,
)
from .runtime import (
    ShellUICapability,
    apply_shell_ui_defaults,
    detect_shell_ui_capability,
)


class StationShell:
    def __init__(self, db_path: str | None = None, plain: bool = False) -> None:
        self.db_path = db_path
        if plain:
            self.ui_capability = ShellUICapability(False, "plain_flag")
        elif not PROMPT_TOOLKIT_AVAILABLE:
            self.ui_capability = ShellUICapability(False, "prompt_toolkit_unavailable")
        else:
            self.ui_capability = detect_shell_ui_capability()
        apply_shell_ui_defaults(self.ui_capability)
        self.plain = plain or not self.ui_capability.advanced
        self.console = build_console(plain=self.plain)
        self.output_mode = "plain"
        self.enrichments = DEFAULT_ENRICHMENTS
        self.history_entries: list[str] = []
        self.start_time = time.monotonic()
        self.session = self._build_session()
        self.last_probe: ProbeBundle | None = None
        self.last_dependencies: DependencyReport | None = None

    def boot(self) -> None:
        if self.console.is_terminal:
            self.console.print(render_banner())

        self.last_probe = run_probe_bundle(self.db_path)
        self.last_dependencies = collect_dependency_report(self.db_path)
        for line in render_probe_lines(self.last_probe):
            self.console.print(line)
        for line in render_dependency_lines(self.last_dependencies):
            self.console.print(line)
        self.console.print(
            f"SHELL MODE={self.ui_capability.mode.upper()} REASON={self.ui_capability.reason}",
            style="bold cyan",
        )

    def run(self) -> int:
        self.boot()
        for line in render_shell_help():
            self.console.print(line)

        prompt_markup = (
            "gips> "
            if self.plain or HTML is None
            else HTML("<ansicyan><b>gips</b></ansicyan><ansibrightblack>> </ansibrightblack>")
        )
        prompt_text = "gips> "
        while True:
            try:
                raw_command = self._prompt(prompt_markup, prompt_text)
            except KeyboardInterrupt:
                self.console.print("CTRL-C ignored; use exit to leave.", style="yellow")
                continue
            except EOFError:
                self.console.print("session closed", style="yellow")
                return 0

            if not raw_command.strip():
                continue

            self.history_entries.append(raw_command.strip())
            try:
                should_exit = self.execute(raw_command)
            except GeoIPError as exc:
                self.console.print(f"ERR {exc}", style="bold red")
                continue
            except ValueError as exc:
                self.console.print(f"ERR {exc}", style="bold red")
                continue

            if should_exit:
                self.console.print("session closed", style="yellow")
                return 0

    def execute(self, raw_command: str) -> bool:
        parts = shlex.split(raw_command)
        command = parts[0]

        if command in {"exit", "quit"}:
            return True
        if command == "help":
            for line in render_shell_help():
                self.console.print(line)
            return False
        if command == "clear":
            self.console.clear()
            return False
        if command == "history":
            self._print_history()
            return False
        if command == "probe":
            self._run_probe()
            return False
        if command == "status":
            self._print_status()
            return False
        if command == "doctor":
            self._print_doctor()
            return False
        if command == "version":
            self._print_version()
            return False
        if command == "set":
            self._handle_set(parts[1:])
            return False
        if command == "batch":
            if len(parts) != 2:
                raise ValueError("usage: batch <file>")
            self._run_batch(parts[1])
            return False
        if command == "lookup":
            if len(parts) != 2:
                raise ValueError("usage: lookup <target>")
            self._run_lookup(parts[1])
            return False
        if is_supported_target(command):
            self._run_lookup(command)
            return False

        raise ValueError(f"unknown command: {command}")

    def _run_lookup(self, target: str) -> None:
        rows = collect_lookup_rows(
            [target],
            db_path=self.db_path,
            enrichments=self.enrichments,
        )
        network_ok, db_ok = self._status_flags()
        self._emit_rows(rows, network_ok=network_ok, db_ok=db_ok)

    def _run_batch(self, source: str) -> None:
        targets = load_batch_targets(source)
        rows = collect_lookup_rows(
            targets,
            db_path=self.db_path,
            enrichments=self.enrichments,
        )
        network_ok, db_ok = self._status_flags()
        self._emit_rows(rows, network_ok=network_ok, db_ok=db_ok)

    def _run_probe(self) -> None:
        self.last_probe = run_probe_bundle(self.db_path)
        self.last_dependencies = collect_dependency_report(self.db_path)
        for line in render_probe_lines(self.last_probe):
            self.console.print(line)
        for line in render_dependency_lines(self.last_dependencies):
            self.console.print(line)

    def _emit_rows(self, rows, *, network_ok: bool, db_ok: bool) -> None:
        if self.output_mode == "json":
            self.console.print(render_json_payload(rows, network_ok=network_ok, db_ok=db_ok))
            return
        if self.output_mode == "jsonl":
            self.console.print(render_jsonl_payload(rows, network_ok=network_ok, db_ok=db_ok))
            return
        if self.output_mode == "csv":
            self.console.print(render_csv_payload(rows, network_ok=network_ok, db_ok=db_ok))
            return

        for row in rows:
            self.console.print(
                render_lookup_line(row, network_ok=network_ok, db_ok=db_ok),
                no_wrap=True,
                overflow="ignore",
                crop=False,
            )

    def _handle_set(self, args: list[str]) -> None:
        if len(args) < 2:
            raise ValueError("usage: set output <mode> | set enrich <default|none|all|list>")

        key = args[0]
        value = " ".join(args[1:]).strip()
        if key == "output":
            if value not in {"plain", "json", "jsonl", "csv"}:
                raise ValueError("output mode must be one of: plain, json, jsonl, csv")
            self.output_mode = value
            self.console.print(f"OUTPUT {value}", style="bold cyan")
            return

        if key == "enrich":
            self.enrichments = parse_enrichments(value)
            display = ",".join(self.enrichments) if self.enrichments else "none"
            self.console.print(f"ENRICH {display}", style="bold cyan")
            return

        raise ValueError(f"unknown setting: {key}")

    def _print_status(self) -> None:
        bundle = self.last_probe or run_probe_bundle(self.db_path)
        dependencies = self.last_dependencies or collect_dependency_report(self.db_path)
        metadata = None
        if bundle.db_path:
            try:
                metadata = read_db_metadata(bundle.db_path)
            except GeoIPError:
                metadata = None

        for line in render_status_lines(
            bundle,
            metadata=metadata,
            dependency_report=dependencies,
            ui_capability=self.ui_capability,
        ):
            self.console.print(line)

    def _print_doctor(self) -> None:
        dependencies = collect_dependency_report(self.db_path)
        metadata = None
        if dependencies.by_name["geoip_db"].present:
            try:
                metadata = read_db_metadata(self.db_path)
            except GeoIPError:
                metadata = None

        if self.output_mode == "json":
            self.console.print(
                json.dumps(
                    {
                        "version": __version__,
                        "features": FEATURES,
                        "python": python_runtime_report(),
                        "dependencies": dependencies.as_dict(),
                        "shell_ui": self.ui_capability.as_dict(),
                        "db_metadata": metadata.as_dict() if metadata else None,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return

        for line in render_doctor_lines(
            dependency_report=dependencies,
            metadata=metadata,
            ui_capability=self.ui_capability,
            python_runtime=python_runtime_report(),
        ):
            self.console.print(line)

    def _print_version(self) -> None:
        metadata = None
        try:
            metadata = read_db_metadata(self.db_path)
        except GeoIPError:
            metadata = None

        if self.output_mode == "json":
            self.console.print(
                json.dumps(
                    {
                        "version": __version__,
                        "features": FEATURES,
                        "db_metadata": metadata.as_dict() if metadata else None,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return

        for line in render_version_lines(metadata=metadata):
            self.console.print(line)

    def _print_history(self) -> None:
        if not self.history_entries:
            self.console.print("history empty", style="yellow")
            return

        for index, command in enumerate(self.history_entries, start=1):
            self.console.print(f"{index:03d} {command}")

    def _status_flags(self) -> tuple[bool, bool]:
        if self.last_probe is not None:
            return self.last_probe.network_ok, self.last_probe.db_ok
        network_ok = quick_network_status().ok
        return network_ok, True

    def _bottom_toolbar(self):
        frame_index = int((time.monotonic() - self.start_time) * 8)
        return HTML(render_toolbar(frame_index, self.output_mode, self.enrichments))

    def _build_session(self):
        if not PROMPT_TOOLKIT_AVAILABLE:
            return None

        try:
            return PromptSession(
                completer=WordCompleter(
                    [
                        "lookup",
                        "batch",
                        "probe",
                        "status",
                        "doctor",
                        "version",
                        "set",
                        "history",
                        "clear",
                        "help",
                        "exit",
                        "quit",
                    ],
                    ignore_case=True,
                ),
                history=InMemoryHistory(),
            )
        except Exception:
            self.ui_capability = ShellUICapability(False, "prompt_session_init_failed")
            apply_shell_ui_defaults(self.ui_capability)
            self.plain = True
            self.console = build_console(plain=True)
            return None

    def _prompt(self, prompt_markup, prompt_text: str) -> str:
        if self.session is None:
            return input(prompt_text)

        return self.session.prompt(
            prompt_markup,
            refresh_interval=None if self.plain else 0.12,
            bottom_toolbar=None if self.plain else self._bottom_toolbar,
        )


def launch_shell(db_path: str | None = None, plain: bool = False) -> int:
    shell = StationShell(db_path=db_path, plain=plain)
    return shell.run()
