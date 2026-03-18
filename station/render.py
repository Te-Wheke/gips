from __future__ import annotations

from rich.console import Console
from rich.text import Text

from . import FEATURES, __version__
from .diagnostics import CheckResult, DependencyReport, ProbeBundle
from .geoip import DBMetadata
from .intel import LookupRow
from .runtime import ShellUICapability

RECON_BANNER = r"""
 ____  _____ ____ ___  _   _
|  _ \| ____/ ___/ _ \| \ | |
| |_) |  _|| |  | | | |  \| |
|  _ <| |__| |__| |_| | |\  |
|_| \_\_____\____\___/|_| \_|
"""

RECON_FRAMES = (
    "[ RECON | ]",
    "[ RECON / ]",
    "[ RECON - ]",
    "[ RECON \\ ]",
)


def build_console(plain: bool = False) -> Console:
    return Console(highlight=False, no_color=plain, soft_wrap=False)


def render_banner() -> Text:
    banner = Text(RECON_BANNER.rstrip("\n"), style="bold cyan")
    banner.append("\n")
    banner.append("operator shell online", style="bold white")
    return banner


def recon_logo_frame(frame_index: int) -> str:
    return RECON_FRAMES[frame_index % len(RECON_FRAMES)]


def render_toolbar(frame_index: int, output_mode: str, enrichments: tuple[str, ...]) -> str:
    enrich_value = ",".join(enrichments) if enrichments else "none"
    return (
        "<ansimagenta><b>"
        f"{recon_logo_frame(frame_index)}"
        "</b></ansimagenta> "
        "<ansicyan>output=</ansicyan>"
        f"<ansibrightwhite>{output_mode}</ansibrightwhite> "
        "<ansicyan>enrich=</ansicyan>"
        f"<ansibrightwhite>{enrich_value}</ansibrightwhite>"
    )


def render_lookup_line(row: LookupRow, network_ok: bool, db_ok: bool) -> Text:
    line = Text()
    line.no_wrap = True
    line.append("GEO", style="bold cyan")
    line.append("[")
    line.append("OK" if db_ok else "FAIL", style="bold green" if db_ok else "bold red")
    line.append("] ")
    _append_token(line, "TARGET", row.requested_target if row.requested_target != row.ip else row.ip)
    if row.requested_target != row.ip:
        _append_token(line, "IP", row.ip)
    _append_token(line, "CC", row.country_code, "bold magenta")
    _append_token(line, "COUNTRY", _tokenize(row.country))
    _append_token(line, "TZ", row.timezone, "bold yellow")
    _append_token(line, "LAT", _format_coordinate(row.latitude), "bold green")
    _append_token(line, "LON", _format_coordinate(row.longitude), "bold green")
    if row.asn:
        _append_token(line, "ASN", row.asn)
    if row.bgp_prefix:
        _append_token(line, "PREFIX", row.bgp_prefix)
    if row.reverse_dns:
        _append_token(line, "RDNS", _tokenize(row.reverse_dns))
    if row.latency_ms is not None:
        _append_token(line, "RTT", f"{row.latency_ms:.2f}ms", "bold green")
    if row.whois_org:
        _append_token(line, "ORG", _tokenize(row.whois_org))
    if row.whois_netname:
        _append_token(line, "NETNAME", _tokenize(row.whois_netname))
    line.append("NET=", style="bold cyan")
    line.append("UP" if network_ok else "DEGRADED", style="bold green" if network_ok else "bold red")
    line.append(" ")
    line.append("DB=", style="bold cyan")
    line.append("READY" if db_ok else "FAIL", style="bold green" if db_ok else "bold red")
    return line


def render_probe_line(check: CheckResult) -> Text:
    line = Text()
    line.append("CHK", style="bold cyan")
    line.append("[")
    line.append("OK" if check.ok else "FAIL", style="bold green" if check.ok else "bold red")
    line.append("] ")
    line.append(check.name.upper(), style="bold white")
    line.append(" ")
    line.append(check.detail, style="white")
    return line


def render_probe_lines(bundle: ProbeBundle) -> list[Text]:
    return [render_probe_line(item) for item in bundle.checks]


def render_status_lines(
    bundle: ProbeBundle,
    metadata: DBMetadata | None = None,
    dependency_report: DependencyReport | None = None,
    ui_capability: ShellUICapability | None = None,
) -> list[Text]:
    checks = bundle.by_name
    summary = Text()
    summary.append("STATUS ", style="bold cyan")
    summary.append("DNS=", style="bold cyan")
    summary.append("UP" if checks.get("dns", CheckResult("dns", False, "")).ok else "DOWN", style="bold green" if checks.get("dns", CheckResult("dns", False, "")).ok else "bold red")
    summary.append(" HTTPS=", style="bold cyan")
    summary.append("UP" if checks.get("https", CheckResult("https", False, "")).ok else "DOWN", style="bold green" if checks.get("https", CheckResult("https", False, "")).ok else "bold red")
    summary.append(" DB=", style="bold cyan")
    summary.append("READY" if bundle.db_ok else "FAIL", style="bold green" if bundle.db_ok else "bold red")
    summary.append(" PUBLIC=", style="bold cyan")
    public_ip = checks.get("public_ip", CheckResult("public_ip", False, "unknown"))
    summary.append(public_ip.detail if public_ip.ok else "UNSET", style="bold white")

    lines = [summary]
    if dependency_report is not None:
        lines.extend(render_dependency_lines(dependency_report))
    if ui_capability is not None:
        lines.append(render_shell_ui_line(ui_capability))
    if metadata is not None:
        db_line = Text()
        db_line.append("DB ", style="bold cyan")
        db_line.append(metadata.database_type, style="bold white")
        db_line.append(" BUILD=", style="bold cyan")
        db_line.append(metadata.build_time, style="white")
        db_line.append(" AGE=", style="bold cyan")
        db_line.append(f"{metadata.age_days}d/{metadata.freshness}", style="bold white")
        lines.append(db_line)

    path_line = Text()
    path_line.append("DBPATH ", style="bold cyan")
    path_line.append(bundle.db_path or "unavailable", style="white")
    lines.append(path_line)

    iface_label = Text()
    iface_label.append("IFACES", style="bold cyan")
    lines.append(iface_label)

    if bundle.interfaces:
        for item in bundle.interfaces:
            iface_line = Text()
            iface_line.append(" - ", style="bold cyan")
            iface_line.append(item, style="white")
            lines.append(iface_line)
    else:
        iface_line = Text()
        iface_line.append(" - ", style="bold cyan")
        iface_line.append("no active interfaces detected", style="yellow")
        lines.append(iface_line)

    return lines


def render_version_lines(metadata: DBMetadata | None = None) -> list[Text]:
    lines: list[Text] = []

    summary = Text()
    summary.append("VERSION ", style="bold cyan")
    summary.append(__version__, style="bold white")
    summary.append(" FEATURES=", style="bold cyan")
    summary.append(",".join(FEATURES), style="white")
    lines.append(summary)

    if metadata is not None:
        db_line = Text()
        db_line.append("DB ", style="bold cyan")
        db_line.append(metadata.database_type, style="bold white")
        db_line.append(" BUILD=", style="bold cyan")
        db_line.append(metadata.build_time, style="white")
        db_line.append(" AGE=", style="bold cyan")
        db_line.append(f"{metadata.age_days}d/{metadata.freshness}", style="bold white")
        lines.append(db_line)

    return lines


def render_doctor_lines(
    dependency_report: DependencyReport,
    metadata: DBMetadata | None,
    ui_capability: ShellUICapability,
    python_runtime: dict[str, object],
) -> list[Text]:
    lines: list[Text] = []

    summary = Text()
    summary.append("DOCTOR ", style="bold cyan")
    summary.append("CORE=", style="bold cyan")
    summary.append("READY" if dependency_report.core_ready else "FAIL", style="bold green" if dependency_report.core_ready else "bold red")
    summary.append(" OPTIONAL=", style="bold cyan")
    summary.append("READY" if dependency_report.optional_ready else "DEGRADED", style="bold green" if dependency_report.optional_ready else "bold yellow")
    summary.append(" PY=", style="bold cyan")
    summary.append(str(python_runtime["version"]), style="bold white")
    lines.append(summary)

    lines.extend(render_dependency_lines(dependency_report))
    lines.append(render_shell_ui_line(ui_capability))

    if metadata is not None:
        lines.extend(render_version_lines(metadata=metadata)[1:])

    return lines


def render_shell_help() -> list[Text]:
    commands = (
        "lookup <target>",
        "batch <file>",
        "probe",
        "status",
        "doctor",
        "version",
        "set output <plain|json|jsonl|csv>",
        "set enrich <default|none|all|list>",
        "history",
        "clear",
        "help",
        "exit",
    )
    rendered: list[Text] = []
    for item in commands:
        line = Text()
        line.append("CMD ", style="bold cyan")
        line.append(item, style="bold white")
        rendered.append(line)
    return rendered


def _append_token(line: Text, label: str, value: str, value_style: str = "bold white") -> None:
    line.append(f"{label}=", style="bold cyan")
    line.append(value, style=value_style)
    line.append(" ")


def _tokenize(value: str, limit: int = 36) -> str:
    collapsed = "_".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def _format_coordinate(value: float | None) -> str:
    if value is None:
        return "na"
    return f"{value:.6f}"


def render_dependency_lines(report: DependencyReport) -> list[Text]:
    lines: list[Text] = []

    summary = Text()
    summary.append("DEPS ", style="bold cyan")
    summary.append("CORE=", style="bold cyan")
    summary.append("READY" if report.core_ready else "FAIL", style="bold green" if report.core_ready else "bold red")
    summary.append(" OPTIONAL=", style="bold cyan")
    summary.append("READY" if report.optional_ready else "DEGRADED", style="bold green" if report.optional_ready else "bold yellow")
    lines.append(summary)

    missing = report.missing_core + report.missing_optional
    if missing:
        detail = Text()
        detail.append("MISS ", style="bold cyan")
        detail.append(",".join(missing), style="yellow")
        lines.append(detail)

    return lines


def render_shell_ui_line(capability: ShellUICapability) -> Text:
    line = Text()
    line.append("SHELL ", style="bold cyan")
    line.append("MODE=", style="bold cyan")
    line.append(capability.mode.upper(), style="bold green" if capability.advanced else "bold yellow")
    line.append(" REASON=", style="bold cyan")
    line.append(capability.reason, style="white")
    return line
