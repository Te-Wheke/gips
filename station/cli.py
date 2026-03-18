from __future__ import annotations

import os

import click

from . import FEATURES, __version__
from .diagnostics import (
    collect_dependency_report,
    python_runtime_report,
    quick_network_status,
    run_probe_bundle,
)
from .geoip import GeoIPError, read_db_metadata
from .intel import (
    DEFAULT_MAX_TARGETS,
    collect_lookup_rows,
    load_batch_targets,
    parse_enrichments,
    render_csv_payload,
    render_json_payload,
    render_jsonl_payload,
)
from .render import (
    build_console,
    render_dependency_lines,
    render_doctor_lines,
    render_lookup_line,
    render_probe_lines,
    render_shell_ui_line,
    render_status_lines,
    render_version_lines,
)
from .runtime import apply_env_defaults, detect_shell_ui_capability
from .shell import launch_shell

HELP_OPTION_NAMES = {"help_option_names": ["-h", "--help"]}


def _db_path_option(command):
    return click.option(
        "--db-path",
        type=click.Path(dir_okay=False, path_type=str),
        default=None,
        help="Path to a local GeoLite2 City database.",
    )(command)


def _plain_option(command):
    return click.option("--plain", is_flag=True, help="Disable ANSI color output.")(command)


def _max_targets_option(command):
    return click.option(
        "--max-targets",
        default=DEFAULT_MAX_TARGETS,
        show_default=True,
        type=click.IntRange(min=1),
        help="Maximum addresses expanded from a CIDR or range target.",
    )(command)


def _enrich_option(command):
    return click.option(
        "--enrich",
        default="default",
        show_default=True,
        help="Comma list of enrichments: default, none, all, rdns, asn, whois, latency.",
    )(command)


def _structured_output_options(command):
    command = click.option("--csv", "csv_output", is_flag=True, help="Emit CSV output.")(command)
    command = click.option(
        "--jsonl",
        "jsonl_output",
        is_flag=True,
        help="Emit newline-delimited JSON output.",
    )(command)
    command = click.option("--json", "json_output", is_flag=True, help="Emit JSON output.")(command)
    return command


class GipsGroup(click.Group):
    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and args[0] not in {"--help", "-h"}:
            args.insert(0, "lookup")
        return super().parse_args(ctx, args)


@click.group(
    cls=GipsGroup,
    context_settings=HELP_OPTION_NAMES,
    invoke_without_command=True,
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """gips operator CLI."""
    if ctx.invoked_subcommand is None:
        raise SystemExit(launch_shell())


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@_structured_output_options
@_enrich_option
@_max_targets_option
@click.argument("target")
def lookup(
    db_path: str | None,
    plain: bool,
    json_output: bool,
    jsonl_output: bool,
    csv_output: bool,
    enrich: str,
    max_targets: int,
    target: str,
) -> None:
    """Resolve an IP, CIDR, or explicit range."""
    output_mode = _resolve_output_mode(json_output=json_output, jsonl_output=jsonl_output, csv_output=csv_output)
    try:
        enrichments = parse_enrichments(enrich)
        rows = collect_lookup_rows([target], db_path=db_path, enrichments=enrichments, max_targets=max_targets)
        network = quick_network_status()
    except GeoIPError as exc:
        raise click.ClickException(str(exc)) from exc

    _emit_rows(rows, output_mode=output_mode, plain=plain, network_ok=network.ok, db_ok=True)


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@_structured_output_options
@_enrich_option
@_max_targets_option
@click.argument("source", required=False)
def batch(
    db_path: str | None,
    plain: bool,
    json_output: bool,
    jsonl_output: bool,
    csv_output: bool,
    enrich: str,
    max_targets: int,
    source: str | None,
) -> None:
    """Resolve newline-delimited targets from a file or stdin."""
    output_mode = _resolve_output_mode(json_output=json_output, jsonl_output=jsonl_output, csv_output=csv_output)
    stdin_text = None
    if source in (None, "-") and not click.get_text_stream("stdin").isatty():
        stdin_text = click.get_text_stream("stdin").read()

    try:
        targets = load_batch_targets(source, stdin_text=stdin_text)
        rows = collect_lookup_rows(
            targets,
            db_path=db_path,
            enrichments=parse_enrichments(enrich),
            max_targets=max_targets,
        )
        network = quick_network_status()
    except GeoIPError as exc:
        raise click.ClickException(str(exc)) from exc

    _emit_rows(rows, output_mode=output_mode, plain=plain, network_ok=network.ok, db_ok=True)


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@click.option("--json", "json_output", is_flag=True, help="Emit JSON output.")
def probe(db_path: str | None, plain: bool, json_output: bool) -> None:
    """Run live operator diagnostics."""
    bundle = run_probe_bundle(db_path)
    dependencies = collect_dependency_report(db_path)
    ui_capability = detect_shell_ui_capability()
    if json_output:
        import json

        payload = {
            "probe": bundle.as_dict(),
            "dependencies": dependencies.as_dict(),
            "shell_ui": ui_capability.as_dict(),
        }
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return

    console = build_console(plain=plain)
    for line in render_probe_lines(bundle):
        console.print(line)
    for line in render_dependency_lines(dependencies):
        console.print(line)
    console.print(render_shell_ui_line(ui_capability))


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@click.option("--json", "json_output", is_flag=True, help="Emit JSON output.")
def status(db_path: str | None, plain: bool, json_output: bool) -> None:
    """Show DB, network, interface, and dependency status."""
    bundle = run_probe_bundle(db_path)
    dependencies = collect_dependency_report(db_path)
    ui_capability = detect_shell_ui_capability()
    metadata = None
    if bundle.db_path:
        try:
            metadata = read_db_metadata(bundle.db_path)
        except GeoIPError:
            metadata = None

    if json_output:
        import json

        payload = {
            "version": __version__,
            "features": FEATURES,
            "probe": bundle.as_dict(),
            "dependencies": dependencies.as_dict(),
            "shell_ui": ui_capability.as_dict(),
            "db_metadata": metadata.as_dict() if metadata else None,
        }
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return

    console = build_console(plain=plain)
    for line in render_status_lines(
        bundle,
        metadata=metadata,
        dependency_report=dependencies,
        ui_capability=ui_capability,
    ):
        console.print(line)


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@click.option("--json", "json_output", is_flag=True, help="Emit JSON output.")
@click.pass_context
def doctor(ctx: click.Context, db_path: str | None, plain: bool, json_output: bool) -> None:
    """Report deployment readiness and missing prerequisites."""
    dependencies = collect_dependency_report(db_path)
    ui_capability = detect_shell_ui_capability()
    metadata = None
    if dependencies.by_name["geoip_db"].present:
        try:
            metadata = read_db_metadata(db_path)
        except GeoIPError:
            metadata = None

    if json_output:
        import json

        payload = {
            "version": __version__,
            "features": FEATURES,
            "python": python_runtime_report(),
            "dependencies": dependencies.as_dict(),
            "shell_ui": ui_capability.as_dict(),
            "db_metadata": metadata.as_dict() if metadata else None,
        }
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        ctx.exit(0 if dependencies.core_ready else 1)

    console = build_console(plain=plain)
    for line in render_doctor_lines(
        dependency_report=dependencies,
        metadata=metadata,
        ui_capability=ui_capability,
        python_runtime=python_runtime_report(),
    ):
        console.print(line)
    ctx.exit(0 if dependencies.core_ready else 1)


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
@click.option("--json", "json_output", is_flag=True, help="Emit JSON output.")
def version(db_path: str | None, plain: bool, json_output: bool) -> None:
    """Show release and database version details."""
    metadata = None
    try:
        metadata = read_db_metadata(db_path)
    except GeoIPError:
        metadata = None

    if json_output:
        import json

        payload = {
            "version": __version__,
            "features": FEATURES,
            "db_metadata": metadata.as_dict() if metadata else None,
        }
        click.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return

    console = build_console(plain=plain)
    for line in render_version_lines(metadata=metadata):
        console.print(line)


@cli.command(context_settings=HELP_OPTION_NAMES)
@_db_path_option
@_plain_option
def shell(db_path: str | None, plain: bool) -> None:
    """Launch the interactive shell UI."""
    raise SystemExit(launch_shell(db_path=db_path, plain=plain))


def _emit_rows(
    rows,
    *,
    output_mode: str,
    plain: bool,
    network_ok: bool,
    db_ok: bool,
) -> None:
    if output_mode == "json":
        click.echo(render_json_payload(rows, network_ok=network_ok, db_ok=db_ok))
        return
    if output_mode == "jsonl":
        click.echo(render_jsonl_payload(rows, network_ok=network_ok, db_ok=db_ok))
        return
    if output_mode == "csv":
        click.echo(render_csv_payload(rows, network_ok=network_ok, db_ok=db_ok))
        return

    console = build_console(plain=plain)
    for row in rows:
        console.print(
            render_lookup_line(row, network_ok=network_ok, db_ok=db_ok),
            no_wrap=True,
            overflow="ignore",
            crop=False,
        )


def _resolve_output_mode(*, json_output: bool, jsonl_output: bool, csv_output: bool) -> str:
    selected = [
        mode
        for mode, enabled in (
            ("json", json_output),
            ("jsonl", jsonl_output),
            ("csv", csv_output),
        )
        if enabled
    ]
    if len(selected) > 1:
        raise click.UsageError("Choose only one output format: --json, --jsonl, or --csv")
    return selected[0] if selected else "plain"


def main(prog_name: str | None = None) -> None:
    apply_env_defaults()
    cli(prog_name=prog_name or os.environ.get("GIPS_PROG_NAME") or "gips")


if __name__ == "__main__":
    main()
