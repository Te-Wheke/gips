from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

from click.testing import CliRunner

from station import __version__
from station.cli import cli
from station.diagnostics import (
    CheckResult,
    DependencyReport,
    DependencyStatus,
    ProbeBundle,
    get_local_interfaces,
    probe_dns,
    probe_https,
    probe_terminal,
)
from station.geoip import DBMetadata, GeoIPError, parse_double_value, parse_string_value, resolve_db_path
from station.intel import DEFAULT_ENRICHMENTS, LookupRow, expand_target, parse_enrichments
from station.render import recon_logo_frame
from station.runtime import (
    ShellUICapability,
    apply_env_defaults,
    detect_shell_ui_capability,
    parse_env_file,
)
from station.shell import StationShell

REPO_ROOT = Path(__file__).resolve().parents[1]


class GeoIPParsingTests(unittest.TestCase):
    def test_parse_string_value(self) -> None:
        self.assertEqual(parse_string_value('  "United States" <utf8_string>'), "United States")

    def test_parse_double_value(self) -> None:
        self.assertEqual(parse_double_value("  37.751000 <double>"), 37.751)

    def test_resolve_db_path_prefers_explicit_path(self) -> None:
        with tempfile.NamedTemporaryFile() as handle:
            self.assertEqual(resolve_db_path(handle.name), handle.name)

    def test_resolve_db_path_raises_when_missing(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch("station.geoip.DEFAULT_DB_PATHS", ("/missing/db.mmdb",)):
                with self.assertRaises(GeoIPError):
                    resolve_db_path()


class RuntimeTests(unittest.TestCase):
    def test_parse_env_file(self) -> None:
        parsed = parse_env_file(
            "# comment\nexport GIP_DB_PATH=/tmp/db.mmdb\nPROMPT_TOOLKIT_NO_CPR=1\n"
        )
        self.assertEqual(parsed["GIP_DB_PATH"], "/tmp/db.mmdb")
        self.assertEqual(parsed["PROMPT_TOOLKIT_NO_CPR"], "1")

    def test_apply_env_defaults_preserves_existing_values(self) -> None:
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write("GIP_DB_PATH=/tmp/from-file.mmdb\n")
            path = handle.name

        try:
            env = {"GIP_DB_PATH": "/tmp/from-env.mmdb"}
            apply_env_defaults(path=path, environ=env)
            self.assertEqual(env["GIP_DB_PATH"], "/tmp/from-env.mmdb")
        finally:
            os.unlink(path)

    def test_detect_shell_ui_capability_auto_fallback(self) -> None:
        capability = detect_shell_ui_capability(
            env={"TERM": "xterm-256color"},
            stdin_tty=True,
            stdout_tty=True,
            term="xterm-256color",
        )
        self.assertFalse(capability.advanced)
        self.assertEqual(capability.reason, "cpr_unverified")

    def test_detect_shell_ui_capability_supported(self) -> None:
        capability = detect_shell_ui_capability(
            env={"TERM": "xterm-256color", "VTE_VERSION": "7600"},
            stdin_tty=True,
            stdout_tty=True,
            term="xterm-256color",
        )
        self.assertTrue(capability.advanced)
        self.assertEqual(capability.reason, "supported")

    def test_package_version_matches_runtime_version(self) -> None:
        with open(REPO_ROOT / "pyproject.toml", "rb") as handle:
            payload = tomllib.load(handle)

        self.assertEqual(payload["project"]["version"], __version__)

    def test_shell_falls_back_when_prompt_toolkit_unavailable(self) -> None:
        with mock.patch("station.shell.PROMPT_TOOLKIT_AVAILABLE", False):
            shell = StationShell(plain=False)

        self.assertTrue(shell.plain)
        self.assertIsNone(shell.session)
        self.assertEqual(shell.ui_capability.reason, "prompt_toolkit_unavailable")

    def test_probe_terminal_handles_tput_failure(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch("sys.stdout.isatty", return_value=True):
                with mock.patch("station.diagnostics.shutil.which", return_value="/usr/bin/tput"):
                    with mock.patch("station.diagnostics.subprocess.run", side_effect=OSError("boom")):
                        result = probe_terminal()

        self.assertFalse(result.ok)
        self.assertIn("no-color", result.detail)

    def test_get_local_interfaces_handles_subprocess_timeout(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch("station.diagnostics.shutil.which", return_value="/usr/sbin/ip"):
                with mock.patch(
                    "station.diagnostics.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(cmd=["ip"], timeout=2),
                ):
                    self.assertEqual(get_local_interfaces(), [])

    def test_fixture_mode_uses_deterministic_network_checks(self) -> None:
        with mock.patch.dict("os.environ", {"GIPS_TEST_MODE": "1"}, clear=True):
            self.assertTrue(probe_dns().ok)
            self.assertEqual(probe_https().detail, "example.com 200")
            self.assertEqual(get_local_interfaces(), ["eth0 UP 192.0.2.10/24"])


class IntelTests(unittest.TestCase):
    def test_parse_enrichments_default(self) -> None:
        self.assertEqual(parse_enrichments("default"), DEFAULT_ENRICHMENTS)

    def test_parse_enrichments_none(self) -> None:
        self.assertEqual(parse_enrichments("none"), ())

    def test_expand_target_range(self) -> None:
        kind, values = expand_target("8.8.8.8-8.8.8.10", 8)
        self.assertEqual(kind, "range")
        self.assertEqual(values, ["8.8.8.8", "8.8.8.9", "8.8.8.10"])

    def test_expand_target_cidr_limit(self) -> None:
        with self.assertRaises(GeoIPError):
            expand_target("8.8.8.0/24", 8)

    def test_recon_logo_rotates(self) -> None:
        self.assertNotEqual(recon_logo_frame(0), recon_logo_frame(1))


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()
        self.rows = [
            LookupRow(
                requested_target="8.8.8.8",
                target_kind="ip",
                ip="8.8.8.8",
                country="United States",
                country_code="US",
                timezone="America/Chicago",
                latitude=37.751,
                longitude=-97.822,
                asn="15169",
                bgp_prefix="8.8.8.0/24",
                registry=None,
                allocated=None,
                as_name="GOOGLE",
                reverse_dns="dns.google",
                whois_org=None,
                whois_netname=None,
                whois_cidr=None,
                whois_range=None,
                latency_ms=12.3,
                db_path="/tmp/GeoLite2-City.mmdb",
            )
        ]
        self.bundle = ProbeBundle(
            checks=[
                CheckResult("terminal", True, "xterm 256 colors"),
                CheckResult("geoip_db", True, "ready /tmp/db.mmdb"),
                CheckResult("dns", True, "example.com 1.1.1.1"),
                CheckResult("https", True, "example.com 200"),
                CheckResult("public_ip", True, "1.2.3.4"),
            ],
            interfaces=["eth0 UP 127.0.0.1/24"],
            db_path="/tmp/db.mmdb",
        )
        self.metadata = DBMetadata(
            path="/tmp/db.mmdb",
            database_type="GeoLite2-City",
            build_epoch=1773737240,
            build_time="2026-03-17T08:47:20+00:00",
            file_mtime="2026-03-19T00:00:00+00:00",
            age_days=2,
            ip_version="IPv6",
            node_count=123,
            record_size_bits=28,
            languages=["en"],
        )
        self.dependencies = DependencyReport(
            statuses=[
                DependencyStatus("mmdblookup", True, True, "/usr/bin/mmdblookup", "mmdb-bin"),
                DependencyStatus("whois", False, False, "install package whois", "whois"),
                DependencyStatus("ping", False, True, "/usr/bin/ping", "iputils-ping"),
                DependencyStatus("ip", False, True, "/usr/sbin/ip", "iproute2"),
                DependencyStatus("tput", False, True, "/usr/bin/tput", "ncurses-bin"),
                DependencyStatus("geoip_db", True, True, "ready /tmp/db.mmdb", None),
            ]
        )
        self.ui_capability = ShellUICapability(False, "cpr_unverified")

    def test_lookup_default_dispatch_single_line_output(self) -> None:
        with mock.patch("station.cli.collect_lookup_rows", return_value=self.rows):
            with mock.patch(
                "station.cli.quick_network_status",
                return_value=mock.Mock(ok=True, detail="DNS=ok HTTPS=ok"),
            ):
                result = self.runner.invoke(cli, ["--plain", "8.8.8.8"])

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("\n"), 1)
        self.assertIn("TARGET=8.8.8.8", result.output)
        self.assertIn("ASN=15169", result.output)

    def test_lookup_json_output(self) -> None:
        with mock.patch("station.cli.collect_lookup_rows", return_value=self.rows):
            with mock.patch(
                "station.cli.quick_network_status",
                return_value=mock.Mock(ok=False, detail="DNS=down HTTPS=down"),
            ):
                result = self.runner.invoke(cli, ["lookup", "--json", "8.8.8.8"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["ip"], "8.8.8.8")
        self.assertEqual(payload["db_status"], "READY")
        self.assertEqual(payload["net_status"], "DEGRADED")

    def test_batch_jsonl_output(self) -> None:
        with mock.patch("station.cli.collect_lookup_rows", return_value=self.rows):
            with mock.patch(
                "station.cli.quick_network_status",
                return_value=mock.Mock(ok=True, detail="DNS=ok HTTPS=ok"),
            ):
                result = self.runner.invoke(cli, ["batch", "-", "--jsonl"], input="8.8.8.8\n")

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["requested_target"], "8.8.8.8")

    def test_doctor_json_output_and_exit_code(self) -> None:
        with mock.patch("station.cli.collect_dependency_report", return_value=self.dependencies):
            with mock.patch("station.cli.read_db_metadata", return_value=self.metadata):
                with mock.patch("station.cli.detect_shell_ui_capability", return_value=self.ui_capability):
                    result = self.runner.invoke(cli, ["doctor", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["version"], __version__)
        self.assertFalse(payload["dependencies"]["optional_ready"])
        self.assertEqual(payload["shell_ui"]["reason"], "cpr_unverified")

    def test_doctor_fails_when_core_missing(self) -> None:
        dependencies = DependencyReport(
            statuses=[
                DependencyStatus("mmdblookup", True, False, "install package mmdb-bin", "mmdb-bin"),
                DependencyStatus("geoip_db", True, False, "GeoIP database not found", None),
            ]
        )
        with mock.patch("station.cli.collect_dependency_report", return_value=dependencies):
            with mock.patch("station.cli.detect_shell_ui_capability", return_value=self.ui_capability):
                result = self.runner.invoke(cli, ["doctor", "--json"])

        self.assertEqual(result.exit_code, 1, result.output)
        payload = json.loads(result.output)
        self.assertFalse(payload["dependencies"]["core_ready"])

    def test_version_json_output(self) -> None:
        with mock.patch("station.cli.read_db_metadata", return_value=self.metadata):
            result = self.runner.invoke(cli, ["version", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["db_metadata"]["database_type"], "GeoLite2-City")

    def test_status_json_output(self) -> None:
        with mock.patch("station.cli.run_probe_bundle", return_value=self.bundle):
            with mock.patch("station.cli.collect_dependency_report", return_value=self.dependencies):
                with mock.patch("station.cli.read_db_metadata", return_value=self.metadata):
                    with mock.patch("station.cli.detect_shell_ui_capability", return_value=self.ui_capability):
                        result = self.runner.invoke(cli, ["status", "--json"])

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["probe"]["db_path"], "/tmp/db.mmdb")
        self.assertEqual(payload["db_metadata"]["age_days"], 2)
        self.assertIn("whois", payload["dependencies"]["missing_optional"])

    def test_lookup_failure_is_actionable(self) -> None:
        with mock.patch("station.cli.collect_lookup_rows", side_effect=GeoIPError("Invalid IP address: nope")):
            result = self.runner.invoke(cli, ["lookup", "nope"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid IP address: nope", result.output)


if __name__ == "__main__":
    unittest.main()
