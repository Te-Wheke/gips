from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

from .geoip import GeoIPError, resolve_db_path, validate_geoip_backend

REQUIRED_TOOLS = {
    "mmdblookup": "mmdb-bin",
}
OPTIONAL_TOOLS = {
    "whois": "whois",
    "ping": "iputils-ping",
    "ip": "iproute2",
    "tput": "ncurses-bin",
}


@dataclass(slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


@dataclass(slots=True)
class DependencyStatus:
    name: str
    required: bool
    present: bool
    detail: str
    package: str | None = None

    @property
    def state(self) -> str:
        if self.present:
            return "ready"
        return "missing_core" if self.required else "missing_optional"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "required": self.required,
            "present": self.present,
            "detail": self.detail,
            "package": self.package,
            "state": self.state,
        }


@dataclass(slots=True)
class DependencyReport:
    statuses: list[DependencyStatus]

    @property
    def by_name(self) -> dict[str, DependencyStatus]:
        return {item.name: item for item in self.statuses}

    @property
    def core_ready(self) -> bool:
        return all(item.present for item in self.statuses if item.required)

    @property
    def optional_ready(self) -> bool:
        optional = [item for item in self.statuses if not item.required]
        return all(item.present for item in optional)

    @property
    def missing_core(self) -> list[str]:
        return [item.name for item in self.statuses if item.required and not item.present]

    @property
    def missing_optional(self) -> list[str]:
        return [item.name for item in self.statuses if not item.required and not item.present]

    def as_dict(self) -> dict[str, object]:
        return {
            "core_ready": self.core_ready,
            "optional_ready": self.optional_ready,
            "missing_core": self.missing_core,
            "missing_optional": self.missing_optional,
            "statuses": [item.as_dict() for item in self.statuses],
        }


@dataclass(slots=True)
class ProbeBundle:
    checks: list[CheckResult]
    interfaces: list[str]
    db_path: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "checks": [item.as_dict() for item in self.checks],
            "interfaces": self.interfaces,
            "db_path": self.db_path,
        }

    @property
    def by_name(self) -> dict[str, CheckResult]:
        return {item.name: item for item in self.checks}

    @property
    def network_ok(self) -> bool:
        checks = self.by_name
        return checks.get("dns", CheckResult("dns", False, "")).ok and checks.get(
            "https", CheckResult("https", False, "")
        ).ok

    @property
    def db_ok(self) -> bool:
        return self.by_name.get("geoip_db", CheckResult("geoip_db", False, "")).ok


@dataclass(slots=True)
class NetworkStatus:
    ok: bool
    detail: str


def _fixture_mode_enabled() -> bool:
    return os.environ.get("GIPS_TEST_MODE", "") == "1"


def _read_url(url: str, timeout: float = 4.0) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "gips/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(128).decode("utf-8", errors="replace").strip()
            return True, f"{response.status} {body}".strip()
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return False, str(reason)


def collect_dependency_report(db_path: str | None = None) -> DependencyReport:
    statuses: list[DependencyStatus] = []

    mmdblookup_present = shutil.which("mmdblookup") is not None
    statuses.append(
        _tool_dependency_status(
            "mmdblookup",
            required=True,
            package=REQUIRED_TOOLS["mmdblookup"],
        )
    )

    for tool_name, package_name in OPTIONAL_TOOLS.items():
        statuses.append(_tool_dependency_status(tool_name, required=False, package=package_name))

    if mmdblookup_present:
        try:
            resolved = validate_geoip_backend(db_path)
            statuses.append(
                DependencyStatus(
                    name="geoip_db",
                    required=True,
                    present=True,
                    detail=f"ready {resolved}",
                    package=None,
                )
            )
        except GeoIPError as exc:
            statuses.append(
                DependencyStatus(
                    name="geoip_db",
                    required=True,
                    present=False,
                    detail=str(exc),
                    package=None,
                )
            )
    else:
        try:
            resolved = resolve_db_path(db_path)
            detail = f"blocked by missing mmdblookup; db found at {resolved}"
        except GeoIPError as exc:
            detail = str(exc)
        statuses.append(
            DependencyStatus(
                name="geoip_db",
                required=True,
                present=False,
                detail=detail,
                package=None,
            )
        )

    return DependencyReport(statuses=statuses)


def python_runtime_report() -> dict[str, object]:
    return {
        "version": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
    }


def probe_terminal() -> CheckResult:
    term = os.environ.get("TERM", "unknown")
    color_count = 0
    if sys.stdout.isatty() and term != "dumb" and shutil.which("tput"):
        try:
            result = subprocess.run(
                ["tput", "colors"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode == 0:
            try:
                color_count = int(result.stdout.strip() or "0")
            except ValueError:
                color_count = 0

    ok = color_count > 1
    detail = f"{term} {color_count} colors" if color_count else f"{term} no-color"
    return CheckResult("terminal", ok, detail)


def probe_geoip_db(db_path: str | None = None) -> CheckResult:
    try:
        resolved = validate_geoip_backend(db_path)
    except GeoIPError as exc:
        return CheckResult("geoip_db", False, str(exc))
    return CheckResult("geoip_db", True, f"ready {resolved}")


def probe_dns() -> CheckResult:
    if _fixture_mode_enabled():
        return CheckResult("dns", True, "example.com 93.184.216.34")
    try:
        address = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)[0][4][0]
    except OSError as exc:
        return CheckResult("dns", False, str(exc))
    return CheckResult("dns", True, f"example.com {address}")


def probe_https() -> CheckResult:
    if _fixture_mode_enabled():
        return CheckResult("https", True, "example.com 200")
    ok, detail = _read_url("https://example.com")
    if not ok:
        return CheckResult("https", False, detail)
    status_code = detail.split(" ", 1)[0]
    return CheckResult("https", True, f"example.com {status_code}")


def probe_public_ip() -> CheckResult:
    if _fixture_mode_enabled():
        return CheckResult("public_ip", True, "203.0.113.10")
    last_error = "public IP lookup unavailable"
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        ok, detail = _read_url(url)
        if not ok:
            last_error = detail
            continue

        candidate = detail.split(" ", 1)[-1].strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            last_error = candidate or "invalid public IP response"
            continue

        return CheckResult("public_ip", True, candidate)

    return CheckResult("public_ip", False, last_error)


def get_local_interfaces() -> list[str]:
    if _fixture_mode_enabled():
        return ["eth0 UP 192.0.2.10/24"]
    if shutil.which("ip") is None:
        return []

    try:
        result = subprocess.run(
            ["ip", "-brief", "addr", "show", "up"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines


def run_probe_bundle(db_path: str | None = None) -> ProbeBundle:
    checks = [
        probe_terminal(),
        probe_geoip_db(db_path),
        probe_dns(),
        probe_https(),
        probe_public_ip(),
    ]
    ready_db_path = None
    for item in checks:
        if item.name == "geoip_db" and item.ok:
            ready_db_path = item.detail.split(" ", 1)[-1]
            break
    return ProbeBundle(checks=checks, interfaces=get_local_interfaces(), db_path=ready_db_path)


def quick_network_status() -> NetworkStatus:
    dns = probe_dns()
    https = probe_https()
    ok = dns.ok and https.ok
    detail = f"DNS={dns.detail} HTTPS={https.detail}"
    return NetworkStatus(ok=ok, detail=detail)


def _tool_dependency_status(name: str, *, required: bool, package: str) -> DependencyStatus:
    resolved = shutil.which(name)
    if resolved:
        detail = resolved
        present = True
    else:
        detail = f"install package {package}"
        present = False

    return DependencyStatus(
        name=name,
        required=required,
        present=present,
        detail=detail,
        package=package,
    )
