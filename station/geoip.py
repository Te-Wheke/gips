from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
import re
import shutil
import subprocess

DEFAULT_DB_PATHS = (
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
)

STRING_RE = re.compile(r'"([^"]+)"\s*<utf8_string>')
DOUBLE_RE = re.compile(r"([-+]?\d+(?:\.\d+)?)\s*<double>")
METADATA_INTEGER_RE = re.compile(r"^\s*([A-Za-z ]+):\s+(\d+)(?:\s+\(([^)]+)\))?\s*$")
METADATA_STRING_RE = re.compile(r"^\s*([A-Za-z ]+):\s+(.+?)\s*$")


class GeoIPError(RuntimeError):
    """Raised when GeoIP lookup prerequisites or parsing fail."""


@dataclass(slots=True)
class GeoRecord:
    ip: str
    country: str | None
    country_code: str | None
    timezone: str | None
    latitude: float | None
    longitude: float | None
    db_path: str

    def as_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "timezone": self.timezone,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "db_path": self.db_path,
        }


@dataclass(slots=True)
class DBMetadata:
    path: str
    database_type: str
    build_epoch: int
    build_time: str
    file_mtime: str
    age_days: int
    ip_version: str
    node_count: int
    record_size_bits: int
    languages: list[str]

    @property
    def freshness(self) -> str:
        if self.age_days <= 7:
            return "fresh"
        if self.age_days <= 30:
            return "aging"
        return "stale"

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "database_type": self.database_type,
            "build_epoch": self.build_epoch,
            "build_time": self.build_time,
            "file_mtime": self.file_mtime,
            "age_days": self.age_days,
            "freshness": self.freshness,
            "ip_version": self.ip_version,
            "node_count": self.node_count,
            "record_size_bits": self.record_size_bits,
            "languages": self.languages,
        }


def resolve_db_path(explicit_path: str | None = None) -> str:
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)

    env_path = os.environ.get("GIP_DB_PATH")
    if env_path and env_path not in candidates:
        candidates.append(env_path)

    for path in DEFAULT_DB_PATHS:
        if path not in candidates:
            candidates.append(path)

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path

    checked = ", ".join(candidates) or "<none>"
    raise GeoIPError(f"GeoIP database not found or unreadable. Checked: {checked}")


def validate_ip(ip_value: str) -> str:
    try:
        return str(ipaddress.ip_address(ip_value))
    except ValueError as exc:
        raise GeoIPError(f"Invalid IP address: {ip_value}") from exc


def parse_string_value(raw_output: str) -> str:
    match = STRING_RE.search(raw_output)
    if not match:
        raise GeoIPError(f"Unable to parse string value from mmdblookup output: {raw_output!r}")
    return match.group(1).strip()


def parse_double_value(raw_output: str) -> float:
    match = DOUBLE_RE.search(raw_output)
    if not match:
        raise GeoIPError(f"Unable to parse numeric value from mmdblookup output: {raw_output!r}")
    return float(match.group(1))


def run_mmdblookup(db_path: str, ip_value: str, *keys: str, verbose: bool = False) -> str:
    if shutil.which("mmdblookup") is None:
        raise GeoIPError("mmdblookup is not installed or not available in PATH")

    command = ["mmdblookup"]
    if verbose:
        command.append("--verbose")
    command.extend(["--file", db_path, "--ip", ip_value, *keys])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    output = result.stdout.strip()
    if result.returncode != 0 or not output:
        message = result.stderr.strip() or output or "mmdblookup returned no data"
        raise GeoIPError(message)
    return output


def validate_geoip_backend(explicit_path: str | None = None) -> str:
    db_path = resolve_db_path(explicit_path)
    validated_ip = validate_ip("8.8.8.8")
    run_mmdblookup(db_path, validated_ip, "location", "latitude")
    return db_path


def read_db_metadata(db_path: str | None = None) -> DBMetadata:
    resolved_db_path = resolve_db_path(db_path)
    raw_output = run_mmdblookup(
        resolved_db_path,
        validate_ip("8.8.8.8"),
        "location",
        "latitude",
        verbose=True,
    )
    metadata_block = raw_output.split("Record prefix length:", 1)[0]

    values: dict[str, str] = {}
    for line in metadata_block.splitlines():
        match = METADATA_INTEGER_RE.match(line)
        if match:
            key = match.group(1).strip().lower().replace(" ", "_")
            values[key] = match.group(2)
            if match.group(3):
                values[f"{key}_display"] = match.group(3)
            continue

        match = METADATA_STRING_RE.match(line)
        if match:
            key = match.group(1).strip().lower().replace(" ", "_")
            values[key] = match.group(2).strip()

    build_epoch = int(values.get("build_epoch", "0"))
    if build_epoch <= 0:
        raise GeoIPError("Unable to read GeoIP database metadata")

    stat_result = os.stat(resolved_db_path)
    build_time = datetime.fromtimestamp(build_epoch, tz=timezone.utc)
    file_mtime = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
    age_days = max(0, int((datetime.now(timezone.utc) - build_time).total_seconds() // 86400))

    return DBMetadata(
        path=resolved_db_path,
        database_type=values.get("type", "unknown"),
        build_epoch=build_epoch,
        build_time=build_time.isoformat(),
        file_mtime=file_mtime.isoformat(),
        age_days=age_days,
        ip_version=values.get("ip_version", "unknown"),
        node_count=int(values.get("node_count", "0")),
        record_size_bits=_leading_int(values.get("record_size", "0")),
        languages=values.get("languages", "").split(),
    )


def lookup_geoip(ip_value: str, db_path: str | None = None) -> GeoRecord:
    resolved_ip = validate_ip(ip_value)
    resolved_db_path = resolve_db_path(db_path)

    country = _optional_string_lookup(resolved_db_path, resolved_ip, "country", "names", "en")
    country_code = _optional_string_lookup(resolved_db_path, resolved_ip, "country", "iso_code")
    timezone = _optional_string_lookup(resolved_db_path, resolved_ip, "location", "time_zone")
    latitude = _optional_double_lookup(resolved_db_path, resolved_ip, "location", "latitude")
    longitude = _optional_double_lookup(resolved_db_path, resolved_ip, "location", "longitude")

    return GeoRecord(
        ip=resolved_ip,
        country=country,
        country_code=country_code,
        timezone=timezone,
        latitude=latitude,
        longitude=longitude,
        db_path=resolved_db_path,
    )


def _leading_int(raw_value: str) -> int:
    match = re.search(r"\d+", raw_value)
    if not match:
        return 0
    return int(match.group(0))


def _optional_string_lookup(db_path: str, ip_value: str, *keys: str) -> str | None:
    try:
        return parse_string_value(run_mmdblookup(db_path, ip_value, *keys))
    except GeoIPError:
        return None


def _optional_double_lookup(db_path: str, ip_value: str, *keys: str) -> float | None:
    try:
        return parse_double_value(run_mmdblookup(db_path, ip_value, *keys))
    except GeoIPError:
        return None
