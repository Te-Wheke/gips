from __future__ import annotations

from dataclasses import dataclass
import csv
from functools import lru_cache
import io
import ipaddress
import socket
import subprocess
from typing import Iterable, Sequence

from .geoip import GeoIPError, lookup_geoip

DEFAULT_ENRICHMENTS = ("rdns", "asn", "latency")
VALID_ENRICHMENTS = ("rdns", "asn", "whois", "latency")
DEFAULT_MAX_TARGETS = 256

WHOIS_ORG_KEYS = ("orgname", "organization", "org-name", "owner", "descr")
WHOIS_NETNAME_KEYS = ("netname", "network-name", "ownerid", "originas", "origin")
WHOIS_CIDR_KEYS = ("cidr", "route", "route6")
WHOIS_RANGE_KEYS = ("netrange", "inetnum")


@dataclass(slots=True)
class LookupRow:
    requested_target: str
    target_kind: str
    ip: str
    country: str
    country_code: str
    timezone: str
    latitude: float | None
    longitude: float | None
    db_path: str
    reverse_dns: str | None = None
    asn: str | None = None
    bgp_prefix: str | None = None
    registry: str | None = None
    allocated: str | None = None
    as_name: str | None = None
    whois_org: str | None = None
    whois_netname: str | None = None
    whois_cidr: str | None = None
    whois_range: str | None = None
    latency_ms: float | None = None

    def as_dict(self, network_ok: bool, db_ok: bool) -> dict[str, object]:
        return {
            "requested_target": self.requested_target,
            "target_kind": self.target_kind,
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "timezone": self.timezone,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "reverse_dns": self.reverse_dns,
            "asn": self.asn,
            "bgp_prefix": self.bgp_prefix,
            "registry": self.registry,
            "allocated": self.allocated,
            "as_name": self.as_name,
            "whois_org": self.whois_org,
            "whois_netname": self.whois_netname,
            "whois_cidr": self.whois_cidr,
            "whois_range": self.whois_range,
            "latency_ms": self.latency_ms,
            "db_path": self.db_path,
            "db_status": "READY" if db_ok else "FAIL",
            "net_status": "UP" if network_ok else "DEGRADED",
        }


def parse_enrichments(raw_value: str | None) -> tuple[str, ...]:
    if raw_value is None or raw_value.strip() == "" or raw_value.strip().lower() == "default":
        return DEFAULT_ENRICHMENTS

    values = [item.strip().lower() for item in raw_value.split(",") if item.strip()]
    if not values:
        return DEFAULT_ENRICHMENTS
    if "none" in values:
        return ()
    if "all" in values:
        return VALID_ENRICHMENTS

    invalid = sorted({item for item in values if item not in VALID_ENRICHMENTS})
    if invalid:
        raise GeoIPError(f"Unsupported enrichment(s): {', '.join(invalid)}")

    ordered = [item for item in VALID_ENRICHMENTS if item in values]
    return tuple(ordered)


def is_supported_target(raw_value: str) -> bool:
    try:
        expand_target(raw_value, DEFAULT_MAX_TARGETS)
    except GeoIPError:
        return False
    return True


def expand_target(target: str, max_targets: int) -> tuple[str, list[str]]:
    target = target.strip()
    if not target:
        raise GeoIPError("Empty target is not valid")

    try:
        return "ip", [str(ipaddress.ip_address(target))]
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        network = None

    if network is not None:
        if isinstance(network, ipaddress.IPv4Network) and network.num_addresses > 2:
            expanded = [str(address) for address in network.hosts()]
        else:
            expanded = [str(address) for address in network]

        if len(expanded) > max_targets:
            raise GeoIPError(
                f"Target {target} expands to {len(expanded)} addresses; limit is {max_targets}"
            )
        return "cidr", expanded

    if "-" in target:
        start_raw, end_raw = [item.strip() for item in target.split("-", 1)]
        try:
            start_ip = ipaddress.ip_address(start_raw)
            end_ip = ipaddress.ip_address(end_raw)
        except ValueError as exc:
            raise GeoIPError(f"Invalid range target: {target}") from exc

        if start_ip.version != end_ip.version:
            raise GeoIPError(f"Mixed-address-family range is not supported: {target}")
        if int(start_ip) > int(end_ip):
            raise GeoIPError(f"Range start must be before range end: {target}")

        count = int(end_ip) - int(start_ip) + 1
        if count > max_targets:
            raise GeoIPError(f"Target {target} expands to {count} addresses; limit is {max_targets}")

        expanded = [str(ipaddress.ip_address(value)) for value in range(int(start_ip), int(end_ip) + 1)]
        return "range", expanded

    raise GeoIPError(f"Unsupported target format: {target}")


def load_batch_targets(source: str | None, stdin_text: str | None = None) -> list[str]:
    if source in (None, "-"):
        if stdin_text is None:
            raise GeoIPError("No batch input supplied")
        lines = stdin_text.splitlines()
    else:
        try:
            with open(source, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError as exc:
            raise GeoIPError(f"Unable to read batch source {source}: {exc}") from exc

    targets = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not targets:
        raise GeoIPError("Batch source did not contain any lookup targets")
    return targets


def collect_lookup_rows(
    targets: Sequence[str],
    db_path: str | None = None,
    enrichments: Sequence[str] = DEFAULT_ENRICHMENTS,
    max_targets: int = DEFAULT_MAX_TARGETS,
) -> list[LookupRow]:
    rows: list[LookupRow] = []
    selected = tuple(enrichments)
    for target in targets:
        target_kind, addresses = expand_target(target, max_targets)
        for ip_value in addresses:
            record = lookup_geoip(ip_value, db_path)
            row = LookupRow(
                requested_target=target,
                target_kind=target_kind,
                ip=record.ip,
                country=record.country or "unknown",
                country_code=record.country_code or "--",
                timezone=record.timezone or "unknown",
                latitude=record.latitude,
                longitude=record.longitude,
                db_path=record.db_path,
            )
            enrich_lookup_row(row, selected)
            rows.append(row)
    return rows


def render_json_payload(rows: Sequence[LookupRow], network_ok: bool, db_ok: bool) -> str:
    payload = [row.as_dict(network_ok=network_ok, db_ok=db_ok) for row in rows]
    if len(payload) == 1:
        return _json_dumps(payload[0])
    return _json_dumps(payload)


def render_jsonl_payload(rows: Sequence[LookupRow], network_ok: bool, db_ok: bool) -> str:
    return "\n".join(_json_dumps(row.as_dict(network_ok=network_ok, db_ok=db_ok)) for row in rows)


def render_csv_payload(rows: Sequence[LookupRow], network_ok: bool, db_ok: bool) -> str:
    fieldnames = [
        "requested_target",
        "target_kind",
        "ip",
        "country_code",
        "country",
        "timezone",
        "latitude",
        "longitude",
        "reverse_dns",
        "asn",
        "bgp_prefix",
        "registry",
        "allocated",
        "as_name",
        "whois_org",
        "whois_netname",
        "whois_cidr",
        "whois_range",
        "latency_ms",
        "db_path",
        "db_status",
        "net_status",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row.as_dict(network_ok=network_ok, db_ok=db_ok))
    return buffer.getvalue().strip()


def _json_dumps(payload: object) -> str:
    import json

    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def enrich_lookup_row(row: LookupRow, enrichments: Sequence[str]) -> None:
    selected = set(enrichments)
    if "rdns" in selected:
        row.reverse_dns = reverse_dns_lookup(row.ip)

    if "latency" in selected:
        row.latency_ms = latency_lookup(row.ip)

    cymru_summary: dict[str, str | None] = {}
    if "asn" in selected:
        cymru_summary = asn_lookup(row.ip)
        row.asn = cymru_summary.get("asn")
        row.bgp_prefix = cymru_summary.get("bgp_prefix")
        row.registry = cymru_summary.get("registry")
        row.allocated = cymru_summary.get("allocated")
        row.as_name = cymru_summary.get("as_name")

    if "whois" in selected:
        whois_summary = whois_lookup(row.ip)
        row.whois_org = whois_summary.get("whois_org")
        row.whois_netname = whois_summary.get("whois_netname")
        row.whois_cidr = whois_summary.get("whois_cidr")
        row.whois_range = whois_summary.get("whois_range")
        if row.asn is None:
            row.asn = whois_summary.get("asn")


@lru_cache(maxsize=1024)
def reverse_dns_lookup(ip_value: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip_value)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


@lru_cache(maxsize=1024)
def latency_lookup(ip_value: str) -> float | None:
    command = ["ping", "-n", "-c", "1", "-W", "1", ip_value]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None

    output = f"{result.stdout}\n{result.stderr}"
    for token in output.split():
        if token.startswith("time="):
            try:
                return float(token.split("=", 1)[1])
            except ValueError:
                return None
    return None


@lru_cache(maxsize=1024)
def asn_lookup(ip_value: str) -> dict[str, str | None]:
    command = ["whois", "-h", "whois.cymru.com", f" -v {ip_value}"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}

    lines = [line.strip() for line in result.stdout.splitlines() if "|" in line]
    payload_lines = [line for line in lines if not line.lower().startswith("as      |")]
    if not payload_lines:
        return {}

    parts = [item.strip() for item in payload_lines[0].split("|")]
    if len(parts) < 7:
        return {}

    return {
        "asn": parts[0] or None,
        "bgp_prefix": parts[2] or None,
        "registry": parts[4] or None,
        "allocated": parts[5] or None,
        "as_name": parts[6] or None,
    }


@lru_cache(maxsize=1024)
def whois_lookup(ip_value: str) -> dict[str, str | None]:
    command = ["whois", ip_value]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}

    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        normalized = key.strip().lower()
        value = raw_value.strip()
        if normalized not in values and value:
            values[normalized] = value

    org = _first_value(values, WHOIS_ORG_KEYS)
    netname = _first_value(values, WHOIS_NETNAME_KEYS)
    cidr = _first_value(values, WHOIS_CIDR_KEYS)
    net_range = _first_value(values, WHOIS_RANGE_KEYS)

    return {
        "whois_org": org,
        "whois_netname": netname,
        "whois_cidr": cidr,
        "whois_range": net_range,
        "asn": values.get("origin"),
    }


def _first_value(values: dict[str, str], keys: Iterable[str]) -> str | None:
    for key in keys:
        if key in values:
            return values[key]
    return None
