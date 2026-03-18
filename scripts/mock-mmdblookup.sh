#!/usr/bin/env bash
set -euo pipefail

db_file=""
ip_value=""
verbose=0
keys=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)
      db_file="${2:-}"
      shift 2
      ;;
    --ip)
      ip_value="${2:-}"
      shift 2
      ;;
    --verbose)
      verbose=1
      shift
      ;;
    *)
      keys+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$db_file" || -z "$ip_value" ]]; then
  printf 'mock-mmdblookup requires --file and --ip\n' >&2
  exit 1
fi

if [[ ! -r "$db_file" ]]; then
  printf 'mock-mmdblookup database is not readable: %s\n' "$db_file" >&2
  exit 1
fi

case "${keys[*]}" in
  "country names en")
    value='"United States" <utf8_string>'
    ;;
  "country iso_code")
    value='"US" <utf8_string>'
    ;;
  "location time_zone")
    value='"America/Chicago" <utf8_string>'
    ;;
  "location latitude")
    value='37.751000 <double>'
    ;;
  "location longitude")
    value='-97.822000 <double>'
    ;;
  *)
    printf 'mock-mmdblookup does not support key path: %s\n' "${keys[*]}" >&2
    exit 1
    ;;
esac

if [[ "$verbose" -eq 1 ]]; then
  cat <<EOF
  Node count: 123
  Record size: 28 bits
  IP version: IPv6
  Type: GeoLite2-City
  Build epoch: 1773737240
  Languages: en
Record prefix length: 24
  $value
EOF
else
  printf '  %s\n' "$value"
fi

