#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/default/gips"
STANDARD_DB="/var/lib/GeoIP/GeoLite2-City.mmdb"
DB_PATH=""

usage() {
  cat <<'EOF'
Usage: bootstrap-ubuntu.sh [--db-path /path/to/GeoLite2-City.mmdb]

Installs Ubuntu/Debian prerequisites for gips, prepares /var/lib/GeoIP,
and writes /etc/default/gips when a custom database path is provided.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-path)
      DB_PATH="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run as root or with sudo: sudo %s %s\n' "$0" "${DB_PATH:+--db-path \"$DB_PATH\"}" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  python3-pip \
  python3-venv \
  mmdb-bin \
  whois \
  iputils-ping \
  iproute2 \
  ncurses-bin

install -d -m 755 /var/lib/GeoIP

if [[ -n "$DB_PATH" ]]; then
  if [[ ! -r "$DB_PATH" ]]; then
    printf 'Provided database path is not readable: %s\n' "$DB_PATH" >&2
    exit 1
  fi
fi

if [[ -z "$DB_PATH" && ! -r "$STANDARD_DB" ]]; then
  cat >&2 <<EOF
No readable GeoIP database was found at:
  $STANDARD_DB

Provide an existing database path:
  sudo $0 --db-path /path/to/GeoLite2-City.mmdb
EOF
  exit 1
fi

{
  printf '# Managed by bootstrap-ubuntu.sh for gips\n'
  printf '# Leave GIP_DB_PATH unset to use the standard search paths.\n'
  if [[ -n "$DB_PATH" ]]; then
    printf 'GIP_DB_PATH=%q\n' "$DB_PATH"
  fi
} > "$ENV_FILE"

cat <<EOF
Bootstrap complete.

Packages installed:
  python3-pip python3-venv mmdb-bin whois iputils-ping iproute2 ncurses-bin

Environment file:
  $ENV_FILE

Next steps:
  pip install .
  gips doctor
EOF
