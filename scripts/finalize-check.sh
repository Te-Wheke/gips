#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INSTALL_DIR="$(mktemp -d /tmp/gips-finalize-XXXXXX)"
DOCTOR_JSON="$INSTALL_DIR/doctor.json"
VERSION_JSON="$INSTALL_DIR/version.json"
BATCH_JSONL="$INSTALL_DIR/batch.jsonl"

cleanup() {
  rm -rf "$INSTALL_DIR"
  rm -rf "$ROOT_DIR/build" "$ROOT_DIR/gips.egg-info"
  find "$ROOT_DIR/station" "$ROOT_DIR/tests" -type d -name __pycache__ -prune -exec rm -rf {} +
}
trap cleanup EXIT

cd "$ROOT_DIR"

echo "[1/7] Checking version alignment"
runtime_version="$(python3 -c 'import station; print(station.__version__)')"
package_version="$(python3 - <<'PY'
import tomllib
from pathlib import Path

payload = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
print(payload["project"]["version"])
PY
)"

if [[ "$runtime_version" != "1.0.0" || "$package_version" != "1.0.0" ]]; then
  printf 'Expected version 1.0.0, got runtime=%s package=%s\n' "$runtime_version" "$package_version" >&2
  exit 1
fi

echo "[2/7] Validating shell launchers and helper scripts"
bash -n gips gip.sh scripts/bootstrap-ubuntu.sh scripts/finalize-check.sh

echo "[3/7] Running Python bytecode checks and unit tests"
python3 -m compileall station tests >/dev/null
python3 -m unittest discover -s tests

echo "[4/7] Exercising repo-local CLI integration"
./gips --help >/dev/null
./gips doctor --json > "$DOCTOR_JSON"
./gips version --json > "$VERSION_JSON"
lookup_output="$(./gips lookup --plain 8.8.8.8)"
if [[ "$lookup_output" == *$'\n'* ]]; then
  echo "lookup output is not a single physical line" >&2
  exit 1
fi
if [[ "$lookup_output" != *"TARGET=8.8.8.8"* ]]; then
  echo "lookup output missing target marker" >&2
  exit 1
fi

printf '8.8.8.8\n1.1.1.1\n' | ./gips batch - --jsonl > "$BATCH_JSONL"

python3 - "$DOCTOR_JSON" "$VERSION_JSON" "$BATCH_JSONL" <<'PY'
import json
import sys
from pathlib import Path

doctor = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
version = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
batch_lines = [
    json.loads(line)
    for line in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]

if doctor["version"] != "1.0.0":
    raise SystemExit("doctor version mismatch")
if version["version"] != "1.0.0":
    raise SystemExit("version command mismatch")
if len(batch_lines) != 2:
    raise SystemExit("batch did not emit two records")
PY

echo "[5/7] Verifying deployability and status commands"
./gips status --plain >/dev/null
./gips probe --plain >/dev/null

echo "[6/7] Validating packaged install"
python3 -m pip install --root-user-action ignore --target "$INSTALL_DIR" . >/dev/null
packaged_gips="$INSTALL_DIR/bin/gips"
PYTHONPATH="$INSTALL_DIR" "$packaged_gips" doctor --json > "$INSTALL_DIR/packaged-doctor.json"
PYTHONPATH="$INSTALL_DIR" "$packaged_gips" version --json > "$INSTALL_DIR/packaged-version.json"
python3 - "$INSTALL_DIR/packaged-doctor.json" "$INSTALL_DIR/packaged-version.json" <<'PY'
import json
import sys
from pathlib import Path

doctor = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
version = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

if doctor["version"] != "1.0.0":
    raise SystemExit("packaged doctor version mismatch")
if version["version"] != "1.0.0":
    raise SystemExit("packaged version mismatch")
PY

echo "[7/7] Finalization gate passed"
