#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_VENV="$(mktemp -d /tmp/gips-build-venv-XXXXXX)"

cleanup() {
  rm -rf "$BUILD_VENV" "$ROOT_DIR/build" "$ROOT_DIR/gips.egg-info"
}
trap cleanup EXIT

cd "$ROOT_DIR"

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

rm -rf build dist gips.egg-info
python3 -m venv "$BUILD_VENV"
"$BUILD_VENV/bin/python" -m pip install --upgrade pip build >/dev/null
"$BUILD_VENV/bin/python" -m build >/dev/null

(
  cd dist
  sha256sum *.whl *.tar.gz > SHA256SUMS
)

printf 'Release artifacts built in %s/dist\n' "$ROOT_DIR"
ls -1 dist
