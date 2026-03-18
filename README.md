# gips

`gips` is a Linux-first recon CLI for GeoIP lookup, operator diagnostics, and local batch workflows. Release `1.0.0` is production-supported on Ubuntu and Debian only.

## Release Assets

Stable releases publish a wheel, source tarball, and `SHA256SUMS` through GitHub Releases. Install from a release asset with:

```bash
python3 -m pip install ./gips-1.0.0-py3-none-any.whl
gips version --json
```

## Install

```bash
sudo ./scripts/bootstrap-ubuntu.sh --db-path /path/to/GeoLite2-City.mmdb
pip install .
gips doctor
./scripts/finalize-check.sh
./scripts/build-release.sh
```

Repo-local launchers:

```bash
./gips --help
./gip.sh --help
```

## Commands

- `gips lookup <target>` resolves a single IP, CIDR, or range.
- `gips batch <file|->` reads newline-delimited targets from a file or stdin.
- `gips probe` runs live terminal, DB, DNS, HTTPS, and public-IP checks.
- `gips status` shows current network and DB state.
- `gips doctor` reports deployment readiness, missing packages, DB status, and shell capability.
- `gips shell` launches the interactive UI with the rotating `RECON` logo.
- `gips version` prints release and DB metadata.

## Examples

```bash
gips lookup 8.8.8.8
gips lookup --json 8.8.8.0/30
printf '8.8.8.8\n1.1.1.1\n' | gips batch - --jsonl
gips lookup --enrich all 8.8.8.8
gips doctor --json
gips status --json
gips shell
```

## Notes

- Ubuntu/Debian bootstrap automation is in `scripts/bootstrap-ubuntu.sh`.
- `scripts/finalize-check.sh` is the release gate for local syntax, unit, CLI, and packaged-install validation.
- `scripts/build-release.sh` builds the wheel, source tarball, and `SHA256SUMS` for GitHub Releases.
- `gips doctor` exits non-zero only when core GeoIP requirements are missing.
- GeoIP data is resolved from `--db-path`, `GIP_DB_PATH`, `/var/lib/GeoIP/GeoLite2-City.mmdb`, then `/usr/share/GeoIP/GeoLite2-City.mmdb`.
- Packaged installs also read `/etc/default/gips` when present.
- Batch expansion is capped by `--max-targets` to prevent accidental explosion on large CIDR blocks or ranges.
- Reverse DNS, ASN, WHOIS, and latency enrichment rely on locally available CLI tools and network reachability; missing optional tools degrade those features without blocking core lookup.
- Limited terminals automatically fall back to a plain shell prompt instead of using the animated `RECON` toolbar.
- If `prompt_toolkit` is unavailable or cannot initialize cleanly, `gips shell` falls back to a plain stdio prompt instead of breaking the rest of the CLI.

## Release Validation

Use the finalization gate before tagging or handing off a build:

```bash
./scripts/finalize-check.sh
```

The script validates version alignment, shell syntax, `compileall`, `unittest`, core CLI commands, and a packaged install in `/tmp`.

## GitHub Release Automation

- `.github/workflows/ci.yml` runs the finalize gate on Python `3.11` and `3.12`.
- `.github/workflows/release.yml` validates, builds release assets, smoke-tests the built wheel, and uploads artifacts on `v*` tags.
- GitHub branch protection should require the `ci` workflow and one approving review on `main`.
