# Changelog

## 1.0.0

- Added the public `gips` command with `lookup`, `batch`, `probe`, `status`, `shell`, and `version`.
- Added CIDR and explicit range expansion with `--max-targets` safeguards.
- Added JSON, JSONL, and CSV output modes for lookup and batch workflows.
- Added reverse DNS, ASN, WHOIS, and latency enrichments.
- Added DB metadata parsing and freshness reporting.
- Added an interactive shell UI with a boot banner and persistent rotating `RECON` logo.
- Added `gips doctor` for deployment readiness and prerequisite reporting.
- Added Ubuntu/Debian bootstrap automation in `scripts/bootstrap-ubuntu.sh`.
- Added GitHub Actions CI and tag-driven release automation for wheel, sdist, and checksum artifacts.
- Added Apache-2.0 licensing plus contributor, security, and issue/PR templates for a public repository release.
- Added `/etc/default/gips` support for packaged and repo-local launches.
- Hardened shell UI startup with automatic fallback when advanced prompt features are not trustworthy.
- Distinguished core GeoIP requirements from optional enrichment dependencies in runtime status output.
- Added `scripts/finalize-check.sh` to run syntax, test, integration, and packaged-install validation before release sign-off.
- Added `scripts/build-release.sh` for repeatable release artifact generation.
- Kept `gip.sh` as a compatibility shim for repo-local usage.
