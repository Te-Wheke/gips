# Repository Guidelines

## Project Structure & Module Organization
`gips` is a Linux-first GeoIP and recon CLI. Repo launchers live at the root in [`gips`](/home/rangatira/IP/gips) and [`gip.sh`](/home/rangatira/IP/gip.sh). Runtime code lives in `station/`, deployment helpers in `scripts/`, GitHub automation in `.github/`, and tests plus fixtures in `tests/`. Package metadata is in `pyproject.toml`, and release notes live in `CHANGELOG.md`.

## Build, Test, and Development Commands
- `bash -n gips gip.sh` validates both shell launchers.
- `./gips lookup --plain 8.8.8.8` runs a one-shot lookup.
- `printf '8.8.8.8\n1.1.1.1\n' | ./gips batch - --jsonl` exercises streaming batch mode.
- `./gips probe --plain` runs live diagnostics.
- `./gips doctor --json` checks deployability and missing prerequisites.
- `./scripts/finalize-check.sh` runs the release validation gate for syntax, tests, CLI integration, and packaged install checks.
- `./scripts/build-release.sh` builds the wheel, source tarball, and `SHA256SUMS` for GitHub Releases.
- `sudo ./scripts/bootstrap-ubuntu.sh --db-path /path/to/GeoLite2-City.mmdb` prepares an Ubuntu/Debian host.
- `python3 -m unittest discover -s tests` runs the unit and CLI tests.
- `python3 -m pip install --target /tmp/gips-install .` validates packaging without touching the global environment.

## Coding Style & Naming Conventions
Keep Bash wrappers thin and put behavior in Python modules. Use 4-space indentation in Python, shell-safe quoting in Bash, and `snake_case` names. Prefer standard library modules first; keep third-party use limited to terminal UX (`click`, `rich`, `prompt_toolkit`). `RECON` is visual shell branding only, not a public command or schema name. Do not commit generated content from `build/`, `dist/`, or `*.egg-info/`.

## Testing Guidelines
Cover target parsing, DB metadata parsing, env-file loading, prerequisite classification, CLI output formats, and shell UI helpers. Use `unittest` in `tests/test_*.py`. Mock network-dependent enrichments in automated tests. Preserve the single-line default for lookup output unless a structured mode is requested.

## Commit & Pull Request Guidelines
This directory is not yet a Git repository, so use imperative Conventional Commits once version control is initialized, for example `feat: add batch recon workflow` or `fix: parse MaxMind build metadata`. Pull requests should list commands run, affected operator workflows, and sample terminal output when shell UI or output formats change.
