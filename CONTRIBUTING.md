# Contributing

## Local Validation

Run the release gate before opening a pull request:

```bash
./scripts/finalize-check.sh
```

The gate validates shell syntax, Python importability, unit coverage, CLI integration, and a packaged install.

## Support Boundary

`gips` is production-supported on Ubuntu and Debian only for `1.0.0`. Keep core GeoIP resolution local through `mmdblookup` and an operator-supplied MaxMind database.

## Pull Requests

- Use imperative commit messages such as `fix: harden shell fallback`.
- Describe operator-visible behavior changes clearly.
- Include the exact validation commands run.
- Do not commit generated artifacts such as `build/`, `dist/`, or `*.egg-info/`.

