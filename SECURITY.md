# Security Policy

## Supported Release

`gips` `1.0.0` is supported for Ubuntu and Debian deployments that use a local MaxMind database and the documented bootstrap flow.

## Reporting

Open a GitHub issue for vulnerabilities and label it `security`. Include:

- affected version
- impact summary
- reproduction steps
- any prerequisite tooling or database assumptions

Do not post secrets, tokens, or proprietary database material in the report.

## Scope

The project does not support cloud GeoIP services, hosted enrichment, or non-Linux production targets in `1.0.0`.

