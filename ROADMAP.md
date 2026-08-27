# NetMon Roadmap

This roadmap separates **implemented capabilities** from **planned improvements** so repository documentation stays technically accurate.

## Near term

- Add reproducible screenshots and a short demo recording from a clean test environment.
- Add a documented sample/lab environment for SNMP, WMI/WinRM and SSH-backed features.
- Improve per-feature readiness reporting so the UI clearly distinguishes configured, available and unavailable integrations.
- Expand integration tests for DHCP monitoring, SNMP switch mapping and network-device configuration collection using deterministic mocks/fixtures.
- Add structured API documentation examples for core inventory and operations endpoints.
- Reduce oversized backend/frontend modules by extracting focused services and UI modules without changing current behavior.

## Reliability and packaging

- Add a release checklist and semantic versioning policy.
- Produce a repeatable Windows release artifact from CI after the packaging flow is verified end-to-end.
- Add dependency/security scanning to CI.
- Add linting/formatting checks after the current codebase is normalized to avoid noisy mechanical changes.

## Future exploration

The following items are exploration targets, not current product claims:

- richer topology evidence from additional standards/protocols where available
- historical baselining and trend analysis for operational anomalies
- exportable inventory/operations reports with clearer provenance of each field
- optional containerized web deployment for environments that do not use the desktop shell

## Documentation rule

A feature should move from this roadmap into the main README only when the repository contains an implementation path and there is enough evidence to describe its behavior accurately. Where a capability depends on credentials, operating-system permissions, network-device configuration or third-party tooling, those dependencies should remain explicit.
