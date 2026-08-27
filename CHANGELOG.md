# Changelog

All notable repository-level changes will be documented in this file.

The project is under active development and has not yet declared a stable 1.0 release. Dates below describe repository changes, not product support guarantees.

## Unreleased

### Documentation
- Reworked the main README around verifiable capabilities and explicit technical limits.
- Added a roadmap that separates implemented behavior from planned work.
- Added a CI-backed quality section describing the current Windows/Python test matrix.

### Current verified baseline
- GitHub Actions runs the pytest suite on Windows across Python 3.10, 3.11, 3.12 and 3.13.
- The CI run for commit `5cdcce7` completed successfully on all four Python versions.
- The Python 3.12 job collected and passed 105 tests.

## Release policy

Future releases should use semantic versioning once a repeatable packaging and release flow is verified. Until then, features and fixes should be tracked through commits and this `Unreleased` section.
