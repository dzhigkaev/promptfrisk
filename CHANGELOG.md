# Changelog

All notable changes to promptfrisk are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-06-14

### Added
- **ReDoS / resource guard**: `GuardrailConfig.max_text_length` (default 100,000)
  caps text fed to regex scanners; oversized input is truncated and flagged.
- `SECURITY.md` with a threat model (in/out of scope) and the regex ReDoS audit.
- `CHANGELOG.md`.
- Expanded precision corpus: more benign prompts (other languages, code, security
  discussion) and more attack variants.
- A performance/ReDoS regression test (pathological input completes quickly).

### Notes
- promptfrisk remains a heuristic, defense-in-depth filter — not a sole security
  control. See `SECURITY.md`.

## [0.1.0] - 2026-06-14

### Added
- Initial release: `Guardrail` engine with four heuristic scanners (injection,
  pii, secrets, tool_call) behind a pluggable `BaseScanner`.
- Actions ALLOW / FLAG / REDACT / BLOCK with configurable thresholds.
- PII redaction modes (mask / redact / tokenize / hash).
- CLI (`promptfrisk scan`) for CI gating.
- Precision regression suite (benign corpus + attack controls).
