# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than a public
issue. Include a reproduction and the affected version. We aim to acknowledge
within a few days.

## Supported versions

The latest released `0.x` line receives fixes. promptfrisk is pre-1.0; APIs may
change between minor versions.

## Threat model — what promptfrisk is and isn't

promptfrisk is a **fast, heuristic, defense-in-depth filter** for the LLM
boundary. Be clear-eyed about its guarantees.

**In scope (what it aims to catch):**
- Obvious prompt-injection / jailbreak phrasing (instruction override, DAN, role
  switches, delimiter/encoding bypass) via regex heuristics.
- Common PII (email, phone, SSN, Luhn-valid cards) with redaction.
- Well-known secret formats (cloud keys, tokens, JWTs, private keys).
- Risky tool-call parameters (destructive commands, SSRF, path traversal) and a
  tool allowlist.

**Explicitly out of scope (do NOT rely on promptfrisk alone for these):**
- **Determined or novel attackers.** Regex heuristics are evadable by
  obfuscation, paraphrase, unusual languages, or token smuggling. promptfrisk
  raises the cost of *lazy* attacks; it is not a substitute for a trained
  classifier, server-side authorization, output encoding, or least-privilege
  tool design.
- **Comprehensive PII/secret coverage.** Regexes miss many formats (names,
  addresses, non-US identifiers, unlisted key types). Expect false negatives.
- **A statistical efficacy guarantee.** The bundled corpus is hand-built; there
  is no published precision/recall benchmark yet.

Use promptfrisk as **one layer** alongside provider guardrails, authz, sandboxed
tool execution, and monitoring — never as the sole control.

## ReDoS (regular-expression denial of service)

Because detection is regex-based, we treat catastrophic backtracking as a
first-class concern.

**Audit (v0.2):** all bundled patterns were reviewed for super-linear
constructs (nested quantifiers like `(a+)+`, overlapping alternations). The
patterns use bounded quantifiers and disjoint character classes and are
linear-time on adversarial input. There is no catch-all guarantee for
*user-registered* custom scanners.

**Mitigation (defense-in-depth):** the engine caps scanned text at
`GuardrailConfig.max_text_length` (default 100,000 chars). Longer input is
truncated before scanning and flagged, bounding worst-case regex work regardless
of any single pattern's complexity.

**Hardening option:** for untrusted, high-volume input you can back the scanners
with a linear-time engine such as Google RE2 (`google-re2`) instead of the
stdlib `re`. This is not a default dependency (promptfrisk's core is dependency-free).
