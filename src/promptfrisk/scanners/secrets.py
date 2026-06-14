"""Secrets / data-leakage scanner.

Detects leaked credentials, tokens, private keys, and internal-only data that
should never appear in an LLM response (or a user-supplied prompt). Secrets are
high severity and block by default.
"""

from __future__ import annotations

import re
from typing import Any

from promptfrisk.base import BaseScanner
from promptfrisk.models import Finding, GuardrailConfig, ScanContext, ScanResult

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    (
        "connection_string",
        re.compile(r"\b(?:mongodb|postgres|postgresql|mysql|redis)://[^\s]+", re.IGNORECASE),
    ),
    (
        "password_assignment",
        re.compile(
            r"(?:password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
            re.IGNORECASE,
        ),
    ),
]

_INTERNAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    (
        "internal_hostname",
        re.compile(r"\b[a-z0-9-]+\.(?:internal|local|corp|priv)\b", re.IGNORECASE),
    ),
]

_SECRET_SEVERITY = 0.9
_INTERNAL_SEVERITY = 0.6


class SecretsScanner(BaseScanner):
    name = "secrets"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.check_internal = self.config.get("check_internal", True)

    def scan(self, text: str, context: ScanContext, gconfig: GuardrailConfig) -> ScanResult:
        findings: list[Finding] = []
        max_severity = 0.0

        for name, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=name,
                        message="Secret or credential detected",
                        confidence=_SECRET_SEVERITY,
                        start=m.start(),
                        end=m.end(),
                    )
                )
                max_severity = max(max_severity, _SECRET_SEVERITY)

        if self.check_internal:
            for name, pattern in _INTERNAL_PATTERNS:
                for m in pattern.finditer(text):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category=name,
                            message="Internal-only data detected",
                            confidence=_INTERNAL_SEVERITY,
                            start=m.start(),
                            end=m.end(),
                        )
                    )
                    max_severity = max(max_severity, _INTERNAL_SEVERITY)

        return ScanResult(
            scanner=self.name,
            action=self.decide(max_severity, gconfig),
            confidence=max_severity,
            findings=findings,
        )
