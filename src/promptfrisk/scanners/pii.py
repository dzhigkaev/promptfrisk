"""PII scanner with configurable redaction.

Detects common PII and rewrites it in one of four modes. Because redaction is the
safe handling for PII, this scanner returns ``Action.REDACT`` (with modified text)
rather than blocking, unless there is nothing to redact.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

from promptfrisk.base import BaseScanner
from promptfrisk.models import Action, Finding, GuardrailConfig, ScanContext, ScanResult


class RedactionMode(str, Enum):
    MASK = "mask"          # replace with the mask char
    REDACT = "redact"      # replace with [CATEGORY_REDACTED]
    TOKENIZE = "tokenize"  # replace with a reversible token
    HASH = "hash"          # replace with a stable short hash


@dataclass(frozen=True)
class PIIPattern:
    name: str
    pattern: re.Pattern
    category: str


_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "contact",
    ),
    PIIPattern(
        "phone",
        re.compile(r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"),
        "contact",
    ),
    PIIPattern(
        "ssn",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        "identity",
    ),
    PIIPattern(
        "credit_card",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
            r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        "financial",
    ),
]


class PIIScanner(BaseScanner):
    name = "pii"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.mode = RedactionMode(self.config.get("mode", "redact"))
        self.mask_char = self.config.get("mask_char", "*")
        self.categories = set(
            self.config.get("categories", ["contact", "identity", "financial"])
        )
        self._token_store: dict[str, str] = {}

    def scan(self, text: str, context: ScanContext, gconfig: GuardrailConfig) -> ScanResult:
        findings: list[Finding] = []
        modified = text

        for pii in _PATTERNS:
            if pii.category not in self.categories:
                continue
            for m in pii.pattern.finditer(text):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=pii.name,
                        message=f"{pii.category} PII detected",
                        confidence=0.95,
                        start=m.start(),
                        end=m.end(),
                    )
                )
                modified = modified.replace(m.group(), self._replace(m.group(), pii), 1)

        if not findings:
            return ScanResult(self.name, Action.ALLOW, 0.0, [])

        confidence = min(0.5 + len(findings) * 0.1, 1.0)
        return ScanResult(
            scanner=self.name,
            action=Action.REDACT,
            confidence=confidence,
            findings=findings,
            modified_text=modified if gconfig.redact else None,
        )

    def _replace(self, original: str, pii: PIIPattern) -> str:
        if self.mode is RedactionMode.MASK:
            return self.mask_char * len(original)
        if self.mode is RedactionMode.TOKENIZE:
            token = f"<<{pii.name.upper()}_{uuid.uuid4().hex[:8]}>>"
            self._token_store[token] = original
            return token
        if self.mode is RedactionMode.HASH:
            digest = hashlib.sha256(original.encode()).hexdigest()[:12]
            return f"[{pii.name.upper()}_{digest}]"
        return f"[{pii.name.upper()}_REDACTED]"

    def detokenize(self, text: str) -> str:
        """Reverse tokenization (only works for tokens this instance created)."""
        result = text
        for token, original in self._token_store.items():
            result = result.replace(token, original)
        return result
