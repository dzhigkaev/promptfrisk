"""Prompt-injection / jailbreak scanner (heuristic, Tier 1).

Regex patterns merged from two production reference implementations. Each pattern
carries a severity; the scanner's confidence is the max severity matched. When a
session is tracked, a sustained pattern of low-grade attempts escalates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from promptfrisk.base import BaseScanner
from promptfrisk.models import Finding, GuardrailConfig, ScanContext, ScanResult


@dataclass(frozen=True)
class InjectionPattern:
    name: str
    pattern: re.Pattern
    severity: float
    description: str


_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        "ignore_instructions",
        re.compile(
            r"ignore\s+(all\s+)?(previous|above|prior|earlier)\s+"
            r"(instructions?|prompts?|rules?)",
            re.IGNORECASE,
        ),
        0.9,
        "Attempts to override prior instructions",
    ),
    InjectionPattern(
        "forget_instructions",
        re.compile(
            r"forget\s+(everything|all)\s+(you|that)\s+(know|learned|were\s+told)",
            re.IGNORECASE,
        ),
        0.85,
        "Attempts to wipe prior context",
    ),
    InjectionPattern(
        "system_prompt_reveal",
        re.compile(
            r"(show|reveal|tell|give|repeat|print|output|display)\s+(me\s+)?"
            r"(your|the|system)\s+(system\s+)?(prompt|instructions?|rules?)",
            re.IGNORECASE,
        ),
        0.85,
        "Attempts to extract the system prompt",
    ),
    InjectionPattern(
        "role_switch",
        re.compile(
            r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you'?re)|"
            r"from\s+now\s+on\s+you|roleplay\s+as)",
            re.IGNORECASE,
        ),
        0.8,
        "Attempts to change the assistant's role",
    ),
    InjectionPattern(
        "jailbreak_dan",
        re.compile(
            r"(\bDAN\b|do\s+anything\s+now|jailbreak|bypass\s+(filters?|guardrails?|safety)|"
            r"unfiltered|uncensored|jailbroken)",
            re.IGNORECASE,
        ),
        0.95,
        "Known jailbreak phrasing",
    ),
    InjectionPattern(
        "special_mode",
        re.compile(r"(developer|debug|admin|root|sudo|god)\s+mode", re.IGNORECASE),
        0.9,
        "Attempts to enable a privileged mode",
    ),
    InjectionPattern(
        "delimiter_escape",
        re.compile(
            r"(```\s*(system|assistant|admin)|<\|im_start\|>|<\|im_end\|>|"
            r"<\|endoftext\|>|\[SYSTEM\]|\[/INST\]|</system>)",
            re.IGNORECASE,
        ),
        0.85,
        "Chat-template delimiter injection",
    ),
    InjectionPattern(
        "encoding_bypass",
        re.compile(r"(base64|hex|rot13|unicode|encoded)\s*:?\s*[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
        0.75,
        "Possible encoded-payload bypass",
    ),
    InjectionPattern(
        "authority_claim",
        re.compile(
            r"(i'?m\s+the\s+(admin|developer|owner)|i\s+have\s+(permission|authority)|"
            r"authorized\s+user)",
            re.IGNORECASE,
        ),
        0.7,
        "False authority claim",
    ),
]


class InjectionScanner(BaseScanner):
    name = "injection"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._session_scores: dict[str, list[float]] = {}
        self._max_sessions = 10_000

    def scan(self, text: str, context: ScanContext, gconfig: GuardrailConfig) -> ScanResult:
        findings: list[Finding] = []
        max_severity = 0.0

        for pat in _PATTERNS:
            m = pat.pattern.search(text)
            if m:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=pat.name,
                        message=pat.description,
                        confidence=pat.severity,
                        start=m.start(),
                        end=m.end(),
                    )
                )
                max_severity = max(max_severity, pat.severity)

        # Multi-turn escalation: a steady drip of low-grade attempts is itself a signal.
        max_severity = max(max_severity, self._escalation(context, max_severity, findings))

        return ScanResult(
            scanner=self.name,
            action=self.decide(max_severity, gconfig),
            confidence=max_severity,
            findings=findings,
        )

    def _escalation(
        self, context: ScanContext, current: float, findings: list[Finding]
    ) -> float:
        if not context.session_id:
            return 0.0
        scores = self._session_scores.setdefault(context.session_id, [])
        scores.append(current)
        if len(scores) > 100:
            del scores[:-100]
        if len(self._session_scores) > self._max_sessions:
            for key in list(self._session_scores)[: self._max_sessions // 2]:
                del self._session_scores[key]

        recent = scores[-5:]
        if len(recent) >= 3:
            avg = sum(recent) / len(recent)
            if avg > 0.4:
                escalated = min(avg + 0.2, 1.0)
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="escalating_injection",
                        message=f"Sustained injection attempts across {len(recent)} turns",
                        confidence=escalated,
                    )
                )
                return escalated
        return 0.0
