"""Base scanner interface.

Subclass :class:`BaseScanner` and implement ``scan`` to add a custom detector
(for example an ML-backed tier). Register it with the engine via
``Guardrail.register(MyScanner())``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from promptfrisk.models import Action, GuardrailConfig, ScanContext, ScanResult


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    #: Stable identifier used in findings and metrics. Override in subclasses.
    name: str = "base"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    def scan(self, text: str, context: ScanContext, gconfig: GuardrailConfig) -> ScanResult:
        """Inspect ``text`` and return a :class:`ScanResult`."""
        raise NotImplementedError

    @staticmethod
    def decide(confidence: float, gconfig: GuardrailConfig) -> Action:
        """Map a confidence score to an action using the engine thresholds."""
        if confidence >= gconfig.block_threshold:
            return Action.BLOCK
        if confidence >= gconfig.flag_threshold:
            return Action.FLAG
        return Action.ALLOW
