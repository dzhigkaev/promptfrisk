"""Core data model for promptfrisk.

A scanner inspects text (or a tool call) and returns a :class:`ScanResult`. The
:class:`~promptfrisk.engine.Guardrail` aggregates per-scanner results into a single
:class:`GuardResult` carrying the overall action, confidence, findings, and the
(possibly redacted) text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Action(IntEnum):
    """What to do with the content. Ordered least → most restrictive so that
    aggregating with ``max`` yields the strongest action."""

    ALLOW = 0
    FLAG = 1
    REDACT = 2
    BLOCK = 3

    @property
    def label(self) -> str:
        return self.name


class Direction(str, Enum):
    """Which side of the model boundary the text came from."""

    INPUT = "input"
    OUTPUT = "output"


@dataclass(frozen=True)
class Finding:
    """One thing a scanner flagged."""

    scanner: str
    category: str
    message: str
    confidence: float
    start: int | None = None
    end: int | None = None


@dataclass
class ScanContext:
    """Optional context passed to scanners (enables multi-turn analysis)."""

    direction: Direction = Direction.INPUT
    session_id: str | None = None
    conversation_history: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result from a single scanner."""

    scanner: str
    action: Action
    confidence: float
    findings: list[Finding] = field(default_factory=list)
    modified_text: str | None = None


@dataclass
class GuardResult:
    """Aggregate result across all scanners."""

    action: Action
    confidence: float
    findings: list[Finding]
    text: str
    results: list[ScanResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.action == Action.ALLOW

    @property
    def flagged(self) -> bool:
        return self.action >= Action.FLAG

    @property
    def redacted(self) -> bool:
        return self.action == Action.REDACT

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK


@dataclass
class GuardrailConfig:
    """Engine-wide thresholds and behaviour."""

    flag_threshold: float = 0.5
    block_threshold: float = 0.8
    fail_open: bool = False  # on scanner error: True → allow, False → block
    redact: bool = True      # apply scanner text modifications (e.g. PII masking)
    # Defense-in-depth against pathological/ReDoS inputs: text longer than this is
    # truncated before scanning (and flagged), bounding regex work regardless of
    # any single pattern's complexity. Set to 0 to disable.
    max_text_length: int = 100_000
