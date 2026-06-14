"""Tool-call inspector.

LLM tool/function calls have a different shape from free text (a name plus a
parameters object), so this scanner is invoked via ``inspect(name, parameters)``
rather than the text pipeline. It checks the serialized parameters for dangerous
shell/command, SSRF, and path-traversal patterns, and optionally enforces a tool
allowlist.
"""

from __future__ import annotations

import json
import re
from typing import Any

from promptfrisk.base import BaseScanner
from promptfrisk.models import Action, Finding, GuardrailConfig, ScanContext, ScanResult

_DANGEROUS: list[tuple[str, re.Pattern]] = [
    (
        "destructive_command",
        re.compile(
            r"\brm\s+-\w*[rf]"            # rm -rf / -fr / -r / -f
            r"|\b(?:drop|truncate)\s+table\b"
            r"|\bdelete\s+from\b"
            r"|\bmkfs\b"
            r"|;\s*(?:rm|del|shutdown|reboot|halt)\b",  # chained destructive cmds
            re.IGNORECASE,
        ),
    ),
    ("pipe_to_shell", re.compile(r"\|\s*(?:bash|sh|zsh|cmd|powershell)\b", re.IGNORECASE)),
    ("command_substitution", re.compile(r"`[^`]+`|\$\([^)]+\)")),
    (
        "ssrf",
        re.compile(
            r"(?:file|gopher|ftp|https?)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
            r"169\.254\.169\.254|metadata|internal)",
            re.IGNORECASE,
        ),
    ),
    ("path_traversal", re.compile(r"\.\.[\\/]")),
]


class ToolCallScanner(BaseScanner):
    name = "tool_call"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        # Optional allowlist of permitted tool names. Empty = allow any name.
        self.allowed_tools: set[str] = set(self.config.get("allowed_tools", []))

    def inspect(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        context: ScanContext | None = None,
        gconfig: GuardrailConfig | None = None,
    ) -> ScanResult:
        """Inspect a single tool call."""
        gconfig = gconfig or GuardrailConfig()
        findings: list[Finding] = []
        max_severity = 0.0

        if self.allowed_tools and tool_name not in self.allowed_tools:
            findings.append(
                Finding(
                    scanner=self.name,
                    category="tool_not_allowed",
                    message=f"Tool {tool_name!r} is not on the allowlist",
                    confidence=1.0,
                )
            )
            max_severity = 1.0

        param_str = json.dumps(parameters, default=str)
        for name, pattern in _DANGEROUS:
            if pattern.search(param_str):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=name,
                        message=f"Dangerous pattern in tool '{tool_name}' parameters",
                        confidence=0.9,
                    )
                )
                max_severity = max(max_severity, 0.9)

        return ScanResult(
            scanner=self.name,
            action=self.decide(max_severity, gconfig),
            confidence=max_severity,
            findings=findings,
        )

    def scan(self, text: str, context: ScanContext, gconfig: GuardrailConfig) -> ScanResult:
        """Text-pipeline entry: ``text`` is treated as JSON ``{"name", "parameters"}``."""
        try:
            call = json.loads(text)
            name = call.get("name", "")
            params = call.get("parameters", call.get("arguments", {}))
        except (json.JSONDecodeError, AttributeError):
            return ScanResult(self.name, Action.ALLOW, 0.0, [])
        return self.inspect(name, params, context, gconfig)
