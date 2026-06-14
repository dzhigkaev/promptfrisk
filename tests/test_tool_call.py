from __future__ import annotations

from promptfrisk.models import Action, GuardrailConfig, ScanContext
from promptfrisk.scanners.tool_call import ToolCallScanner

CFG = GuardrailConfig()
CTX = ScanContext()


def test_destructive_command_blocks():
    r = ToolCallScanner().inspect("run_shell", {"cmd": "ls; rm -rf /"}, CTX, CFG)
    assert r.action is Action.BLOCK
    assert any(f.category == "destructive_command" for f in r.findings)


def test_command_substitution_blocks():
    r = ToolCallScanner().inspect("run", {"arg": "$(cat /etc/passwd)"}, CTX, CFG)
    assert r.action is Action.BLOCK


def test_ssrf_blocks():
    r = ToolCallScanner().inspect(
        "fetch", {"url": "http://169.254.169.254/latest/meta-data"}, CTX, CFG
    )
    assert r.action is Action.BLOCK
    assert any(f.category == "ssrf" for f in r.findings)


def test_path_traversal_blocks():
    r = ToolCallScanner().inspect("read_file", {"path": "../../etc/shadow"}, CTX, CFG)
    assert r.action is Action.BLOCK


def test_allowlist_blocks_unknown_tool():
    s = ToolCallScanner({"allowed_tools": ["search", "calculator"]})
    r = s.inspect("delete_database", {}, CTX, CFG)
    assert r.action is Action.BLOCK
    assert any(f.category == "tool_not_allowed" for f in r.findings)


def test_clean_tool_call_allows():
    r = ToolCallScanner().inspect("search", {"query": "weather in Paris"}, CTX, CFG)
    assert r.action is Action.ALLOW


def test_scan_text_entrypoint():
    payload = '{"name": "run", "parameters": {"cmd": "echo hi; rm -rf /tmp"}}'
    r = ToolCallScanner().scan(payload, CTX, CFG)
    assert r.action is Action.BLOCK


def test_scan_non_json_allows():
    r = ToolCallScanner().scan("not json at all", CTX, CFG)
    assert r.action is Action.ALLOW
