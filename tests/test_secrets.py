from __future__ import annotations

from promptfrisk.models import Action, GuardrailConfig, ScanContext
from promptfrisk.scanners.secrets import SecretsScanner

CFG = GuardrailConfig()
CTX = ScanContext()


def _scan(text: str):
    return SecretsScanner().scan(text, CTX, CFG)


def test_aws_access_key_blocks():
    r = _scan("AWS_KEY=AKIAIOSFODNN7EXAMPLE rest of text")
    assert r.action is Action.BLOCK
    assert any(f.category == "aws_access_key" for f in r.findings)


def test_github_token_blocks():
    r = _scan("token ghp_1234567890abcdefghijklmnopqrstuvwxyz1 here")
    assert r.action is Action.BLOCK


def test_private_key_blocks():
    r = _scan("-----BEGIN RSA PRIVATE KEY-----\nMIIabc")
    assert r.action is Action.BLOCK


def test_internal_ip_flags():
    r = _scan("the service runs on 10.1.2.3 internally")
    assert r.action is Action.FLAG
    assert r.confidence < 0.8


def test_clean_text_allows():
    r = _scan("the weather is nice today")
    assert r.action is Action.ALLOW


def test_internal_check_can_be_disabled():
    s = SecretsScanner({"check_internal": False})
    r = s.scan("host is 192.168.1.5", CTX, CFG)
    assert r.action is Action.ALLOW
