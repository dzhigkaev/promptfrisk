from __future__ import annotations

from promptfrisk.models import Action, GuardrailConfig, ScanContext
from promptfrisk.scanners.pii import PIIScanner

CFG = GuardrailConfig()
CTX = ScanContext()


def test_detects_and_redacts_email():
    r = PIIScanner().scan("contact me at john.doe@example.com please", CTX, CFG)
    assert r.action is Action.REDACT
    assert "john.doe@example.com" not in r.modified_text
    assert any(f.category == "email" for f in r.findings)


def test_detects_ssn_and_credit_card():
    text = "SSN 123-45-6789 card 4111111111111111"
    r = PIIScanner().scan(text, CTX, CFG)
    cats = {f.category for f in r.findings}
    assert "ssn" in cats
    assert "credit_card" in cats


def test_clean_text_allows():
    r = PIIScanner().scan("no personal data here", CTX, CFG)
    assert r.action is Action.ALLOW
    assert r.modified_text is None


def test_mask_mode():
    s = PIIScanner({"mode": "mask"})
    r = s.scan("email a@b.com", CTX, CFG)
    assert "*" in r.modified_text


def test_tokenize_roundtrip():
    s = PIIScanner({"mode": "tokenize"})
    r = s.scan("reach me at a@b.com", CTX, CFG)
    assert "a@b.com" not in r.modified_text
    assert s.detokenize(r.modified_text) == "reach me at a@b.com"


def test_category_filter():
    s = PIIScanner({"categories": ["financial"]})
    r = s.scan("email a@b.com", CTX, CFG)  # contact category excluded
    assert r.action is Action.ALLOW


def test_no_redaction_when_disabled():
    r = PIIScanner().scan("a@b.com", CTX, GuardrailConfig(redact=False))
    assert r.action is Action.REDACT
    assert r.modified_text is None  # findings reported, but text not rewritten
