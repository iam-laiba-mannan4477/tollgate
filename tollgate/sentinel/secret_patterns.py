"""Secret-looking patterns, shared by scripts/check_secrets.py and the Sentinel scanner.

Each pattern has a plain label. Reports name the label only, never any part of the value.
"""
from __future__ import annotations

import re

LABELED_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("Braintree public or private key assignment",
     re.compile(r"BRAINTREE_(PRIVATE|PUBLIC)_KEY\s*=\s*[A-Za-z0-9]{16,}")),
    ("Braintree merchant id assignment", re.compile(r"BRAINTREE_MERCHANT_ID\s*=\s*[A-Za-z0-9]{12,}")),
    ("Groq API key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),                 # Groq key shape
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),      # Anthropic key shape
    ("model API key assignment", re.compile(r"(GROQ|ANTHROPIC)_API_KEY\s*=\s*\S{8,}")),
    ("PEM private key block", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ("generic key or token assignment",
     re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}")),
)
PATTERNS = [pattern for _, pattern in LABELED_PATTERNS]
PLACEHOLDER = re.compile(r"(?i)your_|example|changeme|xxxx|<.*>")
MASK = "[masked]"


def label_for(line: str) -> str | None:
    """The label of the first pattern that matches a non-placeholder line, else None."""
    if PLACEHOLDER.search(line):
        return None
    for label, pattern in LABELED_PATTERNS:
        if pattern.search(line):
            return label
    return None


def mask(text: str) -> str:
    """Replace anything matching a pattern with [masked] (placeholders included)."""
    for _, pattern in LABELED_PATTERNS:
        text = pattern.sub(MASK, text)
    return text
