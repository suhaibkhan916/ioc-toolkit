"""Pull indicators out of free text such as a threat report or a ticket."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ioctk.defang import refang
from ioctk.types import Ioc, IocType
from ioctk.validate import validate

# Each pattern is run on refanged text. They are loose on purpose and every
# match is passed through validate() before it is kept.
_PATTERNS: list[tuple[IocType, re.Pattern[str]]] = [
    (IocType.URL, re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.I)),
    (IocType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")),
    (IocType.CVE, re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    (IocType.SHA256, re.compile(r"\b[0-9a-fA-F]{64}\b")),
    (IocType.SHA1, re.compile(r"\b[0-9a-fA-F]{40}\b")),
    (IocType.MD5, re.compile(r"\b[0-9a-fA-F]{32}\b")),
    # Not part of a longer dotted number such as a version "1.2.3.4.5".
    # A full stop that ends a sentence ("... 203.0.113.45.") is still allowed.
    (IocType.IPV4, re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")),
    (IocType.IPV6, re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")),
    (IocType.DOMAIN, re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z][A-Za-z0-9-]{1,62}\b")),
]

# Characters that often end a URL in prose but are not part of it.
_URL_TRAIL = ".,;:!?)]}'\""


def _clean_url(url: str) -> str:
    while url and url[-1] in _URL_TRAIL:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def extract(text: str, types: Iterable[IocType] | None = None) -> list[Ioc]:
    """Return unique valid indicators in order of first appearance.

    Text inside a URL or email is not reported again as a separate domain or
    IP, so "https://evil.example/x" gives one URL, not a URL and a domain.
    """
    wanted = set(types) if types is not None else set(IocType)
    live = refang(text) if text.strip() else text
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, Ioc]] = []
    seen: set[tuple[IocType, str]] = set()

    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(live):
            start, end = m.span()
            raw = m.group(0)
            if kind is IocType.URL:
                raw = _clean_url(raw)
                end = start + len(raw)
            if any(s <= start and end <= e for s, e in taken):
                continue
            result = validate(raw, expected=kind)
            if not result.valid:
                continue
            taken.append((start, end))
            key = (kind, result.value)
            if kind in wanted and key not in seen:
                seen.add(key)
                found.append((start, Ioc(kind, result.value)))

    found.sort(key=lambda pair: pair[0])
    return [ioc for _, ioc in found]
