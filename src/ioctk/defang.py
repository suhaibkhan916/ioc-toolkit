"""Defang (make safe to paste) and refang (make live again) indicators.

Style written by defang():
  URL     https://evil.example/a.php  ->  hxxps://evil[.]example/a.php
  domain  evil.example                ->  evil[.]example
  IPv4    203.0.113.7                 ->  203[.]0[.]113[.]7
  IPv6    2001:db8::1                 ->  2001[:]db8[:][:]1
  email   a@evil.example              ->  a[@]evil[.]example

refang() accepts many more styles, because reports written by people and
other tools are not consistent: [.] (.) {.} [dot] (dot) {dot} " dot ",
[:] [://] [:]//, hxxp hXXp fxp, [@] [at] (at), and backslash-escaped dots.
"""

from __future__ import annotations

import re

from ioctk.types import IocType

_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_URL_PARTS = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)", re.S)

_SPACED_DOT = re.compile(r"\s+dot\s+", re.I)

# Order matters: longer and more specific patterns first.
_REFANG_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[:\]//|\[://\]|\(://\)|\[:/\]/", re.I), "://"),
    (re.compile(r"\b(h[xt]{2}p)(s?)(?=(://|\[:))", re.I), r"http\2"),
    (re.compile(r"\bfxp(?=(://|\[:))", re.I), "ftp"),
    (re.compile(r"\s*[\[({]\s*(?:dot|\.)\s*[\])}]\s*", re.I), "."),
    (_SPACED_DOT, "."),
    (re.compile(r"\\\."), "."),
    (re.compile(r"\s*[\[({]\s*(?:at|@)\s*[\])}]\s*", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
]


def refang(text: str, *, spaced_dot: bool = True) -> str:
    """Turn a defanged string back into its live form. Safe on live input.

    Set spaced_dot=False for prose, where "the dot com" is just words.
    """
    out = text.strip()
    for pattern, repl in _REFANG_RULES:
        if pattern is _SPACED_DOT and not spaced_dot:
            continue
        out = pattern.sub(repl, out)
    return out


def _dots(host: str) -> str:
    return host.replace(".", "[.]")


def _defang_url(url: str) -> str:
    # A regex, not urlsplit: urlsplit raises ValueError on "http://[" and drops tabs and
    # newlines, which would shift the offsets. Defanging must work on broken URLs too.
    match = _URL_PARTS.match(url)
    if match is None:
        return _dots(url)
    scheme, host, rest = match.groups()
    new_scheme = _SCHEMES.get(scheme.lower(), scheme)
    if host.startswith("[") and "]" in host:  # IPv6 literal keeps its brackets
        inner, after = host[1:].split("]", 1)
        host = "[" + inner.replace(":", "[:]") + "]" + _dots(after)
    else:
        host = _dots(host)
    return f"{new_scheme}://{host}{rest}"


def defang(value: str, ioc_type: IocType | None = None) -> str:
    """Return a defanged copy of one indicator.

    The input is refanged first, so calling defang twice gives the same
    result as calling it once.
    """
    # Imported here to avoid a cycle: validate uses refang.
    from ioctk.validate import classify

    live = refang(value)
    kind = ioc_type or classify(live)
    if kind is IocType.URL:
        return _defang_url(live)
    if kind is IocType.EMAIL:
        local, _, domain = live.rpartition("@")
        return f"{local}[@]{_dots(domain)}"
    if kind is IocType.IPV6:
        return live.replace(":", "[:]")
    if kind in (IocType.MD5, IocType.SHA1, IocType.SHA256, IocType.CVE):
        return live  # nothing clickable in a hash or a CVE id
    return _dots(live)
