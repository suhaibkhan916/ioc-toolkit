"""Classify and validate single indicators."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ioctk.defang import refang
from ioctk.types import IocType, Validation

# \Z and not $: $ also matches before a final newline, so "a\n" would pass.
_HEX = re.compile(r"^[0-9a-fA-F]+\Z")
_HASH_LENGTHS = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}
# re.ASCII: \d alone also accepts digits from other scripts.
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,7})\Z", re.I | re.ASCII)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\Z", re.I)
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\Z", re.I)
_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}\Z")
_URL_SCHEMES = {"http", "https", "ftp"}

# A string such as "invoice.pdf" looks like a domain. These endings are
# treated as file names, not domains. Some are also real TLDs (.zip, .mov),
# so a real domain under them is missed: that trade-off is in the README.
FILE_EXTENSIONS = frozenset(
    {
        "exe", "dll", "bat", "ps1", "vbs", "js", "jar", "py", "sh", "msi",
        "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
        "txt", "log", "csv", "json", "xml", "html", "htm", "zip", "rar", "7z",
        "gz", "tar", "iso", "img", "lnk", "png", "jpg", "jpeg", "gif", "mov",
    }
)  # fmt: skip


def _valid_email_local(local: str) -> bool:
    # RFC 5321 dot-atom: no leading, trailing or doubled dot.
    return bool(_EMAIL_LOCAL.match(local)) and all(local.split("."))


def _is_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    labels = value.rstrip(".").split(".")
    if not all(_LABEL.match(label) for label in labels):
        return False
    tld = labels[-1]
    return bool(_TLD.match(tld)) and tld.lower() not in FILE_EXTENSIONS


def _is_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def classify(value: str) -> IocType | None:
    """Guess the type of an already refanged value, or None."""
    v = value.strip()
    if not v:
        return None
    if _CVE.match(v):
        return IocType.CVE
    if _HEX.match(v) and len(v) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(v)]
    if _is_ip(v, 4):
        return IocType.IPV4
    if _is_ip(v, 6):
        return IocType.IPV6
    if "://" in v:
        return IocType.URL
    if "@" in v and _is_domain(v.rpartition("@")[2]):
        return IocType.EMAIL
    if _is_domain(v):
        return IocType.DOMAIN
    return None


def _ip_notes(value: str) -> tuple[str, ...]:
    ip = ipaddress.ip_address(value)
    notes: list[str] = []
    for attr in ("is_private", "is_loopback", "is_reserved", "is_multicast", "is_link_local"):
        if getattr(ip, attr):
            notes.append(attr.removeprefix("is_").replace("_", " "))
    if ip.version == 4 and any(
        ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ):
        notes.append("documentation range")
    return tuple(dict.fromkeys(notes))


def _normalise_url(url: str, scheme: str, netloc: str) -> str:
    """Lower-case the scheme and host, so one URL is not listed twice.

    User info and path are case-sensitive and stay as they are.
    """
    userinfo, at, hostport = netloc.rpartition("@")
    rest = url[len(scheme) + 3 + len(netloc) :]
    return f"{scheme.lower()}://{userinfo}{at}{hostport.lower()}{rest}"


def _check_url(v: str) -> Validation:
    try:
        parts = urlsplit(v)
    except ValueError as exc:  # urlsplit raises on "http://[" and "http://[]"
        return Validation(v, IocType.URL, False, f"malformed URL: {exc}")
    if parts.scheme.lower() not in _URL_SCHEMES:
        return Validation(v, IocType.URL, False, f"unsupported scheme {parts.scheme!r}")
    host = parts.hostname
    if not host:
        return Validation(v, IocType.URL, False, "no host")
    try:
        _ = parts.port
    except ValueError:
        return Validation(v, IocType.URL, False, "bad port")
    if _is_ip(host, 4) or _is_ip(host, 6):
        clean = _normalise_url(v, parts.scheme, parts.netloc)
        return Validation(clean, IocType.URL, True, notes=_ip_notes(host))
    if not _is_domain(host):
        return Validation(v, IocType.URL, False, f"bad host {host!r}")
    return Validation(_normalise_url(v, parts.scheme, parts.netloc), IocType.URL, True)


def validate(value: str, expected: IocType | None = None) -> Validation:
    """Refang, classify and check one value.

    With ``expected`` set, a value of another type is reported invalid.
    """
    v = refang(value)
    kind = classify(v)
    if expected is not None and kind is not expected:
        got = kind.value if kind else "unknown"
        return Validation(v, kind, False, f"expected {expected.value}, got {got}")
    if kind is None:
        return Validation(v, None, False, "not a recognised indicator")
    if any(ch.isspace() or not ch.isprintable() for ch in v):
        return Validation(v, kind, False, "contains whitespace or control characters")
    if kind in (IocType.IPV4, IocType.IPV6):
        return Validation(v, kind, True, notes=_ip_notes(v))
    if kind is IocType.URL:
        return _check_url(v)
    if kind is IocType.EMAIL and not _valid_email_local(v.rpartition("@")[0]):
        return Validation(v, kind, False, "bad local part")
    if kind is IocType.CVE:
        year = int(v[4:8])
        if year < 1999:
            return Validation(v, kind, False, "CVE ids start in 1999")
        return Validation(v.upper(), kind, True)
    if kind in (IocType.MD5, IocType.SHA1, IocType.SHA256):
        return Validation(v.lower(), kind, True)
    return Validation(v.lower() if kind is IocType.DOMAIN else v, kind, True)
