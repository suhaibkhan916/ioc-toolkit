"""Core types shared by every module."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IocType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


@dataclass(frozen=True)
class Ioc:
    """One indicator in its refanged (live) form."""

    type: IocType
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type.value, "value": self.value}


@dataclass(frozen=True)
class Validation:
    """Result of checking one string."""

    value: str
    type: IocType | None
    valid: bool
    reason: str = ""
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "type": self.type.value if self.type else None,
            "valid": self.valid,
            "reason": self.reason,
            "notes": list(self.notes),
        }
