import pytest

from ioctk import IocType, classify, validate


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("203.0.113.7", IocType.IPV4),
        ("2001:db8::1", IocType.IPV6),
        ("evil.example", IocType.DOMAIN),
        ("xn--bcher-kva.example", IocType.DOMAIN),
        ("https://evil.example/a", IocType.URL),
        ("a@evil.example", IocType.EMAIL),
        ("098f6bcd4621d373cade4e832627b4f6", IocType.MD5),
        ("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", IocType.SHA1),
        ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", IocType.SHA256),
        ("CVE-2026-12345", IocType.CVE),
        ("cve-2021-44228", IocType.CVE),
    ],
)
def test_classify(value: str, kind: IocType) -> None:
    assert classify(value) is kind


@pytest.mark.parametrize(
    "value",
    ["", "hello", "invoice.pdf", "stage2.ps1", "readme.txt", "256.1.1.1", "-bad.example", "a..b"],
)
def test_classify_rejects(value: str) -> None:
    assert classify(value) is None


def test_validate_refangs_first() -> None:
    r = validate("203[.]0[.]113[.]7")
    assert r.valid and r.type is IocType.IPV4 and r.value == "203.0.113.7"


def test_ip_notes() -> None:
    assert "private" in validate("10.20.0.15").notes
    assert "loopback" in validate("127.0.0.1").notes
    assert "documentation range" in validate("198.51.100.23").notes
    assert validate("8.8.8.8").notes == ()


def test_expected_type_mismatch() -> None:
    r = validate("evil.example", IocType.IPV4)
    assert not r.valid and r.reason == "expected ipv4, got domain"


def test_url_checks() -> None:
    assert validate("hxxps://evil[.]example/a").valid
    assert not validate("javascript://evil.example").valid
    assert validate("http://evil.example:99999/").reason == "bad port"
    assert validate("http://bad_host.example/").reason == "bad host 'bad_host.example'"
    assert "documentation range" in validate("http://203.0.113.9/x").notes


def test_email_local_part() -> None:
    assert validate("a.b+tag@evil.example").valid
    assert not validate('a"b@evil.example').valid


def test_cve_normalised_and_year_checked() -> None:
    assert validate("cve-2021-44228").value == "CVE-2021-44228"
    assert not validate("CVE-1998-0001").valid


def test_hash_lowercased() -> None:
    assert validate("098F6BCD4621D373CADE4E832627B4F6").value == "098f6bcd4621d373cade4e832627b4f6"


def test_domain_lowercased() -> None:
    assert validate("Evil.Example").value == "evil.example"


def test_to_dict() -> None:
    d = validate("nope").to_dict()
    assert d == {"value": "nope", "type": None, "valid": False,
                 "reason": "not a recognised indicator", "notes": []}  # fmt: skip


def test_malformed_url_is_invalid_not_a_crash() -> None:
    """Found by property tests. One such URL used to stop a whole extract run."""
    for broken in ("http://[", "http://[]"):
        assert validate(broken).valid is False


def test_email_local_part_dots() -> None:
    """Found by property tests: these used to validate."""
    for bad in (".a@x.example", "a.@x.example", "a..b@x.example"):
        assert validate(bad).valid is False
    assert validate("a.b@x.example").valid is True
