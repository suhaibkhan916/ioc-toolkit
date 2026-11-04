import pytest

from ioctk import IocType, defang, refang


@pytest.mark.parametrize(
    ("live", "defanged"),
    [
        ("https://evil.example/a.php", "hxxps://evil[.]example/a.php"),
        ("http://evil.example:8080/x?q=1.2", "hxxp://evil[.]example:8080/x?q=1.2"),
        ("ftp://files.example/drop.zip", "fxp://files[.]example/drop.zip"),
        ("evil.example", "evil[.]example"),
        ("203.0.113.7", "203[.]0[.]113[.]7"),
        ("2001:db8::1", "2001[:]db8[:][:]1"),
        ("billing@invoices.example", "billing[@]invoices[.]example"),
        ("http://[2001:db8::1]:8080/x", "hxxp://[2001[:]db8[:][:]1]:8080/x"),
    ],
)
def test_defang_and_back(live: str, defanged: str) -> None:
    assert defang(live) == defanged
    assert refang(defanged) == live


def test_defang_is_idempotent() -> None:
    once = defang("https://evil.example/a")
    assert defang(once) == once


def test_hashes_and_cves_are_left_alone() -> None:
    md5 = "098f6bcd4621d373cade4e832627b4f6"
    assert defang(md5) == md5
    assert defang("CVE-2026-12345") == "CVE-2026-12345"


def test_unknown_value_still_loses_its_dots() -> None:
    assert defang("not a real.thing") == "not a real[.]thing"


def test_type_hint_overrides_guess() -> None:
    assert defang("evil.example", IocType.DOMAIN) == "evil[.]example"


@pytest.mark.parametrize(
    "styled",
    [
        "evil[.]example",
        "evil(.)example",
        "evil{.}example",
        "evil[dot]example",
        "evil(DOT)example",
        "evil dot example",
        "evil [.] example",
        "evil\\.example",
    ],
)
def test_refang_dot_styles(styled: str) -> None:
    assert refang(styled) == "evil.example"


@pytest.mark.parametrize(
    "styled",
    [
        "hxxps://evil[.]example/a",
        "hXXps://evil[.]example/a",
        "https[:]//evil[.]example/a",
        "hxxps[://]evil[.]example/a",
    ],
)
def test_refang_scheme_styles(styled: str) -> None:
    assert refang(styled) == "https://evil.example/a"


@pytest.mark.parametrize("styled", ["a[@]evil.example", "a[at]evil.example", "a (at) evil.example"])
def test_refang_at_styles(styled: str) -> None:
    assert refang(styled) == "a@evil.example"


def test_refang_leaves_live_text_alone() -> None:
    text = "https://evil.example/path"
    assert refang(text) == text


def test_refang_does_not_touch_words_that_contain_dot() -> None:
    assert refang("dotnet.example") == "dotnet.example"
