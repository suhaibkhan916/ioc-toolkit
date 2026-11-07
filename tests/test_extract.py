from pathlib import Path

from ioctk import Ioc, IocType, extract

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "report.txt"


def test_sample_report_finds_every_planted_indicator() -> None:
    found = extract(SAMPLE.read_text(encoding="utf-8"))
    assert found == [
        Ioc(IocType.EMAIL, "billing@invoices-portal.example"),
        Ioc(IocType.URL, "https://invoices-portal.example/view?id=88"),
        Ioc(IocType.URL, "http://cdn-update.test:8080/kit/stage2.php"),
        Ioc(IocType.IPV4, "203.0.113.45"),
        Ioc(IocType.IPV4, "198.51.100.23"),
        Ioc(IocType.IPV6, "2001:db8:0:1::25"),
        Ioc(IocType.DOMAIN, "update-check.example"),
        Ioc(IocType.SHA256, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        Ioc(IocType.SHA1, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"),
        Ioc(IocType.MD5, "098f6bcd4621d373cade4e832627b4f6"),
        Ioc(IocType.CVE, "CVE-2026-12345"),
        Ioc(IocType.IPV4, "10.20.0.15"),
        Ioc(IocType.DOMAIN, "fileserver.corp.test"),
        Ioc(IocType.URL, "https://wiki.corp.test/ir/runbook"),
    ]


def test_version_number_is_not_an_ip() -> None:
    assert extract("upgrade to 1.2.3.4.5 today") == []


def test_ip_at_end_of_sentence() -> None:
    assert extract("It called 203.0.113.45.") == [Ioc(IocType.IPV4, "203.0.113.45")]


def test_file_names_are_not_domains() -> None:
    assert extract("opened invoice.pdf.exe and stage2.ps1") == []


def test_url_host_not_reported_twice() -> None:
    assert extract("see https://evil.example/x") == [Ioc(IocType.URL, "https://evil.example/x")]


def test_url_trailing_punctuation() -> None:
    text = "(see https://a.example/x). Also https://b.example/wiki_(page), done"
    assert [i.value for i in extract(text)] == [
        "https://a.example/x",
        "https://b.example/wiki_(page)",
    ]


def test_duplicates_removed_and_order_kept() -> None:
    text = "b.example then a.example then b[.]example again"
    assert [i.value for i in extract(text)] == ["b.example", "a.example"]


def test_type_filter() -> None:
    found = extract(SAMPLE.read_text(encoding="utf-8"), [IocType.IPV4])
    assert [i.value for i in found] == ["203.0.113.45", "198.51.100.23", "10.20.0.15"]


def test_hash_inside_longer_hex_is_ignored() -> None:
    assert extract("a" * 70) == []


def test_empty_text() -> None:
    assert extract("") == []
    assert extract("   \n") == []


def test_malformed_url_does_not_stop_the_run() -> None:
    """Found by property tests."""
    found = extract("bad http://[ then good 203.0.113.7")
    assert Ioc(IocType.IPV4, "203.0.113.7") in found


def test_url_with_ipv6_host_keeps_its_closing_bracket() -> None:
    """Found by property tests. It used to come back as the bare address."""
    assert extract("see http://[2001:db8::1]") == [Ioc(IocType.URL, "http://[2001:db8::1]")]


def test_bracket_around_a_url_is_still_dropped() -> None:
    assert extract("[http://a.example/x]") == [Ioc(IocType.URL, "http://a.example/x")]


def test_ipv4_mapped_ipv6_is_one_address() -> None:
    """Found by property tests. It used to give ::ffff:0 and 0.0.0.0, and the first is a
    different address that nobody wrote."""
    assert extract("from ::ffff:192.0.2.1 today") == [Ioc(IocType.IPV6, "::ffff:192.0.2.1")]


def test_broken_dotted_ipv6_gives_no_wrong_address() -> None:
    assert [i for i in extract("x ::ffff:0.0.0 y") if i.type is IocType.IPV6] == []


def test_ipv6_at_the_end_of_a_sentence_still_matches() -> None:
    assert extract("came from 2001:db8::1.") == [Ioc(IocType.IPV6, "2001:db8::1")]


def test_colon_before_an_ipv4_still_matches() -> None:
    assert extract("src:203.0.113.7") == [Ioc(IocType.IPV4, "203.0.113.7")]


def test_email_starting_with_a_hyphen_keeps_it() -> None:
    """Found by property tests: the hyphen was dropped, which gave a different address."""
    assert extract("from -x@a.example") == [Ioc(IocType.EMAIL, "-x@a.example")]
