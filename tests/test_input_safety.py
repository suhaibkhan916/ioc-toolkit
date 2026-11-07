"""Regression tests from a code review: hostile characters in indicators."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import ioctk
from ioctk import Ioc, IocType, classify, extract, refang, validate

ARABIC_TWO = chr(0x662)


@pytest.mark.parametrize(
    "value",
    [
        "a\n.example",
        "a\n@x.example",
        "x@a\n.example",
        "http://a.example/x\ny",
        "http://a.example/a b",
        "http://a.example/x\ty",
        "http://a.example/" + chr(0x2028) + "x",
        "http://a.example/" + chr(0) + "x",
    ],
)
def test_whitespace_or_control_characters_are_not_valid(value: str) -> None:
    assert validate(value).valid is False


def test_cve_digits_must_be_ascii() -> None:
    assert validate(f"CVE-{ARABIC_TWO * 4}-1234").valid is False
    assert validate("CVE-2024-1234").valid is True


def test_url_scheme_and_host_are_lower_cased_and_the_rest_kept() -> None:
    result = validate("HTTP://User:Pw@A.Example:8080/Path?Q=1")
    assert result.valid is True
    assert result.value == "http://User:Pw@a.example:8080/Path?Q=1"


def test_url_with_upper_case_host_is_not_listed_twice() -> None:
    found = extract("http://A.example/x and http://a.example/x")
    assert found == [Ioc(IocType.URL, "http://a.example/x")]


def test_prose_with_the_word_dot_does_not_invent_a_domain() -> None:
    assert extract("click the dot com link") == []


def test_bracketed_dot_in_prose_is_still_read() -> None:
    assert extract("seen at evil[dot]example today") == [Ioc(IocType.DOMAIN, "evil.example")]


def test_refang_of_one_value_still_reads_a_spaced_dot() -> None:
    assert refang("evil dot example") == "evil.example"


def test_cli_does_not_crash_on_a_console_that_cannot_print_the_value() -> None:
    env = dict(
        os.environ,
        PYTHONIOENCODING="cp1252",
        PYTHONPATH=str(Path(ioctk.__file__).resolve().parents[1]),
    )
    result = subprocess.run(
        [sys.executable, "-m", "ioctk", "validate", f"CVE-{ARABIC_TWO * 4}-1234"],
        env=env,
        capture_output=True,
    )
    assert result.returncode == 1, result.stderr


def test_classify_does_not_call_a_value_with_an_inner_newline_a_domain() -> None:
    """validate would refuse it anyway, but classify is public too."""
    assert classify("a\n.example") is None
