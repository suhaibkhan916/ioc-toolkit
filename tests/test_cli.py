import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ioctk.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "report.txt"


def test_defang_args(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["defang", "https://evil.example/a", "203.0.113.7"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "hxxps://evil[.]example/a",
        "203[.]0[.]113[.]7",
    ]


def test_refang_stdin(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("evil[.]example\n\nhxxp://a[.]example\n"))
    assert main(["refang"]) == 0
    assert capsys.readouterr().out.splitlines() == ["evil.example", "http://a.example"]


def test_validate_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "203.0.113.7", "evil.example"]) == 0
    assert main(["validate", "203.0.113.7", "nope"]) == 1
    assert main(["validate", "--type", "ipv4", "evil.example"]) == 1
    out = capsys.readouterr().out
    assert "INVALID (expected ipv4, got domain)" in out


def test_validate_json(capsys: pytest.CaptureFixture[str]) -> None:
    main(["validate", "--json", "10.20.0.15"])
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["type"] == "ipv4" and "private" in rows[0]["notes"]


def test_unknown_type_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "--type", "hostname", "x"]) == 2
    assert "unknown type 'hostname'" in capsys.readouterr().err


def test_extract_file_defanged_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["extract", str(SAMPLE), "--type", "url", "--json", "--defang"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0] == {"type": "url", "value": "hxxps://invoices-portal[.]example/view?id=88"}
    assert len(rows) == 3


def test_extract_nothing_found_exits_1(tmp_path: Path) -> None:
    f = tmp_path / "clean.txt"
    f.write_text("nothing to see here", encoding="utf-8")
    assert main(["extract", str(f)]) == 1


def test_extract_missing_file_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["extract", "no/such/file.txt"]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_extract_reads_utf8_bom(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "bom.txt"
    f.write_bytes(b"\xef\xbb\xbfevil[.]example\n")
    assert main(["extract", str(f)]) == 0
    assert capsys.readouterr().out == "domain\tevil.example\n"


def test_module_entry_point() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "ioctk", "defang", "evil.example"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "evil[.]example"
