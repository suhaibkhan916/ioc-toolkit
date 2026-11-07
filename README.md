# ioctk: IOC toolkit

A typed Python library and command line tool for indicators of compromise (IOCs): defang them so they are safe to paste into a ticket or chat, refang them so tools can use them again, validate them, and extract them from free text such as a threat report.

The point of this lab is the packaging as much as the code: `src` layout, `pyproject.toml`, a `py.typed` marker, `mypy --strict`, `ruff`, and a wheel that the tests run against in CI.

All sample data is **synthetic**. `samples/report.txt` is a made-up analyst note. IPs are in documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and domains use the reserved `.example` and `.test` names. The hashes are MD5, SHA-1 and SHA-256 of the word `test`.

## The problem

IOCs move between people and tools in many shapes. A report says `hxxps://evil[.]example`, another says `evil(dot)example`, a ticket has a version number `1.2.3.4.5` that looks like an IP, and a file name `invoice.pdf` looks like a domain. Copying a live URL into chat can make it clickable. This tool gives one consistent defang style out, accepts many styles in, and checks every value before it calls it an indicator.

| Type | Defanged style written | Checks |
|---|---|---|
| URL | `hxxps://evil[.]example/a.php` (dots only in the host) | scheme http/https/ftp, host is a domain or IP, port in range |
| domain | `evil[.]example` | label rules (1 to 63 chars, no leading or trailing hyphen), TLD letters or `xn--`, not a common file extension |
| IPv4 / IPv6 | `203[.]0[.]113[.]7`, `2001[:]db8[:][:]1` | stdlib `ipaddress`; notes for private, loopback, reserved, documentation range |
| email | `a[@]evil[.]example` | local part characters, domain as above |
| MD5 / SHA-1 / SHA-256 | unchanged | hex and length 32 / 40 / 64 |
| CVE | unchanged | `CVE-YYYY-NNNN+`, year 1999 or later, upper-cased |

`refang` also reads `(.)`, `{.}`, `[dot]`, `(dot)`, ` dot `, `\.`, `[:]//`, `[://]`, `hXXp`, `fxp`, `[at]` and `(at)`.

## How to run

Needs Python 3.10 or later. No third-party packages at run time.

```bash
pip install -e ".[dev]"
ioctk defang https://evil.example/a 203.0.113.7
ioctk refang "hxxps://evil[.]example/a"
ioctk validate 10.20.0.15 invoice.pdf --json
ioctk extract samples/report.txt --defang
ioctk extract samples/report.txt --type url --type ipv4 --json
python -m pytest -q
ruff check . && ruff format --check . && mypy
python -m build                      # dist/ioctk-0.1.1-py3-none-any.whl and the sdist
```

`defang`, `refang` and `validate` read values from the arguments, or one per line from stdin. Exit codes: `0` success, `1` `validate` found an invalid value or `extract` found nothing, `2` usage error or unreadable file.

As a library:

```python
from ioctk import IocType, defang, extract, validate

defang("https://evil.example/a")  # 'hxxps://evil[.]example/a'
validate("10.20.0.15").notes  # ('private',)
[i.value for i in extract(text, [IocType.URL])]
```

## Results

`ioctk extract samples/report.txt --defang` on the synthetic report finds 14 indicators: 1 email, 3 URLs, 3 IPv4, 1 IPv6, 2 domains, 1 of each hash type and 1 CVE. It does not report `stage2.ps1`, `invoice.pdf.exe`, `readme.txt`, the version `1.2.3.4.5`, the time `10.20`, or the host names inside the URLs a second time. The closing bracket after the runbook URL is dropped.

```
$ ioctk validate 10.20.0.15 "hxxps://invoices-portal[.]example/view?id=88" invoice.pdf CVE-1998-0001
ipv4    valid                          10.20.0.15 [private]
url     valid                          https://invoices-portal.example/view?id=88
-       INVALID (not a recognised indicator) invoice.pdf
cve     INVALID (CVE ids start in 1999) CVE-1998-0001
exit code 1
```

Checks run in this build:

- 104 pytest tests pass (Python 3.14 locally on the editable install). Version 0.1.0 had 77 tests and also passed against its built wheel on Python 3.11.
- `mypy --strict` on `src` and `tests`: no issues in 11 files.
- `ruff check` and `ruff format --check`: clean.
- `python -m build` gives `ioctk-0.1.1-py3-none-any.whl` (10 KB) with `ioctk/py.typed` inside.

CI runs lint and type checks once, then builds the wheel on Python 3.10, 3.12 and 3.13, installs it, and runs the tests and the console script against the installed copy. CI has not been run yet because the repo has not been pushed.

## What broke and how it was fixed

- **A version number was read as an IP.** The first run of `extract` on the sample reported `1.2.3.4` from the text `version 1.2.3.4.5`. The IPv4 pattern used `\b`, and a dot counts as a word boundary. Fixed with lookarounds that reject a digit or dot before the match and a digit (or dot then digit) after it, so `203.0.113.45.` at the end of a sentence still matches. Both cases have tests.
- **setuptools deprecation warning on build.** `python -m build` printed a warning that the table form `license = { text = "MIT" }` is deprecated, with a removal date of 2027-02-18. Changed to the SPDX string `license = "MIT"` with `license-files`, and raised the build requirement to `setuptools>=77`. The wheel metadata now has `License-Expression: MIT`.
- **A virtual environment on this machine had no `python.exe`.** `python -m venv .venv` created the folder without the interpreter, so the local checks used the user site-packages instead, and the wheel test used `pip install --target` into a temporary folder. This is a local environment problem, not a project one; CI uses clean runners.

- **Bugs found later by property tests and a code review (fixed in 0.1.1).** The 77 example tests had 97% branch coverage and missed all of these. `http://[` crashed `validate`, `defang` and a whole `extract` run. `http://[2001:db8::1]` lost its closing bracket and came back as a bare IP. `::ffff:0.0.0.0` was reported as `::ffff:0`, a different address nobody wrote. Bad dots in email local parts passed, and a leading hyphen was dropped. Values holding a newline or space passed, because `$` also matches before a final newline and nothing checked the characters. CVE ids accepted digits from other scripts. `the dot com` in prose invented the domain `the.com`. Printing an unusual character crashed the CLI on a cp1252 console. Each has a regression test.

## Limitations

- File extensions are excluded as TLDs. `.zip` and `.mov` are real TLDs, so a real domain such as `something.zip` is missed. This is a deliberate trade-off for fewer false positives in prose.
- Domains are checked by shape, not against the public suffix list, so `anything.notatld` passes as long as the TLD is letters.
- A domain that appears only inside a URL is not listed as a separate domain. Block lists that want both need to parse the URL host themselves.
- IPv6 extraction from prose is loose and is checked by `ipaddress` afterwards.
- `extract` does not read a spaced ` dot ` in prose, because that would turn ordinary words into a domain. So `evil dot example` in a report is missed, while `refang` on a single value still reads it.
- Defanged URLs keep dots in the path and query on purpose, so file names stay readable. Only the host is defanged.
- No hash type beyond MD5, SHA-1 and SHA-256 (no SHA-512, ssdeep or imphash).

## Layout

```
src/ioctk/types.py      IocType, Ioc, Validation (frozen dataclasses)
src/ioctk/defang.py     defang, refang
src/ioctk/validate.py   classify, validate
src/ioctk/extract.py    extract from text
src/ioctk/cli.py        argparse CLI and exit codes
src/ioctk/py.typed      marker so type checkers use the inline types
samples/report.txt      synthetic analyst note
tests/                  pytest
docs/DESIGN_NOTES.md    design decisions
```

## Licence

MIT, see LICENSE.
