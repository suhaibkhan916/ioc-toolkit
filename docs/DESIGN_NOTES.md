# Design notes

## Package layout

- **`src` layout.** The package lives in `src/ioctk`, not at the repo root. Running `pytest` from the root then cannot import the source folder by accident, so tests only pass if the package is installed. CI installs the built wheel and runs the tests against it, which catches files missing from the wheel (for example `py.typed`).
- **`pyproject.toml` only.** No `setup.py` or `setup.cfg`. Build backend is setuptools 77 or later so the licence can be an SPDX string.
- **`py.typed` marker (PEP 561).** Without it, mypy treats an installed package as untyped, and the strict type hints help nobody downstream.
- **No run-time dependencies.** `re`, `ipaddress` and `urllib.parse` cover everything. Dev tools are in the `dev` extra.

## Types

- `IocType` is a `str` enum, so values print and serialise as plain strings (`"ipv4"`) and the CLI can turn `--type ipv4` into a member with `IocType("ipv4")`.
- `Ioc` and `Validation` are frozen dataclasses. Frozen means they can go in sets and cannot be changed after a check has run.
- `mypy --strict` covers the tests too. That forces typed fixtures (`pytest.CaptureFixture[str]`) and keeps test helpers honest.

## Behaviour

- **One output style, many input styles.** `defang` always writes `[.]`, `[@]`, `[:]` and `hxxp`. `refang` accepts the common variants. Being strict in what you write and loose in what you read keeps tickets consistent.
- **`defang` refangs first.** That makes it idempotent: running it on an already defanged value does not give `evil[[.]]example`.
- **Only the URL host is defanged.** The host is what makes a link live. Leaving dots in the path keeps file names readable.
- **Extraction is loose, validation is strict.** Each regex is wide on purpose, and every match goes through `validate(..., expected=type)` before it is kept. This keeps the regexes readable and puts the real rules in one tested place.
- **Patterns run in a fixed order: URL, email, CVE, hashes, IPs, domains.** A span taken by an earlier type is skipped by later ones, so a URL's host is not reported again as a domain and a SHA-256 is not also reported as part of a shorter hash.
- **File-extension TLD list.** Prose is full of file names. Excluding common extensions as TLDs removes most false domains, at the cost of missing real `.zip` and `.mov` domains. The list is a module constant so it can be changed.
- **IP notes, not rejection.** A private or documentation IP is still a valid IP. The note lets the analyst decide; an internal IP in a report is often the victim, not the attacker.

## CLI

- `argparse` with subcommands. `main(argv)` returns an int instead of calling `sys.exit`, so tests call it directly and check the return code.
- Exit `1` means "the check found something worth attention" (an invalid value, or no indicators). Exit `2` means the run itself failed. A script can tell them apart.
- Files are read as `utf-8-sig` so a BOM from Windows editors does not end up inside the first indicator.

## Next steps

- Public suffix list check for domains (optional dependency).
- STIX 2.1 or MISP JSON output for the extract command.
- Property-based tests: `refang(defang(x)) == x` for generated domains, URLs and IPs (planned as the next lab).
