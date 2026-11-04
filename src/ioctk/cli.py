"""Command line interface.

  ioctk defang VALUE...       (or read lines from stdin)
  ioctk refang VALUE...
  ioctk validate VALUE... [--type ipv4] [--json]
  ioctk extract FILE|- [--type url --type domain] [--json] [--defang]

Exit codes: 0 success, 1 validate found an invalid value (or extract found
nothing), 2 usage error or unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ioctk import __version__
from ioctk.defang import defang, refang
from ioctk.extract import extract
from ioctk.types import IocType
from ioctk.validate import validate

EXIT_OK, EXIT_FINDING, EXIT_USAGE = 0, 1, 2


def _values(args: argparse.Namespace) -> list[str]:
    if args.values:
        return list(args.values)
    return [line.strip() for line in sys.stdin if line.strip()]


def _type(text: str) -> IocType:
    try:
        return IocType(text.lower())
    except ValueError:
        names = ", ".join(t.value for t in IocType)
        raise argparse.ArgumentTypeError(f"unknown type {text!r} (use {names})") from None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ioctk", description="Defang, refang, validate, extract IOCs.")
    p.add_argument("--version", action="version", version=f"ioctk {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    for name in ("defang", "refang"):
        s = sub.add_parser(name, help=f"{name} values (args or stdin, one per line)")
        s.add_argument("values", nargs="*")

    v = sub.add_parser("validate", help="check values; exit 1 if any is invalid")
    v.add_argument("values", nargs="*")
    v.add_argument("--type", type=_type, help="require this type")
    v.add_argument("--json", action="store_true")

    e = sub.add_parser("extract", help="pull indicators out of a text file ('-' for stdin)")
    e.add_argument("file")
    e.add_argument("--type", type=_type, action="append", dest="types", help="repeatable")
    e.add_argument("--json", action="store_true")
    e.add_argument("--defang", action="store_true", help="print values defanged")
    return p


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 2 on errors, 0 on --help
        return int(exc.code or 0)

    if args.command in ("defang", "refang"):
        fn = defang if args.command == "defang" else refang
        for value in _values(args):
            print(fn(value))
        return EXIT_OK

    if args.command == "validate":
        results = [validate(value, args.type) for value in _values(args)]
        if args.json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for r in results:
                kind = r.type.value if r.type else "-"
                status = "valid" if r.valid else f"INVALID ({r.reason})"
                notes = f" [{', '.join(r.notes)}]" if r.notes else ""
                print(f"{kind:7} {status:30} {r.value}{notes}")
        return EXIT_OK if all(r.valid for r in results) else EXIT_FINDING

    try:
        text = _read(args.file)
    except OSError as exc:
        print(f"ioctk: cannot read {args.file}: {exc.strerror}", file=sys.stderr)
        return EXIT_USAGE
    iocs = extract(text, args.types)
    if args.json:
        rows = [
            {"type": i.type.value, "value": defang(i.value, i.type) if args.defang else i.value}
            for i in iocs
        ]
        print(json.dumps(rows, indent=2))
    else:
        for i in iocs:
            shown = defang(i.value, i.type) if args.defang else i.value
            print(f"{i.type.value}\t{shown}")
    return EXIT_OK if iocs else EXIT_FINDING


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
