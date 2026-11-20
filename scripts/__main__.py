import argparse
import os
import struct
import sys
from pathlib import Path

lazy import capstone
lazy import pefile

from .analysis import FORMATS, Inspector
from .output import Output, OutputClosed
from .sources import PE, coordinate, integer

COMMANDS = {
    "info": "File identity, sections, imports, and exports",
    "find": "Search for text, byte patterns, or numbers",
    "refs": "Find instructions and stored pointers that refer to an address, or instructions that use a displacement",
    "disasm": "Disassemble a byte range or a whole function",
    "data": "Read values or a pointer table",
    "rtti": "Find the virtual function tables of a class by name",
    "describe": "Say what an address holds: its function and class slots, a string, an import, or an export",
}
ADDRESSES = "rva:N, va:N, or offset:N; - reads the leading address of each line on standard input"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        text = f"error: {message} (see {self.prog} --help)"
        print(text)
        print(text, file=sys.stderr)
        raise SystemExit(2)


def number(text):
    try:
        return integer(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def signed_number(text):
    try:
        return integer(text, signed=True)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parser():
    root = Parser(prog="inspector", description="Read-only inspection of AMD64 code and data in PE files.")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in COMMANDS.items():
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument("--file", type=Path, required=True, help="AMD64 PE32+ executable or DLL")
        command.add_argument("--jsonl", action="store_true", help="Print JSON records instead of text lines")
        if name != "data":
            command.add_argument(
                "--limit", type=number, default=100, help="Results shown per query (1..10000; default 100)"
            )
        if name in ("find", "refs"):
            command.add_argument("--section", help="Search only this section, by exact name")
            command.add_argument("--start", help="Search start: rva:N, va:N, or offset:N; requires --length")
            command.add_argument("--length", type=number, help="Search byte count; requires --start")
        if name == "find":
            terms = command.add_mutually_exclusive_group(required=True)
            terms.add_argument("--text", action="append", help="Text to find; repeat for several")
            terms.add_argument("--pattern", action="append", help="Space-separated bytes with ?? wildcards")
            terms.add_argument("--value", action="append", help="Number, encoded according to --type")
            command.add_argument("--encoding", choices=("ascii", "utf-16le", "both"), default="ascii")
            command.add_argument("--ignore-case", action="store_true", help="Match text in any letter case")
            command.add_argument("--type", choices=FORMATS, default="u32")
        elif name == "refs":
            command.add_argument("addresses", nargs="*", help=f"Targets: {ADDRESSES}")
            command.add_argument(
                "--displacement", type=signed_number, help="Nonzero signed memory displacement"
            )
            command.add_argument(
                "--kind", choices=("all", "call", "branch", "memory", "pointer"), default="all"
            )
        elif name in ("disasm", "data", "describe"):
            command.add_argument("addresses", nargs="+", help=ADDRESSES)
            if name == "disasm":
                bounds = command.add_mutually_exclusive_group()
                bounds.add_argument(
                    "--bytes", type=number, help="Exact byte count; default up to 256 (maximum 1 MiB)"
                )
                bounds.add_argument(
                    "--function", action="store_true", help="The whole function that holds the address"
                )
                command.add_argument(
                    "--show-bytes", action="store_true", help="Show the bytes of each instruction"
                )
            elif name == "data":
                command.add_argument("--type", choices=FORMATS, default="u8")
                command.add_argument("--count", type=number, default=16, help="Values to read (1..4096)")
        elif name == "rtti":
            command.add_argument(
                "names", nargs="+", help="Class name: Actor, BSScript::Object, or .?AVActor@@"
            )
            command.add_argument("--slot-start", type=number, default=0)
            command.add_argument("--slots", type=number, default=16, help="Slots shown per table (1..1024)")
    return root


def lines(tokens, stream):
    """Yield (kind, text) for each query; `-` takes them from the text lines another command printed."""
    for token in tokens:
        if token != "-":
            yield "query", token
            continue
        for raw in stream:
            text = raw.rstrip("\r\n").lstrip("\ufeff")
            if not text.strip():
                continue
            if text.startswith("#"):
                yield "note", text
            elif text.startswith("error:"):
                yield "error", text
            elif text.lstrip().startswith("{"):
                raise ValueError("Standard input is JSONL; pipe the default text lines instead")
            else:
                first = text.split(None, 1)[0]
                try:
                    coordinate(first)
                except ValueError:
                    yield "malformed", text
                else:
                    yield "query", first


class Run:
    def __init__(self, args, inspector, out):
        self.args = args
        self.inspector = inspector
        self.source = inspector.source
        self.out = out
        self.failed = False
        self.listed = {}

    def summary(self, query, fields):
        record = {"record": "summary", "command": self.args.command, "query": query, **fields}
        record["warning"] = self.source.packed
        if self.out.jsonl:
            record.update(file=str(self.source.path), sha256=self.source.sha256)
        self.out.emit(record)

    def error(self, query, message):
        self.failed = True
        self.out.emit({"record": "error", "query": query, "message": str(message)})

    def answer(self, query, compute, key=None):
        """Print what one query returns; an answer already printed in this call is referred to, not repeated."""
        try:
            if key is not None:
                identity, fields = key(query)
                if identity in self.listed:
                    self.summary(query, {**fields, "listed_under": self.listed[identity]})
                    return
            answers = compute(query)
        except (ValueError, struct.error, OverflowError, capstone.CsError) as exc:
            self.error(query, exc)
            return
        if key is not None:
            self.listed[identity] = query
        for fields, rows in answers:
            self.summary(query, fields)
            for row in rows:
                self.out.emit({"record": "result", "query": query, **row})

    def addresses(self, compute, key):
        for kind, text in lines(self.args.addresses, sys.stdin):
            if kind == "query":
                self.answer(text, compute, key)
            elif kind == "note":
                self.out.emit({"record": "note", "text": text})
            elif kind == "error":
                self.failed = True
                self.out.emit({"record": "error", "message": text.removeprefix("error:").strip()})
            else:
                self.error(None, f"Not an address line: {text[:80]}")

    def located(self, query):
        return self.source.locate(query), {}

    def function(self, query):
        found = self.inspector.functions.function(self.source.va(query))
        return found.start, {"function": self.source.show(found.start)}

    def __call__(self):
        args, inspector = self.args, self.inspector
        limit = getattr(args, "limit", None)
        if limit is not None and not 1 <= limit <= 10000:
            raise ValueError("--limit must be 1..10000")
        scope = {name: getattr(args, name, None) for name in ("section", "start", "length")}
        if args.command == "info":
            for part, answer in inspector.info(limit=limit).items():
                self.answer(part, lambda _: [answer])
        elif args.command == "find":
            options = {
                "encoding": args.encoding,
                "ignore_case": args.ignore_case,
                "limit": limit,
                "scope": scope,
            }
            for term in args.text or ():
                self.answer(term, lambda term: inspector.find(text=term, **options))
            for term in args.pattern or ():
                self.answer(term, lambda term: inspector.find(pattern=term, **options))
            for term in args.value or ():
                self.answer(term, lambda term: inspector.find(value=term, value_type=args.type, **options))
        elif args.command == "refs":
            if bool(args.addresses) == (args.displacement is not None):
                raise ValueError("Give addresses or --displacement, not both")
            options = {"kind": args.kind, "limit": limit, "scope": scope}
            if args.displacement is not None:
                compute = lambda _: inspector.refs(displacement=args.displacement, **options)  # noqa: E731
                self.answer(f"displacement {args.displacement:#x}", compute)
            else:
                self.addresses(lambda address: inspector.refs(address, **options), self.located)
        elif args.command == "disasm":
            self.addresses(
                lambda address: inspector.disasm(
                    address,
                    byte_count=args.bytes,
                    function=args.function,
                    limit=limit,
                    show_bytes=args.show_bytes,
                ),
                self.function if args.function else self.located,
            )
        elif args.command == "data":
            self.addresses(
                lambda address: inspector.data(address, value_type=args.type, count=args.count), self.located
            )
        elif args.command == "describe":
            self.addresses(lambda address: inspector.describe(address, limit=limit), self.located)
        else:
            for name in args.names:
                self.answer(
                    name,
                    lambda name: inspector.rtti(
                        name, slots=args.slots, slot_start=args.slot_start, limit=limit
                    ),
                )
        return 1 if self.failed else 0


def main(argv=None):
    args = parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    out = Output(sys.stdout, args.jsonl)
    try:
        try:
            code = Run(args, Inspector(PE(args.file)), out)()
        except (OSError, ValueError, struct.error, OverflowError, pefile.PEFormatError) as exc:
            # The whole call failed: say so on both streams, because either one may be discarded.
            out.emit({"record": "error", "message": str(exc)})
            print(f"error: {exc}", file=sys.stderr)
            code = 1
        out.flush()
        return code
    except OutputClosed:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # nothing more can be written
        return 0


if __name__ == "__main__":
    sys.exit(main())
