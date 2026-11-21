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
lazy from .process import Live

COMMANDS = {
    "info": "Identity, sections, imports, and exports; for a process, also its loaded modules",
    "find": "Search for text, byte patterns, or numbers",
    "refs": "Find instructions and stored pointers that refer to an address, or instructions that use a displacement",
    "disasm": "Disassemble a byte range or a whole function",
    "data": "Read values or a pointer table",
    "rtti": "Find the virtual function tables of a class by name",
    "describe": "Say what an address holds: its function and class slots, a string, an import, or an export",
    "snapshot": "Save a module of a running process as a file that the other commands read with --file",
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


class File:
    """A file is one source: every address is in it."""

    note = None

    def __init__(self, path):
        self.home = Inspector(PE(path))

    def inspector(self, address):
        return self.home, address

    def close(self):
        pass


def parser():
    root = Parser(
        prog="inspector",
        description="Read-only inspection of AMD64 code and data in PE files and running processes.",
    )
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in COMMANDS.items():
        command = commands.add_parser(name, help=help_text, description=help_text)
        source = command.add_mutually_exclusive_group(required=True)
        if name != "snapshot":
            source.add_argument(
                "--file", type=Path, help="AMD64 PE32+ executable or DLL, or a module saved by snapshot"
            )
        source.add_argument("--process", help="Running process: the name of its executable, or its PID")
        command.add_argument(
            "--module",
            help="With --process: the loaded module to work on, by name (default: the process's executable)",
        )
        command.add_argument("--jsonl", action="store_true", help="Print JSON records instead of text lines")
        if name == "snapshot":
            command.add_argument(
                "--output", type=Path, required=True, help="File to write; never overwritten"
            )
            continue
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
                "--displacement",
                type=signed_number,
                action="append",
                help="Nonzero signed memory displacement; repeat for several",
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
                    "--before", type=number, default=0, help="Also show this many bytes before the address"
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
    def __init__(self, args, view, out):
        self.args = args
        self.view = view
        self.home = view.home  # the inspector of the file, or of the module that commands work on
        self.out = out
        self.failed = False
        self.listed = {}

    def summary(self, query, fields, source):
        record = {"record": "summary", "command": self.args.command, "query": query, **fields}
        # A read of unreadable bytes fails where it is asked for; a search would only come back with less,
        # and so would anything that names what an address holds once the tables it uses are affected.
        searched = self.args.command not in ("disasm", "data") or source.damaged
        record["warning"] = "; ".join(filter(None, (source.packed, searched and source.unread))) or None
        if self.out.jsonl:
            for key, value in source.identity.items():  # a field the answer states itself stays its own
                record.setdefault(key, value)
        self.out.emit(record)

    def error(self, query, message):
        self.failed = True
        self.out.emit({"record": "error", "query": query, "message": str(message)})

    def answer(self, query, compute, key=None, inspector=None):
        """Print what one query returns; an answer already printed in this call is referred to, not repeated."""
        source = (inspector or self.home).source
        try:
            if key is not None:
                identity, fields = key(query)
                if identity in self.listed:
                    self.summary(query, {**fields, "listed_under": self.listed[identity]}, source)
                    return
            answers = compute(query)
        except (ValueError, struct.error, OverflowError, capstone.CsError) as exc:
            self.error(query, exc)
            return
        if key is not None:
            self.listed[identity] = query
        for fields, rows in answers:
            self.summary(query, fields, source)
            for row in rows:
                self.out.emit({"record": "result", "query": query, **row})

    def addresses(self, command, key, anywhere=True):
        """Answer each address with `command(inspector, address)`.

        `anywhere` reads an address where it is; in a process that can be outside the module. Without it
        the module is what gets searched, and the address is only what is searched for.
        """
        for kind, text in lines(self.args.addresses, sys.stdin):
            if kind == "query":
                try:
                    inspector, address = self.view.inspector(text) if anywhere else (self.home, text)
                except ValueError as exc:
                    self.error(text, exc)
                    continue
                self.answer(
                    text, lambda _: command(inspector, address), lambda _: key(inspector, address), inspector
                )
            elif kind == "note":
                self.out.emit({"record": "note", "text": text})
            elif kind == "error":
                self.failed = True
                self.out.emit({"record": "error", "message": text.removeprefix("error:").strip()})
            else:
                self.error(None, f"Not an address line: {text[:80]}")

    @staticmethod
    def located(inspector, address):
        return inspector.source.locate(address), {}

    @staticmethod
    def function(inspector, address):
        found = inspector.functions.function(inspector.source.va(address))
        return found.start, {"function": inspector.source.show(found.start)}

    def __call__(self):
        args, inspector = self.args, self.home
        limit = getattr(args, "limit", None)
        if limit is not None and not 1 <= limit <= 10000:
            raise ValueError("--limit must be 1..10000")
        scope = {name: getattr(args, name, None) for name in ("section", "start", "length")}
        if self.view.note:
            self.out.emit({"record": "note", "text": self.view.note})
        if args.command == "snapshot":  # a copy that cannot be saved fails the whole call
            self.summary(inspector.source.name, self.view.save(args.output), inspector.source)
        elif args.command == "info":
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
                for displacement in args.displacement:
                    self.answer(
                        f"displacement {displacement:#x}",
                        lambda _: inspector.refs(displacement=displacement, **options),
                    )
            else:
                self.addresses(
                    lambda inspector, address: inspector.refs(address, **options),
                    self.located,
                    anywhere=False,
                )
        elif args.command == "disasm":
            self.addresses(
                lambda inspector, address: inspector.disasm(
                    address,
                    byte_count=args.bytes,
                    before=args.before,
                    function=args.function,
                    limit=limit,
                    show_bytes=args.show_bytes,
                ),
                self.function if args.function else self.located,
            )
        elif args.command == "data":
            self.addresses(
                lambda inspector, address: inspector.data(address, value_type=args.type, count=args.count),
                self.located,
            )
        elif args.command == "describe":
            self.addresses(lambda inspector, address: inspector.describe(address, limit=limit), self.located)
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
        view = None
        try:
            if args.module is not None and args.process is None:
                raise ValueError("--module names a module of a running process; give --process with it")
            view = File(args.file) if args.process is None else Live(args.process, args.module)
            code = Run(args, view, out)()
        except (OSError, ValueError, struct.error, OverflowError, pefile.PEFormatError) as exc:
            # The whole call failed: say so on both streams, because either one may be discarded.
            out.emit({"record": "error", "message": str(exc)})
            print(f"error: {exc}", file=sys.stderr)
            code = 1
        finally:
            if view is not None:
                view.close()
        out.flush()
        return code
    except OutputClosed:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # nothing more can be written
        return 0


if __name__ == "__main__":
    sys.exit(main())
