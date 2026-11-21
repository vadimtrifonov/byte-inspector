"""The commands. Each returns answers: a summary and its result rows, as fields in display order."""

import math
import re
import struct
from functools import cached_property

lazy import capstone as cs

from .classes import Classes, decorated_names, readable
from .functions import MAX_DECODE_BYTES, VERIFIED, Functions
from .references import ReferenceScanner, access, float_type, instruction_refs, pointers
from .scan import occurrences, pattern_bytes
from .sources import integer

FORMATS = {
    "u8": "B",
    "i8": "b",
    "u16": "H",
    "i16": "h",
    "u32": "I",
    "i32": "i",
    "u64": "Q",
    "i64": "q",
    "f32": "f",
    "f64": "d",
    "pointer": "Q",
}
STUB_JUMPS = (b"\xff\x25", b"\x48\xff\x25")  # jmp qword ptr [rip + disp32], without and with REX.W
RIP_CELL = re.compile(r"qword ptr \[rip(?: ([+-]) (\w+))?\]")  # the operand of a call or jump through a cell
STRING_SHOWN = 120  # characters of a string shown beside an address
MATCH_SHOWN = 256  # characters of a string shown around a text match
TEXT = rb"[\t\n\r\x20-\x7e]"
# By character width: the text after a position and, matched on reversed bytes, the text before it.
AFTER = {1: re.compile(TEXT + b"*"), 2: re.compile(b"(?:" + TEXT + rb"\x00)*")}
BEFORE = {1: AFTER[1], 2: re.compile(rb"(?:\x00" + TEXT + b")*")}


def limited(rows, limit):
    shown, total = [], 0
    for row in rows:
        total += 1
        if len(shown) < limit:
            shown.append(row)
    return shown, total


def counted(total, shown, word="results"):
    return {word: total, **({"showing": len(shown)} if total > len(shown) else {})}


def text_run(data, begin, end, low, high, step):
    """Widen [begin, end) over the text characters on both sides of it, within [low, high)."""
    end = AFTER[step].match(data, end, max(end, high)).end()  # a match can run past its section
    while begin > low:
        chunk = data[max(low, begin - 4096) : begin]
        run = BEFORE[step].match(chunk[::-1]).end()
        begin -= run
        if run < len(chunk):
            break
    return begin, end


def folds(data, at, needle):
    """Whether UTF-16 bytes equal the needle apart from the case of ASCII letters."""
    for index in range(0, len(needle), 2):
        sought, found = needle[index : index + 2], data[at + index : at + index + 2]
        letter = sought[1] == 0 and sought[:1].isalpha()
        if sought != found and not (letter and sought.lower() == found.lower()):
            return False
    return True


def shortest(value, fmt):
    """The shortest decimal text that reads back as the same stored float."""
    if not math.isfinite(value):
        return str(value)
    for digits in range(1, 18):
        text = f"{value:.{digits}g}"
        try:
            same = struct.pack(fmt, float(text)) == struct.pack(fmt, value)
        except OverflowError:  # rounding up from the largest f32 leaves its range
            continue
        if same:
            return repr(float(text))  # 70.0, not 7e+01
    return repr(value)


def stored_float(raw, fmt, name):
    """A stored float as fields. A NaN also gives its bits: a bit mask such as 0x7fffffff reads as one."""
    value = struct.unpack(fmt, raw)[0]
    fields = {name: shortest(value, fmt)}
    if math.isnan(value):
        fields["hex"] = hex(int.from_bytes(raw, "little"))
    return fields


class Inspector:
    def __init__(self, source, elsewhere=None, pointer=None):
        self.source = source
        self.elsewhere = elsewhere or source.where  # what an address outside the source is, as fields
        self.pointer = pointer  # the address a cell outside the source holds; only a running process has it
        self.functions = Functions(source)
        self.classes = Classes(source)

    @cached_property
    def decoder(self):
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True
        return md

    @cached_property
    def lowered(self):
        return self.source.data.lower()

    # What an address holds

    def string_around(self, va):
        """(start VA, text, encoding) of the NUL-terminated string that holds this address.

        Text is printable ASCII, tabs, and line breaks in either encoding; long text is cut with '...'.
        """
        source = self.source
        region = source.region_of(va)
        if region is None:
            return None
        data = source.data
        at = region.offset + va - region.va
        low, high = region.offset, region.offset + region.size
        # The address can be the second byte of a UTF-16 character, so that character is tried as well.
        for encoding, step, origin in (("ascii", 1, at), ("utf-16le", 2, at), ("utf-16le", 2, at - 1)):
            if origin < low:
                continue
            begin, end = text_run(data, origin, origin, low, high, step)
            if end == origin or end - begin < 3 * step:
                continue
            if end + step > high or data[end : end + step] != b"\0" * step:
                continue
            shown = min(end, begin + STRING_SHOWN * step)
            text = data[begin:shown].decode(encoding) + ("..." if shown < end else "")
            return region.va + begin - low, text, encoding
        return None

    def code_facts(self, va):
        start = self.functions.start(va)
        if start is None:
            return {}
        return {"function_start": True} if start == va else {"function": self.source.show(start)}

    def site_function(self, va):
        """The function an instruction is in; an estimate, labelled as one, where there is no unwind data."""
        start = self.functions.start(va)
        if start is not None:
            return {"function": self.source.show(start)}
        try:
            found = self.functions.function(va)
        except ValueError:
            return {}
        return {"function": self.source.show(found.start), "estimated_from": ", ".join(found.estimated)}

    def export_name(self, va):
        """The name an address is exported by; `+N` counts its other exported names."""
        symbols = self.source.exported.get(va)
        if not symbols:
            return {}
        name = symbols[0]["name"] or f"#{symbols[0]['ordinal']}"
        return {"export": name + (f" +{len(symbols) - 1}" if len(symbols) > 1 else "")}

    def import_stub(self, va):
        """The import that code at an address jumps straight to: `jmp [import cell]`, as calls to a stub reach it."""
        source = self.source
        region = source.region_of(va)
        if region is None or not region.executable:
            return {}
        for opcode in STUB_JUMPS:
            size = len(opcode) + 4
            try:
                raw = source.read(va, size)
            except ValueError:
                continue
            if raw.startswith(opcode):
                symbol = source.imports.get(va + size + struct.unpack_from("<i", raw, len(opcode))[0])
                return {"import_stub": symbol["name"]} if symbol else {}
        return {}

    def constant(self, ins, va):
        """The float an instruction reads from read-only data, as {type: value}."""
        kind = float_type(ins)
        region = self.source.region_of(va)
        if kind is None or region is None or region.writable:
            return {}
        fmt = "<" + FORMATS[kind]
        try:
            raw = self.source.read(va, struct.calcsize(fmt))
        except ValueError:
            return {}
        return stored_float(raw, fmt, kind)

    def import_cell(self, va):
        """An import cell: the import the image declares and, in a process, where the cell led when read.

        The declared import and the place are separate facts. They name different modules when the
        import is forwarded, and when something replaced what the loader wrote.
        """
        source = self.source
        symbol = source.imports[va]
        fields = {"import": symbol["name"]}
        if symbol.get("unnamed"):
            fields["name_unavailable"] = True
        if source.from_process:
            try:
                value = struct.unpack("<Q", source.read(va, 8))[0]
            except ValueError:
                return fields
            known = self._named(value) if source.holds(value) else self.elsewhere(value)
            fields["points_to"] = {"address": source.show(value), **known}
        return fields

    def destination(self, ins, va):
        """Where a call or jump through a cell leads in a process: what the cell held when it was read.

        A file has only the cell's initial value. An import cell says where it leads with its import.
        """
        source = self.source
        transfer = ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)
        if not source.from_process or not transfer or va in source.imports:
            return {}
        if source.holds(va):
            try:
                value = struct.unpack("<Q", source.read(va, 8))[0]
            except ValueError:
                return {}  # the cell's own facts say why: unreadable, or no bytes
        elif self.pointer is None:
            return {"not_saved": True}  # a saved copy holds one module; the cell was elsewhere in the process
        else:
            try:
                value = self.pointer(va)
            except ValueError:
                return {"unreadable": True}
        return {"points_to": self.held(value)}

    def slot_facts(self, va):
        found = self.classes.slot_at(va)
        return {"class": readable(found[0].name), "slot": found[1]} if found else {}

    def facts(self, va):
        """What is known cheaply about an address: an import or a stub for one, an export, a function, a class slot, or a string."""
        source = self.source
        if not source.holds(va):
            return self.elsewhere(va)
        if va in source.imports:
            return self.import_cell(va)
        return self._named(va)

    def _named(self, va):
        return {**self.export_name(va), **self._holds(va)}

    def _holds(self, va):
        source = self.source
        region = source.region_of(va)
        if region is None:
            return source.missing(va)
        if region.executable:
            return {**self.code_facts(va), **self.import_stub(va)}
        found = self.slot_facts(va)
        if found:
            return found
        found = self.string_around(va)
        if not found:
            return {}
        return {"string": found[1]} if found[0] == va else {"inside_string": source.show(found[0])}

    def held(self, va):
        source = self.source
        known = self.facts(va)
        if not source.image and source.holds(
            va
        ):  # memory outside a module has no names: say what memory, as elsewhere
            known = {"in": source.name, **known}
        return {"address": source.show(va), **known}

    # Instructions

    def instruction(self, ins, *, show_bytes=False, targets=True):
        source = self.source
        refs = list(instruction_refs(ins))
        operands = ins.op_str
        for kind, va in refs:
            if kind != "memory" and operands == hex(va):
                operands = source.show(va)
        row = {"address": source.show(ins.address)}
        if show_bytes:
            row["bytes"] = ins.bytes.hex(" ")
        row["instruction"] = f"{ins.mnemonic} {operands}".rstrip()
        if targets:
            for kind, va in refs:
                if kind == "memory":
                    row["target"] = {**self.held(va), **self.constant(ins, va), **self.destination(ins, va)}
                else:  # the operand already gives the address of a call or jump
                    inside = source.holds(va)
                    named = {**self.export_name(va), **self.import_stub(va)} if inside else self.elsewhere(va)
                    if named:
                        row["target"] = {"address": source.show(va), **named}
        return row

    # Commands

    def info(self, *, limit=100):
        source = self.source
        pe = source.pe
        sections = []
        for section in source.sections:
            flags = section["characteristics"]
            row = {
                "address": source.show(source.base + section["rva"]),
                "name": section["name"],
                "size": hex(section["virtual_size"]),
            }
            region = source.region_of(source.base + section["rva"])
            if (
                section["raw_size"] and not source.record
            ):  # a loaded module has no layout of its own in a file
                row.update(in_file=f"offset:{section['offset']:#x}", size_in_file=hex(section["raw_size"]))
            if region is not None:
                row["entropy"] = f"{source.entropy(region):.2f}"
            row.update(code=bool(flags & 0x20000000), writable=bool(flags & 0x80000000))
            sections.append(row)
        record = source.record
        identity = dict(source.identity)
        if record:
            process = record["process"]
            identity.update(
                process=process["name"], pid=process["pid"], module=source.name, read=record["read"]
            )
            identity.update(process_started=process["started"], module_path=record["module"]["path"])
        identity |= {
            "image_base": f"va:{source.base:#x}",
            "image_size": hex(source.image_size),
            "entry": source.show(source.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "timestamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "unwind_entries": len(source.entries),
        }

        def import_row(va, symbol):
            cell = self.import_cell(va)
            leads = cell.pop("points_to", None)
            return {"address": source.show(va), **cell, "delayed": symbol["delayed"], "points_to": leads}

        shown, total_imports = limited(source.imports.items(), limit)
        imports = [import_row(va, symbol) for va, symbol in shown]
        unnamed = sum(1 for symbol in source.imports.values() if symbol.get("unnamed"))
        exports, total_exports = limited(
            (
                {
                    "address": source.show(source.base + symbol["rva"]),
                    "export": symbol["name"],
                    "ordinal": symbol["ordinal"],
                    "forwarded_to": symbol["forwarder"],
                }
                for symbol in source.exports
            ),
            limit,
        )
        warnings = pe.get_warnings()
        if warnings:
            identity["pe_warnings"] = "; ".join(warnings)
        parts = {
            "sections": ({**identity, "results": len(sections)}, sections),
            "imports": ({**counted(total_imports, imports), "names_unavailable": unnamed or None}, imports),
            "exports": (counted(total_exports, exports), exports),
        }
        if record:  # what the process had loaded, and what could not be read from it
            modules, total_modules = limited(
                (
                    {
                        "address": f"va:{module['base']:#x}",
                        "name": module["name"],
                        "size": hex(module["size"]),
                        "path": module["path"],
                    }
                    for module in record["modules"]
                ),
                limit,
            )
            parts["modules"] = (counted(total_modules, modules), modules)
            if source.holes:
                holes = [
                    {
                        "address": source.show(source.base + begin),
                        "size": hex(end - begin),
                        "unreadable": reason,
                    }
                    for begin, end, reason in source.holes
                ]
                parts["unreadable"] = ({"results": len(holes)}, holes[:limit])
        return parts

    def find(
        self,
        *,
        text=None,
        pattern=None,
        value=None,
        encoding="ascii",
        ignore_case=False,
        value_type="u32",
        limit=100,
        scope=None,
    ):
        source = self.source
        data = source.data
        spans = source.spans(**(scope or {}))
        if text is not None:
            if not text:
                raise ValueError("Search text must not be empty")
            needles = []
            for codec in ["ascii", "utf-16le"] if encoding == "both" else [encoding]:
                try:
                    needles.append((codec, text.encode(codec)))
                except UnicodeEncodeError:
                    if encoding == "both" and codec == "ascii":
                        continue
                    raise ValueError(f"Text cannot be encoded as {codec}") from None
            row = self._string_row
        else:
            if pattern is not None:
                needles = [(None, pattern_bytes(pattern))]
            else:
                number = float(value) if value_type.startswith("f") else integer(value, signed=True)
                needles = [(None, struct.pack("<" + FORMATS[value_type], number))]
            row = self._bytes_row

        def hits():
            for codec, needle in needles:
                if pattern is not None:
                    matcher = re.compile(b"(?=(" + needle + b"))", re.DOTALL)
                    for low, high in spans:
                        for match in matcher.finditer(data, low, high):
                            yield match.start(), len(match[1]), codec
                else:
                    # Only ASCII letters have their case ignored, so a lowered copy finds every match.
                    # In UTF-16 it also pairs unrelated characters, which `folds` rejects.
                    fold = bool(text) and ignore_case
                    haystack, sought = (self.lowered, needle.lower()) if fold else (data, needle)
                    for low, high in spans:
                        for at in occurrences(haystack, sought, low, high):
                            if not fold or codec == "ascii" or folds(data, at, needle):
                                yield at, len(needle), codec

        shown, total = limited(hits(), limit)
        rows = [row(at, length, codec) for at, length, codec in shown]
        return [({**counted(total, rows), "scanned_bytes": sum(b - a for a, b in spans)}, rows)]

    def _string_row(self, at, length, codec):
        """The text around a match; the row leads with the start of that text, however far back it is."""
        source = self.source
        data = source.data
        step = 2 if codec == "utf-16le" else 1
        region = source.region_of_offset(at)
        low, high = (region.offset, region.offset + region.size) if region else (0, len(data))
        begin, end = text_run(data, at, at + length, low, high, step)
        match, total = (at - begin) // step, (end - begin) // step
        # Long text is shown as a part around the match.
        first = min(max(0, match - max(0, MATCH_SHOWN - length // step) // 2), max(0, total - MATCH_SHOWN))
        last = min(total, first + MATCH_SHOWN)
        shown = data[begin + first * step : begin + last * step].decode(codec, errors="replace")
        row = {
            "address": source.show_offset(begin),
            "string": ("..." if first else "") + shown + ("..." if last < total else ""),
        }
        if step == 2:
            row["encoding"] = codec
        row["match"] = f"+{match}"
        return row

    def _bytes_row(self, at, length, codec):
        source = self.source
        row = {"address": source.show_offset(at), "bytes": source.data[at : at + min(length, 32)].hex(" ")}
        region = source.region_of_offset(at)
        if region is not None and region.executable:
            row.update(self.code_facts(region.va + at - region.offset))
        return row

    def refs(self, address=None, *, displacement=None, kind="all", limit=100, scope=None):
        source = self.source
        if (address is None) == (displacement is None):
            raise ValueError("Give addresses or --displacement, not both")
        scope = scope or {}
        target = None
        if address is not None:
            target, _ = source.locate(address)
            if target is None:
                return [
                    (
                        {
                            "results": 0,
                            "not_loaded": True,
                            "note": "nothing can refer to bytes that are not loaded",
                        },
                        [],
                    )
                ]
        else:
            if displacement == 0 or not -(1 << 31) <= displacement < 1 << 31:
                raise ValueError("Displacement searches require a nonzero signed 32-bit displacement")
            if kind not in ("all", "memory"):
                raise ValueError("--displacement only supports --kind all or memory")
        code_spans = source.spans(**scope, executable=True) if kind != "pointer" else []
        # shortcut: broad disp8 searches are expensive; add indexing only if bounded searches stop sufficing.
        if (
            displacement is not None
            and -128 <= displacement <= 127
            and sum(b - a for a, b in code_spans) > MAX_DECODE_BYTES
        ):
            raise ValueError("disp8 searches require a --start/--length or section scope of at most 1 MiB")

        def sites():
            """(instruction, boundary evidence), then (offset of a pointer cell, None)."""
            if kind != "pointer":
                scanner = ReferenceScanner(source, self.functions, self.decoder)
                yield from scanner.code(target, kind, displacement, code_spans)
            if target is not None and kind in ("all", "pointer"):
                for offset in pointers(source, target, source.spans(**scope)):
                    yield offset, None

        # Every site is counted; a row, which can need a function estimate, is made for the ones shown.
        shown, total = limited(sites(), limit)
        rows = [
            self._cell_row(site) if boundary is None else self._site_row(site, boundary, target is None)
            for site, boundary in shown
        ]
        summary = counted(total, rows)
        if target is not None:
            summary["target"] = self.facts(target) or None
        return [(summary, rows)]

    def _site_row(self, ins, boundary, targets):
        row = self.instruction(ins, targets=targets)
        row.update(dict.fromkeys(access(ins), True), **self.site_function(ins.address))
        if boundary != VERIFIED:
            row["unverified"] = boundary
        return row

    def _cell_row(self, offset):
        source = self.source
        row = {"address": source.show_offset(offset), "pointer": True}
        region = source.region_of_offset(offset)
        if region is not None:
            cell = region.va + offset - region.offset
            row.update(self.code_facts(cell) if region.executable else self.slot_facts(cell))
        return row

    def disasm(self, address, *, byte_count=None, before=0, function=False, limit=100, show_bytes=False):
        source = self.source
        va = source.va(address)
        summary = {}
        open_ended = False
        if function and before:
            raise ValueError("--before does not apply to a whole function")
        if function:
            found = self.functions.function(va)
            ranges = found.pieces
            size = sum(end - begin for begin, end in ranges)
            summary.update(function=source.show(found.start), **self.export_name(found.start))
            summary.update(self._function_fields(found))
        else:
            region = source.region_at(va)
            open_ended = byte_count is None
            if open_ended:
                byte_count = min(256, region.va + region.size - va)
            first = max(region.va, va - before)
            size = va + byte_count - first
            # Decoding from inside an instruction gives instructions that are not there.
            begin = self.functions.instruction_at(first)
            begin = first if begin is None else begin
            ranges = [(begin, va + byte_count)]
            summary["range"] = self._range(*ranges[0])
            # What precedes the code that holds the address may not be code. Decoding starts again where that
            # code starts, so that nothing before it can put the listing out of step.
            start = self.functions.piece_start(va) if before else None
            if start is not None and begin < start:
                ranges = [(begin, start), (start, va + byte_count)]
            summary.update(self.code_facts(va))
            inside = self.functions.instruction_at(va)
            if inside is not None and inside != va:
                summary["inside_instruction"] = source.show(inside)
        if not 0 < size <= MAX_DECODE_BYTES:
            raise ValueError(f"Disassembly ranges must be 1..{MAX_DECODE_BYTES} bytes")
        rows, total, pointers, stops = [], 0, 0, {}

        def stop(reason, at):
            if source.show(at) not in stops.setdefault(reason, []):
                stops[reason].append(source.show(at))

        for begin, end in ranges:
            # Bytes that the process did not let anyone read end a listing; what precedes them is listed.
            # A range without a given size would have gone on, so it also says when they are what ended it.
            unread = source.unread_from(begin, end + open_ended)
            if unread is not None:
                stop("unreadable_at", unread)
                if unread == begin:
                    continue
                end = unread
            raw = source.read(begin, end - begin)
            decoded = begin
            reached = function or begin == va or "inside_instruction" in summary
            cells = []
            for at, size in self._instructions(raw, begin, cells):
                total += 1
                decoded = at + size
                reached = reached or at == va
            if cells:
                pointers += len(cells)
                decoded = max(decoded, cells[-1] + 8)
                reached = reached or any(cell <= va < cell + 8 for cell in cells)
            if not reached and decoded > va:
                summary["note"] = (
                    f"decoding from {source.show(begin)} does not arrive at {source.show(va)} as the start of an "
                    "instruction, so the instructions shown before it may not be the real ones"
                )
            if decoded < end:
                stop(*self._stopped(decoded, end))
            at = begin
            for cell in [*cells, end]:
                if len(rows) >= limit:
                    break
                code = raw[at - begin : cell - begin]
                for ins in self.decoder.disasm(code, at, count=limit - len(rows)):
                    rows.append(self.instruction(ins, show_bytes=show_bytes))
                if cell == end or len(rows) >= limit:
                    break
                rows.append(self._stored_address(cell, raw[cell - begin : cell - begin + 8], show_bytes))
                at = cell + 8
        summary["instructions"] = total
        if pointers:
            summary["pointers"] = pointers
        if total + pointers > len(rows):
            summary["showing"] = len(rows)
        summary.update(stops)
        return [(summary, rows)]

    def _instructions(self, raw, begin, cells):
        """The address and size of each instruction in a range, in order.

        The eight bytes from which a call or jump in the range reads its destination hold an address, not
        instructions: decoding steps over them, and `cells` receives where they are.
        """
        end = begin + len(raw)
        ahead = set()
        at = begin
        while at < end:
            for start, size, mnemonic, operands in self.functions.lite.disasm_lite(raw[at - begin :], at):
                yield start, size
                at = start + size
                found = mnemonic in ("jmp", "call") and RIP_CELL.fullmatch(operands)
                if found:
                    cell = at + int((found[1] or "") + (found[2] or "0"), 0)
                    if at <= cell <= end - 8:
                        ahead.add(cell)
                if at in ahead:
                    break
            else:
                return
            cells.append(at)
            at += 8

    def _stored_address(self, va, raw, show_bytes):
        row = {"address": self.source.show(va)}
        if show_bytes:
            row["bytes"] = raw.hex(" ")
        return {**row, "pointer": True, "points_to": self.held(struct.unpack("<Q", raw)[0])}

    def _stopped(self, va, end):
        """Why decoding a range stopped at `va` before its `end`, and the address that reason is about."""
        source = self.source
        region = source.region_at(va)
        raw = source.read(va, min(15, region.va + region.size - va))
        if any(va + size > end for _, size, _, _ in self.functions.lite.disasm_lite(raw, va, 1)):
            return "ends_inside_instruction", va
        unread = source.unread_from(va + len(raw), va + 15)
        if unread == va + len(raw):  # an instruction here would run into bytes nobody could read
            return "unreadable_at", unread
        return "undecodable_at", va

    def _range(self, begin, end):
        return f"{self.source.show(begin)}..{self.source.show(end)}"

    def _function_fields(self, found, pieces="pieces"):
        fields = {pieces: [self._range(*piece) for piece in found.pieces]}
        if found.estimated:
            fields["estimated_from"] = ", ".join(found.estimated)
        return fields

    def data(self, address, *, value_type="u8", count=16):
        source = self.source
        fmt = "<" + FORMATS[value_type]
        width = struct.calcsize(fmt)
        if not 1 <= count <= 4096:
            raise ValueError("Data count must be 1..4096")
        va, offset = source.locate(address)
        if va is not None:
            # Loaded bytes are read as their address, so a read stays within one section.
            offset = source.offset_of_va(va, width * count)
        elif offset + width * count > len(source.data):
            raise ValueError("Read exceeds the file")
        raw = source.data[offset : offset + width * count]
        rows = []
        if value_type == "u8":
            for at in range(0, count, 16):
                chunk = raw[at : at + 16]
                text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in chunk)
                rows.append(
                    {"address": source.show_offset(offset + at), "bytes": chunk.hex(" "), "ascii": text}
                )
            return [({"type": value_type, "count": count}, rows)]
        for at in range(0, len(raw), width):
            cell = raw[at : at + width]
            (value,) = struct.unpack(fmt, cell)
            row = {"address": source.show_offset(offset + at)}
            if value_type == "pointer":
                row["points_to"] = self.held(value)
            elif isinstance(value, float):
                row.update(stored_float(cell, fmt, "value"))
            else:
                row.update(value=value, hex=hex(value % (1 << (8 * width))))
            rows.append(row)
        return [({"type": value_type, "count": count}, rows)]

    def rtti(self, name, *, slots=16, slot_start=0, limit=100):
        source = self.source
        if not 1 <= slots <= 1024 or not 0 <= slot_start <= 65535:
            raise ValueError("Use 1..1024 slots and a starting slot of 0..65535")
        tables = [table for decorated in decorated_names(name) for table in self.classes.tables(decorated)]
        tables.sort(key=lambda table: (table.subobject, table.vtable))
        if not tables:
            return [({"tables": 0}, [])]
        answers = []
        for number, table in enumerate(tables[:limit], 1):
            # Cells past the table's last slot belong to whatever follows it, often another table.
            count = self.classes.slot_count(table.vtable, slot_start + slots)
            rows = []
            for index in range(slot_start, count):
                cell = table.vtable + index * 8
                target = self.classes.code_pointer(cell)
                outside = {} if source.holds(target) else self.elsewhere(target)  # where a mod redirected it
                rows.append(
                    {"address": source.show(target), **outside, "slot": index, "cell": source.show(cell)}
                )
            summary = {
                "table": f"{number} of {len(tables)}",
                "type": table.name,
                "vtable": source.show(table.vtable),
                "subobject": f"+{table.subobject:#x}",
                "slots": len(rows),
                "table_ends_before_slot": count if count < slot_start + slots else None,
            }
            answers.append((summary, rows))
        return answers

    def describe(self, address, *, limit=100):
        source = self.source
        va, offset = source.locate(address)
        if va is None:
            return [
                (
                    {
                        "not_loaded": True,
                        "note": "file bytes that are not loaded into memory have no address",
                    },
                    [],
                )
            ]
        if not source.holds(va):
            return [({"outside_the_image": True, **self.elsewhere(va)}, [])]
        summary = source.place(va, offset)

        def names(address):
            for symbol in source.exported.get(address, ()):
                yield {
                    "address": source.show(address),
                    "export": symbol["name"],
                    "ordinal": symbol["ordinal"],
                }
            stub = self.import_stub(address)
            if stub:
                yield {"address": source.show(address), **stub}

        def rows():
            if va in source.imports:
                yield {"address": source.show(va), **self.import_cell(va)}
            region = source.region_of(va)
            if region is not None and region.executable:
                try:
                    found = self.functions.function(va)
                except ValueError as exc:
                    summary["note"] = str(exc)
                    yield from names(va)
                    return
                row = {"address": source.show(found.start), **self._function_fields(found, "function_pieces")}
                row["function_size"] = hex(sum(end - begin for begin, end in found.pieces))
                if va != found.start:
                    row["query_at"] = f"{va - found.start:+#x}"
                piece = next((piece for piece in found.pieces if piece[0] <= va < piece[1]), None)
                inside = self.functions.instruction_at(va, piece if found.estimated else None)
                if inside is not None and inside != va:
                    row["inside_instruction"] = source.show(inside)
                yield row
                # What follows is about the function: its exported names, the import it is a stub for,
                # and the class slots it fills.
                for address in dict.fromkeys((found.start, va)):
                    yield from names(address)
                for cell, table, index in self.classes.owners(found.start):
                    yield self._slot_row(cell, table, index)
                return
            yield from names(va)
            if region is None:
                return
            found = self.classes.slot_at(va)
            if found:
                yield {**self._slot_row(va, *found), "points_to": self.held(self.classes.code_pointer(va))}
            text = self.string_around(va)
            if text:
                start, shown, encoding = text
                row = {"address": source.show(start), "string": shown, "encoding": encoding}
                if start != va:
                    row["query_at"] = f"{va - start:+#x}"
                yield row

        shown, total = limited(rows(), limit)
        note = summary.pop("note", None)
        return [({**summary, **counted(total, shown), "note": note}, shown)]

    def _slot_row(self, cell, table, index):
        return {
            "address": self.source.show(cell),
            "class": readable(table.name),
            "slot": index,
            "vtable": self.source.show(table.vtable),
            "subobject": f"+{table.subobject:#x}",
        }
