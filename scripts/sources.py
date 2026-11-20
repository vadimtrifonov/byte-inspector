from __future__ import annotations

import bisect
import hashlib
import json
import math
import struct
from collections import Counter
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path

lazy import pefile

ADDRESS_LIMIT = 1 << 64
PACKED_ENTROPY = 7.0
ENTROPY_SAMPLE = (64, 4096)
COPY_END = (
    b"byte-inspector\x00\x01"  # ends a saved copy of a loaded module; its record and length come before
)


def integer(value, *, signed=False):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"Expected an integer, got {value!r}")
    number = int(value, 0) if isinstance(value, str) else value
    if not -(ADDRESS_LIMIT // 2 if signed else 0) <= number < ADDRESS_LIMIT:
        raise ValueError("Integer is outside the supported 64-bit range")
    return number


def coordinate(text):
    mode, separator, value = text.partition(":")
    if not separator or mode not in ("rva", "va", "offset"):
        raise ValueError(f"Not an address: {text[:80]} (use rva:0x1000, va:0x140001000, or offset:0x400)")
    try:
        return mode, integer(value)
    except ValueError:
        raise ValueError(f"Not an address: {text[:80]}") from None


def split_copy(raw):
    """(image, record, the bytes after the image) of a saved copy; any other file is all image."""
    if not raw.endswith(COPY_END):
        return raw, None, b""
    footer = len(COPY_END) + 8
    start = len(raw) - footer - struct.unpack_from("<Q", raw, len(raw) - footer)[0]
    if start < 0:
        raise ValueError("Damaged saved copy: its record is longer than the file")
    return raw[:start], json.loads(raw[start : len(raw) - footer]), raw[start:]


def copy_end(record):
    """The bytes that follow the image in a saved copy."""
    text = json.dumps(record, separators=(",", ":")).encode("utf-8")
    return text + struct.pack("<Q", len(text)) + COPY_END


def as_loaded(pe, base, length):
    """Make parsed headers describe the module as memory holds it: at `base`, each section at its address.

    The headers of a loaded module still give the layout of its file, and can give the base it prefers
    rather than the one it got. Only what the parser took from them changes; the bytes stay as read.
    """
    header = pe.OPTIONAL_HEADER
    alignment = header.SectionAlignment
    if not alignment:
        raise ValueError("The module's PE header has no section alignment")
    header.ImageBase, header.FileAlignment = base, alignment
    for section in pe.sections:
        rva = section.VirtualAddress
        size = -(-max(section.Misc_VirtualSize, 1) // alignment) * alignment
        section.PointerToRawData, section.SizeOfRawData = rva, max(min(size, length - rva), 0)
        # pefile keeps what it first derived from these fields.
        section.PointerToRawData_adj = section.VirtualAddress_adj = None
        section.section_min_addr = section.section_max_addr = None


@dataclass(frozen=True)
class Region:
    """Bytes that are loaded at an address."""

    name: str
    offset: int
    size: int
    va: int
    executable: bool
    writable: bool


class Memory:
    """Bytes at addresses: a part of a process's memory. A PE image adds what its headers describe."""

    path = None  # the file the bytes are from
    record = None  # for a module read from a process: the process, the time, its modules, what was unreadable
    home = None  # the image whose addresses are printed as rva:, when that is not this one
    image = False  # whether the bytes are one PE image, with sections and addresses relative to its base
    from_process = (
        True  # whether the bytes are what a process held at one moment, not a file's initial values
    )
    packed = unread = None
    damaged = ()
    holes = ()
    sections = entries = starts = exports = ()
    imports = exported = {}

    def __init__(self, data, va, *, name, executable, writable, home, identity, place):
        self.data = data
        self.base = va
        self.image_size = len(data)
        self.name = name
        self.home = home
        self.identity = identity
        self._place = place
        self._map([Region(name, 0, len(data), va, executable, writable)])

    def _map(self, regions):
        self.regions = sorted(regions, key=lambda r: r.va)
        self._by_offset = sorted(regions, key=lambda r: r.offset)
        for ordered, key in ((self.regions, "va"), (self._by_offset, "offset")):
            if any(getattr(a, key) + a.size > getattr(b, key) for a, b in zip(ordered, ordered[1:])):
                raise ValueError("Overlapping PE regions are unsupported")
        self._vas = [r.va for r in self.regions]
        self._offsets = [r.offset for r in self._by_offset]

    def holds(self, va):
        return self.base <= va < self.base + self.image_size

    def where(self, va):
        """What is known about an address outside these bytes, as fields."""
        return {}

    def place(self, va, offset):
        """Where an address is, as the fields that lead what `describe` says about it."""
        return dict(self._place)

    def missing(self, va):
        """Why an address these bytes cover has no bytes, as a field."""
        return {"unreadable": True}

    def owner(self, va):
        return None

    def relocated(self, va):
        return False

    def section_name(self, va):
        return None

    # Addresses

    def show(self, va):
        """The address as printed and accepted: relative to the image when inside it."""
        home = self.home or self
        if home.image and home.holds(va):
            return f"rva:{va - home.base:#x}"
        return f"va:{va:#x}"

    def show_offset(self, offset):
        region = self.region_of_offset(offset)
        return self.show(region.va + offset - region.offset) if region else f"offset:{offset:#x}"

    def region_of(self, va):
        index = bisect.bisect_right(self._vas, va) - 1
        if index >= 0 and va < self.regions[index].va + self.regions[index].size:
            return self.regions[index]
        return None

    def region_of_offset(self, offset):
        index = bisect.bisect_right(self._offsets, offset) - 1
        if index >= 0 and offset < self._by_offset[index].offset + self._by_offset[index].size:
            return self._by_offset[index]
        return None

    def region_at(self, va):
        region = self.region_of(va)
        if region is None:
            hole = next((hole for hole in self.holes if hole[0] <= va - self.base < hole[1]), None)
            if hole:
                raise ValueError(f"Cannot read {self.show(va)} from the process: {hole[2]}")
            raise ValueError(f"No bytes in the {'file' if self.path else 'process'} at {self.show(va)}")
        return region

    def unread_from(self, begin, end):
        """The first address in a range that the process did not let anyone read, or None."""
        for low, high, _ in self.holes:
            if self.base + low < end and begin < self.base + high:
                return max(begin, self.base + low)
        return None

    def va_of_offset(self, offset):
        if not 0 <= offset < len(self.data):
            raise ValueError("Offset is outside the file")
        region = self.region_of_offset(offset)
        if region is None:
            raise ValueError("This file offset is not loaded into memory, so it has no address")
        return region.va + offset - region.offset

    def offset_of_va(self, va, count=1):
        if count <= 0 or not 0 <= va < va + count <= ADDRESS_LIMIT:
            raise ValueError("Invalid address range")
        region = self.region_at(va)
        available = region.va + region.size - va
        if count > available:
            end = self.unread_from(va, va + count)
            raise ValueError(
                f"Read at {self.show(va)} needs {count} bytes; only {available} "
                + (
                    f"precede {self.show(end)}, which could not be read from the process"
                    if end == va + available
                    else f"available in {region.name}"
                )
            )
        return region.offset + va - region.va

    def address(self, text):
        mode, value = coordinate(text)
        if mode == "offset" and self.from_process:  # a saved copy too: its bytes lie as they did in memory
            raise ValueError("Bytes read from a process have no file offsets; use rva: or va:")
        return mode, value

    def va(self, address):
        mode, value = self.address(address)
        if mode == "va":
            return value
        if mode == "rva":
            if value >= self.image_size:
                raise ValueError("RVA is outside the image")
            return self.base + value
        return self.va_of_offset(value)

    def offset(self, address, count=1):
        mode, value = self.address(address)
        if mode == "offset":
            if count <= 0 or value + count > len(self.data):
                raise ValueError("Read exceeds the file")
            return value
        return self.offset_of_va(self.va(address), count)

    def locate(self, address):
        """(va, offset) of an address; va is None for file bytes that are not loaded, offset for no file bytes."""
        mode, value = self.address(address)
        if mode == "offset":
            if value >= len(self.data):
                raise ValueError("Offset is outside the file")
            region = self.region_of_offset(value)
            return (region.va + value - region.offset if region else None), value
        va = self.va(address)
        region = self.region_of(va)
        return va, (region.offset + va - region.va if region else None)

    def read(self, va, count):
        offset = self.offset_of_va(va, count)
        return self.data[offset : offset + count]

    def spans(self, *, section=None, start=None, length=None, executable=False):
        if (start is None) != (length is None):
            raise ValueError("Supply --start and --length together")
        low, high = 0, len(self.data)
        if start is not None:
            low = self.offset(start, length)
            high = low + length
        if section or executable:
            regions = [r for r in self._by_offset if (not section or r.name == section)]
            if not regions:
                raise ValueError(f"Section not found: {section}")
            if executable:
                regions = [r for r in regions if r.executable]
            ranges = [(r.offset, r.offset + r.size) for r in regions]
        else:
            ranges = [(0, len(self.data))]
            for begin, end, _ in self.holes:  # where the image is the whole file, as a loaded module is
                ranges = [
                    part
                    for a, b in ranges
                    for part in ((a, min(b, begin)), (max(a, end), b))
                    if part[0] < part[1]
                ]
        return [(max(a, low), min(b, high)) for a, b in ranges if max(a, low) < min(b, high)]


class PE(Memory):
    """A PE image: a file on disk, or a module read from a running process."""

    image = True

    def __init__(self, path):
        path = Path(path).resolve()
        image, record, tail = split_copy(path.read_bytes())
        self._load(image, path=path, record=record, tail=tail)

    @classmethod
    def loaded(cls, image, record, home=None):
        """A module as just read from a process."""
        self = cls.__new__(cls)
        self._load(image, record=record, home=home)
        return self

    def _load(self, data, *, path=None, record=None, tail=b"", home=None):
        self.data, self.path, self.record, self.tail, self.home = data, path, record, tail, home
        self.pe = pe = pefile.PE(data=data, fast_load=True)
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError("Only AMD64 PE32+ images are supported")
        if record is not None:
            as_loaded(pe, record["module"]["base"], len(data))
        self.base = base = pe.OPTIONAL_HEADER.ImageBase
        self.image_size = size = pe.OPTIONAL_HEADER.SizeOfImage
        headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        if not 0 < headers <= len(data) or not headers <= size or base + size > ADDRESS_LIMIT:
            raise ValueError("Invalid PE header/image bounds")
        if len(pe.sections) != pe.FILE_HEADER.NumberOfSections:
            raise ValueError("Truncated PE section table")
        if record is not None:  # in memory the headers fill their pages, up to the first section
            first = min((section.VirtualAddress for section in pe.sections), default=size)
            headers = max(headers, min(first, size, len(data)))
        regions = [Region("headers", 0, headers, base, False, False)]
        self.sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
            offset = section.get_PointerToRawData_adj()
            rva = section.get_VirtualAddress_adj()
            raw_size = section.SizeOfRawData
            self.sections.append(
                {
                    "name": name,
                    "rva": rva,
                    "virtual_size": section.Misc_VirtualSize,
                    "offset": offset,
                    "raw_size": raw_size,
                    "characteristics": section.Characteristics,
                }
            )
            if not raw_size:
                continue
            if offset + raw_size > len(data) or rva + raw_size > size:
                raise ValueError("Truncated or out-of-image PE section")
            flags = section.Characteristics
            regions.append(
                Region(name, offset, raw_size, base + rva, bool(flags & 0x20000000), bool(flags & 0x80000000))
            )
        # Bytes that could not be read from the process are no bytes at all, so nothing reads them as zeros.
        self.holes = sorted(tuple(hole) for hole in (record or {}).get("unreadable", ()))
        self._map([part for region in regions for part in self._readable(region)])
        modules = sorted((m["base"], m["size"], m["name"]) for m in (record or {}).get("modules", ()))
        self._modules, self._module_bases = modules, [module[0] for module in modules]

    def _readable(self, region):
        """The parts of a region outside the unreadable ranges."""
        begin, end = region.offset, region.offset + region.size
        for low, high, _ in self.holes:
            if low >= end:
                break
            if high <= begin:
                continue
            if low > begin:
                yield replace(region, offset=begin, size=low - begin, va=region.va + begin - region.offset)
            begin = high
        if begin < end:
            yield replace(region, offset=begin, size=end - begin, va=region.va + begin - region.offset)

    @property
    def from_process(self):
        return self.record is not None

    @property
    def name(self):
        return self.record["module"]["name"] if self.record else self.path.name

    def where(self, va):
        """The loaded module that holds an address outside the image, from the record of the process."""
        index = bisect.bisect_right(self._module_bases, va) - 1
        if index >= 0 and va < self._modules[index][0] + self._modules[index][1]:
            return {"in": f"{self._modules[index][2]} rva:{va - self._modules[index][0]:#x}"}
        return {}

    def missing(self, va):
        unreadable = any(begin <= va - self.base < end for begin, end, _ in self.holes)
        return {"unreadable" if unreadable else "no_bytes_in_file": True}

    def place(self, va, offset):
        fields = {"in": f"{self.name} rva:{va - self.base:#x}"} if self.home else {}
        fields["section"] = self.section_name(va)
        if offset is None:
            fields.update(self.missing(va))
        elif not self.record:  # a loaded module has no layout of its own in a file
            fields["in_file"] = f"offset:{offset:#x}"
        return fields

    def section_name(self, va):
        rva = va - self.base
        for section in self.sections:
            if section["rva"] <= rva < section["rva"] + max(section["virtual_size"], section["raw_size"]):
                return section["name"]
        return "headers" if 0 <= rva < self.regions[0].size else None

    # Identity

    @cached_property
    def sha256(self):
        digest = hashlib.sha256(self.data)
        digest.update(self.tail)
        return digest.hexdigest()

    @property
    def identity(self):
        """What the bytes are, for a record of where a result came from."""
        if self.path:
            return {"file": str(self.path), "sha256": self.sha256}
        record = self.record
        return {
            "process": record["process"]["name"],
            "pid": record["process"]["pid"],
            "module": self.name,
            "read": record["read"],
            "sha256": self.sha256,
        }

    def entropy(self, region):
        """Bits per byte, from evenly spaced samples of a large region."""
        count, size = ENTROPY_SAMPLE
        if region.size <= count * size:
            sample = self.data[region.offset : region.offset + region.size]
        else:
            step = (region.size - size) // (count - 1)
            sample = b"".join(
                self.data[region.offset + index * step : region.offset + index * step + size]
                for index in range(count)
            )
        return -sum(n / len(sample) * math.log2(n / len(sample)) for n in Counter(sample).values())

    @cached_property
    def packed(self):
        """A warning when the largest code section does not look like code."""
        code = [r for r in self.regions if r.executable]
        if not code:
            return None
        largest = max(code, key=lambda r: r.size)
        entropy = self.entropy(largest)
        if entropy <= PACKED_ENTROPY:
            return None
        return (
            f"code in {largest.name} looks encrypted or compressed (entropy {entropy:.2f}); "
            "results that depend on code are unreliable"
        )

    @cached_property
    def damaged(self):
        """The tables whose section has unreadable bytes; what any command says can then lack them."""
        tables = {0: "exports", 1: "imports", 3: "unwind data", 5: "relocations", 13: "delayed imports"}
        found = []
        for index, name in tables.items():
            try:
                rva, size = self.directory(index)
            except ValueError:
                continue
            for section in self.sections if size else ():
                begin, end = (
                    section["rva"],
                    section["rva"] + max(section["virtual_size"], section["raw_size"]),
                )
                if begin <= rva < end and any(low < end and high > begin for low, high, _ in self.holes):
                    found.append(name)
        return found

    @cached_property
    def unread(self):
        """A warning when part of the module could not be read from the process, for whatever searches it."""
        if not self.holes:
            return None
        size = sum(end - begin for begin, end, _ in self.holes)
        tables = f", in a section that holds {', '.join(self.damaged)}" if self.damaged else ""
        return (
            f"{size:#x} bytes could not be read from the process{tables} (info lists the ranges); "
            "results that depend on them are missing"
        )

    # PE metadata

    def directory(self, index):
        directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if index >= len(directories):
            return 0, 0
        entry = directories[index]
        if bool(entry.VirtualAddress) != bool(entry.Size):
            raise ValueError(f"Incomplete PE data directory {index}")
        return entry.VirtualAddress, entry.Size

    @cached_property
    def imports(self):
        """IAT cell VA -> imported symbol. `unnamed` marks a cell known only by its DLL."""
        self.pe.parse_data_directories(directories=[1, 13])
        result = {}
        for attribute, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
            for library in getattr(self.pe, attribute, []):
                dll = library.dll.decode("ascii", errors="replace")
                for symbol in library.imports:
                    name = (
                        symbol.name.decode("ascii", errors="replace") if symbol.name else f"#{symbol.ordinal}"
                    )
                    result[symbol.address] = {"name": f"{dll}!{name}", "delayed": delayed}
        for dll, cell in self._unnamed_imports():
            result.setdefault(cell, {"name": dll, "delayed": False, "unnamed": True})
        return result

    def _unnamed_imports(self):
        """(DLL, cell VA) of the imports whose names a loaded module no longer holds.

        A module without a separate table of names keeps them in the cells themselves, and the loader
        writes the addresses it resolved over them.
        """
        if self.record is None:
            return
        try:
            rva, size = self.directory(1)
            for at in range(self.base + rva, self.base + rva + size - 19, 20):
                names, _, _, dll, cells = struct.unpack("<5I", self.read(at, 20))
                if not dll and not cells:
                    break
                if names or not cells:
                    continue
                region = self.region_at(self.base + dll)
                begin = region.offset + self.base + dll - region.va
                end = self.data.find(b"\0", begin, min(begin + 256, region.offset + region.size))
                name = self.data[begin : max(end, begin)].decode("ascii", errors="replace")
                cell = self.base + cells
                while struct.unpack("<Q", self.read(cell, 8))[0]:
                    yield name, cell
                    cell += 8
        except ValueError:  # unreadable bytes: `damaged` says so in every summary
            return

    @cached_property
    def exports(self):
        self.pe.parse_data_directories(directories=[0])
        directory = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        return [
            {
                "name": symbol.name.decode("ascii", errors="replace") if symbol.name else None,
                "ordinal": symbol.ordinal,
                "rva": symbol.address,
                "forwarder": symbol.forwarder.decode("ascii", errors="replace") if symbol.forwarder else None,
            }
            for symbol in (directory.symbols if directory else [])
        ]

    @cached_property
    def exported(self):
        """VA -> the exports at that address, in table order; a forwarded export has no address in this file."""
        found = {}
        for symbol in self.exports:
            if not symbol["forwarder"]:
                found.setdefault(self.base + symbol["rva"], []).append(symbol)
        return found

    @cached_property
    def _relocations(self):
        """Page RVA -> the entries of that page's base-relocation block."""
        blocks = {}
        try:
            rva, size = self.directory(5)
            raw = self.read(self.base + rva, size) if size else b""
        except ValueError:
            return blocks
        cursor = 0
        while cursor + 8 <= len(raw):
            page, length = struct.unpack_from("<II", raw, cursor)
            if length < 8 or cursor + length > len(raw):
                break
            blocks[page] = raw[cursor + 8 : cursor + length]
            cursor += length
        return blocks

    def relocated(self, va):
        """Whether the image says the 8 bytes at this address hold an address, one the loader adjusts."""
        rva = va - self.base
        wanted = 0xA000 | (rva & 0xFFF)  # IMAGE_REL_BASED_DIR64
        block = self._relocations.get(rva & ~0xFFF, b"")
        return any(entry == wanted for (entry,) in struct.iter_unpack("<H", block[: len(block) & ~1]))

    @cached_property
    def entries(self):
        """RUNTIME_FUNCTION entries (begin RVA, end RVA, unwind-info RVA), sorted."""
        rva, size = self.directory(3)
        if not size:
            return []
        if size % 12:
            raise ValueError("Exception directory size is not a multiple of RUNTIME_FUNCTION size")
        try:
            raw = self.read(self.base + rva, size)
        except ValueError:
            if "unwind data" not in self.damaged:
                raise
            # Unreadable in the process: what does not need function bounds still answers, and
            # every summary carries the warning.
            return []
        entries = [entry for entry in struct.iter_unpack("<III", raw) if entry[0] != entry[1]]
        previous = 0
        for begin, end, unwind in entries:
            if not previous <= begin < end <= self.image_size or not 0 < unwind < self.image_size:
                raise ValueError("Invalid, overlapping, or unsorted exception-directory entries")
            previous = end
        return entries

    @cached_property
    def starts(self):
        return [entry[0] for entry in self.entries]

    def owner(self, va):
        rva = va - self.base
        index = bisect.bisect_right(self.starts, rva) - 1
        return self.entries[index] if index >= 0 and rva < self.entries[index][1] else None

    def unwind_chain(self, entry):
        """The entry and the entries it chains to; the last one starts the function."""
        chain, seen = [], set()
        while True:
            if entry in seen or len(chain) >= 64:
                raise ValueError("Cyclic or excessive unwind chain")
            seen.add(entry)
            begin, end, unwind = entry
            if not 0 <= begin < end <= self.image_size or unwind & 3:
                raise ValueError("Invalid chained RUNTIME_FUNCTION")
            chain.append(entry)
            header = self.read(self.base + unwind, 4)
            version, flags = header[0] & 7, header[0] >> 3
            if version not in (1, 2):
                raise ValueError(f"Unsupported unwind-info version: {version}")
            if not flags & 4:
                return chain
            if flags & 3:
                raise ValueError("Chained unwind info also specifies a handler")
            offset = (4 + header[2] * 2 + 3) & ~3
            entry = struct.unpack("<III", self.read(self.base + unwind + offset, 12))
