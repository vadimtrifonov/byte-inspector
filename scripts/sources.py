from __future__ import annotations

import bisect
import hashlib
import math
import struct
from collections import Counter
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

lazy import pefile

ADDRESS_LIMIT = 1 << 64
PACKED_ENTROPY = 7.0
ENTROPY_SAMPLE = (64, 4096)


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


@dataclass(frozen=True)
class Region:
    """File bytes that are loaded at an address."""

    name: str
    offset: int
    size: int
    va: int
    executable: bool
    writable: bool


class PE:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.data = data = self.path.read_bytes()
        self.pe = pe = pefile.PE(data=data, fast_load=True)
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError("Only AMD64 PE32+ images are supported")
        self.base = base = pe.OPTIONAL_HEADER.ImageBase
        self.image_size = size = pe.OPTIONAL_HEADER.SizeOfImage
        headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        if not 0 < headers <= len(data) or not headers <= size or base + size > ADDRESS_LIMIT:
            raise ValueError("Invalid PE header/image bounds")
        if len(pe.sections) != pe.FILE_HEADER.NumberOfSections:
            raise ValueError("Truncated PE section table")
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
        self.regions = sorted(regions, key=lambda r: r.va)
        self._by_offset = sorted(regions, key=lambda r: r.offset)
        for ordered, key in ((self.regions, "va"), (self._by_offset, "offset")):
            if any(getattr(a, key) + a.size > getattr(b, key) for a, b in zip(ordered, ordered[1:])):
                raise ValueError("Overlapping PE regions are unsupported")
        self._vas = [r.va for r in self.regions]
        self._offsets = [r.offset for r in self._by_offset]

    # Addresses

    def show(self, va):
        """The address as printed and accepted: relative to the image when inside it."""
        if self.base <= va < self.base + self.image_size:
            return f"rva:{va - self.base:#x}"
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
            raise ValueError(f"No bytes in the file at {self.show(va)}")
        return region

    def section_name(self, va):
        rva = va - self.base
        for section in self.sections:
            if section["rva"] <= rva < section["rva"] + max(section["virtual_size"], section["raw_size"]):
                return section["name"]
        return "headers" if 0 <= rva < self.regions[0].size else None

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
            raise ValueError(
                f"Read at {self.show(va)} needs {count} bytes; only {available} available in {region.name}"
            )
        return region.offset + va - region.va

    def va(self, address):
        mode, value = coordinate(address)
        if mode == "va":
            return value
        if mode == "rva":
            if value >= self.image_size:
                raise ValueError("RVA is outside the image")
            return self.base + value
        return self.va_of_offset(value)

    def offset(self, address, count=1):
        mode, value = coordinate(address)
        if mode == "offset":
            if count <= 0 or value + count > len(self.data):
                raise ValueError("Read exceeds the file")
            return value
        return self.offset_of_va(self.va(address), count)

    def locate(self, address):
        """(va, offset) of an address; va is None for file bytes that are not loaded, offset for no file bytes."""
        mode, value = coordinate(address)
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
        return [(max(a, low), min(b, high)) for a, b in ranges if max(a, low) < min(b, high)]

    # Identity

    @cached_property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

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
        """IAT cell VA -> imported symbol."""
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
        return result

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
    def entries(self):
        """RUNTIME_FUNCTION entries (begin RVA, end RVA, unwind-info RVA), sorted."""
        rva, size = self.directory(3)
        if not size:
            return []
        if size % 12:
            raise ValueError("Exception directory size is not a multiple of RUNTIME_FUNCTION size")
        entries = [
            entry
            for entry in struct.iter_unpack("<III", self.read(self.base + rva, size))
            if entry[0] != entry[1]
        ]
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
