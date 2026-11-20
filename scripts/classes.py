"""MSVC x64 class tables (vtables), found through RTTI: by class name, and from a slot back to its class."""

import re
import struct
from dataclasses import dataclass
from functools import lru_cache

from .scan import occurrences

MAX_SLOTS = 4096
PLAIN = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*")
SIMPLE = re.compile(r"\.\?A[VU]([A-Za-z_]\w*(?:@[A-Za-z_]\w*)*)@@")


def readable(decorated):
    """Actor for .?AVActor@@; other decorated names stay as they are."""
    match = SIMPLE.fullmatch(decorated)
    return "::".join(reversed(match[1].split("@"))) if match else decorated


def decorated_names(name):
    if name.startswith(".?A"):
        if not name.startswith((".?AV", ".?AU")) or not name.endswith("@@"):
            raise ValueError("A decorated class or struct name looks like .?AVActor@@")
        return [name]
    if not PLAIN.fullmatch(name):
        raise ValueError(
            "Use a class name such as Actor or BSScript::Object, or a decorated name such as .?AVActor@@"
        )
    body = "@".join(reversed(name.split("::")))
    return [f".?AV{body}@@", f".?AU{body}@@"]


@dataclass(frozen=True)
class Table:
    name: str  # decorated type name
    vtable: int  # VA of slot 0
    subobject: int  # offset of the subobject this table serves
    locator: int  # VA of the complete object locator


class Classes:
    def __init__(self, source):
        self.source = source

    def code_pointer(self, cell):
        """The function a table slot at this address points to, or None when the cell is not a slot.

        In a running process a slot can point outside the image, where a mod redirected it. Such a cell is
        still a slot when the image's relocation data says it holds an address.
        """
        source = self.source
        try:
            value = struct.unpack("<Q", source.read(cell, 8))[0]
        except ValueError:
            return None
        if source.holds(value):
            region = source.region_of(value)
            return value if region is not None and region.executable else None
        return value if source.relocated(cell) else None

    def slot_count(self, vtable, most):
        """The slots of a table, counted up to `most`; it ends at the first cell that is not a slot."""
        count = 0
        while count < most and self.code_pointer(vtable + count * 8) is not None:
            count += 1
        return count

    @lru_cache(maxsize=4096)
    def locator(self, va):
        """(decorated name, subobject offset) of a complete object locator at this address, or None."""
        source = self.source
        try:
            signature, offset, _, descriptor, hierarchy, self_rva = struct.unpack("<6I", source.read(va, 24))
            if signature != 1 or self_rva != va - source.base or not 0 < hierarchy < source.image_size:
                return None
            source.read(source.base + hierarchy, 16)
            name_va = source.base + descriptor + 16
            region = source.region_at(name_va)
            raw = source.read(name_va, min(1024, region.va + region.size - name_va))
        except ValueError:
            return None
        name = raw.split(b"\0", 1)[0]
        if not name.startswith(b".?A") or len(name) == len(raw):
            return None
        return name.decode("ascii", errors="replace"), offset

    def tables(self, decorated):
        """The class tables of a type, the primary one (subobject offset 0) first."""
        source = self.source
        data = source.data
        locators = {}
        for name_offset in occurrences(data, decorated.encode("ascii") + b"\0"):
            try:
                descriptor = source.va_of_offset(name_offset) - 16 - source.base
                source.read(source.base + descriptor, 16)
            except ValueError:
                continue
            if not 0 < descriptor < source.image_size:
                continue
            for reference in occurrences(data, struct.pack("<I", descriptor)):
                try:
                    locator = source.va_of_offset(reference - 12) if reference >= 12 else None
                except ValueError:
                    continue
                found = self.locator(locator) if locator is not None else None
                if found is not None and found[0] == decorated:
                    locators[locator] = found[1]
        tables = {}
        # Locators of one class lie together, so one search per 64 KiB block finds the cells that point to them.
        for block in sorted({locator >> 16 for locator in locators}):
            for region in source.regions:
                end = region.offset + region.size
                for at in occurrences(data, struct.pack("<Q", block << 16)[2:], region.offset + 2, end):
                    locator = struct.unpack_from("<Q", data, at - 2)[0]
                    vtable = region.va + at - 2 - region.offset + 8
                    if locator in locators and not vtable % 8 and self.code_pointer(vtable) is not None:
                        tables[vtable] = Table(decorated, vtable, locators[locator], locator)
        return sorted(tables.values(), key=lambda table: (table.subobject, table.vtable))

    def slot_at(self, cell):
        """(table, slot index) when this address is a slot of a class table."""
        if cell % 8 or self.code_pointer(cell) is None:
            return None
        for index in range(MAX_SLOTS):
            below = cell - 8 * (index + 1)
            if self.code_pointer(below) is not None:
                continue
            try:
                locator = struct.unpack("<Q", self.source.read(below, 8))[0]
            except ValueError:
                return None
            found = self.locator(locator)
            return (Table(found[0], below + 8, found[1], locator), index) if found else None
        return None

    def owners(self, function):
        """Yield (cell VA, table, slot index) for every class-table slot that points to the function."""
        source = self.source
        needle = struct.pack("<Q", function)
        for region in source.regions:
            for offset in occurrences(source.data, needle, region.offset, region.offset + region.size):
                cell = region.va + offset - region.offset
                found = self.slot_at(cell)
                if found:
                    yield cell, *found
