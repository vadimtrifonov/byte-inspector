"""Where functions begin and end.

Unwind data gives the answer for most functions: every entry that chains to one start belongs to that
function, wherever its bytes are. A function without unwind data gets an estimate, labelled with its evidence.
"""

import bisect
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import cached_property, lru_cache

lazy import capstone as cs

from .scan import occurrences, rel32_fields
from .sources import ADDRESS_LIMIT

MAX_DECODE_BYTES = 1 << 20
CALL_CHECKS = 16
PADDING = {"int3", "nop"}
ENDINGS = {"ret", "retf", "jmp", "int3", "iretq", "ud2"}

VERIFIED = "verified"
NO_UNWIND = "no unwind data"
AFTER_GAP = "after undecodable bytes"
AFTER_UNREAD = "after unreadable bytes"
OVER_LIMIT = "function over 1 MiB"


@dataclass(frozen=True)
class Function:
    start: int
    pieces: tuple  # (begin VA, end VA) in address order
    estimated: tuple = ()  # the evidence for the start, when there is no unwind data


class Functions:
    def __init__(self, source):
        self.source = source

    @cached_property
    def lite(self):
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

    # Unwind data

    @cached_property
    def fragments(self):
        """Start RVA -> indices of all unwind entries of that function, for functions with chained entries."""
        source = self.source
        entries, data, base = source.entries, source.data, source.base
        if not entries:
            return {}
        unwinds = [entry[2] for entry in entries]
        region = source.region_of(base + min(unwinds))
        if region is None or base + max(unwinds) + 4 > region.va + region.size:
            return self._fragments_by_chain()
        delta = region.offset - (region.va - base)
        end = region.offset + region.size
        by_begin = {entry[0]: index for index, entry in enumerate(entries)}
        parents = {}
        for index, unwind in enumerate(unwinds):
            at = unwind + delta
            if data[at] & 0x20:  # UNW_FLAG_CHAININFO
                at += (4 + data[at + 2] * 2 + 3) & ~3
                if at + 4 <= end:
                    parents[index] = struct.unpack_from("<I", data, at)[0]
        groups = defaultdict(list)
        for index in parents:
            root, steps = parents[index], 0
            while (parent := by_begin.get(root)) in parents and steps < 64:
                root, steps = parents[parent], steps + 1
            groups[root].append(index)
        for root, indices in groups.items():
            if root in by_begin:
                indices.append(by_begin[root])
            indices.sort()
        return dict(groups)

    def _fragments_by_chain(self):
        groups = defaultdict(set)
        for index, entry in enumerate(self.source.entries):
            try:
                chain = self.source.unwind_chain(entry)
            except ValueError:
                continue
            if len(chain) > 1:
                root = chain[-1][0]
                groups[root].add(index)
                position = bisect.bisect_left(self.source.starts, root)
                if position < len(self.source.starts) and self.source.starts[position] == root:
                    groups[root].add(position)
        return {root: sorted(indices) for root, indices in groups.items()}

    @lru_cache(maxsize=4096)
    def _root(self, entry):
        return self.source.unwind_chain(entry)[-1]

    def start(self, va):
        """The start of the function that unwind data places this address in, or None."""
        entry = self.source.owner(va)
        if entry is None:
            return None
        try:
            return self.source.base + self._root(entry)[0]
        except ValueError:
            return None

    @lru_cache(maxsize=1024)
    def function(self, va):
        source = self.source
        entry = source.owner(va)
        if entry is None:
            return self.estimate(va)
        root = self._root(entry)
        indices = self.fragments.get(root[0])
        ranges = sorted({root[:2], entry[:2], *(source.entries[i][:2] for i in indices or ())})
        pieces = []
        for begin, end in ranges:
            if pieces and pieces[-1][1] == begin:
                pieces[-1][1] = end
            else:
                pieces.append([begin, end])
        return Function(source.base + root[0], tuple((source.base + a, source.base + b) for a, b in pieces))

    # Instruction boundaries

    @lru_cache(maxsize=128)
    def _decoded(self, begin, end):
        if end - begin > MAX_DECODE_BYTES:
            return [], begin, OVER_LIMIT
        # An unreadable page ends what decoding from the start can confirm; what precedes it stays confirmed.
        unread = self.source.unread_from(begin, end)
        readable = end if unread is None else unread
        starts, stop = [], begin
        if readable > begin:
            for va, size, _, _ in self.lite.disasm_lite(self.source.read(begin, readable - begin), begin):
                starts.append(va)
                stop = va + size
        return starts, stop, AFTER_GAP if unread is None or stop + 15 <= unread else AFTER_UNREAD

    def _span(self, va):
        entry = self.source.owner(va)
        return (self.source.base + entry[0], self.source.base + entry[1]) if entry else None

    def boundary(self, va):
        """How far an instruction start at this address is supported; None when it is inside an instruction."""
        span = self._span(va)
        if span is None:
            return NO_UNWIND
        starts, stop, reason = self._decoded(*span)
        if va >= stop:
            return reason
        index = bisect.bisect_left(starts, va)
        return VERIFIED if index < len(starts) and starts[index] == va else None

    def instruction_at(self, va, span=None):
        """The start of the instruction that holds this address, decoding from the start of its range."""
        span = span or self._span(va)
        if span is None:
            return None
        starts, stop, _ = self._decoded(*span)
        if not span[0] <= va < stop:
            return None
        return starts[bisect.bisect_right(starts, va) - 1]

    # Functions without unwind data

    def estimate(self, va):
        """Walk forward from the last known function end to find the function that holds this address.

        A function ends at a return or jump that no earlier branch jumps past.
        An address that a verified call instruction or a stored pointer refers to starts a function.
        """
        source = self.source
        region = source.region_at(va)
        if not source.image:
            raise ValueError("No function data outside a module; give disasm an explicit --bytes")
        if not region.executable:
            raise ValueError("No function here: the address is not in a code section")
        base = source.base
        index = bisect.bisect_right(source.starts, va - base) - 1
        floor = max(region.va, base + source.entries[index][1] if index >= 0 else 0)
        following = base + source.entries[index + 1][0] if index + 1 < len(source.entries) else ADDRESS_LIMIT
        ceiling = min(region.va + region.size, following, floor + MAX_DECODE_BYTES)
        if not floor <= va < ceiling:
            raise ValueError(
                "No function data within 1 MiB before this address; give disasm an explicit --bytes"
            )
        return self._walk(va, floor, ceiling)

    def _walk(self, va, floor, ceiling):
        source = self.source
        sites, pointers = self._entries_into(floor, ceiling)
        strong = sorted({*sites, *pointers})
        verified = {}

        def calls(target):
            if target not in verified:
                checked = sites.get(target, ())[:CALL_CHECKS]
                verified[target] = sum(1 for site in checked if self.boundary(site) == VERIFIED)
            return verified[target]

        def entered(address):
            return address in pointers or calls(address) > 0

        start = end = on_boundary = None
        ended, reach, padding = True, 0, False
        for address, size, mnemonic, operands in self.lite.disasm_lite(
            source.read(floor, ceiling - floor), floor
        ):
            if on_boundary is None and address > va:
                on_boundary = False
            if on_boundary is not None and (
                ended
                or (mnemonic == "int3" and reach <= address)
                or (address != start and address in strong and entered(address))
            ):
                end = address
                break
            if ended:
                if mnemonic in PADDING and address != va:
                    start = None
                    continue
                if mnemonic == "int3":
                    padding = True
                    break
                start, ended, reach = address, False, 0
            elif on_boundary is None and address != start and address in strong and entered(address):
                start, reach = address, 0
            if address == va:
                on_boundary = True
            if mnemonic[0] == "j" or mnemonic.startswith("loop"):
                try:
                    target = int(operands, 16)
                except ValueError:
                    target = None
                if target is not None and address < target < ceiling and target > reach:
                    low = bisect.bisect_right(strong, address + size)
                    high = bisect.bisect_right(strong, target)
                    if not any(entered(candidate) for candidate in strong[low:high]):
                        reach = target
            if mnemonic in ENDINGS and reach < address + size:
                ended = True
            end = address + size
        if on_boundary is None and not padding:
            raise ValueError(
                "Cannot estimate a function: the bytes before this address do not decode as code"
            )
        if start is None or padding:
            raise ValueError("No function here: the address is in padding between functions")
        evidence = []
        if calls(start):
            more = "at least " if len(sites[start]) > CALL_CHECKS else ""
            evidence.append(f"{more}{calls(start)} direct call{'s' if calls(start) != 1 else ''}")
        if pointers.get(start):
            evidence.append(f"{pointers[start]} pointer{'s' if pointers[start] != 1 else ''}")
        return Function(start, ((start, end),), tuple(evidence or ["the preceding code only"]))

    @lru_cache(maxsize=256)
    def _entries_into(self, floor, ceiling):
        """Call sites and stored pointers that refer into [floor, ceiling), by destination."""
        source = self.source
        data = source.data
        sites = defaultdict(list)
        for low, high in source.spans(executable=True):
            start_va = source.va_of_offset(low)
            for field, target in rel32_fields(data, low, high, start_va, floor, width=ceiling - floor):
                if field > low and data[field - 1] == 0xE8:
                    sites[target].append(start_va + field - 1 - low)
        pointers = Counter()
        for block in range(floor >> 16, ((ceiling - 1) >> 16) + 1):
            prefix = struct.pack("<Q", block << 16)[2:]
            for region in source.regions:
                if region.executable:
                    continue
                for at in occurrences(data, prefix, region.offset + 2, region.offset + region.size):
                    target = struct.unpack_from("<Q", data, at - 2)[0]
                    if floor <= target < ceiling:
                        pointers[target] += 1
        return sites, pointers
