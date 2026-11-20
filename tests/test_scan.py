import random
import re
import struct
import unittest

from scripts.references import fields
from scripts.sources import ADDRESS_LIMIT


def reference_fields(data, low, high, start_va, target, kind):
    """The plain search that `fields` must agree with: test every candidate opcode in the range."""
    if kind in ("all", "call", "branch"):
        patterns = [(rb"\xe8", 1, 4)]
        if kind != "call":
            patterns += [(rb"\xe9", 1, 4), (rb"[\xeb\x70-\x7f\xe0-\xe3]", 1, 1), (rb"\x0f[\x80-\x8f]", 2, 4)]
        for pattern, prefix, width in patterns:
            for match in re.compile(b"(?=(" + pattern + b"))").finditer(data, low, high):
                field = match.start() + prefix
                if field + width > high:
                    continue
                value = int.from_bytes(data[field : field + width], "little", signed=True)
                if (start_va + field - low + width + value) % ADDRESS_LIMIT == target:
                    yield field, width, "imm"
    if kind in ("all", "memory"):
        pattern = re.compile(rb"(?=([\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}))", re.DOTALL)
        for match in pattern.finditer(data, low, high):
            field = match.start() + 1
            value = struct.unpack_from("<i", data, field)[0]
            end = start_va + field - low + 4
            if any(
                (end + extra + value) % modulus == target
                for extra in (0, 1, 2, 4)
                for modulus in (ADDRESS_LIMIT, 1 << 32)
            ):
                yield field, 4, "disp"


class OperandFieldTests(unittest.TestCase):
    def test_fast_search_finds_the_same_fields_as_testing_every_candidate(self):
        rng = random.Random(20261120)
        size = 200_000  # several 64 KiB windows
        data = bytearray(rng.randbytes(size))
        opcodes = [b"\xe8", b"\xe9", b"\xeb", b"\x74", b"\xe2", b"\x0f\x84", b"\x8b\x05", b"\x83\x3d"]
        sites = []
        for index in range(4000):  # real reference opcodes, dense at the start for the small range
            opcode = rng.choice(opcodes)
            at = rng.randrange(1, 290 if index < 40 else size - 8)
            data[at : at + len(opcode)] = opcode
            sites.append(at)
        data = bytes(data)

        def destination(at, start_va, low):
            va = start_va + at - low
            if data[at] in (0xE8, 0xE9):
                return (va + 5 + struct.unpack_from("<i", data, at + 1)[0]) % ADDRESS_LIMIT
            if data[at] in (0xEB, 0x74, 0xE2):
                return (va + 2 + struct.unpack_from("<b", data, at + 1)[0]) % ADDRESS_LIMIT
            modulus = ADDRESS_LIMIT if data[at] == 0x0F else rng.choice((ADDRESS_LIMIT, 1 << 32))
            extra = 0 if data[at] == 0x0F else rng.choice((0, 1, 2, 4))
            return (va + 6 + extra + struct.unpack_from("<i", data, at + 2)[0]) % modulus

        checked = matched = 0
        # Images never wrap, but the addresses they refer to can: next to zero and next to 2**64.
        for start_va in (0x140001000, 0x10, ADDRESS_LIMIT - size, (1 << 32) - 70_000):
            for low, high in ((0, size), (65_530, 131_080), (1, 300)):
                inside = [at for at in sites if low <= at < high - 6]
                for at in rng.sample(inside, 10):
                    target = destination(at, start_va, low)
                    for kind in ("call", "branch", "memory", "all"):
                        expected = list(reference_fields(data, low, high, start_va, target, kind))
                        found = list(fields(data, low, high, start_va, target, kind, None))
                        self.assertEqual(found, expected, (hex(start_va), low, high, hex(target), kind))
                        checked += 1
                        matched += bool(expected)
        self.assertGreater(matched, checked // 3)  # the comparison is not vacuous

    def test_short_branches_across_address_zero_are_found(self):
        back = bytes.fromhex("90eb80")  # at va 0x10: jmp to 0x13 - 0x80, below zero
        self.assertEqual(
            list(fields(back, 0, 3, 0x10, (0x13 - 0x80) % ADDRESS_LIMIT, "branch", None)), [(2, 1, "imm")]
        )
        ahead = bytes.fromhex("eb7f90")  # at the top of the address space: jmp past 2**64
        start = ADDRESS_LIMIT - 3
        self.assertEqual(
            list(fields(ahead, 0, 3, start, (start + 2 + 0x7F) % ADDRESS_LIMIT, "all", None)), [(1, 1, "imm")]
        )


if __name__ == "__main__":
    unittest.main()
