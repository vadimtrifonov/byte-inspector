import hashlib
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

from support import BASE, fixture, saved_copy

from scripts.analysis import Inspector
from scripts.references import access, float_type
from scripts.sources import PE


def one(answers):
    """The summary and rows of a command that returns one answer."""
    ((summary, rows),) = answers
    return summary, rows


def addresses(rows):
    return [row["address"] for row in rows]


def rip(at, opcode, target):
    """An instruction at RVA `at` whose RIP-relative operand refers to RVA `target`."""
    return opcode + struct.pack("<i", target - at - len(opcode) - 4)


class InspectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="byte-inspector-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = fixture(self.root / "fixture.dll")
        self.source = PE(self.path)
        self.inspector = Inspector(self.source)

    def patched(self, patches, name="patched.dll"):
        return Inspector(PE(fixture(self.root / name, patches)))

    def loaded(self, name="loaded.bin", **changes):
        """The fixture as saved from a process that had it loaded."""
        return Inspector(PE(saved_copy(self.path, self.root / name, **changes)))

    def test_identity_mapping_imports_and_exports(self):
        source = self.source
        self.assertEqual(source.sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(source.va("rva:0x2040"), BASE + 0x2040)
        self.assertEqual(source.va_of_offset(0x840), BASE + 0x2040)
        self.assertEqual(source.offset("va:0x140002040"), 0x840)
        self.assertEqual(source.locate("offset:0x840"), (BASE + 0x2040, 0x840))
        self.assertEqual(source.imports[BASE + 0x2190]["name"], "KERNEL32.dll!LoadLibraryW")
        self.assertEqual(source.exports[0]["name"], "Exported")
        self.assertEqual(source.exports[1]["forwarder"], "OTHER.forwarded")
        self.assertIsNone(source.exports[1]["name"])
        for address, count in ((BASE + 0x1400, 1), (BASE + 0x13FF, 2), (BASE + 0x3FFF, 2)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                source.read(address, count)

    def test_printed_addresses_are_relative_inside_the_image_and_offsets_only_when_not_loaded(self):
        source = self.source
        self.assertEqual(source.show(BASE + 0x2040), "rva:0x2040")
        self.assertEqual(source.show(BASE + 0x4000), "va:0x140004000")
        self.assertEqual(source.show_offset(0x840), "rva:0x2040")
        self.assertEqual(source.show_offset(0x1200), "offset:0x1200")
        self.assertEqual(source.locate("offset:0x1200"), (None, 0x1200))
        self.assertEqual(source.locate("rva:0x1400"), (BASE + 0x1400, None))  # in .text, past its file bytes
        for address in ("0x1000", "rva:", "file:0x10", "rva:zz", "rva:0x4000", "offset:0x2000"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                source.locate(address)

    def test_text_search_returns_the_enclosing_string(self):
        find = self.inspector.find
        summary, rows = one(find(text="Name"))
        self.assertEqual(summary["results"], 1)
        self.assertEqual(rows, [{"address": "rva:0x2040", "string": "AnchorName", "match": "+6"}])
        _, rows = one(find(text="name", encoding="both", ignore_case=True))
        self.assertEqual(
            rows,
            [
                {"address": "rva:0x2040", "string": "AnchorName", "match": "+6"},
                {"address": "rva:0x2060", "string": "WideName", "encoding": "utf-16le", "match": "+4"},
            ],
        )
        self.assertEqual(one(find(text="name", encoding="both"))[0]["results"], 0)
        # File bytes that are not loaded have no address; the row leads with the file offset instead.
        _, rows = one(find(text="Anchor", scope={"start": "offset:0x1200", "length": 14}))
        self.assertEqual(rows, [{"address": "offset:0x1200", "string": "OverlayAnchor", "match": "+7"}])

    def test_a_match_far_into_a_string_leads_with_the_address_a_pointer_holds(self):
        text = b"Line one.\n" + b"x" * 300 + b" needle here\0"
        inspector = self.patched({0x2600: text, 0x2780: struct.pack("<Q", BASE + 0x2600)})
        _, rows = one(inspector.find(text="needle"))
        self.assertEqual((rows[0]["address"], rows[0]["match"]), ("rva:0x2600", "+311"))
        shown = rows[0]["string"]  # a part of the text around the match
        self.assertTrue(shown.startswith("...x") and shown.endswith("x needle here"), shown)
        self.assertEqual(
            addresses(one(inspector.refs(rows[0]["address"], kind="pointer"))[1]), ["rva:0x2780"]
        )

    def test_ignoring_case_applies_to_ascii_letters_only(self):
        find = self.patched({0x2600: "\u0141\0\u0142\0\u0161\0".encode("utf-16le")}).find
        _, rows = one(find(text="\u0141", encoding="utf-16le", ignore_case=True))
        self.assertEqual(addresses(rows), ["rva:0x2600"])  # not U+0161, whose low byte is a lowered 'A'

    def test_patterns_numbers_scopes_and_exact_counts(self):
        find = self.patched({0x2700: b"AAA"}).find
        summary, rows = one(find(pattern="48 8D ?? ?? ?? ?? ??"))
        self.assertEqual(summary["results"], 1)
        self.assertEqual(
            rows, [{"address": "rva:0x1000", "bytes": "48 8d 0d 39 10 00 00", "function_start": True}]
        )
        summary, rows = one(find(pattern="00 00", limit=2))
        self.assertEqual((summary["showing"], len(rows)), (2, 2))
        self.assertGreater(summary["results"], 2)
        self.assertEqual(one(find(text="AnchorName", scope={"section": ".text"}))[0]["results"], 0)
        _, rows = one(find(value=str(BASE + 0x2040), value_type="u64"))
        self.assertEqual(addresses(rows), ["rva:0x2088"])
        self.assertEqual(one(find(text="AA"))[0]["results"], 2)  # overlapping matches count
        for kwargs in ({"pattern": "?? ??"}, {"pattern": "GG"}, {"text": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                find(**kwargs)
        with self.assertRaisesRegex(ValueError, "together"):
            find(text="Anchor", scope={"start": "rva:0x1000"})

    def test_callers_validate_boundaries_and_name_their_function(self):
        refs = self.inspector.refs
        summary, rows = one(refs("rva:0x1050", kind="call"))
        self.assertEqual(summary["target"], {"export": "Exported", "function_start": True})
        self.assertEqual(
            rows,
            [
                {"address": "rva:0x1007", "instruction": "call rva:0x1050", "function": "rva:0x1000"},
                # Without unwind data the function is an estimate, and the row says so.
                {
                    "address": "rva:0x1040",
                    "instruction": "call rva:0x1050",
                    "function": "rva:0x1040",
                    "estimated_from": "the preceding code only",
                    "unverified": "no unwind data",
                },
                # The instruction keeps its prefix, and its site is the function's own start.
                {"address": "rva:0x1060", "instruction": "call rva:0x1050", "function": "rva:0x1060"},
            ],
        )  # The E8 inside the movabs at 0x100c is not a call.
        summary, rows = one(refs("rva:0x1050", kind="call", limit=1))  # all are counted
        self.assertEqual((summary["results"], summary["showing"], addresses(rows)), (3, 1, ["rva:0x1007"]))
        _, rows = one(refs("rva:0x1030", kind="branch"))
        self.assertEqual(
            rows, [{"address": "rva:0x102e", "instruction": "jmp rva:0x1030", "function": "rva:0x1000"}]
        )

    def test_pointer_references_name_the_class_slot_they_are(self):
        _, rows = one(self.inspector.refs("rva:0x1050", kind="pointer"))
        self.assertEqual(
            rows,
            [
                {"address": "rva:0x2080", "pointer": True},
                {"address": "rva:0x2508", "pointer": True, "class": "Widget", "slot": 0},
                {"address": "rva:0x2548", "pointer": True, "class": "Widget", "slot": 0},
            ],
        )
        summary, rows = one(self.inspector.refs("offset:0x1200"))
        self.assertEqual((summary["results"], summary["not_loaded"], rows), (0, True, []))
        self.assertEqual(
            one(self.inspector.refs("offset:0x840", kind="pointer"))[1],
            [{"address": "rva:0x2088", "pointer": True}],
        )

    def test_memory_refs_cover_vex_trailing_immediates_and_import_slots(self):
        refs = self.inspector.refs
        summary, rows = one(refs("rva:0x2040", kind="memory"))
        self.assertEqual(summary["target"], {"string": "AnchorName"})
        self.assertEqual(addresses(rows), ["rva:0x1000", "rva:0x1016", "rva:0x1026"])
        self.assertEqual(  # lea, cmp, vmovss: a row says what its instruction does with the address
            [[use for use in ("address_taken", "read", "write") if use in row] for row in rows],
            [["address_taken"], ["read"], ["read"]],
        )
        summary, rows = one(refs("rva:0x2190", kind="memory"))
        self.assertEqual(summary["target"], {"import": "KERNEL32.dll!LoadLibraryW"})
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x1050",
                    "instruction": "call qword ptr [rip + 0x113a]",
                    "read": True,
                    "function": "rva:0x1050",
                }
            ],
        )
        _, rows = one(refs(displacement=0x3F4))
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x1020",
                    "instruction": "mov eax, dword ptr [rcx + 0x3f4]",
                    "read": True,
                    "function": "rva:0x1000",
                }
            ],
        )
        with self.assertRaisesRegex(ValueError, "nonzero"):
            refs(displacement=0)

    def test_what_an_instruction_does_with_its_memory_operand(self):
        cases = {  # code: (use of the operand, float it reads)
            "488d0510000000": (("address_taken",), None),  # lea rax, [rip + 0x10]
            "488b0510000000": (("read",), None),  # mov rax, [rip + 0x10]
            "48890510000000": (("write",), None),  # mov [rip + 0x10], rax
            "833d1000000001": (("read",), None),  # cmp dword ptr [rip + 0x10], 1
            "840510000000": (("read",), None),  # test byte ptr [rip + 0x10], al
            "83251000000001": (("read", "write"), None),  # and dword ptr [rip + 0x10], 1
            "f0480fb10d10000000": (("read", "write"), None),  # lock cmpxchg [rip + 0x10], rcx
            "ff0510000000": (("read", "write"), None),  # inc dword ptr [rip + 0x10]
            "0f950510000000": (("write",), None),  # setne byte ptr [rip + 0x10]
            "ff1510000000": (("read",), None),  # call qword ptr [rip + 0x10]
            "0f1f4010": ((), None),  # nop dword ptr [rax + 0x10]
            "a5": ((), None),  # movsd, the string instruction
            "c5fa110510000000": (("write",), None),  # vmovss [rip + 0x10], xmm0
            "c5fa100510000000": (("read",), "f32"),  # vmovss xmm0, [rip + 0x10]
            "c5fa590510000000": (("read",), "f32"),  # vmulss xmm0, xmm0, [rip + 0x10]
            "f20f100510000000": (("read",), "f64"),  # movsd xmm0, [rip + 0x10]
            "f20f5a0510000000": (("read",), "f64"),  # cvtsd2ss xmm0, [rip + 0x10]
            "f30f2a0510000000": (("read",), None),  # cvtsi2ss xmm0, [rip + 0x10] reads an integer
            "660f383d0510000000": (("read",), None),  # pmaxsd xmm0, [rip + 0x10] reads four integers
            "62f17c58590510000000": (("read",), None),  # vmulps zmm0, zmm0, [rip + 0x10]{1to16}
        }
        for code, expected in cases.items():
            ins = next(self.inspector.decoder.disasm(bytes.fromhex(code), 0x1000))
            with self.subTest(instruction=f"{ins.mnemonic} {ins.op_str}"):
                self.assertEqual((access(ins), float_type(ins)), expected)

    def test_reference_scans_deduplicate_operand_fields(self):
        code = bytes.fromhex(
            "488d05f90f0000" + "c5f8118424e0010000" * 2 + "488d4c2440e8dd00000048ff15d6100000"
        )
        refs = self.patched({0x1100: code}).refs
        scope = {"start": "rva:0x1100", "length": len(code)}
        summary, rows = one(refs("rva:0x2100", kind="memory", scope=scope))
        self.assertEqual(summary["results"], 1)
        self.assertEqual(
            (rows[0]["address"], rows[0]["instruction"]), ("rva:0x1100", "lea rax, [rip + 0xff9]")
        )
        _, rows = one(refs(displacement=0x1E0, scope=scope))
        self.assertEqual(addresses(rows), ["rva:0x1107", "rva:0x1110"])
        self.assertTrue(all(row["instruction"].startswith("vmovups") for row in rows))
        self.assertTrue(all(row["unverified"] == "no unwind data" for row in rows))
        _, rows = one(refs("rva:0x1200", kind="call", scope=scope))
        self.assertEqual(addresses(rows), ["rva:0x111e"])
        _, rows = one(refs("rva:0x2200", kind="memory", scope=scope))
        self.assertEqual(addresses(rows), ["rva:0x1123"])  # the REX prefix belongs to the instruction

        # A prefix byte before a function must not hide its verified first instruction.
        summary, rows = one(self.patched({0x104F: b"\x48"}, "prefix.dll").refs("rva:0x2190", kind="memory"))
        self.assertEqual(summary["results"], 1)
        self.assertEqual(rows[0]["address"], "rva:0x1050")
        self.assertNotIn("unverified", rows[0])

    def test_loop_references_preserve_counter_address_size(self):
        for code in ("67e006", "67e106", "67e206"):
            with self.subTest(code=code):
                refs = self.patched({0x1100: bytes.fromhex(code)}, f"loop-{code}.dll").refs
                _, rows = one(refs("rva:0x1109", kind="branch", scope={"start": "rva:0x1100", "length": 3}))
                self.assertEqual(addresses(rows), ["rva:0x1100"])
                self.assertEqual(rows[0]["unverified"], "no unwind data")

    def test_eip_relative_addresses_and_negative_displacements(self):
        origin = BASE + 0x1070
        displacement = 0x2040 - ((origin + 8) % (1 << 32))
        code = b"\x67\x48\x8b\x05" + struct.pack("<i", displacement) + b"\x48\x8b\x41\xf8\xc3"
        refs = self.patched({0x1070: code}).refs
        _, rows = one(refs("va:0x2040", kind="memory"))
        self.assertEqual(addresses(rows), ["rva:0x1070"])
        _, rows = one(refs(displacement=-8, scope={"start": "rva:0x1070", "length": len(code)}))
        self.assertIn("rva:0x1078", addresses(rows))

    def test_a_function_is_every_unwind_entry_that_chains_to_one_start(self):
        functions = self.inspector.functions
        expected = ((BASE + 0x1000, BASE + 0x1030), (BASE + 0x1080, BASE + 0x1090))
        for inside in (0x1000, 0x1028, 0x1085):  # the start, an adjacent chained entry, a separated piece
            found = functions.function(BASE + inside)
            self.assertEqual((found.start, found.pieces, found.estimated), (BASE + 0x1000, expected, ()))
        self.assertEqual(functions.start(BASE + 0x1085), BASE + 0x1000)
        self.assertEqual(functions.function(BASE + 0x1034).pieces, ((BASE + 0x1030, BASE + 0x1040),))
        summary, rows = one(self.inspector.disasm("rva:0x1085", function=True))
        self.assertEqual(summary["function"], "rva:0x1000")
        self.assertEqual(summary["pieces"], ["rva:0x1000..rva:0x1030", "rva:0x1080..rva:0x1090"])
        self.assertEqual(summary["instructions"], len(rows))
        self.assertLess(addresses(rows).index("rva:0x102e"), addresses(rows).index("rva:0x1080"))
        cyclic = self.patched({0x2218: struct.pack("<III", 0x1020, 0x1030, 0x2210)}, "cycle.dll")
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            cyclic.functions.function(BASE + 0x1020)

    def test_a_function_without_unwind_data_gets_an_estimate_with_its_evidence(self):
        functions = self.inspector.functions
        called = functions.function(BASE + 0x10A5)
        self.assertEqual((called.start, called.pieces), (BASE + 0x10A0, ((BASE + 0x10A0, BASE + 0x10A6),)))
        self.assertEqual(called.estimated, ("1 direct call", "1 pointer"))
        bare = functions.function(BASE + 0x10B2)
        self.assertEqual((bare.start, bare.pieces), (BASE + 0x10B0, ((BASE + 0x10B0, BASE + 0x10B3),)))
        self.assertEqual(bare.estimated, ("the preceding code only",))
        self.assertIsNone(functions.start(BASE + 0x10A5))  # result rows name functions from unwind data only
        summary, rows = one(self.inspector.disasm("rva:0x10a5", function=True))
        self.assertEqual(summary["estimated_from"], "1 direct call, 1 pointer")
        self.assertEqual(addresses(rows), ["rva:0x10a0", "rva:0x10a5"])
        with self.assertRaisesRegex(ValueError, "padding"):
            functions.function(BASE + 0x1098)
        with self.assertRaisesRegex(ValueError, "not in a code section"):
            functions.function(BASE + 0x2040)

    def test_empty_unwind_entries_leave_valid_ranges_intact(self):
        expected = self.source.entries
        entries = [expected[0], (0x1020, 0x1020, 0x2210), *expected[1:]]
        raw = bytearray(self.path.read_bytes())
        table = b"".join(struct.pack("<III", *entry) for entry in entries)
        raw[0x1000 : 0x1000 + len(table)] = table
        struct.pack_into("<I", raw, 0x98 + 112 + 3 * 8 + 4, len(table))
        self.path.write_bytes(raw)
        source = PE(self.path)
        self.assertEqual(source.entries, expected)
        self.assertEqual(source.owner(BASE + 0x1020), expected[1])
        self.assertEqual(Inspector(source).info()["sections"][0]["unwind_entries"], len(expected))
        struct.pack_into("<III", raw, 0x100C, 0x1021, 0x1020, 0x2210)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "exception-directory"):
            _ = PE(self.path).entries

    def test_disassembly_ranges_limits_and_undecodable_bytes(self):
        disasm = self.inspector.disasm
        summary, rows = one(disasm("rva:0x1000", byte_count=32, limit=1))
        self.assertEqual(
            (summary["range"], summary["instructions"], summary["showing"]), ("rva:0x1000..rva:0x1020", 7, 1)
        )
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x1000",
                    "instruction": "lea rcx, [rip + 0x1039]",
                    "target": {"address": "rva:0x2040", "string": "AnchorName"},
                }
            ],
        )
        _, rows = one(disasm("rva:0x1007", byte_count=5, show_bytes=True))
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x1007",
                    "bytes": "e8 44 00 00 00",
                    "instruction": "call rva:0x1050",
                    "target": {"address": "rva:0x1050", "export": "Exported"},
                }
            ],
        )
        self.assertEqual(
            one(disasm("rva:0x1000"))[0]["range"], "rva:0x1000..rva:0x1100"
        )  # 256 bytes by default
        # A listing starts at the instruction that holds the address, where unwind data shows one.
        summary, rows = one(disasm("rva:0x1009", byte_count=3))
        self.assertEqual(
            (summary["range"], summary["inside_instruction"], addresses(rows)),
            ("rva:0x1007..rva:0x100c", "rva:0x1007", ["rva:0x1007"]),
        )
        summary, rows = one(disasm("rva:0x10a1", byte_count=4))
        self.assertEqual(
            (summary["range"], addresses(rows)), ("rva:0x10a1..rva:0x10a5", ["rva:0x10a1", "rva:0x10a3"])
        )
        self.assertNotIn("inside_instruction", summary)
        # A listing that stops before the end of its range says where, and which of two reasons applies.
        summary, rows = one(disasm("rva:0x1000", byte_count=3))
        self.assertEqual((rows, summary["ends_inside_instruction"]), ([], ["rva:0x1000"]))
        summary, rows = one(
            self.patched({0x1100: bytes.fromhex("900690")}).disasm("rva:0x1100", byte_count=3)
        )
        self.assertEqual((summary["instructions"], summary["undecodable_at"]), (1, ["rva:0x1101"]))
        summary, rows = one(self.patched({0x1057: b"\x06"}, "gap.dll").disasm("rva:0x1050", function=True))
        self.assertEqual((summary["instructions"], summary["undecodable_at"]), (2, ["rva:0x1057"]))
        # Every piece of a function that stops short is named.
        broken = self.patched({0x1000: b"\x06", 0x1080: b"\x06"}, "two.dll")
        summary, _ = one(broken.disasm("rva:0x1000", function=True))
        self.assertEqual(summary["undecodable_at"], ["rva:0x1000", "rva:0x1080"])
        with self.assertRaisesRegex(ValueError, "only 2 available"):
            disasm("rva:0x13fe", byte_count=3)
        with self.assertRaisesRegex(ValueError, "not loaded"):
            disasm("offset:0x1200")

    def test_a_listing_shows_the_float_read_from_read_only_data(self):
        code = (
            rip(0x1100, bytes.fromhex("c5fa5905"), 0x2700)  # vmulss xmm0, xmm0, [0x2700]
            + rip(0x1108, bytes.fromhex("f20f1005"), 0x2708)  # movsd xmm0, [0x2708]
            + rip(0x1110, bytes.fromhex("c5fa1105"), 0x2700)  # vmovss [0x2700], xmm0
        )
        patches = {0x1100: code, 0x2700: struct.pack("<f4xd", 0.5625, 0.1)}
        _, rows = one(self.patched(patches).disasm("rva:0x1100", byte_count=len(code)))
        self.assertEqual(
            [row["target"] for row in rows],
            [
                {"address": "rva:0x2700", "f32": "0.5625"},
                {"address": "rva:0x2708", "f64": "0.1"},
                {"address": "rva:0x2700"},  # a store reads nothing
            ],
        )
        # A value in a writable section is only what the file starts with, so it is not shown.
        path = fixture(self.root / "writable.dll", patches)
        raw = bytearray(path.read_bytes())
        struct.pack_into("<I", raw, 0x188 + 40 + 36, 0xC0000040)
        path.write_bytes(raw)
        _, rows = one(Inspector(PE(path)).disasm("rva:0x1100", byte_count=8))
        self.assertEqual(rows[0]["target"], {"address": "rva:0x2700"})

    def test_a_stub_that_jumps_to_an_import_carries_its_name(self):
        name = "KERNEL32.dll!LoadLibraryW"
        patched = self.patched(
            {
                0x1300: rip(0x1300, b"\xff\x25", 0x2190),
                0x1310: rip(0x1310, b"\x48\xff\x25", 0x2190),  # the same jump with a REX.W prefix
                0x1320: rip(0x1320, b"\xe8", 0x1300) + rip(0x1325, b"\xe9", 0x1310),
                0x1330: rip(0x1330, b"\xff\x25", 0x2040),  # a jump through a cell that is not an import
            },
            "stubs.dll",
        )
        _, rows = one(patched.disasm("rva:0x1320", byte_count=10))
        self.assertEqual(
            [row["target"] for row in rows],
            [{"address": "rva:0x1300", "import_stub": name}, {"address": "rva:0x1310", "import_stub": name}],
        )
        self.assertEqual(one(patched.refs("rva:0x1300", kind="call"))[0]["target"], {"import_stub": name})
        self.assertIn({"address": "rva:0x1300", "import_stub": name}, one(patched.describe("rva:0x1300"))[1])
        self.assertEqual(patched.import_stub(BASE + 0x1330), {})
        self.assertEqual(patched.import_stub(BASE + 0x2190), {})  # the import cell is not code

    def test_typed_reads_floats_and_pointer_tables(self):
        values = struct.pack("<fffi", float("nan"), 70.0, 0.1, -2) + bytes.fromhex("ffff7f7f")
        data = self.patched({0x2700: values}).data
        summary, rows = one(data("rva:0x2080", value_type="pointer", count=3))
        self.assertEqual(summary, {"type": "pointer", "count": 3})
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x2080",
                    "points_to": {"address": "rva:0x1050", "export": "Exported", "function_start": True},
                },
                {"address": "rva:0x2088", "points_to": {"address": "rva:0x2040", "string": "AnchorName"}},
                {"address": "rva:0x2090", "points_to": {"address": "rva:0x10a0"}},
            ],
        )
        _, rows = one(data("rva:0x2700", value_type="f32", count=3))
        self.assertEqual([row["value"] for row in rows], ["nan", "70.0", "0.1"])
        json.dumps(rows, allow_nan=False)
        self.assertEqual(one(data("rva:0x2710", value_type="f32", count=1))[1][0]["value"], "3.4028235e+38")
        _, rows = one(data("rva:0x270c", value_type="i32", count=1))
        self.assertEqual(rows, [{"address": "rva:0x270c", "value": -2, "hex": "0xfffffffe"}])
        _, rows = one(data("offset:0x1200", count=14))  # bytes that are not loaded can still be read
        self.assertEqual(
            rows,
            [
                {
                    "address": "offset:0x1200",
                    "bytes": "4f 76 65 72 6c 61 79 41 6e 63 68 6f 72 00",
                    "ascii": "OverlayAnchor.",
                }
            ],
        )
        with self.assertRaises(ValueError):
            data("rva:0x13ff", value_type="u32", count=1)
        with self.assertRaises(ValueError):
            data("offset:0x1200", count=20)

    def test_class_tables_by_name_list_the_primary_table_first(self):
        rtti = self.inspector.rtti
        primary, secondary = rtti("Widget", slots=8)
        self.assertEqual(
            primary[0],
            {
                "table": "1 of 2",
                "type": ".?AVWidget@@",
                "vtable": "rva:0x2548",
                "subobject": "+0x0",
                "slots": 2,
                "table_ends_before_slot": 2,
            },
        )
        # Slot rows lead with the function, so they can be given to disasm.
        self.assertEqual(
            primary[1],
            [
                {"address": "rva:0x1050", "slot": 0, "cell": "rva:0x2548"},
                {"address": "rva:0x1000", "slot": 1, "cell": "rva:0x2550"},
            ],
        )
        self.assertEqual((secondary[0]["vtable"], secondary[0]["subobject"]), ("rva:0x2508", "+0x48"))
        self.assertEqual(rtti(".?AVWidget@@", slots=8), [primary, secondary])
        selected = rtti("Widget", slot_start=1, slots=1)[0]
        self.assertEqual((selected[0]["slots"], selected[0]["table_ends_before_slot"]), (1, None))
        self.assertEqual(selected[1][0]["slot"], 1)
        # A request past a table's last slot returns nothing, not the cells of the table that follows.
        primary, secondary = rtti("Widget", slot_start=8, slots=1)
        self.assertEqual((primary[1], primary[0]["table_ends_before_slot"]), ([], 2))
        self.assertEqual((secondary[1], secondary[0]["table_ends_before_slot"]), ([], 1))
        self.assertEqual(rtti("Gadget"), [({"tables": 0}, [])])
        for name in ("Widget@@", ".?AXWidget@@", "a b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                rtti(name)

    def test_describe_says_what_an_address_holds(self):
        describe = self.inspector.describe
        summary, rows = one(describe("rva:0x1050"))
        self.assertEqual(summary, {"section": ".text", "in_file": "offset:0x450", "results": 4, "note": None})
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x1050",
                    "function_pieces": ["rva:0x1050..rva:0x1060"],
                    "function_size": "0x10",
                },
                # After the function come the names it is exported by and the class slots it fills.
                {"address": "rva:0x1050", "export": "Exported", "ordinal": 1},
                # One function can be a slot of several class tables; each is a row.
                {
                    "address": "rva:0x2508",
                    "class": "Widget",
                    "slot": 0,
                    "vtable": "rva:0x2508",
                    "subobject": "+0x48",
                },
                {
                    "address": "rva:0x2548",
                    "class": "Widget",
                    "slot": 0,
                    "vtable": "rva:0x2548",
                    "subobject": "+0x0",
                },
            ],
        )
        _, rows = one(describe("rva:0x1056"))  # further into the function, its export is still named
        self.assertEqual((rows[0]["query_at"], rows[1]["export"]), ("+0x6", "Exported"))
        # Several exports can share an address; where one name is shown, `+N` counts the others.
        shared = self.patched({0x22C4: struct.pack("<I", 0x1050)}, "shared.dll")
        self.assertEqual(shared.facts(BASE + 0x1050), {"export": "Exported +1", "function_start": True})
        self.assertEqual(
            [row.get("ordinal") for row in one(shared.describe("rva:0x1050"))[1]][:3], [None, 1, 2]
        )
        _, rows = one(describe("rva:0x1087"))  # in a separated piece, and inside no instruction
        self.assertEqual(
            rows[0],
            {
                "address": "rva:0x1000",
                "function_pieces": ["rva:0x1000..rva:0x1030", "rva:0x1080..rva:0x1090"],
                "function_size": "0x40",
                "query_at": "+0x87",
            },
        )
        self.assertEqual(one(describe("rva:0x1009"))[1][0]["inside_instruction"], "rva:0x1007")
        _, rows = one(describe("rva:0x10a2"))
        self.assertEqual(
            (rows[0]["estimated_from"], rows[0]["inside_instruction"]),
            ("1 direct call, 1 pointer", "rva:0x10a0"),
        )
        _, rows = one(describe("rva:0x2550"))
        self.assertEqual(
            rows,
            [
                {
                    "address": "rva:0x2550",
                    "class": "Widget",
                    "slot": 1,
                    "vtable": "rva:0x2548",
                    "subobject": "+0x0",
                    "points_to": {"address": "rva:0x1000", "function_start": True},
                }
            ],
        )
        self.assertEqual(
            one(describe("rva:0x2060"))[1],
            [{"address": "rva:0x2060", "string": "WideName", "encoding": "utf-16le"}],
        )
        # An address inside a string is described by the string, which starts where code refers to it.
        self.assertEqual(
            one(describe("rva:0x2045"))[1],
            [{"address": "rva:0x2040", "string": "AnchorName", "encoding": "ascii", "query_at": "+0x5"}],
        )
        self.assertEqual(self.inspector.facts(BASE + 0x2045), {"inside_string": "rva:0x2040"})
        self.assertEqual(  # the second byte of a UTF-16 character
            one(describe("rva:0x2065"))[1],
            [{"address": "rva:0x2060", "string": "WideName", "encoding": "utf-16le", "query_at": "+0x5"}],
        )
        self.assertEqual(
            one(describe("rva:0x2190"))[1], [{"address": "rva:0x2190", "import": "KERNEL32.dll!LoadLibraryW"}]
        )
        summary, rows = one(describe("rva:0x1098"))
        self.assertEqual((rows, summary["results"]), ([], 0))
        self.assertIn("padding", summary["note"])
        self.assertEqual(one(describe("rva:0x1400"))[0]["no_bytes_in_file"], True)
        self.assertEqual(one(describe("offset:0x1200"))[0]["not_loaded"], True)
        self.assertEqual(one(describe("va:0x150000000"))[0], {"outside_the_image": True})

    def test_a_listing_can_start_before_its_address(self):
        disasm = self.inspector.disasm
        # The bytes before the address start at an instruction where unwind data shows one.
        summary, rows = one(disasm("rva:0x1016", before=5, byte_count=7))
        self.assertEqual(
            (summary["range"], addresses(rows)), ("rva:0x100c..rva:0x101d", ["rva:0x100c", "rva:0x1016"])
        )
        self.assertNotIn("note", summary)
        self.assertEqual(
            one(disasm("rva:0x1002", before=0x40, byte_count=5))[0]["range"], "rva:0x1000..rva:0x1007"
        )
        # Without unwind data they are decoded from the byte asked for, which can miss the address.
        summary, rows = one(disasm("rva:0x10a5", before=3, byte_count=1))
        self.assertEqual(addresses(rows), ["rva:0x10a2", "rva:0x10a4"])
        self.assertIn("does not arrive at rva:0x10a5", summary["note"])
        with self.assertRaises(ValueError):
            disasm("rva:0x1016", before=5, function=True)

    def test_a_saved_copy_of_a_loaded_module_answers_as_its_file_does(self):
        mod = 0x7FF800000000
        copy = self.loaded(modules=[("mod.dll", mod, 0x10000)])
        path = copy.source.path
        for ask in (
            lambda inspector: inspector.refs("rva:0x1050"),
            lambda inspector: inspector.rtti("Widget", slots=8),
            lambda inspector: inspector.disasm("rva:0x1000", byte_count=48),
            lambda inspector: inspector.find(text="Name", encoding="both")[0][1],  # a file has more to search
            lambda inspector: inspector.describe("rva:0x1050")[0][1],
        ):
            self.assertEqual(ask(copy), ask(self.inspector))
        # The record after the image is not part of the program: it is not searched, and info shows it.
        self.assertEqual(one(copy.find(text="game.exe"))[0]["results"], 0)
        self.assertEqual(copy.source.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        info = copy.info()
        self.assertEqual((info["sections"][0]["process"], info["sections"][0]["pid"]), ("game.exe", 4242))
        self.assertEqual(
            info["modules"][1],
            [{"address": f"va:{mod:#x}", "name": "mod.dll", "size": "0x10000", "path": "mod.dll"}],
        )
        # An address in another loaded module is named by that module.
        _, rows = one(
            self.loaded(
                "hooked.bin",
                patches={0x2090: struct.pack("<Q", mod + 0x1234)},
                modules=[("mod.dll", mod, 0x10000)],
            ).data("rva:0x2088", value_type="pointer", count=2)
        )
        self.assertEqual(
            rows[1]["points_to"], {"address": f"va:{mod + 0x1234:#x}", "in": "mod.dll rva:0x1234"}
        )

    def test_a_loaded_module_is_read_where_it_is_and_as_the_process_held_it(self):
        # Windows can load a module away from the base its header prefers, and the header keeps the file's layout.
        there = 0x7FF712340000
        copy = self.loaded(base=there)
        self.assertEqual(copy.info()["sections"][0]["image_base"], f"va:{there:#x}")
        self.assertEqual(
            one(copy.data(f"va:{there:#x}", count=2))[1],
            [{"address": "rva:0x0", "bytes": "4d 5a", "ascii": "MZ"}],
        )
        self.assertEqual(
            one(copy.disasm("rva:0x1050", byte_count=6))[1][0]["target"]["import"],
            "KERNEL32.dll!LoadLibraryW",
        )
        # The size and position of .text in the file, as the header in memory still states them.
        _, rows = one(copy.data("rva:0x198", value_type="u32", count=2))
        self.assertEqual([row["value"] for row in rows], [0x400, 0x400])

    def test_an_import_cell_says_what_it_imports_and_where_it_leads(self):
        mod = 0x7FF800000000
        leads = {"address": f"va:{mod + 0x1234:#x}", "in": "mod.dll rva:0x1234"}
        cell = {0x2190: struct.pack("<Q", mod + 0x1234)}
        modules = [("mod.dll", mod, 0x10000)]
        # In a process the cell holds an address, which need not be in the DLL the import names.
        copy = self.loaded(patches=cell, modules=modules)
        named = {"address": "rva:0x2190", "import": "KERNEL32.dll!LoadLibraryW", "points_to": leads}
        self.assertEqual(one(copy.disasm("rva:0x1050", byte_count=6))[1][0]["target"], named)
        self.assertEqual(one(copy.describe("rva:0x2190"))[1], [named])
        self.assertEqual(copy.info()["imports"][1], [{**named, "delayed": False}])
        # A module without a separate table of names loses them to the addresses the loader writes.
        copy = self.loaded("unnamed.bin", patches={0x2100: bytes(4), **cell}, modules=modules)
        summary, rows = copy.info()["imports"]
        self.assertEqual(
            (summary, rows[0]["import"]), ({"results": 1, "names_unavailable": 1}, "KERNEL32.dll")
        )
        self.assertEqual(
            one(copy.describe("rva:0x2190"))[1],
            [
                {
                    "address": "rva:0x2190",
                    "import": "KERNEL32.dll",
                    "name_unavailable": True,
                    "points_to": leads,
                }
            ],
        )

    def test_class_tables_keep_the_slots_a_mod_redirected(self):
        mod = 0x7FF800000000
        there, nowhere = mod + 0x1000, 0x7FF900000000
        patches = {0x2548: struct.pack("<Q", there), 0x2508: struct.pack("<Q", nowhere)}
        modules = [("mod.dll", mod, 0x10000)]
        copy = self.loaded(patches=patches, relocated=[0x2508, 0x2548, 0x2550], modules=modules)
        primary, secondary = copy.rtti("Widget", slots=8)
        self.assertEqual(
            primary[1],
            [
                {"address": f"va:{there:#x}", "in": "mod.dll rva:0x1000", "slot": 0, "cell": "rva:0x2548"},
                {"address": "rva:0x1000", "slot": 1, "cell": "rva:0x2550"},
            ],
        )
        self.assertEqual(secondary[1], [{"address": f"va:{nowhere:#x}", "slot": 0, "cell": "rva:0x2508"}])
        # From the address a mod put there back to the class and slot it took over.
        self.assertEqual(
            one(copy.refs(f"va:{there:#x}", kind="pointer")),
            (
                {"results": 1, "target": {"in": "mod.dll rva:0x1000"}},
                [{"address": "rva:0x2548", "pointer": True, "class": "Widget", "slot": 0}],
            ),
        )
        row = one(copy.describe("rva:0x2548"))[1][0]
        self.assertEqual(
            (row["class"], row["slot"], row["points_to"]),
            ("Widget", 0, {"address": f"va:{there:#x}", "in": "mod.dll rva:0x1000"}),
        )
        # Only relocation data says that a cell with an address outside the image holds an address.
        bare = self.loaded("bare.bin", patches=patches, modules=modules)
        self.assertEqual(bare.rtti("Widget"), [({"tables": 0}, [])])

    def test_bytes_that_a_process_did_not_let_be_read_are_not_read_as_zeros(self):
        copy = self.loaded(unreadable=[(0x2000, 0x3000, "no access")])
        source = copy.source
        with self.assertRaisesRegex(ValueError, "Cannot read rva:0x2040 from the process: no access"):
            source.read(BASE + 0x2040, 1)
        self.assertEqual(one(copy.find(text="AnchorName"))[0], {"results": 0, "scanned_bytes": 0x3000})
        self.assertEqual(one(copy.describe("rva:0x2040"))[0]["unreadable"], True)
        with self.assertRaisesRegex(ValueError, "no file offsets"):  # no other way to the same bytes
            copy.data("offset:0x2040", count=1)
        self.assertEqual(
            one(copy.disasm("rva:0x1000", byte_count=7))[1][0]["target"],
            {"address": "rva:0x2040", "unreadable": True},
        )
        self.assertEqual(
            copy.info()["unreadable"][1],
            [{"address": "rva:0x2000", "size": "0x1000", "unreadable": "no access"}],
        )
        # The section held the import and export tables, so every command's results can lack names.
        self.assertEqual(source.damaged, ["exports", "imports"])
        self.assertRegex(
            source.unread, r"0x1000 bytes could not be read .* holds exports, imports \(info lists"
        )
        code = self.loaded("code.bin", unreadable=[(0x1000, 0x2000, "no access")]).source
        self.assertEqual((code.damaged, code.spans(executable=True)), ([], []))
        # Without its unwind data a module has no function bounds; its code and its ranges are still read.
        bare = self.loaded("bare.bin", unreadable=[(0x3000, 0x4000, "no access")])
        self.assertEqual((bare.source.damaged, bare.source.entries), (["unwind data"], []))
        summary, rows = one(bare.disasm("rva:0x1002", byte_count=5))
        self.assertEqual((summary["range"], addresses(rows)), ("rva:0x1002..rva:0x1007", ["rva:0x1002"]))
        self.assertEqual(bare.info()["unreadable"][1][0]["address"], "rva:0x3000")

    def test_unreadable_bytes_in_a_function_hide_only_what_needs_them(self):
        # The function at 0x1000 with four bytes missing from the middle of its third instruction.
        holed = self.loaded("holed.bin", unreadable=[(0x1010, 0x1014, "no access")])
        summary, rows = one(holed.disasm("rva:0x1007", byte_count=5))
        self.assertEqual((addresses(rows), summary["function"]), (["rva:0x1007"], "rva:0x1000"))
        # A search still confirms the instructions before those bytes, and marks the ones after them.
        _, rows = one(holed.refs("rva:0x2040", kind="memory"))
        self.assertEqual(
            [(row["address"], row.get("unverified")) for row in rows][:2],
            [("rva:0x1000", None), ("rva:0x1016", "after unreadable bytes")],
        )
        self.assertEqual(one(holed.describe("rva:0x1007"))[1][0]["address"], "rva:0x1000")
        # A listing gives what precedes them and says where it stopped; the function's other piece follows.
        summary, rows = one(holed.disasm("rva:0x1000", function=True))
        self.assertEqual(addresses(rows)[:4], ["rva:0x1000", "rva:0x1007", "rva:0x1080", "rva:0x1085"])
        self.assertEqual((summary["unreadable_at"], "undecodable_at" in summary), (["rva:0x1010"], False))
        summary, rows = one(holed.disasm("rva:0x1000", byte_count=0x20))
        self.assertEqual(
            (addresses(rows), summary["unreadable_at"]), (["rva:0x1000", "rva:0x1007"], ["rva:0x1010"])
        )
        summary, rows = one(holed.disasm("rva:0x1000"))  # without a size it would have gone on
        self.assertEqual(
            (summary["range"], summary["unreadable_at"]), ("rva:0x1000..rva:0x1010", ["rva:0x1010"])
        )
        with self.assertRaisesRegex(ValueError, "only 9 precede rva:0x1010, which could not be read"):
            holed.data("rva:0x1007", count=16)

    def test_a_saved_copy_says_when_a_jump_goes_through_a_cell_it_does_not_hold(self):
        # A mod's call through a cell in memory of its own, which is not part of the module that was saved.
        cell = BASE + 0x10000
        copy = self.loaded(patches={0x1050: rip(0x1050, b"\xff\x15", 0x10000)})
        self.assertEqual(
            one(copy.disasm("rva:0x1050", byte_count=6))[1][0]["target"],
            {"address": f"va:{cell:#x}", "not_saved": True},
        )

    def test_code_that_looks_encrypted_is_reported(self):
        self.assertIsNone(self.source.packed)
        noise = random.Random(7).randbytes(0x400)
        packed = PE(fixture(self.root / "packed.dll", {0x1000: noise}))
        self.assertRegex(packed.packed, r"code in \.text looks encrypted or compressed \(entropy 7\.\d\d\)")

    def test_invalid_pe_architecture_and_layout_are_rejected(self):
        for mutate in (
            lambda raw: struct.pack_into("<H", raw, 0x84, 0x14C),
            lambda raw: struct.pack_into("<I", raw, 0x188 + 40 + 20, 0x400),
        ):
            raw = bytearray(self.path.read_bytes())
            mutate(raw)
            path = self.root / "invalid.dll"
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                PE(path)


if __name__ == "__main__":
    unittest.main()
