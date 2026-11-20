import contextlib
import io
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import fixture

from scripts.__main__ import main
from scripts.output import line
from scripts.sources import coordinate

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = [
    ["info"],
    ["find", "--text", "Anchor", "--text", "WideName", "--encoding", "both"],
    ["find", "--pattern", "48 8D ?? ?? ?? ?? ??"],
    ["refs", "rva:0x1050", "rva:0x2040"],
    ["refs", "--displacement", "0x3F4"],
    ["disasm", "rva:0x1028", "--function"],
    ["disasm", "rva:0x1000", "--bytes", "32", "--show-bytes"],
    ["data", "rva:0x2080", "--type", "pointer", "--count", "3"],
    ["data", "offset:0x1200", "--count", "14"],
    ["rtti", "Widget", "--slots", "4"],
    ["describe", "rva:0x1050", "rva:0x10a2", "rva:0x2550", "rva:0x2040"],
]


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="byte-inspector-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = fixture(self.root / "fixture.dll")

    def run_cli(self, *arguments, stdin="", path=None):
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
            mock.patch("sys.stdin", io.StringIO(stdin)),
        ):
            try:
                code = main([*arguments, "--file", str(path or self.path)])
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue().splitlines(), err.getvalue()

    def test_every_result_line_leads_with_an_address_the_tool_accepts(self):
        printed = []
        for command in COMMANDS:
            code, lines, err = self.run_cli(*command)
            with self.subTest(command=command):
                self.assertEqual((code, err), (0, ""))
                self.assertTrue(lines[0].startswith(f"# {command[0]} "))
                for text in lines:
                    if not text.startswith("#"):
                        coordinate(text.split()[0])
                        self.assertIn("  ", text)
                printed += lines
        # Every line the tool printed is valid input: addresses are answered, summaries pass through.
        code, lines, err = self.run_cli("describe", "-", stdin="\n".join(printed))
        self.assertEqual((code, err), (0, ""))
        self.assertFalse([text for text in lines if text.startswith("error:")])
        passed = [text for text in printed if text.startswith("#") and not text.startswith("# describe")]
        self.assertEqual(
            [text for text in lines if text.startswith("#") and not text.startswith("# describe")], passed
        )

    def test_jsonl_states_the_same_facts_as_the_lines(self):
        for command in COMMANDS:
            _, lines, _ = self.run_cli(*command)
            code, records, err = self.run_cli(*command, "--jsonl")
            with self.subTest(command=command):
                self.assertEqual((code, err), (0, ""))
                records = [json.loads(text) for text in records]
                for record in records:
                    if record["record"] == "summary":
                        self.assertEqual(record["file"], str(self.path.resolve()))
                        self.assertEqual(len(record["sha256"]), 64)
                        if command[0] != "info" or record["query"] != "sections":
                            del record["file"], record["sha256"]
                self.assertEqual([line(record) for record in records], lines)

    def test_each_address_is_answered_alone_with_its_own_limit(self):
        code, lines, _ = self.run_cli("refs", "rva:0x1050", "rva:0x2040", "--limit", "2")
        self.assertEqual(code, 0)
        self.assertEqual(
            [text.split("  ")[:3] for text in lines if text.startswith("#")],
            [
                ["# refs rva:0x1050", "results 6", "showing 2"],
                ["# refs rva:0x2040", "results 4", "showing 2"],
            ],
        )
        self.assertEqual([text.startswith("#") for text in lines], [True, False, False, True, False, False])

    def test_a_failed_address_is_reported_in_place_and_the_rest_are_answered(self):
        code, lines, err = self.run_cli(
            "data", "rva:0x2040", "rva:0x1400", "bogus", "rva:0x2060", "--count", "4"
        )
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(
            [text.split("  ")[0] for text in lines],
            [
                "# data rva:0x2040",
                "rva:0x2040",
                "error: rva:0x1400: No bytes in the file at rva:0x1400",
                "error: bogus: Not an address: bogus (use rva:0x1000, va:0x140001000, or offset:0x400)",
                "# data rva:0x2060",
                "rva:0x2060",
            ],
        )
        code, records, _ = self.run_cli("data", "rva:0x1400", "--jsonl")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(records[0])["record"], "error")
        # A file offset that is loaded is read as its address: both of these run past the end of .text.
        code, lines, _ = self.run_cli("data", "offset:0x7ff", "rva:0x13ff", "--count", "2")
        self.assertEqual((code, [text.split(": ")[0] for text in lines]), (1, ["error", "error"]))

    def test_a_listing_is_printed_once_per_call(self):
        code, lines, _ = self.run_cli(
            "disasm", "rva:0x1016", "rva:0x1085", "rva:0x1050", "rva:0x1000", "--function"
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            [text for text in lines if text.startswith("#")],
            [
                "# disasm rva:0x1016  function rva:0x1000  pieces rva:0x1000..rva:0x1030 rva:0x1080..rva:0x1090"
                "  instructions 22",
                "# disasm rva:0x1085  function rva:0x1000  listed under rva:0x1016",
                "# disasm rva:0x1050  function rva:0x1050  export Exported  pieces rva:0x1050..rva:0x1060"
                "  instructions 11",
                "# disasm rva:0x1000  function rva:0x1000  listed under rva:0x1016",
            ],
        )
        self.assertEqual(sum(text.startswith("rva:0x1000  ") for text in lines), 1)
        _, records, _ = self.run_cli("disasm", "rva:0x1016", "rva:0x1085", "--function", "--jsonl")
        self.assertEqual(json.loads(records[-1])["listed_under"], "rva:0x1016")

    def test_commands_connect_through_text_lines(self):
        _, callers, _ = self.run_cli("refs", "rva:0x2040", "--kind", "memory")
        code, lines, err = self.run_cli("disasm", "-", "--function", "--limit", "1", stdin="\n".join(callers))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            lines,
            [
                callers[0],  # the earlier summary stays, so the history of the answer is visible
                "# disasm rva:0x1000  function rva:0x1000  pieces rva:0x1000..rva:0x1030 rva:0x1080..rva:0x1090"
                "  instructions 22  showing 1",
                'rva:0x1000  lea rcx, [rip + 0x1039]  target rva:0x2040 string "AnchorName"',
                "# disasm rva:0x1016  function rva:0x1000  listed under rva:0x1000",
                "# disasm rva:0x1026  function rva:0x1000  listed under rva:0x1000",
            ],
        )
        # Slot rows lead with functions; an address mixed with arguments keeps its place.
        _, slots, _ = self.run_cli("rtti", "Widget", "--limit", "1")
        _, lines, _ = self.run_cli("describe", "rva:0x2040", "-", stdin="\n".join(slots))
        self.assertEqual(
            [text.split("  ")[0] for text in lines if text.startswith("#")],
            ["# describe rva:0x2040", "# rtti Widget", "# describe rva:0x1050", "# describe rva:0x1000"],
        )

    def test_a_record_is_one_line_whatever_the_query_holds(self):
        path = fixture(self.root / "lines.dll", {0x2640: b"First\r\nSecond\0"})
        code, found, _ = self.run_cli("find", "--text", "First\r\nSecond", path=path)
        self.assertEqual(
            found,
            [
                "# find First\\r\\nSecond  results 1  scanned bytes 4622",
                'rva:0x2640  string "First\\r\\nSecond"  match +0',
            ],
        )
        code, lines, err = self.run_cli("refs", "-", stdin="\n".join(found), path=path)
        self.assertEqual((code, err, lines[0]), (0, "", found[0]))
        code, lines, _ = self.run_cli("data", "rva:0x1\nrva:0x2")
        self.assertEqual((code, len(lines)), (1, 1))

    def test_input_lines_that_are_not_addresses(self):
        stdin = "# a note\n\nrva:0x2040  text\nerror: rva:0x1: failed earlier\nsomething else\nrva:0x2060\n"
        code, lines, err = self.run_cli("data", "-", "--count", "2", stdin=stdin)
        self.assertEqual(
            (code, err), (1, "")
        )  # an error passed on, or a line that cannot be read, fails the call
        self.assertEqual(
            lines,
            [
                "# a note",
                "# data rva:0x2040  type u8  count 2",
                'rva:0x2040  41 6e  ascii "An"',
                "error: rva:0x1: failed earlier",
                "error: Not an address line: something else",
                "# data rva:0x2060  type u8  count 2",
                'rva:0x2060  57 00  ascii "W."',
            ],
        )
        code, lines, err = self.run_cli("data", "-", stdin='{"record": "summary"}\nrva:0x2040\n')
        self.assertEqual(code, 1)
        self.assertEqual(lines, ["error: Standard input is JSONL; pipe the default text lines instead"])
        self.assertEqual(err.strip(), lines[0])

    def test_a_failed_call_says_so_on_both_streams(self):
        for arguments, path, expected in (
            (["info"], self.root / "missing.dll", 1),
            (["disasm", "rva:0x1000", "--limit", "0"], None, 1),
            (["refs", "rva:0x1000", "--displacement", "8"], None, 1),
            (["disasm"], None, 2),
            (["find"], None, 2),
        ):
            code, lines, err = self.run_cli(*arguments, path=path)
            with self.subTest(arguments=arguments):
                self.assertEqual(code, expected)
                self.assertEqual(len(lines), 1)
                self.assertTrue(lines[0].startswith("error: "))
                self.assertEqual(err.strip(), lines[0])
                self.assertNotIn("Traceback", err)

    def test_every_summary_warns_when_code_looks_encrypted(self):
        packed = fixture(self.root / "packed.dll", {0x1000: random.Random(7).randbytes(0x400)})
        for command in (
            ["refs", "rva:0x2040"],
            ["data", "rva:0x2040"],
            ["info"],
            ["find", "--text", "Anchor"],
        ):
            _, lines, _ = self.run_cli(*command, path=packed)
            _, records, _ = self.run_cli(*command, "--jsonl", path=packed)
            _, clean, _ = self.run_cli(*command)
            with self.subTest(command=command):
                summaries = [text for text in lines if text.startswith("#")]
                self.assertTrue(summaries)
                for text in summaries:
                    self.assertRegex(
                        text, r"  warning code in \.text looks encrypted or compressed \(entropy 7\.\d\d\); "
                    )
                self.assertTrue(all("warning" in json.loads(text) for text in records if '"summary"' in text))
                self.assertFalse([text for text in clean if "warning" in text])

    def test_the_tool_runs_as_a_module_and_does_not_change_the_file(self):
        before = self.path.read_bytes()
        refs = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "scripts",
                "refs",
                "rva:0x2040",
                "--kind",
                "memory",
                "--file",
                self.path,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual((refs.returncode, refs.stderr), (0, ""))
        listing = subprocess.run(
            [sys.executable, "-B", "-m", "scripts", "disasm", "-", "--function", "--file", self.path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            input=refs.stdout,
        )
        self.assertEqual((listing.returncode, listing.stderr), (0, ""))
        self.assertEqual(listing.stdout.count("listed under rva:0x1000"), 2)
        failed = subprocess.run(
            [sys.executable, "-B", "-m", "scripts", "disasm", "rva:0x1400", "--file", self.path],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(failed.stdout.strip(), "error: rva:0x1400: No bytes in the file at rva:0x1400")
        self.assertNotIn("Traceback", failed.stderr)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
