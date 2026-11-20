import contextlib
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.__main__ import main

DLL = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
# A process with what mods leave in a game: jumps in memory of its own that lead into a module, directly and
# through cells in other memory, and a page nobody may read in a module that nothing else uses.
CHILD = r"""
import ctypes, json, os, sys
kernel32 = ctypes.WinDLL("kernel32")
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
export = ctypes.cast(ctypes.pythonapi.PySet_Add, ctypes.c_void_p).value
page = kernel32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)
ctypes.memmove(page, b"\xff\x25\x00\x00\x00\x00" + export.to_bytes(8, "little"), 14)
def near(base, protection):
    for step in range(1, 0x4000):
        at = kernel32.VirtualAlloc(base - step * 0x10000, 0x1000, 0x3000, protection)
        if at:
            return at
    raise SystemExit("no free page within reach of a jump")
def through(at, cell):
    ctypes.memmove(at, b"\xff\x25" + (cell - at - 6).to_bytes(4, "little", signed=True), 6)
data = near(page, 0x04)
gone = near(data, 0x01)
through(page + 0x20, data + 0x108)
through(page + 0x30, gone + 0x10)
ctypes.memmove(data + 0x100, (data + 0x200).to_bytes(8, "little") + export.to_bytes(8, "little"), 16)
ctypes.memmove(data + 0x200, b"HeapAnchorText\0", 15)
unused = ctypes.WinDLL("dbghelp")._handle
kernel32.VirtualProtect(unused + 0x1000, 0x1000, 1, ctypes.byref(ctypes.c_uint32()))
state = {"pid": os.getpid(), "page": page, "data": data, "export": export, "python": ctypes.pythonapi._handle}
state["gone"] = gone
state["stable"] = ctypes.WinDLL("python3")._handle
state["headers"] = ctypes.string_at(state["python"], 0x400).hex(" ")
print(json.dumps(state), flush=True)
sys.stdin.read()
"""


@unittest.skipUnless(sys.platform == "win32", "reads a Windows process")
class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.child = subprocess.Popen(
            [sys.executable, "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        cls.addClassCleanup(cls.child.wait, 10)
        cls.addClassCleanup(cls.child.stdin.close)
        cls.addClassCleanup(cls.child.stdout.close)
        state = json.loads(cls.child.stdout.readline())
        cls.pid, cls.page, cls.data, cls.export = (
            str(state["pid"]),
            state["page"],
            state["data"],
            state["export"],
        )
        cls.rva = state["export"] - state["python"]
        cls.stable, cls.headers, cls.gone = state["stable"], state["headers"], state["gone"]
        temporary = tempfile.TemporaryDirectory(prefix="byte-inspector-test-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)

    def run_cli(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
            mock.patch("sys.stdin", io.StringIO("")),
        ):
            try:
                code = main([str(argument) for argument in arguments])
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue().splitlines(), err.getvalue()

    def in_python(self, *arguments):
        return self.run_cli(*arguments, "--process", self.pid, "--module", DLL)

    def test_a_module_answers_the_same_in_the_process_in_its_saved_copy_and_in_its_file(self):
        copy = self.root / "python.bin"
        code, lines, err = self.in_python("snapshot", "--output", copy)
        self.assertEqual((code, err), (0, ""))
        self.assertRegex(
            lines[0], rf"^# process python\S*  pid {self.pid}  module {DLL}  base va:0x\w+  read \S+$"
        )
        self.assertRegex(
            lines[1], rf"^# snapshot {DLL}  saved \S+python\.bin  size 0x\w+  sha256 \w{{64}}  modules \d+$"
        )
        file = Path(sys.base_prefix) / DLL
        at = f"rva:{self.rva:#x}"
        for command in (
            ["describe", at],
            ["refs", at, "--limit", "5"],
            ["disasm", at, "--bytes", "24"],
            ["find", "--text", "PySet_Add"],
            ["rtti", "type_info"],
        ):
            with self.subTest(command=command):
                code, live, err = self.in_python(*command)
                self.assertEqual((code, err), (0, ""))
                self.assertTrue(live[0].startswith(lines[0].partition("  read ")[0]))
                self.assertEqual(self.run_cli(*command, "--file", copy)[1], live[1:])
                if command[0] in ("refs", "disasm"):  # a describe summary also places the address in the file
                    self.assertEqual(self.run_cli(*command, "--file", file)[1], live[1:])
        self.assertIn(f"{at}  export PySet_Add", "\n".join(self.in_python("describe", at)[1]))
        # A saved copy is evidence: a second one does not replace it.
        code, lines, err = self.in_python("snapshot", "--output", copy)
        refused = f"error: {copy} exists; a saved copy is never overwritten"
        self.assertEqual((code, lines[-1], err.strip()), (1, refused, refused))

    def test_an_address_is_read_wherever_it_is(self):
        page, data, there = self.page, self.data, f"rva:{self.rva:#x} export PySet_Add function start"
        # Memory that belongs to no module: the jump is followed through its cell to where it leads,
        # and an address in that memory says so, as it does when a module refers to it.
        code, lines, _ = self.in_python("disasm", f"va:{page:#x}", "--bytes", "6")
        self.assertEqual(
            (code, lines[1:]),
            (
                0,
                [
                    f"# disasm va:{page:#x}  range va:{page:#x}..va:{page + 6:#x}  instructions 1",
                    f"va:{page:#x}  jmp qword ptr [rip]  target va:{page + 6:#x} in private memory points to {there}",
                ],
            ),
        )
        # A listing that goes on past the jump shows the cell as the address it is, not as instructions.
        code, lines, _ = self.in_python("disasm", f"va:{page:#x}", "--bytes", "14")
        self.assertEqual(
            (lines[1].rpartition("  instructions ")[2], lines[3]),
            ("1  pointers 1", f"va:{page + 6:#x}  pointer  points to {there}"),
        )
        # So is a jump through a cell in other memory; a cell nobody may read says that it is one.
        code, lines, _ = self.in_python(
            "disasm", f"va:{page + 0x20:#x}", f"va:{page + 0x30:#x}", "--bytes", "6"
        )
        self.assertEqual(
            [line.partition("  target ")[2] for line in lines if line.startswith("va:")],
            [
                f"va:{data + 0x108:#x} in private memory points to {there}",
                f"va:{self.gone + 0x10:#x} unreadable",
            ],
        )
        code, lines, _ = self.in_python("data", f"va:{data + 0x100:#x}", "--type", "pointer", "--count", "2")
        self.assertEqual(
            lines[2:],
            [
                f'va:{data + 0x100:#x}  points to va:{data + 0x200:#x} in private memory string "HeapAnchorText"',
                f"va:{data + 0x108:#x}  points to {there}",
            ],
        )
        code, lines, _ = self.in_python("describe", f"va:{data + 0x200:#x}")
        self.assertEqual(
            lines[1:],
            [
                f"# describe va:{data + 0x200:#x}  in private memory  region va:{data:#x}..va:{data + 0x1000:#x}  "
                "access read write  results 1",
                f'va:{data + 0x200:#x}  string "HeapAnchorText"  encoding ascii',
            ],
        )
        # An address in a module other than the one commands work on: that module answers, in absolute addresses.
        code, lines, _ = self.run_cli("describe", f"va:{self.export:#x}", "--process", self.pid)
        self.assertEqual(code, 0)
        self.assertIn(
            f"# describe va:{self.export:#x}  in {DLL} rva:{self.rva:#x}  section .text  results", lines[1]
        )
        self.assertEqual(lines[3].split("  ")[:2], [f"va:{self.export:#x}", "export PySet_Add"])
        # Addresses that cannot be read, or that a process does not have, fail in place.
        code, lines, _ = self.in_python("data", "va:0x1000", f"va:{page:#x}", "offset:0x400", "--count", "2")
        self.assertEqual(code, 1)
        self.assertRegex(lines[1], r"^error: va:0x1000: va:0x1000 cannot be read in the process: ")
        self.assertEqual(lines[3], f'va:{page:#x}  ff 25  ascii "' + '.%"')
        self.assertEqual(
            lines[4], "error: offset:0x400: Bytes read from a process have no file offsets; use rva: or va:"
        )

    def test_a_module_is_read_at_its_address_as_the_process_holds_it(self):
        # python3.dll gets an address of its own choosing; its header can go on naming the one it prefers.
        module = ("--process", self.pid, "--module", "python3.dll")
        code, lines, _ = self.run_cli("data", f"va:{self.stable:#x}", "--count", "2", *module)
        self.assertEqual((code, lines[2]), (0, 'rva:0x0  4d 5a  ascii "MZ"'))
        self.assertIn(f"  module python3.dll  base va:{self.stable:#x}  read ", lines[0])
        # The header says how the file is laid out. Those bytes are read as they are, not as a layout in memory.
        code, lines, _ = self.in_python("data", "rva:0", "--count", "1024")
        self.assertEqual(" ".join(line.split("  ")[1] for line in lines[2:]), self.headers)

    def test_what_a_process_does_not_let_be_read_is_said_and_kept(self):
        module = ("--process", self.pid, "--module", "dbghelp.dll")
        hole = "rva:0x1000  size 0x1000  unreadable no access"
        code, lines, _ = self.run_cli("info", *module, "--limit", "1")
        self.assertEqual((code, lines[-1]), (0, hole))
        code, lines, _ = self.run_cli("data", "rva:0x1000", "rva:0x2000", "--count", "1", *module)
        self.assertEqual(code, 1)
        self.assertEqual(lines[1], "error: rva:0x1000: Cannot read rva:0x1000 from the process: no access")
        self.assertEqual(lines[2], "# data rva:0x2000  type u8  count 1")
        # A search of the module would only come back with less, so its summary says what is missing.
        code, lines, _ = self.run_cli("find", "--text", "dbghelp", *module)
        self.assertIn(
            "warning 0x1000 bytes could not be read from the process (info lists the ranges)", lines[1]
        )
        copy = self.root / "dbghelp.bin"
        code, records, _ = self.run_cli("snapshot", "--output", copy, "--jsonl", *module)
        saved = json.loads(records[-1])
        self.assertEqual((code, saved["sha256"]), (0, hashlib.sha256(copy.read_bytes()).hexdigest()))
        self.assertEqual(self.run_cli("info", "--file", copy, "--limit", "1")[1][-1], hole)
        # The copy keeps what was unreadable, by whatever address the bytes are asked for.
        for address in ("rva:0x1000", "offset:0x1000"):
            code, lines, _ = self.run_cli("data", address, "--count", "4", "--file", copy)
            self.assertEqual((code, len(lines), lines[0][:6]), (1, 1, "error:"))

    def test_a_process_or_module_that_is_not_there_fails_the_call(self):
        for arguments, message in (
            (("--process", "no-such-process.exe"), "error: No running process is named no-such-process.exe"),
            (("--process", self.pid, "--module", "absent.dll"), "is not loaded in python"),
            (("--file", sys.executable, "--module", DLL), "--module names a module of a running process"),
        ):
            with self.subTest(arguments=arguments):
                code, lines, err = self.run_cli("info", *arguments)
                self.assertEqual((code, lines, [err.strip()]), (1, lines[:1], lines[:1]))
                self.assertIn(message, lines[0])


if __name__ == "__main__":
    unittest.main()
