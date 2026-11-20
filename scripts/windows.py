"""Read-only access to a running Windows process: its modules, its memory map, and its bytes."""

import bisect
import ctypes
import sys
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise OSError("Reading a process requires 64-bit Python on Windows")

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8
PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400
ERROR_NO_MORE_FILES = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
COMMITTED, GUARD = 0x1000, 0x100
READABLE = {0x02: "read", 0x04: "read write", 0x08: "read write", 0x20: "read execute"}
READABLE |= {0x40: "read write execute", 0x80: "read write execute"}
KINDS = {0x20000: "private", 0x40000: "mapped", 0x1000000: "image"}


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class ModuleEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


class MemoryRegion(ctypes.Structure):
    """Consecutive pages with one state and protection, as VirtualQueryEx reports them."""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

    @property
    def begin(self):
        return self.BaseAddress or 0

    @property
    def end(self):
        return self.begin + self.RegionSize

    @property
    def access(self):
        """`read write execute` in the words that apply, or None for pages that cannot be read.

        Guard pages count as unreadable: reading one changes the process.
        """
        if self.State != COMMITTED or self.Protect & GUARD:
            return None
        return READABLE.get(self.Protect & 0xFF)

    @property
    def kind(self):
        return KINDS.get(self.Type, "unknown")

    @property
    def state(self):
        if self.State != COMMITTED:
            return "not committed"
        return "a guard page" if self.Protect & GUARD else "no access"


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MemoryRegion),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
kernel32.GetProcessTimes.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL
for name, entry_type in (("Process32", ProcessEntry), ("Module32", ModuleEntry)):
    for step in ("FirstW", "NextW"):
        function = getattr(kernel32, name + step)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(entry_type)]
        function.restype = wintypes.BOOL


def check(result, operation):
    if not result:
        error = ctypes.get_last_error()
        message = f"{operation}: {ctypes.FormatError(error).strip()}"
        if error == 5:
            message += " Reading this process may need an elevated terminal."
        raise ctypes.WinError(error, message)


@contextmanager
def toolhelp(flags, pid):
    handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
    check(handle != INVALID_HANDLE_VALUE, f"CreateToolhelp32Snapshot(pid={pid})")
    try:
        yield handle
    finally:
        kernel32.CloseHandle(handle)


def listed(handle, entry, name, what):
    entry.dwSize = ctypes.sizeof(entry)
    found = getattr(kernel32, name + "FirstW")(handle, ctypes.byref(entry))
    while found:
        yield entry
        found = getattr(kernel32, name + "NextW")(handle, ctypes.byref(entry))
    if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
        check(found, f"List {what}")


def find_pid(name):
    with toolhelp(TH32CS_SNAPPROCESS, 0) as handle:
        matches = [
            int(entry.th32ProcessID)
            for entry in listed(handle, ProcessEntry(), "Process32", "processes")
            if entry.szExeFile.casefold() == name.casefold()
        ]
    if not matches:
        raise ValueError(f"No running process is named {name}")
    if len(matches) != 1:
        raise ValueError(
            f"{len(matches)} processes are named {name}; give --process one of the PIDs {matches}"
        )
    return matches[0]


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    base: int
    size: int


class Process:
    """One running process, opened for reading. `selector` is its executable's name or its PID."""

    def __init__(self, selector):
        self.pid = int(selector) if selector.isdecimal() else find_pid(selector)
        self.handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
        if not self.handle and ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER
            raise ValueError(f"No running process has the PID {self.pid}")
        check(self.handle, f"OpenProcess(pid={self.pid})")
        try:
            narrow = wintypes.BOOL()
            check(kernel32.IsWow64Process(self.handle, ctypes.byref(narrow)), "IsWow64Process")
            if narrow.value:
                raise ValueError(f"PID {self.pid} is a 32-bit process; only AMD64 processes can be read")
            buffer = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(buffer))
            check(
                kernel32.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)),
                f"QueryFullProcessImageNameW(pid={self.pid})",
            )
            self.path = buffer.value
            self.name = Path(self.path).name
            times = [wintypes.FILETIME() for _ in range(4)]
            check(kernel32.GetProcessTimes(self.handle, *map(ctypes.byref, times)), "GetProcessTimes")
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            started = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
            self.started = started.astimezone().isoformat(timespec="seconds")
            with toolhelp(TH32CS_SNAPMODULE, self.pid) as handle:
                modules = [
                    Module(entry.szModule, entry.szExePath, entry.modBaseAddr or 0, int(entry.modBaseSize))
                    for entry in listed(handle, ModuleEntry(), "Module32", f"modules of PID {self.pid}")
                ]
        except BaseException:
            self.close()
            raise
        self.modules = sorted(modules, key=lambda module: module.base)
        self._bases = [module.base for module in self.modules]

    def close(self):
        kernel32.CloseHandle(self.handle)

    def module(self, name):
        matches = [module for module in self.modules if module.name.casefold() == name.casefold()]
        if len(matches) != 1:
            state = "is not loaded" if not matches else "is loaded more than once"
            raise ValueError(f"Module {name} {state} in {self.name} (PID {self.pid}); info lists the modules")
        return matches[0]

    def module_at(self, va):
        index = bisect.bisect_right(self._bases, va) - 1
        if index >= 0 and va < self.modules[index].base + self.modules[index].size:
            return self.modules[index]
        return None

    def query(self, va):
        """The memory region at an address, or None where the process has no address space."""
        region = MemoryRegion()
        count = kernel32.VirtualQueryEx(self.handle, va, ctypes.byref(region), ctypes.sizeof(region))
        return region if count == ctypes.sizeof(region) and region.begin <= va < region.end else None

    def read_into(self, target, offset, va, size):
        """Read bytes of the process into a bytearray, without a copy in between."""
        buffer = (ctypes.c_char * size).from_buffer(target, offset)
        count = ctypes.c_size_t()
        done = kernel32.ReadProcessMemory(self.handle, va, buffer, size, ctypes.byref(count))
        check(done, f"ReadProcessMemory(pid={self.pid}, address={va:#x}, size={size})")
        if count.value != size:
            raise OSError(f"Short read at {va:#x}: wanted {size} bytes, got {count.value}")

    def read(self, va, size):
        data = bytearray(size)
        self.read_into(data, 0, va, size)
        return bytes(data)
