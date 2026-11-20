"""A running process as sources: the module that commands work on, and wherever else an address leads."""

import hashlib
import struct
from datetime import datetime

lazy import pefile

from .analysis import Inspector
from .sources import PE, Memory, copy_end
lazy from .windows import Process

WINDOW = 1 << 20  # bytes read on each side of an address that is outside every module
CHUNK = 1 << 24
PAGE = 0x1000


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def capture(process, module):
    """(image, record) of a loaded module as it is now.

    A range that cannot be read is recorded with the reason and never filled in.
    """
    base = module.base
    image = bytearray(module.size)
    unreadable = []

    def lost(begin, end, reason):
        if unreadable and unreadable[-1][1] == begin - base and unreadable[-1][2] == reason:
            unreadable[-1][1] = end - base
        else:
            unreadable.append([begin - base, end - base, reason])

    cursor, end = base, base + module.size
    while cursor < end:
        region = process.query(cursor)
        stop = min(region.end, end) if region else end
        if region is None or not region.access:
            lost(cursor, stop, region.state if region else "no memory there")
            cursor = stop
            continue
        for begin in range(cursor, stop, CHUNK):
            size = min(CHUNK, stop - begin)
            try:
                process.read_into(image, begin - base, begin, size)
            except OSError:  # page by page, so that only the pages that fail are lost
                for page in range(begin, begin + size, PAGE):
                    try:
                        process.read_into(image, page - base, page, min(PAGE, begin + size - page))
                    except OSError:
                        lost(page, min(page + PAGE, begin + size), "the read failed")
        cursor = stop
    if unreadable and unreadable[0][0] == 0:
        raise ValueError(f"The headers of {module.name} cannot be read: {unreadable[0][2]}")
    record = {
        "process": {
            "name": process.name,
            "path": process.path,
            "pid": process.pid,
            "started": process.started,
        },
        "module": {"name": module.name, "path": module.path, "base": base},
        "read": now(),
        "modules": [
            {"name": other.name, "path": other.path, "base": other.base, "size": other.size}
            for other in process.modules
        ],
        "unreadable": unreadable,
    }
    return bytes(image), record


class Live:
    """A running process. Searches cover one module; an address can also be read anywhere else."""

    def __init__(self, selector, module=None):
        self.process = process = Process(selector)
        try:
            self._modules = {}
            self.home = None
            self.home = self._module(process.module(module or process.name))
        except BaseException:
            process.close()
            raise

    def close(self):
        self.process.close()

    @property
    def note(self):
        """What the results were read from, as a line that travels with them."""
        source, process = self.home.source, self.process
        return (
            f"# process {process.name}  pid {process.pid}  module {source.name}  "
            f"base va:{source.base:#x}  read {source.record['read']}"
        )

    def _module(self, module):
        if module.base not in self._modules:
            try:
                image, record = capture(self.process, module)
                source = PE.loaded(image, record, self.home and self.home.source)
            except (pefile.PEFormatError, struct.error) as exc:
                raise ValueError(f"{module.name} does not read as a PE image: {exc}") from None
            self._modules[module.base] = Inspector(source, self.where, self.pointer)
        return self._modules[module.base]

    def _memory(self, va):
        process = self.process
        region = process.query(va)
        if region is None or not region.access:
            reason = region.state if region else "no memory there"
            raise ValueError(f"va:{va:#x} cannot be read in the process: {reason}")
        low, high = max(region.begin, va - WINDOW), min(region.end, va + WINDOW)
        try:
            data = process.read(low, high - low)
        except OSError as exc:
            raise ValueError(f"va:{va:#x} cannot be read in the process: {exc}") from None
        name = f"{region.kind} memory"
        source = Memory(
            data,
            low,
            name=name,
            executable="execute" in region.access,
            writable="write" in region.access,
            home=self.home.source,
            identity={
                "process": process.name,
                "pid": process.pid,
                "memory": f"va:{low:#x}..va:{high:#x}",
                "read": now(),
            },
            place={
                "in": name,
                "region": f"va:{region.begin:#x}..va:{region.end:#x}",
                "access": region.access,
            },
        )
        return Inspector(source, self.where, self.pointer)

    def inspector(self, address):
        """(inspector, address) for the bytes an address is in: the module, another module, or other memory."""
        home = self.home.source
        va = home.va(address)
        if home.holds(va):
            return self.home, address
        module = self.process.module_at(va)
        return (self._module(module) if module else self._memory(va)), f"va:{va:#x}"

    def where(self, va):
        """What an address outside the bytes being read is: something in the module, or where else it lies."""
        if self.home.source.holds(va):
            return self.home.facts(va)
        module = self.process.module_at(va)
        if module is not None:
            return {"in": f"{module.name} rva:{va - module.base:#x}"}
        region = self.process.query(va)
        return {"in": f"{region.kind} memory"} if region is not None and region.access else {}

    def pointer(self, va):
        """The address that a cell anywhere in the process holds now."""
        try:
            return struct.unpack("<Q", self.process.read(va, 8))[0]
        except OSError as exc:
            raise ValueError(f"va:{va:#x} cannot be read in the process: {exc}") from None

    def save(self, path):
        """Write the module as a file the other commands read: its bytes, then the record of the process."""
        source = self.home.source
        tail = copy_end(source.record)
        try:
            with open(path, "xb") as stream:
                stream.write(source.data)
                stream.write(tail)
        except FileExistsError:
            raise ValueError(f"{path} exists; a saved copy is never overwritten") from None
        digest = hashlib.sha256(source.data)
        digest.update(tail)
        return {
            "saved": str(path.resolve()),
            "size": hex(len(source.data) + len(tail)),
            "sha256": digest.hexdigest(),
            "modules": len(source.record["modules"]),
            "unreadable_bytes": sum(end - begin for begin, end, _ in source.holes) or None,
        }
