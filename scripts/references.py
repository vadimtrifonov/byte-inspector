"""Instructions that refer to an address, or use a memory displacement."""

import re
import struct

lazy import capstone as cs
lazy from capstone import x86

from .scan import occurrences, rel32_fields
from .sources import ADDRESS_LIMIT

IGNORED_SEGMENT = re.compile(r"\b[cdes]s:")
SHORT_BRANCHES = frozenset([0xEB, *range(0x70, 0x80), *range(0xE0, 0xE4)])
LONG_CONDITIONS = frozenset(range(0x80, 0x90))
RIP_MODRM = frozenset([0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D])
# What an instruction does with a memory operand, by mnemonic.
UPDATES = frozenset(
    "adc add and btc btr bts cmpxchg cmpxchg8b cmpxchg16b dec inc neg not or rcl rcr rol ror sal sar sbb shl "
    "shld shr shrd sub xadd xchg xor".split()
)
COMPARES = frozenset(["bt", "cmp", "test"])
READS_ONE = frozenset("call div idiv imul jmp mul push".split())
FLOAT_WIDTHS = {"ss": 4, "sd": 8}


def instruction_refs(ins):
    """Yield (kind, VA) for the addresses an instruction names directly."""
    branch = ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_BRANCH_RELATIVE)
    for operand in ins.operands:
        if branch and operand.type == x86.X86_OP_IMM:
            yield ("call" if ins.group(cs.CS_GRP_CALL) else "branch"), operand.imm % ADDRESS_LIMIT
        if operand.type != x86.X86_OP_MEM:
            continue
        memory = operand.mem
        if memory.segment in (x86.X86_REG_FS, x86.X86_REG_GS) or memory.index:
            continue
        if memory.base == x86.X86_REG_RIP:
            yield "memory", (ins.address + ins.size + memory.disp) % ADDRESS_LIMIT
        elif memory.base == x86.X86_REG_EIP:
            yield "memory", (ins.address + ins.size + memory.disp) % (1 << 32)
        elif not memory.base:
            yield "memory", memory.disp % (1 << (ins.addr_size * 8))


def memory_operand(ins):
    """(position, operand) of the memory operand; None for no memory operand, or two as string instructions have."""
    found = [(position, op) for position, op in enumerate(ins.operands) if op.type == x86.X86_OP_MEM]
    return found[0] if len(found) == 1 else None


def access(ins):
    """How an instruction uses its memory operand: read, write, both, or address_taken; () when not known.

    The mnemonic and the operand's position decide; Capstone 5 reports SSE and AVX stores as reads.
    """
    found = memory_operand(ins)
    if found is None:
        return ()
    position = found[0]
    name = ins.mnemonic.split()[-1]  # without lock and rep
    if name == "lea":
        return ("address_taken",)
    if name == "nop" or name.startswith("prefetch"):
        return ()
    if position:
        return ("read",)
    if name in UPDATES:
        return "read", "write"
    if len(ins.operands) > 1:
        return ("read",) if name in COMPARES else ("write",)
    if name in READS_ONE:
        return ("read",)
    return ("write",) if name == "pop" or name.startswith("set") else ()


def float_type(ins):
    """f32 or f64 when the instruction reads one scalar float from its memory operand."""
    found = memory_operand(ins)
    if found is None or found[0] == 0:
        return None
    name = ins.mnemonic.split()[-1].removeprefix("v")
    # A conversion names what it reads first: cvtss2sd reads an f32.
    kind = name.removeprefix("cvtt").removeprefix("cvt")[:2] if name.startswith("cvt") else name[-2:]
    width = FLOAT_WIDTHS.get(kind)
    return f"f{width * 8}" if width == found[1].size else None


def redundant_prefix(earlier, later):
    # LOOP's implicit counter width is not shown in its operand text.
    if later.id in (x86.X86_INS_LOOP, x86.X86_INS_LOOPE, x86.X86_INS_LOOPNE):
        if earlier.addr_size != later.addr_size:
            return False
    # Retain REX on ModR/M forms, including MSVC's 48 FF 15/25 encodings.
    return (
        earlier.mnemonic == later.mnemonic
        and IGNORED_SEGMENT.sub("", earlier.op_str) == IGNORED_SEGMENT.sub("", later.op_str)
        and (earlier.rex == later.rex or not later.modrm_offset)
    )


def fields(data, low, high, start_va, target, kind, displacement):
    """Yield (offset, width, encoding field) of operand fields in data[low:high] that may hold the reference."""
    if displacement is not None:
        for width in (1, 4):
            if -(1 << (8 * width - 1)) <= displacement < 1 << (8 * width - 1):
                needle = displacement.to_bytes(width, "little", signed=True)
                for field in occurrences(data, needle, low, high):
                    yield field, width, "disp"
        return
    if kind in ("all", "call", "branch"):
        direct = sorted(field for field, _ in rel32_fields(data, low, high, start_va, target))
        for field in direct:
            if field > low and data[field - 1] == 0xE8:
                yield field, 4, "imm"
        if kind != "call":
            for field in direct:
                if field > low and data[field - 1] == 0xE9:
                    yield field, 4, "imm"
            # A rel8 field lies within 128 bytes of its destination, in address space that wraps at 2**64.
            short = sorted(
                low + (target - 1 - value - start_va) % ADDRESS_LIMIT for value in range(-128, 128)
            )
            for field in short:
                if low < field < high and data[field - 1] in SHORT_BRANCHES:
                    value = data[field] - 256 if data[field] > 127 else data[field]
                    if (start_va + field - low + 1 + value) % ADDRESS_LIMIT == target:
                        yield field, 1, "imm"
            for field in direct:
                if field >= low + 2 and data[field - 2] == 0x0F and data[field - 1] in LONG_CONDITIONS:
                    yield field, 4, "imm"
    if kind in ("all", "memory"):
        # All RIP/EIP ModR/M forms, including VEX and instructions with trailing immediates.
        memory = {
            field
            for modulus in (ADDRESS_LIMIT, 1 << 32)
            for extra in (0, 1, 2, 4)
            for field, _ in rel32_fields(data, low, high, start_va, target, extra=extra, modulus=modulus)
        }
        for field in sorted(memory):
            if field > low and data[field - 1] in RIP_MODRM:
                yield field, 4, "disp"


class ReferenceScanner:
    def __init__(self, source, functions, decoder):
        self.source = source
        self.functions = functions
        self.md = decoder

    def around(self, field, width, encoding_field, low, high):
        source = self.source
        owner = source.owner(source.va_of_offset(field))
        if owner:
            low = max(low, source.offset_of_va(source.base + owner[0]))
        for start in range(max(low, field - 14), field):
            va = source.va_of_offset(start)
            boundary = self.functions.boundary(va)
            if boundary is None:
                continue
            ins = next(self.md.disasm(source.data[start : min(high, start + 15)], va, count=1), None)
            if ins is None:
                continue
            if (
                start + getattr(ins, encoding_field + "_offset") != field
                or getattr(ins, encoding_field + "_size") != width
            ):
                continue
            owner = source.owner(va)
            if owner and va + ins.size > source.base + owner[1]:
                continue
            yield ins, boundary

    def code(self, target, kind, displacement, spans):
        """Yield (instruction, boundary evidence) once per operand field and reference kind."""
        data = self.source.data
        seen = set()
        for low, high in spans:
            start_va = self.source.va_of_offset(low)
            for field, width, encoding_field in fields(data, low, high, start_va, target, kind, displacement):
                candidates = {}
                for ins, boundary in self.around(field, width, encoding_field, low, high):
                    if displacement is not None:
                        matched = any(
                            op.type == x86.X86_OP_MEM and op.mem.disp == displacement for op in ins.operands
                        )
                        matches = ["displacement"] if matched else []
                    else:
                        matches = [
                            ref_kind
                            for ref_kind, va in instruction_refs(ins)
                            if va == target and (kind == "all" or ref_kind == kind)
                        ]
                    for ref_kind in matches:
                        candidates.setdefault(ref_kind, []).append((ins, boundary))
                for ref_kind, found in candidates.items():
                    key = (field, ref_kind)
                    if key in seen:
                        continue
                    seen.add(key)
                    ins, boundary = found[-1]
                    # shortcut: prefix selection is heuristic, use a known boundary for exact starts.
                    for earlier, earlier_boundary in reversed(found[:-1]):
                        if redundant_prefix(earlier, ins):
                            break
                        ins, boundary = earlier, earlier_boundary
                    yield ins, boundary


def pointers(source, target, spans):
    """Offsets of 64-bit cells that hold the target address."""
    needle = struct.pack("<Q", target)
    for low, high in spans:
        yield from occurrences(source.data, needle, low, high)
