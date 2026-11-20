"""Byte searches that the commands share."""

import re
import struct

from .sources import ADDRESS_LIMIT

WINDOW = 1 << 16


def occurrences(data, needle, start=0, end=None):
    """Offsets of every match, overlapping ones included."""
    end = len(data) if end is None else end
    while (start := data.find(needle, start, end)) >= 0:
        yield start
        start += 1


def pattern_bytes(text):
    tokens = text.split()
    if not tokens or any(not re.fullmatch(r"[0-9a-fA-F]{2}|\?\?", token) for token in tokens):
        raise ValueError("Patterns use space-separated byte pairs and ?? wildcards")
    if all(token == "??" for token in tokens):
        raise ValueError("A byte pattern must contain at least one exact byte")
    return b"".join(b"." if token == "??" else re.escape(bytes.fromhex(token)) for token in tokens)


def rel32_fields(data, low, high, start_va, target, *, width=1, extra=0, modulus=ADDRESS_LIMIT):
    """Yield (offset, destination) of 32-bit relative fields in data[low:high] that refer into a target range.

    A field at offset f, loaded at va(f), refers to (va(f) + 4 + extra + stored) % modulus; it matches when
    that lands in [target, target + width).
    Within one 64 KiB window of offsets the stored values span few 64 KiB blocks, so the two upper bytes
    take few values and each window needs only a few 2-byte searches.
    """
    signed = modulus == ADDRESS_LIMIT
    for window in range(low, high, WINDOW):
        stop = min(high, window + WINDOW)
        first = (target - (start_va + stop - 1 - low + 4 + extra)) % modulus
        span = stop - 1 - window + width - 1
        uppers = set()
        for step in (*range(0, span + 1, WINDOW), span):
            value = (first + step) % modulus
            if signed:
                value -= ADDRESS_LIMIT if value >> 63 else 0
                if not -(1 << 31) <= value < 1 << 31:
                    continue
            uppers.add(struct.pack("<i" if signed else "<I", value)[2:])
        limit = min(high, stop + 3)
        for upper in uppers:
            at = window + 2
            while (at := data.find(upper, at, limit)) >= 0:
                field = at - 2
                at += 1
                if field + 4 > high:
                    continue
                stored = struct.unpack_from("<i", data, field)[0]
                destination = (start_va + field - low + 4 + extra + stored) % modulus
                if (destination - target) % modulus < width:
                    yield field, destination
