"""Records as text lines or JSONL.

A text line states each field with the words of its name, so both outputs use one term per fact:
`listed_under` in JSONL reads `listed under` in a line.
"""

import json
import re

CONTROL = re.compile(r"[\x00-\x1f]")
BARE = {"instruction", "bytes", "value", "name"}  # shown without their name
QUOTED = {"string", "ascii"}
LAST = ("note", "warning")  # free text that runs to the end of the line


def words(key, value):
    label = key.replace("_", " ")
    if value is True:
        return label
    if isinstance(value, dict):
        inner = [words(k, v) for k, v in value.items() if k != "address"]
        return " ".join([label, *([value["address"]] if "address" in value else []), *inner])
    if isinstance(value, (list, tuple)):
        value = " ".join(str(item) for item in value)
    if key in QUOTED:
        value = json.dumps(value, ensure_ascii=True)
    return str(value) if key in BARE else f"{label} {value}"


def clean(record):
    """Drop fields that state nothing; put free text last."""
    kept = {}
    for key, value in record.items():
        if isinstance(value, dict):
            value = clean(value)
        if value is None or value is False or (key not in ("address", "query") and value in ("", [], {})):
            continue
        kept[key] = value
    for key in LAST:
        if key in kept:
            kept[key] = kept.pop(key)
    return kept


def line(record):
    kind = record["record"]
    if kind == "note":
        return record["text"]
    if kind == "error":
        text = "error: " + ": ".join(part for part in (record.get("query"), record["message"]) if part)
    else:
        lead = f"# {record['command']} {record['query']}".rstrip() if kind == "summary" else record["address"]
        named = ("record", "command", "query", "address")
        text = "  ".join([lead, *(words(k, v) for k, v in record.items() if k not in named)])
    # A record is one line: control characters, which a query or the file can hold, are written as escapes.
    return CONTROL.sub(lambda found: json.dumps(found[0])[1:-1], text)


class OutputClosed(Exception):
    """The reader of the output went away, as `head` does."""


class Output:
    def __init__(self, stream, jsonl=False):
        self.stream = stream
        self.jsonl = jsonl

    def emit(self, record):
        record = clean(record)
        text = json.dumps(record, ensure_ascii=True, allow_nan=False) if self.jsonl else line(record)
        try:
            print(text, file=self.stream)
        except OSError as exc:
            raise OutputClosed from exc

    def flush(self):
        try:
            self.stream.flush()
        except OSError as exc:
            raise OutputClosed from exc
