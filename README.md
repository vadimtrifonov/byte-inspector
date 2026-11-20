# Byte Inspector

Byte Inspector is a command-line tool for reading x86-64 code and data in Windows PE executables and DLLs.
It disassembles functions, finds references, strings, and byte patterns, and says what an address holds.

## Output

Results are text lines: a summary for each query, then one result per line, each starting with an address.
Printed addresses are valid input, so a command accepts several addresses at once and can read another command's lines from standard input.
`--jsonl` prints the same facts as JSON records.

Addresses inside the image are relative to its base (`rva:`), so they stay the same wherever the image is loaded.

## Commands

| Command | Input | Output |
|---|---|---|
| `info` | – | File identity, sections with entropy, imports, exports |
| `find` | Text, byte patterns, or numbers | Matches; for text, the string around each match |
| `refs` | Addresses, or a memory displacement | Instructions and stored pointers that refer to each address |
| `disasm` | Addresses | Instructions in a byte range or in the whole function |
| `data` | Addresses and a type | Values, or a pointer table with what each pointer refers to |
| `rtti` | Class names | Virtual function tables and their slots |
| `describe` | Addresses | The function, class slots, string, import, or export at each address |

## Functions

Windows unwind data records where functions are; it can split one function into pieces that lie far apart.
Byte Inspector treats all pieces that belong to one start as one function.
Functions that the unwind data omits get an estimated extent, labelled with the evidence for it.

## Encrypted code

Some executables keep their code encrypted or compressed on disk.
Their strings and data still read normally, while disassembly is meaningless and reference searches come back empty.
Byte Inspector measures the entropy of the largest code section and adds a warning to every summary when it is above 7.0 bits per byte.
The measure is a heuristic: a missing warning does not prove the code is plain.

## Getting started

Setup and development tasks use [mise](https://mise.jdx.dev/).
See [SKILL.md](SKILL.md) for setup and operating commands.

## Development

Run the unit tests with `mise run test`.
Check the tool's Python formatting and lint rules with `mise run check`.
