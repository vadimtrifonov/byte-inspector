---
name: byte-inspector
description: Disassemble and search AMD64 PE executable and DLL files. Find references, strings, byte signatures, and MSVC class tables; identify the function or class slot at an address.
---

# Byte Inspector

Use this skill directory as the working directory.
Commands read one PE file and never change it.

```powershell
mise trust mise.toml
mise run inspector -- <command> --file "C:\Path\To\image.exe" ...
```

## Output

A command prints one `#` summary line for each query, then one result per line.
Every result line starts with an address that any command accepts as input.
Fields are separated by two spaces.
A line break or other control character in a line is written as an escape such as `\n`.

```
# refs rva:0x4af7310  results 17  showing 2  target string "ActivateTypeMode"
rva:0x2da9  lea rdx, [rip + 0x4af4560]  address taken  function rva:0x2da0
rva:0x3299  lea rdx, [rip + 0x4af4070]  address taken  function rva:0x3270
```

`--limit N` applies to each query separately (1..10000, default 100).
A summary gives the full count, and `showing` when the limit cut the results.

`--jsonl` prints the same facts as JSON records, one per line.
`record` is `summary`, `result`, `error`, or `note`; other field names are the words of the text line joined by underscores.
`instruction`, `bytes`, `value`, and `name` are the fields that lines print without a name.
Each summary record also has the `file` path and its `sha256`.

A summary ends with `warning code in <section> looks encrypted or compressed` when the largest code section has an entropy above 7.0.
Then disassembly is meaningless and reference searches find little or nothing, without any other sign.
Use an unpacked copy of the file; executables wrapped by Steam DRM are a common case.

## Addresses

| Address | Meaning |
|---|---|
| `rva:0x1000` | Relative to the image base |
| `va:0x140001000` | At the preferred image base stored in the file |
| `offset:0x400` | Position in the file |

Output uses `rva:` for every address inside the image and `va:` for addresses outside it.
An `offset:` whose bytes are loaded is answered as its `rva:`.
A line starts with `offset:` only when the bytes are in the file but are not loaded into memory, such as a signature after the last section.
Such bytes can be read with `data`; they have no address, so `disasm` fails and `refs` finds nothing.

## Several queries and piping

`refs`, `disasm`, `data`, and `describe` accept any number of addresses.
Each address gets the answer it would get alone.
An answer that an earlier address in the same call already produced is not repeated; its summary says `listed under <that address>`.

A failed address prints `error: <address>: <reason>` in its place, the other addresses are answered, and the exit code is 1.
When the whole call fails, one `error:` line goes to both stdout and stderr.

The address `-` reads standard input and takes the first field of each line as an address, so one command's lines feed another.

```powershell
mise run inspector -- refs rva:0x62b200 --kind call --file $exe | mise run inspector -- disasm - --function --file $exe
```

`#` lines pass through unchanged, so earlier summaries stay visible.
`error:` lines pass through and make the exit code 1; so does any other line that does not start with an address.
JSONL is not accepted as input.

## What rows say about an address

Rows describe the addresses they mention with these fields.

| Field | Meaning |
|---|---|
| `function rva:…` | Start of the function that holds the address; from unwind data unless `estimated from` follows |
| `function start` | The address is itself that start |
| `export Name` | The address is exported by that name; `+N` counts its other exported names |
| `string "…"` | A NUL-terminated ASCII or UTF-16 string starts there |
| `inside string rva:…` | The address is inside the string that starts at that address |
| `import DLL!Name` | The address is that import's IAT cell |
| `import stub DLL!Name` | The code at the address jumps through that import's IAT cell, so a call to the address reaches the import |
| `class Name  slot N` | The address is slot N of a virtual function table of that class |
| `no bytes in file` | The address is in the image but the file has no bytes for it, as in uninitialized data |

A function without unwind data is named only where a command estimates it: `describe`, `disasm --function`, and the instruction rows of `refs`.
Other mentions of an address in such code have neither `function` field.

## describe

```powershell
mise run inspector -- describe rva:0xa94b90 rva:0x62b217 --file $exe
```

```
# describe rva:0xa94b90  section .text  in file offset:0xa94190  results 4
rva:0xa94b90  function pieces rva:0xa94b90..rva:0xa94bbc  function size 0x2c
rva:0x4b80928  class TESKey  slot 16  vtable rva:0x4b808a8  subobject +0x0
rva:0x4b87ac8  class TESObjectMISC  slot 16  vtable rva:0x4b87a48  subobject +0x0
rva:0x4b8e338  class TESSoulGem  slot 16  vtable rva:0x4b8e2b8  subobject +0x0
# describe rva:0x62b217  section .text  in file offset:0x62a817  results 1
rva:0x62b200  function pieces rva:0x62b200..rva:0x62b228  estimated from 4 direct calls  function size 0x28  query at +0x17
```

For an address in code, the first row leads with the start of its function.
The rows after it are about that function: each name it is exported by, the import it is a stub for, and each class-table slot that points to it.
One function can serve several classes.
`inside instruction rva:…` appears when the address is not the start of an instruction.
For data, rows give the import, export, or class slot at the address, and the string that holds it.
A string row leads with the start of the string, with `query at` when the address is further in.

## Functions

A function is every unwind entry that chains to one start.
`pieces` lists its byte ranges; compilers place rarely executed pieces far from the start.

Leaf functions have no unwind data.
Their extent is estimated by decoding forward from the end of the preceding function with unwind data, and labelled `estimated from`:

| Evidence | Wrong starts in tests on known functions |
|---|---|
| `N direct calls`, `N pointers` | 0–2% |
| `the preceding code only` | 0.2–7%, higher in DLLs than in game executables |

An estimated function ends at the first return or jump that no earlier branch passes; later blocks reached only from elsewhere are not included.

## disasm

```powershell
mise run inspector -- disasm rva:0x2da9 --function --file $exe --limit 300
mise run inspector -- disasm rva:0x2da9 rva:0x3299 --bytes 19 --show-bytes --file $exe
mise run inspector -- disasm rva:0x2feedd --bytes 11 --file $exe
```

```
# disasm rva:0x2da9  function rva:0x2da0  pieces rva:0x2da0..rva:0x326f  instructions 256
rva:0x2da0  push rbx
...
# disasm rva:0x2da9  range rva:0x2da9..rva:0x2dbc  function rva:0x2da0  instructions 3
rva:0x2da9  48 8d 15 60 45 af 04  lea rdx, [rip + 0x4af4560]  target rva:0x4af7310 string "ActivateTypeMode"
rva:0x2db0  48 8d 0d 09 81 1f 06  lea rcx, [rip + 0x61f8109]  target rva:0x61faec0 no bytes in file
rva:0x2db7  e8 c4 8c 8c 02  call rva:0x28cba80
# disasm rva:0x2feedd  range rva:0x2feedb..rva:0x2feee8  function rva:0x2feae0  inside instruction rva:0x2feedb  instructions 2
rva:0x2feedb  vmulss xmm0, xmm0, dword ptr [rip + 0x4c04f5d]  target rva:0x4f03e40 f32 0.001
rva:0x2feee3  vmovss dword ptr [rbx + 0x7c], xmm0
```

Without options, a listing covers up to 256 bytes from the address.
`--bytes N` sets the byte count (up to 1 MiB); `--function` lists the whole function that holds the address, piece by piece.
`--show-bytes` adds each instruction's bytes, for signatures and patch sizes.

Where unwind data covers the address, a listing starts at the instruction that holds it.
An address inside an instruction moves the start back to that instruction, and the summary says `inside instruction rva:…`.
Elsewhere decoding starts at the given byte.
Decoding is linear from the start, including bytes after returns.
When it stops before the end of a range or piece, the summary says where: `ends inside instruction rva:…` for an instruction that needs bytes beyond it, `undecodable at rva:…` for bytes that are not an instruction.

Direct call and jump operands are printed as addresses.
`target` gives the address a memory operand refers to and what it holds.
For an instruction that reads one float from a read-only section, `target` also gives that value as `f32` or `f64`.
A direct call or jump has a `target` only when its destination is exported or is an import stub.

## refs

```powershell
mise run inspector -- refs rva:0x123450 rva:0x456780 --file $exe --kind call
mise run inspector -- refs --displacement 0x3F4 --file $exe --section .text
```

`--kind` selects `all` (default), `call`, `branch`, `memory`, or `pointer`.
Calls and branches are direct relative transfers; memory references are RIP-relative operands.
Pointer rows are 64-bit cells that hold the address, anywhere in the file; a cell in a class table names its class and slot, which identifies virtual functions that nothing calls directly.
Transfers through registers and computed addresses are not found.

For a call or jump through an import, search for the import's IAT cell with `--kind memory`.
That search also finds the import's stub, if it has one; the callers of the stub are direct calls to the stub's address.

Code rows name their function; `estimated from` follows where the function has no unwind data.
A row whose instruction refers to the address through a memory operand says what it does there: `read`, `write`, both, or `address taken` for `lea`.
`unverified <reason>` marks a row whose instruction start could not be confirmed by decoding from the start of its unwind entry; without the mark it was confirmed.

`--displacement N` finds instructions with that signed memory displacement on any base register, which locates accesses to a structure field.
These rows also say `read`, `write`, or `address taken`.
Displacements from -128 to 127 need `--section` or `--start`/`--length` covering at most 1 MiB.

## find

```powershell
mise run inspector -- find --text "Gravity" --text "fJump" --ignore-case --encoding both --file $exe
mise run inspector -- find --pattern "48 8D ?? ?? ?? ?? ?? E8" --section .text --file $exe
mise run inspector -- find --value 0x1234 --type u32 --file $exe
```

```
# find TypeMode  results 1  scanned bytes 102476200
rva:0x4af7310  string "ActivateTypeMode"  match +8
```

Each `--text`, `--pattern`, or `--value` is a query.
A text row leads with the start of the text around the match, which is the address code refers to; `match` is the character position of the match in it.
That text is the printable ASCII characters, tabs, and line breaks on both sides of the match.
Long text is shown as a part around the match, with `...` where it is cut.
Decorated C++ type names such as `.?AVActor@@` are found this way.

Text is `ascii` (default), `utf-16le`, or `both`.
`--ignore-case` ignores the case of the letters A to Z; other characters match exactly.
Patterns are byte pairs with `??` wildcards; numbers are little-endian in the given `--type`.
Searches cover the whole file; `--section NAME` or `--start ADDRESS --length N` narrows them.
Counts include overlapping matches.

## data

```powershell
mise run inspector -- data rva:0x4b87a48 --type pointer --count 8 --file $exe
mise run inspector -- data rva:0x3b4a144 --type f32 --count 4 --file $exe
```

Types are `u8 i8 u16 i16 u32 i32 u64 i64 f32 f64 pointer`, little-endian; `--count` defaults to 16 (maximum 4096).
`u8` prints 16 bytes per row with their ASCII text; other types print one value per row.
A `pointer` row says what the address it points to holds.

## rtti

```powershell
mise run inspector -- rtti Actor BSScript::Object --slots 2 --limit 1 --file $exe
mise run inspector -- rtti Actor --slot-start 275 --slots 1 --limit 1 --file $exe
```

```
# rtti Actor  table 1 of 25  type .?AVActor@@  vtable rva:0x4cb9248  subobject +0x0  slots 2
rva:0x18d7c40  slot 0  cell rva:0x4cb9248
rva:0x3ae910  slot 1  cell rva:0x4cb9250
```

A name is a plain class or struct name, with `::` for namespaces, or an exact decorated name such as `.?AVActor@@`, which templates require.
Each virtual function table is a summary; the primary table, `subobject +0x0`, comes first, and `--limit` counts tables.
Slot rows lead with the function, with the slot's own address in `cell`.

`--slots` defaults to 16 (1..1024) and `--slot-start` to 0.
A table ends at its first cell that does not point into code.
`table ends before slot N` says the table has only N slots when the request reaches past them.
Only MSVC x64 RTTI is supported.

## info

```powershell
mise run inspector -- info --file $exe --limit 50
```

Prints the file's SHA-256, image base, and entry point, then sections with their entropy, imports with their IAT cells, and exports.
`--limit` applies to imports and exports separately.
