---
name: byte-inspector
description: Disassemble and search AMD64 Windows executables and DLLs, on disk or loaded in a running process. Find references, strings, byte signatures, and MSVC class tables; identify the function or class slot at an address; follow hooked code and class slots to where they lead.
---

# Byte Inspector

Use this skill directory as the working directory.
Commands read a PE file or a running process and never change either.

```powershell
mise trust mise.toml
mise run inspector -- <command> --file "C:\Path\To\image.exe" ...
mise run inspector -- <command> --process Game.exe ...
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

`--limit N` applies to each query separately (1..10000; default 100, or 10000 for `disasm --function`).
A summary gives the full count, and `showing` when the limit cut the results.

`--jsonl` prints the same facts as JSON records, one per line; `record` is `summary`, `result`, `error`, or `note`.
Each summary record also says what was read: the `file` path and its `sha256`, or the `process`, `pid`, `module`, `read` time, and the `sha256` of the module as read.

A summary ends with `warning code in <section> looks encrypted or compressed` when the largest code section has an entropy above 7.0.
Use an unpacked copy of the file, or the running process, which holds the code decrypted; executables wrapped by Steam DRM are a common case.

## Addresses

| Address | Meaning |
|---|---|
| `rva:0x1000` | Relative to the image base |
| `va:0x140001000` | Absolute: at the preferred image base stored in a file, or as loaded in a process |
| `offset:0x400` | Position in a file |

Output uses `rva:` for every address inside the image and `va:` for addresses outside it.
An `offset:` whose bytes are loaded is answered as its `rva:`.
A line starts with `offset:` only when the bytes are in the file but are not loaded into memory, such as a signature after the last section.
`data` reads such bytes; they have no address, so `disasm` fails and `refs` finds nothing.

## Several queries and piping

`refs`, `disasm`, `data`, and `describe` accept any number of addresses.
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

## Functions

A function is every unwind entry that chains to one start.
`pieces` lists its byte ranges; compilers place rarely executed pieces far from the start.

Leaf functions have no unwind data.
Their extent is estimated by decoding forward from the end of the preceding function with unwind data, and labelled `estimated from` with the evidence for the start: `N direct calls`, `N pointers`, or `the preceding code only`.
In tests on functions with known starts, the start was wrong in 0–2% of estimates from calls or pointers and in 0.2–7% of estimates from the preceding code only, more often in DLLs than in game executables.
An estimated function ends at the first return or jump that no earlier branch passes; later blocks reached only from elsewhere are not included.

A function without unwind data is named only where a command estimates it: `describe`, `disasm --function`, and the instruction rows of `refs`.
Other mentions of an address in such code have no `function` field.

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
For data, rows give the import, export, or class slot at the address, and the string that holds it.
A string row leads with the start of the string, with `query at` when the address is further in.

## disasm

```powershell
mise run inspector -- disasm rva:0x2da9 --function --file $exe
mise run inspector -- disasm rva:0x2da9 --bytes 19 --show-bytes --file $exe
mise run inspector -- disasm rva:0x2feedd --bytes 11 --file $exe
```

```
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
`--before N` starts the listing N bytes before the address, which shows how the values an instruction uses were set.
Where unwind data covers the address, decoding starts again at the start of its function, or of the piece that holds it, so bytes before the function that are not code cannot put the listing out of step.
`--show-bytes` adds each instruction's bytes, for signatures and patch sizes.

Where unwind data covers the address, a listing starts at the instruction that holds it; the summary says `inside instruction rva:…` when that moved the start back.
Elsewhere decoding starts at the given byte.
With `--before`, such a start can be inside an instruction; the summary ends with a `note` when decoding then does not arrive at the address.
Decoding is linear and does not stop at a return, so data that lies in code, such as a jump table, is printed as instructions.
The exception is the eight bytes that a call or jump in the listing reads its destination from, as after `jmp qword ptr [rip]`.
They are one `pointer` row that says where they point, and the summary counts them as `pointers`.
When decoding stops before the end of a range or piece, the summary says where and why.

`target` gives the address a memory operand refers to and what it holds.
`no bytes in file` marks an address in the image that the file stores no bytes for, such as uninitialized data.
For an instruction that reads one float from a read-only section, `target` also gives that value as `f32` or `f64`.
A direct call or jump has a `target` only when its destination is exported, is an import stub, or is outside the image.
`export Name +N` counts the other names the address is exported by.

## refs

```powershell
mise run inspector -- refs rva:0x123450 rva:0x456780 --file $exe --kind call
mise run inspector -- refs --displacement 0x3F4 --displacement 0x3F8 --file $exe --section .text
```

`--kind` selects `all` (default), `call`, `branch`, `memory`, or `pointer`.
Calls and branches are direct relative transfers; memory references are RIP-relative operands.
Pointer rows are 64-bit cells that hold the address, anywhere in the file; a cell in a class table names its class and slot, which identifies virtual functions that nothing calls directly.
Transfers through registers and computed addresses are not found.

For a call or jump through an import, search for the import's IAT cell with `--kind memory`.
That search also finds the import's stub, if it has one; the callers of the stub are direct calls to the stub's address.

A row for a memory operand says what the instruction does there: `read`, `write`, both, or `address taken` for `lea`.
`unverified <reason>` marks a row whose instruction start could not be confirmed by decoding from the start of its unwind entry; without the mark it was confirmed.

`--displacement N` finds instructions with that signed memory displacement on any base register, which locates accesses to a structure field.
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
A text row leads with the start of the run of printable characters that holds the match, which is the address code refers to; `match` is the position of the match in it.
Decorated C++ type names such as `.?AVActor@@` are found this way.

Text is `ascii` (default), `utf-16le`, or `both`.
`--ignore-case` ignores the case of the letters A to Z; other characters match exactly.
Patterns are byte pairs with `??` wildcards; numbers are little-endian in the given `--type`.
Searches cover the whole file; `--section NAME` or `--start ADDRESS --length N` narrows them.

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

`--slots` defaults to 16 (1..1024) and `--slot-start` to 0.
A table ends at its first cell that does not point into code.
Only MSVC x64 RTTI is supported.

## info

```powershell
mise run inspector -- info --file $exe --limit 50
```

Prints the file's SHA-256, image base, and entry point, then sections with their entropy, imports with their IAT cells, and exports.
For a process or a saved copy of a module, it also names the process and the read time, says where each import cell points, and lists the loaded modules and any ranges that could not be read.
`--limit` applies to imports, exports, and modules separately.

## Running processes

```powershell
mise run inspector -- info --process SkyrimVR.exe
mise run inspector -- disasm rva:0x48060 --process 51216 --module python315.dll
```

`--process` takes the name of an executable or a PID, in place of `--file`.
Every command then works on one loaded module as it is at that moment: the process's executable, or the module that `--module` names.
Each call reads the module again; `info` lists the loaded modules.
Output starts with a `# process` line that names the process, the module, the `base` where it is loaded, and the read time.

`rva:` is relative to that module and `va:` is the address in the process; `offset:` is refused.
`find`, `refs`, and `rtti` search that module only.
A `refs` target can be anywhere, so `refs va:…` finds what in the module refers to an address in another module or in allocated memory.

`disasm`, `data`, and `describe` read an address wherever it is.

| The address is in | The answer |
|---|---|
| Another loaded module | From that module, with its functions and names; its addresses print as `va:` |
| Other memory | The bytes there, and from `describe` the region and its access; no function data, so `disasm --function` fails |

Rows say where an address outside the module lies: `in EngineFixes.dll rva:0x87e90`, or the kind of memory, as `in private memory` for memory the process allocated.
A call or jump through a pointer cell also says where the cell pointed when it was read, wherever the cell is:

```
rva:0x1843ef  call qword ptr [rip - 0x1a3aa3]  target va:0x7ff7c1920952 in private memory points to va:0x7ffe1e6ea5e0 in skyrimvresl.dll rva:0x2a5e0
```

`target` is the cell, and `points to` is the address it held.

An import cell says what the file declares and where the cell pointed: `import api-ms-win-crt-heap-l1-1-0.dll!malloc  points to va:0x7ffd2ef010e0 in EngineFixes.dll rva:0x1410e0`.
The two name different modules when a mod replaced the import, as here, and also when Windows forwards it, as from an `api-ms-win-…` name to `ucrtbase.dll`.
A module that kept its import names only in the cells shows `import DLL  name unavailable`, because the loader wrote the addresses over them.

In a class table, a slot that a mod redirected points outside the image; it stays a slot when the image's relocation data marks the cell, and its row says where it leads.

Lines from `--file` and `--process` use the same `rva:` addresses, so the same command on both shows what changed.

Bytes that the process does not let anyone read are never read as zeros.
A read of them fails, and a summary ends with a `warning` when results can be missing because of them; `info` lists the ranges.

## snapshot

```powershell
mise run inspector -- snapshot --process SkyrimVR.exe --output "$env:TEMP\skyrimvr.bin"
```

Saves the module as a file that every command reads with `--file`, with the answers the process gave at that moment.
An existing file is never overwritten.

The file is the module's bytes as read from memory, followed by a record that `info` prints: the process and its PID, the read time, every loaded module, and the ranges that could not be read.
The bytes lie as they did in memory, not as in a PE file on disk, so `offset:` is refused as for a process.

The copy holds the bytes of that module only.
It names an address in another loaded module but cannot read it, and it neither names nor reads memory the process allocated.
So a call or jump that leaves the module cannot be followed in the copy, and one through a cell outside the module says `not saved`.
