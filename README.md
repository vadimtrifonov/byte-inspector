# Byte Inspector

Byte Inspector is an agent skill for reading the machine code and data of x64 Windows executables and DLLs, on disk or loaded in a running process.
It finds strings, byte patterns, and what refers to an address, lists instructions, and says what an address belongs to: a function, a class and its slot, a string, or an import.

```
# refs rva:0x4af7310  results 17  showing 2  target string "ActivateTypeMode"
rva:0x2da9  lea rdx, [rip + 0x4af4560]  address taken  function rva:0x2da0
rva:0x3299  lea rdx, [rip + 0x4af4070]  address taken  function rva:0x3270
```

Every result line starts with an address that any command accepts, so the lines of one command feed the next.
Addresses are relative to the image, so they are the same in the file and wherever it is loaded.

## Running processes

The same commands read a module of a running process.
It shows what the file cannot: decrypted code, current values, and what other code changed.
Where a mod redirected a call, a class slot, or an import, the line says where it now leads.
Here a call in a game goes through a cell in memory that a mod allocated, to the mod's DLL:

```
rva:0x1843ef  call qword ptr [rip - 0x1a3aa3]  target va:0x7ff7c1920952 in private memory points to va:0x7ffe1e6ea5e0 in skyrimvresl.dll rva:0x2a5e0
```

A loaded module can be saved to a file, which the commands read after the process has ended.

## Install

The skill runs on Windows and needs [mise](https://mise.jdx.dev/), which installs the Python version and the packages that the skill pins.
Install it with [skills](https://github.com/vercel-labs/skills):

```powershell
npx skills add vadimtrifonov/byte-inspector
```

## Limits

Byte Inspector is a disassembler: it shows the instructions of a function, not C.
To read a function as C, use [Ghidra Decompiler](https://github.com/vadimtrifonov/ghidra-decompiler).

It finds references that are written into code and data: a call to an address, an instruction that reads it, a pointer that holds it.
A virtual call, or any call through a register, has no address written into it, so the callers of a virtual function are not found.
For such a function it names the class and slot instead, in binaries that keep MSVC RTTI.
