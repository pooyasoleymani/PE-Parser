# PE Parser — Ubuntu / GCC

A C++17 command-line PE parser intended as a practical starting implementation for the PE parser challenge.

## Implemented

- DOS header signature and `e_lfanew`
- NT signature and COFF File Header fields
- PE32 and PE32+ Optional Header fields and available Data Directories
- Section Headers
- RVA-to-file-offset translation with raw-data bounds
- Import Directory: DLL names, imported names, Hint, and ordinal imports
- Export Directory: names, ordinals, function RVAs, ordinal-only exports, and forwarded exports
- Optional MSVC decorated-name demangling through `llvm-undname` on Linux
- Bounds checks and malformed/truncated input errors

The optional Dependency Walker (challenge item D) is not included in this version.

## Build

```bash
sudo apt update
sudo apt install build-essential cmake llvm binutils
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Try static linking (may require the system's static C++ runtime packages):

```bash
cmake -S . -B build-static -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC=ON
cmake --build build-static -j
```

## Run

```bash
./build/peparser /path/to/sample.exe
./build/peparser /path/to/sample.dll
```

If `llvm-undname` is installed and available in `PATH`, decorated MSVC export names beginning with `?` are passed to it using `execvp` (not a shell). The output contains the demangled signature, which commonly includes class and parameter types. Exact prototype reconstruction depends on the completeness and form of the symbol.

## Validate against system tools

```bash
file sample.exe
objdump -x sample.exe
objdump -p sample.exe
objdump -h sample.exe
llvm-readobj --file-headers --sections --coff-imports --coff-exports sample.dll
```

Compare import/export lists and section/header values with this program.

## Important limitations

This is a challenge-oriented parser, not a hardened malware-analysis library.

- It supports ordinary PE32/PE32+ images and standard import/export tables.
- It does not currently parse delay imports, bound-import metadata, resource trees, relocations, TLS, debug directories, certificates, or load-config structures.
- It does not resolve Windows API sets, side-by-side assemblies, architecture-specific loader rules, or runtime `LoadLibrary`/`GetProcAddress` dependencies.
- The optional demangler depends on LLVM's `llvm-undname`; it is not a full in-process MSVC ABI demangler.
- The parser uses little-endian byte decoding and targets Ubuntu/Linux.
- Some unusual or malformed but loader-tolerated PE files may be rejected.

## Suggested test matrix

1. PE32 EXE with imports.
2. PE32+ EXE with imports.
3. DLL with named exports.
4. DLL with ordinal-only exports.
5. DLL with forwarded exports.
6. DLL with MSVC-decorated exports.
7. File with no imports or exports.
8. Truncated file, invalid `e_lfanew`, invalid section raw range, invalid thunk RVA.

## Submission notes

Submit the source folder and a statically linked binary if the static build succeeds. The challenge asks for static binaries alongside source. Verify that your output binary is actually static:

```bash
file build-static/peparser
ldd build-static/peparser
```

`ldd` should report that the file is not a dynamic executable for a fully static build.
