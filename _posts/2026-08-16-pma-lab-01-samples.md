---
title: Practical Malware Analysis Lab 01-01 through 01-04
date: 2026-08-16 10:00
categories: [analysis, security, malware, lab]
tags: [analysis, security, lab, pma]
---

This post covers the initial static and dynamic analysis pass for the four samples in Practical Malware Analysis Lab 01: `Lab01-01.dll`, `Lab01-01.exe`, `Lab01-02.exe`, `Lab01-03.exe`, and `Lab01-04.exe`. The first three samples didn't turn up much worth screenshotting after the initial pass, so those sections are notes only. The last two samples had the most interesting behavior, so those sections include screenshots.

## Lab01-01.dll

**File info**

- Size: 160 KB
- Type: PE32, likely compiled with C++
- SHA256: `f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba`
- Entropy: 0.12857 (very low, not packed)
- Compilation timestamp: Sun Dec 19 16:16:38 2010 (UTC)
- Exports: none

### Static Analysis

Three imported DLLs stood out:

- `kernel32.dll`
- `ws2_32.dll`
- `msvcrt.dll`

PE-Bear turned up 5 imports on its own, but pestudio filled in the rest of the picture. The `ws2_32.dll` imports are the most telling part of this sample:

```
socket
WSAStartup
inet_addr
connect
send
shutdown
closesocket
recv
WSACleanup
```

Alongside those, a handful of CRT and process-related imports showed up:

```
malloc
free
strncmp
Sleep
CreateProcessA
CreateMutexA
OpenMutexA
CloseHandle
```

Two strings worth noting were `hello` and the IP address `127.26.152.13`.

### Dynamic Analysis

FLOSS didn't find any stack strings or decoded strings, so there's nothing further to pull out that way.

### Assessment

**Key finding:** the combination of the `ws2_32.dll` networking imports and a hardcoded IP address strongly suggests this DLL is built to reach out to a remote host over a raw socket. The `CreateMutexA`/`OpenMutexA` pair implies an infection-marker check, and `CreateProcessA` suggests it can spawn additional processes. My working theory is that this is a C2 loader: it checks for a mutex to avoid re-infecting a host, then connects out to the hardcoded IP to potentially pull down further payloads.

## Lab01-01.exe

**File info**

- Size: 16 KB
- Type: PE32, likely compiled with C++
- SHA256: `58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47`
- Entropy: 1.95380 (low, not packed)

### Static Analysis

The import list here leans heavily toward file manipulation rather than networking:

```
CloseHandle
MapViewOfFile
CreateFileMappingA
CreateFileA
FindClose
FindNextFileA
FindFirstFileA
CopyFileA
malloc
exit
```

Two CRT functions are worth a closer look:

- [`_setusermatherr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/setusermatherr?view=msvc-170)
- [`_stricmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l?view=msvc-170)

A few embedded strings appear to reference `Lab01-01.dll` directly, which suggests these two samples are meant to run as a pair.

### Dynamic Analysis

FLOSS didn't find any stack strings or decoded strings for this sample either.

### Assessment

**Key finding:** the file-mapping and file-copy imports, combined with the string references back to `Lab01-01.dll`, point to this EXE acting as a loader or launcher for the DLL. Given the DLL's apparent C2/networking role, my assessment is this pairing is meant for data exfiltration with some file-manipulation or file-destruction capability on the host. I haven't seen anything yet that indicates file encryption.

## Lab01-02.exe

**File info**

- Size: 3 KB
- Type: PE32, likely compiled with C++
- SHA256: `c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6`
- Compilation timestamp: Wed Jan 19 16:10:41 2011 (UTC)
- Overall entropy: 5.24974
- Packed: yes, UPX

### Static Analysis

Detect It Easy flagged this sample as packed with UPX. Overall file entropy doesn't scream "packed" at 5.24974, but the `UPX1` section alone comes in at 7.06718, which is a much stronger signal. Every section besides the header carries a UPX name, and both `UPX0` and `UPX1` are marked executable. `UPX0` is virtual only, with no size on disk outside its virtual size, which is typical of UPX-packed binaries.

Imported DLLs:

- `kernel32.dll`
- `advapi32.dll`
- `msvcrt.dll`
- `wininet.dll`

Imports:

```
LoadLibraryA
GetProcAddress
VirtualProtect
VirtualAlloc
VirtualFree
ExitProcess
CreateServiceA
InternetOpenA
```

The `wininet.dll` import and `CreateServiceA` are the two standouts here: one points to internet connectivity, the other to service creation (a common persistence mechanism).

### Dynamic Analysis

FLOSS didn't find any stack or decoded strings on the packed binary. Capa also couldn't identify much beyond confirming the sample is packed.

After manually unpacking with `upx -d`, both tools had a lot more to work with. Capa picked up on:

- Internet connectivity capabilities
- Mutex checking
- Service creation and execution
- Possible persistence setup

### Assessment

**Key finding:** this is very likely a persistent C2 payload. It installs itself as a service for persistence and uses `wininet.dll` to reach back out to a C2 server for further instructions. UPX is doing a reasonable job of hiding these capabilities from static tools until the sample is unpacked.

## Lab01-03.exe

**File info**

- Size: 4.64 KB
- Type: PE32
- SHA256: `7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec`
- Entropy: low overall, except for one section at 7.36186

### Static Analysis

The only imports visible at this stage are `LoadLibraryA` and `GetProcAddress`, which is a strong hint that the rest of the functionality is resolved dynamically at runtime rather than through the standard import table.

A few other symbols of interest:

```
OleInitialize
CoCreateInstance
OleUninitialize
__getmainargs
_controlfp
_except_handler3
```

### Dynamic Analysis

FLOSS didn't find any stack strings and couldn't decode anything. Capa found no capabilities either, which lines up with the minimal import table.

The first executable instruction sits at `0x00401000`. Stepping through the code, there's a conditional jump (`je`) at `0x004050E1` that leads to `Lab01-03.401090`. Following that memory region in the dump, it's empty at rest.

To confirm whether this region gets populated at runtime, I set a hardware breakpoint on it. This is a similar approach to manually unpacking a UPX sample in a debugger, except UPX typically uses an unconditional jump into an empty region followed by a large run of zeroes. Here, the unpacking stub instead uses a conditional jump into the empty region.

Letting execution run and stop at the breakpoint, the target region is now populated, and since EIP now points there, the unpacked contents can be dumped directly from memory.

![Lab01-03.exe empty region](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_03_exe_empty_region.png?raw=true)

![Lab01-03.exe region with content](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_03_exe_region_with_content.png?raw=true)

![Lab01-03.exe packed compared with unpacked](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_03_exe_compared_packed_with_unpacked.png?raw=true)

![Lab01-03.exe unpacked in die](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_03_unpacked_die.png?raw=true)

### Assessment

**Key finding:** the minimal static import table combined with the manual unpacking process at the conditional jump strongly suggests a custom or non-standard packer, rather than a well-known one like UPX. Further analysis of the dumped contents is needed to determine the sample's actual capabilities.

## Lab01-04.exe

**File info**

- Size: 36 KB
- Type: PE32, likely compiled with C++
- SHA256: `0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126`
- Compilation timestamp: Fri Aug 30 22:26:59 2019 (UTC)
- Packing: DiE flags a generic packer, though section entropy doesn't confirm packing on the main sections

### Static Analysis

None of the main sections show elevated entropy according to DiE, but a resource named `BIN` is flagged as executable and accounts for over 55% of the total file size, located at offset `0x00004060` in the `rsrc` section. That's a strong indicator of an embedded PE.

Imports lean toward file and process manipulation:

- File and process manipulation functions
- String copy functions
- Handle manipulation functions

Two file path strings stand out:

```
\system32\wupdmgr.exe
\winup.exe
```

Both reference executables that would live in the Windows `system32` path, which suggests the sample may be dropping or masquerading as a legitimate-looking Windows update component.

### Dynamic Analysis

FLOSS didn't find any stack or decoded strings. Capa flagged that a PE is embedded within a section of the file, which lines up with the oversized `rsrc` section identified during static analysis.

Pulling the resource up in DiE confirms the `BIN` resource, which starts with `4d5a`, the `MZ` header for a PE file.

![Lab01-04.exe embedded BIN resource in Detect It Easy](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_04_die_rsrc_section.png?raw=true)

Dumping the resource with DiE and confirming in a hex editor shows a clean 16 KB PE32 file.

Loading the dumped 16 KB PE into PEStudio shows strings related to file downloading and dropping additional files into a temp path.

![Lab01-04.exe dumped PE strings in PEStudio](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/pma_lab_01/lab_01_04_bin_dump.png?raw=true)

### Assessment

**Key finding:** this sample acts as a dropper. The outer executable embeds a second, smaller PE inside its `rsrc` section disguised as a generic `BIN` resource, and the dropped file's strings point to further file downloading and staging in a temp directory. The `wupdmgr.exe` and `winup.exe` path references also suggest an attempt to blend in with legitimate Windows update processes for persistence or evasion.

## Summary

| Sample | Type | Packed | Primary Behavior |
|---|---|---|---|
| Lab01-01.dll | DLL | No | Socket-based C2 connectivity, mutex check |
| Lab01-01.exe | EXE | No | Loader/launcher for the DLL, file manipulation |
| Lab01-02.exe | EXE | UPX | Persistent C2 payload, service creation |
| Lab01-03.exe | EXE | Custom/unknown packer | Unpacks via conditional jump, capabilities TBD |
| Lab01-04.exe | EXE | Embedded PE (resource) | Dropper, embeds a second PE disguised as a Windows update file |

Taken together, these five samples look like components of the same malware family: a dropper and loader pair (`Lab01-01.exe`/`Lab01-01.dll`) with C2 connectivity, a packed persistence mechanism (`Lab01-02.exe`), and two additional samples (`Lab01-03.exe`, `Lab01-04.exe`) that use packing and resource embedding to hide a similar dropper/loader pattern.