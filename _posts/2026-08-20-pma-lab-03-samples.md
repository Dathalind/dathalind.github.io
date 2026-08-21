---
title: Practical Malware Analysis - Lab 03
date: 2026-08-20
categories: [analysis, security, malware, lab]
tags: [analysis, security, lab, backdoor, service-persistence, poison-ivy]
---

Lab 03 from *Practical Malware Analysis* covers four samples, each demonstrating a different flavor of Windows persistence and command and control. The set includes a minimal HTTP beacon, a service-installing DLL backdoor, a sample that appears to share identical binary content with the first, and a fully featured backdoor with remote shell and anti-forensic capabilities. Static analysis was performed with PE-Bear, PEStudio, FLOSS, Capa, and Detect It Easy, with dynamic behavior captured through process and registry monitoring. Selected samples were also examined in a disassembler to confirm behavior that dynamic analysis alone could not fully surface.

## Lab03-01.exe

### Static Analysis

- **File type:** PE32, 7 KB, x86 assembly
- **Sections:** 2, no evidence of packing
- **SHA256:** `eb84360ca4e33b8bb60df47ab5ce962501ef3420bc7aab90655fd507d2ffcedd`
- **Imports:** a single import, `ExitProcess` from `kernel32.dll`
- **Capa findings:** limited to a terminate process capability at `0x400208`

The single-import footprint and absence of decoded or stack strings suggest most functional logic is either resolved dynamically at runtime or that this sample is deliberately minimal. Notable strings recovered from the binary point toward network beaconing and registry-based persistence:

```
CONNECT %s:%i HTTP/1.0\r\n\r\n
Software\Microsoft\Active Setup\Installed Components\
vmx32to64.exe
SOFTWARE\Classes\http\shell\open\commandV
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
```

The `CONNECT` string is characteristic of an HTTP proxy tunnel request, and the `vmx32to64.exe` string alongside the Active Setup registry path suggests the sample is designed to masquerade as a legitimate VMware-related component while establishing persistence.

### Dynamic Analysis

Execution under an administrator context did not yield new observable behavior. The process appears to hit an unhandled exception shortly after launch and terminates, which limited the ability to fully replicate all indicators referenced in the static strings. One registry artifact was confirmed during execution:

- `HKU\S-1-5-21-2092677455-4225181490-3885091302-1001\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Users\micro\Desktop\Lab03-01.exe`

This key is written by the Windows Application Compatibility subsystem whenever a process runs, and is not itself evidence of malicious persistence. It does, however, confirm the sample executed and briefly ran before crashing.

### Assessment

Lab03-01.exe appears to be a lightweight HTTP beacon intended to establish command and control over port 80 using a `CONNECT` style request, while persisting through the Active Setup `Installed Components` registry mechanism. The extremely small import table and reliance on strings rather than resolvable API calls suggest the sample either dynamically resolves its imports at runtime or is a stub/loader component. The crash observed during dynamic analysis prevented full behavioral confirmation, so this assessment is based primarily on static string evidence.

## Lab03-02.dll

### Static Analysis

- **File type:** PE32 DLL, 23.5 KB, compiled in C/C++
- **Entropy:** 6.34 (overall), consistent with unpacked, non-obfuscated code
- **SHA256:** `5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9`
- **Section names:** unremarkable, no indication of packing

PEStudio flagged a substantial number of imports, including several referenced only by ordinal that correspond to network functionality. Additional flagged imports of note:

| Import | Purpose |
| --- | --- |
| `CreateServiceA` / `DeleteService` | Windows service installation and removal |
| `RegCreateKeyA` / `RegSetValueExA` | Registry key creation and value writes |
| `CreateProcessA` / `CreatePipe` | Process creation with redirected I/O |
| `CreateThread` / `Sleep` | Execution control and timing |
| `GetProcAddress` / `lstrlenA` | Dynamic API resolution |

The DLL exports five functions: `install`, `ServiceMain`, `UninstallService`, `installA`, and `uninstallA`. This export naming convention, combined with the imports above, strongly suggests the DLL is designed to be invoked with a specific export as an argument to `rundll32.exe` in order to install itself as a Windows service. Recovered strings included a hardcoded domain, base64-encoded data, and command-line fragments referencing `cmd.exe /c`.

### Dynamic Analysis

Executing the DLL through `rundll32.exe` without explicitly specifying an export resulted in a crash, and no service creation was observed in this state. Based on the export list, `installA` or `ServiceMain` are the most likely intended entry points for triggering the installation routine.

### Deeper Code Analysis

Loading the sample into a disassembler surfaced the string `IPRIP` referenced as `arg1[-7]` inside the `Install` subroutine. Tracing this value further down the function confirmed it is passed directly to `CreateServiceA` as the service name:

```nasm
10004883    SC_HANDLE hSCObject = CreateServiceA(
10004883        hSCManager: eax_13,
10004883        lpServiceName: arg1[-7],
10004883        lpDisplayName: "Intranet Network Awareness (INA+)",
10004883        dwDesiredAccess: 0xf01ff,
10004883        dwServiceType: SERVICE_WIN32_SHARE_PROCESS,
10004883        dwStartType: SERVICE_AUTO_START,
10004883        dwErrorControl: SERVICE_ERROR_NORMAL,
10004883        lpBinaryPathName: "%SystemRoot%\System32\svchost.exe -k netsvcs",
10004883        lpLoadOrderGroup: nullptr,
10004883        lpdwTagId: nullptr,
10004883        lpDependencies: nullptr,
10004883        lpServiceStartName: nullptr,
10004883        lpPassword: nullptr)
```

This confirms the sample registers itself under the service name **IPRIP**, displayed to the user as **"Intranet Network Awareness (INA+)"**, a name chosen specifically to blend in with legitimate Windows networking services. The service is configured to run inside a shared `svchost.exe` process group (`netsvcs`) with automatic startup, which is a common technique for hiding a malicious service among dozens of legitimate ones in Task Manager or Services.msc. Per the [CreateServiceA documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea), the `0xf01ff` access mask requested is broad, and the [service security and access rights documentation](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) confirms this grants full control over the created service object.

### Assessment

Lab03-02.dll is a service-installer backdoor component. It masquerades as the legitimate-sounding "Intranet Network Awareness (INA+)" service while actually registering itself under the real Windows service name `IPRIP` (Internet Protocol Routing Information Protocol, normally disabled by default on modern Windows), a name unlikely to draw attention during a casual review of installed services. Hosting itself inside `svchost.exe -k netsvcs` allows the malicious code to run under a trusted parent process, complicating process-based detection. This is consistent with a persistence-and-execution stage of a larger malware toolkit rather than a standalone payload.

## Lab03-03.exe

### Static Analysis

- **File type:** PE32, 7 KB, x86 assembly
- **Entropy:** 5.96 overall, 6.40 in the `.data` section
- **SHA256:** `ae8a1c7eb64c42ea2a04f97523ebf0844c27029eb040d910048b680f884b9dce`
- **Compile timestamp:** Sun Jan 06 14:51:31 2008 (UTC)
- **Sections:** `.text` and `.data`, with `.data` accounting for 85.71% of the total file size

Heuristic AV scanning flagged the sample as a variant of [Poison Ivy](https://attack.mitre.org/software/S0012/), a well-documented remote access trojan. The single import, `ExitProcess`, matches Lab03-01, and the string set is nearly identical:

```
ws2_32
CONNECT %s:%i HTTP/1.0
advapi32
ntdll
user32
StubPath
SOFTWARE\Classes\http\shell\open\commandV
Software\Microsoft\Active Setup\Installed Components\
www.practicalmalwareanalysis.com
VideoDriver
WinVMX32-
vmx32to64.exe
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
```

Capa's Malware Behavior Catalog mapping again returned only a process termination capability:

| MBC Objective | MBC Behavior |
| --- | --- |
| PROCESS | Terminate Process |

| Capability | Namespace |
| --- | --- |
| Terminate Process | `host-interaction/process/terminate` |

### Dynamic Analysis

The process did not surface in System Informer's process list during execution, despite generating approximately 334 recorded events spanning DLL loads and registry modifications. The only observed child process was `WerFault.exe`, Windows' error reporting handler, confirming the sample crashed during execution rather than exiting cleanly. As with Lab03-01, this crash limited the ability to capture the full runtime behavior, and remaining conclusions are inferred from the combination of static evidence and the small window of dynamic activity captured before failure.

### Assessment

Lab03-03.exe is a distinct binary from Lab03-01.exe, but the two share a near-identical string set, import table, and HTTP `CONNECT` beaconing and Active Setup persistence behavior, strongly suggesting they belong to the same malware family or build lineage. The AV heuristic detection of Poison Ivy RAT on this sample adds useful context that was not available from Lab03-01 alone, indicating both samples align with known Poison Ivy tradecraft, including the use of `vmx32to64.exe` as a masquerading filename. The crash encountered during dynamic analysis again limited full behavioral confirmation, so this assessment leans on the strong static overlap between the two samples.

## Lab03-04.exe

### Static Analysis

- **File type:** PE32, 60 KB, C/C++
- **Entropy:** 5.22 overall, 6.31 in `.text`
- **SHA256:** `6ac06dfa543dca43327d55a61d0aaed25f3c90cce791e0555e3e306d47107859`
- **Compile timestamp:** Tue Oct 18 18:46:44 2011 (UTC)
- **Sections:** `.text` accounts for 66% of the file

Of 87 total imports, PEStudio flagged 27. These break down into clear functional groups:

**Networking**
```
recv, send, shutdown, socket, closesocket, connect,
gethostbyname, htons, WSAStartup, WSACleanup
```

**Service manipulation**
```
CreateServiceA, ChangeServiceConfigA, DeleteService,
OpenSCManagerA, OpenServiceA
```

**Process and file manipulation**
```
CreateProcessA, CreatePipe, ShellExecuteA, CopyFileA,
DeleteFileA, VirtualAlloc, WriteFile, ReadFile, CreateFileA
```

**Environment and registry**
```
GetEnvironmentStringsA/W, SetEnvironmentVariableA,
RegCreateKeyExA, RegDeleteValueA, RegSetValueExA, RegOpenKeyExA
```

Recovered strings point directly to a command-and-control protocol built around a small instruction set:

```
CMD
DOWNLOAD
UPLOAD
SLEEP
NOTHING
GET
HTTP/1.0
http://www.practicalmalwareanalysis.com
cmd.exe
/c del
Manager Service
SOFTWARE\Microsoft \XPS
```

**Key finding:** the registry path `SOFTWARE\Microsoft \XPS` contains an unusual space between "Microsoft" and the trailing backslash. This is almost certainly a deliberate typosquat of the legitimate `SOFTWARE\Microsoft\` hive path, intended to make the key blend in during a quick visual review of the registry.

FLOSS also recovered a decoded string, `LRqw/wsXe.u4B`, which does not resemble readable configuration data and is likely an encoded C2 parameter, key, or campaign identifier.

Capa's analysis confirmed a broad and coherent capability set:

| Capability | Namespace | Address |
| --- | --- | --- |
| Create service | `host-interaction/service/create` | `0x402600` |
| Modify service | `host-interaction/service/modify` | `0x402600` |
| Delete service | `host-interaction/service/delete` | `0x402900` |
| Persist via Windows service | `persistence/service` | `0x402600` |
| Connect / create TCP socket, act as TCP client | `communication/socket/tcp` | `0x401640`, `0x40169B` |
| Send data on socket (3 matches) | `communication/socket/send` | `0x401790`, `0x401870`, `0x401AF0` |
| Receive data (2 matches) | `communication` | `0x4019E0`, `0x401AF0` |
| Query environment variable (2 matches) | `host-interaction/environment-variable` | `0x402600`, `0x402900` |
| Self delete | `anti-analysis/anti-forensic/self-deletion` | `0x402410` |
| Timestomp file | `anti-analysis/anti-forensic/timestomp` | `0x4014E0` |

The combination of service persistence, TCP client communication, self-deletion, and timestomping in a single sample indicates a mature, purpose-built backdoor rather than a simple downloader.

### Deeper Code Analysis

`OpenSCManagerA` is called requesting `SC_MANAGER_ALL_ACCESS` (`0xF003F`), which per the [OpenSCManagerA documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera) opens the local `SERVICES_ACTIVE_DATABASE` with full administrative control over service objects:

```nasm
004026cc    SC_HANDLE eax_3 = OpenSCManagerA(
004026cc        lpMachineName: nullptr,
004026cc        lpDatabaseName: nullptr,
004026cc        dwDesiredAccess: 0xf003f)
```

`RegCreateKeyExA` is used to write to the `SOFTWARE\Microsoft \XPS` key identified above, confirming the space-padded path is used programmatically and not a transcription artifact from analysis.

Further into the binary, a handle-duplication and shell-selection pattern was identified consistent with building a remote shell over a socket:

```nasm
004032fd    if (DuplicateHandle(
004032fd        hSourceProcessHandle: eax_2,
004032fd        hSourceHandle: *((&data_40f080)[eax_10 >> 5] + ((eax_10 & 0x1f) << 3)),
004032fd        hTargetProcessHandle: eax_2,
004032fd        lpTargetHandle: &targetHandle,
004032fd        dwDesiredAccess: 0, bInheritHandle: 1,
004032fd        dwOptions: DUPLICATE_SAME_ACCESS) != 0)
00403308        CloseHandle(hObject: *(esi_4 + (&data_40f080)[eax_4]))

...
004033bd    char* eax_25 = sub_404c82("COMSPEC")
004033fb    label_4033fb:
004033fb        char const* const eax_28 = "command.com"
00403400        if ((data_40eb70:1.b & 0x80) == 0)
00403402            eax_28 = "cmd.exe"
```

This shows the sample resolving the `COMSPEC` environment variable to locate the system shell, defaulting to `command.com` on older systems or `cmd.exe` otherwise, and duplicating pipe handles so that shell input and output can be relayed back over the established C2 socket. This is a textbook implementation of an interactive remote shell.

### Dynamic Analysis

Execution produced the following confirmed artifacts:

- Registry values written under `AppCompatFlags\Compatibility Assistant\Store` and under `Services\bam\State\UserSettings`, both consistent with normal Windows process-execution tracking rather than malicious persistence in themselves, but useful as forensic evidence the binary ran
- Prefetch file created: `C:\Windows\Prefetch\LAB03-04.EXE-39A8DF5D.pf`
- Self-deletion executed via `"C:\Windows\System32\cmd.exe" /c del C:\Users\micro\Desktop\Lab03-04.exe >> NUL`

No outbound network connections were captured directly during this analysis run, which is notable given the strong static evidence of TCP client functionality. This is most likely explained by the sample's C2 domain being unreachable in the analysis environment, causing the socket logic to fail silently before the self-deletion routine executed regardless.

### Assessment

Lab03-04.exe is a full-featured backdoor combining service-based persistence, an interactive remote shell, a compact C2 command set (`CMD`, `DOWNLOAD`, `UPLOAD`, `SLEEP`), and multiple anti-forensic techniques. The self-deletion behavior and timestomping capability indicate the author prioritized post-execution cleanup, and the deliberately malformed `SOFTWARE\Microsoft \XPS` registry path shows attention to blending in with legitimate system configuration. Compared to the earlier samples in this lab, this binary represents a significantly more mature and complete implant.

## Summary Comparison

| Sample | Type | Size | Persistence | C2 Mechanism | Notable Techniques |
| --- | --- | --- | --- | --- | --- |
| Lab03-01.exe | EXE | 7 KB | Active Setup registry key | HTTP `CONNECT` beacon | Minimal import table, crashes on execution |
| Lab03-02.dll | DLL | 23.5 KB | Windows service (`IPRIP` / "INA+") | Not directly observed | Service masquerading inside `svchost.exe -k netsvcs` |
| Lab03-03.exe | EXE | 7 KB | Active Setup registry key | HTTP `CONNECT` beacon | Identical hash to Lab03-01; AV-flagged Poison Ivy RAT |
| Lab03-04.exe | EXE | 60 KB | Windows service via `CreateServiceA` | TCP socket, custom CMD/DOWNLOAD/UPLOAD/SLEEP protocol | Remote shell via `cmd.exe`, self-deletion, timestomping |

Across all four samples, a consistent theme emerges: registry-based or service-based persistence paired with masquerading, whether through filenames like `vmx32to64.exe`, service names like `IPRIP`, or subtly malformed registry paths like `SOFTWARE\Microsoft \XPS`. Lab03-04.exe stands out as the most capable sample in the set, and its behavior likely represents the more complete payload that Lab03-02's service installer was designed to deploy and protect.