---
title: Kernel Shield - Malops.io Windows Kernel Driver Analysis
date: 2026-10-15
categories: [analysis, security, malware, lab]
tags: [analysis, security, lab]
---

## Overview

This write-up covers the Malops.io driver challenge built around `NSecKrnl64.sys`, a small, unpacked, signed Windows kernel driver. The analysis is **static only**. Findings are presented as conclusions supported by the cited evidence, and anything that relies on background knowledge rather than the artifacts is explicitly marked as unverified.

**Key findings**

- The driver exposes `\\.\NSecKrnl` to user mode and handles four IOCTLs. One of them (`0x2248e0`) **terminates an arbitrary process by PID** using a kernel-mode handle.
- Only a non-NULL buffer check is visible in the dispatcher. No caller validation was observed.
- The driver also protects selected processes by stripping `PROCESS_TERMINATE` through an `ObRegisterCallbacks` pre-operation callback (altitude `328987`).
- During `DriverEntry` it ORs `0x20` into a loader entry field at offset `0x68`, a known technique for allowing `ObRegisterCallbacks` to succeed without `/INTEGRITYCHECK`.
- The combination of a user-reachable kill primitive and a valid signing chain fits the profile of a **BYOVD (bring your own vulnerable driver) "EDR killer" primitive**. This does not prove malicious intent by the vendor.

## Sample Fingerprint

| Attribute | Value |
|---|---|
| File | driver_challenge (NSecKrnl64.sys) |
| Size | 25,056 bytes (24.47 KB) |
| MD5 | `80961850786d6531f075b8a6f9a756ad` |
| SHA1 | `b0b912a3fd1c05d72080848ec4c92880004021a1` |
| SHA256 | `206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261` |
| Type | PE64, x64, native subsystem, Windows 10 64-bit kernel driver |
| Compiler | MSVC 19.25 / VS2019 16.5, likely C |
| Compile time | 2020-04-27 08:13:11 UTC |
| Entry point | RVA `0x9000` (INIT section, GS stub leading to `DriverEntry` at `0x14000114c`) |
| Version info | NSEC Co.,Ltd / NSecKrnl / 3.7.40.5314 |
| Copyright | (C) 2020 NSEC. All Rights Reserved. |
| PDB | `D:\NSecsoft\NSec\NSEC-Client-Kernel\Drivers\NSecKrnl\NSecKrnl\bin\NSecKrnl64.pdb` |
| Signer | Shandong Anzai Information Technology CO.,Ltd, business ID 91370100306819342R (DigiCert EV, valid 2020-04-28 to 2021-03-22) |
| Counter-signature | 2020-05-13 (DigiCert timestamp) |
| Certificate format | WinAuth 2.0 PKCS #7 |
| Microsoft chain | Windows Hardware Compatibility Publisher (WHCP) present in the signature blob |

> Signature validity was **not** verified (`python-signify` was not installed). The checksum matches the header value.

## Static Analysis

### Packing and Section Review

Entropy for the file overall is 6.53693, and no section layout suggests packing. The entry point sits in the discardable `INIT` section, which is expected for a driver. No RWX sections and no high-entropy sections were observed.

| Section | Entropy | Note |
|---|---|---|
| .text | 5.48 | Normal code |
| INIT | 4.96 | Normal. Entry point `0x9000` is in this discardable init section, as expected for a driver |
| .rdata | 2.90 | Normal |
| .rsrc | 2.84 | Normal |
| .pdata | 1.64 | Normal |
| .data | 0.28 | Virtual size 16,432 vs 512 raw: zero-initialized space that backs the two 1024 x 8-byte PID arrays (see Q6) |
| .reloc | 0.26 | Normal |

The low-entropy `.data` section is explained by its layout. The raw size is tiny but the virtual size is large, consistent with uninitialized storage for the tracking arrays rather than hidden payload data.

### Imports and API Chains

Imports are limited to `ntoskrnl.exe`. Grouping them by purpose shows a compact and coherent driver design.

| Stage | APIs |
|---|---|
| **Setup** | `RtlInitUnicodeString`, `IoCreateDevice`, `IoCreateSymbolicLink` |
| **Kill** | `PsLookupProcessByProcessId`, `ObOpenObjectByPointer`, `ZwTerminateProcess`, `ZwClose`, `ObfDereferenceObject` |
| **Monitor** | `PsSetCreateProcessNotifyRoutine`, `PsSetLoadImageNotifyRoutine` |
| **Protect** | `ObRegisterCallbacks`, `PsProcessType` |
| **Cleanup** | `IoDeleteSymbolicLink`, `IoDeleteDevice`, `ObUnRegisterCallbacks`, `PsRemoveLoadImageNotifyRoutine` |

Other imports support the design: `KeAcquireInStackQueuedSpinLock` and `KeReleaseInStackQueuedSpinLock` (table locking), `IoGetCurrentProcess`, `PsGetCurrentProcessId`, `PsGetProcessId`, `IofCompleteRequest`.

There are **no imports for networking, file system, registry or crypto operations**, which limits what the driver can do on its own.

### capa and FLOSS Results

- capa matched *create device object*, *terminate process*, *find process by PID* (T1057), *complete asynchronous IO request*, *contain loop* and *contains PDB path*.
- capa matched **find process by PID** and **terminate process** within the same function at `0x1400013E8`, which is the kill handler analyzed below.
- capa did not cover IOCTL dispatch, process protection callbacks or BYOVD behavior, so those required manual analysis in Binary Ninja.
- FLOSS static strings surfaced the PDB path, the device and symlink names, and the UTF-16LE string `328987` next to them. No decoded or stack strings were found.

### Signing and Provenance

The PDB path, version info, internal naming and clean compile metadata all point to a conventional commercial build from a Chinese security vendor. The signing chain contains a real EV certificate and a WHCP signature.

**A null view is worth stating.** The sample may be a legitimate driver that is being repurposed, so the vendor branding should not be treated as evidence of intent. Signed, legitimate-looking drivers are exactly what BYOVD abuse relies on.

## Code Analysis

All function names below are Binary Ninja auto-names (`sub_<address>`), with roles inferred from the code.

### DriverEntry (`sub_14000114c`)

```nasm
14000114c    NTSTATUS sub_14000114c(DRIVER_OBJECT* arg1)
140001152        void* DriverSection = arg1->DriverSection
140001165        *(DriverSection + 0x68) |= 0x20
140001169        data_140003018 = 0
140001171        UNICODE_STRING var_28
140001171        RtlInitUnicodeString(DestinationString: &var_28, SourceString: sub_1400016f0)
140001183        UNICODE_STRING var_18
140001183        RtlInitUnicodeString(DestinationString: &var_18,
140001183            SourceString: u"\DosDevices\NSecKrnl")
140001196        arg1->MajorFunction[0] = sub_140001010
14000119f        arg1->MajorFunction[2] = sub_140001010
1400011b2        arg1->MajorFunction[0xe] = sub_140001030
1400011c0        arg1->DriverUnload = sub_1400010e0
```

In order, `DriverEntry`:

1. **Tampers with its own loader entry** (`Flags |= 0x20`) before registering anything. See Q2 and Q3.
2. Zeroes the spinlock global (`data_140003018`).
3. Creates `\Device\NSecKrnl` (type `0x22`, non-exclusive, no security descriptor) and the symlink `\DosDevices\NSecKrnl`, reachable from user mode as `\\.\NSecKrnl`.
4. Builds the dispatch table: CREATE (0) and CLOSE (2) go to `sub_140001010` (completes the IRP), DEVICE_CONTROL (`0xE`) goes to `sub_140001030`, and `DriverUnload` is `sub_1400010e0`.
5. Registers the process-create notify routine (`sub_140001480`), the image-load notify routine (`_guard_check_icall`, effectively a no-op), and then calls `sub_140001518` to register the object callback. The callback registration occurs at `140001233`, after the flag tamper, which fits the expected ordering.

Creating the device with no security descriptor and `Exclusive = 0` is relevant to exposure: whether unprivileged users can open the device depends on the default device ACL, which still needs dynamic confirmation.

### IOCTL Dispatch (`sub_140001030`)

```nasm
140001030    uint64_t sub_140001030(int64_t arg1, IRP* arg2)

140001049        int64_t* MasterIrp = arg2->AssociatedIrp.MasterIrp
14000104d        int32_t rdi = -0x3fffffff
140001052        int32_t r8 = *(arg2->Tail.Overlay.__offset(0x40).q + 0x18)

14000105d        if (r8 == 0x2248d4)
1400010af            if (MasterIrp != 0 && sub_1400012b8(*MasterIrp) != 0)
1400010bb                rdi = 0
14000105d        else
140001063            char rax_1

140001063            if (r8 == 0x2248d8)
140001098                if (MasterIrp != 0)
14000109d                    rax_1 = sub_140001614(*MasterIrp)
1400010a2                label_1400010a2:

1400010a4                    if (rax_1 != 0)
1400010a6                        rdi = 0
140001063            else if (r8 == 0x2248dc)
140001087                if (MasterIrp != 0)
14000108c                    rax_1 = sub_140001240(*MasterIrp)
140001091                    goto label_1400010a2
140001069            else if (r8 == 0x2248e0 && MasterIrp != 0)
14000107b                rax_1 = sub_1400013e8(*MasterIrp)
140001080                goto label_1400010a2

1400010c0        arg2->IoStatus..Status = rdi
1400010c6        IofCompleteRequest(Irp: arg2, PriorityBoost: 0)
1400010dd        return zx.q(rdi)
```

| IOCTL | Function # | Handler | Role |
|---|---|---|---|
| `0x2248d4` | `0x235` | `sub_1400012b8` | List operation (unverified) |
| `0x2248d8` | `0x236` | `sub_140001614` | Removes a PID from the array at `data_140003030` (confirmed by code) |
| `0x2248dc` | `0x237` | `sub_140001240` | List operation (unverified) |
| `0x2248e0` | `0x238` | `sub_1400013e8` | **Kill process by PID** (confirmed) |

All four use `METHOD_BUFFERED` and `FILE_READ_ACCESS`. The input is a 64-bit value dereferenced from the system buffer, most likely a PID. The dispatcher defaults to `0xC0000001` and only sets success when the matching handler reports success.

### Kill Path (`sub_1400013e8`)

The termination sequence is:

1. `PsLookupProcessByProcessId` resolves the PID to a `PEPROCESS` and takes a reference.
2. `ObOpenObjectByPointer` opens a handle with `HandleAttributes = 0x200`, `DesiredAccess = 1` (`PROCESS_TERMINATE`) and `AccessMode = KernelMode`.
3. `ZwTerminateProcess(handle, STATUS_SUCCESS)` ends the process.
4. `ZwClose` closes the handle.
5. `ObfDereferenceObject` releases the reference taken in step 1.

> **Key finding:** The handle is opened from kernel mode, so the driver's own object callback does not restrict it. Combined with the missing caller validation, any process that can open `\\.\NSecKrnl` and send this IOCTL can terminate any process it names, including protected security processes. Standard user-mode protections such as protected process light are not consulted by a `ZwTerminateProcess` call made this way.

### Object Callback (`sub_140001518` and `sub_1400014b0`)

```nasm
140001518    {
140001518        int64_t (* const var_58)() =
140001518            PsProcessType;
14000153e        int64_t var_50 = 3;
14000154f        int64_t (* var_48)(int64_t arg1,
14000154f            void* arg2) = sub_1400014b0;
14000155d        int64_t var_40;
14000155d        __builtin_memset(&var_40, 0, 0x30);
140001565        int128_t CallbackRegistration;
140001565        (uint32_t)CallbackRegistration =
140001565            0x10100;
14000156c        RtlInitUnicodeString(
14000156c            (uint128_t*)((char*)
14000156c                &CallbackRegistration + 8),
14000156c            u"328987");
140001576        int128_t var_28;
140001576        *(uint64_t*)((char*)&var_28 + 8) = 0;
140001581        int64_t (* const* var_18)() = &var_58;
140001589        NTSTATUS result = ObRegisterCallbacks(
140001589            &CallbackRegistration, &data_140003020);
14000158f        int64_t rcx_2 = data_140003020;
14000158f
140001598        if (result < STATUS_SUCCESS)
140001598            rcx_2 = 0;
140001598
1400015a4        data_140003020 = rcx_2;
1400015b0        return result;
140001518    }
```

The registration uses version `0x100`, one operation registration, `ObjectType = PsProcessType`, `Operations = 3`, pre-operation callback `sub_1400014b0`, and altitude `328987`. The handle is stored in `data_140003020`.

The pre-operation callback clears `PROCESS_TERMINATE` (mask `0xfffffffe`) from the requested `DesiredAccess` only when **all** of these hold:

1. The caller is not the target process (`IoGetCurrentProcess() != Process`).
2. The target PID is found by `sub_14000138c` (likely the protected list).
3. The caller PID is **not** found by `sub_140001330` (likely the trusted list).

This is a self-protection design: protected PIDs cannot be terminated by ordinary callers, while trusted callers (presumably the vendor's own components) are exempt. Which IOCTL populates which list was not confirmed.

## Challenge Questions

### Summary

| Q | Question (short) | Answer |
|---|---|---|
| 1 | Name exposed to user mode | `NSecKrnl` |
| 2 | Value OR'd into loader entry field | `0x20` |
| 3 | Byte offset of tampering | `0x68` |
| 4 | IOCTL for forced process termination | `0x2248e0` |
| 5 | NTSTATUS for unrecognized IOCTL or NULL buffer | `0xC0000001` |
| 6 | Capacity of each tracking array | `1024` |
| 7 | Callback altitude | `328987` |
| 8 | HandleAttributes when opening a process to kill | `0x200` |
| 9 | Embedded PDB filename | `NSecKrnl64.pdb` |
| 10 | Device type constant | `0x22` |
| 11 | Stride between IOCTL codes | `4` |
| 12 | API for the current process pointer (self-check) | `IoGetCurrentProcess` |
| 13 | Registration handle value after unregister | `0` |
| 14 | Combined operation flag value | `3` |
| 15 | API that releases the process reference | `ObfDereferenceObject` |
| 16 | Size of the image-load callback (hex) | `0x3` |
| 17 | DriverUnload handler address | `0x1400010e0` |

### Q1. Name exposed to user mode

**Answer:** `NSecKrnl`

The name appears in the "Name" field in Exeinfo PE. It is also consistent with the device path `\Device\NSecKrnl` and symlink `\DosDevices\NSecKrnl` in `DriverEntry`.

![Exeinfo PE showing the driver name](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/kernelshield/exeinfo.png?raw=true)

### Q2. Value OR'd into the loader entry

**Answer:** `0x20`

Start from the `_start` subroutine and pivot to the subroutine it returns, `sub_14000114c` (`DriverEntry`). The references to the `DriverSection` variable at the top of this function reveal the operation:

```c
*(uint32_t*)((char*)DriverSection + 0x68) |= 0x20;
```

`(char*)DriverSection + 0x68` moves forward `0x68` bytes from the start of the structure, and `*(uint32_t*)` treats those four bytes as a 32-bit integer. `|= 0x20` reads the current value, sets bit 5 and writes it back, leaving the other bits unchanged.

`DriverSection` is the loader data table entry, and `+0x68` is its `Flags` field. Bit `0x20` is the one `MmVerifyCallbackFunction` checks, so setting it lets `ObRegisterCallbacks` succeed without the image being linked with `/INTEGRITYCHECK`. This runs as the first action in `DriverEntry`, before the driver registers anything.

> **Unverified:** the field name `Flags` and the `MmVerifyCallbackFunction` behavior come from public technique knowledge, not from the artifacts. Confirm with `dt nt!_KLDR_DATA_TABLE_ENTRY` and `uf nt!MmVerifyCallbackFunction` in a kernel debugger. The value `0x20` and offset `0x68` are directly observed.

### Q3. Byte offset of the tampering

**Answer:** `0x68`

Same line as Q2: `(char*)DriverSection + 0x68`.

### Q4. IOCTL that forces process termination

**Answer:** `0x2248e0`

`sub_140001030` is the IOCTL dispatch routine. Look for a switch or chain of `==` comparisons, where the constants are the IOCTL codes. In the routine, `r8` holds `IoControlCode`, read from `*(IO_STACK_LOCATION + 0x18)`. The branch `r8 == 0x2248e0` calls `sub_1400013e8(*MasterIrp)`, which is the function capa matched for both *find process by PID* and *terminate process*.

**Decoding `0x2248e0` (CTL_CODE layout)**

| Field | Value | Meaning |
|---|---|---|
| Device type | `0x22` | `FILE_DEVICE_UNKNOWN`, matching the type passed to `IoCreateDevice` |
| Access | `FILE_READ_ACCESS` | Callers need only read access to the handle |
| Function number | `0x238` | Fourth in the `0x235` to `0x238` sequence |
| Method | `METHOD_BUFFERED` (0) | Consistent with the code reading `AssociatedIrp.MasterIrp` (the system buffer) |

References: [IoCreateDevice](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice), [Specifying device types](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types).

`FILE_READ_ACCESS` is a low bar. Combined with no security descriptor on the device, this matters for how easily the kill IOCTL can be reached.

### Q5. NTSTATUS for unrecognized IOCTL or NULL buffer

**Answer:** `0xC0000001`

At the top of `sub_140001030`, `rdi` is initialized to `-0x3fffffff`. Converted to an unsigned 32-bit value, that is `0xC0000001`, which the [NTSTATUS documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) lists as `STATUS_UNSUCCESSFUL`.

`rdi` is only set to `0` inside the success paths, which are the matching IOCTL cases where `MasterIrp != 0` and the helper returns nonzero. An unrecognized IOCTL falls through every `else if` without touching `rdi`. A NULL `MasterIrp` skips the handler branch, so `rdi` is also untouched. The final value is written to `IoStatus.Status` and returned.

### Q6. Capacity of each tracking array

**Answer:** `1024`

Check `sub_140001240`, `sub_1400012b8` and `sub_140001614` for a loop with a constant limit (for example `cmp ecx, 0x400`, or a pointer compared to a base plus `0x2000`). Evidence from `sub_140001614`:

1. The loop runs `while (rax.d u< 0x400)`, scanning indices 0 to 1023, which is `0x400` = 1024 entries.
2. The stride is 8 bytes (`rdx_1 = &rdx_1[1]` on an `int64_t*`, and `rax << 3` for indexing), so one array occupies 1024 x 8 = 8192 bytes (`0x2000`).
3. The array base is `data_140003030`, with the spinlock at `data_140003018` (which is why `DriverEntry` zeroed it).

This also explains the large virtual size of `.data`. The fixed size is a design limit worth noting: only 1024 PIDs can be tracked per list.

### Q7. Callback altitude

**Answer:** `328987`

The import list showed `ObRegisterCallbacks`, `ObUnRegisterCallbacks` and `PsProcessType`, which suggested a handle-operation callback registration. The workflow was:

1. `ObRegisterCallbacks` takes an [`OB_CALLBACK_REGISTRATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) structure, which includes an `Altitude` `UNICODE_STRING`.
2. FLOSS static strings contained the UTF-16LE string `328987` at offset 2848, next to `\DosDevices\NSecKrnl` and `\Device\NSecKrnl`. Its numeric format fit an altitude, so it became the working hypothesis.
3. In Binary Ninja, the function at `0x140001518` passes that string through `RtlInitUnicodeString` into the `Altitude` field (offset `+8`) of the registration structure, then calls `ObRegisterCallbacks`. See the listing in the Object Callback section.

> **Unverified:** that `328987` falls inside the Microsoft anti-virus altitude range (320000 to 329998) is background knowledge. If true, it would mean the driver registers at an altitude associated with security products, which is notable for a process-protection driver.

### Q8. HandleAttributes when opening a process to kill

**Answer:** `0x200`

The handle is opened with [`ObOpenObjectByPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer), which appears in the imports and in capa's chain for this function. `HandleAttributes` is its second argument, and the value passed is `0x200`, which is `OBJ_KERNEL_HANDLE`. A kernel handle cannot be used or inspected from user mode.

### Q9. Embedded PDB filename

**Answer:** `NSecKrnl64.pdb`

The FLOSS ASCII string at offset 3664 is the full path `D:\NSecsoft\NSec\NSEC-Client-Kernel\Drivers\NSecKrnl\NSecKrnl\bin\NSecKrnl64.pdb`. The `RSDS` signature sits just before it at offset 3640, which marks the CodeView debug record that holds the PDB path. capa independently matched *contains PDB path* (regex `:\\.*\.pdb`) at file offset 3664 and captured the same path. Two tools agree on both the offset and the content.

### Q10. Device type constant

**Answer:** `0x22`

Pivoting off the `IoCreateDevice` import leads to `DriverEntry`:

```c
IoCreateDevice(arg1, 0, &var_28, 0x22, 0, 0, &DeviceObject);
```

Per the [documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice), the fourth argument is the device type, and `0x22` is `FILE_DEVICE_UNKNOWN`. The remaining arguments are `DeviceExtensionSize = 0`, `DeviceCharacteristics = 0` and `Exclusive = 0`.

### Q11. Stride between IOCTL codes

**Answer:** `4`

The four codes are `0x2248d4`, `0x2248d8`, `0x2248dc` and `0x2248e0`. Each is 4 more than the previous one (`0xd8 - 0xd4 = 4`, and so on). The stride is 4 because the function number occupies bits 2 to 13 of the code, so consecutive function numbers (`0x235` to `0x238`) differ by 4 in the full value.

### Q12. API for the current process pointer

**Answer:** `IoGetCurrentProcess`

The condition `IoGetCurrentProcess() != Process` is the self-check in the object callback. `Process` is `*(arg2 + 8)`, which is `OperationInformation->Object` (the target `PEPROCESS`). If the caller is the target, the whole condition fails and the callback returns `0` without changing anything. `PsGetCurrentProcessId` is used later in the same condition, but for the table lookup rather than the pointer comparison. Reference: [IoGetCurrentProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentprocess).

### Q13. Registration handle value after unregister

**Answer:** `0`

In `sub_140001674`, if `data_140003020` (the registration handle) is nonzero, the function calls `ObUnRegisterCallbacks(RegistrationHandle)` and then sets `data_140003020 = 0`. The `!= 0` guard confirms `0` is the "not registered" sentinel, matching the failure path in the registration function at `0x140001518`.

### Q14. Combined operation flag value

**Answer:** `3`

In the registration function at `0x140001518`, the operation registration sets `var_50 = 3`. That field is `Operations`, and it combines two flags:

- `OB_OPERATION_HANDLE_CREATE` = 1
- `OB_OPERATION_HANDLE_DUPLICATE` = 2

1 + 2 = 3, so the callback intercepts both handle creation and handle duplication on `PsProcessType`. Monitoring duplication as well as creation closes the obvious gap where an attacker obtains a handle indirectly.

### Q15. API that releases the process reference

**Answer:** `ObfDereferenceObject` ([documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obdereferenceobject))

In `sub_1400013e8`, after `ZwClose`, the function runs `Object = Object_1; if (Object != 0) ObfDereferenceObject(Object)`. `Object_1` is the `PEPROCESS` returned by `PsLookupProcessByProcessId`, which takes a reference on the process, and `ObfDereferenceObject` releases it. It is also in the import list, and capa matched it as the optional part of the *find process by PID* rule at `0x140001464`.

### Q16. Size of the image-load callback

**Answer:** `0x3`

Pivot from [`PsSetLoadImageNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine) and follow the registered routine to `_guard_check_icall`. The disassembly shows a single instruction, `c2 00 00` (`retn 0x0`), which is 3 bytes: opcode `c2` plus a 16-bit immediate `00 00`.

```nasm
140001000    void _guard_check_icall(void (* arg1)())
140001000      __pure
140001000  c20000             retn    0x0 {__return_addr}
```

This is a Control Flow Guard stub, so the registered image-load callback does nothing. The capability is effectively unused, although we did not confirm whether other code consumes `data_140003011`.

### Q17. DriverUnload handler address

**Answer:** `0x1400010e0`

In `DriverEntry` (`sub_14000114c`), the assignment `arg1->DriverUnload = sub_1400010e0` gives the address directly (see the listing in the DriverEntry section).

## Assessment

### Hypotheses

| # | Hypothesis | Confidence | Status |
|---|---|---|---|
| H1 | Driver terminates arbitrary processes by PID on user-mode request | High | Supported: IOCTL `0x2248e0` leads to `PsLookupProcessByProcessId`, `ObOpenObjectByPointer` (kernel handle), `ZwTerminateProcess`. Only a non-NULL buffer check is visible. Device ACL reachability still to test dynamically |
| H2 | Legitimate vendor endpoint or anti-cheat style driver, not purpose-built malware | Medium | Consistent with PDB path, version info, EV and WHCP signing. Abuse as BYOVD remains possible |
| H3 | Driver protects processes via `ObRegisterCallbacks` by stripping `PROCESS_TERMINATE` | High | Confirmed in code (`sub_1400014b0`) |
| H4 | Driver monitors process creation and image loads | Medium | Process-create notify registered (`sub_140001480`, not yet read). Image-load callback is a no-op stub |
| H5 | Spinlock-protected PID tables: protected list and trusted caller list | High | Two 1024-entry arrays implied. Which IOCTL fills which array is unverified |
| H6 | No data theft, network, persistence or evasion logic in the driver | Medium (null-leaning) | No such imports, no decoded or stack strings, no packing |

### Conclusion

`NSecKrnl64.sys` is most consistent with a legitimate process self-protection driver from a security vendor that also exposes an unauthenticated **kill process by PID** primitive to user mode. That combination makes it a strong BYOVD candidate for terminating EDR and AV processes, particularly because it is validly signed. Any malicious behavior would live in a separate user-mode loader or controller, since the driver itself contains no networking, file, registry, persistence or evasion logic.

Whether this exact hash has been abused in the wild was not verified. Check VirusTotal, LOLDrivers and the Microsoft vulnerable driver blocklist.

## Indicators of Compromise

| Type | Value |
|---|---|
| MD5 | `80961850786d6531f075b8a6f9a756ad` |
| SHA1 | `b0b912a3fd1c05d72080848ec4c92880004021a1` |
| SHA256 | `206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261` |
| Device | `\Device\NSecKrnl` |
| Symlink | `\DosDevices\NSecKrnl` (user-mode handle `\\.\NSecKrnl`) |
| IOCTLs | `0x2248d4`, `0x2248d8`, `0x2248dc`, `0x2248e0` |
| Callback altitude | `328987` |
| Signer | Shandong Anzai Information Technology CO.,Ltd (business ID 91370100306819342R) |
| PDB | `NSecKrnl64.pdb` (full path in the fingerprint table) |
| Version | 3.7.40.5314 |
| Inferred, not observed | Service key `HKLM\SYSTEM\CurrentControlSet\Services\NSecKrnl` |

## Detection Opportunities

- **Driver load:** Sysmon Event ID 6 for this hash and signer.
- **Service creation:** a new service named `NSecKrnl`.
- **Device access:** handle opens to `\\.\NSecKrnl` from processes that are not the vendor's software.
- **Loader hunting:** user-mode binaries that call `DeviceIoControl` with the IOCTLs above.
- **Blocking:** add the hash and signer to application control or driver block rules where this vendor's software is not expected.
