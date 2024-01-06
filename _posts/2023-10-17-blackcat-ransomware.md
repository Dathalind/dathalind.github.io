---
title: BlackCat Ransomware
date: 2023-10-17 10:00
categories: [analysis, security, ransomware]
tags: [blackcat, ransomware, analysis]
---

# Overview

Blackcat Ransomware is a ransomware-as-a-service threat who's origin is believed to be a Russian speaking cybercrime group. In this post, we examine a sample from this malware family.

## Static Analysis

### [VirusTotal](https://www.virustotal.com/gui/file/0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479)

Hash: `0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479`

### Detect It Easy

![Blackcat DetectItEasy](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/blackcat/blackcatdetectiteasy.png?raw=true)
This binary is a 32-bit Portable executable that is packed, `7.1115` entropy.

### PE Studio
`67` flagged imports, Cryptography is flagged as a library with this binary. DEP, CFG, ASLR are on.

### Floss
Interesting strings (sites defanged):

- hxxps://github.com/clap-rs/clap/issues
- /cargo/registry/src/github.com-1ecc6299db9ec823/indexmap-1.7.0/src/map/core/
- other odd strings: uespemosarenegyl
- Initializing Networking Routine
- Trying to remove shadow copies
- Waiting for kills to complete
- Shutdown Routine
- Dropping Note and Wallpaper Image
- src/bin/encrypt_app/app.rs
- `hxxp://zujgzbu5y64xbmvc42addp4lxkoosb4tslf5mehnh7pvqjpwxn5gokyd.onion/b21e1fb6-ff88-425b-8339-3523179a1e3e/886cf430a907bbe9a3fd38fb704d524dbd199c1b042ad6f65dc72ad78704e21\\n\\n\\n`
- Message about key: hxxp://mu75ltv3lxd24dbyu6gtvmnwybecigs5auki7fces437xvvflzva2nqd.onion/?access-key=${ACCESS_KEY}
- :`"Important files on your system was ENCRYPTED.\nSensitive data on your system was DOWNLOADED.\nTo recover your files and prevent publishing of sensitive information follow instructions in \"${NOTE_FILE_NAME}\" file.”`
- "default_file_cipher":"Best","credentials":[["KELLERSUPPLY\\Administrator","d@gw00d"],["KELLERSUPPLY\\AdminRecovery","K3ller!$Supp1y"],[".\\Administrator","d@gw00d"],[".\\Administrator","K3ller!$Supp1y"]]
- rebroadcast_cache_to=
- locker::core::clustersrc/core/cluster.rs
- broadcasting=
- 127.0.0.1:

![Blackcat FlossStrings](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/blackcat/blackcatstrings.png?raw=true)

![Blackcat PEStudioStrings](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/blackcat/blackcatpestudio.png?raw=true)

## Dynamic Analysis

### ProcMon
After initial execution, it didn’t encrypt any files. We will try killing it to see if it changes anything. No interesting files were written to the host.

- Restoring, doing regshot again. 
- Running as admin on the process. No inetsim.
- Wireshark is only detecting certain ICMP requests for Microsoft related sites. Restarting the VM does not appear to show any changes.
- No `currentversion\run` keys; no startup or runonce. Nothing sticks out as something interesting from regshot. Rebooting.
- Reboot shows no visible difference. Ran `FakeNet-NG`, not seeing any suspicious or malicious connections with this tool either.

### TCP View
![Blackcat TCPView](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/blackcat/blackcattcpview.png?raw=true)

We restarted the VM after letting the file execute. This is done to see if anything changes after the restart. 

- Still no sign of the drive being encrypted.

- We couldn’t get things to run because the ransomware is using an `access-token` to prevent analysis. There are references to such above in the strings that were extracted. However, if we `supply any string`, it allows us to actually activate the binary and initiate the ransomware.

### Files Encrypted
Now it executed, encrypted data on the host, dropped the files and changed the wallpapper. We rebooted to ensure it is still there. 
- `cat.exe --child --verbose --access-token cats1234 —paths C:\Users`
- Does not work as propogated.
    -  You have to specify a file path to propogate through, looks like it finally worked with sending as a child process, then it encrypts files, giving them a `.sykffle` file extension
- `RECOVER-sykffle-FILES.txt` on Desktop with image, ransomware note.

![Blackcat EncryptionMessage](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/blackcat/blackcatencryptedmessage.png?raw=true)

> Back to ProcMon:
>> Using Procmon, we see some additional things firing off from wmic and fsutil.exe; also conhost.exe and git.exe.
>> - wmic csproduct get UUID
>> - fsutil behavior set SymlinkEvaluation R2L:1 & fsutil behavior set SymlinkEvaluation R2R:1
>> - git --no-pager config cmder.cmdstatus
>> - Upon reboot, files should be encrypted. Seems like it is inconsistent. Need to find the write command set to get things encrypted right away. 
>> - looks like you should run the app with the access token separately, then run whatever commands you want as a separate command, doesn’t appear to be a UI.

## Advanced Static Analysis

### Ghidra & Cutter
Entry point, has a few functions for us to check out, lets see about following the first jump point.

- HeapFree, 3 pushes before this call.

## Advanced Dynamic Analysis

### x32dbg
After loading, we hit entry point. Then, Virtual protect.

- only 2 hits on that, then it exits the application.
- value was 01
- We changed it to 0, but didn’t help anything.
- looks like we may need a specific key in order to get things to run correctly
### Yara Rule
```java
rule black_cat_ransom{
    
    meta:
        last_updated = "2023-07-12"
        author = "Dathalind"
        description = "Rule for BlackCat Ransomware"

    strings:
        $string1 = "uespemosarenegyl" ascii
        $string2 = ".onion" ascii
        $string3 = "Important files on your system was ENCRYPTED" ascii
        $MZ_Header = { 4D 5A }
        $string4 = "BCryptGenRandom" ascii
        $string5 = "svssadmin.exe delete shadows /all /quietshadow_copy::remove_all" ascii

    condition:
        $MZ_Header at 0 and 
        ($string1 and
        $string2 and
        $string3 and
        $string4 and
        $string5)
}
```