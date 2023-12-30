---
title: Fake WinRar
date: 2023-11-11 12:00
categories: [analysis, security, fake-app]
tags: [analysis, security, winrar]
---

# Overview

Threat actors will sometimes modify a known and widely utilized application in order to trick users into downloading something they thought is safe, but contains malicious code. This is often done through uploading to a trusted open repo or can be done through advertising the download on google. In this blog, we examine a sample of Fake-Winrar, which is normally a safe archive unpacking tool that contains malicious code.

# Static Analysis

### [VirusTotal](https://www.virustotal.com/gui/file/eb2723d97df6cf5db266cf6461d0fd63c2c3d686297c9f503ebc24fbd5529d37)

Hash: `eb2723d97df6cf5db266cf6461d0fd63c2c3d686297c9f503ebc24fbd5529d37` 

## PEStudio
PE32, certificate WinAuth2.0, potentially not packed. Overlay & .text are packed.
Data execution prevention, control flow guard, ASLR are enabled.

![PE Studio](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/pestudiowinrar1.png?raw=true)

Only 3 libraries; Interesting version, original file name and copyright info.

## Floss
> Typical error message, attempting to appear to be legitimate winrar.exe.
>> An application has made an attempt to load the C runtime library incorrectly.
>> Please contact the application's support team for more information.

> - Attempt to use MSIL code from this assembly during native code initialization
> This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.
> - not enough space for locale information
> - Attempt to initialize the CRT more than once.
> This indicates a bug in your application.
> - CRT not initialized
> - unable to initialize heap
> - not enough space for lowio initialization
> - not enough space for stdio initialization
> - pure virtual function call
> - not enough space for _onexit/atexit table
> - unable to open console device
> - unexpected heap error
> - unexpected multithread lock error
> - not enough space for thread data
> This application has requested the Runtime to terminate it in an unusual way.
> Please contact the application's support team for more information.
> - not enough space for environment
> - not enough space for arguments
> - floating point support not loaded
> - Microsoft Visual C++ Runtime Library
> - `<program name unknown>`
> - Runtime Error!

## Unusual strings
![Unusual Strings](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/stringswinrar1.png?raw=true)

## Certificates
![Certificates](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/stringswinrar2.png?raw=true)

## UTF-strings
> C:.NET.0.30319.exe 
>> InternalName - AJIfy80xO6tP 

>> LegalCopyright Uganda Telecom Limited (UTL) All rights reserved. LegalTrademarks Uganda Telecom Limited (UTL) Trademarks 

>> OriginalFilename MjrVL53K.exe 

## Digital Signature
![Digital Signature](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/winrardigitalsignature.png?raw=true)

# Dynamic Analysis

## ProcMon
> Written File:
>> C:\Users\dath\AppData\Local\Microsoft\CLR_v4.0_32\UsageLogs\AppLaunch.exe.log

> Child process: 
>> conhost.exe \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1

## RegShot
> Deleted one key: 
>> HKU\S-1-5-21-1248556568-55694383-3693071177-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\JumplistData

>> - no currentverison; startup; 

> Runonce keys value added:
>> HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1248556568-55694383-3693071177-1001\\Device\HarddiskVolume2\Users\dath\Desktop\winrarfake.exe

## Wireshark
Lots of get requests over http traffic, tcp traffic is all garbled up. No post requests as of yet. Seems to be intended to pull down certificates. May have to check and see what this does when executing on the internet. Killed inetsim, the process is still on desktop, will shutdown and see if anything unusual happens.

> Certificate pop-up after reboot: 

![CertPopUp](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/winrarcertpopup.png?raw=true)

Ran process again to see if anything would come up in wireshark. Lets reset and see if Fake-Net picks up anything.

Still not seeing a whole lot, see some DNS requests to microsoft related domains, some ICMP pings.

# Advanced Static Analysis

## Ghidra & Cutter

> Entry: 
>> - Takes you to FUN_00403f2e function - has main function inside at bottom 
>> - FUN_00402160 - converted to the winmain 
>> - Some unusual strings in this location 
>> - `“Y0UsfKyxz3czqSZ9O50fhz6rog” - “2RQTIguQ46XiLms9” - “teLqNO0uYvKpFMesAW9p5OpnNlVZ” - “ZwYo4fCLKuUixSBe3MQTHIG6M2kda9g” - “pWgQQcDcDEFti2IMtb6y” - “Hohq04nEGcHlah” `

![Cutter1](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/fake_winrar/winrarcuttergraph.png?raw=true)

# Advanced Dynamic Analysis

## x32dbg
Set breakpoints, after the system point, we hit entry bp.

- Next we hit virtual Protect
- One run through, we get to Virtual Alloc
    - Memory space is open
    - we follow in dump 1, we see an executable, 0x2220000
- back to virtual protect
    - doesn’t seem to be doing anything interesting yet
    - could be loading or writing data from a dll, different sections
    - hit virtual protect 11 times, nothing interesting, turning off bp
- back to virtual alloc
    - following dump 2, address near the previous, 0x2300000, empty
    - fills up with a bunch of FF’s, nothing interesting
    - seems to be setting up additional memory spaces
    - 0x2301000 is empty still even after going back to VirtualAlloc
    
    At 8 virtual alloc bp’s, we then hit the IsDebugger API
    
    - ran till return, value is 0, should be good to continue
    - back to VirtualAlloc
    - another empty space, 0x2313000
        - dumped some code, possible shellcode
    - more space being allocated
    - small bits of code being spit out to other addresses, scattered
    - is there any more code that is worth looking at with this?
    - 16 bp’s with VirtualAlloc
    
    - Using Process Hacker, we can see the executable has conhost.exe running as child process
    
    - Lets dump the one PE at 0x22200000

## PE-Bear
- May have dumped this one too early, won’t let me override a section
- Still seems incomplete

After turning off bp for Virtual Alloc, we let process run.

- So far, hanging in the process running with a specific dll; diasymreader.dll
- The process doesn’t proceed any further

## Yara Rule
```java
rule fake_winrar{
    
    meta:
        last_updated = "2023-07-08"
        author = "Dathalind"
        description = "Rule for a fake winrar executable"

    strings:
        $GetCurrentProcess = "GetCurrentProcessId" ascii
        $VirtualProtect = "VirtualProtect" ascii
        $FakeError = "<program name unknown>" ascii
        $MZ_Header = { 4D 5A }
        $OriginalFileName = "MjrVL53K.exe" wide ascii
        $Fake_Signer = "Python Software Foundation" ascii

    condition:
        $MZ_Header at 0 and 
        ($GetCurrentProcess and
        $OriginalFileName and
        $Fake_Signer and
        $VirtualProtect and
        $FakeError)

}
```