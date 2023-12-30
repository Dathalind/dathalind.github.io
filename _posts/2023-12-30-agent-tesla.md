---
title: Agent Tesla
date: 2023-12-30 10:00
categories: [analysis, security, stealer]
tags: [analysis, security, agent-tesla]
---

# Overview
Agent Tesla is a remote access trojan (RAT) that is often associated with phishing attacks. Due to its increased flexibility, it has seen a lot of use by threat actors. In this page, we break down some of the techniques used in the compilation of the malicious executable. 

#  Static Analysis

### [VirusTotal](https://www.virustotal.com/gui/file/7f7323ef90321761d5d058a3da7f2fb622823993a221a8653a170fe8735f6a45)
Hash: `7f7323ef90321761d5d058a3da7f2fb622823993a221a8653a170fe8735f6a45`

## DetectItEasy

File is a 32-bit portable executable, identified as a .NET linker file. 

- Not super high levels of entropy, 6.41799 overall. Different sections are not packed either, highest capping at 6.42465

![DetectItEasy]() 

## Floss
Lots of strings, some seemingly base64 strings contained inside, other interesting strings:

- IEnumUnkno.exe; likely original file name
- Welcome traveler! What is your name?
- Please enter a valid name.
- TaskStart
- DebuggerNonUserCodeAttribute
- CreateDirectory
- System.Resources
- System.IO

There seems to be some fake checks for a valid username, and some string references to gear items for a RPG type of game.

## PEStudio
Indicators page flags the compiler timestamp, as being 2065 as the year this was compiled. We see original file name “IEnumUnkno.exe”.

No flagged imports. 

We do see some other interesting strings flagged, camo casing:

- CMd
- arP
- URL pattern: 16.0.0.0

One library: mscoree.dll

# Dynamic Analysis

Done with multiple tools; Wireshark, ProcMon, RegShot, TCPView, InetSim. 

## Wireshark
Wireshark is capturing a lot of requests, need to drill down to find any interesting packets. The get and post http requests I see are either related to Microsoft or Google; nothing helpful or interesting there. Same for the DNS requests, nothing out of the ordinary.

## ProcMon
Looks like we can see this running locally. Looks to be grabbing browser data, likely to try and exploit it. Seems to be checking for a lot of different browser types. Didn’t really see it write any interesting files. We could revert and try to look for the original file name. 

## RegShot
Took first shot before execution. Now after a good amount of time has passed, we are taking the second shot. Then running the comparison. Huge number of changes, almost 200,000 registry changes. Nothing immediately standing out as interesting. Not seeing any persistence mechanisms via registry.

## InetSim
Enabled on Remnux box, ensure your windows box is using that box IP for its DNS. Stopped inetsim, Tesla.exe still on box. Doesn’t appear to have a check to ensure constant sustained internet connection. 

## TCPView
Check for any weird connections we can see locally. Nothing interesting. 

- Going to restart to see if there is anything interesting that happens upon restart. Nothing interesting.

# Advanced Static Analysis

Done with using a common decompiler for C# code, dnSpy. 

## dnSpy

Different section names are obfuscated as random characters, will take some digging around to find the main functions of the program. 

- Class wocfI2D05srfZBaCuI.iSyUEjkWDhXhlElyN3:
    - this class appears to be tracking certain files and contains methods to verify those files exist
    - contains other methods to which there appear to be lines tracking the fake Game contents; level, xp, basehealth, gold, etc.
- Namespace reURv8uvvybnkNvJNUv
    - appears to be used for tracking player items
- Namespace Ot68Ruub1p0fnheGXAy appears to contain the methods to display the fake title for the game
- Namespace os5WmYFcANvHTSukje
    - method iARGDbDs5; has some interesting code, big block of what looks to be a large string text
    - contains 4D5A at the start, it is a PE, contained with some unicode bytes
    - perhaps it will pull this out and decode it later in execution?
    - There is additional obfuscation for it, which it does a replace of the code block “@\u200c” for “000”.
- Namespace olDHtbgqTWwIPBKQWn
    - this contains some different methods, where it references a lot of unicode bytes that just are for adding a space “\u0020”
- Namespace fjM9JnK3XjjvimtWCg
    - contains methods that could be used as a way to stop debugging this executable
- We renamed some namespace to help get a better sense of what is going on, it is still mostly a mystery, with there being some of these methods only related to the game stuff that is garbage, but we have the interesting unicode stuff
- Part way through the process running, we are able to see some things start to unpacked, another park of Tesla.exe unpacks into an obfuscated name “kSXxsUeGsLjOjKcVpywguppkUCja”
    - From here, we see 2 new name spaces that look interesting, `“<PrivateImplementationDetails>{96CF4D0F-AB06-44C3-B8C6-95BF0E0250D0}”` and “A”
    - If reading this correctly, this appears to be a loop for the length of the element `“E531F780-6F11-40DE-8643-19357D9410BE.<<EMPTY_NAME>>”`, to pass bytes into this placeholder
- Looking at namespace A with internal class “b”, we see some more interesting functions here
    - inside of internal class “b”, we also see a call to have the application run “Application.Run();”
    - dll imports of user32 and ntdll, it is grabbing some user input
    - Further down in the code, we see a long sleep for 1000, followed by the next section which appears to enumerating data from the user device
    - the function b() appears to be set up to execute httpwebrequests, grabbing a credential cache, and is looking for a response stream
- When asking for the program entry point, it is going to namespace “H8ByT4o9A2rvy7R3kC”, class “NUSpMfsvFIoS6G7cAh”
- Additionally, we have some steganography being utilized, where it contains a packed image inside of the Resources page “Game.Properties.Resources.resources”, 331739 bytes
- under namespace A, class C, we see some encryption metehods used and the CipherMode ECB, with PaddingMode PKC57
    - this appears to be the encryption/decryption methods being utilized to pull the data out
- class “D 0x0200000F” under namespace “A” has additional windows api calls to create hooks at the entry point of the program
- class AccountConfiguration appears to be very interesting, looks to be stealing data from the host such as account name, avatar, creation time, and possibly password stealing
- class MailAccountConfiguration
- class MailAddress
- class SmtpAccountConfiguration

# Advanced Dynamic Analysis

Debugging inside of dnSpy. 

While doing some debugging inside of dnspy, we see some references to the place where the packed PE is contained `“Application.Run(new ETUso0QLpeOnaYARDb());”`

This is reached shortly after coming to the entry point. Seems to be tricky to be able to step through with a debugger, but the main operation appears to be unpacking the PE contained in the main part of the first file, to then utilize some scrapping on the host for browser and email data to extract. 