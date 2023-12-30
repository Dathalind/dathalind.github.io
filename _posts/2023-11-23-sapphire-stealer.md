---
title: Sapphire Stealer
date: 2023-11-23 12:00
categories: [analysis, security, stealer]
tags: [analysis, security, sapphire]
---

# Overview

Sapphire Stealer is an Open Source information stealer, observed across multiple repositories. The purpose of this information stealer is to steal browser data and other data in files, and then export this data to a telegram bot. In this blog, a sample of this stealer malware will be analyzed. 

# Static Analysis

### [VirusTotal](https://www.virustotal.com/gui/file/f70651906b9cbf25b3db874e969af7a14caac21bf1db328e4664db54566a15b0)
Hash: `f70651906b9cbf25b3db874e969af7a14caac21bf1db328e4664db54566a15b0`

## Detect It Easy
This file is a Portable Executable 32-bit, .NET linker type of file, with a high level of entropy at 7.98.

![DetectItEasy](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/detectiteasysapphire.png?raw=true)

## Floss

Interesting strings grabbed with Floss.exe: 

- costura.costura.dll.compressed; reference to a add-in capable of embedding dll’s into exe’s
- Telegram.BotAPI
- GetUserData
- BCRYPT api calls
- DecryptPassword
- get_password
- set_password
- get_StackTrace
- FileStream
- DeflateStream
- MemoryStream
- Browser\User Data
- sapphire\ by barion @dark_legion89

## PeStudio

Library:

- bcrypt.dll

.NET namespaces:

- System.net.http
- System.net.mail
- System.security.cryptography
- System.io.compression
- Ionic.zip
- Ionic.zlib
- Costura

31 flagged imports:

![PeStudio](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/pestudiosapphire.png?raw=true)

Has a copyright and file version. Sapphire.exe, 1.0.0.0, Copyright 2022.

# Dynamic Analysis
Right when it executes, command prompt comes up right away, and a screenshot was taken of the desktop. 

![executionerrors](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/sapphireerrorexecution.png?raw=true)

## ProcMon

We see a huge amount of processes execute, conhost.exe and werfault.exe ran in conjunction.

- We also see multiple files being read and the program copying the data from the files. We also see that the program is looking for sapphire related processes. 

- Log file written to path: `C:\Users\dath\AppData\Local\Temp`

## RegShot

Shows over 20,000 keys deleted. Don’t see any persistence added.

## Wireshark

Seems to be http Get requests related to pulling down a specific certificate:

- `hxxp://ocsp.digicert.com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBT3xL4LQLXDRDM9P665TW442vrsUQQUReuir%2FSSy4IxLVGLp6chnfNtyA8CEAQJGBtf1btmdVNDtW%2BVUAg%3D`

We can also see the call to telegram api:

![telegramapi](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/wiresharktelegramapicallssapphire.png?raw=true)

We also see post requests made to update.googleapis.com: 

![postrequests](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/wiresharkpostrequests.png?raw=true)

Checking to see if anything is new after restart. Nothing new.

After doing some debugging, there seems to be a set of errors that prevent this malware from running correctly:

![moreerrors](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/errorsduringdebugsapphire.png?raw=true)

# Advanced Static Analysis

Due to this malware created in C# language, we can analyze this file through using a tool called "dnSpy."

## dnSpy

Inside of the code, we can see more references to the costura and the Fody, confirms the use of this compression. Gives us the versions used.

We can see an important reference to stealing user data, function “GetUserData”.

- There is a boolean operation here, where it checks for certain directory browser path’s existing, and if they do exist, the function will return true.
- It also checks if the text contains the word “Profile”, and will add it to a list of data.

![userdata](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/dnspystealuserdatasapphire.png?raw=true)

There is a Dictionary that is checking for multiple types of Browsers, huge list of different browsers. 

* So now we see the Main function under the Sapphire namespace.

> Sapphire has 5 classes:
>>  - Format: seems to be setting up to retrieve data and have it formatted in a specific way when stealing
>> - Paths: this class seems responsible for the stealing of data by running through a list of browser data to check for
>> - Program: contains the main function to execute the different operations
    >>> seems to be a bug, may need to add a line of code to get this to actually call the password stealing: `loginData.AddRange(Passwords(p.Value, p.Key));`

![mainfunction](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/dnspymainfuncsapphire.png?raw=true)

> The main program appears to go in this order:
>> - Grabbing browser data, saving to a text file and ready to be added to an archive folder.
>> - Grabbing a screenshot of the current machine.
>> - Grabbing files, creating a directory to store those files for extraction, specifically targeting .txt, .pdf and .doc files to copy their contents.
>> - Creates an archive and uses compression in order to hide what is being put in the archive.
>> - Sending a log of the data extracted about the machine.
>> - Telegram extraction, uploading data to the specified telegram bot.
>> - Deleting the archive created earlier as part of cleanup.

> SendLog: appears to be the class ready to create a log of certain data on the machine, but not the browser data; seems to be after IP data, Username, screenshot, OS version, GPU, etc.

![SendLog](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/dnspydataextractionsapphire.png?raw=true)

> Telegram: this seems to be the main method of extraction from the device, upload to a telegram bot, has specific  data referenced to which botClient to send data to. 
>> There also seem to be built in functions set up to decrypt saved passwords from the machine. 

![Upload](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/sapphire_stealer/dnspytelegramsapphire.png?raw=true)