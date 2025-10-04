---
title: LetsDefend - SOC104 - EventID 36
date: 2025-10-04
categories: [analysis, security, malware]
tags: [malware, obfuscated code, analysis]
---

# Overview
SOC104 - EventID 36 is a practice challenge on the letsdefend.io site. These challenges are designed to test a defender's ability to spot and investigate malicious activity based on the initial information you are given, and then you run a playbook to do additional investigation and analysis on the logs you are able to search through. Based on whether it is malicious, you then proceed with the rest of the playbook to contain and remediate the potential threat in this scenario. 

## Initial Triage
To begin in the investigation, you are given a handful of data points which are good to note down and keep for reference:

* Source Address: `10.15.15.18`
* Source Hostname: `AdamPRD`
* File Name: `Invoice.exe`
* File Hash: `f83fb9ce6a83da58b20685c1d7e1e546`
* File Size: `473 KB`
* Device Action: `Allowed`

As we can note right away, we can see this file was allowed to be on the device and execute. Assuming this device has an AV engine, it would have bypassed this engine in its execution and would have potentially run malicious code on the Host `AdamPRD`. We can do a quick VirusTotal search to determine this file is clearly malicious, but lets save that for the end and perform the other analysis steps first.

## Log Analysis
Doing a quick search on the Source IP `10.15.15.18`, we can see a proxy connection likely from Firewall logs, where we have a Destination IP `92.63.8.47` with a Port `443`. Due to the destination port, this is likely web related traffic, so if this file is malware, this is likely a C2 connection on the web. The log also indicates a URL: `http://92.63.8.47/`

## Case Management
Running the playbook, we need to confirm that we have outbound traffic, indicating the malware is not currently remediated. We also need to pivot over to the Endpoint Security section and determine if the host is network isolated. If its not, we should isolate it from the network to ensure the infection is not given a chance to spread to additional devices. 

* You would normally do this action on a workstation, but if this is a server, in a real environment, there are more considerations to factor before you isolate a server from the network. 

> We already confirmed there is a potential C2 connection doing a log analysis.
>> We can see this Host AdamPRD is not current contained. We should push containment on this device after we confirm this is malware.
>> Checking out VirusTotal results, this is malware, and appears to be [Maze Ransomware](https://www.virustotal.com/gui/file/e8a091a84dd2ea7ee429135ff48e9f48f7787637ccb79f6c3eb42f34588bc684).
>> We have confirmed ransomware, so we push containment on the Host, and continue the playbook confirming this is malicious. 
>> Based on the previous log analysis, we can see this site was accessed. 
>> We can add all the artifacts of our investigation for this Case. 

## Closing The Case
Once we have the playbook finalized, we can now close the case, and confirm this file is malicious. We indicate this is a `True Positive`, and can now resolve this case. If you submit this in this way, you should see a result of `Correct Answer`. If you correctly identified all the steps in the playbook, you should have 5 points for each correct answer. 