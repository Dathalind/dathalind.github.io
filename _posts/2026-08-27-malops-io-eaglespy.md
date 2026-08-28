---
title: EagleSpy - Malops.io Android RAT Analysis
date: 2026-08-27
categories: [analysis, security, malware, lab]
tags: [analysis, security, lab]
---

## Overview

This write-up documents the analysis of an Android sample identified as **EagleSpy**, a remote access trojan (RAT) distributed through a dropper application. This challenge was completed on [Malops.io](https://malops.io). Unlike the desktop PE samples covered in the *Practical Malware Analysis* series, this lab required Android-specific tooling, primarily [JADX](https://github.com/skylot/jadx) for decompiling the APK and reviewing the `AndroidManifest.xml`.

The sample follows a two-stage delivery model: an initial dropper application performs environment checks and requests the permissions necessary to sideload a second-stage payload, which then masquerades as a legitimate government application to establish persistence and a command-and-control (C2) channel.

### Sample Summary

| Attribute | Value |
|---|---|
| Package ID | `com.appd.instll.load` |
| Entry point class | `splash` |
| Permissions declared | 4 |
| Second-stage payload SHA256 | `799A3D9663BB9C26C3CFE68ED2C8E35C657AC3EDF969825DC83F2C5812F96429` |
| Trojanized application impersonated | VNeID |
| C2 address | `103.253.23.8:7773` |
| Connection key | `EagleSpy` |

## Static Analysis

### AndroidManifest.xml

Every Android application defines its essential structures and metadata, including declared permissions, components, and entry points, within `AndroidManifest.xml`. This file was the starting point for identifying the sample's package identity and declared capabilities.

The package ID for this sample is `com.appd.instll.load`, a name designed to blend in with legitimate installer or loader utilities rather than draw attention as malicious.

### Declared Permissions

The manifest declares four permissions:

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
<uses-permission android:name="android.permission.REQUEST_DELETE_PACKAGES"/>
```

**Key observation:** the combination of `REQUEST_INSTALL_PACKAGES` and `REQUEST_DELETE_PACKAGES` is a strong early indicator of dropper behavior. Legitimate applications rarely need the ability to both install and remove other packages on the device; this pairing suggests the app's primary function is to manage the lifecycle of a second-stage payload rather than provide any user-facing functionality of its own.

### Entry Point

The main activity used as the application's entry point is a class named `splash`. JADX's built-in navigation made this straightforward to confirm, as it links directly to the activity declared as `MAIN`/`LAUNCHER` in the manifest. Using a generic name like `splash` is a common technique to avoid drawing suspicion during casual code review, since splash screens are a standard pattern in legitimate Android development.

## Behavioral Analysis

### Environment and Installation Checks

Before proceeding with its payload delivery routine, the sample performs a check to determine whether a specific application is already present on the device. This logic lives in the `isAppAvailable` method within the `splash` class. Note that `isAppAvailable` is the sample's own validation method, not a direct Android API call; it wraps the underlying package manager query used to test for the presence of another app.

The package name checked by this method is `com.found.hentai`. The use of an adult-content-themed package name as a checkpoint is consistent with a distribution model where this dropper is bundled with or disguised as pirated or adult content, a common lure for this class of Android malware.

### Locale Targeting

The sample also queries the device's default language via calls to `getLanguage()`. Reviewing the branching logic around these calls shows the sample targets **six languages**, evaluated through a series of additional `case` statements. This kind of locale-aware branching is typically used to tailor social-engineering prompts, C2 configuration, or payload selection to the victim's likely region, and its presence here indicates the operators are targeting more than a single geographic market.

### Dynamic Permission Requests

To install the next-stage payload, the sample dynamically requests two permissions at runtime through a call to `requestPermissions`, rather than relying solely on manifest-declared permissions:

- `WRITE_EXTERNAL_STORAGE`
- `READ_EXTERNAL_STORAGE`

Requesting these at runtime, in addition to their manifest declaration, ensures the app has the storage access needed to write the embedded payload to disk immediately before installation, while also satisfying Android's runtime permission model on newer OS versions.

### Payload Delivery

The second-stage payload APK is embedded directly within the application and loaded from the `assets` directory of the package resources, rather than being downloaded from a remote server at this stage. Embedding the payload locally reduces the dropper's reliance on network infrastructure during the initial install phase and avoids generating network traffic that could be flagged before the payload is even installed.

The extracted payload has a SHA256 hash of:

```
799A3D9663BB9C26C3CFE68ED2C8E35C657AC3EDF969825DC83F2C5812F96429
```

### Second-Stage Payload: Impersonation of VNeID

Analysis of the second payload's `resources.arsc` file, specifically `res/values/strings.xml`, reveals that the application is designed to impersonate **VNeID**, a legitimate government identity application. String values such as `MyName` and `CopyRights` directly reference VNeID branding, and further references to this string are used throughout the payload's UI and metadata. This impersonation strategy is intended to lend legitimacy to the malware in the eyes of the victim and to lower suspicion once the app is installed and running, since it appears to be an official government utility.

### Persistence

To maintain access to the compromised device across reboots, the payload's utilities class registers a receiver for the `RECEIVE_BOOT_COMPLETED` permission. This allows the malicious component to relaunch automatically when the device restarts, without requiring any further user interaction, ensuring continued access even if the victim reboots or powers off the device.

## Further Code Analysis

### Command-and-Control Configuration

Locating the method responsible for establishing the C2 connection led to a search for the `ClientHost` field, which resolves to a decoded C2 address of:

```
103.253.23.8:7773
```

In the same location, a `ConnectionKey` field decodes to the string `EagleSpy`, which both identifies the malware family and likely serves as an identifier or campaign tag used by the C2 infrastructure to distinguish this build or operator instance from others using the same panel.

### JSON Encryption

Communication between the malware and its C2 server is not sent in plaintext. Searching for `cipher.getInstance` (and cross-referencing against the `SECRET_KEY` field) identified the encryption scheme used to protect the JSON payloads exchanged with the C2 server. The secret key used for this encryption and decryption is:

```
93b89a273c1fbe59073af7bd9adfa6c0
```

This key is used symmetrically, meaning it both encrypts outbound telemetry/command responses and decrypts inbound commands from the operator, consistent with typical AES-based configuration obfuscation seen in commodity Android RATs.

## Additional Findings

- **RAT family context:** the decoded `ConnectionKey` value of `EagleSpy` aligns with a known, publicly documented Android RAT family that circulates in underground forums. Builders for this family typically expose the C2 host, port, and connection key as configurable fields, which is consistent with the discrete, easily located configuration values recovered during this analysis.
- **Layered social engineering:** the sample combines two distinct impersonation techniques, first posing as a generic loader/installer utility (`com.appd.instll.load`) to gain initial installation, then posing as a trusted government identity application (VNeID) once the second-stage payload is deployed. This layered approach is designed to survive scrutiny at two separate points in the infection chain.
- **Minimal manifest footprint by design:** the first-stage dropper deliberately limits its declared permissions to four, only what is strictly necessary to check for an existing app and manage package installation/removal. The bulk of the sample's surveillance and C2 capability is deferred to the second-stage payload, which likely declares a much broader permission set once installed under the guise of VNeID.

## Assessment

This sample demonstrates a fairly standard, but effective, two-stage Android RAT delivery chain. The first-stage dropper is intentionally lightweight, limiting itself to environment checks, locale detection, and the permissions required to sideload a second payload from its own assets. The real capability, remote access, persistence via `RECEIVE_BOOT_COMPLETED`, and encrypted C2 communication over a hardcoded IP and port, is deferred to the second-stage payload, which impersonates a legitimate Vietnamese government identity application (VNeID) to maintain the appearance of legitimacy post-installation.

The recovered C2 address (`103.253.23.8:7773`), connection key (`EagleSpy`), and AES secret key (`93b89a273c1fbe59073af7bd9adfa6c0`) provide concrete indicators of compromise that could be used for network-based detection or blocklisting, while the `com.found.hentai` package check and six-language locale targeting offer useful context on the sample's intended distribution vector and victim geography.