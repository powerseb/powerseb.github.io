---
title: Read memory dumps without a cat
author: powerseb
date: 2023-06-10 00:00:00 +0800
categories: [Windows, PowerShell, RedTeam]
tags: [LSASS, Windows, PowerShell]
render_with_liquid: false
img_path: /assets/img/2023-06-10/
---


The aim of this article is to provide an insight in the most hidden secrets of the hacker world and the inner workings of their most holy tools or maybe it is just an article how to read and parse LSASS memory dumps. 

## TL;DR

A powershell based tool to parse LSASS dumps [PowerExtract](https://github.com/powerseb/PowerExtract.git).


## Digging in Memory for what?

Before we get out hands dirty (and minds twisted) - the first questions is why we are doing this? 

Yeah that is a good question. So one step back - when an hacker lands on a target machine (and given it is running windows) one essentials step is the gathering of credentials. Within Windows there are two go-to credentials storages - the local security database (Security Account Manager) and the LSASS process. The logon process and the involved processes is quite good documented from [Microsoft](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

The Security Account Manager (short SAM) database of windows is located within the registry - the SAM hive. This hive holds the credentials for local accounts like the local Administrator. So this could be interessting for Password-Reuse attacks within local networks - but due to the further distribution and usage of LAPS (Local Administrator Password Solution) or other mechanisms this vector becomes more and more unattractive (I am looking at you LocalAccountTokenFilterPolicy).

![SAM Database in authentication process](SAM-1.jpg)

The LSASS process is a different kind of animal - within windows this process regulates the authentication. This means this process is a central hub to handle authentication requests from different services. Because Windows is trimmed to an Single-Sign-On experience this process bundles and structures the authentication flow. This means, within this process different authentication packages are implemented like NTLM, Kerberos, WDigest etc. Further this process handles and stores currently used credentials for those credential packages. So quite complex, valuable and fully stuffed with interessting stuff - the perfect target for hackers. So the LSASS process holds various credentials of the current windows session (of all identities which are logged on).

![LSASS process in authentication process](LSASS-1.jpg)

So when we want to compromise a whole active directory infrastructure we need network credentials - which are (usally) stored in the LSASS process. 

And here comes a little kicker - the secrets in the registry database can be extracted offline from the hard disk of the system. In contrast the name LSASS PROCESS already implies it only holds sensitive information during the runtime of Windows. 

So by now it should be clear the LSASS process is a very valuable target so how we get in (or the valuable things out)? - Yeah that is an essential question so currently two main paths are known to do that:

- live - the process will be touched during the runtime (usally with debug priveledges) and the secrets extracted - to most popular tool for this method is [Mimikatz](https://github.com/gentilkiwi/mimikatz.git). In my personal experience this way is usally very noisy and is easly detected by various Antivirus and EDR solutions (additionally you may also face the issue how you execute [Mimikatz](https://github.com/gentilkiwi/mimikatz.git) on your target).
- memorydumps - for this method the LSASS process will be dumped. This means the full content of the process will be written to a single file. This resulting dump file  contains the secrets. Sure this method raises also some eyebrows for the AV and EDR - depending on the method but is usally more successful than trying to execute [Mimikatz](https://github.com/gentilkiwi/mimikatz.git) and touching the live process.

So because of the title of this article we focus on the second method (and also the first method is a little bit more complex) - so let´s start digging!

![Lets go](Start-dig.jpg)

## Can you read that? 

We established why we want to read lsass memory dumps - so how we do that?

Further due to my personal ambition and will to suffer - can we do that with onboard Windows tools (ideally PowerShell)? 

To be able to read something we need to understand how the data we want to read is structured - in our case small memory dumps. By now I have not found a nice (and simple) picture which would explain the internal structrue of memory dumps there I tried to paint one on my own: 

![Minidump structure](minidmp-1.jpg)

Now to understand the structure better here are some explanations: 

- Header - the file starts with a header which contains basic information about the file like Version, Timestamp etc. The relevant information for further analysis is the "NumberOfStreams" and the "StreamDirectoryRVA". The rest of the data is organized in different "streams" which contain various types of information (e.g. Systeminformation, Credentials etc.).
- Directories - So for each Stream (indicated by the NumbersOfStreams) we want to parse, we need to identify the type of the stream, the start and end address. This provides us with a table of content for our memory dump. 
- Stream - Now we can parse every available stream based on the indicated type. This means when the streamtype "7" is identified, this is mapped to the "SystemInfoStream" and therefore the Streamdata need to be parsed with the corresponding template.

Within the dump there are multiple Streams - to get what we want (reminder - hashes) we "only" require the following streams:

- ThreadListStream: Contains information about the threads running at the time of the dump, including thread IDs, stack traces, and register values.
- ModuleListStream: Provides information about the loaded modules (DLLs and executables) in the process address space, including module names, base addresses, sizes, and file paths.
- MemoryInfoListStream: Contains information about the memory regions with additional details like allocation base.
- ThreadInfoListStream: Stores thread state information.
- SystemInfoStream: Provides general system information at the time of the dump, such as the operating system version, processor architecture, and other system-specific details.
- Memory64ListStream: Similar to the MemoryListStream, but provides extended information for 64-bit memory addresses.

Based on the documentation from [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_stream_type)

This gives us a rough understanding of the structure. Now - how we read? 

![Read it](Read-it.jpg)

As mentioned personally I wanted to do it with PowerShell. So in PowerShell there are multiple methods how to read files - I experimented with things like "Get-Content" etc. but this lead to a high memory usage and makes the navigation quite difficult. I had the best results with "System.IO.FileStream" which provides an direct access to the raw file content. Combined with the method "System.IO.BinaryReader" we are able to read the content of the file byte wise which is exactly the level of detail we require. 

```powershell
$PathToDMP = "C:\Temp\lsass.dmp"

$fileStream = New-Object –TypeName System.IO.FileStream –ArgumentList ($PathToDMP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
$fileReader = New-Object –TypeName System.IO.BinaryReader –ArgumentList $fileStream
$fileReader.BaseStream.Position=0
$Signature = ([System.BitConverter]::ToString($fileReader.ReadBytes(4))).replace('-','')
...
```

So now we know what we want to read and how we can read the file byte wise with PowerShell - the result is shown in picture below. This enables us to parse the different streams according to their documentation.

![PowerShell reading](read-ps1.jpg)

Let's start the extraction of the jucy parts.

![Delicous](Delicous.jpg)

## Credential Extraction 

Before we start with the fancy memory stuff we should focus on what we want to extract. As explained at the beginning the LSASS process is quite complex and contains multiple credential packages. So there is not one central credential storage for everything in reality each credential package hold its own credentials. So we need to deceide with which package we want to start - and because the article is already quite long we take the easy package - the logonpasswords (kerberos is a little bit more complicated). 

![MSV in authentication process](msv1_0.jpg)

The credential package which holds the logonpasswords is called "MSV1_0".

Fortunatly credentials are not stored in cleartext - they are encrypted so we need to aquire the crypto material to ensure that NT hashes, passwords etc. can be decrypted. 

### First things first

So where to find the crypto material? - This is the neat part the required keys are also stored within the LSASS process and therefore within the dump. So how we can find it?

Here Microsoft became creative - because where the keys are stored depends on the windows version, lsasrv.dll version and the underlying systemarchitecture. Therefore we need to know which systemversion the lsass dump was created - you remember the different streams we parsed? - Great here we can extract the relevant information from the "SystemInfoStream". This stream contains the "ProcessorArchitecture" and the "Buildnumber".

![Systeminfostream](systeminfo.jpg)

Further we need to extract the Timestamp of the "lsasrv.dll" from the "ModuleListStream".

![LSASRV version](lsasrv.jpg)

With this gahtered information we can select the correct crypto template. This template defines certain patterns and offset to identify the crypto material within the memory structure and differs between windows versions.

The following listing shows an example crypto template:

```powershell
Pattern    : 8364243000488D45E0448B4DD8488D15
AES-Offset : 16
IV-Offset  : 58
DES-Offset : -89
key-handle : Get-BCRYPT_HANDLE_KEY
key-struct : Get-BCRYPT_KEY81
```

The template consists of a Pattern which is basically the starting point for all following operations - so we need to find this pattern first. The cryptographic material of the lsass process is runtime data - this means it is changed after every reboot (yeah I know I pointing out the obvious). So where we search for this pattern? - Do you remember the following picture?

![lsasrv dll](lsasrv-dll.jpg)

Yes the central instance for credential management (for credentials packages like "MSV1_0") is the "lsasrv.dll". Within this dll also the crypto material is stored. The "ModuleListStream" provides us with the start and end address of this module in memory. So we know the area where to search the specified pattern. 

![Pattern in memory](pattern.jpg)

After aquireing the Address of the pattern we can start with the different parts of the crypto material. The IV, DES and AES key are independed from each other. So if we first aquire the IV or the DES key is not relevant so here a short wrap up:

- IV - the steps to extract the IV are - we need to add the IV-offset to the address where the pattern has been identified. There we need to extract 4 bytes - which is a pointer to IV data. Now we need to add the IV-offset, the extracted pointer and 4 bytes to the address of the pattern - and there we have it the IV. 

![IV Pointer](IVPointer.jpg)

![IV](IV.jpg)

- DES / AES - the procedure for DES and AES key is the same (but with different offsets) - so we start again by adding the offset to the pattern address. This brings us again to a pointer where we extract 4 bytes. Within the next step we add the extracted pointer and the offset to the pattern address which brings us to the key handle. The handle is a little special because this is the starting point of an additional structure we need to parse (in my script i called it a BCRYPT_HANDLE_KEY). During the parsing of this structure we are able to extract a pointer - which brings us to the key structure. Also here different kinds of structures can be applied to parse the key data (you may notice the "key-struct" entry in the crypto template). Depended which key structure is provided by the template, it is applied with the extracted key pointer which will finally result in the key.

![Key Pointer](AES-DES-Pointer.jpg)

![Key](AES-DES-Key.jpg)

Here an example of the result:

```powershell
DESKey : 1CD7CCC70EA46FAA77DE8F592695A71A454A20F425A0758A
IV     : 2AF4C45FD1786BA8D237DA9166E51CF5
AESKey : 48FE7A5E250B8336F51C4E1BA51AF879
```

Great so now we have aquired the crypto stuff now we get some hashes or? 

![Easy?](Easy-right.jpg)

### NT-Hashes 

Before it is raining hashes - we need to find them. To identify where those are stored we need to remind us - ok we want the logon passwords and how those are handled by the LSA process? 

Basically the credentials are initially provided by the Winlogon process and sent to the LSA process. Here the LSA process calls the MSV1_0 credential package to process those. The MSV1_0 package compares the credentials to those in the internal SAM database (the registry hive) or sends them by use of the netlogon protocol to a domain controller. Therefore (and according to the [Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) documentation) this credential package also holds the logon credentials during the runtime of the system. 

![msv process](msv1_0-process.jpg)

So we need to identify the MSV1_0 credential package within the memory dump - for this we follow a simular process as we did for the crypto material. Currently I am not aware of an official documentation of how this can be done therefore I used [Pypykatz](https://github.com/skelsec/pypykatz.git) and [Mimikatz](https://github.com/gentilkiwi/mimikatz.git) as a reference to do that. So both tools are working with patterns and offsets (like for the crypto material) - here an example of a template which can be used to identify the entry positions for the MSV1_0 credential package:

```powershell
Pattern                : 33FF4189374C8BF34585C074
SessionNo              : -4
FirstEntry             : 23
ParsingFunction        : Get-MSV1_0_LIST_63
CredParsingFunction    : Parse-PrimaryCredential-Win10-1607
```

So as you may recall from the crypto stuff we start with searching of the pattern within the memory dump. A specialty of the MSV package is that the pattern is located in the lsasrv.dll and not in the msv1_0.dll. 
When we identified the pattern address we are able to extract the number of logonsessions and receive the addresses of the MSV entries.

For now we focus on the MSV entries - to receive those we add the FirstEntry offset to the pattern address. This gives us a Pointer - when we add that to the pattern address and the FirstEntry offset we receive an address where the address of the first entry is stored. So when we extract the first address we can directly jump to the next entry which is stored 8 bytes next to the first entry. So we can read the full list of entries by just jumping always to the next 8 bytes until the memory stream shows 8 bytes of "0". 

![MSV first entry](MSV-Fst.jpg)

![MSV structures](MSV-entries.jpg)

This sets the starting point of the NT hash extraction - we parse the MSV entries

#### MSV Parsing

MSV entries a little special structure - as you may already noticed they also differ between the windows versions - so for each version we have separate template. Additionally the entries are organized as a linked list which means we exam the MSV structure until we reach the beginning again. Within an MSV entry various information is available - for us our main focus is the "Primary Credential" structure. Within this the encrypted credentials are stored. 

So when we parse the MSV entry according to the selected template we are able to extract the encrypted credentials. 

%BILD%

#### Hash extraction

Finally we are there we have an encrypted blob of something - great. So the decryption mechanism is as far as I know not officially documented - beside the tools [Mimikatz](https://github.com/gentilkiwi/mimikatz.git), [Pypykatz](https://github.com/skelsec/pypykatz.git) or other. By looking at those tools we can identify that the primary credentials of the MSV structures are encrypted with a 3DES Key and IV (I know obvious because the crypto stuff is already named like that...). When we apply the extracted Key and IV we receive ... the NT Hash! 

![NTHash](NTHash.jpg)

Awsome - and all that within PowerShell so without any other tools - so all of it is executed within memory and (currently) not flagged by any AV or EDR (besides the memory dump maybe)

## Wrapping it up

With that you have everything you need to create your own LSASS dump parser in PowerShell - if you don´t want (and there are some very good reasons like mental health) to you can also use mine from here [PowerExtract](https://github.com/powerseb/PowerExtract.git). I hope you learned something during the articel about the inner workings of some security tools. Further we are not done here - this was the boring stuff within the next article we explore kerberos - which is way more complicated and where i gained a super power during the development - read of hex encoded kerberos tickets (maybe not super useful but we will see) - so stay tuned :) 

PS: Because no cat was involved in the parsing of this LSASS dump (and because my boss will not greenlight this post without a cat) - here a cat:

![cat](cat.jpg)
