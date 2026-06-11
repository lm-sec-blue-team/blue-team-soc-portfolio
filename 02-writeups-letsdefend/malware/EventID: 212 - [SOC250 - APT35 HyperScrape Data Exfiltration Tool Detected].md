## Initial Info
- EventID :212
- Event Time : Dec, 27, 2023, 11:22 AM
- Rule : SOC250 - APT35 HyperScrape Data Exfiltration Tool Detected
- Level : Security Analyst
- Hostname : Arthur
- Ip Address : 172.16.17.72
- Process Name : EmailDownloader.exe
- Process Path : C:\Users\LetsDefend\Downloads\EmailDownloader.exe
- Parent Process : C:\Windows\Explorer.EXE
- Command Line : C:\Users\LetsDefend\Downloads\EmailDownloader.exe
- File Hash : cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa
- Trigger Reason : Unusual or suspicious patterns of behavior linked to the hash have been identified, indicating potential malicious intent.
- Device Action : Allowed

## Playbook

I first analyzed the source IP address in Log Management to gather additional context.

Key findings:

- Event ID: 4624
- Logon Type: 10 (Remote Interactive)
- Destination IP: 136.243.108.14 (Classified as malicious in VirusTotal and LetsDefend Threat Intelligence) - Associated with APT35
- File Hash: cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa (Detected as malicious in VirusTotal)

These indicators strongly suggest malicious activity related to a known threat actor.

## Suspicious Domain, HTTP, and DNS Activity

I continued the investigation by searching for unusual or suspicious network activity, including HTTP and DNS requests, using Endpoint Security and Log Management.

Findings:

- The endpoint Arthur-PC established a connection on December 27, 2023 – 11:22:32.539 to the malicious IP address 136.243.108.14.
- Other ip detected is 173.209.51.54
- Both suspicious IPs are associated with APT35

The IP address 173.209.51.54 is likely the attacker’s source IP, while 136.243.108.14, accessed over an insecure protocol (HTTP), appears to act as the communication channel with the Command and Control (C2) server.

Since only the user Arthur was affected, and based on validation from the VirusTotal community, the activity aligns with a Reconnaissance tactic. More specifically, it matches the technique Gathering Victim Identity Information: Email Addresses, as the initial access vector was identified as a phishing email.

## Reconnaissance Technique Identification

Based on the activity observed in Endpoint Security and the nature of the network connections, the attack matches the following reconnaissance technique:

Phishing for Information

This aligns with known APT35 tradecraft, which frequently uses social engineering and phishing-based reconnaissance prior to further stages of the attack.

## Attacker IP Classification

The attacker IP address was analyzed using Log Management.

- Attacker IP Type: External

- Attacker IP Reputation

A reputation check was performed using multiple threat intelligence sources.

- Reputation Status: Suspicious / Malicious

Sources: VirusTotal, LetsDefend Threat Intelligence

Attribution: Linked to APT35

## Containment Decision

Given the confirmed malicious indicators and multiple affected systems:

Does the device need to be isolated?
Yes

Isolation is required to prevent further data exposure or follow-on activity.
