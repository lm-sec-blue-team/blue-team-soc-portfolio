# CyberDefenders – Insider Lab (DFIR Forensics)  
Write-up and analysis of the *Insider* challenge from CyberDefenders:

This repository documents the forensic investigation of a Linux disk image associated with an employee suspected of insider activity. The goal of the lab is to analyze forensic artifacts and answer a predefined set of questions using standard DFIR methodology and tools, mainly **FTK Imager**.  
All explanations below are written in my own words and are not copied from the official walkthrough.


## Challenge Overview

In this scenario, the fictional company **TAAUSAI** suspects malicious internal activity carried out by an employee named *Karen*. A forensic disk image of her Linux workstation is provided.  
As a security analyst, the task is to examine the image, identify relevant artifacts, and answer questions related to system usage, tools, logs, and potential malicious behavior.


## Investigation Methodology

1. **Mounting the forensic image**  
   The provided `.AD1` image is loaded into FTK Imager as evidence, allowing a full read-only exploration of the file system.

2. **File system analysis**  
   Key directories such as `/boot`, `/var/log`, `/root`, and user workspace folders are reviewed to identify configuration details and suspicious artifacts.

3. **Log and artifact review**  
   Authentication logs, command history, documents, and downloaded tools are analyzed to reconstruct user activity.

4. **Hash verification**  
   Hash values are extracted to verify file integrity and identify specific files requested in the challenge.

---

### Q1 — Linux distribution

**Answer:** *Kali Linux*  
**Explanation:**  
System-related artifacts found in boot and configuration directories clearly indicate that the operating system installed on the machine is Kali Linux.


### Q2 — MD5 hash of `access.log`

**Answer:**  
The MD5 hash was obtained directly from the Apache `access.log` file.

**How it was identified:**  
FTK Imager was used to calculate and export file hashes, allowing direct identification of the MD5 value associated with this specific log file.

### Q3 — Credential dumping tool name

**Answer:** `mimikatz_trunk.zip`  
**Reasoning:**  
This file appears in the root user’s download directory. Its name matches a well-known credential dumping tool commonly used for extracting authentication material.

### Q4 — Absolute path of the “super secret” file

**Answer:**  
`/root/Desktop/SuperSecretFile.txt`

**Explanation:**  
Although the file is not immediately visible, its creation and location are referenced in the Bash command history, which reveals the full absolute path.


### Q5 — Tool used on `didyouthinkwedmakeiteasy.jpg`

**Answer:** `binwalk`  
**Explanation:**  
The Bash history shows Binwalk being executed against this image file, indicating it was analyzed for embedded data or hidden content.


### Q6 — Third goal in Karen’s checklist

**Answer:** `Profit`  
**How it was found:**  
A checklist file located on the desktop contains several listed objectives. The third entry in this list is “Profit”.

### Q7 — Number of times Apache was executed

**Answer:** `0`  
**Justification:**  
Apache log files exist but contain no activity entries, indicating the web service was never executed on this system.

### Q8 — Evidence of an attack on another machine

**Answer:** `irZLAohL.jpeg`  
**Explanation:**  
This image provides visual evidence suggesting interaction with another system, consistent with offensive or unauthorized activity.


### Q9 — Person Karen was mocking

**Answer:** `Young`  
**Reasoning:**  
A Bash script stored in the documents directory prints a message containing this name in a mocking or taunting context.


### Q10 — User who escalated privileges to root at 11:26

**Answer:** `postgres`  
**Evidence:**  
Authentication logs (`auth.log`) show multiple `su` events initiated by the `postgres` user around the specified time.


### Q11 — Current working directory from Bash history

**Answer:**  
`/root/Documents/myfirsthack`

**Explanation:**  
This path is the last recorded working directory in the user’s Bash command history.

## Tools Used

- **FTK Imager** — For mounting and analyzing the forensic disk image  
- **Built-in hash calculation** — To verify and identify file hashes

