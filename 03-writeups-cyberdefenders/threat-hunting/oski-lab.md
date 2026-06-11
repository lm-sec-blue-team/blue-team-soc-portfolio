### Q1 – Malware Family
Identified the malware family as Stealc based on VirusTotal Crowdsourced IDS detections.

### Q2 – Creation Time
Checked the Creation Time field in VirusTotal Details for the provided hash. 

### Q3 – C2 Server
Found Contacted URLs in VirusTotal and identified the C2 endpoint used by the malware.

### Q4 – First DLL Requested
Reviewed Behavior/HTTP Requests in VirusTotal and observed the first DLL requested post-infection.

### Q5 – RC4 Key
Used Recorded Future Tria.ge report to extract the RC4 key used for decrypting base64 strings.

### Q6 – MITRE Technique
Mapped malware activity to MITRE ATT&CK T1555 – Credentials from Password Stores.

### Q7 – Targeted Directory for Deletion
Analyzed Any.Run report and found deletion of files in C:\ProgramData (Indicator Removal: File Deletion).

### Q8 – Self-Deletion Timeout
Observed a 5-second timeout before malware self-deletion after exfiltration.
