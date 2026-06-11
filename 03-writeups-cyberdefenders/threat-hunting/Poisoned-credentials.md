### Q1 – Mistyped Name Query
Filtered LLMNR/NBT-NS traffic from 192.168.232.162 in Wireshark and found the mistyped query *fileshaare*. 

### Q2 – Rogue Machine IP
Identified attacker by finding fake LLMNR/NBT-NS responses from *192.168.232.215*.

### Q3 – Second Affected Machine
Filtered traffic involving the attacker IP and found *192.168.232.176* also received poisoned replies.

### Q4 – Compromised Username
Filtered SMB/NTLMSSP traffic and located the username *janesmith*.

### Q5 – Hostname Accessed via SMB
Followed SMB TCP stream and found the hostname *ACCOUNTINGPC* in NTLM/SMB session details.
