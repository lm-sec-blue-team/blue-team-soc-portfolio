# EventID: 234 - [SOC176 - RDP Brute Force Detected]

## Initial info

- EventID : 234
- Event Time : Mar, 07, 2024, 11:44 AM
- Rule : SOC176 - RDP Brute Force Detected
- Level : Security Analyst
- Source IP Address : 218.92.0.56
- Destination IP Address : 172.16.17.148
- Destination Hostname : Matthew
- Protocol : RDP
- Firewall Action : Allowed
- Alert Trigger Reason : Login failure from a single source with different non existing accounts

## Playbook: 

1. Check the Source IP address. Is the IP address 'internal' or 'external'?

Source IP is 218.92.0.56, we know that the Internal IPs belongs to (10.0.0.0, 172.16.0.0 and 192.168.0.0). For this reason we can say that 218.92.0.56 is a external IP.

2. Is the attacker IP suspicious or not?

We check the Ip in Virustotal, AbuseIp and Lets defend IP. The tools detect the IP like malicious. So we can say that attacker Ip is suspicious.

3. Search for the Attacker IP address in Log Management. Is there a request from the Attacker IP address to the target server's SSH or RDP port?

Yes, we can see in log managment, many events (30 events) from attacket Ip to the RDP port (3389) of destination address IP 172.16.17.148. The firewall blocked most attempts.

4. Does the Attacker IP address try to establish an SSH/RDP connection with multiple servers/clients as the target?

No, the attacker try to attack 172.16.17.148 all time. Is the focus.

5. Was the brute force attack successful?

Yes, the brute force attack is successful. We found a EventID 4624, that indicates the successful logon. The timestamp is: Mar, 07, 2024, 11:44 AM with the username: Mathews.

6. Systems exposed to a cyber-attack should be isolated to reduce the impact of the cyber-attack. Does the device require isolation?

Yes, we should isolate the PC to avoid data exfiltration.

## Lesson Learned

How did the cyber attack happen?
The attack is a RDP brute force attack. We can see TTS in MITRE for RDP. If we investigate the terminal history in endpoint, we can see netstat commands, for this reasoen, the attecker maybe look a RDP Hijacking(T1563.001). 

How well did staff and management perform in dealing with the incident?
We dont have information about the managment perform. I isolated the pc, but I recommend scalte to L2, because the attackcer want to have info about de network. Maybe, he obtain info to attack other endpoint in network.
