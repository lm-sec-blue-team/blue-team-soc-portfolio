### Q1 – What city did the attack originate from?
Identified attacker IP from PCAP and checked geolocation → *Tianjin, China*.

### Q2 – What was the attacker’s User-Agent?
Filtered HTTP from attacker IP and followed stream → *Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0*.

### Q3 – What’s the name of the malicious web shell uploaded?
Looked at POST file upload packets → *image.jpg.php*.

### Q4 – Which directory stores uploaded files?
Examined request URIs → */reviews/uploads/*.

### Q5 – What port did the web shell use for outbound comms?
Filtered reverse shell traffic → *Port 8080*.

### Q6 – What file was the attacker trying to exfiltrate?
Analyzed shell commands → *passwd*.
