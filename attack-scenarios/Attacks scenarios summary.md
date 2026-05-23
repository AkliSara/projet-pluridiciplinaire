Attack Scenarios Summary :
 The four attack scenarios conducted in this project form a single, coordinated campaign executed from Kali Linux (100.117.116.16) against the target machine (100.108.27.54), following a complete kill chain from reconnaissance to malware simulation.

-Incident 1 : SSH Brute Force (CRITICAL): The attacker scanned the network with Nmap, identified an open SSH port, and launched a Hydra brute force attack using the rockyou wordlist. The password "password" was recovered in seconds, granting initial access. The attacker then escalated to root via a misconfigured sudo policy, accessed sensitive system files, modified binaries, and created a persistent backdoor account named "hacker."

-Incident 2 : Privilege Escalation (CRITICAL): Building on the foothold from Incident 1, the attacker escalated from the compromised user account to full root access using a permissive sudo configuration.

-Incident 3 : Web Probing (MEDIUM → HIGH): Using Nikto, the attacker automatically scanned the DVWA web server and identified several misconfigurations : exposed Apache version, missing security headers, and an ETag information leak. No direct compromise occurred, but this phase provided the attacker with a full map of the web attack surface, representing the reconnaissance step preceding more severe exploitation.

-Incident 4 : Malware Simulation (HIGH): Still using the SSH access from Incident 1, the attacker dropped an EICAR test file into the monitored /tmp directory, deleted it, and recreated it to simulate payload evasion behavior. 

 