## MITRE ATT&CK Mapping

Based on the detected activities and vulnerabilities observed through Wazuh and Suricata, the following MITRE ATT&CK techniques are applicable to this project:

### Credential Access
- **T1110 – Brute Force**  
  Detected multiple SSH authentication failures and brute-force attempts against the honeypot system.

### Initial Access
- **T1078 – Valid Accounts**  
  Successful SSH login events detected after repeated authentication attempts.

### Discovery
- **T1046 – Network Service Scanning**  
  Nmap TCP SYN scans triggered network discovery behavior, observed via Suricata flow and interface monitoring.

### Defense Evasion
- **T1562.001 – Disable or Modify Security Tools**  
  Wazuh agent stop/start events were detected, indicating possible attempts to evade monitoring.

### Privilege Escalation
- **T1548.003 – Abuse Elevation Control Mechanism (Sudo)**  
  Successful sudo execution to ROOT was logged by Wazuh.

### Credential Access (Hardware-Level Risk)
- **T1601 – Modify System Image**  
  Vulnerabilities in CPU microcode (CVE-2025-29934) pose risks that could enable low-level privilege escalation or system compromise.

---
