# Network- versus host-based detection

1. Network- versus host-based

* Network-based IDS (NIDS) Problems:
  - <ins>Encrypted Traffic</ins>: Limited or no visibility into encrypted payloads, making detection challenging.
  - <ins>High-Speed Networks</ins>: Difficulty accurately processing traffic at high volumes, potentially leading to dropped packets or missed detections.
  - <ins>Network Blind Spots</ins>: Unable to monitor traffic not passing through monitored segments, causing visibility gaps.
  - <ins>Signature Maintenance Overhead</ins>: Requires continuous updates of signatures or rules to detect evolving threats.
  - <ins>False Positives and Alert Fatigue</ins>: High false-positive rates due to normal network behaviors triggering alarms, overwhelming security teams.
  - <ins>Limited Insight into Endpoints</ins>: Unable to detect local threats or modifications on individual hosts (e.g., file tampering, malicious processes).

* Host-based IDS (HIDS) Problems:
  - <ins>Resource Consumption</ins>: Consumes CPU, memory, and disk space, potentially affecting system performance and user productivity.
  - <ins>Management Complexity</ins>: Requires deployment, configuration, and regular updates on each endpoint, creating significant administrative overhead.
  - <ins>Host Tampering Vulnerability</ins>: Susceptible to attackers disabling, manipulating, or bypassing agents running on compromised hosts.
  - <ins>Limited Network Visibility</ins>: Only detects threats affecting the monitored host, lacking broader network context or lateral movement detection capabilities.
  - <ins>False Positives from System Variability</ins>: Legitimate user actions (software installations, updates, administrative tasks) often trigger alerts.
  - <ins>Diverse Operating Systems and Configurations</ins>: Requires tailored solutions for different OS types, complicating deployment and maintenance efforts.

2. IDS/IPS rules

3. Wazuh (HIDS overview)

