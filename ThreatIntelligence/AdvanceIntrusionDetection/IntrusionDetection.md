# Intrusion detection techniques and methods

1. Introduction to Advanced Intrusion Detection

2. What is intrusion detection?

* Intrusion Detection
  - A component of network security monitoring
  - Identifying abnormal activity
  - Data = Security events, Network Logs, Applications and devices
  - Technology = IDS/IPS, SIEM
  - Host-based / Network-based

3. Detection methodology

* Signature-based
* Anomaly-based

Feature | Signature-based Detection | Anomaly-based Detection
| ------------- |:-------------:| :-----:|
Detection Method | Matching known signatures | Detecting deviations from normal behavior
Zero-day Attack Detection | Poor | Good
False Positive Rates | Lower (for known threats) | Higher
Complexity | Simpler | More complex
Maintenance Effort | Requires regular updates | Requires ongoing baseline refinement
Response to New Threats | Reactive | Proactive

* Stateful protocol-based = Vendor-developed standards
* Hybrid-based

4. Types of intrusion detection

* Network-based
* Host-based

Feature | Network-based | Host-based
| ------------- |:-------------:| :-----:|
Scope of Monitoring| Network-level | Endpoint-level
Visibility | Traffic flows, packet content | System logs, file changes, processes
Encrypted Traffic | Limited visibility | Effective visibility
Performance Impact | Minimal to network | Moderate to endpoint resources
Deployment Complexity | Centralized, simpler | Distributed, complex
Detection Coverage | Broad, across multiple hosts | Deep, within specific host
Insider Threat Detection | Less effective | Highly effective
Scalability | Highly scalable | Requires significant management
Response Capabilities | Blocking traffic, isolation | Quarantine, remediation actions

5. Intrusion detection requirements

* IDS Architecture
  - Sensor (Agents)
    - Signature-based
    - Policy-based
    - Anomaly-based
    - Honeypot-based
  - Management server
  - Database server
  - Console
 
