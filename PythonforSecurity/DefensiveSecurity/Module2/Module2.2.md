# 2.2 - Automating Reconnaissance and Scanning with Python

## 1. Why Automate Reconnaissance?

## 2. Executing External Scanners: Nmap Example

### 2.1 Running Nmap from Python

## 3. Parsing Nmap Output (Structured XML)

## 4. Manual Port Scanning with Sockets

## 5. Adding IP Context with APIs (Optional)

## 6. Combining Recon and Scan in One Script

## 7. Logging and Alerting

## 8. Defensive Use Cases

## 9. Exercise (Hands-on)

1. Accepts an IP address or domain as input.

```python
import socket

def resolve_target():
    # Accepts either an IP (e.g., 8.8.8.8) or a domain (e.g., google.com)
    target = input("Enter a Domain or IP address: ").strip().lower()
    
    if not target:
        print("Error: No input provided.")
        return

    try:
        # Resolves domain to IP or returns IP as-is
        ip_address = socket.gethostbyname(target)
        print(f"\nTarget: {target}")
        print(f"Resolved IP: {ip_address}")
        
    except socket.gaierror:
        # Handles invalid domains or unresolvable hosts
        print(f"Error: Could not resolve '{target}'. Check the address or your connection.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    resolve_target()
```

2. Performs a TCP SYN scan on ports 20-1024 using Nmap.

```python
import nmap
import sys

def run_syn_scan(target):
    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    
    print(f"Scanning {target} (Ports 20-1024) using TCP SYN scan...")
    
    try:
        # -sS: TCP SYN Scan
        # -Pn: Skip host discovery (treat host as online)
        nm.scan(hosts=target, ports='20-1024', arguments='-sS -Pn')
        
        for host in nm.all_hosts():
            print(f"\nHost : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"Protocol : {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"Port : {port}\tState : {state}\tService : {service}")
                    
    except nmap.PortScannerError as e:
        print(f"Nmap Error: {e}")
        print("Tip: Ensure you are running this script with sudo/administrator privileges.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Example target: Accepts IP or Domain
    target_input = input("Enter target (IP or Domain): ").strip()
    if target_input:
        run_syn_scan(target_input)
```

3. Parses the output using XML.

```python
import nmap
import xml.etree.ElementTree as ET

def scan_and_parse_xml(target):
    nm = nmap.PortScanner()
    
    # Run TCP SYN scan on ports 20-1024
    # Note: Requires sudo/administrator privileges
    nm.scan(hosts=target, ports='20-1024', arguments='-sS')
    
    # Retrieve raw XML output
    xml_data = nm.get_nmap_last_output()
    
    # Parse XML structure
    root = ET.fromstring(xml_data)
    
    print(f"--- Results for {target} ---")
    for host in root.findall('host'):
        addr = host.find('address').attrib.get('addr')
        status = host.find('status').attrib.get('state')
        print(f"Host: {addr} ({status})")
        
        # Iterate through ports in the XML
        for port in host.findall('.//port'):
            port_id = port.attrib.get('portid')
            protocol = port.attrib.get('protocol')
            state = port.find('state').attrib.get('state')
            service = port.find('service').attrib.get('name') if port.find('service') is not None else "Unknown"
            
            print(f"  Port {port_id}/{protocol}: {state} ({service})")

if __name__ == "__main__":
    target_input = input("Enter target IP or Domain: ").strip()
    if target_input:
        scan_and_parse_xml(target_input)
```

4. Runs a socket scan on the same ports as validation.

```python
import socket
import nmap
import xml.etree.ElementTree as ET

def socket_check(ip, port):
    """Attempt a full TCP connection to validate the port state."""
    # Create a TCP socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)  # 1 second timeout
        # connect_ex returns 0 on success, otherwise an error code
        result = s.connect_ex((ip, port))
        return "open" if result == 0 else "closed"

def run_dual_scan(target):
    # 1. Resolve Target to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Could not resolve {target}")
        return

    # 2. Run Nmap SYN Scan & Parse XML
    nm = nmap.PortScanner()
    print(f"Starting Nmap SYN scan on {ip}...")
    nm.scan(ip, '20-1024', arguments='-sS')
    
    xml_data = nm.get_nmap_last_output()
    root = ET.fromstring(xml_data)

    print(f"\n{'PORT':<10} {'NMAP (SYN)':<15} {'SOCKET (CONNECT)':<15}")
    print("-" * 45)

    # 3. Parse XML and Validate with Socket
    for host in root.findall('host'):
        for port_elem in host.findall('.//port'):
            port_id = int(port_elem.attrib.get('portid'))
            nmap_state = port_elem.find('state').attrib.get('state')
            
            # Perform validation check
            socket_state = socket_check(ip, port_id)
            
            print(f"{port_id:<10} {nmap_state:<15} {socket_state:<15}")

if __name__ == "__main__":
    target_input = input("Enter target IP or Domain: ").strip()
    if target_input:
        run_dual_scan(target_input)
```
