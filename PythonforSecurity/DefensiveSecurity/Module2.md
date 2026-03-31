# Automating Security Tasks with Python

## 2.1 - Working with Operating System Commands

1. Prompts the user for a domain name

```python
import socket

def get_ip_info():
    # Prompt the user for a domain name
    domain = input("Enter the domain name (e.g., google.com): ").strip()
    
    try:
        # Resolve the IPv4 address
        ip_address = socket.gethostbyname(domain)
        print(f"\nDomain: {domain}")
        print(f"IP Address: {ip_address}")
    except socket.gaierror:
        # Handle cases where the domain is invalid or unreachable
        print(f"Error: Could not resolve domain '{domain}'.")

if __name__ == "__main__":
    get_ip_info()
```

2. Validates the domain format

```python
import re

def is_valid_domain(domain: str) -> bool:
    # Pattern: 1-63 chars per label, hyphen allowed (but not at start/end)
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-2][a-z0-9-]{0,61}[a-z0-9]$"
    return bool(re.match(pattern, domain.lower()))

# Prompt and Validate
domain_input = input("Enter a domain name: ").strip().lower()

if is_valid_domain(domain_input):
    print(f"✅ '{domain_input}' is a valid format.")
else:
    print(f"❌ '{domain_input}' is not a valid domain format.")
```

3. Runs a ping check and WHOIS lookup

```python
import platform
import subprocess
import whois
from datetime import datetime

def run_ping(host: str, count: int = 4) -> bool:
    """Run a system ping and return True if reachable."""
    # Determine the correct parameter for packet count
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), host]
    
    print(f"\n--- Pinging {host} ---")
    try:
        # Execute and pipe output to avoid cluttering console
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("Status: Reachable ✅")
            return True
        else:
            print("Status: Unreachable ❌")
            return False
    except subprocess.TimeoutExpired:
        print("Status: Timeout ⏳")
        return False

def run_whois(domain: str):
    """Perform a WHOIS lookup and display key registration data."""
    print(f"\n--- WHOIS Lookup: {domain} ---")
    try:
        w = whois.whois(domain)
        
        # Display core fields
        print(f"Registrar: {w.registrar}")
        
        # Standardize dates (some TLDs return lists)
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expires = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        if created:
            print(f"Created:   {created.strftime('%Y-%m-%d')}")
        if expires:
            print(f"Expires:   {expires.strftime('%Y-%m-%d')}")
            
    except Exception as e:
        print(f"WHOIS Error: {e}")

# Example Usage
target = "google.com"
if run_ping(target):
    run_whois(target)
```

4. Parses and displays key metadata

```python
import whois
from datetime import datetime

def display_domain_metadata(domain: str):
    try:
        # Query WHOIS server
        w = whois.whois(domain)
        
        print(f"\n--- Metadata for {domain} ---")
        print(f"{'Registrar:':<15} {w.registrar}")
        
        # Handle cases where dates might be a list (some TLDs return multiple)
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiry = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        if created:
            print(f"{'Created:':<15} {created.strftime('%Y-%m-%d')}")
        if expiry:
            print(f"{'Expires:':<15} {expiry.strftime('%Y-%m-%d')}")
            
            # Calculate days remaining
            days_left = (expiry - datetime.now()).days
            print(f"{'Status:':<15} {days_left} days remaining")

        print(f"{'Name Servers:':<15} {', '.join(w.name_servers[:3]) if w.name_servers else 'N/A'}")

    except Exception as e:
        print(f"Error retrieving metadata: {e}")

# Example usage (assuming domain was validated in previous step)
display_domain_metadata("google.com")
```

5. Outputs the results as a well-formatted JSON file

```python
import json
import platform
import shutil
import subprocess
import whois
from datetime import datetime

def get_domain_data(domain: str) -> dict:
    """Gathers all metadata and status checks into a dictionary."""
    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "reachable": False,
        "metadata": {}
    }

    # 1. Ping Check
    ping_bin = shutil.which("ping")
    if ping_bin:
        param = "-n" if platform.system() == "Windows" else "-c"
        try:
            subprocess.run([ping_bin, param, "1", domain], 
                           capture_output=True, check=True, timeout=5)
            results["reachable"] = True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            results["reachable"] = False

    # 2. WHOIS Lookup
    try:
        w = whois.whois(domain)
        # Normalize dates (taking the first if it's a list)
        created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiry = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        results["metadata"] = {
            "registrar": w.registrar,
            "creation_date": created,
            "expiration_date": expiry,
            "name_servers": w.name_servers
        }
    except Exception as e:
        results["metadata"]["error"] = str(e)

    return results

def save_to_json(data: dict, filename: str = "result.json"):
    """Saves the dictionary to a formatted JSON file."""
    with open(filename, "w") as f:
        # default=str handles datetime objects by converting them to strings
        json.dump(data, f, indent=4, default=str)
    print(f"✅ Results saved to {filename}")

if __name__ == "__main__":
    target = input("Enter domain: ").strip().lower()
    print("Processing...")
    
    report = get_domain_data(target)
    save_to_json(report, f"{target}_report.json")
```

6. Includes exception handling for timeouts and command errors

```python
import json
import platform
import shutil
import subprocess
import whois
from datetime import datetime

def gather_domain_info(domain: str) -> dict:
    # Initialize with default values in case of complete failure
    data = {
        "domain": domain,
        "checked_at": datetime.now().isoformat(),
        "status": "unknown",
        "latency_ms": None,
        "metadata": {}
    }

    # 1. Ping Check with Timeout Handling
    ping_bin = shutil.which("ping")
    if ping_bin:
        param = "-n" if platform.system() == "Windows" else "-c"
        try:
            # Short timeout (3s) to prevent the script from hanging
            result = subprocess.run(
                [ping_bin, param, "1", domain],
                capture_output=True, text=True, timeout=3.0, check=True
            )
            data["status"] = "reachable"
        except subprocess.TimeoutExpired:
            data["status"] = "timeout"
        except subprocess.CalledProcessError:
            data["status"] = "unreachable"
        except Exception as e:
            data["status"] = f"error: {type(e).__name__}"

    # 2. WHOIS Lookup with Exception Handling
    try:
        # Some WHOIS servers are slow; we wrap this in a general try
        w = whois.whois(domain)
        
        # Helper to safely grab the first date if a list is returned
        get_date = lambda d: d[0] if isinstance(d, list) else d
        
        data["metadata"] = {
            "registrar": getattr(w, 'registrar', "N/A"),
            "creation_date": get_date(w.get("creation_date")),
            "expiration_date": get_date(w.get("expiration_date")),
            "name_servers": w.get("name_servers", [])
        }
    except Exception as e:
        data["metadata"] = {"error": f"Lookup failed: {str(e)}"}

    return data

def export_results(data: dict):
    filename = f"{data['domain']}_audit.json"
    try:
        with open(filename, "w") as f:
            # default=str handles datetime objects seamlessly
            json.dump(data, f, indent=4, default=str)
        print(f"\n✨ Report generated: {filename}")
    except IOError as e:
        print(f"❌ Failed to write file: {e}")

if __name__ == "__main__":
    target = input("Enter domain to audit: ").strip().lower()
    if target:
        print(f"🔍 Analyzing {target}...")
        report = gather_domain_info(target)
        export_results(report)
```

* Adapt it to work on both Windows and Linux/macOS

```python
import json
import platform
import shutil
import subprocess
import whois
from datetime import datetime

def audit_domain():
    # 1. User Input & Validation
    domain = input("Enter domain: ").strip().lower()
    if not domain:
        return

    results = {"domain": domain, "checked_at": datetime.now(), "status": "offline"}

    # 4. JSON Export (default=str handles datetime objects)
    filename = f"{domain}_audit.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4, default=str)
    
    print(f"Done. Report saved to {filename}")

if __name__ == "__main__":
    audit_domain()
```

* Add logging to a file

```python
import json
import logging
from datetime import datetime

# Configure logging to 'audit.log'
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def audit_domain():
    domain = input("Enter domain (e.g., google.com): ").strip().lower()
    if not domain:
        logging.warning("Empty domain input.")
        return

    results = {"domain": domain, "checked_at": datetime.now(), "status": "unknown"}
    logging.info(f"Starting audit for: {domain}")

    # 3. Display Formatted JSON (Instead of saving)
    print("\n--- AUDIT RESULTS ---")
    print(json.dumps(results, indent=4, default=str))
    print("----------------------")

if __name__ == "__main__":
    audit_domain()
```

## 2.2 - Automating Reconnaissance and Scanning with Python

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

## 2.2 - Automating Reconnaissance and Scanning with Python

1. Accepts an IP address or domain as input.

```python
import socket

def lookup_target():
    # 1. Accept input from the user
    target = input("Enter an IP address or domain: ").strip()

    if not target:
        print("Error: Input cannot be empty.")
        return

    try:
        # 2. Resolve to an IP address (works for both domains and IPs)
        ip_addr = socket.gethostbyname(target)
        print(f"\n--- Results for: {target} ---")
        print(f"Resolved IP Address: {ip_addr}")

        # 3. Attempt a reverse DNS lookup to find the hostname
        try:
            hostname, alias, addresslist = socket.gethostbyaddr(ip_addr)
            print(f"Associated Hostname: {hostname}")
        except socket.herror:
            print("Hostname: Could not perform reverse DNS lookup.")

    except socket.gaierror:
        print(f"Error: Could not resolve '{target}'. Check the address or your connection.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    lookup_target()
```

2. Performs a TCP SYN scan on ports 20-1024 using Nmap.

```python
!apt-get update && apt-get install nmap -y
```
```python
!pip install python-nmap
```
```python
import nmap
import sys

def syn_scan(target):
    nm = nmap.PortScanner()
    print(f"Starting TCP SYN scan on {target} for ports 20-1024...")
    
    try:
        # -sS: TCP SYN scan (requires root/admin privileges)
        # -p 20-1024: Specific port range
        nm.scan(hosts=target, ports='20-1024', arguments='-sS')
        
        for host in nm.all_hosts():
            print(f'\nHost : {host} ({nm[host].hostname()})')
            print(f'State : {nm[host].state()}')
            for proto in nm[host].all_protocols():
                print(f'----------\nProtocol : {proto}')
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f'port : {port}\tstate : {state}\tservice : {service}')
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    target_input = input("Enter an IP address or domain: ").strip()
    if target_input:
        syn_scan(target_input)
    else:
        print("Invalid input.")
```

3. Parses the output using XML.

```python
!pip install xmltodict
```
```python
import nmap
import xml.etree.ElementTree as ET

def nmap_xml_scan(target):
    nm = nmap.PortScanner()
    print(f"Starting TCP SYN scan on {target} (Ports 20-1024)...")
    
    try:
        # Perform scan and capture XML output
        # -sS: SYN scan, -oX -: Output XML to stdout
        nm.scan(hosts=target, ports='20-1024', arguments='-sS -oX -')
        raw_xml = nm.get_nmap_last_output()
        
        # Parse XML from the string
        root = ET.fromstring(raw_xml)
        
        print(f"\n--- Scan Results for {target} ---")
        
        # Iterate through each host found in the XML
        for host in root.findall('host'):
            address = host.find('address').get('addr')
            status = host.find('status').get('state')
            print(f"Host: {address} | Status: {status}")
            
            # Find all port elements within the host
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                
                # Check for service tag, handle if missing
                service_tag = port.find('service')
                service_name = service_tag.get('name') if service_tag is not None else "unknown"
                
                print(f"  Port: {port_id:<5} | State: {state:<10} | Service: {service_name}")
                
    except Exception as e:
        print(f"Error during scan or parsing: {e}")

if __name__ == "__main__":
    target_input = input("Enter an IP address or domain: ").strip()
    if target_input:
        nmap_xml_scan(target_input)
```

4. Runs a socket scan on the same ports as validation.

```python
import socket
from datetime import datetime

def socket_scan(target, port_range):
    print(f"Scanning {target}...")
    print(f"Time started: {datetime.now()}")
    print("-" * 30)

    open_ports = []

    try:
        for port in port_range:
            # AF_INET = IPv4, SOCK_STREAM = TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set a short timeout (adjust based on network speed)
            s.settimeout(0.5)
            
            # connect_ex returns 0 if successful, or an error code if not
            result = s.connect_ex((target, port))
            
            if result == 0:
                print(f"Port {port:4}: OPEN")
                open_ports.append(port)
            
            s.close()

    except KeyboardInterrupt:
        print("\nScan stopped by user.")
    except socket.gaierror:
        print("\nHostname could not be resolved.")
    except socket.error:
        print("\nCould not connect to server.")

    print("-" * 30)
    print(f"Scan complete. Found {len(open_ports)} open ports.")

if __name__ == "__main__":
    target_input = input("Enter an IP address or domain: ").strip()
    
    if target_input:
        # Define the range 20-1024
        ports_to_scan = range(20, 1025)
        socket_scan(target_input, ports_to_scan)
    else:
        print("Invalid input.")
```

5. Logs all results to a local file with timestamps.

* Only Socket

```python
import socket
from datetime import datetime

def log_result(message, file_path="scan_results.txt"):
    """Appends a message with a timestamp to a local file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(file_path, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def perform_socket_scan(target):
    log_file = "scan_results.txt"
    print(f"Scanning {target}... Results are being logged to {log_file}")
    
    # Initialize log entry for a new session
    log_result(f"--- Starting Scan on Target: {target} ---", log_file)
    
    open_count = 0
    
    try:
        # Scan ports 20 through 1024
        for port in range(20, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # Fast timeout for responsiveness
            
            # connect_ex returns 0 if the port is open
            result = s.connect_ex((target, port))
            
            if result == 0:
                msg = f"Port {port}: OPEN"
                print(msg)
                log_result(msg, log_file)
                open_count += 1
            else:
                # Optional: Log closed ports as well
                log_result(f"Port {port}: CLOSED/FILTERED", log_file)
            
            s.close()

    except KeyboardInterrupt:
        log_result("Scan interrupted by user.", log_file)
        print("\nScan stopped.")
    except socket.gaierror:
        log_result("Error: Hostname could not be resolved.", log_file)
        print("Error: Invalid address.")
    
    log_result(f"--- Scan Complete. Found {open_count} open ports. ---\n", log_file)
    print(f"Done. Found {open_count} open ports.")

if __name__ == "__main__":
    target_input = input("Enter an IP address or domain: ").strip()
    if target_input:
        perform_socket_scan(target_input)

```

* With Nmap

```python
import nmap
import socket
from datetime import datetime

def log_to_file(message, filename="nmap_scan_results.txt"):
    """Appends a message with a timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def run_nmap_scan(target):
    nm = nmap.PortScanner()
    log_file = "nmap_scan_results.txt"
    
    print(f"Starting Nmap SYN scan on {target}... Logging to {log_file}")
    log_to_file(f"--- STARTING SCAN: {target} ---")

    try:
        # Perform TCP SYN Scan (-sS) on ports 20-1024
        # Note: Requires sudo/Admin privileges
        nm.scan(hosts=target, ports='20-1024', arguments='-sS')

        if target not in nm.all_hosts():
            log_to_file(f"Target {target} appeared down or unreachable.")
            print("Target unreachable.")
            return

        # Iterate through results and log them
        for proto in nm[target].all_protocols():
            log_to_file(f"Protocol: {proto}")
            ports = sorted(nm[target][proto].keys())
            
            for port in ports:
                state = nm[target][proto][port]['state']
                service = nm[target][proto][port].get('name', 'unknown')
                result_msg = f"Port {port}: {state} ({service})"
                
                print(result_msg)
                log_to_file(result_msg)

        log_to_file(f"--- SCAN COMPLETE for {target} ---\n")
        print("\nScan complete. Check nmap_scan_results.txt for details.")

    except Exception as e:
        error_msg = f"An error occurred: {str(e)}"
        print(error_msg)
        log_to_file(error_msg)

if __name__ == "__main__":
    target_input = input("Enter an IP address or domain: ").strip()
    if target_input:
        run_nmap_scan(target_input)
```

6. (Optional) Sends an alert via Telegram if port 3389 or 23 is open.

```python
import socket
import requests
from datetime import datetime

# --- Configuration ---
TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"
LOG_FILE = "socket_scan_results.txt"
ALERT_PORTS = [23, 3389] # Telnet and RDP

def send_alert(target, port):
    """Sends a Telegram notification."""
    url = f"https://api.telegram.org{TOKEN}/sendMessage"
    text = f"⚠️ *SECURITY ALERT*\nTarget: `{target}`\nOpen Port: `{port}`\nStatus: OPEN"
    try:
        requests.post(url, data={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"})
    except Exception as e:
        print(f"Telegram Error: {e}")

def log_event(message):
    """Logs to local file with timestamp."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{now}] {message}\n")

def run_scan(target):
    print(f"Scanning {target}... Results logged to {LOG_FILE}")
    log_event(f"--- STARTING SCAN: {target} ---")
    
    # Range 20-1024 plus 3389 specifically
    ports = list(range(20, 1025)) + [3389]
    
    for port in sorted(set(ports)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        
        # connect_ex returns 0 if successful (port is open)
        result = s.connect_ex((target, port))
        
        if result == 0:
            msg = f"Port {port}: OPEN"
            print(msg)
            log_event(msg)
            
            # Trigger alert for specific security ports
            if port in ALERT_PORTS:
                send_alert(target, port)
                print(f"[!] Alert sent for port {port}")
        else:
            # Optional: log closed ports
            log_event(f"Port {port}: CLOSED")
            
        s.close()

    log_event(f"--- SCAN COMPLETE: {target} ---\n")
    print("Scan finished.")

if __name__ == "__main__":
    target_input = input("Enter IP or Domain: ").strip()
    if target_input:
        run_scan(target_input)
```

## 2.3 - Manual Port Scanning with Python Sockets

1. Accepts a domain or IP from the user.

```python
import socket

def lookup_info():
    # Prompt the user for input
    target = input("Enter a domain name (e.g., google.com) or an IP address: ").strip()

    try:
        # 1. Forward Lookup: Get IP from Domain
        ip_address = socket.gethostbyname(target)
        print(f"\nTarget: {target}")
        print(f"Resolved IP Address: {ip_address}")

        # 2. Reverse Lookup: Get Domain from IP
        try:
            # Returns a tuple; index 0 is the primary hostname
            hostname = socket.gethostbyaddr(ip_address)[0]
            print(f"Associated Hostname: {hostname}")
        except socket.herror:
            print("Reverse lookup not available for this IP.")

    except socket.gaierror:
        # Triggered if the domain name is invalid or cannot be resolved
        print(f"Error: Could not resolve '{target}'. Please check the spelling.")

if __name__ == "__main__":
    lookup_info()
```

2. Resolves the domain to an IP.

```python
import socket

def resolve_domain():
    # Prompt the user for a domain name (e.g., google.com)
    domain = input("Enter the domain name you wish to resolve: ").strip()

    try:
        # Use gethostbyname to translate the domain to an IP address
        ip_address = socket.gethostbyname(domain)
        print(f"The IP address for {domain} is: {ip_address}")

    except socket.gaierror:
        # Handle cases where the domain name is invalid or cannot be resolved
        print(f"Error: Could not resolve domain '{domain}'. Please check your connection or spelling.")

if __name__ == "__main__":
    resolve_domain()
```

3. Performs a threaded port scan on ports 1–1024.

```python
import socket
import threading
from queue import Queue

# --- Setup ---
TARGET = "127.0.0.1"
THREADS = 100
QUEUE = Queue()
OPEN_PORTS = []

# --- Functions ---
def port_scanner(port):
    """Attempts connection to a specific port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((TARGET, port)) == 0:
            OPEN_PORTS.append(port)

def thread_worker():
    """Processes ports from queue."""
    while not QUEUE.empty():
        port = QUEUE.get()
        port_scanner(port)
        QUEUE.task_done()

# --- Execution ---
for port in range(1, 1025): QUEUE.put(port)
for _ in range(THREADS):
    t = threading.Thread(target=thread_worker)
    t.start()
    t.join() # Simplified for example

print(f"Open ports: {sorted(OPEN_PORTS)}")
```

4. Grabs banners from open ports.

```python
import socket

def grab_banner(ip, port):
    try:
        # Create a TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Short timeout to avoid hanging
            s.connect((ip, port))
            
            # For some services (like HTTP), you may need to send data first
            # s.send(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
            
            # Receive the banner (usually the first 1024 bytes)
            banner = s.recv(1024)
            return banner.decode().strip()
    except Exception as e:
        return f"Could not grab banner: {e}"

if __name__ == "__main__":
    target_ip = input("Enter IP: ")
    target_port = int(input("Enter Port: "))
    
    result = grab_banner(target_ip, target_port)
    print(f"\n[+] Banner from {target_ip}:{target_port}:\n{result}")
```

5. Exports the data in a structured JSON format.

```python
import json

def export_results_to_json(data, filename="scan_results.json"):
    """
    Saves scan data into a structured JSON file with indentation.
    """
    try:
        with open(filename, 'w') as json_file:
            # indent=4 makes the file human-readable
            json.dump(data, json_file, indent=4)
        print(f"Successfully exported data to {filename}")
    except Exception as e:
        print(f"Error during export: {e}")

# Example structure matching previous steps
scan_data = {
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "open_ports": [
        {"port": 80, "status": "open", "banner": "Apache/2.4.41"},
        {"port": 443, "status": "open", "banner": "nginx/1.18.0"}
    ]
}

if __name__ == "__main__":
    export_results_to_json(scan_data)
```

6. Handles all possible exceptions gracefully.

```python
import socket
import json
import sys

def handle_network_task():
    try:
        target = input("Enter domain or IP: ").strip()
        if not target:
            raise ValueError("Input cannot be empty.")

        # 1. DNS Resolution Errors
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Error: '{target}' is not a valid domain or reachable.")
            return

        # 2. Connection & Timeout Errors
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                result = s.connect_ex((ip, 80))
                if result != 0:
                    print(f"[!] Port 80 is closed or filtered on {ip}")
        except socket.timeout:
            print("[!] Error: Connection timed out.")
        except PermissionError:
            print("[!] Error: Insufficient permissions to open socket.")

        # 3. Data Export Errors (I/O)
        try:
            with open("results.json", "w") as f:
                json.dump({"target": target, "ip": ip}, f)
        except IOError as e:
            print(f"[!] File Error: Could not write to disk. {e}")

    except KeyboardInterrupt:
        print("\n[!] User interrupted the process. Exiting...")
        sys.exit(0)
    except Exception as e:
        # Generic fallback for any unhandled edge cases
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    handle_network_task()
```

7. Add argparse support for CLI usage

```python
import argparse
import sys

def main():
    # Initialize the parser
    parser = argparse.ArgumentParser(
        description="A CLI tool for domain resolution and port scanning."
    )

    # Add arguments
    parser.add_argument(
        "target", 
        help="The domain name or IP address to scan."
    )
    
    parser.add_argument(
        "-p", "--ports", 
        type=int, 
        nargs=2, 
        default=[1, 1024],
        metavar=("START", "END"),
        help="The range of ports to scan (default: 1 1024)."
    )

    parser.add_argument(
        "-o", "--output", 
        default="results.json",
        help="The JSON file to save results to (default: results.json)."
    )

    # Parse the arguments
    try:
        args = parser.parse_args()
        
        # Access arguments using args.target, args.ports, and args.output
        print(f"[*] Target identified: {args.target}")
        print(f"[*] Scanning range: {args.ports[0]} to {args.ports[1]}")
        print(f"[*] Export destination: {args.output}")

    except Exception as e:
        print(f"[!] Argument error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

8. Store results in a local SQLite database

```python
import sqlite3
import json

def setup_db(db_name="scan_results.db"):
    """Initializes the database and creates the results table."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    # Create table with columns for the target, IP, and a JSON block for ports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            target TEXT,
            resolved_ip TEXT,
            port_data TEXT
        )
    ''')
    conn.commit()
    return conn

def save_scan(conn, target, ip, port_results):
    """Saves a single scan entry into the database."""
    try:
        cursor = conn.cursor()
        # Convert port list to a JSON string for storage in a TEXT column
        json_ports = json.dumps(port_results)
        cursor.execute('''
            INSERT INTO scans (target, resolved_ip, port_data)
            VALUES (?, ?, ?)
        ''', (target, ip, json_ports))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] Database Error: {e}")

# Example Integration
if __name__ == "__main__":
    db_conn = setup_db()
    
    # Mock data from your scanner
    target_val = "example.com"
    ip_val = "93.184.216.34"
    results = [
        {"port": 80, "banner": "Apache/2.4.41"},
        {"port": 443, "banner": "nginx/1.18.0"}
    ]
    
    save_scan(db_conn, target_val, ip_val, results)
    print(f"[*] Data saved to scan_results.db")
    db_conn.close()

```

## 2.4 - Interacting with APIs and External Services using Python

1. Accepts an IP from the user.

```python
import ipaddress

def get_user_ip():
    # Prompt the user for an IP address
    user_input = input("Please enter an IP address: ").strip()

    try:
        # Validate the string as a valid IP address
        ip_obj = ipaddress.ip_address(user_input)
        print(f"Success: '{ip_obj}' is a valid {ip_obj.version} address.")
        return str(ip_obj)

    except ValueError:
        # Handle cases where the input is a domain, a typo, or malformed
        print(f"Error: '{user_input}' is not a valid IP address.")
        return None

if __name__ == "__main__":
    validated_ip = get_user_ip()
```

2. Looks up the IP using both:
IPInfo.io
AbuseIPDB (optional)

```python
import requests
import json

# Replace with your actual API keys
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY"

def lookup_ip_info(ip):
    print(f"\n--- IPInfo.io Lookup for {ip} ---")
    try:
        # IPInfo.io Geolocation Lookup
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        print(f"Location: {data.get('city')}, {data.get('region')}, {data.get('country')}")
        print(f"Organization: {data.get('org', 'N/A')}")
        print(f"Coordinates: {data.get('loc', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print(f"IPInfo Error: {e}")

def check_abuse_db(ip):
    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "YOUR_ABUSEIPDB_KEY":
        return

    print(f"\n--- AbuseIPDB Reputation Check ---")
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        response.raise_for_status()
        data = response.json().get('data', {})
        
        score = data.get('abuseConfidenceScore', 0)
        print(f"Abuse Confidence Score: {score}/100")
        print(f"Total Reports: {data.get('totalReports', 0)}")
        print(f"Last Reported: {data.get('lastReportedAt', 'Never')}")
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB Error: {e}")

if __name__ == "__main__":
    target = input("Enter IP to lookup: ").strip()
    lookup_ip_info(target)
    check_abuse_db(target)
```

3. Checks for threat reputation and location.

```python
import requests

def check_ip_details(ip, ipinfo_token, abuse_key):
    headers = {'Accept': 'application/json'}
    
    # 1. Location Lookup (IPInfo.io)
    try:
        geo_url = f"https://ipinfo.io/{ip}/json?token={ipinfo_token}"
        geo_res = requests.get(geo_url, timeout=5)
        geo_data = geo_res.json()
        print(f"\n--- Location Data ({ip}) ---")
        print(f"City/Region: {geo_data.get('city')}, {geo_data.get('region')}")
        print(f"Country: {geo_data.get('country')}")
        print(f"ISP: {geo_data.get('org')}")
    except Exception as e:
        print(f"Location lookup failed: {e}")

    # 2. Threat Reputation (AbuseIPDB)
    try:
        rep_url = "https://api.abuseipdb.com/api/v2/check"
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        rep_headers = {**headers, 'Key': abuse_key}
        
        rep_res = requests.get(rep_url, headers=rep_headers, params=params, timeout=5)
        rep_data = rep_res.json().get('data', {})
        
        score = rep_data.get('abuseConfidenceScore', 0)
        print(f"\n--- Threat Reputation ---")
        print(f"Abuse Confidence Score: {score}/100")
        print(f"Total Reports: {rep_data.get('totalReports', 0)}")
        print(f"Status: {'MALICIOUS' if score > 50 else 'CLEAN'}")
    except Exception as e:
        print(f"Reputation check failed: {e}")

if __name__ == "__main__":
    # Replace with your actual API keys from ipinfo.io and abuseipdb.com
    MY_IPINFO_TOKEN = "your_ipinfo_token"
    MY_ABUSE_KEY = "your_abuseipdb_key"
    
    target_ip = input("Enter IP to check: ").strip()
    check_ip_details(target_ip, MY_IPINFO_TOKEN, MY_ABUSE_KEY)
```

4. Outputs the information in a structured table.

```python
from tabulate import tabulate

def display_results_table(ip_data):
    # Prepare the headers and data rows
    headers = ["Category", "Information"]
    
    # Organize data into a list of lists for tabulate
    table_data = [
        ["IP Address", ip_data.get("ip")],
        ["City", ip_data.get("city")],
        ["Region", ip_data.get("region")],
        ["Country", ip_data.get("country")],
        ["ISP/Org", ip_data.get("org")],
        ["Abuse Score", f"{ip_data.get('abuse_score')}/100"],
        ["Total Reports", ip_data.get("total_reports")],
        ["Status", ip_data.get("status")]
    ]

    # Print the table using the 'grid' format
    print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    # Example data dictionary
    example_data = {
        "ip": "8.8.8.8",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "org": "Google LLC",
        "abuse_score": 0,
        "total_reports": 0,
        "status": "CLEAN"
    }

    display_results_table(example_data)
```

5. Logs results to a local file.

```python
import logging

def setup_logging():
    # Configure the logger
    logging.basicConfig(
        filename='scan_results.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filemode='a'  # 'a' for append, 'w' for overwrite
    )
    return logging.getLogger()

def log_data(ip, city, score):
    logger = setup_logging()
    
    # Create the log entry
    result_entry = f"Target: {ip} | Location: {city} | Abuse Score: {score}"
    
    # Write to the file
    logger.info(result_entry)
    print(f"[*] Entry recorded in scan_results.log")

if __name__ == "__main__":
    # Example data to log
    log_data("8.8.8.8", "Mountain View", "0/100")
```

6. Implements error handling for network/API issues.

```python
import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

def safe_api_lookup(ip, api_key):
    url = f"https://abuseipdb.com{ip}"
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        # Set a timeout (connect, read) to prevent hanging
        response = requests.get(url, headers=headers, timeout=(3, 5))
        
        # Raise an exception for 4xx or 5xx status codes
        response.raise_for_status()
        
        return response.json()

    except HTTPError as http_err:
        if response.status_code == 401:
            print(f"[!] Auth Error: Invalid API Key. ({http_err})")
        elif response.status_code == 429:
            print(f"[!] Rate Limit: Too many requests. ({http_err})")
        else:
            print(f"[!] HTTP Error: {http_err}")
            
    except ConnectionError:
        print("[!] Network Error: Check your internet connection.")
        
    except Timeout:
        print("[!] Timeout Error: The server took too long to respond.")
        
    except RequestException as err:
        print(f"[!] Unexpected Error: {err}")
    
    return None

if __name__ == "__main__":
    # Test with a dummy key
    result = safe_api_lookup("8.8.8.8", "YOUR_API_KEY")
    if result:
        print("Data retrieved successfully.")
```

7. Implement CLI flags with argparse

```python
import argparse
import sys

def main():
    # Initialize the parser
    parser = argparse.ArgumentParser(
        description="CLI tool for IP location and threat reputation lookup."
    )

    # Required positional argument
    parser.add_argument(
        "ip", 
        help="The target IP address to check (e.g., 8.8.8.8)"
    )

    # Optional flags for API keys
    parser.add_argument(
        "--ipinfo", 
        metavar="TOKEN",
        help="Your IPInfo.io API token"
    )
    
    parser.add_argument(
        "--abuse", 
        metavar="KEY",
        help="Your AbuseIPDB API key"
    )

    # Flag to enable/disable logging
    parser.add_argument(
        "-l", "--log", 
        action="store_true",
        help="Log the results to a local file"
    )

    # Parse the arguments from the command line
    try:
        args = parser.parse_args()
        
        # Access the values using args.ip, args.ipinfo, etc.
        print(f"[*] Targeting IP: {args.ip}")
        if args.log:
            print("[*] Logging enabled.")
            
        return args

    except Exception as e:
        print(f"[!] Argument error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    args = main()
```

8. Schedule it to run hourly using schedule or cron

```python
pip install schedule
```

```python
import schedule
import time
import subprocess

def job():
    print("[*] Running hourly IP check...")
    # Replace '8.8.8.8' with your target or logic to get the IP
    # Using subprocess to run your existing CLI-ready script
    subprocess.run(["python", "your_script.py", "8.8.8.8", "--log"])

# Schedule the task every hour
schedule.every().hour.do(job)

print("[*] Scheduler started. Press Ctrl+C to exit.")

while True:
    schedule.run_pending()
    time.sleep(60) # Wait 1 minute between checks
```

9. Output to CSV or JSON file

```python
import csv
import json
import os

def export_data(data, format="json", filename="results"):
    """
    Exports a dictionary of IP data to either CSV or JSON format.
    """
    if format.lower() == "json":
        full_path = f"{filename}.json"
        with open(full_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[*] Data exported to {full_path}")

    elif format.lower() == "csv":
        full_path = f"{filename}.csv"
        # Check if file exists to determine if we need to write headers
        file_exists = os.path.isfile(full_path)
        
        with open(full_path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data.keys())
            if not file_exists:
                writer.writeheader()  # Write header only once
            writer.writerow(data)
        print(f"[*] Data appended to {full_path}")

if __name__ == "__main__":
    # Example structured data
    scan_result = {
        "ip": "8.8.8.8",
        "city": "Mountain View",
        "country": "US",
        "abuse_score": 0,
        "status": "CLEAN",
        "timestamp": "2023-10-27 10:00:00"
    }

    # Exporting examples
    export_data(scan_result, format="json")
    export_data(scan_result, format="csv")

```
