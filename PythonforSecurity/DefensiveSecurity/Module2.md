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
