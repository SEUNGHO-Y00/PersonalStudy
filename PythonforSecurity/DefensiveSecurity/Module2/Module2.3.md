# 2.3 - Manual Port Scanning with Python Sockets

## 1. Introduction to Manual Port Scanning

## 2. The Python socket Module: Fundamentals

## 3. Writing a Full Manual Port Scanner

## 4. Enhancing the Scanner: Threading for Speed

## 5. Banner Grabbing

## 6. Exception Handling and Resilience

## 7. Logging and JSON Export

## 8. Cross-Platform Considerations

## 9. Use Cases in Defensive Security

## 10. Exercise

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
