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
