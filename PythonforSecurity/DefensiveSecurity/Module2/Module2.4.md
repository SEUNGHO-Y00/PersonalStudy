# 2.4 - Interacting with APIs and External Services using Python

## 1. Introduction: Why Use APIs in Defensive Security?

## 2. Python and HTTP APIs: Using the requests Library

## 3. Basic API Call: IPInfo.io Example

## 4. Adding Authentication Headers

## 5. Working with POST Requests

## 6. Handling Errors, Timeouts, and Retries

## 7. Modularizing API Logic

## 8. Real-World Use Cases in Security Operations

## 9. JSON Handling and Integration

## 10. Logging API Results

## 11. Exercise

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
