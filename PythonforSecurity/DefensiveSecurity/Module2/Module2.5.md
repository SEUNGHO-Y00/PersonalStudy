# 2.5 - Filesystem Monitoring and Data Collection

## 1. Introduction: Why Monitor the Filesystem?

## 2. Traversing the Filesystem

## 3. Extracting File Metadata

## 4. Hashing Files for Integrity

## 5. Efficient Hashing with Buffered Reading

## 6. Creating a Baseline for File Integrity

## 7. Real-Time Monitoring with watchdog

## 8. Logging and Alerting

## 9. Handling Exclusions and Patterns

## 10. Use Cases in Defensive Security

## 11. Exercise

1. Accepts a directory path from the user

```python
import os

def get_directory():
    # Accept the path from the user
    user_path = input("Please enter a directory path: ").strip()

    # Validate the path
    if os.path.exists(user_path):
        if os.path.isdir(user_path):
            print(f"Success: '{user_path}' is a valid directory.")
            # Example: List items in the directory
            print("Contents:", os.listdir(user_path))
        else:
            print(f"Error: '{user_path}' exists but it is a file, not a directory.")
    else:
        print(f"Error: The path '{user_path}' does not exist.")

if __name__ == "__main__":
    get_directory()
```

2. Scans all files, logs their metadata and SHA-256 hash

```python
import os
import hashlib
import time

def calculate_sha256(file_path):
    """Calculates SHA-256 hash in 4KB chunks for memory efficiency."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError) as e:
        return f"Error: {e}"

def scan_and_log_directory():
    path = input("Enter the directory path to scan: ").strip()
    if not os.path.isdir(path):
        print("Error: Invalid directory.")
        return

    print(f"\nScanning: {os.path.abspath(path)}\n")

    for root, _, files in os.walk(path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                stats = os.stat(file_path)
                print(f"File: {filename}\n  Size: {stats.st_size}B\n"
                      f"  Hash: {calculate_sha256(file_path)}\n"
                      f"  Mod: {time.ctime(stats.st_mtime)}\n" + "-"*20)
            except Exception as e:
                print(f"Error accessing {filename}: {e}")

if __name__ == "__main__":
    scan_and_log_directory()
```

3. Stores results in a JSON baseline file

```python
import os
import hashlib
import time
import json

def calculate_sha256(file_path):
    """Calculates SHA-256 hash in 4KB chunks."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def scan_to_json():
    path = input("Enter the directory path to scan: ").strip()
    if not os.path.isdir(path):
        print("Error: Invalid directory.")
        return

    baseline_data = []
    print(f"Scanning {path}... please wait.")

    for root, _, files in os.walk(path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                stats = os.stat(file_path)
                file_info = {
                    "file_name": filename,
                    "full_path": os.path.abspath(file_path),
                    "size_bytes": stats.st_size,
                    "sha256": calculate_sha256(file_path),
                    "last_modified": time.ctime(stats.st_mtime)
                }
                baseline_data.append(file_info)
            except Exception as e:
                print(f"Skipping {filename}: {e}")

    # Save to JSON file
    output_file = "baseline.json"
    with open(output_file, "w") as f:
        json.dump(baseline_data, f, indent=4)
    
    print(f"\nScan complete. {len(baseline_data)} files logged to {output_file}")

if __name__ == "__main__":
    scan_to_json()
```

4. Offers a --compare mode to check against the baseline

```python
import os
import hashlib
import time
import json
import sys

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def scan_directory(path):
    """Traverses directory and returns a dictionary of file metadata."""
    results = {}
    for root, _, files in os.walk(path):
        for filename in files:
            file_path = os.path.join(root, filename)
            abs_path = os.path.abspath(file_path)
            try:
                stats = os.stat(file_path)
                results[abs_path] = {
                    "file_name": filename,
                    "size_bytes": stats.st_size,
                    "sha256": calculate_sha256(file_path),
                    "last_modified": time.ctime(stats.st_mtime)
                }
            except Exception:
                continue
    return results

def main():
    # Check for --compare flag in command line arguments
    compare_mode = "--compare" in sys.argv
    baseline_file = "baseline.json"

    path = input("Enter the directory path: ").strip()
    if not os.path.isdir(path):
        print("Error: Invalid directory.")
        return

    current_scan = scan_directory(path)

    if compare_mode:
        if not os.path.exists(baseline_file):
            print(f"Error: {baseline_file} not found. Run a normal scan first.")
            return

        with open(baseline_file, "r") as f:
            baseline = json.load(f)

        print(f"\n--- Comparison Report for {path} ---")
        
        # Check for Deleted and Modified files
        for file_path, original_data in baseline.items():
            if file_path not in current_scan:
                print(f"[DELETED]  {file_path}")
            elif original_data["sha256"] != current_scan[file_path]["sha256"]:
                print(f"[MODIFIED] {file_path}")

        # Check for New files
        for file_path in current_scan:
            if file_path not in baseline:
                print(f"[NEW FILE] {file_path}")
                
        print("\nComparison complete.")

    else:
        # Standard scan: save current state as the new baseline
        with open(baseline_file, "w") as f:
            json.dump(current_scan, f, indent=4)
        print(f"Success: Baseline saved with {len(current_scan)} files.")

if __name__ == "__main__":
    main()
```

5. Includes a --watch mode using watchdog for real-time monitoring

```python
pip install watchdog
```

```python
import os
import json
import time
import hashlib
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- CORE UTILITIES ---

def calculate_sha256(file_path):
    """Calculates SHA-256 hash in 4KB chunks for memory efficiency."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError):
        return None

def scan_directory(path):
    """Recursively scans a directory and returns metadata dictionary."""
    results = {}
    for root, _, files in os.walk(path):
        for filename in files:
            full_path = os.path.abspath(os.path.join(root, filename))
            stats = os.stat(full_path)
            results[full_path] = {
                "hash": calculate_sha256(full_path),
                "size": stats.st_size,
                "modified": time.ctime(stats.st_mtime)
            }
    return results

# --- WATCH MODE HANDLER ---

class MonitorHandler(FileSystemEventHandler):
    """Logs real-time file system events to the console."""
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[MODIFIED] {event.src_path} (Hash: {calculate_sha256(event.src_path)})")

    def on_created(self, event):
        if not event.is_directory:
            print(f"[CREATED]  {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[DELETED]  {event.src_path}")

# --- MAIN LOGIC ---

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("path", help="Directory path to scan/monitor")
    parser.add_argument("--compare", action="store_true", help="Compare against baseline.json")
    parser.add_argument("--watch", action="store_true", help="Start real-time monitoring")
    args = parser.parse_args()

    baseline_file = "baseline.json"

    if args.watch:
        # Real-time monitoring mode
        print(f"[*] Starting real-time monitor on: {args.path}")
        observer = Observer()
        observer.schedule(MonitorHandler(), args.path, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\n[*] Stopping monitor...")
        observer.join()

    elif args.compare:
        # Comparison mode
        if not os.path.exists(baseline_file):
            print(f"Error: {baseline_file} not found. Run a normal scan first.")
            return

        with open(baseline_file, "r") as f:
            baseline = json.load(f)
        
        current = scan_directory(args.path)
        print(f"--- Comparison Report ---")
        
        for p, data in baseline.items():
            if p not in current:
                print(f"[MISSING]  {p}")
            elif data["hash"] != current[p]["hash"]:
                print(f"[CHANGED]  {p}")
        
        for p in current:
            if p not in baseline:
                print(f"[NEW FILE] {p}")
    
    else:
        # Standard scan (Baseline creation)
        data = scan_directory(args.path)
        with open(baseline_file, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Success: Baseline for {len(data)} files saved to {baseline_file}.")

if __name__ == "__main__":
    main()
```

6. Logs all activity and optionally alerts via terminal or file

```python
import os
import logging
import argparse
from datetime import datetime

def setup_logger(log_file, silent_file):
    """Configures logging to both terminal and a file."""
    logger = logging.getLogger("ActivityLogger")
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')

    # Terminal Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler (Optional: only if a filename is provided)
    if not silent_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

def log_activity(logger, message, is_alert=False):
    """Logs the message as INFO or WARNING (alert) based on the flag."""
    if is_alert:
        logger.warning(f"ALERT: {message}")
    else:
        logger.info(message)

def main():
    parser = argparse.ArgumentParser(description="Activity Logger with Optional Alerts")
    parser.add_argument("--log-file", default="activity_log.txt", help="Name of the log file")
    parser.add_argument("--alert", action="store_true", help="Trigger an alert level log")
    parser.add_argument("--no-file", action="store_true", help="Disable logging to a file")
    
    args = parser.parse_args()
    
    # Initialize Logger
    logger = setup_logger(args.log_file, args.no_file)

    # Example Activity
    user_input = input("Enter an action to log: ")
    
    log_activity(logger, user_input, is_alert=args.alert)

    if args.no_file:
        print("\n[Notice] Activity was only logged to the terminal.")
    else:
        print(f"\n[Notice] Activity logged to terminal and '{args.log_file}'.")

if __name__ == "__main__":
    main()
```

7. Add file size thresholds for alerting (e.g., >10MB in /etc)

```python
import os
import logging
import argparse

def setup_logger(log_to_file):
    """Configures logging to terminal and optionally a file."""
    logger = logging.getLogger("ThresholdMonitor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')

    # Terminal output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File output
    if log_to_file:
        file_handler = logging.FileHandler("integrity_alerts.log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

def check_files(target_dir, threshold_mb, sensitive_path, logger):
    """Scans files and alerts if size exceeds threshold in sensitive paths."""
    threshold_bytes = threshold_mb * 1024 * 1024
    count = 0

    logger.info(f"Starting scan: {target_dir} (Threshold: {threshold_mb}MB for paths starting with {sensitive_path})")

    for root, _, files in os.walk(target_dir):
        for filename in files:
            full_path = os.path.abspath(os.path.join(root, filename))
            try:
                file_size = os.path.getsize(full_path)
                
                # Check if file is in a sensitive area AND exceeds threshold
                if full_path.startswith(os.path.abspath(sensitive_path)):
                    if file_size > threshold_bytes:
                        size_mb = round(file_size / (1024 * 1024), 2)
                        logger.warning(f"THRESHOLD ALERT: {full_path} is {size_mb}MB (Limit: {threshold_mb}MB)")
                
                count += 1
            except (PermissionError, FileNotFoundError):
                continue

    logger.info(f"Scan complete. Processed {count} files.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor file sizes in sensitive directories.")
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument("--threshold", type=float, default=10.0, help="Size threshold in MB (default: 10)")
    parser.add_argument("--sensitive", default="/etc", help="Sensitive path prefix to monitor (default: /etc)")
    parser.add_argument("--log", action="store_true", help="Log alerts to integrity_alerts.log")

    args = parser.parse_args()
    
    app_logger = setup_logger(args.log)
    check_files(args.path, args.threshold, args.sensitive, app_logger)
```

8. Track file owner/group via os.stat().st_uid and pwd.getpwuid()

```python
import os
import pwd
import grp
import argparse
import logging

def setup_logger():
    logger = logging.getLogger("OwnershipMonitor")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger.addHandler(handler)
    return logger

def get_ownership_info(file_path):
    """Retrieves human-readable owner and group names."""
    try:
        stats = os.stat(file_path)
        # Get username from UID
        owner = pwd.getpwuid(stats.st_uid).pw_name
        # Get group name from GID
        group = grp.getgrgid(stats.st_gid).gr_name
        return owner, group
    except KeyError:
        # Fallback if UID/GID doesn't exist in system database
        return str(stats.st_uid), str(stats.st_gid)
    except Exception as e:
        return None, None

def scan_ownership(target_path, logger):
    """Scans directory and logs file ownership."""
    if not os.path.exists(target_path):
        logger.error(f"Path not found: {target_path}")
        return

    logger.info(f"Scanning ownership in: {target_path}")
    
    for root, _, files in os.walk(target_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            owner, group = get_ownership_info(full_path)
            
            if owner and group:
                logger.info(f"FILE: {filename} | OWNER: {owner} | GROUP: {group}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Track file owner and group.")
    parser.add_argument("path", help="Directory path to scan")
    args = parser.parse_args()

    app_logger = setup_logger()
    scan_ownership(args.path, app_logger)
```
