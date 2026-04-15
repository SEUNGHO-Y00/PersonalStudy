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



5. Includes a --watch mode using watchdog for real-time monitoring
6. Logs all activity and optionally alerts via terminal or file
7. Add file size thresholds for alerting (e.g., >10MB in /etc)
8. Track file owner/group via os.stat().st_uid and pwd.getpwuid()
