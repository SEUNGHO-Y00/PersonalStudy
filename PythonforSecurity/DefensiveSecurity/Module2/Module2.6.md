# 2.6 - Scheduling and Continuous Monitoring

## 1. Introduction to Task Scheduling

## 2. The time.sleep() Loop – The Most Basic Scheduler

## 3. Using schedule Library – Human-Friendly Scheduling

## 4. Advanced Scheduling with APScheduler

## 5. Persistent Daemon for Continuous Monitoring

## 6. Combining Logging and Alerting

## 7. Integration with System-Level Schedulers

## 8. Use Case: Scheduled Integrity Scan with Baseline Comparison

## 9. Best Practices

## 10. Final Exercise

1. Loads baseline from baseline.json

```python
import json
import os

def load_baseline(filepath='baseline.json'):
    """
    Loads system monitoring thresholds and service lists from a JSON file.
    """
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found. Using internal defaults.")
        # Default baseline if file is missing
        return {
            "cpu_threshold": 80.0,
            "memory_threshold": 85.0,
            "disk_threshold": 90.0,
            "critical_services": ["ssh", "docker"]
        }

    try:
        with open(filepath, 'r') as f:
            baseline_data = json.load(f)
            print(f"Successfully loaded baseline from {filepath}")
            return baseline_data
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse {filepath}. Check for syntax errors. {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Usage
baseline = load_baseline()
if baseline:
    print(f"Monitoring active for services: {', '.join(baseline['critical_services'])}")
```

2. Checks files every 2 hours using schedule

```python
import json
import os
import time
import schedule

def load_baseline(filepath='baseline.json'):
    """Loads monitoring thresholds from the JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Error loading {filepath}. Ensure file exists and is valid JSON.")
        return None

def monitor_task():
    """The core logic that runs every 2 hours."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting file check...")
    
    baseline = load_baseline()
    if not baseline:
        return

    # Example: Check for existence of files defined in your baseline
    # Assuming baseline.json has a key: "files_to_watch": ["/path/to/app.log", "config.yml"]
    files_to_check = baseline.get("files_to_watch", [])
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"  OK: {file_path} (Size: {size} bytes)")
        else:
            print(f"  ALERT: {file_path} is missing!")

# Schedule the task
schedule.every(2).hours.do(monitor_task)

print("Monitoring suite is running. Press Ctrl+C to stop.")

# Keep the script alive
if __name__ == "__main__":
    # Run once immediately on startup (optional)
    monitor_task() 
    
    while True:
        schedule.run_pending()
        time.sleep(60) # Check for pending tasks every minute
```

3. Monitors /var/www/ with watchdog

```python
import time
import json
import os
import schedule
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 1. Baseline Loader
def load_baseline(filepath='baseline.json'):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception:
        return {"files_to_watch": [], "monitor_path": "/var/www/"}

# 2. Watchdog Event Handler
class WebDirHandler(FileSystemEventHandler):
    """Logs real-time changes in /var/www/"""
    def on_modified(self, event):
        if not event.is_directory:
            print(f"[REAL-TIME] Modified: {event.src_path}")

    def on_created(self, event):
        print(f"[REAL-TIME] Created: {event.src_path}")

    def on_deleted(self, event):
        print(f"[REAL-TIME] Deleted: {event.src_path}")

# 3. Scheduled Task (Every 2 Hours)
def scheduled_check():
    print(f"\n--- Starting 2-Hour Baseline Audit: {time.ctime()} ---")
    baseline = load_baseline()
    for f in baseline.get("files_to_watch", []):
        status = "EXISTS" if os.path.exists(f) else "MISSING"
        print(f"Audit: {f} -> {status}")

# --- Main Suite Execution ---
if __name__ == "__main__":
    path_to_monitor = "/var/www/"
    
    # Setup Watchdog
    event_handler = WebDirHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_monitor, recursive=True)
    observer.start()

    # Setup Schedule
    schedule.every(2).hours.do(scheduled_check)
    
    print(f"Monitoring Suite Active.")
    print(f"Real-time: {path_to_monitor} | Scheduled: Every 2 hours")

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
```

4. Logs all changes to monitoring.log

```python
import time
import json
import os
import logging
import schedule
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration & Logging Setup ---
logging.basicConfig(
    filename='monitoring.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_baseline(filepath='baseline.json'):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load baseline: {e}")
        return {"files_to_watch": []}

# --- Real-Time Monitoring (Watchdog) ---
class WebDirHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            logging.info(f"FILE MODIFIED: {event.src_path}")

    def on_created(self, event):
        logging.info(f"FILE CREATED: {event.src_path}")

    def on_deleted(self, event):
        logging.warning(f"FILE DELETED: {event.src_path}")

# --- Scheduled Audit (Every 2 Hours) ---
def scheduled_audit():
    logging.info("--- STARTING 2-HOUR SCHEDULED AUDIT ---")
    baseline = load_baseline()
    files = baseline.get("files_to_watch", [])
    
    if not files:
        logging.info("No baseline files specified for audit.")
        return

    for file_path in files:
        if os.path.exists(file_path):
            logging.info(f"AUDIT OK: {file_path} exists.")
        else:
            logging.critical(f"AUDIT FAIL: {file_path} is missing!")

# --- Main Suite Execution ---
if __name__ == "__main__":
    watch_path = "/var/www/"
    
    # 1. Initialize Watchdog
    event_handler = WebDirHandler()
    observer = Observer()
    observer.schedule(event_handler, watch_path, recursive=True)
    observer.start()
    logging.info(f"Watchdog started on {watch_path}")

    # 2. Initialize Schedule
    schedule.every(2).hours.do(scheduled_audit)
    
    # Run an initial audit on startup
    scheduled_audit()

    print("Monitoring Suite is active. Logging to monitoring.log...")

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Monitoring suite stopped by user.")
        observer.stop()
    
    observer.join()
```

5. Sends alert if a .php or .exe file is created
6. Add CLI interface to select --rebuild-baseline or --monitor-mode
7. Package it as a service using pyinstaller or systemd
