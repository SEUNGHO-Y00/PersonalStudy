## 1.8 Exception Handling Exercises

### 1.8.1 The Exception Model

### 1.8.2 The try / except / else / finally Block

### 1.8.3 Raising Exceptions

### 1.8.4 Exception Hierarchy (abridged)

### 1.8.5 Custom Exception Classes

### 1.8.6 else and finally in Practice

### 1.8.7 The EAFP Principle

### 1.8.8 Logging vs Swallowing

### 1.8.9 Chaining and Re-raising

### 1.8.10 Context Managers for Safe Cleanup

### 1.8.11 New in 3.11: ExceptionGroup and except*

### 1.8.12 Best-Practice Checklist

### 1.8.13 Exercises

1. Safe Divider
* Write safe_div(a, b, default=None) that returns a/b but logs and returns default if division fails for any arithmetic reason (zero or type error), without hiding other exceptions.

```python
import logging

# Configure basic logging
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

def safe_div(a, b, default=None):
    """
    Returns a/b, but logs a warning and returns default if division fails
    for reasons like zero division or incorrect type.
    """
    try:
        result = a / b
        return result
    except (ZeroDivisionError, TypeError) as e:
        logging.warning(f"Division failed for inputs ({a}, {b}): {e}")
        return default

# Example Usage:
print(f"10 / 2 = {safe_div(10, 2)}")
print(f"10 / 0 = {safe_div(10, 0, default='N/A')}")
print(f"10 / 'a' = {safe_div(10, 'a')}")

# This will raise a normal NameError because it's not caught:
try:
    safe_div(x, 2)
except NameError as e:
    print(f"\nCaught expected NameError: {e}")
```

2. Atomic Writer Context Manager
* Implement AtomicWrite(path) as a context manager that yields a temporary writable file handle and, on successful exit, replaces the target file; on exception, deletes the temp file.

```python
import tempfile
import os
import shutil
from pathlib import Path

class AtomicWrite:
    """
    Context manager for safely writing to a file (atomically).
    Yields a writable file handle, replaces the target path on success,
    and cleans up the temporary file on error.
    """
    def __init__(self, target_path):
        self.target_path = Path(target_path)
        self._temp_file = None

    def __enter__(self):
        # Create a temporary file in the same directory as the target file
        temp_dir = self.target_path.parent or '.'
        self._temp_file = tempfile.NamedTemporaryFile(
            mode='w', delete=False, dir=temp_dir
        )
        return self._temp_file

    def __exit__(self, exc_type, exc_value, traceback):
        self._temp_file.close()
        
        # If no exception occurred (exc_type is None)
        if exc_type is None:
            # Atomically replace the target file with the temp file
            os.replace(self._temp_file.name, self.target_path)
            print(f"[SUCCESS] Wrote atomically to {self.target_path}")
        else:
            # An exception occurred: clean up the temporary file
            os.unlink(self._temp_file.name)
            print(f"[ERROR] An exception occurred. Rolled back write attempt.")
            # We return False (or nothing) to propagate the exception

# Example Usage (Success):
with AtomicWrite("safe_config.txt") as f:
    f.write("Configuration Line 1\n")
    f.write("Configuration Line 2\n")
# The file "safe_config.txt" is created with the content

# Example Usage (Failure):
try:
    with AtomicWrite("safe_config_fail.txt") as f:
        f.write("This should not be saved.")
        raise ValueError("Something went wrong!") # Fails here
except ValueError as e:
    print(f"Caught expected error: {e}")
# The file "safe_config_fail.txt" is never created on disk

# Clean up
if Path("safe_config.txt").exists(): os.remove("safe_config.txt")
```

3. Selective Retry Decorator
* Create @retry(exc_types, times=3) that re-calls the function when it raises one of exc_types, but re-raises immediately for all other exceptions.

```python
import time
import random
from functools import wraps

def retry(exc_types, times=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return func(*args, **kwargs)
                except exc_types as e:
                    # Catch and retry only specific types
                    print(f"Attempt {attempt + 1}/{times} failed with {type(e).__name__}. Retrying in {delay}s...")
                    if attempt == times - 1:
                        raise # Re-raise the last exception
                    time.sleep(delay)
                except Exception as e:
                    # Immediately re-raise any other (unexpected) exception
                    print(f"Caught unhandled exception {type(e).__name__}. Not retrying.")
                    raise
        return wrapper
    return decorator

# Example 1: Function that only raises exceptions the decorator handles
@retry(exc_types=(IOError, ConnectionError), times=3)
def unreliable_network_fetch():
    if random.random() < 0.9:
        raise ConnectionError("Connection Timeout")
    return "Data fetched."

# Example 2: Function that might raise an unhandled exception
@retry(exc_types=(ConnectionError,), times=3)
def buggy_function():
    if random.random() < 0.9:
        raise ConnectionError("Timeout")
    # A bug that raises an unhandled type:
    raise NameError("A coding mistake happened")

# Run Example 1 (will eventually succeed or retry 3 times)
try:
    print(f"\nExample 1 Result: {unreliable_network_fetch()}")
except Exception as e:
    print(f"Example 1 Final Failure: {e}")

# Run Example 2 (will immediately fail with NameError)
try:
    print(f"\nExample 2 Result: {buggy_function()}")
except Exception as e:
    print(f"Example 2 Final Failure: {e}")
```

4. Exception Group Splitter (>=3.11)
* Launch three coroutines that intentionally raise different exceptions. Catch the resulting ExceptionGroup and handle each exception type separately with except*.

```python
import asyncio

async def task_a():
    print("Task A starting...")
    await asyncio.sleep(0.1)
    raise ValueError("Error in Task A!")

async def task_b():
    print("Task B starting...")
    await asyncio.sleep(0.2)
    raise ConnectionError("Error in Task B!")

async def main_exception_group():
    print("Running tasks concurrently...")
    try:
        # Create an ExceptionGroup containing exceptions from both tasks
        await asyncio.gather(task_a(), task_b())
    except* ValueError as e_val:
        # Handle all ValueError instances in the group
        print(f"\n--- Handled ValueErrors: {e_val.exceptions} ---")
    except* ConnectionError as e_conn:
        # Handle all ConnectionError instances in the group
        print(f"\n--- Handled ConnectionErrors: {e_conn.exceptions} ---")

# Run the main coroutine
if __name__ == "__main__":
    try:
        asyncio.run(main_exception_group())
    except ExceptionGroup as eg:
        # If an unhandled type bubbles up, it's still an ExceptionGroup
        print(f"\nAn unhandled exception group was raised: {eg}")
```

5. Traceback Formatter
* Use the traceback module to write a function format_exception(e) that returns a coloured, one-line traceback string for logging.

```python
import traceback
import sys

# Define simple ANSI color codes for display
class Color:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

def format_exception_oneline(e):
    """
    Formats an exception and its traceback into a colored, one-line string.
    """
    # Extract the traceback information up to the call site of this function
    exc_type, exc_value, exc_traceback = sys.exc_info()
    if exc_traceback is None:
        return f"{Color.RED}Exception: {type(e).__name__}: {e}{Color.ENDC}"

    # Format the stack frames into a list of strings
    stack_summary = traceback.extract_tb(exc_traceback)
    
    # Get the last (most recent) frame
    last_frame = stack_summary[-1]

    # Format a concise message
    return (
        f"{Color.RED}ERROR{Color.ENDC} in {Color.YELLOW}{last_frame.filename}:{last_frame.lineno}{Color.ENDC} "
        f"('{last_frame.line.strip()}'): {type(e).__name__}: {e}"
    )

# Example Usage:
def risky_operation():
    a = 10
    b = 0
    result = a / b # Raises ZeroDivisionError

try:
    risky_operation()
except Exception as e:
    # Pass the caught exception to our formatter
    log_line = format_exception_oneline(e)
    print("\nFormatted Log Output:")
    print(log_line)
```
