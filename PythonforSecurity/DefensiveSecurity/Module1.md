# Module 1 - Python Fundamentals Study Note

## 1.2 - Basic Data Types (Deep Dive) Exercises
1. Endianness
* Write a function int_to_little_endian(n, length) that converts any positive integer to a little-endian byte sequence of fixed length.

```python
def int_to_little_endian(n: int, length: int) -> bytes:
    """
    Converts a positive integer to a little-endian byte sequence.

    Args:
        n: A positive integer.
        length: The fixed length of the resulting byte sequence.

    Returns:
        A byte sequence representing the integer in little-endian format.
    """
    if n < 0:
        raise ValueError("Input integer must be positive.")
    if length < 0:
        raise ValueError("Length must be a positive integer.")
    
    # 'little' specifies the byte order, and 'unsigned' indicates 
    # that the value is a positive integer.
    return n.to_bytes(length=length, byteorder='little', signed=False)
```

2. Safe Float Comparison
* Implement def almost_equal(a, b, rel_tol=1e-9, abs_tol=0.0) reproducing math.isclose without using the module.

```python
def almost_equal(a: float, b: float, rel_tol: float = 1e-9, abs_tol: float = 0.0) -> bool:
    """
    Compares two floating-point numbers for approximate equality.

    This function reproduces the logic of math.isclose() without using
    the module. It checks if the absolute difference between 'a' and 'b'
    is within either a relative tolerance or an absolute tolerance.

    Args:
        a: The first float.
        b: The second float.
        rel_tol: The relative tolerance.
        abs_tol: The absolute tolerance.

    Returns:
        True if the floats are approximately equal, False otherwise.
    """
    return abs(a - b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)
```

3. Mutable XOR
* Create a function xor_bytes(data: bytearray, key: int) that XORs each byte with a one-byte key in place.

```python
def xor_bytes(data: bytearray, key: int):
    """
    XORs each byte of a bytearray with a one-byte key in place.

    Args:
        data: The bytearray to modify.
        key: The one-byte key (an integer from 0 to 255).
    """
    if not 0 <= key <= 255:
        raise ValueError("Key must be a single byte (0-255).")
    
    for i in range(len(data)):
        data[i] ^= key
```

4. Truthiness Audit
* Write a class OpenPort with attributes port and status, and define __bool__ so that the instance is truthy only when status == "open".

```python
class OpenPort:
    """
    A class representing a network port with custom truthiness.

    An instance of this class is truthy only when its status is "open".
    """
    def __init__(self, port: int, status: str):
        self.port = port
        self.status = status.lower()

    def __bool__(self) -> bool:
        """
        Returns True if the port status is "open", False otherwise.
        """
        return self.status == "open"
```

5. String Builder Benchmark
* Compare execution time between concatenating 10 000 lines with += versus collecting them in a list and "".join. Use time.perf_counter.

```python
import time

def benchmark_concatenation(num_lines: int):
    """Benchmarks string concatenation with `+=`."""
    result = ""
    for i in range(num_lines):
        result += f"Line {i}\n"
    return result

def benchmark_join(num_lines: int):
    """Benchmarks string concatenation with a list and `"".join()`."""
    lines = []
    for i in range(num_lines):
        lines.append(f"Line {i}\n")
    return "".join(lines)
```

## 1.3 Core Data Structures Exercises
1. Port Collation
* Read a file of ip:port pairs, output a dict mapping each ip to a sorted list of unique ports.

```python
def collate_ports_by_ip(filepath):
    """
    Reads a file with 'ip:port' pairs, returning a dictionary mapping each
    IP to a sorted list of unique ports.
    """
    ip_ports = {}
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        ip, port = parts[0], parts[1]
                        try:
                            port = int(port)
                            if ip not in ip_ports:
                                ip_ports[ip] = set()
                            ip_ports[ip].add(port)
                        except ValueError:
                            # Skip lines with invalid port numbers
                            continue
    except FileNotFoundError:
        print(f"Error: The file at {filepath} was not found.")
        return None
```

2. Set Difference Performance
* Benchmark (time.perf_counter) deduplication of two million random URLs using a set versus list membership checks.

```python
import time
import random
import uuid

# Generate a large dataset of unique URLs
def generate_urls(count):
    return [f"http://example.com/{uuid.uuid4()}" for _ in range(count)]

num_urls = 2_000_000
urls_a = generate_urls(num_urls)
urls_b = generate_urls(num_urls // 2)

# Create a scenario where we want to find URLs in list_a that are not in list_b
urls_to_remove = random.sample(urls_a, num_urls // 4)
urls_b.extend(urls_to_remove)
random.shuffle(urls_b)

# Benchmark using set difference
start_time = time.perf_counter()
set_a = set(urls_a)
set_b = set(urls_b)
result_set = set_a - set_b
end_time = time.perf_counter()
set_duration = end_time - start_time
print(f"Set difference benchmark: {set_duration:.6f} seconds")
```

3. Immutable Config Key
* Build a frozenset of (host, port, protocol) triples and use it as keys in a dict that stores timeout values.

```python
# Create a dictionary to store timeout values
timeout_config = {}

# Define some configuration parameters
config_set1 = frozenset([('host1', 80, 'http'), ('host2', 443, 'https')])
config_set2 = frozenset([('host3', 22, 'ssh')])
config_set3 = frozenset([('host1', 80, 'http'), ('host2', 443, 'https')]) # Same as config_set1

# Use frozensets as dictionary keys
timeout_config[config_set1] = 60
timeout_config[config_set2] = 30

# Retrieve and print the value using an equivalent frozenset
# This works because frozensets with the same elements are considered equal.
print(f"Timeout for config_set1: {timeout_config[config_set1]}s")
print(f"Timeout for config_set3: {timeout_config[config_set3]}s")

# Demonstrate that a regular set cannot be used as a key
try:
    mutable_set = {('host4', 8080, 'http')}
    timeout_config[mutable_set] = 120
except TypeError as e:
    print(f"\nError: {e}")
```

4. Defaultdict Graph
* Implement an undirected graph of internal hosts where each node’s adjacency list is maintained by defaultdict(set). Write add_edge(a, b) and has_path(a, b) using BFS.

```python
from collections import defaultdict, deque

class UndirectedGraph:
    def __init__(self):
        self.graph = defaultdict(set)

    def add_edge(self, node_a, node_b):
        """Adds an edge between node_a and node_b."""
        self.graph[node_a].add(node_b)
        self.graph[node_b].add(node_a)

    def has_path(self, start_node, end_node):
        """
        Performs a Breadth-First Search (BFS) to check if a path exists
        between start_node and end_node.
        """
        if start_node == end_node:
            return True
        
        if start_node not in self.graph or end_node not in self.graph:
            return False

        queue = deque([start_node])
        visited = {start_node}
        
        while queue:
            current_node = queue.popleft()
            if current_node == end_node:
                return True
            
            for neighbor in self.graph[current_node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        
        return False

# Example Usage:
g = UndirectedGraph()
g.add_edge('hostA', 'hostB')
g.add_edge('hostB', 'hostC')
g.add_edge('hostC', 'hostD')
g.add_edge('hostE', 'hostF')

print(f"Path from hostA to hostD exists: {g.has_path('hostA', 'hostD')}")
print(f"Path from hostA to hostE exists: {g.has_path('hostA', 'hostE')}")
```

5. Deep Copy Pitfall
* Show how shallow copying a list of bytearray payloads leads to unwanted mutation, then correct it using copy.deepcopy.

```python
import copy

# Pitfall: Shallow copy with nested mutable objects
print("--- Shallow Copy Pitfall ---")
original_payloads = [
    bytearray(b'secret_data_1'),
    bytearray(b'secret_data_2')
]

# Shallow copy the list
shallow_copied_payloads = original_payloads.copy()

# Modify a nested bytearray in the shallow copy
shallow_copied_payloads[0][0:7] = b'EXPOSED'

print(f"Original payloads: {original_payloads}")
print(f"Shallow copy payloads: {shallow_copied_payloads}")
# The change to the shallow copy also affected the original list

# Correction: Deep copy for full independence
print("\n--- Deep Copy Correction ---")
original_payloads_fixed = [
    bytearray(b'secret_data_1'),
    bytearray(b'secret_data_2')
]

# Deep copy the list
deep_copied_payloads = copy.deepcopy(original_payloads_fixed)

# Modify a nested bytearray in the deep copy
deep_copied_payloads[0][0:7] = b'MODIFIED'

print(f"Original payloads (after deep copy): {original_payloads_fixed}")
print(f"Deep copy payloads: {deep_copied_payloads}")
# The change to the deep copy does not affect the original list
```

## 1.4 - Control Flow (Deep Dive) Exercise

1. FizzBuzz with Assignment Expression
* Write a function fizzbuzz(n) that prints numbers 1…n, substituting “Fizz”, “Buzz”, or “FizzBuzz” using a single for loop.

```python
def fizzbuzz(n):
    for i in range(1, n + 1):
        # Use an assignment expression to build the output string
        if s := (not i % 3) * "Fizz" + (not i % 5) * "Buzz":
            print(s)
        else:
            print(i)

# Example Usage:
print("FizzBuzz up to 20:")
fizzbuzz(20)
```

2. Find First Duplicate
* Implement first_duplicate(seq) that returns the first value that appears twice, using a for/else construct.

```python
def first_duplicate(seq):
    """
    Returns the first value that appears twice in the sequence.
    Uses a for/else loop.
    """
    seen = set()
    for item in seq:
        if item in seen:
            print(f"First duplicate found: {item}")
            break
        seen.add(item)
    else:
        print("No duplicates found.")

# Example Usage:
first_duplicate([1, 2, 3, 4, 3, 2, 1])
first_duplicate([10, 20, 30, 40, 50])
```

3. Sentinel File Reader
* Read lines from a file until a line containing only STOP\n is found; count how many non-empty lines were read.

```python
import os

def read_until_sentinel(filepath):
    """
    Reads a file line-by-line, counting non-empty lines until a
    line containing "STOP" is found.
    """
    count = 0
    sentinel = "STOP\n"

    # Create a dummy file for demonstration
    with open(filepath, 'w') as f:
        f.write("Line 1\n")
        f.write("\n")
        f.write("Line 2\n")
        f.write("STOP\n")
        f.write("This line should not be read\n")

    try:
        with open(filepath, 'r') as file:
            for line in file:
                if line == sentinel:
                    break
                if line.strip(): # Check if line is not empty
                    count += 1
    except FileNotFoundError:
        print(f"Error: The file at {filepath} was not found.")
        return -1
    finally:
        os.remove(filepath) # Clean up dummy file

    return count

# Example Usage:
file_to_read = 'sentinel_file.txt'
lines_read = read_until_sentinel(file_to_read)
print(f"Number of non-empty lines read: {lines_read}")
```

4. Cartesian Product Comprehension
* Given two lists of numbers, create a list of (a, b, a*b) tuples for every combination where a*b is even.

```python
def cartesian_product_even_multiples(list1, list2):
    """
    Generates a list of (a, b, a*b) tuples for every combination
    where a*b is even.
    """
    return [(a, b, a * b) for a in list1 for b in list2 if (a * b) % 2 == 0]

# Example Usage:
numbers1 = [1, 2, 3]
numbers2 = [4, 5, 6]

result = cartesian_product_even_multiples(numbers1, numbers2)
print(f"Cartesian product with even multiples: {result}")
# Expected output: [(1, 4, 4), (1, 6, 6), (2, 4, 8), (2, 5, 10), (2, 6, 12), (3, 4, 12), (3, 6, 18)]
```

5. Pattern-Match Calculator
* Accept strings like "ADD 4 5" or "MUL 3 9". Use match … case to parse and compute the result.

```python
def calculate_from_string(command):
    """
    Parses a string command and computes the result using match-case.
    """
    parts = command.split()
    match parts:
        case ["ADD", a, b]:
            return int(a) + int(b)
        case ["MUL", a, b]:
            return int(a) * int(b)
        case ["SUB", a, b]:
            return int(a) - int(b)
        case ["DIV", a, b]:
            # Handle potential division by zero
            divisor = int(b)
            if divisor == 0:
                return "Error: Division by zero"
            return int(a) / divisor
        case _:
            return "Error: Invalid command format"

# Example Usage:
print(f"'ADD 4 5' -> Result: {calculate_from_string('ADD 4 5')}")
print(f"'MUL 3 9' -> Result: {calculate_from_string('MUL 3 9')}")
print(f"'SUB 10 2' -> Result: {calculate_from_string('SUB 10 2')}")
print(f"'DIV 10 2' -> Result: {calculate_from_string('DIV 10 2')}")
print(f"'MOD 10 3' -> Result: {calculate_from_string('MOD 10 3')}")
```

## 1.5 Functions Exercises

1. Keyword-only Logger
* Write log(msg, *, level="INFO") that prints [LEVEL] msg. Enforce keyword-only for level.

```python
def log(msg, *, level="INFO"):
    """
    Prints a log message with a specified level.
    The 'level' parameter must be passed as a keyword argument.
    """
    print(f"[{level}] {msg}")

# Example Usage:
log("System starting up")
log("Interface down", level="WARNING")

# This will raise a TypeError:
try:
    log("Interface down", "ERROR")
except TypeError as e:
    print(f"\nCaught expected error: {e}")
```

2. LRU (Least Recently Used) Fibonacci
* Implement fib(n) with @lru_cache(maxsize=None) and time it against a non-cached version.

```python
import time
from functools import lru_cache

# --- Non-cached version ---
def fib_slow(n):
    if n <= 1:
        return n
    return fib_slow(n - 1) + fib_slow(n - 2)

# --- Cached version ---
@lru_cache(maxsize=None)  # maxsize=None means the cache can grow indefinitely
def fib_fast(n):
    if n <= 1:
        return n
    return fib_fast(n - 1) + fib_fast(n - 2)

# Benchmark the non-cached version
n_val = 35
start_time = time.perf_counter()
result_slow = fib_slow(n_val)
end_time = time.perf_counter()
print(f"fib_slow({n_val}) = {result_slow} (Took {end_time - start_time:.4f} seconds)")

# Benchmark the cached version
start_time = time.perf_counter()
result_fast = fib_fast(n_val)
end_time = time.perf_counter()
print(f"fib_fast({n_val}) = {result_fast} (Took {end_time - start_time:.4f} seconds)")

# To reset the cache for new runs
fib_fast.cache_clear()
```

3. Decorator with Arguments
* Create @retry(times=3) that re-invokes the wrapped function if it raises Exception.

```python
import time
import random
from functools import wraps

def retry(times=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    print(f"Attempt {attempt + 1}/{times} failed: {e}")
                    if attempt < times - 1:
                        time.sleep(delay)
                    else:
                        raise
        return wrapper
    return decorator

@retry(times=5, delay=0.5)
def unstable_network_call():
    """Simulates a function that fails randomly."""
    if random.random() < 0.8: # 80% chance of failure
        raise Exception("Connection lost!")
    return "Data retrieved successfully!"

# Example Usage:
try:
    result = unstable_network_call()
    print(f"\nSuccess: {result}")
except Exception as e:
    print(f"\nFinal failure: {e}")
```

4. Closure Counter
* Build three independent counters from make_counter() and show that each maintains its own state.

```python
def make_counter():
    count = 0
    def increment():
        nonlocal count
        count += 1
        return count
    return increment

# Build three independent counters
counter_a = make_counter()
counter_b = make_counter()
counter_c = make_counter()

# Increment and show independent state
print(f"Counter A: {counter_a()}") # 1
print(f"Counter B: {counter_b()}") # 1
print(f"Counter A: {counter_a()}") # 2
print(f"Counter C: {counter_c()}") # 1
print(f"Counter B: {counter_b()}") # 2
```

5. Generator Pipeline
* Compose generator functions to read a file, strip whitespace, filter out blank lines, and yield line numbers plus text.

```python
# Create a dummy file for the example
with open('data_file.txt', 'w') as f:
    f.write("  Line One  \n")
    f.write("Line Two\n")
    f.write("\n") # Blank line
    f.write("  Line Four\n")

def read_file_gen(filepath):
    """Generator 1: Reads lines from a file."""
    with open(filepath, 'r') as f:
        yield from f

def strip_whitespace_gen(lines):
    """Generator 2: Strips whitespace from lines."""
    for line in lines:
        yield line.strip()

def filter_blank_lines_gen(lines):
    """Generator 3: Filters out blank lines."""
    for line in lines:
        if line: # If line is not empty
            yield line

def enumerate_lines_gen(lines):
    """Generator 4: Yields line numbers and text."""
    for i, line in enumerate(lines, 1):
        yield i, line

# Compose the pipeline
pipeline = enumerate_lines_gen(
               filter_blank_lines_gen(
                   strip_whitespace_gen(
                       read_file_gen('data_file.txt')
                   )
               )
           )

# Process the pipeline
print("Generator Pipeline Output:")
for line_num, text in pipeline:
    print(f"{line_num}: {text}")

# Clean up the dummy file
import os
os.remove('data_file.txt')
```

6. Positional-only Division
* Define def div(a, b, /, precision=2) that forbids keyword use of a and b but allows precision=4.

```python
def div(a, b, /, precision=2):
    """
    Performs division of a by b.
    'a' and 'b' must be positional-only arguments.
    'precision' can be positional or keyword.
    """
    result = a / b
    return round(result, precision)

# Example Usage (Valid):
print(f"Positional only: {div(22, 7)}")
print(f"Positional only with keyword precision: {div(22, 7, precision=4)}")
print(f"Positional only with positional precision: {div(22, 7, 5)}")

# This will raise a TypeError because 'a' and 'b' are used as keywords:
try:
    print(div(a=22, b=7))
except TypeError as e:
    print(f"\nCaught expected error: {e}")
```

## 1.6 Modules and Packages Exercises
1. Package Skeleton
* Create calc/ with __init__.py, add.py, sub.py. Re-export add and sub functions at package level. Demonstrate usage from a parent directory.

```python
project_root/
├── calc/
│   ├── __init__.py
│   ├── add.py
│   └── sub.py
└── main.py
```
```python
# calc/add.py
def add(a, b):
    return a + b

# calc/sub.py
def sub(a, b):
    return a - b

# calc/__init__.py
from .add import add
from .sub import sub
__all__ = ['add', 'sub']

# main.py (run from project_root)
import calc
print(f"5 + 3 = {calc.add(5, 3)}")
print(f"5 - 3 = {calc.sub(5, 3)}")
```

2. Import Cycle Detection
* Build two modules a.py and b.py that import each other. Observe the runtime error and refactor to remove the cycle.
```python
cycle_project/
├── a.py
└── b.py
```
```python
# a.py
import b

def func_a():
    print("Inside func_a")
    b.func_b() # This call fails when imported from b

if __name__ == "__main__":
    func_a()

# b.py
import a

def func_b():
    print("Inside func_b")
    # A.func_a() # If we called this, it would definitely fail
```
* Refactoring the Cycle
```python
# a_fixed.py
# No top-level import of b

def func_a_fixed():
    print("Inside func_a_fixed")
    import b_fixed # Import inside the function
    b_fixed.func_b_fixed()

if __name__ == "__main__":
    func_a_fixed()

# b_fixed.py
# No top-level import of a_fixed needed for this structure

def func_b_fixed():
    print("Inside func_b_fixed")
```

3. Namespace Package Experiment
* Create two separate directories, each containing plugins/spam.py and plugins/eggs.py (without __init__.py). Add both parent paths to PYTHONPATH and show that import plugins.spam finds both.
```python
path1/
└── plugins/
    └── spam.py

path2/
└── plugins/
    └── eggs.py
```
```python
# path1/plugins/spam.py
def spam_func():
    return "This is the spam plugin from path1."

# path2/plugins/eggs.py
def eggs_func():
    return "This is the eggs plugin from path2."
```
```bash
# On Linux/macOS/Git Bash:
export PYTHONPATH=$PWD/path1:$PWD/path2
python3 demo.py

# On Windows Command Prompt:
set PYTHONPATH=%cd%\path1;%cd%\path2
python3 demo.py
```
```python
# demo.py
import plugins.spam
import plugins.eggs
import plugins # The 'plugins' object itself is a namespace package

print(f"Spam result: {plugins.spam.spam_func()}")
print(f"Eggs result: {plugins.eggs.eggs_func()}")

# You can inspect the paths Python found for the namespace package
print("\nPaths used by the plugins namespace package:")
for p in plugins.__path__:
    print(p)
```

4. Module Reload Pitfall
* Write a module with a mutable global list. Import it, mutate the list from the main script, reload the module, and inspect how state is preserved.
```python
reload_pitfall/
├── state_module.py
└── main_reload.py
```
```python
# state_module.py
print("--- state_module.py is being executed ---")
MUTABLE_LIST = ["initial_item"]
IMMUTABLE_VALUE = 1

# main_reload.py
import state_module
import importlib

print(f"\nOriginal List: {state_module.MUTABLE_LIST}")
print(f"Original Value: {state_module.IMMUTABLE_VALUE}")

# Mutate the shared global list from the main script
state_module.MUTABLE_LIST.append("item_added_by_main")

print(f"\nList after modification by main: {state_module.MUTABLE_LIST}")

# Reload the module
print("\n--- Reloading state_module ---")
importlib.reload(state_module)
print("--- Reload finished ---")

# Inspect the state again
print(f"\nList after reload: {state_module.MUTABLE_LIST}")
print(f"Value after reload: {state_module.IMMUTABLE_VALUE}")

# The list *keeps* the added item because the *object reference*
# held by main.py wasn't destroyed, even though the module code ran again.
# The immutable value *does* revert to its initial state.
```

5. Console Script
* Build a small package echo with cli.py exposing main(). Add a console_scripts entry point in pyproject.toml, build a wheel, install it in a venv, and verify that the echo command runs.

```python
echo_package/
├── src/
│   └── echo/
│       ├── __init__.py
│       └── cli.py
├── pyproject.toml
└── README.md
```
```python
# src/echo/__init__.py

# src/echo/cli.py
import sys

def main():
    """
    Main function for the 'echo' console script.
    Echos command line arguments back to the console.
    """
    if len(sys.argv) > 1:
        message = " ".join(sys.argv[1:])
        print(f"Echoing: {message}")
    else:
        print("Usage: echo <message to echo>")

if __name__ == "__main__":
    main()
```
```toml
# pyproject.toml
[project]
name = "simple-echo-cli"
version = "0.1.0"
description = "A simple demonstration package with a console script."
authors = [
    { name = "Your Name", email = "your.email@example.com" }
]

[project.scripts]
# This defines the console command name ("echo") and links it
# to the function: "module.sub_module:function_name"
echo = "echo.cli:main"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
```

## 1.7 File Handling Exercises
1. Chunked Copier
* Implement copy(src, dst, chunk_size=262144) that copies any size file using binary reads and writes, reporting bytes per second.

```python
import time
import shutil

def copy_chunked(src, dst, chunk_size=262144):
    """
    Copies a file using binary reads and writes in specified chunk sizes,
    reporting the transfer rate.
    """
    start_time = time.perf_counter()
    total_bytes = 0

    try:
        with open(src, 'rb') as f_src:
            with open(dst, 'wb') as f_dst:
                while True:
                    chunk = f_src.read(chunk_size)
                    if not chunk:
                        break
                    f_dst.write(chunk)
                    total_bytes += len(chunk)
    except FileNotFoundError:
        print(f"Error: Source file '{src}' not found.")
        return
    except IOError as e:
        print(f"Error during file operation: {e}")
        return

    end_time = time.perf_counter()
    duration = end_time - start_time

    if duration > 0:
        bytes_per_second = total_bytes / duration
        print(f"Copied {total_bytes} bytes in {duration:.2f} seconds.")
        print(f"Rate: {bytes_per_second / 1024 / 1024:.2f} MiB/s")
    else:
        print(f"Copied {total_bytes} bytes instantly.")

# Example Usage:
# Create a dummy source file first
with open("source.bin", "wb") as f:
    f.write(b'\x00' * 1024 * 1024 * 10) # 10 MiB dummy file

copy_chunked("source.bin", "destination.bin")

# Clean up
import os
os.remove("source.bin")
os.remove("destination.bin")
```

2. Line Reverser
* Read input.txt and create output.txt where line order is reversed but internal character order is preserved.

```python
def reverse_lines(input_path, output_path):
    """
    Reads a file and writes its lines in reverse order to a new file.
    """
    try:
        with open(input_path, 'r') as f_in:
            lines = f_in.readlines()
        
        # Reverse the list of lines
        lines.reverse()

        with open(output_path, 'w') as f_out:
            f_out.writelines(lines)
        print(f"Lines reversed successfully from '{input_path}' to '{output_path}'.")

    except IOError as e:
        print(f"Error during file operation: {e}")

# Example Usage:
# Create dummy input file
with open("input.txt", "w") as f:
    f.write("First line\n")
    f.write("Second line\n")
    f.write("Third line\n")

reverse_lines("input.txt", "output.txt")

# Verify the output (optional)
with open("output.txt", "r") as f:
    print("\nContents of output.txt:")
    print(f.read())

# Clean up
import os
os.remove("input.txt")
os.remove("output.txt")
```

3. Safe Config Writer
* Write a function save_json(path, obj) that atomically writes pretty-printed JSON by using NamedTemporaryFile and os.replace.

```python
import json
import os
import tempfile

def save_json_atomically(path, obj):
    """
    Writes a dictionary to a JSON file atomically using a temporary file.
    """
    # Use NamedTemporaryFile to get a safe, temporary location in the same directory
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(path) or '.') as temp_file:
        try:
            # Write all data to the temporary file
            json.dump(obj, temp_file, indent=4)
            temp_file.flush()
            os.fsync(temp_file.fileno()) # Ensure data is written to disk
        except Exception as e:
            # If anything fails, close and delete the temp file immediately
            temp_file.close()
            os.unlink(temp_file.name)
            raise IOError(f"Failed to write to temporary file: {e}")

    # If writing succeeded, safely replace the original file
    os.replace(temp_file.name, path)
    print(f"Configuration saved safely to '{path}'.")

# Example Usage:
config_data = {
    "hostname": "router-a",
    "interfaces": ["eth0", "eth1"],
    "settings": {"timeout": 30}
}
save_json_atomically("config.json", config_data)

# Verify the output (optional)
with open("config.json", "r") as f:
    print("\nContents of config.json:")
    print(f.read())

# Clean up
os.remove("config.json")
```

4. Directory Tree Size
* Using pathlib, compute total size (in bytes) of all regular files under a directory, skipping symlinks.

```python
from pathlib import Path

def get_dir_size(directory_path):
    """
    Computes the total size (in bytes) of all regular files within a directory.
    """
    path = Path(directory_path)
    if not path.is_dir():
        raise ValueError(f"Path is not a valid directory: {directory_path}")

    total_size = 0
    # Use rglob('*') for a recursive search of all items
    for item in path.rglob('*'):
        # Check if it is a file and not a symlink
        if item.is_file() and not item.is_symlink():
            total_size += item.stat().st_size
    return total_size

# Example Usage:
# Create dummy files in a temporary structure
os.makedirs("temp_dir/subdir", exist_ok=True)
with open("temp_dir/file1.txt", "w") as f: f.write("12345")
with open("temp_dir/subdir/file2.bin", "wb") as f: f.write(b'\x00' * 100)

size = get_dir_size("temp_dir")
print(f"Total size of 'temp_dir': {size} bytes") # Expected: 105 bytes

# Clean up (requires a helper to remove non-empty dir)
import shutil
shutil.rmtree("temp_dir")
```

5. CSV Aggregator
* Combine every .csv in a folder into a single combined.csv with an additional column source_file indicating origin.

```python
import csv
import os
import glob

def aggregate_csvs(folder_path, output_filename="combined.csv"):
    """
    Combines all CSV files in a folder into one, adding a source_file column.
    """
    output_path = os.path.join(folder_path, output_filename)
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    
    if not all_files:
        print(f"No CSV files found in {folder_path}")
        return

    # Use a set to track if the header has been written to the combined file
    header_written = False
    with open(output_path, 'w', newline='') as outfile:
        writer = csv.writer(outfile)

        for filename in all_files:
            with open(filename, 'r', newline='') as infile:
                reader = csv.reader(infile)
                header = next(reader)
                
                # Write the header only once for the output file
                if not header_written:
                    writer.writerow(header + ["source_file"])
                    header_written = True

                # Write data rows, appending the source filename
                for row in reader:
                    writer.writerow(row + [os.path.basename(filename)])
    
    print(f"Aggregated {len(all_files)} files into {output_path}")

# Example Usage:
os.makedirs("csv_data", exist_ok=True)
with open("csv_data/fileA.csv", "w", newline="") as f:
    f.write("ID,Value\n1,100\n2,200\n")
with open("csv_data/fileB.csv", "w", newline="") as f:
    f.write("ID,Value\n3,300\n4,400\n")

aggregate_csvs("csv_data")

# Verify the output (optional)
with open("csv_data/combined.csv", "r") as f:
    print("\nContents of combined.csv:")
    print(f.read())

# Clean up
shutil.rmtree("csv_data")
```

6. Memory-Mapped Patch
* Open a large binary file with mmap, locate all occurrences of the byte sequence b"\x90\x90\x90\x90", and overwrite them with b"\xCC\xCC\xCC\xCC".

```python
import mmap
import os
import contextlib

def patch_binary_file_mmap(filepath, find_bytes, replace_bytes):
    """
    Locates occurrences of a byte sequence in a file using mmap and replaces them.
    """
    if len(find_bytes) != len(replace_bytes):
        print("Error: Find and replace byte sequences must be the same length.")
        return

    try:
        # Open in read/write binary mode
        with open(filepath, "r+b") as f:
            # Memory map the file
            with contextlib.closing(mmap.mmap(f.fileno(), 0)) as mm:
                print(f"Opened {filepath} with mmap. File size: {len(mm)} bytes.")
                
                offset = 0
                count = 0
                # Find the first occurrence
                offset = mm.find(find_bytes, offset)
                
                while offset != -1:
                    print(f"Found sequence at offset {offset}. Patching...")
                    # Overwrite the bytes in the mapped memory
                    mm[offset:offset + len(replace_bytes)] = replace_bytes
                    count += 1
                    # Search for the next occurrence, starting after the current patch
                    offset = mm.find(find_bytes, offset + len(replace_bytes))
                
                # mmap is automatically flushed to disk upon close by context manager
                print(f"Patching complete. Total occurrences replaced: {count}.")

    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example Usage:
# Create a dummy large binary file with sequences to find
test_file = "large_binary.bin"
with open(test_file, "wb") as f:
    f.write(b'data' + b"\x90\x90\x90\x90" + b'more_data' + b"\x90\x90\x90\x90" + b'end')

patch_binary_file_mmap(
    filepath=test_file,
    find_bytes=b"\x90\x90\x90\x90",
    replace_bytes=b"\xCC\xCC\xCC\xCC"
)

# Verify the changes (optional)
with open(test_file, "rb") as f:
    print("\nContents after patching:")
    print(f.read())

# Clean up
os.remove(test_file)
```

## 1.8 Exception Handling Exercises
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

```
Traceback Formatter
Use the traceback module to write a function format_exception(e) that returns a coloured, one-line traceback string for logging.
