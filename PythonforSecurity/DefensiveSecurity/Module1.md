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
Write a function fizzbuzz(n) that prints numbers 1…n, substituting “Fizz”, “Buzz”, or “FizzBuzz” using a single for loop.

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
Implement first_duplicate(seq) that returns the first value that appears twice, using a for/else construct.

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
Read lines from a file until a line containing only STOP\n is found; count how many non-empty lines were read.

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
Given two lists of numbers, create a list of (a, b, a*b) tuples for every combination where a*b is even.

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
Accept strings like "ADD 4 5" or "MUL 3 9". Use match … case to parse and compute the result.

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
