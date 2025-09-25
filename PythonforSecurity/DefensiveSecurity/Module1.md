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

4. Defaultdict Graph
* Implement an undirected graph of internal hosts where each node’s adjacency list is maintained by defaultdict(set). Write add_edge(a, b) and has_path(a, b) using BFS.

5. Deep Copy Pitfall
* Show how shallow copying a list of bytearray payloads leads to unwanted mutation, then correct it using copy.deepcopy.
