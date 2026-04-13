## 1.3 Core Data Structures

### 1.3.1 Lists (list)

### 1.3.2 Tuples (tuple)

### 1.3.3 Dictionaries (dict)

### 1.3.4 Sets (set, frozenset)

### 1.3.5 Shallow vs Deep Copies

### 1.3.6 Choosing the Right Structure

### 1.3.7 Security-Centric Examples

### 1.3.8 Exercises

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
