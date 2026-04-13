## 1.5 Functions

### 1.5.1 Defining a Function

### 1.5.2 Argument-Passing Semantics

### 1.5.3 Positional, Keyword, and Mixed Calls

### 1.5.4 Default Argument Values

### 1.5.5 Variable-Length Parameters

### 1.5.6 Positional-only and Keyword-only Parameters (3.8+)

### 1.5.7 Annotations and Type Hints

### 1.5.8 First-Class and Higher-Order Functions

### 1.5.9 Lambda Expressions

### 1.5.10 Closures

### 1.5.11 Decorators

### 1.5.12 Generator Functions

### 1.5.13 Recursion

### 1.5.14 Standard-Library Helpers

### 1.5.15 Introspection

### 1.5.16 Performance Notes

### 1.5.17 Exercises

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
