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
