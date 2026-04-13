## 1.9 - Writing “Pythonic” Code and Style Guidelines

### 1.9.1 The Zen of Python (PEP 20)

### 1.9.2 PEP 8 Basics

### 1.9.3 Docstrings (PEP 257)

### 1.9.4 Type Hints (PEP 484, PEP 563, PEP 644)

### 1.9.5 Idiomatic Patterns

### 1.9.6 EAFP vs LBYL

### 1.9.7 Comprehensions and Generators

### 1.9.8 Context Managers

### 1.9.9 Data Classes vs NamedTuples vs Regular Classes

### 1.9.10 Common “Code Smells”

### 1.9.11 Import Time and Side Effects

### 1.9.12 Performance Without Premature Optimisation

### 1.9.13 Testing and Continuous Integration

### 1.9.14 Exercises

1. PEP 8 Refactor
* The snippet below violates several style rules. Re-write it Pythonically.
```python
def compute(a,b):  
  if a>0 and b>0: return a+b  
  else:  
     return(a-b)
```
```python
def compute(a, b):
    if a > 0 and b > 0:
        return a + b
    else:
        return a - b
```

2. Docstring Practice
* Add a NumPy-style docstring (parameters, returns, examples) to compute.
```python
def compute(a, b):
    """
    Perform a conditional sum or difference of two numbers.

    Parameters
    ----------
    a : int or float
        The first input number.
    b : int or float
        The second input number.

    Returns
    -------
    int or float
        The sum of `a` and `b` if both are positive; 
        otherwise, the difference (`a` - `b`).

    Examples
    --------
    >>> compute(5, 3)
    8
    >>> compute(5, -3)
    8
    >>> compute(-5, 3)
    -8
    """
    if a > 0 and b > 0:
        return a + b
    else:
        return a - b
```

3. Type-Check
* Annotate compute and run mypy so it passes with strict=True.

```python
from typing import Union

def compute(a: Union[int, float], b: Union[int, float]) -> Union[int, float]:
    """
    Perform a conditional sum or difference of two numbers.

    Parameters
    ----------
    a : int or float
        The first input number.
    b : int or float
        The second input number.

    Returns
    -------
    int or float
        The sum of `a` and `b` if both are positive; 
        otherwise, the difference (`a` - `b`).

    Examples
    --------
    >>> compute(5, 3)
    8
    >>> compute(5, -3)
    8
    """
    if a > 0 and b > 0:
        return a + b
    else:
        return a - b
```

4. Context Manager
* Implement a Timer() context manager that prints elapsed time on exit and use it to wrap a call to sum(range(10**7)).

```python
import time

class Timer:
    """A context manager to measure and print elapsed time."""
    def __enter__(self):
        # Start the clock using perf_counter for high precision
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Calculate and print the difference on exit
        self.end = time.perf_counter()
        self.elapsed = self.end - self.start
        print(f"Elapsed time: {self.elapsed:.6f} seconds")

# Wrapping the target call
with Timer():
    result = sum(range(10**7))
```

5. Data Class Equality
* Create a frozen dataclass Point(x: int, y: int) and demonstrate that two points with the same coordinates compare equal and are hashable.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Point:
    x: int
    y: int

# 1. Demonstrate Equality
p1 = Point(10, 20)
p2 = Point(10, 20)
print(f"p1 == p2: {p1 == p2}")  # True

# 2. Demonstrate Hashability
# Since it is frozen, it can be used as a dictionary key or in a set
points_set = {p1, p2}
print(f"Set size: {len(points_set)}")  # 1 (duplicates are handled by hash/eq)
print(f"Hash of p1: {hash(p1)}")
```
