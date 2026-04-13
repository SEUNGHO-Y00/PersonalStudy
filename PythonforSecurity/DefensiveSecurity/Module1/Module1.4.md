## 1.4 - Control Flow (Deep Dive)

### 1.4.1 Boolean Contexts

### 1.4.2 if / elif / else

### 1.4.3 while Loop

### 1.4.4 for Loop

### 1.4.5 Loop Control Statements

### 1.4.6 Comprehensions

### 1.4.7 Assignment Expression (:=, “walrus”)

### 1.4.8 Structural Pattern Matching (match … case, 3.10+)

### 1.4.9 Scope Rules in Loops

### 1.4.10 Idiomatic Guidelines

### 1.4.11 Practice Exercises

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
